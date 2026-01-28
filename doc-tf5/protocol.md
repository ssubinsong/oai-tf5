# Protocol Design

[Back to Index](index.md)

---

## Key Chain Generation

TESLA uses a one-way hash chain for key management. The gNB generates keys in reverse order:

```
K_N (seed) --F--> K_{N-1} --F--> ... --F--> K_1 --F--> K_0 (root/commitment)
```

- **K_N**: Random seed (generated at initialization)
- **F**: One-way function: `K_i = HMAC-SHA256(K_{i+1}, 0x00)[0:15]`
- **K_0**: Root key (commitment), shared with UE in static parameters

The gNB uses keys in forward order (K_1, K_2, ..., K_N), disclosing each key one interval after it was used.

---

## Time Intervals

Time is divided into discrete intervals:

| Parameter | Default Value | Description |
|-----------|---------------|-------------|
| T_int | 20 ms (pattern 1) or SSB period (pattern 2/3) | Interval duration |
| chain_len | 65536 | Number of intervals (configurable) |
| Duration | Depends on T_int (e.g., ~21.8 min for T_int=20ms) | Total key chain lifetime |

**Interval Index Calculation**:
```
i = floor((current_time - T_0) / T_int)
```

Where `T_0` is the start time of interval 0, aligned with the first SIB1 transmission occasion.

### T_int Alignment with SIB1 Repetition Period

Per **3GPP TS 38.331 Section 5.2.1.2**, the TESLA interval duration (T_int) is aligned with the SIB1 repetition transmission period.

**Current implementation**: T_int is fixed at **20 ms**, assuming CORESET mux pattern 1. The gNB will abort if a different pattern is detected.

### T_0 Alignment with First SIB1 Transmission

T_0 is set to the first SIB1 transmission occasion (SSB index 0):
- First frame where `(SFN % 2 == sfn_c)`, at slot `n_0`

### Chain Length

The default chain length is 65536 intervals. With T_int = 20 ms, this gives a key chain lifetime of ~21.8 minutes.

The chain length can be configured by the user if a different lifetime is needed.

---

## Disclosure Delay

The **disclosure delay** (d) determines how many intervals elapse before a key is revealed:

- Default: **d = 1**
- At interval i, gNB discloses K_{i-d} = K_{i-1}
- UE can verify messages from interval i-1 using the disclosed key

**Timeline Example** (d=1):
```
Interval 5: gNB uses K_5 for MAC, discloses K_4
Interval 6: gNB uses K_6 for MAC, discloses K_5
            UE verifies buffered message from interval 5 using K_5
```

### Why d=1 is Safe (RFC 4082 Consideration)

RFC 4082 Section 3.6 states that d=1 "does not work" for packets sent near interval boundaries, as network delay may cause them to arrive after the key is disclosed. However, **d=1 is safe in this implementation** because:

1. **Deterministic broadcast scheduling**: SIB1 is transmitted at the **beginning** of each TESLA interval (aligned with SSB/SIB1 timing per 3GPP TS 38.331)

2. **Full propagation margin**: Packets have the entire interval duration (~20ms) to reach receivers before key disclosure in the next interval

3. **No boundary timing issue**: Unlike generic TESLA deployments where packets may be sent at arbitrary times within an interval, 5G broadcast scheduling ensures packets never approach interval boundaries

**Security guarantee**: RFC 4082 Section 3.2 confirms the scheme "remains secure for any values of T_int and d>0"

**Latency benefit**: Using d=1 minimizes authentication delay (1 interval vs 2+ intervals with higher d values)

---

## Dual Authentication Mechanism

TF5 implements **two authentication mechanisms**:

### 1. BLS Signature (Immediate)
- gNB signs the authentication input with its BLS private key
- UE verifies immediately if it has the pre-provisioned BLS public key
- Provides strong authentication without waiting

### 2. TESLA MAC (Delayed)
- gNB computes HMAC using the current interval's key
- UE buffers the message and verifies when key is disclosed
- Provides authentication even without pre-provisioned keys
