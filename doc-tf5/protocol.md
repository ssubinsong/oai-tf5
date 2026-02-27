# Protocol Design

[Back to Index](index.md)

---

## Key Chain Generation

TESLA uses a one-way hash chain for key management. The gNB generates keys in reverse order:

```
K_N (seed) --F--> K_{N-1} --F--> ... --F--> K_1 --F--> K_0 (root/commitment)
```

- **K_N**: Random seed (generated at initialization)
- **F**: One-way function: `K_i = SHA-256(0x00 || K_{i+1})[0:15]`
- **K_0**: Root key (commitment), shared with UE in static parameters

The gNB uses keys in forward order (K_1, K_2, ..., K_N), disclosing each key one interval after it was used.

---

## Time Intervals

Time is divided into discrete intervals:

| Parameter | Default Value | Description |
|-----------|---------------|-------------|
| T_int | 160 ms | Interval duration (fixed) |
| chain_len | 65536 | Number of intervals (configurable) |
| Duration | Depends on T_int (e.g., ~174.8 min for T_int=160ms) | Total key chain lifetime |

**Interval Index Calculation**:

```
i = floor((current_time - T_0) / T_int)
```

Where `T_0` is the start time of interval 0, aligned with the first SIB1 transmission occasion.

### T_int Alignment with SIB1 Broadcast Period

Per **3GPP TS 38.331 Section 5.2.1.2**, the TESLA interval duration (T_int) is aligned with the SIB1 broadcast period.

**Current implementation**: T_int is fixed at **160 ms**, matching the SIB1 broadcast period (8 repetitions at 20ms SSB periodicity, CORESET mux pattern 1). The gNB will abort if a different pattern is detected.

### T_0 Alignment with First SIB1 Transmission

T_0 is set to the first SIB1 transmission occasion (SSB index 0):
- First frame where `(SFN % 2 == sfn_c)`, at slot `n_0`

### Chain Length

The default chain length is 65536 intervals. With T_int = 160 ms, this gives a key chain lifetime of ~174.8 minutes (~2.9 hours).

The chain length can be configured by the user if a different lifetime is needed.

---

## Disclosure Delay

The **disclosure delay** (d) determines how many intervals elapse before a key is revealed:

- Default: **d = 1**
- At interval i, gNB discloses `K_{i-d}` = `K_{i-1}`
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

2. **Full propagation margin**: Packets have the entire interval duration (~160ms) to reach receivers before key disclosure in the next interval

3. **No boundary timing issue**: Unlike generic TESLA deployments where packets may be sent at arbitrary times within an interval, 5G broadcast scheduling ensures packets never approach interval boundaries

**Security guarantee**: RFC 4082 Section 3.2 confirms the scheme "remains secure for any values of T_int and d>0"

**Latency benefit**: Using `d=1` minimizes authentication delay (1 interval vs 2+ intervals with higher `d` values)

---

## Bootstrap Intervals (interval < d)

During the first `d` intervals (0 to d-1), the gNB cannot disclose `K_{i-d}` because that would require a negative index. Instead, it discloses the **bootstrap key** `K_{-1} = F(K_0)`.

### Chain Property

Per RFC 4082 Section 3.2, `K_i = F(K_{i+1})`. Extending this relationship:
- `K_{-1} = F(K_0)`
- `K_n` chains to `K_{-1}` in `(n+1)` hash steps

### UE Verification with Bootstrap Anchor

When the UE receives a SIB1 during a bootstrap interval:
1. The IBS signature authenticates `K_{-1}` along with all other extension fields
2. `K_{-1}` becomes the trust anchor with `trust_anchor_idx = -1`
3. When `K_0` is disclosed later, the UE verifies `F(K_0) == K_{-1}`
4. Upon successful verification, the anchor is promoted to `K_0` for O(1) future verifications

This maintains the security property from RFC 4082 Section 3.3: "One authenticated key of the one-way key chain."

---

## SIB1/SIB9 Data Split

TESLA authentication data is split across two system information messages to minimize SIB1 overhead:

| Message | Content | Size | Update Frequency |
|---------|---------|------|------------------|
| SIB1 `lateNonCriticalExtension` | Per-interval data (version, interval index, disclosed key, TESLA tag) | 37 B | Every TESLA interval |
| SIB9 `lateNonCriticalExtension` | Static data + IBS signature (version, TESLA params, validity, timestamp, signature) | 114 B | Per key chain epoch |

SIB9 is registered in SIB1's `si-SchedulingInfo` and broadcast as a separate SI message on its own schedule.

---

## SIB1/SIB9 Extension Wire Format

### SIB1 Extension (37 bytes)

```
te_version       (1 B)   Protocol version
interval_index   (4 B)   Current TESLA interval index
key_disclosure  (16 B)   Disclosed key K_{i-d}
tesla_tag       (16 B)   HMAC tag over original SIB1
```

### SIB9 Extension (114 bytes)

```
te_version       (1 B)   Protocol version
tesla_params    (11 B)   t_int(2) + d(1) + t0(4) + chain_len(4)
validity_end     (3 B)   gNB key expiration (minutes since epoch)
timestamp_ms     (3 B)   Signature timestamp for replay protection
signature       (96 B)   GG09 Schnorr IBS signature (R[32] + σ[32] + pk[32])
```

---

## Authentication Input Formats

### MAC Auth Input (for TESLA tag computation)

```
original_SIB1    (variable)   SIB1 encoding excluding the lateNonCriticalExtension
te_version       (1 B)        Protocol version
```

### Signature Auth Input (for IBS signing/verification)

```
te_version       (1 B)    Protocol version
tesla_params    (11 B)    Packed TESLA parameters
validity_end     (3 B)    gNB key validity period
timestamp_ms     (3 B)    Signature timestamp
                ------
Total:           18 B
```

---

## Dual Authentication Mechanism

TF5 implements **two authentication mechanisms**:

### 1. GG09 Schnorr IBS Signature (Immediate) — First-time UE
- gNB signs the signature auth input with its IBS secret key (sk_ID); the signature is carried in **SIB9**
- First-time UE receives SIB1, stores it, then waits for the next SIB9 broadcast
- UE verifies the IBS signature immediately using the pre-provisioned Core Master Public Key (MPK)
- Establishes trust anchor for subsequent TESLA MAC verification
- Upon successful verification, RACH proceeds immediately

### 2. TESLA MAC (Delayed) — Returning UE
- gNB computes HMAC over the MAC auth input using the current interval's key; the tag is carried in **SIB1**
- Returning UE already has a TESLA trust anchor, so **SIB9 is not needed**
- UE buffers the message and verifies when key is disclosed in the next interval
- **RACH is blocked until verification completes**: the UE does not initiate random access until the TESLA MAC is successfully verified, ensuring SIB1 authenticity before any NAS messages (containing SUCI) are sent
- Provides lightweight re-authentication without expensive IBS signature verification
