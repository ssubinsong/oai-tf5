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
| chain_len | Scaled to maintain ~21.8 min lifetime | Number of intervals |
| Duration | ~21.8 minutes | Total key chain lifetime |

**Interval Index Calculation**:
```
i = floor((current_time - T_0) / T_int)
```

Where `T_0` is the start time of interval 0, aligned with the first SIB1 transmission occasion.

### T_int Alignment with SIB1 Repetition Period

Per **3GPP TS 38.331 Section 5.2.1.2**, the TESLA interval duration (T_int) is aligned with the SIB1 repetition transmission period:

| SSB/CORESET Mux Pattern | SIB1 Repetition Period | T_int |
|-------------------------|------------------------|-------|
| Pattern 1 (FR1, FR2 common) | 20 ms (fixed) | 20 ms |
| Pattern 2 (FR2 120/240kHz SSB) | SSB period | SSB period |
| Pattern 3 (FR2 120kHz SSB/PDCCH) | SSB period | SSB period |

**SSB Period Values**:

| Enum | Period |
|------|--------|
| 0 | 5 ms |
| 1 | 10 ms |
| 2 | 20 ms |
| 3 | 40 ms |
| 4 | 80 ms |
| 5 | 160 ms |

### T_0 Alignment with First SIB1 Transmission

T_0 is set to the first SIB1 transmission occasion (SSB index 0):
- **Mux pattern 1**: First frame where `(SFN % 2 == sfn_c)`, at slot `n_0`
- **Mux patterns 2/3**: Based on SSB timing, slot `n_c`

### Chain Length Scaling

To maintain a consistent key chain lifetime of ~21.8 minutes regardless of T_int, the chain length is scaled:

```
chain_len = (65536 * 20) / T_int_ms
```

| T_int | chain_len | Lifetime |
|-------|-----------|----------|
| 5 ms | 262144 | ~21.8 min |
| 10 ms | 131072 | ~21.8 min |
| 20 ms | 65536 | ~21.8 min |
| 40 ms | 32768 | ~21.8 min |
| 80 ms | 16384 | ~21.8 min |
| 160 ms | 8192 | ~21.8 min |

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

---

## Dual Authentication Mechanism

TF5 implements **two authentication mechanisms**:

### 1. Ed25519 Signature (Immediate)
- gNB signs the authentication input with its private key
- UE verifies immediately if it has the pre-provisioned public key
- Provides strong authentication without waiting

### 2. TESLA MAC (Delayed)
- gNB computes HMAC using the current interval's key
- UE buffers the message and verifies when key is disclosed
- Provides authentication even without pre-provisioned keys
