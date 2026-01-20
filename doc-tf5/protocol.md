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
| T_int | 20 ms | Interval duration |
| chain_len | 65536 | Number of intervals |
| Duration | ~21.8 minutes | Total key chain lifetime |

**Interval Index Calculation**:
```
i = floor((current_time - T_0) / T_int)
```

Where `T_0` is the start time of interval 0, specified in static parameters using (HFN, SFN, slot).

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
