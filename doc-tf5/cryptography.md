# Cryptographic Primitives

[Back to Index](index.md)

**Source**: [tf5_tesla.c](../openair3/SECU/tf5_tesla.c)

---

## Algorithm Summary

| Primitive | Algorithm | Key/Output Size |
|-----------|-----------|-----------------|
| Key chain derivation | SHA-256(0x00 \|\| K) | 128 bits (truncated) |
| MAC key derivation | SHA-256(0x01 \|\| K) | 256 bits |
| TESLA tag | HMAC-SHA256(K', data) | 128 bits (truncated) |
| Signature | BLS12-381 IBS (pk-in-G2) | 384 bits (48 bytes) |

---

## Identity-Based Signature (IBS) Scheme

**Source**: [tf5_tesla_sig.c](../openair3/SECU/tf5_tesla_sig.c)

For full IBS documentation, see [ibs-overview.md](ibs-overview.md).

Uses the blst library (Supranational) with BLS12-381 curve in pk-in-G2 mode
for Identity-Based Signatures:

| Component | Size | Group |
|-----------|------|-------|
| Master secret (s) | 32 bytes | Scalar |
| Master public key (MPK) | 96 bytes | G2 point (compressed) |
| gNB secret key (sk_ID) | 32 bytes | Scalar |
| Signature (Σ) | 48 bytes | G1 point (compressed) |

### IBS Scheme

```
Sign:   Σ = sk_ID * H_m(message)
Verify: e(Σ, Q) = e(H_m(message), pk_ID * MPK)
```

Where `pk_ID = H_s(Cell_ID || validity_end)` is the identity-derived scalar.

**Identity IKM Construction:**
```
IKM = DST (35 bytes) || Cell_ID (5 bytes) || validity_end (3 bytes, big-endian)
pk_ID = blst_keygen(IKM) mod r
```

The `validity_end` is encoded as minutes since 2024-01-01 00:00:00 UTC (epoch 1704067200).

### Domain Separation Tags

| Function | DST |
|----------|-----|
| H_s (identity to scalar) | `TF5_IBS_BLS12381_XMD:SHA-256_H_s_v1` |
| H_m (message to G1) | `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_` |

### Key File Format

Keys are stored as raw binary files:
- **Master secret key (msk)**: 32-byte scalar (big-endian)
- **Master public key (mpk)**: 96-byte compressed G2 point
- **gNB secret key (sk_ID)**: 32-byte scalar (big-endian)

### Sign Operation

```c
int tf5_tesla_bls_sign(const uint8_t secret_key[32],  // sk_ID
                       const uint8_t *data,
                       size_t data_len,
                       uint8_t signature[48]);
```

### IBS Verify Operation

```c
int tf5_tesla_ibs_verify(const uint8_t mpk[96],           // Core's MPK
                          const uint8_t cell_id[5],        // gNB's Cell ID
                          uint32_t validity_end,           // Key expiration (minutes since 2024-01-01)
                          const uint8_t *data,
                          size_t data_len,
                          const uint8_t signature[48]);
```

The verification derives `pk_ID = H_s(cell_id || validity_end)` and computes
`derived_pk = pk_ID * MPK` for pairing verification.

---

## Key Chain Function (F)

**Source**: [tf5_tesla.c](../openair3/SECU/tf5_tesla.c) `tf5_tesla_chain_key()`

Derives the previous key in the chain:
```c
K_i = F(K_{i+1}) = SHA-256(0x00 || K_{i+1})[0:15]
```

Implementation:
```c
void tf5_tesla_chain_key(const uint8_t key_next[16], uint8_t key_out[16]) {
    uint8_t input[1 + 16];
    input[0] = 0x00;  // Domain separation prefix
    memcpy(input + 1, key_next, 16);
    uint8_t hash_out[32];
    SHA256(input, sizeof(input), hash_out);
    memcpy(key_out, hash_out, 16);  // Truncate to 128 bits
}
```

---

## MAC Key Derivation (F')

**Source**: [tf5_tesla.c](../openair3/SECU/tf5_tesla.c) `tf5_tesla_derive_mac_key()`

Derives the MAC key from a TESLA key:
```c
K'_i = F'(K_i) = SHA-256(0x01 || K_i)
```



This separation ensures that F and F' are cryptographically independent functions,
so revealing K_i doesn't directly expose the MAC key used.

---

## TESLA Tag Computation

**Source**: [tf5_tesla.c:79](../openair3/SECU/tf5_tesla.c#L79) `tf5_tesla_compute_tag()`

```c
tag = HMAC-SHA256(K'_i, auth_input)[0:15]
```

The tag is truncated to 128 bits (16 bytes) for efficiency.

---

## Authentication Input

The signature and MAC use different authentication inputs:

### Signature Auth Input

**Source**: [tf5_tesla.c](../openair3/SECU/tf5_tesla.c) `tf5_tesla_build_sig_auth_input()`

```
sig_auth_input = original_SIB1 || te_version || tesla_params || validity_end || i || key_disclosure || timestamp_ms
```

- **original_SIB1**: SIB1 content without TESLA extension
- **te_version**: 1 byte protocol version
- **tesla_params**: 11 bytes of TESLA parameters (includes T_0)
- **validity_end**: 3 bytes key expiration (minutes since 2024-01-01)
- **i**: 4 bytes current interval index
- **key_disclosure**: 16 bytes K_{i-d}
- **timestamp_ms**: 3 bytes Unix epoch timestamp LSB (milliseconds) for signature replay protection

### MAC Auth Input

**Source**: [tf5_tesla.c](../openair3/SECU/tf5_tesla.c) `tf5_tesla_build_mac_auth_input()`

Per RFC 4082, the MAC does NOT include interval index and key disclosure.
Additionally, `tesla_params` is excluded as it is already authenticated by
the BLS signature during first-time UE verification:
```
mac_auth_input = original_SIB1 || validity_end
```

- **original_SIB1**: SIB1 content without TESLA extension
- **validity_end**: 3 bytes key expiration (minutes since 2024-01-01, big-endian)
