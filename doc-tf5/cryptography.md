# Cryptographic Primitives

[Back to Index](index.md)

**Source**: [tf5_tesla.c](../openair3/SECU/tf5_tesla.c), [tf5_crypto.h](../openair3/SECU/tf5_crypto.h)/[tf5_crypto.c](../openair3/SECU/tf5_crypto.c) (SHA-256/HMAC primitives)

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

TF5 uses BLS12-381 IBS (pk-in-G2 variant) for authenticating the initial TESLA
key disclosure. For the full cryptographic specification (algorithms, security
analysis, domain separation tags), see [pkg-cryptography.md](pkg-cryptography.md).

### Key File Format

Keys are stored as raw binary files:
- **Master secret key (msk)**: 32-byte scalar (big-endian)
- **Master public key (mpk)**: 96-byte compressed G2 point
- **gNB secret key (sk_ID)**: 32-byte scalar (big-endian)

### Sign Operation

```c
int tf5_bls_sign(const uint8_t secret_key[32],  // sk_ID
                 const uint8_t *data,
                 size_t data_len,
                 uint8_t signature[48]);
```

### IBS Verify Operation

```c
int tf5_sig_verify(const uint8_t mpk[96],           // Core's MPK
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

**Source**: [tf5_tesla.c](../openair3/SECU/tf5_tesla.c) `tf5_chain_key()`

Derives the previous key in the chain:
```c
K_i = F(K_{i+1}) = SHA-256(0x00 || K_{i+1})[0:15]
```

Implementation:
```c
void tf5_chain_key(const uint8_t key_next[16], uint8_t key_out[16]) {
    uint8_t input[1 + 16];
    input[0] = 0x00;  // Domain separation prefix
    memcpy(input + 1, key_next, 16);
    uint8_t hash_out[32];
    tf5_sha256(input, sizeof(input), hash_out);
    memcpy(key_out, hash_out, 16);  // Truncate to 128 bits
}
```

---

## MAC Key Derivation (F')

**Source**: [tf5_tesla.c](../openair3/SECU/tf5_tesla.c) `tf5_derive_mac_key()`

Derives the MAC key from a TESLA key:
```c
K'_i = F'(K_i) = SHA-256(0x01 || K_i)
```



This separation ensures that F and F' are cryptographically independent functions,
so revealing K_i doesn't directly expose the MAC key used.

---

## TESLA Tag Computation

**Source**: [tf5_tesla.c:46](../openair3/SECU/tf5_tesla.c#L46) `tf5_compute_tag()`

```c
tag = HMAC-SHA256(K'_i, auth_input)[0:15]
```

The tag is truncated to 128 bits (16 bytes) for efficiency.

---

## Authentication Input

The signature and MAC use different authentication inputs:

### Signature Auth Input

**Source**: [tf5_tesla.c](../openair3/SECU/tf5_tesla.c) `tf5_build_sig_auth_input()`

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

**Source**: [tf5_tesla.c](../openair3/SECU/tf5_tesla.c) `tf5_build_mac_auth_input()`

Per RFC 4082, the MAC does NOT include interval index and key disclosure.
Additionally, `tesla_params` is excluded as it is already authenticated by
the BLS signature during first-time UE verification:
```
mac_auth_input = original_SIB1 || validity_end
```

- **original_SIB1**: SIB1 content without TESLA extension
- **validity_end**: 3 bytes key expiration (minutes since 2024-01-01, big-endian)
