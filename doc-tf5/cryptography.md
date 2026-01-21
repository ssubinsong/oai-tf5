# Cryptographic Primitives

[Back to Index](index.md)

**Source**: [tf5_tesla.c](../openair3/SECU/tf5_tesla.c)

---

## Algorithm Summary

| Primitive | Algorithm | Key/Output Size |
|-----------|-----------|-----------------|
| Key chain derivation | HMAC-SHA256(K, 0x00) | 128 bits (truncated) |
| MAC key derivation | HMAC-SHA256(K, 0x01) | 256 bits |
| TESLA tag | HMAC-SHA256(K', data) | 128 bits (truncated) |
| Signature | Ed25519 | 512 bits |

---

## Key Chain Function (F)

**Source**: [tf5_tesla.c:62](../openair3/SECU/tf5_tesla.c#L62) `tf5_tesla_chain_key()`

Derives the previous key in the chain:
```c
K_i = F(K_{i+1}) = HMAC-SHA256(K_{i+1}, 0x00)[0:15]
```

Implementation:
```c
void tf5_tesla_chain_key(const uint8_t key_next[16], uint8_t key_out[16]) {
    uint8_t hmac_out[32];
    uint8_t constant = 0x00;
    HMAC(EVP_sha256(), key_next, 16, &constant, 1, hmac_out, NULL);
    memcpy(key_out, hmac_out, 16);  // Truncate to 128 bits
}
```

---

## MAC Key Derivation (F')

**Source**: [tf5_tesla.c:48](../openair3/SECU/tf5_tesla.c#L48) `tf5_tesla_derive_mac_key()`

Derives the MAC key from a TESLA key:
```c
K'_i = F'(K_i) = HMAC-SHA256(K_i, 0x01)
```

This separation ensures that revealing K_i doesn't directly expose the MAC key used.

---

## TESLA Tag Computation

**Source**: [tf5_tesla.c:79](../openair3/SECU/tf5_tesla.c#L79) `tf5_tesla_compute_tag()`

```c
tag = HMAC-SHA256(K'_i, auth_input)[0:15]
```

The tag is truncated to 128 bits (16 bytes) for efficiency.

---

## Authentication Input

The signature and MAC use different authentication inputs per RFC 4082:

### Signature Auth Input

**Source**: [tf5_tesla.c:196](../openair3/SECU/tf5_tesla.c#L196) `tf5_tesla_build_sig_auth_input()`

```
sig_auth_input = original_SIB1 || static_params || timesync_info || interval_index || disclosed_key || timestamp_ms
```

- **original_SIB1**: SIB1 content without TESLA extension
- **static_params**: 30 bytes of static TESLA parameters
- **timesync_info**: 6 bytes of timing information
- **interval_index**: 4 bytes current interval
- **disclosed_key**: 16 bytes K_{i-d}
- **timestamp_ms**: 8 bytes Unix epoch timestamp (milliseconds) for replay protection

### MAC Auth Input

**Source**: [tf5_tesla.c:149](../openair3/SECU/tf5_tesla.c#L149) `tf5_tesla_build_mac_auth_input()`

Per RFC 4082, the MAC does NOT include the interval index, disclosed key, or timestamp:
```
mac_auth_input = original_SIB1 || static_params || timesync_info
```

- **original_SIB1**: SIB1 content without TESLA extension
- **static_params**: 30 bytes of static TESLA parameters
- **timesync_info**: 6 bytes of timing information
