# Appendix

[Back to Index](index.md)

---

## A. Configuration Parameters

| Parameter | Default | Range | Description |
|-----------|---------|-------|-------------|
| `TF5_TESLA_KEY_LEN` | 16 | Fixed | TESLA key size (128 bits) |
| `TF5_TESLA_TAG_LEN` | 16 | Fixed | MAC tag size (128 bits) |
| `TF5_TESLA_SIG_LEN` | 64 | Fixed | Ed25519 signature size |
| `TF5_TESLA_CHAIN_LEN` | 65536 | 1-2^32 | Key chain length |
| `T_int` | 20ms | Configurable | Interval duration |
| `d` | 1 | 1-255 | Disclosure delay |

---

## B. Error Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| -1 | Invalid parameter (NULL pointer) |
| -2 | Buffer too small |
| -3 | Memory allocation failed |
| -4 | Cryptographic operation failed |
| -5 | Signature verification failed |
| -6 | Key chain verification failed |

---

## C. Logging

TESLA operations are logged using OAI logging macros:

```c
LOG_I(NR_RRC, "TESLA: ...")  // Informational
LOG_D(NR_RRC, "TESLA: ...")  // Debug
LOG_W(NR_RRC, "TESLA: ...")  // Warning
LOG_E(NR_RRC, "TESLA: ...")  // Error
```

**Key log messages**:
- gNB initialization: Public key logged for UE provisioning
- Signature verification: Success/failure logged
- HFN tracking: Initialization and mismatch warnings
- Buffered verification: Success/failure of delayed verification
