# Security Analysis

[Back to Index](index.md)

---

## Threat Model

| Threat | Mitigated | Mechanism |
|--------|-----------|-----------|
| Fake base station | Yes | BLS signature verification |
| Message tampering | Yes | Signature + MAC verification |
| Signature replay attack | Yes | Wall-clock timestamp validation (±60s window) |
| Replay attack (recent) | Yes | Interval check in safe packet test |
| Key compromise | Partial | Delayed disclosure limits exposure |

---

## Security Properties

1. **Source Authentication**: BLS signature proves message originated from legitimate gNB
2. **Message Integrity**: Both signature and MAC protect against tampering
3. **Timeliness**: Interval tracking detects stale/replayed messages
4. **Key Chain Integrity**: Each disclosed key is verified to chain to K_0

---

## RFC 4082 Compliance

**Critical Requirement** (Section 3.3 - Bootstrapping Receivers):

> "One authenticated key of the one-way key chain. (Typically, this will be the last key in the chain;
> i.e., K_0. This key will be signed by the sender, and all receivers will verify the signature
> with the public key of the signer.)"

**Implementation**:
- K_0 is included in the BLS-signed `auth_input` along with SIB1 content
- UE verifies signature BEFORE accepting K_0 into state
- Without signature verification, K_0 is NOT trusted and TESLA is not used
- Disclosed keys must chain to authenticated K_0 via one-way function F

**Key Provisioning**: The UE loads the gNB public key from a binary file specified via `--tesla-gnb-pubkey` command-line parameter (default: `./tesla_keys/gnb_tesla_pubkey.bin`). See [Build Configuration](build.md) for key generation instructions.

---

## Limitations

| Limitation | Description | Mitigation |
|------------|-------------|------------|
| Key distribution | UE needs gNB public key file | Use `--tesla-gnb-pubkey` parameter or default path |
| Finite chain lifetime | ~21.8 minutes | Future: chain renewal mechanism |
| Bootstrap trust | First SIB1 must be trusted | BLS signature provides immediate trust |
| Memory usage | 1MB for key chain (65536 × 16B) | Configurable chain length |
| Self-signed certificates | No CA chain verification | Future: proper PKI infrastructure |

---

## Attack Resistance

### Fake Base Station Attack
- Attacker cannot forge BLS signatures without private key
- Attacker cannot predict future TESLA keys (one-way function)
- Attacker cannot replay old messages (interval check)

### Replay Attack
- **Signature replay**: Wall-clock timestamp in extension (signed by BLS)
  - UE validates timestamp against local system time (GNSS/NTP synced)
  - Default window: ±60 seconds (configurable via `timestamp_window_ms`)
  - Attacker capturing and replaying old signed SIB1 is detected
- **Interval check**: Safe packet test detects stale messages

### Key Disclosure Attack
- Attacker learns K_{i-d} at interval i
- Cannot forge messages for intervals > i-d (keys not yet disclosed)
- Safe packet test ensures: x < i + d
