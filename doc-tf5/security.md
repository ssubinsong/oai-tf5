# Security Analysis

[Back to Index](index.md)

---

## Threat Model

| Threat | Mitigated | Mechanism |
|--------|-----------|-----------|
| Fake base station | Yes | Ed25519 signature verification |
| Message tampering | Yes | Signature + MAC verification |
| Replay attack (recent) | Yes | Interval check in safe packet test |
| Replay attack (old HFN cycle) | Yes | HFN mismatch detection |
| Key compromise | Partial | Delayed disclosure limits exposure |

---

## Security Properties

1. **Source Authentication**: Ed25519 signature proves message originated from legitimate gNB
2. **Message Integrity**: Both signature and MAC protect against tampering
3. **Timeliness**: Interval tracking detects stale/replayed messages
4. **Key Chain Integrity**: Each disclosed key can be verified against K_0

---

## Limitations

| Limitation | Description | Mitigation |
|------------|-------------|------------|
| Pre-provisioned keys | UE needs gNB public key | Future: certificate-based distribution |
| Finite chain lifetime | ~21.8 minutes | Future: chain renewal mechanism |
| Bootstrap trust | First SIB1 must be trusted | Ed25519 signature provides immediate trust |
| Memory usage | 1MB for key chain (65536 × 16B) | Configurable chain length |

---

## Attack Resistance

### Fake Base Station Attack
- Attacker cannot forge Ed25519 signatures without private key
- Attacker cannot predict future TESLA keys (one-way function)
- Attacker cannot replay old messages (HFN/interval check)

### Replay Attack
- Same SFN cycle: Interval check detects stale messages
- Different HFN cycle: HFN mismatch detection (±1 tolerance)

### Key Disclosure Attack
- Attacker learns K_{i-d} at interval i
- Cannot forge messages for intervals > i-d (keys not yet disclosed)
- Safe packet test ensures: x < i + d
