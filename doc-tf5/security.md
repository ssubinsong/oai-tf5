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
4. **Key Chain Integrity**: Each disclosed key is verified to chain to K_0

---

## RFC 4082 Compliance

**Critical Requirement** (Section 3.3 - Bootstrapping Receivers):

> "One authenticated key of the one-way key chain. (Typically, this will be the last key in the chain;
> i.e., K_0. This key will be signed by the sender, and all receivers will verify the signature
> with the public key of the signer.)"

**Implementation**:
- K_0 is included in the Ed25519-signed `auth_input` along with SIB1 content
- UE verifies signature BEFORE accepting K_0 into state
- Without signature verification, K_0 is NOT trusted and TESLA is not used
- Disclosed keys must chain to authenticated K_0 via one-way function F

**Design Assumption**: The UE has a pre-provisioned gNB public key (AssertFatal if missing)

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
