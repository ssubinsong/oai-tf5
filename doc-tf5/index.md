# TESLA Broadcast Authentication for 5G NR SIB1

**TF5 (TESLA for 5G) Implementation Documentation**

This documentation describes the TESLA (Timed Efficient Stream Loss-tolerant Authentication) protocol implementation for authenticating SIB1 broadcast messages in 5G NR, protecting UEs from fake base station attacks.

---

## Purpose

The TF5 TESLA implementation protects 5G NR User Equipment (UE) from **Fake Base Station (FBS)** attacks by authenticating System Information Block 1 (SIB1) broadcast messages.

**Problem**: In 5G NR, SIB1 is broadcast unencrypted and unauthenticated. An attacker can set up a rogue gNB that broadcasts malicious SIB1, potentially:
- Redirecting UEs to attacker-controlled networks
- Performing denial-of-service attacks
- Enabling man-in-the-middle attacks

**Solution**: TESLA provides broadcast authentication without requiring per-UE state on the gNB, making it suitable for the broadcast nature of SIB1.

## Reference

- **RFC 4082**: Timed Efficient Stream Loss-Tolerant Authentication (TESLA)
- Location in repo: `claude-ref/rfc/rfc4082.txt`

## Key Features

| Feature | Description |
|---------|-------------|
| Delayed key disclosure | Keys revealed one interval after use |
| Dual authentication | Ed25519 signature + TESLA MAC |
| HFN tracking | Handles SFN wraparound for long key chains |
| Conditional compilation | Enabled via `TF5_ENABLE_TESLA` flag |

---

## Documentation Index

### Core Protocol
- [Protocol Design](protocol.md) - Key chains, time intervals, disclosure delay, dual authentication
- [Cryptographic Primitives](cryptography.md) - Algorithms, key derivation, MAC computation

### Data Structures
- [Data Structures](data-structures.md) - Static/dynamic parameters, extension format, state structures

### Implementation
- [gNB Implementation](gnb-implementation.md) - gNB-side initialization and transmission flow
- [UE Implementation](ue-implementation.md) - UE-side verification and reception flow
- [HFN Tracking](hfn-tracking.md) - Hyper-Frame Number tracking for SFN wraparound
- [Time Synchronization](time-sync.md) - Time sync model, D calculation, and safe packet test

### Integration
- [Integration Points](integration.md) - File locations and OAI structure modifications
- [API Reference](api-reference.md) - Complete function reference for gNB and UE

### Build & Configuration
- [Build Configuration](build.md) - CMake options, build commands, dependencies

### Security
- [Security Analysis](security.md) - Threat model, security properties, attack resistance

### Reference
- [Appendix](appendix.md) - Configuration parameters, error codes, logging
