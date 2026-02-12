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

## Documentation Index

### Core Protocol
- [Protocol Design](protocol.md) - Key chains, time intervals, disclosure delay, dual authentication
- [Cryptographic Primitives](cryptography.md) - Algorithms, key derivation, MAC computation
- [IBS Protocol Specification](pkg-cryptography.md) - BLS12-381 IBS scheme, Core PKG, key hierarchy, security analysis

### Data Structures
- [Data Structures](data-structures.md) - Static/dynamic parameters, extension format, state structures

### Implementation
- [gNB Implementation](gnb-implementation.md) - gNB-side initialization and transmission flow
- [UE Implementation](ue-implementation.md) - UE-side verification and reception flow
- [Time Synchronization](time-sync.md) - Time sync model, D calculation, and safe packet test

### Integration
- [Integration Points](integration.md) - File locations and OAI structure modifications

### Build & Configuration
- [Build Configuration](build.md) - CMake options, build commands, dependencies
- [TESLA Configuration](tesla-config.md) - TESLA-optimized gNB config file and parameter rationale

### Roadmap
- [Unimplemented Features](unimplemented-features.md) - Features described in the paper not yet implemented
