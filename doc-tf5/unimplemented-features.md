# Unimplemented Features

[Back to Index](index.md)

---

This document catalogs features described in the TF5 research paper that are not yet implemented in the main `tf5` branch. It serves as a roadmap for future development and clarifies the gap between the paper's design and the current implementation.

## Status Legend

- **Not Implemented**: No functional code exists (may have ASN.1 declarations only)

---

## 1. HFN (Hyper-Frame Number) Tracking

**Description**: Full RRC-layer HFN tracking to extend replay protection beyond the 10.24-second SFN wrap cycle.

The System Frame Number (SFN) is a 10-bit counter (0-1023) that wraps every 10.24 seconds. To extend replay protection for TESLA key chains that span longer periods, the paper describes a Hyper-Frame Number (HFN)---a 10-bit counter that increments each time the SFN wraps from 1023 to 0.

**Architecture (per paper)**:
1. The lower layer (MAC for gNB, PHY for UE) detects the SFN wrap event
2. An internal notification (`NRRRC_SFN_WRAP`) is sent to the RRC layer
3. RRC increments its HFN counter, which serves as the single source of truth for TESLA interval computation

This extends replay protection from 10.24 seconds (one SFN cycle) to approximately 2.9 hours (one HFN cycle).

**Current Status**: Not implemented. ASN.1 declaration exists in OAI but no actual tracking logic is present. SFN wrap-around (every 10.24 seconds) is assumed not to occur during experiments since SFN and slots start from 0 at bootup.

**Rationale for Deferral**: Current evaluation scope uses short sessions where SFN wrap-around does not occur.

---

## 2. Neighbor TESLA Broadcast

**Description**: Complete neighbor broadcast mechanism for efficient handover without IBS re-verification.

When a UE performs cell reselection, it normally must perform expensive IBS (BLS pairing) verification to trust the new cell's TESLA parameters. The neighbor broadcast mechanism enables UEs to skip IBS verification by using cached TESLA parameters from neighboring cells that have been attested by multiple serving cells.

**Current Status**: Not implemented.

### Sub-components

#### SIBn-TF5
A new System Information Block carrying neighbor TESLA parameters:
- Up to 16 neighbor entries per SIBn-TF5
- Each entry contains: Cell ID, PCI, carrier frequency, TESLA parameters, checkpoint commitment
- Authenticated by the serving cell's TESLA MAC (`teslaTag-tf5`)

#### Inter-gNB Protocol
gNBs share TESLA parameters via `TESLA_ANNOUNCE` messages over trusted backhaul:
- Cell ID and TESLA static parameters
- T0 timing (HFN/SFN/slot)
- Sync domain ID for timing compatibility
- All checkpoint commitments
- Optional next-chain parameters for seamless renewal

#### Checkpoint Verification
O(C) verification speedup using blinded checkpoint commitments:
- Instead of verifying against K0 (up to N hash operations), verify against nearest checkpoint
- With checkpoint periodicity C, verification requires at most C-1 hash operations
- Commitments are blinded: `Commit(K_kC)` - neighbors never learn actual keys

#### Multi-Cell Attestation
Byzantine fault tolerance for neighbor cache:
- UE maintains attestation count for each cached neighbor entry
- Entry trusted only if attested by >= n independent cells (default n=2)
- Protects against up to n-1 compromised cells
- Mismatch handling: reset cache entry on conflicting commitments

#### UE Neighbor Cache
- Bounded by UE memory constraints (e.g., 32 entries)
- LRU eviction and expiration based on validity period
- Stores per neighbor: PCI, carrier frequency, current checkpoint commitment, attestation count, attestor list

#### gNB Neighbor Cache
- Bounded by deployment configuration (e.g., 16 entries)
- LRU eviction and expiration based on key validity
- Stores per neighbor: Cell ID, TESLA parameters, all checkpoint commitments, active checkpoint index, next chain parameters

**Rationale for Deferral**:
- Requires multi-cell testbed for proper evaluation
- Core single-cell authentication must be stable first
- Adds significant complexity to ASN.1 definitions

---

## 3. Chain Renewal Optimization

**Description**: Pre-announcement mechanism for seamless TESLA chain transitions without IBS re-verification.

TESLA uses a finite key chain of length N. When the chain is exhausted, the gNB must switch to a new chain with a new root key K'0. Without chain renewal optimization, returning UEs would need to perform expensive IBS signature verification to trust the new chain.

**Pre-Announcement**:
- gNB pre-announces next chain's parameters before current chain exhaustion
- Broadcast via SIBn-TF5 includes:
  - T0 for the next chain (HFN/SFN/slot)
  - K0 commitment: `Commit(K'0)`
  - `sameParams` flag: if true, new chain inherits parameters from current chain
  - If `sameParams` is false, new parameters included explicitly

**Chain Transition**:
1. UE detects chain transition (new T0)
2. If cached next-chain params exist, verify: `Commit(K_disclosed) == cached commitment`
3. If verification succeeds, apply new params and continue with TESLA (no IBS needed)
4. If verification fails or no cached params, fall back to IBS signature verification

**Current Status**: Not implemented. When the chain expires, the current implementation requires full IBS re-verification.

**Rationale for Deferral**:
- Requires neighbor broadcast infrastructure for optimal benefit
- Current chain length (65536 intervals = ~21.8 minutes) is sufficient for evaluation
- Lower priority than core authentication

---

## 4. IBS Signature Batch Verification

**Description**: Amortize pairing costs across multiple BLMQ IBS signatures during cell selection/reselection.

During cell selection and reselection, UEs detect and measure multiple candidate cells, ranking them by signal quality before selecting the best one (3GPP TS 38.304). This procedure inherently requires authenticating signatures from several gNBs.

BLMQ IBS verification uses a single pairing per signature (via multi-Miller loop). Batch verification could further reduce costs by sharing final exponentiation across multiple verifications.

**Current Status**: Not implemented. The current implementation verifies one BLMQ IBS signature at a time via a single-pairing check.

**Rationale for Deferral**:
- Requires neighbor broadcast infrastructure (UE needs to receive SIB1 from multiple cells)
- Current single-cell evaluation does not exercise multi-cell scenarios
- Optimization benefit is marginal for small n (e.g., 2-3 candidate cells)

---

## Summary

| Feature | Status | Dependencies |
|---------|--------|--------------|
| HFN Tracking | Not implemented | None (independent) |
| Neighbor TESLA Broadcast | Not implemented | Multi-cell testbed |
| Chain Renewal Optimization | Not implemented | Neighbor broadcast (for optimal path) |
| BLS Batch Verification | Not implemented | Multi-cell scenario |

---

## Implementation Roadmap

### Phase 1: Core Stabilization (Current)
- Complete single-cell authentication
- Validate performance on real hardware

### Phase 2: HFN Tracking
- Implement RRC-layer HFN tracking
- Enable long-session support (>10.24 seconds)

### Phase 3: Multi-Cell Foundation
- Implement neighbor broadcast infrastructure
- Deploy multi-cell testbed

### Phase 4: Optimization
- Implement chain renewal pre-announcement
- Fine-tune checkpoint periodicity
