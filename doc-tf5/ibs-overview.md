# Identity-Based Signatures (IBS) for TESLA

[Back to Index](index.md)

---

## Overview

TF5 uses an **Identity-Based Signature (IBS)** scheme for authenticating the initial TESLA key disclosure. This allows UEs to verify gNB signatures using only:

1. **Core's Master Public Key (MPK)** - Pre-provisioned in UE (e.g., SIM card)
2. **gNB's Cell ID** - Extracted from SIB1's `cellIdentity` field

This eliminates the need to distribute individual gNB public keys to UEs.

---

## Cryptographic Scheme

### BLS12-381 Based IBS (pk-in-G2 Variant)

| Parameter | Description | Size |
|-----------|-------------|------|
| `s` | Core master secret (scalar in Z_r) | 32 bytes |
| `MPK = s*Q` | Core master public key (G2 point) | 96 bytes |
| `ID` | gNB's NR Cell ID | 5 bytes (36 bits) |
| `pk_ID = H_s(ID)` | Identity-derived scalar | 32 bytes |
| `sk_ID = s * pk_ID mod r` | gNB's secret key (issued by Core) | 32 bytes |
| `Σ = sk_ID * H_m(m)` | Signature (G1 point) | 48 bytes |

### Verification Equation

```
e(Σ, Q) = e(H_m(m), pk_ID * MPK)
```

Where:
- `e(·,·)` is the BLS12-381 pairing function
- `Q` is the G2 generator
- `H_m` is the hash-to-G1 function (message hash)
- `pk_ID * MPK` is scalar multiplication in G2

---

## Domain Separation Tags

| Function | DST |
|----------|-----|
| H_s (identity to scalar) | `TF5_IBS_BLS12381_XMD:SHA-256_H_s_v1` |
| H_m (message to G1) | `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_` |

---

## Key Hierarchy

```
Core PKG
    │
    └──> Master Keypair (one-time generation)
         ├── msk.bin (32B) - Master Secret Key (SECURE!)
         └── mpk.bin (96B) - Master Public Key (distribute to UEs)

gNB-specific Keys (issued per Cell ID)
    │
    └──> sk_ID = s * H_s(Cell_ID) mod r
         └── sk_gnb.bin (32B) - gNB Secret Key
```

---

## Workflow

### 1. Core PKG Setup (One-time)

```bash
# Generate master keypair
./tf5_ibs_pkg_keygen pkg_keys/msk.bin pkg_keys/mpk.bin
```

### 2. gNB Key Issuance

```bash
# Issue key for gNB with Cell ID 0x123456789 (36 bits)
./tf5_ibs_issue pkg_keys/msk.bin 123456789 gnb_keys/sk_gnb1.bin
```

### 3. Deployment

**gNB** (loads secret key):
```bash
./nr-softmodem -O gnb.conf --tesla-privkey /path/to/sk_gnb.bin
```

**UE** (loads Core's MPK):
```bash
./nr-uesoftmodem -O ue.conf --tesla-gnb-pubkey /path/to/mpk.bin
```

### 4. Runtime Verification

1. UE receives SIB1 with TESLA extension (includes signature Σ)
2. UE extracts `Cell_ID` from SIB1's `cellAccessRelatedInfo`
3. UE computes `pk_ID = H_s(Cell_ID)`
4. UE computes `derived_pk = pk_ID * MPK`
5. UE verifies: `e(Σ, Q) = e(H_m(auth_input), derived_pk)`

---

## Comparison with Standard BLS

| Aspect | Standard BLS | IBS |
|--------|--------------|-----|
| UE pre-provisioning | Per-gNB public key | Single Core MPK |
| Key management | Distribute each gNB's pk | Distribute one MPK |
| Adding new gNB | Update all UEs | No UE update needed |
| gNB identity binding | None | Cell ID bound to key |

---

## Security Properties

### Identity Binding
The gNB's secret key is cryptographically bound to its Cell ID:
- `sk_ID = s * H_s(Cell_ID)`
- Changing Cell ID invalidates the key
- UE derives verification key from Cell ID in SIB1

### Forward Security (Limited)
- Compromising one gNB's `sk_ID` doesn't expose other gNBs' keys
- Compromising master secret `s` allows forging all gNB keys

### Man-in-the-Middle Resistance
An attacker cannot:
- Sign SIB1 without knowing `sk_ID`
- Forge `sk_ID` without knowing master secret `s`
- Use another gNB's key (Cell ID mismatch detected)

---

## Implementation Files

| Component | File | Description |
|-----------|------|-------------|
| Core PKG | `tf5-core-pkg/src/tf5_ibs_keygen.c` | Master keypair generation |
| Core PKG | `tf5-core-pkg/src/tf5_ibs_issue.c` | gNB key issuance |
| Core PKG | `tf5-core-pkg/src/tf5_ibs_common.c` | H_s hash function |
| gNB | `openair3/SECU/tf5_tesla_sig.c` | Signing (unchanged from BLS) |
| UE | `openair3/SECU/tf5_tesla_sig.c` | IBS verification |
| UE | `openair2/RRC/NR_UE/rrc_UE.c` | Cell ID extraction |

---

## Wire Format

The IBS mode uses `crypto_suite_id = 0x03` in the TESLA extension header:

| Value | Mode |
|-------|------|
| 0x01 | Reserved (HMAC-SHA256 only) |
| 0x02 | Reserved (legacy BLS) |
| 0x03 | HMAC-SHA256 + IBS |

---

## References

- **BLS12-381**: [IETF draft-irtf-cfrg-pairing-friendly-curves](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves)
- **IBS**: Boneh-Franklin Identity-Based Encryption (adapted for signatures)
- **blst Library**: [github.com/supranational/blst](https://github.com/supranational/blst)
