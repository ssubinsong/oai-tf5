# Identity-Based Signatures (IBS) for TESLA

[Back to Index](index.md)

---

## Overview

TF5 uses an **Identity-Based Signature (IBS)** scheme for authenticating the initial TESLA key disclosure. This allows UEs to verify gNB signatures using only:

1. **Core's Master Public Key (MPK)** - Pre-provisioned in UE (e.g., SIM card)
2. **gNB's Cell ID** - Extracted from SIB1's `cellIdentity` field
3. **Key Validity Period** - Included in TESLA extension (expiration time)

This eliminates the need to distribute individual gNB public keys to UEs and enables key expiration.

---

## Cryptographic Scheme

### BLS12-381 Based IBS (pk-in-G2 Variant)

| Parameter | Description | Size |
|-----------|-------------|------|
| `s` | Core master secret (scalar in Z_r) | 32 bytes |
| `MPK = s*Q` | Core master public key (G2 point) | 96 bytes |
| `Cell_ID` | gNB's NR Cell ID | 5 bytes (36 bits) |
| `gnb_key_validity_end` | Key expiration (minutes since 2024-01-01 UTC) | 3 bytes (24 bits) |
| `pk_ID = H_s(Cell_ID ‖ gnb_key_validity_end)` | Identity-derived scalar | 32 bytes |
| `sk_ID = s * pk_ID mod r` | gNB's secret key (issued by Core) | 32 bytes |
| `Σ = sk_ID * H_m(m)` | Signature (G1 point) | 48 bytes |

**Key Identity Construction:**
```
Identity = Cell_ID (5 bytes) || gnb_key_validity_end (3 bytes, big-endian)
pk_ID = H_s(Identity)
```

The gnb_key_validity_end is encoded as minutes since the epoch 2024-01-01 00:00:00 UTC (Unix timestamp 1704067200).
Maximum value 0xFFFFFF = 16,777,215 minutes ≈ 31.9 years (until ~2056).

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

gNB-specific Keys (issued per Cell ID + validity)
    │
    └──> sk_ID = s * H_s(Cell_ID || gnb_key_validity_end) mod r
         └── sk_gnb.bin (32B) - gNB Secret Key (valid until expiration)
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
# Issue key for gNB with Cell ID 0x123456789, valid for 2 years (1051200 minutes)
./tf5_ibs_issue pkg_keys/msk.bin 123456789 1051200 gnb_keys/sk_gnb1.bin
```

### 3. Deployment

**gNB** (loads secret key and specifies validity):

```bash
./nr-softmodem -O gnb.conf \
    --tesla-privkey /path/to/sk_gnb.bin \
    --tesla-key-validity-end 1051200
```

**UE** (loads Core's MPK):
```bash
./nr-uesoftmodem -O ue.conf --tesla-core-mpk /path/to/mpk.bin
```

### 4. Runtime Verification

1. UE receives SIB1 with TESLA extension (includes signature Σ and gnb_key_validity_end)
2. UE extracts `Cell_ID` from SIB1's `cellAccessRelatedInfo`
3. UE extracts `gnb_key_validity_end` from TESLA extension
4. **UE checks expiration**: if current_time >= gnb_key_validity_end, reject
5. UE computes `pk_ID = H_s(Cell_ID || gnb_key_validity_end)`
6. UE computes `derived_pk = pk_ID * MPK`
7. UE verifies: `e(Σ, Q) = e(H_m(auth_input), derived_pk)`

---

## Security Properties

### Identity and Validity Binding
The gNB's secret key is cryptographically bound to both its Cell ID and validity period:
- `sk_ID = s * H_s(Cell_ID || gnb_key_validity_end)`
- Changing Cell ID or gnb_key_validity_end invalidates the key
- UE derives verification key from Cell ID (in SIB1) and gnb_key_validity_end (in extension)

### Key Expiration
- Keys have a finite validity period set at issuance time
- UE rejects SIB1 if the embedded gnb_key_validity_end has passed
- Compromised keys become unusable after expiration

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

The TESLA extension uses HMAC-SHA256 for MAC computation and IBS (BLS12-381 based) for signatures.
