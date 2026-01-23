# TF5 Identity-Based Signature Protocol Specification

## 1. Overview

This document specifies the Identity-Based Signature (IBS) scheme used for authenticating 5G NR SIB1 messages. The scheme allows UEs to verify gNB signatures using only:
- The Core's master public key (MPK), pre-provisioned in UE
- The gNB's NR Cell ID, extracted from the received SIB1

## 2. Cryptographic Primitives

### 2.1 Elliptic Curve

- **Curve:** BLS12-381
- **Variant:** Minimal signature size (pk-in-G2)
- **Groups:**
  - G1: 48-byte compressed points (signatures)
  - G2: 96-byte compressed points (public keys)
  - GT: Target group for pairing
- **Order:** r ≈ 2^255 (prime)

### 2.2 Bilinear Pairing

```
e: G1 × G2 → GT
```

Properties:
- Bilinearity: `e(aP, bQ) = e(P, Q)^(ab)`
- Non-degeneracy: `e(G1, G2) ≠ 1`

### 2.3 Hash Functions

**H_s: Identity → Scalar (Z_r)**
- Input: NR Cell ID (36 bits)
- Output: Scalar in Z_r
- Implementation: IETF hash-to-field via `blst_keygen` with DST
- DST: `"TF5_IBS_BLS12381_XMD:SHA-256_H_s_v1"`

**H_m: Message → G1**
- Input: Arbitrary-length message
- Output: Point in G1
- Implementation: IETF hash-to-curve via `blst_hash_to_g1`
- DST: `"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"`

## 3. Key Hierarchy

```
                    ┌─────────────────┐
                    │   Core PKG      │
                    │                 │
                    │  s (secret)     │
                    │  MPK = s*Q      │
                    └────────┬────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
           ▼                 ▼                 ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │   gNB 1      │  │   gNB 2      │  │   gNB N      │
    │              │  │              │  │              │
    │ Cell ID: ID1 │  │ Cell ID: ID2 │  │ Cell ID: IDN │
    │ sk_ID1       │  │ sk_ID2       │  │ sk_IDN       │
    └──────────────┘  └──────────────┘  └──────────────┘
```

## 4. Algorithms

### 4.1 Setup (Core PKG)

**Input:** Security parameter λ (implicit: BLS12-381)

**Output:** Master secret `s`, Master public key `MPK`

```
1. s ← random scalar in Z_r
2. MPK ← s * Q, where Q is the generator of G2
3. Return (s, MPK)
```

**File Output:**
- `msk.bin`: 32 bytes, `s` serialized big-endian
- `mpk.bin`: 96 bytes, `MPK` compressed

### 4.2 Key Issuance (Core PKG)

**Input:** Master secret `s`, gNB identity `ID` (NR Cell ID, 36 bits)

**Output:** gNB secret key `sk_ID`

```
1. pk_ID ← H_s(ID)           // Hash identity to scalar
2. sk_ID ← s * pk_ID mod r   // Scalar multiplication
3. Return sk_ID
```

**Properties:**
- `sk_ID` is a 32-byte scalar
- Different Cell IDs produce different keys
- Core can issue keys without gNB interaction

### 4.3 Sign (gNB)

**Input:** gNB secret key `sk_ID`, message `m`

**Output:** Signature `Σ`

```
1. h ← H_m(m)               // Hash message to G1
2. Σ ← sk_ID * h            // Scalar multiplication in G1
3. Return Σ
```

**Properties:**
- `Σ` is a 48-byte G1 point (compressed)
- Same algorithm as standard BLS signature
- `sk_ID` acts as the signing key

### 4.4 Verify (UE)

**Input:** Master public key `MPK`, identity `ID`, message `m`, signature `Σ`

**Output:** Accept or Reject

```
1. pk_ID ← H_s(ID)          // Derive identity-based public key (scalar)
2. PK ← pk_ID * MPK         // Compute verification key (G2 point)
3. h ← H_m(m)               // Hash message to G1
4. Accept iff e(Σ, Q) = e(h, PK)
```

**Verification Equation Derivation:**

```
e(Σ, Q) = e(sk_ID * h, Q)
        = e(h, Q)^sk_ID
        = e(h, sk_ID * Q)

pk_ID * MPK = pk_ID * (s * Q)
            = (pk_ID * s) * Q
            = (s * pk_ID) * Q
            = sk_ID * Q

Therefore: e(Σ, Q) = e(h, sk_ID * Q) = e(h, pk_ID * MPK) = e(h, PK)
```

## 5. Message Format

The signature is computed over the TESLA authentication input:

```
auth_input = SIB1_content || static_params || timesync_info ||
             interval_index || disclosed_key || timestamp_ms
```

Where:
- `SIB1_content`: Original SIB1 without lateNonCriticalExtension
- `static_params`: TESLA parameters (30 bytes)
- `timesync_info`: TX timing (4 bytes)
- `interval_index`: Current TESLA interval (4 bytes)
- `disclosed_key`: Key K_{i-d} (16 bytes)
- `timestamp_ms`: Unix timestamp in milliseconds (8 bytes)

## 6. Identity Format

**NR Cell ID (3GPP TS 38.331):**
- Size: 36 bits
- Encoding: BIT STRING
- Storage: 5 bytes (36 bits + 4 padding bits in last byte)

**Byte Layout:**
```
byte[0] = bits 35-28
byte[1] = bits 27-20
byte[2] = bits 19-12
byte[3] = bits 11-4
byte[4] = bits 3-0 (upper nibble), padding (lower nibble)
```

**Hex Representation:**
- 9 hex characters (e.g., `"123456789"`)
- Represents the 36-bit value

## 7. Security Analysis

### 7.1 Security Model

The scheme provides **existential unforgeability under chosen message attack (EUF-CMA)** in the random oracle model, assuming:
- CDH (Computational Diffie-Hellman) is hard in G1 and G2
- H_s and H_m are modeled as random oracles

### 7.2 Security Properties

| Property | Guarantee |
|----------|-----------|
| Signature Unforgeability | Cannot forge signature without sk_ID |
| Identity Binding | Signature valid only for correct Cell ID |
| Key Isolation | Compromising one gNB key doesn't affect others |
| Forward Secrecy | Not provided (would require key evolution) |

### 7.3 Trust Model

| Entity | Trusts | Holds |
|--------|--------|-------|
| Core PKG | — | Master secret (s) |
| gNB | Core PKG | sk_ID |
| UE | Core PKG | MPK |

### 7.4 Attack Resistance

**Key Extraction Attack:**
- Attacker with MPK and Cell ID cannot compute sk_ID
- Requires solving CDH: given `Q`, `s*Q`, compute `s*pk_ID*Q`

**Rogue Key Attack:**
- Not applicable: gNB doesn't choose its own key
- Key is deterministically derived from Cell ID

**Identity Substitution:**
- Cell ID is in signed content (indirectly via SIB1)
- Changing Cell ID breaks signature validity

## 8. Implementation Notes

### 8.1 Library

Uses **blst** (Supranational) for BLS12-381 operations:
- `blst_keygen`: Secure scalar derivation from IKM
- `blst_sk_mul_n_check`: Scalar multiplication with zero check
- `blst_sk_to_pk_in_g2`: Compute public key from scalar
- `blst_hash_to_g1`: Hash-to-curve for messages
- `blst_sign_pk_in_g2`: BLS signing
- `blst_core_verify_pk_in_g2`: BLS verification
- `blst_p2_mult`: G2 scalar multiplication (for pk_ID * MPK)

### 8.2 Performance

| Operation | Approximate Time |
|-----------|-----------------|
| H_s (hash to scalar) | ~50 μs |
| Sign | ~500 μs |
| Verify (IBS) | ~2 ms |

Note: IBS verification includes one extra G2 scalar multiplication compared to standard BLS.

### 8.3 Key Sizes

| Key | Size | Encoding |
|-----|------|----------|
| Master secret (s) | 32 bytes | Scalar, big-endian |
| Master public (MPK) | 96 bytes | G2 compressed |
| gNB secret (sk_ID) | 32 bytes | Scalar, big-endian |
| Signature (Σ) | 48 bytes | G1 compressed |

## 9. References

1. RFC 4082 - TESLA Protocol
2. IETF BLS Signatures (draft-irtf-cfrg-bls-signature)
3. 3GPP TS 38.331 - NR RRC Protocol Specification
4. Boneh, Lynn, Shacham - "Short Signatures from the Weil Pairing" (2004)
5. Supranational blst library - https://github.com/supranational/blst
