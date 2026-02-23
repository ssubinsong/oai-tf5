# TF5 Identity-Based Signature Protocol Specification

## 1. Overview

This document specifies the GG09 Schnorr Identity-Based Signature scheme (Galindo-Garcia, 2009; 1-level Schnorr IBS) used for authenticating 5G NR SIB1 messages. The scheme is instantiated over Ed25519 using libsodium and provides EUF-CMIA security under the DL assumption in the random oracle model.

The scheme allows UEs to verify gNB signatures using only:
- The Core's master public key (MPK), pre-provisioned in UE
- The gNB's NR Cell ID, extracted from the received SIB1

## 2. Cryptographic Primitives

### 2.1 Elliptic Curve

- **Curve:** Ed25519 (Twisted Edwards curve over GF(2^255 - 19))
- **Base point:** B (standard Ed25519 generator)
- **Group order:** l ≈ 2^252 (prime)
- **Scalar size:** 32 bytes (little-endian)
- **Point size:** 32 bytes (compressed)

### 2.2 Hash Functions

**Identity hash: $H_{id}$**
- Input: cell_id (5B) || validity_end_be (3B) || pk (32B) || mpk (32B)
- Output: Scalar in $\mathbb{Z}_l$
- Implementation: BLAKE2b-512 → `crypto_core_ed25519_scalar_reduce()`
- Used in both key extraction and verification

**Message hash: $H_m$**
- Input: data || R (32B point)
- Output: Scalar in $\mathbb{Z}_l$
- Implementation: BLAKE2b-512 → `crypto_core_ed25519_scalar_reduce()`
- Used in signing and verification

## 3. Key Hierarchy

```
                    ┌─────────────────┐
                    │   Core PKG      │
                    │                 │
                    │  z (secret)     │
                    │  MPK = z·B     │
                    └────────┬────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
           ▼                 ▼                 ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │   gNB 1      │  │   gNB 2      │  │   gNB N      │
    │              │  │              │  │              │
    │ Cell ID: ID1 │  │ Cell ID: ID2 │  │ Cell ID: IDN │
    │ sk = (y, pk) │  │ sk = (y, pk) │  │ sk = (y, pk) │
    └──────────────┘  └──────────────┘  └──────────────┘
```

## 4. Algorithms

### 4.1 Setup (Core PKG)

**Input:** Security parameter λ (implicit: Ed25519)

**Output:** Master secret z, Master public key MPK

$$
\begin{aligned}
1. &\ z \leftarrow \text{random scalar in } \mathbb{Z}_l \\
2. &\ \text{MPK} \leftarrow z \cdot B \\
3. &\ \text{Return } (z, \text{MPK})
\end{aligned}
$$

**File Output:**
- `msk.bin`: 32 bytes, z serialized little-endian
- `mpk.bin`: 32 bytes, MPK compressed

### 4.2 Key Extraction (Core PKG)

**Input:** Master secret z, MPK, gNB identity ID (NR Cell ID || validity_end)

**Output:** gNB secret key sk_ID = (y, pk)

$$
\begin{aligned}
1. &\ b \leftarrow \text{random scalar in } \mathbb{Z}_l \\
2. &\ pk \leftarrow b \cdot B & \text{// identity-derived public point} \\
3. &\ cid \leftarrow H_{id}(\text{Cell\_ID} \| \text{validity\_end} \| pk \| \text{MPK}) & \text{// identity scalar} \\
4. &\ y \leftarrow cid \cdot z + b \mod l & \text{// secret scalar} \\
5. &\ \text{Return } sk_{ID} = (y, pk)
\end{aligned}
$$

**Properties:**
- sk_ID is 64 bytes: y[32] scalar + pk[32] point
- Different Cell IDs produce different keys
- Key extraction is NOT deterministic (random b each time)
- Core can issue keys without gNB interaction

### 4.3 Sign (gNB)

**Input:** gNB secret key sk_ID = (y, pk), message m

**Output:** Signature σ = (R, sigma, pk)

$$
\begin{aligned}
1. &\ r \leftarrow \text{random scalar in } \mathbb{Z}_l \\
2. &\ R \leftarrow r \cdot B & \text{// commitment point} \\
3. &\ h \leftarrow H_m(m \| R) & \text{// challenge scalar} \\
4. &\ \sigma \leftarrow h \cdot y + r \mod l & \text{// response scalar} \\
5. &\ \text{Return } (R, \sigma, pk)
\end{aligned}
$$

**Properties:**
- R is a 32-byte Ed25519 point
- σ is a 32-byte scalar
- pk is a 32-byte Ed25519 point (from sk_ID)
- Total signature: 96 bytes = R[32] || σ[32] || pk[32]
- Signature is **randomized** (different each time due to random r)

**Online/Offline Split:**
- Offline: precompute (r, R = r·B) — message-independent
- Online: compute h = H_m(m || R), σ = h·y + r — only scalar operations

### 4.4 Verify (UE)

**Input:** Master public key MPK, identity ID, message m, signature (R, σ, pk)

**Output:** Accept or Reject

$$
\begin{aligned}
1. &\ cid \leftarrow H_{id}(\text{Cell\_ID} \| \text{validity\_end} \| pk \| \text{MPK}) & \text{// identity scalar} \\
2. &\ Q \leftarrow cid \cdot \text{MPK} + pk & \text{// identity-derived verification key} \\
3. &\ h \leftarrow H_m(m \| R) & \text{// recompute challenge} \\
4. &\ R' \leftarrow \sigma \cdot B - h \cdot Q & \text{// double scalar mult (Shamir's trick)} \\
5. &\ \text{Accept iff } R = R'
\end{aligned}
$$

**Verification Equation Derivation:**

If the signature is valid, then σ = h·y + r where y = cid·z + b.

$$
\begin{aligned}
\sigma \cdot B &= (h \cdot y + r) \cdot B \\
               &= h \cdot (cid \cdot z + b) \cdot B + r \cdot B \\
               &= h \cdot (cid \cdot z \cdot B + b \cdot B) + R \\
               &= h \cdot (cid \cdot \text{MPK} + pk) + R \\
               &= h \cdot Q + R
\end{aligned}
$$

Therefore $R' = \sigma \cdot B - h \cdot Q = R$, and verification succeeds.

**Optimization:** Step 4 uses `ge25519_double_scalarmult_vartime` (Shamir's trick) for a single combined double-scalar multiplication, which is faster than two separate scalar multiplications.

## 5. Message Format

The signature is computed over the TESLA authentication input:

```
auth_input = SIB1_content || te_version || tesla_params || validity_end ||
             i || key_disclosure || timestamp_ms
```

Where:
- `SIB1_content`: Original SIB1 without lateNonCriticalExtension
- `te_version`: Protocol version (1 byte)
- `tesla_params`: TESLA parameters including T_0 (11 bytes)
- `validity_end`: Key expiration (3 bytes, minutes since 2024-01-01)
- `i`: Current TESLA interval (4 bytes)
- `key_disclosure`: Key $K_{i-d}$ (16 bytes)
- `timestamp_ms`: Unix timestamp LSB in milliseconds (3 bytes)

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

The GG09 Schnorr IBS scheme provides **existential unforgeability under chosen message and identity attack (EUF-CMIA)** under:
- The **DL** (Discrete Logarithm) assumption on Ed25519
- $H_{id}$ and $H_m$ are modeled as random oracles

This is a standard and well-studied assumption in elliptic curve cryptography.

### 7.2 Security Properties

| Property | Guarantee |
|----------|-----------|
| Signature Unforgeability | Cannot forge signature without sk_ID (DL assumption) |
| Identity Binding | Signature valid only for correct Cell ID + validity + pk |
| Key Isolation | Compromising one gNB key doesn't affect others |
| Forward Secrecy | Not provided (would require key evolution) |

### 7.3 Trust Model

| Entity | Trusts | Holds |
|--------|--------|-------|
| Core PKG | — | Master secret (z) |
| gNB | Core PKG | sk_ID = (y, pk) |
| UE | Core PKG | MPK = z·B |

### 7.4 Attack Resistance

**Key Extraction Attack:**
- Attacker with MPK and Cell ID cannot compute sk_ID
- Requires solving DL: given B and z·B, compute z

**Rogue Key Attack:**
- Not applicable: gNB doesn't choose its own key
- Key is derived by Core PKG from Cell ID and master secret

**Identity Substitution:**
- Cell ID and validity_end are included in the identity hash
- pk is bound to the identity via cid = H(id || pk || mpk)
- Changing Cell ID breaks signature validity

## 8. Implementation Notes

### 8.1 Library

Uses **libsodium** for Ed25519 operations:
- `crypto_core_ed25519_scalar_reduce`: Reduce 64-byte hash to scalar mod l
- `crypto_core_ed25519_scalar_mul`: Scalar multiplication mod l
- `crypto_core_ed25519_scalar_add`: Scalar addition mod l
- `crypto_scalarmult_ed25519_base_noclamp`: Base-point scalar multiplication
- `crypto_core_ed25519_is_valid_point`: Point validation (subgroup check)
- `ge25519_double_scalarmult_vartime`: Shamir's trick (via ed25519_precomp.h)
- `crypto_generichash_blake2b`: BLAKE2b hashing

**Note:** `ed25519_precomp.h` contains local reimplementations of libsodium internal `ge25519_*` functions (they are `static` in libsodium source and not exported).

### 8.2 Performance

| Operation | Approximate Time |
|-----------|-----------------|
| Sign (GG09 Schnorr) | ~50 μs |
| Sign online (precomputed) | ~15 μs |
| Verify (GG09 Schnorr) | ~80 μs |

Note: GG09 Schnorr verification uses Ed25519 point arithmetic only.

### 8.3 Key Sizes

| Key | Size | Encoding |
|-----|------|----------|
| Master secret (z) | 32 bytes | Scalar, little-endian |
| Master public (MPK) | 32 bytes | Ed25519 point, compressed |
| gNB secret (sk_ID) | 64 bytes | y[32] scalar + pk[32] point |
| Signature (σ) | 96 bytes | R[32] || σ[32] || pk[32] |

### 8.4 Precomputed Values

The following optimizations are used:
- **MPK precomp table**: 32×8 Duif table (~30KB, fits L1 cache) for fast `cid·MPK` computation during verification
- **Shamir's trick**: `ge25519_double_scalarmult_vartime` combines σ·B and h·Q into a single operation
- **Variable-time operations**: Verification inputs are public, so variable-time algorithms are safe

## 9. References

1. RFC 4082 - TESLA Protocol
2. Galindo, Garcia - "Schnorr-like Identification Schemes from IBS" (2009)
3. 3GPP TS 38.331 - NR RRC Protocol Specification
4. Bernstein et al. - "High-speed high-security signatures" (Ed25519)
5. libsodium library - https://doc.libsodium.org/
