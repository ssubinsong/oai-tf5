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
  - $G_1$: 48-byte compressed points (signatures)
  - $G_2$: 96-byte compressed points (public keys)
  - $G_T$: Target group for pairing
- **Order:** $r \approx 2^{255}$ (prime)

### 2.2 Bilinear Pairing

$$e: G_1 \times G_2 \rightarrow G_T$$

Properties:
- Bilinearity: $e(aP, bQ) = e(P, Q)^{ab}$
- Non-degeneracy: $e(G_1, G_2) \neq 1$

### 2.3 Hash Functions

**$H_s: \text{Identity} \rightarrow \text{Scalar}\ (\mathbb{Z}_r)$**
- Input: NR Cell ID (36 bits)
- Output: Scalar in $\mathbb{Z}_r$
- Implementation: IETF hash-to-field via `blst_keygen` with DST
- DST: `"TF5_IBS_BLS12381_XMD:SHA-256_H_s_v1"`

**$H_m: \text{Message} \rightarrow G_1$**
- Input: Arbitrary-length message
- Output: Point in $G_1$
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

**Input:** Security parameter $\lambda$ (implicit: BLS12-381)

**Output:** Master secret $s$, Master public key $MPK$

$$
\begin{aligned}
1. &\ s \leftarrow \text{random scalar in } \mathbb{Z}_r \\
2. &\ MPK \leftarrow s \cdot Q, \text{ where } Q \text{ is the generator of } G_2 \\
3. &\ \text{Return } (s, MPK)
\end{aligned}
$$

**File Output:**
- `msk.bin`: 32 bytes, $s$ serialized big-endian
- `mpk.bin`: 96 bytes, $MPK$ compressed

### 4.2 Key Issuance (Core PKG)

**Input:** Master secret $s$, gNB identity $ID$ (NR Cell ID, 36 bits)

**Output:** gNB secret key $sk_{ID}$

$$
\begin{aligned}
1. &\ pk_{ID} \leftarrow H_s(ID) & \text{// Hash identity to scalar} \\
2. &\ sk_{ID} \leftarrow s \cdot pk_{ID} \mod r & \text{// Scalar multiplication} \\
3. &\ \text{Return } sk_{ID}
\end{aligned}
$$

**Properties:**
- $sk_{ID}$ is a 32-byte scalar
- Different Cell IDs produce different keys
- Core can issue keys without gNB interaction

### 4.3 Sign (gNB)

**Input:** gNB secret key $sk_{ID}$, message $m$

**Output:** Signature $\Sigma$

$$
\begin{aligned}
1. &\ h \leftarrow H_m(m) & \text{// Hash message to } G_1 \\
2. &\ \Sigma \leftarrow sk_{ID} \cdot h & \text{// Scalar multiplication in } G_1 \\
3. &\ \text{Return } \Sigma
\end{aligned}
$$

**Properties:**
- $\Sigma$ is a 48-byte $G_1$ point (compressed)
- Same algorithm as standard BLS signature
- $sk_{ID}$ acts as the signing key

### 4.4 Verify (UE)

**Input:** Master public key $MPK$, identity $ID$, message $m$, signature $\Sigma$

**Output:** Accept or Reject

$$
\begin{aligned}
1. &\ pk_{ID} \leftarrow H_s(ID) & \text{// Derive identity-based public key (scalar)} \\
2. &\ PK \leftarrow pk_{ID} \cdot MPK & \text{// Compute verification key (} G_2 \text{ point)} \\
3. &\ h \leftarrow H_m(m) & \text{// Hash message to } G_1 \\
4. &\ \text{Accept iff } e(\Sigma, Q) = e(h, PK)
\end{aligned}
$$

**Verification Equation Derivation:**

$$
\begin{aligned}
e(\Sigma, Q) &= e(sk_{ID} \cdot h, Q) \\
             &= e(h, Q)^{sk_{ID}} \\
             &= e(h, sk_{ID} \cdot Q)
\end{aligned}
$$

$$
\begin{aligned}
pk_{ID} \cdot MPK &= pk_{ID} \cdot (s \cdot Q) \\
                  &= (pk_{ID} \cdot s) \cdot Q \\
                  &= (s \cdot pk_{ID}) \cdot Q \\
                  &= sk_{ID} \cdot Q
\end{aligned}
$$

$$\text{Therefore: } e(\Sigma, Q) = e(h, sk_{ID} \cdot Q) = e(h, pk_{ID} \cdot MPK) = e(h, PK)$$

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
- `disclosed_key`: Key $K_{i-d}$ (16 bytes)
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
- CDH (Computational Diffie-Hellman) is hard in $G_1$ and $G_2$
- $H_s$ and $H_m$ are modeled as random oracles

### 7.2 Security Properties

| Property | Guarantee |
|----------|-----------|
| Signature Unforgeability | Cannot forge signature without $sk_{ID}$ |
| Identity Binding | Signature valid only for correct Cell ID |
| Key Isolation | Compromising one gNB key doesn't affect others |
| Forward Secrecy | Not provided (would require key evolution) |

### 7.3 Trust Model

| Entity | Trusts | Holds |
|--------|--------|-------|
| Core PKG | — | Master secret ($s$) |
| gNB | Core PKG | $sk_{ID}$ |
| UE | Core PKG | $MPK$ |

### 7.4 Attack Resistance

**Key Extraction Attack:**
- Attacker with $MPK$ and Cell ID cannot compute $sk_{ID}$
- Requires solving CDH: given $Q$, $s \cdot Q$, compute $s \cdot pk_{ID} \cdot Q$

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
- `blst_p2_mult`: $G_2$ scalar multiplication (for $pk_{ID} \cdot MPK$)

### 8.2 Performance

| Operation | Approximate Time |
|-----------|-----------------|
| $H_s$ (hash to scalar) | ~50 μs |
| Sign | ~500 μs |
| Verify (IBS) | ~2 ms |

Note: IBS verification includes one extra $G_2$ scalar multiplication compared to standard BLS.

### 8.3 Key Sizes

| Key | Size | Encoding |
|-----|------|----------|
| Master secret ($s$) | 32 bytes | Scalar, big-endian |
| Master public ($MPK$) | 96 bytes | $G_2$ compressed |
| gNB secret ($sk_{ID}$) | 32 bytes | Scalar, big-endian |
| Signature ($\Sigma$) | 48 bytes | $G_1$ compressed |

## 9. References

1. RFC 4082 - TESLA Protocol
2. IETF BLS Signatures (draft-irtf-cfrg-bls-signature)
3. 3GPP TS 38.331 - NR RRC Protocol Specification
4. Boneh, Lynn, Shacham - "Short Signatures from the Weil Pairing" (2004)
5. Supranational blst library - https://github.com/supranational/blst
