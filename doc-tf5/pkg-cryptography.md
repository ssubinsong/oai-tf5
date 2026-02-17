# TF5 Identity-Based Signature Protocol Specification

## 1. Overview

This document specifies the BLMQ (Barreto-Libert-McCullagh-Quisquater) Identity-Based Signature scheme used for authenticating 5G NR SIB1 messages. The BLMQ scheme (ASIACRYPT 2005, Section 3) provides efficient single-pairing verification and EUF-CMA security under the q-SDH assumption.

The scheme allows UEs to verify gNB signatures using only:
- The Core's master public key (MPK), pre-provisioned in UE
- The gNB's NR Cell ID, extracted from the received SIB1

## 2. Cryptographic Primitives

### 2.1 Elliptic Curve

- **Curve:** BLS12-381
- **Variant:** pk-in-G2 (public keys and verification keys in $G_2$)
- **Groups:**
  - $G_1$: 48-byte compressed points (secret keys, signatures)
  - $G_2$: 96-byte compressed points (public keys)
  - $G_T$: Target group for pairing
- **Order:** $r \approx 2^{255}$ (prime)

### 2.2 Bilinear Pairing

$$e: G_1 \times G_2 \rightarrow G_T$$

Properties:
- Bilinearity: $e(aP, bQ) = e(P, Q)^{ab}$
- Non-degeneracy: $e(G_1, G_2) \neq 1$

### 2.3 Hash Functions

**$H_1: \text{Identity} \rightarrow \text{Scalar}\ (\mathbb{Z}_r^*)$**
- Input: NR Cell ID (36 bits) || validity_end (24 bits)
- Output: Scalar in $\mathbb{Z}_r^*$
- Implementation: IETF hash-to-field via `blst_keygen` with DST
- DST: `"TF5_IBS_BLMQ_BLS12381_XMD:SHA-256_H1_v1"` (40 bytes)

**$H_2: \{0,1\}^* \times G_T \rightarrow \mathbb{Z}_r^*$**
- Input: Message data || $G_T$ element (serialized as `blst_fp12`, 576 bytes)
- Output: Scalar in $\mathbb{Z}_r^*$
- Implementation: SHA-256(DST_H2 || data || fp12_bytes) → `blst_keygen` for mod $r$ reduction
- DST: `"TF5_IBS_BLMQ_BLS12381_XMD:SHA-256_H2_v1"` (40 bytes)

## 3. Key Hierarchy

```
                    ┌─────────────────┐
                    │   Core PKG      │
                    │                 │
                    │  s (secret)     │
                    │  Qpub = s*Q    │
                    │  g = e(P, Q)   │
                    └────────┬────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
           ▼                 ▼                 ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │   gNB 1      │  │   gNB 2      │  │   gNB N      │
    │              │  │              │  │              │
    │ Cell ID: ID1 │  │ Cell ID: ID2 │  │ Cell ID: IDN │
    │ sk_ID1 ∈ G1  │  │ sk_ID2 ∈ G1  │  │ sk_IDN ∈ G1  │
    └──────────────┘  └──────────────┘  └──────────────┘
```

## 4. Algorithms

### 4.1 Setup (Core PKG)

**Input:** Security parameter $\lambda$ (implicit: BLS12-381)

**Output:** Master secret $s$, Master public key $Q_{pub}$, precomputed $g$

$$
\begin{aligned}
1. &\ s \leftarrow \text{random scalar in } \mathbb{Z}_r^* \\
2. &\ Q_{pub} \leftarrow s \cdot Q, \text{ where } Q \text{ is the generator of } G_2 \\
3. &\ P \leftarrow \psi(Q), \text{ where } P \text{ is the generator of } G_1 \\
4. &\ g \leftarrow e(P, Q) \in G_T \\
5. &\ \text{Return } (s, Q_{pub})
\end{aligned}
$$

**File Output:**
- `msk.bin`: 32 bytes, $s$ serialized big-endian
- `mpk.bin`: 96 bytes, $Q_{pub}$ compressed

### 4.2 Key Issuance (Core PKG)

**Input:** Master secret $s$, gNB identity $ID$ (NR Cell ID || validity_end)

**Output:** gNB secret key $sk_{ID} \in G_1$

$$
\begin{aligned}
1. &\ h_1 \leftarrow H_1(ID) & \text{// Hash identity to scalar} \\
2. &\ \text{sum} \leftarrow h_1 + s \mod r & \text{// Add to master secret} \\
3. &\ \text{inv} \leftarrow \text{sum}^{-1} \mod r & \text{// Scalar inverse} \\
4. &\ sk_{ID} \leftarrow \text{inv} \cdot P & \text{// Scalar mult of } G_1 \text{ generator} \\
5. &\ \text{Return } sk_{ID}
\end{aligned}
$$

**Properties:**
- $sk_{ID}$ is a 48-byte compressed $G_1$ point
- $sk_{ID} = \frac{1}{H_1(ID) + s} \cdot P$
- Different Cell IDs produce different keys
- Core can issue keys without gNB interaction

### 4.3 Sign (gNB)

**Input:** gNB secret key $sk_{ID} \in G_1$, message $m$

**Output:** Signature $\sigma = (h, S)$

$$
\begin{aligned}
1. &\ x \leftarrow \text{random scalar in } \mathbb{Z}_r^* \\
2. &\ r \leftarrow g^x = e(x \cdot P, Q) \in G_T \\
3. &\ h \leftarrow H_2(m, r) \in \mathbb{Z}_r^* \\
4. &\ S \leftarrow (x + h) \cdot sk_{ID} \in G_1 \\
5. &\ \text{Return } \sigma = (h, S)
\end{aligned}
$$

**Properties:**
- $h$ is a 32-byte scalar
- $S$ is a 48-byte compressed $G_1$ point
- $\sigma$ is 80 bytes total: $h[32] \| S[48]$
- Signature is **randomized** (different each time due to random $x$)

### 4.4 Verify (UE)

**Input:** Master public key $Q_{pub}$, identity $ID$, message $m$, signature $\sigma = (h, S)$

**Output:** Accept or Reject

$$
\begin{aligned}
1. &\ h_1 \leftarrow H_1(ID) & \text{// Hash identity to scalar} \\
2. &\ Q_{ID} \leftarrow h_1 \cdot Q + Q_{pub} \in G_2 & \text{// Compute verification key} \\
3. &\ r' \leftarrow e(S, Q_{ID}) \cdot e(-h \cdot P, Q) & \text{// Multi-Miller-loop + final exp} \\
4. &\ h' \leftarrow H_2(m, r') \\
5. &\ \text{Accept iff } h = h'
\end{aligned}
$$

**Verification Equation Derivation:**

If the signature is valid, then $S = (x + h) \cdot sk_{ID} = \frac{x + h}{H_1(ID) + s} \cdot P$.

$$
\begin{aligned}
e(S, Q_{ID}) &= e\left(\frac{x + h}{H_1(ID) + s} \cdot P,\ (H_1(ID) + s) \cdot Q\right) \\
             &= e(P, Q)^{x + h} \\
             &= g^{x + h}
\end{aligned}
$$

$$
e(-h \cdot P, Q) = e(P, Q)^{-h} = g^{-h}
$$

$$
r' = g^{x+h} \cdot g^{-h} = g^x = r
$$

Therefore $H_2(m, r') = H_2(m, r) = h$, and verification succeeds.

**Optimization:** The two pairings are computed via a single multi-Miller-loop call
(`blst_miller_loop_n` with 2 pairs) followed by one final exponentiation.

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

The BLMQ scheme provides **existential unforgeability under chosen message and identity attack (EUF-CMIA)** under:
- The **q-SDH** (q-Strong Diffie-Hellman) assumption in bilinear groups
- $H_1$ and $H_2$ are modeled as random oracles

This is a stronger security result than CDH-based schemes, as q-SDH is a well-studied
assumption in the pairing-based cryptography literature.

### 7.2 Security Properties

| Property | Guarantee |
|----------|-----------|
| Signature Unforgeability | Cannot forge signature without $sk_{ID}$ (q-SDH) |
| Identity Binding | Signature valid only for correct Cell ID + validity |
| Key Isolation | Compromising one gNB key doesn't affect others |
| Forward Secrecy | Not provided (would require key evolution) |

### 7.3 Trust Model

| Entity | Trusts | Holds |
|--------|--------|-------|
| Core PKG | — | Master secret ($s$) |
| gNB | Core PKG | $sk_{ID} \in G_1$ |
| UE | Core PKG | $Q_{pub} \in G_2$ |

### 7.4 Attack Resistance

**Key Extraction Attack:**
- Attacker with $Q_{pub}$ and Cell ID cannot compute $sk_{ID}$
- Requires solving q-SDH: given $(P, sP, s^2P, \ldots, s^qP)$, compute $(c, \frac{1}{s+c} \cdot P)$

**Rogue Key Attack:**
- Not applicable: gNB doesn't choose its own key
- Key is deterministically derived from Cell ID and master secret

**Identity Substitution:**
- Cell ID and validity_end are in signed content (indirectly via SIB1)
- Changing Cell ID breaks signature validity

## 8. Implementation Notes

### 8.1 Library

Uses **blst** (Supranational) for BLS12-381 operations:
- `blst_keygen`: Secure scalar derivation from IKM (used for H1, H2)
- `blst_sk_add_n_check`: Scalar addition with overflow check
- `blst_sk_inverse`: Scalar modular inverse
- `blst_sign_pk_in_g2`: $G_1$ scalar multiplication (signing)
- `blst_p1_mult`: $G_1$ scalar multiplication
- `blst_p2_mult`: $G_2$ scalar multiplication
- `blst_p2_add_or_double`: $G_2$ point addition
- `blst_p1_cneg`: $G_1$ point negation
- `blst_miller_loop_n`: Multi-Miller-loop (batched pairing)
- `blst_final_exp`: Final exponentiation

### 8.2 Performance

| Operation | Approximate Time |
|-----------|-----------------|
| $H_1$ (hash to scalar) | ~50 μs |
| Sign (BLMQ) | ~1 ms |
| Verify (BLMQ, single pairing) | ~1.5 ms |

Note: BLMQ verification uses a single multi-Miller-loop with 2 pairs, which is
faster than the previous scheme that required 2 separate pairings.

### 8.3 Key Sizes

| Key | Size | Encoding |
|-----|------|----------|
| Master secret ($s$) | 32 bytes | Scalar, big-endian |
| Master public ($Q_{pub}$) | 96 bytes | $G_2$ compressed |
| gNB secret ($sk_{ID}$) | 48 bytes | $G_1$ compressed |
| Signature ($\sigma$) | 80 bytes | $h[32] \| S[48]$ ($\mathbb{Z}_r \times G_1$) |

### 8.4 Precomputed Values

The following values are computed once during `tf5_ibs_init()` and reused:
- $g = e(P, Q) \in G_T$ — base for $g^x$ computation in signing
- $Q$ affine ($G_2$ generator) — for Miller loops
- $P$ affine ($G_1$ generator) — for $h \cdot P$ negation in verification

## 9. References

1. RFC 4082 - TESLA Protocol
2. IETF BLS Signatures (draft-irtf-cfrg-bls-signature)
3. 3GPP TS 38.331 - NR RRC Protocol Specification
4. Barreto, Libert, McCullagh, Quisquater - "Efficient and Provably-Secure Identity-Based Signatures and Signcryption from Bilinear Maps" (ASIACRYPT 2005, Section 3)
5. Supranational blst library - https://github.com/supranational/blst
