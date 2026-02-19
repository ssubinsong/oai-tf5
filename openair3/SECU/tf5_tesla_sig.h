/**
 * @file tf5_tesla_sig.h
 * @brief BLMQ IBS signature operations for TESLA broadcast authentication
 *
 * Implements the Barreto-Libert-McCullagh-Quisquater (BLMQ) Identity-Based
 * Signature scheme (ASIACRYPT 2005, Section 3) using blst (BLS12-381).
 *
 * Keygen: sk_ID = [1/(H1(ID)+s)] * P ∈ G1  (48 bytes)
 * Sign:   σ = (h, S) where h ∈ Z*p, S = (x+h)*sk_ID ∈ G1  (80 bytes)
 * Verify: h == H2(M, e(S, H1(ID)*Q + Qpub) * g^{-h})  (single pairing)
 */

#ifndef TF5_TESLA_SIG_H
#define TF5_TESLA_SIG_H

#ifdef ENABLE_TF5

#include <stdint.h>
#include <stddef.h>

#include "tf5_ibs_defs.h"
#include "blst.h"

/* Precomputed offline state for online/offline signing split.
 * The offline phase computes (x, r = g^x) which is message-independent,
 * saving a G1 scalar mult + Miller loop + final exp from the online path. */
typedef struct {
    blst_scalar x;   /* random scalar (consumed and zeroed by sign_online) */
    blst_fp12   r;   /* g^x ∈ GT */
} tf5_ibs_sign_precomp_t;

/**
 * Initialize BLMQ IBS subsystem
 *
 * Precomputes g = e(P, Q) ∈ GT and caches Q ∈ G2 (affine).
 * Must be called once before any other IBS operations.
 * NOT thread-safe - call at startup before spawning threads.
 *
 * @return 0 on success, negative on error
 */
int tf5_ibs_init(void);

/**
 * Validate a BLMQ IBS secret key (G1 point)
 *
 * Decompresses the 48-byte G1 point and checks:
 *   - Successful decompression
 *   - Point is in G1 subgroup
 *   - Point is not the identity (infinity)
 *
 * @param sk_id   Secret key (48 bytes, compressed G1 point)
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_KEY_INVALID
 */
int tf5_ibs_validate_sk(const uint8_t sk_id[TF5_IBS_GNB_SK_LEN]);

/**
 * Sign data with BLMQ IBS
 *
 * BLMQ signing algorithm:
 *   1. x ← random scalar
 *   2. r = g^x  (where g = e(P, Q) is precomputed)
 *   3. h = H2(data, r)
 *   4. S = (x + h) * sk_ID
 *   5. σ = (h, S)  → h[32] || S_compressed[48] = 80 bytes
 *
 * @param sk_id       BLMQ secret key (48 bytes, G1 point)
 * @param data        Data to sign
 * @param data_len    Length of data
 * @param signature   Output: BLMQ signature (80 bytes: h[32] || S[48])
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_KEY_INVALID, TF5_ERR_SIGN
 */
int tf5_ibs_sign(const uint8_t sk_id[TF5_IBS_GNB_SK_LEN],
                 const uint8_t *data,
                 size_t data_len,
                 uint8_t signature[TF5_IBS_SIG_LEN]);

/**
 * Offline precomputation for BLMQ IBS signing
 *
 * Computes the message-independent part of BLMQ signing:
 *   1. x ← random scalar
 *   2. r = g^x ∈ GT  (via xP scalar mult + Miller loop + final exp)
 *
 * This removes the most expensive operations from the online signing path.
 * The precomp state must be used exactly once by tf5_ibs_sign_online().
 *
 * @param precomp   Output: precomputed (x, r) pair
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_SIGN, TF5_ERR_CRYPTO
 */
int tf5_ibs_sign_precomp(tf5_ibs_sign_precomp_t *precomp);

/**
 * Online phase of BLMQ IBS signing (uses precomputed state)
 *
 * Completes the signing using precomputed (x, r):
 *   1. h = H2(data, r)
 *   2. S = (x + h) * sk_ID
 *   3. σ = (h, S)
 *
 * The precomp->x scalar is consumed (zeroed) after use.
 *
 * @param sk_id       BLMQ secret key (48 bytes, G1 point)
 * @param data        Data to sign
 * @param data_len    Length of data
 * @param precomp     Precomputed (x, r) from tf5_ibs_sign_precomp (consumed)
 * @param signature   Output: BLMQ signature (80 bytes: h[32] || S[48])
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_KEY_INVALID, TF5_ERR_SIGN
 */
int tf5_ibs_sign_online(const uint8_t sk_id[TF5_IBS_GNB_SK_LEN],
                         const uint8_t *data,
                         size_t data_len,
                         tf5_ibs_sign_precomp_t *precomp,
                         uint8_t signature[TF5_IBS_SIG_LEN]);

/**
 * Verify BLMQ IBS signature
 *
 * BLMQ verification algorithm:
 *   1. Parse σ = (h, S)
 *   2. Compute QID = H1(ID)*Q + Qpub ∈ G2
 *   3. Compute r' = e(S, QID) * g^{-h}
 *      via multi-Miller-loop: ML(S, QID) * ML(-hP, Q) → final_exp
 *   4. h' = H2(data, r')
 *   5. Accept iff h == h' (constant-time)
 *
 * @param mpk          Core's Master Public Key (96 bytes, G2 point = Qpub = s*Q)
 * @param cell_id      gNB's NR Cell ID (5 bytes, 36 bits)
 * @param gnb_key_validity_end Key expiration (minutes since 2024-01-01 00:00 UTC)
 * @param data         Signed data
 * @param data_len     Length of data
 * @param signature    Signature to verify (80 bytes: h[32] || S[48])
 * @return TF5_OK on success (signature valid), or TF5_ERR_INVALID_PARAM,
 *         TF5_ERR_CRYPTO, TF5_ERR_KEY_INVALID, TF5_ERR_VERIFY
 */
int tf5_ibs_verify(const uint8_t mpk[TF5_IBS_GNB_PK_LEN],
                   const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                   uint32_t gnb_key_validity_end,
                   const uint8_t *data,
                   size_t data_len,
                   const uint8_t signature[TF5_IBS_SIG_LEN]);

#endif /* ENABLE_TF5 */

#endif /* TF5_TESLA_SIG_H */
