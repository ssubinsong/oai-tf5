/**
 * @file tf5_tesla_sig.h
 * @brief GG09 Schnorr IBS signature operations for TESLA broadcast authentication
 *
 * Implements the Galindo-Garcia (GG09) Schnorr Identity-Based Signature scheme
 * (1-level, Ed25519/libsodium) for SIB1 broadcast authentication.
 *
 * Extract: b ← Z_l, pk = b·B, cid = H(id‖pk‖mpk), y = cid·z + b
 * Sign:    r ← Z_l, R = r·B, h = H(data‖R), σ = h·y + r
 * Verify:  cid = H(id‖pk‖mpk), Q = cid·mpk + pk, R' = σ·B − h·Q
 */

#ifndef TF5_TESLA_SIG_H
#define TF5_TESLA_SIG_H

#ifdef ENABLE_TF5

#include <stdint.h>
#include <stddef.h>

#include "tf5_ibs_defs.h"

/* Precomputed offline state for online/offline signing split.
 * The offline phase computes (r, R = r·B) which is message-independent,
 * saving a base-point scalar mult from the online path. */
typedef struct {
    uint8_t r_scalar[TF5_ED25519_SCALAR_LEN]; /* random nonce (consumed by sign_online) */
    uint8_t R_point[TF5_ED25519_POINT_LEN];   /* R = r·B (precomputed commitment) */
} tf5_ibs_sign_precomp_t;

/**
 * Initialize GG09 Schnorr IBS subsystem
 *
 * Calls sodium_init(). Must be called once before any other IBS operations.
 * NOT thread-safe - call at startup before spawning threads.
 *
 * @return 0 on success, negative on error
 */
int tf5_ibs_init(void);

/**
 * Validate a GG09 Schnorr IBS secret key
 *
 * Decompresses the pk portion (bytes 32-63) as an Ed25519 point and checks:
 *   - Successful decompression
 *   - Point is not the identity (all zeros)
 *
 * @param sk_id   Secret key (64 bytes: y[32] scalar + pk[32] point)
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_KEY_INVALID
 */
int tf5_ibs_validate_sk(const uint8_t sk_id[TF5_IBS_GNB_SK_LEN]);

/**
 * Sign data with GG09 Schnorr IBS
 *
 * GG09 signing algorithm:
 *   1. r ← random scalar
 *   2. R = r·B
 *   3. h = BLAKE2b(data ‖ R) mod l
 *   4. σ = h·y + r mod l
 *   5. Output: R[32] || σ[32] || pk[32] = 96 bytes
 *
 * @param sk_id       GG09 secret key (64 bytes: y[32] + pk[32])
 * @param data        Data to sign
 * @param data_len    Length of data
 * @param signature   Output: GG09 signature (96 bytes: R[32] || sigma[32] || pk[32])
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_KEY_INVALID, TF5_ERR_SIGN
 */
int tf5_ibs_sign(const uint8_t sk_id[TF5_IBS_GNB_SK_LEN],
                 const uint8_t *data,
                 size_t data_len,
                 uint8_t signature[TF5_IBS_SIG_LEN]);

/**
 * Offline precomputation for GG09 Schnorr IBS signing
 *
 * Computes the message-independent part:
 *   1. r ← random scalar (reduced mod l)
 *   2. R = r·B (base-point scalar mult)
 *
 * This removes the scalar mult from the online signing path.
 * The precomp state must be used exactly once by tf5_ibs_sign_online().
 *
 * @param precomp   Output: precomputed (r, R) pair
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_SIGN, TF5_ERR_CRYPTO
 */
int tf5_ibs_sign_precomp(tf5_ibs_sign_precomp_t *precomp);

/**
 * Online phase of GG09 Schnorr IBS signing (uses precomputed state)
 *
 * Completes the signing using precomputed (r, R):
 *   1. h = BLAKE2b(data ‖ R) mod l
 *   2. sigma = h·y + r mod l
 *   3. Output: R[32] || sigma[32] || pk[32]
 *
 * The precomp->r_scalar is consumed (zeroed) after use.
 *
 * @param sk_id       GG09 secret key (64 bytes: y[32] + pk[32])
 * @param data        Data to sign
 * @param data_len    Length of data
 * @param precomp     Precomputed (r, R) from tf5_ibs_sign_precomp (consumed)
 * @param signature   Output: GG09 signature (96 bytes: R[32] || sigma[32] || pk[32])
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_KEY_INVALID, TF5_ERR_SIGN
 */
int tf5_ibs_sign_online(const uint8_t sk_id[TF5_IBS_GNB_SK_LEN],
                         const uint8_t *data,
                         size_t data_len,
                         tf5_ibs_sign_precomp_t *precomp,
                         uint8_t signature[TF5_IBS_SIG_LEN]);

/**
 * Verify GG09 Schnorr IBS signature
 *
 * GG09 verification algorithm:
 *   1. Parse σ = (R, sigma, pk) from signature
 *   2. cid = BLAKE2b(cell_id ‖ validity_be ‖ pk ‖ mpk) mod l
 *   3. Q = cid·mpk + pk (via precomp table for mpk + point add)
 *   4. R' = sigma·B − h·Q (via Shamir's trick / double scalar mult)
 *   5. h' = BLAKE2b(data ‖ R')
 *   6. Accept iff h == h' (constant-time)
 *
 * Optimizations (matching bench_schnorr_2ibs.c):
 *   - MPK precomp table (32×8 Duif, ~30KB, L1 cache)
 *   - ge25519_double_scalarmult_vartime for Shamir's trick
 *   - Variable-time ops (verification inputs are public)
 *
 * @param mpk          Core's Master Public Key (32 bytes, Ed25519 point = z·B)
 * @param cell_id      gNB's NR Cell ID (5 bytes, 36 bits)
 * @param gnb_key_validity_end Key expiration (minutes since 2024-01-01 00:00 UTC)
 * @param data         Signed data
 * @param data_len     Length of data
 * @param signature    Signature to verify (96 bytes: R[32] || sigma[32] || pk[32])
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
