/**
 * @file tf5_tesla_sig.h
 * @brief BLS signature operations for TESLA broadcast authentication
 *
 * Uses blst library (Supranational) with BLS12-381 curve.
 * Minimal-signature-size variant: Signatures in G1 (48 bytes), Public keys in G2 (96 bytes).
 */

#ifndef TF5_TESLA_SIG_H
#define TF5_TESLA_SIG_H

#ifdef ENABLE_TF5

#include <stdint.h>
#include <stddef.h>

#include "tf5_ibs_defs.h"

/**
 * Initialize BLS library
 *
 * Must be called once before any other BLS operations.
 * NOT thread-safe - call at startup before spawning threads.
 *
 * @return 0 on success, negative on error
 */
int tf5_bls_init(void);

/**
 * Derive BLS public key from secret key
 *
 * @param secret_key   BLS secret key (32 bytes)
 * @param public_key   Output: BLS public key (96 bytes)
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_KEY_INVALID
 */
int tf5_bls_derive_pubkey(const uint8_t secret_key[TF5_IBS_GNB_SK_LEN],
                                uint8_t public_key[TF5_IBS_GNB_PK_LEN]);

/**
 * Sign data with BLS
 *
 * @param secret_key   BLS secret key (32 bytes)
 * @param data         Data to sign
 * @param data_len     Length of data
 * @param signature    Output: BLS signature (48 bytes)
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_KEY_INVALID
 */
int tf5_bls_sign(const uint8_t secret_key[TF5_IBS_GNB_SK_LEN],
                       const uint8_t *data,
                       size_t data_len,
                       uint8_t signature[TF5_IBS_SIG_LEN]);

/*
 * =============================================================================
 * IBS (Identity-Based Signature) Functions
 * =============================================================================
 */

/**
 * Verify IBS signature
 *
 * Verifies a BLS signature using Identity-Based Signature scheme:
 *   1. Compute pk_ID = H_s(cell_id || gnb_key_validity_end) (scalar)
 *   2. Compute derived_pk = pk_ID * MPK (G2 point)
 *   3. Verify: e(signature, Q) = e(H_m(data), derived_pk)
 *
 * @param mpk          Core's Master Public Key (96 bytes, G2 point)
 * @param cell_id      gNB's NR Cell ID (5 bytes, 36 bits)
 * @param gnb_key_validity_end Key expiration (minutes since 2024-01-01 00:00 UTC)
 * @param data         Signed data
 * @param data_len     Length of data
 * @param signature    Signature to verify (48 bytes, G1 point)
 * @return TF5_OK on success (signature valid), or TF5_ERR_INVALID_PARAM,
 *         TF5_ERR_CRYPTO, TF5_ERR_KEY_INVALID, TF5_ERR_VERIFY
 */
int tf5_sig_verify(const uint8_t mpk[TF5_IBS_GNB_PK_LEN],
                          const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                          uint32_t gnb_key_validity_end,
                          const uint8_t *data,
                          size_t data_len,
                          const uint8_t signature[TF5_IBS_SIG_LEN]);

#endif /* ENABLE_TF5 */

#endif /* TF5_TESLA_SIG_H */
