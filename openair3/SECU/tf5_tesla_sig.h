/*
 * TESLA Broadcast Authentication - BLS Signature Operations
 *
 * Uses blst library (Supranational) with BLS12-381 curve.
 * Minimal-signature-size variant: Signatures in G1 (48 bytes), Public keys in G2 (96 bytes).
 */

#ifndef TF5_TESLA_SIG_H
#define TF5_TESLA_SIG_H

#ifdef ENABLE_TF5

#include <stdint.h>
#include <stddef.h>

/* BLS12-381 key and signature sizes (non-ETH mode) */
#define TF5_GNB_SECRET_KEY_LEN   32   /* Fr element */
#define TF5_GNB_PUBKEY_LEN   96   /* G2 point (compressed) */
#define TF5_SIG_LEN    48   /* G1 point (compressed) */

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
 * @return 0 on success, negative on error
 */
int tf5_bls_derive_pubkey(const uint8_t secret_key[TF5_GNB_SECRET_KEY_LEN],
                                uint8_t public_key[TF5_GNB_PUBKEY_LEN]);

/**
 * Sign data with BLS
 *
 * @param secret_key   BLS secret key (32 bytes)
 * @param data         Data to sign
 * @param data_len     Length of data
 * @param signature    Output: BLS signature (48 bytes)
 * @return 0 on success, negative on error
 */
int tf5_bls_sign(const uint8_t secret_key[TF5_GNB_SECRET_KEY_LEN],
                       const uint8_t *data,
                       size_t data_len,
                       uint8_t signature[TF5_SIG_LEN]);

/*
 * =============================================================================
 * IBS (Identity-Based Signature) Functions
 * =============================================================================
 */

/* IBS Cell ID size (also defined in tf5_tesla.h) */
#ifndef TF5_IBS_CELL_ID_LEN
#define TF5_IBS_CELL_ID_LEN   5    /* 36 bits = 5 bytes */
#endif

/* IBS Key validity period: 24 bits = 3 bytes (minutes since 2024-01-01) */
#ifndef TF5_IBS_VALIDITY_PERIOD_LEN
#define TF5_IBS_VALIDITY_PERIOD_LEN  3
#endif

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
 * @return 0 on success (signature valid), negative on error
 *
 * Error codes:
 *   -1: Invalid parameters
 *   -3: Invalid MPK format
 *   -4: Invalid signature format
 *   -5: Signature verification failed
 */
int tf5_sig_verify(const uint8_t mpk[TF5_GNB_PUBKEY_LEN],
                          const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                          uint32_t gnb_key_validity_end,
                          const uint8_t *data,
                          size_t data_len,
                          const uint8_t signature[TF5_SIG_LEN]);

#endif /* ENABLE_TF5 */

#endif /* TF5_TESLA_SIG_H */
