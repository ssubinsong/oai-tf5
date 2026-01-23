/*
 * TF5 Identity-Based Signature (IBS) - Private Key Generator (PKG)
 *
 * This module implements the Core PKG for the TESLA IBS scheme.
 * The PKG generates master keys and issues gNB-specific secret keys
 * based on the gNB's NR Cell ID.
 *
 * IBS Scheme (BLS-based):
 *   - Master secret: s (scalar in Z_r)
 *   - Master public key: MPK = s*Q where Q is G2 generator
 *   - gNB identity: NR Cell ID (36 bits)
 *   - gNB public key: pk_ID = H_s(Cell_ID) (scalar)
 *   - gNB secret key: sk_ID = s * pk_ID mod r (scalar)
 *   - Signature: Sigma = sk_ID * H_m(m) (G1 point)
 *   - Verification: e(Sigma, Q) = e(H_m(m), pk_ID * MPK)
 */

#ifndef TF5_IBS_PKG_H
#define TF5_IBS_PKG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * Key sizes (BLS12-381 curve)
 */
#define TF5_IBS_MASTER_SECRET_LEN   32   /* s: scalar in Z_r (big-endian) */
#define TF5_IBS_MASTER_PUBLIC_LEN   96   /* MPK = s*Q: G2 point (compressed) */
#define TF5_IBS_GNB_SECRET_LEN      32   /* sk_ID: scalar (big-endian) */
#define TF5_IBS_SIGNATURE_LEN       48   /* Sigma: G1 point (compressed) */

/*
 * NR Cell ID: 36 bits = 5 bytes
 * Per 3GPP TS 38.331, cellIdentity is a BIT STRING (SIZE (36))
 */
#define TF5_IBS_CELL_ID_LEN         5
#define TF5_IBS_CELL_ID_BITS        36

/*
 * Domain Separation Tag for H_s (identity-to-scalar hash)
 * Uses IETF hash-to-field approach via blst_keygen
 */
#define TF5_IBS_DST_HS      "TF5_IBS_BLS12381_XMD:SHA-256_H_s_v1"
#define TF5_IBS_DST_HS_LEN  35

/*
 * File format constants
 */
#define TF5_IBS_MSK_FILE_SIZE   TF5_IBS_MASTER_SECRET_LEN   /* 32 bytes */
#define TF5_IBS_MPK_FILE_SIZE   TF5_IBS_MASTER_PUBLIC_LEN   /* 96 bytes */
#define TF5_IBS_SK_FILE_SIZE    TF5_IBS_GNB_SECRET_LEN      /* 32 bytes */

/*
 * =============================================================================
 * API Functions
 * =============================================================================
 */

/**
 * Generate Core PKG master keypair
 *
 * Generates a new master secret key (s) and corresponding master public key
 * (MPK = s*Q) using cryptographically secure randomness.
 *
 * @param msk_path  Path to save master secret key (32 bytes, binary)
 * @param mpk_path  Path to save master public key (96 bytes, binary)
 * @return 0 on success, negative on error
 *
 * Error codes:
 *   -1: Invalid parameters
 *   -2: Failed to read random bytes
 *   -3: Failed to create output file
 *   -4: Failed to write output file
 */
int tf5_ibs_generate_master_keypair(const char *msk_path, const char *mpk_path);

/**
 * Issue gNB secret key from Cell ID
 *
 * Computes the gNB's secret key as sk_ID = s * H_s(cell_id) mod r
 *
 * @param msk_path   Path to master secret key file
 * @param cell_id    NR Cell ID (5 bytes, 36 bits with 4 padding bits)
 * @param sk_path    Path to save gNB secret key (32 bytes, binary)
 * @return 0 on success, negative on error
 *
 * Error codes:
 *   -1: Invalid parameters
 *   -2: Failed to open master secret file
 *   -3: Invalid master secret format
 *   -4: Scalar multiplication failed
 *   -5: Failed to create output file
 */
int tf5_ibs_issue_gnb_key(const char *msk_path,
                           const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                           const char *sk_path);

/**
 * Hash identity (Cell ID) to scalar in Z_r
 *
 * Implements H_s: {0,1}* -> Z_r using IETF hash-to-field
 *
 * @param cell_id     NR Cell ID (5 bytes)
 * @param cell_id_len Length of cell_id (should be TF5_IBS_CELL_ID_LEN)
 * @param scalar_out  Output buffer for scalar (32 bytes, big-endian)
 * @return 0 on success, negative on error
 */
int tf5_ibs_hash_to_scalar(const uint8_t *cell_id,
                            size_t cell_id_len,
                            uint8_t scalar_out[TF5_IBS_GNB_SECRET_LEN]);

/**
 * Parse Cell ID from hex string
 *
 * Converts a hex string (e.g., "123456789") to 5-byte Cell ID format.
 * The input should be 9 hex characters representing 36 bits.
 * The output is 5 bytes with 4 padding bits (MSB of last byte).
 *
 * @param hex_str    Hex string (9 characters for 36 bits)
 * @param cell_id    Output buffer (5 bytes)
 * @return 0 on success, negative on error
 */
int tf5_ibs_parse_cell_id_hex(const char *hex_str,
                               uint8_t cell_id[TF5_IBS_CELL_ID_LEN]);

/**
 * Format Cell ID as hex string
 *
 * Converts 5-byte Cell ID to hex string format.
 *
 * @param cell_id    Cell ID (5 bytes)
 * @param hex_str    Output buffer (must be at least 10 bytes for 9 chars + null)
 * @return 0 on success, negative on error
 */
int tf5_ibs_format_cell_id_hex(const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                                char hex_str[10]);

/*
 * =============================================================================
 * Low-level Functions (for integration with OAI)
 * =============================================================================
 */

/**
 * Load master secret key from file
 *
 * @param filepath   Path to master secret key file
 * @param msk_out    Output buffer (32 bytes)
 * @return 0 on success, negative on error
 */
int tf5_ibs_load_master_secret(const char *filepath,
                                uint8_t msk_out[TF5_IBS_MASTER_SECRET_LEN]);

/**
 * Load master public key from file
 *
 * @param filepath   Path to master public key file
 * @param mpk_out    Output buffer (96 bytes)
 * @return 0 on success, negative on error
 */
int tf5_ibs_load_master_public(const char *filepath,
                                uint8_t mpk_out[TF5_IBS_MASTER_PUBLIC_LEN]);

/**
 * Compute gNB secret key from master secret and Cell ID
 *
 * sk_ID = s * H_s(cell_id) mod r
 *
 * @param msk        Master secret key (32 bytes)
 * @param cell_id    NR Cell ID (5 bytes)
 * @param sk_out     Output gNB secret key (32 bytes)
 * @return 0 on success, negative on error
 */
int tf5_ibs_compute_gnb_secret(const uint8_t msk[TF5_IBS_MASTER_SECRET_LEN],
                                const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                                uint8_t sk_out[TF5_IBS_GNB_SECRET_LEN]);

#endif /* TF5_IBS_PKG_H */
