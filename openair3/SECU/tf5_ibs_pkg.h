/**
 * @file tf5_ibs_pkg.h
 * @brief Core PKG for TF5 GG09 Schnorr Identity-Based Signature (IBS) scheme
 *
 * This module implements the Core PKG for the TESLA GG09 Schnorr IBS scheme
 * (Galindo-Garcia, 2009; 1-level Schnorr IBS over Ed25519).
 * The PKG generates master keys and issues gNB-specific secret keys
 * based on the gNB's NR Cell ID and key validity period.
 *
 * GG09 Schnorr-2IBS Scheme:
 *   - Master secret: z (scalar in Z_l)
 *   - Master public key: MPK = z·B where B is the Ed25519 base point
 *   - gNB identity: NR Cell ID (36 bits) || gnb_key_validity_end (24 bits)
 *   - Extract: b ← Z_l, pk = b·B, cid = H(id‖pk‖mpk), y = cid·z + b
 *   - gNB secret key: sk_id = (y[32], pk[32]) = 64 bytes
 *   - Signature: σ = R[32] || sigma[32] || pk[32] = 96 bytes
 *   - Verification: cid = H(id‖pk‖mpk), Q = cid·mpk + pk, check σ·B − h·Q == R
 */

#ifndef TF5_IBS_PKG_H
#define TF5_IBS_PKG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "tf5_ibs_defs.h"

/*
 * =============================================================================
 * API Functions
 * =============================================================================
 */

/**
 * Generate Core PKG master keypair
 *
 * Generates a new master secret key (z) and corresponding master public key
 * (MPK = z·B) using cryptographically secure randomness.
 *
 * @param msk_path  Path to save master secret key (32 bytes, binary)
 * @param mpk_path  Path to save master public key (32 bytes, binary)
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_CRYPTO,
 *         TF5_ERR_KEY_INVALID, TF5_ERR_FILE_WRITE
 */
int tf5_ibs_generate_master_keypair(const char *msk_path, const char *mpk_path);

/**
 * Issue gNB secret key from Cell ID and validity period
 *
 * Computes the gNB's secret key:
 *   b ← Z_l, pk = b·B, cid = H(id‖pk‖mpk), y = cid·z + b
 *   sk_id = (y[32], pk[32]) = 64 bytes
 *
 * @param msk_path     Path to master secret key file
 * @param cell_id      NR Cell ID (5 bytes, 36 bits with 4 padding bits)
 * @param gnb_key_validity_end Key expiration (minutes since 2024-01-01 00:00:00 UTC)
 * @param sk_path      Path to save gNB secret key (67 bytes: 64B sk_id + 3B validity)
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_FILE_WRITE,
 *         or propagated error from tf5_ibs_load_master_secret / tf5_ibs_compute_gnb_secret
 */
int tf5_ibs_issue_gnb_key(const char *msk_path,
                           const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                           uint32_t gnb_key_validity_end,
                           const char *sk_path);

/**
 * Hash identity to scalar for GG09 Schnorr IBS
 *
 * Computes cid = BLAKE2b(cell_id ‖ validity_be[3] ‖ pk ‖ mpk) mod l
 *
 * Used by both PKG (key extraction) and RAN (signature verification) to derive
 * the identity scalar from public parameters.
 *
 * @param cell_id      NR Cell ID (5 bytes)
 * @param cell_id_len  Length of cell_id (should be TF5_IBS_CELL_ID_LEN)
 * @param gnb_key_validity_end Key expiration (minutes since 2024-01-01 00:00:00 UTC)
 * @param pk           Identity-derived public key (32 bytes, Ed25519 point)
 * @param mpk          Master public key (32 bytes, Ed25519 point)
 * @param scalar_out   Output buffer for scalar (32 bytes, little-endian)
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM
 */
int tf5_ibs_hash_identity(const uint8_t *cell_id,
                           size_t cell_id_len,
                           uint32_t gnb_key_validity_end,
                           const uint8_t pk[TF5_ED25519_POINT_LEN],
                           const uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN],
                           uint8_t scalar_out[TF5_ED25519_SCALAR_LEN]);

/**
 * Parse Cell ID from hex string
 *
 * Converts a hex string (e.g., "123456789") to 5-byte Cell ID format.
 * The input should be 9 hex characters representing 36 bits.
 * The output is 5 bytes with 4 padding bits (MSB of last byte).
 *
 * @param hex_str    Hex string (9 characters for 36 bits)
 * @param cell_id    Output buffer (5 bytes)
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM
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
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM
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
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_FILE_OPEN, TF5_ERR_FILE_IO
 */
int tf5_ibs_load_master_secret(const char *filepath,
                                uint8_t msk_out[TF5_IBS_MASTER_SECRET_LEN]);

/**
 * Compute GG09 Schnorr IBS gNB secret key from master secret, Cell ID, and validity
 *
 * Extract: b ← Z_l, pk = b·B, cid = H(id‖pk‖mpk), y = cid·z + b
 * Output:  sk_out = y[32] || pk[32] = 64 bytes
 *
 * NOTE: This function is NOT deterministic — it generates a random b each call.
 *
 * @param msk          Master secret key (32 bytes, Ed25519 scalar)
 * @param cell_id      NR Cell ID (5 bytes)
 * @param gnb_key_validity_end Key expiration (minutes since 2024-01-01 00:00:00 UTC)
 * @param mpk          Master public key (32 bytes, Ed25519 point)
 * @param sk_out       Output gNB secret key (64 bytes: y[32] + pk[32])
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_KEY_INVALID, TF5_ERR_CRYPTO
 */
int tf5_ibs_compute_gnb_secret(const uint8_t msk[TF5_IBS_MASTER_SECRET_LEN],
                                const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                                uint32_t gnb_key_validity_end,
                                const uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN],
                                uint8_t sk_out[TF5_IBS_GNB_SK_LEN]);

/*
 * =============================================================================
 * Validity Period Conversion Utilities
 * =============================================================================
 */

/**
 * Convert Unix timestamp to gnb_key_validity_end format
 *
 * @param unix_sec  Unix timestamp (seconds since 1970-01-01)
 * @return Minutes since 2024-01-01 00:00:00 UTC (24-bit value)
 */
static inline uint32_t tf5_unix_to_gnb_key_validity(uint64_t unix_sec)
{
    if (unix_sec <= TF5_IBS_VALIDITY_EPOCH) {
        return 0;
    }
    return (uint32_t)((unix_sec - TF5_IBS_VALIDITY_EPOCH) / 60);
}

/**
 * Convert gnb_key_validity_end format to Unix timestamp
 *
 * @param gnb_key_validity_end  Minutes since 2024-01-01 00:00:00 UTC
 * @return Unix timestamp (seconds since 1970-01-01)
 */
static inline uint64_t tf5_gnb_key_validity_to_unix(uint32_t gnb_key_validity_end)
{
    return TF5_IBS_VALIDITY_EPOCH + (uint64_t)gnb_key_validity_end * 60;
}

#endif /* TF5_IBS_PKG_H */
