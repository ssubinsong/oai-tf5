/*
 * TF5 Identity-Based Signature (IBS) - Private Key Generator (PKG)
 *
 * This module implements the Core PKG for the TESLA IBS scheme.
 * The PKG generates master keys and issues gNB-specific secret keys
 * based on the gNB's NR Cell ID and key validity period.
 *
 * IBS Scheme (BLS-based):
 *   - Master secret: s (scalar in Z_r)
 *   - Master public key: MPK = s*Q where Q is G2 generator
 *   - gNB identity: NR Cell ID (36 bits) || gnb_key_validity_end (24 bits)
 *   - gNB public key: pk_ID = H_s(Cell_ID || gnb_key_validity_end) (scalar)
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
 * Key validity period: 24 bits = 3 bytes
 * Encodes minutes since 2024-01-01 00:00:00 UTC
 * Range: 0 to 16,777,215 minutes (~31.9 years, covers until ~2056)
 */
#define TF5_IBS_VALIDITY_LEN        3
#define TF5_VALIDITY_EPOCH          1704067200UL  /* 2024-01-01 00:00:00 UTC (Unix seconds) */

/*
 * Domain Separation Tag for H_s (identity-to-scalar hash)
 * Uses IETF hash-to-field approach via blst_keygen
 * IKM = DST || Cell_ID || gnb_key_validity_end
 */
#define TF5_IBS_DST_HS      "TF5_IBS_BLS12381_XMD:SHA-256_H_s_v1"
#define TF5_IBS_DST_HS_LEN  35

/*
 * File format constants
 */
#define TF5_IBS_MSK_FILE_SIZE   TF5_IBS_MASTER_SECRET_LEN   /* 32 bytes */
#define TF5_IBS_MPK_FILE_SIZE   TF5_IBS_MASTER_PUBLIC_LEN   /* 96 bytes */
/* gNB secret key file: sk_ID (32 bytes) + gnb_key_validity_end (3 bytes, big-endian) */
#define TF5_IBS_SK_FILE_SIZE    (TF5_IBS_GNB_SECRET_LEN + TF5_IBS_VALIDITY_LEN)  /* 35 bytes */

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
 * Issue gNB secret key from Cell ID and validity period
 *
 * Computes the gNB's secret key as sk_ID = s * H_s(cell_id || gnb_key_validity_end) mod r
 *
 * @param msk_path     Path to master secret key file
 * @param cell_id      NR Cell ID (5 bytes, 36 bits with 4 padding bits)
 * @param gnb_key_validity_end Key expiration (minutes since 2024-01-01 00:00:00 UTC)
 * @param sk_path      Path to save gNB secret key (32 bytes, binary)
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
                           uint32_t gnb_key_validity_end,
                           const char *sk_path);

/**
 * Hash identity (Cell ID || gnb_key_validity_end) to scalar in Z_r
 *
 * Implements H_s: {0,1}* -> Z_r using IETF hash-to-field
 * IKM = DST || cell_id || gnb_key_validity_end (3 bytes, big-endian)
 *
 * @param cell_id      NR Cell ID (5 bytes)
 * @param cell_id_len  Length of cell_id (should be TF5_IBS_CELL_ID_LEN)
 * @param gnb_key_validity_end Key expiration (minutes since 2024-01-01 00:00:00 UTC)
 * @param scalar_out   Output buffer for scalar (32 bytes, big-endian)
 * @return 0 on success, negative on error
 */
int tf5_ibs_hash_to_scalar(const uint8_t *cell_id,
                            size_t cell_id_len,
                            uint32_t gnb_key_validity_end,
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
 * Compute gNB secret key from master secret, Cell ID, and validity period
 *
 * sk_ID = s * H_s(cell_id || gnb_key_validity_end) mod r
 *
 * @param msk          Master secret key (32 bytes)
 * @param cell_id      NR Cell ID (5 bytes)
 * @param gnb_key_validity_end Key expiration (minutes since 2024-01-01 00:00:00 UTC)
 * @param sk_out       Output gNB secret key (32 bytes)
 * @return 0 on success, negative on error
 */
int tf5_ibs_compute_gnb_secret(const uint8_t msk[TF5_IBS_MASTER_SECRET_LEN],
                                const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                                uint32_t gnb_key_validity_end,
                                uint8_t sk_out[TF5_IBS_GNB_SECRET_LEN]);

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
static inline uint32_t tf5_ibs_unix_to_gnb_key_validity(uint64_t unix_sec)
{
    if (unix_sec <= TF5_VALIDITY_EPOCH) {
        return 0;
    }
    return (uint32_t)((unix_sec - TF5_VALIDITY_EPOCH) / 60);
}

/**
 * Convert gnb_key_validity_end format to Unix timestamp
 *
 * @param gnb_key_validity_end  Minutes since 2024-01-01 00:00:00 UTC
 * @return Unix timestamp (seconds since 1970-01-01)
 */
static inline uint64_t tf5_ibs_gnb_key_validity_to_unix(uint32_t gnb_key_validity_end)
{
    return TF5_VALIDITY_EPOCH + (uint64_t)gnb_key_validity_end * 60;
}

#endif /* TF5_IBS_PKG_H */
