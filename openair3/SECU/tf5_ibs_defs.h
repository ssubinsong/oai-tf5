/**
 * @file tf5_ibs_defs.h
 * @brief IBS shared definitions for BLS curve constants and identity parameters
 *
 * Single source of truth for BLS curve constants, IBS identity constants,
 * DST strings, and file format sizes shared between the TESLA/RAN hierarchy
 * (tf5_tesla_sig.h / tf5_tesla.h) and the Core PKG hierarchy (tf5_ibs_pkg.h).
 *
 * NOTE: No ENABLE_TF5 guard - this header is also used by standalone PKG tools.
 */

#ifndef TF5_IBS_DEFS_H
#define TF5_IBS_DEFS_H

#include <stdint.h>
#include <stddef.h>

/* ==========================================================================
 * Unified Error Codes
 *
 * Error handling policy:
 *   - tf5_error_t:  All recoverable/expected failure conditions
 *   - AssertFatal:  Unrecoverable system failures (e.g. OpenSSL primitives
 *                   in tf5_crypto.c that should never fail with valid inputs)
 *   - bool returns: Verification-only functions (safe packet test, key chain)
 * ========================================================================== */

typedef enum {
    TF5_OK                      =  0,
    /* Parameter validation */
    TF5_ERR_INVALID_PARAM       = -1,   // NULL pointers, zero-length, bad format
    TF5_ERR_BUFFER_OVERFLOW     = -2,   // Output buffer too small
    /* Resource allocation */
    TF5_ERR_ALLOC               = -3,   // malloc/calloc failure
    /* Cryptographic operations */
    TF5_ERR_CRYPTO              = -4,   // RNG, hash, or scalar multiplication failure
    TF5_ERR_KEY_INVALID         = -5,   // Key deserialization or validation failure
    /* Signature operations */
    TF5_ERR_SIGN                = -6,   // Signature generation failure
    TF5_ERR_VERIFY              = -7,   // Signature verification failure
    /* File I/O */
    TF5_ERR_FILE_OPEN           = -8,   // fopen / open failure
    TF5_ERR_FILE_IO             = -9,   // fread size mismatch or read error
    TF5_ERR_FILE_WRITE          = -10,  // fwrite or file creation failure
    /* Protocol state */
    TF5_ERR_CHAIN_EXHAUSTED     = -11,  // TESLA key chain interval exceeded
    TF5_ERR_NO_DATA             = -12,  // No buffered entries for verification
    /* Timestamp validation */
    TF5_ERR_TIMESTAMP_OLD       = -13,  // Received timestamp too old
    TF5_ERR_TIMESTAMP_FUTURE    = -14,  // Received timestamp too far in future
} tf5_error_t;

/* ==========================================================================
 * BLS12-381 Curve Base Constants
 * ========================================================================== */

#define TF5_BLS_SCALAR_LEN          32   // Fr element (big-endian)
#define TF5_BLS_G1_COMPRESSED_LEN   48   // G1 point (compressed)
#define TF5_BLS_G2_COMPRESSED_LEN   96   // G2 point (compressed)

/* ==========================================================================
 * Semantic Aliases
 * ========================================================================== */

/*
 * All sizes derive from the BLS12-381 curve parameters above.
 * Minimal-signature-size variant: Signatures in G1, Public keys in G2.
 */
#define TF5_IBS_GNB_SK_LEN      TF5_BLS_SCALAR_LEN          // sk_ID: scalar
#define TF5_IBS_GNB_PK_LEN          TF5_BLS_G2_COMPRESSED_LEN   // Public key in G2
#define TF5_IBS_SIG_LEN                 TF5_BLS_G1_COMPRESSED_LEN   // Signature in G1

#define TF5_IBS_MASTER_SECRET_LEN   TF5_BLS_SCALAR_LEN          // s: master secret scalar
#define TF5_IBS_MASTER_PUBLIC_LEN   TF5_BLS_G2_COMPRESSED_LEN   // MPK = s*Q in G2
#define TF5_IBS_MPK_LEN             TF5_IBS_MASTER_PUBLIC_LEN   // Alias used by TESLA module

/* ==========================================================================
 * IBS Identity Constants
 * ========================================================================== */

#define TF5_IBS_CELL_ID_LEN         5    // NR Cell ID: 36 bits = 5 bytes (per 3GPP TS 38.331)
#define TF5_IBS_VALIDITY_PERIOD_LEN 3    // Key validity period: 24 bits = 3 bytes (minutes since epoch)
#define TF5_IBS_VALIDITY_EPOCH          1704067200UL  // 2024-01-01 00:00:00 UTC (Unix seconds)

// IKM size for H_s: DST (35) + Cell_ID (5) + gnb_key_validity_end (3) = 43 bytes
#define TF5_IBS_IKM_LEN  (TF5_IBS_DST_HS_LEN + TF5_IBS_CELL_ID_LEN + TF5_IBS_VALIDITY_PERIOD_LEN)

/* ==========================================================================
 * gNB Secret Key File Format
 * ========================================================================== */

// File layout: sk_ID (32 bytes) + gnb_key_validity_end (3 bytes, big-endian)
#define TF5_IBS_SK_FILE_SIZE        (TF5_IBS_GNB_SK_LEN + TF5_IBS_VALIDITY_PERIOD_LEN)  // 35 bytes

/* ==========================================================================
 * Domain Separation Tag
 * ========================================================================== */

/*
 * DST for H_s (identity-to-scalar hash).
 * Used by both PKG (key issuance) and RAN (signature verification) to derive
 * pk_ID = H_s(cell_id || gnb_key_validity_end).
 */
#define TF5_IBS_DST_HS              "TF5_IBS_BLS12381_XMD:SHA-256_H_s_v1"
#define TF5_IBS_DST_HS_LEN          35

#endif /* TF5_IBS_DEFS_H */
