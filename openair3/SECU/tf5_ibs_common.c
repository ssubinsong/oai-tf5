/*
 * TF5 IBS - Common Utility Functions
 *
 * Shared code for PKG utilities: H_s hash, file I/O, hex parsing
 */

#include "tf5_ibs_pkg.h"
#include "blst.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/crypto.h>

/*
 * Hash identity (Cell ID || gnb_key_validity_end) to scalar in Z_r
 *
 * Implements H_s: {0,1}* -> Z_r by:
 *   1. Expanding (DST || cell_id || gnb_key_validity_end) to create IKM for blst_keygen
 *   2. Using blst_keygen to derive scalar with proper mod r reduction
 *
 * Note: blst_keygen requires IKM >= 32 bytes for security.
 * IKM = DST (35 bytes) || cell_id (5 bytes) || gnb_key_validity_end (3 bytes) = 43 bytes
 */
int tf5_ibs_hash_to_scalar(const uint8_t *cell_id,
                            size_t cell_id_len,
                            uint32_t gnb_key_validity_end,
                            uint8_t scalar_out[TF5_IBS_GNB_SK_LEN])
{
    if (!cell_id || !scalar_out || cell_id_len == 0) {
        return TF5_ERR_INVALID_PARAM;
    }

    /*
     * Create expanded IKM by concatenating DST, cell_id, and gnb_key_validity_end.
     * This ensures:
     *   - IKM >= 32 bytes (43 bytes: 35 DST + 5 cell_id + 3 validity)
     *   - Domain separation is inherent in the IKM itself
     *   - Key is bound to both Cell ID and validity period
     */
    uint8_t ikm[TF5_IBS_IKM_LEN];
    memcpy(ikm, TF5_IBS_DST_HS, TF5_IBS_DST_HS_LEN);
    memcpy(ikm + TF5_IBS_DST_HS_LEN, cell_id, cell_id_len);

    /* Encode gnb_key_validity_end as 3 bytes big-endian */
    size_t off = TF5_IBS_DST_HS_LEN + cell_id_len;
    ikm[off + 0] = (gnb_key_validity_end >> 16) & 0xFF;
    ikm[off + 1] = (gnb_key_validity_end >> 8) & 0xFF;
    ikm[off + 2] = gnb_key_validity_end & 0xFF;

    blst_scalar pk_id;

    /*
     * blst_keygen performs HKDF-Extract + HKDF-Expand + mod r reduction.
     * Using empty info since domain separation is in IKM.
     */
    blst_keygen(&pk_id, ikm, sizeof(ikm), NULL, 0);

    /* Serialize scalar as big-endian bytes */
    blst_bendian_from_scalar(scalar_out, &pk_id);

    /* Clear sensitive data */
    OPENSSL_cleanse(&pk_id, sizeof(pk_id));
    OPENSSL_cleanse(ikm, sizeof(ikm));

    return 0;
}

/*
 * Parse Cell ID from hex string
 *
 * Input: 9 hex characters representing 36 bits (e.g., "123456789")
 * Output: 5 bytes with layout:
 *   byte[0] = bits 35-28
 *   byte[1] = bits 27-20
 *   byte[2] = bits 19-12
 *   byte[3] = bits 11-4
 *   byte[4] = bits 3-0 in upper nibble, lower nibble = 0 (padding)
 */
int tf5_ibs_parse_cell_id_hex(const char *hex_str,
                               uint8_t cell_id[TF5_IBS_CELL_ID_LEN])
{
    if (!hex_str || !cell_id) {
        return TF5_ERR_INVALID_PARAM;
    }

    size_t len = strlen(hex_str);
    if (len != 9) {
        /* Expect exactly 9 hex chars for 36 bits */
        return TF5_ERR_INVALID_PARAM;
    }

    /* Validate all characters are hex */
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)hex_str[i])) {
            return TF5_ERR_INVALID_PARAM;
        }
    }

    /* Parse as 64-bit value (only lower 36 bits used) */
    uint64_t value = 0;
    for (size_t i = 0; i < len; i++) {
        char c = hex_str[i];
        uint8_t nibble;
        if (c >= '0' && c <= '9') {
            nibble = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            nibble = 10 + (c - 'a');
        } else { /* c >= 'A' && c <= 'F' */
            nibble = 10 + (c - 'A');
        }
        value = (value << 4) | nibble;
    }

    /* Pack into 5 bytes (36 bits + 4 padding bits) */
    cell_id[0] = (value >> 28) & 0xFF;
    cell_id[1] = (value >> 20) & 0xFF;
    cell_id[2] = (value >> 12) & 0xFF;
    cell_id[3] = (value >> 4) & 0xFF;
    cell_id[4] = (value << 4) & 0xF0;  /* 4 padding bits in lower nibble */

    return 0;
}

/*
 * Format Cell ID as hex string
 */
int tf5_ibs_format_cell_id_hex(const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                                char hex_str[10])
{
    if (!cell_id || !hex_str) {
        return TF5_ERR_INVALID_PARAM;
    }

    /* Reconstruct 36-bit value from 5 bytes */
    uint64_t value = ((uint64_t)cell_id[0] << 28) |
                     ((uint64_t)cell_id[1] << 20) |
                     ((uint64_t)cell_id[2] << 12) |
                     ((uint64_t)cell_id[3] << 4) |
                     ((uint64_t)cell_id[4] >> 4);

    snprintf(hex_str, 10, "%09llx", (unsigned long long)value);
    return 0;
}

/*
 * Load master secret key from file
 */
int tf5_ibs_load_master_secret(const char *filepath,
                                uint8_t msk_out[TF5_IBS_MASTER_SECRET_LEN])
{
    if (!filepath || !msk_out) {
        return TF5_ERR_INVALID_PARAM;
    }

    FILE *f = fopen(filepath, "rb");
    if (!f) {
        return TF5_ERR_FILE_OPEN;
    }

    size_t n = fread(msk_out, 1, TF5_IBS_MASTER_SECRET_LEN, f);
    fclose(f);

    if (n != TF5_IBS_MASTER_SECRET_LEN) {
        OPENSSL_cleanse(msk_out, TF5_IBS_MASTER_SECRET_LEN);
        return TF5_ERR_FILE_IO;
    }

    return 0;
}

/*
 * Compute gNB secret key from master secret, Cell ID, and validity period
 *
 * sk_ID = s * H_s(cell_id || gnb_key_validity_end) mod r
 */
int tf5_ibs_compute_gnb_secret(const uint8_t msk[TF5_IBS_MASTER_SECRET_LEN],
                                const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                                uint32_t gnb_key_validity_end,
                                uint8_t sk_out[TF5_IBS_GNB_SK_LEN])
{
    if (!msk || !cell_id || !sk_out) {
        return TF5_ERR_INVALID_PARAM;
    }

    blst_scalar s, pk_id, sk_id;

    /* Deserialize master secret */
    blst_scalar_from_bendian(&s, msk);

    /* Validate master secret is in valid range */
    if (!blst_sk_check(&s)) {
        OPENSSL_cleanse(&s, sizeof(s));
        return TF5_ERR_KEY_INVALID;
    }

    /* Compute pk_ID = H_s(cell_id || gnb_key_validity_end) */
    uint8_t pk_id_scalar[TF5_IBS_GNB_SK_LEN];
    if (tf5_ibs_hash_to_scalar(cell_id, TF5_IBS_CELL_ID_LEN, gnb_key_validity_end, pk_id_scalar) != 0) {
        OPENSSL_cleanse(&s, sizeof(s));
        return TF5_ERR_CRYPTO;
    }
    blst_scalar_from_bendian(&pk_id, pk_id_scalar);
    OPENSSL_cleanse(pk_id_scalar, sizeof(pk_id_scalar));

    /* Compute sk_ID = s * pk_ID mod r */
    if (!blst_sk_mul_n_check(&sk_id, &s, &pk_id)) {
        /* Multiplication failed (result is zero, which shouldn't happen) */
        OPENSSL_cleanse(&s, sizeof(s));
        OPENSSL_cleanse(&pk_id, sizeof(pk_id));
        return TF5_ERR_CRYPTO;
    }

    /* Serialize result */
    blst_bendian_from_scalar(sk_out, &sk_id);

    /* Clear sensitive data from memory */
    OPENSSL_cleanse(&s, sizeof(s));
    OPENSSL_cleanse(&pk_id, sizeof(pk_id));
    OPENSSL_cleanse(&sk_id, sizeof(sk_id));

    return 0;
}
