/*
 * TF5 IBS - Common Utility Functions
 *
 * Shared code for PKG utilities: identity hash, key extraction, file I/O, hex parsing
 *
 * GG09 Schnorr IBS (Ed25519/libsodium):
 *   Extract: b ← Z_l, pk = b·B, cid = H(id‖pk‖mpk), y = cid·z + b
 *   sk_id = (y[32], pk[32]) = 64 bytes
 */

#include "tf5_ibs_pkg.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Reduce a 32-byte value mod l (Ed25519 group order).
 * libsodium's crypto_core_ed25519_scalar_reduce requires 64-byte input. */
static void scalar_reduce_32(uint8_t out[32], const uint8_t in[32])
{
    uint8_t tmp[64];
    memcpy(tmp, in, 32);
    memset(tmp + 32, 0, 32);
    crypto_core_ed25519_scalar_reduce(out, tmp);
}

/*
 * Hash identity to scalar for GG09 Schnorr IBS
 *
 * Computes cid = BLAKE2b(cell_id ‖ validity_be[3] ‖ pk ‖ mpk) mod l
 *
 * Used by both PKG (key extraction) and RAN (signature verification) to derive
 * the identity scalar from public parameters.
 */
int tf5_ibs_hash_identity(const uint8_t *cell_id,
                           size_t cell_id_len,
                           uint32_t gnb_key_validity_end,
                           const uint8_t pk[TF5_ED25519_POINT_LEN],
                           const uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN],
                           uint8_t scalar_out[TF5_ED25519_SCALAR_LEN])
{
    if (!cell_id || !pk || !mpk || !scalar_out || cell_id_len == 0) {
        return TF5_ERR_INVALID_PARAM;
    }

    /* Encode validity as 3 bytes big-endian */
    uint8_t validity_be[TF5_IBS_VALIDITY_PERIOD_LEN];
    validity_be[0] = (gnb_key_validity_end >> 16) & 0xFF;
    validity_be[1] = (gnb_key_validity_end >> 8) & 0xFF;
    validity_be[2] = gnb_key_validity_end & 0xFF;

    /* concat = cell_id ‖ validity_be[3] ‖ pk ‖ mpk */
    const size_t concat_len = cell_id_len + TF5_IBS_VALIDITY_PERIOD_LEN
                            + TF5_ED25519_POINT_LEN + TF5_IBS_MASTER_PUBLIC_LEN;
    uint8_t concat[TF5_IBS_CELL_ID_LEN + TF5_IBS_VALIDITY_PERIOD_LEN
                  + TF5_ED25519_POINT_LEN + TF5_IBS_MASTER_PUBLIC_LEN];

    size_t off = 0;
    memcpy(concat + off, cell_id, cell_id_len);                     off += cell_id_len;
    memcpy(concat + off, validity_be, TF5_IBS_VALIDITY_PERIOD_LEN); off += TF5_IBS_VALIDITY_PERIOD_LEN;
    memcpy(concat + off, pk, TF5_ED25519_POINT_LEN);               off += TF5_ED25519_POINT_LEN;
    memcpy(concat + off, mpk, TF5_IBS_MASTER_PUBLIC_LEN);

    /* Hash with BLAKE2b and reduce mod l */
    uint8_t hash_buf[32];
    crypto_generichash(hash_buf, 32, concat, concat_len, NULL, 0);
    scalar_reduce_32(scalar_out, hash_buf);

    return TF5_OK;
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

    return TF5_OK;
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
    return TF5_OK;
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
        sodium_memzero(msk_out, TF5_IBS_MASTER_SECRET_LEN);
        return TF5_ERR_FILE_IO;
    }

    return TF5_OK;
}

/*
 * Compute GG09 Schnorr IBS gNB secret key from master secret, Cell ID, and validity
 *
 * Extract: b ← Z_l, pk = b·B, cid = H(id‖pk‖mpk), y = cid·z + b
 * Output:  sk_out = y[32] || pk[32] = 64 bytes
 *
 * NOTE: This function is NOT deterministic — it generates a random b each call.
 */
int tf5_ibs_compute_gnb_secret(const uint8_t msk[TF5_IBS_MASTER_SECRET_LEN],
                                const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                                uint32_t gnb_key_validity_end,
                                const uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN],
                                uint8_t sk_out[TF5_IBS_GNB_SK_LEN])
{
    if (!msk || !cell_id || !mpk || !sk_out) {
        return TF5_ERR_INVALID_PARAM;
    }

    /* Reduce msk to ensure it's a valid scalar mod l */
    uint8_t z[TF5_ED25519_SCALAR_LEN];
    scalar_reduce_32(z, msk);

    /* b ← random scalar in Z_l */
    uint8_t b[TF5_ED25519_SCALAR_LEN];
    randombytes_buf(b, TF5_ED25519_SCALAR_LEN);
    scalar_reduce_32(b, b);

    /* pk = b·B */
    uint8_t pk[TF5_ED25519_POINT_LEN];
    if (crypto_scalarmult_ed25519_base_noclamp(pk, b) != 0) {
        sodium_memzero(b, sizeof(b));
        sodium_memzero(z, sizeof(z));
        return TF5_ERR_CRYPTO;
    }

    /* cid = H(cell_id ‖ validity ‖ pk ‖ mpk) mod l */
    uint8_t cid[TF5_ED25519_SCALAR_LEN];
    int rc = tf5_ibs_hash_identity(cell_id, TF5_IBS_CELL_ID_LEN,
                                    gnb_key_validity_end, pk, mpk, cid);
    if (rc != TF5_OK) {
        sodium_memzero(b, sizeof(b));
        sodium_memzero(z, sizeof(z));
        return rc;
    }

    /* y = cid·z + b mod l */
    uint8_t y[TF5_ED25519_SCALAR_LEN];
    uint8_t cid_z[TF5_ED25519_SCALAR_LEN];
    crypto_core_ed25519_scalar_mul(cid_z, cid, z);
    crypto_core_ed25519_scalar_add(y, cid_z, b);

    /* Output: sk_out = y[32] || pk[32] */
    memcpy(sk_out, y, TF5_ED25519_SCALAR_LEN);
    memcpy(sk_out + TF5_ED25519_SCALAR_LEN, pk, TF5_ED25519_POINT_LEN);

    /* Clear sensitive data */
    sodium_memzero(b, sizeof(b));
    sodium_memzero(z, sizeof(z));
    sodium_memzero(y, sizeof(y));
    sodium_memzero(cid, sizeof(cid));
    sodium_memzero(cid_z, sizeof(cid_z));

    return TF5_OK;
}
