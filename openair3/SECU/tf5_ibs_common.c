/*
 * TF5 IBS - Common Utility Functions
 *
 * Shared code for PKG utilities: identity hash, key extraction, file I/O, hex parsing
 *
 * GG09 Schnorr IBS (Ed25519/libsodium):
 *   Extract via crypto_sign_detached: sign(msk, id_msg) → (R||S), sk_id = (S, R)
 *   Identity hash: cid = SHA-512(pk ‖ mpk ‖ cell_id ‖ validity) mod l
 */

#include "tf5_ibs_pkg.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/*
 * Hash identity to scalar for GG09 Schnorr IBS
 *
 * Computes cid = SHA-512(pk ‖ mpk ‖ cell_id ‖ validity_be[3]) mod l
 *
 * Input order follows Ed25519 convention: H(R ‖ A ‖ M) where
 *   R = pk (identity-derived public point)
 *   A = mpk (master public key)
 *   M = cell_id ‖ validity (identity message)
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
    if (!cell_id || !pk || !mpk || !scalar_out || cell_id_len == 0
        || cell_id_len > TF5_IBS_CELL_ID_LEN) {
        return TF5_ERR_INVALID_PARAM;
    }

    /* Encode validity as 3 bytes big-endian */
    uint8_t validity_be[TF5_IBS_VALIDITY_PERIOD_LEN];
    validity_be[0] = (gnb_key_validity_end >> 16) & 0xFF;
    validity_be[1] = (gnb_key_validity_end >> 8) & 0xFF;
    validity_be[2] = gnb_key_validity_end & 0xFF;

    /* concat = pk ‖ mpk ‖ cell_id ‖ validity_be[3]
     * (Ed25519 convention: R ‖ A ‖ M) */
    const size_t concat_len = TF5_ED25519_POINT_LEN + TF5_IBS_MASTER_PUBLIC_LEN
                            + cell_id_len + TF5_IBS_VALIDITY_PERIOD_LEN;
    uint8_t concat[TF5_ED25519_POINT_LEN + TF5_IBS_MASTER_PUBLIC_LEN
                  + TF5_IBS_CELL_ID_LEN + TF5_IBS_VALIDITY_PERIOD_LEN];

    size_t off = 0;
    memcpy(concat + off, pk, TF5_ED25519_POINT_LEN);               off += TF5_ED25519_POINT_LEN;
    memcpy(concat + off, mpk, TF5_IBS_MASTER_PUBLIC_LEN);          off += TF5_IBS_MASTER_PUBLIC_LEN;
    memcpy(concat + off, cell_id, cell_id_len);                     off += cell_id_len;
    memcpy(concat + off, validity_be, TF5_IBS_VALIDITY_PERIOD_LEN);

    /* Hash with SHA-512 (64 bytes) and reduce mod l */
    uint8_t hash_buf[64];
    crypto_hash_sha512(hash_buf, concat, concat_len);
    crypto_core_ed25519_scalar_reduce(scalar_out, hash_buf);

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
 * Compute GG09 Schnorr IBS gNB secret key via Ed25519 signing
 *
 * Uses crypto_sign_detached to sign the identity message (cell_id ‖ validity)
 * with the master seed. The Ed25519 signature (R ‖ S) maps to:
 *   pk = R (identity-derived public point)
 *   y  = S (identity-derived secret scalar)
 *
 * Output:  sk_out = y[32] || pk[32] = 64 bytes
 *
 * This function is deterministic — same inputs always produce the same output
 * (Ed25519 uses a deterministic nonce derived from the seed and message).
 */
int tf5_ibs_compute_gnb_secret(const uint8_t msk[TF5_IBS_MASTER_SECRET_LEN],
                                const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                                uint32_t gnb_key_validity_end,
                                uint8_t sk_out[TF5_IBS_GNB_SK_LEN])
{
    if (!msk || !cell_id || !sk_out) {
        return TF5_ERR_INVALID_PARAM;
    }

    /* Expand seed to full Ed25519 signing key (64 bytes) */
    uint8_t pk_derived[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk_full[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk_derived, sk_full, msk);

    /* Build identity message: cell_id[5] ‖ validity_be[3] = 8 bytes */
    uint8_t id_msg[TF5_IBS_CELL_ID_LEN + TF5_IBS_VALIDITY_PERIOD_LEN];
    memcpy(id_msg, cell_id, TF5_IBS_CELL_ID_LEN);
    id_msg[TF5_IBS_CELL_ID_LEN + 0] = (gnb_key_validity_end >> 16) & 0xFF;
    id_msg[TF5_IBS_CELL_ID_LEN + 1] = (gnb_key_validity_end >> 8) & 0xFF;
    id_msg[TF5_IBS_CELL_ID_LEN + 2] = gnb_key_validity_end & 0xFF;

    /* Sign identity message: produces (R[32] ‖ S[32]) */
    uint8_t sig[crypto_sign_BYTES];
    if (crypto_sign_detached(sig, NULL, id_msg, sizeof(id_msg), sk_full) != 0) {
        sodium_memzero(sk_full, sizeof(sk_full));
        return TF5_ERR_SIGN;
    }

    /* Output: sk_out = S[32] ‖ R[32] (y=S, pk=R) */
    memcpy(sk_out, sig + TF5_ED25519_SCALAR_LEN, TF5_ED25519_SCALAR_LEN);
    memcpy(sk_out + TF5_ED25519_SCALAR_LEN, sig, TF5_ED25519_POINT_LEN);

    /* Clear sensitive data */
    sodium_memzero(sk_full, sizeof(sk_full));

    return TF5_OK;
}
