#ifdef ENABLE_TF5

#include "tf5_tesla_sig.h"
#include "common/utils/LOG/log.h"

#include <string.h>
#include <stdio.h>
#include "blst.h"

/* Domain Separation Tag for hash-to-curve (IETF BLS basic scheme) */
static const uint8_t TF5_BLS_DST[] = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
static const size_t TF5_BLS_DST_LEN = sizeof(TF5_BLS_DST) - 1;

int tf5_bls_init(void)
{
    /* blst library requires no initialization - it is stateless */
    LOG_I(NR_RRC, "TESLA: BLST library ready (BLS12-381, pk-in-G2 mode)\n");
    return 0;
}

int tf5_bls_derive_pubkey(const uint8_t secret_key[TF5_GNB_SECRET_KEY_LEN],
                                uint8_t public_key[TF5_GNB_PUBKEY_LEN])
{
    if (!secret_key || !public_key) {
        return -1;
    }

    blst_scalar sk;
    blst_p2 pk_p2;

    /* Deserialize secret key (big-endian) */
    blst_scalar_from_bendian(&sk, secret_key);

    /* Check secret key validity */
    if (!blst_sk_check(&sk)) {
        LOG_E(NR_RRC, "TESLA: Invalid secret key scalar\n");
        return -3;
    }

    /* Derive public key in G2 */
    blst_sk_to_pk_in_g2(&pk_p2, &sk);

    /* Serialize public key (compressed, 96 bytes) */
    blst_p2_compress(public_key, &pk_p2);

    /* Clear secret key from memory */
    memset(&sk, 0, sizeof(sk));

    return 0;
}

int tf5_bls_sign(const uint8_t secret_key[TF5_GNB_SECRET_KEY_LEN],
                       const uint8_t *data,
                       size_t data_len,
                       uint8_t signature[TF5_SIG_LEN])
{
    if (!secret_key || !data || !signature || data_len == 0) {
        return -1;
    }

    blst_scalar sk;
    blst_p1 hash_point;
    blst_p1 sig_p1;

    /* Deserialize secret key (big-endian) */
    blst_scalar_from_bendian(&sk, secret_key);

    /* Check secret key validity */
    if (!blst_sk_check(&sk)) {
        LOG_E(NR_RRC, "TESLA: Invalid secret key for signing\n");
        memset(&sk, 0, sizeof(sk));
        return -3;
    }

    /* Hash message to G1 */
    blst_hash_to_g1(&hash_point, data, data_len, TF5_BLS_DST, TF5_BLS_DST_LEN, NULL, 0);

    /* Sign: sig = sk * H(m) */
    blst_sign_pk_in_g2(&sig_p1, &hash_point, &sk);

    /* Serialize signature (compressed, 48 bytes) */
    blst_p1_compress(signature, &sig_p1);

    /* Clear secret key from memory */
    memset(&sk, 0, sizeof(sk));

    return 0;
}

/*
 * =============================================================================
 * IBS (Identity-Based Signature) Functions
 * =============================================================================
 */

/* IBS Domain Separation Tag for H_s (identity-to-scalar hash) */
static const uint8_t TF5_IBS_DST_HS[] = "TF5_IBS_BLS12381_XMD:SHA-256_H_s_v1";
static const size_t TF5_IBS_DST_HS_LEN = sizeof(TF5_IBS_DST_HS) - 1;

/* IKM size: DST (35) + Cell_ID (5) + gnb_key_validity_end (3) = 43 bytes */
#define TF5_IBS_IKM_LEN  (TF5_IBS_DST_HS_LEN + TF5_IBS_CELL_ID_LEN + TF5_IBS_VALIDITY_PERIOD_LEN)

/*
 * Thread-local MPK cache for verification fast path.
 * Only MPK parsing/in-G2 checks are cached; per-message derived_pk and pairing
 * verification remain unchanged.
 */
typedef struct {
    int valid;
    uint8_t mpk[TF5_GNB_PUBKEY_LEN];
    blst_p2_affine mpk_affine;
} tf5_mpk_cache_t;

static __thread tf5_mpk_cache_t s_mpk_cache = {0};

int tf5_sig_verify(const uint8_t mpk[TF5_GNB_PUBKEY_LEN],
                          const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                          uint32_t gnb_key_validity_end,
                          const uint8_t *data,
                          size_t data_len,
                          const uint8_t signature[TF5_SIG_LEN])
{
    if (!mpk || !cell_id || !data || !signature || data_len == 0) {
        return -1;
    }

    blst_scalar pk_id;
    blst_p2_affine mpk_affine;
    blst_p2 derived_pk;
    blst_p2_affine pk_final;
    blst_p1_affine sig_affine;
    uint8_t pk_id_bytes[32];
    BLST_ERROR err;

    /* Step 1: Compute pk_ID = H_s(cell_id || gnb_key_validity_end) using expanded IKM */
    uint8_t ikm[TF5_IBS_IKM_LEN];
    memcpy(ikm, TF5_IBS_DST_HS, TF5_IBS_DST_HS_LEN);
    memcpy(ikm + TF5_IBS_DST_HS_LEN, cell_id, TF5_IBS_CELL_ID_LEN);

    /* Encode gnb_key_validity_end as 3 bytes big-endian */
    size_t off = TF5_IBS_DST_HS_LEN + TF5_IBS_CELL_ID_LEN;
    ikm[off + 0] = (gnb_key_validity_end >> 16) & 0xFF;
    ikm[off + 1] = (gnb_key_validity_end >> 8) & 0xFF;
    ikm[off + 2] = gnb_key_validity_end & 0xFF;

    blst_keygen(&pk_id, ikm, sizeof(ikm), NULL, 0);
    memset(ikm, 0, sizeof(ikm));

    /* Step 2: Deserialize/validate MPK once per thread and cache result */
    if (s_mpk_cache.valid &&
        memcmp(s_mpk_cache.mpk, mpk, TF5_GNB_PUBKEY_LEN) == 0) {
        mpk_affine = s_mpk_cache.mpk_affine;
    } else {
        err = blst_p2_uncompress(&mpk_affine, mpk);
        if (err != BLST_SUCCESS) {
            LOG_E(NR_RRC, "TESLA IBS: Failed to deserialize MPK: %d\n", err);
            memset(&pk_id, 0, sizeof(pk_id));
            return -3;
        }

        if (!blst_p2_affine_in_g2(&mpk_affine)) {
            LOG_E(NR_RRC, "TESLA IBS: MPK not in G2\n");
            memset(&pk_id, 0, sizeof(pk_id));
            return -3;
        }

        memcpy(s_mpk_cache.mpk, mpk, TF5_GNB_PUBKEY_LEN);
        s_mpk_cache.mpk_affine = mpk_affine;
        s_mpk_cache.valid = 1;
    }

    /* Step 3: Compute derived_pk = pk_ID * MPK */
    blst_p2_from_affine(&derived_pk, &mpk_affine);

    /* Serialize pk_id as little-endian bytes for scalar multiplication
     * Note: blst_p2_mult expects scalar in little-endian format */
    blst_lendian_from_scalar(pk_id_bytes, &pk_id);

    /* Scalar multiplication: derived_pk = pk_ID * MPK */
    blst_p2_mult(&derived_pk, &derived_pk, pk_id_bytes, 256);

    /* Clear sensitive pk_id_bytes */
    memset(pk_id_bytes, 0, sizeof(pk_id_bytes));
    memset(&pk_id, 0, sizeof(pk_id));

    /* Step 4: Convert to affine for verification */
    blst_p2_to_affine(&pk_final, &derived_pk);

    /* Check derived key is valid (not point at infinity) */
    if (blst_p2_affine_is_inf(&pk_final)) {
        LOG_E(NR_RRC, "TESLA IBS: Derived public key is infinity\n");
        return -3;
    }

    /* Step 5: Deserialize signature */
    err = blst_p1_uncompress(&sig_affine, signature);
    if (err != BLST_SUCCESS) {
        LOG_E(NR_RRC, "TESLA IBS: Failed to deserialize signature: %d\n", err);
        return -4;
    }

    /* Validate signature is in G1 */
    if (!blst_p1_affine_in_g1(&sig_affine)) {
        LOG_E(NR_RRC, "TESLA IBS: Signature not in G1\n");
        return -4;
    }

    /* Step 6: Verify e(Σ, Q) = e(H_m(m), pk_ID * MPK) */
    err = blst_core_verify_pk_in_g2(&pk_final, &sig_affine,
                                     1,  /* hash_or_encode = true */
                                     data, data_len,
                                     TF5_BLS_DST, TF5_BLS_DST_LEN,
                                     NULL, 0);  /* No augmentation */

    if (err != BLST_SUCCESS) {
        LOG_W(NR_RRC, "TESLA IBS: Signature verification failed: %d\n", err);
        return -5;
    }

    LOG_D(NR_RRC, "TESLA IBS: Signature verified successfully\n");
    return 0;
}

#endif /* ENABLE_TF5 */
