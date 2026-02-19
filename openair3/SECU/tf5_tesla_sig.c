#ifdef ENABLE_TF5

#include "tf5_tesla_sig.h"
#include "tf5_ibs_pkg.h"
#include "common/utils/LOG/log.h"

#include <string.h>
#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "blst.h"

/* ==========================================================================
 * Precomputed globals (set once in tf5_ibs_init)
 * ========================================================================== */

/* g = e(P, Q) ∈ GT — precomputed base pairing.
 * Not used in the signing/verification hot path: signing computes
 * g^x = e(xP, Q) directly via a single Miller loop, which is cheaper
 * than exponentiating in GT.  Retained for potential future use. */
static blst_fp12 s_g;

/* Q (G2 generator) in affine form — for Miller loops */
static blst_p2_affine s_Q_affine;

/* Precomputed Miller loop lines for Q (G2 generator).
 * Since Q never changes, we precompute once and reuse via
 * blst_miller_loop_lines(), avoiding repeated G2 line evaluation. */
static blst_fp6 s_Q_lines[68];

/* P (G1 generator) in affine form — for g^{-h} computation */
static blst_p1_affine s_P_affine;

static int s_initialized = 0;

/* ==========================================================================
 * Thread-local MPK cache (avoids repeated deserialization on UE side)
 * ========================================================================== */

typedef struct {
    int valid;
    uint8_t mpk[TF5_IBS_GNB_PK_LEN];
    blst_p2_affine mpk_affine;
} tf5_mpk_cache_t;

static __thread tf5_mpk_cache_t s_mpk_cache = {0};

/* ==========================================================================
 * sk_ID cache (avoids repeated decompression on gNB side)
 *
 * gNB signs with the same sk_ID for the entire key validity period,
 * so we cache the deserialized affine + projective forms.
 * ========================================================================== */

typedef struct {
    int valid;
    uint8_t sk_compressed[TF5_IBS_GNB_SK_LEN];
    blst_p1_affine sk_affine;
    blst_p1 sk_p1;
} tf5_sk_cache_t;

static tf5_sk_cache_t s_sk_cache = {0};

/* ==========================================================================
 * H2: {0,1}* × GT → Z*p
 *
 * Implements H2(data, r) = blst_keygen(SHA-256(DST_H2 || data || r_bytes))
 * where r_bytes is the serialized GT element.
 * ========================================================================== */

/* Thread-local EVP_MD_CTX for H2 — avoids heap alloc/free per call */
static __thread EVP_MD_CTX *s_h2_md_ctx = NULL;

static int tf5_ibs_h2(const uint8_t *data,
                       size_t data_len,
                       const blst_fp12 *r,
                       blst_scalar *h_out)
{
    /*
     * Build IKM = SHA-256(DST_H2 || data || r_serialized)
     * This reduces the variable-length input to a fixed 32-byte IKM,
     * then blst_keygen performs HKDF + mod r reduction.
     */
    if (!s_h2_md_ctx) {
        s_h2_md_ctx = EVP_MD_CTX_new();
    }

    uint8_t digest[32];

    EVP_DigestInit_ex(s_h2_md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(s_h2_md_ctx, TF5_IBS_DST_H2, TF5_IBS_DST_H2_LEN);
    EVP_DigestUpdate(s_h2_md_ctx, data, data_len);
    EVP_DigestUpdate(s_h2_md_ctx, (const uint8_t *)r, sizeof(blst_fp12));
    EVP_DigestFinal_ex(s_h2_md_ctx, digest, NULL);

    /* Use blst_keygen for proper mod r reduction */
    blst_keygen(h_out, digest, sizeof(digest), NULL, 0);
    OPENSSL_cleanse(digest, sizeof(digest));

    return 0;
}

/* ==========================================================================
 * Public API
 * ========================================================================== */

int tf5_ibs_init(void)
{
    /* Compute g = e(P, Q) where P is G1 generator, Q is G2 generator */
    const blst_p1_affine *P = blst_p1_affine_generator();
    const blst_p2_affine *Q = blst_p2_affine_generator();

    s_P_affine = *P;
    s_Q_affine = *Q;
    blst_precompute_lines(s_Q_lines, &s_Q_affine);

    /* g = e(P, Q) via Miller loop + final exponentiation */
    blst_miller_loop(&s_g, Q, P);
    blst_final_exp(&s_g, &s_g);

    s_initialized = 1;

    LOG_I(TF5, "BLMQ IBS subsystem initialized (BLS12-381, single-pairing verification)\n");
    return 0;
}

int tf5_ibs_validate_sk(const uint8_t sk_id[TF5_IBS_GNB_SK_LEN])
{
    if (!sk_id) {
        return TF5_ERR_INVALID_PARAM;
    }

    blst_p1_affine sk_affine;
    BLST_ERROR err = blst_p1_uncompress(&sk_affine, sk_id);
    if (err != BLST_SUCCESS) {
        LOG_E(TF5, "Failed to decompress sk_ID: %d\n", err);
        return TF5_ERR_KEY_INVALID;
    }

    if (!blst_p1_affine_in_g1(&sk_affine)) {
        LOG_E(TF5, "sk_ID not in G1 subgroup\n");
        return TF5_ERR_KEY_INVALID;
    }

    if (blst_p1_affine_is_inf(&sk_affine)) {
        LOG_E(TF5, "sk_ID is identity (infinity)\n");
        return TF5_ERR_KEY_INVALID;
    }

    return TF5_OK;
}

int tf5_ibs_sign(const uint8_t sk_id[TF5_IBS_GNB_SK_LEN],
                 const uint8_t *data,
                 size_t data_len,
                 uint8_t signature[TF5_IBS_SIG_LEN])
{
    if (!sk_id || !data || !signature || data_len == 0) {
        return TF5_ERR_INVALID_PARAM;
    }

    if (!s_initialized) {
        LOG_E(TF5, "BLMQ IBS not initialized (call tf5_ibs_init first)\n");
        return TF5_ERR_SIGN;
    }

    blst_p1_affine sk_affine;
    blst_p1 sk_p1;
    blst_scalar x, h, xph;
    blst_fp12 r;
    blst_p1 S;

    /* Step 1: Deserialize sk_ID from compressed G1 (48B), with cache */
    if (s_sk_cache.valid &&
        memcmp(s_sk_cache.sk_compressed, sk_id, TF5_IBS_GNB_SK_LEN) == 0) {
        sk_affine = s_sk_cache.sk_affine;
        sk_p1 = s_sk_cache.sk_p1;
    } else {
        BLST_ERROR err = blst_p1_uncompress(&sk_affine, sk_id);
        if (err != BLST_SUCCESS) {
            LOG_E(TF5, "Failed to decompress sk_ID for signing: %d\n", err);
            return TF5_ERR_KEY_INVALID;
        }
        blst_p1_from_affine(&sk_p1, &sk_affine);
        memcpy(s_sk_cache.sk_compressed, sk_id, TF5_IBS_GNB_SK_LEN);
        s_sk_cache.sk_affine = sk_affine;
        s_sk_cache.sk_p1 = sk_p1;
        s_sk_cache.valid = 1;
    }

    /* Step 2: Generate random x via RAND_bytes + blst_keygen */
    uint8_t rand_bytes[32];
    if (RAND_bytes(rand_bytes, 32) != 1) {
        LOG_E(TF5, "RNG failure in BLMQ signing\n");
        return TF5_ERR_CRYPTO;
    }
    blst_keygen(&x, rand_bytes, 32, NULL, 0);
    OPENSSL_cleanse(rand_bytes, 32);

    /* Step 3: Compute r = g^x ∈ GT
     * g^x = e(P, Q)^x = e(xP, Q)
     * We compute xP first, then Miller loop with Q */
    blst_p1 xP;
    uint8_t x_le[32];
    blst_lendian_from_scalar(x_le, &x);
    blst_p1_mult(&xP, blst_p1_generator(), x_le, 256);
    OPENSSL_cleanse(x_le, 32);

    blst_p1_affine xP_affine;
    blst_p1_to_affine(&xP_affine, &xP);
    blst_miller_loop_lines(&r, s_Q_lines, &xP_affine);
    blst_final_exp(&r, &r);

    /* Step 4: Compute h = H2(data, r) */
    tf5_ibs_h2(data, data_len, &r, &h);

    /* Step 5: Compute (x + h) mod r */
    if (!blst_sk_add_n_check(&xph, &x, &h)) {
        LOG_E(TF5, "Scalar addition (x+h) failed\n");
        OPENSSL_cleanse(&x, sizeof(x));
        OPENSSL_cleanse(&h, sizeof(h));
        return TF5_ERR_SIGN;
    }
    OPENSSL_cleanse(&x, sizeof(x));

    /* Step 6: Compute S = (x+h) * sk_ID ∈ G1 */
    uint8_t xph_le[32];
    blst_lendian_from_scalar(xph_le, &xph);
    blst_p1_mult(&S, &sk_p1, xph_le, 256);
    OPENSSL_cleanse(xph_le, 32);
    OPENSSL_cleanse(&xph, sizeof(xph));

    /* Step 7: Output signature = h_bytes[32] || S_compressed[48] */
    blst_bendian_from_scalar(signature, &h);
    blst_p1_compress(signature + TF5_IBS_SIG_H_LEN, &S);
    OPENSSL_cleanse(&h, sizeof(h));

    return TF5_OK;
}

int tf5_ibs_sign_precomp(tf5_ibs_sign_precomp_t *precomp)
{
    if (!precomp) {
        return TF5_ERR_INVALID_PARAM;
    }

    if (!s_initialized) {
        LOG_E(TF5, "BLMQ IBS not initialized (call tf5_ibs_init first)\n");
        return TF5_ERR_SIGN;
    }

    /* Generate random x via RAND_bytes + blst_keygen */
    uint8_t rand_bytes[32];
    if (RAND_bytes(rand_bytes, 32) != 1) {
        LOG_E(TF5, "RNG failure in BLMQ sign precomp\n");
        return TF5_ERR_CRYPTO;
    }
    blst_keygen(&precomp->x, rand_bytes, 32, NULL, 0);
    OPENSSL_cleanse(rand_bytes, 32);

    /* Compute r = g^x = e(xP, Q) */
    blst_p1 xP;
    uint8_t x_le[32];
    blst_lendian_from_scalar(x_le, &precomp->x);
    blst_p1_mult(&xP, blst_p1_generator(), x_le, 256);
    OPENSSL_cleanse(x_le, 32);

    blst_p1_affine xP_affine;
    blst_p1_to_affine(&xP_affine, &xP);
    blst_miller_loop_lines(&precomp->r, s_Q_lines, &xP_affine);
    blst_final_exp(&precomp->r, &precomp->r);

    return TF5_OK;
}

int tf5_ibs_sign_online(const uint8_t sk_id[TF5_IBS_GNB_SK_LEN],
                         const uint8_t *data,
                         size_t data_len,
                         tf5_ibs_sign_precomp_t *precomp,
                         uint8_t signature[TF5_IBS_SIG_LEN])
{
    if (!sk_id || !data || !signature || !precomp || data_len == 0) {
        return TF5_ERR_INVALID_PARAM;
    }

    if (!s_initialized) {
        LOG_E(TF5, "BLMQ IBS not initialized (call tf5_ibs_init first)\n");
        return TF5_ERR_SIGN;
    }

    blst_p1_affine sk_affine;
    blst_p1 sk_p1;
    blst_scalar h, xph;

    /* Deserialize sk_ID from compressed G1, with cache */
    if (s_sk_cache.valid &&
        memcmp(s_sk_cache.sk_compressed, sk_id, TF5_IBS_GNB_SK_LEN) == 0) {
        sk_affine = s_sk_cache.sk_affine;
        sk_p1 = s_sk_cache.sk_p1;
    } else {
        BLST_ERROR err = blst_p1_uncompress(&sk_affine, sk_id);
        if (err != BLST_SUCCESS) {
            LOG_E(TF5, "Failed to decompress sk_ID for online signing: %d\n", err);
            return TF5_ERR_KEY_INVALID;
        }
        blst_p1_from_affine(&sk_p1, &sk_affine);
        memcpy(s_sk_cache.sk_compressed, sk_id, TF5_IBS_GNB_SK_LEN);
        s_sk_cache.sk_affine = sk_affine;
        s_sk_cache.sk_p1 = sk_p1;
        s_sk_cache.valid = 1;
    }

    /* h = H2(data, r) */
    tf5_ibs_h2(data, data_len, &precomp->r, &h);

    /* (x + h) mod r */
    if (!blst_sk_add_n_check(&xph, &precomp->x, &h)) {
        LOG_E(TF5, "Scalar addition (x+h) failed in online signing\n");
        OPENSSL_cleanse(&precomp->x, sizeof(precomp->x));
        OPENSSL_cleanse(&h, sizeof(h));
        return TF5_ERR_SIGN;
    }
    OPENSSL_cleanse(&precomp->x, sizeof(precomp->x));

    /* S = (x+h) * sk_ID ∈ G1 */
    blst_p1 S;
    uint8_t xph_le[32];
    blst_lendian_from_scalar(xph_le, &xph);
    blst_p1_mult(&S, &sk_p1, xph_le, 256);
    OPENSSL_cleanse(xph_le, 32);
    OPENSSL_cleanse(&xph, sizeof(xph));

    /* Output: h[32] || S_compressed[48] */
    blst_bendian_from_scalar(signature, &h);
    blst_p1_compress(signature + TF5_IBS_SIG_H_LEN, &S);
    OPENSSL_cleanse(&h, sizeof(h));

    return TF5_OK;
}

int tf5_ibs_verify(const uint8_t mpk[TF5_IBS_GNB_PK_LEN],
                   const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                   uint32_t gnb_key_validity_end,
                   const uint8_t *data,
                   size_t data_len,
                   const uint8_t signature[TF5_IBS_SIG_LEN])
{
    if (!mpk || !cell_id || !data || !signature || data_len == 0) {
        return TF5_ERR_INVALID_PARAM;
    }

    if (!s_initialized) {
        LOG_E(TF5, "BLMQ IBS not initialized (call tf5_ibs_init first)\n");
        return TF5_ERR_VERIFY;
    }

    BLST_ERROR err;

    /* Step 1: Parse signature → h[32] and S[48] */
    blst_scalar h;
    blst_scalar_from_bendian(&h, signature);
    if (!blst_sk_check(&h)) {
        /* h must be a valid non-zero scalar in [1, r-1] */
        LOG_W(TF5, "Signature h is not a valid scalar\n");
        return TF5_ERR_VERIFY;
    }

    blst_p1_affine S_affine;
    err = blst_p1_uncompress(&S_affine, signature + TF5_IBS_SIG_H_LEN);
    if (err != BLST_SUCCESS) {
        LOG_W(TF5, "Failed to deserialize S from signature: %d\n", err);
        return TF5_ERR_KEY_INVALID;
    }
    if (!blst_p1_affine_in_g1(&S_affine)) {
        LOG_W(TF5, "Signature S not in G1\n");
        return TF5_ERR_KEY_INVALID;
    }

    /* Step 2: Compute H1(ID) */
    uint8_t h1_bytes[TF5_BLS_SCALAR_LEN];
    if (tf5_ibs_hash_to_scalar(cell_id, TF5_IBS_CELL_ID_LEN,
                                gnb_key_validity_end, h1_bytes) != 0) {
        LOG_E(TF5, "Failed to compute H1(ID)\n");
        return TF5_ERR_CRYPTO;
    }
    blst_scalar h1_scalar;
    blst_scalar_from_bendian(&h1_scalar, h1_bytes);
    OPENSSL_cleanse(h1_bytes, sizeof(h1_bytes));

    /* Step 3: Compute QID = H1(ID)*Q + Qpub ∈ G2 */
    blst_p2 h1Q;
    uint8_t h1_le[32];
    blst_lendian_from_scalar(h1_le, &h1_scalar);
    blst_p2_mult(&h1Q, blst_p2_generator(), h1_le, 256);
    OPENSSL_cleanse(h1_le, 32);

    /* Deserialize/cache MPK (Qpub) */
    blst_p2_affine mpk_affine;
    if (s_mpk_cache.valid &&
        memcmp(s_mpk_cache.mpk, mpk, TF5_IBS_GNB_PK_LEN) == 0) {
        mpk_affine = s_mpk_cache.mpk_affine;
    } else {
        err = blst_p2_uncompress(&mpk_affine, mpk);
        if (err != BLST_SUCCESS) {
            LOG_E(TF5, "Failed to deserialize MPK: %d\n", err);
            return TF5_ERR_KEY_INVALID;
        }
        memcpy(s_mpk_cache.mpk, mpk, TF5_IBS_GNB_PK_LEN);
        s_mpk_cache.mpk_affine = mpk_affine;
        s_mpk_cache.valid = 1;
    }

    blst_p2 Qpub;
    blst_p2_from_affine(&Qpub, &mpk_affine);

    /* QID = H1(ID)*Q + Qpub */
    blst_p2 QID;
    blst_p2_add_or_double(&QID, &h1Q, &Qpub);

    blst_p2_affine QID_affine;
    blst_p2_to_affine(&QID_affine, &QID);

    if (blst_p2_affine_is_inf(&QID_affine)) {
        LOG_E(TF5, "QID is infinity (H1(ID) + s = 0 mod r)\n");
        return TF5_ERR_KEY_INVALID;
    }

    /* Step 4: Compute -hP ∈ G1 (for g^{-h} term) */
    blst_p1 hP;
    uint8_t h_le[32];
    blst_lendian_from_scalar(h_le, &h);
    blst_p1_mult(&hP, blst_p1_generator(), h_le, 256);
    OPENSSL_cleanse(h_le, 32);

    /* Negate: -hP */
    blst_p1_cneg(&hP, 1);

    blst_p1_affine neg_hP_affine;
    blst_p1_to_affine(&neg_hP_affine, &hP);

    /* Step 5: Fused multi-Miller loop + final exponentiation → r'
     * blst_miller_loop_n shares doublings across both pairs. */
    const blst_p1_affine *p1s[2] = { &S_affine, &neg_hP_affine };
    const blst_p2_affine *p2s[2] = { &QID_affine, &s_Q_affine };

    blst_fp12 r_prime;
    blst_miller_loop_n(&r_prime, p2s, p1s, 2);
    blst_final_exp(&r_prime, &r_prime);

    /* Step 7: Compute h' = H2(data, r') */
    blst_scalar h_prime;
    tf5_ibs_h2(data, data_len, &r_prime, &h_prime);

    /* Step 8: Accept iff h == h' (constant-time comparison) */
    uint8_t h_bytes[32], h_prime_bytes[32];
    blst_bendian_from_scalar(h_bytes, &h);
    blst_bendian_from_scalar(h_prime_bytes, &h_prime);

    if (CRYPTO_memcmp(h_bytes, h_prime_bytes, 32) != 0) {
        LOG_W(TF5, "BLMQ IBS signature verification failed: h != h'\n");
        OPENSSL_cleanse(h_bytes, 32);
        OPENSSL_cleanse(h_prime_bytes, 32);
        return TF5_ERR_VERIFY;
    }

    OPENSSL_cleanse(h_bytes, 32);
    OPENSSL_cleanse(h_prime_bytes, 32);

    LOG_D(TF5, "BLMQ IBS signature verified successfully\n");
    return TF5_OK;
}

#endif /* ENABLE_TF5 */
