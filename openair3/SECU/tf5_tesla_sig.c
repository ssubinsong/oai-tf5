/*
 * GG09 Schnorr IBS signature operations for TESLA broadcast authentication
 *
 * Implements the Galindo-Garcia (GG09) Schnorr Identity-Based Signature scheme
 * (1-level, Ed25519/libsodium) for SIB1 broadcast authentication.
 *
 * Extract: b ← Z_l, pk = b·B, cid = H(id‖pk‖mpk), y = cid·z + b
 * Sign:    r ← Z_l, R = r·B, h = H(data‖R), σ = h·y + r
 * Verify:  cid = H(id‖pk‖mpk), Q = cid·mpk + pk, R' = σ·B − h·Q
 *
 * Optimizations (matching bench_schnorr_2ibs.c):
 *   - MPK precomp table (32×8 Duif, ~30KB, L1 cache) for cid·mpk
 *   - Shamir's trick (ge25519_double_scalarmult_vartime) for σ·B − h·Q
 *   - Variable-time ops for verification (inputs are public)
 */

#ifdef ENABLE_TF5

#include "tf5_tesla_sig.h"
#include "tf5_ibs_pkg.h"
#include "ed25519_precomp.h"
#include "common/utils/LOG/log.h"

#include <sodium.h>
#include <string.h>

/* ==========================================================================
 * Static helpers
 * ========================================================================== */

/* Reduce a 32-byte value mod l (Ed25519 group order) */
static void scalar_reduce_32(uint8_t out[32], const uint8_t in[32])
{
    uint8_t tmp[64];
    memcpy(tmp, in, 32);
    memset(tmp + 32, 0, 32);
    crypto_core_ed25519_scalar_reduce(out, tmp);
}

static int s_initialized = 0;

/* ==========================================================================
 * Thread-local MPK cache (avoids repeated precomp table construction on UE side)
 *
 * The 32×8 Duif precomp table (~30KB) fits in L1 cache and accelerates
 * the fixed-point scalar multiplication cid·mpk in verification.
 * ========================================================================== */

typedef struct {
    int valid;
    uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN];
    ge25519_precomp table[32][8];
} tf5_mpk_cache_t;

static __thread tf5_mpk_cache_t s_mpk_cache = {0};

/* ==========================================================================
 * Public API
 * ========================================================================== */

int tf5_ibs_init(void)
{
    if (sodium_init() < 0) {
        LOG_E(TF5, "sodium_init() failed\n");
        return -1;
    }

    s_initialized = 1;

    LOG_I(TF5, "GG09 Schnorr IBS subsystem initialized (Ed25519/libsodium)\n");
    return 0;
}

int tf5_ibs_precompute_mpk(const uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN])
{
    if (!mpk) return TF5_ERR_INVALID_PARAM;
    if (!s_initialized) {
        LOG_E(TF5, "GG09 IBS not initialized\n");
        return TF5_ERR_INVALID_PARAM;
    }

    /* Skip if already cached for this MPK */
    if (s_mpk_cache.valid &&
        sodium_memcmp(s_mpk_cache.mpk, mpk, TF5_IBS_MASTER_PUBLIC_LEN) == 0) {
        return TF5_OK;
    }

    ge25519_p3 mpk_p3;
    if (ge25519_frombytes(&mpk_p3, mpk) != 0) {
        LOG_E(TF5, "Failed to decompress MPK for precomputation\n");
        return TF5_ERR_KEY_INVALID;
    }

    build_precomp_table(s_mpk_cache.table, &mpk_p3);
    memcpy(s_mpk_cache.mpk, mpk, TF5_IBS_MASTER_PUBLIC_LEN);
    s_mpk_cache.valid = 1;

    LOG_I(TF5, "MPK precomputation table built (32x8 Duif, ~30KB)\n");
    return TF5_OK;
}

int tf5_ibs_validate_sk(const uint8_t sk_id[TF5_IBS_GNB_SK_LEN])
{
    if (!sk_id) {
        return TF5_ERR_INVALID_PARAM;
    }

    /* pk is the second 32 bytes of sk_id */
    const uint8_t *pk = sk_id + TF5_ED25519_SCALAR_LEN;

    /* Full validation: on-curve, not identity, in prime-order subgroup */
    if (crypto_core_ed25519_is_valid_point(pk) != 1) {
        LOG_E(TF5, "pk in sk_id is not a valid Ed25519 point\n");
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
        LOG_E(TF5, "GG09 IBS not initialized (call tf5_ibs_init first)\n");
        return TF5_ERR_SIGN;
    }

    const uint8_t *y  = sk_id;
    const uint8_t *pk = sk_id + TF5_ED25519_SCALAR_LEN;

    /* Step 1: r ← random scalar in Z_l */
    uint8_t r_scalar[TF5_ED25519_SCALAR_LEN];
    randombytes_buf(r_scalar, TF5_ED25519_SCALAR_LEN);
    scalar_reduce_32(r_scalar, r_scalar);

    /* Step 2: R = r·B */
    uint8_t R_point[TF5_ED25519_POINT_LEN];
    if (crypto_scalarmult_ed25519_base_noclamp(R_point, r_scalar) != 0) {
        sodium_memzero(r_scalar, sizeof(r_scalar));
        return TF5_ERR_SIGN;
    }

    /* Step 3: h = SHA-512(data ‖ R) mod l */
    uint8_t h[TF5_ED25519_SCALAR_LEN];
    {
        crypto_hash_sha512_state state;
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, data, data_len);
        crypto_hash_sha512_update(&state, R_point, TF5_ED25519_POINT_LEN);
        uint8_t hash_buf[64];
        crypto_hash_sha512_final(&state, hash_buf);
        crypto_core_ed25519_scalar_reduce(h, hash_buf);
    }

    /* Step 4: sigma = h·y + r mod l */
    uint8_t sigma[TF5_ED25519_SCALAR_LEN];
    sc25519_muladd(sigma, h, y, r_scalar);

    /* Step 5: Output: R[32] || sigma[32] || pk[32] */
    memcpy(signature, R_point, TF5_ED25519_POINT_LEN);
    memcpy(signature + TF5_ED25519_POINT_LEN, sigma, TF5_ED25519_SCALAR_LEN);
    memcpy(signature + TF5_ED25519_POINT_LEN + TF5_ED25519_SCALAR_LEN,
           pk, TF5_ED25519_POINT_LEN);

    /* Clear sensitive data */
    sodium_memzero(r_scalar, sizeof(r_scalar));
    sodium_memzero(h, sizeof(h));
    sodium_memzero(sigma, sizeof(sigma));

    return TF5_OK;
}

int tf5_ibs_sign_precomp(tf5_ibs_sign_precomp_t *precomp)
{
    if (!precomp) {
        return TF5_ERR_INVALID_PARAM;
    }

    if (!s_initialized) {
        LOG_E(TF5, "GG09 IBS not initialized (call tf5_ibs_init first)\n");
        return TF5_ERR_SIGN;
    }

    /* r ← random scalar in Z_l */
    randombytes_buf(precomp->r_scalar, TF5_ED25519_SCALAR_LEN);
    scalar_reduce_32(precomp->r_scalar, precomp->r_scalar);

    /* R = r·B */
    if (crypto_scalarmult_ed25519_base_noclamp(precomp->R_point, precomp->r_scalar) != 0) {
        sodium_memzero(precomp->r_scalar, TF5_ED25519_SCALAR_LEN);
        return TF5_ERR_CRYPTO;
    }

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
        LOG_E(TF5, "GG09 IBS not initialized (call tf5_ibs_init first)\n");
        return TF5_ERR_SIGN;
    }

    const uint8_t *y  = sk_id;
    const uint8_t *pk = sk_id + TF5_ED25519_SCALAR_LEN;

    /* h = SHA-512(data ‖ R) mod l */
    uint8_t h[TF5_ED25519_SCALAR_LEN];
    {
        crypto_hash_sha512_state state;
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, data, data_len);
        crypto_hash_sha512_update(&state, precomp->R_point, TF5_ED25519_POINT_LEN);
        uint8_t hash_buf[64];
        crypto_hash_sha512_final(&state, hash_buf);
        crypto_core_ed25519_scalar_reduce(h, hash_buf);
    }

    /* sigma = h·y + r mod l */
    uint8_t sigma[TF5_ED25519_SCALAR_LEN];
    sc25519_muladd(sigma, h, y, precomp->r_scalar);

    /* Output: R[32] || sigma[32] || pk[32] */
    memcpy(signature, precomp->R_point, TF5_ED25519_POINT_LEN);
    memcpy(signature + TF5_ED25519_POINT_LEN, sigma, TF5_ED25519_SCALAR_LEN);
    memcpy(signature + TF5_ED25519_POINT_LEN + TF5_ED25519_SCALAR_LEN,
           pk, TF5_ED25519_POINT_LEN);

    /* Consume precomp: zero the r_scalar nonce */
    sodium_memzero(precomp->r_scalar, TF5_ED25519_SCALAR_LEN);
    sodium_memzero(h, sizeof(h));
    sodium_memzero(sigma, sizeof(sigma));

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
        LOG_E(TF5, "GG09 IBS not initialized (call tf5_ibs_init first)\n");
        return TF5_ERR_VERIFY;
    }

    /* Step 1: Parse signature → R[32], sigma[32], pk[32] */
    const uint8_t *R_point = signature;
    const uint8_t *sigma   = signature + TF5_ED25519_POINT_LEN;
    const uint8_t *pk      = signature + TF5_ED25519_POINT_LEN + TF5_ED25519_SCALAR_LEN;

    /* Step 2: cid = H(pk ‖ mpk ‖ cell_id ‖ validity) mod l */
    uint8_t cid[TF5_ED25519_SCALAR_LEN];
    int rc = tf5_ibs_hash_identity(cell_id, TF5_IBS_CELL_ID_LEN,
                                    gnb_key_validity_end, pk, mpk, cid);
    if (rc != TF5_OK) {
        LOG_E(TF5, "Failed to compute identity hash\n");
        return TF5_ERR_CRYPTO;
    }

    /* Step 3: Q = cid·mpk + pk
     * Uses precomp table for the fixed-point mpk scalar mult. */

    /* Build/cache MPK precomp table (32×8 Duif, ~30KB) */
    if (!s_mpk_cache.valid ||
        sodium_memcmp(s_mpk_cache.mpk, mpk, TF5_IBS_MASTER_PUBLIC_LEN) != 0) {
        ge25519_p3 mpk_p3;
        if (ge25519_frombytes(&mpk_p3, mpk) != 0) {
            LOG_E(TF5, "Failed to decompress MPK\n");
            return TF5_ERR_KEY_INVALID;
        }
        build_precomp_table(s_mpk_cache.table, &mpk_p3);
        memcpy(s_mpk_cache.mpk, mpk, TF5_IBS_MASTER_PUBLIC_LEN);
        s_mpk_cache.valid = 1;
    }

    /* Q_part = cid · mpk (via precomp table) */
    ge25519_p3 Q_part_p3;
    scalarmult_precomp_vartime(&Q_part_p3, cid, s_mpk_cache.table);

    /* pk must be a valid prime-order point (reject small-subgroup attacks) */
    if (!crypto_core_ed25519_is_valid_point(pk)) {
        LOG_W(TF5, "Invalid pk in signature (not a valid Ed25519 point)\n");
        return TF5_ERR_KEY_INVALID;
    }
    ge25519_p3 pk_p3;
    ge25519_frombytes(&pk_p3, pk);  /* safe: is_valid_point already checked */

    /* Q = Q_part + pk */
    ge25519_cached pk_cached;
    ge25519_p3_to_cached_(&pk_cached, &pk_p3);
    ge25519_p1p1 Q_sum;
    ge25519_add_cached_(&Q_sum, &Q_part_p3, &pk_cached);
    ge25519_p3 Q_p3;
    ge25519_p1p1_to_p3(&Q_p3, &Q_sum);

    /* Step 4: h = SHA-512(data ‖ R) mod l */
    uint8_t h[TF5_ED25519_SCALAR_LEN];
    {
        crypto_hash_sha512_state state;
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, data, data_len);
        crypto_hash_sha512_update(&state, R_point, TF5_ED25519_POINT_LEN);
        uint8_t hash_buf[64];
        crypto_hash_sha512_final(&state, hash_buf);
        crypto_core_ed25519_scalar_reduce(h, hash_buf);
    }

    /* Step 5: R' = sigma·B − h·Q  via Shamir's trick (double scalar mult) */
    uint8_t neg_h[TF5_ED25519_SCALAR_LEN];
    crypto_core_ed25519_scalar_negate(neg_h, h);

    ge25519_p2 R_prime_p2;
    ge25519_double_scalarmult_vartime(&R_prime_p2, neg_h, &Q_p3, sigma);

    uint8_t R_prime[TF5_ED25519_POINT_LEN];
    ge25519_tobytes(R_prime, &R_prime_p2);

    /* Step 6: h' = SHA-512(data ‖ R') mod l */
    uint8_t h_prime[TF5_ED25519_SCALAR_LEN];
    {
        crypto_hash_sha512_state state;
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, data, data_len);
        crypto_hash_sha512_update(&state, R_prime, TF5_ED25519_POINT_LEN);
        uint8_t hash_buf[64];
        crypto_hash_sha512_final(&state, hash_buf);
        crypto_core_ed25519_scalar_reduce(h_prime, hash_buf);
    }

    /* Step 7: Accept iff h == h' (constant-time comparison) */
    if (sodium_memcmp(h, h_prime, TF5_ED25519_SCALAR_LEN) != 0) {
        LOG_W(TF5, "GG09 Schnorr IBS signature verification failed: h != h'\n");
        return TF5_ERR_VERIFY;
    }

    LOG_D(TF5, "GG09 Schnorr IBS signature verified successfully\n");
    return TF5_OK;
}

#endif /* ENABLE_TF5 */
