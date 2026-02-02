/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*
 * TESLA Broadcast Authentication - BLS Signature Implementation
 *
 * Uses blst library (Supranational) with BLS12-381 curve.
 * Minimal-signature-size variant: Signatures in G1 (48 bytes), Public keys in G2 (96 bytes).
 */

#ifdef ENABLE_TF5

#include "tf5_tesla_sig.h"
#include "common/utils/LOG/log.h"

#include <string.h>
#include <stdio.h>
#include "blst.h"

/* Domain Separation Tag for hash-to-curve (IETF BLS basic scheme) */
static const uint8_t TF5_BLS_DST[] = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
static const size_t TF5_BLS_DST_LEN = sizeof(TF5_BLS_DST) - 1;

int tf5_tesla_bls_init(void)
{
    /* blst library requires no initialization - it is stateless */
    LOG_I(NR_RRC, "TESLA: BLST library ready (BLS12-381, pk-in-G2 mode)\n");
    return 0;
}

int tf5_tesla_bls_derive_public(const uint8_t secret_key[TF5_BLS_SECRET_KEY_LEN],
                                uint8_t public_key[TF5_BLS_PUBKEY_LEN])
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

int tf5_tesla_bls_sign(const uint8_t secret_key[TF5_BLS_SECRET_KEY_LEN],
                       const uint8_t *data,
                       size_t data_len,
                       uint8_t signature[TF5_BLS_SIG_LEN])
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

int tf5_tesla_bls_verify(const uint8_t public_key[TF5_BLS_PUBKEY_LEN],
                         const uint8_t *data,
                         size_t data_len,
                         const uint8_t signature[TF5_BLS_SIG_LEN])
{
    if (!public_key || !data || !signature || data_len == 0) {
        return -1;
    }

    blst_p2_affine pk_affine;
    blst_p1_affine sig_affine;
    BLST_ERROR err;

    /* Deserialize public key */
    err = blst_p2_uncompress(&pk_affine, public_key);
    if (err != BLST_SUCCESS) {
        LOG_E(NR_RRC, "TESLA: Failed to deserialize public key: %d\n", err);
        return -3;
    }

    /* Check public key is in G2 */
    if (!blst_p2_affine_in_g2(&pk_affine)) {
        LOG_E(NR_RRC, "TESLA: Public key not in G2\n");
        return -3;
    }

    /* Deserialize signature */
    err = blst_p1_uncompress(&sig_affine, signature);
    if (err != BLST_SUCCESS) {
        LOG_E(NR_RRC, "TESLA: Failed to deserialize signature: %d\n", err);
        return -4;
    }

    /* Check signature is in G1 */
    if (!blst_p1_affine_in_g1(&sig_affine)) {
        LOG_E(NR_RRC, "TESLA: Signature not in G1\n");
        return -4;
    }

    /* Verify signature using core_verify which handles hash-to-curve internally */
    err = blst_core_verify_pk_in_g2(&pk_affine, &sig_affine,
                                     1,  /* hash_or_encode = true for hash */
                                     data, data_len,
                                     TF5_BLS_DST, TF5_BLS_DST_LEN,
                                     NULL, 0);  /* No augmentation */

    if (err != BLST_SUCCESS) {
        LOG_W(NR_RRC, "TESLA: BLS signature verification failed: %d\n", err);
        return -5;
    }

    return 0;
}

int tf5_tesla_bls_keygen(uint8_t secret_key[TF5_BLS_SECRET_KEY_LEN],
                         uint8_t public_key[TF5_BLS_PUBKEY_LEN])
{
    if (!secret_key || !public_key) {
        return -1;
    }

    blst_scalar sk;
    blst_p2 pk_p2;
    uint8_t ikm[32];

    /* Generate random IKM using system CSPRNG */
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        LOG_E(NR_RRC, "TESLA: Failed to open /dev/urandom\n");
        return -3;
    }
    if (fread(ikm, 1, sizeof(ikm), urandom) != sizeof(ikm)) {
        fclose(urandom);
        LOG_E(NR_RRC, "TESLA: Failed to read from /dev/urandom\n");
        return -3;
    }
    fclose(urandom);

    /* Derive secret key from IKM using blst_keygen */
    blst_keygen(&sk, ikm, sizeof(ikm), NULL, 0);

    /* Clear IKM immediately */
    memset(ikm, 0, sizeof(ikm));

    /* Derive public key */
    blst_sk_to_pk_in_g2(&pk_p2, &sk);

    /* Serialize secret key (big-endian, 32 bytes) */
    blst_bendian_from_scalar(secret_key, &sk);

    /* Serialize public key (compressed, 96 bytes) */
    blst_p2_compress(public_key, &pk_p2);

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
#define TF5_IBS_IKM_LEN  (TF5_IBS_DST_HS_LEN + TF5_IBS_CELL_ID_LEN + TF5_VALIDITY_PERIOD_LEN)

int tf5_tesla_ibs_hash_to_scalar(const uint8_t *cell_id,
                                  size_t cell_id_len,
                                  uint32_t gnb_key_validity_end,
                                  uint8_t scalar_out[TF5_BLS_SECRET_KEY_LEN])
{
    if (!cell_id || !scalar_out || cell_id_len == 0) {
        return -1;
    }

    /*
     * Create expanded IKM by concatenating DST, cell_id, and gnb_key_validity_end.
     * This ensures IKM >= 32 bytes (43 bytes: 35 DST + 5 cell_id + 3 validity)
     * which is required for blst_keygen to produce non-zero output.
     *
     * Identity hash: pk_ID = H_s(Cell_ID || gnb_key_validity_end)
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
     * blst_keygen performs HKDF-based derivation with proper mod r reduction.
     * Using empty info since domain separation is embedded in IKM.
     */
    blst_keygen(&pk_id, ikm, sizeof(ikm), NULL, 0);

    /* Serialize as big-endian */
    blst_bendian_from_scalar(scalar_out, &pk_id);

    /* Clear sensitive data */
    memset(&pk_id, 0, sizeof(pk_id));
    memset(ikm, 0, sizeof(ikm));

    return 0;
}

int tf5_tesla_ibs_verify(const uint8_t mpk[TF5_BLS_PUBKEY_LEN],
                          const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                          uint32_t gnb_key_validity_end,
                          const uint8_t *data,
                          size_t data_len,
                          const uint8_t signature[TF5_BLS_SIG_LEN])
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

    /* Step 2: Deserialize MPK (Master Public Key) */
    err = blst_p2_uncompress(&mpk_affine, mpk);
    if (err != BLST_SUCCESS) {
        LOG_E(NR_RRC, "TESLA IBS: Failed to deserialize MPK: %d\n", err);
        memset(&pk_id, 0, sizeof(pk_id));
        return -3;
    }

    /* Validate MPK is in G2 */
    if (!blst_p2_affine_in_g2(&mpk_affine)) {
        LOG_E(NR_RRC, "TESLA IBS: MPK not in G2\n");
        memset(&pk_id, 0, sizeof(pk_id));
        return -3;
    }

    /* Step 3: Compute derived_pk = pk_ID * MPK */
    blst_p2_from_affine(&derived_pk, &mpk_affine);

    /* Serialize pk_id as big-endian bytes for scalar multiplication */
    blst_bendian_from_scalar(pk_id_bytes, &pk_id);

    /* Scalar multiplication: derived_pk = pk_ID * MPK */
    blst_p2_mult(&derived_pk, &derived_pk, pk_id_bytes, 255);

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
