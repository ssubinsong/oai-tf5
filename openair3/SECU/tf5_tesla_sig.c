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

#ifdef TF5_ENABLE_TESLA

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
                                uint8_t public_key[TF5_BLS_PUBLIC_KEY_LEN])
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
                       uint8_t signature[TF5_BLS_SIGNATURE_LEN])
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

int tf5_tesla_bls_verify(const uint8_t public_key[TF5_BLS_PUBLIC_KEY_LEN],
                         const uint8_t *data,
                         size_t data_len,
                         const uint8_t signature[TF5_BLS_SIGNATURE_LEN])
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
                         uint8_t public_key[TF5_BLS_PUBLIC_KEY_LEN])
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

#endif /* TF5_ENABLE_TESLA */
