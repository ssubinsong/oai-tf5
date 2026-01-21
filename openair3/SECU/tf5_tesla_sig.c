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
 * Uses herumi-bls library with BLS12-381 curve in non-ETH mode.
 * Signatures in G1 (48 bytes), Public keys in G2 (96 bytes).
 */

#ifdef TF5_ENABLE_TESLA

#include "tf5_tesla_sig.h"
#include "common/utils/LOG/log.h"

#include <string.h>
#include <bls/bls.h>
#include <mcl/bn.h>

/* Track initialization state */
static int bls_initialized = 0;

int tf5_tesla_bls_init(void)
{
    if (bls_initialized) {
        return 0;  /* Already initialized */
    }

    int rc = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    if (rc != 0) {
        LOG_E(NR_RRC, "TESLA: blsInit failed with error %d\n", rc);
        return -1;
    }

    bls_initialized = 1;
    LOG_I(NR_RRC, "TESLA: BLS library initialized (BLS12-381, non-ETH mode)\n");
    return 0;
}

int tf5_tesla_bls_derive_public(const uint8_t secret_key[TF5_BLS_SECRET_KEY_LEN],
                                uint8_t public_key[TF5_BLS_PUBLIC_KEY_LEN])
{
    if (!secret_key || !public_key) {
        return -1;
    }

    if (!bls_initialized) {
        LOG_E(NR_RRC, "TESLA: BLS library not initialized\n");
        return -2;
    }

    blsSecretKey sec;
    blsPublicKey pub;

    /* Deserialize secret key */
    if (blsSecretKeyDeserialize(&sec, secret_key, TF5_BLS_SECRET_KEY_LEN)
            != TF5_BLS_SECRET_KEY_LEN) {
        LOG_E(NR_RRC, "TESLA: Failed to deserialize secret key\n");
        return -3;
    }

    /* Derive public key */
    blsGetPublicKey(&pub, &sec);

    /* Serialize public key */
    size_t pub_len = blsPublicKeySerialize(public_key, TF5_BLS_PUBLIC_KEY_LEN, &pub);
    if (pub_len != TF5_BLS_PUBLIC_KEY_LEN) {
        LOG_E(NR_RRC, "TESLA: Unexpected public key size: %zu (expected %d)\n",
              pub_len, TF5_BLS_PUBLIC_KEY_LEN);
        return -4;
    }

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

    if (!bls_initialized) {
        LOG_E(NR_RRC, "TESLA: BLS library not initialized\n");
        return -2;
    }

    blsSecretKey sec;
    blsSignature sig;

    /* Deserialize secret key */
    if (blsSecretKeyDeserialize(&sec, secret_key, TF5_BLS_SECRET_KEY_LEN)
            != TF5_BLS_SECRET_KEY_LEN) {
        LOG_E(NR_RRC, "TESLA: Failed to deserialize secret key for signing\n");
        return -3;
    }

    /* Sign the data */
    blsSign(&sig, &sec, data, data_len);

    /* Serialize signature */
    size_t sig_len = blsSignatureSerialize(signature, TF5_BLS_SIGNATURE_LEN, &sig);
    if (sig_len != TF5_BLS_SIGNATURE_LEN) {
        LOG_E(NR_RRC, "TESLA: Unexpected signature size: %zu (expected %d)\n",
              sig_len, TF5_BLS_SIGNATURE_LEN);
        return -4;
    }

    /* Clear secret key from memory */
    memset(&sec, 0, sizeof(sec));

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

    if (!bls_initialized) {
        LOG_E(NR_RRC, "TESLA: BLS library not initialized\n");
        return -2;
    }

    blsPublicKey pub;
    blsSignature sig;

    /* Deserialize public key */
    if (blsPublicKeyDeserialize(&pub, public_key, TF5_BLS_PUBLIC_KEY_LEN)
            != TF5_BLS_PUBLIC_KEY_LEN) {
        LOG_E(NR_RRC, "TESLA: Failed to deserialize public key for verification\n");
        return -3;
    }

    /* Deserialize signature */
    if (blsSignatureDeserialize(&sig, signature, TF5_BLS_SIGNATURE_LEN)
            != TF5_BLS_SIGNATURE_LEN) {
        LOG_E(NR_RRC, "TESLA: Failed to deserialize signature for verification\n");
        return -4;
    }

    /* Verify signature: returns 1 if valid, 0 if invalid */
    int rc = blsVerify(&sig, &pub, data, data_len);
    if (rc != 1) {
        LOG_W(NR_RRC, "TESLA: BLS signature verification failed\n");
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

    if (!bls_initialized) {
        LOG_E(NR_RRC, "TESLA: BLS library not initialized\n");
        return -2;
    }

    blsSecretKey sec;
    blsPublicKey pub;

    /* Generate random secret key using CSPRNG */
    if (blsSecretKeySetByCSPRNG(&sec) != 0) {
        LOG_E(NR_RRC, "TESLA: Failed to generate BLS secret key\n");
        return -3;
    }

    /* Derive public key */
    blsGetPublicKey(&pub, &sec);

    /* Serialize secret key */
    size_t sec_len = blsSecretKeySerialize(secret_key, TF5_BLS_SECRET_KEY_LEN, &sec);
    if (sec_len != TF5_BLS_SECRET_KEY_LEN) {
        LOG_E(NR_RRC, "TESLA: Unexpected secret key size: %zu (expected %d)\n",
              sec_len, TF5_BLS_SECRET_KEY_LEN);
        memset(&sec, 0, sizeof(sec));
        return -4;
    }

    /* Serialize public key */
    size_t pub_len = blsPublicKeySerialize(public_key, TF5_BLS_PUBLIC_KEY_LEN, &pub);
    if (pub_len != TF5_BLS_PUBLIC_KEY_LEN) {
        LOG_E(NR_RRC, "TESLA: Unexpected public key size: %zu (expected %d)\n",
              pub_len, TF5_BLS_PUBLIC_KEY_LEN);
        memset(&sec, 0, sizeof(sec));
        memset(secret_key, 0, TF5_BLS_SECRET_KEY_LEN);
        return -5;
    }

    /* Clear secret key object from memory */
    memset(&sec, 0, sizeof(sec));

    return 0;
}

#endif /* TF5_ENABLE_TESLA */
