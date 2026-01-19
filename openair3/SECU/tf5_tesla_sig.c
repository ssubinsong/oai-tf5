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
 * TESLA Broadcast Authentication - Ed25519 Signature Implementation
 *
 * Uses OpenSSL EVP API for Ed25519 operations.
 */

#ifdef TF5_ENABLE_TESLA

#include "tf5_tesla_sig.h"
#include "common/utils/LOG/log.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

int tf5_tesla_ed25519_derive_public(const uint8_t private_key[32],
                                    uint8_t public_key[32])
{
    if (!private_key || !public_key) {
        return -1;
    }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                   private_key, 32);
    if (!pkey) {
        LOG_E(NR_RRC, "TESLA: Failed to create EVP_PKEY from private key\n");
        return -2;
    }

    size_t pub_len = 32;
    int rc = EVP_PKEY_get_raw_public_key(pkey, public_key, &pub_len);
    EVP_PKEY_free(pkey);

    if (rc != 1 || pub_len != 32) {
        LOG_E(NR_RRC, "TESLA: Failed to derive public key\n");
        return -3;
    }

    return 0;
}

int tf5_tesla_ed25519_sign(const uint8_t private_key[32],
                           const uint8_t *data,
                           size_t data_len,
                           uint8_t signature[64])
{
    if (!private_key || !data || !signature || data_len == 0) {
        return -1;
    }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                   private_key, 32);
    if (!pkey) {
        LOG_E(NR_RRC, "TESLA: Failed to create EVP_PKEY for signing\n");
        return -2;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        LOG_E(NR_RRC, "TESLA: Failed to create EVP_MD_CTX\n");
        return -3;
    }

    int rc = EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey);
    if (rc != 1) {
        LOG_E(NR_RRC, "TESLA: EVP_DigestSignInit failed\n");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -4;
    }

    size_t sig_len = 64;
    rc = EVP_DigestSign(ctx, signature, &sig_len, data, data_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (rc != 1 || sig_len != 64) {
        LOG_E(NR_RRC, "TESLA: EVP_DigestSign failed\n");
        return -5;
    }

    return 0;
}

int tf5_tesla_ed25519_verify(const uint8_t public_key[32],
                             const uint8_t *data,
                             size_t data_len,
                             const uint8_t signature[64])
{
    if (!public_key || !data || !signature || data_len == 0) {
        return -1;
    }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                                  public_key, 32);
    if (!pkey) {
        LOG_E(NR_RRC, "TESLA: Failed to create EVP_PKEY for verification\n");
        return -2;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        LOG_E(NR_RRC, "TESLA: Failed to create EVP_MD_CTX\n");
        return -3;
    }

    int rc = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey);
    if (rc != 1) {
        LOG_E(NR_RRC, "TESLA: EVP_DigestVerifyInit failed\n");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -4;
    }

    rc = EVP_DigestVerify(ctx, signature, 64, data, data_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (rc != 1) {
        // rc == 0 means signature invalid, rc < 0 means error
        if (rc == 0) {
            LOG_W(NR_RRC, "TESLA: Signature verification failed - invalid signature\n");
        } else {
            LOG_E(NR_RRC, "TESLA: EVP_DigestVerify error\n");
        }
        return -5;
    }

    return 0;
}

int tf5_tesla_ed25519_keygen(uint8_t private_key[32],
                             uint8_t public_key[32])
{
    if (!private_key || !public_key) {
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx) {
        LOG_E(NR_RRC, "TESLA: Failed to create EVP_PKEY_CTX for keygen\n");
        return -2;
    }

    int rc = EVP_PKEY_keygen_init(ctx);
    if (rc != 1) {
        LOG_E(NR_RRC, "TESLA: EVP_PKEY_keygen_init failed\n");
        EVP_PKEY_CTX_free(ctx);
        return -3;
    }

    EVP_PKEY *pkey = NULL;
    rc = EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    if (rc != 1 || !pkey) {
        LOG_E(NR_RRC, "TESLA: EVP_PKEY_keygen failed\n");
        return -4;
    }

    // Extract raw private key
    size_t priv_len = 32;
    rc = EVP_PKEY_get_raw_private_key(pkey, private_key, &priv_len);
    if (rc != 1 || priv_len != 32) {
        LOG_E(NR_RRC, "TESLA: Failed to extract private key\n");
        EVP_PKEY_free(pkey);
        return -5;
    }

    // Extract raw public key
    size_t pub_len = 32;
    rc = EVP_PKEY_get_raw_public_key(pkey, public_key, &pub_len);
    EVP_PKEY_free(pkey);

    if (rc != 1 || pub_len != 32) {
        LOG_E(NR_RRC, "TESLA: Failed to extract public key\n");
        return -6;
    }

    return 0;
}

#endif /* TF5_ENABLE_TESLA */
