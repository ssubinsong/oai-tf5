#ifdef ENABLE_TF5

#include "tf5_crypto.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <pthread.h>
#include <assert.h>

/* --- SHA-256 (one-shot, no per-call allocation) --- */

void tf5_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    unsigned int md_len = 32;
    int rc = EVP_Digest(data, len, out, &md_len, EVP_sha256(), NULL);
    assert(rc == 1);
    (void)rc;
}

/* --- HMAC-SHA256 (cached EVP_MAC via pthread_once) --- */

static EVP_MAC *s_hmac_mac = NULL;
static pthread_once_t s_hmac_once = PTHREAD_ONCE_INIT;

static void tf5_hmac_init_once(void)
{
    s_hmac_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    assert(s_hmac_mac != NULL);
}

static __thread EVP_MAC_CTX *s_hmac_ctx = NULL;
static __thread OSSL_PARAM s_hmac_params[2];
static __thread int s_hmac_params_init = 0;
static __thread char s_hmac_digest_name[] = "SHA2-256";

void tf5_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[32])
{
    pthread_once(&s_hmac_once, tf5_hmac_init_once);

    if (!s_hmac_ctx) {
        s_hmac_ctx = EVP_MAC_CTX_new(s_hmac_mac);
        assert(s_hmac_ctx != NULL);
    }

    if (!s_hmac_params_init) {
        s_hmac_params[0] = OSSL_PARAM_construct_utf8_string(
                        OSSL_MAC_PARAM_DIGEST, s_hmac_digest_name,
                        sizeof(s_hmac_digest_name));
        s_hmac_params[1] = OSSL_PARAM_construct_end();
        s_hmac_params_init = 1;
    }

    int rc = EVP_MAC_init(s_hmac_ctx, key, key_len, s_hmac_params);
    assert(rc == 1);

    rc = EVP_MAC_update(s_hmac_ctx, data, data_len);
    assert(rc == 1);

    size_t out_len = 32;
    rc = EVP_MAC_final(s_hmac_ctx, out, &out_len, 32);
    assert(rc == 1);

    (void)rc;
}

#endif /* ENABLE_TF5 */
