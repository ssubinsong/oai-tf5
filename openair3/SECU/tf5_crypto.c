#ifdef ENABLE_TF5

#include "tf5_crypto.h"

#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <pthread.h>
#include "common/utils/assertions.h"

/* --- SHA-256 (one-shot, no per-call allocation) --- */

void tf5_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    unsigned int md_len = TF5_SHA256_DIGEST_LEN;
    int rc = EVP_Digest(data, len, out, &md_len, EVP_sha256(), NULL);
    AssertFatal(rc == 1, "tf5_sha256: EVP_Digest failed\n");
    (void)rc;
}

/* --- HMAC-SHA256 (cached EVP_MAC via pthread_once) --- */

static EVP_MAC *s_hmac_mac = NULL;
static pthread_once_t s_hmac_once = PTHREAD_ONCE_INIT;

static void tf5_hmac_cleanup(void)
{
    if (s_hmac_mac) {
        EVP_MAC_free(s_hmac_mac);
        s_hmac_mac = NULL;
    }
}

static void tf5_hmac_init_once(void)
{
    s_hmac_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    AssertFatal(s_hmac_mac != NULL, "tf5_hmac: EVP_MAC_fetch failed\n");
    atexit(tf5_hmac_cleanup);
}

/* Thread-specific HMAC context with automatic cleanup via pthread_key_t destructor */
static pthread_key_t s_hmac_ctx_key;
static pthread_once_t s_hmac_key_once = PTHREAD_ONCE_INIT;

static void tf5_hmac_ctx_destructor(void *ptr)
{
    if (ptr) {
        EVP_MAC_CTX_free((EVP_MAC_CTX *)ptr);
    }
}

static void tf5_hmac_key_init_once(void)
{
    int rc = pthread_key_create(&s_hmac_ctx_key, tf5_hmac_ctx_destructor);
    AssertFatal(rc == 0, "tf5_hmac: pthread_key_create failed\n");
}

static __thread OSSL_PARAM s_hmac_params[2];
static __thread int s_hmac_params_init = 0;
static const char s_hmac_digest_name[] = "SHA2-256";

void tf5_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[32])
{
    pthread_once(&s_hmac_once, tf5_hmac_init_once);
    pthread_once(&s_hmac_key_once, tf5_hmac_key_init_once);

    EVP_MAC_CTX *ctx = (EVP_MAC_CTX *)pthread_getspecific(s_hmac_ctx_key);
    if (!ctx) {
        ctx = EVP_MAC_CTX_new(s_hmac_mac);
        AssertFatal(ctx != NULL, "tf5_hmac: EVP_MAC_CTX_new failed\n");
        pthread_setspecific(s_hmac_ctx_key, ctx);
    }

    if (!s_hmac_params_init) {
        s_hmac_params[0] = OSSL_PARAM_construct_utf8_string(
                        OSSL_MAC_PARAM_DIGEST, (char *)s_hmac_digest_name,
                        sizeof(s_hmac_digest_name));
        s_hmac_params[1] = OSSL_PARAM_construct_end();
        s_hmac_params_init = 1;
    }

    int rc = EVP_MAC_init(ctx, key, key_len, s_hmac_params);
    AssertFatal(rc == 1, "tf5_hmac: EVP_MAC_init failed\n");

    rc = EVP_MAC_update(ctx, data, data_len);
    AssertFatal(rc == 1, "tf5_hmac: EVP_MAC_update failed\n");

    size_t out_len = TF5_SHA256_DIGEST_LEN;
    rc = EVP_MAC_final(ctx, out, &out_len, TF5_SHA256_DIGEST_LEN);
    AssertFatal(rc == 1, "tf5_hmac: EVP_MAC_final failed\n");

    (void)rc;
}

#endif /* ENABLE_TF5 */
