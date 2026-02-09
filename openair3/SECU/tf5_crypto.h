#ifndef TF5_CRYPTO_H
#define TF5_CRYPTO_H

#ifdef ENABLE_TF5

#include <stdint.h>
#include <stddef.h>

/*
 * TF5-optimized SHA-256 and HMAC-SHA256
 *
 * Unlike OAI's sha_256_hmac.c (which creates/destroys OSSL_LIB_CTX on every
 * call), these functions use EVP_Digest() one-shot for SHA-256 and cache the
 * EVP_MAC* handle for HMAC, eliminating per-call provider lookup overhead.
 */

void tf5_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

void tf5_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[32]);

#endif /* ENABLE_TF5 */
#endif /* TF5_CRYPTO_H */
