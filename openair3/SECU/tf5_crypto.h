/**
 * @file tf5_crypto.h
 * @brief TF5-optimized SHA-256 and HMAC-SHA256 wrappers
 *
 * Unlike OAI's sha_256_hmac.c (which creates/destroys OSSL_LIB_CTX on every
 * call), these functions use EVP_Digest() one-shot for SHA-256 and cache the
 * EVP_MAC* handle for HMAC, eliminating per-call provider lookup overhead.
 */

#ifndef TF5_CRYPTO_H
#define TF5_CRYPTO_H

#ifdef ENABLE_TF5

#include <stdint.h>
#include <stddef.h>

/**
 * Compute SHA-256 hash
 *
 * @param data  Input data
 * @param len   Length of input data
 * @param out   Output hash (32 bytes)
 */
void tf5_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/**
 * Compute HMAC-SHA256
 *
 * @param key       HMAC key
 * @param key_len   Length of key
 * @param data      Input data
 * @param data_len  Length of input data
 * @param out       Output MAC (32 bytes)
 */
void tf5_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[32]);

#endif /* ENABLE_TF5 */
#endif /* TF5_CRYPTO_H */
