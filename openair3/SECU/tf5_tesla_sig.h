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
 * TESLA Broadcast Authentication - BLS Signature Operations
 *
 * Uses blst library (Supranational) with BLS12-381 curve.
 * Minimal-signature-size variant: Signatures in G1 (48 bytes), Public keys in G2 (96 bytes).
 */

#ifndef TF5_TESLA_SIG_H
#define TF5_TESLA_SIG_H

#ifdef TF5_ENABLE_TESLA

#include <stdint.h>
#include <stddef.h>

/* BLS12-381 key and signature sizes (non-ETH mode) */
#define TF5_BLS_SECRET_KEY_LEN   32   /* Fr element */
#define TF5_BLS_PUBLIC_KEY_LEN   96   /* G2 point (compressed) */
#define TF5_BLS_SIGNATURE_LEN    48   /* G1 point (compressed) */

/**
 * Initialize BLS library
 *
 * Must be called once before any other BLS operations.
 * NOT thread-safe - call at startup before spawning threads.
 *
 * @return 0 on success, negative on error
 */
int tf5_tesla_bls_init(void);

/**
 * Derive BLS public key from secret key
 *
 * @param secret_key   BLS secret key (32 bytes)
 * @param public_key   Output: BLS public key (96 bytes)
 * @return 0 on success, negative on error
 */
int tf5_tesla_bls_derive_public(const uint8_t secret_key[TF5_BLS_SECRET_KEY_LEN],
                                uint8_t public_key[TF5_BLS_PUBLIC_KEY_LEN]);

/**
 * Sign data with BLS
 *
 * @param secret_key   BLS secret key (32 bytes)
 * @param data         Data to sign
 * @param data_len     Length of data
 * @param signature    Output: BLS signature (48 bytes)
 * @return 0 on success, negative on error
 */
int tf5_tesla_bls_sign(const uint8_t secret_key[TF5_BLS_SECRET_KEY_LEN],
                       const uint8_t *data,
                       size_t data_len,
                       uint8_t signature[TF5_BLS_SIGNATURE_LEN]);

/**
 * Verify BLS signature
 *
 * @param public_key   BLS public key (96 bytes)
 * @param data         Signed data
 * @param data_len     Length of data
 * @param signature    Signature to verify (48 bytes)
 * @return 0 on success (signature valid), negative on error
 */
int tf5_tesla_bls_verify(const uint8_t public_key[TF5_BLS_PUBLIC_KEY_LEN],
                         const uint8_t *data,
                         size_t data_len,
                         const uint8_t signature[TF5_BLS_SIGNATURE_LEN]);

/**
 * Generate BLS key pair
 *
 * @param secret_key   Output: BLS secret key (32 bytes)
 * @param public_key   Output: BLS public key (96 bytes)
 * @return 0 on success, negative on error
 */
int tf5_tesla_bls_keygen(uint8_t secret_key[TF5_BLS_SECRET_KEY_LEN],
                         uint8_t public_key[TF5_BLS_PUBLIC_KEY_LEN]);

#endif /* TF5_ENABLE_TESLA */

#endif /* TF5_TESLA_SIG_H */
