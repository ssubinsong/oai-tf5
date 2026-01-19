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
 * TESLA Broadcast Authentication - Ed25519 Signature Operations
 */

#ifndef TF5_TESLA_SIG_H
#define TF5_TESLA_SIG_H

#ifdef TF5_ENABLE_TESLA

#include <stdint.h>
#include <stddef.h>

/**
 * Derive Ed25519 public key from private key
 *
 * @param private_key   Ed25519 private key (32 bytes)
 * @param public_key    Output: Ed25519 public key (32 bytes)
 * @return 0 on success, negative on error
 */
int tf5_tesla_ed25519_derive_public(const uint8_t private_key[32],
                                    uint8_t public_key[32]);

/**
 * Sign data with Ed25519
 *
 * @param private_key   Ed25519 private key (32 bytes)
 * @param data          Data to sign
 * @param data_len      Length of data
 * @param signature     Output: Ed25519 signature (64 bytes)
 * @return 0 on success, negative on error
 */
int tf5_tesla_ed25519_sign(const uint8_t private_key[32],
                           const uint8_t *data,
                           size_t data_len,
                           uint8_t signature[64]);

/**
 * Verify Ed25519 signature
 *
 * @param public_key    Ed25519 public key (32 bytes)
 * @param data          Signed data
 * @param data_len      Length of data
 * @param signature     Signature to verify (64 bytes)
 * @return 0 on success (signature valid), negative on error
 */
int tf5_tesla_ed25519_verify(const uint8_t public_key[32],
                             const uint8_t *data,
                             size_t data_len,
                             const uint8_t signature[64]);

/**
 * Generate Ed25519 key pair
 *
 * @param private_key   Output: Ed25519 private key (32 bytes)
 * @param public_key    Output: Ed25519 public key (32 bytes)
 * @return 0 on success, negative on error
 */
int tf5_tesla_ed25519_keygen(uint8_t private_key[32],
                             uint8_t public_key[32]);

#endif /* TF5_ENABLE_TESLA */

#endif /* TF5_TESLA_SIG_H */
