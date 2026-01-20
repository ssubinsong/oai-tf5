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
 * TESLA Broadcast Authentication for SIB1
 *
 * This module implements the TESLA (Timed Efficient Stream Loss-tolerant
 * Authentication) protocol for authenticating SIB1 messages in 5G NR.
 *
 * Reference: RFC 4082 - Timed Efficient Stream Loss-Tolerant Authentication
 */

#ifndef TF5_TESLA_H
#define TF5_TESLA_H

#ifdef TF5_ENABLE_TESLA

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "tf5_tesla_sig.h"  // Ed25519 signature functions

/*
 * TESLA Configuration Constants
 */
#define TF5_TESLA_KEY_LEN           16      // 128-bit keys
#define TF5_TESLA_TAG_LEN           16      // Truncated HMAC-SHA256 to 128 bits
#define TF5_TESLA_SIG_LEN           64      // Ed25519 signature length
#define TF5_TESLA_CHAIN_LEN         65536   // ~21 minutes at T_int=20ms
#define TF5_TESLA_MAX_SIB1_LEN      374     // Max SIB1 encoded size (2976 bits)
#define TF5_TESLA_MAX_AUTH_INPUT    512     // Max auth input buffer size

// Protocol version
#define TF5_TESLA_VERSION           0x01

// Crypto suite identifiers
#define TF5_CRYPTO_SUITE_HMAC_SHA256_ED25519  0x01

/*
 * TESLA Static Parameters
 *
 * These parameters are constant for the lifetime of a key chain.
 * Total size: 30 bytes
 */
typedef struct {
    uint8_t  te_version;           // 1B - Protocol version
    uint8_t  crypto_suite_id;      // 1B - Algorithm identifier
    uint16_t t_int_ms;             // 2B - Interval duration in ms (e.g., 20ms)
    uint8_t  disclosure_delay;     // 1B - Key disclosure delay d (e.g., 1)
    uint8_t  key_len;              // 1B - TESLA key length (16)
    uint8_t  root_key[TF5_TESLA_KEY_LEN]; // 16B - K_0 chain commitment
    uint16_t t0_hfn;               // 2B - HFN at interval 0 start (for SFN wraparound)
    uint16_t t0_sfn;               // 2B - SFN of interval 0 start (PHY timing)
    uint16_t t0_slot;              // 2B - slot of interval 0 start (PHY timing)
    uint32_t chain_len;            // 4B - Number of intervals N
} tf5_tesla_static_params_t;

/*
 * TESLA Dynamic Parameters
 *
 * These parameters change with each SIB1 transmission.
 * Total size: 26 bytes
 */
typedef struct {
    uint32_t interval_index;       // 4B - Current interval i
    uint16_t ti_hfn;               // 2B - HFN when this SIB1 sent (for SFN wraparound)
    uint16_t ti_sfn;               // 2B - SFN when this SIB1 sent
    uint16_t ti_slot;              // 2B - slot when this SIB1 sent
    uint8_t  disclosed_key[TF5_TESLA_KEY_LEN]; // 16B - K_{i-d}
} tf5_tesla_dynamic_params_t;

/*
 * Complete TESLA Extension Payload
 *
 * This structure represents the complete TESLA data appended to SIB1
 * via lateNonCriticalExtension.
 * Total size: ~136 bytes
 */
typedef struct {
    tf5_tesla_static_params_t  static_params;      // 30B
    tf5_tesla_dynamic_params_t dynamic_params;     // 26B
    uint8_t  gnb_signature[TF5_TESLA_SIG_LEN];     // 64B - Ed25519 signature
    uint8_t  tesla_tag[TF5_TESLA_TAG_LEN];         // 16B - HMAC tag
} tf5_tesla_extension_t;

/*
 * gNB-side TESLA State
 *
 * Maintains the key chain and parameters for TESLA authentication on gNB.
 */
typedef struct {
    tf5_tesla_static_params_t params;

    // Key chain storage (backward chain: K_i = F(K_{i+1}))
    uint8_t  (*key_chain)[TF5_TESLA_KEY_LEN];      // Dynamically allocated
    uint32_t key_chain_len;

    // Current state
    uint32_t current_interval;

    // HFN tracking (for SFN wraparound handling)
    uint16_t current_hfn;         // Current Hyper-Frame Number
    uint16_t last_sfn;            // Last seen SFN (to detect wraparound)

    // Ed25519 keys
    uint8_t  gnb_private_key[32];
    uint8_t  gnb_public_key[32];

    // Slots per frame (depends on numerology)
    uint16_t slots_per_frame;

    // Initialization flag
    bool     initialized;
} tf5_tesla_gnb_state_t;

/*
 * UE-side TESLA State
 *
 * Maintains state for TESLA verification on UE.
 */
typedef struct {
    tf5_tesla_static_params_t static_params;

    // Pre-provisioned gNB public key
    uint8_t  gnb_public_key[32];
    bool     has_gnb_public_key;     // Is gNB public key configured?

    // Verification state
    bool     params_received;        // Have we received static params?
    uint32_t last_verified_key_idx;  // Index of last verified key
    uint8_t  last_verified_key[TF5_TESLA_KEY_LEN];

    // HFN tracking (for SFN wraparound handling)
    uint16_t current_hfn;         // Current Hyper-Frame Number
    uint16_t last_sfn;            // Last seen SFN (to detect wraparound)

    // Buffered SIB1 pending TESLA verification
    struct {
        uint8_t  auth_input[TF5_TESLA_MAX_AUTH_INPUT];
        size_t   auth_input_len;
        uint32_t interval_index;
        uint8_t  tag[TF5_TESLA_TAG_LEN];
        uint16_t rx_hfn;             // HFN when SIB1 was received
        uint16_t rx_sfn;
        uint16_t rx_slot;
        bool     pending;
    } buffer;

    // Slots per frame (depends on numerology)
    uint16_t slots_per_frame;

    // Initialization flag
    bool     initialized;
} tf5_tesla_ue_state_t;

/*
 * =============================================================================
 * gNB API Functions
 * =============================================================================
 */

/**
 * Initialize TESLA state on gNB
 *
 * Generates the key chain and sets up static parameters.
 * HFN starts at 0 by default.
 *
 * @param state         Pointer to gNB TESLA state structure
 * @param t_int_ms      Interval duration in milliseconds (e.g., 20)
 * @param d             Key disclosure delay (e.g., 1)
 * @param chain_len     Number of intervals in key chain
 * @param private_key   Ed25519 private key (32 bytes)
 * @param hfn           Initial HFN (usually 0)
 * @param sfn           Current SFN (for T_0)
 * @param slot          Current slot (for T_0)
 * @param slots_per_frame Number of slots per frame
 * @return 0 on success, negative on error
 */
int tf5_tesla_gnb_init(tf5_tesla_gnb_state_t *state,
                       uint16_t t_int_ms,
                       uint8_t d,
                       uint32_t chain_len,
                       const uint8_t private_key[32],
                       uint16_t hfn,
                       uint16_t sfn,
                       uint16_t slot,
                       uint16_t slots_per_frame);

/**
 * Free TESLA state resources on gNB
 *
 * @param state         Pointer to gNB TESLA state structure
 */
void tf5_tesla_gnb_free(tf5_tesla_gnb_state_t *state);

/**
 * Get current interval index from SFN/slot
 *
 * Updates internal HFN tracking based on SFN wraparound detection.
 *
 * @param state         Pointer to gNB TESLA state structure (updated for HFN)
 * @param sfn           Current SFN
 * @param slot          Current slot
 * @return Current interval index
 */
uint32_t tf5_tesla_gnb_get_interval(tf5_tesla_gnb_state_t *state,
                                    uint16_t sfn,
                                    uint16_t slot);

/**
 * Build authentication input buffer
 *
 * Constructs the data to be signed/MAC'd:
 * original_SIB1 || static_params || dynamic_params
 *
 * @param out           Output buffer
 * @param out_len       Output: length of data written
 * @param original_sib1 Original SIB1 encoded data (without TESLA extension)
 * @param sib1_len      Length of original SIB1 data
 * @param static_params Static TESLA parameters
 * @param dynamic_params Dynamic TESLA parameters
 * @return 0 on success, negative on error
 */
int tf5_tesla_build_auth_input(uint8_t *out,
                               size_t *out_len,
                               const uint8_t *original_sib1,
                               size_t sib1_len,
                               const tf5_tesla_static_params_t *static_params,
                               const tf5_tesla_dynamic_params_t *dynamic_params);

/**
 * Update dynamic parameters and compute signature/tag
 *
 * This should be called before each SIB1 transmission.
 *
 * @param state         Pointer to gNB TESLA state structure
 * @param sfn           Current SFN
 * @param slot          Current slot
 * @param original_sib1 Original SIB1 encoded data
 * @param sib1_len      Length of original SIB1 data
 * @param ext           Output: complete TESLA extension
 * @return 0 on success, negative on error
 */
int tf5_tesla_gnb_prepare_extension(tf5_tesla_gnb_state_t *state,
                                    uint16_t sfn,
                                    uint16_t slot,
                                    const uint8_t *original_sib1,
                                    size_t sib1_len,
                                    tf5_tesla_extension_t *ext);

/**
 * Pack TESLA extension into binary format
 *
 * @param ext           TESLA extension structure
 * @param buf           Output buffer
 * @param buf_len       Size of output buffer
 * @return Number of bytes written, or negative on error
 */
int tf5_tesla_pack_extension(const tf5_tesla_extension_t *ext,
                             uint8_t *buf,
                             size_t buf_len);

/*
 * =============================================================================
 * UE API Functions
 * =============================================================================
 */

/**
 * Initialize TESLA state on UE
 *
 * @param state         Pointer to UE TESLA state structure
 * @param gnb_public_key Pre-provisioned gNB Ed25519 public key (32 bytes)
 * @param slots_per_frame Number of slots per frame
 * @return 0 on success, negative on error
 */
int tf5_tesla_ue_init(tf5_tesla_ue_state_t *state,
                      const uint8_t gnb_public_key[32],
                      uint16_t slots_per_frame);

/**
 * Free TESLA state resources on UE
 *
 * @param state         Pointer to UE TESLA state structure
 */
void tf5_tesla_ue_free(tf5_tesla_ue_state_t *state);

/**
 * Unpack TESLA extension from binary format
 *
 * @param buf           Input buffer
 * @param buf_len       Length of input buffer
 * @param ext           Output: unpacked TESLA extension
 * @return 0 on success, negative on error
 */
int tf5_tesla_unpack_extension(const uint8_t *buf,
                               size_t buf_len,
                               tf5_tesla_extension_t *ext);

/**
 * Verify Ed25519 signature
 *
 * @param state         Pointer to UE TESLA state structure
 * @param auth_input    Authentication input (SIB1 + static + dynamic)
 * @param auth_input_len Length of auth input
 * @param signature     Signature to verify (64 bytes)
 * @return 0 on success (signature valid), negative on error
 */
int tf5_tesla_ue_verify_signature(const tf5_tesla_ue_state_t *state,
                                  const uint8_t *auth_input,
                                  size_t auth_input_len,
                                  const uint8_t signature[TF5_TESLA_SIG_LEN]);

/**
 * Perform safe packet test
 *
 * Verifies that x < i + d where:
 * - x = current interval based on UE's clock
 * - i = claimed interval index
 * - d = disclosure delay
 *
 * @param state         Pointer to UE TESLA state structure
 * @param ext           TESLA extension from received SIB1
 * @param rx_hfn        HFN when packet was received
 * @param rx_sfn        SFN when packet was received
 * @param rx_slot       Slot when packet was received
 * @return true if packet is safe, false otherwise
 */
bool tf5_tesla_ue_safe_packet_test(const tf5_tesla_ue_state_t *state,
                                   const tf5_tesla_extension_t *ext,
                                   uint16_t rx_hfn,
                                   uint16_t rx_sfn,
                                   uint16_t rx_slot);

/**
 * Buffer SIB1 for delayed TESLA verification
 *
 * @param state         Pointer to UE TESLA state structure
 * @param auth_input    Authentication input
 * @param auth_input_len Length of auth input
 * @param interval_index Interval index of this SIB1
 * @param tag           TESLA tag from SIB1
 * @param rx_hfn        HFN when received
 * @param rx_sfn        SFN when received
 * @param rx_slot       Slot when received
 * @return 0 on success, negative on error
 */
int tf5_tesla_ue_buffer_sib1(tf5_tesla_ue_state_t *state,
                             const uint8_t *auth_input,
                             size_t auth_input_len,
                             uint32_t interval_index,
                             const uint8_t tag[TF5_TESLA_TAG_LEN],
                             uint16_t rx_hfn,
                             uint16_t rx_sfn,
                             uint16_t rx_slot);

/**
 * Verify buffered SIB1 using disclosed key
 *
 * @param state         Pointer to UE TESLA state structure
 * @param disclosed_key Disclosed key K_{key_interval}
 * @param key_interval  Interval index of disclosed key
 * @return 0 on success (MAC valid), negative on error
 */
int tf5_tesla_ue_verify_buffered(tf5_tesla_ue_state_t *state,
                                 const uint8_t disclosed_key[TF5_TESLA_KEY_LEN],
                                 uint32_t key_interval);

/**
 * Verify key chain integrity
 *
 * Verifies that disclosed key chains to a previously verified key or K_0.
 *
 * @param state         Pointer to UE TESLA state structure
 * @param disclosed_key Disclosed key to verify
 * @param key_index     Index of disclosed key
 * @return true if key is valid, false otherwise
 */
bool tf5_tesla_ue_verify_key_chain(tf5_tesla_ue_state_t *state,
                                   const uint8_t disclosed_key[TF5_TESLA_KEY_LEN],
                                   uint32_t key_index);

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

/**
 * Derive MAC key from TESLA key
 *
 * K'_i = F'(K_i) = HMAC-SHA256(K_i, 0x01)
 *
 * @param key_in        Input TESLA key K_i (16 bytes)
 * @param mac_key_out   Output MAC key K'_i (32 bytes)
 */
void tf5_tesla_derive_mac_key(const uint8_t key_in[TF5_TESLA_KEY_LEN],
                              uint8_t mac_key_out[32]);

/**
 * Compute next key in backward chain
 *
 * K_i = F(K_{i+1}) = HMAC-SHA256(K_{i+1}, 0x00)[0:15]
 *
 * @param key_next      Input key K_{i+1} (16 bytes)
 * @param key_out       Output key K_i (16 bytes)
 */
void tf5_tesla_chain_key(const uint8_t key_next[TF5_TESLA_KEY_LEN],
                         uint8_t key_out[TF5_TESLA_KEY_LEN]);

/**
 * Compute TESLA MAC tag
 *
 * tag = HMAC-SHA256(K'_i, auth_input)[0:15]
 *
 * @param key           TESLA key K_i (16 bytes)
 * @param auth_input    Data to authenticate
 * @param auth_input_len Length of data
 * @param tag_out       Output tag (16 bytes)
 * @return 0 on success, negative on error
 */
int tf5_tesla_compute_tag(const uint8_t key[TF5_TESLA_KEY_LEN],
                          const uint8_t *auth_input,
                          size_t auth_input_len,
                          uint8_t tag_out[TF5_TESLA_TAG_LEN]);

/**
 * Get number of slots elapsed since T_0
 *
 * Uses HFN (Hyper-Frame Number) to handle SFN wraparound correctly.
 * SFN wraps every 10.24 seconds (1024 frames × 10ms).
 *
 * @param current_hfn   Current HFN
 * @param current_sfn   Current SFN
 * @param current_slot  Current slot
 * @param t0_hfn        HFN at T_0
 * @param t0_sfn        SFN at T_0
 * @param t0_slot       Slot at T_0
 * @param slots_per_frame Number of slots per frame
 * @return Number of slots elapsed (0 if current time is before T_0)
 */
uint64_t tf5_tesla_slots_since_t0(uint16_t current_hfn,
                                  uint16_t current_sfn,
                                  uint16_t current_slot,
                                  uint16_t t0_hfn,
                                  uint16_t t0_sfn,
                                  uint16_t t0_slot,
                                  uint16_t slots_per_frame);

/**
 * Get interval index from HFN/SFN/slot
 *
 * @param hfn           Current HFN
 * @param sfn           Current SFN
 * @param slot          Current slot
 * @param t0_hfn        HFN at T_0
 * @param t0_sfn        SFN at T_0
 * @param t0_slot       Slot at T_0
 * @param t_int_ms      Interval duration in ms
 * @param slots_per_frame Number of slots per frame
 * @return Interval index
 */
uint32_t tf5_tesla_get_interval_index(uint16_t hfn,
                                      uint16_t sfn,
                                      uint16_t slot,
                                      uint16_t t0_hfn,
                                      uint16_t t0_sfn,
                                      uint16_t t0_slot,
                                      uint16_t t_int_ms,
                                      uint16_t slots_per_frame);

/*
 * =============================================================================
 * HFN (Hyper-Frame Number) Helpers
 * =============================================================================
 */

/**
 * Compute absolute slot count from (HFN, SFN, slot)
 *
 * This handles the full time range without wraparound issues.
 * HFN increments each time SFN wraps from 1023 to 0.
 *
 * @param hfn            Hyper-Frame Number
 * @param sfn            System Frame Number (0-1023)
 * @param slot           Slot within frame
 * @param slots_per_frame Number of slots per frame
 * @return Absolute slot count since HFN=0, SFN=0, slot=0
 */
static inline uint64_t tf5_tesla_absolute_slots(uint16_t hfn,
                                                 uint16_t sfn,
                                                 uint16_t slot,
                                                 uint16_t slots_per_frame)
{
    // Total frames = HFN * 1024 + SFN
    // Total slots = total_frames * slots_per_frame + slot
    uint64_t total_frames = (uint64_t)hfn * 1024 + sfn;
    return total_frames * slots_per_frame + slot;
}

/**
 * Update HFN based on SFN transition
 *
 * Detects SFN wraparound (1023 -> 0) and increments HFN.
 * Call this whenever processing a new SFN value.
 *
 * @param hfn            Pointer to current HFN (will be incremented on wrap)
 * @param last_sfn       Pointer to last seen SFN (will be updated)
 * @param current_sfn    Current SFN value
 */
static inline void tf5_tesla_update_hfn(uint16_t *hfn,
                                         uint16_t *last_sfn,
                                         uint16_t current_sfn)
{
    // Detect wraparound: last_sfn near 1023, current_sfn near 0
    // Use threshold to handle slight variations in timing
    if (*last_sfn > 900 && current_sfn < 100) {
        (*hfn)++;
    }
    *last_sfn = current_sfn;
}

/*
 * =============================================================================
 * Binary Encoding/Decoding Helpers
 * =============================================================================
 */

static inline void tf5_encode_u16_be(uint8_t *buf, uint16_t val) {
    buf[0] = (val >> 8) & 0xFF;
    buf[1] = val & 0xFF;
}

static inline void tf5_encode_u32_be(uint8_t *buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
}

static inline uint16_t tf5_decode_u16_be(const uint8_t *buf) {
    return ((uint16_t)buf[0] << 8) | buf[1];
}

static inline uint32_t tf5_decode_u32_be(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) |
           buf[3];
}

#endif /* TF5_ENABLE_TESLA */

#endif /* TF5_TESLA_H */
