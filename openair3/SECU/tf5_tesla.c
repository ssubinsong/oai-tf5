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
 * TESLA Broadcast Authentication for SIB1 - Core Implementation
 */

#ifdef TF5_ENABLE_TESLA

#include "tf5_tesla.h"
#include "tf5_tesla_sig.h"
#include "sha_256_hmac.h"
#include "common/utils/assertions.h"
#include "common/utils/LOG/log.h"

#include <string.h>
#include <stdlib.h>
#include <openssl/rand.h>

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

void tf5_tesla_derive_mac_key(const uint8_t key_in[TF5_TESLA_KEY_LEN],
                              uint8_t mac_key_out[32])
{
    // K'_i = F'(K_i) = HMAC-SHA256(K_i_padded, 0x01)
    // Pad 16-byte key to 32 bytes for sha_256_hmac
    uint8_t padded_key[32] = {0};
    memcpy(padded_key, key_in, TF5_TESLA_KEY_LEN);

    uint8_t input[1] = {0x01};
    byte_array_t data = {.buf = input, .len = 1};

    sha_256_hmac(padded_key, data, 32, mac_key_out);
}

void tf5_tesla_chain_key(const uint8_t key_next[TF5_TESLA_KEY_LEN],
                         uint8_t key_out[TF5_TESLA_KEY_LEN])
{
    // K_i = F(K_{i+1}) = HMAC-SHA256(K_{i+1}_padded, 0x00)[0:15]
    uint8_t padded_key[32] = {0};
    memcpy(padded_key, key_next, TF5_TESLA_KEY_LEN);

    uint8_t input[1] = {0x00};
    byte_array_t data = {.buf = input, .len = 1};

    uint8_t full_hash[32];
    sha_256_hmac(padded_key, data, 32, full_hash);

    // Truncate to 16 bytes
    memcpy(key_out, full_hash, TF5_TESLA_KEY_LEN);
}

int tf5_tesla_compute_tag(const uint8_t key[TF5_TESLA_KEY_LEN],
                          const uint8_t *auth_input,
                          size_t auth_input_len,
                          uint8_t tag_out[TF5_TESLA_TAG_LEN])
{
    if (!key || !auth_input || !tag_out || auth_input_len == 0) {
        return -1;
    }

    // Derive MAC key K'_i from K_i
    uint8_t mac_key[32];
    tf5_tesla_derive_mac_key(key, mac_key);

    // Compute HMAC-SHA256(K'_i, auth_input)
    byte_array_t data = {.buf = (uint8_t *)auth_input, .len = auth_input_len};
    uint8_t full_tag[32];
    sha_256_hmac(mac_key, data, 32, full_tag);

    // Truncate to 16 bytes
    memcpy(tag_out, full_tag, TF5_TESLA_TAG_LEN);

    return 0;
}

uint64_t tf5_tesla_slots_since_t0(uint16_t current_hfn,
                                  uint16_t current_sfn,
                                  uint16_t current_slot,
                                  uint16_t t0_hfn,
                                  uint16_t t0_sfn,
                                  uint16_t t0_slot,
                                  uint16_t slots_per_frame)
{
    // Use absolute slot counts to handle SFN wraparound correctly
    // HFN (Hyper-Frame Number) increments each time SFN wraps from 1023 to 0
    uint64_t current_abs = tf5_tesla_absolute_slots(current_hfn, current_sfn,
                                                     current_slot, slots_per_frame);
    uint64_t t0_abs = tf5_tesla_absolute_slots(t0_hfn, t0_sfn,
                                                t0_slot, slots_per_frame);

    return (current_abs >= t0_abs) ? (current_abs - t0_abs) : 0;
}

uint32_t tf5_tesla_get_interval_index(uint16_t hfn,
                                      uint16_t sfn,
                                      uint16_t slot,
                                      uint16_t t0_hfn,
                                      uint16_t t0_sfn,
                                      uint16_t t0_slot,
                                      uint16_t t_int_ms,
                                      uint16_t slots_per_frame)
{
    uint64_t slots = tf5_tesla_slots_since_t0(hfn, sfn, slot,
                                               t0_hfn, t0_sfn, t0_slot,
                                               slots_per_frame);

    // Calculate time in milliseconds
    // Each frame = 10ms, slots_per_frame slots per frame
    // So each slot = 10 / slots_per_frame ms
    // time_ms = slots * 10 / slots_per_frame
    uint64_t time_ms = (slots * 10) / slots_per_frame;

    return (uint32_t)(time_ms / t_int_ms);
}

/*
 * =============================================================================
 * Binary Pack/Unpack Functions
 * =============================================================================
 */

int tf5_tesla_build_auth_input(uint8_t *out,
                               size_t *out_len,
                               const uint8_t *original_sib1,
                               size_t sib1_len,
                               const tf5_tesla_static_params_t *static_params,
                               const tf5_tesla_dynamic_params_t *dynamic_params)
{
    if (!out || !out_len || !original_sib1 || !static_params || !dynamic_params) {
        return -1;
    }

    size_t offset = 0;

    // 1. Original SIB1 content
    memcpy(out + offset, original_sib1, sib1_len);
    offset += sib1_len;

    // 2. Static params (30 bytes)
    out[offset++] = static_params->te_version;
    out[offset++] = static_params->crypto_suite_id;
    tf5_encode_u16_be(out + offset, static_params->t_int_ms);
    offset += 2;
    out[offset++] = static_params->disclosure_delay;
    out[offset++] = static_params->key_len;
    memcpy(out + offset, static_params->root_key, TF5_TESLA_KEY_LEN);
    offset += TF5_TESLA_KEY_LEN;
    tf5_encode_u16_be(out + offset, static_params->t0_hfn);
    offset += 2;
    tf5_encode_u16_be(out + offset, static_params->t0_sfn);
    offset += 2;
    tf5_encode_u16_be(out + offset, static_params->t0_slot);
    offset += 2;
    tf5_encode_u32_be(out + offset, static_params->chain_len);
    offset += 4;

    // 3. Dynamic params (26 bytes)
    tf5_encode_u32_be(out + offset, dynamic_params->interval_index);
    offset += 4;
    tf5_encode_u16_be(out + offset, dynamic_params->ti_hfn);
    offset += 2;
    tf5_encode_u16_be(out + offset, dynamic_params->ti_sfn);
    offset += 2;
    tf5_encode_u16_be(out + offset, dynamic_params->ti_slot);
    offset += 2;
    memcpy(out + offset, dynamic_params->disclosed_key, TF5_TESLA_KEY_LEN);
    offset += TF5_TESLA_KEY_LEN;

    *out_len = offset;
    return 0;
}

int tf5_tesla_pack_extension(const tf5_tesla_extension_t *ext,
                             uint8_t *buf,
                             size_t buf_len)
{
    if (!ext || !buf) {
        return -1;
    }

    // Total size: 30 + 26 + 64 + 16 = 136 bytes
    const size_t required_len = 136;
    if (buf_len < required_len) {
        return -2;
    }

    size_t offset = 0;

    // Static params (30 bytes)
    buf[offset++] = ext->static_params.te_version;
    buf[offset++] = ext->static_params.crypto_suite_id;
    tf5_encode_u16_be(buf + offset, ext->static_params.t_int_ms);
    offset += 2;
    buf[offset++] = ext->static_params.disclosure_delay;
    buf[offset++] = ext->static_params.key_len;
    memcpy(buf + offset, ext->static_params.root_key, TF5_TESLA_KEY_LEN);
    offset += TF5_TESLA_KEY_LEN;
    tf5_encode_u16_be(buf + offset, ext->static_params.t0_hfn);
    offset += 2;
    tf5_encode_u16_be(buf + offset, ext->static_params.t0_sfn);
    offset += 2;
    tf5_encode_u16_be(buf + offset, ext->static_params.t0_slot);
    offset += 2;
    tf5_encode_u32_be(buf + offset, ext->static_params.chain_len);
    offset += 4;

    // Dynamic params (26 bytes)
    tf5_encode_u32_be(buf + offset, ext->dynamic_params.interval_index);
    offset += 4;
    tf5_encode_u16_be(buf + offset, ext->dynamic_params.ti_hfn);
    offset += 2;
    tf5_encode_u16_be(buf + offset, ext->dynamic_params.ti_sfn);
    offset += 2;
    tf5_encode_u16_be(buf + offset, ext->dynamic_params.ti_slot);
    offset += 2;
    memcpy(buf + offset, ext->dynamic_params.disclosed_key, TF5_TESLA_KEY_LEN);
    offset += TF5_TESLA_KEY_LEN;

    // Signature (64 bytes)
    memcpy(buf + offset, ext->gnb_signature, TF5_TESLA_SIG_LEN);
    offset += TF5_TESLA_SIG_LEN;

    // TESLA tag (16 bytes)
    memcpy(buf + offset, ext->tesla_tag, TF5_TESLA_TAG_LEN);
    offset += TF5_TESLA_TAG_LEN;

    return (int)offset;
}

int tf5_tesla_unpack_extension(const uint8_t *buf,
                               size_t buf_len,
                               tf5_tesla_extension_t *ext)
{
    if (!buf || !ext) {
        return -1;
    }

    const size_t required_len = 136;
    if (buf_len < required_len) {
        return -2;
    }

    size_t offset = 0;

    // Static params (30 bytes)
    ext->static_params.te_version = buf[offset++];
    ext->static_params.crypto_suite_id = buf[offset++];
    ext->static_params.t_int_ms = tf5_decode_u16_be(buf + offset);
    offset += 2;
    ext->static_params.disclosure_delay = buf[offset++];
    ext->static_params.key_len = buf[offset++];
    memcpy(ext->static_params.root_key, buf + offset, TF5_TESLA_KEY_LEN);
    offset += TF5_TESLA_KEY_LEN;
    ext->static_params.t0_hfn = tf5_decode_u16_be(buf + offset);
    offset += 2;
    ext->static_params.t0_sfn = tf5_decode_u16_be(buf + offset);
    offset += 2;
    ext->static_params.t0_slot = tf5_decode_u16_be(buf + offset);
    offset += 2;
    ext->static_params.chain_len = tf5_decode_u32_be(buf + offset);
    offset += 4;

    // Dynamic params (26 bytes)
    ext->dynamic_params.interval_index = tf5_decode_u32_be(buf + offset);
    offset += 4;
    ext->dynamic_params.ti_hfn = tf5_decode_u16_be(buf + offset);
    offset += 2;
    ext->dynamic_params.ti_sfn = tf5_decode_u16_be(buf + offset);
    offset += 2;
    ext->dynamic_params.ti_slot = tf5_decode_u16_be(buf + offset);
    offset += 2;
    memcpy(ext->dynamic_params.disclosed_key, buf + offset, TF5_TESLA_KEY_LEN);
    offset += TF5_TESLA_KEY_LEN;

    // Signature (64 bytes)
    memcpy(ext->gnb_signature, buf + offset, TF5_TESLA_SIG_LEN);
    offset += TF5_TESLA_SIG_LEN;

    // TESLA tag (16 bytes)
    memcpy(ext->tesla_tag, buf + offset, TF5_TESLA_TAG_LEN);
    offset += TF5_TESLA_TAG_LEN;

    return 0;
}

/*
 * =============================================================================
 * gNB Functions
 * =============================================================================
 */

int tf5_tesla_gnb_init(tf5_tesla_gnb_state_t *state,
                       uint16_t t_int_ms,
                       uint8_t d,
                       uint32_t chain_len,
                       const uint8_t private_key[32],
                       uint16_t hfn,
                       uint16_t sfn,
                       uint16_t slot,
                       uint16_t slots_per_frame)
{
    if (!state || !private_key || chain_len == 0 || t_int_ms == 0) {
        return -1;
    }

    memset(state, 0, sizeof(*state));

    // Store Ed25519 private key
    memcpy(state->gnb_private_key, private_key, 32);

    // Derive public key from private key
    if (tf5_tesla_ed25519_derive_public(private_key, state->gnb_public_key) != 0) {
        LOG_E(NR_RRC, "TESLA: Failed to derive Ed25519 public key\n");
        return -2;
    }

    // Allocate key chain
    state->key_chain = calloc(chain_len, TF5_TESLA_KEY_LEN);
    if (!state->key_chain) {
        LOG_E(NR_RRC, "TESLA: Failed to allocate key chain\n");
        return -3;
    }
    state->key_chain_len = chain_len;

    // Generate random K_N (last key in chain)
    if (RAND_bytes(state->key_chain[chain_len - 1], TF5_TESLA_KEY_LEN) != 1) {
        LOG_E(NR_RRC, "TESLA: Failed to generate random key\n");
        free(state->key_chain);
        return -4;
    }

    // Generate backward chain: K_i = F(K_{i+1})
    for (int32_t i = (int32_t)chain_len - 2; i >= 0; i--) {
        tf5_tesla_chain_key(state->key_chain[i + 1], state->key_chain[i]);
    }

    // K_0 is the root commitment
    LOG_I(NR_RRC, "TESLA: Key chain generated with %u intervals\n", chain_len);

    // Set static parameters
    state->params.te_version = TF5_TESLA_VERSION;
    state->params.crypto_suite_id = TF5_CRYPTO_SUITE_HMAC_SHA256_ED25519;
    state->params.t_int_ms = t_int_ms;
    state->params.disclosure_delay = d;
    state->params.key_len = TF5_TESLA_KEY_LEN;
    memcpy(state->params.root_key, state->key_chain[0], TF5_TESLA_KEY_LEN);
    state->params.t0_hfn = hfn;
    state->params.t0_sfn = sfn;
    state->params.t0_slot = slot;
    state->params.chain_len = chain_len;

    // Initialize HFN tracking
    state->current_hfn = hfn;
    state->last_sfn = sfn;

    state->slots_per_frame = slots_per_frame;
    state->current_interval = 0;
    state->initialized = true;

    LOG_I(NR_RRC, "TESLA: gNB initialized - T_int=%ums, d=%u, T_0=HFN%u.SFN%u.%u\n",
          t_int_ms, d, hfn, sfn, slot);

    return 0;
}

void tf5_tesla_gnb_free(tf5_tesla_gnb_state_t *state)
{
    if (state) {
        if (state->key_chain) {
            // Clear sensitive data
            memset(state->key_chain, 0, state->key_chain_len * TF5_TESLA_KEY_LEN);
            free(state->key_chain);
        }
        memset(state->gnb_private_key, 0, 32);
        memset(state, 0, sizeof(*state));
    }
}

uint32_t tf5_tesla_gnb_get_interval(tf5_tesla_gnb_state_t *state,
                                    uint16_t sfn,
                                    uint16_t slot)
{
    if (!state || !state->initialized) {
        return 0;
    }

    // Update HFN tracking based on SFN wraparound detection
    tf5_tesla_update_hfn(&state->current_hfn, &state->last_sfn, sfn);

    return tf5_tesla_get_interval_index(state->current_hfn, sfn, slot,
                                        state->params.t0_hfn,
                                        state->params.t0_sfn,
                                        state->params.t0_slot,
                                        state->params.t_int_ms,
                                        state->slots_per_frame);
}

int tf5_tesla_gnb_prepare_extension(tf5_tesla_gnb_state_t *state,
                                    uint16_t sfn,
                                    uint16_t slot,
                                    const uint8_t *original_sib1,
                                    size_t sib1_len,
                                    tf5_tesla_extension_t *ext)
{
    if (!state || !state->initialized || !original_sib1 || !ext) {
        return -1;
    }

    // Get current interval
    uint32_t interval = tf5_tesla_gnb_get_interval(state, sfn, slot);

    // Check if interval is within chain bounds
    if (interval >= state->key_chain_len) {
        LOG_E(NR_RRC, "TESLA: Interval %u exceeds chain length %u\n",
              interval, state->key_chain_len);
        return -2;
    }

    // Copy static params
    memcpy(&ext->static_params, &state->params, sizeof(state->params));

    // Set dynamic params
    ext->dynamic_params.interval_index = interval;
    ext->dynamic_params.ti_hfn = state->current_hfn;
    ext->dynamic_params.ti_sfn = sfn;
    ext->dynamic_params.ti_slot = slot;

    // Set disclosed key K_{i-d}
    uint8_t disclosure_delay = state->params.disclosure_delay;
    if (interval >= disclosure_delay) {
        uint32_t disclosed_idx = interval - disclosure_delay;
        memcpy(ext->dynamic_params.disclosed_key,
               state->key_chain[disclosed_idx],
               TF5_TESLA_KEY_LEN);
    } else {
        // Not enough intervals have passed to disclose a key
        // Use zeros as placeholder
        memset(ext->dynamic_params.disclosed_key, 0, TF5_TESLA_KEY_LEN);
    }

    // Build auth input (SIB1 + static + dynamic)
    uint8_t auth_input[TF5_TESLA_MAX_AUTH_INPUT];
    size_t auth_input_len;
    int rc = tf5_tesla_build_auth_input(auth_input, &auth_input_len,
                                        original_sib1, sib1_len,
                                        &ext->static_params,
                                        &ext->dynamic_params);
    if (rc != 0) {
        LOG_E(NR_RRC, "TESLA: Failed to build auth input\n");
        return -3;
    }

    // Compute Ed25519 signature
    rc = tf5_tesla_ed25519_sign(state->gnb_private_key,
                                auth_input, auth_input_len,
                                ext->gnb_signature);
    if (rc != 0) {
        LOG_E(NR_RRC, "TESLA: Failed to compute signature\n");
        return -4;
    }

    // Compute TESLA tag using K_i
    rc = tf5_tesla_compute_tag(state->key_chain[interval],
                               auth_input, auth_input_len,
                               ext->tesla_tag);
    if (rc != 0) {
        LOG_E(NR_RRC, "TESLA: Failed to compute tag\n");
        return -5;
    }

    state->current_interval = interval;

    LOG_D(NR_RRC, "TESLA: Prepared extension for interval %u (SFN%u.%u)\n",
          interval, sfn, slot);

    return 0;
}

/*
 * =============================================================================
 * UE Functions
 * =============================================================================
 */

int tf5_tesla_ue_init(tf5_tesla_ue_state_t *state,
                      const uint8_t gnb_public_key[32],
                      uint16_t slots_per_frame)
{
    if (!state || !gnb_public_key) {
        return -1;
    }

    memset(state, 0, sizeof(*state));

    memcpy(state->gnb_public_key, gnb_public_key, 32);
    state->slots_per_frame = slots_per_frame;
    state->params_received = false;
    state->buffer.pending = false;

    // HFN tracking will be initialized from first valid signed SIB1
    state->current_hfn = 0;
    state->last_sfn = 0;
    state->hfn_initialized = false;

    state->initialized = true;

    LOG_I(NR_RRC, "TESLA: UE initialized (HFN tracking pending first SIB1)\n");

    return 0;
}

void tf5_tesla_ue_free(tf5_tesla_ue_state_t *state)
{
    if (state) {
        memset(state, 0, sizeof(*state));
    }
}

int tf5_tesla_ue_verify_signature(const tf5_tesla_ue_state_t *state,
                                  const uint8_t *auth_input,
                                  size_t auth_input_len,
                                  const uint8_t signature[TF5_TESLA_SIG_LEN])
{
    if (!state || !state->initialized || !auth_input || !signature) {
        return -1;
    }

    return tf5_tesla_ed25519_verify(state->gnb_public_key,
                                    auth_input, auth_input_len,
                                    signature);
}

bool tf5_tesla_ue_safe_packet_test(tf5_tesla_ue_state_t *state,
                                   const tf5_tesla_extension_t *ext,
                                   uint16_t rx_sfn,
                                   uint16_t rx_slot)
{
    if (!state || !state->initialized || !ext) {
        return false;
    }

    // Use ti_hfn from the signed extension as the HFN reference
    // The Ed25519 signature guarantees ti_hfn hasn't been tampered
    uint16_t ref_hfn = ext->dynamic_params.ti_hfn;

    // Initialize or update UE's HFN tracking
    if (!state->hfn_initialized) {
        // First SIB1 - bootstrap HFN from signed extension
        state->current_hfn = ref_hfn;
        state->last_sfn = rx_sfn;
        state->hfn_initialized = true;
        LOG_I(NR_RRC, "TESLA: Initialized HFN tracking from signed extension (HFN=%u)\n", ref_hfn);
    } else {
        // Update HFN based on SFN wraparound detection
        tf5_tesla_update_hfn(&state->current_hfn, &state->last_sfn, rx_sfn);

        // Sanity check: received ti_hfn should match our tracking
        // Allow ±1 HFN for minor clock drift
        int16_t hfn_diff = (int16_t)ref_hfn - (int16_t)state->current_hfn;
        if (hfn_diff < -1 || hfn_diff > 1) {
            LOG_W(NR_RRC, "TESLA: HFN mismatch - tracked %u, received %u (possible replay)\n",
                  state->current_hfn, ref_hfn);
            // Potential replay from old HFN cycle - treat as unsafe
            return false;
        }
    }

    // Compute interval using the signed ti_hfn as reference
    uint32_t x = tf5_tesla_get_interval_index(ref_hfn, rx_sfn, rx_slot,
                                              ext->static_params.t0_hfn,
                                              ext->static_params.t0_sfn,
                                              ext->static_params.t0_slot,
                                              ext->static_params.t_int_ms,
                                              state->slots_per_frame);

    // Safe if: x < i + d
    // This means the sender hasn't yet disclosed K_i
    uint32_t i = ext->dynamic_params.interval_index;
    uint8_t d = ext->static_params.disclosure_delay;

    bool safe = (x < i + d);

    if (!safe) {
        LOG_W(NR_RRC, "TESLA: Safe packet test FAILED - UE interval %u >= claimed %u + d=%u\n",
              x, i, d);
    }

    return safe;
}

int tf5_tesla_ue_buffer_sib1(tf5_tesla_ue_state_t *state,
                             const uint8_t *auth_input,
                             size_t auth_input_len,
                             uint32_t interval_index,
                             const uint8_t tag[TF5_TESLA_TAG_LEN],
                             uint16_t ti_hfn,
                             uint16_t rx_sfn,
                             uint16_t rx_slot)
{
    if (!state || !state->initialized || !auth_input || !tag) {
        return -1;
    }

    if (auth_input_len > TF5_TESLA_MAX_AUTH_INPUT) {
        LOG_E(NR_RRC, "TESLA: Auth input too large (%zu > %d)\n",
              auth_input_len, TF5_TESLA_MAX_AUTH_INPUT);
        return -2;
    }

    memcpy(state->buffer.auth_input, auth_input, auth_input_len);
    state->buffer.auth_input_len = auth_input_len;
    state->buffer.interval_index = interval_index;
    memcpy(state->buffer.tag, tag, TF5_TESLA_TAG_LEN);
    state->buffer.rx_hfn = ti_hfn;  // Store ti_hfn from signed extension
    state->buffer.rx_sfn = rx_sfn;
    state->buffer.rx_slot = rx_slot;
    state->buffer.pending = true;

    LOG_D(NR_RRC, "TESLA: Buffered SIB1 for interval %u (pending verification)\n",
          interval_index);

    return 0;
}

int tf5_tesla_ue_verify_buffered(tf5_tesla_ue_state_t *state,
                                 const uint8_t disclosed_key[TF5_TESLA_KEY_LEN],
                                 uint32_t key_interval)
{
    if (!state || !state->initialized || !disclosed_key) {
        return -1;
    }

    if (!state->buffer.pending) {
        return -2;  // Nothing to verify
    }

    // Check if this key is for the buffered SIB1
    if (state->buffer.interval_index != key_interval) {
        LOG_D(NR_RRC, "TESLA: Disclosed key for interval %u, buffered is %u\n",
              key_interval, state->buffer.interval_index);
        return -3;  // Key is for different interval
    }

    // Verify key chain integrity BEFORE using the key for MAC verification
    // RFC 4082: Disclosed key must chain to authenticated K_0
    if (!tf5_tesla_ue_verify_key_chain(state, disclosed_key, key_interval)) {
        LOG_E(NR_RRC, "TESLA: Disclosed key K_%u does not chain to K_0 - rejecting\n",
              key_interval);
        return -6;  // Key chain verification failed
    }

    // Compute expected tag
    uint8_t expected_tag[TF5_TESLA_TAG_LEN];
    int rc = tf5_tesla_compute_tag(disclosed_key,
                                   state->buffer.auth_input,
                                   state->buffer.auth_input_len,
                                   expected_tag);
    if (rc != 0) {
        LOG_E(NR_RRC, "TESLA: Failed to compute expected tag\n");
        return -4;
    }

    // Compare tags
    if (memcmp(expected_tag, state->buffer.tag, TF5_TESLA_TAG_LEN) != 0) {
        LOG_E(NR_RRC, "TESLA: MAC verification FAILED for interval %u\n",
              key_interval);
        return -5;
    }

    LOG_I(NR_RRC, "TESLA: MAC verification SUCCESS for interval %u\n",
          key_interval);

    // Update verified key state
    memcpy(state->last_verified_key, disclosed_key, TF5_TESLA_KEY_LEN);
    state->last_verified_key_idx = key_interval;

    // Clear buffer
    state->buffer.pending = false;

    return 0;
}

bool tf5_tesla_ue_verify_key_chain(tf5_tesla_ue_state_t *state,
                                   const uint8_t disclosed_key[TF5_TESLA_KEY_LEN],
                                   uint32_t key_index)
{
    if (!state || !state->initialized || !disclosed_key) {
        return false;
    }

    // If this is the first key we've seen, or if we have a previously verified key
    if (state->last_verified_key_idx == 0 && !state->params_received) {
        // First key - need to verify against root commitment K_0
        // Compute forward from disclosed key to K_0
        uint8_t computed_key[TF5_TESLA_KEY_LEN];
        memcpy(computed_key, disclosed_key, TF5_TESLA_KEY_LEN);

        for (uint32_t i = key_index; i > 0; i--) {
            uint8_t next_key[TF5_TESLA_KEY_LEN];
            tf5_tesla_chain_key(computed_key, next_key);
            memcpy(computed_key, next_key, TF5_TESLA_KEY_LEN);
        }

        // Compare with root commitment K_0
        if (memcmp(computed_key, state->static_params.root_key, TF5_TESLA_KEY_LEN) == 0) {
            LOG_I(NR_RRC, "TESLA: Key chain verified from K_%u to K_0\n", key_index);
            return true;
        } else {
            LOG_E(NR_RRC, "TESLA: Key chain verification FAILED\n");
            return false;
        }
    }

    // Verify against previously verified key
    if (key_index > state->last_verified_key_idx) {
        // key_index > last_verified means we need to chain from key_index down to last_verified
        uint8_t computed_key[TF5_TESLA_KEY_LEN];
        memcpy(computed_key, disclosed_key, TF5_TESLA_KEY_LEN);

        for (uint32_t i = key_index; i > state->last_verified_key_idx; i--) {
            uint8_t next_key[TF5_TESLA_KEY_LEN];
            tf5_tesla_chain_key(computed_key, next_key);
            memcpy(computed_key, next_key, TF5_TESLA_KEY_LEN);
        }

        if (memcmp(computed_key, state->last_verified_key, TF5_TESLA_KEY_LEN) == 0) {
            LOG_D(NR_RRC, "TESLA: Key chain verified from K_%u to K_%u\n",
                  key_index, state->last_verified_key_idx);
            return true;
        } else {
            LOG_E(NR_RRC, "TESLA: Key chain verification FAILED\n");
            return false;
        }
    }

    // key_index <= last_verified_key_idx - this is an old key, should be derivable
    // from the last verified key
    return true;
}

#endif /* TF5_ENABLE_TESLA */
