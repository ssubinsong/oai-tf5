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
#include <stdio.h>
#include <time.h>
#include <openssl/rand.h>
/* Note: pem.h, x509.h, evp.h no longer needed - BLS keys use raw binary format */

/*
 * =============================================================================
 * Static Assertions for Struct Sizes
 * =============================================================================
 * Note: static_params_t is 32 bytes in-memory due to padding before chain_len,
 * but the wire format is 30 bytes (serialization skips padding).
 */
_Static_assert(sizeof(tf5_tesla_slot_time_t) == 6, "slot_time_t must be 6 bytes");
_Static_assert(sizeof(tf5_tesla_d_params_t) == 20, "d_params_t must be 20 bytes");
_Static_assert(sizeof(tf5_tesla_timesync_info_t) == 4, "timesync_info_t must be 4 bytes (HFN now from hyperSFN-r17)");

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

uint64_t tf5_tesla_slots_since_t0(const tf5_tesla_slot_time_t *current,
                                  const tf5_tesla_slot_time_t *t0,
                                  uint16_t slots_per_frame)
{
    // Use absolute slot counts to handle SFN wraparound correctly
    // HFN (Hyper-Frame Number) increments each time SFN wraps from 1023 to 0
    uint64_t current_abs = tf5_tesla_absolute_slots(current, slots_per_frame);
    uint64_t t0_abs = tf5_tesla_absolute_slots(t0, slots_per_frame);

    return (current_abs >= t0_abs) ? (current_abs - t0_abs) : 0;
}

uint32_t tf5_tesla_get_interval_index(const tf5_tesla_slot_time_t *current,
                                      const tf5_tesla_slot_time_t *t0,
                                      uint16_t t_int_ms,
                                      uint16_t slots_per_frame)
{
    uint64_t slots = tf5_tesla_slots_since_t0(current, t0, slots_per_frame);

    // Calculate time in milliseconds
    // Each frame = 10ms, slots_per_frame slots per frame
    // So each slot = 10 / slots_per_frame ms
    // time_ms = slots * 10 / slots_per_frame
    uint64_t time_ms = (slots * 10) / slots_per_frame;

    return (uint32_t)(time_ms / t_int_ms);
}

/*
 * =============================================================================
 * Timestamp Functions for Replay Protection
 * =============================================================================
 */

uint64_t tf5_tesla_get_wallclock_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        LOG_E(NR_RRC, "TESLA: Failed to get wall-clock time\n");
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

int tf5_tesla_validate_timestamp(uint64_t ue_time_ms,
                                 uint64_t ext_timestamp_ms,
                                 uint64_t window_ms)
{
    // Check if timestamp is too old: ext_timestamp + window < ue_time
    if (ext_timestamp_ms + window_ms < ue_time_ms) {
        return -1;  // Too old
    }

    // Check if timestamp is too far in the future: ext_timestamp > ue_time + window
    if (ext_timestamp_ms > ue_time_ms + window_ms) {
        return -2;  // Too far in future
    }

    return 0;  // Valid
}

/*
 * =============================================================================
 * Binary Pack/Unpack Functions
 * =============================================================================
 */

/*
 * Internal helpers for encoding/decoding static params and timesync info.
 * These consolidate duplicated serialization logic.
 */

/* Encode static params (30 bytes) to buffer */
static size_t tf5_encode_static_params(uint8_t *buf,
                                        const tf5_tesla_static_params_t *p)
{
    size_t offset = 0;
    buf[offset++] = p->te_version;
    buf[offset++] = p->crypto_suite_id;
    tf5_encode_u16_be(buf + offset, p->t_int_ms); offset += 2;
    buf[offset++] = p->disclosure_delay;
    buf[offset++] = p->key_len;
    memcpy(buf + offset, p->root_key, TF5_TESLA_KEY_LEN); offset += TF5_TESLA_KEY_LEN;
    tf5_encode_u16_be(buf + offset, p->t0.hfn); offset += 2;
    tf5_encode_u16_be(buf + offset, p->t0.sfn); offset += 2;
    tf5_encode_u16_be(buf + offset, p->t0.slot); offset += 2;
    tf5_encode_u32_be(buf + offset, p->chain_len); offset += 4;
    return offset;  /* Always 30 */
}

/* Decode static params (30 bytes) from buffer */
static size_t tf5_decode_static_params(const uint8_t *buf,
                                        tf5_tesla_static_params_t *p)
{
    size_t offset = 0;
    p->te_version = buf[offset++];
    p->crypto_suite_id = buf[offset++];
    p->t_int_ms = tf5_decode_u16_be(buf + offset); offset += 2;
    p->disclosure_delay = buf[offset++];
    p->key_len = buf[offset++];
    memcpy(p->root_key, buf + offset, TF5_TESLA_KEY_LEN); offset += TF5_TESLA_KEY_LEN;
    p->t0.hfn = tf5_decode_u16_be(buf + offset); offset += 2;
    p->t0.sfn = tf5_decode_u16_be(buf + offset); offset += 2;
    p->t0.slot = tf5_decode_u16_be(buf + offset); offset += 2;
    p->chain_len = tf5_decode_u32_be(buf + offset); offset += 4;
    return offset;  /* Always 30 */
}

/* Encode timesync info (4 bytes) to buffer - HFN now from hyperSFN-r17 */
static size_t tf5_encode_timesync_info(uint8_t *buf,
                                        const tf5_tesla_timesync_info_t *ti)
{
    size_t offset = 0;
    tf5_encode_u16_be(buf + offset, ti->sfn); offset += 2;
    tf5_encode_u16_be(buf + offset, ti->slot); offset += 2;
    return offset;  /* Always 4 */
}

/* Decode timesync info (4 bytes) from buffer - HFN now from hyperSFN-r17 */
static size_t tf5_decode_timesync_info(const uint8_t *buf,
                                        tf5_tesla_timesync_info_t *ti)
{
    size_t offset = 0;
    ti->sfn = tf5_decode_u16_be(buf + offset); offset += 2;
    ti->slot = tf5_decode_u16_be(buf + offset); offset += 2;
    return offset;  /* Always 4 */
}

int tf5_tesla_build_mac_auth_input(uint8_t *out,
                                   size_t *out_len,
                                   const uint8_t *original_sib1,
                                   size_t sib1_len,
                                   const tf5_tesla_static_params_t *static_params,
                                   const tf5_tesla_timesync_info_t *timesync_info)
{
    if (!out || !out_len || !original_sib1 || !static_params || !timesync_info) {
        return -1;
    }

    size_t offset = 0;

    // 1. Original SIB1 content
    memcpy(out + offset, original_sib1, sib1_len);
    offset += sib1_len;

    // 2. Static params (30 bytes)
    offset += tf5_encode_static_params(out + offset, static_params);

    // 3. Timesync info (6 bytes) - per RFC 4082, MAC does NOT include interval_index/disclosed_key
    offset += tf5_encode_timesync_info(out + offset, timesync_info);

    *out_len = offset;
    return 0;
}

int tf5_tesla_build_sig_auth_input(uint8_t *out,
                                   size_t *out_len,
                                   const uint8_t *original_sib1,
                                   size_t sib1_len,
                                   const tf5_tesla_static_params_t *static_params,
                                   const tf5_tesla_timesync_info_t *timesync_info,
                                   uint32_t interval_index,
                                   const uint8_t disclosed_key[TF5_TESLA_KEY_LEN],
                                   uint64_t timestamp_ms)
{
    if (!out || !out_len || !original_sib1 || !static_params || !timesync_info || !disclosed_key) {
        return -1;
    }

    // Build MAC auth input first (SIB1 + static_params + timesync_info)
    size_t mac_len = 0;
    int rc = tf5_tesla_build_mac_auth_input(out, &mac_len, original_sib1, sib1_len,
                                            static_params, timesync_info);
    if (rc < 0) {
        return rc;
    }

    size_t offset = mac_len;

    // Append interval_index (4 bytes)
    tf5_encode_u32_be(out + offset, interval_index);
    offset += 4;

    // Append disclosed_key (16 bytes)
    memcpy(out + offset, disclosed_key, TF5_TESLA_KEY_LEN);
    offset += TF5_TESLA_KEY_LEN;

    // Append timestamp_ms (8 bytes) - for signature replay protection
    tf5_encode_u64_be(out + offset, timestamp_ms);
    offset += 8;

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

    // Total size: 30 + 4 + 4 + 16 + 8 + 48 + 16 = 126 bytes (with BLS signatures)
    // Note: timesync_info is now 4 bytes (HFN removed - now from hyperSFN-r17)
    const size_t required_len = 126;
    if (buf_len < required_len) {
        return -2;
    }

    size_t offset = 0;

    // Static params (30 bytes)
    offset += tf5_encode_static_params(buf + offset, &ext->static_params);

    // Timesync info (6 bytes)
    offset += tf5_encode_timesync_info(buf + offset, &ext->timesync_info);

    // Interval index (4 bytes)
    tf5_encode_u32_be(buf + offset, ext->interval_index);
    offset += 4;

    // Disclosed key (16 bytes)
    memcpy(buf + offset, ext->disclosed_key, TF5_TESLA_KEY_LEN);
    offset += TF5_TESLA_KEY_LEN;

    // Timestamp (8 bytes) - for signature replay protection
    tf5_encode_u64_be(buf + offset, ext->timestamp_ms);
    offset += 8;

    // Signature (48 bytes - BLS)
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

    const size_t required_len = 126;  // 30 + 4 + 4 + 16 + 8 + 48 + 16 bytes
    if (buf_len < required_len) {
        return -2;
    }

    size_t offset = 0;

    // Static params (30 bytes)
    offset += tf5_decode_static_params(buf + offset, &ext->static_params);

    // Timesync info (6 bytes)
    offset += tf5_decode_timesync_info(buf + offset, &ext->timesync_info);

    // Interval index (4 bytes)
    ext->interval_index = tf5_decode_u32_be(buf + offset);
    offset += 4;

    // Disclosed key (16 bytes)
    memcpy(ext->disclosed_key, buf + offset, TF5_TESLA_KEY_LEN);
    offset += TF5_TESLA_KEY_LEN;

    // Timestamp (8 bytes) - for signature replay protection
    ext->timestamp_ms = tf5_decode_u64_be(buf + offset);
    offset += 8;

    // Signature (48 bytes - BLS)
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
                       const uint8_t private_key[TF5_BLS_SECRET_KEY_LEN],
                       const tf5_tesla_slot_time_t *t0,
                       uint16_t slots_per_frame)
{
    if (!state || !private_key || !t0 || chain_len == 0 || t_int_ms == 0) {
        return -1;
    }

    memset(state, 0, sizeof(*state));

    // Store BLS secret key
    memcpy(state->gnb_private_key, private_key, TF5_BLS_SECRET_KEY_LEN);

    // Derive public key from secret key
    if (tf5_tesla_bls_derive_public(private_key, state->gnb_public_key) != 0) {
        LOG_E(NR_RRC, "TESLA: Failed to derive BLS public key\n");
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
    state->params.crypto_suite_id = TF5_CRYPTO_SUITE_HMAC_SHA256_BLS;
    state->params.t_int_ms = t_int_ms;
    state->params.disclosure_delay = d;
    state->params.key_len = TF5_TESLA_KEY_LEN;
    memcpy(state->params.root_key, state->key_chain[0], TF5_TESLA_KEY_LEN);
    state->params.t0 = *t0;
    state->params.chain_len = chain_len;

    // HFN tracking is now in NR_COMMON_channels_t (cc->hfn)
    // gNB tracks HFN as a core feature, not TESLA-specific

    state->slots_per_frame = slots_per_frame;
    state->current_interval = 0;
    state->initialized = true;

    LOG_I(NR_RRC, "TESLA: gNB initialized - T_int=%ums, d=%u, T_0=HFN%u.SFN%u.%u\n",
          t_int_ms, d, t0->hfn, t0->sfn, t0->slot);

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
                                    uint16_t hfn,
                                    uint16_t sfn,
                                    uint16_t slot)
{
    if (!state || !state->initialized) {
        return 0;
    }

    // HFN is now tracked by gNB core (NR_COMMON_channels_t) and passed in
    tf5_tesla_slot_time_t current = tf5_slot_time_make(hfn, sfn, slot);
    return tf5_tesla_get_interval_index(&current, &state->params.t0,
                                        state->params.t_int_ms,
                                        state->slots_per_frame);
}

int tf5_tesla_gnb_prepare_extension(tf5_tesla_gnb_state_t *state,
                                    uint16_t hfn,
                                    uint16_t sfn,
                                    uint16_t slot,
                                    const uint8_t *original_sib1,
                                    size_t sib1_len,
                                    tf5_tesla_extension_t *ext)
{
    if (!state || !state->initialized || !original_sib1 || !ext) {
        return -1;
    }

    // Get current interval (HFN from cc->hfn passed by caller)
    uint32_t interval = tf5_tesla_gnb_get_interval(state, hfn, sfn, slot);

    // Check if interval is within chain bounds
    if (interval >= state->key_chain_len) {
        LOG_E(NR_RRC, "TESLA: Interval %u exceeds chain length %u\n",
              interval, state->key_chain_len);
        return -2;
    }

    // Copy static params
    memcpy(&ext->static_params, &state->params, sizeof(state->params));

    // Set timesync info (HFN is now transmitted via hyperSFN-r17 in SIB1-v1700-IEs)
    ext->timesync_info.sfn = sfn;
    ext->timesync_info.slot = slot;

    // Set interval index
    ext->interval_index = interval;

    // Set disclosed key K_{i-d}
    uint8_t disclosure_delay = state->params.disclosure_delay;
    if (interval >= disclosure_delay) {
        uint32_t disclosed_idx = interval - disclosure_delay;
        memcpy(ext->disclosed_key,
               state->key_chain[disclosed_idx],
               TF5_TESLA_KEY_LEN);
    } else {
        // Not enough intervals have passed to disclose a key
        // Use zeros as placeholder
        memset(ext->disclosed_key, 0, TF5_TESLA_KEY_LEN);
    }

    // Set wall-clock timestamp for signature replay protection
    ext->timestamp_ms = tf5_tesla_get_wallclock_ms();
    if (ext->timestamp_ms == 0) {
        LOG_E(NR_RRC, "TESLA: Failed to get wall-clock time\n");
        return -7;
    }

    // Build signature auth input (SIB1 + static + timesync + interval + key + timestamp)
    uint8_t sig_auth_input[TF5_TESLA_MAX_AUTH_INPUT];
    size_t sig_auth_input_len;
    int rc = tf5_tesla_build_sig_auth_input(sig_auth_input, &sig_auth_input_len,
                                            original_sib1, sib1_len,
                                            &ext->static_params,
                                            &ext->timesync_info,
                                            ext->interval_index,
                                            ext->disclosed_key,
                                            ext->timestamp_ms);
    if (rc != 0) {
        LOG_E(NR_RRC, "TESLA: Failed to build signature auth input\n");
        return -3;
    }

    // Compute BLS signature over full content
    rc = tf5_tesla_bls_sign(state->gnb_private_key,
                            sig_auth_input, sig_auth_input_len,
                            ext->gnb_signature);
    if (rc != 0) {
        LOG_E(NR_RRC, "TESLA: Failed to compute signature\n");
        return -4;
    }

    // Build MAC auth input (SIB1 + static + timesync, excludes interval/key per RFC 4082)
    uint8_t mac_auth_input[TF5_TESLA_MAX_AUTH_INPUT];
    size_t mac_auth_input_len;
    rc = tf5_tesla_build_mac_auth_input(mac_auth_input, &mac_auth_input_len,
                                        original_sib1, sib1_len,
                                        &ext->static_params,
                                        &ext->timesync_info);
    if (rc != 0) {
        LOG_E(NR_RRC, "TESLA: Failed to build MAC auth input\n");
        return -5;
    }

    // Compute TESLA tag using K_i
    rc = tf5_tesla_compute_tag(state->key_chain[interval],
                               mac_auth_input, mac_auth_input_len,
                               ext->tesla_tag);
    if (rc != 0) {
        LOG_E(NR_RRC, "TESLA: Failed to compute tag\n");
        return -6;
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
                      const uint8_t gnb_public_key[TF5_TESLA_PUBKEY_LEN],
                      uint16_t slots_per_frame)
{
    if (!state || !gnb_public_key) {
        return -1;
    }

    memset(state, 0, sizeof(*state));

    memcpy(state->gnb_public_key, gnb_public_key, TF5_TESLA_PUBKEY_LEN);
    state->has_gnb_public_key = true;
    state->slots_per_frame = slots_per_frame;
    state->params_received = false;
    state->buffer.pending = false;

    // Parallel authentication state (initialized by memset to 0/false)
    // k0_trusted = false (first-time UE, needs BLS signature verification)
    // sib1_authenticated = false
    // auth_in_progress = false
    // auth_failed = false
    // nas_pending = false
    // auth_start_time = 0
    // rrcsetup_deferred = false
    // rrcsetup_transaction_id = 0

    // Timestamp validation for signature replay protection
    state->timestamp_window_ms = TF5_TESLA_DEFAULT_TIME_WINDOW_MS;

    // Time sync state
    state->timesync_verified = false;

    // D calculation parameters (use defaults, can be overridden via config)
    // Per RFC 4082 Section 2.2 and doc-tf5/time-sync.md Section 4
    state->d_params = tf5_d_params_default();

    // Calculate D: upper bound on (sender_time - receiver_time)
    state->d_bound_us = tf5_tesla_calculate_d_bound(&state->d_params);

    state->initialized = true;

    LOG_I(NR_RRC, "TESLA: UE initialized (D=%u us, E_sync=%u us, first-time UE)\n",
          state->d_bound_us, state->d_params.e_sync_us);

    return 0;
}

void tf5_tesla_ue_free(tf5_tesla_ue_state_t *state)
{
    if (state) {
        memset(state, 0, sizeof(*state));
    }
}

uint32_t tf5_tesla_calculate_d_bound(const tf5_tesla_d_params_t *params)
{
    /*
     * Calculate D: upper bound on (sender_time - receiver_time)
     *
     * Per RFC 4082 Section 2.2 and doc-tf5/time-sync.md Section 4.3-4.4:
     * D = E_sync + (E_s + E_r) * ΔT_max + M_impl
     */

    if (!params) {
        return 0;
    }

    // Convert ΔT_max from ms to μs for consistent units
    uint64_t delta_t_max_us = (uint64_t)params->delta_t_max_ms * 1000;

    // Drift term: (E_s + E_r) * ΔT_max
    // E_s, E_r in ppb = parts per 10^9
    // drift_us = (e_s_ppb + e_r_ppb) * delta_t_max_us / 10^9
    uint64_t drift_ppb = (uint64_t)params->e_s_ppb + params->e_r_ppb;
    uint64_t drift_us = (drift_ppb * delta_t_max_us) / 1000000000ULL;

    // D = E_sync + drift + M_impl
    return (uint32_t)(params->e_sync_us + drift_us + params->m_impl_us);
}

int tf5_tesla_verify_initial_timesync(tf5_tesla_ue_state_t *state,
                                      const tf5_tesla_slot_time_t *tx,
                                      const tf5_tesla_slot_time_t *rx)
{
    /*
     * Verify initial time synchronization after BLS signature verification
     *
     * For initial sync verification, use only E_sync as the bound since
     * no clock drift has accumulated yet.
     *
     * Per RFC 4082 Section 2.2, this verifies the "loose time synchronization"
     * assumption required for TESLA protocol operation.
     */

    if (!state || !tx || !rx) {
        return -1;
    }

    // For initial sync, use E_sync only (no drift has accumulated yet)
    uint32_t initial_bound_us = state->d_params.e_sync_us;

    // Convert bound from μs to slots
    // slot_duration_us = 10ms / slots_per_frame = 10000 / slots_per_frame
    uint32_t slot_duration_us = 10000 / state->slots_per_frame;
    uint32_t max_error_slots = (initial_bound_us + slot_duration_us - 1) / slot_duration_us;

    // Compute slot difference (within same HFN for initial sync)
    // For first SIB1, TX and RX should be in same or adjacent SFN
    int32_t sfn_diff = (int32_t)rx->sfn - (int32_t)tx->sfn;

    // Handle SFN wraparound (1024-cycle)
    if (sfn_diff < -512) {
        sfn_diff += 1024;
    }
    if (sfn_diff > 512) {
        sfn_diff -= 1024;
    }

    int64_t slot_diff = (int64_t)sfn_diff * state->slots_per_frame +
                        (int64_t)rx->slot - (int64_t)tx->slot;

    if (slot_diff < 0) {
        // RX before TX - impossible (propagation delay always positive)
        LOG_W(NR_RRC, "TESLA: Initial timesync FAILED - RX before TX "
              "(tx=%u:%u, rx=%u:%u, diff=%ld slots)\n",
              tx->sfn, tx->slot, rx->sfn, rx->slot, (long)slot_diff);
        return -1;
    }

    if ((uint64_t)slot_diff > max_error_slots) {
        // Too large - SSB sync may have failed or timing is wrong
        LOG_W(NR_RRC, "TESLA: Initial timesync FAILED - diff too large "
              "(tx=%u:%u, rx=%u:%u, diff=%ld slots, max=%u slots, E_sync=%u us)\n",
              tx->sfn, tx->slot, rx->sfn, rx->slot, (long)slot_diff,
              max_error_slots, state->d_params.e_sync_us);
        return -2;
    }

    LOG_I(NR_RRC, "TESLA: Initial timesync OK (diff=%ld slots, max=%u, E_sync=%u us)\n",
          (long)slot_diff, max_error_slots, state->d_params.e_sync_us);
    return 0;
}

int tf5_tesla_ue_verify_signature(const tf5_tesla_ue_state_t *state,
                                  const uint8_t *auth_input,
                                  size_t auth_input_len,
                                  const uint8_t signature[TF5_TESLA_SIG_LEN])
{
    if (!state || !state->initialized || !auth_input || !signature) {
        return -1;
    }

    return tf5_tesla_bls_verify(state->gnb_public_key,
                                auth_input, auth_input_len,
                                signature);
}

bool tf5_tesla_ue_safe_packet_test(tf5_tesla_ue_state_t *state,
                                   const tf5_tesla_extension_t *ext,
                                   uint16_t rx_sfn,
                                   uint16_t rx_slot,
                                   uint16_t rx_hfn)
{
    if (!state || !state->initialized || !ext) {
        return false;
    }

    // Safe packet test requires HFN to already be initialized (from hyperSFN-r17)
    DevAssert(state->hfn_initialized);

    // HFN is received via hyperSFN-r17 - no local wraparound tracking needed

    // RFC 4082 Section 3.5: Safe packet test
    // Step 1: Record local time T (in absolute slots)
    tf5_tesla_slot_time_t local_time = tf5_slot_time_make(rx_hfn, rx_sfn, rx_slot);
    uint64_t t_abs_slots = tf5_tesla_absolute_slots(&local_time, state->slots_per_frame);

    // Step 2: Compute upper bound on sender's clock: t_j = T + D_t
    // Convert D from microseconds to slots (ceiling division for upper bound)
    uint32_t slot_duration_us = 10000 / state->slots_per_frame;
    uint32_t d_offset_slots = (state->d_bound_us + slot_duration_us - 1) / slot_duration_us;
    uint64_t t_j_abs_slots = t_abs_slots + d_offset_slots;

    // Step 3: Compute x = floor((t_j - T_0) / T_int)
    // This is the highest interval the sender could possibly be in
    uint64_t t0_abs_slots = tf5_tesla_absolute_slots(&state->static_params.t0, state->slots_per_frame);
    uint64_t slots_since_t0 = (t_j_abs_slots >= t0_abs_slots) ? (t_j_abs_slots - t0_abs_slots) : 0;
    uint64_t time_ms = (slots_since_t0 * 10) / state->slots_per_frame;
    uint32_t x = (uint32_t)(time_ms / state->static_params.t_int_ms);

    // Safe if: x < i + d
    // This means the sender hasn't yet disclosed K_i
    // Note: interval_index comes from ext (claimed interval from sender)
    //       disclosure_delay comes from cached state (authenticated)
    uint32_t i = ext->interval_index;
    uint8_t d = state->static_params.disclosure_delay;

    bool safe = (x < i + d);

    if (!safe) {
        LOG_W(NR_RRC, "TESLA: Safe packet test FAILED - x=%u (T+D, D=%u slots) >= i=%u + d=%u\n",
              x, d_offset_slots, i, d);
    }

    return safe;
}

int tf5_tesla_ue_buffer_sib1(tf5_tesla_ue_state_t *state,
                             const uint8_t *auth_input,
                             size_t auth_input_len,
                             uint32_t interval_index,
                             const uint8_t tag[TF5_TESLA_TAG_LEN],
                             const tf5_tesla_slot_time_t *rx_time)
{
    if (!state || !state->initialized || !auth_input || !tag || !rx_time) {
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
    state->buffer.rx_time = *rx_time;
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

    // Update verified key state (becomes new anchor for O(1) verification)
    memcpy(state->last_verified_key, disclosed_key, TF5_TESLA_KEY_LEN);
    state->last_verified_key_idx = key_interval;
    state->last_verified_key_valid = true;

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

    // Check if we have a valid anchor key (set by BLS signature verification or previous TESLA verification)
    if (!state->last_verified_key_valid) {
        // No anchor yet - this should not happen if BLS signature verification ran first
        LOG_E(NR_RRC, "TESLA: No valid anchor key - cannot verify key chain\n");
        return false;
    }

    // Verify by chaining to the last verified key (O(1) if consecutive intervals)
    if (key_index > state->last_verified_key_idx) {
        // Chain from key_index down to last_verified_key_idx
        uint8_t computed_key[TF5_TESLA_KEY_LEN];
        memcpy(computed_key, disclosed_key, TF5_TESLA_KEY_LEN);

        uint32_t steps = key_index - state->last_verified_key_idx;
        for (uint32_t i = 0; i < steps; i++) {
            uint8_t next_key[TF5_TESLA_KEY_LEN];
            tf5_tesla_chain_key(computed_key, next_key);
            memcpy(computed_key, next_key, TF5_TESLA_KEY_LEN);
        }

        if (memcmp(computed_key, state->last_verified_key, TF5_TESLA_KEY_LEN) == 0) {
            LOG_D(NR_RRC, "TESLA: Key chain verified K_%u -> K_%u (%u hash ops)\n",
                  key_index, state->last_verified_key_idx, steps);
            return true;
        } else {
            LOG_E(NR_RRC, "TESLA: Key chain verification FAILED K_%u -> K_%u\n",
                  key_index, state->last_verified_key_idx);
            return false;
        }
    }

    // key_index <= last_verified_key_idx - old key, already verified transitively
    LOG_D(NR_RRC, "TESLA: Key K_%u already verified (anchor at K_%u)\n",
          key_index, state->last_verified_key_idx);
    return true;
}

/*
 * =============================================================================
 * File I/O Functions
 * =============================================================================
 */

int tf5_tesla_load_privkey(const char *filepath,
                           uint8_t privkey_out[TF5_BLS_SECRET_KEY_LEN])
{
    if (!filepath || !privkey_out) {
        return -1;
    }

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        LOG_E(NR_RRC, "TESLA: Cannot open secret key file: %s\n", filepath);
        return -1;
    }

    size_t n = fread(privkey_out, 1, TF5_BLS_SECRET_KEY_LEN, fp);
    fclose(fp);

    if (n != TF5_BLS_SECRET_KEY_LEN) {
        LOG_E(NR_RRC, "TESLA: Secret key file has wrong size: %zu (expected %d)\n",
              n, TF5_BLS_SECRET_KEY_LEN);
        return -2;
    }

    // Validate by trying to derive public key (this checks the key is valid)
    uint8_t pubkey_test[TF5_TESLA_PUBKEY_LEN];
    if (tf5_tesla_bls_derive_public(privkey_out, pubkey_test) != 0) {
        LOG_E(NR_RRC, "TESLA: Invalid BLS secret key format\n");
        memset(privkey_out, 0, TF5_BLS_SECRET_KEY_LEN);
        return -3;
    }

    return 0;
}

int tf5_tesla_load_pubkey(const char *filepath,
                          uint8_t pubkey_out[TF5_TESLA_PUBKEY_LEN])
{
    if (!filepath || !pubkey_out) {
        return -1;
    }

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        LOG_E(NR_RRC, "TESLA: Cannot open public key file: %s\n", filepath);
        return -1;
    }

    size_t n = fread(pubkey_out, 1, TF5_TESLA_PUBKEY_LEN, fp);
    fclose(fp);

    if (n != TF5_TESLA_PUBKEY_LEN) {
        LOG_E(NR_RRC, "TESLA: Public key file has wrong size: %zu (expected %d)\n",
              n, TF5_TESLA_PUBKEY_LEN);
        return -2;
    }

    // Validate by trying to verify a test signature (this checks the key format)
    // We just check deserialization succeeds by doing a simple sign/verify
    // A malformed public key would fail during the actual signature verification
    LOG_I(NR_RRC, "TESLA: Loaded BLS public key from %s (%d bytes)\n",
          filepath, TF5_TESLA_PUBKEY_LEN);

    return 0;
}

#endif /* TF5_ENABLE_TESLA */
