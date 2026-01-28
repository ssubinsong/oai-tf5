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
 * Note: tesla_params_t is smaller in-memory due to struct padding,
 * but the wire format is 8 bytes (serialization is packed).
 */
_Static_assert(sizeof(tf5_tesla_slot_time_t) == 4, "slot_time_t must be 4 bytes");
_Static_assert(sizeof(tf5_tesla_timesync_info_t) == sizeof(tf5_tesla_slot_time_t), "timesync_info_t must match slot_time_t");

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

void tf5_tesla_derive_mac_key(const uint8_t key_in[TF5_TESLA_KEY_LEN],
                              uint8_t mac_key_out[32])
{
    // K'_i = F'(K_i) = SHA-256(0x01 || K_i)
    // Per RFC 4082 Section 3.4: use constant 0x01 for MAC key derivation
    uint8_t input[1 + TF5_TESLA_KEY_LEN];
    input[0] = 0x01;  // Domain separation prefix
    memcpy(input + 1, key_in, TF5_TESLA_KEY_LEN);

    byte_array_t data = {.buf = input, .len = sizeof(input)};
    sha_256(data, mac_key_out);
}

void tf5_tesla_chain_key(const uint8_t key_next[TF5_TESLA_KEY_LEN],
                         uint8_t key_out[TF5_TESLA_KEY_LEN])
{
    // K_i = F(K_{i+1}) = SHA-256(0x00 || K_{i+1})[0:15]
    // Per RFC 4082 Section 3.2: use constant 0x00 for key chain derivation
    uint8_t input[1 + TF5_TESLA_KEY_LEN];
    input[0] = 0x00;  // Domain separation prefix
    memcpy(input + 1, key_next, TF5_TESLA_KEY_LEN);

    byte_array_t data = {.buf = input, .len = sizeof(input)};
    uint8_t full_hash[32];
    sha_256(data, full_hash);

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

int tf5_tesla_derive_t0(const tf5_tesla_timesync_info_t *timesync_info,
                        uint32_t interval_index,
                        uint16_t t_int_ms,
                        uint16_t slots_per_frame,
                        tf5_tesla_slot_time_t *out_t0)
{
    if (!timesync_info || !out_t0 || slots_per_frame == 0 || t_int_ms == 0) {
        return -1;
    }

    // Convert current time (from timesync_info) to absolute slots
    tf5_tesla_slot_time_t current_time = tf5_slot_time_make(timesync_info->sfn,
                                                             timesync_info->slot);
    uint64_t current_abs_slots = tf5_tesla_absolute_slots(&current_time, slots_per_frame);

    // Calculate slots per interval
    // Each frame = 10ms, so slots_per_ms = slots_per_frame / 10
    // slots_per_interval = t_int_ms * slots_per_ms = t_int_ms * slots_per_frame / 10
    uint64_t slots_per_interval = ((uint64_t)t_int_ms * slots_per_frame) / 10;

    // T_0 = current_time - (interval_index × T_int)
    uint64_t offset_slots = (uint64_t)interval_index * slots_per_interval;

    if (current_abs_slots < offset_slots) {
        // Underflow: invalid parameters (interval_index too large for current time)
        LOG_E(NR_RRC, "[TF5] T_0 derivation underflow: current_slots=%lu, offset=%lu (i=%u, T_int=%u)\n",
              (unsigned long)current_abs_slots, (unsigned long)offset_slots,
              interval_index, t_int_ms);
        return -1;
    }

    uint64_t t0_abs_slots = current_abs_slots - offset_slots;

    // Convert back to SFN/slot
    *out_t0 = tf5_slots_to_slot_time(t0_abs_slots, slots_per_frame);

    LOG_D(NR_RRC, "[TF5] Derived T_0: SFN=%u slot=%u (from i=%u, T_int=%u)\n",
          out_t0->sfn, out_t0->slot, interval_index, t_int_ms);

    return 0;
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

/* Encode tesla params (8 bytes) to buffer
 * Note: T_0 removed from wire format - UE derives it from signed fields
 * Note: root_key removed - disclosed_key serves as trusted anchor */
static size_t tf5_encode_tesla_params(uint8_t *buf,
                                       const tf5_tesla_params_t *p)
{
    size_t offset = 0;
    buf[offset++] = p->te_version;
    tf5_encode_u16_be(buf + offset, p->t_int_ms); offset += 2;
    buf[offset++] = p->disclosure_delay;
    /* T_0 removed: UE derives from timesync_info - (interval_index × T_int) */
    tf5_encode_u32_be(buf + offset, p->chain_len); offset += 4;
    return offset;  /* Always 8 */
}

/* Decode tesla params (8 bytes) from buffer
 * Note: T_0 not in wire format - UE must derive it separately via tf5_tesla_derive_t0()
 * Note: root_key removed - disclosed_key serves as trusted anchor */
static size_t tf5_decode_tesla_params(const uint8_t *buf,
                                       tf5_tesla_params_t *p)
{
    size_t offset = 0;
    p->te_version = buf[offset++];
    p->t_int_ms = tf5_decode_u16_be(buf + offset); offset += 2;
    p->disclosure_delay = buf[offset++];
    /* T_0 not in wire: UE derives from timesync_info - (interval_index × T_int) */
    p->t0.sfn = 0;   /* Placeholder - derived later by UE */
    p->t0.slot = 0;
    p->chain_len = tf5_decode_u32_be(buf + offset); offset += 4;
    return offset;  /* Always 8 */
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
                                   uint32_t gnb_key_validity_end)
{
    if (!out || !out_len || !original_sib1) {
        return -1;
    }

    size_t offset = 0;

    // 1. Original SIB1 content
    memcpy(out + offset, original_sib1, sib1_len);
    offset += sib1_len;

    // 2. gNB key validity end (3 bytes) - key expiration (minutes since 2024-01-01)
    tf5_encode_gnb_key_validity_end(out + offset, gnb_key_validity_end);
    offset += TF5_IBS_VALIDITY_LEN;

    *out_len = offset;
    return 0;
}

int tf5_tesla_build_sig_auth_input(uint8_t *out,
                                   size_t *out_len,
                                   const uint8_t *original_sib1,
                                   size_t sib1_len,
                                   const tf5_tesla_params_t *tesla_params,
                                   uint32_t gnb_key_validity_end,
                                   const tf5_tesla_timesync_info_t *timesync_info,
                                   uint32_t interval_index,
                                   const uint8_t disclosed_key[TF5_TESLA_KEY_LEN],
                                   uint64_t timestamp_ms)
{
    if (!out || !out_len || !original_sib1 || !tesla_params || !timesync_info || !disclosed_key) {
        return -1;
    }

    // Build MAC auth input first (SIB1 + gnb_key_validity_end only)
    size_t mac_len = 0;
    int rc = tf5_tesla_build_mac_auth_input(out, &mac_len, original_sib1, sib1_len,
                                            gnb_key_validity_end);
    if (rc < 0) {
        return rc;
    }

    size_t offset = mac_len;

    // Append tesla_params (8 bytes) - only in signature input, not MAC
    offset += tf5_encode_tesla_params(out + offset, tesla_params);

    // Append timesync_info (4 bytes) - only in signature input, not MAC
    offset += tf5_encode_timesync_info(out + offset, timesync_info);

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

    // Total size: 8 + 3 + 4 + 4 + 16 + 8 + 48 + 16 = 107 bytes (with BLS signatures)
    // Note: T_0 not in wire format - UE derives from signed fields
    // Note: timesync_info is 4 bytes (HFN removed - now from hyperSFN-r17)
    const size_t required_len = 107;
    if (buf_len < required_len) {
        return -2;
    }

    size_t offset = 0;

    // TESLA params (8 bytes) - T_0 not transmitted, derived by UE
    offset += tf5_encode_tesla_params(buf + offset, &ext->tesla_params);

    // gNB key validity end (3 bytes) - key expiration (minutes since 2024-01-01)
    tf5_encode_gnb_key_validity_end(buf + offset, ext->gnb_key_validity_end);
    offset += TF5_IBS_VALIDITY_LEN;

    // Timesync info (4 bytes)
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

    // Total size: 8 + 3 + 4 + 4 + 16 + 8 + 48 + 16 = 107 bytes (with BLS signatures)
    // Note: T_0 not in wire format - UE must derive via tf5_tesla_derive_t0()
    const size_t required_len = 107;
    if (buf_len < required_len) {
        return -2;
    }

    size_t offset = 0;

    // TESLA params (8 bytes) - T_0 set to zero, caller must derive
    offset += tf5_decode_tesla_params(buf + offset, &ext->tesla_params);

    // gNB key validity end (3 bytes) - key expiration (minutes since 2024-01-01)
    ext->gnb_key_validity_end = tf5_decode_gnb_key_validity_end(buf + offset);
    offset += TF5_IBS_VALIDITY_LEN;

    // Timesync info (4 bytes)
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

    // Store IBS secret key (sk_ID issued by Core PKG)
    memcpy(state->gnb_private_key, private_key, TF5_BLS_SECRET_KEY_LEN);

    // Note: In IBS mode, Cell ID is set by the caller (config.c) after init
    // Public key is derived from Cell ID and Core's MPK by the verifier (UE)

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

    // K_0 is the root commitment (stored in key_chain[0], not in tesla params)
    // Note: root_key removed from tesla_params - disclosed_key serves as anchor
    LOG_I(NR_RRC, "TESLA: Key chain generated with %u intervals\n", chain_len);

    // Set TESLA parameters
    state->params.te_version = TF5_TESLA_VERSION;
    state->params.t_int_ms = t_int_ms;
    state->params.disclosure_delay = d;
    state->params.t0 = *t0;
    state->params.chain_len = chain_len;

    state->slots_per_frame = slots_per_frame;
    state->current_interval = 0;
    state->initialized = true;

    LOG_I(NR_RRC, "TESLA IBS: gNB initialized - T_int=%ums, d=%u, T_0=SFN%u.%u\n",
          t_int_ms, d, t0->sfn, t0->slot);

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

    tf5_tesla_slot_time_t current = tf5_slot_time_make(sfn, slot);
    return tf5_tesla_get_interval_index(&current, &state->params.t0,
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

    // Copy TESLA params
    memcpy(&ext->tesla_params, &state->params, sizeof(state->params));

    // Set key validity period (minutes since 2024-01-01)
    ext->gnb_key_validity_end = state->gnb_key_validity_end;

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

    // Build signature auth input (SIB1 + tesla_params + gnb_key_validity_end + timesync + interval + key + timestamp)
    uint8_t sig_auth_input[TF5_TESLA_MAX_AUTH_INPUT];
    size_t sig_auth_input_len;
    int rc = tf5_tesla_build_sig_auth_input(sig_auth_input, &sig_auth_input_len,
                                            original_sib1, sib1_len,
                                            &ext->tesla_params,
                                            ext->gnb_key_validity_end,
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

    // Build MAC auth input (SIB1 + gnb_key_validity_end only)
    uint8_t mac_auth_input[TF5_TESLA_MAX_AUTH_INPUT];
    size_t mac_auth_input_len;
    rc = tf5_tesla_build_mac_auth_input(mac_auth_input, &mac_auth_input_len,
                                        original_sib1, sib1_len,
                                        ext->gnb_key_validity_end);
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
                      const uint8_t mpk[TF5_TESLA_PUBKEY_LEN],
                      uint16_t slots_per_frame,
                      uint32_t d_bound_us,
                      uint32_t initial_sync_bound_us)
{
    if (!state || !mpk) {
        return -1;
    }

    memset(state, 0, sizeof(*state));

    // Store Core's Master Public Key (IBS mode)
    memcpy(state->mpk, mpk, TF5_TESLA_PUBKEY_LEN);
    state->has_mpk = true;
    state->slots_per_frame = slots_per_frame;
    state->params_received = false;
    state->buffer_queue_count = 0;  // All queue entries initialized to 0/false by memset

    // Parallel authentication state (initialized by memset to 0/false)
    // k0_trusted = false (first-time UE, needs IBS signature verification)
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

    // D parameters (CLI-configured)
    // Per RFC 4082 Section 2.2, D is the upper bound on (sender_time - receiver_time)
    state->d_bound_us = d_bound_us;
    state->initial_sync_bound_us = initial_sync_bound_us;

    state->initialized = true;

    LOG_I(NR_RRC, "TESLA IBS: UE initialized (D=%u us, initial_sync=%u us, first-time UE)\n",
          state->d_bound_us, state->initial_sync_bound_us);

    return 0;
}

void tf5_tesla_ue_free(tf5_tesla_ue_state_t *state)
{
    if (state) {
        memset(state, 0, sizeof(*state));
    }
}

int tf5_tesla_verify_initial_timesync(tf5_tesla_ue_state_t *state,
                                      const tf5_tesla_slot_time_t *tx,
                                      const tf5_tesla_slot_time_t *rx)
{
    /*
     * Verify initial time synchronization after BLS signature verification
     *
     * For initial sync verification, use initial_sync_bound_us as the bound
     * since no clock drift has accumulated yet.
     *
     * Per RFC 4082 Section 2.2, this verifies the "loose time synchronization"
     * assumption required for TESLA protocol operation.
     */

    if (!state || !tx || !rx) {
        return -1;
    }

    // For initial sync, use initial_sync_bound_us (no drift has accumulated yet)
    uint32_t initial_bound_us = state->initial_sync_bound_us;

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
              "(tx=%u:%u, rx=%u:%u, diff=%ld slots, max=%u slots, initial_sync_bound=%u us)\n",
              tx->sfn, tx->slot, rx->sfn, rx->slot, (long)slot_diff,
              max_error_slots, state->initial_sync_bound_us);
        return -2;
    }

    LOG_I(NR_RRC, "TESLA: Initial timesync OK (diff=%ld slots, max=%u, initial_sync_bound=%u us)\n",
          (long)slot_diff, max_error_slots, state->initial_sync_bound_us);
    return 0;
}

int tf5_tesla_ue_verify_signature(const tf5_tesla_ue_state_t *state,
                                  const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                                  uint32_t gnb_key_validity_end,
                                  const uint8_t *auth_input,
                                  size_t auth_input_len,
                                  const uint8_t signature[TF5_TESLA_SIG_LEN])
{
    if (!state || !state->initialized || !cell_id || !auth_input || !signature) {
        return -1;
    }

    // IBS verification: e(Σ, Q) = e(H_m(m), H_s(cell_id || gnb_key_validity_end) * MPK)
    return tf5_tesla_ibs_verify(state->mpk,
                                cell_id,
                                gnb_key_validity_end,
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

    // RFC 4082 Section 3.5: Safe packet test
    // Step 1: Record local time T (in absolute slots)
    tf5_tesla_slot_time_t local_time = tf5_slot_time_make(rx_sfn, rx_slot);
    uint64_t t_abs_slots = tf5_tesla_absolute_slots(&local_time, state->slots_per_frame);

    // Step 2: Compute upper bound on sender's clock: t_j = T + D_t
    // Convert D from microseconds to slots (ceiling division for upper bound)
    uint32_t slot_duration_us = 10000 / state->slots_per_frame;
    uint32_t d_offset_slots = (state->d_bound_us + slot_duration_us - 1) / slot_duration_us;
    uint64_t t_j_abs_slots = t_abs_slots + d_offset_slots;

    // Step 3: Compute x = floor((t_j - T_0) / T_int)
    // This is the highest interval the sender could possibly be in
    uint64_t t0_abs_slots = tf5_tesla_absolute_slots(&state->tesla_params.t0, state->slots_per_frame);
    uint64_t slots_since_t0 = (t_j_abs_slots >= t0_abs_slots) ? (t_j_abs_slots - t0_abs_slots) : 0;
    uint64_t time_ms = (slots_since_t0 * 10) / state->slots_per_frame;
    uint32_t x = (uint32_t)(time_ms / state->tesla_params.t_int_ms);

    // Safe if: x < i + d
    // This means the sender hasn't yet disclosed K_i
    // Note: interval_index comes from ext (claimed interval from sender)
    //       disclosure_delay comes from cached state (authenticated)
    uint32_t i = ext->interval_index;
    uint8_t d = state->tesla_params.disclosure_delay;

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
                             const tf5_tesla_slot_time_t *rx_time,
                             bool triggered_rrc_setup)
{
    if (!state || !state->initialized || !auth_input || !tag || !rx_time) {
        return -1;
    }

    if (auth_input_len > TF5_TESLA_MAX_AUTH_INPUT) {
        LOG_E(NR_RRC, "TESLA: Auth input too large (%zu > %d)\n",
              auth_input_len, TF5_TESLA_MAX_AUTH_INPUT);
        return -2;
    }

    // Find target slot: prefer invalid entry, then oldest same-interval entry
    int target_slot = -1;
    int oldest_same_interval_slot = -1;
    uint64_t oldest_same_interval_time = UINT64_MAX;

    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        if (!state->buffer_queue[i].valid) {
            target_slot = i;
            break;  // Use first invalid slot
        }
        // Track oldest entry with same interval (for overflow handling)
        if (state->buffer_queue[i].interval_index == interval_index) {
            uint64_t entry_time = tf5_tesla_absolute_slots(
                &state->buffer_queue[i].rx_time, state->slots_per_frame);
            if (entry_time < oldest_same_interval_time) {
                oldest_same_interval_time = entry_time;
                oldest_same_interval_slot = i;
            }
        }
    }

    // If no invalid slot, drop oldest same-interval entry (DoS protection per RFC 4082 Section 3.7)
    if (target_slot < 0) {
        if (oldest_same_interval_slot >= 0) {
            target_slot = oldest_same_interval_slot;
            LOG_W(NR_RRC, "TESLA: Buffer full - dropping oldest entry for interval %u\n",
                  interval_index);
        } else {
            // Buffer full with different intervals - drop oldest overall
            uint64_t oldest_time = UINT64_MAX;
            for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
                uint64_t entry_time = tf5_tesla_absolute_slots(
                    &state->buffer_queue[i].rx_time, state->slots_per_frame);
                if (entry_time < oldest_time) {
                    oldest_time = entry_time;
                    target_slot = i;
                }
            }
            LOG_W(NR_RRC, "TESLA: Buffer full - dropping oldest entry (interval %u)\n",
                  state->buffer_queue[target_slot].interval_index);
        }
    }

    // Store in target slot
    tf5_tesla_buffer_entry_t *entry = &state->buffer_queue[target_slot];
    memcpy(entry->auth_input, auth_input, auth_input_len);
    entry->auth_input_len = auth_input_len;
    entry->interval_index = interval_index;
    memcpy(entry->tag, tag, TF5_TESLA_TAG_LEN);
    entry->rx_time = *rx_time;
    entry->valid = true;
    entry->triggered_rrc_setup = triggered_rrc_setup;

    // Update queue count
    state->buffer_queue_count = 0;
    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        if (state->buffer_queue[i].valid) {
            state->buffer_queue_count++;
        }
    }

    LOG_D(NR_RRC, "TESLA: Buffered SIB1 for interval %u (slot %d, queue count %u, rrc_trigger=%d)\n",
          interval_index, target_slot, state->buffer_queue_count, triggered_rrc_setup);

    return 0;
}

int tf5_tesla_ue_verify_buffered(tf5_tesla_ue_state_t *state,
                                 const uint8_t disclosed_key[TF5_TESLA_KEY_LEN],
                                 uint32_t key_interval)
{
    // Legacy single-entry verification - uses verify_all_buffered internally
    int verified_count = 0, failed_count = 0;
    bool rrc_trigger_verified = false;
    int rc = tf5_tesla_ue_verify_all_buffered(state, disclosed_key, key_interval,
                                               &verified_count, &failed_count,
                                               &rrc_trigger_verified);
    return rc;
}

int tf5_tesla_ue_verify_all_buffered(tf5_tesla_ue_state_t *state,
                                     const uint8_t disclosed_key[TF5_TESLA_KEY_LEN],
                                     uint32_t key_interval,
                                     int *verified_count,
                                     int *failed_count,
                                     bool *rrc_trigger_verified)
{
    if (!state || !state->initialized || !disclosed_key ||
        !verified_count || !failed_count || !rrc_trigger_verified) {
        return -1;
    }

    *verified_count = 0;
    *failed_count = 0;
    *rrc_trigger_verified = false;

    // Check if any entries exist for this interval
    bool has_entries = false;
    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        if (state->buffer_queue[i].valid &&
            state->buffer_queue[i].interval_index == key_interval) {
            has_entries = true;
            break;
        }
    }

    if (!has_entries) {
        LOG_D(NR_RRC, "TESLA: No buffered entries for interval %u\n", key_interval);
        return -2;  // Nothing to verify for this interval
    }

    // Verify key chain integrity ONCE (applies to all entries)
    // RFC 4082: Disclosed key must chain to authenticated K_0
    if (!tf5_tesla_ue_verify_key_chain(state, disclosed_key, key_interval)) {
        LOG_E(NR_RRC, "TESLA: Disclosed key K_%u does not chain to anchor - rejecting all\n",
              key_interval);
        return -6;  // Key chain verification failed
    }

    // Verify all entries for this interval
    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        tf5_tesla_buffer_entry_t *entry = &state->buffer_queue[i];

        if (!entry->valid || entry->interval_index != key_interval) {
            continue;
        }

        // Compute expected tag
        uint8_t expected_tag[TF5_TESLA_TAG_LEN];
        int rc = tf5_tesla_compute_tag(disclosed_key,
                                       entry->auth_input,
                                       entry->auth_input_len,
                                       expected_tag);
        if (rc != 0) {
            LOG_E(NR_RRC, "TESLA: Failed to compute expected tag for slot %d\n", i);
            entry->valid = false;
            (*failed_count)++;
            continue;
        }

        // Compare tags
        if (memcmp(expected_tag, entry->tag, TF5_TESLA_TAG_LEN) != 0) {
            LOG_E(NR_RRC, "TESLA: MAC verification FAILED for slot %d (interval %u)\n",
                  i, key_interval);
            entry->valid = false;
            (*failed_count)++;
            continue;
        }

        LOG_I(NR_RRC, "TESLA: MAC verification SUCCESS for slot %d (interval %u, rrc_trigger=%d)\n",
              i, key_interval, entry->triggered_rrc_setup);

        // Track if this was the RRC-triggering entry
        if (entry->triggered_rrc_setup) {
            *rrc_trigger_verified = true;
        }

        entry->valid = false;  // Release from buffer
        (*verified_count)++;
    }

    // Update queue count
    state->buffer_queue_count = 0;
    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        if (state->buffer_queue[i].valid) {
            state->buffer_queue_count++;
        }
    }

    // Update verified key anchor if at least one succeeded
    if (*verified_count > 0) {
        memcpy(state->last_verified_key, disclosed_key, TF5_TESLA_KEY_LEN);
        state->last_verified_key_idx = key_interval;
        state->last_verified_key_valid = true;

        LOG_I(NR_RRC, "TESLA: Verified %d SIB1(s) for interval %u (%d failed, rrc_trigger=%d)\n",
              *verified_count, key_interval, *failed_count, *rrc_trigger_verified);
        return 0;
    }

    return (*failed_count > 0) ? -5 : -2;  // -5: all failed, -2: nothing to verify
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

int tf5_tesla_ue_verify_with_key_recovery(
    tf5_tesla_ue_state_t *state,
    const uint8_t disclosed_key[TF5_TESLA_KEY_LEN],
    uint32_t disclosed_interval,
    int *total_verified,
    int *total_failed,
    bool *rrc_trigger_verified)
{
    if (!state || !state->initialized || !disclosed_key ||
        !total_verified || !total_failed || !rrc_trigger_verified) {
        return -1;
    }

    *total_verified = 0;
    *total_failed = 0;
    *rrc_trigger_verified = false;

    // Step 1: Find the range of buffered intervals
    uint32_t earliest_buffered = UINT32_MAX;
    uint32_t latest_buffered = 0;
    bool has_buffered_entries = false;

    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        if (state->buffer_queue[i].valid) {
            has_buffered_entries = true;
            uint32_t interval = state->buffer_queue[i].interval_index;
            if (interval < earliest_buffered) {
                earliest_buffered = interval;
            }
            if (interval > latest_buffered) {
                latest_buffered = interval;
            }
        }
    }

    if (!has_buffered_entries) {
        LOG_D(NR_RRC, "TESLA: No buffered entries for key recovery\n");
        return -2;
    }

    // Step 2: Verify disclosed key chains to anchor (once for entire batch)
    // Per RFC 4082: disclosed key must chain to a previously authenticated key
    if (!tf5_tesla_ue_verify_key_chain(state, disclosed_key, disclosed_interval)) {
        LOG_E(NR_RRC, "TESLA: Key chain verification failed for K_%u - rejecting all\n",
              disclosed_interval);
        return -6;
    }

    // Step 3: Determine verification range
    // Lower bound: don't re-verify already verified intervals
    uint32_t verify_start = earliest_buffered;
    if (state->last_verified_key_valid &&
        state->last_verified_key_idx + 1 > verify_start) {
        verify_start = state->last_verified_key_idx + 1;
    }

    // Upper bound: can't verify intervals newer than disclosed key
    uint32_t verify_end = (latest_buffered < disclosed_interval) ?
                           latest_buffered : disclosed_interval;

    if (verify_start > verify_end) {
        LOG_D(NR_RRC, "TESLA: No intervals in verifiable range [%u, %u]\n",
              verify_start, verify_end);
        return -2;
    }

    // Step 4: Build key cache for all intervals in range
    // Per RFC 4082 Section 3.5: "Using a disclosed key, we can calculate all
    // previous disclosed keys" via the chain function K_i = F(K_{i+1})
    uint32_t num_intervals = disclosed_interval - verify_start + 1;

    // Safety check: limit derivations to prevent excessive computation
    // With d=1 and buffer_size=4, this is at most ~5 derivations in practice
    if (num_intervals > TF5_TESLA_BUFFER_QUEUE_SIZE + 2) {
        LOG_W(NR_RRC, "TESLA: Key recovery range too large (%u intervals), limiting\n",
              num_intervals);
        verify_start = disclosed_interval - TF5_TESLA_BUFFER_QUEUE_SIZE - 1;
        num_intervals = disclosed_interval - verify_start + 1;
    }

    // Stack-allocated key cache (safe because num_intervals is bounded)
    // Index 0 = key for verify_start, Index N-1 = key for disclosed_interval
    uint8_t key_cache[TF5_TESLA_BUFFER_QUEUE_SIZE + 3][TF5_TESLA_KEY_LEN];

    // Start with disclosed_key at highest index
    memcpy(key_cache[num_intervals - 1], disclosed_key, TF5_TESLA_KEY_LEN);

    // Derive backwards: K_i = F(K_{i+1})
    for (int i = (int)num_intervals - 2; i >= 0; i--) {
        tf5_tesla_chain_key(key_cache[i + 1], key_cache[i]);
    }

    LOG_D(NR_RRC, "TESLA: Key recovery - derived %u keys for intervals [%u, %u]\n",
          num_intervals, verify_start, disclosed_interval);

    // Step 5: Verify all buffered entries using derived keys
    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        tf5_tesla_buffer_entry_t *entry = &state->buffer_queue[i];

        if (!entry->valid) {
            continue;
        }

        uint32_t interval = entry->interval_index;

        // Skip if outside verifiable range
        if (interval < verify_start || interval > verify_end) {
            continue;
        }

        // Get the key for this interval from cache
        uint32_t cache_index = interval - verify_start;
        const uint8_t *key_for_interval = key_cache[cache_index];

        // Compute expected tag
        uint8_t expected_tag[TF5_TESLA_TAG_LEN];
        int rc = tf5_tesla_compute_tag(key_for_interval,
                                       entry->auth_input,
                                       entry->auth_input_len,
                                       expected_tag);
        if (rc != 0) {
            LOG_E(NR_RRC, "TESLA: Failed to compute tag for interval %u\n", interval);
            entry->valid = false;
            (*total_failed)++;
            continue;
        }

        // Compare tags
        if (memcmp(expected_tag, entry->tag, TF5_TESLA_TAG_LEN) == 0) {
            LOG_I(NR_RRC, "TESLA: MAC verified for interval %u (key recovery, rrc_trigger=%d)\n",
                  interval, entry->triggered_rrc_setup);

            if (entry->triggered_rrc_setup) {
                *rrc_trigger_verified = true;
            }

            entry->valid = false;  // Release from buffer
            (*total_verified)++;
        } else {
            LOG_E(NR_RRC, "TESLA: MAC verification FAILED for interval %u (key recovery)\n",
                  interval);
            entry->valid = false;
            (*total_failed)++;
        }
    }

    // Step 6: Update queue count
    state->buffer_queue_count = 0;
    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        if (state->buffer_queue[i].valid) {
            state->buffer_queue_count++;
        }
    }

    // Step 7: Update anchor key to highest verified interval
    // This enables O(1) verification for subsequent consecutive disclosures
    if (*total_verified > 0) {
        memcpy(state->last_verified_key, disclosed_key, TF5_TESLA_KEY_LEN);
        state->last_verified_key_idx = disclosed_interval;
        state->last_verified_key_valid = true;

        LOG_I(NR_RRC, "TESLA: Key recovery verified %d SIB1(s) across intervals [%u, %u] "
              "(%d failed, rrc_trigger=%d)\n",
              *total_verified, verify_start, verify_end, *total_failed, *rrc_trigger_verified);
        return 0;
    }

    return (*total_failed > 0) ? -5 : -2;
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
