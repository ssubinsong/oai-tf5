#ifdef ENABLE_TF5

#include "tf5_tesla.h"
#include "tf5_tesla_sig.h"
#include "tf5_crypto.h"
#include "common/utils/assertions.h"
#include "common/utils/LOG/log.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

void tf5_derive_mac_key(const uint8_t key_in[TF5_TESLA_KEY_LEN],
                              uint8_t mac_key_out[32])
{
    uint8_t input[1 + TF5_TESLA_KEY_LEN];
    input[0] = TF5_DS_PREFIX_MAC_KEY;  // Domain separation prefix
    memcpy(input + 1, key_in, TF5_TESLA_KEY_LEN);

    tf5_sha256(input, sizeof(input), mac_key_out);
}

void tf5_chain_key(const uint8_t key_next[TF5_TESLA_KEY_LEN],
                         uint8_t key_out[TF5_TESLA_KEY_LEN])
{
    uint8_t input[1 + TF5_TESLA_KEY_LEN];
    input[0] = TF5_DS_PREFIX_CHAIN_KEY;  // Domain separation prefix
    memcpy(input + 1, key_next, TF5_TESLA_KEY_LEN);

    uint8_t full_hash[TF5_SHA256_DIGEST_LEN];
    tf5_sha256(input, sizeof(input), full_hash);

    // Truncate to 16 bytes
    memcpy(key_out, full_hash, TF5_TESLA_KEY_LEN);
}

int tf5_compute_tag(const uint8_t key[TF5_TESLA_KEY_LEN],
                          const uint8_t *auth_input,
                          size_t auth_input_len,
                          uint8_t tag_out[TF5_TESLA_TAG_LEN])
{
    if (!key || !auth_input || !tag_out || auth_input_len == 0) {
        return TF5_ERR_INVALID_PARAM;
    }

    // Derive MAC key K'_i from K_i
    uint8_t mac_key[TF5_SHA256_DIGEST_LEN];
    tf5_derive_mac_key(key, mac_key);

    // Compute HMAC-SHA256(K'_i, auth_input)
    uint8_t full_tag[TF5_SHA256_DIGEST_LEN];
    tf5_hmac_sha256(mac_key, TF5_SHA256_DIGEST_LEN, auth_input, auth_input_len, full_tag);

    // Truncate to 16 bytes
    memcpy(tag_out, full_tag, TF5_TESLA_TAG_LEN);

    return 0;
}

/* Internal helper - compute slots since T_0 */
static uint64_t tf5_tesla_slots_since_t0(const tf5_slot_time_t *current,
                                         const tf5_slot_time_t *t0,
                                         uint16_t slots_per_frame)
{
    uint64_t current_abs = tf5_absolute_slots(current, slots_per_frame);
    uint64_t t0_abs = tf5_absolute_slots(t0, slots_per_frame);

    return (current_abs >= t0_abs) ? (current_abs - t0_abs) : 0;
}

/* Internal helper - compute interval index from timing */
static uint32_t tf5_tesla_get_interval_index(const tf5_slot_time_t *current,
                                             const tf5_slot_time_t *t0,
                                             uint16_t t_int_ms,
                                             uint16_t slots_per_frame)
{
    uint64_t slots = tf5_tesla_slots_since_t0(current, t0, slots_per_frame);

    // Calculate time in milliseconds
    // Each frame = TF5_NR_FRAME_DURATION_MS ms, slots_per_frame slots per frame
    // time_ms = slots * TF5_NR_FRAME_DURATION_MS / slots_per_frame
    uint64_t time_ms = (slots * TF5_NR_FRAME_DURATION_MS) / slots_per_frame;

    return (uint32_t)(time_ms / t_int_ms);
}

/*
 * =============================================================================
 * Timestamp Functions for Replay Protection
 * =============================================================================
 */

uint64_t tf5_rp_get_wallclock_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        LOG_E(TF5, "Failed to get wall-clock time\n");
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

int tf5_rp_validate_timestamp(uint64_t ue_time_ms,
                                 uint32_t ext_timestamp_ms,
                                 uint64_t window_ms)
{
    uint32_t ue_time_lsb_ms = (uint32_t)ue_time_ms & TF5_RP_TIMESTAMP_MASK;
    uint32_t ext_time_lsb_ms = ext_timestamp_ms & TF5_RP_TIMESTAMP_MASK;
    // Proper 24-bit modular signed difference: map into [-2^23, 2^23)
    int32_t diff_ms = (int32_t)(((ue_time_lsb_ms - ext_time_lsb_ms + TF5_RP_TIMESTAMP_HALF) & TF5_RP_TIMESTAMP_MASK)) - (int32_t)TF5_RP_TIMESTAMP_HALF;

    // This comparison assumes window_ms << 2^23 (fits into 24-bit signed range).
    if (diff_ms > 0 && (uint64_t)diff_ms > window_ms) {
        return TF5_ERR_TIMESTAMP_OLD;
    }

    if (diff_ms < 0 && (uint64_t)(-diff_ms) > window_ms) {
        return TF5_ERR_TIMESTAMP_FUTURE;
    }

    return TF5_OK;
}

/*
 * =============================================================================
 * Binary Pack/Unpack Functions
 * =============================================================================
 */

/* Encode tesla params to buffer */
static size_t tf5_encode_tesla_params(uint8_t *buf,
                                       const tf5_tesla_params_t *p)
{
    size_t offset = 0;
    tf5_encode_u16_be(buf + offset, p->t_int_ms); offset += 2;
    buf[offset++] = p->d;
    tf5_encode_u16_be(buf + offset, p->t0.sfn); offset += 2;
    tf5_encode_u16_be(buf + offset, p->t0.slot); offset += 2;
    tf5_encode_u32_be(buf + offset, p->chain_len); offset += 4;
    return offset;  /* Always TF5_TESLA_PARAMS_PACKED_SIZE */
}

/* Decode tesla params (TF5_TESLA_PARAMS_PACKED_SIZE bytes) from buffer */
static size_t tf5_decode_tesla_params(const uint8_t *buf,
                                       tf5_tesla_params_t *p)
{
    size_t offset = 0;
    p->t_int_ms = tf5_decode_u16_be(buf + offset); offset += 2;
    p->d = buf[offset++];
    p->t0.sfn = tf5_decode_u16_be(buf + offset); offset += 2;
    p->t0.slot = tf5_decode_u16_be(buf + offset); offset += 2;
    p->chain_len = tf5_decode_u32_be(buf + offset); offset += 4;
    return offset;  /* Always TF5_TESLA_PARAMS_PACKED_SIZE */
}

int tf5_build_mac_auth_input(uint8_t *out,
                                   size_t *out_len,
                                   const uint8_t *original_sib1,
                                   size_t sib1_len,
                                   uint32_t gnb_key_validity_end)
{
    if (!out || !out_len || !original_sib1) {
        return TF5_ERR_INVALID_PARAM;
    }

    if (sib1_len + TF5_IBS_VALIDITY_PERIOD_LEN > TF5_MAX_AUTH_INPUT) {
        return TF5_ERR_BUFFER_OVERFLOW;
    }

    size_t offset = 0;

    // 1. Original SIB1 content
    memcpy(out + offset, original_sib1, sib1_len);
    offset += sib1_len;

    // 2. gNB key validity end
    tf5_encode_gnb_key_validity_end(out + offset, gnb_key_validity_end);
    offset += TF5_IBS_VALIDITY_PERIOD_LEN;

    *out_len = offset;
    return 0;
}

int tf5_build_sig_auth_input(uint8_t *out,
                                   size_t *out_len,
                                   const uint8_t *original_sib1,
                                   size_t sib1_len,
                                   uint8_t te_version,
                                   const tf5_tesla_params_t *tesla_params,
                                   uint32_t gnb_key_validity_end,
                                   uint32_t interval_index,
                                   const uint8_t key_disclosure[TF5_TESLA_KEY_LEN],
                                   uint32_t timestamp_ms)
{
    if (!out || !out_len || !original_sib1 || !tesla_params || !key_disclosure) {
        return TF5_ERR_INVALID_PARAM;
    }

    if (sib1_len + TF5_SIG_AUTH_OVERHEAD > TF5_MAX_AUTH_INPUT) {
        return TF5_ERR_BUFFER_OVERFLOW;
    }

    // Build MAC auth input first (SIB1 + gnb_key_validity_end only)
    size_t mac_len = 0;
    int rc = tf5_build_mac_auth_input(out, &mac_len, original_sib1, sib1_len,
                                            gnb_key_validity_end);
    if (rc < 0) {
        return rc;
    }

    size_t offset = mac_len;

    // Append te_version (1 byte)
    out[offset++] = te_version;

    // Append tesla_params (11 bytes)
    offset += tf5_encode_tesla_params(out + offset, tesla_params);

    // Append interval_index (4 bytes)
    tf5_encode_u32_be(out + offset, interval_index);
    offset += 4;

    // Append key_disclosure (16 bytes)
    memcpy(out + offset, key_disclosure, TF5_TESLA_KEY_LEN);
    offset += TF5_TESLA_KEY_LEN;

    // Append timestamp_ms (3 bytes) - for signature replay protection
    tf5_encode_u24_be(out + offset, timestamp_ms);
    offset += 3;

    *out_len = offset;
    return 0;
}

int tf5_pack_extension(const tf5_extension_t *ext,
                             uint8_t *buf,
                             size_t buf_len)
{
    if (!ext || !buf) {
        return TF5_ERR_INVALID_PARAM;
    }

    const size_t required_len = TF5_EXTENSION_PACKED_SIZE;
    if (buf_len < required_len) {
        return TF5_ERR_BUFFER_OVERFLOW;
    }

    size_t offset = 0;

    // TESLA version (1 byte)
    buf[offset++] = ext->te_version;

    // TESLA params (11 bytes)
    offset += tf5_encode_tesla_params(buf + offset, &ext->tesla_params);

    // gNB key validity end (3 bytes) - key expiration (minutes since 2024-01-01)
    tf5_encode_gnb_key_validity_end(buf + offset, ext->validity_end);
    offset += TF5_IBS_VALIDITY_PERIOD_LEN;

    // Interval index (4 bytes)
    tf5_encode_u32_be(buf + offset, ext->i);
    offset += 4;

    // Disclosed key (16 bytes)
    memcpy(buf + offset, ext->key_disclosure, TF5_TESLA_KEY_LEN);
    offset += TF5_TESLA_KEY_LEN;

    // Timestamp (3 bytes) - for signature replay protection
    tf5_encode_u24_be(buf + offset, ext->timestamp_ms);
    offset += 3;

    // Signature (48 bytes - BLS)
    memcpy(buf + offset, ext->signature, TF5_IBS_SIG_LEN);
    offset += TF5_IBS_SIG_LEN;

    // TESLA tag (16 bytes)
    memcpy(buf + offset, ext->tesla_tag, TF5_TESLA_TAG_LEN);
    offset += TF5_TESLA_TAG_LEN;

    return (int)offset;
}

int tf5_unpack_extension(const uint8_t *buf,
                               size_t buf_len,
                               tf5_extension_t *ext)
{
    if (!buf || !ext) {
        return TF5_ERR_INVALID_PARAM;
    }

    const size_t required_len = TF5_EXTENSION_PACKED_SIZE;
    if (buf_len < required_len) {
        return TF5_ERR_BUFFER_OVERFLOW;
    }

    size_t offset = 0;

    // TESLA version (1 byte)
    ext->te_version = buf[offset++];

    // TESLA params (11 bytes) - includes T_0
    offset += tf5_decode_tesla_params(buf + offset, &ext->tesla_params);

    // gNB key validity end (3 bytes) - key expiration (minutes since 2024-01-01)
    ext->validity_end = tf5_decode_gnb_key_validity_end(buf + offset);
    offset += TF5_IBS_VALIDITY_PERIOD_LEN;

    // Interval index (4 bytes)
    ext->i = tf5_decode_u32_be(buf + offset);
    offset += 4;

    // Disclosed key (16 bytes)
    memcpy(ext->key_disclosure, buf + offset, TF5_TESLA_KEY_LEN);
    offset += TF5_TESLA_KEY_LEN;

    // Timestamp (3 bytes) - for signature replay protection
    ext->timestamp_ms = tf5_decode_u24_be(buf + offset);
    offset += 3;

    // Signature (48 bytes - BLS)
    memcpy(ext->signature, buf + offset, TF5_IBS_SIG_LEN);
    offset += TF5_IBS_SIG_LEN;

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

int tf5_gnb_init(tf5_gnb_state_t *state,
                       uint16_t t_int_ms,
                       uint8_t d,
                       uint32_t chain_len,
                       const uint8_t private_key[TF5_IBS_GNB_SK_LEN],
                       const tf5_slot_time_t *t0,
                       uint16_t slots_per_frame)
{
    if (!state || !private_key || !t0 || chain_len == 0 || t_int_ms == 0) {
        return TF5_ERR_INVALID_PARAM;
    }

    // Clean up any previous state (prevents memory leak on reinitialization)
    tf5_gnb_free(state);

    memset(state, 0, sizeof(*state));

    // Store IBS secret key (sk_ID issued by Core PKG)
    memcpy(state->private_key, private_key, TF5_IBS_GNB_SK_LEN);

    // Allocate key chain: chain_len + 1 entries to include K_{-1} at index 0
    // key_chain[0] = K_{-1}, key_chain[1] = K_0, ..., key_chain[chain_len] = K_{N-1}
    state->key_chain = calloc(chain_len + 1, TF5_TESLA_KEY_LEN);
    if (!state->key_chain) {
        LOG_E(TF5, "Failed to allocate key chain\n");
        return TF5_ERR_ALLOC;
    }
    state->key_chain_len = chain_len;

    // Generate random K_{N-1} (last key in chain, stored at index chain_len)
    uint32_t last_key_idx = tf5_key_interval_to_index(chain_len - 1);
    if (RAND_bytes(state->key_chain[last_key_idx], TF5_TESLA_KEY_LEN) != 1) {
        LOG_E(TF5, "Failed to generate random key\n");
        free(state->key_chain);
        return TF5_ERR_CRYPTO;
    }

    // Generate backward chain: K_i = F(K_{i+1}) for i = N-2 down to -1
    // This includes K_{-1} = F(K_0) at index 0
    for (int32_t i = (int32_t)chain_len - 2; i >= -1; i--) {
        uint32_t curr_idx = tf5_key_interval_to_index(i);
        uint32_t next_idx = tf5_key_interval_to_index(i + 1);
        tf5_chain_key(state->key_chain[next_idx], state->key_chain[curr_idx]);
    }

    LOG_I(TF5, "Key chain generated with %u intervals (K_{-1} at index 0)\n", chain_len);

    // Set TESLA parameters
    state->tesla_params.t_int_ms = t_int_ms;
    state->tesla_params.d = d;
    state->tesla_params.t0 = *t0;
    state->tesla_params.chain_len = chain_len;

    state->slots_per_frame = slots_per_frame;
    state->initialized = true;

    LOG_I(TF5, "gNB initialized - T_int=%ums, d=%u, T_0=SFN%u.%u\n",
          t_int_ms, d, t0->sfn, t0->slot);

    return 0;
}

void tf5_gnb_free(tf5_gnb_state_t *state)
{
    if (state) {
        if (state->key_chain) {
            // Clear sensitive data (chain_len + 1 entries including K_{-1})
            OPENSSL_cleanse(state->key_chain, (state->key_chain_len + 1) * TF5_TESLA_KEY_LEN);
            free(state->key_chain);
        }
        OPENSSL_cleanse(state->private_key, TF5_IBS_GNB_SK_LEN);
        memset(state, 0, sizeof(*state));
    }
}

/* Internal helper - get current interval index from SFN/slot */
static uint32_t tf5_tesla_gnb_get_interval(tf5_gnb_state_t *state,
                                           uint16_t sfn,
                                           uint16_t slot)
{
    if (!state || !state->initialized) {
        return 0;
    }

    tf5_slot_time_t current = tf5_slot_time_make(sfn, slot);
    return tf5_tesla_get_interval_index(&current, &state->tesla_params.t0,
                                        state->tesla_params.t_int_ms,
                                        state->slots_per_frame);
}

int tf5_gnb_prepare_extension(tf5_gnb_state_t *state,
                                    uint16_t sfn,
                                    uint16_t slot,
                                    const uint8_t *original_sib1,
                                    size_t sib1_len,
                                    tf5_extension_t *ext)
{
    if (!state || !state->initialized || !original_sib1 || !ext) {
        return TF5_ERR_INVALID_PARAM;
    }

    // Get current interval
    uint32_t interval = tf5_tesla_gnb_get_interval(state, sfn, slot);

    // Check if interval is within chain bounds
    if (interval >= state->key_chain_len) {
        LOG_E(TF5, "Interval %u exceeds chain length %u\n",
              interval, state->key_chain_len);
        return TF5_ERR_CHAIN_EXHAUSTED;
    }

    // Copy TESLA params
    memcpy(&ext->tesla_params, &state->tesla_params, sizeof(state->tesla_params));
    ext->te_version = TF5_VERSION;

    // Set key validity period (minutes since 2024-01-01)
    ext->validity_end = state->key_validity_end;

    // Set interval index
    ext->i = interval;

    // Set disclosed key K_{i-d} (works uniformly for all intervals including bootstrap)
    int32_t disclosed_interval = (int32_t)interval - state->tesla_params.d;
    uint32_t disclosed_idx = tf5_key_interval_to_index(disclosed_interval);
    memcpy(ext->key_disclosure, state->key_chain[disclosed_idx], TF5_TESLA_KEY_LEN);

    if (disclosed_interval < 0) {
        LOG_D(TF5, "Bootstrap interval %u, disclosing K_{%d}\n",
              interval, disclosed_interval);
    }

    // Set wall-clock timestamp for signature replay protection
    ext->timestamp_ms = (uint32_t)tf5_rp_get_wallclock_ms() & TF5_RP_TIMESTAMP_MASK;
    if (ext->timestamp_ms == 0) {
        LOG_E(TF5, "Failed to get wall-clock time\n");
        return TF5_ERR_CRYPTO;
    }

    // Build signature auth input
    uint8_t sig_auth_input[TF5_MAX_AUTH_INPUT];
    size_t sig_auth_input_len;
    int rc = tf5_build_sig_auth_input(sig_auth_input, &sig_auth_input_len,
                                            original_sib1, sib1_len,
                                            ext->te_version,
                                            &ext->tesla_params,
                                            ext->validity_end,
                                            ext->i,
                                            ext->key_disclosure,
                                            ext->timestamp_ms);
    if (rc != 0) {
        LOG_E(TF5, "Failed to build signature auth input\n");
        return rc;
    }

    // Compute BLS signature over full content
    rc = tf5_bls_sign(state->private_key,
                            sig_auth_input, sig_auth_input_len,
                            ext->signature);
    if (rc != 0) {
        LOG_E(TF5, "Failed to compute signature\n");
        return TF5_ERR_SIGN;
    }

    // Build MAC auth input (SIB1 + gnb_key_validity_end only)
    uint8_t mac_auth_input[TF5_MAX_AUTH_INPUT];
    size_t mac_auth_input_len;
    rc = tf5_build_mac_auth_input(mac_auth_input, &mac_auth_input_len,
                                        original_sib1, sib1_len,
                                        ext->validity_end);
    if (rc != 0) {
        LOG_E(TF5, "Failed to build MAC auth input\n");
        return rc;
    }

    // Compute TESLA tag using K_i
    rc = tf5_compute_tag(state->key_chain[tf5_key_interval_to_index(interval)],
                               mac_auth_input, mac_auth_input_len,
                               ext->tesla_tag);
    if (rc != 0) {
        LOG_E(TF5, "Failed to compute tag\n");
        return rc;
    }

    LOG_D(TF5, "Prepared extension for interval %u (SFN%u.%u)\n",
          interval, sfn, slot);

    return 0;
}

/*
 * =============================================================================
 * UE Functions
 * =============================================================================
 */

int tf5_ue_init(tf5_ue_state_t *state,
                      const uint8_t mpk[TF5_IBS_MPK_LEN],
                      uint16_t slots_per_frame,
                      uint32_t d_bound_us,
                      uint64_t rp_timestamp_window_ms)
{
    if (!state || !mpk) {
        return TF5_ERR_INVALID_PARAM;
    }

    memset(state, 0, sizeof(*state));

    // Store Core's Master Public Key
    memcpy(state->mpk, mpk, TF5_IBS_MPK_LEN);
    state->slots_per_frame = slots_per_frame;
    state->buffer_queue_count = 0;  // All queue entries initialized to 0/false by memset

    // Timestamp validation for signature replay protection
    state->rp_timestamp_window_ms = (rp_timestamp_window_ms == 0)
                                     ? TF5_RP_DEFAULT_TIME_WINDOW_MS
                                     : rp_timestamp_window_ms;

    // D parameter (CLI-configured)
    // Per RFC 4082 Section 2.2, D is the upper bound on (sender_time - receiver_time)
    // Pre-compute D in slots (ceiling division for upper bound)
    uint32_t slot_duration_us = TF5_NR_FRAME_DURATION_US / slots_per_frame;
    state->d_offset_slots = (d_bound_us + slot_duration_us - 1) / slot_duration_us;

    state->initialized = true;

    LOG_I(TF5, "UE initialized (D=%u slots, first-time UE)\n", state->d_offset_slots);

    return 0;
}

void tf5_ue_free(tf5_ue_state_t *state)
{
    if (state) {
        memset(state, 0, sizeof(*state));
    }
}

bool tf5_ue_safe_packet_test(tf5_ue_state_t *ue_state,
                                   const tf5_extension_t *tf5_ext,
                                   uint16_t rx_sfn,
                                   uint16_t rx_slot)
{
    if (!ue_state || !ue_state->initialized || !tf5_ext) {
        return false;
    }

    // Step 1: Record rx time T (in absolute slots)
    tf5_slot_time_t rx_time = tf5_slot_time_make(rx_sfn, rx_slot);
    uint64_t t_abs_slots = tf5_absolute_slots(&rx_time, ue_state->slots_per_frame);

    // Step 2: Compute upper bound on sender's clock: t_j = T + D_t
    uint64_t t_j_abs_slots = t_abs_slots + ue_state->d_offset_slots;

    // Step 3: Compute x = floor((t_j - T_0) / T_int)
    // This is the highest interval the sender could possibly be in
    uint64_t t0_abs_slots = tf5_absolute_slots(&ue_state->tesla_params.t0, ue_state->slots_per_frame);
    uint64_t slots_since_t0 = (t_j_abs_slots >= t0_abs_slots) ? (t_j_abs_slots - t0_abs_slots) : 0;
    uint64_t time_ms = (slots_since_t0 * TF5_NR_FRAME_DURATION_MS) / ue_state->slots_per_frame;
    uint32_t x = (uint32_t)(time_ms / ue_state->tesla_params.t_int_ms);

    // Safe if: x < i + d
    // This means the sender hasn't yet disclosed K_i
    uint32_t i = tf5_ext->i;
    uint8_t d = ue_state->tesla_params.d;

    bool safe = (x < i + d);

    if (!safe) {
        LOG_W(TF5, "Safe packet test FAILED - x=%u (T+D, D=%u slots) >= i=%u + d=%u\n",
              x, ue_state->d_offset_slots, i, d);
    }

    return safe;
}

/* Recount valid entries in the buffer queue */
static void tf5_ue_recount_buffer(tf5_ue_state_t *state)
{
    state->buffer_queue_count = 0;
    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        if (state->buffer_queue[i].valid) {
            state->buffer_queue_count++;
        }
    }
}

/* Apply one-way chain function in-place: key = F(key) */
static void tf5_chain_key_inplace(uint8_t key[TF5_TESLA_KEY_LEN])
{
    uint8_t tmp[TF5_TESLA_KEY_LEN];
    tf5_chain_key(key, tmp);
    memcpy(key, tmp, TF5_TESLA_KEY_LEN);
}

int tf5_ue_buffer_msg(tf5_ue_state_t *state,
                             const uint8_t *auth_input,
                             size_t auth_input_len,
                             uint32_t interval_index,
                             const uint8_t tag[TF5_TESLA_TAG_LEN],
                             bool triggered_rrc_setup)
{
    if (!state || !state->initialized || !auth_input || !tag) {
        return TF5_ERR_INVALID_PARAM;
    }

    if (auth_input_len > TF5_MAX_AUTH_INPUT) {
        LOG_E(TF5, "Auth input too large (%zu > %d)\n",
              auth_input_len, TF5_MAX_AUTH_INPUT);
        return TF5_ERR_BUFFER_OVERFLOW;
    }

    // Find target slot: prefer invalid entry, then oldest entry
    int target_slot = -1;
    int oldest_slot = -1;
    uint32_t oldest_index = UINT32_MAX;

    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        if (!state->buffer_queue[i].valid) {
            target_slot = i;
            break;  // Use first invalid slot
        }
        // Choose an oldest entry (i.e., smallest rx_interval_index)
        uint32_t idx = state->buffer_queue[i].rx_interval_index;
        if (idx < oldest_index) {
          oldest_index = idx;
          oldest_slot = i;
        }
    }
    if (target_slot < 0) {
        target_slot = oldest_slot;
        LOG_W(TF5, "Buffer full - dropping oldest entry (interval %u)\n",
                  state->buffer_queue[target_slot].rx_interval_index);
    }

    // Store in target slot
    tf5_buffer_entry_t *entry = &state->buffer_queue[target_slot];
    memcpy(entry->auth_input, auth_input, auth_input_len);
    entry->auth_input_len = auth_input_len;
    entry->rx_interval_index = interval_index;
    memcpy(entry->tag, tag, TF5_TESLA_TAG_LEN);
    entry->valid = true;
    entry->triggered_rrc_setup = triggered_rrc_setup;

    // Update queue count
    tf5_ue_recount_buffer(state);

    LOG_D(TF5, "Buffered SIB1 for interval %u (slot %d, queue count %u, rrc_trigger=%d)\n",
          interval_index, target_slot, state->buffer_queue_count, triggered_rrc_setup);

    return 0;
}

bool tf5_ue_verify_key_disclosure(tf5_ue_state_t *ue_state,
                                   const uint8_t disclosed_key[TF5_TESLA_KEY_LEN],
                                   uint32_t disclosed_key_interval)
{
    if (!ue_state || !ue_state->initialized || !disclosed_key) {
        return false;
    }

    // chain_bootstrapped indicates the anchor is valid (set when IBS signature verified)
    if (!ue_state->chain_bootstrapped) {
        LOG_E(TF5, "No valid anchor key - cannot verify key chain\n");
        return false;
    }

    // Verify by chaining disclosed key to the trust anchor
    // Works uniformly for all cases including bootstrap (trust_anchor_idx == -1)
    int32_t disclosed_interval = (int32_t)disclosed_key_interval;

    DevAssert(disclosed_interval > ue_state->trust_anchor_idx);

    // Chain from disclosed_key_interval down to trust_anchor_idx
    uint8_t computed_key[TF5_TESLA_KEY_LEN];
    memcpy(computed_key, disclosed_key, TF5_TESLA_KEY_LEN);

    uint32_t steps = (uint32_t)(disclosed_interval - ue_state->trust_anchor_idx);
    for (uint32_t i = 0; i < steps; i++) {
      tf5_chain_key_inplace(computed_key);
    }

    if (memcmp(computed_key, ue_state->trust_anchor_key, TF5_TESLA_KEY_LEN) == 0) {
      LOG_D(TF5,
            "Key chain verified K_%u -> K_%d (%u hash ops)\n",
            disclosed_key_interval,
            ue_state->trust_anchor_idx,
            steps);

      // Update anchor to newly verified key for O(1) future verifications
      // Per RFC 4082: once a key is verified, it becomes the new trust anchor
      memcpy(ue_state->trust_anchor_key, disclosed_key, TF5_TESLA_KEY_LEN);
      ue_state->trust_anchor_idx = disclosed_interval;
      return true;
    }
    LOG_E(TF5, "Key chain verification FAILED K_%u -> K_%d\n", disclosed_key_interval, ue_state->trust_anchor_idx);
    return false;
}

int tf5_tesla_ue_verify_buffered_msgs(tf5_ue_state_t *ue_state,
                                                     const uint8_t key_disclosure[TF5_TESLA_KEY_LEN],
                                                     uint32_t key_disclosure_interval,
                                                     bool *rrc_trigger_verified)
{
    if (!ue_state || !ue_state->initialized || !key_disclosure || !rrc_trigger_verified) {
        return TF5_ERR_INVALID_PARAM;
    }
    *rrc_trigger_verified = false;

    // Step 1: Find the range of buffered intervals
    uint32_t earliest_buffered = UINT32_MAX;
    uint32_t latest_buffered = 0;
    bool has_buffered_entries = false;

    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        if (ue_state->buffer_queue[i].valid) {
            has_buffered_entries = true;
            uint32_t interval = ue_state->buffer_queue[i].rx_interval_index;
            if (interval < earliest_buffered) {
                earliest_buffered = interval;
            }
            if (interval > latest_buffered) {
                latest_buffered = interval;
            }
        }
    }

    if (!has_buffered_entries) {
        LOG_D(TF5, "No buffered entries for verification\n");
        return TF5_ERR_NO_DATA;
    }

    // Step 2: Determine verification range
    // Lower bound: don't re-verify already verified intervals
    uint32_t verify_start = earliest_buffered;

    // Upper bound: can't verify intervals newer than verified key
    uint32_t verify_end = (latest_buffered < key_disclosure_interval) ?
                           latest_buffered : key_disclosure_interval;

    if (verify_start > verify_end) {
        LOG_D(TF5, "No intervals in verifiable range [%u, %u]\n",
              verify_start, verify_end);
        return TF5_ERR_NO_DATA;
    }

    // Step 3: Derive keys incrementally and verify buffered entries
    bool mac_failed = false;
    uint8_t current_key[TF5_TESLA_KEY_LEN];
    memcpy(current_key, key_disclosure, TF5_TESLA_KEY_LEN);

    for (uint32_t i = key_disclosure_interval; ; i--) {
        // Check all buffered entries for this interval
        for (int j = 0; j < TF5_TESLA_BUFFER_QUEUE_SIZE; j++) {
            tf5_buffer_entry_t *entry = &ue_state->buffer_queue[j];

            if (!entry->valid || entry->rx_interval_index != i) {
                continue;
            }

            // Compute expected tag using current_key
            uint8_t expected_tag[TF5_TESLA_TAG_LEN];
            int rc = tf5_compute_tag(current_key,
                                           entry->auth_input,
                                           entry->auth_input_len,
                                           expected_tag);
            if (rc != 0) {
                LOG_E(TF5, "Failed to compute tag for interval %u\n", i);
                entry->valid = false;
                continue;
            }

            // Compare tags
            if (memcmp(expected_tag, entry->tag, TF5_TESLA_TAG_LEN) == 0) {
                LOG_I(TF5, "MAC verified for interval %u (rrc_trigger=%d)\n",
                      i, entry->triggered_rrc_setup);

                if (entry->triggered_rrc_setup) {
                  *rrc_trigger_verified = true;
                }

                entry->valid = false;  // Release from buffer
            } else {
                LOG_E(TF5, "MAC verification FAILED for interval %u\n",
                      i);
              entry->valid = false;
              mac_failed = true;
              if (entry->triggered_rrc_setup) {
                *rrc_trigger_verified = false;
              }
            }
        }

        // Stop if we've reached verify_start
        if (i == verify_start) {
          break;
        }

        // Derive key for next (earlier) interval: K_{i-1} = F(K_i)
        tf5_chain_key_inplace(current_key);
    }

    // Step 4: Update queue count
    tf5_ue_recount_buffer(ue_state);

    return mac_failed ? TF5_ERR_VERIFY : TF5_OK;
}

/*
 * =============================================================================
 * File I/O Functions
 * =============================================================================
 */

int tf5_load_gnb_privkey(const char *filepath,
                           uint8_t privkey_out[TF5_IBS_GNB_SK_LEN],
                           uint32_t *validity_out)
{
    if (!filepath || !privkey_out || !validity_out) {
        return TF5_ERR_INVALID_PARAM;
    }

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        LOG_E(TF5, "Cannot open secret key file: %s\n", filepath);
        return TF5_ERR_FILE_OPEN;
    }

    // Read 35-byte key file: sk_ID (32 bytes) + gnb_key_validity_end (3 bytes, big-endian)
    uint8_t buffer[TF5_IBS_SK_FILE_SIZE];
    size_t n = fread(buffer, 1, TF5_IBS_SK_FILE_SIZE, fp);
    fclose(fp);

    if (n != TF5_IBS_SK_FILE_SIZE) {
        LOG_E(TF5, "Secret key file has wrong size: %zu (expected %d)\n",
              n, TF5_IBS_SK_FILE_SIZE);
        return TF5_ERR_FILE_IO;
    }

    // Extract secret key (bytes 0-31)
    memcpy(privkey_out, buffer, TF5_IBS_GNB_SK_LEN);

    // Extract validity from bytes 32-34 (big-endian)
    *validity_out = tf5_decode_u24_be(&buffer[32]);

    // Clear buffer
    OPENSSL_cleanse(buffer, TF5_IBS_SK_FILE_SIZE);

    // Validate by trying to derive public key (this checks the key is valid)
    uint8_t pubkey_test[TF5_IBS_MPK_LEN];
    if (tf5_bls_derive_pubkey(privkey_out, pubkey_test) != 0) {
        LOG_E(TF5, "Invalid BLS secret key format\n");
        OPENSSL_cleanse(privkey_out, TF5_IBS_GNB_SK_LEN);
        return TF5_ERR_KEY_INVALID;
    }

    return 0;
}

int tf5_load_core_mpk(const char *filepath,
                      uint8_t mpk_out[TF5_IBS_MPK_LEN])
{
    if (!filepath || !mpk_out) {
        return TF5_ERR_INVALID_PARAM;
    }

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        LOG_E(TF5, "Cannot open MPK file: %s\n", filepath);
        return TF5_ERR_FILE_OPEN;
    }

    size_t n = fread(mpk_out, 1, TF5_IBS_MPK_LEN, fp);
    fclose(fp);

    if (n != TF5_IBS_MPK_LEN) {
        LOG_E(TF5, "MPK file has wrong size: %zu (expected %d)\n",
              n, TF5_IBS_MPK_LEN);
        return TF5_ERR_FILE_IO;
    }

    LOG_I(TF5, "Loaded Core MPK from %s (%d bytes)\n",
          filepath, TF5_IBS_MPK_LEN);

    return 0;
}

#endif /* ENABLE_TF5 */
