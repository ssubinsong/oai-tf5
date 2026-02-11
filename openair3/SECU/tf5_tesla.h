/**
 * @file tf5_tesla.h
 * @brief TESLA broadcast authentication protocol for 5G NR SIB1
 *
 * Core data structures, constants, and API functions for the TESLA protocol
 * integration with OpenAirInterface. Implements key chain management, MAC
 * computation/verification, and binary extension serialization for both
 * gNB (signing) and UE (verification) sides.
 */

#ifndef TF5_TESLA_H
#define TF5_TESLA_H

#ifdef ENABLE_TF5

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "tf5_tesla_sig.h"

/* ── Protocol Version ──────────────────────────────────── */
#define TF5_VERSION                 0x01

/* ── TESLA Chain & MAC Constants ───────────────────────── */
#define TF5_TESLA_KEY_LEN           16      // 128-bit chain keys
#define TF5_TESLA_TAG_LEN           16      // Truncated HMAC-SHA256
#define TF5_DS_PREFIX_CHAIN_KEY     0x00    // F(K_{i+1}) domain separation
#define TF5_DS_PREFIX_MAC_KEY       0x01    // F'(K_i) domain separation

/* ── Buffer & Wire Format Sizes ────────────────────────── */
#define TF5_MAX_AUTH_INPUT          372     // Max auth input buffer size
#define TF5_EXTENSION_PACKED_SIZE   102     // Wire format size (tf5_extension_t)

/* ── Default Configuration ─────────────────────────────── */
#define TF5_TESLA_DEFAULT_D_BOUND_US       1005    // D bound (microseconds)
#define TF5_TESLA_BUFFER_QUEUE_SIZE        4       // Max SIB1s buffered per UE
#define TF5_RP_DEFAULT_TIME_WINDOW_MS      60000   // Replay protection window (60s)

/* ── NR Radio Timing Constants (3GPP TS 38.211) ──────── */
#define TF5_NR_FRAME_DURATION_MS    10      // 1 radio frame = 10ms
#define TF5_NR_FRAME_DURATION_US    10000   // Frame duration in microseconds
#define TF5_NR_SFN_MODULUS          1024    // SFN wraps at 1024 (0-1023)

/* ── Replay Protection Timestamp Constants ────────────── */
#define TF5_RP_TIMESTAMP_BITS       24
#define TF5_RP_TIMESTAMP_MASK       ((1u << TF5_RP_TIMESTAMP_BITS) - 1)   // 0xFFFFFF
#define TF5_RP_TIMESTAMP_HALF       (1u << (TF5_RP_TIMESTAMP_BITS - 1))   // 0x800000

/* ── Wire Format Sizes ────────────────────────────────── */
#define TF5_TESLA_PARAMS_PACKED_SIZE  11    // t_int(2) + d(1) + t0(4) + chain_len(4)
#define TF5_SIG_AUTH_OVERHEAD         (TF5_IBS_VALIDITY_PERIOD_LEN + 1 + TF5_TESLA_PARAMS_PACKED_SIZE + 4 + TF5_TESLA_KEY_LEN + 3)  // 38 bytes

/**
 * Generic PHY Timing (SFN/slot)
 */
typedef struct {
    uint16_t sfn;   // 2B - System Frame Number (0-1023)
    uint16_t slot;  // 2B - Slot within frame
} tf5_slot_time_t;


/**
 * Buffer Entry for Pending TESLA Verification
 */
typedef struct {
    uint8_t  auth_input[TF5_MAX_AUTH_INPUT];
    size_t   auth_input_len;
    uint32_t rx_interval_index;
    uint8_t  tag[TF5_TESLA_TAG_LEN];
    bool     valid;                  // Entry contains valid data
    bool     triggered_rrc_setup;    // This SIB1 triggered the current RRC session
} tf5_buffer_entry_t;

/* Helper to construct slot_time_t inline */
static inline tf5_slot_time_t tf5_slot_time_make(uint16_t sfn,
                                                        uint16_t slot)
{
    return (tf5_slot_time_t){.sfn = sfn, .slot = slot};
}

/**
 * Convert TESLA key interval to array index
 *
 * Key chain storage: key_chain[0] = K_{-1}, key_chain[1] = K_0, ..., key_chain[n+1] = K_n
 * This simplifies bootstrap key handling by storing K_{-1} in the same array.
 *
 * @param interval  Key interval (-1, 0, 1, ..., N-1)
 * @return Array index (0, 1, 2, ..., N)
 */
static inline uint32_t tf5_key_interval_to_index(int32_t interval)
{
    return (uint32_t)(interval + 1);
}


/*
 * TESLA Parameters
 */
typedef struct {
    uint16_t t_int_ms;             // 2B - Interval duration in ms (e.g., 20ms)
    uint8_t  d;     // 1B - Key disclosure delay d (e.g., 1)
    tf5_slot_time_t t0;      // 4B - T_0: interval 0 start (transmitted in wire format)
    uint32_t chain_len;            // 4B - Number of intervals N
} tf5_tesla_params_t;


/*
 * Complete TESLA Extension Payload
 */
typedef struct {
    uint8_t                    te_version;                    // 1B - TESLA-for-5G Protocol version
    tf5_tesla_params_t         tesla_params;                  // TESLA parameters
    uint32_t                   i;                // 4B - Current interval i
    uint8_t                    key_disclosure[TF5_TESLA_KEY_LEN]; // 16B - K_{i-d}
    uint32_t                   validity_end;          // 3B (wire) - Key expiration (minutes since 2024-01-01)
    uint32_t                   timestamp_ms;                  // 3B (wire) - Unix epoch timestamp LSB (ms) for replay protection
    uint8_t                    signature[TF5_IBS_SIG_LEN]; // 48B - BLS signature
    uint8_t                    tesla_tag[TF5_TESLA_TAG_LEN];  // 16B - HMAC tag
} tf5_extension_t;

/*
 * gNB-side TESLA State
 */
typedef struct {
    tf5_tesla_params_t tesla_params;

    // Key chain storage: key_chain[0] = K_{-1}, key_chain[1] = K_0, ..., key_chain[N] = K_{N-1}
    // Use tf5_key_interval_to_index() to convert interval to array index
    uint8_t  (*key_chain)[TF5_TESLA_KEY_LEN];      // Dynamically allocated (chain_len + 1 entries)
    uint32_t key_chain_len;                         // Number of intervals N

    // IBS keys
    uint8_t  private_key[TF5_IBS_GNB_SK_LEN];   // 32B - sk_ID (issued by Core PKG)
    uint32_t key_validity_end;                      // Key expiration (minutes since 2024-01-01)

    // Slots per frame (depends on numerology)
    uint16_t slots_per_frame;

    // Initialization flag
    bool     initialized;
} tf5_gnb_state_t;

typedef enum {
  TF5_PHASE_INITIAL = 0, // No SIB1 has been buffered & marked for RRC
  TF5_PHASE_IBS_AUTHENTICATED, // SIB1 authenticated via IBS signature (first-time UE)
  TF5_PHASE_BUFFERED, // An SIB1 has been buffered & marked for RRC
  TF5_PHASE_BUFFERED_AUTHENTICATED,
  TF5_PHASE_RRCSETUP_DEFERRED, // An SIB1 has been buffered & marked for RRC and RRCSetupComplete is deferred
  TF5_PHASE_RRCSETUP_DEFERRED_AUTHENTICATED,
  TF5_PHASE_RRCSETUP_COMPLETE,
} tf5_ue_phase_t;

/*
 * UE-side TESLA State
 */
typedef struct {
    tf5_tesla_params_t tesla_params;
    uint32_t d_offset_slots;          // D bound for safe packet test (in slots, pre-computed)

    // Pre-provisioned Core Master Public Key
    uint8_t  mpk[TF5_IBS_MPK_LEN];  // 96B - Core's MPK = s*Q (G2 point)

    // Verification state (trust anchor for key chain verification)
    int32_t  trust_anchor_idx;        // Interval index of the trust anchor key (-1 for K_{-1})
    uint8_t  trust_anchor_key[TF5_TESLA_KEY_LEN];  // Key used as anchor for chain verification

    // Buffer queue for pending TESLA verification
    tf5_buffer_entry_t buffer_queue[TF5_TESLA_BUFFER_QUEUE_SIZE];
    uint8_t buffer_queue_count;  // Number of valid entries in queue

    uint16_t slots_per_frame; // Slots per frame (depends on numerology)
    bool initialized; // Initialization flag
    bool     chain_bootstrapped;      // TESLA chain established via IBS signature (persistent across SIB1s)
    tf5_ue_phase_t curr_phase; // Current authentication state
    uint8_t  rrcsetup_transaction_id; // Saved transaction ID for deferred RRCSetupComplete (used when phase == RRCSETUP_DEFERRED)
    uint64_t rp_timestamp_window_ms;     // Timestamp window for signature replay protection (default 60000ms)

} tf5_ue_state_t;

/*
 * =============================================================================
 * gNB API Functions
 * =============================================================================
 */

/**
 * Initialize TESLA state on gNB
 *
 * Generates the key chain and sets up static parameters.
 *
 * @param state         Pointer to gNB TESLA state structure
 * @param t_int_ms      Interval duration in milliseconds (e.g., 20)
 * @param d             Key disclosure delay (e.g., 1)
 * @param chain_len     Number of intervals in key chain
 * @param private_key   BLS secret key (32 bytes)
 * @param t0            T_0 timing (HFN/SFN/slot at interval 0 start)
 * @param slots_per_frame Number of slots per frame
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_ALLOC, TF5_ERR_CRYPTO
 */
int tf5_gnb_init(tf5_gnb_state_t *state,
                       uint16_t t_int_ms,
                       uint8_t d,
                       uint32_t chain_len,
                       const uint8_t private_key[TF5_IBS_GNB_SK_LEN],
                       const tf5_slot_time_t *t0,
                       uint16_t slots_per_frame);

/**
 * Free TESLA state resources on gNB
 *
 * @param state         Pointer to gNB TESLA state structure
 */
void tf5_gnb_free(tf5_gnb_state_t *state);

/**
 * Build MAC authentication input buffer
 *
 * Constructs the data to be MAC'd (per RFC 4082):
 * original_SIB1 || gnb_key_validity_end
 *
 * Note: interval_index and key_disclosure are NOT included in MAC input.
 * Note: tesla_params excluded - authenticated by signature.
 *
 * @param out           Output buffer
 * @param out_len       Output: length of data written
 * @param original_sib1 Original SIB1 encoded data (without TESLA extension)
 * @param sib1_len      Length of original SIB1 data
 * @param gnb_key_validity_end  Key expiration (minutes since 2024-01-01 00:00 UTC)
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_BUFFER_OVERFLOW
 */
int tf5_build_mac_auth_input(uint8_t *out,
                                   size_t *out_len,
                                   const uint8_t *original_sib1,
                                   size_t sib1_len,
                                   uint32_t gnb_key_validity_end);

/**
 * Build signature authentication input buffer
 *
 * Constructs the data to be signed:
 * original_SIB1 || tesla_params || gnb_key_validity_end || interval_index || key_disclosure || timestamp_ms
 *
 * @param out           Output buffer
 * @param out_len       Output: length of data written
 * @param original_sib1 Original SIB1 encoded data (without TESLA extension)
 * @param sib1_len      Length of original SIB1 data
 * @param te_version   TESLA protocol version
 * @param tesla_params TESLA parameters (includes T_0)
 * @param gnb_key_validity_end  Key expiration (minutes since 2024-01-01 00:00 UTC)
 * @param interval_index Current interval index
 * @param disclosed_key Disclosed key K_{i-d}
 * @param timestamp_ms  Wall-clock timestamp LSB (ms since Unix epoch) for replay protection (24-bit)
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_BUFFER_OVERFLOW
 */
int tf5_build_sig_auth_input(uint8_t *out,
                                   size_t *out_len,
                                   const uint8_t *original_sib1,
                                   size_t sib1_len,
                                   uint8_t te_version,
                                   const tf5_tesla_params_t *tesla_params,
                                   uint32_t gnb_key_validity_end,
                                   uint32_t interval_index,
                                   const uint8_t disclosed_key[TF5_TESLA_KEY_LEN],
                                   uint32_t timestamp_ms);

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
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_CHAIN_EXHAUSTED,
 *         TF5_ERR_SIGN, TF5_ERR_CRYPTO, or propagated error from sub-operations
 */
int tf5_gnb_prepare_extension(tf5_gnb_state_t *state,
                                    uint16_t sfn,
                                    uint16_t slot,
                                    const uint8_t *original_sib1,
                                    size_t sib1_len,
                                    tf5_extension_t *ext);

/**
 * Pack TESLA extension into binary format
 *
 * @param ext           TESLA extension structure
 * @param buf           Output buffer
 * @param buf_len       Size of output buffer
 * @return Number of bytes written on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_BUFFER_OVERFLOW
 */
int tf5_pack_extension(const tf5_extension_t *ext,
                             uint8_t *buf,
                             size_t buf_len);

/*
 * =============================================================================
 * UE API Functions
 * =============================================================================
 */

/**
 * Initialize TESLA state on UE (IBS mode)
 *
 * @param state         Pointer to UE TESLA state structure
 * @param mpk           Pre-provisioned Core Master Public Key (96 bytes)
 * @param slots_per_frame Number of slots per frame
 * @param d_bound_us    D bound for safe packet test (microseconds)
 * @param rp_timestamp_window_ms Timestamp window for signature replay protection (ms)
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM
 */
int tf5_ue_init(tf5_ue_state_t *state,
                      const uint8_t mpk[TF5_IBS_MPK_LEN],
                      uint16_t slots_per_frame,
                      uint32_t d_bound_us,
                      uint64_t rp_timestamp_window_ms);

/**
 * Free TESLA state resources on UE
 *
 * @param state         Pointer to UE TESLA state structure
 */
void tf5_ue_free(tf5_ue_state_t *state);

/**
 * Unpack TESLA extension from binary format
 *
 * @param buf           Input buffer
 * @param buf_len       Length of input buffer
 * @param ext           Output: unpacked TESLA extension
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_BUFFER_OVERFLOW
 */
int tf5_unpack_extension(const uint8_t *buf,
                               size_t buf_len,
                               tf5_extension_t *ext);

/**
 * Perform safe packet test
 *
 * Verifies that x < i + d where:
 * - x = current interval based on UE's clock
 * - i = claimed interval index
 * - d = disclosure delay
 *
 * Uses ti_hfn from the signed extension as the HFN reference since UE cannot
 * know gNB's HFN during initial SSB synchronization. The signature
 * guarantees ti_hfn hasn't been tampered.
 *
 * Checks that the packet arrived within a safe time window.
 *
 * @param ue_state         Pointer to UE TESLA state structure
 * @param tf5_ext           TESLA extension from received SIB1
 * @param rx_sfn        SFN when packet was received
 * @param rx_slot       Slot when packet was received
 * @return true if packet is safe, false otherwise
 */
bool tf5_ue_safe_packet_test(tf5_ue_state_t *ue_state,
                                   const tf5_extension_t *tf5_ext,
                                   uint16_t rx_sfn,
                                   uint16_t rx_slot);

/**
 * Buffer SIB1 for delayed TESLA verification
 *
 * Per RFC 4082 Section 3.5, buffers SIB1 for verification when key is disclosed.
 * Supports multiple buffered entries (queue).
 *
 * @param state              Pointer to UE TESLA state structure
 * @param auth_input         Authentication input
 * @param auth_input_len     Length of auth input
 * @param interval_index     Interval index of this SIB1
 * @param tag                TESLA tag from SIB1
 * @param triggered_rrc_setup True if this SIB1 triggered the current RRC session
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_BUFFER_OVERFLOW
 */
int tf5_ue_buffer_msg(tf5_ue_state_t *state,
                             const uint8_t *auth_input,
                             size_t auth_input_len,
                             uint32_t interval_index,
                             const uint8_t tag[TF5_TESLA_TAG_LEN],
                             bool triggered_rrc_setup);

/**
 * Verify key chain integrity
 *
 * Verifies that disclosed key chains to a previously verified key or K_0.
 *
 * @param ue_state         Pointer to UE TESLA state structure
 * @param disclosed_key Disclosed key to verify
 * @param disclosed_key_interval     Index of disclosed key
 * @return true if key is valid, false otherwise
 */
bool tf5_ue_verify_key_disclosure(tf5_ue_state_t *ue_state,
                                   const uint8_t disclosed_key[TF5_TESLA_KEY_LEN],
                                   uint32_t disclosed_key_interval);

/**
 * Verify buffered SIB1s using an already-verified key
 *
 * Per RFC 4082 Section 3.5: Key verification (step 3) must be done BEFORE
 * packet buffering. This function handles message verification (step 4) using
 * a key that has already been verified by tf5_ue_verify_key_disclosure.
 *
 * @param ue_state              Pointer to UE TESLA state structure
 * @param key_disclosure          Key that has been verified via key chain
 * @param key_disclosure_interval Interval index of verified key
 * @param rrc_trigger_verified    Output: true if any buffered RRC-trigger SIB1 was verified
 * @return TF5_OK on success, TF5_ERR_VERIFY if any MAC verification failed,
 *         or TF5_ERR_INVALID_PARAM, TF5_ERR_NO_DATA
 */
int tf5_tesla_ue_verify_buffered_msgs(tf5_ue_state_t *ue_state,
                                                     const uint8_t key_disclosure[TF5_TESLA_KEY_LEN],
                                                     uint32_t key_disclosure_interval,
                                                     bool *rrc_trigger_verified);

/*
 * =============================================================================
 * File I/O Functions
 * =============================================================================
 */

/**
 * Load BLS secret key and validity period from key file
 *
 * File format: 35 bytes (sk_ID [32] + gnb_key_validity_end [3, big-endian])
 *
 * @param filepath      Path to binary key file (35 bytes)
 * @param privkey_out   Output: 32-byte raw secret key
 * @param validity_out  Output: key validity (minutes since 2024-01-01 00:00 UTC)
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_FILE_OPEN,
 *         TF5_ERR_FILE_IO, TF5_ERR_KEY_INVALID
 */
int tf5_load_gnb_privkey(const char *filepath,
                           uint8_t privkey_out[TF5_IBS_GNB_SK_LEN],
                           uint32_t *validity_out);

/**
 * Load Core's Master Public Key (MPK) from raw binary file
 *
 * @param filepath  Path to binary file containing MPK (96-byte BLS12-381 G2 point)
 * @param mpk_out   Output: 96-byte raw MPK
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_FILE_OPEN, TF5_ERR_FILE_IO
 */
int tf5_load_core_mpk(const char *filepath,
                      uint8_t mpk_out[TF5_IBS_MPK_LEN]);

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

/**
 * Derive MAC key from TESLA key
 *
 * K'_i = F'(K_i) = SHA-256(0x01 || K_i)
 *
 * Per RFC 4082 Section 3.4: uses constant 0x01 for domain separation
 *
 * @param key_in        Input TESLA key K_i (16 bytes)
 * @param mac_key_out   Output MAC key K'_i (32 bytes)
 */
void tf5_derive_mac_key(const uint8_t key_in[TF5_TESLA_KEY_LEN],
                              uint8_t mac_key_out[32]);

/**
 * Compute next key in backward chain
 *
 * K_i = F(K_{i+1}) = SHA-256(0x00 || K_{i+1})[0:15]
 *
 * Per RFC 4082 Section 3.2: uses constant 0x00 for domain separation
 *
 * @param key_next      Input key K_{i+1} (16 bytes)
 * @param key_out       Output key K_i (16 bytes)
 */
void tf5_chain_key(const uint8_t key_next[TF5_TESLA_KEY_LEN],
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
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM
 */
int tf5_compute_tag(const uint8_t key[TF5_TESLA_KEY_LEN],
                          const uint8_t *auth_input,
                          size_t auth_input_len,
                          uint8_t tag_out[TF5_TESLA_TAG_LEN]);

/**
 * Compute absolute slot count from timing struct
 *
 * This handles the full time range without wraparound issues.
 *
 * @param time           Timing struct (SFN/slot)
 * @param slots_per_frame Number of slots per frame
 * @return Absolute slot count since SFN=0, slot=0
 */
static inline uint64_t tf5_absolute_slots(const tf5_slot_time_t *time,
                                                 uint16_t slots_per_frame)
{
    // Total slots = SFN * slots_per_frame + slot
    return (uint64_t)time->sfn * slots_per_frame + time->slot;
}

/**
 * Convert absolute slot count back to timing struct
 *
 * Inverse of tf5_absolute_slots.
 *
 * @param abs_slots      Absolute slot count
 * @param slots_per_frame Number of slots per frame
 * @return Timing struct (SFN/slot)
 */
static inline tf5_slot_time_t tf5_slots_to_slot_time(uint64_t abs_slots,
                                                            uint16_t slots_per_frame)
{
    // abs_slots = sfn * slots_per_frame + slot
    uint16_t sfn = (uint16_t)((abs_slots / slots_per_frame) % TF5_NR_SFN_MODULUS);
    uint16_t slot = abs_slots % slots_per_frame;
    return tf5_slot_time_make(sfn, slot);
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

static inline void tf5_encode_u24_be(uint8_t *buf, uint32_t val) {
    buf[0] = (val >> 16) & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
    buf[2] = val & 0xFF;
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

static inline uint32_t tf5_decode_u24_be(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 16) | ((uint32_t)buf[1] << 8) | buf[2];
}

/* Encode 24-bit gnb_key_validity_end as 3 bytes big-endian */
static inline void tf5_encode_gnb_key_validity_end(uint8_t *buf, uint32_t val) {
    tf5_encode_u24_be(buf, val);
}

/* Decode 24-bit gnb_key_validity_end from 3 bytes big-endian */
static inline uint32_t tf5_decode_gnb_key_validity_end(const uint8_t *buf) {
    return tf5_decode_u24_be(buf);
}

/*
 * =============================================================================
 * Timestamp Functions for Replay Protection
 * =============================================================================
 */

/**
 * Get current wall-clock time in milliseconds since Unix epoch
 *
 * Uses CLOCK_REALTIME for system time. Both gNB and UE must have
 * synchronized clocks (via NTP, GNSS, or PTP) for this to work.
 *
 * @return Current time in milliseconds, or 0 on error
 */
uint64_t tf5_rp_get_wallclock_ms(void);

/**
 * Validate wall-clock timestamp against local time
 *
 * Checks if the received timestamp is within acceptable window of local time.
 * This prevents signature replay attacks using old captured SIB1 messages.
 *
 * @param ue_time_ms      UE's current wall-clock time (ms since epoch)
 * @param ext_timestamp_ms Timestamp LSB from received extension
 * @param window_ms       Acceptable time window in milliseconds
 * @return TF5_OK if valid, TF5_ERR_TIMESTAMP_OLD if too old,
 *         TF5_ERR_TIMESTAMP_FUTURE if too far in future
 */
int tf5_rp_validate_timestamp(uint64_t ue_time_ms,
                                 uint32_t ext_timestamp_ms,
                                 uint64_t window_ms);

#endif /* ENABLE_TF5 */

#endif /* TF5_TESLA_H */
