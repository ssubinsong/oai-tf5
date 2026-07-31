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
#define TF5_VERSION                 0x02

/* ── TESLA Chain & MAC Constants ───────────────────────── */
#define TF5_TESLA_KEY_LEN           16      // 128-bit chain keys
#define TF5_TESLA_TAG_LEN           16      // Truncated HMAC-SHA256
#define TF5_DS_PREFIX_CHAIN_KEY     0x00    // F(K_{i+1}) domain separation
#define TF5_DS_PREFIX_MAC_KEY       0x01    // F'(K_i) domain separation

/* ── Buffer & Wire Format Sizes ────────────────────────── */
#define TF5_MAX_AUTH_INPUT          390     // Max auth input buffer size (max SIB1 372B + 1B version_sp + 16B K_0^next + 1B margin)
#define TF5_SIB1_EXT_PACKED_SIZE    53      // Wire format: version_sp(1) + interval(4) + key(16) + k0_next(16) + tag(16)
#define TF5_SIB9_EXT_PACKED_SIZE    135     // Wire format: version(1) + cell_id(5) + params(11) + k0(16) + sig(96) + timestamp(3) + validity(3)

/* ── Default Configuration ─────────────────────────────── */
#define TF5_TESLA_BUFFER_QUEUE_SIZE        16      // Max SIB1s buffered per UE
#define TF5_RP_DEFAULT_TIME_WINDOW_S        10800   // Replay protection window (3 hours, in seconds)

/* ── NR Radio Timing Constants (3GPP TS 38.211) ──────── */
#define TF5_NR_FRAME_DURATION_MS    10      // 1 radio frame = 10ms
#define TF5_NR_FRAME_DURATION_US    10000   // Frame duration in microseconds

/* ── Replay Protection Timestamp Constants ────────────── */
#define TF5_RP_TIMESTAMP_BITS       24
#define TF5_RP_TIMESTAMP_MASK       ((1u << TF5_RP_TIMESTAMP_BITS) - 1)   // 0xFFFFFF
#define TF5_RP_TIMESTAMP_HALF       (1u << (TF5_RP_TIMESTAMP_BITS - 1))   // 0x800000

/* ── Wire Format Sizes ────────────────────────────────── */
#define TF5_TESLA_PARAMS_PACKED_SIZE  11    // t_int(2) + d(1) + t0(4) + chain_len(4)
#define TF5_SIG_AUTH_OVERHEAD         (1 + TF5_IBS_CELL_ID_LEN + TF5_TESLA_PARAMS_PACKED_SIZE + TF5_TESLA_KEY_LEN + 3 + TF5_IBS_VALIDITY_PERIOD_LEN)  // 39 bytes: version(1) + cell_id(5) + params(11) + K_0(16) + timestamp(3) + validity(3)

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
    uint16_t t_int_ms;             // 2B - Interval duration in ms (e.g., 160ms)
    uint8_t  d;     // 1B - Key disclosure delay d (e.g., 1)
    tf5_slot_time_t t0;      // 4B - T_0: interval 0 start (transmitted in wire format)
    uint32_t chain_len;            // 4B - Number of intervals N
} tf5_tesla_params_t;


/*
 * Complete TESLA Extension Payload
 */
typedef struct {
    uint8_t                    te_version;
    uint8_t                    sp_next;                              // 1 bit
    uint8_t                    cell_id[TF5_IBS_CELL_ID_LEN];        // 5B
    tf5_tesla_params_t         tesla_params;
    uint32_t                   i;
    uint8_t                    key_disclosure[TF5_TESLA_KEY_LEN];   // 16B
    uint8_t                    k0[TF5_TESLA_KEY_LEN];               // 16B
    uint8_t                    k0_next[TF5_TESLA_KEY_LEN];          // 16B
    uint32_t                   validity_end;
    uint32_t                   timestamp_s;
    uint8_t                    signature[TF5_IBS_SIG_LEN];          // 96B
    uint8_t                    tesla_tag[TF5_TESLA_TAG_LEN];        // 16B
} tf5_extension_t;

/*
 * SIB1 extension: per-interval data (MAC tag + key disclosure)
 */
typedef struct {
    uint8_t  te_version;
    uint8_t  sp_next;                               // 1 bit - Same-params flag (packed into version byte on wire)
    uint32_t i;                                     // interval index
    uint8_t  key_disclosure[TF5_TESLA_KEY_LEN];     // 16B
    uint8_t  k0_next[TF5_TESLA_KEY_LEN];            // 16B - Next-chain commitment (zeros when unused)
    uint8_t  tesla_tag[TF5_TESLA_TAG_LEN];          // 16B
} tf5_sib1_ext_t;

/*
 * SIB9 extension: TESLA params + IBS signature
 */
typedef struct {
    uint8_t            te_version;
    uint8_t            cell_id[TF5_IBS_CELL_ID_LEN]; // 5B - NR Cell Identity
    tf5_tesla_params_t tesla_params;                  // 11B
    uint8_t            k0[TF5_TESLA_KEY_LEN];         // 16B - Chain commitment K_0
    uint8_t            signature[TF5_IBS_SIG_LEN];    // 96B
    uint32_t           timestamp_s;                   // 3B wire
    uint32_t           validity_end;                  // 3B wire
} tf5_sib9_ext_t;

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
    uint8_t  private_key[TF5_IBS_GNB_SK_LEN];   // 64B - sk_id: y[32] + pk[32] (issued by Core PKG)
    uint32_t key_validity_end;                      // Key expiration (minutes since 2024-01-01)
    uint8_t  cell_id[TF5_IBS_CELL_ID_LEN];         // 5B - NR Cell Identity (for SIB9 construction)

    // IBS signature precomputation table (offline/online signing split)
    // Pre-generates (r, R=r·B) nonce pairs at init time, removing the expensive
    // base-point scalar multiplication from the per-SIB1 online signing path.
    tf5_ibs_sign_precomp_t *sign_precomps;          // Pre-generated nonce commitments
    uint32_t sign_precomp_count;                    // Total entries allocated
    uint32_t sign_precomp_next;                     // Next entry to consume

    // Slots per frame (depends on numerology)
    uint16_t slots_per_frame;

    // Initialization flag
    bool     initialized;
    bool     sib9_pdu_cached;                       // SIB9 PDU already signed & encoded (once per chain)
} tf5_gnb_state_t;

typedef enum {
  TF5_PHASE_INITIAL = 0,           // No SIB1 has been buffered & marked for RRC
  TF5_PHASE_BUFFERED,              // SIB1 buffered, pending TESLA verification
  TF5_PHASE_AUTHENTICATED,        // Authenticated via IBS signature or TESLA MAC
} tf5_ue_phase_t;

/*
 * UE-side TESLA State
 */
typedef struct {
    tf5_tesla_params_t tesla_params;
    uint32_t d_offset_slots;          // D bound for safe packet test (in slots, pre-computed)

    // Pre-provisioned Core Master Public Key
    uint8_t  mpk[TF5_IBS_MPK_LEN];  // 32B - Core's MPK = z·B (Ed25519 point)

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
    uint64_t rp_timestamp_window_s;      // Timestamp window for signature replay protection (default 10800s)
    uint8_t cid_boot[TF5_IBS_CELL_ID_LEN];  // Cell ID from SIB9 bootstrap (Alg 2 step 2)
    bool initial_tesla_verified;  // true after first TESLA MAC verification post-IBS

    // Returning UE simulation fields (--tf5-returning-ue mode)
    bool returning_ue_sim;          // --tf5-returning-ue mode enabled
    bool returning_release_done;    // Phase 1 complete, SIB1 re-acquisition scheduled
    bool returning_idle_phase;      // Awaiting returning path SIB1
    bool returning_auth_pending;    // Returning SIB1 buffered, awaiting deferred verification
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
 * @param t_int_ms      Interval duration in milliseconds (e.g., 160)
 * @param d             Key disclosure delay (e.g., 1)
 * @param chain_len     Number of intervals in key chain
 * @param private_key   GG09 Schnorr IBS secret key (64 bytes: y[32] + pk[32])
 * @param cell_id       NR Cell Identity (5 bytes)
 * @param t0            T_0 timing (HFN/SFN/slot at interval 0 start)
 * @param slots_per_frame Number of slots per frame
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_ALLOC, TF5_ERR_CRYPTO
 */
int tf5_gnb_init(tf5_gnb_state_t *state,
                 uint16_t t_int_ms,
                 uint8_t d,
                 uint32_t chain_len,
                 const uint8_t private_key[TF5_IBS_GNB_SK_LEN],
                 const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
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
 * Constructs the data to be MAC'd:
 * original_SIB1 || version_sp_byte || K_0^next
 *
 * SIB1 content is the sole TESLA MAC authentication target.
 * TESLA params are authenticated separately by IBS signature in SIB9.
 *
 * @param out           Output buffer
 * @param out_len       Output: length of data written
 * @param original_sib1 Original SIB1 encoded data (without TESLA extension)
 * @param sib1_len      Length of original SIB1 data
 * @param version_sp_byte Version byte with sp_next flag packed in MSB
 * @param k0_next       Next-chain commitment K_0^next (16 bytes)
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_BUFFER_OVERFLOW
 */
int tf5_build_mac_auth_input(uint8_t *out,
                             size_t *out_len,
                             const uint8_t *original_sib1,
                             size_t sib1_len,
                             uint8_t version_sp_byte,
                             const uint8_t k0_next[TF5_TESLA_KEY_LEN]);

/**
 * Build signature authentication input buffer
 *
 * Constructs the data to be signed (SIB9 data only, no SIB1 content):
 * te_version || cell_id || tesla_params || K_0 || timestamp_s || validity_end
 *
 * IBS authenticates TESLA params only. SIB1 content is authenticated by TESLA MAC.
 *
 * @param out           Output buffer
 * @param out_len       Output: length of data written
 * @param te_version    TESLA protocol version
 * @param cell_id       NR Cell Identity (5 bytes)
 * @param tesla_params  TESLA parameters (includes T_0)
 * @param k0            Chain commitment K_0 (16 bytes)
 * @param timestamp_s   Wall-clock timestamp LSB (seconds since Unix epoch) for replay protection (24-bit)
 * @param validity_end  Key expiration (minutes since 2024-01-01 00:00 UTC)
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_BUFFER_OVERFLOW
 */
int tf5_build_sig_auth_input(uint8_t *out,
                             size_t *out_len,
                             uint8_t te_version,
                             const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                             const tf5_tesla_params_t *tesla_params,
                             const uint8_t k0[TF5_TESLA_KEY_LEN],
                             uint32_t timestamp_s,
                             uint32_t validity_end);

/**
 * Pack SIB1 extension (per-interval data) into binary format
 *
 * @param ext       SIB1 extension structure
 * @param buf       Output buffer
 * @param buf_len   Size of output buffer
 * @return Number of bytes written on success, or negative error code
 */
int tf5_pack_sib1_ext(const tf5_sib1_ext_t *ext, uint8_t *buf, size_t buf_len);

/**
 * Unpack SIB1 extension from binary format
 *
 * @param buf       Input buffer
 * @param buf_len   Length of input buffer
 * @param ext       Output: unpacked SIB1 extension
 * @return TF5_OK on success, or negative error code
 */
int tf5_unpack_sib1_ext(const uint8_t *buf, size_t buf_len, tf5_sib1_ext_t *ext);

/**
 * Pack SIB9 extension (TESLA params + IBS signature) into binary format
 *
 * @param ext       SIB9 extension structure
 * @param buf       Output buffer
 * @param buf_len   Size of output buffer
 * @return Number of bytes written on success, or negative error code
 */
int tf5_pack_sib9_ext(const tf5_sib9_ext_t *ext, uint8_t *buf, size_t buf_len);

/**
 * Unpack SIB9 extension from binary format
 *
 * @param buf       Input buffer
 * @param buf_len   Length of input buffer
 * @param ext       Output: unpacked SIB9 extension
 * @return TF5_OK on success, or negative error code
 */
int tf5_unpack_sib9_ext(const uint8_t *buf, size_t buf_len, tf5_sib9_ext_t *ext);

/*
 * =============================================================================
 * UE API Functions
 * =============================================================================
 */

/**
 * Initialize TESLA state on UE (IBS mode)
 *
 * @param state         Pointer to UE TESLA state structure
 * @param mpk           Pre-provisioned Core Master Public Key (32 bytes)
 * @param slots_per_frame Number of slots per frame
 * @param d_bound_us    D bound for safe packet test (microseconds)
 * @param rp_timestamp_window_s Timestamp window for signature replay protection (seconds)
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM
 */
int tf5_ue_init(tf5_ue_state_t *state,
                      const uint8_t mpk[TF5_IBS_MPK_LEN],
                      uint16_t slots_per_frame,
                      uint32_t d_bound_us,
                      uint64_t rp_timestamp_window_s);

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
 * @return TF5_OK on success, or TF5_ERR_INVALID_PARAM, TF5_ERR_BUFFER_OVERFLOW
 */
int tf5_ue_buffer_msg(tf5_ue_state_t *state,
                             const uint8_t *auth_input,
                             size_t auth_input_len,
                             uint32_t interval_index,
                             const uint8_t tag[TF5_TESLA_TAG_LEN]);

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
 * @return TF5_OK on success, TF5_ERR_VERIFY if any MAC verification failed,
 *         or TF5_ERR_INVALID_PARAM, TF5_ERR_NO_DATA
 */
int tf5_tesla_ue_verify_buffered_msgs(tf5_ue_state_t *ue_state,
                                                     const uint8_t key_disclosure[TF5_TESLA_KEY_LEN],
                                                     uint32_t key_disclosure_interval);

/*
 * =============================================================================
 * File I/O Functions
 * =============================================================================
 */

/**
 * Load GG09 Schnorr IBS secret key and validity period from key file
 *
 * File format: 67 bytes (sk_id [64, y[32]+pk[32]] + gnb_key_validity_end [3, big-endian])
 *
 * @param filepath      Path to binary key file (67 bytes)
 * @param privkey_out   Output: 64-byte secret key (y[32] + pk[32])
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
 * @param filepath  Path to binary file containing MPK (32-byte Ed25519 point)
 * @param mpk_out   Output: 32-byte raw MPK
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
 * @param ue_time_s       UE's current wall-clock time (seconds since epoch)
 * @param ext_timestamp_s Timestamp LSB from received extension
 * @param window_s        Acceptable time window in seconds
 * @return TF5_OK if valid, TF5_ERR_TIMESTAMP_OLD if too old,
 *         TF5_ERR_TIMESTAMP_FUTURE if too far in future
 */
int tf5_rp_validate_timestamp(uint64_t ue_time_s,
                                 uint32_t ext_timestamp_s,
                                 uint64_t window_s);

#endif /* ENABLE_TF5 */

#endif /* TF5_TESLA_H */
