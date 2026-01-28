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

#include "tf5_tesla_sig.h"  // BLS signature functions

/*
 * TESLA Configuration Constants
 * Note: TF5_TESLA_KEY_LEN is hardcoded (not configurable) per design.
 */
#define TF5_TESLA_KEY_LEN           16      // 128-bit TESLA chain keys (hardcoded)
#define TF5_TESLA_TAG_LEN           16      // Truncated HMAC-SHA256 to 128 bits
#define TF5_TESLA_SIG_LEN           TF5_BLS_SIGNATURE_LEN   // BLS signature length (48 bytes)
#define TF5_TESLA_PUBKEY_LEN        TF5_BLS_PUBLIC_KEY_LEN  // BLS public key length (96 bytes)
#define TF5_TESLA_CHAIN_LEN         65536   // ~21 minutes at T_int=20ms
#define TF5_TESLA_MAX_SIB1_LEN      374     // Max SIB1 encoded size (2976 bits)
#define TF5_TESLA_MAX_AUTH_INPUT    512     // Max auth input buffer size
#define TF5_TESLA_TIMESTAMP_LEN     8       // 64-bit Unix timestamp (ms)
#define TF5_TESLA_DEFAULT_TIME_WINDOW_MS  60000   // 60 seconds default window
#define TF5_TESLA_BUFFER_QUEUE_SIZE       4       // Max SIB1s buffered per RFC 4082 multi-packet

/*
 * Default D parameters (CLI-configurable)
 *
 * D is the upper bound on (sender_time - receiver_time), per RFC 4082 Section 2.2.
 * These defaults were pre-calculated from the formula:
 * D = E_sync + (E_s + E_r) * ΔT_max + M_impl
 * With: E_sync=500us, E_s=100ppb, E_r=10000ppb, ΔT_max=10.24s, M_impl=1000us => D≈1604us
 */
#define TF5_DEFAULT_D_BOUND_US           1604    // Pre-calculated D bound (microseconds)
#define TF5_DEFAULT_INITIAL_SYNC_US      500     // E_sync for initial timesync check (microseconds)

// Protocol version
#define TF5_TESLA_VERSION           0x01

// Crypto suite identifiers
#define TF5_CRYPTO_SUITE_HMAC_SHA256_IBS  0x03   // IBS-BLS (Identity-Based Signature)

/*
 * IBS (Identity-Based Signature) Constants
 *
 * NR Cell ID is used as the gNB identity for IBS key derivation.
 * UE derives gNB's verification key from Cell ID, validity period, and Core's MPK.
 */
#define TF5_IBS_CELL_ID_LEN   5    // 36 bits = 5 bytes (per 3GPP TS 38.331)
#define TF5_IBS_CELL_ID_BITS  36

/*
 * Key validity period: 24 bits = 3 bytes
 * Encodes minutes since 2024-01-01 00:00:00 UTC
 * Range: 0 to 16,777,215 minutes (~31.9 years, covers until ~2056)
 *
 * Identity hash: pk_ID = H_s(Cell_ID || gnb_key_validity_end)
 */
#define TF5_IBS_VALIDITY_LEN   3     // 24-bit minutes since epoch
#define TF5_VALIDITY_EPOCH     1704067200UL  // 2024-01-01 00:00:00 UTC (Unix seconds)

// Domain Separation Tag for H_s (identity-to-scalar hash)
#define TF5_IBS_DST_HS        "TF5_IBS_BLS12381_XMD:SHA-256_H_s_v1"
#define TF5_IBS_DST_HS_LEN    35

/*
 * =============================================================================
 * Common Timing Structures
 * =============================================================================
 */

/**
 * Generic PHY Timing (SFN/slot)
 *
 * Represents a point in 5G NR time. Used for T_0 reference, TX timing,
 * and RX timing throughout the TESLA module.
 * Total size: 4 bytes
 */
typedef struct {
    uint16_t sfn;   // 2B - System Frame Number (0-1023)
    uint16_t slot;  // 2B - Slot within frame
} tf5_tesla_slot_time_t;


/**
 * Buffer Entry for Pending TESLA Verification
 *
 * Per RFC 4082 Section 3.5, receivers must buffer multiple packets
 * before key disclosure. This struct represents one buffered SIB1.
 */
typedef struct {
    uint8_t  auth_input[TF5_TESLA_MAX_AUTH_INPUT];
    size_t   auth_input_len;
    uint32_t interval_index;
    uint8_t  tag[TF5_TESLA_TAG_LEN];
    tf5_tesla_slot_time_t rx_time;   // RX timing (SFN/slot when received)
    bool     valid;                  // Entry contains valid data
    bool     triggered_rrc_setup;    // This SIB1 triggered the current RRC session
} tf5_tesla_buffer_entry_t;

/* Helper to construct slot_time_t inline */
static inline tf5_tesla_slot_time_t tf5_slot_time_make(uint16_t sfn,
                                                        uint16_t slot)
{
    return (tf5_tesla_slot_time_t){.sfn = sfn, .slot = slot};
}


/*
 * TESLA Parameters
 *
 * These parameters are constant for the lifetime of a key chain.
 * Wire format size: 8 bytes (T_0 not transmitted, derived by UE)
 * In-memory size: includes T_0 for internal use (derived after IBS verification)
 *
 * Note: T_0 is derived by UE from signed fields: T_0 = timesync - (i × T_int)
 * Note: root_key (K_0) is not included here. Since every SIB1 is signed,
 * the disclosed_key serves as a trusted anchor for key chain verification.
 */
typedef struct {
    uint8_t  te_version;           // 1B - Protocol version
    uint16_t t_int_ms;             // 2B - Interval duration in ms (e.g., 20ms)
    uint8_t  disclosure_delay;     // 1B - Key disclosure delay d (e.g., 1)
    tf5_tesla_slot_time_t t0;      // 4B - T_0: interval 0 start (NOT in wire format, derived by UE)
    uint32_t chain_len;            // 4B - Number of intervals N
} tf5_tesla_params_t;

/**
 * Time Synchronization Info (4 bytes)
 *
 * Alias for tf5_tesla_slot_time_t used in TESLA extension wire format.
 * HFN is obtained from hyperSFN-r17 in SIB1-v1700-IEs (standard 3GPP).
 */
typedef tf5_tesla_slot_time_t tf5_tesla_timesync_info_t;

/*
 * Complete TESLA Extension Payload
 *
 * This structure represents the complete TESLA data appended to SIB1
 * via lateNonCriticalExtension.
 *
 * Signature authenticates: SIB1 || tesla_params || gnb_key_validity_end || timesync_info || interval_index || disclosed_key || timestamp_ms
 * MAC authenticates:       SIB1 || tesla_params || gnb_key_validity_end || timesync_info (per RFC 4082)
 *
 * Wire format size: 107 bytes (with BLS signatures)
 *   tesla_params(8) + gnb_key_validity_end(3) + timesync_info(4) + interval_index(4) +
 *   disclosed_key(16) + timestamp_ms(8) + gnb_signature(48) + tesla_tag(16)
 *
 * Note: T_0 not in wire format - UE derives from signed fields
 * Note: HFN removed from timesync_info - now obtained from hyperSFN-r17
 * Note: root_key removed - disclosed_key serves as trusted anchor (every SIB1 is signed)
 */
typedef struct {
    tf5_tesla_params_t         tesla_params;                  // 8B (wire) - T_0 derived by UE
    uint32_t                   gnb_key_validity_end;          // 3B (wire) - Key expiration (minutes since 2024-01-01)
    tf5_tesla_timesync_info_t  timesync_info;                 // 4B (sfn + slot only)
    uint32_t                   interval_index;                // 4B - Current interval i
    uint8_t                    disclosed_key[TF5_TESLA_KEY_LEN]; // 16B - K_{i-d}
    uint64_t                   timestamp_ms;                  // 8B - Unix epoch timestamp (ms) for replay protection
    uint8_t                    gnb_signature[TF5_TESLA_SIG_LEN]; // 48B - BLS signature
    uint8_t                    tesla_tag[TF5_TESLA_TAG_LEN];  // 16B - HMAC tag
} tf5_tesla_extension_t;

/*
 * gNB-side TESLA State
 *
 * Maintains the key chain and parameters for TESLA authentication on gNB.
 */
typedef struct {
    tf5_tesla_params_t params;

    // Key chain storage (backward chain: K_i = F(K_{i+1}))
    uint8_t  (*key_chain)[TF5_TESLA_KEY_LEN];      // Dynamically allocated
    uint32_t key_chain_len;

    // Current state
    uint32_t current_interval;

    // HFN tracking moved to NR_COMMON_channels_t (cc->hfn)
    // gNB tracks HFN as a core feature, not TESLA-specific

    // IBS keys
    uint8_t  gnb_private_key[TF5_BLS_SECRET_KEY_LEN];   // 32B - sk_ID (issued by Core PKG)
    uint8_t  gnb_cell_id[TF5_IBS_CELL_ID_LEN];          // 5B - NR Cell ID (36 bits)
    uint32_t gnb_key_validity_end;                      // Key expiration (minutes since 2024-01-01)

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
    tf5_tesla_params_t tesla_params;

    // Pre-provisioned Core Master Public Key (IBS mode)
    uint8_t  mpk[TF5_TESLA_PUBKEY_LEN];  // 96B - Core's MPK = s*Q (G2 point)
    bool     has_mpk;                     // Is Core MPK configured?

    // Verification state
    bool     params_received;         // Have we received static params?
    bool     last_verified_key_valid; // Is last_verified_key initialized with authenticated key?
    uint32_t last_verified_key_idx;   // Index of last verified key
    uint8_t  last_verified_key[TF5_TESLA_KEY_LEN];

    // Buffer queue for pending TESLA verification (RFC 4082 multi-packet)
    tf5_tesla_buffer_entry_t buffer_queue[TF5_TESLA_BUFFER_QUEUE_SIZE];
    uint8_t buffer_queue_count;  // Number of valid entries in queue

    // Slots per frame (depends on numerology)
    uint16_t slots_per_frame;

    // Initialization flag
    bool     initialized;

    // Parallel authentication state (for NAS gating)
    bool     k0_trusted;              // K_0 authenticated via BLS signature (persistent across SIB1s)
    bool     sib1_authenticated;      // SIB1 that triggered RRC setup is verified (sig OR tesla)
    bool     auth_in_progress;        // Authentication running in parallel with RACH
    bool     auth_failed;             // Authentication failed - must abort RRC
    bool     nas_pending;             // NAS waiting for authentication to complete
    uint64_t auth_start_time;         // When authentication started (ms, for timeout)

    // Deferred RRCSetupComplete (when auth is pending at RRCSetup time)
    bool     rrcsetup_deferred;       // RRCSetupComplete deferred waiting for auth
    uint8_t  rrcsetup_transaction_id; // Saved transaction ID for deferred RRCSetupComplete

    // Timestamp validation for signature replay protection
    uint64_t timestamp_window_ms;     // Acceptable time window (default 60000ms)

    // Time sync verification state (per doc-tf5/time-sync.md Section 4)
    bool     timesync_verified;       // Has SSB-based time sync been verified?

    // D parameters (CLI-configured, used by receiver)
    // Per RFC 4082 Section 2.2, D is the upper bound on (sender_time - receiver_time)
    uint32_t d_bound_us;              // D bound for safe packet test (microseconds)
    uint32_t initial_sync_bound_us;   // Bound for initial timesync check (microseconds)
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
 *
 * @param state         Pointer to gNB TESLA state structure
 * @param t_int_ms      Interval duration in milliseconds (e.g., 20)
 * @param d             Key disclosure delay (e.g., 1)
 * @param chain_len     Number of intervals in key chain
 * @param private_key   BLS secret key (32 bytes)
 * @param t0            T_0 timing (HFN/SFN/slot at interval 0 start)
 * @param slots_per_frame Number of slots per frame
 * @return 0 on success, negative on error
 */
int tf5_tesla_gnb_init(tf5_tesla_gnb_state_t *state,
                       uint16_t t_int_ms,
                       uint8_t d,
                       uint32_t chain_len,
                       const uint8_t private_key[TF5_BLS_SECRET_KEY_LEN],
                       const tf5_tesla_slot_time_t *t0,
                       uint16_t slots_per_frame);

/**
 * Free TESLA state resources on gNB
 *
 * @param state         Pointer to gNB TESLA state structure
 */
void tf5_tesla_gnb_free(tf5_tesla_gnb_state_t *state);

/**
 * Get current interval index from HFN/SFN/slot
 *
 * @param state         Pointer to gNB TESLA state structure
 * @param sfn           Current SFN
 * @param slot          Current slot
 * @return Current interval index
 */
uint32_t tf5_tesla_gnb_get_interval(tf5_tesla_gnb_state_t *state,
                                    uint16_t sfn,
                                    uint16_t slot);

/**
 * Build MAC authentication input buffer
 *
 * Constructs the data to be MAC'd (per RFC 4082):
 * original_SIB1 || gnb_key_validity_end
 *
 * Note: interval_index and disclosed_key are NOT included in MAC input.
 * Note: tesla_params and timesync_info excluded - authenticated by signature.
 *
 * @param out           Output buffer
 * @param out_len       Output: length of data written
 * @param original_sib1 Original SIB1 encoded data (without TESLA extension)
 * @param sib1_len      Length of original SIB1 data
 * @param gnb_key_validity_end  Key expiration (minutes since 2024-01-01 00:00 UTC)
 * @return 0 on success, negative on error
 */
int tf5_tesla_build_mac_auth_input(uint8_t *out,
                                   size_t *out_len,
                                   const uint8_t *original_sib1,
                                   size_t sib1_len,
                                   uint32_t gnb_key_validity_end);

/**
 * Build signature authentication input buffer
 *
 * Constructs the data to be signed:
 * original_SIB1 || tesla_params || gnb_key_validity_end || timesync_info || interval_index || disclosed_key || timestamp_ms
 *
 * @param out           Output buffer
 * @param out_len       Output: length of data written
 * @param original_sib1 Original SIB1 encoded data (without TESLA extension)
 * @param sib1_len      Length of original SIB1 data
 * @param tesla_params  TESLA parameters
 * @param gnb_key_validity_end  Key expiration (minutes since 2024-01-01 00:00 UTC)
 * @param timesync_info Time synchronization info
 * @param interval_index Current interval index
 * @param disclosed_key Disclosed key K_{i-d}
 * @param timestamp_ms  Wall-clock timestamp (ms since Unix epoch) for replay protection
 * @return 0 on success, negative on error
 */
int tf5_tesla_build_sig_auth_input(uint8_t *out,
                                   size_t *out_len,
                                   const uint8_t *original_sib1,
                                   size_t sib1_len,
                                   const tf5_tesla_params_t *tesla_params,
                                   uint32_t gnb_key_validity_end,
                                   const tf5_tesla_timesync_info_t *timesync_info,
                                   uint32_t interval_index,
                                   const uint8_t disclosed_key[TF5_TESLA_KEY_LEN],
                                   uint64_t timestamp_ms);

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
 * Initialize TESLA state on UE (IBS mode)
 *
 * @param state         Pointer to UE TESLA state structure
 * @param mpk           Pre-provisioned Core Master Public Key (96 bytes)
 * @param slots_per_frame Number of slots per frame
 * @param d_bound_us    D bound for safe packet test (microseconds)
 * @param initial_sync_bound_us Bound for initial timesync check (microseconds)
 * @return 0 on success, negative on error
 */
int tf5_tesla_ue_init(tf5_tesla_ue_state_t *state,
                      const uint8_t mpk[TF5_TESLA_PUBKEY_LEN],
                      uint16_t slots_per_frame,
                      uint32_t d_bound_us,
                      uint32_t initial_sync_bound_us);

/**
 * Free TESLA state resources on UE
 *
 * @param state         Pointer to UE TESLA state structure
 */
void tf5_tesla_ue_free(tf5_tesla_ue_state_t *state);

/**
 * Verify initial time synchronization after BLS signature verification
 *
 * Checks that UE's RX timing is consistent with gNB's signed TX timing.
 * Uses initial_sync_bound_us as the bound since no drift has accumulated yet.
 *
 * Per RFC 4082 Section 2.2, this verifies the "loose time synchronization"
 * assumption required for TESLA protocol operation.
 *
 * @param state         UE TESLA state (reads initial_sync_bound_us, slots_per_frame)
 * @param tx            TX timing from signed extension (gNB TX time, only sfn/slot used)
 * @param rx            UE's actual RX timing (from MAC layer, only sfn/slot used)
 * @return 0 if valid, -1 if RX before TX, -2 if diff exceeds initial_sync_bound
 */
int tf5_tesla_verify_initial_timesync(tf5_tesla_ue_state_t *state,
                                      const tf5_tesla_slot_time_t *tx,
                                      const tf5_tesla_slot_time_t *rx);

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
 * Verify IBS signature
 *
 * Verifies signature using Identity-Based Signature scheme:
 *   e(Σ, Q) = e(H_m(auth_input), H_s(cell_id || gnb_key_validity_end) * MPK)
 *
 * @param state         Pointer to UE TESLA state structure (contains MPK)
 * @param cell_id       gNB's NR Cell ID (5 bytes, 36 bits) from SIB1
 * @param gnb_key_validity_end  Key expiration (minutes since 2024-01-01 00:00 UTC)
 * @param auth_input    Authentication input (SIB1 + static + dynamic)
 * @param auth_input_len Length of auth input
 * @param signature     Signature to verify (48 bytes)
 * @return 0 on success (signature valid), negative on error
 */
int tf5_tesla_ue_verify_signature(const tf5_tesla_ue_state_t *state,
                                  const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                                  uint32_t gnb_key_validity_end,
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
 * Uses ti_hfn from the signed extension as the HFN reference since UE cannot
 * know gNB's HFN during initial SSB synchronization. The Ed25519 signature
 * guarantees ti_hfn hasn't been tampered.
 *
 * Checks that the packet arrived within a safe time window.
 *
 * @param state         Pointer to UE TESLA state structure
 * @param ext           TESLA extension from received SIB1
 * @param rx_sfn        SFN when packet was received
 * @param rx_slot       Slot when packet was received
 * @return true if packet is safe, false otherwise
 */
bool tf5_tesla_ue_safe_packet_test(tf5_tesla_ue_state_t *state,
                                   const tf5_tesla_extension_t *ext,
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
 * @param rx_time            RX timing (HFN from signed extension, SFN/slot when received)
 * @param triggered_rrc_setup True if this SIB1 triggered the current RRC session
 * @return 0 on success, negative on error
 */
int tf5_tesla_ue_buffer_sib1(tf5_tesla_ue_state_t *state,
                             const uint8_t *auth_input,
                             size_t auth_input_len,
                             uint32_t interval_index,
                             const uint8_t tag[TF5_TESLA_TAG_LEN],
                             const tf5_tesla_slot_time_t *rx_time,
                             bool triggered_rrc_setup);

/**
 * Verify buffered SIB1 using disclosed key (single entry - legacy)
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
 * Verify all buffered SIB1s for a given interval using disclosed key
 *
 * Per RFC 4082 Section 3.5 Step 4: "The receiver continues to verify and
 * release (or not) any remaining buffered packets that depend on the newly
 * disclosed key K_{i-d}."
 *
 * @param state              Pointer to UE TESLA state structure
 * @param disclosed_key      Disclosed key K_{key_interval}
 * @param key_interval       Interval index of disclosed key
 * @param verified_count     Output: number of successfully verified entries
 * @param failed_count       Output: number of failed verifications
 * @param rrc_trigger_verified Output: true if entry with triggered_rrc_setup was verified
 * @return 0 if at least one verified, negative if all failed or error
 */
int tf5_tesla_ue_verify_all_buffered(tf5_tesla_ue_state_t *state,
                                     const uint8_t disclosed_key[TF5_TESLA_KEY_LEN],
                                     uint32_t key_interval,
                                     int *verified_count,
                                     int *failed_count,
                                     bool *rrc_trigger_verified);

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

/**
 * Verify buffered SIB1s with key recovery for lost disclosures
 *
 * Per RFC 4082 Section 3.5: "Using a disclosed key, we can calculate all
 * previous disclosed keys, so even if packets are lost, we will still be
 * able to verify buffered, safe packets from earlier time intervals."
 *
 * This function derives intermediate keys from disclosed_key down to the
 * earliest buffered interval and verifies all pending entries.
 *
 * @param state              Pointer to UE TESLA state structure
 * @param disclosed_key      Disclosed key K_{disclosed_interval}
 * @param disclosed_interval Interval index of disclosed key
 * @param total_verified     Output: total successfully verified entries
 * @param total_failed       Output: total failed verifications
 * @param rrc_trigger_verified Output: true if RRC-triggering entry verified
 * @return 0 if at least one verified, negative on error:
 *         -1: Invalid parameters
 *         -2: No buffered entries to verify
 *         -5: All entries failed verification
 *         -6: Key chain verification failed
 */
int tf5_tesla_ue_verify_with_key_recovery(
    tf5_tesla_ue_state_t *state,
    const uint8_t disclosed_key[TF5_TESLA_KEY_LEN],
    uint32_t disclosed_interval,
    int *total_verified,
    int *total_failed,
    bool *rrc_trigger_verified);

/*
 * =============================================================================
 * File I/O Functions
 * =============================================================================
 */

/**
 * Load BLS secret key from raw binary file
 *
 * @param filepath      Path to binary file containing BLS secret key (32 bytes)
 * @param privkey_out   Output: 32-byte raw secret key
 * @return 0 on success, negative on error:
 *         -1: Cannot open file
 *         -2: File read error or wrong size
 *         -3: Invalid key format
 */
int tf5_tesla_load_privkey(const char *filepath,
                           uint8_t privkey_out[TF5_BLS_SECRET_KEY_LEN]);

/**
 * Load BLS public key from raw binary file
 *
 * @param filepath      Path to binary file containing BLS public key (96 bytes)
 * @param pubkey_out    Output: 96-byte raw public key
 * @return 0 on success, negative on error:
 *         -1: Cannot open file
 *         -2: File read error or wrong size
 *         -3: Invalid key format
 */
int tf5_tesla_load_pubkey(const char *filepath,
                          uint8_t pubkey_out[TF5_TESLA_PUBKEY_LEN]);

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
void tf5_tesla_derive_mac_key(const uint8_t key_in[TF5_TESLA_KEY_LEN],
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
 * @param current         Current timing (HFN/SFN/slot)
 * @param t0              T_0 timing (HFN/SFN/slot)
 * @param slots_per_frame Number of slots per frame
 * @return Number of slots elapsed (0 if current time is before T_0)
 */
uint64_t tf5_tesla_slots_since_t0(const tf5_tesla_slot_time_t *current,
                                  const tf5_tesla_slot_time_t *t0,
                                  uint16_t slots_per_frame);

/**
 * Get interval index from timing
 *
 * @param current         Current timing (HFN/SFN/slot)
 * @param t0              T_0 timing (HFN/SFN/slot)
 * @param t_int_ms        Interval duration in ms
 * @param slots_per_frame Number of slots per frame
 * @return Interval index
 */
uint32_t tf5_tesla_get_interval_index(const tf5_tesla_slot_time_t *current,
                                      const tf5_tesla_slot_time_t *t0,
                                      uint16_t t_int_ms,
                                      uint16_t slots_per_frame);

/*
 * =============================================================================
 * HFN (Hyper-Frame Number) Helpers
 * =============================================================================
 */

/**
 * Compute absolute slot count from timing struct
 *
 * This handles the full time range without wraparound issues.
 * HFN increments each time SFN wraps from 1023 to 0.
 *
 * @param time           Timing struct (HFN/SFN/slot)
 * @param slots_per_frame Number of slots per frame
 * @return Absolute slot count since SFN=0, slot=0
 */
static inline uint64_t tf5_tesla_absolute_slots(const tf5_tesla_slot_time_t *time,
                                                 uint16_t slots_per_frame)
{
    // Total slots = SFN * slots_per_frame + slot
    return (uint64_t)time->sfn * slots_per_frame + time->slot;
}

/**
 * Alias for tf5_tesla_absolute_slots (consistency with inverse function name)
 */
static inline uint64_t tf5_slot_time_to_slots(const tf5_tesla_slot_time_t *time,
                                               uint16_t slots_per_frame)
{
    return tf5_tesla_absolute_slots(time, slots_per_frame);
}

/**
 * Convert absolute slot count back to timing struct
 *
 * Inverse of tf5_tesla_absolute_slots / tf5_slot_time_to_slots.
 *
 * @param abs_slots      Absolute slot count
 * @param slots_per_frame Number of slots per frame
 * @return Timing struct (SFN/slot)
 */
static inline tf5_tesla_slot_time_t tf5_slots_to_slot_time(uint64_t abs_slots,
                                                            uint16_t slots_per_frame)
{
    // abs_slots = sfn * slots_per_frame + slot
    uint16_t sfn = (uint16_t)((abs_slots / slots_per_frame) % 1024);
    uint16_t slot = abs_slots % slots_per_frame;
    return tf5_slot_time_make(sfn, slot);
}

/**
 * Derive T_0 from signed fields (UE use after IBS verification)
 *
 * Since T_0 is not broadcast in the SIB1 TESLA extension, the UE must derive it
 * from other signed fields. Formula: T_0 = current_time - (interval_index × T_int)
 *
 * @param timesync_info   Current time (SFN/slot) from signed SIB1 extension
 * @param interval_index  Current interval index i
 * @param t_int_ms        Interval duration in milliseconds
 * @param slots_per_frame Number of slots per frame (SCS-dependent)
 * @param out_t0          Output: derived T_0
 * @return 0 on success, -1 on error (e.g., underflow)
 */
int tf5_tesla_derive_t0(const tf5_tesla_timesync_info_t *timesync_info,
                        uint32_t interval_index,
                        uint16_t t_int_ms,
                        uint16_t slots_per_frame,
                        tf5_tesla_slot_time_t *out_t0);

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

static inline void tf5_encode_u64_be(uint8_t *buf, uint64_t val) {
    buf[0] = (val >> 56) & 0xFF;
    buf[1] = (val >> 48) & 0xFF;
    buf[2] = (val >> 40) & 0xFF;
    buf[3] = (val >> 32) & 0xFF;
    buf[4] = (val >> 24) & 0xFF;
    buf[5] = (val >> 16) & 0xFF;
    buf[6] = (val >> 8) & 0xFF;
    buf[7] = val & 0xFF;
}

static inline uint64_t tf5_decode_u64_be(const uint8_t *buf) {
    return ((uint64_t)buf[0] << 56) |
           ((uint64_t)buf[1] << 48) |
           ((uint64_t)buf[2] << 40) |
           ((uint64_t)buf[3] << 32) |
           ((uint64_t)buf[4] << 24) |
           ((uint64_t)buf[5] << 16) |
           ((uint64_t)buf[6] << 8) |
           (uint64_t)buf[7];
}

/* Encode 24-bit gnb_key_validity_end as 3 bytes big-endian */
static inline void tf5_encode_gnb_key_validity_end(uint8_t *buf, uint32_t gnb_key_validity_end) {
    buf[0] = (gnb_key_validity_end >> 16) & 0xFF;
    buf[1] = (gnb_key_validity_end >> 8) & 0xFF;
    buf[2] = gnb_key_validity_end & 0xFF;
}

/* Decode 24-bit gnb_key_validity_end from 3 bytes big-endian */
static inline uint32_t tf5_decode_gnb_key_validity_end(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 16) | ((uint32_t)buf[1] << 8) | buf[2];
}

/*
 * =============================================================================
 * Validity Period Conversion Utilities
 * =============================================================================
 */

/**
 * Convert Unix timestamp to gnb_key_validity_end format
 *
 * @param unix_sec  Unix timestamp (seconds since 1970-01-01)
 * @return Minutes since 2024-01-01 00:00:00 UTC (24-bit value)
 */
static inline uint32_t tf5_ibs_unix_to_gnb_key_validity(uint64_t unix_sec) {
    if (unix_sec <= TF5_VALIDITY_EPOCH) {
        return 0;
    }
    return (uint32_t)((unix_sec - TF5_VALIDITY_EPOCH) / 60);
}

/**
 * Convert gnb_key_validity_end format to Unix timestamp
 *
 * @param gnb_key_validity_end  Minutes since 2024-01-01 00:00:00 UTC
 * @return Unix timestamp (seconds since 1970-01-01)
 */
static inline uint64_t tf5_ibs_gnb_key_validity_to_unix(uint32_t gnb_key_validity_end) {
    return TF5_VALIDITY_EPOCH + (uint64_t)gnb_key_validity_end * 60;
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
uint64_t tf5_tesla_get_wallclock_ms(void);

/**
 * Validate wall-clock timestamp against local time
 *
 * Checks if the received timestamp is within acceptable window of local time.
 * This prevents signature replay attacks using old captured SIB1 messages.
 *
 * @param ue_time_ms      UE's current wall-clock time (ms since epoch)
 * @param ext_timestamp_ms Timestamp from received extension
 * @param window_ms       Acceptable time window in milliseconds
 * @return 0 if valid, -1 if too old, -2 if too far in future
 */
int tf5_tesla_validate_timestamp(uint64_t ue_time_ms,
                                 uint64_t ext_timestamp_ms,
                                 uint64_t window_ms);

#endif /* TF5_ENABLE_TESLA */

#endif /* TF5_TESLA_H */
