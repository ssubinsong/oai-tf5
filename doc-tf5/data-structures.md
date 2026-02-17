# Data Structures

[Back to Index](index.md)

**Source**: [tf5_tesla.h](../openair3/SECU/tf5_tesla.h)

---

## Common Timing Structures

### Slot Time (4 bytes)

Generic PHY timing representing a point in 5G NR time:

```c
typedef struct {
    uint16_t sfn;   // 2B - System Frame Number (0-1023)
    uint16_t slot;  // 2B - Slot within frame
} tf5_slot_time_t;
```

Used for T_0 reference, TX timing, and RX timing throughout the TESLA module.

---

## Buffer Entry Structure

Per RFC 4082 Section 3.5, receivers must buffer multiple packets before key disclosure.
This struct represents one buffered SIB1:

```c
typedef struct {
    uint8_t  auth_input[TF5_MAX_AUTH_INPUT];  // 372B - MAC input data
    size_t   auth_input_len;
    uint32_t rx_interval_index;               // Interval index of this SIB1
    uint8_t  tag[TF5_TESLA_TAG_LEN];          // 16B - Received TESLA tag
    bool     valid;                           // Entry contains valid data
    bool     triggered_rrc_setup;             // This SIB1 triggered the current RRC session
} tf5_buffer_entry_t;
```

**Fields**:
- `valid`: Indicates this buffer slot contains a pending SIB1
- `triggered_rrc_setup`: Marks the SIB1 that triggered the current RRC session (for NAS gating)

---

## Authentication Phase Enum

Tracks UE-side authentication progress for NAS gating:

```c
typedef enum {
    TF5_PHASE_INITIAL = 0,           // No SIB1 has been buffered & marked for RRC
    TF5_PHASE_AUTHENTICATED,        // Authenticated via IBS signature or TESLA MAC
    TF5_PHASE_BUFFERED,              // SIB1 buffered, pending TESLA verification
    TF5_PHASE_RRCSETUP_DEFERRED,    // RRCSetup arrived, verification pending
    TF5_PHASE_RRCSETUP_COMPLETE,    // Connection established
} tf5_ue_phase_t;
```

Used by `tf5_ue_state_t` to coordinate RRCSetupComplete deferral.

Phase transitions:
- `INITIAL` → `AUTHENTICATED`: IBS signature verification succeeds (first-time UE)
- `INITIAL` → `BUFFERED`: UE buffers SIB1 for TESLA MAC verification
- `BUFFERED` → `AUTHENTICATED`: MAC verification succeeds before RRCSetup
- `BUFFERED` → `RRCSETUP_DEFERRED`: RRCSetup arrives before auth completes
- `RRCSETUP_DEFERRED` → `RRCSETUP_COMPLETE`: MAC verification succeeds, sends deferred RRCSetupComplete
- `AUTHENTICATED` → `RRCSETUP_COMPLETE`: RRCSetup arrives after auth

---

## TESLA Parameters (11 bytes wire format)

Parameters constant for the lifetime of a key chain.

**Wire format**: 11 bytes (T_0 now transmitted directly, authenticated by signature)
**Key length**: Hardcoded to 16 bytes (128 bits) - not configurable

```c
typedef struct {
    uint16_t t_int_ms;             // 2B - Interval duration (20ms)
    uint8_t  d;                    // 1B - Key disclosure delay (e.g., 1)
    tf5_slot_time_t t0;      // 4B - T_0: interval 0 start (transmitted in wire format)
    uint32_t chain_len;            // 4B - Number of intervals N
} tf5_tesla_params_t;
```

T_0 is transmitted directly in the wire format and authenticated by the IBS signature.

---

## TESLA Extension (134 bytes)

Complete extension appended to SIB1 via `lateNonCriticalExtension`:

```c
typedef struct {
    uint8_t                     te_version;                    // 1B - Protocol version (0x02)
    tf5_tesla_params_t          tesla_params;                  // 11B (wire) - includes T_0
    uint32_t                    i;                             // 4B - Current interval index
    uint8_t                     key_disclosure[TF5_TESLA_KEY_LEN]; // 16B - K_{i-d}
    uint32_t                    validity_end;                  // 3B (wire) - Key expiration (minutes since 2024-01-01)
    uint32_t                    timestamp_ms;                  // 3B - Unix epoch LSB (ms) for replay protection
    uint8_t                     signature[TF5_IBS_SIG_LEN];  // 80B - BLMQ IBS: h[32] || S[48]
    uint8_t                     tesla_tag[TF5_TESLA_TAG_LEN];  // 16B - HMAC tag
} tf5_extension_t;
```

### Key Validity Period

The `validity_end` field enables key expiration:
- **Format**: 24 bits (3 bytes), minutes since 2024-01-01 00:00:00 UTC
- **Range**: 0 to 16,777,215 minutes (~31.9 years, covers until ~2056)
- **Identity Hash**: pk_ID = H_s(Cell_ID || validity_end)

Conversion utilities:
```c
#define TF5_IBS_VALIDITY_EPOCH  1704067200UL  // 2024-01-01 00:00:00 UTC

// Unix seconds to validity_end
uint32_t tf5_ibs_unix_to_gnb_key_validity(uint64_t unix_sec);

// validity_end to Unix seconds
uint64_t tf5_ibs_gnb_key_validity_to_unix(uint32_t validity_end);
```

**Authentication Coverage**:

- **Signature**: SIB1 || te_version || tesla_params || validity_end || i || key_disclosure || timestamp_ms
- **MAC**: SIB1 || validity_end

**Binary Wire Format** (134 bytes, big-endian):

```
Offset  Size  Field
------  ----  -----
0       1     te_version
1       2     t_int_ms
3       1     d (disclosure delay)
4       2     t0.sfn                 (T_0 now transmitted)
6       2     t0.slot
8       4     chain_len
12      3     validity_end           (minutes since 2024-01-01)
15      4     i (interval index)
19      16    key_disclosure
35      3     timestamp_ms
38      80    signature (BLMQ IBS: h[32] || S[48])
118     16    tesla_tag
------
134 bytes total (with BLMQ IBS signatures)

Note: T_0 now transmitted in tesla_params (authenticated by signature)
Note: key_disclosure serves as trusted anchor (every SIB1 is signed)
```

---

## gNB State Structure

```c
typedef struct {
    tf5_tesla_params_t tesla_params;

    // Key chain storage (dynamically allocated, chain_len + 1 entries)
    // Layout: key_chain[0] = K_{-1}, key_chain[1] = K_0, ..., key_chain[N] = K_{N-1}
    // Use tf5_key_interval_to_index(i) to convert interval to array index
    uint8_t  (*key_chain)[TF5_TESLA_KEY_LEN];
    uint32_t key_chain_len;         // Number of intervals N (array has N+1 entries)

    // IBS keys
    uint8_t  private_key[TF5_IBS_GNB_SK_LEN];   // 48B - sk_ID: G1 point [1/(H1(ID)+s)]·P
    uint32_t key_validity_end;      // Key expiration (minutes since 2024-01-01)

    // Timing
    uint16_t slots_per_frame;

    bool     initialized;
} tf5_gnb_state_t;
```

**Key constants**:
- `TF5_TESLA_KEY_LEN` = 16 (128-bit TESLA chain keys)
- `TF5_IBS_GNB_SK_LEN` = 48 (BLMQ IBS secret key, G1 point)

---

## UE State Structure

```c
typedef struct {
    tf5_tesla_params_t tesla_params;
    uint32_t d_offset_slots;          // D bound for safe packet test (in slots, pre-computed)

    // Pre-provisioned Core Master Public Key (IBS mode)
    uint8_t  mpk[TF5_IBS_MPK_LEN];        // 96B - Core's MPK = s*Q (G2 point)

    // Verification state (trust anchor for key chain verification)
    // trust_anchor_idx = -1 indicates K_{-1} (bootstrap key)
    int32_t  trust_anchor_idx;        // Interval index of the trust anchor key
    uint8_t  trust_anchor_key[TF5_TESLA_KEY_LEN];  // Key used as anchor for chain verification

    // Buffer queue for pending TESLA verification (RFC 4082 multi-packet)
    tf5_buffer_entry_t buffer_queue[TF5_TESLA_BUFFER_QUEUE_SIZE];  // Array of 4
    uint8_t buffer_queue_count;       // Number of valid entries in queue

    // Slots per frame (depends on numerology)
    uint16_t slots_per_frame;

    // Initialization flag
    bool     initialized;

    // Parallel authentication state (for NAS gating)
    bool     chain_bootstrapped;      // TESLA chain established via IBS signature (persistent)
    tf5_ue_phase_t curr_phase;           // Current authentication phase

    // Saved transaction ID for deferred RRCSetupComplete (used when phase == RRCSETUP_DEFERRED)
    uint8_t  rrcsetup_transaction_id;

    // Timestamp validation for signature replay protection
    uint64_t rp_timestamp_window_ms;  // Acceptable time window (default 60000ms)
} tf5_ue_state_t;
```

**Key constants**:
- `TF5_IBS_MPK_LEN` = 96 (BLS public key / G2 point)
- `TF5_TESLA_KEY_LEN` = 16 (128-bit TESLA chain keys)
- `TF5_TESLA_BUFFER_QUEUE_SIZE` = 4 (max buffered SIB1s)

**Key design notes:**
- `buffer_queue[4]`: Supports RFC 4082 multi-packet buffering (up to 4 pending SIB1s)
- `buffer_queue_count`: Tracks number of valid entries
- `curr_phase`: Enum for tracking authentication phase (replaces older auth_state)

---

## OAI Integration

For how these structures are integrated into existing OAI types
(`NR_COMMON_channels_t`, `NR_UE_RRC_SI_INFO`) and the full call flow,
see [integration.md](integration.md).
