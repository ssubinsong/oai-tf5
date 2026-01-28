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
} tf5_tesla_slot_time_t;
```

Used for T_0 reference, TX timing, and RX timing throughout the TESLA module.

### D-Bound Parameters (20 bytes)

Parameters for calculating D (upper bound on sender-receiver time offset) per RFC 4082:

```c
typedef struct {
    uint32_t e_sync_us;      // E_sync: Sync accuracy bound (microseconds)
    uint32_t e_s_ppb;        // E_s: gNB max drift rate (parts per billion)
    uint32_t e_r_ppb;        // E_r: UE max drift rate (parts per billion)
    uint32_t delta_t_max_ms; // ΔT_max: Operating horizon (milliseconds)
    uint32_t m_impl_us;      // M_impl: Implementation margin (microseconds)
} tf5_tesla_d_params_t;
```

---

## TESLA Parameters (8 bytes wire format)

Parameters constant for the lifetime of a key chain.

**Wire format**: 8 bytes (T_0 not transmitted, derived by UE from signed fields)
**In-memory**: Includes T_0 for internal use (derived after IBS verification)

```c
typedef struct {
    uint8_t  te_version;           // 1B - Protocol version (0x01)
    uint16_t t_int_ms;             // 2B - Interval duration (20ms)
    uint8_t  disclosure_delay;     // 1B - Key disclosure delay (1)
    // T_0 NOT in wire format - derived by UE: T_0 = timesync - (i × T_int)
    tf5_tesla_slot_time_t t0;      // 4B - T_0: interval 0 start (NOT in wire, derived by UE)
    uint32_t chain_len;            // 4B - Number of intervals N
} tf5_tesla_params_t;
```

### T_0 Derivation

Since T_0 is not transmitted in the wire format, the UE derives it from signed fields:

```
T_0 = timesync_info - (interval_index × T_int)
```

This derivation is performed via `tf5_tesla_derive_t0()` after IBS signature verification.
All components needed for derivation (timesync_info, interval_index, T_int) are authenticated by the signature.

---

## Time Synchronization Info (4 bytes)

Timing information for UE-gNB time synchronization. HFN is now obtained from hyperSFN-r17 in SIB1-v1700-IEs:

```c
typedef struct {
    uint16_t sfn;   // 2B - System Frame Number (0-1023)
    uint16_t slot;  // 2B - Slot within frame
} tf5_tesla_timesync_info_t;
```

Field access: `.sfn`, `.slot`

---

## TESLA Extension (107 bytes)

Complete extension appended to SIB1 via `lateNonCriticalExtension`:

```c
typedef struct {
    tf5_tesla_params_t          tesla_params;    // 8B (wire) - T_0 derived by UE
    uint32_t                    gnb_key_validity_end;  // 3B (wire) - Key expiration (minutes since 2024-01-01)
    tf5_tesla_timesync_info_t   timesync_info;   // 4B (sfn + slot only)
    uint32_t                    interval_index;  // 4B - Current interval i
    uint8_t                     disclosed_key[16]; // 16B - K_{i-d} (serves as trusted anchor)
    uint64_t                    timestamp_ms;    // 8B - Unix epoch (ms) for replay protection
    uint8_t  gnb_signature[48];                  // 48B - BLS signature
    uint8_t  tesla_tag[16];                      // 16B - HMAC tag
} tf5_tesla_extension_t;
```

### Key Validity Period

The `gnb_key_validity_end` field enables key expiration:
- **Format**: 24 bits (3 bytes), minutes since 2024-01-01 00:00:00 UTC
- **Range**: 0 to 16,777,215 minutes (~31.9 years, covers until ~2056)
- **Identity Hash**: pk_ID = H_s(Cell_ID || gnb_key_validity_end)

Conversion utilities:
```c
#define TF5_VALIDITY_EPOCH  1704067200UL  // 2024-01-01 00:00:00 UTC

// Unix seconds to gnb_key_validity_end
uint32_t tf5_ibs_unix_to_gnb_key_validity(uint64_t unix_sec);

// gnb_key_validity_end to Unix seconds
uint64_t tf5_ibs_gnb_key_validity_to_unix(uint32_t gnb_key_validity_end);
```

**Authentication Coverage**:

- **Signature**: SIB1 || tesla_params || gnb_key_validity_end || timesync_info || interval_index || disclosed_key || timestamp_ms
- **MAC**: SIB1 || tesla_params || gnb_key_validity_end || timesync_info

**Binary Wire Format** (107 bytes, big-endian):

```
Offset  Size  Field
------  ----  -----
0       1     te_version
1       2     t_int_ms
3       1     disclosure_delay
4       4     chain_len              (T_0 REMOVED - derived by UE)
8       3     gnb_key_validity_end   (minutes since 2024-01-01)
11      2     timesync_info.sfn
13      2     timesync_info.slot
15      4     interval_index
19      16    disclosed_key
35      8     timestamp_ms
43      48    gnb_signature (BLS)
91      16    tesla_tag
------
107 bytes total (with BLS signatures)

Note: T_0 not in wire format - UE derives from signed fields: T_0 = timesync - (i × T_int)
Note: root_key removed - disclosed_key serves as trusted anchor (every SIB1 is signed)
```

---

## gNB State Structure

```c
typedef struct {
    tf5_tesla_params_t params;

    // Key chain storage (dynamically allocated)
    uint8_t  (*key_chain)[16];    // K_0 ... K_N
    uint32_t key_chain_len;

    // Current state
    uint32_t current_interval;

    // IBS keys
    uint8_t  gnb_private_key[32];   // sk_ID (issued by Core PKG)
    uint8_t  gnb_cell_id[5];        // NR Cell ID (36 bits)
    uint32_t gnb_key_validity_end;  // Key expiration (minutes since 2024-01-01)

    // Timing
    uint16_t slots_per_frame;

    bool     initialized;
} tf5_tesla_gnb_state_t;
```

---

## UE State Structure

```c
typedef struct {
    tf5_tesla_params_t tesla_params;

    // Pre-provisioned core MPK
    uint8_t  mpk[96];  // BLS public key (G2)
    bool     has_mpk;

    // Verification state
    bool     params_received;
    bool     last_verified_key_valid;
    uint32_t last_verified_key_idx;
    uint8_t  last_verified_key[16];

    // Buffered SIB1 pending verification
    struct {
        uint8_t  auth_input[512];
        size_t   auth_input_len;
        uint32_t interval_index;
        uint8_t  tag[16];
        tf5_tesla_slot_time_t rx_time;  // RX timing (SFN/slot)
        bool     pending;
    } buffer;

    uint16_t slots_per_frame;
    bool     initialized;

    // Parallel authentication state
    bool     k0_trusted;
    bool     sib1_authenticated;
    bool     auth_in_progress;
    bool     auth_failed;
    bool     nas_pending;
    uint64_t auth_start_time;

    // Deferred RRCSetupComplete
    bool     rrcsetup_deferred;
    uint8_t  rrcsetup_transaction_id;

    // Timestamp validation
    uint64_t timestamp_window_ms;

    // Time sync state
    bool     timesync_verified;

    // D calculation parameters
    tf5_tesla_d_params_t d_params;
    uint32_t d_bound_us;  // Calculated D value
} tf5_tesla_ue_state_t;
```

---

## OAI Integration Points

TESLA state is integrated into existing OAI structures:

### gNB: NR_COMMON_channels_t

**Source**: [nr_mac_gNB.h](../openair2/LAYER2/NR_MAC_gNB/nr_mac_gNB.h)

```c
// In NR_COMMON_channels_t:
tf5_tesla_gnb_state_t *tesla_state;      // TESLA state pointer
uint8_t sib1_original[NR_MAX_SIB_LENGTH / 8];  // Original SIB1 for signing
int sib1_original_length;
```

### UE: NR_UE_RRC_SI_INFO

**Source**: [rrc_defs.h](../openair2/RRC/NR_UE/rrc_defs.h)

```c
// In NR_UE_RRC_SI_INFO:
tf5_tesla_ue_state_t *tesla_state;       // TESLA state pointer
```
