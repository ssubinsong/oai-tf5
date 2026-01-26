# Data Structures

[Back to Index](index.md)

**Source**: [tf5_tesla.h](../openair3/SECU/tf5_tesla.h)

---

## Common Timing Structures

### Slot Time (6 bytes)

Generic PHY timing representing a point in 5G NR time:

```c
typedef struct {
    uint16_t hfn;   // 2B - Hyper-Frame Number (for SFN wraparound)
    uint16_t sfn;   // 2B - System Frame Number (0-1023)
    uint16_t slot;  // 2B - Slot within frame
} tf5_tesla_slot_time_t;
```

Used for T_0 reference, TX timing, and RX timing throughout the TESLA module.

### HFN Tracking (RRC Layer via ITTI)

HFN tracking uses symmetric ITTI-based architecture for both gNB and UE:

```c
// In gNB_RRC_INST (nr_rrc_defs.h)
#ifdef TF5_ENABLE_TESLA
uint16_t current_hfn;  // HFN tracked by RRC, incremented on SFN wrap
#endif

// In NR_UE_RRC_INST_t (rrc_defs.h)
#ifdef TF5_ENABLE_TESLA
uint16_t current_hfn;   // HFN tracked by RRC, incremented on SFN wrap
bool hfn_initialized;   // Has HFN been initialized from hyperSFN-r17?
#endif
```

- **gNB**: MAC detects SFN wrap → sends `NRRRC_SFN_WRAP` ITTI → RRC increments `current_hfn`
- **UE**: PHY detects SFN wrap → sends `NRRRC_SFN_WRAP` ITTI → RRC increments `current_hfn`
- **UE**: Also reconciles with hyperSFN-r17 from authenticated SIB1

See [hfn-tracking.md](hfn-tracking.md) for detailed architecture.

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

## Static Parameters (14 bytes)

Parameters constant for the lifetime of a key chain:

```c
typedef struct {
    uint8_t  te_version;           // 1B - Protocol version (0x01)
    uint8_t  crypto_suite_id;      // 1B - Algorithm suite (0x02 for BLS)
    uint16_t t_int_ms;             // 2B - Interval duration (20ms)
    uint8_t  disclosure_delay;     // 1B - Key disclosure delay (1)
    uint8_t  key_len;              // 1B - TESLA key length (16)
    // root_key removed: disclosed_key serves as anchor (every SIB1 is signed)
    tf5_tesla_slot_time_t t0;      // 6B - T_0: interval 0 start (HFN/SFN/slot)
    uint32_t chain_len;            // 4B - Number of intervals N
} tf5_tesla_static_params_t;
```

---

## Time Synchronization Info (4 bytes)

Timing information for UE-gNB time synchronization. HFN is now obtained from hyperSFN-r17 in SIB1-v1700-IEs:

```c
typedef struct {
    uint16_t sfn;   // 2B - System Frame Number (0-1023)
    uint16_t slot;  // 2B - Slot within frame
} tf5_tesla_timesync_info_t;
```

Field access: `.sfn`, `.slot` (HFN obtained separately from hyperSFN-r17)

---

## TESLA Extension (113 bytes)

Complete extension appended to SIB1 via `lateNonCriticalExtension`:

```c
typedef struct {
    tf5_tesla_static_params_t   static_params;   // 14B (root_key removed)
    uint32_t                    validity_end;    // 3B (wire) - Key expiration (minutes since 2024-01-01)
    tf5_tesla_timesync_info_t   timesync_info;   // 4B (sfn + slot only)
    uint32_t                    interval_index;  // 4B - Current interval i
    uint8_t                     disclosed_key[16]; // 16B - K_{i-d} (serves as trusted anchor)
    uint64_t                    timestamp_ms;    // 8B - Unix epoch (ms) for replay protection
    uint8_t  gnb_signature[48];                  // 48B - BLS signature
    uint8_t  tesla_tag[16];                      // 16B - HMAC tag
} tf5_tesla_extension_t;
```

### Key Validity Period

The `validity_end` field enables key expiration:
- **Format**: 24 bits (3 bytes), minutes since 2024-01-01 00:00:00 UTC
- **Range**: 0 to 16,777,215 minutes (~31.9 years, covers until ~2056)
- **Identity Hash**: pk_ID = H_s(Cell_ID || validity_end)

Conversion utilities:
```c
#define TF5_VALIDITY_EPOCH  1704067200UL  // 2024-01-01 00:00:00 UTC

// Unix seconds to validity_end
uint32_t tf5_ibs_unix_to_validity(uint64_t unix_sec);

// validity_end to Unix seconds
uint64_t tf5_ibs_validity_to_unix(uint32_t validity_end);
```

**Authentication Coverage**:
- **Signature**: SIB1 || static_params || validity_end || timesync_info || interval_index || disclosed_key || timestamp_ms
- **MAC**: SIB1 || static_params || validity_end || timesync_info (per RFC 4082, excludes timestamp)

**Binary Wire Format** (113 bytes, big-endian):
```
Offset  Size  Field
------  ----  -----
0       1     te_version
1       1     crypto_suite_id
2       2     t_int_ms
4       1     disclosure_delay
5       1     key_len
(root_key removed - disclosed_key serves as trusted anchor)
6       2     t0.hfn
8       2     t0.sfn
10      2     t0.slot
12      4     chain_len
16      3     validity_end           (minutes since 2024-01-01)
19      2     timesync_info.sfn
21      2     timesync_info.slot
23      4     interval_index
27      16    disclosed_key
43      8     timestamp_ms
51      48    gnb_signature (BLS)
99      16    tesla_tag
------
113 bytes total (with BLS signatures)

Note: HFN removed from timesync_info - now obtained from hyperSFN-r17 in SIB1-v1700-IEs
Note: root_key removed - disclosed_key serves as trusted anchor (every SIB1 is signed)
```

---

## gNB State Structure

```c
typedef struct {
    tf5_tesla_static_params_t params;

    // Key chain storage (dynamically allocated)
    uint8_t  (*key_chain)[16];    // K_0 ... K_N
    uint32_t key_chain_len;

    // Current state
    uint32_t current_interval;

    // HFN tracking is in gNB_RRC_INST (rrc->current_hfn)
    // MAC sends NRRRC_SFN_WRAP ITTI to RRC on SFN wraparound

    // IBS keys
    uint8_t  gnb_private_key[32];   // sk_ID (issued by Core PKG)
    uint8_t  gnb_cell_id[5];        // NR Cell ID (36 bits)
    uint32_t validity_end;          // Key expiration (minutes since 2024-01-01)

    // Timing
    uint16_t slots_per_frame;

    bool     initialized;
} tf5_tesla_gnb_state_t;
```

---

## UE State Structure

```c
typedef struct {
    tf5_tesla_static_params_t static_params;

    // Pre-provisioned gNB public key
    uint8_t  gnb_public_key[96];  // BLS public key (G2)
    bool     has_gnb_public_key;

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
        tf5_tesla_slot_time_t rx_time;  // RX timing (HFN/SFN/slot)
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
