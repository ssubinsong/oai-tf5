# Data Structures

[Back to Index](index.md)

**Source**: [tf5_tesla.h](../openair3/SECU/tf5_tesla.h)

---

## Static Parameters (30 bytes)

**Source**: [tf5_tesla.h:64-75](../openair3/SECU/tf5_tesla.h#L64-L75)

Parameters constant for the lifetime of a key chain:

```c
typedef struct {
    uint8_t  te_version;           // 1B - Protocol version (0x01)
    uint8_t  crypto_suite_id;      // 1B - Algorithm suite (0x01)
    uint16_t t_int_ms;             // 2B - Interval duration (20ms)
    uint8_t  disclosure_delay;     // 1B - Key disclosure delay (1)
    uint8_t  key_len;              // 1B - TESLA key length (16)
    uint8_t  root_key[16];         // 16B - K_0 chain commitment
    uint16_t t0_hfn;               // 2B - HFN at T_0
    uint16_t t0_sfn;               // 2B - SFN at T_0
    uint16_t t0_slot;              // 2B - Slot at T_0
    uint32_t chain_len;            // 4B - Number of intervals N
} tf5_tesla_static_params_t;
```

---

## Time Synchronization Info (6 bytes)

**Source**: [tf5_tesla.h:83-89](../openair3/SECU/tf5_tesla.h#L83-L89)

Timing information for UE-gNB time synchronization:

```c
typedef struct {
    uint16_t ti_hfn;               // 2B - HFN when SIB1 sent
    uint16_t ti_sfn;               // 2B - SFN when SIB1 sent
    uint16_t ti_slot;              // 2B - Slot when SIB1 sent
} tf5_tesla_timesync_info_t;
```

---

## TESLA Extension (136 bytes)

**Source**: [tf5_tesla.h:91-103](../openair3/SECU/tf5_tesla.h#L91-L103)

Complete extension appended to SIB1 via `lateNonCriticalExtension`:

```c
typedef struct {
    tf5_tesla_static_params_t   static_params;   // 30B
    tf5_tesla_timesync_info_t   timesync_info;   // 6B
    uint32_t                    interval_index;  // 4B - Current interval i
    uint8_t                     disclosed_key[16]; // 16B - K_{i-d}
    uint8_t  gnb_signature[64];                  // 64B - Ed25519 signature
    uint8_t  tesla_tag[16];                      // 16B - HMAC tag
} tf5_tesla_extension_t;
```

**Authentication Coverage**:
- **Signature**: SIB1 || static_params || timesync_info || interval_index || disclosed_key
- **MAC**: SIB1 || static_params || timesync_info (per RFC 4082)

**Binary Wire Format** (136 bytes, big-endian):
```
Offset  Size  Field
------  ----  -----
0       1     te_version
1       1     crypto_suite_id
2       2     t_int_ms
4       1     disclosure_delay
5       1     key_len
6       16    root_key
22      2     t0_hfn
24      2     t0_sfn
26      2     t0_slot
28      4     chain_len
30      2     ti_hfn
32      2     ti_sfn
34      2     ti_slot
36      4     interval_index
40      16    disclosed_key
56      64    gnb_signature
120     16    tesla_tag
------
136 bytes total
```

---

## gNB State Structure

**Source**: [tf5_tesla.h:110-133](../openair3/SECU/tf5_tesla.h#L110-L133)

```c
typedef struct {
    tf5_tesla_static_params_t params;

    // Key chain storage (dynamically allocated)
    uint8_t  (*key_chain)[16];    // K_0 ... K_N
    uint32_t key_chain_len;

    // Current state
    uint32_t current_interval;

    // HFN tracking
    uint16_t current_hfn;
    uint16_t last_sfn;

    // Ed25519 keys
    uint8_t  gnb_private_key[32];
    uint8_t  gnb_public_key[32];

    // Timing
    uint16_t slots_per_frame;

    bool     initialized;
} tf5_tesla_gnb_state_t;
```

---

## UE State Structure

**Source**: [tf5_tesla.h:140-187](../openair3/SECU/tf5_tesla.h#L140-L187)

```c
typedef struct {
    tf5_tesla_static_params_t static_params;

    // Pre-provisioned gNB public key
    uint8_t  gnb_public_key[32];
    bool     has_gnb_public_key;

    // Verification state
    bool     params_received;
    uint32_t last_verified_key_idx;
    uint8_t  last_verified_key[16];

    // HFN tracking
    uint16_t current_hfn;
    uint16_t last_sfn;
    bool     hfn_initialized;

    // Buffered SIB1 pending verification
    struct {
        uint8_t  auth_input[512];
        size_t   auth_input_len;
        uint32_t interval_index;
        uint8_t  tag[16];
        uint16_t rx_hfn;
        uint16_t rx_sfn;
        uint16_t rx_slot;
        bool     pending;
    } buffer;

    uint16_t slots_per_frame;
    bool     initialized;
} tf5_tesla_ue_state_t;
```

---

## OAI Integration Points

TESLA state is integrated into existing OAI structures:

### gNB: NR_COMMON_channels_t

**Source**: [nr_mac_gNB.h:336-339](../openair2/LAYER2/NR_MAC_gNB/nr_mac_gNB.h#L336-L339)

```c
// In NR_COMMON_channels_t:
tf5_tesla_gnb_state_t *tesla_state;      // TESLA state pointer
uint8_t sib1_original[NR_MAX_SIB_LENGTH / 8];  // Original SIB1 for signing
int sib1_original_length;
```

### UE: NR_UE_RRC_SI_INFO

**Source**: [rrc_defs.h:166](../openair2/RRC/NR_UE/rrc_defs.h#L166)

```c
// In NR_UE_RRC_SI_INFO:
tf5_tesla_ue_state_t *tesla_state;       // TESLA state pointer
```
