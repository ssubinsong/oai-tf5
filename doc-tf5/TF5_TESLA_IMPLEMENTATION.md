# TESLA Broadcast Authentication for 5G NR SIB1

**TF5 (TESLA for 5G) Implementation Documentation**

This document describes the TESLA (Timed Efficient Stream Loss-tolerant Authentication) protocol implementation for authenticating SIB1 broadcast messages in 5G NR, protecting UEs from fake base station attacks.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Protocol Design](#2-protocol-design)
3. [Cryptographic Primitives](#3-cryptographic-primitives)
4. [Data Structures](#4-data-structures)
5. [gNB-Side Implementation](#5-gnb-side-implementation)
6. [UE-Side Implementation](#6-ue-side-implementation)
7. [HFN Tracking](#7-hfn-tracking)
8. [Integration Points](#8-integration-points)
9. [API Reference](#9-api-reference)
10. [Build Configuration](#10-build-configuration)
11. [Security Analysis](#11-security-analysis)

---

## 1. Overview

### 1.1 Purpose

The TF5 TESLA implementation protects 5G NR User Equipment (UE) from **Fake Base Station (FBS)** attacks by authenticating System Information Block 1 (SIB1) broadcast messages.

**Problem**: In 5G NR, SIB1 is broadcast unencrypted and unauthenticated. An attacker can set up a rogue gNB that broadcasts malicious SIB1, potentially:
- Redirecting UEs to attacker-controlled networks
- Performing denial-of-service attacks
- Enabling man-in-the-middle attacks

**Solution**: TESLA provides broadcast authentication without requiring per-UE state on the gNB, making it suitable for the broadcast nature of SIB1.

### 1.2 Reference

- **RFC 4082**: Timed Efficient Stream Loss-Tolerant Authentication (TESLA)
- Location in repo: `claude-ref/rfc/rfc4082.txt`

### 1.3 Key Features

| Feature | Description |
|---------|-------------|
| Delayed key disclosure | Keys revealed one interval after use |
| Dual authentication | Ed25519 signature + TESLA MAC |
| HFN tracking | Handles SFN wraparound for long key chains |
| Conditional compilation | Enabled via `TF5_ENABLE_TESLA` flag |

---

## 2. Protocol Design

### 2.1 Key Chain Generation

TESLA uses a one-way hash chain for key management. The gNB generates keys in reverse order:

```
K_N (seed) --F--> K_{N-1} --F--> ... --F--> K_1 --F--> K_0 (root/commitment)
```

- **K_N**: Random seed (generated at initialization)
- **F**: One-way function: `K_i = HMAC-SHA256(K_{i+1}, 0x00)[0:15]`
- **K_0**: Root key (commitment), shared with UE in static parameters

The gNB uses keys in forward order (K_1, K_2, ..., K_N), disclosing each key one interval after it was used.

### 2.2 Time Intervals

Time is divided into discrete intervals:

| Parameter | Default Value | Description |
|-----------|---------------|-------------|
| T_int | 20 ms | Interval duration |
| chain_len | 65536 | Number of intervals |
| Duration | ~21.8 minutes | Total key chain lifetime |

**Interval Index Calculation**:
```
i = floor((current_time - T_0) / T_int)
```

Where `T_0` is the start time of interval 0, specified in static parameters using (HFN, SFN, slot).

### 2.3 Disclosure Delay

The **disclosure delay** (d) determines how many intervals elapse before a key is revealed:

- Default: **d = 1**
- At interval i, gNB discloses K_{i-d} = K_{i-1}
- UE can verify messages from interval i-1 using the disclosed key

**Timeline Example** (d=1):
```
Interval 5: gNB uses K_5 for MAC, discloses K_4
Interval 6: gNB uses K_6 for MAC, discloses K_5
            UE verifies buffered message from interval 5 using K_5
```

### 2.4 Dual Authentication Mechanism

TF5 implements **two authentication mechanisms**:

1. **Ed25519 Signature** (Immediate)
   - gNB signs the authentication input with its private key
   - UE verifies immediately if it has the pre-provisioned public key
   - Provides strong authentication without waiting

2. **TESLA MAC** (Delayed)
   - gNB computes HMAC using the current interval's key
   - UE buffers the message and verifies when key is disclosed
   - Provides authentication even without pre-provisioned keys

---

## 3. Cryptographic Primitives

### 3.1 Algorithm Summary

| Primitive | Algorithm | Key/Output Size |
|-----------|-----------|-----------------|
| Key chain derivation | HMAC-SHA256(K, 0x00) | 128 bits (truncated) |
| MAC key derivation | HMAC-SHA256(K, 0x01) | 256 bits |
| TESLA tag | HMAC-SHA256(K', data) | 128 bits (truncated) |
| Signature | Ed25519 | 512 bits |

### 3.2 Key Chain Function (F)

Derives the previous key in the chain:
```c
K_i = F(K_{i+1}) = HMAC-SHA256(K_{i+1}, 0x00)[0:15]
```

Implementation in `tf5_tesla_chain_key()`:
```c
void tf5_tesla_chain_key(const uint8_t key_next[16], uint8_t key_out[16]) {
    uint8_t hmac_out[32];
    uint8_t constant = 0x00;
    HMAC(EVP_sha256(), key_next, 16, &constant, 1, hmac_out, NULL);
    memcpy(key_out, hmac_out, 16);  // Truncate to 128 bits
}
```

### 3.3 MAC Key Derivation (F')

Derives the MAC key from a TESLA key:
```c
K'_i = F'(K_i) = HMAC-SHA256(K_i, 0x01)
```

This separation ensures that revealing K_i doesn't directly expose the MAC key used.

### 3.4 TESLA Tag Computation

```c
tag = HMAC-SHA256(K'_i, auth_input)[0:15]
```

The tag is truncated to 128 bits (16 bytes) for efficiency.

### 3.5 Authentication Input

The data authenticated by both signature and MAC:
```
auth_input = original_SIB1 || static_params || dynamic_params
```

- **original_SIB1**: SIB1 content without TESLA extension
- **static_params**: 30 bytes of static TESLA parameters
- **dynamic_params**: 26 bytes of per-transmission parameters

---

## 4. Data Structures

### 4.1 Static Parameters (30 bytes)

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

### 4.2 Dynamic Parameters (26 bytes)

Parameters that change with each SIB1 transmission:

```c
typedef struct {
    uint32_t interval_index;       // 4B - Current interval i
    uint16_t ti_hfn;               // 2B - HFN when SIB1 sent
    uint16_t ti_sfn;               // 2B - SFN when SIB1 sent
    uint16_t ti_slot;              // 2B - Slot when SIB1 sent
    uint8_t  disclosed_key[16];    // 16B - K_{i-d}
} tf5_tesla_dynamic_params_t;
```

### 4.3 TESLA Extension (136 bytes)

Complete extension appended to SIB1 via `lateNonCriticalExtension`:

```c
typedef struct {
    tf5_tesla_static_params_t  static_params;  // 30B
    tf5_tesla_dynamic_params_t dynamic_params; // 26B
    uint8_t  gnb_signature[64];                // 64B - Ed25519 signature
    uint8_t  tesla_tag[16];                    // 16B - HMAC tag
} tf5_tesla_extension_t;
```

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
32      4     interval_index
36      2     ti_hfn
38      2     ti_sfn
40      2     ti_slot
42      16    disclosed_key
58      64    gnb_signature
122     16    tesla_tag
------
136 bytes total
```

### 4.4 gNB State Structure

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

### 4.5 UE State Structure

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

## 5. gNB-Side Implementation

### 5.1 Initialization Flow

**Location**: `openair2/LAYER2/NR_MAC_gNB/config.c`

```
1. Generate Ed25519 key pair
   └── tf5_tesla_ed25519_keygen()

2. Allocate and initialize TESLA state
   └── tf5_tesla_gnb_init()
       ├── Generate random seed K_N
       ├── Compute key chain K_{N-1}, ..., K_0
       ├── Store static params (T_int, d, K_0, T_0, N)
       └── Initialize HFN tracking

3. Store original SIB1 (without extension)
   └── cc->sib1_original[], cc->sib1_original_length

4. Log public key for UE provisioning
   └── LOG_I() with hex-encoded public key
```

### 5.2 Per-Transmission Flow

**Location**: `openair2/LAYER2/NR_MAC_gNB/nr_radio_config.c` → `nr_mac_update_sib1_tesla()`

Called from scheduler before each SIB1 transmission:

```
1. Get current interval from SFN/slot
   └── tf5_tesla_gnb_get_interval()
       ├── Update HFN if SFN wrapped
       └── Calculate interval index

2. Prepare TESLA extension
   └── tf5_tesla_gnb_prepare_extension()
       ├── Set dynamic params (i, ti_sfn, ti_slot, K_{i-d})
       ├── Build auth_input = SIB1 || static || dynamic
       ├── Sign auth_input with Ed25519
       └── Compute TESLA tag with K_i

3. Pack extension to binary
   └── tf5_tesla_pack_extension()

4. Set lateNonCriticalExtension
   └── sib1->message.lateNonCriticalExtension = ...

5. Re-encode SIB1
   └── encode_SIB_NR()
```

### 5.3 Scheduler Integration

**Location**: `openair2/LAYER2/NR_MAC_gNB/gNB_scheduler_bch.c`

```c
#ifdef TF5_ENABLE_TESLA
if (cc->tesla_state && cc->tesla_state->initialized) {
    nr_mac_update_sib1_tesla(mac, cc, slot);
}
#endif
```

---

## 6. UE-Side Implementation

### 6.1 Initialization

**Location**: `openair2/RRC/NR_UE/rrc_UE.c`

```c
// Allocate TESLA state
SI_info->tesla_state = calloc(1, sizeof(tf5_tesla_ue_state_t));

// Initialize with pre-provisioned gNB public key
tf5_tesla_ue_init(SI_info->tesla_state, gnb_public_key, slots_per_frame);
```

**Note**: The gNB public key must be pre-provisioned on the UE. In the current implementation, it's hardcoded for testing.

### 6.2 SIB1 Reception Flow

```
1. Check for TESLA extension
   └── sib1->message.lateNonCriticalExtension

2. Unpack extension
   └── tf5_tesla_unpack_extension()

3. Store static params (first reception)
   └── Copy to UE state

4. Build auth_input for verification
   └── tf5_tesla_build_auth_input()

5. Verify Ed25519 signature (IMMEDIATE)
   └── tf5_tesla_ue_verify_signature()
       └── If valid: SIB1 is authenticated

6. Check buffered SIB1 verification (DELAYED)
   └── If disclosed_key available for buffered message:
       └── tf5_tesla_ue_verify_buffered()

7. Buffer current SIB1
   └── tf5_tesla_ue_buffer_sib1()
```

### 6.3 Safe Packet Test

The safe packet test determines if a message could have been forged by an attacker who saw a key disclosure:

```c
bool tf5_tesla_ue_safe_packet_test(state, ext, rx_sfn, rx_slot) {
    // Get ti_hfn from signed extension (trusted)
    uint16_t ref_hfn = ext->dynamic_params.ti_hfn;

    // Initialize or verify HFN tracking
    if (!state->hfn_initialized) {
        state->current_hfn = ref_hfn;  // Bootstrap
        state->hfn_initialized = true;
    } else {
        // Check for HFN mismatch (potential replay)
        if (abs(ref_hfn - state->current_hfn) > 1) {
            return false;  // Possible replay attack
        }
    }

    // Compute current interval
    uint32_t x = compute_interval(ref_hfn, rx_sfn, rx_slot, ...);
    uint32_t i = ext->dynamic_params.interval_index;
    uint8_t d = ext->static_params.disclosure_delay;

    // Safe if: x < i + d
    return (x < i + d);
}
```

### 6.4 Key Chain Verification

When verifying a disclosed key:

```c
bool tf5_tesla_ue_verify_key_chain(state, disclosed_key, key_index) {
    // Case 1: First key verification - chain to root K_0
    // Case 2: Subsequent - chain to last verified key

    // Apply F repeatedly until reaching known key
    uint8_t computed_key[16];
    memcpy(computed_key, disclosed_key, 16);

    for (uint32_t i = key_index; i > target_index; i--) {
        tf5_tesla_chain_key(computed_key, computed_key);
    }

    // Compare with known key
    return memcmp(computed_key, known_key, 16) == 0;
}
```

---

## 7. HFN Tracking

### 7.1 Problem

The System Frame Number (SFN) is a 10-bit counter (0-1023) that wraps every:
```
1024 frames × 10ms = 10.24 seconds
```

However, the TESLA key chain lasts ~21.8 minutes, requiring tracking across multiple SFN cycles.

### 7.2 Solution: Hyper-Frame Number (HFN)

HFN is a counter that increments each time SFN wraps from 1023 to 0:

```c
// Absolute slot calculation
uint64_t absolute_slots = (HFN × 1024 + SFN) × slots_per_frame + slot;
```

### 7.3 Wraparound Detection

```c
static inline void tf5_tesla_update_hfn(uint16_t *hfn,
                                         uint16_t *last_sfn,
                                         uint16_t current_sfn) {
    // Detect wraparound: last_sfn near 1023, current_sfn near 0
    if (*last_sfn > 900 && current_sfn < 100) {
        (*hfn)++;
    }
    *last_sfn = current_sfn;
}
```

### 7.4 UE HFN Synchronization Challenge

**Problem**: UE learns SFN from SSB synchronization, but **not HFN**. The gNB's HFN is unknown to UE at initial connection.

**Solution**: Use the **signed ti_hfn** from the TESLA extension:

1. The Ed25519 signature covers ti_hfn, making it trustworthy
2. **First SIB1**: UE bootstraps HFN from signed extension
3. **Subsequent SIB1s**: UE tracks HFN locally and compares (±1 tolerance)

```c
// First reception
state->current_hfn = ext->dynamic_params.ti_hfn;
state->hfn_initialized = true;

// Subsequent receptions
int16_t hfn_diff = (int16_t)received_hfn - (int16_t)state->current_hfn;
if (hfn_diff < -1 || hfn_diff > 1) {
    // HFN mismatch - possible replay from old SFN cycle
    return false;
}
```

---

## 8. Integration Points

### 8.1 File Summary

| File | Component | Purpose |
|------|-----------|---------|
| `openair3/SECU/tf5_tesla.h` | Core | Data structures, API declarations |
| `openair3/SECU/tf5_tesla.c` | Core | Protocol implementation (~760 lines) |
| `openair3/SECU/tf5_tesla_sig.h` | Core | Ed25519 function declarations |
| `openair3/SECU/tf5_tesla_sig.c` | Core | Ed25519 implementation |
| `openair2/LAYER2/NR_MAC_gNB/nr_mac_gNB.h` | gNB | State struct definition |
| `openair2/LAYER2/NR_MAC_gNB/config.c` | gNB | Initialization |
| `openair2/LAYER2/NR_MAC_gNB/nr_radio_config.c` | gNB | Extension update |
| `openair2/LAYER2/NR_MAC_gNB/gNB_scheduler_bch.c` | gNB | Scheduler hook |
| `openair2/LAYER2/NR_MAC_gNB/mac_proto.h` | gNB | Function prototype |
| `openair2/RRC/NR_UE/rrc_defs.h` | UE | State struct definition |
| `openair2/RRC/NR_UE/rrc_UE.c` | UE | Verification logic |

### 8.2 gNB Structure Modification

In `nr_mac_gNB.h`, added to `NR_COMMON_channels_t`:

```c
#ifdef TF5_ENABLE_TESLA
  tf5_tesla_gnb_state_t *tesla_state;
  uint8_t sib1_original[TF5_TESLA_MAX_SIB1_LEN];
  size_t sib1_original_length;
#endif
```

### 8.3 UE Structure Modification

In `rrc_defs.h`, added to `NR_UE_RRC_SI_INFO`:

```c
#ifdef TF5_ENABLE_TESLA
  tf5_tesla_ue_state_t *tesla_state;
#endif
```

---

## 9. API Reference

### 9.1 gNB API

```c
// Initialize TESLA state
int tf5_tesla_gnb_init(tf5_tesla_gnb_state_t *state,
                       uint16_t t_int_ms,      // Interval duration (20)
                       uint8_t d,              // Disclosure delay (1)
                       uint32_t chain_len,     // Number of intervals (65536)
                       const uint8_t private_key[32],
                       uint16_t hfn,           // Initial HFN (0)
                       uint16_t sfn,           // T_0 SFN
                       uint16_t slot,          // T_0 slot
                       uint16_t slots_per_frame);

// Free resources
void tf5_tesla_gnb_free(tf5_tesla_gnb_state_t *state);

// Get current interval (updates HFN tracking)
uint32_t tf5_tesla_gnb_get_interval(tf5_tesla_gnb_state_t *state,
                                    uint16_t sfn,
                                    uint16_t slot);

// Prepare TESLA extension for transmission
int tf5_tesla_gnb_prepare_extension(tf5_tesla_gnb_state_t *state,
                                    uint16_t sfn,
                                    uint16_t slot,
                                    const uint8_t *original_sib1,
                                    size_t sib1_len,
                                    tf5_tesla_extension_t *ext);

// Pack extension to binary
int tf5_tesla_pack_extension(const tf5_tesla_extension_t *ext,
                             uint8_t *buf,
                             size_t buf_len);
```

### 9.2 UE API

```c
// Initialize UE state
int tf5_tesla_ue_init(tf5_tesla_ue_state_t *state,
                      const uint8_t gnb_public_key[32],
                      uint16_t slots_per_frame);

// Free resources
void tf5_tesla_ue_free(tf5_tesla_ue_state_t *state);

// Unpack extension from binary
int tf5_tesla_unpack_extension(const uint8_t *buf,
                               size_t buf_len,
                               tf5_tesla_extension_t *ext);

// Verify Ed25519 signature
int tf5_tesla_ue_verify_signature(const tf5_tesla_ue_state_t *state,
                                  const uint8_t *auth_input,
                                  size_t auth_input_len,
                                  const uint8_t signature[64]);

// Safe packet test (also initializes HFN tracking)
bool tf5_tesla_ue_safe_packet_test(tf5_tesla_ue_state_t *state,
                                   const tf5_tesla_extension_t *ext,
                                   uint16_t rx_sfn,
                                   uint16_t rx_slot);

// Buffer SIB1 for delayed verification
int tf5_tesla_ue_buffer_sib1(tf5_tesla_ue_state_t *state,
                             const uint8_t *auth_input,
                             size_t auth_input_len,
                             uint32_t interval_index,
                             const uint8_t tag[16],
                             uint16_t ti_hfn,
                             uint16_t rx_sfn,
                             uint16_t rx_slot);

// Verify buffered SIB1 with disclosed key
int tf5_tesla_ue_verify_buffered(tf5_tesla_ue_state_t *state,
                                 const uint8_t disclosed_key[16],
                                 uint32_t key_interval);

// Verify key chain integrity
bool tf5_tesla_ue_verify_key_chain(tf5_tesla_ue_state_t *state,
                                   const uint8_t disclosed_key[16],
                                   uint32_t key_index);
```

### 9.3 Utility Functions

```c
// Build authentication input
int tf5_tesla_build_auth_input(uint8_t *out,
                               size_t *out_len,
                               const uint8_t *original_sib1,
                               size_t sib1_len,
                               const tf5_tesla_static_params_t *static_params,
                               const tf5_tesla_dynamic_params_t *dynamic_params);

// Derive MAC key from TESLA key
void tf5_tesla_derive_mac_key(const uint8_t key_in[16],
                              uint8_t mac_key_out[32]);

// Compute key chain (K_i from K_{i+1})
void tf5_tesla_chain_key(const uint8_t key_next[16],
                         uint8_t key_out[16]);

// Compute TESLA tag
int tf5_tesla_compute_tag(const uint8_t key[16],
                          const uint8_t *auth_input,
                          size_t auth_input_len,
                          uint8_t tag_out[16]);

// Get slots since T_0 (with HFN)
uint64_t tf5_tesla_slots_since_t0(uint16_t current_hfn,
                                  uint16_t current_sfn,
                                  uint16_t current_slot,
                                  uint16_t t0_hfn,
                                  uint16_t t0_sfn,
                                  uint16_t t0_slot,
                                  uint16_t slots_per_frame);

// Get interval index
uint32_t tf5_tesla_get_interval_index(uint16_t hfn,
                                      uint16_t sfn,
                                      uint16_t slot,
                                      uint16_t t0_hfn,
                                      uint16_t t0_sfn,
                                      uint16_t t0_slot,
                                      uint16_t t_int_ms,
                                      uint16_t slots_per_frame);
```

---

## 10. Build Configuration

### 10.1 CMake Option

In `CMakeLists.txt`:

```cmake
option(TF5_ENABLE_TESLA
       "Enable TESLA broadcast authentication for SIB1 (fake base station protection)"
       OFF)

if(TF5_ENABLE_TESLA)
  add_definitions(-DTF5_ENABLE_TESLA)
endif()
```

### 10.2 Build Commands

**Build gNB and UE with TESLA enabled**:
```bash
cd cmake_targets
./build_oai --ninja --gNB --nrUE -w SIMU --cmake-opt -DTF5_ENABLE_TESLA=ON
```

**Build gNB only**:
```bash
./build_oai --ninja --gNB -w SIMU --cmake-opt -DTF5_ENABLE_TESLA=ON
```

### 10.3 Dependencies

| Dependency | Purpose |
|------------|---------|
| OpenSSL | HMAC-SHA256 |
| herumi/bls | Ed25519 signatures |

The herumi/bls library is included as a submodule at `cmake_targets/bls/`.

---

## 11. Security Analysis

### 11.1 Threat Model

| Threat | Mitigated | Mechanism |
|--------|-----------|-----------|
| Fake base station | Yes | Ed25519 signature verification |
| Message tampering | Yes | Signature + MAC verification |
| Replay attack (recent) | Yes | Interval check in safe packet test |
| Replay attack (old HFN cycle) | Yes | HFN mismatch detection |
| Key compromise | Partial | Delayed disclosure limits exposure |

### 11.2 Security Properties

1. **Source Authentication**: Ed25519 signature proves message originated from legitimate gNB
2. **Message Integrity**: Both signature and MAC protect against tampering
3. **Timeliness**: Interval tracking detects stale/replayed messages
4. **Key Chain Integrity**: Each disclosed key can be verified against K_0

### 11.3 Limitations

| Limitation | Description | Mitigation |
|------------|-------------|------------|
| Pre-provisioned keys | UE needs gNB public key | Future: certificate-based distribution |
| Finite chain lifetime | ~21.8 minutes | Future: chain renewal mechanism |
| Bootstrap trust | First SIB1 must be trusted | Ed25519 signature provides immediate trust |
| Memory usage | 1MB for key chain (65536 × 16B) | Configurable chain length |

### 11.4 Attack Resistance

**Fake Base Station Attack**:
- Attacker cannot forge Ed25519 signatures without private key
- Attacker cannot predict future TESLA keys (one-way function)
- Attacker cannot replay old messages (HFN/interval check)

**Replay Attack**:
- Same SFN cycle: Interval check detects stale messages
- Different HFN cycle: HFN mismatch detection (±1 tolerance)

**Key Disclosure Attack**:
- Attacker learns K_{i-d} at interval i
- Cannot forge messages for intervals > i-d (keys not yet disclosed)
- Safe packet test ensures: x < i + d

---

## Appendix A: Configuration Parameters

| Parameter | Default | Range | Description |
|-----------|---------|-------|-------------|
| `TF5_TESLA_KEY_LEN` | 16 | Fixed | TESLA key size (128 bits) |
| `TF5_TESLA_TAG_LEN` | 16 | Fixed | MAC tag size (128 bits) |
| `TF5_TESLA_SIG_LEN` | 64 | Fixed | Ed25519 signature size |
| `TF5_TESLA_CHAIN_LEN` | 65536 | 1-2^32 | Key chain length |
| `T_int` | 20ms | Configurable | Interval duration |
| `d` | 1 | 1-255 | Disclosure delay |

---

## Appendix B: Error Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| -1 | Invalid parameter (NULL pointer) |
| -2 | Buffer too small |
| -3 | Memory allocation failed |
| -4 | Cryptographic operation failed |
| -5 | Signature verification failed |
| -6 | Key chain verification failed |

---

## Appendix C: Logging

TESLA operations are logged using OAI logging macros:

```c
LOG_I(NR_RRC, "TESLA: ...")  // Informational
LOG_D(NR_RRC, "TESLA: ...")  // Debug
LOG_W(NR_RRC, "TESLA: ...")  // Warning
LOG_E(NR_RRC, "TESLA: ...")  // Error
```

**Key log messages**:
- gNB initialization: Public key logged for UE provisioning
- Signature verification: Success/failure logged
- HFN tracking: Initialization and mismatch warnings
- Buffered verification: Success/failure of delayed verification
