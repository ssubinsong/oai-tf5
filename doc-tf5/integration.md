# Integration Points

[Back to Index](index.md)

---

## Overview

TF5 integrates TESLA broadcast authentication into the OpenAirInterface (OAI) 5G NR stack. This document describes file locations, OAI structure modifications, and the call flow between components.

---

## File Structure

### Core TESLA Implementation

Located in `openair3/SECU/`:

| File | Purpose |
|------|---------|
| `tf5_tesla.c` | TESLA protocol implementation (key chains, MAC, verification) |
| `tf5_tesla.h` | Data structures, API declarations, constants |
| `tf5_tesla_sig.c` | BLMQ IBS signature operations (sign, verify, init) |
| `tf5_tesla_sig.h` | BLMQ IBS API declarations |
| `tf5_ibs_common.c` | IBS utilities shared between gNB and Core PKG |
| `tf5_ibs_pkg.h` | IBS PKG API declarations |

### Core PKG Tools

Located in `openair3/SECU/core-pkg/`:

| File | Purpose |
|------|---------|
| `tf5_ibs_keygen.c` | Master keypair generation tool (`tf5_ibs_pkg_keygen`) |
| `tf5_ibs_issue.c` | gNB secret key issuance tool (`tf5_ibs_issue`) |

### gNB Integration

Located in `openair2/LAYER2/NR_MAC_gNB/`:

| File | Lines | Purpose |
|------|-------|---------|
| `config.c` | 1185-1270 | TESLA state initialization in `nr_mac_configure_sib1()` |
| `nr_radio_config.c` | 4379-4446 | Per-SIB1 extension update in `nr_mac_update_sib1_tf5()` |
| `gNB_scheduler_bch.c` | 601-606 | Scheduler integration (calls update before TX) |
| `nr_mac_gNB.h` | 334-340 | State pointer in `NR_COMMON_channels_t` |

### UE Integration

Located in `openair2/RRC/NR_UE/`:

| File | Lines | Purpose |
|------|-------|---------|
| `rrc_UE.c` | 600-801 | Main verification logic (`tf5_verify_sib1()`, etc.) |
| `rrc_UE.c` | 2354 | NAS gating / RRCSetupComplete deferral |
| `rrc_defs.h` | 165-167 | State pointer in `NR_UE_RRC_SI_INFO` |

### Unit Tests

Located in `openair3/SECU/tests/`:

| File | Purpose |
|------|---------|
| `test_tf5_tesla_crypto.cpp` | Cryptographic primitives |
| `test_tf5_tesla_gnb.cpp` | gNB functions |
| `test_tf5_tesla_ue.cpp` | UE verification |
| `test_tf5_tesla_e2e.cpp` | End-to-end flow |
| `test_tf5_tesla_bls.cpp` | BLMQ IBS signatures |
| `test_tf5_tesla_serial.cpp` | Serialization |
| `test_tf5_tesla_timing.cpp` | Timing/replay protection |
| `test_tf5_tesla_fileio.cpp` | Key file I/O |
| `test_tf5_ibs_pkg.cpp` | Core PKG key management |
| `tf5_test_vectors.h` | Common test vectors |

---

## OAI Structure Modifications

### gNB: NR_COMMON_channels_t

**Source**: [nr_mac_gNB.h:334-340](../openair2/LAYER2/NR_MAC_gNB/nr_mac_gNB.h#L334-L340)

```c
typedef struct {
    // ... existing fields ...

#ifdef ENABLE_TF5
    tf5_gnb_state_t *tf5_state;                     // TESLA state pointer
    uint8_t sib1_original[NR_MAX_SIB_LENGTH / 8];   // Original SIB1 for signing
    int sib1_original_length;
#endif

    // ... existing fields ...
} NR_COMMON_channels_t;
```

**Fields**:
- `tf5_state`: Pointer to TESLA state (key chain, IBS key, params)
- `sib1_original`: Cached SIB1 encoding (without extension) for MAC computation
- `sib1_original_length`: Length of cached encoding

### UE: NR_UE_RRC_SI_INFO

**Source**: [rrc_defs.h:165-167](../openair2/RRC/NR_UE/rrc_defs.h#L165-L167)

```c
typedef struct NR_UE_RRC_SI_INFO_s {
    // ... existing fields ...

#ifdef ENABLE_TF5
    tf5_ue_state_t *tf5_state;                      // TESLA state pointer
#endif

    // ... existing fields ...
} NR_UE_RRC_SI_INFO;
```

**Fields**:
- `tf5_state`: Pointer to TESLA state (MPK, trust anchor, buffer queue, phase)

---

## Conditional Compilation

All TF5 code is guarded by `#ifdef ENABLE_TF5`:

```c
#ifdef ENABLE_TF5
  // TF5-specific code
#endif
```

### CMake Configuration

The `ENABLE_TF5` option is defined in CMake:

```cmake
add_boolean_option(ENABLE_TF5 OFF "Enable TESLA broadcast authentication for SIB1 (fake base station protection)" ON)

if(ENABLE_TF5)
  add_definitions(-DENABLE_TF5)
  # Link BLST library for BLS signatures
endif()
```

Build command:
```bash
./build_oai --ninja --gNB --nrUE --cmake-opt -DENABLE_TF5=ON
```

---

## Entry Points and Call Flow

### gNB Startup

```
main() [nr-softmodem]
  └── init_gNB()
        └── nr_mac_config_scc()
              └── nr_mac_configure_sib1()           [config.c:1166]
                    ├── tf5_ibs_init()              [tf5_tesla_sig.c]
                    ├── tf5_load_gnb_privkey()      [tf5_tesla.c]
                    ├── tf5_compute_t0_reference()
                    └── tf5_gnb_init()              [tf5_tesla.c]
```

### gNB Per-SIB1 TX

```
gNB_scheduler()
  └── schedule_sib1() [gNB_scheduler_bch.c]
        └── nr_mac_update_sib1_tf5()               [nr_radio_config.c:4381]
              ├── uper_encode_to_buffer()          (original SIB1)
              ├── tf5_gnb_prepare_extension()      [tf5_tesla.c]
              │     ├── tf5_ibs_sign()
              │     └── tf5_compute_tag()
              ├── tf5_pack_extension()             [tf5_tesla.c]
              └── encode_SIB_NR()                  (SIB1 with extension)
```

### UE SIB1 Reception

```
nr_rrc_ue_process_masterCellGroup()
  └── decode_SIB1()
        └── tf5_verify_sib1()                      [rrc_UE.c:760]
              ├── tf5_tesla_unpack_and_validate()  [tf5_tesla.c]
              ├── tf5_encode_sib1_for_auth()
              │
              ├── [First-time UE path]
              │     └── tf5_verify_firsttime()     [rrc_UE.c:605]
              │           ├── tf5_rp_validate_timestamp()
              │           ├── tf5_build_sig_auth_input()
              │           ├── tf5_ibs_verify()     [tf5_tesla_sig.c]
              │           └── tf5_send_deferred_rrcsetupcomplete()
              │
              └── [Returning UE path]
                    └── tf5_verify_returning()     [rrc_UE.c:681]
                          ├── tf5_ue_safe_packet_test()
                          ├── tf5_ue_verify_key_disclosure()
                          ├── tf5_ue_buffer_msg()
                          └── tf5_tesla_ue_verify_buffered_msgs()
```

### UE NAS Gating

```
nr_rrc_ue_process_rrcSetup()
  └── [Check tf5_state->curr_phase]
        ├── BUFFERED → Defer RRCSetupComplete
        │               Save transaction_id
        │               Phase = RRCSETUP_DEFERRED
        │
        └── BUFFERED_AUTHENTICATED → Send RRCSetupComplete
                                     Phase = RRCSETUP_COMPLETE
```

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Core Network                            │
│  ┌───────────────────┐                                          │
│  │    Core PKG       │  Issues gNB secret keys                  │
│  │ (tf5_ibs_keygen,  │  Distributes MPK to UEs                  │
│  │  tf5_ibs_issue)   │                                          │
│  └───────────────────┘                                          │
└─────────────────────────────────────────────────────────────────┘
              │                               │
              │ sk_ID (51B file)              │ MPK (96B)
              ▼                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                            gNB                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ NR_COMMON_channels_t                                        ││
│  │  ├── tf5_state (tf5_gnb_state_t)                            ││
│  │  │    ├── key_chain[N+1]                                    ││
│  │  │    ├── private_key (sk_ID)                               ││
│  │  │    └── tesla_params (T_int, d, T_0, chain_len)           ││
│  │  ├── sib1_original                                          ││
│  │  └── sib1_bcch_pdu                                          ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
│  config.c: Initialize TESLA state                               │
│  nr_radio_config.c: Update SIB1 extension per TX                │
│  gNB_scheduler_bch.c: Call update before broadcast              │
└─────────────────────────────────────────────────────────────────┘
              │
              │ SIB1 + TESLA Extension (134B)
              │ (signature, tag, disclosed key, params)
              ▼
┌─────────────────────────────────────────────────────────────────┐
│                             UE                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ NR_UE_RRC_SI_INFO                                           ││
│  │  └── tf5_state (tf5_ue_state_t)                             ││
│  │       ├── mpk (Core's Master Public Key)                    ││
│  │       ├── trust_anchor_key / trust_anchor_idx               ││
│  │       ├── buffer_queue[4]                                   ││
│  │       ├── curr_phase (NAS gating state)                     ││
│  │       └── chain_bootstrapped                                ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
│  rrc_UE.c:                                                      │
│    tf5_verify_sib1() → tf5_verify_firsttime()  (IBS path)       │
│                      → tf5_verify_returning()  (TESLA path)     │
│    NAS gating: Defer RRCSetupComplete until authenticated       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Related Documentation

- [gNB Implementation](gnb-implementation.md) - Detailed gNB flow
- [UE Implementation](ue-implementation.md) - Detailed UE flow
- [Data Structures](data-structures.md) - State structure definitions
- [Build Configuration](build.md) - CMake options, key management
