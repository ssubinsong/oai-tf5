# HFN Tracking

[Back to Index](index.md)

---

## Problem

The System Frame Number (SFN) is a 10-bit counter (0-1023) that wraps every:
```
1024 frames × 10ms = 10.24 seconds
```

However, the TESLA key chain lasts ~21.8 minutes, requiring tracking across multiple SFN cycles.

---

## Solution: Hyper-Frame Number (HFN)

HFN is a 10-bit counter (0-1023) that increments each time SFN wraps from 1023 to 0:

```c
// Absolute slot calculation
uint64_t absolute_slots = (HFN × 1024 + SFN) × slots_per_frame + slot;
```

---

## Architecture: Symmetric ITTI-based HFN Tracking

Both gNB and UE use the same architecture for HFN tracking:

1. **Lower layer detects SFN wrap** (MAC for gNB, PHY for UE)
2. **Sends ITTI notification** (`NRRRC_SFN_WRAP`) to RRC
3. **RRC increments HFN counter** (`current_hfn`)

This design keeps HFN tracking exclusively in the RRC layer (single source of truth).

### Shared ITTI Message Definition

```c
// In rrc_messages_types.h
typedef struct nrrrc_sfn_wrap_s {
  // Empty - the message itself is the notification
} NRRrcSfnWrap;

// In rrc_messages_def.h
MESSAGE_DEF(NRRRC_SFN_WRAP, MESSAGE_PRIORITY_MED, NRRrcSfnWrap, nrrrc_sfn_wrap)
```

---

## gNB HFN Tracking

### RRC Structure

```c
// In nr_rrc_defs.h - gNB_RRC_INST
#ifdef TF5_ENABLE_TESLA
  uint16_t current_hfn;  // HFN tracked by RRC, incremented on SFN wrap
#endif
```

### SFN Wrap Detection (MAC Layer)

In `gNB_scheduler.c`:
```c
#ifdef TF5_ENABLE_TESLA
  static frame_t last_frame = -1;
  if (last_frame == MAX_FRAME_NUMBER - 1 && frame == 0) {
    // SFN wrapped - send ITTI notification to RRC
    MessageDef *msg_p = itti_alloc_new_message(TASK_MAC_GNB, 0, NRRRC_SFN_WRAP);
    itti_send_msg_to_task(TASK_RRC_GNB, module_idP, msg_p);
  }
  last_frame = frame;
#endif
```

### HFN Increment (RRC Layer)

In `rrc_gNB.c`:
```c
#ifdef TF5_ENABLE_TESLA
  case NRRRC_SFN_WRAP:
    RC.nrrrc[instance]->current_hfn = (RC.nrrrc[instance]->current_hfn + 1) & 0x3FF;
    break;
#endif
```

### hyperSFN-r17 Update

In `nr_radio_config.c`:
```c
// Get HFN from RRC (single source of truth)
uint16_t hfn = RC.nrrrc[mac->Mod_id]->current_hfn;

// Update hyperSFN-r17 in SIB1 with current HFN
update_hypersfn_r17(sib1, hfn);
```

---

## UE HFN Tracking

### RRC Structure

```c
// In rrc_defs.h - NR_UE_RRC_INST_t
#ifdef TF5_ENABLE_TESLA
  uint16_t current_hfn;   // HFN tracked by RRC, incremented on SFN wrap
  bool hfn_initialized;   // Has HFN been initialized from hyperSFN-r17?
#endif
```

### SFN Wrap Detection (PHY Layer)

In `nr-ue.c`:
```c
#ifdef TF5_ENABLE_TESLA
  static int last_frame_rx = -1;
  if (last_frame_rx == MAX_FRAME_NUMBER - 1 && curMsg.proc.frame_rx == 0) {
    // SFN wrapped - notify RRC
    nr_ue_rrc_sfn_wrap_notify(UE->Mod_id);
  }
  last_frame_rx = curMsg.proc.frame_rx;
#endif
```

### HFN Increment (RRC Layer)

In `rrc_UE.c`:
```c
#ifdef TF5_ENABLE_TESLA
  case NRRRC_SFN_WRAP:
    rrc->current_hfn = (rrc->current_hfn + 1) & 0x3FF;  // 10-bit wrap
    break;
#endif
```

---

## UE HFN Initialization and Reconciliation

The UE initializes and reconciles its HFN from the network's hyperSFN-r17 in SIB1:

```c
// In rrc_UE.c - SIB1 processing
if (sib1_v1700 && sib1_v1700->hyperSFN_r17) {
  uint16_t network_hfn = (sib1_v1700->hyperSFN_r17->buf[0] << 2) |
                         (sib1_v1700->hyperSFN_r17->buf[1] >> 6);

  if (!rrc->hfn_initialized) {
    // First SIB1: initialize RRC HFN from network
    rrc->current_hfn = network_hfn;
    rrc->hfn_initialized = true;
  } else {
    // Reconciliation: compare RRC-tracked HFN vs network hyperSFN
    int16_t diff = (int16_t)network_hfn - (int16_t)rrc->current_hfn;
    // Handle wraparound for 10-bit values
    if (diff > 512) diff -= 1024;
    if (diff < -512) diff += 1024;

    if (diff != 0) {
      LOG_W(NR_RRC, "TESLA: HFN mismatch! local=%u, network=%u. Adopting network.\n",
            rrc->current_hfn, network_hfn);
      rrc->current_hfn = network_hfn;
    }
  }
}
```

### Safe Packet Test

The TESLA safe packet test uses the RRC-tracked HFN (local value):

```c
uint16_t rx_hfn = rrc->current_hfn;  // Use local HFN for timing verification
tf5_tesla_ue_safe_packet_test(tesla_state, &ext, rx_frame, rx_slot, rx_hfn);
```

---

## Data Flow Summary

### gNB
```
MAC (scheduler) --[NRRRC_SFN_WRAP]--> RRC (current_hfn++) --[used by]--> SIB1 hyperSFN-r17
```

### UE
```
PHY (nr-ue.c) --[NRRRC_SFN_WRAP]--> RRC (current_hfn++)
                                         |
SIB1 hyperSFN-r17 ---------------------->| (init/reconcile)
                                         |
                                   Safe Packet Test (uses rrc->current_hfn)
```

---

## Log Messages

### gNB Logs
- `Sent NRRRC_SFN_WRAP notification` - MAC sends wrap notification every ~10.24s
- `SFN wrap detected, HFN incremented to X` - RRC increments HFN

### UE Logs
- `Sent NRRRC_SFN_WRAP notification` - PHY sends wrap notification every ~10.24s
- `SFN wrap detected, HFN incremented to X` - RRC increments HFN
- `TESLA: HFN initialized from hyperSFN-r17: X` - First SIB1 reception
- `TESLA: HFN in sync (HFN=X)` - Subsequent SIB1, HFN matches
- `TESLA: HFN mismatch! local=X, network=Y` - Drift detected, corrected

---

## Conditional Compilation

All HFN tracking code is TESLA-conditional:

```c
#ifdef TF5_ENABLE_TESLA
  // HFN tracking code
#endif
```

Build with TESLA:
```bash
./build_oai --ninja --gNB -c --cmake-opt "-DTF5_ENABLE_TESLA=ON"
./build_oai --ninja --nrUE -c --cmake-opt "-DTF5_ENABLE_TESLA=ON"
```
