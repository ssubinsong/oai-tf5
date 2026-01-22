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

HFN is a counter that increments each time SFN wraps from 1023 to 0:

```c
// Absolute slot calculation
uint64_t absolute_slots = (HFN × 1024 + SFN) × slots_per_frame + slot;
```

---

## gNB HFN Tracking (Core Feature)

HFN is tracked as a **core gNB MAC feature** in `NR_COMMON_channels_t`:

```c
// In nr_mac_gNB.h
typedef struct {
    // ...
    uint16_t hfn;       // Current Hyper-Frame Number (10-bit, 0-1023)
    uint16_t last_sfn;  // Last seen SFN for wraparound detection
    // ...
} NR_COMMON_channels_t;
```

Wraparound detection in `gNB_scheduler_bch.c`:
```c
// Update HFN tracking for hyperSFN-r17 (per TS 38.331)
// Detect SFN wraparound (1023 -> 0) and increment HFN
if (cc->last_sfn > 900 && frameP < 100) {
    cc->hfn = (cc->hfn + 1) & 0x3FF;  // 10-bit wrap
}
cc->last_sfn = frameP;
```

---

## UE HFN Synchronization Challenge

**Problem**: UE learns SFN from SSB synchronization, but **not HFN**. The gNB's HFN is unknown to UE at initial connection.

**Solution**: Use the standard **hyperSFN-r17** field from SIB1-v1700-IEs (per TS 38.331):

1. gNB transmits HFN via hyperSFN-r17 in SIB1-v1700-IEs
2. **Every SIB1**: UE extracts hyperSFN-r17 and updates its HFN tracker
3. UE can also track HFN locally via SFN wraparound detection as backup

```c
// Extract hyperSFN-r17 from SIB1-v1700-IEs (10-bit BIT STRING)
uint16_t hypersfn = (sib1_v1700->hyperSFN_r17->buf[0] << 2) |
                    (sib1_v1700->hyperSFN_r17->buf[1] >> 6);

// Update UE's HFN (simple storage, no local wraparound tracking needed)
state->current_hfn = hypersfn;
state->hfn_initialized = true;
```

> **Note**: UE receives HFN directly from hyperSFN-r17 and stores it as a simple `uint16_t`.
> No local SFN wraparound detection is needed on UE side (gNB handles this).
> HFN is no longer included in the TESLA extension's timesync_info, reducing the
> extension size from 128 to 126 bytes.
