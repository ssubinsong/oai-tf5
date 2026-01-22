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

## Wraparound Detection

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

// Update UE's HFN tracker
state->hfn_tracker.current_hfn = hypersfn;
state->hfn_tracker.last_sfn = rx_sfn;
state->hfn_initialized = true;
```

> **Note**: HFN is no longer included in the TESLA extension's timesync_info.
> This reduces the extension size from 128 to 126 bytes and uses standard 3GPP signaling.
