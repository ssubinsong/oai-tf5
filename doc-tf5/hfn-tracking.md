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

**Solution**: Use the **signed ti_hfn** from the TESLA extension:

1. The Ed25519 signature covers ti_hfn, making it trustworthy
2. **First SIB1**: UE bootstraps HFN from signed extension
3. **Subsequent SIB1s**: UE tracks HFN locally via SFN wraparound detection

```c
// First reception
state->current_hfn = ext->timesync_info.ti_hfn;
state->hfn_initialized = true;

// Subsequent receptions - update HFN based on SFN wraparound
tf5_tesla_update_hfn(&state->current_hfn, &state->last_sfn, rx_sfn);
```
