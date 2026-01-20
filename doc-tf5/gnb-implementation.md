# gNB-Side Implementation

[Back to Index](index.md)

---

## Initialization Flow

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

---

## Per-Transmission Flow

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

---

## Scheduler Integration

**Location**: `openair2/LAYER2/NR_MAC_gNB/gNB_scheduler_bch.c`

```c
#ifdef TF5_ENABLE_TESLA
if (cc->tesla_state && cc->tesla_state->initialized) {
    nr_mac_update_sib1_tesla(mac, cc, slot);
}
#endif
```
