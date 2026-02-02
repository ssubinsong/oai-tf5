# gNB-Side Implementation

[Back to Index](index.md)

---

## Initialization Flow

**Location**: [config.c:1120-1282](../openair2/LAYER2/NR_MAC_gNB/config.c#L1120-L1282)

The initialization is performed in `nr_mac_configure_sib1()` within the `#ifdef ENABLE_TF5` block:

```
1. Allocate TESLA state
   └── Allocate tf5_tesla_gnb_state_t

2. Get slots per frame from numerology
   └── slots_per_frame = nr_slots_per_frame[mu]

3. Check key path is provided
   └── Verify tesla_privkey_file is set

4. Initialize BLS library
   └── tf5_tesla_bls_init()

5. Load IBS secret key + validity period (35 bytes)
   └── tf5_tesla_load_privkey(tesla_privkey_file, private_key, &gnb_key_validity_end)

6. Validate gnb_key_validity_end range
   └── Assert validity fits in 24 bits

7. Check if key has expired
   └── Compare against current wall-clock time
   └── AssertFatal if key is expired

8. Extract NR Cell ID (36 bits = 5 bytes)
   └── Extract from gNB config -> gnb_cell_id[5]

9. Log loaded key info
   └── LOG_I() with file path and validity

10. Calculate T_0 via tf5_get_first_sib1_occasion()
    └── Uses Type0-PDCCH CSS configuration
    └── Only CORESET mux pattern 1 is supported

11. Initialize TESLA with tf5_tesla_gnb_init()
    └── Generate random seed K_N
    └── Compute key chain K_{N-1}, ..., K_0
    └── Store params (T_int, d, chain_len, private_key, T_0, slots_per_frame)

12. Store Cell ID in TESLA state
    └── memcpy(tesla_state->gnb_cell_id, ...)

13. Store key validity period in TESLA state
    └── tesla_state->gnb_key_validity_end = gnb_key_validity_end

14. Log validity info
    └── LOG_I() with expiration timestamp

15. Encode initial SIB1
    └── encode_SIB_NR() -> cc->sib1_bcch_pdu[]
```

**Helper function**: `tf5_get_first_sib1_occasion()` at [config.c:1120-1162](../openair2/LAYER2/NR_MAC_gNB/config.c#L1120-L1162)
- Calculates T_0 based on Type0-PDCCH CSS configuration
- Validates only CORESET mux pattern 1 is used

**Command-line parameters**:
- `--tesla-privkey <path>` - IBS secret key file (35 bytes: sk_ID + validity, issued by Core PKG)

**Key generation**: Use the Core PKG to issue gNB keys:
```bash
cd tf5-core-pkg/build
./tf5_ibs_issue pkg_keys/msk.bin <cell_id_hex> <validity_end> gnb_keys/sk_gnb.bin
```

The validity period is embedded in the 35-byte key file (bytes 32-34, big-endian).

**Cell ID binding**: The gNB's secret key is cryptographically bound to its Cell ID.
The `cellID` in your gNB config must match the Cell ID used during key issuance.

---

## Per-Transmission Flow

**Location**: [nr_radio_config.c:4383-4453](../openair2/LAYER2/NR_MAC_gNB/nr_radio_config.c#L4383-L4453) → `nr_mac_update_sib1_tesla()`

Called from scheduler before each SIB1 transmission:

```
1. Check tesla_state is initialized
   └── Early return if not initialized

2. Capture original SIB1 (without extension) for signature computation
   └── Save lateNonCriticalExtension pointer
   └── Temporarily set to NULL
   └── Encode NR_SIB1 to cc->sib1_original
   └── Restore lateNonCriticalExtension pointer

3. Prepare TESLA extension
   └── tf5_tesla_gnb_prepare_extension(state, sfn, slot, sib1_original, sib1_len, &ext)
       ├── Compute current interval from SFN/slot
       ├── Set dynamic params (interval_index, disclosed_key, timestamp_ms)
       ├── Build signature auth_input = SIB1 || tesla_params || gnb_key_validity_end || ...
       ├── Sign auth_input with IBS (uses sk_ID)
       ├── Build MAC auth_input = SIB1 || gnb_key_validity_end
       └── Compute TESLA tag with K_i

4. Pack extension to binary (103 bytes)
   └── tf5_tesla_pack_extension(&ext, buffer, sizeof(buffer))

5. Allocate/set lateNonCriticalExtension
   └── sib1->lateNonCriticalExtension = OCTET_STRING with packed extension

6. Re-encode SIB1 with TESLA extension
   └── encode_SIB_NR()
```

**Critical step**: The original SIB1 capture (step 2) ensures the signature covers the SIB1 content without the extension itself, preventing circular dependency.

---

## Scheduler Integration

**Location**: [gNB_scheduler_bch.c:601-606](../openair2/LAYER2/NR_MAC_gNB/gNB_scheduler_bch.c#L601-L606)

```c
#ifdef ENABLE_TF5
      // Update TESLA extension with current frame/slot before transmission
      if (cc->tesla_state && cc->tesla_state->initialized) {
        nr_mac_update_sib1_tesla(gNB_mac, cc, frameP, slotP);
      }
#endif
```

**Function signature** (declared in [mac_proto.h:63](../openair2/LAYER2/NR_MAC_gNB/mac_proto.h#L63)):
```c
void nr_mac_update_sib1_tesla(gNB_MAC_INST *mac,
                              NR_COMMON_channels_t *cc,
                              frame_t frame,
                              slot_t slot);
```

---

## Data Structure Integration

**Location**: [nr_mac_gNB.h:334-340](../openair2/LAYER2/NR_MAC_gNB/nr_mac_gNB.h#L334-L340)

Fields added to `NR_COMMON_channels_t`:

```c
#ifdef ENABLE_TF5
  /// TESLA broadcast authentication state
  tf5_tesla_gnb_state_t *tesla_state;
  /// Original SIB1 (without TESLA extension) for MAC computation
  uint8_t sib1_original[NR_MAX_SIB_LENGTH / 8];
  int sib1_original_length;
#endif
```
