# gNB-Side Implementation

[Back to Index](index.md)

---

## Initialization Flow

**Location**: [config.c:1174-1254](../openair2/LAYER2/NR_MAC_gNB/config.c#L1174-L1254)

The initialization is performed in `configure_common_channels_nr()` within the `#ifdef ENABLE_TF5` block:

```
1. Allocate TESLA state
   └── Allocate tf5_gnb_state_t

2. Get slots per frame from numerology
   └── slots_per_frame = nr_slots_per_frame[mu]

3. Check key path is provided
   └── Verify tf5_privkey_file is set

4. Initialize BLS library
   └── tf5_tesla_bls_init()

5. Load IBS secret key + validity period (35 bytes)
   └── tf5_tesla_load_privkey(tf5_privkey_file, private_key, &key_validity_end)

6. Validate key_validity_end range
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

12. Store key validity period in TESLA state
    └── tf5_state->key_validity_end = key_validity_end

13. Log validity info
    └── LOG_I() with expiration timestamp

14. Encode initial SIB1
    └── encode_SIB_NR() -> cc->sib1_bcch_pdu[]
```

**Helper function**: `tf5_get_first_sib1_occasion()` in [config.c](../openair2/LAYER2/NR_MAC_gNB/config.c)
- Calculates T_0 based on Type0-PDCCH CSS configuration
- Validates only CORESET mux pattern 1 is used

**Command-line parameters**:
- `--tf5-privkey <path>` - IBS secret key file (35 bytes: sk_ID + validity, issued by Core PKG)

**Key generation**: Use the Core PKG utilities (located in `openair3/SECU/core-pkg/`) to issue gNB keys:
```bash
cd cmake_targets/ran_build/build
./tf5_ibs_issue pkg_keys/msk.bin <cell_id_hex> <validity_end> gnb_keys/sk_gnb.bin
```

See [build.md](build.md#key-management-ibs) for the full key generation workflow.

The validity period is embedded in the 35-byte key file (bytes 32-34, big-endian).

**Cell ID binding**: The gNB's secret key is cryptographically bound to its Cell ID.
The `cellID` in your gNB config must match the Cell ID used during key issuance.

---

## Per-Transmission Flow

**Location**: [nr_radio_config.c:4381-4448](../openair2/LAYER2/NR_MAC_gNB/nr_radio_config.c#L4381-L4448) → `nr_mac_update_sib1_tf5()`

Called from scheduler before each SIB1 transmission:

```
1. Check tf5_state is initialized
   └── Early return if not initialized

2. Capture original SIB1 (without extension) for signature computation
   └── Save lateNonCriticalExtension pointer
   └── Temporarily set to NULL
   └── Encode NR_SIB1 to cc->sib1_original
   └── Restore lateNonCriticalExtension pointer

3. Prepare TESLA extension
   └── tf5_tesla_gnb_prepare_extension(state, sfn, slot, sib1_original, sib1_len, &ext)
       ├── Compute current interval from SFN/slot
       ├── Set dynamic params (i, key_disclosure, timestamp_ms)
       ├── Build signature auth_input = SIB1 || tesla_params || validity_end || ...
       ├── Sign auth_input with IBS (uses sk_ID)
       ├── Build MAC auth_input = SIB1 || validity_end
       └── Compute TESLA tag with K_i

4. Pack extension to binary (102 bytes)
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
      if (cc->tf5_state && cc->tf5_state->initialized) {
        nr_mac_update_sib1_tf5(cc, frameP, slotP);
      }
#endif
```

**Function signature** (declared in [mac_proto.h](../openair2/LAYER2/NR_MAC_gNB/mac_proto.h)):
```c
void nr_mac_update_sib1_tf5(NR_COMMON_channels_t *cc,
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
  tf5_gnb_state_t *tf5_state;
  /// Original SIB1 (without TESLA extension) for MAC computation
  uint8_t sib1_original[NR_MAX_SIB_LENGTH / 8];
  int sib1_original_length;
#endif
```
