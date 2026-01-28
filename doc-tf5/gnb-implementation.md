# gNB-Side Implementation

[Back to Index](index.md)

---

## Initialization Flow

**Location**: [config.c:1121-1192](../openair2/LAYER2/NR_MAC_gNB/config.c#L1121-L1192)

```
1. Load IBS secret key (sk_ID) from file
   └── tf5_tesla_load_privkey(tesla_privkey_file, private_key)

2. Extract Cell ID from gNB configuration
   └── cellID (36 bits) -> gnb_cell_id[5]

3. Allocate and initialize TESLA state
   └── tf5_tesla_gnb_init()
       ├── Generate random seed K_N
       ├── Compute key chain K_{N-1}, ..., K_0
       ├── Store static params (T_int, d, K_0, T_0, N)
       └── Store Cell ID for signature binding

4. Store original SIB1 (without extension)
   └── cc->sib1_original[], cc->sib1_original_length

5. Log loaded key path
   └── LOG_I() with file path
```

**Command-line parameters**:
- `--tesla-privkey <path>` - IBS secret key file (sk_ID issued by Core PKG)

**Key generation**: Use the Core PKG to issue gNB keys:
```bash
cd tf5-core-pkg/build
./tf5_ibs_issue pkg_keys/msk.bin <cell_id_hex> gnb_keys/sk_gnb.bin
```

**Cell ID binding**: The gNB's secret key is cryptographically bound to its Cell ID.
The `cellID` in your gNB config must match the Cell ID used during key issuance.

---

## Per-Transmission Flow

**Location**: [nr_radio_config.c:4380](../openair2/LAYER2/NR_MAC_gNB/nr_radio_config.c#L4380) → `nr_mac_update_sib1_tesla()`

Called from scheduler before each SIB1 transmission:

```
1. Get current interval from SFN/slot
   └── tf5_tesla_gnb_get_interval()
       └── Calculate interval index

2. Prepare TESLA extension
   └── tf5_tesla_gnb_prepare_extension()
       ├── Set dynamic params (i, ti_sfn, ti_slot, K_{i-d})
       ├── Build auth_input = SIB1 || static || dynamic
       ├── Sign auth_input with IBS (uses sk_ID)
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

**Location**: [gNB_scheduler_bch.c:601-604](../openair2/LAYER2/NR_MAC_gNB/gNB_scheduler_bch.c#L601-L604)

```c
#ifdef TF5_ENABLE_TESLA
if (cc->tesla_state && cc->tesla_state->initialized) {
    nr_mac_update_sib1_tesla(mac, cc, slot);
}
#endif
```
