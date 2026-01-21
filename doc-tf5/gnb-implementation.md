# gNB-Side Implementation

[Back to Index](index.md)

---

## Initialization Flow

**Location**: [config.c:1121-1192](../openair2/LAYER2/NR_MAC_gNB/config.c#L1121-L1192)

```
1. Load BLS key pair from files
   ├── tf5_tesla_load_privkey(tesla_privkey_file, private_key)
   └── tf5_tesla_load_pubkey(tesla_pubkey_file, public_key)

2. Allocate and initialize TESLA state
   └── tf5_tesla_gnb_init()
       ├── Generate random seed K_N
       ├── Compute key chain K_{N-1}, ..., K_0
       ├── Store static params (T_int, d, K_0, T_0, N)
       └── Initialize HFN tracking

3. Store original SIB1 (without extension)
   └── cc->sib1_original[], cc->sib1_original_length

4. Log loaded key paths and public key
   └── LOG_I() with file paths and hex-encoded public key
```

**Command-line parameters**:
- `--tesla-privkey <path>` - Private key file (default: `./tesla_keys/gnb_tesla_privkey.bin`)
- `--tesla-pubkey <path>` - Public key file (default: `./tesla_keys/gnb_tesla_pubkey.bin`)

**Key generation**: Run `./scripts/tf5_generate_bls_keys.sh` before starting gNB.

---

## Per-Transmission Flow

**Location**: [nr_radio_config.c:4380](../openair2/LAYER2/NR_MAC_gNB/nr_radio_config.c#L4380) → `nr_mac_update_sib1_tesla()`

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
       ├── Sign auth_input with BLS
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
