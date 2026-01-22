# TESLA Configuration File

[Back to Index](index.md)

---

## Overview

The TESLA-optimized configuration file `gnb.sa.band78.fr1.106PRB.tesla.conf` provides gNB settings suitable for running with TESLA broadcast authentication enabled. This configuration ensures sufficient PDSCH resources for the larger SIB1 message that includes the TESLA extension.

**Location**: `targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.tesla.conf`

---

## Base Configuration

The TESLA config is derived from the standard OAI RF simulator configuration:

**Original**: `gnb.sa.band78.fr1.106PRB.usrpb210.conf`

This is OAI's reference configuration for:
- Band 78 (3.5 GHz TDD band)
- 106 PRB carrier bandwidth (20 MHz at 30 kHz SCS)
- USRP B210 SDR (also works with RF simulator)

---

## Parameter Changes

### 1. CORESET0 Index

| Parameter | Original | TESLA | Rationale |
|-----------|----------|-------|-----------|
| `initialDLBWPcontrolResourceSetZero` | 12 | 11 | Provides larger SIB1 BWP |

**Why this matters**:

Per TS 38.213 Table 13-4 (CORESET0 configuration for 30 kHz SSB + 30 kHz PDCCH):

| Index | CORESET0 RBs | Symbols | Effect on SIB1 |
|-------|--------------|---------|----------------|
| 12 | 24 | 2 | 48 PRB BWP, ~16 RBs available for PDSCH |
| 11 | 48 | 1 | Larger BWP, more RBs available for PDSCH |

The CORESET0 configuration determines the BWP used for SIB1 PDCCH and PDSCH scheduling. With TESLA, SIB1 grows by ~122 bytes (static params, signature, key, tag). The original CORESET0 index 12 leaves only ~16 contiguous RBs for SIB1 PDSCH after CORESET0 occupies its resources, which is insufficient for the ~234 byte TESLA-extended SIB1.

CORESET0 index 11 uses only 1 OFDM symbol (vs 2 for index 12), leaving more time-domain resources for PDSCH. Combined with the 48 PRB CORESET0 bandwidth, this provides sufficient resources for the larger SIB1.

### 2. Minimum RX-TX Time

| Parameter | Original | TESLA | Rationale |
|-----------|----------|-------|-----------|
| `min_rxtxtime` | (not set) | 6 | Required for RF simulator timing |

**Why this matters**:

The RF simulator mode requires a larger gap between DL reception and UL transmission to account for processing delays. Without this parameter, the UE may fail with:

```
Assertion (k2 >= GET_DURATION_RX_TO_TX(get_UE_ul_slot_offset(nrUE_config))) failed!
```

Setting `min_rxtxtime = 6` in the config eliminates the need to pass `--gNBs.[0].min_rxtxtime 6` on the command line.

---

## Complete Parameter Reference

The TESLA config inherits all other parameters from the base configuration:

| Category | Key Parameters |
|----------|---------------|
| **Frequency** | Band 78, 3600 MHz, 106 PRB (20 MHz) |
| **SCS** | 30 kHz (numerology 1) |
| **TDD Pattern** | 5ms period, DDDDDDSUU (7 DL slots, 6 DL symbols, 2 UL slots, 4 UL symbols) |
| **SSB** | Single beam, 20ms periodicity |
| **PRACH** | Config index 98, root sequence 1 |
| **Security** | NEA0 ciphering, NIA2/NIA0 integrity |

---

## Usage

```bash
cd cmake_targets/ran_build/build

# Generate TESLA keys
../../../scripts/tf5_generate_bls_keys.sh

# Run gNB with TESLA config
sudo ./nr-softmodem \
    -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.tesla.conf \
    --rfsim

# Run UE (separate terminal)
sudo ./nr-uesoftmodem -r 106 --numerology 1 --band 78 -C 3619200000 --rfsim \
    -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/ue.conf
```

---

## Creating Configs for Other Bands/Bandwidths

To create a TESLA-compatible config for a different band or bandwidth:

1. Start with the appropriate OAI reference config
2. Change `initialDLBWPcontrolResourceSetZero` to an index that provides sufficient SIB1 resources
3. Add `min_rxtxtime = 6` for RF simulator mode
4. Verify SIB1 can be scheduled by checking for resource allocation errors

**CORESET0 index selection guidance** (TS 38.213 Table 13-1 to 13-15):
- Choose indices with fewer OFDM symbols (1 symbol preferred over 2-3)
- Larger CORESET0 bandwidth indices often provide more PDSCH resources
- Test with TESLA-enabled build to verify sufficient resources

---

## Troubleshooting

If you see this error with the TESLA config:

```
Couldn't allocate enough resources for X bytes in SIB PDSCH
```

The CORESET0 configuration still doesn't provide enough resources. Try:
1. A different CORESET0 index with fewer symbols
2. A configuration with larger carrier bandwidth
3. Verify the config file is being loaded correctly (check gNB startup logs)

See [Troubleshooting](troubleshooting.md) for more details.
