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

### 3. SIB1 Time Domain Allocation

| Parameter | Original | TESLA | Rationale |
|-----------|----------|-------|-----------|
| `sib1_tda` | 1 (default) | 5 | Avoids SSB symbol overlap |

**Why this matters**:

SSB occupies symbols 2-5 in the SIB1 slot. The default TDA (index 1) places SIB1 PDSCH in symbols 2-11, causing time-domain overlap with SSB. During this overlap, SSB's 20 RBs are unavailable in the vrb_map, leaving only 14 contiguous RBs on each side of SSB - insufficient for the 234-byte TESLA SIB1.

TDA index 5 places SIB1 PDSCH in symbols 9-12, completely avoiding SSB overlap:
- Symbols 9-12: 4 OFDM symbols for PDSCH
- All 48 RBs available (no SSB conflict)
- Capacity: ~500+ bytes (sufficient for 234-byte TESLA SIB1)

Without this parameter, the gNB fails with:
```
Couldn't allocate enough resources for 234 bytes in SIB PDSCH (rbStart 0, rbSize 14, bwpSize 48)
```

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
# Generate TESLA keys (from project root)
mkdir -p pkg_keys gnb_keys
./openair3/SECU/core-pkg/tf5_ibs_keygen.sh pkg_keys/msk.bin pkg_keys/mpk.bin
./openair3/SECU/core-pkg/tf5_ibs_issue.sh pkg_keys/msk.bin 000000e00 2628000 gnb_keys/sk_gnb.bin

# Run gNB with TESLA config
cd cmake_targets/ran_build/build
sudo ./nr-softmodem \
    -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.tesla.conf \
    --rfsim \
    --tf5-privkey ../../../gnb_keys/sk_gnb.bin

# Run UE (separate terminal)
sudo ./nr-uesoftmodem -r 106 --numerology 1 --band 78 -C 3619200000 --rfsim \
    -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/ue.conf \
    --tf5-core-mpk pkg_keys/mpk.bin
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
Couldn't allocate enough resources for X bytes in SIB PDSCH (rbStart 0, rbSize 14, bwpSize 48)
```

This typically indicates time-domain overlap between SIB1 PDSCH and SSB. The fix is to add `sib1_tda = 5` to the config file, which places SIB1 PDSCH in symbols 9-12 (avoiding SSB's symbols 2-5).

If the error persists after adding `sib1_tda`:
1. Try alternative TDA values: `sib1_tda = 7` (symbols 5-11) or `sib1_tda = 15` (symbols 8-11)
2. Verify the config file is being loaded correctly (check gNB startup logs for parameter values)
3. Try a different CORESET0 index (10, 11, or 12 all provide 48 RBs)

If the issue persists, check the gNB startup logs for additional diagnostic information.
