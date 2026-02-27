# gNB Configuration

[Back to Index](index.md)

---

## Overview

TF5 works with the **standard OAI gNB configuration** — no custom config file is needed.

After the SIB1/SIB9 data split, the SIB1 TESLA extension is only 37 bytes (version + interval index + disclosed key + tag). This fits within the default CORESET0 index 12 / `sib1_tda=1` scheduling parameters. The larger static data (TESLA params + IBS signature, 114 bytes) is carried in SIB9 as a separate SI message.

**Base config**: `targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.usrpb210.conf`

### RF Simulator: `min_rxtxtime`

When using `--rfsim`, the UE requires a larger RX-to-TX gap. Pass this on the command line:

```
--gNBs.[0].min_rxtxtime 6
```

Without it, the UE will crash with:
```
Assertion (k2 >= GET_DURATION_RX_TO_TX(get_UE_ul_slot_offset(nrUE_config))) failed!
```

This is an RF simulator requirement, not TESLA-specific.

---

## Usage

```bash
# Generate TESLA keys (from project root)
mkdir -p pkg_keys gnb_keys
./openair3/SECU/core-pkg/tf5_ibs_keygen.sh pkg_keys/msk.bin pkg_keys/mpk.bin
./openair3/SECU/core-pkg/tf5_ibs_issue.sh pkg_keys/msk.bin 000000e00 2628000 gnb_keys/sk_gnb.bin

# Run gNB (standard config + min_rxtxtime for rfsim)
cd cmake_targets/ran_build/build
sudo ./nr-softmodem \
    -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.usrpb210.conf \
    --rfsim \
    --gNBs.[0].min_rxtxtime 6 \
    --tf5-privkey ../../../gnb_keys/sk_gnb.bin

# Run UE (separate terminal)
sudo ./nr-uesoftmodem -r 106 --numerology 1 --band 78 -C 3619200000 --rfsim \
    -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/ue.conf \
    --tf5-core-mpk ../../../pkg_keys/mpk.bin
```

---

## Historical Note

Before the SIB1/SIB9 data split, all TESLA data (~150 bytes) was carried in SIB1's `lateNonCriticalExtension`. This made SIB1 too large for the default CORESET0/TDA settings, requiring a dedicated config file (`gnb.sa.band78.fr1.106PRB.tesla.conf`) with CORESET0 index 11 and `sib1_tda=5`.

With the split, SIB1 extension shrank to 37 bytes — well within default scheduling capacity. The dedicated config was removed.
