# Integration Points

[Back to Index](index.md)

---

## File Summary

| File | Component | Purpose |
|------|-----------|---------|
| `openair3/SECU/tf5_tesla.h` | Core | Data structures, API declarations |
| `openair3/SECU/tf5_tesla.c` | Core | Protocol implementation (~760 lines) |
| `openair3/SECU/tf5_tesla_sig.h` | Core | Ed25519 function declarations |
| `openair3/SECU/tf5_tesla_sig.c` | Core | Ed25519 implementation |
| `openair2/LAYER2/NR_MAC_gNB/nr_mac_gNB.h` | gNB | State struct definition |
| `openair2/LAYER2/NR_MAC_gNB/config.c` | gNB | Initialization |
| `openair2/LAYER2/NR_MAC_gNB/nr_radio_config.c` | gNB | Extension update |
| `openair2/LAYER2/NR_MAC_gNB/gNB_scheduler_bch.c` | gNB | Scheduler hook |
| `openair2/LAYER2/NR_MAC_gNB/mac_proto.h` | gNB | Function prototype |
| `openair2/RRC/NR_UE/rrc_defs.h` | UE | State struct definition |
| `openair2/RRC/NR_UE/rrc_UE.c` | UE | Verification logic |

---

## gNB Structure Modification

In `nr_mac_gNB.h`, added to `NR_COMMON_channels_t`:

```c
#ifdef TF5_ENABLE_TESLA
  tf5_tesla_gnb_state_t *tesla_state;
  uint8_t sib1_original[TF5_TESLA_MAX_SIB1_LEN];
  size_t sib1_original_length;
#endif
```

---

## UE Structure Modification

In `rrc_defs.h`, added to `NR_UE_RRC_SI_INFO`:

```c
#ifdef TF5_ENABLE_TESLA
  tf5_tesla_ue_state_t *tesla_state;
#endif
```
