# Integration Points

[Back to Index](index.md)

---

## File Summary

| File | Component | Purpose | TESLA Lines |
|------|-----------|---------|-------------|
| [tf5_tesla.h](../openair3/SECU/tf5_tesla.h) | Core | Data structures, API declarations | 1-680 |
| [tf5_tesla.c](../openair3/SECU/tf5_tesla.c) | Core | Protocol implementation | 1-928 |
| [tf5_tesla_sig.h](../openair3/SECU/tf5_tesla_sig.h) | Core | BLS signature function declarations | 1-103 |
| [tf5_tesla_sig.c](../openair3/SECU/tf5_tesla_sig.c) | Core | BLS signature implementation | 1-231 |
| [nr_mac_gNB.h](../openair2/LAYER2/NR_MAC_gNB/nr_mac_gNB.h) | gNB | State struct definition | 334-340 |
| [config.c](../openair2/LAYER2/NR_MAC_gNB/config.c) | gNB | Initialization | 1174-1254 |
| [nr_radio_config.c](../openair2/LAYER2/NR_MAC_gNB/nr_radio_config.c) | gNB | Extension update (`nr_mac_update_sib1_tf5`) | 4381-4448 |
| [gNB_scheduler_bch.c](../openair2/LAYER2/NR_MAC_gNB/gNB_scheduler_bch.c) | gNB | Scheduler hook | 601-606 |
| [mac_proto.h](../openair2/LAYER2/NR_MAC_gNB/mac_proto.h) | gNB | Function prototype | varies |
| [rrc_defs.h](../openair2/RRC/NR_UE/rrc_defs.h) | UE | State struct definition | 165-167 |
| [rrc_UE.c](../openair2/RRC/NR_UE/rrc_UE.c) | UE | Verification logic (`tf5_verify_sib1`) | 499-812 |

---

## gNB Structure Modification

**Source**: [nr_mac_gNB.h:334-340](../openair2/LAYER2/NR_MAC_gNB/nr_mac_gNB.h#L334-L340)

In `NR_COMMON_channels_t`:

```c
#ifdef ENABLE_TF5
  tf5_gnb_state_t *tf5_state;
  uint8_t sib1_original[NR_MAX_SIB_LENGTH / 8];
  int sib1_original_length;
#endif
```

---

## UE Structure Modification

**Source**: [rrc_defs.h:165-167](../openair2/RRC/NR_UE/rrc_defs.h#L165-L167)

In `NR_UE_RRC_SI_INFO`:

```c
#ifdef ENABLE_TF5
  tf5_ue_state_t *tf5_state;
#endif
```
