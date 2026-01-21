# Integration Points

[Back to Index](index.md)

---

## File Summary

| File | Component | Purpose | TESLA Lines |
|------|-----------|---------|-------------|
| [tf5_tesla.h](../openair3/SECU/tf5_tesla.h) | Core | Data structures, API declarations | 1-540 |
| [tf5_tesla.c](../openair3/SECU/tf5_tesla.c) | Core | Protocol implementation | 1-859 |
| [tf5_tesla_sig.h](../openair3/SECU/tf5_tesla_sig.h) | Core | BLS signature function declarations | 1-103 |
| [tf5_tesla_sig.c](../openair3/SECU/tf5_tesla_sig.c) | Core | BLS signature implementation | 1-225 |
| [nr_mac_gNB.h](../openair2/LAYER2/NR_MAC_gNB/nr_mac_gNB.h) | gNB | State struct definition | [334-339](../openair2/LAYER2/NR_MAC_gNB/nr_mac_gNB.h#L334-L339) |
| [config.c](../openair2/LAYER2/NR_MAC_gNB/config.c) | gNB | Initialization | [1121-1192](../openair2/LAYER2/NR_MAC_gNB/config.c#L1121-L1192) |
| [nr_radio_config.c](../openair2/LAYER2/NR_MAC_gNB/nr_radio_config.c) | gNB | Extension update | [4366-4440](../openair2/LAYER2/NR_MAC_gNB/nr_radio_config.c#L4366-L4440) |
| [gNB_scheduler_bch.c](../openair2/LAYER2/NR_MAC_gNB/gNB_scheduler_bch.c) | gNB | Scheduler hook | [601-604](../openair2/LAYER2/NR_MAC_gNB/gNB_scheduler_bch.c#L601-L604) |
| [mac_proto.h](../openair2/LAYER2/NR_MAC_gNB/mac_proto.h) | gNB | Function prototype | [62-64](../openair2/LAYER2/NR_MAC_gNB/mac_proto.h#L62-L64) |
| [rrc_defs.h](../openair2/RRC/NR_UE/rrc_defs.h) | UE | State struct definition | [165-167](../openair2/RRC/NR_UE/rrc_defs.h#L165-L167) |
| [rrc_UE.c](../openair2/RRC/NR_UE/rrc_UE.c) | UE | Verification logic | [489-630](../openair2/RRC/NR_UE/rrc_UE.c#L489-L630), [1475-1499](../openair2/RRC/NR_UE/rrc_UE.c#L1475-L1499) |

---

## gNB Structure Modification

**Source**: [nr_mac_gNB.h:334-339](../openair2/LAYER2/NR_MAC_gNB/nr_mac_gNB.h#L334-L339)

In `NR_COMMON_channels_t`:

```c
#ifdef TF5_ENABLE_TESLA
  tf5_tesla_gnb_state_t *tesla_state;
  uint8_t sib1_original[TF5_TESLA_MAX_SIB1_LEN];
  size_t sib1_original_length;
#endif
```

---

## UE Structure Modification

**Source**: [rrc_defs.h:165-167](../openair2/RRC/NR_UE/rrc_defs.h#L165-L167)

In `NR_UE_RRC_SI_INFO`:

```c
#ifdef TF5_ENABLE_TESLA
  tf5_tesla_ue_state_t *tesla_state;
#endif
```
