# oai-tf5 — Project Overview

## Purpose
TF5 (TESLA for 5G) implements TESLA broadcast authentication (RFC 4082) for 5G NR SIB1 messages, protecting UEs against fake base station attacks. This is an extended OpenAirInterface (OAI) 5G RAN stack (gNB + UE) with TESLA protocol integration.

## Tech Stack
- **Language**: C (source), C++ (unit tests)
- **Build system**: CMake + Ninja (via `build_oai` wrapper or CMake presets)
- **Test framework**: Google Test (GTest)
- **Crypto libraries**: OpenSSL (HMAC-SHA256), blst (BLS12-381 pairings)
- **Platform**: Linux (5G RAN typically runs on Linux)

## High-Level Architecture
```
executables/           Top-level main() for nr-softmodem (gNB), nr-uesoftmodem (UE)
openair1/              Layer 1 - Physical layer (PHY)
openair2/              Layer 2 - MAC/RLC/PDCP/RRC
  └── LAYER2/NR_MAC_gNB/   gNB MAC scheduler — TESLA signing at SIB1 TX
  └── RRC/NR_UE/            UE RRC — TESLA verification at SIB1 RX
openair3/              Layer 3 - Security, S1AP/NGAP
  └── SECU/                 TESLA core implementation (tf5_tesla.c, tf5_tesla_sig.c)
      └── core-pkg/         Standalone IBS key generation tools
      └── tests/            Unit tests (10 suites, GTest)
doc-tf5/               Project-specific documentation
claude-ref/            RFC & 3GPP specification corpus
```

## Key TF5 Files
| File | Purpose |
|------|---------|
| `openair3/SECU/tf5_tesla.c` | Protocol: key chains, MAC, verification |
| `openair3/SECU/tf5_tesla.h` | Data structures, API, constants |
| `openair3/SECU/tf5_tesla_sig.c/h` | BLMQ IBS signature operations (sign, verify, init) |
| `openair3/SECU/tf5_crypto.c/h` | Crypto primitives (SHA256, HMAC) |
| `openair3/SECU/tf5_ibs_defs.h` | Shared IBS/BLMQ constants, error codes, BLS curve params |
| `openair3/SECU/tf5_ibs_common.c` | IBS common utilities |
| `openair3/SECU/tf5_ibs_pkg.h` | Core PKG interface |
| `openair2/LAYER2/NR_MAC_gNB/config.c` | gNB TESLA state initialization |
| `openair2/LAYER2/NR_MAC_gNB/nr_radio_config.c` | TESLA extension update per SIB1 |
| `openair2/RRC/NR_UE/rrc_UE.c` | UE verification logic |

## Conditional Compilation
All TESLA code is wrapped in `#ifdef ENABLE_TF5`. The CMake option `ENABLE_TF5` controls this.

## Dual Authentication Protocol
1. **BLMQ IBS Signature** (immediate): BLMQ IBS (ASIACRYPT 2005 Section 3) over BLS12-381. sk_ID = [1/(H1(ID)+s)]·P ∈ G1 (48B), σ = (h, S) ∈ Z*p × G1 (80B). Single-pairing verification via multi-Miller loop.
2. **TESLA MAC** (delayed): HMAC-SHA256 verified after key disclosure (d=1 interval delay)

## Key Sizes
| Component | Size |
|-----------|------|
| gNB secret key (sk_ID) | 48B (G1 point) |
| IBS signature | 80B (32B h + 48B S) |
| TESLA extension wire | 134B |
| gNB SK file | 51B (48B sk + 3B validity) |
| Master secret (msk) | 32B (scalar) |
| Master public (MPK) | 96B (G2 point) |
| Protocol version | 0x02 |

## Branch
Main branch: `tf5`
