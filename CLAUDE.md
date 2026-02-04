# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Directions

- Whenever you make a `git commit`, make sure to override the author name as "Claude Code".
- When writing code, focus on making the algorithm efficient. Especially, aim to minimize time complexity.

## Project Overview

TF5 (TESLA for 5G) implements TESLA (RFC 4082) broadcast authentication for 5G NR SIB1 messages, protecting UEs against fake base station attacks. This is an extended OpenAirInterface (OAI) stack with TESLA protocol integration.

## Build Commands

**Standard build with TESLA enabled:**
```bash
cd cmake_targets
./build_oai --ninja --gNB --nrUE --cmake-opt -DENABLE_TF5=ON
```

**Build with tests:**
```bash
cd cmake_targets
./build_oai --ninja --gNB --nrUE --cmake-opt "-DENABLE_TESTS=ON -DENABLE_TF5=ON"
```

**Using CMake presets:**
```bash
cmake --preset default        # Configure (ENABLE_TF5=ON by default)
cmake --build --preset 5gdefault    # Build gNB + UE
cmake --preset tests          # Configure with tests
cmake --build --preset tf5_tests    # Build TF5 tests only
```

Build output: `cmake_targets/ran_build/build/` (default) or `cmake_targets/ran_build/build_test/` (tests)

## Running Tests

```bash
cd cmake_targets/ran_build/build

# All TF5 tests
ctest -R tf5 -V

# Individual test suites
./test_tf5_tesla_crypto    # Crypto primitives
./test_tf5_tesla_gnb       # gNB functions
./test_tf5_tesla_ue        # UE verification
./test_tf5_tesla_e2e       # End-to-end flow
./test_tf5_tesla_bls       # BLS signatures
./test_tf5_tesla_serial    # Serialization
./test_tf5_tesla_timing    # Timing/replay protection
./test_tf5_tesla_fileio    # Key file I/O
./test_tf5_ibs_pkg         # Core PKG key management
```

## Architecture

### Layer Structure

```
executables/           Top-level main() for nr-softmodem (gNB), nr-uesoftmodem (UE)
openair1/              Layer 1 - Physical layer (PHY)
openair2/              Layer 2 - MAC/RLC/PDCP/RRC
  └── LAYER2/NR_MAC_gNB/   gNB MAC scheduler - TESLA signing at SIB1 transmission
  └── RRC/NR_UE/           UE RRC - TESLA verification at SIB1 reception
openair3/              Layer 3 - Security, S1AP/NGAP
  └── SECU/                TESLA core implementation
      └── core-pkg/        IBS key generation utilities (Core PKG)
      └── tests/           Unit tests (10 test suites)
```

### Key TESLA Files

| File | Purpose |
|------|---------|
| `openair3/SECU/tf5_tesla.c` | Protocol implementation (key chains, MAC, verification) |
| `openair3/SECU/tf5_tesla.h` | Data structures, API, constants |
| `openair3/SECU/tf5_tesla_sig.c` | BLS signature operations |
| `openair2/LAYER2/NR_MAC_gNB/config.c` | gNB TESLA state initialization |
| `openair2/LAYER2/NR_MAC_gNB/nr_radio_config.c` | TESLA extension update per SIB1 |
| `openair2/RRC/NR_UE/rrc_UE.c` | UE verification logic |

### Integration Points

TESLA state is added to existing OAI structures:
- **gNB**: `tf5_tesla_gnb_state_t` in `NR_COMMON_channels_t` (`nr_mac_gNB.h:334`)
- **UE**: `tf5_tesla_ue_state_t` in `NR_UE_RRC_SI_INFO` (`rrc_defs.h:165`)

### Dual Authentication

1. **IBS Signature** (immediate): BLS12-381 signature verified using Core's Master Public Key
2. **TESLA MAC** (delayed): HMAC verified after key disclosure (d=1 interval delay)

## Key Management

**Generate master keypair (one-time):**
```bash
./tf5_ibs_pkg_keygen pkg_keys/msk.bin pkg_keys/mpk.bin
```

**Issue gNB secret key:**
```bash
./tf5_ibs_issue pkg_keys/msk.bin <cell_id_hex> <validity_minutes> gnb_keys/sk_gnb.bin
# validity_minutes: minutes since 2024-01-01 00:00 UTC
```

**Runtime:**
```bash
# gNB
./nr-softmodem -O gnb.conf --tesla-privkey /path/to/sk_gnb.bin

# UE
./nr-uesoftmodem ... --tesla-core-mpk /path/to/mpk.bin
```

## Configuration

Use TESLA-optimized gNB config: `targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.tesla.conf`

This config uses CORESET0 index 11 which provides sufficient PRBs for the larger SIB1 with TESLA extension.

## Documentation

Project-specific docs in `doc-tf5/`:
- `index.md` - Documentation index
- `protocol.md` - TESLA key chains, intervals, disclosure delay
- `cryptography.md` - Algorithms, key derivation
- `ibs-overview.md` - Identity-Based Signatures scheme
- `build.md` - Build commands, key management
- `integration.md` - OAI modification points

**Important**: Keep `doc-tf5/` synchronized with code changes.

## Standards References

Local corpus in `claude-ref/`:
- `rfc/rfc4082.txt` - TESLA protocol (primary reference)
- `3gpp/38331-j10/` - NR RRC Protocol (SIB1 structure)
- `3gpp/38213-j20/` - Physical layer procedures (timing)

Implementation decisions must cite RFC 4082 sections or 3GPP TS clauses.

## Protocol Constants

```c
TF5_TESLA_KEY_LEN              16      // 128-bit chain keys
TF5_TESLA_TAG_LEN              16      // 128-bit truncated HMAC
TF5_TESLA_SIG_LEN              48      // BLS signature length
TF5_TESLA_CHAIN_LEN            65536   // ~21 min at T_int=20ms
TF5_TESLA_BUFFER_QUEUE_SIZE    4       // Max buffered SIB1s
```

## Conditional Compilation

All TESLA code is wrapped in `#ifdef ENABLE_TF5`. The CMake option `ENABLE_TF5` controls this via `-DENABLE_TF5` definition.
