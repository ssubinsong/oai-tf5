# oai-tf5 — Project Overview

## Purpose
TF5 (TESLA for 5G) implements TESLA broadcast authentication (RFC 4082) for 5G NR SIB1 messages, protecting UEs against fake base station attacks. This is an extended OpenAirInterface (OAI) 5G RAN stack (gNB + UE) with TESLA protocol integration.

## Tech Stack
- **Language**: C (source), C++ (unit tests)
- **Build system**: CMake + Ninja (via CMake presets)
- **Test framework**: Google Test (GTest)
- **Crypto libraries**: OpenSSL (HMAC-SHA256), libsodium (GG09 Schnorr IBS, Ed25519)
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
      └── core-pkg/         Standalone IBS key generation tools (keygen, issue)
      └── tests/            Unit tests (9 test files, GTest)
doc-tf5/               Project-specific documentation
claude-ref/            RFC & 3GPP specification corpus
```

## Key TF5 Files
| File | Purpose |
|------|---------|
| `openair3/SECU/tf5_tesla.c` | Protocol: key chains, MAC, buffer queue, extension pack/unpack, replay protection |
| `openair3/SECU/tf5_tesla.h` | Data structures (gNB/UE state, extension, params), API, constants |
| `openair3/SECU/tf5_tesla_sig.c` | GG09 Schnorr IBS: sign, sign_precomp/sign_online, verify, MPK precomputation |
| `openair3/SECU/tf5_tesla_sig.h` | GG09 Schnorr IBS API (init, sign, verify, precomp types) |
| `openair3/SECU/tf5_crypto.c/h` | Crypto primitives (SHA256, HMAC) |
| `openair3/SECU/tf5_ibs_defs.h` | Ed25519 constants, IBS identity constants, error codes, file format sizes |
| `openair3/SECU/tf5_ibs_common.c` | IBS common utilities (identity hashing) |
| `openair3/SECU/tf5_ibs_pkg.h` | Core PKG interface (keygen, issue, hash_identity) |
| `openair3/SECU/ed25519_precomp.h` | Local re-implementations of libsodium internal `ge25519_*` functions (static in libsodium) |
| `openair2/LAYER2/NR_MAC_gNB/config.c` | gNB TESLA state initialization |
| `openair2/LAYER2/NR_MAC_gNB/nr_radio_config.c` | TESLA extension update per SIB1 |
| `openair2/RRC/NR_UE/rrc_UE.c` | UE verification logic (IBS + TESLA MAC, phase state machine) |

## Conditional Compilation
All TESLA code is wrapped in `#ifdef ENABLE_TF5`. The CMake option `ENABLE_TF5` controls this.

## Dual Authentication Protocol
1. **GG09 Schnorr IBS Signature** (immediate): Galindo-Garcia 2009, 1-level Schnorr IBS over Ed25519/libsodium. Extract: cid=H(pk‖mpk‖id), y=cid·z+b. Sign: h=H(data‖R), σ=h·y+r. Verify: Q=cid·mpk+pk, R'=σ·B−h·Q.
2. **TESLA MAC** (delayed): HMAC-SHA256 verified after key disclosure (d=1 interval delay)

## Key Sizes (Ed25519/GG09 Schnorr)
| Component | Size |
|-----------|------|
| gNB secret key (sk_id) | 64B (y[32] scalar + pk[32] point) |
| IBS signature | 96B (R[32] + sigma[32] + pk[32]) |
| TESLA extension wire | 150B (tf5_extension_t packed) |
| gNB SK file | 67B (64B sk_id + 3B validity) |
| Master secret (msk) | 32B (Ed25519 seed) |
| Master public (mpk) | 32B (Ed25519 point = z·B) |
| TESLA chain key | 16B (128-bit) |
| TESLA MAC tag | 16B (truncated HMAC-SHA256) |
| Protocol version | 0x02 |

## Performance Optimizations
- **Online/offline signing split**: `tf5_ibs_sign_precomp()` pre-generates (r, R=r·B) nonce pairs at init; `tf5_ibs_sign_online()` performs only scalar ops per SIB1
- **MPK precomputation table**: `tf5_ibs_precompute_mpk()` builds 32×8 Duif precomp table (~30KB) at UE init for fast cid·mpk fixed-point scalar mult
- **Shamir's trick**: `ge25519_double_scalarmult_vartime` for σ·B−h·Q in verification
- **Variable-time ops**: Verification inputs are public, so vartime is safe

## UE Authentication Phase State Machine
`tf5_ue_phase_t`: INITIAL → BUFFERED → AUTHENTICATED / RRCSETUP_DEFERRED → RRCSETUP_COMPLETE

## Replay Protection
- Wall-clock timestamp (24-bit LSB, ms since epoch) included in signed extension
- UE validates timestamp within configurable window (default 60s)
- Requires gNB/UE clock synchronization (NTP/GNSS/PTP)

## Branch
Main branch: `tf5` (base: `v2.4.0-branch`)
