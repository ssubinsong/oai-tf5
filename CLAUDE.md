## ⚠️ CRITICAL: Research PoC — Keep It Simple

This is a **research proof-of-concept** for a paper, NOT production code. Simplicity is intentional.
The primary goal is **measuring latency overhead** of the TESLA-based SIB1 authentication scheme. Correctness and measurability matter; robustness and completeness do not.

- **Only implement what is explicitly asked.** No extra features, no "while we're at it" improvements.
- **Do NOT suggest or add:** unnecessary error handling, logging, abstractions, config options, backwards compatibility, or defensive code.
- **Do NOT comment on:** missing edge-case handling, lack of input validation, hardcoded values, or other "production concerns". These are known and intentional.
- **Prefer the simplest working solution.** 3 direct lines > 1 elegant abstraction.
- **When proposing changes**, always ask: "Is this the minimum change needed?" If not, simplify.

## IMPORTANT: Base Branch

- The base branch of the repository is `v2.4.0-branch`, and I'm currently working on `tf5` branch. To understand what changes have been made, you can compare the `tf5` branch with the `v2.4.0-branch` to see the differences in code and commits.

## Building
When building the project do NOT clear the existing build unless necessary, because building this project is a heavy process.
`-DENABLE_TF5=ON` is REQUIRED to build the TF5 code.

### Standard build (gNB + UE with TESLA-for-5G)
```bash
cmake --preset default
cmake --build --preset 5gdefault
```

### Build tests
```bash
cmake --preset tests
cmake --build --preset tf5_tests
```

### Build output directories
- Default: `cmake_targets/ran_build/build/`
- Tests: `cmake_targets/ran_build/build_test/`

### Build gotcha
- `cmake --build` commands require `dangerouslyDisableSandbox: true` in Bash tool because ccache writes to `~/.cache` which is outside the sandbox allowlist.

## Testing

### Run all TF5 tests
```bash
cd cmake_targets/ran_build/build_test
ctest -R tf5 -V
```

### Run a single test
```bash
cd cmake_targets/ran_build/build_test
ctest -R test_tf5_tesla_crypto -V
```

Available tests: `test_tf5_tesla_crypto`, `test_tf5_tesla_gnb`, `test_tf5_tesla_ue`, `test_tf5_tesla_serial`, `test_tf5_tesla_ibs`, `test_tf5_tesla_timing`, `test_tf5_tesla_fileio`, `test_tf5_tesla_e2e`, `test_tf5_ibs_pkg`

## Key TF5 Files

TF5 code lives in two layers within the OAI tree:

| Path | Purpose |
|------|---------|
| `openair3/SECU/tf5_tesla.{c,h}` | TESLA chain generation, MAC tag, key disclosure |
| `openair3/SECU/tf5_tesla_sig.{c,h}` | TESLA + IBS combined signing/verification |
| `openair3/SECU/tf5_crypto.{c,h}` | Low-level crypto helpers (SHA-256, HMAC) |
| `openair3/SECU/tf5_ibs_common.c` | GG09 IBS sign/verify (Ed25519 curve ops) |
| `openair3/SECU/tf5_ibs_defs.h` | IBS type definitions and wire formats |
| `openair3/SECU/tf5_ibs_pkg.h` | IBS key extraction (PKG role) |
| `openair3/SECU/ed25519_precomp.h` | Reimplemented libsodium internal `ge25519_*` functions |
| `openair3/SECU/core-pkg/` | Standalone PKG key issuance scripts |
| `openair3/SECU/tests/` | GTest test suite (9 test binaries) |
| `openair2/LAYER2/NR_MAC_gNB/gNB_scheduler_bch.c` | SIB1/SIB9 PDSCH scheduling (VRB allocation) |
| `openair2/LAYER2/NR_MAC_gNB/config.c` | gNB MAC config (SIB9 setup) |
| `openair2/RRC/NR_UE/rrc_UE.c` | UE RRC — SIB1/SIB9 reception and TESLA verification |
| `executables/nr-softmodem.c` | gNB main — TF5 initialization |

## Unimplemented Features

`doc-tf5/unimplemented-features.md` documents unimplemented features of the codebase. DO NOT report them as new bugs or attempt to implement them unless explicitly asked.

## IBS Scheme

TF5 uses **GG09 Schnorr IBS** (Ed25519/libsodium) for SIB1 broadcast authentication.
- Algorithm: Extract(cid=H(pk‖mpk‖id‖validity), y=cid·z+b), Sign(σ=h·y+r), Verify(R'=σ·B−h·Q)
- Key sizes: mpk=32B, sk_id=64B(y[32]+pk[32]), sig=96B(R[32]+σ[32]+pk[32])
- `openair3/SECU/ed25519_precomp.h` contains local reimplementations of libsodium internal `ge25519_*` functions (they are `static` in libsodium source and not exported)

## Data Split: SIB1 / SIB9
- SIB1 `lateNonCriticalExtension`: per-interval (version_sp + interval + key + k0_next + tag = 53B)
- SIB9 `lateNonCriticalExtension`: static + IBS sig (version + cell_id + params + k0 + sig + timestamp + validity = 135B)
- First-time UE: store SIB1 → verify SIB9 IBS signature → chain bootstrap
- Returning UE: verify SIB1 MAC only (SIB9 not needed)

## SIB PDSCH Scheduling (VRB Allocation)
- SIB1 and SIB9 are scheduled in the same slot (slot 0) within CORESET0 BWP (48 RBs)
- `update_rb_mcs_tbs()` in `gNB_scheduler_bch.c`: modified OAI's original function to search for the next free VRB block when the first one is too small
- PLMN/SNSSAI in config affects SIB1 ASN.1 encoding size → changes TBS/rbSize → changes VRB map pattern → may affect whether SIB9 can be allocated
