## ⚠️ CRITICAL: Research PoC — Keep It Simple

This is a **research proof-of-concept** for a paper, NOT production code. Simplicity is intentional.
The primary goal is **measuring latency overhead** of the TESLA-based SIB1 authentication scheme. Correctness and measurability matter; robustness and completeness do not.

- **Only implement what is explicitly asked.** No extra features, no "while we're at it" improvements.
- **Do NOT suggest or add:** unnecessary error handling, logging, abstractions, config options, backwards compatibility, or defensive code.
- **Do NOT comment on:** missing edge-case handling, lack of input validation, hardcoded values, or other "production concerns". These are known and intentional.
- **Prefer the simplest working solution.** 3 direct lines > 1 elegant abstraction.
- **When proposing changes**, always ask: "Is this the minimum change needed?" If not, simplify.

## (MANDATORY) Serena MCP Usage

VERY IMPORTANT: ALWAYS use Serena MCP to analyze the codebase and understand the code.

Use **all** of Serena's capabilities fully: onboarding, project memories, symbolic exploration, symbol-level editing, refactoring, thinking/reflection checkpoints, and pattern search. Read Serena's instruction manual (`initial_instructions`) if unsure which tool to use.

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
cd cmake_targets
cmake --preset tests
cmake --build --preset tf5_tests
```

### Build output directories
- Default: `cmake_targets/ran_build/build/`
- Tests: `cmake_targets/ran_build/build_test/`

## Testing

### Run all TF5 tests
```bash
cd cmake_targets/ran_build/build_test
ctest -R tf5 -V
```

## Unimplemented Features

`doc-tf5/unimplemented-features.md` documents unimplemented features of the codebase. DO NOT report them as new bugs or attempt to implement them unless explicitly asked.

## IBS Scheme

TF5 uses **GG09 Schnorr IBS** (Ed25519/libsodium) for SIB1 broadcast authentication.
- Algorithm: Extract(cid=H(id‖pk‖mpk), y=cid·z+b), Sign(σ=h·y+r), Verify(R'=σ·B−h·Q)
- Key sizes: mpk=32B, sk_id=64B(y[32]+pk[32]), sig=96B(R[32]+σ[32]+pk[32])
- `openair3/SECU/ed25519_precomp.h` contains local reimplementations of libsodium internal `ge25519_*` functions (they are `static` in libsodium source and not exported)