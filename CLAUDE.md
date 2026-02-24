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

## Known Issues

`doc-tf5/known-issues.md` documents known limitations of the codebase. Issues listed there are already acknowledged — do NOT report them as new bugs or attempt to fix them unless explicitly asked.

## IBS Scheme

TF5 uses **GG09 Schnorr IBS** (Ed25519/libsodium) for SIB1 broadcast authentication.
- Algorithm: Extract(cid=H(id‖pk‖mpk), y=cid·z+b), Sign(σ=h·y+r), Verify(R'=σ·B−h·Q)
- Key sizes: mpk=32B, sk_id=64B(y[32]+pk[32]), sig=96B(R[32]+σ[32]+pk[32])
- `openair3/SECU/ed25519_precomp.h` contains local reimplementations of libsodium internal `ge25519_*` functions (they are `static` in libsodium source and not exported)