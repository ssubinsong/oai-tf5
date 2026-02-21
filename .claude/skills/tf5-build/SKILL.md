---
name: tf5-build
description: Build and test TF5 code using CMake presets
---

# TF5 Build & Test

Build and run TF5 tests. Accept optional arguments:
- No args: build tf5_tests and run ctest
- `build`: only build (no test)
- `full`: full 5G build (gNB + UE + TF5)

## Steps

### Default (build + test)
1. Configure: `cmake --preset tests`
2. Build: `cmake --build --preset tf5_tests`
3. Test: `cd cmake_targets/ran_build/build_test && ctest -R tf5 -V --output-on-failure`
4. Report results concisely

### `build` (build only)
1. Configure: `cmake --preset tests`
2. Build: `cmake --build --preset tf5_tests`

### `full` (full 5G build)
1. Configure: `cmake --preset default`
2. Build: `cmake --build --preset 5gdefault`

## Important
- Do NOT use `--clean-first` unless explicitly requested (building this project is heavy)
- `-DENABLE_TF5=ON` is already included in all presets
- If build fails, analyze the error and suggest fixes
- Build output: `cmake_targets/ran_build/build_test/` (tests) or `cmake_targets/ran_build/build/` (default)
