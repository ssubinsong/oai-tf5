## (MANDATORY) Serena MCP Usage

VERY IMPORTANT: ALWAYS use Serena MCP to analyze the codebase and understand the code.

Also, use Serena as the **primary tool** for ALL code interaction — exploration, navigation, editing, refactoring, and search. Prefer Serena over raw file reads, text-based grep, and line-based edits whenever possible. Fall back to non-Serena tools only for non-code files, intra-symbol line edits, or shell/git operations.

Use **all** of Serena's capabilities fully: onboarding, project memories, symbolic exploration, symbol-level editing, refactoring, thinking/reflection checkpoints, and pattern search. Read Serena's instruction manual (`initial_instructions`) if unsure which tool to use.


## Building
When building the project do NOT clear the existing build unless necessary, because building this project is a heavy process.
`-DENABLE_TF5=ON` is REQUIRED to build the TF5 code.

### Standard build (gNB + UE with TESLA-for-5G)
```bash
cd cmake_targets
./build_oai --ninja --gNB --nrUE --cmake-opt -DENABLE_TF5=ON
```

### Build with tests
```bash
cd cmake_targets
./build_oai --ninja --gNB --nrUE --cmake-opt "-DENABLE_TESTS=ON -DENABLE_TF5=ON"
```

### Using CMake presets (preferred for dev)
```bash
cmake --preset default           # Configure (ENABLE_TF5=ON by default)
cmake --build --preset 5gdefault # Build gNB + UE
cmake --preset tests             # Configure with tests
cmake --build --preset tf5_tests # Build TF5 tests only
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

## Others

- The base branch of the repository is `v2.4.0-branch`, and I'm currently working on `tf5` branch. To understand what changes have been made, you can compare the `tf5` branch with the `v2.4.0-branch` to see the differences in code and commits.