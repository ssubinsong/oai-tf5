# Repository Guidelines

## Project Structure & Module Organization
- `executables/`: top-level entry points for gNB/UE binaries.
- `openair1/`, `openair2/`, `openair3/`: PHY, MAC/RLC/RRC, and higher layers.
- `openair3/SECU/`: TF5/TESLA core, BLS signatures, and IBS utilities.
- `openair2/LAYER2/NR_MAC_gNB/` and `openair2/RRC/NR_UE/`: TF5 integration points.
- `cmake_targets/`: build scripts and build outputs under `cmake_targets/ran_build/`.
- `doc/` and `doc-tf5/`: general OAI docs and TF5 documentation.
- `claude-ref/`: standards references (RFC 4082, 3GPP specs).
- `tests/`: CMake-driven tests; TF5 unit tests are built in the main build tree.

## Build, Test, and Development Commands
Standard TF5 build:
```bash
cd cmake_targets
./build_oai --ninja --gNB --nrUE --cmake-opt -DENABLE_TF5=ON
```
Build with TF5 tests:
```bash
cd cmake_targets
./build_oai --ninja --gNB --nrUE --cmake-opt "-DENABLE_TESTS=ON -DENABLE_TF5=ON"
```
CMake presets:
```bash
cmake --preset default
cmake --build --preset 5gdefault
cmake --preset tests
cmake --build --preset tf5_tests
```
Build outputs: `cmake_targets/ran_build/build/` and `cmake_targets/ran_build/build_test/`.

## Coding Style & Naming Conventions
- `.clang-format` enforced; 2-space indentation, no tabs, 132-column limit.
- Function braces on new lines; control-flow braces on the same line.
- Right-align pointers/references (`type *ptr`).
- TF5 symbols follow `tf5_*` or `tf5_tesla_*` prefixes.

## Testing Guidelines
- Run TF5 suite with CTest:
```bash
cd cmake_targets/ran_build/build
ctest -R tf5 -V
```
- Individual TF5 test binaries include `test_tf5_tesla_crypto`, `test_tf5_tesla_gnb`, `test_tf5_tesla_ue`, `test_tf5_tesla_e2e`, and `test_tf5_ibs_pkg`.

## TF5 Architecture & Key Files
- TESLA signing happens at SIB1 transmission in `openair2/LAYER2/NR_MAC_gNB/`.
- UE verification happens on SIB1 reception in `openair2/RRC/NR_UE/`.
- Core implementation in `openair3/SECU/tf5_tesla.c` and `openair3/SECU/tf5_tesla_sig.c`.

## TF5 Key Management & Runtime
- Generate keys with `tf5_ibs_pkg_keygen` and `tf5_ibs_issue` (see `doc-tf5/build.md`).
- gNB runtime flag: `--tesla-privkey /path/to/sk_gnb.bin`.
- UE runtime flag: `--tesla-core-mpk /path/to/mpk.bin`.
- Reference config: `targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.tesla.conf`.

## Commit & Pull Request Guidelines
- Commit messages follow `feat(tf5): ...`, `fix(cmake): ...`, `refactor(tf5): ...`.
- Keep commits small and logical; rebase to keep history linear; target `develop`.
- Merge requests must include a CI label: `~documentation`, `~BUILD-ONLY`, `~4G-LTE`, or `~5G-NR`.
- CLA is required; see `CONTRIBUTING.md`.

## Documentation & Standards
- Update `doc-tf5/` when TF5 behavior changes.
- Cite RFC 4082 and relevant 3GPP clauses from `claude-ref/` for protocol changes.
