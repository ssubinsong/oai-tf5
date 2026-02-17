# Suggested Commands

## Building

### Standard build (gNB + UE with TESLA)
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

### Individual test suites
```bash
./test_tf5_tesla_crypto    # Crypto primitives
./test_tf5_tesla_gnb       # gNB functions
./test_tf5_tesla_ue        # UE verification
./test_tf5_tesla_e2e       # End-to-end flow
./test_tf5_tesla_bls       # BLMQ IBS signatures
./test_tf5_tesla_serial    # Serialization
./test_tf5_tesla_timing    # Timing/replay protection
./test_tf5_tesla_fileio    # Key file I/O
./test_tf5_ibs_pkg         # Core PKG key management
```

## Key Management

### Generate master keypair (one-time)
```bash
./tf5_ibs_pkg_keygen pkg_keys/msk.bin pkg_keys/mpk.bin
```

### Issue gNB secret key
```bash
./tf5_ibs_issue pkg_keys/msk.bin <cell_id_hex> <validity_minutes> gnb_keys/sk_gnb.bin
```

## Running

### gNB
```bash
./nr-softmodem -O gnb.conf --tesla-privkey /path/to/sk_gnb.bin
```

### UE
```bash
./nr-uesoftmodem ... --tesla-core-mpk /path/to/mpk.bin
```

### TESLA-optimized gNB config
```
targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.tesla.conf
```

## Formatting
```bash
clang-format -i <file>   # Uses .clang-format at repo root
```

## Utility Commands (Linux)
```bash
git status / git log / git diff   # Version control
rg <pattern>                       # Ripgrep for fast code search
```
