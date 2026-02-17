# Build Configuration

[Back to Index](index.md)

---

## CMake Option

In `CMakeLists.txt`:

```cmake
option(ENABLE_TF5
       "Enable TESLA broadcast authentication for SIB1 (fake base station protection)"
       OFF)

if(ENABLE_TF5)
  add_definitions(-DENABLE_TF5)
endif()
```

---

## Build Commands

**Build gNB and UE with TESLA enabled**:
```bash
cd cmake_targets
./build_oai --ninja --gNB --nrUE --cmake-opt -DENABLE_TF5=ON
```

---

## Key Management (IBS)

TF5 uses **Identity-Based Signatures (IBS)** where the 5G Core acts as a Private Key Generator (PKG).
See [pkg-cryptography.md](pkg-cryptography.md) for the full cryptographic specification
(key hierarchy, algorithms, domain separation tags, security analysis).

### Step 1: Build Core PKG Utilities

The Core PKG utilities are built automatically when building OAI with TESLA enabled:

```bash
cd cmake_targets
./build_oai --ninja --gNB --nrUE --cmake-opt -DENABLE_TF5=ON
```

Or using CMake presets:
```bash
cmake --preset default
cmake --build --preset 5gdefault
```

This produces two utilities in `cmake_targets/ran_build/build/`:
- `tf5_ibs_pkg_keygen` - Master keypair generation
- `tf5_ibs_issue` - gNB secret key issuance

### Step 2: Generate Master Keypair (One-time)

```bash
cd cmake_targets/ran_build/build
./tf5_ibs_pkg_keygen pkg_keys/msk.bin pkg_keys/mpk.bin
```

**Output:**
- `msk.bin` (32 bytes) - Master secret key. **KEEP SECURE!**
- `mpk.bin` (96 bytes) - Master public key. Distribute to all UEs.

### Step 3: Issue gNB Secret Key

For each gNB, issue a secret key based on its NR Cell ID (36 bits) and a validity period:

```bash
cd cmake_targets/ran_build/build
# Cell ID 0x000000e00, valid for 5 years (2628000 minutes from 2024-01-01)
./tf5_ibs_issue pkg_keys/msk.bin 000000e00 2628000 gnb_keys/sk_gnb.bin
```

**Usage:**
```
tf5_ibs_issue <msk_path> <cell_id_hex> <validity_end> <sk_path>
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `msk_path` | Path to Core's master secret key |
| `cell_id_hex` | NR Cell ID in hex (36 bits, e.g., `000000e00`) |
| `validity_end` | Key expiration: minutes since 2024-01-01 00:00 UTC (max 16777215) |
| `sk_path` | Output path for gNB's secret key |

**Validity Period Examples:**
| Duration | Minutes | Expiration Date |
|----------|---------|-----------------|
| 1 year | 525600 | 2025-01-01 |
| 2 years | 1051200 | 2026-01-01 |
| 5 years | 2628000 | 2029-01-01 |
| 10 years | 5256000 | 2034-01-01 |

### Key File Format

| Key Type | Size | Description |
|----------|------|-------------|
| Master secret (msk) | 32 bytes | Scalar (big-endian) |
| Master public (mpk) | 96 bytes | G2 point (compressed) |
| gNB secret (sk_ID) | 51 bytes | G1 point (48B) + validity (3B, big-endian) |

Inspect generated keys with:
```bash
xxd pkg_keys/msk.bin   # Should show 32 bytes
xxd pkg_keys/mpk.bin   # Should show 96 bytes
xxd gnb_keys/sk_gnb.bin  # Should show 51 bytes (48B sk_ID G1 point + 3B validity)
```

### Required Parameters

Key paths **must** be specified explicitly on the command line (no defaults):

| Component | Parameter | Description |
|-----------|-----------|-------------|
| gNB | `--tf5-privkey` | Path to gNB's secret key file (51 bytes: sk_ID G1 point + validity) |
| UE | `--tesla-core-mpk` | Path to Core's Master Public Key (MPK) |

**Note**: The validity period is embedded in the 51-byte key file (bytes 48-50, big-endian).

### Running with TESLA

**IMPORTANT**: Use the TESLA-optimized configuration file `gnb.sa.band78.fr1.106PRB.tesla.conf`.
This configuration uses CORESET0 index 11 which provides sufficient resources for the larger
SIB1 message with TESLA extension. The standard config uses CORESET0 index 12 which limits
the SIB1 BWP to 48 PRBs, insufficient for TESLA.

```bash
# From project root
cd /path/to/oai-tf5

# Run gNB with IBS secret key (validity embedded in key file)
cd cmake_targets/ran_build/build
sudo ./nr-softmodem \
    -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.tesla.conf \
    --rfsim \
    --tf5-privkey /path/to/gnb_keys/sk_gnb.bin

# Run UE with Core's MPK (in another terminal)
sudo ./nr-uesoftmodem -r 106 --numerology 1 --band 78 -C 3619200000 --uicc0.imsi 001010000000001 --rfsim \
    -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/ue.conf \
    --tesla-core-mpk /path/to/pkg_keys/mpk.bin
```

**Key Validity Checks:**
- **gNB startup**: Refuses to start if the key has expired (current time >= gnb_key_validity_end)
- **UE verification**: Rejects SIB1 if the embedded gnb_key_validity_end has passed

### Cell ID and Validity Binding

The gNB's secret key is cryptographically bound to both its Cell ID and validity period:

**Cell ID binding:**
- The `cellID` parameter in your gNB config must match the Cell ID used during key issuance
- UE extracts Cell ID from SIB1's `cellAccessRelatedInfo` and uses it for verification
- Mismatch causes signature verification failure

**Validity binding:**
- The validity period is embedded in the 51-byte key file (bytes 48-50, big-endian)
- Both Cell ID and gnb_key_validity_end are hashed together: `H1(Cell_ID || gnb_key_validity_end)`
- UE extracts gnb_key_validity_end from the TESLA extension in SIB1
- UE checks if the key has expired before attempting verification

---

## Dependencies

| Dependency | Purpose |
|------------|---------|
| OpenSSL | SHA-256 for key derivation, HMAC-SHA256 for MAC computation |
| blst | BLS12-381 BLMQ IBS signatures |

The blst library (Supranational) is included as a submodule at `cmake_targets/third_party/blst/`.

---

## Unit Testing

TF5 includes comprehensive unit tests using Google Test (GTest) framework.

### Build with Tests Enabled

```bash
cd cmake_targets
./build_oai --ninja --gNB --nrUE --cmake-opt "-DENABLE_TESTS=ON -DENABLE_TF5=ON"
```

**Required CMake options:**
| Option | Description |
|--------|-------------|
| `ENABLE_TESTS=ON` | Enables test target and CTest |
| `ENABLE_TF5=ON` | Enables TESLA authentication code |

### Run All TF5 Tests

```bash
cd cmake_targets/ran_build/build

# Build and run all tests
ninja tests
ctest -V
```

### Run Specific Test Suites

```bash
cd cmake_targets/ran_build/build

# Run individual test executables
./test_tf5_tesla_crypto    # Cryptographic primitives
./test_tf5_tesla_gnb       # gNB functions
./test_tf5_tesla_ue        # UE functions
./test_tf5_tesla_serial    # Serialization (pack/unpack)
./test_tf5_tesla_bls       # BLS signatures
./test_tf5_tesla_e2e       # End-to-end integration
```

### Run Tests with CTest Filters

```bash
# Run only TF5 tests
ctest -R tf5

# Run with verbose output
ctest -R tf5 -V

# List available tests
ctest -N
```

### Test Coverage

| Test Suite | File | Coverage |
|------------|------|----------|
| `test_tf5_tesla_crypto` | `test_tf5_tesla_crypto.cpp` | SHA-256 (`tf5_sha256` from `tf5_crypto.h`), key chain (`tf5_chain_key`), MAC key derivation (`tf5_derive_mac_key`), tag computation (`tf5_compute_tag`), auth input builders (`tf5_build_mac_auth_input`, `tf5_build_sig_auth_input`) |
| `test_tf5_tesla_gnb` | `test_tf5_tesla_gnb.cpp` | gNB init, interval calculation, extension preparation, resource cleanup |
| `test_tf5_tesla_ue` | `test_tf5_tesla_ue.cpp` | UE init, safe packet test, SIB1 buffering, key chain verification, buffered verification, key recovery, IBS signature verification (`tf5_ibs_verify`), buffered message verification (`tf5_tesla_ue_verify_buffered_msgs`) |
| `test_tf5_tesla_serial` | `test_tf5_tesla_serial.cpp` | Extension pack/unpack (134-byte format), big-endian encoding helpers |
| `test_tf5_tesla_bls` | `test_tf5_tesla_bls.cpp` | BLMQ IBS sign, verify; IBS hash-to-scalar, sk validation |
| `test_tf5_tesla_e2e` | `test_tf5_tesla_e2e.cpp` | Full gNB→UE flow, tamper detection, key recovery scenarios |
| `test_tf5_tesla_timing` | `test_tf5_tesla_timing.cpp` | Timing utilities (`tf5_tesla_slots_since_t0`, `tf5_tesla_get_interval_index`), replay protection (`tf5_rp_get_wallclock_ms`, `tf5_rp_validate_timestamp`) |
| `test_tf5_tesla_fileio` | `test_tf5_tesla_fileio.cpp` | Key file I/O (`tf5_load_gnb_privkey`, `tf5_load_core_mpk`) |

### Test Files Location

Tests are located in `openair3/SECU/tests/`:

```
openair3/SECU/tests/
├── CMakeLists.txt              # Test build configuration
├── tf5_test_vectors.h          # Known-answer test vectors
├── test_tf5_tesla_crypto.cpp   # Crypto primitive tests
├── test_tf5_tesla_gnb.cpp      # gNB function tests
├── test_tf5_tesla_ue.cpp       # UE function tests
├── test_tf5_tesla_serial.cpp   # Serialization tests
├── test_tf5_tesla_bls.cpp      # BLS signature tests
├── test_tf5_tesla_e2e.cpp      # Integration tests
├── test_tf5_tesla_timing.cpp   # Timing and replay protection tests
└── test_tf5_tesla_fileio.cpp   # Key file I/O tests
```
