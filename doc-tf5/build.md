# Build Configuration

[Back to Index](index.md)

---

## CMake Option

In `CMakeLists.txt`:

```cmake
option(TF5_ENABLE_TESLA
       "Enable TESLA broadcast authentication for SIB1 (fake base station protection)"
       OFF)

if(TF5_ENABLE_TESLA)
  add_definitions(-DTF5_ENABLE_TESLA)
endif()
```

---

## Build Commands

**Build gNB and UE with TESLA enabled**:
```bash
cd cmake_targets
./build_oai --ninja --gNB --nrUE -w SIMU --cmake-opt -DTF5_ENABLE_TESLA=ON
```

**Build gNB only**:
```bash
./build_oai --ninja --gNB -w SIMU --cmake-opt -DTF5_ENABLE_TESLA=ON
```

---

## Key Management

### Key Persistence

The key generation script stores keys in the **project root** directory (`${PROJECT_ROOT}/tesla_keys/`).
This ensures keys persist across build directory cleans (`ninja clean`, `make clean`, or build directory deletion).

### Generate TESLA Keys

Before running gNB and UE with TESLA enabled, generate the BLS key pair:

```bash
./scripts/tf5_generate_bls_keys.sh
```

This creates the following files in `${PROJECT_ROOT}/tesla_keys/`:
- `gnb_tesla_privkey.bin` - BLS secret key (32 bytes raw binary, gNB only)
- `gnb_tesla_pubkey.bin` - BLS public key (96 bytes raw binary, gNB and UE)

You can also specify a custom output directory:
```bash
./scripts/tf5_generate_bls_keys.sh /path/to/custom/keydir
```

The key generation utility (`tf5_bls_keygen`) is automatically built when TESLA is enabled.

### Key File Format

Keys are stored as raw binary files (no PEM encoding):

| Key Type | Size | Description |
|----------|------|-------------|
| Secret key | 32 bytes | Fr element (scalar field) |
| Public key | 96 bytes | G2 point (compressed) |

Inspect generated keys with:
```bash
xxd tesla_keys/gnb_tesla_privkey.bin  # Should show 32 bytes
xxd tesla_keys/gnb_tesla_pubkey.bin   # Should show 96 bytes
```

### Required Parameters

Key paths **must** be specified explicitly on the command line (no defaults):

| Component | Parameter | Description |
|-----------|-----------|-------------|
| gNB | `--tesla-privkey` | Path to BLS secret key file (REQUIRED) |
| gNB | `--tesla-pubkey` | Path to BLS public key file (REQUIRED) |
| UE | `--tesla-gnb-pubkey` | Path to gNB's BLS public key file (REQUIRED) |

### Running with TESLA

**IMPORTANT**: Use the TESLA-optimized configuration file `gnb.sa.band78.fr1.106PRB.tesla.conf`.
This configuration uses CORESET0 index 11 which provides sufficient resources for the larger
SIB1 message with TESLA extension. The standard config uses CORESET0 index 12 which limits
the SIB1 BWP to 48 PRBs, insufficient for TESLA.

```bash
# From project root
cd /path/to/oai-tf5

# Generate keys (one-time, stored in project root)
./scripts/tf5_generate_bls_keys.sh

# Run gNB with explicit key paths
cd cmake_targets/ran_build/build
sudo ./nr-softmodem \
    -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.tesla.conf \
    --rfsim \
    --tesla-privkey ../../../tesla_keys/gnb_tesla_privkey.bin \
    --tesla-pubkey ../../../tesla_keys/gnb_tesla_pubkey.bin

# Run UE with explicit key path (in another terminal)
sudo ./nr-uesoftmodem -r 106 --numerology 1 --band 78 -C 3619200000 --uicc0.imsi 001010000000001 --rfsim \
    -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/ue.conf \
    --tesla-gnb-pubkey ../../../tesla_keys/gnb_tesla_pubkey.bin
```

---

## Dependencies

| Dependency | Purpose |
|------------|---------|
| OpenSSL | HMAC-SHA256 for key chain and MAC computation |
| blst | BLS12-381 signatures (pk-in-G2 mode) |

The blst library (Supranational) is included as a submodule at `cmake_targets/third_party/blst/`.

### Key Migration Note

**Key Location Change**: The key generation script now defaults to storing keys in the
**project root** (`${PROJECT_ROOT}/tesla_keys/`) rather than the current directory.
This ensures keys persist across build cleans.

If you have existing keys in the build directory:
```bash
# Move keys to project root (one-time migration)
mv cmake_targets/ran_build/build/tesla_keys/* tesla_keys/
```

**herumi-bls Migration**: If upgrading from a previous version that used herumi-bls,
existing keys must be regenerated. The blst implementation uses big-endian scalar
serialization, which is incompatible with herumi-bls's little-endian format.

Run `./scripts/tf5_generate_bls_keys.sh` to generate new keys after upgrading.
