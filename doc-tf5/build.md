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

## Key Management (IBS Mode)

TF5 uses **Identity-Based Signatures (IBS)** where the 5G Core acts as a Private Key Generator (PKG).
See [ibs-overview.md](ibs-overview.md) for the full cryptographic specification.

### Key Hierarchy

```
Core PKG (tf5-core-pkg/)
    │
    └──> Master Keypair (one-time generation)
         ├── msk.bin (32B) - Master Secret Key (SECURE!)
         └── mpk.bin (96B) - Master Public Key (distribute to UEs)

gNB-specific Keys (issued per Cell ID)
    │
    └──> sk_gnb.bin (32B) - gNB Secret Key (issued by Core)
```

### Step 1: Build Core PKG

```bash
cd ../tf5-core-pkg
mkdir build && cd build
cmake ..
make
```

This produces two utilities:
- `tf5_ibs_pkg_keygen` - Master keypair generation
- `tf5_ibs_issue` - gNB secret key issuance

### Step 2: Generate Master Keypair (One-time)

```bash
./tf5_ibs_pkg_keygen pkg_keys/msk.bin pkg_keys/mpk.bin
```

**Output:**
- `msk.bin` (32 bytes) - Master secret key. **KEEP SECURE!**
- `mpk.bin` (96 bytes) - Master public key. Distribute to all UEs.

### Step 3: Issue gNB Secret Key

For each gNB, issue a secret key based on its NR Cell ID (36 bits):

```bash
# Cell ID 0x123456789 (match your gNB config's cellID)
./tf5_ibs_issue pkg_keys/msk.bin 123456789 gnb_keys/sk_gnb.bin
```

### Key File Format

| Key Type | Size | Description |
|----------|------|-------------|
| Master secret (msk) | 32 bytes | Scalar (big-endian) |
| Master public (mpk) | 96 bytes | G2 point (compressed) |
| gNB secret (sk_ID) | 32 bytes | Scalar (big-endian) |

Inspect generated keys with:
```bash
xxd pkg_keys/msk.bin   # Should show 32 bytes
xxd pkg_keys/mpk.bin   # Should show 96 bytes
xxd gnb_keys/sk_gnb.bin  # Should show 32 bytes
```

### Required Parameters

Key paths **must** be specified explicitly on the command line (no defaults):

| Component | Parameter | Description |
|-----------|-----------|-------------|
| gNB | `--tesla-privkey` | Path to gNB's secret key (sk_ID) from PKG |
| UE | `--tesla-gnb-pubkey` | Path to Core's Master Public Key (MPK) |

**Note**: gNB no longer needs `--tesla-pubkey` in IBS mode.

### Running with TESLA

**IMPORTANT**: Use the TESLA-optimized configuration file `gnb.sa.band78.fr1.106PRB.tesla.conf`.
This configuration uses CORESET0 index 11 which provides sufficient resources for the larger
SIB1 message with TESLA extension. The standard config uses CORESET0 index 12 which limits
the SIB1 BWP to 48 PRBs, insufficient for TESLA.

```bash
# From project root
cd /path/to/oai-tf5

# Run gNB with IBS secret key
cd cmake_targets/ran_build/build
sudo ./nr-softmodem \
    -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.tesla.conf \
    --rfsim \
    --tesla-privkey /path/to/gnb_keys/sk_gnb.bin

# Run UE with Core's MPK (in another terminal)
sudo ./nr-uesoftmodem -r 106 --numerology 1 --band 78 -C 3619200000 --uicc0.imsi 001010000000001 --rfsim \
    -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/ue.conf \
    --tesla-gnb-pubkey /path/to/pkg_keys/mpk.bin
```

### Cell ID Binding

The gNB's secret key is cryptographically bound to its Cell ID:
- The `cellID` parameter in your gNB config must match the Cell ID used during key issuance
- UE extracts Cell ID from SIB1's `cellAccessRelatedInfo` and uses it for verification
- Mismatch causes verification failure

---

## Dependencies

| Dependency | Purpose |
|------------|---------|
| OpenSSL | SHA-256 for key derivation, HMAC-SHA256 for MAC computation |
| blst | BLS12-381 IBS signatures (pk-in-G2 mode) |

The blst library (Supranational) is included as a submodule at `cmake_targets/third_party/blst/`.

### Migration from Legacy BLS Mode

If upgrading from a previous version that used standard BLS signatures:

1. **Regenerate keys** - IBS uses a different key hierarchy (Core PKG issues gNB keys)
2. **Update UE parameters** - UE now loads Core's MPK instead of gNB public key
3. **Update gNB parameters** - gNB no longer needs `--tesla-pubkey`

```bash
# Build Core PKG
cd tf5-core-pkg && mkdir build && cd build && cmake .. && make

# Generate new IBS keys
./tf5_ibs_pkg_keygen pkg_keys/msk.bin pkg_keys/mpk.bin
./tf5_ibs_issue pkg_keys/msk.bin <your_cell_id_hex> gnb_keys/sk_gnb.bin
```
