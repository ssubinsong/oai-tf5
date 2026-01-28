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

For each gNB, issue a secret key based on its NR Cell ID (36 bits) and a validity period:

```bash
# Cell ID 0x123456789, valid for 2 years (1051200 minutes from 2024-01-01)
./tf5_ibs_issue pkg_keys/msk.bin 123456789 1051200 gnb_keys/sk_gnb.bin
```

**Usage:**
```
tf5_ibs_issue <msk_path> <cell_id_hex> <validity_end> <sk_path>
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `msk_path` | Path to Core's master secret key |
| `cell_id_hex` | NR Cell ID in hex (36 bits, e.g., `123456789`) |
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
| gNB secret (sk_ID) | 32 bytes | Scalar (big-endian) |

Inspect generated keys with:
```bash
xxd pkg_keys/msk.bin   # Should show 32 bytes
xxd pkg_keys/mpk.bin   # Should show 96 bytes
xxd gnb_keys/sk_gnb.bin  # Should show 32 bytes
```

### Required Parameters

Key paths and validity **must** be specified explicitly on the command line (no defaults):

| Component | Parameter | Description |
|-----------|-----------|-------------|
| gNB | `--tesla-privkey` | Path to gNB's secret key (sk_ID) from PKG |
| gNB | `--tesla-validity-end` | Key validity end (minutes since 2024-01-01 00:00 UTC). **REQUIRED.** |
| UE | `--tesla-core-mpk` | Path to Core's Master Public Key (MPK) |

**Note**: gNB no longer needs `--tesla-pubkey` in IBS mode.

**Important**: The `--tesla-validity-end` value on the gNB command line **must match** the validity_end
used when the key was issued via `tf5_ibs_issue`. Mismatched values cause signature verification failure.

### Running with TESLA

**IMPORTANT**: Use the TESLA-optimized configuration file `gnb.sa.band78.fr1.106PRB.tesla.conf`.
This configuration uses CORESET0 index 11 which provides sufficient resources for the larger
SIB1 message with TESLA extension. The standard config uses CORESET0 index 12 which limits
the SIB1 BWP to 48 PRBs, insufficient for TESLA.

```bash
# From project root
cd /path/to/oai-tf5

# Run gNB with IBS secret key and validity
cd cmake_targets/ran_build/build
sudo ./nr-softmodem \
    -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.tesla.conf \
    --rfsim \
    --tesla-privkey /path/to/gnb_keys/sk_gnb.bin \
    --tesla-validity-end 1051200

# Run UE with Core's MPK (in another terminal)
sudo ./nr-uesoftmodem -r 106 --numerology 1 --band 78 -C 3619200000 --uicc0.imsi 001010000000001 --rfsim \
    -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/ue.conf \
    --tesla-core-mpk /path/to/pkg_keys/mpk.bin
```

**Key Validity Checks:**
- **gNB startup**: Refuses to start if the key has expired (current time >= validity_end)
- **UE verification**: Rejects SIB1 if the embedded validity_end has passed

### Cell ID and Validity Binding

The gNB's secret key is cryptographically bound to both its Cell ID and validity period:

**Cell ID binding:**
- The `cellID` parameter in your gNB config must match the Cell ID used during key issuance
- UE extracts Cell ID from SIB1's `cellAccessRelatedInfo` and uses it for verification
- Mismatch causes signature verification failure

**Validity binding:**
- The `--tesla-validity-end` parameter must match the validity_end used during key issuance
- Both Cell ID and validity_end are hashed together: `pk_ID = H_s(Cell_ID || validity_end)`
- If validity_end is mismatched, the derived public key differs and verification fails
- UE also checks if the key has expired before attempting verification

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
./tf5_ibs_issue pkg_keys/msk.bin <your_cell_id_hex> <validity_end> gnb_keys/sk_gnb.bin

# Example: Cell ID 123456789, valid for 2 years
./tf5_ibs_issue pkg_keys/msk.bin 123456789 1051200 gnb_keys/sk_gnb.bin
```
