# Build Configuration

[Back to Index](index.md)

---

## Build Commands

**Build gNB and UE with TESLA enabled**:
```bash
cmake --preset default
cmake --build --preset 5gdefault
```

---

## Key Management (IBS)

TF5 uses **Identity-Based Signatures (IBS)** where the 5G Core acts as a Private Key Generator (PKG).
See [pkg-cryptography.md](pkg-cryptography.md) for the full cryptographic specification
(key hierarchy, algorithms, domain separation tags, security analysis).

### Step 1: Generate Master Keypair (One-time)

```bash
./openair3/SECU/core-pkg/tf5_ibs_keygen.sh pkg_keys/msk.bin pkg_keys/mpk.bin
```

**Output:**
- `msk.bin` (32 bytes) - Master secret key. **KEEP SECURE!**
- `mpk.bin` (32 bytes) - Master public key. Distribute to all UEs.

### Step 2: Issue gNB Secret Key

For each gNB, issue a secret key based on its NR Cell ID (36 bits) and a validity period:

```bash
# Cell ID 0x000000e00, valid for 5 years (2628000 minutes from 2024-01-01)
./openair3/SECU/core-pkg/tf5_ibs_issue.sh pkg_keys/msk.bin 000000e00 2628000 gnb_keys/sk_gnb.bin
```

**Usage:**
```
tf5_ibs_issue.sh <msk_path> <cell_id_hex> <validity_end> <sk_path>
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
| Master secret (msk) | 32 bytes | Ed25519 scalar (little-endian) |
| Master public (mpk) | 32 bytes | Ed25519 point (compressed) |
| gNB secret (sk_ID) | 67 bytes | sk_ID (64B: y[32] + pk[32]) + validity (3B, big-endian) |

Inspect generated keys with:
```bash
xxd pkg_keys/msk.bin   # Should show 32 bytes
xxd pkg_keys/mpk.bin   # Should show 32 bytes
xxd gnb_keys/sk_gnb.bin  # Should show 67 bytes (64B sk_ID + 3B validity)
```

### Required Parameters

Key paths **must** be specified explicitly on the command line (no defaults):

| Component | Parameter | Description |
|-----------|-----------|-------------|
| gNB | `--tf5-privkey` | Path to gNB's secret key file (67 bytes: sk_ID + validity) |
| UE | `--tf5-core-mpk` | Path to Core's Master Public Key (MPK) |

**Note**: The validity period is embedded in the 67-byte key file (bytes 64-66, big-endian).

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
    --tf5-core-mpk /path/to/pkg_keys/mpk.bin
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
- The validity period is embedded in the 67-byte key file (bytes 64-66, big-endian)
- Both Cell ID and gnb_key_validity_end are hashed together: `H(Cell_ID || gnb_key_validity_end || mpk)`
- UE extracts gnb_key_validity_end from the TESLA extension in SIB1
- UE checks if the key has expired before attempting verification
