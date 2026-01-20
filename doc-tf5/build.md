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

## Dependencies

| Dependency | Purpose |
|------------|---------|
| OpenSSL | HMAC-SHA256 |
| herumi/bls | Ed25519 signatures |

The herumi/bls library is included as a submodule at `cmake_targets/bls/`.
