# TESLA-for-5G PoC Implementation

This repository is the source code artifact for [TESLA-for-5G: Broadcast Authentication for 5G Networks Using TESLA](https://arxiv.org/abs/2606.26528). It contains the proof-of-concept implementation built on OpenAirInterface (OAI). The evaluation code used in the paper is not included.

## Repository scope

The implementation is based on OAI commit `91e7030cf8adefce502f0701fb7aaa1d512379df`. OAI does not endorse this work. [README-OAI.md](README-OAI.md) contains the upstream front page and OAI documentation.

## Build

Initialize the pinned TF5 dependency before configuring a build:

```bash
git submodule update --init cmake_targets/third_party/libsodium
cmake --list-presets=all
```

Presets are `default`, `tests`, `tf5`, and `tf5-tests`. `default` disables TF5; `tf5` and `tf5-tests` enable it. `tf5-tests` is a preset, while `tf5_tests` is the aggregate CMake target. Configure and build TF5 as follows:

```bash
cmake --preset tf5
cmake --build --preset tf5
cmake --preset tf5-tests
cmake --build --preset tf5-tests
ctest --test-dir cmake_targets/ran_build/build_tf5_tests \
  -R '^test_tf5_' --output-on-failure
```

## Key generation

The Core-PKG scripts require `openssl` with Ed25519 support and `python3`. Run this sequence from the repository root:

```bash
mkdir -p pkg_keys gnb_keys
openair3/SECU/core-pkg/tf5_ibs_keygen.sh pkg_keys/msk.bin pkg_keys/mpk.bin
openair3/SECU/core-pkg/tf5_ibs_issue.sh pkg_keys/msk.bin 123456789 \
  FUTURE_VALIDITY_MINUTES gnb_keys/sk_gnb1.bin
wc -c pkg_keys/msk.bin pkg_keys/mpk.bin gnb_keys/sk_gnb1.bin
```

`FUTURE_VALIDITY_MINUTES` is a 24-bit count of minutes since 2024-01-01 UTC (0 to 16,777,215). Set it to a value that remains valid through the experiment. The final command prints only the generated file sizes.

Core-PKG hashes `pk || mpk || cell_id || validity` with SHA-512 and reduces the result modulo `l`. It obtains `(R || S) = Ed25519_sign(msk, id_msg)` and stores `sk_id = y=S || pk=R`. To sign, the gNB samples `r`, computes `R=r*B` and `h=H(data || R)`, then returns `sigma=h*y+r`. The verifier derives `Q=cid*MPK+pk` and accepts the signature when `sigma*B-h*Q=R`.

| File | Size | Format | Mode |
| --- | ---: | --- | ---: |
| `msk.bin` | 32 bytes | Ed25519 seed | `0600` |
| `mpk.bin` | 32 bytes | compressed Ed25519 public key | `0644` |
| `sk_gnb1.bin` | 67 bytes | `y[32] || pk[32] || validity[3]` | `0600` |

Each UE needs a copy of the public MPK. Transfer `sk_gnb1.bin` to the gNB over a secure channel. Anyone with `msk.bin` can issue keys for any Cell ID, so changing a gNB Cell ID requires a new gNB key.

## Runtime options

| Component | Option | Default | Meaning |
| --- | --- | --- | --- |
| gNB | `--tf5-privkey` | none; required | Path to the gNB key file issued by Core-PKG. |
| gNB | `--tf5-chain-len` | 65,536 | TESLA chain length in intervals. |
| UE | `--tf5-core-mpk` | none; required | Path to the Core master public key. |
| UE | `--tf5-sig-rp-window-s` | 10,800 seconds | Signature timestamp replay window. |
| UE | `--tf5-d-bound-us` | 1,005 microseconds | Delay bound used by the UE implementation. |
| UE | `--tf5-returning-ue` | off | Simulates forced release and reacquisition for two seconds. |

## Source map

| Area | Review entry point |
| --- | --- |
| TF5 core and public formats | [`openair3/SECU/tf5_tesla.h`](openair3/SECU/tf5_tesla.h) |
| Core-PKG scripts and file formats | [`tf5_ibs_keygen.sh`](openair3/SECU/core-pkg/tf5_ibs_keygen.sh), [`tf5_ibs_issue.sh`](openair3/SECU/core-pkg/tf5_ibs_issue.sh) |
| gNB initialization and SIB payload updates | [`openair2/LAYER2/NR_MAC_gNB/config.c`](openair2/LAYER2/NR_MAC_gNB/config.c) |
| UE SIB handling | [`openair2/RRC/NR_UE/rrc_UE.c`](openair2/RRC/NR_UE/rrc_UE.c) |
| Seven included test executables | [`openair3/SECU/tests/CMakeLists.txt`](openair3/SECU/tests/CMakeLists.txt) |

## Limitations

Current implementation lacks SFN wrapping, HFN tracking and chain renewal feature.

## Citation

```bibtex
@misc{song2026teslafor5gbroadcastauthentication5g,
      title={TESLA-for-5G: Broadcast Authentication for 5G Networks Using TESLA}, 
      author={Subin Song and Michael K. Reiter and Taekyoung Kwon},
      year={2026},
      eprint={2606.26528},
      archivePrefix={arXiv},
      primaryClass={cs.CR},
      url={https://arxiv.org/abs/2606.26528}, 
}
```

## License

This repository is distributed under the [OAI Public License V1.1](LICENSE). See [NOTICE.md](NOTICE.md) for third-party notices.
