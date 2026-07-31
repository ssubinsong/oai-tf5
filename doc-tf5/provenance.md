# OAI-TF5 Portfolio Provenance

This task creates a local, unpublished portfolio snapshot. It does not create
a publication, tag, push, or OpenAirInterface endorsement.

The snapshot uses OAI base `91e7030cf8adefce502f0701fb7aaa1d512379df` and
research source `3d72e6a138b4154b46b1a0ad718f76ba8a7205f0`.
`provenance-files.txt` records the complete base-to-snapshot inventory.

| Source group | Origin | Rightsholder | Public-copy license | Redistribution basis |
| --- | --- | --- | --- | --- |
| Pre-existing OAI files | OAI base | OpenAirInterface Software Alliance | OAI Public License V1.1 | Preserve upstream OAI notices. |
| TF5 and Core-PKG contribution, including TF5 additions or modifications in existing OAI files | Research source; Core-PKG subtree split `b17cbb4e2e2a09d99c5d4d633311a6476d81fe7c` | Subin Song | OAI Public License V1.1 | Original contribution in the portfolio copy. |
| libsodium-derived portions of `openair3/SECU/ed25519_precomp.h` | `src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c`, `ref10/fe_51/constants.h`, and `ref10/fe_25_5/constants.h` at `3d9d8f500162d8488a6d83c08dcc13bc12a10e30` | Frank Denis | ISC | Retain the ISC notice in `NOTICE.md`, the header, and the pinned submodule. |
| TF5 tests and test data | Research source and locally reproducible test data | Subin Song for locally authored material | OAI Public License V1.1 | Preserve attribution for standard SHA-256 known answers. |

The repository-level `LICENSE`, `NOTICE.md`, and this document carry the
public-copy notice. The four research-exact files remain byte-identical to the
research source and therefore do not each add an inline header.
