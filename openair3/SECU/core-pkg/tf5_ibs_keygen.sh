#!/bin/bash
# TF5 IBS - Master Keypair Generation (OpenSSL Ed25519)
#
# Generates an Ed25519 master keypair for the Core PKG.
# Output: msk (32-byte seed) and mpk (32-byte public key) as raw binary files.
#
# Usage: tf5_ibs_keygen.sh <msk_path> <mpk_path>

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "TF5 IBS - Master Keypair Generation" >&2
    echo "" >&2
    echo "Usage: $0 <msk_path> <mpk_path>" >&2
    echo "" >&2
    echo "Arguments:" >&2
    echo "  msk_path  Path to save master secret key (32-byte Ed25519 seed)" >&2
    echo "  mpk_path  Path to save master public key (32-byte Ed25519 point)" >&2
    echo "" >&2
    echo "Example:" >&2
    echo "  $0 pkg_keys/msk.bin pkg_keys/mpk.bin" >&2
    echo "" >&2
    echo "SECURITY: The master secret key is the root of trust." >&2
    echo "          Store it securely (HSM, encrypted storage)." >&2
    exit 1
fi

MSK_PATH="$1"
MPK_PATH="$2"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Generate Ed25519 keypair (PKCS#8 DER format)
openssl genpkey -algorithm Ed25519 -outform DER -out "$TMPDIR/sk.der"

# Extract 32-byte seed from DER private key
# Ed25519 PKCS#8 DER: 16-byte header + 32-byte seed
dd if="$TMPDIR/sk.der" of="$MSK_PATH" bs=1 skip=16 count=32 2>/dev/null
chmod 600 "$MSK_PATH"

# Extract 32-byte public key from DER public key
# Ed25519 SubjectPublicKeyInfo DER: 12-byte header + 32-byte pubkey
openssl pkey -in "$TMPDIR/sk.der" -inform DER -pubout -outform DER 2>/dev/null | \
    dd of="$MPK_PATH" bs=1 skip=12 count=32 2>/dev/null
chmod 644 "$MPK_PATH"

echo "Master keypair generated successfully."
echo "  Master secret: $MSK_PATH (32 bytes, Ed25519 seed)"
echo "  Master public: $MPK_PATH (32 bytes, Ed25519 point)"
echo ""
echo "Next steps:"
echo "  1. Secure the master secret key ($MSK_PATH)"
echo "  2. Distribute the master public key ($MPK_PATH) to UEs"
echo "  3. Issue gNB keys using: tf5_ibs_issue.sh $MSK_PATH <cell_id_hex> <validity_end> <sk_path>"
