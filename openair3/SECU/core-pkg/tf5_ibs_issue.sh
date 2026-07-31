#!/bin/bash
# TF5 IBS - gNB Secret Key Issuance (OpenSSL Ed25519)
#
# Issues a gNB-specific secret key by signing the identity message with
# the master key using Ed25519 (crypto_sign_detached equivalent via OpenSSL).
#
# Output file layout: y[32] || pk[32] || validity_be[3] = 67 bytes
#   where (R || S) = Ed25519 signature, y = S, pk = R
#
# Usage: tf5_ibs_issue.sh <msk_path> <cell_id_hex> <validity_end> <sk_path>

set -euo pipefail

if [ $# -ne 4 ]; then
    echo "TF5 IBS - gNB Secret Key Issuance" >&2
    echo "" >&2
    echo "Usage: $0 <msk_path> <cell_id_hex> <validity_end> <sk_path>" >&2
    echo "" >&2
    echo "Arguments:" >&2
    echo "  msk_path       Path to master secret key file (32-byte Ed25519 seed)" >&2
    echo "  cell_id_hex    NR Cell ID as 9-character hex string (36 bits)" >&2
    echo "  validity_end   Key expiration (minutes since 2024-01-01 00:00 UTC)" >&2
    echo "  sk_path        Path to save gNB secret key (67 bytes)" >&2
    echo "" >&2
    echo "Example:" >&2
    echo "  $0 pkg_keys/msk.bin 123456789 1051200 gnb_keys/sk_001.bin" >&2
    exit 1
fi

MSK_PATH="$1"
CELL_ID_HEX="$2"
VALIDITY_END="$3"
SK_PATH="$4"

# Validate inputs
if [ ! -f "$MSK_PATH" ]; then
    echo "ERROR: Master secret key file not found: $MSK_PATH" >&2
    exit 1
fi

if ! echo "$CELL_ID_HEX" | grep -qE '^[0-9a-fA-F]{9}$'; then
    echo "ERROR: Cell ID must be exactly 9 hex characters, got: $CELL_ID_HEX" >&2
    exit 1
fi

if ! echo "$VALIDITY_END" | grep -qE '^[0-9]+$' || [ "$VALIDITY_END" -gt 16777215 ]; then
    echo "ERROR: Validity must be 0-16777215, got: $VALIDITY_END" >&2
    exit 1
fi

# Ed25519 PKCS#8 DER header (fixed 16 bytes for 32-byte seed)
ED25519_SK_DER_HEADER='\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20'

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Reconstruct DER private key from seed
printf "$ED25519_SK_DER_HEADER" > "$TMPDIR/sk.der"
cat "$MSK_PATH" >> "$TMPDIR/sk.der"

# Build identity message: cell_id[5] || validity_be[3] = 8 bytes
python3 -c "
import struct, sys
cid = int('$CELL_ID_HEX', 16)
# 36 bits -> 5 bytes: byte[0..3] = upper 32 bits, byte[4] = lower 4 bits << 4
msg = struct.pack('>I', (cid >> 4) & 0xFFFFFFFF) + bytes([(cid & 0xF) << 4])
val = int('$VALIDITY_END')
msg += struct.pack('>I', val)[1:]  # 3 bytes big-endian (24-bit)
sys.stdout.buffer.write(msg)
" > "$TMPDIR/id_msg.bin"

# Sign identity with master key -> Ed25519 signature (R[32] || S[32])
openssl pkeyutl -sign -inkey "$TMPDIR/sk.der" -keyform DER -rawin \
    -in "$TMPDIR/id_msg.bin" -out "$TMPDIR/sig.bin"

# Build sk_id file: y[32] || pk[32] || validity_be[3]
# Ed25519 signature layout: R[32] || S[32]
# Our sk_id layout: y[32] || pk[32] where y=S, pk=R (swap order)
dd if="$TMPDIR/sig.bin" of="$SK_PATH" bs=1 skip=32 count=32 2>/dev/null  # y = S
dd if="$TMPDIR/sig.bin" bs=1 skip=0 count=32 >> "$SK_PATH" 2>/dev/null   # pk = R

# Append validity (3 bytes big-endian)
python3 -c "
import struct, sys
val = int('$VALIDITY_END')
sys.stdout.buffer.write(struct.pack('>I', val)[1:])
" >> "$SK_PATH"

chmod 600 "$SK_PATH"

echo "gNB secret key issued successfully (67 bytes: sk + validity)."
echo "  Cell ID: 0x$CELL_ID_HEX"
echo "  Validity end: $VALIDITY_END"
echo "  Output: $SK_PATH"
