#!/bin/bash
#
# TF5 IBS PKG Setup Script
#
# This script builds the PKG utilities and generates a sample master keypair.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PKG_DIR/build"
KEYS_DIR="$PKG_DIR/pkg_keys"

echo "=== TF5 IBS PKG Setup ==="
echo ""

# Initialize blst submodule if needed
if [ ! -f "$PKG_DIR/third_party/blst/src/server.c" ]; then
    echo "Initializing blst submodule..."
    cd "$PKG_DIR"
    git submodule update --init third_party/blst
    echo "Submodule initialized."
    echo ""
fi

# Build
echo "Building PKG utilities..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
cmake ..
make -j$(nproc)
echo "Build complete."
echo ""

# Generate master keypair
echo "Generating master keypair..."
mkdir -p "$KEYS_DIR"

if [ -f "$KEYS_DIR/msk.bin" ]; then
    echo "WARNING: Master keypair already exists at $KEYS_DIR/"
    echo "         To regenerate, delete msk.bin and mpk.bin first."
else
    "$BUILD_DIR/tf5_ibs_pkg_keygen" "$KEYS_DIR/msk.bin" "$KEYS_DIR/mpk.bin"
    echo ""
    echo "Master keypair generated:"
    echo "  Secret: $KEYS_DIR/msk.bin (KEEP SECURE!)"
    echo "  Public: $KEYS_DIR/mpk.bin"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Issue gNB keys:"
echo "     $BUILD_DIR/tf5_ibs_issue $KEYS_DIR/msk.bin <cell_id_hex> <output_path>"
echo ""
echo "  2. Example (Cell ID 0x123456789):"
echo "     $BUILD_DIR/tf5_ibs_issue $KEYS_DIR/msk.bin 123456789 gnb_sk.bin"
echo ""
echo "  3. Distribute keys:"
echo "     - MPK ($KEYS_DIR/mpk.bin) to all UEs"
echo "     - gnb_sk.bin to the corresponding gNB"
