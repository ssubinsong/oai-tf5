#!/bin/bash
# Generate BLS12-381 keys for TESLA gNB authentication
#
# Usage: ./tf5_generate_bls_keys.sh [output_dir]
#
# Default output_dir is ${PROJECT_ROOT}/tesla_keys/ to persist across build cleans.
#
# Generates:
#   - gnb_tesla_privkey.bin  (BLS secret key, 32 bytes raw binary)
#   - gnb_tesla_pubkey.bin   (BLS public key, 96 bytes raw binary)
#
# Key paths MUST be specified explicitly when running gNB and UE:
#   gNB: --tesla-privkey <path> --tesla-pubkey <path>
#   UE:  --tesla-core-mpk <path>

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default output directory: project root tesla_keys/ (survives build cleans)
# Priority: 1) TF5_TESLA_KEYDIR env var, 2) CLI argument, 3) project root default
if [ -n "${TF5_TESLA_KEYDIR}" ]; then
    OUTPUT_DIR="${TF5_TESLA_KEYDIR}"
elif [ -n "$1" ]; then
    OUTPUT_DIR="$1"
else
    OUTPUT_DIR="${PROJECT_ROOT}/tesla_keys"
fi
PRIVKEY="${OUTPUT_DIR}/gnb_tesla_privkey.bin"
PUBKEY="${OUTPUT_DIR}/gnb_tesla_pubkey.bin"

# Path to the BLS key generation tool (look in common build locations)
BLS_KEYGEN=""
for path in \
    "${SCRIPT_DIR}/../cmake_targets/ran_build/build/tf5_bls_keygen" \
    "${SCRIPT_DIR}/../cmake_targets/build/tf5_bls_keygen" \
    "$(which tf5_bls_keygen 2>/dev/null || true)"; do
    if [ -x "$path" ]; then
        BLS_KEYGEN="$path"
        break
    fi
done

if [ -z "$BLS_KEYGEN" ]; then
    echo "Error: BLS keygen tool not found."
    echo ""
    echo "Please build OAI with TF5_ENABLE_TESLA=ON first:"
    echo "  ./build_oai --ninja --gNB --nrUE -w SIMU --cmake-opt -DTF5_ENABLE_TESLA=ON"
    echo ""
    echo "Then run this script again."
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "${OUTPUT_DIR}"

echo "=========================================="
echo " TESLA BLS Key Generator"
echo "=========================================="
echo ""
echo "Output directory: ${OUTPUT_DIR}"
echo "Using keygen tool: ${BLS_KEYGEN}"
echo ""

# Generate keys
"${BLS_KEYGEN}" "${PRIVKEY}" "${PUBKEY}"

# Set permissions
chmod 600 "${PRIVKEY}"  # Restrict secret key permissions
chmod 644 "${PUBKEY}"   # Public key can be readable

echo ""
echo "=========================================="
echo " Files Created"
echo "=========================================="
echo ""
echo "  Secret key: ${PRIVKEY} (32 bytes)"
echo "  Public key: ${PUBKEY} (96 bytes)"
echo ""
ls -la "${PRIVKEY}" "${PUBKEY}"

echo ""
echo "=========================================="
echo " Usage"
echo "=========================================="
echo ""
echo "Keys are stored in project root and persist across build cleans."
echo "Key paths MUST be specified explicitly on the command line."
echo ""
echo "  gNB: ./nr-softmodem -O gnb.conf \\"
echo "         --tesla-privkey ${PRIVKEY} \\"
echo "         --tesla-pubkey ${PUBKEY}"
echo ""
echo "  UE:  ./nr-uesoftmodem -O ue.conf \\"
echo "         --tesla-core-mpk ${PUBKEY}"
echo ""
echo "=========================================="
