#!/bin/bash
# Generate self-signed Ed25519 certificate for TESLA gNB authentication
#
# Usage: ./tf5_generate_cert.sh [output_dir]
#
# Default output_dir is ./tesla_keys/ (matches default paths in OAI softmodem)
#
# Generates:
#   - gnb_tesla_privkey.pem  (Ed25519 private key)
#   - gnb_tesla_cert.pem     (Self-signed certificate with public key)
#
# The generated files can be used directly with the OAI gNB and UE:
#   gNB: ./nr-softmodem -O gnb.conf
#   UE:  ./nr-uesoftmodem -O ue.conf
#
# Or with custom paths:
#   gNB: --tesla-privkey <path> --tesla-cert <path>
#   UE:  --tesla-gnb-cert <path>

set -e

# Default output directory matches the default paths in nr-softmodem.h and nr-uesoftmodem.h
OUTPUT_DIR="${1:-./tesla_keys}"
PRIVKEY="${OUTPUT_DIR}/gnb_tesla_privkey.pem"
CERT="${OUTPUT_DIR}/gnb_tesla_cert.pem"
DAYS=3650  # 10 years validity

# Create output directory if it doesn't exist
mkdir -p "${OUTPUT_DIR}"

echo "=========================================="
echo " TESLA Ed25519 Certificate Generator"
echo "=========================================="
echo ""
echo "Output directory: ${OUTPUT_DIR}"
echo ""

# Generate Ed25519 private key
echo "Generating Ed25519 private key..."
openssl genpkey -algorithm ED25519 -out "${PRIVKEY}"
chmod 600 "${PRIVKEY}"  # Restrict private key permissions
echo "  Created: ${PRIVKEY}"

# Generate self-signed certificate
echo "Generating self-signed certificate..."
openssl req -new -x509 -key "${PRIVKEY}" -out "${CERT}" -days ${DAYS} \
    -subj "/CN=TESLA-gNB/O=OAI/OU=TF5"
echo "  Created: ${CERT}"

# Display public key for verification
echo ""
echo "=========================================="
echo " Public Key (hex)"
echo "=========================================="
openssl pkey -in "${PRIVKEY}" -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 32

echo ""
echo "=========================================="
echo " Usage"
echo "=========================================="
echo ""
echo "These are the default paths used by OAI softmodem."
echo "Just run gNB and UE without extra arguments:"
echo ""
echo "  gNB: ./nr-softmodem -O gnb.conf"
echo "  UE:  ./nr-uesoftmodem -O ue.conf"
echo ""
echo "Or override with custom paths:"
echo ""
echo "  gNB: ./nr-softmodem -O gnb.conf \\"
echo "         --tesla-privkey /path/to/privkey.pem \\"
echo "         --tesla-cert /path/to/cert.pem"
echo ""
echo "  UE:  ./nr-uesoftmodem -O ue.conf \\"
echo "         --tesla-gnb-cert /path/to/cert.pem"
echo ""
echo "=========================================="
