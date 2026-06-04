#!/bin/bash
# Generate RSA 2048-bit key pair for JWT signing (PKCS#8 format)
# Usage: bash generate-keys.sh

mkdir -p keys

# Generate private key in PKCS#8 format (required by Java PKCS8EncodedKeySpec)
openssl genpkey -algorithm RSA -out keys/private.pem -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -in keys/private.pem -pubout -out keys/public.pem

echo "Keys generated in ./keys/"
echo "  private.pem - Keep secret, used by auth-server to sign JWTs"
echo "  public.pem  - Shared with gateway and internal services to verify JWTs"
