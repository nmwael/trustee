#!/bin/bash

# Usage: ./generate_wrap_key.sh <UUID> <PIN> <PKCS11_MODULE_PATH>
# Example: ./generate_wrap_key.sh 123e4567-e89b-12d3-a456-426614174000 123456 /usr/lib/opensc-pkcs11.so

LABEL_UUID="$1"
USER_PIN="$2"
MODULE_PATH="$3"

if [ -z "$LABEL_UUID" ] || [ -z "$USER_PIN" ] || [ -z "$MODULE_PATH" ]; then
  echo "Usage: $0 <UUID> <PIN> <PKCS11_MODULE_PATH>"
  exit 1
fi

PUBLIC_LABEL="trustee-${LABEL_UUID}-public"
PRIVATE_LABEL="trustee-${LABEL_UUID}-private"

echo "Generating RSA 4096-bit key pair with labels:"
echo "  Public:  $PUBLIC_LABEL"
echo "  Private: $PRIVATE_LABEL"

pkcs11-tool --module "$MODULE_PATH" \
  --login --pin "$USER_PIN" \
  --keypairgen \
  --key-type rsa:4096 \
  --label "$PUBLIC_LABEL" \
  --id "$(echo -n "$LABEL_UUID" | xxd -p)" \
  --usage-encrypt --usage-decrypt
if [ $? -eq 0 ]; then
  echo "Key pair generated successfully."
else
  echo "Failed to generate key pair."
  exit 2
fi