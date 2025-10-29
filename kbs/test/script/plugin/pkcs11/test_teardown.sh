#!/bin/bash

# Usage: ./delete_wrap_key.sh <UUID> <PIN> <PKCS11_MODULE_PATH>
# Example: ./delete_wrap_key.sh 123e4567-e89b-12d3-a456-426614174000 123456 /usr/lib/opensc-pkcs11.so

LABEL_UUID="$1"
USER_PIN="$2"
MODULE_PATH="$3"

if [ -z "$LABEL_UUID" ] || [ -z "$USER_PIN" ] || [ -z "$MODULE_PATH" ]; then
  echo "Usage: $0 <UUID> <PIN> <PKCS11_MODULE_PATH>"
  exit 1
fi

PUBLIC_LABEL="trustee-${LABEL_UUID}-public"
PRIVATE_LABEL="trustee-${LABEL_UUID}-private"

echo "Deleting RSA key pair with labels:"
echo "  Public:  $PUBLIC_LABEL"
echo "  Private: $PRIVATE_LABEL"

# Delete public key
pkcs11-tool --module "$MODULE_PATH" \
  --login --pin "$USER_PIN" \
  --delete-object --label "$PUBLIC_LABEL"

# Delete private key
pkcs11-tool --module "$MODULE_PATH" \
  --login --pin "$USER_PIN" \
  --delete-object --label "$PRIVATE_LABEL"

if [ $? -eq 0 ]; then
  echo "Key pair deleted successfully."
else
  echo "Failed to delete key pair."
  exit 2
fi