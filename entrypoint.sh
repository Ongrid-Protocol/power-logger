#!/bin/sh
set -e

# Copy the appropriate identity config
if [ -n "${NODE_NAME}" ] && [ -f "identities/${NODE_NAME}_config.yaml" ]; then
    echo "Setting up configuration for ${NODE_NAME}"
    mkdir -p ./logs/$NODE_NAME
    touch ./logs/$NODE_NAME/verification_log.txt
    cp "identities/${NODE_NAME}_config.yaml" config.yaml
    cp identities/devices.yaml devices.yaml
fi

# Get the device ID from the first argument or environment variable
DEVICE_ID=${1:-$DEVICE_ID}

if [ -z "$DEVICE_ID" ]; then
    echo "Error: No device ID provided"
    exit 1
fi

echo "Starting power-logger with device ID: ${DEVICE_ID}"
exec ./power-logger "$DEVICE_ID"