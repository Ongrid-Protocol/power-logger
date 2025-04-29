#!/bin/sh

# Exit on any error
set -ex

# Set default log level if not provided
: "${RUST_LOG:=debug}"
export RUST_LOG

# Show environment
env

# Show current directory and files
pwd
ls -la

# Create log directory if it doesn't exist
mkdir -p "${LOG_DIR:-/app/logs}"

# Show binary permissions
ls -la ./power-logger

# Start the P2P node
echo "Starting P2P node..."
exec ./power-logger 