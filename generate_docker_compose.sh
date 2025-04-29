#!/bin/bash

# Source the device IDs from generate_configs.sh to ensure consistency
source generate_configs.sh

# This script generates a docker-compose.yml file with services for each node
echo "Generating docker-compose.yml..."

# Base configuration
cat > docker-compose.yml << EOL
version: '3.8'

# Common build definition using YAML anchors
x-node-build: &node-build
  build:
    context: .
    dockerfile: Dockerfile

services:
EOL

# Add nodes using the DEVICE_IDS array
for i in "${!DEVICE_IDS[@]}"; do
    NODE_NUM=$((i + 1))
    DEVICE_ID="${DEVICE_IDS[$i]}"
    MDNS_PORT=$((5353 + NODE_NUM))
    
    cat >> docker-compose.yml << EOL
  node${NODE_NUM}:
    <<: *node-build
    image: p2p-node-image
    volumes:
      - ./identities/node${NODE_NUM}_config.yaml:/app/config.yaml
      - ./identities/devices.yaml:/app/devices.yaml
      - ./logs/node${NODE_NUM}:/app/logs
    environment:
      - NODE_NAME=node${NODE_NUM}
      - DEVICE_ID=${DEVICE_ID}
      - RUST_LOG=info
      - MDNS_PORT=${MDNS_PORT}
    network_mode: host
    command: ["${DEVICE_ID}"]
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 500M

EOL
done

# Add IC canister
cat >> docker-compose.yml << EOL
  # Add the Internet Computer canister service for node registry
  ic-canister:
    image: dfinity/ic-standalone:latest
    ports:
      - "4943:4943"
    volumes:
      - ic_state:/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:4943/api/v2/status"]
      interval: 10s
      timeout: 5s
      retries: 3

volumes:
  ic_state:
EOL

echo "Generated docker-compose.yml with ${#DEVICE_IDS[@]} nodes"

# Create required directories
echo "Creating log directories..."
for i in "${!DEVICE_IDS[@]}"; do
    NODE_NUM=$((i + 1))
    mkdir -p "./logs/node${NODE_NUM}"
    touch "./logs/node${NODE_NUM}/verification_log.txt"
done

echo "Setup complete!"