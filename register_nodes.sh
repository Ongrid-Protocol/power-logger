#!/bin/bash

# Base port number
BASE_PORT=33334

# Create nodes directory if it doesn't exist
mkdir -p nodes

for i in $(seq 1 10); do
  # Calculate unique port for each node
  PORT=$((BASE_PORT + i))
  
  echo "Starting interactive container for PowerNode$i on port $PORT"
  
  # Create node-specific directory
  mkdir -p nodes/node$i/data
  mkdir -p nodes/node$i/logs
  
  # Create a temporary config file with the unique port
  cp config.yaml nodes/node$i/config.yaml
  sed -i '' "s/port: 8080/port: $PORT/" nodes/node$i/config.yaml

  docker run -it --rm \
    --name power-node-$i \
    --network=host \
    -e IC_URL="http://host.docker.internal:4943" \
    -v $(pwd)/nodes/node$i/config.yaml:/app/config.yaml:ro \
    -v $(pwd)/nodes/node$i/data:/app/data \
    -v $(pwd)/nodes/node$i/logs:/app/logs \
    -e NODE_ID=$i \
    -e NODE_NAME=PowerNode$i \
    -e RUST_LOG=info \
    power-logger:latest

  echo "Finished registering PowerNode$i. Press Enter to continue to the next node..."
  read
done
