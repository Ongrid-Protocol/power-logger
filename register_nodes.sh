#!/bin/bash

for i in $(seq 1 10); do
  echo "Starting interactive container for PowerNode$i"

  docker run -it --rm \
    --name power-node-$i \
    --network=host \
    -v $(pwd)/config.yaml:/app/config.yaml:ro \
    -v $(pwd)/devices.yaml:/app/devices.yaml:ro \
    -v $(pwd)/nodes/node$i/data:/app/data \
    -v $(pwd)/nodes/node$i/logs:/app/logs \
    -e NODE_ID=$i \
    -e NODE_NAME=PowerNode$i \
    -e RUST_LOG=info \
    power-logger:latest

  echo "Finished registering PowerNode$i. Press Enter to continue to the next node..."
  read
done
