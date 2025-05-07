#!/bin/bash

# This script creates the necessary folder structure and prepares the environment for running multiple nodes

# Create directories for node data and logs
mkdir -p nodes

# Loop through and create directories for each node
for i in {1..10}
do
  mkdir -p nodes/node$i/data
  mkdir -p nodes/node$i/logs
  
  echo "Created directory structure for node$i"
done

# Check if needed folders exist
if [ ! -d "script" ]; then
  mkdir -p script
fi

echo "Setup complete. You can now run docker-compose up to start the nodes."
echo "Each node will generate its own private key and principal ID on first startup."
echo ""
echo "To start all nodes: docker-compose up -d"
echo "To start specific nodes: docker-compose up -d node1 node2 node3"
echo "To view logs: docker-compose logs -f"
echo "To view logs for specific node: docker-compose logs -f node1"
echo "To stop all nodes: docker-compose down" 