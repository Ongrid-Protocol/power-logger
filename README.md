# Power Logger Node Deployment

This repository contains the configuration and scripts needed to deploy multiple power-logger nodes in Docker containers, each with their own private keys but sharing common configuration.

## Setup

Each node runs in its own Docker container with:
- Shared config.yaml and devices.yaml files
- Independent node_private_key.bin and node_principal.txt files
- Separate log directories

## How Keys Are Generated

The power-logger application (`main.rs`) automatically handles private key generation during bootup:
- On first run, it checks for existing private keys in the /app/data directory
- If no keys exist, it generates new ones and saves them to disk
- The keys are persisted to the host machine via Docker volumes
- Each node container maintains its own unique keys

## Prerequisites

- Docker 
- Docker Compose
- Internet connection to download dependencies

## Quick Start

1. Clone this repository and navigate to the power-logger directory:

```bash
cd power-logger
```

2. Run the setup script to create the necessary directory structure:

```bash
chmod +x script/node-setup.sh
./script/node-setup.sh
```

3. Build and start the containers:

```bash
docker-compose up -d
```

This will start all 10 nodes. On first startup, each node will generate its own private key and principal ID automatically through the main.rs process.

## Viewing Logs

To view logs from all nodes:

```bash
docker-compose logs -f
```

To view logs from a specific node:

```bash
docker-compose logs -f node1
```

## Managing Nodes

### Start specific nodes:

```bash
docker-compose up -d node1 node2 node3
```

### Stop all nodes:

```bash
docker-compose down
```

### Restart a specific node:

```bash
docker-compose restart node1
```

## Node Private Keys

Each node has its own private key stored in:

```
nodes/node{N}/data/node_private_key.bin
```

And its principal ID in:

```
nodes/node{N}/data/node_principal.txt
```

These files are generated automatically by the application at startup if they don't exist.

## Configuration

- `config.yaml`: Shared configuration for all nodes
- `devices.yaml`: Shared devices configuration
- Each node connects to the same locally hosted canister

## Data Directories

Each node has its own:
- `data` directory for storing private keys and other node-specific data
- `logs` directory for storing node logs

## Example Workflow

1. Setup the directory structure:
   ```bash
   ./script/node-setup.sh
   ```

2. Start all nodes:
   ```bash
   docker-compose up -d
   ```
   
3. Monitor the nodes:
   ```bash
   docker-compose logs -f
   ```

4. Check the principal IDs:
   ```bash
   cat nodes/node1/data/node_principal.txt
   ```

5. When finished, shut down all nodes:
   ```bash
   docker-compose down
   ```

## Troubleshooting

If a node fails to start:

1. Check the logs:
   ```bash
   docker-compose logs node1
   ```

2. If the node wasn't able to generate keys properly, try removing the data directory and restarting:
   ```bash
   rm -rf nodes/node1/data/*
   docker-compose restart node1
   ```

3. You can also check if the node is able to access the canister:
   ```bash
   docker exec power-node-1 ping -c 3 127.0.0.1
   ```

# Power Logger Node System

This project implements a distributed power logger system using Docker containers, each running with independent private keys while sharing common configuration.

## Configuration

### devices.yaml

The system includes a default `devices.yaml` file built into the Docker image. This ensures the system can run without errors even if an external devices.yaml file is not provided.

To override the default configuration:
- Create your own `devices.yaml` file with your device configurations
- The file will be mounted into the containers as a read-only volume

The container has an entrypoint script that checks:
- If a devices.yaml file is mounted
- If the mounted file has content
- Uses the default configuration if no valid file is provided

### Custom Deployment

You can modify the number of nodes, ports, and other settings in the `docker-compose.yml` file.

## System Requirements

The application uses Ubuntu 22.04 as the base container image to ensure compatibility with the required glibc version. The Docker setup handles all the dependencies, but if you're running the application outside of Docker, you'll need a system with:

- GLIBC version 2.34 or higher
- libssl-dev
- ca-certificates

## Building and Running

Build the Docker images with:

```bash
docker-compose build
```

Start the power-logger nodes:

```bash
docker-compose up -d
```

## Monitoring

Check logs for each node:

```bash
docker-compose logs node1
```

Follow logs in real-time:

```bash
docker-compose logs -f node1
```

## Network Configuration

The nodes form a peer-to-peer network over a Docker bridge network. Each node has:
- An independent data directory
- Independent private keys
- Shared configuration for devices

## Timeouts and Intervals

The system uses the following time intervals:
- Heartbeat interval: 1 minute
- Message verification: every 10 minutes
- Pre-verification connection check: runs 5 seconds before verification

## Troubleshooting

### GLIBC Version Issues

If you encounter errors related to GLIBC versions such as:
```
/app/power-logger: /lib/aarch64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by /app/power-logger)
```

This typically means your Rust binary was compiled with a newer version of glibc than what's available in your runtime environment. The Docker setup in this repository uses Ubuntu 22.04 to avoid these issues.
