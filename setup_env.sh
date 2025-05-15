#!/bin/bash

# Check if .env file already exists
if [ -f .env ]; then
    echo ".env file already exists. Do you want to overwrite it? (y/n)"
    read answer
    if [ "$answer" != "y" ]; then
        echo "Aborting."
        exit 1
    fi
fi

# Create .env file
cat > .env << EOF
# Blockchain Settings
BLOCKCHAIN_RPC_URL=https://base-sepolia.g.alchemy.com/v2/TsX8xUhaHbNdbCx8EN3YO4CTvkD39VHj
BLOCKCHAIN_PRIVATE_KEY=28776c81c5d353f98ff0ad475a5dcf1c557bc6067c35f3e3483c446ad09dfc93
ENERGY_BRIDGE_ADDRESS=0x2dCfA53aEfE9F62D4fF13281e72ECE6203D7149A

# RabbitMQ Settings
RABBITMQ_HOST=localhost
RABBITMQ_PORT=5672
RABBITMQ_USER=guest
RABBITMQ_PASSWORD=guest
RABBITMQ_VHOST=/

EOF

echo ".env file created. Please edit it with your blockchain settings."

# Optional: Open the .env file in an editor
if command -v nano > /dev/null; then
    nano .env
elif command -v vim > /dev/null; then
    vim .env
else
    echo "Please edit the .env file manually with your blockchain settings."
fi 