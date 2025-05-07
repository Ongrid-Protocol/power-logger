#!/bin/bash
set -e

# Print system information
echo "=== System Information ==="
uname -a
cat /etc/os-release
echo "========================="

# Print library information
echo "=== Library Information ==="
ldd /app/power-logger
echo "=========================="

# Function to check if a file is empty
is_file_empty() {
  [ ! -s "$1" ]
}

# Function to check if a file exists
file_exists() {
  [ -f "$1" ]
}

# Check if devices.yaml exists and has content
if file_exists "/app/devices.yaml"; then
  if is_file_empty "/app/devices.yaml"; then
    echo "WARNING: Mounted devices.yaml is empty, using default configuration"
    # If empty, the built-in default is used (nothing needed)
  else
    echo "Using mounted devices.yaml configuration"
  fi
else
  echo "No devices.yaml mounted, using default configuration"
fi

# Print message before executing
echo "Starting power-logger with arguments: $@"

# Execute the power-logger with all arguments
exec /app/power-logger "$@" 