FROM rust:latest

# Install required dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    iputils-ping \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Create app directories
WORKDIR /app
RUN mkdir -p /app/config /app/data /app/logs && \
    chmod 777 /app/data /app/logs

# Copy configuration files
COPY config.yaml /app/config/
COPY default-devices.yaml /app/devices.yaml

# Copy source code
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
COPY .env ./

# Display Rust version for debugging
RUN rustc --version && cargo --version

# Build for the target architecture of the container
RUN cargo build --release && \
    cp target/release/power-logger /app/ && \
    chmod +x /app/power-logger && \
    # Print info about the binary to verify architecture
    file /app/power-logger

# Create debugging script
RUN echo '#!/bin/bash \n\
ls -la /app \n\
ls -la /app/config \n\
ls -la /app/data \n\
ls -la /app/logs \n\
echo "Starting power-logger..." \n\
exec /app/power-logger "$@"' > /app/start.sh && \
    chmod +x /app/start.sh

# Set environment variables
ENV RUST_LOG=info
ENV DATA_DIR=/app/data
ENV LOG_DIR=/app/logs

# Expose ports
EXPOSE 33334

# Run the debugging script instead of directly running power-logger
CMD ["/app/start.sh"] 