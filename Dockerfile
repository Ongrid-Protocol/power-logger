# Stage 1: Build environment
FROM rust:latest AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    git \
    libssl-dev \
    pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for building
RUN useradd -m -u 1001 rust
WORKDIR /app
RUN chown rust:rust /app

# Switch to non-root user
USER rust

# Create cargo directory and set ownership
RUN mkdir -p /home/rust/.cargo && \
    chown -R rust:rust /home/rust/.cargo

# Copy dependency files with explicit ownership
COPY --chown=rust:rust Cargo.toml Cargo.lock ./

# Create dummy src and src/bin for dependency caching
RUN mkdir -p src/bin && \
    echo 'fn main() { println!("dummy"); }' > src/main.rs && \
    echo 'fn main() { println!("dummy bin"); }' > src/bin/dummy.rs && \
    echo 'fn main() { println!("dummy update"); }' > src/bin/update_peer_id.rs

# First build for dependency caching
RUN cargo build --release || (echo "Initial build failed, continuing with source build..." && true)

# Clean up dummy build
RUN rm -f target/release/deps/power-logger* target/release/deps/update_peer_id*

# Copy the source files
COPY --chown=rust:rust src ./src/
COPY --chown=rust:rust identities ./identities/

# Final build with error handling
RUN cargo build --release || (echo "Build failed, showing cargo output:" && cargo build --release --verbose && exit 1)

# Stage 2: Runtime environment
FROM rust:latest

# Create non-root user for running
RUN useradd -m -u 1001 app && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    libssl-dev \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create necessary directories
RUN mkdir -p /app/data /app/logs && \
    chown -R app:app /app

# Setup log rotation
COPY --chown=root:root <<EOF /etc/logrotate.d/power-logger
/app/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 app app
}
EOF

# Copy built binaries
COPY --from=builder /app/target/release/power-logger .
COPY --from=builder /app/target/release/update_peer_id .
COPY --from=builder /app/identities ./identities/

# Set proper permissions
RUN chown -R app:app /app && \
    chmod -R 755 /app

# Switch to non-root user
USER app

COPY --chown=app:app entrypoint.sh .
RUN chmod +x entrypoint.sh

# Environment variables
ENV RUST_LOG=debug

# Verify setup
RUN ls -la /app && \
    echo "NODE_NAME is: ${NODE_NAME}"

# Set the entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
# Allow CMD to provide the device ID
CMD ["${DEVICE_ID}"]