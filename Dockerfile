# Build stage
FROM rust:1.86-slim as builder

ARG APP_NAME=power-logger # Ensure this matches the [package].name in Cargo.toml

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Copy project manifest and lock file
COPY Cargo.toml Cargo.lock ./

# Build dependencies.
# Create a dummy main.rs. `cargo build` will compile dependencies based on Cargo.toml
# and then compile this dummy main.rs.
RUN mkdir src && \
    echo "fn main() {println!(\"Building dependencies...\");}" > src/main.rs && \
    cargo build --release --quiet && \
    # Remove the dummy main.rs and the dummy executable.
    # The executable name is ${APP_NAME}.
    # This leaves the compiled dependencies in target/release/deps/
    rm -rf src target/release/${APP_NAME}

# Copy the actual source code
COPY src ./src
# If you have a build.rs, copy it now. It should be picked up by the next cargo build.
# COPY build.rs ./build.rs
# If you have other local path dependencies or workspace members needed for the build, copy them.
# e.g. COPY crates/my_local_crate ./crates/my_local_crate

# Build the application with the actual source code.
# This will reuse the dependencies compiled in the previous step.
# Cargo is smart enough to only rebuild what's necessary (i.e., your main crate).
RUN cargo build --release --quiet

# Runtime stage
FROM debian:bookworm-slim

ARG APP_NAME=power-logger # Ensure this is available in the runtime stage

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user and group
RUN groupadd --system appgroup && useradd --system --gid appgroup -d /app -s /sbin/nologin appuser

WORKDIR /app

# Create app directories and set permissions
RUN mkdir -p /app/config /app/data /app/logs && \
    chown -R appuser:appgroup /app/data /app/logs /app/config && \
    chmod 750 /app/data /app/logs && \
    chmod 750 /app/config


# Copy built binary from builder stage
COPY --from=builder /usr/src/app/target/release/${APP_NAME} /app/
# Copy configuration files from the build context
COPY config.yaml /app/config.yaml
COPY default-devices.yaml /app/devices.yaml
COPY .env /app/.env

# Set ownership for the app directory contents and ensure binary is executable
RUN chown appuser:appgroup /app/${APP_NAME} /app/config.yaml /app/devices.yaml /app/.env && \
    chmod 750 /app/${APP_NAME} && \
    chmod 640 /app/config.yaml /app/devices.yaml /app/.env


# Create start script
RUN echo '#!/bin/bash\nexec /app/'"${APP_NAME}"' "$@"' > /app/start.sh && \
    chmod +x /app/start.sh


# Set environment variables
ENV RUST_LOG=warn \
    DATA_DIR=/app/data \
    LOG_DIR=/app/logs

# Expose ports
EXPOSE 33334

# Grant appuser ownership of /app so it can write log/state files there
RUN chown appuser:appgroup /app

# Switch to non-root user
USER appuser

# Run the application
CMD ["/app/start.sh"] 