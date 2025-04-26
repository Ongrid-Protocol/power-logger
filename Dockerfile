# Stage 1: Build environment
FROM rust:latest AS builder

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

USER rust

RUN mkdir -p /home/rust/.cargo && \
    chown -R rust:rust /home/rust/.cargo

# Copy dependency files
COPY --chown=rust:rust Cargo.toml Cargo.lock ./

# Dummy build for caching
RUN mkdir -p src/bin && \
    echo 'fn main() { println!("dummy"); }' > src/main.rs && \
    echo 'fn main() { println!("dummy bin"); }' > src/bin/dummy.rs

RUN cargo build --release || true

# Remove dummy
RUN rm -f target/release/deps/p2p*

# Copy real source
COPY --chown=rust:rust src ./src/
COPY --chown=rust:rust identities ./identities/
COPY --chown=rust:rust config ./config/

# Final build
RUN cargo build --release || (echo "Build failed, showing cargo output:" && cargo build --release --verbose && exit 1)

# Stage 2: Runtime environment
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd -m -u 1001 app
WORKDIR /app

COPY --from=builder /app/target/release/p2p .
COPY --from=builder /app/identities ./identities/

USER app

# Environment variables passed at runtime
ENV DEVICE_ID=SG1001KE01

# Start the node
CMD ["sh", "-c", "./p2p $DEVICE_ID"]
