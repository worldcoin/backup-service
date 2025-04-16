FROM rust:1.85.1-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.toml

# Cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY . .

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install SSL certificates
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary
COPY --from=builder /app/target/release/backup-service /app/backup-service

# Set the entrypoint
USER 100
EXPOSE 8000
ENTRYPOINT ["/app/backup-service"]