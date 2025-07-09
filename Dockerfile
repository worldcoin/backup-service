FROM --platform=linux/amd64 rust:1.85.1-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    musl-tools \
    clang \
    pkg-config \
    build-essential \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY . .

# Build the application
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage
FROM scratch

WORKDIR /app

# Copy SSL certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/backup-service /app/backup-service

# Set the entrypoint
USER 100
EXPOSE 8000
ENTRYPOINT ["/app/backup-service"]