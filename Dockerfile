FROM rust:1.89.0-slim AS builder

ARG GIT_REV
ENV GIT_REV=${GIT_REV}

WORKDIR /app

RUN apt-get update && apt-get install -y \
    musl-tools \
    clang \
    libssl-dev \
    pkg-config \
    build-essential \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY test-utils/Cargo.toml test-utils/Cargo.toml
# test-utils won't actually be included in the final image

# Cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    mkdir -p test-utils/src && \
    echo "fn main() {}" > test-utils/src/main.rs && \
    cargo build --locked --release && \
    rm -rf src

# Copy source code
COPY . .

# Build the application
RUN cargo build --locked --release --target x86_64-unknown-linux-musl

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
