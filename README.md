# Backup Service

### Running Locally

To run the service locally with a Localstack S3 service:

```bash
cp .env.example .env
docker compose up -d
cargo run
```

The service will be available at `http://localhost:8000`. View the API documentation at `http://localhost:8000/docs`.

### Running Tests

To run the integration tests:

```bash
docker compose up -d # if not already running
cargo test -- --nocapture

# Clean up:
docker compose down
```