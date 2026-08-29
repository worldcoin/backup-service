# Backup Service

- Staging: https://tfh-backup-api.dev-nethermind.xyz/docs
- Production: https://api-tfh-backup-prod.nethermind.io/docs
- Mobile flows: https://excalidraw.com/#json=pJTLrSff6hYYAI0fztR2v,F8_Z-kkzbVN1Icd37CMV6Q

### High-level description

Backup Service stores and manages authentication for encrypted backups represented as binary blobs. The data is stored
on S3. The service also uses DynamoDB for mapping between factors and backups, as well as for some ephemeral data (e.g. used challenges).

A typical backup lifecycle:

1. **Creation** (`/create`): Client creates a backup with an authentication factor (passkey, OIDC, or keypair) and a sync factor (EC keypair). The client also signs a challenge with its break-glass key to prove it owns the `backup_account_id` it is claiming.
2. **Retrieval** (`/retrieve/from-challenge`): Client retrieves backup using an authentication factor
3. **Add sync factor** (`/add-sync-factor`): Client adds new sync factor after performing recovery.
4. **Sync** (`/sync`): Client updates backup content using a sync factor
5. **Management**: Client can add factors (`/add-factor`), or delete factors (`/delete-factor`). It can also view backup metadata (`/retrieve-metadata`).

### Definitions

- **Sealed Backup**: Binary blob from user device with backup ciphertext.
- **Backup Metadata**: Information about a backup including its ID, authentication factors, sync factors, and encrypted keys
- **Main Factor**: Authentication method that can access a backup and **manage the backup** (add new factors, and perform recovery). It is a passkey, OIDC account, or EC keypair.
- **Sync Factor**: Special factor (EC keypair) that can update backup content, delete factors and read metadata, but cannot add new factors or perform recovery
- **Encrypted Backup Key**: Encryption key for the backup data, encrypted separately for each factor kind. The encrypted key is coming from user's device and is stored in the backup metadata.
- **Turnkey Shared Passkey Challenge**: A passkey challenge that is a valid [Webauthn Turnkey stamp](https://docs.turnkey.com/developer-reference/api-overview/stamps#webauthn) and can be used to add a new factor to backup-service. Allows to add new factor with authorization to Turnkey & backup-service in a single passkey prompt.

### Shutdown

On `SIGTERM` or `SIGINT` the service drains: `/ready` answers `503` for 10 seconds so the instance
leaves the load balancer's rotation, then the listeners close and in-flight requests get a further
30 seconds — the request timeout — to finish. `/health` stays `200` so liveness does not restart a
pod that is already leaving. Both deadlines run from the signal, and the process exits once the
second one passes however far startup or a request got. Two deployment settings match those
numbers:

- `terminationGracePeriodSeconds` must be at least 45, or the pod is `SIGKILL`ed mid-request.
- Whatever removes the instance from rotation must act within the 10 second drain. Deleting the
  pod from its `Service` endpoints does; a balancer that health-checks `/ready` itself only does
  if `periodSeconds` times `failureThreshold` is under 10 seconds, which the Kubernetes defaults
  (10 times 3) are not.

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

### E2E Testing Against Remote Environments

An end-to-end Python test script is available to test the complete backup flow against remote environments:

```bash
export ATTESTATION_TOKEN="dummy-token-for-testing-purposes-xxxxx"
python3 tests/e2e/create-and-retrieve-backup.py \
  --url "https://tfh-backup-api.dev-nethermind.xyz" \
  --attestation-token "$ATTESTATION_TOKEN"
```
