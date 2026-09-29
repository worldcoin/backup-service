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

### Recovery when sync access is full

Authenticated retrieval returns `metadataEtag` alongside the existing single-use `syncFactorToken`.
At or above 25 sync factors, a client may ask the user to select one existing sync access and send
`replacement: {"factorId": "<selected ID>", "metadataEtag": "<returned version>"}` in the existing
`/v1/add-sync-factor` request. The signed new key and Main-issued token are still required. One
conditional metadata write replaces exactly that access, preserving every other factor, encryption
key and backup blob. A legacy account above 25 stays at its existing count; this operation never
silently removes additional accesses. Unmodified clients retain the existing capacity error.

Persist the new private key securely **before** sending registration. On an uncertain response,
retain that key and selection, obtain fresh Main-authenticated metadata, and check whether the exact
new public key is a member. Repeating replacement with that same current key and a fresh token is
idempotent and can repair its lookup; it never removes another factor. A changed snapshot returns
`confirmation_stale`. Reconfirm the same target and reuse the pending key; only offer another target
if the original target ID is absent. Do not infer that a request never committed from a transport
error or token expiry. Cancelling before registration makes no remote change.

This uses the existing storage schema and requires no account migration. Metadata membership is
authoritative even if best-effort lookup cleanup fails. Replacement revokes future authentication;
it does not cancel a sync request that was already authenticated and in flight. The existing
non-atomic blob/metadata sync behavior is unchanged.
