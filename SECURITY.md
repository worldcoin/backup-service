# Security

For reporting security vulnerabilities and our responsible disclosure policy, please
see the [orb-software repo][orb-software].

[orb-software]: https://github.com/worldcoin/orb-software/blob/main/SECURITY.md

## Sensitive data handling

The service must receive OIDC tokens, signatures and encrypted backup material to verify or
store them. Hashing applies to equality checks and replay tracking; it cannot replace signature
verification or encryption for data that clients must recover.

| Location | Data retained | Protection and purpose |
| --- | --- | --- |
| Redis `syncFactorToken` | SHA-256 of a random 256-bit token; backup ID and used flag | 15-minute TTL; atomic consumption. The stored hash cannot be submitted as the token. |
| Redis `usedChallengeHash` | SHA-256 of the challenge JWE; used flag | 15-minute TTL; atomic replay prevention. |
| Redis `usedOidcNonceHash` | SHA-256 of provider plus nonce; used flag | One-year TTL; atomic replay prevention. No ID token or claims are stored. |
| Redis locks | Resource identifiers and random ownership markers | Expiring concurrency locks, not API authentication credentials. Identifiers can contain OIDC issuer/subject, credential IDs or public keys. |
| Client-held challenge JWE | Challenge state and operation context | AES-256-GCM with a KMS-wrapped key; 15-minute lifetime. Add-factor approval binds to the SHA-256 of the exact OIDC token. |
| S3 backup object | Client-supplied encrypted backup bytes | The service cannot verify that arbitrary uploaded bytes are ciphertext. |
| S3 metadata | Encrypted backup keys, public credentials, passkey registration, OIDC subject and masked email, Turnkey IDs | Recoverable metadata, not password hashes. Optional SSE-KMS is configured by `BACKUP_S3_BUCKET_KMS_KEY_ARN`. |
| DynamoDB factor lookup | Factor identity mapped to backup ID | OIDC issuer/subject, passkey credential ID or public key are stored in the primary key without application hashing. This index does not authorize access by itself. |
| Process memory | Incoming credentials, verified claims, temporary JWE encryption keys | Request processing needs the original values. JWK caches contain public provider keys only. Memory is not explicitly zeroized. |

Passkey PRF results can derive client-side encryption keys and must not be sent to this service.
Both registration and authentication reject `prf.results` under either accepted extension name
(`clientExtensionResults` or `extensions`). Registration persists the parsed WebAuthn credential
instead of arbitrary client JSON, dropping unknown JSON fields. The signed attestation object and
client data remain necessary for subsequent Turnkey registration. See the
[WebAuthn PRF specification](https://www.w3.org/TR/webauthn-3/#prf-extension).

Request spans omit query strings and headers. OIDC parsing and verification failures, malformed
passkey credentials, challenge decryption failures and rejected attestation tokens must not log
raw token content or untrusted claim values. Nonce mismatch responses omit both nonce values.
Authentication failures still produce events, following
[OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).

This is not a claim that all stored data is anonymous or hashed. Identity mappings, backup IDs,
public keys, masked email addresses and registration attestations remain sensitive metadata;
some are also logged. Short email local parts are currently returned unchanged by `mask_email`.
Replacing persistent identity keys with keyed hashes requires a separately planned data rewrite
and a deployment strategy that preserves existing backup recovery.

## Deployment and historical data

Changing the add-factor context from `oidcToken` to `oidcTokenHash` invalidates outstanding
add-factor approval challenges. Coordinate the rollout so old and new issuers/verifiers do not
serve this flow concurrently; clients must request fresh challenges. There is no legacy-token
fallback. Redis replay keys and persistent backup identities are unchanged.

New passkey registrations use the WebAuthn library's serialized shape, including its `extensions`
field and base64url encoding for binary fields. Existing registration documents remain readable.
Clients consuming exported registration JSON must accept the canonical shape; PRF results and
unknown extension fields are not retained.

The source review and local Redis/LocalStack tests do not inspect production data or deployment
configuration. Before rollout, investigate whether historical S3 registrations or object versions
contain PRF results or unexpected secrets, and whether old logs contain credentials or claims.
New validation does not clean up existing objects, replicas, logs or snapshots. Do not export raw
values during that investigation. Any cleanup or key rotation needs a separate operational plan.

Verify deployment-owned Redis TLS/ACLs and persistence, S3/DynamoDB encryption and access policies,
log retention, ingress/APM body capture, and debug logging settings. These controls cannot be
established from this repository alone. Do not enable dependency wire/body tracing in production.
