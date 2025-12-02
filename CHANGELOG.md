# Changelog



# [0.7.11] - 2025-12-02

## What's Changed
* feat: return backup meta on creation by @paolodamico in https://github.com/worldcoin/backup-service/pull/154
* chore(e2e): attestation token support to E2E test script by @nme-mvasylenko in https://github.com/worldcoin/backup-service/pull/151


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.7.10...0.7.11




# [0.7.10] - 2025-11-20

## What's Changed
* feat: return metadata on endpoints by @paolodamico in https://github.com/worldcoin/backup-service/pull/152
* feat: add support for SSE on S3 bucket by @paolodamico in https://github.com/worldcoin/backup-service/pull/150


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.7.9...0.7.10




# [0.7.9] - 2025-11-10

## What's Changed
* feat: expose credential_id for passkeys by @paolodamico in https://github.com/worldcoin/backup-service/pull/146
* feat: backup status endpoint by @paolodamico in https://github.com/worldcoin/backup-service/pull/147
* fix!: update backup ID requirements by @paolodamico in https://github.com/worldcoin/backup-service/pull/148


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.7.8...0.7.9




# [0.7.8] - 2025-10-27

## What's Changed
* fix: only verify passkey challenge for existing Turnkey by @paolodamico in https://github.com/worldcoin/backup-service/pull/143
* feat: improved error messages by @paolodamico in https://github.com/worldcoin/backup-service/pull/144


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.7.7...0.7.8




# [0.7.7] - 2025-10-23

## What's Changed
* feat!: improvements to deletion process by @paolodamico in https://github.com/worldcoin/backup-service/pull/139
* fix: tiny log improvements & use Docker Hub token for CI by @paolodamico in https://github.com/worldcoin/backup-service/pull/140
* feat: only allow one key per type by @paolodamico in https://github.com/worldcoin/backup-service/pull/141


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.7.6...0.7.7




# [0.7.6] - 2025-10-16

## What's Changed
* feat: add backup_deleted to /delete-factor by @paolodamico in https://github.com/worldcoin/backup-service/pull/123
* feat: update encoding for turnkey nonce by @paolodamico in https://github.com/worldcoin/backup-service/pull/126
* feat: improve logging by @paolodamico in https://github.com/worldcoin/backup-service/pull/127
* chore(deps): bump thiserror from 2.0.12 to 2.0.17 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/125
* chore(deps): bump aws-sdk-kms from 1.63.0 to 1.65.0 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/124
* fix: don't log /health requests by @paolodamico in https://github.com/worldcoin/backup-service/pull/128
* feat: improve logging of spans by @paolodamico in https://github.com/worldcoin/backup-service/pull/129
* feat!: client-provided backup account id by @paolodamico in https://github.com/worldcoin/backup-service/pull/130
* fix: prevent encryption key removal when not appropriate by @paolodamico in https://github.com/worldcoin/backup-service/pull/131
* feat: allow providing a label for passkeys by @paolodamico in https://github.com/worldcoin/backup-service/pull/132
* feat: only keep masked_email by @paolodamico in https://github.com/worldcoin/backup-service/pull/133
* fix: spans aren't dropped correctly by @paolodamico in https://github.com/worldcoin/backup-service/pull/134
* feat: return explicit error codes for when the backup cannot be found by @paolodamico in https://github.com/worldcoin/backup-service/pull/135


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.7.5...0.7.6




# [0.7.5] - 2025-09-22

## What's Changed
* chore: push and attest Docker image to GH registry by @paolodamico in https://github.com/worldcoin/backup-service/pull/112
* Release 0.7.1 by @github-actions[bot] in https://github.com/worldcoin/backup-service/pull/113
* fix: unify crate versioning by @paolodamico in https://github.com/worldcoin/backup-service/pull/114
* Release 0.7.2 by @github-actions[bot] in https://github.com/worldcoin/backup-service/pull/116
* fix: fix docker build by @paolodamico in https://github.com/worldcoin/backup-service/pull/117
* Release 0.7.3 by @github-actions[bot] in https://github.com/worldcoin/backup-service/pull/118
* fix: remove duplicate worldcoin prefix for GH package by @paolodamico in https://github.com/worldcoin/backup-service/pull/119
* Release 0.7.4 by @github-actions[bot] in https://github.com/worldcoin/backup-service/pull/120
* fix: continue on attestation failure by @paolodamico in https://github.com/worldcoin/backup-service/pull/121


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.7.0...0.7.5




# [0.7.4] - 2025-09-22

## What's Changed
* chore: push and attest Docker image to GH registry by @paolodamico in https://github.com/worldcoin/backup-service/pull/112
* Release 0.7.1 by @github-actions[bot] in https://github.com/worldcoin/backup-service/pull/113
* fix: unify crate versioning by @paolodamico in https://github.com/worldcoin/backup-service/pull/114
* Release 0.7.2 by @github-actions[bot] in https://github.com/worldcoin/backup-service/pull/116
* fix: fix docker build by @paolodamico in https://github.com/worldcoin/backup-service/pull/117
* Release 0.7.3 by @github-actions[bot] in https://github.com/worldcoin/backup-service/pull/118
* fix: remove duplicate worldcoin prefix for GH package by @paolodamico in https://github.com/worldcoin/backup-service/pull/119


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.7.0...0.7.4




# [0.7.3] - 2025-09-19

## What's Changed
* chore: push and attest Docker image to GH registry by @paolodamico in https://github.com/worldcoin/backup-service/pull/112
* Release 0.7.1 by @github-actions[bot] in https://github.com/worldcoin/backup-service/pull/113
* fix: unify crate versioning by @paolodamico in https://github.com/worldcoin/backup-service/pull/114
* Release 0.7.2 by @github-actions[bot] in https://github.com/worldcoin/backup-service/pull/116
* fix: fix docker build by @paolodamico in https://github.com/worldcoin/backup-service/pull/117


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.7.0...0.7.3




# [0.7.2] - 2025-09-19

## What's Changed
* chore: push and attest Docker image to GH registry by @paolodamico in https://github.com/worldcoin/backup-service/pull/112
* Release 0.7.1 by @github-actions[bot] in https://github.com/worldcoin/backup-service/pull/113
* fix: unify crate versioning by @paolodamico in https://github.com/worldcoin/backup-service/pull/114


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.7.0...0.7.2




# [0.7.1] - 2025-09-19

## What's Changed
* chore: push and attest Docker image to GH registry by @paolodamico in https://github.com/worldcoin/backup-service/pull/112


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.7.0...0.7.1




# [0.7.0] - 2025-09-18

## What's Changed
* chore(deps): bump tokio from 1.44.2 to 1.46.1 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/84
* chore: bump version to 0.6.0 by @paolodamico in https://github.com/worldcoin/backup-service/pull/91
* chore(deps): bump strum from 0.27.1 to 0.27.2 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/85
* chore(deps): bump aws-sdk-s3 from 1.79.0 to 1.82.0 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/86
* feat!: backup manifest updates by @paolodamico in https://github.com/worldcoin/backup-service/pull/93
* chore(deps): bump reqwest from 0.12.22 to 0.12.23 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/95
* chore(deps): bump tokio from 1.46.1 to 1.47.1 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/94
* fix: exponential backoff on S3 tests & bump tracing-subscriber by @paolodamico in https://github.com/worldcoin/backup-service/pull/100
* chore(deps): bump serde_json from 1.0.140 to 1.0.143 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/98
* feat!: simplify retrieve metadata response by @paolodamico in https://github.com/worldcoin/backup-service/pull/99
* feat: add Aug 4 Anvil audit summary by @paolodamico in https://github.com/worldcoin/backup-service/pull/90
* feat!: add Redis and update lock to prevent race conditions by @paolodamico in https://github.com/worldcoin/backup-service/pull/103
* feat: redis cache manager by @paolodamico in https://github.com/worldcoin/backup-service/pull/104
* feat: add World App's apple client id by @lukejmann in https://github.com/worldcoin/backup-service/pull/105
* chore(ci): dynamodb table name env var by @nme-mvasylenko in https://github.com/worldcoin/backup-service/pull/106
* chore(e2e-tests): fix e2e test script by @nme-mvasylenko in https://github.com/worldcoin/backup-service/pull/107
* chore: bump Rust to 1.89.0 (stable) by @paolodamico in https://github.com/worldcoin/backup-service/pull/109
* fix: release workflow by @paolodamico in https://github.com/worldcoin/backup-service/pull/110

## New Contributors
* @lukejmann made their first contribution in https://github.com/worldcoin/backup-service/pull/105

**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.6.0...0.7.0



# [0.6.0] - 2025-08-13

## What's Changed
* feat: attestation token in backup retrieval by @paolodamico in https://github.com/worldcoin/backup-service/pull/60
* feat: add build version to health check by @paolodamico in https://github.com/worldcoin/backup-service/pull/62
* feat: add changelog and deliberate release process by @paolodamico in https://github.com/worldcoin/backup-service/pull/63
* feat: general clean up, linting & housekeeping by @paolodamico in https://github.com/worldcoin/backup-service/pull/64
* feat: abstract test utils by @paolodamico in https://github.com/worldcoin/backup-service/pull/65
* chore: add git revision build arg by @nme-mvasylenko in https://github.com/worldcoin/backup-service/pull/68
* feat: slimify docker, single statically linked binary by @paolodamico in https://github.com/worldcoin/backup-service/pull/66
* feat: delete sync factor by @paolodamico in https://github.com/worldcoin/backup-service/pull/67
* feat: ensure atomicity of updating backup metadata with etags by @paolodamico in https://github.com/worldcoin/backup-service/pull/69
* feat: security best practices by @paolodamico in https://github.com/worldcoin/backup-service/pull/71
* feat: sync factor integration failure tests & todo clean up by @paolodamico in https://github.com/worldcoin/backup-service/pull/70
* chore(deps): bump public-suffix from 0.1.2 to 0.1.3 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/77
* chore(deps): bump reqwest from 0.12.20 to 0.12.22 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/74
* chore(deps): bump aws-config from 1.6.0 to 1.6.1 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/76
* feat: delete backup endpoint by @paolodamico in https://github.com/worldcoin/backup-service/pull/78
* chore(deps): bump anyhow from 1.0.97 to 1.0.98 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/73
* feat: api versioning by @aurel-fr in https://github.com/worldcoin/backup-service/pull/80
* feat: improvements to delete factor by @paolodamico in https://github.com/worldcoin/backup-service/pull/79
* feat!: enforce explicit scope in /delete-factor by @paolodamico in https://github.com/worldcoin/backup-service/pull/83
* feat!: release attestation enforcement by @paolodamico in https://github.com/worldcoin/backup-service/pull/82
* feat: ready endpoint by @paolodamico in https://github.com/worldcoin/backup-service/pull/81
* fix: factor scope serialization in docs by @paolodamico in https://github.com/worldcoin/backup-service/pull/87
* fix: /ready endpoint should be GET by @paolodamico in https://github.com/worldcoin/backup-service/pull/88
* feat: refactor auth handling to remove duplicated logic by @paolodamico in https://github.com/worldcoin/backup-service/pull/89

## New Contributors
* @dependabot[bot] made their first contribution in https://github.com/worldcoin/backup-service/pull/77

**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.5.0...0.6.0


# [0.5.0] - 2025-06-24

## What's Changed
* feat: abstract authentication by @paolodamico in https://github.com/worldcoin/backup-service/pull/50
* refactor: authhandler as an extension service by @paolodamico in https://github.com/worldcoin/backup-service/pull/51
* general improvements & TODOs by @paolodamico in https://github.com/worldcoin/backup-service/pull/52
* feat: cache jwk set by @aurel-fr in https://github.com/worldcoin/backup-service/pull/54
* feat: safe parser for webauthn credentials by @aurel-fr in https://github.com/worldcoin/backup-service/pull/55
* feat: attestation gateway by @aurel-fr in https://github.com/worldcoin/backup-service/pull/56
* feat: Apple OIDC provider by @aurel-fr in https://github.com/worldcoin/backup-service/pull/57
* prevent OIDC nonce re-use by @paolodamico in https://github.com/worldcoin/backup-service/pull/53
* feat: increase max backup size to 10MB by @paolodamico in https://github.com/worldcoin/backup-service/pull/59

**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.4.0...0.5.0


# [0.4.0] - 2025-06-04

## What's Changed

* feat(delete-factor): add support to delete encryption key (#49)
* feat(delete-factor): add support to delete encryption key
* fix ci test

**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.3.0...0.4.0


# [0.3.0] - 2025-06-01

## What's Changed

* feat: verify OIDC nonce with keypair public key (#43)

**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.2.0...0.3.0


# [0.2.0] - 2025-05-23

## What's Changed

* feat: add factor endpoint (#38)

**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.1.0...0.2.0



# [0.1.0] - 2025-05-14

## What's Changed

* Initial version. Not ready for production use.
