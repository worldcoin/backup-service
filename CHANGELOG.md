# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.7](https://github.com/worldcoin/backup-service/compare/0.9.6...0.9.7) - 2026-10-01

### Added

- gate OIDC add factor ([#279](https://github.com/worldcoin/backup-service/pull/279))

### Other

- *(deps)* bump tokio from 1.49.0 to 1.50.0 ([#294](https://github.com/worldcoin/backup-service/pull/294))
- *(deps)* bump aws-sdk-dynamodb from 1.121.0 to 1.123.0 ([#292](https://github.com/worldcoin/backup-service/pull/292))
- *(deps)* bump async-trait from 0.1.89 to 0.1.92 ([#293](https://github.com/worldcoin/backup-service/pull/293))
- *(deps)* bump chrono from 0.4.44 to 0.4.45 ([#291](https://github.com/worldcoin/backup-service/pull/291))

## [0.9.6](https://github.com/worldcoin/backup-service/compare/0.9.5...0.9.6) - 2026-10-01

### Added

- improvements to universal factor and refactor ([#283](https://github.com/worldcoin/backup-service/pull/283))
- *(add-factor)* OIDC existing main factor authorization ([#233](https://github.com/worldcoin/backup-service/pull/233))
- *(add-factor)* challenge API for universal add-factor ([#232](https://github.com/worldcoin/backup-service/pull/232))
- prove backup account key on backup creation ([#243](https://github.com/worldcoin/backup-service/pull/243))

### Fixed

- *(release)* read versions from git tags in release-plz ([#288](https://github.com/worldcoin/backup-service/pull/288))
- [MCORE-1898] replace selected sync access atomically during recovery ([#287](https://github.com/worldcoin/backup-service/pull/287))
- *(add-factor)* post-insert FactorLookup ensure reconcile ([#237](https://github.com/worldcoin/backup-service/pull/237))
- *(add-factor)* lookup ensure vs delete + heal retries ([#235](https://github.com/worldcoin/backup-service/pull/235))
- *(add-factor)* concurrent lookup heal + same-session OIDC ([#234](https://github.com/worldcoin/backup-service/pull/234))
- *(add-factor)* verify factor presence inside add_encryption_key_only ([#269](https://github.com/worldcoin/backup-service/pull/269))
- avoid race condition on backup update ([#262](https://github.com/worldcoin/backup-service/pull/262))
- graceful shutdown ([#261](https://github.com/worldcoin/backup-service/pull/261))
- *(auth)* follow-ups on FactorLookup mutate locking ([#239](https://github.com/worldcoin/backup-service/pull/239))
- *(auth)* GC stale FactorLookup when metadata does not authorize ([#238](https://github.com/worldcoin/backup-service/pull/238))
- *(storage)* factor write reconcile + consistent lookup ([#231](https://github.com/worldcoin/backup-service/pull/231))

### Other

- *(add-factor)* unit-test metadata factor presence helper ([#236](https://github.com/worldcoin/backup-service/pull/236))
- *(deps)* bump k256 from 0.13.4 to 0.14.0 ([#224](https://github.com/worldcoin/backup-service/pull/224))
- *(deps)* bump serial_test from 3.5.0 to 4.0.1 ([#223](https://github.com/worldcoin/backup-service/pull/223))
- *(deps)* bump passkey from 0.4.0 to 0.5.0 ([#268](https://github.com/worldcoin/backup-service/pull/268))
- *(deps)* bump webauthn-rs from 0.5.2 to 0.5.5 ([#266](https://github.com/worldcoin/backup-service/pull/266))
- *(deps)* bump bytes from 1.11.1 to 1.12.1 ([#267](https://github.com/worldcoin/backup-service/pull/267))
- improve ci config ([#260](https://github.com/worldcoin/backup-service/pull/260))
- Dependency Update - Rust - rustls ([#264](https://github.com/worldcoin/backup-service/pull/264))
- unit tests for content-length validation ([#263](https://github.com/worldcoin/backup-service/pull/263))
- *(auth)* add a metric for auth-time stale FactorLookup GC ([#248](https://github.com/worldcoin/backup-service/pull/248))
- *(deps)* bump rsa from 0.9.8 to 0.9.10 ([#259](https://github.com/worldcoin/backup-service/pull/259))
- *(deps)* bump reqwest from 0.12.24 to 0.12.28 ([#257](https://github.com/worldcoin/backup-service/pull/257))
- *(deps)* bump serde_json from 1.0.149 to 1.0.151 ([#258](https://github.com/worldcoin/backup-service/pull/258))
- version bumps & RUSTSEC-2026-0258 ([#244](https://github.com/worldcoin/backup-service/pull/244))
- refactor all types into a separate crate ([#240](https://github.com/worldcoin/backup-service/pull/240))
- *(deps)* bump anyhow from 1.0.103 to 1.0.104 ([#222](https://github.com/worldcoin/backup-service/pull/222))
- *(deps)* bump serde from 1.0.228 to 1.0.229 ([#225](https://github.com/worldcoin/backup-service/pull/225))
- *(deps)* bump aws-sdk-s3 from 1.128.0 to 1.129.0 ([#226](https://github.com/worldcoin/backup-service/pull/226))
- Fix Redis lock release race by binding lock to owner token ([#214](https://github.com/worldcoin/backup-service/pull/214))

# [0.9.5] - 2026-08-03

## What's Changed
* feat: test to ensure rejection of dual audiences by @paolodamico in https://github.com/worldcoin/backup-service/pull/220
* fix: performant byte handling & minor sec improvements by @paolodamico in https://github.com/worldcoin/backup-service/pull/217
* fix: hash full /v1 request path for attestation JTI validation by @SeanROlszewski in https://github.com/worldcoin/backup-service/pull/227
* feat: specify aud for apple oidc & support all clients by @paolodamico in https://github.com/worldcoin/backup-service/pull/221

## New Contributors
* @SeanROlszewski made their first contribution in https://github.com/worldcoin/backup-service/pull/227

**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.9.4...0.9.5




# [0.9.4] - 2026-07-16

## What's Changed
* feat: validate attestation gateway even on disabled by @paolodamico in https://github.com/worldcoin/backup-service/pull/213


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.9.3...0.9.4




# [0.9.3] - 2026-07-15

## What's Changed
* fix: provide claim details on attest failures by @paolodamico in https://github.com/worldcoin/backup-service/pull/211


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.9.2...0.9.3




# [0.9.2] - 2026-07-14

## What's Changed
* chore(deps): bump uuid from 1.16.0 to 1.23.0 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/199
* chore(deps): bump mockito from 1.7.1 to 1.7.2 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/198
* chore(deps): bump tower-http from 0.6.7 to 0.6.8 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/197
* chore(deps): bump aws-sdk-s3 from 1.127.0 to 1.128.0 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/196
* chore: default enable attestation gateway by @aurel-fr in https://github.com/worldcoin/backup-service/pull/204
* chore(deps): bump axum from 0.8.1 to 0.8.8 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/200
* chore: address rustsec advisories by @paolodamico in https://github.com/worldcoin/backup-service/pull/206
* Release 0.9.1 by @github-actions[bot] in https://github.com/worldcoin/backup-service/pull/207
* ci by @aurel-fr in https://github.com/worldcoin/backup-service/pull/208
* chore: address RUSTSEC-2026-0048 by @paolodamico in https://github.com/worldcoin/backup-service/pull/209


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.9.0...0.9.2




# [0.9.1] - 2026-07-10

## What's Changed
* chore(deps): bump uuid from 1.16.0 to 1.23.0 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/199
* chore(deps): bump mockito from 1.7.1 to 1.7.2 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/198
* chore(deps): bump tower-http from 0.6.7 to 0.6.8 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/197
* chore(deps): bump aws-sdk-s3 from 1.127.0 to 1.128.0 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/196
* chore: default enable attestation gateway by @aurel-fr in https://github.com/worldcoin/backup-service/pull/204
* chore(deps): bump axum from 0.8.1 to 0.8.8 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/200
* chore: address rustsec advisories by @paolodamico in https://github.com/worldcoin/backup-service/pull/206


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.9.0...0.9.1




# [0.9.0] - 2026-05-26

## What's Changed
* chore(deps): bump reqwest from 0.12.23 to 0.12.24 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/170
* fix: backup keys are on the secp256k1 curve by @paolodamico in https://github.com/worldcoin/backup-service/pull/193
* chore: add localstack token by @paolodamico in https://github.com/worldcoin/backup-service/pull/195
* Add support for multiple clients by @ketzusaka in https://github.com/worldcoin/backup-service/pull/201

## New Contributors
* @ketzusaka made their first contribution in https://github.com/worldcoin/backup-service/pull/201

**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.8.5...0.9.0




# [0.8.5] - 2026-03-06

## What's Changed
* chore(deps): bump tokio from 1.48.0 to 1.49.0 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/190
* chore(deps): bump chrono from 0.4.40 to 0.4.44 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/189
* fix: always lowercase manifest hash by @paolodamico in https://github.com/worldcoin/backup-service/pull/169
* chore(tfh-backup): fix ECDSA DER signature length validation by @nme-mvasylenko in https://github.com/worldcoin/backup-service/pull/185
* feat: expose /metrics endpoint via axum-prometheus by @nme-mvasylenko in https://github.com/worldcoin/backup-service/pull/191
* chore(deps): bump serde from 1.0.219 to 1.0.228 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/172


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.8.4...0.8.5




# [0.8.4] - 2026-02-17

## What's Changed
* feat: introduce verify factor endpoint by @paolodamico in https://github.com/worldcoin/backup-service/pull/186


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.8.3...0.8.4




# [0.8.3] - 2026-02-12

## What's Changed
* feat: introduce /reset endpoint by @paolodamico in https://github.com/worldcoin/backup-service/pull/176
* chore(tfh-backup): bump rust to 1.91, configure ConnectionManager timeouts by @nme-mvasylenko in https://github.com/worldcoin/backup-service/pull/183


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.8.2...0.8.3




# [0.8.2] - 2026-02-04

## What's Changed
* feat: improve multipart request handling by @paolodamico in https://github.com/worldcoin/backup-service/pull/179
* chore(deps): bump tracing from 0.1.41 to 0.1.44 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/173
* chore(deps): bump serde_json from 1.0.143 to 1.0.148 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/171
* chore(tfh-backup): enable TLS support for Redis connections by @nme-mvasylenko in https://github.com/worldcoin/backup-service/pull/181
* chore(deps): bump mockito from 1.7.0 to 1.7.1 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/158


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.8.1...0.8.2




# [0.8.1] - 2026-01-29

## What's Changed
* Update GH workflows to use public runner groups by @ernish in https://github.com/worldcoin/backup-service/pull/168
* chore(deps): bump openidconnect from 4.0.0 to 4.0.1 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/159
* feat: improve max file size handling by @paolodamico in https://github.com/worldcoin/backup-service/pull/177

## New Contributors
* @ernish made their first contribution in https://github.com/worldcoin/backup-service/pull/168

**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.8.0...0.8.1




# [0.8.0] - 2025-12-09

## What's Changed
* feat: debug invalid oidc tokens by @paolodamico in https://github.com/worldcoin/backup-service/pull/165
* chore: MIT license by @paolodamico in https://github.com/worldcoin/backup-service/pull/166


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.7.12...0.8.0




# [0.7.12] - 2025-12-08

## What's Changed
* fix: docker hub login CI by @paolodamico in https://github.com/worldcoin/backup-service/pull/162
* chore(deps): bump tokio from 1.47.1 to 1.48.0 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/157
* chore(deps): bump async-trait from 0.1.88 to 0.1.89 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/160
* chore(deps): bump tower-http from 0.6.6 to 0.6.7 by @dependabot[bot] in https://github.com/worldcoin/backup-service/pull/156
* feat: improve errors for failed signature by @paolodamico in https://github.com/worldcoin/backup-service/pull/163


**Full Changelog**: https://github.com/worldcoin/backup-service/compare/0.7.11...0.7.12




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
