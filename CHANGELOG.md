# Changelog


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