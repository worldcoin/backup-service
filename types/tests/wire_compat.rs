//! Locks down the JSON these types produce to avoid accidental breaking changes
//! on the wire format

use backup_service_types::endpoints::{
    AddFactorRequest, BodyKind, CreateBackupRequest, Endpoint, Method, NewFactor, Platform,
    ResetRequest, SyncBackupRequest, ALL_ENDPOINTS,
};
use backup_service_types::{
    Authorization, BackupEncryptionKey, ErrorBody, ErrorCode, ErrorObject, ExportedBackupMetadata,
    ExportedFactor, ExportedFactorKind, ExportedOidcAccountKind, FactorScope, OidcProvider,
    OidcToken,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use strum::IntoEnumIterator;

/// Asserts the value serializes to exactly `expected`, and that the JSON deserializes back to an
/// equal value.
fn assert_wire<T>(value: &T, expected: &Value)
where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let encoded = serde_json::to_value(value).expect("serialize");
    assert_eq!(&encoded, expected);

    let decoded: T = serde_json::from_value(encoded).expect("deserialize");
    assert_eq!(&decoded, value);
}

#[test]
fn authorization_passkey() {
    assert_wire(
        &Authorization::Passkey {
            credential: json!({"id": "abc"}),
            label: "iCloud Keychain".to_string(),
        },
        &json!({
            "kind": "PASSKEY",
            "credential": {"id": "abc"},
            "label": "iCloud Keychain",
        }),
    );
}

#[test]
fn authorization_passkey_label_defaults_to_empty() {
    let decoded: Authorization =
        serde_json::from_value(json!({"kind": "PASSKEY", "credential": {}})).expect("deserialize");
    assert_eq!(
        decoded,
        Authorization::Passkey {
            credential: json!({}),
            label: String::new(),
        }
    );
}

#[test]
fn authorization_oidc_account() {
    assert_wire(
        &Authorization::OidcAccount {
            oidc_token: OidcToken::Apple {
                token: "jwt".to_string(),
                aud: Some("com.example.app".to_string()),
            },
            public_key: "cHVibGlj".to_string(),
            signature: "c2ln".to_string(),
        },
        &json!({
            "kind": "OIDC_ACCOUNT",
            "oidcToken": {"kind": "APPLE", "token": "jwt", "aud": "com.example.app"},
            "publicKey": "cHVibGlj",
            "signature": "c2ln",
        }),
    );
}

#[test]
fn authorization_ec_keypair() {
    assert_wire(
        &Authorization::EcKeypair {
            public_key: "cHVibGlj".to_string(),
            signature: "c2ln".to_string(),
        },
        &json!({
            "kind": "EC_KEYPAIR",
            "publicKey": "cHVibGlj",
            "signature": "c2ln",
        }),
    );
}

#[test]
fn oidc_token_google_and_apple_without_aud() {
    assert_wire(
        &OidcToken::Google {
            token: "jwt".to_string(),
        },
        &json!({"kind": "GOOGLE", "token": "jwt"}),
    );
    assert_wire(
        &OidcToken::Apple {
            token: "jwt".to_string(),
            aud: None,
        },
        &json!({"kind": "APPLE", "token": "jwt", "aud": null}),
    );

    // `aud` is optional on the wire.
    let decoded: OidcToken =
        serde_json::from_value(json!({"kind": "APPLE", "token": "jwt"})).expect("deserialize");
    assert_eq!(
        decoded,
        OidcToken::Apple {
            token: "jwt".to_string(),
            aud: None
        }
    );
}

#[test]
fn backup_encryption_keys() {
    assert_wire(
        &BackupEncryptionKey::Prf {
            encrypted_key: "key".to_string(),
        },
        &json!({"kind": "PRF", "encryptedKey": "key"}),
    );
    assert_wire(
        &BackupEncryptionKey::Icloud {
            encrypted_key: "key".to_string(),
        },
        &json!({"kind": "ICLOUD", "encryptedKey": "key"}),
    );
    assert_wire(
        &BackupEncryptionKey::Turnkey {
            encrypted_key: "key".to_string(),
            turnkey_account_id: "account".to_string(),
            turnkey_user_id: "user".to_string(),
            turnkey_private_key_id: "private".to_string(),
        },
        &json!({
            "kind": "TURNKEY",
            "encryptedKey": "key",
            "turnkeyAccountId": "account",
            "turnkeyUserId": "user",
            "turnkeyPrivateKeyId": "private",
        }),
    );
}

#[test]
fn backup_encryption_key_flattened_kinds() {
    assert_eq!(
        BackupEncryptionKey::Prf {
            encrypted_key: String::new()
        }
        .flattened_kind(),
        "prf"
    );
    assert_eq!(
        BackupEncryptionKey::Icloud {
            encrypted_key: String::new()
        }
        .flattened_kind(),
        "icloud"
    );
    assert_eq!(
        BackupEncryptionKey::Turnkey {
            encrypted_key: String::new(),
            turnkey_account_id: String::new(),
            turnkey_user_id: String::new(),
            turnkey_private_key_id: String::new(),
        }
        .flattened_kind(),
        "turnkey"
    );
}

#[test]
fn factor_scope() {
    assert_wire(&FactorScope::Main, &json!("MAIN"));
    assert_wire(&FactorScope::Sync, &json!("SYNC"));
    // The storage keys are derived from `Display`, so it has to agree with the wire form.
    assert_eq!(FactorScope::Main.to_string(), "MAIN");
    assert_eq!(FactorScope::Sync.to_string(), "SYNC");
    assert!(serde_json::from_value::<FactorScope>(json!("main")).is_err());
}

#[test]
fn oidc_provider_display_is_stable() {
    // The service builds Redis keys for OIDC nonce replay protection out of this. If it changes,
    // every nonce a user has already spent starts looking unused.
    assert_eq!(OidcProvider::Google.to_string(), "Google");
    assert_eq!(OidcProvider::Apple.to_string(), "Apple");

    assert_eq!(
        OidcProvider::from(&OidcToken::Google {
            token: "jwt".to_string()
        }),
        OidcProvider::Google
    );
    assert_eq!(
        OidcProvider::from(&OidcToken::Apple {
            token: "jwt".to_string(),
            aud: None
        }),
        OidcProvider::Apple
    );
}

#[test]
fn platform() {
    assert_wire(&Platform::Android, &json!("ANDROID"));
    assert_wire(&Platform::Ios, &json!("IOS"));
}

#[test]
fn new_factor() {
    assert_wire(
        &NewFactor::OidcAccount {
            oidc_token: "jwt".to_string(),
        },
        &json!({"kind": "OIDC_ACCOUNT", "oidcToken": "jwt"}),
    );
}

#[test]
fn backup_metadata() {
    let metadata = ExportedBackupMetadata {
        id: "backup_123".to_string(),
        keys: vec![BackupEncryptionKey::Prf {
            encrypted_key: "key".to_string(),
        }],
        factors: vec![
            ExportedFactor {
                id: "factor_1".to_string(),
                created_at: 1_700_000_000,
                kind: ExportedFactorKind::Passkey {
                    credential_id: "Y3JlZA".to_string(),
                    registration: json!({"attestation": "none"}),
                    label: "Added on Pixel 7".to_string(),
                },
            },
            ExportedFactor {
                id: "factor_2".to_string(),
                created_at: 1_700_000_001,
                kind: ExportedFactorKind::OidcAccount {
                    account: ExportedOidcAccountKind::Google {
                        masked_email: "ex***@gmail.com".to_string(),
                    },
                    turnkey_provider_id: "provider_1".to_string(),
                },
            },
        ],
        sync_factors: vec![ExportedFactor {
            id: "factor_3".to_string(),
            created_at: 1_700_000_002,
            kind: ExportedFactorKind::EcKeypair {
                public_key: "cHVibGlj".to_string(),
            },
        }],
        manifest_hash: "ab".repeat(32),
    };

    assert_wire(
        &metadata,
        &json!({
            "id": "backup_123",
            "keys": [{"kind": "PRF", "encryptedKey": "key"}],
            "factors": [
                {
                    "id": "factor_1",
                    "createdAt": 1_700_000_000_i64,
                    "kind": {
                        "kind": "PASSKEY",
                        "credentialId": "Y3JlZA",
                        "registration": {"attestation": "none"},
                        "label": "Added on Pixel 7",
                    },
                },
                {
                    "id": "factor_2",
                    "createdAt": 1_700_000_001_i64,
                    "kind": {
                        "kind": "OIDC_ACCOUNT",
                        "account": {"kind": "GOOGLE", "maskedEmail": "ex***@gmail.com"},
                        "turnkeyProviderId": "provider_1",
                    },
                },
            ],
            "syncFactors": [
                {
                    "id": "factor_3",
                    "createdAt": 1_700_000_002_i64,
                    "kind": {"kind": "EC_KEYPAIR", "publicKey": "cHVibGlj"},
                },
            ],
            "manifestHash": "ab".repeat(32),
        }),
    );
}

#[test]
fn backup_oidc_account_apple() {
    assert_wire(
        &ExportedOidcAccountKind::Apple {
            masked_email: "ex***@icloud.com".to_string(),
        },
        &json!({"kind": "APPLE", "maskedEmail": "ex***@icloud.com"}),
    );
}

#[test]
fn error_body() {
    assert_wire(
        &ErrorBody {
            allow_retry: false,
            error: ErrorObject {
                code: ErrorCode::UnauthorizedFactor,
                message: "The provided factor is not authorized for this backup.".to_string(),
            },
        },
        &json!({
            "allowRetry": false,
            "error": {
                "code": "unauthorized_factor",
                "message": "The provided factor is not authorized for this backup.",
            },
        }),
    );
}

/// Every error code the service can emit. Adding a code is additive and safe; renaming is
/// a breaking change. Removing is likely a breaking change if clients depend on it.
const ERROR_CODES: &[&str] = &[
    "already_used",
    "backup_account_id_already_exists",
    "backup_does_not_exist",
    "backup_id_mismatch",
    "backup_missing",
    "backup_not_found",
    "backup_untraceable",
    "conflicting_lock",
    "content_too_large",
    "empty_backup_file",
    "encryption_key_not_allowed",
    "encryption_key_not_found",
    "factor_already_exists",
    "factor_not_found",
    "factor_orphaned_from_encryption_key",
    "internal_server_error",
    "invalid_attestation_token",
    "invalid_attestation_token_claim",
    "invalid_attestation_token_header",
    "invalid_authorization_type",
    "invalid_backup_account_id",
    "invalid_challenge",
    "invalid_challenge_context",
    "invalid_new_factor_authorization_type",
    "invalid_new_factor_type",
    "invalid_payload",
    "invalid_signature",
    "invalid_sync_factor_type",
    "invalid_turnkey_activity",
    "jwt_error",
    "manifest_hash_mismatch",
    "missing_backup_account_proof",
    "missing_backup_field",
    "missing_email",
    "missing_payload_field",
    "missing_turnkey_activity",
    "missing_turnkey_provider_id",
    "multipart_error",
    "not_found",
    "not_supported",
    "oidc_token_invalid_aud",
    "oidc_token_invalid_nonce",
    "oidc_token_mismatch",
    "oidc_token_parse_error",
    "oidc_token_verification_error",
    "only_one_encryption_key_per_type_allowed",
    "signature_verification_error",
    "sync_factor_must_be_keypair",
    "token_expired",
    "token_not_found",
    "too_many_factors",
    "turnkey_activity_error",
    "unauthorized",
    "unauthorized_factor",
    "unexpected_challenge_type",
    "webauthn_error",
    "webauthn_invalid_payload",
    "webauthn_prf_results_not_allowed",
];

#[test]
fn error_codes_are_stable() {
    let mut actual: Vec<String> = ErrorCode::iter()
        .filter(|code| !matches!(code, ErrorCode::Unknown(_)))
        .map(|code| code.as_str().to_string())
        .collect();
    actual.sort();

    assert_eq!(actual, ERROR_CODES);
}

#[test]
fn error_codes_round_trip() {
    for code in ErrorCode::iter().filter(|code| !matches!(code, ErrorCode::Unknown(_))) {
        let encoded = serde_json::to_value(&code).expect("serialize");
        let decoded: ErrorCode = serde_json::from_value(encoded).expect("deserialize");
        assert_eq!(decoded, code, "{code} did not round-trip");
    }
}

#[test]
fn unknown_error_code_does_not_fail_parsing() {
    let decoded: ErrorBody = serde_json::from_value(json!({
        "allowRetry": false,
        "error": {"code": "a_code_from_the_future", "message": "..."},
    }))
    .expect("an unrecognised code must not break clients");

    assert_eq!(
        decoded.error.code,
        ErrorCode::Unknown("a_code_from_the_future".to_string())
    );
    assert_eq!(decoded.error.code.as_str(), "a_code_from_the_future");
}

#[test]
fn manifest_hashes_are_normalized_on_the_way_in() {
    let request: SyncBackupRequest = serde_json::from_value(json!({
        "authorization": {"kind": "EC_KEYPAIR", "publicKey": "pk", "signature": "sig"},
        "challengeToken": "token",
        "currentManifestHash": format!("0x{}", "AB".repeat(32)),
        "newManifestHash": "cd".repeat(32),
    }))
    .expect("deserialize");

    assert_eq!(request.current_manifest_hash, "ab".repeat(32));
    assert_eq!(request.new_manifest_hash, "cd".repeat(32));
}

#[test]
fn manifest_hashes_of_the_wrong_length_are_rejected() {
    let body = json!({
        "authorization": {"kind": "EC_KEYPAIR", "publicKey": "pk", "signature": "sig"},
        "challengeToken": "token",
        "currentManifestHash": "ab".repeat(31),
        "newManifestHash": "cd".repeat(32),
    });
    assert!(serde_json::from_value::<SyncBackupRequest>(body).is_err());
}

#[test]
fn backup_account_ids_are_validated() {
    let valid = format!("backup_account_{}", "ab".repeat(33));
    let request: ResetRequest = serde_json::from_value(json!({
        "backupAccountId": valid,
        "signature": "sig",
        "challengeToken": "token",
    }))
    .expect("deserialize");
    assert_eq!(request.backup_account_id, valid);

    for invalid in [
        "ab".repeat(33),                               // missing prefix
        format!("backup_account_{}", "ab".repeat(32)), // too short
        "backup_account_nothex".to_string(),           // not hex
    ] {
        let body = json!({
            "backupAccountId": invalid,
            "signature": "sig",
            "challengeToken": "token",
        });
        assert!(
            serde_json::from_value::<ResetRequest>(body).is_err(),
            "{invalid} should have been rejected"
        );
    }
}

#[test]
fn endpoint_paths_are_unique_and_versioned() {
    let mut paths: Vec<&str> = ALL_ENDPOINTS.iter().map(|endpoint| endpoint.path).collect();
    let count = paths.len();
    paths.sort_unstable();
    paths.dedup();
    assert_eq!(paths.len(), count, "duplicate endpoint path");

    for endpoint in ALL_ENDPOINTS {
        assert!(
            endpoint.path.starts_with("/v1/")
                || endpoint.path == "/health"
                || endpoint.path == "/ready",
            "{} is neither versioned nor a probe",
            endpoint.path
        );
    }
}

#[test]
fn multipart_endpoints() {
    let multipart: Vec<&str> = ALL_ENDPOINTS
        .iter()
        .filter(|endpoint| endpoint.body == BodyKind::Multipart)
        .map(|endpoint| endpoint.path)
        .collect();

    assert_eq!(multipart, vec!["/v1/create", "/v1/sync"]);
    assert_eq!(CreateBackupRequest::BODY, BodyKind::Multipart);
    assert_eq!(SyncBackupRequest::BODY, BodyKind::Multipart);
    assert_eq!(AddFactorRequest::BODY, BodyKind::Json);
    assert_eq!(AddFactorRequest::METHOD, Method::Post);
}
