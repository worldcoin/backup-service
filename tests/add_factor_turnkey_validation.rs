mod common;

use crate::common::{
    create_test_backup, create_turnkey_activity_and_hash, get_add_factor_challenges_generic,
    parse_response_body, send_post_request_with_environment,
};
use axum::http::StatusCode;
use backup_service_test_utils::get_mock_passkey_client;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::json;
use serial_test::serial;
use sha2::{Digest, Sha256};

// OIDC(existing) → OIDC(new) metadata-only upgrade should add TURNKEY key
#[tokio::test]
#[serial]
async fn test_add_factor_metadata_only_turnkey_upgrade() {
    let test =
        crate::common::create_test_backup_with_oidc_account("user-subject", b"BACKUP DATA").await;
    assert_eq!(test.response.status(), StatusCode::OK);
    let body = test
        .response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let create_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = create_response["backupId"].as_str().unwrap();

    // Request challenges with existing OIDC and new OIDC (same account)
    let challenges = get_add_factor_challenges_generic(
        json!({
            "kind": "OIDC_ACCOUNT",
            "oidcToken": test.oidc_token
        }),
        Some("OIDC_ACCOUNT"),
    )
    .await;

    let existing_sig = crate::common::sign_keypair_challenge(
        &test.secret_key,
        challenges["existingFactorChallenge"].as_str().unwrap(),
    );
    let new_sig = crate::common::sign_keypair_challenge(
        &test.secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    let response = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": test.oidc_token.clone() },
                "publicKey": test.public_key,
                "signature": existing_sig,
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": test.oidc_token },
                "publicKey": test.public_key,
                "signature": new_sig,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "turnkeyProviderId": "turnkey_provider_id",
            "encryptedBackupKey": {
                "kind": "TURNKEY",
                "encryptedKey": "ENCRYPTED_KEY",
                "turnkeyAccountId": "org123",
                "turnkeyUserId": "TURNKEY_USER_ID",
                "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID"
            }
        }),
        Some(test.environment),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = crate::common::verify_s3_metadata_exists(backup_id).await;
    let keys = metadata["keys"].as_array().unwrap();
    let turnkey_key_found = keys.iter().any(|k| k["kind"] == "TURNKEY");
    assert!(turnkey_key_found);
}
