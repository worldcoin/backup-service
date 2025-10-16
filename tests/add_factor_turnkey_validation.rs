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
use serde_json::json;
use serial_test::serial;
use sha2::{Digest, Sha256};

// Table-driven Turnkey activity validation
#[tokio::test]
#[serial]
async fn test_turnkey_activity_validation_cases() {
    let mut passkey_client = get_mock_passkey_client();
    let (_cred, _resp) = create_test_backup(&mut passkey_client, b"DATA").await;
    let challenges =
        get_add_factor_challenges_generic(json!({ "kind": "EC_KEYPAIR" }), Some("PASSKEY")).await;

    // Helper: build base payload
    let (pk, sk) = crate::common::generate_keypair();
    let sig = crate::common::sign_keypair_challenge(
        &sk,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    // Valid baseline activity
    let (valid_activity, valid_hash) =
        create_turnkey_activity_and_hash(challenges["existingFactorChallenge"].as_str().unwrap());
    let valid_passkey =
        backup_service_test_utils::get_passkey_assertion(&mut passkey_client, &valid_hash).await;

    // Cases
    let wrong_type_activity = json!({
        "type": "WRONG_TYPE",
        "organizationId": "org123",
        "timestampMs": Utc::now().timestamp_millis().to_string(),
        "metadata": {"challenge": challenges["existingFactorChallenge"]}
    })
    .to_string();

    let missing_challenge_activity = json!({
        "type": "ACTIVITY_TYPE_CREATE_API_KEYS_V2",
        "organizationId": "org123",
        "timestampMs": Utc::now().timestamp_millis().to_string(),
        "metadata": {}
    })
    .to_string();

    let stale_ts = (Utc::now().timestamp_millis() - 1000 * 60 * 10).to_string();
    let stale_ts_activity = json!({
        "type": "ACTIVITY_TYPE_CREATE_API_KEYS_V2",
        "organizationId": "org123",
        "timestampMs": stale_ts,
        "metadata": {"challenge": challenges["existingFactorChallenge"]}
    })
    .to_string();

    let modified_after_sign_activity = {
        // sign valid, then modify
        let (_a, hash) = create_turnkey_activity_and_hash(
            challenges["existingFactorChallenge"].as_str().unwrap(),
        );
        let _assertion =
            backup_service_test_utils::get_passkey_assertion(&mut passkey_client, &hash).await;
        // Change content (different timestamp)
        json!({
            "type": "ACTIVITY_TYPE_CREATE_API_KEYS_V2",
            "organizationId": "org123",
            "timestampMs": Utc::now().timestamp_millis().to_string(),
            "metadata": {"challenge": challenges["existingFactorChallenge"]}
        })
        .to_string()
    };

    // Build assertions per activity
    let cases = vec![
        ("wrong_type", wrong_type_activity, "webauthn_error"),
        (
            "missing_challenge",
            missing_challenge_activity,
            "webauthn_error",
        ),
        ("stale_timestamp", stale_ts_activity, "webauthn_error"),
        (
            "modified_after_sign",
            modified_after_sign_activity,
            "webauthn_error",
        ),
    ];

    for (name, activity, expected_code) in cases {
        // For each case, compute hash and passkey assertion from that activity
        let mut hasher = Sha256::new();
        hasher.update(activity.as_bytes());
        let case_hash =
            BASE64_URL_SAFE_NO_PAD.encode(format!("{:x}", hasher.finalize()).as_bytes());
        let passkey_assertion =
            backup_service_test_utils::get_passkey_assertion(&mut passkey_client, &case_hash).await;

        let resp = send_post_request_with_environment(
            "/v1/add-factor",
            json!({
                "existingFactorAuthorization": { "kind": "PASSKEY", "credential": passkey_assertion },
                "existingFactorChallengeToken": challenges["existingFactorToken"],
                "existingFactorTurnkeyActivity": activity,
                "newFactorAuthorization": { "kind": "EC_KEYPAIR", "publicKey": pk, "signature": sig },
                "newFactorChallengeToken": challenges["newFactorToken"],
            }),
            None,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "case={}", name);
        let body = parse_response_body(resp).await;
        assert_eq!(body["error"]["code"], expected_code, "case={}", name);
    }
}

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
