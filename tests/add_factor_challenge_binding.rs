mod common;

use crate::common::{
    create_test_backup, create_turnkey_activity_and_hash, get_add_factor_challenges_generic,
    parse_response_body, send_post_request_with_environment,
};
use axum::http::StatusCode;
use backup_service_test_utils::get_mock_passkey_client;
use serde_json::json;
use serial_test::serial;

// Token replay, mismatched new-factor type, swapped tokens
#[tokio::test]
#[serial]
async fn test_add_factor_challenge_binding_matrix() {
    // Create a backup with passkey
    let mut passkey_client = get_mock_passkey_client();
    let (_cred, _create_response) = create_test_backup(&mut passkey_client, b"DATA").await;

    // Ask EFC for EC_KEYPAIR, existing PASSKEY
    let challenges =
        get_add_factor_challenges_generic(json!({ "kind": "EC_KEYPAIR" }), Some("PASSKEY")).await;

    // Prepare base artifacts
    let (turnkey_activity, challenge_hash) =
        create_turnkey_activity_and_hash(challenges["existingFactorChallenge"].as_str().unwrap());
    let passkey_assertion =
        backup_service_test_utils::get_passkey_assertion(&mut passkey_client, &challenge_hash)
            .await;
    let (public_key, secret_key) = crate::common::generate_keypair();
    let signature = crate::common::sign_keypair_challenge(
        &secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    // Valid payload template
    let base_payload = json!({
        "existingFactorAuthorization": { "kind": "PASSKEY", "credential": passkey_assertion },
        "existingFactorChallengeToken": challenges["existingFactorToken"],
        "existingFactorTurnkeyActivity": turnkey_activity,
        "newFactorAuthorization": { "kind": "EC_KEYPAIR", "publicKey": public_key, "signature": signature },
        "newFactorChallengeToken": challenges["newFactorToken"],
        "encryptedBackupKey": {
            "kind": "TURNKEY",
            "encryptedKey": "ENCRYPTED_KEY",
            "turnkeyAccountId": "org123",
            "turnkeyUserId": "TURNKEY_USER_ID",
            "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID"
        }
    });

    // 1) Reuse same tokens (already_used)
    let resp1 =
        send_post_request_with_environment("/v1/add-factor", base_payload.clone(), None).await;
    assert_eq!(resp1.status(), StatusCode::OK);
    let resp2 =
        send_post_request_with_environment("/v1/add-factor", base_payload.clone(), None).await;
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
    let body2 = parse_response_body(resp2).await;
    assert_eq!(body2["error"]["code"], "already_used");

    // 2) Mismatched requested new factor vs submitted (invalid_new_factor_type)
    let mismatched_payload = json!({
        "existingFactorAuthorization": base_payload["existingFactorAuthorization"].clone(),
        "existingFactorChallengeToken": base_payload["existingFactorChallengeToken"].clone(),
        "existingFactorTurnkeyActivity": base_payload["existingFactorTurnkeyActivity"].clone(),
        "newFactorAuthorization": { "kind": "PASSKEY", "credential": json!({"dummy": true}) },
        "newFactorChallengeToken": base_payload["newFactorChallengeToken"].clone(),
    });
    let resp3 =
        send_post_request_with_environment("/v1/add-factor", mismatched_payload, None).await;
    assert_eq!(resp3.status(), StatusCode::BAD_REQUEST);
    let body3 = parse_response_body(resp3).await;
    assert_eq!(body3["error"]["code"], "invalid_new_factor_type");

    // 3) Swapped tokens (unexpected_challenge_type or binding error depending on implementation)
    let swapped_tokens_payload = json!({
        "existingFactorAuthorization": base_payload["existingFactorAuthorization"].clone(),
        "existingFactorChallengeToken": base_payload["newFactorChallengeToken"].clone(),
        "existingFactorTurnkeyActivity": base_payload["existingFactorTurnkeyActivity"].clone(),
        "newFactorAuthorization": base_payload["newFactorAuthorization"].clone(),
        "newFactorChallengeToken": base_payload["existingFactorChallengeToken"].clone(),
    });
    let resp4 =
        send_post_request_with_environment("/v1/add-factor", swapped_tokens_payload, None).await;
    assert_eq!(resp4.status(), StatusCode::BAD_REQUEST);
    let body4 = parse_response_body(resp4).await;
    // Accept either of the two codes if implementation varies; prefer the stricter type error
    let code = body4["error"]["code"].as_str().unwrap_or("");
    assert!(code == "unexpected_challenge_type" || code == "invalid_new_factor_type");
}

// Existing-factor kind mismatch: EFC expects EC_KEYPAIR but we submit PASSKEY assertion
#[tokio::test]
#[serial]
async fn test_add_factor_existing_kind_mismatch() {
    // Create a backup with passkey
    let mut passkey_client = get_mock_passkey_client();
    let (_cred, _create_resp) = create_test_backup(&mut passkey_client, b"DATA").await;

    // Ask for EFC with EC_KEYPAIR kind (existing factor kind mismatch)
    let challenges =
        get_add_factor_challenges_generic(json!({ "kind": "EC_KEYPAIR" }), Some("EC_KEYPAIR"))
            .await;

    // Sign EFC using passkey (invalid for token’s challenge type)
    let (turnkey_activity, challenge_hash) =
        create_turnkey_activity_and_hash(challenges["existingFactorChallenge"].as_str().unwrap());
    let passkey_assertion =
        backup_service_test_utils::get_passkey_assertion(&mut passkey_client, &challenge_hash)
            .await;

    // New EC
    let (public_key, secret_key) = crate::common::generate_keypair();
    let signature = crate::common::sign_keypair_challenge(
        &secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    let resp = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": { "kind": "PASSKEY", "credential": passkey_assertion },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "existingFactorTurnkeyActivity": turnkey_activity,
            "newFactorAuthorization": { "kind": "EC_KEYPAIR", "publicKey": public_key, "signature": signature },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "encryptedBackupKey": {
                "kind": "TURNKEY",
                "encryptedKey": "ENCRYPTED_KEY",
                "turnkeyAccountId": "org123",
                "turnkeyUserId": "TURNKEY_USER_ID",
                "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID"
            }
        }),
        None,
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = parse_response_body(resp).await;
    assert_eq!(body["error"]["code"], "unexpected_challenge_type");
}
