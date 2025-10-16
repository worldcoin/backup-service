mod common;

use crate::common::{
    create_test_backup, create_turnkey_activity_and_hash, get_add_factor_challenges_generic,
    parse_response_body, send_post_request_with_environment,
};
use axum::http::StatusCode;
use backup_service_test_utils::get_mock_passkey_client;
use serde_json::json;
use serial_test::serial;

// Request EFC as EC_KEYPAIR but submit PASSKEY for existing factor → challenge type mismatch
#[tokio::test]
#[serial]
async fn test_add_factor_existing_kind_mismatch() {
    let mut passkey_client = get_mock_passkey_client();
    let (_cred, _create_resp) = create_test_backup(&mut passkey_client, b"DATA").await;

    // Ask for EFC with EC_KEYPAIR kind
    let challenges = get_add_factor_challenges_generic(
        json!({ "kind": "EC_KEYPAIR" }),
        Some("EC_KEYPAIR"),
    )
    .await;

    // But sign EFC using passkey (invalid for token’s challenge type)
    let (turnkey_activity, challenge_hash) =
        create_turnkey_activity_and_hash(challenges["existingFactorChallenge"].as_str().unwrap());
    let passkey_assertion = backup_service_test_utils::get_passkey_assertion(&mut passkey_client, &challenge_hash).await;

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
        }),
        None,
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = parse_response_body(resp).await;
    assert_eq!(body["error"]["code"], "unexpected_challenge_type");
}

