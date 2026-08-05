mod common;

use crate::common::{
    create_test_backup, create_turnkey_activity_and_hash, get_add_factor_challenges_generic,
    parse_response_body, send_post_request_with_environment,
};
use axum::http::StatusCode;
use backup_service_test_utils::get_mock_passkey_client;
use serde_json::json;
use serial_test::serial;

// Token replay, mismatched new-factor type, swapped tokens (Passkey → OIDC)
#[tokio::test]
#[serial]
async fn test_add_factor_challenge_binding_matrix() {
    let mut passkey_client = get_mock_passkey_client();
    let (_cred, _create_response) = create_test_backup(&mut passkey_client, b"DATA").await;

    let oidc_server = backup_service_test_utils::MockOidcServer::new().await;
    let environment = backup_service::types::Environment::development(Some(
        oidc_server.server.socket_address().port() as usize,
    ));
    let (session_public_key, session_secret_key) = crate::common::generate_keypair();
    let oidc_token = oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        None,
        &session_public_key,
    );

    let challenges = get_add_factor_challenges_generic(
        json!({
            "kind": "OIDC_ACCOUNT",
            "oidcToken": oidc_token,
        }),
        Some("PASSKEY"),
    )
    .await;

    let (turnkey_activity, challenge_hash) =
        create_turnkey_activity_and_hash(challenges["existingFactorChallenge"].as_str().unwrap());
    let passkey_assertion =
        backup_service_test_utils::get_passkey_assertion(&mut passkey_client, &challenge_hash)
            .await;
    let signature = crate::common::sign_keypair_challenge(
        &session_secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    let base_payload = json!({
        "existingFactorAuthorization": { "kind": "PASSKEY", "credential": passkey_assertion },
        "existingFactorChallengeToken": challenges["existingFactorToken"],
        "existingFactorTurnkeyActivity": turnkey_activity,
        "newFactorAuthorization": {
            "kind": "OIDC_ACCOUNT",
            "oidcToken": { "kind": "GOOGLE", "token": oidc_token },
            "publicKey": session_public_key,
            "signature": signature,
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
    });

    // 1) Reuse same tokens (already_used)
    let resp1 = send_post_request_with_environment(
        "/v1/add-factor",
        base_payload.clone(),
        Some(environment),
    )
    .await;
    assert_eq!(resp1.status(), StatusCode::OK);
    let resp2 = send_post_request_with_environment(
        "/v1/add-factor",
        base_payload.clone(),
        Some(environment),
    )
    .await;
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
    let body2 = parse_response_body(resp2).await;
    assert_eq!(body2["error"]["code"], "already_used");

    // Fresh challenges for cases below — tokens from case 1 are already spent.
    let challenges2 = get_add_factor_challenges_generic(
        json!({
            "kind": "OIDC_ACCOUNT",
            "oidcToken": oidc_token,
        }),
        Some("PASSKEY"),
    )
    .await;
    let (turnkey_activity2, challenge_hash2) =
        create_turnkey_activity_and_hash(challenges2["existingFactorChallenge"].as_str().unwrap());
    let passkey_assertion2 =
        backup_service_test_utils::get_passkey_assertion(&mut passkey_client, &challenge_hash2)
            .await;

    // 2) Mismatched requested new factor vs submitted (invalid_new_factor_type)
    let mismatched_payload = json!({
        "existingFactorAuthorization": { "kind": "PASSKEY", "credential": passkey_assertion2 },
        "existingFactorChallengeToken": challenges2["existingFactorToken"],
        "existingFactorTurnkeyActivity": turnkey_activity2,
        "newFactorAuthorization": { "kind": "PASSKEY", "credential": json!({"dummy": true}) },
        "newFactorChallengeToken": challenges2["newFactorToken"],
    });
    let resp3 =
        send_post_request_with_environment("/v1/add-factor", mismatched_payload, Some(environment))
            .await;
    assert_eq!(resp3.status(), StatusCode::BAD_REQUEST);
    let body3 = parse_response_body(resp3).await;
    assert_eq!(body3["error"]["code"], "invalid_new_factor_type");

    // Fresh challenges again (case 2 may have consumed existing-factor token on the passkey path).
    let challenges3 = get_add_factor_challenges_generic(
        json!({
            "kind": "OIDC_ACCOUNT",
            "oidcToken": oidc_token,
        }),
        Some("PASSKEY"),
    )
    .await;
    let (turnkey_activity3, challenge_hash3) =
        create_turnkey_activity_and_hash(challenges3["existingFactorChallenge"].as_str().unwrap());
    let passkey_assertion3 =
        backup_service_test_utils::get_passkey_assertion(&mut passkey_client, &challenge_hash3)
            .await;
    let signature3 = crate::common::sign_keypair_challenge(
        &session_secret_key,
        challenges3["newFactorChallenge"].as_str().unwrap(),
    );

    // 3) Swapped tokens
    let swapped_tokens_payload = json!({
        "existingFactorAuthorization": { "kind": "PASSKEY", "credential": passkey_assertion3 },
        "existingFactorChallengeToken": challenges3["newFactorToken"],
        "existingFactorTurnkeyActivity": turnkey_activity3,
        "newFactorAuthorization": {
            "kind": "OIDC_ACCOUNT",
            "oidcToken": { "kind": "GOOGLE", "token": oidc_token },
            "publicKey": session_public_key,
            "signature": signature3,
        },
        "newFactorChallengeToken": challenges3["existingFactorToken"],
        "turnkeyProviderId": "turnkey_provider_id",
    });
    let resp4 = send_post_request_with_environment(
        "/v1/add-factor",
        swapped_tokens_payload,
        Some(environment),
    )
    .await;
    assert_eq!(resp4.status(), StatusCode::BAD_REQUEST);
    let body4 = parse_response_body(resp4).await;
    let code = body4["error"]["code"].as_str().unwrap_or("");
    assert!(code == "unexpected_challenge_type" || code == "invalid_new_factor_type");
}

// Existing-factor kind mismatch: token is OIDC/Keypair but we submit PASSKEY
#[tokio::test]
#[serial]
async fn test_add_factor_existing_kind_mismatch() {
    let mut passkey_client = get_mock_passkey_client();
    let (_cred, _create_resp) = create_test_backup(&mut passkey_client, b"DATA").await;

    let oidc_server = backup_service_test_utils::MockOidcServer::new().await;
    let (session_public_key, _) = crate::common::generate_keypair();
    let oidc_token = oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        None,
        &session_public_key,
    );

    // Issue existing-factor challenge as OIDC (Keypair), but authorize with Passkey
    let challenges = get_add_factor_challenges_generic(
        json!({
            "kind": "OIDC_ACCOUNT",
            "oidcToken": oidc_token,
        }),
        Some("OIDC_ACCOUNT"),
    )
    .await;

    let (turnkey_activity, challenge_hash) =
        create_turnkey_activity_and_hash(challenges["existingFactorChallenge"].as_str().unwrap());
    let passkey_assertion =
        backup_service_test_utils::get_passkey_assertion(&mut passkey_client, &challenge_hash)
            .await;

    let resp = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": { "kind": "PASSKEY", "credential": passkey_assertion },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "existingFactorTurnkeyActivity": turnkey_activity,
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": oidc_token },
                "publicKey": session_public_key,
                "signature": "AAAA",
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "turnkeyProviderId": "turnkey_provider_id",
        }),
        None,
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = parse_response_body(resp).await;
    assert_eq!(body["error"]["code"], "unexpected_challenge_type");
}
