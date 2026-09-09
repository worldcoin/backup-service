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
    let environment = backup_service::environment::Environment::development(Some(
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

// OIDC existing-factor challenge replay is rejected (AuthHandler::verify marks token used)
#[tokio::test]
#[serial]
async fn test_add_factor_oidc_existing_challenge_replay() {
    let subject = format!("replay-{}", uuid::Uuid::new_v4());
    let test = crate::common::create_test_backup_with_oidc_account(&subject, b"DATA").await;
    assert_eq!(test.response.status(), StatusCode::OK);

    let mut passkey_client = get_mock_passkey_client();
    let challenges = get_add_factor_challenges_generic(
        json!({
            "kind": "PASSKEY_REGISTRATION",
            "platform": "IOS"
        }),
        Some("OIDC_ACCOUNT"),
    )
    .await;
    let registration_payload = json!({ "challenge": challenges["newFactorChallenge"].clone() });
    let credential = backup_service_test_utils::make_credential_from_passkey_challenge(
        &mut passkey_client,
        &registration_payload,
    )
    .await;

    let (existing_session_public_key, existing_session_secret_key) =
        crate::common::generate_keypair();
    let existing_oidc_token = test.oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(subject)),
        &existing_session_public_key,
    );
    let existing_sig = crate::common::sign_keypair_challenge(
        &existing_session_secret_key,
        challenges["existingFactorChallenge"].as_str().unwrap(),
    );

    let payload = json!({
        "existingFactorAuthorization": {
            "kind": "OIDC_ACCOUNT",
            "oidcToken": { "kind": "GOOGLE", "token": existing_oidc_token },
            "publicKey": existing_session_public_key,
            "signature": existing_sig,
        },
        "existingFactorChallengeToken": challenges["existingFactorToken"],
        "newFactorAuthorization": {
            "kind": "PASSKEY",
            "credential": credential,
            "label": "Replay Passkey"
        },
        "newFactorChallengeToken": challenges["newFactorToken"],
        "encryptedBackupKey": null
    });

    let resp1 = send_post_request_with_environment(
        "/v1/add-factor",
        payload.clone(),
        Some(test.environment),
    )
    .await;
    assert_eq!(resp1.status(), StatusCode::OK);

    let resp2 =
        send_post_request_with_environment("/v1/add-factor", payload, Some(test.environment)).await;
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
    let body2 = parse_response_body(resp2).await;
    assert_eq!(body2["error"]["code"], "already_used");
}

/// Existing-factor approval must not accept a swapped passkey registration ceremony.
#[tokio::test]
#[serial]
async fn test_add_factor_rejects_swapped_passkey_registration_token() {
    let subject = format!("swap-{}", uuid::Uuid::new_v4());
    let test = crate::common::create_test_backup_with_oidc_account(&subject, b"DATA").await;
    assert_eq!(test.response.status(), StatusCode::OK);

    let mut passkey_client = get_mock_passkey_client();

    // Ceremony A: existing factor will authorize this registration.
    let challenges_a = get_add_factor_challenges_generic(
        json!({
            "kind": "PASSKEY_REGISTRATION",
            "platform": "IOS"
        }),
        Some("OIDC_ACCOUNT"),
    )
    .await;

    // Ceremony B: attacker's alternate registration token/credential.
    let challenges_b = get_add_factor_challenges_generic(
        json!({
            "kind": "PASSKEY_REGISTRATION",
            "platform": "IOS"
        }),
        Some("OIDC_ACCOUNT"),
    )
    .await;
    let credential_b = backup_service_test_utils::make_credential_from_passkey_challenge(
        &mut passkey_client,
        &json!({ "challenge": challenges_b["newFactorChallenge"].clone() }),
    )
    .await;

    let (existing_session_public_key, existing_session_secret_key) =
        crate::common::generate_keypair();
    let existing_oidc_token = test.oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(subject)),
        &existing_session_public_key,
    );
    let existing_sig = crate::common::sign_keypair_challenge(
        &existing_session_secret_key,
        challenges_a["existingFactorChallenge"].as_str().unwrap(),
    );

    let resp = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": existing_oidc_token },
                "publicKey": existing_session_public_key,
                "signature": existing_sig,
            },
            "existingFactorChallengeToken": challenges_a["existingFactorToken"],
            // Swap: credential + token from ceremony B, while existing factor signed ceremony A.
            "newFactorAuthorization": {
                "kind": "PASSKEY",
                "credential": credential_b,
                "label": "Attacker Passkey"
            },
            "newFactorChallengeToken": challenges_b["newFactorToken"],
            "encryptedBackupKey": null
        }),
        Some(test.environment),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = parse_response_body(resp).await;
    assert_eq!(body["error"]["code"], "passkey_registration_mismatch");
}
