mod common;

use crate::common::{
    add_factor_payload_for_oidc_new, add_factor_payload_for_passkey_new, create_test_backup,
    create_turnkey_activity_and_hash, get_add_factor_challenges_generic, parse_response_body,
    send_post_request_with_environment,
};
use axum::http::StatusCode;
use backup_service_test_utils::{get_mock_passkey_client, registered_passkey_material};
use serde_json::json;
use serial_test::serial;

// Token replay, mismatched new-factor type, swapped tokens, stale approval (Passkey → OIDC)
#[tokio::test]
#[serial]
#[allow(clippy::too_many_lines)] // end-to-end scenario, splitting it would hide the flow
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

    let encrypted_backup_key = json!({
        "kind": "TURNKEY",
        "encryptedKey": "ENCRYPTED_KEY",
        "turnkeyAccountId": "org123",
        "turnkeyUserId": "TURNKEY_USER_ID",
        "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID"
    });
    // The existing passkey authorizes `existingFactorChallenge || SHA256(tag ||
    // new_factor_material)` by stamping a Turnkey activity that carries it as metadata.challenge.
    let existing_payload = add_factor_payload_for_oidc_new(
        &challenges,
        &oidc_token,
        Some("turnkey_provider_id"),
        &encrypted_backup_key,
    );
    let (turnkey_activity, challenge_hash) = create_turnkey_activity_and_hash(&existing_payload);
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
        "encryptedBackupKey": encrypted_backup_key,
    });

    // 1) Replaying the exact request: the first call's commit consumed both tokens and the nonce
    //    (already_used).
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

    // Fresh challenges for the cases below — tokens from case 1 are already spent. The activity is
    // correct for the requested (OIDC) new factor, so the only fault is the one each case injects.
    let challenges2 = get_add_factor_challenges_generic(
        json!({
            "kind": "OIDC_ACCOUNT",
            "oidcToken": oidc_token,
        }),
        Some("PASSKEY"),
    )
    .await;
    let existing_payload2 =
        add_factor_payload_for_oidc_new(&challenges2, &oidc_token, None, &json!(null));
    let (turnkey_activity2, challenge_hash2) = create_turnkey_activity_and_hash(&existing_payload2);
    let passkey_assertion2 =
        backup_service_test_utils::get_passkey_assertion(&mut passkey_client, &challenge_hash2)
            .await;

    // 2) Requested an OIDC new factor but submitted a PASSKEY one, tokens as issued.
    //    Now unexpected_challenge_type (was invalid_new_factor_type): both tokens are decrypted
    //    before the new-factor-type check, and the new-factor token was minted as a Keypair (OIDC)
    //    challenge, which cannot be opened against a PASSKEY authorization.
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
    assert_eq!(body3["error"]["code"], "unexpected_challenge_type");

    // 2b) The same mismatch with a Passkey-type new-factor token (from a PASSKEY_REGISTRATION
    //     ceremony) gets past decryption and is caught by the new-factor descriptor recorded in
    //     the existing token (invalid_new_factor_type). Case 2 failed before the commit, so
    //     round 2's existing token, activity and stamp are still unspent.
    let registration_challenges = get_add_factor_challenges_generic(
        json!({
            "kind": "PASSKEY_REGISTRATION",
            "platform": "IOS"
        }),
        Some("PASSKEY"),
    )
    .await;
    let mismatched_type_payload = json!({
        "existingFactorAuthorization": { "kind": "PASSKEY", "credential": passkey_assertion2 },
        "existingFactorChallengeToken": challenges2["existingFactorToken"],
        "existingFactorTurnkeyActivity": turnkey_activity2,
        "newFactorAuthorization": { "kind": "PASSKEY", "credential": json!({"dummy": true}) },
        "newFactorChallengeToken": registration_challenges["newFactorToken"],
    });
    let resp3b = send_post_request_with_environment(
        "/v1/add-factor",
        mismatched_type_payload,
        Some(environment),
    )
    .await;
    assert_eq!(resp3b.status(), StatusCode::BAD_REQUEST);
    let body3b = parse_response_body(resp3b).await;
    assert_eq!(body3b["error"]["code"], "invalid_new_factor_type");

    // Fresh challenges again so the swap below is the only fault.
    let challenges3 = get_add_factor_challenges_generic(
        json!({
            "kind": "OIDC_ACCOUNT",
            "oidcToken": oidc_token,
        }),
        Some("PASSKEY"),
    )
    .await;
    let existing_payload3 = add_factor_payload_for_oidc_new(
        &challenges3,
        &oidc_token,
        Some("turnkey_provider_id"),
        &json!(null),
    );
    let (turnkey_activity3, challenge_hash3) = create_turnkey_activity_and_hash(&existing_payload3);
    let passkey_assertion3 =
        backup_service_test_utils::get_passkey_assertion(&mut passkey_client, &challenge_hash3)
            .await;
    let signature3 = crate::common::sign_keypair_challenge(
        &session_secret_key,
        challenges3["newFactorChallenge"].as_str().unwrap(),
    );

    // 3) Swapped tokens: the existing slot now holds the Keypair-type new-factor token, rejected
    //    when decrypted against the PASSKEY authorization. Exactly unexpected_challenge_type now
    //    (the previous alternative, invalid_new_factor_type, is unreachable from here).
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
    assert_eq!(body4["error"]["code"], "unexpected_challenge_type");

    // 4) Stale approval: the activity + passkey stamp captured in round 1 (its payload embeds
    //    round 1's challenge) replayed with round 3's still-unspent tokens. New factor and request
    //    fields are identical to round 1, so only the challenge half of the signed payload is
    //    wrong: existing_factor_material_binding_mismatch, reached after the stamp itself verified.
    let stale_activity_payload = json!({
        "existingFactorAuthorization": { "kind": "PASSKEY", "credential": passkey_assertion },
        "existingFactorChallengeToken": challenges3["existingFactorToken"],
        "existingFactorTurnkeyActivity": turnkey_activity,
        "newFactorAuthorization": {
            "kind": "OIDC_ACCOUNT",
            "oidcToken": { "kind": "GOOGLE", "token": oidc_token },
            "publicKey": session_public_key,
            "signature": signature3,
        },
        "newFactorChallengeToken": challenges3["newFactorToken"],
        "turnkeyProviderId": "turnkey_provider_id",
        "encryptedBackupKey": encrypted_backup_key,
    });
    let resp5 = send_post_request_with_environment(
        "/v1/add-factor",
        stale_activity_payload,
        Some(environment),
    )
    .await;
    assert_eq!(resp5.status(), StatusCode::BAD_REQUEST);
    let body5 = parse_response_body(resp5).await;
    assert_eq!(
        body5["error"]["code"],
        "existing_factor_material_binding_mismatch"
    );
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

    // The activity is right for the requested (OIDC) new factor; the only fault is the kind.
    let existing_payload = add_factor_payload_for_oidc_new(
        &challenges,
        &oidc_token,
        Some("turnkey_provider_id"),
        &json!(null),
    );
    let (turnkey_activity, challenge_hash) = create_turnkey_activity_and_hash(&existing_payload);
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

// OIDC existing-factor challenge replay is rejected: the first call's atomic commit consumed both
// challenge tokens (and the existing factor's nonce), so the identical second call is already_used.
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
    let (_, new_public_key_sec1) = registered_passkey_material(&passkey_client);

    let (existing_session_public_key, existing_session_secret_key) =
        crate::common::generate_keypair();
    let existing_oidc_token = test.oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(subject)),
        &existing_session_public_key,
    );
    // Existing factor signs `existingFactorChallenge || SHA256(tag || new_factor_material)`.
    let existing_payload = add_factor_payload_for_passkey_new(
        &challenges,
        &credential,
        &new_public_key_sec1,
        "Replay Passkey",
        None,
        &json!(null),
    );
    let existing_sig =
        crate::common::sign_keypair_challenge(&existing_session_secret_key, &existing_payload);

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
    let (_, credential_b_public_key_sec1) = registered_passkey_material(&passkey_client);

    let (existing_session_public_key, existing_session_secret_key) =
        crate::common::generate_keypair();
    let existing_oidc_token = test.oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(subject)),
        &existing_session_public_key,
    );
    // The existing factor approves ceremony A's challenge but is deliberately bound to credential
    // B's material and label, so the material binding alone would pass: the ceremony check has to
    // reject the swapped registration token on its own.
    let existing_payload = add_factor_payload_for_passkey_new(
        &challenges_a,
        &credential_b,
        &credential_b_public_key_sec1,
        "Attacker Passkey",
        None,
        &json!(null),
    );
    let existing_sig =
        crate::common::sign_keypair_challenge(&existing_session_secret_key, &existing_payload);

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
