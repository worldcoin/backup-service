//! Kill switch for OIDC accounts as the *existing* main factor in `/add-factor` (#233). The path
//! landed before the existing factor's authorization is bound to the new factor's material (#271),
//! so production keeps it off (`ADD_FACTOR_OIDC_EXISTING_ENABLED`) and answers `not_supported`,
//! as releases before #233 did. These tests close the gate in the development environment, where
//! it is open by default, and check that both endpoints refuse the OIDC-existing path, that a
//! refusal consumes nothing, and that the shipped passkey-existing flow is untouched.
//!
//! The variable is process-global, so every test here is `#[serial]` and clears it on exit.

mod common;

use crate::common::{
    create_test_backup, create_test_backup_with_oidc_account, create_turnkey_activity_and_hash,
    generate_keypair, get_add_factor_challenges_generic, parse_response_body,
    send_post_request_with_environment, sign_keypair_challenge, verify_s3_metadata_exists,
};
use axum::http::StatusCode;
use backup_service::environment::Environment;
use backup_service_test_utils::{
    get_mock_passkey_client, get_passkey_assertion, make_credential_from_passkey_challenge,
    MockOidcProvider, MockOidcServer,
};
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

const GATE_VAR: &str = "ADD_FACTOR_OIDC_EXISTING_ENABLED";

/// Closes the gate for one test and reopens it (removes the variable) on drop, panic included.
struct GateClosed;

impl GateClosed {
    fn new() -> Self {
        std::env::set_var(GATE_VAR, "false");
        Self
    }
}

impl Drop for GateClosed {
    fn drop(&mut self) {
        std::env::remove_var(GATE_VAR);
    }
}

fn challenge_request(existing_factor_kind: Option<&str>) -> serde_json::Value {
    let mut request = json!({
        "newFactor": { "kind": "PASSKEY_REGISTRATION", "platform": "IOS" },
    });
    if let Some(kind) = existing_factor_kind {
        request["existingFactorKind"] = json!(kind);
    }
    request
}

#[tokio::test]
#[serial]
async fn test_closed_gate_refuses_oidc_existing_challenge_but_serves_passkey_existing() {
    let _gate = GateClosed::new();

    let response = send_post_request_with_environment(
        "/v1/add-factor/challenge",
        challenge_request(Some("OIDC_ACCOUNT")),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = parse_response_body(response).await;
    assert_eq!(body["error"]["code"], "not_supported", "{body}");

    // Explicit and default (omitted) passkey existing factor: exactly as before the gate.
    for existing_factor_kind in [Some("PASSKEY"), None] {
        let response = send_post_request_with_environment(
            "/v1/add-factor/challenge",
            challenge_request(existing_factor_kind),
            None,
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "existingFactorKind={existing_factor_kind:?}"
        );
    }
}

#[tokio::test]
#[serial]
async fn test_closed_gate_refuses_oidc_existing_add_factor_and_consumes_nothing() {
    let subject = format!("gate-{}", Uuid::new_v4());
    let test = create_test_backup_with_oidc_account(&subject, b"BACKUP DATA").await;
    assert_eq!(test.response.status(), StatusCode::OK);

    // Challenges minted while the gate is open (the default here)...
    let mut passkey_client = get_mock_passkey_client();
    let challenges = get_add_factor_challenges_generic(
        json!({ "kind": "PASSKEY_REGISTRATION", "platform": "IOS" }),
        Some("OIDC_ACCOUNT"),
    )
    .await;
    let credential = make_credential_from_passkey_challenge(
        &mut passkey_client,
        &json!({ "challenge": challenges["newFactorChallenge"].clone() }),
    )
    .await;
    let (existing_public_key, existing_secret_key) = generate_keypair();
    let existing_oidc_token = test.oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(subject)),
        &existing_public_key,
    );
    let existing_signature = sign_keypair_challenge(
        &existing_secret_key,
        challenges["existingFactorChallenge"]
            .as_str()
            .expect("existingFactorChallenge"),
    );
    let payload = json!({
        "existingFactorAuthorization": {
            "kind": "OIDC_ACCOUNT",
            "oidcToken": { "kind": "GOOGLE", "token": existing_oidc_token },
            "publicKey": existing_public_key,
            "signature": existing_signature,
        },
        "existingFactorChallengeToken": challenges["existingFactorToken"],
        "newFactorAuthorization": {
            "kind": "PASSKEY",
            "credential": credential,
            "label": "Gated Passkey"
        },
        "newFactorChallengeToken": challenges["newFactorToken"],
        "encryptedBackupKey": null
    });

    // ...are refused once it is closed, before anything is verified or consumed.
    let gate = GateClosed::new();
    let response = send_post_request_with_environment(
        "/v1/add-factor",
        payload.clone(),
        Some(test.environment),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = parse_response_body(response).await;
    assert_eq!(body["error"]["code"], "not_supported", "{body}");

    // With the gate reopened the very same tokens, nonce and credential go through, so the
    // refusal consumed nothing.
    drop(gate);
    let response =
        send_post_request_with_environment("/v1/add-factor", payload, Some(test.environment)).await;
    let status = response.status();
    let body = parse_response_body(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
#[serial]
async fn test_closed_gate_leaves_passkey_existing_flow_untouched() {
    let _gate = GateClosed::new();

    let mut passkey_client = get_mock_passkey_client();
    let (_credential, create_response) =
        create_test_backup(&mut passkey_client, b"BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);
    let backup_id = parse_response_body(create_response).await["backupId"]
        .as_str()
        .expect("backupId")
        .to_string();

    let oidc_server = MockOidcServer::new().await;
    let environment =
        Environment::development(Some(oidc_server.server.socket_address().port() as usize));
    let (session_public_key, session_secret_key) = generate_keypair();
    let oidc_token =
        oidc_server.generate_token(&MockOidcProvider::Google, None, &session_public_key);

    let challenges = get_add_factor_challenges_generic(
        json!({ "kind": "OIDC_ACCOUNT", "oidcToken": oidc_token }),
        Some("PASSKEY"),
    )
    .await;
    let (turnkey_activity, challenge_hash) = create_turnkey_activity_and_hash(
        challenges["existingFactorChallenge"]
            .as_str()
            .expect("existingFactorChallenge"),
    );
    let passkey_assertion = get_passkey_assertion(&mut passkey_client, &challenge_hash).await;
    let new_signature = sign_keypair_challenge(
        &session_secret_key,
        challenges["newFactorChallenge"]
            .as_str()
            .expect("newFactorChallenge"),
    );

    let response = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": { "kind": "PASSKEY", "credential": passkey_assertion },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "existingFactorTurnkeyActivity": turnkey_activity,
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": oidc_token },
                "publicKey": session_public_key,
                "signature": new_signature,
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
        Some(environment),
    )
    .await;
    let status = response.status();
    let body = parse_response_body(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let metadata = verify_s3_metadata_exists(&backup_id).await;
    assert!(
        metadata["factors"]
            .as_array()
            .expect("factors")
            .iter()
            .any(|factor| factor["kind"]["kind"] == "OIDC_ACCOUNT"),
        "OIDC factor not persisted: {metadata}"
    );
}
