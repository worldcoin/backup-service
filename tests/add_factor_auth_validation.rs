mod common;

use crate::common::{
    create_test_backup_with_oidc_account, get_add_factor_challenges_generic, parse_response_body,
    send_post_request_with_environment,
};
use axum::http::StatusCode;
use backup_service_test_utils::MockOidcProvider;
use openidconnect::SubjectIdentifier;
use serde_json::json;
use serial_test::serial;

// OIDC(new) missing provider id
#[tokio::test]
#[serial]
async fn test_add_factor_missing_turnkey_provider_id() {
    let test = create_test_backup_with_oidc_account("sig-mismatch", b"DATA").await;

    // Distinct session keypairs for existing/new to avoid nonce reuse
    let (existing_session_public_key, existing_session_secret_key) =
        crate::common::generate_keypair();
    let (new_session_public_key, new_session_secret_key) = crate::common::generate_keypair();

    // New-factor OIDC token bound to new-session key
    let new_oidc_token =
        test.oidc_server
            .generate_token(&MockOidcProvider::Google, None, &new_session_public_key);

    // Challenges for OIDC(new)
    let challenges = get_add_factor_challenges_generic(
        json!({ "kind": "OIDC_ACCOUNT", "oidcToken": new_oidc_token }),
        Some("OIDC_ACCOUNT"),
    )
    .await;

    // Existing OIDC auth for this challenge
    let existing_sig = crate::common::sign_keypair_challenge(
        &existing_session_secret_key,
        challenges["existingFactorChallenge"].as_str().unwrap(),
    );
    let existing_oidc_token = test.oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(SubjectIdentifier::new("sig-mismatch".to_string())),
        &existing_session_public_key,
    );

    // New-factor signature
    let new_sig = crate::common::sign_keypair_challenge(
        &new_session_secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
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
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": new_oidc_token },
                "publicKey": new_session_public_key,
                "signature": new_sig,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "encryptedBackupKey": null
        }),
        Some(test.environment.clone()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = parse_response_body(resp).await;
    assert_eq!(body["error"]["code"], "missing_turnkey_provider_id");
}

// OIDC(new) signature verification error
#[tokio::test]
#[serial]
async fn test_add_factor_new_oidc_signature_mismatch() {
    let test = create_test_backup_with_oidc_account("sig-mismatch", b"DATA").await;

    let (existing_session_public_key, existing_session_secret_key) =
        crate::common::generate_keypair();
    let (new_session_public_key, _new_session_secret_key) = crate::common::generate_keypair();
    let (_wrong_pub, wrong_sk) = crate::common::generate_keypair();

    let new_oidc_token =
        test.oidc_server
            .generate_token(&MockOidcProvider::Google, None, &new_session_public_key);

    let challenges = get_add_factor_challenges_generic(
        json!({ "kind": "OIDC_ACCOUNT", "oidcToken": new_oidc_token }),
        Some("OIDC_ACCOUNT"),
    )
    .await;

    let existing_sig = crate::common::sign_keypair_challenge(
        &existing_session_secret_key,
        challenges["existingFactorChallenge"].as_str().unwrap(),
    );
    let existing_oidc_token = test.oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(SubjectIdentifier::new("sig-mismatch".to_string())),
        &existing_session_public_key,
    );

    let wrong_sig = crate::common::sign_keypair_challenge(
        &wrong_sk,
        challenges["newFactorChallenge"].as_str().unwrap(),
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
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": new_oidc_token },
                "publicKey": new_session_public_key,
                "signature": wrong_sig,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "turnkeyProviderId": "turnkey_provider_id",
            "encryptedBackupKey": null
        }),
        Some(test.environment.clone()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = parse_response_body(resp).await;
    assert_eq!(body["error"]["code"], "signature_verification_error");
}
