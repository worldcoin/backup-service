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

// New EC signature verification error
#[tokio::test]
#[serial]
async fn test_add_factor_new_ec_signature_mismatch() {
    let test = create_test_backup_with_oidc_account("sig-mismatch", b"DATA").await;

    // Challenges for EC(new)
    let challenges =
        get_add_factor_challenges_generic(json!({ "kind": "EC_KEYPAIR" }), Some("OIDC_ACCOUNT"))
            .await;

    // Existing OIDC auth for this challenge
    let existing_sig = crate::common::sign_keypair_challenge(
        &test.secret_key,
        challenges["existingFactorChallenge"].as_str().unwrap(),
    );
    let existing_oidc_token = test.oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(SubjectIdentifier::new("sig-mismatch".to_string())),
        &test.public_key,
    );

    let (pub1, _sk1) = crate::common::generate_keypair();
    let (_pub2, sk2) = crate::common::generate_keypair();
    let wrong_sig = crate::common::sign_keypair_challenge(
        &sk2,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    let resp = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": existing_oidc_token },
                "publicKey": test.public_key,
                "signature": existing_sig,
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "newFactorAuthorization": { "kind": "EC_KEYPAIR", "publicKey": pub1, "signature": wrong_sig },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "encryptedBackupKey": null
        }),
        Some(test.environment.clone()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = parse_response_body(resp).await;
    assert_eq!(body["error"]["code"], "signature_verification_error");
}
