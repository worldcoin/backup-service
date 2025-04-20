mod common;

use crate::common::{
    get_passkey_challenge, make_credential_from_passkey_challenge, send_post_request,
    send_post_request_with_multipart,
};
use axum::body::Bytes;
use axum::http::StatusCode;
use backup_service::types::Environment;
use http_body_util::BodyExt;
use serde_json::json;

#[tokio::test]
async fn test_add_oidc_account_integration() {
    let environment = Environment::development(None);
    let oidc_server = common::MockOidcServer::new().await;

    let mut passkey_client = common::get_mock_passkey_client();

    // Get a challenge from the server
    let challenge_response = get_passkey_challenge().await;

    // Register a credential by solving the challenge
    let credential =
        make_credential_from_passkey_challenge(&mut passkey_client, &challenge_response).await;

    // Send the credential to the server to create a backup
    let response = send_post_request_with_multipart(
        "/create",
        json!({
            "solvedChallenge": {
                "kind": "PASSKEY",
                "credential": credential,
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
        }),
        Bytes::from(b"TEST FILE".as_slice()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Add OIDC account
    let response = send_post_request(
        "/add-oidc-account",
        json!({
            "oidcToken": {
                "kind": "GOOGLE",
                "token": oidc_server.generate_token(environment),
            },
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let response = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&response).unwrap();

    assert_eq!(response, json!({}));

    let incorrect_token_payloads: Vec<serde_json::Value> = vec![
        // Expired token
        json!({
            "oidcToken": {
                "kind": "GOOGLE",
                "token": oidc_server.generate_expired_token(environment),
            },
        }),
        // Incorrectly signed token
        json!({
            "oidcToken": {
                "kind": "GOOGLE",
                "token": oidc_server.generate_incorrectly_signed_token(environment),
            },
        }),
        // Invalid issuer
        json!({
            "oidcToken": {
                "kind": "GOOGLE",
                "token": oidc_server.generate_token_with_incorrect_issuer(environment),
            },
        }),
        // Invalid audience
        json!({
            "oidcToken": {
                "kind": "GOOGLE",
                "token": oidc_server.generate_token_with_incorrect_audience(environment),
            },
        }),
        // Invalid issued at
        json!({
            "oidcToken": {
                "kind": "GOOGLE",
                "token": oidc_server.generate_token_with_incorrect_issued_at(environment),
            },
        }),
    ];

    for payload in incorrect_token_payloads {
        let response = send_post_request("/add-oidc-account", payload).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = response.into_body().collect().await.unwrap().to_bytes();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(
            response,
            json!({
                "error": "invalid_oidc_token"
            })
        );
    }
}

// TODO/FIXME: Primary factor authentication; update checks (e.g. no previous OIDC account, existing OIDC account, etc.)
