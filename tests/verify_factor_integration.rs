mod common;

use crate::common::{
    create_test_backup, create_test_backup_with_keypair, create_test_backup_with_sync_keypair,
    generate_test_attestation_token, get_test_router, send_post_request,
    send_post_request_with_bypass_attestation_token, sign_keypair_challenge,
};
use axum::{extract::Request, http::StatusCode};
use backup_service::attestation_gateway::ATTESTATION_GATEWAY_HEADER;
use backup_service_test_utils::{authenticate_with_passkey_challenge, get_mock_passkey_client};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::json;
use serial_test::serial;
use tower::ServiceExt;

async fn get_verify_factor_passkey_challenge() -> serde_json::Value {
    let response =
        send_post_request("/v1/verify-factor/challenge/passkey", json!({})).await;
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn get_verify_factor_keypair_challenge() -> serde_json::Value {
    let response =
        send_post_request("/v1/verify-factor/challenge/keypair", json!({})).await;
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn test_verify_factor_with_passkey() {
    let mut passkey_client = get_mock_passkey_client();

    let (_, create_response) = create_test_backup(&mut passkey_client, b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    let challenge = get_verify_factor_passkey_challenge().await;
    let credential = authenticate_with_passkey_challenge(&mut passkey_client, &challenge).await;

    let body = json!({
        "authorization": {
            "kind": "PASSKEY",
            "credential": credential,
        },
        "challengeToken": challenge["token"],
    });

    let (jwk, jwt) = generate_test_attestation_token(&body, "/verify-factor");
    let mut server = mockito::Server::new_async().await;
    let mut key_response =
        json!({ "keys": [serde_json::to_value(jwk.to_public_key().unwrap()).unwrap()] });
    key_response["keys"][0]["kid"] = json!("integration-test-kid");

    server
        .mock("GET", "/.well-known/jwks.json")
        .with_status(200)
        .with_body(key_response.to_string())
        .create();

    let router = get_test_router(None, Some(server.url().as_str())).await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/v1/verify-factor")
                .method("POST")
                .header("Content-Type", "application/json")
                .header(ATTESTATION_GATEWAY_HEADER, jwt)
                .body(body.to_string())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(response["backupId"].is_string());
    // Should not contain backup payload or metadata
    assert!(response.get("backup").is_none());
    assert!(response.get("metadata").is_none());
    assert!(response.get("syncFactorToken").is_none());
}

#[tokio::test]
#[serial]
async fn test_verify_factor_with_ec_keypair() {
    let ((public_key, secret_key), create_response) =
        create_test_backup_with_keypair(b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    let challenge = get_verify_factor_keypair_challenge().await;
    let signature = sign_keypair_challenge(&secret_key, challenge["challenge"].as_str().unwrap());

    let response = send_post_request_with_bypass_attestation_token(
        "/v1/verify-factor",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key,
                "signature": signature,
            },
            "challengeToken": challenge["token"],
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(response["backupId"].is_string());
    assert!(response.get("backup").is_none());
    assert!(response.get("metadata").is_none());
}

#[tokio::test]
#[serial]
async fn test_verify_factor_with_invalid_token() {
    let ((public_key, secret_key), create_response) =
        create_test_backup_with_keypair(b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    let challenge = get_verify_factor_keypair_challenge().await;
    let signature = sign_keypair_challenge(&secret_key, challenge["challenge"].as_str().unwrap());

    let response = send_post_request_with_bypass_attestation_token(
        "/v1/verify-factor",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key,
                "signature": signature,
            },
            "challengeToken": "INVALID_TOKEN",
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["error"]["code"], "jwt_error");
}

#[tokio::test]
#[serial]
async fn test_verify_factor_with_nonexistent_keypair() {
    let (public_key, secret_key) = common::generate_keypair();

    let challenge = get_verify_factor_keypair_challenge().await;
    let signature = sign_keypair_challenge(&secret_key, challenge["challenge"].as_str().unwrap());

    let response = send_post_request_with_bypass_attestation_token(
        "/v1/verify-factor",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key,
                "signature": signature,
            },
            "challengeToken": challenge["token"],
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["error"]["code"], "backup_untraceable");
}

/// Sync factors should not be usable with verify_factor (requires Main scope)
#[tokio::test]
#[serial]
async fn test_verify_factor_rejects_sync_factor() {
    let ((_, _), create_response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    let challenge = get_verify_factor_keypair_challenge().await;
    let sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());
    let signature =
        sign_keypair_challenge(&sync_secret_key, challenge["challenge"].as_str().unwrap());

    let response = send_post_request_with_bypass_attestation_token(
        "/v1/verify-factor",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge["token"],
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["error"]["code"], "backup_untraceable");
}

/// A retrieve challenge token should not be accepted by verify_factor (wrong context)
#[tokio::test]
#[serial]
async fn test_verify_factor_rejects_retrieve_challenge_context() {
    let ((public_key, secret_key), create_response) =
        create_test_backup_with_keypair(b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    // Get a *retrieve* challenge instead of a verify-factor challenge
    let retrieve_challenge = common::get_keypair_retrieval_challenge().await;
    let signature = sign_keypair_challenge(
        &secret_key,
        retrieve_challenge["challenge"].as_str().unwrap(),
    );

    let response = send_post_request_with_bypass_attestation_token(
        "/v1/verify-factor",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key,
                "signature": signature,
            },
            "challengeToken": retrieve_challenge["token"],
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["error"]["code"], "invalid_challenge_context");
}
