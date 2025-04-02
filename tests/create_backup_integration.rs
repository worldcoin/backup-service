mod common;

use crate::common::{
    get_passkey_challenge, make_credential_from_passkey_challenge, send_post_request,
};
use axum::http::StatusCode;
use http_body_util::BodyExt;
use serde_json::json;

#[tokio::test]
async fn test_create_backup() {
    let mut passkey_client = common::get_mock_passkey_client();

    // Get a challenge from the server
    let challenge_response = get_passkey_challenge().await;

    // Register a credential by solving the challenge
    let credential =
        make_credential_from_passkey_challenge(&mut passkey_client, &challenge_response).await;

    // Send the credential to the server to create a backup
    let response = send_post_request(
        "/create",
        json!({
            "solvedChallenge": {
                "kind": "PASSKEY",
                "credential": credential,
            },
            "challengeToken": challenge_response["token"],
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(response, json!({}));

    // TODO/FIXME: Check that backup was successfully created on S3
}

#[tokio::test]
async fn test_create_backup_with_incorrect_token() {
    let mut passkey_client = common::get_mock_passkey_client();

    // Get a challenge from the server
    let challenge_response = get_passkey_challenge().await;

    // Register a credential by solving the challenge
    let credential =
        make_credential_from_passkey_challenge(&mut passkey_client, &challenge_response).await;

    // Send the credential to the server to create a backup
    let response = send_post_request(
        "/create",
        json!({
            "solvedChallenge": {
                "kind": "PASSKEY",
                "credential": credential,
            },
            "challengeToken": "INCORRECT TOKEN",
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(response, json!({"error": "jwt_error"}));
}

#[tokio::test]
async fn test_create_backup_with_incorrectly_solved_challenge() {
    let mut passkey_client = common::get_mock_passkey_client();

    // Get a challenge from the server
    let challenge_response = get_passkey_challenge().await;

    // Register a credential by solving the challenge
    let credential =
        make_credential_from_passkey_challenge(&mut passkey_client, &challenge_response).await;

    // Flip a bit in response.clientDataJSON that looks like [145, 64, ...]
    let mut credential: serde_json::Value = serde_json::from_value(credential).unwrap();
    credential["response"]["clientDataJSON"][10] = json!(
        credential["response"]["clientDataJSON"][10]
            .as_u64()
            .unwrap()
            + 1
    );

    // Send the credential to the server to create a backup
    let response = send_post_request(
        "/create",
        json!({
            "solvedChallenge": {
                "kind": "PASSKEY",
                "credential": credential,
            },
            "challengeToken": challenge_response["token"],
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(response, json!({"error": "webauthn_error"}));
}
