mod common;

use crate::common::{
    authenticate_with_passkey_challenge, create_test_backup, get_passkey_challenge,
    get_passkey_retrieval_challenge, make_credential_from_passkey_challenge, send_post_request,
};
use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::json;

#[tokio::test]
async fn test_retrieve_backup() {
    let mut passkey_client = common::get_mock_passkey_client();

    // Create a backup
    let (_, create_response) = create_test_backup(&mut passkey_client, b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    // Get a new challenge for retrieving the backup
    let retrieve_challenge = get_passkey_retrieval_challenge().await;

    // Solve the challenge with the same credential
    let retrieve_credential =
        authenticate_with_passkey_challenge(&mut passkey_client, &retrieve_challenge).await;

    // Retrieve the backup using the solved challenge
    let retrieve_response = send_post_request(
        "/retrieve/from-challenge",
        json!({
            "solvedChallenge": {
                "kind": "PASSKEY",
                "credential": retrieve_credential,
            },
            "challengeToken": retrieve_challenge["token"],
        }),
    )
    .await;

    assert_eq!(retrieve_response.status(), StatusCode::OK);

    let body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify we got back a backup and metadata
    assert!(response["backup"].is_string());
    assert!(response["metadata"].is_object());

    // Decode and verify the backup data
    let backup_base64 = response["backup"].as_str().unwrap();
    let backup_bytes = STANDARD.decode(backup_base64).unwrap();
    assert_eq!(backup_bytes, b"TEST BACKUP DATA");

    // Verify the metadata contains expected fields
    let metadata = &response["metadata"];
    assert_eq!(metadata["turnkeyAccountId"], json!(null));
}

#[tokio::test]
async fn test_retrieve_backup_with_incorrect_token() {
    let mut passkey_client = common::get_mock_passkey_client();

    // Create a backup first
    let (_, create_response) = create_test_backup(&mut passkey_client, b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    // Get a retrieve challenge
    let retrieve_challenge = get_passkey_retrieval_challenge().await;

    // Solve the challenge with the same credential
    let retrieve_credential =
        authenticate_with_passkey_challenge(&mut passkey_client, &retrieve_challenge).await;

    // Attempt to retrieve the backup using an incorrect token
    let retrieve_response = send_post_request(
        "/retrieve/from-challenge",
        json!({
            "solvedChallenge": {
                "kind": "PASSKEY",
                "credential": retrieve_credential,
            },
            "challengeToken": "INCORRECT TOKEN",
        }),
    )
    .await;

    assert_eq!(retrieve_response.status(), StatusCode::BAD_REQUEST);

    let body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(response, json!({"error": "jwt_error"}));
}

#[tokio::test]
async fn test_retrieve_backup_with_incorrectly_solved_challenge() {
    let mut passkey_client = common::get_mock_passkey_client();

    // Create a backup first
    let (_, create_response) = create_test_backup(&mut passkey_client, b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    // Get a retrieve challenge
    let retrieve_challenge = get_passkey_retrieval_challenge().await;

    // Solve the challenge with the same credential
    let mut retrieve_credential =
        authenticate_with_passkey_challenge(&mut passkey_client, &retrieve_challenge).await;

    // Tamper with the credential response
    retrieve_credential["response"]["clientDataJSON"][10] = json!(
        retrieve_credential["response"]["clientDataJSON"][10]
            .as_u64()
            .unwrap()
            + 1
    );

    // Attempt to retrieve the backup using the tampered credential
    let retrieve_response = send_post_request(
        "/retrieve/from-challenge",
        json!({
            "solvedChallenge": {
                "kind": "PASSKEY",
                "credential": retrieve_credential,
            },
            "challengeToken": retrieve_challenge["token"],
        }),
    )
    .await;

    assert_eq!(retrieve_response.status(), StatusCode::BAD_REQUEST);

    let body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(response, json!({"error": "webauthn_error"}));
}

#[tokio::test]
async fn test_retrieve_backup_with_nonexistent_credential() {
    let mut passkey_client_1 = common::get_mock_passkey_client();
    let mut passkey_client_2 = common::get_mock_passkey_client();

    // Create backup for first client
    let (_, create_response) = create_test_backup(&mut passkey_client_1, b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    // For the second client, register a credential but do not create a backup
    let challenge_response = get_passkey_challenge().await;
    make_credential_from_passkey_challenge(&mut passkey_client_2, &challenge_response).await;

    // Get a retrieve challenge
    let retrieve_challenge = get_passkey_retrieval_challenge().await;

    // Solve the challenge with the second client (which has no associated backup)
    let retrieve_credential =
        authenticate_with_passkey_challenge(&mut passkey_client_2, &retrieve_challenge).await;

    // Attempt to retrieve a backup that doesn't exist
    let retrieve_response = send_post_request(
        "/retrieve/from-challenge",
        json!({
            "solvedChallenge": {
                "kind": "PASSKEY",
                "credential": retrieve_credential,
            },
            "challengeToken": retrieve_challenge["token"],
        }),
    )
    .await;

    assert_eq!(retrieve_response.status(), StatusCode::BAD_REQUEST);
    let body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response, json!({"error": "webauthn_error"}));
}
