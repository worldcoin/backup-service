mod common;

use crate::common::{
    get_passkey_challenge, get_test_s3_client, make_credential_from_passkey_challenge,
    send_post_request_with_multipart,
};
use axum::body::Bytes;
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

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(response, json!({}));

    // Check that backup was successfully created on S3
    let s3_client = get_test_s3_client().await;
    let bucket_name = "backup-service-bucket";
    let backup_key = format!("{}/backup", credential["id"].as_str().unwrap());
    let backup = s3_client
        .get_object()
        .bucket(bucket_name)
        .key(&backup_key)
        .send()
        .await
        .unwrap();
    let backup = backup.body.collect().await.unwrap().to_vec();
    assert_eq!(backup, b"TEST FILE".as_slice());

    // Check that metadata was successfully created on S3
    let metadata_key = format!("{}/metadata", credential["id"].as_str().unwrap());
    let metadata = s3_client
        .get_object()
        .bucket(bucket_name)
        .key(&metadata_key)
        .send()
        .await
        .unwrap();
    let metadata = metadata.body.collect().await.unwrap().to_vec();
    let metadata: serde_json::Value = serde_json::from_slice(&metadata).unwrap();
    assert_eq!(metadata["primaryFactor"]["kind"]["kind"], "PASSKEY");
    assert_eq!(
        metadata["primaryFactor"]["kind"]["webauthnCredential"]["cred"]["cred_id"],
        credential["id"]
    );
    assert_eq!(metadata["oidcAccounts"], json!([]));
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
    let response = send_post_request_with_multipart(
        "/create",
        json!({
            "solvedChallenge": {
                "kind": "PASSKEY",
                "credential": credential,
            },
            "challengeToken": "INCORRECT TOKEN",
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
        }),
        Bytes::from(b"TEST FILE".as_slice()),
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

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(response, json!({"error": "webauthn_error"}));
}

#[tokio::test]
async fn test_create_backup_with_empty_file() {
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
        Bytes::from(b"".as_slice()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(response, json!({"error": "empty_backup_file"}));
}

#[tokio::test]
async fn test_create_backup_with_large_file() {
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
        Bytes::from(vec![0; 5 * 1024 * 1024 + 1]), // 5 MB file + 1 byte
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(response, json!({"error": "backup_file_too_large"}));
}
