mod common;

use crate::common::{
    create_test_backup_with_sync_keypair, make_sync_factor, sign_keypair_challenge,
    verify_s3_backup_exists,
};
use axum::body::Bytes;
use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::json;

// Happy path - update backup file with a sync factor
#[tokio::test]
async fn test_sync_backup_happy_path() {
    // Create a backup with a keypair and get the sync factor secret key
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    // Extract the backup ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupId"].as_str().unwrap();

    // Get a sync challenge
    let challenge_response = common::send_post_request("/sync/challenge/keypair", json!({})).await;
    let challenge_response_body = challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response: serde_json::Value =
        serde_json::from_slice(&challenge_response_body).unwrap();

    // Sign the challenge with the sync factor secret key
    let sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());
    let signature = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Sync the backup with new content
    let response = common::send_post_request_with_multipart(
        "/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
        }),
        Bytes::from(b"UPDATED BACKUP".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["backupId"], backup_id);

    // Verify the backup was updated in S3
    verify_s3_backup_exists(backup_id, b"UPDATED BACKUP").await;
}

// Test with incorrect authorization - should fail
#[tokio::test]
async fn test_sync_backup_with_incorrect_authorization() {
    // Create a backup with a keypair and get the sync factor secret key
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    // Get the backup ID
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let _backup_id = response["backupId"].as_str().unwrap();

    // Get a sync challenge
    let challenge_response = common::send_post_request("/sync/challenge/keypair", json!({})).await;
    let challenge_response_body = challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response: serde_json::Value =
        serde_json::from_slice(&challenge_response_body).unwrap();

    // Create a new sync factor - different from the one we used to create the backup
    let (_new_sync_factor, _, new_sync_secret_key) = make_sync_factor().await;

    // Use the correct public key from the original sync factor
    let sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());

    // But sign with the new sync factor secret key
    let wrong_signature = sign_keypair_challenge(
        &new_sync_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Try to sync the backup with signature from a different key
    let response = common::send_post_request_with_multipart(
        "/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": wrong_signature,
            },
            "challengeToken": challenge_response["token"],
        }),
        Bytes::from(b"UPDATED BACKUP".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        error_response["error"]["code"],
        "signature_verification_error"
    );
}
