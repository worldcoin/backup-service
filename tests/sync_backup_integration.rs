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
    let challenge_response =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
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
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "fileList": [],
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
    let challenge_response =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
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
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": wrong_signature,
            },
            "challengeToken": challenge_response["token"],
            "fileList": [],
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

#[tokio::test]
async fn test_sync_backup_with_file_list_happy_path() {
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupId"].as_str().unwrap();

    let challenge_response =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
    let challenge_response_body = challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response: serde_json::Value =
        serde_json::from_slice(&challenge_response_body).unwrap();

    let sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());
    let signature = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "fileList": ["cksum:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
        }),
        Bytes::from(b"UPDATED BACKUP WITH FILES".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["backupId"], backup_id);

    verify_s3_backup_exists(backup_id, b"UPDATED BACKUP WITH FILES").await;
}

#[tokio::test]
async fn test_sync_backup_prevents_accidental_file_removal() {
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let _backup_id = response["backupId"].as_str().unwrap();

    let challenge_response =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
    let challenge_response_body = challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response: serde_json::Value =
        serde_json::from_slice(&challenge_response_body).unwrap();

    let sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());
    let signature = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key.clone(),
                "signature": signature.clone(),
            },
            "challengeToken": challenge_response["token"],
            "fileList": ["cksum:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "cksum:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"],
        }),
        Bytes::from(b"FIRST UPDATE WITH TWO FILES".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let challenge_response2 =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
    let challenge_response_body2 = challenge_response2
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response2: serde_json::Value =
        serde_json::from_slice(&challenge_response_body2).unwrap();

    let signature2 = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response2["challenge"].as_str().unwrap(),
    );

    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature2,
            },
            "challengeToken": challenge_response2["token"],
            "fileList": ["cksum:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
        }),
        Bytes::from(b"SECOND UPDATE MISSING A FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error_response["error"]["code"], "file_loss_prevention");
}

#[tokio::test]
async fn test_sync_backup_allows_explicit_file_removal() {
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupId"].as_str().unwrap();

    let challenge_response =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
    let challenge_response_body = challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response: serde_json::Value =
        serde_json::from_slice(&challenge_response_body).unwrap();

    let sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());
    let signature = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key.clone(),
                "signature": signature.clone(),
            },
            "challengeToken": challenge_response["token"],
            "fileList": [
                "cksum:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "cksum:0000000000000000000000000000000000000000000000000000000000000000"
            ],
        }),
        Bytes::from(b"FIRST UPDATE WITH TWO FILES".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let challenge_response2 =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
    let challenge_response_body2 = challenge_response2
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response2: serde_json::Value =
        serde_json::from_slice(&challenge_response_body2).unwrap();

    let signature2 = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response2["challenge"].as_str().unwrap(),
    );

    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature2,
            },
            "challengeToken": challenge_response2["token"],
            "fileList": ["cksum:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
            "filesToRemove": ["cksum:0000000000000000000000000000000000000000000000000000000000000000"],
        }),
        Bytes::from(b"SECOND UPDATE WITH EXPLICIT REMOVAL".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["backupId"], backup_id);

    verify_s3_backup_exists(backup_id, b"SECOND UPDATE WITH EXPLICIT REMOVAL").await;
}

#[tokio::test]
async fn test_sync_backup_maintains_file_list_when_unchanged() {
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupId"].as_str().unwrap();

    let challenge_response =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
    let challenge_response_body = challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response: serde_json::Value =
        serde_json::from_slice(&challenge_response_body).unwrap();

    let sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());
    let signature = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key.clone(),
                "signature": signature.clone(),
            },
            "challengeToken": challenge_response["token"],
            "fileList": ["cksum:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
        }),
        Bytes::from(b"FIRST UPDATE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let challenge_response2 =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
    let challenge_response_body2 = challenge_response2
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response2: serde_json::Value =
        serde_json::from_slice(&challenge_response_body2).unwrap();

    let signature2 = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response2["challenge"].as_str().unwrap(),
    );

    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature2,
            },
            "challengeToken": challenge_response2["token"],
            "fileList": ["cksum:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
        }),
        Bytes::from(b"SECOND UPDATE WITH SAME FILES".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["backupId"], backup_id);

    verify_s3_backup_exists(backup_id, b"SECOND UPDATE WITH SAME FILES").await;
}

#[tokio::test]
async fn test_sync_backup_rejects_empty_file_list_after_files_added() {
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let _backup_id = response["backupId"].as_str().unwrap();

    let challenge_response =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
    let challenge_response_body = challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response: serde_json::Value =
        serde_json::from_slice(&challenge_response_body).unwrap();

    let sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());
    let signature = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key.clone(),
                "signature": signature.clone(),
            },
            "challengeToken": challenge_response["token"],
            "fileList": ["cksum:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
        }),
        Bytes::from(b"FIRST UPDATE WITH A FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let challenge_response2 =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
    let challenge_response_body2 = challenge_response2
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response2: serde_json::Value =
        serde_json::from_slice(&challenge_response_body2).unwrap();

    let signature2 = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response2["challenge"].as_str().unwrap(),
    );

    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature2,
            },
            "challengeToken": challenge_response2["token"],
            "fileList": [],
        }),
        Bytes::from(b"SECOND UPDATE WITH NO FILES".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error_response["error"]["code"], "file_loss_prevention");
}

#[tokio::test]
async fn test_sync_backup_rejects_invalid_checksum_format() {
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let _backup_id = response["backupId"].as_str().unwrap();

    let challenge_response =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
    let challenge_response_body = challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response: serde_json::Value =
        serde_json::from_slice(&challenge_response_body).unwrap();

    let sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());
    let signature = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Test with missing cksum: prefix
    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key.clone(),
                "signature": signature.clone(),
            },
            "challengeToken": challenge_response["token"],
            "fileList": ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
        }),
        Bytes::from(b"UPDATE WITH INVALID FORMAT".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Get another challenge for the next test
    let challenge_response2 =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
    let challenge_response_body2 = challenge_response2
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response2: serde_json::Value =
        serde_json::from_slice(&challenge_response_body2).unwrap();

    let signature2 = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response2["challenge"].as_str().unwrap(),
    );

    // Test with invalid checksum length (32 chars instead of 64)
    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key.clone(),
                "signature": signature2.clone(),
            },
            "challengeToken": challenge_response2["token"],
            "fileList": ["cksum:0123456789abcdef0123456789abcdef"],
        }),
        Bytes::from(b"UPDATE WITH SHORT CHECKSUM".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Get another challenge for the next test
    let challenge_response3 =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
    let challenge_response_body3 = challenge_response3
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response3: serde_json::Value =
        serde_json::from_slice(&challenge_response_body3).unwrap();

    let signature3 = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response3["challenge"].as_str().unwrap(),
    );

    // Test with non-hex characters in checksum
    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key.clone(),
                "signature": signature3.clone(),
            },
            "challengeToken": challenge_response3["token"],
            "fileList": ["cksum:ZZZZ456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
        }),
        Bytes::from(b"UPDATE WITH NON-HEX CHECKSUM".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Get another challenge for the next test
    let challenge_response4 =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
    let challenge_response_body4 = challenge_response4
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response4: serde_json::Value =
        serde_json::from_slice(&challenge_response_body4).unwrap();

    let signature4 = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response4["challenge"].as_str().unwrap(),
    );

    // Test with uppercase hex (should work due to lowercasing)
    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature4,
            },
            "challengeToken": challenge_response4["token"],
            "fileList": ["CKSUM:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"],
        }),
        Bytes::from(b"UPDATE WITH UPPERCASE".as_slice()),
        None,
    )
    .await;

    // Should succeed because the function lowercases the input
    assert_eq!(response.status(), StatusCode::OK);
}
