mod common;

use crate::common::{
    create_test_backup_with_sync_keypair, make_sync_factor, sign_keypair_challenge,
    verify_s3_backup_exists, verify_s3_metadata_exists,
};
use axum::body::Bytes;
use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::json;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::time::timeout;

// Happy path - update backup file with a sync factor
#[tokio::test]
async fn test_sync_backup_happy_path() {
    // Create a backup with a keypair and get the sync factor secret key
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    // Extract the backup ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupMetadata"]["id"].as_str().unwrap();

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
            "currentManifestHash": "0101010101010101010101010101010101010101010101010101010101010101",
            "newManifestHash": "0202020202020202020202020202020202020202020202020202020202020202",
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
    let _backup_id = response["backupMetadata"]["id"].as_str().unwrap();

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
            "currentManifestHash": "0101010101010101010101010101010101010101010101010101010101010101",
            "newManifestHash": "0202020202020202020202020202020202020202020202020202020202020202",
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

/// Test with incorrect current manifest hash - should fail with conflict error
///
/// A client can only update the backup from the immediate current state. This protection is added so the client can have confidence
/// on its updates.
#[tokio::test]
async fn test_sync_backup_with_wrong_current_manifest_hash() {
    // Create a backup with a keypair and get the sync factor secret key
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    // Get the backup ID
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupMetadata"]["id"].as_str().unwrap();

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

    // Try to sync the backup with wrong current manifest hash
    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "currentManifestHash": "1111111111111111111111111111111111111111111111111111111111111111", // Wrong hash
            "newManifestHash": "0202020202020202020202020202020202020202020202020202020202020202",
        }),
        Bytes::from(b"UPDATED BACKUP".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error_response["error"]["code"], "manifest_hash_mismatch");

    // Verify the backup content hasn't been updated (still contains original content)
    verify_s3_backup_exists(backup_id, b"INITIAL BACKUP").await;

    // Verify the manifest hash hasn't been updated (still contains original manifest hash)
    let metadata = verify_s3_metadata_exists(backup_id).await;
    assert_eq!(metadata["manifestHash"], hex::encode([1u8; 32])); // The original manifest hash from create_test_backup_with_sync_keypair
}

// Test with invalid manifest hash format - should fail with validation error
#[tokio::test]
async fn test_sync_backup_with_invalid_manifest_hash_format() {
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

    // Sign the challenge with the sync factor secret key
    let sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());
    let signature = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Try to sync the backup with invalid manifest hash format (too short)
    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "currentManifestHash": "invalid_hash", // Invalid format
            "newManifestHash": "0202020202020202020202020202020202020202020202020202020202020202",
        }),
        Bytes::from(b"UPDATED BACKUP".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error_response["error"]["code"], "invalid_payload");
}

/// Test that concurrent backup updates are prevented by Redis lock
/// One should succeed, the other should fail with "update_in_progress" conflict
#[tokio::test]
async fn test_concurrent_sync_backup_prevention() {
    // Create a backup with a sync keypair
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    // Extract the backup ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupMetadata"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Counter for tracking results
    let success_count = Arc::new(AtomicU32::new(0));
    let conflict_count = Arc::new(AtomicU32::new(0));

    // Spawn 2 concurrent sync operations
    let mut handles = Vec::new();

    for i in 0..2 {
        let backup_id = backup_id.clone();
        let sync_secret_key = sync_secret_key.clone();
        let success_count = Arc::clone(&success_count);
        let conflict_count = Arc::clone(&conflict_count);

        let handle = tokio::spawn(async move {
            // Get a fresh sync challenge for each operation
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

            // Both operations use the same manifest hash to test the lock mechanism
            let response = common::send_post_request_with_multipart(
                "/v1/sync",
                json!({
                    "authorization": {
                        "kind": "EC_KEYPAIR",
                        "publicKey": sync_public_key,
                        "signature": signature,
                    },
                    "challengeToken": challenge_response["token"],
                    "currentManifestHash": "0101010101010101010101010101010101010101010101010101010101010101",
                    "newManifestHash": format!("{:0>64}", format!("0{}", i + 2)),
                }),
                Bytes::from(format!("UPDATED BACKUP {}", i).into_bytes()),
                None,
            )
            .await;

            match response.status() {
                StatusCode::OK => {
                    let body = response.into_body().collect().await.unwrap().to_bytes();
                    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(response["backupId"], backup_id);
                    success_count.fetch_add(1, Ordering::SeqCst);
                }
                StatusCode::LOCKED => {
                    let body = response.into_body().collect().await.unwrap().to_bytes();
                    let error_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    let error_code = error_response["error"]["code"].as_str().unwrap_or("");

                    // Expected conflict codes: conflicting_lock
                    if error_code == "conflicting_lock" {
                        conflict_count.fetch_add(1, Ordering::SeqCst);
                    } else {
                        panic!("Unexpected conflict error code: {}", error_code);
                    }
                }
                status => {
                    let body = response.into_body().collect().await.unwrap().to_bytes();
                    panic!(
                        "Unexpected status {}: {}",
                        status,
                        String::from_utf8_lossy(&body)
                    );
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all operations to complete
    let _join_results = timeout(
        std::time::Duration::from_secs(10),
        futures::future::try_join_all(handles),
    )
    .await
    .expect("Concurrent operations timed out")
    .expect("One or more operations failed");

    let successes = success_count.load(Ordering::SeqCst);
    let conflicts = conflict_count.load(Ordering::SeqCst);

    // Exactly one operation should succeed, the other should be rejected
    assert_eq!(successes, 1, "Expected exactly one operation to succeed");
    assert_eq!(
        conflicts, 1,
        "Expected exactly one operation to fail with conflict"
    );
}

/// Test that after a lock is released, subsequent operations can succeed
#[tokio::test]
async fn test_lock_release_allows_subsequent_operations() {
    // Create a backup with a sync keypair
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    // Extract the backup ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupMetadata"]["id"].as_str().unwrap();

    // First sync operation
    let challenge_response1 =
        common::send_post_request("/v1/sync/challenge/keypair", json!({})).await;
    let challenge_response_body1 = challenge_response1
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response1: serde_json::Value =
        serde_json::from_slice(&challenge_response_body1).unwrap();

    let sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());
    let signature1 = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response1["challenge"].as_str().unwrap(),
    );

    let response1 = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature1,
            },
            "challengeToken": challenge_response1["token"],
            "currentManifestHash": "0101010101010101010101010101010101010101010101010101010101010101",
            "newManifestHash": "0202020202020202020202020202020202020202020202020202020202020202",
        }),
        Bytes::from(b"UPDATED BACKUP 1".as_slice()),
        None,
    )
    .await;

    // First operation should succeed
    assert_eq!(response1.status(), StatusCode::OK);
    let body1 = response1.into_body().collect().await.unwrap().to_bytes();
    let response1: serde_json::Value = serde_json::from_slice(&body1).unwrap();
    assert_eq!(response1["backupId"], backup_id);

    // Second sync operation (should succeed after first lock is released)
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

    let response2 = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature2,
            },
            "challengeToken": challenge_response2["token"],
            "currentManifestHash": "0202020202020202020202020202020202020202020202020202020202020202",
            "newManifestHash": "0303030303030303030303030303030303030303030303030303030303030303",
        }),
        Bytes::from(b"UPDATED BACKUP 2".as_slice()),
        None,
    )
    .await;

    // Second operation should also succeed
    assert_eq!(response2.status(), StatusCode::OK);
    let body2 = response2.into_body().collect().await.unwrap().to_bytes();
    let response2: serde_json::Value = serde_json::from_slice(&body2).unwrap();
    assert_eq!(response2["backupId"], backup_id);

    // Verify the final backup content
    verify_s3_backup_exists(backup_id, b"UPDATED BACKUP 2").await;
}

#[tokio::test]
async fn test_sync_backup_with_large_file() {
    // Create a backup with a keypair and get the sync factor secret key
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    // Extract the backup ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let _backup_id = response["backupMetadata"]["id"].as_str().unwrap();

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

    // Sync the backup with a file that's too large (15 MB + 1 byte)
    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "currentManifestHash": "0101010101010101010101010101010101010101010101010101010101010101",
            "newManifestHash": "0202020202020202020202020202020202020202020202020202020202020202",
        }),
        Bytes::from(vec![0; 15 * 1024 * 1024 + 1]), // 15 MB + 1 byte
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "backup_file_too_large",
                "message": "Backup file too large",
            },
        })
    );
}

/// We test the header parser works as expected using the bona-fide `Content-Length`.
///
/// This is useful because Axum will truncate the multipart data if it exceeds the safety
/// max length, and an esoteric error gets returned to the user.
#[tokio::test]
async fn test_sync_backup_with_extremely_large_file() {
    // Create a backup with a keypair and get the sync factor secret key
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    // Extract the backup ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let _backup_id = response["backupMetadata"]["id"].as_str().unwrap();

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

    // Sync the backup with a file that's too large (15 MB + 1 byte)
    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "currentManifestHash": "0101010101010101010101010101010101010101010101010101010101010101",
            "newManifestHash": "0202020202020202020202020202020202020202020202020202020202020202",
        }),
        Bytes::from(vec![0; 30 * 1024 * 1024]), // 30 MB is way past the safety limit
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "backup_file_too_large",
                "message": "Backup file too large",
            },
        })
    );
}
