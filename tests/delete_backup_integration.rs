mod common;

use crate::common::{
    create_test_backup_with_sync_keypair, generate_keypair, send_post_request,
    sign_keypair_challenge, verify_s3_metadata_exists,
};
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::error::SdkError;
use axum::http::StatusCode;
use backup_service::factor_lookup::{FactorLookup, FactorScope, FactorToLookup};
use backup_service::types::Environment;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::json;
use std::sync::Arc;

/// Helper function to get a delete backup challenge
async fn get_delete_backup_challenge() -> serde_json::Value {
    let challenge_response =
        send_post_request("/v1/delete-backup/challenge/keypair", json!({})).await;
    assert_eq!(challenge_response.status(), StatusCode::OK);
    let challenge_body = challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    serde_json::from_slice(&challenge_body).unwrap()
}

/// Helper function to verify backup was deleted by checking S3
async fn verify_backup_deleted(backup_id: &str) {
    let s3_client = common::get_test_s3_client().await;
    let bucket_name = "backup-service-bucket";
    let metadata_key = format!("{}/metadata", backup_id);

    let metadata_result = s3_client
        .get_object()
        .bucket(bucket_name)
        .key(&metadata_key)
        .send()
        .await;

    // Should return a NoSuchKey error
    assert!(metadata_result.is_err());
    match metadata_result {
        Err(SdkError::ServiceError(err)) => {
            assert_eq!(err.err().code(), Some("NoSuchKey"));
        }
        _ => panic!("Expected NoSuchKey error"),
    }

    let backup_key = format!("{}/backup", backup_id);
    let backup_result = s3_client
        .get_object()
        .bucket(bucket_name)
        .key(&backup_key)
        .send()
        .await;

    assert!(backup_result.is_err());
    match backup_result {
        Err(SdkError::ServiceError(err)) => {
            assert_eq!(err.err().code(), Some("NoSuchKey"));
        }
        _ => panic!("Expected NoSuchKey error"),
    }
}

/// Happy path - successfully delete a backup using a sync factor
#[tokio::test]
async fn test_delete_backup_happy_path() {
    // Setup test environment
    dotenvy::from_path(".env.example").ok();
    let environment = Environment::development(None);
    let dynamodb_client = Arc::new(aws_sdk_dynamodb::Client::new(
        &environment.aws_config().await,
    ));
    let factor_lookup = FactorLookup::new(environment, dynamodb_client.clone());

    // Create a backup with a sync keypair
    let ((main_public_key, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"TEST BACKUP DATA").await;

    // Extract the backup ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let create_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    tracing::info!("create_response: {:?}", create_response);
    let backup_id = create_response["backupId"].as_str().unwrap();

    // Verify backup exists before deletion
    let _metadata = verify_s3_metadata_exists(backup_id).await;

    // Extract factor information to verify they exist in DynamoDB
    let main_factor = FactorToLookup::from_ec_keypair(main_public_key);
    let sync_public_key_str = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());
    let sync_factor = FactorToLookup::from_ec_keypair(sync_public_key_str.clone());

    // Verify factors exist in DynamoDB before deletion
    assert!(factor_lookup
        .lookup(FactorScope::Main, &main_factor)
        .await
        .unwrap()
        .is_some());
    assert!(factor_lookup
        .lookup(FactorScope::Sync, &sync_factor)
        .await
        .unwrap()
        .is_some());

    // Get a delete backup challenge
    let challenge_response = get_delete_backup_challenge().await;

    // Sign the challenge with the sync factor secret key
    let signature = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Delete the backup
    let delete_response = send_post_request(
        "/v1/delete-backup",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key_str,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
        }),
    )
    .await;

    // Verify the response
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    // Verify the backup was deleted
    verify_backup_deleted(backup_id).await;

    // Verify all factors were deleted from DynamoDB
    assert!(factor_lookup
        .lookup(FactorScope::Main, &main_factor)
        .await
        .unwrap()
        .is_none());
    assert!(factor_lookup
        .lookup(FactorScope::Sync, &sync_factor)
        .await
        .unwrap()
        .is_none());
}

/// Failure case - incorrectly signed request
#[tokio::test]
async fn test_delete_backup_with_incorrect_signature() {
    // Create a backup with a sync keypair
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"TEST BACKUP DATA").await;

    // Extract the backup ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let create_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = create_response["backupMetadata"]["id"].as_str().unwrap();

    // Get a delete backup challenge
    let challenge_response = get_delete_backup_challenge().await;

    // Sign the challenge with a different keypair (incorrect signature)
    let (_, wrong_secret_key) = generate_keypair();
    let sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());
    let wrong_signature = sign_keypair_challenge(
        &wrong_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Attempt to delete the backup with wrong signature
    let delete_response = send_post_request(
        "/v1/delete-backup",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": wrong_signature,
            },
            "challengeToken": challenge_response["token"],
        }),
    )
    .await;

    assert_eq!(delete_response.status(), StatusCode::BAD_REQUEST);
    let error_body = delete_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&error_body).unwrap();
    assert_eq!(
        error_response["error"]["code"].as_str().unwrap(),
        "signature_verification_error"
    );

    // Verify the backup still exists
    let _metadata = verify_s3_metadata_exists(backup_id).await;
}

/// Failure case - trying with a main factor instead of sync factor
#[tokio::test]
async fn test_delete_backup_with_main_factor() {
    // Create a backup with a main keypair (not sync)
    let ((main_public_key, main_secret_key), response) =
        common::create_test_backup_with_keypair(b"TEST BACKUP DATA").await;

    // Extract the backup ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let create_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = create_response["backupMetadata"]["id"].as_str().unwrap();

    // Get a delete backup challenge
    let challenge_response = get_delete_backup_challenge().await;

    // Sign the challenge with the main factor (should fail)
    let signature = sign_keypair_challenge(
        &main_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Attempt to delete the backup with main factor
    let delete_response = send_post_request(
        "/v1/delete-backup",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": main_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
        }),
    )
    .await;

    assert_eq!(delete_response.status(), StatusCode::BAD_REQUEST);

    // Verify the backup still exists
    let _metadata = verify_s3_metadata_exists(backup_id).await;
}

/// Failure case - non-existent backup (using a sync factor not associated with any backup)
#[tokio::test]
async fn test_delete_backup_with_non_existent_backup() {
    // Generate a keypair that's not associated with any backup
    let (non_existent_public_key, non_existent_secret_key) = generate_keypair();

    // Get a delete backup challenge
    let challenge_response = get_delete_backup_challenge().await;

    // Sign the challenge with the non-existent keypair
    let signature = sign_keypair_challenge(
        &non_existent_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Attempt to delete a backup with non-existent factor
    let delete_response = send_post_request(
        "/v1/delete-backup",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": non_existent_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
        }),
    )
    .await;

    // Should fail with bad request (backup not found)
    assert_eq!(delete_response.status(), StatusCode::BAD_REQUEST);
    let error_body = delete_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&error_body).unwrap();
    assert_eq!(
        error_response["error"]["code"].as_str().unwrap(),
        "backup_untraceable"
    );
}

/// Test that challenge token cannot be reused (replay attack prevention)
#[tokio::test]
async fn test_delete_backup_challenge_token_reuse() {
    // Create a backup with a sync keypair
    let ((_, _), _, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"TEST BACKUP DATA").await;

    // Get a delete backup challenge
    let challenge_response = get_delete_backup_challenge().await;

    // Sign the challenge with the sync factor secret key
    let sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());
    let signature = sign_keypair_challenge(
        &sync_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // First delete attempt (should succeed)
    let delete_response = send_post_request(
        "/v1/delete-backup",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key.clone(),
                "signature": signature.clone(),
            },
            "challengeToken": challenge_response["token"],
        }),
    )
    .await;

    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    // Create another backup to test token reuse
    let ((_, _), _, sync_secret_key2) =
        create_test_backup_with_sync_keypair(b"TEST BACKUP DATA 2").await;

    // Try to reuse the same challenge token (should fail)
    let sync_public_key2 = STANDARD.encode(sync_secret_key2.public_key().to_sec1_bytes());
    let signature2 = sign_keypair_challenge(
        &sync_secret_key2,
        challenge_response["challenge"].as_str().unwrap(),
    );

    let reuse_response = send_post_request(
        "/v1/delete-backup",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key2,
                "signature": signature2,
            },
            "challengeToken": challenge_response["token"], // Reusing the same token
        }),
    )
    .await;

    // Should fail with bad request (token already used)
    assert_eq!(reuse_response.status(), StatusCode::BAD_REQUEST);
    let error_body = reuse_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&error_body).unwrap();
    assert_eq!(
        error_response["error"]["code"].as_str().unwrap(),
        "already_used"
    );
}
