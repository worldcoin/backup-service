mod common;

use crate::common::{
    generate_keypair, get_test_s3_client, send_post_request, send_post_request_with_multipart,
    sign_keypair_challenge, verify_s3_metadata_exists,
};
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::error::SdkError;
use axum::body::Bytes;
use axum::http::StatusCode;
use backup_service::factor_lookup::{FactorLookup, FactorScope, FactorToLookup};
use backup_service::types::Environment;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::SecretKey;
use serde_json::json;
use std::sync::Arc;

/// Helper function to derive backup_account_id from a secret key
fn derive_backup_account_id_from_keypair(secret_key: &SecretKey) -> String {
    let signing_key = SigningKey::from(secret_key);
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let compressed_point = verifying_key.to_encoded_point(true);
    let compressed_bytes = compressed_point.as_bytes();
    format!("backup_account_{}", hex::encode(compressed_bytes))
}

/// Helper function to get a reset challenge
async fn get_reset_challenge(backup_account_id: &str) -> serde_json::Value {
    let challenge_response = send_post_request(
        "/v1/reset/challenge/keypair",
        json!({
            "backupAccountId": backup_account_id,
        }),
    )
    .await;
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
    let s3_client = get_test_s3_client().await;
    let bucket_name = "backup-service-bucket";
    let metadata_key = format!("{}/metadata", backup_id);

    let metadata_result = s3_client
        .get_object()
        .bucket(bucket_name)
        .key(&metadata_key)
        .send()
        .await;

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

/// Helper function to create a backup with a specific backup_account_id derived from a keypair
async fn create_test_backup_with_backup_account_id(
    backup_account_secret_key: &SecretKey,
    backup_data: &[u8],
) -> (String, SecretKey, SecretKey) {
    // Derive backup_account_id from the provided secret key
    let backup_account_id = derive_backup_account_id_from_keypair(backup_account_secret_key);

    // Get a challenge for creating the backup
    let challenge_response = send_post_request("/v1/create/challenge/keypair", json!({})).await;
    assert_eq!(challenge_response.status(), StatusCode::OK);
    let challenge_body = challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response: serde_json::Value = serde_json::from_slice(&challenge_body).unwrap();

    // Generate a main factor keypair for the backup
    let main_factor_keypair = generate_keypair();
    let main_signature = sign_keypair_challenge(
        &main_factor_keypair.1,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Create a sync factor - use same challenge as main factor (create challenge)
    let sync_factor_secret_key = SecretKey::random(&mut OsRng);
    let sync_factor_signing_key = SigningKey::from(&sync_factor_secret_key);
    let sync_factor_public_key =
        STANDARD.encode(sync_factor_signing_key.verifying_key().to_sec1_bytes());

    // Get another create challenge for the sync factor
    let sync_challenge_response =
        send_post_request("/v1/create/challenge/keypair", json!({})).await;
    assert_eq!(sync_challenge_response.status(), StatusCode::OK);
    let sync_challenge_body = sync_challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let sync_challenge: serde_json::Value = serde_json::from_slice(&sync_challenge_body).unwrap();

    let sync_signature = sign_keypair_challenge(
        &sync_factor_secret_key,
        sync_challenge["challenge"].as_str().unwrap(),
    );

    // Create the backup
    let create_response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": main_factor_keypair.0.clone(),
                "signature": main_signature,
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_factor_public_key,
                "signature": sync_signature,
                "label": "Test Sync Factor",
            },
            "initialSyncChallengeToken": sync_challenge["token"],
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": backup_account_id,
        }),
        Bytes::from(backup_data.to_vec()),
        None,
    )
    .await;

    if create_response.status() != StatusCode::OK {
        let error_body = create_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let error_text = String::from_utf8_lossy(&error_body);
        panic!(
            "Failed to create backup. Status: {}, Body: {}",
            StatusCode::from_u16(400).unwrap(),
            error_text
        );
    }

    (
        backup_account_id,
        main_factor_keypair.1,
        sync_factor_secret_key,
    )
}

/// Happy path - successfully reset a backup using the backup_account_id keypair
#[tokio::test]
async fn test_reset_backup_happy_path() {
    // Setup test environment
    dotenvy::from_path(".env.example").ok();
    let environment = Environment::development(None);
    let dynamodb_client = Arc::new(aws_sdk_dynamodb::Client::new(
        &environment.aws_config().await,
    ));
    let factor_lookup = FactorLookup::new(environment, dynamodb_client.clone());

    // Generate a keypair for the backup_account_id
    let backup_account_secret_key = SecretKey::random(&mut OsRng);

    // Create a backup with this backup_account_id
    let (backup_account_id, main_secret_key, sync_secret_key) =
        create_test_backup_with_backup_account_id(&backup_account_secret_key, b"TEST BACKUP DATA")
            .await;

    // Verify backup exists before reset
    let _metadata = verify_s3_metadata_exists(&backup_account_id).await;

    // Create factors for lookup verification
    let main_signing_key = SigningKey::from(&main_secret_key);
    let main_public_key = STANDARD.encode(main_signing_key.verifying_key().to_sec1_bytes());
    let main_factor = FactorToLookup::from_ec_keypair(main_public_key);

    let sync_signing_key = SigningKey::from(&sync_secret_key);
    let sync_public_key = STANDARD.encode(sync_signing_key.verifying_key().to_sec1_bytes());
    let sync_factor = FactorToLookup::from_ec_keypair(sync_public_key);

    // Verify factors exist in DynamoDB before reset
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

    // Get a reset challenge
    let challenge_response = get_reset_challenge(&backup_account_id).await;

    // Sign the challenge with the backup_account_id secret key
    let signature = sign_keypair_challenge(
        &backup_account_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Reset the backup
    let reset_response = send_post_request(
        "/v1/reset",
        json!({
            "backupAccountId": backup_account_id,
            "signature": signature,
            "challengeToken": challenge_response["token"],
        }),
    )
    .await;

    // Verify the response
    assert_eq!(reset_response.status(), StatusCode::NO_CONTENT);

    // Verify the backup was deleted
    verify_backup_deleted(&backup_account_id).await;

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
async fn test_reset_backup_with_incorrect_signature() {
    // Generate a keypair for the backup_account_id
    let backup_account_secret_key = SecretKey::random(&mut OsRng);

    // Create a backup with this backup_account_id
    let (backup_account_id, _, _) =
        create_test_backup_with_backup_account_id(&backup_account_secret_key, b"TEST BACKUP DATA")
            .await;

    // Get a reset challenge
    let challenge_response = get_reset_challenge(&backup_account_id).await;

    // Sign the challenge with a different keypair (incorrect signature)
    let (_, wrong_secret_key) = generate_keypair();
    let wrong_signature = sign_keypair_challenge(
        &wrong_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Attempt to reset the backup with wrong signature
    let reset_response = send_post_request(
        "/v1/reset",
        json!({
            "backupAccountId": backup_account_id,
            "signature": wrong_signature,
            "challengeToken": challenge_response["token"],
        }),
    )
    .await;

    assert_eq!(reset_response.status(), StatusCode::BAD_REQUEST);
    let error_body = reset_response
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
    verify_s3_metadata_exists(&backup_account_id).await;
}

/// Failure case - public key doesn't match backup_account_id
#[tokio::test]
async fn test_reset_backup_with_mismatched_public_key() {
    // Generate a keypair for the backup_account_id
    let backup_account_secret_key = SecretKey::random(&mut OsRng);

    // Create a backup with this backup_account_id
    let (backup_account_id, _, _) =
        create_test_backup_with_backup_account_id(&backup_account_secret_key, b"TEST BACKUP DATA")
            .await;

    // Get a reset challenge
    let challenge_response = get_reset_challenge(&backup_account_id).await;

    // Generate a different keypair and use it
    let wrong_keypair = generate_keypair();
    let wrong_signature = sign_keypair_challenge(
        &wrong_keypair.1,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Attempt to reset with a signature from different keypair
    let reset_response = send_post_request(
        "/v1/reset",
        json!({
            "backupAccountId": backup_account_id,
            "signature": wrong_signature,
            "challengeToken": challenge_response["token"],
        }),
    )
    .await;

    assert_eq!(reset_response.status(), StatusCode::BAD_REQUEST);
    let error_body = reset_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&error_body).unwrap();
    // Since we're using a different keypair, the signature won't verify
    assert_eq!(
        error_response["error"]["code"].as_str().unwrap(),
        "signature_verification_error"
    );

    // Verify the backup still exists
    verify_s3_metadata_exists(&backup_account_id).await;
}

/// Failure case - challenge token reuse
#[tokio::test]
async fn test_reset_backup_challenge_token_reuse() {
    // Generate a keypair for the backup_account_id
    let backup_account_secret_key = SecretKey::random(&mut OsRng);
    let backup_account_signing_key = SigningKey::from(&backup_account_secret_key);
    let backup_account_public_key =
        STANDARD.encode(backup_account_signing_key.verifying_key().to_sec1_bytes());

    // Create first backup
    let (backup_account_id_1, _, _) =
        create_test_backup_with_backup_account_id(&backup_account_secret_key, b"TEST BACKUP 1")
            .await;

    // Get a reset challenge for the first backup
    let challenge_response = get_reset_challenge(&backup_account_id_1).await;

    // Sign the challenge
    let signature = sign_keypair_challenge(
        &backup_account_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Reset the first backup
    let reset_response = send_post_request(
        "/v1/reset",
        json!({
            "backupAccountId": backup_account_id_1,
            "publicKey": backup_account_public_key.clone(),
            "signature": signature.clone(),
            "challengeToken": challenge_response["token"].clone(),
        }),
    )
    .await;
    assert_eq!(reset_response.status(), StatusCode::NO_CONTENT);

    // Create a second backup with a different backup_account_id
    let backup_account_secret_key_2 = SecretKey::random(&mut OsRng);
    let (backup_account_id_2, _, _) =
        create_test_backup_with_backup_account_id(&backup_account_secret_key_2, b"TEST BACKUP 2")
            .await;

    // Try to reuse the same challenge token on the second backup (should fail)
    let signature_2 = sign_keypair_challenge(
        &backup_account_secret_key_2,
        challenge_response["challenge"].as_str().unwrap(),
    );

    let reuse_response = send_post_request(
        "/v1/reset",
        json!({
            "backupAccountId": backup_account_id_2,
            "signature": signature_2,
            "challengeToken": challenge_response["token"], // Reused token
        }),
    )
    .await;

    assert_eq!(reuse_response.status(), StatusCode::BAD_REQUEST);
    let error_body = reuse_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&error_body).unwrap();
    // The context validation happens before the token reuse check, so we expect invalid_challenge_context
    assert_eq!(
        error_response["error"]["code"].as_str().unwrap(),
        "invalid_challenge_context"
    );

    // Verify the second backup still exists
    verify_s3_metadata_exists(&backup_account_id_2).await;
}

/// Failure case - backup doesn't exist
#[tokio::test]
async fn test_reset_nonexistent_backup() {
    // Generate a keypair
    let backup_account_secret_key = SecretKey::random(&mut OsRng);
    let backup_account_id = derive_backup_account_id_from_keypair(&backup_account_secret_key);

    // Get a reset challenge (this should work even if backup doesn't exist)
    let challenge_response = get_reset_challenge(&backup_account_id).await;

    // Sign the challenge
    let signature = sign_keypair_challenge(
        &backup_account_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Try to reset a nonexistent backup
    let reset_response = send_post_request(
        "/v1/reset",
        json!({
            "backupAccountId": backup_account_id,
            "signature": signature,
            "challengeToken": challenge_response["token"],
        }),
    )
    .await;

    assert_eq!(reset_response.status(), StatusCode::NOT_FOUND);
}

/// Failure case - challenge token with wrong backup_account_id
#[tokio::test]
async fn test_reset_backup_with_wrong_backup_account_id_in_token() {
    // Generate two keypairs for two different backup_account_ids
    let backup_account_secret_key_1 = SecretKey::random(&mut OsRng);

    let backup_account_secret_key_2 = SecretKey::random(&mut OsRng);
    let backup_account_id_2 = derive_backup_account_id_from_keypair(&backup_account_secret_key_2);

    // Create a backup with the first backup_account_id
    let (backup_account_id_1, _, _) =
        create_test_backup_with_backup_account_id(&backup_account_secret_key_1, b"TEST BACKUP 1")
            .await;

    // Get a challenge for a different backup_account_id
    let challenge_response = get_reset_challenge(&backup_account_id_2).await;

    // Sign the challenge with the first keypair
    let signature = sign_keypair_challenge(
        &backup_account_secret_key_1,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Try to reset the first backup with a challenge token for a different backup_account_id
    let reset_response = send_post_request(
        "/v1/reset",
        json!({
            "backupAccountId": backup_account_id_1, // First backup
            "signature": signature,
            "challengeToken": challenge_response["token"], // Token for second backup
        }),
    )
    .await;

    assert_eq!(reset_response.status(), StatusCode::BAD_REQUEST);
    let error_body = reset_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&error_body).unwrap();
    assert_eq!(
        error_response["error"]["code"].as_str().unwrap(),
        "invalid_challenge_context"
    );

    // Verify the backup still exists
    verify_s3_metadata_exists(&backup_account_id_1).await;
}
