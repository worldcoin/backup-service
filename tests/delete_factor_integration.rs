mod common;

use std::sync::Arc;

use crate::common::{
    create_test_backup_with_sync_keypair, sign_keypair_challenge, verify_s3_metadata_exists,
};
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::Client as S3Client;
use axum::http::StatusCode;
use backup_service::factor_lookup::FactorScope;
use backup_service::factor_lookup::FactorToLookup;
use backup_service::types::backup_metadata::FactorKind;
use backup_service::types::Environment;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use futures::future;
use http_body_util::BodyExt;
use serde_json::json;
use uuid::Uuid;

/// Happy path - delete the last `Main` factor with a sync keypair.
/// Deleting the last factor also deletes the backup.
#[tokio::test]
async fn test_delete_last_factor_happy_path() {
    // Create a backup with a keypair and a sync factor
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    // Extract the backup ID and the main factor ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let create_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = create_response["backupId"].as_str().unwrap();

    // Get the metadata to extract the factor ID
    let metadata = verify_s3_metadata_exists(backup_id).await;

    let factor_id = metadata["factors"][0]["id"].as_str().unwrap().to_string();

    // Get a delete factor challenge
    let challenge_response = common::send_post_request(
        "/v1/delete-factor/challenge/keypair",
        json!({
            "factorId": factor_id
        }),
    )
    .await;
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

    // Delete the factor (which should delete the backup)
    let response = common::send_post_request_with_bypass_attestation_token(
        "/v1/delete-factor",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "factorId": factor_id,
            "scope": "MAIN",
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    // Verify the backup was deleted by trying to get the metadata (should fail)
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
}

#[tokio::test]
async fn test_delete_sync_factor_happy_path() {
    // Setup test environment
    dotenvy::from_path(".env.example").ok();
    let environment = Environment::development(None);
    let dynamodb_client = Arc::new(aws_sdk_dynamodb::Client::new(
        &environment.aws_config().await,
    ));
    let factor_lookup =
        backup_service::factor_lookup::FactorLookup::new(environment, dynamodb_client.clone());

    // Create a backup with a keypair and a sync factor
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    // Extract the backup ID and the main factor ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let create_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = create_response["backupId"].as_str().unwrap();

    // Get the metadata to extract the factor ID
    let metadata = verify_s3_metadata_exists(backup_id).await;

    let factor_id = metadata["syncFactors"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // check the factor exists in DynamoDB
    let factor_to_lookup = FactorToLookup::from_ec_keypair(
        metadata["syncFactors"][0]["kind"]["publicKey"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    let observed_backup_id = factor_lookup
        .lookup(FactorScope::Sync, &factor_to_lookup)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(backup_id, &observed_backup_id);

    // Get a delete factor challenge
    let challenge_response = common::send_post_request(
        "/v1/delete-factor/challenge/keypair",
        json!({
            "factorId": factor_id
        }),
    )
    .await;
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

    // Delete the factor (which should **NOT** delete the backup as there are still `Main` factors)
    let response = common::send_post_request_with_bypass_attestation_token(
        "/v1/delete-factor",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "factorId": factor_id,
            "scope": "SYNC",
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = verify_s3_metadata_exists(backup_id).await;

    let factors = metadata["factors"].as_array().unwrap();
    assert_eq!(factors.len(), 1);

    let sync_factors = metadata["syncFactors"].as_array().unwrap();
    assert_eq!(sync_factors.len(), 0);

    // Verify the sync factor was deleted from DynamoDB
    let lookup_result = factor_lookup
        .lookup(FactorScope::Sync, &factor_to_lookup)
        .await
        .unwrap();

    assert_eq!(lookup_result, None);
}

// Test with incorrect factor ID - should fail
#[tokio::test]
async fn test_delete_factor_with_incorrect_factor_id() {
    // Create a backup with a keypair and a sync factor
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    // Extract the backup ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupId"].as_str().unwrap();

    // Get the metadata to extract the factor ID
    let metadata = verify_s3_metadata_exists(backup_id).await;
    let factor_id = metadata["factors"][0]["id"].as_str().unwrap().to_string();

    // Use an incorrect factor ID in the challenge
    let incorrect_factor_id = "incorrect-factor-id";

    // Get a delete factor challenge with the incorrect factor ID
    let challenge_response = common::send_post_request(
        "/v1/delete-factor/challenge/keypair",
        json!({
            "factorId": incorrect_factor_id
        }),
    )
    .await;
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

    // Try to delete the actual factor ID with a challenge for the incorrect factor ID
    let response = common::send_post_request_with_bypass_attestation_token(
        "/v1/delete-factor",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "factorId": factor_id, // Mismatching factor ID
            "scope": "MAIN",
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // the ChallengeContext from the JWE won't match the one in the request
    assert_eq!(error_response["error"]["code"], "invalid_challenge_context");

    // Verify the factor was not deleted
    let metadata = verify_s3_metadata_exists(backup_id).await;
    let factors = metadata["factors"].as_array().unwrap();
    assert_eq!(factors.len(), 1);
}

#[tokio::test]
async fn test_cannot_delete_sync_with_incorrect_scope() {
    // Setup test environment
    dotenvy::from_path(".env.example").ok();
    let environment = Environment::development(None);
    let dynamodb_client = Arc::new(aws_sdk_dynamodb::Client::new(
        &environment.aws_config().await,
    ));
    let factor_lookup =
        backup_service::factor_lookup::FactorLookup::new(environment, dynamodb_client.clone());

    // Create a backup with a keypair and a sync factor
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"INITIAL BACKUP").await;

    // Extract the backup ID and the main factor ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let create_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = create_response["backupId"].as_str().unwrap();

    // Get the metadata to extract the factor ID
    let metadata = verify_s3_metadata_exists(backup_id).await;

    let factor_id = metadata["syncFactors"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // check the factor exists in DynamoDB
    let factor_to_lookup = FactorToLookup::from_ec_keypair(
        metadata["syncFactors"][0]["kind"]["publicKey"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    let observed_backup_id = factor_lookup
        .lookup(FactorScope::Sync, &factor_to_lookup)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(backup_id, &observed_backup_id);

    // Get a delete factor challenge
    let challenge_response = common::send_post_request(
        "/v1/delete-factor/challenge/keypair",
        json!({
            "factorId": factor_id
        }),
    )
    .await;
    assert_eq!(challenge_response.status(), StatusCode::OK);
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

    // Delete the factor (which should **NOT** delete the backup as there are still `Main` factors)
    let response = common::send_post_request_with_bypass_attestation_token(
        "/v1/delete-factor",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "factorId": factor_id,
            "scope": "MAIN", // note we're trying to delete a sync factor with a `Main` scope
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error_response["error"]["code"], "factor_not_found");

    let metadata = verify_s3_metadata_exists(backup_id).await;

    let factors = metadata["factors"].as_array().unwrap();
    assert_eq!(factors.len(), 1);

    let sync_factors = metadata["syncFactors"].as_array().unwrap();
    assert_eq!(sync_factors.len(), 1);
}

/// Validates that a race condition does not occur when removing sync factors concurrently.
#[tokio::test]
async fn test_remove_sync_factor_etag_concurrency() {
    // Setup test environment
    dotenvy::from_path(".env.example").ok();
    let environment = Environment::development(None);
    let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
    let backup_storage = Arc::new(backup_service::backup_storage::BackupStorage::new(
        environment,
        s3_client.clone(),
    ));

    // Create a backup with multiple sync factors
    let backup_id = Uuid::new_v4().to_string();
    let test_backup_data = vec![1, 2, 3, 4, 5];

    // Create three sync factors
    let sync_factor1 =
        backup_service::types::backup_metadata::Factor::new_ec_keypair("public-key-1".to_string());
    let sync_factor2 =
        backup_service::types::backup_metadata::Factor::new_ec_keypair("public-key-2".to_string());
    let sync_factor3 =
        backup_service::types::backup_metadata::Factor::new_ec_keypair("public-key-3".to_string());

    let initial_metadata = backup_service::types::backup_metadata::BackupMetadata {
        id: backup_id.clone(),
        factors: vec![],
        sync_factors: vec![
            sync_factor1.clone(),
            sync_factor2.clone(),
            sync_factor3.clone(),
        ],
        keys: vec![],
        manifest_hash: [1u8; 32],
    };

    // Create the backup
    backup_storage
        .create(test_backup_data.clone(), &initial_metadata)
        .await
        .unwrap();

    // Clone the necessary data for the concurrent operations
    let backup_storage_clone1 = backup_storage.clone();
    let backup_storage_clone2 = backup_storage.clone();
    let backup_storage_clone3 = backup_storage.clone();
    let backup_id_clone1 = backup_id.clone();
    let backup_id_clone2 = backup_id.clone();
    let backup_id_clone3 = backup_id.clone();
    let factor_id1 = sync_factor1.id.clone();
    let factor_id2 = sync_factor2.id.clone();
    let factor_id3 = sync_factor3.id.clone();

    // Launch three concurrent operations to remove different sync factors
    let handle1 = tokio::spawn(async move {
        backup_storage_clone1
            .remove_sync_factor(&backup_id_clone1, &factor_id1)
            .await
    });

    let handle2 = tokio::spawn(async move {
        backup_storage_clone2
            .remove_sync_factor(&backup_id_clone2, &factor_id2)
            .await
    });

    let handle3 = tokio::spawn(async move {
        backup_storage_clone3
            .remove_sync_factor(&backup_id_clone3, &factor_id3)
            .await
    });

    // Wait for all operations to complete
    let results = future::join_all([handle1, handle2, handle3]).await;

    // Extract the results
    let result1 = results[0].as_ref().unwrap();
    let result2 = results[1].as_ref().unwrap();
    let result3 = results[2].as_ref().unwrap();

    // Count successes and failures
    let successes = [result1, result2, result3]
        .iter()
        .filter(|r| r.is_ok())
        .count();
    let failures = [result1, result2, result3]
        .iter()
        .filter(|r| r.is_err())
        .count();

    // Exactly one operation should succeed, the others should fail due to eTag mismatch
    assert_eq!(successes, 1, "Expected exactly one operation to succeed");
    assert_eq!(
        failures, 2,
        "Expected exactly two operations to fail due to eTag mismatch"
    );

    // Verify that the failed operations are due to PutObjectError with PreconditionFailed
    for result in [result1, result2, result3] {
        if let Err(err) = result {
            match err {
                backup_service::backup_storage::BackupManagerError::PutObjectError(sdk_err) => {
                    match sdk_err {
                        aws_sdk_s3::error::SdkError::ServiceError(service_err) => {
                            assert_eq!(service_err.err().code(), Some("PreconditionFailed"));
                        }
                        _ => panic!(
                            "Expected ServiceError with PreconditionFailed, got: {:?}",
                            sdk_err
                        ),
                    }
                }
                _ => panic!("Expected PutObjectError, got: {:?}", err),
            }
        }
    }

    // Verify that exactly two sync factors remain in the backup
    let final_metadata = backup_storage
        .get_metadata_by_backup_id(&backup_id)
        .await
        .unwrap()
        .unwrap()
        .0;

    assert_eq!(final_metadata.sync_factors.len(), 2);

    // print remaining factors
    // high likelihood that the removed factor is the one with the public key "public-key-1", but we don't assert as it's not deterministic
    let remaining_factors = final_metadata
        .sync_factors
        .iter()
        .map(|f| {
            let kind = f.kind.clone();
            match kind {
                FactorKind::EcKeypair { public_key } => public_key,
                _ => panic!("Expected EcKeypair, got: {:?}", kind),
            }
        })
        .collect::<Vec<_>>();

    println!("remaining factors: {:?}", remaining_factors);
}
