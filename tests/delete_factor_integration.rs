mod common;

use crate::common::{
    create_test_backup_with_sync_keypair, sign_keypair_challenge, verify_s3_metadata_exists,
};
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::error::SdkError;
use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::json;

// Happy path - delete the last factor with a sync keypair, should delete the backup
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
        "/delete-factor/challenge/keypair",
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
    let response = common::send_post_request(
        "/delete-factor",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "factorId": factor_id,
        }),
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
        "/delete-factor/challenge/keypair",
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
    let response = common::send_post_request(
        "/delete-factor",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "factorId": factor_id, // Mismatching factor ID
        }),
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
