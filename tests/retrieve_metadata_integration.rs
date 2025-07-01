mod common;

use crate::common::{create_test_backup_with_sync_keypair, sign_keypair_challenge};
use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::json;

// Happy path - retrieve backup metadata with a sync factor
#[tokio::test]
async fn test_retrieve_metadata_happy_path() {
    // Create a backup with a keypair and get the sync factor secret key
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"TEST BACKUP").await;

    // Extract the backup ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupId"].as_str().unwrap();

    // Get a metadata challenge
    let challenge_response =
        common::send_post_request("/retrieve-metadata/challenge/keypair", json!({})).await;
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

    // Retrieve the backup metadata
    let response = common::send_post_request(
        "/retrieve-metadata",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify the response contains the correct backup ID and metadata
    assert_eq!(response["backupId"], backup_id);
    assert!(response["metadata"]["id"].is_string());
    assert!(response["metadata"]["factors"].is_array());
    assert!(response["metadata"]["syncFactors"].is_array());
    assert!(response["metadata"]["keys"].is_array());

    // Verify that the sync factor is included in the metadata
    let sync_factor_found = response["metadata"]["syncFactors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|factor| {
            if factor["kind"]["kind"] == json!("EC_KEYPAIR")
                && factor["kind"]["publicKey"] == json!(sync_public_key)
            {
                return true;
            }
            false
        });

    assert!(sync_factor_found, "Sync factor not found in metadata");
}

// Test with incorrect authorization - should fail
#[tokio::test]
async fn test_retrieve_metadata_with_incorrect_authorization() {
    // Create a backup with a keypair and get the sync factor secret key
    let ((_, _), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"TEST BACKUP").await;

    // Get the backup ID
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let _backup_id = response["backupId"].as_str().unwrap();

    // Get a metadata challenge
    let challenge_response =
        common::send_post_request("/retrieve-metadata/challenge/keypair", json!({})).await;
    let challenge_response_body = challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response: serde_json::Value =
        serde_json::from_slice(&challenge_response_body).unwrap();

    // Create a new sync factor - different from the one we used to create the backup
    let (_new_sync_factor, _, new_sync_secret_key) = common::make_sync_factor().await;

    // Use the correct public key from the original sync factor
    let sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());

    // But sign with the new sync factor secret key
    let wrong_signature = sign_keypair_challenge(
        &new_sync_secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Try to retrieve the metadata with signature from a different key
    let response = common::send_post_request(
        "/retrieve-metadata",
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

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        error_response["error"]["code"],
        "signature_verification_error"
    );
}
