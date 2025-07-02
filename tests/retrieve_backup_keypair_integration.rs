mod common;

use crate::common::{
    create_test_backup_with_keypair, create_test_backup_with_sync_keypair,
    get_keypair_retrieval_challenge, send_post_request_with_bypass_attestation_token,
    sign_keypair_challenge,
};
use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::json;

#[tokio::test]
async fn test_retrieve_backup_with_ec_keypair() {
    // Create a backup with EC keypair
    let ((public_key, secret_key), create_response) =
        create_test_backup_with_keypair(b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    // Get a new challenge for retrieving the backup
    let retrieve_challenge = get_keypair_retrieval_challenge().await;

    // Sign the retrieval challenge with the same keypair
    let signature = sign_keypair_challenge(
        &secret_key,
        retrieve_challenge["challenge"].as_str().unwrap(),
    );

    // Retrieve the backup using the solved challenge
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key,
                "signature": signature,
            },
            "challengeToken": retrieve_challenge["token"],
        }),
        None,
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
    assert_eq!(metadata["keys"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_retrieve_backup_with_incorrect_token_ec_keypair() {
    // Create a backup with EC keypair
    let ((public_key, secret_key), create_response) =
        create_test_backup_with_keypair(b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    // Get a new challenge for retrieving the backup
    let retrieve_challenge = get_keypair_retrieval_challenge().await;

    // Sign the retrieval challenge with the same keypair
    let signature = sign_keypair_challenge(
        &secret_key,
        retrieve_challenge["challenge"].as_str().unwrap(),
    );

    // Retrieve the backup using an incorrect token
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key,
                "signature": signature,
            },
            "challengeToken": "INCORRECT TOKEN",
        }),
        None,
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

    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "jwt_error",
                "message": "jwt_error",
            }
        })
    );
}

#[tokio::test]
async fn test_retrieve_backup_with_wrong_keypair() {
    // Create a backup with first keypair
    let ((public_key1, _), create_response) =
        create_test_backup_with_keypair(b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    // Create a second keypair (that doesn't have access to the backup)
    let (_, secret_key2) = common::generate_keypair();

    // Get a new challenge for retrieving the backup
    let retrieve_challenge = get_keypair_retrieval_challenge().await;

    // Sign the retrieval challenge with the second keypair
    let signature = sign_keypair_challenge(
        &secret_key2,
        retrieve_challenge["challenge"].as_str().unwrap(),
    );

    // Attempt to retrieve the backup using the second keypair's signature but first keypair's public key
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key1,
                "signature": signature,
            },
            "challengeToken": retrieve_challenge["token"],
        }),
        None,
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

    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "signature_verification_error",
                "message": "signature_verification_error",
            }
        })
    );
}

#[tokio::test]
async fn test_retrieve_backup_with_nonexistent_keypair() {
    // Generate a keypair but don't create a backup with it
    let (public_key, secret_key) = common::generate_keypair();

    // Get a retrieve challenge
    let retrieve_challenge = get_keypair_retrieval_challenge().await;

    // Sign the challenge with the keypair
    let signature = sign_keypair_challenge(
        &secret_key,
        retrieve_challenge["challenge"].as_str().unwrap(),
    );

    // Attempt to retrieve a backup that doesn't exist
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key,
                "signature": signature,
            },
            "challengeToken": retrieve_challenge["token"],
        }),
        None,
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

    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "backup_not_found",
                "message": "backup_not_found",
            }
        })
    );
}

#[tokio::test]
async fn test_retrieve_backup_with_sync_keypair() {
    // Create a backup with EC keypair and get the sync keypair's secret key
    let ((_, _), create_response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    // Get a new challenge for retrieving the backup
    let retrieve_challenge = get_keypair_retrieval_challenge().await;

    // Sign the retrieval challenge with the sync keypair
    let signature = sign_keypair_challenge(
        &sync_secret_key,
        retrieve_challenge["challenge"].as_str().unwrap(),
    );

    // Get the sync keypair's public key
    let sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());

    // Attempt to retrieve the backup using the sync factor
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": sync_public_key,
                "signature": signature,
            },
            "challengeToken": retrieve_challenge["token"],
        }),
        None,
    )
    .await;

    // This should fail because sync factors cannot be used to retrieve backups
    assert_eq!(retrieve_response.status(), StatusCode::BAD_REQUEST);

    let body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // The service should respond with backup_not_found error
    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "backup_not_found",
                "message": "backup_not_found",
            }
        })
    );
}
