mod common;

use crate::common::{
    create_test_backup_with_oidc_account, generate_keypair, get_keypair_retrieve_challenge,
    send_post_request_with_environment, sign_keypair_challenge,
};
use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use openidconnect::SubjectIdentifier;
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn test_retrieve_backup_with_oidc_account() {
    let subject = Uuid::new_v4().to_string();

    // Create a backup with OIDC account
    let test_backup = create_test_backup_with_oidc_account(&subject, b"TEST BACKUP DATA").await;
    assert_eq!(test_backup.response.status(), StatusCode::OK);

    // Get a new challenge for retrieving the backup
    let retrieve_challenge = get_keypair_retrieve_challenge().await;

    // Generate new OIDC token for the same user
    let new_oidc_token = test_backup.oidc_server.generate_token(
        test_backup.environment,
        Some(SubjectIdentifier::new(subject.clone())),
    );

    // Sign the retrieval challenge with the same keypair
    let signature = sign_keypair_challenge(
        &test_backup.secret_key,
        retrieve_challenge["challenge"].as_str().unwrap(),
    );

    // Retrieve the backup using the solved challenge
    let retrieve_response = send_post_request_with_environment(
        "/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": new_oidc_token,
                },
                "publicKey": test_backup.public_key,
                "signature": signature,
            },
            "challengeToken": retrieve_challenge["token"],
        }),
        // Must be sent to the same JWT issuer as the one used to create the backup
        Some(test_backup.environment),
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
async fn test_retrieve_backup_with_different_oidc_account() {
    let subject = Uuid::new_v4().to_string();

    // Create a backup with OIDC account
    let test_backup = create_test_backup_with_oidc_account(&subject, b"TEST BACKUP DATA").await;
    assert_eq!(test_backup.response.status(), StatusCode::OK);

    // Get a new challenge for retrieving the backup
    let retrieve_challenge = get_keypair_retrieve_challenge().await;

    // Generate new OIDC token for a DIFFERENT user
    let different_subject = Uuid::new_v4().to_string();
    let different_oidc_token = test_backup.oidc_server.generate_token(
        test_backup.environment,
        Some(SubjectIdentifier::new(different_subject)),
    );

    // Sign the retrieval challenge with the same keypair
    let signature = sign_keypair_challenge(
        &test_backup.secret_key,
        retrieve_challenge["challenge"].as_str().unwrap(),
    );

    // Retrieve the backup using the solved challenge with a different OIDC account
    let retrieve_response = send_post_request_with_environment(
        "/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": different_oidc_token,
                },
                "publicKey": test_backup.public_key,
                "signature": signature,
            },
            "challengeToken": retrieve_challenge["token"],
        }),
        // Must be sent to the same JWT issuer as the one used to create the backup
        Some(test_backup.environment),
    )
    .await;

    // Should fail with bad request because the OIDC account is different
    assert_eq!(retrieve_response.status(), StatusCode::BAD_REQUEST);

    let body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify error message
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
async fn test_retrieve_backup_with_different_keypair() {
    let subject = Uuid::new_v4().to_string();

    // Create a backup with OIDC account
    let test_backup = create_test_backup_with_oidc_account(&subject, b"TEST BACKUP DATA").await;
    assert_eq!(test_backup.response.status(), StatusCode::OK);

    // Get a new challenge for retrieving the backup
    let retrieve_challenge = get_keypair_retrieve_challenge().await;

    // Generate new OIDC token for the same user
    let new_oidc_token = test_backup.oidc_server.generate_token(
        test_backup.environment,
        Some(SubjectIdentifier::new(subject.clone())),
    );

    // Generate a different keypair for signing
    let (_, different_secret_key) = generate_keypair();

    // Sign the retrieval challenge with the different keypair
    let signature = sign_keypair_challenge(
        &different_secret_key,
        retrieve_challenge["challenge"].as_str().unwrap(),
    );

    // Retrieve the backup using the solved challenge with different signature
    let retrieve_response = send_post_request_with_environment(
        "/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": new_oidc_token,
                },
                "publicKey": test_backup.public_key,
                "signature": signature,
            },
            "challengeToken": retrieve_challenge["token"],
        }),
        // Must be sent to the same JWT issuer as the one used to create the backup
        Some(test_backup.environment),
    )
    .await;

    // Should fail with bad request because the signature verification will fail
    assert_eq!(retrieve_response.status(), StatusCode::BAD_REQUEST);

    let body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify error message
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
