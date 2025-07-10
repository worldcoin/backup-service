mod common;

use crate::common::{
    create_test_backup_with_oidc_account, generate_keypair, get_keypair_retrieve_challenge,
    send_post_request_with_bypass_attestation_token, sign_keypair_challenge,
};
use axum::http::StatusCode;
use backup_service_test_utils::MockOidcProvider;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use openidconnect::SubjectIdentifier;
use serde_json::json;
use uuid::Uuid;

/// Retrieves a backup with an OIDC account and ensures replays are not allowed for OIDC nonces.
#[tokio::test]
async fn test_retrieve_backup_with_oidc_account() {
    let subject = Uuid::new_v4().to_string();

    // Create a backup with OIDC account
    let test_backup = create_test_backup_with_oidc_account(&subject, b"TEST BACKUP DATA").await;
    assert_eq!(test_backup.response.status(), StatusCode::OK);

    // Get a new challenge for retrieving the backup
    let retrieve_challenge = get_keypair_retrieve_challenge().await;

    // Generate new OIDC token for the same user
    let (public_key, secret_key) = generate_keypair();
    let new_oidc_token = test_backup.oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(SubjectIdentifier::new(subject.clone())),
        &public_key,
    );

    // Sign the retrieval challenge with the same keypair
    let signature = sign_keypair_challenge(
        &secret_key,
        retrieve_challenge["challenge"].as_str().unwrap(),
    );

    // Retrieve the backup using the solved challenge
    let json_body = json!({
        "authorization": {
            "kind": "OIDC_ACCOUNT",
            "oidcToken": {
                "kind": "GOOGLE",
                "token": new_oidc_token,
            },
            "publicKey": public_key,
            "signature": signature,
        },
        "challengeToken": retrieve_challenge["token"],
    });
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/retrieve/from-challenge",
        json_body.clone(),
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

    // Ensure the OIDC nonce cannot be re-used
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/retrieve/from-challenge",
        json_body,
        // Must be sent to the same JWT issuer as the one used to create the backup
        Some(test_backup.environment),
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
                "code": "already_used",
                "message": "already_used",
            }
        })
    );
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
    let (public_key, secret_key) = generate_keypair();
    let different_subject = Uuid::new_v4().to_string();
    let different_oidc_token = test_backup.oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(SubjectIdentifier::new(different_subject)),
        &public_key,
    );

    // Sign the retrieval challenge with the same keypair
    let signature = sign_keypair_challenge(
        &secret_key,
        retrieve_challenge["challenge"].as_str().unwrap(),
    );

    // Retrieve the backup using the solved challenge with a different OIDC account
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": different_oidc_token,
                },
                "publicKey": public_key,
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
    let (public_key, _) = generate_keypair(); // a new keypair for the OIDC nonce is used on each request
    let new_oidc_token = test_backup.oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(SubjectIdentifier::new(subject.clone())),
        &public_key,
    );

    // Generate a different keypair for signing
    let (_, different_secret_key) = generate_keypair();

    // Sign the retrieval challenge with the different keypair
    let signature = sign_keypair_challenge(
        &different_secret_key,
        retrieve_challenge["challenge"].as_str().unwrap(),
    );

    // Retrieve the backup using the solved challenge with different signature
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": new_oidc_token,
                },
                "publicKey": public_key,
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

#[tokio::test]
async fn test_retrieve_backup_with_incorrect_nonce() {
    let subject = Uuid::new_v4().to_string();

    // Create a backup with OIDC account
    let test_backup = create_test_backup_with_oidc_account(&subject, b"TEST BACKUP DATA").await;
    assert_eq!(test_backup.response.status(), StatusCode::OK);

    // Get a new challenge for retrieving the backup
    let retrieve_challenge = get_keypair_retrieve_challenge().await;

    // Generate new OIDC token for the same user with an incorrect nonce
    let token_with_incorrect_nonce = test_backup.oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(SubjectIdentifier::new(subject.clone())),
        &generate_keypair().0,
    );

    // Sign the retrieval challenge with the correct keypair
    let signature = sign_keypair_challenge(
        &test_backup.secret_key,
        retrieve_challenge["challenge"].as_str().unwrap(),
    );

    // Retrieve the backup using the solved challenge but with incorrect nonce in token
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": token_with_incorrect_nonce,
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

    // Should fail with bad request because the nonce verification will fail
    assert_eq!(retrieve_response.status(), StatusCode::BAD_REQUEST);

    let body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify error message - it's returned as a token verification error
    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "oidc_token_verification_error",
                "message": "oidc_token_verification_error",
            }
        })
    );
}
