mod common;

use std::sync::Arc;

use crate::common::get_test_s3_client;
use crate::common::{
    create_test_backup, generate_keypair, get_keypair_retrieve_challenge,
    send_post_request_with_bypass_attestation_token, sign_keypair_challenge,
    verify_s3_metadata_exists,
};
use axum::http::StatusCode;
use axum::response::Response;
use backup_service::backup_storage::BackupStorage;
use backup_service::types::backup_metadata::{Factor, OidcAccountKind};
use backup_service::types::encryption_key::BackupEncryptionKey;
use backup_service::types::Environment;
use backup_service_test_utils::get_mock_passkey_client;
use backup_service_test_utils::get_passkey_assertion;
use backup_service_test_utils::MockOidcProvider;
use backup_service_test_utils::MockOidcServer;
use backup_service_test_utils::MockPasskeyClient;
use base64::engine::general_purpose::STANDARD;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use http_body_util::BodyExt;
use openidconnect::SubjectIdentifier;
use p256::SecretKey;
use serde_json::{json, Value};
use serial_test::serial;
use sha2::{Digest, Sha256};

/// Sets up a test environment with OIDC server, mock passkey client and a backup
async fn setup_test_environment() -> (MockOidcServer, Environment, String, MockPasskeyClient) {
    // Setup OIDC server
    let oidc_server = MockOidcServer::new().await;
    let environment =
        Environment::development(Some(oidc_server.server.socket_address().port() as usize));

    // Create a backup with a passkey
    let mut passkey_client = get_mock_passkey_client();
    let (_credential, response) = create_test_backup(&mut passkey_client, b"BACKUP DATA").await;

    // Extract the backup ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let create_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = create_response["backupMetadata"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    (oidc_server, environment, backup_id, passkey_client)
}

/// Gets challenges for adding a new factor (both existing passkey and new keypair challenges)
async fn get_add_factor_challenges(oidc_token: &str) -> Value {
    let challenge_response = common::send_post_request(
        "/v1/add-factor/challenge",
        json!({
            "newFactor": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": oidc_token,
            }
        }),
    )
    .await;

    parse_response_body(challenge_response).await
}

/// Creates a Turnkey activity JSON with the given challenge
fn create_turnkey_activity(challenge: &str) -> (String, String) {
    let turnkey_activity = json!({
        "type": "ACTIVITY_TYPE_CREATE_API_KEYS_V2",
        "organizationId": "org123",
        "timestampMs": Utc::now().timestamp_millis().to_string(),
        "metadata": {
            "challenge": challenge
        }
    })
    .to_string();

    let turnkey_activity_challenge = {
        let mut hasher = Sha256::new();
        hasher.update(turnkey_activity.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        BASE64_URL_SAFE_NO_PAD.encode(hash.as_bytes())
    };

    (turnkey_activity, turnkey_activity_challenge)
}

/// Creates a new keypair and signs a challenge
fn create_keypair_and_sign(challenge: &str) -> (String, SecretKey, String) {
    let (public_key, secret_key) = common::generate_keypair();
    let signature = common::sign_keypair_challenge(&secret_key, challenge);
    (public_key, secret_key, signature)
}

/// Parses a response body to JSON
async fn parse_response_body(response: Response) -> Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

// Happy path - add a new OIDC account factor to an existing backup using a passkey
#[tokio::test]
#[serial]
async fn test_add_factor_happy_path() {
    // Setup test environment
    let (oidc_server, environment, backup_id, mut passkey_client) = setup_test_environment().await;

    // Generate keypair for new factor
    let (new_public_key, new_secret_key) = common::generate_keypair();

    // Generate subject ID and OIDC token with consistent subject
    let subject = format!("test-subject-{}", uuid::Uuid::new_v4());
    let oidc_token = oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(SubjectIdentifier::new(subject.clone())),
        &new_public_key,
    );

    // Get challenges for both existing passkey and new factor
    let challenges = get_add_factor_challenges(&oidc_token).await;

    // Sign the new factor challenge with new factor keypair
    let new_factor_signature = common::sign_keypair_challenge(
        &new_secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    // Create Turnkey activity and get passkey assertion
    let (turnkey_activity, challenge_hash) =
        create_turnkey_activity(challenges["existingFactorChallenge"].as_str().unwrap());
    let passkey_assertion = get_passkey_assertion(&mut passkey_client, &challenge_hash).await;

    // Add the new factor
    let response = common::send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "PASSKEY",
                "credential": passkey_assertion
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "existingFactorTurnkeyActivity": turnkey_activity,
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": oidc_token
                },
                "publicKey": new_public_key,
                "signature": new_factor_signature,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "encryptedBackupKey": {
                "kind": "TURNKEY",
                "encryptedKey": "ENCRYPTED_KEY",
                "turnkeyAccountId": "org123",
                "turnkeyUserId": "TURNKEY_USER_ID",
                "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID",
            },
            "turnkeyProviderId": "turnkey_provider_id",
        }),
        Some(environment),
    )
    .await;

    // Verify the response
    assert_eq!(response.status(), StatusCode::OK);
    let add_factor_response = parse_response_body(response).await;
    assert!(add_factor_response["factorId"].as_str().is_some());
    assert!(add_factor_response["backupMetadata"].is_object());
    assert_eq!(
        add_factor_response["backupMetadata"]["id"]
            .as_str()
            .unwrap(),
        backup_id
    );
    assert_eq!(
        add_factor_response["backupMetadata"]["factors"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // Verify the factor was added to the backup metadata
    let metadata = verify_s3_metadata_exists(&backup_id).await;
    let factors = metadata["factors"].as_array().unwrap();
    assert_eq!(factors.len(), 2); // Original factor + new OIDC factor
    let new_factor = factors
        .iter()
        .find(|f| f["id"].as_str().unwrap() == add_factor_response["factorId"].as_str().unwrap())
        .unwrap();
    assert_eq!(new_factor["kind"]["kind"], "OIDC_ACCOUNT");

    // Now try to retrieve the backup using the newly added OIDC factor
    // Get a challenge for retrieving the backup
    let retrieve_challenge = get_keypair_retrieve_challenge().await;

    // Sign the retrieval challenge with a new keypair
    let (retrieval_public_key, _, retrieval_signature) =
        create_keypair_and_sign(retrieve_challenge["challenge"].as_str().unwrap());

    // Generate a new OIDC token with the same subject ID
    let new_oidc_token = oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(SubjectIdentifier::new(subject)),
        &retrieval_public_key,
    );

    // Attempt to retrieve the backup using the OIDC factor
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/v1/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": new_oidc_token,
                },
                "publicKey": retrieval_public_key,
                "signature": retrieval_signature,
            },
            "challengeToken": retrieve_challenge["token"],
        }),
        Some(environment),
    )
    .await;

    // Verify the retrieval was successful
    assert_eq!(retrieve_response.status(), StatusCode::OK);

    // Parse the response body
    let body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let retrieve_response: Value = serde_json::from_slice(&body).unwrap();

    // Verify we got back a backup and metadata
    assert!(retrieve_response["backup"].is_string());
    assert!(retrieve_response["metadata"].is_object());

    // Decode and verify the backup data (we used "BACKUP DATA" when creating the test backup)
    let backup_base64 = retrieve_response["backup"].as_str().unwrap();
    let backup_bytes = STANDARD.decode(backup_base64).unwrap();
    assert_eq!(backup_bytes, b"BACKUP DATA");

    // Verify the metadata contains expected fields
    let metadata = &retrieve_response["metadata"];
    assert_eq!(metadata["id"].as_str().unwrap(), &backup_id);
}

// Mismatch between OIDC token when getting the challenge and when adding the factor
#[tokio::test]
#[serial]
async fn test_add_factor_with_mismatched_oidc_token() {
    // Setup test environment
    let (oidc_server, environment, _, mut passkey_client) = setup_test_environment().await;

    // Create keypair for new factor
    let (new_public_key, new_secret_key) = common::generate_keypair();

    // Generate two different OIDC tokens
    let original_oidc_token =
        oidc_server.generate_token(&MockOidcProvider::Google, None, &new_public_key);
    let different_oidc_token = oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(
            "different-subject".to_string(),
        )),
        &new_public_key,
    );

    // Get challenges with the original token
    let challenges = get_add_factor_challenges(&original_oidc_token).await;

    // Sign the new factor challenge with the new factor keypair
    let new_signature = common::sign_keypair_challenge(
        &new_secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    // Create Turnkey activity and get passkey assertion
    let (turnkey_activity, challenge_hash) =
        create_turnkey_activity(challenges["existingFactorChallenge"].as_str().unwrap());
    let passkey_assertion = get_passkey_assertion(&mut passkey_client, &challenge_hash).await;

    // Attempt to add the new factor but use a different OIDC token than what was used for the challenge
    let response = common::send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "PASSKEY",
                "credential": passkey_assertion
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "existingFactorTurnkeyActivity": turnkey_activity,
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": different_oidc_token // Using a different token than in the challenge
                },
                "publicKey": new_public_key,
                "signature": new_signature,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "encryptedBackupKey": {
                "kind": "TURNKEY",
                "encryptedKey": "ENCRYPTED_KEY",
                "turnkeyAccountId": "org123",
                "turnkeyUserId": "TURNKEY_USER_ID",
                "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID",
            },
            "turnkeyProviderId": "turnkey_provider_id",
        }),
        Some(environment),
    )
    .await;

    // Verify the request was rejected with an error
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let add_factor_response = parse_response_body(response).await;
    assert_eq!(
        add_factor_response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "oidc_token_mismatch",
                "message": "OIDC Token mismatch",
            }
        })
    );
}

// No challenge in the Turnkey activity
#[tokio::test]
#[serial]
async fn test_add_factor_without_challenge_in_turnkey_activity() {
    // Setup test environment
    let (oidc_server, environment, _, mut passkey_client) = setup_test_environment().await;

    // Create keypair for the new factor
    let (new_public_key, new_secret_key) = generate_keypair();

    // Generate OIDC token
    let oidc_token = oidc_server.generate_token(&MockOidcProvider::Google, None, &new_public_key);

    // Get challenges for both factors
    let challenges = get_add_factor_challenges(&oidc_token).await;

    // Sign the challenge with the new keypair
    let new_signature = sign_keypair_challenge(
        &new_secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    // Create Turnkey activity WITHOUT the challenge
    let turnkey_activity = json!({
        "type": "ACTIVITY_TYPE_CREATE_API_KEYS_V2",
        "organizationId": "org123",
        "timestampMs": Utc::now().timestamp_millis().to_string(),
        // No challenge field in metadata
        "metadata": {}
    })
    .to_string();

    let turnkey_activity_challenge = {
        let mut hasher = Sha256::new();
        hasher.update(turnkey_activity.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        BASE64_URL_SAFE_NO_PAD.encode(hash.as_bytes())
    };

    // Sign the invalid activity with the passkey
    let passkey_assertion =
        get_passkey_assertion(&mut passkey_client, &turnkey_activity_challenge).await;

    // Attempt to add the new factor with the invalid Turnkey activity
    let response = common::send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "PASSKEY",
                "credential": passkey_assertion
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "existingFactorTurnkeyActivity": turnkey_activity, // Activity without challenge
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": oidc_token
                },
                "publicKey": new_public_key,
                "signature": new_signature,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "encryptedBackupKey": {
                "kind": "TURNKEY",
                "encryptedKey": "ENCRYPTED_KEY",
                "turnkeyAccountId": "org123",
                "turnkeyUserId": "TURNKEY_USER_ID",
                "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID",
            }
        }),
        Some(environment),
    )
    .await;

    // Verify the request was rejected with an error
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error_response = parse_response_body(response).await;
    assert_eq!(error_response["error"]["code"], "invalid_turnkey_activity");
}

// Modified Turnkey activity after signing
#[tokio::test]
async fn test_add_factor_with_modified_turnkey_activity() {
    // Setup test environment
    let (oidc_server, environment, _, mut passkey_client) = setup_test_environment().await;

    // Create keypair for the new factor
    let (new_public_key, new_secret_key) = generate_keypair();

    // Generate OIDC token
    let oidc_token = oidc_server.generate_token(&MockOidcProvider::Google, None, &new_public_key);

    // Get challenges for both factors
    let challenges = get_add_factor_challenges(&oidc_token).await;

    // Sign the challenge with the new keypair
    let new_signature = sign_keypair_challenge(
        &new_secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    // Create valid Turnkey activity with the challenge
    let (_turnkey_activity, challenge_hash) =
        create_turnkey_activity(challenges["existingFactorChallenge"].as_str().unwrap());

    // Sign the activity with the passkey
    let passkey_assertion = get_passkey_assertion(&mut passkey_client, &challenge_hash).await;

    // Modify the activity AFTER signing it by generating it again with new timestamp
    let (modified_activity, _) =
        create_turnkey_activity(challenges["existingFactorChallenge"].as_str().unwrap());

    // Attempt to add the new factor with the modified activity
    let response = common::send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "PASSKEY",
                "credential": passkey_assertion
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "existingFactorTurnkeyActivity": modified_activity, // Modified after signing
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": oidc_token
                },
                "publicKey": new_public_key,
                "signature": new_signature,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "encryptedBackupKey": null,
            "turnkeyProviderId": "turnkey_provider_id",
        }),
        Some(environment),
    )
    .await;

    // Verify the request was rejected with an error
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error_response = parse_response_body(response).await;
    assert_eq!(error_response["error"]["code"], "turnkey_activity_error");
}

// Incorrectly signed challenge for new keypair
#[tokio::test]
#[serial]
async fn test_add_factor_incorrectly_signed_challenge_for_new_keypair() {
    // Setup test environment
    let (oidc_server, environment, _, mut passkey_client) = setup_test_environment().await;

    // Create keypair for new factor
    let (new_public_key, _) = common::generate_keypair();

    // Generate OIDC token
    let oidc_token = oidc_server.generate_token(&MockOidcProvider::Google, None, &new_public_key);

    // Get challenges for both factors
    let challenges = get_add_factor_challenges(&oidc_token).await;

    // Sign the challenge with a different keypair
    let (_, _, new_incorrect_signature) =
        create_keypair_and_sign(challenges["newFactorChallenge"].as_str().unwrap());

    // Create Turnkey activity and get passkey assertion
    let (turnkey_activity, challenge_hash) =
        create_turnkey_activity(challenges["existingFactorChallenge"].as_str().unwrap());
    let passkey_assertion = get_passkey_assertion(&mut passkey_client, &challenge_hash).await;

    // Add the new factor
    let response = common::send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "PASSKEY",
                "credential": passkey_assertion
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "existingFactorTurnkeyActivity": turnkey_activity,
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": oidc_token
                },
                "publicKey": new_public_key,
                "signature": new_incorrect_signature,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "encryptedBackupKey": {
                "kind": "TURNKEY",
                "encryptedKey": "ENCRYPTED_KEY",
                "turnkeyAccountId": "org123",
                "turnkeyUserId": "TURNKEY_USER_ID",
                "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID",
            },
            "turnkeyProviderId": "turnkey_provider_id",
        }),
        Some(environment),
    )
    .await;

    // Verify the response
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let add_factor_response = parse_response_body(response).await;
    assert_eq!(
        add_factor_response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "signature_verification_error",
                "message": "Signature verification failed",
            }
        })
    );
}

// Attempt to add a new factor with a passkey credential for a different user
#[tokio::test]
#[serial]
async fn test_add_factor_with_passkey_credential_for_different_user() {
    let (oidc_server, environment, _, _) = setup_test_environment().await;
    let mut passkey_client_1 = get_mock_passkey_client();
    let mut passkey_client_2 = get_mock_passkey_client();

    // Create a backup with the first and second passkey
    let (_, response) = create_test_backup(&mut passkey_client_1, b"BACKUP DATA").await;
    assert_eq!(response.status(), StatusCode::OK);
    let (passkey_client_2_credential, response) =
        create_test_backup(&mut passkey_client_2, b"BACKUP DATA").await;
    assert_eq!(response.status(), StatusCode::OK);

    // Create keypair for the new factor
    let (new_public_key, new_secret_key) = generate_keypair();

    // Generate OIDC token
    let oidc_token = oidc_server.generate_token(&MockOidcProvider::Google, None, &new_public_key);

    // Get challenges for both factors
    let challenges = get_add_factor_challenges(&oidc_token).await;

    // Sign the challenge with the new keypair
    let new_signature = sign_keypair_challenge(
        &new_secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    // Create Turnkey activity and get passkey assertion from user 1
    let (turnkey_activity, challenge_hash) =
        create_turnkey_activity(challenges["existingFactorChallenge"].as_str().unwrap());
    let mut passkey_assertion = get_passkey_assertion(&mut passkey_client_1, &challenge_hash).await;

    // But replace credential ID with user 2's credential
    passkey_assertion["id"] = passkey_client_2_credential["id"].clone();
    passkey_assertion["rawId"] = passkey_client_2_credential["rawId"].clone();

    // Attempt to add the new factor with the modified passkey assertion
    let response = common::send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "PASSKEY",
                "credential": passkey_assertion
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "existingFactorTurnkeyActivity": turnkey_activity,
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": oidc_token
                },
                "publicKey": new_public_key,
                "signature": new_signature,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "encryptedBackupKey": {
                "kind": "TURNKEY",
                "encryptedKey": "ENCRYPTED_KEY",
                "turnkeyAccountId": "org123",
                "turnkeyUserId": "TURNKEY_USER_ID",
                "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID",
            },
            "turnkeyProviderId": "turnkey_provider_id",
        }),
        Some(environment),
    )
    .await;

    // Verify the response
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let add_factor_response = parse_response_body(response).await;
    assert_eq!(
        add_factor_response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "turnkey_activity_error",
                "message": "Signature verification failed",
            }
        })
    );
}

// Different account ID in the Turnkey activity and encrypted backup key
#[tokio::test]
#[serial]
async fn test_add_factor_with_different_account_id_in_turnkey_activity_and_encrypted_backup_key() {
    // Setup test environment
    let (oidc_server, environment, backup_id, mut passkey_client) = setup_test_environment().await;

    // Update the backup metadata with a pre-registered OIDC factor
    let s3_client = Arc::new(get_test_s3_client().await);
    let backup_storage = BackupStorage::new(environment, s3_client.clone());
    let factor = Factor::new_oidc_account(
        OidcAccountKind::Google {
            sub: "12345".to_string(),
            masked_email: "t****@example.com".to_string(),
        },
        "turnkey_provider_id".to_string(),
    );
    let encryption_key = BackupEncryptionKey::Turnkey {
        encrypted_key: "ENCRYPTED_KEY".to_string(),
        turnkey_account_id: "org_123".to_string(),
        turnkey_user_id: "TURNKEY_USER_ID".to_string(),
        turnkey_private_key_id: "TURNKEY_PRIVATE_KEY_ID".to_string(),
    };
    backup_storage
        .add_factor(&backup_id, factor, Some(encryption_key))
        .await
        .unwrap();

    // Create keypair for new factor
    let (new_public_key, new_secret_key) = common::generate_keypair();

    // Generate OIDC token
    let oidc_token = oidc_server.generate_token(&MockOidcProvider::Google, None, &new_public_key);

    // Get challenges for both factors
    let challenges = get_add_factor_challenges(&oidc_token).await;

    // Sign the new factor challenge with new factor keypair
    let new_signature = common::sign_keypair_challenge(
        &new_secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    // Create Turnkey activity and get passkey assertion
    let (turnkey_activity, challenge_hash) =
        create_turnkey_activity(challenges["existingFactorChallenge"].as_str().unwrap());
    let passkey_assertion = get_passkey_assertion(&mut passkey_client, &challenge_hash).await;

    // Attempt to add the new factor with a different account ID in the encrypted backup key
    let response = common::send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "PASSKEY",
                "credential": passkey_assertion
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "existingFactorTurnkeyActivity": turnkey_activity,
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": oidc_token
                },
                "publicKey": new_public_key,
                "signature": new_signature,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "encryptedBackupKey": {
                "kind": "TURNKEY",
                "encryptedKey": "ENCRYPTED_KEY",
                // Different account ID than in the activity, not `org123` (doesn't match the existing backup metadata)
                "turnkeyAccountId": "different_account_id",
                "turnkeyUserId": "TURNKEY_USER_ID",
                "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID",
            },
            "turnkeyProviderId": "turnkey_provider_id",
        }),
        Some(environment),
    )
    .await;

    // Verify the response
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let add_factor_response = parse_response_body(response).await;
    assert_eq!(
        add_factor_response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "turnkey_activity_error",
                "message": "organizationId does not match expected Turnkey account ID",
            }
        })
    );
}
