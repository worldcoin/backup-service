mod common;

use crate::common::{create_test_backup, verify_s3_metadata_exists, MockPasskeyClient};
use axum::http::StatusCode;
use axum::response::Response;
use backup_service::mock_oidc_server::MockOidcServer;
use backup_service::types::Environment;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use http_body_util::BodyExt;
use p256::SecretKey;
use passkey::types::webauthn::CredentialRequestOptions;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

/// Sets up a test environment with OIDC server, mock passkey client and a backup
async fn setup_test_environment() -> (MockOidcServer, Environment, String, MockPasskeyClient) {
    // Setup OIDC server
    let oidc_server = MockOidcServer::new().await;
    let environment =
        Environment::development(Some(oidc_server.server.socket_address().port() as usize));

    // Create a backup with a passkey
    let mut passkey_client = common::get_mock_passkey_client();
    let (_credential, response) = create_test_backup(&mut passkey_client, b"BACKUP DATA").await;

    // Extract the backup ID from the response
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let create_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = create_response["backupId"].as_str().unwrap().to_string();

    (oidc_server, environment, backup_id, passkey_client)
}

/// Gets a challenge for adding a new factor with a passkey
async fn get_add_factor_passkey_challenge(oidc_token: &str) -> Value {
    let challenge_response = common::send_post_request(
        "/add-factor/challenge/existing/passkey",
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

/// Gets a challenge for adding a new keypair factor
async fn get_add_factor_keypair_challenge() -> Value {
    let challenge_response =
        common::send_post_request("/add-factor/challenge/new/keypair", json!({})).await;

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
        BASE64_URL_SAFE_NO_PAD.encode(hash.as_bytes().to_vec())
    };

    (turnkey_activity, turnkey_activity_challenge)
}

/// Gets a passkey assertion for a Turnkey activity
async fn get_passkey_assertion(client: &mut MockPasskeyClient, challenge: &str) -> Value {
    let credential_request_options: CredentialRequestOptions = serde_json::from_value(json!({
        "publicKey": {
            "challenge": challenge,
            "timeout": 60000,
            "rpId": "keys.world.app",
            "userVerification": "preferred"
        },
    }))
    .unwrap();

    serde_json::to_value(
        client
            .authenticate(
                &Url::parse("https://keys.world.app").unwrap(),
                credential_request_options,
                passkey::client::DefaultClientData,
            )
            .await
            .unwrap(),
    )
    .unwrap()
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
async fn test_add_factor_happy_path() {
    // Setup test environment
    let (oidc_server, environment, backup_id, mut passkey_client) = setup_test_environment().await;

    // Generate OIDC token
    let oidc_token = oidc_server.generate_token(environment.clone(), None);

    // Get challenges for existing passkey and new OIDC factor
    let existing_challenge = get_add_factor_passkey_challenge(&oidc_token).await;
    let new_challenge = get_add_factor_keypair_challenge().await;

    // Create keypair and sign the new factor challenge
    let (new_public_key, _, new_factor_signature) =
        create_keypair_and_sign(new_challenge["challenge"].as_str().unwrap());

    // Create Turnkey activity and get passkey assertion
    let (turnkey_activity, challenge_hash) =
        create_turnkey_activity(existing_challenge["challenge"].as_str().unwrap());
    let passkey_assertion = get_passkey_assertion(&mut passkey_client, &challenge_hash).await;

    // Add the new factor
    let response = common::send_post_request_with_environment(
        "/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "PASSKEY",
                "credential": passkey_assertion
            },
            "existingFactorChallengeToken": existing_challenge["token"],
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
            "newFactorChallengeToken": new_challenge["token"],
            "encryptedBackupKey": {
                "kind": "TURNKEY",
                "encryptedKey": "ENCRYPTED_KEY",
                "turnkeyAccountId": "org123",
                "turnkeyUserId": "TURNKEY_USER_ID",
                "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID",
            },
        }),
        Some(environment),
    )
    .await;

    // Verify the response
    assert_eq!(response.status(), StatusCode::OK);
    let add_factor_response = parse_response_body(response).await;
    assert!(add_factor_response["factorId"].as_str().is_some());

    // Verify the factor was added to the backup metadata
    let metadata = verify_s3_metadata_exists(&backup_id).await;
    let factors = metadata["factors"].as_array().unwrap();
    assert_eq!(factors.len(), 2); // Original factor + new OIDC factor
    let new_factor = factors
        .iter()
        .find(|f| f["id"].as_str().unwrap() == add_factor_response["factorId"].as_str().unwrap())
        .unwrap();
    assert_eq!(new_factor["kind"]["kind"], "OIDC_ACCOUNT");
}

// Mismatch between OIDC token when getting the challenge and when adding the factor
#[tokio::test]
async fn test_add_factor_with_mismatched_oidc_token() {
    // Setup test environment
    let (oidc_server, environment, _, mut passkey_client) = setup_test_environment().await;

    // Generate two different OIDC tokens
    let original_oidc_token = oidc_server.generate_token(environment.clone(), None);
    let different_oidc_token = oidc_server.generate_token(
        environment.clone(),
        Some(openidconnect::SubjectIdentifier::new(
            "different-subject".to_string(),
        )),
    );

    // Get existing factor challenge with the original token
    let existing_challenge = get_add_factor_passkey_challenge(&original_oidc_token).await;

    // Get a challenge for the new factor
    let new_challenge = get_add_factor_keypair_challenge().await;

    // Create keypair and sign the challenge
    let (new_public_key, _, new_signature) =
        create_keypair_and_sign(new_challenge["challenge"].as_str().unwrap());

    // Create Turnkey activity and get passkey assertion
    let (turnkey_activity, challenge_hash) =
        create_turnkey_activity(existing_challenge["challenge"].as_str().unwrap());
    let passkey_assertion = get_passkey_assertion(&mut passkey_client, &challenge_hash).await;

    // Attempt to add the new factor but use a different OIDC token than what was used for the challenge
    let response = common::send_post_request_with_environment(
        "/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "PASSKEY",
                "credential": passkey_assertion
            },
            "existingFactorChallengeToken": existing_challenge["token"],
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
            "newFactorChallengeToken": new_challenge["token"],
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
    let add_factor_response = parse_response_body(response).await;
    assert_eq!(
        add_factor_response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "invalid_oidc_token",
                "message": "invalid_oidc_token",
            }
        })
    );
}

// No challenge in the Turnkey activity
#[tokio::test]
async fn test_add_factor_without_challenge_in_turnkey_activity() {
    // Setup test environment
    let (oidc_server, environment, _, mut passkey_client) = setup_test_environment().await;

    // Generate OIDC token
    let oidc_token = oidc_server.generate_token(environment.clone(), None);

    // Get challenges for existing passkey and new OIDC factor
    let existing_challenge = get_add_factor_passkey_challenge(&oidc_token).await;
    let new_challenge = get_add_factor_keypair_challenge().await;

    // Create keypair and sign the challenge
    let (new_public_key, _, new_signature) =
        create_keypair_and_sign(new_challenge["challenge"].as_str().unwrap());

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
        BASE64_URL_SAFE_NO_PAD.encode(hash.as_bytes().to_vec())
    };

    // Sign the invalid activity with the passkey
    let passkey_assertion =
        get_passkey_assertion(&mut passkey_client, &turnkey_activity_challenge).await;

    // Attempt to add the new factor with the invalid Turnkey activity
    let response = common::send_post_request_with_environment(
        "/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "PASSKEY",
                "credential": passkey_assertion
            },
            "existingFactorChallengeToken": existing_challenge["token"],
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
            "newFactorChallengeToken": new_challenge["token"],
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
    assert_eq!(error_response["error"]["code"], "webauthn_error");
}

#[tokio::test]
async fn test_add_factor_with_modified_turnkey_activity() {
    // Setup test environment
    let (oidc_server, environment, _, mut passkey_client) = setup_test_environment().await;

    // Generate OIDC token
    let oidc_token = oidc_server.generate_token(environment.clone(), None);

    // Get challenges for existing passkey and new OIDC factor
    let existing_challenge = get_add_factor_passkey_challenge(&oidc_token).await;
    let new_challenge = get_add_factor_keypair_challenge().await;

    // Create keypair and sign the challenge
    let (new_public_key, _, new_signature) =
        create_keypair_and_sign(new_challenge["challenge"].as_str().unwrap());

    // Create valid Turnkey activity with the challenge
    let (_turnkey_activity, challenge_hash) =
        create_turnkey_activity(existing_challenge["challenge"].as_str().unwrap());

    // Sign the activity with the passkey
    let passkey_assertion = get_passkey_assertion(&mut passkey_client, &challenge_hash).await;

    // Modify the activity AFTER signing it by generating it again with new timestamp
    let (modified_activity, _) =
        create_turnkey_activity(existing_challenge["challenge"].as_str().unwrap());

    // Attempt to add the new factor with the modified activity
    let response = common::send_post_request_with_environment(
        "/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "PASSKEY",
                "credential": passkey_assertion
            },
            "existingFactorChallengeToken": existing_challenge["token"],
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
            "newFactorChallengeToken": new_challenge["token"],
            "encryptedBackupKey": null,
        }),
        Some(environment),
    )
    .await;

    // Verify the request was rejected with an error
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error_response = parse_response_body(response).await;
    assert_eq!(error_response["error"]["code"], "webauthn_error");
}
