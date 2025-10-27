mod common;

use crate::common::{
    generate_keypair, generate_random_backup_id, get_keypair_challenge, get_passkey_challenge,
    make_sync_factor, send_post_request_with_multipart, sign_keypair_challenge,
    verify_s3_backup_exists, verify_s3_metadata_exists,
};
use axum::body::Bytes;
use axum::http::StatusCode;
use backup_service::types::Environment;
use backup_service_test_utils::{
    get_mock_passkey_client, make_credential_from_passkey_challenge, MockOidcProvider,
    MockOidcServer,
};
use http_body_util::BodyExt;
use serde_json::json;

// Happy path - passkey
#[tokio::test]
async fn test_create_backup_with_passkey() {
    let mut passkey_client = get_mock_passkey_client();

    // Get a challenge from the server
    let challenge_response = get_passkey_challenge().await;

    // Register a credential by solving the challenge
    let credential =
        make_credential_from_passkey_challenge(&mut passkey_client, &challenge_response).await;

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    let backup_account_id = generate_random_backup_id();

    // Send the credential to the server to create a backup
    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "PASSKEY",
                "credential": credential,
                "label": "Google Credential Manager",
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_challenge_token,
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": backup_account_id,
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupId"].as_str().unwrap();
    assert_eq!(backup_id, backup_account_id);

    // Check that backup was successfully created on S3
    verify_s3_backup_exists(&backup_account_id, b"TEST FILE").await;

    // Check that metadata was successfully created on S3
    let metadata = verify_s3_metadata_exists(backup_id).await;
    assert_eq!(metadata["factors"][0]["kind"]["kind"], "PASSKEY");
    assert_eq!(
        metadata["factors"][0]["kind"]["label"],
        "Google Credential Manager"
    );
    assert_eq!(
        metadata["factors"][0]["kind"]["webauthnCredential"]["cred"]["cred_id"],
        credential["id"]
    );

    // check challenge_token cannot be reused
    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "PASSKEY",
                "credential": credential,
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_challenge_token,
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": generate_random_backup_id(),
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "already_used",
                "message": "Token has already been used.",
            },
        })
    );
}

/// Happy path - OIDC
#[tokio::test]
async fn test_create_backup_with_oidc_token() {
    let oidc_server = MockOidcServer::new().await;
    let environment =
        Environment::development(Some(oidc_server.server.socket_address().port() as usize));

    // Get a challenge from the server
    let challenge_response = get_keypair_challenge().await;

    // Generate temporary keypair for OIDC authentication
    let (public_key, secret_key) = generate_keypair();

    // Generate OIDC token
    let oidc_token = oidc_server.generate_token(&MockOidcProvider::Google, None, &public_key);
    let signature = sign_keypair_challenge(
        &secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    let request_body = json!({
        "authorization": {
            "kind": "OIDC_ACCOUNT",
            "oidcToken": {
                "kind": "GOOGLE",
                "token": oidc_token,
            },
            "publicKey": public_key,
            "signature": signature,
        },
        "challengeToken": challenge_response["token"],
        "initialEncryptionKey": {
            "kind": "PRF",
            "encryptedKey": "ENCRYPTED_KEY",
        },
        "initialSyncFactor": sync_factor,
        "initialSyncChallengeToken": sync_challenge_token,
        "turnkeyProviderId": "turnkey_provider_id",
        "manifestHash": hex::encode([1u8; 32]),
        "backupAccountId": generate_random_backup_id(),
    });

    // Send the OIDC token to the server to create a backup
    let response = send_post_request_with_multipart(
        "/v1/create",
        request_body,
        Bytes::from(b"TEST FILE".as_slice()),
        Some(environment),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupId"].as_str().unwrap();

    // Check that backup was successfully created on S3
    verify_s3_backup_exists(backup_id, b"TEST FILE").await;
}

// Happy path - keypair
#[tokio::test]
async fn test_create_backup_with_ec_keypair() {
    // Get a challenge from the server
    let challenge_response = get_keypair_challenge().await;

    // Generate keypair and sign the challenge
    let (public_key, secret_key) = generate_keypair();
    let signature = sign_keypair_challenge(
        &secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    // Send the keypair signature to the server to create a backup
    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_challenge_token,
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": generate_random_backup_id(),
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupId"].as_str().unwrap();

    // Check that backup was successfully created on S3
    verify_s3_backup_exists(backup_id, b"TEST FILE").await;
}

#[tokio::test]
async fn test_create_backup_with_incorrect_token() {
    let mut passkey_client = get_mock_passkey_client();

    // Get a challenge from the server
    let challenge_response = get_passkey_challenge().await;

    // Register a credential by solving the challenge
    let credential =
        make_credential_from_passkey_challenge(&mut passkey_client, &challenge_response).await;

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    // Send the credential to the server to create a backup
    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "PASSKEY",
                "credential": credential,
            },
            "challengeToken": "INCORRECT TOKEN",
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_challenge_token,
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": generate_random_backup_id(),
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "jwt_error",
                "message": "Invalid or expired token.",
            },
        })
    );
}

#[tokio::test]
async fn test_create_backup_with_incorrectly_passkey_solved_challenge() {
    let mut passkey_client = get_mock_passkey_client();

    // Get a challenge from the server
    let challenge_response = get_passkey_challenge().await;

    // Register a credential by solving the challenge
    let credential =
        make_credential_from_passkey_challenge(&mut passkey_client, &challenge_response).await;

    // Flip a bit in response.clientDataJSON that looks like [145, 64, ...]
    let mut credential: serde_json::Value = serde_json::from_value(credential).unwrap();
    credential["response"]["clientDataJSON"][10] = json!(
        credential["response"]["clientDataJSON"][10]
            .as_u64()
            .unwrap()
            + 1
    );

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    // Send the credential to the server to create a backup
    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "PASSKEY",
                "credential": credential,
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_challenge_token,
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": generate_random_backup_id(),
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "webauthn_client_error",
                "message": "webauthn_client_error",
            },
        })
    );
}

#[tokio::test]
async fn test_create_backup_with_empty_file() {
    let mut passkey_client = get_mock_passkey_client();

    // Get a challenge from the server
    let challenge_response = get_passkey_challenge().await;

    // Register a credential by solving the challenge
    let credential =
        make_credential_from_passkey_challenge(&mut passkey_client, &challenge_response).await;

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    // Send the credential to the server to create a backup
    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "PASSKEY",
                "credential": credential,
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_challenge_token,
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": generate_random_backup_id(),
        }),
        Bytes::from(b"".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "empty_backup_file",
                "message": "Empty backup file",
            },
        })
    );
}

#[tokio::test]
async fn test_create_backup_with_large_file() {
    let mut passkey_client = get_mock_passkey_client();

    // Get a challenge from the server
    let challenge_response = get_passkey_challenge().await;

    // Register a credential by solving the challenge
    let credential =
        make_credential_from_passkey_challenge(&mut passkey_client, &challenge_response).await;

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    // Send the credential to the server to create a backup
    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "PASSKEY",
                "credential": credential,
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_challenge_token,
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": generate_random_backup_id(),
        }),
        Bytes::from(vec![0; 10 * 1024 * 1024 + 1]), // 10 MB file + 1 byte
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "backup_file_too_large",
                "message": "Backup file too large",
            },
        })
    );
}

#[tokio::test]
async fn test_create_backup_with_invalid_oidc_token() {
    let oidc_server = MockOidcServer::new().await;
    let environment =
        Environment::development(Some(oidc_server.server.socket_address().port() as usize));

    // Get a challenge from the server
    let challenge_response = get_keypair_challenge().await;

    // Generate invalid OIDC token
    let oidc_token = oidc_server.generate_expired_token(&MockOidcProvider::Google);

    // Generate temporary keypair for OIDC authentication and sign the challenge
    let (public_key, secret_key) = generate_keypair();
    let signature = sign_keypair_challenge(
        &secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    // Send the OIDC token to the server to create a backup
    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": oidc_token,
                },
                "publicKey": public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_challenge_token,
            "turnkeyProviderId": "turnkey_provider_id",
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": generate_random_backup_id(),
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        Some(environment),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "oidc_token_verification_error",
                "message": "Failed to verify OIDC token.",
            },
        })
    );
}

#[tokio::test]
async fn test_create_backup_with_incorrect_nonce_in_oidc_token() {
    let oidc_server = MockOidcServer::new().await;
    let environment =
        Environment::development(Some(oidc_server.server.socket_address().port() as usize));

    // Get a challenge from the server
    let challenge_response = get_keypair_challenge().await;

    // Generate temporary keypair for OIDC authentication
    let (public_key, secret_key) = generate_keypair();

    // Generate OIDC token with incorrect nonce
    let incorrect_nonce_token =
        oidc_server.generate_token(&MockOidcProvider::Google, None, &generate_keypair().0);

    // Sign the challenge correctly
    let signature = sign_keypair_challenge(
        &secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    // Send the OIDC token to the server to create a backup
    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": incorrect_nonce_token,
                },
                "publicKey": public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_challenge_token,
            "turnkeyProviderId": "turnkey_provider_id",
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": generate_random_backup_id(),
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        Some(environment),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "oidc_token_verification_error",
                "message": "Failed to verify OIDC token.",
            },
        })
    );
}

#[tokio::test]
async fn test_create_backup_with_invalid_ec_keypair() {
    // Get a challenge from the server
    let challenge_response = get_keypair_challenge().await;

    // Generate keypair and sign the challenge
    let (_public_key, secret_key) = generate_keypair();
    let signature = sign_keypair_challenge(
        &secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Generate another keypair
    let (public_key2, _) = generate_keypair();

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    // Pass the public key from the second keypair, but the signature from the first keypair
    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key2,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_challenge_token,
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": generate_random_backup_id(),
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "signature_verification_error",
                "message": "Signature verification failed.",
            },
        })
    );
}

/// Only EC keypairs are valid sync factors
#[tokio::test]
async fn test_create_backup_with_invalid_sync_factor() {
    // Get a challenge from the server
    let challenge_response = get_keypair_challenge().await;

    // Generate keypair and sign the challenge
    let (public_key, secret_key) = generate_keypair();
    let signature = sign_keypair_challenge(
        &secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    let mut passkey_client = get_mock_passkey_client();

    // Get a challenge from the server
    let passkey_challenge_response = get_passkey_challenge().await;

    // Get a sync factor challenge
    let (_, sync_challenge_token, _) = make_sync_factor().await;

    // Register a credential by solving the challenge
    let credential =
        make_credential_from_passkey_challenge(&mut passkey_client, &passkey_challenge_response)
            .await;

    // Send the keypair signature to the server to create a backup
    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": {
                "kind": "PASSKEY",
                "credential": credential,
            },
            "initialSyncChallengeToken": sync_challenge_token,
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": generate_random_backup_id(),
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "invalid_sync_factor_type",
                "message": "Client-side auth failure: invalid_sync_factor_type",
            },
        })
    );
}

/// Incorrectly signed sync factor
#[tokio::test]
async fn test_create_backup_with_incorrectly_signed_sync_factor() {
    // Get a challenge from the server
    let challenge_response = get_keypair_challenge().await;

    // Generate keypair and sign the challenge
    let (public_key, secret_key) = generate_keypair();
    let signature = sign_keypair_challenge(
        &secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Get a sync factor challenge
    let (mut sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    let mut sig = sync_factor["signature"].as_str().unwrap().to_string();
    sig.pop();
    sync_factor["signature"] = json!(sig);

    // Send the keypair signature to the server to create a backup
    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_challenge_token,
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": generate_random_backup_id(),
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "signature_verification_error",
                "message": "Signature verification failed.",
            },
        })
    );
}

/// Test that duplicate backup_account_id is rejected
#[tokio::test]
async fn test_create_backup_with_duplicate_backup_account_id() {
    let mut passkey_client = get_mock_passkey_client();

    // Get a challenge from the server
    let challenge_response = get_passkey_challenge().await;

    // Register a credential by solving the challenge
    let credential =
        make_credential_from_passkey_challenge(&mut passkey_client, &challenge_response).await;

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    // Generate a backup_account_id that we'll use for both requests
    let backup_account_id = generate_random_backup_id();

    // Send the first request to create a backup
    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "PASSKEY",
                "credential": credential.clone(),
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor.clone(),
            "initialSyncChallengeToken": sync_challenge_token.clone(),
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": backup_account_id.clone(),
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    // Now try to create another backup with the same backup_account_id
    // Get a new challenge
    let challenge_response2 = get_passkey_challenge().await;
    let credential2 =
        make_credential_from_passkey_challenge(&mut passkey_client, &challenge_response2).await;

    // Create a new sync factor
    let (sync_factor2, sync_challenge_token2, _) = make_sync_factor().await;

    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "PASSKEY",
                "credential": credential2,
            },
            "challengeToken": challenge_response2["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY_2",
            },
            "initialSyncFactor": sync_factor2,
            "initialSyncChallengeToken": sync_challenge_token2,
            "manifestHash": hex::encode([2u8; 32]),
            "backupAccountId": backup_account_id,
        }),
        Bytes::from(b"TEST FILE 2".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "backup_account_id_already_exists",
                "message": "Backup ID already exists. Please `/sync` instead.",
            },
        })
    );
}

/// Test that invalid backup account IDs are rejected during deserialization
#[tokio::test]
async fn test_create_backup_with_invalid_backup_account_id() {
    let mut passkey_client = get_mock_passkey_client();

    // Get a challenge from the server
    let challenge_response = get_passkey_challenge().await;

    // Register a credential by solving the challenge
    let credential =
        make_credential_from_passkey_challenge(&mut passkey_client, &challenge_response).await;

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    // Test with missing prefix
    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "PASSKEY",
                "credential": credential.clone(),
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor.clone(),
            "initialSyncChallengeToken": sync_challenge_token.clone(),
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "invalid_payload",
                "message": "invalid_payload",
            },
        })
    );

    // Test with wrong length (too short)
    let challenge_response2 = get_passkey_challenge().await;
    let credential2 =
        make_credential_from_passkey_challenge(&mut passkey_client, &challenge_response2).await;
    let (sync_factor2, sync_challenge_token2, _) = make_sync_factor().await;

    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "PASSKEY",
                "credential": credential2.clone(),
            },
            "challengeToken": challenge_response2["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor2.clone(),
            "initialSyncChallengeToken": sync_challenge_token2.clone(),
            "manifestHash": hex::encode([1u8; 32]),
            "backupAccountId": "backup_account_0102",
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "invalid_payload",
                "message": "Failed to deserialize payload",
            },
        })
    );
}

/// Test that concurrent requests to create backups with the same backup_account_id don't cause race conditions
#[tokio::test]
async fn test_no_race_conditions_on_concurrent_backup_account_id() {
    use futures::future::join_all;

    let backup_account_id = generate_random_backup_id();
    let num_concurrent_requests = 5;

    // Create multiple concurrent requests with the same backup_account_id
    let mut handles = vec![];
    for _ in 0..num_concurrent_requests {
        let backup_account_id = backup_account_id.clone();
        let handle = tokio::spawn(async move {
            let mut passkey_client = get_mock_passkey_client();
            let challenge_response = get_passkey_challenge().await;
            let credential =
                make_credential_from_passkey_challenge(&mut passkey_client, &challenge_response)
                    .await;
            let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

            send_post_request_with_multipart(
                "/v1/create",
                json!({
                    "authorization": {
                        "kind": "PASSKEY",
                        "credential": credential,
                    },
                    "challengeToken": challenge_response["token"],
                    "initialEncryptionKey": {
                        "kind": "PRF",
                        "encryptedKey": "ENCRYPTED_KEY",
                    },
                    "initialSyncFactor": sync_factor,
                    "initialSyncChallengeToken": sync_challenge_token,
                    "manifestHash": hex::encode([1u8; 32]),
                    "backupAccountId": backup_account_id,
                }),
                Bytes::from(b"TEST FILE".as_slice()),
                None,
            )
            .await
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    let responses = join_all(handles).await;

    // Exactly one request should succeed, the rest should fail with either:
    // - conflicting_lock (423 LOCKED) - if they hit the Redis lock
    // - backup_account_id_already_exists (409 CONFLICT) - if they got past the lock but backup already exists
    let mut success_count = 0;
    let mut error_count = 0;

    for result in responses {
        let response = result.unwrap();
        if response.status() == StatusCode::OK {
            success_count += 1;
        } else if response.status() == StatusCode::LOCKED {
            // StatusCode::LOCKED is 423
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let response_body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if response_body["error"]["code"] == "conflicting_lock" {
                error_count += 1;
            }
        } else if response.status() == StatusCode::CONFLICT {
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let response_body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if response_body["error"]["code"] == "backup_account_id_already_exists" {
                error_count += 1;
            }
        }
    }

    assert_eq!(
        success_count, 1,
        "Expected exactly 1 successful request, got {}",
        success_count
    );
    assert_eq!(
        error_count,
        num_concurrent_requests - 1,
        "Expected {} errors (conflicting_lock or backup_account_id_already_exists), got {}",
        num_concurrent_requests - 1,
        error_count
    );
}
