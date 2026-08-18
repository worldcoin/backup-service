mod common;

use crate::common::{
    generate_keypair, get_keypair_challenge, get_passkey_challenge, get_test_router,
    make_sync_factor, send_post_request, send_post_request_with_multipart, sign_keypair_challenge,
    verify_s3_backup_exists, verify_s3_metadata_exists, BackupAccount,
};
use axum::body::{Body, Bytes};
use axum::http::StatusCode;
use backup_service::environment::Environment;
use backup_service_test_utils::{
    get_mock_passkey_client, make_credential_from_passkey_challenge, MockOidcProvider,
    MockOidcServer,
};
use http::Request;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

// Happy path - passkey
#[tokio::test]
async fn test_create_backup_with_passkey() {
    let mut passkey_client = get_mock_passkey_client();

    // Get a challenge from the server, which also carries the Backup Account challenge
    let backup_account = BackupAccount::generate();
    let backup_account_id = backup_account.id.clone();
    let challenge_response = get_passkey_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);

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
            "backupAccountChallengeToken": proof_token,
            "backupAccountSignature": proof_signature,
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupMetadata"]["id"].as_str().unwrap();
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
            "backupAccountId": backup_account.id,
            "backupAccountChallengeToken": proof_token,
            "backupAccountSignature": proof_signature,
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

    // Get a challenge from the server, which also carries the Backup Account challenge
    let backup_account = BackupAccount::generate();
    let challenge_response = get_keypair_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);

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
        "backupAccountId": backup_account.id,
        "backupAccountChallengeToken": proof_token,
        "backupAccountSignature": proof_signature,
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
    let backup_id = response["backupMetadata"]["id"].as_str().unwrap();

    // Check that backup was successfully created on S3
    verify_s3_backup_exists(backup_id, b"TEST FILE").await;
}

// Happy path - keypair
#[tokio::test]
async fn test_create_backup_with_ec_keypair() {
    // Get a challenge from the server, which also carries the Backup Account challenge
    let backup_account = BackupAccount::generate();
    let challenge_response = get_keypair_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);

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
            "backupAccountId": backup_account.id,
            "backupAccountChallengeToken": proof_token,
            "backupAccountSignature": proof_signature,
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupMetadata"]["id"].as_str().unwrap();

    // Check that backup was successfully created on S3
    verify_s3_backup_exists(backup_id, b"TEST FILE").await;
}

#[tokio::test]
async fn test_create_backup_with_incorrect_token() {
    let mut passkey_client = get_mock_passkey_client();

    // Get a challenge from the server, which also carries the Backup Account challenge
    let backup_account = BackupAccount::generate();
    let challenge_response = get_passkey_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);

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
            "backupAccountId": backup_account.id,
            "backupAccountChallengeToken": proof_token,
            "backupAccountSignature": proof_signature,
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

    // Get a challenge from the server, which also carries the Backup Account challenge
    let backup_account = BackupAccount::generate();
    let challenge_response = get_passkey_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);

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
            "backupAccountId": backup_account.id,
            "backupAccountChallengeToken": proof_token,
            "backupAccountSignature": proof_signature,
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
                "code": "webauthn_error",
                "message": "The JSON from the client did not indicate webauthn.<method> correctly",
            },
        })
    );
}

#[tokio::test]
async fn test_create_backup_with_empty_file() {
    let mut passkey_client = get_mock_passkey_client();

    // Get a challenge from the server, which also carries the Backup Account challenge
    let backup_account = BackupAccount::generate();
    let challenge_response = get_passkey_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);

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
            "backupAccountId": backup_account.id,
            "backupAccountChallengeToken": proof_token,
            "backupAccountSignature": proof_signature,
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

    // Get a challenge from the server, which also carries the Backup Account challenge
    let backup_account = BackupAccount::generate();
    let challenge_response = get_passkey_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);

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
            "backupAccountId": backup_account.id,
            "backupAccountChallengeToken": proof_token,
            "backupAccountSignature": proof_signature,
        }),
        Bytes::from(vec![0; 15 * 1024 * 1024 + 1]), // 15 MB file + 1 byte
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "content_too_large",
                "message": "Backup file exceeds maximum allowed size.",
            },
        })
    );
}

#[tokio::test]
async fn test_create_backup_with_invalid_oidc_token() {
    let oidc_server = MockOidcServer::new().await;
    let environment =
        Environment::development(Some(oidc_server.server.socket_address().port() as usize));

    // Get a challenge from the server, which also carries the Backup Account challenge
    let backup_account = BackupAccount::generate();
    let challenge_response = get_keypair_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);

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
            "backupAccountId": backup_account.id,
            "backupAccountChallengeToken": proof_token,
            "backupAccountSignature": proof_signature,
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

    // Get a challenge from the server, which also carries the Backup Account challenge
    let backup_account = BackupAccount::generate();
    let challenge_response = get_keypair_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);

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
            "backupAccountId": backup_account.id,
            "backupAccountChallengeToken": proof_token,
            "backupAccountSignature": proof_signature,
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        Some(environment),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["error"]["code"], "oidc_token_invalid_nonce");
}

#[tokio::test]
async fn test_create_backup_with_invalid_ec_keypair() {
    // Get a challenge from the server, which also carries the Backup Account challenge
    let backup_account = BackupAccount::generate();
    let challenge_response = get_keypair_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);

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
            "backupAccountId": backup_account.id,
            "backupAccountChallengeToken": proof_token,
            "backupAccountSignature": proof_signature,
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
                "message": "Signature verification failed",
            },
        })
    );
}

/// Only EC keypairs are valid sync factors
#[tokio::test]
async fn test_create_backup_with_invalid_sync_factor() {
    // Get a challenge from the server, which also carries the Backup Account challenge
    let backup_account = BackupAccount::generate();
    let challenge_response = get_keypair_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);

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
            "backupAccountId": backup_account.id,
            "backupAccountChallengeToken": proof_token,
            "backupAccountSignature": proof_signature,
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
    // Get a challenge from the server, which also carries the Backup Account challenge
    let backup_account = BackupAccount::generate();
    let challenge_response = get_keypair_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);

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
            "backupAccountId": backup_account.id,
            "backupAccountChallengeToken": proof_token,
            "backupAccountSignature": proof_signature,
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
                "message": "Failed to decode a value from base64: Invalid padd",
            },
        })
    );
}

/// Test that duplicate `backup_account_id` is rejected
#[tokio::test]
async fn test_create_backup_with_duplicate_backup_account_id() {
    let mut passkey_client = get_mock_passkey_client();

    // Generate the backup account we'll use for both requests
    let backup_account = BackupAccount::generate();
    let backup_account_id = backup_account.id.clone();

    // Get a challenge from the server, which also carries the Backup Account challenge
    let challenge_response = get_passkey_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);

    // Register a credential by solving the challenge
    let credential =
        make_credential_from_passkey_challenge(&mut passkey_client, &challenge_response).await;

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

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
            "backupAccountChallengeToken": proof_token,
            "backupAccountSignature": proof_signature,
        }),
        Bytes::from(b"TEST FILE".as_slice()),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    // Now try to create another backup with the same backup_account_id. The owner of the break-glass
    // key can produce a fresh proof, but the ID is taken.
    let challenge_response2 = get_passkey_challenge().await;
    let (proof_token2, proof_signature2) = backup_account.proof(&challenge_response2);
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
            "backupAccountChallengeToken": proof_token2,
            "backupAccountSignature": proof_signature2,
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

    // Get a challenge from the server. No break-glass challenge is needed: these requests are
    // rejected while deserializing the payload, before the proof is looked at.
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
                "message": "Failed to deserialize payload",
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

/// A correctly shaped ID that is not a point on secp256k1 (x = 0 has no square root there) has no
/// secret key, so no proof can be produced for it. It is rejected when the proof is checked rather
/// than while deserializing, which keeps IDs already in the field working on other paths.
#[tokio::test]
async fn test_create_backup_with_off_curve_backup_account_id() {
    let off_curve_id = format!("backup_account_03{}", hex::encode([0u8; 32]));

    // The challenge endpoint mints for it, since it too only checks the shape.
    let challenge_response = get_keypair_challenge().await;
    let proof_token = challenge_response["backupAccountChallengeToken"]
        .as_str()
        .unwrap();

    let response = create_with_proof(
        &off_curve_id,
        &challenge_response,
        (Some(proof_token), Some("MEQCIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["error"]["code"], "invalid_backup_account_id");
}

/// Test that concurrent requests to create backups with the same `backup_account_id` don't cause race conditions
#[tokio::test]
async fn test_no_race_conditions_on_concurrent_backup_account_id() {
    use futures::future::join_all;

    let backup_account = BackupAccount::generate();
    let num_concurrent_requests = 5;

    // Create multiple concurrent requests with the same backup_account_id. Each holds the
    // break-glass key, so each can mint its own valid proof.
    let mut handles = vec![];
    for _ in 0..num_concurrent_requests {
        let secret_key = backup_account.secret_key.clone();
        let handle = tokio::spawn(async move {
            let backup_account = BackupAccount::from_secret_key(secret_key);
            let mut passkey_client = get_mock_passkey_client();
            let challenge_response = get_passkey_challenge().await;
            let (proof_token, proof_signature) = backup_account.proof(&challenge_response);
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
                    "backupAccountId": backup_account.id,
                    "backupAccountChallengeToken": proof_token,
                    "backupAccountSignature": proof_signature,
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
        "Expected exactly 1 successful request, got {success_count}"
    );
    assert_eq!(
        error_count,
        num_concurrent_requests - 1,
        "Expected {} errors (conflicting_lock or backup_account_id_already_exists), got {}",
        num_concurrent_requests - 1,
        error_count
    );
}

/// Ensures the multipart parsing error is propagated
#[tokio::test]
async fn test_create_backup_with_malformed_multipart_data() {
    let environment = Environment::development(None);
    let boundary = format!("Boundary-{}", Uuid::new_v4());

    let body_bytes = b"This is not valid multipart data\r\n";
    let req = Request::builder()
        .uri("/v1/create")
        .method("POST")
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header("Content-Length", body_bytes.len())
        .body(Body::from(body_bytes.to_vec()))
        .unwrap();

    let app = get_test_router(Some(environment), None).await;
    let response = app.oneshot(req).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(response["error"]["code"], "multipart_error");
    assert_eq!(response["error"]["message"], "incomplete multipart stream");
}

//------------------------------------------------------------------------------------------------
// Break-glass proof of the backup account ID
//------------------------------------------------------------------------------------------------

/// Posts a JSON payload and parses the response body.
async fn post_json(route: &str, payload: serde_json::Value) -> serde_json::Value {
    let response = send_post_request(route, payload).await;
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

/// Sends a `/create` request with an EC keypair main factor. `proof` carries the break-glass
/// challenge token and signature, either of which can be omitted.
async fn create_with_proof(
    backup_account_id: &str,
    challenge_response: &serde_json::Value,
    proof: (Option<&str>, Option<&str>),
) -> axum::response::Response {
    let (public_key, secret_key) = generate_keypair();
    let signature = sign_keypair_challenge(
        &secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    let mut payload = json!({
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
        "backupAccountId": backup_account_id,
    });
    if let Some(token) = proof.0 {
        payload["backupAccountChallengeToken"] = json!(token);
    }
    if let Some(signature) = proof.1 {
        payload["backupAccountSignature"] = json!(signature);
    }

    send_post_request_with_multipart(
        "/v1/create",
        payload,
        Bytes::from(b"TEST FILE".as_slice()),
        None,
    )
    .await
}

/// A create without a break-glass proof is refused outright, so a backup account ID cannot be
/// squatted by whoever calls `/create` first.
#[tokio::test]
async fn test_create_backup_without_backup_account_proof() {
    let backup_account = BackupAccount::generate();
    let challenge_response = get_keypair_challenge().await;

    let response = create_with_proof(&backup_account.id, &challenge_response, (None, None)).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["error"]["code"], "missing_backup_account_proof");
}

/// The squat this is all for: an attacker holding a perfectly valid proof of their own account
/// cannot use it to claim someone else's ID, because the signature is checked against the key that
/// the claimed ID *is*.
#[tokio::test]
async fn test_create_backup_cannot_claim_another_backup_account_id() {
    let victim = BackupAccount::generate();
    let attacker = BackupAccount::generate();

    let challenge_response = get_keypair_challenge().await;
    let (proof_token, proof_signature) = attacker.proof(&challenge_response);

    let response = create_with_proof(
        &victim.id,
        &challenge_response,
        (Some(&proof_token), Some(&proof_signature)),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["error"]["code"], "signature_verification_error");
}

/// A signature the break-glass key made for `/reset` cannot be replayed to authorize a create.
#[tokio::test]
async fn test_create_backup_with_reset_challenge_as_proof() {
    let backup_account = BackupAccount::generate();

    // The break-glass key signs a challenge, but one minted for resetting rather than creating.
    let reset_challenge = post_json(
        "/v1/reset/challenge/keypair",
        json!({ "backupAccountId": backup_account.id }),
    )
    .await;
    let reset_token = reset_challenge["token"].as_str().unwrap();
    let reset_signature = backup_account.sign(reset_challenge["challenge"].as_str().unwrap());

    let challenge_response = get_keypair_challenge().await;
    let response = create_with_proof(
        &backup_account.id,
        &challenge_response,
        (Some(reset_token), Some(&reset_signature)),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["error"]["code"], "invalid_challenge_context");
}

/// A break-glass proof is single use. Resetting frees the ID, but the spent proof cannot create
/// the backup a second time.
#[tokio::test]
async fn test_create_backup_rejects_replayed_backup_account_proof() {
    let backup_account = BackupAccount::generate();

    // Create the backup, keeping the proof around.
    let challenge_response = get_keypair_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);
    let response = create_with_proof(
        &backup_account.id,
        &challenge_response,
        (Some(&proof_token), Some(&proof_signature)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Reset it, which frees the backup account ID for a fresh create.
    let reset_challenge = post_json(
        "/v1/reset/challenge/keypair",
        json!({ "backupAccountId": backup_account.id }),
    )
    .await;
    let reset_response = send_post_request(
        "/v1/reset",
        json!({
            "backupAccountId": backup_account.id,
            "signature": backup_account.sign(reset_challenge["challenge"].as_str().unwrap()),
            "challengeToken": reset_challenge["token"],
        }),
    )
    .await;
    assert_eq!(reset_response.status(), StatusCode::NO_CONTENT);

    // The ID is free, but the proof has been spent.
    let challenge_response2 = get_keypair_challenge().await;
    let response = create_with_proof(
        &backup_account.id,
        &challenge_response2,
        (Some(&proof_token), Some(&proof_signature)),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["error"]["code"], "already_used");
}

/// Half a proof is a client bug rather than a client that predates the proof, so it is rejected
/// distinctly from an absent proof.
#[tokio::test]
async fn test_create_backup_with_incomplete_backup_account_proof() {
    let backup_account = BackupAccount::generate();
    let challenge_response = get_keypair_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);

    for proof in [
        (Some(proof_token.as_str()), None),
        (None, Some(proof_signature.as_str())),
    ] {
        let response = create_with_proof(&backup_account.id, &challenge_response, proof).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            response["error"]["code"], "incomplete_backup_account_proof",
            "expected an incomplete proof to be rejected on its own terms"
        );
    }
}
