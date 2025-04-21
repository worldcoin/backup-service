#![allow(dead_code)]

mod oidc_server;
mod passkey_client;

use aws_sdk_s3::Client as S3Client;
use axum::body::{Body, Bytes};
use axum::http::Request;
use axum::response::Response;
use axum::Extension;
use backup_service::backup_storage::BackupStorage;
use backup_service::challenge_manager::ChallengeManager;
use backup_service::kms_jwe::KmsJwe;
use backup_service::types::Environment;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
#[allow(unused_imports)]
pub use oidc_server::*;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::SecretKey;
#[allow(unused_imports)]
pub use passkey_client::*;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

pub async fn get_test_s3_client() -> S3Client {
    let environment = Environment::development(None);
    S3Client::from_conf(environment.s3_client_config().await)
}

pub async fn get_challenge_manager() -> ChallengeManager {
    let environment = Environment::development(None);
    let kms_client = aws_sdk_kms::Client::new(&environment.aws_config().await);
    let kms_jwe = KmsJwe::new(environment.challenge_token_kms_key(), kms_client);
    ChallengeManager::new(environment.challenge_token_ttl(), kms_jwe)
}

pub async fn get_test_router(environment: Option<Environment>) -> axum::Router {
    dotenvy::from_path(".env.example").ok();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init()
        .ok();

    let environment = environment.unwrap_or_else(|| Environment::development(None));
    let s3_client = Arc::new(get_test_s3_client().await);
    let dynamodb_client = Arc::new(aws_sdk_dynamodb::Client::new(
        &environment.aws_config().await,
    ));
    let challenge_manager = get_challenge_manager().await;
    let backup_storage = BackupStorage::new(environment, s3_client.clone());
    let factor_lookup =
        backup_service::factor_lookup::FactorLookup::new(environment, dynamodb_client);
    let oidc_token_verifier =
        backup_service::oidc_token_verifier::OidcTokenVerifier::new(environment);

    backup_service::handler(environment)
        .finish_api(&mut Default::default())
        .layer(Extension(environment))
        .layer(Extension(s3_client))
        .layer(Extension(challenge_manager))
        .layer(Extension(backup_storage))
        .layer(Extension(factor_lookup))
        .layer(Extension(oidc_token_verifier))
}

pub async fn send_post_request(route: &str, payload: serde_json::Value) -> Response {
    let app = get_test_router(None).await;
    app.oneshot(
        Request::builder()
            .uri(route)
            .method("POST")
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .unwrap(),
    )
    .await
    .unwrap()
}

/// Send a POST request with multipart form data
pub async fn send_post_request_with_multipart(
    route: &str,
    payload: serde_json::Value,
    file: Bytes,
    environment: Option<Environment>,
) -> Response {
    let environment = environment.unwrap_or_else(|| Environment::development(None));
    // Multipart form data is structured as:
    // --boundary
    // Content-Disposition: form-data; name="payload"
    // Content-Type: application/json
    //
    // <JSON payload>
    //
    // --boundary
    // Content-Disposition: form-data; name="backup"; filename="backup.bin"
    // Content-Type: application/octet-stream
    //
    // <file bytes>
    //
    // --boundary--
    let boundary = format!("Boundary-{}", Uuid::new_v4());
    let mut body_bytes = Vec::new();

    // Start boundary
    body_bytes.extend_from_slice(b"--");
    body_bytes.extend_from_slice(boundary.as_bytes());
    body_bytes.extend_from_slice(b"\r\n");

    // JSON part
    body_bytes.extend_from_slice(b"Content-Disposition: form-data; name=\"payload\"\r\n");
    body_bytes.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
    body_bytes.extend_from_slice(payload.to_string().as_bytes());
    body_bytes.extend_from_slice(b"\r\n");

    // File part
    body_bytes.extend_from_slice(b"--");
    body_bytes.extend_from_slice(boundary.as_bytes());
    body_bytes.extend_from_slice(b"\r\n");
    body_bytes.extend_from_slice(
        b"Content-Disposition: form-data; name=\"backup\"; filename=\"backup.bin\"\r\n",
    );
    body_bytes.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body_bytes.extend_from_slice(&file);
    body_bytes.extend_from_slice(b"\r\n");

    // End boundary
    body_bytes.extend_from_slice(b"--");
    body_bytes.extend_from_slice(boundary.as_bytes());
    body_bytes.extend_from_slice(b"--\r\n");

    let req = Request::builder()
        .uri(route)
        .method("POST")
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={}", boundary),
        )
        .body(Body::from(body_bytes))
        .unwrap();

    let app = get_test_router(Some(environment)).await;
    app.oneshot(req).await.unwrap()
}

// Get a passkey challenge response from the server
pub async fn get_passkey_challenge() -> serde_json::Value {
    let challenge_response = send_post_request(
        "/create/challenge/passkey",
        json!({
            "name": "MOCK USERNAME",
            "displayName": "MOCK DISPLAY NAME",
            "platform": "IOS"
        }),
    )
    .await;
    let challenge_response: Bytes = challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    serde_json::from_slice(&challenge_response).unwrap()
}

// Get a keypair challenge response from the server that's used for OIDC and Keypair authentication
pub async fn get_keypair_challenge() -> serde_json::Value {
    let challenge_response = send_post_request("/create/challenge/keypair", json!({})).await;
    let challenge_response: Bytes = challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    serde_json::from_slice(&challenge_response).unwrap()
}

/// Create a new passkey credential by solving a challenge. Returns the credential as a JSON value.
pub async fn make_credential_from_passkey_challenge(
    passkey_client: &mut MockPasskeyClient,
    challenge_response: &serde_json::Value,
) -> serde_json::Value {
    let credential_input: passkey::types::webauthn::CredentialCreationOptions =
        serde_json::from_value(challenge_response["challenge"].clone()).unwrap();
    let credential = passkey_client
        .register(
            Url::parse("https://keys.world.app").unwrap(),
            credential_input,
            passkey::client::DefaultClientData,
        )
        .await
        .unwrap();
    serde_json::to_value(credential).unwrap()
}

/// Get a passkey retrieval challenge response from the server.
pub async fn get_passkey_retrieval_challenge() -> serde_json::Value {
    let challenge_response = send_post_request("/retrieve/challenge/passkey", json!({})).await;
    let challenge_response: Bytes = challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    serde_json::from_slice(&challenge_response).unwrap()
}

/// Authenticate using a passkey client with a retrieval challenge. Returns the credential as a JSON value.
pub async fn authenticate_with_passkey_challenge(
    passkey_client: &mut MockPasskeyClient,
    challenge_response: &serde_json::Value,
) -> serde_json::Value {
    let credential_request_options: passkey::types::webauthn::CredentialRequestOptions =
        serde_json::from_value(challenge_response["challenge"].clone()).unwrap();
    let credential = passkey_client
        .authenticate(
            &Url::parse("https://keys.world.app").unwrap(),
            credential_request_options,
            passkey::client::DefaultClientData,
        )
        .await
        .unwrap();
    serde_json::to_value(credential).unwrap()
}

/// Create a test backup with a passkey credential. Returns both the credential JSON and the create response.
pub async fn create_test_backup(
    passkey_client: &mut MockPasskeyClient,
    backup_data: &[u8],
) -> (serde_json::Value, Response) {
    // Get a challenge from the server
    let challenge_response = get_passkey_challenge().await;

    // Register a credential by solving the challenge
    let credential =
        make_credential_from_passkey_challenge(passkey_client, &challenge_response).await;

    // Send the credential to the server to create a backup
    let create_response = send_post_request_with_multipart(
        "/create",
        json!({
            "solvedChallenge": {
                "kind": "PASSKEY",
                "credential": credential.clone(),
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
        }),
        Bytes::from(backup_data.to_vec()),
        None,
    )
    .await;

    (credential, create_response)
}

/// Generate a P256 keypair that's used as a temporary session keypair in OIDC authentication
/// and as a permanent keypair in the keypair backups.
pub fn generate_keypair() -> (String, SecretKey) {
    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());
    (public_key, secret_key)
}

/// Signs a challenge from the */challenge/keypair using the generated keypair.
pub fn sign_keypair_challenge(secret_key: &SecretKey, challenge: &str) -> String {
    let signing_key = SigningKey::from(secret_key.clone());
    let challenge = STANDARD.decode(challenge).unwrap();
    let signature: Signature = signing_key.sign(&challenge);
    let signature_der = signature.to_der();
    STANDARD.encode(signature_der)
}

/// Checks that a backup file with the given ID and expected content exists in S3.
/// Returns the actual backup content as a vector of bytes.
pub async fn verify_s3_backup_exists(backup_id: &str, expected_content: &[u8]) -> Vec<u8> {
    let s3_client = get_test_s3_client().await;
    let bucket_name = "backup-service-bucket";
    let backup_key = format!("{}/backup", backup_id);

    let backup = s3_client
        .get_object()
        .bucket(bucket_name)
        .key(&backup_key)
        .send()
        .await
        .unwrap();

    let backup_content = backup.body.collect().await.unwrap().to_vec();
    assert_eq!(backup_content, expected_content);

    backup_content
}

/// Checks that a backup metadata file with the given ID exists in S3.
/// Returns the metadata as a serde_json::Value.
pub async fn verify_s3_metadata_exists(backup_id: &str) -> serde_json::Value {
    let s3_client = get_test_s3_client().await;
    let bucket_name = "backup-service-bucket";
    let metadata_key = format!("{}/metadata", backup_id);

    let metadata_response = s3_client
        .get_object()
        .bucket(bucket_name)
        .key(&metadata_key)
        .send()
        .await
        .unwrap();

    let metadata_content = metadata_response.body.collect().await.unwrap().to_vec();
    serde_json::from_slice(&metadata_content).unwrap()
}
