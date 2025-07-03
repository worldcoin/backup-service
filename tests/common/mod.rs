#![allow(dead_code)]

mod passkey_client;

use aws_sdk_s3::Client as S3Client;
use axum::body::{Body, Bytes};
use axum::http::Request;
use axum::response::Response;
use axum::Extension;
use backup_service::attestation_gateway::{
    AttestationGateway, AttestationGatewayConfig, GenerateRequestHashInput,
    ATTESTATION_GATEWAY_HEADER,
};
use backup_service::auth::AuthHandler;
use backup_service::backup_storage::BackupStorage;
use backup_service::challenge_manager::ChallengeManager;
use backup_service::kms_jwe::KmsJwe;
use backup_service::types::{Environment, OidcProvider};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{Duration, Utc};
use http::Method;
use http_body_util::BodyExt;
use josekit::jwk::alg::ec::EcCurve;
use josekit::jwk::Jwk;
use josekit::jws::{JwsHeader, ES256};
use josekit::jwt::{self, JwtPayload};
use openidconnect::SubjectIdentifier;
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

pub async fn get_challenge_manager() -> Arc<ChallengeManager> {
    let environment = Environment::development(None);
    let kms_client = aws_sdk_kms::Client::new(&environment.aws_config().await);
    let kms_jwe = KmsJwe::new(environment.challenge_token_kms_key(), kms_client);
    Arc::new(ChallengeManager::new(
        environment.challenge_token_ttl(),
        kms_jwe,
    ))
}

pub async fn get_test_router(
    environment: Option<Environment>,
    attestation_gateway_base_url_override: Option<&str>,
) -> axum::Router {
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
    let backup_storage = Arc::new(BackupStorage::new(environment, s3_client.clone()));
    let factor_lookup = Arc::new(backup_service::factor_lookup::FactorLookup::new(
        environment,
        dynamodb_client.clone(),
    ));
    let dynamo_cache_manager = Arc::new(backup_service::dynamo_cache::DynamoCacheManager::new(
        environment,
        environment.cache_default_ttl(),
        dynamodb_client.clone(),
    ));
    let oidc_token_verifier =
        Arc::new(backup_service::oidc_token_verifier::OidcTokenVerifier::new(
            environment,
            dynamo_cache_manager.clone(),
        ));

    let auth_handler = AuthHandler::new(
        backup_storage.clone(),
        dynamo_cache_manager.clone(),
        challenge_manager.clone(),
        environment,
        factor_lookup.clone(),
        oidc_token_verifier.clone(),
    );

    let attestation_gateway = Arc::new(AttestationGateway::new(AttestationGatewayConfig {
        base_url: attestation_gateway_base_url_override
            .unwrap_or(environment.attestation_gateway_host())
            .to_string(),
        env: environment,
        enabled: true,
    }));

    backup_service::handler(environment)
        .finish_api(&mut Default::default())
        .layer(Extension(environment))
        .layer(Extension(s3_client))
        .layer(Extension(challenge_manager))
        .layer(Extension(backup_storage))
        .layer(Extension(factor_lookup))
        .layer(Extension(oidc_token_verifier))
        .layer(Extension(dynamo_cache_manager))
        .layer(Extension(auth_handler))
        .layer(Extension(attestation_gateway))
}

pub async fn send_post_request(route: &str, payload: serde_json::Value) -> Response {
    let app = get_test_router(None, None).await;
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

/// Send a POST request with a specific environment. Helpful when trying to fetch a backup from
/// an environment that's attached to a specific mock JWT issuer.
pub async fn send_post_request_with_environment(
    route: &str,
    payload: serde_json::Value,
    environment: Option<Environment>,
) -> Response {
    let environment = environment.unwrap_or_else(|| Environment::development(None));
    let app = get_test_router(Some(environment), None).await;
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

    let app = get_test_router(Some(environment), None).await;
    app.oneshot(req).await.unwrap()
}

pub async fn send_post_request_with_bypass_attestation_token(
    route: &str,
    payload: serde_json::Value,
    environment: Option<Environment>,
) -> Response {
    let app = get_test_router(environment, None).await;
    app.oneshot(
        Request::builder()
            .uri(route)
            .method("POST")
            .header("Content-Type", "application/json")
            .header(
                ATTESTATION_GATEWAY_HEADER,
                std::env::var("ATTESTATION_GATEWAY_BYPASS_TOKEN")
                    .expect("ATTESTATION_GATEWAY_BYPASS_TOKEN must be set"),
            )
            .body(payload.to_string())
            .unwrap(),
    )
    .await
    .unwrap()
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

// Get a keypair challenge response from the server that's used for OIDC and Keypair registration
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

// Get a keypair challenge response from the server that's used for OIDC and Keypair authentication
pub async fn get_keypair_retrieve_challenge() -> serde_json::Value {
    let challenge_response = send_post_request("/retrieve/challenge/keypair", json!({})).await;
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

// Get sync factor as keypair that signs a challenge from the server.
// Returns (factor, challenge token, secret key).
pub async fn make_sync_factor() -> (serde_json::Value, String, SecretKey) {
    // Get a challenge from the server
    let challenge_response = get_keypair_challenge().await;

    // Generate keypair and sign the challenge
    let (public_key, secret_key) = generate_keypair();
    let signature = sign_keypair_challenge(
        &secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    (
        json!({
            "kind": "EC_KEYPAIR",
            "publicKey": public_key,
            "signature": signature,
        }),
        challenge_response["token"].as_str().unwrap().to_string(),
        secret_key,
    )
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

/// Get a keypair retrieval challenge response from the server.
pub async fn get_keypair_retrieval_challenge() -> serde_json::Value {
    let challenge_response = send_post_request("/retrieve/challenge/keypair", json!({})).await;
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

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    // Send the credential to the server to create a backup
    let create_response = send_post_request_with_multipart(
        "/create",
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
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_challenge_token,
        }),
        Bytes::from(backup_data.to_vec()),
        None,
    )
    .await;

    (credential, create_response)
}

/// Create a test backup with an EC keypair. Returns the keypair (public_key, secret_key) and the create response.
pub async fn create_test_backup_with_keypair(
    backup_data: &[u8],
) -> ((String, SecretKey), Response) {
    // Get a challenge from the server
    let challenge_response = get_keypair_challenge().await;

    // Generate keypair and sign the challenge
    let keypair = generate_keypair();
    let signature = sign_keypair_challenge(
        &keypair.1,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    // Send the keypair signature to the server to create a backup
    let create_response = send_post_request_with_multipart(
        "/create",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": keypair.0.clone(),
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_challenge_token,
        }),
        Bytes::from(backup_data.to_vec()),
        None,
    )
    .await;

    (keypair, create_response)
}

/// Create a test backup with an EC keypair, returning the sync factor's secret key as well.
/// Returns:
/// - The main keypair (public_key, secret_key)
/// - The create response
/// - The sync factor's secret key
pub async fn create_test_backup_with_sync_keypair(
    backup_data: &[u8],
) -> ((String, SecretKey), Response, SecretKey) {
    // Get a challenge from the server
    let challenge_response = get_keypair_challenge().await;

    // Generate keypair and sign the challenge
    let keypair = generate_keypair();
    let signature = sign_keypair_challenge(
        &keypair.1,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Create a sync factor
    let (sync_factor, sync_challenge_token, sync_secret_key) = make_sync_factor().await;

    // Send the keypair signature to the server to create a backup
    let create_response = send_post_request_with_multipart(
        "/create",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": keypair.0.clone(),
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": {
                "kind": "PRF",
                "encryptedKey": "ENCRYPTED_KEY",
            },
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_challenge_token,
        }),
        Bytes::from(backup_data.to_vec()),
        None,
    )
    .await;

    (keypair, create_response, sync_secret_key)
}

pub struct TestBackupWithOidcAccount {
    pub public_key: String,
    pub secret_key: SecretKey,
    pub oidc_token: String,
    pub environment: Environment,
    pub response: Response,
    pub oidc_server: backup_service::mock_oidc_server::MockOidcServer,
}

/// Create a test backup with an OIDC account.
pub async fn create_test_backup_with_oidc_account(
    subject: &str,
    backup_data: &[u8],
) -> TestBackupWithOidcAccount {
    // Setup OIDC server
    let oidc_server = backup_service::mock_oidc_server::MockOidcServer::new().await;
    let environment =
        Environment::development(Some(oidc_server.server.socket_address().port() as usize));

    // Get a challenge from the server
    let challenge_response = get_keypair_challenge().await;

    // Generate temporary keypair for OIDC authentication and sign the challenge
    let (public_key, secret_key) = generate_keypair();

    // Generate OIDC token
    let oidc_token = oidc_server.generate_token(
        environment,
        OidcProvider::Google,
        Some(SubjectIdentifier::new(subject.to_string())),
        &public_key,
    );

    let signature = sign_keypair_challenge(
        &secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Create a sync factor
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    // Send the OIDC token to the server to create a backup
    let create_response = send_post_request_with_multipart(
        "/create",
        json!({
            "authorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": {
                    "kind": "GOOGLE",
                    "token": oidc_token.clone(),
                },
                "publicKey": public_key.clone(),
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
        }),
        Bytes::from(backup_data.to_vec()),
        Some(environment),
    )
    .await;

    TestBackupWithOidcAccount {
        public_key,
        secret_key,
        oidc_token,
        environment,
        response: create_response,
        oidc_server,
    }
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

pub fn generate_test_attestation_token(body: &serde_json::Value, path: &str) -> (Jwk, String) {
    let mut jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
    jwk.set_key_id("integration-test-kid");

    let request_hash_input = GenerateRequestHashInput {
        path_uri: path.to_string(),
        method: Method::POST,
        body: Some(body.to_string()),
    };

    let request_hash = AttestationGateway::compute_request_hash(&request_hash_input).unwrap();

    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    header.set_key_id("integration-test-kid");

    let mut payload = JwtPayload::new();
    payload.set_claim("jti", Some(json!(request_hash))).unwrap();
    payload.set_claim("pass", Some(json!(true))).unwrap();
    payload
        .set_claim("iss", Some(json!("attestation.worldcoin.org")))
        .unwrap();
    payload
        .set_claim("aud", Some(json!("toolsforhumanity.com")))
        .unwrap();

    let exp = Utc::now() + Duration::seconds(3600);

    payload.set_expires_at(&exp.into());
    payload.set_issued_at(&Utc::now().into());

    let signer = ES256.signer_from_jwk(&jwk).unwrap();

    let jwt = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    (jwk, jwt)
}
