#![allow(dead_code)]

mod passkey_client;

use aws_sdk_s3::Client as S3Client;
use axum::body::Bytes;
use axum::http::Request;
use axum::response::Response;
use axum::Extension;
use backup_service::challenge_manager::ChallengeManager;
use backup_service::kms_jwe::KmsJwe;
use backup_service::types::Environment;
use http_body_util::BodyExt;
#[allow(unused_imports)]
pub use passkey_client::*;
use serde_json::json;
use tower::ServiceExt;
use url::Url;

pub async fn get_test_s3_client() -> S3Client {
    let environment = Environment::Development;
    S3Client::from_conf(environment.s3_client_config().await)
}

pub async fn get_challenge_manager() -> ChallengeManager {
    let environment = Environment::Development;
    let kms_client = aws_sdk_kms::Client::new(&environment.aws_config().await);
    let kms_jwe = KmsJwe::new(environment.challenge_token_kms_key(), kms_client);
    ChallengeManager::new(environment.challenge_token_ttl(), kms_jwe)
}

pub async fn get_test_router() -> axum::Router {
    dotenvy::from_path(".env.example").ok();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init()
        .ok();

    let environment = Environment::Development;
    let s3_client = get_test_s3_client().await;
    let challenge_manager = get_challenge_manager().await;

    backup_service::handler()
        .finish_api(&mut Default::default())
        .layer(Extension(environment))
        .layer(Extension(s3_client))
        .layer(Extension(challenge_manager))
}

pub async fn send_post_request(route: &str, payload: serde_json::Value) -> Response {
    let app = get_test_router().await;
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

// Get a passkey challenge response from the server
pub async fn get_passkey_challenge() -> serde_json::Value {
    let challenge_response = send_post_request(
        "/create/challenge/passkey",
        json!({
            "name": "MOCK USERNAME",
            "displayName": "MOCK DISPLAY NAME",
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

/// Create a new passkey credential by solving a challenge. Returns the credential as a JSON value.
pub async fn make_credential_from_passkey_challenge(
    passkey_client: &mut MockPasskeyClient,
    challenge_response: &serde_json::Value,
) -> serde_json::Value {
    let credential_input: passkey::types::webauthn::CredentialCreationOptions =
        serde_json::from_value(challenge_response["challenge"].clone()).unwrap();
    let credential = passkey_client
        .register(
            Url::parse("https://keys.world.org").unwrap(),
            credential_input,
            passkey::client::DefaultClientData,
        )
        .await
        .unwrap();
    serde_json::to_value(credential).unwrap()
}
