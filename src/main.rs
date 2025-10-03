use aws_sdk_s3::Client as S3Client;
use backup_service::attestation_gateway::{AttestationGateway, AttestationGatewayConfig};
use backup_service::auth::AuthHandler;
use backup_service::backup_storage::BackupStorage;
use backup_service::challenge_manager::ChallengeManager;
use backup_service::factor_lookup::FactorLookup;
use backup_service::kms_jwe::KmsJwe;
use backup_service::oidc_token_verifier::OidcTokenVerifier;
use backup_service::redis_cache::RedisCacheManager;
use backup_service::server;
use backup_service::types::Environment;
use dotenvy::dotenv;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .json()
        .flatten_event(true)
        .init();

    tracing::info!("...Starting backup service");

    let environment = Environment::from_env();
    let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
    let dynamodb_client = Arc::new(aws_sdk_dynamodb::Client::new(
        &environment.aws_config().await,
    ));
    let attestation_gateway = Arc::new(AttestationGateway::new(AttestationGatewayConfig {
        base_url: environment.attestation_gateway_host().to_string(),
        env: environment,
        enabled: environment.enable_attestation_gateway(),
    }));

    // Initialize challenge manager
    let kms_client = aws_sdk_kms::Client::new(&environment.aws_config().await);
    let kms_jwe = KmsJwe::new(environment.challenge_token_kms_key(), kms_client);
    let challenge_manager = Arc::new(ChallengeManager::new(
        environment.challenge_token_ttl(),
        kms_jwe,
    ));

    let backup_storage = Arc::new(BackupStorage::new(environment, s3_client.clone()));
    let factor_lookup = Arc::new(FactorLookup::new(environment, dynamodb_client.clone()));
    let redis_cache_manager = Arc::new(
        RedisCacheManager::new(environment, environment.cache_default_ttl())
            .await
            .expect("failed to build RedisCacheManager"),
    );

    let oidc_token_verifier = Arc::new(OidcTokenVerifier::new(
        environment,
        redis_cache_manager.clone(),
    ));

    let auth_handler = AuthHandler::new(
        backup_storage.clone(),
        redis_cache_manager.clone(),
        challenge_manager.clone(),
        environment,
        factor_lookup.clone(),
        oidc_token_verifier.clone(),
    );

    tracing::info!("Initial set up is complete.");

    server::start(
        environment,
        s3_client,
        challenge_manager,
        backup_storage,
        factor_lookup,
        oidc_token_verifier,
        redis_cache_manager,
        auth_handler,
        attestation_gateway,
    )
    .await
}
