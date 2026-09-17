use aws_sdk_s3::Client as S3Client;
use backup_service::attestation_gateway::AttestationGateway;
use backup_service::auth::AuthHandler;
use backup_service::backup_storage::BackupStorage;
use backup_service::challenge_manager::ChallengeManager;
use backup_service::environment::Environment;
use backup_service::factor_lookup::FactorLookup;
use backup_service::kms_jwe::KmsJwe;
use backup_service::oidc_token_verifier::OidcTokenVerifier;
use backup_service::redis_cache::RedisCacheManager;
use backup_service::server;
use dotenvy::dotenv;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    dotenv().ok();
    let use_json = std::env::var("JSON_LOG_FORMAT").is_ok();
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(env_filter);

    if use_json {
        builder.json().flatten_event(true).init();
    } else {
        builder.init();
    }

    backup_service::shutdown::install_signal_handlers()?;

    tracing::info!("...Starting backup service");

    let environment = Environment::from_env();

    // Degraded security mode worth one line per process start: while the bridge is open, legacy
    // clients' add-factor approvals are not bound to the new factor (#253). Evaluated here so an
    // open bridge, or a mistyped sunset (logged as an error by the getter), is visible at startup
    // rather than only once a legacy request arrives.
    let legacy_bridge = environment.legacy_passkey_payload_bridge();
    if legacy_bridge.is_open() {
        tracing::warn!(
            message = "add-factor legacy passkey payload bridge is open; legacy clients are not covered by the material binding",
            bridge = %legacy_bridge,
        );
    }

    let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
    let dynamodb_client = Arc::new(aws_sdk_dynamodb::Client::new(
        &environment.aws_config().await,
    ));
    let attestation_gateway = Arc::new(AttestationGateway::new(
        environment.attestation_gateway_host().to_string(),
        &environment,
        environment.disable_attestation_gateway_enforcement(),
    ));

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
