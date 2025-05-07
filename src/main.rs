use aws_sdk_s3::Client as S3Client;
use backup_service::backup_storage::BackupStorage;
use backup_service::challenge_manager::ChallengeManager;
use backup_service::factor_lookup::FactorLookup;
use backup_service::kms_jwe::KmsJwe;
use backup_service::oidc_token_verifier::OidcTokenVerifier;
use backup_service::server;
use backup_service::sync_factor_token::SyncFactorTokenManager;
use backup_service::types::Environment;
use dotenvy::dotenv;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let environment = Environment::from_env();
    let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
    let dynamodb_client = Arc::new(aws_sdk_dynamodb::Client::new(
        &environment.aws_config().await,
    ));

    // Initialize challenge manager
    let kms_client = aws_sdk_kms::Client::new(&environment.aws_config().await);
    let kms_jwe = KmsJwe::new(environment.challenge_token_kms_key(), kms_client);
    let challenge_manager = ChallengeManager::new(environment.challenge_token_ttl(), kms_jwe);

    let backup_storage = BackupStorage::new(environment, s3_client.clone());
    let factor_lookup = FactorLookup::new(environment, dynamodb_client.clone());
    let oidc_token_verifier = OidcTokenVerifier::new(environment);
    let sync_factor_token_manager = SyncFactorTokenManager::new(
        environment,
        environment.sync_factor_token_ttl(),
        dynamodb_client.clone(),
    );

    server::start(
        environment,
        s3_client,
        challenge_manager,
        backup_storage,
        factor_lookup,
        oidc_token_verifier,
        sync_factor_token_manager,
    )
    .await
}
