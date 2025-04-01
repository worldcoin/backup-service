use aws_sdk_s3::Client as S3Client;
use axum::Extension;
use backup_service::challenge_manager::ChallengeManager;
use backup_service::kms_jwe::KmsJwe;
use backup_service::types::Environment;

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
        .init();

    let environment = Environment::Development;
    let s3_client = get_test_s3_client().await;
    let challenge_manager = get_challenge_manager().await;

    backup_service::handler()
        .finish_api(&mut Default::default())
        .layer(Extension(environment))
        .layer(Extension(s3_client))
        .layer(Extension(challenge_manager))
}
