use aws_sdk_s3::Client as S3Client;
use axum::Extension;
use backup_service::types::Environment;

pub async fn get_test_s3_client() -> S3Client {
    let environment = Environment::Development;
    S3Client::from_conf(environment.s3_client_config().await)
}

pub async fn get_test_router() -> axum::Router {
    dotenvy::from_path(".env.example").ok();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let environment = Environment::Development;
    let s3_client = get_test_s3_client().await;

    backup_service::handler()
        .finish_api(&mut Default::default())
        .layer(Extension(environment))
        .layer(Extension(s3_client))
}
