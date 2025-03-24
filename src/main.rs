use aws_sdk_s3::Client as S3Client;
use backup_service::server;
use backup_service::types::Environment;
use dotenvy::dotenv;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let environment = Environment::from_env();
    let s3_client = S3Client::from_conf(environment.s3_client_config().await);

    server::start(environment, s3_client).await
}
