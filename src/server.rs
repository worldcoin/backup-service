use crate::challenge_manager::ChallengeManager;
use crate::routes;
use crate::types::Environment;
use aide::openapi::{Info, OpenApi};
use aws_sdk_s3::Client as S3Client;
use axum::Extension;
use tokio::net::TcpListener;

pub async fn start(
    environment: Environment,
    s3_client: S3Client,
    challenge_manager: ChallengeManager,
) -> anyhow::Result<()> {
    let mut openapi = OpenApi {
        info: Info {
            title: "Backup Service".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let router = routes::handler(environment)
        .finish_api(&mut openapi)
        .layer(Extension(environment))
        .layer(Extension(s3_client))
        .layer(Extension(openapi))
        .layer(Extension(challenge_manager))
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(tower_http::timeout::TimeoutLayer::new(
            std::time::Duration::from_secs(30),
        ));

    let addr = std::net::SocketAddr::from((
        [127, 0, 0, 1],
        std::env::var("PORT").map_or(Ok(8000), |p| p.parse())?,
    ));

    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("🔄 Backup service started on http://{addr}");

    axum::serve(listener, router.into_make_service())
        .await
        .map_err(anyhow::Error::from)
}
