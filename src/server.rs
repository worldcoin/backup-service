use crate::attestation_gateway::AttestationGateway;
use crate::challenge_manager::ChallengeManager;
use crate::factor_lookup::FactorLookup;
use crate::oidc_token_verifier::OidcTokenVerifier;
use crate::redis_cache::RedisCacheManager;
use crate::routes;
use crate::types::Environment;
use crate::{auth::AuthHandler, backup_storage::BackupStorage};
use aide::openapi::{ApiKeyLocation, Info, OpenApi, ReferenceOr, SecurityScheme};
use aws_sdk_s3::Client as S3Client;
use axum::Extension;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::Level;

/// Starts the backup service.
///
/// # Errors
/// - Returns an error if there are any issues starting the server. In practice, this will terminate the process.
#[allow(clippy::too_many_arguments)] // logical module separation is preferred
pub async fn start(
    environment: Environment,
    s3_client: Arc<S3Client>,
    challenge_manager: Arc<ChallengeManager>,
    backup_storage: Arc<BackupStorage>,
    factor_lookup: Arc<FactorLookup>,
    oidc_token_verifier: Arc<OidcTokenVerifier>,
    redis_cache_manager: Arc<RedisCacheManager>,
    auth_handler: AuthHandler,
    attestation_gateway: Arc<AttestationGateway>,
) -> anyhow::Result<()> {
    let mut openapi = OpenApi {
        info: Info {
            title: "Backup Service".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    // register attestation-token as a header based security scheme
    openapi
        .components
        .get_or_insert_with(Default::default)
        .security_schemes
        .insert(
            "AttestationToken".to_string(),
            ReferenceOr::Item(SecurityScheme::ApiKey {
                name: "attestation-token".into(), // header name
                location: ApiKeyLocation::Header, // mark as header
                description: Some("An Attestation Gateway Token is used to prove provenance of requests from attested mobile applications.".into()),
                extensions: Default::default(),
            }),
        );

    let router = routes::handler(environment)
        .finish_api(&mut openapi)
        .layer(Extension(environment))
        .layer(Extension(s3_client))
        .layer(Extension(openapi))
        .layer(Extension(challenge_manager))
        .layer(Extension(backup_storage))
        .layer(Extension(factor_lookup))
        .layer(Extension(oidc_token_verifier))
        .layer(Extension(redis_cache_manager))
        .layer(Extension(auth_handler))
        .layer(Extension(attestation_gateway))
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(tower_http::trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(tower_http::timeout::TimeoutLayer::new(
            std::time::Duration::from_secs(30),
        ));

    // By default Axum enforces a 2MB limit on the request body. Explicitly for the routes that upload or update backups,
    // a higher limit is set on a per-route basis.
    // Reference: <https://docs.rs/axum/latest/axum/extract/struct.DefaultBodyLimit.html>

    let addr = std::net::SocketAddr::from((
        [0, 0, 0, 0],
        std::env::var("PORT").map_or(Ok(8000), |p| p.parse())?,
    ));

    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("✅ Backup service started on http://{addr}");

    axum::serve(listener, router.into_make_service())
        .await
        .map_err(anyhow::Error::from)
}
