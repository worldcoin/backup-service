use aws_sdk_s3::Client as S3Client;
use axum::http::{Request, StatusCode};
use axum::Extension;
use backup_service::types::Environment;
use dotenvy::dotenv;
use http_body_util::BodyExt;
use serde_json::json;
use tower::util::ServiceExt;

// TODO/FIXME: Move to a testlib library

async fn get_test_s3_client() -> S3Client {
    let environment = Environment::Development;
    S3Client::from_conf(environment.s3_client_config().await)
}

async fn get_test_router() -> axum::Router {
    dotenv().ok();
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

#[tokio::test]
async fn test_create_backup() {
    let app = get_test_router().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/create-backup")
                .method("POST")
                .body(json!({}).to_string())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(response, json!({}));
}
