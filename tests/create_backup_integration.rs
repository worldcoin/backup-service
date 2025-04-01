mod common;

use crate::common::get_test_router;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use tower::util::ServiceExt;

#[tokio::test]
async fn test_create_backup() {
    let app = get_test_router().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/create")
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
