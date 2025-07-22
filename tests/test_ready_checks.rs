use axum::extract::Request;
use http::StatusCode;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

use crate::common::get_test_router;

mod common;

#[tokio::test]
async fn test_ready_endpoint() {
    dotenvy::from_filename(".env.example").unwrap();
    let app = get_test_router(None, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .method("POST")
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer not_a_real_secret")
                .body(json!({}).to_string())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let response_body = response.into_body().collect().await.unwrap().to_bytes();
    let response_body: serde_json::Value = serde_json::from_slice(&response_body).unwrap();
    assert_eq!(response_body, json!({ "status": "ok" }));
}

#[tokio::test]
async fn test_cannot_call_ready_endpoint_unauthenticated() {
    dotenvy::from_filename(".env.example").unwrap();
    let response = common::send_post_request("/ready", json!({})).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_cannot_call_ready_endpoint_with_wrong_auth_token() {
    dotenvy::from_filename(".env.example").unwrap();
    let app = get_test_router(None, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .method("POST")
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer wrong_token")
                .body(json!({}).to_string())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
