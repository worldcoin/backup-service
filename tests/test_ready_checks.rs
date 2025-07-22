use http::StatusCode;
use http_body_util::BodyExt;
use serde_json::json;

mod common;

#[tokio::test]
async fn test_ready_endpoint() {
    let response = common::send_post_request("/ready", json!({})).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response_body = response.into_body().collect().await.unwrap().to_bytes();
    let response_body: serde_json::Value = serde_json::from_slice(&response_body).unwrap();
    assert_eq!(response_body, json!({ "status": "ok" }));
}
