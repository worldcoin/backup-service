mod common;

use crate::common::send_post_request;
use axum::http::StatusCode;
use http_body_util::BodyExt;
use serde_json::json;

#[tokio::test]
async fn test_retrieve_challenge() {
    let response = send_post_request("/retrieve/challenge/passkey", json!({})).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        response["challenge"]["publicKey"]["rpId"].as_str(),
        Some("keys.world.org")
    );
    assert_eq!(
        response["challenge"]["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .len(),
        43
    );
    assert_eq!(
        response["challenge"]["publicKey"]["authenticatorSelection"]["userVerification"].as_str(),
        Some("required")
    );
    assert_eq!(
        response["challenge"]["publicKey"]["extensions"]["uvm"].as_bool(),
        Some(true)
    );
    assert_eq!(
        response["challenge"]["mediation"].as_str(),
        Some("conditional")
    );

    assert!(response["token"].as_str().is_some());
}
