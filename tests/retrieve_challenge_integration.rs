mod common;

use crate::common::send_post_request;
use axum::http::StatusCode;
use http_body_util::BodyExt;
use serde_json::json;

#[tokio::test]
async fn test_retrieve_challenge_passkey() {
    let response = send_post_request("/retrieve/challenge/passkey", json!({})).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        response["challenge"]["publicKey"]["rpId"].as_str(),
        Some("keys.world.app")
    );
    assert_eq!(
        response["challenge"]["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .len(),
        43
    );
    assert_eq!(
        response["challenge"]["publicKey"]["userVerification"].as_str(),
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

#[tokio::test]
async fn test_retrieve_challenge_keypair() {
    let response = send_post_request("/retrieve/challenge/keypair", json!({})).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Check that the challenge is a string of appropriate length (32 bytes Base64 encoded)
    assert!(response["challenge"].is_string());
    let challenge = response["challenge"].as_str().unwrap();
    assert!(challenge.len() >= 42 && challenge.len() <= 44); // Base64 encoding of 32 bytes

    // Check that token is present
    assert!(response["token"].is_string());
    assert!(response["token"].as_str().unwrap().len() > 10);
}
