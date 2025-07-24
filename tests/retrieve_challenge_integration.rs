mod common;

use crate::common::{get_test_router, send_post_request};
use axum::{extract::Request, http::StatusCode};
use backup_service::attestation_gateway::ATTESTATION_GATEWAY_HEADER;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn test_retrieve_challenge_passkey() {
    let response = send_post_request("/v1/retrieve/challenge/passkey", json!({})).await;

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
    let response = send_post_request("/v1/retrieve/challenge/keypair", json!({})).await;

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

#[ignore = "FIXME: Remove ignore. We are temporarily not enforcing the presence of attestation-token, while the roll out of attestation is in progress."]
#[tokio::test]
async fn test_retrieve_challenge_without_attestation() {
    let endpoints = ["/v1/retrieve/from-challenge"];

    for endpoint in endpoints {
        let response = send_post_request(endpoint, json!({})).await;

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Expected BAD_REQUEST from {}",
            endpoint
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            response["error"]["code"], "missing_attestation_token_header",
            "error.code mismatch on {}",
            endpoint
        );
        assert_eq!(
            response["error"]["message"], "missing_attestation_token_header",
            "error.message mismatch on {}",
            endpoint
        );
    }
}

#[tokio::test]
async fn test_retrieve_challenge_with_incorrect_attestation() {
    let endpoints = ["/v1/retrieve/from-challenge"];

    for endpoint in endpoints {
        let app = get_test_router(None, None).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri(endpoint)
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .header(ATTESTATION_GATEWAY_HEADER, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30")
                    .body(json!({}).to_string())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Expected BAD_REQUEST from {}",
            endpoint
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            response["error"]["code"], "invalid_attestation_token",
            "error.code mismatch on {}",
            endpoint
        );
        assert_eq!(
            response["error"]["message"], "invalid_attestation_token",
            "error.message mismatch on {}",
            endpoint
        );
    }
}
