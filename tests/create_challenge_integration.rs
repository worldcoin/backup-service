mod common;

use crate::common::send_post_request;
use axum::http::StatusCode;
use http_body_util::BodyExt;
use serde_json::json;

#[tokio::test]
async fn test_create_challenge() {
    let response = send_post_request(
        "/v1/create/challenge/passkey",
        json!({
            "name": "MOCK USERNAME",
            "displayName": "MOCK DISPLAY NAME",
            "platform": "IOS",
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        response["challenge"]["publicKey"]["rp"]["name"].as_str(),
        Some("World App")
    );
    assert_eq!(
        response["challenge"]["publicKey"]["rp"]["id"].as_str(),
        Some("keys.world.app")
    );
    assert_eq!(
        response["challenge"]["publicKey"]["user"]["name"].as_str(),
        Some("MOCK USERNAME")
    );
    assert_eq!(
        response["challenge"]["publicKey"]["user"]["displayName"].as_str(),
        Some("MOCK DISPLAY NAME")
    );
    assert_eq!(
        response["challenge"]["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .len(),
        43
    );
    assert_eq!(
        response["challenge"]["publicKey"]["pubKeyCredParams"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        response["challenge"]["publicKey"]["timeout"].as_u64(),
        Some(300000)
    );
    assert_eq!(
        response["challenge"]["publicKey"]["authenticatorSelection"]["residentKey"].as_str(),
        Some("discouraged")
    );
    assert_eq!(
        response["challenge"]["publicKey"]["authenticatorSelection"]["requireResidentKey"]
            .as_bool(),
        Some(false)
    );
    assert_eq!(
        response["challenge"]["publicKey"]["authenticatorSelection"]["userVerification"].as_str(),
        Some("required")
    );
    assert_eq!(
        response["challenge"]["publicKey"]["attestation"].as_str(),
        Some("none")
    );
    assert_eq!(
        response["challenge"]["publicKey"]["extensions"]["credentialProtectionPolicy"].as_str(),
        Some("userVerificationRequired")
    );
    assert_eq!(
        response["challenge"]["publicKey"]["extensions"]["enforceCredentialProtectionPolicy"]
            .as_bool(),
        Some(false)
    );
    assert_eq!(
        response["challenge"]["publicKey"]["extensions"]["uvm"].as_bool(),
        Some(true)
    );

    assert!(response["token"].as_str().is_some());
}
