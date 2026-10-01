mod common;

use crate::common::send_post_request;
use http_body_util::BodyExt;
use serde_json::json;

#[tokio::test]
async fn test_add_factor_challenge_response_shapes() {
    let oidc_resp = send_post_request(
        "/v1/add-factor/challenge",
        json!({
            "newFactor": { "kind": "OIDC_ACCOUNT", "oidcToken": "opaque" }
        }),
    )
    .await;
    assert_eq!(oidc_resp.status(), http::StatusCode::OK);
    let body = oidc_resp.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(value["existingFactorChallenge"].is_string());
    assert!(value["existingFactorToken"].is_string());
    assert!(value["newFactorChallenge"].is_string());
    assert!(value["newFactorToken"].is_string());

    let passkey_resp = send_post_request(
        "/v1/add-factor/challenge",
        json!({
            "newFactor": { "kind": "PASSKEY_REGISTRATION", "platform": "IOS" }
        }),
    )
    .await;
    assert_eq!(passkey_resp.status(), http::StatusCode::OK);
    let body = passkey_resp.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(value["existingFactorChallenge"].is_string());
    assert!(value["existingFactorToken"].is_string());
    assert!(value["newFactorChallenge"].is_object());
    assert!(value["newFactorToken"].is_string());

    let android_resp = send_post_request(
        "/v1/add-factor/challenge",
        json!({
            "newFactor": { "kind": "PASSKEY_REGISTRATION", "platform": "ANDROID" }
        }),
    )
    .await;
    assert_eq!(android_resp.status(), http::StatusCode::OK);
    let body = android_resp.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(value["newFactorChallenge"].is_object());
    assert!(value["newFactorChallenge"]["publicKey"].is_object());
    assert!(value["newFactorToken"].is_string());

    let mut passkey_client = backup_service_test_utils::get_mock_passkey_client();
    let credential = backup_service_test_utils::make_credential_from_passkey_challenge(
        &mut passkey_client,
        &json!({ "challenge": value["newFactorChallenge"].clone() }),
    )
    .await;
    assert!(credential["id"].is_string() || credential["rawId"].is_string());
}
