mod common;

use crate::common::send_post_request;
use http_body_util::BodyExt;
use serde_json::json;

#[tokio::test]
async fn test_add_factor_challenge_shapes() {
    // OIDC new-factor returns string challenges
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

    // PASSKEY_REGISTRATION returns object challenge for new-factor
    let passkey_resp = send_post_request(
        "/v1/add-factor/challenge",
        json!({
            "newFactor": { "kind": "PASSKEY_REGISTRATION" }
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
}
