mod common;

use crate::common::send_post_request;
use http_body_util::BodyExt;
use serde_json::json;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn oidc_challenge_contains_only_token_hash() {
    use backup_service::challenge_manager::{ChallengeContext, ChallengeType, NewFactorType};

    let oidc_token = "sensitive-oidc-token";
    let response = send_post_request(
        "/v1/add-factor/challenge",
        json!({ "newFactor": { "kind": "OIDC_ACCOUNT", "oidcToken": oidc_token } }),
    )
    .await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let body = crate::common::parse_response_body(response).await;
    let (_, context) = crate::common::get_challenge_manager()
        .await
        .extract_token_payload(
            ChallengeType::Passkey,
            body["existingFactorToken"].as_str().unwrap().to_owned(),
        )
        .await
        .unwrap();
    let serialized = serde_json::to_string(&context).unwrap();
    assert!(!serialized.contains(oidc_token));
    assert_eq!(
        context,
        ChallengeContext::AddFactor {
            new_factor_type: NewFactorType::OidcAccount {
                oidc_token_hash: hex::encode(Sha256::digest(oidc_token.as_bytes())),
            },
        },
    );
    assert!(serialized.contains("oidcTokenHash"));
}

#[tokio::test]
#[ignore = "Add-factor passkey registration is disabled until #271 ships."]
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
