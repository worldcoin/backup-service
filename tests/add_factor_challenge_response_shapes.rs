//! Response-shape checks for `/v1/add-factor/challenge` only (not the full add-factor
//! completion flow, which lives in `add_factor_integration.rs`).

mod common;

use crate::common::{get_challenge_manager, send_post_request};
use backup_service::challenge_manager::{ChallengeContext, ChallengeType, NewFactorType};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::json;
use sha2::{Digest, Sha256};

/// Decrypts a challenge token and returns its payload and context, so tests can assert on what
/// the server actually committed to rather than just the response's shape.
async fn decrypt_token(challenge_type: ChallengeType, token: &str) -> (Vec<u8>, ChallengeContext) {
    get_challenge_manager()
        .await
        .extract_token_payload(challenge_type, token.to_string())
        .await
        .expect("token should decrypt with the same KMS key the server used to mint it")
}

#[tokio::test]
async fn test_add_factor_challenge_shapes_oidc_new_factor() {
    let resp = send_post_request(
        "/v1/add-factor/challenge",
        json!({
            "newFactor": { "kind": "OIDC_ACCOUNT", "oidcToken": "opaque" }
        }),
    )
    .await;
    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(value["existingFactorChallenge"].is_string());
    assert!(value["existingFactorToken"].is_string());
    assert!(value["newFactorChallenge"].is_string());
    assert!(value["newFactorToken"].is_string());

    // The existing-factor token must commit to exactly the OIDC new-factor descriptor the
    // caller asked to add, and carry the same challenge bytes returned in the response.
    let (existing_payload, existing_context) = decrypt_token(
        ChallengeType::Passkey,
        value["existingFactorToken"].as_str().unwrap(),
    )
    .await;
    assert_eq!(
        existing_payload,
        STANDARD
            .decode(value["existingFactorChallenge"].as_str().unwrap())
            .unwrap()
    );
    assert_eq!(
        existing_context,
        ChallengeContext::AddFactor {
            new_factor_type: NewFactorType::OidcAccount {
                oidc_token: "opaque".to_string()
            }
        }
    );

    // The new-factor token is a plain keypair challenge whose payload is the challenge bytes
    // returned in the response.
    let (new_payload, new_context) = decrypt_token(
        ChallengeType::Keypair,
        value["newFactorToken"].as_str().unwrap(),
    )
    .await;
    assert_eq!(
        new_payload,
        STANDARD
            .decode(value["newFactorChallenge"].as_str().unwrap())
            .unwrap()
    );
    assert_eq!(new_context, ChallengeContext::AddFactorByNewFactor {});
}

#[tokio::test]
async fn test_add_factor_challenge_shapes_passkey_registration_ios() {
    let resp = send_post_request(
        "/v1/add-factor/challenge",
        json!({
            "newFactor": { "kind": "PASSKEY_REGISTRATION", "platform": "IOS" }
        }),
    )
    .await;
    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(value["existingFactorChallenge"].is_string());
    assert!(value["existingFactorToken"].is_string());
    assert!(value["newFactorChallenge"].is_object());
    assert!(value["newFactorToken"].is_string());

    // The new-factor token's payload is the registration ceremony state; its hash must match
    // the registration_hash the existing-factor token was bound to, otherwise a swapped
    // ceremony would go undetected.
    let (new_registration_payload, new_context) = decrypt_token(
        ChallengeType::Passkey,
        value["newFactorToken"].as_str().unwrap(),
    )
    .await;
    assert_eq!(new_context, ChallengeContext::AddFactorByNewFactor {});
    let actual_registration_hash = hex::encode(Sha256::digest(&new_registration_payload));

    let (existing_payload, existing_context) = decrypt_token(
        ChallengeType::Passkey,
        value["existingFactorToken"].as_str().unwrap(),
    )
    .await;
    assert_eq!(
        existing_payload,
        STANDARD
            .decode(value["existingFactorChallenge"].as_str().unwrap())
            .unwrap()
    );
    assert_eq!(
        existing_context,
        ChallengeContext::AddFactor {
            new_factor_type: NewFactorType::PasskeyRegistration {
                registration_hash: actual_registration_hash
            }
        }
    );
}

#[tokio::test]
async fn test_add_factor_challenge_shapes_passkey_registration_android() {
    let resp = send_post_request(
        "/v1/add-factor/challenge",
        json!({
            "newFactor": { "kind": "PASSKEY_REGISTRATION", "platform": "ANDROID" }
        }),
    )
    .await;
    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(value["newFactorChallenge"].is_object());
    assert!(value["newFactorChallenge"]["publicKey"].is_object());
    assert!(value["newFactorToken"].is_string());

    // Android registration challenge must be completable by a WebAuthn client.
    let mut passkey_client = backup_service_test_utils::get_mock_passkey_client();
    let credential = backup_service_test_utils::make_credential_from_passkey_challenge(
        &mut passkey_client,
        &json!({ "challenge": value["newFactorChallenge"].clone() }),
    )
    .await;
    assert!(credential["id"].is_string() || credential["rawId"].is_string());
}
