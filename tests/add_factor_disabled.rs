mod common;

use crate::common::{
    create_test_backup_with_oidc_account, generate_keypair, get_add_factor_challenges_generic,
    get_challenge_manager, parse_response_body, send_post_request,
    send_post_request_with_environment, sign_keypair_challenge, verify_s3_metadata_exists,
};
use axum::http::{Request, StatusCode};
use axum::Extension;
use backup_service::challenge_manager::{ChallengeContext, ChallengeType, NewFactorType};
use backup_service::environment::Environment;
use backup_service::oidc_token_verifier::OidcTokenVerifier;
use backup_service::redis_cache::RedisCacheManager;
use backup_service_test_utils::MockOidcProvider;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openidconnect::SubjectIdentifier;
use serde_json::json;
use serial_test::serial;
use std::sync::Arc;
use tower::ServiceExt;
use types::OidcToken;
use uuid::Uuid;

#[tokio::test]
async fn oidc_existing_challenges_are_disabled_in_every_environment() {
    dotenvy::from_filename(".env.example").unwrap();
    let challenges = get_challenge_manager().await;
    for environment in [
        Environment::development(None),
        Environment::Staging,
        Environment::Production,
    ] {
        let app = backup_service::handler(environment)
            .finish_api(&mut Default::default())
            .layer(Extension(environment))
            .layer(Extension(challenges.clone()));
        for new_factor in [
            json!({ "kind": "OIDC_ACCOUNT", "oidcToken": "unused" }),
            json!({ "kind": "PASSKEY_REGISTRATION", "platform": "IOS" }),
            json!({ "kind": "PASSKEY_REGISTRATION", "platform": "ANDROID" }),
        ] {
            let request = json!({
                "existingFactorKind": "OIDC_ACCOUNT", "newFactor": new_factor
            });
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/add-factor/challenge")
                        .header("Content-Type", "application/json")
                        .body(request.to_string())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                parse_response_body(response).await["error"]["code"],
                "not_supported"
            );
        }
    }
}

#[tokio::test]
async fn oidc_existing_add_factor_rejects_before_validating_proofs() {
    for provider in ["GOOGLE", "APPLE"] {
        let authorization = json!({
            "kind": "OIDC_ACCOUNT", "oidcToken": { "kind": provider, "token": "unused" },
            "publicKey": "unused", "signature": "unused"
        });
        for new_authorization in [
            authorization.clone(),
            json!({ "kind": "PASSKEY", "credential": {} }),
        ] {
            let response = send_post_request(
                "/v1/add-factor",
                json!({
                    "existingFactorAuthorization": authorization,
                    "existingFactorChallengeToken": "unused",
                    "newFactorAuthorization": new_authorization,
                    "newFactorChallengeToken": "unused"
                }),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                parse_response_body(response).await["error"]["code"],
                "not_supported"
            );
        }
    }
}

#[tokio::test]
#[serial]
async fn previously_issued_oidc_proofs_are_rejected_without_consuming_tokens_or_writing_metadata() {
    let subject = Uuid::new_v4().to_string();
    let test = create_test_backup_with_oidc_account(&subject, b"DATA").await;
    assert_eq!(test.response.status(), StatusCode::OK);
    let created = parse_response_body(test.response).await;
    let backup_id = created["backupId"].as_str().unwrap();
    let metadata = verify_s3_metadata_exists(backup_id).await;
    let (public_key, secret_key) = generate_keypair();
    let token = test.oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(SubjectIdentifier::new(subject)),
        &public_key,
    );
    let challenges = get_add_factor_challenges_generic(
        json!({ "kind": "OIDC_ACCOUNT", "oidcToken": token }),
        Some("PASSKEY"),
    )
    .await;
    // Reproduce the Keypair challenge issued by the OIDC-existing flow before shutdown.
    let existing_token = get_challenge_manager()
        .await
        .create_challenge_token(
            ChallengeType::Keypair,
            &STANDARD
                .decode(challenges["existingFactorChallenge"].as_str().unwrap())
                .unwrap(),
            ChallengeContext::AddFactor {
                new_factor_type: NewFactorType::OidcAccount {
                    oidc_token: token.clone(),
                },
            },
        )
        .await
        .unwrap();
    let existing_signature = sign_keypair_challenge(
        &secret_key,
        challenges["existingFactorChallenge"].as_str().unwrap(),
    );
    let new_signature = sign_keypair_challenge(
        &secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );
    let response = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "OIDC_ACCOUNT", "oidcToken": { "kind": "GOOGLE", "token": token },
                "publicKey": public_key, "signature": existing_signature,
            },
            "existingFactorChallengeToken": existing_token,
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT", "oidcToken": { "kind": "GOOGLE", "token": token },
                "publicKey": public_key, "signature": new_signature,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "turnkeyProviderId": "turnkey_provider_id",
            "encryptedBackupKey": {
                "kind": "TURNKEY", "encryptedKey": "ENCRYPTED_KEY", "turnkeyAccountId": "org123",
                "turnkeyUserId": "user", "turnkeyPrivateKeyId": "key"
            }
        }),
        Some(test.environment),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        parse_response_body(response).await["error"]["code"],
        "not_supported"
    );
    assert_eq!(verify_s3_metadata_exists(backup_id).await, metadata);

    let cache = Arc::new(
        RedisCacheManager::new(test.environment, test.environment.cache_default_ttl())
            .await
            .unwrap(),
    );
    for challenge in [
        &existing_token,
        challenges["newFactorToken"].as_str().unwrap(),
    ] {
        cache
            .use_challenge_token(challenge.to_string())
            .await
            .unwrap();
    }
    OidcTokenVerifier::new(test.environment, cache)
        .verify_token(&OidcToken::Google { token }, public_key, true)
        .await
        .unwrap();
}
