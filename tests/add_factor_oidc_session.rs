mod common;

use crate::common::{
    create_test_backup_with_oidc_account, generate_keypair, get_add_factor_challenges_generic,
    parse_response_body, send_post_request_with_environment, sign_keypair_challenge,
    verify_s3_metadata_exists,
};
use axum::http::StatusCode;
use backup_service::redis_cache::{RedisCacheError, RedisCacheManager};
use backup_service_test_utils::MockOidcProvider;
use openidconnect::SubjectIdentifier;
use p256::SecretKey;
use serde_json::{json, Value};
use serial_test::serial;
use uuid::Uuid;

async fn same_session_request(token: &str, public_key: &str, secret_key: &SecretKey) -> Value {
    let challenges = get_add_factor_challenges_generic(
        json!({ "kind": "OIDC_ACCOUNT", "oidcToken": token }),
        Some("OIDC_ACCOUNT"),
    )
    .await;
    let authorization = |challenge: &str| {
        json!({
            "kind": "OIDC_ACCOUNT",
            "oidcToken": { "kind": "GOOGLE", "token": token },
            "publicKey": public_key,
            "signature": sign_keypair_challenge(secret_key, challenges[challenge].as_str().unwrap()),
        })
    };
    json!({
        "existingFactorAuthorization": authorization("existingFactorChallenge"),
        "existingFactorChallengeToken": challenges["existingFactorToken"],
        "newFactorAuthorization": authorization("newFactorChallenge"),
        "newFactorChallengeToken": challenges["newFactorToken"],
        "turnkeyProviderId": "turnkey_provider_id",
        "encryptedBackupKey": {
            "kind": "TURNKEY",
            "encryptedKey": "ENCRYPTED_KEY",
            "turnkeyAccountId": "org123",
            "turnkeyUserId": "TURNKEY_USER_ID",
            "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID"
        }
    })
}

#[tokio::test]
#[serial]
async fn same_session_consumes_both_challenges_and_rejects_fresh_challenge_replay() {
    let subject = Uuid::new_v4().to_string();
    let test = create_test_backup_with_oidc_account(&subject, b"DATA").await;
    assert_eq!(test.response.status(), StatusCode::OK);
    let created = parse_response_body(test.response).await;
    let backup_id = created["backupId"].as_str().unwrap();
    let (public_key, secret_key) = generate_keypair();
    let token = test.oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(SubjectIdentifier::new(subject)),
        &public_key,
    );
    let request = same_session_request(&token, &public_key, &secret_key).await;
    let response = send_post_request_with_environment(
        "/v1/add-factor",
        request.clone(),
        Some(test.environment),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let cache = RedisCacheManager::new(test.environment, test.environment.cache_default_ttl())
        .await
        .unwrap();
    for field in ["existingFactorChallengeToken", "newFactorChallengeToken"] {
        let result = cache
            .use_challenge_token(request[field].as_str().unwrap().to_string())
            .await;
        let Err(RedisCacheError::AlreadyUsed) = result else {
            panic!("Challenge was not consumed: {field}: {result:?}");
        };
    }
    let metadata = verify_s3_metadata_exists(backup_id).await;
    let mut replay = same_session_request(&token, &public_key, &secret_key).await;
    replay["encryptedBackupKey"]["encryptedKey"] = json!("REPLAYED_KEY");
    let response =
        send_post_request_with_environment("/v1/add-factor", replay, Some(test.environment)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        parse_response_body(response).await["error"]["code"],
        "already_used"
    );
    assert_eq!(verify_s3_metadata_exists(backup_id).await, metadata);
}

#[tokio::test]
#[serial]
async fn same_session_requires_both_challenge_signatures() {
    for authorization in ["existingFactorAuthorization", "newFactorAuthorization"] {
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
        let mut request = same_session_request(&token, &public_key, &secret_key).await;
        request[authorization]["signature"] = json!(sign_keypair_challenge(&secret_key, "AAAA"));
        let response =
            send_post_request_with_environment("/v1/add-factor", request, Some(test.environment))
                .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            parse_response_body(response).await["error"]["code"],
            "signature_verification_error"
        );
        assert_eq!(verify_s3_metadata_exists(backup_id).await, metadata);
    }
}

#[tokio::test]
#[serial]
async fn same_session_rejects_wrong_new_challenge_context() {
    let subject = Uuid::new_v4().to_string();
    let test = create_test_backup_with_oidc_account(&subject, b"DATA").await;
    assert_eq!(test.response.status(), StatusCode::OK);
    let (public_key, secret_key) = generate_keypair();
    let token = test.oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(SubjectIdentifier::new(subject)),
        &public_key,
    );
    let mut request = same_session_request(&token, &public_key, &secret_key).await;
    request["newFactorChallengeToken"] = request["existingFactorChallengeToken"].clone();
    request["newFactorAuthorization"] = request["existingFactorAuthorization"].clone();
    let response =
        send_post_request_with_environment("/v1/add-factor", request, Some(test.environment)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        parse_response_body(response).await["error"]["code"],
        "invalid_challenge_context"
    );
}

#[tokio::test]
#[serial]
async fn same_session_rejects_either_spent_challenge_with_a_fresh_nonce() {
    for field in ["existingFactorChallengeToken", "newFactorChallengeToken"] {
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
        let request = same_session_request(&token, &public_key, &secret_key).await;
        let cache = RedisCacheManager::new(test.environment, test.environment.cache_default_ttl())
            .await
            .unwrap();
        cache
            .use_challenge_token(request[field].as_str().unwrap().to_string())
            .await
            .unwrap();
        let response =
            send_post_request_with_environment("/v1/add-factor", request, Some(test.environment))
                .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{field}");
        assert_eq!(
            parse_response_body(response).await["error"]["code"],
            "already_used"
        );
        assert_eq!(verify_s3_metadata_exists(backup_id).await, metadata);
    }
}
