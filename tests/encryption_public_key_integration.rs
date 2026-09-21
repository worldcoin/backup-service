mod common;

use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::Response;
use base64::prelude::{Engine, BASE64_STANDARD};
use http_body_util::BodyExt;
use p256::SecretKey;
use serde_json::{json, Value};

use crate::common::{
    generate_keypair, get_keypair_challenge, make_sync_factor, send_post_request,
    send_post_request_with_bypass_attestation_token, send_post_request_with_multipart,
    sign_keypair_challenge, verify_s3_backup_exists, verify_s3_metadata_exists, BackupAccount,
};

async fn body(response: Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn authorization(key: &SecretKey, challenge: &Value) -> Value {
    json!({
        "kind": "EC_KEYPAIR",
        "publicKey": BASE64_STANDARD.encode(key.public_key().to_sec1_bytes()),
        "signature": sign_keypair_challenge(key, challenge["challenge"].as_str().unwrap()),
    })
}

async fn create(key: Option<&str>) -> (String, SecretKey, SecretKey) {
    let account = BackupAccount::generate();
    let challenge = get_keypair_challenge().await;
    let (proof_token, proof_signature) = account.proof(&challenge);
    let (_, main_key) = generate_keypair();
    let (sync_factor, sync_token, sync_key) = make_sync_factor().await;
    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": authorization(&main_key, &challenge),
            "challengeToken": challenge["token"],
            "initialEncryptionKey": {"kind": "PRF", "encryptedKey": "encrypted"},
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_token,
            "manifestHash": "01".repeat(32),
            "backupAccountId": account.id,
            "backupAccountChallengeToken": proof_token,
            "backupAccountSignature": proof_signature,
            "encryptionPublicKey": key,
        }),
        Bytes::from_static(b"old"),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = body(response).await;
    assert_eq!(
        response["backupMetadata"]["encryptionPublicKey"],
        json!(key.map(|key| key.trim_start_matches("0x").to_lowercase()))
    );
    (account.id, main_key, sync_key)
}

async fn retrieve(key: &SecretKey) -> Value {
    let challenge =
        body(send_post_request("/v1/retrieve/challenge/keypair", json!({})).await).await;
    let response = send_post_request_with_bypass_attestation_token(
        "/v1/retrieve/from-challenge",
        json!({"authorization": authorization(key, &challenge), "challengeToken": challenge["token"]}),
        None,
    ).await;
    assert_eq!(response.status(), StatusCode::OK);
    body(response).await
}

async fn sync(
    key: &SecretKey,
    encryption_key: Option<&str>,
    previous: &str,
    next: &str,
) -> Response {
    let challenge = body(send_post_request("/v1/sync/challenge/keypair", json!({})).await).await;
    send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": authorization(key, &challenge),
            "challengeToken": challenge["token"],
            "currentManifestHash": previous,
            "newManifestHash": next,
            "encryptionPublicKey": encryption_key,
        }),
        Bytes::from_static(b"new"),
        None,
    )
    .await
}

async fn enroll(token: &str, encryption_key: Option<&str>, key: &SecretKey) -> Response {
    let challenge =
        body(send_post_request("/v1/add-sync-factor/challenge/keypair", json!({})).await).await;
    send_post_request(
        "/v1/add-sync-factor",
        json!({
            "syncFactor": authorization(key, &challenge),
            "challengeToken": challenge["token"],
            "syncFactorToken": token,
            "encryptionPublicKey": encryption_key,
        }),
    )
    .await
}

#[tokio::test]
async fn creation_and_sync_check_the_key_without_breaking_old_requests() {
    let encryption_key = "ab".repeat(32);
    let (id, main, sync_key) = create(Some(&format!("0x{}", "AB".repeat(32)))).await;
    let snapshot = verify_s3_metadata_exists(&id).await;
    assert_eq!(snapshot["encryptionPublicKey"], encryption_key);
    let retrieved = retrieve(&main).await;
    assert_eq!(retrieved["metadata"]["encryptionPublicKey"], encryption_key);

    let rejected = sync(
        &sync_key,
        Some(&"cd".repeat(32)),
        &"01".repeat(32),
        &"02".repeat(32),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::CONFLICT);
    assert_eq!(
        body(rejected).await["error"]["code"],
        "encryption_public_key_mismatch"
    );
    assert_eq!(verify_s3_metadata_exists(&id).await, snapshot);
    verify_s3_backup_exists(&id, b"old").await;

    let accepted = sync(
        &sync_key,
        Some(&encryption_key),
        &"01".repeat(32),
        &"02".repeat(32),
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    let metadata = verify_s3_metadata_exists(&id).await;
    assert_eq!(metadata["manifestHash"], "02".repeat(32));
    assert_eq!(metadata["encryptionPublicKey"], encryption_key);
    verify_s3_backup_exists(&id, b"new").await;

    let legacy = sync(&sync_key, None, &"02".repeat(32), &"03".repeat(32)).await;
    assert_eq!(legacy.status(), StatusCode::OK);
    assert_eq!(
        verify_s3_metadata_exists(&id).await["encryptionPublicKey"],
        encryption_key
    );
}

#[tokio::test]
async fn only_main_authorized_registration_can_initialize_a_legacy_key() {
    let encryption_key = "ab".repeat(32);
    let (id, main, sync_key) = create(None).await;
    let snapshot = verify_s3_metadata_exists(&id).await;
    assert!(snapshot.get("encryptionPublicKey").is_none());
    let rejected = sync(
        &sync_key,
        Some(&encryption_key),
        &"01".repeat(32),
        &"02".repeat(32),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::CONFLICT);
    assert_eq!(verify_s3_metadata_exists(&id).await, snapshot);

    let unauthorized = enroll(
        "invalid-token",
        Some(&encryption_key),
        &generate_keypair().1,
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::BAD_REQUEST);
    assert_eq!(verify_s3_metadata_exists(&id).await, snapshot);

    let retrieved = retrieve(&main).await;
    assert!(retrieved["metadata"].get("encryptionPublicKey").is_none());
    let accepted = enroll(
        retrieved["syncFactorToken"].as_str().unwrap(),
        Some(&encryption_key),
        &generate_keypair().1,
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    let initialized = verify_s3_metadata_exists(&id).await;
    assert_eq!(initialized["encryptionPublicKey"], encryption_key);
    assert_eq!(initialized["archiveId"], snapshot["archiveId"]);
    assert_eq!(initialized["manifestHash"], snapshot["manifestHash"]);
    assert_eq!(initialized["syncFactors"].as_array().unwrap().len(), 2);
    assert_eq!(
        sync(
            &sync_key,
            Some(&encryption_key),
            &"01".repeat(32),
            &"02".repeat(32)
        )
        .await
        .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn registration_rejects_replacement_and_can_retry_with_the_matching_key() {
    let encryption_key = "ab".repeat(32);
    let (id, main, _) = create(Some(&encryption_key)).await;
    let snapshot = verify_s3_metadata_exists(&id).await;
    let retrieved = retrieve(&main).await;
    let token = retrieved["syncFactorToken"].as_str().unwrap();
    let rejected = enroll(token, Some(&"cd".repeat(32)), &generate_keypair().1).await;
    assert_eq!(rejected.status(), StatusCode::CONFLICT);
    assert_eq!(
        body(rejected).await["error"]["code"],
        "encryption_public_key_mismatch"
    );
    assert_eq!(verify_s3_metadata_exists(&id).await, snapshot);

    let accepted = enroll(token, Some(&encryption_key), &generate_keypair().1).await;
    assert_eq!(accepted.status(), StatusCode::OK);
    let after = verify_s3_metadata_exists(&id).await;
    assert_eq!(after["archiveId"], snapshot["archiveId"]);
    assert_eq!(after["encryptionPublicKey"], encryption_key);
    assert_eq!(after["syncFactors"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn mismatched_duplicate_registration_preserves_a_repaired_lookup() {
    use backup_service::environment::Environment;
    use backup_service::factor_lookup::{FactorLookup, FactorToLookup};
    use std::sync::Arc;
    use types::FactorScope;

    let encryption_key = "ab".repeat(32);
    let (id, main, sync_key) = create(Some(&encryption_key)).await;
    let snapshot = verify_s3_metadata_exists(&id).await;
    let retrieved = retrieve(&main).await;
    let environment = Environment::development(None);
    let lookup = FactorLookup::new(
        environment,
        Arc::new(aws_sdk_dynamodb::Client::new(
            &environment.aws_config().await,
        )),
    );
    let factor = FactorToLookup::from_ec_keypair(
        BASE64_STANDARD.encode(sync_key.public_key().to_sec1_bytes()),
    );
    lookup.delete(FactorScope::Sync, &factor).await.unwrap();

    let rejected = enroll(
        retrieved["syncFactorToken"].as_str().unwrap(),
        Some(&"cd".repeat(32)),
        &sync_key,
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body(rejected).await["error"]["code"],
        "factor_already_exists"
    );
    assert_eq!(verify_s3_metadata_exists(&id).await, snapshot);
    assert_eq!(
        lookup
            .lookup_consistent(FactorScope::Sync, &factor)
            .await
            .unwrap(),
        Some(id)
    );
    let synced = sync(
        &sync_key,
        Some(&encryption_key),
        &"01".repeat(32),
        &"02".repeat(32),
    )
    .await;
    assert_eq!(synced.status(), StatusCode::OK);
}
