mod common;

use std::sync::Arc;
use std::time::Duration;

use crate::common::{
    create_test_backup_with_sync_keypair, get_keypair_retrieval_challenge, send_post_request,
    send_post_request_with_bypass_attestation_token, sign_keypair_challenge,
};
use axum::http::StatusCode;
use backup_service::environment::Environment;
use backup_service::factor_lookup::{FactorLookup, FactorToLookup};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use p256::SecretKey;
use serde_json::json;
use serial_test::serial;
use types::FactorScope;

const DAY_SECS: i64 = 24 * 60 * 60;

struct TestBackup {
    backup_id: String,
    main_public_key: String,
    main_secret_key: SecretKey,
    sync_public_key: String,
    sync_secret_key: SecretKey,
}

async fn create_backup() -> TestBackup {
    let ((main_public_key, main_secret_key), response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"TEST BACKUP").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    TestBackup {
        backup_id: response["backupMetadata"]["id"]
            .as_str()
            .unwrap()
            .to_string(),
        main_public_key,
        main_secret_key,
        sync_public_key: STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes()),
        sync_secret_key,
    }
}

async fn factor_lookup() -> FactorLookup {
    dotenvy::from_path(".env.example").ok();
    let environment = Environment::development(None);
    let dynamodb_client = Arc::new(aws_sdk_dynamodb::Client::new(
        &environment.aws_config().await,
    ));
    FactorLookup::new(environment, dynamodb_client)
}

/// Authenticates a request with the sync factor, which is what records its use.
async fn use_sync_factor(backup: &TestBackup) {
    let challenge = send_post_request("/v1/retrieve-metadata/challenge/keypair", json!({})).await;
    let body = challenge.into_body().collect().await.unwrap().to_bytes();
    let challenge: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let signature = sign_keypair_challenge(
        &backup.sync_secret_key,
        challenge["challenge"].as_str().unwrap(),
    );
    let response = send_post_request(
        "/v1/retrieve-metadata",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": backup.sync_public_key,
                "signature": signature,
            },
            "challengeToken": challenge["token"],
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// Recovers the backup with its Main factor and returns the exported sync factors.
async fn recovered_sync_factors(backup: &TestBackup) -> Vec<serde_json::Value> {
    let challenge = get_keypair_retrieval_challenge().await;
    let signature = sign_keypair_challenge(
        &backup.main_secret_key,
        challenge["challenge"].as_str().unwrap(),
    );
    let response = send_post_request_with_bypass_attestation_token(
        "/v1/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": backup.main_public_key,
                "signature": signature,
            },
            "challengeToken": challenge["token"],
        }),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    response["metadata"]["syncFactors"]
        .as_array()
        .unwrap()
        .clone()
}

async fn stored_last_used(lookup: &FactorLookup, backup: &TestBackup) -> Option<i64> {
    lookup
        .lookup_record(
            FactorScope::Sync,
            &FactorToLookup::from_ec_keypair(backup.sync_public_key.clone()),
        )
        .await
        .unwrap()
        .unwrap()
        .last_used_at
}

/// The write runs detached from the request, so poll briefly for it to land.
async fn await_last_used(
    lookup: &FactorLookup,
    backup: &TestBackup,
    accept: impl Fn(i64) -> bool,
) -> i64 {
    for _ in 0..50 {
        if let Some(at) = stored_last_used(lookup, backup)
            .await
            .filter(|at| accept(*at))
        {
            return at;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("sync factor last use was not recorded");
}

#[tokio::test]
#[serial]
async fn sync_factor_use_is_recorded_and_reported_on_recovery() {
    let backup = create_backup().await;
    let lookup = factor_lookup().await;

    let before_use = recovered_sync_factors(&backup).await;
    assert_eq!(before_use.len(), 1);
    assert!(
        before_use[0].get("lastUsedAt").is_none(),
        "an unused factor has no last use"
    );

    let started = chrono::Utc::now().timestamp();
    use_sync_factor(&backup).await;
    let recorded = await_last_used(&lookup, &backup, |_| true).await;
    assert!(recorded >= started && recorded <= chrono::Utc::now().timestamp());

    let after_use = recovered_sync_factors(&backup).await;
    assert_eq!(after_use[0]["lastUsedAt"], json!(recorded));
    assert_eq!(
        after_use[0]["kind"]["publicKey"],
        json!(backup.sync_public_key)
    );
}

#[tokio::test]
#[serial]
async fn sync_factor_use_within_a_day_is_not_rewritten() {
    let backup = create_backup().await;
    let lookup = factor_lookup().await;
    let factor = FactorToLookup::from_ec_keypair(backup.sync_public_key.clone());
    let recent = chrono::Utc::now().timestamp() - 3_600;
    assert!(lookup
        .record_last_used(FactorScope::Sync, &factor, &backup.backup_id, recent)
        .await
        .unwrap());

    use_sync_factor(&backup).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(stored_last_used(&lookup, &backup).await, Some(recent));
}

#[tokio::test]
#[serial]
async fn sync_factor_use_older_than_a_day_is_refreshed() {
    let backup = create_backup().await;
    let lookup = factor_lookup().await;
    let factor = FactorToLookup::from_ec_keypair(backup.sync_public_key.clone());
    let stale = chrono::Utc::now().timestamp() - 2 * DAY_SECS;
    assert!(lookup
        .record_last_used(FactorScope::Sync, &factor, &backup.backup_id, stale)
        .await
        .unwrap());

    use_sync_factor(&backup).await;

    let refreshed = await_last_used(&lookup, &backup, |at| at > stale).await;
    assert!(refreshed > stale + DAY_SECS);
}

#[tokio::test]
#[serial]
async fn recording_use_never_creates_or_moves_a_lookup_row() {
    let backup = create_backup().await;
    let lookup = factor_lookup().await;
    let factor = FactorToLookup::from_ec_keypair(backup.sync_public_key.clone());
    let now = chrono::Utc::now().timestamp();

    // A row that maps to another backup is left untouched.
    assert!(!lookup
        .record_last_used(FactorScope::Sync, &factor, "another-backup", now)
        .await
        .unwrap());
    assert_eq!(stored_last_used(&lookup, &backup).await, None);

    // A missing row is not recreated.
    let missing = FactorToLookup::from_ec_keypair("bm90LXJlZ2lzdGVyZWQ".to_string());
    assert!(!lookup
        .record_last_used(FactorScope::Sync, &missing, &backup.backup_id, now)
        .await
        .unwrap());
    assert_eq!(
        lookup.lookup(FactorScope::Sync, &missing).await.unwrap(),
        None
    );
}

#[tokio::test]
#[serial]
async fn last_use_never_moves_backwards() {
    let backup = create_backup().await;
    let lookup = factor_lookup().await;
    let factor = FactorToLookup::from_ec_keypair(backup.sync_public_key.clone());
    let newer = chrono::Utc::now().timestamp();

    assert!(lookup
        .record_last_used(FactorScope::Sync, &factor, &backup.backup_id, newer)
        .await
        .unwrap());
    // A slower concurrent update captured before the newer one must not rewind it.
    assert!(!lookup
        .record_last_used(FactorScope::Sync, &factor, &backup.backup_id, newer - 60)
        .await
        .unwrap());

    assert_eq!(stored_last_used(&lookup, &backup).await, Some(newer));
}

#[tokio::test]
#[serial]
async fn last_use_of_a_row_owned_by_another_backup_is_not_reported() {
    let backup = create_backup().await;
    let lookup = factor_lookup().await;
    let factor = FactorToLookup::from_ec_keypair(backup.sync_public_key.clone());
    let now = chrono::Utc::now().timestamp();
    assert!(lookup
        .record_last_used(FactorScope::Sync, &factor, &backup.backup_id, now)
        .await
        .unwrap());

    let own = lookup
        .last_used_at(
            FactorScope::Sync,
            std::slice::from_ref(&factor),
            &backup.backup_id,
        )
        .await
        .unwrap();
    assert_eq!(own.get(&factor.primary_key()), Some(&now));

    let other = lookup
        .last_used_at(FactorScope::Sync, &[factor], "another-backup")
        .await
        .unwrap();
    assert!(other.is_empty());
}
