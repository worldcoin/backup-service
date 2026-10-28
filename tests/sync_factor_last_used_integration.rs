mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::common::{
    create_test_backup_with_sync_keypair, get_keypair_retrieval_challenge, send_post_request,
    send_post_request_with_bypass_attestation_token, sign_keypair_challenge,
};
use aws_sdk_dynamodb::types::AttributeValue;
use axum::http::StatusCode;
use backup_service::backup_metadata::Factor;
use backup_service::environment::Environment;
use backup_service::factor_lookup::{FactorLookup, FactorToLookup, ReadConsistency};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{Days, NaiveDate, Utc};
use http_body_util::BodyExt;
use p256::SecretKey;
use serde_json::json;
use serial_test::serial;
use types::FactorScope;

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

async fn stored_last_used(lookup: &FactorLookup, backup: &TestBackup) -> Option<NaiveDate> {
    lookup
        .lookup(
            FactorScope::Sync,
            &FactorToLookup::from_ec_keypair(backup.sync_public_key.clone()),
            ReadConsistency::Strong,
        )
        .await
        .unwrap()
        .unwrap()
        .last_used
}

/// The use is recorded in the background, so wait for it to land.
async fn wait_for_last_used(lookup: &FactorLookup, backup: &TestBackup, expected: NaiveDate) {
    for _ in 0..50 {
        if stored_last_used(lookup, backup).await == Some(expected) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("sync factor last use was not recorded as {expected}");
}

fn days_ago(days: u64) -> NaiveDate {
    Utc::now().date_naive() - Days::new(days)
}

#[tokio::test]
#[serial]
async fn sync_factor_use_is_recorded_and_reported_on_recovery() {
    let backup = create_backup().await;
    let lookup = factor_lookup().await;

    let before_use = recovered_sync_factors(&backup).await;
    assert_eq!(before_use.len(), 1);
    assert!(
        before_use[0].get("lastUsed").is_none(),
        "an unused factor has no last use"
    );

    use_sync_factor(&backup).await;
    let today = Utc::now().date_naive();
    wait_for_last_used(&lookup, &backup, today).await;

    let after_use = recovered_sync_factors(&backup).await;
    assert_eq!(after_use[0]["lastUsed"], json!(today.to_string()));
    assert_eq!(
        after_use[0]["kind"]["publicKey"],
        json!(backup.sync_public_key)
    );
}

#[tokio::test]
#[serial]
async fn sync_factor_use_older_than_a_day_is_refreshed() {
    let backup = create_backup().await;
    let lookup = factor_lookup().await;
    let factor = FactorToLookup::from_ec_keypair(backup.sync_public_key.clone());
    assert!(lookup
        .set_last_used(&factor, &backup.backup_id, days_ago(2))
        .await
        .unwrap());

    use_sync_factor(&backup).await;

    wait_for_last_used(&lookup, &backup, Utc::now().date_naive()).await;
}

#[tokio::test]
#[serial]
async fn recording_use_never_creates_or_moves_a_lookup_row() {
    let backup = create_backup().await;
    let lookup = factor_lookup().await;
    let factor = FactorToLookup::from_ec_keypair(backup.sync_public_key.clone());
    let today = Utc::now().date_naive();

    // A row that maps to another backup is left untouched.
    assert!(!lookup
        .set_last_used(&factor, "another-backup", today)
        .await
        .unwrap());
    assert_eq!(stored_last_used(&lookup, &backup).await, None);

    // A missing row is not recreated.
    let missing = FactorToLookup::from_ec_keypair(uuid::Uuid::new_v4().to_string());
    assert!(!lookup
        .set_last_used(&missing, &backup.backup_id, today)
        .await
        .unwrap());
    assert_eq!(
        lookup
            .lookup(FactorScope::Sync, &missing, ReadConsistency::Eventual)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
#[serial]
async fn recovery_succeeds_without_last_use_when_it_cannot_be_read() {
    let backup = create_backup().await;
    let factor = FactorToLookup::from_ec_keypair(backup.sync_public_key.clone());
    assert!(factor_lookup()
        .await
        .set_last_used(&factor, &backup.backup_id, days_ago(0))
        .await
        .unwrap());
    let environment = Environment::development(None);
    // Overwrites that row without a backup ID, which fails the whole batch read.
    aws_sdk_dynamodb::Client::new(&environment.aws_config().await)
        .put_item()
        .table_name(environment.factor_lookup_dynamodb_table_name())
        .item(
            "PK",
            AttributeValue::S(format!("SYNC#EC_KEYPAIR|{}", backup.sync_public_key)),
        )
        .item("LastUsed", AttributeValue::S(days_ago(0).to_string()))
        .send()
        .await
        .unwrap();

    let sync_factors = recovered_sync_factors(&backup).await;

    assert!(sync_factors[0].get("lastUsed").is_none());
}

#[tokio::test]
#[serial]
async fn last_use_is_reported_per_factor_and_only_to_its_backup() {
    let backup = create_backup().await;
    let lookup = factor_lookup().await;
    let second_key = uuid::Uuid::new_v4().to_string();
    lookup
        .insert(
            FactorScope::Sync,
            &FactorToLookup::from_ec_keypair(second_key.clone()),
            backup.backup_id.clone(),
        )
        .await
        .unwrap();
    let first = Factor::new_ec_keypair(backup.sync_public_key.clone());
    let second = Factor::new_ec_keypair(second_key.clone());
    for (key, date) in [
        (&backup.sync_public_key, days_ago(0)),
        (&second_key, days_ago(1)),
    ] {
        assert!(lookup
            .set_last_used(
                &FactorToLookup::from_ec_keypair(key.clone()),
                &backup.backup_id,
                date,
            )
            .await
            .unwrap());
    }
    let factors = [first.clone(), second.clone()];

    let own = lookup
        .fetch_last_used(&factors, &backup.backup_id)
        .await
        .unwrap();
    assert_eq!(
        own,
        HashMap::from([(first.id, days_ago(0)), (second.id, days_ago(1))])
    );

    let other = lookup
        .fetch_last_used(&factors, "another-backup")
        .await
        .unwrap();
    assert!(other.is_empty());
}
