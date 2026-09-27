//! End-to-end recovery -> bounded reclaim -> registration against isolated `LocalStack`/Redis.
mod common;

use aws_sdk_s3::primitives::ByteStream;
use axum::response::Response;
use backup_service::{
    backup_metadata::{BackupMetadata, Factor},
    environment::Environment,
    factor_lookup::FactorLookup,
};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::sync::Arc;
use types::FactorScope;

async fn body(response: Response) -> Value {
    assert!(
        response.status().is_success(),
        "status: {}",
        response.status()
    );
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

async fn recover(public_key: &str, secret: &p256::SecretKey) -> Value {
    let challenge = common::get_keypair_retrieval_challenge().await;
    body(common::send_post_request_with_bypass_attestation_token(
        "/v1/retrieve/from-challenge", json!({
            "authorization": {"kind": "EC_KEYPAIR", "publicKey": public_key,
                "signature": common::sign_keypair_challenge(secret, challenge["challenge"].as_str().unwrap())},
            "challengeToken": challenge["token"]
        }), None).await).await
}

async fn register(token: &Value) {
    let challenge =
        body(common::send_post_request("/v1/add-sync-factor/challenge/keypair", json!({})).await)
            .await;
    let (public_key, secret) = common::generate_keypair();
    body(common::send_post_request("/v1/add-sync-factor", json!({
        "challengeToken": challenge["token"],
        "syncFactorToken": token,
        "syncFactor": {"kind": "EC_KEYPAIR", "publicKey": public_key,
            "signature": common::sign_keypair_challenge(&secret, challenge["challenge"].as_str().unwrap())}
    })).await).await;
}

#[tokio::test]
async fn main_recovery_reclaims_one_stale_slot_then_registers_without_touching_other_backup() {
    let ((public_key, secret), created) =
        common::create_test_backup_with_keypair(b"recover me").await;
    let created = body(created).await;
    let id = created["backupMetadata"]["id"].as_str().unwrap();
    let (_, other) = common::create_test_backup_with_keypair(b"untouched").await;
    let other = body(other).await;
    let other_id = other["backupMetadata"]["id"].as_str().unwrap();
    let other_before = common::verify_s3_metadata_exists(other_id).await;
    let environment = Environment::development(None);
    let lookup = FactorLookup::new(
        environment,
        Arc::new(aws_sdk_dynamodb::Client::new(
            &environment.aws_config().await,
        )),
    );
    let mut metadata: BackupMetadata =
        serde_json::from_value(common::verify_s3_metadata_exists(id).await).unwrap();
    // Keep the original recent sync factor; fill the remaining slots with abandoned device keys.
    for i in 1..25 {
        let mut factor = Factor::new_ec_keypair(common::generate_keypair().0);
        factor.created_at = Utc::now() - chrono::Duration::days(365 + i);
        lookup
            .insert(
                FactorScope::Sync,
                &factor.as_factor_to_lookup(&environment),
                id.to_string(),
            )
            .await
            .unwrap();
        metadata.sync_factors.push(factor);
    }
    let oldest = metadata.sync_factors.last().unwrap().clone();
    common::get_test_s3_client()
        .await
        .put_object()
        .bucket(environment.s3_bucket())
        .key(format!("{id}/metadata"))
        .body(ByteStream::from(serde_json::to_vec(&metadata).unwrap()))
        .send()
        .await
        .unwrap();
    let recovered = recover(&public_key, &secret).await;
    assert_ne!(
        recovered["syncFactorToken"],
        recovered["syncFactorMaintenanceToken"]
    );
    let request = json!({"syncFactorMaintenanceToken": recovered["syncFactorMaintenanceToken"]});
    let reclaimed = body(
        common::send_post_request_with_bypass_attestation_token(
            "/v1/reclaim-sync-factor-slot",
            request.clone(),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(reclaimed, json!({"reclaimed": true}));
    let after: BackupMetadata =
        serde_json::from_value(common::verify_s3_metadata_exists(id).await).unwrap();
    assert_eq!(after.sync_factors.len(), 24);
    assert!(!after.sync_factors.contains(&oldest));
    assert_eq!(after.sync_factors[0], metadata.sync_factors[0]);
    assert_eq!(after.factors, metadata.factors);
    assert_eq!(after.keys, metadata.keys);
    assert!(lookup
        .lookup_consistent(FactorScope::Sync, &oldest.as_factor_to_lookup(&environment))
        .await
        .unwrap()
        .is_none());
    let replay = common::send_post_request_with_bypass_attestation_token(
        "/v1/reclaim-sync-factor-slot",
        request,
        None,
    )
    .await;
    assert!(!replay.status().is_success());
    register(&recovered["syncFactorToken"]).await;
    assert_eq!(
        common::verify_s3_metadata_exists(id).await["syncFactors"]
            .as_array()
            .unwrap()
            .len(),
        25
    );
    assert_eq!(
        common::verify_s3_metadata_exists(other_id).await,
        other_before
    );
}

#[tokio::test]
async fn failed_best_effort_reclaim_still_allows_existing_registration_flow() {
    let ((public_key, secret), _) = common::create_test_backup_with_keypair(b"recover me").await;
    let recovered = recover(&public_key, &secret).await;
    // A registration token must not authorize maintenance or be burned by the wrong endpoint.
    let rejected = common::send_post_request_with_bypass_attestation_token(
        "/v1/reclaim-sync-factor-slot",
        json!({"syncFactorMaintenanceToken": recovered["syncFactorToken"]}),
        None,
    )
    .await;
    assert!(!rejected.status().is_success());
    register(&recovered["syncFactorToken"]).await;
}
