use std::sync::Arc;

use axum::extract::Request;
use backup_service::{
    backup_storage::BackupStorage,
    challenge_manager::{ChallengeContext, ChallengeType},
    factor_lookup::{FactorScope, FactorToLookup},
    types::{backup_metadata::BackupMetadata, Environment},
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use http::StatusCode;
use http_body_util::BodyExt;
use rand::RngCore;
use serde_json::json;
use tower::ServiceExt;

use crate::common::{get_challenge_manager, get_test_router, get_test_s3_client};

mod common;

/// This end-to-end test runs through multiple operations to ensure all relevant AWS policies are set.
///
/// In particular, it will ensure the right policies for both Dynamo tables and the S3 bucket are set.
#[tokio::test]
async fn test_end_to_end_readiness() {
    dotenvy::from_filename(".env.example").unwrap();

    let environment = Environment::development(None);
    let s3_client = Arc::new(get_test_s3_client().await);
    let dynamodb_client = Arc::new(aws_sdk_dynamodb::Client::new(
        &environment.aws_config().await,
    ));
    let challenge_manager = get_challenge_manager().await;
    let backup_storage = BackupStorage::new(environment, s3_client.clone());
    let factor_lookup = Arc::new(backup_service::factor_lookup::FactorLookup::new(
        environment,
        dynamodb_client.clone(),
    ));
    let dynamo_cache_manager = Arc::new(backup_service::dynamo_cache::DynamoCacheManager::new(
        environment,
        environment.cache_default_ttl(),
        dynamodb_client.clone(),
    ));

    const TEST_BACKUP_ID: &str = "canary_backup";

    // Step 0: Delete the `TEST_BACKUP` if it exists (this is clean up in case a previous test failed mid-way)
    let _ = backup_storage.delete_backup(TEST_BACKUP_ID).await; // we ignore the result because it's fine (even expected) that there's no backup to delete

    // Step 1: Check Dynamo Cache Manager (PutItem)
    let token = dynamo_cache_manager
        .create_sync_factor_token(TEST_BACKUP_ID.to_string())
        .await
        .expect("Failed to create sync factor token");

    // Step 2: Check Dynamo Cache Manager (GetItem + UpdateItem)
    dynamo_cache_manager
        .use_sync_factor_token(token)
        .await
        .expect("Failed to use sync factor token");

    // Step 3: Insert a factor into FactorLookup (PutItem)
    let mut canary_key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut canary_key_bytes);
    let canary_key = BASE64_URL_SAFE_NO_PAD.encode(canary_key_bytes);
    let canary_factor = FactorToLookup::from_ec_keypair(canary_key);
    factor_lookup
        .insert(
            FactorScope::Sync,
            &canary_factor,
            TEST_BACKUP_ID.to_string(),
        )
        .await
        .expect("Failed to insert factor into FactorLookup");

    // Step 4: Remove the factor from FactorLookup (DeleteItem)
    factor_lookup
        .delete(FactorScope::Sync, &canary_factor)
        .await
        .expect("Failed to delete factor from FactorLookup");

    // Step 5: Create a demo backup (S3 PutObject)
    let backup_metadata = BackupMetadata {
        id: TEST_BACKUP_ID.to_string(),
        factors: vec![],
        sync_factors: vec![],
        keys: vec![],
        manifest_hash: hex::encode([1u8; 32]),
    };

    backup_storage
        .create(b"TEST_BACKUP_CONTENT".to_vec(), &backup_metadata)
        .await
        .expect("Failed to create backup");

    // Step 6: Remove the backup (S3 GetObject + DeleteObject)
    backup_storage
        .get_by_backup_id(TEST_BACKUP_ID)
        .await
        .expect("Failed to get backup");

    backup_storage
        .delete_backup(TEST_BACKUP_ID)
        .await
        .expect("Failed to delete backup");

    // Step 7: Create a challenge token (KMS)
    challenge_manager
        .create_challenge_token(
            ChallengeType::Keypair,
            b"TEST_CHALLENGE",
            ChallengeContext::AddSyncFactor {},
        )
        .await
        .expect("Failed to create challenge token");
}

#[tokio::test]
async fn test_ready_endpoint() {
    dotenvy::from_filename(".env.example").unwrap();
    let app = get_test_router(None, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .method("GET")
                .header("Content-Type", "application/json")
                .body(json!({}).to_string())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let response_body = response.into_body().collect().await.unwrap().to_bytes();
    let response_body: serde_json::Value = serde_json::from_slice(&response_body).unwrap();
    assert_eq!(response_body, json!({ "status": "ok" }));
}
