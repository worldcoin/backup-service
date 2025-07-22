use std::sync::Arc;

use axum::{Extension, Json};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use schemars::JsonSchema;
use serde::Serialize;

use crate::{
    backup_storage::BackupStorage,
    challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType},
    dynamo_cache::DynamoCacheManager,
    factor_lookup::{FactorLookup, FactorScope, FactorToLookup},
    types::{backup_metadata::BackupMetadata, ErrorResponse},
};

#[derive(Serialize)]
pub struct ReadyRequest {}

#[derive(Serialize, JsonSchema)]
pub struct ReadyResponse {
    status: String,
}

const TEST_BACKUP_ID: &str = "canary_backup";

/// Runs multiple preflight checks to ensure the application is ready to serve requests (Dynamo, S3 and KMS configurations are correct).
///
/// Returns 200 if everything works as expected.
///
/// This endpoint is intended to only be run internally, and will generally not be publicly accessible.
pub async fn handler(
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(dynamo_cache_manager): Extension<Arc<DynamoCacheManager>>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
) -> Result<Json<ReadyResponse>, ErrorResponse> {
    // Step 1: Check Dynamo Cache Manager (PutItem)
    let token = dynamo_cache_manager
        .create_sync_factor_token(TEST_BACKUP_ID.to_string())
        .await
        .map_err(|e| {
            tracing::error!(
                "System is not ready. DynamoChacheManager (PutItem): {:?}",
                e
            );
            ErrorResponse::internal_server_error()
        })?;

    // Step 2: Check Dynamo Cache Manager (GetItem + UpdateItem)
    dynamo_cache_manager
        .use_sync_factor_token(token)
        .await
        .map_err(|e| {
            tracing::error!(
                "System is not ready. Error using sync factor token (GetItem + UpdateItem): {:?}",
                e
            );
            ErrorResponse::internal_server_error()
        })?;

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
        .map_err(|e| {
            tracing::error!("System is not ready. FactorLookup (PutItem): {:?}", e);
            ErrorResponse::internal_server_error()
        })?;

    // Step 4: Remove the factor from FactorLookup (DeleteItem)
    factor_lookup
        .delete(FactorScope::Sync, &canary_factor)
        .await
        .map_err(|e| {
            tracing::error!("System is not ready. FactorLookup (DeleteItem): {:?}", e);
            ErrorResponse::internal_server_error()
        })?;

    // Step 5: Create a demo backup (S3 PutObject)
    let backup_metadata = BackupMetadata {
        id: TEST_BACKUP_ID.to_string(),
        factors: vec![],
        sync_factors: vec![],
        keys: vec![],
    };
    backup_storage
        .create(b"TEST_BACKUP_CONTENT".to_vec(), &backup_metadata)
        .await
        .map_err(|e| {
            tracing::error!("System is not ready. BackupStorage (Create): {:?}", e);
            ErrorResponse::internal_server_error()
        })?;

    // Step 6: Remove the backup (S3 GetObject + DeleteObject)
    backup_storage
        .get_backup_by_backup_id(TEST_BACKUP_ID)
        .await
        .map_err(|e| {
            tracing::error!("System is not ready. BackupStorage (GetObject): {:?}", e);
            ErrorResponse::internal_server_error()
        })?;

    backup_storage
        .delete_backup(TEST_BACKUP_ID)
        .await
        .map_err(|e| {
            tracing::error!("System is not ready. BackupStorage (DeleteObject): {:?}", e);
            ErrorResponse::internal_server_error()
        })?;

    // Step 7: Create a challenge token (KMS)
    challenge_manager
        .create_challenge_token(
            ChallengeType::Keypair,
            b"TEST_CHALLENGE",
            ChallengeContext::AddSyncFactor {},
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "System is not ready. ChallengeManager (CreateChallengeToken): {:?}",
                e
            );
            ErrorResponse::internal_server_error()
        })?;

    Ok(Json(ReadyResponse {
        status: "ok".to_string(),
    }))
}
