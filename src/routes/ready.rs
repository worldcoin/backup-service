use std::sync::Arc;

use axum::{Extension, Json};
use schemars::JsonSchema;
use serde::Serialize;

use crate::{
    backup_storage::BackupStorage, dynamo_cache::DynamoCacheManager, factor_lookup::FactorLookup,
    types::ErrorResponse,
};

#[derive(Serialize)]
pub struct ReadyRequest {}

#[derive(Serialize, JsonSchema)]
pub struct ReadyResponse {
    status: String,
}

/// Runs multiple preflight checks to ensure the application is ready to serve requests (Dynamo, S3 and KMS configurations are correct).
///
/// Returns 200 if everything works as expected.
pub async fn handler(
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(dynamo_cache_manager): Extension<Arc<DynamoCacheManager>>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
) -> Result<Json<ReadyResponse>, ErrorResponse> {
    // Step 1: Check `DynamoCacheManager` is ready
    if !dynamo_cache_manager.is_ready().await {
        return Err(ErrorResponse::internal_server_error());
    }

    // Step 2: Check `FactorLookup` is ready
    if !factor_lookup.is_ready().await {
        return Err(ErrorResponse::internal_server_error());
    }

    // Step 3: Check `BackupStorage` is ready
    if !backup_storage.is_ready().await {
        return Err(ErrorResponse::internal_server_error());
    }

    Ok(Json(ReadyResponse {
        status: "ok".to_string(),
    }))
}
