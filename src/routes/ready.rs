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
    // Run all ready checks in parallel
    let (dynamo_ready, factor_lookup_ready, backup_storage_ready) = tokio::join!(
        dynamo_cache_manager.is_ready(),
        factor_lookup.is_ready(),
        backup_storage.is_ready()
    );

    // Check if any of the services are not ready
    if !dynamo_ready || !factor_lookup_ready || !backup_storage_ready {
        return Err(ErrorResponse::internal_server_error());
    }

    Ok(Json(ReadyResponse {
        status: "ok".to_string(),
    }))
}
