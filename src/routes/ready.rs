use std::sync::Arc;

use axum::{Extension, Json};
use http::StatusCode;
use schemars::JsonSchema;
use serde::Serialize;

use crate::{
    backup_storage::BackupStorage, factor_lookup::FactorLookup, redis_cache::RedisCacheManager,
    shutdown,
};

#[derive(Serialize, JsonSchema)]
pub struct ReadyResponse {
    status: String,
}

/// Reports whether this instance should receive traffic: shutdown has not started and the Redis,
/// S3, `DynamoDB` and KMS configurations all work.
///
/// Returns 200 when ready, 503 otherwise. Each preflight check logs its own failure.
pub async fn handler(
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(redis_cache_manager): Extension<Arc<RedisCacheManager>>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
) -> Result<Json<ReadyResponse>, StatusCode> {
    if shutdown::is_draining() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    // Run all ready checks in parallel
    let (redis_ready, factor_lookup_ready, backup_storage_ready) = tokio::join!(
        redis_cache_manager.is_ready(),
        factor_lookup.is_ready(),
        backup_storage.is_ready()
    );

    // Check if any of the services are not ready
    if !redis_ready || !factor_lookup_ready || !backup_storage_ready {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    Ok(Json(ReadyResponse {
        status: "ok".to_string(),
    }))
}
