use std::sync::Arc;

use crate::auth::AuthHandler;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
use crate::error::ErrorResponse;
use crate::factor_lookup::{
    factor_lookup_mutate_lock_id, FactorLookup, FACTOR_LOOKUP_MUTATE_LOCK_PREFIX,
    FACTOR_LOOKUP_MUTATE_LOCK_TTL_SECS,
};
use crate::redis_cache::RedisCacheManager;
use axum::{Extension, Json};
use types::{AddSyncFactorRequest, AddSyncFactorResponse, FactorScope};

/// Adds a new sync factor to an existing backup.
pub async fn handler(
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(redis_cache_manager): Extension<Arc<RedisCacheManager>>,
    Extension(auth_handler): Extension<AuthHandler>,
    request: Json<AddSyncFactorRequest>,
) -> Result<Json<AddSyncFactorResponse>, ErrorResponse> {
    // Step 1: Validate the new sync factor using AuthHandler
    let validation_result = auth_handler
        .validate_factor_registration(
            &request.sync_factor,
            request.challenge_token.clone(),
            ChallengeContext::AddSyncFactor {},
            None,
            true, // is_sync_factor
        )
        .await?;

    let sync_factor = validation_result.factor;
    let sync_factor_to_lookup = validation_result.factor_to_lookup;

    // Acquire before consuming the one-time sync token so a Locked response does not burn the token.
    let mut factor_lock = redis_cache_manager
        .try_acquire_lock_guard(
            FACTOR_LOOKUP_MUTATE_LOCK_PREFIX,
            factor_lookup_mutate_lock_id(&sync_factor_to_lookup),
            Some(FACTOR_LOOKUP_MUTATE_LOCK_TTL_SECS),
        )
        .await?;

    // Step 2: Verify the sync factor token and extract the backup ID
    let backup_id = redis_cache_manager
        .use_sync_factor_token(request.sync_factor_token.clone())
        .await?;

    // Step 3: Add the sync factor to backup lookup
    factor_lookup
        .insert(FactorScope::Sync, &sync_factor_to_lookup, backup_id.clone())
        .await?;

    // Step 4: Add the sync factor to the backup metadata
    let write = backup_storage
        .add_sync_factor(&backup_id, sync_factor)
        .await;

    // Step 4.1: Roll back lookup / token only when the metadata write definitely did not land
    // (`NotInserted`). Skip for `Unknown` (ambiguous S3 write or factor already present).
    if write.should_rollback_lookup() {
        if let Err(e) = factor_lookup
            .delete(FactorScope::Sync, &sync_factor_to_lookup)
            .await
        {
            tracing::error!(message = "Failed to delete factor from lookup table after failed sync factor addition.", error = ?e, sync_factor_pk = sync_factor_to_lookup.primary_key());
        }

        if let Err(e) = redis_cache_manager
            .unuse_sync_factor_token(request.sync_factor_token.clone())
            .await
        {
            tracing::error!(message = "Failed to unmark sync factor token as used after failed sync factor addition.", error = ?e);
        }
    }

    let _ = factor_lock.release().await;

    write.into_result()?;

    Ok(Json(AddSyncFactorResponse { backup_id }))
}
