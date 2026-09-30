use std::sync::Arc;

use crate::auth::AuthHandler;
use crate::backup_metadata::Factor;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
use crate::environment::Environment;
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
    Extension(environment): Extension<Environment>,
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

    // Step 3: Reserve the new key's lookup. A lost response may already have inserted this
    // same owner's row; retain it and reconcile metadata rather than rejecting a safe retry.
    let inserted_lookup = match factor_lookup
        .insert(FactorScope::Sync, &sync_factor_to_lookup, backup_id.clone())
        .await
    {
        Ok(()) => true,
        Err(error) => {
            if factor_lookup
                .lookup_consistent(FactorScope::Sync, &sync_factor_to_lookup)
                .await?
                != Some(backup_id.clone())
            {
                return Err(error.into());
            }
            false
        }
    };

    // Step 4: Add the sync factor, or swap it in for `sync_factor_to_replace` when present.
    let write = backup_storage
        .register_sync_factor(
            &backup_id,
            sync_factor,
            request.sync_factor_to_replace.as_deref(),
        )
        .await;

    // Step 4.1: Roll back lookup / token only when the metadata write definitely did not land
    // (`NotInserted`). Skip for `Unknown` (ambiguous S3 write or factor already present).
    if write.should_rollback_lookup() && inserted_lookup {
        if let Err(e) = factor_lookup
            .delete_if_maps_to(FactorScope::Sync, &sync_factor_to_lookup, &backup_id)
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

    if let Some(removed) = write.into_result()? {
        if let Err(error) = cleanup_replaced_lookup(
            environment,
            &backup_storage,
            &factor_lookup,
            &redis_cache_manager,
            &backup_id,
            &removed,
        )
        .await
        {
            tracing::warn!(?error, factor_id = %removed.id, backup_id = %backup_id,
                "Sync factor replaced but lookup cleanup failed");
        }
    }

    Ok(Json(AddSyncFactorResponse { backup_id }))
}

/// Recheck membership while holding the same key lock as registration. Cleanup must not delete
/// a re-registered key or another backup's row. Stale lookup rows alone never grant access.
async fn cleanup_replaced_lookup(
    environment: Environment,
    storage: &BackupStorage,
    lookup: &FactorLookup,
    redis: &RedisCacheManager,
    backup_id: &str,
    removed: &Factor,
) -> Result<(), ErrorResponse> {
    let factor = removed.as_factor_to_lookup(&environment);
    let mut guard = redis
        .try_acquire_lock_guard(
            FACTOR_LOOKUP_MUTATE_LOCK_PREFIX,
            factor_lookup_mutate_lock_id(&factor),
            Some(FACTOR_LOOKUP_MUTATE_LOCK_TTL_SECS),
        )
        .await?;
    let metadata = storage.get_metadata_by_backup_id(backup_id).await?;
    let present = metadata.is_some_and(|(metadata, _)| {
        metadata
            .sync_factors
            .iter()
            .any(|factor| factor.kind == removed.kind)
    });
    if !present {
        lookup
            .delete_if_maps_to(FactorScope::Sync, &factor, backup_id)
            .await?;
    }
    guard.release().await?;
    Ok(())
}
