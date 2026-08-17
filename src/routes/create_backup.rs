use std::sync::Arc;

use crate::auth::AuthHandler;
use crate::backup_metadata::BackupMetadata;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
use crate::environment::Environment;
use crate::error::ErrorResponse;
use crate::factor_lookup::{
    factor_lookup_mutate_lock_id, FactorLookup, FACTOR_LOOKUP_MUTATE_LOCK_PREFIX,
    FACTOR_LOOKUP_MUTATE_LOCK_TTL_SECS,
};
use crate::redis_cache::RedisCacheManager;
use crate::utils::extract_fields_from_multipart;
use axum::extract::Multipart;
use axum::{extract::Extension, Json};
use types::{
    CreateBackupRequest, CreateBackupResponse, ErrorCode, FactorScope, MULTIPART_BACKUP_FIELD,
    MULTIPART_PAYLOAD_FIELD,
};

const CREATE_BACKUP_LOCK_KEY: &str = "crate_backup_lock:";
const CREATE_BACKUP_LOCK_TTL: u64 = 120; // 2 minutes (normally timeout shouldn't be hit, it's a fallback in case the lock is not released)

#[allow(clippy::too_many_lines)]
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(auth_handler): Extension<AuthHandler>,
    Extension(redis_cache_manager): Extension<Arc<RedisCacheManager>>,
    mut multipart: Multipart,
) -> Result<Json<CreateBackupResponse>, ErrorResponse> {
    // Step 1: Parse multipart form data. It should include the main JSON payload with parameters
    // and the attached backup file.
    let mut multipart_fields = extract_fields_from_multipart(&mut multipart).await?;
    let request = multipart_fields
        .get(MULTIPART_PAYLOAD_FIELD)
        .ok_or_else(|| {
            tracing::debug!(message = "Missing payload field in multipart data");
            ErrorResponse::bad_request(
                ErrorCode::MissingPayloadField,
                "Missing payload field in multipart data",
            )
        })?;
    let request: CreateBackupRequest = serde_json::from_slice(request).map_err(|err| {
        tracing::debug!(message = "Failed to deserialize payload", error = ?err);
        ErrorResponse::bad_request(ErrorCode::InvalidPayload, "Failed to deserialize payload")
    })?;
    let backup = multipart_fields
        .remove(MULTIPART_BACKUP_FIELD)
        .ok_or_else(|| {
            tracing::debug!(message = "Missing backup field in multipart data");
            ErrorResponse::bad_request(
                ErrorCode::MissingBackupField,
                "Missing backup field in multipart data",
            )
        })?;

    // Step 1.1: Validate the backup file size
    if backup.is_empty() {
        tracing::debug!(message = "Empty backup file");
        return Err(ErrorResponse::bad_request(
            ErrorCode::EmptyBackupFile,
            "Empty backup file",
        ));
    }
    if backup.len() > environment.max_backup_file_size() {
        tracing::debug!(message = "Backup file too large");
        return Err(ErrorResponse::content_too_large(
            "Backup file exceeds maximum allowed size.".to_string(),
        ));
    }

    // Step 2: Verify the main authentication factor
    // This validates the primary factor used to authenticate the user creating the backup

    let validation_result = auth_handler
        .validate_factor_registration(
            &request.authorization,
            request.challenge_token.clone(),
            ChallengeContext::Create {},
            request.turnkey_provider_id.clone(),
            false, // not a sync factor
        )
        .await?;

    let backup_factor = validation_result.factor;
    let factor_to_lookup = validation_result.factor_to_lookup;

    // Step 3: Verify the initial sync factor
    // This validates the sync factor (EC keypair) that will be used for cross-device synchronization
    let sync_validation_result = auth_handler
        .validate_factor_registration(
            &request.initial_sync_factor,
            request.initial_sync_challenge_token.clone(),
            ChallengeContext::Create {},
            None,
            true, // is a sync factor
        )
        .await?;

    let initial_sync_factor = sync_validation_result.factor;
    let initial_sync_factor_to_lookup = sync_validation_result.factor_to_lookup;

    // Step 4: Ensure the backup account ID is unique
    if backup_storage
        .does_backup_exist(&request.backup_account_id)
        .await?
    {
        tracing::info!(
            message = "Backup account ID already exists",
            backup_account_id = request.backup_account_id
        );
        return Err(ErrorResponse::conflict(
            ErrorCode::BackupAccountIdAlreadyExists,
            "Backup ID already exists. Please `/sync` instead.",
        ));
    }
    let mut lock_guard = redis_cache_manager
        .try_acquire_lock_guard(
            CREATE_BACKUP_LOCK_KEY,
            request.backup_account_id.clone(),
            Some(CREATE_BACKUP_LOCK_TTL),
        )
        .await?;

    // Step 5: Initialize backup metadata
    let backup_metadata = BackupMetadata {
        id: request.backup_account_id,
        factors: vec![backup_factor],
        sync_factors: vec![initial_sync_factor],
        keys: vec![request.initial_encryption_key.clone()],
        manifest_hash: request.manifest_hash,
    };

    // Hold factor mutate locks across lookup insert + S3 create so auth stale-delete cannot remove
    // rows while metadata is still being written.
    let mut main_factor_lock = redis_cache_manager
        .try_acquire_lock_guard(
            FACTOR_LOOKUP_MUTATE_LOCK_PREFIX,
            factor_lookup_mutate_lock_id(&factor_to_lookup),
            Some(FACTOR_LOOKUP_MUTATE_LOCK_TTL_SECS),
        )
        .await?;
    let mut sync_factor_lock = redis_cache_manager
        .try_acquire_lock_guard(
            FACTOR_LOOKUP_MUTATE_LOCK_PREFIX,
            factor_lookup_mutate_lock_id(&initial_sync_factor_to_lookup),
            Some(FACTOR_LOOKUP_MUTATE_LOCK_TTL_SECS),
        )
        .await?;

    // Step 6: Link credential ID and sync factor public key to backup ID for lookup during recovery
    // and sync. This should happen before the backup storage is updated, because
    // it might fail with a duplicate key error.
    factor_lookup
        .insert(
            FactorScope::Main,
            &factor_to_lookup,
            backup_metadata.id.clone(),
        )
        .await?;
    factor_lookup
        .insert(
            FactorScope::Sync,
            &initial_sync_factor_to_lookup,
            backup_metadata.id.clone(),
        )
        .await?;

    // Step 7: Save the backup to S3
    let result = backup_storage.create(backup, &backup_metadata).await;

    // Step 7.1: On failure, roll back lookups while still holding mutate locks, then release.
    if let Err(e) = result {
        if let Err(del_err) = factor_lookup
            .delete(FactorScope::Main, &factor_to_lookup)
            .await
        {
            tracing::error!(message = "Failed to delete factor from lookup table after failed backup creation.", error = ?del_err);
        }
        if let Err(del_err) = factor_lookup
            .delete(FactorScope::Sync, &initial_sync_factor_to_lookup)
            .await
        {
            tracing::error!(message = "Failed to delete factor from lookup table after failed backup creation.", error = ?del_err);
        }
        let _ = main_factor_lock.release().await;
        let _ = sync_factor_lock.release().await;
        let _ = lock_guard.release().await;
        return Err(e.into());
    }

    let _ = main_factor_lock.release().await;
    let _ = sync_factor_lock.release().await;
    let _ = lock_guard.release().await; // explicitly releasing the lock is more reliable

    let backup_id = backup_metadata.id.clone();

    Ok(Json(CreateBackupResponse {
        backup_id,
        backup_metadata: backup_metadata.exported(),
    }))
}
