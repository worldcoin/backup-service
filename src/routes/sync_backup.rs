use std::sync::Arc;

use crate::auth::AuthHandler;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
use crate::environment::Environment;
use crate::error::ErrorResponse;
use crate::redis_cache::RedisCacheManager;
use crate::utils::extract_fields_from_multipart;
use axum::extract::Multipart;
use axum::{extract::Extension, Json};
use tracing::Instrument;
use types::{
    ErrorCode, FactorScope, SyncBackupRequest, SyncBackupResponse, MULTIPART_BACKUP_FIELD,
    MULTIPART_PAYLOAD_FIELD,
};

const SYNC_BACKUP_LOCK_KEY: &str = "sync_backup_lock:";
const SYNC_BACKUP_LOCK_TTL: u64 = 120; // 2 minutes (normally timeout shouldn't be hit, it's a fallback in case the lock is not released)

// Lock guard is now provided by the redis_cache module

pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(auth_handler): Extension<AuthHandler>,
    Extension(redis_cache_manager): Extension<Arc<RedisCacheManager>>,
    mut multipart: Multipart,
) -> Result<Json<SyncBackupResponse>, ErrorResponse> {
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
    let request: SyncBackupRequest = serde_json::from_slice(request).map_err(|err| {
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

    // Step 2: Auth. Verify the solved challenge in the authorization parameter
    let (backup_id, backup_metadata) = auth_handler
        .verify(
            &request.authorization,
            FactorScope::Sync,
            ChallengeContext::Sync {},
            request.challenge_token,
        )
        .await?;

    let span = tracing::info_span!(
        "sync_backup",
        backup_id = %backup_id,
        current_manifest_hash = %backup_metadata.manifest_hash,
        new_manifest_hash = %request.new_manifest_hash
    );
    async move {
        // Step 3: Acquire a lock on the backup to prevent concurrent updates
        let mut lock_guard = redis_cache_manager
            .try_acquire_lock_guard(
                SYNC_BACKUP_LOCK_KEY,
                backup_id.clone(),
                Some(SYNC_BACKUP_LOCK_TTL),
            )
            .await?;

        // Step 4: Update the backup with the new backup file
        let update_result = backup_storage
            .update_backup(
                &backup_id,
                backup,
                request.current_manifest_hash,
                request.new_manifest_hash,
            )
            .await;

        let _ = lock_guard.release().await; // explicitly releasing the lock is more reliable

        if let Err(e) = update_result {
            return Err(e.into());
        }

        Ok(Json(SyncBackupResponse { backup_id }))
    }
    .instrument(span)
    .await
}
