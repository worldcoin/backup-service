use std::sync::Arc;
use std::time::Duration;

use crate::auth::AuthHandler;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
use crate::environment::Environment;
use crate::error::ErrorResponse;
use crate::utils::extract_fields_from_multipart;
use axum::extract::{Multipart, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum::{extract::Extension, Json};
use tokio::time::Instant;
use tracing::Instrument;
use types::{
    ErrorCode, FactorScope, SyncBackupRequest, SyncBackupResponse, MULTIPART_BACKUP_FIELD,
    MULTIPART_PAYLOAD_FIELD,
};

#[derive(Clone, Copy)]
pub struct SyncDeadline(Instant);

pub async fn with_deadline(mut request: Request, next: Next) -> Response {
    // Leave time to return a committed sync before the server's 30-second timeout.
    request
        .extensions_mut()
        .insert(SyncDeadline(Instant::now() + Duration::from_secs(25)));
    next.run(request).await
}

pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(auth_handler): Extension<AuthHandler>,
    Extension(deadline): Extension<SyncDeadline>,
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
    let (backup_id, backup_metadata, mut account_lock) = auth_handler
        .verify(
            &request.authorization,
            FactorScope::Sync,
            ChallengeContext::Sync {},
            request.challenge_token,
        )
        .await?;

    account_lock.limit_deadline(deadline.0);

    let span = tracing::info_span!(
        "sync_backup",
        backup_id = %backup_id,
        current_manifest_hash = %backup_metadata.manifest_hash,
        new_manifest_hash = %request.new_manifest_hash
    );
    async move {
        let previous_archive = account_lock
            .run(async {
                Ok::<_, ErrorResponse>(
                    backup_storage
                        .update_backup(
                            &backup_id,
                            backup,
                            request.current_manifest_hash,
                            request.new_manifest_hash,
                            request.encryption_public_key.as_deref(),
                        )
                        .await?,
                )
            })
            .await?;

        if let Err(error) = account_lock
            .run(async {
                backup_storage
                    .delete_archive(&previous_archive)
                    .await
                    .map_err(ErrorResponse::from)
            })
            .await
        {
            metrics::counter!("backup_archive_cleanup_failures_total", "operation" => "sync")
                .increment(1);
            tracing::warn!(
                message = "Sync committed but previous archive deletion failed",
                ?error
            );
        }

        let _ = tokio::time::timeout(Duration::from_secs(1), account_lock.release()).await;

        Ok(Json(SyncBackupResponse { backup_id }))
    }
    .instrument(span)
    .await
}
