use std::sync::Arc;

use crate::auth::AuthHandler;
use crate::backup_metadata::BackupMetadata;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
use crate::environment::Environment;
use crate::error::ErrorResponse;
use crate::factor_lookup::FactorLookup;
use crate::headers::CLIENT_VERSION;
use crate::redis_cache::RedisCacheManager;
use aide::transform::TransformOperation;
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http::HeaderMap;
use tracing::Instrument;
use types::{
    ExportedBackupMetadata, FactorScope, RetrieveBackupFromChallengeRequest,
    RetrieveBackupFromChallengeResponse,
};

/// Outcome of reading sync factors' last use during recovery (`ok`, `error`, `timeout`).
const SYNC_FACTOR_LAST_USED_READ_METRIC: &str = "sync_factor_last_used_read_total";

const SYNC_FACTOR_LAST_USED_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

pub fn docs(op: TransformOperation) -> TransformOperation {
    op.description(
        "Request to retrieve a full backup (ciphertext) with an authenticated challenge. This endpoint requires Attestation Gateway checks (through the `attestation-token` header).",
    )
    .security_requirement("AttestationToken")
}

/// Request to retrieve a backup using a solved challenge.
pub async fn handler(
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(redis_cache_manager): Extension<Arc<RedisCacheManager>>,
    Extension(auth_handler): Extension<AuthHandler>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(environment): Extension<Environment>,
    headers: HeaderMap,
    request: Json<RetrieveBackupFromChallengeRequest>,
) -> Result<Json<RetrieveBackupFromChallengeResponse>, ErrorResponse> {
    // Step 1: Auth. Verify the solved challenge
    let (backup_id, backup_metadata) = auth_handler
        .verify(
            &request.authorization,
            FactorScope::Main,
            ChallengeContext::Retrieve {},
            request.challenge_token.clone(),
        )
        .await?;

    let client_version = headers
        .get(&CLIENT_VERSION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let span = tracing::info_span!("retrieve_backup_from_challenge", backup_id = %backup_id, client_version = %client_version);

    async move {
        // Step 2: Fetch the backup from S3
        let backup = backup_storage.get_backup_by_backup_id(&backup_id).await?;
        let Some(backup) = backup else {
            tracing::error!(message = "No backup found for the verified backup ID.");
            return Err(ErrorResponse::internal_server_error());
        };

        // Step 3: Create a sync factor token to allow the user to add a new sync factor later
        let sync_factor_token = redis_cache_manager
            .create_sync_factor_token(backup_metadata.id.clone())
            .await?;

        // Step 4: Return the backup and metadata
        let mut metadata = backup_metadata.exported();
        attach_sync_factor_last_used(
            &factor_lookup,
            &environment,
            &backup_metadata,
            &mut metadata,
        )
        .await;

        Ok(Json(RetrieveBackupFromChallengeResponse {
            backup: STANDARD.encode(backup),
            metadata,
            sync_factor_token,
        }))
    }
    .instrument(span)
    .await
}

/// Adds each sync factor's last use so a client at the sync-factor cap can replace the least
/// recently used access. Best-effort and bounded: on failure the values are omitted and the client
/// falls back to creation time, so recovery itself never fails here.
async fn attach_sync_factor_last_used(
    factor_lookup: &FactorLookup,
    environment: &Environment,
    backup_metadata: &BackupMetadata,
    exported: &mut ExportedBackupMetadata,
) {
    if backup_metadata.sync_factors.is_empty() {
        return;
    }
    let lookups = backup_metadata
        .sync_factors
        .iter()
        .map(|factor| factor.as_factor_to_lookup(environment))
        .collect::<Vec<_>>();
    let read = factor_lookup.last_used_at(FactorScope::Sync, &lookups, &backup_metadata.id);
    let last_used = match tokio::time::timeout(SYNC_FACTOR_LAST_USED_READ_TIMEOUT, read).await {
        Ok(Ok(last_used)) => {
            metrics::counter!(SYNC_FACTOR_LAST_USED_READ_METRIC, "result" => "ok").increment(1);
            last_used
        }
        Ok(Err(err)) => {
            metrics::counter!(SYNC_FACTOR_LAST_USED_READ_METRIC, "result" => "error").increment(1);
            tracing::warn!(?err, "Failed to read sync factors' last use; omitting it");
            return;
        }
        Err(_) => {
            metrics::counter!(SYNC_FACTOR_LAST_USED_READ_METRIC, "result" => "timeout")
                .increment(1);
            tracing::warn!(
                timeout_ms = SYNC_FACTOR_LAST_USED_READ_TIMEOUT.as_millis(),
                "Timed out reading sync factors' last use; omitting it"
            );
            return;
        }
    };
    for (factor, lookup) in backup_metadata.sync_factors.iter().zip(&lookups) {
        if let Some(exported_factor) = exported
            .sync_factors
            .iter_mut()
            .find(|it| it.id == factor.id)
        {
            exported_factor.last_used_at = last_used.get(&lookup.primary_key()).copied();
        }
    }
}
