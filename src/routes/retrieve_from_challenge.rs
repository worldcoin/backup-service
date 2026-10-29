use std::sync::Arc;

use crate::auth::{AuthHandler, AuthenticationResult};
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
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
use types::{FactorScope, RetrieveBackupFromChallengeRequest, RetrieveBackupFromChallengeResponse};

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
    headers: HeaderMap,
    request: Json<RetrieveBackupFromChallengeRequest>,
) -> Result<Json<RetrieveBackupFromChallengeResponse>, ErrorResponse> {
    // Step 1: Auth. Verify the solved challenge
    let AuthenticationResult {
        backup_id,
        backup_metadata,
        account_lock,
        ..
    } = auth_handler
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

    account_lock
        .run_and_release(async move {
            // Step 2: Fetch the backup from S3
            let backup = backup_storage
                .get_backup_by_metadata(&backup_metadata)
                .await?;
            let Some(backup) = backup else {
                tracing::error!(message = "No backup found for the verified backup ID.");
                return Err(ErrorResponse::internal_server_error());
            };

            // Step 3: Create a sync factor token to allow the user to add a new sync factor later
            let sync_factor_token = redis_cache_manager
                .create_sync_factor_token(backup_metadata.id.clone())
                .await?;

            // Step 4: Return the backup and metadata
            // 4.1: Include the last_used attribute (best-effort)
            let last_used = factor_lookup
                .fetch_last_used(&backup_metadata.sync_factors, &backup_metadata.id)
                .await
                .inspect_err(|err| {
                    tracing::error!(?err, "Failed to fetch sync factors' last use; omitting it");
                })
                .unwrap_or_default();
            let mut metadata = backup_metadata.exported();
            for factor in &mut metadata.sync_factors {
                factor.last_used = last_used.get(&factor.id).copied();
            }

            Ok(Json(RetrieveBackupFromChallengeResponse {
                backup: STANDARD.encode(backup),
                metadata,
                sync_factor_token,
            }))
        })
        .instrument(span)
        .await
}
