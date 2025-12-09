use std::sync::Arc;

use crate::auth::AuthHandler;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
use crate::factor_lookup::FactorScope;
use crate::redis_cache::RedisCacheManager;
use crate::types::backup_metadata::ExportedBackupMetadata;
use crate::types::{Authorization, ErrorResponse};
use aide::transform::TransformOperation;
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http::HeaderMap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::Instrument;

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveBackupFromChallengeRequest {
    authorization: Authorization,
    challenge_token: String,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveBackupFromChallengeResponse {
    /// Encrypted backup in base64.
    backup: String,
    /// Metadata about the backup, including the Turnkey ID and encryption keys.
    metadata: ExportedBackupMetadata,
    /// Token to add a new sync factor later.
    sync_factor_token: String,
}

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
        .get("client-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let client_name = headers
        .get("client-name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let span = tracing::info_span!("retrieve_backup_from_challenge", backup_id = %backup_id, client_version = %client_version, client_name = %client_name);

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
        Ok(Json(RetrieveBackupFromChallengeResponse {
            backup: STANDARD.encode(backup),
            metadata: backup_metadata.exported(),
            sync_factor_token,
        }))
    }
    .instrument(span)
    .await
}
