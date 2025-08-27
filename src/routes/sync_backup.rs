use std::sync::Arc;

use crate::auth::AuthHandler;
use crate::axum_utils::extract_fields_from_multipart;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
use crate::deserialize_hex_32;
use crate::factor_lookup::FactorScope;
use crate::types::{Authorization, Environment, ErrorResponse};
use axum::extract::Multipart;
use axum::{extract::Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SyncBackupRequest {
    authorization: Authorization,
    challenge_token: String,
    #[serde(deserialize_with = "deserialize_hex_32")]
    current_manifest_hash: [u8; 32],
    #[serde(deserialize_with = "deserialize_hex_32")]
    new_manifest_hash: [u8; 32],
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncBackupResponse {
    pub backup_id: String,
}

pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(auth_handler): Extension<AuthHandler>,
    mut multipart: Multipart,
) -> Result<Json<SyncBackupResponse>, ErrorResponse> {
    // Step 1: Parse multipart form data. It should include the main JSON payload with parameters
    // and the attached backup file.
    let multipart_fields = extract_fields_from_multipart(&mut multipart).await?;
    let request = multipart_fields.get("payload").ok_or_else(|| {
        tracing::info!(message = "Missing payload field in multipart data");
        ErrorResponse::bad_request("missing_payload_field")
    })?;
    let request: SyncBackupRequest = serde_json::from_slice(request).map_err(|err| {
        tracing::info!(message = "Failed to deserialize payload", error = ?err);
        ErrorResponse::bad_request("invalid_payload")
    })?;
    let backup = multipart_fields.get("backup").ok_or_else(|| {
        tracing::info!(message = "Missing backup field in multipart data");
        ErrorResponse::bad_request("missing_backup_field")
    })?;

    // Step 1.1: Validate the backup file size
    if backup.is_empty() {
        tracing::info!(message = "Empty backup file");
        return Err(ErrorResponse::bad_request("empty_backup_file"));
    }
    if backup.len() > environment.max_backup_file_size() {
        tracing::info!(message = "Backup file too large");
        return Err(ErrorResponse::bad_request("backup_file_too_large"));
    }

    // Step 2: Auth. Verify the solved challenge in the authorization parameter
    let (backup_id, _backup_metadata) = auth_handler
        .verify(
            &request.authorization,
            FactorScope::Sync,
            ChallengeContext::Sync {},
            request.challenge_token,
        )
        .await?;

    // Step 3: Update the backup with the new backup file
    backup_storage
        .update_backup(
            &backup_id,
            backup.to_vec(),
            request.current_manifest_hash,
            request.new_manifest_hash,
        )
        .await?;

    Ok(Json(SyncBackupResponse { backup_id }))
}
