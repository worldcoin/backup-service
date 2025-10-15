use std::sync::Arc;

use crate::auth::{AuthError, AuthHandler};
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
use crate::factor_lookup::FactorScope;
use crate::types::backup_metadata::ExportedBackupMetadata;
use crate::types::{Authorization, ErrorResponse};
use axum::{extract::Extension, Json};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveMetadataRequest {
    authorization: Authorization,
    challenge_token: String,
    /// (Optional). If provided, the system will verify the provided backup ID matches the backup ID from the factors.
    ///
    /// It will also return a specific error if the backup ID no longer exists. This is useful to handle multi-device setups
    /// where the user may have deleted their backup on one device and the other device is unaware.
    backup_id: Option<String>,
}

/// Retrieves the backup metadata using a sync factor. This endpoint allows a client to view
/// the metadata of a backup using only a sync factor for authentication. It's powering the
/// settings screen in the client app.
pub async fn handler(
    Extension(auth_handler): Extension<AuthHandler>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Json(request): Json<RetrieveMetadataRequest>,
) -> Result<Json<ExportedBackupMetadata>, ErrorResponse> {
    // Step 1: Auth. Verify the solved challenge
    let backup_metadata = auth_handler
        .verify(
            &request.authorization,
            FactorScope::Sync,
            ChallengeContext::RetrieveMetadata {},
            request.challenge_token,
        )
        .await;

    if matches!(backup_metadata, Err(AuthError::BackupUntraceable)) {
        // when the backup cannot be traced to a specific backup ID and if the client provided an explicit backup ID we check
        // if the problem is the backup does not actually exist or instead the factor is invalid
        if let Some(backup_id) = request.backup_id {
            let exists = backup_storage.does_backup_exist(&backup_id).await?;
            if exists {
                // This may happen e.g. if user has a backup in two devices and device A revokes access to the sync factor of device B
                // (e.g. through deleting and re-creating the entire backup). Device B can remediate by adding a new sync
                return Err(AuthError::UnauthorizedFactor.into());
            }
            return Err(AuthError::BackupDoesNotExist.into());
        }
    }

    let (backup_id, backup_metadata) = backup_metadata?;

    if let Some(expected_backup_id) = request.backup_id {
        if backup_id != expected_backup_id {
            return Err(AuthError::BackupIdMismatch.into());
        }
    }

    // Step 2: Return the backup metadata
    let exported_metadata = backup_metadata.exported();

    Ok(Json(exported_metadata))
}
