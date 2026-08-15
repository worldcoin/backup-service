use std::sync::Arc;

use crate::auth::AuthHandler;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
use crate::error::ErrorResponse;
use crate::factor_lookup::FactorLookup;
use axum::http::StatusCode;
use axum::{Extension, Json};
use tracing::Instrument;
use types::{DeleteBackupRequest, FactorScope};

/// Request to delete the entire backup and all related metadata.
pub async fn handler(
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(auth_handler): Extension<AuthHandler>,
    request: Json<DeleteBackupRequest>,
) -> Result<StatusCode, ErrorResponse> {
    // Step 1: Auth. Verify the solved challenge
    let (backup_id, _backup_metadata) = auth_handler
        .verify(
            &request.authorization,
            FactorScope::Sync,
            ChallengeContext::DeleteBackup {},
            request.challenge_token.clone(),
        )
        .await?;

    let span = tracing::info_span!("delete_backup", backup_id = %backup_id);

    async move {
        // Step 2: Delete the backup and the metadata
        backup_storage.delete_backup(&backup_id).await?;

        // Step 3: Delete all factors from `FactorLookup`
        factor_lookup
            .delete_all_by_backup_id(backup_id.clone())
            .await?;

        Ok(StatusCode::NO_CONTENT)
    }
    .instrument(span)
    .await
}
