use std::sync::Arc;

use crate::auth::AuthHandler;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
use crate::factor_lookup::{FactorLookup, FactorScope};
use crate::types::{Authorization, Environment, ErrorResponse};
use axum::http::StatusCode;
use axum::{Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteBackupRequest {
    authorization: Authorization,
    challenge_token: String,
}

/// Request to delete the entire backup and all related metadata.
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(auth_handler): Extension<AuthHandler>,
    request: Json<DeleteBackupRequest>,
) -> Result<StatusCode, ErrorResponse> {
    // Step 1: Auth. Verify the solved challenge
    let (backup_id, backup_metadata) = auth_handler
        .verify(
            &request.authorization,
            FactorScope::Sync,
            ChallengeContext::DeleteBackup {},
            request.challenge_token.clone(),
        )
        .await?;

    // Step 2: Delete the backup and the metadata
    backup_storage.delete_backup(&backup_id).await?;

    // Step 3: Delete all `Sync` factors from `FactorLookup`
    for factor in backup_metadata.sync_factors {
        let result = factor_lookup
            .delete(FactorScope::Sync, &factor.as_factor_to_lookup(&environment))
            .await;

        if let Err(e) = result {
            tracing::warn!(
                message = "[DeleteBackup] - Failed to delete `Sync` factor from FactorLookup, but continuing.",
                error = ?e,
                backup_id = backup_id,
                factor_id = factor.id,
            );
        }
    }

    // Step 4: Delete all `Main` factors from `FactorLookup`
    for factor in backup_metadata.factors {
        let result = factor_lookup
            .delete(FactorScope::Main, &factor.as_factor_to_lookup(&environment))
            .await;

        if let Err(e) = result {
            tracing::warn!(
                message = "[DeleteBackup] - Failed to delete `Main` factor from FactorLookup, but continuing.",
                error = ?e,
                backup_id = backup_id,
                factor_id = factor.id,
            );
        }
    }

    Ok(StatusCode::NO_CONTENT)
}
