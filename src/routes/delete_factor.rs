use std::sync::Arc;

use crate::auth::AuthHandler;
use crate::backup_storage::{BackupStorage, DeletionResult};
use crate::challenge_manager::ChallengeContext;
use crate::factor_lookup::{FactorLookup, FactorScope};
use crate::types::encryption_key::BackupEncryptionKey;
use crate::types::{Authorization, Environment, ErrorResponse};
use aide::transform::TransformOperation;
use axum::{Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::Instrument;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteFactorRequest {
    /// The authorization for the request (from a `Sync` factor).
    authorization: Authorization,
    /// The challenge token that will be authenticated against the factor to delete.
    challenge_token: String,
    /// The ID of the factor to delete.
    factor_id: String,
    /// Key that should be deleted from encryption key list in the metadata as part of this request
    encryption_key: Option<BackupEncryptionKey>,
    /// The scope of the factor to delete.
    scope: FactorScope,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteFactorResponse {
    backup_deleted: bool,
}

pub fn docs(op: TransformOperation) -> TransformOperation {
    op.description(
        "Request to delete a factor (main or sync) with an authenticated challenge. This endpoint requires Attestation Gateway checks (through the `attestation-token` header).",
    )
    .security_requirement("AttestationToken")
}

/// Request to delete a factor (main or sync) from backup metadata using a solved challenge.
/// If it is the last `Main` factor, this will also delete the entire backup (as the backup becomes inaccessible).
///
/// This endpoint allows deleting both `Main` and `Sync` factors:
/// 1. `Main` factors are deleted manually by the user.
/// 2. `Sync` factors are deleted when the user logs out of their account as they're local to each device.
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(auth_handler): Extension<AuthHandler>,
    request: Json<DeleteFactorRequest>,
) -> Result<Json<DeleteFactorResponse>, ErrorResponse> {
    // Step 1: Extract the factor IDs from the request
    let factor_id = request.factor_id.clone();
    let encryption_key = request.encryption_key.clone();

    // Step 1.1 Validate there is no encryption key if deleting a `Sync` factor
    if request.scope == FactorScope::Sync && encryption_key.is_some() {
        return Err(ErrorResponse::bad_request("encryption_key_not_allowed", "Removing an encryption key is not allowed when removing sync factors"));
    }

    // Step 2: Auth. Verify the solved challenge
    let (backup_id, backup_metadata) = auth_handler
        .verify(
            &request.authorization,
            FactorScope::Sync,
            // this will be compared in the `AuthHandler::verify()` function.
            // if the ChallengeContext is not the same between the request and the challenge token,
            // the request will be rejected.
            ChallengeContext::DeleteFactor {
                factor_id: request.factor_id.clone(),
            },
            request.challenge_token.clone(),
        )
        .await?;

    let span = tracing::info_span!("delete_factor", backup_id = %backup_id, scope = %request.scope);
    async move {
        // Step 3: Find the factor to delete from the backup
        let factor_to_delete = match request.scope {
            FactorScope::Main => backup_metadata.factors.iter().find(|f| f.id == factor_id),
            FactorScope::Sync => backup_metadata
                .sync_factors
                .iter()
                .find(|f| f.id == factor_id),
        };

        let Some(factor_to_delete) = factor_to_delete else {
            tracing::info!(message = "Factor not found in backup metadata");
            return Err(ErrorResponse::bad_request("factor_not_found", "Factor not found in backup"));
        };

        // Step 4: Delete the factor from the backup storage
        let mut backup_deleted = false;
        match request.scope {
            FactorScope::Main => {
                let result = backup_storage
                    .remove_factor(&backup_id, &factor_id, encryption_key.as_ref())
                    .await?;
                backup_deleted = matches!(result, DeletionResult::BackupDeleted);
            }
            FactorScope::Sync => {
                backup_storage
                    .remove_sync_factor(&backup_id, &factor_id)
                    .await?;
            }
        }

        let msg = if backup_deleted {
            "Backup deleted from removal of last main factor"
        } else {
            "Factor deleted from backup storage"
        };
        tracing::info!(message = msg, backup_id = %backup_id, scope = %request.scope, 
            backup_deleted = %backup_deleted, factor_id = %factor_id, factor_kind = %factor_to_delete.as_flattened_kind());

        // Note on atomicity: The factor is deleted from the backup storage first as this is the source of
        //   truth. Only factors in the S3 metadata are considered valid and allowed for authentication. In
        //   the edge case where the factor is deleted from the S3 metadata but not from the `FactorLookup`,
        //   this may lead to a backup not found error when retrieval, but it does not affect security.

        // Step 5: Delete the factor from the `FactorLookup` (or all factors for the backup if it's the last main factor)
        if backup_deleted {
            factor_lookup
                .delete_all_by_backup_id(backup_id.clone())
                .await?;
        } else {
            factor_lookup
                .delete(request.scope, &factor_to_delete.as_factor_to_lookup(&environment))
                .await?;
        }

        Ok(Json(DeleteFactorResponse { backup_deleted }))
    }
    .instrument(span)
    .await
}
