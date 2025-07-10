use std::sync::Arc;

use crate::auth::AuthHandler;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
use crate::factor_lookup::{FactorLookup, FactorScope};
use crate::types::encryption_key::BackupEncryptionKey;
use crate::types::{Authorization, Environment, ErrorResponse};
use axum::{Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteFactorRequest {
    authorization: Authorization,
    challenge_token: String,
    factor_id: String,
    /// Key that should be deleted from encryption key list in the metadata as part of this request
    encryption_key: Option<BackupEncryptionKey>,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteFactorResponse {}

/// Request to delete a factor from backup metadata using a solved challenge.
/// If it is the last `Main`factor, this will also delete the entire backup (as the backup becomes inaccessible).
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

    // Step 3: Find the factor to delete from the backup (either Main or Sync). Main will be searched first.
    let factor_to_delete = {
        // First check main factors
        if let Some(factor) = backup_metadata.factors.iter().find(|f| f.id == factor_id) {
            Some((factor.as_factor_to_lookup(&environment), FactorScope::Main))
        }
        // Then check sync factors
        else {
            backup_metadata
                .sync_factors
                .iter()
                .find(|f| f.id == factor_id)
                .map(|factor| (factor.as_factor_to_lookup(&environment), FactorScope::Sync))
        }
    };

    let Some((factor_to_delete, factor_scope)) = factor_to_delete else {
        tracing::info!(message = "Factor not found in backup metadata");
        return Err(ErrorResponse::bad_request("factor_not_found"));
    };

    // Step 3.1 Validate there is no encryption key if deleting a `Sync` factor
    if factor_scope == FactorScope::Sync && encryption_key.is_some() {
        return Err(ErrorResponse::bad_request("encryption_key_not_allowed"));
    }

    // Step 4: Delete the factor from the backup storage
    match factor_scope {
        FactorScope::Main => {
            backup_storage
                .remove_factor(&backup_id, &factor_id, encryption_key.as_ref())
                .await?;
        }
        FactorScope::Sync => {
            backup_storage
                .remove_sync_factor(&backup_id, &factor_id)
                .await?;
        }
    }

    // Note on atomicity: The factor is deleted from the backup storage first as this is the source of
    //   truth. Only factors in the S3 metadata are considered valid and allowed for authentication. In
    //   the edge case where the factor is deleted from the S3 metadata but not from the `FactorLookup`,
    //   this may lead to a backup not found error when retrieval, but it does not affect security.

    // Step 5: Delete the factor from the factor lookup
    factor_lookup
        .delete(factor_scope, &factor_to_delete)
        .await?;

    Ok(Json(DeleteFactorResponse {}))
}
