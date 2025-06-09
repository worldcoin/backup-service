use std::sync::Arc;

use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType};
use crate::dynamo_cache::DynamoCacheManager;
use crate::factor_lookup::{FactorLookup, FactorScope, FactorToLookup};
use crate::types::backup_metadata::Factor;
use crate::types::{Authorization, ErrorResponse};
use crate::verify_signature::verify_signature;
use axum::{Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AddSyncFactorRequest {
    /// The challenge token that was used to create the sync factor, from AddSyncFactorChallengeKeypairResponse
    challenge_token: String,
    /// New sync factor to add. Must be an EC keypair.
    sync_factor: Authorization,
    /// From sync_factor_token in RetrieveBackupFromChallengeResponse, used to authorize the request
    /// to specific backup.
    sync_factor_token: String,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddSyncFactorResponse {
    /// The ID of the backup that was modified
    pub backup_id: String,
}

/// Request to retrieve a backup using a solved challenge.
pub async fn handler(
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(dynamo_cache_manager): Extension<Arc<DynamoCacheManager>>,
    request: Json<AddSyncFactorRequest>,
) -> Result<Json<AddSyncFactorResponse>, ErrorResponse> {
    // Step 1: Verify the sync factor is a valid EC keypair and transform it to a factor object
    let (sync_factor, sync_factor_to_lookup) = match &request.sync_factor {
        Authorization::EcKeypair {
            public_key,
            signature,
        } => {
            // Step 1.1: Get the challenge payload from the challenge token
            let (trusted_challenge, challenge_context) = challenge_manager
                .extract_token_payload(ChallengeType::Keypair, request.challenge_token.to_string())
                .await?;
            if challenge_context != (ChallengeContext::AddSyncFactor {}) {
                return Err(ErrorResponse::bad_request("invalid_challenge_context"));
            }

            // Step 1.2: Verify the signature using the public key
            verify_signature(public_key, signature, trusted_challenge.as_ref())?;

            // Step 1.3: Track used challenges to prevent replay attacks
            dynamo_cache_manager
                .use_challenge_token(request.challenge_token.to_string())
                .await?;

            // Step 1.4: Create a factor that's going to be saved in the metadata and a factor to lookup
            (
                Factor::new_ec_keypair(public_key.to_string()),
                FactorToLookup::from_ec_keypair(public_key.to_string()),
            )
        }
        Authorization::Passkey { .. } | Authorization::OidcAccount { .. } => {
            tracing::info!(message = "Invalid sync factor type");
            return Err(ErrorResponse::bad_request("invalid_sync_factor"));
        }
    };

    // Step 2: Verify the sync factor token and extract the backup ID
    let backup_id = dynamo_cache_manager
        .use_sync_factor_token(request.sync_factor_token.to_string())
        .await?;

    // Step 3: Add the sync factor to backup lookup
    factor_lookup
        .insert(FactorScope::Sync, &sync_factor_to_lookup, backup_id.clone())
        .await?;

    // Step 4: Add the sync factor to the backup metadata
    let result = backup_storage
        .add_sync_factor(&backup_id, sync_factor)
        .await;

    // Step 4.1: If `add_sync_factor` into the S3 metadata fails, remove sync factor from lookup and allow the token to be reused for retries
    if let Err(e) = result {
        if let Err(e) = factor_lookup
            .delete(FactorScope::Sync, &sync_factor_to_lookup)
            .await
        {
            tracing::error!(message = "Failed to delete factor from lookup table after failed sync factor addition.", error = ?e, sync_factor_pk = sync_factor_to_lookup.primary_key());
        }

        if let Err(e) = dynamo_cache_manager
            .unuse_sync_factor_token(request.sync_factor_token.to_string())
            .await
        {
            tracing::error!(message = "Failed to unmark sync factor token as used after failed sync factor addition.", error = ?e);
        }

        return Err(e.into());
    }

    Ok(Json(AddSyncFactorResponse { backup_id }))
}
