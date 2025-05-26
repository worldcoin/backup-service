use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType};
use crate::factor_lookup::{FactorLookup, FactorScope, FactorToLookup};
use crate::types::backup_metadata::{ExportedBackupMetadata, FactorKind};
use crate::types::{Authorization, ErrorResponse};
use crate::verify_signature::verify_signature;
use axum::{extract::Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveMetadataRequest {
    authorization: Authorization,
    challenge_token: String,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveMetadataResponse {
    pub backup_id: String,
    pub metadata: ExportedBackupMetadata,
}

/// Retrieves the backup metadata using a sync factor. This endpoint allows a client to view
/// the metadata of a backup using only a sync factor for authentication. It's powering the
/// settings screen in the client app.
pub async fn handler(
    Extension(challenge_manager): Extension<ChallengeManager>,
    Extension(backup_storage): Extension<BackupStorage>,
    Extension(factor_lookup): Extension<FactorLookup>,
    Json(request): Json<RetrieveMetadataRequest>,
) -> Result<Json<RetrieveMetadataResponse>, ErrorResponse> {
    // Step 1: Verify the solved challenge in the authorization parameter
    let (factor_to_lookup, sync_factor_public_key) = match &request.authorization {
        Authorization::EcKeypair {
            public_key,
            signature,
        } => {
            // Step 1.1: Get the challenge payload from the challenge token
            let (trusted_challenge, challenge_context) = challenge_manager
                .extract_token_payload(ChallengeType::Keypair, request.challenge_token.to_string())
                .await?;
            if challenge_context != (ChallengeContext::RetrieveMetadata {}) {
                return Err(ErrorResponse::bad_request("invalid_challenge_context"));
            }

            // Step 1.2: Verify the signature using the public key
            verify_signature(public_key, signature, trusted_challenge.as_ref())?;

            // Step 1.3: Track used challenges to prevent replay attacks
            // TODO/FIXME

            // Step 1.4: Create a factor to lookup for retrieving backup metadata
            (
                FactorToLookup::from_ec_keypair(public_key.to_string()),
                public_key.to_string(),
            )
        }
        Authorization::Passkey { .. } | Authorization::OidcAccount { .. } => {
            tracing::info!(message = "Invalid sync factor type");
            return Err(ErrorResponse::bad_request("invalid_sync_factor"));
        }
    };

    // Step 2: Find the backup metadata using the factor to lookup
    let backup_id = factor_lookup
        .lookup(FactorScope::Sync, &factor_to_lookup)
        .await?;
    let Some(backup_id) = backup_id else {
        tracing::info!(message = "No backup ID found for the given sync keypair account");
        return Err(ErrorResponse::bad_request("backup_not_found"));
    };
    let found_backup = backup_storage.get_by_backup_id(&backup_id).await?;
    let Some(found_backup) = found_backup else {
        tracing::info!(message = "No backup metadata found for the given backup ID");
        return Err(ErrorResponse::bad_request("backup_not_found"));
    };

    // Step 3: Verify the backup metadata contains the factor as a sync factor
    let metadata_contains_sync_factor_from_signature =
        found_backup.metadata.sync_factors.iter().any(|factor| {
            if let FactorKind::EcKeypair { public_key } = &factor.kind {
                public_key == &sync_factor_public_key
            } else {
                false
            }
        });
    if !metadata_contains_sync_factor_from_signature {
        tracing::info!(
            message = "Backup metadata does not contain the sync factor",
            backup_id = backup_id,
            sync_factor_public_key = sync_factor_public_key
        );
        return Err(ErrorResponse::internal_server_error());
    }

    // Step 4: Return the backup metadata
    let exported_metadata = found_backup.metadata.exported();

    Ok(Json(RetrieveMetadataResponse {
        backup_id,
        metadata: exported_metadata,
    }))
}
