use crate::axum_utils::extract_fields_from_multipart;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType};
use crate::factor_lookup::{FactorLookup, FactorToLookup};
use crate::types::backup_metadata::FactorKind;
use crate::types::{Authorization, Environment, ErrorResponse};
use crate::verify_signature::verify_signature;
use axum::extract::Multipart;
use axum::{extract::Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SyncBackupRequest {
    authorization: Authorization,
    challenge_token: String,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncBackupResponse {
    pub backup_id: String,
}

pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(challenge_manager): Extension<ChallengeManager>,
    Extension(backup_storage): Extension<BackupStorage>,
    Extension(factor_lookup): Extension<FactorLookup>,
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

    // Step 2: Verify the solved challenge in the authorization parameter
    let (factor_to_lookup, sync_factor_public_key) = match &request.authorization {
        Authorization::EcKeypair {
            public_key,
            signature,
        } => {
            // Step 2.1: Get the challenge payload from the challenge token
            let (trusted_challenge, challenge_context) = challenge_manager
                .extract_token_payload(ChallengeType::Keypair, request.challenge_token.to_string())
                .await?;
            if challenge_context != (ChallengeContext::Sync {}) {
                return Err(ErrorResponse::bad_request("invalid_challenge_context"));
            }

            // Step 2.2: Verify the signature using the public key
            verify_signature(public_key, signature, trusted_challenge.as_ref())?;

            // Step 2.3: Track used challenges to prevent replay attacks
            // TODO/FIXME

            // Step 2.4: Create a factor to lookup for updatabale backup and save the verified public key
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

    // Step 3: Find the backup metadata using the factor to lookup
    let backup_id = factor_lookup.lookup(&factor_to_lookup).await?;
    let Some(backup_id) = backup_id else {
        tracing::info!(
            message = "No backup ID found for the given sync keypair account",
            sync_factor_public_key = sync_factor_public_key
        );
        return Err(ErrorResponse::bad_request("backup_not_found"));
    };
    let found_backup = backup_storage.get_by_backup_id(&backup_id).await?;
    let Some(found_backup) = found_backup else {
        tracing::info!(message = "No backup metadata found for the given backup ID");
        return Err(ErrorResponse::bad_request("backup_not_found"));
    };

    // Step 4: Verify the backup metadata contains the factor as a sync factor
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

    // Step 5: Update the backup metadata with the new backup file
    backup_storage
        .update_backup(&backup_id, backup.to_vec())
        .await?;

    Ok(Json(SyncBackupResponse { backup_id }))
}
