use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeManager, ChallengeType};
use crate::types::backup_metadata::{ExportedBackupMetadata, PrimaryFactorKind};
use crate::types::{Environment, ErrorResponse, SolvedChallenge};
use axum::{Extension, Json};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{DiscoverableAuthentication, PublicKeyCredential};

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveBackupFromChallengeRequest {
    solved_challenge: SolvedChallenge,
    challenge_token: String,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveBackupFromChallengeResponse {
    /// Encrypted backup in base64.
    backup: String,
    /// Metadata about the backup, including the Turnkey ID and encryption keys.
    metadata: ExportedBackupMetadata,
    // TODO/FIXME: token to add a new backup update keypair
}

/// Request to retrieve a backup using a solved challenge.
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(challenge_manager): Extension<ChallengeManager>,
    Extension(backup_storage): Extension<BackupStorage>,
    request: Json<RetrieveBackupFromChallengeRequest>,
) -> Result<Json<RetrieveBackupFromChallengeResponse>, ErrorResponse> {
    // Step 1: Decrypt passkey state from the token
    let challenge_token_payload = challenge_manager
        .extract_token_payload(ChallengeType::Passkey, request.challenge_token.to_string())
        .await?;
    let passkey_state: DiscoverableAuthentication =
        serde_json::from_slice(&challenge_token_payload).map_err(|err| {
            // If a valid token cannot be deserialized, it's an internal error
            tracing::error!(message = "Failed to deserialize passkey state", error = ?err);
            ErrorResponse::internal_server_error()
        })?;

    // Step 2: Verify the solved challenge and get the backup from S3
    let found_backup = match &request.solved_challenge {
        SolvedChallenge::Passkey { credential } => {
            // Step 2A.1: Deserialize the credential
            let user_provided_credential: PublicKeyCredential = serde_json::from_value(
                credential.clone(),
            )
            .map_err(|err| {
                tracing::info!(message = "Failed to deserialize passkey credential", error = ?err);
                ErrorResponse::bad_request("webauthn_error")
            })?;

            // Step 2A.2: Identify which user is referenced by the credential. Note that at
            // this point, the credential is not verified yet.
            let (_not_verified_user_id, not_verified_credential_id) = environment
                .webauthn_config()
                .identify_discoverable_authentication(&user_provided_credential)?;

            // Step 2A.3: Fetch the backup from the storage to get the reference
            // credential object
            let found_backup = backup_storage
                .get_by_primary_factor_id(&URL_SAFE_NO_PAD.encode(not_verified_credential_id))
                .await?;
            let found_backup = match found_backup {
                Some(found_backup) => found_backup,
                None => {
                    tracing::info!(message = "No backup metadata found for the given credential");
                    return Err(ErrorResponse::bad_request("webauthn_error"));
                }
            };
            let reference_credential = match &found_backup.metadata.primary_factor.kind {
                PrimaryFactorKind::Passkey {
                    webauthn_credential,
                } => webauthn_credential,
                // Uncomment when other primary factor types are implemented
                // _ => {
                //     tracing::info!(message = "Invalid primary factor type");
                //     return Err(ErrorResponse::bad_request("webauthn_error"));
                // }
            };

            // Step 2A.4: Verify the credential using the reference credential object
            let _authentication_result = environment
                .webauthn_config()
                .finish_discoverable_authentication(
                    &user_provided_credential,
                    passkey_state,
                    &[reference_credential.into()],
                )?;

            // TODO/FIXME: Track used challenges to prevent replay attacks
            // TODO/FIXME: Track authentication counter

            // Step 2A.5: Now that the credential is verified, we can return the backup
            found_backup
        }
    };

    // Step 3: Return the backup and metadata
    Ok(Json(RetrieveBackupFromChallengeResponse {
        backup: STANDARD.encode(found_backup.backup),
        metadata: found_backup.metadata.exported(),
    }))
}
