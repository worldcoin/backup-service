use crate::axum_utils::extract_fields_from_multipart;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeManager, ChallengeType};
use crate::types::backup_metadata::{BackupMetadata, PrimaryFactor};
use crate::types::encryption_key::BackupEncryptionKey;
use crate::types::{Environment, ErrorResponse, SolvedChallenge};
use axum::extract::Multipart;
use axum::{extract::Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{PasskeyRegistration, RegisterPublicKeyCredential};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateBackupRequest {
    solved_challenge: SolvedChallenge,
    challenge_token: String,
    initial_encryption_key: BackupEncryptionKey,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateBackupResponse {}

pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(challenge_manager): Extension<ChallengeManager>,
    Extension(backup_storage): Extension<BackupStorage>,
    mut multipart: Multipart,
) -> Result<Json<CreateBackupResponse>, ErrorResponse> {
    // Step 1: Parse multipart form data. It should include the main JSON payload with parameters
    // and the attached backup file.
    let multipart_fields = extract_fields_from_multipart(&mut multipart)
        .await
        .map_err(|err| {
            tracing::info!(message = "Failed to parse multipart data", error = ?err);
            ErrorResponse::bad_request("invalid_multipart_data")
        })?;
    let request = multipart_fields.get("payload").ok_or_else(|| {
        tracing::info!(message = "Missing payload field in multipart data");
        ErrorResponse::bad_request("missing_payload_field")
    })?;
    let request: CreateBackupRequest = serde_json::from_slice(request).map_err(|err| {
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

    // Step 2: Decrypt passkey state from the token
    let challenge_token_payload = challenge_manager
        .extract_token_payload(ChallengeType::Passkey, request.challenge_token.to_string())
        .await?;
    let passkey_state: PasskeyRegistration = serde_json::from_slice(&challenge_token_payload)
        .map_err(|err| {
            // If a valid token cannot be deserialized, it's an internal error
            tracing::error!(message = "Failed to deserialize passkey state", error = ?err);
            ErrorResponse::internal_server_error()
        })?;

    // Step 3: Verify the solved challenge
    let verified_primary_factor = match &request.solved_challenge {
        SolvedChallenge::Passkey { credential } => {
            // Step 2A: Verify the passkey credential using the WebAuthn implementation
            let user_provided_credential: RegisterPublicKeyCredential = serde_json::from_value(
                credential.clone(),
            )
            .map_err(|err| {
                tracing::info!(message = "Failed to deserialize passkey credential", error = ?err);
                ErrorResponse::bad_request("webauthn_error")
            })?;
            let verified_passkey = environment
                .webauthn_config()
                .finish_passkey_registration(&user_provided_credential, &passkey_state)?;

            // TODO/FIXME: Track used challenges to prevent replay attacks

            PrimaryFactor::new_passkey(verified_passkey)
        }
    };

    // Step 4: Initialize backup metadata
    let backup_metadata = BackupMetadata {
        primary_factor: verified_primary_factor,
        oidc_accounts: vec![],
        keys: vec![request.initial_encryption_key.clone()],
    };

    // TODO/FIXME: More checks and metadata initialization

    // Step 5: Save the backup to S3
    backup_storage
        .create(backup.to_vec(), &backup_metadata)
        .await?;

    Ok(Json(CreateBackupResponse {}))
}
