use crate::challenge_manager::{ChallengeManager, ChallengeType};
use crate::types::backup_metadata::{BackupMetadata, PrimaryFactor};
use crate::types::{Environment, ErrorResponse};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;
use axum::{extract::Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use webauthn_rs::prelude::{PasskeyRegistration, RegisterPublicKeyCredential};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum SolvedChallenge {
    #[serde(rename_all = "camelCase")]
    Passkey { credential: serde_json::Value },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateBackupRequest {
    solved_challenge: SolvedChallenge,
    challenge_token: String,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateBackupResponse {}

pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(s3_client): Extension<S3Client>,
    Extension(challenge_manager): Extension<ChallengeManager>,
    request: Json<CreateBackupRequest>,
) -> Result<Json<CreateBackupResponse>, ErrorResponse> {
    // Step 1: Decrypt passkey state from the token
    let challenge_token_payload = challenge_manager
        .extract_token_payload(ChallengeType::Passkey, request.challenge_token.to_string())
        .await?;
    let passkey_state: PasskeyRegistration = serde_json::from_slice(&challenge_token_payload)
        .map_err(|err| {
            // If a valid token cannot be deserialized, it's an internal error
            tracing::error!(message = "Failed to deserialize passkey state", error = ?err);
            ErrorResponse::internal_server_error()
        })?;

    // Step 2: Verify the solved challenge
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

    // Step 3: Initialize backup metadata
    let _backup_metadata = BackupMetadata {
        primary_factor: verified_primary_factor,
        turnkey_account_id: None,
    };

    // TODO/FIXME: More checks and metadata initialization

    // TODO/FIXME: Replace this stub with a proper storage service
    let key = format!("backup-{}", Instant::now().elapsed().as_millis());
    let body = ByteStream::from(vec![0u8; 1024]);
    s3_client
        .put_object()
        .bucket(environment.s3_bucket_arn())
        .key(key)
        .body(body)
        .send()
        .await
        .map_err(|err| {
            tracing::error!(message = "Failed to upload backup to S3", error = ?err);
            ErrorResponse::internal_server_error()
        })?;

    Ok(Json(CreateBackupResponse {}))
}
