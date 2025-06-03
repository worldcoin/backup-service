use crate::auth::AuthHandler;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeContext, ChallengeManager};
use crate::dynamo_cache::DynamoCacheManager;
use crate::factor_lookup::{FactorLookup, FactorScope};
use crate::oidc_token_verifier::OidcTokenVerifier;
use crate::types::backup_metadata::ExportedBackupMetadata;
use crate::types::{Authorization, Environment, ErrorResponse};
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveBackupFromChallengeRequest {
    authorization: Authorization,
    challenge_token: String,
}

impl From<RetrieveBackupFromChallengeRequest> for AuthHandler {
    fn from(request: RetrieveBackupFromChallengeRequest) -> Self {
        AuthHandler::new(
            request.authorization,
            vec![FactorScope::Main],
            ChallengeContext::Retrieve {},
            request.challenge_token,
        )
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveBackupFromChallengeResponse {
    /// Encrypted backup in base64.
    backup: String,
    /// Metadata about the backup, including the Turnkey ID and encryption keys.
    metadata: ExportedBackupMetadata,
    /// Token to add a new sync factor later.
    sync_factor_token: String,
}

/// Request to retrieve a backup using a solved challenge.
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(challenge_manager): Extension<ChallengeManager>,
    Extension(backup_storage): Extension<BackupStorage>,
    Extension(factor_lookup): Extension<FactorLookup>,
    Extension(oidc_token_verifier): Extension<OidcTokenVerifier>,
    Extension(dynamo_cache_manager): Extension<DynamoCacheManager>,
    request: Json<RetrieveBackupFromChallengeRequest>,
) -> Result<Json<RetrieveBackupFromChallengeResponse>, ErrorResponse> {
    // Step 1: Auth. Verify the solved challenge
    let auth_handler: AuthHandler = request.0.into();
    let (backup_id, backup_metadata) = auth_handler
        .verify(
            &backup_storage,
            &dynamo_cache_manager,
            &challenge_manager,
            &environment,
            &factor_lookup,
            Some(&oidc_token_verifier),
        )
        .await?;

    // Step 2: Fetch the backup from S3
    let backup = backup_storage.get_backup_by_backup_id(&backup_id).await?;
    let Some(backup) = backup else {
        tracing::error!(message = "No backup found for the verified backup ID.");
        return Err(ErrorResponse::internal_server_error());
    };

    // Step 3: Create a sync factor token to allow the user to add a new sync factor later
    let sync_factor_token = dynamo_cache_manager
        .create_sync_factor_token(backup_metadata.id.clone())
        .await?;

    // Step 4: Return the backup and metadata
    Ok(Json(RetrieveBackupFromChallengeResponse {
        backup: STANDARD.encode(backup),
        metadata: backup_metadata.exported(),
        sync_factor_token,
    }))
}
