use crate::auth::AuthHandler;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeContext, ChallengeManager};
use crate::dynamo_cache::DynamoCacheManager;
use crate::factor_lookup::{FactorLookup, FactorScope};
use crate::types::backup_metadata::ExportedBackupMetadata;
use crate::types::{Authorization, Environment, ErrorResponse};
use axum::{extract::Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveMetadataRequest {
    authorization: Authorization,
    challenge_token: String,
}

impl From<RetrieveMetadataRequest> for AuthHandler {
    fn from(request: RetrieveMetadataRequest) -> Self {
        AuthHandler::new(
            request.authorization,
            FactorScope::Sync,
            ChallengeContext::RetrieveMetadata {},
            request.challenge_token,
        )
    }
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
    Extension(environment): Extension<Environment>,
    Extension(dynamo_cache_manager): Extension<DynamoCacheManager>,
    Extension(challenge_manager): Extension<ChallengeManager>,
    Extension(backup_storage): Extension<BackupStorage>,
    Extension(factor_lookup): Extension<FactorLookup>,
    Json(request): Json<RetrieveMetadataRequest>,
) -> Result<Json<RetrieveMetadataResponse>, ErrorResponse> {
    // Step 1: Auth. Verify the solved challenge
    let auth_handler: AuthHandler = request.into();
    let (backup_id, backup_metadata) = auth_handler
        .verify(
            &backup_storage,
            &dynamo_cache_manager,
            &challenge_manager,
            &environment,
            &factor_lookup,
            None,
        )
        .await?;

    // Step 2: Return the backup metadata
    let exported_metadata = backup_metadata.exported();

    Ok(Json(RetrieveMetadataResponse {
        backup_id,
        metadata: exported_metadata,
    }))
}
