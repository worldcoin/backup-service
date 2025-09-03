use crate::auth::AuthHandler;
use crate::challenge_manager::ChallengeContext;
use crate::factor_lookup::FactorScope;
use crate::types::backup_metadata::ExportedBackupMetadata;
use crate::types::{Authorization, ErrorResponse};
use axum::{extract::Extension, Json};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveMetadataRequest {
    authorization: Authorization,
    challenge_token: String,
}

/// Retrieves the backup metadata using a sync factor. This endpoint allows a client to view
/// the metadata of a backup using only a sync factor for authentication. It's powering the
/// settings screen in the client app.
pub async fn handler(
    Extension(auth_handler): Extension<AuthHandler>,
    Json(request): Json<RetrieveMetadataRequest>,
) -> Result<Json<ExportedBackupMetadata>, ErrorResponse> {
    // Step 1: Auth. Verify the solved challenge
    let (_backup_id, backup_metadata) = auth_handler
        .verify(
            &request.authorization,
            FactorScope::Sync,
            ChallengeContext::RetrieveMetadata {},
            request.challenge_token,
        )
        .await?;

    // Step 2: Return the backup metadata
    let exported_metadata = backup_metadata.exported();

    Ok(Json(exported_metadata))
}
