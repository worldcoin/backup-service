use std::sync::Arc;

use crate::challenge_manager::{ChallengeContext, ChallengeManager};
use crate::routes::keypair_challenge::mint_challenge;
use crate::types::ErrorResponse;
use axum::{Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateChallengeKeypairRequest {}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateChallengeKeypairResponse {
    /// Base64-encoded challenge for the factor being registered.
    challenge: String,
    token: String,
    /// Base64-encoded challenge to be signed by the Backup Account Key and passed to `/create`.
    backup_account_challenge: String,
    /// Token accompanying `backupAccountChallenge`.
    backup_account_challenge_token: String,
}

/// Request a challenge for creating a backup with a keypair or OIDC factor.
///
/// Both challenges are minted in one request so that creating a backup does not need an extra round
/// trip to prove ownership of the backup account ID. The Backup Account challenge is minted even
/// when the caller is registering the initial sync factor and will not use it; skipping it would
/// mean taking a `backupAccountId` here purely as a signal, which the proof does not need.
pub async fn handler(
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
    Json(_request): Json<CreateChallengeKeypairRequest>,
) -> Result<Json<CreateChallengeKeypairResponse>, ErrorResponse> {
    // Minted concurrently: each one is a KMS Encrypt round trip.
    let ((challenge, token), (backup_account_challenge, backup_account_challenge_token)) = tokio::try_join!(
        mint_challenge(&challenge_manager, ChallengeContext::Create {}),
        mint_challenge(&challenge_manager, ChallengeContext::CreateBackupAccount {}),
    )?;

    Ok(Json(CreateChallengeKeypairResponse {
        challenge,
        token,
        backup_account_challenge,
        backup_account_challenge_token,
    }))
}
