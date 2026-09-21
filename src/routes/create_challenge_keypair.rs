use std::sync::Arc;

use crate::challenge_manager::{ChallengeContext, ChallengeManager};
use crate::error::ErrorResponse;
use crate::routes::keypair_challenge::mint_challenge;
use axum::{Extension, Json};
use types::{CreateChallengeKeypairRequest, CreateChallengeKeypairResponse};

/// Request a challenge for creating a backup with a keypair or OIDC factor.
///
/// Unlike the other `.../challenge/keypair` endpoints this one does not go through the generic
/// handler: it also mints the Backup Account challenge, so that creating a backup does not need an
/// extra round trip to prove ownership of the `backupAccountId`. The Backup Account challenge is
/// minted even when the caller is registering the initial sync factor and will not use it; the
/// alternative is taking a `backupAccountId` here purely as a signal, which the proof does not
/// need — the signature is verified against the public key that the claimed ID is.
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
