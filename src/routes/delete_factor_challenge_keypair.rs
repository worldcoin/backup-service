use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType};
use crate::types::ErrorResponse;
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteFactorChallengeKeypairResponse {
    challenge: String,
    token: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteFactorChallengeKeypairRequest {
    factor_id: String,
}

/// Request to retrieve a challenge for keypair authentication. Used to delete a factor
/// from the backup metadata. The challenge has to be signed by the keypair that's stored
/// as a sync factor in the backup metadata.
pub async fn handler(
    Extension(challenge_manager): Extension<ChallengeManager>,
    Json(request): Json<DeleteFactorChallengeKeypairRequest>,
) -> Result<Json<DeleteFactorChallengeKeypairResponse>, ErrorResponse> {
    // Step 1: Create a new challenge as 32 bytes of random data
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);

    // Step 2: Encrypt the challenge in a JWE to verify later
    let token = challenge_manager
        .create_challenge_token(
            ChallengeType::Keypair,
            &challenge,
            ChallengeContext::DeleteFactor {
                factor_id: request.factor_id,
            },
        )
        .await?;

    Ok(Json(DeleteFactorChallengeKeypairResponse {
        challenge: STANDARD.encode(challenge),
        token,
    }))
}
