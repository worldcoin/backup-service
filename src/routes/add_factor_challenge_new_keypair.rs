use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType};
use crate::types::ErrorResponse;
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddFactorChallengeNewKeypairResponse {
    challenge: String,
    token: String,
}

/// Request to retrieve a challenge for keypair authentication. Used to add a new factor
/// by proving ownership of a newly created keypair.
pub async fn handler(
    Extension(challenge_manager): Extension<ChallengeManager>,
) -> Result<Json<AddFactorChallengeNewKeypairResponse>, ErrorResponse> {
    // Step 1: Create a new challenge as 32 bytes of random data
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);

    // Step 2: Encrypt the challenge in a JWE to verify later
    let token = challenge_manager
        .create_challenge_token(
            ChallengeType::Keypair,
            &challenge,
            ChallengeContext::AddFactorByNewFactor {},
        )
        .await?;

    // Step 3: Return the challenge and token to the client
    Ok(Json(AddFactorChallengeNewKeypairResponse {
        challenge: STANDARD.encode(challenge),
        token,
    }))
}
