use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType, NewFactorType};
use crate::types::ErrorResponse;
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NewFactor {
    #[serde(rename_all = "camelCase")]
    OidcAccount { oidc_token: String },
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AddFactorChallengeExistingPasskeyRequest {
    new_factor: NewFactor,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddFactorChallengeExistingPasskeyResponse {
    challenge: String,
    token: String,
}

/// Request to get a challenge for adding a new factor using an existing passkey.
/// This endpoint is used when a user wants to add a new factor to their backup using an existing passkey.
pub async fn handler(
    Extension(challenge_manager): Extension<ChallengeManager>,
    Json(request): Json<AddFactorChallengeExistingPasskeyRequest>,
) -> Result<Json<AddFactorChallengeExistingPasskeyResponse>, ErrorResponse> {
    // Create a new challenge as 32 bytes of random data
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);

    // Extract the OIDC token and create the appropriate NewFactorType
    let new_factor_type = match request.new_factor {
        NewFactor::OidcAccount { oidc_token } => NewFactorType::OidcAccount { oidc_token },
    };

    // Encrypt the challenge in a JWE to verify later
    let token = challenge_manager
        .create_challenge_token(
            ChallengeType::Passkey,
            &challenge,
            ChallengeContext::AddFactor { new_factor_type },
        )
        .await?;

    // Return the challenge and token to the client
    Ok(Json(AddFactorChallengeExistingPasskeyResponse {
        challenge: STANDARD.encode(challenge),
        token,
    }))
}
