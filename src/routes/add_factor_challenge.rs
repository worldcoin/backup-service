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
pub struct AddFactorChallengeRequest {
    new_factor: NewFactor,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddFactorChallengeResponse {
    // Challenge for the existing factor
    existing_factor_challenge: String,
    existing_factor_token: String,

    // Challenge for the new factor
    new_factor_challenge: String,
    new_factor_token: String,
}

/// Request to get challenges for adding a new factor.
///
/// This endpoint generates two challenges:
/// 1. For the existing passkey factor to prove ownership over the backup. Currently, this is signed
///    with a passkey using a Turnkey activity with extra metadata — see turnkey_activity.rs for more.
/// 2. For the new factor to prove ownership over the new factor. Currently, this is a keypair
///    that's in the nonce of an OIDC token that user wants to add.
///
/// Both challenges are required to add a factor in the /add-factor endpoint.
pub async fn handler(
    Extension(challenge_manager): Extension<ChallengeManager>,
    Json(request): Json<AddFactorChallengeRequest>,
) -> Result<Json<AddFactorChallengeResponse>, ErrorResponse> {
    // Create token for the existing passkey factor
    // This token also includes the new factor details in the context to link the two challenges
    // and require the old factor to sign the new factor.
    let mut existing_factor_challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut existing_factor_challenge);
    let new_factor_type = match &request.new_factor {
        NewFactor::OidcAccount { oidc_token } => NewFactorType::OidcAccount {
            oidc_token: oidc_token.clone(),
        },
    };
    let existing_factor_token = challenge_manager
        .create_challenge_token(
            ChallengeType::Passkey,
            &existing_factor_challenge,
            ChallengeContext::AddFactor { new_factor_type },
        )
        .await?;

    // Create token for the new factor
    let mut new_factor_challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut new_factor_challenge);
    let new_factor_token = challenge_manager
        .create_challenge_token(
            ChallengeType::Keypair,
            &new_factor_challenge,
            ChallengeContext::AddFactorByNewFactor {},
        )
        .await?;

    Ok(Json(AddFactorChallengeResponse {
        existing_factor_challenge: STANDARD.encode(existing_factor_challenge),
        existing_factor_token,
        new_factor_challenge: STANDARD.encode(new_factor_challenge),
        new_factor_token,
    }))
}
