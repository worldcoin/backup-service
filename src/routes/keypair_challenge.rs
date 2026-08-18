use std::sync::Arc;

use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType};
use crate::types::ErrorResponse;
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeKeypairResponse {
    challenge: String,
    token: String,
}

/// Request to retrieve a challenge for keypair authentication / registration.
///
/// Used as a generic route builder for multiple routes. Normally, user fetches a challenge token
/// (using this endpoint), signs the challenge with a keypair (e.g. iCloud Keychain keypair
/// or a sync factor) and sends it back to the server, where we validate it using challenge manager.
///
/// Optionally, the request can contain additional context that is used to create the challenge token.
/// This context should be validated alongside the challenge token when receiving the signed challenge.
pub async fn handler<T: DeserializeOwned + Into<ChallengeContext>>(
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
    Json(request): Json<T>,
) -> Result<Json<ChallengeKeypairResponse>, ErrorResponse> {
    let (challenge, token) = mint_challenge(&challenge_manager, request.into()).await?;

    Ok(Json(ChallengeKeypairResponse { challenge, token }))
}

/// Mints a keypair challenge: 32 bytes of random data, plus the JWE token that binds those bytes
/// to `challenge_context` so the challenge cannot be answered for a different purpose.
///
/// Returns the base64-encoded challenge for the client to sign, and the token to send back.
///
/// # Errors
/// Returns an error if the challenge token cannot be created.
pub async fn mint_challenge(
    challenge_manager: &ChallengeManager,
    challenge_context: ChallengeContext,
) -> Result<(String, String), ErrorResponse> {
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);

    let token = challenge_manager
        .create_challenge_token(ChallengeType::Keypair, &challenge, challenge_context)
        .await?;

    Ok((STANDARD.encode(challenge), token))
}
