use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType};
use crate::types::{Environment, ErrorResponse};
use axum::{Extension, Json};
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveChallengePasskeyResponse {
    challenge: serde_json::Value,
    token: String,
}

/// Request to retrieve a challenge for passkey authentication. Used to start the recovery process
/// for a backup.
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(challenge_manager): Extension<ChallengeManager>,
) -> Result<Json<RetrieveChallengePasskeyResponse>, ErrorResponse> {
    // Step 1: Create a new challenge using WebAuthn implementation
    let (challenge, authentication) = environment
        .webauthn_config()
        .start_discoverable_authentication()?;
    let challenge_json: serde_json::Value = serde_json::to_value(&challenge)?;

    // Step 2: Encrypt the server-side object in a JWE
    let authentication_json = serde_json::to_string(&authentication)?;
    let token = challenge_manager
        .create_challenge_token(
            ChallengeType::Passkey,
            authentication_json.as_bytes(),
            ChallengeContext::Retrieve {},
        )
        .await?;

    Ok(Json(RetrieveChallengePasskeyResponse {
        challenge: challenge_json,
        token,
    }))
}
