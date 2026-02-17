use std::sync::Arc;

use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType};
use crate::types::{Environment, ErrorResponse};

use axum::{Extension, Json};
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyFactorChallengePasskeyResponse {
    challenge: serde_json::Value,
    token: String,
}

pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
) -> Result<Json<VerifyFactorChallengePasskeyResponse>, ErrorResponse> {
    let (challenge, authentication) = environment
        .webauthn_config()
        .start_discoverable_authentication()?;
    let challenge_json: serde_json::Value = serde_json::to_value(&challenge)?;

    let authentication_json = serde_json::to_string(&authentication)?;
    let token = challenge_manager
        .create_challenge_token(
            ChallengeType::Passkey,
            authentication_json.as_bytes(),
            ChallengeContext::VerifyFactor {},
        )
        .await?;

    Ok(Json(VerifyFactorChallengePasskeyResponse {
        challenge: challenge_json,
        token,
    }))
}
