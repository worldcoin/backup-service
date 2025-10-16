use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType, NewFactorType};
use crate::types::{Environment, ErrorResponse};
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NewFactor {
    #[serde(rename_all = "camelCase")]
    OidcAccount { oidc_token: String },
    #[serde(rename_all = "camelCase")]
    PasskeyRegistration {},
    #[serde(rename_all = "camelCase")]
    EcKeypair {},
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExistingFactorKind {
    Passkey,
    OidcAccount,
    EcKeypair,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AddFactorChallengeRequest {
    new_factor: NewFactor,
    /// Optional; defaults to PASSKEY to preserve current clients
    #[serde(default)]
    existing_factor_kind: Option<ExistingFactorKind>,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddFactorChallengeResponse {
    // Challenge for the existing factor
    existing_factor_challenge: String,
    existing_factor_token: String,

    // Challenge for the new factor
    new_factor_challenge: serde_json::Value,
    new_factor_token: String,
}

/// Request to get challenges for adding a new factor.
///
/// This endpoint generates two challenges:
/// 1. For the existing passkey factor to prove ownership over the backup. Currently, this is signed
///    with a passkey using a Turnkey activity with extra metadata — see `turnkey_activity.rs` for more.
/// 2. For the new factor to prove ownership over the new factor. Currently, this is a keypair
///    that's in the nonce of an OIDC token that user wants to add.
///
/// Both challenges are required to add a factor in the /add-factor endpoint.
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
    Json(request): Json<AddFactorChallengeRequest>,
) -> Result<Json<AddFactorChallengeResponse>, ErrorResponse> {
    // Create token for the existing factor
    // This token also includes the new factor details in the context to link the two challenges
    // and require the old factor to sign the new factor.
    let mut existing_factor_challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut existing_factor_challenge);
    let new_factor_type = match &request.new_factor {
        NewFactor::OidcAccount { oidc_token } => NewFactorType::OidcAccount {
            oidc_token: oidc_token.clone(),
        },
        NewFactor::PasskeyRegistration {} => NewFactorType::PasskeyRegistration {},
        NewFactor::EcKeypair {} => NewFactorType::EcKeypair {},
    };

    let existing_challenge_type = match request
        .existing_factor_kind
        .unwrap_or(ExistingFactorKind::Passkey)
    {
        ExistingFactorKind::Passkey => ChallengeType::Passkey,
        ExistingFactorKind::OidcAccount | ExistingFactorKind::EcKeypair => ChallengeType::Keypair,
    };
    let existing_factor_token = challenge_manager
        .create_challenge_token(
            existing_challenge_type,
            &existing_factor_challenge,
            ChallengeContext::AddFactor { new_factor_type },
        )
        .await?;

    // Create token for the new factor
    let (new_factor_challenge_value, new_factor_token) = match &request.new_factor {
        NewFactor::PasskeyRegistration {} => {
            let (challenge, registration) = environment
                .webauthn_config()
                .start_passkey_registration(Uuid::new_v4(), "World App", "World App", None)?;
            let challenge_json: serde_json::Value = serde_json::to_value(&challenge)?;
            let registration_json = serde_json::to_string(&registration)?;
            let token = challenge_manager
                .create_challenge_token(
                    ChallengeType::Passkey,
                    registration_json.as_bytes(),
                    ChallengeContext::AddFactorByNewFactor {},
                )
                .await?;
            (challenge_json, token)
        }
        NewFactor::OidcAccount { .. } | NewFactor::EcKeypair {} => {
            let mut new_factor_challenge = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut new_factor_challenge);
            let token = challenge_manager
                .create_challenge_token(
                    ChallengeType::Keypair,
                    &new_factor_challenge,
                    ChallengeContext::AddFactorByNewFactor {},
                )
                .await?;
            (
                serde_json::Value::String(STANDARD.encode(new_factor_challenge)),
                token,
            )
        }
    };

    Ok(Json(AddFactorChallengeResponse {
        existing_factor_challenge: STANDARD.encode(existing_factor_challenge),
        existing_factor_token,
        new_factor_challenge: new_factor_challenge_value,
        new_factor_token,
    }))
}
