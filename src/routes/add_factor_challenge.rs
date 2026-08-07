use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType, NewFactorType};
use crate::types::{Environment, ErrorResponse};
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use super::create_challenge_passkey::Platform;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NewFactor {
    #[serde(rename_all = "camelCase")]
    OidcAccount { oidc_token: String },
    #[serde(rename_all = "camelCase")]
    PasskeyRegistration { platform: Platform },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExistingFactorKind {
    Passkey,
    OidcAccount,
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

/// Hex-encoded SHA-256 of the `WebAuthn` registration state stored in the new-factor challenge token.
pub(crate) fn registration_state_hash(registration_bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(registration_bytes))
}

/// Request to get challenges for adding a new factor.
///
/// This endpoint generates two challenges:
/// 1. For the existing Main Factor (Passkey or OIDC) to prove ownership over the backup.
///    Passkey existing uses a Turnkey activity with extra metadata — see `turnkey_activity.rs`.
/// 2. For the new Main Factor (Passkey registration or OIDC) to prove ownership of the new factor.
///
/// Both challenges are required to add a factor in the /add-factor endpoint.
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
    Json(request): Json<AddFactorChallengeRequest>,
) -> Result<Json<AddFactorChallengeResponse>, ErrorResponse> {
    let mut existing_factor_challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut existing_factor_challenge);

    let existing_challenge_type = match request
        .existing_factor_kind
        .unwrap_or(ExistingFactorKind::Passkey)
    {
        ExistingFactorKind::Passkey => ChallengeType::Passkey,
        ExistingFactorKind::OidcAccount => ChallengeType::Keypair,
    };

    // For passkey registration: mint the registration ceremony first so its hash can be bound
    // into the existing-factor token (same security property as OIDC token binding).
    let (new_factor_type, new_factor_challenge_value, new_factor_token) = match &request.new_factor
    {
        NewFactor::PasskeyRegistration { platform } => {
            let (challenge, registration) = match platform {
                Platform::Ios => environment.webauthn_config().start_passkey_registration(
                    Uuid::new_v4(),
                    "World App",
                    "World App",
                    None,
                )?,
                Platform::Android => environment
                    .webauthn_config()
                    .start_google_passkey_in_google_password_manager_only_registration(
                        Uuid::new_v4(),
                        "World App",
                        "World App",
                        None,
                    )?,
            };
            let challenge_json: serde_json::Value = serde_json::to_value(&challenge)?;
            let registration_json = serde_json::to_string(&registration)?;
            let registration_hash = registration_state_hash(registration_json.as_bytes());
            let token = challenge_manager
                .create_challenge_token(
                    ChallengeType::Passkey,
                    registration_json.as_bytes(),
                    ChallengeContext::AddFactorByNewFactor {},
                )
                .await?;
            (
                NewFactorType::PasskeyRegistration { registration_hash },
                challenge_json,
                token,
            )
        }
        NewFactor::OidcAccount { oidc_token } => {
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
                NewFactorType::OidcAccount {
                    oidc_token: oidc_token.clone(),
                },
                serde_json::Value::String(STANDARD.encode(new_factor_challenge)),
                token,
            )
        }
    };

    // Existing-factor token embeds the exact new-factor descriptor the old factor is authorizing.
    let existing_factor_token = challenge_manager
        .create_challenge_token(
            existing_challenge_type,
            &existing_factor_challenge,
            ChallengeContext::AddFactor { new_factor_type },
        )
        .await?;

    Ok(Json(AddFactorChallengeResponse {
        existing_factor_challenge: STANDARD.encode(existing_factor_challenge),
        existing_factor_token,
        new_factor_challenge: new_factor_challenge_value,
        new_factor_token,
    }))
}
