use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType, NewFactorType};
use crate::environment::Environment;
use crate::error::ErrorResponse;
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use types::{
    AddFactorChallengeRequest, AddFactorChallengeResponse, ExistingFactorKind, NewFactor, Platform,
};
use uuid::Uuid;

pub(crate) fn registration_state_hash(registration_bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(registration_bytes))
}

/// Issues the existing-factor approval challenge and the new-factor ownership challenge.
///
/// # Errors
/// Returns an error if registration setup or challenge token creation fails.
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

    let (new_factor_type, new_factor_challenge_value, new_factor_token) = match &request.new_factor
    {
        NewFactor::PasskeyRegistration { platform } => {
            // Recovery requires a discoverable credential; this helper requires a resident key.
            let (challenge, registration) = match platform {
                Platform::Ios | Platform::Android => environment
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
            // OIDC ownership is proved by the session key bound to the token's nonce.
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
