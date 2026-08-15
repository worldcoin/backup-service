use std::sync::Arc;

use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType};
use crate::environment::Environment;
use crate::error::ErrorResponse;
use axum::{Extension, Json};
use types::{CreateChallengePasskeyRequest, CreateChallengePasskeyResponse, Platform};
use uuid::Uuid;

pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
    request: Json<CreateChallengePasskeyRequest>,
) -> Result<Json<CreateChallengePasskeyResponse>, ErrorResponse> {
    // Step 1: Create a new challenge using WebAuthn implementation
    let (challenge, registration) = match request.platform {
        Platform::Ios => environment.webauthn_config().start_passkey_registration(
            Uuid::new_v4(),
            &request.name,
            &request.display_name,
            None,
        )?,
        Platform::Android => environment
            .webauthn_config()
            .start_google_passkey_in_google_password_manager_only_registration(
                Uuid::new_v4(),
                &request.name,
                &request.display_name,
                None,
            )?,
    };
    let challenge_json: serde_json::Value = serde_json::to_value(&challenge)?;

    // Step 2: Encrypt the server-side object in a JWE
    let registration_json = serde_json::to_string(&registration)?;
    let token = challenge_manager
        .create_challenge_token(
            ChallengeType::Passkey,
            registration_json.as_bytes(),
            ChallengeContext::Create {},
        )
        .await?;

    Ok(Json(CreateChallengePasskeyResponse {
        challenge: challenge_json,
        token,
    }))
}
