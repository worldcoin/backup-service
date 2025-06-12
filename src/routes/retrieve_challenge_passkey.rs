use std::sync::Arc;

use crate::attestation_gateway::{
    AllowedHttpMethod, AttestationGateway, AttestationHeaderExt, GenerateRequestHashInput,
};
use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType};
use crate::types::{Environment, ErrorResponse};
use axum::http::{HeaderMap, Method, Uri};
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
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
    Extension(attestation_gateway): Extension<Arc<AttestationGateway>>,
    headers: HeaderMap,
    uri: Uri,
    method: Method,
) -> Result<Json<RetrieveChallengePasskeyResponse>, ErrorResponse> {
    // Step 0: verify the attestation token
    attestation_gateway
        .validate_token(
            headers.attestation_token()?.to_string(),
            &GenerateRequestHashInput {
                path_uri: uri.path().to_string(),
                method: method.to_string(),
                body: None,
                public_key_id: None,
                client_build: None, //TODO mobile does not seem to include those for the nfc uniqueness service?
                client_name: None, //TODO mobile does not seem to include those for the nfc uniqueness service?
            },
        )
        .await?;

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
