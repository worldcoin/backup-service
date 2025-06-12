use std::sync::Arc;

use crate::attestation_gateway::{
    AttestationGateway, AttestationHeaderExt, GenerateRequestHashInput,
};
use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType};
use crate::types::ErrorResponse;

use axum::http::{HeaderMap, Method, Uri};
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

/// Helper function to generate a cryptographic challenge and corresponding encrypted token.
///
/// This function encapsulates the creation of a random 32-byte challenge and its encryption using
/// the provided ChallengeManager. The resulting token is returned alongside the challenge,
/// encoded in base64.
async fn generate_keypair_challenge<T: Into<ChallengeContext>>(
    challenge_manager: Arc<ChallengeManager>,
    request: T,
) -> Result<Json<ChallengeKeypairResponse>, ErrorResponse> {
    // Step 1: Create a new challenge as 32 bytes of random data
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);

    // Step 2: Encrypt the challenge in a JWE to verify later
    let token = challenge_manager
        .create_challenge_token(ChallengeType::Keypair, &challenge, request.into())
        .await?;

    Ok(Json(ChallengeKeypairResponse {
        challenge: STANDARD.encode(challenge),
        token,
    }))
}

/// Endpoint handler to retrieve a keypair challenge.
///
/// This handler initiates the keypair authentication or registration flow by generating
/// a challenge and an encrypted token. Clients typically use this endpoint to fetch a challenge,
/// sign it with their keypair (e.g., stored in iCloud Keychain), and subsequently validate it on return.
pub async fn handler<T: DeserializeOwned + Into<ChallengeContext>>(
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
    Json(request): Json<T>,
) -> Result<Json<ChallengeKeypairResponse>, ErrorResponse> {
    generate_keypair_challenge(challenge_manager, request).await
}

/// Endpoint handler to retrieve a keypair challenge with attestation token validation.
///
/// Before generating a keypair challenge, this handler validates an attestation token included
/// in the request headers, ensuring request authenticity. It leverages the attestation gateway module
/// for token validation.
pub async fn handler_with_attestation<T: DeserializeOwned + Into<ChallengeContext>>(
    Extension(attestation_gateway): Extension<Arc<AttestationGateway>>,
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
    headers: HeaderMap,
    uri: Uri,
    method: Method,
    Json(request): Json<T>,
) -> Result<Json<ChallengeKeypairResponse>, ErrorResponse> {
    attestation_gateway
        .validate_token(
            headers.attestation_token()?.to_string(),
            &GenerateRequestHashInput {
                path_uri: uri.path().to_string(),
                method: method.to_string(),
                body: None,
                public_key_id: None,
                client_build: None,
                client_name: None,
            },
        )
        .await?;
    generate_keypair_challenge(challenge_manager, request).await
}
