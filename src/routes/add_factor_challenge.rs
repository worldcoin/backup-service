use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType, NewFactorType};
use crate::environment::Environment;
use crate::error::ErrorResponse;
use crate::factor_binding::registration_state_hash;
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use std::sync::Arc;
use types::{
    AddFactorChallengeRequest, AddFactorChallengeResponse, ExistingFactorKind, NewFactor, Platform,
};
use uuid::Uuid;
use webauthn_rs::prelude::COSEAlgorithm;

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

    // The new-factor descriptor minted here is written into the existing-factor token only for
    // pods running the previous release, which still verify it (#277); `/add-factor` binds the
    // existing factor's approval to the submitted new-factor material instead. That is the only
    // reason the registration ceremony is still minted before the existing-factor token.
    let (new_factor_type, new_factor_challenge_value, new_factor_token) = match &request.new_factor
    {
        NewFactor::PasskeyRegistration { platform } => {
            // `start_passkey_registration` sets `residentKey: discouraged` with no
            // authenticator-attachment constraint, so registration can succeed on a
            // non-discoverable credential (e.g. a security key). Recovery only ever runs a
            // discoverable-only authentication ceremony (no `allowCredentials`), which would
            // leave such a factor impossible to select. webauthn-rs 0.5.2's only non-attested
            // helper that requires a resident/discoverable credential is this Android-named
            // one; the WebAuthn options it produces (platform attachment + resident key
            // required + user verification required) are exactly what we need on iOS too, and
            // Apple platforms honor them the same way — it's just not named for that.
            let (mut challenge, registration) = match platform {
                Platform::Ios | Platform::Android => environment
                    .webauthn_config()
                    .start_google_passkey_in_google_password_manager_only_registration(
                        Uuid::new_v4(),
                        "World App",
                        "World App",
                        None,
                    )?,
            };
            // The binding digest encodes the new passkey's P-256 key, so `/add-factor` rejects any
            // non-ES256 credential (`unsupported_passkey_algorithm`). Advertise only what will be
            // accepted, so no authenticator picks an algorithm the ceremony then fails on. The
            // registration state keeps webauthn-rs's default list; a credential outside the
            // advertised set is still caught at completion.
            challenge
                .public_key
                .pub_key_cred_params
                .retain(|params| params.alg == COSEAlgorithm::ES256 as i64);
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
            // Proof of possession for an OIDC factor is done via the EC keypair bound into the
            // OIDC token's nonce, not the token itself — there's no dedicated OIDC challenge
            // type because verification never happens by "signing via OIDC", only by signing
            // this raw challenge with that keypair (see `ChallengeType::from(&Authorization)`).
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
            ChallengeContext::AddFactor {
                new_factor_type: Some(new_factor_type),
            },
        )
        .await?;

    Ok(Json(AddFactorChallengeResponse {
        existing_factor_challenge: STANDARD.encode(existing_factor_challenge),
        existing_factor_token,
        new_factor_challenge: new_factor_challenge_value,
        new_factor_token,
    }))
}
