use std::sync::Arc;

use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType, NewFactorType};
use crate::factor_lookup::{FactorLookup, FactorScope, FactorToLookup};
use crate::oidc_token_verifier::OidcTokenVerifier;
use crate::turnkey_activity::{
    verify_turnkey_activity_parameters, verify_turnkey_activity_webauthn_stamp,
};
use crate::types::backup_metadata::{Factor, FactorKind, OidcAccountKind};
use crate::types::encryption_key::BackupEncryptionKey;
use crate::types::{Authorization, ErrorResponse, OidcToken};
use crate::utils::webauthn::safe_deserialize_passkey_credential;
use crate::verify_signature::verify_signature;
use axum::{Extension, Json};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::Duration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::PublicKeyCredential;

/// Sanity check on what kind of activity is being signed alongside the backup service challenge.
/// It should be an activity to create a new API key, because client uses it to a start a session
/// and issue subsequent Turnkey requests without user verification.
const EXPECTED_TURNKEY_ACTIVITY_TYPE: &str = "ACTIVITY_TYPE_CREATE_API_KEYS_V2";

const TURNKEY_ACTIVITY_TTL: Duration = Duration::minutes(5);

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AddFactorRequest {
    /// Authorization for the existing factor
    existing_factor_authorization: Authorization,
    existing_factor_challenge_token: String,
    /// Activity used by Turnkey to create a session using the existing factor. It should also
    ///  include the backup-service challenge as one of the fields.
    existing_factor_turnkey_activity: Option<String>,

    /// Authorization for the new factor
    new_factor_authorization: Authorization,
    new_factor_challenge_token: String,

    /// Optional encrypted backup keypair
    encrypted_backup_key: Option<BackupEncryptionKey>,

    /// Provider ID from Turnkey ID. Only applicable if `new_factor_authorization` is `Authorization::OidcAccount`.
    turnkey_provider_id: Option<String>,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddFactorResponse {
    factor_id: String,
}

/// Adds a new factor to an existing backup.
///
/// This endpoint requires authentication with both an existing factor (to prove access to the backup)
/// and the new factor (to prove ownership of the new factor).
pub async fn handler(
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(oidc_token_verifier): Extension<Arc<OidcTokenVerifier>>,
    request: Json<AddFactorRequest>,
) -> Result<Json<AddFactorResponse>, ErrorResponse> {
    // Step 1: Check authorization for the existing factor and get the backup ID
    let (backup_id, expected_new_factor) = match &request.existing_factor_authorization {
        Authorization::Passkey { credential } => {
            // Step 1A.1: Validate the format of data: turnkey activity, passkey assertion object

            // Turnkey activity is required for passkeys
            let Some(turnkey_activity) = &request.existing_factor_turnkey_activity else {
                return Err(ErrorResponse::bad_request("missing_turnkey_activity"));
            };
            // Parse credential per the WebAuthn spec
            let user_provided_credential: PublicKeyCredential =
                safe_deserialize_passkey_credential(credential)?;

            // Step 1A.2: Retrieve the potential backup using credential ID in the passkey.
            // At this point, the user has not verified that they correctly signed the challenge.
            let provided_credential_id = user_provided_credential.get_credential_id();
            let backup_id = factor_lookup
                .lookup(
                    FactorScope::Main,
                    &FactorToLookup::from_passkey(URL_SAFE_NO_PAD.encode(provided_credential_id)),
                )
                .await?;
            let Some(backup_id) = backup_id else {
                return Err(ErrorResponse::bad_request("backup_not_found"));
            };
            let backup = backup_storage.get_by_backup_id(&backup_id).await?;
            let Some(backup) = backup else {
                return Err(ErrorResponse::bad_request("backup_not_found"));
            };

            // Step 1A.3: Verify the signature of the passkey assertion object using the public key
            // from backup metadata as a reference. It should sign the Turnkey activity.
            let reference_passkey = backup
                .metadata
                .factors
                .iter()
                .find_map(|factor| {
                    if let FactorKind::Passkey {
                        webauthn_credential,
                        ..
                    } = &factor.kind
                    {
                        if webauthn_credential.cred_id() == provided_credential_id {
                            Some(webauthn_credential)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .ok_or_else(|| ErrorResponse::bad_request("backup_not_found"))?;
            verify_turnkey_activity_webauthn_stamp(
                reference_passkey.get_public_key(),
                turnkey_activity,
                &URL_SAFE_NO_PAD.encode(&user_provided_credential.response.authenticator_data),
                &URL_SAFE_NO_PAD.encode(&user_provided_credential.response.client_data_json),
                &URL_SAFE_NO_PAD.encode(&user_provided_credential.response.signature),
            )?;

            // Step 1A.4: Verify the Turnkey activity is valid and matches what we know about the user.
            let expected_turnkey_account_id = match &request.encrypted_backup_key {
                // If user is creating a new Turnkey account as part of this flow, new account ID
                // should be the expected one.
                Some(BackupEncryptionKey::Turnkey {
                    turnkey_account_id, ..
                }) => turnkey_account_id.clone(),
                // Otherwise, we expect the Turnkey account ID to be the same as the one in
                // the existing backup.
                _ => {
                    if let Some(turnkey_account_id) = backup.metadata.keys.iter().find_map(|key| {
                        if let BackupEncryptionKey::Turnkey {
                            turnkey_account_id, ..
                        } = key
                        {
                            Some(turnkey_account_id.clone())
                        } else {
                            None
                        }
                    }) {
                        turnkey_account_id
                    } else {
                        return Err(ErrorResponse::bad_request("no_turnkey_account_id"));
                    }
                }
            };
            verify_turnkey_activity_parameters(
                turnkey_activity,
                &expected_turnkey_account_id,
                EXPECTED_TURNKEY_ACTIVITY_TYPE,
                TURNKEY_ACTIVITY_TTL,
            )?;

            // Step 1A.5: Verify that Turnkey activity includes backup-service challenge.
            // This challenge should also be of correct type.
            let turnkey_activity_json: serde_json::Value = serde_json::from_str(turnkey_activity)
                .map_err(|err| {
                tracing::info!(message = "Failed to deserialize Turnkey activity", error = ?err);
                ErrorResponse::bad_request("webauthn_error")
            })?;
            let backup_service_challenge = turnkey_activity_json["metadata"]["challenge"]
                .as_str()
                .ok_or_else(|| {
                    tracing::info!(
                        message =
                            "Failed to get the backup-service challenge from Turnkey activity"
                    );
                    ErrorResponse::bad_request("webauthn_error")
                })?;
            let (trusted_challenge, challenge_context) = challenge_manager
                .extract_token_payload(
                    ChallengeType::Passkey,
                    request.existing_factor_challenge_token.to_string(),
                )
                .await?;
            if STANDARD.encode(trusted_challenge) != backup_service_challenge {
                return Err(ErrorResponse::bad_request("invalid_challenge"));
            }
            let new_factor_type = match challenge_context {
                ChallengeContext::AddFactor { new_factor_type } => new_factor_type,
                _ => {
                    return Err(ErrorResponse::bad_request("invalid_challenge_context"));
                }
            };
            // We do not need to check signature here, because whole activity is signed and verified
            // in the previous steps.

            // Step 1A.6: Track the used challenge to prevent replay attacks
            // TODO / FIXME

            // Step 1A.7: Return the backup ID and the new factor type
            (backup_id, new_factor_type)
        }
        Authorization::OidcAccount { .. } | Authorization::EcKeypair { .. } => {
            // TODO/FIXME: Implement the logic for verifying the existing factor for OIDC and EC keypair
            return Err(ErrorResponse::bad_request("not_supported"));
        }
    };

    // Step 2: Check authorization for the new factor and create the appropriate factor
    let (new_factor, factor_to_lookup) = match &request.new_factor_authorization {
        Authorization::OidcAccount {
            oidc_token,
            public_key,
            signature,
        } => {
            // Step 2A.0: Get the Turnkey API OIDC provider ID from the request. We should save it
            // to metadata and allow client to look it up later.
            let turnkey_provider_id = request
                .turnkey_provider_id
                .clone()
                .ok_or_else(|| ErrorResponse::bad_request("missing_turnkey_provider_id"))?;

            // Step 2A.1: Verify the OIDC token is the same as in the verified challenge context
            // for existing factor. It asserts that the existing factor signed this particular
            // OIDC token.
            #[allow(irrefutable_let_patterns)]
            if let NewFactorType::OidcAccount {
                oidc_token: expected_oidc_token,
            } = &expected_new_factor
            {
                let raw_oidc_token = match &oidc_token {
                    OidcToken::Google { token } => token,
                };
                if raw_oidc_token != expected_oidc_token {
                    return Err(ErrorResponse::bad_request("invalid_oidc_token"));
                }
            } else {
                return Err(ErrorResponse::bad_request("invalid_new_factor_type"));
            }

            // Step 2A.2: Get the challenge payload from the challenge token
            let (trusted_challenge, challenge_context) = challenge_manager
                .extract_token_payload(
                    ChallengeType::Keypair,
                    request.new_factor_challenge_token.clone(),
                )
                .await?;
            let ChallengeContext::AddFactorByNewFactor {} = challenge_context else {
                return Err(ErrorResponse::bad_request("invalid_challenge_context"));
            };

            // Step 2A.3: Verify the signature of the challenge using the public key
            let claims = oidc_token_verifier
                .verify_token(oidc_token, public_key.clone())
                .await
                .map_err(|_| ErrorResponse::bad_request("oidc_token_verification_error"))?;

            // Step 2A.4: Verify the signature using the public key
            verify_signature(public_key, signature, trusted_challenge.as_ref())?;

            // Step 2A.5: Track used challenges to prevent replay attacks
            // TODO/FIXME

            // Step 2A.6: Create a new factor and factor lookup
            let oidc_account = match &oidc_token {
                OidcToken::Google { .. } => {
                    let email = claims
                        .email()
                        .ok_or_else(|| {
                            tracing::info!(message = "Missing email in OIDC token");
                            ErrorResponse::bad_request("missing_email")
                        })?
                        .to_string();
                    OidcAccountKind::Google {
                        sub: claims.subject().to_string(),
                        email,
                    }
                }
            };
            (
                Factor::new_oidc_account(oidc_account, turnkey_provider_id),
                FactorToLookup::from_oidc_account(
                    claims.issuer().to_string(),
                    claims.subject().to_string(),
                ),
            )
        }
        _ => {
            // Only OIDC account is supported at this time
            return Err(ErrorResponse::bad_request(
                "invalid_new_factor_authorization_type",
            ));
        }
    };

    // Step 3.1: Update the factor lookup with the new factor
    factor_lookup
        .insert(FactorScope::Main, &factor_to_lookup, backup_id.clone())
        .await?;

    // Step 3.2: Add the new factor and potentially new encrypted key to the backup metadata
    backup_storage
        .add_factor(
            &backup_id,
            new_factor.clone(),
            request.encrypted_backup_key.clone(),
        )
        .await?;

    // Step 4: Return the new factor ID
    Ok(Json(AddFactorResponse {
        factor_id: new_factor.id,
    }))
}
