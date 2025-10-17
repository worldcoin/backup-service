use std::sync::Arc;

use crate::auth::{AuthError, AuthHandler};
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType, NewFactorType};
use crate::factor_lookup::{FactorLookup, FactorScope, FactorToLookup};
use crate::redis_cache::RedisCacheManager;
use crate::turnkey_activity::{
    verify_turnkey_activity_parameters, verify_turnkey_activity_webauthn_stamp,
};
use crate::types::backup_metadata::FactorKind;
use crate::types::encryption_key::BackupEncryptionKey;
use crate::types::{Authorization, ErrorResponse, OidcToken};
use crate::verify_signature::verify_signature;
use crate::webauthn::TryFromValue;
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
#[allow(clippy::too_many_lines)] // the code is properly split out into steps
pub async fn handler(
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(redis_cache_manager): Extension<Arc<RedisCacheManager>>,
    Extension(auth_handler): Extension<AuthHandler>,
    request: Json<AddFactorRequest>,
) -> Result<Json<AddFactorResponse>, ErrorResponse> {
    // Step 1: Check authorization for the existing factor and get the backup ID
    let (backup_id, expected_new_factor) = match &request.existing_factor_authorization {
        Authorization::Passkey { credential, .. } => {
            // Step 1A.1: Validate the format of data: turnkey activity, passkey assertion object

            // Turnkey activity is required for passkeys
            let Some(turnkey_activity) = &request.existing_factor_turnkey_activity else {
                return Err(ErrorResponse::bad_request("missing_turnkey_activity"));
            };
            // Parse credential per the WebAuthn spec
            let user_provided_credential = PublicKeyCredential::try_from_value(credential)?;

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
                return Err(AuthError::BackupUntraceable.into());
            };
            let backup = backup_storage.get_by_backup_id(&backup_id).await?;
            let Some(backup) = backup else {
                return Err(AuthError::BackupMissing.into());
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
                .ok_or_else(|| AuthError::BackupUntraceable)?;
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
            let ChallengeContext::AddFactor { new_factor_type } = challenge_context else {
                return Err(ErrorResponse::bad_request("invalid_challenge_context"));
            };
            // We do not need to check signature here, because whole activity is signed and verified
            // in the previous steps.

            // Step 1A.6: Track the used challenge to prevent replay attacks
            let _ = redis_cache_manager
                .use_challenge_token(request.existing_factor_challenge_token.clone())
                .await;

            // Step 1A.7: Return the backup ID and the new factor type
            (backup_id, new_factor_type)
        }
        Authorization::OidcAccount { .. } | Authorization::EcKeypair { .. } => {
            // Generic path: authenticate existing factor and retrieve backup id; also bind to expected new factor type via challenge context
            let (_trusted_challenge, challenge_context) = challenge_manager
                .extract_token_payload(
                    (&request.existing_factor_authorization).into(),
                    request.existing_factor_challenge_token.to_string(),
                )
                .await?;

            let ChallengeContext::AddFactor { new_factor_type } = challenge_context else {
                return Err(ErrorResponse::bad_request("invalid_challenge_context"));
            };

            // Use AuthHandler.verify to both authenticate and mark the EFC token as used
            let (verified_backup_id, _metadata) = auth_handler
                .clone()
                .verify(
                    &request.existing_factor_authorization,
                    FactorScope::Main,
                    ChallengeContext::AddFactor {
                        new_factor_type: new_factor_type.clone(),
                    },
                    request.existing_factor_challenge_token.clone(),
                )
                .await?;

            (verified_backup_id, new_factor_type)
        }
    };

    // Special-case: OIDC(existing) -> OIDC(new) with the SAME id_token.
    // Handle metadata-only Turnkey key append: skip second OIDC verification to avoid
    // nonce reuse; verify new-factor challenge signature, mark the token used, append
    // TURNKEY key if provided, and return the existing OIDC factorId.
    if let (
        NewFactorType::OidcAccount { .. },
        Authorization::OidcAccount {
            oidc_token: existing_oidc_token,
            ..
        },
        Authorization::OidcAccount {
            oidc_token: new_oidc_token,
            public_key: new_public_key,
            signature: new_signature,
        },
    ) = (
        &expected_new_factor,
        &request.existing_factor_authorization,
        &request.new_factor_authorization,
    ) {
        let raw_existing = match existing_oidc_token {
            OidcToken::Google { token } | OidcToken::Apple { token } => token,
        };
        let raw_new = match new_oidc_token {
            OidcToken::Google { token } | OidcToken::Apple { token } => token,
        };

        if raw_existing == raw_new {
            // Verify new-factor challenge binding without re-verifying the OIDC token
            let (new_challenge_payload, new_challenge_context) = challenge_manager
                .extract_token_payload(
                    (&request.new_factor_authorization).into(),
                    request.new_factor_challenge_token.clone(),
                )
                .await?;

            if !matches!(
                new_challenge_context,
                ChallengeContext::AddFactorByNewFactor { .. }
            ) {
                return Err(ErrorResponse::bad_request("invalid_challenge_context"));
            }

            // Ensure the client signed the challenge with the provided OIDC session keypair
            verify_signature(new_public_key, new_signature, &new_challenge_payload)?;

            // Mark the new-factor challenge token as used to prevent replay
            redis_cache_manager
                .use_challenge_token(request.new_factor_challenge_token.clone())
                .await?;

            // Append the TURNKEY key if provided
            if let Some(key) = request.encrypted_backup_key.clone() {
                backup_storage
                    .add_encryption_key_only(&backup_id, key)
                    .await?;
            }

            // Return the existing OIDC factor id
            if let Some((metadata, _)) =
                backup_storage.get_metadata_by_backup_id(&backup_id).await?
            {
                if let Some(existing) = metadata
                    .factors
                    .iter()
                    .find(|f| matches!(&f.kind, FactorKind::OidcAccount { .. }))
                {
                    return Ok(Json(AddFactorResponse {
                        factor_id: existing.id.clone(),
                    }));
                }
            }

            return Err(ErrorResponse::bad_request("factor_not_found"));
        }
    }

    // Step 2: Validate the new factor using AuthHandler
    // Enforce binding between expected_new_factor and new_factor_authorization
    match (&expected_new_factor, &request.new_factor_authorization) {
        (
            NewFactorType::OidcAccount {
                oidc_token: expected,
            },
            Authorization::OidcAccount { oidc_token, .. },
        ) => {
            let raw = match oidc_token {
                crate::types::OidcToken::Google { token }
                | crate::types::OidcToken::Apple { token } => token,
            };
            if raw != expected {
                return Err(ErrorResponse::bad_request("invalid_oidc_token"));
            }
        }
        (NewFactorType::PasskeyRegistration {}, Authorization::Passkey { .. })
        | (NewFactorType::EcKeypair {}, Authorization::EcKeypair { .. }) => {}
        _ => {
            return Err(ErrorResponse::bad_request("invalid_new_factor_type"));
        }
    }

    // Step 2A.2: Use AuthHandler to validate the new factor
    let validation_result = auth_handler
        .validate_factor_registration(
            &request.new_factor_authorization,
            request.new_factor_challenge_token.clone(),
            ChallengeContext::AddFactorByNewFactor {},
            request.turnkey_provider_id.clone(),
            false, // not a sync factor
        )
        .await?;

    let new_factor = validation_result.factor;
    let new_factor_kind = new_factor.kind.clone();
    let new_factor_id = new_factor.id.clone();
    let factor_to_lookup = validation_result.factor_to_lookup;

    // Step 3.1: Update the factor lookup with the new factor
    let lookup_insert_result = factor_lookup
        .insert(FactorScope::Main, &factor_to_lookup, backup_id.clone())
        .await;
    let lookup_insert_succeeded = lookup_insert_result.is_ok();
    // If factor already exists in lookup, we treat this as idempotent and continue to metadata handling
    if let Err(err) = &lookup_insert_result {
        tracing::info!(message = "Lookup insert failed (possibly duplicate)", error = ?err, factor_pk = factor_to_lookup.primary_key());
    }

    // Step 3.2: Add the new factor and potentially new encrypted key to the backup metadata
    let mut final_factor_id = new_factor_id;
    if let Err(e) = backup_storage
        .add_factor(
            &backup_id,
            new_factor.clone(),
            request.encrypted_backup_key.clone(),
        )
        .await
    {
        match e {
            crate::backup_storage::BackupManagerError::FactorAlreadyExists => {
                // If factor already exists and we have a new encryption key, append it; otherwise no-op
                if let Some(key) = request.encrypted_backup_key.clone() {
                    backup_storage
                        .add_encryption_key_only(&backup_id, key)
                        .await?;
                }
                // Determine existing factorId from metadata
                if let Some((metadata, _)) =
                    backup_storage.get_metadata_by_backup_id(&backup_id).await?
                {
                    if let Some(existing) =
                        metadata.factors.iter().find(|f| f.kind == new_factor_kind)
                    {
                        final_factor_id = existing.id.clone();
                    }
                }
                // best-effort cleanup if we inserted lookup above when not needed
                let _ = factor_lookup
                    .delete(FactorScope::Main, &factor_to_lookup)
                    .await;
            }
            other => {
                // Rollback lookup entry to avoid orphaned unrevokeable factor
                if lookup_insert_succeeded {
                    if let Err(err) = factor_lookup
                        .delete(FactorScope::Main, &factor_to_lookup)
                        .await
                    {
                        tracing::error!(message = "Failed to rollback factor lookup after metadata write failure", error = ?err, factor_pk = factor_to_lookup.primary_key());
                    }
                }
                return Err(other.into());
            }
        }
    }

    // Step 4: Return the new factor ID
    Ok(Json(AddFactorResponse {
        factor_id: final_factor_id,
    }))
}
