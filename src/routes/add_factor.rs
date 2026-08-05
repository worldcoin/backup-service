use std::sync::Arc;

use crate::auth::{AuthError, AuthHandler};
use crate::backup_storage::{BackupManagerError, BackupStorage, FactorMetadataWrite};
use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType, NewFactorType};
use crate::factor_lookup::{FactorLookup, FactorLookupError, FactorScope, FactorToLookup};
use crate::redis_cache::RedisCacheManager;
use crate::turnkey_activity::{
    verify_turnkey_activity_parameters, verify_turnkey_activity_webauthn_stamp,
};
use crate::types::backup_metadata::{ExportedBackupMetadata, FactorKind};
use crate::types::encryption_key::BackupEncryptionKey;
use crate::types::{Authorization, ErrorResponse};
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
    backup_metadata: ExportedBackupMetadata,
}

/// Adds a new factor to an existing backup.
///
/// This endpoint requires authentication with both an existing factor (to prove access to the backup)
/// and the new factor (to prove ownership of the new factor).
///
/// Supported Main Factor combinations: Passkey ↔ OIDC (Google/Apple). EC/keychain is not supported
/// as a Main Factor for add-factor.
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
                return Err(ErrorResponse::bad_request(
                    "missing_turnkey_activity",
                    "Turnkey activity is missing",
                ));
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

            // If the user already has a Turnkey account registered, we expect the Turnkey activity to contain the same account ID.
            let expected_turnkey_account_id = backup.metadata.keys.iter().find_map(|key| {
                if let BackupEncryptionKey::Turnkey {
                    turnkey_account_id, ..
                } = key
                {
                    Some(turnkey_account_id.clone())
                } else {
                    None
                }
            });

            verify_turnkey_activity_parameters(
                turnkey_activity,
                expected_turnkey_account_id,
                EXPECTED_TURNKEY_ACTIVITY_TYPE,
                TURNKEY_ACTIVITY_TTL,
            )?;

            // Step 1A.5: Verify that Turnkey activity includes backup-service challenge.
            // This challenge should also be of correct type.
            let turnkey_activity_json: serde_json::Value = serde_json::from_str(turnkey_activity)
                .map_err(|err| {
                tracing::info!(message = "Failed to deserialize Turnkey activity", error = ?err);
                ErrorResponse::bad_request(
                    "invalid_turnkey_activity",
                    "Provided Turnkey activity is invalid",
                )
            })?;

            let backup_service_challenge = turnkey_activity_json["metadata"]["challenge"]
                .as_str()
                .ok_or_else(|| {
                    tracing::info!(
                        message =
                            "Failed to get the backup-service challenge from Turnkey activity"
                    );
                    ErrorResponse::bad_request(
                        "invalid_turnkey_activity",
                        "Turnkey activity is missing server challenge",
                    )
                })?;
            let (trusted_challenge, challenge_context) = challenge_manager
                .extract_token_payload(
                    ChallengeType::Passkey,
                    request.existing_factor_challenge_token.clone(),
                )
                .await?;

            // This is the most important piece, it binds the user's passkey signature to the challenge we provided originally in `/add-factor/challenge`
            if STANDARD.encode(trusted_challenge) != backup_service_challenge {
                return Err(ErrorResponse::bad_request(
                    "invalid_challenge",
                    "Challenge mismatch with Turnkey activity",
                ));
            }

            let ChallengeContext::AddFactor { new_factor_type } = challenge_context else {
                return Err(ErrorResponse::bad_request(
                    "invalid_challenge_context",
                    "Challenge context mismatch",
                ));
            };
            // We do not need to check signature here, because whole activity is signed and verified
            // in the previous steps.

            // Step 1A.6: Track the used challenge to prevent replay attacks
            redis_cache_manager
                .use_challenge_token(request.existing_factor_challenge_token.clone())
                .await?;

            // Step 1A.7: Return the backup ID and the new factor type
            (backup_id, new_factor_type)
        }
        Authorization::OidcAccount { .. } => {
            // Authenticate existing OIDC factor and bind to the expected new-factor descriptor.
            let (_trusted_challenge, challenge_context) = challenge_manager
                .extract_token_payload(
                    (&request.existing_factor_authorization).into(),
                    request.existing_factor_challenge_token.clone(),
                )
                .await?;

            let ChallengeContext::AddFactor { new_factor_type } = challenge_context else {
                return Err(ErrorResponse::bad_request(
                    "invalid_challenge_context",
                    "Challenge context mismatch",
                ));
            };

            // AuthHandler.verify authenticates and marks the existing-factor challenge token as used.
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
        Authorization::EcKeypair { .. } => {
            return Err(ErrorResponse::bad_request(
                "not_supported",
                "EC keypair is not supported as an existing main factor for add-factor",
            ));
        }
    };

    // Step 2: Enforce binding between expected_new_factor and new_factor_authorization
    match (&expected_new_factor, &request.new_factor_authorization) {
        (
            NewFactorType::OidcAccount {
                oidc_token: expected,
            },
            Authorization::OidcAccount { oidc_token, .. },
        ) => {
            let raw = match oidc_token {
                crate::types::OidcToken::Google { token }
                | crate::types::OidcToken::Apple { token, aud: _ } => token,
            };
            if raw != expected {
                return Err(ErrorResponse::bad_request(
                    "oidc_token_mismatch",
                    "OIDC Token mismatch",
                ));
            }
        }
        (NewFactorType::PasskeyRegistration {}, Authorization::Passkey { .. }) => {}
        (_, Authorization::EcKeypair { .. }) => {
            return Err(ErrorResponse::bad_request(
                "not_supported",
                "EC keypair is not supported as a main factor for add-factor",
            ));
        }
        _ => {
            return Err(ErrorResponse::bad_request(
                "invalid_new_factor_type",
                "Invalid new factor type",
            ));
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

    // Step 3.1: Update the factor lookup with the new factor.
    // Same-backup ConditionalCheckFailed is treated as idempotent; other failures abort.
    let lookup_insert_succeeded = match factor_lookup
        .insert(FactorScope::Main, &factor_to_lookup, backup_id.clone())
        .await
    {
        Ok(()) => true,
        Err(FactorLookupError::DynamoDbPutError(ref sdk_err))
            if matches!(
                sdk_err,
                aws_sdk_dynamodb::error::SdkError::ServiceError(inner)
                    if inner.err().is_conditional_check_failed_exception()
            ) =>
        {
            match factor_lookup
                .lookup(FactorScope::Main, &factor_to_lookup)
                .await?
            {
                Some(existing_backup_id) if existing_backup_id == backup_id => {
                    tracing::info!(
                        message = "Lookup insert skipped; factor already mapped to this backup",
                        factor_pk = factor_to_lookup.primary_key(),
                    );
                    false
                }
                Some(_) => {
                    return Err(ErrorResponse::bad_request(
                        "factor_already_exists",
                        "This factor already exists.",
                    ));
                }
                None => {
                    tracing::error!(
                        message = "Lookup ConditionalCheckFailed but factor not found on re-read",
                        factor_pk = factor_to_lookup.primary_key(),
                    );
                    return Err(ErrorResponse::internal_server_error());
                }
            }
        }
        Err(err) => return Err(err.into()),
    };

    // Note on atomicity: This process is not atomic. The factor is added to the lookup first because this
    // provides the best security guarantees: it avoids a window where a factor exists in the backup
    // metadata (and is therefore usable) without a lookup entry.

    // Step 3.2: Add the new factor and potentially new encrypted key to the backup metadata
    let write = backup_storage
        .add_factor(
            &backup_id,
            new_factor.clone(),
            request.encrypted_backup_key.clone(),
        )
        .await;

    // Metadata-only encryption-key upgrade when the factor already exists (e.g. same OIDC again).
    if let FactorMetadataWrite::Unknown(BackupManagerError::FactorAlreadyExists) = &write {
        if let Some(key) = request.encrypted_backup_key.clone() {
            backup_storage
                .add_encryption_key_only(&backup_id, key)
                .await?;
        }
        let Some((metadata, _)) = backup_storage.get_metadata_by_backup_id(&backup_id).await?
        else {
            return Err(BackupManagerError::BackupNotFound.into());
        };
        let factor_id = metadata
            .factors
            .iter()
            .find(|f| f.kind == new_factor_kind)
            .map_or(new_factor_id, |f| f.id.clone());
        // Do not roll back lookup: factor is present in metadata; keeping lookup can heal inconsistency.
        return Ok(Json(AddFactorResponse {
            factor_id,
            backup_metadata: metadata.exported(),
        }));
    }

    // Step 3.3: Roll back FactorLookup only when we inserted this request's row and the metadata
    // write definitely did not land (`NotInserted`).
    if lookup_insert_succeeded && write.should_rollback_lookup() {
        if let Err(delete_err) = factor_lookup
            .delete(FactorScope::Main, &factor_to_lookup)
            .await
        {
            tracing::error!(message = "Failed to delete factor from lookup table after failed factor addition.", error = ?delete_err, factor_pk = factor_to_lookup.primary_key());
        }
    }

    let updated_metadata = write.into_result()?;

    // Step 4: Return the new factor ID and the updated backup metadata
    Ok(Json(AddFactorResponse {
        factor_id: new_factor.id,
        backup_metadata: updated_metadata.exported(),
    }))
}
