use std::sync::Arc;

use crate::auth::{AuthError, AuthHandler};
use crate::backup_metadata::{BackupMetadata, FactorKind};
use crate::backup_storage::{BackupManagerError, BackupStorage, FactorMetadataWrite};
use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType, NewFactorType};
use crate::error::ErrorResponse;
use crate::factor_lookup::{
    factor_lookup_mutate_lock_id, FactorLookup, FactorLookupError, FactorToLookup,
    FACTOR_LOOKUP_MUTATE_LOCK_PREFIX, FACTOR_LOOKUP_MUTATE_LOCK_TTL_SECS,
};
use crate::redis_cache::RedisCacheManager;
use crate::turnkey_activity::{
    verify_turnkey_activity_parameters, verify_turnkey_activity_webauthn_stamp,
};
use crate::webauthn::TryFromValue;
use axum::{Extension, Json};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::Duration;
use types::{
    AddFactorRequest, AddFactorResponse, Authorization, BackupEncryptionKey, ErrorCode,
    FactorScope, OidcToken,
};
use webauthn_rs::prelude::PublicKeyCredential;

/// Sanity check on what kind of activity is being signed alongside the backup service challenge.
/// It should be an activity to create a new API key, because client uses it to a start a session
/// and issue subsequent Turnkey requests without user verification.
const EXPECTED_TURNKEY_ACTIVITY_TYPE: &str = "ACTIVITY_TYPE_CREATE_API_KEYS_V2";

const TURNKEY_ACTIVITY_TTL: Duration = Duration::minutes(5);

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
                    ErrorCode::MissingTurnkeyActivity,
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
                    ErrorCode::InvalidTurnkeyActivity,
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
                        ErrorCode::InvalidTurnkeyActivity,
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
                    ErrorCode::InvalidChallenge,
                    "Challenge mismatch with Turnkey activity",
                ));
            }

            let ChallengeContext::AddFactor { new_factor_type } = challenge_context else {
                return Err(ErrorResponse::bad_request(
                    ErrorCode::InvalidChallengeContext,
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
            // Step 1B.1: Authenticate the existing OIDC factor and bind to the expected new-factor
            // descriptor, so the OIDC factor signs over the exact new factor being added.
            let (_trusted_challenge, challenge_context) = challenge_manager
                .extract_token_payload(
                    (&request.existing_factor_authorization).into(),
                    request.existing_factor_challenge_token.clone(),
                )
                .await?;

            let ChallengeContext::AddFactor { new_factor_type } = challenge_context else {
                return Err(ErrorResponse::bad_request(
                    ErrorCode::InvalidChallengeContext,
                    "Challenge context mismatch",
                ));
            };

            // `AuthHandler::verify` authenticates the existing OIDC factor and marks its challenge
            // token as used.
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
                ErrorCode::NotSupported,
                "EC keypair is not supported as an existing main factor for add-factor",
            ));
        }
    };

    // Step 2: Enforce the binding between the new-factor descriptor the existing factor
    // authorized and the new-factor authorization actually provided.
    match (&expected_new_factor, &request.new_factor_authorization) {
        (
            NewFactorType::OidcAccount {
                oidc_token: expected_oidc_token,
            },
            Authorization::OidcAccount { oidc_token, .. },
        ) => {
            let raw_oidc_token = match oidc_token {
                OidcToken::Google { token } | OidcToken::Apple { token, aud: _ } => token,
            };
            if raw_oidc_token != expected_oidc_token {
                return Err(ErrorResponse::bad_request(
                    ErrorCode::OidcTokenMismatch,
                    "OIDC Token mismatch",
                ));
            }
        }
        (
            NewFactorType::PasskeyRegistration {
                registration_hash: expected_hash,
            },
            Authorization::Passkey { .. },
        ) => {
            // Existing factor authorized this exact WebAuthn registration state (hash bound in
            // its challenge context). Reject swapped new-factor challenge tokens.
            let (registration_payload, new_factor_context) = challenge_manager
                .extract_token_payload(
                    ChallengeType::Passkey,
                    request.new_factor_challenge_token.clone(),
                )
                .await?;
            if !matches!(
                new_factor_context,
                ChallengeContext::AddFactorByNewFactor {}
            ) {
                return Err(ErrorResponse::bad_request(
                    ErrorCode::InvalidChallengeContext,
                    "Challenge context mismatch",
                ));
            }
            let actual_hash =
                super::add_factor_challenge::registration_state_hash(&registration_payload);
            if actual_hash != *expected_hash {
                return Err(ErrorResponse::bad_request(
                    ErrorCode::PasskeyRegistrationMismatch,
                    "Passkey registration does not match the one authorized by the existing factor",
                ));
            }
        }
        (_, Authorization::EcKeypair { .. }) => {
            return Err(ErrorResponse::bad_request(
                ErrorCode::NotSupported,
                "EC keypair is not supported as a main factor for add-factor",
            ));
        }
        _ => {
            return Err(ErrorResponse::bad_request(
                ErrorCode::InvalidNewFactorType,
                "Invalid new factor type",
            ));
        }
    }

    // Step 2A.1: When the same OIDC ID token + session keypair authorize both sides (same-account
    // metadata-only upgrade), the existing-factor verify above already consumed the nonce — skip a
    // second Redis mark so registration can still verify the new-factor challenge signature.
    // Compare raw JWT + session key per-provider (not full `OidcToken`), so Apple `aud: None` vs
    // explicit default does not block reuse of the already-consumed nonce, while still requiring
    // both sides to be the same provider — a Google and an Apple token must never be treated as
    // the same session merely because their opaque JWT strings happened to be equal.
    let reuse_same_oidc_session = match (
        &request.existing_factor_authorization,
        &request.new_factor_authorization,
    ) {
        (
            Authorization::OidcAccount {
                oidc_token: existing_token,
                public_key: existing_pk,
                ..
            },
            Authorization::OidcAccount {
                oidc_token: new_token,
                public_key: new_pk,
                ..
            },
        ) => {
            let same_raw_token = match (existing_token, new_token) {
                (OidcToken::Google { token: existing }, OidcToken::Google { token: new }) => {
                    existing == new
                }
                (
                    OidcToken::Apple {
                        token: existing, ..
                    },
                    OidcToken::Apple { token: new, .. },
                ) => existing == new,
                _ => false,
            };
            same_raw_token && existing_pk == new_pk
        }
        _ => false,
    };

    // Step 2A.2: Use AuthHandler to validate the new factor
    let validation_result = auth_handler
        .validate_factor_registration(
            &request.new_factor_authorization,
            request.new_factor_challenge_token.clone(),
            ChallengeContext::AddFactorByNewFactor {},
            request.turnkey_provider_id.clone(),
            false, // not a sync factor
            !reuse_same_oidc_session,
        )
        .await?;

    let new_factor = validation_result.factor;
    let new_factor_kind = new_factor.kind.clone();
    let factor_to_lookup = validation_result.factor_to_lookup;

    // Hold the factor mutate lock across lookup insert + metadata put (and any lookup heal/ensure
    // that follows) so auth stale-delete cannot remove the row while S3 is still catching up.
    let mut factor_lock = redis_cache_manager
        .try_acquire_lock_guard(
            FACTOR_LOOKUP_MUTATE_LOCK_PREFIX,
            factor_lookup_mutate_lock_id(&factor_to_lookup),
            Some(FACTOR_LOOKUP_MUTATE_LOCK_TTL_SECS),
        )
        .await?;

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
            // Consistent read: ConditionalCheckFailed proves the item exists; an eventually
            // consistent GetItem can still return None and spuriously 500.
            let consistent_lookup = match factor_lookup
                .lookup_consistent(FactorScope::Main, &factor_to_lookup)
                .await
            {
                Ok(result) => result,
                Err(err) => {
                    let _ = factor_lock.release().await;
                    return Err(err.into());
                }
            };
            match consistent_lookup {
                Some(existing_backup_id) if existing_backup_id == backup_id => {
                    tracing::info!(
                        message = "Lookup insert skipped; factor already mapped to this backup",
                        factor_pk = factor_to_lookup.primary_key(),
                    );
                    false
                }
                Some(_) => {
                    let _ = factor_lock.release().await;
                    return Err(ErrorResponse::bad_request(
                        ErrorCode::FactorAlreadyExists,
                        "This factor already exists.",
                    ));
                }
                None => {
                    tracing::error!(
                        message = "Lookup ConditionalCheckFailed but factor not found on consistent re-read",
                        factor_pk = factor_to_lookup.primary_key(),
                    );
                    let _ = factor_lock.release().await;
                    return Err(ErrorResponse::internal_server_error());
                }
            }
        }
        Err(err) => {
            let _ = factor_lock.release().await;
            return Err(err.into());
        }
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
            if let Err(err) = backup_storage
                .add_encryption_key_only(&backup_id, key)
                .await
            {
                let _ = factor_lock.release().await;
                return Err(err.into());
            }
        }
        let metadata_lookup = match backup_storage.get_metadata_by_backup_id(&backup_id).await {
            Ok(result) => result,
            Err(err) => {
                let _ = factor_lock.release().await;
                return Err(err.into());
            }
        };
        let Some((metadata, _)) = metadata_lookup else {
            let _ = factor_lock.release().await;
            return Err(BackupManagerError::BackupNotFound.into());
        };
        // Require the stored factor still exist. A concurrent delete can remove it between the
        // AlreadyExists race and this read — do not invent an ID or restore a stale lookup.
        let Some(factor_id) = stored_main_factor_id(&metadata, &new_factor_kind) else {
            tracing::warn!(
                message = "FactorAlreadyExists reconcile found no matching factor in metadata",
                factor_pk = factor_to_lookup.primary_key(),
            );
            if lookup_insert_succeeded {
                if let Err(delete_err) = factor_lookup
                    .delete(FactorScope::Main, &factor_to_lookup)
                    .await
                {
                    tracing::error!(
                        message = "Failed to delete factor from lookup after missing duplicate factor",
                        error = ?delete_err,
                        factor_pk = factor_to_lookup.primary_key(),
                    );
                }
            }
            let _ = factor_lock.release().await;
            return Err(BackupManagerError::FactorNotFound.into());
        };
        // Factor is in metadata — ensure lookup still maps here (a concurrent inserter may have
        // rolled back the shared row after we adopted it).
        let ensure_result = ensure_main_factor_lookup(
            &backup_storage,
            &factor_lookup,
            &factor_to_lookup,
            &backup_id,
            &new_factor_kind,
        )
        .await;
        let _ = factor_lock.release().await;
        ensure_result?;
        return Ok(Json(AddFactorResponse {
            factor_id,
            backup_metadata: metadata.exported(),
        }));
    }

    // Step 3.3: Roll back FactorLookup only when we inserted this request's row and the metadata
    // write definitely did not land (`NotInserted`).
    //
    // Another concurrent request may adopt this lookup row (same-backup ConditionalCheckFailed)
    // and write the factor around our rollback. Skip delete if the factor is already present;
    // after delete, re-check and re-insert (heal) if it appeared in the race window.
    if lookup_insert_succeeded && write.should_rollback_lookup() {
        let factor_still_absent = match backup_storage.get_metadata_by_backup_id(&backup_id).await {
            Ok(Some((metadata, _))) => !metadata.factors.iter().any(|f| f.kind == new_factor_kind),
            Ok(None) => true,
            Err(err) => {
                tracing::error!(
                    message = "Failed to re-read metadata before lookup rollback; keeping lookup row",
                    error = ?err,
                    factor_pk = factor_to_lookup.primary_key(),
                );
                false
            }
        };

        if factor_still_absent {
            if let Err(delete_err) = factor_lookup
                .delete(FactorScope::Main, &factor_to_lookup)
                .await
            {
                // Delete may still have applied despite a timeout/dispatch error — continue to
                // heal so we do not leave a concurrent successful writer untraceable.
                tracing::error!(message = "Failed to delete factor from lookup table after failed factor addition.", error = ?delete_err, factor_pk = factor_to_lookup.primary_key());
            }

            // Heal whether delete returned Ok or Err: a concurrent writer may have committed the
            // factor around this rollback, and an ambiguous delete response may have removed a
            // lookup that writer had just restored.
            heal_main_factor_lookup_if_present(
                &backup_storage,
                &factor_lookup,
                &factor_to_lookup,
                &backup_id,
                &new_factor_kind,
            )
            .await;
        } else {
            tracing::info!(
                message =
                    "Skipping lookup rollback; factor present in metadata after concurrent write",
                factor_pk = factor_to_lookup.primary_key(),
            );
        }
    }

    let updated_metadata_result = write.into_result();

    // Successful writer always verifies lookup: a concurrent request that inserted the row may
    // still roll it back around our metadata commit.
    let ensure_result = if updated_metadata_result.is_ok() {
        Some(
            ensure_main_factor_lookup(
                &backup_storage,
                &factor_lookup,
                &factor_to_lookup,
                &backup_id,
                &new_factor_kind,
            )
            .await,
        )
    } else {
        None
    };

    let _ = factor_lock.release().await;

    let updated_metadata = updated_metadata_result?;
    if let Some(ensure_result) = ensure_result {
        ensure_result?;
    }

    // Step 4: Return the new factor ID and the updated backup metadata
    Ok(Json(AddFactorResponse {
        factor_id: new_factor.id,
        backup_metadata: updated_metadata.exported(),
    }))
}

/// After a lookup rollback delete (or ambiguous delete error), restore the row if metadata now
/// contains the factor — covering concurrent successful writers and lost delete ACKs.
///
/// Retries a few times so a transient `DynamoDB` failure does not permanently orphan a factor that
/// another request successfully wrote.
async fn heal_main_factor_lookup_if_present(
    backup_storage: &BackupStorage,
    factor_lookup: &FactorLookup,
    factor_to_lookup: &FactorToLookup,
    backup_id: &str,
    new_factor_kind: &FactorKind,
) {
    const MAX_ATTEMPTS: u32 = 3;
    // Once we have observed the factor in metadata, prefer Dynamo insert retries over abandoning
    // heal when a later S3 re-read fails transiently.
    let mut confirmed_factor_present = false;
    // After ConditionalCheckFailed + consistent miss, retry insert without another S3 read.
    let mut retry_insert_without_metadata = false;

    for attempt in 1..=MAX_ATTEMPTS {
        let needs_heal = if retry_insert_without_metadata {
            retry_insert_without_metadata = false;
            true
        } else {
            match backup_storage.get_metadata_by_backup_id(backup_id).await {
                Ok(Some((metadata, _))) => {
                    let present = metadata.factors.iter().any(|f| f.kind == *new_factor_kind);
                    if present {
                        confirmed_factor_present = true;
                    }
                    present
                }
                Ok(None) => false,
                Err(err) => {
                    tracing::error!(
                        message =
                            "Failed to re-read metadata after lookup rollback; will retry heal",
                        error = ?err,
                        factor_pk = factor_to_lookup.primary_key(),
                        attempt,
                    );
                    if confirmed_factor_present {
                        true
                    } else if attempt == MAX_ATTEMPTS {
                        return;
                    } else {
                        continue;
                    }
                }
            }
        };

        if !needs_heal {
            return;
        }

        match attempt_heal_lookup_insert(factor_lookup, factor_to_lookup, backup_id, attempt).await
        {
            HealInsertOutcome::Done | HealInsertOutcome::WrongOwner => return,
            HealInsertOutcome::RowVanished => {
                // Retry insert without requiring another S3 metadata read (that read can fail
                // and wrongly abandon heal).
                confirmed_factor_present = true;
                match attempt_heal_lookup_insert(
                    factor_lookup,
                    factor_to_lookup,
                    backup_id,
                    attempt,
                )
                .await
                {
                    HealInsertOutcome::Done | HealInsertOutcome::WrongOwner => return,
                    HealInsertOutcome::RowVanished | HealInsertOutcome::Failed => {
                        retry_insert_without_metadata = true;
                    }
                }
            }
            HealInsertOutcome::Failed => {}
        }
    }

    tracing::error!(
        message = "Exhausted FactorLookup heal retries; factor may be untraceable until repaired",
        factor_pk = factor_to_lookup.primary_key(),
        backup_id,
    );
}

enum HealInsertOutcome {
    Done,
    WrongOwner,
    RowVanished,
    Failed,
}

async fn attempt_heal_lookup_insert(
    factor_lookup: &FactorLookup,
    factor_to_lookup: &FactorToLookup,
    backup_id: &str,
    attempt: u32,
) -> HealInsertOutcome {
    match factor_lookup
        .insert(FactorScope::Main, factor_to_lookup, backup_id.to_string())
        .await
    {
        Ok(()) => {
            tracing::info!(
                message = "Healed FactorLookup after concurrent factor write during rollback",
                factor_pk = factor_to_lookup.primary_key(),
                attempt,
            );
            HealInsertOutcome::Done
        }
        Err(FactorLookupError::DynamoDbPutError(ref sdk_err))
            if matches!(
                sdk_err,
                aws_sdk_dynamodb::error::SdkError::ServiceError(inner)
                    if inner.err().is_conditional_check_failed_exception()
            ) =>
        {
            match factor_lookup
                .lookup_consistent(FactorScope::Main, factor_to_lookup)
                .await
            {
                Ok(Some(existing)) if existing == backup_id => HealInsertOutcome::Done,
                Ok(Some(other_backup_id)) => {
                    tracing::error!(
                        message = "Heal aborted: FactorLookup maps factor to a different backup",
                        factor_pk = factor_to_lookup.primary_key(),
                        expected_backup_id = backup_id,
                        actual_backup_id = other_backup_id.as_str(),
                    );
                    HealInsertOutcome::WrongOwner
                }
                Ok(None) => {
                    tracing::warn!(
                        message = "FactorLookup row missing after ConditionalCheckFailed during heal; retrying insert without metadata re-read",
                        factor_pk = factor_to_lookup.primary_key(),
                        attempt,
                    );
                    HealInsertOutcome::RowVanished
                }
                Err(err) => {
                    tracing::error!(
                        message = "Failed consistent FactorLookup read during heal reconcile",
                        error = ?err,
                        factor_pk = factor_to_lookup.primary_key(),
                        attempt,
                    );
                    HealInsertOutcome::Failed
                }
            }
        }
        Err(err) => {
            tracing::error!(
                message = "Failed to heal FactorLookup after concurrent factor write during rollback",
                error = ?err,
                factor_pk = factor_to_lookup.primary_key(),
                attempt,
            );
            HealInsertOutcome::Failed
        }
    }
}

/// Ensures `FactorLookup` maps this factor to `backup_id` after metadata was written successfully.
///
/// Closes the race where another request inserted the lookup, we adopted it, wrote metadata, and
/// that other request then deleted the row during its `NotInserted` rollback.
///
/// Re-reads metadata first so a concurrent `/delete-factor` (or backup delete) does not cause us to
/// resurrect a stale lookup for a factor that is no longer present. Metadata reads are retried; if
/// they remain unavailable we still attempt the lookup insert so a transient S3 error does not
/// abandon repair after a successful factor write.
async fn ensure_main_factor_lookup(
    backup_storage: &BackupStorage,
    factor_lookup: &FactorLookup,
    factor_to_lookup: &FactorToLookup,
    backup_id: &str,
    new_factor_kind: &FactorKind,
) -> Result<(), ErrorResponse> {
    let factor_pk = factor_to_lookup.primary_key();
    match factor_present_in_metadata_with_retry(
        backup_storage,
        backup_id,
        new_factor_kind,
        &factor_pk,
    )
    .await
    {
        FactorPresence::Absent => {
            tracing::info!(
                message = "Skipping FactorLookup ensure; factor or backup no longer in metadata",
                factor_pk = factor_pk.as_str(),
            );
            return Ok(());
        }
        FactorPresence::Present | FactorPresence::Unknown => {}
    }

    match factor_lookup
        .insert(FactorScope::Main, factor_to_lookup, backup_id.to_string())
        .await
    {
        Ok(()) => {
            tracing::info!(
                message = "Restored FactorLookup after successful factor write",
                factor_pk = factor_pk.as_str(),
            );
            Ok(())
        }
        Err(FactorLookupError::DynamoDbPutError(ref sdk_err))
            if matches!(
                sdk_err,
                aws_sdk_dynamodb::error::SdkError::ServiceError(inner)
                    if inner.err().is_conditional_check_failed_exception()
            ) =>
        {
            match factor_lookup
                .lookup_consistent(FactorScope::Main, factor_to_lookup)
                .await?
            {
                Some(existing) if existing == backup_id => Ok(()),
                Some(_) => Err(ErrorResponse::bad_request(
                    ErrorCode::FactorAlreadyExists,
                    "This factor already exists.",
                )),
                None => {
                    // Row disappeared between ConditionalCheckFailed and read (rollback race).
                    // Re-check metadata so we do not resurrect after a concurrent delete.
                    match factor_present_in_metadata_with_retry(
                        backup_storage,
                        backup_id,
                        new_factor_kind,
                        &factor_pk,
                    )
                    .await
                    {
                        FactorPresence::Absent => {
                            tracing::info!(
                                message = "Skipping FactorLookup ensure retry; factor no longer in metadata",
                                factor_pk = factor_pk.as_str(),
                            );
                            return Ok(());
                        }
                        FactorPresence::Present | FactorPresence::Unknown => {}
                    }

                    match factor_lookup
                        .insert(FactorScope::Main, factor_to_lookup, backup_id.to_string())
                        .await
                    {
                        Ok(()) => Ok(()),
                        Err(FactorLookupError::DynamoDbPutError(ref sdk_err))
                            if matches!(
                                sdk_err,
                                aws_sdk_dynamodb::error::SdkError::ServiceError(inner)
                                    if inner.err().is_conditional_check_failed_exception()
                            ) =>
                        {
                            match factor_lookup
                                .lookup_consistent(FactorScope::Main, factor_to_lookup)
                                .await?
                            {
                                Some(existing) if existing == backup_id => Ok(()),
                                _ => {
                                    tracing::error!(
                                        message = "Failed to ensure FactorLookup after successful factor write",
                                        factor_pk = factor_pk.as_str(),
                                    );
                                    Err(ErrorResponse::internal_server_error())
                                }
                            }
                        }
                        Err(err) => Err(err.into()),
                    }
                }
            }
        }
        Err(err) => Err(err.into()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactorPresence {
    Present,
    Absent,
    /// Metadata could not be read after retries; prefer attempting lookup repair.
    Unknown,
}

async fn factor_present_in_metadata_with_retry(
    backup_storage: &BackupStorage,
    backup_id: &str,
    new_factor_kind: &FactorKind,
    factor_pk: &str,
) -> FactorPresence {
    const MAX_ATTEMPTS: u32 = 3;

    for attempt in 1..=MAX_ATTEMPTS {
        match backup_storage.get_metadata_by_backup_id(backup_id).await {
            Ok(None) => return FactorPresence::Absent,
            Ok(Some((metadata, _))) => {
                return if metadata.factors.iter().any(|f| f.kind == *new_factor_kind) {
                    FactorPresence::Present
                } else {
                    FactorPresence::Absent
                };
            }
            Err(err) => {
                tracing::warn!(
                    message = "Failed to re-read metadata before FactorLookup ensure; retrying",
                    error = ?err,
                    factor_pk,
                    attempt,
                );
            }
        }
    }

    tracing::error!(
        message = "Exhausted metadata re-read retries before FactorLookup ensure; attempting repair anyway",
        factor_pk,
        backup_id,
    );
    FactorPresence::Unknown
}

/// Returns the stored main-factor id for `kind`, if present.
fn stored_main_factor_id(metadata: &BackupMetadata, kind: &FactorKind) -> Option<String> {
    metadata
        .factors
        .iter()
        .find(|f| f.kind == *kind)
        .map(|f| f.id.clone())
}

#[cfg(test)]
mod tests {
    use super::stored_main_factor_id;
    use crate::backup_metadata::{BackupMetadata, Factor, FactorKind, OidcAccountKind};

    #[test]
    fn stored_main_factor_id_returns_none_when_factor_absent() {
        let metadata = BackupMetadata {
            id: "backup".to_string(),
            factors: vec![],
            sync_factors: vec![],
            keys: vec![],
            manifest_hash: hex::encode([1u8; 32]),
        };
        let kind = FactorKind::OidcAccount {
            account: OidcAccountKind::Google {
                sub: "sub".to_string(),
                masked_email: "a****@b.com".to_string(),
            },
            turnkey_provider_id: "tp".to_string(),
        };
        assert!(stored_main_factor_id(&metadata, &kind).is_none());
    }

    #[test]
    fn stored_main_factor_id_returns_persisted_id_when_present() {
        let factor = Factor::new_oidc_account(
            OidcAccountKind::Google {
                sub: "sub".to_string(),
                masked_email: "a****@b.com".to_string(),
            },
            "tp".to_string(),
        );
        let expected_id = factor.id.clone();
        let kind = factor.kind.clone();
        let metadata = BackupMetadata {
            id: "backup".to_string(),
            factors: vec![factor],
            sync_factors: vec![],
            keys: vec![],
            manifest_hash: hex::encode([1u8; 32]),
        };
        assert_eq!(
            stored_main_factor_id(&metadata, &kind).as_deref(),
            Some(expected_id.as_str())
        );
    }
}
