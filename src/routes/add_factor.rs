use std::sync::Arc;

use crate::auth::{AuthError, AuthHandler, DecryptedChallengeToken, NewFactorMaterialParts};
use crate::backup_metadata::{BackupMetadata, FactorKind};
use crate::backup_storage::{BackupManagerError, BackupStorage, FactorMetadataWrite};
use crate::challenge_manager::{ChallengeContext, ChallengeManager, NewFactorType};
use crate::environment::Environment;
use crate::error::ErrorResponse;
use crate::factor_binding::{
    existing_factor_signed_payload, registration_state_hash, NewFactorMaterial,
    NewFactorMaterialKind, EXISTING_FACTOR_CHALLENGE_LEN,
};
use crate::factor_lookup::{
    factor_lookup_mutate_lock_id, FactorLookup, FactorLookupError, FactorToLookup,
    FACTOR_LOOKUP_MUTATE_LOCK_PREFIX, FACTOR_LOOKUP_MUTATE_LOCK_TTL_SECS,
};
use crate::headers::CLIENT_VERSION;
use crate::redis_cache::{BurnKey, RedisCacheManager};
use crate::turnkey_activity::{
    verify_turnkey_activity_parameters, verify_turnkey_activity_webauthn_stamp,
};
use crate::verify_signature::{verify_signature, VerifySignatureError};
use crate::webauthn::TryFromValue;
use axum::{Extension, Json};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use http::HeaderMap;
use rand::Rng;
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

/// Outcome of the existing-factor ↔ new-factor material binding check. A `mismatch` is either an
/// attempt at the authenticator/field-swap attack the check exists for, or a client building the
/// signed payload wrong; `legacy_rejected` is a client still signing the bare challenge, and
/// `legacy_accepted` is the same client being let through by the rollout bridge (see
/// [`legacy_passkey_payload_bridge`]). All must be visible on their own rather than folded into
/// generic 400s — `legacy_accepted` in particular is the number that has to reach zero before the
/// bridge is switched off.
const ADD_FACTOR_BINDING_METRIC: &str = "add_factor_binding_check_total";

/// The rollout bridge for the existing=Passkey path: while
/// `ADD_FACTOR_LEGACY_PASSKEY_PAYLOAD_SUNSET` is in the future, a Turnkey activity carrying only the
/// bare challenge (what shipped clients sign today) is still accepted, so the server can deploy
/// ahead of the app release. Returns the sunset while the bridge is active. Every request that uses
/// it is one the binding check did not protect, which is why it is counted and logged separately
/// and why the bridge is off by default and ends by itself.
fn legacy_passkey_payload_bridge(environment: &Environment) -> Option<DateTime<Utc>> {
    environment
        .add_factor_legacy_passkey_payload_sunset()
        .filter(|sunset| Utc::now() < *sunset)
}

fn authorization_kind_label(authorization: &Authorization) -> &'static str {
    match authorization {
        Authorization::Passkey { .. } => "passkey",
        Authorization::OidcAccount { .. } => "oidc",
        Authorization::EcKeypair { .. } => "ec_keypair",
    }
}

fn record_binding_outcome(
    result: &'static str,
    existing_kind: &'static str,
    new_kind: &'static str,
) {
    metrics::counter!(
        ADD_FACTOR_BINDING_METRIC,
        "result" => result,
        "existing_kind" => existing_kind,
        "new_kind" => new_kind,
    )
    .increment(1);
}

/// The existing factor's authorization does not cover the new-factor material actually submitted.
/// `legacy_shape` means it verifiably covered the bare challenge instead — an outdated client, not
/// a swapped request — which is tracked separately so the cutover can be watched.
fn binding_mismatch(
    backup_id: &str,
    existing_kind: &'static str,
    new_kind: &'static str,
    legacy_shape: bool,
) -> ErrorResponse {
    record_binding_outcome(
        if legacy_shape {
            "legacy_rejected"
        } else {
            "mismatch"
        },
        existing_kind,
        new_kind,
    );
    tracing::warn!(
        message = "Existing-factor authorization does not match the submitted new-factor material",
        backup_id = backup_id,
        existing_kind = existing_kind,
        new_kind = new_kind,
        legacy_shape = legacy_shape,
    );
    let message = if legacy_shape {
        "The existing factor signed only the challenge; it must sign existing_factor_challenge || SHA256(tag || new_factor_material)"
    } else {
        "The existing factor's authorization does not match the submitted new factor"
    };
    ErrorResponse::bad_request(ErrorCode::ExistingFactorMaterialBindingMismatch, message)
}

/// Adds a new factor to an existing backup.
///
/// This endpoint requires authentication with both an existing factor (to prove access to the backup)
/// and the new factor (to prove ownership of the new factor). The existing factor's authorization is
/// bound to the new factor's material: it signs `existing_factor_challenge || SHA256(tag ||
/// new_factor_material)` (see `factor_binding`), so a relay cannot swap the credential, token, label,
/// Turnkey provider id or encrypted backup key after the user approved the operation.
///
/// Nothing is consumed (no Redis write) until both factors have been verified and the factor mutate
/// lock is held, so a rejection anywhere before that costs the user nothing.
///
/// During the client rollout, and only for existing=Passkey, the legacy bare-challenge payload is
/// still accepted while the configured sunset is in the future — see
/// [`legacy_passkey_payload_bridge`].
///
/// Supported Main Factor combinations: Passkey ↔ OIDC (Google/Apple). EC/keychain is not supported
/// as a Main Factor for add-factor.
#[allow(clippy::too_many_lines)] // the code is properly split out into steps
#[allow(clippy::too_many_arguments)] // axum extractors, one per dependency; not a call-site API
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(redis_cache_manager): Extension<Arc<RedisCacheManager>>,
    Extension(auth_handler): Extension<AuthHandler>,
    headers: HeaderMap,
    request: Json<AddFactorRequest>,
) -> Result<Json<AddFactorResponse>, ErrorResponse> {
    let existing_kind = authorization_kind_label(&request.existing_factor_authorization);
    let new_kind = authorization_kind_label(&request.new_factor_authorization);
    let client_version = headers
        .get(&CLIENT_VERSION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    // Step 1: Reject unsupported factor kinds and decrypt both challenge tokens. Decryption only
    // proves we issued the tokens and they have not expired; nothing is consumed yet.
    if matches!(
        request.existing_factor_authorization,
        Authorization::EcKeypair { .. }
    ) {
        return Err(ErrorResponse::bad_request(
            ErrorCode::NotSupported,
            "EC keypair is not supported as an existing main factor for add-factor",
        ));
    }
    if matches!(
        request.new_factor_authorization,
        Authorization::EcKeypair { .. }
    ) {
        return Err(ErrorResponse::bad_request(
            ErrorCode::NotSupported,
            "EC keypair is not supported as a main factor for add-factor",
        ));
    }
    if matches!(
        request.existing_factor_authorization,
        Authorization::Passkey { .. }
    ) && request.existing_factor_turnkey_activity.is_none()
    {
        return Err(ErrorResponse::bad_request(
            ErrorCode::MissingTurnkeyActivity,
            "Turnkey activity is missing",
        ));
    }

    let (existing_challenge, existing_context) = challenge_manager
        .extract_token_payload(
            (&request.existing_factor_authorization).into(),
            request.existing_factor_challenge_token.clone(),
        )
        .await?;
    let ChallengeContext::AddFactor {
        new_factor_type: expected_new_factor,
    } = existing_context
    else {
        return Err(ErrorResponse::bad_request(
            ErrorCode::InvalidChallengeContext,
            "Challenge context mismatch",
        ));
    };
    // The 64-byte signed payload is only distinguishable from the bare 32-byte challenges the same
    // session keypair signs elsewhere because the challenge length is fixed; enforce it here rather
    // than trust that `/add-factor/challenge` never changes.
    let existing_challenge: [u8; EXISTING_FACTOR_CHALLENGE_LEN] =
        existing_challenge.as_slice().try_into().map_err(|_| {
            tracing::error!(
                message = "Existing-factor challenge token carries a payload of unexpected length",
                payload_len = existing_challenge.len(),
            );
            ErrorResponse::bad_request(
                ErrorCode::InvalidChallenge,
                "Existing-factor challenge has an unexpected length",
            )
        })?;

    let (new_challenge_payload, new_context) = challenge_manager
        .extract_token_payload(
            (&request.new_factor_authorization).into(),
            request.new_factor_challenge_token.clone(),
        )
        .await?;
    if !matches!(new_context, ChallengeContext::AddFactorByNewFactor {}) {
        return Err(ErrorResponse::bad_request(
            ErrorCode::InvalidChallengeContext,
            "Challenge context mismatch",
        ));
    }

    // Step 2: Detect the same-account metadata-only upgrade, where one OIDC ID token + session
    // keypair authorizes both sides. Both sides then carry the same nonce, which the commit step
    // below burns exactly once. Compare raw JWT + session key per provider (not the full
    // `OidcToken`), so Apple `aud: None` vs an explicit default still counts as one session, while a
    // Google and an Apple token are never treated as the same session merely because their opaque
    // JWT strings happened to be equal.
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

    // Step 3: Enforce the binding between the new-factor descriptor the existing factor's token
    // was minted for and the new-factor authorization actually provided. This catches a swapped
    // new-factor challenge token (a different ceremony entirely); the material binding in step 5
    // catches a swapped credential within the same ceremony. Cheap, so it runs before any crypto.
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
            if registration_state_hash(&new_challenge_payload) != *expected_hash {
                return Err(ErrorResponse::bad_request(
                    ErrorCode::PasskeyRegistrationMismatch,
                    "Passkey registration does not match the one authorized by the existing factor",
                ));
            }
        }
        _ => {
            return Err(ErrorResponse::bad_request(
                ErrorCode::InvalidNewFactorType,
                "Invalid new factor type",
            ));
        }
    }

    // Step 4: Verify the new factor's proof. Nothing is consumed: its challenge token and (for
    // OIDC) nonce come back as keys to burn at the commit step. The token was already decrypted
    // in step 1; each decrypt is a KMS call, so it is handed over rather than decrypted again.
    let (validation_result, pending_new_factor) = auth_handler
        .verify_factor_registration_with_decrypted_token(
            &request.new_factor_authorization,
            DecryptedChallengeToken {
                token: request.new_factor_challenge_token.clone(),
                payload: new_challenge_payload,
                context: new_context,
            },
            ChallengeContext::AddFactorByNewFactor {},
            request.turnkey_provider_id.clone(),
            false, // not a sync factor
        )
        .await?;

    // Step 5: Compute what the existing factor must have signed from what was actually submitted,
    // then verify the existing factor against it. The digest covers the verified credential/token
    // plus every request field that gets persisted with it.
    let material_kind = match &validation_result.material {
        NewFactorMaterialParts::Passkey {
            credential_id,
            public_key_sec1,
            algorithm,
            label,
            client_data_json,
            attestation_object,
        } => {
            let Some(public_key_sec1) = public_key_sec1 else {
                // Reachable before the existing factor is authenticated, so counted rather than
                // logged loudly; the metric is the alerting signal.
                record_binding_outcome("unsupported_alg", existing_kind, new_kind);
                tracing::info!(
                    message =
                        "Rejected add-factor passkey registration: not an ES256/P-256 credential",
                    algorithm = algorithm,
                    credential_id = URL_SAFE_NO_PAD.encode(credential_id),
                );
                return Err(ErrorResponse::bad_request(
                    ErrorCode::UnsupportedPasskeyAlgorithm,
                    "Only ES256 (P-256) passkeys can be added as a factor",
                ));
            };
            NewFactorMaterialKind::Passkey {
                credential_id,
                public_key_sec1,
                label,
                client_data_json,
                attestation_object,
            }
        }
        NewFactorMaterialParts::Oidc { raw_jwt } => NewFactorMaterialKind::Oidc { raw_jwt },
        NewFactorMaterialParts::EcKeypair => {
            return Err(ErrorResponse::bad_request(
                ErrorCode::NotSupported,
                "EC keypair is not supported as a main factor for add-factor",
            ));
        }
    };
    let material = NewFactorMaterial {
        kind: material_kind,
        turnkey_provider_id: request.turnkey_provider_id.as_deref(),
        encrypted_backup_key: request.encrypted_backup_key.as_ref(),
    };
    let signed_payload = existing_factor_signed_payload(&existing_challenge, &material.digest());
    // Existing=OIDC only: a session-keypair signature that fails to verify over the bound payload is
    // indistinguishable from one made with the wrong key, so every such failure is reported as a
    // binding mismatch (`result=mismatch`). For existing=Passkey the stamp is verified first, so
    // there a mismatch is exactly that.

    // Recorded once, after the existing-factor check: `ok` for a bound payload, `legacy_accepted`
    // when the rollout bridge let a bare challenge through (never both).
    let mut binding_outcome = "ok";
    let (backup_id, existing_factor_nonce) = match &request.existing_factor_authorization {
        Authorization::Passkey { credential, .. } => {
            // Step 5A.1: Validate the format of data: turnkey activity, passkey assertion object
            let Some(turnkey_activity) = &request.existing_factor_turnkey_activity else {
                return Err(ErrorResponse::bad_request(
                    ErrorCode::MissingTurnkeyActivity,
                    "Turnkey activity is missing",
                ));
            };
            // Parse credential per the WebAuthn spec
            let user_provided_credential = PublicKeyCredential::try_from_value(credential)?;

            // Step 5A.2: Retrieve the potential backup using credential ID in the passkey.
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

            // Step 5A.3: Verify the signature of the passkey assertion object using the public key
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

            // Step 5A.4: Verify the Turnkey activity is valid and matches what we know about the user.

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

            // Step 5A.5: Verify that the Turnkey activity carries the backup-service binding payload.
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

            // This is the most important piece: the stamped activity must carry
            // `challenge || material_digest`, which binds the passkey signature both to the
            // challenge we issued in `/add-factor/challenge` and to the exact new factor and
            // request fields submitted here. The whole activity is signed and verified above, so
            // no separate signature check is needed on this field.
            if STANDARD.encode(signed_payload) != backup_service_challenge {
                let legacy_shape = STANDARD.encode(existing_challenge) == backup_service_challenge;
                match legacy_passkey_payload_bridge(&environment) {
                    Some(sunset) if legacy_shape => {
                        // The client signed only the challenge, exactly as shipped clients do
                        // today, and the rollout bridge is still open: let it through, but make
                        // it count — this request's new factor is NOT bound to the approval.
                        binding_outcome = "legacy_accepted";
                        tracing::warn!(
                            message = "Accepted legacy add-factor payload (bare challenge) under the rollout bridge; the new factor is not bound to this approval",
                            backup_id = backup_id,
                            new_kind = new_kind,
                            client_version = client_version,
                            bridge_sunset = %sunset.to_rfc3339(),
                        );
                    }
                    _ => {
                        return Err(binding_mismatch(
                            &backup_id,
                            existing_kind,
                            new_kind,
                            legacy_shape,
                        ));
                    }
                }
            }

            (backup_id, None)
        }
        Authorization::OidcAccount {
            oidc_token,
            public_key,
            signature,
        } => {
            // Step 5B.1: Verify the ID token (no Redis) and resolve the account to its backup.
            let (backup_id, _metadata, verified_token) = auth_handler
                .authenticate_existing_oidc_claims(oidc_token, public_key)
                .await?;

            // Step 5B.2: The session keypair must have signed `challenge || material_digest`.
            match verify_signature(public_key, signature, &signed_payload) {
                Ok(()) => {}
                Err(VerifySignatureError::SignatureVerificationError) => {
                    let legacy_shape =
                        verify_signature(public_key, signature, &existing_challenge).is_ok();
                    return Err(binding_mismatch(
                        &backup_id,
                        existing_kind,
                        new_kind,
                        legacy_shape,
                    ));
                }
                Err(err) => return Err(err.into()),
            }

            (backup_id, Some(verified_token.burn_key()))
        }
        Authorization::EcKeypair { .. } => {
            return Err(ErrorResponse::bad_request(
                ErrorCode::NotSupported,
                "EC keypair is not supported as an existing main factor for add-factor",
            ));
        }
    };
    record_binding_outcome(binding_outcome, existing_kind, new_kind);

    let new_factor = validation_result.factor;
    let new_factor_kind = new_factor.kind.clone();
    let factor_to_lookup = validation_result.factor_to_lookup;

    // Step 6: Hold the factor mutate lock across the commit, lookup insert and metadata put (and
    // any lookup heal/ensure that follows) so auth stale-delete cannot remove the row while S3 is
    // still catching up. Taken before the commit so a lost lock race burns nothing.
    let mut factor_lock = redis_cache_manager
        .try_acquire_lock_guard(
            FACTOR_LOOKUP_MUTATE_LOCK_PREFIX,
            factor_lookup_mutate_lock_id(&factor_to_lookup),
            Some(FACTOR_LOOKUP_MUTATE_LOCK_TTL_SECS),
        )
        .await?;

    // Step 7: Commit — consume both challenge tokens and every OIDC nonce in one atomic step, so
    // a replay of any of them fails and a failure here leaves nothing half-consumed. In the
    // same-session case both sides carry one nonce, burned once.
    let mut burn_keys = pending_new_factor.into_burn_keys();
    burn_keys.push(BurnKey::ChallengeToken(
        request.existing_factor_challenge_token.clone(),
    ));
    if let Some(existing_factor_nonce) = existing_factor_nonce {
        if !reuse_same_oidc_session {
            burn_keys.push(existing_factor_nonce);
        }
    }
    if let Err(err) = redis_cache_manager.burn_all_or_nothing(&burn_keys).await {
        let _ = factor_lock.release().await;
        return Err(err.into());
    }

    // Step 8.1: Update the factor lookup with the new factor.
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

    // Step 8.2: Add the new factor and potentially new encrypted key to the backup metadata
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
                .add_encryption_key_only(&backup_id, &new_factor.kind, key)
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

    // Step 8.3: Roll back FactorLookup only when we inserted this request's row and the metadata
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

    // Step 9: Return the new factor ID and the updated backup metadata
    Ok(Json(AddFactorResponse {
        factor_id: new_factor.id,
        backup_metadata: updated_metadata.exported(),
    }))
}

/// Exponential backoff with jitter between the bounded metadata-read retries below, so a batch
/// of concurrent requests hitting a transient S3 blip don't all retry in lockstep. `attempt` is
/// the 1-based attempt number that just failed.
async fn retry_backoff(attempt: u32) {
    let base_ms = 25u64 << attempt.min(4);
    let jitter_ms = rand::thread_rng().gen_range(0..base_ms);
    tokio::time::sleep(std::time::Duration::from_millis(base_ms + jitter_ms)).await;
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
                        retry_backoff(attempt).await;
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
///
/// After a successful insert (or adopt), re-checks metadata and deletes the lookup if the factor
/// disappeared in the TOCTOU window between the pre-check and the Dynamo write.
async fn ensure_main_factor_lookup(
    backup_storage: &BackupStorage,
    factor_lookup: &FactorLookup,
    factor_to_lookup: &FactorToLookup,
    backup_id: &str,
    new_factor_kind: &FactorKind,
) -> Result<(), ErrorResponse> {
    let factor_pk = factor_to_lookup.primary_key();
    if skip_ensure_when_factor_absent(
        backup_storage,
        backup_id,
        new_factor_kind,
        &factor_pk,
        "Skipping FactorLookup ensure; factor or backup no longer in metadata",
    )
    .await?
    {
        return Ok(());
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
            reconcile_ensured_lookup_against_metadata(
                backup_storage,
                factor_lookup,
                factor_to_lookup,
                backup_id,
                new_factor_kind,
                &factor_pk,
            )
            .await
        }
        Err(FactorLookupError::DynamoDbPutError(ref sdk_err))
            if matches!(
                sdk_err,
                aws_sdk_dynamodb::error::SdkError::ServiceError(inner)
                    if inner.err().is_conditional_check_failed_exception()
            ) =>
        {
            ensure_after_conditional_check_failed(
                backup_storage,
                factor_lookup,
                factor_to_lookup,
                backup_id,
                new_factor_kind,
                &factor_pk,
            )
            .await
        }
        Err(err) => Err(err.into()),
    }
}

/// Returns `true` when ensure should stop because metadata no longer contains the factor.
async fn skip_ensure_when_factor_absent(
    backup_storage: &BackupStorage,
    backup_id: &str,
    new_factor_kind: &FactorKind,
    factor_pk: &str,
    skip_message: &str,
) -> Result<bool, ErrorResponse> {
    match factor_present_in_metadata_with_retry(
        backup_storage,
        backup_id,
        new_factor_kind,
        factor_pk,
    )
    .await
    {
        FactorPresence::Absent => {
            tracing::info!(message = skip_message, factor_pk);
            Ok(true)
        }
        FactorPresence::Present | FactorPresence::Unknown => Ok(false),
    }
}

async fn ensure_after_conditional_check_failed(
    backup_storage: &BackupStorage,
    factor_lookup: &FactorLookup,
    factor_to_lookup: &FactorToLookup,
    backup_id: &str,
    new_factor_kind: &FactorKind,
    factor_pk: &str,
) -> Result<(), ErrorResponse> {
    match factor_lookup
        .lookup_consistent(FactorScope::Main, factor_to_lookup)
        .await?
    {
        Some(existing) if existing == backup_id => {
            reconcile_ensured_lookup_against_metadata(
                backup_storage,
                factor_lookup,
                factor_to_lookup,
                backup_id,
                new_factor_kind,
                factor_pk,
            )
            .await
        }
        Some(_) => Err(ErrorResponse::bad_request(
            ErrorCode::FactorAlreadyExists,
            "This factor already exists.",
        )),
        None => {
            // Row disappeared between ConditionalCheckFailed and read (rollback race).
            // Re-check metadata so we do not resurrect after a concurrent delete.
            if skip_ensure_when_factor_absent(
                backup_storage,
                backup_id,
                new_factor_kind,
                factor_pk,
                "Skipping FactorLookup ensure retry; factor no longer in metadata",
            )
            .await?
            {
                return Ok(());
            }
            retry_ensure_insert_after_vanished_row(
                backup_storage,
                factor_lookup,
                factor_to_lookup,
                backup_id,
                new_factor_kind,
                factor_pk,
            )
            .await
        }
    }
}

async fn retry_ensure_insert_after_vanished_row(
    backup_storage: &BackupStorage,
    factor_lookup: &FactorLookup,
    factor_to_lookup: &FactorToLookup,
    backup_id: &str,
    new_factor_kind: &FactorKind,
    factor_pk: &str,
) -> Result<(), ErrorResponse> {
    match factor_lookup
        .insert(FactorScope::Main, factor_to_lookup, backup_id.to_string())
        .await
    {
        Ok(()) => {
            reconcile_ensured_lookup_against_metadata(
                backup_storage,
                factor_lookup,
                factor_to_lookup,
                backup_id,
                new_factor_kind,
                factor_pk,
            )
            .await
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
                Some(existing) if existing == backup_id => {
                    reconcile_ensured_lookup_against_metadata(
                        backup_storage,
                        factor_lookup,
                        factor_to_lookup,
                        backup_id,
                        new_factor_kind,
                        factor_pk,
                    )
                    .await
                }
                _ => {
                    tracing::error!(
                        message = "Failed to ensure FactorLookup after successful factor write",
                        factor_pk,
                    );
                    Err(ErrorResponse::internal_server_error())
                }
            }
        }
        Err(err) => Err(err.into()),
    }
}

/// After ensuring a lookup row for `backup_id`, drop it if metadata no longer contains the factor.
///
/// Closes the TOCTOU where `/delete-factor` removes the factor (and its lookup) between the
/// pre-insert presence check and a successful ensure insert.
///
/// Runs up to two delete+heal rounds so a heal insert that races with another `/delete-factor` is
/// reconciled once without async recursion. Deletes are owner-conditional; heal runs after both
/// successful and ambiguous delete outcomes.
async fn reconcile_ensured_lookup_against_metadata(
    backup_storage: &BackupStorage,
    factor_lookup: &FactorLookup,
    factor_to_lookup: &FactorToLookup,
    backup_id: &str,
    new_factor_kind: &FactorKind,
    factor_pk: &str,
) -> Result<(), ErrorResponse> {
    const MAX_ROUNDS: u32 = 2;

    for round in 1..=MAX_ROUNDS {
        match factor_present_in_metadata_with_retry(
            backup_storage,
            backup_id,
            new_factor_kind,
            factor_pk,
        )
        .await
        {
            FactorPresence::Present | FactorPresence::Unknown => return Ok(()),
            FactorPresence::Absent => {
                match factor_lookup
                    .lookup_consistent(FactorScope::Main, factor_to_lookup)
                    .await?
                {
                    Some(existing) if existing == backup_id => {
                        tracing::info!(
                            message =
                                "Deleting FactorLookup restored after concurrent factor deletion",
                            factor_pk,
                            round,
                        );
                        // Owner-conditional: do not remove another backup's mapping if ownership
                        // changed after the consistent read. Heal even on ambiguous delete errors.
                        if let Err(delete_err) = factor_lookup
                            .delete_if_maps_to(FactorScope::Main, factor_to_lookup, backup_id)
                            .await
                        {
                            tracing::error!(
                                message = "Failed owner-conditional FactorLookup delete during ensure reconcile; continuing to heal",
                                error = ?delete_err,
                                factor_pk,
                                round,
                            );
                        }
                        // Concurrent add-factor may have restored the factor and adopted this mapping
                        // before our delete; heal re-inserts if metadata now contains the factor.
                        // A second loop round reconciles a heal insert that raced with delete-factor.
                        heal_main_factor_lookup_if_present(
                            backup_storage,
                            factor_lookup,
                            factor_to_lookup,
                            backup_id,
                            new_factor_kind,
                        )
                        .await;
                    }
                    Some(_) | None => return Ok(()),
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactorPresence {
    Present,
    Absent,
    /// Metadata could not be read after retries; prefer attempting lookup repair.
    Unknown,
}

/// Classifies a successfully fetched metadata snapshot for ensure/heal decisions.
///
/// `None` means the backup object is missing. Does not represent transport failures (`Unknown`).
fn classify_fetched_metadata_factor_presence(
    metadata: Option<&BackupMetadata>,
    kind: &FactorKind,
) -> FactorPresence {
    match metadata {
        Some(metadata) if metadata.factors.iter().any(|f| f.kind == *kind) => {
            FactorPresence::Present
        }
        Some(_) | None => FactorPresence::Absent,
    }
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
            Ok(None) => {
                return classify_fetched_metadata_factor_presence(None, new_factor_kind);
            }
            Ok(Some((metadata, _))) => {
                return classify_fetched_metadata_factor_presence(Some(&metadata), new_factor_kind);
            }
            Err(err) => {
                tracing::warn!(
                    message = "Failed to re-read metadata before FactorLookup ensure; retrying",
                    error = ?err,
                    factor_pk,
                    attempt,
                );
                if attempt < MAX_ATTEMPTS {
                    retry_backoff(attempt).await;
                }
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
    use super::{classify_fetched_metadata_factor_presence, stored_main_factor_id, FactorPresence};
    use crate::backup_metadata::{BackupMetadata, Factor, FactorKind, OidcAccountKind};

    fn google_kind(sub: &str) -> FactorKind {
        FactorKind::OidcAccount {
            account: OidcAccountKind::Google {
                sub: sub.to_string(),
                masked_email: "a****@b.com".to_string(),
            },
            turnkey_provider_id: "tp".to_string(),
        }
    }

    #[test]
    fn stored_main_factor_id_returns_none_when_factor_absent() {
        let metadata = BackupMetadata {
            id: "backup".to_string(),
            factors: vec![],
            sync_factors: vec![],
            keys: vec![],
            manifest_hash: hex::encode([1u8; 32]),
        };
        let kind = google_kind("sub");
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

    #[test]
    fn classify_fetched_metadata_factor_presence_absent_when_backup_missing() {
        let kind = google_kind("sub");
        assert_eq!(
            classify_fetched_metadata_factor_presence(None, &kind),
            FactorPresence::Absent
        );
    }

    #[test]
    fn classify_fetched_metadata_factor_presence_absent_when_kind_missing() {
        let kind = google_kind("wanted");
        let other = Factor::new_oidc_account(
            OidcAccountKind::Google {
                sub: "other".to_string(),
                masked_email: "o****@b.com".to_string(),
            },
            "tp".to_string(),
        );
        let metadata = BackupMetadata {
            id: "backup".to_string(),
            factors: vec![other],
            sync_factors: vec![],
            keys: vec![],
            manifest_hash: hex::encode([1u8; 32]),
        };
        assert_eq!(
            classify_fetched_metadata_factor_presence(Some(&metadata), &kind),
            FactorPresence::Absent
        );
    }

    #[test]
    fn classify_fetched_metadata_factor_presence_present_when_kind_matches() {
        let factor = Factor::new_oidc_account(
            OidcAccountKind::Google {
                sub: "sub".to_string(),
                masked_email: "a****@b.com".to_string(),
            },
            "tp".to_string(),
        );
        let kind = factor.kind.clone();
        let metadata = BackupMetadata {
            id: "backup".to_string(),
            factors: vec![factor],
            sync_factors: vec![],
            keys: vec![],
            manifest_hash: hex::encode([1u8; 32]),
        };
        assert_eq!(
            classify_fetched_metadata_factor_presence(Some(&metadata), &kind),
            FactorPresence::Present
        );
    }
}
