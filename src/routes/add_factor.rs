use std::sync::Arc;

use crate::auth::{AuthError, AuthHandler, ValidationResult};
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
use rand::Rng;
use types::{
    AddFactorRequest, AddFactorResponse, Authorization, BackupEncryptionKey, ErrorCode,
    FactorScope, OidcToken,
};
use webauthn_rs::prelude::PublicKeyCredential;

const EXPECTED_TURNKEY_ACTIVITY_TYPE: &str = "ACTIVITY_TYPE_CREATE_API_KEYS_V2";
const TURNKEY_ACTIVITY_TTL: Duration = Duration::minutes(5);

/// Adds a main factor using proofs from both the existing and new factors.
///
/// # Errors
/// Rejects invalid or replayed proofs, unsupported factors, and storage conflicts or failures.
pub async fn handler(
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(redis_cache_manager): Extension<Arc<RedisCacheManager>>,
    Extension(auth_handler): Extension<AuthHandler>,
    request: Json<AddFactorRequest>,
) -> Result<Json<AddFactorResponse>, ErrorResponse> {
    // Step 1: Check authorization for the existing factor and get the backup ID.
    let (backup_id, expected_new_factor) = match &request.existing_factor_authorization {
        Authorization::Passkey { .. } => {
            let authorized = authenticate_existing_passkey(
                &backup_storage,
                &factor_lookup,
                &challenge_manager,
                &request,
            )
            .await?;
            redis_cache_manager
                .use_challenge_token(request.existing_factor_challenge_token.clone())
                .await?;
            authorized
        }
        Authorization::OidcAccount { .. } => {
            let (_, context) = challenge_manager
                .extract_token_payload(
                    (&request.existing_factor_authorization).into(),
                    request.existing_factor_challenge_token.clone(),
                )
                .await?;
            let ChallengeContext::AddFactor { new_factor_type } = context else {
                return Err(ErrorResponse::bad_request(
                    ErrorCode::InvalidChallengeContext,
                    "Challenge context mismatch",
                ));
            };
            let (backup_id, _) = auth_handler
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
            (backup_id, new_factor_type)
        }
        Authorization::EcKeypair { .. } => {
            return Err(ErrorResponse::bad_request(
                ErrorCode::NotSupported,
                "EC keypair is not supported as an existing main factor for add-factor",
            ));
        }
    };
    // Step 2: Validate the new factor against the existing factor's approval.
    verify_new_factor_binding(&challenge_manager, &expected_new_factor, &request).await?;
    let validation = auth_handler
        .validate_factor_registration(
            &request.new_factor_authorization,
            request.new_factor_challenge_token.clone(),
            ChallengeContext::AddFactorByNewFactor {},
            request.turnkey_provider_id.clone(),
            false,
            !same_oidc_session(
                &request.existing_factor_authorization,
                &request.new_factor_authorization,
            ),
        )
        .await?;

    // Step 3: Persist the new factor and any encrypted backup key.
    // Auth-time stale-row cleanup shares this lock with lookup and metadata writes.
    let mut lock = redis_cache_manager
        .try_acquire_lock_guard(
            FACTOR_LOOKUP_MUTATE_LOCK_PREFIX,
            factor_lookup_mutate_lock_id(&validation.factor_to_lookup),
            Some(FACTOR_LOOKUP_MUTATE_LOCK_TTL_SECS),
        )
        .await?;
    let result = persist_factor(
        &backup_storage,
        &factor_lookup,
        &request,
        validation,
        &backup_id,
    )
    .await;
    if let Err(error) = lock.release().await {
        tracing::error!(message = "Failed to release add-factor lookup lock", ?error);
    }
    // Step 4: Return the new factor ID and updated backup metadata.
    result
}

async fn authenticate_existing_passkey(
    storage: &BackupStorage,
    lookup: &FactorLookup,
    challenges: &ChallengeManager,
    request: &AddFactorRequest,
) -> Result<(String, NewFactorType), ErrorResponse> {
    let Authorization::Passkey { credential, .. } = &request.existing_factor_authorization else {
        return Err(AuthError::InvalidAuthorizationType.into());
    };
    let activity = request
        .existing_factor_turnkey_activity
        .as_deref()
        .ok_or_else(|| {
            ErrorResponse::bad_request(
                ErrorCode::MissingTurnkeyActivity,
                "Turnkey activity is missing",
            )
        })?;
    let credential = PublicKeyCredential::try_from_value(credential)?;
    let factor =
        FactorToLookup::from_passkey(URL_SAFE_NO_PAD.encode(credential.get_credential_id()));
    let id = lookup
        .lookup(FactorScope::Main, &factor)
        .await?
        .ok_or(AuthError::BackupUntraceable)?;
    let backup = storage
        .get_by_backup_id(&id)
        .await?
        .ok_or(AuthError::BackupMissing)?;
    verify_existing_activity(&backup.metadata, &credential, activity)?;
    let activity: serde_json::Value = serde_json::from_str(activity).map_err(|error| {
        tracing::info!(message = "Invalid Turnkey activity JSON", ?error);
        ErrorResponse::bad_request(
            ErrorCode::InvalidTurnkeyActivity,
            "Provided Turnkey activity is invalid",
        )
    })?;
    let signed_challenge = activity["metadata"]["challenge"].as_str().ok_or_else(|| {
        ErrorResponse::bad_request(
            ErrorCode::InvalidTurnkeyActivity,
            "Turnkey activity is missing server challenge",
        )
    })?;
    let (challenge, context) = challenges
        .extract_token_payload(
            ChallengeType::Passkey,
            request.existing_factor_challenge_token.clone(),
        )
        .await?;
    if STANDARD.encode(challenge) != signed_challenge {
        return Err(ErrorResponse::bad_request(
            ErrorCode::InvalidChallenge,
            "Challenge mismatch with Turnkey activity",
        ));
    }
    let ChallengeContext::AddFactor { new_factor_type } = context else {
        return Err(ErrorResponse::bad_request(
            ErrorCode::InvalidChallengeContext,
            "Challenge context mismatch",
        ));
    };
    Ok((id, new_factor_type))
}

fn verify_existing_activity(
    metadata: &BackupMetadata,
    credential: &PublicKeyCredential,
    activity: &str,
) -> Result<(), ErrorResponse> {
    let passkey = metadata
        .factors
        .iter()
        .find_map(|factor| {
            let FactorKind::Passkey {
                webauthn_credential,
                ..
            } = &factor.kind
            else {
                return None;
            };
            (webauthn_credential.cred_id() == credential.get_credential_id())
                .then_some(webauthn_credential)
        })
        .ok_or(AuthError::BackupUntraceable)?;
    verify_turnkey_activity_webauthn_stamp(
        passkey.get_public_key(),
        activity,
        &URL_SAFE_NO_PAD.encode(&credential.response.authenticator_data),
        &URL_SAFE_NO_PAD.encode(&credential.response.client_data_json),
        &URL_SAFE_NO_PAD.encode(&credential.response.signature),
    )?;
    let account_id = metadata.keys.iter().find_map(|key| {
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
        activity,
        account_id,
        EXPECTED_TURNKEY_ACTIVITY_TYPE,
        TURNKEY_ACTIVITY_TTL,
    )?;
    Ok(())
}

async fn verify_new_factor_binding(
    challenge_manager: &ChallengeManager,
    expected_new_factor: &NewFactorType,
    request: &AddFactorRequest,
) -> Result<(), ErrorResponse> {
    match (expected_new_factor, &request.new_factor_authorization) {
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
            let (registration_payload, new_factor_context) = challenge_manager
                .extract_token_payload(
                    ChallengeType::Passkey,
                    request.new_factor_challenge_token.clone(),
                )
                .await?;
            let ChallengeContext::AddFactorByNewFactor {} = new_factor_context else {
                return Err(ErrorResponse::bad_request(
                    ErrorCode::InvalidChallengeContext,
                    "Challenge context mismatch",
                ));
            };
            let actual_hash =
                crate::routes::add_factor_challenge::registration_state_hash(&registration_payload);
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

    Ok(())
}

// Apple audience aliases do not change the session; token verification still checks the audience.
fn same_oidc_session(existing: &Authorization, new: &Authorization) -> bool {
    match (existing, new) {
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
    }
}

async fn persist_factor(
    storage: &BackupStorage,
    lookup: &FactorLookup,
    request: &AddFactorRequest,
    validation: ValidationResult,
    backup_id: &str,
) -> Result<Json<AddFactorResponse>, ErrorResponse> {
    let factor = validation.factor;
    let lookup_key = validation.factor_to_lookup;
    // Step 3.1: Update the factor lookup with the new factor.
    let inserted = match insert_main_lookup(lookup, &lookup_key, backup_id).await? {
        LookupInsert::Inserted => true,
        LookupInsert::Existing => false,
        LookupInsert::WrongOwner => {
            return Err(ErrorResponse::bad_request(
                ErrorCode::FactorAlreadyExists,
                "This factor already exists.",
            ))
        }
        LookupInsert::Missing => {
            tracing::error!(
                message = "Lookup missing after insert conflict",
                factor_pk = lookup_key.primary_key(),
            );
            return Err(ErrorResponse::internal_server_error());
        }
    };
    // Step 3.2: Add the factor and any encrypted backup key to metadata.
    let write = storage
        .add_factor(
            backup_id,
            factor.clone(),
            request.encrypted_backup_key.clone(),
        )
        .await;
    let (metadata, factor_id) = match write {
        FactorMetadataWrite::Unknown(BackupManagerError::FactorAlreadyExists) => {
            if let Some(key) = &request.encrypted_backup_key {
                storage
                    .add_encryption_key_only(backup_id, &factor.kind, key.clone())
                    .await?;
            }
            let (metadata, _) = storage
                .get_metadata_by_backup_id(backup_id)
                .await?
                .ok_or(BackupManagerError::BackupNotFound)?;
            let Some(id) = stored_main_factor_id(&metadata, &factor.kind) else {
                tracing::warn!(
                    message = "Duplicate factor disappeared from metadata",
                    factor_pk = lookup_key.primary_key(),
                );
                if inserted {
                    if let Err(error) = lookup.delete(FactorScope::Main, &lookup_key).await {
                        tracing::error!(
                            message = "Failed to remove lookup for missing duplicate factor",
                            ?error,
                            factor_pk = lookup_key.primary_key(),
                        );
                    }
                }
                return Err(BackupManagerError::FactorNotFound.into());
            };
            (metadata, id)
        }
        // Step 3.3: Roll back our lookup insertion when the metadata write did not land.
        FactorMetadataWrite::NotInserted(error) => {
            if inserted {
                rollback_lookup_if_absent(storage, lookup, &lookup_key, backup_id, &factor.kind)
                    .await;
            }
            return Err(error.into());
        }
        FactorMetadataWrite::Unknown(error) => return Err(error.into()),
        FactorMetadataWrite::Inserted(metadata) => (metadata, factor.id),
    };
    ensure_main_factor_lookup(storage, lookup, &lookup_key, backup_id, &factor.kind).await?;
    Ok(Json(AddFactorResponse {
        factor_id,
        backup_metadata: metadata.exported(),
    }))
}

enum LookupInsert {
    Inserted,
    Existing,
    WrongOwner,
    Missing,
}

async fn insert_main_lookup(
    lookup: &FactorLookup,
    factor: &FactorToLookup,
    backup_id: &str,
) -> Result<LookupInsert, FactorLookupError> {
    match lookup
        .insert(FactorScope::Main, factor, backup_id.to_string())
        .await
    {
        Ok(()) => return Ok(LookupInsert::Inserted),
        Err(FactorLookupError::DynamoDbPutError(
            aws_sdk_dynamodb::error::SdkError::ServiceError(error),
        )) if error.err().is_conditional_check_failed_exception() => {}
        Err(error) => return Err(error),
    }
    // An eventually consistent read can miss the row that caused the insert conflict.
    Ok(
        match lookup.lookup_consistent(FactorScope::Main, factor).await? {
            Some(owner) if owner == backup_id => LookupInsert::Existing,
            Some(_) => LookupInsert::WrongOwner,
            None => LookupInsert::Missing,
        },
    )
}

async fn rollback_lookup_if_absent(
    storage: &BackupStorage,
    lookup: &FactorLookup,
    factor: &FactorToLookup,
    backup_id: &str,
    kind: &FactorKind,
) {
    match storage.get_metadata_by_backup_id(backup_id).await {
        Ok(Some((metadata, _))) if metadata.factors.iter().any(|f| f.kind == *kind) => return,
        Ok(Some(_) | None) => {}
        Err(error) => {
            tracing::error!(
                message = "Failed to read metadata before rollback; keeping lookup",
                ?error,
                factor_pk = factor.primary_key(),
            );
            return;
        }
    }
    if let Err(error) = lookup.delete(FactorScope::Main, factor).await {
        tracing::error!(
            message = "Lookup rollback failed; checking for an ambiguous delete",
            ?error,
            factor_pk = factor.primary_key(),
        );
    }
    // A failed delete can still have applied; repair any concurrently committed factor.
    heal_main_factor_lookup_if_present(storage, lookup, factor, backup_id, kind).await;
}

async fn retry_backoff(attempt: u32) {
    let base_ms = 25u64 << attempt.min(4);
    let jitter_ms = rand::thread_rng().gen_range(0..base_ms);
    tokio::time::sleep(std::time::Duration::from_millis(base_ms + jitter_ms)).await;
}

async fn heal_main_factor_lookup_if_present(
    storage: &BackupStorage,
    lookup: &FactorLookup,
    factor: &FactorToLookup,
    backup_id: &str,
    kind: &FactorKind,
) {
    // A confirmed factor can still be repaired if later metadata reads fail.
    let mut confirmed_present = false;
    let mut retry_without_metadata = false;
    for attempt in 1..=3 {
        if !retry_without_metadata {
            match storage.get_metadata_by_backup_id(backup_id).await {
                Ok(metadata) => {
                    if classify_fetched_metadata_factor_presence(
                        metadata.as_ref().map(|(metadata, _)| metadata),
                        kind,
                    ) == FactorPresence::Absent
                    {
                        return;
                    }
                    confirmed_present = true;
                }
                Err(error) => {
                    tracing::error!(
                        message = "Failed to read metadata during lookup repair",
                        ?error,
                        backup_id,
                        attempt,
                    );
                    if !confirmed_present {
                        if attempt < 3 {
                            retry_backoff(attempt).await;
                        }
                        continue;
                    }
                }
            }
        }
        retry_without_metadata = false;
        for _ in 0..2 {
            match insert_main_lookup(lookup, factor, backup_id).await {
                Ok(LookupInsert::Inserted | LookupInsert::Existing) => return,
                Ok(LookupInsert::WrongOwner) => {
                    tracing::error!(
                        message = "Lookup repair conflicts with another backup",
                        factor_pk = factor.primary_key(),
                        backup_id,
                    );
                    return;
                }
                Ok(LookupInsert::Missing) => {
                    // Retry a vanished row without making repair depend on another metadata read.
                    confirmed_present = true;
                    retry_without_metadata = true;
                }
                Err(error) => {
                    tracing::error!(
                        message = "Failed to repair factor lookup",
                        ?error,
                        factor_pk = factor.primary_key(),
                        attempt,
                    );
                    break;
                }
            }
        }
    }
    tracing::error!(
        message = "Lookup repair exhausted retries; factor may be untraceable",
        factor_pk = factor.primary_key(),
        backup_id,
    );
}

async fn ensure_main_factor_lookup(
    storage: &BackupStorage,
    lookup: &FactorLookup,
    factor: &FactorToLookup,
    backup_id: &str,
    kind: &FactorKind,
) -> Result<(), ErrorResponse> {
    let factor_pk = factor.primary_key();
    for attempt in 0..2 {
        if factor_present_in_metadata_with_retry(storage, backup_id, kind, &factor_pk).await
            == FactorPresence::Absent
        {
            return Ok(());
        }
        match insert_main_lookup(lookup, factor, backup_id).await? {
            LookupInsert::Inserted | LookupInsert::Existing => {
                return reconcile_ensured_lookup_against_metadata(
                    storage, lookup, factor, backup_id, kind,
                )
                .await;
            }
            LookupInsert::WrongOwner if attempt == 0 => {
                return Err(ErrorResponse::bad_request(
                    ErrorCode::FactorAlreadyExists,
                    "This factor already exists.",
                ))
            }
            LookupInsert::WrongOwner | LookupInsert::Missing => {}
        }
    }
    tracing::error!(
        message = "Failed to ensure lookup after factor write",
        factor_pk
    );
    Err(ErrorResponse::internal_server_error())
}

async fn reconcile_ensured_lookup_against_metadata(
    backup_storage: &BackupStorage,
    factor_lookup: &FactorLookup,
    factor_to_lookup: &FactorToLookup,
    backup_id: &str,
    new_factor_kind: &FactorKind,
) -> Result<(), ErrorResponse> {
    const MAX_ROUNDS: u32 = 2;
    let factor_pk = factor_to_lookup.primary_key();

    for round in 1..=MAX_ROUNDS {
        match factor_present_in_metadata_with_retry(
            backup_storage,
            backup_id,
            new_factor_kind,
            &factor_pk,
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
                        if let Err(delete_err) = factor_lookup
                            .delete_if_maps_to(FactorScope::Main, factor_to_lookup, backup_id)
                            .await
                        {
                            tracing::error!(
                                message = "Lookup reconcile delete failed; continuing repair",
                                error = ?delete_err,
                                factor_pk,
                                round,
                            );
                        }
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
    // Metadata reads failed; absence has not been established.
    Unknown,
}

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
            Ok(metadata) => {
                return classify_fetched_metadata_factor_presence(
                    metadata.as_ref().map(|(metadata, _)| metadata),
                    new_factor_kind,
                );
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
        message = "Metadata reads exhausted retries; attempting lookup repair",
        factor_pk,
        backup_id,
    );
    FactorPresence::Unknown
}

fn stored_main_factor_id(metadata: &BackupMetadata, kind: &FactorKind) -> Option<String> {
    metadata
        .factors
        .iter()
        .find(|f| f.kind == *kind)
        .map(|f| f.id.clone())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::backup_storage::BackupStorage;
    use crate::environment::Environment;
    use crate::factor_lookup::{FactorLookup, FactorToLookup};
    use mockito::{Matcher, Server};
    use types::FactorScope;

    use crate::backup_metadata::{BackupMetadata, Factor, FactorKind, OidcAccountKind};
    use crate::routes::add_factor::{
        classify_fetched_metadata_factor_presence, ensure_main_factor_lookup,
        rollback_lookup_if_absent, stored_main_factor_id, FactorPresence,
    };

    fn google_kind(sub: &str) -> FactorKind {
        FactorKind::OidcAccount {
            account: OidcAccountKind::Google {
                sub: sub.to_string(),
                masked_email: "a****@b.com".to_string(),
            },
            turnkey_provider_id: "tp".to_string(),
        }
    }

    fn metadata(factors: Vec<Factor>) -> BackupMetadata {
        BackupMetadata {
            id: "backup".to_string(),
            factors,
            sync_factors: vec![],
            keys: vec![],
            manifest_hash: hex::encode([1u8; 32]),
        }
    }

    #[test]
    fn stored_main_factor_id_returns_none_when_factor_absent() {
        assert!(stored_main_factor_id(&metadata(vec![]), &google_kind("sub")).is_none());
    }

    #[test]
    fn stored_main_factor_id_returns_persisted_id_when_present() {
        let factor = Factor {
            id: "stored-id".to_string(),
            created_at: chrono::Utc::now(),
            kind: google_kind("sub"),
        };
        assert_eq!(
            stored_main_factor_id(&metadata(vec![factor]), &google_kind("sub")).as_deref(),
            Some("stored-id"),
        );
    }

    #[test]
    fn classify_fetched_metadata_factor_presence_absent_when_backup_missing() {
        assert_eq!(
            classify_fetched_metadata_factor_presence(None, &google_kind("sub")),
            FactorPresence::Absent,
        );
    }

    #[test]
    fn classify_fetched_metadata_factor_presence_absent_when_kind_missing() {
        let factor = Factor {
            id: "other".to_string(),
            created_at: chrono::Utc::now(),
            kind: google_kind("other"),
        };
        assert_eq!(
            classify_fetched_metadata_factor_presence(
                Some(&metadata(vec![factor])),
                &google_kind("sub")
            ),
            FactorPresence::Absent,
        );
    }

    #[test]
    fn classify_fetched_metadata_factor_presence_present_when_kind_matches() {
        let factor = Factor {
            id: "stored-id".to_string(),
            created_at: chrono::Utc::now(),
            kind: google_kind("sub"),
        };
        assert_eq!(
            classify_fetched_metadata_factor_presence(
                Some(&metadata(vec![factor])),
                &google_kind("sub")
            ),
            FactorPresence::Present,
        );
    }

    async fn fault_storage(server: &Server) -> BackupStorage {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::development(None);
        let config = environment
            .s3_client_config()
            .await
            .to_builder()
            .endpoint_url(server.url())
            .force_path_style(true)
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .build();
        BackupStorage::new(environment, Arc::new(aws_sdk_s3::Client::from_conf(config)))
    }

    async fn factor_lookup(endpoint: Option<String>) -> FactorLookup {
        let environment = Environment::development(None);
        let mut config = aws_sdk_dynamodb::config::Builder::from(&environment.aws_config().await)
            .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::disabled());
        if let Some(endpoint) = endpoint {
            config = config.endpoint_url(endpoint);
        }
        FactorLookup::new(
            environment,
            Arc::new(aws_sdk_dynamodb::Client::from_conf(config.build())),
        )
    }

    #[tokio::test]
    async fn unreadable_metadata_preserves_or_restores_the_lookup() {
        let mut server = Server::new_async().await;
        let _failure = server
            .mock("GET", Matcher::Any)
            .with_status(503)
            .create_async()
            .await;
        let storage = fault_storage(&server).await;
        let lookup = factor_lookup(None).await;
        let id = uuid::Uuid::new_v4().to_string();
        let kind = google_kind(&id);
        let factor = FactorToLookup::OidcAccount {
            iss: "google".to_string(),
            sub: id.clone(),
        };
        lookup
            .insert(FactorScope::Main, &factor, id.clone())
            .await
            .unwrap();

        rollback_lookup_if_absent(&storage, &lookup, &factor, &id, &kind).await;
        assert_eq!(
            lookup
                .lookup_consistent(FactorScope::Main, &factor)
                .await
                .unwrap(),
            Some(id.clone())
        );

        lookup
            .delete_if_maps_to(FactorScope::Main, &factor, &id)
            .await
            .unwrap();
        ensure_main_factor_lookup(&storage, &lookup, &factor, &id, &kind)
            .await
            .unwrap();
        assert_eq!(
            lookup
                .lookup_consistent(FactorScope::Main, &factor)
                .await
                .unwrap(),
            Some(id)
        );
    }

    #[tokio::test]
    async fn ambiguous_delete_is_repaired_when_metadata_confirms_the_factor() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut s3 = Server::new_async().await;
        let mut dynamo = Server::new_async().await;
        let storage = fault_storage(&s3).await;
        let lookup = factor_lookup(Some(dynamo.url())).await;
        let kind = google_kind("subject");
        let factor = FactorToLookup::OidcAccount {
            iss: "google".to_string(),
            sub: "subject".to_string(),
        };
        let metadata = BackupMetadata {
            id: "backup".to_string(),
            factors: vec![Factor::new_oidc_account(
                OidcAccountKind::Google {
                    sub: "subject".to_string(),
                    masked_email: String::new(),
                },
                "provider".to_string(),
            )],
            sync_factors: vec![],
            keys: vec![],
            manifest_hash: hex::encode([0u8; 32]),
        };
        let _missing = s3
            .mock("GET", Matcher::Any)
            .with_status(404)
            .with_body("<Error><Code>NoSuchKey</Code></Error>")
            .expect(1)
            .create_async()
            .await;
        let _committed = s3
            .mock("GET", Matcher::Any)
            .with_status(200)
            .with_body(serde_json::to_vec(&metadata).unwrap())
            .create_async()
            .await;
        let present = Arc::new(AtomicBool::new(true));
        let deleted = present.clone();
        let delete = dynamo
            .mock("POST", "/")
            .match_header("x-amz-target", "DynamoDB_20120810.DeleteItem")
            .with_status(500)
            .with_body_from_request(move |_| {
                deleted.store(false, Ordering::SeqCst);
                "{\"__type\":\"InternalServerError\"}".into()
            })
            .create_async()
            .await;
        let restored = present.clone();
        let insert = dynamo
            .mock("POST", "/")
            .match_header("x-amz-target", "DynamoDB_20120810.PutItem")
            .with_status(200)
            .with_body_from_request(move |_| {
                restored.store(true, Ordering::SeqCst);
                "{}".into()
            })
            .create_async()
            .await;

        rollback_lookup_if_absent(&storage, &lookup, &factor, "backup", &kind).await;
        delete.assert_async().await;
        insert.assert_async().await;
        assert!(present.load(Ordering::SeqCst));
    }
}
