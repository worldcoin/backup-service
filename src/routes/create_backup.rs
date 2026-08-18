use std::sync::Arc;

use crate::auth::AuthHandler;
use crate::backup_account::{validate_backup_account_id, verify_backup_account_signature};
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType};
use crate::factor_lookup::{
    factor_lookup_mutate_lock_id, FactorLookup, FactorScope, FACTOR_LOOKUP_MUTATE_LOCK_PREFIX,
    FACTOR_LOOKUP_MUTATE_LOCK_TTL_SECS,
};
use crate::normalize_hex_32;
use crate::redis_cache::{RedisCacheError, RedisCacheManager};
use crate::types::backup_metadata::{BackupMetadata, ExportedBackupMetadata};
use crate::types::encryption_key::BackupEncryptionKey;
use crate::types::{Authorization, Environment, ErrorResponse};
use crate::utils::extract_fields_from_multipart;
use axum::extract::Multipart;
use axum::{extract::Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const CREATE_BACKUP_LOCK_KEY: &str = "crate_backup_lock:";
const CREATE_BACKUP_LOCK_TTL: u64 = 120; // 2 minutes (normally timeout shouldn't be hit, it's a fallback in case the lock is not released)

// TODO: Metric relevant for progressive roll out, can be removed after full release.
const BACKUP_ACCOUNT_PROOF_METRIC: &str = "backup_account_proof_total";

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateBackupRequest {
    /// `Main` factor that will be used to manage the backup.
    authorization: Authorization,
    challenge_token: String,
    initial_encryption_key: BackupEncryptionKey,
    /// First `Sync` factor that will be registered for this backup.
    initial_sync_factor: Authorization,
    initial_sync_challenge_token: String,
    /// Provider ID from Turnkey. Only applicable if `initial_sync_factor` is `Authorization::OidcAccount`.
    ///
    /// To avoid confusion, this is NOT the Turnkey account ID, it is specifically the provider ID.
    /// <https://docs.turnkey.com/api-reference/activities/create-oauth-providers>.
    turnkey_provider_id: Option<String>,
    /// The initial manifest hash of the backup.
    #[serde(deserialize_with = "normalize_hex_32")]
    manifest_hash: String,
    /// The unique identifier for the backup account (derived deterministically by the client).
    ///
    /// This is the derived as the public key of the `break_glass` user. Ownership must be proven with
    /// `backup_account_challenge_token` and `backup_account_signature`.
    #[serde(deserialize_with = "validate_backup_account_id")]
    backup_account_id: String,
    /// Token for the challenge issued alongside the factor challenge, bound to
    /// `backup_account_id`.
    backup_account_challenge_token: Option<String>,
    /// Base64-encoded DER `secp256k1` signature over the challenge that
    /// `backup_account_challenge_token` carries, made with the `backup_account_id` secret key.
    backup_account_signature: Option<String>,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateBackupResponse {
    /// DEPRECATED. Please use `backup_metadata.id` instead.
    backup_id: String,
    /// The current state of the backup metadata for the newly created backup.
    backup_metadata: ExportedBackupMetadata,
}

/// Verifies ownership over the provided `backup_account_id`.
///
/// Returns the challenge token to consume once the create commits.
async fn verify_backup_account_proof(
    environment: Environment,
    challenge_manager: &ChallengeManager,
    request: &CreateBackupRequest,
) -> Result<Option<String>, ErrorResponse> {
    let (token, signature) = match (
        request.backup_account_challenge_token.as_deref(),
        request.backup_account_signature.as_deref(),
    ) {
        (Some(token), Some(signature)) => (token, signature),
        (None, None) => {
            metrics::counter!(BACKUP_ACCOUNT_PROOF_METRIC, "result" => "missing").increment(1);
            if environment.enforce_backup_account_proof() {
                return Err(ErrorResponse::bad_request(
                    "missing_backup_account_proof",
                    "backupAccountChallengeToken and backupAccountSignature are required.",
                ));
            }
            return Ok(None);
        }
        _ => {
            return Err(ErrorResponse::bad_request(
                "incomplete_backup_account_proof",
                "backupAccountChallengeToken and backupAccountSignature must be sent together.",
            ));
        }
    };

    let (challenge, challenge_context) = challenge_manager
        .extract_token_payload(ChallengeType::Keypair, token.to_string())
        .await
        .map_err(|err| {
            metrics::counter!(BACKUP_ACCOUNT_PROOF_METRIC, "result" => "invalid").increment(1);
            ErrorResponse::from(err)
        })?;

    // Only the kind is checked: the signature below is verified against the public key that the
    // claimed backupAccountId is, so it cannot authorize any other account.
    if challenge_context != (ChallengeContext::CreateBackupAccount {}) {
        metrics::counter!(BACKUP_ACCOUNT_PROOF_METRIC, "result" => "invalid").increment(1);
        return Err(ErrorResponse::bad_request(
            "invalid_challenge_context",
            "Challenge token was not created to authorize a backup account.",
        ));
    }

    verify_backup_account_signature(&request.backup_account_id, signature, &challenge)
        .inspect_err(|err| {
            metrics::counter!(BACKUP_ACCOUNT_PROOF_METRIC, "result" => "invalid").increment(1);
            tracing::warn!(
                message = "Rejected create with an invalid backup account proof",
                backup_account_id = request.backup_account_id,
                error_code = err.code()
            );
        })?;

    Ok(Some(token.to_string()))
}

#[allow(clippy::too_many_lines)]
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(auth_handler): Extension<AuthHandler>,
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
    Extension(redis_cache_manager): Extension<Arc<RedisCacheManager>>,
    mut multipart: Multipart,
) -> Result<Json<CreateBackupResponse>, ErrorResponse> {
    // Step 1: Parse multipart form data. It should include the main JSON payload with parameters
    // and the attached backup file.
    let mut multipart_fields = extract_fields_from_multipart(&mut multipart).await?;
    let request = multipart_fields.get("payload").ok_or_else(|| {
        tracing::debug!(message = "Missing payload field in multipart data");
        ErrorResponse::bad_request(
            "missing_payload_field",
            "Missing payload field in multipart data",
        )
    })?;
    let request: CreateBackupRequest = serde_json::from_slice(request).map_err(|err| {
        tracing::debug!(message = "Failed to deserialize payload", error = ?err);
        ErrorResponse::bad_request("invalid_payload", "Failed to deserialize payload")
    })?;
    let backup = multipart_fields.remove("backup").ok_or_else(|| {
        tracing::debug!(message = "Missing backup field in multipart data");
        ErrorResponse::bad_request(
            "missing_backup_field",
            "Missing backup field in multipart data",
        )
    })?;

    // Step 1.1: Validate the backup file size
    if backup.is_empty() {
        tracing::debug!(message = "Empty backup file");
        return Err(ErrorResponse::bad_request(
            "empty_backup_file",
            "Empty backup file",
        ));
    }
    if backup.len() > environment.max_backup_file_size() {
        tracing::debug!(message = "Backup file too large");
        return Err(ErrorResponse::content_too_large(
            "Backup file exceeds maximum allowed size.".to_string(),
        ));
    }

    // Step 2: Verify the proof over the backup account ID
    let backup_account_proof_token =
        verify_backup_account_proof(environment, &challenge_manager, &request).await?;

    // Step 3: Verify the main authentication factor
    // This validates the primary factor used to authenticate the user creating the backup

    let validation_result = auth_handler
        .validate_factor_registration(
            &request.authorization,
            request.challenge_token.clone(),
            ChallengeContext::Create {},
            request.turnkey_provider_id.clone(),
            false, // not a sync factor
        )
        .await?;

    let backup_factor = validation_result.factor;
    let factor_to_lookup = validation_result.factor_to_lookup;

    // Step 4: Verify the initial sync factor
    // This validates the sync factor (EC keypair) that will be used for cross-device synchronization
    let sync_validation_result = auth_handler
        .validate_factor_registration(
            &request.initial_sync_factor,
            request.initial_sync_challenge_token.clone(),
            ChallengeContext::Create {},
            None,
            true, // is a sync factor
        )
        .await?;

    let initial_sync_factor = sync_validation_result.factor;
    let initial_sync_factor_to_lookup = sync_validation_result.factor_to_lookup;

    // Step 5: Ensure the backup account ID is unique
    if backup_storage
        .does_backup_exist(&request.backup_account_id)
        .await?
    {
        tracing::info!(
            message = "Backup account ID already exists",
            backup_account_id = request.backup_account_id
        );
        return Err(ErrorResponse::conflict(
            "backup_account_id_already_exists",
            "Backup ID already exists. Please `/sync` instead.",
        ));
    }
    let mut lock_guard = redis_cache_manager
        .try_acquire_lock_guard(
            CREATE_BACKUP_LOCK_KEY,
            request.backup_account_id.clone(),
            Some(CREATE_BACKUP_LOCK_TTL),
        )
        .await?;

    // Step 6: Consume the backupAccountId challenge token
    if let Some(token) = backup_account_proof_token {
        if let Err(err) = redis_cache_manager.use_challenge_token(token).await {
            let result = if matches!(err, RedisCacheError::AlreadyUsed) {
                "replayed"
            } else {
                "not_consumed"
            };
            metrics::counter!(BACKUP_ACCOUNT_PROOF_METRIC, "result" => result).increment(1);
            let _ = lock_guard.release().await;
            return Err(err.into());
        }
        metrics::counter!(BACKUP_ACCOUNT_PROOF_METRIC, "result" => "ok").increment(1);
    }

    // Step 7: Initialize backup metadata
    let backup_metadata = BackupMetadata {
        id: request.backup_account_id,
        factors: vec![backup_factor],
        sync_factors: vec![initial_sync_factor],
        keys: vec![request.initial_encryption_key.clone()],
        manifest_hash: request.manifest_hash,
    };

    // Hold factor mutate locks across lookup insert + S3 create so auth stale-delete cannot remove
    // rows while metadata is still being written.
    let mut main_factor_lock = redis_cache_manager
        .try_acquire_lock_guard(
            FACTOR_LOOKUP_MUTATE_LOCK_PREFIX,
            factor_lookup_mutate_lock_id(&factor_to_lookup),
            Some(FACTOR_LOOKUP_MUTATE_LOCK_TTL_SECS),
        )
        .await?;
    let mut sync_factor_lock = redis_cache_manager
        .try_acquire_lock_guard(
            FACTOR_LOOKUP_MUTATE_LOCK_PREFIX,
            factor_lookup_mutate_lock_id(&initial_sync_factor_to_lookup),
            Some(FACTOR_LOOKUP_MUTATE_LOCK_TTL_SECS),
        )
        .await?;

    // Step 8: Link credential ID and sync factor public key to backup ID for lookup during recovery
    // and sync. This should happen before the backup storage is updated, because
    // it might fail with a duplicate key error.
    factor_lookup
        .insert(
            FactorScope::Main,
            &factor_to_lookup,
            backup_metadata.id.clone(),
        )
        .await?;
    factor_lookup
        .insert(
            FactorScope::Sync,
            &initial_sync_factor_to_lookup,
            backup_metadata.id.clone(),
        )
        .await?;

    // Step 9: Save the backup to S3
    let result = backup_storage.create(backup, &backup_metadata).await;

    // Step 9.1: On failure, roll back lookups while still holding mutate locks, then release.
    if let Err(e) = result {
        if let Err(del_err) = factor_lookup
            .delete(FactorScope::Main, &factor_to_lookup)
            .await
        {
            tracing::error!(message = "Failed to delete factor from lookup table after failed backup creation.", error = ?del_err);
        }
        if let Err(del_err) = factor_lookup
            .delete(FactorScope::Sync, &initial_sync_factor_to_lookup)
            .await
        {
            tracing::error!(message = "Failed to delete factor from lookup table after failed backup creation.", error = ?del_err);
        }
        let _ = main_factor_lock.release().await;
        let _ = sync_factor_lock.release().await;
        let _ = lock_guard.release().await;
        return Err(e.into());
    }

    let _ = main_factor_lock.release().await;
    let _ = sync_factor_lock.release().await;
    let _ = lock_guard.release().await; // explicitly releasing the lock is more reliable

    let backup_id = backup_metadata.id.clone();

    Ok(Json(CreateBackupResponse {
        backup_id,
        backup_metadata: backup_metadata.exported(),
    }))
}
