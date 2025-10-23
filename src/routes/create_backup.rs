use std::sync::Arc;

use crate::auth::AuthHandler;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
use crate::factor_lookup::{FactorLookup, FactorScope};
use crate::redis_cache::RedisCacheManager;
use crate::types::backup_metadata::BackupMetadata;
use crate::types::encryption_key::BackupEncryptionKey;
use crate::types::{Authorization, Environment, ErrorResponse};
use crate::utils::extract_fields_from_multipart;
use crate::{normalize_hex_32, validate_backup_account_id};
use axum::extract::Multipart;
use axum::{extract::Extension, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const CREATE_BACKUP_LOCK_KEY: &str = "crate_backup_lock:";
const CREATE_BACKUP_LOCK_TTL: u64 = 120; // 2 minutes (normally timeout shouldn't be hit, it's a fallback in case the lock is not released)

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
    #[serde(deserialize_with = "validate_backup_account_id")]
    backup_account_id: String,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateBackupResponse {
    pub backup_id: String,
}

#[allow(clippy::too_many_lines)]
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(auth_handler): Extension<AuthHandler>,
    Extension(redis_cache_manager): Extension<Arc<RedisCacheManager>>,
    mut multipart: Multipart,
) -> Result<Json<CreateBackupResponse>, ErrorResponse> {
    // Step 1: Parse multipart form data. It should include the main JSON payload with parameters
    // and the attached backup file.
    let multipart_fields = extract_fields_from_multipart(&mut multipart).await?;
    let request = multipart_fields.get("payload").ok_or_else(|| {
        tracing::info!(message = "Missing payload field in multipart data");
        ErrorResponse::bad_request("missing_payload_field")
    })?;
    let request: CreateBackupRequest = serde_json::from_slice(request).map_err(|err| {
        tracing::info!(message = "Failed to deserialize payload", error = ?err);
        ErrorResponse::bad_request("invalid_payload")
    })?;
    let backup = multipart_fields.get("backup").ok_or_else(|| {
        tracing::info!(message = "Missing backup field in multipart data");
        ErrorResponse::bad_request("missing_backup_field")
    })?;

    // Step 1.1: Validate the backup file size
    if backup.is_empty() {
        tracing::info!(message = "Empty backup file");
        return Err(ErrorResponse::bad_request("empty_backup_file"));
    }
    if backup.len() > environment.max_backup_file_size() {
        tracing::info!(message = "Backup file too large");
        return Err(ErrorResponse::bad_request("backup_file_too_large"));
    }

    // Step 2: Verify the main authentication factor
    // This validates the primary factor used to authenticate the user creating the backup

    let validation_result = auth_handler
        .validate_factor_registration(
            &request.authorization,
            request.challenge_token.to_string(),
            ChallengeContext::Create {},
            request.turnkey_provider_id.clone(),
            false, // not a sync factor
        )
        .await?;

    let backup_factor = validation_result.factor;
    let factor_to_lookup = validation_result.factor_to_lookup;

    // Step 3: Verify the initial sync factor
    // This validates the sync factor (EC keypair) that will be used for cross-device synchronization
    let sync_validation_result = auth_handler
        .validate_factor_registration(
            &request.initial_sync_factor,
            request.initial_sync_challenge_token.to_string(),
            ChallengeContext::Create {},
            None,
            true, // is a sync factor
        )
        .await?;

    let initial_sync_factor = sync_validation_result.factor;
    let initial_sync_factor_to_lookup = sync_validation_result.factor_to_lookup;

    // Step 4: Ensure the backup account ID is unique
    if backup_storage
        .does_backup_exist(&request.backup_account_id)
        .await?
    {
        tracing::info!(
            message = "Backup account ID already exists",
            backup_account_id = request.backup_account_id
        );
        return Err(ErrorResponse::conflict("backup_account_id_already_exists"));
    }
    let mut lock_guard = redis_cache_manager
        .try_acquire_lock_guard(
            CREATE_BACKUP_LOCK_KEY,
            request.backup_account_id.clone(),
            Some(CREATE_BACKUP_LOCK_TTL),
        )
        .await?;

    // Step 5: Initialize backup metadata
    let backup_metadata = BackupMetadata {
        id: request.backup_account_id,
        factors: vec![backup_factor],
        sync_factors: vec![initial_sync_factor],
        keys: vec![request.initial_encryption_key.clone()],
        manifest_hash: request.manifest_hash,
    };

    // Step 6: Link credential ID and sync factor public key to backup ID for lookup during recovery
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

    // Step 7: Save the backup to S3
    let result = backup_storage
        .create(backup.to_vec(), &backup_metadata)
        .await;

    let _ = lock_guard.release().await; // explicitly releasing the lock is more reliable

    // Step 7.1: If the backup storage create fails, remove the factor from the lookup table
    if let Err(e) = result {
        if let Err(e) = factor_lookup
            .delete(FactorScope::Main, &factor_to_lookup)
            .await
        {
            tracing::error!(message = "Failed to delete factor from lookup table after failed backup creation.", error = ?e);
        }
        if let Err(e) = factor_lookup
            .delete(FactorScope::Sync, &initial_sync_factor_to_lookup)
            .await
        {
            tracing::error!(message = "Failed to delete factor from lookup table after failed backup creation.", error = ?e);
        }
        return Err(e.into());
    }

    Ok(Json(CreateBackupResponse {
        backup_id: backup_metadata.id,
    }))
}
