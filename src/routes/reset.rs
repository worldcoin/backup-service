use std::sync::Arc;

use crate::backup_account::verify_backup_account_signature;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeContext, ChallengeManager};
use crate::error::ErrorResponse;
use crate::factor_lookup::FactorLookup;
use crate::redis_cache::RedisCacheManager;
use axum::http::StatusCode;
use axum::{Extension, Json};
use tracing::Instrument;
use types::{ErrorCode, ResetRequest};

/// Request to reset the entire backup using the `backup_account_id` keypair.
///
/// This endpoint is a disaster recovery mechanism, used when all main and sync factors are lost but
/// the user is still in posession of their raw data. In this situation, the user still has the secret
/// key corresponding to their `backup_account_id`. Upon success, the existing backup will be completely
/// removed and the user will be able to initialize a fresh new backup.
pub async fn handler(
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(challenge_manager): Extension<Arc<ChallengeManager>>,
    Extension(redis_cache_manager): Extension<Arc<RedisCacheManager>>,
    request: Json<ResetRequest>,
) -> Result<StatusCode, ErrorResponse> {
    // Step 1: Extract and validate the challenge token
    let (challenge_token_payload, challenge_context) = challenge_manager
        .extract_token_payload(
            crate::challenge_manager::ChallengeType::Keypair,
            request.challenge_token.clone(),
        )
        .await
        .map_err(ErrorResponse::from)?;

    // Step 2: Verify the challenge context matches the expected reset context
    let expected_context = ChallengeContext::Reset {
        backup_account_id: request.backup_account_id.clone(),
    };
    if challenge_context != expected_context {
        return Err(ErrorResponse::bad_request(
            ErrorCode::InvalidChallengeContext,
            "Challenge token was not created for reset operation or backup_account_id mismatch.",
        ));
    }

    // Step 3: Verify the signature against the challenge using the public key from `backup_account_id`
    verify_backup_account_signature(
        &request.backup_account_id,
        &request.signature,
        &challenge_token_payload,
    )?;

    // Step 4: Check if backup exists
    let backup_exists = backup_storage
        .does_backup_exist(&request.backup_account_id)
        .await
        .map_err(|_| ErrorResponse::internal_server_error())?;

    if !backup_exists {
        return Err(ErrorResponse::not_found());
    }

    let backup_id = request.backup_account_id.clone();
    let span = tracing::info_span!("reset_backup", backup_id = %backup_id);

    async move {
        // Step 5: Mark the challenge token as used (replay protection)
        redis_cache_manager
            .use_challenge_token(request.challenge_token.clone())
            .await
            .map_err(ErrorResponse::from)?;

        // Step 6: Delete the backup and metadata from S3
        backup_storage
            .delete_backup(&backup_id)
            .await
            .map_err(ErrorResponse::from)?;

        // Step 7: Delete all factors from FactorLookup (DynamoDB)
        factor_lookup
            .delete_all_by_backup_id(backup_id.clone())
            .await
            .map_err(ErrorResponse::from)?;

        Ok(StatusCode::NO_CONTENT)
    }
    .instrument(span)
    .await
}
