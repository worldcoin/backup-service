use std::sync::Arc;

use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeContext, ChallengeManager};
use crate::factor_lookup::FactorLookup;
use crate::redis_cache::RedisCacheManager;
use crate::types::ErrorResponse;
use crate::validate_backup_account_id;
use axum::http::StatusCode;
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::EncodedPoint;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::Instrument;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResetRequest {
    #[serde(deserialize_with = "validate_backup_account_id")]
    backup_account_id: String,
    /// Base64-encoded DER signature
    signature: String,
    challenge_token: String,
}

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
            "invalid_challenge_context",
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

/// Extracts the public key from a `backup_account_id` and verifies a signature on a given message.
fn verify_backup_account_signature(
    backup_account_id: &str,
    signature_base64: &str,
    message: &[u8],
) -> Result<(), ErrorResponse> {
    // Extract the hex-encoded compressed public key from backup_account_id
    let compressed_hex = backup_account_id
        .strip_prefix("backup_account_")
        .ok_or_else(|| {
            ErrorResponse::bad_request(
                "invalid_backup_account_id",
                "backup_account_id must start with 'backup_account_' prefix.",
            )
        })?;

    // Decode the hex to get compressed SEC1 bytes (33 bytes)
    let compressed_bytes = hex::decode(compressed_hex).map_err(|_| {
        ErrorResponse::bad_request(
            "invalid_backup_account_id",
            "backup_account_id contains invalid hex encoding.",
        )
    })?;

    if compressed_bytes.len() != 33 {
        return Err(ErrorResponse::bad_request(
            "invalid_backup_account_id",
            "backup_account_id must contain exactly 33 bytes of compressed public key data.",
        ));
    }

    // Parse the compressed SEC1 public key
    let encoded_point = EncodedPoint::from_bytes(&compressed_bytes).map_err(|_| {
        ErrorResponse::bad_request(
            "invalid_backup_account_id",
            "Failed to parse compressed public key from backup_account_id.",
        )
    })?;

    let verifying_key = VerifyingKey::from_encoded_point(&encoded_point).map_err(|_| {
        ErrorResponse::bad_request(
            "invalid_backup_account_id",
            "Failed to create verifying key from backup_account_id.",
        )
    })?;

    // Decode the base64 signature
    let signature_bytes = STANDARD.decode(signature_base64).map_err(|_| {
        ErrorResponse::bad_request("invalid_signature", "Signature must be valid base64.")
    })?;

    // Parse DER signature
    let signature = Signature::from_der(&signature_bytes).map_err(|_| {
        ErrorResponse::bad_request(
            "invalid_signature",
            "Failed to parse signature as DER format.",
        )
    })?;

    // Verify the signature
    verifying_key.verify(message, &signature).map_err(|_| {
        ErrorResponse::bad_request(
            "signature_verification_error",
            "Signature verification failed.",
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::SecretKey;

    #[test]
    fn test_verify_backup_account_signature_success() {
        // Generate a test keypair
        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(&secret_key);
        let verifying_key = VerifyingKey::from(&signing_key);

        // Create backup_account_id from compressed public key
        let compressed_bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();
        let backup_account_id = format!("backup_account_{}", hex::encode(&compressed_bytes));

        // Sign a message
        let message = b"test challenge";
        let signature: Signature = signing_key.sign(message);
        let signature_base64 = STANDARD.encode(signature.to_der());

        // Should succeed
        let result =
            verify_backup_account_signature(&backup_account_id, &signature_base64, message);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_backup_account_signature_wrong_signature() {
        // Generate a test keypair
        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(&secret_key);
        let verifying_key = VerifyingKey::from(&signing_key);

        // Create backup_account_id from compressed public key
        let compressed_bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();
        let backup_account_id = format!("backup_account_{}", hex::encode(&compressed_bytes));

        // Sign a different message
        let message = b"test challenge";
        let wrong_message = b"wrong challenge";
        let signature: Signature = signing_key.sign(wrong_message);
        let signature_base64 = STANDARD.encode(signature.to_der());

        // Should fail
        let result =
            verify_backup_account_signature(&backup_account_id, &signature_base64, message);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_backup_account_signature_invalid_backup_account_id() {
        let result = verify_backup_account_signature("invalid_format", "dGVzdA==", b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_backup_account_signature_invalid_hex() {
        let result = verify_backup_account_signature("backup_account_GGGG", "dGVzdA==", b"test");
        assert!(result.is_err());
    }
}
