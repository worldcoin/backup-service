//! Module handling the "Backup Account Key". The public key is essentially the `backupAccountId`,
//! the private key is used for the break-glass `/reset` operation.
//!
//! Reference: <https://docs.toolsforhumanity.com/world-app/backup/advanced#disaster-recovery-via-/v1/reset>

use crate::error::ErrorResponse;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::EncodedPoint;
use types::ErrorCode;

pub const BACKUP_ACCOUNT_ID_PREFIX: &str = "backup_account_";

/// Length of a SEC.1 compressed `secp256k1` public key.
const COMPRESSED_PUBLIC_KEY_LEN: usize = 33;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum BackupAccountIdError {
    #[error("backup_account_id must start with the 'backup_account_' prefix")]
    MissingPrefix,
    #[error("backup_account_id contains invalid hex encoding")]
    InvalidHex,
    #[error("backup_account_id must contain exactly 33 bytes of compressed public key data")]
    InvalidLength,
    #[error("backup_account_id is not a valid compressed secp256k1 public key")]
    InvalidPublicKey,
}

impl From<BackupAccountIdError> for ErrorResponse {
    fn from(err: BackupAccountIdError) -> Self {
        ErrorResponse::bad_request(ErrorCode::InvalidBackupAccountId, &err.to_string())
    }
}

/// Checks the shape of a `backup_account_id`: prefix, hex encoding, and length.
///
/// Deliberately does not check that the bytes are a point on `secp256k1` for backwards compatibility.
///
/// # Errors
/// Returns a `BackupAccountIdError` if the ID is malformed.
fn check_backup_account_id_format(
    backup_account_id: &str,
) -> Result<Vec<u8>, BackupAccountIdError> {
    let compressed_hex = backup_account_id
        .strip_prefix(BACKUP_ACCOUNT_ID_PREFIX)
        .ok_or(BackupAccountIdError::MissingPrefix)?;

    let compressed_bytes =
        hex::decode(compressed_hex).map_err(|_| BackupAccountIdError::InvalidHex)?;

    if compressed_bytes.len() != COMPRESSED_PUBLIC_KEY_LEN {
        return Err(BackupAccountIdError::InvalidLength);
    }

    Ok(compressed_bytes)
}

/// Parses a `backup_account_id` into the `secp256k1` verifying key it encodes.
///
/// # Errors
/// Returns a `BackupAccountIdError` if the ID is malformed or does not encode a point on the
/// `secp256k1` curve.
pub fn parse_backup_account_id(
    backup_account_id: &str,
) -> Result<VerifyingKey, BackupAccountIdError> {
    let compressed_bytes = check_backup_account_id_format(backup_account_id)?;

    let encoded_point = EncodedPoint::from_bytes(&compressed_bytes)
        .map_err(|_| BackupAccountIdError::InvalidPublicKey)?;

    VerifyingKey::from_encoded_point(&encoded_point)
        .map_err(|_| BackupAccountIdError::InvalidPublicKey)
}

/// Verifies that `signature_base64` is a signature over `message` by the Backup Account Key that
/// `backup_account_id` encodes.
///
/// # Arguments
/// - `backup_account_id`: the claimed backup account ID, i.e. the public key.
/// - `signature_base64`: base64-encoded DER `secp256k1` ECDSA signature.
/// - `message`: the payload that was signed. Must come from a server-minted challenge.
///
/// # Errors
/// Returns a bad request `ErrorResponse` if the ID is malformed, the signature cannot be decoded,
/// or verification fails.
pub fn verify_backup_account_signature(
    backup_account_id: &str,
    signature_base64: &str,
    message: &[u8],
) -> Result<(), ErrorResponse> {
    let verifying_key = parse_backup_account_id(backup_account_id)?;

    let signature_bytes = STANDARD.decode(signature_base64).map_err(|_| {
        ErrorResponse::bad_request(
            ErrorCode::InvalidSignature,
            "Signature must be valid base64.",
        )
    })?;

    let signature = Signature::from_der(&signature_bytes).map_err(|_| {
        ErrorResponse::bad_request(
            ErrorCode::InvalidSignature,
            "Failed to parse signature as DER format.",
        )
    })?;

    verifying_key.verify(message, &signature).map_err(|_| {
        ErrorResponse::bad_request(
            ErrorCode::SignatureVerificationError,
            "Signature verification failed.",
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::Signer;
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::rand_core::OsRng;
    use k256::SecretKey;

    fn generate_backup_account() -> (SigningKey, String) {
        let signing_key = SigningKey::from(&SecretKey::random(&mut OsRng));
        let compressed_bytes = VerifyingKey::from(&signing_key)
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let backup_account_id = format!(
            "{BACKUP_ACCOUNT_ID_PREFIX}{}",
            hex::encode(&compressed_bytes)
        );

        (signing_key, backup_account_id)
    }

    fn sign(signing_key: &SigningKey, message: &[u8]) -> String {
        let signature: Signature = signing_key.sign(message);
        STANDARD.encode(signature.to_der())
    }

    #[test]
    fn test_verify_backup_account_signature_success() {
        let (signing_key, backup_account_id) = generate_backup_account();
        let message = b"test challenge";

        let result = verify_backup_account_signature(
            &backup_account_id,
            &sign(&signing_key, message),
            message,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_backup_account_signature_wrong_message() {
        let (signing_key, backup_account_id) = generate_backup_account();

        let result = verify_backup_account_signature(
            &backup_account_id,
            &sign(&signing_key, b"wrong challenge"),
            b"test challenge",
        );
        assert_eq!(
            result.unwrap_err().code(),
            &ErrorCode::SignatureVerificationError,
            "a signature over other bytes must not verify"
        );
    }

    #[test]
    fn test_verify_backup_account_signature_wrong_key() {
        let (signing_key, _) = generate_backup_account();
        let (_, other_backup_account_id) = generate_backup_account();
        let message = b"test challenge";

        let result = verify_backup_account_signature(
            &other_backup_account_id,
            &sign(&signing_key, message),
            message,
        );
        assert_eq!(
            result.unwrap_err().code(),
            &ErrorCode::SignatureVerificationError
        );
    }

    #[test]
    fn test_verify_backup_account_signature_invalid_signature_encoding() {
        let (_, backup_account_id) = generate_backup_account();

        let result = verify_backup_account_signature(&backup_account_id, "not base64!", b"test");
        assert_eq!(result.unwrap_err().code(), &ErrorCode::InvalidSignature);

        // Valid base64, but not a DER signature.
        let result = verify_backup_account_signature(&backup_account_id, "dGVzdA==", b"test");
        assert_eq!(result.unwrap_err().code(), &ErrorCode::InvalidSignature);
    }

    #[test]
    fn test_parse_backup_account_id_rejects_malformed_ids() {
        assert_eq!(
            parse_backup_account_id("invalid_format").unwrap_err(),
            BackupAccountIdError::MissingPrefix
        );
        assert_eq!(
            parse_backup_account_id("backup_account_GGGG").unwrap_err(),
            BackupAccountIdError::InvalidHex
        );
        assert_eq!(
            parse_backup_account_id(&format!(
                "{BACKUP_ACCOUNT_ID_PREFIX}{}",
                hex::encode([3u8; 32])
            ))
            .unwrap_err(),
            BackupAccountIdError::InvalidLength
        );
    }

    /// An off-curve ID passes the wire-level format check that `types` applies, so that clients
    /// already in the field keep working on paths that never touch the key. It still cannot pass a
    /// signature check, which is the only place ownership is decided.
    #[test]
    fn test_off_curve_id_is_well_formed_but_unusable() {
        let id = format!("{BACKUP_ACCOUNT_ID_PREFIX}03{}", hex::encode([0u8; 32]));

        assert!(check_backup_account_id_format(&id).is_ok());
        assert_eq!(
            parse_backup_account_id(&id).unwrap_err(),
            BackupAccountIdError::InvalidPublicKey
        );
        assert_eq!(
            verify_backup_account_signature(&id, "dGVzdA==", b"test")
                .unwrap_err()
                .code(),
            &ErrorCode::InvalidBackupAccountId
        );
    }

    #[test]
    fn test_parse_backup_account_id_rejects_off_curve_key() {
        let mut off_curve = [0u8; COMPRESSED_PUBLIC_KEY_LEN];
        off_curve[0] = 0x03;
        let id = format!("{BACKUP_ACCOUNT_ID_PREFIX}{}", hex::encode(off_curve));

        assert_eq!(
            parse_backup_account_id(&id).unwrap_err(),
            BackupAccountIdError::InvalidPublicKey
        );
    }
}
