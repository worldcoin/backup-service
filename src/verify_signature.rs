use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::VerifyingKey;

/// Verifies a signature using the provided public key. Returns `Ok(())` if the
/// signature is valid, or an error if it is not.
///
/// # Arguments
/// - `public_key`: The public key in base64-encoded SEC1 format.
/// - `signature`: The signature in base64-encoded DER format.
/// - `trusted_payload`: The payload that was signed. This should be passed from a trusted source,
///    not user input. In some cases, this maybe user input, but server verified (e.g. timestamp
///    of a signature).
///
/// # Errors
/// - `Base64DecodeError`: If the public key or signature cannot be decoded from base64.
/// - `DecodeVerifyingKeyError`: If the verifying key cannot be created from the public key.
/// - `DecodeSignatureError`: If the signature cannot be created from the DER bytes.
pub fn verify_signature(
    public_key: &str,
    signature: &str,
    trusted_payload: &[u8],
) -> Result<(), VerifySignatureError> {
    if public_key.is_empty() || signature.is_empty() || trusted_payload.is_empty() {
        return Err(VerifySignatureError::EmptyArgumentError);
    }

    // Decode the verifying key from base64
    let public_key = STANDARD.decode(public_key)?;
    // Check if the public key is of the expected length (65 bytes for P-256)
    if public_key.len() != 65 {
        return Err(VerifySignatureError::DecodeVerifyingKeyError);
    }
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key)
        .map_err(|_| VerifySignatureError::DecodeVerifyingKeyError)?;

    // Decode the signature from base64
    let signature = STANDARD.decode(signature)?;
    // Check if the signature is between 70 and 72 bytes (DER format)
    if signature.len() < 70 || signature.len() > 72 {
        return Err(VerifySignatureError::DecodeSignatureError(format!(
            "Invalid signature length. Received {} bytes",
            signature.len()
        )));
    }
    let signature = p256::ecdsa::Signature::from_der(&signature)
        .map_err(|e| VerifySignatureError::DecodeSignatureError(e.to_string()))?;

    // Verify the signature
    verifying_key
        .verify(trusted_payload, &signature)
        .map_err(|_| VerifySignatureError::SignatureVerificationError)?;

    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub enum VerifySignatureError {
    #[error("Public key, signature or trusted payload is empty")]
    EmptyArgumentError,
    #[error("Failed to decode a value from base64: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Failed to create verifying key from SEC1 bytes")]
    DecodeVerifyingKeyError,
    #[error("Failed to create signature from DER bytes: {0}")]
    DecodeSignatureError(String),
    #[error("Signature verification failed")]
    SignatureVerificationError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::SecretKey;
    use rand::rngs::OsRng;

    fn generate_test_keypair() -> (SigningKey, VerifyingKey) {
        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(secret_key);
        let verifying_key = VerifyingKey::from(&signing_key);

        (signing_key, verifying_key)
    }

    fn sign_payload(signing_key: &SigningKey, payload: &[u8]) -> Signature {
        signing_key.sign(payload)
    }

    #[test]
    fn test_valid_signature() {
        let payload = b"test payload";

        // Generate a keypair and sign the payload
        let (signing_key, verifying_key) = generate_test_keypair();
        let signature = sign_payload(&signing_key, payload);

        // Encode the public key and signature in the expected format
        let public_key_bytes = verifying_key.to_sec1_bytes();
        let public_key_base64 = STANDARD.encode(public_key_bytes);

        let signature_der = signature.to_der();
        let signature_base64 = STANDARD.encode(signature_der);

        // Verify the signature
        let result = verify_signature(&public_key_base64, &signature_base64, payload);

        assert!(result.is_ok());

        // Should fail with an invalid payload
        let invalid_payload = b"invalid payload";
        let result = verify_signature(&public_key_base64, &signature_base64, invalid_payload);
        assert!(result.is_err());
        match result {
            Err(VerifySignatureError::SignatureVerificationError) => {}
            _ => panic!("Expected SignatureVerificationError"),
        }
    }

    #[test]
    fn test_invalid_signature() {
        let payload = b"test payload";

        // Generate two different keypairs
        let (signing_key1, _) = generate_test_keypair();
        let (_, verifying_key2) = generate_test_keypair();

        // Sign the payload with the first key
        let signature = sign_payload(&signing_key1, payload);

        // Encode the second public key and the signature in the expected format
        let public_key_bytes = verifying_key2.to_sec1_bytes();
        let public_key_base64 = STANDARD.encode(public_key_bytes);

        let signature_der = signature.to_der();
        let signature_base64 = STANDARD.encode(signature_der);

        // Try to verify the signature using a different public key than the one that signed it
        let result = verify_signature(&public_key_base64, &signature_base64, payload);

        // Verification should fail
        assert!(result.is_err());
        match result {
            Err(VerifySignatureError::SignatureVerificationError) => {}
            _ => panic!("Expected SignatureVerificationError"),
        }
    }
}
