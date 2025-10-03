use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openidconnect::{Nonce, NonceVerifier};
use p256::ecdsa::VerifyingKey;
use sha2::Digest;

/// OIDC tokens that users are passing to the backup-service should have `nonce` field equal
/// to hash of a public key that signs a `backup-service` challenge. In addition to that, the same
/// OIDC token and session keypair is used for authentication with Turnkey — so the way public key
/// is embedded in the nonce has to be compatible with Turnkey specification. Without compatibility
/// here, user would have to request two OIDC tokens — one for backup-service and one for Turnkey.
///
/// This verifier checks the nonce in the token against the expected public key. Caller is expected
/// to verify the ownership of `expected_public_key_base64` before / after using this verifier.
#[derive(Debug, Clone, Default)]
pub struct OidcNonceVerifier {
    /// Key that should be hashed in the nonce according to Turnkey specification:
    /// <https://docs.turnkey.com/authentication/social-logins#nonce-restrictions-in-oidc-tokens>.
    /// Public keys are usually represented in base64 format in our API.
    pub expected_public_key_sec1_base64: String,
}

impl OidcNonceVerifier {
    /// Creates a new `OidcNonceVerifier` with the expected public key.
    #[must_use]
    pub fn new(expected_public_key_sec1_base64: String) -> Self {
        OidcNonceVerifier {
            expected_public_key_sec1_base64,
        }
    }
}

impl NonceVerifier for OidcNonceVerifier {
    /// Verifies the nonce against the expected public key.
    ///
    /// Note this only verifies validity. It does not track used nonces (this is done in
    /// `oidc_token_verifier.rs`).
    fn verify(self, nonce: Option<&Nonce>) -> Result<(), String> {
        let expected_nonce = public_key_sec1_base64_to_expected_turnkey_nonce(
            &self.expected_public_key_sec1_base64,
        )?;

        if let Some(nonce) = nonce {
            if nonce.secret() == &expected_nonce {
                Ok(())
            } else {
                Err(format!(
                    "Nonce mismatch: expected {}, got {}",
                    // value of a nonce is derived from public key, so it's not actually secret
                    expected_nonce,
                    nonce.secret()
                ))
            }
        } else {
            Err("Nonce is required for OIDC verification".to_string())
        }
    }
}

/// Converts a public key in SEC1 uncompressed format (encoded base64) to the expected
/// Turnkey OIDC nonce.
/// <https://docs.turnkey.com/authentication/social-logins#nonce-restrictions-in-oidc-tokens>
///
/// Uses `String` as an error type for compatibility with `NonceVerifier` trait.
///
/// # Errors
/// - Returns an error if the public key is not valid base64.
/// - Returns an error if the public key is not the right length for a P256 uncompressed public key.
pub fn public_key_sec1_base64_to_expected_turnkey_nonce(
    public_key_sec1_base64: &str,
) -> Result<String, String> {
    let public_key_bytes = STANDARD
        .decode(public_key_sec1_base64)
        .map_err(|_| "Invalid public key base64".to_string())?;
    if public_key_bytes.len() != 65 {
        return Err("P256 in SEC1 uncompressed public key must be 65 bytes long".to_string());
    }
    let public_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
        .map_err(|_| "Invalid public key".to_string())?;
    let public_key_hex = hex::encode(public_key.to_encoded_point(true)); // Turnkey expects a compressed point

    // Nonce should be equal to sha256 hash of the public key in hex format (as a string)
    let mut hasher = sha2::Sha256::new();
    hasher.update(public_key_hex.as_bytes());
    let nonce_value = hex::encode(hasher.finalize());

    Ok(nonce_value)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ref: https://docs.turnkey.com/authentication/social-logins#nonce-restrictions-in-oidc-tokens
    #[test]
    fn test_oidc_nonce_verifier_docs_example() {
        // Usually specified as base64 in our API, but here keeping it consistent with the example in the docs.
        let public_key_as_hex =
            "0394e549c71fa99dd5cf752fba623090be314949b74e4cdf7ca72031dd638e281a";
        let correct_nonce = Nonce::new(
            "1663bba492a323085b13895634a3618792c4ec6896f3c34ef3c26396df22ef82".to_string(),
        );
        let incorrect_nonce = Nonce::new(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        );

        let public_key_bytes = hex::decode(public_key_as_hex).expect("Valid hex string");
        let public_key = VerifyingKey::from_sec1_bytes(&public_key_bytes).unwrap();
        let public_key_base64 = STANDARD.encode(public_key.to_sec1_bytes());
        let verifier = OidcNonceVerifier {
            expected_public_key_sec1_base64: public_key_base64,
        };
        assert!(verifier.clone().verify(Some(&correct_nonce)).is_ok());
        assert_eq!(
            verifier
                .clone()
                .verify(Some(&incorrect_nonce))
                .unwrap_err()
                .to_string(),
            "Nonce mismatch: expected 1663bba492a323085b13895634a3618792c4ec6896f3c34ef3c26396df22ef82, got 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
        assert_eq!(
            verifier.clone().verify(None).unwrap_err(),
            "Nonce is required for OIDC verification".to_string()
        );
    }
}
