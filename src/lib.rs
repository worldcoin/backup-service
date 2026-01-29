#![deny(clippy::all, dead_code, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::default_trait_access)]
pub mod attestation_gateway;
pub mod auth;
pub mod backup_storage;
pub mod challenge_manager;
pub mod factor_lookup;
pub mod kms_jwe;
pub mod middleware;
pub mod oidc_nonce_verifier;
pub mod oidc_token_verifier;
pub mod redis_cache;
pub mod routes;
pub mod server;
pub mod turnkey_activity;
pub mod types;
pub mod utils;
pub mod verify_signature;
pub mod webauthn;

pub use routes::handler;

/// Utility function to mask an email address with two first letters and full domain.
///
///
/// For example, "seva.zhidkov@toolsforhumanity.com" => "se***@toolsforhumanity.com"
/// If the email is not valid, it returns None.
#[must_use]
pub fn mask_email(email: &str) -> Option<String> {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return None;
    }
    let local_part = parts[0];
    let domain_part = parts[1];
    if local_part.is_empty() || domain_part.is_empty() {
        return None;
    }

    if local_part.len() <= 2 {
        return Some(email.to_string());
    }

    let masked_local_part = format!("{}***", &local_part[..2]);
    Some(format!("{masked_local_part}@{domain_part}"))
}

use serde::{de, Deserialize, Deserializer};

/// Deserializes a hex string into a byte array and verifies it's exactly 32 bytes long.
///
/// # Errors
///
/// Returns an error if the hex string is not a valid hex-encoded byte array
/// or if the hex string is not exactly 32 bytes long.
pub fn normalize_hex_32<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let s = s.trim_start_matches("0x");
    let bytes = hex::decode(s).map_err(de::Error::custom)?;
    if bytes.len() != 32 {
        return Err(de::Error::custom("Expected 32 bytes"));
    }
    Ok(s.to_string())
}

/// Deserializes a provided backup account ID and verifies it has the correct format.
///
/// # Errors
/// Returns an error if the provided value is not valid.
pub fn validate_backup_account_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if !s.starts_with("backup_account_") {
        return Err(de::Error::custom(
            "Invalid backup account ID. Missing expected prefix.",
        ));
    }
    let bytes = hex::decode(s.trim_start_matches("backup_account_")).map_err(de::Error::custom)?;
    // 33 bytes because we expect a SEC.1 compressed public key
    if bytes.len() != 33 {
        return Err(de::Error::custom(
            "Invalid backup account ID. Expected 33 bytes after the prefix.",
        ));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_email() {
        assert_eq!(
            mask_email("seva.zhidkov@toolsforhumanity.com"),
            Some("se***@toolsforhumanity.com".to_string())
        );
        assert_eq!(
            mask_email("example@gmail.com"),
            Some("ex***@gmail.com".to_string())
        );
        assert_eq!(mask_email("ex@gmail.com"), Some("ex@gmail.com".to_string()));
        assert_eq!(mask_email("e@gmail.com"), Some("e@gmail.com".to_string()));
        assert_eq!(mask_email("@gmail.com"), None);
        assert_eq!(mask_email("ex@"), None);
        assert_eq!(mask_email("@"), None);
    }
}
