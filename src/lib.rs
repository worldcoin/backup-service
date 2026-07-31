#![deny(clippy::all, dead_code, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::default_trait_access)]
pub mod attestation_gateway;
pub mod auth;
pub mod backup_storage;
pub mod challenge_manager;
pub mod factor_lookup;
pub mod headers;
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

    // Take the first two characters (not bytes) so multibyte UTF-8 local parts,
    // don't cause a mid-character slice panic.
    let mut chars = local_part.chars();
    let prefix: String = chars.by_ref().take(2).collect();
    if chars.next().is_none() {
        // Local part is two characters or fewer; nothing to mask.
        return Some(email.to_string());
    }

    Some(format!("{prefix}***@{domain_part}"))
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
    Ok(s.to_lowercase())
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

    #[test]
    fn test_mask_email_multibyte_does_not_panic() {
        // multibyte characters do not get sliced
        assert_eq!(
            mask_email("😀🎉rest@gmail.com"),
            Some("😀🎉***@gmail.com".to_string())
        );
        assert_eq!(
            mask_email("ébcd@gmail.com"),
            Some("éb***@gmail.com".to_string())
        );
        // two or less characters are returned as-is
        assert_eq!(mask_email("é@gmail.com"), Some("é@gmail.com".to_string()));
        assert_eq!(mask_email("😀@gmail.com"), Some("😀@gmail.com".to_string()));
    }
}
