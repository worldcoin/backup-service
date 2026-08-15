pub mod attestation_gateway;
pub mod auth;
pub mod backup_metadata;
pub mod backup_storage;
pub mod challenge_manager;
pub mod environment;
pub mod error;
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
