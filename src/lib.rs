pub mod attestation_gateway;
pub mod auth;
pub mod axum_utils;
pub mod backup_storage;
pub mod challenge_manager;
pub mod dynamo_cache;
pub mod factor_lookup;
pub mod kms_jwe;
pub mod mock_oidc_server;
pub mod oidc_nonce_verifier;
pub mod oidc_token_verifier;
pub mod routes;
pub mod server;
pub mod turnkey_activity;
pub mod types;
pub mod verify_signature;
pub mod webauthn;

pub use routes::handler;

/// Utility function to mask an email address with two first letters and full domain.
/// For example, "seva.zhidkov@toolsforhumanity.com" => "se***@toolsforhumanity.com"
/// If the email is not valid, it returns None.
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
    Some(format!("{}@{}", masked_local_part, domain_part))
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
