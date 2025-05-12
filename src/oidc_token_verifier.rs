use crate::oidc_nonce_verifier::OidcNonceVerifier;
use crate::types::{Environment, OidcPlatform, OidcToken};
use chrono::{DateTime, Utc};
use openidconnect::core::CoreGenderClaim;
use openidconnect::core::{CoreIdToken, CoreIdTokenVerifier, CoreJsonWebKeySet};
use openidconnect::reqwest;
use openidconnect::{EmptyAdditionalClaims, IdTokenClaims};
use std::str::FromStr;

/// Verifier for OIDC tokens.
///
/// Downloads the public keys from the OIDC provider and verifies the token, returning the claims.
#[derive(Debug, Clone)]
pub struct OidcTokenVerifier {
    environment: Environment,
    reqwest_client: reqwest::Client,
}

impl OidcTokenVerifier {
    pub fn new(environment: Environment) -> Self {
        OidcTokenVerifier {
            environment,
            reqwest_client: reqwest::Client::new(),
        }
    }

    pub async fn verify_token(
        &self,
        token: &OidcToken,
    ) -> Result<IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>, OidcTokenVerifierError> {
        // Extract the token and other parameters based on the OIDC provider
        let (oidc_token, jwk_set_url, client_id, issuer_url) = match token {
            OidcToken::Google { token, platform } => {
                let client_id = match platform {
                    Some(OidcPlatform::Android) => self.environment.google_client_id_android(),
                    Some(OidcPlatform::Ios) => self.environment.google_client_id_ios(),
                    // Android is used by default for compatibility reasons. TODO/FIXME: disallow None
                    None => self.environment.google_client_id_android(),
                };
                (
                    token,
                    self.environment.google_jwk_set_url(),
                    client_id,
                    self.environment.google_issuer_url(),
                )
            }
        };

        // Load the public keys from the OIDC provider
        // TODO/FIXME: Cache the keys
        let signature_keys = CoreJsonWebKeySet::fetch_async(&jwk_set_url, &self.reqwest_client)
            .await
            .map_err(|err| {
                tracing::error!(message = "Failed to fetch JWK set", err = ?err);
                OidcTokenVerifierError::JwkSetFetchError
            })?;

        // Create the token verifier
        let token_verifier =
            CoreIdTokenVerifier::new_public_client(client_id, issuer_url, signature_keys)
                .set_issue_time_verifier_fn(issue_time_verifier);

        // Verify the token and extract claims
        let oidc_token = CoreIdToken::from_str(oidc_token).map_err(|err| {
            tracing::warn!(message = "Failed to parse OIDC token", err = ?err);
            OidcTokenVerifierError::TokenParseError
        })?;

        let claims = oidc_token
            .claims(&token_verifier, OidcNonceVerifier::default())
            .map_err(|err| {
                tracing::error!(message = "Token verification error", err = ?err);
                OidcTokenVerifierError::TokenVerificationError
            })?;

        Ok(claims.clone())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum OidcTokenVerifierError {
    #[error("Failed to fetch JWK set from OIDC provider")]
    JwkSetFetchError,
    #[error("Failed to parse OIDC token")]
    TokenParseError,
    #[error("Failed to verify OIDC token")]
    TokenVerificationError,
}

/// If issued at is in the future or too far in the past, the token is invalid
fn issue_time_verifier(iat: DateTime<Utc>) -> Result<(), String> {
    let now = Utc::now();
    // Token should not be issued more than 5 minutes in the past
    let min = now - chrono::Duration::minutes(5);
    // Token should not be issued more than 30 seconds in the future (clock skew)
    let max = now + chrono::Duration::seconds(30);
    if iat < min || iat > max {
        return Err("Invalid issue time".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_oidc_server::MockOidcServer;

    #[tokio::test]
    async fn test_verify_valid_token() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));

        let verifier = OidcTokenVerifier::new(environment);

        // Generate a valid token
        let token = oidc_server.generate_token(environment, None);

        // Verify the token
        let result = verifier
            .verify_token(&OidcToken::Google {
                token,
                platform: None,
            })
            .await;

        // The test should pass with a valid token
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_expired_token() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));

        let verifier = OidcTokenVerifier::new(environment);

        // Generate an expired token
        let token = oidc_server.generate_expired_token(environment);

        // Verify the token
        let result = verifier
            .verify_token(&OidcToken::Google {
                token,
                platform: None,
            })
            .await;

        // The test should fail with an expired token
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(OidcTokenVerifierError::TokenVerificationError)
        ));
    }

    #[tokio::test]
    async fn test_verify_incorrectly_signed_token() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));

        let verifier = OidcTokenVerifier::new(environment);

        // Generate an incorrectly signed token
        let token = oidc_server.generate_incorrectly_signed_token(environment);

        // Verify the token
        let result = verifier
            .verify_token(&OidcToken::Google {
                token,
                platform: None,
            })
            .await;

        // The test should fail with an incorrectly signed token
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(OidcTokenVerifierError::TokenVerificationError)
        ));
    }

    #[tokio::test]
    async fn test_verify_token_with_incorrect_issuer() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));

        let verifier = OidcTokenVerifier::new(environment);

        // Generate a token with incorrect issuer
        let token = oidc_server.generate_token_with_incorrect_issuer(environment);

        // Verify the token
        let result = verifier
            .verify_token(&OidcToken::Google {
                token,
                platform: None,
            })
            .await;

        // The test should fail with an incorrect issuer
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(OidcTokenVerifierError::TokenVerificationError)
        ));
    }

    #[tokio::test]
    async fn test_verify_token_with_incorrect_audience() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));

        let verifier = OidcTokenVerifier::new(environment);

        // Generate a token with incorrect audience
        let token = oidc_server.generate_token_with_incorrect_audience(environment);

        // Verify the token
        let result = verifier
            .verify_token(&OidcToken::Google {
                token,
                platform: None,
            })
            .await;

        // The test should fail with an incorrect audience
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(OidcTokenVerifierError::TokenVerificationError)
        ));
    }

    #[tokio::test]
    async fn test_verify_token_with_incorrect_issued_at() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));

        let verifier = OidcTokenVerifier::new(environment);

        // Generate a token with incorrect issued_at
        let token = oidc_server.generate_token_with_incorrect_issued_at(environment);

        // Verify the token
        let result = verifier
            .verify_token(&OidcToken::Google {
                token,
                platform: None,
            })
            .await;

        // The test should fail with an incorrect issued_at
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(OidcTokenVerifierError::TokenVerificationError)
        ));
    }
}
