use crate::oidc_nonce_verifier::OidcNonceVerifier;
use crate::types::{Environment, OidcToken};
use chrono::{DateTime, Utc};
use openidconnect::core::CoreGenderClaim;
use openidconnect::core::{CoreIdToken, CoreIdTokenVerifier, CoreJsonWebKeySet};
use openidconnect::{reqwest, JsonWebKeySetUrl};
use openidconnect::{EmptyAdditionalClaims, IdTokenClaims};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::Instant;

// TODO make this a config?
const TTL: Duration = Duration::from_secs(60 * 60); // 1h
const STALE_AFTER: Duration = Duration::from_secs(60); // 1min

/// Verifier for OIDC tokens.
///
/// Downloads the public keys from the OIDC provider and verifies the token, returning the claims.
#[derive(Debug, Clone)]
pub struct OidcTokenVerifier {
    environment: Environment,
    reqwest_client: reqwest::Client,
    cached_keys: Arc<RwLock<HashMap<JsonWebKeySetUrl, (Arc<CoreJsonWebKeySet>, Instant)>>>,
}

impl OidcTokenVerifier {
    pub fn new(environment: Environment) -> Self {
        OidcTokenVerifier {
            environment,
            reqwest_client: reqwest::Client::new(),
            cached_keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // TODO Add a guard if this service becomes heavily used. This implementation does not protect against cache stampedes under high loads.
    async fn _get_jwk_set(
        &self,
        jwk_set_url: &JsonWebKeySetUrl,
    ) -> Result<Arc<CoreJsonWebKeySet>, OidcTokenVerifierError> {
        let fetched = CoreJsonWebKeySet::fetch_async(jwk_set_url, &self.reqwest_client)
            .await
            .map_err(|err| {
                tracing::error!(message = "Failed to fetch JWK set", err = ?err);
                OidcTokenVerifierError::JwkSetFetchError
            })?;

        let arc = Arc::new(fetched);
        // Store value
        {
            let mut cache = self.cached_keys.write().await;
            cache.insert(jwk_set_url.to_owned(), (arc.clone(), Instant::now()));
        }
        Ok(arc)
    }

    /// Retrieves the JWK Set for the given URL.
    ///
    /// First checks the in-memory cache. If the cached value exists and is within
    /// the TTL, it is returned immediately. If the cached value is
    /// stale but not expired, it is returned and a background task is spawned to
    /// revalidate and refresh it. If the cache is missing or expired, the key set
    /// is fetched synchronously from the source.
    async fn get_jwk_set(
        &self,
        jwk_set_url: &JsonWebKeySetUrl,
    ) -> Result<Arc<CoreJsonWebKeySet>, OidcTokenVerifierError> {
        // Try cached value
        if let Some((keys, fetched_at)) = {
            let cache = self.cached_keys.read().await;
            cache.get(jwk_set_url).cloned()
        } {
            let age = fetched_at.elapsed();
            if age < TTL {
                // if keys are stale revalidate in a background process
                if age >= STALE_AFTER {
                    let url = jwk_set_url.clone();
                    let this = self.clone();
                    tokio::spawn(async move {
                        let _ = this._get_jwk_set(&url).await;
                    });
                }
                return Ok(keys);
            }
        }
        // Cache miss
        Ok(self._get_jwk_set(jwk_set_url).await?)
    }

    pub async fn verify_token(
        &self,
        token: &OidcToken,
        expected_public_key_sec1_base64: String,
    ) -> Result<IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>, OidcTokenVerifierError> {
        // Extract the token and other parameters based on the OIDC provider
        let (oidc_token, jwk_set_url, client_id, issuer_url) = match token {
            OidcToken::Google { token } => (
                token,
                self.environment.google_jwk_set_url(),
                self.environment.google_client_id(),
                self.environment.google_issuer_url(),
            ),
        };

        // Load the public keys from the OIDC provider
        let signature_keys = self.get_jwk_set(&jwk_set_url).await?.as_ref().clone();

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
            .claims(
                &token_verifier,
                OidcNonceVerifier::new(expected_public_key_sec1_base64),
            )
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
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::SecretKey;

    #[tokio::test]
    async fn test_verify_valid_token() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());

        let verifier = OidcTokenVerifier::new(environment);

        // Generate a valid token
        let token = oidc_server.generate_token(environment, None, &public_key);

        // Verify the token
        let result = verifier
            .verify_token(&OidcToken::Google { token }, public_key)
            .await;

        // The test should pass with a valid token
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_expired_token() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());

        let verifier = OidcTokenVerifier::new(environment);

        // Generate an expired token
        let token = oidc_server.generate_expired_token(environment);

        // Verify the token
        let result = verifier
            .verify_token(&OidcToken::Google { token }, public_key)
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
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());

        let verifier = OidcTokenVerifier::new(environment);

        // Generate an incorrectly signed token
        let token = oidc_server.generate_incorrectly_signed_token(environment);

        // Verify the token
        let result = verifier
            .verify_token(&OidcToken::Google { token }, public_key)
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
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());

        let verifier = OidcTokenVerifier::new(environment);

        // Generate a token with incorrect issuer
        let token = oidc_server.generate_token_with_incorrect_issuer(environment);

        // Verify the token
        let result = verifier
            .verify_token(&OidcToken::Google { token }, public_key)
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
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());

        let verifier = OidcTokenVerifier::new(environment);

        // Generate a token with incorrect audience
        let token = oidc_server.generate_token_with_incorrect_audience(environment);

        // Verify the token
        let result = verifier
            .verify_token(&OidcToken::Google { token }, public_key)
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
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());

        let verifier = OidcTokenVerifier::new(environment);

        // Generate a token with incorrect issued_at
        let token = oidc_server.generate_token_with_incorrect_issued_at(environment);

        // Verify the token
        let result = verifier
            .verify_token(&OidcToken::Google { token }, public_key)
            .await;

        // The test should fail with an incorrect issued_at
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(OidcTokenVerifierError::TokenVerificationError)
        ));
    }

    #[tokio::test]
    async fn test_verify_token_with_incorrect_public_key() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));

        // Generate a correct key pair for token generation
        let correct_secret_key = SecretKey::random(&mut OsRng);
        let correct_public_key = STANDARD.encode(correct_secret_key.public_key().to_sec1_bytes());

        // Generate a different key pair for verification
        let incorrect_secret_key = SecretKey::random(&mut OsRng);
        let incorrect_public_key =
            STANDARD.encode(incorrect_secret_key.public_key().to_sec1_bytes());

        let verifier = OidcTokenVerifier::new(environment);

        // Generate a token with the correct public key
        let token = oidc_server.generate_token(environment, None, &correct_public_key);

        // Verify the token but pass a different public key
        let result = verifier
            .verify_token(&OidcToken::Google { token }, incorrect_public_key)
            .await;

        // The test should fail with an incorrect public key
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(OidcTokenVerifierError::TokenVerificationError)
        ));
    }
}
