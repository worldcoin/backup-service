use crate::oidc_nonce_verifier::OidcNonceVerifier;
use crate::redis_cache::{RedisCacheError, RedisCacheManager};
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

const TTL: Duration = Duration::from_secs(60 * 60); // 1h
const STALE_AFTER: Duration = Duration::from_secs(60); // 1min

type JwkCacheEntry = (Arc<CoreJsonWebKeySet>, Instant);
type JwkCache = Arc<RwLock<HashMap<JsonWebKeySetUrl, JwkCacheEntry>>>;

/// Verifier for OIDC tokens.
///
/// Downloads the public keys from the OIDC provider and verifies the token, returning the claims.
#[derive(Clone)]
pub struct OidcTokenVerifier {
    environment: Environment,
    redis_cache_manager: Arc<RedisCacheManager>,
    reqwest_client: reqwest::Client,
    cached_keys: JwkCache,
}

impl OidcTokenVerifier {
    pub fn new(environment: Environment, redis_cache_manager: Arc<RedisCacheManager>) -> Self {
        OidcTokenVerifier {
            environment,
            redis_cache_manager,
            reqwest_client: reqwest::Client::new(),
            cached_keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // TODO Add a guard if this service becomes heavily used. This implementation does not protect against cache stampedes under high loads.
    /// Fetches the JWK Set from the OIDC provider's well known URL.
    async fn fetch_remote_jwk_set(
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
                        let _ = this.fetch_remote_jwk_set(&url).await;
                    });
                }
                return Ok(keys);
            }
        }
        // Cache miss
        self.fetch_remote_jwk_set(jwk_set_url).await
    }

    /// Verifies an OIDC token. It also ensures that the nonce has not been used before.
    ///
    /// # Errors
    /// - `OidcTokenVerifierError`s will be raised if the token is not valid or the nonce has been used before.
    pub async fn verify_token(
        &self,
        token: &OidcToken,
        expected_public_key_sec1_base64: String,
    ) -> Result<IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>, OidcTokenVerifierError> {
        // Step 1: Extract the token and other parameters based on the OIDC provider
        let (oidc_token, jwk_set_url, client_id, issuer_url) = match token {
            OidcToken::Google { token } => (
                token,
                self.environment.google_jwk_set_url(),
                self.environment.google_client_id(),
                self.environment.google_issuer_url(),
            ),
            OidcToken::Apple { token } => (
                token,
                self.environment.apple_jwk_set_url(),
                self.environment.apple_client_id(),
                self.environment.apple_issuer_url(),
            ),
        };

        // Load the public keys from the OIDC provider
        let signature_keys = self.get_jwk_set(&jwk_set_url).await?.as_ref().clone();

        // Step 3: Create the token verifier
        let token_verifier =
            CoreIdTokenVerifier::new_public_client(client_id, issuer_url, signature_keys)
                .set_issue_time_verifier_fn(issue_time_verifier);

        // Step 4: Verify the token and extract claims
        let oidc_token = CoreIdToken::from_str(oidc_token).map_err(|err| {
            tracing::warn!(message = "Failed to parse OIDC token", err = ?err);
            OidcTokenVerifierError::TokenParseError
        })?;

        // Step 5: Verify the nonce and extract the claims
        let claims = oidc_token
            .claims(
                &token_verifier,
                OidcNonceVerifier::new(expected_public_key_sec1_base64),
            )
            .map_err(|err| {
                tracing::error!(message = "Token verification error", err = ?err);
                OidcTokenVerifierError::TokenVerificationError
            })?;

        // Step 6: Track the nonce to prevent replays
        let nonce = claims
            .nonce()
            .ok_or(OidcTokenVerifierError::MissingNonce)?
            .secret();

        self.redis_cache_manager
            .use_oidc_nonce(nonce, &token.into())
            .await?;

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
    #[error("OIDC token is missing nonce claim")]
    MissingNonce,
    #[error(transparent)]
    RedisCacheError(#[from] RedisCacheError),
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
    use crate::types::OidcProvider;
    use backup_service_test_utils::{MockOidcProvider, MockOidcServer};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::SecretKey;

    impl From<OidcProvider> for &MockOidcProvider {
        fn from(provider: OidcProvider) -> Self {
            match provider {
                OidcProvider::Google => &MockOidcProvider::Google,
                OidcProvider::Apple => &MockOidcProvider::Apple,
            }
        }
    }

    async fn get_redis_cache_manager() -> Arc<RedisCacheManager> {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::development(None);
        Arc::new(
            RedisCacheManager::new(environment, environment.cache_default_ttl())
                .await
                .unwrap(),
        )
    }

    async fn verify_token_for_provider(
        verifier: &OidcTokenVerifier,
        provider: OidcProvider,
        token: String,
        public_key: String,
    ) -> Result<IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>, OidcTokenVerifierError> {
        match provider {
            OidcProvider::Google => {
                verifier
                    .verify_token(&OidcToken::Google { token }, public_key)
                    .await
            }
            OidcProvider::Apple => {
                verifier
                    .verify_token(&OidcToken::Apple { token }, public_key)
                    .await
            }
        }
    }

    #[tokio::test]
    async fn test_verify_valid_token() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());

        let verifier = OidcTokenVerifier::new(environment, get_redis_cache_manager().await);

        // Test both Google and Apple OIDC tokens
        for provider in [OidcProvider::Google, OidcProvider::Apple] {
            // Generate a valid token
            let token = oidc_server.generate_token(provider.into(), None, &public_key);

            // Verify the token
            let result =
                verify_token_for_provider(&verifier, provider, token, public_key.clone()).await;

            // The test should pass with a valid token
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_verify_expired_token() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());

        let verifier = OidcTokenVerifier::new(environment, get_redis_cache_manager().await);

        // Test both Google and Apple OIDC tokens
        for provider in [OidcProvider::Google, OidcProvider::Apple] {
            // Generate an expired token
            let token = oidc_server.generate_expired_token(provider.into());

            // Verify the token
            let result =
                verify_token_for_provider(&verifier, provider, token, public_key.clone()).await;

            // The test should fail with an expired token
            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(OidcTokenVerifierError::TokenVerificationError)
            ));
        }
    }

    #[tokio::test]
    async fn test_verify_incorrectly_signed_token() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());

        let verifier = OidcTokenVerifier::new(environment, get_redis_cache_manager().await);

        // Test both Google and Apple OIDC tokens
        for provider in [OidcProvider::Google, OidcProvider::Apple] {
            // Generate an incorrectly signed token
            let token = oidc_server.generate_incorrectly_signed_token(provider.into());

            // Verify the token
            let result =
                verify_token_for_provider(&verifier, provider, token, public_key.clone()).await;

            // The test should fail with an incorrectly signed token
            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(OidcTokenVerifierError::TokenVerificationError)
            ));
        }
    }

    #[tokio::test]
    async fn test_verify_token_with_incorrect_issuer() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());

        let verifier = OidcTokenVerifier::new(environment, get_redis_cache_manager().await);

        // Test both Google and Apple OIDC tokens
        for provider in [OidcProvider::Google, OidcProvider::Apple] {
            // Generate a token with incorrect issuer
            let token = oidc_server.generate_token_with_incorrect_issuer(provider.into());

            // Verify the token
            let result =
                verify_token_for_provider(&verifier, provider, token, public_key.clone()).await;

            // The test should fail with an incorrect issuer
            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(OidcTokenVerifierError::TokenVerificationError)
            ));
        }
    }

    #[tokio::test]
    async fn test_verify_token_with_incorrect_audience() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());

        let verifier = OidcTokenVerifier::new(environment, get_redis_cache_manager().await);

        // Test both Google and Apple OIDC tokens
        for provider in [OidcProvider::Google, OidcProvider::Apple] {
            // Generate a token with incorrect audience
            let token = oidc_server.generate_token_with_incorrect_audience(provider.into());

            // Verify the token
            let result =
                verify_token_for_provider(&verifier, provider, token, public_key.clone()).await;

            // The test should fail with an incorrect audience
            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(OidcTokenVerifierError::TokenVerificationError)
            ));
        }
    }

    #[tokio::test]
    async fn test_verify_token_with_incorrect_issued_at() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());

        let verifier = OidcTokenVerifier::new(environment, get_redis_cache_manager().await);

        // Test both Google and Apple OIDC tokens
        for provider in [OidcProvider::Google, OidcProvider::Apple] {
            // Generate a token with incorrect issued_at
            let token = oidc_server.generate_token_with_incorrect_issued_at(provider.into());

            // Verify the token
            let result =
                verify_token_for_provider(&verifier, provider, token, public_key.clone()).await;

            // The test should fail with an incorrect issued_at
            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(OidcTokenVerifierError::TokenVerificationError)
            ));
        }
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

        let verifier = OidcTokenVerifier::new(environment, get_redis_cache_manager().await);

        // Test both Google and Apple OIDC tokens
        for provider in [OidcProvider::Google, OidcProvider::Apple] {
            // Generate a token with the correct public key
            let token = oidc_server.generate_token(provider.into(), None, &correct_public_key);

            // Verify the token but pass a different public key
            let result =
                verify_token_for_provider(&verifier, provider, token, incorrect_public_key.clone())
                    .await;

            // The test should fail with an incorrect public key
            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(OidcTokenVerifierError::TokenVerificationError)
            ));
        }
    }

    #[tokio::test]
    async fn test_verify_replay_attack_fails() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());

        let verifier = OidcTokenVerifier::new(environment, get_redis_cache_manager().await);

        let token = oidc_server.generate_token(OidcProvider::Google.into(), None, &public_key);
        let _ = verify_token_for_provider(
            &verifier,
            OidcProvider::Google,
            token.clone(),
            public_key.clone(),
        )
        .await
        .unwrap(); // The first time is successful

        // The second time fails because the nonce is already used
        let result = verify_token_for_provider(
            &verifier,
            OidcProvider::Google,
            token.clone(),
            public_key.clone(),
        )
        .await;
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(OidcTokenVerifierError::RedisCacheError(
                RedisCacheError::AlreadyUsed
            ))
        ));

        // Even if we generate a new token with the same nonce, it still fails
        let new_token = oidc_server.generate_token(OidcProvider::Google.into(), None, &public_key);

        assert_ne!(token, new_token);
        let result =
            verify_token_for_provider(&verifier, OidcProvider::Google, token, public_key.clone())
                .await;
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(OidcTokenVerifierError::RedisCacheError(
                RedisCacheError::AlreadyUsed
            ))
        ));
    }
}
