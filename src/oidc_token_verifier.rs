use crate::dynamo_cache::{DynamoCacheError, DynamoCacheManager};
use crate::oidc_nonce_verifier::OidcNonceVerifier;
use crate::types::{Environment, OidcToken};
use chrono::{DateTime, Utc};
use openidconnect::core::CoreGenderClaim;
use openidconnect::core::{CoreIdToken, CoreIdTokenVerifier, CoreJsonWebKeySet};
use openidconnect::reqwest;
use openidconnect::{EmptyAdditionalClaims, IdTokenClaims};
use std::str::FromStr;
use std::sync::Arc;

/// Verifier for OIDC tokens.
///
/// Downloads the public keys from the OIDC provider and verifies the token, returning the claims.
#[derive(Debug, Clone)]
pub struct OidcTokenVerifier {
    environment: Environment,
    dynamo_cache_manager: Arc<DynamoCacheManager>,
    reqwest_client: reqwest::Client,
}

impl OidcTokenVerifier {
    pub fn new(environment: Environment, dynamo_cache_manager: Arc<DynamoCacheManager>) -> Self {
        OidcTokenVerifier {
            environment,
            dynamo_cache_manager,
            reqwest_client: reqwest::Client::new(),
        }
    }

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
        };

        // Step 2:Load the public keys from the OIDC provider
        // TODO/FIXME: Cache the keys
        let signature_keys = CoreJsonWebKeySet::fetch_async(&jwk_set_url, &self.reqwest_client)
            .await
            .map_err(|err| {
                tracing::error!(message = "Failed to fetch JWK set", err = ?err);
                OidcTokenVerifierError::JwkSetFetchError
            })?;

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

        self.dynamo_cache_manager
            .use_challenge_token(format!("oidc:{nonce}"))
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
    DynamoCacheError(#[from] DynamoCacheError),
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
    use std::time::Duration;

    use super::*;
    use crate::mock_oidc_server::MockOidcServer;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::SecretKey;

    async fn get_dynamo_cache_manager() -> Arc<DynamoCacheManager> {
        let environment = Environment::development(None);
        let aws_config = environment.aws_config().await;
        let dynamodb_client = Arc::new(aws_sdk_dynamodb::Client::new(&aws_config));
        Arc::new(DynamoCacheManager::new(
            environment,
            Duration::from_secs(60 * 60 * 24),
            dynamodb_client,
        ))
    }

    #[tokio::test]
    async fn test_verify_valid_token() {
        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());

        let verifier = OidcTokenVerifier::new(environment, get_dynamo_cache_manager().await);

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

        let verifier = OidcTokenVerifier::new(environment, get_dynamo_cache_manager().await);

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

        let verifier = OidcTokenVerifier::new(environment, get_dynamo_cache_manager().await);

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

        let verifier = OidcTokenVerifier::new(environment, get_dynamo_cache_manager().await);

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

        let verifier = OidcTokenVerifier::new(environment, get_dynamo_cache_manager().await);

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

        let verifier = OidcTokenVerifier::new(environment, get_dynamo_cache_manager().await);

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

        let verifier = OidcTokenVerifier::new(environment, get_dynamo_cache_manager().await);

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
