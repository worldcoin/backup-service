#![allow(clippy::missing_panics_doc)] // this is module used for testing, panics are allowed and self-explanatory
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
    CoreRsaPrivateSigningKey,
};
use openidconnect::{
    Audience, EmptyAdditionalClaims, EndUserEmail, IssuerUrl, JsonWebKeyId, Nonce,
    PrivateSigningKey, StandardClaims, SubjectIdentifier,
};
use p256::ecdsa::VerifyingKey;
use rsa::RsaPrivateKey;
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub enum MockOidcProvider {
    Google,
    Apple,
}

impl MockOidcProvider {
    /// Note this matches the same client ID defined in the `Environment` struct (`src/types/environment.rs`)
    #[must_use]
    pub const fn as_client_id(&self) -> &'static str {
        match self {
            Self::Google => {
                "949370763172-0pu3c8c3rmp8ad665jsb1qkf8lai592i.apps.googleusercontent.com"
            }
            Self::Apple => "placeholder",
        }
    }

    #[must_use]
    pub fn as_issuer_url(&self) -> IssuerUrl {
        match self {
            Self::Google => IssuerUrl::new("https://accounts.google.com".to_string())
                .expect("Invalid issuer URL"),
            Self::Apple => {
                IssuerUrl::new("https://appleid.apple.com".to_string()).expect("Invalid issuer URL")
            }
        }
    }
}

/// Mock OIDC server for testing purposes. We have to expose it as a module, because it's used in
/// both integration and unit tests.
pub struct MockOidcServer {
    signing_key: CoreRsaPrivateSigningKey,
    pub server: mockito::ServerGuard,
    pub google_jwk_set_mock: mockito::Mock,
    pub apple_jwk_set_mock: mockito::Mock,
}

impl MockOidcServer {
    pub async fn new() -> Self {
        // Initialize signing key
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let signing_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let signing_key = CoreRsaPrivateSigningKey::from_pem(
            &signing_key.to_pkcs1_pem(LineEnding::default()).unwrap(),
            Some(JsonWebKeyId::new("key1".to_string())), // ID can be any string
        )
        .expect("Invalid RSA private key");

        // Create a JWK set with the signing key
        let jwk_set = CoreJsonWebKeySet::new(vec![signing_key.as_verification_key()]);

        // Set up the mock server with the JWK set
        let mut server = mockito::Server::new_async().await;

        // Set up Google JWK set endpoint
        let google_jwk_set_mock = server
            .mock("GET", "/oauth2/v3/certs")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&jwk_set).unwrap().as_bytes())
            .create();

        // Set up Apple JWK set endpoint
        let apple_jwk_set_mock = server
            .mock("GET", "/auth/keys")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&jwk_set).unwrap().as_bytes())
            .create();

        Self {
            signing_key,
            server,
            google_jwk_set_mock,
            apple_jwk_set_mock,
        }
    }

    pub fn port(&self) -> usize {
        self.server.socket_address().port() as usize
    }

    /// Generate a token for the specified provider
    pub fn generate_token(
        &self,
        provider: &MockOidcProvider,
        subject: Option<SubjectIdentifier>,
        public_key_sec1_base64: &str,
    ) -> String {
        let subject = subject.unwrap_or_else(|| SubjectIdentifier::new(Uuid::new_v4().to_string()));

        // convert public key to expected turnkey nonce
        // see `public_key_sec1_base64_to_expected_turnkey_nonce` for details.
        let public_key_bytes = STANDARD.decode(public_key_sec1_base64).unwrap();
        let public_key = VerifyingKey::from_sec1_bytes(&public_key_bytes).unwrap();
        let public_key_hex = hex::encode(public_key.to_encoded_point(true));
        let mut hasher = Sha256::new();
        hasher.update(public_key_hex.as_bytes());
        let nonce_value = hex::encode(hasher.finalize());

        // Initialize claims with subject and standard OIDC fields
        let claims: CoreIdTokenClaims = CoreIdTokenClaims::new(
            provider.as_issuer_url(),
            vec![Audience::new(provider.as_client_id().to_string())],
            Utc::now().checked_add_signed(Duration::hours(1)).unwrap(), // expiration time
            Utc::now(),                                                 // issued at
            StandardClaims::new(subject),
            EmptyAdditionalClaims {},
        )
        .set_nonce(Some(Nonce::new(nonce_value)))
        .set_email(Some(EndUserEmail::new("hello@example.com".to_string())));

        // Sign the claims with the private key
        let id_token = CoreIdToken::new(
            claims,
            &self.signing_key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256, // RS256, same as both providers
            None,
            None,
        )
        .expect("failed to create id_token");

        id_token.to_string()
    }

    /// Generate an expired token for the specified provider
    pub fn generate_expired_token(&self, provider: &MockOidcProvider) -> String {
        // Initialize claims with subject and standard OIDC fields
        let claims: CoreIdTokenClaims = CoreIdTokenClaims::new(
            provider.as_issuer_url(),
            vec![Audience::new(provider.as_client_id().to_string())],
            Utc::now(), // expiration time
            Utc::now(), // issued at
            StandardClaims::new(SubjectIdentifier::new("test-subject".to_string())),
            EmptyAdditionalClaims {},
        )
        .set_nonce(Some(Nonce::new("test-nonce".to_string())))
        .set_email(Some(EndUserEmail::new("hello@example.com".to_string())));

        // Sign the claims with the private key
        let id_token = CoreIdToken::new(
            claims,
            &self.signing_key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .expect("failed to create id_token");

        id_token.to_string()
    }

    /// Generate a token with incorrect signature for the specified provider
    pub fn generate_incorrectly_signed_token(&self, provider: &MockOidcProvider) -> String {
        // Initialize claims with subject and standard OIDC fields
        let claims: CoreIdTokenClaims = CoreIdTokenClaims::new(
            provider.as_issuer_url(),
            vec![Audience::new(provider.as_client_id().to_string())],
            Utc::now().checked_add_signed(Duration::hours(1)).unwrap(), // expiration time
            Utc::now(),                                                 // issued at
            StandardClaims::new(SubjectIdentifier::new("test-subject".to_string())),
            EmptyAdditionalClaims {},
        );

        // Create a new signing key for incorrect signing
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let incorrect_signing_key =
            RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let incorrect_signing_key = CoreRsaPrivateSigningKey::from_pem(
            &incorrect_signing_key
                .to_pkcs1_pem(LineEnding::default())
                .unwrap(),
            Some(JsonWebKeyId::new("key2".to_string())), // Different key ID
        )
        .expect("Invalid RSA private key");

        // Sign the claims with the incorrect private key
        let id_token = CoreIdToken::new(
            claims,
            &incorrect_signing_key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .expect("failed to create id_token");

        id_token.to_string()
    }

    /// Generate a token with incorrect issuer for the specified provider
    pub fn generate_token_with_incorrect_issuer(&self, provider: &MockOidcProvider) -> String {
        let claims: CoreIdTokenClaims = CoreIdTokenClaims::new(
            provider.as_issuer_url(),
            vec![Audience::new(provider.as_client_id().to_string())],
            Utc::now().checked_add_signed(Duration::hours(1)).unwrap(), // expiration time
            Utc::now(),                                                 // issued at
            StandardClaims::new(SubjectIdentifier::new("test-subject".to_string())),
            EmptyAdditionalClaims {},
        );

        // Sign the claims with the private key
        let id_token = CoreIdToken::new(
            claims,
            &self.signing_key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .expect("failed to create id_token");

        id_token.to_string()
    }

    /// Generate a token with incorrect audience for the specified provider
    pub fn generate_token_with_incorrect_audience(&self, provider: &MockOidcProvider) -> String {
        let claims: CoreIdTokenClaims = CoreIdTokenClaims::new(
            provider.as_issuer_url(),
            vec![Audience::new("incorrect-audience".to_string())],
            Utc::now().checked_add_signed(Duration::hours(1)).unwrap(), // expiration time
            Utc::now(),                                                 // issued at
            StandardClaims::new(SubjectIdentifier::new("test-subject".to_string())),
            EmptyAdditionalClaims {},
        );

        // Sign the claims with the private key
        let id_token = CoreIdToken::new(
            claims,
            &self.signing_key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .expect("failed to create id_token");

        id_token.to_string()
    }

    /// Generate a token with incorrect `issued_at` time for the specified provider
    pub fn generate_token_with_incorrect_issued_at(&self, provider: &MockOidcProvider) -> String {
        let claims: CoreIdTokenClaims = CoreIdTokenClaims::new(
            provider.as_issuer_url(),
            vec![Audience::new(provider.as_client_id().to_string())],
            Utc::now().checked_add_signed(Duration::hours(1)).unwrap(), // expiration time
            Utc::now()
                .checked_add_signed(Duration::minutes(30))
                .unwrap(), // issued at in future
            StandardClaims::new(SubjectIdentifier::new("test-subject".to_string())),
            EmptyAdditionalClaims {},
        );

        // Sign the claims with the private key
        let id_token = CoreIdToken::new(
            claims,
            &self.signing_key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .expect("failed to create id_token");

        id_token.to_string()
    }
}
