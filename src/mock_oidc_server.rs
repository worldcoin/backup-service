use crate::types::Environment;
use chrono::{Duration, Utc};
use mockito::ServerOpts;
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
    CoreRsaPrivateSigningKey,
};
use openidconnect::{
    Audience, EmptyAdditionalClaims, EndUserEmail, IssuerUrl, JsonWebKeyId, Nonce,
    PrivateSigningKey, StandardClaims, SubjectIdentifier,
};
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::RsaPrivateKey;
use uuid::Uuid;

/// Mock OIDC server for testing purposes. We have to expose it as a module, because it's used in
/// both integration and unit tests.
pub struct MockOidcServer {
    signing_key: CoreRsaPrivateSigningKey,
    pub server: mockito::Server,
    pub jwk_set_mock: mockito::Mock,
}

// TODO/FIXME: DRY with other implementation

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
        let mut server = mockito::Server::new_with_opts_async(ServerOpts {
            port: 0, // Dynamically assign port
            ..Default::default()
        })
        .await;

        let jwk_set_mock = server
            .mock("GET", "/oauth2/v3/certs")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&jwk_set).unwrap().as_bytes())
            .create();

        Self {
            signing_key,
            server,
            jwk_set_mock,
        }
    }

    pub fn port(&self) -> usize {
        self.server.socket_address().port() as usize
    }

    pub fn generate_token(
        &self,
        environment: Environment,
        subject: Option<SubjectIdentifier>,
    ) -> String {
        let subject = subject.unwrap_or_else(|| SubjectIdentifier::new(Uuid::new_v4().to_string()));
        // Initialize claims with subject and standard OIDC fields
        let claims: CoreIdTokenClaims = CoreIdTokenClaims::new(
            environment.google_issuer_url(),
            vec![Audience::new(
                environment.google_client_id_android().to_string(),
            )],
            Utc::now().checked_add_signed(Duration::hours(1)).unwrap(), // expiration time
            Utc::now(),                                                 // issued at
            StandardClaims::new(subject),
            EmptyAdditionalClaims {},
        )
        .set_nonce(Some(Nonce::new("test-nonce".to_string())))
        .set_email(Some(EndUserEmail::new("hello@example.com".to_string())));

        // Sign the claims with the private key
        let id_token = CoreIdToken::new(
            claims,
            &self.signing_key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256, // RS256, same as the Google OIDC provider
            None,
            None,
        )
        .expect("failed to create id_token");

        id_token.to_string()
    }

    pub fn generate_expired_token(&self, environment: Environment) -> String {
        // Initialize claims with subject and standard OIDC fields
        let claims: CoreIdTokenClaims = CoreIdTokenClaims::new(
            environment.google_issuer_url(),
            vec![Audience::new(
                environment.google_client_id_android().to_string(),
            )],
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
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256, // RS256, same as the Google OIDC provider
            None,
            None,
        )
        .expect("failed to create id_token");

        id_token.to_string()
    }

    pub fn generate_incorrectly_signed_token(&self, environment: Environment) -> String {
        // Initialize claims with subject and standard OIDC fields
        let claims: CoreIdTokenClaims = CoreIdTokenClaims::new(
            environment.google_issuer_url(),
            vec![Audience::new(
                environment.google_client_id_android().to_string(),
            )],
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
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256, // RS256, same as the Google OIDC provider
            None,
            None,
        )
        .expect("failed to create id_token");

        id_token.to_string()
    }

    pub fn generate_token_with_incorrect_issuer(&self, environment: Environment) -> String {
        let claims: CoreIdTokenClaims = CoreIdTokenClaims::new(
            IssuerUrl::new("https://incorrect-issuer.com".to_string()).unwrap(),
            vec![Audience::new(
                environment.google_client_id_android().to_string(),
            )],
            Utc::now().checked_add_signed(Duration::hours(1)).unwrap(), // expiration time
            Utc::now(),                                                 // issued at
            StandardClaims::new(SubjectIdentifier::new("test-subject".to_string())),
            EmptyAdditionalClaims {},
        );

        // Sign the claims with the private key
        let id_token = CoreIdToken::new(
            claims,
            &self.signing_key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256, // RS256, same as the Google OIDC provider
            None,
            None,
        )
        .expect("failed to create id_token");

        id_token.to_string()
    }

    pub fn generate_token_with_incorrect_audience(&self, environment: Environment) -> String {
        let claims: CoreIdTokenClaims = CoreIdTokenClaims::new(
            environment.google_issuer_url(),
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
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256, // RS256, same as the Google OIDC provider
            None,
            None,
        )
        .expect("failed to create id_token");

        id_token.to_string()
    }

    pub fn generate_token_with_incorrect_issued_at(&self, environment: Environment) -> String {
        let claims: CoreIdTokenClaims = CoreIdTokenClaims::new(
            environment.google_issuer_url(),
            vec![Audience::new(
                environment.google_client_id_android().to_string(),
            )],
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
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256, // RS256, same as the Google OIDC provider
            None,
            None,
        )
        .expect("failed to create id_token");

        id_token.to_string()
    }
}
