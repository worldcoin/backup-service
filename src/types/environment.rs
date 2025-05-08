use crate::kms_jwe::KmsKey;
use openidconnect::{ClientId, IssuerUrl, JsonWebKeySetUrl};
use std::env;
use webauthn_rs::prelude::Url;
use webauthn_rs::{Webauthn, WebauthnBuilder};

#[derive(Debug, Clone, Copy)]
pub enum Environment {
    Production,
    Staging,
    Development {
        jwk_set_url_port_override: Option<usize>,
    },
}

impl Environment {
    pub fn from_env() -> Self {
        let env = env::var("APP_ENV")
            .expect("APP_ENV environment variable is not set")
            .trim()
            .to_lowercase();
        match env.as_str() {
            "production" => Self::Production,
            "staging" => Self::Staging,
            "development" => Self::Development {
                jwk_set_url_port_override: None,
            },
            _ => panic!("Invalid environment: {}", env),
        }
    }

    pub fn development(jwk_set_url_port_override: Option<usize>) -> Self {
        Self::Development {
            jwk_set_url_port_override,
        }
    }

    /// S3 bucket where backups are stored
    pub fn s3_bucket_arn(&self) -> String {
        match self {
            Self::Production | Self::Staging => env::var("BACKUP_S3_BUCKET_ARN")
                .expect("BACKUP_S3_BUCKET_ARN environment variable is not set")
                .to_string(),
            // We can't specify the bucket ARN for localstack,
            // so we use the bucket name instead.
            // Path-style addressing (which is used only on development
            // for local stack support) cannot be used with ARN buckets.
            Self::Development { .. } => "backup-service-bucket".to_string(),
        }
    }

    /// Returns the endpoint URL to use for AWS services
    pub const fn override_aws_endpoint_url(&self) -> Option<&str> {
        match self {
            // Regular AWS endpoints to be used for production and staging
            Self::Production | Self::Staging => None,
            // Localstack to be used for development
            Self::Development { .. } => Some("http://localhost:4566"),
        }
    }

    /// AWS configuration to be used for the application, including any environment-specific overrides
    pub async fn aws_config(&self) -> aws_config::SdkConfig {
        let mut aws_config = aws_config::defaults(aws_config::BehaviorVersion::v2025_01_17());
        if let Some(endpoint_url) = self.override_aws_endpoint_url() {
            aws_config = aws_config.endpoint_url(endpoint_url);
        }
        aws_config.load().await
    }

    /// AWS S3 service configuration
    pub async fn s3_client_config(&self) -> aws_sdk_s3::Config {
        let aws_config = self.aws_config().await;
        let s3_config: aws_sdk_s3::Config = (&aws_config).into();
        let mut builder = s3_config.to_builder();
        // Override "force path style" to true for compatibility with localstack
        // https://github.com/awslabs/aws-sdk-rust/discussions/874
        if let Self::Development { .. } = self {
            builder.set_force_path_style(Some(true));
        }
        builder.build()
    }

    /// Returns whether the API docs should be visible
    pub fn show_api_docs(&self) -> bool {
        match self {
            Self::Production => false,
            Self::Staging | Self::Development { .. } => true,
        }
    }

    /// KMS keys used to encrypt challenge tokens
    pub fn challenge_token_kms_key(&self) -> KmsKey {
        KmsKey::from_arn(
            env::var("CHALLENGE_TOKEN_KMS_KEY_ARN")
                .expect("CHALLENGE_TOKEN_KMS_KEY_ARN environment variable is not set")
                .as_str(),
        )
    }

    /// What's the TTL for the challenge tokens
    pub fn challenge_token_ttl(&self) -> std::time::Duration {
        // 15 minutes
        std::time::Duration::from_secs(15 * 60)
    }

    /// What's the TTL for the token that's issued during recovery and allows to add a new sync factor
    pub fn sync_factor_token_ttl(&self) -> std::time::Duration {
        // 15 minutes
        std::time::Duration::from_secs(15 * 60)
    }

    /// Configuration to generate passkeys
    pub fn webauthn_config(&self) -> Webauthn {
        WebauthnBuilder::new(
            "keys.world.app",
            &Url::parse("https://keys.world.app").expect("Invalid URL"),
        )
        .expect("Failed to create WebauthnBuilder")
        .rp_name("World App")
        // Android dev & staging — app signing key hash
        .append_allowed_origin(
            &"android:apk-key-hash:o0Fu39yqrsxeWSucqge7eOzG8xrsRAn0nKbTtN_x2-A"
                .parse()
                .unwrap(),
        )
        // Android prod — app signing key hash
        .append_allowed_origin(
            &"android:apk-key-hash:ndK9En8JkZKXFMAZW0NHhDRTHNi38YE2XCvVzYXjRu8"
                .parse()
                .unwrap(),
        )
        .build()
        .expect("Failed to build Webauthn")
    }

    /// Max size of the backup file
    pub fn max_backup_file_size(&self) -> usize {
        5 * 1024 * 1024 // 5 MB
    }

    /// JWK Set URL for the Google OIDC provider
    pub fn google_jwk_set_url(&self) -> JsonWebKeySetUrl {
        match self {
            Self::Production | Self::Staging => {
                JsonWebKeySetUrl::new("https://www.googleapis.com/oauth2/v3/certs".to_string())
                    .expect("Invalid JWK set URL")
            }
            Self::Development {
                jwk_set_url_port_override: port,
            } => {
                let port = port.unwrap_or(8001);
                JsonWebKeySetUrl::new(format!("http://localhost:{}/oauth2/v3/certs", port))
                    .expect("Invalid JWK set URL")
            }
        }
    }

    /// The client ID for the Google OIDC provider
    pub fn google_client_id(&self) -> ClientId {
        match self {
            Self::Production | Self::Staging => ClientId::new(
                "730924878354-jvi49m445q2mv6s1dn4oklm8i4vlpct9.apps.googleusercontent.com"
                    .to_string(),
            ),
            Self::Development { .. } => ClientId::new(
                "949370763172-0pu3c8c3rmp8ad665jsb1qkf8lai592i.apps.googleusercontent.com"
                    .to_string(),
            ),
        }
    }

    /// Issuer URL for the Google OIDC provider
    pub fn google_issuer_url(&self) -> IssuerUrl {
        IssuerUrl::new("https://accounts.google.com".to_string()).expect("Invalid issuer URL")
    }

    pub fn factor_lookup_dynamodb_table_name(&self) -> &'static str {
        match self {
            Self::Production | Self::Staging | Self::Development { .. } => {
                "backup-service-factor-lookup"
            }
        }
    }

    pub fn sync_factor_token_table_name(&self) -> &'static str {
        match self {
            Self::Production | Self::Staging | Self::Development { .. } => {
                "backup-service-sync-factor-tokens"
            }
        }
    }
}
