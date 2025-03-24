use std::env;

#[derive(Debug, Clone, Copy)]
pub enum Environment {
    Production,
    Staging,
    Development,
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
            "development" => Self::Development,
            _ => panic!("Invalid environment: {}", env),
        }
    }

    /// S3 bucket where backups are stored
    pub fn s3_bucket_name(&self) -> &str {
        match self {
            Self::Production | Self::Staging => {
                todo!("Implement bucket name for production and staging")
            }
            Self::Development => "backup-service-bucket",
        }
    }

    /// Returns the endpoint URL to use for AWS services
    pub const fn override_aws_endpoint_url(&self) -> Option<&str> {
        match self {
            // Regular AWS endpoints to be used for production and staging
            Self::Production | Self::Staging => None,
            // Localstack to be used for development
            Self::Development => Some("http://localhost:4566"),
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
        if let Self::Development = self {
            builder.set_force_path_style(Some(true));
        }
        builder.build()
    }

    /// Returns whether the API docs should be visible
    pub fn show_api_docs(&self) -> bool {
        match self {
            Self::Production => false,
            Self::Staging | Self::Development => true,
        }
    }
}
