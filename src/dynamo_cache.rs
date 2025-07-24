use crate::types::{Environment, OidcProvider};
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::get_item::GetItemError;
use aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_sdk_dynamodb::operation::update_item::UpdateItemError;
use aws_sdk_dynamodb::types::AttributeValue;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use strum_macros::{Display, EnumString};

/// The `DynamoCacheManager` introduces a simple and generic cache layer on top of `DynamoDB`.
///
/// # Use Cases
/// - It is used to store tokens that are used to add a sync factor to a backup.
/// - It is also used to prevent replay attacks by storing used challenge tokens.
#[derive(Clone, Debug)]
pub struct DynamoCacheManager {
    environment: Environment,
    default_ttl: Duration,
    dynamodb_client: Arc<aws_sdk_dynamodb::Client>,
}

impl DynamoCacheManager {
    #[must_use]
    pub fn new(
        environment: Environment,
        default_ttl: Duration,
        dynamodb_client: Arc<aws_sdk_dynamodb::Client>,
    ) -> Self {
        Self {
            environment,
            default_ttl,
            dynamodb_client,
        }
    }

    /// Creates a new sync factor token that allows to update `backup_id` and stores it
    /// in the `DynamoDB` database. The token is returned to the caller.
    ///
    /// Sync Factor Tokens are prefixed in Dynamo with `syncFactorToken#`
    ///
    /// # Errors
    /// * `SyncFactorTokenError::DynamoDbPutError` - if the token cannot be inserted into the `DynamoDB` table
    pub async fn create_sync_factor_token(
        &self,
        backup_id: String,
    ) -> Result<String, DynamoCacheError> {
        // Generate a random token
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let token = BASE64_URL_SAFE_NO_PAD.encode(token_bytes);

        // Hash the token for storage
        let token_hash = hash_token(SYNC_FACTOR_TOKEN_PREFIX, &token);

        // Calculate TTL timestamp
        let expiration_time = Utc::now() + self.default_ttl;
        let ttl = expiration_time.timestamp();

        // Store in DynamoDB
        self.dynamodb_client
            .put_item()
            .table_name(self.environment.cache_table_name())
            .item(
                SyncFactorTokenAttribute::Pk.to_string(),
                AttributeValue::S(token_hash),
            )
            .item(
                SyncFactorTokenAttribute::BackupId.to_string(),
                AttributeValue::S(backup_id),
            )
            .item(
                SyncFactorTokenAttribute::IsUsed.to_string(),
                AttributeValue::Bool(false),
            )
            .item(
                SyncFactorTokenAttribute::CreatedAt.to_string(),
                AttributeValue::N(Utc::now().timestamp_millis().to_string()),
            )
            .item(
                SyncFactorTokenAttribute::ExpiresAt.to_string(),
                AttributeValue::N(ttl.to_string()),
            )
            .send()
            .await?;

        Ok(token)
    }

    /// Verifies the token and returns the backup ID, unless it was already used.
    /// The token is then marked as used. The corresponding backup ID is returned.
    ///
    /// The motivation for this two-step process is to prevent users from adding a sync factor to
    /// their backup if they haven't passed the risk checks.
    ///
    /// If a sync factor was added in the same step, users who haven't passed the risk checks
    /// (and therefore not let into the app) would have added a sync factor to their backup.
    /// Since users might make multiple attempts to retrieve their backup, this would lead to
    /// accumulation of sync factors in the backup that are not used and likely not even saved in the app.
    ///
    /// The token is a random secret value that's stored hashed in the cache table in Dynamo. The token is
    /// issued at retrieval and removed when the sync factor is added. This method retrieves and marks the token as used
    /// in a semi-atomic process.
    ///
    /// # Errors
    /// * `DynamoCacheError::DynamoDbGetError` - if the token cannot be fetched from the `DynamoDB` table
    /// * `DynamoCacheError::DynamoDbUpdateError` - if the token cannot be marked as used in the `DynamoDB` table
    /// * `DynamoCacheError::TokenNotFound` - if the token does not exist in the database
    /// * `DynamoCacheError::AlreadyUsed` - if the token was already used
    /// * `DynamoCacheError::TokenExpired` - if the token has expired
    /// * `DynamoCacheError::ParseBackupIdError` - if the backup ID cannot be parsed from the token
    /// * `DynamoCacheError::MalformedToken` - if the token is missing required attributes
    pub async fn use_sync_factor_token(&self, token: String) -> Result<String, DynamoCacheError> {
        // Hash the token for lookup
        let token_hash = hash_token(SYNC_FACTOR_TOKEN_PREFIX, &token);

        // Get the token from `DynamoDB`
        let result = self
            .dynamodb_client
            .get_item()
            .table_name(self.environment.cache_table_name())
            .key(
                SyncFactorTokenAttribute::Pk.to_string(),
                AttributeValue::S(token_hash.clone()),
            )
            .send()
            .await?;

        let Some(item) = result.item() else {
            return Err(DynamoCacheError::TokenNotFound);
        };

        // Check if the token is already used
        let is_used = item
            .get(&SyncFactorTokenAttribute::IsUsed.to_string())
            .ok_or(DynamoCacheError::MalformedToken)?
            .as_bool()
            .map_err(|_| DynamoCacheError::MalformedToken)?;
        if *is_used {
            return Err(DynamoCacheError::AlreadyUsed);
        }

        // Check if the token has expired
        let expires_at = item
            .get(&SyncFactorTokenAttribute::ExpiresAt.to_string())
            .ok_or(DynamoCacheError::MalformedToken)?
            .as_n()
            .map_err(|_| DynamoCacheError::MalformedToken)?
            .parse::<i64>()
            .map_err(|_| DynamoCacheError::ParseExpirationError)?;
        if Utc::now().timestamp() > expires_at {
            return Err(DynamoCacheError::TokenExpired);
        }

        // Extract the backup ID
        let backup_id = item
            .get(&SyncFactorTokenAttribute::BackupId.to_string())
            .ok_or(DynamoCacheError::MalformedToken)?
            .as_s()
            .map_err(|_| DynamoCacheError::MalformedToken)?
            .to_string();

        // Atomically mark the token as used
        self.dynamodb_client
            .update_item()
            .table_name(self.environment.cache_table_name())
            .key(
                SyncFactorTokenAttribute::Pk.to_string(),
                AttributeValue::S(token_hash),
            )
            .update_expression("SET #is_used = :true")
            .expression_attribute_names("#is_used", SyncFactorTokenAttribute::IsUsed.to_string())
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .condition_expression("#is_used = :false")
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .send()
            .await
            .map_err(|err| match err.into_service_error() {
                UpdateItemError::ConditionalCheckFailedException(_) => {
                    DynamoCacheError::AlreadyUsed
                }
                err => DynamoCacheError::DynamoDbUpdateError(err),
            })?;

        Ok(backup_id)
    }

    /// Unmarks a sync factor token as used. This is used to ensure atomicity in the process to add a sync factor.
    ///
    /// If the process of adding the factor to the backup metadata in S3 fails, the token is unmarked as used
    /// to allow the user to try again.
    ///
    /// # Errors
    /// * `DynamoCacheError::DynamoDbUpdateError` - if the token cannot be unmarked as used in the `DynamoDB` table
    pub async fn unuse_sync_factor_token(&self, token: String) -> Result<(), DynamoCacheError> {
        let token_hash = hash_token(SYNC_FACTOR_TOKEN_PREFIX, &token);
        self.dynamodb_client
            .update_item()
            .table_name(self.environment.cache_table_name())
            .key(
                SyncFactorTokenAttribute::Pk.to_string(),
                AttributeValue::S(token_hash),
            )
            .update_expression("SET #is_used = :false")
            .expression_attribute_names("#is_used", SyncFactorTokenAttribute::IsUsed.to_string())
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .send()
            .await
            .map_err(|err| DynamoCacheError::DynamoDbUpdateError(err.into_service_error()))?;
        Ok(())
    }

    /// Records a hashed challenge token as used in `DynamoDB` to prevent replay attacks.
    ///
    /// # Errors
    /// * `DynamoCacheError::DynamoDbPutError` - if the token cannot be inserted into the `DynamoDB` table
    pub async fn use_challenge_token(
        &self,
        challenge_token: String,
    ) -> Result<(), DynamoCacheError> {
        let token_hash = hash_token(USED_CHALLENGE_PREFIX, &challenge_token);

        let expiration_time = Utc::now() + self.default_ttl;
        let ttl = expiration_time.timestamp();

        self.dynamodb_client
            .put_item()
            .table_name(self.environment.cache_table_name())
            .item(
                UsedChallengeAttribute::Pk.to_string(),
                AttributeValue::S(token_hash),
            )
            .item(
                UsedChallengeAttribute::ExpiresAt.to_string(),
                AttributeValue::N(ttl.to_string()),
            )
            .condition_expression("attribute_not_exists(#pk)")
            .expression_attribute_names("#pk", UsedChallengeAttribute::Pk.to_string())
            .send()
            .await
            .map_err(|err| {
                if let SdkError::ServiceError(context) = &err {
                    if context.err().is_conditional_check_failed_exception() {
                        return DynamoCacheError::AlreadyUsed;
                    }
                }
                DynamoCacheError::DynamoDbPutError(err)
            })?;
        Ok(())
    }

    /// Stores a hashed OIDC nonce to prevent replay attacks.
    ///
    /// Note this method is very similar to `use_challenge_token` but uses different configuration
    ///
    /// # Errors
    /// * `DynamoCacheError::DynamoDbPutError` - if the token cannot be inserted into the `DynamoDB` table
    pub async fn use_oidc_nonce(
        &self,
        nonce: &str,
        oidc_provider: &OidcProvider,
    ) -> Result<(), DynamoCacheError> {
        let token_hash = hash_token(
            USED_OIDC_NONCE_PREFIX,
            format!("{oidc_provider}:{nonce}").as_ref(),
        );

        // Nonces may be indefinitely valid, in a regular OIDC flow, the nonce would be created by the RP and short-lived,
        // but this nonce depends on Turnkey, so we can't depend on a server-side expiration.
        // For the time being, we cache the hashed nonce indefinitely to prevent replay.
        let creation_date = Utc::now().date_naive();

        self.dynamodb_client
            .put_item()
            .table_name(self.environment.cache_table_name())
            .item(
                UsedChallengeAttribute::Pk.to_string(),
                AttributeValue::S(token_hash),
            )
            .item(
                UsedChallengeAttribute::CreationDate.to_string(),
                AttributeValue::S(creation_date.to_string()),
            )
            .condition_expression("attribute_not_exists(#pk)")
            .expression_attribute_names("#pk", UsedChallengeAttribute::Pk.to_string())
            .send()
            .await
            .map_err(|err| {
                if let SdkError::ServiceError(context) = &err {
                    if context.err().is_conditional_check_failed_exception() {
                        return DynamoCacheError::AlreadyUsed;
                    }
                }
                DynamoCacheError::DynamoDbPutError(err)
            })?;
        Ok(())
    }

    pub async fn is_ready(&self) -> bool {
        let result = self
            .dynamodb_client
            .describe_table()
            .table_name(self.environment.cache_table_name())
            .send()
            .await;

        if let Ok(result) = result {
            result.table().is_some()
        } else {
            tracing::error!(
                "System is not ready. DynamoChacheManager (DescribeTable): {:?}",
                result.err()
            );
            false
        }
    }
}

/// Hashes a token using SHA-256 and returns the hex representation
fn hash_token(prefix: &str, token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{prefix}#{:x}", hasher.finalize())
}

#[derive(Debug, Clone, Display, EnumString)]
pub enum SyncFactorTokenAttribute {
    /// Primary key for the token (prefix `SYNC_FACTOR_TOKEN_PREFIX`)
    #[strum(serialize = "PK")]
    Pk,
    /// Backup ID that the token is associated with
    BackupId,
    /// Whether the token has been used
    IsUsed,
    /// Creation timestamp for debugging
    CreatedAt,
    /// Expiration timestamp for TTL
    ExpiresAt,
}

const SYNC_FACTOR_TOKEN_PREFIX: &str = "syncFactorToken";
const USED_CHALLENGE_PREFIX: &str = "usedChallengeHash";
const USED_OIDC_NONCE_PREFIX: &str = "usedOidcNonceHash";

#[derive(Debug, Clone, Display, EnumString)]
pub enum UsedChallengeAttribute {
    /// Primary key for the token (prefix `USED_CHALLENGE_PREFIX`)
    #[strum(serialize = "PK")]
    Pk,
    /// Expiration timestamp for TTL
    ExpiresAt,
    /// Creation date (only used for some attributes)
    CreationDate,
}

#[derive(thiserror::Error, Debug)]
pub enum DynamoCacheError {
    #[error("Failed to insert token into DynamoDB: {0}")]
    DynamoDbPutError(#[from] SdkError<PutItemError>),
    #[error("Failed to fetch token from DynamoDB: {0}")]
    DynamoDbGetError(#[from] SdkError<GetItemError>),
    #[error("Failed to update token in DynamoDB: {0}")]
    DynamoDbUpdateError(#[from] UpdateItemError),
    #[error("Token not found")]
    TokenNotFound,
    #[error("Token or challenge has already been used")]
    AlreadyUsed,
    #[error("Token has expired")]
    TokenExpired,
    #[error("Malformed token: missing required attributes")]
    MalformedToken,
    #[error("Failed to parse backup ID from token")]
    ParseBackupIdError,
    #[error("Failed to parse expiration time from token")]
    ParseExpirationError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn get_test_dynamodb_client() -> Arc<aws_sdk_dynamodb::Client> {
        let environment = Environment::development(None);
        let aws_config = environment.aws_config().await;
        Arc::new(aws_sdk_dynamodb::Client::new(&aws_config))
    }

    #[tokio::test]
    async fn test_create_and_use_token() {
        let dynamodb_client = get_test_dynamodb_client().await;
        let environment = Environment::development(None);
        let token_manager =
            DynamoCacheManager::new(environment, Duration::from_secs(60), dynamodb_client);

        let backup_id = format!("test_backup_id_{}", uuid::Uuid::new_v4());

        // Create a token
        let token = token_manager
            .create_sync_factor_token(backup_id.clone())
            .await
            .unwrap();

        // Use the token
        let retrieved_backup_id = token_manager
            .use_sync_factor_token(token.clone())
            .await
            .unwrap();
        assert_eq!(retrieved_backup_id, backup_id);

        // Try to use the token again - should fail as already used
        let result = token_manager.use_sync_factor_token(token).await;
        assert!(matches!(result, Err(DynamoCacheError::AlreadyUsed)));
    }

    #[tokio::test]
    async fn test_use_nonexistent_token() {
        let dynamodb_client = get_test_dynamodb_client().await;
        let environment = Environment::development(None);
        let token_manager =
            DynamoCacheManager::new(environment, Duration::from_secs(60), dynamodb_client);

        // Try to use a non-existent token
        let token = format!("nonexistent_token_{}", uuid::Uuid::new_v4());
        let result = token_manager.use_sync_factor_token(token).await;
        assert!(matches!(result, Err(DynamoCacheError::TokenNotFound)));
    }

    #[tokio::test]

    async fn test_token_expiration() {
        let dynamodb_client = get_test_dynamodb_client().await;
        let environment = Environment::development(None);
        // Set a very short expiration time
        let token_manager = DynamoCacheManager::new(
            environment,
            Duration::from_secs(1), // 1 second expiration
            dynamodb_client,
        );

        let backup_id = format!("test_backup_id_{}", uuid::Uuid::new_v4());

        // Create a token that expires in 1 second
        let token = token_manager
            .create_sync_factor_token(backup_id)
            .await
            .unwrap();

        // Sleep for 2 seconds to ensure the token expires
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Try to use the expired token
        let result = token_manager.use_sync_factor_token(token).await;
        assert!(matches!(result, Err(DynamoCacheError::TokenExpired)));
    }

    #[tokio::test]
    async fn test_prevent_challenge_token_reuse_replay_attack() {
        let dynamodb_client = get_test_dynamodb_client().await;

        let environment = Environment::development(None);
        let token_manager =
            DynamoCacheManager::new(environment, Duration::from_secs(60), dynamodb_client);

        let challenge_token = format!("my_one_time_challenge_token_{}", uuid::Uuid::new_v4());

        // first time it succeeds
        token_manager
            .use_challenge_token(challenge_token.to_string())
            .await
            .unwrap();

        // second time it fails
        let result = token_manager
            .use_challenge_token(challenge_token.to_string())
            .await;
        assert!(matches!(result, Err(DynamoCacheError::AlreadyUsed)));
    }

    #[tokio::test]
    async fn test_ensure_challenge_token_is_hashed() {
        let dynamodb_client = get_test_dynamodb_client().await;
        let environment = Environment::development(None);
        let token_manager = DynamoCacheManager::new(
            environment,
            Duration::from_secs(60),
            dynamodb_client.clone(),
        );

        let challenge_token = format!("my_one_time_challenge_token_{}", uuid::Uuid::new_v4());

        token_manager
            .use_challenge_token(challenge_token.to_string())
            .await
            .unwrap();

        let mut hasher = Sha256::new();
        hasher.update(challenge_token.as_bytes());
        let token_hash = format!("{USED_CHALLENGE_PREFIX}#{:x}", hasher.finalize());

        dynamodb_client
            .get_item()
            .table_name(environment.cache_table_name())
            .key(
                SyncFactorTokenAttribute::Pk.to_string(),
                AttributeValue::S(token_hash.clone()),
            )
            .send()
            .await
            .unwrap();
    }

    // NOTE: explicit lack of tests for expired tokens. we don't care that they're expired, they cannot be re-used.
}
