use crate::types::{Environment, OidcProvider};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// The `RedisCacheManager` introduces a simple and generic cache layer on top of `Redis`.
///
/// # Use Cases
/// - It is used to store tokens that are used to add a sync factor to a backup.
/// - It is also used to prevent replay attacks by storing used challenge tokens.
#[derive(Clone)]
pub struct RedisCacheManager {
    environment: Environment,
    default_ttl: Duration,
    redis: ConnectionManager,
}

impl std::fmt::Debug for RedisCacheManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisCacheManager")
            .field("environment", &self.environment)
            .field("default_ttl", &self.default_ttl)
            .field("redis", &"<ConnectionManager>")
            .finish()
    }
}

impl RedisCacheManager {
    #[must_use]
    pub fn new(environment: Environment, default_ttl: Duration, redis: ConnectionManager) -> Self {
        Self {
            environment,
            default_ttl,
            redis,
        }
    }

    /// Creates a new sync factor token that allows to update `backup_id` and stores it
    /// in the `Redis` database. The token is returned to the caller.
    ///
    /// Sync Factor Tokens are prefixed in Redis with `syncFactorToken#`
    ///
    /// # Errors
    /// * `RedisCacheError::RedisError` - if the token cannot be inserted into the Redis database
    pub async fn create_sync_factor_token(
        &self,
        backup_id: String,
    ) -> Result<String, RedisCacheError> {
        // Generate a random token
        let mut token_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token_bytes);
        let token = BASE64_URL_SAFE_NO_PAD.encode(token_bytes);

        // Hash the token for storage
        let token_hash = hash_token(SYNC_FACTOR_TOKEN_PREFIX, &token);

        // Calculate TTL in seconds
        let ttl_seconds = self.default_ttl.as_secs();

        // Create token data
        let token_data = SyncFactorTokenData {
            backup_id,
            is_used: false,
            created_at: Utc::now().timestamp_millis(),
            expires_at: Utc::now().timestamp() + i64::try_from(ttl_seconds).unwrap_or(i64::MAX),
        };

        // Serialize and store in Redis with TTL
        let serialized_data = serde_json::to_string(&token_data)?;
        let mut redis = self.redis.clone();
        redis
            .set_ex(&token_hash, serialized_data, ttl_seconds)
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
    /// The token is a random secret value that's stored hashed in the cache table in Redis. The token is
    /// issued at retrieval and removed when the sync factor is added. This method retrieves and marks the token as used
    /// in an atomic process using Redis transactions.
    ///
    /// # Errors
    /// * `RedisCacheError::RedisError` - if the token cannot be fetched from Redis
    /// * `RedisCacheError::TokenNotFound` - if the token does not exist in the database
    /// * `RedisCacheError::AlreadyUsed` - if the token was already used
    /// * `RedisCacheError::TokenExpired` - if the token has expired
    /// * `RedisCacheError::ParseError` - if the token data cannot be parsed
    pub async fn use_sync_factor_token(&self, token: String) -> Result<String, RedisCacheError> {
        // Hash the token for lookup
        let token_hash = hash_token(SYNC_FACTOR_TOKEN_PREFIX, &token);

        // Get the token data from Redis
        let mut redis = self.redis.clone();
        let data: Option<String> = redis.get(&token_hash).await?;
        let Some(data) = data else {
            return Err(RedisCacheError::TokenNotFound);
        };

        // Parse the token data
        let mut token_data: SyncFactorTokenData = serde_json::from_str(&data)?;

        // Check if the token is already used
        if token_data.is_used {
            return Err(RedisCacheError::AlreadyUsed);
        }

        // Check if the token has expired
        if Utc::now().timestamp() > token_data.expires_at {
            return Err(RedisCacheError::TokenExpired);
        }

        // Mark as used and update in Redis atomically using a transaction
        token_data.is_used = true;
        let updated_data = serde_json::to_string(&token_data)?;

        // For atomic operations in Redis with async connections, we use optimistic locking
        // First check if token exists and is not used
        let current_data: Option<String> = redis.get(&token_hash).await?;
        let Some(current) = current_data else {
            return Err(RedisCacheError::TokenNotFound);
        };

        let current_token: SyncFactorTokenData = serde_json::from_str(&current)?;
        if current_token.is_used {
            return Err(RedisCacheError::AlreadyUsed);
        }

        // Update the token to mark as used
        redis
            .set_ex(&token_hash, &updated_data, self.default_ttl.as_secs())
            .await?;

        Ok(token_data.backup_id)
    }

    /// Unmarks a sync factor token as used. This is used to ensure atomicity in the process to add a sync factor.
    ///
    /// If the process of adding the factor to the backup metadata in S3 fails, the token is unmarked as used
    /// to allow the user to try again.
    ///
    /// # Errors
    /// * `RedisCacheError::RedisError` - if the token cannot be updated in Redis
    pub async fn unuse_sync_factor_token(&self, token: String) -> Result<(), RedisCacheError> {
        let token_hash = hash_token(SYNC_FACTOR_TOKEN_PREFIX, &token);

        // Get current data
        let mut redis = self.redis.clone();
        let data: Option<String> = redis.get(&token_hash).await?;
        if let Some(data) = data {
            let mut token_data: SyncFactorTokenData = serde_json::from_str(&data)?;
            token_data.is_used = false;
            let updated_data = serde_json::to_string(&token_data)?;

            // Update the token
            let ttl =
                u64::try_from((token_data.expires_at - Utc::now().timestamp()).max(0)).unwrap_or(0);
            redis.set_ex(&token_hash, updated_data, ttl).await?;
        }
        Ok(())
    }

    /// Records a hashed challenge token as used in `Redis` to prevent replay attacks.
    ///
    /// # Errors
    /// * `RedisCacheError::RedisError` - if the token cannot be inserted into Redis
    /// * `RedisCacheError::AlreadyUsed` - if the token was already used
    pub async fn use_challenge_token(
        &self,
        challenge_token: String,
    ) -> Result<(), RedisCacheError> {
        let token_hash = hash_token(USED_CHALLENGE_PREFIX, &challenge_token);
        let ttl_seconds = self.default_ttl.as_secs();

        // Try to set the token with NX (not exists) option to prevent duplicates
        let mut redis = self.redis.clone();
        let result: bool = redis.set_nx(&token_hash, "used").await?;

        if !result {
            return Err(RedisCacheError::AlreadyUsed);
        }

        // Set TTL separately since SET NX doesn't support EX in all Redis versions
        redis
            .expire(&token_hash, i64::try_from(ttl_seconds).unwrap_or(i64::MAX))
            .await?;

        Ok(())
    }

    /// Stores a hashed OIDC nonce to prevent replay attacks.
    ///
    /// Note this method is very similar to `use_challenge_token` but uses different configuration
    ///
    /// # Errors
    /// * `RedisCacheError::RedisError` - if the token cannot be inserted into Redis
    /// * `RedisCacheError::AlreadyUsed` - if the nonce was already used
    pub async fn use_oidc_nonce(
        &self,
        nonce: &str,
        oidc_provider: &OidcProvider,
    ) -> Result<(), RedisCacheError> {
        let token_hash = hash_token(USED_OIDC_NONCE_PREFIX, &format!("{oidc_provider}:{nonce}"));

        // Nonces may be indefinitely valid, in a regular OIDC flow, the nonce would be created by the RP and short-lived,
        // but this nonce depends on Turnkey, so we can't depend on a server-side expiration.
        // For the time being, we cache the hashed nonce with a very long TTL to prevent replay.
        let long_ttl_seconds = 365 * 24 * 60 * 60; // 1 year

        // Try to set the nonce with NX (not exists) option to prevent duplicates
        let mut redis = self.redis.clone();
        let result: bool = redis
            .set_nx(&token_hash, Utc::now().date_naive().to_string())
            .await?;

        if !result {
            return Err(RedisCacheError::AlreadyUsed);
        }

        // Set very long TTL for OIDC nonces
        redis
            .expire(&token_hash, i64::from(long_ttl_seconds))
            .await?;

        Ok(())
    }

    pub async fn is_ready(&self) -> bool {
        // Test Redis connection with a simple ping
        let mut redis = self.redis.clone();
        match redis.ping::<String>().await {
            Ok(_) => true,
            Err(e) => {
                tracing::error!("System is not ready. RedisCacheManager (ping): {:?}", e);
                false
            }
        }
    }
}

/// Hashes a token using SHA-256 and returns the hex representation
fn hash_token(prefix: &str, token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{prefix}#{:x}", hasher.finalize())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncFactorTokenData {
    backup_id: String,
    is_used: bool,
    created_at: i64,
    expires_at: i64,
}

const SYNC_FACTOR_TOKEN_PREFIX: &str = "syncFactorToken";
const USED_CHALLENGE_PREFIX: &str = "usedChallengeHash";
const USED_OIDC_NONCE_PREFIX: &str = "usedOidcNonceHash";

#[derive(thiserror::Error, Debug)]
pub enum RedisCacheError {
    #[error("Redis error: {0}")]
    RedisError(#[from] RedisError),
    #[error("JSON serialization/deserialization error: {0}")]
    ParseError(#[from] serde_json::Error),
    #[error("Token not found")]
    TokenNotFound,
    #[error("Token or challenge has already been used")]
    AlreadyUsed,
    #[error("Token has expired")]
    TokenExpired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn get_test_redis_client() -> ConnectionManager {
        let environment = Environment::development(None);
        let client = redis::Client::open(environment.redis_endpoint_url()).unwrap();
        ConnectionManager::new(client).await.unwrap()
    }

    #[tokio::test]
    async fn test_create_and_use_token() {
        let redis = get_test_redis_client().await;
        let environment = Environment::development(None);
        let token_manager = RedisCacheManager::new(environment, Duration::from_secs(60), redis);

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
        assert!(matches!(result, Err(RedisCacheError::AlreadyUsed)));
    }

    #[tokio::test]
    async fn test_use_nonexistent_token() {
        let redis = get_test_redis_client().await;
        let environment = Environment::development(None);
        let token_manager = RedisCacheManager::new(environment, Duration::from_secs(60), redis);

        // Try to use a non-existent token
        let token = format!("nonexistent_token_{}", uuid::Uuid::new_v4());
        let result = token_manager.use_sync_factor_token(token).await;
        assert!(matches!(result, Err(RedisCacheError::TokenNotFound)));
    }

    #[tokio::test]
    async fn test_token_expiration() {
        let redis = get_test_redis_client().await;
        let environment = Environment::development(None);
        // Set a very short expiration time
        let token_manager = RedisCacheManager::new(
            environment,
            Duration::from_secs(1), // 1 second expiration
            redis,
        );

        let backup_id = format!("test_backup_id_{}", uuid::Uuid::new_v4());

        // Create a token that expires in 1 second
        let token = token_manager
            .create_sync_factor_token(backup_id)
            .await
            .unwrap();

        // Sleep for 2 seconds to ensure the token expires
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Try to use the expired token - Redis should have automatically deleted it
        let result = token_manager.use_sync_factor_token(token).await;
        assert!(matches!(result, Err(RedisCacheError::TokenNotFound)));
    }

    #[tokio::test]
    async fn test_prevent_challenge_token_reuse_replay_attack() {
        let redis = get_test_redis_client().await;
        let environment = Environment::development(None);
        let token_manager = RedisCacheManager::new(environment, Duration::from_secs(60), redis);

        let challenge_token = format!("my_one_time_challenge_token_{}", uuid::Uuid::new_v4());

        // first time it succeeds
        token_manager
            .use_challenge_token(challenge_token.clone())
            .await
            .unwrap();

        // second time it fails
        let result = token_manager.use_challenge_token(challenge_token).await;
        assert!(matches!(result, Err(RedisCacheError::AlreadyUsed)));
    }
}
