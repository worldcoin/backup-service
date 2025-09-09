use crate::types::{Environment, OidcProvider};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use redis::aio::ConnectionManager;
use redis::{AsyncTypedCommands, ExistenceCheck, RedisError, Script, SetExpiry, SetOptions};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// The `RedisCacheManager` introduces a simple and generic cache layer on top of `Redis`.
///
/// # Use Cases
/// - It is used to store tokens that are used to add a sync factor to a backup.
/// - It is also used to prevent replay attacks by storing used challenge tokens.
#[derive(Clone)]
pub struct RedisCacheManager {
    default_ttl: Duration,
    redis: ConnectionManager,
}

impl RedisCacheManager {
    /// Creates a new `RedisCacheManager` instance.
    ///
    /// # Arguments
    /// - `environment`: The environment to use for the `RedisCacheManager`
    /// - `default_ttl`: The default TTL for cached values. Note we could derive this from the environment, but it's useful to be able to override it for testing.
    ///
    /// # Errors
    /// * `RedisError` - if the Redis connection cannot be established
    pub async fn new(environment: Environment, default_ttl: Duration) -> Result<Self, RedisError> {
        let client: redis::Client = redis::Client::open(environment.redis_endpoint_url())?;
        let redis = ConnectionManager::new(client).await?;

        tracing::info!("✅ Redis connection pool built successfully.");

        Ok(Self { default_ttl, redis })
    }

    /// Creates a new sync factor token that allows to update `backup_id` and stores it
    /// in the cache. The token is returned to the caller.
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

        let token_hash = hash_token(SYNC_FACTOR_TOKEN_PREFIX, &token);

        let ttl_seconds = self.default_ttl.as_secs();
        let token_data = SyncFactorTokenData::new(backup_id);
        let mut redis = self.redis.clone();
        redis
            .set_options(
                &token_hash,
                token_data.into_bytes(),
                SetOptions::default()
                    .with_expiration(SetExpiry::EX(ttl_seconds))
                    .conditional_set(ExistenceCheck::NX),
            )
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
    /// The token is a random secret value that's stored hashed in Redis. The token is
    /// issued at retrieval and removed when the sync factor is added. This method retrieves and marks the token as used
    /// in an atomic process to ensure race condition safety.
    ///
    /// # Errors
    /// * `RedisCacheError::RedisError` - if the token cannot be fetched from Redis
    /// * `RedisCacheError::TokenNotFound` - if the token does not exist in the database
    /// * `RedisCacheError::AlreadyUsed` - if the token was already used
    /// * `RedisCacheError::TokenExpired` - if the token has expired
    /// * `RedisCacheError::ParseError` - if the token data cannot be parsed
    pub async fn use_sync_factor_token(&self, token: String) -> Result<String, RedisCacheError> {
        let token_hash = hash_token(SYNC_FACTOR_TOKEN_PREFIX, &token);
        let mut redis = self.redis.clone();

        // Lua script for atomic check-and-set operation
        // Returns:
        // - `-1` if token doesn't exist
        // - `1` if token exists but is already used
        // - `2` and the value of updated data if token exists and was successfully marked as used
        let script = Script::new(
            "
            local key = KEYS[1]
            local data = redis.call('GET', key)

            -- token not found
            if not data or #data == 0 then
                return {-1, \"\"}
            end

            -- already used
            if string.byte(data, 1) == 1 then
                return {1, \"\"}
            end
            
            -- Update the token data while preserving existing TTL
            local updated_data = string.char(1) .. string.sub(data, 2)
            redis.call('SET', key, updated_data, 'KEEPTTL')
            
            return {2, updated_data}
        ",
        );

        let (code, token_data): (i64, Vec<u8>) =
            script.key(&token_hash).invoke_async(&mut redis).await?;

        match code {
            -1 => Err(RedisCacheError::TokenNotFound),
            1 => Err(RedisCacheError::AlreadyUsed),
            2 => {
                let sync_factor_token_data = SyncFactorTokenData::from_bytes(&token_data)?;
                Ok(sync_factor_token_data.backup_id)
            }
            _ => Err(RedisCacheError::EncodingError),
        }
    }

    /// Unmarks a sync factor token as used. This is used to ensure atomicity in the process to add a sync factor.
    ///
    /// If the process of adding the factor to the backup metadata in S3 fails, the token is unmarked as used
    /// to allow the user to try again. This method keeps the existing TTL of the token.
    ///
    /// # Errors
    /// * `RedisCacheError::RedisError` - if the token cannot be updated in Redis
    pub async fn unuse_sync_factor_token(&self, token: String) -> Result<(), RedisCacheError> {
        let token_hash = hash_token(SYNC_FACTOR_TOKEN_PREFIX, &token);
        let mut redis = self.redis.clone();

        // check if the key exists to not store the token otherwise
        // (done so we don't accidentally store the token without a TTL)
        if !redis.exists(&token_hash).await? {
            return Err(RedisCacheError::TokenNotFound);
        }

        redis.setrange(&token_hash, 0, 0).await?;
        Ok(())
    }

    /// Records a hashed challenge token as used in redis to prevent replay attacks.
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
        let result = redis
            .set_options(
                &token_hash,
                true,
                SetOptions::default()
                    .with_expiration(SetExpiry::EX(ttl_seconds))
                    .conditional_set(ExistenceCheck::NX), // critical to ensure tokens are only used once
            )
            .await?;

        if result.is_none() || result.unwrap_or_default() != "OK" {
            return Err(RedisCacheError::AlreadyUsed);
        }

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
        let result = redis
            .set_options(
                &token_hash,
                true,
                SetOptions::default()
                    .with_expiration(SetExpiry::EX(long_ttl_seconds))
                    .conditional_set(ExistenceCheck::NX), // critical to ensure it's only used once
            )
            .await?;

        if result.is_none() || result.unwrap_or_default() != "OK" {
            return Err(RedisCacheError::AlreadyUsed);
        }

        Ok(())
    }

    /// Attempts to acquire a Redis lock and returns a guard that releases it on drop.
    ///
    /// # Errors
    /// * `RedisCacheError::Locked` - if the lock already exists
    /// * `RedisCacheError::RedisError` - if there's an unexpected failure with Redis
    pub async fn try_acquire_lock_guard(
        &self,
        prefix: impl Into<String>,
        identifier: impl Into<String>,
        ttl_seconds: Option<u64>,
    ) -> Result<RedisLockGuard, RedisCacheError> {
        let prefix = prefix.into();
        let identifier = identifier.into();

        RedisLockGuard::new_from_manager(
            self,
            prefix,
            identifier,
            ttl_seconds.unwrap_or(self.default_ttl.as_secs()),
        )
        .await
    }

    pub async fn is_ready(&self) -> bool {
        let mut redis = self.redis.clone();
        match redis.ping().await {
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

/// Stores the authorized `backup_id` and whether the token was used for a sync factor token.
///
/// Sync factor tokens are how operations to add sync factors are authorized.
///
/// Encoded as bytes for efficient Redis operations.
struct SyncFactorTokenData {
    backup_id: String,
    is_used: bool,
}

impl SyncFactorTokenData {
    /// Creates a new `SyncFactorTokenData` with the given `backup_id` and `is_used` set to `false`.
    fn new(backup_id: String) -> Self {
        Self {
            backup_id,
            is_used: false,
        }
    }

    /// Creates byte representation of token data
    fn into_bytes(self) -> Vec<u8> {
        let mut data = Vec::with_capacity(1 + self.backup_id.len());
        data.push(u8::from(self.is_used));
        data.extend_from_slice(self.backup_id.as_bytes());
        data
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, RedisCacheError> {
        if bytes.is_empty() {
            return Err(RedisCacheError::EncodingError);
        }

        let is_used = bytes[0] != 0;
        let backup_id =
            String::from_utf8(bytes[1..].to_vec()).map_err(|_| RedisCacheError::EncodingError)?;
        Ok(Self { backup_id, is_used })
    }
}

const SYNC_FACTOR_TOKEN_PREFIX: &str = "syncFactorToken";
const USED_CHALLENGE_PREFIX: &str = "usedChallengeHash";
const USED_OIDC_NONCE_PREFIX: &str = "usedOidcNonceHash";

#[derive(thiserror::Error, Debug)]
pub enum RedisCacheError {
    #[error("unexpected encoding error")]
    EncodingError,
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
    #[error("Conflicting lock")]
    Locked,
}

/// A guard that releases a Redis lock when dropped.
pub struct RedisLockGuard {
    redis: ConnectionManager,
    prefix: String,
    identifier: String,
    released: bool,
}

impl RedisLockGuard {
    async fn new_from_manager(
        manager: &RedisCacheManager,
        prefix: String,
        identifier: String,
        ttl_seconds: u64,
    ) -> Result<Self, RedisCacheError> {
        let mut redis = manager.redis.clone();

        let lock_options = SetOptions::default()
            .conditional_set(ExistenceCheck::NX)
            .with_expiration(SetExpiry::EX(ttl_seconds));

        let result = redis
            .set_options::<String, bool>(format!("lock#{prefix}#{identifier}"), true, lock_options)
            .await?;

        let acquired = result.is_some() && result.unwrap_or_default() == "OK";

        if !acquired {
            return Err(RedisCacheError::Locked);
        }

        Ok(Self {
            redis,
            prefix,
            identifier,
            released: false,
        })
    }

    /// Explicitly releases the lock. Safe to call multiple times.
    ///
    /// # Errors
    /// * `RedisCacheError::RedisError` - if there's a failure with Redis
    pub async fn release(&mut self) -> Result<(), RedisCacheError> {
        if !self.released {
            let mut redis = self.redis.clone();
            redis.del(self.as_key()).await?;
            self.released = true;
        }
        Ok(())
    }

    fn as_key(&self) -> String {
        format!("lock#{}#{}", self.prefix, self.identifier)
    }
}

impl Drop for RedisLockGuard {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let mut redis = self.redis.clone();
        let key = self.as_key();
        // Best-effort release as `Drop` cannot be async.
        tokio::spawn(async move {
            if let Err(e) = redis.del(key).await {
                tracing::error!(
                    message = "Failed to release Redis lock in Drop",
                    error = ?e
                );
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_create_and_use_token() {
        let environment = Environment::development(None);
        let token_manager = RedisCacheManager::new(environment, environment.cache_default_ttl())
            .await
            .unwrap();

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
        let environment = Environment::development(None);
        let token_manager = RedisCacheManager::new(environment, environment.cache_default_ttl())
            .await
            .unwrap();

        // Try to use a non-existent token
        let token = format!("nonexistent_token_{}", uuid::Uuid::new_v4());
        let result = token_manager.use_sync_factor_token(token).await;
        assert!(matches!(result, Err(RedisCacheError::TokenNotFound)));
    }

    #[tokio::test]
    async fn test_token_expiration() {
        let environment = Environment::development(None);
        // Set a very short expiration time
        let token_manager = RedisCacheManager::new(environment, Duration::from_secs(1))
            .await
            .unwrap();

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
        let environment = Environment::development(None);
        let token_manager = RedisCacheManager::new(environment, environment.cache_default_ttl())
            .await
            .unwrap();

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

    #[tokio::test]
    async fn test_no_race_conditions_on_concurrent_sync_token_usage() {
        let environment = Environment::development(None);
        let token_manager = RedisCacheManager::new(environment, environment.cache_default_ttl())
            .await
            .unwrap();

        let backup_id = format!("test_backup_id_{}", uuid::Uuid::new_v4());

        let token = token_manager
            .create_sync_factor_token(backup_id.clone())
            .await
            .unwrap();

        // Spawn 10 concurrent tasks that all try to use the same token
        let mut handles = Vec::new();
        for i in 0..10 {
            let token_manager_clone = token_manager.clone();
            let token_clone = token.clone();
            let handle = tokio::spawn(async move {
                (
                    i,
                    token_manager_clone.use_sync_factor_token(token_clone).await,
                )
            });
            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            let (_task_id, result) = handle.await.unwrap();
            results.push(result);
        }

        let mut success_count = 0;
        let mut already_used_count = 0;

        for result in results {
            match result {
                Ok(_) => {
                    success_count += 1;
                }
                Err(RedisCacheError::AlreadyUsed) => {
                    already_used_count += 1;
                }
                Err(other_error) => {
                    panic!("Unexpected error: {other_error:?}");
                }
            }
        }

        assert_eq!(success_count, 1);
        assert_eq!(already_used_count, 9);
    }
}
