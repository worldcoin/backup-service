use crate::environment::Environment;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{AsyncTypedCommands, ExistenceCheck, RedisError, Script, SetExpiry, SetOptions};
use sha2::{Digest, Sha256};
use std::time::Duration;
use types::OidcProvider;

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
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Duration::from_secs(3))
            .set_response_timeout(Duration::from_secs(3))
            .set_number_of_retries(3)
            .set_exponent_base(2)
            .set_factor(100)
            .set_max_delay(5000);
        let redis = ConnectionManager::new_with_config(client, config).await?;

        tracing::info!("Redis connection pool built successfully.");

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

        // Try to set the nonce with NX (not exists) option to prevent duplicates
        let mut redis = self.redis.clone();
        let result = redis
            .set_options(
                &token_hash,
                true,
                SetOptions::default()
                    .with_expiration(SetExpiry::EX(OIDC_NONCE_TTL_SECONDS))
                    .conditional_set(ExistenceCheck::NX), // critical to ensure it's only used once
            )
            .await?;

        if result.is_none() || result.unwrap_or_default() != "OK" {
            return Err(RedisCacheError::AlreadyUsed);
        }

        Ok(())
    }

    /// Whether a challenge token has already been consumed. Read-only.
    ///
    /// # Errors
    /// * `RedisCacheError::RedisError` - if Redis cannot be queried
    pub async fn is_challenge_token_used(
        &self,
        challenge_token: &str,
    ) -> Result<bool, RedisCacheError> {
        let mut redis = self.redis.clone();
        Ok(redis
            .exists(hash_token(USED_CHALLENGE_PREFIX, challenge_token))
            .await?)
    }

    /// Whether an OIDC nonce has already been consumed. Read-only.
    ///
    /// # Errors
    /// * `RedisCacheError::RedisError` - if Redis cannot be queried
    pub async fn is_oidc_nonce_used(
        &self,
        nonce: &str,
        oidc_provider: &OidcProvider,
    ) -> Result<bool, RedisCacheError> {
        let mut redis = self.redis.clone();
        Ok(redis
            .exists(hash_token(
                USED_OIDC_NONCE_PREFIX,
                &format!("{oidc_provider}:{nonce}"),
            ))
            .await?)
    }

    /// Marks every key in `keys` as used, or none of them.
    ///
    /// Add-factor consumes two challenge tokens and up to two OIDC nonces at a single commit
    /// point; burning them one by one would let a failure (or a dropped request) in between waste
    /// an approval the user already gave. A Lua script runs atomically in Redis, so the
    /// existence check and the writes cannot interleave with any other command. Keys and TTLs are
    /// the same as [`Self::use_challenge_token`] / [`Self::use_oidc_nonce`], so a value burned
    /// here is seen as used by every other flow and vice versa. Duplicate keys are rejected: two
    /// different ID tokens carrying the same nonce must fail exactly as two sequential burns do.
    ///
    /// # Errors
    /// * `RedisCacheError::AlreadyUsed` - if any key was already used, or two keys are identical;
    ///   nothing was written
    /// * `RedisCacheError::RedisError` - if the script cannot be run
    pub async fn burn_all_or_nothing(&self, keys: &[BurnKey]) -> Result<(), RedisCacheError> {
        if keys.is_empty() {
            return Ok(());
        }

        let script = Script::new(BURN_ALL_OR_NOTHING_SCRIPT);
        let mut invocation = script.prepare_invoke();
        for key in keys {
            invocation.key(key.redis_key());
        }
        for key in keys {
            invocation.arg(key.ttl_seconds(self.default_ttl));
        }

        let mut redis = self.redis.clone();
        let outcome: i64 = invocation.invoke_async(&mut redis).await?;
        match outcome {
            BURN_OUTCOME_OK => Ok(()),
            BURN_OUTCOME_ALREADY_USED => Err(RedisCacheError::AlreadyUsed),
            BURN_OUTCOME_DUPLICATE_KEY => {
                // A client bug or misuse (e.g. two different ID tokens minted on one session
                // keypair), not a replay — but it must fail the same way two sequential burns would.
                tracing::warn!(
                    message =
                        "Rejected single-use commit: the same key appears twice in one request",
                    key_count = keys.len(),
                );
                Err(RedisCacheError::AlreadyUsed)
            }
            other => {
                tracing::error!(
                    message = "Single-use commit script returned an unexpected outcome",
                    outcome = other,
                );
                Err(RedisCacheError::EncodingError)
            }
        }
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

/// Nonces may be indefinitely valid: in a regular OIDC flow the nonce would be created by the RP
/// and short-lived, but this nonce depends on Turnkey, so there is no server-side expiration to
/// lean on. The hashed nonce is kept for a very long time instead.
const OIDC_NONCE_TTL_SECONDS: u64 = 365 * 24 * 60 * 60;

/// A single-use value consumed by [`RedisCacheManager::burn_all_or_nothing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BurnKey {
    /// A challenge token, as passed to [`RedisCacheManager::use_challenge_token`].
    ChallengeToken(String),
    /// An OIDC ID token nonce, as passed to [`RedisCacheManager::use_oidc_nonce`].
    OidcNonce {
        /// The provider that issued the token.
        provider: OidcProvider,
        /// The token's nonce claim.
        nonce: String,
    },
}

impl BurnKey {
    fn redis_key(&self) -> String {
        match self {
            Self::ChallengeToken(challenge_token) => {
                hash_token(USED_CHALLENGE_PREFIX, challenge_token)
            }
            Self::OidcNonce { provider, nonce } => {
                hash_token(USED_OIDC_NONCE_PREFIX, &format!("{provider}:{nonce}"))
            }
        }
    }

    fn ttl_seconds(&self, default_ttl: Duration) -> u64 {
        match self {
            Self::ChallengeToken(_) => default_ttl.as_secs(),
            Self::OidcNonce { .. } => OIDC_NONCE_TTL_SECONDS,
        }
    }
}

const BURN_OUTCOME_OK: i64 = 0;
const BURN_OUTCOME_ALREADY_USED: i64 = 1;
const BURN_OUTCOME_DUPLICATE_KEY: i64 = 2;

/// `KEYS[i]` is a hashed single-use key and `ARGV[i]` its TTL in seconds. Returns `1` if any key
/// already exists, `2` if two keys are identical, `0` after writing all of them. Redis runs the
/// whole script atomically, so a non-zero return means nothing was written.
///
/// The keys share no hash tag, which is fine on the single-node Redis this service uses; a move to
/// cluster mode would make this multi-key script fail with `CROSSSLOT` and would need the key
/// layout (shared with the single-key `use_*` methods) revisited first.
const BURN_ALL_OR_NOTHING_SCRIPT: &str = "
    for i = 1, #KEYS do
        for j = 1, i - 1 do
            if KEYS[j] == KEYS[i] then
                return 2
            end
        end
        if redis.call('EXISTS', KEYS[i]) == 1 then
            return 1
        end
    end
    for i = 1, #KEYS do
        redis.call('SET', KEYS[i], '1', 'EX', ARGV[i])
    end
    return 0
";

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

/// Atomically deletes a lock key only when its value matches the owner token.
/// Prevents a stale guard (after TTL expiry) from deleting a newer holder's lock.
const RELEASE_LOCK_IF_OWNER_SCRIPT: &str = r"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
else
    return 0
end
";

/// A guard that releases a Redis lock when dropped.
pub struct RedisLockGuard {
    redis: ConnectionManager,
    prefix: String,
    identifier: String,
    owner_token: String,
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

        let owner_token = uuid::Uuid::new_v4().to_string();

        let result = redis
            .set_options::<String, String>(
                format!("lock#{prefix}#{identifier}"),
                owner_token.clone(),
                lock_options,
            )
            .await?;

        let acquired = result.is_some() && result.unwrap_or_default() == "OK";

        if !acquired {
            return Err(RedisCacheError::Locked);
        }

        Ok(Self {
            redis,
            prefix,
            identifier,
            owner_token,
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
            let _: i32 = Script::new(RELEASE_LOCK_IF_OWNER_SCRIPT)
                .key(self.as_key())
                .arg(&self.owner_token)
                .invoke_async(&mut redis)
                .await?;
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
        let owner_token = self.owner_token.clone();
        // Best-effort release as `Drop` cannot be async.
        tokio::spawn(async move {
            let result: Result<i32, RedisError> = Script::new(RELEASE_LOCK_IF_OWNER_SCRIPT)
                .key(key)
                .arg(owner_token)
                .invoke_async(&mut redis)
                .await;

            if let Err(e) = result {
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

    /// Stale lock guards must not delete a newer holder's lock after TTL expiry.
    #[tokio::test]
    async fn test_stale_lock_guard_cannot_delete_newer_lock_on_release() {
        let environment = Environment::development(None);
        let cache = RedisCacheManager::new(environment, Duration::from_mins(1))
            .await
            .unwrap();

        let prefix = "stale_lock_release_test";
        let identifier = uuid::Uuid::new_v4().to_string();

        // Acquire lock A with a short TTL, then let it expire.
        let mut stale_guard = cache
            .try_acquire_lock_guard(prefix, identifier.clone(), Some(1))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;

        // A newer holder acquires the same lock key.
        let mut current_guard = cache
            .try_acquire_lock_guard(prefix, identifier.clone(), Some(60))
            .await
            .unwrap();

        // Releasing the stale guard must leave the current holder's lock intact.
        stale_guard.release().await.unwrap();
        assert!(matches!(
            cache
                .try_acquire_lock_guard(prefix, identifier.clone(), Some(60))
                .await,
            Err(RedisCacheError::Locked)
        ));

        current_guard.release().await.unwrap();
    }

    /// Same safety property via the `Drop` best-effort release path.
    #[tokio::test]
    async fn test_stale_lock_guard_cannot_delete_newer_lock_on_drop() {
        let environment = Environment::development(None);
        let cache = RedisCacheManager::new(environment, Duration::from_mins(1))
            .await
            .unwrap();

        let prefix = "stale_lock_drop_test";
        let identifier = uuid::Uuid::new_v4().to_string();

        let stale_guard = cache
            .try_acquire_lock_guard(prefix, identifier.clone(), Some(1))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;

        let mut current_guard = cache
            .try_acquire_lock_guard(prefix, identifier.clone(), Some(60))
            .await
            .unwrap();

        drop(stale_guard);
        // Allow the Drop spawn to finish its compare-and-delete attempt.
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(matches!(
            cache
                .try_acquire_lock_guard(prefix, identifier.clone(), Some(60))
                .await,
            Err(RedisCacheError::Locked)
        ));

        current_guard.release().await.unwrap();
    }
}

#[cfg(test)]
mod burn_tests {
    use super::*;

    async fn manager() -> RedisCacheManager {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::development(None);
        RedisCacheManager::new(environment, environment.cache_default_ttl())
            .await
            .unwrap()
    }

    fn fresh_token() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    #[tokio::test]
    async fn burn_all_or_nothing_writes_every_key_and_is_visible_to_single_key_burns() {
        let manager = manager().await;
        let (token_a, token_b, nonce) = (fresh_token(), fresh_token(), fresh_token());
        let keys = [
            BurnKey::ChallengeToken(token_a.clone()),
            BurnKey::ChallengeToken(token_b.clone()),
            BurnKey::OidcNonce {
                provider: OidcProvider::Google,
                nonce: nonce.clone(),
            },
        ];

        manager.burn_all_or_nothing(&keys).await.unwrap();

        assert!(manager.is_challenge_token_used(&token_a).await.unwrap());
        assert!(manager.is_challenge_token_used(&token_b).await.unwrap());
        assert!(manager
            .is_oidc_nonce_used(&nonce, &OidcProvider::Google)
            .await
            .unwrap());
        // Same provider-qualified key layout as `use_oidc_nonce`: a different provider is a
        // different nonce.
        assert!(!manager
            .is_oidc_nonce_used(&nonce, &OidcProvider::Apple)
            .await
            .unwrap());
        assert!(matches!(
            manager.use_challenge_token(token_a).await,
            Err(RedisCacheError::AlreadyUsed)
        ));
        assert!(matches!(
            manager.use_oidc_nonce(&nonce, &OidcProvider::Google).await,
            Err(RedisCacheError::AlreadyUsed)
        ));
        assert!(matches!(
            manager.burn_all_or_nothing(&keys[1..2]).await,
            Err(RedisCacheError::AlreadyUsed)
        ));
    }

    #[tokio::test]
    async fn burn_all_or_nothing_writes_nothing_when_any_key_is_already_used() {
        let manager = manager().await;
        let (fresh, used) = (fresh_token(), fresh_token());
        manager.use_challenge_token(used.clone()).await.unwrap();

        let result = manager
            .burn_all_or_nothing(&[
                BurnKey::ChallengeToken(fresh.clone()),
                BurnKey::OidcNonce {
                    provider: OidcProvider::Apple,
                    nonce: fresh.clone(),
                },
                BurnKey::ChallengeToken(used),
            ])
            .await;

        assert!(matches!(result, Err(RedisCacheError::AlreadyUsed)));
        assert!(!manager.is_challenge_token_used(&fresh).await.unwrap());
        assert!(!manager
            .is_oidc_nonce_used(&fresh, &OidcProvider::Apple)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn burn_all_or_nothing_rejects_duplicate_keys_without_writing() {
        let manager = manager().await;
        let nonce = fresh_token();
        let duplicate = BurnKey::OidcNonce {
            provider: OidcProvider::Google,
            nonce: nonce.clone(),
        };

        let result = manager
            .burn_all_or_nothing(&[
                BurnKey::ChallengeToken(fresh_token()),
                duplicate.clone(),
                duplicate,
            ])
            .await;

        assert!(matches!(result, Err(RedisCacheError::AlreadyUsed)));
        assert!(!manager
            .is_oidc_nonce_used(&nonce, &OidcProvider::Google)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn burn_all_or_nothing_with_no_keys_is_a_noop() {
        manager().await.burn_all_or_nothing(&[]).await.unwrap();
    }
}
