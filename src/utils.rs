use axum::body::Bytes;
use axum::extract::multipart::MultipartError;
use axum::extract::Multipart;
use redis::aio::ConnectionManager;
use redis::{AsyncTypedCommands, ExistenceCheck, RedisError, SetExpiry, SetOptions};
use std::collections::HashMap;

/// Extracts fields from a multipart request to a `HashMap` for easy access.
///
/// # Errors
/// Returns `MultipartError` if the multipart request is invalid.
pub async fn extract_fields_from_multipart(
    multipart: &mut Multipart,
) -> Result<HashMap<String, Bytes>, MultipartError> {
    let mut fields = HashMap::new();
    while let Some(field) = multipart.next_field().await? {
        let name = field.name().unwrap_or_default().to_string();
        let value = field.bytes().await?;
        fields.insert(name, value);
    }
    Ok(fields)
}

/// Sets a lock in Redis for a given identifier.
///
/// # Errors
/// Returns `RedisError` if the lock cannot be set in Redis.
pub async fn set_redis_lock(
    prefix: &str,
    identifier: &str,
    ttl_seconds: u64,
    redis: &mut ConnectionManager,
) -> Result<bool, RedisError> {
    let request_hash_lock_options = SetOptions::default()
        .conditional_set(ExistenceCheck::NX)
        .with_expiration(SetExpiry::EX(ttl_seconds));

    let result = redis
        .set_options::<String, bool>(
            format!("{prefix}{identifier}"),
            true,
            request_hash_lock_options,
        )
        .await?;

    let lock_set = result.is_some() && result.unwrap_or_default() == "OK";

    Ok(lock_set)
}

/// Releases a lock in Redis for a given identifier.
///
/// Will not return an error if the lock does not exist.
///
/// # Errors
/// Returns `RedisError` if the lock cannot be released in Redis.
pub async fn release_redis_lock(
    prefix: &str,
    identifier: &str,
    redis: &mut ConnectionManager,
) -> Result<(), RedisError> {
    redis.del(format!("{prefix}{identifier}")).await?;
    Ok(())
}
