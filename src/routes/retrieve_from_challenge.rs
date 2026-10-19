use std::collections::HashMap;
use std::sync::Arc;

use crate::auth::{AuthHandler, AuthenticationResult};
use crate::backup_metadata::BackupMetadata;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
use crate::error::ErrorResponse;
use crate::factor_lookup::FactorLookup;
use crate::headers::CLIENT_VERSION;
use crate::redis_cache::RedisCacheManager;
use aide::transform::TransformOperation;
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http::HeaderMap;
use tracing::Instrument;
use types::{FactorScope, RetrieveBackupFromChallengeRequest, RetrieveBackupFromChallengeResponse};

/// Outcome of reading sync factors' last use during recovery (`ok`, `error`, `timeout`).
const SYNC_FACTOR_LAST_USED_READ_METRIC: &str = "sync_factor_last_used_read_total";

const SYNC_FACTOR_LAST_USED_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

pub fn docs(op: TransformOperation) -> TransformOperation {
    op.description(
        "Request to retrieve a full backup (ciphertext) with an authenticated challenge. This endpoint requires Attestation Gateway checks (through the `attestation-token` header).",
    )
    .security_requirement("AttestationToken")
}

/// Request to retrieve a backup using a solved challenge.
pub async fn handler(
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(redis_cache_manager): Extension<Arc<RedisCacheManager>>,
    Extension(auth_handler): Extension<AuthHandler>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    headers: HeaderMap,
    request: Json<RetrieveBackupFromChallengeRequest>,
) -> Result<Json<RetrieveBackupFromChallengeResponse>, ErrorResponse> {
    // Step 1: Auth. Verify the solved challenge
    let AuthenticationResult {
        backup_id,
        backup_metadata,
        ..
    } = auth_handler
        .verify(
            &request.authorization,
            FactorScope::Main,
            ChallengeContext::Retrieve {},
            request.challenge_token.clone(),
        )
        .await?;

    let client_version = headers
        .get(&CLIENT_VERSION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let span = tracing::info_span!("retrieve_backup_from_challenge", backup_id = %backup_id, client_version = %client_version);

    async move {
        // Step 2: Fetch the backup from S3
        let backup = backup_storage.get_backup_by_backup_id(&backup_id).await?;
        let Some(backup) = backup else {
            tracing::error!(message = "No backup found for the verified backup ID.");
            return Err(ErrorResponse::internal_server_error());
        };

        // Step 3: Create a sync factor token to allow the user to add a new sync factor later
        let sync_factor_token = redis_cache_manager
            .create_sync_factor_token(backup_metadata.id.clone())
            .await?;

        // Step 4: Return the backup and metadata
        let last_used = sync_factors_last_used(&factor_lookup, &backup_metadata).await;
        let mut metadata = backup_metadata.exported();
        for factor in &mut metadata.sync_factors {
            factor.last_used_at = last_used.get(&factor.id).copied();
        }

        Ok(Json(RetrieveBackupFromChallengeResponse {
            backup: STANDARD.encode(backup),
            metadata,
            sync_factor_token,
        }))
    }
    .instrument(span)
    .await
}

/// Reads each sync factor's last use so a client at the sync-factor cap can replace the least
/// recently used access. Best-effort and bounded: on failure it is empty and the client falls back
/// to creation time, so recovery itself never fails here.
async fn sync_factors_last_used(
    factor_lookup: &FactorLookup,
    backup_metadata: &BackupMetadata,
) -> HashMap<String, i64> {
    let read =
        factor_lookup.sync_factors_last_used(&backup_metadata.sync_factors, &backup_metadata.id);
    match tokio::time::timeout(SYNC_FACTOR_LAST_USED_READ_TIMEOUT, read).await {
        Ok(Ok(last_used)) => {
            metrics::counter!(SYNC_FACTOR_LAST_USED_READ_METRIC, "result" => "ok").increment(1);
            last_used
        }
        Ok(Err(err)) => {
            metrics::counter!(SYNC_FACTOR_LAST_USED_READ_METRIC, "result" => "error").increment(1);
            tracing::warn!(?err, "Failed to read sync factors' last use; omitting it");
            HashMap::new()
        }
        Err(_) => {
            metrics::counter!(SYNC_FACTOR_LAST_USED_READ_METRIC, "result" => "timeout")
                .increment(1);
            tracing::warn!(
                timeout_ms = SYNC_FACTOR_LAST_USED_READ_TIMEOUT.as_millis(),
                "Timed out reading sync factors' last use; omitting it"
            );
            HashMap::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use mockito::{Matcher, Server};
    use serde_json::json;

    use crate::backup_metadata::{BackupMetadata, Factor};
    use crate::environment::Environment;
    use crate::factor_lookup::test_factor_lookup;
    use crate::routes::retrieve_from_challenge::{
        sync_factors_last_used, SYNC_FACTOR_LAST_USED_READ_TIMEOUT,
    };

    fn backup_with_sync_keys(public_keys: &[&str]) -> BackupMetadata {
        BackupMetadata {
            id: "backup".to_string(),
            factors: vec![],
            sync_factors: public_keys
                .iter()
                .map(|key| Factor::new_ec_keypair((*key).to_string()))
                .collect(),
            keys: vec![],
            manifest_hash: String::new(),
        }
    }

    #[tokio::test]
    async fn partial_batch_read_reports_no_last_use() {
        let table = Environment::development(None).factor_lookup_dynamodb_table_name();
        let mut dynamo = Server::new_async().await;
        let _partial = dynamo
            .mock("POST", Matcher::Any)
            .with_header("content-type", "application/x-amz-json-1.0")
            .with_body(
                json!({
                    "Responses": {(table.clone()): [{
                        "PK": {"S": "SYNC#EC_KEYPAIR|used"},
                        "BackupId": {"S": "backup"},
                        "LastUsedAt": {"N": "1700000000"},
                    }]},
                    "UnprocessedKeys": {(table): {
                        "Keys": [{"PK": {"S": "SYNC#EC_KEYPAIR|throttled"}}],
                    }},
                })
                .to_string(),
            )
            .create_async()
            .await;
        let lookup = test_factor_lookup(Some(dynamo.url())).await;

        let last_used =
            sync_factors_last_used(&lookup, &backup_with_sync_keys(&["used", "throttled"])).await;

        assert!(
            last_used.is_empty(),
            "a partial read would make the throttled factor look unused"
        );
    }

    #[tokio::test]
    async fn hung_read_reports_no_last_use_at_its_timeout() {
        // Accepts connections but never answers, so the read hangs.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let lookup =
            test_factor_lookup(Some(format!("http://{}", silent.local_addr().unwrap()))).await;
        let started = std::time::Instant::now();

        let last_used = tokio::time::timeout(
            SYNC_FACTOR_LAST_USED_READ_TIMEOUT * 2,
            sync_factors_last_used(&lookup, &backup_with_sync_keys(&["key"])),
        )
        .await
        .expect("the read must not hold up recovery");

        assert!(last_used.is_empty());
        assert!(started.elapsed() >= SYNC_FACTOR_LAST_USED_READ_TIMEOUT);
    }
}
