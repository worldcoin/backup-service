//! Storage contracts run against loopback AWS mocks. Tests named `redis_` additionally require
//! the isolated Redis sidecar; no test in this file contacts AWS or an attestation service.
mod common;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use axum::{body::Body, http::Request, Extension};
use backup_service::{
    backup_metadata::{BackupMetadata, Factor},
    backup_storage::{BackupManagerError, BackupStorage},
    environment::Environment,
    factor_lookup::FactorLookup,
    redis_cache::RedisCacheManager,
};
use chrono::Utc;
use http_body_util::BodyExt;
use mockito::{Matcher, Server, ServerGuard};
use serde_json::json;
use tower::ServiceExt;
use types::{BackupEncryptionKey, Endpoint, ReclaimSyncFactorSlotRequest};

fn metadata(count: usize, stale: bool) -> BackupMetadata {
    let now = Utc::now();
    let fixture = uuid::Uuid::new_v4();
    let sync_factors = (0..count)
        .map(|i| {
            let mut f = Factor::new_ec_keypair(format!("{fixture}-sync-{i}"));
            f.id = format!("sync-{i:02}");
            f.created_at = now - chrono::Duration::days(if stale { 366 } else { 364 });
            f
        })
        .collect();
    let mut main = Factor::new_ec_keypair("main-key".to_string());
    main.created_at = now - chrono::Duration::days(1000);
    BackupMetadata {
        id: "backup-a".to_string(),
        factors: vec![main],
        sync_factors,
        keys: vec![BackupEncryptionKey::Prf {
            encrypted_key: "encrypted".to_string(),
        }],
        manifest_hash: "ab".repeat(32),
    }
}

fn storage(server: &ServerGuard) -> Arc<BackupStorage> {
    let config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            "test", "test", None, None, "test",
        ))
        .endpoint_url(server.url())
        .force_path_style(true)
        .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
        .build();
    Arc::new(BackupStorage::new(
        Environment::development(None),
        Arc::new(aws_sdk_s3::Client::from_conf(config)),
    ))
}

fn metadata_path() -> String {
    format!(
        "/{}/backup-a/metadata",
        Environment::development(None).s3_bucket()
    )
}

#[tokio::test]
async fn storage_cap_boundaries_preserve_main_keys_and_remove_at_most_one() {
    for count in [24, 25, 26] {
        let mut server = Server::new_async().await;
        let before = metadata(count, true);
        let mut after = before.clone();
        let removed = after.sync_factors.remove(0);
        let read = server
            .mock("GET", metadata_path().as_str())
            .match_query(Matcher::Any)
            .with_header("etag", "\"v1\"")
            .with_body(serde_json::to_vec(&before).unwrap())
            .create_async()
            .await;
        let write = server
            .mock("PUT", metadata_path().as_str())
            .match_query(Matcher::Any)
            .match_header("if-match", "\"v1\"")
            .match_body(Matcher::Json(serde_json::to_value(&after).unwrap()))
            .with_status(200)
            .expect(usize::from(count >= 25))
            .create_async()
            .await;
        let result = storage(&server)
            .reclaim_stale_sync_factor_slot("backup-a")
            .await
            .unwrap();
        if count < 25 {
            assert!(result.is_none());
        } else {
            let (actual_removed, actual_metadata) = result.unwrap();
            assert_eq!(actual_removed, removed);
            assert_eq!(actual_metadata, after);
        }
        read.assert_async().await;
        write.assert_async().await;
    }
}

#[tokio::test]
async fn storage_no_eligible_factor_never_writes() {
    let mut server = Server::new_async().await;
    let read = server
        .mock("GET", metadata_path().as_str())
        .match_query(Matcher::Any)
        .with_header("etag", "\"v1\"")
        .with_body(serde_json::to_vec(&metadata(25, false)).unwrap())
        .create_async()
        .await;
    let write = server
        .mock("PUT", Matcher::Any)
        .expect(0)
        .create_async()
        .await;
    assert!(storage(&server)
        .reclaim_stale_sync_factor_slot("backup-a")
        .await
        .unwrap()
        .is_none());
    read.assert_async().await;
    write.assert_async().await;
}

#[tokio::test]
async fn storage_missing_etag_fails_closed() {
    let mut server = Server::new_async().await;
    let read = server
        .mock("GET", metadata_path().as_str())
        .match_query(Matcher::Any)
        .with_body(serde_json::to_vec(&metadata(25, true)).unwrap())
        .create_async()
        .await;
    let write = server
        .mock("PUT", Matcher::Any)
        .expect(0)
        .create_async()
        .await;
    assert!(matches!(
        storage(&server)
            .reclaim_stale_sync_factor_slot("backup-a")
            .await,
        Err(BackupManagerError::ETagNotFound)
    ));
    read.assert_async().await;
    write.assert_async().await;
}

#[tokio::test]
async fn storage_cas_conflict_is_not_retried_against_new_metadata() {
    let mut server = Server::new_async().await;
    let read = server
        .mock("GET", metadata_path().as_str())
        .match_query(Matcher::Any)
        .with_header("etag", "\"v1\"")
        .with_body(serde_json::to_vec(&metadata(25, true)).unwrap())
        .expect(1)
        .create_async()
        .await;
    let write = server
        .mock("PUT", metadata_path().as_str())
        .match_query(Matcher::Any)
        .match_header("if-match", "\"v1\"")
        .with_status(412)
        .with_body("<Error><Code>PreconditionFailed</Code></Error>")
        .expect(1)
        .create_async()
        .await;
    assert!(matches!(
        storage(&server)
            .reclaim_stale_sync_factor_slot("backup-a")
            .await,
        Err(BackupManagerError::PutObjectError(_))
    ));
    read.assert_async().await;
    write.assert_async().await;
}

async fn redis_app(server: &ServerGuard) -> (axum::Router, Arc<RedisCacheManager>) {
    let environment = Environment::development(None);
    let redis = Arc::new(
        RedisCacheManager::new(environment, Duration::from_mins(1))
            .await
            .unwrap(),
    );
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version_latest()
        .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
            "test", "test", None, None, "test",
        ))
        .endpoint_url(server.url())
        .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::disabled())
        .build();
    let lookup = Arc::new(FactorLookup::new(
        environment,
        Arc::new(aws_sdk_dynamodb::Client::from_conf(config)),
    ));
    let app = backup_service::routes::handler(environment)
        .finish_api(&mut Default::default())
        .layer(Extension(environment))
        .layer(Extension(storage(server)))
        .layer(Extension(lookup))
        .layer(Extension(redis.clone()));
    (app, redis)
}

async fn reclaim(app: axum::Router, token: &str) -> (http::StatusCode, serde_json::Value) {
    // Sign each exact request and serve its public key locally. This exercises attestation
    // without setting process-wide environment or depending on a configured bypass token.
    let body = json!({"syncFactorMaintenanceToken": token});
    let (jwk, jwt) =
        common::generate_test_attestation_token(&body, ReclaimSyncFactorSlotRequest::PATH);
    let mut attestation_server = Server::new_async().await;
    let mut public_key = serde_json::to_value(jwk.to_public_key().unwrap()).unwrap();
    public_key["kid"] = json!("integration-test-kid");
    let jwks = attestation_server
        .mock("GET", "/.well-known/jwks.json")
        .with_header("content-type", "application/json")
        .with_body(json!({"keys": [public_key]}).to_string())
        .expect(1)
        .create_async()
        .await;
    let gateway = backup_service::attestation_gateway::AttestationGateway::new(
        attestation_server.url(),
        &Environment::development(None),
        false,
    );
    let response = app
        .layer(Extension(Arc::new(gateway)))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(ReclaimSyncFactorSlotRequest::PATH)
                .header("content-type", "application/json")
                .header("attestation-token", jwt)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    jwks.assert_async().await;
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn redis_invalid_tokens_never_touch_storage_or_consume_registration() {
    let mut server = Server::new_async().await;
    let mut no_io = Vec::new();
    for method in ["GET", "PUT", "POST"] {
        no_io.push(
            server
                .mock(method, Matcher::Any)
                .expect(0)
                .create_async()
                .await,
        );
    }
    let (app, redis) = redis_app(&server).await;
    let registration = redis
        .create_sync_factor_token("backup-a".to_string())
        .await
        .unwrap();
    for token in ["", "missing", registration.as_str()] {
        let (status, error) = reclaim(app.clone(), token).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST);
        assert_eq!(error["error"]["code"], "token_not_found");
    }
    assert_eq!(
        redis.use_sync_factor_token(registration).await.unwrap(),
        "backup-a"
    );
    for request in no_io {
        request.assert_async().await;
    }
}

#[tokio::test]
async fn redis_replay_and_concurrent_use_allow_only_one_metadata_write() {
    let mut server = Server::new_async().await;
    let before = metadata(25, true);
    let mut after = before.clone();
    let removed = after.sync_factors.remove(0);
    let calls = AtomicUsize::new(0);
    let read = server
        .mock("GET", metadata_path().as_str())
        .match_query(Matcher::Any)
        .with_header("etag", "\"v1\"")
        .with_body_from_request(move |_| {
            serde_json::to_vec(if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                &before
            } else {
                &after
            })
            .unwrap()
        })
        .expect(2)
        .create_async()
        .await;
    let write = server
        .mock("PUT", metadata_path().as_str())
        .match_query(Matcher::Any)
        .match_header("if-match", "\"v1\"")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;
    let delete = server.mock("POST", "/")
        .match_header("x-amz-target", "DynamoDB_20120810.DeleteItem")
        .match_body(Matcher::PartialJson(json!({
            "Key": {"PK": {"S": format!("SYNC#{}", removed.as_factor_to_lookup(&Environment::development(None)).primary_key())}},
            "ConditionExpression": "#backup_id = :backup_id",
            "ExpressionAttributeValues": {":backup_id": {"S": "backup-a"}}
        })))
        .with_header("content-type", "application/x-amz-json-1.0")
        .with_body("{}").expect(1).create_async().await;
    let (app, redis) = redis_app(&server).await;
    let token = redis
        .create_sync_factor_maintenance_token("backup-a".to_string())
        .await
        .unwrap();
    let results = futures::future::join_all((0..10).map(|_| reclaim(app.clone(), &token))).await;
    assert_eq!(
        results
            .iter()
            .filter(|(status, body)| status.is_success() && body["reclaimed"] == true)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|(status, _)| !status.is_success())
            .count(),
        9
    );
    assert!(!reclaim(app, &token).await.0.is_success());
    read.assert_async().await;
    write.assert_async().await;
    delete.assert_async().await;
}

#[tokio::test]
async fn redis_cleanup_does_not_delete_a_reregistered_factor() {
    let mut server = Server::new_async().await;
    // The second read simulates re-registration landing between reclaim's CAS and cleanup.
    let read = server
        .mock("GET", metadata_path().as_str())
        .match_query(Matcher::Any)
        .with_header("etag", "\"v1\"")
        .with_body(serde_json::to_vec(&metadata(25, true)).unwrap())
        .expect(2)
        .create_async()
        .await;
    let write = server
        .mock("PUT", metadata_path().as_str())
        .match_query(Matcher::Any)
        .with_status(200)
        .expect(1)
        .create_async()
        .await;
    let no_delete = server.mock("POST", "/").expect(0).create_async().await;
    let (app, redis) = redis_app(&server).await;
    let token = redis
        .create_sync_factor_maintenance_token("backup-a".to_string())
        .await
        .unwrap();
    let (status, body) = reclaim(app, &token).await;
    assert!(status.is_success());
    assert_eq!(body, json!({"reclaimed": true}));
    read.assert_async().await;
    write.assert_async().await;
    no_delete.assert_async().await;
}

#[tokio::test]
async fn redis_cas_failure_burns_only_maintenance_and_never_cleans_lookup() {
    let mut server = Server::new_async().await;
    let read = server
        .mock("GET", metadata_path().as_str())
        .match_query(Matcher::Any)
        .with_header("etag", "\"v1\"")
        .with_body(serde_json::to_vec(&metadata(25, true)).unwrap())
        .expect(1)
        .create_async()
        .await;
    let write = server
        .mock("PUT", metadata_path().as_str())
        .match_query(Matcher::Any)
        .match_header("if-match", "\"v1\"")
        .with_status(412)
        .with_body("<Error><Code>PreconditionFailed</Code></Error>")
        .expect(1)
        .create_async()
        .await;
    let no_delete = server.mock("POST", "/").expect(0).create_async().await;
    let (app, redis) = redis_app(&server).await;
    let (registration, token) = redis
        .create_recovery_tokens("backup-a".to_string())
        .await
        .unwrap();
    let token = token.unwrap();
    assert!(!reclaim(app.clone(), &token).await.0.is_success());
    assert!(!reclaim(app, &token).await.0.is_success());
    assert_eq!(
        redis.use_sync_factor_token(registration).await.unwrap(),
        "backup-a"
    );
    read.assert_async().await;
    write.assert_async().await;
    no_delete.assert_async().await;
}

#[tokio::test]
async fn redis_cleanup_failure_and_changed_lookup_owner_are_best_effort() {
    for (status, body) in [
        (
            500,
            r#"{"__type":"InternalServerError","message":"injected"}"#,
        ),
        (
            400,
            r#"{"__type":"ConditionalCheckFailedException","message":"owner changed"}"#,
        ),
    ] {
        let mut server = Server::new_async().await;
        let before = metadata(25, true);
        let mut after = before.clone();
        after.sync_factors.remove(0);
        let calls = AtomicUsize::new(0);
        let read = server
            .mock("GET", metadata_path().as_str())
            .match_query(Matcher::Any)
            .with_header("etag", "\"v1\"")
            .with_body_from_request(move |_| {
                serde_json::to_vec(if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    &before
                } else {
                    &after
                })
                .unwrap()
            })
            .expect(2)
            .create_async()
            .await;
        let write = server
            .mock("PUT", metadata_path().as_str())
            .match_query(Matcher::Any)
            .with_status(200)
            .expect(1)
            .create_async()
            .await;
        let delete = server
            .mock("POST", "/")
            .match_header("x-amz-target", "DynamoDB_20120810.DeleteItem")
            .match_body(Matcher::PartialJson(json!({
                "ConditionExpression": "#backup_id = :backup_id",
                "ExpressionAttributeValues": {":backup_id": {"S": "backup-a"}}
            })))
            .with_status(status)
            .with_header("content-type", "application/x-amz-json-1.0")
            .with_body(body)
            .expect(1)
            .create_async()
            .await;
        let (app, redis) = redis_app(&server).await;
        let token = redis
            .create_sync_factor_maintenance_token("backup-a".to_string())
            .await
            .unwrap();
        assert_eq!(
            reclaim(app, &token).await,
            (http::StatusCode::OK, json!({"reclaimed": true}))
        );
        read.assert_async().await;
        write.assert_async().await;
        delete.assert_async().await;
    }
}
