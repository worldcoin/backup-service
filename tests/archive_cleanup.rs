mod common;

use aws_sdk_s3::config::retry::RetryConfig;
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::Response;
use axum::Router;
use backup_service::backup_storage::BackupStorage;
use backup_service::environment::Environment;
use backup_service::redis_cache::RedisCacheManager;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http::Request;
use http_body_util::BodyExt;
use mockito::Matcher;
use p256::SecretKey;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

async fn router_with_storage(server: &mockito::Server) -> Router {
    let environment = Environment::development(None);
    let client = aws_sdk_s3::Client::from_conf(
        environment
            .s3_client_config()
            .await
            .to_builder()
            .endpoint_url(server.url())
            .retry_config(RetryConfig::disabled())
            .build(),
    );
    common::get_test_router_with_storage(
        None,
        None,
        Some(Arc::new(BackupStorage::new(environment, Arc::new(client)))),
    )
    .await
}

fn sync_request(payload: &Value) -> Request<String> {
    let body = format!(
        "--test-boundary\r\nContent-Disposition: form-data; name=\"payload\"\r\n\r\n{payload}\r\n\
         --test-boundary\r\nContent-Disposition: form-data; name=\"backup\"; filename=\"backup.bin\"\r\n\r\nnew\r\n\
         --test-boundary--\r\n"
    );
    Request::builder()
        .uri("/v1/sync")
        .method("POST")
        .header(
            "Content-Type",
            "multipart/form-data; boundary=test-boundary",
        )
        .header("Content-Length", body.len())
        .body(body)
        .unwrap()
}

async fn json_body(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

async fn authorization(route: &str, secret: &SecretKey) -> Value {
    let challenge = json_body(common::send_post_request(route, json!({})).await).await;
    json!({
        "authorization": {
            "kind": "EC_KEYPAIR",
            "publicKey": STANDARD.encode(secret.public_key().to_sec1_bytes()),
            "signature": common::sign_keypair_challenge(secret, challenge["challenge"].as_str().unwrap()),
        },
        "challengeToken": challenge["token"],
    })
}

#[tokio::test]
async fn account_lock_blocks_read_sync_delete_and_enrollment_without_burning_tokens() {
    let ((_, main_key), response, sync_key) =
        common::create_test_backup_with_sync_keypair(b"old").await;
    let created = json_body(response).await;
    let id = created["backupId"].as_str().unwrap();
    let environment = Environment::development(None);
    let cache = RedisCacheManager::new(environment, environment.cache_default_ttl())
        .await
        .unwrap();
    let mut lock = cache.lock_backup(id).await.unwrap();

    let read = authorization("/v1/retrieve/challenge/keypair", &main_key).await;
    let mut sync = authorization("/v1/sync/challenge/keypair", &sync_key).await;
    sync["currentManifestHash"] = json!("01".repeat(32));
    sync["newManifestHash"] = json!("02".repeat(32));
    let delete = authorization("/v1/delete-backup/challenge/keypair", &sync_key).await;
    let token = cache.create_sync_factor_token(id.to_owned()).await.unwrap();
    let (_, new_key) = common::generate_keypair();
    let enrollment = authorization("/v1/add-sync-factor/challenge/keypair", &new_key).await;
    let enrollment = json!({
        "syncFactor": enrollment["authorization"],
        "challengeToken": enrollment["challengeToken"],
        "syncFactorToken": token,
    });

    let response = common::send_post_request_with_bypass_attestation_token(
        "/v1/retrieve/from-challenge",
        read.clone(),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::LOCKED);
    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        sync.clone(),
        Bytes::from_static(b"new"),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::LOCKED);
    assert_eq!(
        common::send_post_request("/v1/delete-backup", delete.clone())
            .await
            .status(),
        StatusCode::LOCKED
    );
    assert_eq!(
        common::send_post_request("/v1/add-sync-factor", enrollment.clone())
            .await
            .status(),
        StatusCode::LOCKED
    );
    assert_eq!(cache.sync_factor_backup_id(&token).await.unwrap(), id);
    lock.release().await.unwrap();

    let response = common::send_post_request_with_bypass_attestation_token(
        "/v1/retrieve/from-challenge",
        read,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        STANDARD
            .decode(json_body(response).await["backup"].as_str().unwrap())
            .unwrap(),
        b"old"
    );
    assert_eq!(
        common::send_post_request("/v1/add-sync-factor", enrollment)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        common::send_post_request_with_multipart(
            "/v1/sync",
            sync,
            Bytes::from_static(b"new"),
            None,
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        common::send_post_request("/v1/delete-backup", delete)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn syncing_a_legacy_backup_deletes_its_old_ciphertext() {
    let (_, response, sync_key) = common::create_test_backup_with_sync_keypair(b"old").await;
    let created = json_body(response).await;
    let id = created["backupId"].as_str().unwrap();
    let client = common::get_test_s3_client().await;
    let environment = Environment::development(None);
    let storage = BackupStorage::new(environment, Arc::new(client.clone()));
    let (mut metadata, _) = storage
        .get_metadata_by_backup_id(id)
        .await
        .unwrap()
        .unwrap();
    client
        .delete_object()
        .bucket(environment.s3_bucket())
        .key(format!(
            "{id}/backups/{}",
            metadata.archive_id.take().unwrap()
        ))
        .send()
        .await
        .unwrap();
    for (key, body) in [
        (format!("{id}/backup"), b"old".to_vec()),
        (
            format!("{id}/metadata"),
            serde_json::to_vec(&metadata).unwrap(),
        ),
    ] {
        client
            .put_object()
            .bucket(environment.s3_bucket())
            .key(key)
            .body(body.into())
            .send()
            .await
            .unwrap();
    }
    let mut sync = authorization("/v1/sync/challenge/keypair", &sync_key).await;
    sync["currentManifestHash"] = json!("01".repeat(32));
    sync["newManifestHash"] = json!("02".repeat(32));
    let response = common::send_post_request_with_multipart(
        "/v1/sync",
        sync,
        Bytes::from_static(b"new"),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(storage
        .get_backup_by_metadata(&metadata)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        storage.get_by_backup_id(id).await.unwrap().unwrap().backup,
        b"new"
    );
}

#[tokio::test]
async fn cleanup_failure_does_not_fail_a_committed_sync() {
    let (_, response, sync_key) = common::create_test_backup_with_sync_keypair(b"old").await;
    let created = json_body(response).await;
    let id = created["backupId"].as_str().unwrap();
    let metadata = common::verify_s3_metadata_exists(id).await;
    let mut server = mockito::Server::new_async().await;
    let read = server
        .mock(
            "GET",
            format!("/backup-service-bucket/{id}/metadata").as_str(),
        )
        .match_query(Matcher::Any)
        .with_header("etag", "original")
        .with_body(metadata.to_string())
        .create_async()
        .await;
    let upload = server
        .mock(
            "PUT",
            Matcher::Regex(format!(
                "^/backup-service-bucket/{id}/backups/archive_[0-9a-f]{{32}}$"
            )),
        )
        .match_query(Matcher::Any)
        .match_body("new")
        .create_async()
        .await;
    let commit = server
        .mock(
            "PUT",
            format!("/backup-service-bucket/{id}/metadata").as_str(),
        )
        .match_query(Matcher::Any)
        .match_header("if-match", "original")
        .match_body(Matcher::PartialJson(
            json!({"manifestHash": "02".repeat(32)}),
        ))
        .create_async()
        .await;
    let cleanup = server
        .mock(
            "DELETE",
            format!(
                "/backup-service-bucket/{id}/backups/{}",
                metadata["archiveId"].as_str().unwrap()
            )
            .as_str(),
        )
        .match_query(Matcher::Any)
        .with_status(503)
        .with_body("<Error><Code>ServiceUnavailable</Code></Error>")
        .create_async()
        .await;
    let mut payload = authorization("/v1/sync/challenge/keypair", &sync_key).await;
    payload["currentManifestHash"] = json!("01".repeat(32));
    payload["newManifestHash"] = json!("02".repeat(32));
    let response = router_with_storage(&server)
        .await
        .oneshot(sync_request(&payload))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["backupId"], id);
    read.assert_async().await;
    upload.assert_async().await;
    commit.assert_async().await;
    cleanup.assert_async().await;
}

#[tokio::test]
async fn deletion_waits_until_the_reader_has_fetched_all_ciphertext() {
    let ((_, main_key), response, sync_key) =
        common::create_test_backup_with_sync_keypair(b"old").await;
    let created = json_body(response).await;
    let id = created["backupId"].as_str().unwrap();
    let metadata = common::verify_s3_metadata_exists(id).await;
    let mut server = mockito::Server::new_async().await;
    let (started, receiving) = tokio::sync::oneshot::channel();
    let started = std::sync::Mutex::new(Some(started));
    let (finish, finished) = std::sync::mpsc::channel();
    let finished = std::sync::Mutex::new(finished);
    let read = server
        .mock(
            "GET",
            format!(
                "/backup-service-bucket/{id}/backups/{}",
                metadata["archiveId"].as_str().unwrap()
            )
            .as_str(),
        )
        .match_query(Matcher::Any)
        .with_chunked_body(move |writer| {
            started.lock().unwrap().take().unwrap().send(()).unwrap();
            finished
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            writer.write_all(b"old")
        })
        .create_async()
        .await;
    let payload = authorization("/v1/retrieve/challenge/keypair", &main_key).await;
    let request = Request::builder()
        .uri("/v1/retrieve/from-challenge")
        .method("POST")
        .header("Content-Type", "application/json")
        .header(
            backup_service::attestation_gateway::ATTESTATION_GATEWAY_HEADER,
            std::env::var("ATTESTATION_GATEWAY_BYPASS_TOKEN").unwrap(),
        )
        .body(payload.to_string())
        .unwrap();
    let retrieval = tokio::spawn(router_with_storage(&server).await.oneshot(request));
    tokio::time::timeout(std::time::Duration::from_secs(10), receiving)
        .await
        .unwrap()
        .unwrap();
    let delete = authorization("/v1/delete-backup/challenge/keypair", &sync_key).await;
    assert_eq!(
        common::send_post_request("/v1/delete-backup", delete.clone())
            .await
            .status(),
        StatusCode::LOCKED
    );
    finish.send(()).unwrap();
    let response = retrieval.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        STANDARD
            .decode(json_body(response).await["backup"].as_str().unwrap())
            .unwrap(),
        b"old"
    );
    assert_eq!(
        common::send_post_request("/v1/delete-backup", delete)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    read.assert_async().await;
}
