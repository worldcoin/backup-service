use std::sync::Arc;

use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use backup_service::backup_metadata::{BackupMetadata, Factor};
use backup_service::backup_storage::{BackupManagerError, BackupStorage};
use backup_service::environment::Environment;
use backup_service::error::ErrorResponse;
use mockito::Matcher;
use types::ErrorCode;
use uuid::Uuid;

async fn storage() -> (BackupStorage, Client, Environment) {
    dotenvy::from_filename(".env.example").unwrap();
    let environment = Environment::development(None);
    let client = Client::from_conf(environment.s3_client_config().await);
    let storage = BackupStorage::new(environment, Arc::new(client.clone()));
    (storage, client, environment)
}

fn metadata() -> BackupMetadata {
    BackupMetadata {
        id: format!("safe-writes-{}", Uuid::new_v4()),
        factors: vec![],
        sync_factors: vec![],
        keys: vec![],
        manifest_hash: "01".repeat(32),
        archive_id: None,
    }
}

#[tokio::test]
async fn legacy_snapshot_survives_sync_and_factor_changes() {
    let (storage, client, environment) = storage().await;
    let original = metadata();
    for (key, body) in [
        (format!("{}/backup", original.id), b"old".to_vec()),
        (
            format!("{}/metadata", original.id),
            serde_json::to_vec(&original).unwrap(),
        ),
    ] {
        client
            .put_object()
            .bucket(environment.s3_bucket())
            .key(key)
            .body(ByteStream::from(body))
            .send()
            .await
            .unwrap();
    }

    storage
        .update_backup(
            &original.id,
            b"new".to_vec().into(),
            "01".repeat(32),
            "02".repeat(32),
        )
        .await
        .unwrap();
    let committed = storage
        .get_by_backup_id(&original.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.backup, b"new");
    assert_eq!(committed.metadata.manifest_hash, "02".repeat(32));
    assert!(committed.metadata.archive_id.is_some());
    assert_eq!(
        storage
            .get_backup_by_metadata(&original)
            .await
            .unwrap()
            .unwrap(),
        b"old"
    );
    assert!(serde_json::to_value(committed.metadata.exported())
        .unwrap()
        .get("archiveId")
        .is_none());

    let factor = Factor::new_ec_keypair("new-sync-key".into());
    storage
        .add_sync_factor(&original.id, factor.clone())
        .await
        .into_result()
        .unwrap();
    storage
        .remove_sync_factor(&original.id, &factor.id)
        .await
        .unwrap();
    let after = storage
        .get_by_backup_id(&original.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.backup, committed.backup);
    assert_eq!(after.metadata.archive_id, committed.metadata.archive_id);
    assert_eq!(
        after.metadata.manifest_hash,
        committed.metadata.manifest_hash
    );
}

#[tokio::test]
async fn concurrent_syncs_publish_one_matching_archive_and_hash() {
    let (storage, _, _) = storage().await;
    let original = metadata();
    storage
        .create(b"old".to_vec().into(), &original)
        .await
        .unwrap();
    let snapshot = storage
        .get_by_backup_id(&original.id)
        .await
        .unwrap()
        .unwrap();
    let (first, second) = tokio::join!(
        storage.update_backup(
            &original.id,
            b"first".to_vec().into(),
            "01".repeat(32),
            "02".repeat(32)
        ),
        storage.update_backup(
            &original.id,
            b"second".to_vec().into(),
            "01".repeat(32),
            "03".repeat(32)
        ),
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let (bytes, hash, loser) = if first.is_ok() {
        (b"first".as_slice(), "02".repeat(32), second)
    } else {
        (b"second".as_slice(), "03".repeat(32), first)
    };
    let Err(BackupManagerError::ManifestHashMismatch) = loser else {
        panic!("losing sync must report a conflict");
    };
    let committed = storage
        .get_by_backup_id(&original.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.backup, bytes);
    assert_eq!(committed.metadata.manifest_hash, hash);
    assert_eq!(
        storage
            .get_backup_by_metadata(&snapshot.metadata)
            .await
            .unwrap()
            .unwrap(),
        b"old"
    );
}

#[tokio::test]
async fn concurrent_creation_publishes_only_one_backup() {
    let (storage, _, _) = storage().await;
    let first = metadata();
    let mut second = first.clone();
    second.manifest_hash = "02".repeat(32);
    let (first_result, second_result) = tokio::join!(
        storage.create(b"first".to_vec().into(), &first),
        storage.create(b"second".to_vec().into(), &second),
    );
    assert_ne!(first_result.is_ok(), second_result.is_ok());
    let committed = storage.get_by_backup_id(&first.id).await.unwrap().unwrap();
    let (bytes, hash) = if first_result.is_ok() {
        (b"first".as_slice(), first.manifest_hash)
    } else {
        (b"second".as_slice(), second.manifest_hash)
    };
    assert_eq!(committed.backup, bytes);
    assert_eq!(committed.metadata.manifest_hash, hash);
}

#[tokio::test]
async fn orphaned_upload_does_not_reserve_an_account() {
    let (storage, client, environment) = storage().await;
    let original = metadata();
    for key in [
        format!("{}/backup", original.id),
        format!(
            "{}/backups/archive_{}",
            original.id,
            Uuid::new_v4().simple()
        ),
    ] {
        client
            .put_object()
            .bucket(environment.s3_bucket())
            .key(key)
            .body(ByteStream::from_static(b"unpublished"))
            .send()
            .await
            .unwrap();
    }
    assert!(!storage.does_backup_exist(&original.id).await.unwrap());
    storage
        .create(b"new".to_vec().into(), &original)
        .await
        .unwrap();
    let committed = storage
        .get_by_backup_id(&original.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.backup, b"new");
    assert_eq!(committed.metadata.manifest_hash, original.manifest_hash);
}

#[tokio::test]
async fn concurrent_factor_write_and_sync_preserve_the_selected_archive() {
    let (storage, _, _) = storage().await;
    let original = metadata();
    storage
        .create(b"old".to_vec().into(), &original)
        .await
        .unwrap();
    let factor = Factor::new_ec_keypair("concurrent-sync-key".into());
    let (sync, addition) = tokio::join!(
        storage.update_backup(
            &original.id,
            b"new".to_vec().into(),
            "01".repeat(32),
            "02".repeat(32)
        ),
        storage.add_sync_factor(&original.id, factor.clone()),
    );
    let addition = addition.into_result();
    assert!(sync.is_ok() || addition.is_ok());
    let committed = storage
        .get_by_backup_id(&original.id)
        .await
        .unwrap()
        .unwrap();
    let (bytes, hash) = if sync.is_ok() {
        (b"new".as_slice(), "02".repeat(32))
    } else {
        (b"old".as_slice(), "01".repeat(32))
    };
    assert_eq!(committed.backup, bytes);
    assert_eq!(committed.metadata.manifest_hash, hash);
    assert_eq!(
        committed.metadata.sync_factors.contains(&factor),
        addition.is_ok()
    );
}

#[tokio::test]
async fn deletion_unpublishes_without_invalidating_an_existing_reader() {
    let (storage, _, _) = storage().await;
    let original = metadata();
    storage
        .create(b"old".to_vec().into(), &original)
        .await
        .unwrap();
    let snapshot = storage
        .get_by_backup_id(&original.id)
        .await
        .unwrap()
        .unwrap();
    storage.delete_backup(&original.id).await.unwrap();
    assert!(!storage.does_backup_exist(&original.id).await.unwrap());
    assert!(storage
        .get_by_backup_id(&original.id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        storage
            .get_backup_by_metadata(&snapshot.metadata)
            .await
            .unwrap()
            .unwrap(),
        b"old"
    );
    storage
        .create(b"replacement".to_vec().into(), &original)
        .await
        .unwrap();
    assert_eq!(
        storage
            .get_backup_by_metadata(&snapshot.metadata)
            .await
            .unwrap()
            .unwrap(),
        b"old"
    );
}

#[tokio::test]
async fn failed_upload_or_metadata_commit_keeps_the_published_backup() {
    let (storage, _, environment) = storage().await;
    let original = metadata();
    storage
        .create(b"old".to_vec().into(), &original)
        .await
        .unwrap();
    let (snapshot, etag) = storage
        .get_metadata_by_backup_id(&original.id)
        .await
        .unwrap()
        .unwrap();

    for (upload_status, commit_status) in
        [(503, 200), (200, 412), (200, 409), (200, 404), (200, 503)]
    {
        let mut server = mockito::Server::new_async().await;
        let config = environment
            .s3_client_config()
            .await
            .to_builder()
            .endpoint_url(server.url())
            .retry_config(RetryConfig::disabled())
            .build();
        let faulty = BackupStorage::new(environment, Arc::new(Client::from_conf(config)));
        let path = format!("/{}/{}/metadata", environment.s3_bucket(), original.id);
        let read = server
            .mock("GET", path.as_str())
            .match_query(Matcher::Any)
            .with_header("etag", etag.as_ref().unwrap())
            .with_body(serde_json::to_vec(&snapshot).unwrap())
            .create_async()
            .await;
        let upload = server
            .mock(
                "PUT",
                Matcher::Regex(format!(
                    "^/{}/{}/backups/archive_[0-9a-f]{{32}}$",
                    environment.s3_bucket(),
                    original.id
                )),
            )
            .match_header("if-none-match", "*")
            .match_query(Matcher::Any)
            .with_status(upload_status)
            .with_body(if upload_status == 200 {
                ""
            } else {
                "<Error><Code>ServiceUnavailable</Code></Error>"
            })
            .create_async()
            .await;
        let commit = server
            .mock("PUT", path.as_str())
            .match_query(Matcher::Any)
            .match_header("if-match", etag.as_ref().unwrap().as_str())
            .with_status(commit_status)
            .with_body(if commit_status == 404 {
                "<Error><Code>NoSuchKey</Code></Error>"
            } else {
                "<Error><Code>PreconditionFailed</Code></Error>"
            })
            .expect(usize::from(upload_status == 200))
            .create_async()
            .await;
        let cleanup = server
            .mock("DELETE", Matcher::Any)
            .expect(0)
            .create_async()
            .await;

        let result = faulty
            .update_backup(
                &original.id,
                b"new".to_vec().into(),
                "01".repeat(32),
                "02".repeat(32),
            )
            .await;
        let error = ErrorResponse::from(result.unwrap_err());
        let expected = if commit_status == 404 {
            ErrorCode::BackupNotFound
        } else if commit_status == 409 || commit_status == 412 {
            ErrorCode::ManifestHashMismatch
        } else {
            ErrorCode::InternalServerError
        };
        assert_eq!(error.code(), &expected);
        read.assert_async().await;
        upload.assert_async().await;
        commit.assert_async().await;
        cleanup.assert_async().await;
        let committed = storage
            .get_by_backup_id(&original.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(committed.backup, b"old");
        assert_eq!(committed.metadata, snapshot);
    }
}
