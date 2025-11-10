use http::StatusCode;
use http_body_util::BodyExt;
use serde_json::json;
use uuid::Uuid;

use crate::common::{
    create_test_backup_with_keypair, create_test_backup_with_oidc_account,
    generate_random_backup_id, send_post_request,
};

mod common;

#[tokio::test]
async fn test_fetch_backup_status_happy_path() {
    let ((_, _), response) = create_test_backup_with_keypair(b"TEST BACKUP").await;

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupId"].as_str().unwrap();

    let response = send_post_request("/v1/backup/status", json!({"backupId": backup_id})).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let factor_kinds = response["factors"].as_array().unwrap();
    assert_eq!(factor_kinds.len(), 1);
    assert_eq!(factor_kinds[0]["kind"].as_str().unwrap(), "EC_KEYPAIR");
    assert_eq!(factor_kinds[0]["accountKind"].as_str(), None);
    assert_eq!(response["backupId"].as_str().unwrap(), backup_id);
}

#[tokio::test]
async fn test_fetch_backup_status_with_oidc_account() {
    let subject = Uuid::new_v4().to_string();
    let test_backup = create_test_backup_with_oidc_account(&subject, b"TEST BACKUP").await;

    let body = test_backup
        .response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupId"].as_str().unwrap();

    let response = send_post_request("/v1/backup/status", json!({"backupId": backup_id})).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let factor_kinds = response["factors"].as_array().unwrap();
    assert_eq!(factor_kinds.len(), 1);
    assert_eq!(factor_kinds[0]["kind"].as_str().unwrap(), "OIDC_ACCOUNT");
    assert_eq!(factor_kinds[0]["accountKind"].as_str().unwrap(), "GOOGLE");
    assert_eq!(response["backupId"].as_str().unwrap(), backup_id);
}

#[tokio::test]
async fn test_fetch_backup_not_found() {
    let response = send_post_request(
        "/v1/backup/status",
        json!({"backupId": generate_random_backup_id()}),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
