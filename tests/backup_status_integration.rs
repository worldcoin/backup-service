use http::StatusCode;
use http_body_util::BodyExt;

use crate::common::{create_test_backup_with_keypair, generate_random_backup_id, send_get_request};

mod common;

#[tokio::test]
async fn test_fetch_backup_status_happy_path() {
    let ((_, _), response) = create_test_backup_with_keypair(b"TEST BACKUP").await;

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = response["backupId"].as_str().unwrap();

    let response = send_get_request(format!("/v1/backup/{}", backup_id).as_str()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let factor_kinds = response["factorKindsFlattened"].as_array().unwrap();
    assert_eq!(factor_kinds.len(), 1);
    assert_eq!(factor_kinds[0].as_str().unwrap(), "EC_KEYPAIR");
    assert_eq!(response["backupId"].as_str().unwrap(), backup_id);
}

#[tokio::test]
async fn test_fetch_backup_not_found() {
    let response =
        send_get_request(format!("/v1/backup/{}", generate_random_backup_id()).as_str()).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
