use crate::types::{Environment, ErrorResponse};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;
use axum::{extract::Extension, Json};
use schemars::JsonSchema;
use serde::Serialize;
use tokio::time::Instant;

#[derive(Debug, JsonSchema, Serialize)]
pub struct CreateBackupResponse {}

pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(s3_client): Extension<S3Client>,
) -> Result<Json<CreateBackupResponse>, ErrorResponse> {
    // TODO: Replace this stub with a proper storage service
    let key = format!("backup-{}", Instant::now().elapsed().as_millis());
    let body = ByteStream::from(vec![0u8; 1024]);
    s3_client
        .put_object()
        .bucket(environment.s3_bucket_arn())
        .key(key)
        .body(body)
        .send()
        .await
        .map_err(|err| {
            tracing::error!(message = "Failed to upload backup to S3", error = ?err);
            ErrorResponse::internal_server_error()
        })?;

    Ok(Json(CreateBackupResponse {}))
}
