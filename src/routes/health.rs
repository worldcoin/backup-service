use axum::http::StatusCode;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    status: String,
}

pub async fn handler() -> (StatusCode, axum::Json<HealthResponse>) {
    (
        StatusCode::OK,
        axum::Json(HealthResponse {
            status: "ok".to_string(),
        }),
    )
}
