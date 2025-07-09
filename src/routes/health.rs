use axum::http::StatusCode;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    status: String,
    /// Current version of the application
    semver: String,
    /// Commit hash of the current build (if available)
    rev: Option<String>,
}

pub async fn handler() -> (StatusCode, axum::Json<HealthResponse>) {
    (
        StatusCode::OK,
        axum::Json(HealthResponse {
            status: "ok".to_string(),
            semver: env!("CARGO_PKG_VERSION").to_string(),
            rev: option_env!("GIT_REV").map(ToString::to_string),
        }),
    )
}
