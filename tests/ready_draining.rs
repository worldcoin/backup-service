use axum::extract::Request;
use backup_service::shutdown;
use http::StatusCode;
use tower::ServiceExt;

use crate::common::get_test_router;

mod common;

async fn get_ready(app: axum::Router) -> StatusCode {
    app.oneshot(
        Request::builder()
            .uri("/ready")
            .method("GET")
            .body(String::new())
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}

/// Draining is process-wide state, so this lives in its own test binary: once shutdown starts,
/// every later `/ready` call in the process must report failure.
#[tokio::test]
async fn ready_reports_service_unavailable_once_draining() {
    dotenvy::from_filename(".env.example").unwrap();
    let app = get_test_router(None, None).await;

    assert_eq!(get_ready(app.clone()).await, StatusCode::OK);

    shutdown::begin();

    assert_eq!(
        get_ready(app).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "a draining instance must be taken out of the load balancer's rotation"
    );
}
