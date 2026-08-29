use std::process::Command;
use std::time::Duration;

use axum::extract::Request;
use backup_service::shutdown;
use http::StatusCode;
use tower::ServiceExt;

use crate::common::get_test_router;

mod common;

async fn get_ready(app: axum::Router) -> StatusCode {
    let request = Request::builder()
        .uri("/ready")
        .body(String::new())
        .unwrap();
    app.oneshot(request).await.unwrap().status()
}

/// Draining is process-wide state, so this lives in its own test binary. The signal is real, so
/// the test also dies of `SIGTERM` if the handler stops covering the signal the orchestrator sends.
#[tokio::test]
async fn ready_reports_service_unavailable_once_draining() {
    dotenvy::from_filename(".env.example").unwrap();
    shutdown::install_signal_handlers().unwrap();
    let app = get_test_router(None, None).await;

    assert_eq!(get_ready(app.clone()).await, StatusCode::OK);

    let pid = std::process::id().to_string();
    Command::new("kill").args(["-TERM", &pid]).status().unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !shutdown::is_draining() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the signal handler must start the drain");

    assert_eq!(
        get_ready(app).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "a draining instance must be taken out of the load balancer's rotation"
    );
}
