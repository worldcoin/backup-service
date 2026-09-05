//! Graceful shutdown. Stops new requests and drains running ones. On `SIGTERM` or `SIGINT` the service
//! drains: `/ready` answers `503` for 10 seconds so the instance leaves the load balancer's rotation.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tokio::time::Instant;

/// Reports /ready as 503 for this period, then stops listening.
const DRAIN_DELAY: Duration = Duration::from_secs(10);

/// Max timeout for full shutdown (incl. in-flight requests)
const IN_FLIGHT_GRACE: Duration = Duration::from_secs(30);

/// When the listeners may close.
static CLOSE_AT: OnceLock<watch::Sender<Option<Instant>>> = OnceLock::new();

fn close_at() -> &'static watch::Sender<Option<Instant>> {
    CLOSE_AT.get_or_init(|| watch::channel(None).0)
}

pub fn is_draining() -> bool {
    close_at().borrow().is_some()
}

/// Starts draining on `SIGTERM` or `SIGINT`.
///
/// # Errors
/// Fails if the signal handlers cannot be registered.
pub fn install_signal_handlers() -> std::io::Result<()> {
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
            if is_draining() {
                tracing::warn!(message = "second shutdown signal, exiting now");
                std::process::exit(1);
            }
            tracing::warn!(message = "shutdown started, failing readiness while requests drain");
            close_at().send_replace(Some(Instant::now() + DRAIN_DELAY));
        }
    });

    Ok(())
}

async fn close_deadline() -> Instant {
    let mut receiver = close_at().subscribe();
    let _ = receiver.wait_for(Option::is_some).await;
    (*close_at().borrow()).unwrap_or_else(Instant::now)
}

/// Shuts down after [`DRAIN_DELAY`].
pub(crate) async fn drained() {
    tokio::time::sleep_until(close_deadline().await).await;
}

/// Hard stop: requests still running here are severed rather than left to hold the process open
/// past the orchestrator's grace period.
pub(crate) async fn deadline() {
    tokio::time::sleep_until(close_deadline().await + IN_FLIGHT_GRACE).await;
}
