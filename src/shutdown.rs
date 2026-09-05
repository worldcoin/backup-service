//! Graceful shutdown. The binary runs as PID 1 in a `scratch` image, where a signal with no
//! handler is discarded, so before this module a rolling deploy waited out the whole termination
//! grace period and then `SIGKILL`ed the process mid-request.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tokio::time::Instant;

/// How long `/ready` reports failure before the listeners stop accepting. It must outlast whatever
/// takes the instance out of rotation; see the shutdown section of the README.
const DRAIN_DELAY: Duration = Duration::from_secs(10);

/// When the listeners may close, fixed when the signal arrives so a slow startup cannot push it out.
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
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
        tracing::warn!(message = "shutdown started, failing readiness while requests drain");
        close_at().send_replace(Some(Instant::now() + DRAIN_DELAY));
    });

    Ok(())
}

/// Resolves once the load balancer has had [`DRAIN_DELAY`] to see `/ready` fail, which is when the
/// listeners may stop accepting new connections.
pub async fn drained() {
    let mut receiver = close_at().subscribe();
    let _ = receiver.wait_for(Option::is_some).await;
    let deadline = (*close_at().borrow()).unwrap_or_else(Instant::now);
    tokio::time::sleep_until(deadline).await;
}
