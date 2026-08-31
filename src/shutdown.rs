//! Process-wide graceful shutdown. Nothing handled `SIGTERM` before this module existed, and the
//! binary runs as PID 1 in a `scratch` image, where a signal with no handler is discarded: a
//! rolling deploy waited out the grace period, then `SIGKILL`ed the process mid-request.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tokio::time::Instant;

/// How long `/ready` reports failure before the listeners stop accepting. It must outlast whatever
/// removes the instance from rotation; see the shutdown section of the README.
const DRAIN_DELAY: Duration = Duration::from_secs(10);

/// Set together: the flag wakes the waiters, the instant anchors the delay to the signal itself.
static DRAIN: OnceLock<watch::Sender<bool>> = OnceLock::new();
static BEGAN_AT: OnceLock<Instant> = OnceLock::new();

fn drain() -> &'static watch::Sender<bool> {
    DRAIN.get_or_init(|| watch::channel(false).0)
}

/// Whether shutdown has started, in which case readiness must report failure.
pub fn is_draining() -> bool {
    *drain().borrow()
}

/// Installs the `SIGTERM`/`SIGINT` handlers that start draining.
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
        BEGAN_AT.get_or_init(Instant::now);
        if !drain().send_replace(true) {
            tracing::warn!(message = "shutdown started, failing readiness while requests drain");
        }
    });

    Ok(())
}

/// Resolves once the load balancer has had [`DRAIN_DELAY`] to observe `/ready` failing, which is
/// when the listeners may stop accepting new connections. The delay runs from the signal, so a
/// slow startup cannot push it past the orchestrator's grace period.
pub async fn drained() {
    let mut receiver = drain().subscribe();
    // The sender lives in a `static`, so the wait cannot fail.
    let _ = receiver.wait_for(|draining| *draining).await;
    tokio::time::sleep_until(*BEGAN_AT.get_or_init(Instant::now) + DRAIN_DELAY).await;
}
