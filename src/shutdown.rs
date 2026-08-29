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

/// Budget for in-flight requests once the listeners have closed. It matches the request timeout in
/// [`crate::server`], so shutdown never cuts off a request the server itself still considers valid.
const IN_FLIGHT_GRACE: Duration = Duration::from_secs(30);

/// Set together: the flag wakes the waiters, the instant anchors every deadline to the signal.
static DRAIN: OnceLock<watch::Sender<bool>> = OnceLock::new();
static BEGAN_AT: OnceLock<Instant> = OnceLock::new();

fn drain() -> &'static watch::Sender<bool> {
    DRAIN.get_or_init(|| watch::channel(false).0)
}

/// Whether shutdown has started, in which case readiness must report failure.
#[must_use]
pub fn is_draining() -> bool {
    *drain().borrow()
}

/// Starts draining. Idempotent: a repeat signal does not extend the budget.
fn begin() {
    BEGAN_AT.get_or_init(Instant::now);
    if !drain().send_replace(true) {
        tracing::warn!(message = "shutdown started, failing readiness while requests drain");
    }
}

/// Installs the `SIGTERM`/`SIGINT` handlers that start draining, and the watchdog that bounds the
/// whole shutdown. The watchdog covers startup too, which the server's own drain cannot reach.
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
        begin();
        deadline().await;
        tracing::error!(message = "shutdown deadline hit, exiting with work still in flight");
        std::process::exit(0);
    });

    Ok(())
}

async fn began_at() -> Instant {
    let mut receiver = drain().subscribe();
    // The sender lives in a `static`, so the wait cannot fail.
    let _ = receiver.wait_for(|draining| *draining).await;
    *BEGAN_AT.get_or_init(Instant::now)
}

/// Resolves once the load balancer has had [`DRAIN_DELAY`] to observe `/ready` failing, which is
/// when the listeners may stop accepting new connections.
pub async fn drained() {
    tokio::time::sleep_until(began_at().await + DRAIN_DELAY).await;
}

/// Resolves once in-flight requests have used up [`IN_FLIGHT_GRACE`] after the listeners closed.
async fn deadline() {
    tokio::time::sleep_until(began_at().await + DRAIN_DELAY + IN_FLIGHT_GRACE).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::pin::pin;
    use tokio::time::timeout;

    const TICK: Duration = Duration::from_secs(1);

    /// A single test, because [`begin`] flips process-wide state that a second test would race.
    #[tokio::test(start_paused = true)]
    async fn draining_gates_readiness_then_closes_listeners() {
        let mut listeners = pin!(drained());
        assert!(!is_draining());
        assert!(timeout(DRAIN_DELAY, &mut listeners).await.is_err());

        begin();
        assert!(is_draining());

        // Listeners stay open for the drain delay so the load balancer sees /ready fail first.
        assert!(timeout(DRAIN_DELAY.saturating_sub(TICK), &mut listeners)
            .await
            .is_err());
        assert!(timeout(TICK * 2, &mut listeners).await.is_ok());

        // Deadlines run from the signal, so a waiter polled late does not restart the budget.
        let grace = IN_FLIGHT_GRACE.saturating_sub(TICK);
        assert!(timeout(grace, pin!(deadline())).await.is_err());
        assert!(timeout(TICK * 2, pin!(deadline())).await.is_ok());
    }
}
