//! Process-wide graceful shutdown.
//!
//! Nothing handled `SIGTERM` before this module existed. The binary runs as PID 1 in a `scratch`
//! image, and PID 1 discards signals whose action is the default, so a rolling deploy waited out
//! the whole termination grace period and then `SIGKILL`ed the process with requests in flight.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;

/// How long `/ready` reports failure before the listeners stop accepting, so the load balancer
/// takes this instance out of rotation before its socket closes. It must outlast the deployment's
/// readiness probe period times its unhealthy threshold; see the shutdown section of the README.
const DRAIN_DELAY: Duration = Duration::from_secs(10);

/// Budget for in-flight requests once the listeners have closed. Together with [`DRAIN_DELAY`] it
/// must stay under the orchestrator's termination grace period (30s by default on Kubernetes).
const IN_FLIGHT_GRACE: Duration = Duration::from_secs(15);

static DRAIN: OnceLock<watch::Sender<bool>> = OnceLock::new();

fn drain() -> &'static watch::Sender<bool> {
    DRAIN.get_or_init(|| watch::channel(false).0)
}

/// Whether shutdown has started, in which case readiness must report failure.
#[must_use]
pub fn is_draining() -> bool {
    *drain().borrow()
}

/// Starts draining. Idempotent.
pub fn begin() {
    if !drain().send_replace(true) {
        tracing::warn!(message = "shutdown started, failing readiness while requests drain");
    }
}

/// Installs the `SIGTERM`/`SIGINT` handlers that call [`begin`].
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
    });

    Ok(())
}

/// Resolves once the load balancer has had [`DRAIN_DELAY`] to observe `/ready` failing, which is
/// when the listeners may stop accepting new connections.
pub async fn drained() {
    // The sender lives in a `static`, so the wait cannot fail.
    let _ = drain().subscribe().wait_for(|draining| *draining).await;
    tokio::time::sleep(DRAIN_DELAY).await;
}

/// Resolves once in-flight requests have used up [`IN_FLIGHT_GRACE`] after the listeners closed.
pub async fn deadline() {
    drained().await;
    tokio::time::sleep(IN_FLIGHT_GRACE).await;
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

        // In-flight requests get their full budget before the process gives up on them.
        let mut hard_deadline = pin!(deadline());
        assert!(timeout(
            (DRAIN_DELAY + IN_FLIGHT_GRACE).saturating_sub(TICK),
            &mut hard_deadline
        )
        .await
        .is_err());
        assert!(timeout(TICK * 2, &mut hard_deadline).await.is_ok());
    }
}
