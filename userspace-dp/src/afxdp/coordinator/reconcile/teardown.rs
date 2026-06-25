//! #1328 Phase 2 — teardown phase.
//!
//! Pure code motion from the head of the pre-#1328 monolithic
//! `Coordinator::reconcile` body: preserve synced sessions + healthy
//! slow-path, call `stop_inner(false)`, then — only when a rebind will
//! actually follow on the same queue set — sleep 500ms if there were
//! live workers (mlx5 zero-copy queue teardown is not synchronously
//! reusable; EBUSY guard for back-to-back snapshot refreshes).
//!
//! #2522: the quiesce is now gated on `will_rebind` (the reconcile is
//! applying a snapshot) IN ADDITION to `had_live_workers`. A teardown
//! that is not followed by a bind — the `no_snapshot` / shutdown path —
//! never rebinds the queues, so the 500ms quiesce was pure dead
//! latency there. Gating it on `will_rebind` removes that stall while
//! keeping the EBUSY guard exactly where a back-to-back rebind needs
//! it. `quiesce()` routes through a test seam so a unit test can prove
//! the gate without paying the real 500ms.
use super::PreservedReconcileState;
use super::super::Coordinator;
use std::time::Duration;

/// The mlx5 zero-copy teardown quiesce. Real builds sleep; tests
/// record the request and skip the sleep (see [`test_seam`]).
const TEARDOWN_QUIESCE: Duration = Duration::from_millis(500);

#[cfg(test)]
pub(in crate::afxdp) mod test_seam {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    /// Total quiesce duration requested by `tear_down`, in
    /// milliseconds. A test resets this to 0, drives a reconcile, and
    /// asserts whether the gate fired. The real `thread::sleep` is
    /// skipped under `cfg(test)` so the suite stays fast.
    pub(in crate::afxdp) static QUIESCE_MS: AtomicU64 = AtomicU64::new(0);

    pub(in crate::afxdp) fn reset() {
        QUIESCE_MS.store(0, Ordering::Relaxed);
    }

    pub(in crate::afxdp) fn requested_ms() -> u64 {
        QUIESCE_MS.load(Ordering::Relaxed)
    }

    pub(super) fn record(d: Duration) {
        QUIESCE_MS.fetch_add(d.as_millis() as u64, Ordering::Relaxed);
    }
}

#[inline]
fn quiesce(d: Duration) {
    #[cfg(test)]
    {
        // Record the request; skip the real sleep so the suite is fast.
        test_seam::record(d);
    }
    #[cfg(not(test))]
    {
        std::thread::sleep(d);
    }
}

/// `will_rebind` is true when the reconcile is applying a snapshot and
/// will therefore re-bind the XSK on (potentially) the same queue set
/// — the only case where the mlx5 EBUSY quiesce is load-bearing. A
/// teardown with no following bind (`no_snapshot` / shutdown) passes
/// `false` and skips the quiesce.
pub(super) fn tear_down(coord: &mut Coordinator, will_rebind: bool) -> PreservedReconcileState {
    let had_live_workers = !coord.workers.handles.is_empty();
    let synced_sessions = coord.snapshot_shared_session_entries();
    // #1873 R-D (AGY code r3): capture the tunnel-owner map and the
    // installed flag BEFORE stop_inner defaults coord.forwarding and
    // coord.validation — apply_snapshot's remap purge diffs against
    // these, not the (post-teardown empty) live state.
    let tunnel_owners: Vec<(u16, String)> = coord
        .forwarding
        .tunnel_endpoints
        .iter()
        .map(|(id, ep)| (*id, ep.interface.clone()))
        .collect();
    let snapshot_was_installed = coord.validation.snapshot_installed;
    // Keep a healthy slow-path worker across back-to-back reconciles.
    // The userspace helper can receive multiple snapshot refreshes
    // during HA role changes; recreating the fixed-name TUN on every
    // reconcile can race with teardown and leave the new owner
    // without xpf-usp0.
    let slow_path = coord.slow_path.as_ref().and_then(|slow| {
        if slow.status().active {
            Some(slow.clone())
        } else {
            None
        }
    });
    coord.stop_inner(false);
    if had_live_workers && will_rebind {
        // Zero-copy queue teardown is not synchronously reusable on
        // mlx5. A short quiesce avoids EBUSY when a later snapshot
        // refresh rebuilds the same queue set immediately after
        // shutdown. #2522: skipped when no rebind follows (the
        // `no_snapshot` / shutdown teardown), where it was pure dead
        // latency. Counted in `reconcile_quiesce_count` for
        // observability.
        coord.reconcile_quiesce_count = coord.reconcile_quiesce_count.saturating_add(1);
        quiesce(TEARDOWN_QUIESCE);
    }
    PreservedReconcileState {
        synced_sessions,
        slow_path,
        tunnel_owners,
        snapshot_was_installed,
    }
}
