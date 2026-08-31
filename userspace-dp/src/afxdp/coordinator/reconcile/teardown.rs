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
//! it. Under `cfg(test)` the quiesce is RECORDED on the per-instance
//! `Coordinator::last_quiesce_ms` field and the real `thread::sleep`
//! is skipped, so a unit test proves the gate against ITS OWN
//! coordinator (no process-global state, no cross-test race) and the
//! suite stays fast.
use super::PreservedReconcileState;
use super::super::Coordinator;
use std::time::Duration;

/// The mlx5 zero-copy teardown quiesce. Real builds sleep; tests
/// record the request on `Coordinator::last_quiesce_ms` and skip the
/// sleep.
const TEARDOWN_QUIESCE: Duration = Duration::from_millis(500);

/// Apply the teardown quiesce. In a real build this sleeps; under
/// `cfg(test)` it records the requested duration on the coordinator's
/// own `last_quiesce_ms` field (per-instance — no shared global) and
/// returns immediately so the suite is fast.
#[inline]
fn quiesce(coord: &mut Coordinator, d: Duration) {
    #[cfg(test)]
    {
        coord.last_quiesce_ms = coord
            .last_quiesce_ms
            .saturating_add(d.as_millis() as u64);
    }
    #[cfg(not(test))]
    {
        let _ = coord;
        std::thread::sleep(d);
    }
}

/// `will_rebind` is true when the reconcile is applying a snapshot and
/// will therefore re-bind the XSK on (potentially) the same queue set
/// — the only case where the mlx5 EBUSY quiesce is load-bearing. A
/// teardown with no following bind (`no_snapshot` / shutdown) passes
/// `false` and skips the quiesce.
pub(super) fn tear_down(coord: &mut Coordinator, will_rebind: bool) -> PreservedReconcileState {
    let had_live_workers = !coord.workers.records.is_empty();
    // #8157: the synced-session set is NO LONGER captured here. It used to be
    // cloned before `stop_inner(false)` and replayed at bringup, which left a
    // window: an entry landing in the shared map between this point and the
    // replay was absent from the captured Vec, never published to the new
    // session map, and never replayed — while still being answered to Go as
    // installed. The replay now reads the live map at replay time instead, so
    // a late arrival is included by construction. Safe because
    // `stop_inner(false)` does NOT clear `sessions.synced` (the clear is gated
    // on `clear_synced_state`, which only full shutdown passes), so the map
    // survives the teardown intact — see #6652, whose own regression note is
    // "stop_inner(false) replaced the workers and bring-up replayed nothing,
    // while the shared map still held them".
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
        // latency. Counted in `reconcile_quiesce_count` (an internal /
        // test counter — not wired to any status surface).
        coord.reconcile_quiesce_count = coord.reconcile_quiesce_count.saturating_add(1);
        quiesce(coord, TEARDOWN_QUIESCE);
    }
    PreservedReconcileState {
        slow_path,
        tunnel_owners,
        snapshot_was_installed,
    }
}
