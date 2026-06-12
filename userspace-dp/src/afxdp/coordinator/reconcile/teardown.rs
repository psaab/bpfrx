//! #1328 Phase 2 — teardown phase.
//!
//! Pure code motion from the head of the pre-#1328 monolithic
//! `Coordinator::reconcile` body: preserve synced sessions + healthy
//! slow-path, call `stop_inner(false)`, sleep 500ms if there were
//! live workers (mlx5 zero-copy queue teardown is not synchronously
//! reusable; EBUSY guard for back-to-back snapshot refreshes).
use super::PreservedReconcileState;
use super::super::Coordinator;
use std::thread;
use std::time::Duration;

pub(super) fn tear_down(coord: &mut Coordinator) -> PreservedReconcileState {
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
    if had_live_workers {
        // Zero-copy queue teardown is not synchronously reusable on
        // mlx5. A short quiesce avoids EBUSY when a later snapshot
        // refresh rebuilds the same queue set immediately after
        // shutdown.
        thread::sleep(Duration::from_millis(500));
    }
    PreservedReconcileState {
        synced_sessions,
        slow_path,
        tunnel_owners,
        snapshot_was_installed,
    }
}
