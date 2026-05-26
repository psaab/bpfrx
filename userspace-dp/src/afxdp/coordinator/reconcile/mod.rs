//! #1328 Phase 2: per-phase decomposition of `Coordinator::reconcile`.
//!
//! Pure code motion of the previous 506-LOC `reconcile()` body in
//! `coordinator/mod.rs` into four phase modules. The orchestrator
//! itself lives in [`reconcile`](Coordinator::reconcile) below; each
//! phase helper is a free `pub(super) fn` defined in its own module.
//!
//! Side-effect ordering and `last_reconcile_stage` writes are
//! preserved verbatim. See
//! `docs/pr/1328-coordinator-reconcile-split/plan.md` §"Hidden
//! invariants" for the load-bearing inventory.
use super::*;
// Bring afxdp scope so types like SyncedSessionEntry / SlowPathReinjector
// / OwnedFd / DnatTableFds / BindingStatus / ConfigSnapshot are usable in
// the orchestrator and the PreservedReconcileState/ReconcileSnapshotFds
// definitions below.
use super::super::*;

pub(super) mod bringup;
pub(super) mod reset;
pub(super) mod snapshot;
pub(super) mod teardown;

/// State preserved across `stop_inner(false)` that the later phases
/// need to consume. Two fields only — `had_live_workers` lives
/// entirely inside `teardown.rs` (it gates the 500ms mlx5 quiesce
/// sleep, which is not needed outside teardown).
pub(in crate::afxdp) struct PreservedReconcileState {
    pub(super) synced_sessions: Vec<SyncedSessionEntry>,
    pub(super) slow_path: Option<Arc<SlowPathReinjector>>,
}

/// Owned BPF map FDs returned by [`snapshot::apply_snapshot`] and
/// consumed by [`bringup::bring_up_workers`], which stores them on
/// `self.bpf_maps` after the per-worker spawn loop runs.
pub(in crate::afxdp) struct ReconcileSnapshotFds {
    pub(super) map_fd: OwnedFd,
    pub(super) heartbeat_map_fd: OwnedFd,
    pub(super) session_map_fd: OwnedFd,
    pub(super) conntrack_v4_fd: Option<OwnedFd>,
    pub(super) conntrack_v6_fd: Option<OwnedFd>,
    pub(super) dnat_table_fd: Option<OwnedFd>,
    pub(super) dnat_table_v6_fd: Option<OwnedFd>,
    pub(super) dnat_fds: DnatTableFds,
}

impl Coordinator {
    /// Reconcile the coordinator state against an optional config
    /// `snapshot`.
    ///
    /// Phases (preserved verbatim from pre-#1328 monolithic body):
    /// 1. Teardown: preserve synced sessions + healthy slow path,
    ///    stop workers, 500ms quiesce if workers were live.
    /// 2. Reset: zero per-binding counter fields.
    /// 3. Snapshot apply (only if `snapshot.is_some()`): install
    ///    validation/forwarding state, re-arm slow path, open BPF
    ///    map FDs. Returns early on missing pin / open failure with
    ///    `last_reconcile_stage` + per-binding `last_error` set.
    /// 4. Bringup: build worker plans, replay preserved synced
    ///    sessions, per-worker spawn loop (#925 panic-slot inline),
    ///    start neighbor monitor + local tunnel sources.
    /// 5. Final `refresh_bindings(bindings)` so the operator-visible
    ///    `BindingStatus` snapshot reflects the just-spawned workers.
    pub fn reconcile(
        &mut self,
        snapshot: Option<&ConfigSnapshot>,
        bindings: &mut [BindingStatus],
        ring_entries: usize,
    ) {
        self.reconcile_calls += 1;
        self.last_reconcile_stage = "start".to_string();
        let preserved = teardown::tear_down(self);
        reset::reset_binding_counters(bindings);
        let Some(snapshot) = snapshot else {
            self.policy_counters.reconcile_rules(&[]);
            self.last_reconcile_stage = "no_snapshot".to_string();
            return;
        };
        let Some(fds) =
            snapshot::apply_snapshot(self, snapshot, bindings, preserved.slow_path)
        else {
            // last_reconcile_stage + per-binding last_error already set
            // inside apply_snapshot on the missing-pin/open-failed legs.
            return;
        };
        bringup::bring_up_workers(
            self,
            snapshot,
            bindings,
            fds,
            ring_entries,
            preserved.synced_sessions,
        );
        self.refresh_bindings(bindings);
    }
}
