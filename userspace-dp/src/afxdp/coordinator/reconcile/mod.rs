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
/// need to consume. `had_live_workers` lives entirely inside
/// `teardown.rs` (it gates the 500ms mlx5 quiesce sleep alongside the
/// `will_rebind` flag, which is not needed outside teardown).
pub(in crate::afxdp) struct PreservedReconcileState {
    pub(super) synced_sessions: Vec<SyncedSessionEntry>,
    pub(super) slow_path: Option<Arc<SlowPathReinjector>>,
    /// #1873 R-D (AGY code r3): the tunnel-owner map (id -> logical
    /// interface name) captured BEFORE `stop_inner(false)` resets
    /// `coord.forwarding` to default. The remap purge diff in
    /// `apply_snapshot` MUST run against this — diffing the
    /// post-teardown empty state makes every purge arm inert across a
    /// reconcile boundary.
    pub(super) tunnel_owners: Vec<(u16, String)>,
    /// Captured before `stop_inner` resets `coord.validation`: gates
    /// the new-appearance purge arm so only the GENUINE first apply of
    /// the helper's life skips it (not every post-teardown apply).
    pub(super) snapshot_was_installed: bool,
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
    /// #2484: the fully-built forwarding state, produced in the
    /// pre-teardown preflight so a snapshot INTEGRITY fault aborts the
    /// reconcile BEFORE `tear_down` stops the workers and resets
    /// `coord.forwarding` / `coord.validation`. `apply_snapshot` REUSES
    /// this rather than rebuilding — the build reads `Some(&coord.forwarding)`
    /// as the "previous" arg, which teardown defaults to empty, so it MUST
    /// happen before teardown. Building once also avoids re-inserting
    /// per-rule counter handles into the live counter stores twice.
    pub(super) forwarding: ForwardingState,
}

impl Coordinator {
    /// Reconcile the coordinator state against an optional config
    /// `snapshot`.
    ///
    /// Phases (preserved verbatim from pre-#1328 monolithic body):
    /// 1. Teardown: preserve synced sessions + healthy slow path,
    ///    stop workers, 500ms quiesce if workers were live AND a rebind
    ///    follows (snapshot-apply path only — #2522).
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
    ///
    /// The `no_snapshot` (config-cleared / shutdown) path returns after
    /// phase 2 but ALSO runs `refresh_bindings(bindings)` before
    /// returning (#2515) — phase 1 stopped every worker, so the refresh
    /// routes each now-workerless slot through `zero_unbound_slot`
    /// (clearing the bind-mode / socket / capacity fields that the phase
    /// 2 counter reset leaves untouched) and rebuilds the CoS owner map
    /// empty. Without it, status commands report torn-down slots as if
    /// still bound and the CoS owner->worker map keeps stale entries.
    pub fn reconcile(
        &mut self,
        snapshot: Option<&ConfigSnapshot>,
        bindings: &mut [BindingStatus],
        ring_entries: usize,
    ) {
        self.reconcile_calls += 1;
        self.last_reconcile_stage = "start".to_string();
        // #1606 (AGY r2 finding 4.2): policy-integrity preflight
        // BEFORE tear_down. If the snapshot has duplicate / zero /
        // unknown book IDs, reject WITHOUT tearing down the
        // existing workers. Workers keep running on the previous
        // good config until a valid snapshot arrives.
        //
        // Uses a scratch counter store (Codex r1 F2) so we don't
        // leak Arc<PolicyRuleCounter> entries on rejected snapshots.
        if let Some(snap) = snapshot {
            let preflight_counters = crate::policy::PolicyCounterStore::default();
            if let Err(err) = crate::policy::parse_policy_state_with_counters(
                &snap.default_policy,
                &snap.policies,
                &self.forwarding.zone_name_to_id,
                &snap.address_books,
                &preflight_counters,
            ) {
                eprintln!(
                    "xpf-userspace-dp: snapshot integrity error during reconcile preflight: {} — keeping previous workers + forwarding state",
                    err
                );
                self.last_reconcile_stage = format!("snapshot_integrity_error: {}", err);
                return;
            }
        }
        // #2440 fail-open partial-apply fix: open the mandatory BPF map
        // FDs (xsk/heartbeat/sessions) — the real correctness boundary —
        // BEFORE `tear_down` stops the running workers and BEFORE
        // `apply_snapshot` publishes a newer forwarding generation. If
        // any mandatory pin is missing or its FD fails to open, abort
        // HERE: the prior workers keep running and the prior forwarding
        // generation stays published. Previously the FD open happened
        // AFTER teardown + publish, so a snapshot with an unopenable
        // required pin tore down the workers, published a newer
        // `snapshot_installed` generation, then aborted bring-up —
        // leaving the helper advertising a data-plane view backed by no
        // workers (fail-open on a security appliance).
        //
        // `preflight_map_fds` only opens FDs and writes
        // `last_reconcile_stage` / per-binding `last_error` on failure;
        // it mutates no published state, so returning here is safe.
        let preflight_fds = if let Some(snap) = snapshot {
            let mut fds = match snapshot::preflight_map_fds(self, snap, bindings) {
                Some(fds) => fds,
                None => {
                    // last_reconcile_stage + per-binding last_error set
                    // inside preflight_map_fds. No teardown, no publish.
                    return;
                }
            };
            // #2484 fail-open partial-apply fix (completes the #2440/#2444
            // trilogy): build the full forwarding state HERE, BEFORE
            // `tear_down`. The top-of-reconcile policy preflight above only
            // parses policy/address-book state, so snapshot INTEGRITY faults
            // reachable only inside the full build (e.g. Nat64UnparseableRule,
            // NPTv6/static-NAT integrity faults) used to surface inside
            // `apply_snapshot` — AFTER teardown stopped the workers and reset
            // `coord.validation` / `shared_validation`, stranding the helper
            // with no forwarding and no workers (residual fail-open). Building
            // here aborts on such a fault with the prior generation + workers
            // still live, mirroring the map-FD hoist #2440 added.
            //
            // This is the SAME call `apply_snapshot` made; the result is
            // stashed on `fds.forwarding` and reused there (build-once), so we
            // do NOT pay a second build on the success path nor re-insert
            // per-rule counter handles into the live stores twice. The build
            // reads `Some(&self.forwarding)` as its "previous" arg, which
            // `tear_down` defaults to empty — another reason it MUST run
            // before teardown.
            match snapshot::build_reconcile_forwarding(self, snap) {
                Ok(forwarding) => fds.forwarding = forwarding,
                Err(()) => {
                    // last_reconcile_stage = "snapshot_integrity_error" set
                    // inside build_reconcile_forwarding. No teardown, no
                    // publish: prior generation + workers stay live.
                    return;
                }
            }
            Some(fds)
        } else {
            None
        };
        // #2522: only the snapshot-apply path rebinds the XSK on the
        // (possibly) same queue set, so only it needs the mlx5 EBUSY
        // quiesce. A `None`-snapshot teardown (config cleared / shutdown
        // reconcile) returns at `no_snapshot` below without ever
        // rebinding — pass `will_rebind = false` so it skips the 500ms
        // stall.
        let will_rebind = snapshot.is_some();
        let mut preserved = teardown::tear_down(self, will_rebind);
        reset::reset_binding_counters(bindings);
        let Some(snapshot) = snapshot else {
            self.policy_counters.reconcile_rules(&[]);
            // #2218: no snapshot -> no active NAT rules -> drop all counters.
            self.nat_counters.reconcile_ids(&[]);
            // #2515: the no_snapshot teardown stopped every worker
            // (`stop_inner` emptied `workers.live` and cleared the CoS
            // owner maps), but `reset_binding_counters` only zeroes the
            // counter scalars + `bound`/`xsk_registered`/`socket_fd` — it
            // leaves `xsk_bind_mode`, `socket_ifindex`/`queue_id`/
            // `bind_flags`, `zero_copy`, and the `flow_cache_capacity`/
            // `active_flow_count` gauges at their pre-teardown values.
            // Without the refresh below, status commands keep reporting
            // those slots as if still bound, and the rebuilt CoS
            // owner->worker map is never emptied. `refresh_bindings`
            // routes every now-workerless slot through `zero_unbound_slot`
            // (clearing exactly those residual fields) and rebuilds the
            // CoS owner map empty — the same tail the snapshot-apply path
            // runs at the end of `reconcile`. Run it BEFORE setting the
            // stage so the operator-visible state is consistent on return.
            self.refresh_bindings(bindings);
            self.last_reconcile_stage = "no_snapshot".to_string();
            return;
        };
        // SAFETY: preflight_fds is Some whenever snapshot is Some (both
        // gated on the same `snapshot` Option above).
        let fds = preflight_fds.expect("preflight_map_fds ran for a Some snapshot");
        // #2484: `apply_snapshot` no longer rebuilds the forwarding state
        // or rejects on an integrity fault — that build (and its integrity
        // check) was hoisted into the pre-teardown preflight above
        // (`build_reconcile_forwarding`), so by the time we reach here the
        // build has already succeeded and `apply_snapshot` reuses
        // `fds.forwarding`. The `Option` return is retained for signature
        // stability; the `else` arm is now defensively unreachable.
        let Some(fds) = snapshot::apply_snapshot(
            self,
            snapshot,
            preserved.slow_path,
            &preserved.tunnel_owners,
            preserved.snapshot_was_installed,
            &mut preserved.synced_sessions,
            fds,
        ) else {
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
