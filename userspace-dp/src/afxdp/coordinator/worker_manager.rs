use super::*;

/// #6242: the complete per-worker runtime, keyed by `worker_id`.
///
/// Consolidates the four previously-scattered owners — `WorkerManager.handles`
/// plus the three `Coordinator` sibling maps (`worker_panics` /
/// `worker_exception_rings` / `worker_last_resolution`) — into ONE record so a
/// worker's runtime is registered and rolled back as a single unit
/// (`records.insert` / `records.clear`), not a hand-sequenced multi-map
/// triplet. Registration is POST-SPAWN-SUCCESS (see
/// `reconcile/bringup.rs`): a worker that fails to spawn never had a record, so
/// spawn-failure rollback has nothing to unwind (the #4952 differential), and
/// the pre-spawn insert / spawn-Err `.remove` / teardown double-clear the old
/// layout required are gone.
///
/// COLD-PATH ONLY. The packet path never looks this up — each worker holds
/// DIRECT `Arc` clones of its own `exception_ring` / `last_resolution` (threaded
/// via `WorkerPublishedTelemetry` -> `WorkerContext`). The record is read only
/// by the ~1 Hz status thread, teardown, and the HA control fan-out. It holds
/// the SAME `Arc`s the worker telemetry holds (shared allocation, not a fresh
/// alloc), so the consolidation adds zero hot-path indirection and no extra
/// allocation vs. the pre-#6242 four-owner layout.
///
/// `runtime_atomics` / `cold_path_atomics` stay INSIDE `WorkerHandle` — the
/// record wraps the handle, it does not flatten it.
pub(in crate::afxdp) struct WorkerRuntimeRecord {
    pub(in crate::afxdp) handle: WorkerHandle,
    /// #925: panic-payload slot, written once when the worker dies, read at
    /// most once per gRPC status poll (~1 Hz).
    pub(in crate::afxdp) panic: Arc<Mutex<Option<String>>>,
    /// #5289: per-worker exception ring; the worker pushes compact POD events,
    /// the status thread drains + formats them.
    pub(in crate::afxdp) exception_ring: Arc<Mutex<ExceptionEventRing>>,
    /// #5289: per-worker last-forwarding-resolution slot; the status thread
    /// picks the newest across all workers.
    pub(in crate::afxdp) last_resolution: Arc<Mutex<Option<ResolutionEvent>>>,
}

#[cfg(test)]
impl WorkerRuntimeRecord {
    /// Wrap a bare `WorkerHandle` in a record with fresh empty observability
    /// slots — the common test shape (a handle installed to drive HA / status
    /// / lifecycle assertions that do not exercise the exception/resolution
    /// content). Content-specific tests build the record inline with the exact
    /// `exception_ring` / `last_resolution` `Arc`s they assert on.
    pub(in crate::afxdp) fn for_test(handle: WorkerHandle) -> Self {
        Self {
            handle,
            panic: Arc::new(Mutex::new(None)),
            exception_ring: Arc::new(Mutex::new(ExceptionEventRing::new())),
            last_resolution: Arc::new(Mutex::new(None)),
        }
    }
}

/// Per-worker lifecycle and planning state.
///
/// Two distinct key spaces live here:
/// - `live` and `identities` are keyed by binding `slot` (per-binding
///   per-worker, populated from `BindingPlan::slot` in `refresh_bindings`).
/// - `records` is keyed by `worker_id` (one [`WorkerRuntimeRecord`] per
///   spawned worker thread — the #6242 consolidation of the former `handles`
///   map plus the three sibling `Coordinator` observability maps).
///
/// `last_planned_workers` and `last_planned_bindings` are reconcile-pass
/// bookkeeping surfaced in the stage label and operator status surface.
///
/// `last_planned_worker_slots` is the companion SIZING value for
/// per-worker-id-indexed structures (#1830 follow-up, Codex review on
/// PR #1841): `max(planned worker_id) + 1`, i.e. the array length
/// needed so every planned worker id is in range. Worker ids can be
/// SPARSE — the runtime binding/queue unregister handlers
/// (server/handlers/{binding,queue}.rs) can remove the bindings that
/// carried the low worker ids while a high-id worker survives the next
/// reconcile (bring_up_workers skips unregistered/invalid bindings) —
/// so this is NOT interchangeable with the COUNT
/// (`last_planned_workers`). Consumers that want "how many workers"
/// (status surface, stage label) keep using the count; consumers that
/// INDEX by worker id (v8 queue-lease per-worker arrays + rotation
/// scratch, V_min vtime floors) must use the slots value.
pub(in crate::afxdp) struct WorkerManager {
    pub(in crate::afxdp) live: BTreeMap<u32, Arc<BindingLiveState>>,
    pub(in crate::afxdp) identities: BTreeMap<u32, BindingIdentity>,
    pub(in crate::afxdp) records: BTreeMap<u32, WorkerRuntimeRecord>,
    pub(super) last_planned_workers: usize,
    pub(super) last_planned_bindings: usize,
    pub(super) last_planned_worker_slots: usize,
    /// #5290: rotating cursor for the fair RPC-fallback session-delta drain
    /// (`Coordinator::drain_session_deltas`). Persists the binding index the
    /// last drain stopped at so the next drain resumes there, guaranteeing no
    /// binding is perpetually starved across successive polls. A positional
    /// index into the slot-ordered `live` map (`% live.len()` at use), not a
    /// slot key — membership changes are rare (reconcile only) and the rotation
    /// self-corrects, so a stale index costs at most one poll of imperfect
    /// fairness, never permanent starvation.
    pub(in crate::afxdp) session_delta_drain_cursor: std::sync::atomic::AtomicUsize,
}

impl WorkerManager {
    pub(super) fn new() -> Self {
        Self {
            live: BTreeMap::new(),
            identities: BTreeMap::new(),
            records: BTreeMap::new(),
            last_planned_workers: 0,
            last_planned_bindings: 0,
            last_planned_worker_slots: 0,
            session_delta_drain_cursor: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    #[inline]
    pub(super) fn last_planned_workers(&self) -> usize {
        self.last_planned_workers
    }

    #[inline]
    pub(super) fn last_planned_worker_slots(&self) -> usize {
        self.last_planned_worker_slots
    }

    #[inline]
    pub(super) fn last_planned_bindings(&self) -> usize {
        self.last_planned_bindings
    }

    /// #1189 Phase 1: stop all workers, drain map slots, and clear
    /// per-worker state. Called from `Coordinator::stop_inner`.
    /// Caller passes the BPF map fds because they live on
    /// `Coordinator::bpf_maps`, not on `WorkerManager`.
    ///
    /// #6242: the two-pass signal-ALL-then-join-ALL order is load-bearing —
    /// join one worker while its peers are unsignalled and a peer that blocks
    /// on a shared resource deadlocks the join. The XSK/heartbeat slot deletion
    /// runs over `live` (slot-keyed) while the coordinator FDs are still open,
    /// BEFORE clearing. `records.clear()` then drops each record's handle +
    /// panic + exception_ring + last_resolution `Arc`s together, in one step —
    /// subsuming the three `Coordinator.*.clear()` the pre-#6242 layout ran and
    /// removing the dead #5289 content-clear loops that iterated the
    /// already-emptied maps.
    pub(super) fn stop_and_clear(
        &mut self,
        xsk_map_fd: Option<&crate::afxdp::bpf_map::OwnedFd>,
        heartbeat_map_fd: Option<&crate::afxdp::bpf_map::OwnedFd>,
    ) {
        for rec in self.records.values_mut() {
            rec.handle.stop.store(true, Ordering::Relaxed);
        }
        for rec in self.records.values_mut() {
            if let Some(join) = rec.handle.join.take() {
                let _ = join.join();
            }
        }
        if let Some(fd) = xsk_map_fd {
            for (&slot, _) in &self.live {
                let _ = delete_xsk_slot(fd.fd, slot);
            }
        }
        if let Some(fd) = heartbeat_map_fd {
            for (&slot, _) in &self.live {
                let _ = delete_heartbeat_slot(fd.fd, slot);
            }
        }
        self.records.clear();
        self.identities.clear();
        self.live.clear();
    }
}
