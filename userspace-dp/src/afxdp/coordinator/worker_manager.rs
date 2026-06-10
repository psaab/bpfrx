use super::*;

/// Per-worker lifecycle and planning state.
///
/// Two distinct key spaces live here:
/// - `live` and `identities` are keyed by binding `slot` (per-binding
///   per-worker, populated from `BindingPlan::slot` in `refresh_bindings`).
/// - `handles` is keyed by `worker_id` (one entry per spawned worker
///   thread).
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
    pub(in crate::afxdp) handles: BTreeMap<u32, WorkerHandle>,
    pub(super) last_planned_workers: usize,
    pub(super) last_planned_bindings: usize,
    pub(super) last_planned_worker_slots: usize,
}

impl WorkerManager {
    pub(super) fn new() -> Self {
        Self {
            live: BTreeMap::new(),
            identities: BTreeMap::new(),
            handles: BTreeMap::new(),
            last_planned_workers: 0,
            last_planned_bindings: 0,
            last_planned_worker_slots: 0,
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
    pub(super) fn stop_and_clear(
        &mut self,
        xsk_map_fd: Option<&crate::afxdp::bpf_map::OwnedFd>,
        heartbeat_map_fd: Option<&crate::afxdp::bpf_map::OwnedFd>,
    ) {
        for handle in self.handles.values_mut() {
            handle.stop.store(true, Ordering::Relaxed);
        }
        for handle in self.handles.values_mut() {
            if let Some(join) = handle.join.take() {
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
        self.handles.clear();
        self.identities.clear();
        self.live.clear();
    }
}
