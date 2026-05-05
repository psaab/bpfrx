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
pub(in crate::afxdp) struct WorkerManager {
    pub(in crate::afxdp) live: BTreeMap<u32, Arc<BindingLiveState>>,
    pub(in crate::afxdp) identities: BTreeMap<u32, BindingIdentity>,
    pub(in crate::afxdp) handles: BTreeMap<u32, WorkerHandle>,
    pub(in crate::afxdp) last_planned_workers: usize,
    pub(in crate::afxdp) last_planned_bindings: usize,
}

impl WorkerManager {
    pub(super) fn new() -> Self {
        Self {
            live: BTreeMap::new(),
            identities: BTreeMap::new(),
            handles: BTreeMap::new(),
            last_planned_workers: 0,
            last_planned_bindings: 0,
        }
    }

    pub(super) fn last_planned_workers(&self) -> usize {
        self.last_planned_workers
    }

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
        for (_, handle) in self.handles.iter_mut() {
            if let Some(join) = handle.join.take() {
                let _ = join.join();
            }
        }
        if let Some(map_fd) = xsk_map_fd {
            for slot in self.live.keys().copied().collect::<Vec<_>>() {
                let _ = delete_xsk_slot(map_fd.fd, slot);
            }
        }
        if let Some(map_fd) = heartbeat_map_fd {
            for slot in self.live.keys().copied().collect::<Vec<_>>() {
                let _ = delete_heartbeat_slot(map_fd.fd, slot);
            }
        }
        self.handles.clear();
        self.identities.clear();
        self.live.clear();
    }
}
