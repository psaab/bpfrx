use super::*;

/// Per-worker lifecycle and planning state.
///
/// Two distinct key spaces live here:
/// - `live` and `identities` are keyed by binding `slot` (per-binding
///   per-worker, populated from `BindingPlan::slot` in `refresh_bindings`).
/// - `handles` is keyed by `worker_id` (one entry per spawned worker
///   thread).
///
/// `last_planned_count` and `last_planned_bindings` are reconcile-pass
/// bookkeeping surfaced in the stage label and operator status surface.
pub(in crate::afxdp) struct WorkerManager {
    pub(in crate::afxdp) live: BTreeMap<u32, Arc<BindingLiveState>>,
    pub(in crate::afxdp) identities: BTreeMap<u32, BindingIdentity>,
    pub(in crate::afxdp) handles: BTreeMap<u32, WorkerHandle>,
    pub(in crate::afxdp) last_planned_count: usize,
    pub(in crate::afxdp) last_planned_bindings: usize,
}

impl WorkerManager {
    pub(super) fn new() -> Self {
        Self {
            live: BTreeMap::new(),
            identities: BTreeMap::new(),
            handles: BTreeMap::new(),
            last_planned_count: 0,
            last_planned_bindings: 0,
        }
    }
}
