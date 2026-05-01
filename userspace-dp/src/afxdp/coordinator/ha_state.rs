use super::*;

/// Cross-thread HA reconciliation state shared between the coordinator,
/// HA worker, and packet workers via `Arc<ArcSwap<…>>`.
///
/// The 3 fields land here together because they're all written by the
/// same reconciliation pass (RG demote/activate, fabric refresh,
/// forwarding rebuild) and read by the worker hot path. Splitting them
/// further would create artificial cross-struct coupling on the
/// reconcile call sites.
pub(in crate::afxdp) struct HaState {
    pub(in crate::afxdp) rg_runtime: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    pub(in crate::afxdp) fabrics: Arc<ArcSwap<Vec<FabricLink>>>,
    pub(in crate::afxdp) forwarding: Arc<ArcSwap<ForwardingState>>,
}

impl HaState {
    pub(super) fn new() -> Self {
        Self {
            rg_runtime: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            fabrics: Arc::new(ArcSwap::from_pointee(Vec::new())),
            forwarding: Arc::new(ArcSwap::from_pointee(ForwardingState::default())),
        }
    }
}
