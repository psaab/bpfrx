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
    /// #6592: the single worker-visible runtime gate — validation AND
    /// forwarding in ONE `Arc`, so a reader can never pair them across
    /// generations. Replaces the former `forwarding: Arc<ArcSwap<
    /// ForwardingState>>` + the sibling `Coordinator::shared_validation`;
    /// see `types/runtime_view.rs` for why the forwarding half stays a
    /// nested `Arc` (the #1188 short-circuit).
    ///
    /// **Narrower than its two siblings on purpose.** `pub(super)` — the
    /// `coordinator` module tree only — not `pub(in crate::afxdp)`. Publishing
    /// a view pairs `Coordinator::validation` with a forwarding state, and that
    /// pairing is the whole point of #6592; every publish must therefore go
    /// through `Coordinator::store_runtime_view`, which builds the view from
    /// `self.validation` AT the store. A site elsewhere in `crate::afxdp`
    /// storing directly — say an HA or fabric path publishing forwarding with a
    /// validation it captured earlier — would reintroduce the torn pair on the
    /// WRITER side, where neither RED-on-revert seam can see it (both sit
    /// inside or behind the choke point). This visibility removes the reach
    /// from `worker/`, `tunnel.rs`, `ha/`, `forwarding/` and every other afxdp
    /// module; it does NOT by itself stop a new site inside `coordinator/`,
    /// which is what `tests/runtime_view_publish_canary.rs` pins.
    ///
    /// Readers outside the coordinator take a handle via
    /// [`HaState::runtime_reader`].
    pub(super) runtime: Arc<ArcSwap<RuntimeView>>,
}

impl HaState {
    pub(super) fn new() -> Self {
        Self {
            rg_runtime: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            fabrics: Arc::new(ArcSwap::from_pointee(Vec::new())),
            runtime: Arc::new(ArcSwap::from_pointee(RuntimeView::default())),
        }
    }

    /// #6592: a READER handle on the published runtime view, for the worker
    /// launch bundle and the GRE/WG aux threads. The `ArcSwap` itself is not
    /// reachable as a field outside the coordinator (see the field doc); this
    /// is the one way out, and it is named so a `.store(` on its result reads
    /// as obviously wrong at review time. The canary
    /// (`tests/runtime_view_publish_canary.rs`) is what mechanically pins that:
    /// a `RuntimeView` cannot be CONSTRUCTED outside the choke point without
    /// tripping it, so no holder of this handle can publish a mispaired view.
    pub(in crate::afxdp) fn runtime_reader(&self) -> Arc<ArcSwap<RuntimeView>> {
        self.runtime.clone()
    }
}
