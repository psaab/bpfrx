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
    /// `self.validation` AT the store.
    ///
    /// The type is [`RuntimeViewChannel`], not a bare `Arc<ArcSwap<..>>`: its
    /// `ArcSwap` is a private field, so `publish` is the only mutation
    /// reachable anywhere and `swap` / `rcu` / `compare_and_swap` / `Deref` are
    /// not. Readers outside the coordinator take a [`RuntimeViewReader`] via
    /// [`HaState::runtime_reader`], which cannot publish at all.
    pub(super) runtime: RuntimeViewChannel,
}

impl HaState {
    pub(super) fn new() -> Self {
        Self {
            rg_runtime: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            fabrics: Arc::new(ArcSwap::from_pointee(Vec::new())),
            runtime: RuntimeViewChannel::default(),
        }
    }

    /// #6592: a READ-ONLY handle on the published runtime view, for the worker
    /// launch bundle and the GRE/WG aux threads.
    ///
    /// It returns a [`RuntimeViewReader`], not the `ArcSwap`. The earlier
    /// version returned `Arc<ArcSwap<RuntimeView>>` and a review probe used
    /// exactly that to alias the writer and publish a torn pair from
    /// `refresh_fabric_links` — every textual canary rule passed. A consumer
    /// now has no way to reach a writer, so that bypass is a COMPILE error
    /// rather than something a canary has to notice.
    pub(in crate::afxdp) fn runtime_reader(&self) -> RuntimeViewReader {
        self.runtime.reader()
    }
}
