//! #6592: the atomically-paired worker-visible runtime view.
//!
//! # Why this type exists
//!
//! Validation (`config_generation` / `fib_generation`, the values
//! `classify_metadata` matches a packet's shim stamp against) and the
//! `ForwardingState` (the policy/FIB/NAT tables a `Valid` packet is then
//! forwarded under) used to be published through TWO independent `ArcSwap`s.
//! A worker refreshing its per-tick view performed two separate acquire-loads,
//! so a coordinator publish landing between them left the worker holding one
//! half from generation N and the other from N-1 — a TORN pair. Both
//! orientations were reachable and both are unsafe:
//!
//! - `(old validation, new forwarding)` — a packet stamped at the OLD
//!   generation matches the worker's old validation, classifies `Valid`, and
//!   is then forwarded under the NEW tables. (#6291.)
//! - `(new validation, old forwarding)` — once the coordinator's reply reaches
//!   Go and Go writes the new generation into `userspace_ctrl`, the shim stamps
//!   NEW. Those packets match the worker's new validation, classify `Valid`,
//!   and are forwarded under the STALE tables — a withdrawn route still
//!   resolves, a newly added deny is not applied. (#6592, the mirror.)
//!
//! Reordering the two loads can only ever exclude ONE orientation (the
//! producer and consumer must run in opposite orders for an acquire/release
//! pair, which is exactly one of the two). Closing BOTH needs the two values to
//! travel in ONE `Arc`, which is this type: a worker's refresh is a single
//! `ArcSwap` load, and whichever `RuntimeView` it observes, `validation` and
//! `forwarding` came from the same publish. There is no pair to tear.
//!
//! Holding an OLD view is still possible and is still SAFE — that is the
//! intended fail-closed behaviour. A worker that has not refreshed matches
//! new-stamped packets against old validation, they mismatch, and they DROP.
//! The defect this type closes is specifically an INCOHERENT pair, not a stale
//! coherent one; nothing here forces a refresh.
//!
//! # Why `forwarding` is a nested `Arc`, not an inlined field
//!
//! The obvious alternative — make `ValidationState` a field of
//! `ForwardingState` — is structurally simpler but breaks the #1188 worker
//! short-circuit. `Coordinator::bump_fib_generation` advances validation with
//! NO forwarding rebuild (that is its entire purpose: Go's
//! `Manager.BumpFIBGeneration` fires repeatedly during route convergence
//! precisely to avoid the full `buildSnapshot()` + `apply_snapshot` round
//! trip). Inlining would force a full `ForwardingState` clone — 69 fields, ~20
//! heap-owning collections including the FIB — per bump on the coordinator,
//! and on every worker would rotate the forwarding `Arc`, taking the expensive
//! rotation branch (screen-profile + opening-override clones, cold-path slot
//! rescan, input-filter session purges, CoS runtime reset) for a change that
//! touched neither policy nor FIB tables.
//!
//! With the nested `Arc`, a validation-only publish allocates one small
//! `RuntimeView` and REUSES the inner forwarding `Arc`. The worker's
//! `Arc::ptr_eq` short-circuit still hits, so #1188 is preserved exactly.
//!
//! # Publish ordering is unchanged
//!
//! The `RuntimeView` store sits exactly where the `ha.forwarding` store sat: it
//! is still THE single worker-visible release gate, and #5166 still holds —
//! the CoS owner/live/lease/backlog/vtime maps and `ha.fabrics` are stored
//! BEFORE it, and the worker reads them AFTER its view load.
use super::*;

/// The worker-visible `(validation, forwarding)` pair, published as ONE
/// `Arc` so the two can never be observed from different generations.
///
/// Cheap to clone: `ValidationState` is `Copy` (24 bytes) and `forwarding` is
/// an `Arc` refcount bump. Publishing a view that reuses the current
/// forwarding costs one small allocation and no table copying.
#[derive(Clone, Debug)]
pub(in crate::afxdp) struct RuntimeView {
    /// Generation stamps a packet's shim metadata is matched against
    /// (`classify_metadata`).
    pub(in crate::afxdp) validation: ValidationState,
    /// The policy / FIB / NAT tables a `Valid` packet is forwarded under.
    pub(in crate::afxdp) forwarding: Arc<ForwardingState>,
}

impl Default for RuntimeView {
    fn default() -> Self {
        Self {
            validation: ValidationState::default(),
            forwarding: Arc::new(ForwardingState::default()),
        }
    }
}

impl RuntimeView {
    /// Build a view pairing `validation` with an already-published forwarding
    /// `Arc` (refcount bump, no table copy). Used by the validation-only
    /// publish path (`bump_fib_generation`) so the forwarding `Arc` identity —
    /// and with it the worker's #1188 short-circuit — is preserved.
    pub(in crate::afxdp) fn new(validation: ValidationState, forwarding: Arc<ForwardingState>) -> Self {
        Self {
            validation,
            forwarding,
        }
    }
}

/// #1188 short-circuit over a [`RuntimeView`] `ArcSwap` for readers that need
/// ONLY the forwarding half (the GRE local-origin / WG control threads).
///
/// Returns `Some(new_arc)` when the published forwarding `Arc` differs from
/// `cached`, `None` when it is the same allocation. A validation-only publish
/// rotates the view but NOT the inner forwarding `Arc`, so such readers
/// correctly see no change.
#[inline]
pub(in crate::afxdp) fn load_forwarding_if_changed(
    cached: &Arc<ForwardingState>,
    shared: &ArcSwap<RuntimeView>,
) -> Option<Arc<ForwardingState>> {
    let view = shared.load();
    if Arc::ptr_eq(cached, &view.forwarding) {
        None
    } else {
        Some(view.forwarding.clone())
    }
}
