// CoS TX-selection resolve + COS fast-path enqueue helpers for the
// dispatch loop (#1443).
//
// Pure code motion from `dispatch/mod.rs`. All helpers are per-
// request hot path; the orchestrator calls them once per
// `pending_forwards` iteration. `#[inline]` on each helper — one
// caller, release-build inlining is reliable.
//
// `enqueue_local_request_to_target_or_owner` is the COS-shared
// fast-path enqueue that may either keep the request on the
// local TX queue or hand it off to the owner binding's MPSC
// channel via `owner_live.enqueue_tx_owned(req)`. Cross-worker
// ordering (HA session-sync) depends on this happening in the
// same per-request sequence the master code uses — no batching,
// no reordering, no hoisting upstream of the loop.

use super::*;

#[inline]
pub(super) fn cos_queue_fast_path_for_request<'a>(
    cos_fast_interfaces: &'a FastMap<i32, WorkerCoSInterfaceFastPath>,
    egress_ifindex: i32,
    requested_queue_id: Option<u8>,
) -> Option<&'a WorkerCoSQueueFastPath> {
    let iface = cos_fast_interfaces.get(&egress_ifindex)?;
    iface.queue_fast_path(requested_queue_id)
}

#[inline]
pub(super) fn cos_owner_live_for_request(
    cos_fast_interfaces: &FastMap<i32, WorkerCoSInterfaceFastPath>,
    egress_ifindex: i32,
    requested_queue_id: Option<u8>,
) -> Option<Arc<BindingLiveState>> {
    cos_queue_fast_path_for_request(cos_fast_interfaces, egress_ifindex, requested_queue_id)
        .and_then(|queue_fast| queue_fast.owner_live.clone())
}

/// #1598 (secondary fix): does this request target a queue that runs
/// under the shared multi-worker drain policy?
///
/// This is the routing-level "stay local — don't funnel to one owner"
/// signal. It distinguishes three queue regimes:
///
/// - Exact + high-rate queues: `shared_exact = true` AND
///   `shared_queue_lease = Some(...)` (lease holds the per-queue rate
///   cap). Returns `true`.
/// - Non-exact + high-rate queues (e.g. Junos `priority low` uncapped
///   class with effective rate at the iface shaping rate): `shared_exact
///   = true` but `shared_queue_lease = None` (no per-queue rate cap to
///   serve, see `coordinator/mod.rs:1058`). Returns `true`.
/// - Low-rate queues (exact or non-exact): `shared_exact = false`.
///   Returns `false`; the request funnels to `owner_worker_id`.
///
/// The previous implementation of this gate consulted
/// `shared_queue_lease.is_some()` as a proxy for the routing policy.
/// That worked before #1598 (the two were coextensive on the production
/// queue set, exact queues only), but diverged once non-exact uncapped
/// queues were admitted to `shared_exact` — they have no lease, so the
/// proxy mis-classified them as "single-owner, route to owner",
/// recreating the cross-worker funnel that the routing-side
/// `queue_uses_shared_exact_service` fix at `worker/cos/mod.rs:126-131`
/// was supposed to break (#1598 primary smoke regression).
///
/// Lease-bookkeeping consumers (`token_bucket.rs`, `tx_completion.rs`)
/// inspect `queue_fast.shared_queue_lease.as_ref()` directly via
/// `if let Some(lease)`; they have never used a helper for the
/// "is there a lease?" question, so no separate helper is needed.
#[inline]
pub(super) fn request_runs_under_shared_exact_policy(
    cos_fast_interfaces: &FastMap<i32, WorkerCoSInterfaceFastPath>,
    egress_ifindex: i32,
    requested_queue_id: Option<u8>,
) -> bool {
    cos_queue_fast_path_for_request(cos_fast_interfaces, egress_ifindex, requested_queue_id)
        .is_some_and(|queue_fast| queue_fast.shared_exact)
}

#[inline]
pub(super) fn enqueue_local_request_to_target_or_owner(
    target_binding: &mut BindingWorker,
    req: TxRequest,
) -> Result<(), TxRequest> {
    // #1598 secondary fix: gate on the routing-level `shared_exact`
    // flag rather than on `shared_queue_lease.is_some()`. The lease is
    // an exact-queue-only marker — non-exact uncapped queues run under
    // shared_exact but have no per-queue lease, so the lease-only gate
    // here was funneling them to a single owner_worker_id (rebuilding
    // the cross-binding funnel the worker/cos/mod.rs:126-131 primary
    // fix was supposed to break).
    if request_runs_under_shared_exact_policy(
        &target_binding.cos.cos_fast_interfaces,
        req.egress_ifindex,
        req.cos_queue_id,
    ) {
        target_binding.tx_pipeline.pending_tx_local.push_back(req);
        bound_pending_tx_local(target_binding);
        return Ok(());
    }
    let owner_live = cos_owner_live_for_request(
        &target_binding.cos.cos_fast_interfaces,
        req.egress_ifindex,
        req.cos_queue_id,
    );
    if let Some(owner_live) = owner_live {
        if !Arc::ptr_eq(&owner_live, &target_binding.live) {
            return owner_live.enqueue_tx_owned(req);
        }
    }
    target_binding.tx_pipeline.pending_tx_local.push_back(req);
    bound_pending_tx_local(target_binding);
    Ok(())
}

#[inline]
pub(super) fn resolve_pending_forward_cos_tx_selection(
    forwarding: &ForwardingState,
    request: &PendingForwardRequest,
    now_ns: u64,
) -> CoSTxSelection {
    resolve_cos_tx_selection_at(
        forwarding,
        request.decision.resolution.egress_ifindex,
        request.meta,
        request.flow_key.as_ref(),
        now_ns,
    )
}

#[inline]
pub(super) fn pending_forward_needs_cos_tx_selection(
    request: &PendingForwardRequest,
    tx_selection_enabled_v4: bool,
    tx_selection_enabled_v6: bool,
) -> bool {
    let tx_selection_enabled = if request.meta.addr_family as i32 == libc::AF_INET6 {
        tx_selection_enabled_v6
    } else {
        tx_selection_enabled_v4
    };
    tx_selection_enabled && !request.cos_tx_selection_resolved
}
