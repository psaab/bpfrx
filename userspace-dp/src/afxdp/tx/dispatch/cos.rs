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

#[inline]
pub(super) fn request_uses_shared_exact_queue_lease(
    cos_fast_interfaces: &FastMap<i32, WorkerCoSInterfaceFastPath>,
    egress_ifindex: i32,
    requested_queue_id: Option<u8>,
) -> bool {
    cos_queue_fast_path_for_request(cos_fast_interfaces, egress_ifindex, requested_queue_id)
        .is_some_and(|queue_fast| queue_fast.shared_queue_lease.is_some())
}

#[inline]
pub(super) fn enqueue_local_request_to_target_or_owner(
    target_binding: &mut BindingWorker,
    req: TxRequest,
) -> Result<(), TxRequest> {
    if request_uses_shared_exact_queue_lease(
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
