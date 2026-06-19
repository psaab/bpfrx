use super::*;

// #1986: was a module-private `fn` in the monolithic mirror.rs; widened to
// `pub(super)` so the fast path (now in `fast_path.rs`) can still reach it
// across the new module boundary. `#[inline]` preserves the same-module
// inlining the fast path relied on before the split.
#[inline]
pub(super) fn mirror_target_binding_index(
    binding_lookup: &WorkerBindingLookup,
    ingress_index: usize,
    ingress_ifindex: i32,
    ingress_queue_id: u32,
    mirror_tx_ifindex: i32,
) -> Option<usize> {
    if ingress_ifindex == mirror_tx_ifindex {
        return Some(ingress_index);
    }
    binding_lookup
        .by_if_queue
        .get(&(mirror_tx_ifindex, ingress_queue_id))
        .copied()
        .or_else(|| {
            let indices = binding_lookup.all_by_if.get(&mirror_tx_ifindex)?;
            (indices.len() == 1).then_some(indices[0])
        })
}

// #1986: `#[inline]` added so the fast path's admission check keeps inlining
// after the cross-module split (it was fully inlined when colocated in
// mirror.rs); visibility is unchanged from the monolith.
#[inline]
pub(in crate::afxdp) fn admit_mirror_clone_to_live(
    mirror_targets: &MirrorTargetMap,
    mirror_tx_ifindex: i32,
    ingress_queue_id: u32,
    frame_len: usize,
) -> Result<PendingTxAdmission, MirrorCloneResult> {
    if frame_len > tx_frame_capacity() {
        return Err(MirrorCloneResult::NoFrame);
    }
    let Some(target_live) = mirror_targets.target_live(mirror_tx_ifindex, ingress_queue_id) else {
        return Err(MirrorCloneResult::NoBinding);
    };
    BindingLiveState::try_reserve_mirror_tx_owned(&target_live, MIRROR_PENDING_LIMIT)
        .map_err(|_| MirrorCloneResult::QueueFullCrossWorker)
}

#[inline]
pub(in crate::afxdp) fn mirror_cos_queue_id(
    forwarding: &ForwardingState,
    output_ifindex: i32,
    meta: ForwardPacketMeta,
    flow_key: Option<&SessionKey>,
) -> Option<u8> {
    resolve_cached_cos_tx_selection(forwarding, output_ifindex, meta.into(), flow_key).queue_id
}

#[inline]
pub(in crate::afxdp) fn record_mirror_clone_result(
    live: &BindingLiveState,
    result: MirrorCloneResult,
    frame_len: usize,
) {
    match result {
        MirrorCloneResult::Enqueued => {
            live.mirrored_packets.fetch_add(1, Ordering::Relaxed);
            live.mirrored_bytes
                .fetch_add(frame_len as u64, Ordering::Relaxed);
        }
        MirrorCloneResult::NoBinding => {
            live.mirror_drops_no_binding.fetch_add(1, Ordering::Relaxed);
        }
        MirrorCloneResult::NoFrame => {
            live.mirror_drops_no_frame.fetch_add(1, Ordering::Relaxed);
        }
        MirrorCloneResult::TxFrameReserve => {
            live.mirror_drops_tx_frame_reserve
                .fetch_add(1, Ordering::Relaxed);
        }
        MirrorCloneResult::QueueFullSameWorker => {
            live.mirror_drops_queue_full.fetch_add(1, Ordering::Relaxed);
            live.mirror_drops_queue_full_same_worker
                .fetch_add(1, Ordering::Relaxed);
        }
        MirrorCloneResult::QueueFullCrossWorker => {
            live.mirror_drops_queue_full.fetch_add(1, Ordering::Relaxed);
            live.mirror_drops_queue_full_cross_worker
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}
