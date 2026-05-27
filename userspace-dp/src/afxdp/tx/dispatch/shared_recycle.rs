// Phase 10 + cross-tick shared-UMEM recycle routing (#1443).
//
// Pure code motion from `dispatch/mod.rs` — every function in this
// file lived in `dispatch.rs` before the #1443 split. The dispatch
// `mod.rs` re-exports `apply_shared_recycles`,
// `apply_shared_recycles_to_bindings`, and `resolve_tx_binding_ifindex`
// at `pub(in crate::afxdp)` so the 16+ external call sites and the
// `use self::tx::dispatch::*;` glob at `afxdp/mod.rs:140` resolve
// verbatim.

use super::*;

pub(in crate::afxdp) fn apply_shared_recycles(
    left: &mut [BindingWorker],
    current_index: usize,
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    if shared_recycles.is_empty() {
        return;
    }
    let mut dropped = 0u64;
    let mut first_drop = None;
    for (slot, offset) in shared_recycles.drain(..) {
        if route_shared_recycle_by_slot(
            left,
            current_index,
            current,
            right,
            binding_lookup,
            slot,
            offset,
        ) {
            continue;
        }
        first_drop.get_or_insert((slot, offset));
        dropped = dropped.saturating_add(1);
    }
    log_shared_recycle_unknown_slot_drops(dropped, first_drop);
    record_shared_recycle_unknown_slot_drops(Some(&current.live), dropped);
}

fn route_shared_recycle_by_slot(
    left: &mut [BindingWorker],
    current_index: usize,
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    slot: u32,
    offset: u64,
) -> bool {
    let target_index = shared_recycle_target_index_for_split(
        left.len(),
        right.len(),
        binding_lookup,
        slot,
        |idx| split_binding_slot_at(left, current_index, current, right, idx),
    );
    if let Some(target_index) = target_index
        && let Some(binding) =
            binding_by_index_mut(left, current_index, current, right, target_index)
    {
        binding.tx_pipeline.pending_fill_frames.push_back(offset);
        return true;
    }
    false
}

pub(super) fn shared_recycle_target_index_for_split<F>(
    left_len: usize,
    right_len: usize,
    binding_lookup: &WorkerBindingLookup,
    slot: u32,
    slot_at: F,
) -> Option<usize>
where
    F: FnMut(usize) -> Option<u32>,
{
    shared_recycle_target_index(
        left_len.saturating_add(1).saturating_add(right_len),
        binding_lookup,
        slot,
        slot_at,
    )
}

fn split_binding_slot_at(
    left: &[BindingWorker],
    current_index: usize,
    current: &BindingWorker,
    right: &[BindingWorker],
    target_index: usize,
) -> Option<u32> {
    if target_index == current_index {
        return Some(current.slot);
    }
    if target_index < current_index {
        return left.get(target_index).map(|binding| binding.slot);
    }
    right
        .get(target_index.saturating_sub(current_index + 1))
        .map(|binding| binding.slot)
}

pub(super) fn shared_recycle_target_index<F>(
    binding_count: usize,
    binding_lookup: &WorkerBindingLookup,
    slot: u32,
    mut slot_at: F,
) -> Option<usize>
where
    F: FnMut(usize) -> Option<u32>,
{
    if let Some(target_index) = binding_lookup.slot_index(slot)
        && target_index < binding_count
        && slot_at(target_index) == Some(slot)
    {
        return Some(target_index);
    }
    (0..binding_count).find(|&idx| slot_at(idx) == Some(slot))
}

pub(super) fn record_shared_recycle_unknown_slot_drops(
    error_live: Option<&BindingLiveState>,
    dropped: u64,
) {
    if dropped == 0 {
        return;
    }
    if let Some(live) = error_live {
        live.tx_errors.fetch_add(dropped, Ordering::Relaxed);
        live.tx_shared_recycle_unknown_slot_drops
            .fetch_add(dropped, Ordering::Relaxed);
    }
}

fn log_shared_recycle_unknown_slot_drops(dropped: u64, first_drop: Option<(u32, u64)>) {
    if dropped == 0 {
        return;
    }
    if let Some((slot, offset)) = first_drop {
        eprintln!(
            "xpf-userspace-dp: dropping {} shared UMEM recycles for unknown slots \
             (first slot {} offset {})",
            dropped, slot, offset
        );
    } else {
        eprintln!(
            "xpf-userspace-dp: dropping {} shared UMEM recycles for unknown slots",
            dropped
        );
    }
}

pub(in crate::afxdp) fn apply_shared_recycles_to_bindings(
    bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> u64 {
    if shared_recycles.is_empty() {
        return 0;
    }
    let mut dropped = 0u64;
    let mut first_drop = None;
    for (slot, offset) in shared_recycles.drain(..) {
        let target_index =
            shared_recycle_target_index(bindings.len(), binding_lookup, slot, |idx| {
                bindings.get(idx).map(|binding| binding.slot)
            });
        if let Some(target_index) = target_index
            && let Some(binding) = bindings.get_mut(target_index)
        {
            binding.tx_pipeline.pending_fill_frames.push_back(offset);
            continue;
        }
        first_drop.get_or_insert((slot, offset));
        dropped = dropped.saturating_add(1);
    }
    log_shared_recycle_unknown_slot_drops(dropped, first_drop);
    record_shared_recycle_unknown_slot_drops(
        bindings.first().map(|binding| binding.live.as_ref()),
        dropped,
    );
    dropped
}

pub(in crate::afxdp) fn resolve_tx_binding_ifindex(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
) -> i32 {
    if let Some(fabric) = forwarding
        .fabrics
        .iter()
        .find(|fabric| fabric.parent_ifindex == egress_ifindex)
    {
        return fabric.parent_ifindex;
    }
    forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.bind_ifindex)
        .filter(|ifindex| *ifindex > 0)
        .unwrap_or(egress_ifindex)
}
