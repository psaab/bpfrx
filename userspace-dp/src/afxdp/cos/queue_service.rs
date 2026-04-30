// #956 Phase 7: CoS dispatch / drain / submit subsystem, extracted
// from tx.rs. The largest move of the campaign — ~2400 LOC covering
// the full per-byte hot-path chain:
//
//   drain_shaped_tx ->
//     select_cos_*_batch (guarantee / nonexact / surplus / fast-path) ->
//       service_exact_*_queue_direct(_flow_fair) ->
//         drain_exact_*_to_scratch ->
//           submit_cos_batch + cos_batch_tx_made_progress ->
//             settle_exact_*_submission*
//
// Plus the dispatch types (CoSBatch, CoSServicePhase, ExactCoSQueueKind,
// ExactCoSQueueSelection, ExactCoSScratchBuild, DrainedQueueRef,
// ParkReason) and scheduler helpers (cos_*_quantum_bytes,
// estimate_cos_queue_wakeup_tick, count_park_reason, park_cos_queue).
//
// Per the Phase 4-6 lesson, all per-byte / per-batch hot-path fns
// carry #[inline] (added on the move; the source bodies didn't have
// it). Larger bodies (drain_*_to_scratch, settle_*) skip #[inline] —
// LLVM's heuristic threshold should cover them; revisit only if a
// post-merge perf regression points at one.
//
// TX-completion + timer-wheel back-edges (apply_cos_*_result,
// restore_cos_*_inner, prime_cos_root_for_service,
// refresh_cos_interface_activity, cos_tick_for_ns +
// cos_timer_wheel_level_and_slot + count_tx_ring_full_submit_stall)
// moved to cos/tx_completion.rs in #956 P1.
//
// Remaining back-edges to crate::afxdp::tx are XSK-ring /
// worker-binding / prepared-frame primitives (transmit_*,
// reap_tx_completions, maybe_wake_tx, recycle_*, stamp_submits,
// cos_queue_dscp_rewrite, TxError, the guarantee/quantum constants).
// Those move with the afxdp/tx/ split in #984.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use crate::afxdp::frame::{apply_dscp_rewrite_to_frame, frame_has_tcp_rst};
use crate::afxdp::neighbor::monotonic_nanos;
use crate::afxdp::types::{
    CoSInterfaceRuntime, CoSPendingTxItem,
    CoSQueueRuntime, ExactLocalScratchTxRequest, ExactPreparedScratchTxRequest,
    PreparedTxRecycle, PreparedTxRequest, TxRequest,
    WorkerCoSQueueFastPath, COS_PRIORITY_LEVELS,
};
use crate::afxdp::umem::MmapArea;
use crate::afxdp::worker::BindingWorker;
use crate::xsk_ffi::xdp::XdpDesc;
use crate::afxdp::{tx_frame_capacity, FastMap, TX_BATCH_SIZE};

use super::{
    cos_item_len,
    cos_queue_clear_orphan_snapshot_after_drop, cos_queue_front, cos_queue_is_empty,
    cos_queue_pop_front, cos_queue_push_front,
    cos_queue_v_min_consume_suspension, cos_queue_v_min_continue,
    cos_refill_ns_until, maybe_top_up_cos_queue_lease, publish_committed_queue_vtime,
    refill_cos_tokens, COS_MIN_BURST_BYTES,
};

// #956 P1: TX-completion + timer-wheel symbols + scheduling primitives
// (CoSServicePhase, ParkReason, count_park_reason, park_cos_queue)
// moved to cos/tx_completion.rs. Moving the scheduling primitives
// breaks the previous cyclic queue_service <-> tx_completion module
// dependency (Copilot review on PR #990).
use super::tx_completion::{
    apply_cos_prepared_result, apply_cos_send_result,
    apply_direct_exact_send_result, cos_tick_for_ns,
    count_park_reason, count_tx_ring_full_submit_stall,
    park_cos_queue, prime_cos_root_for_service, refresh_cos_interface_activity,
    restore_cos_local_items_inner, restore_cos_prepared_items_inner, CoSServicePhase,
    ParkReason,
};
// Remaining back-edges to tx.rs (XSK-ring / worker-binding /
// prepared-frame primitives + TxError + guarantee/quantum constants —
// deferred to #984 / afxdp/tx/ split).
use crate::afxdp::tx::{
    cos_queue_dscp_rewrite, maybe_wake_tx, reap_tx_completions,
    recycle_cancelled_prepared_offset, remember_prepared_recycle, stamp_submits,
    transmit_batch, transmit_prepared_queue, TxError,
    COS_GUARANTEE_QUANTUM_MAX_BYTES, COS_GUARANTEE_QUANTUM_MIN_BYTES,
    COS_GUARANTEE_VISIT_NS, COS_SURPLUS_ROUND_QUANTUM_BYTES,
};

pub(in crate::afxdp) enum CoSBatch {
    Local {
        queue_idx: usize,
        phase: CoSServicePhase,
        batch_bytes: u64,
        items: VecDeque<TxRequest>,
    },
    Prepared {
        queue_idx: usize,
        phase: CoSServicePhase,
        batch_bytes: u64,
        items: VecDeque<PreparedTxRequest>,
    },
}

#[derive(Clone, Copy)]
enum ExactCoSQueueKind {
    Local,
    Prepared,
}

#[derive(Clone, Copy)]
pub(in crate::afxdp) struct ExactCoSQueueSelection {
    pub(in crate::afxdp) queue_idx: usize,
    pub(in crate::afxdp) secondary_budget: u64,
    kind: ExactCoSQueueKind,
}

pub(in crate::afxdp) enum ExactCoSScratchBuild {
    Ready,
    Drop { error: String, dropped_bytes: u64 },
}

/// #751: one drain pass through the binding's CoS interfaces. Returns
/// the (root_ifindex, queue_idx, queue_id) that was actually serviced
/// so the caller can attribute the drain latency to the specific
/// queue's per-queue atomics without walking the queues vec a second
/// time.
///
/// `queue_idx` is the stable position within `root.queues` captured
/// at selection time. The drain path mutates queue state (tokens,
/// queued_bytes) but does not reorder or reshape `root.queues`
/// within a single drain pass, so using the idx for direct indexed
/// access is safe and avoids the O(#queues) linear scan by
/// `queue_id` that the first revision of this PR used (Copilot
/// review, tx.rs:262).
///
/// `queue_id` is retained as a stable 8-bit identifier for the
/// snapshot and telemetry paths which key on id, not idx.
pub(in crate::afxdp) struct DrainedQueueRef {
    pub(in crate::afxdp) root_ifindex: i32,
    pub(in crate::afxdp) queue_idx: usize,
    pub(in crate::afxdp) queue_id: u8,
}

#[inline]
pub(in crate::afxdp) fn drain_shaped_tx(
    binding: &mut BindingWorker,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Option<DrainedQueueRef> {
    if binding.cos_nonempty_interfaces == 0 || binding.cos_interface_order.is_empty() {
        return None;
    }
    let start = binding.cos_interface_rr % binding.cos_interface_order.len();
    for offset in 0..binding.cos_interface_order.len() {
        let root_ifindex =
            binding.cos_interface_order[(start + offset) % binding.cos_interface_order.len()];
        let Some(root) = binding.cos_interfaces.get(&root_ifindex) else {
            continue;
        };
        if root.nonempty_queues == 0 {
            continue;
        }
        if !prime_cos_root_for_service(binding, root_ifindex, now_ns) {
            continue;
        }
        if let Some(serviced) = service_exact_guarantee_queue_direct_with_info(
            binding,
            root_ifindex,
            now_ns,
            shared_recycles,
        ) {
            binding.cos_interface_rr = (start + offset + 1) % binding.cos_interface_order.len();
            return serviced;
        }
        let Some(batch) = build_nonexact_cos_batch(binding, root_ifindex, now_ns) else {
            continue;
        };
        // #751: capture both queue_idx (stable Vec position) and
        // queue_id (stable u8 identifier) BEFORE submit_cos_batch
        // takes ownership of the batch. Pre-Copilot-review this
        // resolved only queue_id and the outer loop did a linear
        // scan by id; now we carry the idx through for direct
        // indexed access.
        let located = cos_batch_queue_ref(binding, root_ifindex, &batch);
        binding.cos_interface_rr = (start + offset + 1) % binding.cos_interface_order.len();
        if submit_cos_batch(binding, root_ifindex, batch, now_ns, shared_recycles) {
            return located.map(|(queue_idx, queue_id)| DrainedQueueRef {
                root_ifindex,
                queue_idx,
                queue_id,
            });
        }
        return None;
    }
    None
}

#[inline]
fn cos_batch_queue_ref(
    binding: &BindingWorker,
    root_ifindex: i32,
    batch: &CoSBatch,
) -> Option<(usize, u8)> {
    let queue_idx = match batch {
        CoSBatch::Local { queue_idx, .. } | CoSBatch::Prepared { queue_idx, .. } => *queue_idx,
    };
    binding
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .map(|queue| (queue_idx, queue.queue_id))
}

#[inline]
fn build_nonexact_cos_batch(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    now_ns: u64,
) -> Option<CoSBatch> {
    let selected = {
        let root = binding.cos_interfaces.get_mut(&root_ifindex)?;
        select_nonexact_cos_guarantee_batch(root, now_ns)
            .or_else(|| select_cos_surplus_batch(root, now_ns))
    };
    if selected.is_some() {
        refresh_cos_interface_activity(binding, root_ifindex);
    }
    selected
}

#[inline]
fn service_exact_guarantee_queue_direct(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Option<bool> {
    service_exact_guarantee_queue_direct_with_info(
        binding,
        root_ifindex,
        now_ns,
        shared_recycles,
    )
    .map(|slot| slot.is_some())
}

/// #751: variant that additionally reports which queue was actually
/// serviced so the caller can attribute per-queue drain latency.
/// Returns:
///   * `Some(Some(ref))` — exact-guarantee selection fired, batch
///     service progressed on `ref`.
///   * `Some(None)` — exact-guarantee selection fired but the service
///     call made no progress (batch build declined / TX ring refused).
///   * `None` — no exact-guarantee selection; caller falls through
///     to the non-exact path.
#[inline]
fn service_exact_guarantee_queue_direct_with_info(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Option<Option<DrainedQueueRef>> {
    let queue_fast_path = binding
        .cos_fast_interfaces
        .get(&root_ifindex)?
        .queue_fast_path
        .as_slice();
    let selection = {
        let root = binding.cos_interfaces.get_mut(&root_ifindex)?;
        select_exact_cos_guarantee_queue_with_fast_path(root, queue_fast_path, now_ns)?
    };

    let queue_id = binding
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(selection.queue_idx))
        .map(|queue| queue.queue_id);

    let progress = match selection.kind {
        ExactCoSQueueKind::Local => service_exact_local_queue_direct(
            binding,
            root_ifindex,
            selection.queue_idx,
            selection.secondary_budget,
            now_ns,
            shared_recycles,
        ),
        ExactCoSQueueKind::Prepared => service_exact_prepared_queue_direct(
            binding,
            root_ifindex,
            selection.queue_idx,
            selection.secondary_budget,
            now_ns,
        ),
    };

    Some(if progress {
        queue_id.map(|queue_id| DrainedQueueRef {
            root_ifindex,
            queue_idx: selection.queue_idx,
            queue_id,
        })
    } else {
        None
    })
}

#[cfg(test)]
#[inline]
pub(in crate::afxdp) fn select_cos_guarantee_batch(root: &mut CoSInterfaceRuntime, now_ns: u64) -> Option<CoSBatch> {
    select_cos_guarantee_batch_with_fast_path(root, &[], now_ns)
}

// Legacy single-pass guarantee selector that walks both classes in one
// iteration. The production path in `drain_shaped_tx` no longer calls this
// (it uses the two specialized selectors for strict-priority exact-over-
// nonexact service); `select_cos_guarantee_batch_with_fast_path` is retained
// solely for unit-test coverage of the batch-build mechanics and is
// compiled out of non-test builds along with its `legacy_guarantee_rr`
// cursor. Uses its own cursor so test harnesses that call this do not
// corrupt the production `exact_guarantee_rr` / `nonexact_guarantee_rr`
// cursors and vice versa.
#[cfg(test)]
#[inline]
pub(in crate::afxdp) fn select_cos_guarantee_batch_with_fast_path(
    root: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    now_ns: u64,
) -> Option<CoSBatch> {
    let queue_count = root.queues.len();
    if queue_count == 0 {
        return None;
    }
    let start = root.legacy_guarantee_rr % queue_count;
    for offset in 0..queue_count {
        let queue_idx = (start + offset) % queue_count;
        let queue = &mut root.queues[queue_idx];
        if cos_queue_is_empty(queue) || !queue.runnable {
            continue;
        }
        if queue.exact {
            maybe_top_up_cos_queue_lease(
                queue,
                queue_fast_path
                    .get(queue_idx)
                    .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref()),
                now_ns,
            );
        } else {
            refill_cos_tokens(
                &mut queue.tokens,
                queue.transmit_rate_bytes,
                queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
                &mut queue.last_refill_ns,
                now_ns,
            );
        }
        let Some(head) = cos_queue_front(queue) else {
            continue;
        };
        let head_len = cos_item_len(head);
        if root.tokens < head_len {
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.tokens,
                queue.transmit_rate_bytes,
                head_len,
                now_ns,
                queue.exact,
            ) {
                count_park_reason(root, queue_idx, ParkReason::RootTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        if queue.tokens < head_len {
            if queue.exact {
                if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                    root.tokens,
                    root.shaping_rate_bytes,
                    queue.tokens,
                    queue.transmit_rate_bytes,
                    head_len,
                    now_ns,
                    true,
                ) {
                    count_park_reason(root, queue_idx, ParkReason::QueueTokenStarvation);
                    park_cos_queue(root, queue_idx, wake_tick);
                }
            }
            continue;
        }
        root.legacy_guarantee_rr = (start + offset + 1) % queue_count;
        let guarantee_budget = queue
            .tokens
            .min(cos_guarantee_quantum_bytes(queue))
            .max(head_len);
        if let Some(batch) = build_cos_batch_from_queue(
            queue,
            queue_idx,
            root.tokens,
            guarantee_budget,
            CoSServicePhase::Guarantee,
        ) {
            return Some(batch);
        }
    }
    None
}

// Selects the next exact-class guarantee queue for service. Rotates
// independently of the non-exact pass via `exact_guarantee_rr` — the two
// classes are scheduled with strict-priority exact-over-nonexact and
// class-independent RR within each class.
#[inline]
pub(in crate::afxdp) fn select_exact_cos_guarantee_queue_with_fast_path(
    root: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    now_ns: u64,
) -> Option<ExactCoSQueueSelection> {
    let queue_count = root.queues.len();
    if queue_count == 0 {
        return None;
    }
    let start = root.exact_guarantee_rr % queue_count;
    for offset in 0..queue_count {
        let queue_idx = (start + offset) % queue_count;
        let queue = &mut root.queues[queue_idx];
        if cos_queue_is_empty(queue) || !queue.runnable || !queue.exact {
            continue;
        }
        maybe_top_up_cos_queue_lease(
            queue,
            queue_fast_path
                .get(queue_idx)
                .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref()),
            now_ns,
        );
        let Some(head) = cos_queue_front(queue) else {
            continue;
        };
        let head_len = cos_item_len(head);
        if root.tokens < head_len {
            // #760 instrumentation: record the per-queue observation
            // that the interface shaper held it back. Written
            // regardless of whether the wakeup-tick estimator
            // succeeds in parking it, because "gate fired" is the
            // signal we care about, not "queue successfully
            // scheduled". Same Relaxed reasoning as drain_invocations.
            queue
                .owner_profile
                .drain_park_root_tokens
                .fetch_add(1, Ordering::Relaxed);
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.tokens,
                queue.transmit_rate_bytes,
                head_len,
                now_ns,
                true,
            ) {
                count_park_reason(root, queue_idx, ParkReason::RootTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        if queue.tokens < head_len {
            // #760 instrumentation: the per-queue token gate held
            // this queue back. A queue that sustains throughput
            // above its configured rate with this counter near zero
            // is direct evidence the gate never fired.
            queue
                .owner_profile
                .drain_park_queue_tokens
                .fetch_add(1, Ordering::Relaxed);
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.tokens,
                queue.transmit_rate_bytes,
                head_len,
                now_ns,
                true,
            ) {
                count_park_reason(root, queue_idx, ParkReason::QueueTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        root.exact_guarantee_rr = (start + offset + 1) % queue_count;
        let secondary_budget = queue
            .tokens
            .min(cos_guarantee_quantum_bytes(queue))
            .max(head_len);
        let kind = match head {
            CoSPendingTxItem::Local(_) => ExactCoSQueueKind::Local,
            CoSPendingTxItem::Prepared(_) => ExactCoSQueueKind::Prepared,
        };
        return Some(ExactCoSQueueSelection {
            queue_idx,
            secondary_budget,
            kind,
        });
    }
    None
}

// Selects the next non-exact guarantee queue for service. Rotates
// independently of the exact pass via `nonexact_guarantee_rr` — a service
// event on an exact queue does not advance this cursor, so non-exact RR
// order is stable across bursts of exact-queue activity.
#[inline]
pub(in crate::afxdp) fn select_nonexact_cos_guarantee_batch(
    root: &mut CoSInterfaceRuntime,
    now_ns: u64,
) -> Option<CoSBatch> {
    let queue_count = root.queues.len();
    if queue_count == 0 {
        return None;
    }
    let start = root.nonexact_guarantee_rr % queue_count;
    for offset in 0..queue_count {
        let queue_idx = (start + offset) % queue_count;
        let queue = &mut root.queues[queue_idx];
        if cos_queue_is_empty(queue) || !queue.runnable || queue.exact {
            continue;
        }
        refill_cos_tokens(
            &mut queue.tokens,
            queue.transmit_rate_bytes,
            queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
            &mut queue.last_refill_ns,
            now_ns,
        );
        let Some(head) = cos_queue_front(queue) else {
            continue;
        };
        let head_len = cos_item_len(head);
        if root.tokens < head_len {
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.tokens,
                queue.transmit_rate_bytes,
                head_len,
                now_ns,
                false,
            ) {
                count_park_reason(root, queue_idx, ParkReason::RootTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        if queue.tokens < head_len {
            continue;
        }
        root.nonexact_guarantee_rr = (start + offset + 1) % queue_count;
        let guarantee_budget = queue
            .tokens
            .min(cos_guarantee_quantum_bytes(queue))
            .max(head_len);
        if let Some(batch) = build_cos_batch_from_queue(
            queue,
            queue_idx,
            root.tokens,
            guarantee_budget,
            CoSServicePhase::Guarantee,
        ) {
            return Some(batch);
        }
    }
    None
}

#[inline]
pub(in crate::afxdp) fn select_cos_surplus_batch(root: &mut CoSInterfaceRuntime, now_ns: u64) -> Option<CoSBatch> {
    for priority in 0..COS_PRIORITY_LEVELS {
        let indices_len = root.queue_indices_by_priority[priority].len();
        if indices_len == 0 {
            continue;
        }
        let start = root.rr_index_by_priority[priority] % indices_len;
        for offset in 0..indices_len {
            let queue_idx =
                root.queue_indices_by_priority[priority][(start + offset) % indices_len];
            let queue = &mut root.queues[queue_idx];
            if cos_queue_is_empty(queue) || !queue.runnable || queue.exact {
                continue;
            }
            let Some(head) = cos_queue_front(queue) else {
                continue;
            };
            let head_len = cos_item_len(head);
            if root.tokens < head_len {
                if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                    root.tokens,
                    root.shaping_rate_bytes,
                    queue.tokens,
                    queue.transmit_rate_bytes,
                    head_len,
                    now_ns,
                    false,
                ) {
                    count_park_reason(root, queue_idx, ParkReason::RootTokenStarvation);
                    park_cos_queue(root, queue_idx, wake_tick);
                }
                continue;
            }
            if queue.surplus_deficit < head_len {
                queue.surplus_deficit = queue
                    .surplus_deficit
                    .saturating_add(cos_surplus_quantum_bytes(queue));
                if queue.surplus_deficit < head_len {
                    continue;
                }
            }
            root.rr_index_by_priority[priority] = (start + offset + 1) % indices_len;
            if let Some(batch) = build_cos_batch_from_queue(
                queue,
                queue_idx,
                root.tokens,
                queue.surplus_deficit,
                CoSServicePhase::Surplus,
            ) {
                return Some(batch);
            }
        }
    }
    None
}

#[inline]
fn service_exact_local_queue_direct(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    secondary_budget: u64,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool {
    let flow_fair = binding
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .map(|queue| queue.flow_fair)
        .unwrap_or(false);
    if flow_fair {
        return service_exact_local_queue_direct_flow_fair(
            binding,
            root_ifindex,
            queue_idx,
            secondary_budget,
            now_ns,
            shared_recycles,
        );
    }
    if binding.free_tx_frames.is_empty() {
        let _ = reap_tx_completions(binding, shared_recycles);
    }
    let queue_dscp_rewrite = cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx);
    binding.scratch_exact_local_tx.clear();
    let root_budget = binding
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.tokens)
        .unwrap_or(0);
    let build = {
        let root = match binding.cos_interfaces.get_mut(&root_ifindex) {
            Some(root) => root,
            None => return false,
        };
        let queue = match root.queues.get_mut(queue_idx) {
            Some(queue) => queue,
            None => return false,
        };
        drain_exact_local_fifo_items_to_scratch(
            queue,
            &mut binding.free_tx_frames,
            &mut binding.scratch_exact_local_tx,
            binding.umem.area(),
            root_budget,
            secondary_budget,
            queue_dscp_rewrite,
        )
    };
    match build {
        ExactCoSScratchBuild::Ready => {}
        ExactCoSScratchBuild::Drop {
            error,
            dropped_bytes,
        } => {
            release_exact_local_scratch_frames(
                &mut binding.free_tx_frames,
                &mut binding.scratch_exact_local_tx,
            );
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(binding, root_ifindex, queue_idx, dropped_bytes);
            } else {
                refresh_cos_interface_activity(binding, root_ifindex);
            }
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: the scratch-build fell through `ExactCoSScratchBuild::Drop`
            // with a frame-level error (capacity or slice). Subset of
            // tx_errors.
            binding
                .live
                .tx_submit_error_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(error);
            return false;
        }
    }
    if binding.scratch_exact_local_tx.is_empty() {
        maybe_wake_tx(binding, true, now_ns);
        binding
            .live
            .set_error("no free TX frame available".to_string());
        return false;
    }

    let mut writer = binding
        .tx
        .transmit(binding.scratch_exact_local_tx.len() as u32);
    let inserted = writer.insert(binding.scratch_exact_local_tx.iter().map(|req| XdpDesc {
        addr: req.offset,
        len: req.len,
        options: 0,
    }));
    writer.commit();
    drop(writer);
    // #812 Codex round-1 HIGH #1: sample the submit stamp AFTER
    // `writer.commit()` so a scheduler preemption between `insert`
    // and the ring submit does NOT inflate the measured latency.
    // Pre-commit stamping attributed the preemption window to the
    // kernel (submit→completion), which is exactly the opposite of
    // what we want to observe. A reused caller `now_ns` would still
    // leak up to ~1 ms of worker-loop staleness, so we take a fresh
    // `monotonic_nanos()` here rather than re-using one from the
    // outer scope. Only the accepted prefix (`.take(inserted as
    // usize)`) is stamped — the retry tail returns to
    // `free_tx_frames` and MUST NOT be stamped.
    let ts_submit = monotonic_nanos();
    stamp_submits(
        &mut binding.tx_submit_ns,
        binding
            .scratch_exact_local_tx
            .iter()
            .take(inserted as usize)
            .map(|req| req.offset),
        ts_submit,
    );

    if inserted == 0 {
        let dropped = binding.scratch_exact_local_tx.len() as u64;
        binding.dbg_tx_ring_full += 1;
        count_tx_ring_full_submit_stall(binding, root_ifindex, queue_idx, dropped);
        maybe_wake_tx(binding, true, now_ns);
        release_exact_local_scratch_frames(
            &mut binding.free_tx_frames,
            &mut binding.scratch_exact_local_tx,
        );
        refresh_cos_interface_activity(binding, root_ifindex);
        binding.live.set_error("tx ring insert failed".to_string());
        return false;
    }
    binding.dbg_tx_ring_submitted += inserted as u64;
    binding.outstanding_tx = binding.outstanding_tx.saturating_add(inserted);

    let (sent_packets, sent_bytes) = settle_exact_local_fifo_submission(
        binding
            .cos_interfaces
            .get_mut(&root_ifindex)
            .and_then(|root| root.queues.get_mut(queue_idx)),
        &mut binding.free_tx_frames,
        &mut binding.scratch_exact_local_tx,
        inserted as usize,
    );
    // #940: post-settle V_min publish. FIFO queues currently have
    // vtime_floor=None so this is a no-op; kept for uniformity and
    // to shield future flow_fair-FIFO adoption.
    publish_committed_queue_vtime(
        binding
            .cos_interfaces
            .get(&root_ifindex)
            .and_then(|root| root.queues.get(queue_idx)),
    );
    apply_direct_exact_send_result(binding, root_ifindex, queue_idx, sent_packets, sent_bytes);
    maybe_wake_tx(binding, true, now_ns);
    sent_packets > 0 || sent_bytes > 0
}

#[inline]
fn service_exact_local_queue_direct_flow_fair(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    secondary_budget: u64,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool {
    if binding.free_tx_frames.is_empty() {
        let _ = reap_tx_completions(binding, shared_recycles);
    }
    let queue_dscp_rewrite = cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx);
    binding.scratch_local_tx.clear();
    let root_budget = binding
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.tokens)
        .unwrap_or(0);
    let build = {
        let root = match binding.cos_interfaces.get_mut(&root_ifindex) {
            Some(root) => root,
            None => return false,
        };
        let queue = match root.queues.get_mut(queue_idx) {
            Some(queue) => queue,
            None => return false,
        };
        drain_exact_local_items_to_scratch_flow_fair(
            queue,
            &mut binding.free_tx_frames,
            &mut binding.scratch_local_tx,
            binding.umem.area(),
            root_budget,
            secondary_budget,
            queue_dscp_rewrite,
        )
    };
    match build {
        ExactCoSScratchBuild::Ready => {}
        ExactCoSScratchBuild::Drop {
            error,
            dropped_bytes,
        } => {
            restore_exact_local_scratch_to_queue_head_flow_fair(
                binding
                    .cos_interfaces
                    .get_mut(&root_ifindex)
                    .and_then(|root| root.queues.get_mut(queue_idx)),
                &mut binding.free_tx_frames,
                &mut binding.scratch_local_tx,
            );
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(binding, root_ifindex, queue_idx, dropped_bytes);
            } else {
                refresh_cos_interface_activity(binding, root_ifindex);
            }
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: the scratch-build fell through `ExactCoSScratchBuild::Drop`
            // with a frame-level error (capacity or slice). Subset of
            // tx_errors.
            binding
                .live
                .tx_submit_error_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(error);
            return false;
        }
    }
    if binding.scratch_local_tx.is_empty() {
        maybe_wake_tx(binding, true, now_ns);
        binding
            .live
            .set_error("no free TX frame available".to_string());
        return false;
    }

    let mut writer = binding.tx.transmit(binding.scratch_local_tx.len() as u32);
    let inserted = writer.insert(
        binding
            .scratch_local_tx
            .iter()
            .map(|(offset, req)| XdpDesc {
                addr: *offset,
                len: req.bytes.len() as u32,
                options: 0,
            }),
    );
    writer.commit();
    drop(writer);
    // #812 Codex round-1 HIGH #1: submit stamp AFTER commit — see plan
    // §3.1 submit-site table (this is the
    // service_exact_local_queue_direct_flow_fair variant). Stamping
    // post-commit prevents a preemption window between `insert` and
    // ring submit from being attributed to submit→completion latency.
    let ts_submit = monotonic_nanos();
    stamp_submits(
        &mut binding.tx_submit_ns,
        binding
            .scratch_local_tx
            .iter()
            .take(inserted as usize)
            .map(|(offset, _)| *offset),
        ts_submit,
    );

    if inserted == 0 {
        let dropped = binding.scratch_local_tx.len() as u64;
        binding.dbg_tx_ring_full += 1;
        count_tx_ring_full_submit_stall(binding, root_ifindex, queue_idx, dropped);
        maybe_wake_tx(binding, true, now_ns);
        restore_exact_local_scratch_to_queue_head_flow_fair(
            binding
                .cos_interfaces
                .get_mut(&root_ifindex)
                .and_then(|root| root.queues.get_mut(queue_idx)),
            &mut binding.free_tx_frames,
            &mut binding.scratch_local_tx,
        );
        refresh_cos_interface_activity(binding, root_ifindex);
        binding.live.set_error("tx ring insert failed".to_string());
        return false;
    }
    binding.dbg_tx_ring_submitted += inserted as u64;
    binding.outstanding_tx = binding.outstanding_tx.saturating_add(inserted);

    let (sent_packets, sent_bytes) = settle_exact_local_scratch_submission_flow_fair(
        binding
            .cos_interfaces
            .get_mut(&root_ifindex)
            .and_then(|root| root.queues.get_mut(queue_idx)),
        &mut binding.free_tx_frames,
        &mut binding.scratch_local_tx,
        inserted as usize,
    );
    // #940: post-settle V_min publish. Settle has already applied
    // any partial-rollback push_fronts (which republished via the
    // rollback hook), so queue.queue_vtime now reflects only the
    // actually-shipped frames.
    publish_committed_queue_vtime(
        binding
            .cos_interfaces
            .get(&root_ifindex)
            .and_then(|root| root.queues.get(queue_idx)),
    );
    apply_direct_exact_send_result(binding, root_ifindex, queue_idx, sent_packets, sent_bytes);
    maybe_wake_tx(binding, true, now_ns);
    sent_packets > 0 || sent_bytes > 0
}

#[inline]
fn service_exact_prepared_queue_direct(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    secondary_budget: u64,
    now_ns: u64,
) -> bool {
    let flow_fair = binding
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .map(|queue| queue.flow_fair)
        .unwrap_or(false);
    if flow_fair {
        return service_exact_prepared_queue_direct_flow_fair(
            binding,
            root_ifindex,
            queue_idx,
            secondary_budget,
            now_ns,
        );
    }
    let queue_dscp_rewrite = cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx);
    binding.scratch_exact_prepared_tx.clear();
    let root_budget = binding
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.tokens)
        .unwrap_or(0);
    let build = {
        let root = match binding.cos_interfaces.get_mut(&root_ifindex) {
            Some(root) => root,
            None => return false,
        };
        let queue = match root.queues.get_mut(queue_idx) {
            Some(queue) => queue,
            None => return false,
        };
        drain_exact_prepared_fifo_items_to_scratch(
            queue,
            &mut binding.scratch_exact_prepared_tx,
            binding.umem.area(),
            &mut binding.free_tx_frames,
            &mut binding.pending_fill_frames,
            binding.slot,
            root_budget,
            secondary_budget,
            queue_dscp_rewrite,
        )
    };
    match build {
        ExactCoSScratchBuild::Ready => {}
        ExactCoSScratchBuild::Drop {
            error,
            dropped_bytes,
        } => {
            release_exact_prepared_scratch(&mut binding.scratch_exact_prepared_tx);
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(binding, root_ifindex, queue_idx, dropped_bytes);
            } else {
                refresh_cos_interface_activity(binding, root_ifindex);
            }
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: the scratch-build fell through `ExactCoSScratchBuild::Drop`
            // with a frame-level error (capacity or slice). Subset of
            // tx_errors.
            binding
                .live
                .tx_submit_error_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(error);
            return false;
        }
    }
    if binding.scratch_exact_prepared_tx.is_empty() {
        return false;
    }

    if cfg!(feature = "debug-log") {
        for req in &binding.scratch_exact_prepared_tx {
            if let Some(frame_data) = binding
                .umem
                .area()
                .slice(req.offset as usize, req.len as usize)
            {
                if frame_has_tcp_rst(frame_data) {
                    binding.dbg_tx_tcp_rst += 1;
                }
            }
        }
    }

    let mut writer = binding
        .tx
        .transmit(binding.scratch_exact_prepared_tx.len() as u32);
    let inserted = writer.insert(binding.scratch_exact_prepared_tx.iter().map(|req| XdpDesc {
        addr: req.offset,
        len: req.len,
        options: 0,
    }));
    writer.commit();
    drop(writer);
    // #812 Codex round-1 HIGH #1: submit stamp AFTER commit — plan
    // §3.1 submit-site table (the service_exact_prepared_queue_direct
    // variant). Post-commit stamping ensures the measurement reflects
    // the moment the ring submission actually landed in the kernel,
    // not the moment before a potential preemption window.
    let ts_submit = monotonic_nanos();
    stamp_submits(
        &mut binding.tx_submit_ns,
        binding
            .scratch_exact_prepared_tx
            .iter()
            .take(inserted as usize)
            .map(|req| req.offset),
        ts_submit,
    );

    if inserted == 0 {
        let dropped = binding.scratch_exact_prepared_tx.len() as u64;
        binding.dbg_tx_ring_full += 1;
        count_tx_ring_full_submit_stall(binding, root_ifindex, queue_idx, dropped);
        maybe_wake_tx(binding, true, now_ns);
        release_exact_prepared_scratch(&mut binding.scratch_exact_prepared_tx);
        refresh_cos_interface_activity(binding, root_ifindex);
        binding
            .live
            .set_error("prepared tx ring insert failed".to_string());
        return false;
    }
    binding.dbg_tx_ring_submitted += inserted as u64;
    binding.outstanding_tx = binding.outstanding_tx.saturating_add(inserted);

    let (sent_packets, sent_bytes) = settle_exact_prepared_fifo_submission(
        binding
            .cos_interfaces
            .get_mut(&root_ifindex)
            .and_then(|root| root.queues.get_mut(queue_idx)),
        &mut binding.scratch_exact_prepared_tx,
        &mut binding.in_flight_prepared_recycles,
        inserted as usize,
    );
    // #940: post-settle V_min publish. FIFO queues have
    // vtime_floor=None today; no-op shield for future adoption.
    publish_committed_queue_vtime(
        binding
            .cos_interfaces
            .get(&root_ifindex)
            .and_then(|root| root.queues.get(queue_idx)),
    );
    apply_direct_exact_send_result(binding, root_ifindex, queue_idx, sent_packets, sent_bytes);
    maybe_wake_tx(binding, true, now_ns);
    sent_packets > 0 || sent_bytes > 0
}

#[inline]
fn service_exact_prepared_queue_direct_flow_fair(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    secondary_budget: u64,
    now_ns: u64,
) -> bool {
    let queue_dscp_rewrite = cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx);
    binding.scratch_prepared_tx.clear();
    let root_budget = binding
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.tokens)
        .unwrap_or(0);
    let build = {
        let root = match binding.cos_interfaces.get_mut(&root_ifindex) {
            Some(root) => root,
            None => return false,
        };
        let queue = match root.queues.get_mut(queue_idx) {
            Some(queue) => queue,
            None => return false,
        };
        drain_exact_prepared_items_to_scratch_flow_fair(
            queue,
            &mut binding.scratch_prepared_tx,
            binding.umem.area(),
            &mut binding.free_tx_frames,
            &mut binding.pending_fill_frames,
            binding.slot,
            root_budget,
            secondary_budget,
            queue_dscp_rewrite,
        )
    };
    match build {
        ExactCoSScratchBuild::Ready => {}
        ExactCoSScratchBuild::Drop {
            error,
            dropped_bytes,
        } => {
            restore_exact_prepared_scratch_to_queue_head_flow_fair(
                binding
                    .cos_interfaces
                    .get_mut(&root_ifindex)
                    .and_then(|root| root.queues.get_mut(queue_idx)),
                &mut binding.scratch_prepared_tx,
            );
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(binding, root_ifindex, queue_idx, dropped_bytes);
            } else {
                refresh_cos_interface_activity(binding, root_ifindex);
            }
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: the scratch-build fell through `ExactCoSScratchBuild::Drop`
            // with a frame-level error (capacity or slice). Subset of
            // tx_errors.
            binding
                .live
                .tx_submit_error_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(error);
            return false;
        }
    }
    if binding.scratch_prepared_tx.is_empty() {
        return false;
    }

    if cfg!(feature = "debug-log") {
        for req in &binding.scratch_prepared_tx {
            if let Some(frame_data) = binding
                .umem
                .area()
                .slice(req.offset as usize, req.len as usize)
            {
                if frame_has_tcp_rst(frame_data) {
                    binding.dbg_tx_tcp_rst += 1;
                }
            }
        }
    }

    let mut writer = binding
        .tx
        .transmit(binding.scratch_prepared_tx.len() as u32);
    let inserted = writer.insert(binding.scratch_prepared_tx.iter().map(|req| XdpDesc {
        addr: req.offset,
        len: req.len,
        options: 0,
    }));
    writer.commit();
    drop(writer);
    // #812 Codex round-1 HIGH #1: submit stamp AFTER commit — plan
    // §3.1 submit-site table (the
    // service_exact_prepared_queue_direct_flow_fair variant). See the
    // exact_local variant above for the preemption-window rationale.
    let ts_submit = monotonic_nanos();
    stamp_submits(
        &mut binding.tx_submit_ns,
        binding
            .scratch_prepared_tx
            .iter()
            .take(inserted as usize)
            .map(|req| req.offset),
        ts_submit,
    );

    if inserted == 0 {
        let dropped = binding.scratch_prepared_tx.len() as u64;
        binding.dbg_tx_ring_full += 1;
        count_tx_ring_full_submit_stall(binding, root_ifindex, queue_idx, dropped);
        maybe_wake_tx(binding, true, now_ns);
        restore_exact_prepared_scratch_to_queue_head_flow_fair(
            binding
                .cos_interfaces
                .get_mut(&root_ifindex)
                .and_then(|root| root.queues.get_mut(queue_idx)),
            &mut binding.scratch_prepared_tx,
        );
        refresh_cos_interface_activity(binding, root_ifindex);
        binding
            .live
            .set_error("prepared tx ring insert failed".to_string());
        return false;
    }
    binding.dbg_tx_ring_submitted += inserted as u64;
    binding.outstanding_tx = binding.outstanding_tx.saturating_add(inserted);

    let (sent_packets, sent_bytes) = settle_exact_prepared_scratch_submission_flow_fair(
        binding
            .cos_interfaces
            .get_mut(&root_ifindex)
            .and_then(|root| root.queues.get_mut(queue_idx)),
        &mut binding.scratch_prepared_tx,
        &mut binding.in_flight_prepared_recycles,
        inserted as usize,
    );
    // #940: post-settle V_min publish. Settle has applied any
    // partial-rollback push_fronts via the rollback hook;
    // queue.queue_vtime now reflects only actually-shipped frames.
    publish_committed_queue_vtime(
        binding
            .cos_interfaces
            .get(&root_ifindex)
            .and_then(|root| root.queues.get(queue_idx)),
    );
    apply_direct_exact_send_result(binding, root_ifindex, queue_idx, sent_packets, sent_bytes);
    maybe_wake_tx(binding, true, now_ns);
    sent_packets > 0 || sent_bytes > 0
}

pub(in crate::afxdp) fn drain_exact_local_fifo_items_to_scratch(
    queue: &mut CoSQueueRuntime,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<ExactLocalScratchTxRequest>,
    area: &MmapArea,
    root_budget: u64,
    secondary_budget: u64,
    queue_dscp_rewrite: Option<u8>,
) -> ExactCoSScratchBuild {
    debug_assert!(!queue.flow_fair);
    // #942: no V_min wiring needed here. This FIFO Local variant
    // runs only on `!flow_fair` queues per the debug_assert above.
    // shared_exact queues always have `flow_fair = queue.exact`
    // (per `promote_cos_queue_flow_fair`), so this path is
    // unreachable on shared_exact. V_min coordination is a
    // shared_exact-only concept.
    let mut remaining_root = root_budget;
    let mut remaining_secondary = secondary_budget;
    let mut index = 0usize;
    while scratch_local_tx.len() < TX_BATCH_SIZE {
        if free_tx_frames.is_empty() {
            break;
        }
        let mut drop_error: Option<(String, u64)> = None;
        let mut built = false;
        {
            let Some(front) = queue.items.get(index) else {
                break;
            };
            let CoSPendingTxItem::Local(req) = front else {
                break;
            };
            let len = req.bytes.len() as u64;
            if remaining_root < len || remaining_secondary < len {
                break;
            }
            if req.bytes.len() > tx_frame_capacity() {
                drop_error = Some((
                    format!(
                        "local tx frame exceeds UMEM frame capacity: len={} cap={}",
                        req.bytes.len(),
                        tx_frame_capacity()
                    ),
                    len,
                ));
            } else {
                let Some(offset) = free_tx_frames.pop_front() else {
                    break;
                };
                if let Some(frame) =
                    unsafe { area.slice_mut_unchecked(offset as usize, req.bytes.len()) }
                {
                    frame.copy_from_slice(&req.bytes);
                    if let Some(dscp_rewrite) = req.dscp_rewrite.or(queue_dscp_rewrite) {
                        let _ = apply_dscp_rewrite_to_frame(frame, dscp_rewrite);
                    }
                    scratch_local_tx.push(ExactLocalScratchTxRequest {
                        offset,
                        len: req.bytes.len() as u32,
                    });
                    remaining_root = remaining_root.saturating_sub(len);
                    remaining_secondary = remaining_secondary.saturating_sub(len);
                    built = true;
                } else {
                    free_tx_frames.push_front(offset);
                    drop_error = Some((
                        format!(
                            "tx frame slice out of range: offset={offset} len={}",
                            req.bytes.len()
                        ),
                        len,
                    ));
                }
            }
        }
        if let Some((error, fallback_dropped_bytes)) = drop_error {
            // Error path only: remove the specific malformed item we just
            // examined. VecDeque::remove(index) is O(N), but this only runs for
            // oversized/out-of-range frames, never on the steady-state hot path.
            let dropped_bytes = match queue.items.remove(index) {
                Some(CoSPendingTxItem::Local(req)) => req.bytes.len() as u64,
                Some(CoSPendingTxItem::Prepared(_)) | None => fallback_dropped_bytes,
            };
            return ExactCoSScratchBuild::Drop {
                error,
                dropped_bytes,
            };
        }
        if !built {
            break;
        }
        index += 1;
    }

    ExactCoSScratchBuild::Ready
}

pub(in crate::afxdp) fn drain_exact_local_items_to_scratch_flow_fair(
    queue: &mut CoSQueueRuntime,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<(u64, TxRequest)>,
    area: &MmapArea,
    root_budget: u64,
    secondary_budget: u64,
    queue_dscp_rewrite: Option<u8>,
) -> ExactCoSScratchBuild {
    // #785 Phase 3 — Codex round-3 NEW-2 / Rust reviewer LOW:
    // clear the pop-snapshot stack at batch start. The bound
    // "at most TX_BATCH_SIZE snapshots live at once" (see
    // `CoSQueueRuntime::pop_snapshot_stack` doc) relies on each
    // batch drain starting from an empty stack; committed
    // submissions leave stale snapshots until some later event
    // (push_back or another rollback) happens to clear them.
    // Without this clear, drain-all teardown paths and
    // successful-commit chains can grow the stack unbounded.
    queue.pop_snapshot_stack.clear();
    // #941 Work item D: drain-call preflight. If no free TX frames at
    // entry, return early WITHOUT consuming a suspension slot — that
    // way TX-ring-full no-progress drains don't burn the suspension
    // window.
    if free_tx_frames.is_empty() {
        return ExactCoSScratchBuild::Ready;
    }
    // #941 Work item D: consume one suspension slot for this drain
    // call. `suspended` persists for the entire loop body — every pop
    // sees the same suspension state, so a hard-cap-armed suspension
    // is honored across all cadence pops (1, 8, 16, ...) within this
    // drain.
    let suspended = cos_queue_v_min_consume_suspension(queue);
    let mut remaining_root = root_budget;
    let mut remaining_secondary = secondary_budget;
    let mut v_min_pop_count = 0u32;
    while scratch_local_tx.len() < TX_BATCH_SIZE {
        if free_tx_frames.is_empty() {
            break;
        }
        // #917 Phase 4: V_min check on drain-batch start (pop_count
        // transitions 0→1) and every K=8 pops thereafter. Throttle
        // = early break out of this queue's drain. The fast worker
        // moves on to next runnable queue (or exits the drain
        // entirely if all queues throttle); revisits this queue
        // next round when V_min has likely advanced.
        //
        // #941 Work item D: skip the V_min check entirely when this
        // drain is suspended (hard-cap previously armed).
        v_min_pop_count = v_min_pop_count.saturating_add(1);
        if !suspended && !cos_queue_v_min_continue(queue, v_min_pop_count) {
            break;
        }
        let Some(front) = cos_queue_front(queue) else {
            break;
        };
        let len = match front {
            CoSPendingTxItem::Local(req) => req.bytes.len() as u64,
            CoSPendingTxItem::Prepared(_) => break,
        };
        if remaining_root < len || remaining_secondary < len {
            break;
        }
        let Some(CoSPendingTxItem::Local(mut req)) = cos_queue_pop_front(queue) else {
            break;
        };
        remaining_root = remaining_root.saturating_sub(len);
        remaining_secondary = remaining_secondary.saturating_sub(len);

        if let Some(dscp_rewrite) = queue_dscp_rewrite {
            req.dscp_rewrite = req.dscp_rewrite.or(Some(dscp_rewrite));
        }
        if let Some(dscp_rewrite) = req.dscp_rewrite {
            let _ = apply_dscp_rewrite_to_frame(&mut req.bytes, dscp_rewrite);
        }
        if req.bytes.len() > tx_frame_capacity() {
            // #913: clean up the orphan snapshot for this dropped
            // item. The matching pop pushed a snapshot; on Drop
            // we abandon the item, so the snapshot would
            // otherwise sit at the top of the stack and trip a
            // bucket-mismatch panic when the subsequent
            // restore_front push_fronts a different surviving
            // item. Codex code review (HIGH): also clamp
            // remaining snapshots' pre_pop_queue_vtime so
            // survivor restores preserve this dropped item's
            // committed vtime advance — see helper docstring.
            cos_queue_clear_orphan_snapshot_after_drop(queue);
            return ExactCoSScratchBuild::Drop {
                error: format!(
                    "local tx frame exceeds UMEM frame capacity: len={} cap={}",
                    req.bytes.len(),
                    tx_frame_capacity()
                ),
                dropped_bytes: len,
            };
        }
        let Some(offset) = free_tx_frames.pop_front() else {
            cos_queue_push_front(queue, CoSPendingTxItem::Local(req));
            break;
        };
        let Some(frame) = (unsafe { area.slice_mut_unchecked(offset as usize, req.bytes.len()) })
        else {
            free_tx_frames.push_front(offset);
            // #913: same orphan-snapshot cleanup as above (slice
            // failure path).
            cos_queue_clear_orphan_snapshot_after_drop(queue);
            return ExactCoSScratchBuild::Drop {
                error: format!(
                    "tx frame slice out of range: offset={offset} len={}",
                    req.bytes.len()
                ),
                dropped_bytes: len,
            };
        };
        frame.copy_from_slice(&req.bytes);
        scratch_local_tx.push((offset, req));
    }

    ExactCoSScratchBuild::Ready
}

pub(in crate::afxdp) fn drain_exact_prepared_fifo_items_to_scratch(
    queue: &mut CoSQueueRuntime,
    scratch_prepared_tx: &mut Vec<ExactPreparedScratchTxRequest>,
    area: &MmapArea,
    free_tx_frames: &mut VecDeque<u64>,
    pending_fill_frames: &mut VecDeque<u64>,
    slot: u32,
    root_budget: u64,
    secondary_budget: u64,
    queue_dscp_rewrite: Option<u8>,
) -> ExactCoSScratchBuild {
    debug_assert!(!queue.flow_fair);
    // #942: no V_min wiring needed here. This FIFO Prepared variant
    // runs only on `!flow_fair` queues per the debug_assert above,
    // and shared_exact queues always have `flow_fair = queue.exact`
    // (per `promote_cos_queue_flow_fair`), so this path is
    // unreachable on shared_exact. V_min coordination is a
    // shared_exact-only concept; no participation needed.
    let mut remaining_root = root_budget;
    let mut remaining_secondary = secondary_budget;
    let mut index = 0usize;

    while scratch_prepared_tx.len() < TX_BATCH_SIZE {
        let mut drop_error: Option<(String, u64)> = None;
        let mut built = false;
        {
            let Some(front) = queue.items.get(index) else {
                break;
            };
            let CoSPendingTxItem::Prepared(req) = front else {
                break;
            };
            let len = req.len as u64;
            if remaining_root < len || remaining_secondary < len {
                break;
            }
            if req.len as usize > tx_frame_capacity() {
                drop_error = Some((
                    format!(
                        "prepared tx frame exceeds UMEM frame capacity: len={} cap={}",
                        req.len,
                        tx_frame_capacity()
                    ),
                    len,
                ));
            } else {
                let valid = if let Some(dscp_rewrite) = req.dscp_rewrite.or(queue_dscp_rewrite) {
                    match unsafe { area.slice_mut_unchecked(req.offset as usize, req.len as usize) }
                    {
                        Some(frame) => {
                            let _ = apply_dscp_rewrite_to_frame(frame, dscp_rewrite);
                            true
                        }
                        None => false,
                    }
                } else {
                    area.slice(req.offset as usize, req.len as usize).is_some()
                };
                if !valid {
                    drop_error = Some((
                        format!(
                            "prepared tx frame slice out of range: offset={} len={}",
                            req.offset, req.len
                        ),
                        len,
                    ));
                } else {
                    scratch_prepared_tx.push(ExactPreparedScratchTxRequest {
                        offset: req.offset,
                        len: req.len,
                    });
                    remaining_root = remaining_root.saturating_sub(len);
                    remaining_secondary = remaining_secondary.saturating_sub(len);
                    built = true;
                }
            }
        }
        if let Some((error, fallback_dropped_bytes)) = drop_error {
            let dropped_bytes = match queue.items.remove(index) {
                Some(CoSPendingTxItem::Prepared(req)) => {
                    recycle_cancelled_prepared_offset(
                        free_tx_frames,
                        pending_fill_frames,
                        slot,
                        req.recycle,
                        req.offset,
                    );
                    req.len as u64
                }
                Some(CoSPendingTxItem::Local(_)) | None => fallback_dropped_bytes,
            };
            return ExactCoSScratchBuild::Drop {
                error,
                dropped_bytes,
            };
        }
        if !built {
            break;
        }
        index += 1;
    }

    ExactCoSScratchBuild::Ready
}

pub(in crate::afxdp) fn drain_exact_prepared_items_to_scratch_flow_fair(
    queue: &mut CoSQueueRuntime,
    scratch_prepared_tx: &mut Vec<PreparedTxRequest>,
    area: &MmapArea,
    free_tx_frames: &mut VecDeque<u64>,
    pending_fill_frames: &mut VecDeque<u64>,
    slot: u32,
    root_budget: u64,
    secondary_budget: u64,
    queue_dscp_rewrite: Option<u8>,
) -> ExactCoSScratchBuild {
    // #785 Phase 3 — Codex round-3 NEW-2 / Rust reviewer LOW:
    // clear the pop-snapshot stack at batch start. See the
    // matching comment in `drain_exact_local_items_to_scratch_flow_fair`
    // for the rationale — committed-submit chains or drain-all
    // teardowns can otherwise leave stale snapshots that violate
    // the documented TX_BATCH_SIZE bound.
    queue.pop_snapshot_stack.clear();
    let mut remaining_root = root_budget;
    let mut remaining_secondary = secondary_budget;
    // #942: V_min wiring on the Prepared flow-fair drain. Mirrors
    // the Local-flow pattern at `drain_exact_local_items_to_scratch_flow_fair`.
    //
    // The original attempt (commit eeade5e2 in #950) caused a severe
    // regression because peer slots held stale-low values that
    // throttled the heavy worker indefinitely. #941 (PR #952) added
    // bucket-empty vacate + hard-cap-with-suspension to make this
    // safe: a temporary smoke with the wiring confirmed iperf-c P=12 =
    // 23.1 Gb/s (clears the 22 Gb/s gate).
    //
    // Preflight (mirrors Local's `free_tx_frames.is_empty()` early-
    // return): if there is no Prepared item at the front of the queue,
    // return early WITHOUT consuming a suspension slot. This prevents
    // a no-progress Prepared drain (e.g. queue head is Local) from
    // eroding the hard-cap suspension window.
    match cos_queue_front(queue) {
        Some(CoSPendingTxItem::Prepared(_)) => {}
        _ => return ExactCoSScratchBuild::Ready,
    }
    // #942: consume one suspension slot for this drain call. The
    // `suspended` flag persists for the entire loop body so cadence
    // pops at pop_count=1, 8, 16, ... all see the same suspension
    // state. See `cos_queue_v_min_consume_suspension` doc.
    let suspended = cos_queue_v_min_consume_suspension(queue);
    let mut v_min_pop_count = 0u32;

    while scratch_prepared_tx.len() < TX_BATCH_SIZE {
        // #942: V_min check on the Prepared flow-fair drain path,
        // mirroring the Local-flow wiring. Same K=8 cadence with
        // mandatory check at pop_count==1 (drain-batch start).
        // Skipped entirely when the drain is suspended (#941 hard-cap).
        v_min_pop_count = v_min_pop_count.saturating_add(1);
        if !suspended && !cos_queue_v_min_continue(queue, v_min_pop_count) {
            break;
        }
        let Some(front) = cos_queue_front(queue) else {
            break;
        };
        let len = match front {
            CoSPendingTxItem::Prepared(req) => req.len as u64,
            CoSPendingTxItem::Local(_) => break,
        };
        if remaining_root < len || remaining_secondary < len {
            break;
        }
        let Some(CoSPendingTxItem::Prepared(mut req)) = cos_queue_pop_front(queue) else {
            break;
        };
        remaining_root = remaining_root.saturating_sub(len);
        remaining_secondary = remaining_secondary.saturating_sub(len);

        if let Some(dscp_rewrite) = queue_dscp_rewrite {
            req.dscp_rewrite = req.dscp_rewrite.or(Some(dscp_rewrite));
        }
        if req.len as usize > tx_frame_capacity() {
            recycle_cancelled_prepared_offset(
                free_tx_frames,
                pending_fill_frames,
                slot,
                req.recycle,
                req.offset,
            );
            // #913: orphan snapshot cleanup with vtime preservation.
            // See helper docstring; same as local-builder
            // capacity-fail site.
            cos_queue_clear_orphan_snapshot_after_drop(queue);
            return ExactCoSScratchBuild::Drop {
                error: format!(
                    "prepared tx frame exceeds UMEM frame capacity: len={} cap={}",
                    req.len,
                    tx_frame_capacity()
                ),
                dropped_bytes: len,
            };
        }
        let valid = if let Some(dscp_rewrite) = req.dscp_rewrite {
            match unsafe { area.slice_mut_unchecked(req.offset as usize, req.len as usize) } {
                Some(frame) => {
                    let _ = apply_dscp_rewrite_to_frame(frame, dscp_rewrite);
                    true
                }
                None => false,
            }
        } else {
            area.slice(req.offset as usize, req.len as usize).is_some()
        };
        if !valid {
            recycle_cancelled_prepared_offset(
                free_tx_frames,
                pending_fill_frames,
                slot,
                req.recycle,
                req.offset,
            );
            // #913: orphan snapshot cleanup with vtime preservation
            // (slice failure path). See helper docstring.
            cos_queue_clear_orphan_snapshot_after_drop(queue);
            return ExactCoSScratchBuild::Drop {
                error: format!(
                    "prepared tx frame slice out of range: offset={} len={}",
                    req.offset, req.len
                ),
                dropped_bytes: len,
            };
        }
        scratch_prepared_tx.push(req);
    }

    ExactCoSScratchBuild::Ready
}

pub(in crate::afxdp) fn release_exact_local_scratch_frames(
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<ExactLocalScratchTxRequest>,
) {
    while let Some(req) = scratch_local_tx.pop() {
        free_tx_frames.push_front(req.offset);
    }
}

fn restore_exact_local_scratch_to_queue_head_flow_fair(
    queue: Option<&mut CoSQueueRuntime>,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<(u64, TxRequest)>,
) {
    let Some(queue) = queue else {
        scratch_local_tx.clear();
        return;
    };
    while let Some((offset, req)) = scratch_local_tx.pop() {
        free_tx_frames.push_front(offset);
        cos_queue_push_front(queue, CoSPendingTxItem::Local(req));
    }
}

pub(in crate::afxdp) fn release_exact_prepared_scratch(scratch_prepared_tx: &mut Vec<ExactPreparedScratchTxRequest>) {
    scratch_prepared_tx.clear();
}

fn restore_exact_prepared_scratch_to_queue_head_flow_fair(
    queue: Option<&mut CoSQueueRuntime>,
    scratch_prepared_tx: &mut Vec<PreparedTxRequest>,
) {
    let Some(queue) = queue else {
        scratch_prepared_tx.clear();
        return;
    };
    while let Some(req) = scratch_prepared_tx.pop() {
        cos_queue_push_front(queue, CoSPendingTxItem::Prepared(req));
    }
}

pub(in crate::afxdp) fn settle_exact_local_fifo_submission(
    queue: Option<&mut CoSQueueRuntime>,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<ExactLocalScratchTxRequest>,
    inserted: usize,
) -> (u64, u64) {
    let Some(queue) = queue else {
        release_exact_local_scratch_frames(free_tx_frames, scratch_local_tx);
        return (0, 0);
    };
    let sent = inserted.min(scratch_local_tx.len());
    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    for _ in 0..sent {
        match queue.items.pop_front() {
            Some(CoSPendingTxItem::Local(req)) => {
                sent_packets += 1;
                sent_bytes += req.bytes.len() as u64;
            }
            Some(item) => {
                queue.items.push_front(item);
                break;
            }
            None => break,
        }
    }
    for req in scratch_local_tx.drain(sent..).rev() {
        free_tx_frames.push_front(req.offset);
    }
    scratch_local_tx.clear();
    (sent_packets, sent_bytes)
}

pub(in crate::afxdp) fn settle_exact_local_scratch_submission_flow_fair(
    queue: Option<&mut CoSQueueRuntime>,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<(u64, TxRequest)>,
    inserted: usize,
) -> (u64, u64) {
    let Some(queue) = queue else {
        scratch_local_tx.clear();
        return (0, 0);
    };
    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    while let Some((offset, req)) = scratch_local_tx.pop() {
        if scratch_local_tx.len() >= inserted {
            free_tx_frames.push_front(offset);
            cos_queue_push_front(queue, CoSPendingTxItem::Local(req));
        } else {
            sent_packets += 1;
            sent_bytes += req.bytes.len() as u64;
        }
    }
    (sent_packets, sent_bytes)
}

pub(in crate::afxdp) fn settle_exact_prepared_fifo_submission(
    queue: Option<&mut CoSQueueRuntime>,
    scratch_prepared_tx: &mut Vec<ExactPreparedScratchTxRequest>,
    in_flight_prepared_recycles: &mut FastMap<u64, PreparedTxRecycle>,
    inserted: usize,
) -> (u64, u64) {
    let Some(queue) = queue else {
        scratch_prepared_tx.clear();
        return (0, 0);
    };
    let sent = inserted.min(scratch_prepared_tx.len());
    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    for _ in 0..sent {
        match queue.items.pop_front() {
            Some(CoSPendingTxItem::Prepared(req)) => {
                remember_prepared_recycle(in_flight_prepared_recycles, &req);
                sent_packets += 1;
                sent_bytes += req.len as u64;
            }
            Some(item) => {
                queue.items.push_front(item);
                break;
            }
            None => break,
        }
    }
    scratch_prepared_tx.clear();
    (sent_packets, sent_bytes)
}

fn settle_exact_prepared_scratch_submission_flow_fair(
    queue: Option<&mut CoSQueueRuntime>,
    scratch_prepared_tx: &mut Vec<PreparedTxRequest>,
    in_flight_prepared_recycles: &mut FastMap<u64, PreparedTxRecycle>,
    inserted: usize,
) -> (u64, u64) {
    let Some(queue) = queue else {
        scratch_prepared_tx.clear();
        return (0, 0);
    };
    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    while let Some(req) = scratch_prepared_tx.pop() {
        if scratch_prepared_tx.len() >= inserted {
            cos_queue_push_front(queue, CoSPendingTxItem::Prepared(req));
        } else {
            remember_prepared_recycle(in_flight_prepared_recycles, &req);
            sent_packets += 1;
            sent_bytes += req.len as u64;
        }
    }
    (sent_packets, sent_bytes)
}

#[inline]
fn subtract_direct_cos_queue_bytes(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    dropped_bytes: u64,
) {
    if dropped_bytes == 0 {
        refresh_cos_interface_activity(binding, root_ifindex);
        return;
    }
    if let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) {
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            queue.queued_bytes = queue.queued_bytes.saturating_sub(dropped_bytes);
        }
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}

#[inline]
fn build_cos_batch_from_queue(
    queue: &mut CoSQueueRuntime,
    queue_idx: usize,
    root_budget: u64,
    secondary_budget: u64,
    phase: CoSServicePhase,
) -> Option<CoSBatch> {
    let head = cos_queue_front(queue)?;
    match head {
        CoSPendingTxItem::Local(_) => {
            let mut items = VecDeque::new();
            let mut remaining_root = root_budget;
            let mut remaining_secondary = secondary_budget;
            let mut batch_bytes = 0u64;
            while items.len() < TX_BATCH_SIZE {
                let Some(front) = cos_queue_front(queue) else {
                    break;
                };
                let len = cos_item_len(front);
                if !matches!(front, CoSPendingTxItem::Local(_))
                    || remaining_root < len
                    || remaining_secondary < len
                {
                    break;
                }
                remaining_root = remaining_root.saturating_sub(len);
                remaining_secondary = remaining_secondary.saturating_sub(len);
                match cos_queue_pop_front(queue) {
                    Some(CoSPendingTxItem::Local(req)) => {
                        batch_bytes = batch_bytes.saturating_add(len);
                        items.push_back(req);
                    }
                    Some(other) => {
                        cos_queue_push_front(queue, other);
                        break;
                    }
                    None => break,
                }
            }
            if items.is_empty() {
                None
            } else {
                Some(CoSBatch::Local {
                    queue_idx,
                    phase,
                    batch_bytes,
                    items,
                })
            }
        }
        CoSPendingTxItem::Prepared(_) => {
            let mut items = VecDeque::new();
            let mut remaining_root = root_budget;
            let mut remaining_secondary = secondary_budget;
            let mut batch_bytes = 0u64;
            while items.len() < TX_BATCH_SIZE {
                let Some(front) = cos_queue_front(queue) else {
                    break;
                };
                let len = cos_item_len(front);
                if !matches!(front, CoSPendingTxItem::Prepared(_))
                    || remaining_root < len
                    || remaining_secondary < len
                {
                    break;
                }
                remaining_root = remaining_root.saturating_sub(len);
                remaining_secondary = remaining_secondary.saturating_sub(len);
                match cos_queue_pop_front(queue) {
                    Some(CoSPendingTxItem::Prepared(req)) => {
                        batch_bytes = batch_bytes.saturating_add(len);
                        items.push_back(req);
                    }
                    Some(other) => {
                        cos_queue_push_front(queue, other);
                        break;
                    }
                    None => break,
                }
            }
            if items.is_empty() {
                None
            } else {
                Some(CoSBatch::Prepared {
                    queue_idx,
                    phase,
                    batch_bytes,
                    items,
                })
            }
        }
    }
}

#[inline]
fn submit_cos_batch(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    batch: CoSBatch,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool {
    match batch {
        CoSBatch::Local {
            queue_idx,
            phase,
            batch_bytes,
            mut items,
        } => {
            assign_local_dscp_rewrite(
                &mut items,
                cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx),
            );
            match transmit_batch(binding, &mut items, now_ns, shared_recycles) {
                Ok((packets, bytes)) => {
                    apply_cos_send_result(
                        binding,
                        root_ifindex,
                        queue_idx,
                        phase,
                        batch_bytes,
                        bytes,
                        items,
                    );
                    if packets > 0 {
                        binding
                            .live
                            .tx_packets
                            .fetch_add(packets, Ordering::Relaxed);
                        binding.live.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
                        // #760 instrumentation, non-exact / shared-exact
                        // Local path. See umem.rs field comment.
                        binding
                            .live
                            .owner_profile_owner
                            .drain_sent_bytes_shaped_unconditional
                            .fetch_add(bytes, Ordering::Relaxed);
                    }
                    cos_batch_tx_made_progress(Ok((packets, bytes)))
                }
                Err(TxError::Retry(err)) => {
                    binding.live.set_error(err);
                    restore_cos_local_items(binding, root_ifindex, queue_idx, batch_bytes, items);
                    cos_batch_tx_made_progress(Err(TxError::Retry(String::new())))
                }
                Err(TxError::Drop(err)) => {
                    binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
                    // #710: frame-level submit drop during CoS batch
                    // transmit; items are restored to the queue head,
                    // so this counts the submit-attempt failure, not a
                    // lost packet. Subset of tx_errors.
                    binding
                        .live
                        .tx_submit_error_drops
                        .fetch_add(1, Ordering::Relaxed);
                    binding.live.set_error(err);
                    restore_cos_local_items(binding, root_ifindex, queue_idx, batch_bytes, items);
                    cos_batch_tx_made_progress(Err(TxError::Drop(String::new())))
                }
            }
        }
        CoSBatch::Prepared {
            queue_idx,
            phase,
            batch_bytes,
            mut items,
        } => {
            assign_prepared_dscp_rewrite(
                &mut items,
                cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx),
            );
            match transmit_prepared_queue(binding, &mut items, now_ns) {
                Ok((packets, bytes)) => {
                    apply_cos_prepared_result(
                        binding,
                        root_ifindex,
                        queue_idx,
                        phase,
                        batch_bytes,
                        bytes,
                        items,
                    );
                    if packets > 0 {
                        binding
                            .live
                            .tx_packets
                            .fetch_add(packets, Ordering::Relaxed);
                        binding.live.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
                        // #760 instrumentation, Prepared path (the
                        // in-place-rewrite hot path). See umem.rs
                        // field comment.
                        binding
                            .live
                            .owner_profile_owner
                            .drain_sent_bytes_shaped_unconditional
                            .fetch_add(bytes, Ordering::Relaxed);
                    }
                    cos_batch_tx_made_progress(Ok((packets, bytes)))
                }
                Err(TxError::Retry(err)) => {
                    binding.live.set_error(err);
                    restore_cos_prepared_items(
                        binding,
                        root_ifindex,
                        queue_idx,
                        batch_bytes,
                        items,
                    );
                    cos_batch_tx_made_progress(Err(TxError::Retry(String::new())))
                }
                Err(TxError::Drop(err)) => {
                    binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
                    binding
                        .live
                        .tx_submit_error_drops
                        .fetch_add(1, Ordering::Relaxed);
                    binding.live.set_error(err);
                    restore_cos_prepared_items(
                        binding,
                        root_ifindex,
                        queue_idx,
                        batch_bytes,
                        items,
                    );
                    cos_batch_tx_made_progress(Err(TxError::Drop(String::new())))
                }
            }
        }
    }
}

#[inline]
pub(in crate::afxdp) fn cos_batch_tx_made_progress(result: Result<(u64, u64), TxError>) -> bool {
    matches!(result, Ok((packets, bytes)) if packets > 0 || bytes > 0)
}

#[inline]
pub(in crate::afxdp) fn cos_surplus_quantum_bytes(queue: &CoSQueueRuntime) -> u64 {
    COS_SURPLUS_ROUND_QUANTUM_BYTES.saturating_mul(u64::from(queue.surplus_weight.max(1)))
}

#[inline]
pub(in crate::afxdp) fn cos_guarantee_quantum_bytes(queue: &CoSQueueRuntime) -> u64 {
    let bytes_for_visit = ((queue.transmit_rate_bytes as u128) * (COS_GUARANTEE_VISIT_NS as u128)
        / 1_000_000_000u128) as u64;
    bytes_for_visit.clamp(
        COS_GUARANTEE_QUANTUM_MIN_BYTES,
        COS_GUARANTEE_QUANTUM_MAX_BYTES,
    )
}

pub(in crate::afxdp) fn estimate_cos_queue_wakeup_tick(
    root_tokens: u64,
    root_rate_bytes: u64,
    queue_tokens: u64,
    queue_rate_bytes: u64,
    need_bytes: u64,
    now_ns: u64,
    require_queue_tokens: bool,
) -> Option<u64> {
    let root_refill_ns = cos_refill_ns_until(root_tokens, need_bytes, root_rate_bytes)?;
    let queue_refill_ns = if require_queue_tokens {
        cos_refill_ns_until(queue_tokens, need_bytes, queue_rate_bytes)?
    } else {
        0
    };
    let wake_ns = now_ns.saturating_add(root_refill_ns.max(queue_refill_ns));
    Some(cos_tick_for_ns(wake_ns).max(cos_tick_for_ns(now_ns).saturating_add(1)))
}


#[inline]
pub(in crate::afxdp) fn assign_local_dscp_rewrite(items: &mut VecDeque<TxRequest>, queue_dscp_rewrite: Option<u8>) {
    if queue_dscp_rewrite.is_none() {
        return;
    }
    for req in items.iter_mut() {
        req.dscp_rewrite = req.dscp_rewrite.or(queue_dscp_rewrite);
    }
}

#[inline]
fn assign_prepared_dscp_rewrite(
    items: &mut VecDeque<PreparedTxRequest>,
    queue_dscp_rewrite: Option<u8>,
) {
    if queue_dscp_rewrite.is_none() {
        return;
    }
    for req in items.iter_mut() {
        req.dscp_rewrite = req.dscp_rewrite.or(queue_dscp_rewrite);
    }
}

fn restore_cos_local_items(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    batch_bytes: u64,
    retry: VecDeque<TxRequest>,
) {
    {
        let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) else {
            return;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            let retry_bytes = restore_cos_local_items_inner(queue, retry);
            queue.queued_bytes = queue
                .queued_bytes
                .saturating_sub(batch_bytes)
                .saturating_add(retry_bytes);
        }
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}

fn restore_cos_prepared_items(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    batch_bytes: u64,
    retry: VecDeque<PreparedTxRequest>,
) {
    {
        let Some(root) = binding.cos_interfaces.get_mut(&root_ifindex) else {
            return;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            let retry_bytes = restore_cos_prepared_items_inner(queue, retry);
            queue.queued_bytes = queue
                .queued_bytes
                .saturating_sub(batch_bytes)
                .saturating_add(retry_bytes);
        }
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}

