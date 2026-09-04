// #1331: Prepared-variant submit handler extracted verbatim from
// the CoSBatch::Prepared arm of submit_cos_batch (mod.rs
// pre-refactor L1298-L1402). Pure code motion.
use super::*;

#[inline]
pub(super) fn submit_prepared(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    phase: CoSServicePhase,
    batch_bytes: u64,
    mut items: VecDeque<PreparedTxRequest>,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool {
    assign_prepared_dscp_rewrite(
        &mut items,
        cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx),
    );
    // #1229 v7: pre-transmit sidecar (same shape as Local
    // path — transmit_prepared_queue consumes the successful
    // prefix in-place). Stack array avoids per-batch
    // allocation; only populated for flow-fair queues.
    let prepared_seed_opt = binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .and_then(|q| q.flow_fair_state.as_ref())
        .map(|ff| ff.flow_hash_seed);
    let mut sidecar = [(0u16, 0u64); TX_BATCH_SIZE];
    let sidecar_len = if let Some(seed) = prepared_seed_opt {
        let mut n = 0usize;
        for req in items.iter().take(TX_BATCH_SIZE) {
            sidecar[n] = (
                cos_flow_bucket_index(seed, req.flow_key.as_ref()) as u16,
                req.len as u64,
            );
            n += 1;
        }
        n
    } else {
        0
    };
    // #1829 Phase 1 (Codex review on PR #1846): unconditional
    // enqueue_ns sidecar for committed-prefix-only sojourn sampling —
    // see the matching comment in submit_local.rs.
    let mut enq_sidecar = [0u64; TX_BATCH_SIZE];
    let enq_len = {
        let mut n = 0usize;
        for req in items.iter().take(TX_BATCH_SIZE) {
            enq_sidecar[n] = req.enqueue_ns;
            n += 1;
        }
        n
    };
    // #4973: capture the batch outcome so the drained `items` deque can be
    // stored back into the per-worker Prepared batch scratch after the match,
    // retaining the ring-buffer allocation `build_cos_batch_from_queue` reused.
    let made_progress = match transmit_prepared_queue(binding, &mut items, now_ns, shared_recycles) {
        Ok((packets, bytes)) => {
            items = apply_cos_prepared_result(
                binding,
                root_ifindex,
                queue_idx,
                phase,
                batch_bytes,
                bytes,
                items,
            );
            if packets > 0 && sidecar_len > 0 {
                if let Some(ff) = binding
                    .cos
                    .cos_interfaces
                    .get_mut(&root_ifindex)
                    .and_then(|root| root.queues.get_mut(queue_idx))
                    .and_then(|q| q.flow_fair_state.as_mut())
                {
                    // #8597 K36: clamp to the FILLED prefix, mirroring the
                    // `enq_sidecar` line below. `sidecar` is a fixed
                    // [(u16, u64); TX_BATCH_SIZE] and `packets` is a count
                    // returned by `finalise_prepared`; today three independent
                    // invariants keep it <= `sidecar_len` (the batch build caps
                    // at TX_BATCH_SIZE, the fill covers the whole batch, and
                    // sent never exceeds staged), so this cannot currently
                    // overrun. It is clamped because the cost of being wrong is
                    // an index-OOB panic on a TX worker -- a fail-closed stall
                    // with no restart, the supervisor being detection-only --
                    // and because a `.min()` is a single cmp/cmov on a
                    // per-batch path. The sibling line already pays it.
                    for &(bucket, bytes) in &sidecar[..(packets as usize).min(sidecar_len)] {
                        account_flow_bucket_tx(ff, bucket, bytes, now_ns);
                    }
                }
            }
            // #1829: committed-prefix-only sojourn samples — see the
            // matching block in submit_local.rs.
            if packets > 0 {
                if let Some(queue) = binding
                    .cos
                    .cos_interfaces
                    .get_mut(&root_ifindex)
                    .and_then(|root| root.queues.get_mut(queue_idx))
                {
                    for &enqueue_ns in &enq_sidecar[..(packets as usize).min(enq_len)] {
                        queue.telemetry.sojourn.record(enqueue_ns, now_ns);
                    }
                }
            }
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
            // #hb166 T-6(e): publish the committed queue_vtime on the
            // Prepared CoSBatch settle boundary too — see the matching
            // block + rationale in submit_local.rs. No-op for
            // non-flow-fair / non-shared queues.
            publish_committed_queue_vtime(
                binding
                    .cos
                    .cos_interfaces
                    .get(&root_ifindex)
                    .and_then(|root| root.queues.get(queue_idx)),
            );
            cos_batch_tx_made_progress(Ok((packets, bytes)))
        }
        Err(TxError::Retry(reason)) => {
            // #4971: expected TX backpressure — lock-free status, no
            // `last_error` mutex on the send hot path.
            binding.live.set_tx_retry_status(reason);
            items = restore_cos_prepared_items(
                binding,
                root_ifindex,
                queue_idx,
                batch_bytes,
                items,
            );
            cos_batch_tx_made_progress(Err(TxError::Retry(reason)))
        }
        Err(TxError::Drop(reason)) => {
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            binding
                .live
                .tx_submit_error_drops
                .fetch_add(1, Ordering::Relaxed);
            // #4971: exceptional drop path (rare) still renders the
            // diagnostic message via the mutex-backed set_error.
            binding.live.set_error(reason.message());
            items = restore_cos_prepared_items(
                binding,
                root_ifindex,
                queue_idx,
                batch_bytes,
                items,
            );
            cos_batch_tx_made_progress(Err(TxError::Drop(reason)))
        }
    };
    // #4973: return the drained batch deque to the per-worker Prepared batch
    // scratch so the next shaped-TX drain reuses its capacity instead of
    // allocating a fresh `VecDeque`.
    binding.cos.cos_prepared_batch_scratch = items;
    made_progress
}

// Moved from queue_service/mod.rs (pre-refactor L1511-L1532). Sole
// caller is submit_prepared's Err arms above.
//
// #4973: returns the drained (now-empty) `retry` deque so the submit handler
// can reclaim it as the per-worker Prepared batch scratch. On the
// queue-torn-down early return the deque is returned undrained (its items are
// dropped by the next `build_cos_batch_from_queue` `clear()`, exactly as the
// previous by-value drop dropped them — the queue is gone).
fn restore_cos_prepared_items(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    batch_bytes: u64,
    mut retry: VecDeque<PreparedTxRequest>,
) -> VecDeque<PreparedTxRequest> {
    {
        let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) else {
            return retry;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            let retry_bytes = restore_cos_prepared_items_inner(queue, &mut retry);
            queue.hot.queued_bytes = queue
                .hot
                .queued_bytes
                .saturating_sub(batch_bytes)
                .saturating_add(retry_bytes);
        }
    }
    refresh_cos_interface_activity(binding, root_ifindex);
    retry
}
