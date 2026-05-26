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
    match transmit_prepared_queue(binding, &mut items, now_ns, shared_recycles) {
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
            if packets > 0 && sidecar_len > 0 {
                if let Some(ff) = binding
                    .cos
                    .cos_interfaces
                    .get_mut(&root_ifindex)
                    .and_then(|root| root.queues.get_mut(queue_idx))
                    .and_then(|q| q.flow_fair_state.as_mut())
                {
                    for &(bucket, bytes) in &sidecar[..packets as usize] {
                        account_flow_bucket_tx(ff, bucket, bytes, now_ns);
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

// Moved from queue_service/mod.rs (pre-refactor L1511-L1532). Sole
// caller is submit_prepared's Err arms above.
fn restore_cos_prepared_items(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    batch_bytes: u64,
    retry: VecDeque<PreparedTxRequest>,
) {
    {
        let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) else {
            return;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            let retry_bytes = restore_cos_prepared_items_inner(queue, retry);
            queue.hot.queued_bytes = queue
                .hot
                .queued_bytes
                .saturating_sub(batch_bytes)
                .saturating_add(retry_bytes);
        }
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}
