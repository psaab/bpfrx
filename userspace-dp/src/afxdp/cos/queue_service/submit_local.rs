// #1331: Local-variant submit handler extracted verbatim from the
// CoSBatch::Local arm of submit_cos_batch (mod.rs pre-refactor
// L1192-L1297). Pure code motion. The mirror_clone sidecar
// prefix-attribution defect on transmit_batch (transmit.rs:96-109)
// is preserved verbatim — fixing it is out of scope for this PR
// (carry-over follow-up tracked separately).
use super::*;

#[inline]
pub(super) fn submit_local(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    phase: CoSServicePhase,
    batch_bytes: u64,
    mut items: VecDeque<TxRequest>,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool {
    assign_local_dscp_rewrite(
        &mut items,
        cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx),
    );
    // #1229 v7: pre-transmit sidecar — record (bucket, bytes)
    // for each item in submit order. transmit_batch consumes
    // the successful prefix in-place; we slice the sidecar by
    // returned `packets` to account only the bytes actually
    // shipped (not retries).
    //
    // Stack-allocated array (TX_BATCH_SIZE × 10 bytes = 640 B)
    // avoids per-batch heap allocation on the hot path. The
    // Option<u64> seed acts as a presence flag: None means no
    // flow_fair state → sidecar_len stays 0 and accounting is
    // skipped entirely (no iteration, no branch inside the
    // success block).
    let local_seed_opt = binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .and_then(|q| q.flow_fair_state.as_ref())
        .map(|ff| ff.flow_hash_seed);
    let mut sidecar = [(0u16, 0u64); TX_BATCH_SIZE];
    let sidecar_len = if let Some(seed) = local_seed_opt {
        let mut n = 0usize;
        for req in items.iter().take(TX_BATCH_SIZE) {
            sidecar[n] = (
                cos_flow_bucket_index(seed, req.flow_key.as_ref()) as u16,
                req.bytes.len() as u64,
            );
            n += 1;
        }
        n
    } else {
        0
    };
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
            // #1229 v7: account per-bucket bytes for the sent
            // prefix. sidecar_len > 0 ↔ flow_fair is active.
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

// Moved from queue_service/mod.rs (pre-refactor L1488-L1509). Sole
// caller is submit_local's Err arms above; the *_inner variant lives
// in tx_completion and is still reached via super::.
fn restore_cos_local_items(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    batch_bytes: u64,
    retry: VecDeque<TxRequest>,
) {
    {
        let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) else {
            return;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            let retry_bytes = restore_cos_local_items_inner(queue, retry);
            queue.hot.queued_bytes = queue
                .hot
                .queued_bytes
                .saturating_sub(batch_bytes)
                .saturating_add(retry_bytes);
        }
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}
