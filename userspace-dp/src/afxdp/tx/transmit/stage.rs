// #1354 phase split: STAGE — pop up to TX_BATCH_SIZE prepared TX
// requests from `pending` into `binding.scratch.scratch_prepared_tx`,
// dropping any whose `req.len` exceeds the UMEM frame capacity.
//
// Drop semantics on oversized request: orphan-recycle every already-
// staged entry plus the offender via
// `recycle_prepared_immediately_with_shared`, account orphan count
// against `tx_submit_error_drops` + `tx_errors` (#710 — the orphan
// list here does NOT include the offender; the caller's `+= 1` for
// the Drop return covers it), then return Err(Drop).

use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use crate::afxdp::tx_frame_capacity;
use crate::afxdp::types::PreparedTxRequest;
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::TX_BATCH_SIZE;

use super::{recycle_prepared_immediately_with_shared, TxError};

#[inline]
pub(super) fn stage_batch_into_scratch(
    binding: &mut BindingWorker,
    pending: &mut VecDeque<PreparedTxRequest>,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(), TxError> {
    let batch_size = pending.len().min(TX_BATCH_SIZE);
    binding.scratch.scratch_prepared_tx.clear();
    while binding.scratch.scratch_prepared_tx.len() < batch_size {
        let Some(req) = pending.pop_front() else {
            break;
        };
        if req.len as usize > tx_frame_capacity() {
            let orphaned: Vec<_> = binding.scratch.scratch_prepared_tx.drain(..).collect();
            recycle_prepared_immediately_with_shared(binding, &req, Some(shared_recycles));
            for r in &orphaned {
                recycle_prepared_immediately_with_shared(binding, r, Some(shared_recycles));
            }
            // #710: each orphan is a silently-recycled packet that will
            // not reach the TX ring. The caller's post-return `+= 1`
            // covers the offender (`req`); this accounts for the
            // orphans so `tx_submit_error_drops` matches the actual
            // packet count lost on this Drop return.
            if !orphaned.is_empty() {
                binding
                    .live
                    .tx_submit_error_drops
                    .fetch_add(orphaned.len() as u64, Ordering::Relaxed);
                binding
                    .live
                    .tx_errors
                    .fetch_add(orphaned.len() as u64, Ordering::Relaxed);
            }
            return Err(TxError::Drop(format!(
                "prepared tx frame exceeds UMEM frame capacity: len={} cap={}",
                req.len,
                tx_frame_capacity()
            )));
        }
        binding.scratch.scratch_prepared_tx.push(req);
    }
    Ok(())
}
