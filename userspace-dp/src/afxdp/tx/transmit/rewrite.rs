// #1354 phase split: REWRITE — iterate `scratch_prepared_tx` and
// apply per-frame DSCP rewrite mutations to the UMEM frame slice.
//
// Drop semantics on slice-out-of-range: orphan-recycle EVERY staged
// entry (including the offender; the failing iteration's `req` is
// still in `scratch_prepared_tx` at the point of failure, so the
// drain captures it). Account `orphan_count.saturating_sub(1)`
// against `tx_submit_error_drops` + `tx_errors` because the caller's
// post-return `+= 1` covers the offender (#710).

use std::sync::atomic::Ordering;

use crate::afxdp::frame::apply_dscp_rewrite_to_frame;
use crate::afxdp::worker::BindingWorker;

use super::{recycle_prepared_immediately_with_shared, TxError};

#[inline]
pub(super) fn apply_dscp_rewrites_to_staged(
    binding: &mut BindingWorker,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(), TxError> {
    for idx in 0..binding.scratch.scratch_prepared_tx.len() {
        let req = &binding.scratch.scratch_prepared_tx[idx];
        let Some(dscp_rewrite) = req.dscp_rewrite else {
            continue;
        };
        let req_offset = req.offset;
        let req_len = req.len;
        let Some(frame) = (unsafe {
            binding
                .umem
                .area()
                .slice_mut_unchecked(req_offset as usize, req_len as usize)
        }) else {
            let err_offset = req_offset;
            let err_len = req_len;
            let orphaned: Vec<_> = binding.scratch.scratch_prepared_tx.drain(..).collect();
            for r in &orphaned {
                recycle_prepared_immediately_with_shared(binding, r, Some(shared_recycles));
            }
            // #710: each orphan is a silently-recycled packet. Caller
            // will `+= 1` for the offender; this accounts for the rest.
            let orphan_count = orphaned.len();
            if orphan_count > 0 {
                binding
                    .live
                    .tx_submit_error_drops
                    .fetch_add(orphan_count.saturating_sub(1) as u64, Ordering::Relaxed);
                binding
                    .live
                    .tx_errors
                    .fetch_add(orphan_count.saturating_sub(1) as u64, Ordering::Relaxed);
            }
            return Err(TxError::Drop(format!(
                "prepared tx frame slice out of range: offset={} len={}",
                err_offset, err_len
            )));
        };
        let _ = apply_dscp_rewrite_to_frame(frame, dscp_rewrite);
    }
    Ok(())
}
