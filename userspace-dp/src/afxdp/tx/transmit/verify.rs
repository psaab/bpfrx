// #1354 phase split: VERIFY — re-validate every staged frame's UMEM
// slice via the shared (read-only) accessor before reservation. This
// guards against any window where a previous phase mutated state in a
// way that could invalidate the slice bounds. Drop semantics match
// the REWRITE phase: orphan-recycle EVERY staged entry (drain
// captures the offender), account orphan_count.saturating_sub(1) for
// the counters (#710).

use std::sync::atomic::Ordering;

use crate::afxdp::worker::BindingWorker;

use super::{recycle_prepared_immediately_with_shared, TxError};

#[inline]
pub(super) fn verify_umem_slices_for_staged(
    binding: &mut BindingWorker,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(), TxError> {
    for idx in 0..binding.scratch.scratch_prepared_tx.len() {
        let req = &binding.scratch.scratch_prepared_tx[idx];
        let req_offset = req.offset;
        let req_len = req.len;
        if binding
            .umem
            .area()
            .slice(req_offset as usize, req_len as usize)
            .is_none()
        {
            let err_offset = req_offset;
            let err_len = req_len;
            let orphaned: Vec<_> = binding.scratch.scratch_prepared_tx.drain(..).collect();
            for r in &orphaned {
                recycle_prepared_immediately_with_shared(binding, r, Some(shared_recycles));
            }
            // #710: same shape as the slice_mut_unchecked site above —
            // `orphaned` drains EVERY entry including the offender.
            // Caller adds 1 for the offender; we add (len-1) for the
            // rest so `tx_submit_error_drops` matches the actual count.
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
        }
    }
    Ok(())
}
