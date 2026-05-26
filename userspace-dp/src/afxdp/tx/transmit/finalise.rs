// #1354 phase split: FINALISE — apply post-commit accounting and
// recovery. On `inserted == 0` (ring full): bump the ring-full
// telemetry, kick TX, push the entire staged scratch back to the
// front of `pending`, and return Retry. On success: bump
// `outstanding_tx`, walk the staged scratch counting sent bytes/
// packets, call `remember_prepared_recycle` for entries the kernel
// accepted, push the un-accepted tail back to `pending` front in the
// right order, and kick TX.

use std::collections::VecDeque;

use crate::afxdp::types::PreparedTxRequest;
use crate::afxdp::worker::BindingWorker;

use super::super::rings::maybe_wake_tx;
use super::{remember_prepared_recycle, TxError};

#[inline]
pub(super) fn finalise_prepared(
    binding: &mut BindingWorker,
    pending: &mut VecDeque<PreparedTxRequest>,
    now_ns: u64,
    inserted: u32,
) -> Result<(u64, u64), TxError> {
    if inserted == 0 {
        binding.telemetry.dbg_tx_ring_full += 1;
        maybe_wake_tx(binding, true, now_ns);
        while let Some(req) = binding.scratch.scratch_prepared_tx.pop() {
            pending.push_front(req);
        }
        return Err(TxError::Retry("prepared tx ring insert failed".to_string()));
    }
    binding.telemetry.dbg_tx_ring_submitted += inserted as u64;
    binding.tx_pipeline.outstanding_tx =
        binding.tx_pipeline.outstanding_tx.saturating_add(inserted);

    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    let mut retry_tail = Vec::new();
    for (idx, req) in binding.scratch.scratch_prepared_tx.drain(..).enumerate() {
        if idx < inserted as usize {
            remember_prepared_recycle(&mut binding.tx_pipeline.in_flight_prepared_recycles, &req);
            sent_packets += 1;
            sent_bytes += req.len as u64;
        } else {
            retry_tail.push(req);
        }
    }
    for req in retry_tail.into_iter().rev() {
        pending.push_front(req);
    }

    // Prepared cross-binding forwards need the same explicit TX kick.
    maybe_wake_tx(binding, true, now_ns);
    Ok((sent_packets, sent_bytes))
}
