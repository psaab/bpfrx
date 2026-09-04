// HA session-delta RPC-fallback buffer: the bounded
// `pending_session_deltas` FIFO, its generated/dropped/drained
// counters, and the #5290 per-binding loss-of-sync latch
// (`delta_loss_pending`) that forces a full owner-RG resync when the
// fallback stream goes lossy. Extracted from `umem/mod.rs` (#6436).

use super::*;

impl BindingLiveState {
    pub(in crate::afxdp) fn push_session_delta(&self, delta: SessionDeltaInfo) {
        self.session_delta_generated.fetch_add(1, Ordering::Relaxed);
        match self.pending_session_deltas.lock() {
            Ok(mut pending) => {
                if pending.len() >= MAX_PENDING_SESSION_DELTAS {
                    self.session_delta_dropped.fetch_add(1, Ordering::Relaxed);
                    // #5290: a dropped RPC-fallback delta is a HA-relevant
                    // open/close the standby will never observe — the fallback
                    // stream just went lossy. Latch loss-of-sync so the owning
                    // worker forces a full owner-RG resync (table-truth rescan),
                    // mirroring `SessionTable::push_delta`'s #2442 behavior.
                    self.delta_loss_pending.store(true, Ordering::Relaxed);
                    return;
                }
                pending.push_back(delta);
                // #8108: record how FULL the buffer got, not how full it is.
                //
                // The acceptance measurement this issue asks for -- "a measured
                // ring-occupancy figure from a revocation burst" -- could not be
                // taken: `len()` was read only for the cap check above and
                // nothing retained it, and `delta_loss_pending` is a BOOLEAN
                // that says "we overflowed at least once", never "we reached
                // 90%". So there was no way to distinguish a buffer that is
                // comfortable from one that survives on luck.
                //
                // A HIGH-WATER MARK rather than a depth gauge, and that is the
                // whole point. This buffer DRAINS; a depth sampled at 1 Hz sees
                // a burst only if the sample lands inside it, and misses it
                // otherwise -- reporting a healthy-looking small number for
                // exactly the event being measured. A high-water mark cannot
                // miss a burst it observed.
                let depth = pending.len();
                self.session_delta_high_water
                    .fetch_max(depth as u64, Ordering::Relaxed);
            }
            Err(_) => {
                self.session_delta_dropped.fetch_add(1, Ordering::Relaxed);
                self.delta_loss_pending.store(true, Ordering::Relaxed);
            }
        }
    }

    /// #5290: true if the RPC-fallback buffer still holds undrained deltas.
    /// Used by the fair-drain overflow scan to arm loss-of-sync only on the
    /// bindings that actually fell behind. A poisoned lock is treated as "not
    /// pending" — the separate poison path in `push_session_delta` already
    /// latched loss-of-sync, so this avoids double-counting.
    pub(in crate::afxdp) fn has_pending_session_deltas(&self) -> bool {
        self.pending_session_deltas
            .lock()
            .map(|pending| !pending.is_empty())
            .unwrap_or(false)
    }

    /// #5290: arm the per-binding loss-of-sync latch. Called by the control-
    /// thread fair drain when the caller budget overflowed and left this
    /// binding's deltas undrained. Mirror of `SessionTable::set_delta_loss`.
    pub(in crate::afxdp) fn set_delta_loss(&self) {
        self.delta_loss_pending.store(true, Ordering::Relaxed);
    }

    /// #5290: consume the per-binding loss-of-sync latch. Called once per drain
    /// cycle by the owning worker loop, which folds a true result into
    /// `SessionTable::set_delta_loss` to drive the existing owner-RG resync.
    /// Single bool swap, so a burst that armed it repeatedly before this read
    /// raises exactly one resync (debounce by construction).
    pub(in crate::afxdp) fn take_delta_loss(&self) -> bool {
        self.delta_loss_pending.swap(false, Ordering::Relaxed)
    }

    pub(in crate::afxdp) fn drain_session_deltas(&self, max: usize) -> Vec<SessionDeltaInfo> {
        let drain = max.max(1);
        match self.pending_session_deltas.lock() {
            Ok(mut pending) => {
                let count = drain.min(pending.len());
                let mut out = Vec::with_capacity(count);
                for _ in 0..count {
                    if let Some(delta) = pending.pop_front() {
                        out.push(delta);
                    }
                }
                self.session_delta_drained
                    .fetch_add(out.len() as u64, Ordering::Relaxed);
                out
            }
            Err(_) => Vec::new(),
        }
    }
}
