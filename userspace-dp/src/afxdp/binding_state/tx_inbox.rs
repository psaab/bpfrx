// Cross-worker redirect TX inbox: the bounded lock-free MPSC ring
// (`BindingLiveState::pending_tx`), its linearizable admission
// counter (`pending_tx_admitted`), the hot per-packet enqueue paths
// (`enqueue_tx` / `enqueue_tx_owned` / `try_enqueue_tx_owned`), the
// `PendingTxAdmission` RAII single-release token, and the owner-side
// drain (`take_pending_tx_into`). Extracted from `umem/mod.rs`
// (#6436).

use super::*;
use super::latency::next_redirect_sample;

/// Hard capacity of the per-binding redirect inbox
/// (`BindingLiveState::pending_tx`). Sized to cover the highest expected
/// soft cap produced by `pending_tx_capacity()` in prod
/// (`ring_entries = 2048` → `2 * ring_entries = 4096`). The MPSC ring is
/// allocated once at `BindingLiveState::new()` with this capacity, then
/// the soft cap from `set_max_pending_tx()` gates admissions inside
/// `enqueue_tx` / `enqueue_tx_owned`. If a caller ever requests a soft
/// cap larger than the hard cap, the effective cap clamps here and
/// excess pushes drop with a `redirect_inbox_overflow_drops` counter bump.
pub(in crate::afxdp) const PENDING_TX_INBOX_HARD_CAP: usize = 4096;

pub(in crate::afxdp) struct PendingTxAdmission {
    live: Arc<BindingLiveState>,
    active: bool,
}

impl PendingTxAdmission {
    #[inline]
    pub(in crate::afxdp) fn enqueue_owned(mut self, req: TxRequest) -> Result<(), TxRequest> {
        match self.live.pending_tx.push(req) {
            Ok(()) => {
                self.active = false;
                Ok(())
            }
            Err(req) => Err(req),
        }
    }
}

impl Drop for PendingTxAdmission {
    #[inline]
    fn drop(&mut self) {
        if self.active {
            self.live.release_pending_tx_admission();
        }
    }
}

impl BindingLiveState {
    pub(in crate::afxdp) fn enqueue_tx(&self, req: TxRequest) -> Result<(), String> {
        self.push_redirect_inbox(req);
        Ok(())
    }

    pub(in crate::afxdp) fn enqueue_tx_owned(&self, req: TxRequest) -> Result<(), TxRequest> {
        // #709: redirect-acquire latency, sampled 1-in-256.
        //
        // Hot-path cost on the non-sampled branch: one
        // `fetch_add(1, Relaxed)` + one `&` + one `==`. Under a few ns
        // on modern x86_64. On the sampled branch: two
        // `monotonic_nanos()` (VDSO `clock_gettime(MONOTONIC)`, ~15 ns
        // each) + one bucket write. 1-in-256 sampling amortises to
        // `~(2 * 15 + 2) / 256 ≈ 0.13 ns` per push — well below the
        // noise floor of the redirect path itself.
        //
        // The timer wraps only `push_redirect_inbox`. #5160: the sample
        // sequence is PRODUCER-LOCAL (thread-local `REDIRECT_SAMPLE_SEQ`),
        // NOT a shared atomic on the destination `BindingLiveState` — so a
        // many-producer redirect into one owner pays only the inbox head CAS,
        // never a second contended RMW on a shared sample-counter cacheline.
        // Only the SAMPLED op touches the shared destination histogram below.
        // MPSC invariants from #715 are preserved.
        let sample = next_redirect_sample();
        let start = if sample {
            Some(monotonic_nanos())
        } else {
            None
        };
        self.push_redirect_inbox(req);
        if let Some(start) = start {
            let delta = monotonic_nanos().saturating_sub(start);
            let bucket = bucket_index_for_ns(delta);
            self.owner_profile_peer.redirect_acquire_hist[bucket].fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    pub(in crate::afxdp) fn try_enqueue_tx_owned(&self, req: TxRequest) -> Result<(), TxRequest> {
        self.try_push_redirect_inbox(req)
    }

    pub(in crate::afxdp) fn try_reserve_mirror_tx_owned(
        live: &Arc<Self>,
        mirror_pending_limit: usize,
    ) -> Result<PendingTxAdmission, ()> {
        live.try_acquire_pending_tx_admission(Some(mirror_pending_limit), false)?;
        Ok(PendingTxAdmission {
            live: Arc::clone(live),
            active: true,
        })
    }

    /// Shared push path for `enqueue_tx` and `enqueue_tx_owned`.
    /// Drop-newest on overflow: if the soft cap or ring hard cap is hit,
    /// drop the incoming request and bump the overflow counters. This is
    /// a deliberate change from the pre-#706 drop-oldest behaviour —
    /// older queued packets are closer to being serviced by the owner
    /// worker, so evicting them just extends tail latency. The counter
    /// contract (`tx_errors` as the generic error,
    /// `redirect_inbox_overflow_drops` as the dedicated view) is preserved.
    #[inline]
    fn push_redirect_inbox(&self, req: TxRequest) {
        if self.try_acquire_pending_tx_admission(None, true).is_err() {
            return;
        }
        if self.pending_tx.push(req).is_err() {
            self.release_pending_tx_admission();
            self.record_redirect_inbox_overflow();
        }
    }

    #[inline]
    fn try_push_redirect_inbox(&self, req: TxRequest) -> Result<(), TxRequest> {
        if self.try_acquire_pending_tx_admission(None, true).is_err() {
            return Err(req);
        }
        if let Err(req) = self.pending_tx.push(req) {
            self.release_pending_tx_admission();
            self.record_redirect_inbox_overflow();
            return Err(req);
        }
        Ok(())
    }

    #[inline]
    fn pending_tx_admission_cap(&self, extra_limit: Option<usize>) -> usize {
        let mut admission_cap = self.pending_tx.capacity();
        let max_pending = self.max_pending_tx.load(Ordering::Relaxed) as usize;
        if max_pending > 0 {
            admission_cap = admission_cap.min(max_pending);
        }
        if let Some(limit) = extra_limit {
            if limit > 0 {
                admission_cap = admission_cap.min(limit);
            }
        }
        admission_cap
    }

    #[inline]
    fn try_acquire_pending_tx_admission(
        &self,
        extra_limit: Option<usize>,
        record_overflow: bool,
    ) -> Result<(), ()> {
        let admission_cap = self.pending_tx_admission_cap(extra_limit);
        let mut admitted = self.pending_tx_admitted.load(Ordering::Relaxed);
        loop {
            if admitted >= admission_cap {
                if record_overflow {
                    self.record_redirect_inbox_overflow();
                }
                return Err(());
            }
            match self.pending_tx_admitted.compare_exchange_weak(
                admitted,
                admitted + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => admitted = actual,
            }
        }
    }

    #[inline]
    fn release_pending_tx_admission(&self) {
        let previous = self.pending_tx_admitted.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "pending_tx_admitted underflow");
    }

    #[inline]
    fn record_redirect_inbox_overflow(&self) {
        self.tx_errors.fetch_add(1, Ordering::Relaxed);
        // #710 / #706: non-zero values here indicate the owner worker
        // cannot drain redirects fast enough relative to producer push
        // rate. After #706 the path is lock-free, so contention is no
        // longer the bottleneck — further growth typically points at
        // owner-worker hotspot (#709) or CoS admission (#707 / #708).
        self.redirect_inbox_overflow_drops
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Drain the redirect inbox into a caller-provided `VecDeque`, so the
    /// owner worker's drain stays allocation-free on the hot path. The
    /// caller reuses its existing `pending_tx_local` buffer across polls
    /// — calling `VecDeque::new()` / growing a fresh buffer on every drain
    /// put allocator noise back on the exact thread #706 is trying to
    /// keep quiet.
    pub(in crate::afxdp) fn take_pending_tx_into(&self, out: &mut VecDeque<TxRequest>) {
        if self.pending_tx.is_empty() {
            return;
        }
        // SAFETY: `MpscInbox::pop` requires the single-consumer
        // invariant. The per-binding redirect inbox has exactly one
        // consumer — the owner worker — which is also the sole caller
        // of `take_pending_tx_into`. Enforced by convention (see the doc
        // comment on `pending_tx` in `BindingLiveState`).
        while let Some(req) = unsafe { self.pending_tx.pop() } {
            self.release_pending_tx_admission();
            out.push_back(req);
        }
    }

    pub(in crate::afxdp) fn pending_tx_empty(&self) -> bool {
        self.pending_tx.is_empty()
    }
}
