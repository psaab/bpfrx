// #2158 (P2): interface-global exact-backlog visibility, extracted from
// shared_cos_lease/mod.rs as a pure code-motion split. The
// `SharedCoSExactBacklog` cluster (PaddedBacklogSlot, PaddedResidualBudget,
// the residual-surplus token bucket) is self-contained — it reaches no
// sibling-submodule item — so this move requires NO visibility widening.
// Type/impl bodies are byte-identical to the pre-split form; atomic
// orderings are preserved exactly.

use std::sync::atomic::{AtomicU64, Ordering};

#[repr(align(64))]
struct PaddedBacklogSlot {
    queued_bytes: AtomicU64,
    serviceable_bytes: AtomicU64,
    demand_queue_mask: AtomicU64,
}

#[repr(align(64))]
struct PaddedResidualBudget {
    tokens: AtomicU64,
    last_refill_ns: AtomicU64,
    /// #7206 A1-b5-F4: bumped by every `reset_residual_surplus_budget`, so a
    /// refill that computed `added` from a PRE-reset epoch can detect that a
    /// reset landed underneath it and decline to resurrect the burst.
    ///
    /// `tokens` and `last_refill_ns` are two independent atomics, so a reset
    /// cannot be made atomic with respect to a refill by ordering alone: the
    /// refill claims its window with a CAS on `last_refill_ns` and then adds
    /// to `tokens` in a SEPARATE loop, and a reset interleaving between those
    /// two steps leaves non-zero tokens after a completed reset. The
    /// generation is the third value that lets the refill notice.
    generation: AtomicU64,
}

/// Interface-global exact-backlog visibility for diagnostics and
/// cross-binding surplus suppression. Each binding owns one slot and publishes:
///   * queued exact bytes, used by diagnostics; and
///   * serviceable exact bytes, used as the priority signal for suppressing
///     peer non-exact surplus.
///   * backlogged exact queue mask, used to reserve each exact queue's
///     aggregate guarantee rate once when bounding peer residual surplus.
///
/// The serviceable/rate signals use release/acquire ordering so transitions are
/// visible across bindings without putting a locked operation in the forwarding
/// loop. The queued-byte diagnostic remains relaxed.
pub(in crate::afxdp) struct SharedCoSExactBacklog {
    worker_bytes: Box<[PaddedBacklogSlot]>,
    residual_budget: PaddedResidualBudget,
}

impl SharedCoSExactBacklog {
    pub(in crate::afxdp) fn new(max_binding_slot: usize) -> Self {
        Self {
            worker_bytes: (0..=max_binding_slot)
                .map(|_| PaddedBacklogSlot {
                    queued_bytes: AtomicU64::new(0),
                    serviceable_bytes: AtomicU64::new(0),
                    demand_queue_mask: AtomicU64::new(0),
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            residual_budget: PaddedResidualBudget {
                tokens: AtomicU64::new(0),
                last_refill_ns: AtomicU64::new(0),
                generation: AtomicU64::new(0),
            },
        }
    }

    pub(in crate::afxdp) fn matches_config(&self, max_binding_slot: usize) -> bool {
        self.worker_bytes.len() == max_binding_slot.saturating_add(1)
    }

    #[inline]
    pub(in crate::afxdp) fn publish(&self, binding_slot: u32, bytes: u64) {
        self.publish_with_serviceable(
            binding_slot,
            bytes,
            bytes,
            if bytes > 0 { u64::MAX } else { 0 },
        );
    }

    #[inline]
    pub(in crate::afxdp) fn publish_with_serviceable(
        &self,
        binding_slot: u32,
        queued_bytes: u64,
        serviceable_bytes: u64,
        demand_queue_mask: u64,
    ) {
        if let Some(slot) = self.worker_bytes.get(binding_slot as usize) {
            slot.queued_bytes.store(queued_bytes, Ordering::Relaxed);
            slot.serviceable_bytes
                .store(serviceable_bytes, Ordering::Release);
            slot.demand_queue_mask
                .store(demand_queue_mask, Ordering::Release);
        }
    }

    #[inline]
    pub(in crate::afxdp) fn has_peer_backlog(&self, binding_slot: u32) -> bool {
        self.worker_bytes
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx != binding_slot as usize)
            .any(|(_, slot)| slot.queued_bytes.load(Ordering::Relaxed) > 0)
    }

    #[inline]
    pub(in crate::afxdp) fn has_peer_serviceable_backlog(&self, binding_slot: u32) -> bool {
        self.worker_bytes
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx != binding_slot as usize)
            .any(|(_, slot)| slot.serviceable_bytes.load(Ordering::Acquire) > 0)
    }

    #[inline]
    pub(in crate::afxdp) fn peer_exact_demand_queue_mask(&self, binding_slot: u32) -> u64 {
        self.worker_bytes
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx != binding_slot as usize)
            .fold(0u64, |acc, (_, slot)| {
                acc | slot.demand_queue_mask.load(Ordering::Acquire)
            })
    }

    /// Zero the residual-surplus budget and restart its refill epoch at
    /// `now_ns`.
    ///
    /// #7206 A1-b5-F4: the generation is bumped FIRST, before either store. A
    /// concurrent `refill_residual_surplus_budget` that has already claimed its
    /// window re-reads the generation around its token CAS, so bumping first
    /// guarantees the refill observes the change and restores the zero rather
    /// than adding tokens derived from the epoch this reset just ended.
    pub(in crate::afxdp) fn reset_residual_surplus_budget(&self, now_ns: u64) {
        self.residual_budget
            .generation
            .fetch_add(1, Ordering::AcqRel);
        self.residual_budget.tokens.store(0, Ordering::Release);
        self.residual_budget
            .last_refill_ns
            .store(now_ns, Ordering::Release);
    }

    pub(in crate::afxdp) fn residual_surplus_budget(
        &self,
        now_ns: u64,
        residual_rate_bytes: u64,
        residual_burst_bytes: u64,
    ) -> u64 {
        if residual_rate_bytes == 0 || residual_burst_bytes == 0 {
            self.reset_residual_surplus_budget(now_ns);
            return 0;
        }
        self.refill_residual_surplus_budget(now_ns, residual_rate_bytes, residual_burst_bytes);
        self.residual_budget
            .tokens
            .load(Ordering::Acquire)
            .min(residual_burst_bytes)
    }

    pub(in crate::afxdp) fn consume_residual_surplus_budget(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        loop {
            let tokens = self.residual_budget.tokens.load(Ordering::Acquire);
            let new_tokens = tokens.saturating_sub(bytes);
            if self
                .residual_budget
                .tokens
                .compare_exchange_weak(tokens, new_tokens, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    fn refill_residual_surplus_budget(
        &self,
        now_ns: u64,
        residual_rate_bytes: u64,
        residual_burst_bytes: u64,
    ) {
        loop {
            // #7206 A1-b5-F4: sample the generation BEFORE reading the epoch,
            // so any reset from here on is observable. `added` below is derived
            // from `last_refill_ns`, and a reset invalidates that derivation.
            let generation = self.residual_budget.generation.load(Ordering::Acquire);
            let last_refill_ns = self.residual_budget.last_refill_ns.load(Ordering::Acquire);
            if last_refill_ns == 0 {
                if self
                    .residual_budget
                    .last_refill_ns
                    .compare_exchange(0, now_ns, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return;
                }
                continue;
            }
            if now_ns <= last_refill_ns {
                return;
            }
            let elapsed_ns = now_ns - last_refill_ns;
            let added =
                ((elapsed_ns as u128) * (residual_rate_bytes as u128) / 1_000_000_000u128) as u64;
            if added == 0 {
                return;
            }
            if self
                .residual_budget
                .last_refill_ns
                .compare_exchange(last_refill_ns, now_ns, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            self.commit_refill_tokens(generation, added, residual_burst_bytes);
            return;
        }
    }

    /// Add `added` tokens on behalf of a refill that sampled `generation`
    /// before deriving `added` from its epoch, declining if a reset has
    /// intervened (#7206 A1-b5-F4).
    ///
    /// Extracted from `refill_residual_surplus_budget` so the guard is
    /// reachable from a test without having to win a race: the defect is a
    /// specific interleaving, and a threaded probe that merely fails to hit it
    /// reports the same green as a correct implementation.
    fn commit_refill_tokens(&self, generation: u64, added: u64, residual_burst_bytes: u64) {
        loop {
            let tokens = self.residual_budget.tokens.load(Ordering::Acquire);
            let new_tokens = tokens.saturating_add(added).min(residual_burst_bytes);
            if self
                .residual_budget
                .tokens
                .compare_exchange_weak(tokens, new_tokens, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // The generation is checked AFTER the CAS, and ONLY after.
                //
                // A pre-CAS check is the intuitive place for it and is what I
                // wrote first, but it cannot be the guarantee: a reset can land
                // between that check and the CAS, and the CAS cannot detect it.
                // A reset stores 0, so if our expected `tokens` was also 0 the
                // compare SUCCEEDS and writes the stale `added` on top of a
                // completed reset — the exact resurrected burst this row
                // reports. Only a check that runs after the write can see it.
                //
                // Both checks were implemented at first, and mutation testing
                // showed each was REDUNDANT GIVEN THE OTHER: deleting either
                // one alone left the suite green, because the survivor caught
                // the case. Two guards where one is load-bearing reads as
                // defence in depth and is really an untested branch plus a
                // guard nobody can tell is doing the work, so the pre-CAS check
                // was removed. Deleting the check below now reds
                // a_refill_whose_epoch_a_reset_ended_adds_nothing_7206_f4.
                //
                // Restoring 0 rather than retrying is deliberate: the reset is
                // the newer intent and it said the budget is empty as of its
                // own `now_ns`. The cost is that a legitimate post-reset refill
                // running concurrently can have its tokens dropped here; that
                // is transient — the next refill re-adds them — and it errs
                // toward granting LESS surplus, which is the safe direction.
                if self.residual_budget.generation.load(Ordering::Acquire) != generation {
                    self.residual_budget.tokens.store(0, Ordering::Release);
                }
                return;
            }
        }
    }

    #[cfg(test)]
    pub(in crate::afxdp) fn residual_generation_for_test(&self) -> u64 {
        self.residual_budget.generation.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(in crate::afxdp) fn residual_tokens_for_test(&self) -> u64 {
        self.residual_budget.tokens.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(in crate::afxdp) fn commit_refill_tokens_for_test(
        &self,
        generation: u64,
        added: u64,
        residual_burst_bytes: u64,
    ) {
        self.commit_refill_tokens(generation, added, residual_burst_bytes);
    }
}
