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

    pub(in crate::afxdp) fn reset_residual_surplus_budget(&self, now_ns: u64) {
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
            loop {
                let tokens = self.residual_budget.tokens.load(Ordering::Acquire);
                let new_tokens = tokens.saturating_add(added).min(residual_burst_bytes);
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
    }
}
