use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

// #1035 P4: shared CoS lease + MQFQ V_min coordination types extracted
// from types.rs. Implements the cross-worker virtual-time floor
// (PaddedVtimeSlot, SharedCoSQueueVtimeFloor) and the lease handshake
// state used by the shared-exact CoS queue scheduler
// (SharedCoSLeaseConfig/State, SharedCoSQueueLease, SharedCoSRootLease).
//
// The corresponding inline `#[cfg(test)] mod tests` block moves
// with the production code per modularity-discipline test-colocation.

pub(in crate::afxdp) struct SharedCoSQueueLease {
    config: SharedCoSLeaseConfig,
    state: SharedCoSLeaseState,
}

pub(in crate::afxdp) struct SharedCoSRootLease {
    config: SharedCoSLeaseConfig,
    state: SharedCoSLeaseState,
}

/// #917 — cross-worker MQFQ V_min synchronization. Per-worker
/// slot of the most recent committed `queue_vtime` for a
/// shared_exact CoS queue. Each worker writes its OWN slot
/// (Release store, single-writer) and reads peers' slots
/// (Acquire load) on each scheduling decision (subject to
/// the K-cadence throttle in tx.rs). The minimum across
/// participating workers' slots is the cross-worker V_min;
/// a worker whose local `queue_vtime` advances more than
/// `LAG_THRESHOLD` past V_min throttles itself for one
/// timer-wheel tick to let slower peers catch up.
///
/// Sentinel value `NOT_PARTICIPATING = u64::MAX` means the
/// slot's worker has no flows on this queue. Peers skip
/// `NOT_PARTICIPATING` slots in the V_min reduction so an
/// idle worker doesn't peg V_min near zero.
///
/// Memory ordering (plan §3.4): `publish` and `vacate` use
/// Release stores; readers use Acquire loads. This
/// establishes a happens-before ordering so any observed
/// vtime is paired with the corresponding pre-vtime queue
/// state mutations.
///
/// Cache layout: each `PaddedVtimeSlot` is 64-byte aligned
/// to prevent false sharing across the worker writers; reads
/// pull each peer's line into Shared once per K-cadence
/// check. See plan §3.3 for the cost analysis.
#[repr(align(64))]
pub(in crate::afxdp) struct PaddedVtimeSlot {
    pub(in crate::afxdp) vtime: AtomicU64,
    _pad: [u8; 56],
}

pub(in crate::afxdp) const NOT_PARTICIPATING: u64 = u64::MAX;

impl PaddedVtimeSlot {
    pub(in crate::afxdp) const fn not_participating() -> Self {
        Self {
            vtime: AtomicU64::new(NOT_PARTICIPATING),
            _pad: [0; 56],
        }
    }

    /// Worker calls this on commit boundary publish (after a
    /// drain commits or push_front rolls back) AND on first
    /// enqueue when the bucket count transitions 0 → ≥1.
    /// Release ordering ensures any prior writes to
    /// `flow_bucket_*_finish_bytes` and `queue_vtime` are
    /// visible to peers that observe this slot Acquire.
    pub(in crate::afxdp) fn publish(&self, vtime: u64) {
        debug_assert_ne!(
            vtime, NOT_PARTICIPATING,
            "live vtime must not equal sentinel"
        );
        self.vtime.store(vtime, Ordering::Release);
    }

    /// Worker calls this when the queue's last bucket drains
    /// for this worker — i.e., the worker has no more
    /// flows on this queue.
    pub(in crate::afxdp) fn vacate(&self) {
        self.vtime.store(NOT_PARTICIPATING, Ordering::Release);
    }

    /// Peer reads. Returns `Some(vtime)` if the slot's
    /// worker is participating, `None` otherwise (skip in
    /// the V_min reduction).
    pub(in crate::afxdp) fn read(&self) -> Option<u64> {
        let v = self.vtime.load(Ordering::Acquire);
        if v == NOT_PARTICIPATING {
            None
        } else {
            Some(v)
        }
    }
}

/// #917 V_min coordination structure for a shared_exact CoS
/// queue. Allocated lazily on shared_exact promotion (see
/// `coordinator.rs`). The slot count is fixed at construction
/// time and matches the configured worker count. Holding an
/// `Arc` of this structure pins it across HA / config-commit
/// transitions.
pub(in crate::afxdp) struct SharedCoSQueueVtimeFloor {
    /// One slot per worker. Index by the worker's
    /// 0-based id.
    pub(in crate::afxdp) slots: Box<[PaddedVtimeSlot]>,
}

impl SharedCoSQueueVtimeFloor {
    pub(in crate::afxdp) fn new(num_workers: usize) -> Self {
        let slots = (0..num_workers)
            .map(|_| PaddedVtimeSlot::not_participating())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self { slots }
    }

    /// Compute V_min across participating peers. Skips
    /// `worker_id`'s own slot to avoid self-throttling.
    /// Returns `None` if no peer is participating (so the
    /// caller treats the queue as unthrottled).
    #[inline]
    pub(in crate::afxdp) fn read_v_min(&self, worker_id: u32) -> Option<u64> {
        let mut v_min = u64::MAX;
        let mut found = false;
        for (idx, slot) in self.slots.iter().enumerate() {
            if idx == worker_id as usize {
                continue;
            }
            if let Some(peer) = slot.read() {
                v_min = v_min.min(peer);
                found = true;
            }
        }
        if found { Some(v_min) } else { None }
    }

    /// Count of currently-participating peers (excludes
    /// `worker_id`'s own slot). Used to size LAG_THRESHOLD
    /// per plan §3.5.
    #[inline]
    pub(in crate::afxdp) fn participating_peer_count(&self, worker_id: u32) -> u32 {
        let mut count = 0u32;
        for (idx, slot) in self.slots.iter().enumerate() {
            if idx == worker_id as usize {
                continue;
            }
            if slot.read().is_some() {
                count += 1;
            }
        }
        count
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SharedCoSLeaseConfig {
    rate_bytes: u64,
    burst_bytes: u64,
    lease_bytes: u64,
    max_total_leased: u64,
    active_shards: usize,
}

#[repr(align(64))]
#[derive(Debug)]
struct SharedCoSLeaseState {
    credits: AtomicU64,
    last_refill_ns: AtomicU64,
}

const COS_ROOT_LEASE_TARGET_US: u64 = 200;
const COS_ROOT_LEASE_MIN_BYTES: u64 = 1500;
const COS_ROOT_LEASE_MAX_BYTES: u64 = 512 * 1024;

fn compute_shared_cos_lease_config(
    rate_bytes: u64,
    burst_bytes: u64,
    active_shards: usize,
) -> SharedCoSLeaseConfig {
    let burst_bytes = burst_bytes
        .max(COS_ROOT_LEASE_MIN_BYTES)
        .min(u32::MAX as u64);
    let active_shards = active_shards.max(1);
    let target_lease_bytes =
        ((rate_bytes as u128) * (COS_ROOT_LEASE_TARGET_US as u128) / 1_000_000u128) as u64;
    let lease_ceiling = burst_bytes
        .saturating_div(8)
        .min(COS_ROOT_LEASE_MAX_BYTES)
        .max(COS_ROOT_LEASE_MIN_BYTES);
    let lease_bytes = target_lease_bytes
        .max(COS_ROOT_LEASE_MIN_BYTES)
        .min(lease_ceiling);
    let max_frame_lease_bytes = lease_bytes.max(tx_frame_capacity() as u64);
    let max_total_leased = burst_bytes
        .saturating_div(4)
        .min(max_frame_lease_bytes.saturating_mul(active_shards as u64));
    debug_assert!(max_total_leased <= u32::MAX as u64);
    SharedCoSLeaseConfig {
        rate_bytes,
        burst_bytes,
        lease_bytes,
        max_total_leased,
        active_shards,
    }
}

#[inline(always)]
fn pack_shared_cos_lease_credits(available_tokens: u64, outstanding_leased_tokens: u64) -> u64 {
    debug_assert!(available_tokens <= u32::MAX as u64);
    debug_assert!(outstanding_leased_tokens <= u32::MAX as u64);
    (available_tokens << 32) | outstanding_leased_tokens
}

#[inline(always)]
fn unpack_shared_cos_lease_credits(credits: u64) -> (u64, u64) {
    ((credits >> 32) as u64, (credits as u32) as u64)
}

fn shared_cos_lease_acquire(
    config: SharedCoSLeaseConfig,
    state: &SharedCoSLeaseState,
    now_ns: u64,
    requested: u64,
) -> u64 {
    if requested == 0 {
        return 0;
    }
    refill_shared_cos_lease_state(config, state, now_ns);
    loop {
        let credits = state.credits.load(Ordering::Acquire);
        let (available_tokens, outstanding_leased_tokens) =
            unpack_shared_cos_lease_credits(credits);
        let lease_headroom = config
            .max_total_leased
            .saturating_sub(outstanding_leased_tokens);
        let granted = requested.min(available_tokens).min(lease_headroom);
        if granted == 0 {
            return 0;
        }
        let new_credits = pack_shared_cos_lease_credits(
            available_tokens.saturating_sub(granted),
            outstanding_leased_tokens.saturating_add(granted),
        );
        if state
            .credits
            .compare_exchange_weak(credits, new_credits, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return granted;
        }
    }
}

fn shared_cos_lease_consume(state: &SharedCoSLeaseState, bytes: u64) {
    if bytes == 0 {
        return;
    }
    loop {
        let credits = state.credits.load(Ordering::Acquire);
        let (available_tokens, outstanding_leased_tokens) =
            unpack_shared_cos_lease_credits(credits);
        let new_credits = pack_shared_cos_lease_credits(
            available_tokens,
            outstanding_leased_tokens.saturating_sub(bytes),
        );
        if state
            .credits
            .compare_exchange_weak(credits, new_credits, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
    }
}

#[inline(always)]
fn shared_cos_lease_available_cap(
    config: SharedCoSLeaseConfig,
    outstanding_leased_tokens: u64,
) -> u64 {
    config.burst_bytes.saturating_sub(outstanding_leased_tokens)
}

fn shared_cos_lease_release_unused(
    config: SharedCoSLeaseConfig,
    state: &SharedCoSLeaseState,
    bytes: u64,
) {
    if bytes == 0 {
        return;
    }
    loop {
        let credits = state.credits.load(Ordering::Acquire);
        let (available_tokens, outstanding_leased_tokens) =
            unpack_shared_cos_lease_credits(credits);
        let new_outstanding = outstanding_leased_tokens.saturating_sub(bytes);
        let new_available = available_tokens
            .saturating_add(bytes)
            .min(shared_cos_lease_available_cap(config, new_outstanding));
        let new_credits = pack_shared_cos_lease_credits(new_available, new_outstanding);
        if state
            .credits
            .compare_exchange_weak(credits, new_credits, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
    }
}

fn refill_shared_cos_lease_state(
    config: SharedCoSLeaseConfig,
    state: &SharedCoSLeaseState,
    now_ns: u64,
) {
    if config.burst_bytes == 0 {
        return;
    }
    loop {
        let last_refill_ns = state.last_refill_ns.load(Ordering::Acquire);
        if last_refill_ns == 0 {
            if state
                .last_refill_ns
                .compare_exchange(0, now_ns, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
            continue;
        }
        if now_ns <= last_refill_ns || config.rate_bytes == 0 {
            return;
        }
        let elapsed_ns = now_ns - last_refill_ns;
        let added = ((elapsed_ns as u128) * (config.rate_bytes as u128) / 1_000_000_000u128) as u64;
        if added == 0 {
            return;
        }
        if state
            .last_refill_ns
            .compare_exchange(last_refill_ns, now_ns, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            continue;
        }
        loop {
            let credits = state.credits.load(Ordering::Acquire);
            let (available_tokens, outstanding_leased_tokens) =
                unpack_shared_cos_lease_credits(credits);
            let new_available =
                available_tokens
                    .saturating_add(added)
                    .min(shared_cos_lease_available_cap(
                        config,
                        outstanding_leased_tokens,
                    ));
            let new_credits =
                pack_shared_cos_lease_credits(new_available, outstanding_leased_tokens);
            if state
                .credits
                .compare_exchange_weak(credits, new_credits, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }
}

impl SharedCoSQueueLease {
    pub(in crate::afxdp) fn new(rate_bytes: u64, burst_bytes: u64, active_shards: usize) -> Self {
        let config = compute_shared_cos_lease_config(rate_bytes, burst_bytes, active_shards);
        Self {
            config,
            state: SharedCoSLeaseState {
                credits: AtomicU64::new(pack_shared_cos_lease_credits(config.burst_bytes, 0)),
                last_refill_ns: AtomicU64::new(0),
            },
        }
    }

    pub(in crate::afxdp) fn lease_bytes(&self) -> u64 {
        self.config.lease_bytes
    }

    pub(in crate::afxdp) fn matches_config(
        &self,
        rate_bytes: u64,
        burst_bytes: u64,
        active_shards: usize,
    ) -> bool {
        self.config == compute_shared_cos_lease_config(rate_bytes, burst_bytes, active_shards)
    }

    pub(in crate::afxdp) fn acquire(&self, now_ns: u64, requested: u64) -> u64 {
        shared_cos_lease_acquire(self.config, &self.state, now_ns, requested)
    }

    pub(in crate::afxdp) fn consume(&self, bytes: u64) {
        shared_cos_lease_consume(&self.state, bytes);
    }

    pub(in crate::afxdp) fn release_unused(&self, bytes: u64) {
        shared_cos_lease_release_unused(self.config, &self.state, bytes);
    }
}

impl SharedCoSRootLease {
    pub(in crate::afxdp) fn new(shaping_rate_bytes: u64, burst_bytes: u64, active_shards: usize) -> Self {
        let config =
            compute_shared_cos_lease_config(shaping_rate_bytes, burst_bytes, active_shards);
        Self {
            config,
            state: SharedCoSLeaseState {
                credits: AtomicU64::new(pack_shared_cos_lease_credits(config.burst_bytes, 0)),
                last_refill_ns: AtomicU64::new(0),
            },
        }
    }

    pub(in crate::afxdp) fn lease_bytes(&self) -> u64 {
        self.config.lease_bytes
    }

    pub(in crate::afxdp) fn matches_config(
        &self,
        shaping_rate_bytes: u64,
        burst_bytes: u64,
        active_shards: usize,
    ) -> bool {
        self.config
            == compute_shared_cos_lease_config(shaping_rate_bytes, burst_bytes, active_shards)
    }

    pub(in crate::afxdp) fn acquire(&self, now_ns: u64, requested: u64) -> u64 {
        shared_cos_lease_acquire(self.config, &self.state, now_ns, requested)
    }

    pub(in crate::afxdp) fn consume(&self, bytes: u64) {
        shared_cos_lease_consume(&self.state, bytes);
    }

    pub(in crate::afxdp) fn release_unused(&self, bytes: u64) {
        shared_cos_lease_release_unused(self.config, &self.state, bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::align_of;

    // #694 / #711: `FlowRrRing` invariant pins.
    //
    // The ring is the SFQ round-robin cursor storage. Every bug class
    // that can break it is pinned here so a future refactor that
    // changes the indexing math, the wrap condition, or the head/len
    // update order fails loudly in CI instead of during live
    // validation.








    fn shared_cos_lease_snapshot(lease: &SharedCoSRootLease) -> (u64, u64, u64) {
        let (available_tokens, outstanding_leased_tokens) =
            unpack_shared_cos_lease_credits(lease.state.credits.load(Ordering::Relaxed));
        let last_refill_ns = lease.state.last_refill_ns.load(Ordering::Relaxed);
        (available_tokens, outstanding_leased_tokens, last_refill_ns)
    }

    #[test]
    fn shared_cos_root_lease_refill_respects_outstanding_burst_credit() {
        let lease = SharedCoSRootLease::new(10_000_000, 16_000, 1);
        lease
            .state
            .credits
            .store(pack_shared_cos_lease_credits(0, 4_000), Ordering::Relaxed);
        lease.state.last_refill_ns.store(1, Ordering::Relaxed);

        refill_shared_cos_lease_state(lease.config, &lease.state, 1_000_000_001);

        let (available_tokens, outstanding_leased_tokens, _) = shared_cos_lease_snapshot(&lease);
        assert_eq!(
            available_tokens,
            lease.config.burst_bytes - outstanding_leased_tokens
        );
    }

    #[test]
    fn shared_cos_root_lease_release_unused_preserves_total_burst_bound() {
        let lease = SharedCoSRootLease::new(10_000_000, 16_000, 1);
        lease.state.credits.store(
            pack_shared_cos_lease_credits(lease.config.burst_bytes, 4_000),
            Ordering::Relaxed,
        );

        lease.release_unused(1_500);

        let (available_tokens, outstanding_leased_tokens, _) = shared_cos_lease_snapshot(&lease);
        assert_eq!(
            available_tokens + outstanding_leased_tokens,
            lease.config.burst_bytes
        );
    }

    #[test]
    fn shared_cos_lease_state_is_cacheline_aligned() {
        assert_eq!(align_of::<SharedCoSLeaseState>(), 64);
    }

    #[test]
    fn shared_cos_lease_config_clamps_burst_to_packed_range() {
        let lease = SharedCoSRootLease::new(10_000_000, u64::MAX, 1);
        assert_eq!(lease.config.burst_bytes, u32::MAX as u64);
    }
}