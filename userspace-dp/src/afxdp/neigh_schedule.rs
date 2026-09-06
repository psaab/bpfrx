//! #7156: deadline-ordered, budgeted scheduling for the per-worker
//! `pending_neigh` buffer.
//!
//! ## The cost this replaces, measured before it was written
//!
//! `retry_pending_neigh` used to snapshot EVERY unresolved key into a fresh
//! `Vec` and walk all of them, on every sweep, with the only bound an
//! empty-map early-out — and it runs TWICE per poll iteration
//! (`worker/lifecycle.rs`, the RX-empty branch and the post-batch call).
//! Timings on the release build, one binding, keys unresolved and not due:
//!
//! | pending keys | ns/sweep | ns/key | Vec bytes/sweep |
//! |--------------|----------|--------|-----------------|
//! | 0            | 8        | —      | 0               |
//! | 64           | 2 673    | 41.8   | 1 536           |
//! | 1 024        | 40 709   | 39.8   | 24 576          |
//! | 4 096 (cap)  | 182 207  | 44.5   | 98 304          |
//!
//! A healthy binding holds zero pending keys and pays 8 ns, which is why this
//! never showed up in ordinary profiling. At the `MAX_PENDING_NEIGH` cap it is
//! ~182 us per sweep, ~364 us per poll iteration, plus ~196 KiB of allocation
//! per poll — an idle worker core spent entirely on bookkeeping for hops whose
//! packets are already being dropped and negatively cached. Filling that cap is
//! attacker-reachable (a scan across distinct unresolved next-hops), and the
//! cost lands on forwarding for unrelated traffic on the same worker.
//!
//! The per-key cost is dominated by the `dynamic_neighbors` lookup, which takes
//! a SHARD MUTEX (`ShardedNeighborMap::get`) — so the sweep is not merely
//! O(all-keys) arithmetic, it is O(all-keys) lock acquisitions contending with
//! the resolver thread that writes those shards. That is the #1187 constraint
//! `stage_screen_check` documents for the aggregate screen counters, arriving
//! here through a different door.
//!
//! ## Why a plain min-heap is enough, and tombstone-free
//!
//! The general worry with lazy-deletion deadline queues is unbounded tombstones
//! under attacker-driven churn. That cannot arise here, and the reason is a
//! property of the buffer rather than of this module:
//!
//! * There is exactly ONE production insert site
//!   (`poll_descriptor`'s `MissingNeighbor` arm), and it inserts only on
//!   `PendingNeighAdmission::Buffer`.
//! * A second packet for a key already pending is `DuplicateDrop` — recycled,
//!   NOT inserted. The buffered representative is never REPLACED (keep-oldest,
//!   #1771 §2.2), so a key cannot acquire a second live deadline.
//! * Both removals (`neighbor_dispatch.rs`, timeout drop and resolved dispatch)
//!   happen on a key the sweep has just POPPED, so the entry that named it is
//!   already gone from the heap.
//!
//! So every live map key has exactly one heap entry and every heap entry names
//! a live map key. The `None` arm on the map lookup after a pop is retained as
//! a belt-and-braces invariant check rather than an expected path, and
//! [`PendingNeighSchedule::len`] is asserted against the map in tests.
//!
//! ## Freshness: what changed, stated plainly
//!
//! The old sweep re-checked EVERY key against both neighbor maps on every
//! poll, so a resolved packet was dispatched on the next poll. Deadline order
//! alone would not do that: a key's own schedule has nothing actionable between
//! its last probe (queued + 260 ms) and its timeout (800 ms–2 s), so a neighbour
//! that resolved at 300 ms would wait until the timeout deadline to be noticed —
//! a correctness regression, not just a latency one, since the packet would be
//! dropped as timed out.
//!
//! Hence [`RESOLUTION_RECHECK_INTERVAL_NS`]: a surviving key is re-armed at
//! `min(next probe slot, timeout instant, now + recheck)`, so it is revisited at
//! least that often regardless of where it sits in its probe schedule. Worst-case
//! added dispatch latency for a resolved packet is one recheck interval, against
//! a 10 ms first probe and a 800 ms–2 s timeout.
//!
//! Under a poll rate too low to fund every key's recheck within the budget, the
//! effective recheck interval stretches. That is the correct degradation: the
//! budget bounds the work, and because the heap is deadline-ordered the entries
//! that fall behind are the ones with the LATEST deadlines, so timeouts and
//! probes — which have earlier deadlines — keep firing on schedule.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::net::IpAddr;

/// Maximum pending-neigh keys visited per sweep. Bounds worst-case sweep cost
/// at ~`BUDGET * 45 ns` (~2.9 us here) independent of how many keys are
/// pending, against ~182 us for the unbounded walk at the 4096 cap.
///
/// Not a fairness knob: the heap is deadline-ordered, so a budget cut short
/// leaves the LATEST-deadline entries unvisited and the earliest — timeouts and
/// due probes — always win. Raising it trades worst-case poll latency for
/// recheck throughput at a large pending population.
pub(super) const PENDING_NEIGH_SWEEP_BUDGET: usize = 64;

/// Backstop bound on how long a key can go unvisited while it has no probe slot
/// and no timeout due.
///
/// This is NOT what keeps resolution prompt — the generation gate in
/// `retry_pending_neigh` does that, walking every key on the sweep after any
/// neighbour insert, so a dynamically-resolved hop dispatches with exactly the
/// pre-#7156 latency. This covers the case that gate cannot see: the STATIC
/// `forwarding.neighbors` map, which changes on config apply rather than
/// through `ShardedNeighborMap`, and so bumps no insert generation.
///
/// #9071: this used to say "the ONE case", and that was false. Two DYNAMIC
/// paths were also invisible to the gate -- `bulk_replace_neighbors` and
/// `learn_pair_if_changed` bumped only the shard epoch, never the insert
/// generation -- so the netlink bulk sync and the #1787 RX source-MAC transit
/// learn both relied on this backstop without saying so. Both now bump, and the
/// static map is genuinely the remaining case.
///
/// The correction matters more than the latency it fixed: a reader tuning
/// RESOLUTION_RECHECK_INTERVAL_NS upward on the strength of "the one case is the
/// static map" would have converted a bounded 50 ms delay on two live paths into
/// a real drop. A rationale that has silently stopped being true is the kind
/// that gets acted on later.
///
/// Sized against that: a config apply is a human-scale event, and 50 ms is far
/// inside the 800 ms–2 s pending timeout, so a statically-configured neighbour
/// resolves a buffered packet long before it could be dropped. Cost at the
/// MAX_PENDING_NEIGH cap is ~4096 x 45 ns per 50 ms, under 0.4% of a core.
///
/// Do not shorten it to buy freshness the gate already provides: at 1 ms the
/// same arithmetic is ~18% of a core at the cap, which is most of the cost this
/// module exists to remove.
pub(super) const RESOLUTION_RECHECK_INTERVAL_NS: u64 = 50_000_000; // 50 ms

/// One armed key. Ordered by deadline first so the heap is a deadline queue;
/// the key breaks ties so ordering is TOTAL and a sweep over same-deadline keys
/// is deterministic rather than dependent on heap internals.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct Armed {
    due_ns: u64,
    key: (i32, IpAddr),
}

/// Deadline-ordered arming for one binding's `pending_neigh` map.
///
/// Holds no packet state: the map remains authoritative and this only decides
/// WHEN a key is next looked at. Pushes and pops do not allocate once the heap
/// has grown to its high-water mark, and it is never rebuilt per sweep.
#[derive(Default, Debug)]
pub(super) struct PendingNeighSchedule {
    heap: BinaryHeap<Reverse<Armed>>,
}

impl PendingNeighSchedule {
    /// Arm `key` to be visited at `due_ns`. Called at the single insert site
    /// and again for every key that survives a sweep.
    #[inline]
    pub(super) fn arm(&mut self, key: (i32, IpAddr), due_ns: u64) {
        self.heap.push(Reverse(Armed { due_ns, key }));
    }

    /// Pop the earliest-deadline key if it is due at `now_ns`, else `None`.
    ///
    /// The `None` return is the whole point: with nothing due, a sweep costs one
    /// heap peek regardless of how many keys are pending.
    #[inline]
    pub(super) fn pop_due(&mut self, now_ns: u64) -> Option<(i32, IpAddr)> {
        match self.heap.peek() {
            Some(Reverse(top)) if top.due_ns <= now_ns => {
                self.heap.pop().map(|Reverse(a)| a.key)
            }
            _ => None,
        }
    }

    /// Number of armed entries. Equal to the map's length by the invariant in
    /// the module header.
    #[inline]
    pub(super) fn len(&self) -> usize {
        self.heap.len()
    }

    /// Earliest armed deadline, for tests and telemetry.
    #[cfg(test)]
    pub(super) fn next_due_ns(&self) -> Option<u64> {
        self.heap.peek().map(|Reverse(a)| a.due_ns)
    }
}

/// When a surviving unresolved key should next be visited.
///
/// `min` of three independent clocks:
/// * its timeout instant, so a timed-out key is popped at the right moment
///   rather than a recheck tick later;
/// * its next probe slot, if the schedule has one left;
/// * `now + recheck`, so resolution is noticed even between slots.
///
/// Saturating throughout: `queued_ns + timeout` cannot wrap the sweep into
/// never visiting a key, which would leak a UMEM frame for the life of the
/// process.
#[inline]
pub(super) fn next_due_for_pending(
    now_ns: u64,
    queued_ns: u64,
    probe_attempts: u8,
    timeout_ns: u64,
    probe_schedule_ns: &[u64],
) -> u64 {
    // The instant the timeout comparison `elapsed > timeout` first holds.
    let timeout_at = queued_ns.saturating_add(timeout_ns).saturating_add(1);
    let mut due = timeout_at;
    if let Some(&slot) = probe_schedule_ns.get(probe_attempts as usize) {
        due = due.min(queued_ns.saturating_add(slot));
    }
    // Clamp forward of `now`: a sweep uses ONE `now_ns` for all its pops, so a
    // key re-armed at or before it would be popped again in the same sweep. The
    // iface-name-miss path does not advance `probe_attempts`, so its next slot
    // stays in the past and it would re-arm in the past every time -- consuming
    // the whole budget and starving every other key. Clamping makes each key
    // visitable at most once per sweep, which is what makes the budget a
    // fairness bound rather than just a cost bound.
    due.min(now_ns.saturating_add(RESOLUTION_RECHECK_INTERVAL_NS))
        .max(now_ns.saturating_add(1))
}
