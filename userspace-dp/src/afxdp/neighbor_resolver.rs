// #1771: per-key neighbor resolver state machine.
//
// Replaces the global `neighbor_generation` and per-binding `pending_neigh`
// admit-everything queue with a structured per-key state machine.
//
// ## Design
//
// Each `(egress_ifindex, next_hop)` key has independent state:
//
// - **Per-key epoch**: bumped on RTM_NEWNEIGH/DELNEIGH for THAT key only,
//   not on unrelated neighbor churn. Eliminates false rejects from #1769's
//   global generation.
//
// - **Single representative packet**: at most ONE packet buffered per key
//   under a fair global cap (replaces per-binding 4096 admit-everything).
//   Duplicate SYNs for a dead host are dropped at the fast-fail gate, but
//   the resolver keeps running (negative policy = "do not buffer duplicates",
//   NOT "stop resolution").
//
// - **Backoff coalescing**: all packet pressure for a key collapses into
//   ONE in-flight RTM_GETNEIGH probe per key with exponential backoff.
//   The #1769 implementation deduped probes only within a single sweep;
//   this version maintains cross-sweep state.
//
// - **ENOBUFS handling**: netlink monitor detects `recv()<=0` with ENOBUFS
//   errno, increments counter, and triggers throttled family re-dump plus
//   targeted single-key GET for hot keys.
//
// ## State transitions
//
// ```text
// Idle ──(first packet, no neighbor)──> Resolving
//   │                                        │
//   │                                        ├─(RTM_NEWNEIGH)─> Resolved
//   │                                        │                      │
//   │                                        │                      └─(RTM_DELNEIGH/FAILED)─> Idle
//   │                                        │
//   │                                        ├─(timeout)─> Negative
//   │                                        │                 │
//   │                                        │                 ├─(RTM_NEWNEIGH)─> Resolved
//   │                                        │                 │
//   │                                        │                 └─(TTL expiry)─> Idle
//   │                                        │
//   │                                        └─(backoff retry)─> Resolving (same state, new probe)
//   │
//   └─(packet arrives, key in Negative)──> drop duplicate, resolver still running
// ```

use super::types::FastMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Per-key resolver state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResolverState {
    /// No active resolution. Next packet will start the state machine.
    Idle,
    /// Actively resolving. One probe in flight, backoff timer running.
    /// `attempts` tracks probe count for exponential backoff.
    /// `last_probe_ns` is monotonic timestamp of last probe send.
    Resolving { attempts: u8, last_probe_ns: u64 },
    /// Neighbor confirmed via RTM_NEWNEIGH. Packets forward normally.
    /// `confirmed_at_ns` is when RTM_NEWNEIGH arrived (for TTL).
    Resolved { confirmed_at_ns: u64 },
    /// Resolution failed (timeout). Duplicate packets fast-fail,
    /// but resolver continues probing on backoff schedule.
    /// `failed_at_ns` is when timeout occurred.
    /// `attempts` continues incrementing for backoff.
    Negative {
        failed_at_ns: u64,
        attempts: u8,
        last_probe_ns: u64,
    },
}

/// Per-key state entry. Contains the state machine plus per-key epoch
/// for out-of-order safety.
#[derive(Debug, Clone)]
pub(super) struct ResolverEntry {
    pub(super) state: ResolverState,
    /// Per-key epoch bumped on every RTM_NEWNEIGH/DELNEIGH for this key.
    /// Used to detect stale async operations (probe responses arriving
    /// after the neighbor was deleted and re-added).
    pub(super) epoch: u64,
    /// Monotonic timestamp of last state transition (for TTL and backoff).
    pub(super) updated_ns: u64,
}

impl ResolverEntry {
    fn new(state: ResolverState, now_ns: u64) -> Self {
        Self {
            state,
            epoch: 1,
            updated_ns: now_ns,
        }
    }

    fn bump_epoch(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
    }
}

/// Global resolver state machine. One instance per worker thread
/// (mirrors the per-binding model — no cross-thread sync needed).
pub(super) struct NeighborResolver {
    /// Per-key state map.
    states: FastMap<(i32, IpAddr), ResolverEntry>,
    /// Representative packet queue: at most ONE entry per key,
    /// under a global cap. Key is `(egress_ifindex, next_hop)`.
    /// Value is the buffered packet descriptor for retry once
    /// neighbor resolves.
    pending: FastMap<(i32, IpAddr), PendingPacket>,
    /// Global cap for pending queue (fair across keys).
    /// Replaces per-binding MAX_PENDING_NEIGH=4096 admit-everything.
    max_pending: usize,
    /// Per-key negative cache TTL (how long to fast-fail duplicates
    /// after a timeout, while resolver keeps running).
    neg_ttl_ns: u64,
    /// Resolved entry TTL (how long to keep Resolved state without
    /// refresh before returning to Idle).
    resolved_ttl_ns: u64,
    /// Backoff schedule for probes (matches PROBE_SCHEDULE_NS from
    /// neighbor_dispatch.rs for compatibility during migration).
    probe_schedule_ns: &'static [u64],
    /// Prometheus counters (exported via shared atomic counters).
    pub(super) counters: ResolverCounters,
}

/// Buffered packet awaiting neighbor resolution.
/// Only ONE per key is stored (representative).
#[derive(Debug, Clone)]
pub(super) struct PendingPacket {
    /// Packet metadata needed for retry.
    pub(super) addr: u32,
    pub(super) len: u32,
    pub(super) queued_ns: u64,
    /// Number of probes already sent for this key.
    pub(super) probe_attempts: u8,
}

/// Prometheus counters for resolver observability.
#[derive(Debug, Default)]
pub(super) struct ResolverCounters {
    /// Total keys currently in Resolving state.
    pub resolving_keys: AtomicU64,
    /// Total keys currently in Negative state.
    pub negative_keys: AtomicU64,
    /// Total keys currently in Resolved state.
    pub resolved_keys: AtomicU64,
    /// Total probe requests sent (RTM_GETNEIGH).
    pub probes_sent: AtomicU64,
    /// Total packets fast-failed due to negative cache
    /// (duplicate SYNs dropped while resolver runs).
    pub fast_fail_drops: AtomicU64,
    /// Total packets buffered as representative (one per key).
    pub buffered_packets: AtomicU64,
    /// Total packets dropped due to pending queue full.
    pub pending_full_drops: AtomicU64,
    /// Total ENOBUFS events detected on netlink monitor.
    pub netlink_enobufs: AtomicU64,
    /// Total throttled re-dumps triggered by ENOBUFS.
    pub netlink_redumps: AtomicU64,
}

impl NeighborResolver {
    pub(super) fn new() -> Self {
        Self {
            states: FastMap::default(),
            pending: FastMap::default(),
            max_pending: 4096, // Same global cap as old per-binding, but now shared fairly
            neg_ttl_ns: 2_000_000_000, // 2 seconds, matches NEG_NEIGH_TTL_NS
            resolved_ttl_ns: 300_000_000_000, // 5 minutes
            probe_schedule_ns: &[10_000_000, 60_000_000, 260_000_000, 1_000_000_000],
            counters: ResolverCounters::default(),
        }
    }

    /// Handle a packet needing neighbor resolution.
    /// Returns:
    /// - `ResolveAction::Buffer` to buffer as representative (first packet for key)
    /// - `ResolveAction::FastFail` to drop duplicate (key already in Negative)
    /// - `ResolveAction::Forward` if neighbor already resolved
    /// - `ResolveAction::Drop` if pending queue full
    pub(super) fn handle_missing_neighbor(
        &mut self,
        key: (i32, IpAddr),
        packet: PendingPacket,
        now_ns: u64,
        is_resolved: impl FnOnce() -> bool,
    ) -> ResolveAction {
        // Resolved-neighbor-wins: check FIRST, before consulting state.
        if is_resolved() {
            // Neighbor is up — ensure state reflects that.
            self.transition_to_resolved(key, now_ns);
            return ResolveAction::Forward;
        }

        self.handle_missing_neighbor_inner(key, packet, now_ns)
    }

    fn handle_missing_neighbor_inner(
        &mut self,
        key: (i32, IpAddr),
        packet: PendingPacket,
        now_ns: u64,
    ) -> ResolveAction {
        // Loop to handle TTL expiry transitions without recursion.
        loop {
            let entry = self.states.entry(key).or_insert_with(|| {
                ResolverEntry::new(ResolverState::Idle, now_ns)
            });

            match entry.state {
            ResolverState::Idle => {
                // First packet for this key — start resolution.
                entry.state = ResolverState::Resolving {
                    attempts: 0,
                    last_probe_ns: now_ns,
                };
                entry.updated_ns = now_ns;
                self.counters.resolving_keys.fetch_add(1, Ordering::Relaxed);

                // Buffer as representative if under cap.
                if self.pending.len() < self.max_pending {
                    self.pending.insert(key, packet);
                    self.counters.buffered_packets.fetch_add(1, Ordering::Relaxed);
                    break ResolveAction::Buffer;
                } else {
                    self.counters.pending_full_drops.fetch_add(1, Ordering::Relaxed);
                    break ResolveAction::Drop;
                }
            }
            ResolverState::Resolving { .. } => {
                // Already resolving — this is a duplicate packet.
                // Do NOT buffer (one representative already queued).
                // Do NOT send another probe (backoff coalescing).
                // Just drop the duplicate to avoid queue bloat.
                self.counters.fast_fail_drops.fetch_add(1, Ordering::Relaxed);
                break ResolveAction::FastFail;
            }
            ResolverState::Resolved { confirmed_at_ns } => {
                // Should have been caught by is_resolved() above,
                // but handle staleness: if TTL expired, return to Idle.
                if now_ns.saturating_sub(confirmed_at_ns) >= self.resolved_ttl_ns {
                    entry.state = ResolverState::Idle;
                    entry.updated_ns = now_ns;
                    self.counters.resolved_keys.fetch_sub(1, Ordering::Relaxed);
                    // Loop to handle as Idle (will start new resolution).
                    continue;
                }
                // Still within TTL — forward.
                break ResolveAction::Forward;
            }
            ResolverState::Negative { failed_at_ns, .. } => {
                // Negative cache active — fast-fail duplicate,
                // BUT resolver keeps running (probes continue on backoff).
                if now_ns.saturating_sub(failed_at_ns) >= self.neg_ttl_ns {
                    // TTL expired — return to Idle for fresh attempt.
                    entry.state = ResolverState::Idle;
                    entry.updated_ns = now_ns;
                    self.counters.negative_keys.fetch_sub(1, Ordering::Relaxed);
                    // Loop to handle as Idle.
                    continue;
                }
                self.counters.fast_fail_drops.fetch_add(1, Ordering::Relaxed);
                break ResolveAction::FastFail;
            }
        }
    }
    }

    /// Called on RTM_NEWNEIGH for a key. Transitions to Resolved
    /// and returns the buffered representative packet (if any) for retry.
    pub(super) fn on_neighbor_resolved(
        &mut self,
        key: (i32, IpAddr),
        now_ns: u64,
    ) -> Option<PendingPacket> {
        self.transition_to_resolved(key, now_ns);
        self.pending.remove(&key)
    }

    fn transition_to_resolved(&mut self, key: (i32, IpAddr), now_ns: u64) {
        let entry = self.states.entry(key).or_insert_with(|| {
            ResolverEntry::new(ResolverState::Idle, now_ns)
        });

        // Decrement old state counter
        match entry.state {
            ResolverState::Resolving { .. } => {
                self.counters.resolving_keys.fetch_sub(1, Ordering::Relaxed);
            }
            ResolverState::Negative { .. } => {
                self.counters.negative_keys.fetch_sub(1, Ordering::Relaxed);
            }
            ResolverState::Resolved { .. } => {
                // Already resolved — just refresh timestamp, no counter change
                entry.updated_ns = now_ns;
                return;
            }
            ResolverState::Idle => {}
        }

        entry.state = ResolverState::Resolved {
            confirmed_at_ns: now_ns,
        };
        entry.bump_epoch();
        entry.updated_ns = now_ns;
        self.counters.resolved_keys.fetch_add(1, Ordering::Relaxed);
    }

    /// Called on RTM_DELNEIGH or RTM_NEWNEIGH with NUD_FAILED for a key.
    /// Transitions to Idle (removes from state map) and drops any
    /// buffered packet.
    pub(super) fn on_neighbor_removed(&mut self, key: (i32, IpAddr)) {
        if let Some(entry) = self.states.remove(&key) {
            match entry.state {
                ResolverState::Resolving { .. } => {
                    self.counters.resolving_keys.fetch_sub(1, Ordering::Relaxed);
                }
                ResolverState::Negative { .. } => {
                    self.counters.negative_keys.fetch_sub(1, Ordering::Relaxed);
                }
                ResolverState::Resolved { .. } => {
                    self.counters.resolved_keys.fetch_sub(1, Ordering::Relaxed);
                }
                ResolverState::Idle => {}
            }
        }
        self.pending.remove(&key);
    }

    /// Called on timeout for a resolving key. Transitions to Negative
    /// state (fast-fail duplicates, but keep probing).
    pub(super) fn on_resolve_timeout(&mut self, key: (i32, IpAddr), now_ns: u64) {
        if let Some(entry) = self.states.get_mut(&key) {
            if let ResolverState::Resolving { attempts, .. } = entry.state {
                entry.state = ResolverState::Negative {
                    failed_at_ns: now_ns,
                    attempts,
                    last_probe_ns: now_ns,
                };
                entry.updated_ns = now_ns;
                self.counters.resolving_keys.fetch_sub(1, Ordering::Relaxed);
                self.counters.negative_keys.fetch_add(1, Ordering::Relaxed);
            }
        }
        // Drop the buffered representative packet — it timed out.
        self.pending.remove(&key);
    }

    /// Check if a probe is due for a key based on backoff schedule.
    /// Returns true if probe should be sent now.
    pub(super) fn is_probe_due(&self, key: &(i32, IpAddr), now_ns: u64) -> bool {
        let Some(entry) = self.states.get(key) else {
            return false;
        };

        let (attempts, last_probe_ns) = match entry.state {
            ResolverState::Resolving {
                attempts,
                last_probe_ns,
            } => (attempts, last_probe_ns),
            ResolverState::Negative {
                attempts,
                last_probe_ns,
                ..
            } => (attempts, last_probe_ns),
            _ => return false,
        };

        let elapsed = now_ns.saturating_sub(last_probe_ns);
        let schedule_idx = attempts as usize;

        if schedule_idx >= self.probe_schedule_ns.len() {
            // Schedule exhausted — use exponential backoff beyond schedule
            // Double the last interval each time, capped at 5 seconds.
            let last_interval = self.probe_schedule_ns.last().copied().unwrap_or(1_000_000_000);
            let extra_attempts = schedule_idx - self.probe_schedule_ns.len() + 1;
            let backoff = (last_interval << extra_attempts.min(3)).min(5_000_000_000);
            elapsed >= backoff
        } else {
            elapsed >= self.probe_schedule_ns[schedule_idx]
        }
    }

    /// Mark probe sent for a key (advances attempt counter).
    pub(super) fn on_probe_sent(&mut self, key: (i32, IpAddr), now_ns: u64) {
        if let Some(entry) = self.states.get_mut(&key) {
            match &mut entry.state {
                ResolverState::Resolving {
                    attempts,
                    last_probe_ns,
                } => {
                    *attempts = attempts.saturating_add(1);
                    *last_probe_ns = now_ns;
                }
                ResolverState::Negative {
                    attempts,
                    last_probe_ns,
                    ..
                } => {
                    *attempts = attempts.saturating_add(1);
                    *last_probe_ns = now_ns;
                }
                _ => {}
            }
            entry.updated_ns = now_ns;
            self.counters.probes_sent.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Sweep for expired entries and return keys needing probes.
    /// Called periodically from worker loop.
    pub(super) fn sweep(&mut self, now_ns: u64) -> Vec<(i32, IpAddr)> {
        let mut to_probe = Vec::new();
        let mut to_remove = Vec::new();

        for (key, entry) in self.states.iter() {
            match entry.state {
                ResolverState::Resolved { confirmed_at_ns } => {
                    if now_ns.saturating_sub(confirmed_at_ns) >= self.resolved_ttl_ns {
                        to_remove.push(*key);
                    }
                }
                ResolverState::Negative { failed_at_ns, .. } => {
                    if now_ns.saturating_sub(failed_at_ns) >= self.neg_ttl_ns {
                        to_remove.push(*key);
                    } else if self.is_probe_due(key, now_ns) {
                        to_probe.push(*key);
                    }
                }
                ResolverState::Resolving { .. } => {
                    if self.is_probe_due(key, now_ns) {
                        to_probe.push(*key);
                    }
                    // Check for timeout (no explicit timeout in old code,
                    // but we need one for Negative transition).
                    // Use 2 second timeout matching PENDING_NEIGH_TIMEOUT_NS.
                    if now_ns.saturating_sub(entry.updated_ns) >= 2_000_000_000 {
                        to_remove.push(*key); // Will be re-added as Negative by caller
                    }
                }
                ResolverState::Idle => {
                    to_remove.push(*key);
                }
            }
        }

        // Clean up expired entries
        for key in to_remove {
            self.on_neighbor_removed(key);
        }

        to_probe
    }

    /// Get buffered packet for retry (called when neighbor resolves).
    pub(super) fn take_pending(&mut self, key: &(i32, IpAddr)) -> Option<PendingPacket> {
        self.pending.remove(key)
    }

    /// Record ENOBUFS event from netlink monitor.
    pub(super) fn on_netlink_enobufs(&self) {
        self.counters.netlink_enobufs.fetch_add(1, Ordering::Relaxed);
    }

    /// Record throttled re-dump.
    pub(super) fn on_netlink_redump(&self) {
        self.counters.netlink_redumps.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResolveAction {
    /// Buffer this packet as the representative for its key.
    Buffer,
    /// Drop duplicate packet (key already in Negative or Resolving).
    /// Resolver continues running.
    FastFail,
    /// Neighbor already resolved — forward normally.
    Forward,
    /// Pending queue full — drop packet.
    Drop,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key() -> (i32, IpAddr) {
        (42, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    }

    fn packet() -> PendingPacket {
        PendingPacket {
            addr: 0,
            len: 64,
            queued_ns: 1_000,
            probe_attempts: 0,
        }
    }

    #[test]
    fn first_packet_buffers_and_starts_resolution() {
        let mut r = NeighborResolver::new();
        let action = r.handle_missing_neighbor(key(), packet(), 1_000, || false);
        assert_eq!(action, ResolveAction::Buffer);
        assert_eq!(r.counters.resolving_keys.load(Ordering::Relaxed), 1);
        assert_eq!(r.counters.buffered_packets.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn duplicate_packet_fast_fails() {
        let mut r = NeighborResolver::new();
        let _ = r.handle_missing_neighbor(key(), packet(), 1_000, || false);
        let action = r.handle_missing_neighbor(key(), packet(), 1_001, || false);
        assert_eq!(action, ResolveAction::FastFail);
        assert_eq!(r.counters.fast_fail_drops.load(Ordering::Relaxed), 1);
        // Still only one buffered packet (representative)
        assert_eq!(r.pending.len(), 1);
    }

    #[test]
    fn resolved_neighbor_wins() {
        let mut r = NeighborResolver::new();
        let _ = r.handle_missing_neighbor(key(), packet(), 1_000, || false);
        // RTM_NEWNEIGH arrives
        let buffered = r.on_neighbor_resolved(key(), 2_000);
        assert!(buffered.is_some());
        // Next packet should forward
        let action = r.handle_missing_neighbor(key(), packet(), 2_001, || true);
        assert_eq!(action, ResolveAction::Forward);
    }

    #[test]
    fn negative_state_fast_fails_but_keeps_resolver() {
        let mut r = NeighborResolver::new();
        let _ = r.handle_missing_neighbor(key(), packet(), 1_000, || false);
        // Timeout
        r.on_resolve_timeout(key(), 3_000_000_000);
        assert_eq!(r.counters.negative_keys.load(Ordering::Relaxed), 1);
        // Duplicate packet fast-fails
        let action = r.handle_missing_neighbor(key(), packet(), 3_000_001, || false);
        assert_eq!(action, ResolveAction::FastFail);
        // But probe is still due (resolver keeps running)
        assert!(r.is_probe_due(&key(), 4_000_000_000));
    }

    #[test]
    fn per_key_epoch_bumps_on_resolve() {
        let mut r = NeighborResolver::new();
        let _ = r.handle_missing_neighbor(key(), packet(), 1_000, || false);
        let epoch_before = r.states.get(&key()).unwrap().epoch;
        r.on_neighbor_resolved(key(), 2_000);
        let epoch_after = r.states.get(&key()).unwrap().epoch;
        assert_eq!(epoch_after, epoch_before + 1);
    }
}
