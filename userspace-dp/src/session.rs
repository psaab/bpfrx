use crate::afxdp::{ForwardingDisposition, ForwardingResolution};
use crate::nat::NatDecision;
use crate::nat64::Nat64ReverseInfo;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;

const SESSION_GC_INTERVAL_NS: u64 = 1_000_000_000;
const DEFAULT_MAX_SESSIONS: usize = 131072;
const DEFAULT_TCP_SESSION_TIMEOUT_NS: u64 = 300_000_000_000;
const TCP_CLOSING_TIMEOUT_NS: u64 = 30_000_000_000;
const DEFAULT_UDP_SESSION_TIMEOUT_NS: u64 = 60_000_000_000;
const DEFAULT_ICMP_SESSION_TIMEOUT_NS: u64 = 60_000_000_000;
const OTHER_SESSION_TIMEOUT_NS: u64 = 30_000_000_000;

// #965: bucketed timer-wheel session GC.
// 256 buckets x 1-second ticks = 256-second window. Long-timeout
// sessions (> 256 s) re-bucket via the FAR_FUTURE_OFFSET path on
// pop; see plan docs/pr/965-session-gc-timer-wheel/plan.md.
const WHEEL_BUCKETS: usize = 256;
const WHEEL_MASK: u64 = (WHEEL_BUCKETS as u64) - 1;
const WHEEL_TICK_NS: u64 = 1_000_000_000;
const FAR_FUTURE_OFFSET: u64 = (WHEEL_BUCKETS as u64) - 1;

#[inline]
fn bucket_for_tick(tick: u64) -> usize {
    (tick & WHEEL_MASK) as usize
}

/// Compute the absolute wheel tick at which an entry expiring at
/// `expiration_ns` should be checked, given the current `now_ns`.
/// Floors the expiration to a tick boundary; entries past their
/// expiration land in the current tick (delta=0), entries in the
/// far future are clamped to FAR_FUTURE_OFFSET ticks ahead and get
/// re-checked there (still-alive case triggers re-bucketing in pop).
#[inline]
fn target_tick_for(now_ns: u64, expiration_ns: u64) -> u64 {
    let now_tick = now_ns / WHEEL_TICK_NS;
    let expiration_tick = expiration_ns / WHEEL_TICK_NS;
    let delta = expiration_tick.saturating_sub(now_tick);
    now_tick + delta.min(FAR_FUTURE_OFFSET)
}

#[derive(Clone, Debug)]
struct WheelEntry {
    key: SessionKey,
    scheduled_tick: u64,
}

struct SessionWheel {
    buckets: Box<[VecDeque<WheelEntry>]>,
    base_tick: u64,
    cursor_tick: u64,
    initialized: bool,
}

impl SessionWheel {
    fn new() -> Self {
        let mut buckets: Vec<VecDeque<WheelEntry>> = Vec::with_capacity(WHEEL_BUCKETS);
        for _ in 0..WHEEL_BUCKETS {
            buckets.push(VecDeque::new());
        }
        Self {
            buckets: buckets.into_boxed_slice(),
            base_tick: 0,
            cursor_tick: 0,
            initialized: false,
        }
    }
}

/// Per-call statistics for `expire_stale_entries` pop work, used by
/// the timer-wheel unit tests to assert K-bounds and entry
/// classification under specific synthetic workloads. Fields are
/// accumulated over all buckets popped in a single call.
#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct WheelPopStats {
    /// Total `WheelEntry`s scanned (popped from a bucket and
    /// classified) during the call.
    pub(crate) scanned: usize,
    /// Entries dropped because the canonical key is no longer in
    /// `sessions` (already removed by another path).
    pub(crate) dropped_gone: usize,
    /// Entries dropped because `wheel_tick != scheduled_tick` (a
    /// fresher entry has superseded this one).
    pub(crate) dropped_stale: usize,
    /// Entries that actually expired and were removed.
    pub(crate) expired: usize,
    /// Entries that were re-bucketed (long-timeout / not yet
    /// expired).
    pub(crate) re_bucketed: usize,
}

/// Configurable session timeout values (in nanoseconds).
#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionTimeouts {
    pub(crate) tcp_established_ns: u64,
    pub(crate) udp_ns: u64,
    pub(crate) icmp_ns: u64,
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            tcp_established_ns: DEFAULT_TCP_SESSION_TIMEOUT_NS,
            udp_ns: DEFAULT_UDP_SESSION_TIMEOUT_NS,
            icmp_ns: DEFAULT_ICMP_SESSION_TIMEOUT_NS,
        }
    }
}

impl SessionTimeouts {
    /// Build from snapshot timeout values (in seconds). A value of 0 means use
    /// the default.
    pub(crate) fn from_seconds(tcp_secs: u64, udp_secs: u64, icmp_secs: u64) -> Self {
        Self {
            tcp_established_ns: if tcp_secs > 0 {
                tcp_secs * 1_000_000_000
            } else {
                DEFAULT_TCP_SESSION_TIMEOUT_NS
            },
            udp_ns: if udp_secs > 0 {
                udp_secs * 1_000_000_000
            } else {
                DEFAULT_UDP_SESSION_TIMEOUT_NS
            },
            icmp_ns: if icmp_secs > 0 {
                icmp_secs * 1_000_000_000
            } else {
                DEFAULT_ICMP_SESSION_TIMEOUT_NS
            },
        }
    }
}
const MAX_SESSION_DELTAS: usize = 4096;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;
const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

#[allow(unused_macros)]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-log")]
        eprintln!($($arg)*);
    };
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct SessionKey {
    pub addr_family: u8,
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Clone, Debug)]
struct SessionEntry {
    decision: SessionDecision,
    metadata: SessionMetadata,
    origin: SessionOrigin,
    install_epoch: u64,
    last_seen_ns: u64,
    expires_after_ns: u64,
    closing: bool,
    /// #965: absolute wheel tick at which this session is scheduled to
    /// be checked for expiration. Updated on every push to the wheel.
    /// A WheelEntry whose `scheduled_tick != entry.wheel_tick` is a
    /// stale duplicate (lazy-delete discriminator).
    wheel_tick: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionDecision {
    pub(crate) resolution: ForwardingResolution,
    pub(crate) nat: NatDecision,
}

/// #919: zone names dropped from the fast path. `ingress_zone` and
/// `egress_zone` are now `u16` IDs that index into
/// `forwarding.zone_id_to_name` for slow-path consumers (logging,
/// gRPC export, status). `0` means "unknown / unset" (matches the
/// existing `UserspaceDpMeta.ingress_zone` default at types.rs:64).
/// Removing the `Arc<str>` saves 28 bytes per `SessionMetadata` and
/// eliminates the `LOCK XADD` atomic on every `metadata.clone()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionMetadata {
    pub(crate) ingress_zone: u16,
    pub(crate) egress_zone: u16,
    pub(crate) owner_rg_id: i32,
    pub(crate) fabric_ingress: bool,
    pub(crate) is_reverse: bool,
    /// For NAT64 sessions: stores original IPv6 addresses so reverse IPv4
    /// replies can be translated back.
    pub(crate) nat64_reverse: Option<Nat64ReverseInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionLookup {
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForwardSessionMatch {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionOrigin {
    ForwardFlow,
    ReverseFlow,
    LocalMiss,
    MissingNeighborSeed,
    SyncImport,
    SharedMaterialize,
    SharedPromote,
    #[allow(dead_code)] // enum variant for completeness
    WorkerLocalImport,
}

impl SessionOrigin {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ForwardFlow => "forward_flow",
            Self::ReverseFlow => "reverse_flow",
            Self::LocalMiss => "local_miss",
            Self::MissingNeighborSeed => "missing_neighbor_seed",
            Self::SyncImport => "sync_import",
            Self::SharedMaterialize => "shared_materialize",
            Self::SharedPromote => "shared_promote",
            Self::WorkerLocalImport => "worker_local_import",
        }
    }

    /// Returns true for origins that represent peer-synced sessions.
    /// These are sessions that arrived from the HA peer rather than
    /// being created by local traffic.
    pub(crate) fn is_peer_synced(self) -> bool {
        matches!(
            self,
            Self::SyncImport | Self::SharedMaterialize | Self::WorkerLocalImport
        )
    }

    pub(crate) fn is_promotable_synced(self) -> bool {
        matches!(self, Self::SyncImport | Self::SharedMaterialize)
    }

    pub(crate) fn worker_replica_origin(self) -> Self {
        if self.is_promotable_synced() {
            Self::SyncImport
        } else {
            Self::WorkerLocalImport
        }
    }

    pub(crate) fn materialized_shared_hit_origin(self) -> Self {
        if self.is_promotable_synced() {
            Self::SharedMaterialize
        } else {
            Self::WorkerLocalImport
        }
    }

    pub(crate) fn is_transient_local_seed(self) -> bool {
        matches!(self, Self::MissingNeighborSeed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionDeltaKind {
    Open,
    Close,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionDelta {
    pub(crate) kind: SessionDeltaKind,
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) fabric_redirect_sync: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExpiredSession {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
}

pub(crate) struct SessionTable {
    sessions: FxHashMap<SessionKey, SessionEntry>,
    nat_reverse_index: FxHashMap<SessionKey, SessionKey>,
    forward_wire_index: FxHashMap<SessionKey, SessionKey>,
    reverse_translated_index: FxHashMap<SessionKey, SessionKey>,
    owner_rg_sessions: FxHashMap<i32, FxHashSet<SessionKey>>,
    deltas: VecDeque<SessionDelta>,
    last_gc_ns: u64,
    max_sessions: usize,
    timeouts: SessionTimeouts,
    epoch_counter: u64,
    expired: u64,
    create_drops: u64,
    delta_drops: u64,
    delta_drained: u64,
    /// #965: bucketed timer wheel that mirrors `sessions`. Pop one
    /// bucket per tick (1 s) instead of scanning the whole HashMap.
    wheel: SessionWheel,
    /// #965: stats from the most-recent `expire_stale_entries` call.
    /// Reset at the start of each call. Used by unit tests to assert
    /// K-bounds and classification (scanned / dropped_stale /
    /// dropped_gone / expired / re_bucketed). Accumulator overhead
    /// is 4-5 increments per popped entry — sub-µs at typical loads.
    last_pop_stats: WheelPopStats,
}

impl SessionTable {
    pub fn new() -> Self {
        Self {
            sessions: FxHashMap::default(),
            nat_reverse_index: FxHashMap::default(),
            forward_wire_index: FxHashMap::default(),
            reverse_translated_index: FxHashMap::default(),
            owner_rg_sessions: FxHashMap::default(),
            deltas: VecDeque::with_capacity(MAX_SESSION_DELTAS.min(256)),
            last_gc_ns: 0,
            max_sessions: DEFAULT_MAX_SESSIONS,
            timeouts: SessionTimeouts::default(),
            epoch_counter: 0,
            expired: 0,
            create_drops: 0,
            delta_drops: 0,
            delta_drained: 0,
            wheel: SessionWheel::new(),
            last_pop_stats: WheelPopStats::default(),
        }
    }

    /// #965: stats from the most-recent `expire_stale_entries` call.
    /// Used by tests to validate K-bounds and entry classification.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn last_pop_stats(&self) -> WheelPopStats {
        self.last_pop_stats
    }

    /// #965: lazily initialize the wheel cursor to the first observed
    /// `now_ns`. SessionTable::new() does not have a `now_ns`, so we
    /// must initialize on the first call to any method that takes one.
    /// Without this, `now_tick = now_ns / TICK_NS` can be billions
    /// (monotonic time) and the pop loop would walk billions of empty
    /// buckets on the first GC.
    #[inline]
    fn wheel_observe(&mut self, now_ns: u64) {
        if !self.wheel.initialized {
            let now_tick = now_ns / WHEEL_TICK_NS;
            self.wheel.base_tick = now_tick;
            self.wheel.cursor_tick = now_tick;
            self.wheel.initialized = true;
        }
    }

    /// #965: schedule (or re-schedule) `key` for an expiration check
    /// at the tick implied by its `last_seen_ns + expires_after_ns`.
    /// Throttled: only pushes when the canonical wheel tick changes,
    /// so per-second touches within the same tick produce zero new
    /// wheel entries.
    ///
    /// MUST be called only AFTER `last_seen_ns` / `expires_after_ns`
    /// have been written and the &mut borrow on `self.sessions` has
    /// dropped — otherwise the borrow checker will reject the
    /// `self.wheel.buckets[bucket].push_back(...)` line because it
    /// aliases `self` through both `self.sessions` and `self.wheel`.
    #[inline]
    fn push_to_wheel(&mut self, key: &SessionKey, now_ns: u64) {
        self.wheel_observe(now_ns);
        let new_tick = match self.sessions.get_mut(key) {
            Some(entry) => {
                let nt = target_tick_for(
                    now_ns,
                    entry.last_seen_ns.saturating_add(entry.expires_after_ns),
                );
                if nt != entry.wheel_tick {
                    entry.wheel_tick = nt;
                    Some(nt)
                } else {
                    None
                }
            }
            None => return,
        };
        if let Some(tick) = new_tick {
            let bucket = bucket_for_tick(tick);
            self.wheel.buckets[bucket].push_back(WheelEntry {
                key: key.clone(),
                scheduled_tick: tick,
            });
        }
    }

    fn next_epoch(&mut self) -> u64 {
        self.epoch_counter += 1;
        self.epoch_counter
    }

    /// Update the configurable session timeouts.
    pub fn set_timeouts(&mut self, timeouts: SessionTimeouts) {
        self.timeouts = timeouts;
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Update the last-seen timestamp for a session (prevents GC expiry).
    /// Used by the flow cache to amortize session keepalive.
    #[inline]
    pub fn touch(&mut self, key: &SessionKey, now_ns: u64) {
        if self.sessions.get_mut(key).is_some_and(|e| {
            e.last_seen_ns = now_ns;
            true
        }) {
            self.push_to_wheel(key, now_ns);
        }
    }

    /// #965: GC pass over the timer wheel.
    ///
    /// Replaces the prior O(N) scan over `self.sessions` with a wheel
    /// pop. For each tick that has elapsed since the last call (up to
    /// `now_ns / WHEEL_TICK_NS`), drain the bucket at the current
    /// cursor and process its entries via the lazy-delete discriminator:
    ///
    ///   1. Entry gone (HashMap miss) → drop.
    ///   2. Stale duplicate (`wheel_tick != scheduled_tick`) → drop.
    ///   3. Expired (`now > last_seen + expires_after`) → remove,
    ///      emit delta + ExpiredSession.
    ///   4. Still alive → re-bucket at the new absolute target tick.
    ///
    /// See docs/pr/965-session-gc-timer-wheel/plan.md for the full
    /// algorithm and complexity analysis.
    pub fn expire_stale_entries(&mut self, now_ns: u64) -> Vec<ExpiredSession> {
        // Reset per-call stats BEFORE the gc-interval gate so that a
        // gated no-op call returns zeroed stats rather than leftovers
        // from a prior call (Codex impl-review round-2 non-blocking note).
        self.last_pop_stats = WheelPopStats::default();
        if self.last_gc_ns != 0 && now_ns.saturating_sub(self.last_gc_ns) < SESSION_GC_INTERVAL_NS {
            return Vec::new();
        }
        self.last_gc_ns = now_ns;
        self.wheel_observe(now_ns);
        let now_tick = now_ns / WHEEL_TICK_NS;
        let mut expired_entries: Vec<ExpiredSession> = Vec::new();
        while self.wheel.cursor_tick < now_tick {
            let bucket_idx = bucket_for_tick(self.wheel.cursor_tick);
            // Drain the bucket allocation-free: snapshot the length
            // before iterating, then `pop_front` exactly that many
            // times. Re-pushes targeting THIS bucket land at the back
            // of the VecDeque and are not popped during this BUCKET
            // drain (re-pushes into LATER buckets the outer loop
            // visits will be popped within the same call — by design).
            let due_count = self.wheel.buckets[bucket_idx].len();
            for _ in 0..due_count {
                let WheelEntry { key, scheduled_tick } = self.wheel.buckets[bucket_idx]
                    .pop_front()
                    .expect("len snapshot bounds the iteration");
                self.last_pop_stats.scanned += 1;
                // Case 1: entry already removed elsewhere — drop hint.
                let Some(entry) = self.sessions.get(&key) else {
                    self.last_pop_stats.dropped_gone += 1;
                    continue;
                };
                // Case 2: stale duplicate — entry's canonical wheel_tick
                // has advanced past this scheduled_tick, so the new tick
                // already has its own wheel entry. Drop.
                if entry.wheel_tick != scheduled_tick {
                    self.last_pop_stats.dropped_stale += 1;
                    continue;
                }
                // Case 3 vs 4: canonical entry. Match today's strict `>`
                // expiration semantics.
                if now_ns.saturating_sub(entry.last_seen_ns) > entry.expires_after_ns {
                    if let Some(removed) = self.remove_entry(&key) {
                        self.last_pop_stats.expired += 1;
                        let decision = removed.decision;
                        let metadata = removed.metadata;
                        if key.protocol == PROTO_TCP {
                            debug_log!(
                                "SESS_EXPIRE: proto=TCP {}:{} -> {}:{} closing={} age_ns={} timeout_ns={} rev={} origin={} nat=({:?},{:?})",
                                key.src_ip,
                                key.src_port,
                                key.dst_ip,
                                key.dst_port,
                                removed.closing,
                                now_ns.saturating_sub(removed.last_seen_ns),
                                removed.expires_after_ns,
                                metadata.is_reverse,
                                removed.origin.as_str(),
                                decision.nat.rewrite_src,
                                decision.nat.rewrite_dst,
                            );
                        }
                        if !metadata.is_reverse
                            && !removed.origin.is_peer_synced()
                            && !removed.origin.is_transient_local_seed()
                        {
                            self.push_delta(SessionDelta {
                                kind: SessionDeltaKind::Close,
                                key: key.clone(),
                                decision,
                                metadata: metadata.clone(),
                                origin: removed.origin,
                                fabric_redirect_sync: false,
                            });
                        }
                        expired_entries.push(ExpiredSession {
                            key,
                            decision,
                            metadata,
                            origin: removed.origin,
                        });
                    }
                } else {
                    // Case 4: still alive — long-timeout (>= 256s) case
                    // or a session re-scheduled to exactly this tick.
                    // Re-bucket at the new absolute target tick.
                    let new_target_tick = target_tick_for(
                        now_ns,
                        entry.last_seen_ns.saturating_add(entry.expires_after_ns),
                    );
                    let new_bucket = bucket_for_tick(new_target_tick);
                    if let Some(entry_mut) = self.sessions.get_mut(&key) {
                        entry_mut.wheel_tick = new_target_tick;
                    }
                    self.wheel.buckets[new_bucket].push_back(WheelEntry {
                        key,
                        scheduled_tick: new_target_tick,
                    });
                    self.last_pop_stats.re_bucketed += 1;
                }
            }
            self.wheel.cursor_tick = self.wheel.cursor_tick.saturating_add(1);
        }
        self.wheel.base_tick = now_tick;
        let expired = expired_entries.len() as u64;
        self.expired = self.expired.saturating_add(expired);
        expired_entries
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn expire_stale(&mut self, now_ns: u64) -> u64 {
        self.expire_stale_entries(now_ns).len() as u64
    }

    pub fn lookup(
        &mut self,
        key: &SessionKey,
        now_ns: u64,
        tcp_flags: u8,
    ) -> Option<SessionLookup> {
        self.lookup_with_origin(key, now_ns, tcp_flags)
            .map(|(lookup, _origin)| lookup)
    }

    pub fn lookup_with_origin(
        &mut self,
        key: &SessionKey,
        now_ns: u64,
        tcp_flags: u8,
    ) -> Option<(SessionLookup, SessionOrigin)> {
        let actual_key = if self.sessions.contains_key(key) {
            key.clone()
        } else if let Some(alias) = self.reverse_translated_index.get(key) {
            alias.clone()
        } else {
            return None;
        };
        // Pre-compute the timeout before borrowing &mut self.sessions
        // so the inner block doesn't need to access self.timeouts.
        let timeouts = self.timeouts;
        // Scope the &mut self.sessions borrow so it ends BEFORE we
        // touch self.wheel via push_to_wheel. Without this scoping
        // the closure form `self.sessions.get_mut(...).map(|entry| { ... })`
        // would hold &mut self via self.sessions and conflict with
        // a second &mut self via self.wheel.
        let result = {
            let entry = self.sessions.get_mut(&actual_key)?;
            if matches!(key.protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0 {
                if !entry.closing {
                    debug_log!(
                        "SESS_CLOSING: {} proto=TCP {}:{} -> {}:{} rev={} tcp_flags=0x{:02x}",
                        if (tcp_flags & TCP_RST) != 0 {
                            "RST"
                        } else {
                            "FIN"
                        },
                        key.src_ip,
                        key.src_port,
                        key.dst_ip,
                        key.dst_port,
                        entry.metadata.is_reverse,
                        tcp_flags,
                    );
                }
                entry.closing = true;
            }
            entry.last_seen_ns = now_ns;
            entry.expires_after_ns = if matches!(key.protocol, PROTO_TCP) && entry.closing {
                TCP_CLOSING_TIMEOUT_NS
            } else {
                session_timeout_ns(key.protocol, tcp_flags, &timeouts)
            };
            (
                SessionLookup {
                    decision: entry.decision,
                    metadata: entry.metadata.clone(),
                },
                entry.origin,
            )
        }; // <-- &mut self.sessions borrow ends here
        // Push the canonical key (NOT the alias `key`) into the wheel.
        // push_to_wheel re-reads the entry to compute the throttled
        // target_tick, so a second HashMap lookup is needed; that
        // matches the model in the plan (~100 ns per FxHashMap lookup
        // on the hot path).
        self.push_to_wheel(&actual_key, now_ns);
        Some(result)
    }

    pub fn find_forward_nat_match(&self, reply_key: &SessionKey) -> Option<ForwardSessionMatch> {
        let forward_key = self.nat_reverse_index.get(reply_key)?;
        let entry = self.sessions.get(forward_key)?;
        if entry.metadata.is_reverse
            || !reply_matches_forward_session(forward_key, entry.decision.nat, reply_key)
        {
            return None;
        }
        Some(ForwardSessionMatch {
            key: forward_key.clone(),
            decision: entry.decision,
            metadata: entry.metadata.clone(),
        })
    }

    pub fn find_forward_wire_match(&self, wire_key: &SessionKey) -> Option<ForwardSessionMatch> {
        self.find_forward_wire_match_with_origin(wire_key)
            .map(|(matched, _origin)| matched)
    }

    pub fn find_forward_wire_match_with_origin(
        &self,
        wire_key: &SessionKey,
    ) -> Option<(ForwardSessionMatch, SessionOrigin)> {
        let forward_key = self.forward_wire_index.get(wire_key)?;
        let entry = self.sessions.get(forward_key)?;
        if entry.metadata.is_reverse
            || forward_wire_key(forward_key, entry.decision.nat) != *wire_key
        {
            return None;
        }
        Some((
            ForwardSessionMatch {
                key: forward_key.clone(),
                decision: entry.decision,
                metadata: entry.metadata.clone(),
            },
            entry.origin,
        ))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn install_with_protocol(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
    ) -> bool {
        self.install_with_protocol_with_origin(
            key,
            decision,
            metadata,
            SessionOrigin::ForwardFlow,
            now_ns,
            protocol,
            tcp_flags,
        )
    }

    pub fn install_with_protocol_with_origin(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
    ) -> bool {
        if self.sessions.len() >= self.max_sessions {
            self.create_drops = self.create_drops.saturating_add(1);
            return false;
        }
        self.remove_entry(&key);
        let epoch = self.next_epoch();
        self.sessions.insert(
            key.clone(),
            SessionEntry {
                decision,
                metadata: metadata.clone(),
                origin,
                install_epoch: epoch,
                last_seen_ns: now_ns,
                expires_after_ns: session_timeout_ns(protocol, tcp_flags, &self.timeouts),
                closing: matches!(protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0,
                wheel_tick: 0,
            },
        );
        self.index_forward_nat_key(&key, decision, &metadata);
        // #965: schedule the new entry for expiration check.
        self.push_to_wheel(&key, now_ns);
        if !metadata.is_reverse && !origin.is_peer_synced() && !origin.is_transient_local_seed() {
            self.push_delta(SessionDelta {
                kind: SessionDeltaKind::Open,
                key,
                decision,
                metadata,
                origin,
                fabric_redirect_sync: false,
            });
        }
        true
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn upsert_synced(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
        allow_replace_local: bool,
    ) -> bool {
        self.upsert_synced_with_origin(
            key,
            decision,
            metadata,
            SessionOrigin::SyncImport,
            now_ns,
            protocol,
            tcp_flags,
            allow_replace_local,
        )
    }

    pub fn upsert_synced_with_origin(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
        allow_replace_local: bool,
    ) -> bool {
        // Reject peer data that would clobber a locally-owned session
        // unless explicitly allowed (e.g. during HA activation).
        if matches!(self.sessions.get(&key), Some(existing) if !existing.origin.is_peer_synced())
            && !allow_replace_local
        {
            return false;
        }
        self.remove_entry(&key);
        let epoch = self.next_epoch();
        let index_key = key.clone();
        self.sessions.insert(
            key,
            SessionEntry {
                decision,
                metadata: metadata.clone(),
                origin,
                install_epoch: epoch,
                last_seen_ns: now_ns,
                expires_after_ns: session_timeout_ns(protocol, tcp_flags, &self.timeouts),
                closing: matches!(protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0,
                wheel_tick: 0,
            },
        );
        self.index_forward_nat_key(&index_key, decision, &metadata);
        // #965: schedule the synced entry for expiration check.
        self.push_to_wheel(&index_key, now_ns);
        true
    }

    /// Unified session update function replacing promote_synced,
    /// refresh_local, and refresh_for_ha_activation.
    ///
    /// Collision rules:
    /// - `ha_activation=true`: always updates (highest priority, used by
    ///   RefreshOwnerRGs to re-resolve all sessions with local state)
    /// - Peer-synced entries (origin.is_peer_synced()): local traffic can
    ///   promote them (sets new origin + emits delta)
    /// - Local entries (!origin.is_peer_synced()): rejects older peer data
    pub fn update_session(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
        ha_activation: bool,
    ) -> bool {
        let Some(mut entry) = self.remove_entry(key) else {
            return false;
        };
        if !ha_activation {
            if entry.origin.is_peer_synced() && !origin.is_peer_synced() {
                // Peer-synced entry being promoted by local traffic — allow
            } else if entry.origin.is_peer_synced() && origin.is_peer_synced() {
                // Both peer-synced: reject (refresh_local on synced entry)
                self.restore_entry(key.clone(), entry);
                return false;
            } else if !entry.origin.is_peer_synced() && origin.is_peer_synced() {
                // Local entry: reject peer data trying to overwrite
                self.restore_entry(key.clone(), entry);
                return false;
            }
            // Both local: allow (local refresh of local entry)
        }
        let was_peer_synced = entry.origin.is_peer_synced();
        entry.decision = decision;
        entry.metadata = metadata.clone();
        entry.origin = origin;
        entry.install_epoch = self.next_epoch();
        entry.last_seen_ns = now_ns;
        entry.expires_after_ns = session_timeout_ns(protocol, tcp_flags, &self.timeouts);
        entry.closing = matches!(protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0;
        self.restore_entry(key.clone(), entry);
        // #965: schedule the refreshed entry. Last_seen / expires_after
        // were rewritten above; push_to_wheel is throttled and will only
        // emit a new wheel entry if the canonical tick changed.
        self.push_to_wheel(key, now_ns);
        // Emit open delta when promoting a peer-synced entry to local
        if was_peer_synced && !origin.is_peer_synced() && !metadata.is_reverse {
            self.push_delta(SessionDelta {
                kind: SessionDeltaKind::Open,
                key: key.clone(),
                decision,
                metadata,
                origin,
                fabric_redirect_sync: false,
            });
        }
        true
    }

    /// Thin wrapper for local-only refresh (non-HA-activation path).
    /// Keeps the existing origin; skips peer-synced entries.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn refresh_local(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        tcp_flags: u8,
    ) -> bool {
        let origin = self
            .sessions
            .get(key)
            .map(|e| e.origin)
            .unwrap_or(SessionOrigin::ForwardFlow);
        self.update_session(
            key,
            decision,
            metadata,
            origin,
            now_ns,
            key.protocol,
            tcp_flags,
            false,
        )
    }

    /// Convenience: refresh for HA activation (always updates regardless
    /// of origin). Preserves existing origin.
    pub fn refresh_for_ha_activation(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        tcp_flags: u8,
    ) -> bool {
        let origin = self
            .sessions
            .get(key)
            .map(|e| e.origin)
            .unwrap_or(SessionOrigin::ForwardFlow);
        self.update_session(
            key,
            decision,
            metadata,
            origin,
            now_ns,
            key.protocol,
            tcp_flags,
            true,
        )
    }

    /// Refresh an existing session for an HA path transition while
    /// preserving its origin and current liveness state.
    pub fn refresh_for_ha_transition(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
    ) -> bool {
        let Some(mut entry) = self.remove_entry(key) else {
            return false;
        };
        entry.decision = decision;
        entry.metadata = metadata;
        entry.install_epoch = self.next_epoch();
        entry.last_seen_ns = now_ns;
        self.restore_entry(key.clone(), entry);
        // #965: schedule the refreshed entry for expiration check.
        self.push_to_wheel(key, now_ns);
        true
    }

    /// Promote a peer-synced session to local ownership.
    /// Convenience wrapper around update_session.
    pub fn promote_synced_with_origin(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
    ) -> bool {
        self.update_session(
            key, decision, metadata, origin, now_ns, protocol, tcp_flags, false,
        )
    }

    pub fn emit_open_delta_with_origin(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        fabric_redirect_sync: bool,
    ) {
        if metadata.is_reverse {
            return;
        }
        self.push_delta(SessionDelta {
            kind: SessionDeltaKind::Open,
            key,
            decision,
            metadata,
            origin,
            fabric_redirect_sync,
        });
    }

    pub fn delete(&mut self, key: &SessionKey) {
        self.remove_entry(key);
    }

    pub fn entry_with_origin(
        &self,
        key: &SessionKey,
    ) -> Option<(SessionDecision, SessionMetadata, SessionOrigin)> {
        self.sessions
            .get(key)
            .map(|entry| (entry.decision, entry.metadata.clone(), entry.origin))
    }

    pub fn owner_rg_session_keys(&self, owner_rgs: &[i32]) -> Vec<SessionKey> {
        owner_rg_session_keys_from_index(&self.owner_rg_sessions, owner_rgs)
    }

    pub fn take_synced_local(&mut self, key: &SessionKey) -> Option<SessionLookup> {
        let Some(entry) = self.sessions.get(key) else {
            return None;
        };
        if !entry.origin.is_peer_synced()
            || entry.metadata.is_reverse
            || entry.decision.resolution.disposition != ForwardingDisposition::LocalDelivery
        {
            return None;
        }
        self.remove_entry(key).map(|entry| SessionLookup {
            decision: entry.decision,
            metadata: entry.metadata,
        })
    }

    pub fn demote_owner_rg(&mut self, owner_rg_id: i32) -> Vec<crate::session::SessionKey> {
        if owner_rg_id <= 0 {
            return Vec::new();
        }
        let mut demoted_keys = Vec::new();
        for key in self.owner_rg_session_keys(&[owner_rg_id]) {
            let Some(entry) = self.sessions.get_mut(&key) else {
                continue;
            };
            if !entry.origin.is_peer_synced() {
                entry.origin = SessionOrigin::SyncImport;
            }
            demoted_keys.push(key);
        }
        demoted_keys
    }

    pub fn drain_deltas(&mut self, max: usize) -> Vec<SessionDelta> {
        let drain = max.max(1).min(self.deltas.len());
        let mut out = Vec::with_capacity(drain);
        for _ in 0..drain {
            if let Some(delta) = self.deltas.pop_front() {
                out.push(delta);
            }
        }
        self.delta_drained = self.delta_drained.saturating_add(out.len() as u64);
        out
    }

    pub fn has_pending_deltas(&self) -> bool {
        !self.deltas.is_empty()
    }

    pub fn iter_with_origin(
        &self,
        mut f: impl FnMut(&SessionKey, SessionDecision, &SessionMetadata, SessionOrigin),
    ) {
        for (key, entry) in &self.sessions {
            f(key, entry.decision, &entry.metadata, entry.origin);
        }
    }

    /// Iterate over all session entries with idle time (in nanoseconds).
    pub fn iter_with_idle(
        &self,
        now_ns: u64,
        mut f: impl FnMut(&SessionKey, SessionDecision, &SessionMetadata, u64),
    ) {
        self.iter_with_idle_and_origin(now_ns, |key, decision, metadata, _origin, idle_ns| {
            f(key, decision, metadata, idle_ns)
        });
    }

    pub fn iter_with_idle_and_origin(
        &self,
        now_ns: u64,
        mut f: impl FnMut(&SessionKey, SessionDecision, &SessionMetadata, SessionOrigin, u64),
    ) {
        for (key, entry) in &self.sessions {
            let idle_ns = now_ns.saturating_sub(entry.last_seen_ns);
            f(key, entry.decision, &entry.metadata, entry.origin, idle_ns);
        }
    }

    fn push_delta(&mut self, delta: SessionDelta) {
        if self.deltas.len() >= MAX_SESSION_DELTAS {
            self.delta_drops = self.delta_drops.saturating_add(1);
            return;
        }
        self.deltas.push_back(delta);
    }

    fn remove_entry(&mut self, key: &SessionKey) -> Option<SessionEntry> {
        let entry = self.sessions.remove(key)?;
        self.remove_forward_nat_index(key, entry.decision, &entry.metadata);
        remove_owner_rg_index_entry(&mut self.owner_rg_sessions, entry.metadata.owner_rg_id, key);
        Some(entry)
    }

    fn restore_entry(&mut self, key: SessionKey, entry: SessionEntry) -> Option<SessionEntry> {
        self.index_forward_nat_key(&key, entry.decision, &entry.metadata);
        self.sessions.insert(key, entry)
    }

    fn index_forward_nat_key(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: &SessionMetadata,
    ) {
        if metadata.is_reverse {
            let translated = translated_session_key(key, decision.nat);
            if translated != *key {
                self.reverse_translated_index
                    .insert(translated, key.clone());
            }
        } else {
            self.nat_reverse_index
                .insert(reverse_wire_key(key, decision.nat), key.clone());
            let reverse_canonical = reverse_canonical_key(key, decision.nat);
            if reverse_canonical != *key {
                self.nat_reverse_index
                    .insert(reverse_canonical, key.clone());
            }
            let forward_wire = forward_wire_key(key, decision.nat);
            if forward_wire != *key {
                self.forward_wire_index.insert(forward_wire, key.clone());
            }
        }
        if metadata.owner_rg_id > 0 {
            self.owner_rg_sessions
                .entry(metadata.owner_rg_id)
                .or_default()
                .insert(key.clone());
        }
    }

    fn remove_forward_nat_index(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: &SessionMetadata,
    ) {
        if metadata.is_reverse {
            let translated = translated_session_key(key, decision.nat);
            if matches!(
                self.reverse_translated_index.get(&translated),
                Some(existing) if existing == key
            ) {
                self.reverse_translated_index.remove(&translated);
            }
            return;
        }
        let reverse_wire = reverse_wire_key(key, decision.nat);
        if matches!(self.nat_reverse_index.get(&reverse_wire), Some(existing) if existing == key) {
            self.nat_reverse_index.remove(&reverse_wire);
        }
        let reverse_canonical = reverse_canonical_key(key, decision.nat);
        if matches!(self.nat_reverse_index.get(&reverse_canonical), Some(existing) if existing == key)
        {
            self.nat_reverse_index.remove(&reverse_canonical);
        }
        let forward_wire = forward_wire_key(key, decision.nat);
        if matches!(self.forward_wire_index.get(&forward_wire), Some(existing) if existing == key) {
            self.forward_wire_index.remove(&forward_wire);
        }
    }
}

fn owner_rg_session_keys_from_index(
    index: &FxHashMap<i32, FxHashSet<SessionKey>>,
    owner_rgs: &[i32],
) -> Vec<SessionKey> {
    let mut keys = FxHashSet::default();
    for owner_rg_id in owner_rgs {
        if let Some(entries) = index.get(owner_rg_id) {
            keys.extend(entries.iter().cloned());
        }
    }
    keys.into_iter().collect()
}

fn remove_owner_rg_index_entry(
    index: &mut FxHashMap<i32, FxHashSet<SessionKey>>,
    owner_rg_id: i32,
    key: &SessionKey,
) {
    if owner_rg_id <= 0 {
        return;
    }
    if let Some(entries) = index.get_mut(&owner_rg_id) {
        entries.remove(key);
        if entries.is_empty() {
            index.remove(&owner_rg_id);
        }
    }
}

fn session_timeout_ns(protocol: u8, tcp_flags: u8, timeouts: &SessionTimeouts) -> u64 {
    match protocol {
        PROTO_TCP => {
            if (tcp_flags & (TCP_FIN | TCP_RST)) != 0 {
                TCP_CLOSING_TIMEOUT_NS
            } else {
                timeouts.tcp_established_ns
            }
        }
        PROTO_UDP => timeouts.udp_ns,
        PROTO_ICMP | PROTO_ICMPV6 => timeouts.icmp_ns,
        _ => OTHER_SESSION_TIMEOUT_NS,
    }
}

pub(crate) fn reply_matches_forward_session(
    forward_key: &SessionKey,
    nat: NatDecision,
    reply_key: &SessionKey,
) -> bool {
    reverse_wire_key(forward_key, nat) == *reply_key
        || reverse_canonical_key(forward_key, nat) == *reply_key
}

pub(crate) fn forward_wire_key(forward_key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(forward_key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (forward_key.src_port, forward_key.dst_port)
    } else {
        (
            nat.rewrite_src_port.unwrap_or(forward_key.src_port),
            nat.rewrite_dst_port.unwrap_or(forward_key.dst_port),
        )
    };
    let wire_src = nat.rewrite_src.unwrap_or(forward_key.src_ip);
    let wire_dst = nat.rewrite_dst.unwrap_or(forward_key.dst_ip);
    let (addr_family, protocol) = if nat.nat64 {
        let af = match wire_src {
            std::net::IpAddr::V4(_) => libc::AF_INET as u8,
            std::net::IpAddr::V6(_) => libc::AF_INET6 as u8,
        };
        let proto = if af == libc::AF_INET as u8 && forward_key.protocol == PROTO_ICMPV6 {
            PROTO_ICMP
        } else if af == libc::AF_INET6 as u8 && forward_key.protocol == PROTO_ICMP {
            PROTO_ICMPV6
        } else {
            forward_key.protocol
        };
        (af, proto)
    } else {
        (forward_key.addr_family, forward_key.protocol)
    };
    SessionKey {
        addr_family,
        protocol,
        src_ip: wire_src,
        dst_ip: wire_dst,
        src_port,
        dst_port,
    }
}

pub(crate) fn translated_session_key(key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (key.src_port, key.dst_port)
    } else {
        (
            nat.rewrite_src_port.unwrap_or(key.src_port),
            nat.rewrite_dst_port.unwrap_or(key.dst_port),
        )
    };
    SessionKey {
        addr_family: key.addr_family,
        protocol: key.protocol,
        src_ip: nat.rewrite_src.unwrap_or(key.src_ip),
        dst_ip: nat.rewrite_dst.unwrap_or(key.dst_ip),
        src_port,
        dst_port,
    }
}

fn reverse_wire_key(forward_key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(forward_key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (forward_key.src_port, forward_key.dst_port)
    } else {
        (
            nat.rewrite_dst_port.unwrap_or(forward_key.dst_port),
            nat.rewrite_src_port.unwrap_or(forward_key.src_port),
        )
    };
    let wire_src = nat.rewrite_dst.unwrap_or(forward_key.dst_ip);
    let wire_dst = nat.rewrite_src.unwrap_or(forward_key.src_ip);
    // NAT64: the reverse (reply) packet is a different address family.
    // Determine the AF from the NAT-rewritten addresses.
    let (addr_family, protocol) = if nat.nat64 {
        let af = match wire_src {
            std::net::IpAddr::V4(_) => libc::AF_INET as u8,
            std::net::IpAddr::V6(_) => libc::AF_INET6 as u8,
        };
        // ICMPv6 ↔ ICMP protocol mapping.
        let proto = if af == libc::AF_INET as u8 && forward_key.protocol == PROTO_ICMPV6 {
            PROTO_ICMP
        } else if af == libc::AF_INET6 as u8 && forward_key.protocol == PROTO_ICMP {
            PROTO_ICMPV6
        } else {
            forward_key.protocol
        };
        (af, proto)
    } else {
        (forward_key.addr_family, forward_key.protocol)
    };
    SessionKey {
        addr_family,
        protocol,
        src_ip: wire_src,
        dst_ip: wire_dst,
        src_port,
        dst_port,
    }
}

pub(crate) fn reverse_canonical_key(forward_key: &SessionKey, _nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(forward_key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (forward_key.src_port, forward_key.dst_port)
    } else {
        (forward_key.dst_port, forward_key.src_port)
    };
    SessionKey {
        addr_family: forward_key.addr_family,
        protocol: forward_key.protocol,
        src_ip: forward_key.dst_ip,
        dst_ip: forward_key.src_ip,
        src_port,
        dst_port,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_zone_ids::*;
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn key_v4() -> SessionKey {
        SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 12345,
            dst_port: 443,
        }
    }

    fn key_v6() -> SessionKey {
        SessionKey {
            addr_family: 10,
            protocol: PROTO_UDP,
            src_ip: IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("v6 src")),
            dst_ip: IpAddr::V6("2606:4700:4700::1111".parse::<Ipv6Addr>().expect("v6 dst")),
            src_port: 5555,
            dst_port: 53,
        }
    }

    fn resolution() -> ForwardingResolution {
        ForwardingResolution {
            disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: None,
            tx_vlan_id: 0,
        }
    }

    fn decision() -> SessionDecision {
        SessionDecision {
            resolution: resolution(),
            nat: NatDecision::default(),
        }
    }

    fn metadata() -> SessionMetadata {
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        }
    }

    #[test]
    fn session_lookup_hits_after_install() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_TCP,
            0x10
        ));
        let hit = table.lookup(&key, now + 1_000_000, 0x10);
        assert_eq!(
            hit,
            Some(SessionLookup {
                decision: decision(),
                metadata: metadata(),
            })
        );
        let deltas = table.drain_deltas(8);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].kind, SessionDeltaKind::Open);
        assert_eq!(deltas[0].key, key);
    }

    #[test]
    fn missing_neighbor_seed_install_stays_out_of_delta_stream() {
        let mut table = SessionTable::new();
        let key = key_v4();
        assert!(table.install_with_protocol_with_origin(
            key,
            decision(),
            metadata(),
            SessionOrigin::MissingNeighborSeed,
            1_000_000_000,
            PROTO_TCP,
            0x10
        ));
        assert!(
            table.drain_deltas(8).is_empty(),
            "transient missing-neighbor seeds must stay local"
        );
    }

    #[test]
    fn missing_neighbor_seed_expire_stays_out_of_delta_stream() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let then = 1_000_000_000u64;
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            metadata(),
            SessionOrigin::MissingNeighborSeed,
            then,
            PROTO_TCP,
            0x10
        ));
        assert!(table.drain_deltas(8).is_empty());
        table.last_gc_ns = then + 301_000_000_000;
        let expired = table.expire_stale_entries(then + 302_000_000_000);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].key, key);
        assert!(table.drain_deltas(8).is_empty());
    }

    #[test]
    fn session_expire_removes_stale_entries() {
        let mut table = SessionTable::new();
        let key = key_v6();
        let then = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            then,
            PROTO_UDP,
            0
        ));
        let _ = table.drain_deltas(8);
        table.last_gc_ns = then + 118_000_000_000;
        let expired = table.expire_stale(then + 120_000_000_000);
        assert_eq!(expired, 1);
        assert!(table.lookup(&key, then + 121_000_000_000, 0).is_none());
        let deltas = table.drain_deltas(8);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
        assert_eq!(deltas[0].key, key);
    }

    // === #965 timer-wheel tests =================================

    fn make_v4_key(src_octet: u8, port: u16) -> SessionKey {
        SessionKey {
            addr_family: 2,
            protocol: PROTO_UDP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, src_octet)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: port,
            dst_port: 53,
        }
    }

    /// Wheel pop expires an entry whose bucket the cursor advances past.
    #[test]
    fn wheel_pops_expired_entry_from_bucket() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let install_ns = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            install_ns,
            PROTO_UDP,
            0
        ));
        // UDP default timeout is 60 s. Advance past it; bypass GC gate.
        let advance = install_ns + 65 * WHEEL_TICK_NS;
        table.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
        let expired = table.expire_stale_entries(advance);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].key, key);
        assert!(table.lookup(&key, advance + 1_000_000, 0).is_none());
    }

    /// A touched entry is not popped from the wheel — its canonical
    /// wheel_tick advanced, so the old bucket entry is dropped as stale
    /// and the new bucket holds the live entry.
    #[test]
    fn wheel_skips_touched_entry() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let install_ns = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            install_ns,
            PROTO_UDP,
            0
        ));
        // Touch at install_ns + 30s — pushes the expiration target tick
        // forward by 30 (from install+60 to install+90).
        let touch_ns = install_ns + 30 * WHEEL_TICK_NS;
        table.touch(&key, touch_ns);
        // Advance past the ORIGINAL bucket (install+60) but not past
        // the new one (install+90). Bypass GC gate.
        let advance = install_ns + 65 * WHEEL_TICK_NS;
        table.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
        let expired = table.expire_stale_entries(advance);
        assert!(
            expired.is_empty(),
            "touched session should not expire yet; got {:?}",
            expired
        );
        assert!(table.lookup(&key, advance + 1_000_000, 0).is_some());
    }

    /// A timeout > 256 s lands in the FAR_FUTURE bucket; when popped,
    /// re-checks expiration and re-buckets if still alive.
    #[test]
    fn wheel_handles_long_timeout_via_far_future_bucket() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let install_ns = 1_000_000_000u64;
        // 7200 s timeout — far longer than the 256-s wheel.
        let long_timeout_secs = 7200u64;
        let mut t = SessionTimeouts::default();
        t.udp_ns = long_timeout_secs * WHEEL_TICK_NS;
        table.set_timeouts(t);
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            install_ns,
            PROTO_UDP,
            0
        ));
        // Advance 300 s — past one full rotation but well before the
        // real timeout. Bypass GC gate at every check.
        let advance = install_ns + 300 * WHEEL_TICK_NS;
        table.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
        let expired = table.expire_stale_entries(advance);
        assert!(
            expired.is_empty(),
            "long-timeout session must not expire prematurely"
        );
        // Advance past the real timeout — should now expire.
        let final_advance = install_ns + (long_timeout_secs + 5) * WHEEL_TICK_NS;
        table.last_gc_ns = final_advance - SESSION_GC_INTERVAL_NS;
        let expired = table.expire_stale_entries(final_advance);
        assert_eq!(expired.len(), 1);
    }

    /// Entry with `expires_after = WHEEL_BUCKETS * TICK_NS` lands in
    /// the FAR_FUTURE bucket (now_tick + 255), not the current bucket.
    #[test]
    fn wheel_handles_exact_256s_timeout() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let install_ns = 1_000_000_000u64;
        let mut t = SessionTimeouts::default();
        t.udp_ns = (WHEEL_BUCKETS as u64) * WHEEL_TICK_NS; // exactly 256 s
        table.set_timeouts(t);
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            install_ns,
            PROTO_UDP,
            0
        ));
        // Verify the entry's wheel_tick is install_tick + 255, NOT
        // install_tick (which would mean "current bucket").
        let entry = table.sessions.get(&key).expect("entry");
        let install_tick = install_ns / WHEEL_TICK_NS;
        assert_eq!(
            entry.wheel_tick,
            install_tick + FAR_FUTURE_OFFSET,
            "256-s timeout must land in FAR_FUTURE bucket, not current"
        );
    }

    /// First GC with a large monotonic now_ns must not walk billions
    /// of empty buckets — wheel_observe lazily initializes cursor_tick
    /// to the first observed now_tick.
    #[test]
    fn first_gc_with_large_monotonic_now_doesnt_walk_billions_of_buckets() {
        let mut table = SessionTable::new();
        // 10^18 ns = a typical CLOCK_MONOTONIC value after ~31 years.
        let huge_now = 1_000_000_000_000_000_000u64;
        // Should return immediately, no panic, no infinite loop.
        let expired = table.expire_stale_entries(huge_now);
        assert!(expired.is_empty());
        // Wheel should be initialized at the huge tick.
        assert!(table.wheel.initialized);
        assert_eq!(table.wheel.cursor_tick, huge_now / WHEEL_TICK_NS);
    }

    /// Sub-tick precision: at exactly `last_seen + expires_after`, the
    /// session is NOT expired (matches today's strict `>` semantics).
    /// This test exists in addition to the v8 sub-tick lag test.
    #[test]
    fn expiry_boundary_strict_greater_than() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let install_ns = 1_000_000_000u64;
        let mut t = SessionTimeouts::default();
        t.udp_ns = 1_000_000_000; // 1 s
        table.set_timeouts(t);
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            install_ns,
            PROTO_UDP,
            0
        ));
        // Exactly at last_seen + expires_after: NOT expired.
        let at_boundary = install_ns + 1_000_000_000;
        table.last_gc_ns = at_boundary - SESSION_GC_INTERVAL_NS;
        let expired = table.expire_stale_entries(at_boundary);
        assert!(
            expired.is_empty(),
            "exact-boundary entry must not expire under strict `>`"
        );
    }

    /// Wheel adds at most one tick of additional lag vs today's
    /// hypothetical sub-tick scan. At +1 ns the wheel reports
    /// not-yet-expired; at +TICK_NS+1 it reports expired.
    #[test]
    fn wheel_lags_today_subtick_by_at_most_one_tick() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let install_ns = 1_000_000_000u64;
        let mut t = SessionTimeouts::default();
        t.udp_ns = 1_000_000_000; // 1 s
        table.set_timeouts(t);
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            install_ns,
            PROTO_UDP,
            0
        ));
        // +1 ns past expiration: wheel hasn't popped the bucket yet
        // (cursor < now_tick is still false at this sub-tick offset).
        let just_past = install_ns + 1_000_000_000 + 1;
        table.last_gc_ns = just_past - SESSION_GC_INTERVAL_NS;
        let expired = table.expire_stale_entries(just_past);
        assert!(
            expired.is_empty(),
            "wheel may lag today's sub-tick scan by up to 1 tick"
        );
        // +1 wheel-tick + 1 ns past expiration: wheel MUST have caught
        // it. The cursor advances when now_tick advances.
        let one_tick_past = install_ns + 1_000_000_000 + WHEEL_TICK_NS + 1;
        table.last_gc_ns = one_tick_past - SESSION_GC_INTERVAL_NS;
        let expired = table.expire_stale_entries(one_tick_past);
        assert_eq!(
            expired.len(),
            1,
            "wheel must pop the entry once cursor advances one tick past target"
        );
    }

    /// Session touched 100 times within a single tick produces at most
    /// 2 wheel entries (the initial install push + at most one re-push
    /// if the expiration tick changed). Throttle bounds duplicates.
    #[test]
    fn wheel_duplicate_count_per_session_bounded() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let install_ns = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            install_ns,
            PROTO_UDP,
            0
        ));
        // Touch 100 times within the same wheel tick (sub-second).
        for i in 0..100u64 {
            table.touch(&key, install_ns + i * 1_000_000); // 1 ms steps
        }
        // Count wheel entries for this key.
        let count: usize = table
            .wheel
            .buckets
            .iter()
            .map(|b| b.iter().filter(|e| e.key == key).count())
            .sum();
        assert!(
            count <= 2,
            "same-tick touches should produce <=2 wheel entries; got {}",
            count
        );
    }

    /// 50K sessions all expiring at the same tick: a single GC call
    /// drains all of them from the popped bucket. No per-tick cap.
    #[test]
    fn wheel_sustained_overload_drains_all_buckets() {
        let mut table = SessionTable::new();
        let install_ns = 1_000_000_000u64;
        // Use 5K (not 50K) to keep test runtime sub-second; the
        // assertion is about behavior shape, not absolute capacity.
        const N: usize = 5000;
        // Default UDP timeout is 60s. Install all sessions at the
        // same install_ns so they share an expiration tick.
        for i in 0..N {
            let k = make_v4_key((i % 250) as u8, 1024 + (i / 250) as u16);
            assert!(table.install_with_protocol(
                k,
                decision(),
                metadata(),
                install_ns,
                PROTO_UDP,
                0
            ));
        }
        let advance = install_ns + 65 * WHEEL_TICK_NS;
        table.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
        let expired = table.expire_stale_entries(advance);
        assert_eq!(expired.len(), N, "all sessions must drain in one call");
        assert_eq!(table.len(), 0);
    }

    /// Alias path: lookup_with_origin called on a NAT-translated
    /// reverse alias key resolves to the canonical forward key (via
    /// reverse_translated_index), then pushes the CANONICAL key into
    /// the wheel — never the alias. Round-3/4 of plan iteration caught
    /// that the .map(|entry| { ... self.wheel ... }) shape wouldn't
    /// compile; this test additionally validates the runtime
    /// invariant that the canonical key, not the alias, lands in the
    /// wheel after a sub-tick advance.
    #[test]
    fn wheel_alias_lookup_refreshes_canonical_key() {
        let mut table = SessionTable::new();
        // Install a forward session with NAT rewrite_dst so that the
        // alias index gets populated automatically by index_forward_nat_key.
        let canonical_key = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 42)),
            src_port: 5201,
            dst_port: 42424,
        };
        let alias_key = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            src_port: 5201,
            dst_port: 42424,
        };
        let mut reverse_metadata = metadata();
        reverse_metadata.is_reverse = true;
        let nat = SessionDecision {
            resolution: resolution(),
            nat: NatDecision {
                rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                ..NatDecision::default()
            },
        };
        let install_ns = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            canonical_key.clone(),
            nat,
            reverse_metadata,
            install_ns,
            PROTO_TCP,
            0x10,
        ));
        // Sanity: install pushed the canonical key to its bucket.
        let initial_canonical_count: usize = table
            .wheel
            .buckets
            .iter()
            .map(|b| b.iter().filter(|e| e.key == canonical_key).count())
            .sum();
        assert_eq!(initial_canonical_count, 1, "install pushed canonical");
        let initial_alias_count: usize = table
            .wheel
            .buckets
            .iter()
            .map(|b| b.iter().filter(|e| e.key == alias_key).count())
            .sum();
        assert_eq!(initial_alias_count, 0, "alias key MUST NOT be in wheel");
        // Now look up via the ALIAS, advancing the canonical entry's
        // expiration tick by enough to cross the second-grid (so the
        // throttle fires a new push).
        let lookup_ns = install_ns + 2 * WHEEL_TICK_NS;
        let hit = table.lookup_with_origin(&alias_key, lookup_ns, 0x10);
        assert!(hit.is_some(), "alias lookup must hit");
        // Wheel state after alias lookup: canonical key has a NEW
        // entry (the one pushed by lookup_with_origin); alias key
        // STILL has no entries.
        let canonical_count: usize = table
            .wheel
            .buckets
            .iter()
            .map(|b| b.iter().filter(|e| e.key == canonical_key).count())
            .sum();
        assert!(
            canonical_count >= 2,
            "alias lookup must push a fresh wheel entry under the canonical key; \
             canonical_count={}",
            canonical_count
        );
        let alias_count: usize = table
            .wheel
            .buckets
            .iter()
            .map(|b| b.iter().filter(|e| e.key == alias_key).count())
            .sum();
        assert_eq!(
            alias_count, 0,
            "alias key MUST never appear in any bucket; alias_count={}",
            alias_count
        );
    }

    /// Sustained per-second touch on every session: K (entries
    /// scanned per popped bucket) is bounded by N, and pop
    /// classification matches the plan's expected pattern: every
    /// scanned entry is a stale duplicate (entries_dropped_stale ≈ K),
    /// no entries get re-bucketed (sessions are kept alive by
    /// per-second touches that update wheel_tick), and no entries
    /// expire.
    ///
    /// This is the per-second-touch K-bound from §Acceptance gate 4b
    /// (corrected per Codex round-7 #2 classifications and round-12
    /// instrumentation requirement).
    ///
    /// Test scale: N = 1000 (smaller than the 10K plan target to keep
    /// CI runtime under 1 s; the assertion shape is what matters).
    #[test]
    fn wheel_per_second_touch_bounds_k_per_bucket() {
        let mut table = SessionTable::new();
        const N: usize = 1000;
        let install_ns = 1_000_000_000u64;
        // Install N sessions, each at a distinct sub-tick install
        // offset so they spread across buckets after warm-up.
        let keys: Vec<SessionKey> = (0..N)
            .map(|i| make_v4_key((i % 250) as u8, 1024 + (i / 250) as u16))
            .collect();
        for (i, k) in keys.iter().enumerate() {
            assert!(table.install_with_protocol(
                k.clone(),
                decision(),
                metadata(),
                install_ns + (i as u64) * 1_000, // 1 µs spacing
                PROTO_UDP,
                0
            ));
        }
        // Warm-up: touch every session once per tick for ≥ 300 ticks
        // so the wheel reaches steady state under per-second touch on
        // every session. After each touch round, run GC at the
        // matching tick.
        const WARMUP_TICKS: u64 = 300;
        for tick_off in 1..=WARMUP_TICKS {
            let now = install_ns + tick_off * WHEEL_TICK_NS;
            for k in &keys {
                table.touch(k, now);
            }
            table.last_gc_ns = now - SESSION_GC_INTERVAL_NS;
            let _ = table.expire_stale_entries(now);
        }
        // Measurement tick: advance one more, capture the next pop's
        // stats via last_pop_stats().
        let measure_now = install_ns + (WARMUP_TICKS + 1) * WHEEL_TICK_NS;
        for k in &keys {
            table.touch(k, measure_now);
        }
        table.last_gc_ns = measure_now - SESSION_GC_INTERVAL_NS;
        let _ = table.expire_stale_entries(measure_now);
        let stats = table.last_pop_stats();

        // §Acceptance gate 4b classifications under sustained per-
        // second touch: every popped entry is stale duplicate, no
        // re-bucketing, no expirations.
        assert!(
            stats.scanned > 0,
            "must have scanned entries; stats={:?}",
            stats
        );
        // K bound: scanned ≤ N × 1.2 (20 % headroom — a 2× duplicate-
        // push regression would scan >2 N and fail this).
        let k_bound = (N as f64 * 1.2) as usize;
        assert!(
            stats.scanned <= k_bound,
            "K (scanned) must be bounded by N×1.2 = {}; got scanned={} stats={:?}",
            k_bound,
            stats.scanned,
            stats
        );
        // No re-bucketing under sustained-per-tick touch: each
        // session's canonical wheel_tick advances every tick, so all
        // popped entries with stale `scheduled_tick != wheel_tick`
        // hit the dropped_stale path, not re-bucket.
        assert_eq!(
            stats.re_bucketed, 0,
            "expected 0 re-bucketed under per-second touch; stats={:?}",
            stats
        );
        assert_eq!(
            stats.expired, 0,
            "expected 0 expirations under per-second touch; stats={:?}",
            stats
        );
        // dropped_stale + dropped_gone + expired + re_bucketed = scanned.
        assert_eq!(
            stats.dropped_stale + stats.dropped_gone + stats.expired + stats.re_bucketed,
            stats.scanned,
            "case classification must sum to scanned; stats={:?}",
            stats
        );
        // dropped_stale dominates (the lazy-delete discriminator is
        // the right path for this workload).
        assert!(
            stats.dropped_stale >= stats.scanned * 9 / 10,
            "expected dropped_stale ≈ scanned (≥90 %); stats={:?}",
            stats
        );
    }

    /// Across one full wheel rotation under sustained per-second
    /// touch, the total number of entries scanned ≈ 256 × N (every
    /// bucket pops N stale duplicates). Catches leakage of stale
    /// entries that the lazy-delete discriminator should drop on
    /// visit but didn't.
    #[test]
    fn wheel_per_second_touch_total_scan_per_rotation_matches_model() {
        let mut table = SessionTable::new();
        const N: usize = 500;
        let install_ns = 1_000_000_000u64;
        let keys: Vec<SessionKey> = (0..N)
            .map(|i| make_v4_key((i % 250) as u8, 1024 + (i / 250) as u16))
            .collect();
        for (i, k) in keys.iter().enumerate() {
            assert!(table.install_with_protocol(
                k.clone(),
                decision(),
                metadata(),
                install_ns + (i as u64) * 1_000,
                PROTO_UDP,
                0
            ));
        }
        // Warm up beyond one full rotation so steady-state holds.
        const WARMUP_TICKS: u64 = 300;
        for tick_off in 1..=WARMUP_TICKS {
            let now = install_ns + tick_off * WHEEL_TICK_NS;
            for k in &keys {
                table.touch(k, now);
            }
            table.last_gc_ns = now - SESSION_GC_INTERVAL_NS;
            let _ = table.expire_stale_entries(now);
        }
        // Now measure across exactly WHEEL_BUCKETS=256 ticks.
        let mut total_scanned = 0usize;
        for tick_off in 1..=WHEEL_BUCKETS as u64 {
            let now = install_ns + (WARMUP_TICKS + tick_off) * WHEEL_TICK_NS;
            for k in &keys {
                table.touch(k, now);
            }
            table.last_gc_ns = now - SESSION_GC_INTERVAL_NS;
            let _ = table.expire_stale_entries(now);
            total_scanned += table.last_pop_stats().scanned;
        }
        // Plan §Acceptance gate 4b: total_scanned ∈ [0.9, 1.1] × 256 × N.
        let model = WHEEL_BUCKETS * N;
        let lower = (model as f64 * 0.9) as usize;
        let upper = (model as f64 * 1.1) as usize;
        assert!(
            (lower..=upper).contains(&total_scanned),
            "total_scanned ({}) must be within ±10% of model ({}); range [{}, {}]",
            total_scanned,
            model,
            lower,
            upper
        );
    }

    #[test]
    fn expire_stale_entries_returns_helper_only_local_sessions() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let then = 1_000_000_000u64;
        let local_metadata = metadata();
        let local_decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::LocalDelivery,
                ..resolution()
            },
            nat: NatDecision::default(),
        };
        // Install with SyncImport origin to mark as peer-synced
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            local_decision,
            local_metadata.clone(),
            SessionOrigin::SyncImport,
            then,
            PROTO_TCP,
            0x10,
        ));
        table.last_gc_ns = then + 301_000_000_000;
        let expired = table.expire_stale_entries(then + 302_000_000_000);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].key, key);
        assert_eq!(expired[0].decision, local_decision);
        assert_eq!(expired[0].metadata, local_metadata);
        assert!(table.drain_deltas(8).is_empty());
    }

    #[test]
    fn take_synced_local_only_removes_helper_local_sessions() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        let local_metadata = metadata();
        let local_decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::LocalDelivery,
                ..resolution()
            },
            nat: NatDecision::default(),
        };
        // Install with SyncImport origin so it's considered peer-synced
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            local_decision,
            local_metadata.clone(),
            SessionOrigin::SyncImport,
            now,
            PROTO_TCP,
            0x10,
        ));
        let removed = table
            .take_synced_local(&key)
            .expect("local session removed");
        assert_eq!(removed.decision, local_decision);
        assert_eq!(removed.metadata, local_metadata);
        assert!(table.lookup(&key, now + 1_000_000, 0x10).is_none());

        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_TCP,
            0x10,
        ));
        assert!(table.take_synced_local(&key).is_none());
        assert!(table.lookup(&key, now + 1_000_000, 0x10).is_some());
    }

    #[test]
    fn tcp_fin_keeps_session_until_closing_timeout() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_TCP,
            0x10
        ));
        let _ = table.drain_deltas(8);
        let hit = table.lookup(&key, now + 1_000_000, TCP_FIN);
        assert_eq!(
            hit,
            Some(SessionLookup {
                decision: decision(),
                metadata: metadata(),
            })
        );
        assert!(table.lookup(&key, now + 2_000_000, 0x10).is_some());
        table.last_gc_ns = now + TCP_CLOSING_TIMEOUT_NS;
        let expired = table.expire_stale(now + TCP_CLOSING_TIMEOUT_NS + 1_000_000_000);
        assert_eq!(expired, 1);
        assert!(
            table
                .lookup(&key, now + TCP_CLOSING_TIMEOUT_NS + 2_000_000_000, 0)
                .is_none()
        );
        let deltas = table.drain_deltas(8);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
        assert_eq!(deltas[0].key, key);
    }

    #[test]
    fn synced_sessions_do_not_emit_deltas() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        let synced_meta = metadata();
        table.upsert_synced(
            key.clone(),
            decision(),
            synced_meta.clone(),
            now,
            PROTO_TCP,
            0x10,
            false,
        );
        let hit = table.lookup(&key, now + 1_000_000, 0x10);
        assert_eq!(
            hit,
            Some(SessionLookup {
                decision: decision(),
                metadata: synced_meta,
            })
        );
        assert!(table.drain_deltas(8).is_empty());
        let _ = table.lookup(&key, now + 2_000_000, TCP_FIN);
        assert!(table.drain_deltas(8).is_empty());
    }

    #[test]
    fn upsert_synced_does_not_clobber_live_local_session() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        let mut live = metadata();
        live.fabric_ingress = true;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            live.clone(),
            now,
            PROTO_TCP,
            0x10,
        ));
        let synced_meta = metadata();
        table.upsert_synced(
            key.clone(),
            SessionDecision {
                nat: NatDecision {
                    rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                    ..NatDecision::default()
                },
                ..decision()
            },
            synced_meta,
            now + 1_000_000,
            PROTO_TCP,
            0x10,
            false,
        );
        let hit = table
            .lookup(&key, now + 2_000_000, 0x10)
            .expect("live session");
        assert_eq!(hit.metadata, live);
        assert_eq!(hit.decision, decision());
    }

    #[test]
    fn upsert_synced_can_replace_live_local_session_when_allowed() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        let live = metadata();
        assert!(table.install_with_protocol(key.clone(), decision(), live, now, PROTO_TCP, 0x10,));
        let synced_meta = metadata();
        let synced_decision = SessionDecision {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
            ..decision()
        };
        assert!(table.upsert_synced(
            key.clone(),
            synced_decision,
            synced_meta.clone(),
            now + 1_000_000,
            PROTO_TCP,
            0x10,
            true,
        ));
        let hit = table
            .lookup(&key, now + 2_000_000, 0x10)
            .expect("synced session");
        assert_eq!(hit.metadata, synced_meta);
        assert_eq!(hit.decision, synced_decision);
    }

    #[test]
    fn promote_synced_forward_session_emits_open_delta() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        let synced_meta = metadata();
        table.upsert_synced(
            key.clone(),
            decision(),
            synced_meta,
            now,
            PROTO_TCP,
            0x10,
            false,
        );
        let promoted = metadata();
        assert!(table.promote_synced_with_origin(
            &key,
            decision(),
            promoted.clone(),
            SessionOrigin::SharedPromote,
            now + 1_000_000,
            PROTO_TCP,
            0x10,
        ));
        let hit = table.lookup(&key, now + 2_000_000, 0x10);
        assert_eq!(
            hit,
            Some(SessionLookup {
                decision: decision(),
                metadata: promoted.clone(),
            })
        );
        let deltas = table.drain_deltas(8);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].kind, SessionDeltaKind::Open);
        assert_eq!(deltas[0].key, key);
        assert_eq!(deltas[0].metadata, promoted);
    }

    #[test]
    fn promote_synced_reverse_session_stays_quiet() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        let mut synced_meta = metadata();
        synced_meta.is_reverse = true;
        table.upsert_synced(
            key.clone(),
            decision(),
            synced_meta,
            now,
            PROTO_TCP,
            0x10,
            false,
        );
        let mut promoted = metadata();
        promoted.is_reverse = true;
        assert!(table.promote_synced_with_origin(
            &key,
            decision(),
            promoted.clone(),
            SessionOrigin::SharedPromote,
            now + 1_000_000,
            PROTO_TCP,
            0x10,
        ));
        let hit = table.lookup(&key, now + 2_000_000, 0x10);
        assert_eq!(
            hit,
            Some(SessionLookup {
                decision: decision(),
                metadata: promoted,
            })
        );
        assert!(table.drain_deltas(8).is_empty());
    }

    #[test]
    fn demote_owner_rg_marks_forward_and_reverse_entries_synced() {
        let mut table = SessionTable::new();
        let now = 1_000_000_000u64;
        let key_a = key_v4();
        let key_b = SessionKey {
            src_port: 42425,
            ..key_v4()
        };
        let key_other = SessionKey {
            src_port: 42426,
            ..key_v4()
        };
        let mut metadata_a = metadata();
        metadata_a.owner_rg_id = 1;
        let mut metadata_b = metadata();
        metadata_b.owner_rg_id = 1;
        metadata_b.is_reverse = true;
        let mut metadata_other = metadata();
        metadata_other.owner_rg_id = 2;
        assert!(table.install_with_protocol(
            key_a.clone(),
            decision(),
            metadata_a,
            now,
            PROTO_TCP,
            0x10,
        ));
        assert!(table.install_with_protocol(
            key_b.clone(),
            decision(),
            metadata_b,
            now,
            PROTO_TCP,
            0x10,
        ));
        assert!(table.install_with_protocol(
            key_other.clone(),
            decision(),
            metadata_other.clone(),
            now,
            PROTO_TCP,
            0x10,
        ));

        assert_eq!(table.demote_owner_rg(1).len(), 2);

        // Verify demoted sessions have peer-synced origin
        let mut a_origin = None;
        let mut b_origin = None;
        let mut other_origin = None;
        table.iter_with_origin(|key, _decision, _metadata, origin| {
            if key == &key_a {
                a_origin = Some(origin);
            } else if key == &key_b {
                b_origin = Some(origin);
            } else if key == &key_other {
                other_origin = Some(origin);
            }
        });
        assert!(a_origin.expect("key_a exists").is_peer_synced());
        assert!(b_origin.expect("key_b exists").is_peer_synced());
        assert!(
            !other_origin.expect("key_other exists").is_peer_synced(),
            "other RG should remain local"
        );
        assert_eq!(
            table
                .lookup(&key_other, now + 1_000_000, 0x10)
                .expect("other rg")
                .metadata,
            metadata_other
        );
    }

    #[test]
    fn demote_owner_rg_returns_synced_entries_for_transition_refresh() {
        let mut table = SessionTable::new();
        let now = 1_000_000_000u64;
        let key = key_v4();
        let mut metadata = metadata();
        metadata.owner_rg_id = 2;
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            metadata.clone(),
            SessionOrigin::SyncImport,
            now,
            PROTO_TCP,
            0x10,
        ));

        let demoted = table.demote_owner_rg(2);
        assert_eq!(demoted, vec![key.clone()]);

        let (_, _, origin) = table.entry_with_origin(&key).expect("session exists");
        assert_eq!(origin, SessionOrigin::SyncImport);
    }

    #[test]
    fn owner_rg_session_keys_track_insert_update_and_delete() {
        let mut table = SessionTable::new();
        let now = 1_000_000_000u64;
        let key = key_v4();
        let mut metadata_rg1 = metadata();
        metadata_rg1.owner_rg_id = 1;
        let mut metadata_rg2 = metadata();
        metadata_rg2.owner_rg_id = 2;

        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata_rg1.clone(),
            now,
            PROTO_TCP,
            0x10,
        ));
        assert_eq!(table.owner_rg_session_keys(&[1]), vec![key.clone()]);

        assert!(table.refresh_for_ha_activation(
            &key,
            decision(),
            metadata_rg2.clone(),
            now + 1_000_000,
            0x10,
        ));
        assert!(table.owner_rg_session_keys(&[1]).is_empty());
        assert_eq!(table.owner_rg_session_keys(&[2]), vec![key.clone()]);

        table.delete(&key);
        assert!(table.owner_rg_session_keys(&[2]).is_empty());
    }

    #[test]
    fn reply_match_finds_tcp_snat_reverse_tuple() {
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 42424,
            dst_port: 5201,
        };
        let reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 5201,
            dst_port: 42424,
        };
        assert!(reply_matches_forward_session(
            &forward,
            NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_dst: None,
                ..NatDecision::default()
            },
            &reply,
        ));
    }

    #[test]
    fn reply_match_finds_icmp_snat_reverse_tuple() {
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 0x1234,
            dst_port: 0,
        };
        let reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 0x1234,
            dst_port: 0,
        };
        assert!(reply_matches_forward_session(
            &forward,
            NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_dst: None,
                ..NatDecision::default()
            },
            &reply,
        ));
    }

    #[test]
    fn find_forward_nat_match_uses_reverse_index() {
        let mut table = SessionTable::new();
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 42424,
            dst_port: 5201,
        };
        let reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 5201,
            dst_port: 42424,
        };
        let nat = NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_dst: None,
            ..NatDecision::default()
        };
        let decision = SessionDecision {
            resolution: resolution(),
            nat,
        };
        assert!(table.install_with_protocol(
            forward.clone(),
            decision,
            metadata(),
            1_000_000_000,
            PROTO_TCP,
            0x10
        ));

        let hit = table
            .find_forward_nat_match(&reply)
            .expect("forward nat match");
        assert_eq!(hit.key, forward);
        assert_eq!(hit.decision.nat, nat);

        table.delete(&hit.key);
        assert!(table.find_forward_nat_match(&reply).is_none());
    }

    #[test]
    fn find_forward_nat_match_uses_canonical_reverse_index() {
        let mut table = SessionTable::new();
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 42424,
            dst_port: 5201,
        };
        let canonical_reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            src_port: 5201,
            dst_port: 42424,
        };
        let nat = NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        };
        let decision = SessionDecision {
            resolution: resolution(),
            nat,
        };
        assert!(table.install_with_protocol(
            forward.clone(),
            decision,
            metadata(),
            1_000_000_000,
            PROTO_TCP,
            0x10
        ));

        let hit = table
            .find_forward_nat_match(&canonical_reply)
            .expect("canonical reverse match");
        assert_eq!(hit.key, forward);
        assert_eq!(hit.decision.nat, nat);

        table.delete(&hit.key);
        assert!(table.find_forward_nat_match(&canonical_reply).is_none());
    }

    #[test]
    fn reverse_canonical_key_keeps_icmp_identifier_position() {
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            src_port: 0x1234,
            dst_port: 0,
        };
        let reply = reverse_canonical_key(&forward, NatDecision::default());
        assert_eq!(reply.src_ip, IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)));
        assert_eq!(reply.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)));
        assert_eq!(reply.src_port, 0x1234);
        assert_eq!(reply.dst_port, 0);
    }

    #[test]
    fn find_forward_nat_match_uses_canonical_reverse_index_for_icmp() {
        let mut table = SessionTable::new();
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            src_port: 0x1234,
            dst_port: 0,
        };
        let canonical_reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            src_port: 0x1234,
            dst_port: 0,
        };
        let nat = NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 192, 42))),
            ..NatDecision::default()
        };
        let decision = SessionDecision {
            resolution: resolution(),
            nat,
        };
        assert!(table.install_with_protocol(
            forward.clone(),
            decision,
            metadata(),
            1_000_000_000,
            PROTO_ICMP,
            0
        ));

        let hit = table
            .find_forward_nat_match(&canonical_reply)
            .expect("icmp canonical reverse match");
        assert_eq!(hit.key, forward);
        assert_eq!(hit.decision.nat, nat);

        table.delete(&hit.key);
        assert!(table.find_forward_nat_match(&canonical_reply).is_none());
    }

    #[test]
    fn find_forward_wire_match_uses_translated_forward_index() {
        let mut table = SessionTable::new();
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 42528,
            dst_port: 5201,
        };
        let translated = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 42528,
            dst_port: 5201,
        };
        let nat = NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(42528),
            ..NatDecision::default()
        };
        let decision = SessionDecision {
            resolution: resolution(),
            nat,
        };
        assert!(table.install_with_protocol(
            forward.clone(),
            decision,
            metadata(),
            1_000_000_000,
            PROTO_TCP,
            0x10
        ));

        let hit = table
            .find_forward_wire_match(&translated)
            .expect("forward wire match");
        assert_eq!(hit.key, forward);
        assert_eq!(hit.decision.nat, nat);

        table.delete(&hit.key);
        assert!(table.find_forward_wire_match(&translated).is_none());
    }

    #[test]
    fn lookup_uses_translated_reverse_alias() {
        let mut table = SessionTable::new();
        let reverse_wire = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 42)),
            src_port: 5201,
            dst_port: 42424,
        };
        let reverse_canonical = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            src_port: 5201,
            dst_port: 42424,
        };
        let mut reverse_metadata = metadata();
        reverse_metadata.is_reverse = true;
        let reverse_decision = SessionDecision {
            resolution: resolution(),
            nat: NatDecision {
                rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                ..NatDecision::default()
            },
        };
        assert!(table.install_with_protocol(
            reverse_wire.clone(),
            reverse_decision,
            reverse_metadata.clone(),
            1_000_000_000,
            PROTO_TCP,
            0x10
        ));

        let hit = table
            .lookup(&reverse_canonical, 1_001_000_000, 0x10)
            .expect("translated reverse alias");
        assert_eq!(hit.decision, reverse_decision);
        assert_eq!(hit.metadata, reverse_metadata);

        table.delete(&reverse_wire);
        assert!(
            table
                .lookup(&reverse_canonical, 1_002_000_000, 0x10)
                .is_none()
        );
    }

    #[test]
    fn dnat_port_in_reverse_wire_key() {
        // Forward: client:54321 -> external:80, DNAT rewrites dst to internal:8080
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            src_port: 54321,
            dst_port: 80,
        };
        let nat = NatDecision {
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            rewrite_dst_port: Some(8080),
            ..NatDecision::default()
        };
        // Reply from internal:8080 -> client:54321
        let expected_reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            src_port: 8080,
            dst_port: 54321,
        };
        assert!(reply_matches_forward_session(
            &forward,
            nat,
            &expected_reply
        ));
    }

    #[test]
    fn dnat_plus_snat_ports_in_reverse_key() {
        // Forward: client:54321 -> external:80
        // DNAT: dst -> internal:8080, SNAT: src -> egress_ip
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            src_port: 54321,
            dst_port: 80,
        };
        let nat = NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            rewrite_src_port: None,
            rewrite_dst_port: Some(8080),
            nat64: false,
            nptv6: false,
        };
        // Reply: internal:8080 -> egress:54321
        let expected_reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 8080,
            dst_port: 54321,
        };
        assert!(reply_matches_forward_session(
            &forward,
            nat,
            &expected_reply
        ));
    }

    #[test]
    fn icmp_port_handling_unchanged_with_dnat_ports() {
        // ICMP ignores port rewriting even if NatDecision has port fields set
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            src_port: 0x1234,
            dst_port: 0,
        };
        let nat = NatDecision {
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            rewrite_dst_port: Some(8080),
            ..NatDecision::default()
        };
        // ICMP reverse: ports stay the same (ICMP has no port semantics)
        let expected_reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 0x1234,
            dst_port: 0,
        };
        assert!(reply_matches_forward_session(
            &forward,
            nat,
            &expected_reply
        ));
    }

    #[test]
    fn find_forward_nat_match_with_dnat_port_rewrite() {
        let mut table = SessionTable::new();
        // Forward: client:54321 -> external:80 with DNAT to internal:8080
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            src_port: 54321,
            dst_port: 80,
        };
        // Reply from internal:8080 -> client:54321
        let reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            src_port: 8080,
            dst_port: 54321,
        };
        let nat = NatDecision {
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            rewrite_dst_port: Some(8080),
            ..NatDecision::default()
        };
        let decision = SessionDecision {
            resolution: resolution(),
            nat,
        };
        assert!(table.install_with_protocol(
            forward.clone(),
            decision,
            metadata(),
            1_000_000_000,
            PROTO_TCP,
            0x10
        ));

        let hit = table
            .find_forward_nat_match(&reply)
            .expect("forward nat match with port");
        assert_eq!(hit.key, forward);
        assert_eq!(hit.decision.nat, nat);

        table.delete(&hit.key);
        assert!(table.find_forward_nat_match(&reply).is_none());
    }

    #[test]
    fn configurable_tcp_timeout_changes_session_expiry() {
        let mut table = SessionTable::new();
        table.set_timeouts(SessionTimeouts::from_seconds(60, 0, 0));
        let key = key_v4();
        let now = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_TCP,
            0x10,
        ));
        // Session should expire after 60s (configured), not 300s (default)
        table.last_gc_ns = now + 59_000_000_000;
        let expired = table.expire_stale(now + 59_000_000_000 + SESSION_GC_INTERVAL_NS);
        assert_eq!(expired, 0, "session should not expire before 60s");

        table.last_gc_ns = now + 61_000_000_000;
        let expired = table.expire_stale(now + 61_000_000_000 + SESSION_GC_INTERVAL_NS);
        assert_eq!(expired, 1, "session should expire after 60s");
    }

    #[test]
    fn configurable_udp_timeout_changes_session_expiry() {
        let mut table = SessionTable::new();
        table.set_timeouts(SessionTimeouts::from_seconds(0, 120, 0));
        let key = key_v6();
        let now = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_UDP,
            0,
        ));
        // Should not expire at 60s (the old default)
        table.last_gc_ns = now + 61_000_000_000;
        let expired = table.expire_stale(now + 61_000_000_000 + SESSION_GC_INTERVAL_NS);
        assert_eq!(expired, 0, "session should not expire before 120s");

        // Should expire after 120s
        table.last_gc_ns = now + 121_000_000_000;
        let expired = table.expire_stale(now + 121_000_000_000 + SESSION_GC_INTERVAL_NS);
        assert_eq!(expired, 1, "session should expire after 120s");
    }

    #[test]
    fn default_timeouts_match_original_values() {
        let t = SessionTimeouts::default();
        assert_eq!(t.tcp_established_ns, 300_000_000_000);
        assert_eq!(t.udp_ns, 60_000_000_000);
        assert_eq!(t.icmp_ns, 60_000_000_000);
    }

    #[test]
    fn from_seconds_zero_uses_default() {
        let t = SessionTimeouts::from_seconds(0, 0, 0);
        assert_eq!(t.tcp_established_ns, DEFAULT_TCP_SESSION_TIMEOUT_NS);
        assert_eq!(t.udp_ns, DEFAULT_UDP_SESSION_TIMEOUT_NS);
        assert_eq!(t.icmp_ns, DEFAULT_ICMP_SESSION_TIMEOUT_NS);
    }

    #[test]
    fn from_seconds_overrides_values() {
        let t = SessionTimeouts::from_seconds(120, 30, 5);
        assert_eq!(t.tcp_established_ns, 120_000_000_000);
        assert_eq!(t.udp_ns, 30_000_000_000);
        assert_eq!(t.icmp_ns, 5_000_000_000);
    }

    #[test]
    fn iter_with_idle_reports_idle_time() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let install_time = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            install_time,
            PROTO_TCP,
            0x10,
        ));

        let now = install_time + 5_000_000_000; // 5 seconds later
        let mut found = false;
        table.iter_with_idle(now, |k, _decision, _metadata, idle_ns| {
            if k == &key {
                assert_eq!(idle_ns, 5_000_000_000);
                found = true;
            }
        });
        assert!(found, "session should be found in iter_with_idle");
    }

    #[test]
    fn iter_with_idle_reflects_last_seen_update() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let install_time = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            install_time,
            PROTO_TCP,
            0x10,
        ));
        // Touch the session 3 seconds later
        let touch_time = install_time + 3_000_000_000;
        let _ = table.lookup(&key, touch_time, 0x10);

        // Check idle time 5 seconds after install (2 seconds after last touch)
        let now = install_time + 5_000_000_000;
        let mut idle = 0u64;
        table.iter_with_idle(now, |k, _, _, idle_ns| {
            if k == &key {
                idle = idle_ns;
            }
        });
        assert_eq!(idle, 2_000_000_000, "idle should be 2s since last touch");
    }

    #[test]
    fn refresh_local_skips_peer_synced_entries() {
        let mut table = SessionTable::new();
        let key = key_v4();
        // Install with SyncImport origin (peer-synced)
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            metadata(),
            SessionOrigin::SyncImport,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        let new_decision = SessionDecision {
            resolution: ForwardingResolution {
                egress_ifindex: 99,
                ..decision().resolution
            },
            ..decision()
        };
        // refresh_local should return false for peer-synced sessions
        assert!(!table.refresh_local(&key, new_decision, metadata(), 2_000_000, 0x10));
        assert_eq!(table.owner_rg_session_keys(&[1]), vec![key.clone()]);
        // session should still have original decision
        let lookup = table.lookup(&key, 3_000_000, 0x10).expect("session");
        assert_ne!(lookup.decision.resolution.egress_ifindex, 99);
    }

    #[test]
    fn refresh_for_ha_activation_updates_peer_synced_entries() {
        let mut table = SessionTable::new();
        let key = key_v4();
        // Install with SyncImport origin (peer-synced)
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            metadata(),
            SessionOrigin::SyncImport,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        let new_decision = SessionDecision {
            resolution: ForwardingResolution {
                egress_ifindex: 99,
                ..decision().resolution
            },
            ..decision()
        };
        // refresh_for_ha_activation should succeed even for peer-synced sessions
        assert!(table.refresh_for_ha_activation(&key, new_decision, metadata(), 2_000_000, 0x10));
        // session should now have updated decision
        let lookup = table.lookup(&key, 3_000_000, 0x10).expect("session");
        assert_eq!(lookup.decision.resolution.egress_ifindex, 99);
    }
}
