use crate::afxdp::{ForwardingDisposition, ForwardingResolution};
use crate::nat::NatDecision;
use crate::nat64::Nat64ReverseInfo;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::VecDeque;
use std::net::IpAddr;

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
// Wheel tick must equal the GC interval — `expire_stale_entries`
// is gated by `SESSION_GC_INTERVAL_NS` and the cursor advances one
// bucket per tick. If these diverge the cadence math gets silently
// out of sync (Copilot review: bind WHEEL_TICK_NS to the gate).
const WHEEL_TICK_NS: u64 = SESSION_GC_INTERVAL_NS;
const FAR_FUTURE_OFFSET: u64 = (WHEEL_BUCKETS as u64) - 1;
// Compile-time invariant: bucket_for_tick uses `tick & WHEEL_MASK`
// which only computes `tick % WHEEL_BUCKETS` correctly when
// WHEEL_BUCKETS is a power of two (Copilot review: footgun if
// someone changes the bucket count without updating the helper).
const _: () = assert!(
    WHEEL_BUCKETS.is_power_of_two(),
    "WHEEL_BUCKETS must be a power of two for the WHEEL_MASK trick to compute tick % WHEEL_BUCKETS",
);

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
    /// Absolute tick of the next bucket to pop. Advances 1 per
    /// elapsed wheel tick during `expire_stale_entries`. The bucket
    /// index is `cursor_tick & WHEEL_MASK`.
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
            self.wheel.cursor_tick = now_ns / WHEEL_TICK_NS;
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
                    // Re-bucket at the new absolute target tick. The
                    // entry was just read via `self.sessions.get(&key)`
                    // immediately above with no intervening mutation,
                    // so `get_mut(&key)` is a hard invariant — use
                    // `expect` instead of `if let Some` so an invariant
                    // violation surfaces loudly instead of silently
                    // pushing a stale-tick wheel entry (Copilot review).
                    let new_target_tick = target_tick_for(
                        now_ns,
                        entry.last_seen_ns.saturating_add(entry.expires_after_ns),
                    );
                    let new_bucket = bucket_for_tick(new_target_tick);
                    let entry_mut = self
                        .sessions
                        .get_mut(&key)
                        .expect("entry was just read via .get(); no concurrent mutation");
                    entry_mut.wheel_tick = new_target_tick;
                    self.wheel.buckets[new_bucket].push_back(WheelEntry {
                        key,
                        scheduled_tick: new_target_tick,
                    });
                    self.last_pop_stats.re_bucketed += 1;
                }
            }
            self.wheel.cursor_tick = self.wheel.cursor_tick.saturating_add(1);
        }
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
#[path = "session_tests.rs"]
mod tests;
