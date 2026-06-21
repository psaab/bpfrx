use crate::afxdp::{ForwardingDisposition, ForwardingResolution};
use crate::nat::NatDecision;
use crate::nat64::Nat64ReverseInfo;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::VecDeque;
use std::net::IpAddr;

// #1047 P2: SessionKey and the key-transform helpers (forward_wire_key,
// translated_session_key, reverse_canonical_key, reverse_wire_key,
// reply_matches_forward_session) live in session/key.rs. Re-exporting
// at pub(crate) keeps the existing crate::session::* surface intact.
mod key;
pub(crate) use key::*;
mod entry;
pub(crate) use entry::*;
mod ctx;
pub(crate) use ctx::*;
mod wheel;
use wheel::SessionWheel;

const SESSION_GC_INTERVAL_NS: u64 = 1_000_000_000;
const DEFAULT_MAX_SESSIONS: usize = 131072;
const DEFAULT_TCP_SESSION_TIMEOUT_NS: u64 = 300_000_000_000;
const TCP_CLOSING_TIMEOUT_NS: u64 = 30_000_000_000;
const DEFAULT_UDP_SESSION_TIMEOUT_NS: u64 = 60_000_000_000;
const DEFAULT_ICMP_SESSION_TIMEOUT_NS: u64 = 60_000_000_000;
const OTHER_SESSION_TIMEOUT_NS: u64 = 30_000_000_000;

/// #2220: flow-cache keepalive divisor. A cache-served session is
/// re-stamped once its idle time reaches `expires_after_ns /
/// SESSION_KEEPALIVE_DIVISOR` (a quarter of its own timeout), bounding
/// its worst-case age to `(1 + 1/N) × expires_after_ns` independent of
/// co-resident flow rates. Four leaves three full refresh windows of
/// slack before natural expiry — far enough from the edge that ordinary
/// GC jitter (1 s `SESSION_GC_INTERVAL_NS`) never reaps an active flow,
/// yet large enough that the steady-state refresh only writes/re-buckets
/// a few times per timeout window rather than per packet.
const SESSION_KEEPALIVE_DIVISOR: u64 = 4;

/// #2120: stale-synced ceiling multiplier. A peer-synced session HELD
/// by the standby retention gate is reaped once it has been held longer
/// than `min(STALE_SYNCED_CEILING_MULT × expires_after_ns,
/// STALE_SYNCED_CEILING_ABS_NS)`. RELATIVE because configured timeouts
/// can reach `MaxDurationSeconds`, so a fixed ceiling would reap a live
/// long-timeout session on the standby before failover. Multiplier ≈ 3
/// gives the primary several full idle windows to deliver its Close
/// delta (or the journal/reconnect path to reconcile) before the
/// standby reaps on its own.
pub(crate) const STALE_SYNCED_CEILING_MULT: u64 = 3;

/// #2120: stale-synced ceiling absolute cap (≈7 days). Bounds the
/// pathological long-`inactivity-timeout` config (a 30-day-timeout flow
/// would otherwise allow a leaked held entry to be pinned for 90 days at
/// MULT×). 7 days is generously ≥ the largest realistic standby idle
/// window a legitimate failover could need, so the cap reaps only leaked
/// standby state, never a live local flow (a held entry is by definition
/// NOT forwarding on this node). See plan §4.4 / §6.5.
pub(crate) const STALE_SYNCED_CEILING_ABS_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

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
    /// Entries that were re-bucketed (kept on the wheel rather than
    /// removed). Covers the long-timeout / not-yet-expired Case-4 entries
    /// AND, since #2120, idle-crossed entries kept alive by the standby
    /// gate (HOLD and SELF-HEAL both re-bucket). Telemetry/tests must not
    /// read this as "long-timeout only".
    pub(crate) re_bucketed: usize,
    /// #2120: peer-synced (or whole-node-standby `owner_rg_id==0`)
    /// entries that crossed their idle timeout but were HELD instead of
    /// expired because this node does not currently forward their RG.
    /// Restores the dead Go-GC `IsLocalPrimary` retention contract into
    /// the userspace wheel — without it the standby silently reaps
    /// long-lived synced sessions and breaks them on failover (#131
    /// reintroduced by the eBPF→userspace migration).
    pub(crate) held_standby: usize,
    /// #2120: HELD entries reaped anyway because they have been held
    /// past the stale-synced ceiling (`min(MULT × timeout, ABS_CAP)`
    /// measured from `first_held_ns`). Bounds the lost-primary-delete
    /// leak — a held entry whose Close delta and journal entry were both
    /// lost cannot be pinned forever.
    pub(crate) reaped_stale_synced: usize,
    /// #2120: HELD entries re-stamped (kept alive with a fresh
    /// `last_seen_ns`) because this node has STARTED forwarding their RG
    /// but the entry's recorded epoch predates the activation — the
    /// edge-triggered self-heal that closes the promotion command-apply
    /// race (RefreshOwnerRGS may not have landed yet).
    pub(crate) healed_on_promote: usize,
    /// #2120: peer-synced `owner_rg_id==0` entries AGED on an
    /// otherwise-active node (one RG active, the entry belongs to a
    /// standby RG path). This is the known active/active under-retention
    /// residual (plan §4.4 / A2#4); counted so it is OBSERVABLE in the
    /// field rather than a silent drop.
    pub(crate) aged_owner_rg_zero_active_node: usize,
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
use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
// #2151: TCP flag bits from the shared crate::tcp_flags SSOT. Re-exported
// so the conntrack submodules (install, lookup, expire) keep referencing
// TCP_FIN/TCP_RST via `super::*`. The session-closing test is the shared
// `is_closing` predicate.
use crate::tcp_flags::{TCP_FIN, TCP_RST, has_rst, is_closing};

#[allow(unused_macros)]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-log")]
        eprintln!($($arg)*);
    };
}

// #2005 pure code-motion split: the conntrack fast path is split into
// focused submodules that all attach `impl SessionTable` blocks. These
// declarations sit AFTER `debug_log!` so the macro is in textual scope
// for the child modules that call it (`expire`, `lookup`). The
// coordinator/table definition and the #1752/#1855 in-place-refresh
// contract (update_session / refresh_for_ha_transition + the
// secondary-index re-assert + #964 eager cleanup helpers) stay in
// mod.rs. Submodule methods keep their original visibility; the only
// widening is `push_to_wheel` (module-private `fn` → `pub(in
// crate::session)`) because callers in mod.rs / install / lookup cross
// the module boundary into `expire`.
mod expire;
mod install;
mod lookup;

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
    /// #2120: the RG epoch (`rg_epochs[owner_rg_id]`, or the node-level
    /// `rg_epochs[0]` for `owner_rg_id <= 0`) recorded the last time this
    /// entry was self-healed (the expire pass observed this node START
    /// forwarding the RG). The expire pass compares the current epoch
    /// against it to detect the activation edge and fire the self-heal
    /// re-stamp exactly once per activation. This field is NOT
    /// write-once — it is reset and re-stamped over the entry's life:
    ///   - SELF-HEAL stamps it to the current epoch (the only write that
    ///     records a live epoch).
    ///   - `install` / `upsert_synced`, `update_session` (real-traffic
    ///     refresh), and `refresh_for_ha_transition` (promotion refresh)
    ///     RESET it to 0. A reset means "epoch unknown; re-stamp on the
    ///     next SELF-HEAL", and is load-bearing: it guarantees the first
    ///     forwarding pass after any epoch-bumping activation observes
    ///     `current_epoch != seen_rg_epoch` and fires the self-heal.
    /// The HOLD branch deliberately does NOT write it — the worker reads
    /// the HA map and `rg_epochs` as separate loads, so a HOLD can see an
    /// old (inactive) map with a new (already-bumped) epoch; stamping that
    /// epoch on a hold would make the next (active-map) pass skip the
    /// self-heal and age the synced session (the Codex old-map/new-epoch
    /// race). An epoch of 0 is the standalone / never-self-healed default.
    seen_rg_epoch: u32,
    /// #2120: monotonic timestamp (ns) at which this entry FIRST entered
    /// the held (non-forwarding standby) state, or 0 when not held. The
    /// stale-synced ceiling measures the hold duration from here, NOT
    /// from `last_seen_ns`, so a self-heal re-stamp on a flapping RG
    /// cannot reset the leak clock. Cleared (→0) ONLY when the entry
    /// genuinely leaves the held world: real-traffic refresh
    /// (`update_session`), promotion refresh
    /// (`refresh_for_ha_transition`), or re-import (`upsert_synced`).
    first_held_ns: u64,
}

/// #964 Step 1: slab-resident record. Holds the canonical
/// SessionKey alongside the SessionEntry so any handle resolves to
/// both. Required because find_forward_nat_match() etc. must return
/// the canonical key, and lookup_with_origin's wheel push_to_wheel
/// needs the canonical key after dropping the entry borrow.
#[derive(Clone, Debug)]
struct SessionRecord {
    key: SessionKey,
    entry: SessionEntry,
}

pub(crate) struct SessionTable {
    /// #964 Step 1: slab-allocated session storage. Indexed by u32
    /// handle. Replaces the prior `sessions: FxHashMap<Key, Entry>`.
    entries: slab::Slab<SessionRecord>,
    /// #964 Step 1: forward-key → handle. Replaces the
    /// `sessions` HashMap's key-to-entry mapping.
    key_to_handle: FxHashMap<SessionKey, u32>,
    /// #964 Step 1: secondary indices map to u32 handles, not full keys.
    nat_reverse_index: FxHashMap<SessionKey, u32>,
    forward_wire_index: FxHashMap<SessionKey, u32>,
    reverse_translated_index: FxHashMap<SessionKey, u32>,
    /// #964 Step 1: owner-RG sets keyed by handle (was Key).
    owner_rg_sessions: FxHashMap<i32, FxHashSet<u32>>,
    deltas: VecDeque<SessionDelta>,
    last_gc_ns: u64,
    max_sessions: usize,
    timeouts: SessionTimeouts,
    epoch_counter: u64,
    expired: u64,
    create_drops: u64,
    /// #1861 §5.1: pair-admission preflight refusals — one per REFUSED
    /// FLOW (not per missing slot). Bumped by `note_admission_refused`
    /// from the new-flow refusal arms when `can_admit` fails at/near
    /// `max_sessions`. Worker-owned, single-threaded — plain u64, no
    /// atomics (mirrors `create_drops`).
    admission_refused: u64,
    /// #1861 §5.2: impossible-by-construction release residuals — an
    /// install that failed AFTER a passing `can_admit` preflight on the
    /// same descriptor iteration. Expected to stay 0 forever; nonzero
    /// means the preflight/install pairing has a bug (debug builds panic
    /// via `debug_assert!` at the call sites instead, per the #1855
    /// contract). Plain u64 like `create_drops`.
    install_partial: u64,
    delta_drops: u64,
    delta_drained: u64,
    /// #1760: cumulative count of NAT reverse-key displacement events on
    /// `nat_reverse_index`. Incremented whenever the per-flow secondary-
    /// index insert (`index_forward_nat_key_parts`, the `reverse_wire_key`
    /// insert) displaces a DIFFERENT handle for the same reverse key K —
    /// i.e. two distinct sessions resolved to the same external reverse
    /// tuple, the latent 1:N collision the #1758 research documented
    /// (interface-mode SNAT / DNAT-to-shared-backend / NAT64 / non-
    /// bijective static NAT — pool-mode SNAT is immune).
    ///
    /// This is a near-precise upper bound on live 1:N collisions, NOT an
    /// exact distinct-flow-pair count: it measures displacement *events*,
    /// so one colliding active pair can increment repeatedly as packets
    /// alternate across the per-packet re-assert (#1753). A zero counter
    /// is strong evidence the collision never fires; a nonzero value is
    /// the trigger to scope the structural fix (deferred to its own
    /// /research — this counter does NOT resolve #1760). Worker-owned,
    /// single-threaded — plain u64, no atomics (mirrors `create_drops`).
    nat_reverse_key_collisions: u64,
    /// #965: bucketed timer wheel that mirrors `entries`. Pop one
    /// bucket per tick (1 s) instead of scanning the whole HashMap.
    /// Wheel entries hold `(SessionKey, scheduled_tick)` — NOT the
    /// slab handle, because wheel lazy-delete needs a stable
    /// identifier (slab handle reuse after remove+insert would point
    /// stale wheel entries at the wrong session). See
    /// docs/pr/964-session-multi-index/plan.md §"Wheel STAYS key-based".
    wheel: SessionWheel,
    /// #965: stats from the most-recent `expire_stale_entries` call.
    /// Reset at the start of each call. Used by unit tests to assert
    /// K-bounds and classification (scanned / dropped_stale /
    /// dropped_gone / expired / re_bucketed). Accumulator overhead
    /// is 4-5 increments per popped entry — sub-µs at typical loads.
    last_pop_stats: WheelPopStats,
    /// #2134: OFF-gate for per-IP session-limit accounting. True iff any
    /// screen profile configures `limit-session source-ip-based` /
    /// `destination-ip-based`. When false (the ~99% deployment), every
    /// counter-maintenance op below short-circuits so install/remove pay
    /// nothing for an unconfigured feature (#1357 codegen-sensitivity).
    /// Set by `set_session_limit_active`, driven from the worker's
    /// forwarding/screen-profile snapshot apply.
    session_limit_active: bool,
    /// #2134: per-source-IP count of locally-admitted, forward-direction
    /// sessions (the counted-class predicate: `!is_reverse &&
    /// !origin.is_peer_synced() && !origin.is_transient_local_seed()`).
    /// Incremented at the install choke point + HA promote, decremented at
    /// the removal sink + HA demote, evicted the moment a count hits 0 so
    /// the map is bounded by distinct IPs with >=1 live local session
    /// (#2128 — no phantom-zero entries). Read non-mutating at the
    /// new-flow check.
    session_limit_src_counts: FxHashMap<IpAddr, u32>,
    /// #2134: per-destination-IP mirror of `session_limit_src_counts`.
    session_limit_dst_counts: FxHashMap<IpAddr, u32>,
}

impl SessionTable {
    pub fn new() -> Self {
        Self {
            // Start with an empty slab and let it grow on demand.
            // `Slab::with_capacity(DEFAULT_MAX_SESSIONS)` would eagerly
            // allocate a 131072-slot backing Vec per worker (Copilot
            // review finding) — the prior FxHashMap grew on demand,
            // so match that to keep baseline RSS unchanged.
            entries: slab::Slab::new(),
            key_to_handle: FxHashMap::default(),
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
            admission_refused: 0,
            install_partial: 0,
            delta_drops: 0,
            delta_drained: 0,
            nat_reverse_key_collisions: 0,
            wheel: SessionWheel::new(),
            last_pop_stats: WheelPopStats::default(),
            session_limit_active: false,
            session_limit_src_counts: FxHashMap::default(),
            session_limit_dst_counts: FxHashMap::default(),
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

    /// #2134: drive the per-IP session-limit OFF-gate from the worker's
    /// applied screen-profile snapshot. `active` is "any zone configures
    /// `limit-session source-ip-based`/`destination-ip-based`" (mirrors
    /// `ScreenState::has_advanced_features`'s limit predicate). Called at
    /// startup and on every runtime forwarding-snapshot rotation, right
    /// next to `set_timeouts` / `ScreenState::update_profiles`.
    ///
    /// Clear-on-disable: when the gate transitions to false, both count
    /// maps are cleared. Removing `limit-session` at runtime stops the
    /// decrement paths, so without this the maps would freeze at stale,
    /// over-counted values and a later re-enable would resume from wrong
    /// values and spuriously block an under-limit IP. Mirrors the
    /// `ScreenState::update_profiles` retain discipline. On a re-enable
    /// the maps start empty and re-populate from new installs;
    /// pre-existing live sessions are NOT back-counted (benign,
    /// Junos-approximate — Junos likewise does not retroactively count
    /// pre-existing flows when a screen option is enabled).
    pub fn set_session_limit_active(&mut self, active: bool) {
        if !active {
            self.session_limit_src_counts.clear();
            self.session_limit_dst_counts.clear();
        }
        self.session_limit_active = active;
    }

    /// #2134: non-mutating read of the live local-session count for a
    /// source IP. Used by the new-flow check before a session is created
    /// so the (limit+1)-th new flow from an over-limit IP is dropped.
    /// Read-only by construction — an absent IP reads 0 and never inserts
    /// a phantom entry (#2128).
    #[inline]
    pub fn session_limit_src_count(&self, ip: IpAddr) -> u32 {
        self.session_limit_src_counts.get(&ip).copied().unwrap_or(0)
    }

    /// #2134: non-mutating read of the live local-session count for a
    /// destination IP. Mirror of [`session_limit_src_count`].
    #[inline]
    pub fn session_limit_dst_count(&self, ip: IpAddr) -> u32 {
        self.session_limit_dst_counts.get(&ip).copied().unwrap_or(0)
    }

    /// #2134: increment the per-IP counts for a freshly-counted session.
    /// Caller MUST have already evaluated the counted-class predicate
    /// (`!is_reverse && !origin.is_peer_synced() &&
    /// !origin.is_transient_local_seed()`) — this helper only adds the
    /// OFF-gate guard so an unconfigured deployment pays a single branch.
    /// `saturating_add` never wraps (#1357 / overflow policy); the count
    /// is bounded by `max_sessions`.
    #[inline]
    fn session_limit_inc(&mut self, src_ip: IpAddr, dst_ip: IpAddr) {
        if !self.session_limit_active {
            return;
        }
        let c = self.session_limit_src_counts.entry(src_ip).or_insert(0);
        *c = c.saturating_add(1);
        let c = self.session_limit_dst_counts.entry(dst_ip).or_insert(0);
        *c = c.saturating_add(1);
    }

    /// #2134: decrement the per-IP counts for a removed counted session
    /// and evict the map entry the moment its count reaches 0 (#2128 —
    /// keeps the maps bounded by live counted sessions). Caller MUST have
    /// evaluated the counted-class predicate; this helper only adds the
    /// OFF-gate guard. `saturating_sub` never underflows.
    #[inline]
    fn session_limit_dec(&mut self, src_ip: IpAddr, dst_ip: IpAddr) {
        if !self.session_limit_active {
            return;
        }
        if let Some(c) = self.session_limit_src_counts.get_mut(&src_ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.session_limit_src_counts.remove(&src_ip);
            }
        }
        if let Some(c) = self.session_limit_dst_counts.get_mut(&dst_ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.session_limit_dst_counts.remove(&dst_ip);
            }
        }
    }

    /// #2134 test helper: live source-IP count-map entry count. Pins the
    /// #2128 evict-on-zero invariant (the map stays bounded; no phantom
    /// zero entries survive).
    #[cfg(test)]
    pub(crate) fn session_limit_src_map_len(&self) -> usize {
        self.session_limit_src_counts.len()
    }

    /// #2134 test helper: live destination-IP count-map entry count.
    #[cfg(test)]
    pub(crate) fn session_limit_dst_map_len(&self) -> usize {
        self.session_limit_dst_counts.len()
    }

    pub fn len(&self) -> usize {
        // Use key_to_handle (the authoritative primary index) so the
        // count reflects "installed sessions" even if the slab ever
        // held an orphan record from a partial cleanup path.
        self.key_to_handle.len()
    }

    pub fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    /// #1760: cumulative NAT reverse-key displacement events on
    /// `nat_reverse_index` (see the field doc). Published per-worker on
    /// the ~1 Hz runtime cadence and aggregated into
    /// `ProcessStatus.nat_reverse_key_collisions` for operators.
    pub fn nat_reverse_key_collisions(&self) -> u64 {
        self.nat_reverse_key_collisions
    }

    // ── #964 Step 1 internal helpers ─────────────────────────────
    //
    // Centralize key→handle and handle→record resolution so the rest
    // of the impl uses these short forms instead of repeating
    // `self.key_to_handle.get(key).and_then(|h| self.entries.get(*h as usize))`
    // throughout 30+ call sites.

    /// Resolve the slab handle for a forward-key direct lookup.
    /// Returns None if the key isn't installed.
    #[inline]
    fn handle_for_key(&self, key: &SessionKey) -> Option<u32> {
        self.key_to_handle.get(key).copied()
    }

    /// Resolve to a slab record from a forward-key. Returns None if
    /// the key is unknown, the handle is stale, OR the resolved
    /// record's canonical key doesn't match the lookup key (defense
    /// vs reused-slot hazard — Copilot review).
    #[inline]
    fn record_by_key(&self, key: &SessionKey) -> Option<&SessionRecord> {
        let handle = self.handle_for_key(key)?;
        let record = self.entries.get(handle as usize)?;
        if record.key != *key {
            return None;
        }
        Some(record)
    }

    /// Mut version of `record_by_key`. Same key-equality validation.
    #[inline]
    fn record_by_key_mut(&mut self, key: &SessionKey) -> Option<&mut SessionRecord> {
        let handle = self.handle_for_key(key)?;
        let record = self.entries.get_mut(handle as usize)?;
        if record.key != *key {
            return None;
        }
        Some(record)
    }

    /// Convenience: borrow the entry only (skipping the canonical
    /// key field). Used by call sites that don't need the key.
    #[inline]
    fn entry_by_key(&self, key: &SessionKey) -> Option<&SessionEntry> {
        self.record_by_key(key).map(|r| &r.entry)
    }

    #[inline]
    fn entry_by_key_mut(&mut self, key: &SessionKey) -> Option<&mut SessionEntry> {
        self.record_by_key_mut(key).map(|r| &mut r.entry)
    }

    #[inline]
    fn contains_key(&self, key: &SessionKey) -> bool {
        self.key_to_handle.contains_key(key)
    }

    /// Update the last-seen timestamp for a session (prevents GC expiry).
    /// Used by the flow cache to amortize session keepalive.
    #[inline]
    pub fn touch(&mut self, key: &SessionKey, now_ns: u64) {
        if self.entry_by_key_mut(key).is_some_and(|e| {
            e.last_seen_ns = now_ns;
            true
        }) {
            self.push_to_wheel(key, now_ns);
        }
    }

    /// #2220: per-session keepalive throttle for the flow-cache fast
    /// path. Refreshes the matched session's `last_seen_ns` ONLY when it
    /// has gone idle for at least `expires_after_ns / SESSION_KEEPALIVE_DIVISOR`
    /// — i.e. it is a quarter of the way to its OWN expiry. This bounds
    /// every cache-served session's age to `(1 + 1/N) × expires_after_ns`
    /// regardless of co-resident flow rates, so an actively-forwarding
    /// cached flow can never be GC'd mid-flow.
    ///
    /// Why this replaces the prior binding-global modulo-64 counter: that
    /// counter incremented across ALL flows on the binding and touched
    /// only the flow that happened to land on a global multiple of 64.
    /// A low-rate flow co-resident with a saturating flow could be served
    /// entirely from the cache for the whole timeout window without its
    /// session ever being touched, then be reaped while still forwarding
    /// (HA Close delta to the peer + BPF redirect-key deletion + a stale
    /// flow-cache descriptor out-living its session). See issue #2220.
    ///
    /// HOT PATH: a single `key_to_handle` hash probe (the same probe
    /// `touch` performs) plus a Copy field read; the `last_seen_ns` write
    /// and the throttled `push_to_wheel` run only when actually stale, so
    /// the steady-state per-cache-hit cost is one lookup and an integer
    /// compare. Allocation-free.
    #[inline]
    pub fn touch_if_stale(&mut self, key: &SessionKey, now_ns: u64) {
        let stale = match self.record_by_key(key) {
            Some(record) => {
                let last_seen = record.entry.last_seen_ns;
                let refresh_after = record
                    .entry
                    .expires_after_ns
                    .max(SESSION_KEEPALIVE_DIVISOR)
                    / SESSION_KEEPALIVE_DIVISOR;
                now_ns.saturating_sub(last_seen) >= refresh_after
            }
            None => return,
        };
        if stale {
            self.touch(key, now_ns);
        }
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
    #[inline]
    pub fn update_session(&mut self, req: SessionUpdate<'_>, ha_activation: bool) -> bool {
        let SessionUpdate {
            key,
            decision,
            metadata,
            origin,
            now_ns,
            protocol,
            tcp_flags,
        } = req;
        // #1752 Path E: in-place refresh. The prior implementation did
        // `remove_entry` + mutate + `restore_entry`, which tore down and rebuilt
        // every index (key_to_handle map, slab slot with a NEW handle, all four
        // secondary indices) plus ~3 SessionMetadata clones on EVERY packet of an
        // established flow, only to bump timestamps. We now mutate the slab record
        // in place, gating secondary-index REMOVES on key-relevant input changes
        // (nat / is_reverse / owner_rg_id) while still re-asserting
        // secondary-index ADDS every refresh (restore_entry parity). Behavior is
        // byte-identical (modulo the opaque slab handle value); see
        // docs/pr/1752-session-inplace-refresh/plan.md.
        let Some(&handle) = self.key_to_handle.get(key) else {
            return false;
        };
        // Stale-handle + primary-key guard (parity with remove_entry): never
        // index the slab raw — a stale key_to_handle could point at a vacant or
        // reused slot. On mismatch behave like remove_entry returning None.
        //
        // #1855 contract: a stale/vacant mapping is impossible-by-construction
        // (single-writer `&mut self`, #964 eager cleanup), so debug builds
        // assert loudly (logic-bug detector) while release builds tolerate and
        // return false without touching the reused-slot session — the
        // remove_entry #964 "release-mode safety net" precedent. See
        // docs/research/1855-inplace-contract/plan.md.
        let Some(record) = self.entries.get(handle as usize) else {
            debug_assert!(
                false,
                "update_session: key_to_handle had stale handle {} for {:?}",
                handle, key
            );
            return false;
        };
        if record.key != *key {
            debug_assert!(false, "update_session: stale key_to_handle for {:?}", key);
            return false;
        }
        // Snapshot the OLD index-relevant + collision-relevant state (all Copy).
        let old_origin = record.entry.origin;
        let old_nat = record.entry.decision.nat;
        let old_is_reverse = record.entry.metadata.is_reverse;
        let old_owner_rg = record.entry.metadata.owner_rg_id;

        if !ha_activation {
            let new_peer = origin.is_peer_synced();
            // Reject: both peer-synced (refresh_local on a synced entry) OR peer
            // data trying to overwrite a local entry. The prior code reached this
            // via remove_entry + restore_entry + return false, and restore_entry
            // unconditionally re-asserts the entry's own secondary ADDS. To stay
            // byte-identical (incl. re-winning a displaced secondary-index
            // collision), re-assert the OLD adds before bailing.
            let should_reject_update = new_peer;
            if should_reject_update {
                self.index_forward_nat_key_parts(
                    key,
                    handle,
                    old_nat,
                    old_is_reverse,
                    old_owner_rg,
                );
                return false;
            }
            // Else: peer→local promote, or local→local refresh — fall through.
        }
        let was_peer_synced = old_origin.is_peer_synced();

        // Reindex only when a secondary-index input changed (§2 of the plan:
        // indices depend only on key + nat + is_reverse + owner_rg_id, and key +
        // handle are invariant here). Gates only the value-guarded REMOVES.
        let reindex = old_nat != decision.nat
            || old_is_reverse != metadata.is_reverse
            || old_owner_rg != metadata.owner_rg_id;
        if reindex {
            self.remove_forward_nat_index_parts(key, handle, old_nat, old_is_reverse);
            remove_owner_rg_index_entry(&mut self.owner_rg_sessions, old_owner_rg, handle);
        }

        let epoch = self.next_epoch();
        {
            let record = self
                .entries
                .get_mut(handle as usize)
                .expect("handle validated above");
            record.entry.decision = decision;
            record.entry.metadata = metadata.clone();
            record.entry.origin = origin;
            record.entry.install_epoch = epoch;
            record.entry.last_seen_ns = now_ns;
            record.entry.expires_after_ns = session_timeout_ns(protocol, tcp_flags, &self.timeouts);
            record.entry.closing = matches!(protocol, PROTO_TCP) && is_closing(tcp_flags);
            // wheel_tick deliberately preserved (parity with restore_entry).
            // #2120: a real-traffic refresh (or a peer→local promote) means
            // this entry now genuinely lives on this node — it leaves the
            // held world. Clear the hold clock so the stale-synced ceiling
            // restarts cleanly if it is ever held again, and reset the
            // self-healed-epoch to the never-self-healed default (a later
            // SELF-HEAL, if this node forwards the RG, records the live
            // epoch; the HOLD branch never writes seen_rg_epoch).
            record.entry.first_held_ns = 0;
            record.entry.seen_rg_epoch = 0;
        }
        // Always re-assert the secondary ADDS — byte-identical to restore_entry's
        // unconditional index_forward_nat_key. For the no-reindex case this
        // re-inserts the same keys→handle (idempotent when unique, re-wins on a
        // collision); for the reindex case it installs the NEW keys after the
        // removes above.
        self.index_forward_nat_key_parts(
            key,
            handle,
            decision.nat,
            metadata.is_reverse,
            metadata.owner_rg_id,
        );
        // #965: schedule the refreshed entry. Last_seen / expires_after were
        // rewritten above; push_to_wheel is throttled and will only emit a new
        // wheel entry if the canonical tick changed.
        self.push_to_wheel(key, now_ns);
        // Emit open delta when promoting a peer-synced entry to local
        if was_peer_synced && !origin.is_peer_synced() && !metadata.is_reverse {
            // #2134: an in-place promote synced→local turns an uncounted
            // peer-synced session into a counted local one WITHOUT going
            // through the install choke point, so the per-IP count must
            // be incremented explicitly here (same counted-class gate as
            // the Open-delta push). `!is_transient_local_seed()` holds:
            // a promote target is never a MissingNeighborSeed (those are
            // never peer-synced). Capture the Copy IPs before `key` is
            // moved into the delta below.
            let (sip, dip) = (key.src_ip, key.dst_ip);
            self.session_limit_inc(sip, dip);
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
            .entry_by_key(key)
            .map(|e| e.origin)
            .unwrap_or(SessionOrigin::ForwardFlow);
        let protocol = key.protocol;
        self.update_session(
            SessionUpdate {
                key,
                decision,
                metadata,
                origin,
                now_ns,
                protocol,
                tcp_flags,
            },
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
            .entry_by_key(key)
            .map(|e| e.origin)
            .unwrap_or(SessionOrigin::ForwardFlow);
        let protocol = key.protocol;
        self.update_session(
            SessionUpdate {
                key,
                decision,
                metadata,
                origin,
                now_ns,
                protocol,
                tcp_flags,
            },
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
        // #1752 Path E: in-place (mirrors update_session, minus collision rules
        // — this path always applies). No expires_after_ns / closing rewrite,
        // matching the prior behavior.
        let Some(&handle) = self.key_to_handle.get(key) else {
            return false;
        };
        // #1855 contract (same as update_session's guards): impossible state
        // by construction — debug asserts, release tolerates + returns false.
        let Some(record) = self.entries.get(handle as usize) else {
            debug_assert!(
                false,
                "refresh_for_ha_transition: stale handle {} for {:?}",
                handle, key
            );
            return false;
        };
        if record.key != *key {
            debug_assert!(
                false,
                "refresh_for_ha_transition: stale key_to_handle for {:?}",
                key
            );
            return false;
        }
        let old_nat = record.entry.decision.nat;
        let old_is_reverse = record.entry.metadata.is_reverse;
        let old_owner_rg = record.entry.metadata.owner_rg_id;
        // Capture the new index parts before `metadata` is moved into the record.
        let new_nat = decision.nat;
        let new_is_reverse = metadata.is_reverse;
        let new_owner_rg = metadata.owner_rg_id;

        let reindex =
            old_nat != new_nat || old_is_reverse != new_is_reverse || old_owner_rg != new_owner_rg;
        if reindex {
            self.remove_forward_nat_index_parts(key, handle, old_nat, old_is_reverse);
            remove_owner_rg_index_entry(&mut self.owner_rg_sessions, old_owner_rg, handle);
        }

        let epoch = self.next_epoch();
        {
            let record = self
                .entries
                .get_mut(handle as usize)
                .expect("handle validated above");
            record.entry.decision = decision;
            record.entry.metadata = metadata;
            record.entry.install_epoch = epoch;
            record.entry.last_seen_ns = now_ns;
            // #2120: promotion refresh re-stamps `last_seen_ns` (the entry
            // now ages from a full timeout on the promoted node), so it
            // leaves the held world. Clear the hold clock and reset the
            // observed epoch (§6.4 write-site contract). NOTE: the
            // edge-triggered self-heal in the expire pass leaves
            // `first_held_ns` UNTOUCHED — only a genuine departure from the
            // held state (here, real-traffic refresh, or re-import) clears
            // it, so a flapping RG cannot reset the leak ceiling.
            record.entry.first_held_ns = 0;
            record.entry.seen_rg_epoch = 0;
        }
        self.index_forward_nat_key_parts(key, handle, new_nat, new_is_reverse, new_owner_rg);
        // #965: schedule the refreshed entry for expiration check.
        self.push_to_wheel(key, now_ns);
        true
    }

    /// Promote a peer-synced session to local ownership.
    /// Convenience wrapper around update_session that hides the
    /// `ha_activation` flag (always false on this path).
    #[inline]
    pub fn promote_synced_with_origin(&mut self, req: SessionUpdate<'_>) -> bool {
        self.update_session(req, false)
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

    fn push_delta(&mut self, delta: SessionDelta) {
        if self.deltas.len() >= MAX_SESSION_DELTAS {
            self.delta_drops = self.delta_drops.saturating_add(1);
            return;
        }
        self.deltas.push_back(delta);
    }

    /// #964 Step 1: centralized session removal. Eager-cleanup
    /// invariant — every handle-valued internal index MUST be
    /// cleaned BEFORE the slab slot is returned to the free list.
    /// All session removal goes through this helper.
    fn remove_entry(&mut self, key: &SessionKey) -> Option<SessionEntry> {
        let handle = self.key_to_handle.remove(key)?;
        // Read the record (still in slab) to learn what to clean.
        // `.get` not `.remove` — we'll remove from slab last.
        // Fallible: a stale key_to_handle pointing at a freed slot
        // returns None and we restore the mapping. Should never
        // fire under correct cleanup; release-mode safety net
        // (Copilot review — was `.expect()` which panicked).
        let Some(record) = self.entries.get(handle as usize) else {
            debug_assert!(
                false,
                "remove_entry: key_to_handle had stale handle {} for {:?}",
                handle, key
            );
            // Restore the primary-index mapping so a failed remove
            // doesn't mutate len() / leave the table inconsistent
            // (Codex round-3 finding).
            self.key_to_handle.insert(key.clone(), handle);
            return None;
        };
        // PRIMARY-KEY GUARD: defend against a stale key_to_handle
        // pointing at a reused slab slot for a different session.
        // Should never fire under correct cleanup; release-mode
        // safety net (returns None instead of corrupting another
        // session's indices).
        if record.key != *key {
            debug_assert!(false, "remove_entry: stale key_to_handle for {:?}", key);
            self.key_to_handle.insert(key.clone(), handle);
            return None;
        }
        let decision = record.entry.decision;
        let metadata = record.entry.metadata.clone();
        // #2134: snapshot the counted-class predicate inputs (all Copy)
        // before the borrow ends so the per-IP count can be decremented
        // for a removed counted session. This is the sole removal sink —
        // expire, explicit delete (clear / RST / fabric-cancel /
        // promote-purge), and take_synced_local all funnel through here,
        // so the decrement cannot be forgotten by a future delete site.
        let removed_origin = record.entry.origin;
        let removed_is_reverse = metadata.is_reverse;
        // Borrow on `record` ends here; subsequent calls take
        // &mut self (cleanup helpers) without conflict.
        let _ = record;
        // Clean every handle-valued internal index. Each cleanup is
        // VALUE-GUARDED via guarded_remove — only remove if the
        // stored handle still equals our handle. Mirrors today's
        // matches!(... existing == key) pattern.
        self.remove_forward_nat_index(key, handle, decision, &metadata);
        remove_owner_rg_index_entry(&mut self.owner_rg_sessions, metadata.owner_rg_id, handle);
        // Mandatory debug assertion: NO handle-valued index still
        // points at the freed handle. Catches eager-cleanup
        // invariant violations before slab slot reuse.
        debug_assert!(
            self.no_index_points_at(handle),
            "remove_entry leaked handle {} in a secondary index",
            handle
        );
        // Only AFTER all indices are clean, return slot to slab.
        let record = self.entries.remove(handle as usize);
        // #2134: decrement the per-IP count for a removed counted
        // session (success path ONLY — the two early `None` guards above
        // RESTORE the mapping and do not remove, so they must not
        // decrement). Same counted-class predicate the install choke
        // point used to increment.
        if !removed_is_reverse
            && !removed_origin.is_peer_synced()
            && !removed_origin.is_transient_local_seed()
        {
            self.session_limit_dec(key.src_ip, key.dst_ip);
        }
        Some(record.entry)
    }

    /// #964 Step 1: re-insert an entry that was just `remove_entry`'d.
    /// Returns None always — kept return type for API compatibility
    /// with the prior FxHashMap-based shape.
    ///
    /// #1752 Path E: no longer used by the refresh paths (`update_session` /
    /// `refresh_for_ha_transition` now mutate in place). Retained as the
    /// reference half of the remove+restore round-trip the differential tests
    /// compare against, so in release builds it is retained as dead-code-allowed
    /// test reference logic (not conditionally compiled out).
    #[cfg_attr(not(test), allow(dead_code))]
    fn restore_entry(&mut self, key: SessionKey, entry: SessionEntry) -> Option<SessionEntry> {
        let record = SessionRecord {
            key: key.clone(),
            entry,
        };
        let raw = self.entries.insert(record);
        let handle: u32 = raw.try_into().expect("slab handle exceeds u32");
        self.key_to_handle.insert(key.clone(), handle);
        // Clone metadata + decision out of the slab record for
        // index_forward_nat_key (which takes &mut self).
        let (decision, metadata) = {
            let record = &self.entries[handle as usize];
            (record.entry.decision, record.entry.metadata.clone())
        };
        self.index_forward_nat_key(&key, handle, decision, &metadata);
        None
    }

    /// #964 Step 1: insert all secondary indices for a freshly-stored
    /// session. Mirrors today's gates exactly:
    /// - reverse_translated_index for reverse entries when translated
    ///   != key.
    /// - nat_reverse_index for reverse_wire (always) and
    ///   reverse_canonical (when != key) on forward entries.
    /// - forward_wire_index ONLY when forward_wire != key
    ///   (Codex round-4 finding #2 — was unconditional in v4).
    /// - owner_rg_sessions ONLY when owner_rg_id > 0
    ///   (Codex round-4 finding #2).
    fn index_forward_nat_key(
        &mut self,
        key: &SessionKey,
        handle: u32,
        decision: SessionDecision,
        metadata: &SessionMetadata,
    ) {
        self.index_forward_nat_key_parts(
            key,
            handle,
            decision.nat,
            metadata.is_reverse,
            metadata.owner_rg_id,
        );
    }

    /// #1752 Path E: secondary-index insert from the Copy parts the index
    /// actually depends on (`nat`, `is_reverse`, `owner_rg_id`). Lets the
    /// in-place refresh path re-assert (and reindex) without cloning a
    /// `SessionMetadata` / `SessionDecision`. `index_forward_nat_key` delegates
    /// here so the two stay bit-identical.
    fn index_forward_nat_key_parts(
        &mut self,
        key: &SessionKey,
        handle: u32,
        nat: NatDecision,
        is_reverse: bool,
        owner_rg_id: i32,
    ) {
        if is_reverse {
            let translated = translated_session_key(key, nat);
            if translated != *key {
                self.reverse_translated_index.insert(translated, handle);
            }
        } else {
            // #1760: detect the NAT reverse-key 1:N collision cheaply.
            // FxHashMap::insert returns the displaced value, so a
            // collision is observable with no extra lookup on this
            // per-packet re-assert path (#1753). A displaced handle that
            // differs from the one we are installing means a DIFFERENT
            // session previously owned this reverse key K — the latent
            // 1:N collision (#1758). Value-guarded removal keeps the
            // displaced handle near-always live, so this is a near-precise
            // upper bound on live collisions. See the field doc.
            let prev = self
                .nat_reverse_index
                .insert(reverse_wire_key(key, nat), handle);
            if matches!(prev, Some(old) if old != handle) {
                self.nat_reverse_key_collisions =
                    self.nat_reverse_key_collisions.saturating_add(1);
            }
            let reverse_canonical = reverse_canonical_key(key, nat);
            if reverse_canonical != *key {
                self.nat_reverse_index.insert(reverse_canonical, handle);
            }
            let forward_wire = forward_wire_key(key, nat);
            if forward_wire != *key {
                self.forward_wire_index.insert(forward_wire, handle);
            }
        }
        if owner_rg_id > 0 {
            self.owner_rg_sessions
                .entry(owner_rg_id)
                .or_default()
                .insert(handle);
        }
    }

    /// #964 Step 1: value-guarded removal of secondary indices —
    /// only remove an index entry if its stored handle still equals
    /// the handle we're removing. Mirrors today's `matches!(... existing == key)`
    /// shape, just keyed on u32 handle instead of SessionKey.
    fn remove_forward_nat_index(
        &mut self,
        key: &SessionKey,
        handle: u32,
        decision: SessionDecision,
        metadata: &SessionMetadata,
    ) {
        self.remove_forward_nat_index_parts(key, handle, decision.nat, metadata.is_reverse);
    }

    /// #1752 Path E: value-guarded secondary-index removal from the Copy parts
    /// (`nat`, `is_reverse`). Used by the in-place reindex teardown so it needs
    /// no `SessionMetadata`/`SessionDecision` clone. `remove_forward_nat_index`
    /// delegates here.
    fn remove_forward_nat_index_parts(
        &mut self,
        key: &SessionKey,
        handle: u32,
        nat: NatDecision,
        is_reverse: bool,
    ) {
        if is_reverse {
            let translated = translated_session_key(key, nat);
            if matches!(
                self.reverse_translated_index.get(&translated),
                Some(stored) if *stored == handle
            ) {
                self.reverse_translated_index.remove(&translated);
            }
            return;
        }
        let reverse_wire = reverse_wire_key(key, nat);
        if matches!(self.nat_reverse_index.get(&reverse_wire), Some(stored) if *stored == handle) {
            self.nat_reverse_index.remove(&reverse_wire);
        }
        let reverse_canonical = reverse_canonical_key(key, nat);
        if matches!(
            self.nat_reverse_index.get(&reverse_canonical),
            Some(stored) if *stored == handle
        ) {
            self.nat_reverse_index.remove(&reverse_canonical);
        }
        let forward_wire = forward_wire_key(key, nat);
        if matches!(self.forward_wire_index.get(&forward_wire), Some(stored) if *stored == handle) {
            self.forward_wire_index.remove(&forward_wire);
        }
    }

    /// #964 Step 1 mandatory debug assertion: scan every
    /// handle-valued internal index for the freed handle. Used by
    /// `remove_entry` to enforce the eager-cleanup invariant in
    /// debug builds. O(N) per call — acceptable for tests, no-op in
    /// release.
    #[cfg(debug_assertions)]
    fn no_index_points_at(&self, handle: u32) -> bool {
        !self.key_to_handle.values().any(|h| *h == handle)
            && !self.nat_reverse_index.values().any(|h| *h == handle)
            && !self.forward_wire_index.values().any(|h| *h == handle)
            && !self.reverse_translated_index.values().any(|h| *h == handle)
            && !self
                .owner_rg_sessions
                .values()
                .any(|set| set.contains(&handle))
    }

    #[cfg(not(debug_assertions))]
    #[inline]
    fn no_index_points_at(&self, _handle: u32) -> bool {
        true
    }
}

pub(crate) const fn default_max_sessions() -> usize {
    DEFAULT_MAX_SESSIONS
}

fn remove_owner_rg_index_entry(
    index: &mut FxHashMap<i32, FxHashSet<u32>>,
    owner_rg_id: i32,
    handle: u32,
) {
    if owner_rg_id <= 0 {
        return;
    }
    if let Some(entries) = index.get_mut(&owner_rg_id) {
        entries.remove(&handle);
        if entries.is_empty() {
            index.remove(&owner_rg_id);
        }
    }
}

fn session_timeout_ns(protocol: u8, tcp_flags: u8, timeouts: &SessionTimeouts) -> u64 {
    match protocol {
        PROTO_TCP => {
            if is_closing(tcp_flags) {
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

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
