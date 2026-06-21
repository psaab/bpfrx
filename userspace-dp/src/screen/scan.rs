//! Port-scan + IP-sweep windowed trackers used by the advanced screen
//! checks. Each tracks a per-`(zone_id, source-IP)` unique-set over a
//! 10-second detection window.
//!
//! #2209 — per-zone + bounded:
//!
//! - **Per-zone keying.** Junos screen thresholds are read from the
//!   per-zone screen profile, so the scan/sweep history MUST be keyed by
//!   `(zone_id, src_ip)`. A single global per-src tracker (the pre-#2209
//!   shape) bled one zone's scan activity into another zone's threshold
//!   evaluation — a `wan`-side scan could trip (or mask) the `dmz`
//!   threshold for one `dmz` packet from the same source.
//!
//! - **Bounded, fail-safe state.** The backing maps are attacker-driven
//!   (a spoofed-source flood multiplies the source keys; a fan-out flood
//!   multiplies the inner unique entries). Both axes are capped:
//!   `MAX_SOURCES_PER_ZONE` distinct source keys per zone and
//!   `MAX_UNIQUE_PER_SOURCE` unique entries per source. On the UNIQUE-entry
//!   axis the set is capped, but the detection threshold is CLAMPED to
//!   `MAX_UNIQUE_PER_SOURCE - 1` so a source that fills the set ALWAYS
//!   crosses it: a threshold larger than the cap detects AT THE CAP rather
//!   than never (fail-CLOSED, #2227 MAJOR-1). The maps never grow without
//!   bound. This mirrors the #2134/#2177 session-limit per-IP bound
//!   discipline (skip-on-full, never a phantom growth) plus a fail-closed
//!   clamp on the inner axis.
//!
//! - **Bounded stalest-eviction on source-axis saturation (#2234).** The
//!   per-zone source cap was originally a HARD cliff: once a zone held
//!   `MAX_SOURCES_PER_ZONE` keys a brand-new `(zone, src_ip)` was SKIPPED
//!   (bumping `skipped_pressure`). That is fail-safe for forwarding but a
//!   DETECTION-DoS: a high-cardinality spoofed flood fills the table and a
//!   subsequently-arriving REAL scanner is never tracked — and so never
//!   detected — until `WINDOW_SECS` expiry, which the attacker can defer
//!   indefinitely by keeping its 4096 sources fresh. The new-source path now
//!   makes BOUNDED room instead of skipping: it scans a FIXED PREFIX of the
//!   source table (`iter().take(EVICT_SCAN_LIMIT)` — the budget counts EVERY
//!   iterated entry, same-zone or not), reclaims the first expired same-zone
//!   window it finds, and if none is expired evicts the stalest (oldest
//!   `window_start`) same-zone entry within that prefix. Because this branch
//!   only runs when the TARGET zone alone holds `>= MAX_SOURCES_PER_ZONE`
//!   keys, same-zone entries are dense in the table and the prefix reliably
//!   contains a victim, so a fresh real scanner is admissible. The
//!   per-new-flow worst case is O(`EVICT_SCAN_LIMIT`), NOT an O(sources)
//!   min-scan over the whole table (a full scan on every new flow under a
//!   saturation flood would itself be an O(n)-per-packet amplifier). In the
//!   pathological many-zones-sparsely-interleaved case where the prefix holds
//!   no same-zone entry, the path degrades back to skip-on-full
//!   (`skipped_pressure`) — still bounded, never fail-open. The per-zone
//!   source count is tracked in `per_zone_count` so the cap test is O(1); the
//!   only walk is the bounded prefix. Each eviction bumps `evicted_pressure`,
//!   and a rare logarithmic threshold crossing surfaces a
//!   `scan-table-pressure` screen event (see `take_pressure_event`) so the
//!   operator is told the detector is saturated — never a per-flow log.
//!
//! - **Budgeted cleanup.** The periodic sweep walks the source table
//!   (`HashMap::retain`, O(sources)) but removes at most `CLEANUP_BUDGET`
//!   expired entries per call, so the per-tick MUTATION cost is bounded even
//!   though the scan is not. The real ceiling on the walk is the
//!   `MAX_SOURCES_PER_ZONE` per-zone source cap, which bounds the table size
//!   itself; the budget just spreads reclamation across ticks.

use rustc_hash::{FxHashMap, FxHashSet};
use std::net::IpAddr;

/// Maximum distinct source IPs tracked per zone. A `/24` legitimate scan
/// touches <=254 sources; this cap absorbs that with headroom while
/// putting a hard ceiling on attacker-controlled growth. When the cap is
/// reached, a *new* source key for that zone is skipped (not recorded),
/// degrading to no-count for that source — never a fail-open drop.
const MAX_SOURCES_PER_ZONE: usize = 4096;

/// Maximum unique entries (dst ports for port-scan, dst IPs for IP-sweep)
/// tracked per source within the window. This caps memory for a source
/// whose unique fan-out is large; the bounded set can hold at most
/// `MAX_UNIQUE_PER_SOURCE` entries.
///
/// **Fail-CLOSED clamp (#2227 MAJOR-1).** The operator-configured
/// threshold is unbounded (`strconv.Atoi`, no clamp), so it can legitimately
/// exceed this cap (e.g. `port-scan threshold 5000`). The detection compares
/// `set.len() > threshold`, but `len()` can never exceed `MAX_UNIQUE_PER_SOURCE`.
/// If the comparison used the raw threshold, a threshold `>= MAX_UNIQUE_PER_SOURCE`
/// could NEVER be crossed and the scanner would NEVER be dropped — a silent
/// fail-OPEN. To preserve the fail-closed contract, [`check_unique`] clamps the
/// EFFECTIVE comparison threshold to `MAX_UNIQUE_PER_SOURCE - 1`, so a source
/// that fills the bounded set ALWAYS crosses it and is dropped (detection fires
/// AT THE CAP rather than never). The clamp is counted in `threshold_clamped`
/// so it is visible. The Go control plane mirrors this maximum
/// (`pkg/config/compiler_security.go` `maxScanSweepThreshold`) and emits a
/// commit-time WARNING when an operator threshold exceeds it — the two
/// constants MUST stay in sync.
const MAX_UNIQUE_PER_SOURCE: usize = 1024;

/// Maximum expired entries removed per `cleanup` call. Bounds the
/// worst-case per-tick cleanup cost so a large source table cannot stall
/// a single poll tick.
const CLEANUP_BUDGET: usize = 256;

/// Hard upper bound on the number of `per_src` entries examined while
/// looking for an eviction victim on the source-saturation path (#2234).
/// The new-flow worst case is O(`EVICT_SCAN_LIMIT`), NOT O(sources): a full
/// min-scan over all `MAX_SOURCES_PER_ZONE` entries on every new flow under
/// a saturation flood would itself be an O(n)-per-packet DoS amplifier. We
/// instead sample a fixed prefix of the table and evict the stalest
/// same-zone entry found within it. Under the realistic single-zone flood
/// the entire table is the target zone, so the first sampled entries are
/// always same-zone victims; the limit only matters in the pathological
/// many-zones-sparsely-interleaved case, where eviction degrades gracefully
/// back to skip-on-full (still bounded, never fail-open).
const EVICT_SCAN_LIMIT: usize = 64;

/// 10-second detection window shared by both trackers.
const WINDOW_SECS: u64 = 10;

/// Compile-time guard: the eviction sample must be smaller than the per-zone
/// source cap, otherwise the "sample a prefix" bound would be meaningless
/// (it would scan the whole table). It must also be non-empty so the
/// new-source path can always find a victim under a single-zone flood.
const _: () = assert!(EVICT_SCAN_LIMIT > 0 && EVICT_SCAN_LIMIT < MAX_SOURCES_PER_ZONE);

/// Test-only accessor for the per-zone source cap, used by the
/// `ScreenState`-level bounded-state test in `screen/tests.rs`.
#[cfg(test)]
pub(super) fn max_sources_per_zone_for_test() -> usize {
    MAX_SOURCES_PER_ZONE
}

/// Test-only accessor for the per-source unique-entry cap, used by the
/// `ScreenState`-level fail-closed clamp test in `screen/tests.rs` (#2227
/// MAJOR-1). The supported maximum operator threshold is this value minus 1.
#[cfg(test)]
pub(super) fn max_unique_per_source_for_test() -> usize {
    MAX_UNIQUE_PER_SOURCE
}

/// Test-only accessor for the bounded eviction sample limit (#2234), used by
/// the bounded-cost eviction test in `screen/tests.rs`.
#[cfg(test)]
pub(super) fn evict_scan_limit_for_test() -> usize {
    EVICT_SCAN_LIMIT
}

/// Per-zone scan/sweep tracker key: `(zone_id, src_ip)`.
type ScanKey = (u16, IpAddr);

/// Shared bounded windowed-unique tracker core (#2209/#2227/#2234). Both
/// the port-scan (`T = u16`) and IP-sweep (`T = IpAddr`) trackers are thin
/// `T`-specialised wrappers over this single implementation so the bound /
/// eviction / pressure logic exists in exactly ONE place (engineering-style
/// "one source of truth" — the pre-#2234 free functions duplicated the
/// formula across the two trackers).
#[derive(Debug, Clone)]
struct ScanCore<T: std::hash::Hash + Eq> {
    per_src: FxHashMap<ScanKey, (u64, FxHashSet<T>)>, // (window_start_secs, unique entries)
    /// Live count of distinct source keys per zone. Maintained on every
    /// insert / removal so the per-zone cap test is O(1) (#2234) — the
    /// pre-#2234 code walked every key to count one zone (`sources_in_zone`,
    /// O(sources)), which on the new-source-at-cap path under a saturation
    /// flood is O(n) per packet.
    per_zone_count: FxHashMap<u16, u32>,
    /// Count of records skipped because a per-source unique-entry cap was
    /// hit, or because eviction could not free a same-zone slot within the
    /// bounded sample (rare). Pure observability — exposed for the
    /// bounded-state tests and the screen status surface. Never affects a
    /// verdict.
    skipped_pressure: u64,
    /// Count of stalest-eviction events on the source-saturation path
    /// (#2234): a brand-new source displaced an expired-or-stalest existing
    /// source so a fresh real scanner stays trackable. Pure observability.
    evicted_pressure: u64,
    /// Count of checks whose operator threshold exceeded the supported
    /// maximum (`MAX_UNIQUE_PER_SOURCE - 1`) and was clamped to it
    /// (fail-closed clamp, #2227 MAJOR-1). Pure observability — surfaces an
    /// operator misconfiguration (threshold the bounded set can never reach
    /// un-clamped) without changing the (clamped) verdict.
    threshold_clamped: u64,
    /// Next `evicted_pressure` value at which a `scan-table-pressure` screen
    /// event should be surfaced. Grows geometrically (see
    /// [`ScanCore::take_pressure_event`]) so the operator alarm fires at a
    /// LOGARITHMIC rate — never per-flow — even under a sustained flood.
    pressure_event_at: u64,
}

impl<T: std::hash::Hash + Eq> Default for ScanCore<T> {
    fn default() -> Self {
        Self {
            per_src: FxHashMap::default(),
            per_zone_count: FxHashMap::default(),
            skipped_pressure: 0,
            evicted_pressure: 0,
            threshold_clamped: 0,
            // First eviction surfaces an event; thereafter the bar doubles.
            pressure_event_at: 1,
        }
    }
}

impl<T: std::hash::Hash + Eq> ScanCore<T> {
    /// Bounded windowed-unique check. `entry_val` is the per-(zone_id,
    /// src_ip) unique entry (dst port or dst IP).
    ///
    /// Bounds (fail-safe, never fail-OPEN):
    /// - a brand-new source key for a zone already holding
    ///   `MAX_SOURCES_PER_ZONE` keys triggers a BOUNDED stalest-eviction
    ///   (#2234): the stalest (or any expired) entry within an
    ///   `EVICT_SCAN_LIMIT`-sized sample of the zone is removed to admit the
    ///   fresh source, so a real scanner is always trackable. Only if the
    ///   bounded sample finds no same-zone victim (pathological many-zone
    ///   interleave) does it fall back to skip-on-full (bumps
    ///   `skipped_pressure`, returns `false`) — still bounded, never
    ///   fail-open;
    /// - a new unique entry for a source whose set already holds
    ///   `MAX_UNIQUE_PER_SOURCE` entries is SKIPPED, but the threshold is
    ///   still evaluated against the current (capped) set size;
    /// - the EFFECTIVE comparison threshold is CLAMPED to
    ///   `MAX_UNIQUE_PER_SOURCE - 1` (#2227 MAJOR-1). The set can hold at
    ///   most `MAX_UNIQUE_PER_SOURCE` entries, so an operator threshold
    ///   `>= MAX_UNIQUE_PER_SOURCE` could otherwise NEVER be crossed by
    ///   `len() > threshold` — a silent fail-OPEN where the scanner is never
    ///   dropped. Clamping guarantees a source that fills the bounded set
    ///   ALWAYS crosses the effective threshold: detection fires AT THE CAP
    ///   rather than never. The clamp is counted in `threshold_clamped` and
    ///   the Go control plane warns at commit time when a threshold exceeds
    ///   the supported maximum.
    #[inline]
    fn check(
        &mut self,
        zone_id: u16,
        src_ip: IpAddr,
        entry_val: T,
        now_secs: u64,
        threshold: u32,
    ) -> bool {
        if threshold == 0 {
            return false;
        }
        // Fail-closed clamp: the bounded set tops out at
        // MAX_UNIQUE_PER_SOURCE, so the comparison `len() > effective` can
        // only ever fire if `effective <= MAX_UNIQUE_PER_SOURCE - 1`. A
        // larger operator threshold is clamped here (and counted) so
        // detection fires at the cap instead of never. MAX_UNIQUE_PER_SOURCE
        // fits a u32, so the cast and subtraction are safe.
        let max_effective = (MAX_UNIQUE_PER_SOURCE - 1) as u32;
        let effective_threshold = if threshold > max_effective {
            self.threshold_clamped += 1;
            max_effective
        } else {
            threshold
        };
        let key: ScanKey = (zone_id, src_ip);
        let exists = self.per_src.contains_key(&key);
        // Per-zone source-count bound. A brand-new source for a zone at the
        // cap makes BOUNDED room by eviction (#2234) instead of the old
        // hard skip-on-full cliff. An existing key is always allowed through
        // (it is bounded on the inner axis below).
        if !exists && self.zone_count(zone_id) >= MAX_SOURCES_PER_ZONE {
            if !self.evict_stalest_in_zone(zone_id, now_secs) {
                // No same-zone victim within the bounded sample (pathological
                // many-zone interleave). Preserve the fail-safe: skip, never
                // fail-open. Cost is still O(EVICT_SCAN_LIMIT).
                self.skipped_pressure += 1;
                return false;
            }
        }
        let newly_inserted = !exists;
        let entry = self
            .per_src
            .entry(key)
            .or_insert_with(|| (now_secs, FxHashSet::default()));
        if newly_inserted {
            *self.per_zone_count.entry(zone_id).or_insert(0) += 1;
        }
        // Reset window if expired.
        if now_secs.saturating_sub(entry.0) >= WINDOW_SECS {
            entry.0 = now_secs;
            entry.1.clear();
        }
        // Per-source unique-entry bound: once the set is full, skip new
        // entries (counting pressure) but still evaluate the threshold.
        if entry.1.len() >= MAX_UNIQUE_PER_SOURCE {
            if !entry.1.contains(&entry_val) {
                self.skipped_pressure += 1;
            }
        } else {
            entry.1.insert(entry_val);
        }
        entry.1.len() as u32 > effective_threshold
    }

    /// O(1) per-zone source count (maintained incrementally).
    #[inline]
    fn zone_count(&self, zone_id: u16) -> usize {
        self.per_zone_count.get(&zone_id).copied().unwrap_or(0) as usize
    }

    /// Evict one same-zone source so a fresh source can be admitted under
    /// source-axis saturation (#2234). Examines at most `EVICT_SCAN_LIMIT`
    /// `per_src` entries TOTAL (a FIXED prefix of the iterator, NOT the whole
    /// table) and removes the FIRST expired same-zone entry it finds, or —
    /// failing that — the STALEST (oldest `window_start`) same-zone entry
    /// within the sample.
    ///
    /// Cost: O(`EVICT_SCAN_LIMIT`), independent of the table size, because the
    /// budget counts EVERY iterated entry (same-zone or not) — so even a
    /// pathological many-zones-interleaved table cannot turn this into an
    /// O(n)-per-packet amplifier. This branch only runs when the TARGET zone
    /// alone holds `>= MAX_SOURCES_PER_ZONE` keys, so same-zone entries are
    /// dense in the table and the fixed prefix reliably contains a victim;
    /// in the rare event the sample holds no same-zone entry, the caller
    /// falls back to skip-on-full (still bounded, never fail-open).
    /// Returns `true` if a victim was evicted (count decremented,
    /// `evicted_pressure` bumped), `false` otherwise.
    #[inline]
    fn evict_stalest_in_zone(&mut self, zone_id: u16, now_secs: u64) -> bool {
        let mut stalest_key: Option<ScanKey> = None;
        let mut stalest_start = u64::MAX;
        let mut expired_victim: Option<ScanKey> = None;
        // Hard total-iteration bound: take a fixed prefix of the iterator.
        for (k, (start, set)) in self.per_src.iter().take(EVICT_SCAN_LIMIT) {
            if k.0 != zone_id {
                continue; // not a candidate, but still counts against the bound
            }
            // An expired-or-empty window is dead weight — evict it first.
            if now_secs.saturating_sub(*start) >= WINDOW_SECS || set.is_empty() {
                expired_victim = Some(*k);
                break;
            }
            if *start < stalest_start {
                stalest_start = *start;
                stalest_key = Some(*k);
            }
        }
        let victim = expired_victim.or(stalest_key);
        if let Some(victim) = victim {
            if self.per_src.remove(&victim).is_some() {
                if let Some(c) = self.per_zone_count.get_mut(&zone_id) {
                    *c = c.saturating_sub(1);
                }
                self.evicted_pressure += 1;
                return true;
            }
        }
        false
    }

    /// Remove up to `CLEANUP_BUDGET` expired or empty entries.
    /// `HashMap::retain` still WALKS every entry (O(sources)), but the number
    /// REMOVED per call is budgeted — so the per-tick mutation/rehash cost is
    /// bounded, and stale entries that survive a tick are reclaimed on
    /// subsequent ticks. The walk itself is bounded only by the
    /// `MAX_SOURCES_PER_ZONE` cap on the table. The per-zone count is
    /// decremented for each removed key so the eviction cap test stays exact.
    #[inline]
    fn cleanup(&mut self, now_secs: u64) {
        let mut removed = 0usize;
        let per_zone_count = &mut self.per_zone_count;
        self.per_src.retain(|key, (start, set)| {
            if removed >= CLEANUP_BUDGET {
                return true; // budget exhausted — keep the rest for next tick
            }
            let expired = now_secs.saturating_sub(*start) >= WINDOW_SECS || set.is_empty();
            if expired {
                removed += 1;
                if let Some(c) = per_zone_count.get_mut(&key.0) {
                    *c = c.saturating_sub(1);
                }
                false
            } else {
                true
            }
        });
    }

    /// Returns `true` once each time the cumulative eviction count crosses a
    /// geometric threshold (1, 2, 4, 8, ...). Surfacing a `scan-table-
    /// pressure` screen event on this rare transition (#2234) tells the
    /// operator the detector is saturated — at a LOGARITHMIC rate, never
    /// per-flow, so a sustained flood produces a handful of alarms rather
    /// than a per-packet log storm (CLAUDE.md logging rules). Consumes the
    /// crossing (idempotent until the next boundary).
    #[inline]
    fn take_pressure_event(&mut self) -> bool {
        if self.evicted_pressure >= self.pressure_event_at {
            // Advance to the next power-of-two boundary above the current
            // count so repeated calls within the same epoch do not re-fire.
            // `checked_next_power_of_two` returns None when no power of two
            // fits in u64 (count > 2^63); saturate to u64::MAX there so the
            // gate never panics/wraps and simply stops firing (the alarm has
            // long since been raised). Cannot regress below the current bar.
            self.pressure_event_at = self
                .evicted_pressure
                .saturating_add(1)
                .checked_next_power_of_two()
                .unwrap_or(u64::MAX);
            true
        } else {
            false
        }
    }
}

/// Tracks unique destination ports per `(zone_id, source IP)` within a
/// time window (port-scan detection). Thin wrapper over [`ScanCore`].
#[derive(Debug, Clone, Default)]
pub(super) struct PortScanTracker {
    core: ScanCore<u16>,
}

impl PortScanTracker {
    /// Check if `(zone_id, src_ip)` has exceeded the port scan threshold.
    /// Returns true if exceeded. Bounded + fail-safe (see [`ScanCore::check`]).
    pub(super) fn check(
        &mut self,
        zone_id: u16,
        src_ip: IpAddr,
        dst_port: u16,
        now_secs: u64,
        threshold: u32,
    ) -> bool {
        self.core.check(zone_id, src_ip, dst_port, now_secs, threshold)
    }

    /// Remove expired entries (budgeted periodic cleanup).
    pub(super) fn cleanup(&mut self, now_secs: u64) {
        self.core.cleanup(now_secs);
    }

    /// Records skipped due to a per-source unique-entry cap or a failed
    /// bounded eviction (fail-safe overflow pressure). Pure observability.
    pub(super) fn skipped_pressure(&self) -> u64 {
        self.core.skipped_pressure
    }

    /// Stalest-evictions on the source-saturation path (#2234). Pure
    /// observability.
    pub(super) fn evicted_pressure(&self) -> u64 {
        self.core.evicted_pressure
    }

    /// Checks whose operator threshold was clamped to the supported maximum
    /// (`MAX_UNIQUE_PER_SOURCE - 1`). Pure observability (#2227 MAJOR-1).
    pub(super) fn threshold_clamped(&self) -> u64 {
        self.core.threshold_clamped
    }

    /// Rare (logarithmic) pressure-event transition for the operator alarm
    /// (#2234). See [`ScanCore::take_pressure_event`].
    pub(super) fn take_pressure_event(&mut self) -> bool {
        self.core.take_pressure_event()
    }

    #[cfg(test)]
    pub(super) fn tracked_sources(&self) -> usize {
        self.core.per_src.len()
    }
}

/// Tracks unique destination IPs per `(zone_id, source IP)` within a time
/// window (IP-sweep detection). Thin wrapper over [`ScanCore`].
#[derive(Debug, Clone, Default)]
pub(super) struct IpSweepTracker {
    core: ScanCore<IpAddr>,
}

impl IpSweepTracker {
    /// Check if `(zone_id, src_ip)` has exceeded the IP sweep threshold.
    /// Returns true if exceeded. Bounded + fail-safe (see [`ScanCore::check`]).
    pub(super) fn check(
        &mut self,
        zone_id: u16,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        now_secs: u64,
        threshold: u32,
    ) -> bool {
        self.core.check(zone_id, src_ip, dst_ip, now_secs, threshold)
    }

    /// Remove expired entries (budgeted periodic cleanup).
    pub(super) fn cleanup(&mut self, now_secs: u64) {
        self.core.cleanup(now_secs);
    }

    /// Records skipped due to a per-source unique-entry cap or a failed
    /// bounded eviction (fail-safe overflow pressure). Pure observability.
    pub(super) fn skipped_pressure(&self) -> u64 {
        self.core.skipped_pressure
    }

    /// Stalest-evictions on the source-saturation path (#2234). Pure
    /// observability.
    pub(super) fn evicted_pressure(&self) -> u64 {
        self.core.evicted_pressure
    }

    /// Checks whose operator threshold was clamped to the supported maximum
    /// (`MAX_UNIQUE_PER_SOURCE - 1`). Pure observability (#2227 MAJOR-1).
    pub(super) fn threshold_clamped(&self) -> u64 {
        self.core.threshold_clamped
    }

    /// Rare (logarithmic) pressure-event transition for the operator alarm
    /// (#2234). See [`ScanCore::take_pressure_event`].
    pub(super) fn take_pressure_event(&mut self) -> bool {
        self.core.take_pressure_event()
    }

    #[cfg(test)]
    pub(super) fn tracked_sources(&self) -> usize {
        self.core.per_src.len()
    }
}

#[cfg(test)]
mod scan_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, a))
    }

    #[test]
    fn port_scan_keyed_per_zone_no_cross_count() {
        let mut t = PortScanTracker::default();
        let src = v4(1);
        // Threshold 2: zone 1 sees 3 ports → would trip if global.
        assert!(!t.check(1, src, 80, 100, 2));
        assert!(!t.check(1, src, 443, 100, 2));
        // Zone 2 from the SAME src, only 1 port — must NOT inherit zone 1's
        // history. A global tracker would already be at 2 here and trip on
        // the next port.
        assert!(!t.check(2, src, 22, 100, 2));
        assert!(!t.check(2, src, 23, 100, 2));
        // Zone 2's third unique port crosses ITS own threshold.
        assert!(t.check(2, src, 24, 100, 2));
        // Zone 1's third unique port crosses zone 1's threshold,
        // independent of zone 2.
        assert!(t.check(1, src, 8080, 100, 2));
    }

    #[test]
    fn ip_sweep_keyed_per_zone_no_cross_count() {
        let mut t = IpSweepTracker::default();
        let src = v4(1);
        assert!(!t.check(1, src, v4(10), 100, 2));
        assert!(!t.check(1, src, v4(11), 100, 2));
        // Zone 2 starts fresh for the same src.
        assert!(!t.check(2, src, v4(20), 100, 2));
        assert!(!t.check(2, src, v4(21), 100, 2));
        assert!(t.check(2, src, v4(22), 100, 2));
        assert!(t.check(1, src, v4(12), 100, 2));
    }

    #[test]
    fn source_table_bounded_and_not_fail_open() {
        let mut t = IpSweepTracker::default();
        // Fill zone 0 to the source cap with distinct sources (threshold
        // high enough that none trips, so nothing is evicted by detection).
        for i in 0..MAX_SOURCES_PER_ZONE {
            let src = IpAddr::V4(Ipv4Addr::from((0x0a00_0000u32) + i as u32));
            assert!(!t.check(0, src, v4(1), 100, 1_000_000));
        }
        assert_eq!(t.tracked_sources(), MAX_SOURCES_PER_ZONE);
        assert_eq!(t.skipped_pressure(), 0);
        assert_eq!(t.evicted_pressure(), 0);
        // #2234: one more brand-new source must NOW be admitted by BOUNDED
        // stalest-eviction (not skipped), so a fresh real scanner is always
        // trackable — and must NOT fail-open (returns false = no drop). The
        // table must STAY bounded at the cap (eviction made room, the table
        // never grows).
        let overflow_src = IpAddr::V4(Ipv4Addr::from(0x0b00_0000u32));
        assert!(!t.check(0, overflow_src, v4(1), 100, 0));
        assert!(!t.check(0, overflow_src, v4(2), 100, 1));
        assert_eq!(
            t.tracked_sources(),
            MAX_SOURCES_PER_ZONE,
            "eviction must keep the table bounded at the cap, not grow it"
        );
        assert!(
            t.evicted_pressure() >= 1,
            "admitting an over-cap source records eviction pressure"
        );
    }

    #[test]
    fn threshold_above_cap_still_fires_fail_closed() {
        // #2227 MAJOR-1 fail-on-revert: an IP-sweep at a threshold ABOVE the
        // per-source unique cap (e.g. 3000, which parses/validates fine on
        // the Go side) must STILL fire detection. Pre-fix the comparison was
        // `len() as u32 > threshold`, but `len()` tops out at
        // MAX_UNIQUE_PER_SOURCE (1024) < 3000, so the scanner was NEVER
        // dropped — a silent fail-OPEN. The clamp makes the bounded set's
        // worst case (full = MAX_UNIQUE_PER_SOURCE) always cross the effective
        // threshold (MAX_UNIQUE_PER_SOURCE - 1).
        let mut t = IpSweepTracker::default();
        let src = v4(1);
        let threshold: u32 = 3000;
        assert!(
            threshold as usize > MAX_UNIQUE_PER_SOURCE,
            "test premise: threshold must exceed the per-source cap"
        );
        // Sweep more distinct destinations than the cap. The set saturates at
        // MAX_UNIQUE_PER_SOURCE; once it does, the effective (clamped)
        // threshold is crossed and the check returns a drop.
        let mut fired = false;
        for i in 0..(MAX_UNIQUE_PER_SOURCE + 50) {
            let dst = IpAddr::V4(Ipv4Addr::from(0x0e00_0000u32 + i as u32));
            if t.check(0, src, dst, 100, threshold) {
                fired = true;
                break;
            }
        }
        assert!(
            fired,
            "IP-sweep with threshold {threshold} (> cap {MAX_UNIQUE_PER_SOURCE}) must fire \
             detection — pre-fix it NEVER fired (silent fail-open)"
        );
        assert!(
            t.threshold_clamped() >= 1,
            "an over-cap threshold must be recorded as clamped, got {}",
            t.threshold_clamped()
        );
    }

    #[test]
    fn threshold_at_cap_minus_one_is_max_unclamped() {
        // Boundary: a threshold of exactly MAX_UNIQUE_PER_SOURCE - 1 is the
        // largest value that is NOT clamped. The (MAX_UNIQUE_PER_SOURCE)th
        // unique entry crosses it. (We cannot drive 1023 distinct entries
        // cheaply here without a large loop; assert the no-clamp accounting
        // on a single representative check.)
        let mut t = PortScanTracker::default();
        let src = v4(1);
        let at_max = (MAX_UNIQUE_PER_SOURCE - 1) as u32;
        // One SYN at the boundary threshold: not clamped, not yet crossed.
        assert!(!t.check(0, src, 80, 100, at_max));
        assert_eq!(
            t.threshold_clamped(),
            0,
            "threshold == MAX_UNIQUE_PER_SOURCE-1 must NOT be clamped"
        );
        // One above the boundary IS clamped.
        let mut t2 = PortScanTracker::default();
        assert!(!t2.check(0, src, 80, 100, at_max + 1));
        assert_eq!(
            t2.threshold_clamped(),
            1,
            "threshold == MAX_UNIQUE_PER_SOURCE must be clamped"
        );
    }

    #[test]
    fn per_source_unique_entries_bounded() {
        let mut t = IpSweepTracker::default();
        let src = v4(1);
        // High threshold so detection never evicts; flood unique dst IPs
        // past the per-source cap.
        for i in 0..(MAX_UNIQUE_PER_SOURCE + 100) {
            let dst = IpAddr::V4(Ipv4Addr::from(0x0c00_0000u32 + i as u32));
            t.check(7, src, dst, 100, u32::MAX);
        }
        // The inner set is capped; the surplus is recorded as pressure.
        assert_eq!(t.tracked_sources(), 1);
        assert!(
            t.skipped_pressure() >= 100,
            "surplus unique entries record pressure: {}",
            t.skipped_pressure()
        );
    }

    #[test]
    fn window_expiry_resets_per_key() {
        let mut t = PortScanTracker::default();
        let src = v4(1);
        assert!(!t.check(3, src, 80, 100, 2));
        assert!(!t.check(3, src, 443, 100, 2));
        assert!(t.check(3, src, 22, 100, 2));
        // After the window elapses the set resets and the count restarts.
        assert!(!t.check(3, src, 8080, 100 + WINDOW_SECS, 2));
    }

    #[test]
    fn cleanup_is_budgeted() {
        let mut t = IpSweepTracker::default();
        // Seed more expired entries than the budget; one cleanup call must
        // remove at most CLEANUP_BUDGET so the per-tick cost is bounded.
        let seed = CLEANUP_BUDGET + 50;
        for i in 0..seed {
            let src = IpAddr::V4(Ipv4Addr::from(0x0d00_0000u32 + i as u32));
            t.check(0, src, v4(1), 0, 1_000_000);
        }
        assert_eq!(t.tracked_sources(), seed);
        // Far past the window — all are expired, but one sweep removes only
        // up to the budget.
        t.cleanup(1_000);
        assert_eq!(t.tracked_sources(), seed - CLEANUP_BUDGET);
    }

    /// #2234 fail-on-revert: a brand-new REAL scanner that arrives AFTER the
    /// per-zone source table is saturated must still be tracked AND detected.
    /// Pre-#2234 the new source was SKIPPED on a full table (returns false,
    /// only bumps `skipped_pressure`), so a high-cardinality spoofed flood
    /// could suppress detection of a subsequently-arriving genuine scanner
    /// indefinitely — a detection-DoS. Reverting `evict_stalest_in_zone` to
    /// the skip-on-full cliff breaks this test (the scanner never fires).
    #[test]
    fn fresh_scanner_tracked_and_detected_after_saturation() {
        let mut t = IpSweepTracker::default();
        // Fill zone 0 to the cap with spoofed sources at an OLD window so the
        // stalest-eviction has clear victims. High threshold so none of them
        // trips (the flood is high-cardinality, low-per-source fan-out).
        let flood_t = 0u64;
        for i in 0..MAX_SOURCES_PER_ZONE {
            let src = IpAddr::V4(Ipv4Addr::from(0x0a00_0000u32 + i as u32));
            assert!(!t.check(0, src, v4(1), flood_t, 1_000_000));
        }
        assert_eq!(t.tracked_sources(), MAX_SOURCES_PER_ZONE);
        // A real scanner arrives later, sweeping many destinations with a low
        // threshold. Even though the table is full, it must be admitted by
        // eviction and cross its threshold.
        let scanner = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let threshold = 5u32;
        let now = flood_t + 1; // still inside the flood's window
        let mut fired = false;
        for d in 0..(threshold + 3) {
            let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, d as u8));
            if t.check(0, scanner, dst, now, threshold) {
                fired = true;
                break;
            }
        }
        assert!(
            fired,
            "a fresh real scanner arriving after saturation MUST be tracked \
             and detected (pre-#2234 it was skipped on a full table → never \
             detected)"
        );
        // The table must remain bounded (eviction made room, not growth).
        assert_eq!(
            t.tracked_sources(),
            MAX_SOURCES_PER_ZONE,
            "eviction keeps the table at the cap"
        );
        assert!(t.evicted_pressure() >= 1, "admission recorded an eviction");
    }

    /// #2234: eviction must prefer the STALEST (oldest `window_start`) entry
    /// over fresher ones when no entry is expired. We fill a small synthetic
    /// zone to the cap is too expensive here, so exercise the victim-choice
    /// logic on `ScanCore` directly via the public `check` path with a cap
    /// reduced by construction is not possible (the cap is a const) — instead
    /// assert the property on the eviction helper through a saturated table:
    /// the source whose window is oldest is the one removed.
    #[test]
    fn eviction_prefers_stalest_window() {
        let mut core: ScanCore<u16> = ScanCore::default();
        // Seed a handful of zone-9 entries with DISTINCT, increasing window
        // starts so exactly one is the stalest. (Direct ScanCore access keeps
        // this O(few) instead of filling 4096 cap entries.) Each set is
        // NON-EMPTY and the window is FRESH so the expired-or-empty branch
        // never fires — the victim choice is decided purely by window_start.
        let mut nonempty = |p: u16| {
            let mut s = FxHashSet::default();
            s.insert(p);
            s
        };
        let stale_src = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1));
        core.per_src.insert((9, stale_src), (100, nonempty(1)));
        for i in 2..=8u32 {
            let s = IpAddr::V4(Ipv4Addr::from(0x0a09_0000u32 + i));
            core.per_src
                .insert((9, s), (200 + i as u64, nonempty(i as u16)));
        }
        *core.per_zone_count.entry(9).or_insert(0) = core.per_src.len() as u32;
        let before = core.per_src.len();
        // `now` close to the stalest start so NOTHING is expired (force the
        // stalest-not-expired branch).
        let now = 105u64;
        assert!(
            core.evict_stalest_in_zone(9, now),
            "a same-zone victim must be found"
        );
        assert_eq!(core.per_src.len(), before - 1, "exactly one evicted");
        assert!(
            !core.per_src.contains_key(&(9, stale_src)),
            "the STALEST (window_start=100) entry must be the one evicted, \
             not a fresher one"
        );
        assert_eq!(core.evicted_pressure, 1);
    }

    /// #2234: eviction prefers an EXPIRED window even if it is not the
    /// numerically-oldest in iteration order — dead weight is reclaimed first.
    #[test]
    fn eviction_prefers_expired_window() {
        let mut core: ScanCore<u16> = ScanCore::default();
        let expired_src = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 50));
        // One expired entry plus several fresh ones.
        core.per_src
            .insert((9, expired_src), (0, FxHashSet::default()));
        for i in 1..=5u32 {
            let s = IpAddr::V4(Ipv4Addr::from(0x0a09_1000u32 + i));
            let mut set = FxHashSet::default();
            set.insert(i as u16);
            core.per_src.insert((9, s), (1_000, set));
        }
        *core.per_zone_count.entry(9).or_insert(0) = core.per_src.len() as u32;
        // now far past the expired window but inside the fresh entries'.
        let now = 1_000 + WINDOW_SECS - 1;
        assert!(core.evict_stalest_in_zone(9, now));
        assert!(
            !core.per_src.contains_key(&(9, expired_src)),
            "the EXPIRED entry must be reclaimed first"
        );
    }

    /// #2234 bounded-cost guard: the eviction sample is FIXED
    /// (`EVICT_SCAN_LIMIT`), never an O(sources) scan. With many more
    /// same-zone entries than the limit, one eviction must examine at most
    /// the limit and still succeed — and the per-zone count is maintained
    /// exactly across repeated admit-with-eviction so the cap test stays O(1).
    #[test]
    fn eviction_is_bounded_and_count_exact() {
        assert!(
            evict_scan_limit_for_test() < MAX_SOURCES_PER_ZONE,
            "the sample must be a fixed PREFIX, not the whole table"
        );
        let mut t = PortScanTracker::default();
        // Saturate zone 4.
        for i in 0..MAX_SOURCES_PER_ZONE {
            let src = IpAddr::V4(Ipv4Addr::from(0x0a04_0000u32 + i as u32));
            assert!(!t.check(4, src, 80, 0, 1_000_000));
        }
        assert_eq!(t.tracked_sources(), MAX_SOURCES_PER_ZONE);
        // Admit many fresh sources; each must evict one (bounded) and the
        // table size must never exceed the cap.
        for i in 0..1024u32 {
            let fresh = IpAddr::V4(Ipv4Addr::from(0x0b04_0000u32 + i));
            t.check(4, fresh, 80, 1, 1_000_000);
            assert!(
                t.tracked_sources() <= MAX_SOURCES_PER_ZONE,
                "the table must never exceed the cap under sustained churn"
            );
        }
        assert_eq!(
            t.tracked_sources(),
            MAX_SOURCES_PER_ZONE,
            "sustained admit-with-eviction keeps the table exactly at the cap"
        );
        assert!(t.evicted_pressure() >= 1024);
        assert_eq!(t.skipped_pressure(), 0, "single-zone flood never skips");
    }

    /// #2234: the per-zone count is decremented on budgeted cleanup so the
    /// O(1) cap test stays exact after entries age out.
    #[test]
    fn per_zone_count_tracks_cleanup() {
        let mut core: ScanCore<u16> = ScanCore::default();
        for i in 0..10u32 {
            let s = IpAddr::V4(Ipv4Addr::from(0x0a05_0000u32 + i));
            core.check(5, s, 80, 0, 1_000_000);
        }
        assert_eq!(core.zone_count(5), 10);
        // Age everything out; cleanup removes them and the count follows.
        core.cleanup(1_000);
        assert_eq!(core.zone_count(5), 0, "count decremented on cleanup");
        assert_eq!(core.per_src.len(), 0);
    }

    /// #2234: the pressure-event transition fires at a LOGARITHMIC rate
    /// (powers of two), never per eviction — so a sustained flood yields a
    /// handful of operator alarms, not a per-flow log storm.
    #[test]
    fn pressure_event_is_logarithmic() {
        let mut core: ScanCore<u16> = ScanCore::default();
        let mut events = 0u32;
        // Simulate 1000 evictions, asking for a pressure event after each.
        for _ in 0..1000u64 {
            core.evicted_pressure += 1;
            if core.take_pressure_event() {
                events += 1;
            }
        }
        // 1000 evictions cross boundaries 1,2,4,...,512 → 10 events.
        assert_eq!(
            events, 10,
            "pressure events must be logarithmic in eviction count, got {events}"
        );
    }
}
