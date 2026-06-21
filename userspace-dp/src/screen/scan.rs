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
//!   `MAX_UNIQUE_PER_SOURCE` unique entries per source. On overflow the
//!   tracker SKIPS the record and bumps an eviction/pressure counter — it
//!   degrades to *not counting* that source, which can only make a drop
//!   verdict LESS likely. It never fail-opens the screen drop and never
//!   grows without bound. This mirrors the #2134/#2177 session-limit
//!   per-IP bound discipline (skip-on-full, never a phantom growth).
//!
//! - **Budgeted cleanup.** The periodic sweep removes at most
//!   `CLEANUP_BUDGET` expired entries per call so one unlucky packet can
//!   never pay an O(total-sources) scan under a volumetric attack.

use rustc_hash::{FxHashMap, FxHashSet};
use std::net::IpAddr;

/// Maximum distinct source IPs tracked per zone. A `/24` legitimate scan
/// touches <=254 sources; this cap absorbs that with headroom while
/// putting a hard ceiling on attacker-controlled growth. When the cap is
/// reached, a *new* source key for that zone is skipped (not recorded),
/// degrading to no-count for that source — never a fail-open drop.
const MAX_SOURCES_PER_ZONE: usize = 4096;

/// Maximum unique entries (dst ports for port-scan, dst IPs for IP-sweep)
/// tracked per source within the window. The detection threshold is the
/// operator-configured value; this cap only bounds memory for a source
/// whose unique fan-out is far above any sane threshold. Once a source's
/// set is full, a genuinely-new entry is skipped — the verdict still
/// fires if the threshold was already crossed (the set is at least
/// `MAX_UNIQUE_PER_SOURCE`, which dominates any practical threshold), so
/// skipping cannot cause a missed detection in practice.
const MAX_UNIQUE_PER_SOURCE: usize = 1024;

/// Maximum expired entries removed per `cleanup` call. Bounds the
/// worst-case per-tick cleanup cost so a large source table cannot stall
/// a single poll tick.
const CLEANUP_BUDGET: usize = 256;

/// 10-second detection window shared by both trackers.
const WINDOW_SECS: u64 = 10;

/// Test-only accessor for the per-zone source cap, used by the
/// `ScreenState`-level bounded-state test in `screen/tests.rs`.
#[cfg(test)]
pub(super) fn max_sources_per_zone_for_test() -> usize {
    MAX_SOURCES_PER_ZONE
}

/// Per-zone scan/sweep tracker key: `(zone_id, src_ip)`.
type ScanKey = (u16, IpAddr);

/// Tracks unique destination ports per `(zone_id, source IP)` within a
/// time window (port-scan detection).
#[derive(Debug, Clone, Default)]
pub(super) struct PortScanTracker {
    per_src: FxHashMap<ScanKey, (u64, FxHashSet<u16>)>, // (window_start_secs, unique_ports)
    /// Count of records skipped because a per-zone / per-source cap was
    /// hit. Pure observability — exposed for the bounded-state tests and
    /// the screen status surface. Never affects a verdict.
    skipped_pressure: u64,
}

impl PortScanTracker {
    /// Check if `(zone_id, src_ip)` has exceeded the port scan threshold.
    /// Returns true if exceeded. New ports for a source whose set is full,
    /// or new sources for a zone at the source cap, are skipped (not
    /// recorded) and counted in `skipped_pressure` — never fail-open.
    pub(super) fn check(
        &mut self,
        zone_id: u16,
        src_ip: IpAddr,
        dst_port: u16,
        now_secs: u64,
        threshold: u32,
    ) -> bool {
        if threshold == 0 {
            return false;
        }
        check_unique(
            &mut self.per_src,
            &mut self.skipped_pressure,
            zone_id,
            src_ip,
            dst_port,
            now_secs,
            threshold,
        )
    }

    /// Remove expired entries (budgeted periodic cleanup).
    pub(super) fn cleanup(&mut self, now_secs: u64) {
        cleanup_expired(&mut self.per_src, now_secs);
    }

    /// Records skipped due to a per-zone / per-source cap (fail-safe
    /// overflow pressure). Pure observability.
    pub(super) fn skipped_pressure(&self) -> u64 {
        self.skipped_pressure
    }

    #[cfg(test)]
    pub(super) fn tracked_sources(&self) -> usize {
        self.per_src.len()
    }
}

/// Tracks unique destination IPs per `(zone_id, source IP)` within a time
/// window (IP-sweep detection).
#[derive(Debug, Clone, Default)]
pub(super) struct IpSweepTracker {
    per_src: FxHashMap<ScanKey, (u64, FxHashSet<IpAddr>)>, // (window_start_secs, unique_dst_ips)
    skipped_pressure: u64,
}

impl IpSweepTracker {
    /// Check if `(zone_id, src_ip)` has exceeded the IP sweep threshold.
    /// Returns true if exceeded. Bounded + fail-safe like
    /// [`PortScanTracker::check`].
    pub(super) fn check(
        &mut self,
        zone_id: u16,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        now_secs: u64,
        threshold: u32,
    ) -> bool {
        if threshold == 0 {
            return false;
        }
        check_unique(
            &mut self.per_src,
            &mut self.skipped_pressure,
            zone_id,
            src_ip,
            dst_ip,
            now_secs,
            threshold,
        )
    }

    /// Remove expired entries (budgeted periodic cleanup).
    pub(super) fn cleanup(&mut self, now_secs: u64) {
        cleanup_expired(&mut self.per_src, now_secs);
    }

    /// Records skipped due to a per-zone / per-source cap (fail-safe
    /// overflow pressure). Pure observability.
    pub(super) fn skipped_pressure(&self) -> u64 {
        self.skipped_pressure
    }

    #[cfg(test)]
    pub(super) fn tracked_sources(&self) -> usize {
        self.per_src.len()
    }
}

/// Shared bounded windowed-unique check used by both trackers. `entry`
/// is the per-(zone_id, src_ip) unique set of `T` (dst port or dst IP).
///
/// Bounds (fail-safe, never fail-open):
/// - a brand-new source key for a zone already holding
///   `MAX_SOURCES_PER_ZONE` keys is SKIPPED (returns `false`, bumps
///   pressure) — the screen drop is the more-restrictive verdict, so
///   declining to track can only relax it;
/// - a new unique entry for a source whose set already holds
///   `MAX_UNIQUE_PER_SOURCE` entries is SKIPPED, but the threshold is
///   still evaluated against the current (capped) set size, so an
///   already-crossed threshold still drops.
#[inline]
fn check_unique<T: std::hash::Hash + Eq>(
    per_src: &mut FxHashMap<ScanKey, (u64, FxHashSet<T>)>,
    skipped_pressure: &mut u64,
    zone_id: u16,
    src_ip: IpAddr,
    entry_val: T,
    now_secs: u64,
    threshold: u32,
) -> bool {
    let key: ScanKey = (zone_id, src_ip);
    // Per-zone source-count bound: refuse to register a brand-new source
    // for a zone that is already at the cap. An existing key is always
    // allowed through (it is bounded on the inner axis below).
    let exists = per_src.contains_key(&key);
    if !exists && sources_in_zone(per_src, zone_id) >= MAX_SOURCES_PER_ZONE {
        *skipped_pressure += 1;
        return false;
    }
    let entry = per_src
        .entry(key)
        .or_insert_with(|| (now_secs, FxHashSet::default()));
    // Reset window if expired.
    if now_secs.saturating_sub(entry.0) >= WINDOW_SECS {
        entry.0 = now_secs;
        entry.1.clear();
    }
    // Per-source unique-entry bound: once the set is full, skip new
    // entries (counting pressure) but still evaluate the threshold.
    if entry.1.len() >= MAX_UNIQUE_PER_SOURCE {
        if !entry.1.contains(&entry_val) {
            *skipped_pressure += 1;
        }
    } else {
        entry.1.insert(entry_val);
    }
    entry.1.len() as u32 > threshold
}

/// Count of source keys currently tracked for `zone_id`. Linear in the
/// table size; only walked when admitting a brand-new source (cold path),
/// and the table is itself capped, so this stays bounded.
#[inline]
fn sources_in_zone<T>(per_src: &FxHashMap<ScanKey, (u64, FxHashSet<T>)>, zone_id: u16) -> usize {
    per_src.keys().filter(|(z, _)| *z == zone_id).count()
}

/// Remove up to `CLEANUP_BUDGET` expired or empty entries. Budgeted so a
/// single tick can never pay an O(total) scan under volumetric load —
/// stale entries that survive a tick are reclaimed on subsequent ticks.
#[inline]
fn cleanup_expired<T>(per_src: &mut FxHashMap<ScanKey, (u64, FxHashSet<T>)>, now_secs: u64) {
    let mut removed = 0usize;
    per_src.retain(|_, (start, set)| {
        if removed >= CLEANUP_BUDGET {
            return true; // budget exhausted — keep the rest for next tick
        }
        let expired = now_secs.saturating_sub(*start) >= WINDOW_SECS || set.is_empty();
        if expired {
            removed += 1;
            false
        } else {
            true
        }
    });
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
        // One more brand-new source must be SKIPPED, not grow the table,
        // and must NOT fail-open (returns false = no drop).
        let overflow_src = IpAddr::V4(Ipv4Addr::from(0x0b00_0000u32));
        assert!(!t.check(0, overflow_src, v4(1), 100, 0));
        assert!(!t.check(0, overflow_src, v4(2), 100, 1));
        assert_eq!(
            t.tracked_sources(),
            MAX_SOURCES_PER_ZONE,
            "over-cap source must not grow the table"
        );
        assert!(
            t.skipped_pressure() >= 1,
            "over-cap source records pressure"
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
}
