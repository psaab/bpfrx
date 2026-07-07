//! Per-zone per-key flood rate limiter — a count-min sketch of `RateCounter`s
//! (#3315 SYN-flood per-source/per-destination; #4112 ICMP/UDP per-destination).
//!
//! `source-threshold` and `destination-threshold` cap the SYN/s rate for a
//! single source IP or destination IP, distinct from the aggregate per-zone
//! `attack-threshold`. The aggregate counter cannot express them: a single hot
//! destination (a victim, possibly flooded from spoofed sources) can be driven
//! hard while the zone aggregate stays under budget, and `destination-threshold`
//! exists precisely to cap that.
//!
//! The same substrate backs the per-destination ICMP/UDP flood caps (#4112):
//! Junos measures `icmp flood` / `udp flood threshold` PER DESTINATION (UDP
//! additionally per destination PORT), not per zone aggregate. `increment` keys
//! on the destination IP (ICMP); `increment_ip_port` mixes the destination port
//! in (UDP). The per-zone aggregate `RateCounter` is retained as a coarser
//! SECONDARY ceiling above these per-destination caps.
//!
//! ## Substrate — count-min sketch of `RateCounter`s, NO eviction
//!
//! The limiter is a **count-min sketch (CMS)**: `ROWS` independent rows of
//! `cols` `RateCounter`s. A key (an IP) maps, via `ROWS` INDEPENDENT seeded
//! hashes, to one cell per row. `increment` advances and counts the key in all
//! `ROWS` cells and reports whether it is over the threshold.
//!
//! Trip ⟺ EVERY one of the `ROWS` cells reports over-threshold. Because the
//! smallest over-threshold cell implies all cells exceed it, this is exactly
//! the classic CMS `min`-read (`min_i(trailing_sum_i) > threshold`). It is
//! implemented as the logical **AND** of the per-row `increment` results — and
//! it MUST be AND/MIN, never OR/MAX: an OR/MAX inversion would blow the
//! false-positive rate from `(load)^ROWS` to `~ROWS*load`, and the "victim
//! always trips" test cannot catch that inversion (the victim trips under both).
//! A dedicated test (`some_but_not_all_rows_does_not_trip`) pins the AND.
//!
//! ### Why a count-min sketch and not an eviction cache
//!
//! Any BOUNDED *eviction* structure (set-associative cache, stalest-eviction
//! hash map) has two collision-starvation modes a flooder can exploit:
//! **Hot-Set Lockout** (a victim whose slots are already taken by hot keys is
//! never tracked, so it never trips) and a **Cold-Start Eviction Race** (a
//! victim ramping 0→threshold is the coldest entry and gets evicted/reset
//! before it can cross). The CMS has NO eviction and NO per-key slot: every key
//! is ALWAYS counted in its `ROWS` cells, which only ever INCREASE within the
//! sliding window (a colliding key ADDS to a cell, never resets it). So a
//! victim's own flood drives all `ROWS` of its cells up monotonically and it
//! ALWAYS trips, regardless of arrival order or colliding traffic.
//!
//! ### Fail-CLOSED collision bias
//!
//! Collisions can only OVER-estimate a key's rate (another hot key sharing a
//! cell inflates it), never under-estimate. The CMS therefore never produces a
//! false-negative (it never lets a real flood through). Its only error is a
//! false-POSITIVE: a legitimate key whose `ROWS` cells ALL collide with hot keys
//! is throttled. That probability is `~(load)^ROWS`, driven below noise by
//! `ROWS = 4`. For a security rate limiter, over-count is the correct bias.
//!
//! ### Per-source saturation under spoofing
//!
//! Under a heavy spoofed flood the distinct-source cardinality explodes and the
//! per-source sketch would saturate (every cell hot → all legit sources
//! throttled). This is bounded NOT by the structure but by the caller's gate:
//! the per-source sketch is consulted ONLY when the zone is not SYN-cookie
//! active, and the zone goes cookie-active exactly when the aggregate
//! `attack-threshold` trips (the high-cardinality regime). So per-source CMS
//! only runs in the sub-aggregate regime, where source cardinality is bounded
//! and the sketch is accurate. Per-destination has no such concern (destination
//! cardinality is bounded by the real forwarded-server set) and always runs.
//!
//! ## Cost / memory
//!
//! Per non-validated initial SYN with the feature enabled: `ROWS` cell
//! `increment`s per consulted sketch (each an integer add + compare; one cache
//! line of `RateCounter`s per row) plus the AND. No allocation, no rehash, no
//! eviction scan — steady-state AND under a spoofed flood. Allocated once at
//! config for zones that configure a threshold; freed when disabled.
//!
//! `RateCounter` ≈ 16 B. Per configured zone, per worker: per-dest
//! `ROWS*DST_COLS*16 = 64 KiB` + per-source `ROWS*SRC_COLS*16 = 128 KiB` =
//! 192 KiB/zone, × num_workers. Bounded by the Go commit-time memory advisory.

use super::rate::RateCounter;
use rustc_hash::FxHasher;
use std::hash::Hasher;
use std::net::IpAddr;

/// Number of independent hash rows (`d`). 4 keeps the over-count false-positive
/// rate (`~load^4`) below noise while bounding the per-packet cache-line touches.
pub(super) const ROWS: usize = 4;

/// Columns (`w`) for the per-DESTINATION sketch. Power of two for mask indexing.
pub(super) const DST_COLS: usize = 1024;

/// Columns (`w`) for the per-SOURCE sketch — wider than DST because the
/// (gated, sub-aggregate) source cardinality can still exceed the bounded
/// destination set.
pub(super) const SRC_COLS: usize = 2048;

// Compile-time invariant: the `& (cols - 1)` index masking is only correct for
// power-of-two column counts.
const _: () = assert!(DST_COLS.is_power_of_two() && SRC_COLS.is_power_of_two());

/// Independent per-row seeds. Distinct values so the `ROWS` rows hash
/// independently — same-seed rows would collapse the sketch to a single row and
/// inflate the false-positive rate (it never affects the fail-closed bias).
///
/// These fixed per-row constants provide row INDEPENDENCE, not secrecy: they are
/// public, so on their own they do NOT stop an off-box attacker from precomputing
/// which source IPs land in a chosen victim's `ROWS` cells and driving those cells
/// over `source-threshold` to throttle a victim's legit SYNs (a targeted
/// false-positive, #4382). Secrecy comes from the PER-BOOT `SynRateSketch::seed`
/// (drawn once from `hot_hash_seed::hot_path_hash_seed`, #2364) that
/// `cell_index`/`cell_index_ip_port` fold in ALONGSIDE `ROW_SEEDS[row]`: the
/// source→cell mapping is unknowable offline and reshuffles on every restart, so
/// the attacker cannot construct a colliding IP set — exactly as the flow
/// cache / session map / ECMP / CoS hashes already do.
const ROW_SEEDS: [u64; ROWS] = [
    0x9E37_79B9_7F4A_7C15,
    0xC2B2_AE3D_27D4_EB4F,
    0x1656_67B1_9E37_79F9,
    0x27D4_EB2F_1656_67C5,
];

/// Count-min sketch of `RateCounter`s with no eviction. See module docs.
pub(super) struct SynRateSketch {
    /// `ROWS` rows of `cols` counters. `Box<[Box<[RateCounter]>]>` is allocated
    /// once at construction and never resized — the hot path only indexes.
    rows: Box<[Box<[RateCounter]>]>,
    /// Index mask (`cols - 1`); `cols` is a power of two.
    mask: usize,
    /// Per-boot secret folded into the cell hash alongside `ROW_SEEDS[row]`
    /// (#4382). Drawn once from `hot_hash_seed::hot_path_hash_seed()` at
    /// construction and stable for the process lifetime, so a given key maps to
    /// a stable cell across its whole window (counting behaviour unchanged) while
    /// the key→cell mapping is unpredictable off-box and reshuffles on every
    /// restart — the attacker cannot precompute a colliding source-IP set.
    seed: u64,
}

impl SynRateSketch {
    fn with_cols(cols: usize) -> Self {
        Self::with_cols_seeded(cols, crate::hot_hash_seed::hot_path_hash_seed())
    }

    /// Seed-parameterized core of `with_cols`. Split out so adversarial tests can
    /// pin the seed and assert (a) intra-seed stability of the key→cell mapping
    /// and (b) cross-seed reshuffling — mirroring `FlowCache::set_index_seeded`.
    /// Production always calls through `with_cols`, which supplies the per-boot
    /// process seed.
    fn with_cols_seeded(cols: usize, seed: u64) -> Self {
        debug_assert!(
            cols.is_power_of_two(),
            "SynRateSketch cols must be a power of two"
        );
        let rows = (0..ROWS)
            .map(|_| vec![RateCounter::default(); cols].into_boxed_slice())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            rows,
            mask: cols - 1,
            seed,
        }
    }

    /// Allocate the per-DESTINATION sketch (`DST_COLS` columns).
    pub(super) fn for_dst() -> Self {
        Self::with_cols(DST_COLS)
    }

    /// Allocate the per-SOURCE sketch (`SRC_COLS` columns).
    pub(super) fn for_src() -> Self {
        Self::with_cols(SRC_COLS)
    }

    /// Cell index for `ip` in row `row` (independent seeded hash, masked to the
    /// column count).
    #[inline]
    fn cell_index(&self, row: usize, ip: &IpAddr) -> usize {
        let mut h = FxHasher::default();
        h.write_u64(ROW_SEEDS[row]);
        h.write_u64(self.seed);
        match ip {
            IpAddr::V4(a) => h.write(&a.octets()),
            IpAddr::V6(a) => h.write(&a.octets()),
        }
        (h.finish() as usize) & self.mask
    }

    /// Count one SYN for `ip` and report whether `ip` is over `threshold` in the
    /// trailing 1-second window.
    ///
    /// Every row cell is incremented (the count-min side effect MUST happen in
    /// all rows even when an earlier row is already under threshold), then the
    /// per-row over-threshold results are AND-ed: the key trips ⟺ ALL rows
    /// report over-threshold (= `min` over rows > threshold). `&=` here is the
    /// non-short-circuiting bitwise-and assignment, so it never skips a row's
    /// `increment`.
    pub(super) fn increment(&mut self, ip: &IpAddr, now_secs: u64, threshold: u32) -> bool {
        let mut over_all = true;
        for row in 0..ROWS {
            let idx = self.cell_index(row, ip);
            let over = self.rows[row][idx].increment(now_secs, threshold);
            over_all &= over;
        }
        over_all
    }

    /// Cell index for `(ip, port)` in row `row`: the seeded per-row hash of the
    /// address WITH the L4 destination port mixed in. Keys the per-DESTINATION
    /// UDP flood sketch on `(dst_ip, dst_port)` — matching Junos `udp flood
    /// threshold`, which caps the rate to a destination IP AND port (#4112).
    #[inline]
    fn cell_index_ip_port(&self, row: usize, ip: &IpAddr, port: u16) -> usize {
        let mut h = FxHasher::default();
        h.write_u64(ROW_SEEDS[row]);
        h.write_u64(self.seed);
        match ip {
            IpAddr::V4(a) => h.write(&a.octets()),
            IpAddr::V6(a) => h.write(&a.octets()),
        }
        h.write_u16(port);
        (h.finish() as usize) & self.mask
    }

    /// Count one packet for `(ip, port)` and report whether it is over
    /// `threshold` in the trailing 1-second window. Mirrors `increment` but keys
    /// on the L4 destination port too — the UDP per-destination-port flood cap
    /// (#4112 F18). Every row cell is still incremented (non-short-circuiting
    /// AND), so the count-min side effect happens in all rows.
    pub(super) fn increment_ip_port(
        &mut self,
        ip: &IpAddr,
        port: u16,
        now_secs: u64,
        threshold: u32,
    ) -> bool {
        let mut over_all = true;
        for row in 0..ROWS {
            let idx = self.cell_index_ip_port(row, ip, port);
            let over = self.rows[row][idx].increment(now_secs, threshold);
            over_all &= over;
        }
        over_all
    }

    /// Total cell capacity (`ROWS * cols`). Test seam to assert no growth under a
    /// flood (the structure is fixed-capacity).
    #[cfg(test)]
    pub(super) fn capacity(&self) -> usize {
        self.rows.iter().map(|r| r.len()).sum()
    }

    /// The `ROWS` cell indices `ip` maps to. Test seam for the AND-not-OR test.
    #[cfg(test)]
    pub(super) fn cell_indices(&self, ip: &IpAddr) -> [usize; ROWS] {
        let mut out = [0usize; ROWS];
        for (row, slot) in out.iter_mut().enumerate() {
            *slot = self.cell_index(row, ip);
        }
        out
    }

    /// Directly drive a specific `(row, col)` cell over `threshold`, simulating
    /// colliding hot keys without searching for collider IPs. Test seam only.
    #[cfg(test)]
    pub(super) fn saturate_cell(&mut self, row: usize, col: usize, now_secs: u64, threshold: u32) {
        // Drive the trailing-window sum strictly above threshold.
        for _ in 0..=threshold {
            self.rows[row][col].increment(now_secs, threshold);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn power_of_two_columns_const_assert_holds() {
        // The `const _: () = assert!(...)` at module scope fails the build if
        // either width stops being a power of two; this run-time mirror documents
        // the invariant the index masking depends on.
        assert!(DST_COLS.is_power_of_two());
        assert!(SRC_COLS.is_power_of_two());
    }

    #[test]
    fn single_key_trips_above_threshold() {
        let mut s = SynRateSketch::for_dst();
        let victim = v4(10, 0, 0, 1);
        const T: u32 = 5;
        // First T are admitted; the (T+1)th trips.
        for _ in 0..T {
            assert!(!s.increment(&victim, 100, T), "first {T} SYNs admitted");
        }
        assert!(s.increment(&victim, 100, T), "over-threshold SYN trips");
    }

    /// D1 (required): a victim ALWAYS trips regardless of arrival order or
    /// colliding traffic. Pre-load the table with many OTHER hot keys (so the
    /// victim's rows are busy), then flood the victim and assert it trips. The
    /// CMS has no eviction and only increases, so the victim's own cells cross
    /// threshold no matter what shares them. This is the test that dissolves the
    /// Hot-Set Lockout + Cold-Start Eviction Race that killed the eviction-cache
    /// designs.
    #[test]
    fn victim_always_trips_despite_busy_table_and_late_arrival() {
        let mut s = SynRateSketch::for_dst();
        const T: u32 = 8;
        // Make the table busy with 500 distinct hot keys first.
        for k in 0..500u32 {
            let other = v4(172, 16, (k >> 8) as u8, (k & 0xff) as u8);
            for _ in 0..(T + 2) {
                s.increment(&other, 100, T);
            }
        }
        // The victim arrives LATE into a busy table and floods.
        let victim = v4(10, 9, 9, 9);
        let mut tripped = false;
        for _ in 0..(T + 1) {
            tripped |= s.increment(&victim, 100, T);
        }
        assert!(
            tripped,
            "victim must trip even arriving late into a busy table"
        );
    }

    /// AND-not-OR (required, R5 SMR NEW-1): a key whose cells collide with hot
    /// keys in SOME but NOT ALL rows must NOT trip. Catches an OR/MAX inversion
    /// that "victim always trips" cannot. Built deterministically via the
    /// cell-index + saturate-cell seams (no collider search).
    #[test]
    fn some_but_not_all_rows_does_not_trip() {
        let mut s = SynRateSketch::for_dst();
        const T: u32 = 10;
        let key = v4(192, 168, 1, 1);
        let idx = s.cell_indices(&key);
        // Saturate ALL BUT ONE of the key's rows with colliding traffic.
        for (row, &col) in idx.iter().enumerate().take(ROWS - 1) {
            s.saturate_cell(row, col, 100, T);
        }
        // The key sends ONE SYN: ROWS-1 rows are over threshold but the last is
        // not → AND is false → no trip. (An OR/MAX sketch would trip here.)
        assert!(
            !s.increment(&key, 100, T),
            "a key over threshold in only ROWS-1 rows must NOT trip (AND/MIN)"
        );
        // Now saturate the final row too: every row over threshold → trips.
        let final_idx = s.cell_indices(&key)[ROWS - 1];
        s.saturate_cell(ROWS - 1, final_idx, 100, T);
        assert!(
            s.increment(&key, 100, T),
            "once ALL rows are over threshold the key trips"
        );
    }

    /// Independent per-row seeds: a single IP does not map to the same column in
    /// every row (which would collapse the sketch to one effective row). Not a
    /// hard guarantee for every IP; a pinned seed makes this deterministic for a
    /// sampled address (production additionally folds the per-boot seed in — row
    /// independence still comes from the per-row `ROW_SEEDS`).
    #[test]
    fn rows_use_independent_seeds() {
        let s = SynRateSketch::with_cols_seeded(SRC_COLS, 0x1234_5678_9ABC_DEF0);
        let idx = s.cell_indices(&v4(203, 0, 113, 7));
        let all_same = idx.iter().all(|&c| c == idx[0]);
        assert!(
            !all_same,
            "independent seeds must not map an IP to one column in all rows"
        );
    }

    /// No eviction / fixed capacity: a spoofed flood of distinct sources does not
    /// grow the structure. Capacity is constant before and after.
    #[test]
    fn no_growth_under_spoofed_flood() {
        let mut s = SynRateSketch::for_src();
        let before = s.capacity();
        for k in 0..50_000u32 {
            let spoofed = v4((k >> 24) as u8, (k >> 16) as u8, (k >> 8) as u8, k as u8);
            s.increment(&spoofed, 100, 20);
        }
        assert_eq!(
            s.capacity(),
            before,
            "CMS must not grow under a spoofed flood"
        );
        assert_eq!(before, ROWS * SRC_COLS, "capacity is ROWS * SRC_COLS");
    }

    /// Over-count is fail-CLOSED: collisions never let a real flood through. A
    /// victim flooding from many distinct (non-spoofed) sources to one dest
    /// trips per-dest even though no single source is hot — the destination cells
    /// accumulate every SYN.
    #[test]
    fn many_sources_one_dest_trips_per_dest() {
        let mut s = SynRateSketch::for_dst();
        const T: u32 = 50;
        let victim = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let mut tripped = false;
        for _ in 0..(T + 5) {
            // Same destination every time (the per-dest sketch keys on dst).
            tripped |= s.increment(&victim, 100, T);
        }
        assert!(
            tripped,
            "a flooded destination trips per-dest regardless of source spread"
        );
    }

    /// A fixed set of source IPs used to compare cell mappings across seeds.
    fn sample_ips(n: u32) -> Vec<IpAddr> {
        (0..n)
            .map(|i| v4(203, 0, (i >> 8) as u8, (i & 0xff) as u8))
            .collect()
    }

    /// The `ROWS` cell indices each IP maps to, under a pinned seed. Equal
    /// vectors ⇒ identical key→cell mapping.
    fn cell_distribution(seed: u64, ips: &[IpAddr]) -> Vec<[usize; ROWS]> {
        let s = SynRateSketch::with_cols_seeded(SRC_COLS, seed);
        ips.iter().map(|ip| s.cell_indices(ip)).collect()
    }

    /// #4382 (counting consistency): the key→cell mapping MUST be stable for a
    /// fixed seed, or a key's SYNs scatter across cells within its own window and
    /// the count-min counters never accumulate. Repeat under one pinned seed and
    /// demand byte-identical mappings.
    #[test]
    fn cell_mapping_stable_within_one_seed() {
        let ips = sample_ips(64);
        let seed = 0x0123_4567_89AB_CDEF;
        let first = cell_distribution(seed, &ips);
        for _ in 0..64 {
            assert_eq!(
                first,
                cell_distribution(seed, &ips),
                "cell mapping must be stable for a fixed seed"
            );
        }
    }

    /// #4382 (hardening / RED-on-revert): the source→cell mapping must NOT be an
    /// externally probeable pure function of the source IP. Two different
    /// per-boot seeds must produce a DIFFERENT cell distribution for the SAME
    /// attacker IP set, so an off-box attacker cannot precompute a colliding
    /// source-IP set to drive a victim's cells over `source-threshold`. With the
    /// per-boot `seed` dropped from `cell_index` (the reverted state) the
    /// distribution is seed-independent and NO seed diverges → this FAILS.
    #[test]
    fn cell_mapping_depends_on_per_boot_seed() {
        let ips = sample_ips(128);
        let ref_seed = 0xA5A5_0000_C3C3_FFFFu64;
        let reference = cell_distribution(ref_seed, &ips);
        // Under a uniform seeded hash an entire 128-element distribution matching
        // the reference by accident is vanishingly unlikely; one differing seed
        // is essentially immediate. Bound the loop so a truly seed-independent
        // hash (the reverted state) FAILS rather than hangs.
        let mut diverged = false;
        for seed in 1u64..4096u64 {
            if seed == ref_seed {
                continue;
            }
            if cell_distribution(seed, &ips) != reference {
                diverged = true;
                break;
            }
        }
        assert!(
            diverged,
            "sketch cell distribution did not change across seeds — cell_index \
             is per-boot-seed-independent (#4382 regression)"
        );
    }

    /// #4382 (detection preserved): the per-boot seed changes only WHICH cells a
    /// key maps to, never the counting. A real single-source flood still crosses
    /// `source-threshold` under an arbitrary pinned seed — same thresholds, same
    /// trip behaviour as `single_key_trips_above_threshold`.
    #[test]
    fn single_source_flood_trips_under_pinned_seed() {
        for &seed in &[1u64, 0xDEAD_BEEF_CAFE_F00D, u64::MAX] {
            let mut s = SynRateSketch::with_cols_seeded(SRC_COLS, seed);
            let attacker = v4(198, 51, 100, 7);
            const T: u32 = 5;
            for _ in 0..T {
                assert!(
                    !s.increment(&attacker, 100, T),
                    "first {T} SYNs admitted (seed {seed:#x})"
                );
            }
            assert!(
                s.increment(&attacker, 100, T),
                "over-threshold SYN trips (seed {seed:#x})"
            );
        }
    }
}
