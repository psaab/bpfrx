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
//! on the destination IP (ICMP, and a port-less UDP fragment — #4567);
//! `increment_ip_port` mixes the destination port in (UDP with a real L4 port).
//! The per-zone aggregate `RateCounter` is retained as a coarser SECONDARY
//! ceiling above these per-destination caps.
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
#[path = "syn_rate_tests.rs"]
mod tests;
