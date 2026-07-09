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
