// Tests for the session module (#1047). Originally inline in session.rs,
// relocated as session_tests.rs in P1 (PR #1051), then renamed to
// session/tests.rs alongside the structural split that introduced the
// session/ directory module and session/key.rs.
// Loaded as a sibling submodule via `#[path = "tests.rs"]` from session/mod.rs.

use crate::test_zone_ids::*;
use super::*;
// #2005 split: the timer-wheel constants used by the GC tests below were
// previously reachable via `super::*` through mod.rs's explicit
// `use wheel::{...}` re-export. mod.rs no longer imports them directly
// (the wheel-driving methods moved to session/expire.rs), so reference
// them explicitly here. Same symbols, same values — no behavior change.
use super::wheel::{FAR_FUTURE_OFFSET, WHEEL_BUCKETS, WHEEL_TICK_NS};
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
        log_session_init: false,
        log_session_close: false,
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
        0x10,
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
        0x10,
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
    let entry = table.entry_by_key(&key).expect("entry");
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
fn tcp_rst_uses_short_timeout_not_fin_timeout() {
    // #3046 FAIL-ON-REVERT: a RST'd TCP session must be reaped on the short
    // TCP_RST_TIMEOUT_NS, while a FIN-only graceful close keeps the 30s
    // TCP_CLOSING_TIMEOUT_NS. If the RST timeout selection reverts to the FIN
    // closing timeout (the #3046 bug — is_closing lumps RST with FIN at 30s)
    // the first expires_after_ns assert below RED-fails.
    assert!(
        TCP_RST_TIMEOUT_NS < TCP_CLOSING_TIMEOUT_NS,
        "RST timeout must be strictly shorter than the FIN close timeout"
    );
    let now = 1_000_000_000u64;

    // --- RST path: short timeout ---
    let mut table = SessionTable::new();
    let key = key_v4();
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x10
    ));
    let _ = table.drain_deltas(8);
    assert!(table.lookup(&key, now + 1_000_000, TCP_RST).is_some());
    let rst_entry = table.entry_by_key(&key).expect("rst entry");
    assert!(rst_entry.closing, "RST must mark the session closing");
    assert!(rst_entry.reset, "RST must set the sticky reset flag");
    assert_eq!(
        rst_entry.expires_after_ns, TCP_RST_TIMEOUT_NS,
        "RST'd session must use the short RST timeout, not the 30s FIN close timeout"
    );

    // --- FIN path (control): full 30s close timeout, no reset ---
    let mut table2 = SessionTable::new();
    let key2 = key_v4();
    assert!(table2.install_with_protocol(
        key2.clone(),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x10
    ));
    let _ = table2.drain_deltas(8);
    assert!(table2.lookup(&key2, now + 1_000_000, TCP_FIN).is_some());
    let fin_entry = table2.entry_by_key(&key2).expect("fin entry");
    assert!(fin_entry.closing, "FIN must mark the session closing");
    assert!(!fin_entry.reset, "FIN-only close must NOT set the reset flag");
    assert_eq!(
        fin_entry.expires_after_ns, TCP_CLOSING_TIMEOUT_NS,
        "FIN-only close must keep the 30s graceful close timeout"
    );

    // --- stickiness: a reordered non-RST segment after the RST must NOT
    //     promote the entry back to the 30s FIN close window ---
    assert!(table.lookup(&key, now + 2_000_000, 0x10).is_some());
    let post_ack = table.entry_by_key(&key).expect("rst entry post-ack");
    assert_eq!(
        post_ack.expires_after_ns, TCP_RST_TIMEOUT_NS,
        "a stray non-RST segment after a RST must not revert to the 30s FIN timeout"
    );
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
    assert!(table.promote_synced_with_origin(SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: promoted.clone(),
        origin: SessionOrigin::SharedPromote,
        now_ns: now + 1_000_000,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
    }));
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
    assert!(table.promote_synced_with_origin(SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: promoted.clone(),
        origin: SessionOrigin::SharedPromote,
        now_ns: now + 1_000_000,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
    }));
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
fn from_seconds_normal_value_unchanged() {
    // 1 hour: a realistic operator-configured timeout must convert exactly,
    // proving the saturation path does not perturb in-range values.
    let t = SessionTimeouts::from_seconds(3600, 3600, 3600);
    assert_eq!(t.tcp_established_ns, 3_600_000_000_000);
    assert_eq!(t.udp_ns, 3_600_000_000_000);
    assert_eq!(t.icmp_ns, 3_600_000_000_000);
}

#[test]
fn from_seconds_max_accepted_value_exact() {
    // The largest value the Go gate accepts (config.MaxDurationSeconds ==
    // MAX_SESSION_TIMEOUT_SECS) must convert exactly, NOT saturate-short.
    let t = SessionTimeouts::from_seconds(
        MAX_SESSION_TIMEOUT_SECS,
        MAX_SESSION_TIMEOUT_SECS,
        MAX_SESSION_TIMEOUT_SECS,
    );
    assert_eq!(t.tcp_established_ns, MAX_SESSION_TIMEOUT_NS);
    assert_eq!(t.udp_ns, MAX_SESSION_TIMEOUT_NS);
    assert_eq!(t.icmp_ns, MAX_SESSION_TIMEOUT_NS);
    // The conversion must not have wrapped: the ns ceiling is < u64::MAX.
    assert_eq!(
        MAX_SESSION_TIMEOUT_NS,
        MAX_SESSION_TIMEOUT_SECS * 1_000_000_000
    );
}

#[test]
fn from_seconds_saturates_first_overflowing_value() {
    // The first value whose `secs * 1e9` exceeds the ns ceiling. Pre-#2441
    // this is where the raw multiply began to wrap (debug-panic / release-
    // wrap). It must now SATURATE at MAX_SESSION_TIMEOUT_NS, not wrap to a
    // tiny value (premature session expiry).
    let first_over = MAX_SESSION_TIMEOUT_SECS + 1;
    let t = SessionTimeouts::from_seconds(first_over, first_over, first_over);
    assert_eq!(t.tcp_established_ns, MAX_SESSION_TIMEOUT_NS);
    assert_eq!(t.udp_ns, MAX_SESSION_TIMEOUT_NS);
    assert_eq!(t.icmp_ns, MAX_SESSION_TIMEOUT_NS);
}

#[test]
fn from_seconds_saturates_u64_max() {
    // u64::MAX * 1e9 wraps catastrophically with a raw multiply (debug:
    // panic, release: a near-zero timeout). Restoring the raw `*` makes this
    // test panic in debug / produce a tiny non-saturated value in release —
    // the fail-on-revert pin.
    let t = SessionTimeouts::from_seconds(u64::MAX, u64::MAX, u64::MAX);
    assert_eq!(t.tcp_established_ns, MAX_SESSION_TIMEOUT_NS);
    assert_eq!(t.udp_ns, MAX_SESSION_TIMEOUT_NS);
    assert_eq!(t.icmp_ns, MAX_SESSION_TIMEOUT_NS);
    // Saturated, not wrapped-tiny: the result is a very large valid timeout.
    assert!(t.tcp_established_ns > DEFAULT_TCP_SESSION_TIMEOUT_NS);
}

#[test]
fn from_seconds_zero_still_defaults_after_saturation() {
    // 0 must remain "use the default", unaffected by the saturation helper.
    let t = SessionTimeouts::from_seconds(0, 0, 0);
    assert_eq!(t.tcp_established_ns, DEFAULT_TCP_SESSION_TIMEOUT_NS);
    assert_eq!(t.udp_ns, DEFAULT_UDP_SESSION_TIMEOUT_NS);
    assert_eq!(t.icmp_ns, DEFAULT_ICMP_SESSION_TIMEOUT_NS);
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
    table.iter_with_idle(now, |k, _decision, _metadata, idle_ns, _counters| {
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
    table.iter_with_idle(now, |k, _, _, idle_ns, _counters| {
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

// ---------------------------------------------------------------------------
// #1752 Path E: in-place refresh differential tests.
//
// The pre-#1752 update_session did remove_entry + mutate + restore_entry. The
// in-place rewrite must be behaviorally equivalent (handle-normalized — the
// slab handle VALUE legitimately differs because remove+restore allocates a
// fresh slot while in-place keeps the slot). `reference_update_session` below
// reproduces the OLD path verbatim; every scenario applies the same op to two
// tables and asserts equivalence via observable views (entries, lookups,
// owner-RG key sets, deltas) — never raw u32 handles.
// ---------------------------------------------------------------------------

/// Verbatim reproduction of the pre-#1752 remove+restore update_session.
fn reference_update_session(
    table: &mut SessionTable,
    req: SessionUpdate<'_>,
    ha_activation: bool,
) -> bool {
    let SessionUpdate {
        key,
        decision,
        metadata,
        origin,
        now_ns,
        protocol,
        tcp_flags,
    } = req;
    let Some(mut entry) = table.remove_entry(key) else {
        return false;
    };
    if !ha_activation {
        if entry.origin.is_peer_synced() && !origin.is_peer_synced() {
        } else if entry.origin.is_peer_synced() && origin.is_peer_synced() {
            table.restore_entry(key.clone(), entry);
            return false;
        } else if !entry.origin.is_peer_synced() && origin.is_peer_synced() {
            table.restore_entry(key.clone(), entry);
            return false;
        }
    }
    let was_peer_synced = entry.origin.is_peer_synced();
    entry.decision = decision;
    entry.metadata = metadata.clone();
    entry.origin = origin;
    entry.install_epoch = table.next_epoch();
    entry.last_seen_ns = now_ns;
    entry.expires_after_ns = session_timeout_ns(protocol, tcp_flags, &table.timeouts);
    entry.closing = matches!(protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0;
    // #3046: RST is sticky on the in-place path; mirror it here so the
    // reference stays byte-equivalent.
    entry.reset |= matches!(protocol, PROTO_TCP) && (tcp_flags & TCP_RST) != 0;
    let created_ns = entry.created_ns;
    table.restore_entry(key.clone(), entry);
    table.push_to_wheel(key, now_ns);
    if was_peer_synced && !origin.is_peer_synced() && !metadata.is_reverse {
        table.push_delta(SessionDelta {
            kind: SessionDeltaKind::Open,
            key: key.clone(),
            decision,
            metadata,
            origin,
            fabric_redirect_sync: false,
            created_ns,
            last_seen_ns: now_ns,
            counters: SessionCounters::default(),
        });
    }
    true
}

fn entries_equiv(a: &SessionTable, b: &SessionTable, key: &SessionKey) -> bool {
    match (a.entry_by_key(key), b.entry_by_key(key)) {
        (Some(ea), Some(eb)) => {
            ea.decision == eb.decision
                && ea.metadata == eb.metadata
                && ea.origin == eb.origin
                && ea.install_epoch == eb.install_epoch
                && ea.last_seen_ns == eb.last_seen_ns
                && ea.expires_after_ns == eb.expires_after_ns
                && ea.closing == eb.closing
                && ea.reset == eb.reset
                && ea.wheel_tick == eb.wheel_tick
        }
        (None, None) => true,
        _ => false,
    }
}

fn sorted_keys(mut v: Vec<SessionKey>) -> Vec<String> {
    let mut s: Vec<String> = v.drain(..).map(|k| format!("{k:?}")).collect();
    s.sort();
    s
}

/// Assert handle-normalized equivalence of two tables across entries, the
/// reverse/wire NAT lookups for the given probe keys, owner-RG key sets, and
/// drained deltas.
fn assert_tables_equiv(
    inplace: &mut SessionTable,
    reference: &mut SessionTable,
    keys: &[SessionKey],
    probe_keys: &[SessionKey],
    owner_rgs: &[i32],
) {
    assert_eq!(inplace.len(), reference.len(), "len mismatch");
    for k in keys {
        assert!(entries_equiv(inplace, reference, k), "entry mismatch for {k:?}");
    }
    for pk in probe_keys {
        assert_eq!(
            inplace.find_forward_nat_match(pk).map(|m| m.key),
            reference.find_forward_nat_match(pk).map(|m| m.key),
            "find_forward_nat_match diverged for {pk:?}"
        );
        assert_eq!(
            inplace.find_forward_wire_match(pk).map(|m| m.key),
            reference.find_forward_wire_match(pk).map(|m| m.key),
            "find_forward_wire_match diverged for {pk:?}"
        );
    }
    assert_eq!(
        sorted_keys(inplace.owner_rg_session_keys(owner_rgs)),
        sorted_keys(reference.owner_rg_session_keys(owner_rgs)),
        "owner_rg_session_keys diverged"
    );
    assert_eq!(
        inplace.drain_deltas(256),
        reference.drain_deltas(256),
        "deltas diverged"
    );
}

fn nat_rewrite() -> SessionDecision {
    SessionDecision {
        resolution: resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            rewrite_src_port: Some(40001),
            ..NatDecision::default()
        },
    }
}

/// Build two identical tables with `key` installed at the given origin.
fn two_tables_with(
    key: &SessionKey,
    decision: SessionDecision,
    md: SessionMetadata,
    origin: SessionOrigin,
    now: u64,
) -> (SessionTable, SessionTable) {
    let mut a = SessionTable::new();
    let mut b = SessionTable::new();
    for t in [&mut a, &mut b] {
        assert!(t.install_with_protocol_with_origin(
            key.clone(),
            decision,
            md.clone(),
            origin,
            now,
            key.protocol,
            0,
        ));
    }
    (a, b)
}

#[test]
fn inplace_local_refresh_matches_reference() {
    let key = key_v4();
    let (mut ip, mut rf) = two_tables_with(&key, decision(), metadata(), SessionOrigin::ForwardFlow, 1_000);
    let req = |now| SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: now,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(ip.update_session(req(2_000), false));
    assert!(reference_update_session(&mut rf, req(2_000), false));
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[], &[1, 2]);
}

#[test]
fn inplace_peer_to_local_promote_matches_reference() {
    let key = key_v4();
    let (mut ip, mut rf) = two_tables_with(&key, decision(), metadata(), SessionOrigin::SyncImport, 1_000);
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    let r1 = ip.update_session(req.clone(), false);
    let r2 = reference_update_session(&mut rf, req, false);
    assert_eq!(r1, r2);
    assert!(r1, "promote should succeed");
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[], &[1, 2]);
}

#[test]
fn inplace_peer_to_peer_reject_matches_reference() {
    let key = key_v4();
    let (mut ip, mut rf) = two_tables_with(&key, decision(), metadata(), SessionOrigin::SyncImport, 1_000);
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::SyncImport,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(!ip.update_session(req.clone(), false));
    assert!(!reference_update_session(&mut rf, req, false));
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[], &[1, 2]);
}

#[test]
fn inplace_local_from_peer_reject_matches_reference() {
    let key = key_v4();
    let (mut ip, mut rf) = two_tables_with(&key, decision(), metadata(), SessionOrigin::ForwardFlow, 1_000);
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::SyncImport,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(!ip.update_session(req.clone(), false));
    assert!(!reference_update_session(&mut rf, req, false));
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[], &[1, 2]);
}

#[test]
fn inplace_ha_activation_matches_reference() {
    let key = key_v4();
    let (mut ip, mut rf) = two_tables_with(&key, decision(), metadata(), SessionOrigin::SyncImport, 1_000);
    // ha_activation=true always applies regardless of origin.
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::SyncImport,
        now_ns: 3_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(ip.update_session(req.clone(), true));
    assert!(reference_update_session(&mut rf, req, true));
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[], &[1, 2]);
}

#[test]
fn inplace_nat_reindex_matches_reference() {
    let key = key_v4();
    // baseline: default nat. refresh: nat rewrite -> reverse index keys change.
    let (mut ip, mut rf) = two_tables_with(&key, decision(), metadata(), SessionOrigin::ForwardFlow, 1_000);
    let probe_old = reverse_wire_key(&key, NatDecision::default());
    let probe_new = reverse_wire_key(&key, nat_rewrite().nat);
    let req = SessionUpdate {
        key: &key,
        decision: nat_rewrite(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(ip.update_session(req.clone(), false));
    assert!(reference_update_session(&mut rf, req, false));
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[probe_old, probe_new], &[1, 2]);
}

#[test]
fn inplace_owner_rg_transitions_match_reference() {
    let key = key_v4();
    for (from_rg, to_rg) in [(1i32, 2i32), (1, 0), (0, 1)] {
        let mut md_from = metadata();
        md_from.owner_rg_id = from_rg;
        let (mut ip, mut rf) =
            two_tables_with(&key, decision(), md_from, SessionOrigin::ForwardFlow, 1_000);
        let mut md_to = metadata();
        md_to.owner_rg_id = to_rg;
        let req = SessionUpdate {
            key: &key,
            decision: decision(),
            metadata: md_to,
            origin: SessionOrigin::ForwardFlow,
            now_ns: 2_000,
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        assert!(ip.update_session(req.clone(), false));
        assert!(reference_update_session(&mut rf, req, false));
        assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[], &[0, 1, 2]);
    }
}

#[test]
fn inplace_reject_reasserts_displaced_collision_like_reference() {
    // Simulate a secondary-index collision: another (bogus) handle has displaced
    // this session's reverse-wire index slot. Today's reject path re-asserts via
    // remove+restore; in-place re-asserts via index_forward_nat_key_parts. Both
    // must re-win the slot identically.
    let key = key_v4();
    let (mut ip, mut rf) =
        two_tables_with(&key, decision(), metadata(), SessionOrigin::ForwardFlow, 1_000);
    let collide = reverse_wire_key(&key, NatDecision::default());
    for t in [&mut ip, &mut rf] {
        t.nat_reverse_index.insert(collide.clone(), 9999u32);
    }
    // local<-peer reject (origin SyncImport on a local entry).
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::SyncImport,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(!ip.update_session(req.clone(), false));
    assert!(!reference_update_session(&mut rf, req, false));
    // Both must have re-won the displaced slot back to the real session.
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[collide], &[1, 2]);
}

#[test]
fn inplace_accept_reasserts_displaced_collision_like_reference() {
    let key = key_v4();
    let (mut ip, mut rf) =
        two_tables_with(&key, decision(), metadata(), SessionOrigin::ForwardFlow, 1_000);
    let collide = reverse_wire_key(&key, NatDecision::default());
    for t in [&mut ip, &mut rf] {
        t.nat_reverse_index.insert(collide.clone(), 9999u32);
    }
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(ip.update_session(req.clone(), false));
    assert!(reference_update_session(&mut rf, req, false));
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[collide], &[1, 2]);
}

// ── #1855: corrupted key_to_handle contract ──────────────────────────
//
// A stale or vacant `key_to_handle` mapping is impossible-by-construction
// (per-worker single-writer `&mut self`, #964 eager-cleanup invariant in
// `remove_entry`); the rigs below reach it only via private-field access.
// The contract — decided in docs/research/1855-inplace-contract/plan.md —
// is the `remove_entry` #964 precedent:
//   - debug builds: `debug_assert!` fires (loud logic-bug detector),
//     documented by the `#[cfg(debug_assertions)]` `#[should_panic]`
//     variants below;
//   - release builds: tolerate + return false without touching the
//     reused-slot session, documented by the
//     `#[cfg(not(debug_assertions))]` `*_returns_false_no_panic` tests
//     (exercised by `cargo test --release`).

/// Rig: install `key` and `other`, then point `key`'s mapping at
/// `other`'s slab slot — a stale mapping onto a REUSED slot, which the
/// primary-key guard (`record.key != *key`) must catch.
fn rig_stale_handle_table() -> (SessionTable, SessionKey, SessionKey) {
    let key = key_v4();
    let other = key_v6();
    let mut t = SessionTable::new();
    assert!(t.install_with_protocol_with_origin(
        key.clone(), decision(), metadata(), SessionOrigin::ForwardFlow, 1_000, key.protocol, 0,
    ));
    assert!(t.install_with_protocol_with_origin(
        other.clone(), decision(), metadata(), SessionOrigin::ForwardFlow, 1_000, other.protocol, 0,
    ));
    let other_handle = *t.key_to_handle.get(&other).expect("other handle");
    t.key_to_handle.insert(key.clone(), other_handle);
    (t, key, other)
}

#[cfg(not(debug_assertions))]
#[test]
fn inplace_stale_handle_returns_false_no_panic() {
    let (mut t, key, other) = rig_stale_handle_table();
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    // Release contract: must not panic and must not mutate the unrelated
    // `other` session occupying the reused slot.
    let before = t.entry_by_key(&other).map(|e| e.last_seen_ns);
    assert!(!t.update_session(req, false));
    assert_eq!(t.entry_by_key(&other).map(|e| e.last_seen_ns), before);
    // refresh_for_ha_transition shares the primary-key guard (#1855 AGY r1:
    // symmetric release coverage).
    assert!(!t.refresh_for_ha_transition(&key, decision(), metadata(), 2_000));
    assert_eq!(t.entry_by_key(&other).map(|e| e.last_seen_ns), before);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "update_session: stale key_to_handle")]
fn inplace_stale_handle_asserts_in_debug() {
    let (mut t, key, _other) = rig_stale_handle_table();
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    let _ = t.update_session(req, false);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "refresh_for_ha_transition: stale key_to_handle")]
fn ha_transition_stale_handle_asserts_in_debug() {
    let (mut t, key, _other) = rig_stale_handle_table();
    let _ = t.refresh_for_ha_transition(&key, decision(), metadata(), 2_000);
}

#[test]
fn inplace_randomized_sequence_matches_reference() {
    // Deterministic LCG (Math.random is unavailable in this env; fixed seed).
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 33) as u32
    };
    let keys = [key_v4(), key_v6()];
    let mut ip = SessionTable::new();
    let mut rf = SessionTable::new();
    // Install both keys identically.
    for t in [&mut ip, &mut rf] {
        for k in &keys {
            assert!(t.install_with_protocol_with_origin(
                k.clone(), decision(), metadata(), SessionOrigin::ForwardFlow, 1_000, k.protocol, 0,
            ));
        }
    }
    for step in 0..400u64 {
        let k = &keys[(next() % 2) as usize];
        let origin = if next() % 3 == 0 { SessionOrigin::SyncImport } else { SessionOrigin::ForwardFlow };
        let dec = if next() % 4 == 0 { nat_rewrite() } else { decision() };
        let mut md = metadata();
        md.owner_rg_id = (next() % 3) as i32; // 0,1,2
        md.is_reverse = next() % 5 == 0;
        let ha = next() % 7 == 0;
        // Vary tcp_flags so the FIN/RST `closing` + `expires_after_ns` branch is
        // exercised, not only the steady-state tcp_flags=0 path.
        let tcp_flags = match next() % 4 {
            0 => TCP_FIN,
            1 => TCP_RST,
            _ => 0,
        };
        let now = 2_000 + step * 10;
        let req = SessionUpdate {
            key: k,
            decision: dec,
            metadata: md,
            origin,
            now_ns: now,
            protocol: k.protocol,
            tcp_flags,
        };
        let r1 = ip.update_session(req.clone(), ha);
        let r2 = reference_update_session(&mut rf, req, ha);
        assert_eq!(r1, r2, "accept/reject diverged at step {step}");
        let probes: Vec<SessionKey> = keys
            .iter()
            .flat_map(|kk| {
                [
                    reverse_wire_key(kk, NatDecision::default()),
                    reverse_wire_key(kk, nat_rewrite().nat),
                ]
            })
            .collect();
        assert_tables_equiv(&mut ip, &mut rf, &keys, &probes, &[0, 1, 2]);
    }
}

/// Verbatim reproduction of the pre-#1752 remove+restore refresh_for_ha_transition.
fn reference_refresh_for_ha_transition(
    table: &mut SessionTable,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
    now_ns: u64,
) -> bool {
    let Some(mut entry) = table.remove_entry(key) else {
        return false;
    };
    entry.decision = decision;
    entry.metadata = metadata;
    entry.install_epoch = table.next_epoch();
    entry.last_seen_ns = now_ns;
    table.restore_entry(key.clone(), entry);
    table.push_to_wheel(key, now_ns);
    true
}

#[test]
fn inplace_ha_transition_matches_reference() {
    let key = key_v4();
    // Case 0: identical decision + metadata (owner_rg_id stays 1, nat unchanged)
    // -> the no-reindex/skip branch. Case 1: nat rewrite + owner_rg 1->2 -> the
    // reindex branch. Baseline metadata() has owner_rg_id=1, so case 0 must NOT
    // mutate md (else it would also reindex).
    let reindex_md = {
        let mut m = metadata();
        m.owner_rg_id = 2;
        m
    };
    for (dec, md) in [(decision(), metadata()), (nat_rewrite(), reindex_md)] {
        let (mut ip, mut rf) =
            two_tables_with(&key, decision(), metadata(), SessionOrigin::SyncImport, 1_000);
        let probe_old = reverse_wire_key(&key, NatDecision::default());
        let probe_new = reverse_wire_key(&key, dec.nat);
        assert!(ip.refresh_for_ha_transition(&key, dec, md.clone(), 2_000));
        assert!(reference_refresh_for_ha_transition(&mut rf, &key, dec, md, 2_000));
        assert_tables_equiv(
            &mut ip,
            &mut rf,
            &[key.clone()],
            &[probe_old, probe_new],
            &[0, 1, 2],
        );
    }
}

/// Rig: `key_to_handle` points at a slab slot that was never allocated —
/// the `entries.get(handle) == None` guard arm. See the #1855 contract
/// comment above `rig_stale_handle_table`.
fn rig_vacant_handle_table() -> (SessionTable, SessionKey) {
    let key = key_v4();
    let mut t = SessionTable::new();
    t.key_to_handle.insert(key.clone(), 9999u32);
    (t, key)
}

#[cfg(not(debug_assertions))]
#[test]
fn inplace_vacant_handle_returns_false_no_panic() {
    // Release contract: the vacant-slot guard must return false without
    // panicking (the debug_assert is compiled out).
    let (mut t, key) = rig_vacant_handle_table();
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(!t.update_session(req, false));
    // refresh_for_ha_transition shares the same guard.
    assert!(!t.refresh_for_ha_transition(&key, decision(), metadata(), 2_000));
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "update_session: key_to_handle had stale handle")]
fn inplace_vacant_handle_asserts_in_debug() {
    let (mut t, key) = rig_vacant_handle_table();
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    let _ = t.update_session(req, false);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "refresh_for_ha_transition: stale handle")]
fn ha_transition_vacant_handle_asserts_in_debug() {
    let (mut t, key) = rig_vacant_handle_table();
    let _ = t.refresh_for_ha_transition(&key, decision(), metadata(), 2_000);
}

#[test]
fn inplace_fin_rst_closing_matches_reference() {
    // FIN/RST set `closing` and shorten expires_after_ns; verify the in-place
    // path writes them identically to the reference for both flags.
    let key = key_v4();
    for flags in [TCP_FIN, TCP_RST, TCP_FIN | TCP_RST] {
        let (mut ip, mut rf) =
            two_tables_with(&key, decision(), metadata(), SessionOrigin::ForwardFlow, 1_000);
        let req = SessionUpdate {
            key: &key,
            decision: decision(),
            metadata: metadata(),
            origin: SessionOrigin::ForwardFlow,
            now_ns: 2_000,
            protocol: PROTO_TCP,
            tcp_flags: flags,
        };
        assert!(ip.update_session(req.clone(), false));
        assert!(reference_update_session(&mut rf, req, false));
        assert!(
            ip.entry_by_key(&key).expect("entry").closing,
            "closing should be set for flags {flags:#x}"
        );
        assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[], &[1, 2]);
    }
}

// ── #1760: NAT reverse-key 1:N collision telemetry counter ───────────
//
// Reproduces the latent collision documented by the #1758 research:
// under interface-mode SNAT (rewrite_src = Some(egress), rewrite_src_port
// = None), two distinct internal hosts using the SAME ephemeral source
// port to the SAME external server translate to the SAME reverse wire key
// K. The single-valued nat_reverse_index can only point at one of them,
// so the second install displaces the first — a displacement event the
// counter must observe.

/// Interface-mode SNAT decision: rewrite only the source IP to `egress`,
/// leave the source port untranslated (rewrite_src_port = None). This is
/// the default SNAT mode and the #1758 reachable collision vector.
fn iface_snat_decision(egress: Ipv4Addr) -> SessionDecision {
    SessionDecision {
        resolution: resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(egress)),
            ..NatDecision::default()
        },
    }
}

#[test]
fn nat_reverse_key_collision_counter_increments_on_displacement() {
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let egress = Ipv4Addr::new(203, 0, 113, 9);

    // Two distinct internal hosts, SAME ephemeral source port, SAME
    // external server — interface-mode SNAT'd to the SAME egress IP.
    // reverse_wire_key for both = {src=8.8.8.8:443, dst=203.0.113.9:5555}
    // (port comes from the untranslated original src_port). Identical K.
    let mut s1 = key_v4();
    s1.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    s1.src_port = 5555;
    let mut s2 = key_v4();
    s2.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    s2.src_port = 5555;
    assert_ne!(s1, s2, "the two forward keys must be distinct sessions");

    let dec = iface_snat_decision(egress);
    // Guard the repro precondition: the two distinct forward keys really
    // do derive the same reverse wire key.
    assert_eq!(
        reverse_wire_key(&s1, dec.nat),
        reverse_wire_key(&s2, dec.nat),
        "interface-mode SNAT must make the two flows share reverse key K",
    );

    // First install: K -> S1. No prior occupant, so no displacement.
    assert!(table.install_with_protocol(s1.clone(), dec, metadata(), now, PROTO_TCP, 0x10));
    assert_eq!(
        table.nat_reverse_key_collisions(),
        0,
        "a single install with no prior K occupant must not count",
    );

    // Second install: K -> S2 displaces the live S1 -> one collision.
    assert!(table.install_with_protocol(s2.clone(), dec, metadata(), now, PROTO_TCP, 0x10));
    assert_eq!(
        table.nat_reverse_key_collisions(),
        1,
        "S2 install displacing live S1 on shared K must count exactly once",
    );

    // Re-asserting S2's own ownership (refresh re-asserts the same handle)
    // must NOT count — the displaced handle equals the installing handle.
    let refresh_ns = now + 2 * WHEEL_TICK_NS;
    let req = SessionUpdate {
        key: &s2,
        decision: dec,
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: refresh_ns,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
    };
    assert!(table.update_session(req, false));
    assert_eq!(
        table.nat_reverse_key_collisions(),
        1,
        "S2 re-asserting its own K ownership must not count (old == handle)",
    );
}

#[test]
fn nat_reverse_key_collision_counter_zero_without_collision() {
    // Two flows with DISTINCT reverse keys (different source ports) under
    // interface-mode SNAT must never increment the collision counter.
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let dec = iface_snat_decision(Ipv4Addr::new(203, 0, 113, 9));

    let mut a = key_v4();
    a.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    a.src_port = 5555;
    let mut b = key_v4();
    b.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    b.src_port = 6666; // distinct port -> distinct reverse wire key
    assert_ne!(
        reverse_wire_key(&a, dec.nat),
        reverse_wire_key(&b, dec.nat),
        "distinct source ports must yield distinct reverse keys",
    );

    assert!(table.install_with_protocol(a, dec, metadata(), now, PROTO_TCP, 0x10));
    assert!(table.install_with_protocol(b, dec, metadata(), now, PROTO_TCP, 0x10));
    assert_eq!(
        table.nat_reverse_key_collisions(),
        0,
        "non-colliding flows must leave the collision counter at 0",
    );
}

// ── #1861: pair-admission preflight (can_admit) + refusal counters ────
//
// The transactional-install fix relies on `can_admit(needed)` being a
// sound preflight for the forward+reverse install pair: a passing
// preflight on the single-threaded table must make the subsequent
// `needed` installs infallible within the same descriptor iteration.

fn key_with_port(port: u16) -> SessionKey {
    SessionKey {
        src_port: port,
        ..key_v4()
    }
}

#[test]
fn can_admit_boundary_matches_install_cap() {
    let mut table = SessionTable::new();
    table.set_max_sessions_for_test(4);
    let now = 1_000_000_000u64;
    for port in 0..2u16 {
        assert!(table.install_with_protocol(
            key_with_port(10_000 + port),
            decision(),
            metadata(),
            now,
            PROTO_TCP,
            0x02,
        ));
    }
    // len == 2, cap == 4: a forward+reverse pair (2 slots) fits exactly.
    assert!(table.can_admit(2));
    assert!(table.install_with_protocol(
        key_with_port(10_002),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x02,
    ));
    // len == 3, cap == 4: a pair no longer fits, a single still does.
    assert!(!table.can_admit(2), "cap-1 must refuse a 2-slot pair");
    assert!(table.can_admit(1));
    assert!(table.install_with_protocol(
        key_with_port(10_003),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x02,
    ));
    // len == cap: nothing fits, and the raw install agrees (this is the
    // post-preflight infallibility contract: can_admit(n)==true ⇒ the
    // next n installs return true).
    assert!(!table.can_admit(1));
    assert!(!table.install_with_protocol(
        key_with_port(10_004),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x02,
    ));
    assert_eq!(table.create_drops(), 1, "at-cap install must count a create drop");
    // can_admit(0) is the tracking-not-required case — always true.
    assert!(table.can_admit(0));
}

#[test]
fn can_admit_is_conservative_for_replacements() {
    // Matches install_with_protocol_with_origin's own cap check, which
    // refuses replacements at cap even though they would not grow the
    // table. Crediting replacements in the preflight would break the
    // infallibility contract (preflight passes, install fails).
    let mut table = SessionTable::new();
    table.set_max_sessions_for_test(1);
    let now = 1_000_000_000u64;
    let key = key_with_port(20_000);
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x02,
    ));
    assert!(!table.can_admit(1));
    assert!(
        !table.install_with_protocol(key, decision(), metadata(), now, PROTO_TCP, 0x02),
        "raw install also refuses the replacement at cap — preflight matches"
    );
}

#[test]
fn admission_refused_and_install_partial_counters_accumulate() {
    let mut table = SessionTable::new();
    assert_eq!(table.admission_refused(), 0);
    assert_eq!(table.install_partial(), 0);
    table.note_admission_refused();
    table.note_admission_refused();
    table.note_install_partial();
    assert_eq!(table.admission_refused(), 2);
    assert_eq!(table.install_partial(), 1);
}

// ── #1870: sync-family upsert infallibility at max_sessions ─────────
//
// The UpsertLocal arm (session_glue) relies on
// `upsert_synced_with_origin(_, allow_replace_local=true)` having no
// failure mode: no cap check, and the only `false` exit (the
// local-clobber guard) is bypassed. Pin both at-cap shapes in a
// release-effective `assert!` (the arm's own debug_assert!s compile
// out — #1855 contract).
#[test]
fn upsert_synced_allow_replace_is_infallible_at_cap() {
    let mut table = SessionTable::new();
    table.set_max_sessions_for_test(1);
    let key = key_v4();
    let now = 1_000_000_000u64;
    assert!(table.install_with_protocol(key.clone(), decision(), metadata(), now, PROTO_TCP, 0x10));
    assert_eq!(table.len(), 1, "table at cap");

    // Same-key replace at cap: succeeds without growth.
    assert!(
        table.upsert_synced(
            key.clone(),
            decision(),
            metadata(),
            now + 1,
            PROTO_TCP,
            0x10,
            true,
        ),
        "same-key upsert at cap must succeed"
    );
    assert_eq!(table.len(), 1);

    // New-key insert at cap: the sync family is uncapped by design
    // (#1861 row I11) — succeeds and grows past max_sessions.
    let second = SessionKey {
        src_port: key.src_port.wrapping_add(1),
        ..key
    };
    assert!(
        table.upsert_synced(
            second.clone(),
            decision(),
            metadata(),
            now + 2,
            PROTO_TCP,
            0x10,
            true,
        ),
        "new-key upsert at cap must succeed (uncapped sync family)"
    );
    assert_eq!(table.len(), 2, "table exceeds max_sessions by design");
    assert_eq!(table.create_drops(), 0, "no install-path drop counted");
}

// =====================================================================
// #2120: standby retention gate tests.
//
// The STANDBY must NOT age peer-synced sessions for an RG it does not
// forward (restoring the dead Go-GC IsLocalPrimary contract into the
// userspace wheel). These tests drive `expire_stale_entries_ha` with an
// `ExpireHaContext` built from closures so the per-RG forwarding
// predicate, the rg_epoch reader, and node_active are all controllable.
//
// NON-TAUTOLOGY: every HOLD test installs a peer-synced session that the
// PRE-FIX wheel (and the ha=None path) removes unconditionally; the
// assertion that it is RETAINED fails against the old behavior.
// =====================================================================

const TEST_CEIL_MULT: u64 = STALE_SYNCED_CEILING_MULT;
const TEST_CEIL_ABS_NS: u64 = STALE_SYNCED_CEILING_ABS_NS;

/// Build a context: this node forwards `forwarding_rgs`, node_active is
/// derived (forwards anything), and every RG reports epoch `epoch`
/// (including rg_epochs[0] for owner_rg_id<=0).
fn run_expire_ha(
    table: &mut SessionTable,
    now_ns: u64,
    forwarding_rgs: &[i32],
    epoch_for_rg: &dyn Fn(i32) -> u32,
) -> Vec<ExpiredSession> {
    let node_active = !forwarding_rgs.is_empty();
    let fwd = |rg: i32| -> bool {
        if rg > 0 {
            forwarding_rgs.contains(&rg)
        } else {
            node_active
        }
    };
    let ctx = ExpireHaContext {
        node_active,
        forwards_rg: &fwd,
        epoch_of: epoch_for_rg,
        ceiling_mult: TEST_CEIL_MULT,
        ceiling_abs_ns: TEST_CEIL_ABS_NS,
    };
    table.expire_stale_entries_ha(now_ns, Some(&ctx))
}

fn install_synced_tcp(table: &mut SessionTable, key: &SessionKey, rg: i32, now_ns: u64) {
    install_synced_tcp_origin(table, key, rg, now_ns, SessionOrigin::SyncImport);
}

fn install_synced_tcp_origin(
    table: &mut SessionTable,
    key: &SessionKey,
    rg: i32,
    now_ns: u64,
    origin: SessionOrigin,
) {
    let mut md = metadata();
    md.owner_rg_id = rg;
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        md,
        origin,
        now_ns,
        PROTO_TCP,
        0x10,
    ));
    let _ = table.drain_deltas(8);
}

// Advance just past the 300s TCP established timeout, bypassing the GC
// interval gate the way the existing wheel tests do.
fn past_tcp_timeout(then: u64) -> u64 {
    then + 302_000_000_000
}

#[test]
fn expire_holds_peer_synced_when_rg_inactive() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    table.last_gc_ns = then + 301_000_000_000;
    // This node forwards NOTHING (pure standby). RG1 inactive.
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[], &|_| 0);
    assert!(expired.is_empty(), "standby must NOT expire synced RG1 session");
    assert!(
        table.lookup(&key, past_tcp_timeout(then), 0x10).is_some(),
        "held session must still be present"
    );
    let s = table.last_pop_stats();
    assert_eq!(s.held_standby, 1, "exactly one held entry");
    assert_eq!(s.expired, 0);
    assert_eq!(s.reaped_stale_synced, 0);
}

#[test]
fn expire_ages_peer_synced_when_rg_active() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    table.last_gc_ns = then + 301_000_000_000;
    // This node FORWARDS RG1 (active owner) and the epoch matches the
    // stamped one (0 at install) so SELF-HEAL does not fire -> AGE.
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[1], &|_| 0);
    assert_eq!(expired.len(), 1, "active owner must age the session");
    assert!(table.lookup(&key, past_tcp_timeout(then), 0x10).is_none());
    let s = table.last_pop_stats();
    assert_eq!(s.expired, 1);
    assert_eq!(s.held_standby, 0);
}

#[test]
fn expire_ages_active_node_owned_session() {
    // A ForwardFlow (locally-created) session whose RG is active must
    // expire normally -- guards over-retention.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    let mut md = metadata();
    md.owner_rg_id = 1;
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        md,
        SessionOrigin::ForwardFlow,
        then,
        PROTO_TCP,
        0x10,
    ));
    let _ = table.drain_deltas(8);
    table.last_gc_ns = then + 301_000_000_000;
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[1], &|_| 0);
    assert_eq!(expired.len(), 1, "active-node-owned session must age");
    let s = table.last_pop_stats();
    assert_eq!(s.held_standby, 0);
}

#[test]
fn expire_holds_all_peer_synced_origins() {
    // SyncImport, SharedMaterialize, WorkerLocalImport are all
    // peer-synced -> all HELD on a non-forwarding node.
    for origin in [
        SessionOrigin::SyncImport,
        SessionOrigin::SharedMaterialize,
        SessionOrigin::WorkerLocalImport,
    ] {
        let mut table = SessionTable::new();
        let key = key_v4();
        let then = 1_000_000_000u64;
        install_synced_tcp_origin(&mut table, &key, 1, then, origin);
        table.last_gc_ns = then + 301_000_000_000;
        let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[], &|_| 0);
        assert!(
            expired.is_empty(),
            "origin {:?} must be held on a non-forwarding node",
            origin
        );
        assert_eq!(table.last_pop_stats().held_standby, 1, "origin {:?}", origin);
    }
}

#[test]
fn expire_ages_shared_promote_origin() {
    // SharedPromote is set only on the active node (is_peer_synced()
    // false) -> must AGE, not hold (resolves SMR M3).
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp_origin(&mut table, &key, 1, then, SessionOrigin::SharedPromote);
    table.last_gc_ns = then + 301_000_000_000;
    // Node forwards nothing, but the entry is not peer-synced and
    // node_active is false -> (peer_synced || node_active) false -> AGE.
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[], &|_| 0);
    assert_eq!(expired.len(), 1, "SharedPromote must age");
    assert_eq!(table.last_pop_stats().held_standby, 0);
}

#[test]
fn expire_holds_peer_synced_owner_rg_zero_whole_node_standby() {
    // fabric/reverse synced entry, owner_rg_id==0, node forwards
    // nothing -> held via the node-level path.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 0, then);
    table.last_gc_ns = then + 301_000_000_000;
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[], &|_| 0);
    assert!(expired.is_empty(), "owner_rg_id==0 whole-node standby must hold");
    assert_eq!(table.last_pop_stats().held_standby, 1);
}

#[test]
fn expire_ages_owner_rg_zero_on_active_node() {
    // KNOWN residual (plan A2#4): a peer-synced owner_rg_id==0 entry on
    // a node that IS active for some RG ages -- observable via the
    // dedicated counter, not a silent drop.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 0, then);
    table.last_gc_ns = then + 301_000_000_000;
    // node forwards RG1 (node_active true) but the entry's owner_rg_id==0
    // maps forwards_here -> node_active -> true; epoch matches (0) so no
    // self-heal -> AGE, tagged as the residual.
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[1], &|_| 0);
    assert_eq!(expired.len(), 1, "owner_rg_id==0 on active node ages");
    let s = table.last_pop_stats();
    assert_eq!(
        s.aged_owner_rg_zero_active_node, 1,
        "the residual must be counted"
    );
    assert_eq!(s.held_standby, 0);
}

#[test]
fn expire_standalone_ages_normally() {
    // Standalone: ha=None path. A ForwardFlow owner_rg_id==0 session
    // must age exactly like the pre-#2120 wheel.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    let mut md = metadata();
    md.owner_rg_id = 0;
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        md,
        SessionOrigin::ForwardFlow,
        then,
        PROTO_TCP,
        0x10,
    ));
    let _ = table.drain_deltas(8);
    table.last_gc_ns = then + 301_000_000_000;
    // ha=None -> standalone behavior.
    let expired = table.expire_stale_entries(past_tcp_timeout(then));
    assert_eq!(expired.len(), 1, "standalone ForwardFlow must age");
}

#[test]
fn expire_standalone_with_ctx_never_holds() {
    // Even with a context, a node that forwards NOTHING and a session
    // that is NOT peer-synced and owner_rg_id<=0 must age
    // ((peer_synced || node_active) false). Standalone safety.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    let mut md = metadata();
    md.owner_rg_id = 0;
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        md,
        SessionOrigin::ForwardFlow,
        then,
        PROTO_TCP,
        0x10,
    ));
    let _ = table.drain_deltas(8);
    table.last_gc_ns = then + 301_000_000_000;
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[], &|_| 0);
    assert_eq!(expired.len(), 1, "standalone-with-ctx must age");
    assert_eq!(table.last_pop_stats().held_standby, 0);
}

#[test]
fn expire_in_promotion_window_survives() {
    // Held past deadline while RG inactive, then this node STARTS
    // forwarding RG1 AND the epoch is bumped (r3 ordering) WITHOUT a
    // RefreshOwnerRGS landing. SELF-HEAL must re-stamp + survive.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    // First pass: standby, RG1 inactive -> HOLD (stamps seen_rg_epoch=epoch=0).
    table.last_gc_ns = then;
    let t1 = then + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t1, &[], &|_| 0);
    assert!(expired.is_empty());
    assert_eq!(table.last_pop_stats().held_standby, 1);
    // Second pass: RG1 now active AND epoch bumped to 1 (promotion), but
    // RefreshOwnerRGS has not re-stamped. SELF-HEAL fires.
    table.last_gc_ns = t1;
    let t2 = t1 + 2_000_000_000;
    let expired = run_expire_ha(&mut table, t2, &[1], &|_| 1);
    assert!(expired.is_empty(), "self-heal must keep the entry alive");
    let s = table.last_pop_stats();
    assert_eq!(s.healed_on_promote, 1, "self-heal must fire once");
    assert_eq!(s.expired, 0);
    // Re-stamped: it now ages from a full timeout. After another full
    // timeout with the SAME epoch it ages (no perpetual re-stamp).
    table.last_gc_ns = t2;
    let t3 = t2 + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t3, &[1], &|_| 1);
    assert_eq!(expired.len(), 1, "after self-heal it ages normally");
}

#[test]
fn expire_no_selfheal_when_epoch_unchanged() {
    // RG active but the epoch equals seen_rg_epoch (already healed):
    // the entry AGES (no perpetual re-stamp / over-retention).
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    table.last_gc_ns = then + 301_000_000_000;
    // epoch == 0 == the install-stamped seen_rg_epoch, RG active.
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[1], &|_| 0);
    assert_eq!(expired.len(), 1, "matching epoch + active RG -> age");
    assert_eq!(table.last_pop_stats().healed_on_promote, 0);
}

#[test]
fn expire_owner_rg_zero_survives_promotion() {
    // Held owner_rg_id==0 entry, then a NODE-LEVEL activation (epoch[0]
    // bumped). Self-heal must fire via the node epoch.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 0, then);
    table.last_gc_ns = then;
    let t1 = then + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t1, &[], &|_| 0);
    assert!(expired.is_empty());
    assert_eq!(table.last_pop_stats().held_standby, 1);
    // Node-level activation: node forwards RG1 now, node-level epoch
    // bumped to 1. owner_rg_id==0 -> forwards_here == node_active true,
    // epoch_of(0)==1 != seen(0) -> SELF-HEAL.
    table.last_gc_ns = t1;
    let t2 = t1 + 2_000_000_000;
    let expired = run_expire_ha(&mut table, t2, &[1], &|_| 1);
    assert!(expired.is_empty(), "node-level self-heal must keep it alive");
    assert_eq!(table.last_pop_stats().healed_on_promote, 1);
}

#[test]
fn expire_in_demotion_window_holds() {
    // A ForwardFlow session whose RG just flipped inactive, DemoteOwnerRGS
    // NOT yet applied -> held via the FORWARDING gate (!forwards_here),
    // not aged, because the node is still active for another RG.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    let mut md = metadata();
    md.owner_rg_id = 1; // RG1 -- about to be demoted
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        md,
        SessionOrigin::ForwardFlow, // demote flip not yet applied
        then,
        PROTO_TCP,
        0x10,
    ));
    let _ = table.drain_deltas(8);
    table.last_gc_ns = then + 301_000_000_000;
    // Node forwards RG2 (node_active true) but NOT RG1 (just demoted).
    // forwards_here(RG1)=false, node_active=true -> HOLD.
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[2], &|_| 0);
    assert!(expired.is_empty(), "demotion-window entry must be held");
    assert_eq!(table.last_pop_stats().held_standby, 1);
}

#[test]
fn expire_reaps_held_past_relative_ceiling() {
    // A held synced session past the relative ceiling
    // (MULT x 300s = 900s) is reaped even though the node never forwards
    // its RG (lost-primary-delete backstop).
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    // First HOLD pass arms first_held_ns at t1.
    table.last_gc_ns = then;
    let t1 = then + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t1, &[], &|_| 0);
    assert!(expired.is_empty());
    assert_eq!(table.last_pop_stats().held_standby, 1);
    // Past the relative ceiling measured from first_held_ns (t1):
    // ceiling = min(3 x 300s, 7d) = 900s. Advance > 900s past t1.
    table.last_gc_ns = t1;
    let t2 = t1 + 901_000_000_000;
    let expired = run_expire_ha(&mut table, t2, &[], &|_| 0);
    assert_eq!(expired.len(), 1, "held entry past relative ceiling reaped");
    let s = table.last_pop_stats();
    assert_eq!(s.reaped_stale_synced, 1);
    assert_eq!(s.held_standby, 0);
}

#[test]
fn expire_reaps_held_at_abs_cap_for_long_timeout() {
    // A 30-day TCP timeout session, held, is reaped at the ABS cap
    // (~7d), NOT at 90 days (MULT x 30d). Bounds the pathological config.
    // To keep the wheel walk bounded we install at a large `then` and
    // jump in two bounded legs (~30d then ~7d) -- the wheel is O(elapsed
    // ticks) but each tick is a near-empty bucket check.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    let thirty_days_secs = 30u64 * 24 * 60 * 60;
    table.set_timeouts(SessionTimeouts::from_seconds(thirty_days_secs, 0, 0));
    install_synced_tcp(&mut table, &key, 1, then);
    table.last_gc_ns = then;
    // Cross the 30-day timeout so the entry is idle-crossed. First hold
    // observation arms first_held_ns at t1 with held_ns == 0 -> HELD
    // (NOT reaped from its stale install-time last_seen).
    let thirty_days_ns = thirty_days_secs * 1_000_000_000;
    let t1 = then + thirty_days_ns + 2_000_000_000;
    let expired = run_expire_ha(&mut table, t1, &[], &|_| 0);
    assert!(
        expired.is_empty(),
        "idle-crossed long session held on first observation, not reaped"
    );
    // held_standby may be > 1: this single synthetic 30-day jump makes the
    // wheel cursor sweep millions of ticks, and a held entry is re-bucketed
    // to the current tick on each rotation (the same multi-rotation
    // re-processing the existing long-timeout Case-4 exhibits under a huge
    // jump). Production advances ~1 tick per call, so this is a test-only
    // artifact; the load-bearing assertions are "not reaped" + "still
    // present". first_held_ns is armed on the first observation so the cap
    // measures from there, not from the stale install-time last_seen.
    assert!(table.last_pop_stats().held_standby >= 1, "held at least once");
    assert_eq!(table.last_pop_stats().reaped_stale_synced, 0, "not yet reaped");
    // NOTE: presence via `table.len()`, NOT `lookup()` -- lookup refreshes
    // last_seen_ns (it is the packet path) and would defeat the timeout.
    assert_eq!(table.len(), 1, "long-timeout synced session retained on the standby");
    // ABS cap is 7 days from first_held_ns (t1). After > 7 days it is
    // reaped (the relative ceiling would be 90 days).
    table.last_gc_ns = t1;
    let seven_days_ns = 7u64 * 24 * 60 * 60 * 1_000_000_000;
    let t2 = t1 + seven_days_ns + 1_000_000_000;
    let expired = run_expire_ha(&mut table, t2, &[], &|_| 0);
    assert_eq!(expired.len(), 1, "reaped at the abs cap, not 90 days");
    assert!(
        table.last_pop_stats().reaped_stale_synced >= 1,
        "reaped at the abs cap"
    );
    assert_eq!(table.len(), 0, "gone after reap");
}

#[test]
fn expire_flapping_rg_still_reaps() {
    // A flapping RG (repeated promote-edge self-heals) re-stamps
    // last_seen on every activation but must NOT reset first_held_ns --
    // otherwise a dead leaked entry could be pinned forever. We arm
    // first_held, fire several self-heals (each advancing time + bumping
    // the epoch), then a final hold pass past the relative ceiling
    // measured from first_held_ns reaps it despite all the re-stamps.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    // First hold (RG inactive) arms first_held_ns at t_anchor.
    table.last_gc_ns = then;
    let t_anchor = then + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t_anchor, &[], &|_| 0);
    assert!(expired.is_empty());
    assert_eq!(table.last_pop_stats().held_standby, 1);
    // Flap: self-heal on each activation edge (RG active + a NEW epoch).
    // Advance past the timeout each iteration so the entry is idle-crossed
    // and the SELF-HEAL arm fires (re-stamping last_seen but leaving
    // first_held_ns at t_anchor). After 4 iterations the total elapsed
    // since t_anchor exceeds the 900s relative ceiling -- yet self-heal
    // keeps re-stamping because it deliberately ignores the ceiling.
    let mut t = t_anchor;
    let mut epoch = 1u32;
    for _ in 0..4 {
        table.last_gc_ns = t;
        t += 302_000_000_000; // past the 300s timeout -> idle-crossed again
        let e = epoch;
        let expired = run_expire_ha(&mut table, t, &[1], &move |_| e);
        assert!(expired.is_empty(), "self-heal keeps the entry alive");
        assert_eq!(
            table.last_pop_stats().healed_on_promote,
            1,
            "each activation edge self-heals"
        );
        epoch += 1;
    }
    // We are now well past the 900s relative ceiling measured from
    // t_anchor, but the entry survived via self-heals. A HOLD pass (RG
    // inactive) reaps it: held_ns from first_held_ns (t_anchor) >>
    // ceiling, despite the self-heal re-stamps to last_seen.
    assert!(t - t_anchor > 900_000_000_000, "past ceiling after self-heals");
    table.last_gc_ns = t;
    let t_final = t + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t_final, &[], &|_| 0);
    assert_eq!(
        expired.len(),
        1,
        "flapping self-heals must NOT reset the leak ceiling -- reaped"
    );
    assert_eq!(table.last_pop_stats().reaped_stale_synced, 1);
}

#[test]
fn promotion_restamps_held_session() {
    // The command-landed complement to expire_in_promotion_window_survives:
    // hold past deadline, then refresh_for_ha_transition (RefreshOwnerRGS
    // path) re-stamps last_seen and clears the hold clock.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    table.last_gc_ns = then;
    let t1 = then + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t1, &[], &|_| 0);
    assert!(expired.is_empty());
    assert_eq!(table.last_pop_stats().held_standby, 1);
    // RefreshOwnerRGS landed -> refresh_for_ha_transition re-stamps.
    let mut md = metadata();
    md.owner_rg_id = 1;
    assert!(table.refresh_for_ha_transition(&key, decision(), md, t1 + 1_000_000));
    // Now ages from a full timeout on the active node.
    table.last_gc_ns = t1 + 1_000_000;
    let t2 = t1 + 1_000_000 + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t2, &[1], &|_| 0);
    assert_eq!(expired.len(), 1, "after promotion refresh it ages normally");
}

#[test]
fn expire_fabric_ingress_ages_normally() {
    // fabric_ingress synced entries are NOT held (matches the fabric-skip
    // convention) -- they age even on a non-forwarding node.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    let mut md = metadata();
    md.owner_rg_id = 1;
    md.fabric_ingress = true;
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        md,
        SessionOrigin::SyncImport,
        then,
        PROTO_TCP,
        0x10,
    ));
    let _ = table.drain_deltas(8);
    table.last_gc_ns = then + 301_000_000_000;
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[], &|_| 0);
    assert_eq!(expired.len(), 1, "fabric_ingress synced must age");
    assert_eq!(table.last_pop_stats().held_standby, 0);
}

#[test]
fn expire_hold_does_not_poison_selfheal_under_epoch_skew() {
    // REGRESSION (Codex MAJOR): the worker reads the HA map and the
    // rg_epochs counter separately, so a HOLD can observe an OLD (still
    // inactive) map together with a NEW (already bumped) epoch -- the
    // old-map/new-epoch skew. The HOLD must NOT stamp seen_rg_epoch with
    // that new epoch; if it did, the NEXT pass (which sees the new ACTIVE
    // map + the same new epoch) would find current_epoch == seen_rg_epoch
    // and SKIP the self-heal, aging the very synced session this gate
    // exists to preserve.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then); // seen_rg_epoch = 0
    // Skewed HOLD pass: node still reports NOT forwarding RG1 (old map),
    // but epoch_of already returns the bumped value 7 (new epoch).
    table.last_gc_ns = then;
    let t1 = then + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t1, &[], &|_| 7);
    assert!(expired.is_empty(), "skewed hold must still hold");
    assert_eq!(table.last_pop_stats().held_standby, 1);
    // Next pass: the new ACTIVE map is now visible (node forwards RG1) and
    // the epoch is the same 7. With the fix, seen_rg_epoch is still 0
    // (HOLD did not stamp it), so current(7) != seen(0) -> SELF-HEAL.
    // Pre-fix (HOLD stamps seen=7) this would AGE -> failover drop.
    table.last_gc_ns = t1;
    let t2 = t1 + 2_000_000_000;
    let expired = run_expire_ha(&mut table, t2, &[1], &|_| 7);
    assert!(
        expired.is_empty(),
        "self-heal must fire despite the skewed hold having seen epoch 7"
    );
    assert_eq!(
        table.last_pop_stats().healed_on_promote,
        1,
        "the skewed-hold session must self-heal, not age"
    );
}

#[test]
fn promotion_refresh_with_nonzero_epoch_ages_after_one_selfheal() {
    // Companion to promotion_restamps_held_session with a PRODUCTION
    // non-zero activation epoch (Codex Medium): refresh_for_ha_transition
    // resets seen_rg_epoch to 0, so an IDLE active-owned session self-heals
    // exactly ONCE (bounded one-shot extra retention) and then ages -- it
    // never lives forever and the over-retention is one timeout.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    // Hold while inactive.
    table.last_gc_ns = then;
    let t1 = then + 302_000_000_000;
    assert!(run_expire_ha(&mut table, t1, &[], &|_| 0).is_empty());
    // RefreshOwnerRGS lands -> re-stamp, seen_rg_epoch reset to 0.
    let mut md = metadata();
    md.owner_rg_id = 1;
    assert!(table.refresh_for_ha_transition(&key, decision(), md, t1 + 1_000_000));
    // Active node, production epoch 5. First idle expiry: current(5) !=
    // seen(0) -> one self-heal (bounded one-shot).
    table.last_gc_ns = t1 + 1_000_000;
    let t2 = t1 + 1_000_000 + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t2, &[1], &|_| 5);
    assert!(expired.is_empty(), "one bounded self-heal after refresh");
    assert_eq!(table.last_pop_stats().healed_on_promote, 1);
    // Second idle expiry: current(5) == seen(5, just stamped) -> AGE.
    table.last_gc_ns = t2;
    let t3 = t2 + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t3, &[1], &|_| 5);
    assert_eq!(expired.len(), 1, "ages on the next pass -- no perpetual re-stamp");
}

// ===================================================================
// #2134: per-IP session-limit lifecycle, maintained inside SessionTable
// at the install/remove sinks + the two in-place HA transitions. These
// tests drive the REAL install/expire/promote/demote paths (NOT the
// retired ScreenState `session_created` manual hook the old screen tests
// used — that gap was exactly the #2134 no-op). Each is written to FAIL
// if its enforcement-driving count maintenance is reverted to a no-op.
// ===================================================================

/// A counted forward install with a distinct src IP per flow.
fn limit_key(src_octet: u8, dst_octet: u8, src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, src_octet)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, dst_octet)),
        src_port,
        dst_port: 443,
    }
}

/// §5.1 enforcement decision (the security purpose): with the OFF-gate
/// ON, installing `n` forward flows from one source IP drives the count
/// to exactly `n` through the REAL install path, and the new-flow
/// enforcement predicate (`count >= limit`) holds for the (n+1)-th
/// attempt. This FAILS if the install-site increment is reverted (count
/// stays 0, the predicate never fires, the limit is a no-op — the #2134
/// bug). The DST mirror is asserted too.
#[test]
fn session_limit_count_increments_on_forward_install_src_and_dst() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
    let limit = 3u32;

    // Distinct flows (distinct dst host so each is a fresh key) sharing
    // one src IP, all targeting one dst host so dst also counts.
    for i in 0..limit {
        let key = SessionKey {
            src_ip: src,
            dst_ip: dst,
            src_port: 40000 + i as u16,
            ..limit_key(7, 9, 0)
        };
        assert!(table.install_with_protocol_with_origin(
            key,
            decision(),
            metadata(),
            SessionOrigin::ForwardFlow,
            now,
            PROTO_TCP,
            0x10,
        ));
    }

    assert_eq!(
        table.session_limit_src_count(src),
        limit,
        "src count must equal the number of forward installs"
    );
    assert_eq!(
        table.session_limit_dst_count(dst),
        limit,
        "dst count must equal the number of forward installs"
    );
    // The (limit+1)-th new flow's enforcement predicate must fire.
    assert!(
        table.session_limit_src_count(src) >= limit,
        "over-limit src predicate must hold (enforcement would drop)"
    );
    assert!(
        table.session_limit_dst_count(dst) >= limit,
        "over-limit dst predicate must hold"
    );
}

/// §5.2 established-flow regression (the r2 BLOCKER): the per-packet
/// session HIT path (`lookup` / `touch`) must NOT change the per-IP
/// count — only a NEW install does. If the count were maintained
/// per-packet (or the check left in the screen stage), an at-limit
/// flow's own data packets would re-trip the limit. Here, after `n`
/// installs (count == n), MANY lookups/touches of those live sessions
/// leave the count at exactly `n` — never n+1, never growing.
#[test]
fn session_limit_count_unchanged_by_established_flow_packets() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));
    let n = 4u32;
    let mut keys = Vec::new();
    for i in 0..n {
        let key = SessionKey {
            src_ip: src,
            src_port: 41000 + i as u16,
            ..limit_key(11, 9, 0)
        };
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            metadata(),
            SessionOrigin::ForwardFlow,
            now,
            PROTO_TCP,
            0x10,
        ));
        keys.push(key);
    }
    assert_eq!(table.session_limit_src_count(src), n);

    // Drive many established-flow data packets (session HIT + keepalive).
    for tick in 1..200u64 {
        for key in &keys {
            let _ = table.lookup(key, now + tick * 1_000_000, 0x10);
            table.touch(key, now + tick * 1_000_000);
        }
    }
    assert_eq!(
        table.session_limit_src_count(src),
        n,
        "established-flow packets must NOT change the count (r2 BLOCKER)"
    );
}

/// §5.3 decrement + evict-to-0 across the timer wheel + re-admit: after
/// expiry the count decrements and the map ENTRY is removed at 0 (#2128
/// evict-on-zero), and the IP can be admitted again.
#[test]
fn session_limit_decrements_and_evicts_on_expire() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let then = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 13));
    let key = SessionKey {
        src_ip: src,
        ..limit_key(13, 9, 42000)
    };
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        then,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(table.session_limit_src_count(src), 1);
    assert_eq!(table.session_limit_src_map_len(), 1);

    table.last_gc_ns = then + 301_000_000_000;
    let expired = table.expire_stale_entries(then + 302_000_000_000);
    assert_eq!(expired.len(), 1);
    assert_eq!(
        table.session_limit_src_count(src),
        0,
        "count must decrement on expire"
    );
    assert_eq!(
        table.session_limit_src_map_len(),
        0,
        "map entry must be evicted at 0 (#2128)"
    );
    assert_eq!(table.session_limit_dst_map_len(), 0);

    // Re-admittable: a fresh install for the same IP works and counts.
    let key2 = SessionKey {
        src_ip: src,
        src_port: 42001,
        ..limit_key(13, 9, 0)
    };
    assert!(table.install_with_protocol_with_origin(
        key2,
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        then + 303_000_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(table.session_limit_src_count(src), 1);
}

/// §5.4 decrement across the explicit `delete` path (clear / RST
/// teardown / fabric-cancel all funnel through `remove_entry`).
#[test]
fn session_limit_decrements_on_explicit_delete() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 15));
    let key = SessionKey {
        src_ip: src,
        ..limit_key(15, 9, 43000)
    };
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        now,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(table.session_limit_src_count(src), 1);
    table.delete(&key);
    assert_eq!(table.session_limit_src_count(src), 0);
    assert_eq!(table.session_limit_src_map_len(), 0);
}

/// §5.6 HA exclusion + promote + demote — the two in-place transition
/// sites that bypass the install/remove choke points. FAILS if either
/// explicit increment (promote) or decrement (demote) is omitted.
#[test]
fn session_limit_ha_import_promote_demote_count() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 17));
    let key = SessionKey {
        src_ip: src,
        ..limit_key(17, 9, 44000)
    };
    let mut meta = metadata();
    meta.owner_rg_id = 1;

    // Import a peer session (SyncImport) — must NOT count locally.
    assert!(table.upsert_synced_with_origin(
        SessionInstall {
            key: key.clone(),
            decision: decision(),
            metadata: meta.clone(),
            origin: SessionOrigin::SyncImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        },
        false,
    ));
    assert_eq!(
        table.session_limit_src_count(src),
        0,
        "peer-synced import must not count locally"
    );

    // Promote synced -> local: +1 exactly (in-place update_session).
    assert!(table.promote_synced_with_origin(SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: meta.clone(),
        origin: SessionOrigin::SharedPromote,
        now_ns: now + 1_000_000,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
    }));
    assert_eq!(
        table.session_limit_src_count(src),
        1,
        "promote synced->local must increment (in-place site)"
    );

    // Demote local -> synced: -1 and evict at 0 (in-place demote).
    assert_eq!(table.demote_owner_rg(1).len(), 1);
    assert_eq!(
        table.session_limit_src_count(src),
        0,
        "demote local->synced must decrement (in-place site)"
    );
    assert_eq!(table.session_limit_src_map_len(), 0);
}

/// §5.7 reverse + seed exclusion: reverse-flow and MissingNeighborSeed
/// installs must NOT increment (counted-class predicate).
#[test]
fn session_limit_excludes_reverse_and_seed_installs() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;

    let rev_src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 19));
    let rev_key = SessionKey {
        src_ip: rev_src,
        ..limit_key(19, 9, 45000)
    };
    let mut rev_meta = metadata();
    rev_meta.is_reverse = true;
    assert!(table.install_with_protocol_with_origin(
        rev_key,
        decision(),
        rev_meta,
        SessionOrigin::ReverseFlow,
        now,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(
        table.session_limit_src_count(rev_src),
        0,
        "reverse-flow install must not count"
    );

    let seed_src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 21));
    let seed_key = SessionKey {
        src_ip: seed_src,
        ..limit_key(21, 9, 46000)
    };
    assert!(table.install_with_protocol_with_origin(
        seed_key,
        decision(),
        metadata(),
        SessionOrigin::MissingNeighborSeed,
        now,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(
        table.session_limit_src_count(seed_src),
        0,
        "missing-neighbor seed install must not count"
    );
}

/// §5.8 idempotent re-install (the defensive pre-clear path): installing
/// the same key twice nets to count 1, not 2 (pre-clear decrement +
/// install increment self-cancel on the same IP).
#[test]
fn session_limit_idempotent_reinstall_nets_to_one() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 23));
    let key = SessionKey {
        src_ip: src,
        ..limit_key(23, 9, 47000)
    };
    for t in 0..2u64 {
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            metadata(),
            SessionOrigin::ForwardFlow,
            now + t * 1_000_000,
            PROTO_TCP,
            0x10,
        ));
    }
    assert_eq!(
        table.session_limit_src_count(src),
        1,
        "re-install of the same key must net to 1, not 2"
    );
    assert_eq!(table.session_limit_src_map_len(), 1);
}

/// §5.9 differential / invariant (the strongest guard): after an
/// arbitrary sequence of install / expire / delete / promote / demote /
/// refresh, the sum of per-IP src counts EQUALS the number of live
/// counted entries (`!is_reverse && !is_peer_synced && !is_seed`). Same
/// for dst. Catches ANY missed transition site.
#[test]
fn session_limit_counts_match_live_counted_entries_invariant() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let mut now = 1_000_000_000u64;

    // Build a varied population.
    let mut counted_keys: Vec<SessionKey> = Vec::new();
    for i in 0..12u32 {
        now += 1_000_000;
        let key = SessionKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, (i % 4) as u8 + 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, (i % 3) as u8 + 1)),
            src_port: 50000 + i as u16,
            ..limit_key(0, 0, 0)
        };
        let mut meta = metadata();
        meta.owner_rg_id = 1;
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            meta,
            SessionOrigin::ForwardFlow,
            now,
            PROTO_TCP,
            0x10,
        ));
        counted_keys.push(key);
    }
    // A reverse + a seed (uncounted) + a synced import (uncounted).
    let mut rev_meta = metadata();
    rev_meta.is_reverse = true;
    let _ = table.install_with_protocol_with_origin(
        SessionKey {
            src_port: 60001,
            ..limit_key(9, 9, 0)
        },
        decision(),
        rev_meta,
        SessionOrigin::ReverseFlow,
        now,
        PROTO_TCP,
        0x10,
    );
    let _ = table.install_with_protocol_with_origin(
        SessionKey {
            src_port: 60002,
            ..limit_key(9, 9, 0)
        },
        decision(),
        metadata(),
        SessionOrigin::MissingNeighborSeed,
        now,
        PROTO_TCP,
        0x10,
    );
    let synced_key = SessionKey {
        src_port: 60003,
        ..limit_key(8, 8, 0)
    };
    let mut synced_meta = metadata();
    synced_meta.owner_rg_id = 1;
    let _ = table.upsert_synced_with_origin(
        SessionInstall {
            key: synced_key.clone(),
            decision: decision(),
            metadata: synced_meta.clone(),
            origin: SessionOrigin::SyncImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        },
        false,
    );

    // Mutate: delete a few, promote the synced import, refresh one,
    // then demote RG 1.
    table.delete(&counted_keys[0]);
    table.delete(&counted_keys[5]);
    assert!(table.promote_synced_with_origin(SessionUpdate {
        key: &synced_key,
        decision: decision(),
        metadata: synced_meta.clone(),
        origin: SessionOrigin::SharedPromote,
        now_ns: now + 1_000_000,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
    }));
    // refresh that preserves origin/direction (must not change counts).
    let refresh_target = counted_keys[2].clone();
    assert!(table.refresh_for_ha_transition(&refresh_target, decision(), metadata(), now + 2_000_000));

    let check_invariant = |table: &SessionTable, label: &str| {
        let mut src_live: std::collections::HashMap<IpAddr, u32> = std::collections::HashMap::new();
        let mut dst_live: std::collections::HashMap<IpAddr, u32> = std::collections::HashMap::new();
        table.iter_with_origin(|key, _decision, md, origin| {
            if !md.is_reverse && !origin.is_peer_synced() && !origin.is_transient_local_seed() {
                *src_live.entry(key.src_ip).or_insert(0) += 1;
                *dst_live.entry(key.dst_ip).or_insert(0) += 1;
            }
        });
        // Per-IP count must equal the number of live counted entries for
        // that IP, for every IP that has at least one live counted entry.
        for (ip, cnt) in &src_live {
            assert_eq!(
                table.session_limit_src_count(*ip),
                *cnt,
                "{label}: src count for {ip:?} must match live counted entries"
            );
        }
        for (ip, cnt) in &dst_live {
            assert_eq!(
                table.session_limit_dst_count(*ip),
                *cnt,
                "{label}: dst count for {ip:?} must match live counted entries"
            );
        }
        // Map sizes must exactly equal distinct live counted IP sets
        // (no leaked / orphaned entries — #2128).
        assert_eq!(
            table.session_limit_src_map_len(),
            src_live.len(),
            "{label}: src map size must equal distinct live counted src IPs"
        );
        assert_eq!(
            table.session_limit_dst_map_len(),
            dst_live.len(),
            "{label}: dst map size must equal distinct live counted dst IPs"
        );
    };
    check_invariant(&table, "after mutations");

    // Demote RG 1 — every counted RG-1 session becomes uncounted.
    table.demote_owner_rg(1);
    check_invariant(&table, "after demote RG1");

    // Expire everything; counts must drain to empty.
    table.last_gc_ns = now + 600_000_000_000;
    let _ = table.expire_stale_entries(now + 601_000_000_000);
    assert_eq!(table.session_limit_src_map_len(), 0);
    assert_eq!(table.session_limit_dst_map_len(), 0);
}

/// §5.10 runtime disable clears the maps (reviewer B MAJOR): turning the
/// OFF-gate off must clear both count maps so a later re-enable starts
/// from 0 and cannot spuriously block an under-limit IP. FAILS if
/// clear-on-disable is omitted.
#[test]
fn session_limit_clear_on_disable() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 25));
    for i in 0..3u32 {
        let key = SessionKey {
            src_ip: src,
            src_port: 52000 + i as u16,
            ..limit_key(25, 9, 0)
        };
        assert!(table.install_with_protocol_with_origin(
            key,
            decision(),
            metadata(),
            SessionOrigin::ForwardFlow,
            now,
            PROTO_TCP,
            0x10,
        ));
    }
    assert_eq!(table.session_limit_src_count(src), 3);

    // Disable: both maps must clear.
    table.set_session_limit_active(false);
    assert_eq!(table.session_limit_src_map_len(), 0, "src map must clear on disable");
    assert_eq!(table.session_limit_dst_map_len(), 0, "dst map must clear on disable");

    // Re-enable: a fresh flow starts the count from 0 (not stale 3).
    table.set_session_limit_active(true);
    let key = SessionKey {
        src_ip: src,
        src_port: 52999,
        ..limit_key(25, 9, 0)
    };
    assert!(table.install_with_protocol_with_origin(
        key,
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        now + 1_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(
        table.session_limit_src_count(src),
        1,
        "re-enable must start from 0, not the stale pre-disable count"
    );
}

/// OFF-gate zero-cost: when the feature is OFF, install/remove perform NO
/// counter maintenance (the maps stay empty regardless of traffic).
#[test]
fn session_limit_off_gate_skips_all_maintenance() {
    let mut table = SessionTable::new();
    // OFF (default).
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 27));
    for i in 0..5u32 {
        let key = SessionKey {
            src_ip: src,
            src_port: 53000 + i as u16,
            ..limit_key(27, 9, 0)
        };
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            metadata(),
            SessionOrigin::ForwardFlow,
            now,
            PROTO_TCP,
            0x10,
        ));
        table.delete(&key);
    }
    assert_eq!(
        table.session_limit_src_count(src),
        0,
        "OFF-gate: no count maintained"
    );
    assert_eq!(table.session_limit_src_map_len(), 0);
    assert_eq!(table.session_limit_dst_map_len(), 0);
}

// === #2220 flow-cache per-session keepalive ====================
//
// The flow-cache fast path (poll_descriptor/flow_cache_hit.rs) is the
// ONLY code path that refreshes a forwarded flow's last_seen_ns. Before
// #2220 it used a binding-GLOBAL modulo-64 counter: a low-rate flow
// co-resident with a saturating flow could be served entirely from the
// cache for a whole timeout window without its session ever being
// touched, then reaped while still forwarding. The fix replaces that
// counter with `SessionTable::touch_if_stale`, a per-session
// time-threshold keepalive. These tests pin that contract and FAIL
// against the old global-modulo logic (modelled inline below).

/// touch_if_stale re-stamps a session ONLY once it has gone idle for at
/// least `expires_after_ns / SESSION_KEEPALIVE_DIVISOR` (a quarter of
/// its own timeout). Below that threshold it is a pure read (no write,
/// no wheel re-bucket); at/after it, last_seen advances.
#[test]
fn touch_if_stale_throttles_until_quarter_timeout() {
    let mut table = SessionTable::new();
    let key = key_v6(); // UDP, 60 s timeout
    let install_ns = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        install_ns,
        PROTO_UDP,
        0
    ));
    let timeout = table
        .entry_by_key(&key)
        .expect("session installed")
        .expires_after_ns;
    assert_eq!(timeout, DEFAULT_UDP_SESSION_TIMEOUT_NS, "UDP 60 s timeout");
    let quarter = timeout / SESSION_KEEPALIVE_DIVISOR; // 15 s

    // One ns BEFORE the quarter-timeout threshold: must NOT touch.
    let before = install_ns + quarter - 1;
    table.touch_if_stale(&key, before);
    assert_eq!(
        table.entry_by_key(&key).unwrap().last_seen_ns,
        install_ns,
        "touch_if_stale must not re-stamp before idle reaches timeout/4"
    );

    // AT the quarter-timeout threshold: must touch.
    let at = install_ns + quarter;
    table.touch_if_stale(&key, at);
    assert_eq!(
        table.entry_by_key(&key).unwrap().last_seen_ns,
        at,
        "touch_if_stale must re-stamp once idle reaches timeout/4"
    );

    // Immediately again (idle ~0): must NOT touch (steady-state read).
    table.touch_if_stale(&key, at + 1_000_000);
    assert_eq!(
        table.entry_by_key(&key).unwrap().last_seen_ns,
        at,
        "touch_if_stale must stay a pure read until the next threshold"
    );
}

/// FAIL-ON-REVERT core: a UDP flow served continuously from the flow
/// cache (touch_if_stale on every hit, sub-timeout cadence) must NEVER
/// be GC'd, and its last_seen must keep advancing across the whole run.
/// A control session that receives NO keepalive expires at its timeout
/// — proving the keepalive, not the wheel, is what keeps the live flow.
#[test]
fn touch_if_stale_keeps_active_cache_flow_alive() {
    let mut table = SessionTable::new();
    let live = key_v6(); // UDP 60 s, actively forwarding via the cache
    let dead = SessionKey {
        src_port: 6001,
        ..key_v6()
    }; // UDP 60 s, no traffic (control)
    let install_ns = 1_000_000_000u64;
    for k in [&live, &dead] {
        assert!(table.install_with_protocol(
            k.clone(),
            decision(),
            metadata(),
            install_ns,
            PROTO_UDP,
            0
        ));
    }
    let _ = table.drain_deltas(64);

    // Drive 600 s (10× the UDP timeout) of cache hits for the LIVE flow
    // at a 2 s per-flow cadence — the kind of moderate-rate flow #2220
    // says the old global-modulo counter could starve. Run GC every tick.
    let cadence = 2 * WHEEL_TICK_NS;
    let mut now = install_ns;
    for _ in 0..300u64 {
        now += cadence;
        table.touch_if_stale(&live, now);
        // GC gate: advance last_gc so each call actually sweeps.
        table.last_gc_ns = now - SESSION_GC_INTERVAL_NS;
        let expired = table.expire_stale_entries(now);
        // The live flow must never appear in an expiry batch.
        assert!(
            !expired.iter().any(|e| e.key == live),
            "active cache-served flow GC'd mid-flow at now={now}: {expired:?}"
        );
    }

    // Live flow still present, last_seen well past install (keepalive ran).
    let live_last = table
        .entry_by_key(&live)
        .expect("active cache flow must still be in the table")
        .last_seen_ns;
    assert!(
        live_last > install_ns + DEFAULT_UDP_SESSION_TIMEOUT_NS,
        "live flow last_seen ({live_last}) must advance past one timeout window"
    );

    // The untouched control flow expired at its 60 s timeout (a Close
    // delta was emitted for it) — confirms expiry is real, not disabled.
    assert!(
        table.entry_by_key(&dead).is_none(),
        "the no-traffic control session must have expired"
    );
    assert!(
        table
            .drain_deltas(64)
            .iter()
            .any(|d| d.key == dead && d.kind == SessionDeltaKind::Close),
        "expired control session must emit a Close delta"
    );
}

/// FAIL-ON-REVERT (explicit): replays the exact #2220 skew. A saturating
/// high-rate flow and a steady low-rate flow share a binding. The old
/// code is reproduced inline (one binding-global counter; a flow is
/// touched only when its OWN hit lands on a global multiple of 64). The
/// new code calls `touch_if_stale` per hit. The low-rate flow survives
/// under the new code and is reaped under the old — so this test fails
/// if `touch_if_stale` is reverted to the global-modulo counter.
#[test]
fn touch_if_stale_survives_skew_that_starves_global_modulo() {
    let install_ns = 1_000_000_000u64;
    let high = make_v4_key(1, 7001); // saturating UDP flow
    let low = make_v4_key(2, 7002); // steady low-rate UDP flow

    // Interleave: 64 high-rate hits per 1 low-rate hit, both cache-
    // resident. Run for 10× the UDP timeout. Per-flow now_ns spacing:
    // high hits ~every 1 ms, the low hit closes each 64-hit group.
    let group_span = 5 * WHEEL_TICK_NS; // low flow ~ every 5 s
    let groups = 120u64; // 600 s total

    // --- OLD logic (binding-global modulo-64), reproduced inline ---
    {
        let mut table = SessionTable::new();
        for k in [&high, &low] {
            assert!(table.install_with_protocol(
                k.clone(),
                decision(),
                metadata(),
                install_ns,
                PROTO_UDP,
                0
            ));
        }
        let mut global_touch: u64 = 0;
        let mut now = install_ns;
        let mut low_reaped = false;
        for _ in 0..groups {
            // 64 high-rate hits monopolise the modulo boundaries.
            for _ in 0..64u64 {
                now += group_span / 64;
                global_touch += 1;
                if global_touch & 63 == 0 {
                    table.touch(&high, now);
                }
            }
            // one low-rate hit — lands mid-group, never on & 63 == 0.
            global_touch += 1;
            if global_touch & 63 == 0 {
                table.touch(&low, now);
            }
            table.last_gc_ns = now - SESSION_GC_INTERVAL_NS;
            let expired = table.expire_stale_entries(now);
            if expired.iter().any(|e| e.key == low) {
                low_reaped = true;
            }
        }
        assert!(
            low_reaped && table.entry_by_key(&low).is_none(),
            "PRECONDITION: the OLD global-modulo logic must starve+reap \
             the low-rate flow — if this fails the test no longer proves \
             a regression"
        );
    }

    // --- NEW logic (per-session touch_if_stale) ---
    {
        let mut table = SessionTable::new();
        for k in [&high, &low] {
            assert!(table.install_with_protocol(
                k.clone(),
                decision(),
                metadata(),
                install_ns,
                PROTO_UDP,
                0
            ));
        }
        let mut now = install_ns;
        for _ in 0..groups {
            for _ in 0..64u64 {
                now += group_span / 64;
                table.touch_if_stale(&high, now);
            }
            table.touch_if_stale(&low, now);
            table.last_gc_ns = now - SESSION_GC_INTERVAL_NS;
            let expired = table.expire_stale_entries(now);
            assert!(
                !expired.iter().any(|e| e.key == low),
                "NEW logic must keep the low-rate flow alive (got {expired:?})"
            );
        }
        assert!(
            table.entry_by_key(&low).is_some(),
            "NEW per-session keepalive must leave the low-rate flow live"
        );
        assert!(
            table.entry_by_key(&high).is_some(),
            "the high-rate flow stays live too"
        );
    }
}

// === #2442 loss-of-sync resync tests ==========================
//
// `push_delta` drops a delta when the in-worker ring is at
// MAX_SESSION_DELTAS, counting `delta_drops` but — pre-#2442 — never
// surfacing the loss. The fix latches a loss-of-sync signal
// (`take_delta_loss`) that the worker loop reads to force a full owner-RG
// export so the downstream session-sync consumer rescans the table truth.

/// Build a synthetic Open delta from the shared test fixtures. Used only to
/// drive `push_delta` to the ring limit without installing real sessions.
fn open_delta(key: SessionKey) -> SessionDelta {
    SessionDelta {
        kind: SessionDeltaKind::Open,
        key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
        created_ns: 0,
        last_seen_ns: 0,
        counters: SessionCounters::default(),
    }
}

/// (a) Overflowing the ring sets the loss latch and counts the drop.
/// FAIL-ON-REVERT: if `push_delta` stops setting `delta_loss_pending` the
/// latch stays false and this assert goes red — the loss becomes invisible.
#[test]
fn delta_ring_overflow_sets_loss_signal() {
    let mut table = SessionTable::new();
    // Fill exactly to the cap — no drops yet.
    for i in 0..MAX_SESSION_DELTAS {
        table.push_delta(open_delta(make_v4_key(1, 1000 + (i as u16))));
    }
    assert_eq!(table.delta_drops(), 0, "filling to cap must not drop");
    assert!(
        !table.take_delta_loss(),
        "no loss latched before any overflow"
    );
    // One more push overflows -> drop + loss latch.
    table.push_delta(open_delta(make_v4_key(2, 2000)));
    assert_eq!(table.delta_drops(), 1, "overflow must count one drop");
    assert!(table.delta_loss_pending, "overflow must latch loss-of-sync");
}

/// (b) The loss is reported to the consumer via `take_delta_loss`, and a
/// plain `drain_deltas` does NOT clear it (drain and loss are distinct
/// signals — the consumer must learn the stream was lossy).
#[test]
fn drain_does_not_clear_loss_only_take_does() {
    let mut table = SessionTable::new();
    for i in 0..=MAX_SESSION_DELTAS {
        table.push_delta(open_delta(make_v4_key(1, 100 + (i as u16))));
    }
    assert!(table.delta_loss_pending, "overflowed -> latched");
    // Draining the surviving deltas must not swallow the loss signal.
    let _ = table.drain_deltas(MAX_SESSION_DELTAS);
    assert!(
        table.delta_loss_pending,
        "drain must not clear the loss latch"
    );
    assert!(
        table.take_delta_loss(),
        "consumer take must observe the loss"
    );
}

/// (c) DEBOUNCE: a sustained overflow that drops many deltas before the
/// consumer reads raises exactly ONE loss episode. A second `take` with no
/// fresh drop in between returns false (no resync storm).
#[test]
fn loss_signal_debounces_a_burst_into_one_episode() {
    let mut table = SessionTable::new();
    // Overflow hard: push far past the cap so MANY deltas drop.
    for i in 0..(MAX_SESSION_DELTAS * 3) {
        table.push_delta(open_delta(make_v4_key((i % 250) as u8, (i % 1000) as u16)));
    }
    assert!(
        table.delta_drops() >= (MAX_SESSION_DELTAS as u64) * 2,
        "a 3x-cap burst drops well over a cap's worth"
    );
    // The whole burst collapses to one episode.
    assert!(table.take_delta_loss(), "first take sees the episode");
    assert!(
        !table.take_delta_loss(),
        "no fresh drop -> second take is silent (debounced)"
    );
}

/// (d) After the consumer takes (models a completed resync) the signal
/// clears; a FRESH overflow re-arms a NEW episode.
#[test]
fn fresh_overflow_after_take_rearms_a_new_episode() {
    let mut table = SessionTable::new();
    for i in 0..=MAX_SESSION_DELTAS {
        table.push_delta(open_delta(make_v4_key(1, i as u16)));
    }
    assert!(table.take_delta_loss(), "episode 1 observed");
    assert!(!table.take_delta_loss(), "cleared after take");
    // Drain so the ring is empty again (a real resync would too), then a new
    // burst overflows and re-arms.
    let _ = table.drain_deltas(MAX_SESSION_DELTAS * 4);
    for i in 0..=MAX_SESSION_DELTAS {
        table.push_delta(open_delta(make_v4_key(2, i as u16)));
    }
    assert!(
        table.take_delta_loss(),
        "a fresh overflow re-arms a new loss episode"
    );
}

/// RESYNC TRIGGER: the loss path re-exports owned forward sessions. Install
/// real owned sessions, drain their open deltas (consumer is caught up),
/// then run the same full-export walk the worker loop fires on loss and
/// assert every owned forward session is re-emitted as a fresh Open delta —
/// i.e. the consumer can rebuild the table truth after a lossy stream.
#[test]
fn loss_resync_re_exports_owned_forward_sessions() {
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let keys: Vec<SessionKey> = (0..5).map(|i| make_v4_key(10, 3000 + i)).collect();
    for key in &keys {
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_UDP,
            0
        ));
    }
    // Consumer drains the install open-deltas: it is now caught up.
    let drained = table.drain_deltas(64);
    assert_eq!(drained.len(), keys.len(), "one open delta per install");
    assert!(!table.has_pending_deltas());

    // The full-export walk the worker loop runs on loss (owner RG 1 from the
    // shared `metadata()` fixture) re-emits an open delta per owned session.
    let owner_rgs = table.all_owner_rg_ids();
    assert!(
        owner_rgs.contains(&1),
        "owner RG 1 (the metadata fixture) is present"
    );
    crate::afxdp::export_forward_sessions_for_owner_rgs(&mut table, &owner_rgs);
    let resync = table.drain_deltas(64);
    assert_eq!(
        resync.len(),
        keys.len(),
        "resync re-emits every owned forward session"
    );
    assert!(
        resync.iter().all(|d| d.kind == SessionDeltaKind::Open),
        "resync deltas are all Open (table-truth re-population)"
    );
    for key in &keys {
        assert!(
            resync.iter().any(|d| &d.key == key),
            "owned session {key:?} re-exported on resync"
        );
    }
}

/// #2442 MAJOR (hostile review): the resync re-export must NOT overflow the
/// 4096-slot ring. A worker can own up to DEFAULT_MAX_SESSIONS (131072)
/// forward sessions — 32x the ring. A naive "drain then push all N" overflows
/// at delta 4097, drops sessions 4097..N, re-latches the loss, and storms
/// every cycle (the peer never gets a complete snapshot).
///
/// This test installs >4096 owned forward sessions and runs the SAME chunked
/// drain-as-you-export the worker loop performs (collect candidates -> emit in
/// chunks of < cap -> drain between chunks). It asserts:
///   (a) the COMPLETE snapshot ships (all N open deltas reach the drain sink,
///       not 4096);
///   (b) the loss latch is CLEAR after the resync (no permanent re-arm);
///   (c) delta_drops does NOT grow across repeated resync cycles (converges).
///
/// FAIL-ON-REVERT: the naive unbounded export (push all then drain once) ships
/// only 4096 and leaves the latch armed with delta_drops > 0 — reds (a)/(b).
#[test]
fn resync_ships_complete_snapshot_above_ring_cap_without_relatching() {
    const RESYNC_EXPORT_CHUNK: usize = 2048; // mirror the worker loop
    let n: usize = MAX_SESSION_DELTAS + 1000; // 5096 > 4096 cap
    assert!(n > MAX_SESSION_DELTAS, "must exceed the ring to exercise the hole");

    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let mut keys: Vec<SessionKey> = Vec::with_capacity(n);
    for i in 0..n {
        // Unique keys: src octet 0..255 x port. dst is fixed in make_v4_key.
        let key = make_v4_key((i / 256) as u8, ((i % 256) as u16) + 1000);
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_UDP,
            0
        ));
        keys.push(key);
    }
    // The installs themselves overflowed the ring (n > cap) and latched loss.
    assert!(table.delta_drops() > 0, "installing > cap deltas overflows the ring");
    let drops_after_install = table.delta_drops();

    // === one chunked drain-as-you-export resync cycle (mirrors loop_body) ===
    // The export PHASE alone must re-emit the complete owned-session set; the
    // backlog drain ships a subset and is a different signal.
    let exported = run_chunked_resync(&mut table, RESYNC_EXPORT_CHUNK);

    // (a) COMPLETE snapshot: every owned forward session re-emitted.
    assert_eq!(
        exported, n,
        "resync export must ship the COMPLETE snapshot ({n}), not the ring cap"
    );
    // (b) no permanent re-arm: the chunked export never overflowed.
    assert!(
        !table.take_delta_loss(),
        "loss latch must be CLEAR after a complete chunked resync"
    );
    assert_eq!(
        table.delta_drops(),
        drops_after_install,
        "the resync export itself must not drop a single delta"
    );

    // (c) convergence: a second resync cycle ships the same complete snapshot
    // and still drops nothing — delta_drops does not climb cycle over cycle.
    let exported2 = run_chunked_resync(&mut table, RESYNC_EXPORT_CHUNK);
    assert_eq!(exported2, n, "second cycle still ships the complete snapshot");
    assert_eq!(
        table.delta_drops(),
        drops_after_install,
        "delta_drops must NOT grow across resync cycles (converged)"
    );
    assert!(!table.take_delta_loss(), "still no spurious re-arm");
}

/// Drive the chunked drain-as-you-export resync the worker loop performs, but
/// drain into a counter sink instead of `flush_session_deltas`. Clears the
/// loss latch (as `take_delta_loss` does in the loop), drains+discards the
/// backlog so the ring starts empty, then emits the owned forward candidates
/// in chunks, draining between chunks. Returns the number of open deltas the
/// EXPORT PHASE shipped — the completeness measure for the re-derived snapshot.
fn run_chunked_resync(table: &mut SessionTable, chunk: usize) -> usize {
    let _ = table.take_delta_loss();
    // Drain (discard) the existing backlog so the ring starts empty, exactly
    // as the worker loop does before the chunked export.
    while !table.drain_deltas(256).is_empty() {}

    let owner_rgs = table.all_owner_rg_ids();
    let candidates = crate::afxdp::forward_export_candidates_for_owner_rgs(table, &owner_rgs);
    let mut exported = 0usize;
    for c in candidates.chunks(chunk) {
        for (key, decision, metadata, origin) in c.iter().cloned() {
            table.emit_open_delta_with_origin(key, decision, metadata, origin, true);
        }
        loop {
            let d = table.drain_deltas(256);
            if d.is_empty() {
                break;
            }
            exported += d.iter().filter(|x| x.kind == SessionDeltaKind::Open).count();
        }
    }
    exported
}

// ---- #2364: seeded session-index hashing --------------------------------

/// The session indices are private, so assert the hardening property at
/// the BuildHasher the maps are constructed with: `FxSeededState` over a
/// `SessionKey` must produce a seed-dependent bucket distribution (so an
/// attacker cannot precompute a collision chain offline) while staying
/// stable for a fixed seed (so the live table's lookup/insert agree).
///
/// Fail-on-revert: the reverted state used `FxHashMap::default()`
/// (= `FxBuildHasher`, unseeded). `FxBuildHasher::hash_one` ignores any
/// seed, so the "distribution depends on seed" arm below would fail.
#[test]
fn session_key_seeded_hash_depends_on_seed_and_is_stable() {
    use std::hash::BuildHasher;

    // 256 attacker-constructible keys (one src subnet, sweeping src_port).
    let keys: Vec<SessionKey> = (0..256u16)
        .map(|i| make_v4_key((i & 0xff) as u8, 40000u16.wrapping_add(i)))
        .collect();

    // Low bits of the hash model the open-addressing bucket the map would
    // probe; equal vectors ⇒ identical bucket layout.
    let dist = |seed: usize| -> Vec<u64> {
        let state = FxSeededState::with_seed(seed);
        keys.iter().map(|k| state.hash_one(k) & 0x3ff).collect()
    };

    // Stability within one seed (cache/lookup consistency).
    let s = 0x0123_4567usize;
    assert_eq!(dist(s), dist(s), "seeded session hash must be stable per seed");

    // Seed-dependence: some seed produces a different bucket layout for the
    // SAME key set. With the unseeded FxBuildHasher this is impossible
    // (the seed is ignored) → fail-on-revert.
    let reference = dist(0xA5A5_5A5A);
    let mut diverged = false;
    for seed in 1usize..4096 {
        if dist(seed) != reference {
            diverged = true;
            break;
        }
    }
    assert!(
        diverged,
        "session-key bucket layout did not change across seeds — index hash \
         is seed-independent (unseeded FxHashMap regression, #2364)"
    );
}

/// The seeded session table must still behave correctly end-to-end:
/// insert under the per-boot seed, look the key back up, get a hit.
/// Guards against the seed silently breaking normal lookup.
#[test]
fn seeded_session_table_round_trips_lookup() {
    let mut table = SessionTable::new();
    let key = make_v4_key(7, 41000);
    let now = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, now);
    assert!(
        table.lookup(&key, now, 0x10).is_some(),
        "a key inserted into the seeded index must be found by the same key"
    );
    // A different key must miss — proves we are matching the key, not
    // succeeding for everything.
    let other = make_v4_key(8, 41001);
    assert!(
        table.lookup(&other, now, 0x10).is_none(),
        "a non-inserted key must miss under the seeded index"
    );
}

// ── #2501: per-session byte/packet accounting ───────────────────────────

/// A reverse SessionMetadata mirrors `metadata()` with `is_reverse: true`.
fn metadata_reverse() -> SessionMetadata {
    SessionMetadata {
        is_reverse: true,
        ..metadata()
    }
}

#[test]
fn account_packet_forward_increments_fwd_counters() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let now = 1_000_000_000u64;
    assert!(table.install_with_protocol(key.clone(), decision(), metadata(), now, PROTO_TCP, 0x10));

    table.account_packet(&key, 100);
    table.account_packet(&key, 250);

    let c = table.session_counters(&key).expect("forward entry exists");
    // FAIL-ON-REVERT: revert the hot-path increment and these go to 0.
    assert_eq!(c.fwd_packets, 2);
    assert_eq!(c.fwd_bytes, 350);
    assert_eq!(c.rev_packets, 0);
    assert_eq!(c.rev_bytes, 0);
}

#[test]
fn account_packet_reverse_folds_onto_forward_entry() {
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let fwd = key_v4();
    // No-NAT reverse wire key is the src/dst-swapped forward tuple — exactly
    // what `reverse_session_key(fwd, default_nat)` recovers.
    let rev = reverse_session_key(&fwd, NatDecision::default());

    // Install BOTH halves: forward (is_reverse=false) keyed by `fwd`, and the
    // reverse companion (is_reverse=true) keyed by `rev`. This mirrors the
    // poll_descriptor forward+reverse install pair.
    assert!(table.install_with_protocol(fwd.clone(), decision(), metadata(), now, PROTO_TCP, 0x10));
    assert!(table.install_with_protocol(
        rev.clone(),
        decision(),
        metadata_reverse(),
        now,
        PROTO_TCP,
        0x10,
    ));

    // A forward packet (keyed by the forward tuple) and a reverse packet
    // (keyed by the reply tuple).
    table.account_packet(&fwd, 1000);
    table.account_packet(&rev, 40);
    table.account_packet(&rev, 60);

    // Both directions must land on the canonical FORWARD entry so the
    // forward-only BPF mirror / close harvest sees the complete picture.
    let c = table.session_counters(&fwd).expect("forward entry exists");
    assert_eq!(c.fwd_packets, 1, "forward packet counted once");
    assert_eq!(c.fwd_bytes, 1000);
    // FAIL-ON-REVERT: drop the reverse→forward fold and rev_* stays 0 on the
    // forward entry (the reverse volume would be lost by the forward-only
    // conntrack mirror).
    assert_eq!(c.rev_packets, 2, "two reverse packets folded onto fwd entry");
    assert_eq!(c.rev_bytes, 100);
}

#[test]
fn account_packet_miss_is_noop() {
    let mut table = SessionTable::new();
    // No session installed — accounting an unknown key must not panic or
    // create state.
    table.account_packet(&key_v4(), 9999);
    assert!(table.session_counters(&key_v4()).is_none());
}

#[test]
fn close_delta_carries_harvested_counters() {
    let mut table = SessionTable::new();
    let then = 1_000_000_000u64;
    let key = key_v4();
    assert!(table.install_with_protocol(key.clone(), decision(), metadata(), then, PROTO_TCP, 0x10));
    // Drain the Open delta so the next drain only sees the Close.
    let _ = table.drain_deltas(8);

    table.account_packet(&key, 500);
    table.account_packet(&key, 700);

    // Force expiry.
    table.last_gc_ns = then + 301_000_000_000;
    let expired = table.expire_stale_entries(then + 302_000_000_000);
    assert_eq!(expired.len(), 1);

    let deltas = table.drain_deltas(8);
    let close = deltas
        .iter()
        .find(|d| d.kind == SessionDeltaKind::Close)
        .expect("a Close delta was produced");
    // FAIL-ON-REVERT: stop harvesting `removed.counters` onto the Close delta
    // and these revert to 0 — the SESSION_CLOSE RT_FLOW frame loses volume.
    assert_eq!(close.counters.fwd_packets, 2);
    assert_eq!(close.counters.fwd_bytes, 1200);
}
