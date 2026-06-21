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
