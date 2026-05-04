// Tests for the session module (#1047). Originally inline in session.rs,
// relocated as session_tests.rs in P1 (PR #1051), then renamed to
// session/tests.rs alongside the structural split that introduced the
// session/ directory module and session/key.rs.
// Loaded as a sibling submodule via `#[path = "tests.rs"]` from session/mod.rs.

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
