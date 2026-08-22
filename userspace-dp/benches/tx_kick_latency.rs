// #825 plan §3.10 / §7 microbench. Measures the per-call overhead of
// the TX kick-latency instrumentation at the hot-path shape added in
// `maybe_wake_tx`:
//
//   kick_start = monotonic_nanos();
//   // sendto() runs here in production — elided in the bench, we're
//   // only measuring the instrumentation wrapper.
//   kick_end = monotonic_nanos();
//   if kick_end >= kick_start {
//       let delta_ns = kick_end - kick_start;
//       record_kick_latency(owner, delta_ns);   // 3 × fetch_add(Relaxed)
//   }
//
// The daemon code lives in a bin crate (`xpf-userspace-dp` is a
// binary target with `pub(super)` / `pub(crate)` items), so this
// bench recreates the bit-equivalent hot-path shape directly —
// `clock_gettime(CLOCK_MONOTONIC)` via libc, plus a 16-bucket
// [AtomicU64; 16] histogram with `bucket_index_for_ns` reproduced
// verbatim from `umem.rs:198-202`. Any divergence between this
// harness and the in-tree helper is caught by the unit tests in
// `umem.rs::tx_kick_latency_*` which exercise the real production
// functions.
//
// Target (READ BY A HUMAN, not enforced — see the #5190 banner
// below): p99 per-call overhead ≤ 60 ns on the userspace cluster VM
// (VDSO-confirmed monotonic_nanos path). Plan §3.10 R1 correction
// — the earlier 25 ns figure only covered the atomic fast-path; 45 ns
// derivation + 15 ns jitter headroom ≈ 60 ns. Criterion prints the
// distribution; nothing in this file compares it to 60 ns.
//
// ---------------------------------------------------------------------------
// #5190 (A1-b12-F3) VERDICT STATUS: THIS BENCH IS EXPLORATORY — IT DOES NOT
// GATE. It measures and PRINTS; it compares nothing against a threshold and
// never exits non-zero. A severe regression here still exits 0, so a wrapper
// that reads only the exit status learns NOTHING from running it. Read the
// printed numbers.
//
// The benches in this crate that DO gate are `prefix_set_lookup.rs` and
// `runtime_view_refresh.rs`: both compare a measured percentile against a
// named threshold and call `std::process::exit(1)` on breach. Copy that shape
// if this target is ever promoted to a real gate.
//
// Nothing in CI or the Makefile runs `cargo bench` — `make test-rust` builds
// `--bins --tests` and deliberately EXCLUDES benches — so no automated gate is
// currently reporting a false green from this file. The hazard this banner
// closes is a human running it on the strength of the wording below and
// reading exit 0 as a pass.
// ---------------------------------------------------------------------------

use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{Criterion, criterion_group, criterion_main};

const TX_SUBMIT_LAT_BUCKETS: usize = 16;

// Verbatim copy of `umem.rs::bucket_index_for_ns` (plan §3.10:
// "measure `record_kick_latency + two monotonic_nanos()` vs
// baseline"). The unit tests in `umem.rs::tx_kick_latency_*`
// pin bit-equivalence between this and the production helper.
#[inline]
fn bucket_index_for_ns(ns: u64) -> usize {
    let clz = (ns | 1).leading_zeros() as i32;
    let b = (54 - clz).max(0) as usize;
    b.min(TX_SUBMIT_LAT_BUCKETS - 1)
}

// Mirror `OwnerProfileOwnerWrites` kick-latency fields only. The
// real struct is cacheline-aligned (`#[repr(align(64))]`); we match
// the alignment here so contention characteristics match production.
#[repr(align(64))]
struct KickLatencyOwner {
    hist: [AtomicU64; TX_SUBMIT_LAT_BUCKETS],
    count: AtomicU64,
    sum_ns: AtomicU64,
}

impl KickLatencyOwner {
    fn new() -> Self {
        Self {
            hist: std::array::from_fn(|_| AtomicU64::new(0)),
            count: AtomicU64::new(0),
            sum_ns: AtomicU64::new(0),
        }
    }
}

#[inline]
fn record_kick_latency(owner: &KickLatencyOwner, delta_ns: u64) {
    let bucket = bucket_index_for_ns(delta_ns);
    owner.hist[bucket].fetch_add(1, Ordering::Relaxed);
    owner.count.fetch_add(1, Ordering::Relaxed);
    owner.sum_ns.fetch_add(delta_ns, Ordering::Relaxed);
}

// VDSO-backed `clock_gettime(CLOCK_MONOTONIC)`. Same path the
// daemon's `neighbor::monotonic_nanos` uses at
// `userspace-dp/src/afxdp/neighbor.rs:3-15`.
#[inline]
fn monotonic_nanos() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is stack-allocated and writable; `clock_gettime`
    // writes into it and returns 0 on success. Failure returns -1
    // and we fall through to produce 0 — matching the daemon's
    // sentinel behavior.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

fn bench_record_kick_latency(c: &mut Criterion) {
    let owner = KickLatencyOwner::new();

    // Baseline: just two monotonic_nanos calls bracketing a no-op.
    // Subtracting this from the instrumented version isolates the
    // helper's overhead from the VDSO cost.
    c.bench_function("tx_kick_latency_baseline_monotonic_nanos_x2", |b| {
        b.iter(|| {
            let s = monotonic_nanos();
            let e = monotonic_nanos();
            black_box((s, e));
        });
    });

    // Full hot-path shape: two monotonic_nanos + sentinel check +
    // record_kick_latency. This is the structure `maybe_wake_tx`
    // runs after the #825 edit.
    c.bench_function("tx_kick_latency_full_instrumentation", |b| {
        b.iter(|| {
            let kick_start = monotonic_nanos();
            // Cheap blackbox'd no-op stands in for `sendto` — we're
            // measuring instrumentation overhead, not the syscall.
            black_box(());
            let kick_end = monotonic_nanos();
            if kick_end >= kick_start {
                let delta_ns = kick_end - kick_start;
                record_kick_latency(black_box(&owner), delta_ns);
            }
        });
    });

    // Pure record_kick_latency (no VDSO) — pins the atomic fast
    // path cost in isolation.
    c.bench_function("tx_kick_latency_record_only_fixed_delta", |b| {
        b.iter(|| {
            record_kick_latency(black_box(&owner), black_box(5_000));
        });
    });
}

criterion_group!(benches, bench_record_kick_latency);
criterion_main!(benches);
