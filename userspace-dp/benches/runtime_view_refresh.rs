// #6592 design gate: measure the two costs that decided how validation and
// forwarding get paired atomically.
//
// The daemon lives in a bin crate (`xpf-userspace-dp` is a binary target with
// `pub(crate)`-only items), so — like `prefix_set_lookup` and
// `tx_kick_latency` — this bench re-implements the bit-equivalent SHAPES
// rather than importing them. Correctness of the real types is covered by the
// in-tree tests (`snapshot_refresh_runtime_view_pair_is_atomic_6592`,
// `bump_fib_generation_publishes_new_stamps_without_rotating_forwarding`);
// this bench only gates the cost arguments.
//
// ── What is being decided ───────────────────────────────────────────────────
//
// A worker must never observe validation from one generation paired with
// forwarding from another. Two candidate designs:
//
//   (1) ONE ArcSwap holding both, with forwarding kept as a NESTED Arc.
//       Pairing is structural. A validation-only publish allocates one small
//       view and REUSES the inner forwarding Arc.
//   (2) Inline `ValidationState` INTO `ForwardingState` (one ArcSwap, one
//       allocation, no nesting). Structurally simplest — but every
//       validation-only publish must now rebuild the forwarding state.
//
// Design (2) is the one #1188 forbids, and this bench quantifies why:
// `Coordinator::bump_fib_generation` advances validation with no table change,
// and Go fires `Manager.BumpFIBGeneration` repeatedly during route convergence
// precisely to avoid a full `buildSnapshot()` + `apply_snapshot` rebuild.
//
// ── Gates ───────────────────────────────────────────────────────────────────
//
//   G1  Per-tick worker refresh: ONE view load must not be slower than the
//       two independent ArcSwap loads it replaces (it does strictly less
//       work, so this is a no-regression gate on the AF_XDP hot path).
//   G2  Validation-only publish: reusing the nested forwarding Arc must be at
//       least 10x cheaper than deep-cloning the forwarding state, at a
//       moderate config size. This is the #1188 preservation argument.
//
// ── What G1 does NOT prove ──────────────────────────────────────────────────
//
// Because the shapes are reimplemented here, G1 measures the SHAPE change —
// one ArcSwap load versus two — not the production `refresh_runtime_view`
// symbol. In particular it says nothing about whether the `between` test seam
// compiles away: this bench has no seam. That property is established
// separately, by checking the release binary itself — `refresh_runtime_view`
// absent from `nm` while `worker_loop` is present, no closure/`call_once` call
// anywhere in `worker_loop`'s disassembly, and identical `call` / `lock`-prefix
// counts with the seam call removed. Do not read a green G1 as covering it.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;

const TICK_ITERS: usize = 2_000_000;
const PUBLISH_ITERS: usize = 2_000;

/// Mirror of `afxdp::types::ValidationState`: `Copy`, three scalars.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ValidationState {
    snapshot_installed: bool,
    config_generation: u64,
    fib_generation: u32,
}

/// Cost-equivalent stand-in for `ForwardingState`. The real type carries 69
/// fields with ~20 heap-owning collections (the FIB among them); what matters
/// for `Clone` cost is the number and size of those collections, not their
/// element types. Sized from a moderate production config.
#[derive(Clone, Default)]
struct ForwardingShape {
    routes_v4: Vec<(Ipv4Addr, u8, i32)>,
    routes_v6: Vec<(Ipv6Addr, u8, i32)>,
    connected_v4: Vec<(Ipv4Addr, u8, i32)>,
    connected_v6: Vec<(Ipv6Addr, u8, i32)>,
    local_v4: Vec<Ipv4Addr>,
    local_v6: Vec<Ipv6Addr>,
    neighbors: BTreeMap<(i32, Ipv4Addr), [u8; 6]>,
    egress: BTreeMap<i32, [u8; 6]>,
    zones: BTreeMap<String, u16>,
    policies: Vec<(u16, u16, u32, String)>,
    address_books: BTreeMap<String, Vec<(Ipv4Addr, u8)>>,
    applications: BTreeMap<String, Vec<(u8, u16, u16)>>,
    source_nat: Vec<(u32, Ipv4Addr, Ipv4Addr, u16, u16)>,
    dest_nat: Vec<(u32, Ipv4Addr, u16, Ipv4Addr, u16)>,
    static_nat: Vec<(Ipv4Addr, Ipv4Addr)>,
    screen_profiles: BTreeMap<String, [u64; 8]>,
    filters: BTreeMap<String, Vec<(u32, u32, u8)>>,
    cos_queues: BTreeMap<(i32, u8), [u64; 4]>,
    fabrics: Vec<(i32, i32, [u8; 6])>,
    tunnels: BTreeMap<u16, (i32, Ipv4Addr, Ipv4Addr)>,
    validation: ValidationState,
}

fn build_forwarding(routes: usize) -> ForwardingShape {
    let mut fwd = ForwardingShape::default();
    for i in 0..routes {
        let octets = (i as u32).to_be_bytes();
        fwd.routes_v4
            .push((Ipv4Addr::from(octets), 24, (i % 8) as i32));
        if i % 5 == 0 {
            fwd.routes_v6.push((
                Ipv6Addr::new(0x2001, 0x559, 0x8585, i as u16, 0, 0, 0, 1),
                64,
                (i % 8) as i32,
            ));
        }
        if i % 50 == 0 {
            fwd.connected_v4
                .push((Ipv4Addr::from(octets), 24, (i % 8) as i32));
            fwd.local_v4.push(Ipv4Addr::from(octets));
            fwd.neighbors
                .insert(((i % 8) as i32, Ipv4Addr::from(octets)), [2, 0, 0, 0, 0, 1]);
        }
        if i % 100 == 0 {
            fwd.connected_v6.push((
                Ipv6Addr::new(0x2001, 0x559, 0x8585, i as u16, 0, 0, 0, 0),
                64,
                (i % 8) as i32,
            ));
            fwd.local_v6
                .push(Ipv6Addr::new(0x2001, 0x559, 0x8585, i as u16, 0, 0, 0, 1));
            fwd.policies.push((
                (i % 4) as u16,
                ((i + 1) % 4) as u16,
                i as u32,
                format!("policy-{i}"),
            ));
            fwd.address_books
                .insert(format!("book-{i}"), vec![(Ipv4Addr::from(octets), 24)]);
            fwd.applications
                .insert(format!("app-{i}"), vec![(6, 1024, 2048)]);
            fwd.source_nat.push((
                i as u32,
                Ipv4Addr::from(octets),
                Ipv4Addr::from(octets),
                1024,
                65535,
            ));
            fwd.dest_nat.push((
                i as u32,
                Ipv4Addr::from(octets),
                443,
                Ipv4Addr::from(octets),
                8443,
            ));
            fwd.static_nat
                .push((Ipv4Addr::from(octets), Ipv4Addr::from(octets)));
            fwd.filters
                .insert(format!("filter-{i}"), vec![(i as u32, 0xffff_ff00, 6)]);
        }
    }
    for ifindex in 0..8i32 {
        fwd.egress.insert(ifindex, [2, 0, 0, 0, 0, ifindex as u8]);
        fwd.zones.insert(format!("zone-{ifindex}"), ifindex as u16);
        fwd.fabrics.push((ifindex, ifindex + 8, [2, 0, 0, 0, 1, 0]));
        for queue in 0..8u8 {
            fwd.cos_queues.insert((ifindex, queue), [1_000_000; 4]);
        }
    }
    for id in 0..16u16 {
        fwd.screen_profiles.insert(format!("screen-{id}"), [0; 8]);
        fwd.tunnels.insert(
            id,
            (
                id as i32,
                Ipv4Addr::new(10, 0, 0, id as u8),
                Ipv4Addr::new(10, 0, 1, id as u8),
            ),
        );
    }
    fwd
}

/// #6592 shape: one ArcSwap, forwarding nested as an `Arc`.
#[derive(Clone)]
struct RuntimeView {
    validation: ValidationState,
    forwarding: Arc<ForwardingShape>,
}

/// Pre-#6592 worker refresh: TWO independent acquire-loads. This is the shape
/// that could tear the pair — a publish landing between the loads leaves the
/// worker holding halves from two generations, in one orientation or the
/// other depending on which is loaded first.
#[inline]
fn refresh_two_loads(
    cached: &Arc<ForwardingShape>,
    shared_forwarding: &ArcSwap<ForwardingShape>,
    shared_validation: &ArcSwap<ValidationState>,
) -> (Option<Arc<ForwardingShape>>, ValidationState) {
    let guard = shared_forwarding.load();
    let new_forwarding = if Arc::ptr_eq(cached, &guard) {
        None
    } else {
        Some(guard.clone())
    };
    let validation = **shared_validation.load();
    (new_forwarding, validation)
}

/// #6592 worker refresh: ONE acquire-load, both halves read out of it.
#[inline]
fn refresh_one_load(
    cached: &Arc<ForwardingShape>,
    shared_runtime: &ArcSwap<RuntimeView>,
) -> (Option<Arc<ForwardingShape>>, ValidationState) {
    let view = shared_runtime.load();
    let validation = view.validation;
    let new_forwarding = if Arc::ptr_eq(cached, &view.forwarding) {
        None
    } else {
        Some(view.forwarding.clone())
    };
    (new_forwarding, validation)
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

/// Steady-state per-tick refresh cost (no publish in flight — the ~always
/// case: 10K-100K ticks/s per worker against a config that changes rarely).
fn bench_tick(iters: usize) -> (f64, f64) {
    let forwarding = Arc::new(build_forwarding(1_000));
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 7,
        fib_generation: 3,
    };

    let shared_forwarding = ArcSwap::new(forwarding.clone());
    let shared_validation = ArcSwap::from_pointee(validation);
    let shared_runtime = ArcSwap::from_pointee(RuntimeView {
        validation,
        forwarding: forwarding.clone(),
    });

    // Warm both paths so neither pays first-touch page faults in its timing.
    for _ in 0..10_000 {
        black_box(refresh_two_loads(
            &forwarding,
            &shared_forwarding,
            &shared_validation,
        ));
        black_box(refresh_one_load(&forwarding, &shared_runtime));
    }

    let start = Instant::now();
    for _ in 0..iters {
        black_box(refresh_two_loads(
            black_box(&forwarding),
            black_box(&shared_forwarding),
            black_box(&shared_validation),
        ));
    }
    let two = start.elapsed().as_nanos() as f64 / iters as f64;

    let start = Instant::now();
    for _ in 0..iters {
        black_box(refresh_one_load(
            black_box(&forwarding),
            black_box(&shared_runtime),
        ));
    }
    let one = start.elapsed().as_nanos() as f64 / iters as f64;

    (two, one)
}

/// Validation-only publish (`bump_fib_generation`) under the two designs.
fn bench_validation_only_publish(routes: usize, iters: usize) -> (Vec<u64>, Vec<u64>) {
    let forwarding = Arc::new(build_forwarding(routes));
    let shared_runtime = ArcSwap::from_pointee(RuntimeView {
        validation: ValidationState::default(),
        forwarding: forwarding.clone(),
    });
    let shared_inlined = ArcSwap::new(forwarding.clone());

    let mut nested = Vec::with_capacity(iters);
    let mut inlined = Vec::with_capacity(iters);

    for i in 0..iters {
        let validation = ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: i as u32,
        };

        // Design (1): reuse the published forwarding Arc — one small alloc.
        let published = shared_runtime.load().forwarding.clone();
        let start = Instant::now();
        shared_runtime.store(Arc::new(RuntimeView {
            validation,
            forwarding: black_box(published),
        }));
        nested.push(start.elapsed().as_nanos() as u64);

        // Design (2): validation lives INSIDE the forwarding state, so the
        // whole state must be rebuilt to move a generation counter.
        let start = Instant::now();
        let mut next = (**shared_inlined.load()).clone();
        next.validation = validation;
        shared_inlined.store(Arc::new(black_box(next)));
        inlined.push(start.elapsed().as_nanos() as u64);
    }

    nested.sort_unstable();
    inlined.sort_unstable();
    (nested, inlined)
}

fn main() {
    println!("#6592 runtime-view pairing — design gate\n");

    // ── G1: per-tick worker refresh ────────────────────────────────────────
    let (two, one) = bench_tick(TICK_ITERS);
    println!("G1  per-tick refresh ({TICK_ITERS} iters, mean ns/tick)");
    println!("      two ArcSwap loads (pre-#6592):  {two:8.2} ns");
    println!("      one RuntimeView load (#6592):   {one:8.2} ns");
    println!("      delta:                          {:8.2} ns\n", one - two);

    // ── G2: validation-only publish ────────────────────────────────────────
    for routes in [1_000usize, 10_000] {
        let (nested, inlined) = bench_validation_only_publish(routes, PUBLISH_ITERS);
        let n_p50 = percentile(&nested, 0.50);
        let n_p95 = percentile(&nested, 0.95);
        let i_p50 = percentile(&inlined, 0.50);
        let i_p95 = percentile(&inlined, 0.95);
        println!("G2  validation-only publish, {routes} v4 routes ({PUBLISH_ITERS} iters)");
        println!("      nested Arc reuse (#6592):  p50 {n_p50:>9} ns  p95 {n_p95:>9} ns");
        println!("      inlined-validation rebuild: p50 {i_p50:>9} ns  p95 {i_p95:>9} ns");
        println!(
            "      ratio (rebuild / reuse):   p50 {:>9.1}x\n",
            i_p50 as f64 / n_p50.max(1) as f64
        );
    }

    // ── Gate evaluation ────────────────────────────────────────────────────
    let mut failures: Vec<String> = Vec::new();

    // G1: one load does strictly less work than two. Allow a 15% margin for
    // measurement noise on a shared box — the gate is "no regression", not a
    // claimed speedup.
    if one > two * 1.15 {
        failures.push(format!(
            "G1: one-load refresh ({one:.2} ns) is slower than two loads ({two:.2} ns) \
             by more than the 15% noise margin"
        ));
    }

    // G2: at 10K routes the rebuild must be at least 10x the Arc reuse. This
    // is the #1188 argument for keeping forwarding a NESTED Arc.
    let (nested, inlined) = bench_validation_only_publish(10_000, PUBLISH_ITERS);
    let ratio = percentile(&inlined, 0.50) as f64 / percentile(&nested, 0.50).max(1) as f64;
    if ratio < 10.0 {
        failures.push(format!(
            "G2: inlined-validation rebuild is only {ratio:.1}x the nested-Arc reuse \
             (expected >= 10x) — re-derive the #1188 argument before trusting it"
        ));
    }

    if failures.is_empty() {
        println!("PASS: G1 (no hot-path regression), G2 (>= 10x publish saving)");
    } else {
        for failure in &failures {
            println!("FAIL: {failure}");
        }
        std::process::exit(1);
    }
}
