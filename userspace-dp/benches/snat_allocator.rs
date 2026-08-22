// #2852 merge-gate microbench: SNAT PortAllocator contention.
//
// The port allocator keeps its live allocation state behind ONE global
// mutex (`PortAllocatorShared.live: Mutex<PortAllocatorLiveState>`,
// src/nat/allocator.rs:166). Every new-flow `allocate_translation`
// (allocator.rs:312) locks it synchronously to: GC-sweep, reuse-lookup
// `live_by_flow`, cap-check, claim a free port via the forward-probe
// cursor `next_port_offset_by_addr` + `owner_by_translated` +
// `addr_index_by_translated` + the #3011 FIFO `recycled_ports_by_addr`
// queue, and insert `live_by_flow`. #3011 (FIFO recycle) and #4388
// (`reserve_flow`, HA-synced port reservation) piled MORE state under
// the same lock. At high new-flow rates every worker on every core
// serializes on this one mutex.
//
// The #2852 converged v3 plan (Claude-SMR + Codex + AGY, F5 deadlock
// resolved) proposes a phased fix whose Phase 1 (the dominant, lowest-
// churn win) makes the PORT CLAIM lock-free — a per-pool-address atomic
// occupancy bitmap (`Vec<AtomicU64>` + atomic cursor, CAS-claim), the
// bit IS the ownership token — and keeps only a TINY mutex around the
// `live_by_flow` map insert/remove. The global tracked-flow cap becomes
// one `AtomicUsize` (fetch_add-reserve / fetch_sub-rollback, plan F4).
//
// This bench answers the #2852 PLAN-KILL question "is the global mutex
// a measurable bottleneck at the loss cluster's 6-worker scale?" — a
// question a HUMAN answers by reading its table. It was described as a
// "REQUIRED merge gate", which it is not: see the #5190 banner below.
// It re-implements BOTH shapes side by
// side (the production allocator is `pub(crate)` in a bin crate, so we
// re-implement the hot-path shapes here — same pattern as
// benches/session_table.rs / benches/tx_kick_latency.rs) and driving
// them under M = {1,2,4,6,8} threads across the four AGY-5 stress
// profiles: (a) uniform low occupancy, (b) 85-98% occupancy, (c) 80/20
// source skew, (d) a narrow 64-port range.
//
// ---------------------------------------------------------------------------
// #5190 (A1-b12-F3) VERDICT STATUS: THIS BENCH IS EXPLORATORY — IT DOES NOT
// GATE. It measures and PRINTS its table; it compares nothing against a
// threshold and never exits non-zero. A severe regression here still exits 0,
// so a wrapper that reads only the exit status learns NOTHING from running it.
// Read the printed table.
//
// The benches in this crate that DO gate are `prefix_set_lookup.rs` and
// `runtime_view_refresh.rs`: both compare a measured percentile against a
// named threshold and call `std::process::exit(1)` on breach. Copy that shape
// if this target is ever promoted to a real gate.
//
// Nothing in CI or the Makefile runs `cargo bench` — `make test-rust` builds
// `--bins --tests` and deliberately EXCLUDES benches — so no automated gate is
// currently reporting a false green from this file. The hazard this banner
// closes is a human running it on the strength of the wording above and
// reading exit 0 as a pass.
// ---------------------------------------------------------------------------

// It is `harness = false` with its own `fn main()` (not criterion):
// criterion times a single-threaded closure and cannot express M-thread
// contention or cross-thread p99/p999 tail latency, which is the whole
// point of a lock-contention gate. Output is a fixed table
// (allocs/sec + p50/p99/p999 allocate latency, current vs proposed,
// speedup) that is recorded in docs/research/2852-portalloc/.
//
// Modeling notes (kept deliberately faithful so the contrast is the
// lock scope, not incidental work):
//   * Both shapes select the pool address identically and lock-free
//     (sticky `hash(src_ip) % num_addrs`, i.e. address-persistent
//     selection — `sticky_pool_index` is already lock-free on master
//     and untouched by the plan), so the ONLY measured difference is
//     the port-claim + map-lock mechanism.
//   * Both shapes model pure NEW-flow churn (unique 5-tuples). In
//     production established flows hit the session table, not the
//     allocator; `allocate_translation` is called once per new flow.
//     The bench keeps a steady occupancy by releasing the oldest
//     outstanding flow on each successful allocate.
//   * The CURRENT shape holds its ONE mutex across the whole
//     reuse-get + cursor-probe + owner-insert + map-insert critical
//     section (mirrors allocator.rs). The PROPOSED shape does the
//     bitmap claim lock-free and holds a mutex only for the single
//     `live_by_flow` map insert (and remove on release) — that
//     narrowing IS the refactor under test.
//   * Persistent NAT (the two-lock path) is NOT modeled: it is the
//     colder path and Phase 1 has no map sharding. This bench targets
//     the dominant non-persistent hot path the issue calls out.

use rustc_hash::FxHashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Instant;

// ── shared 5-tuple flow key (mirrors SourceNatFlowKey, IPv4) ───────
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Translated {
    ip: u32,
    port: u16,
}

// Small fast mixer for sticky address selection + source generation.
#[inline]
fn mix32(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x7feb_352d);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846c_a68b);
    x ^= x >> 16;
    x
}

// Address selection: sticky, lock-free, identical for both shapes.
#[inline]
fn addr_for(src_ip: u32, num_addrs: usize) -> usize {
    (mix32(src_ip) as usize) % num_addrs
}

// ────────────────────────────────────────────────────────────────
// CURRENT shape: one global Mutex over all live allocation state.
// ────────────────────────────────────────────────────────────────
struct CurrentLive {
    live_by_flow: FxHashMap<FlowKey, Translated>,
    owner_by_translated: FxHashMap<Translated, ()>,
    addr_index_by_translated: FxHashMap<Translated, usize>,
    next_port_offset_by_addr: Vec<u32>,
    recycled_ports_by_addr: Vec<VecDeque<u16>>,
}

struct CurrentAllocator {
    live: Mutex<CurrentLive>,
    port_low: u16,
    port_high: u16,
    num_addrs: usize,
    max_tracked: usize,
    allocations_total: AtomicU64,
}

impl CurrentAllocator {
    fn new(num_addrs: usize, port_low: u16, port_high: u16, max_tracked: usize) -> Self {
        Self {
            live: Mutex::new(CurrentLive {
                live_by_flow: FxHashMap::default(),
                owner_by_translated: FxHashMap::default(),
                addr_index_by_translated: FxHashMap::default(),
                next_port_offset_by_addr: vec![0; num_addrs],
                recycled_ports_by_addr: vec![VecDeque::new(); num_addrs],
            }),
            port_low,
            port_high,
            num_addrs,
            max_tracked,
            allocations_total: AtomicU64::new(0),
        }
    }

    // Mirrors claim_free_port_locked: forward-probe the monotonic cursor,
    // then drain the FIFO recycle queue; `owner_by_translated` is the
    // collision arbiter.
    fn claim_free_port(&self, live: &mut CurrentLive, addr: usize, ip: u32) -> Option<Translated> {
        let range = (self.port_high as u32) - (self.port_low as u32) + 1;
        loop {
            let next = live.next_port_offset_by_addr[addr];
            if next >= range {
                break;
            }
            live.next_port_offset_by_addr[addr] = next + 1;
            let t = Translated {
                ip,
                port: self.port_low + next as u16,
            };
            if !live.owner_by_translated.contains_key(&t) {
                live.owner_by_translated.insert(t, ());
                live.addr_index_by_translated.insert(t, addr);
                return Some(t);
            }
        }
        // FIFO recycle drain (retain on collision, #3011/#3047).
        let mut retained: Vec<u16> = Vec::new();
        let mut claimed = None;
        while let Some(port) = live.recycled_ports_by_addr[addr].pop_front() {
            let t = Translated { ip, port };
            if !live.owner_by_translated.contains_key(&t) {
                live.owner_by_translated.insert(t, ());
                live.addr_index_by_translated.insert(t, addr);
                claimed = Some(t);
                break;
            }
            retained.push(port);
        }
        if !retained.is_empty() {
            live.recycled_ports_by_addr[addr].extend(retained);
        }
        claimed
    }

    fn allocate(&self, flow: FlowKey) -> Option<Translated> {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = live.live_by_flow.get(&flow) {
            return Some(*t); // reuse (never hit in the new-flow bench)
        }
        if live.live_by_flow.len() >= self.max_tracked {
            return None;
        }
        let addr = addr_for(flow.src_ip, self.num_addrs);
        let ip = addr as u32;
        let t = self.claim_free_port(&mut live, addr, ip)?;
        live.live_by_flow.insert(flow, t);
        self.allocations_total.fetch_add(1, Ordering::Relaxed);
        Some(t)
    }

    fn release(&self, flow: FlowKey) {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        let Some(t) = live.live_by_flow.remove(&flow) else {
            return;
        };
        live.owner_by_translated.remove(&t);
        if let Some(addr) = live.addr_index_by_translated.remove(&t) {
            live.recycled_ports_by_addr[addr].push_back(t.port); // FIFO: push back
        }
    }
}

// ────────────────────────────────────────────────────────────────
// PROPOSED Phase-1 shape: per-address atomic occupancy bitmap (lock-
// free CAS claim, the bit IS the ownership token) + a tiny mutex over
// just the flow map + a global atomic tracked-flow cap.
// ────────────────────────────────────────────────────────────────
struct AddressBitmap {
    words: Vec<AtomicU64>, // bit set => occupied
    cursor: AtomicU32,     // forward-probe start hint
    range: u32,            // port_high - port_low + 1
}

impl AddressBitmap {
    fn new(range: u32) -> Self {
        let nwords = ((range as usize) + 63) / 64;
        let mut words = Vec::with_capacity(nwords);
        for _ in 0..nwords {
            words.push(AtomicU64::new(0));
        }
        Self {
            words,
            cursor: AtomicU32::new(0),
            range,
        }
    }

    // Valid-bit mask for a word (last word may be partial when the port
    // range is not a multiple of 64).
    #[inline]
    fn valid_mask(&self, w: usize) -> u64 {
        let base = w * 64;
        if base + 64 <= self.range as usize {
            u64::MAX
        } else {
            let rem = self.range as usize - base; // 1..=63
            (1u64 << rem) - 1
        }
    }

    // CAS-claim: word-scan from the advancing cursor's start word. For each
    // word, `trailing_zeros(!word & valid)` finds a free bit in O(1); a
    // CAS (fetch_or) is the sole PAT arbiter — if the bit was already set a
    // concurrent claimer won it, so retry the same word (other free bits
    // may remain) until it is full, then advance to the next word. This is
    // the standard competent lock-free occupancy bitmap: at any occupancy
    // below 100% the first non-full word yields a bit in O(1), so a
    // near-full pool does NOT devolve to an O(range) linear probe.
    #[inline]
    fn claim(&self) -> Option<u32> {
        let nwords = self.words.len();
        let start_word = (self.cursor.fetch_add(1, Ordering::Relaxed) as usize) % nwords;
        for wi in 0..nwords {
            let w = (start_word + wi) % nwords;
            let valid = self.valid_mask(w);
            loop {
                let cur = self.words[w].load(Ordering::Relaxed);
                let free = !cur & valid;
                if free == 0 {
                    break; // word full — next word
                }
                let bit = free.trailing_zeros();
                let mask = 1u64 << bit;
                if self.words[w].fetch_or(mask, Ordering::AcqRel) & mask == 0 {
                    return Some((w as u32) * 64 + bit);
                }
                // Lost the race for this bit; free bits may remain — retry.
            }
        }
        None
    }

    #[inline]
    fn free(&self, off: u32) {
        let w = (off / 64) as usize;
        let mask = 1u64 << (off % 64);
        self.words[w].fetch_and(!mask, Ordering::Release);
    }
}

struct ProposedAllocator {
    bitmaps: Vec<AddressBitmap>,
    map: Mutex<FxHashMap<FlowKey, (usize, u32)>>, // flow -> (addr, offset)
    live_count: AtomicUsize,                      // global cap, F4
    max_tracked: usize,
    port_low: u16,
    num_addrs: usize,
    allocations_total: AtomicU64,
}

impl ProposedAllocator {
    fn new(num_addrs: usize, port_low: u16, port_high: u16, max_tracked: usize) -> Self {
        let range = (port_high as u32) - (port_low as u32) + 1;
        let mut bitmaps = Vec::with_capacity(num_addrs);
        for _ in 0..num_addrs {
            bitmaps.push(AddressBitmap::new(range));
        }
        Self {
            bitmaps,
            map: Mutex::new(FxHashMap::default()),
            live_count: AtomicUsize::new(0),
            max_tracked,
            port_low,
            num_addrs,
            allocations_total: AtomicU64::new(0),
        }
    }

    fn allocate(&self, flow: FlowKey) -> Option<Translated> {
        // Global cap: reserve, roll back on any failure (plan F4).
        if self.live_count.fetch_add(1, Ordering::Relaxed) >= self.max_tracked {
            self.live_count.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        let addr = addr_for(flow.src_ip, self.num_addrs);
        let Some(off) = self.bitmaps[addr].claim() else {
            self.live_count.fetch_sub(1, Ordering::Relaxed);
            return None;
        };
        // TINY critical section: just the map insert.
        {
            let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
            map.insert(flow, (addr, off));
        }
        self.allocations_total.fetch_add(1, Ordering::Relaxed);
        Some(Translated {
            ip: addr as u32,
            port: self.port_low + off as u16,
        })
    }

    fn release(&self, flow: FlowKey) {
        let entry = {
            let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
            map.remove(&flow)
        };
        if let Some((addr, off)) = entry {
            self.bitmaps[addr].free(off); // lock-free
            self.live_count.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

// ── shared allocator interface so the driver is shape-agnostic ─────
trait Alloc: Send + Sync {
    fn allocate(&self, flow: FlowKey) -> Option<Translated>;
    fn release(&self, flow: FlowKey);
}
impl Alloc for CurrentAllocator {
    fn allocate(&self, f: FlowKey) -> Option<Translated> {
        CurrentAllocator::allocate(self, f)
    }
    fn release(&self, f: FlowKey) {
        CurrentAllocator::release(self, f)
    }
}
impl Alloc for ProposedAllocator {
    fn allocate(&self, f: FlowKey) -> Option<Translated> {
        ProposedAllocator::allocate(self, f)
    }
    fn release(&self, f: FlowKey) {
        ProposedAllocator::release(self, f)
    }
}

// ── workload profiles (AGY-5) ──────────────────────────────────────
#[derive(Clone, Copy)]
struct Profile {
    name: &'static str,
    num_addrs: usize,
    port_low: u16,
    port_high: u16,
    occupancy_num: u64, // occupancy = occupancy_num / occupancy_den
    occupancy_den: u64,
    num_sources: u32, // source-IP space size
    skew: bool,       // 80% of traffic from 10% of sources
    ops_per_thread: usize,
}

impl Profile {
    fn capacity(&self) -> usize {
        self.num_addrs * ((self.port_high as usize) - (self.port_low as usize) + 1)
    }
    fn target_live(&self) -> usize {
        ((self.capacity() as u64) * self.occupancy_num / self.occupancy_den) as usize
    }
    fn max_tracked(&self) -> usize {
        // Global tracked-flow cap set at full pool capacity so the port
        // range (not the cap) is the exhaustion arbiter in these runs.
        self.capacity()
    }
}

fn profiles() -> Vec<Profile> {
    vec![
        // (a) uniform low occupancy — wide pool, 10% full, uniform sources.
        Profile {
            name: "uniform-low-10pct",
            num_addrs: 16,
            port_low: 1024,
            port_high: 5119, // 4096 ports/addr
            occupancy_num: 10,
            occupancy_den: 100,
            num_sources: 8192,
            skew: false,
            ops_per_thread: 300_000,
        },
        // (b) 85-98% occupancy — same wide pool, 92% full, uniform sources.
        Profile {
            name: "high-occ-92pct",
            num_addrs: 16,
            port_low: 1024,
            port_high: 5119,
            occupancy_num: 92,
            occupancy_den: 100,
            num_sources: 8192,
            skew: false,
            ops_per_thread: 300_000,
        },
        // (c) 80/20 source skew — 80% of flows from 10% of sources; with
        // sticky addressing that concentrates load onto ~10% of the
        // bitmaps (per-address CAS contention stress). Mid occupancy.
        Profile {
            name: "skew-80-20",
            num_addrs: 16,
            port_low: 1024,
            port_high: 5119,
            occupancy_num: 50,
            occupancy_den: 100,
            num_sources: 8192,
            skew: true,
            ops_per_thread: 300_000,
        },
        // (d) narrow 64-port range — single address, one AtomicU64 word.
        // Worst-case single-cache-line CAS contention (all threads hammer
        // one atomic) + tests that a narrow pool is fully usable (AGY-2).
        // 75% occupancy leaves 16 free slots so M in-flight reservations
        // (F4 reserve-before-release overshoots the live count by up to M)
        // do NOT spuriously exhaust the cap — this profile measures the
        // claim mechanism on a tiny pool, not cap thrash (which the 64-port
        // pool would hit near capacity; see the results doc's caveat).
        Profile {
            name: "narrow-64port",
            num_addrs: 1,
            port_low: 20000,
            port_high: 20063, // 64 ports
            occupancy_num: 75,
            occupancy_den: 100,
            num_sources: 4096,
            skew: true,
            ops_per_thread: 150_000,
        },
    ]
}

// Deterministic xorshift RNG (per thread) for source selection.
struct XorShift(u64);
impl XorShift {
    #[inline]
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

// Pick a source id following the profile distribution.
#[inline]
fn pick_source(rng: &mut XorShift, p: &Profile) -> u32 {
    if p.skew {
        let hot = (p.num_sources / 10).max(1);
        if rng.next() % 100 < 80 {
            (rng.next() as u32) % hot // 80% from the hot 10%
        } else {
            hot + (rng.next() as u32) % (p.num_sources - hot)
        }
    } else {
        (rng.next() as u32) % p.num_sources
    }
}

// dst_ip is a UNIQUENESS TAG, not an address and not an accumulator. Its top
// byte identifies who produced the flow and its low 24 bits count within that
// producer, so the full 5-tuple never collides across threads or between the
// prepop pass and the churn loop. That matters because the proposed shape skips
// the reuse-get (in production the session table dedups a repeated 5-tuple
// before allocate is ever called), so a duplicate key would leak a bitmap bit
// plus a live-count slot — a pure bench artifact that must not exist.
//
// #6610: the tag used to be computed as `0xc000_0000 + ((owner as u32) << 24)`,
// with owner 255 for the prepop pass. `0xc0` already occupies the top byte, so
// that addition overflows u32 for any owner >= 64 and panicked on the FIRST
// prepop flow under debug assertions — which is why `cargo test --all-targets`
// blew up while `make test-rust` (release, `--bins --tests`) never noticed.
//
// The release behaviour was NOT wrong, and the fix preserves it exactly. The
// low-24 term cannot carry (every realized `n` is < 2^24), so the wrap was a
// pure mod-256 fold of the top byte: prepop landed on 0xbf and the worker
// threads on 0xc0..0xc7, which are all distinct — the one invariant this
// function has. Every published allocs/sec, percentile and fail-fraction from
// this bench therefore stands; nothing needs re-measuring.
//
// Two fixes that look right and are NOT:
//   - `saturating_add` collapses `0xc0 + 0xff` to u32::MAX for EVERY prepop
//     `n`, destroying the low-24 discriminator and creating the exact duplicate
//     keys the comment above warns about.
//   - a wider accumulator changes the tag values, so the run is no longer
//     byte-comparable with the published numbers.
//
// So the tag is now built the way it was always meant to be read: two DISJOINT
// bit fields OR'd together, with the producer byte named rather than computed.
const WORKER_TAG_BASE: u8 = 0xc0;
const PREPOP_TAG: u8 = 0xbf;

// The producer byte must stay injective over the realized domain, and that is
// the whole correctness argument for this file. A const assert costs nothing and
// runs on every `cargo build`/`cargo check` of the bench — unlike a #[test],
// which the Rust gate never compiles for a bench target. This is what makes the
// `cargo check --benches` leg of `make test-rust` able to catch a reintroduction
// of #6610 rather than merely catching compile rot.
const MAX_BENCH_THREADS: u8 = 8; // main()'s `threads` array tops out at 8
const _: () = assert!(
    WORKER_TAG_BASE.checked_add(MAX_BENCH_THREADS).is_some(),
    "worker tag would overflow u8"
);
const _: () = assert!(
    PREPOP_TAG < WORKER_TAG_BASE,
    "prepop tag must sit below every worker tag so no thread id can collide with it"
);

// Build a GLOBALLY-UNIQUE flow. `src_id` (repeats, drives sticky addressing +
// skew) sets src_ip; `tag` is the producer byte (PREPOP_TAG, or
// WORKER_TAG_BASE + thread id) and `n` counts within that producer.
#[inline]
fn make_flow(src_id: u32, tag: u8, n: u32) -> FlowKey {
    FlowKey {
        src_ip: 0x0a00_0000 + src_id, // 10.x.x.x (drives addressing)
        // Disjoint fields: OR, not +, so no carry between them is even possible.
        dst_ip: ((tag as u32) << 24) | (n & 0x00ff_ffff),
        src_port: 1024 + (n as u16 & 0x3fff),
        dst_port: 80 + ((n >> 14) as u16 & 0x1ff),
        protocol: 6,
    }
}

// Percentile from a sorted latency slice (nanoseconds).
fn pct(sorted: &[u32], q: f64) -> u32 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

struct RunResult {
    allocs_per_sec: f64,
    p50: u32,
    p99: u32,
    p999: u32,
    fail_frac: f64,
}

fn run_config(build: &dyn Fn() -> Arc<dyn Alloc>, p: &Profile, m: usize) -> RunResult {
    let alloc = build();

    // Pre-populate to target occupancy, single-threaded, and hand each
    // worker its own outstanding-flow FIFO so churn keeps occupancy
    // steady. Sources follow the same distribution so per-address
    // occupancy matches the churn distribution.
    let target = p.target_live();
    let mut prepop_rng = XorShift(0x1234_5678_9abc_def0);
    let mut outstanding: Vec<VecDeque<FlowKey>> = vec![VecDeque::new(); m];
    let mut t = 0usize;
    let mut installed = 0usize;
    // Round-robin the pre-populated flows across threads' queues. Prepop
    // flows use the reserved producer byte (PREPOP_TAG) + a monotonic `n`
    // so they never collide with any thread's churn flows.
    let mut prepop_n: u32 = 0;
    let mut attempts = 0usize;
    while installed < target && attempts < target * 4 {
        attempts += 1;
        let src = pick_source(&mut prepop_rng, p);
        let flow = make_flow(src, PREPOP_TAG, prepop_n);
        prepop_n += 1;
        if alloc.allocate(flow).is_some() {
            outstanding[t].push_back(flow);
            t = (t + 1) % m;
            installed += 1;
        }
    }

    let barrier = Arc::new(Barrier::new(m));
    let mut handles = Vec::with_capacity(m);
    for tid in 0..m {
        let alloc = alloc.clone();
        let barrier = barrier.clone();
        let profile = *p;
        let mut queue = std::mem::take(&mut outstanding[tid]);
        let ops = profile.ops_per_thread;
        handles.push(thread::spawn(move || {
            let mut rng = XorShift(0xdead_beef_0000_0001u64.wrapping_add((tid as u64) << 32));
            let mut lat: Vec<u32> = Vec::with_capacity(ops);
            let mut fails: u64 = 0;
            // Per-thread churn key space: owner byte = tid, n = op index,
            // so the 5-tuple is globally unique (see make_flow).
            let tag = WORKER_TAG_BASE + tid as u8;
            barrier.wait();
            let start = Instant::now();
            for n in 0..ops {
                let src = pick_source(&mut rng, &profile);
                let flow = make_flow(src, tag, n as u32);
                let t0 = Instant::now();
                let got = alloc.allocate(flow);
                // #6610: clamp rather than truncate. `as u32` on a u128
                // wraps, so a single allocate() over 4.295s would be recorded
                // as a near-ZERO latency and would pull the percentiles DOWN --
                // the same silent-wrong-number class as the tag overflow above,
                // in the one place a latency figure could go wrong. Observed
                // worst p999 is ~186us, so this is unreachable today; it costs
                // one min() to keep it unreachable by construction.
                let dt = t0.elapsed().as_nanos().min(u32::MAX as u128) as u32;
                lat.push(dt);
                match got {
                    Some(_) => {
                        queue.push_back(flow);
                        if let Some(old) = queue.pop_front() {
                            alloc.release(old); // keep occupancy steady
                        }
                    }
                    None => fails += 1,
                }
            }
            let elapsed = start.elapsed();
            (elapsed.as_secs_f64(), lat, ops as u64, fails)
        }));
    }

    let mut all_lat: Vec<u32> = Vec::new();
    let mut max_elapsed = 0f64;
    let mut total_ops = 0u64;
    let mut total_fail = 0u64;
    for h in handles {
        let (elapsed, lat, ops, fails) = h.join().unwrap();
        max_elapsed = max_elapsed.max(elapsed);
        total_ops += ops;
        total_fail += fails;
        all_lat.extend_from_slice(&lat);
    }
    all_lat.sort_unstable();
    let succeeded = total_ops - total_fail;
    RunResult {
        allocs_per_sec: if max_elapsed > 0.0 {
            succeeded as f64 / max_elapsed
        } else {
            0.0
        },
        p50: pct(&all_lat, 0.50),
        p99: pct(&all_lat, 0.99),
        p999: pct(&all_lat, 0.999),
        fail_frac: total_fail as f64 / total_ops as f64,
    }
}

fn main() {
    let threads = [1usize, 2, 4, 6, 8];
    let profiles = profiles();

    println!("# #2852 SNAT PortAllocator contention microbench");
    println!(
        "# allocs/sec = successful allocate()/sec across M threads; latency ns (allocate only)"
    );
    println!("# CUR = current single global Mutex; NEW = Phase-1 lock-free bitmap + tiny map lock");
    println!();

    for p in &profiles {
        println!(
            "## profile: {}  (addrs={}, ports={}..={} => {} range, cap={}, target_occ={:.0}%, sources={}, skew={}, ops/thread={})",
            p.name,
            p.num_addrs,
            p.port_low,
            p.port_high,
            (p.port_high as u32) - (p.port_low as u32) + 1,
            p.capacity(),
            (p.occupancy_num as f64 / p.occupancy_den as f64) * 100.0,
            p.num_sources,
            p.skew,
            p.ops_per_thread,
        );
        println!(
            "{:>2}  {:>13} {:>13} {:>7}  | {:>7} {:>7} {:>8} (CUR ns)  | {:>7} {:>7} {:>8} (NEW ns) | fail% C/N",
            "M", "CUR a/s", "NEW a/s", "speedup", "p50", "p99", "p999", "p50", "p99", "p999"
        );
        for &m in &threads {
            let pc = *p;
            let cur = run_config(
                &move || -> Arc<dyn Alloc> {
                    Arc::new(CurrentAllocator::new(
                        pc.num_addrs,
                        pc.port_low,
                        pc.port_high,
                        pc.max_tracked(),
                    ))
                },
                p,
                m,
            );
            let pc2 = *p;
            let new = run_config(
                &move || -> Arc<dyn Alloc> {
                    Arc::new(ProposedAllocator::new(
                        pc2.num_addrs,
                        pc2.port_low,
                        pc2.port_high,
                        pc2.max_tracked(),
                    ))
                },
                p,
                m,
            );
            let speedup = if cur.allocs_per_sec > 0.0 {
                new.allocs_per_sec / cur.allocs_per_sec
            } else {
                0.0
            };
            println!(
                "{:>2}  {:>13.0} {:>13.0} {:>6.2}x  | {:>7} {:>7} {:>8}            | {:>7} {:>7} {:>8}           | {:.1}/{:.1}",
                m,
                cur.allocs_per_sec,
                new.allocs_per_sec,
                speedup,
                cur.p50,
                cur.p99,
                cur.p999,
                new.p50,
                new.p99,
                new.p999,
                cur.fail_frac * 100.0,
                new.fail_frac * 100.0,
            );
        }
        println!();
    }
}
