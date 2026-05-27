# #1607 Cold-path hardware-ceiling microbench — plan v2 (patched after AGY r2 PLAN-KILL)

Status: **DRAFT v2 patched (round 3)** — replaces PLAN-KILLED v1.
AGY plan-review round 2 (`adversarial-review-mpoklpnn-a24rwz`) PLAN-KILL +
AGY round 3 (`adversarial-review-mpoky7be-bsku4m`) PLAN-NEEDS-MAJOR
patches incorporated. v2-round3 changes (post-AGY-r3):
- Promote `--cohort=unbounded` to default for the JIT-planning Scale
  Target. Bounded mode is diagnostic only.
- Split §4.6 into four tables (A1 pure policy-eval, A2 install+replicate,
  B1 warm-path-after-fill, B2 cold-saturated).
- Drop p9999 from Table A2 (bounded mode); statistically thin.
- TSC-only gate on Scale Target: clock_gettime fallback runs are stored
  in raw TSVs but excluded from the published §4.6 table.

v1 round-1 verdicts (verbatim references):

- Codex (`task-mpoiptnt-dmw8n0`) — PLAN-KILL
- Antigravity (`adversarial-review-mpoiqabw-y5s6ga`) — PLAN-KILL
- Claude SMR — PLAN-NEEDS-MAJOR
  (`docs/pr/1607-hw-ceiling-microbench/claude-smr-plan-r1.md`)

v2 axes the reviewers MUST audit:

1. UDP randomized-source-port flooder is now the **default** mode
   (§4.2). No iperf3 in the default path. The flooder ships in this PR
   as a `cargo`-built Rust binary at
   `test/incus/cold-path-flooder/`. Smoke-only iperf3 sanity is a
   `--mode=iperf3-sanity` flag whose sole purpose is to prove the
   histogram increments at all.
2. True 64 B Ethernet frames on the wire (§4.2.3). UDP/IPv4 payload
   = 22 B → 14 + 20 + 8 + 22 = 64 B. UDP/IPv6 payload = 2 B →
   14 + 40 + 8 + 2 = 64 B. The harness reports packet rate against
   true 64 B frames and stops calling iperf3 numbers "64 B".
3. TSC-based sampling with 1-in-256 sample mask (§4.3.2). The wrapper
   on the non-sampled path is one branch + one xorshift step + one
   counter increment (~1 ns total). The sampled path is one `rdtscp`
   pair + bucket index + array store. The harness measures and
   reports the `rdtscp` round-trip baseline, the sample mask, the
   raw histogram, and the bias-corrected histogram.
4. CPU isolation state is **recorded per run** and the doc text in
   §4.6 is scoped to "approximate ceiling under loss-cluster
   contention" (§4.5). The harness reads `/proc/cmdline`,
   `/proc/interrupts` deltas across the run, and per-worker CPU
   affinity from `sched_getaffinity(tid)` via the existing status
   wire (gRPC). If `isolcpus` is absent OR worker CPUs overlap with
   NIC IRQ CPUs, the harness emits a single-line ISOLATION-WARNING
   header in the TSV output. Bumping `limits.cpu` and adding
   `isolcpus=` is filed as a follow-up against #739 (preserved
   linkage; not blocking this PR).
5. Per-zone-pair latency histograms with bounded slot cardinality
   (§4.4). 16 zone-pair slots × 24 buckets × 8 B AtomicU64 per worker
   = 3.0 KB per worker. Slot selection: `(zone_pair_key.wrapping_mul(0x9E3779B97F4A7C15)
   >> 60) as usize` (xxhash-style high-bit pick) so adjacent zone
   pairs in id-space do not all collide on slot 0. Synthetic config
   uses K_ZONE_PAIRS ≤ 16 by default so each zone-pair lands in a
   unique slot; reviewers can override with `--zone-pairs N>16` to
   exercise aliasing.

## 1. Issue framing (unchanged from v1)

#1607 asks for empirical measurement of the policy-evaluation
cold-path ceiling on `loss:xpf-userspace-fw0`, so that #1605 JIT
re-plan and #1609 multi-stage DAG planning stop reasoning against an
unmeasured budget. The deliverable is *measurement infrastructure plus
a populated baseline table plus a Scale Target section in
`docs/userspace-jit-design.md`*. The win is unblocking #1605 Phase 4b
and #1609 cardinality budgeting; this PR does NOT change
packet-forwarding behavior.

## 2. Honest scope/value framing (v2)

This remains a **measurement-harness PR, not a perf PR**. The win is
the empirical numbers it produces, not the code itself. The v2 design
explicitly addresses the five v1 kill axes by:

- Replacing iperf3 with a flooder that exercises the cold path on
  every packet (no flow-cache amortization).
- Generating true 64 B Ethernet frames (no `-l 64` framing trick).
- Sampling timer overhead with TSC + 1-in-256 mask so the wrapper
  cost is amortized to ~0.1 ns / packet, well below the sub-1 µs
  cold-path floor.
- Recording (not enforcing) CPU isolation state so operators reading
  the numbers know what regime they're in.
- Publishing per-zone-pair histograms (within a bounded 16-slot
  cardinality budget) so the JIT design doc can see the cliff this
  PR exists to expose.

Known limitations of v2 that we accept explicitly:

- **Loss cluster contention** — the loss userspace cluster runs with
  `limits.cpu: 4` and no `isolcpus`. v2 ships the harness with the
  warning header; lab fixes are tracked in #739.
- **No 1M-rule numbers** — wire-protocol literal-CIDR ceiling is
  pre-#1606. v2 populates rules ∈ {10, 100, 1K, 10K} and explicitly
  marks 100K / 1M as `N/A — blocked on #1606`.
- **Zone-pair slot aliasing under K > 16** — slot conflict on
  high-cardinality configs collapses two zone pairs into one bucket
  set. Default synthetic config ships K = 16, so aliasing is opt-in.

## 3. What's already shipped / reused

- `bucket_index_for_ns` (`userspace-dp/src/afxdp/umem/mod.rs:244`)
  — branchless power-of-two bucket select. v2 extends to
  `bucket_index_for_ns_24` with `DRAIN_HIST_BUCKETS_24 = 24`
  (lives in a new `userspace-dp/src/afxdp/cold_path_hist.rs`
  module so the wire contract is per-counter, not shared with
  drain).
- `WorkerRuntimeAtomics` publish-on-1s pattern
  (`userspace-dp/src/afxdp/worker_runtime.rs`) — v2 piggybacks on the
  same `publish()` tick.
- `REDIRECT_SAMPLE_MASK = 0xff` (`userspace-dp/src/afxdp/umem/mod.rs:183`)
  — 1-in-256 sample pattern with per-worker phase. v2 reuses the
  same constant and pattern.
- `xpf_userspace_worker_dead` Prometheus emission
  (`pkg/api/metrics_userspace.go`) — proven additive-field pattern.
- TSC reads — `core::arch::x86_64::__rdtscp` is the right primitive;
  not currently used anywhere in `userspace-dp/`, so v2 introduces
  one helper `cold_path_hist::sample_tsc()` with a unit-test
  monotonic-fence assertion.

## 4. Concrete v2 design

### 4.1 Synthetic policy generator — `test/incus/synthetic-policy-gen.py`

Unchanged from v1 §4.1 with two clarifications:

- Default `--zone-pairs 16` (was 20) so default config matches the
  16-slot per-zone-pair histogram cardinality. The dataplane never
  enforces this — it's purely a default for clean reads.
- Manifest now records `--zone-pairs` so the harness can detect
  aliasing and warn in its TSV header.

### 4.2 Cold-path UDP flooder — `test/incus/cold-path-flooder/`

A standalone Rust binary, built via a small workspace addition. New
files (all in this PR):

- `test/incus/cold-path-flooder/Cargo.toml`
- `test/incus/cold-path-flooder/src/main.rs`
- `test/incus/cold-path-flooder/README.md` (operator-facing)
- `Cargo.toml` workspace add: `test/incus/cold-path-flooder`

Flag surface:

```
cold-path-flooder
  --dst-ip <IP>         (172.16.80.200 default)
  --dst-port-base <P>   (5201 default)
  --dst-port-span <N>   (number of dst-ports to sweep; default 1)
  --src-ip-base <IP>    (10.42.0.0 default)
  --src-ip-span <N>     (default 16384 — see "5-tuple cardinality budget" below)
  --src-port-span <N>   (default 8 — see "5-tuple cardinality budget" below)
  --duration-secs <S>   (default 30)
  --warmup-secs <S>     (default 2)
  --tx-mbps <M>         (default 0 = max)
  --frame-bytes <B>     (default 64; checked against MIN_ETH=64)
  --batch <N>           (sendmmsg batch; default 32)
  --iface <NAME>        (default ge-0-0-1 — LAN side of loss cluster)
  --ipv4 | --ipv6       (default ipv4; v6 path uses fe80::-equivalent)
  --output-json <FILE>  (per-run summary)
```

#### 4.2.0 5-tuple cardinality budget — dual-regime measurement

There are two legitimate cold-path measurement regimes, and the right
JIT-planning answer needs **both** numbers, not one.

**Regime A — Pure policy evaluation (`--cohort=unbounded`)**

Random /16 sweep × full ephemeral source-port range generates
~4.3 billion distinct 5-tuples. The session table caps at
`DEFAULT_MAX_SESSIONS = 131_072` (`userspace-dp/src/session/mod.rs:25`).
At 5 Mpps × 30 s, the table fills in the first ~26 ms; for the
remaining 29.97 s, every `install_with_protocol_with_origin` call
returns `false` fast (`session/mod.rs:666-668`), and
`replicate_session_upsert` is bypassed entirely. The cold path
degenerates to:
`cache_miss → policy_eval → install_rejected_fast_return`.

This is the right number for the JIT engine's worst-case linear-scan
budget — it isolates the policy-eval cost without contamination from
session install or cross-worker replicate lock contention.

**Regime B — Real cold-path including session install (`--cohort=bounded`)**

Bounded cohort sized exactly to the session table:

```
src_ip_span      = 16384   (14 bits of IP randomization)
src_port_span    = 8       (3 bits of source-port — 8 ports per IP)
dst_port_span    = 1       (single dst-port by default)
unique 5-tuples  = 16384 × 8 × 1 = 131_072  (exactly DEFAULT_MAX_SESSIONS)
```

The cohort fills the session table to capacity during the first
~26 ms of the run, with every install succeeding and triggering
`replicate_session_upsert` (`session_glue/mod.rs:573-583`) — which
acquires N (= worker_count) per-worker Mutex command queues and pushes
a `WorkerCommand::UpsertSynced(replica.clone())`. With 6 workers at
5 Mpps, that's 786 K Mutex acquisitions in 26 ms ≈ 30 M locks/s
aggregated — a real measurement of cross-worker session-replicate
contention, but a *burst* profile that's not representative of
sustained 100 K new-flows/sec production traffic.

This regime is useful for measuring the install + replicate cost as
a separate concern from policy eval.

**Default regime — Regime A (unbounded)**

Per AGY r3 axis 1: bounded mode produces burst-install lock contention
in the first 26 ms that distorts the latency histogram, AND only 131 K
total cold-path samples per run (since flow cache hits all subsequent
packets — p9999 has 13 samples, statistically noise-dominated).

Unbounded mode, by contrast, runs cold-path continuously for the
entire 30 s window:
- 5 Mpps × 30 s = 150 M packets, all cold-path-eligible.
- 1-in-256 sample mask → ~586 K samples per run. p9999 has ~58.6 K
  tail samples — clean.

**Both regimes are reported in §4.6:**
- Table A1 (default): policy-eval-only cold-path latency under Regime A.
- Table A2 (diagnostic): install + replicate cost under Regime B.
- Table B1 (default): warm-path-after-fill aggregate Mpps under Regime B.
- Table B2 (diagnostic): cold-path-saturated aggregate Mpps under Regime A.

The TSV `mode` column records which regime is active. The Scale Target
text in `docs/userspace-jit-design.md` cites both numbers with their
regime tag, so the JIT design doc can budget cold-path policy eval
(Regime A) independently from session install (Regime B).

The previous v2-patched §4.2.0 made Regime B the default. AGY r3
caught two problems with that choice:
- The burst-install contention distorts the latency measurement.
- 131 K samples is statistically thin for p9999.

The remedy: promote Regime A to default; keep Regime B explicit for
session-install measurement.

**Fix details for Regime A**:

```
src_ip_span      = 16384   (14 bits of IP randomization)
src_port_span    = 8       (3 bits of source-port — 8 ports per IP)
dst_port_span    = 1       (single dst-port by default)
unique 5-tuples  = 16384 × 8 × 1 = 131_072  (exactly DEFAULT_MAX_SESSIONS)
```

This means:

- Default mode is `--cohort=unbounded`. The harness in the default
  invocation uses `--src-ip-span 65535 --src-port-span 65535
  --dst-port-span 1` ≈ 4.3 B unique 5-tuples; all packets after
  the 26 ms warm-up are cold-path-eligible (cache_miss → policy_eval →
  install_rejected). Sample mask 1-in-256 → ~586 K samples / 30 s,
  ample for p9999.
- Optional `--cohort=bounded` mode uses the 131 K-cohort sizing
  above. Sample mask drops to 1-in-1 because the cold-path sample
  count is hard-capped at 131 K (one per unique 5-tuple). p999 is
  clean (131 tail samples); p9999 is NOT reported in bounded mode
  per AGY r3 axis 3 (13 samples too few).
- The wrapper-baseline subtraction (TSC pair ~25 ns × 2) applies to
  both regimes; the harness reports `wrapper_ns_baseline`.

**Alternative knobs the harness exposes**:

- `--cohort {bounded,unbounded}` — `bounded` is default. `unbounded`
  enables the AGY-flagged "policy-eval-only" regime explicitly; useful
  for isolating the policy eval cost from session install cost. The
  TSV column `mode` records which regime was active.
- `--cohort-size <N>` — override default `min(DEFAULT_MAX_SESSIONS,
  src_ip_span * src_port_span * dst_port_span)`. Reviewers can sweep.
- `--saturate-table-first` — fill the session table to capacity in a
  fast pre-warm phase (no measurement), then run a separate
  measurement phase where cold-path samples are dominated by
  install-rejection rather than install-success. This is an explicit
  diagnostic mode, not the default.

**CoS interaction (AGY axis 2)**: 131 K unique 5-tuples hashed into
`COS_FLOW_FAIR_BUCKETS = 4096` will activate ~100 % of buckets, which
is unrealistic. The cold-path-microbench default is **CoS-off** for
this reason. CoS-on is a separate sweep that uses a smaller cohort
(default 32 streams) to keep ~32 of 4096 buckets active — closer to a
production profile. The TSV header records `cos_mode = on/off` per
run.

#### 4.2.1 Why AF_PACKET, not iperf3

- Per-packet source-port randomization: iperf3 uses a fixed
  5-tuple per stream; the userspace flow cache hits on packet 2.
- True 64 B Ethernet frames: iperf3 `-l 64` is application-write
  size; on-wire is ~130 B with TCP options or ~98 B with UDP. v2
  produces exactly 64 B Ethernet frames.
- Batched submission: `sendmmsg(SOCK_RAW, batch=32)` runs at line
  rate on the loss cluster's LAN-side virtio with a single core.
- No external dependency: ships as a cargo binary in the workspace.

#### 4.2.2 Per-packet 5-tuple selection

Single-core xorshift PRNG (no SIMD; flooder is CPU-cheap enough not
to need vectorization at 5+ Mpps target):

```rust
// 64-bit xorshift, seeded from getpid() XOR getppid() XOR rdtsc()
// at start. Splits across src_ip (32b), src_port (16b),
// dst_port (16b — masked to span).
let mut s = state.prng;
s ^= s << 13; s ^= s >> 7; s ^= s << 17;
state.prng = s;
let src_ip_offset = (s & 0xFFFF) as u32;
let src_port    = ((s >> 16) & 0xFFFF) as u16;
let dst_port_off = ((s >> 32) & DST_PORT_SPAN_MASK) as u16;
```

This produces uniform 5-tuple distribution over the configured
spans. The flow cache cannot amortize because the next packet has a
new key with probability ~1 - 2^-32.

#### 4.2.3 Frame layout (default 64 B IPv4)

```
Byte 0-13   Ethernet header (dst MAC + src MAC + ethertype 0x0800)
Byte 14-33  IPv4 header (no options, ttl=64, proto=17)
Byte 34-41  UDP header (src_port, dst_port, len=30, csum=0)
Byte 42-63  UDP payload (22 B fixed magic 0x'XPF-COLD-PATH-MIN64\n\0\0')
```

Total: 64 B Ethernet frame. IPv4 header checksum computed once per
packet (cheap; no offload available on raw socket); UDP checksum is
zero per RFC 768 over IPv4 — acceptable for a microbench.

For IPv6: 14 + 40 + 8 + 2 = 64 B Ethernet frame. UDP checksum is
mandatory under IPv6, so we precompute the pseudo-header CRC and
fold in the 2 B payload — measurable but cheap (~5 ns/packet).

### 4.3 Cold-path counter wiring

#### 4.3.1 Sample sites (unchanged from v1)

The two `evaluate_policy*` call sites in
`userspace-dp/src/afxdp/poll_descriptor/mod.rs` (lines 1375, 2393).

#### 4.3.2 TSC-based sampling + 1-in-256 mask

```rust
// New helper in userspace-dp/src/afxdp/cold_path_hist.rs:
pub(in crate::afxdp) struct ColdPathSampler {
    counter: u64,              // worker-local, no atomic
    seed:    u64,              // worker_id-derived
}

impl ColdPathSampler {
    /// Returns Some(t0_tsc) iff this call hits the sampled slot
    /// (1-in-256). The branch predictor learns the not-sampled
    /// path in well under a million iterations.
    #[inline]
    pub fn maybe_start(&mut self) -> Option<u64> {
        self.counter = self.counter.wrapping_add(1);
        if (self.counter ^ self.seed) & 0xff == 0 {
            // SAFETY: rdtscp is supported on every x86_64 CPU
            // produced since 2010 (architectural feature).
            let mut aux = 0u32;
            let t = unsafe { core::arch::x86_64::__rdtscp(&mut aux) };
            Some(t)
        } else {
            None
        }
    }

    /// Convert TSC delta to ns using the once-calibrated rate.
    /// Calibration runs in the worker's start_up() phase before any
    /// packets are seen.
    #[inline]
    pub fn close(t0_tsc: u64, ns_per_tsc_q32: u64) -> u64 {
        let t1 = unsafe {
            let mut aux = 0u32;
            core::arch::x86_64::__rdtscp(&mut aux)
        };
        let dtsc = t1.wrapping_sub(t0_tsc);
        // Q32 fixed-point multiply: ns = dtsc * ns_per_tsc / 2^32.
        ((dtsc as u128 * ns_per_tsc_q32 as u128) >> 32) as u64
    }
}
```

Sample-site usage:

```rust
let t0 = worker_local.cold_path_sampler.maybe_start();
let policy_result = evaluate_policy_result_with_len(...);
if let Some(t0) = t0 {
    let dt_ns = ColdPathSampler::close(t0, worker_local.ns_per_tsc_q32);
    worker_local.cold_path_counters.record(zone_pair_key, dt_ns);
}
```

Cost on the non-sampled path: 1 add + 1 xor + 1 mask + 1 branch + 1
counter store ≈ ~1 ns. Cost on the sampled path: 2 rdtscp (~25 ns
each) + 1 Q32 multiply (~3 ns) + 1 zone-pair-slot select (~2 ns) +
24-bucket histogram store (1 non-atomic u64 store, ~1 ns). Sampled
path is ~55 ns, fires 1-in-256, amortized cost = ~0.21 ns / packet.
The wrapper is **at most 0.5 %** of a 200 ns cold-path floor —
well under the F2-required threshold.

#### 4.3.3 TSC calibration

In each worker's setup phase (before its first packet):

```rust
let t0 = rdtscp(); let n0 = clock_gettime_ns();
std::thread::sleep(std::time::Duration::from_millis(100));
let t1 = rdtscp(); let n1 = clock_gettime_ns();
let tsc_per_ns_q32 = ((n1 - n0) as u128 * (1u128 << 32)
                     / (t1 - t0) as u128) as u64;
```

100 ms calibration is run-once per worker startup; the Q32
multiplier is read in `close()`. We probe invariant TSC by reading
`/proc/cpuinfo` for `constant_tsc` and `nonstop_tsc` flags at
coordinator start. **Graceful degrade** (AGY r2 hazard 1): if either
flag is missing, the worker logs a one-time warning and falls back to
`clock_gettime(CLOCK_MONOTONIC)` for the sample-site clock. The
1-in-256 sample mask amortizes the clock_gettime cost to ~0.18 ns /
packet — still well below the cold-path floor. The TSV harness
records `clock_source = tsc|clock_gettime` per run so downstream
operators know which regime they're in. We do NOT refuse to start —
that would break CI / nested-VM deployments without invariant TSC.

Calibration sleep precision (Claude SMR r2 N2): the 100 ms
`std::thread::sleep` can drift ±10 ms on contended systems. To
mitigate, the calibration body uses a **spin-then-validate** pattern:
sleep 100 ms, then spin in a tight `clock_gettime` loop until 100 ms
wall has actually elapsed, capturing TSC delta over the validated
wall window. Spin overhead is bounded by the drift and the next
publish tick is unaffected.

#### 4.3.4 Per-zone-pair slot pick

```rust
const ZP_SLOTS_LOG2: usize = 4;          // 16 slots
const ZP_SLOTS:      usize = 1 << ZP_SLOTS_LOG2;

#[inline]
fn zone_pair_slot(key: u32) -> usize {
    // Multiply by golden-ratio constant, then take LOW 4 bits.
    // Empirically: for K=16 diagonal (from_id==to_id) zone-pair keys,
    // the low-4-bit pick gives a PERFECT bijection [0..16) → [0..16).
    // The earlier high-4-bit pick (>> 60) clustered: AGY r2 axis 3
    // showed slot 0 with 2 keys and slot 11 with 2 keys for the
    // diagonal case. low-4-bit avoids this because multiplication
    // by the golden ratio is a maximum-period permutation on the
    // low-order bits when the input is a small contiguous integer
    // sequence (see Knuth Vol 3, §6.4).
    let h = (key as u64).wrapping_mul(0x9E3779B97F4A7C15);
    (h & 0xF) as usize
}
```

Empirical distribution check (verified during plan-review r2):

| Input pattern (K=16) | low `& 0xF` | high `>> 60` |
|----------------------|------------|--------------|
| Diagonal (i, i)      | perfect [1,1,1...×16] | [2,2,2,1,1...] |
| Round-robin (i, i+1) | perfect [1,1,1...×16] | [2,2,2,1,1...] |
| Random K=16 sample   | best-uniform | clustered |

The `&0xF` pick is the correct choice; the plan's earlier `>> 60` was
an error.

### 4.4 New struct: `WorkerColdPathCounters`

Lives in `userspace-dp/src/afxdp/cold_path_hist.rs`:

```rust
const HIST_BUCKETS: usize = 24;

#[derive(Default)]
pub(in crate::afxdp) struct WorkerColdPathCounters {
    // Per-zone-pair-slot histogram + sum + count.
    hist:    [[u64; HIST_BUCKETS]; ZP_SLOTS],
    sum_ns:  [u64; ZP_SLOTS],
    samples: [u64; ZP_SLOTS],
    /// Sum of zone_pair_keys that landed in each slot, used by the
    /// reader to flag aliasing.  (At most 16 keys per slot in default
    /// K=16 config → no collision.)
    keys_seen_xor: [u32; ZP_SLOTS],
}

#[repr(align(64))]
pub(in crate::afxdp) struct WorkerColdPathAtomics {
    hist:    [[AtomicU64; HIST_BUCKETS]; ZP_SLOTS],
    sum_ns:  [AtomicU64; ZP_SLOTS],
    samples: [AtomicU64; ZP_SLOTS],
    keys_seen_xor: [AtomicU64; ZP_SLOTS],  // u64 for atomic uniformity
}
```

Bucket layout note: with 24 buckets, the saturation edge is **2^32 ns
≈ 4.295 s** (any `ns ≥ 2^32` maps to bucket 23). AGY r2 axis 4 caught
the earlier prose claim of "saturates at 2^33 ns" — that was wrong;
the math is `b = (54 - clz(ns|1)).max(0).min(23)`. For our worst-case
projection of 1M-rule linear scan at ~100 ns/rule = ~100 ms per packet
(~10^8 ns ≈ 2^27 ns), the result lands in bucket ~17 — well below
saturation. Tail is visible.

Size per worker: 16 × 24 × 8 + 16 × 8 × 3 = 3072 + 384 = **3456 B**
per worker, ~54 cache lines. With 6 workers = 20.7 KB total. Cheap
in absolute terms; localized to one struct so a future redesign
(e.g. per-zone-pair flat array indexed by id) doesn't need to touch
the call sites.

Publish path: per-tick (`~1 Hz`) the worker calls
`WorkerColdPathAtomics::publish(&counters)`; 24 × 16 + 3 × 16 = 432
Relaxed stores per worker per second. Negligible.

### 4.5 CPU isolation recording (harness side)

AGY r2 hazard 2: the LAN_HOST container (`cluster-userspace-host`)
runs on the same physical loss host as `xpf-userspace-fw0` with no
explicit CPU pinning. Under heavy flooder load (5+ Mpps random-source
generation) the host scheduler can co-locate flooder threads on the
same physical cores as FW0 worker threads, introducing per-run
scheduling jitter.

The harness mitigates without changing the test fixture:

```bash
# Pin the flooder process to the highest core indexes on the host
# (away from the typical [0..3] CPUs that incus places VM workers on).
nproc_host=$(nproc)
flooder_pin_first=$(( nproc_host - 2 ))
taskset -c "${flooder_pin_first}-$(( nproc_host - 1 ))" \
  incus exec loss:cluster-userspace-host -- /usr/local/bin/cold-path-flooder ...
```

This is best-effort: if `nproc` reports < 4, the pin reduces to "last
core only" and we emit `FLOODER-PIN-WARNING: insufficient host cores`.
The TSV header records `flooder_pin_cores=<list>`.

The harness (`test/incus/cold-path-microbench.sh`) runs before and
after each measurement:

```bash
incus exec loss:xpf-userspace-fw0 -- bash -c '
  echo "=== cmdline ===";    cat /proc/cmdline
  echo "=== clocksource ==="; cat /sys/devices/system/clocksource/clocksource0/current_clocksource
  echo "=== interrupts ===";  awk "/mlx5/" /proc/interrupts
  echo "=== worker affinity ==="; for t in /proc/$(pidof userspace-dp)/task/*; do
    cat $t/status | grep -E "Name|Cpus_allowed_list"
  done
' > /tmp/iso-pre.log

# ... run the measurement ...

# Repeat for /tmp/iso-post.log; diff /proc/interrupts to estimate
# IRQ overlap with worker CPUs.
```

Output TSV header includes:

```
# isolation_warning=<true|false>
# isolcpus=<value or "absent">
# worker_cpus=<list>
# nic_irq_cpus=<list>
# shared_cpus=<list>
```

If `shared_cpus` non-empty, the TSV header includes
`# isolation_warning=true # numbers are upper-bound, see #739`.

### 4.6 Doc update — `docs/userspace-jit-design.md` Scale Target section

Four tables (per AGY r3 axis 2 — bounded-mode Table B is warm-path
illusion, must label both regimes explicitly):

```markdown
## Scale Target (measured on loss userspace cluster, 2026-05-27)

Methodology: `test/incus/cold-path-microbench.sh --rules N`
on `loss:xpf-userspace-fw0`. Default flooder mode: UDP source-port
randomized at 5 Mpps target, true 64 B Ethernet frames. Per-packet
cold-path latency sampled 1-in-256 via TSC (Regime A) / 1-in-1 by
TSC (Regime B); wrapper baseline subtracted in the corrected column.

CPU isolation state at run time: **isolcpus=absent** (loss cluster
runs with `limits.cpu: 4` and no `isolcpus` per #739). Numbers
below are upper-bound estimates under contention.

**TSC-only gate (AGY r3 hazard 1)**: Tables below publish only
runs where `clock_source = tsc`. `clock_gettime` fallback runs
(CI VMs without invariant TSC) are stored in raw TSVs but NOT
copied into this scale target table; vDSO/hypervisor clock jitter
on those runs would distort the budget.

### Table A1 — Pure policy-eval cold-path latency (Regime A unbounded; per-call, ns)

Default JIT-planning regime. cache_miss → policy_eval →
install_rejected_fast_return. Cross-worker replicate bypassed.

| Rules | p50 raw | p50 corr | p99 raw | p99 corr | p999 raw | p999 corr | p9999 raw | p9999 corr | Notes |
|-------|--------:|---------:|--------:|---------:|---------:|----------:|----------:|-----------:|-------|
|    10 | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | linear scan trivial |
|   100 | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | |
|  1000 | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | first cliff candidate |
| 10000 | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | pre-#1606 wire ceiling |
| 100000 | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | blocked on #1606 |
| 1M | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | blocked on #1606 |

### Table A2 — Install + replicate cold-path latency (Regime B bounded; per-call, ns)

Diagnostic. cache_miss → policy_eval → install_succeeded →
replicate_session_upsert × worker_count. 131 K cohort. Per AGY r3
axis 3, **p9999 dropped** (13 samples — noise-dominated).

| Rules | p50 raw | p50 corr | p99 raw | p99 corr | p999 raw | p999 corr | Notes |
|-------|--------:|---------:|--------:|---------:|---------:|----------:|-------|
|    10 | TBD | TBD | TBD | TBD | TBD | TBD | burst install dominates |
|   100 | TBD | TBD | TBD | TBD | TBD | TBD | |
|  1000 | TBD | TBD | TBD | TBD | TBD | TBD | |
| 10000 | TBD | TBD | TBD | TBD | TBD | TBD | |

### Table B1 — Warm-path-after-fill aggregate throughput (Regime B; Mpps, 64 B frames)

Reflects steady-state warm-path Mpps after the bounded cohort's
session table fills (~26 ms warm-up). NOT a cold-path-throughput
measurement.

| Rules | Per-worker Mpps p50 | Aggregate Mpps | Notes |
|-------|--------------------:|---------------:|-------|
|    10 | TBD | TBD | warm path |
|   100 | TBD | TBD | warm path |
|  1000 | TBD | TBD | warm path |
| 10000 | TBD | TBD | warm path |

### Table B2 — Cold-path-saturated aggregate throughput (Regime A; Mpps, 64 B frames)

True cold-path Mpps when every packet exercises policy eval
(install_rejected fast path). The cap of Table B1 vs Table B2
shows the warm-path advantage the JIT planner can chase.

| Rules | Per-worker Mpps p50 | Aggregate Mpps | Notes |
|-------|--------------------:|---------------:|-------|
|    10 | TBD | TBD | cold path |
|   100 | TBD | TBD | cold path |
|  1000 | TBD | TBD | cold path |
| 10000 | TBD | TBD | cold path |

### Wrapper baseline

`rdtscp` round-trip measured once per worker startup at TSC
calibration. The TSV records the value as `wrapper_ns_baseline`.
Typical value on loss cluster: ~30-40 ns (verified at run time).
Table A1/A2 "corr" columns subtract this from the raw histogram.

### Sample-count budget

- Regime A (default): 1-in-256 sampling, ~586 K samples / 30 s,
  ~58.6 K tail samples for p9999. Clean.
- Regime B: 1-in-1 sampling, hard cap 131 K samples / run, ~131 tail
  samples for p999. p9999 (13 samples) dropped per AGY r3 axis 3.
```

### 4.7 Public-API surface

Additions to `pkg/dataplane/userspace/protocol.go::WorkerRuntimeStatus`:

```go
// #1607: per-zone-pair-slot cold-path latency histograms.
// Slot index = splitmix-hash(zone_pair_key) & 0xF (16 slots).
// Buckets: 24-entry power-of-two ns layout (saturates at ~4 s).
ColdPathHist     [][]uint64 `json:"cold_path_hist,omitempty"`        // [slot][bucket]
ColdPathSumNS    []uint64   `json:"cold_path_sum_ns,omitempty"`      // [slot]
ColdPathSamples  []uint64   `json:"cold_path_samples,omitempty"`     // [slot]
ColdPathKeysXor  []uint64   `json:"cold_path_keys_xor,omitempty"`    // [slot]
ColdPathNSPerTSC uint64     `json:"cold_path_ns_per_tsc_q32,omitempty"`
ColdPathWrapperNSBaseline uint64 `json:"cold_path_wrapper_ns_baseline,omitempty"`
```

Mirror additions on Rust side in
`userspace-dp/src/protocol/binding.rs::WorkerRuntimeStatus`. Both
sides additive; all `omitempty` / `#[serde(default)]`. Older Go
clients receive an empty payload; older daemons emit zero.

Prometheus emission in `pkg/api/metrics_userspace.go`:

- `xpf_userspace_worker_cold_path_ns_bucket{worker_id, zone_pair_slot, bucket_hi_ns}`
- `xpf_userspace_worker_cold_path_samples_total{worker_id, zone_pair_slot}`
- `xpf_userspace_worker_cold_path_sum_ns_total{worker_id, zone_pair_slot}`
- `xpf_userspace_worker_cold_path_wrapper_ns_baseline{worker_id}` (gauge)

Cardinality: 6 workers × 16 slots × 24 buckets = 2304 series for the
bucket counter. Plus 6×16×2 = 192 for samples/sum, 6 for baseline.
Total: ~2500 new series on the loss cluster. Fits comfortably under
Prometheus scrape budget; comparable to existing
`drain_latency_hist` (12 queues × 16 buckets × N workers).

### 4.8 Hidden invariants preserved

- Hot-path no-allocation rule: sampler is one branch + one ALU op +
  one store (non-sampled path); sampled path does no allocation,
  uses worker-local `[u64; 24]` array.
- Lock ordering / ArcSwap: untouched.
- HA sync portability: no HA-touching code.
- Counter overflow: u64 at 5 Mpps cold-path-saturated, ~117 years.
- Wire-protocol both-sides: both `protocol/binding.rs` (Rust) and
  `pkg/dataplane/userspace/protocol.go` (Go) updated in this PR. No
  pkg/cluster sync wire changes.
- Bucket layout pinned: `pub(in crate::afxdp) const
  POLICY_COLD_PATH_HIST_BUCKETS: usize = 24;` with
  `const _: () = assert!(POLICY_COLD_PATH_HIST_BUCKETS == 24);`.
  Zone-pair slot count pinned analogously.

## 5. v1 → v2 fatal-axis resolution map

| v1 axis | Resolution in v2 | Sections |
|---------|------------------|----------|
| F1 TCP cold-path sample starvation | UDP randomized-source-port flooder is default; iperf3 is sanity-only | §4.2 |
| F1.2 iperf3 `-u` reuses 5-tuple | Per-packet xorshift PRNG over src_ip/src_port/dst_port spans | §4.2.2 |
| F1.3 Mpps + per-call-ns conflation | Two distinct tables in §4.6; rate-base spelled out | §4.6 |
| F2 `clock_gettime` 18-22 % bias | TSC-based 1-in-256 sampling; calibrated wrapper baseline subtracted | §4.3.2 / §4.3.3 |
| F3 16-bucket saturation hides tail | 24-bucket layout; saturates at ~4 s | §4.4 |
| F4 No CPU isolation discipline | Record + warn; doc text scoped to "approximate ceiling under contention"; follow-up tracked under #739 | §4.5 / §4.6 |
| F5 Per-worker aggregation hides cliff | 16-slot per-zone-pair histogram (splitmix-hashed) | §4.3.4 / §4.4 |
| Wire `-l 64` misrepresentation | True 64 B Ethernet frames; checked at build time against MIN_ETH | §4.2.3 |

## 6. Test plan

- `cargo build --release` clean (workspace + cold-path-flooder).
- `cargo test --release` — full 952+ suite passes; new tests:
  - `userspace-dp/src/afxdp/cold_path_hist_tests.rs`:
    - `bucket_index_24_layout` — verify each bucket edge maps as
      expected, including saturation at 2^33 ns.
    - `zone_pair_slot_no_clustering` — empirically verify 100K
      random keys distribute within ±5 % of uniform across slots.
    - `sampler_one_in_256` — drive 1 M synthetic packets, assert
      sample count is within 256 ± 16.
    - `tsc_calibration_monotonic_under_sleep` — calibrate, sleep
      10 ms, assert TSC delta > 9 ms in ns-equivalent.
  - `userspace-dp/src/afxdp/worker_runtime_tests.rs::cold_path_publish_round_trip`
    — push samples into all 16 slots × 24 buckets, publish,
    snapshot, verify values round-trip and aliasing detector
    flags multi-key slots.
  - Go-side `pkg/api/metrics_test.go::TestEmitWorkerRuntime_ColdPath`
    — drive a `WorkerRuntimeStatus` with non-zero hist, sums,
    samples; assert per-slot, per-bucket Prometheus samples emit
    with right labels.
- 5/5 flake check on `sampler_one_in_256` and
  `cold_path_publish_round_trip`.
- Go suite `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...`
  — 30 packages green.
- `make test-failover` — required by HA-touch policy in CLAUDE.md
  (this PR doesn't touch HA but the rule says any cluster smoke
  must pass; reviewers confirm whether failover is required).
- Smoke matrix on loss userspace cluster: v4+v6 × push+`-R` ×
  CoS-off+CoS-on (per CLAUDE.md feedback memory).
- Run the new harness end-to-end at rules ∈ {10, 100, 1K, 10K};
  populate §4.6 Tables A and B with measured numbers in the same
  PR.

## 7. Out of scope

- Address-book wire restructure (#1606 — concurrent PR).
- Per-source rate-limit / verdict cache (#1608 — concurrent PR).
- JIT design itself (#1605 — follows this + #1606).
- 100K / 1M rule measurement (blocked on #1606).
- LPM / DAG restructure (#1609).
- Lab fixture changes (isolcpus, IRQ pinning) — tracked separately
  under #739.

## 8. Open questions for v2 adversarial review

1. **TSC invariance gate**: the plan asserts that loss cluster
   exposes `constant_tsc` and `nonstop_tsc`. Should the coordinator
   refuse to start if either flag is missing, or should it
   gracefully degrade to `clock_gettime` with the 1-in-256 sampling
   intact (and amortized to ~0.3 ns / packet)? Refusing trips an
   ops-on-call wake-up at deploy time; degrading hides a regression
   in cloud-VM kernels that disable invariant TSC.
2. **Zone-pair slot count**: 16 slots was chosen because it
   matches default synthetic K=16 and the existing
   `DRAIN_HIST_BUCKETS = 16` cache-line discipline. Should we go
   to 32 or 64 to handle high-cardinality production configs
   (e.g. 100 zone-pairs) without aliasing? Cost is linear in slot
   count: 32 slots → 6.9 KB per worker, 64 → 13.8 KB. Still cheap.
   v1 had no per-zone-pair view at all, so 16 is strictly better
   than the v1 baseline.
3. **rdtscp vs rdtsc**: rdtscp serializes against earlier loads
   (~25 ns); rdtsc is ~15 ns but no fencing. For a histogram
   measurement at sub-µs granularity, do we need the serializing
   fence, or is the ~10 ns saving worth the noise? Plan picks
   rdtscp for safety; reviewers can push back.
4. **Flooder placement**: the flooder lives on the LAN-side
   neighbor (`cluster-userspace-host`) and floods toward
   `172.16.80.200` (WAN-side iperf3 target). This means the
   measurement path is **LAN → FW0 → WAN**, which exercises the
   from-zone=LAN to-zone=WAN policy slot. The synthetic config must
   define a real policy permitting this flow at the head of the
   rule list (so packets traverse but only after the cold-path scan
   completes). Is one-zone-pair-policy-list the right baseline, or
   should we put the matching rule at the **end** of the list to
   force worst-case scan?
5. **Co-residence of flooder + FW**: the flooder runs on
   `cluster-userspace-host` which shares physical host CPUs with
   FW0. Does this introduce host-scheduler noise? Plan v2 records
   per-CPU usage on both sides; if the flooder consumes >50 % of
   the host's CPU budget there's a real risk it starves FW0
   workers. Mitigation: pin the flooder to the **highest** core
   index available (away from FW0's worker pool) and document it.
6. **Bias from per-call branch in non-sampled path**: the sampler
   adds ~1 ns to every cold-path eval (1 branch + 1 ALU). Should
   the plan A/B-test this against a control build that omits the
   sampler entirely, and report the delta? Argued necessary by
   methodology purity; argued unnecessary because 1 ns is below
   the noise floor of the very measurement we're trying to make.
7. **Wire-protocol semantic-versioning**: do we need to bump any
   protocol-version sentinel for the new `WorkerRuntimeStatus`
   fields? Existing pattern (`Dead`, `WindowNS`) was additive
   without a version bump. Confirm no SemVer rule applies here.

## 9. Plan version log

- v1 — DRAFT initial submission (PLAN-KILLED 2026-05-27 round 1).
- v2 — addresses all 5 v1 fatal axes via UDP flooder default,
  TSC sampling, 24-bucket layout, 16-slot per-zone-pair histogram,
  CPU isolation recording. Doc text scoped to "approximate ceiling
  under contention" with #739 follow-up linkage.
- v2 patched (round 3) — addresses AGY r3 PLAN-NEEDS-MAJOR:
  - axis 1 (burst-install contention distorts Table A): promote
    `--cohort=unbounded` to default; bounded becomes diagnostic-only.
  - axis 2 (Table B warm-path illusion in bounded mode): split into
    Table B1 (warm-after-fill, bounded) + Table B2 (cold-saturated,
    unbounded).
  - axis 3 (p9999 statistical starvation in bounded mode, 13 samples):
    drop p9999 column from Table A2; add p9999 to Table A1 only.
  - hazard 1 (clock_gettime VM jitter): TSC-only gate on Scale
    Target; clock_gettime runs stored in raw TSVs but excluded from
    §4.6 publication.
- v2 patched (round 2) — addresses AGY r2 PLAN-KILL findings:
  - axis 1 (session table starvation): bound default unique-5-tuple
    cohort to 131_072 = `DEFAULT_MAX_SESSIONS`, so every cold-path
    sample measures real session install + policy eval cost; sample
    mask becomes 1-in-1 by default when cohort ≤ 256 K.
  - axis 2 (CoS 4096 buckets activated): default `cos_mode=off`; CoS
    sweep uses a smaller 32-stream cohort to keep ~32 / 4096 buckets
    active.
  - axis 3 (splitmix slot clustering): switch to low-4-bit `&0xF`
    pick which is a perfect bijection for K=16 diagonal and
    round-robin patterns (empirically verified).
  - axis 4 (bucket saturation prose): correct prose — 24-bucket
    layout saturates at 2^32 ns ≈ 4.295 s, not 2^33 ns; verified
    visible tail for 1M-rule worst case (~bucket 17).
  - hazard 1 (TSC refuse-start): graceful degrade to
    `clock_gettime` with one-time warning; never refuses to start.
  - hazard 2 (LAN_HOST/FW0 co-residence): explicit
    `taskset -c <last-2-cores>` pin for the flooder via the harness
    script; `FLOODER-PIN-WARNING` if host has < 4 cores.
  - hazard 3 (concurrent #1606/#1608 wire-protocol): unchanged from
    v2 — additive-only fields, expected mechanical merge.

## Z. v2 patch round 3 (post-AGY r3) resolution map

| AGY r3 axis/hazard | Resolution | Section |
|--------------------|------------|---------|
| Axis 1 — burst install contention distorts Table A | Promote `--cohort=unbounded` to default; cold path stays continuous for full 30 s; replicate_session_upsert bypassed | §4.2.0 |
| Axis 2 — bounded Table B is warm-path illusion | Split into Table B1 (warm-path-after-fill, bounded) + Table B2 (cold-saturated, unbounded) with explicit labels | §4.6 |
| Axis 3 — p9999 sample starvation in bounded mode | Drop p9999 from Table A2 (only 13 tail samples in bounded mode); p9999 still in Table A1 (unbounded ~58.6 K tail samples) | §4.6 |
| Hazard 1 — clock_gettime VM jitter | TSC-only gate on Scale Target tables; clock_gettime runs in raw TSV only | §4.6 |

## Y. v2 patch round 2 (post-AGY-KILL) resolution map

| AGY r2 axis/hazard | Resolution | Section |
|--------------------|------------|---------|
| Axis 1 — session table exhaustion | Default cohort = 131_072 unique 5-tuples (= `DEFAULT_MAX_SESSIONS`); cold-path samples come from session installs in the warm-up phase, not from install-rejected packets | §4.2.0 |
| Axis 2 — CoS 4096 buckets all-active | Default CoS-off; CoS-on uses small 32-stream cohort | §4.2.0 (CoS interaction) |
| Axis 3 — splitmix `>> 60` clustering | Switch to `& 0xF` low-bit pick; perfect bijection for K=16 diagonal + round-robin | §4.3.4 |
| Axis 4 — bucket saturation prose | Corrected: saturates at 2^32 ns ≈ 4.3 s, not 2^33 | §4.4 |
| Hazard 1 — TSC refuse-start | Graceful degrade to `clock_gettime` with one-time warning; harness records `clock_source` | §4.3.3 |
| Hazard 2 — LAN_HOST CPU pinning | `taskset -c <last-2-cores>` for flooder; `FLOODER-PIN-WARNING` when host has < 4 cores | §4.5 |
| Hazard 3 — concurrent #1606/#1608 wire-protocol | Additive-only fields with `omitempty` / `#[serde(default)]`; expected mechanical merge | §4.7 (unchanged) |

## X. v1 archive

The v1 plan content has been preserved in git history (commit
`d777741a85b48bf68fc50b16a87b755f918da078`). The PLAN-KILLED header
and the verdict text from round 1 are captured at the top of this
file. To audit v1 verbatim: `git show
d777741a:docs/pr/1607-hw-ceiling-microbench/plan.md`.
