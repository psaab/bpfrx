# #1607 Cold-path hardware-ceiling microbench — plan v1

Status: DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR).

## 1. Issue framing

#1607 asks for empirical measurement of the 64 B policy-evaluation
cold-path ceiling on `loss:xpf-userspace-fw0`, so that the #1605 JIT
re-plan stops reasoning against a derived-but-unmeasured 270 ns/packet
budget (25 Gbps × 64 B = 49 Mpps; ~5.91 Mpps per-worker max from the
architecture doc at 1500 B, scaled). The deliverable is *measurement
infrastructure plus a populated baseline table plus a Scale Target
section in `docs/userspace-jit-design.md`*. The win is unblocking
#1605 Phase 4b; this PR does NOT change packet-forwarding behavior.

Three pieces:

1. **Synthetic policy ConfigSnapshot generator** at
   `test/incus/synthetic-policy-gen.py` — emits Junos `.set` lines
   for N address-books × M CIDRs, K zone-pairs, R rules, A
   apps/rule, P permit/deny mix; ships a manifest JSON of realized
   counts so the harness output is self-describing.
2. **64 B microbench harness** at `test/incus/cold-path-microbench.sh`
   — deploys synthetic config, runs `iperf3 -P 12 -t 30 -b 0 -l 64`
   from `loss:cluster-userspace-host`, scrapes per-worker Mpps + CPU
   + cold-path histogram from `/metrics`, optional perf record on
   cold-path samples.
3. **Cold-path histogram counter** — extend `WorkerRuntimeAtomics`
   with a 16-bucket power-of-two ns histogram (`policy_decision_cold_path_ns_hist`)
   reusing the existing `bucket_index_for_ns` layout (#709/#812)
   and the seqlock-style publish pattern in `worker_runtime.rs`.
   Sample sites: the two `evaluate_policy*` call sites inside
   `userspace-dp/src/afxdp/poll_descriptor/mod.rs` (line 1375 +
   line 2393) — both are session-miss / cold-path paths by
   construction; the flow-cache fast path in
   `flow_cache_hit::stage_flow_cache_hit` bypasses policy eval
   entirely, so the histogram is naturally cold-path-only.

## 2. Honest scope/value framing

This is a **measurement-harness PR, not a perf PR**. The "win" is the
empirical numbers it produces, not the code itself. If reviewers
conclude the harness design is structurally unable to produce
trustworthy numbers (CPU isolation gaps, kernel CRC offset blinding
the 64 B claim, RSS-funnel making per-worker reads meaningless,
iperf3 TCP framing dominating the cold-path measurement), then
**PLAN-KILL is the right verdict** — no harness is better than a
harness that produces numbers everyone believes are real.

Five known structural risks the design must answer credibly:

- **Cold path is bounded by session miss rate, not packet rate**.
  `iperf3 -P 12` opens 12 TCP connections, then the steady-state
  packets all hit the flow cache (warm path). Cold-path measurement
  per packet decays toward zero after the first ~12 RTTs. A 30s run
  produces ~few-hundred cold-path samples at most.
  *Mitigation: optional pktgen mode with random 5-tuples per packet
  to force 100 % cold path; documented as the canonical mode for
  rule-count sweep.*
- **iperf3 `-l 64` is not 64 B on the wire**. `-l 64` is the
  application-write size; iperf3 still emits 14 (Ethernet) + 20 (IPv4
  no options) + 20 (TCP no options, but in practice with timestamp
  option ≈ 32) + 64 = **130 B on the wire** in v4, more in v6. The
  harness MUST report wire-byte size and packet rate distinctly so
  the operator does not conflate "64 B iperf3" with "64 B linerate".
- **CPU isolation discipline**. The harness reports per-worker Mpps,
  but a co-scheduled NIC IRQ on the same CPU steals cycles. The
  harness should record `/proc/interrupts` deltas during the run and
  flag if NIC IRQs and worker threads share a CPU.
- **Cache cold vs warm**. A fresh deploy has cold L1-i / branch
  predictors. The harness must include a documented warm-up phase
  (1 s warmup discard) before sampling.
- **RSS-funnel skew**. AF_XDP UMEM ownership means single-stream
  traffic lands on one worker. With `-P 12`, the RSS hash on the
  iperf3 source-port-randomized streams must actually fan-out across
  workers. The harness should refuse to report aggregate Mpps if
  fewer than `min(P, num_workers) - 1` workers see non-zero RX.

## 3. What's already shipped / partially batched

- **Power-of-two ns histogram pattern** — `DRAIN_HIST_BUCKETS = 16`,
  `bucket_index_for_ns` (branchless, single `leading_zeros` + sat-sub
  + min), published via Prometheus `emitHistogram` with `bucket_hi_ns`
  upper-bound label (pkg/api/metrics.go:326). Used today for CoS
  drain latency (#709), redirect-acquire (#709), TX submit→completion
  (#812). The cold-path histogram reuses this layout verbatim — same
  bucket layout, same wire shape, same Go-side emitter.
- **WorkerRuntimeAtomics publish-on-1s pattern** — already exists for
  CPU/wall/active counters in `userspace-dp/src/afxdp/worker_runtime.rs`
  with a seqlock for window-rotation tuples. The cold-path histogram
  follows the simpler cumulative-counter shape (matches
  `cos_queue_lease_acquire_v8_calls`), since the histogram is
  cumulative — readers compute per-window deltas via Prometheus
  `rate()` / `increase()`.
- **Test environment** — `loss:xpf-userspace-fw0` with the canonical
  iperf3 server on `172.16.80.200` / `2001:559:8585:80::200`. The
  fairness-harness and CoS smoke matrices set the precedent for
  per-class iperf3 invocations + metrics scraping.

## 4. Concrete design

### 4.1 Synthetic policy generator — `test/incus/synthetic-policy-gen.py`

Python because the project already uses Python for parser/validator
helpers (cluster_status_parse, fairness_multi_sample, etc.) and the
ConfigSnapshot Junos-set output is plain-text — no Rust/Go binary
needed.

```
usage: synthetic-policy-gen.py [-h]
  [--address-books N]          default: 100
  [--cidrs-per-book M]         default: 100
  [--zone-pairs K]             default: 20
  [--rules R]                  default: 10000
  [--apps-per-rule A]          default: 5
  [--permit-fraction P]        default: 0.7
  [--cidr-mix MIX]             default: "24:60,28:30,32:10"
                               (percentages, sum=100)
  [--seed SEED]                default: 1607  (reproducible)
  [--output-set FILE.set]      Junos `.set` config
  [--output-manifest FILE.json] Realized-counts JSON
```

Output shape:
- One `set security address-book book-NN address addr-NNNN <CIDR>`
  per CIDR.
- One `set security policies from-zone Z-FROM to-zone Z-TO
  policy rule-NNNNN ...` per rule, citing existing address-books +
  ~A applications.
- Zone names `synth-zone-0` ... `synth-zone-K-1` plus interface
  bindings (single dummy interface per zone, no IP assignment to keep
  the config loadable in dataplane-disabled mode if needed).
- Manifest JSON: `{ "address_books": 100, "total_cidrs": 10000,
  "zone_pairs": 20, "rules": 10000, "apps_per_rule": 5,
  "permit_count": 7000, "deny_count": 3000, "cidr_distribution": {...},
  "seed": 1607, "generated_at": "...", "junos_set_lines": 30137 }`.

CIDR distribution: 60 % /24, 30 % /28, 10 % /32 in RFC 1918 space
(`10.x.x.x/N`), randomly seeded but reproducible. /32 hosts dominate
the worst-case prefix-set linear-scan length per #923; the mix is the
right shape to exercise the cold-path predicate cost.

### 4.2 Microbench harness — `test/incus/cold-path-microbench.sh`

Flow:
1. Source `test/incus/loss-userspace-cluster.env`.
2. `synthetic-policy-gen.py --rules $RULES --output-set /tmp/synth.set
   --output-manifest /tmp/synth-manifest.json`.
3. `incus file push /tmp/synth.set
   loss:xpf-userspace-fw0/tmp/synth.set`.
4. `incus exec loss:xpf-userspace-fw0 -- bash -c 'cli configure;
   delete security policies; delete security address-book; load set
   /tmp/synth.set; commit and-quit'`.
5. **Warmup**: 5 s iperf3 stream to populate flow caches; discard.
6. **Cold-path-saturation mode (default)**: 30 s
   `iperf3 -P 12 -t 30 -b 0 -l 64` from
   `loss:cluster-userspace-host` to `172.16.80.200`. Scrape
   `/metrics` at 1 s intervals; capture
   `xpf_userspace_worker_policy_decision_cold_path_ns_total{worker_id=N,bucket_hi_ns=B}`
   and `xpf_userspace_worker_active_ns` + `wall_ns` deltas for CPU%.
7. **Optional pktgen mode** (flag `--pktgen`): synthetic packet
   generator with random 5-tuples to force 100 % cold-path. Mode
   uses `iperf3-style` UDP with `-u` + `-l 64` + tight `-b 0` budget,
   OR a small Go/Rust UDP flooder if iperf3 framing dominates
   (deferred to round-2 unless reviewers demand it).
8. Emit a single TSV row per rule-count step:
   `rules\tper_worker_mpps_p50\tper_worker_mpps_max\taggregate_mpps\tns_p50\tns_p99\tnotes`.

### 4.3 Cold-path counter wiring

Single sample site, applied to both `evaluate_policy*` call sites in
`poll_descriptor/mod.rs`:

```rust
let t0 = monotonic_nanos();
let policy_result = evaluate_policy_result_with_len(...);
let dt = monotonic_nanos().saturating_sub(t0);
worker_runtime_counters.record_policy_cold_path_sample(dt);
```

The recorder lives on `WorkerRuntimeCounters` (worker-local, no
atomic) and gets flushed to the `WorkerRuntimeAtomics` array
on the existing 1 s `publish()` tick.

`WorkerRuntimeAtomics` gains:
```rust
pub policy_cold_path_ns_hist: [AtomicU64; DRAIN_HIST_BUCKETS],
pub policy_cold_path_samples: AtomicU64,  // count
pub policy_cold_path_sum_ns: AtomicU64,   // sum for mean compute
```

`WorkerRuntimeCounters` gains the same fields as `[u64; ...]` /
`u64`. `publish()` issues 16 + 2 Relaxed stores (cold-path
publish is 1 Hz, not per-packet).

`WorkerRuntimeStatus` (wire) gains:
```rust
#[serde(rename = "policy_cold_path_ns_hist", default,
        skip_serializing_if = "Vec::is_empty")]
pub policy_cold_path_ns_hist: Vec<u64>,
#[serde(rename = "policy_cold_path_samples", default)]
pub policy_cold_path_samples: u64,
#[serde(rename = "policy_cold_path_sum_ns", default)]
pub policy_cold_path_sum_ns: u64,
```

`coordinator/status.rs::worker_runtime_snapshots()` fills the
new fields from `WorkerRuntimeAtomics` (Relaxed loads, mirroring
the existing pattern at status.rs:268-289).

### 4.4 Prometheus + Go-side mirror

`pkg/dataplane/userspace/protocol.go::WorkerRuntimeStatus`:
```go
PolicyColdPathNSHist  []uint64 `json:"policy_cold_path_ns_hist,omitempty"`
PolicyColdPathSamples uint64   `json:"policy_cold_path_samples,omitempty"`
PolicyColdPathSumNS   uint64   `json:"policy_cold_path_sum_ns,omitempty"`
```

`pkg/api/metrics_descriptors.go`: new `policyColdPathLatencyBucket`
descriptor (`xpf_userspace_worker_policy_decision_cold_path_ns_bucket`),
labels `worker_id, bucket_hi_ns`. Plus
`policyColdPathSamplesTotal` (counter,
`xpf_userspace_worker_policy_decision_cold_path_samples_total`)
and `policyColdPathSumNS` (counter,
`xpf_userspace_worker_policy_decision_cold_path_sum_ns_total`).

`pkg/api/metrics_userspace.go::emitWorkerRuntime`: emit the three
new metrics with `worker_id` label. Reuse `emitHistogram`
(metrics.go:326) but with a single `worker_id` label (current sig
takes `ifindexLabel, queueLabel`; add a sibling
`emitWorkerHistogram(ch, desc, hist, workerID)` rather than
overloading the 2-label sig).

### 4.5 Doc update — `docs/userspace-jit-design.md` Scale Target section

Currently no "Scale Target" section exists. Add one after the
"Motivation" section:

```markdown
## Scale Target (measured on loss userspace cluster)

Hardware: mlx5 SR-IOV VF passthrough, kernel 6.18+, AF_XDP
zero-copy, 6 worker threads on a 32-core host.

| Rules | Per-worker Mpps p50 | Aggregate Mpps | Per-packet ns p50 | Notes |
|-------|--------------------:|---------------:|------------------:|-------|
|    10 | TBD | TBD | TBD | linear scan trivial |
|   100 | TBD | TBD | TBD | linear scan still fast |
|  1000 | TBD | TBD | TBD | warm — first cliff candidate |
| 10000 | TBD | TBD | TBD | wire-protocol ceiling pre-#1606 |
| 100000 | N/A | N/A | N/A | blocked on #1606 (literal-CIDR ceiling) |
| 1M | N/A | N/A | N/A | blocked on #1606 |

Methodology: `test/incus/cold-path-microbench.sh --rules N`
on `loss:xpf-userspace-fw0`. iperf3 `-P 12 -l 64` against
`172.16.80.200`; per-worker Mpps from
`xpf_userspace_worker_policy_decision_cold_path_samples_total` rate;
per-packet ns from `_sum_ns_total / _samples_total` ratio
(arithmetic mean; histogram p50 / p99 also published per worker).

64 B note: iperf3 `-l 64` is the application-write size. With
TCP timestamp option the on-wire frame is ~130 B v4 / ~150 B v6.
The 64 B linerate ceiling per the issue's 49 Mpps derivation
requires pktgen-style synthetic packet generation; the iperf3
path measures the **policy-cold-path cost only**, which is the
actual quantity the #1605 JIT plan needs to budget against.
```

## 5. Public API preservation

- All existing `WorkerRuntimeStatus` fields preserved.
- All existing `WorkerRuntimeAtomics` / `WorkerRuntimeCounters`
  fields preserved.
- `evaluate_policy*` signatures unchanged — the timer wraps the
  call at the call site, not inside the function.
- `emitHistogram` signature unchanged — new
  `emitWorkerHistogram` added alongside.
- No Junos config schema changes.
- No HA / session-sync wire changes.

## 6. Hidden invariants the change must preserve

- **Hot path no-allocation rule**: the per-call timer is two
  `monotonic_nanos()` calls + one `bucket_index_for_ns` + 16
  AtomicU64 increments? No — increments are on
  `WorkerRuntimeCounters` (worker-local `[u64; 16]`), no atomic.
  Per-call overhead: 2 clock reads + 1 branchless bucket select +
  1 array store. ~50 ns including clock_gettime worst case.
  Cold path is already 100s of ns minimum, so <1 % overhead.
- **Publish atomicity**: cumulative counters don't need a seqlock
  — readers handle per-field tearing by treating each bucket as
  its own counter (Prometheus `rate()` is per-bucket anyway).
- **Backward compatibility**: all new fields use
  `#[serde(default)]` / `omitempty`; older daemons read zero.
- **HA sync portability**: no HA-touching code modified.
- **Counter overflow**: u64 at one sample per cold-path eval
  per worker, even at 5 Mpps cold-path-saturated, is ~117 years
  to wrap. Safe.
- **Histogram bucket alignment**: must reuse
  `DRAIN_HIST_BUCKETS` / `bucket_index_for_ns` so a future re-layout
  doesn't silently drift this counter against the others. Encoded
  by a `const _: () = assert!(POLICY_COLD_PATH_HIST_BUCKETS == DRAIN_HIST_BUCKETS);`.

## 7. Risk assessment

| Class | Severity | Reasoning |
|-------|----------|-----------|
| Behavioral regression | LOW | Timer wraps a function call; no logic change. The two call sites are already in the cold path. |
| Lifetime / borrow-checker | LOW | `WorkerRuntimeCounters` field add — pure data. |
| Performance regression | LOW (cold path) / NEEDS-MEASURE (counter overhead) | Two `monotonic_nanos()` + bucket index + array store per cold-path eval. Counter sites are 100s of ns minimum, but reviewers should demand the smoke matrix prove no regression. |
| Architectural mismatch | LOW-MED | Risk is the harness producing numbers nobody trusts (see §2 structural risks). Mitigated by the explicit pktgen-mode escape valve and the §4.5 wire-byte caveat. |

## 8. Test plan

- `cargo build --release` clean.
- `cargo test --release` — full 952+ suite passes; new tests added:
  - `userspace-dp/src/afxdp/worker_runtime_tests.rs::policy_cold_path_publish_round_trip` — push samples, publish, snapshot, verify histogram + sum + count match.
  - `userspace-dp/src/policy_tests.rs::cold_path_histogram_increments_in_poll_descriptor` (integration-style via a stub poll-descriptor harness) — deferred to round-2 if too tangled.
  - Go side: `pkg/api/metrics_test.go::TestEmitWorkerRuntime_PolicyColdPathHistogram` — drive a ProcessStatus with non-zero histogram, assert the right number of Prometheus samples emit.
- 5/5 flake check on `policy_cold_path_publish_round_trip`.
- Go suite `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` — 30 packages green.
- Deploy on loss userspace cluster, run Pass A + Pass B smoke matrix per SKILL.md.
- Run the new harness end-to-end at rules ∈ {10, 100, 1000, 10000}; populate the §4.5 Scale Target table with measured numbers.
- Sanity check: histogram p50 at rules=10 should be in single-digit microseconds; at rules=10000 it should be visibly larger.

## 9. Out of scope

- 100K / 1M rule sweeps — blocked on #1606 wire-protocol restructure.
- True 64 B linerate measurement — requires pktgen-style synthetic packet generation. The harness's `--pktgen` flag is a future-extension stub in this PR; the default iperf3 mode measures cold-path latency, not 64 B linerate. See §2 honest framing.
- JIT design itself — #1605 will re-plan after this + #1606 land.
- Address-book wire restructure — #1606.
- Per-rule-id histogram — too high cardinality for Prometheus; not in #1605's budget question. Aggregate per-worker is the unit of analysis.
- Per-zone-pair histogram — same cardinality reason.
- CoS interaction — orthogonal; the cold path is policy-only, not shaper-touching.

## 10. Open questions for adversarial review

1. **Is the iperf3 `-l 64` framing critique strong enough to PLAN-KILL the harness as designed?** If reviewers conclude that "iperf3 with 130 B wire frames" is not a credible 64 B microbench, the §4.5 doc text and harness output need to be reframed entirely. Alternative: ship the harness as "cold-path-cost microbench" with no 64 B claim, and defer 64 B linerate to a separate pktgen PR.
2. **CPU isolation discipline**: the loss userspace cluster's CPU affinity / IRQ pinning is documented where? Should the harness refuse to run if `/proc/interrupts` shows shared CPUs between workers and NIC IRQs, or just emit a warning?
3. **Cold-path saturation under TCP**: with `iperf3 -P 12` over TCP, the cold path is hit ~12 times per run (once per stream). Aggregate cold-path samples over 30 s = 12 — statistically meaningless. Either (a) the harness must use UDP `iperf3 -u` (no connection caching), or (b) the harness needs a synthetic UDP packet flooder that randomizes source ports per packet to defeat any session caching. Which is the right call?
4. **Histogram bucket layout**: the existing `DRAIN_HIST_BUCKETS=16` layout maxes at ~16 ms. Cold-path policy eval at 1M rules and linear scan could be >100 ms per packet — that saturates bucket 15 and the operator loses tail visibility. Should this counter use a wider bucket layout (e.g. 24 buckets to ~1 s)? Or accept saturation as the natural read-out of "this rule count is unworkable"?
5. **Counter overhead under warm flow-cache**: when the flow cache is hot and cold-path fires once per session install, the timer overhead is amortized to near zero per packet. But when cold-path fires on every packet (pktgen mode), the timer overhead becomes a measurement bias — the harness reports `latency + 2*clock_gettime`, not pure policy-eval latency. Should the harness subtract an empirical clock-gettime baseline before reporting?
6. **Wire-protocol scope**: this PR adds three fields to
   `WorkerRuntimeStatus` (Rust + Go). #1606 sub-agent is editing
   protocol.rs concurrently. File-zone disjointness is enforced
   by touching different structs (`WorkerRuntimeStatus` vs
   `AddressBookSnapshot` / `RuleSnapshot`) — verify this is actually
   true on master at the merge point.

## 11. Plan version log

- v1 — DRAFT initial submission, all 11 sections.
