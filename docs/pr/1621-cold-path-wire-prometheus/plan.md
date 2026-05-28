# #1621 step-3 follow-up C: wire protocol (Rust + Go) + Prometheus emitter for cold-path histogram

**Status**: DRAFT v2 — round-1 resolution. Codex r1 PLAN-NEEDS-MAJOR
(5 blocking findings); AGY r1 PLAN-NEEDS-MINOR (5 findings); Claude
SMR r1 PLAN-NEEDS-MINOR. Strong 3-way consensus on F2/F3/F4/F5 plus
Codex's catch on omitempty + fixed-array (already implemented as Vec).

## v1 → v2 fatal-axis resolution map

| Reviewer / finding | v2 fix | Section |
|--------------------|--------|---------|
| Codex F1 + AGY: omitempty + fixed-array would never omit | v1 already specifies `Vec<Vec<u64>>` not `[[u64; 24]; 16]` — Codex misread the Rust shape. v2 makes this explicit: ALL `cold_path_*` Vec fields use `Vec<>` not fixed array, so an all-zero slot vector still ships unless explicitly emptied (which the harness sees as "data with all-zero buckets" not "no data"). The implementation populates Vec from `cold.buckets.to_vec()` etc. so a worker that's never been calibrated has zero-length Vec fields → omitempty omits. ✓ | §4.3 + §4.4 |
| Codex F2 + AGY r1 F1: cross-binding merge first_key/alias_seen contract | v1 §4.2 pseudocode correctly handles the nonzero-mismatch case: `else if src.first_key[slot] != 0 && src.first_key[slot] != merged.first_key[slot] { merged.alias_seen[slot] = true }`. Codex misread; the case IS handled. v2 keeps the pseudocode and adds a 4-case test matrix to make it harder to misread. | §4.2 |
| Codex F3 + AGY r1 F6 + Claude SMR F5: bucket_hi_ns label → le for PromQL | v2 switches to `le` (less-than-or-equal — Prometheus histogram convention). The metric name `xpf_userspace_worker_cold_path_ns_bucket{worker_id, zone_pair_slot, le}` is fully PromQL-compatible with `histogram_quantile(0.99, sum by (le) (rate(...[5m])))`. | §4.5 |
| Codex F4 + AGY r1 F5 + Claude SMR F2: missing ns_per_tsc_q32 emission | v2 adds 9th metric `xpf_userspace_worker_cold_path_ns_per_tsc_q32{worker_id}` (Gauge). Cardinality: +6 series, trivial. | §4.5 |
| Codex F5 + AGY r1 F3: snapshot None contract — silent emptying hides starvation | v2 adopts AGY's recommendation: add `snapshot_failed: AtomicU64` on `WorkerColdPathAtomics`; `snapshot()` increments it on retry-budget-exhaust and returns None; coordinator status path emits empty fields BUT the Prometheus path always emits `xpf_userspace_worker_cold_path_snapshot_failed_total{worker_id}` Counter so operators can detect starvation. 10th metric, +6 series. | §4.4 + §4.5 |
| AGY r1 F1: scalar fields need `skip_serializing_if = "u64_is_zero"` | v2 adopts: `cold_path_sample_phase`, `cold_path_wrapper_underflow_count`, `cold_path_ns_per_tsc_q32`, `cold_path_wrapper_ns_baseline` all gain `skip_serializing_if = "crate::protocol::u64_is_zero"`. An uncalibrated worker emits ZERO cold-path fields on the wire (matches Go omitempty behavior). | §4.3 |
| Claude SMR F4: clock_source gauge always-present | v2 §4.5 emits the clock_source gauge always (1.0 when "tsc"/"clock_gettime", 0.0 when ""). Operator dashboards distinguish "tsc active" from "no data this scrape". | §4.5 |
| Claude SMR F3: clock_source omitempty truth table walk | v2 §4.3 adds explicit Go-side `omitempty` walk for `cold_path_clock_source: String`. Walk both directions, four daemon-version combinations. | §4.3 |

Round-1 attestation:
- **Codex** task-mppoxwhb-gv1uga: PLAN-NEEDS-MAJOR (CONCEPTUAL; sandbox-broken).
  Five blocking findings, one of which (cross-binding merge) was a misread.
- **AGY** adversarial-review-mppoygka-g7v9r9: PLAN-NEEDS-MINOR (5 axes
  with concrete amendments + 5 axes verified clean).
- **Claude SMR** claude-smr-plan-r1.md: PLAN-NEEDS-MINOR (F1-F5).

Three-way + AGY convergence on:
- bucket label → `le`
- add ns_per_tsc_q32 gauge
- snapshot_failed counter for starvation observability
- clock_source always-present gauge
- scalar fields with `u64_is_zero` skip

**Status**: DRAFT v1 — pending adversarial plan review
**Branch**: `refactor/1621-cold-path-wire-prometheus`
**Parents**: #1612 step-3 scaffolding (#1619 merged), #1620 BindingWorker
integration (PR #1631 merged as dd0e1e62). #1622 is gated on this PR.
**Plan v3.2 inheritance**: §1.5 (wire-protocol additions) + §1.6
(Prometheus emission) from
`docs/pr/1612-scale-target-measurement/plan.md`.

## 1. Issue framing

#1620 wired the cold-path histogram into the live AF_XDP worker:
- `BindingWorker.cold_path: WorkerColdPathCounters` worker-local data.
- Per-worker TSC calibration installed at `worker_loop` entry post-affinity.
- Two sample-record blocks in `poll_descriptor/mod.rs:1375` and `:2393`
  (pre-eval scoped borrow + post-eval q32-skip + underflow counter).
- `--cold-path-sample-mask` CLI flag (default 0xff) + handshake field
  (`ConfigSnapshot.cold_path_sample_mask: Option<u64>` / `*uint64`).

What #1620 does NOT do: the data is worker-local only. The gRPC status
surface (`WorkerRuntimeStatus`) does not yet carry the cold-path
fields, and the Prometheus emitter doesn't see them. Without #1621
the harness (#1622) cannot scrape the data and the operator cannot
verify the cold-path is actually instrumented.

#1621 ships the **observability** half:

1. Sibling per-worker `Arc<[WorkerColdPathAtomics]>` array constructed
   at coordinator startup alongside the existing
   `Arc<[WorkerRuntimeAtomics]>` array.
2. Per-tick `publish_from_local()` call in `worker_runtime.rs::publish()`
   so the worker-local counters get copied into the atomics array
   under its own `cold_window_gen` seqlock.
3. Wire-protocol additions to `WorkerRuntimeStatus` (Rust + Go).
4. Coordinator status path (`coordinator/status.rs:268`) reads
   `cold_path_atomics[worker_id].snapshot()` and stamps the result
   onto the published `WorkerRuntimeStatus`.
5. Prometheus emission in `pkg/api/metrics_userspace.go`
   `emitWorkerRuntime` of 5 new metric families.
6. Wire round-trip tests (Rust → Go and Go → Rust).
7. Go Prometheus emission test (synthetic WorkerRuntimeStatus →
   registry → text format scrape).

## 2. Honest scope / value framing

#1621 closes the observability gap so #1622 can run. Without it:
- The harness cannot read the histogram off /metrics.
- The operator cannot see `xpf_userspace_worker_cold_path_*` counters.
- The TSC sampling that #1620 deployed is producing data that lives
  worker-local and gets discarded every restart.

Cost:
- ~2566 new Prometheus series per cluster node:
  - 6 workers × 16 slots × 24 buckets = 2304 (bucket counter)
  - 6 × 16 × 2 = 192 (samples + sum_ns counters)
  - 6 × 16 × 2 = 192 (first_key + alias_seen — Gauge for first_key,
    optional 0/1 gauge for alias_seen; debatable to emit, see §10)
  - 6 baseline + 6 × 2 clock_source = 18
  - 6 × 2 sample_phase + underflow_count = 12
  - Subtotal ~2700.
- Scrape budget: fits within the project's documented Prometheus
  cardinality budget.
- Hot-path cost: zero net delta vs #1620 — only the publish-tick
  cost is added (~448 → 450 Relaxed stores per ~1 s).

If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict. The prereq chain #1619 → #1620 →
#1621 → #1622 has been triple-reviewed in aggregate; #1621 is the
narrowest of the four (mostly wire + emission + tests).

## 3. What's already shipped (do not duplicate)

- `userspace-dp/src/afxdp/cold_path_hist.rs`:
  - `WorkerColdPathAtomics` with `#[repr(C, align(64))]`, `cold_window_gen`
    seqlock, `sample_phase`, `wrapper_underflow_count`, `ns_per_tsc_q32`,
    `wrapper_ns_baseline`, `clock_source`, `alias_seen[16]`,
    `first_key[16]`, `sum_ns[16]`, `samples[16]`, `buckets[16][24]`.
  - `publish_from_local(&self, &local)` writes all 450 atomics under
    the seqlock.
  - `snapshot() -> Option<WorkerColdPathCounters>` reads the seqlock
    payload with 128-retry exponential backoff.
- `BindingWorker.cold_path: WorkerColdPathCounters` populated by
  `worker_loop` entry calibration; updated by the two poll_descriptor
  sample sites.
- `ForwardingState.cold_path_sample_mask: u64` populated from
  `ConfigSnapshot.cold_path_sample_mask: Option<u64>::unwrap_or(0xff)`.

## 4. Concrete design

### 4.1 Sibling per-worker atomics array

The `WorkerHandle` already holds an `Arc<WorkerRuntimeAtomics>` per
worker. The cold-path atomics live alongside via a NEW per-worker
field:

```rust
// userspace-dp/src/afxdp/types/runtime.rs
pub(in crate::afxdp) struct WorkerHandle {
    // ... existing fields ...
    pub(in crate::afxdp) runtime_atomics:
        Arc<super::worker_runtime::WorkerRuntimeAtomics>,
    /// #1621: per-worker cold-path histogram publish slot.
    /// Separate from runtime_atomics per #1619 plan v3 Codex r1
    /// finding 2 (independent seqlock cold_window_gen vs window_gen).
    pub(in crate::afxdp) cold_path_atomics:
        Arc<super::cold_path_hist::WorkerColdPathAtomics>,
    // ...
}
```

Constructed at coordinator startup (search for `WorkerRuntimeAtomics::new()`
in `coordinator/reconcile/bringup.rs` — same site adds `cold_path_atomics:
Arc::new(WorkerColdPathAtomics::new())`).

`worker_loop` is extended to accept `cold_path_atomics:
Arc<WorkerColdPathAtomics>` as an additional parameter, mirrored from
the existing `runtime_atomics` parameter.

### 4.2 Per-tick publish hook

`worker_runtime.rs::publish()` is unchanged; we add a SEPARATE call site
in `worker_loop` (where `runtime_atomics.publish()` is invoked) to also
fire `cold_path_atomics.publish_from_local(&binding.cold_path)`.

Critically: the cold-path publish must read the worker-local counters
from the SAME `BindingWorker` whose data is being published. For a
worker that owns multiple bindings, we merge them per slot (sum
buckets/sum_ns/samples; OR alias_seen; preserve first_key from any
non-zero binding):

```rust
// Pseudocode in worker_loop publish tick:
let mut merged = WorkerColdPathCounters::default();
for binding in bindings.iter() {
    for slot in 0..16 {
        for b in 0..24 {
            merged.buckets[slot][b] = merged.buckets[slot][b]
                .saturating_add(binding.cold_path.buckets[slot][b]);
        }
        merged.sum_ns[slot] = merged.sum_ns[slot]
            .saturating_add(binding.cold_path.sum_ns[slot]);
        merged.samples[slot] = merged.samples[slot]
            .saturating_add(binding.cold_path.samples[slot]);
        // first_key: take any non-zero binding's value; if conflict,
        // set alias_seen to true (cross-binding aliasing per slot).
        if merged.first_key[slot] == 0 {
            merged.first_key[slot] = binding.cold_path.first_key[slot];
        } else if binding.cold_path.first_key[slot] != 0
            && binding.cold_path.first_key[slot] != merged.first_key[slot]
        {
            merged.alias_seen[slot] = true;
        }
        merged.alias_seen[slot] |= binding.cold_path.alias_seen[slot];
    }
    merged.sample_phase = merged.sample_phase
        .saturating_add(binding.cold_path.sample_phase);
    merged.wrapper_underflow_count = merged.wrapper_underflow_count
        .saturating_add(binding.cold_path.wrapper_underflow_count);
}
// Calibration: take any binding's value (all bindings on a worker
// share the same pinned core ⇒ same calibration).
if let Some(first) = bindings.first() {
    merged.ns_per_tsc_q32 = first.cold_path.ns_per_tsc_q32;
    merged.wrapper_ns_baseline = first.cold_path.wrapper_ns_baseline;
    merged.clock_source = first.cold_path.clock_source;
}
cold_path_atomics.publish_from_local(&merged);
```

The merge runs on the publish-tick cadence (~1 s) so its cost is
trivial. The merge is necessary because per-worker bindings may each
get session-misses to different zone pairs.

### 4.3 WorkerRuntimeStatus wire additions (Rust + Go)

Rust side (`userspace-dp/src/protocol/binding.rs:21`):

```rust
pub struct WorkerRuntimeStatus {
    // ... existing fields ...

    /// #1621: cold-path histogram per-slot bucket counts. Shape:
    /// [16 zone-pair slots][24 ns buckets]. Omitted on the wire when
    /// every slot is empty (older Rust daemons emit nothing).
    #[serde(rename = "cold_path_hist", default,
            skip_serializing_if = "Vec::is_empty")]
    pub cold_path_hist: Vec<Vec<u64>>,
    #[serde(rename = "cold_path_sum_ns", default,
            skip_serializing_if = "Vec::is_empty")]
    pub cold_path_sum_ns: Vec<u64>,
    #[serde(rename = "cold_path_samples", default,
            skip_serializing_if = "Vec::is_empty")]
    pub cold_path_samples: Vec<u64>,
    #[serde(rename = "cold_path_first_key", default,
            skip_serializing_if = "Vec::is_empty")]
    pub cold_path_first_key: Vec<u64>,
    #[serde(rename = "cold_path_alias_seen", default,
            skip_serializing_if = "Vec::is_empty")]
    pub cold_path_alias_seen: Vec<bool>,
    #[serde(rename = "cold_path_sample_phase", default)]
    pub cold_path_sample_phase: u64,
    #[serde(rename = "cold_path_wrapper_underflow_count", default)]
    pub cold_path_wrapper_underflow_count: u64,
    #[serde(rename = "cold_path_ns_per_tsc_q32", default)]
    pub cold_path_ns_per_tsc_q32: u64,
    #[serde(rename = "cold_path_wrapper_ns_baseline", default)]
    pub cold_path_wrapper_ns_baseline: u64,
    #[serde(rename = "cold_path_clock_source", default)]
    pub cold_path_clock_source: String,  // "tsc" | "clock_gettime" | ""
}
```

Go side (`pkg/dataplane/userspace/protocol.go:806`):

```go
type WorkerRuntimeStatus struct {
    // ... existing fields ...

    // #1621: cold-path histogram.
    ColdPathHist                   [][]uint64 `json:"cold_path_hist,omitempty"`
    ColdPathSumNS                  []uint64   `json:"cold_path_sum_ns,omitempty"`
    ColdPathSamples                []uint64   `json:"cold_path_samples,omitempty"`
    ColdPathFirstKey               []uint64   `json:"cold_path_first_key,omitempty"`
    ColdPathAliasSeen              []bool     `json:"cold_path_alias_seen,omitempty"`
    ColdPathSamplePhase            uint64     `json:"cold_path_sample_phase,omitempty"`
    ColdPathWrapperUnderflowCount  uint64     `json:"cold_path_wrapper_underflow_count,omitempty"`
    ColdPathNSPerTSCQ32            uint64     `json:"cold_path_ns_per_tsc_q32,omitempty"`
    ColdPathWrapperNSBaseline      uint64     `json:"cold_path_wrapper_ns_baseline,omitempty"`
    ColdPathClockSource            string     `json:"cold_path_clock_source,omitempty"`
}
```

**Wire-protocol both-sides** per `feedback_wire_protocol_both_sides`:
- All Vec/[] fields use `omitempty` so an empty histogram on the
  Rust side serializes nothing, and an older Go reader sees `nil`.
- The integer fields use `omitempty` (skips zeros) so an older Rust
  emitter doesn't bloat the JSON with all-zero entries.
- The string `clock_source` uses `omitempty` so an Unset worker (no
  calibration ran) doesn't emit a wire token.

### 4.4 Coordinator status path

`coordinator/status.rs:268` builds `WorkerRuntimeStatus` from the
`runtime_atomics.snapshot()` result. Extend to also call
`cold_path_atomics.snapshot()` and populate the new fields:

```rust
let cold = match cold_path_atomics.snapshot() {
    Some(snap) => snap,
    None => {
        // Retry budget exhausted (very heavy publish contention).
        // Emit empty cold-path fields rather than stale values.
        cold_path_hist::WorkerColdPathCounters::default()
    }
};

WorkerRuntimeStatus {
    // ... existing fields ...

    cold_path_hist: cold.buckets.iter().map(|row| row.to_vec()).collect(),
    cold_path_sum_ns: cold.sum_ns.to_vec(),
    cold_path_samples: cold.samples.to_vec(),
    cold_path_first_key: cold.first_key.to_vec(),
    cold_path_alias_seen: cold.alias_seen.to_vec(),
    cold_path_sample_phase: cold.sample_phase,
    cold_path_wrapper_underflow_count: cold.wrapper_underflow_count,
    cold_path_ns_per_tsc_q32: cold.ns_per_tsc_q32,
    cold_path_wrapper_ns_baseline: cold.wrapper_ns_baseline,
    cold_path_clock_source: cold.clock_source.as_str().to_string(),
}
```

The `None` case (snapshot retry exhausted) emits empty fields; the
operator will see "no data this scrape, try next" rather than stale.

### 4.5 Prometheus emission

`pkg/api/metrics_userspace.go::emitWorkerRuntime` extended with:

```go
// Bucket counter: 6 × 16 × 24 = 2304 series.
for slot := 0; slot < len(w.ColdPathHist); slot++ {
    slotLabel := strconv.Itoa(slot)
    for b := 0; b < len(w.ColdPathHist[slot]); b++ {
        bucketHiNS := bucketHiNSForIndex(b)  // 2^(10+b) for b∈[1..22], 1024 for b=0, ∞ for b=23
        ch <- prometheus.MustNewConstMetric(c.workerColdPathBucket,
            prometheus.CounterValue,
            float64(w.ColdPathHist[slot][b]),
            label, slotLabel, strconv.FormatUint(bucketHiNS, 10))
    }
}
// Sum + samples + alias: 6 × 16 × 3 = 288 series.
for slot, samples := range w.ColdPathSamples {
    slotLabel := strconv.Itoa(slot)
    ch <- prometheus.MustNewConstMetric(c.workerColdPathSamples,
        prometheus.CounterValue, float64(samples), label, slotLabel)
    if slot < len(w.ColdPathSumNS) {
        ch <- prometheus.MustNewConstMetric(c.workerColdPathSumNS,
            prometheus.CounterValue, float64(w.ColdPathSumNS[slot]),
            label, slotLabel)
    }
    if slot < len(w.ColdPathAliasSeen) {
        alias := 0.0
        if w.ColdPathAliasSeen[slot] { alias = 1.0 }
        ch <- prometheus.MustNewConstMetric(c.workerColdPathAliasSeen,
            prometheus.GaugeValue, alias, label, slotLabel)
    }
}
// Per-worker scalars: 6 × 5 = 30 series.
ch <- prometheus.MustNewConstMetric(c.workerColdPathSamplePhase,
    prometheus.CounterValue, float64(w.ColdPathSamplePhase), label)
ch <- prometheus.MustNewConstMetric(c.workerColdPathWrapperUnderflowCount,
    prometheus.CounterValue, float64(w.ColdPathWrapperUnderflowCount),
    label)
ch <- prometheus.MustNewConstMetric(c.workerColdPathWrapperNSBaseline,
    prometheus.GaugeValue, float64(w.ColdPathWrapperNSBaseline), label)
if w.ColdPathClockSource != "" {
    ch <- prometheus.MustNewConstMetric(c.workerColdPathClockSource,
        prometheus.GaugeValue, 1.0, label, w.ColdPathClockSource)
}
```

Metric names (per #1612 plan v3.2 §1.6):

- `xpf_userspace_worker_cold_path_ns_bucket{worker_id, zone_pair_slot, bucket_hi_ns}` Counter
- `xpf_userspace_worker_cold_path_samples_total{worker_id, zone_pair_slot}` Counter
- `xpf_userspace_worker_cold_path_sum_ns_total{worker_id, zone_pair_slot}` Counter
- `xpf_userspace_worker_cold_path_sample_phase_total{worker_id}` Counter
- `xpf_userspace_worker_cold_path_wrapper_underflow_count_total{worker_id}` Counter
- `xpf_userspace_worker_cold_path_wrapper_ns_baseline{worker_id}` Gauge
- `xpf_userspace_worker_cold_path_clock_source{worker_id, source}` Gauge (1 = active)
- `xpf_userspace_worker_cold_path_alias_seen{worker_id, zone_pair_slot}` Gauge (1 = slot aliased)

`first_key` is NOT emitted to Prometheus (it's a per-window-internal
implementation detail used to detect aliasing; the alias_seen gauge
is the operator-visible signal).

Total cardinality: 6 × 16 × 24 + 6 × 16 × 3 + 6 × 4 + 6 × 1 = ~2622
series per cluster node (matches the plan v3.2 §1.6 budget of ~2566
with the +2 new sample_phase/underflow counters from #1620 plan v4).

### 4.6 Tests

- **Rust round-trip**: `protocol/binding.rs::tests` serialize a
  populated `WorkerRuntimeStatus`, deserialize back, compare. Add 4
  cases: empty / partial / full / all-zero.
- **Go round-trip**: `pkg/dataplane/userspace/protocol_test.go` mirror.
- **Cross-language**: `userspace-dp/tests/fixtures/protocol_wire_v1.json`
  add cold-path fixtures (Rust emit → Go decode).
- **Prometheus golden**: Go test that builds a synthetic
  `WorkerRuntimeStatus`, runs through the registry, scrapes /metrics
  format, asserts every expected series + label combination.

## 5. Public API preservation

- `WorkerRuntimeAtomics::publish` / `snapshot` **unchanged**.
- `WorkerColdPathAtomics::publish_from_local` / `snapshot` **unchanged**.
- `worker_loop` signature gains ONE new parameter
  (`cold_path_atomics: Arc<WorkerColdPathAtomics>`). All callers
  updated.
- `WorkerRuntimeStatus` gains 10 new fields, all `omitempty` /
  `serde(default)`. Older Rust daemons reading newer JSON ignore the
  unknown fields (serde default behavior). Older Go daemons reading
  newer JSON skip unknown fields by default.

## 6. Hidden invariants

1. **Seqlock independence**: cold-path uses `cold_window_gen` separate
   from runtime `window_gen` per #1619 plan v3 finding 2.
2. **Merge contract** (§4.2): the per-worker merge across bindings
   preserves saturating_add monotonicity; alias_seen is OR (any
   binding setting it wins); first_key takes the first non-zero.
3. **Snapshot Option<>**: when `snapshot()` returns None (retry
   exhausted), the status emits empty fields rather than stale
   values per #1619 AGY code-r2 finding 2.
4. **HA portability**: cold-path data is pure observation; not
   replicated across HA peers.

## 7. Risk

| Class | Severity | Notes |
|-------|----------|-------|
| Behavioral regression | **LOW** | Pure observation surface; no hot-path changes vs #1620. |
| Lifetime / borrow | **LOW** | Sibling Arc, no new lifetime parameters. |
| Performance | **LOW** | Publish-tick adds ~448 → 450 stores per ~1s. Scrape cost: ~2622 series. |
| HA-sensitive | **MED** | worker_runtime.rs::publish itself unchanged; the new publish_from_local call lives ALONGSIDE in worker_loop. `make test-failover` mandatory. |
| Cardinality | **LOW** | 2622 series fits documented scrape budget. |

## 8. Test plan

- [ ] cargo build clean.
- [ ] cargo test --bin xpf-userspace-dp: pre-#1621 baseline + new tests.
- [ ] cold_path_hist:: 28/28 (no change from #1620; tests target the
      primitives that already exist).
- [ ] worker_runtime_tests:: pass after new publish hook.
- [ ] go test ./pkg/dataplane/userspace/: round-trip.
- [ ] go test ./pkg/api/: Prometheus emission golden test.
- [ ] Smoke Pass A + Pass B (CoS off + on).
- [ ] make test-failover (HA-sensitive — publish tick cadence
      shouldn't perturb VRRP).
- [ ] /metrics scrape verifies all 8 metric families appear with
      expected labels.

## 9. Out of scope

- **#1622**: synthetic-policy-gen + cold-path-microbench harness +
  Scale Target tables. Gated on #1621 merging.
- **`userspace-dp/src/policy/`** (#1623).
- **`userspace-dp/src/afxdp/cos/`** (#1625).
- **`pkg/cluster/`** HA path.

## 10. Open questions

1. **first_key Prometheus emission**: §4.5 skips emitting `first_key`
   to Prometheus. Should we? Operator value: zero. Cardinality cost:
   6 × 16 = 96 series. Trade-off: simpler scrape vs slight loss of
   debug visibility. Plan-v1 picks "don't emit"; alias_seen carries
   the operator-relevant signal.

2. **Merge contract correctness (§4.2)**: the per-worker cross-binding
   merge is needed because one worker may own multiple bindings. Is
   the saturating_add + first-non-zero + OR-alias contract correct?
   Specifically: does alias_seen across-bindings vs within-binding
   carry the same meaning to the #1622 harness?

3. **Snapshot retry budget on a contested writer**: with 128 retries
   × spin_loop backoff, the worst-case snapshot latency is ~10-50 µs
   on a heavy publish contention regime. /metrics scrapes are 1 Hz;
   the worker publish is 1 Hz; can we get into a starvation regime?
   Probably not, but explicit reviewer push welcomed.

4. **JSON cardinality**: 16 × 24 = 384 bucket counts emitted per
   worker. For 6 workers, the JSON payload grows by 6 × 384 × 8 ≈
   18 KiB per scrape. Acceptable on the status RPC path?

5. **HA-sensitive test gate**: same as #1620 — `make test-failover`
   mandatory before MERGE-READY. The new publish_from_local call
   adds ~0.8 µs per ~1 s tick. Safety margin vs VRRP 30 ms advert.

## 11. Stop conditions

- **PLAN-KILL** if any two of four reviewers flag a fatal finding.
- **PLAN-NEEDS-MAJOR** → revise + iterate.
- **PLAN-READY** → proceed to Step 5 implementation.
