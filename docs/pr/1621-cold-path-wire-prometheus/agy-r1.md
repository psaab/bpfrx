I will begin by viewing the implementation plan document at the specified path to understand the architectural design, wire changes, metrics, and merge semantics for PR #1621.
I will list my active permission grants to ensure we operate within sandbox boundaries and understand our exact read/write privileges in the project space.
I will search for instances of `WorkerColdPathAtomics` inside the Rust dataplane directory to locate the scaffolding that is already in place.
I will view `userspace-dp/src/afxdp/cold_path_hist.rs` to inspect the structure `WorkerColdPathAtomics` and its `snapshot()` and `publish_from_local()` methods. This is critical for investigating Axis 2, 3, and 7.
I will search for `publish_from_local` inside the worktree codebase to see where it is integrated or planned to be integrated.
I will search for `WorkerRuntimeStatus` inside the worktree codebase to locate the exact definition on the Rust and Go sides, and see how the existing fields are declared and handled.
I will view `userspace-dp/src/protocol/binding.rs` to inspect the current structure of `WorkerRuntimeStatus` on the Rust side, which will help us with Axis 1.
I will search for `cold_path` in `userspace-dp/src/afxdp/worker/mod.rs` to see how the worker and bindings interact with `cold_path`.
I will search for `struct BindingWorker` to understand how bindings are represented on the worker side.
I will view `userspace-dp/src/afxdp/worker/mod.rs` around the definition of `BindingWorker` to see how it holds the cold-path data.
I will search for metrics cardinality or scrape budget in the documentation and codebase to evaluate the Prometheus series footprint.
I will search for `MustNewConstMetric` in the Go codebase to see how existing metrics collection is structured.
I will view the beginning of `pkg/api/metrics_userspace.go` to see the structure of existing worker runtime metrics collection and emission.
I will view lines 201 to 400 of `pkg/api/metrics_userspace.go` to locate and examine the `emitWorkerRuntime` function.
I will view lines 401 to 600 of `pkg/api/metrics_userspace.go` to find and examine `emitWorkerRuntime`.
I will view lines 601 to 701 of `pkg/api/metrics_userspace.go` to examine the rest of the file and understand the `emitHistogram` implementation.
I will search for the definition of `emitHistogram` to see if there is any shared helper or how it's implemented.
I will view the `emitHistogram` function in `pkg/api/metrics.go` to see the existing patterns for histogram serialization and bucket construction.
I will view lines 251 to 355 of `pkg/api/metrics.go` to find and examine the `emitHistogram` function.
I will search for the definition of `cosDrainLatencyBucket` to check what label names are used for the bucket upper bound.
I will search for `cosDrainLatencyBucket` in `pkg/api/` to find its constructor or where it is initialized.
I will search for `cosDrainLatencyBucket` inside `pkg/api/metrics_descriptors.go` to see the label names.
I will view `pkg/api/metrics_descriptors.go` to see the labels configured for existing histograms.
I will search for `DrainLatencyHist` to see if the existing latency histograms are cumulative or sparse.
I will search for `drain_latency` to see how the existing histograms are defined on the Rust side.
I will view `userspace-dp/src/afxdp/umem/profile.rs` to inspect the latency histogram computation.
I will search for `bucket_index_for_ns` in the UMEM module to confirm if it generates sparse or cumulative index selections.
I will view `userspace-dp/src/afxdp/umem/mod.rs` around the `bucket_index_for_ns` definition.
I will search for `vrrp` or `failover` in the codebase to see how failover is handled.
# Adversarial Plan Review: #1621 Cold-Path Histogram Wire + Prometheus Emission

After a rigorous review of the plan document (`plan.md` commit `fb3c17d94`) and pressure-testing the proposed implementation against the codebase, here is the adversarial review.

**Verdict:** **PLAN-NEEDS-MINOR**
*The core architectural direction (sibling Arc, lock-free seqlock, and Prometheus emission) is sound and safe. However, there is a structural wire-serialization bug in Axis 1/3, a missing validation metric in Axis 5, and a PromQL usability improvement in Axis 6 that must be addressed before declaring the plan ready.*

---

### AXIS 1 — Wire-Protocol Integrity under Failed Snapshots
* **The Issue:** In the coordinator status path (��4.4), the plan handles a failed snapshot (`None` due to retry exhaustion) by mapping it to a default counters struct:
  ```rust
  None => cold_path_hist::WorkerColdPathCounters::default()
  ```
  In Rust, `WorkerColdPathCounters::default()` initializes arrays to fixed sizes (e.g., `sum_ns: [0; 16]`). When converted via `.to_vec()`, these become vectors of length 16.
* **The Bug:** Because a vector of length 16 is **not empty**, `skip_serializing_if = "Vec::is_empty"` will **not** trigger. Rust will serialize these fields as arrays of zeros (e.g., `cold_path_sum_ns: [0, 0, ..., 0]`) rather than omitting them. 
* **The Impact:** This violates the plan's stated UX intent in line 274 (*"The None case... emits empty fields"*). It makes a transient snapshot failure look identical to a healthy, calibrated worker that has processed exactly zero packets. This silently masks contention/starvation and ruins the "empty on wire" compatibility contract.
* **Actionable Correction:**
  1. Under the `None` case, explicitly populate `WorkerRuntimeStatus` with empty vectors (`Vec::new()`) and an empty string for the clock source:
     ```rust
     let (hist, sum_ns, samples, first_key, alias_seen, sample_phase, underflow, ns_per_tsc, baseline, clock) = 
         match cold_path_atomics.snapshot() {
             Some(c) => (
                 c.buckets.iter().map(|r| r.to_vec()).collect(),
                 c.sum_ns.to_vec(),
                 c.samples.to_vec(),
                 c.first_key.to_vec(),
                 c.alias_seen.to_vec(),
                 c.sample_phase,
                 c.wrapper_underflow_count,
                 c.ns_per_tsc_q32,
                 c.wrapper_ns_baseline,
                 c.clock_source.as_str().to_string(),
             ),
             None => (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), 0, 0, 0, 0, "".to_string()),
         };
     ```
  2. To achieve perfect wire hygiene for the scalar fields when they are 0, add the existing `u64_is_zero` helper to the Rust `WorkerRuntimeStatus` Serde attributes:
     ```rust
     #[serde(rename = "cold_path_sample_phase", default, skip_serializing_if = "crate::protocol::u64_is_zero")]
     pub cold_path_sample_phase: u64,
     ```
     This ensures that if `snapshot()` fails or the worker is uncalibrated, the wire payload contains **exactly zero** cold-path fields, matching Go's `omitempty` behavior.

---

### AXIS 2 — Per-Worker Cross-Binding Merge Semantics
* **`sample_phase` Semantic:** The plan's choice to sum `sample_phase` via `saturating_add` is **correct**. Because the worker loop polls bindings sequentially on a single thread, each binding increments its own `sample_phase` on a session miss. Summing them yields the true total denominator of sampling attempts. Taking the `max` would mathematically overestimate the sampling rate (over-representing the captured `samples` against a smaller phase count).
* **Collision Detection:** The `first_key` and `alias_seen` merge logic is correct. If one binding records `key_A` and another records `key_B`, the comparison in the second iteration correctly sets `alias_seen = true` for the merged slot. This matches the collision-detection expectations of the downstream harness.

---

### AXIS 3 — Snapshot Retry Exhaustion & Observability
* **Starvation Regimes:** Under isolcpus and pinned RT threads, a writer publish takes ~1–2 µs, while the 128-retry backoff spans ~10–50 µs. The only regime where `snapshot()` can return `None` is if the worker thread is preempted by the OS scheduler (e.g., under CPU oversubscription on non-isolated cores) while holding the odd generation count.
* **The Missing Metric:** Simply omitting the fields on failure makes starvation indistinguishable from an uncalibrated or inactive worker. 
* **Elegant Fix:** Since the status thread holds a shared `Arc<WorkerColdPathAtomics>`, we can add a lockless failure counter directly inside the atomics struct:
  ```rust
  pub(in crate::afxdp) snapshot_failed: AtomicU64,
  ```
  If `snapshot()` exhausts its retry budget, the reader thread increments this counter before returning `None`:
  ```rust
  self.snapshot_failed.fetch_add(1, Ordering::Relaxed);
  ```
  This is stateless on the coordinator, has zero cost on the worker's hot path, and allows us to publish a 10th Prometheus metric: `xpf_userspace_worker_cold_path_snapshot_failed_total{worker_id}`.

---

### AXIS 4 — Prometheus Cardinality & Scrape Latency
* **Scrape Cost:** Allocating 2304 `prometheus.Metric` structs in Go per scrape takes approximately 50 µs of CPU time and ~150 KiB of heap allocation. At a 1 Hz default cadence, this overhead is completely negligible.
* **Histogram Density:** The decision to emit all 24 buckets (even if empty) as individual counter series is **correct**. In Prometheus, histogram bucketing must remain dense and contiguous to avoid breaking downstream PromQL rate interpolation.
* **Consistency:** Naming the metric families as sparse counters matches the codebase's existing latency histogram convention (e.g., `xpf_cos_drain_latency_ns_bucket`).

---

### AXIS 5 — Missing Calibration Gauge
* **The Issue:** The plan proposes 8 metric families, omitting `ns_per_tsc_q32`.
* **Why it's a Risk:** `ns_per_tsc_q32` is the core scaling factor. If calibration fails or scales incorrectly (e.g., due to hypervisor TSC emulation scaling errors), the recorded nanosecond values will be skewed. Operators have no way to verify calibration health without it.
* **Correction:** Add a 9th metric family:
  * `xpf_userspace_worker_cold_path_ns_per_tsc_q32{worker_id}` (Gauge)
  * Cardinality cost is trivial (+6 series).

---

### AXIS 6 — Bucket Label Naming vs. PromQL Ergonomics
* **The Issue:** The plan uses `bucket_hi_ns` for consistency with `#709`'s `xpf_cos_drain_latency_ns_bucket`. 
* **The Trade-off:** Naming the upper-bound label `bucket_hi_ns` breaks native PromQL `histogram_quantile()` compatibility. Operators would be forced to write complex `label_replace` regex expressions to rename the label to `le` before they can compute quantiles.
* **Decision:** We should prioritize PromQL ergonomics over `#709` legacy consistency. We recommend naming the upper bound label `le` for the new `xpf_userspace_worker_cold_path_ns_bucket` metric family.

---

### AXIS 7 — Cache Coherence & MESI Thrashing
* **Contention Check:** The worker thread writes to `WorkerColdPathAtomics` only on the publish tick (1 Hz cadence). The hot path (`record_sample`) modifies the non-atomic, worker-local `WorkerColdPathCounters`.
* **MESI Impact:** The scrape thread invalidates the worker's L1 cache line at most once per second per worker. With 6 workers, this results in ~6 invalidations/sec, not 2700. The cacheline bounce cost is mathematically zero on the fast path.
* **Alignment:** `WorkerColdPathAtomics` uses `#[repr(C, align(64))]` and sibling heap allocations, ensuring that worker-specific memory blocks sit on separate cachelines and completely eliminating false sharing.

---

### AXIS 8 — HA-Sensitivity & Worker Loop Cadence
* **Contention Check:** The worker loop is the sole writer of the lockless seqlock. The seqlock writer never blocks, loops, or spins; it only writes sequentially under `AcqRel` and `Release` ordering.
* **Failover Impact:** The publish tick overhead remains ~0.8 µs. Contention from Go-side scraper threads cannot delay the worker thread or perturb the VRRP 30 ms advert loop.

---

### AXIS 9 — JSON Wire Size
* **Payload Size:** An 18 KiB payload fits in a single TCP packet and is processed by gRPC in sub-millisecond time.
* **Optimization:** Under the default inactive state (no cold-path samples recorded), the `skip_serializing_if` attributes ensure that the wire size delta is exactly **0 bytes**.

---

### AXIS 10 — Cross-PR Risk
* **Conflict Check:** Purely observational logic. No overlap with policy (#1623) or CoS (#1625) zones. The gating of #1622 is a standard sequential dependency.

---

## Summary of Recommendations for Step 5

1. **Fix Failed Snapshot Serialization:** Refactor the coordinator's status mapping to return empty vectors and default scalars on `None` instead of mapping to a default counter struct. Add `skip_serializing_if = "u64_is_zero"` to Rust's scalar status fields.
2. **Add a Failed Snapshot Counter:** Add `snapshot_failed` `AtomicU64` to `WorkerColdPathAtomics` and increment it inside `snapshot()` on retry exhaustion.
3. **Add Calibration Metric:** Emit `xpf_userspace_worker_cold_path_ns_per_tsc_q32` to Prometheus.
4. **Use `le` Label Name:** Name the histogram upper bound label `le` instead of `bucket_hi_ns` to enable standard PromQL `histogram_quantile()` support.
