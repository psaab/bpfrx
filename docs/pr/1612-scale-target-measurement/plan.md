# #1612 step-3: cold-path counter wiring + harness + Scale Target table population

**Branch**: `perf/1612-scale-target-measurement`
**Worktree**: `/home/ps/git/bpfrx/.claude/worktrees/1612-scale-target-measurement`
**Plan version**: v3.2 (2026-05-28) — v3 addressed Codex plan-r2
PLAN-NEEDS-MAJOR findings (env override mechanism, sample-phase
monotonicity, alias detector strengthening); v3.1/v3.2 fold Codex
code-r1/r2 findings on the scaffolding (packed-key injectivity,
TSC fence positioning, /proc/cpuinfo token vs substring grep) and
AGY adversarial code-r1 findings (cross-worker false-negative
contract, RDTSCP CPUID probe). v1/v2/v3 archived in git history
of this branch.

**Parent plan**: `docs/pr/1607-hw-ceiling-microbench/plan.md` v2-r4 (4 review
rounds, AGY + Claude SMR + Copilot READY; Codex deterministically infra-blocked
across 5 dispatches). This step-3 PR is the implementation half of §4.3 –
§4.7 of that plan plus the measurement run that populates §4.6 Tables A1/A2/B1/B2.
This plan inherits the parent's measurement strategy and contract verbatim and
documents only the deltas/scope-narrowing decisions for the step-3 implementation
slice and the empirical measurement run.

## v1 → v2 fatal-axis resolution map (Codex r1)

| Codex r1 finding | v1 source | v2 fix | Section |
|------------------|-----------|--------|---------|
| HIGH: bounded-mode 1-in-256 violates parent contract | v1 §1.3 | Sample rate becomes regime-conditional: `unbounded → 0xff` (1-in-256); `bounded → 0` (1-in-1). | §1.3 |
| HIGH: seqlock pair coverage broken if reusing `WorkerRuntimeAtomics.window_gen` | v1 §1.4 | `WorkerColdPathAtomics` carries its OWN `window_gen` field. Publish flips its own gen odd, stores, flips even — independent of `WorkerRuntimeAtomics` 60s-rotation gen. | §1.2 + §1.4 |
| MED: bucket layout self-contradicts existing `bucket_index_for_ns` | v1 §3.3 + §1.1 | Pin exact 24-bucket formula `b = (54 - clz(ns\|1)).max(0).min(23)` — bucket 0 = `[0, 1024)` ns, bucket 23 saturates at 2^32 ns ≈ 4.295 s. Same math as 16-bucket, just `.min(23)` instead of `.min(15)`. | §1.1 + §3.3 |
| MED: splitmix64 collisions on real loss-cluster zone set | v1 §1.1 + §3.4 | Two-prong fix: (a) seed `zone_pair_slot` with the worker's salt to spread collisions across workers per-publish epoch; (b) publish only slots whose `keys_xor` is **stable** across two consecutive publishes — aliased slots reveal themselves as a non-monotonic `keys_xor` toggle. The harness post-filters per parent §4.6 publication gate. *(v2 keys_xor RETIRED in v3 per Codex r2 finding 3 — replaced with first_key + alias_seen; this row preserved for historical context.)* | §1.1 + §3.4 |
| MED: STAGED ship contract gap on Tables + #1609 unblock | v1 §3.6 + §6 | STAGED mode now emits an **explicit disclaimer header** in `docs/userspace-jit-design.md`: "Scale Target measurement deferred — counter wiring shipped; cluster measurement scheduled under follow-up <issue#>. #1609 v2 acceptance criterion REMAINS unmet." | §1.9 + §3.6 + §6 |

Codex cleared (r1): `telemetry.dbg.session_miss` increments in release builds at
poll_descriptor/mod.rs:763 (release-stable). TSC gating (CPU flags +
`current_clocksource == tsc`) is directionally correct.

## v2 → v3 fatal-axis resolution map (Codex r2)

| Codex r2 finding | v2 source | v3 fix | Section |
|------------------|-----------|--------|---------|
| HIGH 1: `XPF_COLD_PATH_SAMPLE_MASK` env-override won't propagate through `systemctl restart` (no `Environment=` in xpfd.service) | v2 §1.3 | Replace env-override with a daemon CLI flag `--cold-path-sample-mask <N>` parsed by `cmd/xpfd/main.go` and threaded into the userspace-dp control-socket bootstrap. Harness sets it via `systemctl edit --force --full xpfd.service` drop-in OR via `cli configure` config knob (preferred — survives daemon restarts). | §1.3 + §7 |
| MED 2: `telemetry.counters.session_misses` is per-poll `BatchCounters` accumulator (reset at flush); 1-in-256 undersamples partial polls | v2 §1.3 | New worker-local monotonic counter `cold_path_sample_phase: u64` on `WorkerColdPathCounters` (already added in scaffolding). Hot-path bumps it on every session-miss path. Mask check reads it; flush DOES NOT reset it. | §1.3 |
| HIGH 3: `keys_xor` fails to detect aliases with `count(K) odd + count(L) even` final-state equal to K | v2 §3.4 | Replace `keys_xor` with `first_key + alias_seen` pair per slot: store the first key seen in the slot, set `alias_seen = true` if any subsequent sample's key differs. Harness publication gate excludes slots with `alias_seen = true`. | §1.1 + §3.4 |

Also resolved as NIT-only:
- Sentinel string consistency: pin to `MEASUREMENT DEFERRED` (with
  space, not hyphen) everywhere. §1.9 + §6 + acceptance prose.
- Reader Acquire fence between Relaxed loads and s2 generation
  re-check: already implemented in `cold_path_hist.rs::snapshot`
  (matches `worker_runtime.rs:323` template).
- Bucket clamp tests cover 2^32 boundary (already in scaffolding
  tests).

## 1. Scope this step-3 PR ships

In tree at end of PR:

1. **`userspace-dp/src/afxdp/cold_path_hist.rs`** — new module providing:
   - `bucket_index_for_ns_24(ns: u64) -> usize` — **pinned formula**:
     ```rust
     #[inline]
     pub(super) fn bucket_index_for_ns_24(ns: u64) -> usize {
         let clz = (ns | 1).leading_zeros() as i32;
         let b = (54 - clz).max(0) as usize;
         b.min(POLICY_COLD_PATH_HIST_BUCKETS - 1)
     }
     ```
     Same math as the 16-bucket `bucket_index_for_ns` at
     `umem/mod.rs:244`, only the `.min()` clamp changes. Bucket 0
     covers `[0, 1024)` ns; bucket[i] covers `[2^(9+i), 2^(10+i))`
     ns for i ∈ [1, 22]; bucket 23 saturates at any `ns ≥ 2^32`
     ≈ 4.295 s. Codex r1 finding 3 fix.
   - `POLICY_COLD_PATH_HIST_BUCKETS: usize = 24` + `const _: () = assert!`.
   - `POLICY_COLD_PATH_ZONE_PAIR_SLOTS: usize = 16` + `const _: () = assert!`.
   - `sample_tsc_start() -> u64` (LFENCE; RDTSCP) and
     `sample_tsc_end() -> u64` (RDTSCP; LFENCE) — asymmetric pair
     bracketing a measurement window per Intel SDM §17.17. The
     prior `sample_tsc()` alias was removed in v3.2 to prevent
     foot-gun usage at the end of a window (Copilot code-r1 +
     Codex code-r1 finding 1).
   - `calibrate_wrapper_baseline_ns(ns_per_tsc_q32: u64) -> u64`
     free function (NOT a newtype as v3 plan v0 documented) that
     takes N=4096 sample_tsc_start / sample_tsc_end pairs and returns
     the median in ns (after Q32 multiplier applied) as the per-worker
     wrapper baseline. Stored once at worker startup AFTER
     `pthread_setaffinity_np` has pinned the worker thread to its
     core — never re-calibrated. (Claude SMR r1 NIT 2 + Copilot
     code-r3.)
   - `ClockSource` enum `{ Unset = 0, Tsc = 1, ClockGettime = 2 }`
     (Copilot code-r3: the v3 plan v0 documented only Tsc + ClockGettime;
     the shipped code also includes Unset as the calibration default
     wired into WorkerColdPathAtomics.clock_source: AtomicU8(0)).
     Per parent §4.3.2,
     graceful degrade if `/proc/cpuinfo` lacks `constant_tsc` + `nonstop_tsc`
     flags OR `/sys/devices/system/clocksource/clocksource0/current_clocksource`
     does not report `tsc`. Worker records its own clock source in
     `WorkerColdPathAtomics` so the harness can per-worker-gate on
     `clock_source = tsc`.
   - `splitmix64(x: u64) -> u64` + `zone_pair_packed_key(from, to) ->
     u64` returning `((from << 16) | to) + 1` (injective per Codex r3
     finding 1; non-zero so `first_key == 0` is the "no sample"
     sentinel) + `zone_pair_slot(from_zone_id, to_zone_id) -> usize`
     returning `(splitmix64(zone_pair_packed_key(from, to)) & 0xF) as
     usize`. Per parent §4.3.4 + AGY r3 axis 5 bijection audit. Pin
     `0xF` mask via `assert!(POLICY_COLD_PATH_ZONE_PAIR_SLOTS == 16)`.
   - **Collision-detection contract** (Codex r1 finding 4 + Codex
     r2 finding 3): each slot stores a `first_key: u64` (the packed
     zone-pair key of the first sample to land in this slot during
     this publish window) and an `alias_seen: bool` (set true if
     any subsequent sample's packed key differs from `first_key`).
     Hot-path update on sample:
     ```rust
     let key = zone_pair_packed_key(from_zone_id, to_zone_id);
     let slot = zone_pair_slot(from_zone_id, to_zone_id);
     if self.first_key[slot] == 0 {
         self.first_key[slot] = key;
     } else if self.first_key[slot] != key {
         self.alias_seen[slot] = true;
     }
     ```
     Cost: 1 branch + 2 array loads + 1 conditional store. Same
     order as `record_sample`'s existing array updates.
     Harness publication gate: exclude any slot where
     `alias_seen[slot] == true` from Tables A1/A2 for the run.
     Raw TSV retains all slot samples with the `alias_seen` flag
     so re-analysis is possible. This is a publication gate, not
     a runtime constraint.

     The earlier `keys_xor` design (v1 + v2) is RETIRED — Codex r2
     proved a false-pass mode where `count(K)` odd + `count(L)`
     even leaves the final XOR equal to K, falsely passing the
     publication gate.

2. **`userspace-dp/src/afxdp/worker_cold_path.rs`** — new module providing
   (v3: scaffolded as `userspace-dp/src/afxdp/cold_path_hist.rs` in this
   branch; final layout absorbs the integration-side glue):
   - `WorkerColdPathCounters` — per-worker mutable state (touched only by
     the owning worker thread; flat `[[u64; 24]; 16]` for buckets,
     `[u64; 16]` for sum_ns, `[u64; 16]` for sample counts, `[u64; 16]`
     for `first_key`, `[bool; 16]` for `alias_seen`, plus single `u64`
     monotonic `sample_phase`). Hot path operations are array index +
     add + conditional store — zero allocations. Per parent §4.3.4
     amended for v3.
   - `WorkerColdPathAtomics` — publish-side per-worker struct living
     **alongside** `WorkerRuntimeAtomics` in `worker_runtime.rs` but
     with its own dedicated `window_gen: AtomicU64`. The cold-path
     seqlock is INDEPENDENT of the runtime seqlock because the
     runtime's even-flip only fires inside the 60s window-rotation
     branch (`worker_runtime.rs:227`), while cold-path counters
     must publish every ~1 s tick. Codex r1 finding 2 fix.

     Publish protocol (every ~1 s; called from `publish()` regardless
     of whether the 60s rotation branch fires):
     ```rust
     // 1. Bump cold gen even → odd.
     self.cold_window_gen.fetch_add(1, Ordering::AcqRel);
     // 2. Relaxed-store 16 × 24 = 384 bucket entries + 16 × 4 = 64
     //    metadata fields (sum_ns / samples / first_key / alias_seen).
     for slot in 0..16 {
         for b in 0..24 {
             self.buckets[slot][b].store(local.buckets[slot][b], Ordering::Relaxed);
         }
         self.sum_ns[slot].store(local.sum_ns[slot], Ordering::Relaxed);
         self.samples[slot].store(local.samples[slot], Ordering::Relaxed);
         self.first_key[slot].store(local.first_key[slot], Ordering::Relaxed);
         self.alias_seen[slot].store(local.alias_seen[slot], Ordering::Relaxed);
     }
     // 3. Bump cold gen odd → even with Release.
     self.cold_window_gen.fetch_add(1, Ordering::Release);
     ```
     The seqlock pair-coverage holds across all 384+64 = 448 atomic stores
     because the bracketing `AcqRel` + `Release` fences forbid any
     interior Relaxed store from being reordered outside the bracket.
     Same correctness argument as `WorkerRuntimeAtomics` rolling-
     window seqlock at `worker_runtime.rs:236-256` — proven via PR
     #1311 round-2. Reader cost is bounded: 384 + 64 = 448 Relaxed
     loads per snapshot, ~0.8 µs on the publish thread's owning core.

     Atomic field layout (separate cacheline alignment per Codex r1
     finding 2; runtime + cold-path atomics do NOT share window_gen):
     - `pub buckets: [[AtomicU64; 24]; 16]` (16 × 24 = 384 atomics
       per worker; layout packed for sequential cacheline access).
     - `pub sum_ns: [AtomicU64; 16]`.
     - `pub samples: [AtomicU64; 16]`.
     - `pub first_key: [AtomicU64; 16]` (per-slot first-observed
       packed zone-pair key; 0 = no sample).
     - `pub alias_seen: [AtomicBool; 16]` (per-slot alias-detected
       flag; mirrored from local state each publish).
     - `pub ns_per_tsc_q32: AtomicU64` (set once at calibration;
       never updated; outside the per-tick seqlock).
     - `pub wrapper_ns_baseline: AtomicU64` (set once at calibration;
       outside the per-tick seqlock).
     - `pub clock_source: AtomicU8` (0 = unset, 1 = TSC, 2 =
       clock_gettime; set once at calibration; outside the per-tick
       seqlock).
     - `pub cold_window_gen: AtomicU64` (per-tick seqlock counter,
       separate from `WorkerRuntimeAtomics.window_gen`).

     **Note on cardinality**: 384 (buckets) + 16 (sum_ns) + 16 (samples)
     + 16 (first_key) + 16 (alias_seen) + 3 (calibration) = ~451 atomics
     per worker × 6 workers = ~2706 atomics. ~22 KiB total per cluster
     node. (Aggregated Prometheus series count is 6 × 16 × 24 = 2304
     for the bucket counter alone — see §1.6 cardinality table.)

3. **Cold-path sampling site in `poll_descriptor/mod.rs`** — exactly two
   single-line inserts. **Sample rate is regime-conditional per Codex
   r1 finding 1 + r2 finding 1+2**:
   - The sample mask is delivered via a daemon CLI flag
     `--cold-path-sample-mask <N>` parsed by `cmd/xpfd/main.go` and
     threaded into the userspace-dp control-socket bootstrap.
     Defaults to `0xff` (1-in-256). Harness sets it to `0` for
     bounded-cohort runs via `cli configure` (preferred — survives
     daemon restarts) OR via `systemctl edit --force --full
     xpfd.service` drop-in. Worker reads the mask once at startup
     from the control-socket handshake; never re-read on the hot
     path.
   - The sample-gate counter source is a NEW worker-local
     monotonic `cold_path_sample_phase: u64` on
     `WorkerColdPathCounters` (NOT `telemetry.counters.session_misses`,
     which is per-poll `BatchCounters` and resets at flush — Codex
     r2 finding 2). Hot-path bumps `cold_path_sample_phase` on every
     session-miss path through the policy-eval site, independent
     of any per-poll counter.

   - **Sample-gate entry**: at line 1374 (right before
     `evaluate_policy_result_with_len(...)`), insert:
     ```rust
     binding.cold_path.sample_phase = binding.cold_path
         .sample_phase.wrapping_add(1);
     let sample_tag = (binding.cold_path.sample_phase
         & worker_ctx.cold_path_sample_mask) == 0;
     let t_in = if sample_tag { sample_tsc_start() } else { 0 };
     ```
     `cold_path_sample_phase` is owned by the worker thread; no
     atomics on the hot path. Mask 0xff gives 1-in-256; mask 0
     gives 1-in-1.
   - **Sample-record exit**: immediately after line 1385 (the
     `evaluate_policy_result_with_len` returns), record
     `t_out = sample_tsc_end()` only if `sample_tag`, compute
     `delta_ns = ((t_out - t_in) * ns_per_tsc_q32) >> 32`, bucket
     via `bucket_index_for_ns_24`, and
     `worker_cold_path.record_sample(zone_pair_slot, delta_ns,
     forward_key_hash)`.

   The inserts are isolated to a single contiguous if-block. The
   non-sampled hot path takes one extra branch + one Relaxed load
   (the sampler is `#[inline(always)]` on the no-op fast path; sampling
   work is a separate `#[cold]` function call). Per parent §4.3.3
   sampling-cost budget.

4. **Per-tick publish** — `WorkerColdPathAtomics::publish_from_local(
   &self, local: &WorkerColdPathCounters)` is invoked at the end of
   the existing `WorkerRuntimeAtomics::publish()` (~1 s cadence)
   using its OWN `cold_window_gen` seqlock — independent of the
   runtime atomics' `window_gen` per Codex r1 finding 2. This means
   the cold-path publish fires every publish tick, NOT only when the
   60s rotation branch executes. Concretely: in `worker_runtime.rs`
   the `publish()` end gets a `cold_path_atomics.publish_from_local(
   &counters.cold_path)` call after the runtime stores complete.

5. **Wire protocol additions** — six new fields on
   `WorkerRuntimeStatus` (Rust + Go), all `#[serde(default)]` /
   `omitempty`:

   ```rust
   // Rust side: userspace-dp/src/protocol/binding.rs
   #[serde(rename = "cold_path_hist", default, skip_serializing_if = "Vec::is_empty")]
   pub cold_path_hist: Vec<Vec<u64>>,        // [16 slots][24 buckets]
   #[serde(rename = "cold_path_sum_ns", default, skip_serializing_if = "Vec::is_empty")]
   pub cold_path_sum_ns: Vec<u64>,           // [16]
   #[serde(rename = "cold_path_samples", default, skip_serializing_if = "Vec::is_empty")]
   pub cold_path_samples: Vec<u64>,          // [16]
   #[serde(rename = "cold_path_first_key", default, skip_serializing_if = "Vec::is_empty")]
   pub cold_path_first_key: Vec<u64>,        // [16]
   #[serde(rename = "cold_path_alias_seen", default, skip_serializing_if = "Vec::is_empty")]
   pub cold_path_alias_seen: Vec<bool>,      // [16]
   #[serde(rename = "cold_path_ns_per_tsc_q32", default)]
   pub cold_path_ns_per_tsc_q32: u64,
   #[serde(rename = "cold_path_wrapper_ns_baseline", default)]
   pub cold_path_wrapper_ns_baseline: u64,
   #[serde(rename = "cold_path_clock_source", default)]
   pub cold_path_clock_source: String,       // "tsc" | "clock_gettime" | ""
   ```

   ```go
   // Go side: pkg/dataplane/userspace/protocol.go
   ColdPathHist            [][]uint64 `json:"cold_path_hist,omitempty"`
   ColdPathSumNS           []uint64   `json:"cold_path_sum_ns,omitempty"`
   ColdPathSamples         []uint64   `json:"cold_path_samples,omitempty"`
   ColdPathFirstKey        []uint64   `json:"cold_path_first_key,omitempty"`
   ColdPathAliasSeen       []bool     `json:"cold_path_alias_seen,omitempty"`
   ColdPathNSPerTSCQ32     uint64     `json:"cold_path_ns_per_tsc_q32,omitempty"`
   ColdPathWrapperNSBaseline uint64   `json:"cold_path_wrapper_ns_baseline,omitempty"`
   ColdPathClockSource     string     `json:"cold_path_clock_source,omitempty"`
   ```

   All omitempty / serde-default. Older daemons emit nothing; older
   Go readers see `nil` Vec / empty string. Per parent §4.7 backward-
   compat invariant.

6. **Prometheus emission in `pkg/api/metrics_userspace.go`** — four new
   gauges per parent §4.7 (skip emission if `ColdPathSamples` is empty):
   - `xpf_userspace_worker_cold_path_ns_bucket{worker_id, zone_pair_slot, bucket_hi_ns}` (counter)
   - `xpf_userspace_worker_cold_path_samples_total{worker_id, zone_pair_slot}` (counter)
   - `xpf_userspace_worker_cold_path_sum_ns_total{worker_id, zone_pair_slot}` (counter)
   - `xpf_userspace_worker_cold_path_wrapper_ns_baseline{worker_id}` (gauge)
   - `xpf_userspace_worker_cold_path_clock_source{worker_id, source}` (gauge, 1 = active)

   Cardinality: 6 × 16 × 24 = 2304 for the bucket counter + 6 × 16 × 2
   for samples/sum + 6 for baseline + 6 × 2 for clock_source =
   ~2500 new series. Fits within scrape budget per parent §4.7.

7. **`test/incus/synthetic-policy-gen.py`** — new generator per parent
   §4.1 + AGY r4 axis 1 SNAT-free policy refinement. CLI flags:
   - `--rules N` — total policy term count (10/100/1K/10K).
   - `--zone-pairs N` — default 16, matches histogram slot count.
   - `--out PATH` — destination Junos set-syntax file.
   - `--seed N` — PRNG seed for reproducibility.
   - `--with-snat` — opt-in; default OFF per AGY r4 axis 1.
   - Emits Junos-syntax `set security policies from-zone X to-zone Y
     policy P-i match source-address SRC destination-address DST
     application APP then permit` lines with deterministic
     pseudo-random `SRC`/`DST`/`APP` selections from a fixed pool.
     Pool is global with deterministic ordering so 10K-rule output is
     a strict superset of 1K-rule output (allows differential analysis).
   - Manifest output prints `--rules`, `--zone-pairs`, `--seed`,
     `--with-snat`, and pool sizes as a comment header.

8. **`test/incus/cold-path-microbench.sh`** — driver script per
   parent §4.5 + §4.6. Bash, runs on the host (not in the VM). Flags:
   - `--rules N` — rule count (10/100/1K/10K). Default 100.
   - `--cohort {bounded,unbounded}` — passes through to flooder. Default unbounded.
   - `--duration N` — flooder duration. Default 30.
   - `--threads N` — flooder thread count. Default 4 (per #1615 plan).
   - `--out-tsv PATH` — destination TSV row.
   - `--no-cos` (default) | `--cos` — CoS toggle.

   Steps:
   1. Pre-flight: capture isolation snapshot (`/proc/cmdline`,
      `/sys/devices/system/clocksource/clocksource0/current_clocksource`,
      `/proc/interrupts` mlx5 only, per-worker `Cpus_allowed_list`).
      Verify host `nproc >= 4`; emit `FLOODER-PIN-WARNING` if not.
      Verify the loss userspace VM's clocksource is `tsc`; emit
      `CLOCKSOURCE-WARNING: tsc not active in guest` if not, but
      proceed — the per-worker `cold_path_clock_source` field is the
      real gate.
   2. Generate synthetic policy: `python3
      test/incus/synthetic-policy-gen.py --rules N --out /tmp/policy.set
      --seed 42`. SCP into `loss:xpf-userspace-fw0:/tmp/policy.set`.
   3. `incus exec loss:xpf-userspace-fw0 -- /usr/local/sbin/cli -c
      "configure; load merge /tmp/policy.set; commit"`. Verify
      `/metrics` returns 200 OK and worker count = 6.
   4. Pre-measurement metrics snapshot.
   5. Pin flooder cores per parent §4.5: `taskset -c
      "$flooder_pin_first-$(( nproc_host - 1 ))" incus exec
      loss:cluster-userspace-host -- /usr/local/bin/cold-path-flooder
      --iface ge-0-0-1 --dst-mac <RETH1-mac> --threads 4 --cohort
      unbounded --duration 30 --warmup 5 ...`. Default JSON output.
   6. Wait for flooder completion. Capture flooder JSON.
   7. Post-measurement metrics snapshot.
   8. Subtract pre/post to get cumulative deltas. Verify all 6 workers
      reported `cold_path_clock_source = tsc`. If ANY worker reports
      `clock_gettime`, set the TSV row's `tsc_gated_publish` column
      to `false` and the harness exits 1 (per parent §4.6 TSC-only
      gate). Output a footnoted partial row to the raw TSV anyway.
   9. Compute p50/p99/p999/p9999 per slot using `numpy.percentile`
      from the bucket histogram (linear interpolation within each
      bucket; bucket midpoint as the sample value per parent §4.4).
   10. Append a row to `--out-tsv` with all parent-§4.6 columns +
       `isolation_warning`, `worker_cpus`, `nic_irq_cpus`,
       `shared_cpus`, `flooder_pin_cores`, `tsc_gated_publish`,
       `wrapper_ns_baseline_median`, `clock_source`.

9. **`docs/userspace-jit-design.md` Scale Target section** — populate
   the four tables (A1, A2, B1, B2) per parent §4.6 schema. **In this
   PR** the tables are populated with the measured numbers from the
   step-3 harness run. If the loss cluster is contested by parallel
   sub-agents and the measurement cannot be serialized within this
   PR's window, the section is checked in with `TBD-PENDING-MEASUREMENT`
   placeholders **and the following explicit STAGED-ship disclaimer is
   prepended to the section per Codex r1 finding 5**:

   ```markdown
   > **MEASUREMENT DEFERRED**: The Scale Target tables below are
   > scaffolded but NOT POPULATED with measured numbers in this
   > release of `userspace-dp`. Counter wiring (cold-path latency
   > histogram, TSC sampler, per-zone-pair slot) shipped in #1612
   > step-3. The cluster measurement run is gated on
   > smoke-runner serialization and is scheduled under follow-up
   > issue **#NNNN** (filed when this PR merges in STAGED form).
   > **#1609 v2 multi-stage policy DAG acceptance criterion
   > REMAINS UNMET** until #NNNN closes — downstream consumers
   > MUST NOT cite TBD rows as empirical bounds.
   ```

   A STAGED-ship PR description also adds a `Refs #1609 v2` line
   noting that #1609 v2 acceptance is still gated.

## 2. Out of scope (deferred to follow-ups)

- 100K and 1M rule sweeps — blocked on #1606 wire-protocol ceiling.
  Tables A1/A2 record those rows as `N/A blocked on #1606`.
- LPM / multi-stage DAG restructure — #1609. The cold-path-flooder
  with the new counter wiring is the empirical input #1609 v2
  acceptance is gated on; we'll post a cross-link comment on the
  #1609 PR once Tables A1/A2 are populated.
- Lab CPU isolation fixture — #739. Numbers in this PR ship with
  `isolation_warning=true` per parent §4.5 default expectation.
- Flooder workspace integration (#1615 closed standalone). The
  harness invokes the flooder via its `/usr/local/bin/cold-path-flooder`
  install path.
- Any change to `userspace-dp/src/policy/` (claimed by #1609 v2,
  sub-agent `a038fadf64da56232`).
- Any change to `userspace-dp/src/afxdp/cos/` or scheduler (claimed by
  #1614, sub-agent `aa8831a54c1f090dd`).
- Any change to `userspace-dp/src/afxdp/poll_stages.rs`
  per-source rate-limit or verdict cache (#1608 v3 parked).
- Any change to `pkg/cluster/` HA paths.

## 3. Risk model

### 3.1 Hot-path perturbation from sampling

Sampling rate is 1-in-256 (matching REDIRECT_SAMPLE_MASK pattern at
`umem/mod.rs:183`). The non-sampled hot path is:
- One Relaxed `load(local.session_miss_counter)` (~1 ns).
- One AND-mask compare + conditional branch (~0 ns predicted not-taken).

The sampled path (~0.39 % of session-miss packets):
- Two `__rdtscp` calls bracketing `evaluate_policy_result_with_len`
  (~25 ns total).
- One `splitmix64` (~3 ns).
- One bucket select (~2 ns).
- Four Relaxed array writes (~2 ns).
- Per-sample overhead: ~32 ns × 1/256 = 0.125 ns amortized.

Total amortized hot-path cost: ~1.1 ns per session-miss packet. Under
the cold-saturated 2.96 Mpps aggregate flood, that's ~3.3 ms/s
per-aggregate worker CPU time, well under noise floor. Per parent
§4.3.3.

### 3.2 TSC non-invariance on the Incus VM

`/sys/devices/system/clocksource/clocksource0/current_clocksource`
must report `tsc`. If `kvm-clock` is active instead, `__rdtscp`
still returns a counter but it may not be invariant (e.g. across vCPU
migrations or CPU frequency changes). Per parent §4.3.2 AGY r3
hazard 1 + #1607-step-3 acceptance criterion:

- Each worker checks `/proc/cpuinfo` at startup for `constant_tsc` +
  `nonstop_tsc` flags AND
  `/sys/devices/system/clocksource/clocksource0/current_clocksource ==
  tsc`. If both pass, `clock_source = ClockSource::Tsc`. Otherwise
  `ClockSource::ClockGettime` (the sampler uses `clock_gettime
  (CLOCK_MONOTONIC_RAW, ...)` — VDSO fast path, ~50 ns per call vs
  TSC's ~12 ns).
- The harness publishes a TSV row regardless, but **gates** the
  Scale Target table publication on `clock_source = tsc` for every
  worker. If any worker reports `clock_gettime`, the row is recorded
  in the raw TSV with a footnote but NOT copied into Tables A1/A2.

### 3.3 Histogram-bucket saturation

Codex r1 finding 3 fix: v2 pins the exact 24-bucket formula. With
`b = (54 - clz(ns|1)).max(0).min(23)`:

- Bucket 0 covers `[0, 1024)` ns (any `ns < 1024` → `clz ≥ 54` →
  `b ≤ 0` → clamped to 0).
- Bucket i (for i ∈ [1, 22]) covers `[2^(9+i), 2^(10+i))` ns.
- Bucket 23 covers `[2^32, ∞)` ns (any `ns ≥ 2^32 ≈ 4.295 s` saturates).

Worst-case projection of 1M-rule linear scan at ~100 ns/rule =
~100 ms per packet (~10^8 ns ≈ 2^27 ns), the result lands in
bucket ~17 — well below saturation. Tail is visible. Sub-1024 ns
samples (typical for 10/100-rule cold path on modern CPUs) all
land in bucket 0; tail buckets are populated above 1 µs.

### 3.4 Splitmix slot collision (Codex r1 finding 4)

`(splitmix64(zone_pair_packed_key(from, to)) & 0xF)` where
`zone_pair_packed_key(from, to) = ((from << 16) | to) + 1` (injective
encoding per Codex r3 finding 1) — AGY r3 axis 5
verified this is a perfect bijection over the K=16 diagonal +
round-robin test patterns. **However, Codex r1 simulated the real
loss-cluster zone set** (trust/untrust/dmz/wan/lan + global +
fabric variants) and found multiple slot collisions:
`trust→dmz ⊕ untrust→trust` both map to slot 3; `trust→wan ⊕
lan→wan` both map to slot 4; `untrust→wan ⊕ global` both map to
slot 11. These collisions are **inherent** to the 16-slot pigeonhole
when the active zone-pair set exceeds 16 entries.

The v3 fix replaces v2's `keys_xor` (Codex r2 finding 3 proved
false-pass) with a **`first_key + alias_seen` pair per slot**:

1. `first_key[slot]: u64` — packed zone-pair key of the first
   sample to land in this slot during the publish window. Zero
   means no sample yet.
2. `alias_seen[slot]: bool` — set true if any subsequent sample's
   key differs from `first_key`. Once true, stays true for the
   window.

Hot-path update (per sample, 1 branch + 2 array loads + 1
conditional store):

```rust
let key = zone_pair_packed_key(from_zone_id, to_zone_id);
let slot = zone_pair_slot(from_zone_id, to_zone_id);
if self.first_key[slot] == 0 {
    self.first_key[slot] = key;
} else if self.first_key[slot] != key {
    self.alias_seen[slot] = true;
}
```

Publication gate (per-worker only): any slot with
`alias_seen[slot] == true` for any worker is **excluded** from
Tables A1/A2 for the run.

**Cross-worker publication gate (AGY r3 finding 2)**: per-worker
`alias_seen` is NOT sufficient on its own. AGY proved a
cross-worker false-pass mode: if key K (e.g. trust→dmz) maps to
slot 3 and is seen only by Worker 0, while key L (e.g.
untrust→trust) also maps to slot 3 and is seen only by Worker 1,
both workers' `alias_seen[3] == false` — but aggregating slot 3
across all workers silently mixes K and L's latency distributions.

The harness MUST also validate that for every slot S used in
Tables A1/A2 publication, ALL workers reporting non-zero samples
in slot S report the SAME `first_key[S]` value. If two workers
disagree on `first_key[S]`, the slot is marked
`cross_worker_aliased = true` and excluded from publication.
Pseudo-code:

```python
def slot_safe_to_publish(slot, worker_snapshots):
    keys_seen = {snap.first_key[slot] for snap in worker_snapshots
                 if snap.samples[slot] > 0 and snap.first_key[slot] != 0}
    any_alias = any(snap.alias_seen[slot] for snap in worker_snapshots)
    return len(keys_seen) <= 1 and not any_alias
```

The raw TSV retains all slot samples with the alias flag so
re-analysis is possible.

The v1/v2 XOR-rolling design failed because XOR cancels: with
`count(K)` odd and `count(L)` even, final XOR == K — false-pass.
`first_key + alias_seen` is monotonic per worker and provably
cannot per-worker false-pass; the harness cross-worker key-set
check closes the multi-worker collision gap.

### 3.5 Wire-protocol both-sides drift

Per `feedback_wire_protocol_both_sides`: BOTH Rust
(`userspace-dp/src/protocol/binding.rs`) AND Go
(`pkg/dataplane/userspace/protocol.go`) get the same six fields. A new
JSON round-trip integration test exercises a Rust producer encoding
the new fields → Go decoder → Go re-encode → Rust decoder. Tests live
beside the existing wire-protocol tests in `protocol/tests.rs`.

### 3.6 Cluster contention / smoke serialization

Two parallel sub-agents are running:
- `a038fadf64da56232` (#1609 v2 multi-stage policy DAG).
- `aa8831a54c1f090dd` (#1614 multi-RSS CoS).

The cluster is shared via the smoke-runner pattern (per
`feedback_smoke_serialized_single_agent`). The measurement run in
step 9 of `cold-path-microbench.sh` is a 30 s flooder window × 4 rule
counts ≈ 2-4 min wall-clock, plus pre/post snapshots and policy
deploy time ≈ 8-12 min total. If the cluster is mid-smoke for either
parallel sub-agent's marker, we either:
- Wait FIFO per the smoke-runner singleton convention.
- Or STAGED-ship: merge the counter wiring + harness in this PR with
  TBD-PENDING-MEASUREMENT placeholders and file a follow-up to run
  the measurement in a dedicated short smoke window.

## 4. Test plan

### 4.1 Rust dataplane tests

- `cargo test -p userspace-dp` — full workspace test suite.
- `cargo test -p userspace-dp cold_path_hist` — new
  module tests (bucket bijection, splitmix slot bijection on
  K=16 diagonal, wrapper-baseline calibration determinism, TSC
  monotonicity within a single thread).
- `cargo test -p userspace-dp worker_cold_path` — counter
  publish/snapshot seqlock test (concurrent writer + reader,
  60 s soak, must observe zero torn snapshots).
- 5×loop on the new tests (per `feedback_no_test_dismissal`).

### 4.2 Go control-plane tests

- `go test ./pkg/dataplane/userspace/...` — protocol round-trip
  test for the six new fields.
- `go test ./pkg/api/...` — Prometheus emission test for the four
  new gauges (synthetic WorkerRuntimeStatus → registry → text
  format scrape).
- 5×loop on the new tests.

### 4.3 Build clean

- `cargo build --release -p userspace-dp` clean.
- `cargo build --release` in `test/incus/cold-path-flooder/` clean
  (no changes — this PR doesn't touch the flooder).
- `go build ./...` clean.
- `make build` + `make build-userspace-dp` clean.

### 4.4 Smoke matrix on loss userspace cluster (Pass A + Pass B)

Counter additions are pure-additive on the hot path. Smoke matrix
verifies no regression:

- Pass A (CoS-off): v4 push + `-R`, v6 push + `-R` on
  `172.16.80.200` / `2001:559:8585:80::200`. Target: ≥ 20 Gb/s
  v4-push baseline matches current master ± 5 %.
- Pass B (CoS-on): same matrix; verify per-class targets unchanged.

### 4.5 No HA-visible Prometheus surface changes

`make test-failover` is NOT required — none of the new fields are
read by `pkg/cluster/` or `pkg/vrrp/`. Per CLAUDE.md HA gate, only
HA-touching changes need `test-failover`. The new counters are
publish-only and consumed only by `pkg/api/` Prometheus and external
TSV.

### 4.6 Measurement run

Run `test/incus/cold-path-microbench.sh --rules N` for N ∈
{10, 100, 1000, 10000}, both cohort modes. Capture TSV. Verify
`tsc_gated_publish = true` for every published row. Populate
`docs/userspace-jit-design.md` Scale Target section. If the cluster is
contested, STAGED ship.

## 5. Open questions for reviewers (5+)

1. **TSC invariance on the Incus VM** — should we hard-fail at worker
   startup if TSC is non-invariant, or gracefully degrade to
   `clock_gettime` and gate the table publication post-hoc? Plan
   picks B (gracefully degrade, post-hoc gate). Reviewer challenge
   welcome.

2. **Histogram dimensions** — 16 slots × 24 buckets = 384 entries per
   worker. 6 workers × 384 × 8 B = 18 KiB total. Plus 6 × ~14 atomic
   metadata fields. ~1 cacheline of metadata per worker per slot.
   Bucket cardinality also pinned at 24 by const-assert. Is the
   24-bucket layout sufficient? Plan picks yes per parent §4.4 +
   AGY r3 axis 3 (p9999 sample budget on Regime A is 58.6 K).

3. **Sampling rate** — 1-in-256 (0xff mask) matches the existing
   REDIRECT_SAMPLE_MASK pattern. Should we instead use 1-in-64 for
   shorter measurement windows? Plan picks 1-in-256 to match
   parent §4.3.3 cost budget. Reviewer challenge welcome.

4. **Per-zone-pair slot count** — 16 splitmix64 slots. With more
   than 16 distinct zone pairs in flight (loss cluster has 5+
   zones: trust/untrust/dmz/wan/lan), aliasing is expected. The
   per-slot `first_key` + `alias_seen` pair (v3, replacing the
   retired keys_xor) exposes alias detection monotonically. The
   harness publication gate **excludes** any slot with
   `alias_seen = true` from Tables A1/A2 publication for that
   rule-count run; the raw TSV retains all slots with the alias
   flag.

5. **TSV vs Prometheus storage** — TSV is the canonical artifact.
   Prometheus is "live observability only". Should the doc cite
   the Prometheus URL or the TSV path? Plan picks TSV path
   (`docs/userspace-jit-design.md` cites the TSV row IDs as the
   source of truth).

6. **Bucket midpoint vs lower-edge for percentile compute** — When
   computing p50/p99/p999 from bucket counts, do we use bucket
   midpoint as the sample value (overestimates by 50 % within the
   bucket) or bucket lower edge (underestimates)? Plan picks
   midpoint per Prometheus `histogram_quantile()` convention. The
   "corr" columns report this transparently.

7. **Wrapper baseline calibration timing** — Calibration runs 4096
   `rdtscp`/`rdtscp` pairs at worker startup. If the worker is
   running on a contested core, the median is inflated. Plan picks:
   calibration runs in a `taskset -c <worker_cpu>` setjmp / unpin
   trampoline at worker thread spawn. Reviewer challenge welcome.

8. **STAGED-ship guardrail** — If the measurement cannot be
   serialized in this PR's window, ship counter wiring + harness +
   `TBD-PENDING-MEASUREMENT` and file follow-up issue. Plan picks:
   acceptable, but reviewers should challenge the STAGED form before
   merge.

## 6. Acceptance criteria

- All six wire-protocol fields land on both Rust + Go side, with
  serde-default / `omitempty` backward-compat tests passing.
- New `cold_path_hist` + `worker_cold_path` Rust modules compile,
  pass cargo tests + 5/5 loop.
- New Prometheus emission passes Go tests + 5/5 loop.
- New `synthetic-policy-gen.py` + `cold-path-microbench.sh` are
  checked in with shellcheck/pylint clean (where lints exist).
- Smoke matrix Pass A + Pass B match master ± 5 %.
- Either:
  - **FULL form**: Scale Target table in `docs/userspace-jit-design.md`
    is populated with measured numbers from clean TSC-gated runs;
    Tables A1/A2/B1/B2 rows are non-TBD; #1609 v2 acceptance criterion
    UNBLOCKED.
  - **STAGED form**: Tables remain TBD with the explicit
    MEASUREMENT DEFERRED disclaimer per §1.9; follow-up issue
    filed referencing this PR's counter-wiring contract; PR
    description explicitly notes `#1609 v2 acceptance REMAINS
    UNMET`.

## 7. Doc-coherency contract

This PR updates:
- `docs/userspace-jit-design.md` — Scale Target section per parent §4.6.
- `docs/pr/1607-hw-ceiling-microbench/plan.md` — strike-through TBD
  notes referencing #1612 deferral; mark step-3 as shipped.

If STAGED, also files a follow-up issue for the measurement run with
the harness reference.

## 8. Reviewer dispatch

- Round 1: Codex (`select:expert,kernel-perf-measurement`) + AGY +
  Claude SMR + Copilot.
- Reviewer prompt frames: HPC perf measurement, TSC vs clock_gettime
  on virtualized timekeeping, AF_XDP cold-path microarch, Prometheus
  histogram design, Junos config-deploy contention model.
- Codex-infra-blocked exception (per `feedback_codex_infra_must_retry`):
  retry thrice; on persistent failure, proceed with embedded-files
  workaround (smr+AGY+Copilot 3-of-4) and label round explicitly.
