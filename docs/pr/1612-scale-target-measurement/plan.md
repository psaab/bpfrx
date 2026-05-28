# #1612 step-3: cold-path counter wiring + harness + Scale Target table population

**Branch**: `perf/1612-scale-target-measurement`
**Worktree**: `/home/ps/git/bpfrx/.claude/worktrees/1612-scale-target-measurement`
**Parent plan**: `docs/pr/1607-hw-ceiling-microbench/plan.md` v2-r4 (4 review
rounds, AGY + Claude SMR + Copilot READY; Codex deterministically infra-blocked
across 5 dispatches). This step-3 PR is the implementation half of §4.3 –
§4.7 of that plan plus the measurement run that populates §4.6 Tables A1/A2/B1/B2.
This plan inherits the parent's measurement strategy and contract verbatim and
documents only the deltas/scope-narrowing decisions for the step-3 implementation
slice and the empirical measurement run.

## 1. Scope this step-3 PR ships

In tree at end of PR:

1. **`userspace-dp/src/afxdp/cold_path_hist.rs`** — new module providing:
   - `bucket_index_for_ns_24(ns: u64) -> usize` (extends existing
     `bucket_index_for_ns` to 24 buckets per parent §3 / §4.4).
   - `POLICY_COLD_PATH_HIST_BUCKETS: usize = 24` + `const _: () = assert!`.
   - `POLICY_COLD_PATH_ZONE_PAIR_SLOTS: usize = 16` + `const _: () = assert!`.
   - `sample_tsc() -> u64` wrapper around `__rdtscp` with `compiler_fence`
     bracket on both sides per Intel SDM §17.17 + Joe Damato 2018 errata.
   - `WrapperBaselineCalibration` newtype with `calibrate(samples: usize)`
     method that takes N=4096 rdtscp/rdtscp pairs, returns the median
     in ns (after Q32 multiplier applied) as the per-worker wrapper
     baseline. Stored once at worker startup; never re-calibrated.
   - `ClockSource` enum `{ Tsc, ClockGettime }`. Per parent §4.3.2,
     graceful degrade if `/proc/cpuinfo` lacks `constant_tsc` + `nonstop_tsc`
     flags. Worker records its own clock source in `WorkerColdPathAtomics`
     so the harness can per-worker-gate on `clock_source = tsc`.
   - `splitmix64(x: u64) -> u64` + `zone_pair_slot(from_zone_id: u16,
     to_zone_id: u16) -> usize` — `splitmix64((from_zone_id as u64) << 32
     | to_zone_id as u64) & 0xF`. Per parent §4.3.4 + AGY r3 axis 5 bijection
     audit. Pin `0xF` mask via `assert!(POLICY_COLD_PATH_ZONE_PAIR_SLOTS == 16)`.

2. **`userspace-dp/src/afxdp/worker_cold_path.rs`** — new module providing:
   - `WorkerColdPathCounters` — per-worker mutable state (touched only by
     the owning worker thread; flat `[[u64; 24]; 16]` for buckets,
     `[u64; 16]` for sum_ns, `[u64; 16]` for sample counts, `[u64; 16]`
     for keys_xor, single `u64` for wrapper baseline). Sized
     `16 × 24 × 8 + 3 × 16 × 8 = 3456 B` per worker. Hot path operations
     are array index + add — zero allocations. Per parent §4.3.4.
   - `WorkerColdPathAtomics` — publish-side per-worker struct sitting next
     to `WorkerRuntimeAtomics` in `worker_runtime.rs`. Same seqlock-style
     `window_gen` publish pattern (`fetch_add(AcqRel)` to odd, store the
     2304-bucket payload + 16+16+16 metadata, `fetch_add(Release)` back to
     even). Per parent §4.8 hidden invariants — same memory-ordering
     contract as `WorkerRuntimeAtomics` per PR #1311 round-2.

     Atomic field layout:
     - `pub buckets: [[AtomicU64; 24]; 16]` (2304 atomics; one cacheline-
       aligned).
     - `pub sum_ns: [AtomicU64; 16]`.
     - `pub samples: [AtomicU64; 16]`.
     - `pub keys_xor: [AtomicU64; 16]`.
     - `pub ns_per_tsc_q32: AtomicU64` (set once at calibration; never updated).
     - `pub wrapper_ns_baseline: AtomicU64` (set once at calibration).
     - `pub clock_source: AtomicU8` (0 = unset, 1 = TSC, 2 = clock_gettime).
     - `pub window_gen: AtomicU64`.

     **Note on cardinality**: 2304 + 16 + 16 + 16 + 3 = ~2360 atomics per
     worker × 6 workers = ~14K atomics. ~112 KiB total per cluster node.

3. **Cold-path sampling site in `poll_descriptor/mod.rs`** — exactly two
   single-line inserts:
   - **Sample-gate entry**: at line 1374 (right before
     `evaluate_policy_result_with_len(...)`), insert a `sample_tag` bool
     computed from the existing per-worker counter `telemetry.dbg.session_miss
     & 0xff == 0` (matches REDIRECT_SAMPLE_MASK pattern at umem.rs:923, same
     1-in-256 rate). When `sample_tag`, record `t_in = sample_tsc()`.
   - **Sample-record exit**: immediately after line 1385 (the
     `evaluate_policy_result_with_len` returns), record
     `t_out = sample_tsc()`, compute `delta_ns = (t_out - t_in) *
     ns_per_tsc_q32 >> 32`, bucket via `bucket_index_for_ns_24`, and
     `worker_cold_path.record_sample(zone_pair_slot, delta_ns,
     forward_key_hash)`.

   The inserts are isolated to a single contiguous if-block. The
   non-sampled hot path takes one extra branch + one Relaxed load
   (the sampler is `#[inline(always)]` on the no-op fast path; sampling
   work is a separate `#[cold]` function call). Per parent §4.3.3
   sampling-cost budget.

4. **Per-tick publish** — extend the existing publish site in
   `worker_runtime.rs::publish` to also write the cold-path histograms
   under the **same seqlock generation** as the runtime atomics. New
   publish entry point: `WorkerColdPathAtomics::publish_from_local(&self,
   local: &WorkerColdPathCounters)`. Called from `publish()` after the
   runtime fields are stored, before the final `window_gen` even-flip.

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
   #[serde(rename = "cold_path_keys_xor", default, skip_serializing_if = "Vec::is_empty")]
   pub cold_path_keys_xor: Vec<u64>,         // [16]
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
   ColdPathKeysXor         []uint64   `json:"cold_path_keys_xor,omitempty"`
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
   placeholders and a follow-up issue is filed; STAGED ship in that case.

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

24 power-of-two buckets per parent §4.4: bucket[i] covers
`[2^(i-1), 2^i)` ns for i ≥ 1; bucket[0] is `[0, 1)` ns. At i=23
the upper bound is 2^23 = 8_388_608 ns ≈ 8.4 ms. Per parent §4.4 +
plan v1 F3 fix: 24 buckets saturate at 4.3 s, comfortably above any
realistic per-call cold-path latency.

### 3.4 Splitmix slot collision

`splitmix64((from_zone_id << 32) | to_zone_id) & 0xF` — AGY r3 axis 5
verified this is a perfect bijection over the K=16 diagonal +
round-robin test patterns. Same 16-slot hash key contract: pinned via
`POLICY_COLD_PATH_ZONE_PAIR_SLOTS == 16` const assertion.

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
   zones: trust/untrust/dmz/wan/lan), aliasing is expected. Slot
   `keys_xor` exposes alias detection. Should the harness reject
   rows with > N aliased slots? Plan picks: harness emits
   `alias_warning` in TSV; doesn't gate Scale Target publication.

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
- Scale Target table in `docs/userspace-jit-design.md` is
  populated with measured numbers from clean TSC-gated runs (or
  STAGED with TBD placeholders if cluster contention prevents
  measurement; follow-up issue filed).

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
