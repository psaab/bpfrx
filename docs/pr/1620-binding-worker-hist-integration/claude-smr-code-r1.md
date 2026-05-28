# Claude SMR code-r1 — #1620 PR #1631

**Reviewer**: Claude (domain SMR: AF_XDP cold-path instrumentation,
seqlock publish semantics, CPU arch/design, SW design patterns,
Rust-Go wire protocols)
**Head SHA**: 0bb5d9d83fef99debd3581cd15c0128261af4489
**Verdict**: MERGE-READY

## Implementation matches plan v4

All five surgical edits from plan v4 §4.1-§4.6 + the Go-side wire
plumbing have been implemented. The diff is mechanical and the smoke
results are clean.

## Axis-by-axis verification

### Borrow shape at poll_descriptor:1375/2393 (plan §4.4)

Walked both call sites:

```rust
// Pre-eval scope:
let (cp_sample_tag, cp_t_in) = {
    let cp = &mut binding.cold_path;
    cp.sample_phase = cp.sample_phase.wrapping_add(1);
    let tag = (cp.sample_phase & worker_ctx.cold_path_sample_mask) == 0;
    let t = if tag { sample_tsc_start() } else { 0 };
    (tag, t)
};
// `&mut binding.cold_path` borrow ends here.

let policy_result = evaluate_policy_result_with_len(
    &worker_ctx.forwarding.policy, ...);  // No cold_path borrow live.

if cp_sample_tag {
    let t_out = sample_tsc_end();
    let q32 = binding.cold_path.ns_per_tsc_q32;  // Fresh shared borrow.
    if q32 != 0 {
        // ... compute delta_ns ...
        binding.cold_path.record_sample(...);  // Fresh exclusive borrow.
    }
}
```

The pre-eval `{...}` scope captures `(tag, t_in)` by value and ends.
`evaluate_policy_*_with_len` borrows `&worker_ctx.forwarding.policy`
and `flow.src_ip/dst_ip` (no `binding` overlap). Post-eval re-opens
a fresh `&mut binding.cold_path`. Borrow checker passes the
`cargo build --release` cleanly without `#[allow]` overrides. The
session-install site (~2393) follows the same pattern.

### q32==0 skip semantics

Verified: when `binding.cold_path.ns_per_tsc_q32 == 0` (ClockGettime
worker), the `if q32 != 0 {...}` block is skipped entirely.
record_sample is NOT called. `samples[]`, `buckets[]`, `first_key[]`,
`alias_seen[]` all stay at 0 for that worker. This matches plan
§4.4 AGY+Codex+SMR F3 amendment.

The harness's per-worker `clock_source = tsc` publication gate
correctly excludes ClockGettime workers from the published Scale
Target tables. ClockGettime workers will report `samples_total = 0`
on /metrics, which the operator reads as "no data" (correct).

### wrapper_underflow_count semantics (AGY r3 AXIS-6)

The implementation matches plan v4 §4.4:

```rust
let delta_ns = if raw_ns < baseline {
    binding.cold_path.wrapper_underflow_count =
        binding.cold_path.wrapper_underflow_count.saturating_add(1);
    0
} else {
    raw_ns - baseline
};
binding.cold_path.record_sample(from_zone_id, to_zone_id, delta_ns);
```

Note: record_sample is still called when delta_ns=0 (underflow path).
This is intentional per plan v4 §4.4 — the sample is COUNTED in
samples[slot] and buckets[slot][0], but the underflow counter
provides the diagnostic signal that the bucket-0 weight is being
inflated by underflow rather than genuine sub-baseline policy_eval.
The harness can compute `inflated_bucket0_ratio = wrapper_underflow_count
/ sum(samples[])` to assess data quality.

AGY r3 originally suggested record_sample(.., 0) — Claude SMR
agrees the inclusion is correct: dropping the sample entirely
would understate the actual sampling denominator. The counter
distinguishes the two interpretations.

### #[repr(C)] layout enforcement

Code matches plan v4 §4.1 + AGY r2 Amendment A:

```rust
#[repr(u8)]
pub(in crate::afxdp) enum ClockSource { ... }

#[repr(C)]
pub(in crate::afxdp) struct WorkerColdPathCounters { ... }

#[repr(C, align(64))]
pub(in crate::afxdp) struct WorkerColdPathAtomics { ... }
```

Two new offset_of! tests pin the layout:
- `worker_cold_path_counters_hot_fields_fit_in_cacheline_0`
- `worker_cold_path_atomics_hot_fields_at_top`
Both pass under `cargo test cold_path_hist::` 5/5 flake.

### Wire-protocol both-sides

Rust side: `pub cold_path_sample_mask: Option<u64>` on
`ConfigSnapshot` (snapshot.rs) with `#[serde(default,
skip_serializing_if = "Option::is_none")]`.

Go side: `ColdPathSampleMask *uint64 json:"cold_path_sample_mask,omitempty"`.

Round-trip truth table verified by `cold_path_sample_mask_test.go`
TestColdPathSampleMask_RoundTripPreservesValues covering nil / 0 /
0x1 / 0xff / 0x3ff / u64::MAX. Plus 3 individual cases:
- nil pointer omits the field (TestColdPathSampleMask_NilPointerOmitsField)
- 0xff serializes as `:255` (TestColdPathSampleMask_DefaultMaskFFSerializesAs255)
- non-nil pointer to 0 serializes as `:0` (TestColdPathSampleMask_ZeroValueSerializesAs0)

The forwarding_build site:
```rust
state.cold_path_sample_mask = snapshot.cold_path_sample_mask.unwrap_or(0xff);
```

Per `feedback_wire_protocol_both_sides`: confirmed both sides
walked, both halves agree on JSON shape, omitempty wires
correctly to None at Rust receiver. PR's smoke deploy shows the
mask propagated correctly (workers read 0xff from `forwarding.cold_path_sample_mask`).

### CLI validator (cmd/xpfd/main.go)

All branches walked. The validator implements plan v4 §4.3 exactly:
- Pass A: `if enable1in1 { mask = 0 }` — explicit override.
- Pass B: `if mask == 0 && !enable1in1 { reject }` — AGY r3 MED-2 fix.
- Pass C: `if mask != 0 { next = mask + 1; if next == 0 || (mask & next) != 0 { reject } }`
  — rejects both non-pow-of-2-minus-1 AND u64::MAX (next wraps to 0).

### Daemon plumbing chain (full walk)

```
cmd/xpfd/main.go
  --cold-path-sample-mask 0xff (validated)
  ↓ daemon.Options.ColdPathSampleMask: *uint64
pkg/daemon/daemon_run.go (after Boot)
  d.dp.(interface{ Manager() *Manager }).Manager().SetColdPathSampleMask(...)
  ↓
pkg/dataplane/userspace/manager.go
  m.coldPathSampleMask = mask  (under m.mu)
  ↓ next snapshot build:
buildSnapshotWithSchedulerState + post-build stamp
  snap.ColdPathSampleMask = m.coldPathSampleMask
  ↓ JSON serialization (omitempty)
Rust: ConfigSnapshot.cold_path_sample_mask: Option<u64>
  ↓ forwarding_build/mod.rs
state.cold_path_sample_mask = snapshot.cold_path_sample_mask.unwrap_or(0xff);
  ↓ worker_loop tick
forwarding.cold_path_sample_mask → cold_path_sample_mask local
  ↓ poll_binding(...) extra arg
worker/lifecycle.rs:166 WorkerContext { cold_path_sample_mask, ... }
  ↓ poll_descriptor sample gate
(cp.sample_phase & worker_ctx.cold_path_sample_mask) == 0
```

Full 9-step chain verified. No drops; every step has the right field
shape.

### Calibration site (worker/loop_body/mod.rs entry)

After `pin_current_thread(worker_id)`:
- `probe_clock_source()` reads /proc/cpuinfo + /sys clocksource.
- `calibrate_ns_per_tsc_q32()` measures TSC↔ns ratio over a 10 ms
  Instant window (returns 0 if probe yielded ClockGettime).
- `calibrate_wrapper_baseline_ns(q32)` measures N=4096 sample_tsc_start
  / sample_tsc_end pair deltas, returns the median in ns.
- One eprintln per worker.

After bindings are built and sorted, every BindingWorker.cold_path
receives the same calibration triple (the calibration reflects the
worker's pinned core; all bindings owned by this worker share that
core's TSC ratio).

Production deploy confirms: all 6 workers report `clock_source=tsc`
with ns_per_tsc_q32 ≈ 1.87B (matches the 2.3 GHz CPU on the loss
userspace cluster) and wrapper_ns_baseline = 43-45 ns (matches
expected RDTSCP/LFENCE pair cost).

### HA path integrity

`worker_runtime.rs::publish()` is NOT modified by this PR (the
sibling Arc<[atomics]> array + publish hook are deferred to #1621
per plan v4 §9). The only HA-visible change is the per-worker
startup eprintln at worker_loop entry. test-failover 13/13 PASS
confirms zero perturbation:
- fw0 priority-0 advert burst on unclean reboot → fw1 takeover
  (<200ms iperf3 survival).
- fw0 reboot + rejoin as secondary with no auto-preempt.
- Manual failover request → fw0 becomes primary for all 3 RGs.
- Bidirectional iperf3 survived all transitions.

### Hot-path cost

Pass A smoke (CoS off): 22.9 Gb/s (v4) / 22.6 Gb/s (v6) on 12-stream
reverse with 0 retrans. Baseline (pre-#1620) on the same cluster
per the #1619 PR description was ~22-23 Gb/s — no measurable
regression.

The unconditional `sample_phase += 1` + AND-mask check runs only
at the session-miss slow path (NOT every packet — only when the
flow-cache misses and we hit the policy_eval call sites). Pass A
12-stream reverse re-uses flow-cache hits after the first packet of
each stream, so the cold-path call sites fire ~12 times in 10
seconds (one miss per stream). Hot-path cost is effectively zero
under the smoke matrix's traffic pattern.

The default `--cold-path-sample-mask 0xff` (1-in-256) ensures the
TSC sample is taken on 12/256 ≈ 4.7% of those 12 misses ≈ 0 actual
TSC reads. The cold path is structurally cold.

### Test coverage

- 1492/1492 binary tests pass (no #1620 regression; pre-existing
  snat_contract_doc_guard doc-only failure is master-level baseline).
- 28/28 cold_path_hist tests with 5/5 flake clean.
- 4/4 new Go round-trip tests pass.
- Go ./... full suite passes.
- Smoke Pass A + Pass B + 13/13 HA failover.

## Verdict — MERGE-READY

All ten axes clean. Implementation matches plan v4 exactly. No
deviation from the design that earned 4-of-4 PLAN-READY at plan
stage. Smoke matrix verifies the wiring on the production loss
userspace cluster with TSC calibration succeeding on all 6 workers.

Awaiting Codex code-r1 (task-mppnbsnc-7h47ps) + AGY code-r1
(adversarial-review-mppnchnm-x84qra) + Copilot to confirm. Expected
4-of-4 MERGE-READY pending those.
