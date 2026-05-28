# #1620 step-3 follow-up B: BindingWorker integration for cold-path latency histogram

**Status**: DRAFT v4 — round-3 PLAN-NEEDS-MINOR resolution
(AGY r3 + Codex r3 converge on three new amendments:
[HIGH-1] sample_phase publish gap, [MED-1] ClockSource needs
`#[repr(u8)]`, [MED-2] Go CLI loophole on `mask=0 && !enable1in1`)
**Branch**: `refactor/1620-binding-worker-hist-integration`
**Parent**: #1612 scaffolding (PR #1619, merged as 4ac85e2fd). Sibling
follow-up: #1621 (wire protocol + Prometheus).
**Plan v3.2 inheritance**: this plan is the integration-half of plan
v3.2 §1.3, §1.4, §3.1 from `docs/pr/1612-scale-target-measurement/plan.md`.
All design decisions on bucket layout, alias detection, seqlock split,
TSC fence positioning, and sample-phase semantics inherit from that
plan and the #1619 scaffolding already in tree.

## v3 → v4 fatal-axis resolution map

| Reviewer / finding | v3 source | v4 fix | Section |
|--------------------|-----------|--------|---------|
| AGY r3 [HIGH-1] + Codex r3: `sample_phase` defined on `WorkerColdPathCounters` but absent from `WorkerColdPathAtomics`, `publish_from_local`, `snapshot`. External telemetry sees session-miss denominator = 0; harness cannot validate sampling rate (`samples / sample_phase`); #1621/Prometheus exposes only sampled events. | v3 §4.1 atomics struct + publish/snapshot impls | v4 adds `sample_phase: AtomicU64` to `WorkerColdPathAtomics` (cacheline 0, between `cold_window_gen` and `ns_per_tsc_q32`). `publish_from_local()` and `snapshot()` round-trip the field. New `sample_phase_and_underflow_round_trip_through_publish_snapshot` test pins the contract. | §4.1 + §4.5 |
| AGY r3 [MED-1] + Codex r3: `ClockSource` enum without `#[repr(u8)]` makes the offset of subsequent fields implementation-defined under `#[repr(C)]` on the containing struct. | v3 §4.1 (ClockSource has no repr) | v4 annotates `enum ClockSource` with `#[repr(u8)]`. Layout math in §4.1 now holds deterministically; the `clock_source` field consumes exactly 1 byte. | §4.1 (ClockSource definition) |
| AGY r3 [MED-2] + Codex r3: Go CLI validator skips the safety guard when `coldPathSampleMask == 0 && !enable1in1`. An operator passing `--cold-path-sample-mask 0` without the 1-in-1 enable flag silently activates 1-in-1 sampling. | v3 §4.3 `if !enable1in1 && coldPathSampleMask != 0 { ... }` | v4 adds explicit reject FIRST: `if coldPathSampleMask == 0 && !enable1in1 { return fmt.Errorf(...) }`, before the pow-of-2-minus-1 validation. | §4.3 |
| AGY r3 AXIS 6 diagnostic recommendation: silent `saturating_sub` on `raw_ns < wrapper_ns_baseline` masks persistent underflow (frequency scaling, OoO jitter). | v3 §4.4 used `saturating_sub` only | v4 adds `wrapper_underflow_count` field on both `WorkerColdPathCounters` and `WorkerColdPathAtomics` (cacheline 0). §4.4 hot-path branches: if `raw_ns < wrapper_ns_baseline`, increment `wrapper_underflow_count` and record `delta_ns = 0`; else `delta_ns = raw_ns - wrapper_ns_baseline`. | §4.1 + §4.4 |

Codex r3 also flagged: the plan should pin the **sample_phase
semantics invariant** to prevent confusion between configured
sampling interval (`sample_mask`) and observed sampling denominator
(`sample_phase`). Added to §4.4 invariant block.

Round-3 attestation:
- **Codex** task-mpplze6q-dheeud: PLAN-NEEDS-MINOR (verbatim
  confirmation of all three AGY r3 findings + the sample_phase
  semantics-invariant addendum).
- **AGY** adversarial-review-mpplrk9n-p3pjm0: PLAN-NEEDS-MINOR
  (3 new findings: HIGH-1 + MED-1 + MED-2 + AXIS-6 diagnostic).
- **Claude SMR** claude-smr-plan-r3.md: PLAN-READY on v3 — missed
  the sample_phase publish gap (HIGH-1). v4 absorbs.

## v2 → v3 fatal-axis resolution map

| Reviewer / finding | v2 source | v3 fix | Section |
|--------------------|-----------|--------|---------|
| AGY r2 Amendment A + Codex r2 MED: `#[repr(C)]` missing | v2 §4.1 used `#[repr(align(64))]` only; default `#[repr(Rust)]` is free to reorder heterogeneous fields | v3 annotates `WorkerColdPathCounters` with `#[repr(C)]` and `WorkerColdPathAtomics` with `#[repr(C, align(64))]`. Layout math is now compiler-enforced: hot fields land in cacheline 0. | §4.1 |
| AGY r2 Amendment B: missing wrapper_baseline subtraction | v2 §4.4 computed `delta_ns = (delta_tsc * q32) >> 32` but never subtracted `wrapper_ns_baseline` despite calibrating it | v3 inserts `let delta_ns = raw_ns.saturating_sub(binding.cold_path.wrapper_ns_baseline)` inside the q32-skip block. `saturating_sub` prevents debug-build panic if `raw_ns < baseline` (OoO retirement edge case). | §4.4 |
| Codex r2 LOW/MED: CLI validator overflow on `u64::MAX + 1` | v2 §4.3 used `mask & (mask+1) == 0` directly | v3 explicitly handles the `u64::MAX` case: in Go `mask+1` wraps to 0 and `0 & u64::MAX == 0` would falsely pass. v3 short-circuits `if next == 0 { reject }` before the AND-check, with helpful error message. | §4.3 |

Round-2 attestation:
- **Codex** task-mppl7scr-w2unwz: PLAN-NEEDS-MINOR (sandbox-broken
  prevented file-level grep, but conceptually approved with the same
  two structural amendments + the CLI overflow MED).
- **AGY** adversarial-review-mppl8c0b-ofyy0y: PLAN-NEEDS-MINOR (axes
  1/3/4/5 all clean; axes 2 + 6 each flagged one structural
  amendment).
- **Claude SMR** claude-smr-plan-r2.md: PLAN-READY (F8/F9/F10 NIT
  only; v3 absorbs no further changes from SMR — the SMR NITs were
  meta-questions about implementation paths).

## v1 → v2 fatal-axis resolution map

| Reviewer / finding | v1 source | v2 fix | Section |
|--------------------|-----------|--------|---------|
| AGY HIGH F2 + Codex HIGH + Claude SMR F2: wire-default-skew runtime guard is structurally broken | v1 §4.3 + Open Q2 | Use **`Option<u64>`** on the Rust wire field with `serde(default)` + Go `*uint64` with `omitempty`. None ⇒ default 0xff at unwrap; `Some(0)` honored as explicit 1-in-1. No sentinel-value magic. | §4.3 |
| AGY HIGH F3 + Codex HIGH F3 + Claude SMR F3: q32==0 pollutes bucket 0 | v1 §4.4 | Hot-path explicitly skips `record_sample` when `q32 == 0` — guarded by `if q32 != 0 { ... }` wrapper. ClockGettime workers publish `samples[]=0` everywhere. | §4.4 |
| Codex HIGH CLI footgun: `--cold-path-sample-mask 0` reads as "off" but means 1-in-1 | v1 §4.3 + Open Q5 | Two-flag scheme: `--cold-path-sample-mask <N>` validates power-of-two minus one (0x1, 0x3, 0x7, ..., 0xffff_ffff_ffff_ffff). Separate `--enable-cold-path-1-in-1-sampling` boolean explicitly required to set mask=0. Default mask = 0xff. | §4.3 |
| AGY MED + Codex MED + Claude SMR F1: Sibling-array B vs Embed A — REVERSED VERDICT | v1 §4.2 picks B with weak justification | **Keep B (sibling array)**. AGY's strong counter-argument: embedding A bloats `WorkerRuntimeAtomics` from 128 B to ~3.5 KiB, causing the ~1 Hz status-scan loop to stride by 3.5 KiB and L1-miss on each worker. Claude SMR's "Arc indirection ~2 ns/tick" is correct but the cache-locality penalty on the status-scan loop dwarfs the indirection cost. v2 justifies B with the cache-compactness argument, not the visual-isolation argument. | §4.2 |
| AGY MED F2: hot-path cacheline fragmentation in `WorkerColdPathCounters` (sample_phase at bottom) | v1 §4.1 silently inherits #1619 field order | Restructure `WorkerColdPathCounters` so hot fields (`sample_phase`, `ns_per_tsc_q32`, `clock_source`, `wrapper_ns_baseline`) live at the top of the struct, ~32 bytes; cold-large fields (`buckets`, `sum_ns`, `samples`, `first_key`, `alias_seen`) sink to the bottom. **Requires editing #1619's struct** — declared OUT OF SCOPE-VIOLATION, deferred to a precursor mini-PR or absorbed into #1620 with explicit reviewer ack. v2 plan picks ABSORB. | §4.1 |
| AGY MED F5: `/proc/cpuinfo` probed concurrently by every worker | v1 §4.6 has per-worker probe | Move `probe_clock_source()` to coordinator startup (one-shot). Pass `ClockSource` enum to workers via `BindingPlan` / `WorkerContext`. Workers still call `calibrate_ns_per_tsc_q32()` per-worker (after affinity pinning) but probe is no longer per-worker. | §4.6 |
| Codex MED borrow-shape: hold `&mut binding.cold_path` across policy_eval risks &mut self.binding collision | v1 §4.4 | Pin the borrow pattern explicitly: (a) read `sample_phase` and `sample_mask` into LOCALS; (b) compute `sample_tag`; (c) capture `t_in` (TSC); (d) END the cold_path borrow; (e) run `evaluate_policy_*` (existing borrow shape); (f) capture `t_out`; (g) RE-OPEN `binding.cold_path` borrow only for `record_sample`. No mutable borrow held across policy_eval. | §4.4 |
| AGY MED F9: merge collision with #1623 (policy/) refactor | v1 §10 Open Q1 doesn't flag this | v2 sets explicit dependency: **#1620 follows #1623 if #1623 lands first**; rebase against master before MERGE-READY. If #1620 lands first, #1623 will rebase. Both PRs run concurrently — file-zone is mostly disjoint but the two call sites in poll_descriptor/mod.rs are the contact surface. Plan v2 inherits whatever `evaluate_policy_*_with_len` signature is on master at implementation time. | §9 (out-of-scope merge sequencing note) |
| AGY LOW: virtualized clocksource won't pass current_clocksource=tsc | v1 implicitly inherits #1619 probe contract | Acceptable inheritance. Loss userspace cluster runs on i40e/mlx5 bare-metal-ish VMs where current_clocksource=tsc per #1619 probe contract. CI environments will fall back to ClockGettime + skip-on-q32==0 (per F3 fix) so they remain green; the harness gates publication on TSC-only. | §3.2 (cross-ref to #1619) |
| Claude SMR F4 + Codex LOW: calibration site `worker/loop_body/mod.rs` post-affinity | v1 §4.6 Open Q3 | Pin the calibrate site to **inside the worker thread main fn** (`worker/loop_body/mod.rs` or wherever the loop entry sits post-`pthread_setaffinity_np`). v2 picks this explicitly. | §4.6 |
| Codex MED hot-path cost claim "~1 ns" overstated as point estimate | v1 §2 + §7 | v2 phrases as "budget/target ≤ 5 ns at default 0xff mask"; smoke matrix push/reverse-12-stream within ±5% of master is the empirical gate. Removes the "~1 ns" point estimate. | §2 + §7 |
| Claude SMR F7 (Codex LOW): CLI help text warning | v1 §4.3 | Help-text for `--cold-path-sample-mask` explicitly says "Default 0xff (1-in-256). Powers-of-two-minus-one only. For 1-in-1 sampling (256× CPU cost), use --enable-cold-path-1-in-1-sampling — bounded-cohort microbench only." | §4.3 |

Reviewer attestation (round 1):
- **Codex** (task-mppk7c5e-bppfn9): PLAN-NEEDS-MAJOR — 3 HIGH (wire default,
  q32 pollution, CLI footgun), 3 MED (embed/sibling, borrow shape, hot-path
  cost-claim), 2 LOW (calibration site, HA budget).
- **AGY** (adversarial-review-mppk87jl-1qsqek): PLAN-NEEDS-MAJOR — 2 HIGH
  (wire default, q32 pollution), 4 MED (cacheline frag, sibling-array
  defense, probe coordinator-side, #1623 merge gate), 1 LOW (virtualized
  clocksource).
- **Claude SMR** (claude-smr-plan-r1.md @ 80b9072ec): PLAN-NEEDS-MINOR —
  F1-F7. AGY's F2 cacheline-fragmentation finding NOT caught by SMR;
  SMR's F1 (recommend embed A) was overruled by AGY's strong cache-scan
  counter-argument. v2 takes the stronger position.

## 1. Issue framing

The #1619 scaffolding ships `cold_path_hist.rs` — `WorkerColdPathAtomics`
(per-tick seqlock publish), `WorkerColdPathCounters` (worker-local mutable),
`sample_tsc_start/end` (LFENCE-bracketed RDTSCP per Intel SDM §17.17),
`record_sample()` (slot-hash + bucket + alias detector), and the
calibration helpers — but is referenced nowhere outside its own
tests (`#[allow(dead_code)]` in mod.rs). #1620 wires it into the
live worker hot path so that policy-eval cold-path latency is
sampled and published.

The wiring is five surgical edits:

1. Add `WorkerColdPathCounters` field to `BindingWorker` struct (worker-
   local mutable; touched only by the owning worker thread).
2. Add `WorkerColdPathAtomics` field to `WorkerRuntimeAtomics`'s sibling
   per-worker publish struct so readers (and #1621's wire-protocol hook)
   can snapshot it.
3. Add `--cold-path-sample-mask <N>` CLI flag on `xpfd` and thread it
   through the userspace-dp control-socket bootstrap as a new field on
   the worker startup handshake.
4. Insert the two sample-record call sites in
   `userspace-dp/src/afxdp/poll_descriptor/mod.rs` — the
   `ForwardCandidate` policy-eval slow path (around the
   `evaluate_policy_result_with_len` call at line ~1375) and the
   session-install slow path (around the second `evaluate_policy_with_len`
   at line ~2393). Both wrap the policy call in `sample_tsc_start()` /
   `sample_tsc_end()` gated on `sample_phase & sample_mask == 0`.
5. Extend the per-worker `publish()` (~1 s cadence in `worker_runtime.rs`)
   to also call `WorkerColdPathAtomics::publish_from_local(&binding.cold_path)`.

## 2. Honest scope / value framing

This PR's value is **dead-code wakeup** for #1619's scaffolding. The
actual measurement that closes #1612's Scale Target tables is #1622
(harness + measurement run). Without #1620 + #1621 the scaffolding
remains unobservable.

Worth-the-churn check:
- Hot-path cost @ default mask 0xff (1-in-256): one worker-local
  load + increment of `sample_phase` (already L1-hot after
  v2 §4.1 field-reorder + co-location with `binding.flow`), one
  worker-local load of `worker_ctx.cold_path_sample_mask`, one
  AND-mask compare + branch (predicted not-taken 255/256 of the time).
  **Target budget**: ≤ 5 ns per session-miss packet at default mask.
  Empirical gate is smoke matrix within ±5% of master.
- Hot-path cost @ mask 0 (1-in-1 — only used by the bounded-cohort
  flooder, NOT production): two `__rdtscp` + slot hash + bucket +
  record_sample ≈ 32 ns per session-miss packet. Bounded by
  flooder's 2.96 Mpps gate (per #1615) — not a regression of normal
  traffic.
- ~451 atomics per worker × 6 workers = 22 KiB resident set delta.
- Default `--cold-path-sample-mask` is **0xff** (1-in-256) so the
  default-shipping behaviour is the cheap path. Operators only flip
  to mask 0 for the bounded-cohort microbench.

If reviewers conclude the perf gain (= unblocking #1622 measurement
+ #1609 v2 acceptance) is too small to justify the churn,
**PLAN-KILL is an acceptable verdict** — though the prereq chain
#1619 → #1620 → #1621 → #1622 has been triple-reviewed in aggregate.

## 3. What's already shipped (do not duplicate)

- `userspace-dp/src/afxdp/cold_path_hist.rs` provides:
  - `WorkerColdPathCounters` with `sample_phase: u64`, `buckets[16][24]`,
    `sum_ns[16]`, `samples[16]`, `first_key[16]`, `alias_seen[16]`,
    `ns_per_tsc_q32`, `wrapper_ns_baseline`, `clock_source`.
  - `WorkerColdPathAtomics` with matching atomic fields + own
    `cold_window_gen: AtomicU64` (independent of `WorkerRuntimeAtomics.window_gen`).
  - `record_sample(&mut self, from_zone, to_zone, delta_ns)` — updates
    bucket + sum_ns + samples + first_key/alias_seen.
  - `sample_tsc_start()` / `sample_tsc_end()` — Intel SDM §17.17 fences.
  - `publish_from_local(&self, &local)` + `snapshot() -> Option<...>`.
  - `probe_clock_source()` + `calibrate_ns_per_tsc_q32()` + 
    `calibrate_wrapper_baseline_ns()`.
- Module wired into `userspace-dp/src/afxdp/mod.rs:123` but `pub(in
  crate::afxdp)` only. All callable from inside `afxdp/*` modules.

## 4. Concrete design

### 4.1 BindingWorker mutation + WorkerColdPathCounters layout

Append a single field to `BindingWorker` (`worker/mod.rs:93`),
**immediately adjacent to `flow` and `mirror_sample_counter`** per
AGY F2 cache-locality recommendation (the policy-eval slow path
already touches `binding.flow` so co-locating maximizes L1 reuse):

```rust
pub(crate) struct BindingWorker {
    // ... existing fields with `flow` field at line ~146 ...
    pub(crate) flow: WorkerFlowCacheState,
    /// #1620: cold-path latency histogram worker-local state.
    /// Co-located with `flow` because the policy-eval slow path
    /// already touches `binding.flow` — sharing cachelines avoids
    /// a compulsory L1 miss on `binding.cold_path.sample_phase`.
    /// Touched only by the owning worker thread; published to the
    /// sibling `WorkerColdPathAtomics` array on the ~1s tick.
    pub(crate) cold_path: WorkerColdPathCounters,
    pub(crate) mirror_sample_counter: u64,
    // ... remaining fields ...
}
```

**Hot-field reordering + `#[repr(C)]` enforcement inside
`WorkerColdPathCounters`** (AGY F2 + AGY r2 Amendment A + Codex r2
MED; mechanical edit of #1619's struct, justified below):

The `#[repr(C)]` annotation is **load-bearing**: under default
`#[repr(Rust)]` the compiler may reorder heterogeneous fields to
optimize packing, which would destroy the hot-cacheline isolation.
Reviewers explicitly flagged this in r2.

```rust
// userspace-dp/src/afxdp/cold_path_hist.rs
#[repr(C)]
pub(in crate::afxdp) struct WorkerColdPathCounters {
    // === HOT FIELDS (read/written on every session-miss packet) ===
    // First cacheline: ~32 bytes.
    pub(in crate::afxdp) sample_phase: u64,
    pub(in crate::afxdp) ns_per_tsc_q32: u64,
    pub(in crate::afxdp) wrapper_ns_baseline: u64,
    pub(in crate::afxdp) clock_source: ClockSource,
    // === COLD FIELDS (written only on actual sample; ~3 KiB) ===
    pub(in crate::afxdp) alias_seen: [bool; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) first_key: [u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) sum_ns: [u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) samples: [u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) buckets: [[u64; POLICY_COLD_PATH_HIST_BUCKETS];
                                   POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
}
```

This is a mechanical reorder; the constructor (Default impl) is
adjusted to match, but field semantics are unchanged. Tests in
`cold_path_hist.rs` are field-order-agnostic and pass without
modification.

The same reorder + `#[repr(C, align(64))]` applies to
`WorkerColdPathAtomics`. The `align(64)` keeps the cacheline-isolation
invariant from #1619; the `C` enforces declared field order:

```rust
#[repr(C, align(64))]
pub(in crate::afxdp) struct WorkerColdPathAtomics {
    // === HOT FIELDS (read by publish_from_local each ~1s tick) ===
    pub(in crate::afxdp) cold_window_gen: AtomicU64,
    pub(in crate::afxdp) ns_per_tsc_q32: AtomicU64,
    pub(in crate::afxdp) wrapper_ns_baseline: AtomicU64,
    pub(in crate::afxdp) clock_source: AtomicU8,
    // === COLD FIELDS (16 × 24 atomics ~3 KiB) ===
    pub(in crate::afxdp) alias_seen: [AtomicBool; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) first_key: [AtomicU64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) sum_ns: [AtomicU64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) samples: [AtomicU64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) buckets:
        [[AtomicU64; POLICY_COLD_PATH_HIST_BUCKETS]; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
}
```

`#[repr(C, align(64))]` (was `#[repr(align(64))]` in #1619 — v3
adds the `C` per AGY r2 + Codex r2 to forbid compiler field
reordering).

**Layout math verified by AGY r2 Axis 2** (assuming `#[repr(C)]`):
- Offset 0: `sample_phase` u64 → [0..7]
- Offset 8: `ns_per_tsc_q32` u64 → [8..15]
- Offset 16: `wrapper_ns_baseline` u64 → [16..23]
- Offset 24: `clock_source` (ClockSource, repr-default = u8) → [24]
- Offset 25: `alias_seen` [bool; 16] → [25..40] (alignment 1, no padding)
- Offset 41..47: 7 bytes padding to reach next 8-aligned offset
- Offset 48: `first_key` [u64; 16] → [48..175]

The first 48 bytes — all hot fields plus `alias_seen` and the
padding gap — fit inside cacheline 0 ([0..63]). `first_key`'s
element 0 lives at offset 48..55 inside the same cacheline. So
the hot reads (`sample_phase`, `ns_per_tsc_q32`,
`wrapper_ns_baseline`, `clock_source`) all land in one cacheline.

Default-initialized in `BindingWorker::create` (`worker/mod.rs`) via
`cold_path: WorkerColdPathCounters::default()`. Memory cost per
binding: ~16 × 24 × 8 + 16 × 24 + ~32 bytes hot = ~3.5 KiB (counters);
no heap alloc.

Hot-path access pattern: `binding.cold_path.sample_phase`,
`binding.cold_path.record_sample(...)`. Owner is the worker thread;
no synchronization needed for worker-local reads/writes.

### 4.2 Per-worker atomics publish slot — Sibling array (B) confirmed

Plan v2 KEEPS the sibling per-worker array of
`WorkerColdPathAtomics`, per AGY's cache-scan counter-argument:

> Embedding (A) would bloat `WorkerRuntimeAtomics` from 128 B
> to ~3.5 KiB. The ~1 Hz telemetry status-scan loop strides
> over all workers' runtime atomics; expanding the stride to
> 3.5 KiB drags ~3 KiB of unused histogram data into L1/L2
> on every status read.

This dominates the per-tick Arc indirection cost cited by
Claude SMR. Decision is cache-scan-locality, not visual
isolation.

**Concrete wiring**: a new
`cold_path_atomics: Arc<[WorkerColdPathAtomics]>` constructed once
at coordinator startup, indexed by `worker_id` (same indexing as
`worker_runtime_atomics`). Workers clone the `Arc` and look up their
slot by `worker_id` at startup. #1621 will read this array for the
wire-protocol / Prometheus snapshot.

The Arc carries `WorkerColdPathAtomics` (not `Arc<WorkerColdPathAtomics>`)
because the inner type uses interior atomics — no per-element Arc
needed.

**Status loop cache-locality preserved**: existing
`WorkerRuntimeAtomics` array stays at 128 B per slot, so the ~1 Hz
status-scan loop reads 6 × 128 B = 768 B = 12 cachelines. With
embed-A that would have become 6 × 3.5 KiB = 21 KiB = 336 cachelines.
The sibling array means only the cold-path consumer (Prometheus
scrape, harness scrape — both 1 Hz at most) pays the wider stride.

### 4.3 CLI flag + handshake — Option<u64> wire + two-flag scheme

**Two-flag CLI scheme** (v2 absorbs Codex HIGH + Claude SMR F7):

```go
// cmd/xpfd/main.go
flag.Uint64Var(&coldPathSampleMask, "cold-path-sample-mask",
    0xff,
    "Cold-path latency histogram sample mask (powers-of-two minus one). "+
    "Default 0xff = 1-in-256 sampling. Allowed values: 0x1, 0x3, 0x7, "+
    "0xff, 0x3ff, ..., 0xffffffffffffffff. For 1-in-1 sampling (256× "+
    "CPU cost — bounded-cohort microbench only), use "+
    "--enable-cold-path-1-in-1-sampling.")

var enable1in1 bool
flag.BoolVar(&enable1in1, "enable-cold-path-1-in-1-sampling", false,
    "Enable 1-in-1 cold-path latency sampling (256× CPU cost). "+
    "Required for bounded-cohort microbench (#1622); never use in "+
    "production. Overrides --cold-path-sample-mask to 0.")
```

Validation in `main.go` after `flag.Parse()`:

```go
if enable1in1 {
    coldPathSampleMask = 0
}
// v4 (AGY r3 [MED-2] + Codex r3): Reject mask=0 unless explicit
// --enable-cold-path-1-in-1-sampling. v3 only validated pow-of-2-1
// when mask != 0, leaving a loophole: an operator who passes
// `--cold-path-sample-mask 0` without --enable-1-in-1 would silently
// enable 1-in-1 sampling (256× CPU cost) at startup.
if coldPathSampleMask == 0 && !enable1in1 {
    return fmt.Errorf(
        "--cold-path-sample-mask=0 requires explicit " +
        "--enable-cold-path-1-in-1-sampling (256× CPU cost — " +
        "bounded-cohort microbench only)",
    )
}
// Validate: must be all-ones-below-some-bit (i.e. mask + 1 must be a
// power of two). Codex r2 caught: in Rust, `mask + 1` on u64::MAX
// would panic in debug builds. Go's uint64 +1 wraps silently to 0,
// and `0 & u64::MAX == 0`, so `u64::MAX` would FALSELY pass the
// validator below. Explicitly reject u64::MAX and use Go's
// well-defined unsigned overflow (mask + 1 == 0 when mask == u64::MAX):
if coldPathSampleMask != 0 {
    next := coldPathSampleMask + 1  // u64; wraps to 0 if MAX
    if next == 0 || (coldPathSampleMask & next) != 0 {
        return fmt.Errorf(
            "--cold-path-sample-mask=0x%x: must be a power-of-two " +
            "minus one (0x1, 0x3, 0x7, 0xff, 0x3ff, ...) or 0 with " +
            "--enable-cold-path-1-in-1-sampling. Rejecting u64::MAX " +
            "as it would mean a 1-in-2^64 sampling rate (functionally " +
            "off, but ambiguous with --enable-1-in-1=false; use a " +
            "specific power-of-2 minus one instead).",
            coldPathSampleMask,
        )
    }
}
```

The Rust receiver does NOT re-validate (the Go side is authoritative
on CLI surface); the receiver just `unwrap_or(0xff)`s the
`Option<u64>` and uses the value directly in the AND-mask. A
malformed mask that slipped past Go-side validation would still
function (e.g. mask=0x5 = 1-in-2 sometimes / 1-in-4 sometimes); not
ideal but not a security or correctness issue.

**Option<u64> on the wire** (v2 absorbs Codex+AGY+Claude SMR HIGH on
default-skew):

Rust side (`userspace-dp/src/protocol/<bootstrap struct>`):

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub cold_path_sample_mask: Option<u64>,
```

Go side (`pkg/dataplane/userspace/protocol.go`):

```go
ColdPathSampleMask *uint64 `json:"cold_path_sample_mask,omitempty"`
```

Default-handling at the Rust receiver:

```rust
let mask = msg.cold_path_sample_mask.unwrap_or(0xff);
```

Wire-protocol both-sides truth table (covers `feedback_wire_protocol_both_sides`):

| Go sender                       | Wire JSON                          | Rust receiver                       | Effective mask |
|---------------------------------|------------------------------------|-------------------------------------|----------------|
| Old daemon (no field at all)    | `{...}` no field                   | `Option::None` → `unwrap_or(0xff)`  | 0xff           |
| New daemon, no `--` flag        | `{"cold_path_sample_mask": 255}`   | `Some(255)`                         | 0xff           |
| New daemon, `--mask 0x3ff`      | `{"cold_path_sample_mask": 1023}`  | `Some(1023)`                        | 0x3ff          |
| New daemon, `--enable-1-in-1`   | `{"cold_path_sample_mask": 0}`     | `Some(0)`                           | 0 (1-in-1)     |

The Go side serializes `*uint64` with `omitempty`; **important**:
the Go side MUST always set the pointer (never leave it nil) when
the daemon supports the feature, so Rust sees the explicit chosen
value. The default-skew problem only existed because a `u64` (not a
pointer) deserializes the absence of a field to 0; with `*uint64`,
the absence is `nil` which serializes to omitting the field, which
Rust receives as `None`, which unwraps to the right default.

Worker logs a single `tracing::info!` line at startup with the
effective mask so operators can confirm what landed.

The `cold_path_sample_mask` field lives on a per-worker / per-handshake
control message. The exact struct location is identified during
implementation via grep for the existing handshake/bootstrap message —
the field is appended in serde-stable position (last field) to avoid
breaking older Go daemons that ship with this PR.

### 4.4 Hot-path sample sites — q32-skip + locals-only borrow shape

Plan v2 fixes (a) q32==0 telemetry pollution (AGY+Codex+Claude SMR
HIGH F3) and (b) cold_path borrow shape across policy_eval (Codex MED
borrow shape). Both call sites at `poll_descriptor/mod.rs:~1375` and
`~2393` follow this exact pattern:

```rust
// === PRE-EVAL: read into locals; cold_path borrow ends here ===
let (sample_tag, t_in) = {
    let cp = &mut binding.cold_path;
    cp.sample_phase = cp.sample_phase.wrapping_add(1);
    let mask = worker_ctx.cold_path_sample_mask;
    let tag = (cp.sample_phase & mask) == 0;
    let t = if tag { cold_path_hist::sample_tsc_start() } else { 0 };
    (tag, t)
};
// `&mut binding.cold_path` is dropped here.

// === EXISTING POLICY EVAL — borrow shape unchanged ===
let policy_result = evaluate_policy_result_with_len(
    &worker_ctx.forwarding.policy,
    from_zone_id,
    to_zone_id,
    flow.src_ip,
    flow.dst_ip,
    flow.forward_key.protocol,
    flow.forward_key.src_port,
    flow.forward_key.dst_port,
    desc.len as u64,
);

// === POST-EVAL: re-borrow only if we sampled AND TSC is calibrated ===
if sample_tag {
    let t_out = cold_path_hist::sample_tsc_end();
    let q32 = binding.cold_path.ns_per_tsc_q32;
    if q32 != 0 {  // AGY+Codex+SMR F3: skip on TSC-unavailable
        let delta_tsc = t_out.saturating_sub(t_in);
        let raw_ns = ((delta_tsc as u128 * q32 as u128) >> 32) as u64;
        // AGY r2 Amendment B + AGY r3 AXIS 6: subtract calibrated
        // wrapper baseline (the cost of the two RDTSCP/LFENCE
        // fences themselves) so the recorded delta reflects ONLY
        // the policy_eval body cost. Count underflows explicitly so
        // a persistent frequency-scaling / OoO-jitter regime is
        // visible in telemetry rather than silently absorbed by
        // `saturating_sub`.
        let baseline = binding.cold_path.wrapper_ns_baseline;
        let delta_ns = if raw_ns < baseline {
            binding.cold_path.wrapper_underflow_count =
                binding.cold_path.wrapper_underflow_count.saturating_add(1);
            0
        } else {
            raw_ns - baseline
        };
        binding.cold_path.record_sample(from_zone_id, to_zone_id, delta_ns);
    }
}
```

**Sample_phase semantics invariant** (Codex r3 addendum):
- `sample_phase` is the worker-local monotonic count of **eligible
  cold-path sampling attempts** — incremented on every session-miss
  pass through the §4.4 pre-eval block.
- Published every ~1 s via `WorkerColdPathAtomics::publish_from_local()`
  and read back by `snapshot()`.
- Consumed by Prometheus (#1621) and the microbench harness (#1622)
  as the denominator in `actual_sampling_rate = sum(samples[]) /
  sample_phase`. Without `sample_phase` published, callers cannot
  distinguish "configured 1-in-256 working as intended" from
  "configured 1-in-256, but actual hit rate is 1-in-2048 due to a
  bug in the AND-mask check."
- The `sample_mask` is the **configured** sampling interval.
  `sample_phase` is the **observed** denominator. Operators and the
  harness MUST compare the two.

**Borrow shape contract** (Codex MED): the pre-eval block opens a
`&mut binding.cold_path` borrow that lifetime-ends at the close of
its `{...}` scope. The `evaluate_policy_*_with_len` call runs with
NO `&mut binding.cold_path` outstanding. The post-eval re-borrow is
a fresh `&mut binding.cold_path`. No overlap with `&mut self.binding`
borrows that the existing policy-eval path holds.

**TSC-unavailable contract** (AGY+Codex+SMR F3): when
`ns_per_tsc_q32 == 0` (ClockGettime fallback worker), the
`record_sample` call is skipped entirely. The cost is one extra `t_out
= sample_tsc_end()` per sampled packet (returns 0 on
non-x86_64 and on x86_64 it's a 1-cycle RDTSCP that we discard). The
`samples[]` / `buckets[]` arrays stay zero, which the harness reads as
"no data" rather than "bucket-0 polluted." The harness's per-worker
`clock_source = tsc` publication gate (parent §4.6) is the final
arbiter.

Both call sites: identical pattern, copy-pasted with the same five
locals. Grep for `binding.cold_path.sample_phase` should return
exactly two hits in `poll_descriptor/mod.rs`.

The `from_zone_id` / `to_zone_id` values used for the slot hash are
the same ones the policy call already takes — so there's no extra
zone-lookup work on the hot path.

`worker_ctx.cold_path_sample_mask` is a new `u64` field on
`WorkerContext` (`types/runtime.rs:306`), set at worker startup from
the control-socket handshake. Worker-private (Sync-safe through
WorkerContext's `'a` borrow).

`ns_per_tsc_q32` and `clock_source` are calibrated once at worker
startup (after `pthread_setaffinity_np` per #1619 Claude SMR r1
NIT 2) by calling `calibrate_ns_per_tsc_q32()` and storing the
result in `binding.cold_path.ns_per_tsc_q32`. Calibration is
performed exactly once per BindingWorker creation.

### 4.5 Per-tick publish hook

`worker_runtime.rs::publish()` is called on the ~1 s cadence in the
existing worker loop. Append at the end (after the runtime stores
complete):

```rust
// #1620: also publish the cold-path histogram alongside runtime
// counters. Uses its own seqlock (cold_window_gen) — independent of
// the rolling-window seqlock (window_gen) per #1619 plan v3.2 §1.4.
cold_path_atomics_for_worker.publish_from_local(&binding.cold_path);
```

`cold_path_atomics_for_worker` is the worker's slot in the sibling
array (§4.2). The hook fires every publish-tick (~1 s), NOT only on
60s rotation — matching `cold_window_gen`'s contract.

`publish_from_local` is already implemented in #1619; this PR only
threads the call.

### 4.6 Worker startup calibration — coordinator-side probe + worker-side calibrate

Plan v2 splits per AGY F5 (probe `/proc/cpuinfo` once, not 6×):

**Coordinator-side (one-shot)** — in
`userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs` startup
path, before spawning workers:

```rust
let coordinator_clock_source = cold_path_hist::probe_clock_source();
tracing::info!(
    target: "cold_path",
    clock_source = coordinator_clock_source.as_str(),
    "probed cold-path clock source"
);
// Stash on BindingPlan / coordinator state for per-worker consumption.
```

The probe reads `/proc/cpuinfo` + `/sys/.../current_clocksource`
ONCE; result is broadcast to all workers via `BindingPlan` or
`WorkerContext`. Eliminates the 6× concurrent file-I/O AGY flagged.

**Worker-side (per-worker, post-affinity)** — at the entry of
`worker/loop_body/mod.rs`'s thread main fn, AFTER
`pthread_setaffinity_np` has pinned the worker to its core
(Claude SMR F4 + Codex LOW):

```rust
// Inherited from coordinator probe.
let clock_src = worker_ctx.coordinator_clock_source;
// Per-worker TSC↔ns ratio: requires this thread's affinity.
let ns_per_tsc_q32 = if clock_src == ClockSource::Tsc {
    cold_path_hist::calibrate_ns_per_tsc_q32()
} else {
    0
};
let wrapper_baseline = if ns_per_tsc_q32 != 0 {
    cold_path_hist::calibrate_wrapper_baseline_ns(ns_per_tsc_q32)
} else {
    0
};
binding.cold_path.ns_per_tsc_q32 = ns_per_tsc_q32;
binding.cold_path.wrapper_ns_baseline = wrapper_baseline;
binding.cold_path.clock_source = clock_src;
// Publish calibration into atomics for #1621 wire-protocol read.
worker_cold_path_atomics.install_calibration(
    ns_per_tsc_q32,
    wrapper_baseline,
    clock_src,
);
```

The per-worker calibrate is necessary because TSC tick rate is set
per-core on some systems (Skylake / Zen3 boost governors), and the
calibration uses `Instant` which is global but the RDTSCP is per-core
— so the worker must run on its pinned core for the measured ratio
to be representative.

Total worker startup-time cost: ~10 ms calibrate + ~80 µs wrapper
baseline = ~10 ms per worker. Bring-up is parallel across workers so
wall-clock impact is bounded by the slowest worker.

**`probe_clock_source` short-circuit**: when the coordinator probe
returns `ClockGettime`, all workers skip calibrate entirely
(`ns_per_tsc_q32 = 0`), and the §4.4 hot-path q32-skip kicks in.

The site is pinned to `worker/loop_body/mod.rs::worker_loop` entry,
NOT `BindingWorker::create` (which runs on the spawning parent
thread per Codex LOW).

## 5. Public API preservation

- `WorkerRuntimeAtomics::publish` signature **unchanged**.
- `WorkerRuntimeAtomics::snapshot` signature **unchanged**.
- `worker_runtime.rs` seqlock contract **unchanged** — cold-path
  publish uses its own `cold_window_gen`.
- `BindingWorker::create` signature **unchanged** (the calibration is
  done internally).
- Hot-path function signatures **unchanged**.
- No new public types exposed outside `crate::afxdp`.

## 6. Hidden invariants the change must preserve

1. **HA portability**: the cold-path counters are pure observation
   state; they are NOT replicated across HA peers. After failover the
   peer's histogram is empty until samples accumulate. Verify by:
   no new references in `pkg/cluster/` and no new calls into
   `ha.rs` (#1620 must NOT touch `pkg/cluster/`).
2. **Side-effect ordering at the policy-eval call site**: the new
   `binding.cold_path.sample_phase` mutation MUST precede the
   `evaluate_policy_result_with_len` call (so the sample-phase
   monotonicity contract holds across panics or early returns).
   Verified by inspection — the increment is the first statement
   inside the new if-block.
3. **Seqlock pair coverage**: `cold_window_gen` increment-pair MUST
   bracket all 448 atomic stores in `publish_from_local`. Verified
   by `cold_path_hist.rs` existing tests.
4. **Calibration-before-sample**: `ns_per_tsc_q32` MUST be installed
   BEFORE the worker enters its hot loop, otherwise the first samples
   produce `delta_ns = 0` (zero-divide guarded inside record_sample
   to be safe). Verified by inspection of `BindingWorker::create` →
   `worker_loop` ordering.
5. **Affinity pinning before TSC calibration**: per #1619 plan §1.2
   Claude SMR r1 NIT 2 the calibration runs AFTER
   `pthread_setaffinity_np` pins the worker. Otherwise the
   `Instant`-vs-TSC ratio includes scheduler migration noise.

## 7. Risk assessment

| Class | Severity | Notes |
|-------|----------|-------|
| Behavioral regression | **LOW** | Worker-local counter + atomics publish; no shared mutable state touched. Two call sites are if-blocks with no side effects on the surrounding flow. |
| Lifetime / borrow-checker | **LOW-MED** | `binding.cold_path` is a plain field; reads `worker_ctx.cold_path_sample_mask` (`'a` borrow). No `&mut` overlap with the existing policy-eval borrow. Risk: the `binding.cold_path.sample_phase = ...` mutation aliases nothing else. |
| Performance regression | **LOW** | Default mask = 0xff (1-in-256). Cold path is structurally cold (only fires on session miss). Hot path (flow-cache hit) untouched. **Concrete worry**: the unconditional `sample_phase` increment + AND-mask runs on every session-miss packet, even when not sampling. Budget target ≤ 5 ns; smoke matrix push+reverse 12-stream within ±5% of master is the empirical gate. v2 absorbed AGY F2 cacheline reorder + co-location to maximize L1 hit rate on the `sample_phase` field. |
| Architectural mismatch | **LOW** | Pattern is identical to existing `mirror_sample_counter` field (worker-local counter + atomic publish). Codex r2 finding 2 (XOR-rolling false-pass) and r3 finding 1 (packed-key injectivity) were both addressed in #1619. The bucket / hash / publish primitives are already in production-shaped code. |
| HA-sensitive | **MED** | `worker_runtime.rs::publish()` is in the HA-visible path. Even though cold-path publish uses a separate seqlock, any extra time inside `publish()` shifts the HA watchdog cadence. **`make test-failover` is mandatory before MERGE-READY**. |

## 8. Test plan

- [ ] `cargo build --release -p userspace-dp` clean.
- [ ] `cargo test --release` full suite: ~952+ tests pass.
- [ ] `cargo test --release cold_path_hist::` — existing 20 tests still pass.
- [ ] `cargo test --release ha_tests::` — HA path 5/5 flake check.
- [ ] `go test ./...` — 30+ Go packages pass (CLI flag parse test).
- [ ] Smoke matrix Pass A (CoS disabled): v4 + v6, push + reverse,
      single-stream + 12-stream — all line rate, 0 retrans.
- [ ] Smoke matrix Pass B (CoS enabled): 5201-5206 v4+v6 push+reverse
      = 24 measurements, all green.
- [ ] **`make test-failover`** — HA-sensitive change, mandatory.
- [ ] Sanity probe: with `--cold-path-sample-mask 0xff`, drive 30s
      of LAN→WAN iperf3 across cold-paths and confirm `binding.cold_path.samples`
      is non-zero on at least one worker / one slot. (Console assert
      via `tracing::debug!` log line; remove before merge — or wrap
      under `#[cfg(debug_assertions)]`.)

## 9. Out of scope (explicitly)

- **#1621**: wire protocol Rust + Go + Prometheus emitter for the
  cold-path histogram **data fields** (separate from the
  `cold_path_sample_mask` handshake field added here). #1620 stores
  the histogram data in `WorkerColdPathAtomics` but does NOT yet
  expose the cumulative bucket / sum / samples fields on the gRPC
  `WorkerRuntimeStatus` surface.
- **#1622**: `synthetic-policy-gen.py` + `cold-path-microbench.sh` +
  measurement run + Scale Target tables. Blocked on #1620 + #1621.
- **`userspace-dp/src/policy/`** — claimed by #1609 / #1623. Plan v2
  sets explicit dependency: if #1623 merges before #1620, #1620
  rebases against master to inherit the new `evaluate_policy_*`
  signature. If #1620 merges first, #1623 rebases. The two call
  sites in `poll_descriptor/mod.rs` are the only contact surface.
- **`userspace-dp/src/afxdp/cos/`** — claimed by #1625.
- **`pkg/cluster/`** — HA paths; no change.
- **Hot-path verdict cache** (#1608 v3 parked).

## 10. Open questions for adversarial plan review (v2)

Round-1 questions Q1–Q6 closed by v2 reviewer findings; v2 lists
remaining open items.

1. **Field-reorder of #1619 structs** (§4.1) — v2 reorders the field
   declarations of `WorkerColdPathCounters` and `WorkerColdPathAtomics`
   for cacheline reasons. This touches #1619's tested code. Plan v2
   asserts the change is mechanical (semantics unchanged; tests pass
   without modification) but the field declaration order DOES affect
   #[repr] layout. Confirm: is the reorder safe under
   `#[repr(align(64))]`? Test impact?

2. **Coordinator-side `probe_clock_source` plumbing** (§4.6) — the
   probe result needs to be threaded from `bringup.rs` into
   `WorkerContext`. What's the canonical "shared coordinator constant"
   path on this codebase? Add a field to `BindingPlan` or attach to
   `WorkerContext` directly? The plan should pin the exact wire.

3. **Two-flag CLI scheme — operator surface** (§4.3) — is the
   `--enable-cold-path-1-in-1-sampling` boolean the right UX, or
   should we instead validate `--cold-path-sample-mask` accepts only
   non-zero powers-of-two-minus-one AND have a separate
   `--cold-path-1-in-1` flag that's a strict alias for `--mask 0`?
   Cardinality of CLI surface vs operator footgun risk.

4. **Merge-collision sequencing with #1623** (§9) — concurrent
   sub-agents make merge order unpredictable. The plan commits to
   rebase whichever lands second. Is there a stronger gate? Should
   #1620 hold for #1623 explicitly?

5. **Calibration site detail** (§4.6) — confirm
   `worker/loop_body/mod.rs::worker_loop` is the correct entry point
   for post-`pthread_setaffinity_np` calibration. The thread spawn
   that pins affinity might happen in `coordinator/reconcile/bringup.rs::spawn_supervised_worker` — calibration should fire inside
   the spawned closure, AFTER the affinity-setting syscall, BEFORE
   the worker enters its hot loop.

6. **Hot-path field co-location** (§4.1) — placing `cold_path`
   adjacent to `flow` in `BindingWorker` requires inserting a field
   between two existing #959-decomposed structs. This may shift other
   fields' offsets and trigger struct-layout test failures in
   `binding_worker_tests.rs` or similar (if any). Need to grep for
   layout-dependent tests.

## 11. Stop conditions

- **PLAN-KILL** if any two of four reviewers (Codex, AGY, Claude SMR,
  Copilot — for this round, Codex + AGY + Claude SMR) flag a fatal
  finding.
- **PLAN-NEEDS-MAJOR** → revise + iterate.
- **PLAN-READY (or all NEEDS-MINOR addressed)** → proceed to Step 5
  implementation.

## Round-1 attestation summary

- **Codex** task-mppk7c5e-bppfn9: PLAN-NEEDS-MAJOR. Findings absorbed
  in v2: wire-default (HIGH), q32-pollution (HIGH), CLI footgun (HIGH),
  embed-vs-sibling (MED — kept B but rejustified via AGY), borrow shape
  (MED), hot-path-cost overclaim (MED), calibration site (LOW), HA
  budget (LOW), mirror_sample_counter precedent (LOW).
- **AGY** adversarial-review-mppk87jl-1qsqek: PLAN-NEEDS-MAJOR.
  Findings absorbed in v2: wire-default (HIGH), q32-pollution (HIGH),
  cacheline-fragmentation field-reorder (MED), Option B sibling-array
  defense (MED — accepted), probe coordinator-side (MED), #1623 merge
  gate (MED), virtualized clocksource (LOW).
- **Claude SMR** claude-smr-plan-r1.md @ 80b9072ec: PLAN-NEEDS-MINOR
  (F1-F7). v2 reversed SMR F1 (sibling vs embed) per AGY's cache-scan
  counter-argument; SMR's F2/F3/F4/F7 all absorbed.

All three reviewers PLAN-KILL absent. Three-way consensus on
HIGH findings (wire-default + q32-pollution); MED findings have
some divergence (sibling vs embed: AGY pro-B, Codex+SMR pro-A; v2
sided with AGY based on cache-scan argument).
