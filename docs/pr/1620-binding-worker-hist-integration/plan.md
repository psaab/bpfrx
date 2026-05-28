# #1620 step-3 follow-up B: BindingWorker integration for cold-path latency histogram

**Status**: DRAFT v1 — pending adversarial plan review
**Branch**: `refactor/1620-binding-worker-hist-integration`
**Parent**: #1612 scaffolding (PR #1619, merged as 4ac85e2fd). Sibling
follow-up: #1621 (wire protocol + Prometheus).
**Plan v3.2 inheritance**: this plan is the integration-half of plan
v3.2 §1.3, §1.4, §3.1 from `docs/pr/1612-scale-target-measurement/plan.md`.
All design decisions on bucket layout, alias detection, seqlock split,
TSC fence positioning, and sample-phase semantics inherit from that
plan and the #1619 scaffolding already in tree.

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
- Hot-path cost @ default mask 0xff (1-in-256): two extra `Relaxed`
  field reads (`binding.cold_path.sample_phase`, `worker_ctx.cold_path_sample_mask`)
  + 1 AND-mask compare + branch (predicted not-taken). ~1 ns amortized
  per session-miss packet. At 1 Mpps session-install rate that's
  ~0.1 % of one core.
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

### 4.1 BindingWorker mutation

Append a single field to `BindingWorker` (`worker/mod.rs:93`):

```rust
pub(crate) struct BindingWorker {
    // ... existing 23 fields ...
    /// #1620: cold-path latency histogram worker-local state.
    /// Touched only by the owning worker thread on the policy-eval
    /// slow path. Published to `WorkerColdPathAtomics` on the ~1s
    /// `publish()` cadence; published struct lives alongside
    /// `WorkerRuntimeAtomics` in the per-worker atomics array.
    pub(crate) cold_path: WorkerColdPathCounters,
}
```

Default-initialized in `BindingWorker::create` (`worker/mod.rs`) via
`cold_path: WorkerColdPathCounters::default()`. Memory cost per
binding: ~16 × 24 × 8 + 16 × 24 = 3.5 KiB (counters); no heap
alloc.

Hot-path access pattern: `binding.cold_path.sample_phase`,
`binding.cold_path.record_sample(...)`. Owner is the worker thread;
no synchronization needed for worker-local reads/writes.

### 4.2 Per-worker atomics publish slot

`WorkerColdPathAtomics` already exists in `cold_path_hist.rs`. The
per-worker storage is the per-worker atomics array that today holds
`WorkerRuntimeAtomics`. Add a sibling field:

In the BindingWorker / per-worker shared state (per #1619 plan v3.2 §1.4 
the cold-path publish lives ALONGSIDE WorkerRuntimeAtomics — separate 
seqlock generation per Codex r1 finding 2).

Two viable wirings; the plan defaults to (B):

- **(A) Embed into `WorkerRuntimeAtomics`**: add `cold_path:
  WorkerColdPathAtomics` field. Risk: bloats the seqlock-protected
  struct; existing `window_gen` semantics unchanged but reader needs
  to know which gen to use. v3.2 specifies the cold-path publish has
  its **own** `cold_window_gen` — so embedding is safe.
- **(B) Sibling per-worker array** mirrored against the
  `WorkerRuntimeAtomics` array: a new `cold_path_atomics: Box<[WorkerColdPathAtomics]>`
  (or `Arc<[...]>`) constructed in the same place as the runtime atomics
  array, indexed identically (`worker_id`-keyed). This isolates the
  cold-path seqlock physically. Cost is one extra pointer indirection
  per publish; per-tick, negligible.

Plan-v1 picks **(B)** because (1) physical isolation makes the
seqlock independence visually obvious in the code, (2) #1619 already
gave `WorkerColdPathAtomics` its own `cold_window_gen`, so the
"sibling array" wiring matches the existing design intent, and (3)
adding a non-`Copy` heap-shaped field to `WorkerRuntimeAtomics`
would force re-considering #1311 round-2's window_gen invariant.
Open question 1 below flags this for reviewer pushback.

The sibling array is constructed once at coordinator startup
alongside `worker_runtime_atomics`. Workers get an `Arc<[WorkerColdPathAtomics]>`
(immutable Arc, internal `AtomicU64` mutation) and look up their slot
by `worker_id`. #1621 will read this array for the wire-protocol /
Prometheus snapshot.

### 4.3 CLI flag + handshake

`cmd/xpfd/main.go` adds:

```go
flag.UintVar(&coldPathSampleMask, "cold-path-sample-mask",
    0xff,
    "Cold-path latency histogram sample mask. Higher bits set ⇒ lower"+
    " sampling rate. 0xff (default) = 1-in-256. 0 = 1-in-1 (bounded-"+
    "cohort microbench only — do not use in production).")
```

The mask propagates into the userspace-dp via the same path that
forwarding/config/CoS use today. Two delivery options:

- **(α) Control-socket handshake field**: extend the existing
  `WorkerStartup` (or equivalent control-socket handshake) protocol
  with `cold_path_sample_mask: u64`. Workers read it once during
  bootstrap and stash it in `WorkerContext`.
- **(β) Per-worker env var**: simpler but per Codex r2 finding 1
  (already adopted into v3.2), env vars don't propagate through
  `systemctl restart` cleanly. **Reject (β)** — same rationale as
  v3.2 §1.3.

Plan-v1 picks **(α)**. Add field to the protocol message Go-side and
Rust-side. Default 0xff. On non-default, the worker startup log
emits a single `tracing::info!` line so operators can confirm it
applied.

If the protocol already has a "common runtime params" struct, append
the field there; otherwise add a single-field extension whose
serde-default is 0xff (so older daemons running newer userspace-dp,
or vice versa, get the right behaviour).

**This is the load-bearing wire-protocol both-sides change for
#1620.** Both Rust and Go sides must add the field with matching
defaults. The plan walks both:
- Rust: `userspace-dp/src/protocol/control.rs` (or wherever the
  bootstrap message lives — search confirms) — append `#[serde(default
  = "default_cold_path_sample_mask")] pub cold_path_sample_mask: u64`,
  with `fn default_cold_path_sample_mask() -> u64 { 0xff }`.
- Go: matching field on the Go-side handshake struct with the same
  default. Backwards-compat: missing field deserializes to 0 — which
  would mean 1-in-1 sampling, which is the WRONG default. Therefore
  use `omitempty` + explicit default in `default_cold_path_sample_mask()`
  on the Rust receiver side AS A RUNTIME GUARD (if `mask == 0` AND
  no explicit `--cold-path-sample-mask 0` was passed in the Go-side
  CLI, log a warning and force mask = 0xff). Open question 2 below
  flags this default-skew risk for reviewers.

### 4.4 Hot-path sample sites

Per plan v3.2 §1.3 + the existing `cold_path_hist::record_sample` 
interface, both call sites take this exact shape:

```rust
// At the policy-eval slow-path entry (poll_descriptor/mod.rs:~1375 and ~2393):
binding.cold_path.sample_phase =
    binding.cold_path.sample_phase.wrapping_add(1);
let sample_tag = (binding.cold_path.sample_phase
    & worker_ctx.cold_path_sample_mask) == 0;
let t_in = if sample_tag {
    cold_path_hist::sample_tsc_start()
} else {
    0
};

let policy_result = evaluate_policy_result_with_len(...);  // existing call

if sample_tag {
    let t_out = cold_path_hist::sample_tsc_end();
    let delta_tsc = t_out.saturating_sub(t_in);
    let q32 = binding.cold_path.ns_per_tsc_q32;
    let delta_ns = if q32 == 0 {
        // clock_gettime fallback — TSC unavailable.
        // No-op; harness gates on per-worker clock_source.
        0
    } else {
        ((delta_tsc as u128 * q32 as u128) >> 32) as u64
    };
    binding.cold_path.record_sample(from_zone_id, to_zone_id, delta_ns);
}
```

Both call sites: same pattern, same five lines, isolated to a single
contiguous if-block so they're trivial to verify by grep.

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

### 4.6 Worker startup calibration

`BindingWorker::create` (or the worker-loop entry point — depending
on where `pthread_setaffinity_np` is called) installs calibration:

```rust
let clock_src = cold_path_hist::probe_clock_source();
let ns_per_tsc_q32 = cold_path_hist::calibrate_ns_per_tsc_q32();
let wrapper_baseline = cold_path_hist::calibrate_wrapper_baseline_ns(ns_per_tsc_q32);
binding.cold_path.ns_per_tsc_q32 = ns_per_tsc_q32;
binding.cold_path.wrapper_ns_baseline = wrapper_baseline;
binding.cold_path.clock_source = clock_src;
cold_path_atomics_for_worker.install_calibration(
    ns_per_tsc_q32,
    wrapper_baseline,
    clock_src,
);
```

Calibration runs ONCE at startup, AFTER affinity pinning, BEFORE the
worker enters its poll loop. Single 10 ms sleep + 4096-sample
back-to-back rdtscp window. Total startup-time cost: ~10 ms per worker.

Plan-v1 places this in `worker_loop` entry (the point where affinity
is already pinned). Open question 3 below asks reviewers to confirm
the correct site.

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
| Performance regression | **LOW** | Default mask = 0xff (1-in-256). Cold path is structurally cold (only fires on session miss). Hot path (flow-cache hit) untouched. **Concrete worry**: the unconditional `sample_phase` increment + AND-mask runs on every session-miss packet, even when not sampling. Plan-v1 cost-models this at ~1 ns; smoke matrix must confirm no measurable change. |
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

- **#1621**: wire protocol Rust + Go + Prometheus emitter. Filed
  separately. #1620 stores the data in `WorkerColdPathAtomics` but
  does NOT yet expose it on the gRPC status surface.
- **#1622**: `synthetic-policy-gen.py` + `cold-path-microbench.sh` +
  measurement run + Scale Target tables. Blocked on #1620 + #1621.
- **`userspace-dp/src/policy/`** — claimed by #1609 / #1623.
- **`userspace-dp/src/afxdp/cos/`** — claimed by #1625.
- **`pkg/cluster/`** — HA paths; no change.
- **Hot-path verdict cache** (#1608 v3 parked).

## 10. Open questions for adversarial plan review

1. **Sibling array vs embedding** (§4.2). Plan-v1 picks sibling array
   for physical seqlock-separation visibility. Is the extra Arc
   indirection per-publish acceptable? Codex r1 finding 2 on #1619
   gave us `cold_window_gen` independence — does embedding into
   `WorkerRuntimeAtomics` (Option A) buy enough cache-locality to
   justify revisiting that decision? Reviewers may PLAN-NEEDS-MAJOR
   if they prefer (A).

2. **Default-skew on the wire** (§4.3). If an OLDER daemon talks to a
   NEWER userspace-dp and the field is absent, serde defaults the
   `u64` to 0 — which would mean mask = 0 = 1-in-1. **Wrong default.**
   Plan-v1 proposes a runtime guard: if the receiver sees `mask == 0`
   on a control-socket message that did NOT explicitly set the field
   AND no `--cold-path-sample-mask 0` CLI flag was passed, force the
   mask to 0xff. Is this the right approach, or should the protocol
   use a sentinel value (e.g. `u64::MAX` = "unset", default 0xff)?
   The wire-protocol both-sides contract is load-bearing; per
   `feedback_wire_protocol_both_sides`.

3. **Calibration site** (§4.6). Plan-v1 places the
   `probe_clock_source` / `calibrate_*` calls in `worker_loop` entry
   (post-affinity). Is this the right site? Alternative: do it in
   `BindingWorker::create` before the worker thread starts. The
   parent thread has different affinity → calibration noise. Confirm
   the affinity-pinned site is correct.

4. **Hot-path cost rigor**: §2 claims ~1 ns amortized per session-miss
   packet. Two extra `Relaxed` loads + AND + branch. Is this
   realistic on the loss userspace cluster's CPU? Or could the extra
   branch frontend-stall the policy-eval prefetcher? Smoke matrix
   12-stream reverse @ 0.39 Mpps session-miss path is the canonical
   reproducer. **Acceptance**: smoke matrix push and reverse both within
   ±5% of master.

5. **Cold-path-sample-mask default 0xff vs 0xfff**: 1-in-256 vs
   1-in-4096. The published #1612 v3.2 chose 0xff. Higher mask =
   lower production cost, lower sample density in the
   bounded-cohort flooder. Per #1615's flooder gate (2.96 Mpps), even
   0xff yields ~11K samples/s — plenty for a 30s flooder run. Should
   the production default be moved higher (e.g. 0xfff)? Reviewers
   weigh CPU vs measurement density.

6. **HA-sensitive test gate**: `worker_runtime.rs::publish()` is in
   the HA-visible publish path. Plan-v1 mandates `make test-failover`
   before MERGE-READY. Is the publish-tick budget tight enough that
   adding ~0.8 µs of extra cold-path publish work could perturb the
   60ms VRRP advert cadence? Worth a smoke + failover-test pass.

## 11. Stop conditions

- **PLAN-KILL** if any two of four reviewers (Codex, AGY, Claude SMR,
  Copilot — for this round, Codex + AGY + Claude SMR) flag a fatal
  finding.
- **PLAN-NEEDS-MAJOR** → revise + iterate.
- **PLAN-READY (or all NEEDS-MINOR addressed)** → proceed to Step 5
  implementation.
