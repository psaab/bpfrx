# Claude SMR plan-r1 — #1620 BindingWorker cold-path integration

**Reviewer**: Claude (domain SMR: AF_XDP cold-path instrumentation,
seqlock publish semantics, CPU arch/design, SW design patterns)
**Plan doc**: plan.md v1 @ 5b43a44d5
**Verdict**: PLAN-NEEDS-MINOR (proceed-conditional)

## Findings

### F1 (MED, §4.2) — Sibling-array option (B) buys nothing the embedded option (A) doesn't already give

Plan-v1 §4.2 argues for **(B) sibling per-worker array** of
`WorkerColdPathAtomics` on the basis of "physical isolation makes
seqlock independence visually obvious."

But #1619 already gave `WorkerColdPathAtomics` its OWN
`cold_window_gen` — so the seqlock independence is a **type-level**
invariant, not a layout one. Embedding `cold_path: WorkerColdPathAtomics`
as a field on `WorkerRuntimeAtomics` does NOT compromise that
invariant — readers explicitly Acquire-load `cold_window_gen`, not
`window_gen`.

Cost of (B) extra Arc indirection per publish: one extra cacheline
load on the publish hot path. ~2 ns. Per-tick. Fine in absolute
terms, but unnecessary.

Benefit of (A): one less heap allocation at coordinator startup;
one less Arc to plumb through `worker_loop` entry; one less type
in the worker bring-up signature. Code path is simpler.

**Recommendation**: switch to (A) embedded `cold_path:
WorkerColdPathAtomics` on `WorkerRuntimeAtomics`. Mark this as a
field with its own seqlock and add a doc-comment to the struct
banner pointing to `cold_path_hist.rs::publish_from_local` for the
contract.

If the implementer disagrees, the plan should document the rejected
embedding rationale explicitly (cache pressure, monomorphization
cost, etc.) rather than the current weak "visually obvious"
argument.

### F2 (HIGH, §4.3) — Default-skew guard is the wrong shape

Plan-v1 §4.3 + open question 2 propose a runtime guard: "if receiver
sees mask == 0 AND no explicit CLI flag was passed, force mask =
0xff."

This is **wrong**: the receiver cannot know whether the CLI flag
was passed by the Go side. The wire only carries the resulting
value. By the time the message reaches the Rust receiver, the
"explicit CLI override" signal is lost.

Two clean alternatives:

**(a) Sentinel-encoded default**: wire `mask = u64::MAX` to mean
"use the built-in default 0xff". Receiver checks `if mask ==
u64::MAX { mask = 0xff }`. Operator who wants 1-in-1 explicitly sets
0; default propagation handles older Go-side daemons.

**(b) Optional field on the wire**: `cold_path_sample_mask:
Option<u64>` (serde). None ⇒ default 0xff. This is the cleanest
because the type system enforces "Go side did not specify ⇒
None ⇒ default", with no sentinel-value contortions.

I recommend **(b)**. Required change: the Rust struct field is
`Option<u64>`, and the receiver does `let mask =
msg.cold_path_sample_mask.unwrap_or(0xff)`. Go-side
`*uint64` is the matching shape.

The current plan §4.3's runtime-guard approach should be rejected
as PLAN-NEEDS-MAJOR. The "did the operator explicitly pass 0?"
signal does not travel over the wire, so the guard is
unobservable.

### F3 (MED, §4.4) — `delta_ns = 0` on q32-unavailable path is misleading

Plan-v1 §4.4 says: "if `q32 == 0`, ... no-op; harness gates on
per-worker clock_source."

But `record_sample(from, to, 0)` is NOT a no-op — it records a
sample with delta_ns=0 into bucket 0, increments `samples[slot]`,
and updates `first_key` / `alias_seen`. The bucket and sample
count will be polluted by zero-delta synthetic entries that the
harness then has to filter out.

**Recommendation**: short-circuit the `record_sample` call entirely
when `q32 == 0`:

```rust
if sample_tag {
    let t_out = cold_path_hist::sample_tsc_end();
    let q32 = binding.cold_path.ns_per_tsc_q32;
    if q32 != 0 {
        let delta_tsc = t_out.saturating_sub(t_in);
        let delta_ns = ((delta_tsc as u128 * q32 as u128) >> 32) as u64;
        binding.cold_path.record_sample(from_zone_id, to_zone_id, delta_ns);
    }
}
```

When clock_source = ClockGettime, samples are simply skipped at the
record site, and the harness's per-worker `clock_source = tsc` gate
still serves its purpose (it gates **publication** of Table A1/A2,
not sample collection). Under the proposed change, ClockGettime
workers will have `samples[slot] = 0` everywhere — which is the
honest state.

Alternatively, fall back to `clock_gettime(CLOCK_MONOTONIC_RAW)`
in the sample path per parent §4.3.2. The plan should explicitly
pick one — either skip-on-no-TSC OR clock_gettime-fallback. Plan-v1
silently picks "no-op delta_ns=0", which is the bug.

### F4 (LOW, §4.6) — Calibration site needs disambiguation

Open question 3 is the right call to make. The correct site is
**inside the worker thread body, after `pthread_setaffinity_np`,
before the poll-loop entry**. The plan should pin this concretely
to `worker/loop_body/mod.rs` (or wherever the worker thread main
fn lives), not `BindingWorker::create` (which runs on the parent
thread). Adding the calibration to `BindingWorker::create` is a
correctness bug — the parent thread doesn't have the right
affinity, and `Instant`-vs-TSC ratio would include scheduler
noise.

### F5 (LOW) — `mirror_sample_counter` precedent is the right pattern reference

§7 architectural-mismatch row cites `mirror_sample_counter` as the
precedent. Confirmed by grep at `worker/mod.rs:149`. The pattern is
identical: worker-local `u64` counter incremented per-sample,
gated against a mask. Good cross-reference.

The plan should ALSO note that #1376 (per-binding mirror sampler)
explicitly chose the worker-local counter pattern over the global
sampler. #1620 inherits that decision for free.

### F6 (NIT, §10 open question 6) — HA-publish budget worry is reasonable but the math says it's fine

Open question 6 worries that the extra ~0.8 µs of cold-path publish
work per ~1 s tick could perturb the 60 ms VRRP advert cadence.

VRRP cadence is 30 ms per spec; the publish loop is ~1 Hz. Even at
worst case, the publish-tick overlaps with at most one VRRP advert
per ~1 s — and 0.8 µs is 27,000× smaller than the advert interval.
The HA watchdog at 200 ms is also untouched.

The mandatory `make test-failover` gate is still the right ask
because correctness is empirical here, but the open-question
phrasing should be relaxed from "could perturb" to "must verify
no perturbation."

### F7 (NIT) — Sample mask = 0 use-case naming

§2 calls mask=0 "bounded-cohort microbench only" but the
`--cold-path-sample-mask` CLI flag's help text should ALSO say
this. Otherwise an operator who reads `--help` won't know they're
about to enable 256× more TSC reads per session miss.

## Cross-PR risk

#1620 is a prereq for #1621 (wire-protocol exposure of the same
data). The wire-protocol change in #1621 will read from the
sibling array (option B) or embedded field (option A) chosen by
this PR. F1's recommendation to switch to (A) simplifies #1621.

## Hot-path / arch check

- The unconditional `binding.cold_path.sample_phase += 1` is the
  ONE per-session-miss-packet cost. Stored in a fresh cacheline
  (cold_path field is at the tail of BindingWorker per plan-v1
  §4.1; if BindingWorker is already cacheline-fragmented, this
  increment becomes a measurable cache miss). **Plan should pin
  the cache layout in §4.1** — at minimum, place `cold_path` next
  to `flow` (which the policy-eval slow path also touches) to
  share cachelines.
- The branch `(sample_phase & mask) == 0` is predicted not-taken on
  the default 0xff mask 255/256 of the time, so the branch
  predictor learns it cleanly. No frontend stall worry.
- The two `sample_tsc_*` calls bracket only `evaluate_policy_*` —
  good. Confirm both call sites preserve this by not letting any
  early-returns escape the sample-end branch.

## Verdict — PLAN-NEEDS-MINOR

Findings F1 (sibling vs embedded), F2 (wire-default-skew fix), and
F3 (q32==0 delta_ns=0 pollution) are the load-bearing minor
revisions. F4 / F5 / F6 / F7 are nits but cheap to fix.

Once v2 addresses F1-F3, this is PLAN-READY pending Codex + AGY
attestation.

## Cross-check log for future rounds

- Plan-v1 commit: 5b43a44d5
- Open questions Q1-Q6 mapped to findings F1, F2, F4, F4, F7, F6.
- F3 (q32==0 pollution) and F5 (mirror_sample_counter precedent)
  are net-new — Codex + AGY independent verification welcomed.
