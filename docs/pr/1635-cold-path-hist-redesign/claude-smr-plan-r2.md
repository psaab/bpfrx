# Claude SMR plan-review r2 — #1635 cold-path histogram redesign

**Reviewer role**: domain SMR (histogram design / hash collision / wire-protocol /
aggregation semantics). Hostile-verify of plan v2.

**Plan under review**: `docs/pr/1635-cold-path-hist-redesign/plan.md` v2 (after r1
F1-F4 patches).

**r1 findings to verify**:
- F1 (HIGH, bucket-stride too wide) — v2 picks 16-ns stride.
- F2 (HIGH, silent slot-63 alias) — v2 picks 128 slots + hard-refuse overflow.
- F3 (MED, older-Go silent miscompile) — v2 adds version switch + `_v2` metric names.
- F4 (HIGH, stale slot-map remapping) — v2 stable-slot-assignment policy.

## Verdict: **PLAN-READY** (conditional on F5/F6/F7 deferred to code-review)

v2 cleanly resolves F1-F4. Three new minor concerns surfaced during re-read; all
fixable at implementation time without further plan iteration.

---

## r1 finding verification

### F1 verification — bucket stride

v2 §2.1 picks 16-ns linear band stride. Worst-case relative error for any true p50
≥ 24 ns is ≤ 16 ns / 24 ns = 67% (= 1.67× error reported). ✅ Matches the SMR r1
remediation option (a). Acceptance criterion now correctly pinned at "p50 ≥ 24 ns"
which lines up with the measured ~25-40 ns wrapper baseline (anything sub-baseline is
already discarded by the wrapper-underflow gate).

### F2 verification — slot count + overflow

v2 §2.2 picks 128 slots + hard-refuse overflow (no slot for the 129th pair, samples
dropped at hot path). ✅ Resolves the F2 escalation: the slot-63 silent-alias pattern
is eliminated.

**Memory cost**: 128 × 80 × 8 + 128 × ~24 ≈ 84 KB local + 84 KB atomics per worker.
v2 §2.2 quotes 10.6 KB — that's the [128 × (1 + 1 + 1 + 0.125 + 80)] calc but the
80-byte term is **80 buckets × 8 bytes = 640 bytes per slot**, not 80. The correct
local size = 128 × 640 = **82 KB**, NOT 10.6 KB. The plan §2.2 has a math error.

**NEW F5 (MED, math error in §2.2 cost estimate)**: per-worker memory cost is ~82 KB
local + ~82 KB atomics, not 10.6 KB. Per-process at 12 workers: ~2 MB total. Still
trivial. Wire payload at ~82 KB matches plan §2.2. Plan §2.2 should be edited to fix
the cost calc but the conclusion ("still under gRPC 4MB cap, still negligible")
stands.

### F3 verification — wire-protocol version switch

v2 §3.2 commits to a version switch on the Go side: v=0/1 → v1 emit, v=2 → v2 emit,
unknown → refuse-and-warn. ✅ Resolves the silent-miscompile risk.

Edge case: the (v2 Rust, v1 Go) row in the compat table acknowledges this is the
dangerous direction. v2 §3.3 mitigates by lockstep deploy. ✅ Acceptable; this matches
the `pkg/dataplane/userspace/protocol.go` versioning convention used elsewhere.

**NEW F6 (NIT) on §4.8 `_v2` suffix**: emitting BOTH v1 and v2 names during a partial
rollout doubles cardinality. The plan §7 Q3 raises this. I think the `_v2` suffix
is correct because PromQL queries are version-specific; mixing 24-bucket data and
80-bucket data under the same metric name would give wrong `histogram_quantile()`
results. Per-version names are the safer choice. Plan should commit to this in v3
or this PR's code-review.

### F4 verification — stable slot assignment

v2 §2.3 + §4.3 commit to append-only-with-hole-reuse stable slot assignment. ✅
Resolves the F4 corruption pattern.

**NEW F7 (LOW) — v2 §2.3 step 3 wording**: "Snapshot 2 applies a policy with pairs
`{A, C, D}` (B removed, D new) → slots `{0, 2, 3}` (B's slot 1 retained but unused;
D gets a fresh slot 3)". Why not slot 1 (B's vacated slot)? The plan §2.3 says
"append-only with hole reuse" but the example shows append-only WITHOUT hole reuse
(D gets slot 3, skipping slot 1).

This is internally inconsistent. The next paragraph says "next pair to be added gets
that slot" (slot 1 reuses). The example contradicts that.

**Resolution for implementation**: pick one — either D goes to slot 1 (hole reuse,
matches the prose) or slot 3 (append-only-no-reuse, matches the example). I
recommend the hole-reuse path because it slows the monotonic-grow that exhausts the
128 slot budget. Plan v3 should fix the example or fix the prose; impl follows the
chosen path.

---

## Final reviewer NITs

### N1 — `splitmix64` still referenced?

Plan §4.1 says "keep `splitmix64` as a `#[cfg(test)]` helper". But splitmix64 is not
used by any test in the post-#1635 code — it's only used by `zone_pair_slot` which is
being removed. So we can delete `splitmix64` entirely. Minor; not gating.

### N2 — Verification harness scope (§5.5)

The accuracy harness drives 1000 samples at synthetic latencies. For the verification
to be meaningful, the samples must trigger `record_sample` via the **real**
`bucket_index_for_ns_80` path, not a unit-test mock. Plan §5.5 doesn't specify
whether the harness sets `cold_path_sample_mask = 0` (1-in-1) and what the synthetic
latencies are mocked through. The implementation should either:
(a) directly call `bucket_index_for_ns_80(ns)` and assert against the cumulative
    midpoint quantile, OR
(b) drive packets through the actual poll_descriptor path with a mocked TSC counter
    so the harness measures the END-TO-END accuracy, not just the formula.

(b) is more honest — it covers the wrapper-baseline subtraction + the formula. Plan
v3 should pick (b).

---

## Decisive summary

v2 cleanly resolves F1/F2/F3/F4 from r1. Three new minor concerns (F5 math, F6 metric
naming commitment, F7 example/prose inconsistency, plus the N2 verification harness
scope question) are all fixable at code-review time without further plan iteration.

**Verdict: PLAN-READY conditional on F5/F6/F7 + N2 being addressed in the code (not
gating on a v3 plan revision).**

I will hold these as code-review check items at the implementation review pass.
