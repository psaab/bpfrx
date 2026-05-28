# Claude SMR code-review r1 — PR #1618 / #1614 Axis A

Reviewer: Claude (SMR — network scheduling / shaper semantics / AF_XDP
queue physics / CPU microarchitecture / Junos CoS contract / Rust
soundness / Go API discipline).

Target: PR #1618 HEAD `19005fedf` on branch
`refactor/1614-multi-rss-cos`.

Method: hostile-verify the implementation against the v5 plan + AGY r3
+ Codex r3 findings. Plan-review is closed; this round only judges
implementation soundness.

Verdict: **MERGE-READY with two NEEDS-MINOR observations.**

## Implementation correctness vs plan v5

### A1 selector — sound

`select_exact_cos_guarantee_queue_with_lease_telemetry` correctly
gates the new path on `oversubscription_policy ==
CoSOversubscriptionPolicy::GuaranteeRate AND
oversubscription_guarantee_fraction > 0.0`. The default
`Proportional` mode falls through to the unchanged legacy body —
no perturbation possible per AGY r2 #1.

`select_exact_cos_guarantee_queue_waterfill` iterates
`root.exact_queues_by_rate_ascending` (precomputed in
`build_cos_interface_runtime` via stable
`sort_by_key`). Per-queue gates (`cos_queue_is_empty`,
`runnable`, `guarantee_enabled`, `exact`, token-bucket checks)
are identical in logic to the legacy selector. The
`secondary_budget` math matches legacy. Cursor advance to `(queue_idx
+ 1) % queue_count` for telemetry parity is correct.

The waterfill doesn't need explicit per-pass Phase 1 vs Phase 2 state
because the per-queue rate-limit gate naturally bounds each small
queue at its configured rate (which is exactly the Phase 1 honor),
and after all small queues are token-empty the iteration falls
through to the larger queues that still have tokens (Phase 2). This
is the elegant minimal mechanism behind the v5 design.

### A2 wire surface — sound; cap_eff deferred

`CoSInterfaceConfig.priority_low_min_share_bytes` plumbed from the
Junos parser through to `CoSInterfaceRuntime`. The runtime carries
`priority_low_reserved_tokens` + `priority_low_last_refill_ns` for
the future per-pass subtraction mechanism. The commit message and
the PR description both call out that the cap_eff subtraction in
the selector is deferred — and indeed, no code reads
`priority_low_min_share_bytes` on the hot path yet. **Clean
deferral, no half-implemented hot-path code.**

### A3 wire surface — sound; sojourn check deferred

`CoSQueueConfig.codel_target_ns` plumbed from
`CoSSchedulerSnapshot.codel_target_ns` through `CoSQueueConfigState`.
Default 0 means disabled. **No hot-path read yet** — the sojourn-time
dequeue check is a separate follow-up. Clean deferral.

### A4 commit warning — sound

`validateCoSOversubscriptionWarnings` correctly:
- Iterates only when `cos != nil`.
- Skips interfaces / units / scheduler-maps / schedulers that are
  nil or empty.
- Computes `sumExact` over schedulers with
  `TransmitRateExact == true`.
- Surfaces the active policy (`proportional` default vs
  `guarantee-rate <X>`) so operators see the actual distribution.

The two new Go tests cover both modes; both pass.

### Wire-protocol additive — sound

All new fields:
- Go: `omitempty` JSON tags, so old daemons that don't set the
  field produce JSON without it (byte-identical to pre-#1614 for
  unused fields).
- Rust: `#[serde(default)]`, so old snapshots without the field
  decode to zero/empty.

The wire-protocol fixture `userspace-dp/tests/fixtures/protocol_wire_v1.json`
was regenerated. New default-zero/empty fields will appear in the
fixture as their JSON-default representation; old dataplanes decoding
this fixture must tolerate the extra keys (which they do, since both
Go and Rust use lenient JSON decoding).

## NEEDS-MINOR observations

### NM1: §3 plan numerics for predicted distribution were corrected, but the v3 prediction table that remains in the plan history still references "2400 KB" in a few diagnostic prose paragraphs

Codex r3 flagged this. Not a code issue but a documentation
consistency issue. Worth a follow-up wording cleanup but not
blocking — the code path correctness is independent.

### NM2: AGY r3 E1 (saturating_sub) and E2 (Phase 2 remaining quantum) findings

E1 (`saturating_sub`) is only relevant when cap_eff subtraction is
wired into the selector — currently deferred per A2 follow-up. The
PR documents the deferral but should add an explicit reminder in
the follow-up issue body so the implementer of the cap_eff path
remembers to use `saturating_sub`.

E2 (Phase 2 remaining quantum) is only relevant when an explicit
two-phase allocator with arithmetic `pass1_budget` is implemented.
The current waterfill mechanism doesn't have an explicit Phase 1
budget — it emerges from per-queue rate-limit gates. So E2 doesn't
apply to the v5 minimal mechanism that shipped. Worth noting in
the follow-up issue body if/when an explicit Phase 1 budget is
added.

## Coverage gaps

The 3 Rust tests cover:
- Default `Proportional` mode + `fraction = 0` → legacy RR (`waterfill_default_proportional_mode_uses_legacy_rr`).
- `GuaranteeRate` mode + `fraction = 0.7` → smallest-rate queue picked first (`waterfill_guarantee_rate_mode_picks_smallest_rate_first`).
- Non-exact queues unaffected (`waterfill_guarantee_rate_skips_non_exact_queues`).

The 2 Go tests cover:
- Default proportional warning.
- Guarantee-rate warning with fraction parsing (regression on the AST-walk for the flat-keys Junos set syntax).

Gaps that are worth adding in a follow-up PR (not blocking):
- `fraction = 1.0` (full strict — Phase 2 budget is 0, large classes get nothing).
- Single exact queue (no sort decision).
- Empty exact queues (the sorted vec is empty; selector returns None).
- Mixed exact + surplus-sharing queues — current `if queue.config.surplus_sharing { continue; }` branches are preserved from legacy; should verify they fire correctly in GuaranteeRate mode too.

## Smoke harness

`test/incus/cos-simul-load-smoke.sh` ports + class map + shape map all
match `test/incus/cos-iperf-config.set`. The reducer's gate-verdict
math:
- Gate 1 small classes ≥ 95% of rate — checked for 100m, 1g, 3g, 6g.
- Gate 2 priority-low ≥ 5% of cluster ceiling (18 G) → 0.9 G floor.
- Gate 3 retrans ≤ 100/30s.
- Gate 8 reverse-direction: ≥ 22 G aggregate (R8 sanity check).

Numerics match plan §7. The harness writes verdict.json with explicit
booleans per gate so smoke runners can check programmatically.

## HA + cluster invariants

The new fields are per-interface-unit config; both chassis derive
the same mapping from the same config. No HA sync state required;
`make test-failover` should be unaffected. The selector is
worker-local; no cross-worker coordination touched.

## Decision

**MERGE-READY.** Implementation matches plan v5 + AGY r3 fixes. The
two NEEDS-MINOR observations are doc-wording cleanups and
follow-up-issue body annotations, neither blocking.

Two deferred mechanisms (A2 cap_eff subtraction, A3 sojourn-time
dequeue check) are clean deferrals — wire surface in place, no
half-implemented hot-path code. The follow-up issues are listed in
the PR description.

Recommend merge after Codex code-r1 + AGY code-r1 + Copilot
attest, on clean smoke matrix (Pass A + B + C/D + test-failover).
