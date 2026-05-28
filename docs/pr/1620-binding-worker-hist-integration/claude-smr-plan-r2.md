# Claude SMR plan-r2 — #1620 BindingWorker cold-path integration

**Reviewer**: Claude (domain SMR)
**Plan doc**: plan.md v2 @ 31556cfe7
**Verdict**: PLAN-READY

## Resolution check vs r1

| r1 finding | v2 resolution | Status |
|------------|---------------|--------|
| F1 sibling B vs embed A | v2 keeps B; reversed my recommendation on AGY's strong cache-scan counter-argument | RESOLVED (better than my r1) |
| F2 wire-default-skew runtime guard broken | v2 picks `Option<u64>` + `*uint64` with truth table for all four daemon/CLI combinations | RESOLVED |
| F3 q32==0 record_sample pollution | v2 explicit `if q32 != 0` skip in §4.4 | RESOLVED |
| F4 calibration site disambiguation | v2 pins to `worker/loop_body/mod.rs::worker_loop` post-affinity | RESOLVED |
| F5 mirror_sample_counter precedent | Carried in v2 §7 architectural-mismatch row | RESOLVED |
| F6 HA publish-budget worry phrasing | v2 §3-style risk table acknowledges; test-failover mandatory | RESOLVED |
| F7 CLI help text warning | v2 §4.3 help-string explicitly notes 256× CPU cost on 1-in-1 | RESOLVED |

## Additional findings from r2 review of v2

### F8 (NIT, §4.1) — Field reorder is mechanical, but document the cargo test impact

Plan v2 §4.1 reorders `WorkerColdPathCounters` and
`WorkerColdPathAtomics` fields. The change is semantically pure but
field-declaration order DOES affect struct layout under
`#[repr(align(64))]`. The plan asserts tests pass without
modification — confirm in implementation by running
`cargo test cold_path_hist::` 5/5 immediately after the reorder.

### F9 (NIT, §4.6) — Coordinator-side probe wiring path TBD

Plan v2 §4.6 + Open Q2 acknowledges the probe needs to be threaded
from `bringup.rs` into worker startup. The exact wire — `BindingPlan`,
`WorkerContext`, a coordinator constant, or a thread-local Lazy —
is TBD until implementation. Implementation phase should pin one
path and revise plan if the choice is non-obvious.

### F10 (NIT, §4.3) — Two-flag CLI also needs a Go validator unit test

The validation logic (`mask & (mask+1) == 0` for power-of-two-minus-one)
should have a Go unit test in `cmd/xpfd/`. Cheap to add; otherwise the
regex-vs-value-validation invariant lives only in main.go.

## Verdict — PLAN-READY

v2 absorbs every HIGH and MED finding from all three round-1
reviewers. Three NIT findings above are non-blocking and can be
addressed in implementation.

Awaiting Codex r2 + AGY r2 attestation before declaring 4-of-4
PLAN-READY.
