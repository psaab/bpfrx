# #1519 capstone-delete — reviewer task/job IDs

Tracks all Codex and AGY plan-review + code-review rounds for the
capstone-delete branch (`refactor/1519-daemon-legacydp-shrink-impl`).

Distinct from `reviewer-ids.md` which tracks the round-1 PLAN-KILL'd
shrink branch (`refactor/1519-daemon-legacydp-shrink`).

## Plan review

### Round 1 (plan-impl v1)

- Codex: task `bvbk382ym` → PLAN-NEEDS-MINOR (3 findings: 1×P2,
  2×P3). P2 = fictional `conntrack.PersistentNATProvider` /
  `conntrack.SessionCountPublisher` references in row 1 of the
  migration matrix (correct surface is `conntrack.NewGC(d.dp,
  interval)` against the exported `RuntimeDomainProvider` at
  `pkg/conntrack/gc.go:45`; the persistent/sessionCount probes are
  intentionally package-private lowercase names internal to gc.go).
  P3a = cliRuntime described as a strict superset of
  `dataplane.RuntimeDataPlane`; reality per `pkg/cli/runtime.go:11`
  is a strict SUBSET of `dataplane.DataPlane`. P3b = flake loop
  `for i in 1..5` is a single-literal-token no-op in bash. All
  three addressed in plan-impl v1.1.
- AGY: `review-mpm1pdkv-g1sycf` — dispatched 2026-05-25T20:08Z,
  pending.
- Date: 2026-05-25

### Round 2 (plan-impl v1.1)

After AGY round-1 returns and any further findings are addressed.
v1.1 fixes the 3 Codex round-1 issues; if AGY round-1 adds new
findings on top of v1, those land in v1.2.

- Codex: _pending — dispatch after AGY round-1 returns_
- AGY: _pending_
- Date: TBD

## Code review

(Populated post-implementation, after #1516/PR #1554 closes and impl
branch is rebased + pushed.)
