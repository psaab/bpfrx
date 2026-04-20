# PR #797 — Go/testing adversarial review (#785 D3)

Reviewer angle: Go idioms, test coverage depth, dead code, error
handling, daemon integration. Networking-OS correctness is covered by
Codex in `docs/785-d3-pr-review.md`.

Files: `pkg/daemon/rss_indirection.go` (new), `.._test.go` (new),
`pkg/daemon/linksetup.go`, `pkg/daemon/daemon.go`, `docs/785-d3-validation.md`.

---

## MEDIUM — `isExecNotFound` uses brittle substring matching

`pkg/daemon/rss_indirection.go:273-283`. Comment claims "avoid pulling
in `errors.Is` wrapping across stdlib versions", but the repo uses
`errors.Is` extensively (`pkg/dataplane/userspace/maps_sync.go:694`,
`pkg/cluster/sync_failover.go:430`) and `exec.ErrNotFound` has been
stable since Go 1.0. Substring match will false-positive on any
unrelated "no such file or directory" error (ethtool segfault,
non-English locales). Mitigation: use
`errors.Is(err, exec.ErrNotFound)` and delete the comment.

## MEDIUM — `TestApplyRSSIndirection_NonMlx_Skips` is effectively a no-op

`pkg/daemon/rss_indirection_test.go:187-205`. Test never calls
`applyRSSIndirection` or `applyRSSIndirectionOne`; it only asserts
`f.readDriver("eth0") != mlx5Driver` and returns, which is tautological
given the fixture. The driver-skip branch at `rss_indirection.go:122`
is never exercised. Mitigation: call `applyRSSIndirection(4, f)` with a
non-mlx5 driver fixture and assert `len(f.calls) == 0`. Requires
injectable sysfs (next finding).

## MEDIUM — `applyRSSIndirection` top-level is not injectable; sysfs scan untested

`pkg/daemon/rss_indirection.go:111`. `os.ReadDir("/sys/class/net")` is
called directly, not via `execer`. Tests can only reach
`applyRSSIndirectionOne`. The tests that do call `applyRSSIndirection`
succeed only because their early-return fires before the sysfs scan;
on a host with real netdevs the tests would leak to real ethtool.
Mitigation: add `listInterfaces() []string` to `rssExecutor` and route
the scan through it.

## LOW — Dead field in test fixture

`pkg/daemon/rss_indirection_test.go:29`. `ethtoolXFailNotFound` is
populated by no test (grep confirms only the declaration + the read).
The `-X not-found` branch is unexercised. Either add a test that sets
it, or delete the field. Existing "ethtool missing" coverage is
probe-only (`TestApplyRSSIndirectionOne_EthtoolMissing_SkipsGracefully`).

## LOW — Boot-time log fires on every deploy that doesn't use userspace-dp

`pkg/daemon/rss_indirection.go:103`. `slog.Info("rss indirection
skipped (no workers configured)")` fires on every ebpf / dpdk deploy.
Once per process, so not flood-level per CLAUDE.md rules, but noise in
the non-D3 paths. Demote the `workers <= 0` branch to `slog.Debug`
(it's the normal "not userspace" state); keep `workers == 1` at Info
(explicit operator choice).

## LOW — Idempotency claim untested on re-invocation

`rss_indirection.go:97,140`. Docstring claims idempotency via
`indirectionTableMatches`. Tests cover match-on-single-call; there is
no "call twice, assert second call issues no write" test. Daemon
restart cycles are frequent (`make test-deploy`) so this matters.
Mitigation: add a two-call test asserting the second call's call count
increments by exactly 1 (probe only).

## LOW — `indirectionTableMatches` returns `false` on empty output

`rss_indirection.go:267`. If `ethtool -x` returns no parseable rows
(unsupported device, future format change), `sawAnyRow=false` triggers
a write attempt that also fails. Two warnings logged instead of one
clean skip. Acceptable but noisier than needed.

## LOW — Signature growth on `enumerateAndRenameInterfaces`

`pkg/daemon/linksetup.go:43`. Three unrelated scalars
`(nodeID, clusterMode, userspaceWorkers)`. One caller today, so fine,
but the next scalar should trigger a `LinkSetupOpts` struct.

## Config plumbing — idiomatic

`pkg/daemon/daemon.go:453-466`. The `clusterMode`/`nodeID` derivation
is extended cleanly; same nil-check discipline, same scope.
`"userspace"` sentinel matches the string used in
`pkg/config/compiler.go:724` and `compiler_system.go:221`. No magic
numbers. Correct fit with existing pattern.

## Error handling — summary

- `ethtool not available`: handled (see MEDIUM on brittleness).
- `ethtool returns non-zero`: Warn with trimmed `output=`
  (`rss_indirection.go:151,171`). Good.
- `malformed ethtool output`: matches returns `false`, re-apply. Safe.
- `interface disappears mid-call`: `readQueueCount` returns 0 (skip),
  ethtool -X would fail with Warn. Acceptable — best-effort.

No `fmt.Printf`/`fmt.Fprintf` debug. No `%w` wrapping because the
function returns nothing by design (`rss_indirection.go:100`).

## Concurrency

Called once from `Daemon.Run()` (`daemon.go:467`) before any goroutine.
No shared state. Race-detector clean by construction.

## Commit hygiene

`ef92b448` subject 57 chars, imperative, `daemon:` prefix, body
explains why. `4fdd4a36` subject 36 chars, `docs:` prefix. No
`Signed-off-by` — consistent with repo (verified across 20 recent
commits, none use it). `Co-Authored-By` line follows `.claude`
convention. Good.

## Docs (`docs/785-d3-validation.md`)

- Commit message says median CoV "51.2 % to 39.5 %"; doc reports
  current-branch median 38.8 / earlier-run median 37.1. "39.5" is in
  neither the doc nor the PR description. Reconcile.
- Methodology never cites the flow count / duration / interface;
  PR description has `iperf3 -P 12 -t 20 -p 5203`. The doc should
  restate this so it stands alone.
- Run 5 CoV = 19.2 % agrees with commit body claim. Consistent.
- Claim "D3 is a clean, low-risk improvement. Ship." is editorial;
  not a technical defect.

## Where the code holds up

- `rssExecutor` dependency injection is minimal (three methods), the
  exact surface needed (`rss_indirection.go:45-55`).
- `computeWeightVector` is pure with full branch coverage: `workers==1`,
  `workers==queues`, `workers>queues`, `4-of-6`, `4-of-8`, zero inputs.
- Call ordering — `applyRSSIndirection` runs from
  `enumerateAndRenameInterfaces` before the routing/FRR/dataplane init
  at `daemon.go:473+`. The "before XSK bind" invariant holds by
  structure, not by coincidence.
- Error propagation shape: D3 failures never fail interface bring-up.
  Correct for a best-effort optimization.
- Config gating at `daemon.go:463-465` checks both
  `DataplaneType == "userspace"` and `UserspaceDataplane != nil`. Safe.
- Package comment (`rss_indirection.go:1-22`) documents invariants and
  the rationale for a sibling file. Good discipline.

## Priority summary

| Sev    | Finding                                          |
|--------|--------------------------------------------------|
| MEDIUM | `isExecNotFound` substring → `errors.Is(err, exec.ErrNotFound)` |
| MEDIUM | `TestApplyRSSIndirection_NonMlx_Skips` is a tautology, no-op |
| MEDIUM | `applyRSSIndirection` top-level not injectable; sysfs scan untested |
| LOW    | Dead field `ethtoolXFailNotFound` in test fixture |
| LOW    | Boot-time log noise on non-userspace deploys     |
| LOW    | Idempotency claim untested on re-invocation      |
| LOW    | Commit/doc median CoV numbers disagree           |
