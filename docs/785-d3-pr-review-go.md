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

---

## Round 2 verification (at `3453dec6`)

Fix commits: `6798f512` (primary feedback), `30401bfd` (CoV errata),
`3453dec6` (active restore on disable). Verified each prior finding
against the current tree; ran `go test ./pkg/daemon/ ./pkg/config/ -run
'RSS|Userspace' -count=1` — all pass.

### Prior findings

1. **Go MEDIUM #1 (substring match) — CLOSED.**
   `pkg/daemon/rss_indirection.go:360-366`: `isExecNotFound` now returns
   `errors.Is(err, exec.ErrNotFound)`. The brittle substring check and
   its stdlib-version comment are deleted entirely, not kept alongside.
   New test `TestIsExecNotFound_DetectsSentinel`
   (`rss_indirection_test.go:379-395`) covers wrapped `*exec.Error`,
   `*fs.PathError`, unrelated errors, and `nil`.

2. **Go MEDIUM #2 (tautological test) — CLOSED.**
   `TestApplyRSSIndirection_NonMlx_Skips`
   (`rss_indirection_test.go:193-203`) now calls
   `applyRSSIndirection(true, 4, f)` with a fake whose driver map is
   `virtio_net`/`iavf`, and asserts `len(f.calls) == 0`. A companion
   `TestApplyRSSIndirection_MixedDrivers_OnlyMlxTouched`
   (lines 207-243) pins that only the single mlx5 sibling in a
   `{lo, virt0, mlx0, iavf0}` set receives ethtool writes.

3. **Go MEDIUM #3 (non-injectable sysfs scan) — CLOSED.**
   `listInterfaces() []string` added to the `rssExecutor` interface
   (`rss_indirection.go:64-67`); production impl reads
   `/sys/class/net` (lines 99-109); the top-level scan now goes through
   `execer.listInterfaces()` (line 154). Every top-level test populates
   `fakeRSSExecutor.ifaces`.

4. **Go LOW #1 (dead `ethtoolXFailNotFound` field) — CLOSED.**
   The field is gone from the fixture
   (`rss_indirection_test.go:22-35`). ErrNotFound is now produced by
   the fake's `runEthtool` returning `&exec.Error{Err: exec.ErrNotFound}`
   when the `-x` probe has no scripted entry (lines 41-48), which the
   `EthtoolMissing_SkipsGracefully` test exercises.

5. **Go LOW #2 (boot log noise) — CLOSED.**
   `rss_indirection.go:143-147`: `workers <= 0` path now uses
   `slog.Debug`. The `workers == 1` path remains `slog.Info` (explicit
   operator choice). The new kill-switch path also logs `slog.Info`
   (line 140) which is appropriate — operator-visible state change.

6. **Go LOW #3 (untested idempotency) — CLOSED.**
   `TestApplyRSSIndirection_TwiceIsIdempotent`
   (`rss_indirection_test.go:323-352`) asserts first call = 1 probe,
   second call = +1 probe and no write.

7. **Go LOW #4 (commit/doc CoV mismatch) — CLOSED via errata.**
   `30401bfd` adds an Errata section to `docs/785-d3-validation.md`
   recording the correct 38.8 % median without rewriting history.
   Acceptable per project norm.

### Round 2 new-angle findings

8. **Test quality — CLEAN.** New tests exercise real branches
   (driver gate, kill switch, mixed fleet, twice-call, restore path).
   None are tautological. `TestUserspaceDataplaneRSSIndirectionDisable`
   (`pkg/config/parser_ast_test.go:2693-2735`) is table-driven across
   `disable`/`enable` and uses `ParseSetCommand`+`SetPath` as required
   by CLAUDE.md. Not worth splitting further.

9. **Config plumbing — CLEAN.** `UserspaceConfig.RSSIndirectionDisabled`
   (`pkg/config/types.go:462`) is an inverted bool tagged
   `omitempty`, so the safe default (enabled) is the zero value and
   omitted from JSON when on. Schema entry in `ast.go:1379`, compiler
   in `compiler_system.go:448-454` keys on `"disable"` only — typos
   fail safe to enabled. Default-enabled is pinned by
   `TestUserspaceDataplaneConfig`
   (`parser_ast_test.go:2684-2687`).

10. **Restore-on-disable path — LOW (documented behavior).**
    `restoreDefaultRSSIndirection` (`rss_indirection.go:182-208`)
    runs `ethtool -X <iface> default`, which reverts to the
    **driver's** default equal-weight table — not a snapshot of
    pre-xpfd weights. If an operator had pre-set a custom
    indirection table before starting xpfd, engaging the kill
    switch will overwrite their custom layout with driver defaults,
    not restore theirs. Mitigation: document this in the
    `rss-indirection disable` help text or in `docs/785-d3-validation.md`.
    Snapshot/replay would require reading and storing the pre-apply
    table, adding state across config commits — not worth it for a
    kill switch. Behavior is acceptable; just undocumented.

11. **Error handling on reapply — CLEAN.** `applyRSSIndirection`
    returns nothing by design (`rss_indirection.go:131`), all errors
    are logged and swallowed inside `applyRSSIndirectionOne` /
    `restoreDefaultRSSIndirection`. `reapplyRSSIndirection`
    (`linksetup.go:115-117`) is a void wrapper. A failed reapply
    cannot crash `applyConfig`; it just logs `slog.Warn`. Matches
    the "D3 is best-effort, never fails interface bring-up" invariant.

12. **API surface — CLEAN.** No new exported identifiers.
    `rssExecutor`, `realRSSExecutor`, `applyRSSIndirection`,
    `reapplyRSSIndirection`, `restoreDefaultRSSIndirection` are all
    lowercase. `RSSIndirectionDisabled` is the only new exported
    name and it is a typed-config field, which is the intended
    public surface. `enumerateAndRenameInterfaces` signature grew
    from 3 to 4 scalars (`rssEnabled` added); the prior `LinkSetupOpts`
    suggestion stands but is still a stylistic LOW, unchanged.

### Merge readiness (Go-quality)

All 3 MEDIUM and all 4 LOW findings are closed or accepted. The
restore-on-disable semantic is the only net-new mild concern and
warrants a doc sentence but not a code change. No regressions in Go
idioms; tests compile and pass. Ship it from the Go angle.


