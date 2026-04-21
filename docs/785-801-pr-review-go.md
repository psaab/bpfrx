ROUND 2: merge-ready YES from Go angle

# PR #803 Go-quality review

Branch: `pr/801-sysctl-coalescence` (commits `7f100cf3`, `c27e09c9`,
`7c12fc95`, `ed822747`).

Focus: Go idioms, test coverage, config-schema plumbing. (Codex owns
architectural/measurement angle; not duplicated here.)

## Verification

- `go build ./...` — clean on branch.
- `go test -run 'Coalescence|HostTunables|NetdevBudget|CPUGovernor|Step0'
  ./pkg/daemon/... ./pkg/config/...` — PASS.
- `go vet ./pkg/daemon/...` — reports the two pre-existing
  `flowexport.NewExporter` lock-copy warnings from master; the PR does
  not introduce new vet diagnostics.
- PR-introduced tests: 18 (`TestParseEthtoolCoalesce_*` ×3,
  `TestApplyCoalescence_*` ×7, `TestResolvedHostTunables_*` ×4,
  `TestApplyCPUGovernor_*` ×5, `TestApplyNetdevBudget_*` ×5,
  `TestApplyHostTunables_AppliesBoth`, plus three config tests
  `TestUserspaceDataplaneStep0Knobs*`). All injection-friendly — the
  fakes (`fakeRSSExecutor`, `fakeHostFS`) are in-process, no shell-out.

## Findings

### F1 [LOW] CLI tree is not updated for the three new knobs

- Summary: `pkg/cmdtree/tree.go` is the project's single source of
  truth for tab completion and `?` help across local CLI, remote CLI,
  and gRPC. The schema in `pkg/config/ast.go` picked up
  `cpu-governor`, `netdev-budget`, `coalescence {adaptive|rx-usecs|tx-usecs}`,
  but `pkg/cmdtree/tree.go` was not touched — and grepping it shows it
  has never listed `rss-indirection` either.
- Citation: `grep -n 'rss-indirection|cpu-governor|netdev-budget|coalescence'
  /home/ps/git/bpfrx/pkg/cmdtree/tree.go` → 0 hits. `pkg/config/ast.go:1380-1386`.
- Mitigation: Pre-existing gap for `rss-indirection`; this PR just
  continues the pattern. Not a merge blocker, but worth filing a
  follow-up (`#systemdataplane cmdtree entries`) so the next PR adds
  all four knobs at once. Tab completion for config leaves still works
  via the schema walker — the ask is aesthetic: `?` help descriptions
  under `set system dataplane ...`.

### F2 [LOW] "cpu governor skip (no cpufreq sysfs — VM?)" is Info on every commit

- Summary: `applyCPUGovernor` logs at `slog.Info` when the requested
  governor is set but no `/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor`
  nodes exist. On a VM this fires at startup (one-time, fine) and again
  on every config commit via `applyConfig()` — i.e. at the cadence the
  operator commits. CLAUDE.md says "Info only for state transitions".
  This is not a state transition on commit #2+.
- Citation: `pkg/daemon/host_tunables.go:108-113`; reconcile site
  `pkg/daemon/daemon.go` in `applyConfig()` (new block added by
  commit `ed822747`).
- Mitigation: Demote to `slog.Debug` after the first fire, or guard
  with a package-level `sync.Once` so the VM skip line appears exactly
  once per process. The other two Info lines (`cpu governor applied`,
  `netdev_budget applied`, `coalescence applied`) are correctly gated
  behind the idempotency `return` and only fire on actual writes, so
  they do pass the state-transition bar.

### F3 [LOW] `coalescence adaptive <anything-not-"enable">` silently disables adaptive

- Summary: `compileUserspaceDataplane` treats any value for
  `coalescence adaptive X` other than literal `"enable"` as disable —
  including typos (`set ... adaptive enabl`). The schema (`args:1`)
  allows any single token. There is no validation that the value is
  one of `{enable, disable}`.
- Citation: `pkg/config/compiler_system.go:480-487`. Schema:
  `pkg/config/ast.go:1382` (`"adaptive": {args: 1, desc: "... (enable|disable)"}`).
- Mitigation: Add a validation step that rejects values other than
  `enable` / `disable` in the compiler (`compileUserspaceDataplane`),
  or add a commit-check to `pkg/configstore` validation. Since the
  daemon's behavior on `disable` is also the default, the blast radius
  is small (typo = default) — documenting this as "permissive parse"
  is acceptable for now, but should be noted.

### F4 [LOW] `CoalescenceAdaptiveExplicit` field is a bit subtle

- Summary: The doc comment on `UserspaceConfig` explains the semantics
  but the flag is load-bearing — the daemon reads `Explicit && !Disabled
  → coalesceEnable=true` at two sites in `daemon.go`. Missing
  `Explicit` means "default apply adaptive=off", which the PR's test
  `TestUserspaceDataplaneStep0Knobs_OmittedDefaultsToZero` asserts
  cleanly. But when `Explicit=true && Disabled=true`, both
  `applyConfig` and `Run` produce identical behavior to
  `Explicit=false` — i.e. an operator who writes `adaptive disable`
  explicitly is indistinguishable from one who omits it. Fine, but
  means `Explicit` is really "operator opted into `enable`" rather than
  the more general name suggests.
- Citation: `pkg/daemon/daemon.go` (two blocks inside `Run()` and
  `applyConfig()` added by `ed822747`), `pkg/config/types.go:492-504`.
- Mitigation: Consider renaming to `CoalescenceAdaptiveEnable bool`
  and dropping `Disabled` + `Explicit` — single tri-state isn't needed
  once you accept that "omitted" = zero = disable. Not merge-blocking;
  the current shape is tested and works.

### F5 [INFO] Test isolation looks correct; no shell-out

- The tests uniformly use the injectable `rssExecutor` / `hostTunableFS`
  interfaces. `fakeRSSExecutor` was extended (not duplicated) with
  `ethtoolC map[string][]byte` for the `-c` probe, which is the
  right call — reuses the existing "-x" plumbing, and the fake error
  path correctly returns `exec.ErrNotFound` so `errors.Is(err,
  exec.ErrNotFound)` works in production.
- `TestFakeHostFS_ErrorSurface` explicitly pins the `errors.Is` /
  `fs.ErrPermission` contract so a future fake refactor can't break
  the permission-denied code path silently. Nice.
- All `applyCoalescence*` and `applyCPUGovernor_*` tests drive the
  per-iface loop, the kill-switch/idempotent paths, and the
  partial-failure continuation — no gaps.

### F6 [INFO] Config schema round-trip: clean

- `set system dataplane coalescence adaptive disable` →
  `Keys=["adaptive","disable"]` → compiler yields
  `Explicit=true, Disabled=true`. `FormatSet()` walks the AST and
  emits the literal path back: `set system dataplane coalescence
  adaptive disable`. Parser → compiler → formatter roundtrip is
  symmetric because the schema is data-driven and the state it carries
  (`Explicit`) is a derived compiler field, not stored in the AST.
- `netdev-budget` and `cpu-governor` both roundtrip as single-arg
  leaves — no formatter changes needed.

### F7 [INFO] Package dependencies

- `pkg/daemon/host_tunables.go` imports `errors`, `log/slog`, `os`,
  `path/filepath`, `strconv`, `strings`. Every one is already used
  elsewhere in `pkg/daemon` — no new stdlib surface.
- `pkg/daemon/coalescence.go` imports `bufio`, `bytes`, `log/slog`,
  `strconv`, `strings`. `bufio` is new to the package (single use for
  line-scanning `ethtool -c` output) — benign.
- No new `os/exec` or `syscall` imports outside the existing
  `rss_indirection.go` path. Fine.

### F8 [INFO] Reconcile idempotency: verified

- `applyRSSIndirection` + `applyHostTunables` + `applyCoalescence` are
  all driven unconditionally from `applyConfig()` on every commit.
  Each has an explicit read-before-write idempotency check:
  - Governor: `readFile` + `strings.TrimSpace` compare, hit Debug on
    match (`host_tunables.go:121-124`).
  - netdev_budget: `readFile` + `strings.TrimSpace` compare
    (`host_tunables.go:176-180`).
  - Coalescence: `ethtool -c` probe + `coalescenceMatches()` compare,
    Debug on match (`coalescence.go:109-115`).
- Double commit with no config change → zero writes, zero Info logs
  (except the F2 VM-skip line).

## ROUND 1 verdict

Merge-ready **YES**, modulo F2 (demote VM-skip Info log) which is a
style nit rather than a correctness issue. F1/F3/F4 are worth a
follow-up commit but do not block merge — tests are comprehensive,
injection-friendly, and cover the exact `Explicit + Disabled` matrix
the daemon reads. Config schema plumbing is complete on the
parse/compile/format paths; the CLI tree gap in F1 is pre-existing.

## Round 2 verification

Commits reviewed: `b9698401`, `5100596e`, `0b2a430b`.
Fresh `go test ./pkg/daemon/ ./pkg/config/` passes; `go build` clean.

### Round-1 findings

- **F1 cmdtree — CLOSED.** `ConfigSetDataplaneKnobs` added in
  `pkg/cmdtree/tree.go:869-879`, wired at `tree.go:896` under
  `ConfigTopLevel["set"].Children["system"].Children["dataplane"]`.
  Surfaces `?` help + tab for rss-indirection, claim-host-tunables,
  cpu-governor, netdev-budget, and the coalescence subtree
  (adaptive/rx-usecs/tx-usecs) with per-knob Desc strings.

- **F2 VM-skip log — CLOSED.** `vmSkipLogOnce sync.Once` at
  `host_tunables.go:86` gates the Info emission. Subsequent reconciles
  fall through to `slog.Debug` at `host_tunables.go:192-193`. The Once
  also adjudicates the M1 bare-metal WARN branch (same gate, single
  emission per process).

- **F3 coalescence adaptive parse — PARTIAL.** `compiler_system.go:490-495`
  treats `"enable"` as the only positive token and lumps `"disable"`,
  `""`, and any unknown value into the "adaptive off" branch. Explicit
  validation of the `enable|disable` vocabulary is still missing —
  typo like `adaptive disble` silently flips adaptive off. Not a
  merge blocker (prior R1 call).

- **F4 CoalescenceAdaptiveExplicit + Disabled collapse — PARTIAL
  (unchanged).** Still two fields on `UserspaceDataplaneConfig`
  (`types.go:518-519`). Daemon read at `daemon.go:2386-2389` still
  derives `coalesceEnable` via the combined check. Follow-up, not
  blocker.

### Round-2 new angles

- **`priorHostTunables` concurrency — OK.** `Daemon.priorTunablesMu
  sync.Mutex` guards `priorTunables`/`priorTunablesActive`
  (`daemon.go:271`). All four accessors in `host_tunables_daemon.go`
  (lines 63/74/105/120) acquire/release correctly. The map mutations
  inside `captureGovernor`/`captureBudget`/`captureMlx5Coalesce` happen
  only while the caller owns the logical apply window (startup +
  serialized `applyConfig` reconcile), so no intra-apply races. Shutdown
  path reads-then-nils under lock before restoring outside the lock,
  which is safe because `applyConfig` can't run concurrently with Stop.

- **Restore on SIGTERM — OK.** `restoreStep0TunablesOnShutdown` called
  from `daemon.go:1325` on the shutdown path, which `signal.NotifyContext`
  (line 646/648) drives for SIGTERM + SIGINT. Synchronous, no flush/
  timeout wrapper — sysfs writes are small atomic `os.WriteFile` calls;
  systemd `TimeoutStopSec=20` is the safety net. Runs on both hitless
  and fail-closed shutdown.

- **VM heuristic idiomatic — OK.** `vmHeuristic`
  (`host_tunables.go:105-122`) uses the `hostTunableFS.readFile`
  abstraction (tests mock without shelling out), probes
  `/sys/hypervisor/type` then the `/proc/cpuinfo` `hypervisor` flag via
  line-by-line `strings.Fields` scan. No `systemd-detect-virt` shellout
  (despite the comment mentioning it) — keeps the dependency surface
  minimal. No pre-existing VM-detection helper in the repo to unify
  with; implementation is self-contained.

- **Tests — STRONG.** `host_tunables_restore_test.go` (313 lines, 9
  tests) covers: B1 opt-in-false-writes-nothing, B2 capture+write,
  B2 restore-on-flip-reverts-to-pre-xpfd (line 157 pins 450 NOT 300 —
  the exact "pre-xpfd not kernel default" invariant), first-apply-wins
  on reconcile, nil-restore no-op, empty-capture no-op, three VM
  heuristic branches, capture idempotence. Not strictly table-driven
  but each test is tightly scoped. The I1 invariant comment at line 158
  is explicit: `"should NOT be kernel default 300"`.

- **Evidence JSONs — REAL.** 15 files under `docs/801-evidence/runs/`.
  `wc -l` shows 1117/1137/4533 lines per matrix (grows with flow count),
  with valid iperf3 Start/Intervals/End structure. Tail of
  `p5201-fwd-1.json` ends in a complete `end.sum_sent` + `cpu_utilization_percent`
  block; not truncated. `summary.txt` matrix mean/stdev numbers
  (p5203-fwd stdev 0.188 Gbps across 5 runs) are consistent with the
  per-file `bits_per_second` sums.

### Round-2 verdict

No new blockers. F3/F4 remain style-grade follow-ups. Opt-in gate +
restore path + shutdown wiring + concurrency + tests + evidence are
all sound.
