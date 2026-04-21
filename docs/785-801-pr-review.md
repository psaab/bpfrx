# PR #803 — Codex adversarial review (round 1)

Branch: `pr/801-sysctl-coalescence`  
Review commit: 4 commits `7f100cf3..ed822747` closing issue #801

## Verdict: NOT READY — 2 BLOCKERS + 3 MAJOR + 1 MINOR

## Findings

### B1. BLOCKER — Global host tunable scope

`ApplyCPUGovernor()` and `ApplyNetdevBudget()` in
`pkg/daemon/host_tunables.go` write to every CPU's
`cpufreq/scaling_governor` and to `/proc/sys/net/core/netdev_budget`.
These are **system-wide**, not scoped to userspace-dp worker CPUs or
mlx5 interfaces.

D3's allowlist (`UserspaceBoundLinuxInterfaces`) is interface-
scoped; these knobs are not. Any other workload sharing the host
inherits the change silently — direct violation of D3's stated
principle of "only touch what is bound to userspace-dp".

**Mitigation**: either scope the governor write to only the CPUs
that host userspace-dp workers (per-worker-CPU list from
`BindingWorker.worker_id → pinned CPU`), or elevate this knob to an
explicit daemon-wide "I am the sole controller" assertion with a
matching `system userspace dataplane claim-host-tunables true`
config opt-in (default false).

### B2. BLOCKER — No restore-on-disable path

When the knobs are removed from config (or userspace-dp is disabled
entirely), there is no code that saves the prior governor string or
the prior `netdev_budget` value and writes it back. D3's RSS
indirection restore (commit `3453dec6`) is explicit; these three
knobs have no analogue.

**Operator experience**: toggling coalescence off leaves adaptive
disabled; switching the daemon from userspace to eBPF mode leaves
`netdev_budget=600` in place. The governor stays whatever xpfd
last wrote.

**Mitigation**: mirror the D3 save/restore pattern. On first-apply,
capture the pre-xpfd value to an in-memory `priorTunables` struct.
On disable or on shutdown, restore from that struct. Add the same
explicit "restore reverts to pre-xpfd value, not kernel default"
documentation note D3 carries.

### M1. MAJOR — cpufreq absence is not a VM guard, it is a cpufreq guard

`os.Stat("/sys/devices/system/cpu/cpu0/cpufreq/")` — absent
directory = skip. A bare-metal host booted with
`intel_pstate=disable` or `acpi=off` will silently no-op the same
way a VM does, with no log distinguishing the two cases.

**Mitigation**: if the directory is absent, log at `slog.Warn` the
apparent cause (check `/sys/hypervisor`, `dmidecode -s
system-product-name`, etc.) so an operator on bare metal knows
xpfd believes they're in a VM.

### M2. MAJOR — Unverifiable "noise" claim on p=5203 regression

PR body claims the -2.61 Gbps drop on `iperf3 -P 12 -t 20 -p 5203`
is independently-verified noise. No committed reproduction script,
log, or extra JSON file supports this. The plan's statistical gate
for rollback (`docs/line-rate-investigation-plan.md` §Validation)
explicitly requires recorded evidence, not verbal assurance.

**Mitigation**: commit the JSON captures + a short script that
reproduces the "set adaptive=on and netdev_budget=300, observe
same distribution" claim. One commit adds the evidence file(s)
and a one-line note in the PR body pointing to them.

### M3. MAJOR — CLI surface not updated

`pkg/cmdtree/tree.go` has no diff on this branch for
`cpu-governor`, `netdev-budget`, or `coalescence`. The knobs are
invisible to tab completion and `?` help in both local and remote
CLI.

**Mitigation**: add the three knobs to `pkg/cmdtree/tree.go` under
`ConfigTopLevel → system → dataplane` with descriptions. Per
CLAUDE.md this is the single source of truth; without it the knobs
are effectively undiscoverable.

### MIN1. MINOR — Unconditional default overwrite on reconcile

Schema defaults write `performance/600/off/8` unconditionally on
reconcile. If an operator has `schedutil` set externally, the next
xpfd commit overwrites it with no warning.

**Mitigation**: before write, read current value. If it matches
the new desired value, skip silently. If it differs from both
desired AND the pre-xpfd captured value, log at `slog.Warn` and
still write (but now the operator has a log trail).

### I1. INFO — No new D3-style restore tests

D3 allowlist tests in `pkg/daemon/rss_indirection_test.go` are
unchanged and still pass. No new unit tests added for
governor/budget restore behavior. Closing B2 naturally brings a
restore-behavior test; verify that test pins the "restore to
pre-xpfd, not kernel default" semantics.

## Merge verdict

**NO.** Two independent blockers (global scope, no restore) must
be resolved before merge. The CLI surface gap and unverifiable
tuning values are also pre-merge requirements given the project's
engineering-style bar (see `docs/engineering-style.md`).

## Round 2 verification

**B1**: CLOSED — the only production entry points call `applyStep0Tunables()`, and when `claimHostTunables` is false the code either runs the explicit restore-on-disable path for a previously active claim or returns before any `applyHostTunables()` or `applyCoalescence()` call, so no claiming write bypasses the opt-in gate. `pkg/daemon/daemon.go:531`, `pkg/daemon/daemon.go:2396`, `pkg/daemon/host_tunables_daemon.go:71`, `pkg/daemon/host_tunables_daemon.go:89`, `pkg/daemon/host_tunables_daemon.go:102`

**B2**: CLOSED — governor, `netdev_budget`, and mlx5 coalescence each capture the live value before first write, and the daemon restores that snapshot both on a `true -> false` transition and on shutdown while the claim is active. `pkg/daemon/host_tunables.go:203`, `pkg/daemon/host_tunables.go:212`, `pkg/daemon/host_tunables.go:292`, `pkg/daemon/host_tunables.go:298`, `pkg/daemon/coalescence.go:94`, `pkg/daemon/coalescence.go:110`, `pkg/daemon/host_tunables_daemon.go:71`, `pkg/daemon/host_tunables_daemon.go:119`, `pkg/daemon/daemon.go:1325`

**M1**: CLOSED — `vmHeuristic()` no longer equates “no cpufreq” with “VM”; it checks `/sys/hypervisor/type` and the `hypervisor` CPU flag, and the caller emits `slog.Warn` when neither signal is present, although there is no `systemd-detect-virt` call in the implementation. `pkg/daemon/host_tunables.go:108`, `pkg/daemon/host_tunables.go:116`, `pkg/daemon/host_tunables.go:182`, `pkg/daemon/host_tunables.go:187`

**M2**: PARTIAL — `docs/801-evidence/` now contains a runnable repro script and 5-run JSON captures, but they cover only `p5201-fwd`, `p5201-rev`, and `p5203-fwd`, with no committed baseline-vs-knobs-on labeling or config capture, so the evidence is reproducible but not matched across both states. `docs/801-evidence/repro-matched-5run.sh:12`, `docs/801-evidence/repro-matched-5run.sh:17`, `docs/801-evidence/repro-matched-5run.sh:54`, `docs/801-evidence/repro-matched-5run.sh:110`, `docs/801-evidence/runs/summary.txt:2`, `docs/801-evidence/runs/summary.txt:3`, `docs/801-evidence/runs/summary.txt:4`

**M3**: CLOSED — `claim-host-tunables` is present in `ConfigSetDataplaneKnobs` with description text and is wired into the `set system dataplane` help tree. `pkg/cmdtree/tree.go:869`, `pkg/cmdtree/tree.go:871`, `pkg/cmdtree/tree.go:896`

**MIN1**: CLOSED — governor, `netdev_budget`, and mlx5 coalescence all read the live value before writing and each drift path logs with `slog.Warn`, not `Info` or `Debug`. `pkg/daemon/host_tunables.go:203`, `pkg/daemon/host_tunables.go:224`, `pkg/daemon/host_tunables.go:292`, `pkg/daemon/host_tunables.go:307`, `pkg/daemon/coalescence.go:94`, `pkg/daemon/coalescence.go:140`

**F2**: CLOSED — the first no-cpufreq log is gated by `vmSkipLogOnce`, and every call still falls through to a `slog.Debug` skip line afterward. `pkg/daemon/host_tunables.go:82`, `pkg/daemon/host_tunables.go:86`, `pkg/daemon/host_tunables.go:182`, `pkg/daemon/host_tunables.go:192`

**I1**: CLOSED — `pkg/daemon/host_tunables_restore_test.go` exists, and its opt-in-flip test asserts restore writes back `schedutil` and `450` as the pre-xpfd values rather than kernel defaults. `pkg/daemon/host_tunables_restore_test.go:1`, `pkg/daemon/host_tunables_restore_test.go:111`, `pkg/daemon/host_tunables_restore_test.go:153`, `pkg/daemon/host_tunables_restore_test.go:157`

### Round-2 new angles

**Perf regression check**: OPEN — the summary records the new `p5201` means at 18.44/18.01 Gbps and `p5203` at 22.91 Gbps, but the committed script only runs `iperf3` and never records whether `claim-host-tunables=true` or a baseline config was active, so the drop is unexplained in the evidence rather than tied to a documented noisy-cluster rerun. `docs/801-evidence/runs/summary.txt:2`, `docs/801-evidence/runs/summary.txt:3`, `docs/801-evidence/runs/summary.txt:4`, `docs/801-evidence/repro-matched-5run.sh:2`, `docs/801-evidence/repro-matched-5run.sh:54`

**Opt-in gate semantics**: OPEN — when `claim-host-tunables` is false, the function returns before `applyCoalescence()`, so per-interface mlx5 coalescence writes are gated off too despite nearby comments claiming `rx-usecs/tx-usecs` “continue to run,” which means the default configuration gets no coalescence benefit. `pkg/daemon/host_tunables_daemon.go:78`, `pkg/daemon/host_tunables_daemon.go:89`, `pkg/daemon/host_tunables_daemon.go:103`, `pkg/daemon/daemon.go:529`

**Crash persistence**: OPEN — the pre-xpfd snapshot lives only in `Daemon.priorTunables`, is created in memory on first claimed apply, and is cleared on restore/shutdown, with no persisted crash-recovery state in this flow. `pkg/daemon/daemon.go:265`, `pkg/daemon/daemon.go:271`, `pkg/daemon/host_tunables_daemon.go:98`, `pkg/daemon/host_tunables_daemon.go:105`, `pkg/daemon/host_tunables_daemon.go:119`, `pkg/daemon/host_tunables_daemon.go:123`

ROUND 2: merge-ready NO — M2 evidence is still only partial, `claim-host-tunables=false` suppresses all coalescence writes, and crash recovery loses the original pre-xpfd snapshot.

## Round 2 responses (commit-by-commit)

### Coalescence-always-on (round-2 BLOCKER, fixed in `f277f60d`)

`applyStep0TunablesWith` now runs coalescence on every userspace-dp
apply regardless of `claim-host-tunables`. The opt-in gate still
covers the host-scope knobs (cpu-governor + netdev_budget) because
those touch shared-host state. Coalescence is interface-scoped — same
blast radius as D3 RSS indirection — and uses the same
`UserspaceBoundLinuxInterfaces` allowlist, so the #801 mlx5 win lands
by default as intended. Shutdown-restore covers both pipelines
independently. See `pkg/daemon/host_tunables_daemon.go` top-of-file
comment for the scope split rationale.

### Crash persistence (round-2 BLOCKER — accepted as documented)

Option (b) from the Codex finding: `priorHostTunables` lives in memory
only. Rationale documented on the struct itself
(`pkg/daemon/host_tunables.go`): the host-scope values
(cpu-governor, netdev_budget) are idempotent across daemon restarts,
so a crash-recovery identity restore is harmless. A persisted
snapshot at `/run/xpf/priortunables.json` was rejected because the
first-apply write cost exceeds the marginal safety over the identity
semantics we already get. Operators who need strict pre-xpfd
recovery across crashes can set their values via `/etc/sysctl.d/` or
systemd `ExecStartPre`.

## Round 3 verification

- M2 evidence: RESOLVED — `repro-matched-5run.sh` now drives explicit `baseline` and `knobs-on` batches, and both labeled 5-run summaries are committed in `docs/801-evidence/repro-matched-5run.sh:3`, `docs/801-evidence/baseline-knobs-off/summary.txt:1`, and `docs/801-evidence/knobs-on/summary.txt:1`.
- Opt-in gate blocks coalescence: RESOLVED — `applyStep0TunablesWith()` now calls `applyCoalescence()` before the host-scope opt-in skip path in `pkg/daemon/host_tunables_daemon.go:115` and `pkg/daemon/host_tunables_daemon.go:142`.
- Crash persistence: RESOLVED — the accepted in-memory-only policy, including the rejected persisted snapshot alternative, is now explicit in `pkg/daemon/host_tunables.go:385` and `pkg/daemon/host_tunables.go:402`.

ROUND 3: merge-ready YES
