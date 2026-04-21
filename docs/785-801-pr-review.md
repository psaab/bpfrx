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
