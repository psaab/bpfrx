Reviewed exact commit `e9ac48db1`. The core atomic-cell design is implementable, but v4 is not ready as written because its RACE-1 reachability proof remains materially incomplete.

Fold status: M1 FOLDED; M2 PARTIAL; M3 PARTIAL; MINOR 1 FOLDED; MINOR 2 FOLDED; MINOR 3 PARTIAL.

## MAJOR

1. **R3 M3 — PARTIAL: “only six RACE-1 readers” is false.**

   The pre-publication watcher has an additional indirect `d.dp` read:

   - The watcher starts before publication at [daemon_run_bringup.go:203](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:203).
   - Promotion calls `removeBlackholeRoutes` at [daemon_ha.go:310](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha.go:310), which calls `userspaceDataplaneActive` at [daemon_ha.go:1123](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha.go:1123).
   - That function reads `d.dp` at [daemon_ha_userspace_readiness.go:202](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_userspace_readiness.go:202).
   - Demotion has the equivalent `daemon_ha.go:359-360 → :1064-1066 → readiness.go:202` path.

   Consequently [plan.md:396](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:396) incorrectly classifies readiness `:202` as post-publication uniformity-only.

   There is also a separate pre-publication chain through recovered commit-confirmed state:

   - The rollback executor is registered before startup phases at [daemon_run.go:130](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:130).
   - Phase-one `Store.Load` at [daemon_run_bringup.go:277](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:277) can re-arm a pending timer with an arbitrarily short remaining duration at [store_persist.go:231](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go:231).
   - Its timer goroutine dispatches at [store_commit.go:815](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go:815) into [daemon_apply_commit.go:629](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go:629).
   - First-commit rollback reads `d.dp` at [bootstrap.go:472](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:472); a non-nil rollback enters `applyConfigLocked`, including the unconditional read at [daemon_apply_dataplane.go:98](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_dataplane.go:98).
   - Boot writes at [daemon_run_bringup.go:448](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:448), `:464`, `:469`, and `:497` do not acquire `applySem`; therefore the rollback callback’s semaphore does not order these accesses.

   This invalidates the exclusivity claims at [plan.md:67](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:67), [plan.md:367](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:367), and [plan.md:607](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:607). The audit and RACE-1 regression coverage must include this timer path.

   The other specifically named early components did not reveal another chain: `ipmon.Start` is early but initially idle; DDNS objects are only constructed at [daemon_run_bringup.go:91](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:91) and their loops start post-publication at [daemon_run.go:549](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:549); SNMP first starts post-publication at [daemon_run.go:488](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:488).

## MINOR

1. **R3 M1 — FOLDED.**

   `Sampler.Start` primes synchronously at [sampler.go:64](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fwdstatus/sampler.go:64); `ReadSelfStat` occurs at `:93`, before the adapter load at `:112`. The writer stores nil only after failing `Start` returns at [daemon_run_naming.go:230](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_naming.go:230).

   Under [plan.md:535](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:535), closing the common release channel is a predecessor of both accesses, but neither post-release access happens-before the other. Both are guaranteed to execute, making the plain-field race deterministic as a memory-model proposition; atomic load/store is race-clean.

   Fresh nit: [plan.md:551](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:551) treats a stopped counter as a join substitute. With a one-second loop at [sampler.go:69](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fwdstatus/sampler.go:69), a temporarily stable counter does not prove exit. Require a done/join seam, or at minimum a synchronized counter, one-shot entry signal, successful fake stat result, and a bounded sustained-quiescence rule.

2. **R3 M2 — PARTIAL.**

   The arithmetic is correct: 163 greppable lines − 29 full-line comments = 134 executable references = 5 writers + 129 readers.

   The requested row repairs are correct: dead adapter methods are marked deleted; server `:255/:256` are BOOT-SYNC; NAT alarm `:101` is APPLY/BOOT-SYNC; shutdown `:161/:167/:173` are exclusion-unreachable while `:214-229` are RACE-2; `daemon_system.go:41` and `daemon.go:1012` have both boot and apply callers.

   Residual inconsistencies remain:

   - [plan.md:105](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:105) still says 128 readers.
   - [plan.md:80](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:80) still lists shutdown `:161` under RACE-2, contradicting its corrected table row.
   - [plan.md:381](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:381) labels all four userspace-stream reads standalone/RACE-2. Actual classification is `:122` mixed standalone/HA; `:67`, `:235`, and `:259` are HA/uniformity paths.
   - [plan.md:350](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:350) calls all four capture-once-at-goroutine-start. Actual `:235` is per full-resync callback, while `:259` is capture-once.
   - [plan.md:384](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:384) cites `daemon_run.go:288`; the registration guard is at `:284`.

3. **R3 MINOR 1 — FOLDED.**

   The kind-gated `IsNil` switch at [plan.md:175](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:175) covers all reachable nillable dynamic kinds. No `Interface` case is needed because interface assignment preserves the underlying dynamic concrete type; `UnsafePointer` is harmless.

   The remaining gap is only the test promise: [plan.md:478](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:478) says all shapes are tested, while [plan.md:509](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:509) specifies pointer, value, and named slice only—not named map, channel, or function.

4. **R3 MINOR 2 — FOLDED.**

   Option D at [plan.md:276](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:276) now fairly credits identity retention and rejects the option on concrete reader-ordering discipline, replacement, and precedent grounds. No remaining finding.

5. **R3 MINOR 3 — PARTIAL.**

   The four requested additions are present, but the sweep is incomplete:

   - [daemon_apply_commit.go:156](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go:156) still says bootstrap exits “one-way.”
   - [daemon_natpoolalarm.go:88](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_natpoolalarm.go:88) says the monitor is constructed and started “exactly once,” contradicting discard-and-rearm at `:118-126`.
   - [cluster_topology_preflight.go:59](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/cluster_topology_preflight.go:59) contains a second stale `daemon_run.go:1868` citation beyond the listed one at `:117`.

The plan should be revised before implementation: add both missing RACE-1 chains and corresponding test coverage, then repair the classification/comment inconsistencies.

VERDICT: NEEDS-REVISION

Codex session ID: 019f921b-6d2d-72a0-9493-a77c68088cb0
Resume in Codex: codex resume 019f921b-6d2d-72a0-9493-a77c68088cb0
