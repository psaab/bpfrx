### Round 5 Adversarial Architecture Review: xpf Issue #2114 (v5 Plan)

---

### Executive Summary & Analysis of v5 Delta

#### 1. RACE-3 Chain Verification: Recovered Commit-Confirmed Rollback Timer vs Boot Publication
* **Registration & Trigger**: `d.store.SetRollbackExecutor(d.executeConfirmedRollback)` is wired at `pkg/daemon/daemon_run.go:136`, prior to phase-1 config loading. Phase 1 (`d.loadAndBootstrapConfig()`) invokes `Store.Load()`. Inside `pkg/configstore/store_persist.go:237-253`, if a commit-confirmed window was active across a restart (`rec.FirstCommit` or pending target), `time.AfterFunc(remaining, ...)` is re-armed with an arbitrarily short remaining duration (down to nanoseconds if expired right at boot).
* **Execution & Lock Mismatch**: When the timer fires, `fireConfirmTimer` runs on a Go timer runtime goroutine and invokes `executeConfirmedRollback(gen)` (`pkg/daemon/daemon_apply_commit.go:629`). `executeConfirmedRollback` acquires `d.applySem` and proceeds to read `d.dp` either via `d.enterBootstrapMode()` -> `bootstrap.go:472` (`d.dp.Teardown()`) or via `applyConfigLocked` -> `daemon_apply_dataplane.go:98+`.
* **Publication Race**: Meanwhile, on the main `Run` goroutine, Phase 3 bringup (`setupDataplaneAndInitialConfig` in `pkg/daemon/daemon_run_bringup.go:448, 464, 469, 497`) assigns `d.dp` (`d.dp = dp` or `d.dp = nil`) **without holding `d.applySem`**. Because `applySem` serializes apply-vs-apply operations but does not order Phase 3 bringup assignments, `executeConfirmedRollback` and `setupDataplaneAndInitialConfig` execute concurrently.
* **Conclusion**: RACE-3 is a valid, structural data race on the un-synchronized `d.dp` interface value.

#### 2. RACE-1 Watcher Chain Inclusion Verification (`daemon_ha_userspace_readiness.go:202`)
* **Call Chain**: `watchClusterEvents` is launched in `initManagers` (`pkg/daemon/daemon_run_bringup.go:203`), prior to Phase 3 dataplane publication (`:469`). An incoming cluster transition triggers event handler `watchClusterEvents` (`pkg/daemon/daemon_ha.go:310` or `:360`), calling `removeBlackholeRoutes` (`:1124`) or `injectBlackholeRoutes` (`:1065`), which calls `d.userspaceDataplaneActive()`.
* **Direct Unsynchronized Read**: `userspaceDataplaneActive()` (`pkg/daemon/daemon_ha_userspace_readiness.go:202`) performs `if runtime, ok := d.dp.(userspaceRuntimeModeReporter); ok`, reading `d.dp` concurrently with Phase 3 publication.
* **Conclusion**: Moving line 202 into the pre-publication RACE-1 watcher set is accurate.

#### 3. Consistency & Test Gate Assessment
* **Four-Link Exclusion Nuance**: Section 2 link (iv) states that `enterBootstrapMode` cannot follow a config with a live cluster runtime. In the rare case where a fresh store's *first commit* included cluster configuration and timed out under `commit confirmed`, `rec.FirstCommit` causes `PromoteRollback` to return `prevCfg == nil`, steering `executeConfirmedRollback` to `enterBootstrapMode` while `d.cluster` was initialized during bringup. However, Option A1's uniform atomic publication cell (`dpCell`) covers all 134 read sites regardless of HA reachability, eliminating any risk.
* **Two-Sided Gate Soundness**: The RACE-3 test design (`TestDataplaneCell_ConfirmTimerVsBootPublication` in §9 item 2) gates the boot-side store immediately *before* `setDataplane(dp)` and the rollback reader immediately *before* `d.dataplane()`. Both wait on a shared `release` channel without cross-goroutine channel signals between the accesses. Once released, the accesses run concurrently. On the raw field this deterministically triggers Go's `-race` detector, while on `dpCell` it is clean. The barrier pattern is free of happens-before flaws.

#### 4. Residual Repairs Spot-Check
* Stream rows (`daemon_ha_userspace_stream.go:122`, `:235`), registration guard (`daemon_run.go:284`), sustained-quiescence teardown polling (§9), table-driven typed-nil matrix over all nillable kinds (§9), and expanded comment sweeps (`daemon_apply_commit.go:156`, `daemon_natpoolalarm.go:88`, `cluster_topology_preflight.go:59`) are correctly detailed and aligned.

---

### Findings

#### MAJOR
* *None.* (The v5 delta successfully integrates RACE-3 and the readiness watcher link without introducing structural regressions or breaking existing invariants.)

#### MINOR
* [docs/research/2114-nat-pool-alarm-dp-race/plan.md:106-117](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L106-L117): **Minor wording imprecision in 4-link exclusion statement (iv)**. Section 2 states `enterBootstrapMode` "cannot follow a config that had a live cluster runtime". If an initial unconfirmed commit on a fresh store introduced cluster configuration and timed out, `rec.FirstCommit` causes `executeConfirmedRollback` to see `prevCfg == nil` and call `enterBootstrapMode` while `d.cluster` was constructed at Phase 3 bringup. Option A1's uniform accessor renders this harmless, but the prose could note this edge case for completeness.

---

VERDICT: PLAN-READY
