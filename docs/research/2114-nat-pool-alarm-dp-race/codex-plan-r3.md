v3’s core atomic-cell design remains viable, but the plan is not implementation-ready. The deterministic race test and the reachability audit are still materially wrong.

### Round 2 fold ledger

| R2 finding | Status | Result |
|---|---|---|
| M1 typed-nil panic | **FOLDED** | The pointer kind gate prevents `IsNil` panics on value implementations, and both requested test shapes are specified. A fresh nil-kind gap remains below. |
| M2 structural sampler-only | **FOLDED** | The one-method adapter cannot satisfy `DataPlaneAccessor` or `Build`. No hidden production caller was found. |
| M3 deterministic sampler barrier | **PARTIAL** | The real sampler participates, but the barrier orders the dataplane read before the writer, so it is not a deterministic race regression. |
| M4 exhaustive audit | **PARTIAL** | Every executable line is listed, but there are **134**, not 133, and multiple classifications remain false. |
| M5 four-link exclusion | **PARTIAL** | The exclusion proof is valid and no hidden cluster construction path exists; the blanket RACE-1 labeling is still wrong, including health. |
| M6 smoke specifics | **FOLDED** | All policy-required commands, thresholds, HA gates, and locking are present. |
| MINOR 1 transition state | **FOLDED** | `readyProbeOnly → userspace → nil` isolates the intended old-wrapper failure. |
| MINOR 2 Option D | **PARTIAL** | The representation correction is folded, but the rejection still relies on unfair/invalid objections. |
| MINOR 3 docs/canary sweep | **FOLDED** for the requested items | README `:936`, the three cited comments, renderer, canary filename, and self-tests are named. Fresh comment gaps remain. |

## MAJOR

1. **M3 PARTIAL — the real-sampler barrier does not cover the conflicting memory accesses.**

   `Sampler.Start` runs `sample` synchronously before spawning its loop at [sampler.go:64](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fwdstatus/sampler.go:64). Therefore `Start` itself must run on a goroutine; otherwise the blocking prime prevents the test from reaching the writer. v3 does not state that.

   More importantly, the proposed daemon adapter loads the dataplane before invoking the fake’s `CachedStatus` at [plan.md:231](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:231); current equivalent control flow is visible at [daemon_forwarding_status.go:107](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_forwarding_status.go:107). Thus:

   `d.dp read → entered signal → test receives entered → arm-failure write`

   The channel barrier happens-before-orders the raw read and write. Reverting the accessor to plain `d.dp` therefore remains race-clean. If the blocking provider is passed directly to `NewSampler`, it bypasses the daemon field entirely.

   Use a common release gate before both accesses—for example, block the sampler in `ProcReader.ReadSelfStat` before its adapter load, and block the failing dataplane `Start` before its nil store; release both after they have entered. Also, “cancel; join” is not currently possible for the sampler’s internal loop because `Start` exposes no join handle.

2. **M4 PARTIAL — the “exact” audit is numerically and semantically wrong.**

   The reproduced grep yields 163 matching production lines. Removing 29 full-line comments leaves **134 executable references: 5 writers + 129 readers**. Section 5.4 itself enumerates all 134, so there is no omitted selector, but its `133 / 5+128` claim is false and repeated at [plan.md:36](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:36), `:97`, `:343`, and `:565`.

   The classification snapshot also remains inaccurate. Examples:

   - [daemon_forwarding_status.go:21](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_forwarding_status.go:21), `:24`, `:36`, `:39`, `:97`, and `:100` belong to dead production methods/helpers, not concurrent sampler calls.
   - HTTP dataplane capture at [daemon_run_servers.go:255](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_servers.go:255) occurs before HTTP startup at `:476`, so it is BOOT-SYNC; the later gRPC capture can be concurrent.
   - [daemon_natpoolalarm.go:101](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_natpoolalarm.go:101) is a pre-serving boot/applySem gate, not a monitor-goroutine read.
   - [daemon_system.go:41](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_system.go:41) and [daemon.go:1012](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon.go:1012) have both boot and apply callers, rather than being APPLY-only.
   - HA-only shutdown reads at [daemon_run_shutdown.go:161](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_shutdown.go:161), `:167`, and `:173` are RACE-2-unreachable under the plan’s own exclusion proof.

3. **M5 PARTIAL — the four-link exclusion holds, but “every HA reader is RACE-1-reachable” does not.**

   The exclusion itself checks out:

   - Compile failure leaves `s.compiled` nil at [store_persist.go:81](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go:81), and `ActiveConfig` returns that pointer at [store_format.go:55](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_format.go:55).
   - The only production `d.cluster` construction is [daemon_run_bringup.go:164](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:164).
   - Plain commit, peer sync, and commit-confirmed all invoke the topology preflight at [daemon_apply_commit.go:204](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go:204), `:381`, and `:558`.
   - `enterBootstrapMode` is reached only after a nil rollback target at [daemon_apply_commit.go:645](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go:645).
   - Both production `startClusterComms` calls are guarded by `d.cluster != nil`; no post-boot cluster construction exists.

   However, [daemon_health.go:141](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_health.go:141) is reachable only through `SessionSync.OnForwardSessionInstalled` at [daemon_ha_sync.go:970](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_sync.go:970). Session sync is constructed by `startClusterComms` after dataplane setup has completed: [daemon_run.go:157](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:157), `:393`, and [daemon_ha_sync.go:790](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_sync.go:790). That goroutine-start chain is post-publication and supplies happens-before.

   Therefore health is:

   - RACE-1-unreachable;
   - RACE-2-unreachable through the four-link exclusion;
   - still correctly included in the uniform conversion for issue requirement #1.

   Most `startClusterComms`-owned `daemon_ha_sync.go` readers are similarly post-publication. Only genuine pre-publication watcher paths, such as [daemon_ha.go:248](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha.go:248) through the read at `:297`, are proven RACE-1-reachable.

## MINOR

1. **Fresh typed-nil gap.**

   The pointer gate at [plan.md:170](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:170) fixes the r2 panic, but not the broader “typed-nil exclusion” invariant. Named chan, func, map, and slice types can have methods and satisfy unconstrained [RuntimeDataPlane](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/apply.go:18); the repository itself demonstrates named slice methods at [wire_uint8list.go:32](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/wire_uint8list.go:32). Nil values of those kinds pass the pointer-only guard and publish as non-nil interfaces.

   Current production backends are pointers, so this is hardening rather than a current production failure. Either check all applicable nilable kinds (`Chan`, `Func`, `Map`, `Pointer`, `Slice`; `Interface` is harmless) or narrow the stated invariant. `UnsafePointer` cannot acquire the required method set and `IsNil` does not accept that kind.

2. **MINOR 2 remains PARTIAL: Option D is still compared unfairly.**

   [plan.md:263](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:263) now correctly distinguishes never-constructed from cleared. But the “future republish tears” objection at `:269` violates Option D’s stated write-once-owner premise. “Identity is lost” is also backwards: the immutable owner physically retains identity, whereas A1 clearing the slot discards it. Retyping the field still compiler-breaks old selectors, and an accessor/canary can enforce flag-before-owner reads. A1 remains preferable for one-word state and arbitrary future replacement, but these objections should be restated accurately.

3. **The requested MINOR 3 items are folded, but the comment sweep remains incomplete.**

   Additional contradictory comments are outside v3’s list:

   - [daemon.go:901](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon.go:901) says bootstrap mode is set once and cleared one-way.
   - [bootstrap.go:276](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:276) says it is written at most once more.
   - [bootstrap.go:303](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:303) says rollback re-suppresses takeover for the daemon lifetime, despite later re-arm at `:307-308`.
   - [cluster_topology_preflight.go:117](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/cluster_topology_preflight.go:117) cites stale `daemon_run.go:1868` instead of `daemon_run_bringup.go:164`.

The `CachedStatusProvider` narrowing itself is sound. `NewSampler` has exactly one production caller at [daemon_run.go:595](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:595) and two test callers at [sampler_test.go:69](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fwdstatus/sampler_test.go:69) and `:106`. The old daemon adapter methods have no production consumer; CLI and gRPC use independent `Build` adapters. Retaining the outer `s.dp != nil` guard preserves nil-provider hold-last behavior, while a live daemon adapter over a nil cell returns `ok=false`.

The smoke plan is now policy-complete. The atomic-cell architecture does not need to be killed, but v3 cannot proceed as written until the regression barrier and the audit/reachability claims are corrected.

VERDICT: NEEDS-REVISION

Codex session ID: 019f91fc-a536-7e40-a628-e92c35c4f70d
Resume in Codex: codex resume 019f91fc-a536-7e40-a628-e92c35c4f70d
