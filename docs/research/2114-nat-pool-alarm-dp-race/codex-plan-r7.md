Reviewed commit `5de29ed7d` on the requested branch. The core gate is sound, but v7 is not implementation-ready.

### Fold ledger

| r6 item | Status |
|---|---|
| M1 production gate semantics | **FOLDED** |
| M1 regression-test critique | **PARTIAL** |
| M2 legacy coexistence | **PARTIAL** |
| MINOR 1 exposure table | **PARTIAL** |
| MINOR 2 prior `:67` classification | **FOLDED** |
| MINOR 3 citations | **PARTIAL** |
| MINOR 4 source/docs sweep | **FOLDED** |
| MINOR 5 gate specification | **PARTIAL** |

### Gate verification

The proposed production ordering satisfies the four requested properties:

- No ordinary pre-ready return need strand the waiter: all current startup failures return through [daemon_run.go:174](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:174), with phase/error handling at [daemon_run.go:794](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:794). A failure defer registered before that call covers them without relying on raw `daemonCtx`.
- Failure closes `startupDone` while leaving `startupOK=false`, so it wakes and abandons rather than authorizing rollback against partial initialization.
- Waiting before `applySem` avoids the boot-apply cycle: boot `applyConfig` acquires the semaphore at [daemon_apply.go:49](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply.go:49).
- Storing OK then closing the channel publishes the preceding manager/dataplane writes. The proposed point follows `vrrpMgr` construction, boot dataplane Start/apply, and LLDP/DHCP-relay/SNMP initialization through [daemon_run.go:511](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:511).

### MAJOR

1. **R6 M1 test critique — PARTIAL. The tests still do not deterministically or hermetically pin the gate.**

   - Test (a) adds the correct semaphore-freedom assertion at [plan.md:701](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:701), but has no acknowledgement that the executor reached `<-startupDone` before the second goroutine tries `applySem`. A wrong acquire-then-wait implementation can pass if the contender runs first. Add a gate-entry test barrier.
   - Manually closing `startupDone` with `startupOK=false` proves executor abandonment, not that the production defer closes it on both the plain-error and signal-abort paths. Existing tests invoke `runStartupOrAbort` directly at [startup_signal_5807_test.go:131](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/startup_signal_5807_test.go:131), bypassing the proposed `Run` defer.
   - Test (c)’s “fire the timer … assert NO dispatch” at [plan.md:715](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:715) is impossible as stated. `fireConfirmTimer` invokes the executor at [store_commit.go:820](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go:820); the new gate is inside that executor. Assert executor entry plus no promotion/apply side effects.
   - A phase hook alone cannot supply the promised fake dataplane. Userspace construction is hard-coded at [daemon_run.go:53](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:53), and phase 4 overwrites `d.dp` at [daemon_run_bringup.go:421](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:421). Persisted custom backend names are rejected at [compiler_validate_strict.go:199](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/config/compiler_validate_strict.go:199). A per-Daemon backend-factory seam is required.
   - A full non-`NoDataplane` `Run` also performs host-mutating interface naming/tunables at [daemon_run_naming.go:16](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_naming.go:16). The plan needs a hermetic startup-orchestration seam.
   - Checking only that `vrrpMgr` and the fake dataplane survived would not catch an incorrect close immediately after phase 4. The test needs an independent milestone covering late LLDP, DHCP-relay, and `snmpBootReady` initialization.

2. **R6 M2 legacy coexistence — PARTIAL. The counterexample is documented, but the required safe handling and regression remain deferred.**

   The actual chain is confirmed:

   - Commit-confirmed marks the active record committed at [store_commit.go:455](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go:455) and persists `FirstCommit` at `:524`.
   - Recovery accepts empty legacy `GuardedHash` at [store_persist.go:149](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go:149), restores `confirmPrevCfg=nil` at `:239-240`, and re-arms the timer at `:231-253`.
   - Boot constructs/starts the cluster runtime and watcher at [daemon_run_bringup.go:161](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:161), then starts cluster comms at [daemon_run.go:393](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:393).
   - Work G releases only later, after line 511. The legacy rollback therefore enters bootstrap after cluster comms are live.
   - `enterBootstrapMode` tears down network/FRR/dataplane at [bootstrap.go:321](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:321) but never stops the cluster runtime. Full cluster stop exists only in shutdown at [daemon_run_shutdown.go:201](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_shutdown.go:201).

   Atomic `dpCell` publication prevents torn-interface access; it does not make concurrent HA election/watchers/VRRP and dataplane teardown lifecycle-safe. The repository itself classifies live topology hybrids as unsafe at [cluster_topology_preflight.go:27](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/cluster_topology_preflight.go:27).

   The narrow recovery guard must ship in this PR: resolve `FirstCommit && active cluster config` before manager construction, with tests for both empty legacy `GuardedHash` and matching nonempty hash records. Broader cluster-runtime lifecycle redesign can remain a follow-up.

### MINOR

1. **R6 MINOR 1 exposure cells — PARTIAL.**

   - The principal apply rows are corrected, but [plan.md:536](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:536) still omits the serialized RACE-2 side and the “pre-gate” qualifier.
   - The preamble says RACE-3 reaches every APPLY-class reader at [plan.md:490](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:490), while the APPLY/BOOT-SYNC NAT-alarm row at `:511` says only `serialized`. If that site is not timer-reachable, narrow the preamble.
   - The unqualified “RACE-2 reaches only standalone/bootstrap” and “unreachable via exclusion” statements at `:488-490` and `:516` contradict the documented legacy cluster/bootstrap path. Qualify them as current-version-only.

2. **R6 MINOR 3 citations — PARTIAL.**

   `daemon_apply_tail.go:50`, `bootstrap.go:472-473`, and fallback `store_commit.go:822-823` are fixed. Executor dispatch is not: [plan.md:332](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:332) cites `:821`, which is the `else`; the branch/call is `:819-820`.

   Fresh v7 citation nits: the recovered nil assignment is `store_persist.go:239-240`, not `:241-242`, and the topology-preflight call is `daemon_apply_commit.go:558`, not `:551-557`.

3. **R6 MINOR 5 gate specification — PARTIAL.**

   Constructor initialization, both contract-comment updates, and all three risk themes are present. Fixture migration is incomplete: [rollback_serialize_test.go:71](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/rollback_serialize_test.go:71), `:150`, `:201`, and `:247` also construct direct executor fixtures and will block on a nil `startupDone`.

4. **Fresh gate-spec contradictions.**

   - [plan.md:292](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:292) requires exactly-once close, while `:312-318` specifies an explicit success close plus a failure defer without stating the guard. Specify `sync.Once` or a guarded outcome publisher; literal `defer close(...)` double-closes on normal shutdown.
   - The safety point is adequate for the known manager/boot-order defects, but [plan.md:313](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:313) overclaims equivalence and “no apply concurrent with server construction.” Closing before HTTP/gRPC permits exactly that concurrency, including promotion before gRPC snapshots `ActiveConfig` at [daemon_run_servers.go:216](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_servers.go:216). Narrow the claim or specify an additional construction barrier.

### Open questions

- **OQ6:** Separate prerequisite commit in the same PR/stack. Work G and its focused lifecycle tests should be reviewable and bisectable before the mechanical `dpCell` conversion.
- **OQ7:** Reject the follow-up split for the narrow recovery guard. Ship that guard and its legacy-record tests here; leave only broader live cluster-runtime lifecycle work to a follow-up.

VERDICT: NEEDS-REVISION

Codex session ID: 019f9268-60a8-7193-a723-ea3ca41ae098
Resume in Codex: codex resume 019f9268-60a8-7193-a723-ea3ca41ae098
