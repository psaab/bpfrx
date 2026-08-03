PLAN-NEEDS-MAJOR

Checkout verified:

- `pwd`: `/home/ps/git/xpf-worktrees/6744-plan-r10-review`
- `HEAD`: exactly `103acbfd28115993f8f6393ed6b55d632bcfb4ee`
- Detached checkout, clean status: only `## HEAD (no branch)`
- Worktree and cached diffs are empty.
- I made no writes to files, branches, issues, or PRs.

I read all 2,448 lines of [plan.md](/home/ps/git/xpf-worktrees/6744-plan-r10-review/docs/research/6744-kimi-review-003/plan.md:1). The verdict below comes from production call graphs and interleavings, not tests.

## Material blockers

### 1. A received transport-config change self-joins its own config callback

Revision 10 requires `Stop` and transport retirement to join every admitted config callback without the current five-second abandon path ([plan.md:1532](/home/ps/git/xpf-worktrees/6744-plan-r10-review/docs/research/6744-kimi-review-003/plan.md:1532)). That deadlocks on an existing production path.

Source:

- `configApplyLoop` is itself a member of `SessionSync.wg`: [sync_conn.go:338](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/cluster/sync_conn.go:338).
- It synchronously invokes `OnConfigReceived`: [sync_conn_config.go:350](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/cluster/sync_conn_config.go:350).
- The callback promotes the peer config and enters the daemon apply pipeline: [daemon_apply_commit.go:353](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/daemon/daemon_apply_commit.go:353), [daemon_ha_sync.go:578](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/daemon/daemon_ha_sync.go:578).
- A change to control/fabric transport synchronously calls `stopClusterComms`: [daemon_apply_tail.go:238](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/daemon/daemon_apply_tail.go:238), [daemon_apply_tail.go:253](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/daemon/daemon_apply_tail.go:253).
- That calls `ss.Stop()`: [daemon_ha_sync.go:1412](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/daemon/daemon_ha_sync.go:1412).
- `Stop` waits for the same `wg` containing the executing `configApplyLoop`: [sync_conn.go:376](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/cluster/sync_conn.go:376).

Executable trace:

1. Fabric 0 delivers G2 changing a sync transport address.
2. `configApplyLoop` admits G2 and calls `OnConfigReceived`.
3. `SyncApply` promotes G2; the store is now mutated.
4. `applyConfigLocked` reaches the transport-change step.
5. The callback calls `stopClusterComms → ss.Stop`.
6. `Stop` waits for `configApplyLoop`.
7. `configApplyLoop` cannot exit until `Stop` returns and its callback completes.
8. G2 never returns success or failure, no high-water is published, and shutdown/restart hangs permanently once the five-second escape is removed.

The lifetime graph needs a specific ownership transfer: transport restart must be scheduled outside the owning `SessionSync` callback and occur only after callback publication, or the callback must execute outside the joined worker set under an explicit handoff. The current plan specifies neither.

### 2. RG0 role becomes globally visible before `BeginConfigAuthorityTransition`

The proposed daemon wrapper cannot meet its stated invariant that admission closes before role publication or positive action. The cluster manager publishes the role before the daemon receives the event that would call `Begin`.

Source:

- Election writes `rg.State` first: [election.go:337](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/cluster/election.go:337), [election.go:341](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/cluster/election.go:341).
- Only afterward is the event sent: [election.go:390](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/cluster/election.go:390).
- The daemon learns the transition asynchronously from `Events()`: [daemon_ha.go:263](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/daemon/daemon_ha.go:263).
- Concurrent readers immediately observe the new state through `IsLocalPrimary`: [group_state.go:218](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/cluster/group_state.go:218).
- Config authority and push decisions use that raw state: [daemon_ha_sync.go:332](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/daemon/daemon_ha_sync.go:332), [daemon_ha_sync.go:451](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/daemon/daemon_ha_sync.go:451).

Executable trace:

1. Secondary has an admitted G2 callback blocked after store mutation.
2. Election sets RG0 to primary and enqueues the event.
3. Election releases `cluster.Manager.mu`.
4. Before `watchClusterEvents` runs `Begin`, the config reconcile goroutine calls `IsLocalPrimary(0)` and sees primary.
5. It reads the newly promoted active store and may queue a config push.
6. Admission/producers have not yet been closed, and the old-role callback has not drained.
7. The daemon wrapper runs later and cannot retroactively restore the promised ordering.

Dropped-event safety-net reconciliation has an even longer pre-`Begin` window. A source canary against direct positive actuators does not cover raw role readers, heartbeat/status publication, config authority, or other derived consumers.

This needs either:

- a two-phase RG0 election protocol that records a pending desired role and commits `rg.State` only after `Complete`, or
- a separately committed RG0 authority state that every authority reader, heartbeat publisher, config writer, store gate, and actuator must use instead of `cluster.Manager`’s desired/raw role.

Revision 10 currently describes neither migration.

### 3. Config-sync mode and zone ownership have no callback-transaction protocol

The plan says subsequent applies use the typed authority setter and that config-sync enable/disable drains admitted config/session/reconcile work ([plan.md:1231](/home/ps/git/xpf-worktrees/6744-plan-r10-review/docs/research/6744-kimi-review-003/plan.md:1231), [plan.md:1238](/home/ps/git/xpf-worktrees/6744-plan-r10-review/docs/research/6744-kimi-review-003/plan.md:1238)). A received config necessarily invokes that setter from inside the admitted config callback being drained.

Current placement demonstrates the problem:

- Zone ownership is updated inside `applyConfigLocked`: [daemon_apply_dataplane.go:193](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/daemon/daemon_apply_dataplane.go:193).
- Cluster/config-sync state is updated later in the same callback: [daemon_apply_tail.go:221](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/daemon/daemon_apply_tail.go:221).
- Still later operations can fail, including the transport path above.
- Callback success alone advances the accepted generation: [sync_conn_config.go:351](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/cluster/sync_conn_config.go:351), [sync_conn_config.go:394](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/cluster/sync_conn_config.go:394).

Executable trace:

1. Protected secondary admits G2 that disables config sync or changes zone ownership.
2. The callback promotes the store and reaches the typed setter.
3. If the setter drains all admitted config callbacks, it waits for itself.
4. If it publishes immediately, protection/baseline/ownership changes before G2 is known successful.
5. A later apply error returns from the callback without advancing `acceptedConfigGen`, but the authority snapshot is already G2.
6. Sessions can then be admitted under an authority/config combination that the gate still reports as unapplied—or the node remains indefinitely transitioning without a specified rollback target.

The callback needs an explicit transactional result, such as a staged `SessionSyncAuthorityDelta` returned with callback success and atomically committed by the gate after the callback lease validates. Failure semantics must state whether the prior authority is restored or the node remains fail-closed pending retry. Reentrant “exclude the current lease” draining alone is insufficient because it does not solve later apply failure.

### 4. Clustered helper debt does not fence direct actuator writers

The plan suppresses the status loop while `haInventoryDebt` exists, but production has direct BPF/helper writers outside that loop. Because the plan deliberately retains the previous published `m.haGroups` until helper replacement succeeds, inventory membership alone authorizes removed slots.

Source:

- Current inventory is published/mutated under `m.mu`: [manager_compile.go:228](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/dataplane/userspace/manager_compile.go:228), [manager_ha.go:277](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/dataplane/userspace/manager_ha.go:277).
- `UpdateRGActive` writes `rg_active`, mutates `m.haGroups`, and sends a complete helper map: [manager_ha.go:657](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/dataplane/userspace/manager_ha.go:657), [manager_ha.go:705](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/dataplane/userspace/manager_ha.go:705).
- `UpdateHAWatchdog` writes the pinned map before acquiring `m.mu`, then can replay `m.haGroups` to the helper: [manager_ha.go:807](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/dataplane/userspace/manager_ha.go:807), [manager_ha.go:816](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/dataplane/userspace/manager_ha.go:816), [manager_ha.go:839](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/dataplane/userspace/manager_ha.go:839).
- The daemon invokes watchdog updates every 500 ms: [daemon_ha_sync.go:742](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/daemon/daemon_ha_sync.go:742), [daemon_ha_sync.go:750](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/daemon/daemon_ha_sync.go:750).
- The status loop is only one of the replay sources: [process_status.go:211](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/dataplane/userspace/process_status.go:211).

Executable trace:

1. Published inventory has RG1 active.
2. A new generation removes RG1 and introduces RG3.
3. Compile clears RG1/RG3 pinned slots.
4. Full helper replacement fails; debt is installed, while published `m.haGroups` remains the previous RG1 inventory.
5. A watchdog tick that captured RG1 before the config transition resumes.
6. `UpdateHAWatchdog(1)` writes a nonzero pinned timestamp before inspecting manager state.
7. Previous inventory membership still accepts RG1.
8. Its backstop path can send the old full RG1 helper map, undoing the debt fence.
9. A delayed positive `UpdateRGActive(1, true)` has the same problem and can supersede the staged generation operationally even though the status-loop retry token is protected.

Every direct actuator must linearize under the debt mutex before any map write, reject or defer debt-fenced slots, avoid helper/status publication while debt exists, and prevent forwarding readiness/arm from being replayed. Debt generation supersession must cover these writers, not just its sole retry consumer.

## Hostile matrix disposition

The remaining revision-10 mechanisms are implementable from the inspected source, subject to the blockers above:

- Capability setup: new/new, new/old, old/new, keyed/unkeyed, auth-consumed pending frames, and delayed first frames are coherently resolved before registration.
- Dual-fabric class/process/defined-flag mismatch correctly requires whole-transport retirement.
- One-fabric replacement can preserve an already-admitted transport/process/role-scoped callback; last-fabric loss correctly needs a join before a lower-generation baseline. The config-driven self-stop path remains the exception.
- Receiver-requested capable cold sync closes the current bulk-before-config race.
- Simultaneous bidirectional requests have independent send/receive tokens and no required lock nesting.
- Fabric-1 repair is correctly pinned to its requesting connection; no silent fabric-0 migration.
- The used-plus-live connection fence, exact-incarnation ACKs, and whole-transport retirement cover vanishing pre-drain connections.
- Other-fabric session traffic during receive/reconcile is correctly fatal to the transport.
- Gate-only receive state and the stated mutex edges are plausible, but the omitted callback/`wg` lifetime edge is material.
- Cancellable joined reconciliation correctly suppresses ACK/readiness/debt completion on cancellation or delete/iterator failure.
- Timeout after reconcile failure changes only availability; it does not call `SetSyncReady`, publish the bulk callback, or clear baseline/repair debt.
- Legacy eight-byte ACKs never prove capable completion. An old receiver’s unconditional ACK is therefore harmless because upgraded senders never initiate authoritative bulk toward it.
- Mixed-version restrictions are symmetric: ordinary incrementals may continue, but neither direction becomes continuity-ready.
- Nontransactional member installs are explicitly retained while failed windows preserve repair debt.
- I-a/I-c inactive scaffolding, independently active I-b debt hardening, and I-d-only peer activation are a sound stacking boundary.

## A–M workstream audit

- A: Dedicated warning-state lock and helper-only access are sufficient.
- B: Pre-normalization, both-node-effective hard rejection is implementable.
- C: Canonical SNMP deep fold, secret-redacted observations, rejected-user dominance, and one runtime evaluator are coherent.
- D: Passing the already parsed ICMP byte under `l4_present` is correctly bounded.
- E: Same-family per-row authority, retained anchor lifetime, co-owner claim release ordering, and no second-credential retry are internally consistent.
- F: Detached override classification/replay and atomic candidate swap are implementable.
- G: Persistence-boundary shape validation plus compiler indexing belts is sufficient for JSON-created trees.
- H: Shared exact family expansion and terminal-row accounting match the renderer model.
- I: Blocked by the four issues above.
- J: Merge-not-replace outer address-book handling matches existing inner merge semantics.
- K: Not-found versus transient lookup classification preserves retryable ownership.
- L: Positive action applicability and normalization at both decoded-event boundaries are coherent.
- M: Exact four-key canonical zone-pair enforcement closes the silent nested-container omission.

## Optional polish

- Specify whether `electionTimeoutExpired` survives last-fabric loss until the next registration. Current code stops the timer on disconnect at [daemon_ha_sync.go:109](/home/ps/git/xpf-worktrees/6744-plan-r10-review/pkg/daemon/daemon_ha_sync.go:109), while the plan says reset on a “new transport”; the exact edge should be unambiguous.
- Give reconciliation’s underlying iterator/delete operations bounded I/O deadlines. Context checks between operations do not interrupt a single stuck operation, while the new `Stop` contract waits without abandonment.
- Expand helper-debt validation to include delayed daemon heartbeat and RG-state events, not only status-loop replay.

No writes were made.
