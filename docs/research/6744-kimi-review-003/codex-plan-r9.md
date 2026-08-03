PLAN-NEEDS-MAJOR

Target re-check: `pwd` is `/home/ps/git/xpf-worktrees/6744-plan-r9-review`; HEAD is `ff17e6351f0e0da4fc2ac0b45d0ecdd4c4b99be5`; `git status --short` is empty. Write scope remained NONE; no files, branches, issues, or PRs were modified.

## Material blockers

1. Per-connection incarnation cannot invalidate delayed config completion as specified.

The plan keeps the connection registry under `s.mu`, but the proposed gate contains no current connection-incarnation set or invalidation generation ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r9-review/docs/research/6744-kimi-review-003/plan.md:1198)). It then requires disconnect to invalidate work for one connection while the other fabric survives ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r9-review/docs/research/6744-kimi-review-003/plan.md:1239)), while completion is allowed to reacquire only `gate.mu` ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r9-review/docs/research/6744-kimi-review-003/plan.md:1295)). That completion cannot determine whether its connection remains registered.

This is not cosmetic. Current same-fabric replacement closes and replaces one slot while leaving the shared transport connected ([sync_conn.go](/home/ps/git/xpf-worktrees/6744-plan-r9-review/pkg/cluster/sync_conn.go:244)); last-fabric-only cleanup is separate ([sync_conn.go](/home/ps/git/xpf-worktrees/6744-plan-r9-review/pkg/cluster/sync_conn.go:480)). Config callbacks perform real daemon/config-store mutation before their success result is recorded ([sync_conn_config.go](/home/ps/git/xpf-worktrees/6744-plan-r9-review/pkg/cluster/sync_conn_config.go:325)).

Executable trace:

1. Register capable `c0` and `c1` in transport `E`; accepted config is `G1`.
2. Deliver encoded config `G2` on `c0`; block the production `OnConfigReceived` callback after it has applied `G2`.
3. Replace only `c0`; `c1` survives, so `transportEpoch` does not advance.
4. Let the callback return success.
5. The plan forbids that stale `c0` token from publishing `acceptedConfigGen=G2`, but it neither establishes a new baseline nor requests a config replay.
6. Deliver a `G2` session on the surviving/current connection. It is refused against stale `acceptedConfigGen=G1`, creating an unrecoverable repair loop because a `G2` bulk is refused for the same mismatch.

The daemon’s config reconciler does not rescue this: its peer epoch advances through `OnPeerConnected` ([daemon_ha_sync.go](/home/ps/git/xpf-worktrees/6744-plan-r9-review/pkg/daemon/daemon_ha_sync.go:51)), whereas a routine one-fabric replacement currently does not schedule that callback. Its already-pushed marker then suppresses a repeat ([daemon_ha_sync.go](/home/ps/git/xpf-worktrees/6744-plan-r9-review/pkg/daemon/daemon_ha_sync.go:417)).

The plan must choose and specify one invariant: either a successfully applied callback remains publishable when transport/process/role are unchanged despite source-connection replacement, or any such replacement raises a baseline obligation and causally requests/replays current config. It must also add gate-visible per-connection state or permit the completion to validate through the registry under the declared lock order.

2. The existing cold-start timeout bypasses “failed bulk publishes no readiness.”

The plan says reconciliation failure produces no readiness release or success callback ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r9-review/docs/research/6744-kimi-review-003/plan.md:1521)) and requires production-path tests for that claim ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r9-review/docs/research/6744-kimi-review-003/plan.md:2137)). It never accounts for the daemon’s independent readiness timer.

On cold connection, the daemon arms `syncReadyTimer`; when it expires it calls `cluster.SetSyncReady(true)` without a successful bulk ([daemon_ha_sync.go](/home/ps/git/xpf-worktrees/6744-plan-r9-review/pkg/daemon/daemon_ha_sync.go:29)). `SetSyncReady` is explicitly the private-RG-election readiness gate and currently means “bulk received or timed out” ([sync_state.go](/home/ps/git/xpf-worktrees/6744-plan-r9-review/pkg/cluster/sync_state.go:11)). Only the successful bulk callback cancels that timer ([daemon_ha_sync.go](/home/ps/git/xpf-worktrees/6744-plan-r9-review/pkg/daemon/daemon_ha_sync.go:90)).

Executable trace:

1. Start a fresh protected standby through the real daemon connection callback.
2. Deliver capable `BulkStart`, members, and matching `BulkEnd`.
3. Inject a production-boundary `ReconcileClusterBulk` error.
4. Verify no ACK and no `OnBulkSyncReceived`.
5. Advance/wait `syncReadyTimeout`.
6. `cluster.IsSyncReady()` becomes true anyway.

An implementor must currently invent whether to remove this availability timeout, split “timed-out election availability” from “session-sync success,” or retain it as an explicit exception. That choice changes automatic failover behavior and must be settled in the plan.

3. “New sender → old receiver is safe” is false on reconciliation failure.

The plan claims a barriered new sender remains safe with a legacy receiver ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r9-review/docs/research/6744-kimi-review-003/plan.md:1403), [plan.md](/home/ps/git/xpf-worktrees/6744-plan-r9-review/docs/research/6744-kimi-review-003/plan.md:1457)) and continues accepting the old receiver’s 8-byte ACK ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r9-review/docs/research/6744-kimi-review-003/plan.md:1583)).

At the immutable old receiver, `reconcileStaleSessions` logs and counts `ReconcileClusterBulk` errors but returns no failure ([sync.go](/home/ps/git/xpf-worktrees/6744-plan-r9-review/pkg/cluster/sync.go:1080)). Its `BulkEnd` handler subsequently sends the ACK, sets `bulkEverCompleted`, and fires `OnBulkSyncReceived` unconditionally ([sync_conn_read.go](/home/ps/git/xpf-worktrees/6744-plan-r9-review/pkg/cluster/sync_conn_read.go:241)). The daemon callback releases the VRRP hold and publishes sync readiness ([daemon_ha_sync.go](/home/ps/git/xpf-worktrees/6744-plan-r9-review/pkg/daemon/daemon_ha_sync.go:90)).

Executable mixed-version trace:

1. New sender performs producer drain and both-fabric barriers.
2. Old receiver receives its legacy-form authoritative bulk.
3. Inject partial-delete or iterator failure in the old receiver’s `ReconcileClusterBulk`.
4. Old receiver still returns an 8-byte ACK and publishes bulk success/readiness.
5. New sender accepts that legacy ACK and clears its pending outbound state after tail handling.

The barriers prove ordering, not successful reconciliation. A new binary cannot repair the old receiver’s fail-open completion semantics. The plan needs an explicit compatibility restriction—most plausibly prohibiting the old-receiver upgrade order/manual transfer and requiring the standby/receiver to be upgraded first—or it must stop claiming legacy receiver safety. The current rolling-upgrade note covers only new receiver/old sender and leaves the reverse direction unsafe.

## Non-blocking review result

No additional source-grounded blocker emerged in A–H, the RG portion of I, or J–M:

- SNMP retains a private credential-aware reconcile hash while secret-free observations use ordinal identity; canonical deep-fold and equal-prefix deny-wins are specified.
- DDNS selects the expected surface at load, durably releases shared claims before publication/provider activity, and distinguishes pre-rename from `PostRenameSyncError`.
- RG staging treats helper updates as full replacement, preserves unchanged bound slots, fences introduced/removed slots, and owns retry payloads without reading unpublished `m.haGroups`.
- `LoadOverride`, confirm metadata validation, route-map counting, routing ownership, lifecycle action, and nested-policy validation retain bounded production paths and compatibility limits.

## Optional polish

- State explicitly that `crypto/rand` failure emits no type-30 frame; an all-zero 26-byte capability would correctly be rejected as malformed.
- Clarify that existing authentication handshake messages 27/28 are exempt from “capability must be the first data/control frame.”
