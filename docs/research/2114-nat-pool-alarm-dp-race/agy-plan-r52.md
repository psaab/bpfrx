# AGY adversarial plan-review — round 52 (plan v52 @ 5e6483dd0)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY (5/5 folds FOLDED; all fresh attacks FAILED — including the QueueConfig-write-bounded pause argument via syncWriteDeadline 5s; no new findings). Structure confirmed. Raw output follows verbatim (file:/// link markup as emitted).

---

(A) Fold verification:
1. FOLDED — Single-owner snapshot contract assigned to `configstore.Store` (`pkg/configstore/store.go:781-849`); `pkg/daemon` -> `pkg/configstore` dependency is acyclic, and every promotion (`pkg/daemon/daemon_apply_commit.go:217`, `pkg/configstore/store_commit.go:217`) and apply outcome (`pkg/daemon/daemon_apply_commit.go:284`, `pkg/daemon/daemon_apply.go:141-355`) publishes the single versioned snapshot.
2. FOLDED — Seqlock read side linearizes via version re-read without holding `applySem` (`pkg/grpcapi/server_show_cluster_text.go:66-74`), `atomic.Pointer` swap of the immutable snapshot struct guarantees acquire-release field visibility, and §9 includes the `STALE-SNAPSHOT-RETURN` leg ([`plan.md:7358`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L7358)).
3. FOLDED — Pending-XSK startup deferral ([`manager_compile.go:230-298`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_compile.go#L230-L298), [`manager.go:348-357`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager.go#L348-L357)) records NOT-converged until deferred publication completes ([`process_status.go:118-131,183-186`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/process_status.go#L118-L186)), and retries maintain `lastApplyOK == false` until completion succeeds.
4. FOLDED — Reconciler observation drops tick/no-op witnesses and brackets verification across one 30s reconcile interval ([`daemon_ha_sync.go:474-489`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_sync.go#L474-L489), [`sync_conn_config.go:222-243`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/cluster/sync_conn_config.go#L222-L243)); paused claimants are bounded by `syncWriteDeadline` (5s, [`sync_protocol.go:63`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/cluster/sync_protocol.go#L63) << 30s), and a continuously flipping state after two intervals triggers a fail-closed stuck-lock incident.
5. FOLDED — §9 explicitly includes all contract legs ([`plan.md:7358-7377`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L7358-L7377): `STALE-SNAPSHOT-RETURN`, `MID-RENDER-ENTRY`, `single-owner publication order`, `PENDING-XSK REJECTION`, `paused-claimant`, `MARKER-NO-OP REJECTION`).

(B) Fresh attacks:
- Configstore snapshot vs daemon apply boundary: FAILED — `daemon_apply.go:141-355` (`applyConfigLocked`) acts as the single chokepoint for all full applies and publishes outcomes via `Store`, while pre-promotion preflight failures leave the existing active config applied and unchanged.
- Bracketed double check operator cost: FAILED — Network writes in `QueueConfig` are bounded by `syncWriteDeadline` (5s), preventing stale claimants from surviving past one 30s interval, and the two-interval cap guarantees bounded termination via fail-closed incident declaration.

(C) New findings:
None. (0 MAJOR, 0 MINOR).

(D) Structure confirmation:
§4.7 delivery structure stands (two units: #2114 core PR + G+H+H2 follow-up issue; r28 (A) dissent remains recorded).

(E) Verdict line:
PLAN-READY

---
### Summary of Work
Completed adversarial round 52 plan review for issue #2114 in `docs/research/2114-nat-pool-alarm-dp-race/plan.md`. Verified all 5 v52 folds against actual source code files (`store.go`, `daemon_apply_commit.go`, `daemon_dhcp.go`, `daemon_feeds.go`, `server_show_cluster_text.go`, `manager_compile.go`, `process_status.go`, `daemon_ha_sync.go`, `sync_conn_config.go`, `sync_protocol.go`), attacked fresh interleavings, confirmed the §4.7 delivery structure, and issued a `PLAN-READY` verdict.
