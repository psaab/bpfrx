# Codex hostile plan-review — round 39 (plan v39 @ 801c9dd3e)

Task: task-ms24nags-qboebk (session 019f9fab-a586-7a80-a096-32c668127acf).
Verdict: NEEDS-REVISION (6 MAJOR, 0 MINOR; fold verification 2 FOLDED / 2 NOT-FOLDED / 1 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. NOT-FOLDED — Stopping the peer blocks future `QueueConfig` sends (`pkg/daemon/daemon_ha_sync.go:336-370,440-497`) but does not drain the receiver’s private 64-entry queue (`pkg/cluster/sync.go:594-616,850-857`; `pkg/cluster/sync_conn_read.go:315-324`). Its consumer can remain blocked in `syncAndApply(context.Background())` (`pkg/cluster/sync_conn_config.go:325-351`; `pkg/daemon/daemon_ha_sync.go:544-578`; `pkg/daemon/daemon_apply_commit.go:331-355`), so the capped wait at `plan.md:3471-3491` is not a quiescence barrier.

2. NOT-FOLDED — The prohibition at `plan.md:3501-3506` is contradicted by the unswept crash-case copy at `plan.md:3298-3314`, which still permits restoring the original pending-shaped record. Moreover, `Resolved:true` alone fails `ReadConfirm` validation before the proposed Resolved-first check (`pkg/configstore/db.go:254-281`; `plan.md:3727-3739`).

3. PARTIAL — The future/expired split matches `pkg/configstore/store_persist.go:171-255`, but the claim that an expired-window bare `commit` returns “no pending confirmed commit” (`plan.md:3518-3523`) is false. That error belongs only to explicit `ConfirmCommitAs` (`pkg/configstore/store_commit.go:729-746`); bare CLI/gRPC/REST commits fall through to ordinary commit when no timer exists (`pkg/cli/cli_config.go:257-280`; `pkg/grpcapi/server_config.go:257-282`; `pkg/api/config.go:238-256`).

4. FOLDED — Live nil-runtime→cluster commits are rejected with the restart/offline path (`pkg/daemon/daemon_apply_commit.go:194-205`; `pkg/daemon/cluster_topology_preflight.go:59-97`), while boot can import and normally commit `xpf.conf` before manager construction (`pkg/daemon/daemon_apply_commit.go:14-61`; `pkg/daemon/daemon_run_bringup.go:277-334,161-182`), matching `plan.md:3524-3534`.

5. FOLDED — The journal schema has no deadline (`pkg/configstore/journal/journal.go:59-80`), confirm state may be encrypted (`pkg/configstore/db.go:199-216`), and startup logs the original remaining interval (`pkg/configstore/store_persist.go:237-255`), matching `plan.md:3535-3539`.

New findings:

MAJOR M1 — The admitted late-SyncApply residual is not bounded to D debt. A queued apply can start after the mask recheck, promote and cancel the old window, then fail its active write (`pkg/configstore/store.go:687-717,738-746`). That leaves `ActivePersistDegraded` while retaining the old record, not actionable D. The plan itself says that record remains the sole crash-recovery intent until active persistence succeeds (`plan.md:2493-2509`), yet the runbook checks only `ConfirmDebtKindMask` before stopping and classifying the record dead (`plan.md:3483-3505`). It needs a real local apply drain plus a full-state check including `ActivePersistDegraded`.

MAJOR M2 — Stopping the peer is not symmetrically safe and its lifecycle is unspecified. The plan itself says process-local debt forbids stopping (`plan.md:3431-3443`), and the retry worker is abandoned on exit (`pkg/configstore/store_persist.go:397-401`), but `plan.md:3462-3484` has no peer-side full-debt preflight. It also omits restart ordering: restarting the peer before the target stops resumes reconnect/reconcile pushes (`pkg/daemon/daemon_ha_sync.go:926-956`), while leaving it stopped when the target stops creates a full cluster outage. The safe ordering must keep the peer fenced until the target is fully stopped, then restart it; target recovery classification runs before cluster comms (`pkg/daemon/daemon_run.go:157-177,393-398`).

MAJOR M3 — `down em0` is not a universal alternative fence. Config sync uses the configured control interface only when both control fields exist; otherwise it falls back to fabric and may have two fabric paths (`pkg/daemon/daemon_ha_sync.go:774-785,820-860`). The authorization at `plan.md:3471-3475,5377-5385` must instead identify and isolate the actual active sync transport and every redundant path.

MAJOR M4 — The dead-record repair contract is internally contradictory and operationally unreasonable. `plan.md:3298-3314,3410-3415` still allows repair to the pre-tombstone pending state, conflicting with `plan.md:3501-3506`. For a new reader, a tombstone needs at least `Resolved:true`, a nonzero parseable `Deadline`, and non-null `PrevTree` because validation precedes `Resolved` (`pkg/configstore/db.go:254-281`). For downgrade safety, the old reader ignores `Resolved` (`plan.md:3765-3771`), requiring the full synthetic shape—current-tree `PrevTree`, bounded deadline, canonical hash/basis, fresh `ArmID`, and `FirstCommit:false` (`plan.md:3165-3215`). Mandate a generator/tool or prefer removal; do not prescribe hand-authoring.

MAJOR M5 — Offline “removal” lacks a durability barrier. Unlink without parent-directory fsync can replay the stale record after power loss (`pkg/configstore/db.go:284-315`). The live path survives because its probe re-drives `DeleteConfirm` (`plan.md:3335-3342,3976-3981`), but the stopped path has no such probe before `Load`. The runbook must require `DeleteConfirm`-equivalent durable removal, not bare `rm`.

MAJOR M6 — The false bare-commit diagnostic can sabotage H recovery. After expired recovery resets the candidate to the reverted tree (`pkg/configstore/store_persist.go:210-213`), bare commit performs an ordinary promotion (`pkg/configstore/store_commit.go:155-225`). In the H empty-tree case this can mark the empty configuration committed, after which the HA node guard and active-config predicate suppress a later `xpf.conf` import (`pkg/daemon/bootstrap.go:65-79,237-247`). The runbook must forbid probing with bare commit after expiry and require staging the intended configuration before committing.

MINOR — None.

Structure confirmation: CONFIRMED — the PR-1/core versus G+H+H2 follow-up split remains coherent at `plan.md:4260-4303`; `git diff --name-only origin/master...801c9dd3e` contains only research documentation, so none of the production plan items exists yet.

NEEDS-REVISION

Codex session ID: 019f9fab-a586-7a80-a096-32c668127acf
Resume in Codex: codex resume 019f9fab-a586-7a80-a096-32c668127acf
