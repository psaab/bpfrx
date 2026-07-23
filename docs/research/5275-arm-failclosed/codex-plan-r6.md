# Codex hostile plan-review r6 (#5275) — VERDICT: PLAN-NEEDS-MAJOR (viable; 3/7 fully closed, 4 design-decision blockers)

Reviewed plan.md @ r7. Final synthesis (file-read dumps stripped):

-  priority, no dual VIP in direct-VIP mode; legacy-peer golden promotes on
-  weight-zero; withdrawal scrub removes inherited VIP/RA/Kea/FRR before yield;
+  owns every mutually-configured, eligible RG (real heartbeat/election), no
+  both-secondary even at higher held priority, no dual VIP in direct-VIP mode;
+  weight-zero stays asserted while ANY hold reason is set (effectiveHold), so a
+  dataplane proof under a still-set kernel-trial hold does not un-yield; a failed
+  withdrawal scrub escalates to the proved-down/service-fenced fallback before the
+  peer takes over; legacy-peer golden promotes on weight-zero; withdrawal scrub
+  removes inherited VIP/RA/Kea/FRR before yield;
   held RG0 store is non-authoritative.
 - **Staged transaction:** add-B-fails ⇒ B never addressed/up, A's policy retained,
   commit fails; committed-empty→first-interface + remove-all→add use the same

[1mcollab:[0m Wait
[1mcollab:[0m Wait
[3mCompleted the r7/prior-review/source audit and cross-checked the seven claimed folds against proof, configstore, commit/rollback, HA-sync, networkd, and election lifecycles.[0m
  [32m✓[0m Read r7, prior reviews, and enumerate cited source paths
  [32m✓[0m Audit each of the seven round-5 closures against source
  [32m✓[0m Stress delayed promotion, proof ordering, HA sync, rollback, and release composition
  [36m→[0m Deliver the hostile design-level verdict
[3mThe review is complete: three claimed folds are fully closed, while proof staging, delayed config authority/HA recovery, and scrub-failure coordination remain design-level blockers.[0m
  [32m✓[0m Read r7, prior reviews, and enumerate cited source paths
  [32m✓[0m Audit each of the seven round-5 closures against source
  [32m✓[0m Stress delayed promotion, proof ordering, HA sync, rollback, and release composition
  [32m✓[0m Deliver the hostile design-level verdict
[35m[3mcodex[0m[0m
No. r7 selects viable mechanisms, but only 3 of the 7 findings are fully closed. Four remain merely partial or textual closures.

| # | Assessment |
|---|---|
| 1. Final proof ordering | **Not closed.** The final proof moved to the correct boundary, but the two stages are internally inconsistent and networkd/address activation is unresolved. |
| 2. RG0 fix-forward | **Apparently closed.** The recovery-slot direction is sound; inbound recovery cannot currently run or land without violating delayed promotion. |
| 3. Publisher TOCTOU | **Apparently closed.** Delayed promotion is the right architecture, but its transaction, rollback, reboot, and HA semantics are unspecified. |
| 4. Release ownership | **Resolved.** One owner clears `dataplaneUnproven` last. Minor inventory wording remains. |
| 5. Sealed facade | **Resolved.** Sealed start, private arm capability, atomic open, and sticky revocation are adequate design contracts. |
| 6. Weight-zero gating | **Resolved.** Tying yield to `effectiveHold` closes the both-secondary hole. |
| 7. Failed scrub fallback | **Not closed.** A fallback is demanded, but no mechanism ensures it completes before autonomous peer takeover. |

The blocking defects are:

1. **The two-stage proof is not executable as specified.** The preliminary stage is described as a shim-attachment check, but “both stages” require the reconciled helper generation and exact ready XSK bindings ([plan.md:152](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:152), [plan.md:163](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:163)). On the cited RETH path, the first apply deliberately defers workers; ready bindings do not exist until the later rebind/reapply ([daemon_apply_dataplane.go:46](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_dataplane.go:46), [manager_compile.go:318](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/userspace/manager_compile.go:318)). Split the proof ingredients: preliminary proves attach-point inventory and exact shim instance; final proves candidate digest, helper generation, and all registered/armed/ready bindings.

2. **“Networkd before proof, addresses after proof” has no composable primitive.** `InterfaceConfig` includes addresses, while `Apply` writes combined files and reloads/reconfigures networkd; reload can bounce interfaces ([networkd.go:46](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/networkd/networkd.go:46), [networkd.go:130](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/networkd/networkd.go:130), [README.md:47](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/networkd/README.md:47)). Current `Apply` before proof publishes addresses early; invoking it after proof can invalidate the proof. The contract must choose a link-only pre-proof stage plus attachment-neutral post-proof address activation, or relocate the final boundary. `pkg/networkd` is consequently missing from the blast radius.

3. **Delayed promotion is a choice, not yet a complete authority model.** Current source does promote before apply, exactly as r7 diagnoses. But r7 still needs design invariants for:

   - Binding the immutable staged tree/digest that was proved to the generation finally promoted; concurrent candidate edits cannot silently substitute another tree.
   - Boot selection: `Load` currently installs disk state as active. The contract must distinguish the recovery configuration used for re-arming from the last-armed configuration exposed to publishers.
   - `commit confirmed`, which is mandatory for bootstrap takeover, including when its timer and durable rollback record begin and what happens when arming fails.
   - Automatic rollback. Current `PromoteRollback` changes `ActiveConfig` before reapply, recreating the same publication race delayed promotion is intended to remove.
   - History, confirmation, and RG0 demotion semantics after moving the promotion boundary.

   These are transaction invariants, not requested line-level APIs.

4. **The promised inbound HA recovery path contradicts the lifecycle and source.** Pre-proof operation is explicitly heartbeat-only, while config sync starts only in post-proof machinery ([plan.md:126](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:126), [plan.md:171](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:171)). An `armFailed` node never reaches that release. Current config ingress is constructed only with full session sync, and current `SyncApply` immediately promotes active state, resets the candidate, and resolves confirmation state ([daemon_ha_sync.go:774](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha_sync.go:774), [store.go:611](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/configstore/store.go:611)). Reusing it would reopen the TOCTOU. The plan needs an authenticated inbound-config-only lifecycle, recovery-slot landing semantics, applied-high-water/ack behavior, and precedence between local recovery edits and primary sync.

5. **The scrub fallback cannot beat peer election by local ordering alone.** The peer can elect after roughly 500 ms of steady-state heartbeat loss, and current timeout handling elects before optional fencing ([heartbeat.go:874](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat.go:874), [heartbeat_manager.go:404](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:404)). FRR clear can take approximately 40 seconds ([manager.go:43](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/frr/manager.go:43)). Saying the fallback completes “before the peer can take over” is therefore an assertion without a mechanism. Select a pre-election fence/ack, remote ownership gate, or another explicit coordination contract.

Minor residuals:

- §8 still says `armPending` admits only the §9 transaction, while §10 says PR1 boot arming does not depend on §9. Define separate boot-arm and staged-delta routes.
- The “full” release inventory should explicitly place facade OPEN immediately before the final hold clear.
- “Every mutually-configured, eligible RG” is correctly fixed.

The architecture remains viable, but the remaining proof, configuration-authority, HA-recovery, and fencing choices materially determine safety and semantics. They must be approved before `/engineer`.

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
323,312
No. r7 selects viable mechanisms, but only 3 of the 7 findings are fully closed. Four remain merely partial or textual closures.

| # | Assessment |
|---|---|
| 1. Final proof ordering | **Not closed.** The final proof moved to the correct boundary, but the two stages are internally inconsistent and networkd/address activation is unresolved. |
| 2. RG0 fix-forward | **Apparently closed.** The recovery-slot direction is sound; inbound recovery cannot currently run or land without violating delayed promotion. |
| 3. Publisher TOCTOU | **Apparently closed.** Delayed promotion is the right architecture, but its transaction, rollback, reboot, and HA semantics are unspecified. |
| 4. Release ownership | **Resolved.** One owner clears `dataplaneUnproven` last. Minor inventory wording remains. |
| 5. Sealed facade | **Resolved.** Sealed start, private arm capability, atomic open, and sticky revocation are adequate design contracts. |
| 6. Weight-zero gating | **Resolved.** Tying yield to `effectiveHold` closes the both-secondary hole. |
| 7. Failed scrub fallback | **Not closed.** A fallback is demanded, but no mechanism ensures it completes before autonomous peer takeover. |

The blocking defects are:

1. **The two-stage proof is not executable as specified.** The preliminary stage is described as a shim-attachment check, but “both stages” require the reconciled helper generation and exact ready XSK bindings ([plan.md:152](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:152), [plan.md:163](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:163)). On the cited RETH path, the first apply deliberately defers workers; ready bindings do not exist until the later rebind/reapply ([daemon_apply_dataplane.go:46](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_dataplane.go:46), [manager_compile.go:318](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/userspace/manager_compile.go:318)). Split the proof ingredients: preliminary proves attach-point inventory and exact shim instance; final proves candidate digest, helper generation, and all registered/armed/ready bindings.

2. **“Networkd before proof, addresses after proof” has no composable primitive.** `InterfaceConfig` includes addresses, while `Apply` writes combined files and reloads/reconfigures networkd; reload can bounce interfaces ([networkd.go:46](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/networkd/networkd.go:46), [networkd.go:130](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/networkd/networkd.go:130), [README.md:47](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/networkd/README.md:47)). Current `Apply` before proof publishes addresses early; invoking it after proof can invalidate the proof. The contract must choose a link-only pre-proof stage plus attachment-neutral post-proof address activation, or relocate the final boundary. `pkg/networkd` is consequently missing from the blast radius.

3. **Delayed promotion is a choice, not yet a complete authority model.** Current source does promote before apply, exactly as r7 diagnoses. But r7 still needs design invariants for:

   - Binding the immutable staged tree/digest that was proved to the generation finally promoted; concurrent candidate edits cannot silently substitute another tree.
   - Boot selection: `Load` currently installs disk state as active. The contract must distinguish the recovery configuration used for re-arming from the last-armed configuration exposed to publishers.
   - `commit confirmed`, which is mandatory for bootstrap takeover, including when its timer and durable rollback record begin and what happens when arming fails.
   - Automatic rollback. Current `PromoteRollback` changes `ActiveConfig` before reapply, recreating the same publication race delayed promotion is intended to remove.
   - History, confirmation, and RG0 demotion semantics after moving the promotion boundary.

   These are transaction invariants, not requested line-level APIs.

4. **The promised inbound HA recovery path contradicts the lifecycle and source.** Pre-proof operation is explicitly heartbeat-only, while config sync starts only in post-proof machinery ([plan.md:126](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:126), [plan.md:171](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:171)). An `armFailed` node never reaches that release. Current config ingress is constructed only with full session sync, and current `SyncApply` immediately promotes active state, resets the candidate, and resolves confirmation state ([daemon_ha_sync.go:774](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha_sync.go:774), [store.go:611](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/configstore/store.go:611)). Reusing it would reopen the TOCTOU. The plan needs an authenticated inbound-config-only lifecycle, recovery-slot landing semantics, applied-high-water/ack behavior, and precedence between local recovery edits and primary sync.

5. **The scrub fallback cannot beat peer election by local ordering alone.** The peer can elect after roughly 500 ms of steady-state heartbeat loss, and current timeout handling elects before optional fencing ([heartbeat.go:874](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat.go:874), [heartbeat_manager.go:404](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:404)). FRR clear can take approximately 40 seconds ([manager.go:43](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/frr/manager.go:43)). Saying the fallback completes “before the peer can take over” is therefore an assertion without a mechanism. Select a pre-election fence/ack, remote ownership gate, or another explicit coordination contract.

Minor residuals:

- §8 still says `armPending` admits only the §9 transaction, while §10 says PR1 boot arming does not depend on §9. Define separate boot-arm and staged-delta routes.
- The “full” release inventory should explicitly place facade OPEN immediately before the final hold clear.
- “Every mutually-configured, eligible RG” is correctly fixed.

The architecture remains viable, but the remaining proof, configuration-authority, HA-recovery, and fencing choices materially determine safety and semantics. They must be approved before `/engineer`.

VERDICT: PLAN-NEEDS-MAJOR
