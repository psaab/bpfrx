# Adversarial Architecture Review (Round 15 — CONVERGENCE)

**Target**: [`docs/research/2114-nat-pool-alarm-dp-race/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md) (v15)  
**Repo Context**: `/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race` off `origin/master` (`ed6999000`)

---

## (A) Verification of v15 Folds & Load-Bearing Idempotence

### Load-Bearing Idempotence Verification: **VERIFIED**
A second execution of a revert to an already-active `prevTree` is observably identical end-to-end:
1. **Store-side**: [`store_persist.go:196-220`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L196-L220) and [`confirm_rollback_durable_5473_test.go:221-293`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/confirm_rollback_durable_5473_test.go#L221-L293) explicitly pin that writing `prevTree` to disk when `s.active` already equals `prevTree` is a safe, idempotent overwrite. `s.active`, `s.compiled`, and `active.json` retain identical content.
2. **Apply-side**: [`applyConfigLocked`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply.go#L125-L138) is a re-entrant desired-state reconcile pipeline:
   - Subsystem reconcilers (`reconcileSNMP`, `reconcileWebManagement`) check desired vs. active state and no-op on identical configs.
   - Deletion-clear session diffing (`#4234`) diffs `oldActive` vs. `newActive`; when identical, diff is empty (0 sessions dropped).
   - `frr-reload.py` diffs generated FRR configuration against running configuration and no-ops.
   - One-shot execution guards (`inBootstrap()` transition in [`daemon_apply.go:221`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply.go#L221) and `maybeReapplyConfigArrivalNaming` in [`daemon_apply.go:234`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply.go#L234)) prevent duplicate startup/naming triggers.
   
No apply step observably differs on a second execution.

---

### Fold Status Evidence Matrix

| v15 Fold Item | Status | Worktree Code Evidence |
|---|---|---|
| **Fold (a): Tombstone scope re-based to IDEMPOTENCE predicate** | **FOLDED** | [`store_command.go:32-37,72-77`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_command.go#L32-L37) (`SetAs`/`DeleteAs` mark `s.dirty = true` allowing edit-away/edit-back content matches); [`store_persist.go:149-159`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L149-L159) (legacy empty `GuardedHash` skips mismatch check); [`factory_reset.go:252-268`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/factory_reset.go#L252-L268) (Class 0 complete `.configdb` wipe). |
| **Fold (b): FOUR-STATE keyed-debt retry** | **FOLDED** | [`store_persist.go:441-443`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L441-L443) (retry drives `removeConfirmState`); [`db.go:297-315`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L297-L315`) (`DeleteConfirm` falls through to `rbSyncDir` on `os.IsNotExist` for post-unlink dir-fsync state). |
| **Fold (c): Persisted opaque ArmID as debt identity** | **FOLDED** | [`store.go:168-179`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store.go#L168-L179) (`confirmGen` verified as memory-only); additive `ArmID` eliminates same-content `GuardedHash` and clock-adjusted `Deadline` collisions. |
| **Fold (d): Residual wording + inventory + diagnostic hedge** | **FOLDED** | [`store_persist.go:159-165`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L159-L165) (diagnostic text hedged); [`factory_reset.go:252-268`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/factory_reset.go#L252-L268) inventory integrated. |

---

## (B) Fresh Attack Evaluation

### 1. Plain-commit auto-confirm tombstone write
* **Analysis**: Plain `commit` promotes `s.candidate` to `s.active` and calls `writeActive` first. If a pending `commit confirmed` window was active, auto-confirm runs `resolveConfirmRemovalLocked`. Under v15, writing `Resolved: true` to `confirm.json` before unlinking ensures that if a crash occurs post-promotion, recovery on reboot sees `rec.Resolved == true` and drops `confirm.json` rather than re-arming or rolling back.
* **Overhead**: For standard commits (no confirm pending), `confirm.json` is absent on disk; `writeTombstone` is a no-op (0 write overhead). For auto-confirms, 1 durable write occurs once per confirm cycle, which is completely acceptable.
* **Verdict**: **SAFE / HOLDS**.

### 2. Lingering UNEXPIRED record after successful rollback
* **Analysis**: A timeout rollback writes `prevTree` to `active.json`. If `DeleteConfirm` subsequently fails, `confirm.json` remains on disk without a tombstone (replacement-class resolution). On a reboot, `Store.Load()` reads `confirm.json`. `rec.GuardedHash` (hash of unconfirmed config) is compared against `journalConfigHash(s.active)` (hash of reverted config `prevTree`). Because the hash mismatches, [`store_persist.go:159-165`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L159-L165) stale-drops the record without re-arming or rolling back. For legacy empty-hash records, recovery re-executes the revert, which is idempotent per (A).
* **Verdict**: **SAFE / HOLDS**.

### 3. SyncApply with synced content identical to window content
* **Analysis**: `SyncApply` is an HA sync supersession (non-idempotent confirm-type class). If primary pushes content $C'$ identical to pending window content $C$, `SyncApply` writes `Resolved: true` to `confirm.json` before deletion. On restart after a deletion failure, `Store.Load()` sees `rec.Resolved == true` and drops `confirm.json` immediately.
* **Verdict**: **SAFE / HOLDS** (covered by the general non-idempotent predicate without special-casing).

### 4. Degenerate record at retry (`ReadConfirm` #5637 errors)
* **Analysis**: If `confirm.json` on disk is unparseable or degenerate, [`db.go:275-281`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L275-L281) returns a read error. The retry machine hits state (d) (`READ ERROR → retain debt + retry with backoff`). This keeps `/health` degraded (503), alerting operators to disk/file corruption without performing unsafe file deletions on unverified disk state.
* **Verdict**: **SAFE / HOLDS**.

### 5. ArmID-less downgrade debt interaction
* **Analysis**: `confirmRemoveDegraded` and `confirmResolvePendingPersist` are memory-resident fields on `type Store` ([`store.go:150-166`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store.go#L150-L166)). Retry debt is never written to disk; it lives only for the duration of a running process. Cross-version persisted debt cannot occur.
* **Verdict**: **SAFE / HOLDS**.

---

## Verdict

**PLAN-READY**

The v15 plan's invariants, idempotence claims, schema evolution rules, and retry mechanics are fully verified against the worktree codebase. Implementation can proceed via `/engineer 2114`.
