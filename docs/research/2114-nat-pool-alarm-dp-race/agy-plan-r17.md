# AGY adversarial plan-review — round 17 (plan v17 @ 3d3b3e8af)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY. Raw output follows verbatim.

---

(A) Verification of Folds 1-6:

1. TWO-FIELD debt identity (`s.armedArmID` + `s.onDiskArmID`): **FOLDED**
   - Evidence: [plan.md:1113-1168](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L1113-L1168).
   - Code verification: [store_commit.go:503-550](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L503-L550) (`writeConfirmState`), [store_persist.go:231-253](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L231-L253) (readable recovery restoration), [db.go:207-220](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L207-L220) (`WriteConfirm`), and [fsatomic.go:45-95](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fsatomic/fsatomic.go#L45-L95) (`PostRenameSyncError`).
   - All `WriteConfirm` call sites and failure phases (pre-rename vs post-rename) form a total update rule: pre-rename failures leave `onDiskArmID` unchanged, while post-rename failures set `onDiskArmID` to the visible record's `ArmID` and raise a rewrite debt. If a tombstone write itself fails post-rename, `onDiskArmID` holds the visible tombstoned `rec.ArmID`, so the retry reads `confirm.json`, matches `rec.ArmID`, sees `Resolved == true`, and completes deletion.

2. Post-rename finalize durability barrier: **FOLDED**
   - Evidence: [plan.md:1200-1230](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L1200-L1230).
   - Code verification: Plain commit [store_commit.go:180-200](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L180-L200), confirmed commit [store_commit.go:437-452](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L437-L452), and `persistRetryLoop` [store_persist.go:414-428](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L414-L428).
   - Program-ordered sequence ensures `writeActive`'s rename precedes the finalize's tombstone `WriteConfirm`. Because `confirm.json` and `active.json` share `.configdb/`, the tombstone write's directory fsync (`fsatomic.go:310-369`) acts as a durability barrier persisting the prior `active.json` rename. The double-failure namespace-replay residual (both writeActive and tombstone write fail post-rename + power loss) is stated honestly.

3. B-rewrite A/B/C transitions & debt-set bound: **FOLDED**
   - Evidence: [plan.md:1170-1199](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L1170-L1199).
   - Analysis: The confirm-side retry carries a keyed debt set bounded at at most 1 removal debt + 1 rewrite debt. `onDiskArmID` is singular. A durable new arm C clears stale debts, a pre-rename failure of C leaves B's debt standing on disk, and a post-rename failure of C re-keys the single rewrite debt to C. The retry never rewrites a record whose `ArmID` differs from its key.

4. Full terminal taxonomy: **FOLDED**
   - Evidence: [plan.md:1233-1260](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L1233-L1260).
   - Code verification: `#5637` parse gates [db.go:226-281](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L226-L281), crypto/envelope/auth/PRF/master-key errors [crypto.go:307-453](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/crypto.go#L307-L453), `persistRetryLoop` [store_persist.go:402-465](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L402-L465), and boot recovery read error [store_persist.go:140-144](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L140-L144).
   - The degraded latch is per-debt (allowing active-config persistence healing to continue). Recovery read failures on permanent errors set the latch at boot, preventing 503-to-healthy laundering across restarts.

5. Election-neutral 503 & REST health: **FOLDED**
   - Evidence: [plan.md:1262-1279](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L1262-L1279).
   - Code verification: `ConfigPersistDegradedFn` in [daemon_run_servers.go:370-374](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_servers.go#L370-L374), REST health 503 in [api/health.go:65-71](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/api/health.go#L65-L71), diagnostic-only cluster annotations in [cluster/readiness.go:20-24](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/cluster/readiness.go#L20-L24), and ungated crash takeover in [cluster/election.go:427-432](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/cluster/election.go#L427-L432).
   - `pkg/api/health.go` is correctly listed as touched to render the distinct terminal confirm-record health message.

6. Citation repairs: **FOLDED**
   - Evidence: [plan.md:1030-1043](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L1030-L1043), [1580-1596](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L1580-L1596).
   - Code verification: `SyncApply` replacement-class flow in [store.go:697-760](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store.go#L697-L760), flow-cache generation eviction in [flow_cache.rs:992-999](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/userspace-dp/src/afxdp/flow_cache.rs#L992-L999) with NAT64 excluded at [flow_cache.rs:385-393](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/userspace-dp/src/afxdp/flow_cache.rs#L385-L393), and NAT64 fragment-association generation guard in [nat64.rs:244-263,528-553](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/userspace-dp/src/nat64.rs#L244-L263).

---

(B) Fresh Attacks & Outcomes:

1. Attack: Test (x8) real post-rename seam implementability.
   - Outcome: **FAILED**.
   - Rationale: Pre-existing test seam `fsatomic.SetAfterRenameSyncDirForTesting` in [postrename_dbboundary_5234_test.go:47](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/postrename_dbboundary_5234_test.go#L47) allows tests to inject a post-rename directory-fsync error specifically when writing `active.json` while allowing subsequent `confirm.json` writes to succeed cleanly. Test (x8) is fully implementable.

2. Attack: Confirm-side debt set bound explosion under rapid re-arming.
   - Outcome: **FAILED**.
   - Rationale: Because `s.onDiskArmID` is a single variable tracking the on-disk record identity, any new arm C that succeeds durably clears stale debts. If C fails post-rename, `onDiskArmID` becomes C and the single rewrite debt re-keys to C. Thus, the confirm-side debt set never exceeds 1 removal debt + 1 rewrite debt.

3. Attack: Master-key IO error permanent/transient classification boundary.
   - Outcome: **FAILED**.
   - Rationale: When `confirm.json` is encrypted, any failure reading or decoding `master.key` renders `confirm.json` un-decryptable. Unless an operator intervenes to restore `master.key` or remove `confirm.json`, retrying indefinitely would loop on unreadable state. Classifying `master-key` failures as permanent (setting the per-debt terminal latch and requiring manual remediation or clean `ReadConfirm`) is correct.

4. Attack: Latch clearance observer on confirmed absence.
   - Outcome: **FAILED**.
   - Rationale: `ReadConfirm()` is called at recovery ([store_persist.go:140](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L140)), in `persistRetryLoop` ([store_persist.go:402](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L402)), and on commit resolution paths. When `confirm.json` is removed by an operator, `ReadConfirm()` executes `os.ReadFile` -> `os.IsNotExist` -> returns `(nil, nil)`. This confirmed absence clears the terminal latch.

---

PLAN-READY
