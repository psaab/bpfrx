# Adversarial Architecture Review (Round 12 - Convergence Round)

**Target Plan**: [plan.md](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md) (v12)  
**Target Codebase**: `origin/master` @ `ed6999000` in worktree `/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race`  
**Verdict**: **`NEEDS-REVISION`**

---

## Part A: Verification of v12 Folds

| Fold Item | Status | Evidence & Code References |
| :--- | :--- | :--- |
| **A1. Confirm/Resolve Path Coverage** | **FOLDED** | Every confirm resolution on master routes through [resolveConfirmRemovalLocked](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L584). Verified coverage across all 6 triggers: (1) `ConfirmCommit`/`ConfirmCommitAs` via `clearPendingConfirmLocked` ([store_commit.go:L702](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L702)); (2) `ConfirmPendingOnDemotion` ([store_commit.go:L784](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L784)); (3) Plain `commit` ([store_commit.go:L245](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L245)); (4) `SyncApply` ([store.go:L754](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store.go#L754)); (5) Timeout auto-rollback `PromoteRollback` ([store_commit.go:L937](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L937)); (6) Boot recovery stale/expired drops ([store_persist.go:L163](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L163), [store_persist.go:L219](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L219)). Deferred retry cleanups also route here via `clearConfirmResolutionPendingLocked` ([store_commit.go:L649](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L649)). No path bypasses this entry point. |
| **A2. Crash Window Boundaries** | **FOLDED** | State boundaries are clean: (a) *Arm $\rightarrow$ Tombstone*: `confirm.json` has `Resolved: false`; crash recovery reads it as pending and re-arms/reverts normally. (b) *Tombstone $\rightarrow$ Delete*: `resolveConfirmRemovalLocked` writes `Resolved: true` before `DeleteConfirm`; crash recovery reads `Resolved: true` and drops without re-arming or triggering H. (c) *Tombstone write failure*: Retains retry debt (`confirmRemoveDegraded = true`) and starts `persistRetryLoop` ([store_commit.go:L586](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L586)). |
| **A3. In-Memory `confirmGen` vs In-Flight Timer** | **FOLDED** | `cancelPendingConfirmTimerLocked` ([store_commit.go:L722](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L722)) increments `s.confirmGen`. If a timer callback fired right before `Stop()` and parked on `s.mu`, its `gen != s.confirmGen` check in `PromoteRollback` ([store_commit.go:L860](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L860)) invalidates the callback. |
| **A4. Canonical Hash Equivalence** | **FOLDED** | Arm-side `canonicalConfigHash(tree) = sha256(Format(jsonRoundTrip(tree)))` normalizes invalid UTF-8 via `json.MarshalIndent` (replacing invalid bytes with `U+FFFD`) at arming ([store_commit.go:L543](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L543), [store.go:L407](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store.go#L407)). On recovery, `s.active` is loaded via `json.Unmarshal` (`ReadActiveMeta`), which decodes the already-marshaled file from disk. The recovery side is already in canonical `U+FFFD` form and does not require an additional round-trip. |
| **A5. `SyncApply` Arm Asymmetry** | **FOLDED** | `SyncApply` ([store.go:L717](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store.go#L717)) cancels pending local confirm windows via `cancelPendingConfirmTimerLocked()` but never arms a local timer (since it receives authoritative config from primary). |

---

## Part B: Fresh Attacks & Plan Deficiencies

### Attack 1: False Claim Regarding `confirm.json` Compatibility Envelope
* **Plan Claim** ([plan.md:L169-170](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L169-L170), [plan.md:L769-772](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L769-L772)):  
  > *"The tombstone record-schema change rides the existing envelope versioning (`wrapEnvelope`, `db.go:443-450`); the /engineer pass decides the writer-version bump (pre-floor readers fail closed by design)."*
* **Code Contrast**:  
  `confirm.json` explicitly **does NOT** use `wrapEnvelope` on master today ([db.go:L204-206](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L204-L206)):
  ```go
  // No #1917 compatibility envelope is used — the file is transient recovery state,
  // not a committed config, and confirmRecord evolves via additive JSON fields.
  ```
  `wrapEnvelope` is only invoked inside `writeTreeMarked` ([db.go:L450](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L450)) for config files (`active.json`, `candidate.json`). `WriteConfirm` ([db.go:L207](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L207)) outputs raw JSON.
* **Impact**:  
  Because there is no envelope header on `confirm.json`, an older binary reading a tombstoned `confirm.json` during a version downgrade will unmarshal the JSON normally, ignore `Resolved: true` (standard `json.Unmarshal` behavior), and re-arm or roll back an already-resolved window. The plan's claim that `confirm.json` "rides the existing envelope versioning" is false.

---

### Attack 2: Tombstone Write vs. `#5637` Degenerate-Record Gate
* **Code Mechanics**:  
  `ReadConfirm` enforces the `#5637` degenerate record gate ([db.go:L275-281](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L275-L281)):
  ```go
  if rec.Deadline.IsZero() {
      return nil, fmt.Errorf("parse confirm state: pending commit-confirmed record has no deadline")
  }
  if rec.PrevTree == nil {
      return nil, fmt.Errorf("parse confirm state: pending commit-confirmed record has no rollback target")
  }
  ```
* **Impact**:  
  If the tombstone is written as a minimal record `{ "resolved": true }` (omitting `Deadline` and `PrevTree`), `ReadConfirm()` on recovery will fail at line 275/278 with a parse error (`err != nil`). Recovery in `recoverPendingConfirmLocked` ([store_persist.go:L141](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L141)) catches `err != nil`, logs a warning, and **returns early without ever reaching the `rec.Resolved` check or cleaning up `confirm.json`**.
* **Fix Required in Plan**:  
  The plan must specify that either:
  1. `ReadConfirm`'s `#5637` gate is modified to exempt tombstoned records (`if !rec.Resolved { ... }`), OR
  2. Tombstones must be written via read-mutate-write (preserving `Deadline` and `PrevTree`).

---

### Attack 3: Retry Loop Dual Duty
* **Verified**: `persistRetryLoop` ([store_persist.go:L439-L453](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L439-L453)) re-drives `removeConfirmState()` when `s.confirmRemoveDegraded` is true. If the tombstone write succeeded prior to an unlinking failure, the record on disk already has `Resolved: true`, making recovery safe even if the retry loop is interrupted by a crash.

---

### Attack 4: Recovery Total Order
* **Verified**: The total evaluation order in `recoverPendingConfirmLocked`:
  1. `ReadConfirm()` parse check
  2. `rec.Resolved` check $\rightarrow$ drop tombstone
  3. `GuardedHash` mismatch $\rightarrow$ drop stale record
  4. Expiration check (`time.Now().After(rec.Deadline)`) $\rightarrow$ expired revert
  5. Work Item H (`rec.FirstCommit && s.compiled.Chassis.Cluster != nil`) $\rightarrow$ Load-time revert
  6. Re-arm pending window

  This ordering is sound and prevents re-arming or double-reverting.

---

## Required Remediation for `NEEDS-REVISION`

1. **Correct `confirm.json` Envelope Claims**: Update [plan.md](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md) to acknowledge that `confirm.json` does not currently use `wrapEnvelope`, and explicitly specify whether `WriteConfirm` should be updated to wrap an envelope or if `confirmRecord` schema changes rely on additive JSON fields with documented downgrade semantics.
2. **Specify `#5637` Degenerate Gate Modification**: Update [plan.md](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md) to explicitly specify that `ReadConfirm()` in [db.go](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L275) must exempt `Resolved: true` records from the zero-deadline and nil-PrevTree checks.
