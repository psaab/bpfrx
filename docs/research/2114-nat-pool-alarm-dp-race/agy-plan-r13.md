### Verdict

**`PLAN-READY-WITH-NITS`**

---

### (A) Verification of v13 Folds Against Worktree Code

1. **Envelope claim correction & downgrade semantics**: **FOLDED**
   - **Evidence**: [`db.go:200-205`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L200-L205) explicitly states: *"No #1917 compatibility envelope is used — the file is transient recovery state, not a committed config, and confirmRecord evolves via additive JSON fields."*
   - **Verification**: `WriteConfirm` marshals `confirmRecord` directly without `wrapEnvelope` (which only wraps `active.json` at `db.go:450`). Standard `json.Unmarshal` in `ReadConfirm` ([`db.go:264`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L264)) ignores unrecognized fields. An older build unmarshalling a new `confirmRecord` ignores `Resolved` and `HashBasis`, maintaining faithful legacy behavior.

2. **Read-Mutate-Write tombstone preserving full record**: **FOLDED**
   - **Evidence**: [`db.go:275-281`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L275-L281) rejects records with `Deadline.IsZero()` or `PrevTree == nil`.
   - **Verification**: A minimal `{"resolved":true}` JSON would fail `ReadConfirm` at line 275 and abort recovery at [`store_persist.go:141`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L141). Preserving all fields in the read-mutate-write helper guarantees the tombstone passes `#5637` validation unmodified.

3. **Tombstone-first linearization & crash cases**: **FOLDED**
   - **Evidence**: [`store_commit.go:717-726`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L717-L726).
   - **Verification**: Writing the tombstone durably via `WriteConfirm` *before* in-memory timer cancellation (`cancelPendingConfirmTimerLocked`) establishes durable resolution as the single atomic linearization point.
     - *Crash before tombstone write*: Disk has intact pending record $\rightarrow$ recovery re-arms or rolls back (linearization point not reached).
     - *Crash after tombstone write*: Disk has `Resolved: true` $\rightarrow$ recovery drops the tombstone without re-arm/rollback.
     - *Tombstone write fails + crash before retry*: Documented irreducible residual window; in-memory resolution completes, retry debt is retained, and health stays degraded.

4. **Debt-supersession & arm-write ordering**: **PARTIAL (Nit)**
   - **Evidence**: `writeConfirmState` at [`store_commit.go:535-554`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L535-L554).
   - **Verification**: Clearing `confirmRemoveDegraded` when arming a new window is sound because writing record B overwrites record A. However, clearing the debt **must be guarded by `WriteConfirm(rec) == nil`**. If `WriteConfirm` fails, record B is not written, record A remains on disk, and clearing `confirmRemoveDegraded` would prematurely drop the retry debt. (See Nit 1).

5. **Versioned hash basis & dual-basis compare**: **FOLDED**
   - **Evidence**: Arm site [`store_commit.go:548`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L548) vs recovery [`store_persist.go:159`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L159).
   - **Verification**: For normal records without active migrations, `tree.Format()` is identical before and after JSON serialization. Additive `HashBasis: "canonical-v1"` allows recovery to select `canonicalConfigHash` for new records while using `journalConfigHash` for legacy records (where `HashBasis == ""`), preventing cross-version false stale-drops.

6. **Arm-site inventory correction**: **FOLDED**
   - **Evidence**: [`store_commit.go:524`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L524).
   - **Verification**: `writeConfirmState` is indeed the sole production arm site called via `CommitConfirmedGen`. `SyncApply` ([`daemon_apply_commit.go:710-713`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/daemon_apply_commit.go#L710-L713)) only cancels/resolves pending confirm windows.

7. **Read-mutate-write serialization vs concurrent arms**: **FOLDED**
   - **Evidence**: [`store_commit.go:483,737,782`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L737).
   - **Verification**: All arm, confirm, demotion, and rollback operations hold `s.mu.Lock()`, ensuring read-mutate-write tombstone operations and concurrent arms are strictly serialized.

---

### (B) Analysis of Fresh Attacks & Edge Cases

1. **Intermediate-basis records**:
   - **Finding**: Safe. Because v11–v13 fixes ship together in a single PR, no released build can produce any basis other than legacy (empty `HashBasis`) or `canonical-v1`. Dual-basis logic fully covers all real-world record states.

2. **Tombstone written by a NEW build on a LEGACY record**:
   - **Finding**: Safe. Read-mutate-write reads the legacy record (`HashBasis == ""`), sets `Resolved: true`, and writes it back with `HashBasis` remaining `""`. On recovery, `rec.Resolved == true` is evaluated **first** in the recovery total order, dropping the record before any `HashBasis` / `GuardedHash` comparison is performed.

3. **Resolved record with a mismatched hash (Resolved-first ordering)**:
   - **Finding**: Safe & Sound. Placing `rec.Resolved` check first in recovery total order ensures that any tombstoned record is immediately dropped and cleaned up, regardless of subsequent modifications to `s.active`.

4. **Recovery total order end-to-end**:
   - **Verification**:
     1. `ReadConfirm()` parse & degenerate gate ([`db.go:275-281`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L275-L281))
     2. `rec.Resolved == true` $\rightarrow$ drop tombstone via `resolveConfirmRemovalLocked`
     3. `GuardedHash` mismatch (dual-basis aware) $\rightarrow$ drop stale record via `resolveConfirmRemovalLocked`
     4. `time.Now().After(rec.Deadline)` $\rightarrow$ expired-during-downtime revert
     5. Work item H (`rec.FirstCommit && s.compiled.Chassis.Cluster != nil`) $\rightarrow$ revert-at-Load
     6. Pending active record $\rightarrow$ re-arm `confirmTimer`
   - The sequence is deterministic and leak-free across all branches.

---

### Nits / Required Clarifications for Implementation

* **Nit 1 (`writeConfirmState` debt clearing guard)**: In [`plan.md:200-205`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L200-L205) and [`:890-895`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L890-L895), ensure the plan explicitly specifies that `writeConfirmState` clears `confirmRemoveDegraded` **only on `s.db.WriteConfirm(rec) == nil` success**. If `WriteConfirm` fails, record B was not written to disk, so record A was not overwritten and `confirmRemoveDegraded` must remain `true`.
