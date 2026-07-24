# AGY adversarial plan-review — round 22 (plan v22 @ 055ee7f45)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY. Raw output follows verbatim. NOTE (claude-smr-plan-r22.md): AGY's attack-1 rationale assumes the arm-overwrite-clears-D transition that v22 left unspecified — the SMR M1 / Codex M2 pin.

---

(A) Verification of Folds 1-3

1. Fold 1 — Dominance scoped + restore prioritized (D1/D2): FOLDED
- File:line evidence: `docs/research/2114-nat-pool-alarm-dp-race/plan.md:1598-1636`, `pkg/configstore/store_commit.go:470-524`, `pkg/configstore/store.go:168-179`, `pkg/configstore/store_persist.go:149-165`.
- Verification: Restore-first (D2) prioritizes live window restores over R-kind removal debts targeting the same slot. $W_C$ replaces record $K$ with $s.armedRecord$ via durable `WriteConfirm`; once the restore's directory fsync lands, $R_K$ is subsumed and cleared. This closes the v21 recordless-live-window gap (where an $R_B$ tombstone->delete could leave active $C$ durable without a recovery record if a crash occurred before $W_C$). Furthermore, $s.armedRecord$ is captured verbatim at arming time (`store_commit.go:503-524`) and updated at every nested arm, while $s.armedArmID$ is cleared upon resolution. Thus, the restore payload can never be a dead window's record.

2. Fold 2 — Eager supersession as two-step synthesized tombstone + delete + D-kind slot debt: FOLDED
- File:line evidence: `docs/research/2114-nat-pool-alarm-dp-race/plan.md:1759-1805`, `pkg/configstore/db.go:266-281`, `pkg/configstore/store_persist.go:149-165`.
- Verification: The synthetic tombstone (`Resolved: true`, `PrevTree = s.active.Clone()`, `Deadline = now+window`, `GuardedHash = canonicalConfigHash(s.active)`, fresh `ArmID`) passes the #5637 non-degenerate gates at `db.go:275-281`. Replay during boot drops at the `rec.Resolved == true` check prior to hash comparison at `store_persist.go:149-165`. Any write/unlink failure raises a D-kind slot debt retried by `persistRetryLoop`. For pre-v22 downgrade readers ignoring `Resolved`, the record appears as a valid pending confirm whose `PrevTree` equals active configuration: on expiry, it reverts active to `PrevTree` (a config-neutral no-op, though incurring runtime re-apply churn), which is explicitly pinned and acceptable.

3. Fold 3 — Identity split & doc sweeps: FOLDED
- File:line evidence: `docs/research/2114-nat-pool-alarm-dp-race/plan.md:1483-1498`, `1524-1597`, `2008-2018`, `2650-2652`, `pkg/api/health.go:65-71`.
- Verification: R-kind debts key records via `onDiskArmID`; W-kind debts key live windows via `armedArmID`/`s.armedRecord`. Both `x4c'` regression copies in plan.md reflect live-window re-keying and restore-overwrite. Section 9 x19 marker text has been removed. The health state hierarchy enforces four-level precedence (`TerminalUnreadable > RestartRecoveryOwed > ConfirmDebt > ActivePersist`) with the enum + mask, and §6 explicitly documents the three new cause-distinct degraded messages.

---

(B) Fresh Attacks and Outcomes

1. Attack 1: Unexpected read success during D-kind slot debt retry
- Attack: A D-kind slot debt is retrying eager supersession over an unreadable `confirm.json` slot. During a retry pass, `ReadConfirm()` unexpectedly succeeds (e.g., out-of-band repair or transient mount recovery), returning a valid `confirmRecord` $A$. Will the D-kind debt incorrectly tombstone/delete a valid pending record?
- Outcome: FAILED.
- Reason: The plain commit or SyncApply $B$ that triggered eager supersession already persisted active config $B$ durably to `active.json`. Any record $A$ present before $B$ has $A.\text{GuardedHash} \neq \text{hash}(B)$, making it stale under total order (`store_persist.go:159-165`). If a new confirmed commit $C$ was armed after $B$, its arming path (`writeConfirmState`) replaced `confirm.json` and updated $s.armedArmID$, consuming/clearing the D-kind debt. Thus, an unexpectedly readable record $A$ under D-kind debt is always stale or superseded; tombstoning and deleting $A$ is the required total-order outcome.

2. Attack 2: Coexistence collision between D-kind slot debt and R-kind debts
- Attack: Can a D-kind slot debt (which keys the slot) collide or race with an R-kind debt (which keys `onDiskArmID`) for the same `confirm.json` slot?
- Outcome: FAILED.
- Reason: D-kind debts exist only when `confirm.json` was unreadable at boot (so no `onDiskArmID` could be read or seeded into an R-kind debt). R-kind debts are constructed only from readable, resolved records. A slot is either unreadable (D-kind) or contains a known resolved record (R-kind). A subsequent confirmed commit overwrites the slot or restores it via W-kind, clearing D-kind. They are mutually disjoint by construction.

3. Attack 3: Downgrade reader hazard on synthetic tombstone
- Attack: If a node is downgraded to a pre-v22 binary while a synthetic tombstone (`Resolved: true`, `PrevTree = s.active.Clone()`) exists on disk, could the old binary misinterpret the record and corrupt state?
- Outcome: FAILED.
- Reason: Pre-v22 binaries decode `confirmRecord` via `json.Unmarshal` (`db.go:263`), ignoring unknown field `Resolved`. The old binary reads `rec.Deadline` (future) and `rec.PrevTree` (`s.active.Clone()`). Upon deadline expiry, `recoverPendingConfirmLocked` (`store_persist.go:175`) assigns `s.active = prevTree`. Since `prevTree` is identical to `s.active`, the configuration content is unchanged. The re-apply causes transient subsystem churn (XDP/FRR), but zero configuration drift.

---

Verdict: PLAN-READY
