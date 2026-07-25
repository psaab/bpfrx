# AGY adversarial plan-review — round 25 (plan v25 @ 3028893aa)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY. Raw output follows verbatim.

---

(A) Verification of each fold 1-6:

1. Permanent-error state machine unified: FOLDED
Evidence: [plan.md:L712-L725](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L712-L725), [plan.md:L1857-L1884](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L1857-L1884).
The doctrine self-contradiction is eliminated. Permanent read error terminalization is strictly SCOPED to content-dependent debts (R-kind read-back tombstones), where reading `confirm.json` is required to construct the `Resolved: true` mutation and where auto-erasure would hide a corrupt record that the operator could inspect or repair. Content-independent debts (W-kind restore using in-memory `s.armedRecord` and D-kind synthesized tombstones) are EXEMPT because their action requires no read-back and their purpose is to overwrite a provably superseded unreadable slot. Write failures on any debt kind NEVER terminalize; they retain retry debt and loop degraded at 503 until disk/key issues are remediated.

2. Downgrade oracle corrected: FOLDED
Evidence: [store_persist.go:L166-L195](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L166-L195), [plan.md:L726-L734](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L726-L734), [plan.md:L1947-L1985](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L1947-L1985).
Code inspection confirms `store_persist.go:L175` assigns `s.active = prevTree` unconditionally on recovery. If `rec.FirstCommit` is true on an older reader (which ignores `Resolved: true`), lines [store_persist.go:L177-L184](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L177-L184) set `s.compiled = nil`, `s.everCommitted = false`, and write a `committed=0` marker, forcing the daemon into bootstrap/first-commit import handling rather than an empty-tree revert. The plan's requirement for `FirstCommit=false` on synthesized tombstones is load-bearing because it forces legacy readers into `store_persist.go:L185-L194` (`compiled` set, `everCommitted=true`, `committed=1`), preserving the operator-committed posture.

3. (w-u) restore failure phase-qualified: FOLDED
Evidence: [plan.md:L735-L738](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L735-L738), [plan.md:L1726-L1734](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L1726-L1734).
The failure of a (w-u) restore is accurately qualified by atomic write phase: a PRE-rename failure leaves the unreadable record intact on disk, returning the slot to D's (d-i) synthesized tombstone path; a POST-rename failure leaves live C's record visible on disk, keeping W-kind owed ((w-a) to make C durable) while D's mandatory slot re-read observes readable C (d-iii) and clears D as moot. Dedicated regressions for both phases are specified.

4. Operator ownership pinned: FOLDED
Evidence: [daemon.go:L1042-L1053](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon.go#L1042-L1053), [plan.md:L743-L748](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L743-L748), [plan.md:L1580-L1583](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L1580-L1583).
`confirm.json` is pinned as store-owned. A manually edited/repaired record is classified by the store's recovery pipeline upon load, never trusted at face value. Sanctioned operator remediations are deletion (confirmed absence) or repairing the file to valid schema/crypto for standard store classification. In-process arms/restores overwriting differing records are intentional under the single-Store ownership invariant (`daemon.go:L1042-L1053`).

5. Residual wording corrected: FOLDED
Evidence: [store_commit.go:L550-L553](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L550-L553), [plan.md:L739-L742](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L739-L742), [plan.md:L3073-L3081](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3073-L3081).
The residual wording is corrected: loss of a window's crash-recovery record occurs only if a crash lands inside the seconds-wide retry window before the process-local W debt completes. There is no post-crash heal (the process-local W debt dies with the process), matching master's arm-failure posture at `store_commit.go:L550-L553`.

6. Remaining schema copies unified: FOLDED
Evidence: [plan.md:L749-L753](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L749-L753), [plan.md:L2378-L2386](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L2378-L2386), [plan.md:L2702-L2710](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L2702-L2710), [plan.md:L3426-L3446](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3426-L3446).
All schema descriptions across §5.1, §9 (x14/x21), and §11 carry the exact 3-field snapshot `{ActivePersistDegraded, ConfirmDebtKindMask, ConfirmRecordState}`, derived aggregate `ConfigPersistDegraded()`, and 4-level precedence (`TerminalUnreadable` > `RestartRecoveryOwed` > `ConfirmDebt` > `ActivePersist`).

---

(B) Fresh attacks with outcomes:

1. Attack on Content-Dependent vs Content-Independent Boundary Edge: FAILED
Rationale: The distinction between content-dependent (R-kind) and content-independent (W-kind, D-kind) debts is technically sound. If an R-kind record is unreadable due to remediable master-key corruption ([crypto.go:L451](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/crypto.go#L451)) or file permission errors, auto-erasing or synthesizing a tombstone would destroy the unconfirmed rollback target (`rec.PrevTree`) stored inside `confirm.json`. Terminalizing R-kind debts keeps health at 503 degraded and preserves `confirm.json` on disk so that once the operator fixes `master.key`, `ReadConfirm` can succeed and recover the rollback intent. Conversely, W-kind (restore `s.armedRecord`) and D-kind (synthesized tombstone for a slot superseded by a durable `active.json` landing) carry their target content in memory or via active-tree synthesis; overwriting the unreadable slot is required to prevent a corrupt/stale record from lingering under a newer active config.

2. Attack on Invalid Master Key Remediation Message: FAILED
Rationale: The health endpoint renders standardized, cause-bearing precedence messages ("commit-confirmed recovery record is unreadable/corrupt; operator remediation required — see journal"), while the underlying error (`err`) is logged verbatim in the journal/slog output (`"invalid master key length in /etc/xpf/master.key"` or `"read master key: ..."`). The operator is explicitly directed to the journal, where the exact root cause (`master.key` vs `confirm.json`) is identified.

3. Attack on Downgrade Synthesized Tombstone Oracle: FAILED
Rationale: Setting `FirstCommit=false` in the synthesized tombstone record ensures that if an older reader (which ignores `Resolved: true`) unmarshals the record, it executes `store_persist.go:L185-L194`, compiling `PrevTree` (which equals `s.active`) and setting `everCommitted=true`. Setting `FirstCommit=true` would execute `store_persist.go:L177-L184`, clearing `compiled` and `everCommitted`, which forces the node into bootstrap mode. The pin is load-bearing and verified against `store_persist.go:L166-L195`.

VERDICT:
PLAN-READY
