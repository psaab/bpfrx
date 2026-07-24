# Codex hostile plan-review — round 21 (plan v21 @ bbd9fd43c)

Task: task-mrzftmkd-ft8x9g (session 019f95fa-2519-7bd1-a93a-e60303a0b74c).
Verdict: NEEDS-REVISION (3 MAJOR, 2 MINOR). Raw companion output follows verbatim.

---

Fold verification:
1. PARTIAL — The normative W table correctly re-keys B→C and restores C verbatim (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1469-1505`; `pkg/configstore/store_commit.go:470-524`), but contradictory debt-key/test directives remain and R-first dominance creates a crash gap.
2. FOLDED — `s.armedRecord` retains Deadline, GuardedHash, HashBasis, FirstCommit, PrevTree, and ArmID verbatim; every nested arm replaces it (`plan.md:1477-1502`; `pkg/configstore/store.go:168-179`; `pkg/configstore/store_commit.go:503-553`).
3. PARTIAL — Successful plain-commit/SyncApply writes are durable before deletion (`pkg/configstore/store_commit.go:180-210`; `pkg/configstore/store.go:738-760`; `pkg/configstore/db.go:435-460`), but delete failures and POST-rename transitions are unspecified, so the restart-before-repair chain remains constructible.
4. FOLDED — The independent debt mask and record-state enum carry all promised messages and coexistence, with correct precedence and retained aggregate gauge OR (`plan.md:1805-1829`; `pkg/configstore/store_persist.go:342-353`; `pkg/api/metrics.go:948-958`).
5. PARTIAL — x9, x11, and the three schema fields are corrected (`plan.md:1950-1972,2464-2469,2877-2896`), but stale W, marker, and health-precedence claims remain in the body.

New findings:

MAJOR 1 — R-first dominance creates a crash-durable recordless live window. With R_B plus live W_C, v21 makes W_C wait while R_B tombstones/deletes B, then restores C (`plan.md:1495-1502,1530-1539`). A crash after B’s durable tombstone but before C’s independent `WriteConfirm` makes recovery drop B as Resolved (`plan.md:1876-1883`) while durable active C has no recovery record, silently making an unconfirmed config permanent. Tombstone/delete and restore are separate durable operations (`pkg/configstore/db.go:199-219,284-316`). W_C should durably overwrite B first—simultaneously superseding B and installing C—then stale-clear R_B; R_B should dominate writes of B, not a newer desired C.

MAJOR 2 — Eager deletion specifies only its happy path. The terminal observer is expressly read-only (`plan.md:1650-1652`), while deletion is claimed to close all replay (`plan.md:1691-1708`). `DeleteConfirm` can fail before unlink or after unlink before dir-fsync (`pkg/configstore/db.go:297-315`); no ArmID-keyed debt can identify an unreadable record, and no unkeyed BOOT-delete debt is defined. A crash can replay A; allowed repair then reaches restart recovery (`plan.md:1670-1680,1774-1780`), where content-match or legacy-empty A can bind (`pkg/configstore/store_persist.go:149-165,231-253`). POST-rename plain commit, SyncApply, confirmed-active write, and confirmed-arm outcomes are also unpinned (`pkg/configstore/store_commit.go:180-200,437-452,503-553`; `pkg/configstore/store.go:738-746`). A successful delete could provide the same-directory durability barrier, but v21 never defines that transition or its failure debt.

MAJOR 3 — Normative implementation and regression text still require the rejected v20 W_B behavior. The body says debts key only on `onDiskArmID` (`plan.md:1439-1452`), while both regression copies say C PRE-rename leaves W_B standing and forbid ArmID-mismatch overwrite (`plan.md:1909-1913,2834-2838`). That directly contradicts the new desired-record W_C rule (`plan.md:1469-1502`) and would reproduce r20 M1.

MINOR 1 — The detailed x19 regression still specifies the deleted marker→clean-read→R-debt workflow (`plan.md:2952-2960`), contradicting eager deletion (`plan.md:1681-1708,2902-2909`).

MINOR 2 — Health regressions still pin the old three-level precedence and omit RestartRecoveryOwed (`plan.md:1995-2000,2042-2047,2919-2925,2969-2973`); §6 also says the response gains two messages although terminal, restart-required, and generic debt messages are all new (`plan.md:2532-2534`).

NEEDS-REVISION

Codex session ID: 019f95fa-2519-7bd1-a93a-e60303a0b74c
Resume in Codex: codex resume 019f95fa-2519-7bd1-a93a-e60303a0b74c
