# Codex hostile plan-review — round 20 (plan v20 @ d37961cd7)

Task: task-mrzdpr86-uznxse (session 019f95c4-215c-7c73-a576-b8dd8c449882).
Verdict: NEEDS-REVISION (3 MAJOR [2 NEW + 1 re-verification gap], 3 MINOR). Raw companion output follows verbatim.

---

Fold verification:

1. FOLDED — SAME-RECORD dominance requires R_A to wait while R_B keys current B and permits stale-debt clearing only after R_B’s tombstone barrier lands (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1482-1497`). The retry holds `s.mu` throughout its pass (`pkg/configstore/store_persist.go:402-460`), while arms take that mutex (`pkg/configstore/store_commit.go:368-392`), so arm C cannot interleave between read and tombstone.

2. PARTIAL — The R/W tables, resolved-window stale-clear, same-ArmID restore, and active-hash reasoning are sound (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1459-1481`; `pkg/configstore/store_commit.go:503-550`). However, nested-arm PRE-rename handling leaves W_B healing the wrong window, and the restore payload is not retained explicitly.

3. PARTIAL — RESTART-RECOVERY-OWED correctly remains 503 until reboot, and that conservative posture is acceptable (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1604-1614`). SUPERSEDED-WHILE-UNREADABLE closes the original same-process B→repair-A case, but its marker is neither crash-durable nor scoped across confirmed-arm outcomes (`:1615-1623`).

4. FOLDED — The per-debt ordering, failure-free-suffix convergence, and tombstone-required-over-delete merge are coherent with dominance (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1478-1514`).

5. FOLDED — For a seeded Present(A), confirmed commit overwrites A with its single arm `WriteConfirm`; PRE-rename failure leaves A intact with R_A, adding no pre-arm recordless interval (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1383-1399`; `pkg/configstore/store_commit.go:437-468,503-524`; `pkg/fsatomic/fsatomic.go:45-52`).

6. FOLDED — Initial read plus three retries, 100/200/400 ms delays, `LoadContext(ctx)`, and preserved `Load()` are implementable (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1646-1669`; `pkg/configstore/store_persist.go:21-24`; `pkg/daemon/daemon_run.go:157-161`).

7. PARTIAL — The named source-document sweep and production single-Store premise are included (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1377-1381,2383-2392`; `pkg/daemon/daemon.go:1046-1053`). The health snapshot cannot carry the promised subtype/details, and stale BOOT-latch claims remain in the body.

New findings:

MAJOR 1 [NEW — not raised in r19] — Nested arm C leaves W_B healing the superseded window. V20 explicitly leaves W_B standing when C’s `WriteConfirm` fails PRE-rename, then w-a rewrites matching B without checking `armedArmID` (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1433-1448,1467-1475`). Nested C stops B’s timer and installs C’s new generation, deadline, timer, and record (`pkg/configstore/store_commit.go:470-524`); PRE-rename failure leaves B intact (`pkg/fsatomic/fsatomic.go:45-52`). The retry therefore durably rewrites B while C is live. Different-content C causes recovery to stale-drop B and leave C unconfirmed; identical-content C re-arms B’s old deadline. PRE failures need current-live-window-aware handling, such as a desired-record W_C debt.

MAJOR 2 [NEW — not raised in r19] — `confirmRecordSupersededDuringLatch` has no durable reconstruction rule. Boot 1 can latch unreadable A, durably land B, set the marker, then crash before the clean probe. Boot 2 loses the marker; repaired A can bind when its `GuardedHash` is legacy-empty or B is byte-identical—ambiguities the plan itself acknowledges (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1189-1193,1615-1623`). Normal recovery then re-arms or reverts B (`pkg/configstore/store_persist.go:149-165,231-253`). Supersession evidence must survive Store reconstruction until a durable tombstone barrier.

MAJOR 3 [RE-VERIFICATION GAP IN v20 FOLD 3] — The marker is unscoped across confirmed arms. After plain B sets it, a confirmed arm C may successfully overwrite A with C before the probe (`pkg/configstore/store_commit.go:503-550`; `pkg/configstore/db.go:207-218`); v20 would still treat the current record as stale and create R_C, deleting a live window (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1615-1623`). Conversely, a PRE-rename confirmed-arm failure leaves unreadable A, but the marker excludes confirmed commits and R_A requires a seeded Present(A), unavailable in the LATCH state (`:1355-1360,1386-1394`). Successful, PRE-, and POST-rename arm outcomes need explicit latch/marker transitions.

MINOR 1 [RE-VERIFICATION GAP IN v20 FOLD 2] — W-absent restoration does not pin its payload. Current window state retains the rollback tree/config and timer, but not the absolute deadline or hash (`pkg/configstore/store.go:168-179`); those exist only at the arm site (`pkg/configstore/store_commit.go:503-549`). Require the W debt to retain the immutable attempted record, including Deadline, GuardedHash, HashBasis, FirstCommit, PrevTree, and ArmID (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1471-1475,2127-2136`).

MINOR 2 [RE-VERIFICATION GAP IN v20 FOLDS 3/7] — The promised health diagnostics are structurally uncarryable. The snapshot contains exactly three booleans (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1720-1724,2183-2185`), but `/health` must distinguish corrupt/unreadable from readable-but-restart-required and report R/W debt kinds (`:1725-1734,2193-2196`). The API receives only that callback (`pkg/api/server.go:132-140,338,424`); it needs a recovery-state enum and debt-kind mask/detail.

MINOR 3 [RE-VERIFICATION GAP IN v20 FOLD 7] — Stale body expectations remain. RESTART-RECOVERY-OWED explicitly retains its latch until reboot (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1604-1614`), but x9 twice says clean repair clears the boot latch in-process (`:1857-1864,2754-2759`), and x11 still collapses every unreadable seed into a latch despite transient errors now failing Load (`:1869-1871`). The documentation sweep also says “two new fields” (`:2350-2354`) although the schema adds Resolved, HashBasis, and ArmID (`:1764-1782`).

NEEDS-REVISION

Codex session ID: 019f95c4-215c-7c73-a576-b8dd8c449882
Resume in Codex: codex resume 019f95c4-215c-7c73-a576-b8dd8c449882
