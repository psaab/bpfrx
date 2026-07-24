# Codex hostile plan-review — round 19 (plan v19 @ 1cd0ad1dd)

Task: task-mrzbgq1e-cqjb0p (session 019f958a-71f2-7f82-a285-5ebd1580d5f2).
Verdict: NEEDS-REVISION (3 MAJOR, 6 MINOR); split ruling SPLIT-REJECTED (reasoning inside). Raw companion output follows verbatim.

---

Fold verification:

1. PARTIAL — The churn disclaimer is folded, but the strict-per-pass claim is still false: “eventually-successful I/O” permits arbitrarily many stuttering passes, and tombstone-success/unlink-failure explicitly retains the same debt (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1247-1256,1394-1411`). The required property is eventual convergence under quiescence, fair retries, and eventual success—not shrinkage on every pass.

2. PARTIAL — Same-key R-over-W subsumption is stated and a membership check at W’s turn is sufficient without sorting (`plan.md:1412-1423,1767-1771`). It does not cover R_A executing before R_B: R_A’s mismatch action rewrites current B even though R_B exists (`plan.md:1345-1357,1384-1388`), allowing B to become durable before a crash and then re-arm on recovery (`pkg/configstore/store_persist.go:149-165,231-253`).

3. PARTIAL — Plain commit and SyncApply can correctly key failed orphan removal to seeded A because active writes do not change `onDiskArmID` (`plan.md:1298-1344,1628-1638`), closing the existing early return (`pkg/configstore/store_commit.go:678-682`). Applying the same cleanup generically to CommitConfirmed before B’s confirm record is written adds a hazardous durability window (`pkg/configstore/store_commit.go:437-468,503-524`).

4. PARTIAL — Re-driving DeleteConfirm after confirmed absence is correct for removal debts and supplies the required directory barrier (`plan.md:1513-1520`; `pkg/configstore/db.go:297-315`; `pkg/configstore/store.go:152-166`). It is incorrect for a standalone rewrite debt: absence must restore the still-live window’s record or remain degraded, not no-op and clear.

5. PARTIAL — The DEBT/BOOT distinction and reseed exception are explicit (`plan.md:1497-1513`). Same-Store arm/probe ordering is safe under `s.mu`: if B commits first, the probe reads and reseeds B (`pkg/configstore/store_commit.go:368-388`; `pkg/configstore/store_persist.go:402-405`). However, DEBT incorrectly conflates removal and rewrite continuations, while BOOT clears its latch before deferred recovery or supersession is durably settled. An elapsed pending deadline should cause expiry at restart, but the store must remain degraded until that restart occurs.

6. FOLDED — `ErrConfirmStateUnreadable` can be given a fail-closed classification at `pkg/daemon/bootstrap.go:52-63`; the sole production classifier call is `pkg/daemon/daemon_run_bringup.go:277`. Load occurs before naming/managers (`pkg/daemon/daemon_run.go:157-177`), so the stated exit/restart posture is implementable and cannot strand fxp0.

7. FOLDED — The snapshot faithfully separates today’s active and confirm-removal aggregate causes and adds terminal state with the stated precedence (`pkg/configstore/store_persist.go:342-353`; `pkg/configstore/store.go:114-166`; `plan.md:1592-1627`). Config-field plumbing is testable through `pkg/api/server.go:93-140,324-340,408-425`, existing callback tests at `pkg/api/health_test.go:220-275` and `pkg/api/metrics_persist_degraded_test.go:25-27`, and daemon wiring at `pkg/daemon/daemon_run_servers.go:370-374`.

8. PARTIAL — The staged barrier, plain-goroutine lifecycle, and Config plumbing are folded (`plan.md:1247-1256,1521-1525`). The retry envelope is internally ambiguous, and stale absence/health/error-policy claims remain elsewhere in the body (`plan.md:1532-1538,1751-1764,2014-2016,2201-2208,2588-2633`).

New findings:

MAJOR 1 — Older removal debt can resurrect the current resolved record. The R_A mismatch rule rewrites current B (`plan.md:1345-1357`) while the plan expressly permits R_A, W_B, and R_B to coexist (`plan.md:1384-1388`). If R_A runs before R_B, it durably restores pending-shaped B; a crash before R_B executes makes B binding and re-arms the resolved window (`pkg/configstore/store_persist.go:149-165,231-253`). R-before-W ordering does not constrain R_A versus R_B. Prioritize the removal matching the current ArmID, or prohibit any rewrite of K while R_K exists, and add an R_A-first crash leg to x16.

MAJOR 2 — Rewrite-origin debt is incorrectly processed using removal semantics. W_B can originate from a post-rename arm failure while B’s timer remains live (`plan.md:1361-1369`; `pkg/configstore/store_commit.go:503-524`), yet the proposed DEBT continuation runs match→tombstone→delete for both removal and rewrite origins (`plan.md:1497-1503`). That resolves an unconfirmed live window. Likewise, if the record is externally absent, DeleteConfirm+clear (`plan.md:1513-1520`) leaves the live window without restart recovery. R debts may delete; W debts must rewrite their saved record, and W-absent must restore that record or remain degraded. Absent-for-W is no-op-and-clear only when a same-key R has atomically consumed W.

MAJOR 3 — BOOT-origin needs persistent substates, not clear-and-defer. The plan clears a repaired BOOT latch and postpones action until restart (`plan.md:1504-1513,1561-1575`), but neither plain cleanup nor SyncApply can identify a superseded record while it was unreadable (`pkg/configstore/store_commit.go:678-682`; `pkg/configstore/store.go:697-745`). A durable replacement B followed by repair of old A can therefore go green, then restart into A and re-arm/revert B (`pkg/configstore/store_persist.go:149-165,171-253`). Even without B, a pending record can expire while health reports clean. Track at least “restart recovery owed” and “superseded while unreadable”; the former remains degraded until restart, and the latter becomes removal debt.

MINOR 1 — The convergence proof uses the wrong measure. “Every pass shrinks” (`plan.md:1398-1403`) contradicts staged retained debt (`plan.md:1247-1256`), and the single confirm slot does not by itself bound queued historical keys under churn (`plan.md:1334-1342,1404-1407`). Specify a lexicographic remaining-stage measure and eventual zero after a failure-free suffix; also pin merge semantics so tombstone-required dominates delete-finishing debt.

MINOR 2 — Confirmed-commit orphan cleanup is ordered incorrectly. The generic supersession rule includes CommitConfirmed (`plan.md:1322-1328`), but current active finalization precedes starting the timer and writing B’s confirm record (`pkg/configstore/store_commit.go:437-468,503-524`). Tombstoning/deleting A there adds two durable operations to the admitted recordless crash window. Let successful WriteConfirm(B) overwrite A; pre-rename failure should leave A/R_A intact.

MINOR 3 — The retry count and cancellation seam are underspecified. “Three attempts,” delays 100/200/400 ms, and approximately 0.7 seconds imply either four reads or an unused final delay (`plan.md:1532-1538,2014-2016,2623-2628`). Also, current `Load()` and its startup call chain have no context (`pkg/configstore/store_persist.go:21-24`; `pkg/daemon/daemon_run.go:157-161`; `pkg/daemon/daemon_run_bringup.go:245-277`). Pin this as initial read plus three retries and specify a context-aware wrapper while preserving `Load()`.

MINOR 4 — The proposed confirm-persist health message only describes removal debt (`plan.md:1600-1610`), but the category also contains rewrite debt (`plan.md:1364-1368`). A W-only failure risks losing the pending recovery record, not resurrecting stale rollback. Use a generic durability-degraded diagnostic or report the debt kind.

MINOR 5 — Stale body and source-document claims remain. The plan still says absence clears/drops (`plan.md:1751-1755,2588-2592`) and still refers to “both causes” after introducing three (`plan.md:1760-1764,2201-2208,2595-2599`). Existing documentation also says all confirm-read failures log and continue and describes only three Load shapes (`pkg/configstore/db.go:239-241`; `pkg/configstore/README.md:470-473,937-968`). These belong in the promised documentation sweep.

MINOR 6 — “Present plus no local window is by construction orphan” needs the singleton ownership premise (`plan.md:1324-1326`). `s.mu` serializes only one Store (`pkg/configstore/store.go:61-64`); another Store sharing the directory could own a live window. Production currently creates one Store (`pkg/daemon/daemon.go:1042-1053`), so document that invariant rather than attributing it to the mutex.

Split ruling:

SPLIT-REJECTED — The proposed split includes H without H2, although the plan itself recognizes their correctness dependency (`plan.md:1123-1148`). Today a failed confirm-record removal can linger (`pkg/configstore/store_commit.go:575-608`) and later bind/re-arm (`pkg/configstore/store_persist.go:149-165,231-253`). H alone makes that failure immediate for a confirmed FirstCommit+cluster configuration rather than merely preserving master’s delayed hazard. A sound narrow split would ship the synchronized accessor work plus G and move H together with H2; alternative A is not sound.

NEEDS-REVISION

Codex session ID: 019f958a-71f2-7f82-a285-5ebd1580d5f2
Resume in Codex: codex resume 019f958a-71f2-7f82-a285-5ebd1580d5f2
