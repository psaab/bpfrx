# Codex hostile plan-review — round 22 (plan v22 @ 055ee7f45)

Task: task-mrzhcqms-c4sh29 (session 019f9621-6127-7b13-b891-4dc25b622385).
Verdict: NEEDS-REVISION (4 MAJOR, 3 MINOR). Raw companion output follows verbatim.

---

Fold verification:
1. PARTIAL — D2’s serialization and durability premises hold (`pkg/configstore/store_commit.go:368-397,470-524`; `pkg/configstore/db.go:207-219`; `pkg/fsatomic/fsatomic.go:342-369`), but the earlier normative table still mandates R-first (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1542-1546`), and the failure matrix remains incomplete (`:1621-1628`).
2. PARTIAL — The synthetic record passes the deadline/PrevTree gates and Resolved precedes hash/expiry (`plan.md:1763-1775,1975-1982`; `pkg/configstore/db.go:266-281`), but D-debt reconstruction and readable-record transitions are unsound (`plan.md:1735-1779,1781-1787`).
3. PARTIAL — The identity split and both x4c′ copies are corrected (`plan.md:1481-1488,2008-2018,2959-2969`), but stale R-first, bare-delete, and sole-tombstone-producer claims remain (`:1542-1546,1943-1955,2083-2089,2144-2149`).
4. PARTIAL — §9 x19 and §6 are corrected (`plan.md:3087-3099,2649-2653`), but body x21 and §9 x14 retain the old three-level health model without the enum/mask (`:2153-2158,3050-3056`).

New findings:

MAJOR 1 — The rejected restore-last algorithm remains normative. The first W table says an R debt holds W back, tombstones/deletes the differing dead record, and only then lets W restore from absence (`plan.md:1542-1546`). That directly contradicts D2 (`:1577-1584,1614-1630`) and recreates r21 M1 because tombstone/delete and restore are separate durable operations (`pkg/configstore/db.go:207-219,297-316`): a crash between them leaves active C without its recovery record.

MAJOR 2 — D-kind can erase a newer live window. D keys only the slot and blindly re-runs synthesized tombstone→delete (`plan.md:1761-1779`), while new arms may occur between retry passes (`:1636-1650`; `pkg/configstore/store_persist.go:402-460`). A later confirmed arm can durably install live C (`pkg/configstore/store_commit.go:368-397,503-524`); no rule clears or reclassifies D, so its next pass overwrites and deletes C. A successful read must enter a defined normal/readable-record transition, with explicit D-versus-R/W supersession rules.

MAJOR 3 — Pre-tombstone crash reconstruction is impossible as specified. The plan claims that a crash before step (1) reconstructs the latch and D debt (`plan.md:1781-1783`), yet BOOT-origin is explicitly “no timer, no debt” (`:1735-1736`), the retry is process-local and abandoned on exit (`:1820-1823`), and a pre-rename tombstone failure persists no D provenance. Automatically recreating D for every corrupt boot record would also delete a genuinely pending but unreadable record. This crash case remains operator-mediated, not self-reconstructing.

MAJOR 4 — The acceptance text still mandates v21 behavior. Body x12, body x19, and §9 x12 require bare deletion, including “the same delete rule” after a confirmed-arm pre-rename failure (`plan.md:2083-2089,2144-2149,3035-3040`), contradicting synthesized tombstone+D and W restore (`:1753-1799`). Separately, four normative/test copies still call the read-mutate-write helper the “ONLY tombstone producer” (`:1943-1955,2021-2023,2355-2357,2975-2978`), although v22 necessarily adds the synthesized producer.

MINOR 1 — D2 overclaims its failure crash matrix. A pre-rename restore failure permits R_K’s tombstone→delete (`plan.md:1621-1622`); if that succeeds and the process crashes before the next W pass, K is absent, contradicting “K intact” and “never recordless” (`:1623-1628`). This requires a restore failure and fits the admitted best-effort persistence residual, but the invariant must be scoped accordingly.

MINOR 2 — The downgrade description repeats the rejected idempotence premise. It calls PrevTree=current “semantically harmless” when an old reader ignores Resolved (`plan.md:1765-1769`), while the plan itself proves same-config revert is runtime-churning (`:1285-1299`). The old reader re-arms the future deadline and later executes the full apply (`pkg/configstore/store_persist.go:231-253`; `pkg/daemon/daemon_apply_commit.go:645-698`). Pin `FirstCommit=false`, replace undefined “now+window” with an exact duration, document the churn, and add a downgrade-shape test.

MINOR 3 — D-kind is absent from the health schema. The canonical mask contains only REMOVAL|REWRITE (`plan.md:1904-1913`), later copies inconsistently call `ActivePersistDegraded` an aggregate bool (`:2101-2102,2412-2414,3110-3112`), and no rule maps D into either carrier. Pin D’s mask/aggregate treatment so a readable synthesized tombstone with delete debt cannot become falsely healthy or retain a misleading terminal-unreadable message.

NEEDS-REVISION

Codex session ID: 019f9621-6127-7b13-b891-4dc25b622385
Resume in Codex: codex resume 019f9621-6127-7b13-b891-4dc25b622385
