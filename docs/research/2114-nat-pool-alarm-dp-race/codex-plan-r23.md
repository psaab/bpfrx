# Codex hostile plan-review — round 23 (plan v23 @ d1b64a4f1)

Task: task-mrzidzng-o7br27 (session 019f963b-e63a-7683-be11-7b73d526b21c).
Verdict: NEEDS-REVISION (2 MAJOR, 3 MINOR). Raw companion output follows verbatim.

---

Fold verification:
1. FOLDED — Both normative w-b tables now define the restore as D2 supersession and clear the dead record’s R debt only after the restore’s dir-fsync (`plan.md:1577-1589,1615-1624`). Remaining “R_B runs FIRST” text is correctly limited to D1 identity-preserving rewrites (`plan.md:2214-2228,3170-3183`).
2. PARTIAL — D → durable arm C → retry is fixed: a successful arm clears D, and a readable live-window ArmID match is untouched (`plan.md:1841-1853`). The pass holds `s.mu` continuously (`pkg/configstore/store_persist.go:405-460`), as do arm paths (`pkg/configstore/store_commit.go:368-387`), so no internal arm can interleave between re-read and write. The transient-read and live-W composition remain undefined, however.
3. FOLDED — D is explicitly process-local; a pre-tombstone crash reconstructs only the latch and requires operator-mediated remediation (`plan.md:1854-1870`; `pkg/configstore/store_persist.go:397-405`). No self-reconstruction claim remains.
4. FOLDED — All x12/x19 copies now specify synthesized tombstone → delete with D debt (`plan.md:2175-2192,2240-2253,3136-3151,3198-3210`), and all producer claims distinguish read-back from unreadable-slot synthesis (`plan.md:2031-2052,2118-2121,2461-2464,3082-3086`).
5. PARTIAL — The main scoped guarantee, synthetic pins, and `SLOT_DELETE` aggregate landed (`plan.md:1666-1674,1809-1832,1987-2016`). The complete synthetic inventory is present: existing `Deadline/PrevTree/FirstCommit/GuardedHash` (`pkg/configstore/db.go:169-192`) plus planned `Resolved/HashBasis/ArmID` (`plan.md:2053-2055`). But the hidden invariant, downgrade assertion, and health-schema copies remain inconsistent as detailed below.

New findings:

MAJOR 1 — D’s transient re-read outcome is missing. The generic taxonomy says transient `ReadConfirm` errors retain and retry (`plan.md:1737-1761`), but D overrides permanent errors with destructive healing and defines no transient branch (`plan.md:1841-1844`); acceptance copies weaken this further to unqualified “still-unreadable → proceed” (`plan.md:2186-2189,3145-3149`). If arm C has become visible through a post-rename failure while D remains, a transient EACCES, short read, or master-key I/O error does not prove A still occupies the slot; treating it as d-i tombstones C. Pin transient → retain D, perform no write/delete, with a regression.

MAJOR 2 — The promised W restore over an unreadable record is not implementable from the normative tables. A confirmed arm’s pre-rename failure while the BOOT latch stands is said to let W replace the unreadable record (`plan.md:1875-1882`), but both W tables define only readable match/differ/absent (`plan.md:1576-1592,1603-1633`); the global taxonomy instead terminalizes a permanent read failure (`plan.md:1737-1761`). If D also exists, no rule explicitly extends restore-first priority to slot-keyed D, whose d-i action may tombstone/delete first (`plan.md:1841-1844`). Pin W permanent-unreadable → restore `s.armedRecord`, W-before-D, successful restore subsumes D, and the corresponding crash regression.

MINOR 1 — Hidden invariant 12 still claims D2 yields “no recordless live window ever” (`plan.md:2845-2849`), contradicting the admitted restore-failure → R delete → crash-before-next-W gap (`plan.md:1667-1674`; `pkg/configstore/store_commit.go:550-553`). Scope this copy to ordering-created gaps and include the best-effort arm-persistence residual in `plan.md:2862-2888`.

MINOR 2 — The synthetic downgrade test overclaims unconditional re-arm. The plan already admits canonical and legacy bases diverge for exceptional content (`plan.md:1253-1270`), while the old recovery performs its legacy hash check before re-arm (`pkg/configstore/store_persist.go:149-165`). Specify `HashBasis: "canonical-v1"` rather than “current,” constrain the re-arm regression to NORMAL content, and assert exceptional content safely stale-drops. `FirstCommit=false` is correct, but “trips H on ANY reader” is false because v23 checks `Resolved` before H (`plan.md:2072-2079`); its actual load-bearing role is protecting the old reader’s FirstCommit recovery behavior (`pkg/configstore/store_persist.go:171-194,231-247`).

MINOR 3 — The health-state contract alternates between `{ActivePersistDegraded, mask, enum}` (`plan.md:1987-1992`) and a snapshot carrying an “aggregate bool” (`plan.md:2203-2209,2519-2523,3221-3228`). Choose one exact schema and keep the aggregate OR as an explicitly derived value.

NEEDS-REVISION

Codex session ID: 019f963b-e63a-7683-be11-7b73d526b21c
Resume in Codex: codex resume 019f963b-e63a-7683-be11-7b73d526b21c
