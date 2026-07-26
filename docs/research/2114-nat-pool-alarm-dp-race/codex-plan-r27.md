# Codex hostile plan-review — round 27 (plan v27 @ 554c61356)

Task: task-ms1m9ysd-yq6urv (session 019f9dd4-d4b4-7530-b617-2890252a82c0).
Verdict: NEEDS-REVISION (4 MAJOR, 2 MINOR; fold verification 0/5 clean — all PARTIAL). Raw companion output follows verbatim.

---

Fold verification:

1. PARTIAL — The global/W-table guard is present at plan.md:1844-1852,2075-2088, closing the stated absence-path in intent. But the D table leaves (d-ii)/(d-iii) clears unqualified at plan.md:2256-2265, and duplicate x15 still gates only “any clear,” not every repair, at plan.md:3666-3674. No executable active-side predicate is defined.
2. PARTIAL — The core rule correctly suppresses D for W debt or `armedArmID != ""` at plan.md:1879-1905, and restart alone is safe because D is process-local and unrecreated at plan.md:2266-2270. However, stale copies still route failed W restores into D at plan.md:692-695,741-745,4071-4076,4099-4101; the normative D table at plan.md:2228-2265 also omits the suppression precondition.
3. PARTIAL — Repair-permitting copies are now qualified, and unsupported PRF is soundly non-key-class because PRF is outside sealed `Data` at pkg/configstore/crypto.go:26-32,291-298,428-440. But `ConfirmRecordKeyClassError` has no constructible typed source: authentication and invalid-length errors remain generic at crypto.go:354-356,451-453 and db.go:250-253, while plan.md:2917-2964 omits crypto.go from the change inventory.
4. PARTIAL — The path is corrected at plan.md:2089-2092,2383-2392 and matches crypto.go:34-35 and store.go:302-305. The promised key-class health detail remains unrepresentable: the exact snapshot at plan.md:2425-2453,2988-3007 contains only an active flag, debt mask, and three-state record enum.
5. PARTIAL — The occupant-unprovable rationale and slot-delete inventories are corrected at plan.md:2031-2049,2998-3010,3179-3189. But the residual still says crash “before the next W pass” at plan.md:1941-1950,3323-3326; failed passes do not close it. Later copies correctly require the next successful restore at plan.md:3361-3371,4102-4105.

New findings:

MAJOR 1 — The active-side guard has no executable state machine. Plan.md:2081-2089 says only “readable” and “withhold,” while §5.1 and the boot total order omit the evaluator and placement at plan.md:2917-2997,2516-2523. `ReadActiveMeta` returns `(nil,true,nil)` for absence at pkg/configstore/db.go:319-330: an error-only predicate accepts missing active state and may repair/clear confirm state with no durable active, while requiring a non-nil tree blocks the sanctioned both-files-removed `DeleteConfirm` barrier at plan.md:2303-2312. EACCES is likewise unclassified, and boot currently reads active once before recovery while the runtime loop never reads it at store_persist.go:26-42,113-140,402-465. PRESENT/ABSENT/ERROR behavior, retention versus terminalization, and identical boot/runtime call placement must be pinned and tested.

MAJOR 2 — The write-side block is neither atomic nor no-create. Every current `WriteConfirm` reaches `readOrCreateMasterKey` through pkg/configstore/db.go:207-217 and crypto.go:262-270,457-479, despite plan.md:1858-1864,2070-2075 requiring a missing key to block repair. A plaintext active gate deliberately performs no key access at crypto.go:307-314. Even for encrypted active, validation reads K separately from the repair write; K can become K′ or disappear between those reads, allowing the repair to overwrite confirm state under K′. The repair primitive must use a validated key snapshot or a no-create keyed write, not a check followed by ordinary `WriteConfirm`.

MAJOR 3 — D can outrun an undurable replacement. V27 admits D may survive beside durable live C at plan.md:1880-1885. SyncApply then cancels C before persisting its replacement at pkg/configstore/store.go:687-717,738-746. A PRE-rename failure requires retaining C’s record under #5473 at plan.md:1557-1574, but leaves no W and clears `armedArmID`, making D actionable under plan.md:1879-1892. If D’s fresh read becomes non-key permanent, (d-i) tombstones and deletes C at plan.md:2235-2246; the active gate passes because disk active C is readable. A crash before the replacement retry lands boots unconfirmed C without its recovery record. D must also be suppressed while the replacement/persistence debt remains outstanding.

MAJOR 4 — `errors.As` cannot mechanically distinguish the promised key class from the current chain. Go’s GCM authentication error has no exported typed sentinel; crypto.go:354-356 converts it to an ordinary wrapped error, invalid key length is another plain `fmt.Errorf` at crypto.go:451-453, and ReadConfirm merely adds `%w` at db.go:250-253. The plan must define typed source errors in crypto.go, their unwrap/subtype relationship to `ConfirmRecordPermanentError`, and classification tests.

MINOR 1 — The acceptance suite does not exercise the new durable-arm suppression rule. The D regressions at plan.md:2626-2640,3631-3642 cover read classifications but never seed D, land a fully durable arm with no W, block the moot-clear, and assert D remains inert. An implementation retaining only the old W-debt guard can pass the listed tests.

MINOR 2 — Key-specific operator guidance cannot cross the Store→API boundary. Plan.md:2383-2392 promises an `errors.As`-derived key-class detail, but the exact callback payload and API wiring at plan.md:2425-2453,2988-3007 expose no key-class bit or retained error. Add an explicit non-secret cause field/state and corresponding health regression.

NEEDS-REVISION

Codex session ID: 019f9dd4-d4b4-7530-b617-2890252a82c0
Resume in Codex: codex resume 019f9dd4-d4b4-7530-b617-2890252a82c0
