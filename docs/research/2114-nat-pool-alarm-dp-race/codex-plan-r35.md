# Codex hostile plan-review — round 35 (plan v35 @ 04ac2d9a8)

Task: task-ms20u1nc-sfp9y4 (session 019f9f49-eea4-7dd0-9031-06e20c32d81f).
Verdict: NEEDS-REVISION (1 MAJOR, 2 MINOR; fold verification 3 FOLDED / 1 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. FOLDED — The direct classify→overwrite race is acknowledged and closed authoritatively by offline repair, with same-`s.mu` re-verification as defense-in-depth (`plan.md:3258-3281`); current code confirms the unlocked read and unconditional replacement (`pkg/configstore/db.go:207-218,242-253`; `pkg/fsatomic/fsatomic.go:310-366`).
2. FOLDED — The state exit now performs its own final exact-byte key comparison and retains on mismatch (`plan.md:2741-2756`), with the state-only regression at `plan.md:5048-5054`. Debt-bearing passes cannot expose false green: mutations hold `s.mu` (`pkg/configstore/store_persist.go:402-460`) and outstanding debt remains in the aggregate (`plan.md:3352-3365`).
3. PARTIAL — The named schema, API, x14, and x21 copies are corrected (`plan.md:4122-4159,4835-4855,4918-4940`), but other current inventories still describe only three causes, omitting `ConfigWriteUnverified` (`plan.md:3428-3431,4158-4161,4332-4346`).
4. FOLDED — The cumulative summary now assigns restoration only to key-class permanent failures and master-key read I/O to transient retry with UNVERIFIABLE guidance (`plan.md:5459-5467`).

New findings:

MAJOR 1 — The stopped-repair instruction lacks the mandatory zero-live-debt precondition. The blanket rule at `plan.md:3267-3271,5055-5062` contradicts the existing rule that any live `ConfirmDebtKindMask` requires xpfd to remain running (`plan.md:2676-2701`). Stopping abandons process-local resolution debt (`pkg/configstore/store_persist.go:397-401`); after restart, a repaired pending-shaped record that hash-matches takes expired-revert or future re-arm (`pkg/configstore/store_persist.go:149-165,171-255`), and H can Load-revert FirstCommit+cluster (`plan.md:3477-3484`). Thus an already-confirmed configuration can be rolled back. Require `mask == 0` explicitly; live-debt remediation must use the running probe/removal path. Also warn that successful-active Load runs the total order, whereas absent/compile-failed Load only seeds an orphan (`plan.md:2103-2154`).

MINOR 1 — “Immediately before the rename” lacks an executable mechanism. `WriteConfirm` calls monolithic `WriteFileDurable` (`pkg/configstore/db.go:207-218`), which performs temp creation, write, fsync, and close before its unconditional rename (`pkg/fsatomic/fsatomic.go:310-355`); §5.1 inventories no staged writer or pre-rename hook (`plan.md:4012-4167`). Pin such an API/test seam or weaken the claim. A post-write read does not close the hostile interleave: if the operator’s repair lands before the daemon rename, read-back sees only the daemon’s replacement.

MINOR 2 — The observability documentation remains internally stale: `plan.md:3428-3431,4158-4161,4332-4346` still says “three causes” and omits write-unverified from the scheduled descriptor/README/header updates, despite the corrected four-cause aggregate.

Structure confirmation: CONFIRMED — commit `04ac2d9a8` differs from its `origin/master` base only under `docs/research/2114-nat-pool-alarm-dp-race/`; §4.7 still defines PR-1 core plus the combined G+H+H2 follow-up (`plan.md:3965-4000`).

NEEDS-REVISION

Codex session ID: 019f9f49-eea4-7dd0-9031-06e20c32d81f
Resume in Codex: codex resume 019f9f49-eea4-7dd0-9031-06e20c32d81f
