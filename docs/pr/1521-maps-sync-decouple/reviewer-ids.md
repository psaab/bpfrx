# #1521 reviewer task/job IDs

Tracks Codex task-ids and Antigravity job-ids across plan and code review
rounds so we never re-dispatch instead of fetching a queued result.

## Plan review

| Round | Reviewer | ID | Verdict |
|---|---|---|---|
| 1 | Codex | workflow 20260525-145416-0c2271 | HIGH×2 MED×3 LOW×1; 5 ACCEPT 1 DEFER → plan v2 |
| 1 | Antigravity | adversarial-review-mplbyz4k-oua5ov | PLAN-NEEDS-MAJOR (AST canary + factual correction) → plan v2 |

Plan is PLAN-READY v2 after both r1 verdicts addressed.

## Code review

| Round | Reviewer | ID | Verdict |
|---|---|---|---|
| 1 | Codex | workflow 20260525-145416-0c2271 (impl r1) | MED×1 LOW×2; 2 ACCEPT 1 REJECT → r2 |
| 1 | Antigravity | adversarial-review-mplcamu9-gxguu8 | CODE-NEEDS-MAJOR (alias canary + parity-skip sentinel) → r2 |
| 1 | Claude SMR | self-review post-r1-fixes | MERGE-READY pending r2 confirm |
| 2 | Codex | workflow 20260525-145416-0c2271 (impl r2) | LOW×2; 1 ACCEPT 1 REJECT → r3 |
| 2 | Antigravity | adversarial-review-mplcnpph-45ufpf | CODE-NEEDS-MAJOR (concat fold + trim-bypass) → r3 |
| 2 | Claude SMR | self-review post-r2-fixes | MERGE-READY pending r3 confirm |
| 3 | Codex | workflow 20260525-145416-0c2271 (impl r3) | HIGH×2 MED×1 — REJECT all (review-basis error: Codex inspected wrong checkout) |
| 3 | Antigravity | adversarial-review-mplczt4g-jjot6z | CODE-NEEDS-MAJOR (const-ident bypass + non-standard whitespace + seen orphan + parity hardcode) → r4 |
| 3 | Claude SMR | self-review post-r3-fixes | MERGE-READY pending r4 confirm |
| 4 | Codex | workflow 20260525-145416-0c2271 (impl r4) | MED×1 LOW×1 → 1 REJECT 1 ACCEPT (parseMapsGoRegistry hard-fail) |
| 4 | Antigravity | adversarial-review-mpldeqzb-442pr1 | NEEDS-MINOR (cross-file concat + local-block consts addressed; byte-slice + struct-tag tagged as out-of-scope) → r5 |
| 4 | Copilot | PR review on cfae89555 | 4 inline comments — 2 already-fixed in r3 commit + 2 wording nits addressed in 5b41f9d7 |
| 4 | Claude SMR | self-review post-r4-fixes | MERGE-READY pending r5 confirm |
| 5 | Antigravity | adversarial-review-mpldughx-s5jbfs | NEEDS-MINOR (depth-3 chain, typed conversion, typo-padded new map, generated-file filter) — all 4 addressed |
| 5 | Copilot | PR review on 5b41f9d7 | 3 wording-only comments — all addressed in r5 commit |
| 5 | Claude SMR | self-review post-r5-fixes | MERGE-READY |
| 6 | Antigravity | adversarial-review-mple4zlr-vda9fo | NEEDS-MINOR (block-local const shadowing bypasses package-level chain) — AGY-authored fix applied directly: scopeWalker isolates top-level vs block-local consts; agy_r6_block_shadow_chain_bypass fixture proves the kill |
| 6 | Copilot | PR review on 0692093a | "Copilot reviewed 9 out of 9 changed files in this pull request and generated no new comments." — clean |
| 6 | Claude SMR | self-review post-AGY-authored fix | MERGE-READY |
| 7 | Antigravity | adversarial-review-mplebv9s-a166sj | CONCRETE KILL (switch/case implicit-block shadow) — AGY-authored fix: collectConstsFromStmtList strict stmt-list iteration + scopeWalker push for CaseClause/CommClause; agy_r7_switch_case_shadow_bypass fixture proves the kill |
| 7 | Copilot | review id 4357796234 on 5becd4fa | 3 inline (2 doc-only + 1 correctness): pre-collect violated Go statement-order semantics (later-declared block-local const could shadow outer for earlier uses → both FN and FP). FIX: statement-order binding in scopeWalker.Visit replaces pre-collect; doc comments at maps_decouple_test.go:240,518 updated; 2 new fixtures copilot_r5_statement_order_false_positive + copilot_r5_statement_order_false_negative prove the kill |
| 7 | Claude SMR | post-r7 self-review | MERGE-READY |
| 8 | Codex (rebase) | workflow 20260525-162502-88b826 plan-r1 | HIGH-1/HIGH-2/MED-1/MED-2/MED-3/LOW-1 — 1 FIX (closed by sentinel-gated skip) + 1 DEFER (path) + 4 REJECT (parity-AST evergreen, alias scoping, etc.) |
| 8 | Codex (rebase) | workflow 20260525-162502-88b826 impl-r1 | HIGH-1/MED-1/LOW-1 — 3 REJECT (all evergreen) |
| 8 | Antigravity (rebase) | adversarial-review-mplf2r55-xnr229 | NEEDS-MINOR — concrete kill: inherited-initializer const-decl (Go spec §Constant declarations) bypass. FIX: `bindGenDeclConsts` + `collectFileConstsInto` now track lastValues across specs in the same GenDecl. 2 new fixtures (agy_rebase_inherited_initializer_bypass + ..._local_block) lock the kill. |
| 8 | Copilot | review id 4357897741 on 5bc310fc | 2 inline comments — pos 487 correctness (bind-before-descend let inner shadow leak into its own initializer's child traversal) + pos 729 doc-vs-impl on trimPaddingForBypass. FIX: evalGenDeclConsts returns a pending-bindings map applied via postVisitor on DeclStmt EXIT so initializer expressions descended into during the visit see the OUTER scope. trimPaddingForBypass comment clarified to "leading/trailing only". New fixture copilot_rebase_shadow_initializer_refs_outer locks the kill. |
| 8 | Claude SMR | post-r8 self-review | MERGE-READY |

