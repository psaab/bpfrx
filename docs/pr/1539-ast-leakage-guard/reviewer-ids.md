# #1539 reviewer IDs

## Code review (PR #1553)

- HEAD at code-review: 8c5a4ced, then 6a7d0649 (linter fix +
  multi-LHS bypass test).
- Codex: session 019e5fa4-... (continued) — **MERGE-READY**.
  Reasoning: "The nil clear is placed after strict dataplane
  validation and before the successful compileExpanded return,
  preserving the intended runtime invariant for committed
  configs. The canary structurally scans production pkg/config
  sources and has focused positive/negative fixtures for the
  important gate shapes and known bypass classes from review."
- Antigravity: adversarial-review-mplcczw9-21ub1p — initially
  **MERGE-WITH-MAJOR** on HEAD 8c5a4ced with HIGH (multi-LHS
  bypass in isLHSOfAssignToNil) + MEDIUM (hand-rolled itoa
  out-of-bounds on >=12 digit input, MinInt overflow).
  AGY then applied the fix in the worktree (same as my lint
  pass had already produced); final verdict **MERGE-READY**
  with all findings addressed in 6a7d0649.
- Claude SMR: examined diff hostile-style, noted parenthesized
  `&&` gate would be silently rejected (fail-closed style
  choice, documented).

## Plan v2 (commit 7f0cdacd) — round-2 verdicts

- Codex round-2: session 019e5fa4-0552-7823-915d-79eaf79b1c55
  (rerun after initial dispatch returned no agent message) —
  **PLAN-MINOR**.
  - F1 (pkg/config inclusion): ADDRESSED (line 151).
  - F2 (AST-structural gate): ADDRESSED (lines 162/170, substring
    matching explicitly forbidden).
  - F3 (#1536 stacking): substantively ADDRESSED; stale wording at
    lines 90 + 130 + 358-361 referring to #1536 as a precondition
    or "iterating in review" — #1536 merged at fcd53beb on master.
    Fix the wording.
  - F4 (switch-statement): ADDRESSED (lines 189-194).
  - New: contradictory negation-gate paragraph (lines 179 vs 185);
    pick one stance.
  - Window-of-value: YES, bridge defense justified.

- Antigravity round-2: adversarial-review-mplbulo0-y014py —
  **PLAN-MINOR**.
  - Window-of-value: KILL no longer operative.
  - HIGH: switch-statement multi-case bypass —
    `case dataplaneTypeDPDK, dataplaneTypeUserspace:` would pass
    the v2 recognizer. Require `len(CaseClause.List) == 1`.
  - MEDIUM: nested-conditional false-positive — "nearest enclosing"
    rejects a read inside `if effectiveDataplaneType(...) ==
    dataplaneTypeDPDK { if x { _ = sys.DPDKDataplane.Cores } }`.
    Walk parent chain to FuncDecl, accept if ANY ancestor gates.
  - LOW: local-variable bypass — `dpdkConf = cfg.System.DPDKDataplane`
    inside gate, used outside. Acceptable boundary because Option A
    nil clears at runtime. Document explicitly.
  - Two extra negative/positive fixtures recommended.

## Plan v1 (commit cf9c1518)

- Codex round-1: task-mpku5dam-crjpoi — PLAN-NEEDS-MAJOR
  - 1. Canary excludes pkg/config/ but a future strict validator
    lands in pkg/config/ — primary regression class.
  - 2. Gate recognizer is substring-based and unsound; would
    pass `if effectiveDataplaneType(...) == dataplaneTypeUserspace`
    followed by a DPDK read. Must be AST-structural.
  - 3. Plan must state hard precondition: stack ATOP #1536
    (validateDataplaneTypeStrict not on master yet).
  - 4. Switch-statement blind spot becomes structural once pkg/config
    is included; canary must understand `switch effectiveDataplaneType
    { case dataplaneTypeDPDK: ... }`.
  - Other: ship Option A alongside the fixed canary as belt-and-braces.
    Self-test fixtures: inline temp-fixture pattern (not //go:build).
- Antigravity round-1: adversarial-review-mpku5cqj-z1v7o3 — PLAN-KILL
  - 1. Window of value too small (#1527 merged; #1528 deletes the schema).
  - 2. Helper-function escape hatch makes canary architecturally
    incomplete.
  - 3. Switch-statement blind spot forces unidiomatic if-chains.
  - 4. Option A (one-line `cfg.System.DPDKDataplane = nil` in
    compileExpanded) is the correct defense — guaranteed-nil cleanly
    skips `if cfg.System.DPDKDataplane != nil { ... shadow ... }`
    branches at runtime.
  - 5. Precedent canary in pkg/dataplane/ only checks imports
    (ImportsOnly), not control flow; this canary's domination
    analysis is a class jump in complexity.

Synthesis: ship Option A as primary defense (both reviewers point at
it for different reasons — AGY as preferred, Codex as belt-and-braces),
AND ship a Codex-corrected canary as defense in depth: scan pkg/config
production source, AST-structural gate recognition, switch-statement
support, committed inline self-test.
