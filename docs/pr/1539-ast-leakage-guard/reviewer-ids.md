# #1539 reviewer IDs

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
