# #1539 — Guard against AST leakage / shadow execution of retired DPDK sub-tree fields

Status: DRAFT v2 — round-1 plan-review applied; pending round-2

## Round-1 plan-review summary

- **Codex (task-mpku5dam-crjpoi):** PLAN-NEEDS-MAJOR. Canary
  excludes `pkg/config/` (which is exactly where a future strict
  validator would land); substring-based gate recognizer is
  unsound; switch-statement blind spot becomes structural once
  `pkg/config/` is included; plan must state hard precondition
  that #1536 is merged first. Recommends shipping Option A
  alongside a corrected canary.
- **Antigravity (adversarial-review-mpku5cqj-z1v7o3):** PLAN-KILL
  on Option B alone, recommends Option A as the correct defense:
  the bug class is *shadow execution* of DPDK logic on a userspace
  backend; if `cfg.System.DPDKDataplane` is guaranteed nil after
  the strict validator passes, the standard `if d != nil { ... }`
  guard pattern at any future reader cleanly skips the shadow
  block at runtime regardless of whether the reader gates on
  `effectiveDataplaneType`. Helper-function escape hatch makes
  Option B's call-site analysis incomplete; switch-statement
  blind spot forces unidiomatic if-chains.

**Synthesis adopted in v2:** ship BOTH Option A (primary defense)
AND a Codex-corrected canary (defense in depth). Option A
addresses Antigravity's runtime-safety argument; the corrected
canary addresses Codex's compile-time invariant argument and
catches the helper-function escape hatch by analyzing the
production-source call sites where the field is read OR passed.

## 1. Issue framing (unchanged)

PR #1536 adds `validateDataplaneTypeStrict` to `compileExpanded`
that hard-rejects `cfg.System.DataplaneType == "dpdk"`. The
parser still accepts the full `system dataplane-type dpdk`
sub-tree so a pre-retirement config does not syntax-error on
`load merge`. Typed sub-tree `cfg.System.DPDKDataplane` is only
populated when `effectiveDataplaneType(...) == dpdk` (see
`pkg/config/compiler_system.go:228-246`), which post-#1536 is
unreachable on a committed config.

Issue #1539 names the future risk: a developer adds a new
strict validator for some DPDK sub-field, OR a backend hook
that reads a DPDK sub-field, AND forgets to gate on
`effectiveDataplaneType(...) == dpdk`. The unconditional read
would then evaluate DPDK-specific state on a userspace backend
— "AST leakage" / "shadow execution".

## 2. Honest scope/value framing

This work has no runtime perf impact. Option A is a one-line
nil assignment in the commit path. Option B is a test-only
addition (~200 LOC including self-test fixtures).

Concrete bounds on the value:
1. Today there are ZERO cross-package readers of
   `cfg.System.DPDKDataplane`. `grep -rn "DPDKDataplane"
   --include='*.go' | grep -v "^pkg/config/" | grep -v _test.go`
   returns empty.
2. #1527 (Phase 2, boot decoupling) has already merged into
   master at commit `541b3ea1`.
3. #1528 (Phase 3) is an OPEN issue with no PR yet; its
   acceptance criteria include deleting `DPDKConfig`,
   `DPDKAdaptiveConfig`, `DPDKPort`, and the `DPDKDataplane`
   field on `SystemConfig`. After #1528 lands, the canary
   becomes tautological (no symbol to read) AND Option A
   becomes dead-code-deletion (no field to nil).

The window of value is **(#1536 merge → #1528 merge)**.

**Round-2 reviewers: if you conclude that #1528 is close
enough to landing that this defense is wasted work, PLAN-KILL
is still on the table.** Antigravity already cast a KILL on
those grounds in round-1. The argument FOR shipping anyway:
(a) #1528 is unscheduled and has no draft PR, (b) Option A is
literally one line of production code, (c) the canary catches
new code that lands in the window between #1536 and #1528
before #1528 lands.

## 3. What is already shipped / partially overlapping

- `pkg/config/compiler_system.go:228-246` — typed sub-tree
  population gated on `switch effectiveDataplaneType(...)
  { case dataplaneTypeDPDK: ... }`.
- `pkg/config/compiler.go:954-958` — `effectiveDataplaneType`
  canonical helper.
- PR #1536 (`dpdk-retire/1526-reject`) adds
  `validateDataplaneTypeStrict` at `pkg/config/compiler.go`.
  **HARD PRECONDITION:** this PR must stack ATOP #1536.
  Implementation will not merge until #1536 has merged into
  master OR this PR rebases on top of the merged commit.
- `pkg/dataplane/retirement_boundary_canary_test.go` — 3442-line
  precedent for `go/parser` + `ast.Inspect` canaries. Note
  per Antigravity round-1: the precedent uses package-level
  symbol/import scans (`parser.ImportsOnly` style), NOT
  control-flow domination. This canary is structurally more
  complex than the precedent.

## 4. Concrete design — Option A + Option B together

### 4.1 Option A — one-line structural invariant in compileExpanded

After `validateDataplaneTypeStrict(cfg)` returns nil (i.e., the
config is NOT retired-DPDK) and at the end of `compileExpanded`,
add:

```go
// #1539: explicit structural invariant — after the strict
// validator rejects retired backends, no committed config
// retains DPDK sub-tree state. This nil makes "no
// dataplane-type dpdk" mean "DPDK sub-fields are zeroed" at
// the type-system level so any future helper of the form
//   if cfg.System.DPDKDataplane != nil { ... use it ... }
// is statically dead on every committed config without
// requiring the helper to gate on effectiveDataplaneType.
//
// This is dead code after #1528 (Phase 3) deletes the
// DPDKDataplane field entirely; remove this line in #1528.
cfg.System.DPDKDataplane = nil
```

**Placement:** end of `compileExpanded`, after every error
return path has run including `validateDataplaneTypeStrict`.
Specifically, right before `return cfg, nil` in the success
path. If `compileExpanded` has multiple success-paths, the
nil clear must precede ALL of them.

**Why placement matters per Codex finding 3:** the strict
validator on master today does NOT exist. Option A only makes
sense AFTER `validateDataplaneTypeStrict` has run. The plan
explicitly stacks atop #1536; the nil clear is placed in the
same function and AFTER the same validator that #1536 added.

**Edge case:** an internal compile path that bypasses
`compileExpanded` and calls a lower helper directly would
skip both the validator and the nil clear. Audit:
`grep -n "compileExpanded\|compileSystemConfig" pkg/config/`
shows `compileExpanded` is the sole entry point used by
`CompileConfig` and `CompileConfigForNode`. No bypass path
exists today; if a future commit introduces one, it must
also call the validator + nil clear (a canary item below
asserts this).

### 4.2 Option B — corrected canary test

Single new file: `pkg/config/dpdk_subtree_leakage_canary_test.go`.

**Structural improvements over v1, per Codex findings 1, 2, 4:**

1. **Scan `pkg/config/` production source TOO** (Codex finding 1).
   Walk excludes:
   - `*_test.go`
   - Files under `pkg/dataplane/dpdk/` (retired backend reads
     its own sub-tree)
   - Files with `//go:build ignore`
   - The single writer at `pkg/config/compiler_system.go`
     line range 228-246 — narrowly allowlisted with a comment
     anchor (`// #1539 writer exception: typed-sub-tree
     population gated by switch effectiveDataplaneType`).

2. **AST-structural gate recognition** (Codex finding 2):
   - For each `SelectorExpr` of the form `<X>.DPDKDataplane`,
     ascend to the nearest enclosing `*ast.IfStmt` OR
     `*ast.SwitchStmt` (or `*ast.TypeSwitchStmt` — out of
     scope, none today).
   - For `IfStmt`: walk the `Cond` AST and require a
     `BinaryExpr{Op: ==, X: <call to effectiveDataplaneType>,
     Y: <Ident: dataplaneTypeDPDK> | <BasicLit: "dpdk">}` OR
     the reverse operand order. Substring matching is
     forbidden.
   - For `SwitchStmt`: require the `Tag` to be a
     `CallExpr{Fun: effectiveDataplaneType, ...}`, then find
     the enclosing `*ast.CaseClause` of the selector and
     require one of its `List` entries to be `dataplaneTypeDPDK`.
   - Reject the unsound recognizer that accepts
     `effectiveDataplaneType(...) == dataplaneTypeUserspace`
     followed by a DPDK read (Codex finding 2's counterexample).
   - **Negation form:** `if effectiveDataplaneType(...) !=
     dataplaneTypeDPDK { ... return ... }` followed by a
     post-block read is also a valid gate. Implementation
     detail: if the ascended IfStmt has body that ends in an
     unconditional return/continue/break AND the read is
     in the sibling/parent block, accept. Simpler v2 stance:
     **do NOT support the early-return idiom in v2**; force
     callers to use the positive `==` form OR fall through
     to the allowlist. Document this as a known limitation.

3. **Switch-statement support** (Codex finding 4, AGY finding 3):
   The writer's pattern at `compiler_system.go:228` IS the
   recommended idiom. Canary must accept it. Implementation:
   walk parent chain; if the nearest enclosing block is a
   `*ast.CaseClause` and the `*ast.SwitchStmt` parent's `Tag`
   is `effectiveDataplaneType(...)`, accept iff the case
   clause's `List` contains `dataplaneTypeDPDK`.

4. **Helper-function pass-through detection** (AGY finding 2):
   Additionally walk for `CallExpr` whose arg list contains
   a SelectorExpr matching `<X>.DPDKDataplane`. Apply the
   same gate analysis to the call site. This catches:
   ```go
   func useIt(d *DPDKConfig) { d.Cores }
   // ungated call site — canary fires:
   useIt(cfg.System.DPDKDataplane)
   ```
   It does NOT catch the case where the pointer is
   stored in a struct field and accessed later through that
   field. Document this as a known limitation; mitigation
   is Option A's nil guarantee.

5. **Empty allowlist by default** — `dpdkSubtreeReaderAllowlist`
   map is empty. The single in-package writer is recognized
   structurally (its switch is the canonical gate), not via
   allowlist.

### 4.3 Self-test fixtures (committed)

Per Codex finding: a committed inline negative self-test is
mandatory. The precedent canary uses temp fixtures written to
disk during the test then walked
(`retirement_boundary_canary_test.go:1377`, `:2607`). We follow
the same pattern:

- `TestDPDKSubtreeLeakageCanary_PositiveAcceptsGatedReads` —
  hand-rolled fixture string with `effectiveDataplaneType(...)
  == dataplaneTypeDPDK` if-gate and `switch effectiveDataplaneType
  { case dataplaneTypeDPDK: }`; write to `t.TempDir()`, walk
  it, assert canary returns no findings.
- `TestDPDKSubtreeLeakageCanary_NegativeRejectsUngatedRead` —
  fixture with bare `_ = cfg.System.DPDKDataplane.Cores`;
  assert canary fires with the expected file:line.
- `TestDPDKSubtreeLeakageCanary_NegativeRejectsHelperPassthrough` —
  fixture with `useIt(cfg.System.DPDKDataplane)` at ungated
  call site; assert canary fires.
- `TestDPDKSubtreeLeakageCanary_NegativeRejectsWrongTypeBranch` —
  Codex finding 2's counterexample: `if effectiveDataplaneType
  (...) == dataplaneTypeUserspace { _ = cfg.System.DPDKDataplane }`;
  assert canary fires.
- `TestDPDKSubtreeLeakageCanary_RealRepoIsClean` — runs the
  walker against the real repo at `repoRoot = "../.."`; today
  asserts zero findings (writer is recognized; no other
  references exist).

## 5. Public API preservation

Option A: zero API surface. The field already accepted nil; we
just nil it explicitly.

Option B: zero API surface. New `*_test.go` file only.

## 6. Hidden invariants the change must preserve

1. **`compileExpanded` is the sole entry point** to a committed
   config. Audit confirmed (`CompileConfig`,
   `CompileConfigForNode`); if a future PR adds a bypass, the
   nil clear must also be added there. Optional: add a tiny
   canary item `TestCompileConfigEntryPointsClearDPDKSubtree`
   that scans for top-level functions returning `*Config`
   from `pkg/config/` and asserts each ends in either a call
   to `compileExpanded` OR an explicit `DPDKDataplane = nil`.
   **Round-2 reviewers: decide whether this extra canary is
   worth the additional test surface.**
2. **Stacking discipline** (Codex finding 3): this PR must
   rebase atop the merged #1536 commit. Implementation
   commits in this branch must not merge until #1536 has
   merged. The plan doc states this; CI is not enforcing it.
3. **#1528 dead-code window** — both Option A's nil clear and
   Option B's canary become dead code after #1528 lands.
   #1528's acceptance criteria already list deleting
   `DPDKConfig`; we add a TODO comment near both pointing at
   "#1528 removes this."
4. **Generated files / build tags** — `bpf2go`-generated files
   live in `pkg/dataplane/`, do not reference `DPDKDataplane`,
   not in scope.
5. **No `reflect.ValueOf(cfg).FieldByName("DPDKDataplane")` access** — out of scope; reflective config access is an
   anti-pattern not addressed here.

## 7. Risk assessment

| Class | Level | Justification |
|---|---|---|
| Behavioral regression (Option A) | LOW | One-line nil clear at end of `compileExpanded`. The field is already nil in the common path post-#1536; this just makes it structurally guaranteed. |
| Behavioral regression (Option B) | NONE | Test-only. |
| Lifetime / borrow-checker | N/A | Go. |
| Performance regression | LOW | Canary runs at `go test` only. Option A is one pointer assignment per Commit() call. |
| Architectural mismatch (#946 / #961 pattern) | LOW-MEDIUM | The risk Antigravity flagged in round-1 (#1528 makes the work tautological) is real but bounded. Antigravity round-2 may still PLAN-KILL on the window value alone — that is a legitimate outcome. |
| False positives (canary) | LOW | AST-structural recognition (not substring); writer accepted via structural recognition (not allowlist); committed self-test fixtures lock the recognition logic. |
| Switch-statement blind spot | RESOLVED | v2 design explicitly handles `*ast.SwitchStmt` parent chain with `Tag` matching `effectiveDataplaneType(...)` and `CaseClause.List` containing `dataplaneTypeDPDK`. |
| Helper-function escape hatch | PARTIALLY RESOLVED | v2 catches `CallExpr` whose arg is `<X>.DPDKDataplane`. Does NOT catch storage-then-access through an intermediate field. Mitigation: Option A guarantees nil so the intermediate field is also nil at runtime. |

## 8. Test plan

- `go test ./pkg/config/` — full package suite passes.
- `go test ./pkg/config/ -run TestDPDKSubtreeLeakageCanary
  -count=5` — 5× flake-clean on the named test suite.
- `go test ./...` — full Go suite (30 packages), no regression.
- Negative-fixture sub-tests assert the canary fires on each
  of the four documented escape paths (ungated read, helper
  pass-through, wrong-type branch, switch with wrong case).
- Smoke matrix on the loss userspace cluster — SKIPPED for
  this PR because it has zero runtime impact. Justification:
  Option A is a nil clear in the commit path that runs once
  per `Store.Commit`; Option B is test-only. Round-2 reviewers
  may demand at least a v4+v6 push/reverse single-stream
  sanity check to confirm `cluster-deploy` does not regress
  with the head SHA; we will run it on request.

## 9. Out of scope (explicit)

- Storage-then-access via an intermediate struct field — the
  canary cannot statically resolve this and we are not adding
  type-system rework to do so. Option A's nil guarantee is the
  mitigation.
- Reflective access via `reflect.ValueOf(...).FieldByName(...)`.
- Adding the inverse canary for `UserspaceDataplane` (the
  active sub-tree). Separate issue.
- Detecting helper functions that take a `*DPDKConfig`
  directly and dereference it inside — the canary catches the
  call site, not the helper body. Helper-body analysis would
  require call-graph reachability, beyond scope.
- Optional `TestCompileConfigEntryPointsClearDPDKSubtree`
  canary (open question for round-2).

## 10. Open questions for adversarial round-2

1. **Window value, again.** Antigravity round-1 PLAN-KILLed on
   the grounds that #1528 makes this tautological soon. v2 keeps
   the work because (a) #1528 has no PR yet, (b) Option A is
   one line, (c) the canary's ~200 LOC is the bridge defense.
   Is round-2 satisfied by this framing, or does the window
   argument still kill the work?
2. **Option A alone vs Option A + Option B.** v2 ships both.
   If round-2 thinks Option A alone is sufficient, we can drop
   Option B. The argument for keeping Option B: it catches
   compile-time errors before a regression ever ships, whereas
   Option A only prevents runtime shadow execution given a
   subsequent `if d != nil` guard at the reader.
3. **Switch-statement recognition complexity.** v2 supports
   the switch idiom explicitly. The implementation walks the
   parent chain to find `*ast.SwitchStmt` whose `Tag` is a
   `CallExpr{Fun: effectiveDataplaneType, ...}`. Is this AST
   recognition robust enough, or does it create a fragility
   surface in itself?
4. **Helper-function detection limit.** v2 catches the call
   site `useIt(cfg.System.DPDKDataplane)` but not
   `s.D = cfg.System.DPDKDataplane; ... s.D.Cores`. The plan
   defers the storage-through-field case to Option A's nil
   guarantee. Is that an acceptable boundary, or does round-2
   want stronger detection?
5. **Optional entry-point canary** (section 6 item 1). Worth
   shipping or extra surface?
6. **`compileExpanded` placement of Option A.** The nil clear
   goes AFTER `validateDataplaneTypeStrict` so a config that
   legitimately fails validation never silently has its DPDK
   state cleared. Is the placement correct, or should it run
   even on validator failure (to harden against partial-state
   leakage in error paths)?
7. **Stacking discipline.** v2 names #1536 as a hard
   precondition. If #1536 is still iterating in review, we
   either (a) wait, or (b) cherry-pick the validator into this
   branch with a clear rebase commitment. Round-2 reviewer
   preference?
