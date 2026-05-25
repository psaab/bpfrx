# #1539 — Guard against AST leakage / shadow execution of retired DPDK sub-tree fields

Status: DRAFT v1 — pending adversarial plan review

## 1. Issue framing

PR #1536 ("config: reject `system dataplane-type dpdk` at commit")
adds `validateDataplaneTypeStrict` to `compileExpanded` in
`pkg/config/compiler.go`. That validator hard-rejects
`cfg.System.DataplaneType == "dpdk"` so an active config never
carries the retired dataplane type.

The parser, however, still accepts the full sub-tree under
`system dataplane-type dpdk` (cores, memory, socket-mem, ports, etc.)
so a pre-retirement config does not syntax-error on
`load merge` / `load override` — only the compile step rejects it.
Practically, the typed sub-tree `cfg.System.DPDKDataplane` is only
populated when `effectiveDataplaneType(sys.DataplaneType) ==
dataplaneTypeDPDK` (see `pkg/config/compiler_system.go:228-246`),
and #1536's strict validator rejects exactly that case before
the compiled config ever reaches a downstream consumer.

So today, on a committed config:
- `cfg.System.DataplaneType` is never `"dpdk"` (rejected by
  `validateDataplaneTypeStrict`).
- `cfg.System.DPDKDataplane` is therefore never populated
  (the only writer is the `case dataplaneTypeDPDK` branch).

Issue #1539 names the future risk: a developer adds a new strict
validator for some DPDK sub-field, OR adds a backend hook that
reads a DPDK sub-field, AND forgets to gate on
`effectiveDataplaneType(...) == dpdk`. The unconditional read
would then evaluate / instantiate DPDK-specific state on a
userspace backend — "AST leakage" / "shadow execution".

AGY's adversarial review of #1536 proposed two defenses:

- **Option A** — at the end of `compileExpanded` (after
  `validateDataplaneTypeStrict` has passed), explicitly clear
  `cfg.System.DPDKDataplane = nil` so the structural invariant
  "no `dataplane-type dpdk` ⇒ DPDK sub-fields are zeroed" is
  guaranteed independent of compiler-system population logic.

- **Option B** — add an invariant canary test that statically
  walks the Go AST of every production package and asserts that
  any read of `cfg.System.DPDKDataplane` (or a field on its
  pointee) is dominated by an `effectiveDataplaneType(...) ==
  dpdk` (or equivalent) gate.

The issue recommends Option B as the long-term defense — Option
A is only useful if some downstream code already reads DPDK
sub-fields unconditionally (it does not, today).

## 2. Honest scope/value framing

This work has no runtime perf impact (Option B is a test-only
addition; Option A is an O(1) nil assignment at config commit
time). The value is purely **defense in depth against a future
regression class**.

Concrete pre-existing facts that bound the value:
1. Across the entire repo, the only readers of
   `cfg.System.DPDKDataplane` are inside `pkg/config/` itself
   (the writer + tests). `grep -rn "DPDKDataplane" --include='*.go'
   | grep -v "^pkg/config/"` returns zero matches.
2. #1536 hard-rejects `dataplane-type == dpdk` at commit, so the
   `case dataplaneTypeDPDK` writer at
   `compiler_system.go:236-242` is unreachable on a committed
   config today.
3. #1525 Phase 3 (#1528) will delete `pkg/dataplane/dpdk/` and
   the `DPDKConfig` schema fields entirely. After #1528 lands,
   the canary becomes tautological — there is no struct to read.

The window in which this canary provides real value is
**between #1536 merge and #1528 merge** — the period when
`DPDKConfig` still exists as a parsed schema but no production
code should read it. Issue body explicitly frames this as the
target window.

**If reviewers conclude the perf gain is too small to justify
the churn, PLAN-KILL is an acceptable verdict.** The
counter-argument is "Option B costs ~150 lines of test code and
catches a regression class that already bit #1536 conceptually."
If a reviewer thinks #1528 lands soon enough that this is
wasted work, that is a legitimate KILL.

## 3. What is already shipped / partially overlapping

- `pkg/config/compiler_system.go:228-246` — typed-sub-tree
  population is already gated on `effectiveDataplaneType ==
  dpdk`. The leakage risk requires a *new* unguarded reader.
- `pkg/config/compiler.go:954-958` — `effectiveDataplaneType`
  is the canonical normalization helper that empty-defaults to
  `userspace`. Any gate must call this, not raw
  `cfg.System.DataplaneType`.
- `pkg/dataplane/retirement_boundary_canary_test.go` — 3442-line
  precedent canary that uses `go/parser` + `ast.Inspect` to
  walk production source. Same toolkit; same allowlist /
  build-tag patterns.
- PR #1536 itself adds `validateDataplaneTypeStrict`. This plan
  assumes #1536 lands first; the canary references the typed
  field name `cfg.System.DPDKDataplane`, which exists today
  regardless of #1536's reject path.

## 4. Concrete design

### 4.1 Recommended path — Option B only

Add a single test file:
`pkg/config/dpdk_subtree_leakage_canary_test.go`.

Structural shape (modelled on the precedent canary):

```go
package config

import (
    "go/ast"
    "go/parser"
    "go/token"
    "path/filepath"
    "strings"
    "testing"
)

// dpdkSubtreeReaderAllowlist names production source files
// (outside pkg/config/) that may legitimately reference
// cfg.System.DPDKDataplane WITHOUT the canonical
// effectiveDataplaneType()==dpdk gate. Empty after #1528 lands;
// at plan-v1 time it is also empty.
var dpdkSubtreeReaderAllowlist = map[string]string{}

// gatePredicates is the set of expression shapes the canary
// accepts as proof that a DPDKDataplane read is gated. We
// match against the source text of the dominating if-statement
// condition.
var gatePredicates = []string{
    "effectiveDataplaneType",
    "EffectiveType",
    "DataplaneType == dataplaneTypeDPDK",
    "DataplaneType == \"dpdk\"",
}

func TestDPDKSubtreeReadsAreGatedOnEffectiveDataplaneType(t *testing.T) {
    // Walk every .go file in the repo (excluding _test.go,
    // pkg/config/ itself, and pkg/dataplane/dpdk/) and
    // collect SelectorExpr nodes whose RHS identifier is
    // "DPDKDataplane".
    //
    // For each such node, ascend the AST to the nearest
    // enclosing if-statement; assert its condition source
    // text contains at least one gatePredicates entry.
    //
    // Failure mode: report file:line plus the bare selector,
    // with a remediation hint pointing to
    // effectiveDataplaneType().
}
```

### 4.2 What gets excluded from the walk

- `*_test.go` (tests legitimately probe DPDK fields).
- `pkg/config/` itself (the writer at
  `compiler_system.go:236-242` populates the field; the canary
  would otherwise fire on its own writer).
- `pkg/dataplane/dpdk/` — the retired in-tree backend that
  reads its own sub-tree for compat until #1528 deletes it.
- Anything with a `//go:build ignore` build tag.

### 4.3 What the canary catches

- A new file `pkg/foo/bar.go` that contains
  `cfg.System.DPDKDataplane.Cores` without a dominating
  `effectiveDataplaneType(cfg.System.DataplaneType) ==
  dataplaneTypeDPDK` guard.
- A range loop over `cfg.System.DPDKDataplane.Ports` outside
  a gated branch.
- A pointer-receiver method on a struct that stores
  `DPDKDataplane *DPDKConfig` and dereferences it unconditionally.

### 4.4 What the canary does NOT catch

- Indirect reads via a wrapper helper that takes
  `*DPDKConfig` directly. The canary only catches the
  selector pattern `<X>.DPDKDataplane`. If a developer
  passes `cfg.System.DPDKDataplane` (possibly nil) into a
  helper that then reads `.Cores` unconditionally, the
  helper-side dereference is invisible to the canary.
  **Documented mitigation:** the SelectorExpr walk catches
  the call-site `something(cfg.System.DPDKDataplane)`, so
  the canary still fires at the boundary unless the call is
  inside a gated branch.
- Reflective access (`reflect.ValueOf(cfg).FieldByName(...)`).
  Documented as out-of-scope; reflective access into config
  is already a project-wide anti-pattern caught by other
  canary tests.

### 4.5 Why NOT Option A (or Option A in addition)

Option A clears `cfg.System.DPDKDataplane = nil` at the end of
`compileExpanded`. Pros: structural invariant. Cons:

1. Today, the field is already only populated under the
   `case dataplaneTypeDPDK` branch in `compiler_system.go:236`,
   which is unreachable after #1536 hard-rejects that
   `DataplaneType`. The clear is provably a no-op on
   committed configs.
2. It does NOT defend against the bug class the issue is
   actually worried about — a future reader that *uses*
   `cfg.System.DPDKDataplane` unconditionally would still
   panic on `nil` dereference if the strict validator path
   were ever bypassed (e.g., by a future code path that
   compiles a candidate without going through
   `compileExpanded`).
3. After #1528 deletes `DPDKConfig`, Option A becomes a
   delete-this-line followup; Option B becomes a delete-this-file
   followup. Same churn either way.

Option A is rejected as the primary defense. We MAY still want
it as belt-and-braces (one-line nil assignment); decision
deferred to round-2 plan review.

## 5. Public API preservation

This plan adds zero production code. The only diff is one new
`*_test.go` file under `pkg/config/`. Public API is unchanged.

If round-2 review insists on Option A, the change is a 3-line
addition to `compileExpanded` clearing
`cfg.System.DPDKDataplane = nil` after the strict validator
passes. No API surface added; the field is already nil in the
common path.

## 6. Hidden invariants the canary must preserve

1. **Existing precedent canary in `pkg/dataplane/`** uses
   `go/parser` + `ast.Inspect`. Our new canary lives under
   `pkg/config/`; it should follow the same structural pattern
   (path constants, allowlist map, ascent-to-enclosing-if).
2. **Build tags** — files under `//go:build ignore` (e.g.
   `pkg/dataplane/loader_stub.go`) must be skipped. The
   precedent canary excludes them via path; we will do the
   same.
3. **Generated files** — `bpf2go`-generated `*_bpfel.go` files
   live under `pkg/dataplane/` not `pkg/config/`; they do not
   reference `DPDKDataplane`. No special handling needed, but
   the walk's exclusion list documents this.
4. **`go list` vs direct filepath walk** — the precedent
   canary walks the filesystem directly with `filepath.Walk`
   relative to a `repoRootForBoundaryCanary = "../.."` constant.
   We will do the same with
   `repoRootForDPDKLeakageCanary = "../.."`.

## 7. Risk assessment

| Class | Level | Justification |
|---|---|---|
| Behavioral regression | LOW | Test-only addition. No production code path changed. |
| Lifetime / borrow-checker | N/A | Go, no Rust changes. |
| Performance regression | LOW | Canary runs at `go test` time only. |
| Architectural mismatch (#946-Phase-2 / #961 pattern) | MEDIUM | If #1528 deletes `DPDKConfig` within weeks, this canary becomes tautological — the work is wasted. KILL is appropriate if reviewers think the window is too small. |
| False positives | MEDIUM | The "dominating if-statement" heuristic can miss switch-statements and ternary-equivalent assignments. Mitigated by a clear remediation message and an allowlist for any legitimate cross-package reader. |

## 8. Test plan

- `go test ./pkg/config/ -run TestDPDKSubtreeReadsAreGatedOnEffectiveDataplaneType` — passes against current master.
- `go test ./pkg/config/ -run TestDPDKSubtreeReadsAreGatedOnEffectiveDataplaneType -count=5` — 5× flake check.
- `go test ./...` — full Go suite (30 packages), no regression.
- Negative fixture: introduce a temporary `pkg/config/canary_fixture_test.go`-style file (build-tag-gated `//go:build ignore`) that has an ungated read, prove the canary fires on it. **Do not commit the fixture**; round-2 may ask to commit it as a `//go:build canaryselftest` file.
- Smoke matrix on the loss userspace cluster is OPTIONAL because no runtime code changes — but we will still run a single v4 + v6 push + reverse pair to confirm `cluster-deploy` does not regress on the head SHA. No per-class CoS sweep needed; this is a pure-test PR.

## 9. Out of scope (explicit)

- **Option A (sub-tree clear at commit)** — deferred to a round-2 decision. Default is Option B only.
- **Static analysis of helper functions taking `*DPDKConfig` directly** — the canary only walks selector expressions of the form `<X>.DPDKDataplane`. Indirect access through a helper that accepts `*DPDKConfig` is documented as out-of-scope.
- **Reflective access (`reflect.ValueOf(...).FieldByName(...)`)** — out-of-scope; covered by other repo-wide reflective-access canaries.
- **Deleting `DPDKConfig` itself** — that's #1528 / Phase 3 work. This canary is the bridge between #1536 (reject) and #1528 (delete).
- **Adding the same canary for `UserspaceDataplane`** — `UserspaceDataplane` is the *active* sub-tree, not retired, so the inverse invariant ("only read when effectiveType == userspace") is the normal happy path. Out of scope; a separate issue if anyone cares.

## 10. Open questions for adversarial review

1. **Window value** — Is the (#1536-merge → #1528-merge) window long enough to justify a 100-200 line test? If #1528 is already in flight, PLAN-KILL is appropriate.
2. **Option A vs Option B** — Is Option A's one-line clear enough actual defense to NOT bother with Option B? Or are both worth shipping together?
3. **Indirect access** — How much do reviewers care about the helper-function escape hatch (caller passes `cfg.System.DPDKDataplane` to a function that derefs it)? If this is the realistic future regression vector, Option B is incomplete and we need a stricter type wrapper.
4. **`switch effectiveDataplaneType(...)` pattern recognition** — The canary's "dominating if-statement" heuristic does not natively understand `switch` statements. The existing writer at `compiler_system.go:228-246` uses a `switch` and would be excluded by the pkg/config/ exclusion, but a future cross-package reader could also use `switch`. Should the canary recognize `case dataplaneTypeDPDK:` inside a switch as a valid gate?
5. **Should the canary live in `pkg/config/` or `pkg/dataplane/`?** — The precedent is in `pkg/dataplane/`. But this canary asserts a property of the `*Config` typed schema; `pkg/config/` is more natural. Either is defensible; calling it out for reviewer input.
6. **Self-test fixture commit** — Should we commit a `//go:build canaryselftest` negative fixture that proves the canary actually rejects an ungated read? Or is the inline test enough?
