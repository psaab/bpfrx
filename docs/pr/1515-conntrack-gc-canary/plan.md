# #1515 — conntrack GC legacy-bridge canary

## Goal

Add a regression canary to `pkg/conntrack/` that fails the build if any
`pkg/conntrack` production function (exported or unexported)
reintroduces a parameter or return type of `dataplane.DataPlane`, or
if any package-level type embeds `dataplane.DataPlane`, or if any
interface method signature mentions it. This is the smallest sub-issue
of #1451.

## Current state (master @ da103d81)

- `pkg/conntrack/gc.go` is fully migrated:
  - `NewGC(provider RuntimeDomainProvider, interval time.Duration) *GC`
  - `NewGCWithDomains(sessions dataplane.SessionStore, telemetry
    dataplane.Telemetry, sessionCount sessionCountPublisher,
    persistent persistentNATProvider, interval time.Duration) *GC`
- `pkg/conntrack/gc_test.go` uses a `mockGCDP` that satisfies
  `RuntimeDomainProvider` (a narrow `Sessions()` + `Telemetry()` pair)
  via its own `Sessions()` and `Telemetry()` methods.
- `pkg/conntrack/README.md:13` accurately describes the
  `RuntimeDomainProvider` constructor.
- `grep -n 'dataplane\.DataPlane' pkg/conntrack/*.go` finds zero
  matches.

## Approach

Add a new file `pkg/conntrack/legacy_dataplane_canary_test.go` that
parses every `.go` file in the package (excluding the canary itself)
and walks the AST. The canary fails if:

1. Any `*ast.FuncDecl` parameter or result type expression resolves to
   `dataplane.DataPlane` (or `*dataplane.DataPlane`).
2. Any `*ast.TypeSpec` struct literal embeds `dataplane.DataPlane`.
3. Any `*ast.InterfaceType` method signature mentions
   `dataplane.DataPlane`.

This mirrors the existing canary at
`pkg/dataplane/userspace/manager_coupling_test.go`. The conntrack
canary uses an `isLegacyDataPlaneType()` matcher (switching on
`*ast.SelectorExpr` / `*ast.StarExpr` / `*ast.Ellipsis` /
`*ast.ParenExpr` / `*ast.ArrayType`) rather than the `exprString()`
text-compare helper used by the userspace coupling test — both forms
catch the same naive shapes; the matcher style was chosen for clearer
per-shape rejection and easier extension. The canary skips `*_test.go`
files intentionally — test code may still mention the type to assert
non-implementation (similar to the coupling test in
`pkg/dataplane/userspace`).

The walker has TWO passes (see `findLegacyDataPlaneOffenders`):

1. **Structural pass**: inspects every `*ast.FuncDecl` (exported and
   unexported), every `*ast.StructType` field, and every
   `*ast.InterfaceType` method signature for the prohibited shapes.
   Produces precise diagnostics that name the function / field /
   method holding the prohibited type.
2. **Catch-all selector sweep**: walks every `*ast.SelectorExpr` in
   the file and flags any `dataplane.DataPlane` reference the
   structural pass did not already attribute. This closes the bypass
   categories AGY adversarial-review (#1532 round-N) identified:
   package-level / local `var x dataplane.DataPlane`,
   `&dataplane.DataPlane{}` composite literals, `func(dp
   dataplane.DataPlane){}` closures, and `type X dataplane.DataPlane`
   type definitions. The sweep also subsumes the compound types
   (`[]T`, `map[K]T`, `chan T`, `func(T)`) previously documented as
   `#1548-deferred` — they still contain a literal
   `dataplane.DataPlane` selector in their AST.

Only true `#1548-deferred` bypasses remain, all sharing one
property — the `dataplane.DataPlane` selector disappears from the AST
and only `go/types` can resolve the substitute name back to the
original type:

- **Transitive alias use** — `type DPAlias = dataplane.DataPlane`
  declares the alias (whose RHS the sweep DOES catch), but a
  downstream `var x DPAlias` parses as a bare `*ast.Ident`.
- **Import renames** — `import dp "github.com/psaab/xpf/pkg/dataplane"`
  causes the selector to read `dp.DataPlane`, which the sweep's
  `pkg.Name == "dataplane"` check misses.
- **Dot imports** — `import . "github.com/psaab/xpf/pkg/dataplane"`
  erases the package qualifier entirely; references become bare
  `DataPlane` idents.
- **External-package wrapper types** — a type defined in another
  package that wraps `dataplane.DataPlane` and is then imported
  into pkg/conntrack as `otherpkg.Wrapper`.

Compound types (`[]T`, `map[K]T`, `chan T`, `func(T)`), generic
constraints (`func F[T dataplane.DataPlane]`), and generic
instantiations (`Generic[dataplane.DataPlane]`) are NOT in the
deferred set — the catch-all sweep flags them because they still
contain a literal `dataplane.DataPlane` selector.

## Files touched

- `pkg/conntrack/legacy_dataplane_canary_test.go` — new file,
  ~615 LOC (matcher + two-pass walker + 4 test functions with
  34 subcases covering structural shapes, catch-all sweep, false-
  positive avoidance, and AGY-bypass closures).
- `docs/pr/1515-conntrack-gc-canary/plan.md` — new file.
- `_Log.md` — log entries.

## Files NOT touched (intentional)

- `pkg/conntrack/gc.go` — already migrated; no behaviour change wanted.
- `pkg/conntrack/gc_test.go` — already uses a narrow mock; no change
  needed.
- `pkg/conntrack/README.md` — already accurate; no change needed.

If reviewers push back asking to also delete the `dataplane.SessionStoreOf(nil)`
/ `dataplane.TelemetryOf(nil)` nil-fallthrough in `NewGC`, that's a
separate behavioural change. File as a follow-up rather than expanding
scope (engineering-style.md §5 "Narrow scope").

## Alternatives rejected

- **`const _ = ...` style.** Compile-time asserts can't introspect AST
  shape; we need a `*_test.go` AST walker.
- **`go vet` lint analyzer.** Heavier; the AST walker pattern is
  already in the tree.
- **Touch `gc.go` to remove the legacy bridge fallthrough.** Out of
  scope — separate sub-issue.

## Validation

- `make test ./pkg/conntrack/...` passes.
- Hand-flip `gc.go` to add a fake `func NewGCLegacy(dp dataplane.DataPlane) *GC`
  and confirm the canary fires; revert before commit.

## Smoke evidence

Unit-test only. No dataplane bring-up needed. Documented in the PR
body per `docs/engineering-style.md` §8.

## Risk

Trivial. No production code changes.
