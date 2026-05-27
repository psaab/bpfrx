# #1559 plan — harden legacy_dataplane_canary against struct-field + selector reintroduction

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

PR #1557 (capstone delete `ee4b34bf`) added
`pkg/daemon/legacy_dataplane_canary_test.go` as a regression guard.
The canary scans every non-test `*.go` file under `pkg/daemon` and
fails on two AST shapes:

1. `FuncDecl` named `legacyDP` whose receiver type is `*Daemon` or
   `Daemon` (canary lines 75-90).
2. `CallExpr` whose `Fun` is a `SelectorExpr` with `Sel.Name ==
   "legacyDP"` (canary lines 92-110).

AGY adversarial review on PR #1557 (`adversarial-review-mpm8y8a3-8cbeh2`,
2026-05-26T06:23:17Z) identified two structural blind spots that
shipped with #1557:

- **P2 — struct-field reintroduction.** A developer can re-add
  `legacyDP dataplane.DataPlane` as a `Daemon` struct field and then
  consume it via `dp := d.legacyDP; dp.ReadGlobalCounter(1)`. The
  field declaration parses as `*ast.StructType.Fields`, not
  `*ast.FuncDecl`. The consumer reads `d.legacyDP` as a bare
  `*ast.SelectorExpr` inside `*ast.AssignStmt` — not a `*ast.CallExpr`.
  Both shapes bypass the current canary.
- **P3 — false-positive surface.** The CallExpr check matches *any*
  selector named `legacyDP` regardless of receiver type. A future
  internal helper `type mockHelper struct{}` with a legitimate
  `legacyDP()` method would trip the canary. Not in-tree today; worth
  documenting OR narrowing.

## Honest scope/value framing

This is a test-only file (`pkg/daemon/legacy_dataplane_canary_test.go`).
The "win" is closing two CI bypass paths against re-introduction of
the deleted `(*Daemon).legacyDP()` accessor. No runtime impact, no
performance impact, no API surface change. The two new AST passes
are O(file size) and run once per `go test ./pkg/daemon` invocation.

If reviewers conclude the hardening is unnecessary (e.g. the
retirement boundary canary at `pkg/daemon/retirement_boundary_canary_test.go`
already catches this), PLAN-KILL is an acceptable verdict.

## What's already shipped / partially batched

- PR #1557 (merged as `ee4b34bf`): deleted `(*Daemon).legacyDP()` and
  added the v1 canary at `pkg/daemon/legacy_dataplane_canary_test.go`.
- The retirement-boundary canary at
  `pkg/daemon/retirement_boundary_canary_test.go` enforces a wider
  package-level allowlist but is **not** focused on the `legacyDP`
  identifier specifically.
- The canary itself is brand new (3 days old) and has zero prior
  authors to coordinate with.

## Concrete design

Extend the canary's per-file scan with two additional passes inside
the existing `for _, entry := range entries` loop. Both passes reuse
the same `*token.FileSet` and append to the same `offenders` slice
for a unified failure message.

### Pass 3 — struct-field reintroduction

Walk every `*ast.StructType` in the file and check each field's
identifier list. If any field has `Names[i].Name == "legacyDP"`,
record an offender.

```go
ast.Inspect(file, func(n ast.Node) bool {
    st, ok := n.(*ast.StructType)
    if !ok {
        return true
    }
    if st.Fields == nil {
        return true
    }
    for _, field := range st.Fields.List {
        for _, fname := range field.Names {
            if fname == nil || fname.Name != "legacyDP" {
                continue
            }
            pos := fset.Position(fname.Pos())
            offenders = append(offenders,
                name+":"+itoa(pos.Line)+": forbidden struct field "+
                    "named legacyDP — removed in #1519; do not "+
                    "re-introduce as a Daemon field. Use a typed "+
                    "probe in runtime_probes.go instead")
        }
    }
    return true
})
```

Scope note: this fires on ANY struct field named `legacyDP` in any
`pkg/daemon` non-test `*.go` file, not just on `Daemon` itself. That
is intentional — the historical accessor's whole point was to leak
a `dataplane.DataPlane`-shaped value, and the field-name canary is
the narrowest forbidden-identifier check. If a developer wants to
add a `legacyDP` field to a different struct in `pkg/daemon`, the
canary will fail and they'll need to either (a) rename the field or
(b) update the canary and document the new architectural review.

### Pass 4 — SelectorExpr matching (catches bare selector reads)

Walk every `*ast.SelectorExpr` (including those NOT wrapped in
`*ast.CallExpr`) and fail on `.Sel.Name == "legacyDP"`. This catches:

- Bare field read: `dp := d.legacyDP`
- Method-value expression: `f := d.legacyDP` (when `legacyDP` is a
  method, not a field)
- Method-expression: `(*Daemon).legacyDP` — `*ast.SelectorExpr` with
  ParenExpr receiver
- Any selector chain ending in `.legacyDP` regardless of context

```go
ast.Inspect(file, func(n ast.Node) bool {
    sel, ok := n.(*ast.SelectorExpr)
    if !ok {
        return true
    }
    if sel.Sel == nil || sel.Sel.Name != "legacyDP" {
        return true
    }
    pos := fset.Position(sel.Pos())
    offenders = append(offenders,
        name+":"+itoa(pos.Line)+": forbidden selector .legacyDP — "+
            "removed in #1519; do not re-introduce as a field, "+
            "method, or accessor. Use a typed probe in "+
            "runtime_probes.go instead")
    return true
})
```

Note: this pass subsumes the existing CallExpr check. The current
CallExpr loop fires on `d.legacyDP()`; the new SelectorExpr loop
fires on the inner `d.legacyDP` of the same expression — same line,
same line number. To avoid double-reporting, we keep the CallExpr
loop intact (it has a more specific, call-site-shaped message) and
let the SelectorExpr loop ALSO fire — both emissions reference the
same line; the unified offenders message is acceptable noise for
the rare case where the canary actually trips.

Alternative considered: replace the CallExpr loop entirely with
just the SelectorExpr loop. Rejected because the existing call-shape
message ("forbidden call to .legacyDP()") is more actionable for the
common reintroduction path (a callsite that calls the accessor), and
removing it would be a behavior change unrelated to this hardening.

### Pass 3 vs Pass 4 overlap

`legacyDP` field declarations don't appear as `*ast.SelectorExpr` —
they live in `*ast.StructType.Fields`. So Pass 3 catches the
*declaration*; Pass 4 catches the *use*. A struct-field reintroduction
will trip both (declaration on one line, every consumer on its own
line) — the test author will see a clear unified failure with multiple
offender entries, all pointing at the same root cause. That's the
right behavior: each line that needs to change is named.

### P3 — receiver narrowing (deferred, documented)

The plan does NOT narrow Pass 4 to a specific receiver type because
doing so requires type information (the canary is AST-only and does
not run `go/types`). A future internal helper struct with a
legitimately-named `legacyDP()` method would trip the canary; the
fix is to either rename the new method (the canary documents that
the name is reserved within `pkg/daemon` production code), or to
update the canary AND get architectural-review sign-off as part of
the new feature work.

Update the canary's package doc comment to explicitly state: "the
identifier `legacyDP` is reserved within pkg/daemon production code;
do not re-use it for any field, method, or selector regardless of
the surrounding type."

## Public API preservation

None. This is a test-only file. The exported names are:

- `TestLegacyDPAccessorRemoved` — preserved, same signature.
- `receiverIsDaemon` — package-private helper, unchanged.
- `itoa` — package-private helper, unchanged.

Two new sub-passes are added inline; no new exported names.

## Hidden invariants the change must preserve

- **Out-of-scope comments still allowed.** The canary parses `.go`
  files but only inspects AST nodes — `parser.ParseFile` ignores
  comments by default (no `parser.ParseComments` flag). Plan-impl.md
  and commit messages remain free to mention the historical
  `legacyDP` symbol. **Verify:** `parser.AllErrors` is the only flag
  used; comments are not loaded.
- **_test.go files excluded.** The existing loop skips `_test.go`
  files. Both new passes run inside the same loop and inherit this
  filter — tests can still reference `legacyDP` in their own files
  (and indeed this test file references it in string literals for
  failure messages, which is fine because string literals are
  `*ast.BasicLit` not `*ast.SelectorExpr` / `*ast.StructType.Fields`).
- **No `go/types` dependency.** Pure AST scan; the canary remains
  fast and self-contained.
- **Unified failure message.** All offenders aggregate into the same
  `offenders` slice and are emitted by a single `t.Fatalf` at the
  end. Both new passes feed the same slice.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression risk | **LOW** | Test-only file; no production code touched. |
| Lifetime / borrow-checker risk | **N/A** | Go, not Rust. |
| Performance regression risk | **LOW** | Two added `ast.Inspect` walks per file; pkg/daemon has ~20-30 files; runs once per `go test`. |
| Architectural mismatch risk | **LOW** | This is the AGY-recommended fix, applied directly. The only architectural question is whether the broader retirement-boundary canary already covers this — see "Open questions" below. |
| False-positive risk on developer onboarding | **MED** | If a developer adds an unrelated `legacyDP` identifier in `pkg/daemon`, they get a clear failure pointing at this canary. The canary's doc comment names the constraint explicitly. |

## Test plan

The canary itself is the test. To validate the hardening:

1. **Build and run the canary clean:** confirm `go test ./pkg/daemon -run TestLegacyDPAccessorRemoved` passes on the current master baseline.
2. **Negative tests via temp file:** add a small `legacy_dataplane_canary_synthetic_test.go` (or extend the existing file) that loads synthetic Go source via `parser.ParseFile` against a fake fset, walks it with the new passes wrapped in callable helpers, and asserts:
   - Struct with `legacyDP` field → offender count > 0
   - Function body with `d.legacyDP` (bare selector, no call) → offender count > 0
   - Function body with `d.legacyDP()` (call) → offender count > 0 (existing behavior preserved)
   - File with `legacyDP` in a comment or string literal → offender count == 0
3. **Run the canary against the current tree:** must pass cleanly (the deleted accessor is gone; no production code references it).
4. **Sanity:** `go test ./pkg/daemon ./...` to confirm no incidental breakage.

Smoke testing on `loss:xpf-userspace-fw0/fw1` is NOT required for
this PR — it's a test-only change in `pkg/daemon` that does not
affect deployed dataplane behavior. AGY/Codex/Gemini sign-off plus
Go test suite is the full gate.

## Out of scope (explicitly)

- **Receiver-narrowed Pass 4** (P3 fix). Requires `go/types`, deferred
  with a docstring instead. Captured as a future tightening if a
  legitimate helper hits the reserved-identifier wall.
- **Wider package coverage.** This canary only inspects `pkg/daemon`.
  Other packages don't need their own `legacyDP` canary because the
  identifier never existed outside `pkg/daemon`.
- **String-literal / comment scanning.** Intentionally allowed — see
  "Hidden invariants" above.
- **Adding `legacyDP` to a reserved-identifiers DB / lint rule.**
  Overkill for one identifier; the AST canary is the right shape.

## Open questions for adversarial review

1. **Does `retirement_boundary_canary_test.go` already catch this?**
   If yes, this PR is redundant and PLAN-KILL is correct. (Initial
   reading of #1557 suggests no — the boundary canary is package-
   allowlist-shaped, not identifier-name-shaped — but reviewers
   should confirm.)
2. **Is the false-positive risk on Pass 3/4 acceptable?** A pkg/daemon
   developer who wants to name a *different* field/method `legacyDP`
   will be blocked. Is reserving the identifier across the whole
   package the right scope?
3. **Should Pass 4 also fire on `legacyDP` as a non-selector identifier**
   (e.g. a local var named `legacyDP`, a const named `legacyDP`)?
   The current proposal does not — only selector and struct-field
   shapes. Reviewers: is that the right scope, or should the canary
   reserve the bare identifier entirely?
4. **Should the synthetic negative tests live in this same file** or
   in a new `legacy_dataplane_canary_synthetic_test.go`? Coloc keeps
   the canary self-documenting; separate file keeps the production
   canary file shorter. Either is fine.
5. **Is keeping the existing CallExpr loop alongside the new
   SelectorExpr loop the right call**, or should Pass 4 replace it
   entirely? Keeping both gives two messages on a single offending
   call site; removing the CallExpr loop loses the "this is a call"
   actionable hint. Reviewers: pick one.
