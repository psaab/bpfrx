# #1559 plan — harden legacy_dataplane_canary against struct-field + selector reintroduction

**Status:** DRAFT v3 — addresses Codex round-2 PLAN-NEEDS-MINOR (position tokens + Pass-4 noise wording)

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
  `pkg/dataplane/retirement_boundary_canary_test.go` enforces a wider
  package-level import allowlist (and asserts only that `Daemon.dp`
  remains `dataplane.RuntimeDataPlane`) but is **not** focused on the
  `legacyDP` identifier specifically. Confirmed by Codex round-1:
  it would not catch adding a sibling `legacyDP dataplane.DataPlane`
  field, nor a bare `d.legacyDP` selector read.
- The canary itself is brand new (3 days old) and has zero prior
  authors to coordinate with.

## Concrete design

Extend the canary's per-file scan with two additional passes inside
the existing `for _, entry := range entries` loop. Both passes reuse
the same `*token.FileSet` and append to the same `offenders` slice
for a unified failure message.

### Pass 1 (tightened) — FuncDecl name match, receiver-agnostic

Round-1 Gemini caught a critical bypass: the existing Pass 1 checks
`receiverIsDaemon(fd.Recv)` and returns false when `fd.Recv` is nil
(canary.go line 83 — `if recv == nil || len(recv.List) != 1`). A
package-level `func legacyDP(d *Daemon) dataplane.DataPlane { ... }`
is a `*ast.FuncDecl` with nil receiver and bypasses Pass 1 entirely.
The consumer `legacyDP(d)` parses as `*ast.CallExpr` whose `Fun` is
`*ast.Ident` (not `*ast.SelectorExpr`) — bypasses both the existing
Pass 2 and the new Pass 4.

Tighten Pass 1 to forbid ANY `FuncDecl` named `legacyDP`, regardless
of receiver shape:

```go
for _, decl := range file.Decls {
    fd, ok := decl.(*ast.FuncDecl)
    if !ok {
        continue
    }
    if fd.Name == nil || fd.Name.Name != "legacyDP" {
        continue
    }
    // Receiver shape no longer narrows — Daemon method,
    // package-level function, or any other shape is forbidden.
    // Record at fd.Name.Pos() (not fd.Pos()) so multiline function
    // declarations land the offender on the identifier's line, not
    // the opening `func` keyword. Pairs with Pass 5's ident.Pos().
    pos := fset.Position(fd.Name.Pos())
    msg := "forbidden function/method declaration named legacyDP — " +
        "removed in #1519, see plan-impl.md. The identifier is " +
        "reserved within pkg/daemon production code."
    offenders = append(offenders, name+":"+itoa(pos.Line)+": "+msg)
}
```

The `receiverIsDaemon` helper becomes dead code. Delete it.

### Pass 5 — bare *ast.Ident name match

Close the consumer-side bypass: a callsite `legacyDP(d)` whose `Fun`
is `*ast.Ident` (no selector) needs to be caught by walking
`*ast.Ident` directly. Also catches: package-level var/const named
`legacyDP`, local var assignments `legacyDP := ...`, and any other
bare identifier use.

Because `ast.Inspect` walks every node — including the `Sel` of
every `SelectorExpr`, the `Name` of every `FuncDecl`, and the `Names`
of every `*ast.Field` — Pass 5 will fire on the SAME identifier node
that Pass 1's `fd.Name`, Pass 3's field `Names[i]`, and Pass 4's
`sel.Sel` are also checking. Without dedup, a single struct-field
reintroduction would emit ~3-5 offenders for the same line.

Solution: a record-once dedup keyed on `(file, line)`. First pass
to record wins; later passes on the same line are suppressed. Pass
order is chosen so the most specific diagnostic survives.

```go
recorded := make(map[string]bool)
record := func(pos token.Position, msg string) {
    key := name + ":" + itoa(pos.Line)
    if recorded[key] {
        return
    }
    recorded[key] = true
    offenders = append(offenders, key+": "+msg)
}
```

Each pass calls `record(...)` instead of appending directly. With
dedup in place, Pass 5 becomes:

```go
ast.Inspect(file, func(n ast.Node) bool {
    ident, ok := n.(*ast.Ident)
    if !ok {
        return true
    }
    if ident.Name != "legacyDP" {
        return true
    }
    // Pass 5 is the catch-all. Earlier passes (1, 3, 2, 4) record
    // their more specific diagnostics first; this pass only writes
    // when the (file, line) hasn't been recorded yet, e.g. a bare
    // callsite `legacyDP(d)` whose Fun is *ast.Ident (no SelectorExpr).
    pos := fset.Position(ident.Pos())
    record(pos, "forbidden identifier legacyDP — removed in #1519; "+
        "the name is reserved within pkg/daemon production code "+
        "(no field, method, function, selector, or bare identifier "+
        "may use it)")
    return true
})
```

Pass ordering invariants: most specific first
(FuncDecl > StructType.Field > CallExpr > SelectorExpr >
bare Ident).

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
            // Message intentionally does NOT say "as a Daemon
            // field" — Pass 3 walks every StructType, not just
            // the Daemon struct, so a developer naming an
            // unrelated struct's field legacyDP would otherwise
            // get a misleading diagnostic (Codex round-1 finding).
            record(pos, "forbidden struct field named legacyDP — "+
                "removed in #1519; the identifier is reserved "+
                "within pkg/daemon production code. Use a typed "+
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

### Pass 2 (preserved) — CallExpr match

The existing CallExpr loop (canary lines 92-110) is kept. It produces
a more actionable "forbidden call to .legacyDP()" diagnostic when the
reintroduction takes the call-shape (most common path). With the
record-once deduplication in place, this fires first for any callsite
and suppresses the SelectorExpr/Ident duplicates on the same line.

Update Pass 2 to record at `sel.Sel.Pos()` (not `call.Pos()`) so the
recorded line matches Pass 4 and Pass 5 for the multiline
`d.\n  legacyDP()` case. Pairs with the record-once dedup so the same
line that Pass 2 catches via the CallExpr is also the line Pass 4
would have used for the selector and Pass 5 would have used for the
bare ident.

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
    // Record at sel.Sel.Pos() (not sel.Pos()) so multiline
    // `d.\n  legacyDP` lands on the identifier's line, which
    // matches the line Pass 5 would record. Pairs with the
    // record-once dedup.
    pos := fset.Position(sel.Sel.Pos())
    record(pos, "forbidden selector .legacyDP — removed in #1519; "+
        "do not re-introduce as a field, method, or accessor. "+
        "Use a typed probe in runtime_probes.go instead")
    return true
})
```

Note: this pass overlaps with the existing CallExpr check. The
existing CallExpr loop fires on `d.legacyDP()`; the new SelectorExpr
loop fires on the inner `d.legacyDP` of the same expression. Both
record at `sel.Sel.Pos()` (same identifier token, same line). With
the record-once dedup in place, Pass 2 (CallExpr) runs BEFORE Pass 4
(SelectorExpr), so Pass 2's call-shaped diagnostic wins the
`(file, line)` slot and Pass 4 is suppressed for that line. Pass 4
still fires on its own when the offender is a bare selector read
(no CallExpr wrap), which is the new shape it exists to catch.

Alternative considered: replace the CallExpr loop entirely with
just the SelectorExpr loop. Rejected because the existing call-shape
message ("forbidden call to .legacyDP()") is more actionable for the
common reintroduction path (a callsite that calls the accessor), and
removing it would be a behavior change unrelated to this hardening.

### Pass 3 vs Pass 4 overlap

`legacyDP` field declarations don't appear as `*ast.SelectorExpr` —
they live in `*ast.StructType.Fields`. So Pass 3 catches the
*declaration*; Pass 4 catches the *use*. A struct-field reintroduction
trips Pass 3 on the declaration line and Pass 4 on each consumer
line. With record-once dedup the diagnostic on the declaration line
is the StructType message (Pass 3 wins; Pass 5 is suppressed for that
same line because `ast.Inspect` reaches the field's `*ast.Ident` and
calls `record` for it AFTER Pass 3 has already inserted the key).
Consumer lines get the SelectorExpr message from Pass 4.

### Pass execution order (record-once)

1. Pass 1 — FuncDecl name match (any receiver shape, incl. nil)
2. Pass 3 — StructType.Fields name match
3. Pass 2 — CallExpr selector name match
4. Pass 4 — SelectorExpr name match (bare selector reads)
5. Pass 5 — bare *ast.Ident name match (catches `legacyDP(d)` call
   target, var decls, type names — anything not already recorded)

First match per (file, line) wins; later passes suppressed. Any
single reintroduction will fire at least one offender; complex
multi-line reintroductions (decl + multiple consumers) will fire
one offender per affected line.

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
identifier `legacyDP` is reserved within pkg/daemon production code
(non-test `*.go` files only). The canary will fail on any field,
method, function, selector, or bare identifier using this name,
regardless of surrounding type or receiver." This wording matches
the actual five-pass coverage (Codex round-1 finding 5).

## Public API preservation

None. This is a test-only file. The exported names are:

- `TestLegacyDPAccessorRemoved` — preserved, same signature.
- `receiverIsDaemon` — DELETED (Pass 1 no longer narrows on receiver).
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
   - Struct with `legacyDP` field → offenders contains at least one entry naming the field's line
   - Function body with `d.legacyDP` (bare selector, no call) → at least one entry on the selector's line
   - Function body with `d.legacyDP()` (call) → at least one entry on the call's line (existing behavior preserved)
   - **Package-level `func legacyDP(d *Daemon) X` declaration** → at least one entry on the FuncDecl's line (closes v1 bypass)
   - **Bare `legacyDP(d)` callsite** → at least one entry on the callsite's line (closes v1 bypass)
   - File with `legacyDP` in a comment or string literal → offenders empty

   Tests assert "at least one entry naming the expected line", NOT exact offender counts. Pass overlap + record-once mean the surviving entry per line depends on pass order; the contract the canary documents is "any reintroduction line is named at least once", not "exactly N times". (Codex round-1 finding 4.)
3. **Run the canary against the current tree:** must pass cleanly (the deleted accessor is gone; no production code references it).
4. **Sanity:** `go test ./pkg/daemon ./...` to confirm no incidental breakage.

Smoke testing on `loss:xpf-userspace-fw0/fw1` is NOT required for
this PR — it's a test-only change in `pkg/daemon` that does not
affect deployed dataplane behavior. AGY/Codex/Gemini sign-off plus
Go test suite is the full gate.

## Out of scope (explicitly)

- **Receiver-narrowed Pass 4** (P3 fix). Requires `go/types`, deferred
  with a docstring instead. The identifier is now reserved across
  ALL of pkg/daemon production code (Pass 5 closes the bypass that
  v1 left open); a legitimate future helper hitting the wall must
  either rename or update the canary + architectural review.
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
3. **[RESOLVED v2]** Pass 5 added in v2 to walk bare `*ast.Ident`
   tokens. Closes the Gemini round-1 critical bypass: package-level
   `func legacyDP(d *Daemon)` + callsite `legacyDP(d)` would
   otherwise sneak past every previous pass. The identifier is now
   reserved across all pkg/daemon production-code AST surfaces.
4. **Should the synthetic negative tests live in this same file** or
   in a new `legacy_dataplane_canary_synthetic_test.go`? Coloc keeps
   the canary self-documenting; separate file keeps the production
   canary file shorter. Either is fine.
5. **Is keeping the existing CallExpr loop alongside the new
   SelectorExpr loop the right call**, or should Pass 4 replace it
   entirely? Keeping both gives two messages on a single offending
   call site; removing the CallExpr loop loses the "this is a call"
   actionable hint. Reviewers: pick one.
