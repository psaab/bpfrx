# #1699 — split pkg/config/ast.go: separate config-mode schema grammar from AST node types

**Status:** v2 — PLAN-READY. Round 1: Codex PLAN-NEEDS-MINOR, AGY
PLAN-READY, Claude-SMR PLAN-READY. Seam unanimously judged real. v2
adopts all four Codex minors (both reviewers independently recommended
the `schema_complete.go` split): (1) split the completion functions into
`schema_complete.go` so both new files land below the audit threshold;
(2) update `docs/config-schema.md` + `pkg/config/README.md` references
from `ast.go` to the new files; (3) `schema.go` imports only `strings`
(grammar literal needs neither `fmt` nor `strings` directly, but
`isTypedLeaf`/`appendTypedValueCompletions` move with completion code);
(4) corrected the audit-tag wording — see below.

## 1. Issue framing

`pkg/config/ast.go` is 2021 LOC (verified; `[REFACTOR]` tag in
`docs/refactoring-audit-current.txt`). It crossed the 2000-LOC refactor
threshold when #1319 PR1 added the typed-leaf `schemaNode` fields,
`appendTypedValueCompletions`, and the typed-value branches in
`CompleteSetPathWithValues`.

The file today carries **two distinct concerns** in one compilation unit:

- **Concern A — AST node types & tree machinery.** The `Node` and
  `ConfigTree` types, their accessors (`Name`, `KeyPath`, `QuotedKeyPath`,
  `quoteKey`, `FindChild`, `FindChildren`, `Clone`, `cloneNodes`), and the
  path-navigation helpers used by `ast_edit.go` / `ast_groups.go`
  (`navigatePath`, `matchNodeKeys`, `navigateToNode`, `findNode`,
  `removeNode`, `insertNode`, `findNodeWithParent`). This is the
  *hierarchical/flat-set AST shape* — the data model the parser produces and
  the compiler consumes. Lines 1–352.

- **Concern B — config-mode `set` schema grammar + completion.** The
  `ValueHint` enum, `SchemaCompletion`, `ValueProvider`, the `schemaNode`
  type, the giant `setSchema` literal, `init()` (groups wildcard wiring),
  and the completion/resolution functions (`CompleteSetPath`,
  `appendTypedValueCompletions`, `CompleteSetPathWithValues`,
  `ResolveConsumedSetPathTokens`). This is the *config-mode grammar SSOT*
  described in `docs/config-schema.md`. Lines 354–1713 + 1728–2021.

**Target (from the issue):** split Concern B out of `ast.go` into a cohesive
`config/` module so the AST node types and the schema grammar/completion
machinery live in separate files. The issue names `config/schema.go` as an
example; that is the choice here because the package already has a
`schema_*` file family — `schema_walk.go` (the validation walker),
`schema_validators.go` (the leaf validators), `value_type.go` (`ValueType`).
The grammar definition (`schemaNode` + `setSchema`) and its completion
surface are the missing member of that family; they currently sit in the
wrong file.

This is intra-package file motion: every symbol involved is package-private
or package-level and stays in `package config`. No import graph changes, no
exported-API changes, no call-site changes outside the moved file.

## 2. Honest scope / value framing

This is a **pure code-motion refactor** of a control-plane (config parsing)
file. There is no hot path, no allocation behaviour, no runtime performance
dimension — this code runs at `commit`/tab-completion time, not per-packet.
The value is exactly what the issue states: get `ast.go` back under the
2000-LOC refactor threshold and put the schema grammar in a file named for
what it is, alongside the other `schema_*` files, so the next contributor
editing the grammar (or the AST shape) opens the right file.

Concrete blast radius (v2, with the `schema_complete.go` split):
- `ast.go`: 2021 → ~373 LOC (drops off the heatmap entirely).
- new `schema.go`: ~1390 LOC — the `schemaNode` type + the `setSchema`
  grammar literal + `init()` + `isTypedLeaf`. This is `[WATCH]` (1500-1999
  is `[WATCH]`; ≥2000 is `[REFACTOR]` per `scripts/refactoring-audit.sh:55`).
  At ~1390 it is actually *below* even the `[WATCH]` floor, so it does not
  appear on the heatmap at all.
- new `schema_complete.go`: ~310 LOC — `ValueHint` enum, `SchemaCompletion`,
  `ValueProvider`, the completion/resolution functions
  (`CompleteSetPath`, `appendTypedValueCompletions`,
  `CompleteSetPathWithValues`, `ResolveConsumedSetPathTokens`). Well under
  threshold.

  Audit-tag note (Codex r1 finding): v1 wrongly called a ~1670 LOC single
  file `[REFACTOR]`; the real threshold is `[REFACTOR]` ≥2000 /
  `[WATCH]` 1500-1999 (`scripts/refactoring-audit.sh:55`,
  `docs/refactoring-audit.md:5`). The v2 two-file split sidesteps the
  question — both files land below the `[WATCH]` floor — which is why both
  Codex and AGY recommended it. The grammar SSOT (`setSchema`) still stays
  whole in one file; only the procedural completion logic separates out,
  exactly mirroring how `schema_walk.go` already separates the walker logic
  from the grammar data.

**If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict.** (Here there is no perf gain at all —
the justification is modularity / threshold compliance / discoverability,
which is the stated purpose of the #1661 refactor backlog. If a reviewer
judges the seam is not real — i.e. AST shape and schema grammar are not
genuinely separable and this is mere file-motion with no conceptual
boundary — that is a legitimate PLAN-KILL.)

## 3. What's already shipped / partially in place

The package already separates schema *behaviour* from the grammar
*definition*, just incompletely:

- `value_type.go` — `ValueType` enum + `Placeholder()` (#1319 PR1 moved it
  here from cmdtree).
- `schema_validators.go` — `LeafValidator` + `ValidateRate` / `ValidateEnum`
  / `ValidateByteSizeOrPercent` / etc.
- `schema_walk.go` — `SchemaValidate` + `walkSchemaChildren` /
  `walkSchemaNode` (the commit-check walker over `setSchema`).

The grammar *definition* itself (`schemaNode`, `setSchema`, `init`) and the
*completion* surface (`CompleteSetPath*`, `ResolveConsumedSetPathTokens`)
are the only schema members still living in `ast.go`. This plan finishes the
family by splitting them across `schema.go` (grammar SSOT) and
`schema_complete.go` (completion/resolution helpers).

## 4. Concrete design

Create two files:

1. `pkg/config/schema.go` (`package config`, imports `strings`) with the
   grammar SSOT moved verbatim from `ast.go`:
   - `schemaNode` struct + all doc comments
   - `isTypedLeaf` method
   - `setSchema` var literal
   - `init()` groups-wildcard wiring
2. `pkg/config/schema_complete.go` (`package config`, imports `fmt`) with the
   completion/resolution helpers moved verbatim from `ast.go`:
   - `ValueHint` type + its `const (...)` block
   - `SchemaCompletion` struct
   - `ValueProvider` type
   - `CompleteSetPath`
   - `appendTypedValueCompletions`
   - `CompleteSetPathWithValues`
   - `ResolveConsumedSetPathTokens`

`ast.go` retains, unchanged:
- `Node` / `ConfigTree` types + accessors (1–140).
- All path-navigation helpers (142–352).
- `keysEqual` (1715–1726).

### Why `keysEqual` stays in `ast.go`

`keysEqual` compares two `[]string` key slices. Its callers are
`ast_edit.go` (5×) and `ast_groups.go` (2×) — both AST-mutation files — and
it is **not** referenced anywhere in Concern B (the completion/grammar code
walks `tokens`/`schema.children`, never compares `Node.Keys` slices). It is
an AST-key helper, so it belongs with the AST node machinery. Verified by
`grep -rn keysEqual pkg/config`: the only callers are ast_edit / ast_groups
/ its own definition.

### File-naming rationale

`schema.go` matches the existing `schema_walk.go` / `schema_validators.go`
naming. An alternative considered — an `ast/` sub-directory — was rejected:
it would force a new package (every `schemaNode`/`setSchema` reference from
`schema_walk.go`, `ast_edit.go`, `value_type.go` is package-private and
would need exporting or an awkward internal package), turning a zero-risk
file move into a wide API change. The issue explicitly offers
`config/schema.go` as the option; that is the low-risk correct one.

## 5. Public API preservation

No exported API changes. Exported symbols that move (still in
`package config`, same signatures, callable identically from
`pkg/cli`, `pkg/grpcapi`, `pkg/cmdtree`, tests):

- `ValueHint` (+ all `ValueHint*` consts)
- `SchemaCompletion`
- `ValueProvider`
- `CompleteSetPath(tokens []string) []string`
- `CompleteSetPathWithValues(tokens []string, provider ValueProvider) []SchemaCompletion`
- `ResolveConsumedSetPathTokens(tokens []string) ([]string, bool)`

Package-private symbols that move (`schemaNode`, `setSchema`, `init`,
`isTypedLeaf`, `appendTypedValueCompletions`) keep their visibility; their
in-package callers (`schema_walk.go`, `ast_edit.go`'s `SetPath`) resolve to
the new file with zero edits because Go has no per-file scoping.

## 6. Hidden invariants the change must preserve

1. **`init()` ordering.** `setSchema`'s package-level initialization and the
   `init()` that wires `groups`→top-level-children must remain in the same
   package. Moving both to `schema.go` keeps them co-located and Go's
   package-init runs all `init()`s after all var initializers regardless of
   file — behaviour is identical. (Risk: if `setSchema` and `init` ended up
   in different files the result would still be correct, but co-locating is
   clearer. They move together.)
2. **Dual AST shape preserved.** This refactor does NOT touch `SetPath`
   (`ast_edit.go`), `walkSchemaNode` (`schema_walk.go`), or any grouping
   logic. The hierarchical (`family inet { dhcp; }` → `Keys:["family","inet"]`
   with children) vs flat-set (`set ... family inet dhcp` →
   `Keys:["family"]` + child `Keys:["inet"]`) duality lives in code that is
   not edited. Grouping keys on `children == nil` / `compoundKey` / `args` —
   none of those fields or the code reading them change.
3. **`setSchema` literal byte-identical.** The move is a cut/paste of the
   literal; no field reordering, no value edits. Golden test
   `TestSetPathGrouping_Golden` (schema_validate_test.go) guards grouping.
4. **No `go:linkname` / build-tag / file-local `//go:` directives** in the
   moved block (verified: none present).

## 7. Risk assessment

| Class | Level | Rationale |
|-------|-------|-----------|
| Behavioral regression | **LOW** | Pure verbatim file motion within one package; no symbol renamed, no logic edited. Go resolves package-private refs across files identically. |
| Lifetime / borrow-checker | **N/A** | Go, no borrow checker. No new allocations or escapes. |
| Performance regression | **N/A** | Control-plane (commit/completion) code; no hot path. No runtime change. |
| Architectural mismatch (#961 / #946-Phase-2) | **LOW** | The seam is a real conceptual boundary (AST data model vs config-mode grammar) already evidenced by the `schema_*` file family. Not a wrong-target rearchitecture. The only mismatch risk is if reviewers judge the boundary illusory → PLAN-KILL. |

## 8. Test plan

No cluster smoke (explicitly stated in the task: control-plane config change,
Go test suite is the gate). Gates, in order:

1. `gofmt -l pkg/config/ast.go pkg/config/schema.go` → empty.
2. `go build ./...` clean.
3. `go vet ./pkg/config/...` clean.
4. **Full Go suite:** `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...`
   — all packages pass.
5. **Targeted config-package suite + flake check:**
   `go test ./pkg/config/... -count=1` plus a 5× loop on the schema/
   completion tests (`TestSetPathGrouping_Golden`, `TestCompleteSetPath*`,
   the schema-walk internal tests).
6. **Flat-set syntax discipline:** confirm the existing flat-set tests use
   `ParseSetCommand()` + `tree.SetPath()` (NOT `NewParser()`) and still pass
   — this refactor adds no new tests because behaviour is unchanged, but the
   move must not perturb them. (If a reviewer wants a belt-and-suspenders
   test that `CompleteSetPathWithValues` still resolves a flat-set path
   identically pre/post move, that is cheap to add — see open question 5.)
7. `make audit-check` after regenerating
   `docs/refactoring-audit-current.txt` — must be clean (ast.go drops below
   2000, schema.go appears).

## 9. Out of scope (explicitly)

- #1701 / #1661 `config/types.go` split (wave-2, serialized AFTER this; same
  package, runs separately — this PR owns `pkg/config` for its duration).
- Any change to `setSchema` content (adding/typing leaves) — that is the
  #1319 PR2..N stream.
- Splitting `schema.go` further (e.g. grammar literal vs completion funcs).
  The grammar tree is one SSOT and stays whole; the completion functions are
  small and naturally co-locate with the tree they walk. A follow-up could
  separate `schema_complete.go` if the file is still flagged, but that is not
  this PR.
- Moving `keysEqual` (stays in ast.go — it is an AST-key helper).

## 10. Open questions for adversarial review

1. **Is the seam real, or is this file-motion theatre?** AST node types
   (data model the parser emits / compiler reads) vs the config-mode grammar
   tree (`setSchema` + completion). The existing `schema_walk.go` /
   `schema_validators.go` / `value_type.go` family already treats schema as a
   separate concern from AST nodes — does putting the grammar *definition*
   with its *walkers/validators/types* finish a real boundary, or is it
   arbitrary? If arbitrary → PLAN-KILL.
2. **Should `keysEqual` move with the schema code instead?** Argument for
   staying: its only callers are AST-mutation files and it compares
   `Node.Keys`. Argument against: it's a generic slice helper. Is leaving it
   in `ast.go` correct, or does it belong in a neutral `helpers.go`?
3. **Should `init()` move to `schema.go` or stay where `setSchema` is
   declared?** It only touches `setSchema`. Co-locating both in `schema.go`
   is proposed. Is there any package-init-order subtlety across files that
   makes this unsafe? (Go spec: var inits across files run in
   dependency/declaration order, then all `init()`s — co-location is safe,
   but confirm.)
4. **Is `schema.go` at ~1670 LOC just relocating the threshold problem?**
   The new file is still `[REFACTOR]`-tagged. Is "the grammar SSOT is one
   data literal and stays whole" a sound justification, or should the
   completion functions split into `schema_complete.go` in this same PR to
   land both files under threshold?
5. **Do we need a new behaviour-preservation test**, or does the existing
   config suite (`TestSetPathGrouping_Golden`, completion tests, schema-walk
   internal tests) already fully cover that the moved completion/grammar code
   behaves identically? Pure motion argues no new test; defense-in-depth
   argues a flat-set `CompleteSetPathWithValues` round-trip assertion.
6. **Any file-local state?** Are there unexported package-level vars/consts
   *other than* `setSchema` that the moved functions read, which live in
   `ast.go` and would now be split from their readers (harmless in Go, but
   worth flagging for cohesion)? (Checked: completion funcs read only
   `setSchema` + their params; no other ast.go-local globals.)
