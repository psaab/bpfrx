# #2002 — decompose `pkg/config` parser/AST into `pkg/config/ast/`

**Status:** DRAFT v1 (draft-fanout — NOT yet reviewed by Codex/AGY/Copilot).

This is a PLAN doc only. No code has been written, no production source
touched, no PR opened. The deliverable is this document on the research
branch `research/2002-config-ast-import-cycle`.

---

## 1. Issue framing

`#2002` (refactor-backlog, agy-review-013 Part II.1, peer to #1986–#1990)
asks to decompose the flat parser/AST family in `pkg/config/` into a
dedicated sub-package `pkg/config/ast/`:

```
pkg/config/ast/
  ast.go      # core config-tree node structures
  lexer.go    # lexical analyzer
  parser.go   # recursive-descent parser
  format.go   # pretty printer / serialization
  edit.go     # AST mutable-transaction helpers (+ groups.go)
```

Verified target files + LOC (issue says, confirmed on this branch):
`pkg/config/ast.go` (365), `parser.go` (175), `lexer.go` (258),
`ast_format.go` (527), `ast_edit.go` (386), `ast_groups.go` (300) =
**2011 LOC** across 6 files. The issue's stated intent: *"Behavior-preserving
code motion only. Watch the dual-AST contract … Keep the move mechanical;
no semantic changes."*

**The catch (the entire reason this plan exists).** The issue treats this as
mechanical file motion, identical in spirit to the #1699 split that moved the
schema grammar out of `ast.go`. It is **not** the same, because #1699 kept
everything in `package config` (an intra-package file move, zero import-graph
change — see `docs/pr/1699-config-ast-schema-split/plan.md` §1: *"This is
intra-package file motion … No import graph changes"*). #2002 asks to cross
a **package boundary**, and that boundary cannot be drawn as written without
creating a **guaranteed Go import cycle**:

- `ast_edit.go` (one of the six files slated to move to `pkg/config/ast/`)
  depends on `setSchema` and the `schemaNode` type. These are defined in
  `pkg/config/schema.go` and are **unexported, package-private**, and
  consumed in-package by `schema_complete.go` / `schema_walk.go`. The
  #1891 schema-split header in `schema.go` records the explicit decision
  *"NOT a subpackage, because `setSchema` is unexported and consumed
  in-package … (two-SSOT doctrine, #1319)."* So the schema **stays** in
  `pkg/config`.
- `schema_walk.go` (the validation walker, stays in `pkg/config`) consumes
  AST `*Node` / `*ConfigTree` — i.e. `pkg/config` → would-be
  `pkg/config/ast`.
- Therefore: `pkg/config/ast` (carrying `ast_edit.go`) →
  `setSchema`/`schemaNode` in `pkg/config` → `schema_walk.go` →
  `*Node`/`*ConfigTree` in `pkg/config/ast`. **A → config → A. Cycle.**

The literal layout in the issue compiles to an import cycle on day one. The
real engineering question #2002 forces is: *what is the cycle-free
decomposition, and is it worth the churn?*

## 2. Honest scope / value framing

This is a **pure structural / modularity refactor** of the control-plane
config layer. It touches code that runs at `commit` time and at
tab-completion time — **not** the packet hot path, **not** the dataplane,
**not** allocation behavior, **not** HA/failover/boot decision logic. There
is **no runtime performance dimension whatsoever**: nothing here executes
per-packet, per-session, or per-poll-tick. The value is entirely about
module boundary hygiene and LOC-audit hygiene (the issue is part of a
modularity sweep targeting files over the 2000-LOC audit threshold; the six
files together are 2011 LOC, but individually all six are already well under
2000, so the audit pressure is mild).

Against that mild value sits a real cost: the AST types (`Node`,
`ConfigTree`) are referenced by **129 in-package occurrences across 15
non-test `pkg/config` files** (every compiler aspect file, freetext.go,
tunnelid.go, schema_walk.go) plus **~123 call sites across 4 external
packages** (`pkg/configstore`, `pkg/daemon`, `pkg/dataplane/userspace`,
`pkg/eventengine`) that use `config.ConfigTree` / `config.Node` /
`config.NewParser` / `config.ParseSetCommand` / `config.FormatCompare` /
`config.ParseError`. Moving the types to a sub-package without preserving
the `config.*` names breaks all of them.

> **If reviewers conclude the perf gain / scope is too small to justify the
> churn, PLAN-KILL is acceptable.** This refactor has no performance gain at
> all (it is control-plane code-motion), so the bar is purely "does the
> module boundary improvement justify the cycle-breaking surgery + alias
> surface + ~250 call-site / 15-file blast radius." See §10 self-SMR.

## 3. What's already shipped (precedent + current state)

- **#1699** split the config-mode **schema grammar** (`schemaNode`,
  `setSchema`, completion helpers) out of the then-2021-LOC `ast.go` into
  `schema.go` + `schema_complete.go`, *staying in `package config`*. Plan:
  `docs/pr/1699-config-ast-schema-split/plan.md`. That split is exactly why
  `ast.go` is now only 365 LOC.
- **#1891** further split the schema into per-domain aspect files
  (`schema_security.go`, `schema_interfaces.go`, `schema_routing.go`,
  `schema_system.go`, `schema_chassis.go`, `schema_cos.go`) — again
  deliberately **in-package**, with the header documenting *why a
  sub-package was rejected* (unexported `setSchema`).
- **#1319 two-SSOT doctrine** (`CLAUDE.md`, `docs/config-schema.md`): the
  config-mode `set`/`delete` grammar is owned by `config.setSchema` +
  `config.SchemaValidate`; `SetPath`/`DeletePath` in `ast_edit.go` route
  through `setSchema`. This is the load-bearing coupling that produces the
  cycle.

Current verified dependency facts (this branch, `go build ./pkg/config/`
passes):

| Target file | Imports beyond stdlib? | Cross-file deps inside `pkg/config` |
|---|---|---|
| `lexer.go` | no | **none** — fully self-contained |
| `parser.go` | no | uses only `Lexer` + AST `Node`/`ConfigTree` |
| `ast.go` | no | uses only `quoteKey`/`isIdentChar` (lexer) + own helpers |
| `ast_groups.go` | no | own AST helpers only (`cloneNodes`, `keysEqual`, …) |
| `ast_format.go` | no | own AST helpers + `canonicalOrder` only |
| `ast_edit.go` | no | **`setSchema` + `schemaNode`** ← the back-edge |

No unexported AST helper (`navigatePath`, `cloneNodes`, `keysEqual`,
`canonicalOrder`, `mergeNodes`, …) is referenced from any non-AST,
non-test file in `pkg/config` — verified by grep. The forward edge
(`pkg/config` → AST) is entirely through the **exported** types
`Node`/`ConfigTree` and exported funcs `NewParser`/`ParseSetCommand`/etc.
The single problematic back-edge (AST → `pkg/config`) is `ast_edit.go` →
`setSchema`/`schemaNode`.

## 4. The dependency edges, precisely

```
        ┌────────────────────────── pkg/config (stays) ──────────────────────────┐
        │  schema.go: schemaNode, setSchema (UNEXPORTED)                          │
        │  schema_walk.go: SchemaValidate(*ConfigTree), walk*(*Node)  ───────┐    │
        │  schema_complete.go, value_type.go, freetext.go(*Node), compiler_* │    │
        └────────────────────────────────────────────────────────────────────────┘
                ▲  (back-edge: ast_edit needs setSchema)        │ (fwd-edge:
                │                                                ▼  config needs Node)
        ┌──────────────────── pkg/config/ast (would move) ───────────────────┐
        │  ast.go: Node, ConfigTree, navigate*                                │
        │  lexer.go, parser.go, ast_format.go, ast_groups.go                  │
        │  ast_edit.go: SetPath/DeletePath  → setSchema/schemaNode ───────────┘
        └─────────────────────────────────────────────────────────────────────┘
```

- **Forward edge** (`config` → `ast`): fine, that is the desired direction.
- **Back-edge** (`ast` → `config` via `ast_edit.go`): **the cycle**.

Only `ast_edit.go`'s `SetPath`/`DeletePath`/`deletePath` carry the
back-edge. The other five files (`lexer`, `parser`, `ast`, `ast_format`,
`ast_groups`) are cleanly leaf-ward and could move with zero cycle risk.

## 5. Design — multiple path options

There are three viable cycle-free decompositions, plus the do-nothing
option. Each is described with code-level detail and tradeoffs. The plan's
**recommended path is Option C** (see §10).

### Option A — leaf-primitives sub-package, schema-dependent edit stays put

Move only the **schema-independent** files to `pkg/config/ast/`:
`lexer.go`, `parser.go`, `ast.go`, `ast_format.go`, `ast_groups.go`. Leave
`ast_edit.go`'s schema-driven `SetPath`/`DeletePath` in `pkg/config`
(rename to e.g. `tree_edit.go`), because they need `setSchema`. The
schema-free editing helpers in `ast_edit.go` (`CopyPath`, `RenamePath`,
`InsertBefore`/`InsertAfter`, `insertRelative`) can move with the AST.

- `pkg/config/ast` exports `Node`, `ConfigTree`, `Lexer`, `Parser`,
  `Token*`, `ParseError`, `NewParser`, `ParseSetCommand`, `Format*`,
  `ExpandGroups*`, plus the navigation helpers the in-package edit code
  needs (now exported because they cross the package boundary:
  `FindNodeWithParent`, `InsertNode`, `RemoveNode`, `NavigateToNode`, …).
- `pkg/config` re-exports the public surface as **type aliases** so
  external callers (`configstore`, `daemon`, …) keep using
  `config.ConfigTree` / `config.Node`:
  ```go
  type ConfigTree = ast.ConfigTree
  type Node = ast.Node
  type ParseError = ast.ParseError
  // function re-exports:
  var NewParser = ast.NewParser
  var ParseSetCommand = ast.ParseSetCommand
  var FormatCompare = ast.FormatCompare
  ```
- **Pro:** smallest cycle-breaking surgery; matches the issue's "mechanical
  motion" spirit for 5/6 files; back-edge eliminated by construction.
- **Con:** `ast_edit.go` is **split** — `SetPath`/`DeletePath` (the most
  important editing API, used by every flat-set commit path) stays in
  `config` while sibling editors move to `ast`. This is arguably *worse*
  cohesion than today: the edit family is now spread across two packages.
  Also forces exporting several previously-unexported navigation helpers,
  enlarging the public AST API permanently.

### Option B — schema interface injection (dependency inversion)

Keep all six files together in `pkg/config/ast/`, but break the back-edge
by **inverting** the `SetPath`/`DeletePath` dependency on `setSchema`.
Define a minimal `Schema` interface in `pkg/config/ast` that exposes only
what the path grouping needs (the schema is consulted purely for
args/children/wildcard/compoundKey/multi grouping — never validation):

```go
// in pkg/config/ast
type SchemaLookup interface {
    Child(keyword string) (SchemaLookup, bool) // children[k] or wildcard
    Args() int
    Multi() bool
    CompoundKey() bool
    HasChildren() bool
}
func (t *ConfigTree) SetPath(path []string, schema SchemaLookup) error
func (t *ConfigTree) DeletePath(path []string, schema SchemaLookup) error
```

`pkg/config` then adapts its concrete `*schemaNode` to `SchemaLookup` and
passes it in:

```go
// in pkg/config — schemaNode satisfies the interface via a thin adapter
func SetPath(t *ast.ConfigTree, path []string) error {
    return t.SetPath(path, schemaAdapter{setSchema})
}
```

- **Pro:** keeps the whole edit family cohesive in one sub-package; the AST
  becomes genuinely schema-agnostic (a cleaner abstraction — the AST data
  model should not statically depend on the firewall's grammar SSOT).
- **Con:** changes the **signature** of `SetPath`/`DeletePath`. Currently
  `tree.SetPath(path)` is called package-internally (`ast_edit.go`,
  `schema_walk.go`) and — critically — the CLAUDE.md dual-AST test
  guidance and any external callers use `tree.SetPath(...)`. Every caller
  must now thread the schema. **Interface-method dispatch on the hot
  grouping loop** is a (negligible, control-plane) indirection but a
  behavioral-equivalence risk: `SetPath` walks `schema.children[keyword]`
  and `schema.wildcard` directly today; an interface that returns a fresh
  adapter per call must preserve identity/`nil` semantics exactly (the
  `childSchema == nil` and `childSchema.children == nil` branches are
  load-bearing — see ast_edit.go:151, :196, :244). High behavioral-parity
  burden for a code-motion refactor.

### Option C — full sub-package + a tiny `setSchema` accessor moved with it (RECOMMENDED)

Move all six files to `pkg/config/ast/` AND move the **grouping-only view**
of the schema that `SetPath` needs into `pkg/config/ast` as well — but NOT
the full schema. Concretely: the grouping fields of `schemaNode`
(`args`, `children`, `wildcard`, `multi`, `compoundKey`) are the only
schema fields `ast_edit.go` reads. These grouping fields are **structurally
independent of validation** (`valueType`, `validator`, `treeValidator`,
`keyValidator`, `ValueHint`, etc. are never touched by `SetPath`).

The cleanest cycle-free shape that keeps cohesion:

1. Move `lexer.go`, `parser.go`, `ast.go`, `ast_format.go`,
   `ast_groups.go`, `ast_edit.go` → `pkg/config/ast/`.
2. `ast_edit.go`'s `SetPath`/`DeletePath` take the schema **as a
   parameter** of a type owned by `pkg/config/ast` — same idea as Option B
   but using a **concrete grouping struct** rather than an interface, to
   sidestep the interface-dispatch parity risk:
   ```go
   // pkg/config/ast/group_schema.go
   type GroupSchema struct {
       Args        int
       Children    map[string]*GroupSchema
       Wildcard    *GroupSchema
       Multi       bool
       CompoundKey bool
   }
   ```
   `pkg/config` builds a `*ast.GroupSchema` projection of `setSchema` once
   (a pure, memoized, build-time fold over the existing tree — no per-call
   allocation) and passes it to `SetPath`/`DeletePath`.
3. `pkg/config` re-exports the public surface via type aliases (as in
   Option A) so all ~123 external call sites and the in-package compiler
   files keep using `config.ConfigTree` / `config.Node` unchanged.

- **Pro:** all six files stay together (best cohesion, matches the issue's
  layout intent); back-edge eliminated; AST is fully schema-agnostic; no
  interface-dispatch parity risk (plain struct field reads, same as today);
  the `GroupSchema` projection is a one-time pure fold (no hot-path
  concern). The projection can be **property-tested** to be field-identical
  to `setSchema`'s grouping fields, giving a strong equivalence guarantee.
- **Con:** introduces a *second* representation of the grouping schema
  (`GroupSchema` projection vs `setSchema`), which must be kept in sync —
  but the sync is mechanical and test-guarded (a single fold function +
  a differential test). Slightly more code than Option A, but far better
  cohesion and a cleaner abstraction boundary.

### Option D — do nothing / PLAN-KILL

Decline the move. The six files are each < 600 LOC and already split by
concern; the audit pressure (2011 LOC *collectively*, but no single file
over 2000) is weak; there is no perf or correctness payoff; the cycle
forces non-mechanical surgery that contradicts the issue's "keep it
mechanical" instruction. Record the import-cycle finding on the issue and
close as won't-fix, OR downgrade to a pure intra-package rename (e.g.
`ast_edit.go` → keep, just rename files for clarity) with no package move.

## 6. Public API preservation

External packages (`configstore`, `daemon`, `dataplane/userspace`,
`eventengine`) and all in-package compiler files must keep compiling
unchanged. Preservation strategy for **all** non-kill options:

- **Type aliases** in `pkg/config` for every exported AST type that leaks
  out today: `ConfigTree`, `Node`, `ParseError`, `Token`, `TokenType`,
  `Lexer`, `Parser`. Go type aliases (`type X = ast.X`) are *identical*
  types — method sets, struct literals, and `*config.Node` ↔ `*ast.Node`
  all interoperate, so no external caller changes.
- **Function re-exports** (`var NewParser = ast.NewParser`, etc.) for the
  exported constructors/formatters used externally: `NewParser`,
  `ParseSetCommand`, `NewLexer`, `FormatCompare`, plus the `Token*`
  constants if referenced externally (verify: `pkg/dataplane/userspace`
  and `pkg/configstore` use them).
- **Method-set surface** (`tree.Format()`, `tree.SetPath()`,
  `tree.FormatCompare`, `tree.Clone()`, …) is preserved automatically by
  the alias because methods travel with the underlying `ast.ConfigTree`
  type — EXCEPT where Option B/C change a method signature (`SetPath`).
  For C, the recommendation is to keep a `config.ConfigTree`-level
  convenience wrapper so external `tree.SetPath(path)` callers (if any)
  do not break; verify whether any external caller calls `SetPath`
  directly vs only via configstore.

**Open verification item (becomes an open question):** enumerate the exact
exported AST symbols referenced from each of the 4 external packages and
confirm the alias set is complete (a missing alias is a compile break, not
a runtime bug — caught immediately by `go build ./...`).

## 7. Hidden invariants that must survive

This is control-plane code, so the usual hot-path/byte-order invariants are
**not in play** — but several config-layer invariants are load-bearing:

- **Dual-AST contract (the one the issue explicitly calls out).**
  Hierarchical `family inet { dhcp; }` → `Node{Keys:["family","inet"]}`
  with children; flat `set … family inet dhcp` → nested. The compiler
  handles BOTH. `SetPath`'s grouping (args/children/compoundKey/multi/
  wildcard) is what makes flat-set produce the same tree shape as
  hierarchical parse. Any change to how `SetPath` reads the schema
  (Options B and C) **must** preserve byte-identical tree shapes. This is
  the highest-risk invariant: `pkg/config/dual_ast_differential_test.go`
  exists precisely to guard it and must stay green.
- **`children == nil` replace-vs-container decision** (`ast_edit.go:196`):
  `SetPath` decides "single-value leaf, replace existing" vs "named
  container" purely on `childSchema.children == nil` + `args>0` + `!multi`.
  The #1319 doctrine warns *"a schemaNode MUST NOT gain a children map
  purely to carry typed-leaf metadata."* The `GroupSchema` projection
  (Option C) must reproduce `children == nil` vs non-nil **exactly** —
  including the case where `setSchema` uses `children: nil` explicitly
  (e.g. `apply-groups`).
- **Wildcard + compoundKey grouping** (`ast_edit.go:186`, `:247`):
  `family inet6` compound-key folding and `wildcard`-as-sibling logic must
  be preserved bit-for-bit.
- **`init()` wiring** in `schema.go` sets the `groups` wildcard children
  *after* package init. If the grouping projection (Option C) is built at
  package-init time, it must be built **after** that `init()` runs, or the
  groups-wildcard subtree will be missing. Ordering hazard.
- **Two-SSOT doctrine (#1319)**: completion (`schema_complete.go`),
  validation (`schema_walk.go`), and grouping (`SetPath`) must keep reading
  the *same* schema so they cannot drift. Option C introduces a *projection*
  of the grouping subset — the differential test must prove the projection
  never diverges from `setSchema`'s grouping fields, or the doctrine is
  violated.
- **NOT implicated (state explicitly):** HA/failover ordering, boot-class
  decision logic (`computeBootClass`), hot-path allocation, byte-order /
  native-endian, RETH/VRRP timing — **none** of these touch the AST/parser
  package. This refactor is invisible to the dataplane and to the cluster
  state machine. `make test-failover` is **not** required to prove this
  change (it would only prove unrelated subsystems still work). See §9.

## 8. Risk table (4 classes)

| Class | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| **Correctness** | Dual-AST tree-shape regression from re-plumbing `SetPath`/`DeletePath` schema access (Opt B/C) | Medium | High (silent config mis-grouping → wrong compiled policy) | Keep `dual_ast_differential_test.go` green; add a property test proving `GroupSchema` projection ≡ `setSchema` grouping fields; byte-compare `Format()`/`FormatSet()` round-trips on the full test corpus |
| **Correctness** | Missing type-alias / func re-export → compile break in an external pkg | Low | Low (caught by `go build ./...` immediately) | Enumerate all external symbols first (§6 open item); CI build gate |
| **Build/graph** | A second back-edge discovered mid-implementation (some helper also reaches into `config`) | Low | Medium (forces re-cut of the package boundary) | Pre-implementation grep done (only `ast_edit.go`→`setSchema` found); re-run with `go list -deps` after motion |
| **Maintainability** | `GroupSchema` projection (Opt C) drifts from `setSchema` over time | Medium | Medium (grouping bug introduced by a future schema edit) | Differential test fails the build if projection ≠ schema; document the dual-write in `docs/config-schema.md` |
| **Maintainability** | Exporting previously-private nav helpers (Opt A) permanently enlarges public AST API | Medium (Opt A only) | Low | Prefer Opt C (keeps helpers private by keeping files together) |
| **Scope/process** | Refactor balloons beyond "mechanical motion" the issue asked for | High | Low (process, not runtime) | This plan flags it up front; reviewers decide go/kill on §2 + §10 |

There is **no Performance class row** because there is no hot path. State
this explicitly so reviewers don't expect a perf section.

## 9. Test plan & validation environment

- **Unit / package tests are the entire validation surface.** `go test
  ./pkg/config/...` must stay green — especially
  `dual_ast_differential_test.go`, `parser_ast_test.go`, the
  `schema_validate_*` family, and the round-trip `Format`/`FormatSet`
  tests. These already exercise the dual-AST contract and the
  `SetPath`/`DeletePath` grouping.
- **Full-build gate:** `go build ./...` proves the alias/re-export surface
  is complete (any missing alias is a compile error, not a latent bug).
- **Differential equivalence (new, for Opt B/C):** a property test that
  builds the schema projection / interface adapter and asserts grouping
  decisions are identical to `setSchema` over the entire `setSchema` tree
  (walk every node, compare args/children-nil/wildcard/multi/compoundKey),
  plus a corpus round-trip: parse → `FormatSet` → re-parse via `SetPath` →
  `Format`, byte-compare against today's output on every fixture config.
- **NO loss-cluster lab run needed.** This change does not touch the
  dataplane, HA, VRRP, session sync, or boot path. `make test-failover`
  and the loss userspace cluster would only re-prove unrelated subsystems;
  running them is not a meaningful validation of *this* change and should
  not gate it. (If a reviewer disagrees, the cheapest sanity check is a
  single `cluster-deploy` + `commit`/`rollback`/`show | display set`
  smoke to confirm config-mode still parses end-to-end — but unit tests
  cover this more precisely.)
- **Multi-increment consideration:** the move is naturally splittable. The
  cleanly-leaf files (`lexer`, `parser`, `ast`, `ast_format`,
  `ast_groups`) can move in **increment 1** with zero cycle risk and only
  alias plumbing; `ast_edit.go` (the back-edge file) moves in
  **increment 2** once the schema-projection / inversion lands. This keeps
  each PR small and independently reviewable, and increment 1 alone
  delivers most of the boundary value. See §10 disposition.

## 10. Out of scope

- Any change to the schema grammar SSOT itself (`setSchema` contents,
  typed-leaf validation, completion behavior). This is motion only.
- Touching `pkg/cmdtree` (the *operational* command tree — separate SSOT).
- Splitting the compiler (`compiler_*.go`) or schema aspect files — those
  are #1986–#1990's domain.
- Any dataplane, HA, FRR, or networkd code.
- Performance work (there is none to do here).

## 11. Open questions for adversarial review (>= 5)

1. **Is the cohesion win real, or are we trading one boundary problem for
   another?** Option A splits the edit family across two packages (worse
   cohesion than today). Option C introduces a duplicate grouping-schema
   representation. Does *either* actually improve the codebase, or does the
   import cycle prove the AST and schema are genuinely one module that
   should stay in `package config` (as #1891 already concluded for the
   schema half)? Should the disposition be PLAN-KILL on those grounds?

2. **Exact external alias surface — is it complete and stable?** Which
   precise exported symbols do `pkg/configstore`, `pkg/daemon`,
   `pkg/dataplane/userspace`, `pkg/eventengine` reference
   (`Token`/`TokenType` constants? `ParseError` fields? `Lexer`?), and does
   aliasing them all preserve struct-literal construction and method sets
   exactly? Any symbol where an alias is insufficient (e.g. a const block,
   or a method that must be re-implemented)?

3. **Does any external caller invoke `tree.SetPath(...)` directly** (vs only
   through `configstore`)? If so, Options B/C's signature change leaks past
   the package boundary and the alias trick is not enough — we'd need a
   compatibility wrapper. (Pre-grep suggests `SetPath` is in-package +
   configstore-mediated, but this must be confirmed before committing to a
   signature change.)

4. **`init()` ordering for the grouping projection (Opt C).** The `groups`
   wildcard children are wired in `schema.go`'s `init()`. If we build the
   `*ast.GroupSchema` projection eagerly at init, can we guarantee it runs
   *after* that `init()`? Or must the projection be built lazily on first
   `SetPath` call (and if lazy, is there a concurrency hazard with
   concurrent `commit`s)?

5. **Is the differential test strong enough to catch a drift that breaks
   the dual-AST contract?** The projection (C) or adapter (B) must be
   provably grouping-equivalent to `setSchema` forever. Does walking the
   schema tree and comparing fields actually catch every grouping-relevant
   case (compoundKey folding, explicit `children: nil`, wildcard-as-sibling
   at `ast_edit.go:247`), or are there grouping behaviors that depend on
   schema state the projection wouldn't capture?

6. **Increment boundary correctness.** If increment 1 moves the five leaf
   files but `ast_edit.go` stays in `config` temporarily, does that
   intermediate state compile and stay cycle-free? (It should: `ast_edit`
   in `config` reaching back to `ast` for `Node`/nav helpers is the normal
   forward edge — but the nav helpers it uses (`findNodeWithParent`,
   `insertNode`, etc.) would then need to be exported from `ast` for the
   intermediate state, which may be wasted churn if increment 2 moves
   `ast_edit` back into `ast`. Is the two-increment split actually cheaper
   than a single atomic move?)

---

## Claude self-SMR (hostile)

**Strongest objection to my own plan.** The import cycle is not an
accident of file layout — it is the codebase *telling us* that the AST and
the config-mode schema are a single cohesive module. #1891 already reached
this exact conclusion for the schema half and **deliberately refused a
sub-package** ("NOT a subpackage, because `setSchema` is unexported and
consumed in-package"). #2002 asks to do for the AST half precisely what
#1891 rejected for the schema half, and the only way to make it compile is
to either (a) split the edit family across two packages (Option A — worse
cohesion), (b) change the `SetPath`/`DeletePath` signatures and add
interface-dispatch parity risk to the single most contract-critical config
function (Option B), or (c) introduce a *duplicate* grouping-schema
representation that must be kept in sync forever (Option C). All three add
permanent maintenance surface to break a cycle whose existence is itself
evidence the boundary is wrong. And the payoff is **zero**: no perf, no
correctness, no behavior change — only LOC-audit cosmetics, and none of the
six files is even individually over the 2000-LOC threshold today.

Against that: the counter-argument is that a genuinely schema-agnostic AST
data model is a legitimately cleaner abstraction (the parser's data model
*should not* statically depend on the firewall's grammar), and Option C's
projection is small, pure, and test-guarded. That is real but weak relative
to the churn and the standing #1891 precedent.

**Disposition: LIKELY-DEFER-MULTI-INCREMENT, leaning PLAN-KILL.**

- It is **not** a single mechanical PR as the issue assumes — the import
  cycle makes the literal layout impossible, so the issue's premise
  ("mechanical motion only") is false as written. That alone warrants
  kicking it back for a scope decision.
- If pursued, the **shippable first increment** is: move the five
  cycle-free leaf files (`lexer.go`, `parser.go`, `ast.go`,
  `ast_format.go`, `ast_groups.go`) to `pkg/config/ast/` with full
  `config.*` type-alias preservation, leaving `ast_edit.go` in
  `pkg/config` for a later increment (or permanently). This delivers most
  of the boundary value with zero cycle risk and no `SetPath` signature
  change. Increment 2 (the `ast_edit.go` cycle-break via Option C) is the
  contentious part and should be a separate go/no-go decision.
- **PLAN-KILL is the honest default** if reviewers weigh the #1891
  precedent + zero payoff + permanent maintenance surface and conclude the
  module boundary is correct as-is. The issue should at minimum be
  amended on GitHub to record that the literal layout creates a guaranteed
  import cycle and is not mechanical motion.

**Not LIKELY-DEFER-LAB:** this change is invisible to the dataplane/HA/boot
path; no loss-cluster lab time is warranted. Validation is unit tests +
`go build ./...` only.
