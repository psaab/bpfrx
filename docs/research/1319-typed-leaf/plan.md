# #1319 — Typed leaf-value schema: research plan (post Phase 1/2)

**Status:** PLAN DRAFT v1 (2026-05-29) — research only, no code.
**Branch:** `research/1319-typed-leaf`
**Scope:** decide the architecture for continuing the typed-leaf rollout
after PR #1320 (Phase 1 + schedulers Phase 2, MERGED) and the
PLAN-KILLED Phase 3a (chassis cluster, `refactor/1319-typed-leaf-schema`).

---

## 1. Problem restatement

The issue asks for a typed leaf-value schema driving BOTH:

- **Symptom 1** — `?` completion shows the value type / format / examples
  (`set ... transmit-rate ?` → `<rate>`, examples, `exact`, ...).
- **Symptom 2** — commit-check rejects garbage typed values
  (`transmit-rate asd` → error, not silent coerce-to-0).

## 2. Current state of the codebase (load-bearing findings)

PR #1320 merged Phase 1 + Phase 2. What actually shipped, verified by
reading master:

- **Phase 1 infra (DONE, solid):** `pkg/cmdtree/tree.go` `Node` carries
  `ValueType`, `ValueDesc`, `ValueExamples`, `Validator`. `ValueType`
  enum: `ValueAny`(default), `ValueRate`, `ValueByteSize`,
  `ValueByteSizeOrPercent`, `ValuePercent`, `ValueInteger`,
  `ValueEnumOf`. `Placeholder()` maps each to a `<rate>`-style token.
- **Validators (DONE, reusable):** `pkg/config/schema_validators.go`
  exports `ValidateRate`, `ValidateByteSize`, `ValidateByteSizeOrPercent`,
  `ValidateInteger(min,max)`, `ValidateEnum([]string)`,
  `ValidatePercent(min,max)`. Integer/enum/percent are generic and ready.
- **Commit-check gate (DONE for schedulers only):**
  `pkg/cmdtree/schema_validate.go` `SchemaValidate(tree, cfg)` is called
  from `pkg/configstore/store.go:182,194` on the apply-groups-expanded
  clone BEFORE compile. It currently **early-returns unless
  `class-of-service` exists** (`schema_validate.go:43-46`), then only
  walks `schedulers` via the hand-rolled `walkSchedulers` (2-deep).
- **Typed schedulers leaves (DONE):**
  `cmdtree.ConfigClassOfServiceSchedulers` types `transmit-rate`
  (`ValueRate`), `priority` (`ValueEnumOf`), `buffer-size`
  (`ValueByteSizeOrPercent`).

### 2.1 The dual-tree reality (THE central design fact)

CLAUDE.md and `pkg/cmdtree/README.md` call cmdtree "the single source of
truth" for completion. **For config-mode `set`/`delete`/`show`/`edit`,
this is false today.** There are two parallel trees:

| Tree | Where | Role | Size |
|------|-------|------|------|
| `cmdtree.ConfigTopLevel` + `ConfigClassOfServiceSchedulers` | `pkg/cmdtree/tree.go` | typed-leaf overlay (schedulers + a few `system dataplane` knobs) | sparse |
| `setSchema` (`schemaNode`) | `pkg/config/ast.go:401` | the **actual** structural completion + SetPath grouping tree | ~324 nodes, **~539 `args`-bearing value leaves**, 206 placeholders |

The config-mode completer (`pkg/cli/completion.go:142-158`) routes
`set/delete/show/edit` through `config.CompleteSetPathWithValues`, which
walks **`setSchema`** and **never consults the cmdtree typed leaves**.
`CompleteFromTreeWithDesc` (the function that surfaces
`ValueExamples`/`Placeholder`) is reached by the cmdtree unit tests
(`tree_test.go:130-151`) and by operational-mode (`run`) completion — but
**not** by the live config-mode `set` value completion path.

### 2.2 Consequence: Symptom 1 is effectively STILL OPEN on master

`setSchema`'s schedulers entry (`ast.go:1164-1167`) is:
```go
"schedulers": {args: 1, multi: true, children: map[string]*schemaNode{
    "transmit-rate": {args: 1, children: map[string]*schemaNode{"exact": ...}},
    "priority":    {args: 1, children: nil},
    "buffer-size": {args: 1, children: nil},
```
No `valueHint`, no `placeholder`. So `set ... transmit-rate ?` in the
real CLI returns **nothing** for the value slot — the exact symptom-1
the issue opened on. Phase 2 only closed symptom 2 (validation). **Any
v1 reviewer claiming symptom 1 is fixed is wrong; the test that "proves"
it (tree_test.go:130) exercises a code path the CLI does not use for
`set`.** This must be in the acceptance criteria.

### 2.3 Why Phase 3a was killed

Per the #1319 issue comment (Codex task-mpnhv0ui-j30019 PLAN-NEEDS-MAJOR,
AGY review-mpnhva3y-h1n07y PLAN-KILL): `walkSchedulers` is hand-rolled
for a 2-deep tree and does not generalize to the 5–7-deep chassis-cluster
AST; the `SchemaValidate` early-return on absent class-of-service skips
all other subtrees; AST-shape sketches were wrong; and the Junos numeric
ranges were wrong. Recommended split: (1) generic recursive walker first,
(2) then per-subsystem typed leaves with correct ranges.

## 3. Blast radius (quantified)

- **~539** `args>0` value-consuming leaves in `setSchema` across ~18
  top-level subtrees (`security`, `interfaces`, `routing-options`,
  `policy-options`, `protocols`, `chassis`, `class-of-service`,
  `firewall`, `system`, `services`, `forwarding-options`,
  `routing-instances`, ...).
- **3** of those are typed today (schedulers). So **~536 untyped value
  leaves** remain. "Touch every leaf" = ~536-leaf churn — confirmed
  infeasible as one PR; **incremental per-subsystem is mandatory** and is
  what the issue's own migration plan calls for.
- Most-impactful value types by frequency: integer-with-range,
  enum-of-fixed-set, rate/byte-size, IP/CIDR, identifier-cross-ref
  (forwarding-class, scheduler, zone names).

## 4. Goals / non-goals

**Goals**
- A single recursive walker that validates any typed subtree (kills the
  per-subtree hand-rolled walker problem).
- Wire typed-leaf value completion into the **production config-mode
  `set` completer** so symptom 1 is actually fixed for typed leaves.
- Reconcile the dual-tree so adding a typed leaf is one edit, not two
  trees kept in sync by hand.
- Correct, defensible value validation per migrated subsystem.

**Non-goals (defer)**
- Typing all ~536 leaves in one go.
- Schema-aware show/diff formatters; auto-generated config reference;
  cross-cluster schema versioning (issue "out of scope").
- Cross-reference validators that require compiled `cfg` (forwarding-class
  must exist, etc.) — keep as a later sub-phase; today's compiler already
  does some of these.

## 5. Multiple path options for HOW to attach + reconcile the schema

The issue proposes "extend cmdtree Node". The killed Phase 3a tried to
extend the cmdtree overlay + hand-rolled walker. The real decision is how
to handle the **dual tree** (§2.1). Three viable architectures:

### Option A — Annotate `setSchema` directly (single tree, in pkg/config)

Add `valueType ValueType`, `valueDesc string`, `valueExamples []string`,
`validator LeafValidator` fields to `schemaNode` in `pkg/config/ast.go`.
`CompleteSetPathWithValues` already walks `setSchema` and is the live
completion path — it gains value-slot examples for free. A generic
`SchemaValidate` walks the **same** `setSchema` over the AST. The cmdtree
typed-leaf fields become operational/`run`-only; config-mode typed leaves
live in `setSchema`.

- **Pros:** one tree, the one the CLI already uses; symptom 1 fixed
  inherently (completion path = validation path); generic walker is a
  natural recursion over `schemaNode.children`; no cross-tree sync;
  validators already in `pkg/config` (no import-cycle gymnastics).
- **Cons:** contradicts the "cmdtree is SSOT" doctrine in CLAUDE.md —
  config-mode typed values would live in `pkg/config`, not `pkg/cmdtree`.
  Needs a doctrine-update note. cmdtree's `ConfigClassOfServiceSchedulers`
  would be migrated/retired (small, 3 leaves).
- **Churn:** moderate; concentrated in `pkg/config/ast.go`.

### Option B — Make cmdtree the real SSOT; route `set` completion through it

Build the full config-mode grammar in `cmdtree.ConfigTopLevel`
(today sparse) and switch `pkg/cli/completion.go` + the gRPC completer to
drive `set` completion from cmdtree instead of `setSchema`. `setSchema`
is then derived from (or retired in favor of) cmdtree. Generic walker
lives in cmdtree.

- **Pros:** makes the doctrine true; one place to add a typed leaf.
- **Cons:** **enormous** — `setSchema` is ~324 nodes with `args`,
  `multi`, `midKeyword`, `compoundKey`, `valueHint`, `wildcard`
  semantics that cmdtree's `Node` does not model. Rebuilding the entire
  config grammar in cmdtree AND re-validating SetPath grouping (the
  parser depends on `setSchema` for flat-set token grouping) is a
  multi-PR rewrite with high regression risk on the parser. Out of
  proportion to the issue.

### Option C — Bridge: keep both trees, add a lookup from setSchema leaf → cmdtree typed node

Leave both trees; at the value slot, `CompleteSetPathWithValues` and a
generic `SchemaValidate` look up the consumed `path` in
`cmdtree.ConfigTopLevel` to fetch `ValueType`/`Validator`/examples.

- **Pros:** no migration of existing trees; cmdtree stays the typed-leaf
  home (doctrine-consistent).
- **Cons:** keeps **two trees in sync by hand** for every typed leaf
  (the exact maintainability failure the issue wants to end); the bridge
  must replicate `setSchema`'s arg/midKeyword/compoundKey path-consumption
  to map a path to a cmdtree node — fragile; doubles the per-leaf edit.

### Recommendation (to be tested by reviewers)

**Option A.** It is the only option where the completion path and the
validation path are the same tree (so symptom 1 + symptom 2 are closed
together and cannot drift), the generic walker is a trivial recursion,
and there is no hand-sync. The doctrine cost (config-mode typed values
live in `pkg/config`, not `pkg/cmdtree`) is real but is a documentation
update, and CLAUDE.md's claim is already false for config-mode `set`
today (§2.1) — Option A makes the doctrine *accurate* by stating that
`setSchema` is the config-grammar SSOT and cmdtree is the
operational-tree SSOT, with shared `ValueType`/validator types.

Type definitions (`ValueType`, `LeafValidator`) already live in/near
`pkg/config`; cmdtree aliases them. Option A keeps the enum where the
validators are and lets cmdtree keep aliasing for its operational leaves.

## 6. Proposed plan (Option A), staged

### PR 1 — Generic walker + completion wiring + reconcile (no new subsystems)

1. Add typed-leaf fields to `schemaNode` (`pkg/config/ast.go`):
   `valueType ValueType`, `valueDesc string`, `valueExamples []string`,
   `validator LeafValidator`. Zero values = today's behavior.
2. Populate the **schedulers** leaves in `setSchema` (the 3 already
   typed in cmdtree) with these fields — single source for CoS now.
3. `CompleteSetPathWithValues`: at the value slot, when the leaf has a
   non-`ValueAny` `valueType`, surface `valueDesc` + `valueExamples` +
   `placeholder` (this is the **symptom-1 fix that actually reaches the
   CLI**).
4. Replace `walkSchedulers`/`SchemaValidate` with a **generic recursive
   `validateAST(astNode, schemaNode, path)`** that descends `setSchema`,
   handles all AST shapes (flat-set `Keys=[...]` vs hierarchical
   children), and invokes `validator` at typed leaves. Remove the
   `class-of-service`-only early-return — fan out across all top-level
   subtrees (a subtree with no typed leaves is a no-op walk).
5. Move `SchemaValidate` to `pkg/config` (it now walks `setSchema`, owned
   by `pkg/config`); `pkg/configstore` calls `config.SchemaValidate`.
   Keep a thin `cmdtree.SchemaValidate` shim or update the one caller.
6. **Parity tests:** existing `pkg/cmdtree/schema_validate_test.go` +
   `pkg/config/schema_validate_test.go` cases must pass against the new
   walker. Add a CLI-path test that `set ... transmit-rate ?` returns
   `<rate>` + examples through `CompleteSetPathWithValues` (the gap in
   §2.2). Retire/migrate `cmdtree.ConfigClassOfServiceSchedulers` (note
   it in README so the doctrine is corrected).
7. Docs: `pkg/cmdtree/README.md` + `pkg/config/README.md` +
   `docs/config-schema.md` (new) state the corrected SSOT split and how
   to add a typed leaf (one `setSchema` edit).

**Acceptance for PR 1:**
- `set class-of-service schedulers x transmit-rate ?` returns help with
  `<rate>` + examples + `exact` **through the production CLI completer**.
- `transmit-rate asd` still rejected at commit-check (no regression).
- All 880+ tests pass; the parity tests pin both symptoms.

### PR 2..N — per-subsystem typed leaves (incremental)

Each PR types one subsystem's leaves in `setSchema` with **Junos-vSRX-
correct** ranges and a fixture proving the silent-coerce gap on master.
Suggested ordering by impact + clarity of Junos spec:
- **chassis cluster** (re-do killed Phase 3a with corrected ranges:
  cluster-id 0..15 with MAC-encoding rationale, heartbeat-interval
  1000..2000 or explicit xpf-divergent range w/ rationale + the 30ms lab
  caveat, heartbeat-threshold 3..8, reth-count 1..128, per-RG priority
  1..254, per-RG `hold-down-interval` only if compiled). Gate per-leaf on
  "is this leaf compiled today" (README invariant: do not type a leaf the
  compiler ignores).
- **interfaces** family inet/inet6 address CIDR validation.
- **firewall** filter terms (forwarding-class cross-ref — needs `cfg`).
- **system / services** numeric knobs.

Each subsystem PR: types leaves + adds fixtures + updates that
subsystem's doc. No walker/infra changes after PR 1.

## 7. Hostile questions (answered)

- **Touch every leaf (huge churn)?** No — PR 1 is infra + schedulers
  re-home only; subsystems are independent incremental PRs. ~536 leaves
  stay `ValueAny` and untouched until their subsystem PR.
- **Consistent across local CLI / remote CLI / gRPC?** Yes under Option
  A: all three config-mode completers already call
  `config.CompleteSetPathWithValues` (cli) / the gRPC completer resolves
  the same schema; validation runs in `configstore.compileTree` which is
  the single commit path for all frontends. Under Option C this is the
  weak point (two trees). Verify the gRPC completer path in PR 1.
- **Junos-parity scope (which types matter most)?** integer-with-range
  and enum dominate the ~536 leaves; rate/byte-size/percent already done;
  IP/CIDR and identifier-cross-ref are the next most valuable. Defer
  free-form (`description`, URLs) to permanent `ValueAny`.
- **Does the "compiled-leaf-only" invariant hold?** Yes — keep
  `pkg/cmdtree/README.md:47` invariant: only type a leaf the compiler
  actually consumes, else commit-check rejects config the compiler would
  silently ignore (a behavior change beyond the issue's scope).

## 8. Risks

- **Parser dependency on `setSchema`.** `setSchema` drives flat-set token
  grouping in SetPath. Adding *fields* to `schemaNode` is additive and
  must not change grouping; PR 1 must assert SetPath grouping is
  byte-identical (run full parser test suite). This is the main regression
  surface and why Option A edits fields rather than restructuring nodes.
- **gRPC completer divergence.** Confirm the gRPC `set` completer reaches
  the same value-slot code; add a test.
- **Doctrine churn.** CLAUDE.md says cmdtree is THE SSOT; Option A
  formalizes a two-SSOT split (operational=cmdtree, config-grammar=
  setSchema). Must be documented, not silently contradicted.

## 9. Test plan

- Reuse `pkg/config/schema_validate_test.go` +
  `pkg/cmdtree/schema_validate_test.go` against the generic walker.
- New: CLI-path completion test (`transmit-rate ?` → `<rate>`+examples
  via `CompleteSetPathWithValues`).
- New: SetPath grouping golden test asserting no grouping change.
- Per subsystem PR: fixture showing master silently coerces garbage +
  new walker rejects it.

## 10. Rollout / ordering

PR 1 (infra+walker+wiring+schedulers re-home) → merge → PR 2 chassis
cluster → PR 3 interfaces → PR 4 firewall → ... Each independent,
file-zone disjoint, per-subsystem fixtures.

## 11. Open questions for reviewers

1. Option A vs C: is moving config-mode typed values out of cmdtree into
   `setSchema` acceptable given the SSOT doctrine, or must typed values
   stay in cmdtree (forcing the Option-C bridge / hand-sync)?
2. Is the symptom-1-still-open finding (§2.2) correct — i.e. does any
   production config-mode path consult the cmdtree typed leaves today? If
   a bridge exists that this research missed, Option A's main win shrinks.
3. Should PR 1 retire `cmdtree.ConfigClassOfServiceSchedulers` outright,
   or leave it as dead-but-tested until all CoS leaves move?
