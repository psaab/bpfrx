# #1319 — Typed leaf-value schema: research plan (post Phase 1/2)

**Status:** PLAN v2.1 (2026-05-29) — research only, no code. v2 folds in
the round-1 reviewer findings: Codex PLAN-NEEDS-MAJOR (5) + Claude SMR
PLAN-NEEDS-MAJOR (D1-D5) + AGY PLAN-READY. Five corrections below
(import-cycle, fields-only/no-children, drop `temporal`, walker contract,
frontend-boundary tests). v2.1 adds the `multi && children==nil`
value-tail/range walker row (Codex r2). Option A stands.
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

**Type ownership (corrected v2 — Codex#1/SMR-D1).** `ValueType` currently
lives in `pkg/cmdtree/tree.go:35` and `pkg/cmdtree` already imports
`pkg/config` (`tree.go:19`). `pkg/config` therefore CANNOT reference
`cmdtree.ValueType` — that is an import cycle. Only `LeafValidator` lives
in `pkg/config` today. So Option A's first PR-1 step is a **mechanical
move**: relocate `ValueType` + its constants + `Placeholder()` from
`pkg/cmdtree/tree.go` into `pkg/config` (next to the validators), and add
`type ValueType = config.ValueType` (+ const re-exports) aliases in
`cmdtree` so its operational-tree leaves are unchanged. After the move,
`schemaNode` can hold a `valueType config.ValueType` field with no cycle.

## 6. Proposed plan (Option A), staged

### PR 1 — Generic walker + completion wiring + reconcile (no new subsystems)

0. **Move `ValueType` to `pkg/config`** (Codex#1/SMR-D1): relocate the
   enum + constants + `Placeholder()` from `pkg/cmdtree/tree.go` into
   `pkg/config`; re-export via `type ValueType = config.ValueType` aliases
   in `cmdtree`. No behavior change; unblocks the cycle.
1. **Add typed-leaf fields to `schemaNode`** (`pkg/config/ast.go`):
   `valueType config.ValueType`, `valueDesc string`,
   `valueExamples []string`, `validator LeafValidator`. Zero values =
   today's behavior. **FIELDS ONLY** — PR 1 MUST NOT add or alter any
   `children` map on a `schemaNode` (Codex#3/SMR-D2). SetPath's
   replace-vs-container decision keys on `children==nil`
   (`ast_edit.go:196`); flipping a `children:nil` leaf to a container is
   a grouping regression. A SetPath grouping golden test (§9) pins this.
2. **Populate the three schedulers leaves** in `setSchema` with the new
   fields only: `transmit-rate` → `ValueRate`/`config.ValidateRate`
   (its `exact` child already exists at `ast.go:1166` — unchanged),
   `priority` → `ValueEnumOf`/`config.ValidateEnum([...])`,
   `buffer-size` → `ValueByteSizeOrPercent`/`config.ValidateByteSizeOrPercent`.
   **Do NOT add `buffer-size temporal`** (Codex#2/SMR-D3): it is in the
   cmdtree overlay (`tree.go:1053`) but the compiler never consumes it
   (`compiler_class_of_service.go` buffer-size case reads only the value).
   Carrying it into `setSchema` would (a) add a `children` map — banned
   by step 1 — and (b) violate the compiled-leaf-only invariant. Modifier
   compiled-status table for schedulers: `exact` = compiled (keep);
   `temporal` = NOT compiled (drop); `surplus-sharing`,
   `equal-flow-enforcement` = presence-only, compiled (no value to type).
3. `CompleteSetPathWithValues`: at the value slot, when the leaf has a
   non-`ValueAny` `valueType`, surface `valueDesc` + `valueExamples` +
   `placeholder` (this is the **symptom-1 fix that actually reaches the
   CLI**). Coexists with the existing `valueHint`/`provider` path
   (`ast.go:1789-1800`) — typed-value examples are additive to dynamic
   provider results.
4. **Generic recursive walker** replacing `walkSchedulers`. Contract
   table (Codex#4/SMR-D4) — the walker descends `setSchema` against the
   AST and must port every special case currently encoded in
   `walkSchedulers` + `CompleteSetPathWithValues` + `SetPath`:

   | schema feature | AST match rule |
   |---|---|
   | `args:0` container | match `Keys[0]==keyword`; recurse into `Children` |
   | `args:N` named instance | consume keyword + N tokens from `Keys` (flat) or 1 key + N from `Keys[1:]` / children (hier); recurse |
   | `compoundKey` | consume the following key as part of this node's key, then resolve the sub-child |
   | `midKeyword`/`midKeywordAt` | the fixed keyword (`to-zone`) sits at arg position `midKeywordAt`; skip it when extracting values |
   | `multi` (with children) | leaf may repeat; validate each occurrence; do not treat as replace |
   | `multi && children==nil` value-tail / range | mirror `SetPath`'s rule (`ast_edit.go:237-244`): if the token after the value is a known sibling keyword the leaf ends and siblings continue; otherwise the remaining tokens are a value-tail under THIS leaf (e.g. `destination-port 20000 to 20003` / compiler shape `destination-port 20000 { to 30000; }`, `compiler_nat.go:682`). For a typed such leaf, validate each value token in the tail per its `valueType` (a range tail `<lo> to <hi>` validates `<lo>` and `<hi>`, treating `to` as the fixed mid-token); do NOT flag the tail as an "unknown modifier" |
   | `wildcard` | instance-name slot; descend into wildcard schema |
   | typed leaf (`valueType!=ValueAny`) | first non-modifier token is THE value → run `validator`; remaining tokens must match child keywords (e.g. `exact`) |
   | modifier-only line | `transmit-rate exact` with no rate still fails (the existing `schedulerHasTypedTransmitRate` gate) |
   | `groups { ... }` | already handled — walker runs on the apply-groups-EXPANDED clone (`store.go:182`), so group bodies are inlined before the walk |

   The walker handles BOTH AST shapes (flat-set `Keys=[a,b,c]` and
   hierarchical `Keys=[a]` + children). It is opt-in: a schema node with
   no `validator` and no typed children is a no-op descent.
5. **Remove the `class-of-service`-only early-return**
   (`schema_validate.go:43-46`): the new walker fans out from the
   `setSchema` root across ALL top-level subtrees. Subtrees with no typed
   leaves cost one shallow descent (acceptable; commit-check is not hot).
   Move `SchemaValidate` into `pkg/config` (it now walks the
   `pkg/config`-owned `setSchema`); update the `pkg/configstore` caller
   (`store.go:182,194`) to `config.SchemaValidate`. Drop the thin cmdtree
   shim or leave a deprecated forwarder — decide in PR 1.
6. **Parity + boundary tests** (Codex#5/SMR-D5):
   - existing `pkg/config/schema_validate_test.go` +
     `pkg/cmdtree/schema_validate_test.go` cases pass against the new
     walker (migrate the cmdtree ones into `pkg/config` as the validator
     moves);
   - **frontend-boundary** completion tests — NOT just the
     `CompleteSetPathWithValues` helper: assert
     `cli.completeConfigWithDesc(["set","class-of-service","schedulers",
     "x","transmit-rate"], "")` AND the gRPC `completeConfigPairs`
     equivalent return `<rate>` + examples, including the trailing-space
     case (`...transmit-rate ` → value slot). This is the exact gap §2.2
     calls out; testing only the helper would repeat the same mistake.
   - **SetPath grouping golden test** asserting flat-set grouping is
     byte-identical before/after PR 1 (guards step 1's fields-only rule).
   - Retire `cmdtree.ConfigClassOfServiceSchedulers` outright (AGY + SMR
     agree — dead code on a non-production path is a false-coverage trap);
     update `pkg/cmdtree/README.md` + CLAUDE.md to state the corrected
     two-SSOT split.
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
  grouping in SetPath, and the replace-vs-container decision keys on
  `children==nil` (`ast_edit.go:196`). Adding *fields* to `schemaNode` is
  additive and safe (AGY verified SetPath reads only
  `args`/`children`/`compoundKey`/`multi`); adding/altering `children` is
  NOT (Codex#3). PR 1 is fields-only and asserts byte-identical SetPath
  grouping via a golden test. This is the main regression surface and why
  Option A edits fields rather than restructuring nodes.
- **Import cycle.** `ValueType` must move from `cmdtree` to `config`
  first (Codex#1); skipping this breaks the build. PR-1 step 0.
- **Compiled-leaf-only drift.** The cmdtree overlay already carries one
  uncompiled modifier (`buffer-size temporal`, Codex#2). The migration
  must drop it, not copy it. Each per-subsystem PR re-checks every leaf
  against the compiler before typing it.
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
