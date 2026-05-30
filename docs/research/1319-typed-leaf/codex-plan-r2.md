OpenAI Codex v0.133.0
--------
workdir: /home/ps/git/bpfrx/.claude/worktrees/1319-research
model: gpt-5.5
provider: openai
approval: never
sandbox: read-only
reasoning effort: xhigh
reasoning summaries: none
session id: 019e770f-7ee4-7832-8eec-06b9b82f4782
--------
user
You are a hostile plan reviewer (HPC networking, OS, data structures, JIT, CPU design, networking protocols, Junos config semantics). RESEARCH ONLY — deliverable is a converged plan, no code. This is round 2: you previously returned PLAN-NEEDS-MAJOR on plan v1 of docs/research/1319-typed-leaf/plan.md with 5 findings. The plan has been revised to v2 (read it now on branch research/1319-typed-leaf).

Your 5 round-1 findings were:
1. Import-cycle: ValueType lives in pkg/cmdtree/tree.go:35, not pkg/config; pkg/config can't ref cmdtree.ValueType.
2. buffer-size temporal (tree.go:1053) is uncompiled — violates compiled-leaf-only invariant.
3. Adding children to schemaNode (e.g. buffer-size) flips SetPath replace->container (ast_edit.go:196).
4. Generic walker underspecified (args/compoundKey/midKeyword/multi/modifier-only).
5. Completion tests must hit production boundary (completeConfigWithDesc/completeConfigPairs), not just CompleteSetPathWithValues.

Verify v2 addresses ALL FIVE correctly. Specifically check:
- PR-1 step 0 moves ValueType to pkg/config with alias-back (does this actually break the cycle? does cmdtree still compile?).
- PR-1 step 1 "FIELDS ONLY, no children" rule + golden test.
- PR-1 step 2 drops temporal with a per-modifier compiled-status table; is exact correctly kept (is exact actually compiled? verify compiler_class_of_service.go).
- PR-1 step 4 walker contract table — is it complete/correct against the real setSchema features?
- PR-1 step 6 frontend-boundary tests.

Do NOT issue PLAN-KILL without a verified counter-example. Cite quoted lines. Verdict: PLAN-READY | PLAN-NEEDS-MAJOR | PLAN-KILL.

codex
I’ll treat this as a hostile design review and verify v2 directly against the code, not against the plan’s assertions. I’m going to read the plan, the current branch state, and the real compiler/edit/completion boundaries before giving a verdict.
exec
/bin/bash -lc "sed -n '1,260p' docs/research/1319-typed-leaf/plan.md" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
# #1319 — Typed leaf-value schema: research plan (post Phase 1/2)

**Status:** PLAN v2 (2026-05-29) — research only, no code. v2 folds in
the round-1 reviewer findings: Codex PLAN-NEEDS-MAJOR (5) + Claude SMR
PLAN-NEEDS-MAJOR (D1-D5) + AGY PLAN-READY. Five corrections below
(import-cycle, fields-only/no-children, drop `temporal`, walker contract,
frontend-boundary tests). Option A stands.
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
   | `multi` | leaf may repeat; validate each occurrence; do not treat as replace |
   | `wildcard` | instance-name slot; descend into wildcard schema |
   | typed leaf (`valueType!=ValueAny`) | first non-modifier token is THE value → run `validator`; remaining tokens must match child keywords (e.g. `exact`) |
   | modifier-only line | `transmit-rate exact` with no rate still fails (the existing `schedulerHasTypedTransmitRate` gate) |
   | `groups { ... }` | already handled — walker runs on the apply-groups-EXPANDED clone (`store.go:182`), so group bodies are inlined before the walk |

   The walker handles BOTH AST shapes (flat-set `Keys=[a,b,c]` and
   hierarchical `Keys=[a]` + children). It is opt-in: a schema node with

exec
/bin/bash -lc "sed -n '260,620p' docs/research/1319-typed-leaf/plan.md" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
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

exec
/bin/bash -lc 'pwd && git status --short --branch && git rev-parse --abbrev-ref HEAD && git rev-parse HEAD' in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
/home/ps/git/bpfrx/.claude/worktrees/1319-research
## research/1319-typed-leaf...origin/master [ahead 3]
research/1319-typed-leaf
86da58533abf6584bc851e126284580cd6aadfab

codex
I’ve confirmed the plan text is v2 on `research/1319-typed-leaf` at `86da585`. Next I’m checking the actual package graph and the relevant parser/compiler/completion code paths, because the important failures here would be mismatches between the plan’s contract table and the real schema behavior.
exec
/bin/bash -lc "nl -ba pkg/cmdtree/tree.go | sed -n '1,130p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
     1	// Package cmdtree defines the canonical CLI command trees for xpf.
     2	//
     3	// This is the SINGLE SOURCE OF TRUTH for all command trees used by:
     4	//   - pkg/cli (local interactive CLI)
     5	//   - pkg/grpcapi (gRPC completion handler)
     6	//   - cmd/cli (remote CLI client)
     7	//
     8	// When adding a new command, add it here and it automatically appears
     9	// in tab completion, ? help, and resolveCommand across all CLIs.
    10	package cmdtree
    11	
    12	import (
    13		"fmt"
    14		"io"
    15		"os"
    16		"sort"
    17		"strings"
    18	
    19		"github.com/psaab/xpf/pkg/config"
    20	)
    21	
    22	// ValueType classifies the value a typed-leaf node accepts. #1319 Phase 1.
    23	//
    24	// The zero value, ValueAny, is the legacy behaviour: any string is accepted
    25	// and no schema-time validation runs. Specifying a non-zero ValueType opts
    26	// the leaf in to:
    27	//   - `?` completion surfacing ValueDesc + ValueExamples for the value slot;
    28	//   - SchemaValidate (pkg/config) invoking the leaf's Validator at commit
    29	//     check, so garbage like `transmit-rate asd` fails loud at commit time
    30	//     instead of silently zeroing out the rate inside the compiler.
    31	//
    32	// Add new types here only when we're prepared to wire validators for every
    33	// leaf that adopts them — IP/CIDR/MAC/duration are deliberately deferred
    34	// (see issue #1319) until the schedulers subtree lands first.
    35	type ValueType int
    36	
    37	const (
    38		// ValueAny is the legacy default: any string accepted, no validation.
    39		ValueAny ValueType = iota
    40		// ValueRate is a Junos bandwidth value (bits/sec) with k/m/g suffix.
    41		// Examples: "100k", "10m", "1g". Accepts plain integers.
    42		ValueRate
    43		// ValueByteSize is a byte-count value with k/m/g suffix.
    44		// Examples: "16k", "1m", "256m".
    45		ValueByteSize
    46		// ValueByteSizeOrPercent is a scheduler buffer size: byte-count with
    47		// k/m/g suffix, or percent with an explicit % suffix.
    48		ValueByteSizeOrPercent
    49		// ValuePercent is a percent value in the range [0, 100] (no suffix).
    50		ValuePercent
    51		// ValueInteger is a bare integer. Range is enforced by the leaf's
    52		// Validator (callers use validateInteger(min,max) to bound it).
    53		ValueInteger
    54		// ValueIdentifier is a bare Junos identifier (no spaces, no quotes).
    55		ValueIdentifier
    56		// ValueEnumOf is one of a fixed set of names. The allowed set lives
    57		// in the leaf's Validator closure (validateEnum).
    58		ValueEnumOf
    59		// ValueBool is "true" or "false".
    60		ValueBool
    61	)
    62	
    63	// Placeholder returns the angle-bracket placeholder name shown in `?`
    64	// completion for an unfilled value slot of this type.
    65	func (v ValueType) Placeholder() string {
    66		switch v {
    67		case ValueRate:
    68			return "<rate>"
    69		case ValueByteSize:
    70			return "<bytes>"
    71		case ValueByteSizeOrPercent:
    72			return "<bytes|percent>"
    73		case ValuePercent:
    74			return "<percent>"
    75		case ValueInteger:
    76			return "<integer>"
    77		case ValueIdentifier:
    78			return "<name>"
    79		case ValueEnumOf:
    80			return "<value>"
    81		case ValueBool:
    82			return "<true|false>"
    83		}
    84		return ""
    85	}
    86	
    87	// LeafValidator is invoked by SchemaValidate (this package) on the raw
    88	// AST value for a typed leaf at commit-check time. cfg is the candidate
    89	// Config (may be nil if SchemaValidate runs on the raw AST before compile).
    90	// Validators must return a nil error for accepted input.
    91	//
    92	// We alias config.LeafValidator (same function signature) so cmdtree
    93	// Nodes can carry validators declared in pkg/config directly. The alias
    94	// avoids a config→cmdtree→config import cycle: validators live in
    95	// config (string parsers), the schema walker lives here (typed-leaf
    96	// dispatch).
    97	type LeafValidator = config.LeafValidator
    98	
    99	// Node defines a completion tree node with description, children, and optional dynamic values.
   100	//
   101	// Phase 1 / #1319: optional typed-leaf fields (ValueType, ValueDesc,
   102	// ValueExamples, Validator) describe the value a leaf accepts. The zero
   103	// value of ValueType is ValueAny — every existing Node is backward
   104	// compatible by construction.
   105	type Node struct {
   106		Desc      string
   107		Children  map[string]*Node
   108		DynamicFn func(cfg *config.Config) []string
   109		// ContextDynamicFn is like DynamicFn but receives the consumed words
   110		// so completions can depend on earlier arguments (e.g. zone pair).
   111		ContextDynamicFn func(cfg *config.Config, words []string) []string
   112	
   113		// ValueType, if set to a non-ValueAny value, marks this node as a
   114		// typed leaf: it accepts exactly one value of the given kind, and
   115		// SchemaValidate (pkg/config) will invoke Validator on the raw
   116		// string at commit-check time.
   117		ValueType ValueType
   118		// ValueDesc is a one-line human description of the value slot
   119		// shown in `?` completion (e.g. "Bandwidth (e.g. 100k, 10m, 1g)").
   120		ValueDesc string
   121		// ValueExamples lists illustrative values surfaced in `?` completion.
   122		// These appear as plain completion candidates so operators can pick
   123		// one. Examples are NOT validated as the only acceptable inputs;
   124		// Validator owns acceptance.
   125		ValueExamples []string
   126		// Validator, if set, is called at SchemaValidate time to accept or
   127		// reject the raw string at this leaf. cfg may be nil.
   128		Validator LeafValidator
   129	}
   130	

exec
/bin/bash -lc "rg -n \"type ValueType|ValueAny|func \\(.*Placeholder|type Node struct|pkg/config|pkg/cmdtree|ConfigClassOfServiceSchedulers|buffer-size|temporal|exact\" pkg/cmdtree pkg/config pkg/configstore pkg/cli -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/configstore/store.go:16:	"github.com/psaab/xpf/pkg/cmdtree"
pkg/configstore/store.go:17:	"github.com/psaab/xpf/pkg/config"
pkg/configstore/db_test.go:8:	"github.com/psaab/xpf/pkg/config"
pkg/configstore/history.go:8:	"github.com/psaab/xpf/pkg/config"
pkg/configstore/crypto.go:20:	"github.com/psaab/xpf/pkg/config"
pkg/configstore/dataplane_retire.go:41:	"github.com/psaab/xpf/pkg/config"
pkg/configstore/dataplane_retire_test.go:8:	"github.com/psaab/xpf/pkg/config"
pkg/configstore/store_test.go:10:	"github.com/psaab/xpf/pkg/config"
pkg/configstore/store_test.go:78:		"class-of-service schedulers be buffer-size 16m",
pkg/configstore/store_test.go:1526:// the cleanup. See pkg/configstore/dataplane_retire.go.
pkg/cli/cli_config.go:10:	"github.com/psaab/xpf/pkg/config"
pkg/configstore/db.go:10:	"github.com/psaab/xpf/pkg/config"
pkg/cli/cli_show_cluster.go:10:	"github.com/psaab/xpf/pkg/cmdtree"
pkg/cli/cli_show_system.go:14:	"github.com/psaab/xpf/pkg/config"
pkg/cli/session_display_test.go:6:	"github.com/psaab/xpf/pkg/config"
pkg/cli/session_display_test.go:91:		{"exact match", "ge-0/0/0", true},
pkg/cli/app_resolve.go:16:	"github.com/psaab/xpf/pkg/config"
pkg/cli/permissions.go:10:	"github.com/psaab/xpf/pkg/config"
pkg/cli/cli_show_shared.go:7:	"github.com/psaab/xpf/pkg/cmdtree"
pkg/cli/cli_show_routing.go:8:	"github.com/psaab/xpf/pkg/cmdtree"
pkg/cli/cli_show_routing.go:9:	"github.com/psaab/xpf/pkg/config"
pkg/cli/cli_show_routing.go:38:	// Optional second arg is a modifier: exact, longer, orlonger
pkg/cli/cli_show_routing.go:43:			case "exact", "longer", "orlonger":
pkg/cli/monitor_interface.go:10:	"github.com/psaab/xpf/pkg/config"
pkg/cli/cli_show_nat.go:11:	"github.com/psaab/xpf/pkg/config"
pkg/cli/session_display.go:8:	"github.com/psaab/xpf/pkg/config"
pkg/cli/completion.go:9:	"github.com/psaab/xpf/pkg/cmdtree"
pkg/cli/completion.go:10:	"github.com/psaab/xpf/pkg/config"
pkg/cli/completion.go:16:// operationalTree references the canonical tree in pkg/cmdtree.
pkg/cli/completion.go:19:// configTopLevel references the canonical config tree in pkg/cmdtree.
pkg/cli/completion.go:186:// - The full command name if exactly one match
pkg/cli/session_filter.go:16:	"github.com/psaab/xpf/pkg/config"
pkg/cli/session_filter.go:227:// It matches the exact name or the parent interface (e.g. filter "ge-0/0/0"
pkg/cli/cli_commit_test.go:11:	"github.com/psaab/xpf/pkg/config"
pkg/cli/cli_commit_test.go:30:		t.Fatalf("applyConfigFn must be called exactly once, got %d", called)
pkg/cli/cli_show_services_test.go:8:	"github.com/psaab/xpf/pkg/configstore"
pkg/cli/cli_show_interfaces.go:11:	"github.com/psaab/xpf/pkg/config"
pkg/cli/cli.go:17:	"github.com/psaab/xpf/pkg/config"
pkg/cli/cli.go:18:	"github.com/psaab/xpf/pkg/configstore"
pkg/cli/cli_show.go:11:	"github.com/psaab/xpf/pkg/cmdtree"
pkg/cmdtree/schema_validate.go:4:// time, BEFORE the existing pkg/config compiler.
pkg/cmdtree/schema_validate.go:16://   - Every other subsystem is on ValueAny by default and skipped by
pkg/cmdtree/schema_validate.go:26:	"github.com/psaab/xpf/pkg/config"
pkg/cmdtree/schema_validate.go:47:	schedRoot := ConfigClassOfServiceSchedulers
pkg/cmdtree/schema_validate.go:114:// in Keys[N+] (flat set form: Keys=["transmit-rate","1g","exact"]) or
pkg/cmdtree/schema_validate.go:155:			if tok == "exact" {
pkg/cmdtree/schema_validate.go:167:// transmit-rate accepts <rate> followed optionally by `exact` — the
pkg/cmdtree/schema_validate.go:168:// chain is [<rate>, "exact"]. priority accepts a single enum value. We
pkg/cmdtree/schema_validate.go:170:// ValueAny) and has a Validator, the first token is the value and the
pkg/cmdtree/schema_validate.go:171:// remainder are matched against children keywords (e.g. "exact").
pkg/cmdtree/schema_validate.go:233:	return leafName == "transmit-rate" && tok == "exact"
pkg/cli/monitor_test.go:117:		t.Fatal("should match exact ports")
pkg/cli/cli_clear.go:11:	"github.com/psaab/xpf/pkg/cmdtree"
pkg/cli/runtime.go:5:// CLI-specific surface that lists exactly the methods pkg/cli/*.go
pkg/cli/runtime.go:17:	"github.com/psaab/xpf/pkg/config"
pkg/cmdtree/schema_validate_test.go:6:	"github.com/psaab/xpf/pkg/config"
pkg/cmdtree/schema_validate_test.go:14:// (pkg/configstore/dataplane_retire.go, invoked from both Store.Load
pkg/cmdtree/schema_validate_test.go:50:		"set class-of-service schedulers be-sched buffer-size 10%",
pkg/cli/cli_helpers.go:11:	"github.com/psaab/xpf/pkg/cmdtree"
pkg/cli/cli_helpers.go:12:	"github.com/psaab/xpf/pkg/config"
pkg/cli/cli_show_security_test.go:8:	"github.com/psaab/xpf/pkg/configstore"
pkg/cmdtree/tree_test.go:6:	"github.com/psaab/xpf/pkg/config"
pkg/cmdtree/tree_test.go:20:	if !contains(cands, "exact") || !contains(cands, "longer") || !contains(cands, "orlonger") {
pkg/cmdtree/tree_test.go:124:	if schedulersNode.Children["<scheduler>"] != ConfigClassOfServiceSchedulers {
pkg/cmdtree/tree_test.go:148:	// should surface the `exact` modifier child.
pkg/cmdtree/tree_test.go:155:	if _, ok := containsCand(cands, "exact"); !ok {
pkg/cmdtree/tree_test.go:156:		t.Fatalf("expected `exact` modifier after consumed rate, got %+v", cands)
pkg/cli/cli_show_security_dispatch.go:15:	"github.com/psaab/xpf/pkg/config"
pkg/cli/apply.go:12:	"github.com/psaab/xpf/pkg/config"
pkg/cli/cli_config_test.go:8:	"github.com/psaab/xpf/pkg/configstore"
pkg/cli/cli_show_services.go:10:	"github.com/psaab/xpf/pkg/cmdtree"
pkg/cli/cli_show_flow.go:13:	"github.com/psaab/xpf/pkg/config"
pkg/cli/cli_show_security.go:12:	"github.com/psaab/xpf/pkg/config"
pkg/configstore/journal.go:11:	"github.com/psaab/xpf/pkg/config"
pkg/cmdtree/tree.go:19:	"github.com/psaab/xpf/pkg/config"
pkg/cmdtree/tree.go:24:// The zero value, ValueAny, is the legacy behaviour: any string is accepted
pkg/cmdtree/tree.go:28://   - SchemaValidate (pkg/config) invoking the leaf's Validator at commit
pkg/cmdtree/tree.go:35:type ValueType int
pkg/cmdtree/tree.go:38:	// ValueAny is the legacy default: any string accepted, no validation.
pkg/cmdtree/tree.go:39:	ValueAny ValueType = iota
pkg/cmdtree/tree.go:65:func (v ValueType) Placeholder() string {
pkg/cmdtree/tree.go:93:// Nodes can carry validators declared in pkg/config directly. The alias
pkg/cmdtree/tree.go:103:// value of ValueType is ValueAny — every existing Node is backward
pkg/cmdtree/tree.go:105:type Node struct {
pkg/cmdtree/tree.go:113:	// ValueType, if set to a non-ValueAny value, marks this node as a
pkg/cmdtree/tree.go:114:	// typed leaf: it accepts exactly one value of the given kind, and
pkg/cmdtree/tree.go:115:	// SchemaValidate (pkg/config) will invoke Validator on the raw
pkg/cmdtree/tree.go:137:// i.e. it expects exactly one typed value at the next slot.
pkg/cmdtree/tree.go:139:	return n.ValueType != ValueAny
pkg/cmdtree/tree.go:242:				"exact":    {Desc: "Exactly match the prefix"},
pkg/cmdtree/tree.go:987:// dataplane <knob>`. Codex M3 / Go F1: the schema in pkg/config/ast.go
pkg/cmdtree/tree.go:1005:// ConfigClassOfServiceSchedulers is the per-leaf typed-value schema for
pkg/cmdtree/tree.go:1010:// pkg/config/compiler_class_of_service.go around lines 227-251):
pkg/cmdtree/tree.go:1011:// transmit-rate (rate, optional `exact` modifier), priority (enum),
pkg/cmdtree/tree.go:1012:// and buffer-size (byte-size with optional `temporal` modifier per Junos).
pkg/cmdtree/tree.go:1016:// The existing pkg/config/ast.go schemaNode tree still answers structural
pkg/cmdtree/tree.go:1024:var ConfigClassOfServiceSchedulers = &Node{
pkg/cmdtree/tree.go:1034:				"exact": {Desc: "Enforce exact transmit rate (no surplus)"},
pkg/cmdtree/tree.go:1046:		"buffer-size": {
pkg/cmdtree/tree.go:1053:				"temporal": {Desc: "Temporal buffer interpretation (Junos)"},
pkg/cmdtree/tree.go:1073:				"<scheduler>": ConfigClassOfServiceSchedulers,
pkg/cmdtree/tree.go:1145:// ResolveUniquePrefix returns the exact item, or a uniquely matching prefix.
pkg/cmdtree/tree.go:1200:				// (e.g. "show route <dest> exact"). Otherwise stay at this
pkg/config/parser_ast_test.go:2690:	// file) so the verbatim retirement text lives in exactly one
pkg/config/parser_ast_test.go:2775:// commit time. Substring match (rather than byte-exact) is used
pkg/config/parser_ast_test.go:2783:// Asserts the exact (substring) retirement message lands.
pkg/cli/cli_show_nat_test.go:7:	"github.com/psaab/xpf/pkg/config"
pkg/config/ast.go:10:type Node struct {
pkg/config/ast.go:1166:				"exact": {children: nil},
pkg/config/ast.go:1169:			"buffer-size":            {args: 1, children: nil},
pkg/config/schema_validate_test.go:4:// lives in pkg/cmdtree (the validators it dispatches to live in
pkg/config/schema_validate_test.go:5:// pkg/config); we exercise it end-to-end through configstore.Commit /
pkg/config/schema_validate_test.go:13:	"github.com/psaab/xpf/pkg/cmdtree"
pkg/config/schema_validate_test.go:14:	"github.com/psaab/xpf/pkg/config"
pkg/config/schema_validate_test.go:82:                exact;
pkg/config/schema_validate_test.go:94:		"set class-of-service schedulers be transmit-rate exact",
pkg/config/schema_validate_test.go:101:	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate exact")
pkg/config/schema_validate_test.go:103:		t.Fatal("expected error for transmit-rate exact without a sibling rate, got nil")
pkg/config/schema_validate_test.go:175:            buffer-size 16m;
pkg/config/schema_validate_test.go:187:            buffer-size 50;
pkg/config/schema_validate_test.go:192:		t.Fatal("expected error for ambiguous bare-integer buffer-size 50, got nil")
pkg/config/schema_validate_test.go:200:            buffer-size 10%;
pkg/config/schema_validate_test.go:212:            buffer-size "12.5%";
pkg/config/schema_validate_test.go:224:            buffer-size purple;
pkg/config/schema_validate_test.go:229:		t.Fatal("expected error for buffer-size purple, got nil")
pkg/config/schema_validate_test.go:234:	err := flatSchemaCheck(t, "set class-of-service schedulers be buffer-size 16m typo")
pkg/config/schema_validate_test.go:236:		t.Fatal("expected error for unknown buffer-size modifier, got nil")
pkg/config/schema_validate_test.go:244:	err := flatSchemaCheck(t, "set class-of-service schedulers be buffer-size")
pkg/config/schema_validate_test.go:246:		t.Fatal("expected error for buffer-size with no value, got nil")
pkg/config/schema_validate_test.go:254:            buffer-size 150;
pkg/config/schema_validate_test.go:259:		t.Fatal("expected error for ambiguous bare-integer buffer-size 150, got nil")
pkg/config/schema_validate_test.go:267:            buffer-size 0%;
pkg/config/schema_validate_test.go:272:		t.Fatal("expected error for zero percent buffer-size, got nil")
pkg/config/schema_validate_test.go:274:	if !strings.Contains(err.Error(), "buffer-size") {
pkg/config/schema_validate_test.go:275:		t.Fatalf("error should reference buffer-size: %v", err)
pkg/config/schema_validate_test.go:296:		"set class-of-service schedulers be buffer-size 16m",
pkg/config/schema_validate_test.go:307:		"set class-of-service schedulers be transmit-rate exact",
pkg/config/schema_validate_test.go:308:		"set class-of-service schedulers be buffer-size 16m",
pkg/config/schema_validate_test.go:334:		t.Fatal("expected transmit-rate exact")
pkg/config/schema_validate_test.go:337:		t.Fatalf("buffer-size bytes = %d, want 16000000", got)
pkg/config/schema_validate_test.go:345:		"set class-of-service schedulers be buffer-size 10%",
pkg/config/schema_validate_test.go:368:		t.Fatalf("buffer-size percent = %v, want 10", got)
pkg/config/schema_validate_test.go:371:		t.Fatalf("buffer-size bytes = %d, want 0 for percent form", got)
pkg/config/schema_validate_test.go:378:	// `buffer-size purple` under a different parent should not error
pkg/config/parser_class_of_service_test.go:20:            buffer-size 16m;
pkg/config/parser_class_of_service_test.go:25:            buffer-size 4m;
pkg/config/parser_class_of_service_test.go:95:		"set class-of-service schedulers be-sched transmit-rate exact",
pkg/config/parser_class_of_service_test.go:97:		"set class-of-service schedulers be-sched buffer-size 8m",
pkg/config/parser_class_of_service_test.go:143:		t.Fatal("expected be-sched transmit-rate exact")
pkg/config/parser_class_of_service_test.go:174:		"set class-of-service schedulers be-sched buffer-size 10%",
pkg/config/parser_class_of_service_test.go:207:		"set class-of-service schedulers be-sched buffer-size 75%",
pkg/config/parser_class_of_service_test.go:208:		"set class-of-service schedulers ef-sched buffer-size 75%",
pkg/config/parser_class_of_service_test.go:224:		t.Fatal("expected aggregate percent buffer-size error, got nil")
pkg/config/parser_class_of_service_test.go:226:	for _, want := range []string{"sum of buffer-size percent", "150", "100"} {
pkg/config/parser_class_of_service_test.go:238:		"set class-of-service schedulers be-sched buffer-size 25%",
pkg/config/parser_class_of_service_test.go:239:		"set class-of-service schedulers ef-sched buffer-size 75%",
pkg/config/parser_class_of_service_test.go:270:			name: "non exact transmit rate",
pkg/config/parser_class_of_service_test.go:277:			name: "exact without positive rate",
pkg/config/parser_class_of_service_test.go:279:				"set class-of-service schedulers ef-sched transmit-rate exact",
pkg/config/parser_class_of_service_test.go:301:			if !strings.Contains(err.Error(), "equal-flow-enforcement requires positive transmit-rate exact") {
pkg/config/parser_class_of_service_test.go:310:		"set class-of-service schedulers ef-sched transmit-rate 10m exact",
pkg/config/parser_class_of_service_test.go:335:// that a scheduler-map whose schedulers' buffer-size percentages sum to more
pkg/config/parser_class_of_service_test.go:341:		"set class-of-service schedulers voice buffer-size 75%",
pkg/config/parser_class_of_service_test.go:342:		"set class-of-service schedulers data buffer-size 75%",
pkg/config/parser_class_of_service_test.go:360:	if !strings.Contains(err.Error(), "sum of buffer-size percent") {
pkg/config/parser_class_of_service_test.go:366:// scheduler-map whose schedulers' buffer-size percentages sum to exactly 100%
pkg/config/parser_class_of_service_test.go:370:		"set class-of-service schedulers voice buffer-size 40%",
pkg/config/parser_class_of_service_test.go:371:		"set class-of-service schedulers data buffer-size 60%",
pkg/config/parser_class_of_service_test.go:393:		"set class-of-service schedulers voice buffer-size 100%",
pkg/config/parser_class_of_service_test.go:442:	if !strings.Contains(err.Error(), "both buffer-size bytes") {
pkg/config/parser_class_of_service_test.go:443:		t.Fatalf("validateClassOfServiceStrict error = %v, want both-buffer-size error", err)
pkg/config/parser_class_of_service_test.go:668:		"set class-of-service schedulers be-sched transmit-rate 5g exact",
pkg/config/parser_class_of_service_test.go:693:		t.Fatal("expected inline transmit-rate exact")
pkg/config/parser_class_of_service_test.go:701:		"set class-of-service schedulers iperf-a transmit-rate exact",
pkg/config/parser_class_of_service_test.go:729:		t.Fatal("expected transmit-rate exact")
pkg/config/parser_class_of_service_test.go:737:		"set class-of-service schedulers iperf-a transmit-rate 1g exact",
pkg/config/parser_class_of_service_test.go:763:		t.Fatal("expected transmit-rate exact")
pkg/config/parser_class_of_service_test.go:778:            transmit-rate 1g exact;
pkg/config/parser_class_of_service_test.go:816:		t.Fatalf("expected exact + surplus-sharing; got exact=%v surplus_sharing=%v",
pkg/config/parser_class_of_service_test.go:822:// without transmit-rate exact (#1183 lesson — runtime never sees
pkg/config/parser_class_of_service_test.go:873:// the sum of exact-class transmit-rates on an interface unit exceeds
pkg/config/parser_class_of_service_test.go:883:		"set class-of-service schedulers iperf-a transmit-rate exact",
pkg/config/parser_class_of_service_test.go:885:		"set class-of-service schedulers iperf-b transmit-rate exact",
pkg/config/parser_class_of_service_test.go:906:	// Sum of exact rates is 21g, shaping is 10g — warning must fire.
pkg/config/parser_class_of_service_test.go:909:		if strings.Contains(w, "sum of exact-class transmit-rates") &&
pkg/config/parser_class_of_service_test.go:929:		"set class-of-service schedulers iperf-a transmit-rate exact",
pkg/config/parser_class_of_service_test.go:931:		"set class-of-service schedulers iperf-b transmit-rate exact",
pkg/config/parser_class_of_service_test.go:955:		if strings.Contains(w, "sum of exact-class transmit-rates") &&
pkg/config/parser_class_of_service_test.go:1307:		"set class-of-service schedulers scheduler-iperf-b transmit-rate exact",
pkg/config/parser_class_of_service_test.go:1309:		"set class-of-service schedulers scheduler-iperf-c transmit-rate exact",
pkg/config/parser_class_of_service_test.go:1404:		"set class-of-service schedulers scheduler-iperf-a transmit-rate exact",
pkg/config/compiler.go:265:	// pkg/configstore/dataplane_retire.go.
pkg/config/compiler.go:429:				"class-of-service scheduler %q equal-flow-enforcement requires positive transmit-rate exact",
pkg/config/compiler.go:437:		// Both buffer-size forms set simultaneously is ambiguous. The compiler
pkg/config/compiler.go:439:		// buffer-size case), so this can only arise in constructed or
pkg/config/compiler.go:444:				"class-of-service scheduler %q has both buffer-size bytes (%d) "+
pkg/config/compiler.go:445:					"and buffer-size percent (%.4g%%) set; use one form only",
pkg/config/compiler.go:452:	// so the runtime never silently over-allocates. A sum of exactly
pkg/config/compiler.go:457:	// round to 99.99000000000001% rather than exactly 99.99%, so the check
pkg/config/compiler.go:479:					"sum of buffer-size percent across all schedulers is %.4g%% "+
pkg/config/compiler.go:914:		// exact schedulers; warn-and-strip when set without exact so
pkg/config/compiler.go:922:					"class-of-service scheduler %q surplus-sharing is meaningful only with transmit-rate exact; ignored",
pkg/config/compiler.go:1051:		// interface unit's exact-class transmit-rates exceeds the
pkg/config/compiler.go:1062:// every CoS interface unit whose sum of exact-class transmit rates
pkg/config/compiler.go:1105:				"class-of-service interfaces %s unit %d: sum of exact-class transmit-rates (%d B/s) exceeds shaping-rate (%d B/s); under oversubscription the configured oversubscription-policy=%s",
pkg/config/parser_security_test.go:2091:                route-filter 192.168.50.0/24 exact;
pkg/config/parser_security_test.go:2092:                route-filter 192.168.99.0/24 exact;
pkg/config/parser_security_test.go:2138:	if term.RouteFilters[0].MatchType != "exact" {
pkg/config/parser_security_test.go:2139:		t.Errorf("match-type: got %q, want exact", term.RouteFilters[0].MatchType)
pkg/config/parser_security_test.go:2151:	cmds := []string{"set policy-options prefix-list mgmt 10.0.0.0/8", "set policy-options prefix-list mgmt 172.16.0.0/12", "set policy-options policy-statement export-policy term t1 from protocol direct", "set policy-options policy-statement export-policy term t1 from route-filter 10.0.0.0/8 exact", "set policy-options policy-statement export-policy term t1 then accept"}
pkg/config/parser_security_test.go:3043:                route-filter 10.0.0.0/8 exact;
pkg/config/compiler_test.go:17://     equal-flow-enforcement` without `transmit-rate exact`
pkg/config/compiler_test.go:66:	// Exactly one '\n' separator because this fixture fires exactly
pkg/config/compiler_test.go:143:	// Byte-identity assertion: errors.Join with exactly one
pkg/config/compiler_test.go:177://   - CoS: equal-flow-enforcement without transmit-rate exact
pkg/config/ast_edit.go:153:			// Skip if exact duplicate already exists.
pkg/config/ast_edit.go:222:				// Flag leaf (args == 0) or multi-value leaf: skip if exact duplicate.
pkg/config/ast_edit.go:251:				// Dedup: skip if exact leaf already exists.
pkg/config/compiler_class_of_service.go:232:				rate, exact := parseCoSTransmitRate(child)
pkg/config/compiler_class_of_service.go:236:				sched.TransmitRateExact = sched.TransmitRateExact || exact
pkg/config/compiler_class_of_service.go:239:			case "buffer-size":
pkg/config/compiler_class_of_service.go:497:	exact := false
pkg/config/compiler_class_of_service.go:499:		if key == "exact" {
pkg/config/compiler_class_of_service.go:500:			exact = true
pkg/config/compiler_class_of_service.go:507:	if node.FindChild("exact") != nil {
pkg/config/compiler_class_of_service.go:508:		exact = true
pkg/config/compiler_class_of_service.go:510:	return rate, exact
pkg/config/compiler_routing.go:545:// "from", "protocol", "direct" or "from", "route-filter", "10.0.0.0/8", "exact"
pkg/config/schema_validators.go:49:// consumes. Reject bare integers here so `buffer-size 50` cannot pass
pkg/config/schema_validators.go:65:// ValidateByteSizeOrPercent accepts the two scheduler buffer-size forms
pkg/config/schema_validators.go:74:			return fmt.Errorf("not a valid percent buffer-size (expected >0%%..100%%; xpf rejects Junos 0%% because zero is the legacy absent-field value): %w", err)
pkg/config/schema_validators.go:103:	// indistinguishable from "no buffer-size configured" -- the runtime
pkg/config/schema_validators.go:108:		return 0, fmt.Errorf("percent out of range (0,100] (got %s); note: 0%% is not supported -- omit buffer-size to use the default burst", orig)
pkg/config/schema_validators.go:132:// names (case-sensitive, exact match).
pkg/config/types.go:342:// EventWithin defines a temporal trigger clause.
pkg/config/types.go:423:	MatchType string // "exact", "longer", "orlonger", "upto"
pkg/config/types.go:508:	// transmit-rate exact queues so they can draw from the root
pkg/config/types.go:513:	// EqualFlowEnforcement opts a positive transmit-rate exact
pkg/config/types.go:516:	// exact with a positive rate and does not also opt into
pkg/config/types.go:557:	// behaviour when sum of exact-class transmit-rates exceeds the
pkg/config/types.go:599:	DataplaneType            string   // empty defaults to "userspace"; explicit "ebpf" is legacy; "dpdk" is retired (#1525) and tolerated via rewriteRetiredDataplaneType (pkg/configstore/dataplane_retire.go) at both Store.Load and Store.SyncApply for stored-config rolling upgrade

exec
/bin/bash -lc "nl -ba pkg/config/ast_edit.go | sed -n '150,230p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   150	
   151			if childSchema == nil {
   152				// No schema match: all remaining tokens form a leaf node.
   153				// Skip if exact duplicate already exists.
   154				remaining := path[i:]
   155				for _, n := range *current {
   156					if n.IsLeaf && keysEqual(n.Keys, remaining) {
   157						return nil
   158					}
   159				}
   160				leaf := &Node{
   161					Keys:   append([]string(nil), remaining...),
   162					IsLeaf: true,
   163				}
   164				*current = append(*current, leaf)
   165				return nil
   166			}
   167	
   168			// Consume keyword + extra args as this node's keys.
   169			nodeKeyCount := 1 + childSchema.args
   170			if i+nodeKeyCount > len(path) {
   171				// Not enough tokens; treat remainder as leaf.
   172				leaf := &Node{
   173					Keys:   append([]string(nil), path[i:]...),
   174					IsLeaf: true,
   175				}
   176				*current = append(*current, leaf)
   177				return nil
   178			}
   179	
   180			nodeKeys := path[i : i+nodeKeyCount]
   181			i += nodeKeyCount
   182	
   183			// Compound key: children form part of the key rather than
   184			// separate hierarchy levels (e.g. "family inet6" is a single
   185			// node with Keys=["family","inet6"], not nested nodes).
   186			if childSchema.compoundKey && i < len(path) {
   187				if sub, ok := childSchema.children[path[i]]; ok {
   188					nodeKeys = append(append([]string(nil), nodeKeys...), path[i])
   189					i++
   190					childSchema = sub
   191				}
   192			}
   193	
   194			if i >= len(path) {
   195				// No more tokens after this node: it's a leaf.
   196				if childSchema.args > 0 && !childSchema.multi && childSchema.children == nil {
   197					// Single-value leaf with no sub-structure (e.g. host-name, description): replace existing.
   198					// Nodes with children are named containers that may appear as terminal leaves
   199					// with different values (e.g. "interface eth0", "interface eth1").
   200					// Replace the first match and remove all subsequent duplicates.
   201					replaced := false
   202					filtered := (*current)[:0] // reuse backing array
   203					for _, n := range *current {
   204						if n.IsLeaf && len(n.Keys) > 0 && n.Keys[0] == nodeKeys[0] {
   205							if !replaced {
   206								filtered = append(filtered, &Node{
   207									Keys:   append([]string(nil), nodeKeys...),
   208									IsLeaf: true,
   209								})
   210								replaced = true
   211							}
   212							// skip all duplicate entries
   213							continue
   214						}
   215						filtered = append(filtered, n)
   216					}
   217					if replaced {
   218						*current = filtered
   219						return nil
   220					}
   221				} else {
   222					// Flag leaf (args == 0) or multi-value leaf: skip if exact duplicate.
   223					for _, n := range *current {
   224						if n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
   225							return nil
   226						}
   227					}
   228				}
   229				leaf := &Node{
   230					Keys:   append([]string(nil), nodeKeys...),

exec
/bin/bash -lc "nl -ba pkg/config/ast.go | sed -n '1,90p;380,430p;1148,1178p;1760,1825p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
     1	package config
     2	
     3	import (
     4		"fmt"
     5		"strings"
     6	)
     7	
     8	// Node represents a node in the Junos configuration tree.
     9	// It is either a leaf (terminated by ;) or a block (containing children in {}).
    10	type Node struct {
    11		// Keys is the sequence of identifiers forming this node's identity.
    12		// Examples:
    13		//   "security" -> ["security"]
    14		//   "security-zone trust" -> ["security-zone", "trust"]
    15		//   "from-zone trust to-zone untrust" -> ["from-zone", "trust", "to-zone", "untrust"]
    16		//   "address 10.0.1.0/24" -> ["address", "10.0.1.0/24"]
    17		Keys []string
    18	
    19		// Children are the nodes within this block's braces.
    20		// nil for leaf nodes.
    21		Children []*Node
    22	
    23		// IsLeaf is true when the node is terminated by ; (no block body).
    24		IsLeaf bool
    25	
    26		// Annotation is a user comment set via the "annotate" command.
    27		Annotation string
    28	
    29		// InheritedFrom is the group name this node was inherited from.
    30		// Set during ExpandGroups when tagInherited is true.
    31		InheritedFrom string
    32	
    33		// Line/Column where this node starts (for error reporting).
    34		Line   int
    35		Column int
    36	}
    37	
    38	// Name returns the first key of the node.
    39	func (n *Node) Name() string {
    40		if len(n.Keys) == 0 {
    41			return ""
    42		}
    43		return n.Keys[0]
    44	}
    45	
    46	// KeyPath returns the full key path as a single string (unquoted).
    47	// Used for map lookups and comparison. For display/format output, use QuotedKeyPath.
    48	func (n *Node) KeyPath() string {
    49		return strings.Join(n.Keys, " ")
    50	}
    51	
    52	// QuotedKeyPath returns the key path with keys quoted if they contain
    53	// characters that aren't valid bare identifiers (e.g. ${node}).
    54	func (n *Node) QuotedKeyPath() string {
    55		parts := make([]string, len(n.Keys))
    56		for i, k := range n.Keys {
    57			parts[i] = quoteKey(k)
    58		}
    59		return strings.Join(parts, " ")
    60	}
    61	
    62	// quoteKey wraps a key in double quotes if it contains characters that
    63	// are not valid in bare Junos identifiers.
    64	func quoteKey(s string) string {
    65		if s == "" {
    66			return `""`
    67		}
    68		for i := 0; i < len(s); i++ {
    69			if !isIdentChar(s[i]) {
    70				// Escape any internal quotes.
    71				return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
    72			}
    73		}
    74		return s
    75	}
    76	
    77	// FindChild returns the first child whose first key matches name.
    78	func (n *Node) FindChild(name string) *Node {
    79		for _, child := range n.Children {
    80			if len(child.Keys) > 0 && child.Keys[0] == name {
    81				return child
    82			}
    83		}
    84		return nil
    85	}
    86	
    87	// FindChildren returns all children whose first key matches name.
    88	func (n *Node) FindChildren(name string) []*Node {
    89		var result []*Node
    90		for _, child := range n.Children {
   380	// The path parameter provides consumed tokens for context (e.g., interface name for unit completion).
   381	type ValueProvider func(hint ValueHint, path []string) []SchemaCompletion
   382	
   383	// schemaNode defines a container keyword in the Junos config hierarchy.
   384	// It tells SetPath how to group flat path tokens into the correct tree structure.
   385	type schemaNode struct {
   386		args         int                    // extra tokens consumed as part of this node's key
   387		children     map[string]*schemaNode // known container children
   388		wildcard     *schemaNode            // matches any keyword not in children (for dynamic names)
   389		multi        bool                   // true = multiple leaf values allowed (e.g. source-address); false = replace on set
   390		valueHint    ValueHint              // hint for dynamic value completion (when args > 0)
   391		desc         string                 // description shown in completion help
   392		placeholder  string                 // Junos-style placeholder (e.g., "<interface-name>")
   393		midKeyword   string                 // fixed keyword in the middle of args (e.g., "to-zone")
   394		midKeywordAt int                    // 1-based arg position where midKeyword appears (e.g., 2 for "from-zone X to-zone Y")
   395		compoundKey  bool                   // children form compound key (e.g., "family inet6" → Keys=["family","inet6"])
   396	}
   397	
   398	// setSchema defines the Junos configuration tree structure.
   399	// Keywords present in the schema at a given depth are treated as containers.
   400	// Keywords NOT in the schema become leaf nodes (all remaining tokens form the leaf's Keys).
   401	var setSchema = &schemaNode{children: map[string]*schemaNode{
   402		"groups":       {wildcard: &schemaNode{}}, // children set in init()
   403		"apply-groups": {args: 1, multi: true, children: nil},
   404		"security": {desc: "Security configuration", children: map[string]*schemaNode{
   405			"zones": {desc: "Security zones", children: map[string]*schemaNode{
   406				"security-zone": {desc: "Security zone name", args: 1, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: map[string]*schemaNode{
   407					"description": {desc: "Zone description", args: 1, placeholder: "<text>", children: nil},
   408					"interfaces":  {desc: "Interfaces in this zone", children: nil},
   409					"tcp-rst":     {desc: "Send TCP RST for denied traffic", children: nil},
   410					"screen":      {desc: "Screen profile name", args: 1, placeholder: "<screen-name>", children: nil},
   411					"host-inbound-traffic": {desc: "Host inbound traffic", children: map[string]*schemaNode{
   412						"system-services": {desc: "System services", children: nil},
   413						"protocols":       {desc: "Protocols", children: nil},
   414					}},
   415				}},
   416			}},
   417			"policies": {desc: "Security policies", children: map[string]*schemaNode{
   418				"from-zone": {desc: "From zone", args: 3, valueHint: ValueHintZoneName, midKeyword: "to-zone", midKeywordAt: 2, placeholder: "<zone-name>", children: map[string]*schemaNode{
   419					"policy": {desc: "Policy name", args: 1, valueHint: ValueHintPolicyName, placeholder: "<policy-name>", children: map[string]*schemaNode{
   420						"description": {desc: "Policy description", args: 1, placeholder: "<text>", children: nil},
   421						"match": {desc: "Match criteria", children: map[string]*schemaNode{
   422							"source-address":      {desc: "Source address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
   423							"destination-address": {desc: "Destination address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
   424							"application":         {desc: "Application", args: 1, multi: true, valueHint: ValueHintPolicyApp, placeholder: "<application>", children: nil},
   425						}},
   426						"then": {desc: "Action", children: map[string]*schemaNode{
   427							"log": {desc: "Log session", children: nil},
   428							// permit, deny, reject, count → leaf
   429						}},
   430					}},
  1148						"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
  1149							"code-points": {args: 1, multi: true, children: nil},
  1150						}},
  1151					}},
  1152				}},
  1153			}},
  1154			"rewrite-rules": {children: map[string]*schemaNode{
  1155				"dscp": {args: 1, multi: true, children: map[string]*schemaNode{
  1156					"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
  1157						"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
  1158							"code-point":  {args: 1, children: nil},
  1159							"code-points": {args: 1, multi: true, children: nil},
  1160						}},
  1161					}},
  1162				}},
  1163			}},
  1164			"schedulers": {args: 1, multi: true, children: map[string]*schemaNode{
  1165				"transmit-rate": {args: 1, children: map[string]*schemaNode{
  1166					"exact": {children: nil},
  1167				}},
  1168				"priority":               {args: 1, children: nil},
  1169				"buffer-size":            {args: 1, children: nil},
  1170				"surplus-sharing":        {children: nil}, // #915
  1171				"equal-flow-enforcement": {children: nil},
  1172			}},
  1173			"scheduler-maps": {args: 1, multi: true, children: map[string]*schemaNode{
  1174				"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
  1175					"scheduler": {args: 1, children: nil},
  1176				}},
  1177			}},
  1178			"interfaces": {args: 1, multi: true, children: map[string]*schemaNode{
  1760				if sub, ok := childSchema.children[tokens[i]]; ok {
  1761					path = append(path, tokens[i])
  1762					i++
  1763					childSchema = sub
  1764				}
  1765			}
  1766	
  1767			if i > len(tokens) {
  1768				// Still consuming args for this node — user needs to type a value.
  1769				startIdx := i - nodeKeyCount
  1770				consumed := end - startIdx // tokens consumed for this node (including keyword)
  1771	
  1772				// Check for fixed keyword in the middle of args (e.g., "to-zone" in "from-zone X to-zone Y").
  1773				if childSchema.midKeyword != "" && childSchema.midKeywordAt > 0 {
  1774					nextPos := consumed // 0-indexed position to complete next (0=keyword, 1=arg1, ...)
  1775					// If the last consumed token is a partial match for the midKeyword, suggest it.
  1776					if nextPos == childSchema.midKeywordAt+1 && consumed > 1 {
  1777						lastToken := tokens[end-1]
  1778						if lastToken != childSchema.midKeyword && strings.HasPrefix(childSchema.midKeyword, lastToken) {
  1779							return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}
  1780						}
  1781					}
  1782					// If we need to complete the midKeyword position, suggest it.
  1783					if nextPos == childSchema.midKeywordAt {
  1784						return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}
  1785					}
  1786				}
  1787	
  1788				// Try to provide dynamic values via the provider.
  1789				if provider != nil && childSchema.valueHint != ValueHintNone {
  1790					results := provider(childSchema.valueHint, path)
  1791					// Add placeholder if available.
  1792					if childSchema.placeholder != "" {
  1793						results = append([]SchemaCompletion{{Name: childSchema.placeholder, Desc: childSchema.desc}}, results...)
  1794					}
  1795					return results
  1796				}
  1797				// No provider but have a placeholder — show it.
  1798				if childSchema.placeholder != "" {
  1799					return []SchemaCompletion{{Name: childSchema.placeholder, Desc: childSchema.desc}}
  1800				}
  1801				return nil
  1802			}
  1803	
  1804			if childSchema.multi && childSchema.children == nil {
  1805				// Stay at current schema level so sibling keywords are offered.
  1806			} else {
  1807				schema = childSchema
  1808			}
  1809		}
  1810	
  1811		// We've consumed all tokens. Return child keywords at this schema level.
  1812		if schema == nil {
  1813			return nil
  1814		}
  1815	
  1816		// If we're at a leaf with no children/wildcard, hint that Enter completes.
  1817		if schema.children == nil && schema.wildcard == nil {
  1818			return []SchemaCompletion{{Name: "<[Enter]>", Desc: "Execute this command"}}
  1819		}
  1820	
  1821		var completions []SchemaCompletion
  1822		if schema.children != nil {
  1823			for name, node := range schema.children {
  1824				completions = append(completions, SchemaCompletion{Name: name, Desc: node.desc})
  1825			}

exec
/bin/bash -lc "nl -ba pkg/config/ast.go | sed -n '1700,1865p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
  1700			keyword := tokens[i]
  1701	
  1702			// Look up keyword in current schema level.
  1703			var childSchema *schemaNode
  1704			resolvedKeyword := keyword
  1705			if schema.children != nil {
  1706				if s, ok := schema.children[keyword]; ok {
  1707					childSchema = s
  1708				} else {
  1709					var matches []string
  1710					for name := range schema.children {
  1711						if strings.HasPrefix(name, keyword) {
  1712							matches = append(matches, name)
  1713						}
  1714					}
  1715					if len(matches) == 1 && i < len(tokens)-1 {
  1716						resolvedKeyword = matches[0]
  1717						childSchema = schema.children[resolvedKeyword]
  1718					} else if len(matches) > 0 && i == len(tokens)-1 {
  1719						var completions []SchemaCompletion
  1720						for _, name := range matches {
  1721							completions = append(completions, SchemaCompletion{Name: name, Desc: schema.children[name].desc})
  1722						}
  1723						return completions
  1724					}
  1725				}
  1726			}
  1727			if childSchema == nil && schema.wildcard != nil {
  1728				childSchema = schema.wildcard
  1729			}
  1730			if childSchema == nil {
  1731				// Last token might be a partial prefix — return matching keywords.
  1732				if i == len(tokens)-1 && schema.children != nil {
  1733					var matches []SchemaCompletion
  1734					for name, node := range schema.children {
  1735						if strings.HasPrefix(name, keyword) {
  1736							matches = append(matches, SchemaCompletion{Name: name, Desc: node.desc})
  1737						}
  1738					}
  1739					if len(matches) > 0 {
  1740						return matches
  1741					}
  1742				}
  1743				return nil // unknown keyword, no completions
  1744			}
  1745	
  1746			// Consume keyword + extra args.
  1747			nodeKeyCount := 1 + childSchema.args
  1748			end := i + nodeKeyCount
  1749			if end > len(tokens) {
  1750				end = len(tokens)
  1751			}
  1752			path = append(path, resolvedKeyword)
  1753			if end-i > 1 {
  1754				path = append(path, tokens[i+1:end]...)
  1755			}
  1756			i += nodeKeyCount
  1757	
  1758			// Compound key: consume child token as part of key.
  1759			if childSchema.compoundKey && i < len(tokens) {
  1760				if sub, ok := childSchema.children[tokens[i]]; ok {
  1761					path = append(path, tokens[i])
  1762					i++
  1763					childSchema = sub
  1764				}
  1765			}
  1766	
  1767			if i > len(tokens) {
  1768				// Still consuming args for this node — user needs to type a value.
  1769				startIdx := i - nodeKeyCount
  1770				consumed := end - startIdx // tokens consumed for this node (including keyword)
  1771	
  1772				// Check for fixed keyword in the middle of args (e.g., "to-zone" in "from-zone X to-zone Y").
  1773				if childSchema.midKeyword != "" && childSchema.midKeywordAt > 0 {
  1774					nextPos := consumed // 0-indexed position to complete next (0=keyword, 1=arg1, ...)
  1775					// If the last consumed token is a partial match for the midKeyword, suggest it.
  1776					if nextPos == childSchema.midKeywordAt+1 && consumed > 1 {
  1777						lastToken := tokens[end-1]
  1778						if lastToken != childSchema.midKeyword && strings.HasPrefix(childSchema.midKeyword, lastToken) {
  1779							return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}
  1780						}
  1781					}
  1782					// If we need to complete the midKeyword position, suggest it.
  1783					if nextPos == childSchema.midKeywordAt {
  1784						return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}
  1785					}
  1786				}
  1787	
  1788				// Try to provide dynamic values via the provider.
  1789				if provider != nil && childSchema.valueHint != ValueHintNone {
  1790					results := provider(childSchema.valueHint, path)
  1791					// Add placeholder if available.
  1792					if childSchema.placeholder != "" {
  1793						results = append([]SchemaCompletion{{Name: childSchema.placeholder, Desc: childSchema.desc}}, results...)
  1794					}
  1795					return results
  1796				}
  1797				// No provider but have a placeholder — show it.
  1798				if childSchema.placeholder != "" {
  1799					return []SchemaCompletion{{Name: childSchema.placeholder, Desc: childSchema.desc}}
  1800				}
  1801				return nil
  1802			}
  1803	
  1804			if childSchema.multi && childSchema.children == nil {
  1805				// Stay at current schema level so sibling keywords are offered.
  1806			} else {
  1807				schema = childSchema
  1808			}
  1809		}
  1810	
  1811		// We've consumed all tokens. Return child keywords at this schema level.
  1812		if schema == nil {
  1813			return nil
  1814		}
  1815	
  1816		// If we're at a leaf with no children/wildcard, hint that Enter completes.
  1817		if schema.children == nil && schema.wildcard == nil {
  1818			return []SchemaCompletion{{Name: "<[Enter]>", Desc: "Execute this command"}}
  1819		}
  1820	
  1821		var completions []SchemaCompletion
  1822		if schema.children != nil {
  1823			for name, node := range schema.children {
  1824				completions = append(completions, SchemaCompletion{Name: name, Desc: node.desc})
  1825			}
  1826		}
  1827		// If this level accepts a wildcard name, provide dynamic values too.
  1828		if schema.wildcard != nil {
  1829			if provider != nil && schema.wildcard.valueHint != ValueHintNone {
  1830				completions = append(completions, provider(schema.wildcard.valueHint, path)...)
  1831			}
  1832			// Add placeholder.
  1833			if schema.wildcard.placeholder != "" {
  1834				completions = append(completions, SchemaCompletion{Name: schema.wildcard.placeholder, Desc: schema.wildcard.desc})
  1835			}
  1836		}
  1837		if len(completions) == 0 {
  1838			return nil
  1839		}
  1840		return completions
  1841	}
  1842	
  1843	// ResolveConsumedSetPathTokens expands uniquely matching keyword prefixes in a
  1844	// token list that is already known to contain only consumed words, not the
  1845	// current partial token being completed.
  1846	func ResolveConsumedSetPathTokens(tokens []string) ([]string, bool) {
  1847		schema := setSchema
  1848		i := 0
  1849		var resolved []string
  1850	
  1851		for i < len(tokens) {
  1852			if schema == nil {
  1853				return nil, false
  1854			}
  1855	
  1856			keyword := tokens[i]
  1857			resolvedKeyword := keyword
  1858			var childSchema *schemaNode
  1859			if schema.children != nil {
  1860				if s, ok := schema.children[keyword]; ok {
  1861					childSchema = s
  1862				} else {
  1863					var matches []string
  1864					for name := range schema.children {
  1865						if strings.HasPrefix(name, keyword) {

exec
/bin/bash -lc "nl -ba pkg/config/ast_edit.go | sed -n '90,330p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 1ms:
    90			if c == elem {
    91				elemIdx = i
    92				break
    93			}
    94		}
    95		if elemIdx < 0 {
    96			return fmt.Errorf("element not found in parent")
    97		}
    98		*parentChildren = append((*parentChildren)[:elemIdx], (*parentChildren)[elemIdx+1:]...)
    99	
   100		// Find the reference's new index (may have shifted after removal).
   101		refIdx := -1
   102		for i, c := range *parentChildren {
   103			if c == refNode {
   104				refIdx = i
   105				break
   106			}
   107		}
   108		if refIdx < 0 {
   109			return fmt.Errorf("reference not found in parent")
   110		}
   111	
   112		// Insert before or after the reference.
   113		insertAt := refIdx
   114		if after {
   115			insertAt = refIdx + 1
   116		}
   117	
   118		// Grow and shift.
   119		*parentChildren = append(*parentChildren, nil)
   120		copy((*parentChildren)[insertAt+1:], (*parentChildren)[insertAt:])
   121		(*parentChildren)[insertAt] = elem
   122		return nil
   123	}
   124	
   125	// SetPath inserts a leaf node at the given path in the tree.
   126	// Intermediate block nodes are created as needed. The schema determines
   127	// which keywords are containers (and how many extra args they consume)
   128	// versus leaves (all remaining tokens form the leaf's Keys).
   129	func (t *ConfigTree) SetPath(path []string) error {
   130		if len(path) == 0 {
   131			return fmt.Errorf("empty path")
   132		}
   133	
   134		current := &t.Children
   135		schema := setSchema
   136		i := 0
   137	
   138		for i < len(path) {
   139			keyword := path[i]
   140	
   141			// Look up keyword in current schema level.
   142			var childSchema *schemaNode
   143			if schema != nil {
   144				if s, ok := schema.children[keyword]; ok {
   145					childSchema = s
   146				} else if schema.wildcard != nil {
   147					childSchema = schema.wildcard
   148				}
   149			}
   150	
   151			if childSchema == nil {
   152				// No schema match: all remaining tokens form a leaf node.
   153				// Skip if exact duplicate already exists.
   154				remaining := path[i:]
   155				for _, n := range *current {
   156					if n.IsLeaf && keysEqual(n.Keys, remaining) {
   157						return nil
   158					}
   159				}
   160				leaf := &Node{
   161					Keys:   append([]string(nil), remaining...),
   162					IsLeaf: true,
   163				}
   164				*current = append(*current, leaf)
   165				return nil
   166			}
   167	
   168			// Consume keyword + extra args as this node's keys.
   169			nodeKeyCount := 1 + childSchema.args
   170			if i+nodeKeyCount > len(path) {
   171				// Not enough tokens; treat remainder as leaf.
   172				leaf := &Node{
   173					Keys:   append([]string(nil), path[i:]...),
   174					IsLeaf: true,
   175				}
   176				*current = append(*current, leaf)
   177				return nil
   178			}
   179	
   180			nodeKeys := path[i : i+nodeKeyCount]
   181			i += nodeKeyCount
   182	
   183			// Compound key: children form part of the key rather than
   184			// separate hierarchy levels (e.g. "family inet6" is a single
   185			// node with Keys=["family","inet6"], not nested nodes).
   186			if childSchema.compoundKey && i < len(path) {
   187				if sub, ok := childSchema.children[path[i]]; ok {
   188					nodeKeys = append(append([]string(nil), nodeKeys...), path[i])
   189					i++
   190					childSchema = sub
   191				}
   192			}
   193	
   194			if i >= len(path) {
   195				// No more tokens after this node: it's a leaf.
   196				if childSchema.args > 0 && !childSchema.multi && childSchema.children == nil {
   197					// Single-value leaf with no sub-structure (e.g. host-name, description): replace existing.
   198					// Nodes with children are named containers that may appear as terminal leaves
   199					// with different values (e.g. "interface eth0", "interface eth1").
   200					// Replace the first match and remove all subsequent duplicates.
   201					replaced := false
   202					filtered := (*current)[:0] // reuse backing array
   203					for _, n := range *current {
   204						if n.IsLeaf && len(n.Keys) > 0 && n.Keys[0] == nodeKeys[0] {
   205							if !replaced {
   206								filtered = append(filtered, &Node{
   207									Keys:   append([]string(nil), nodeKeys...),
   208									IsLeaf: true,
   209								})
   210								replaced = true
   211							}
   212							// skip all duplicate entries
   213							continue
   214						}
   215						filtered = append(filtered, n)
   216					}
   217					if replaced {
   218						*current = filtered
   219						return nil
   220					}
   221				} else {
   222					// Flag leaf (args == 0) or multi-value leaf: skip if exact duplicate.
   223					for _, n := range *current {
   224						if n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
   225							return nil
   226						}
   227					}
   228				}
   229				leaf := &Node{
   230					Keys:   append([]string(nil), nodeKeys...),
   231					IsLeaf: true,
   232				}
   233				*current = append(*current, leaf)
   234				return nil
   235			}
   236	
   237			// More tokens follow. If the schema says this is a multi-value leaf
   238			// with no children AND the next token is a known sibling keyword,
   239			// add it as a leaf and continue at the same level so remaining
   240			// tokens become siblings (e.g. "match" children:
   241			// destination-address any source-address any application any).
   242			// If the next token is NOT a known sibling, the remaining tokens
   243			// are trailing values for this leaf (e.g. "destination-port 20000 to 20003").
   244			if childSchema.children == nil && childSchema.multi && i < len(path) {
   245				nextToken := path[i]
   246				_, nextIsSibling := schema.children[nextToken]
   247				if !nextIsSibling && schema.wildcard != nil {
   248					nextIsSibling = true
   249				}
   250				if nextIsSibling {
   251					// Dedup: skip if exact leaf already exists.
   252					dup := false
   253					for _, n := range *current {
   254						if n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
   255							dup = true
   256							break
   257						}
   258					}
   259					if !dup {
   260						*current = append(*current, &Node{
   261							Keys:   append([]string(nil), nodeKeys...),
   262							IsLeaf: true,
   263						})
   264					}
   265					// Don't descend — continue at same level for next sibling.
   266					continue
   267				}
   268			}
   269	
   270			// This is a container (or a leaf with trailing value tokens).
   271			// Find or create matching node.
   272			found := false
   273			for _, n := range *current {
   274				if !n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
   275					current = &n.Children
   276					found = true
   277					break
   278				}
   279			}
   280			if !found {
   281				newNode := &Node{
   282					Keys: append([]string(nil), nodeKeys...),
   283				}
   284				*current = append(*current, newNode)
   285				current = &newNode.Children
   286			}
   287			schema = childSchema
   288		}
   289	
   290		return nil
   291	}
   292	
   293	// DeletePath removes a node at the given path from the tree.
   294	// Uses the same schema-driven traversal as SetPath to navigate the tree,
   295	// then removes the target node from its parent's Children slice.
   296	func (t *ConfigTree) DeletePath(path []string) error {
   297		if len(path) == 0 {
   298			return fmt.Errorf("empty path")
   299		}
   300	
   301		return deletePath(&t.Children, path, setSchema, 0)
   302	}
   303	
   304	func deletePath(current *[]*Node, path []string, schema *schemaNode, i int) error {
   305		if i >= len(path) {
   306			return fmt.Errorf("path not found")
   307		}
   308	
   309		keyword := path[i]
   310	
   311		// Look up keyword in current schema level.
   312		var childSchema *schemaNode
   313		if schema != nil {
   314			if s, ok := schema.children[keyword]; ok {
   315				childSchema = s
   316			} else if schema.wildcard != nil {
   317				childSchema = schema.wildcard
   318			}
   319		}
   320	
   321		if childSchema == nil {
   322			// No schema match: remaining tokens form leaf keys, remove matching node.
   323			leafKeys := path[i:]
   324			return removeMatchingNode(current, leafKeys)
   325		}
   326	
   327		// Consume keyword + extra args as this node's keys.
   328		nodeKeyCount := 1 + childSchema.args
   329		if i+nodeKeyCount > len(path) {
   330			// Not enough tokens; treat remainder as leaf keys.

exec
/bin/bash -lc "nl -ba pkg/cmdtree/schema_validate.go | sed -n '1,280p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
     1	package cmdtree
     2	
     3	// SchemaValidate is the #1319 typed-leaf gate that runs at commit-check
     4	// time, BEFORE the existing pkg/config compiler.
     5	//
     6	// Why pre-compile? parseBandwidthLimit / parseBurstSizeLimit silently
     7	// return 0 on garbage input, so `set class-of-service schedulers x
     8	// transmit-rate asd` currently compiles to zero bps and commits
     9	// silently. SchemaValidate walks the AST against the cmdtree's
    10	// typed-leaf metadata (Node.ValueType + Node.Validator) and fails the
    11	// commit with a human-readable error before the compiler ever sees the
    12	// bad string.
    13	//
    14	// Scope this PR (#1319 Phase 1 + Phase 2 schedulers only):
    15	//   - Walks `class-of-service schedulers <name> { ... }`.
    16	//   - Every other subsystem is on ValueAny by default and skipped by
    17	//     the walker — the gate is opt-in per leaf.
    18	//
    19	// Adding a new typed subtree is purely a matter of populating
    20	// ValueType + Validator on the corresponding cmdtree Nodes and adding
    21	// a walker entry below.
    22	
    23	import (
    24		"fmt"
    25	
    26		"github.com/psaab/xpf/pkg/config"
    27	)
    28	
    29	// SchemaValidate walks the AST and, for every typed-leaf cmdtree Node
    30	// that matches an AST node, invokes its Validator on the leaf's value.
    31	// It returns the FIRST error encountered (matching how the existing
    32	// compiler surfaces commit-check failures). cfg may be nil — none of
    33	// the Phase-2 schedulers validators need it, but the signature reserves
    34	// room for future cross-reference validators.
    35	func SchemaValidate(tree *config.ConfigTree, cfg *config.Config) error {
    36		if tree == nil {
    37			return nil
    38		}
    39		// We only have a typed-leaf map for the `set class-of-service
    40		// schedulers ...` subtree in this PR. Walking the whole AST against
    41		// the (still-mostly-untyped) cmdtree ConfigTopLevel would be wasted
    42		// work; restrict the walk to the subtree we actually validate.
    43		cosNode := tree.FindChild("class-of-service")
    44		if cosNode == nil {
    45			return nil
    46		}
    47		schedRoot := ConfigClassOfServiceSchedulers
    48		if schedRoot == nil {
    49			return nil
    50		}
    51		for _, schedulersNode := range cosNode.FindChildren("schedulers") {
    52			if err := walkSchedulers(schedulersNode, schedRoot, cfg); err != nil {
    53				return err
    54			}
    55		}
    56		return nil
    57	}
    58	
    59	// walkSchedulers handles both AST shapes for the schedulers subtree:
    60	//
    61	//   - hierarchical: `schedulers { be-sched { transmit-rate 7g; ... } }`
    62	//     ⇒ Node Keys=["schedulers"], child Keys=["be-sched"], grandchild
    63	//     leaves like Keys=["transmit-rate","7g"].
    64	//
    65	//   - flat `set` form: `set class-of-service schedulers be-sched
    66	//     transmit-rate 7g` ⇒ Keys=["schedulers","be-sched"] with a chain
    67	//     of leaf Children Keys=["transmit-rate","7g"].
    68	func walkSchedulers(node *config.Node, schemaSchedRoot *Node, cfg *config.Config) error {
    69		if node == nil || schemaSchedRoot == nil {
    70			return nil
    71		}
    72		// AST shape A: Keys = ["schedulers", "<name>"], children = leaves.
    73		if len(node.Keys) >= 2 && node.Keys[0] == "schedulers" {
    74			schedName := node.Keys[1]
    75			var leaves []*config.Node
    76			// Per-scheduler value tokens carried directly on this node
    77			// (uncommon but possible in flat set form).
    78			if len(node.Keys) > 2 {
    79				leaves = append(leaves, &config.Node{Keys: node.Keys[2:]})
    80			}
    81			leaves = append(leaves, node.Children...)
    82			return walkSchedulerInstance(schedName, leaves, schemaSchedRoot, cfg)
    83		}
    84		// AST shape B: Keys = ["schedulers"], children = instance nodes.
    85		for _, inst := range node.Children {
    86			if len(inst.Keys) == 0 {
    87				continue
    88			}
    89			schedName := inst.Keys[0]
    90			var leaves []*config.Node
    91			if len(inst.Keys) > 1 {
    92				leaves = append(leaves, &config.Node{Keys: inst.Keys[1:]})
    93			}
    94			leaves = append(leaves, inst.Children...)
    95			if err := walkSchedulerInstance(schedName, leaves, schemaSchedRoot, cfg); err != nil {
    96				return err
    97			}
    98		}
    99		return nil
   100	}
   101	
   102	func walkSchedulerInstance(schedName string, leaves []*config.Node, schemaSchedRoot *Node, cfg *config.Config) error {
   103		allowSplitTransmitExact := schedulerHasTypedTransmitRate(leaves, cfg)
   104		for _, leaf := range leaves {
   105			if err := validateSchedulerLeaf(schedName, leaf, schemaSchedRoot, cfg, allowSplitTransmitExact); err != nil {
   106				return err
   107			}
   108		}
   109		return nil
   110	}
   111	
   112	// validateSchedulerLeaf resolves the cmdtree node for this AST leaf and
   113	// invokes its Validator on the leaf's value. The "value" lives either
   114	// in Keys[N+] (flat set form: Keys=["transmit-rate","1g","exact"]) or
   115	// in node.Children[0].Keys[0] (hierarchical: child node holds it).
   116	func validateSchedulerLeaf(schedName string, leaf *config.Node, schemaSchedRoot *Node, cfg *config.Config, allowSplitTransmitExact bool) error {
   117		if len(leaf.Keys) == 0 {
   118			return nil
   119		}
   120		leafName := leaf.Keys[0]
   121		schemaNode, ok := schemaSchedRoot.Children[leafName]
   122		if !ok {
   123			// Unknown leaf — leave to existing parser/compiler; gate is opt-in.
   124			return nil
   125		}
   126		return validateValueTokens(
   127			schedName,
   128			leafName,
   129			schemaNode,
   130			schedulerLeafValues(leaf),
   131			cfg,
   132			allowSplitTransmitExact,
   133		)
   134	}
   135	
   136	func schedulerLeafValues(leaf *config.Node) []string {
   137		// Collect value tokens: trailing Keys[1:] plus any leaf child whose
   138		// Keys[0] is the value (hierarchical shape `transmit-rate 1g;` may
   139		// also appear as Keys=["transmit-rate"] with one child Keys=["1g"]).
   140		values := append([]string(nil), leaf.Keys[1:]...)
   141		for _, child := range leaf.Children {
   142			if len(child.Keys) > 0 {
   143				values = append(values, child.Keys[0])
   144			}
   145		}
   146		return values
   147	}
   148	
   149	func schedulerHasTypedTransmitRate(leaves []*config.Node, cfg *config.Config) bool {
   150		for _, leaf := range leaves {
   151			if len(leaf.Keys) == 0 || leaf.Keys[0] != "transmit-rate" {
   152				continue
   153			}
   154			for _, tok := range schedulerLeafValues(leaf) {
   155				if tok == "exact" {
   156					continue
   157				}
   158				if err := config.ValidateRate(tok, cfg); err == nil {
   159					return true
   160				}
   161			}
   162		}
   163		return false
   164	}
   165	
   166	// validateValueTokens applies validators along a chain of value tokens.
   167	// transmit-rate accepts <rate> followed optionally by `exact` — the
   168	// chain is [<rate>, "exact"]. priority accepts a single enum value. We
   169	// walk one token at a time; if the schemaNode is typed (ValueType !=
   170	// ValueAny) and has a Validator, the first token is the value and the
   171	// remainder are matched against children keywords (e.g. "exact").
   172	func validateValueTokens(schedName, leafName string, schemaNode *Node, values []string, cfg *config.Config, allowSplitTransmitExact bool) error {
   173		cur := schemaNode
   174		consumedTypedValue := false
   175		typedLeaf := schemaNode != nil && schemaNode.IsTypedLeaf() && schemaNode.Validator != nil
   176		if typedLeaf && len(values) == 0 {
   177			return fmt.Errorf(
   178				"class-of-service schedulers %s %s: missing value",
   179				schedName, leafName)
   180		}
   181		for _, tok := range values {
   182			if cur == nil {
   183				if typedLeaf {
   184					return fmt.Errorf(
   185						"class-of-service schedulers %s %s: unknown modifier %q",
   186						schedName, leafName, tok)
   187				}
   188				return nil
   189			}
   190			if allowSplitTransmitExact && allowsModifierOnlyTypedLeaf(leafName, tok) && cur == schemaNode && !consumedTypedValue {
   191				if next, ok := cur.Children[tok]; ok {
   192					cur = next
   193					consumedTypedValue = false
   194					continue
   195				}
   196			}
   197			if cur.IsTypedLeaf() && cur.Validator != nil && !consumedTypedValue {
   198				if err := cur.Validator(tok, cfg); err != nil {
   199					return fmt.Errorf(
   200						"class-of-service schedulers %s %s: invalid value %q: %v",
   201						schedName, leafName, tok, err)
   202				}
   203				consumedTypedValue = true
   204				continue
   205			}
   206			// Not a typed value slot — token must be a child keyword.
   207			if cur.Children == nil {
   208				if typedLeaf {
   209					return fmt.Errorf(
   210						"class-of-service schedulers %s %s: unknown modifier %q",
   211						schedName, leafName, tok)
   212				}
   213				return nil
   214			}
   215			next, ok := cur.Children[tok]
   216			if !ok {
   217				if typedLeaf {
   218					return fmt.Errorf(
   219						"class-of-service schedulers %s %s: unknown modifier %q",
   220						schedName, leafName, tok)
   221				}
   222				// Token doesn't match a known modifier on an untyped leaf —
   223				// leave reporting to the existing compiler.
   224				return nil
   225			}
   226			cur = next
   227			consumedTypedValue = false
   228		}
   229		return nil
   230	}
   231	
   232	func allowsModifierOnlyTypedLeaf(leafName, tok string) bool {
   233		return leafName == "transmit-rate" && tok == "exact"
   234	}

exec
/bin/bash -lc "nl -ba pkg/config/compiler_class_of_service.go | sed -n '220,255p;488,516p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   220				}
   221				if len(rewriteRule.Entries) > 0 {
   222					cos.DSCPRewriteRules[rewriteRule.Name] = rewriteRule
   223				}
   224			}
   225		}
   226	
   227		for _, inst := range namedInstances(node.FindChildren("schedulers")) {
   228			sched := &CoSScheduler{Name: inst.name}
   229			for _, child := range inst.node.Children {
   230				switch child.Name() {
   231				case "transmit-rate":
   232					rate, exact := parseCoSTransmitRate(child)
   233					if rate > 0 {
   234						sched.TransmitRateBytes = rate
   235					}
   236					sched.TransmitRateExact = sched.TransmitRateExact || exact
   237				case "priority":
   238					sched.Priority = nodeVal(child)
   239				case "buffer-size":
   240					if v := nodeVal(child); v != "" {
   241						if percent, err := parsePercentWithSuffixStrict(v); err == nil {
   242							sched.BufferSizeBytes = 0
   243							sched.BufferSizePercent = percent
   244						} else {
   245							sched.BufferSizeBytes = parseBurstSizeLimit(v)
   246							sched.BufferSizePercent = 0
   247						}
   248					}
   249				case "surplus-sharing":
   250					// #915: leaf with no value; presence = true.
   251					sched.SurplusSharing = true
   252				case "equal-flow-enforcement":
   253					sched.EqualFlowEnforcement = true
   254				case "codel-target":
   255					// #1614 A3: value in milliseconds; store as
   488		}
   489		if expr == "" {
   490			return "", fmt.Errorf("missing expectation; expected any, balanced, at-least-active-workers, max-worker-flow-share, or cstruct-max")
   491		}
   492		return expr, nil
   493	}
   494	
   495	func parseCoSTransmitRate(node *Node) (uint64, bool) {
   496		var rate uint64
   497		exact := false
   498		for _, key := range node.Keys[1:] {
   499			if key == "exact" {
   500				exact = true
   501				continue
   502			}
   503			if parsed := parseBandwidthLimit(key); parsed > 0 {
   504				rate = parsed
   505			}
   506		}
   507		if node.FindChild("exact") != nil {
   508			exact = true
   509		}
   510		return rate, exact
   511	}
   512	
   513	func collectCoSDSCPCodePoints(node *Node) []uint8 {
   514		var values []uint8
   515		seen := make(map[uint8]struct{})
   516		for _, child := range node.FindChildren("code-points") {

exec
/bin/bash -lc "nl -ba pkg/cmdtree/tree.go | sed -n '1000,1065p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
  1000			"rx-usecs": {Desc: "RX coalescing microseconds"},
  1001			"tx-usecs": {Desc: "TX coalescing microseconds"},
  1002		}},
  1003	}
  1004	
  1005	// ConfigClassOfServiceSchedulers is the per-leaf typed-value schema for
  1006	// `set class-of-service schedulers <name> { ... }` (#1319 Phase 2).
  1007	//
  1008	// It defines the value semantics for the three scheduler leaves the
  1009	// compiler actually consumes today (see
  1010	// pkg/config/compiler_class_of_service.go around lines 227-251):
  1011	// transmit-rate (rate, optional `exact` modifier), priority (enum),
  1012	// and buffer-size (byte-size with optional `temporal` modifier per Junos).
  1013	//
  1014	// The set-mode tab/`?` completer reaches these through
  1015	// ConfigTopLevel["set"].Children["class-of-service"].Children["schedulers"].
  1016	// The existing pkg/config/ast.go schemaNode tree still answers structural
  1017	// completion ("what keywords are valid here") for every other subtree; this
  1018	// map only adds value-slot semantics for the schedulers leaves.
  1019	//
  1020	// Wiring: SchemaValidate (this file) walks the AST against this map
  1021	// at commit-check time; configstore calls SchemaValidate BEFORE the
  1022	// existing compile step so `commit check` fails loud on garbage like
  1023	// `transmit-rate asd`.
  1024	var ConfigClassOfServiceSchedulers = &Node{
  1025		Desc: "Per-scheduler configuration",
  1026		Children: map[string]*Node{
  1027			"transmit-rate": {
  1028				Desc:          "Transmit rate (bandwidth allocated to this scheduler)",
  1029				ValueType:     ValueRate,
  1030				ValueDesc:     "Bandwidth (e.g. 100k, 10m, 1g) or bps integer; >= 8 bps",
  1031				ValueExamples: []string{"100k", "10m", "1g", "10g"},
  1032				Validator:     config.ValidateRate,
  1033				Children: map[string]*Node{
  1034					"exact": {Desc: "Enforce exact transmit rate (no surplus)"},
  1035				},
  1036			},
  1037			"priority": {
  1038				Desc:          "Scheduling priority for this queue",
  1039				ValueType:     ValueEnumOf,
  1040				ValueDesc:     "Scheduler priority (low | medium-low | medium-high | high | strict-high)",
  1041				ValueExamples: []string{"low", "medium-low", "medium-high", "high", "strict-high"},
  1042				Validator: config.ValidateEnum([]string{
  1043					"low", "medium-low", "medium-high", "high", "strict-high",
  1044				}),
  1045			},
  1046			"buffer-size": {
  1047				Desc:          "Buffer allocation for this scheduler",
  1048				ValueType:     ValueByteSizeOrPercent,
  1049				ValueDesc:     "Byte-size with explicit k/m/g suffix, or percent of interface CoS burst pool (e.g. 16m, 256k, 10%)",
  1050				ValueExamples: []string{"16m", "256k", "10%"},
  1051				Validator:     config.ValidateByteSizeOrPercent,
  1052				Children: map[string]*Node{
  1053					"temporal": {Desc: "Temporal buffer interpretation (Junos)"},
  1054				},
  1055			},
  1056			// `surplus-sharing` (#915) and `equal-flow-enforcement` are
  1057			// presence-only flags — no value to validate. We list them for
  1058			// `?` help completeness.
  1059			"surplus-sharing":        {Desc: "Allow scheduler to consume surplus bandwidth (opt-in)"},
  1060			"equal-flow-enforcement": {Desc: "Enforce per-flow equal share within this scheduler"},
  1061		},
  1062	}
  1063	
  1064	// ConfigTopLevel defines tab completion for config mode top-level commands.
  1065	var ConfigTopLevel = map[string]*Node{

exec
/bin/bash -lc "nl -ba pkg/config/compiler_class_of_service.go | sed -n '250,340p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   250					// #915: leaf with no value; presence = true.
   251					sched.SurplusSharing = true
   252				case "equal-flow-enforcement":
   253					sched.EqualFlowEnforcement = true
   254				case "codel-target":
   255					// #1614 A3: value in milliseconds; store as
   256					// nanoseconds. Empty value = 0 = disabled.
   257					if v := nodeVal(child); v != "" {
   258						if ms, err := strconv.ParseUint(v, 10, 64); err == nil {
   259							sched.CodelTargetNS = ms * 1_000_000
   260						}
   261					}
   262				}
   263			}
   264			cos.Schedulers[sched.Name] = sched
   265		}
   266	
   267		for _, inst := range namedInstances(node.FindChildren("scheduler-maps")) {
   268			schedMap := &CoSSchedulerMap{
   269				Name:    inst.name,
   270				Entries: make(map[string]*CoSSchedulerMapEntry),
   271			}
   272			for _, child := range inst.node.Children {
   273				if child.Name() != "forwarding-class" || len(child.Keys) < 2 {
   274					continue
   275				}
   276				className := child.Keys[1]
   277				scheduler := ""
   278				if len(child.Keys) >= 4 && child.Keys[2] == "scheduler" {
   279					scheduler = child.Keys[3]
   280				} else if schedNode := child.FindChild("scheduler"); schedNode != nil {
   281					scheduler = nodeVal(schedNode)
   282				}
   283				schedMap.Entries[className] = &CoSSchedulerMapEntry{
   284					ForwardingClass: className,
   285					Scheduler:       scheduler,
   286				}
   287			}
   288			cos.SchedulerMaps[schedMap.Name] = schedMap
   289		}
   290	
   291		for _, inst := range namedInstances(node.FindChildren("interfaces")) {
   292			iface := &CoSInterface{
   293				Name:  inst.name,
   294				Units: make(map[int]*CoSInterfaceUnit),
   295			}
   296			for _, unitNode := range inst.node.FindChildren("unit") {
   297				if len(unitNode.Keys) < 2 {
   298					continue
   299				}
   300				unitID, err := strconv.Atoi(unitNode.Keys[1])
   301				if err != nil {
   302					continue
   303				}
   304				unit := &CoSInterfaceUnit{Unit: unitID}
   305				if shapingNode := unitNode.FindChild("shaping-rate"); shapingNode != nil {
   306					if v := nodeVal(shapingNode); v != "" {
   307						unit.ShapingRateBytes = parseBandwidthLimit(v)
   308					}
   309					if burstNode := shapingNode.FindChild("burst-size"); burstNode != nil {
   310						if v := nodeVal(burstNode); v != "" {
   311							unit.BurstSizeBytes = parseBurstSizeLimit(v)
   312						}
   313					}
   314				}
   315				if schedMapNode := unitNode.FindChild("scheduler-map"); schedMapNode != nil {
   316					unit.SchedulerMap = nodeVal(schedMapNode)
   317				}
   318				if classifiersNode := unitNode.FindChild("classifiers"); classifiersNode != nil {
   319					if dscpNode := classifiersNode.FindChild("dscp"); dscpNode != nil {
   320						unit.DSCPClassifier = nodeVal(dscpNode)
   321					}
   322					if ieeeNode := classifiersNode.FindChild("ieee-802.1"); ieeeNode != nil {
   323						unit.IEEE8021Classifier = nodeVal(ieeeNode)
   324					}
   325				}
   326				if rewriteRulesNode := unitNode.FindChild("rewrite-rules"); rewriteRulesNode != nil {
   327					if dscpNode := rewriteRulesNode.FindChild("dscp"); dscpNode != nil {
   328						unit.DSCPRewriteRule = nodeVal(dscpNode)
   329					}
   330				}
   331				// #1614 A1: oversubscription-policy { guarantee-rate <X> | proportional }
   332				//
   333				// Junos set syntax `set ... oversubscription-policy guarantee-rate 0.7`
   334				// produces a flat-keys leaf node whose Keys are
   335				// ["oversubscription-policy", "guarantee-rate", "0.7"]. The
   336				// hierarchical text shape produces a parent node with a
   337				// child sub-node for "guarantee-rate" carrying "0.7" as a
   338				// trailing key or leaf value. Handle both forms.
   339				if oversubNode := unitNode.FindChild("oversubscription-policy"); oversubNode != nil {
   340					// Flat-keys path: Keys = [policy_name, value, ...] all on

exec
/bin/bash -lc 'rg -n "codel|drop-profile|red|temporal|buffer-size|transmit-rate|priority|surplus-sharing|equal-flow-enforcement" pkg/config/ast.go pkg/cmdtree/tree.go pkg/config/compiler_class_of_service.go' in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/config/compiler_class_of_service.go:55:		//   * The shared-queue lease derives its rate from a
pkg/config/compiler_class_of_service.go:133:				for _, lpNode := range fcNode.FindChildren("loss-priority") {
pkg/config/compiler_class_of_service.go:166:				for _, lpNode := range fcNode.FindChildren("loss-priority") {
pkg/config/compiler_class_of_service.go:202:				for _, lpNode := range fcNode.FindChildren("loss-priority") {
pkg/config/compiler_class_of_service.go:231:			case "transmit-rate":
pkg/config/compiler_class_of_service.go:237:			case "priority":
pkg/config/compiler_class_of_service.go:239:			case "buffer-size":
pkg/config/compiler_class_of_service.go:249:			case "surplus-sharing":
pkg/config/compiler_class_of_service.go:252:			case "equal-flow-enforcement":
pkg/config/compiler_class_of_service.go:254:			case "codel-target":
pkg/config/compiler_class_of_service.go:381:			// #1614 A2: priority-low-min-share <bps>
pkg/config/compiler_class_of_service.go:382:			if minShareNode := unitNode.FindChild("priority-low-min-share"); minShareNode != nil {
pkg/config/compiler_class_of_service.go:459:			return fmt.Errorf("multiple expectations configured: %q and %q", expr, value)
pkg/cmdtree/tree.go:29://     check, so garbage like `transmit-rate asd` fails loud at commit time
pkg/cmdtree/tree.go:32:// Add new types here only when we're prepared to wire validators for every
pkg/cmdtree/tree.go:33:// leaf that adopts them — IP/CIDR/MAC/duration are deliberately deferred
pkg/cmdtree/tree.go:93:// Nodes can carry validators declared in pkg/config directly. The alias
pkg/cmdtree/tree.go:173:					"statistics": {Desc: "Show fabric redirect statistics"},
pkg/cmdtree/tree.go:346:				"ids-option": {Desc: "Show configured screen profile", DynamicFn: func(cfg *config.Config) []string {
pkg/cmdtree/tree.go:573:			"services": {Desc: "Show configured system services"},
pkg/cmdtree/tree.go:577:			"users":    {Desc: "Show configured login users"},
pkg/cmdtree/tree.go:750:					"data": {Desc: "Fail over all data redundancy groups together", Children: map[string]*Node{
pkg/cmdtree/tree.go:755:					"redundancy-group": {Desc: "Failover a specific redundancy group", DynamicFn: func(cfg *config.Config) []string {
pkg/cmdtree/tree.go:774:						"redundancy-group": {Desc: "Reset failover for a redundancy group", DynamicFn: func(cfg *config.Config) []string {
pkg/cmdtree/tree.go:799:							"register":   {Desc: "Register a queue without arming redirect"},
pkg/cmdtree/tree.go:800:							"unregister": {Desc: "Unregister a queue and release redirect ownership"},
pkg/cmdtree/tree.go:801:							"arm":        {Desc: "Register and arm a queue for redirect"},
pkg/cmdtree/tree.go:802:							"disarm":     {Desc: "Disarm a queue while keeping it registered"},
pkg/cmdtree/tree.go:812:								"register":   {Desc: "Register a binding without arming redirect"},
pkg/cmdtree/tree.go:813:								"unregister": {Desc: "Unregister a binding and release redirect ownership"},
pkg/cmdtree/tree.go:814:								"arm":        {Desc: "Register and arm a binding for redirect"},
pkg/cmdtree/tree.go:815:								"disarm":     {Desc: "Disarm a binding while keeping it registered"},
pkg/cmdtree/tree.go:829:									"source-ip":        {Desc: "Source IP required when emitting on wire"},
pkg/cmdtree/tree.go:837:									"source-ip":        {Desc: "Source IP required when emitting on wire"},
pkg/cmdtree/tree.go:1011:// transmit-rate (rate, optional `exact` modifier), priority (enum),
pkg/cmdtree/tree.go:1012:// and buffer-size (byte-size with optional `temporal` modifier per Junos).
pkg/cmdtree/tree.go:1023:// `transmit-rate asd`.
pkg/cmdtree/tree.go:1027:		"transmit-rate": {
pkg/cmdtree/tree.go:1037:		"priority": {
pkg/cmdtree/tree.go:1038:			Desc:          "Scheduling priority for this queue",
pkg/cmdtree/tree.go:1040:			ValueDesc:     "Scheduler priority (low | medium-low | medium-high | high | strict-high)",
pkg/cmdtree/tree.go:1046:		"buffer-size": {
pkg/cmdtree/tree.go:1053:				"temporal": {Desc: "Temporal buffer interpretation (Junos)"},
pkg/cmdtree/tree.go:1056:		// `surplus-sharing` (#915) and `equal-flow-enforcement` are
pkg/cmdtree/tree.go:1059:		"surplus-sharing":        {Desc: "Allow scheduler to consume surplus bandwidth (opt-in)"},
pkg/cmdtree/tree.go:1060:		"equal-flow-enforcement": {Desc: "Enforce per-flow equal share within this scheduler"},
pkg/cmdtree/tree.go:1068:	"insert":   {Desc: "Insert a new ordered configuration statement"},
pkg/cmdtree/tree.go:1292:						candidates = append(candidates, Candidate{Name: name, Desc: "(configured)"})
pkg/cmdtree/tree.go:1318:				candidates = append(candidates, Candidate{Name: name, Desc: "(configured)"})
pkg/cmdtree/tree.go:1327:// description, plus one entry per declared example.
pkg/cmdtree/tree.go:1463:// CommonPrefix returns the longest shared prefix among the given strings.
pkg/config/ast.go:168:					var filtered []*Node
pkg/config/ast.go:171:							filtered = append(filtered, n)
pkg/config/ast.go:174:					if len(filtered) == 0 {
pkg/config/ast.go:177:					matched = filtered
pkg/config/ast.go:598:				"pre-shared-key": {children: nil},
pkg/config/ast.go:653:				"pre-shared-key":    {args: 1, children: nil},
pkg/config/ast.go:707:			"redundant-parent": {desc: "Parent of this redundant interface", args: 1, children: nil},
pkg/config/ast.go:719:		"redundant-ether-options": {desc: "Redundant Ethernet interface options", children: map[string]*schemaNode{
pkg/config/ast.go:720:			"redundancy-group": {desc: "Redundancy group for this RETH", args: 1, children: nil},
pkg/config/ast.go:759:						"preferred": {desc: "Preferred address", children: nil},
pkg/config/ast.go:781:						"preferred": {desc: "Preferred address", children: nil},
pkg/config/ast.go:795:							"preferred-prefix-length": {desc: "Preferred prefix length", args: 1, placeholder: "<length>", children: nil},
pkg/config/ast.go:1028:			"redistribute":        {desc: "Redistribute", args: 1, placeholder: "<protocol>", children: nil},
pkg/config/ast.go:1115:			"redundancy-group": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1117:					"priority": {args: 1, children: nil},
pkg/config/ast.go:1141:					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1148:					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1157:					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1165:			"transmit-rate": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1168:			"priority":               {args: 1, children: nil},
pkg/config/ast.go:1169:			"buffer-size":            {args: 1, children: nil},
pkg/config/ast.go:1170:			"surplus-sharing":        {children: nil}, // #915
pkg/config/ast.go:1171:			"equal-flow-enforcement": {children: nil},
pkg/config/ast.go:1218:				"loss-priority": {args: 1, children: nil},
pkg/config/ast.go:1239:				"loss-priority": {args: 1, children: nil},
pkg/config/ast.go:1279:							"loss-priority":    {args: 1, children: nil},
pkg/config/ast.go:1323:							"loss-priority":    {args: 1, children: nil},
pkg/config/ast.go:1338:		"no-redirects":  {desc: "Disable ICMP redirects", children: nil},
pkg/config/ast.go:1389:			"socket-mem":     {args: 1, desc: "Legacy DPDK socket memory (retired, ignored)", children: nil},
pkg/config/ast.go:1396:			"shared-umem": {desc: "AF_XDP shared-UMEM policy override", children: map[string]*schemaNode{
pkg/config/ast.go:1397:				"mode":                 {args: 1, desc: "Shared UMEM mode override (auto|off|same-device-debug|cross-nic)", children: nil},
pkg/config/ast.go:1805:			// Stay at current schema level so sibling keywords are offered.

exec
/bin/bash -lc "rg -n \"completeConfigWithDesc|completeConfigPairs|CompleteSetPathWithValues|CompleteSetPath|ValueProvider|SchemaCompletion\" pkg/cli pkg/grpcapi pkg/config -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/config/parser_ast_test.go:5088:func TestCompleteSetPathFromZoneToZone(t *testing.T) {
pkg/config/parser_ast_test.go:5097:			results := CompleteSetPathWithValues(tc.tokens, nil)
pkg/config/completion_prefix_test.go:5:func completionNames(results []SchemaCompletion) []string {
pkg/config/completion_prefix_test.go:13:func containsCompletionName(results []SchemaCompletion, want string) bool {
pkg/config/completion_prefix_test.go:27:	results := CompleteSetPathWithValues(resolved, nil)
pkg/config/completion_prefix_test.go:33:func TestCompleteSetPathWithValuesReturnsAmbiguousLastPrefixMatches(t *testing.T) {
pkg/config/completion_prefix_test.go:34:	results := CompleteSetPathWithValues([]string{"security", "s"}, nil)
pkg/config/completion_prefix_test.go:40:func TestCompleteSetPathWithValuesReturnsRPMProbeCompletions(t *testing.T) {
pkg/config/completion_prefix_test.go:41:	results := CompleteSetPathWithValues([]string{"services", "rpm", "probe", "monitor", "test", "ping-test"}, nil)
pkg/config/completion_prefix_test.go:46:	targetResults := CompleteSetPathWithValues([]string{"services", "rpm", "probe", "monitor", "test", "ping-test", "target"}, nil)
pkg/cli/completion.go:82:		candidates = cc.cli.completeConfigWithDesc(words, partial)
pkg/cli/completion.go:89:			schemaCompletions := config.CompleteSetPathWithValues(subPath, cc.cli.valueProvider)
pkg/cli/completion.go:129:func (c *CLI) completeConfigWithDesc(words []string, partial string) []completionCandidate {
pkg/cli/completion.go:148:		schemaCompletions := config.CompleteSetPathWithValues(pathWords, c.valueProvider)
pkg/cli/completion.go:362:func (c *CLI) valueProvider(hint config.ValueHint, path []string) []config.SchemaCompletion {
pkg/cli/completion.go:369:		var out []config.SchemaCompletion
pkg/cli/completion.go:375:			out = append(out, config.SchemaCompletion{Name: name, Desc: desc})
pkg/cli/completion.go:379:		var out []config.SchemaCompletion
pkg/cli/completion.go:382:				out = append(out, config.SchemaCompletion{Name: addr.Name, Desc: addr.Value})
pkg/cli/completion.go:385:				out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "address-set"})
pkg/cli/completion.go:390:		var out []config.SchemaCompletion
pkg/cli/completion.go:392:			out = append(out, config.SchemaCompletion{Name: app.Name, Desc: app.Description})
pkg/cli/completion.go:395:			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
pkg/cli/completion.go:398:			out = append(out, config.SchemaCompletion{Name: name, Desc: "predefined"})
pkg/cli/completion.go:402:		var out []config.SchemaCompletion
pkg/cli/completion.go:404:			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
pkg/cli/completion.go:408:		var out []config.SchemaCompletion
pkg/cli/completion.go:410:			out = append(out, config.SchemaCompletion{Name: name, Desc: "source pool"})
pkg/cli/completion.go:414:				out = append(out, config.SchemaCompletion{Name: name, Desc: "destination pool"})
pkg/cli/completion.go:419:		var out []config.SchemaCompletion
pkg/cli/completion.go:421:			out = append(out, config.SchemaCompletion{Name: name, Desc: "screen profile"})
pkg/cli/completion.go:425:		var out []config.SchemaCompletion
pkg/cli/completion.go:427:			out = append(out, config.SchemaCompletion{Name: name, Desc: "log stream"})
pkg/cli/completion.go:431:		var out []config.SchemaCompletion
pkg/cli/completion.go:437:			out = append(out, config.SchemaCompletion{Name: name, Desc: desc})
pkg/cli/completion.go:441:		out := []config.SchemaCompletion{
pkg/cli/completion.go:448:				out = append(out, config.SchemaCompletion{Name: addr.Name, Desc: addr.Value})
pkg/cli/completion.go:451:				out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "address-set"})
pkg/cli/completion.go:456:		out := []config.SchemaCompletion{
pkg/cli/completion.go:460:			out = append(out, config.SchemaCompletion{Name: app.Name, Desc: app.Description})
pkg/cli/completion.go:463:			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
pkg/cli/completion.go:466:			out = append(out, config.SchemaCompletion{Name: name, Desc: "predefined"})
pkg/cli/completion.go:490:		var out []config.SchemaCompletion
pkg/cli/completion.go:496:			out = append(out, config.SchemaCompletion{Name: pol.Name, Desc: desc})
pkg/cli/completion.go:515:		var out []config.SchemaCompletion
pkg/cli/completion.go:521:			out = append(out, config.SchemaCompletion{Name: fmt.Sprintf("%d", num), Desc: desc})
pkg/config/ast.go:373:// SchemaCompletion is a completion candidate from the config schema.
pkg/config/ast.go:374:type SchemaCompletion struct {
pkg/config/ast.go:379:// ValueProvider returns possible values for a given hint.
pkg/config/ast.go:381:type ValueProvider func(hint ValueHint, path []string) []SchemaCompletion
pkg/config/ast.go:1668:// CompleteSetPath returns possible completions for a partial set/delete path.
pkg/config/ast.go:1672:func CompleteSetPath(tokens []string) []string {
pkg/config/ast.go:1673:	results := CompleteSetPathWithValues(tokens, nil)
pkg/config/ast.go:1684:// CompleteSetPathWithValues is like CompleteSetPath but uses a ValueProvider
pkg/config/ast.go:1686:// Returns SchemaCompletion pairs with names and descriptions.
pkg/config/ast.go:1687:func CompleteSetPathWithValues(tokens []string, provider ValueProvider) []SchemaCompletion {
pkg/config/ast.go:1719:					var completions []SchemaCompletion
pkg/config/ast.go:1721:						completions = append(completions, SchemaCompletion{Name: name, Desc: schema.children[name].desc})
pkg/config/ast.go:1733:				var matches []SchemaCompletion
pkg/config/ast.go:1736:						matches = append(matches, SchemaCompletion{Name: name, Desc: node.desc})
pkg/config/ast.go:1779:						return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}
pkg/config/ast.go:1784:					return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}
pkg/config/ast.go:1793:					results = append([]SchemaCompletion{{Name: childSchema.placeholder, Desc: childSchema.desc}}, results...)
pkg/config/ast.go:1799:				return []SchemaCompletion{{Name: childSchema.placeholder, Desc: childSchema.desc}}
pkg/config/ast.go:1818:		return []SchemaCompletion{{Name: "<[Enter]>", Desc: "Execute this command"}}
pkg/config/ast.go:1821:	var completions []SchemaCompletion
pkg/config/ast.go:1824:			completions = append(completions, SchemaCompletion{Name: name, Desc: node.desc})
pkg/config/ast.go:1834:			completions = append(completions, SchemaCompletion{Name: schema.wildcard.placeholder, Desc: schema.wildcard.desc})
pkg/cli/cli.go:243:				candidates = c.completeConfigWithDesc(words, partial)
pkg/cli/cli.go:250:					schemaCompletions := config.CompleteSetPathWithValues(subPath, c.valueProvider)
pkg/grpcapi/completion_test.go:16:	pairs := s.completeConfigPairs([]string{"commit"}, "")
pkg/grpcapi/completion_test.go:24:	pairs := s.completeConfigPairs([]string{"load"}, "")
pkg/grpcapi/completion_test.go:40:	pairs := s.completeConfigPairs([]string{"com"}, "")
pkg/grpcapi/completion_test.go:48:	pairs := s.completeConfigPairs([]string{"co"}, "")
pkg/grpcapi/completion_test.go:56:	_ = s.completeConfigPairs([]string{"set", "security", "policies", "from-zone"}, "")
pkg/grpcapi/server_cluster.go:432:		pairs = s.completeConfigPairs(words, partial)
pkg/grpcapi/server_cluster.go:511:func (s *Server) completionValueProvider() config.ValueProvider {
pkg/grpcapi/server_cluster.go:524:		schemaCompletions := config.CompleteSetPathWithValues(subPath, s.completionValueProvider())
pkg/grpcapi/server_cluster.go:549:func (s *Server) completeConfigPairs(words []string, partial string) []completionPair {
pkg/grpcapi/server_cluster.go:568:		schemaCompletions := config.CompleteSetPathWithValues(pathWords, s.completionValueProvider())
pkg/grpcapi/server_cluster.go:610:func (s *Server) valueProvider(hint config.ValueHint, path []string) []config.SchemaCompletion {
pkg/grpcapi/server_cluster.go:620:		var out []config.SchemaCompletion
pkg/grpcapi/server_cluster.go:626:			out = append(out, config.SchemaCompletion{Name: name, Desc: desc})
pkg/grpcapi/server_cluster.go:630:		var out []config.SchemaCompletion
pkg/grpcapi/server_cluster.go:633:				out = append(out, config.SchemaCompletion{Name: addr.Name, Desc: addr.Value})
pkg/grpcapi/server_cluster.go:636:				out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "address-set"})
pkg/grpcapi/server_cluster.go:641:		var out []config.SchemaCompletion
pkg/grpcapi/server_cluster.go:643:			out = append(out, config.SchemaCompletion{Name: app.Name, Desc: app.Description})
pkg/grpcapi/server_cluster.go:646:			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
pkg/grpcapi/server_cluster.go:649:			out = append(out, config.SchemaCompletion{Name: name, Desc: "predefined"})
pkg/grpcapi/server_cluster.go:653:		var out []config.SchemaCompletion
pkg/grpcapi/server_cluster.go:655:			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
pkg/grpcapi/server_cluster.go:659:		var out []config.SchemaCompletion
pkg/grpcapi/server_cluster.go:661:			out = append(out, config.SchemaCompletion{Name: name, Desc: "source pool"})
pkg/grpcapi/server_cluster.go:665:				out = append(out, config.SchemaCompletion{Name: name, Desc: "destination pool"})
pkg/grpcapi/server_cluster.go:670:		var out []config.SchemaCompletion
pkg/grpcapi/server_cluster.go:672:			out = append(out, config.SchemaCompletion{Name: name, Desc: "screen profile"})
pkg/grpcapi/server_cluster.go:676:		var out []config.SchemaCompletion
pkg/grpcapi/server_cluster.go:678:			out = append(out, config.SchemaCompletion{Name: name, Desc: "log stream"})
pkg/grpcapi/server_cluster.go:682:		var out []config.SchemaCompletion
pkg/grpcapi/server_cluster.go:688:			out = append(out, config.SchemaCompletion{Name: name, Desc: desc})
pkg/grpcapi/server_cluster.go:692:		out := []config.SchemaCompletion{
pkg/grpcapi/server_cluster.go:699:				out = append(out, config.SchemaCompletion{Name: addr.Name, Desc: addr.Value})
pkg/grpcapi/server_cluster.go:702:				out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "address-set"})
pkg/grpcapi/server_cluster.go:707:		out := []config.SchemaCompletion{
pkg/grpcapi/server_cluster.go:711:			out = append(out, config.SchemaCompletion{Name: app.Name, Desc: app.Description})
pkg/grpcapi/server_cluster.go:714:			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
pkg/grpcapi/server_cluster.go:717:			out = append(out, config.SchemaCompletion{Name: name, Desc: "predefined"})
pkg/grpcapi/server_cluster.go:739:		var out []config.SchemaCompletion
pkg/grpcapi/server_cluster.go:745:			out = append(out, config.SchemaCompletion{Name: pol.Name, Desc: desc})
pkg/grpcapi/server_cluster.go:763:		var out []config.SchemaCompletion
pkg/grpcapi/server_cluster.go:769:			out = append(out, config.SchemaCompletion{Name: fmt.Sprintf("%d", num), Desc: desc})

codex
The compiler check confirms one important v2 correction: `exact` is consumed by `parseCoSTransmitRate`, while `buffer-size temporal` is not consumed in the buffer-size case. I’m now pressure-testing the walker contract against `SetPath` and the completion frontends, since that is where a “generic walker” plan can still be too hand-wavy.
exec
/bin/bash -lc "nl -ba pkg/cli/completion.go | sed -n '60,175p;350,375p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
    60			for i, c := range pipeCandidates {
    61				names[i] = c.name
    62			}
    63			cp := commonPrefix(names)
    64			suffix := cp[len(partial):]
    65			if suffix == "" {
    66				return nil, 0
    67			}
    68			return [][]rune{[]rune(suffix)}, len(partial)
    69		}
    70	
    71		words := strings.Fields(text)
    72		trailingSpace := len(text) > 0 && text[len(text)-1] == ' '
    73	
    74		var partial string
    75		if !trailingSpace && len(words) > 0 {
    76			partial = words[len(words)-1]
    77			words = words[:len(words)-1]
    78		}
    79	
    80		var candidates []completionCandidate
    81		if cc.cli.store.InConfigMode() {
    82			candidates = cc.cli.completeConfigWithDesc(words, partial)
    83		} else {
    84			// "show configuration <path>" — delegate sub-path to config schema
    85			if subPath, ok := showConfigurationSubPath(words); ok {
    86				if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(subPath); resolved {
    87					subPath = resolvedPath
    88				}
    89				schemaCompletions := config.CompleteSetPathWithValues(subPath, cc.cli.valueProvider)
    90				if schemaCompletions != nil {
    91					for _, sc := range schemaCompletions {
    92						if partial == "" || strings.HasPrefix(sc.Name, partial) {
    93							candidates = append(candidates, completionCandidate{name: sc.Name, desc: sc.Desc})
    94						}
    95					}
    96				}
    97			}
    98			if len(candidates) == 0 {
    99				candidates = completeFromTreeWithDesc(operationalTree, words, partial, cc.cli.store.ActiveConfig())
   100			}
   101		}
   102		if len(candidates) == 0 {
   103			return nil, 0
   104		}
   105	
   106		sort.Slice(candidates, func(i, j int) bool { return candidates[i].name < candidates[j].name })
   107	
   108		if len(candidates) == 1 {
   109			suffix := candidates[0].name[len(partial):]
   110			return [][]rune{[]rune(suffix + " ")}, len(partial)
   111		}
   112	
   113		// Multiple matches: show descriptions above prompt.
   114		writeCompletionHelp(cc.cli.rl.Stdout(), candidates)
   115	
   116		// Complete common prefix.
   117		names := make([]string, len(candidates))
   118		for i, c := range candidates {
   119			names[i] = c.name
   120		}
   121		cp := commonPrefix(names)
   122		suffix := cp[len(partial):]
   123		if suffix == "" {
   124			return nil, 0
   125		}
   126		return [][]rune{[]rune(suffix)}, len(partial)
   127	}
   128	
   129	func (c *CLI) completeConfigWithDesc(words []string, partial string) []completionCandidate {
   130		if len(words) == 0 {
   131			return filterTreeCandidates(configTopLevel, partial)
   132		}
   133	
   134		resolvedTop, ok := resolveUniqueTreePrefix(configTopLevel, words[0])
   135		if !ok {
   136			if len(words) == 1 {
   137				return filterTreeCandidates(configTopLevel, words[0])
   138			}
   139			return nil
   140		}
   141	
   142		switch resolvedTop {
   143		case "set", "delete", "show", "edit":
   144			pathWords := words[1:]
   145			if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(pathWords); resolved {
   146				pathWords = resolvedPath
   147			}
   148			schemaCompletions := config.CompleteSetPathWithValues(pathWords, c.valueProvider)
   149			if schemaCompletions == nil {
   150				return nil
   151			}
   152			var candidates []completionCandidate
   153			for _, sc := range schemaCompletions {
   154				if strings.HasPrefix(sc.Name, partial) {
   155					candidates = append(candidates, completionCandidate{name: sc.Name, desc: sc.Desc})
   156				}
   157			}
   158			return candidates
   159	
   160		case "run":
   161			return completeFromTreeWithDesc(operationalTree, words[1:], partial, c.store.ActiveConfig())
   162	
   163		case "commit", "load":
   164			if len(words) == 1 {
   165				node := configTopLevel[resolvedTop]
   166				if node == nil || node.Children == nil {
   167					return nil
   168				}
   169				var candidates []completionCandidate
   170				for name, child := range node.Children {
   171					if strings.HasPrefix(name, partial) {
   172						candidates = append(candidates, completionCandidate{name: name, desc: child.Desc})
   173					}
   174				}
   175				return candidates
   350		}
   351	
   352		// Partial filter name typed
   353		for _, f := range pipeFilters {
   354			if strings.HasPrefix(f.name, after) {
   355				candidates = append(candidates, f)
   356			}
   357		}
   358		return candidates, true
   359	}
   360	
   361	// #1044c Phase 1: valueProvider relocated from cli.go (no behavior change).
   362	func (c *CLI) valueProvider(hint config.ValueHint, path []string) []config.SchemaCompletion {
   363		cfg := c.store.ActiveConfig()
   364		if cfg == nil {
   365			return nil
   366		}
   367		switch hint {
   368		case config.ValueHintZoneName:
   369			var out []config.SchemaCompletion
   370			for name, zone := range cfg.Security.Zones {
   371				desc := zone.Description
   372				if desc == "" {
   373					desc = "(configured)"
   374				}
   375				out = append(out, config.SchemaCompletion{Name: name, Desc: desc})

exec
/bin/bash -lc "nl -ba pkg/grpcapi/server_cluster.go | sed -n '420,575p;511,535p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   420	
   421		words := strings.Fields(text)
   422		trailingSpace := len(text) > 0 && text[len(text)-1] == ' '
   423	
   424		var partial string
   425		if !trailingSpace && len(words) > 0 {
   426			partial = words[len(words)-1]
   427			words = words[:len(words)-1]
   428		}
   429	
   430		var pairs []completionPair
   431		if req.ConfigMode {
   432			pairs = s.completeConfigPairs(words, partial)
   433		} else {
   434			pairs = s.completeOperationalPairs(words, partial)
   435		}
   436	
   437		sort.Slice(pairs, func(i, j int) bool { return pairs[i].name < pairs[j].name })
   438		resp := &pb.CompleteResponse{
   439			Candidates:   make([]string, len(pairs)),
   440			Descriptions: make([]string, len(pairs)),
   441		}
   442		for i, p := range pairs {
   443			resp.Candidates[i] = p.name
   444			resp.Descriptions[i] = p.desc
   445		}
   446		return resp, nil
   447	}
   448	
   449	// pipeFilterNames lists available pipe filters for completion.
   450	var pipeFilterNames = []string{"count", "display", "except", "find", "grep", "last", "match", "no-more"}
   451	
   452	// completePipeFilter returns pipe filter candidates if the text contains "|".
   453	// Returns nil if no pipe is present (caller should proceed with normal completion).
   454	func (s *Server) completePipeFilter(text string) []string {
   455		idx := strings.LastIndex(text, "|")
   456		if idx < 0 {
   457			return nil
   458		}
   459		after := strings.TrimSpace(text[idx+1:])
   460		trailingSpace := len(text) > 0 && text[len(text)-1] == ' '
   461	
   462		// Right after "|" or "| " — all filters
   463		if after == "" || (trailingSpace && after == "") {
   464			return pipeFilterNames
   465		}
   466	
   467		// User has typed a complete filter + space — no more completions (freeform arg)
   468		if trailingSpace {
   469			return []string{}
   470		}
   471	
   472		// Partial filter name
   473		var candidates []string
   474		for _, f := range pipeFilterNames {
   475			if strings.HasPrefix(f, after) {
   476				candidates = append(candidates, f)
   477			}
   478		}
   479		return candidates
   480	}
   481	
   482	func filterCompletionPairs(tree map[string]*cmdtree.Node, prefix string) []completionPair {
   483		pairs := make([]completionPair, 0, len(tree))
   484		for name, node := range tree {
   485			if prefix == "" || strings.HasPrefix(name, prefix) {
   486				pairs = append(pairs, completionPair{name: name, desc: node.Desc})
   487			}
   488		}
   489		return pairs
   490	}
   491	
   492	func resolveShowConfigurationWords(words []string) ([]string, bool) {
   493		if len(words) < 2 {
   494			return nil, false
   495		}
   496		show, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(cmdtree.OperationalTree), words[0])
   497		if !ok || show != "show" {
   498			return nil, false
   499		}
   500		showNode := cmdtree.OperationalTree[show]
   501		if showNode == nil || showNode.Children == nil {
   502			return nil, false
   503		}
   504		conf, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(showNode.Children), words[1])
   505		if !ok || conf != "configuration" {
   506			return nil, false
   507		}
   508		return words[2:], true
   509	}
   510	
   511	func (s *Server) completionValueProvider() config.ValueProvider {
   511	func (s *Server) completionValueProvider() config.ValueProvider {
   512		if s == nil || s.store == nil {
   512		if s == nil || s.store == nil {
   513			return nil
   513			return nil
   514		}
   514		}
   515		return s.valueProvider
   515		return s.valueProvider
   516	}
   516	}
   517	
   517	
   518	func (s *Server) completeOperationalPairs(words []string, partial string) []completionPair {
   518	func (s *Server) completeOperationalPairs(words []string, partial string) []completionPair {
   519		// "show configuration <path>" — delegate sub-path to config schema
   519		// "show configuration <path>" — delegate sub-path to config schema
   520		if subPath, ok := resolveShowConfigurationWords(words); ok {
   520		if subPath, ok := resolveShowConfigurationWords(words); ok {
   521			if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(subPath); resolved {
   521			if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(subPath); resolved {
   522				subPath = resolvedPath
   522				subPath = resolvedPath
   523			}
   523			}
   524			schemaCompletions := config.CompleteSetPathWithValues(subPath, s.completionValueProvider())
   524			schemaCompletions := config.CompleteSetPathWithValues(subPath, s.completionValueProvider())
   525			if schemaCompletions != nil {
   525			if schemaCompletions != nil {
   526				var pairs []completionPair
   526				var pairs []completionPair
   527				for _, sc := range schemaCompletions {
   527				for _, sc := range schemaCompletions {
   528					if partial == "" || strings.HasPrefix(sc.Name, partial) {
   528					if partial == "" || strings.HasPrefix(sc.Name, partial) {
   529						pairs = append(pairs, completionPair{name: sc.Name, desc: sc.Desc})
   529						pairs = append(pairs, completionPair{name: sc.Name, desc: sc.Desc})
   530					}
   530					}
   531				}
   531				}
   532				if len(pairs) > 0 {
   532				if len(pairs) > 0 {
   533					return pairs
   533					return pairs
   534				}
   534				}
   535			}
   535			}
   536		}
   537		var cfg *config.Config
   538		if s.store != nil {
   539			cfg = s.store.ActiveConfig()
   540		}
   541		candidates := cmdtree.CompleteFromTreeWithDesc(cmdtree.OperationalTree, words, partial, cfg)
   542		pairs := make([]completionPair, len(candidates))
   543		for i, c := range candidates {
   544			pairs[i] = completionPair{name: c.Name, desc: c.Desc}
   545		}
   546		return pairs
   547	}
   548	
   549	func (s *Server) completeConfigPairs(words []string, partial string) []completionPair {
   550		if len(words) == 0 {
   551			return filterCompletionPairs(cmdtree.ConfigTopLevel, partial)
   552		}
   553	
   554		resolvedTop, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(cmdtree.ConfigTopLevel), words[0])
   555		if !ok {
   556			if len(words) == 1 {
   557				return filterCompletionPairs(cmdtree.ConfigTopLevel, words[0])
   558			}
   559			return nil
   560		}
   561	
   562		switch resolvedTop {
   563		case "set", "delete", "show", "edit":
   564			pathWords := words[1:]
   565			if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(pathWords); resolved {
   566				pathWords = resolvedPath
   567			}
   568			schemaCompletions := config.CompleteSetPathWithValues(pathWords, s.completionValueProvider())
   569			if schemaCompletions == nil {
   570				return nil
   571			}
   572			var pairs []completionPair
   573			for _, sc := range schemaCompletions {
   574				if strings.HasPrefix(sc.Name, partial) {
   575					pairs = append(pairs, completionPair{name: sc.Name, desc: sc.Desc})

exec
/bin/bash -lc 'rg -n "compoundKey: true|midKeyword|wildcard:|multi: true|args: [2-9]|valueHint:|placeholder:" pkg/config/ast.go' in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
393:	midKeyword   string                 // fixed keyword in the middle of args (e.g., "to-zone")
394:	midKeywordAt int                    // 1-based arg position where midKeyword appears (e.g., 2 for "from-zone X to-zone Y")
402:	"groups":       {wildcard: &schemaNode{}}, // children set in init()
403:	"apply-groups": {args: 1, multi: true, children: nil},
406:			"security-zone": {desc: "Security zone name", args: 1, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: map[string]*schemaNode{
407:				"description": {desc: "Zone description", args: 1, placeholder: "<text>", children: nil},
410:				"screen":      {desc: "Screen profile name", args: 1, placeholder: "<screen-name>", children: nil},
418:			"from-zone": {desc: "From zone", args: 3, valueHint: ValueHintZoneName, midKeyword: "to-zone", midKeywordAt: 2, placeholder: "<zone-name>", children: map[string]*schemaNode{
419:				"policy": {desc: "Policy name", args: 1, valueHint: ValueHintPolicyName, placeholder: "<policy-name>", children: map[string]*schemaNode{
420:					"description": {desc: "Policy description", args: 1, placeholder: "<text>", children: nil},
422:						"source-address":      {desc: "Source address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
423:						"destination-address": {desc: "Destination address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
424:						"application":         {desc: "Application", args: 1, multi: true, valueHint: ValueHintPolicyApp, placeholder: "<application>", children: nil},
433:				"policy": {desc: "Policy name", args: 1, valueHint: ValueHintPolicyName, placeholder: "<policy-name>", children: map[string]*schemaNode{
434:					"description": {desc: "Policy description", args: 1, placeholder: "<text>", children: nil},
436:						"source-address":      {desc: "Source address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
437:						"destination-address": {desc: "Destination address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
438:						"application":         {desc: "Application", args: 1, multi: true, valueHint: ValueHintPolicyApp, placeholder: "<application>", children: nil},
447:			"ids-option": {desc: "Screen profile name", args: 1, valueHint: ValueHintScreenProfile, placeholder: "<screen-name>", children: map[string]*schemaNode{
460:					"source-ip-based":      {desc: "Source IP based limit", args: 1, placeholder: "<number>", children: nil},
461:					"destination-ip-based": {desc: "Destination IP based limit", args: 1, placeholder: "<number>", children: nil},
467:				"pool":               {args: 1, valueHint: ValueHintPoolName, children: nil},
471:						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
474:						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
478:							"source-address":      {args: 1, multi: true, children: nil},
479:							"destination-address": {args: 1, multi: true, children: nil},
480:							"destination-port":    {args: 1, multi: true, children: nil},
481:							"application":         {args: 1, multi: true, children: nil},
487:								"pool":      {args: 1, valueHint: ValueHintPoolName, children: nil},
494:				"pool": {args: 1, valueHint: ValueHintPoolName, children: nil},
497:						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
500:						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
504:							"source-address":      {args: 1, multi: true, children: nil},
505:							"source-address-name": {args: 1, multi: true, children: nil},
506:							"destination-address": {args: 1, multi: true, children: nil},
507:							"destination-port":    {args: 1, multi: true, children: nil},
508:							"protocol":            {args: 1, multi: true, children: nil},
509:							"application":         {args: 1, multi: true, children: nil},
513:								"pool": {args: 1, valueHint: ValueHintPoolName, children: nil},
539:				"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
540:					"address": {args: 1, multi: true, children: nil},
546:				"address": {args: 2, multi: true, children: nil},
547:				"address-set": {args: 1, valueHint: ValueHintAddressName, children: map[string]*schemaNode{
548:					"address":     {args: 1, multi: true, children: nil},
549:					"address-set": {args: 1, multi: true, valueHint: ValueHintAddressName, children: nil},
557:			"source-interface": {args: 1, valueHint: ValueHintInterfaceName, children: nil},
558:			"stream": {args: 1, valueHint: ValueHintStreamName, children: map[string]*schemaNode{
696:	"interfaces": {desc: "Interface configuration", wildcard: &schemaNode{valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
737:		"unit": {desc: "Logical unit number", args: 1, valueHint: ValueHintUnitNumber, placeholder: "<unit-number>", children: map[string]*schemaNode{
738:			"description":    {desc: "Text description", args: 1, placeholder: "<text>", children: nil},
740:			"vlan-id":        {desc: "VLAN ID", args: 1, placeholder: "<number>", children: nil},
741:			"inner-vlan-id":  {desc: "Inner VLAN ID", args: 1, placeholder: "<number>", children: nil},
743:				"source":          {desc: "Tunnel source address", args: 1, placeholder: "<address>", children: nil},
744:				"destination":     {desc: "Tunnel destination address", args: 1, placeholder: "<address>", children: nil},
745:				"mode":            {desc: "Tunnel mode", args: 1, placeholder: "<mode>", children: nil},
746:				"key":             {desc: "Tunnel key", args: 1, placeholder: "<key>", children: nil},
747:				"ttl":             {desc: "Time to live", args: 1, placeholder: "<number>", children: nil},
748:				"keepalive":       {desc: "Keepalive interval", args: 1, placeholder: "<seconds>", children: nil},
749:				"keepalive-retry": {desc: "Keepalive retry count", args: 1, placeholder: "<number>", children: nil},
751:					"destination": {desc: "Destination routing instance", args: 1, placeholder: "<name>", children: nil},
754:			"family": {desc: "Protocol family", compoundKey: true, children: map[string]*schemaNode{
756:					"mtu": {desc: "Maximum transmit packet size", args: 1, placeholder: "<size>", children: nil},
757:					"address": {desc: "IPv4 address", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
762:						"lease-time":              {desc: "Lease time", args: 1, placeholder: "<seconds>", children: nil},
763:						"retransmission-attempt":  {desc: "Retransmission attempts", args: 1, placeholder: "<number>", children: nil},
764:						"retransmission-interval": {desc: "Retransmission interval", args: 1, placeholder: "<seconds>", children: nil},
772:						"input":  {desc: "Input filter", args: 1, placeholder: "<filter-name>", children: nil},
773:						"output": {desc: "Output filter", args: 1, placeholder: "<filter-name>", children: nil},
777:					"mtu":         {desc: "Maximum transmit packet size", args: 1, placeholder: "<size>", children: nil},
779:					"address": {desc: "IPv6 address", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
788:						"input":  {desc: "Input filter", args: 1, placeholder: "<filter-name>", children: nil},
789:						"output": {desc: "Output filter", args: 1, placeholder: "<filter-name>", children: nil},
792:						"client-type":    {desc: "Client type", args: 1, placeholder: "<type>", children: nil},
793:						"client-ia-type": {desc: "Client IA type", args: 1, placeholder: "<type>", children: nil},
795:							"preferred-prefix-length": {desc: "Preferred prefix length", args: 1, placeholder: "<length>", children: nil},
796:							"sub-prefix-length":       {desc: "Sub-prefix length", args: 1, placeholder: "<length>", children: nil},
799:							"duid-type": {desc: "DUID type", args: 1, placeholder: "<type>", children: nil},
801:						"req-option": {desc: "Request option", args: 1, placeholder: "<option>", children: nil},
803:							"interface": {desc: "Interface", args: 1, placeholder: "<interface>", children: nil},
811:		"application": {desc: "Application name", args: 1, valueHint: ValueHintAppName, placeholder: "<name>", children: map[string]*schemaNode{
812:			"protocol":           {desc: "Protocol", args: 1, placeholder: "<protocol>", children: nil},
813:			"destination-port":   {desc: "Destination port", args: 1, placeholder: "<port>", children: nil},
814:			"source-port":        {desc: "Source port", args: 1, placeholder: "<port>", children: nil},
815:			"inactivity-timeout": {desc: "Inactivity timeout", args: 1, placeholder: "<seconds>", children: nil},
816:			"timeout":            {desc: "Timeout", args: 1, placeholder: "<seconds>", children: nil},
817:			"alg":                {desc: "Application layer gateway", args: 1, placeholder: "<alg>", children: nil},
818:			"description":        {desc: "Description", args: 1, placeholder: "<text>", children: nil},
819:			"term":               {desc: "Term", args: 1, placeholder: "<term>", children: nil},
821:		"application-set": {desc: "Application set", args: 1, valueHint: ValueHintAppSetName, placeholder: "<name>", children: nil},
825:			"route": {desc: "Static route", args: 1, placeholder: "<destination>", children: nil},
827:		"rib": {desc: "Routing information base", args: 1, placeholder: "<rib-name>", children: map[string]*schemaNode{
829:				"route": {desc: "Static route", args: 1, placeholder: "<destination>", children: nil},
832:		"autonomous-system": {desc: "Autonomous system number", args: 1, placeholder: "<as-number>", children: nil},
834:			"export": {desc: "Export policy", args: 1, multi: true, placeholder: "<policy>", children: nil},
836:		"rib-groups": {desc: "RIB groups", wildcard: &schemaNode{children: map[string]*schemaNode{
841:				"inet":  {desc: "IPv4 RIB group", args: 1, placeholder: "<group-name>", children: nil},
842:				"inet6": {desc: "IPv6 RIB group", args: 1, placeholder: "<group-name>", children: nil},
846:			"route": {desc: "Generated route", args: 1, placeholder: "<destination>", children: map[string]*schemaNode{
847:				"policy":  {desc: "Policy", args: 1, placeholder: "<policy>", children: nil},
853:		"community": {desc: "SNMP community", args: 1, placeholder: "<community-name>", children: map[string]*schemaNode{
854:			"authorization": {desc: "Authorization level", args: 1, placeholder: "<level>", children: nil},
856:		"trap-group": {desc: "Trap group", args: 1, placeholder: "<group-name>", children: nil},
860:					"user": {desc: "User name", args: 1, placeholder: "<user-name>", children: map[string]*schemaNode{
861:						"authentication-md5":    {desc: "MD5 authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
862:						"authentication-sha":    {desc: "SHA authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
863:						"authentication-sha256": {desc: "SHA256 authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
864:						"privacy-des":           {desc: "DES privacy", children: map[string]*schemaNode{"privacy-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
865:						"privacy-aes128":        {desc: "AES128 privacy", children: map[string]*schemaNode{"privacy-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
872:		"prefix-list": {desc: "Prefix list", args: 1, placeholder: "<name>", children: nil},
873:		"community": {desc: "Community", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
874:			"members": {desc: "Community members", args: 1, multi: true, placeholder: "<community>", children: nil},
876:		"as-path": {desc: "AS path", args: 2, multi: true, placeholder: "<name>", children: nil},
877:		"policy-statement": {desc: "Policy statement", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
878:			"term": {desc: "Term name", args: 1, placeholder: "<term-name>", children: map[string]*schemaNode{
880:					"protocol":     {desc: "Protocol", args: 1, placeholder: "<protocol>", children: nil},
881:					"prefix-list":  {desc: "Prefix list", args: 1, placeholder: "<list-name>", children: nil},
882:					"route-filter": {desc: "Route filter", args: 2, placeholder: "<prefix>", children: nil},
883:					"community":    {desc: "Community", args: 1, placeholder: "<community>", children: nil},
884:					"as-path":      {desc: "AS path", args: 1, placeholder: "<name>", children: nil},
889:					"next-hop":         {desc: "Next hop", args: 1, placeholder: "<address>", children: nil},
890:					"load-balance":     {desc: "Load balance", args: 1, placeholder: "<policy>", children: nil},
891:					"local-preference": {desc: "Local preference", args: 1, placeholder: "<value>", children: nil},
892:					"metric":           {desc: "Metric", args: 1, placeholder: "<value>", children: nil},
893:					"metric-type":      {desc: "Metric type", args: 1, placeholder: "<type>", children: nil},
894:					"community":        {desc: "Community", args: 1, placeholder: "<community>", children: nil},
895:					"origin":           {desc: "Origin", args: 1, placeholder: "<origin>", children: nil},
903:			"router-id":           {desc: "Router ID", args: 1, placeholder: "<address>", children: nil},
904:			"reference-bandwidth": {desc: "Reference bandwidth", args: 1, placeholder: "<bandwidth>", children: nil},
906:			"export":              {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
907:			"area": {desc: "OSPF area", args: 1, placeholder: "<area-id>", children: map[string]*schemaNode{
908:				"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
911:					"interface-type": {desc: "Interface type", args: 1, placeholder: "<type>", children: nil},
912:					"cost":           {desc: "Interface cost", args: 1, placeholder: "<cost>", children: nil},
914:						"md5": {desc: "MD5 authentication", args: 1, placeholder: "<key-id>", children: map[string]*schemaNode{
915:							"key": {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
917:						"simple-password": {desc: "Simple password", args: 1, placeholder: "<password>", children: nil},
920:						"minimum-interval": {desc: "Minimum interval", args: 1, placeholder: "<milliseconds>", children: nil},
921:						"multiplier":       {desc: "Multiplier", args: 1, placeholder: "<multiplier>", children: nil},
932:				"virtual-link": {desc: "Virtual link", args: 1, placeholder: "<router-id>", children: map[string]*schemaNode{
933:					"transit-area": {desc: "Transit area", args: 1, placeholder: "<area-id>", children: nil},
938:			"router-id": {desc: "Router ID", args: 1, placeholder: "<address>", children: nil},
939:			"export":    {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
940:			"area": {desc: "OSPFv3 area", args: 1, placeholder: "<area-id>", children: map[string]*schemaNode{
941:				"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
943:					"cost":    {desc: "Interface cost", args: 1, placeholder: "<cost>", children: nil},
948:			"local-as":         {desc: "Local AS number", args: 1, placeholder: "<as-number>", children: nil},
949:			"router-id":        {desc: "Router ID", args: 1, placeholder: "<address>", children: nil},
950:			"cluster-id":       {desc: "Cluster ID", args: 1, placeholder: "<id>", children: nil},
957:				"half-life":    {desc: "Half life", args: 1, placeholder: "<minutes>", children: nil},
958:				"reuse":        {desc: "Reuse threshold", args: 1, placeholder: "<value>", children: nil},
959:				"suppress":     {desc: "Suppress threshold", args: 1, placeholder: "<value>", children: nil},
960:				"max-suppress": {desc: "Max suppress time", args: 1, placeholder: "<minutes>", children: nil},
962:			"export": {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
963:			"group": {desc: "BGP group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
964:				"peer-as":            {desc: "Peer AS number", args: 1, placeholder: "<as-number>", children: nil},
965:				"description":        {desc: "Description", args: 1, placeholder: "<text>", children: nil},
966:				"multihop":           {desc: "Multihop TTL", args: 1, placeholder: "<ttl>", children: nil},
967:				"export":             {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
968:				"authentication-key": {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
970:				"loops":              {desc: "Loops", args: 1, placeholder: "<count>", children: nil},
972:				"family": {desc: "Address family", compoundKey: true, children: map[string]*schemaNode{
976:								"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
983:								"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
989:					"minimum-interval": {desc: "Minimum interval", args: 1, placeholder: "<milliseconds>", children: nil},
990:					"multiplier":       {desc: "Multiplier", args: 1, placeholder: "<multiplier>", children: nil},
992:				"neighbor": {desc: "BGP neighbor", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
993:					"description":            {desc: "Description", args: 1, placeholder: "<text>", children: nil},
994:					"peer-as":                {desc: "Peer AS number", args: 1, placeholder: "<as-number>", children: nil},
995:					"multihop":               {desc: "Multihop TTL", args: 1, placeholder: "<ttl>", children: nil},
996:					"authentication-key":     {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
999:					"loops":                  {desc: "Loops", args: 1, placeholder: "<count>", children: nil},
1001:					"family": {desc: "Address family", compoundKey: true, children: map[string]*schemaNode{
1005:									"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
1012:									"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
1018:						"minimum-interval": {desc: "Minimum interval", args: 1, placeholder: "<milliseconds>", children: nil},
1019:						"multiplier":       {desc: "Multiplier", args: 1, placeholder: "<multiplier>", children: nil},
1025:			"group":               {desc: "Group", args: 1, placeholder: "<group-name>", children: nil},
1026:			"neighbor":            {desc: "Neighbor", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: nil},
1027:			"passive-interface":   {desc: "Passive interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: nil},
1028:			"redistribute":        {desc: "Redistribute", args: 1, placeholder: "<protocol>", children: nil},
1029:			"authentication-key":  {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
1030:			"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>", children: nil},
1033:			"net":     {desc: "NET address", args: 1, placeholder: "<net-address>", children: nil},
1034:			"level":   {desc: "Level", args: 1, placeholder: "<level>", children: nil},
1035:			"is-type": {desc: "IS type", args: 1, placeholder: "<type>", children: nil},
1036:			"export":  {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
1037:			"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
1038:				"level":               {desc: "Level", args: 1, placeholder: "<level>", children: nil},
1040:				"metric":              {desc: "Metric", args: 1, placeholder: "<value>", children: nil},
1041:				"authentication-key":  {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
1042:				"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>", children: nil},
1044:					"minimum-interval": {desc: "Minimum interval", args: 1, placeholder: "<milliseconds>", children: nil},
1045:					"multiplier":       {desc: "Multiplier", args: 1, placeholder: "<multiplier>", children: nil},
1048:			"authentication-key":  {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
1049:			"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>", children: nil},
1054:			"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
1055:				"prefix":     {desc: "Prefix", args: 1, placeholder: "<prefix>", children: nil}, // prefix <prefix/len>
1056:				"preference": {desc: "Preference", args: 1, placeholder: "<preference>", children: nil},
1057:				"nat-prefix": {desc: "NAT prefix", args: 1, placeholder: "<prefix>", children: map[string]*schemaNode{
1058:					"lifetime": {desc: "Lifetime", args: 1, placeholder: "<seconds>", children: nil},
1060:				"nat64prefix": {desc: "NAT64 prefix", args: 1, placeholder: "<prefix>", children: map[string]*schemaNode{
1061:					"lifetime": {desc: "Lifetime", args: 1, placeholder: "<seconds>", children: nil},
1066:			"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
1069:			"transmit-interval": {desc: "Transmit interval", args: 1, placeholder: "<seconds>", children: nil},
1070:			"hold-multiplier":   {desc: "Hold multiplier", args: 1, placeholder: "<multiplier>", children: nil},
1125:					"family": {compoundKey: true, children: map[string]*schemaNode{
1126:						"inet": {wildcard: &schemaNode{children: map[string]*schemaNode{
1136:			"queue": {args: 2, multi: true, children: nil},
1139:			"dscp": {args: 1, multi: true, children: map[string]*schemaNode{
1140:				"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
1141:					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
1142:						"code-points": {args: 1, multi: true, children: nil},
1146:			"ieee-802.1": {args: 1, multi: true, children: map[string]*schemaNode{
1147:				"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
1148:					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
1149:						"code-points": {args: 1, multi: true, children: nil},
1155:			"dscp": {args: 1, multi: true, children: map[string]*schemaNode{
1156:				"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
1157:					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
1159:						"code-points": {args: 1, multi: true, children: nil},
1164:		"schedulers": {args: 1, multi: true, children: map[string]*schemaNode{
1173:		"scheduler-maps": {args: 1, multi: true, children: map[string]*schemaNode{
1174:			"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
1178:		"interfaces": {args: 1, multi: true, children: map[string]*schemaNode{
1179:			"unit": {args: 1, multi: true, children: map[string]*schemaNode{
1195:				"ifindex": {args: 1, multi: true, children: map[string]*schemaNode{
1196:					"queue": {args: 1, multi: true, children: map[string]*schemaNode{
1210:		"policer": {args: 1, multi: true, children: map[string]*schemaNode{
1221:		"three-color-policer": {args: 1, multi: true, children: map[string]*schemaNode{
1242:		"family": {compoundKey: true, children: map[string]*schemaNode{
1247:							"source-address":          {args: 1, multi: true, children: nil},
1248:							"destination-address":     {args: 1, multi: true, children: nil},
1251:							"protocol":                {args: 1, multi: true, children: nil},
1252:							"dscp":                    {args: 1, multi: true, children: nil},
1253:							"destination-port":        {args: 1, multi: true, children: nil},
1254:							"source-port":             {args: 1, multi: true, children: nil},
1255:							"icmp-type":               {args: 1, multi: true, children: nil},
1256:							"icmp-code":               {args: 1, multi: true, children: nil},
1257:							"tcp-flags":               {args: 1, multi: true, children: nil},
1291:							"source-address":          {args: 1, multi: true, children: nil},
1292:							"destination-address":     {args: 1, multi: true, children: nil},
1295:							"protocol":                {args: 1, multi: true, children: nil},
1296:							"traffic-class":           {args: 1, multi: true, children: nil},
1297:							"destination-port":        {args: 1, multi: true, children: nil},
1298:							"source-port":             {args: 1, multi: true, children: nil},
1299:							"icmp-type":               {args: 1, multi: true, children: nil},
1300:							"icmp-code":               {args: 1, multi: true, children: nil},
1301:							"tcp-flags":               {args: 1, multi: true, children: nil},
1334:		"host-name":     {desc: "System hostname", args: 1, placeholder: "<hostname>", children: nil},
1335:		"domain-name":   {desc: "Domain name", args: 1, placeholder: "<domain>", children: nil},
1336:		"domain-search": {desc: "Domain search list", args: 1, multi: true, placeholder: "<domain>", children: nil},
1337:		"time-zone":     {desc: "System time zone", args: 1, placeholder: "<timezone>", children: nil},
1339:		"name-server":   {desc: "DNS name server", args: 1, placeholder: "<address>", children: nil},
1340:		"backup-router": {desc: "Backup router", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
1341:			"destination": {desc: "Destination network", args: 1, placeholder: "<network>", children: nil},
1344:			"encrypted-password": {desc: "Encrypted password", args: 1, placeholder: "<password>", children: nil},
1345:			"ssh-ed25519":        {desc: "SSH ED25519 public key", args: 1, placeholder: "<key>", children: nil},
1346:			"ssh-rsa":            {desc: "SSH RSA public key", args: 1, placeholder: "<key>", children: nil},
1347:			"ssh-dsa":            {desc: "SSH DSA public key", args: 1, placeholder: "<key>", children: nil},
1352:				"archive-sites":      {desc: "Archive site URL", args: 1, placeholder: "<url>", children: nil},
1356:			"pseudorandom-function": {desc: "Pseudorandom function", args: 1, placeholder: "<function>", children: nil},
1360:				"url": {desc: "Autoupdate URL", args: 1, placeholder: "<url>", children: nil},
1368:			"server": {desc: "NTP server", args: 1, placeholder: "<address>", children: nil},
1369:			"threshold": {desc: "Threshold", args: 1, placeholder: "<seconds>", children: map[string]*schemaNode{
1370:				"action": {desc: "Action on threshold", args: 1, placeholder: "<action>", children: nil},
1374:			"user": {desc: "Syslog user", args: 1, placeholder: "<user>", children: nil},
1375:			"host": {desc: "Syslog host", args: 1, placeholder: "<host>", children: nil},
1376:			"file": {desc: "Syslog file", args: 1, placeholder: "<filename>", children: nil},
1379:			"user": {desc: "User name", args: 1, placeholder: "<username>", children: map[string]*schemaNode{
1380:				"uid":            {desc: "User ID", args: 1, placeholder: "<uid>", children: nil},
1381:				"class":          {desc: "Login class", args: 1, placeholder: "<class>", children: nil},
1385:		"dataplane-type": {desc: "Dataplane type", args: 1, placeholder: "<type>", children: nil},
1398:				"interface":            {args: 1, multi: true, desc: "Optional participating Linux interface filter", children: nil},
1416:			"ports": {wildcard: &schemaNode{children: map[string]*schemaNode{
1424:				"root-login": {desc: "Root login permission", args: 1, placeholder: "<permit|deny>", children: nil},
1431:					"interface": {desc: "Interface", args: 1, placeholder: "<interface>", children: nil},
1435:					"interface":                    {desc: "Interface", args: 1, placeholder: "<interface>", children: nil},
1438:					"user": {desc: "User name", wildcard: &schemaNode{placeholder: "<username>", children: map[string]*schemaNode{
1439:						"password": {desc: "Password", args: 1, placeholder: "<password>", children: nil},
1441:					"api-key": {desc: "API key", args: 1, placeholder: "<key>", children: nil},
1446:				"group": {desc: "DHCP group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
1447:					"pool": {desc: "Address pool", args: 1, placeholder: "<pool-name>", children: nil},
1451:				"group": {desc: "DHCPv6 group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
1452:					"pool": {desc: "Address pool", args: 1, placeholder: "<pool-name>", children: nil},
1463:					"target":           {desc: "Target IP, hostname, or URL", wildcard: &schemaNode{placeholder: "<target>", desc: "Target IP, hostname, or URL"}, children: map[string]*schemaNode{"url": {args: 1, desc: "HTTP target URL", children: nil}}},
1506:		"family": {compoundKey: true, children: map[string]*schemaNode{
1514:				"family": {compoundKey: true, children: map[string]*schemaNode{
1539:	"bridge-domains": {wildcard: &schemaNode{desc: "Bridge domain name", children: map[string]*schemaNode{
1540:		"vlan-id-list":      {args: 1, multi: true, desc: "VLAN IDs in this bridge domain", children: nil},
1544:	"routing-instances": {wildcard: &schemaNode{children: map[string]*schemaNode{
1568:					"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
1599:				"export":    {args: 1, multi: true, children: nil},
1601:					"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
1621:				"export":  {args: 1, multi: true, children: nil},
1622:				"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
1773:			if childSchema.midKeyword != "" && childSchema.midKeywordAt > 0 {
1775:				// If the last consumed token is a partial match for the midKeyword, suggest it.
1776:				if nextPos == childSchema.midKeywordAt+1 && consumed > 1 {
1778:					if lastToken != childSchema.midKeyword && strings.HasPrefix(childSchema.midKeyword, lastToken) {
1779:						return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}
1782:				// If we need to complete the midKeyword position, suggest it.
1783:				if nextPos == childSchema.midKeywordAt {
1784:					return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}

exec
/bin/bash -lc "nl -ba pkg/configstore/store.go | sed -n '160,205p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   160	// like `transmit-rate asd`. cfg is nil at this point because we haven't
   161	// compiled yet; the schedulers validators don't need it.
   162	func (s *Store) compileTree(tree *config.ConfigTree) (*config.Config, error) {
   163		if err := s.schemaValidateExpandedTree(tree); err != nil {
   164			return nil, err
   165		}
   166		if s.nodeID >= 0 {
   167			return config.CompileConfigForNode(tree, s.nodeID)
   168		}
   169		return config.CompileConfig(tree)
   170	}
   171	
   172	func (s *Store) schemaValidateExpandedTree(tree *config.ConfigTree) error {
   173		if tree == nil {
   174			return nil
   175		}
   176		expanded := tree.Clone()
   177		if s.nodeID >= 0 {
   178			vars := map[string]string{"node": fmt.Sprintf("node%d", s.nodeID)}
   179			if err := expanded.ExpandGroupsWithVars(vars); err != nil {
   180				return fmt.Errorf("apply-groups: %w", err)
   181			}
   182			return cmdtree.SchemaValidate(expanded, nil)
   183		}
   184		if err := expanded.ExpandGroups(); err != nil {
   185			if strings.Contains(err.Error(), `undefined group "${node}"`) {
   186				vars := map[string]string{"node": "node0"}
   187				if err2 := expanded.ExpandGroupsWithVars(vars); err2 != nil {
   188					return fmt.Errorf("apply-groups: %w", err2)
   189				}
   190			} else {
   191				return fmt.Errorf("apply-groups: %w", err)
   192			}
   193		}
   194		return cmdtree.SchemaValidate(expanded, nil)
   195	}
   196	
   197	// SyncApply applies a config received from the cluster primary.
   198	// Bypasses cluster read-only checks. The chassisPreserve function, if set,
   199	// lets the caller patch the parsed tree before compiling (e.g. to preserve
   200	// local chassis cluster settings).
   201	func (s *Store) SyncApply(content string, chassisPreserve func(*config.ConfigTree)) (*config.Config, error) {
   202		s.mu.Lock()
   203		defer s.mu.Unlock()
   204	
   205		tree, errs := config.NewParser(content).Parse()

exec
/bin/bash -lc "nl -ba pkg/grpcapi/server_cluster.go | sed -n '549,590p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   549	func (s *Server) completeConfigPairs(words []string, partial string) []completionPair {
   550		if len(words) == 0 {
   551			return filterCompletionPairs(cmdtree.ConfigTopLevel, partial)
   552		}
   553	
   554		resolvedTop, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(cmdtree.ConfigTopLevel), words[0])
   555		if !ok {
   556			if len(words) == 1 {
   557				return filterCompletionPairs(cmdtree.ConfigTopLevel, words[0])
   558			}
   559			return nil
   560		}
   561	
   562		switch resolvedTop {
   563		case "set", "delete", "show", "edit":
   564			pathWords := words[1:]
   565			if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(pathWords); resolved {
   566				pathWords = resolvedPath
   567			}
   568			schemaCompletions := config.CompleteSetPathWithValues(pathWords, s.completionValueProvider())
   569			if schemaCompletions == nil {
   570				return nil
   571			}
   572			var pairs []completionPair
   573			for _, sc := range schemaCompletions {
   574				if strings.HasPrefix(sc.Name, partial) {
   575					pairs = append(pairs, completionPair{name: sc.Name, desc: sc.Desc})
   576				}
   577			}
   578			return pairs
   579		case "run":
   580			var cfg *config.Config
   581			if s.store != nil {
   582				cfg = s.store.ActiveConfig()
   583			}
   584			names := cmdtree.CompleteFromTree(cmdtree.OperationalTree, words[1:], partial, cfg)
   585			var pairs []completionPair
   586			for _, name := range names {
   587				pairs = append(pairs, completionPair{name: name})
   588			}
   589			return pairs
   590		case "commit", "load":

exec
/bin/bash -lc "nl -ba pkg/config/ast.go | sed -n '1668,1700p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
  1668	// CompleteSetPath returns possible completions for a partial set/delete path.
  1669	// It walks setSchema consuming tokens; at the current position it returns
  1670	// child keyword names. If the current position expects a dynamic argument
  1671	// (wildcard or args > 0), it returns nil (user must type a name).
  1672	func CompleteSetPath(tokens []string) []string {
  1673		results := CompleteSetPathWithValues(tokens, nil)
  1674		if results == nil {
  1675			return nil
  1676		}
  1677		names := make([]string, len(results))
  1678		for i, r := range results {
  1679			names[i] = r.Name
  1680		}
  1681		return names
  1682	}
  1683	
  1684	// CompleteSetPathWithValues is like CompleteSetPath but uses a ValueProvider
  1685	// to suggest dynamic values at positions where schema expects a name argument.
  1686	// Returns SchemaCompletion pairs with names and descriptions.
  1687	func CompleteSetPathWithValues(tokens []string, provider ValueProvider) []SchemaCompletion {
  1688		schema := setSchema
  1689		i := 0
  1690		var path []string // consumed tokens for context
  1691	
  1692		for i < len(tokens) {
  1693			if schema == nil {
  1694				return nil
  1695			}
  1696			if schema.children == nil && schema.wildcard == nil {
  1697				return nil // at a leaf with no further options
  1698			}
  1699	
  1700			keyword := tokens[i]

exec
/bin/bash -lc "nl -ba pkg/config/ast.go | sed -n '1843,1915p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
  1843	// ResolveConsumedSetPathTokens expands uniquely matching keyword prefixes in a
  1844	// token list that is already known to contain only consumed words, not the
  1845	// current partial token being completed.
  1846	func ResolveConsumedSetPathTokens(tokens []string) ([]string, bool) {
  1847		schema := setSchema
  1848		i := 0
  1849		var resolved []string
  1850	
  1851		for i < len(tokens) {
  1852			if schema == nil {
  1853				return nil, false
  1854			}
  1855	
  1856			keyword := tokens[i]
  1857			resolvedKeyword := keyword
  1858			var childSchema *schemaNode
  1859			if schema.children != nil {
  1860				if s, ok := schema.children[keyword]; ok {
  1861					childSchema = s
  1862				} else {
  1863					var matches []string
  1864					for name := range schema.children {
  1865						if strings.HasPrefix(name, keyword) {
  1866							matches = append(matches, name)
  1867						}
  1868					}
  1869					if len(matches) != 1 {
  1870						return nil, false
  1871					}
  1872					resolvedKeyword = matches[0]
  1873					childSchema = schema.children[resolvedKeyword]
  1874				}
  1875			}
  1876			if childSchema == nil && schema.wildcard != nil {
  1877				childSchema = schema.wildcard
  1878			}
  1879			if childSchema == nil {
  1880				return nil, false
  1881			}
  1882	
  1883			resolved = append(resolved, resolvedKeyword)
  1884			nodeKeyCount := 1 + childSchema.args
  1885			end := i + nodeKeyCount
  1886			if end > len(tokens) {
  1887				return resolved, true
  1888			}
  1889			if end-i > 1 {
  1890				resolved = append(resolved, tokens[i+1:end]...)
  1891			}
  1892			i += nodeKeyCount
  1893	
  1894			if childSchema.compoundKey && i < len(tokens) {
  1895				subKeyword := tokens[i]
  1896				if sub, ok := childSchema.children[subKeyword]; ok {
  1897					resolved = append(resolved, subKeyword)
  1898					i++
  1899					childSchema = sub
  1900				} else {
  1901					var matches []string
  1902					for name := range childSchema.children {
  1903						if strings.HasPrefix(name, subKeyword) {
  1904							matches = append(matches, name)
  1905						}
  1906					}
  1907					if len(matches) != 1 {
  1908						return nil, false
  1909					}
  1910					resolved = append(resolved, matches[0])
  1911					i++
  1912					childSchema = childSchema.children[matches[0]]
  1913				}
  1914			}
  1915	

exec
/bin/bash -lc "rg -n \"ValueType|ValueAny|ValueRate|ValueByteSize|ValueInteger|ValueEnumOf|ValueBool|ValueIdentifier|Placeholder\\(\" --glob '*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/cmdtree/tree.go:22:// ValueType classifies the value a typed-leaf node accepts. #1319 Phase 1.
pkg/cmdtree/tree.go:24:// The zero value, ValueAny, is the legacy behaviour: any string is accepted
pkg/cmdtree/tree.go:25:// and no schema-time validation runs. Specifying a non-zero ValueType opts
pkg/cmdtree/tree.go:35:type ValueType int
pkg/cmdtree/tree.go:38:	// ValueAny is the legacy default: any string accepted, no validation.
pkg/cmdtree/tree.go:39:	ValueAny ValueType = iota
pkg/cmdtree/tree.go:40:	// ValueRate is a Junos bandwidth value (bits/sec) with k/m/g suffix.
pkg/cmdtree/tree.go:42:	ValueRate
pkg/cmdtree/tree.go:43:	// ValueByteSize is a byte-count value with k/m/g suffix.
pkg/cmdtree/tree.go:45:	ValueByteSize
pkg/cmdtree/tree.go:46:	// ValueByteSizeOrPercent is a scheduler buffer size: byte-count with
pkg/cmdtree/tree.go:48:	ValueByteSizeOrPercent
pkg/cmdtree/tree.go:51:	// ValueInteger is a bare integer. Range is enforced by the leaf's
pkg/cmdtree/tree.go:53:	ValueInteger
pkg/cmdtree/tree.go:54:	// ValueIdentifier is a bare Junos identifier (no spaces, no quotes).
pkg/cmdtree/tree.go:55:	ValueIdentifier
pkg/cmdtree/tree.go:56:	// ValueEnumOf is one of a fixed set of names. The allowed set lives
pkg/cmdtree/tree.go:58:	ValueEnumOf
pkg/cmdtree/tree.go:59:	// ValueBool is "true" or "false".
pkg/cmdtree/tree.go:60:	ValueBool
pkg/cmdtree/tree.go:65:func (v ValueType) Placeholder() string {
pkg/cmdtree/tree.go:67:	case ValueRate:
pkg/cmdtree/tree.go:69:	case ValueByteSize:
pkg/cmdtree/tree.go:71:	case ValueByteSizeOrPercent:
pkg/cmdtree/tree.go:75:	case ValueInteger:
pkg/cmdtree/tree.go:77:	case ValueIdentifier:
pkg/cmdtree/tree.go:79:	case ValueEnumOf:
pkg/cmdtree/tree.go:81:	case ValueBool:
pkg/cmdtree/tree.go:101:// Phase 1 / #1319: optional typed-leaf fields (ValueType, ValueDesc,
pkg/cmdtree/tree.go:103:// value of ValueType is ValueAny — every existing Node is backward
pkg/cmdtree/tree.go:113:	// ValueType, if set to a non-ValueAny value, marks this node as a
pkg/cmdtree/tree.go:117:	ValueType ValueType
pkg/cmdtree/tree.go:136:// IsTypedLeaf reports whether the node carries a non-default ValueType,
pkg/cmdtree/tree.go:139:	return n.ValueType != ValueAny
pkg/cmdtree/tree.go:1029:			ValueType:     ValueRate,
pkg/cmdtree/tree.go:1039:			ValueType:     ValueEnumOf,
pkg/cmdtree/tree.go:1048:			ValueType:     ValueByteSizeOrPercent,
pkg/cmdtree/tree.go:1131:func isPlaceholder(name string) bool {
pkg/cmdtree/tree.go:1136:func findPlaceholder(tree map[string]*Node) *Node {
pkg/cmdtree/tree.go:1138:		if isPlaceholder(name) {
pkg/cmdtree/tree.go:1179:	// derived from ValueType instead of an explicit "<name>" node).
pkg/cmdtree/tree.go:1197:			if ph := findPlaceholder(current); ph != nil {
pkg/cmdtree/tree.go:1234:		if ph := currentNode.ValueType.Placeholder(); ph != "" {
pkg/cmdtree/tree.go:1264:			if ph := findPlaceholder(current); ph != nil {
pkg/cmdtree/tree.go:1330:	if ph := node.ValueType.Placeholder(); ph != "" {
pkg/cmdtree/tree.go:1402:			if ph := findPlaceholder(current); ph != nil {
pkg/cmdtree/schema_validate.go:10:// typed-leaf metadata (Node.ValueType + Node.Validator) and fails the
pkg/cmdtree/schema_validate.go:16://   - Every other subsystem is on ValueAny by default and skipped by
pkg/cmdtree/schema_validate.go:20:// ValueType + Validator on the corresponding cmdtree Nodes and adding
pkg/cmdtree/schema_validate.go:169:// walk one token at a time; if the schemaNode is typed (ValueType !=
pkg/cmdtree/schema_validate.go:170:// ValueAny) and has a Validator, the first token is the value and the

exec
/bin/bash -lc "nl -ba pkg/cmdtree/tree.go | sed -n '132,145p;1168,1242p;1318,1338p;1388,1412p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   132	func (n *Node) HasDynamic() bool {
   133		return n.DynamicFn != nil || n.ContextDynamicFn != nil
   134	}
   135	
   136	// IsTypedLeaf reports whether the node carries a non-default ValueType,
   137	// i.e. it expects exactly one typed value at the next slot.
   138	func (n *Node) IsTypedLeaf() bool {
   139		return n.ValueType != ValueAny
   140	}
   141	
   142	// DynamicValues returns dynamic completion values, preferring ContextDynamicFn.
   143	func (n *Node) DynamicValues(cfg *config.Config, words []string) []string {
   144		if n.ContextDynamicFn != nil {
   145			return n.ContextDynamicFn(cfg, words)
  1168		return "", nil, matches, false
  1169	}
  1170	
  1171	// CompleteFromTree walks the tree to find completion candidates for the given words and partial.
  1172	func CompleteFromTree(tree map[string]*Node, words []string, partial string, cfg *config.Config) []string {
  1173		current := tree
  1174		var currentNode *Node
  1175		// parentTyped tracks whether the most recent matched node is a typed
  1176		// leaf whose value slot has not yet been consumed. If so, the next
  1177		// unmatched word is the value and we stay at the same children
  1178		// level after consuming it (#1319: same shape as <placeholder> but
  1179		// derived from ValueType instead of an explicit "<name>" node).
  1180		parentTyped := false
  1181		dynamicConsumed := false
  1182		for wi, w := range words {
  1183			dynamicConsumed = false
  1184			_, node, matches, ok := resolveTreeWord(current, w)
  1185			if !ok {
  1186				if parentTyped {
  1187					// Typed-leaf value slot consumed this word; stay at same level.
  1188					parentTyped = false
  1189					dynamicConsumed = true
  1190					continue
  1191				}
  1192				if currentNode != nil && currentNode.HasDynamic() {
  1193					dynamicConsumed = true
  1194					continue
  1195				}
  1196				// Check for placeholder node that consumes any value
  1197				if ph := findPlaceholder(current); ph != nil {
  1198					// Placeholder consumed this word. If the placeholder has
  1199					// children, descend so follow-on keywords can complete
  1200					// (e.g. "show route <dest> exact"). Otherwise stay at this
  1201					// level so sibling options remain available (e.g. "ping
  1202					// <host> count").
  1203					if ph.Children != nil {
  1204						currentNode = ph
  1205						current = ph.Children
  1206					}
  1207					dynamicConsumed = true
  1208					continue
  1209				}
  1210				if wi == len(words)-1 && len(matches) > 0 {
  1211					return matches
  1212				}
  1213				return nil
  1214			}
  1215			currentNode = node
  1216			parentTyped = node.IsTypedLeaf()
  1217			if node.Children == nil {
  1218				if node.HasDynamic() && wi < len(words)-1 {
  1219					dynamicConsumed = true
  1220					continue
  1221				}
  1222				if node.HasDynamic() && cfg != nil {
  1223					return FilterPrefix(node.DynamicValues(cfg, words), partial)
  1224				}
  1225				return nil
  1226			}
  1227			current = node.Children
  1228		}
  1229		candidates := KeysOf(current)
  1230		if parentTyped && currentNode != nil {
  1231			// At the value slot of a typed leaf: surface examples for
  1232			// `?` completion.
  1233			candidates = append(candidates, currentNode.ValueExamples...)
  1234			if ph := currentNode.ValueType.Placeholder(); ph != "" {
  1235				candidates = append(candidates, ph)
  1236			}
  1237		}
  1238		if !dynamicConsumed && currentNode != nil && currentNode.HasDynamic() && cfg != nil {
  1239			candidates = append(candidates, currentNode.DynamicValues(cfg, words)...)
  1240		}
  1241		return FilterPrefix(candidates, partial)
  1242	}
  1318					candidates = append(candidates, Candidate{Name: name, Desc: "(configured)"})
  1319				}
  1320			}
  1321		}
  1322		return candidates
  1323	}
  1324	
  1325	// typedLeafCandidates returns the `?` completion entries for the value
  1326	// slot of a typed leaf: a single placeholder entry carrying the value's
  1327	// description, plus one entry per declared example.
  1328	func typedLeafCandidates(node *Node, partial string) []Candidate {
  1329		var out []Candidate
  1330		if ph := node.ValueType.Placeholder(); ph != "" {
  1331			desc := node.ValueDesc
  1332			if desc == "" {
  1333				desc = node.Desc
  1334			}
  1335			if strings.HasPrefix(ph, partial) {
  1336				out = append(out, Candidate{Name: ph, Desc: desc})
  1337			}
  1338		}
  1388			tree = OperationalTree
  1389		}
  1390	
  1391		// Walk operational tree
  1392		current := tree
  1393		var currentNode *Node
  1394		for _, w := range words {
  1395			_, node, _, ok := resolveTreeWord(current, w)
  1396			if !ok {
  1397				// Dynamic value — skip but stay at same children level.
  1398				if currentNode != nil && currentNode.HasDynamic() {
  1399					continue
  1400				}
  1401				// Placeholder node consumes any value.
  1402				if ph := findPlaceholder(current); ph != nil {
  1403					if ph.Children != nil {
  1404						currentNode = ph
  1405						current = ph.Children
  1406					}
  1407					continue
  1408				}
  1409				return ""
  1410			}
  1411			currentNode = node
  1412			if node.Children == nil {

exec
/bin/bash -lc "rg -n \"github.com/psaab/xpf/pkg/cmdtree|package config\" pkg/config -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/config/parser_services_test.go:1:package config
pkg/config/parser_ast_test.go:1:package config
pkg/config/compiler_nat.go:1:package config
pkg/config/parser_cluster_test.go:1:package config
pkg/config/ast_groups.go:1:package config
pkg/config/compiler_interfaces.go:1:package config
pkg/config/xfrmi_test.go:1:package config
pkg/config/schema_validators.go:1:package config
pkg/config/completion_prefix_test.go:1:package config
pkg/config/compiler_security.go:1:package config
pkg/config/lexer.go:2:package config
pkg/config/compiler_protocols.go:1:package config
pkg/config/ast_format.go:1:package config
pkg/config/compiler_firewall.go:1:package config
pkg/config/schema_validate_test.go:1:package config_test
pkg/config/schema_validate_test.go:13:	"github.com/psaab/xpf/pkg/cmdtree"
pkg/config/types_test.go:1:package config
pkg/config/parser_system_test.go:1:package config
pkg/config/ast.go:1:package config
pkg/config/parser_class_of_service_test.go:1:package config
pkg/config/parser_security_test.go:1:package config
pkg/config/compiler_system.go:1:package config
pkg/config/compiler_ipsec.go:1:package config
pkg/config/ast_edit.go:1:package config
pkg/config/compiler_test.go:1:package config
pkg/config/xfrmi.go:1:package config
pkg/config/compiler_services.go:1:package config
pkg/config/parser.go:1:package config
pkg/config/compiler.go:1:package config
pkg/config/predefined.go:1:package config
pkg/config/types.go:1:package config
pkg/config/compiler_routing.go:1:package config
pkg/config/parser_routing_test.go:1:package config
pkg/config/compiler_class_of_service.go:1:package config

exec
/bin/bash -lc "nl -ba docs/research/1319-typed-leaf/plan.md | sed -n '86,170p;176,250p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
    86	Per the #1319 issue comment (Codex task-mpnhv0ui-j30019 PLAN-NEEDS-MAJOR,
    87	AGY review-mpnhva3y-h1n07y PLAN-KILL): `walkSchedulers` is hand-rolled
    88	for a 2-deep tree and does not generalize to the 5–7-deep chassis-cluster
    89	AST; the `SchemaValidate` early-return on absent class-of-service skips
    90	all other subtrees; AST-shape sketches were wrong; and the Junos numeric
    91	ranges were wrong. Recommended split: (1) generic recursive walker first,
    92	(2) then per-subsystem typed leaves with correct ranges.
    93	
    94	## 3. Blast radius (quantified)
    95	
    96	- **~539** `args>0` value-consuming leaves in `setSchema` across ~18
    97	  top-level subtrees (`security`, `interfaces`, `routing-options`,
    98	  `policy-options`, `protocols`, `chassis`, `class-of-service`,
    99	  `firewall`, `system`, `services`, `forwarding-options`,
   100	  `routing-instances`, ...).
   101	- **3** of those are typed today (schedulers). So **~536 untyped value
   102	  leaves** remain. "Touch every leaf" = ~536-leaf churn — confirmed
   103	  infeasible as one PR; **incremental per-subsystem is mandatory** and is
   104	  what the issue's own migration plan calls for.
   105	- Most-impactful value types by frequency: integer-with-range,
   106	  enum-of-fixed-set, rate/byte-size, IP/CIDR, identifier-cross-ref
   107	  (forwarding-class, scheduler, zone names).
   108	
   109	## 4. Goals / non-goals
   110	
   111	**Goals**
   112	- A single recursive walker that validates any typed subtree (kills the
   113	  per-subtree hand-rolled walker problem).
   114	- Wire typed-leaf value completion into the **production config-mode
   115	  `set` completer** so symptom 1 is actually fixed for typed leaves.
   116	- Reconcile the dual-tree so adding a typed leaf is one edit, not two
   117	  trees kept in sync by hand.
   118	- Correct, defensible value validation per migrated subsystem.
   119	
   120	**Non-goals (defer)**
   121	- Typing all ~536 leaves in one go.
   122	- Schema-aware show/diff formatters; auto-generated config reference;
   123	  cross-cluster schema versioning (issue "out of scope").
   124	- Cross-reference validators that require compiled `cfg` (forwarding-class
   125	  must exist, etc.) — keep as a later sub-phase; today's compiler already
   126	  does some of these.
   127	
   128	## 5. Multiple path options for HOW to attach + reconcile the schema
   129	
   130	The issue proposes "extend cmdtree Node". The killed Phase 3a tried to
   131	extend the cmdtree overlay + hand-rolled walker. The real decision is how
   132	to handle the **dual tree** (§2.1). Three viable architectures:
   133	
   134	### Option A — Annotate `setSchema` directly (single tree, in pkg/config)
   135	
   136	Add `valueType ValueType`, `valueDesc string`, `valueExamples []string`,
   137	`validator LeafValidator` fields to `schemaNode` in `pkg/config/ast.go`.
   138	`CompleteSetPathWithValues` already walks `setSchema` and is the live
   139	completion path — it gains value-slot examples for free. A generic
   140	`SchemaValidate` walks the **same** `setSchema` over the AST. The cmdtree
   141	typed-leaf fields become operational/`run`-only; config-mode typed leaves
   142	live in `setSchema`.
   143	
   144	- **Pros:** one tree, the one the CLI already uses; symptom 1 fixed
   145	  inherently (completion path = validation path); generic walker is a
   146	  natural recursion over `schemaNode.children`; no cross-tree sync;
   147	  validators already in `pkg/config` (no import-cycle gymnastics).
   148	- **Cons:** contradicts the "cmdtree is SSOT" doctrine in CLAUDE.md —
   149	  config-mode typed values would live in `pkg/config`, not `pkg/cmdtree`.
   150	  Needs a doctrine-update note. cmdtree's `ConfigClassOfServiceSchedulers`
   151	  would be migrated/retired (small, 3 leaves).
   152	- **Churn:** moderate; concentrated in `pkg/config/ast.go`.
   153	
   154	### Option B — Make cmdtree the real SSOT; route `set` completion through it
   155	
   156	Build the full config-mode grammar in `cmdtree.ConfigTopLevel`
   157	(today sparse) and switch `pkg/cli/completion.go` + the gRPC completer to
   158	drive `set` completion from cmdtree instead of `setSchema`. `setSchema`
   159	is then derived from (or retired in favor of) cmdtree. Generic walker
   160	lives in cmdtree.
   161	
   162	- **Pros:** makes the doctrine true; one place to add a typed leaf.
   163	- **Cons:** **enormous** — `setSchema` is ~324 nodes with `args`,
   164	  `multi`, `midKeyword`, `compoundKey`, `valueHint`, `wildcard`
   165	  semantics that cmdtree's `Node` does not model. Rebuilding the entire
   166	  config grammar in cmdtree AND re-validating SetPath grouping (the
   167	  parser depends on `setSchema` for flat-set token grouping) is a
   168	  multi-PR rewrite with high regression risk on the parser. Out of
   169	  proportion to the issue.
   170	
   176	
   177	- **Pros:** no migration of existing trees; cmdtree stays the typed-leaf
   178	  home (doctrine-consistent).
   179	- **Cons:** keeps **two trees in sync by hand** for every typed leaf
   180	  (the exact maintainability failure the issue wants to end); the bridge
   181	  must replicate `setSchema`'s arg/midKeyword/compoundKey path-consumption
   182	  to map a path to a cmdtree node — fragile; doubles the per-leaf edit.
   183	
   184	### Recommendation (to be tested by reviewers)
   185	
   186	**Option A.** It is the only option where the completion path and the
   187	validation path are the same tree (so symptom 1 + symptom 2 are closed
   188	together and cannot drift), the generic walker is a trivial recursion,
   189	and there is no hand-sync. The doctrine cost (config-mode typed values
   190	live in `pkg/config`, not `pkg/cmdtree`) is real but is a documentation
   191	update, and CLAUDE.md's claim is already false for config-mode `set`
   192	today (§2.1) — Option A makes the doctrine *accurate* by stating that
   193	`setSchema` is the config-grammar SSOT and cmdtree is the
   194	operational-tree SSOT, with shared `ValueType`/validator types.
   195	
   196	**Type ownership (corrected v2 — Codex#1/SMR-D1).** `ValueType` currently
   197	lives in `pkg/cmdtree/tree.go:35` and `pkg/cmdtree` already imports
   198	`pkg/config` (`tree.go:19`). `pkg/config` therefore CANNOT reference
   199	`cmdtree.ValueType` — that is an import cycle. Only `LeafValidator` lives
   200	in `pkg/config` today. So Option A's first PR-1 step is a **mechanical
   201	move**: relocate `ValueType` + its constants + `Placeholder()` from
   202	`pkg/cmdtree/tree.go` into `pkg/config` (next to the validators), and add
   203	`type ValueType = config.ValueType` (+ const re-exports) aliases in
   204	`cmdtree` so its operational-tree leaves are unchanged. After the move,
   205	`schemaNode` can hold a `valueType config.ValueType` field with no cycle.
   206	
   207	## 6. Proposed plan (Option A), staged
   208	
   209	### PR 1 — Generic walker + completion wiring + reconcile (no new subsystems)
   210	
   211	0. **Move `ValueType` to `pkg/config`** (Codex#1/SMR-D1): relocate the
   212	   enum + constants + `Placeholder()` from `pkg/cmdtree/tree.go` into
   213	   `pkg/config`; re-export via `type ValueType = config.ValueType` aliases
   214	   in `cmdtree`. No behavior change; unblocks the cycle.
   215	1. **Add typed-leaf fields to `schemaNode`** (`pkg/config/ast.go`):
   216	   `valueType config.ValueType`, `valueDesc string`,
   217	   `valueExamples []string`, `validator LeafValidator`. Zero values =
   218	   today's behavior. **FIELDS ONLY** — PR 1 MUST NOT add or alter any
   219	   `children` map on a `schemaNode` (Codex#3/SMR-D2). SetPath's
   220	   replace-vs-container decision keys on `children==nil`
   221	   (`ast_edit.go:196`); flipping a `children:nil` leaf to a container is
   222	   a grouping regression. A SetPath grouping golden test (§9) pins this.
   223	2. **Populate the three schedulers leaves** in `setSchema` with the new
   224	   fields only: `transmit-rate` → `ValueRate`/`config.ValidateRate`
   225	   (its `exact` child already exists at `ast.go:1166` — unchanged),
   226	   `priority` → `ValueEnumOf`/`config.ValidateEnum([...])`,
   227	   `buffer-size` → `ValueByteSizeOrPercent`/`config.ValidateByteSizeOrPercent`.
   228	   **Do NOT add `buffer-size temporal`** (Codex#2/SMR-D3): it is in the
   229	   cmdtree overlay (`tree.go:1053`) but the compiler never consumes it
   230	   (`compiler_class_of_service.go` buffer-size case reads only the value).
   231	   Carrying it into `setSchema` would (a) add a `children` map — banned
   232	   by step 1 — and (b) violate the compiled-leaf-only invariant. Modifier
   233	   compiled-status table for schedulers: `exact` = compiled (keep);
   234	   `temporal` = NOT compiled (drop); `surplus-sharing`,
   235	   `equal-flow-enforcement` = presence-only, compiled (no value to type).
   236	3. `CompleteSetPathWithValues`: at the value slot, when the leaf has a
   237	   non-`ValueAny` `valueType`, surface `valueDesc` + `valueExamples` +
   238	   `placeholder` (this is the **symptom-1 fix that actually reaches the
   239	   CLI**). Coexists with the existing `valueHint`/`provider` path
   240	   (`ast.go:1789-1800`) — typed-value examples are additive to dynamic
   241	   provider results.
   242	4. **Generic recursive walker** replacing `walkSchedulers`. Contract
   243	   table (Codex#4/SMR-D4) — the walker descends `setSchema` against the
   244	   AST and must port every special case currently encoded in
   245	   `walkSchedulers` + `CompleteSetPathWithValues` + `SetPath`:
   246	
   247	   | schema feature | AST match rule |
   248	   |---|---|
   249	   | `args:0` container | match `Keys[0]==keyword`; recurse into `Children` |
   250	   | `args:N` named instance | consume keyword + N tokens from `Keys` (flat) or 1 key + N from `Keys[1:]` / children (hier); recurse |

exec
/bin/bash -lc "nl -ba docs/research/1319-typed-leaf/plan.md | sed -n '250,340p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   250	   | `args:N` named instance | consume keyword + N tokens from `Keys` (flat) or 1 key + N from `Keys[1:]` / children (hier); recurse |
   251	   | `compoundKey` | consume the following key as part of this node's key, then resolve the sub-child |
   252	   | `midKeyword`/`midKeywordAt` | the fixed keyword (`to-zone`) sits at arg position `midKeywordAt`; skip it when extracting values |
   253	   | `multi` | leaf may repeat; validate each occurrence; do not treat as replace |
   254	   | `wildcard` | instance-name slot; descend into wildcard schema |
   255	   | typed leaf (`valueType!=ValueAny`) | first non-modifier token is THE value → run `validator`; remaining tokens must match child keywords (e.g. `exact`) |
   256	   | modifier-only line | `transmit-rate exact` with no rate still fails (the existing `schedulerHasTypedTransmitRate` gate) |
   257	   | `groups { ... }` | already handled — walker runs on the apply-groups-EXPANDED clone (`store.go:182`), so group bodies are inlined before the walk |
   258	
   259	   The walker handles BOTH AST shapes (flat-set `Keys=[a,b,c]` and
   260	   hierarchical `Keys=[a]` + children). It is opt-in: a schema node with
   261	   no `validator` and no typed children is a no-op descent.
   262	5. **Remove the `class-of-service`-only early-return**
   263	   (`schema_validate.go:43-46`): the new walker fans out from the
   264	   `setSchema` root across ALL top-level subtrees. Subtrees with no typed
   265	   leaves cost one shallow descent (acceptable; commit-check is not hot).
   266	   Move `SchemaValidate` into `pkg/config` (it now walks the
   267	   `pkg/config`-owned `setSchema`); update the `pkg/configstore` caller
   268	   (`store.go:182,194`) to `config.SchemaValidate`. Drop the thin cmdtree
   269	   shim or leave a deprecated forwarder — decide in PR 1.
   270	6. **Parity + boundary tests** (Codex#5/SMR-D5):
   271	   - existing `pkg/config/schema_validate_test.go` +
   272	     `pkg/cmdtree/schema_validate_test.go` cases pass against the new
   273	     walker (migrate the cmdtree ones into `pkg/config` as the validator
   274	     moves);
   275	   - **frontend-boundary** completion tests — NOT just the
   276	     `CompleteSetPathWithValues` helper: assert
   277	     `cli.completeConfigWithDesc(["set","class-of-service","schedulers",
   278	     "x","transmit-rate"], "")` AND the gRPC `completeConfigPairs`
   279	     equivalent return `<rate>` + examples, including the trailing-space
   280	     case (`...transmit-rate ` → value slot). This is the exact gap §2.2
   281	     calls out; testing only the helper would repeat the same mistake.
   282	   - **SetPath grouping golden test** asserting flat-set grouping is
   283	     byte-identical before/after PR 1 (guards step 1's fields-only rule).
   284	   - Retire `cmdtree.ConfigClassOfServiceSchedulers` outright (AGY + SMR
   285	     agree — dead code on a non-production path is a false-coverage trap);
   286	     update `pkg/cmdtree/README.md` + CLAUDE.md to state the corrected
   287	     two-SSOT split.
   288	7. Docs: `pkg/cmdtree/README.md` + `pkg/config/README.md` +
   289	   `docs/config-schema.md` (new) state the corrected SSOT split and how
   290	   to add a typed leaf (one `setSchema` edit).
   291	
   292	**Acceptance for PR 1:**
   293	- `set class-of-service schedulers x transmit-rate ?` returns help with
   294	  `<rate>` + examples + `exact` **through the production CLI completer**.
   295	- `transmit-rate asd` still rejected at commit-check (no regression).
   296	- All 880+ tests pass; the parity tests pin both symptoms.
   297	
   298	### PR 2..N — per-subsystem typed leaves (incremental)
   299	
   300	Each PR types one subsystem's leaves in `setSchema` with **Junos-vSRX-
   301	correct** ranges and a fixture proving the silent-coerce gap on master.
   302	Suggested ordering by impact + clarity of Junos spec:
   303	- **chassis cluster** (re-do killed Phase 3a with corrected ranges:
   304	  cluster-id 0..15 with MAC-encoding rationale, heartbeat-interval
   305	  1000..2000 or explicit xpf-divergent range w/ rationale + the 30ms lab
   306	  caveat, heartbeat-threshold 3..8, reth-count 1..128, per-RG priority
   307	  1..254, per-RG `hold-down-interval` only if compiled). Gate per-leaf on
   308	  "is this leaf compiled today" (README invariant: do not type a leaf the
   309	  compiler ignores).
   310	- **interfaces** family inet/inet6 address CIDR validation.
   311	- **firewall** filter terms (forwarding-class cross-ref — needs `cfg`).
   312	- **system / services** numeric knobs.
   313	
   314	Each subsystem PR: types leaves + adds fixtures + updates that
   315	subsystem's doc. No walker/infra changes after PR 1.
   316	
   317	## 7. Hostile questions (answered)
   318	
   319	- **Touch every leaf (huge churn)?** No — PR 1 is infra + schedulers
   320	  re-home only; subsystems are independent incremental PRs. ~536 leaves
   321	  stay `ValueAny` and untouched until their subsystem PR.
   322	- **Consistent across local CLI / remote CLI / gRPC?** Yes under Option
   323	  A: all three config-mode completers already call
   324	  `config.CompleteSetPathWithValues` (cli) / the gRPC completer resolves
   325	  the same schema; validation runs in `configstore.compileTree` which is
   326	  the single commit path for all frontends. Under Option C this is the
   327	  weak point (two trees). Verify the gRPC completer path in PR 1.
   328	- **Junos-parity scope (which types matter most)?** integer-with-range
   329	  and enum dominate the ~536 leaves; rate/byte-size/percent already done;
   330	  IP/CIDR and identifier-cross-ref are the next most valuable. Defer
   331	  free-form (`description`, URLs) to permanent `ValueAny`.
   332	- **Does the "compiled-leaf-only" invariant hold?** Yes — keep
   333	  `pkg/cmdtree/README.md:47` invariant: only type a leaf the compiler
   334	  actually consumes, else commit-check rejects config the compiler would
   335	  silently ignore (a behavior change beyond the issue's scope).
   336	
   337	## 8. Risks
   338	
   339	- **Parser dependency on `setSchema`.** `setSchema` drives flat-set token
   340	  grouping in SetPath, and the replace-vs-container decision keys on

exec
/bin/bash -lc "nl -ba docs/research/1319-typed-leaf/plan.md | sed -n '337,372p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   337	## 8. Risks
   338	
   339	- **Parser dependency on `setSchema`.** `setSchema` drives flat-set token
   340	  grouping in SetPath, and the replace-vs-container decision keys on
   341	  `children==nil` (`ast_edit.go:196`). Adding *fields* to `schemaNode` is
   342	  additive and safe (AGY verified SetPath reads only
   343	  `args`/`children`/`compoundKey`/`multi`); adding/altering `children` is
   344	  NOT (Codex#3). PR 1 is fields-only and asserts byte-identical SetPath
   345	  grouping via a golden test. This is the main regression surface and why
   346	  Option A edits fields rather than restructuring nodes.
   347	- **Import cycle.** `ValueType` must move from `cmdtree` to `config`
   348	  first (Codex#1); skipping this breaks the build. PR-1 step 0.
   349	- **Compiled-leaf-only drift.** The cmdtree overlay already carries one
   350	  uncompiled modifier (`buffer-size temporal`, Codex#2). The migration
   351	  must drop it, not copy it. Each per-subsystem PR re-checks every leaf
   352	  against the compiler before typing it.
   353	- **gRPC completer divergence.** Confirm the gRPC `set` completer reaches
   354	  the same value-slot code; add a test.
   355	- **Doctrine churn.** CLAUDE.md says cmdtree is THE SSOT; Option A
   356	  formalizes a two-SSOT split (operational=cmdtree, config-grammar=
   357	  setSchema). Must be documented, not silently contradicted.
   358	
   359	## 9. Test plan
   360	
   361	- Reuse `pkg/config/schema_validate_test.go` +
   362	  `pkg/cmdtree/schema_validate_test.go` against the generic walker.
   363	- New: CLI-path completion test (`transmit-rate ?` → `<rate>`+examples
   364	  via `CompleteSetPathWithValues`).
   365	- New: SetPath grouping golden test asserting no grouping change.
   366	- Per subsystem PR: fixture showing master silently coerces garbage +
   367	  new walker rejects it.
   368	
   369	## 10. Rollout / ordering
   370	
   371	PR 1 (infra+walker+wiring+schedulers re-home) → merge → PR 2 chassis
   372	cluster → PR 3 interfaces → PR 4 firewall → ... Each independent,

exec
/bin/bash -lc "nl -ba pkg/config/ast.go | sed -n '680,815p;1110,1132p;1236,1250p;1500,1520p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   680			}},
   681			"ssh-known-hosts": {children: map[string]*schemaNode{
   682				"host": {args: 1, children: nil},
   683			}},
   684			"policy-stats": {children: map[string]*schemaNode{
   685				"system-wide": {args: 1, children: nil},
   686			}},
   687			"pre-id-default-policy": {children: map[string]*schemaNode{
   688				"then": {children: map[string]*schemaNode{
   689					"log": {children: map[string]*schemaNode{
   690						"session-init":  {children: nil},
   691						"session-close": {children: nil},
   692					}},
   693				}},
   694			}},
   695		}},
   696		"interfaces": {desc: "Interface configuration", wildcard: &schemaNode{valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
   697			"description":           {desc: "Text description of interface", args: 1, children: nil},
   698			"mtu":                   {desc: "Maximum transmit packet size", args: 1, children: nil},
   699			"speed":                 {desc: "Link speed", args: 1, children: nil},
   700			"duplex":                {desc: "Link duplex mode", args: 1, children: nil},
   701			"bandwidth":             {desc: "Interface bandwidth", args: 1, children: nil},
   702			"disable":               {desc: "Disable this interface", children: nil},
   703			"vlan-tagging":          {desc: "Enable 802.1Q VLAN tagging", children: nil},
   704			"flexible-vlan-tagging": {desc: "Enable flexible 802.1Q VLAN tagging (QinQ)", children: nil},
   705			"encapsulation":         {desc: "Physical link-layer encapsulation", args: 1, children: nil},
   706			"gigether-options": {desc: "Gigabit Ethernet interface options", children: map[string]*schemaNode{
   707				"redundant-parent": {desc: "Parent of this redundant interface", args: 1, children: nil},
   708				"802.3ad":          {desc: "Link aggregation group", args: 1, children: nil},
   709			}},
   710			"aggregated-ether-options": {desc: "Aggregated Ethernet interface options", children: map[string]*schemaNode{
   711				"lacp": {desc: "LACP parameters", children: map[string]*schemaNode{
   712					"active":   {desc: "Active LACP mode", children: nil},
   713					"passive":  {desc: "Passive LACP mode", children: nil},
   714					"periodic": {desc: "LACP timer period", args: 1, children: nil},
   715				}},
   716				"link-speed":    {desc: "Member link speed", args: 1, children: nil},
   717				"minimum-links": {desc: "Minimum active member links", args: 1, children: nil},
   718			}},
   719			"redundant-ether-options": {desc: "Redundant Ethernet interface options", children: map[string]*schemaNode{
   720				"redundancy-group": {desc: "Redundancy group for this RETH", args: 1, children: nil},
   721			}},
   722			"fabric-options": {desc: "Fabric interface options", children: map[string]*schemaNode{
   723				"member-interfaces": {desc: "Member interfaces", children: nil},
   724			}},
   725			"tunnel": {desc: "Tunnel parameters", children: map[string]*schemaNode{
   726				"source":          {desc: "Tunnel source address", args: 1, children: nil},
   727				"destination":     {desc: "Tunnel destination address", args: 1, children: nil},
   728				"mode":            {desc: "Tunnel mode", args: 1, children: nil},
   729				"key":             {desc: "Tunnel key", args: 1, children: nil},
   730				"ttl":             {desc: "Time to live", args: 1, children: nil},
   731				"keepalive":       {desc: "Keepalive interval", args: 1, children: nil},
   732				"keepalive-retry": {desc: "Keepalive retry count", args: 1, children: nil},
   733				"routing-instance": {desc: "Routing instance", children: map[string]*schemaNode{
   734					"destination": {desc: "Destination routing instance", args: 1, children: nil},
   735				}},
   736			}},
   737			"unit": {desc: "Logical unit number", args: 1, valueHint: ValueHintUnitNumber, placeholder: "<unit-number>", children: map[string]*schemaNode{
   738				"description":    {desc: "Text description", args: 1, placeholder: "<text>", children: nil},
   739				"point-to-point": {desc: "Point-to-point interface", children: nil},
   740				"vlan-id":        {desc: "VLAN ID", args: 1, placeholder: "<number>", children: nil},
   741				"inner-vlan-id":  {desc: "Inner VLAN ID", args: 1, placeholder: "<number>", children: nil},
   742				"tunnel": {desc: "Tunnel parameters", children: map[string]*schemaNode{
   743					"source":          {desc: "Tunnel source address", args: 1, placeholder: "<address>", children: nil},
   744					"destination":     {desc: "Tunnel destination address", args: 1, placeholder: "<address>", children: nil},
   745					"mode":            {desc: "Tunnel mode", args: 1, placeholder: "<mode>", children: nil},
   746					"key":             {desc: "Tunnel key", args: 1, placeholder: "<key>", children: nil},
   747					"ttl":             {desc: "Time to live", args: 1, placeholder: "<number>", children: nil},
   748					"keepalive":       {desc: "Keepalive interval", args: 1, placeholder: "<seconds>", children: nil},
   749					"keepalive-retry": {desc: "Keepalive retry count", args: 1, placeholder: "<number>", children: nil},
   750					"routing-instance": {desc: "Routing instance", children: map[string]*schemaNode{
   751						"destination": {desc: "Destination routing instance", args: 1, placeholder: "<name>", children: nil},
   752					}},
   753				}},
   754				"family": {desc: "Protocol family", compoundKey: true, children: map[string]*schemaNode{
   755					"inet": {desc: "IPv4 protocol", children: map[string]*schemaNode{
   756						"mtu": {desc: "Maximum transmit packet size", args: 1, placeholder: "<size>", children: nil},
   757						"address": {desc: "IPv4 address", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
   758							"primary":   {desc: "Primary address", children: nil},
   759							"preferred": {desc: "Preferred address", children: nil},
   760						}},
   761						"dhcp": {desc: "DHCP client", children: map[string]*schemaNode{
   762							"lease-time":              {desc: "Lease time", args: 1, placeholder: "<seconds>", children: nil},
   763							"retransmission-attempt":  {desc: "Retransmission attempts", args: 1, placeholder: "<number>", children: nil},
   764							"retransmission-interval": {desc: "Retransmission interval", args: 1, placeholder: "<seconds>", children: nil},
   765							"force-discover":          {desc: "Force DHCP discover", children: nil},
   766						}},
   767						"sampling": {desc: "Traffic sampling", children: map[string]*schemaNode{
   768							"input":  {desc: "Sample input traffic", children: nil},
   769							"output": {desc: "Sample output traffic", children: nil},
   770						}},
   771						"filter": {desc: "Firewall filter", children: map[string]*schemaNode{
   772							"input":  {desc: "Input filter", args: 1, placeholder: "<filter-name>", children: nil},
   773							"output": {desc: "Output filter", args: 1, placeholder: "<filter-name>", children: nil},
   774						}},
   775					}},
   776					"inet6": {desc: "IPv6 protocol", children: map[string]*schemaNode{
   777						"mtu":         {desc: "Maximum transmit packet size", args: 1, placeholder: "<size>", children: nil},
   778						"dad-disable": {desc: "Disable duplicate address detection", children: nil},
   779						"address": {desc: "IPv6 address", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
   780							"primary":   {desc: "Primary address", children: nil},
   781							"preferred": {desc: "Preferred address", children: nil},
   782						}},
   783						"sampling": {desc: "Traffic sampling", children: map[string]*schemaNode{
   784							"input":  {desc: "Sample input traffic", children: nil},
   785							"output": {desc: "Sample output traffic", children: nil},
   786						}},
   787						"filter": {desc: "Firewall filter", children: map[string]*schemaNode{
   788							"input":  {desc: "Input filter", args: 1, placeholder: "<filter-name>", children: nil},
   789							"output": {desc: "Output filter", args: 1, placeholder: "<filter-name>", children: nil},
   790						}},
   791						"dhcpv6-client": {desc: "DHCPv6 client", children: map[string]*schemaNode{
   792							"client-type":    {desc: "Client type", args: 1, placeholder: "<type>", children: nil},
   793							"client-ia-type": {desc: "Client IA type", args: 1, placeholder: "<type>", children: nil},
   794							"prefix-delegating": {desc: "Prefix delegation", children: map[string]*schemaNode{
   795								"preferred-prefix-length": {desc: "Preferred prefix length", args: 1, placeholder: "<length>", children: nil},
   796								"sub-prefix-length":       {desc: "Sub-prefix length", args: 1, placeholder: "<length>", children: nil},
   797							}},
   798							"client-identifier": {desc: "Client identifier", children: map[string]*schemaNode{
   799								"duid-type": {desc: "DUID type", args: 1, placeholder: "<type>", children: nil},
   800							}},
   801							"req-option": {desc: "Request option", args: 1, placeholder: "<option>", children: nil},
   802							"update-router-advertisement": {desc: "Update router advertisement", children: map[string]*schemaNode{
   803								"interface": {desc: "Interface", args: 1, placeholder: "<interface>", children: nil},
   804							}},
   805						}},
   806					}},
   807				}},
   808			}},
   809		}}},
   810		"applications": {desc: "Applications", children: map[string]*schemaNode{
   811			"application": {desc: "Application name", args: 1, valueHint: ValueHintAppName, placeholder: "<name>", children: map[string]*schemaNode{
   812				"protocol":           {desc: "Protocol", args: 1, placeholder: "<protocol>", children: nil},
   813				"destination-port":   {desc: "Destination port", args: 1, placeholder: "<port>", children: nil},
   814				"source-port":        {desc: "Source port", args: 1, placeholder: "<port>", children: nil},
   815				"inactivity-timeout": {desc: "Inactivity timeout", args: 1, placeholder: "<seconds>", children: nil},
  1110				"peer-fencing":                  {args: 1, children: nil},
  1111				"takeover-hold-time":            {args: 1, children: nil},
  1112				"no-reth-vrrp":                  {children: nil},
  1113				"private-rg-election":           {children: nil},
  1114				"no-private-rg-election":        {children: nil},
  1115				"redundancy-group": {args: 1, children: map[string]*schemaNode{
  1116					"node": {args: 1, children: map[string]*schemaNode{
  1117						"priority": {args: 1, children: nil},
  1118					}},
  1119					"gratuitous-arp-count": {args: 1, children: nil},
  1120					"preempt":              {children: nil},
  1121					"interface-monitor":    {children: nil},
  1122					"ip-monitoring": {children: map[string]*schemaNode{
  1123						"global-weight":    {args: 1, children: nil},
  1124						"global-threshold": {args: 1, children: nil},
  1125						"family": {compoundKey: true, children: map[string]*schemaNode{
  1126							"inet": {wildcard: &schemaNode{children: map[string]*schemaNode{
  1127								"weight": {args: 1, children: nil},
  1128							}}},
  1129						}},
  1130					}},
  1131				}},
  1132			}},
  1236				}},
  1237				"then": {children: map[string]*schemaNode{
  1238					"discard":       {children: nil},
  1239					"loss-priority": {args: 1, children: nil},
  1240				}},
  1241			}},
  1242			"family": {compoundKey: true, children: map[string]*schemaNode{
  1243				"inet": {children: map[string]*schemaNode{
  1244					"filter": {args: 1, children: map[string]*schemaNode{
  1245						"term": {args: 1, children: map[string]*schemaNode{
  1246							"from": {children: map[string]*schemaNode{
  1247								"source-address":          {args: 1, multi: true, children: nil},
  1248								"destination-address":     {args: 1, multi: true, children: nil},
  1249								"source-prefix-list":      {children: nil},
  1250								"destination-prefix-list": {children: nil},
  1500					}},
  1501				}},
  1502			}},
  1503			"application-identification": {children: nil},
  1504		}},
  1505		"forwarding-options": {children: map[string]*schemaNode{
  1506			"family": {compoundKey: true, children: map[string]*schemaNode{
  1507				"inet6": {children: map[string]*schemaNode{
  1508					"mode": {args: 1, children: nil},
  1509				}},
  1510			}},
  1511			"sampling": {children: map[string]*schemaNode{
  1512				"instance": {args: 1, children: map[string]*schemaNode{
  1513					"input": {children: nil},
  1514					"family": {compoundKey: true, children: map[string]*schemaNode{
  1515						"inet": {children: map[string]*schemaNode{
  1516							"output": {children: map[string]*schemaNode{
  1517								"flow-server":  {args: 1, children: nil},
  1518								"inline-jflow": {children: nil},
  1519							}},
  1520						}},

exec
/bin/bash -lc "rg -n \"func nodeVal|nodeVal\\(\" pkg/config -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/config/compiler_nat.go:76:					low := nodeVal(prop)
pkg/config/compiler_nat.go:77:					high := nodeVal(toChild)
pkg/config/compiler_nat.go:89:				if v := nodeVal(prop); v != "" {
pkg/config/compiler_nat.go:111:				rs.Prefix = nodeVal(child)
pkg/config/compiler_nat.go:113:				rs.SourcePool = nodeVal(child)
pkg/config/compiler_nat.go:137:			if v := nodeVal(child); v != "" {
pkg/config/compiler_nat.go:213:				} else if v := nodeVal(prop); v != "" {
pkg/config/compiler_nat.go:238:				} else if v := nodeVal(prop); v != "" {
pkg/config/compiler_nat.go:251:								if v := nodeVal(detProp); v != "" {
pkg/config/compiler_nat.go:260:								} else if v := nodeVal(detProp); v != "" {
pkg/config/compiler_nat.go:265:										if v := nodeVal(hc); v != "" {
pkg/config/compiler_nat.go:293:									if v := nodeVal(hc); v != "" {
pkg/config/compiler_nat.go:307:						if v := nodeVal(pnProp); v == "any-remote-host" {
pkg/config/compiler_nat.go:311:						if v := nodeVal(pnProp); v != "" {
pkg/config/compiler_nat.go:336:				if v := nodeVal(ap); v != "" {
pkg/config/compiler_nat.go:342:				if v := nodeVal(ap); v != "" {
pkg/config/compiler_nat.go:473:							rule.Match.DestinationAddress = nodeVal(m)
pkg/config/compiler_nat.go:485:						} else if v := nodeVal(m); v != "" {
pkg/config/compiler_nat.go:492:						rule.Match.Application = nodeVal(m)
pkg/config/compiler_nat.go:523:							rule.Then.PoolName = nodeVal(poolNode)
pkg/config/compiler_nat.go:562:				pool.Address = nodeVal(prop)
pkg/config/compiler_nat.go:564:				if v := nodeVal(prop); v != "" {
pkg/config/compiler_nat.go:614:							rule.Match.DestinationAddress = nodeVal(m)
pkg/config/compiler_nat.go:634:						rule.Match.SourceAddressName = nodeVal(m)
pkg/config/compiler_nat.go:636:						rule.Match.Protocol = nodeVal(m)
pkg/config/compiler_nat.go:638:						rule.Match.Application = nodeVal(m)
pkg/config/compiler_nat.go:652:							rule.Then.PoolName = nodeVal(poolNode)
pkg/config/compiler_nat.go:692:					if high, err2 := strconv.Atoi(nodeVal(toChild)); err2 == nil && high >= low {
pkg/config/compiler_nat.go:731:	} else if v := nodeVal(m); v != "" {
pkg/config/compiler_nat.go:763:						rule.Match = nodeVal(m)
pkg/config/compiler_nat.go:765:						rule.SourceAddress = nodeVal(m)
pkg/config/compiler_nat.go:780:							rule.Then = nodeVal(np)
pkg/config/compiler_nat.go:785:							rule.Then = nodeVal(pn)
pkg/config/compiler.go:1182:				app.Protocol = nodeVal(prop)
pkg/config/compiler.go:1184:				app.DestinationPort = nodeVal(prop)
pkg/config/compiler.go:1186:				app.SourcePort = nodeVal(prop)
pkg/config/compiler.go:1188:				if v := nodeVal(prop); v != "" {
pkg/config/compiler.go:1194:				app.ALG = nodeVal(prop)
pkg/config/compiler.go:1196:				app.Description = nodeVal(prop)
pkg/config/compiler.go:1232:				v := nodeVal(member)
pkg/config/compiler.go:1416:func nodeVal(n *Node) string {
pkg/config/compiler_protocols.go:26:				if v := nodeVal(child); v != "" {
pkg/config/compiler_protocols.go:34:				if v := nodeVal(child); v != "" {
pkg/config/compiler_protocols.go:40:				if v := nodeVal(child); v != "" {
pkg/config/compiler_protocols.go:63:				if v := nodeVal(child); v != "" {
pkg/config/compiler_protocols.go:89:						iface.NetworkType = nodeVal(prop)
pkg/config/compiler_protocols.go:91:						if v := nodeVal(prop); v != "" {
pkg/config/compiler_protocols.go:101:								if v := nodeVal(authChild); v != "" {
pkg/config/compiler_protocols.go:108:										iface.AuthKey = nodeVal(kc)
pkg/config/compiler_protocols.go:113:								iface.AuthKey = nodeVal(authChild)
pkg/config/compiler_protocols.go:121:								if v := nodeVal(bc); v != "" {
pkg/config/compiler_protocols.go:127:								if v := nodeVal(bc); v != "" {
pkg/config/compiler_protocols.go:165:					if v := nodeVal(taNode); v != "" {
pkg/config/compiler_protocols.go:210:					if v := nodeVal(dc); v != "" {
pkg/config/compiler_protocols.go:264:					if v := nodeVal(child); v != "" {
pkg/config/compiler_protocols.go:270:					groupDesc = nodeVal(child)
pkg/config/compiler_protocols.go:272:					if v := nodeVal(child); v != "" {
pkg/config/compiler_protocols.go:278:					if v := nodeVal(child); v != "" {
pkg/config/compiler_protocols.go:310:					if v := nodeVal(child); v != "" {
pkg/config/compiler_protocols.go:318:					groupAuthKey = nodeVal(child)
pkg/config/compiler_protocols.go:324:							if v := nodeVal(bc); v != "" {
pkg/config/compiler_protocols.go:330:							if v := nodeVal(bc); v != "" {
pkg/config/compiler_protocols.go:338:					nAddr := nodeVal(child)
pkg/config/compiler_protocols.go:363:								neighbor.Description = nodeVal(prop)
pkg/config/compiler_protocols.go:365:								if v := nodeVal(prop); v != "" {
pkg/config/compiler_protocols.go:371:								if v := nodeVal(prop); v != "" {
pkg/config/compiler_protocols.go:377:								neighbor.AuthPassword = nodeVal(prop)
pkg/config/compiler_protocols.go:387:										if v := nodeVal(bc); v != "" {
pkg/config/compiler_protocols.go:393:										if v := nodeVal(bc); v != "" {
pkg/config/compiler_protocols.go:401:								if v := nodeVal(prop); v != "" {
pkg/config/compiler_protocols.go:474:						if v := nodeVal(prop); v != "" {
pkg/config/compiler_protocols.go:519:				if v := nodeVal(child); v != "" {
pkg/config/compiler_protocols.go:523:				if v := nodeVal(child); v != "" {
pkg/config/compiler_protocols.go:552:				if v := nodeVal(child); v != "" {
pkg/config/compiler_protocols.go:556:				if v := nodeVal(child); v != "" {
pkg/config/compiler_protocols.go:581:							iface.AuthKey = nodeVal(prop)
pkg/config/compiler_protocols.go:583:							iface.AuthType = nodeVal(prop)
pkg/config/compiler_protocols.go:589:									if v := nodeVal(bc); v != "" {
pkg/config/compiler_protocols.go:595:									if v := nodeVal(bc); v != "" {
pkg/config/compiler_protocols.go:634:				if v := nodeVal(prop); v != "" {
pkg/config/compiler_protocols.go:640:				if v := nodeVal(prop); v != "" {
pkg/config/compiler_protocols.go:646:				if v := nodeVal(prop); v != "" {
pkg/config/compiler_protocols.go:652:				if v := nodeVal(prop); v != "" {
pkg/config/compiler_protocols.go:659:					ra.DNSServers = append(ra.DNSServers, nodeVal(prop))
pkg/config/compiler_protocols.go:662:				ra.Preference = nodeVal(prop)
pkg/config/compiler_protocols.go:664:				ra.NAT64Prefix = nodeVal(prop)
pkg/config/compiler_protocols.go:667:					if v := nodeVal(ltNode); v != "" {
pkg/config/compiler_protocols.go:674:				pfxName := nodeVal(prop)
pkg/config/compiler_protocols.go:697:							if v := nodeVal(child); v != "" {
pkg/config/compiler_protocols.go:703:							if v := nodeVal(child); v != "" {
pkg/config/compiler_protocols.go:768:	if v := nodeVal(mx); v != "" {
pkg/config/compiler_protocols.go:783:			if v := nodeVal(child); v != "" {
pkg/config/compiler_interfaces.go:22:			ifc.Description = nodeVal(descNode)
pkg/config/compiler_interfaces.go:27:			if v := nodeVal(mtuNode); v != "" {
pkg/config/compiler_interfaces.go:36:			ifc.Speed = nodeVal(speedNode)
pkg/config/compiler_interfaces.go:39:			ifc.Duplex = nodeVal(duplexNode)
pkg/config/compiler_interfaces.go:47:			if v := nodeVal(bwNode); v != "" {
pkg/config/compiler_interfaces.go:64:			ifc.Encapsulation = nodeVal(encapNode)
pkg/config/compiler_interfaces.go:70:				ifc.RedundantParent = nodeVal(rpNode)
pkg/config/compiler_interfaces.go:73:				ifc.LAGParent = nodeVal(adNode)
pkg/config/compiler_interfaces.go:88:					opts.LACPPeriodic = nodeVal(periodicNode)
pkg/config/compiler_interfaces.go:92:				opts.LinkSpeed = nodeVal(lsNode)
pkg/config/compiler_interfaces.go:95:				if v := nodeVal(mlNode); v != "" {
pkg/config/compiler_interfaces.go:105:				if v, err := strconv.Atoi(nodeVal(rgNode)); err == nil {
pkg/config/compiler_interfaces.go:162:					if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:168:					if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:176:						tc.RoutingInstance = nodeVal(destNode)
pkg/config/compiler_interfaces.go:177:					} else if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:194:				unit.Description = nodeVal(descNode)
pkg/config/compiler_interfaces.go:224:						if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:228:						if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:233:							tc.RoutingInstance = nodeVal(destNode)
pkg/config/compiler_interfaces.go:234:						} else if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:238:						if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:242:						if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:248:						if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:254:						if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:260:						if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:272:				if v := nodeVal(vlanNode); v != "" {
pkg/config/compiler_interfaces.go:281:				if v := nodeVal(ivNode); v != "" {
pkg/config/compiler_interfaces.go:329:										if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:333:										if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:341:										if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:345:										vg.AuthType = nodeVal(prop)
pkg/config/compiler_interfaces.go:347:										vg.AuthKey = nodeVal(prop)
pkg/config/compiler_interfaces.go:349:										vg.TrackInterface = nodeVal(prop)
pkg/config/compiler_interfaces.go:351:										if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:370:										if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:374:										if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:378:										if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:389:							if v := nodeVal(mtuNode); v != "" {
pkg/config/compiler_interfaces.go:405:								unit.FilterInputV4 = nodeVal(inputNode)
pkg/config/compiler_interfaces.go:408:								unit.FilterOutputV4 = nodeVal(outputNode)
pkg/config/compiler_interfaces.go:428:							if v := nodeVal(mtuNode); v != "" {
pkg/config/compiler_interfaces.go:446:								unit.FilterInputV6 = nodeVal(inputNode)
pkg/config/compiler_interfaces.go:449:								unit.FilterOutputV6 = nodeVal(outputNode)
pkg/config/compiler_interfaces.go:459:										dc.DUIDType = nodeVal(dtNode)
pkg/config/compiler_interfaces.go:460:									} else if nodeVal(prop) == "duid-type" && len(prop.Keys) >= 3 {
pkg/config/compiler_interfaces.go:465:									dc.ClientType = nodeVal(prop)
pkg/config/compiler_interfaces.go:467:									if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:472:										if v := nodeVal(plNode); v != "" {
pkg/config/compiler_interfaces.go:477:										if v := nodeVal(slNode); v != "" {
pkg/config/compiler_interfaces.go:482:									if v := nodeVal(prop); v != "" {
pkg/config/compiler_interfaces.go:487:										dc.UpdateRAInterface = nodeVal(ifNode)
pkg/config/compiler_firewall.go:31:					if v := nodeVal(child); v != "" {
pkg/config/compiler_firewall.go:35:					if v := nodeVal(child); v != "" {
pkg/config/compiler_firewall.go:49:					if v := nodeVal(child); v != "" {
pkg/config/compiler_firewall.go:94:					if v := nodeVal(child); v != "" {
pkg/config/compiler_firewall.go:98:					if v := nodeVal(child); v != "" {
pkg/config/compiler_firewall.go:102:					if v := nodeVal(child); v != "" {
pkg/config/compiler_firewall.go:125:					if v := nodeVal(child); v != "" {
pkg/config/compiler_firewall.go:129:					if v := nodeVal(child); v != "" {
pkg/config/compiler_firewall.go:133:					if v := nodeVal(child); v != "" {
pkg/config/compiler_firewall.go:137:					if v := nodeVal(child); v != "" {
pkg/config/compiler_firewall.go:150:					if v := nodeVal(child); v != "" {
pkg/config/compiler_firewall.go:221:			if v := nodeVal(child); v != "" {
pkg/config/compiler_firewall.go:225:			if v := nodeVal(child); v != "" {
pkg/config/compiler_firewall.go:289:			v := nodeVal(child)
pkg/config/compiler_firewall.go:296:			v := nodeVal(child)
pkg/config/compiler_firewall.go:322:						if v := nodeVal(rc); v != "" {
pkg/config/compiler_firewall.go:326:						if v := nodeVal(rc); v != "" {
pkg/config/compiler_firewall.go:332:						if v := nodeVal(rc); v != "" {
pkg/config/compiler_firewall.go:338:						if v := nodeVal(rc); v != "" {
pkg/config/compiler_firewall.go:353:						if v := nodeVal(rc); v != "" {
pkg/config/compiler_firewall.go:432:			term.DSCPRewrite = nodeVal(child)
pkg/config/compiler_security.go:61:					if v := nodeVal(kp); v != "" {
pkg/config/compiler_security.go:69:				sec.PolicyStatsEnabled = nodeVal(sw) == "enable"
pkg/config/compiler_security.go:99:				zone.ScreenProfile = nodeVal(prop)
pkg/config/compiler_security.go:119:				zone.Description = nodeVal(prop)
pkg/config/compiler_security.go:262:		pol.Description = nodeVal(descNode)
pkg/config/compiler_security.go:265:		pol.SchedulerName = nodeVal(snNode)
pkg/config/compiler_security.go:286:					} else if v := nodeVal(opt); v != "" {
pkg/config/compiler_security.go:306:							val := nodeVal(swOpt)
pkg/config/compiler_security.go:338:						val := nodeVal(sfOpt)
pkg/config/compiler_security.go:362:							val := nodeVal(psOpt)
pkg/config/compiler_security.go:384:					} else if v := nodeVal(opt); v != "" {
pkg/config/compiler_security.go:396:				val := nodeVal(opt)
pkg/config/compiler_security.go:469:		sec.Log.Mode = nodeVal(modeNode)
pkg/config/compiler_security.go:472:		sec.Log.Format = nodeVal(fmtNode)
pkg/config/compiler_security.go:475:		sec.Log.SourceInterface = nodeVal(srcNode)
pkg/config/compiler_security.go:490:				if v := nodeVal(prop); v != "" {
pkg/config/compiler_security.go:497:						if v := nodeVal(hc); v != "" {
pkg/config/compiler_security.go:510:				if v := nodeVal(prop); v != "" {
pkg/config/compiler_security.go:516:				stream.Severity = nodeVal(prop)
pkg/config/compiler_security.go:518:				stream.Facility = nodeVal(prop)
pkg/config/compiler_security.go:520:				stream.Format = nodeVal(prop)
pkg/config/compiler_security.go:522:				stream.Category = nodeVal(prop)
pkg/config/compiler_security.go:524:				stream.SourceAddress = nodeVal(prop)
pkg/config/compiler_security.go:529:						stream.Transport.Protocol = nodeVal(tc)
pkg/config/compiler_security.go:531:						stream.Transport.TLSProfile = nodeVal(tc)
pkg/config/compiler_security.go:681:			to.File = nodeVal(fileNode)
pkg/config/compiler_security.go:696:				if v := nodeVal(sNode); v != "" {
pkg/config/compiler_security.go:703:				if v := nodeVal(fNode); v != "" {
pkg/config/compiler_security.go:711:			if v := nodeVal(flagNode); v != "" {
pkg/config/compiler_security.go:718:				pf.SourcePrefix = nodeVal(spNode)
pkg/config/compiler_security.go:721:				pf.DestinationPrefix = nodeVal(dpNode)
pkg/config/compiler_class_of_service.go:139:						lossPriority = nodeVal(lpNode)
pkg/config/compiler_class_of_service.go:172:						lossPriority = nodeVal(lpNode)
pkg/config/compiler_class_of_service.go:208:						lossPriority = nodeVal(lpNode)
pkg/config/compiler_class_of_service.go:238:				sched.Priority = nodeVal(child)
pkg/config/compiler_class_of_service.go:240:				if v := nodeVal(child); v != "" {
pkg/config/compiler_class_of_service.go:257:				if v := nodeVal(child); v != "" {
pkg/config/compiler_class_of_service.go:281:				scheduler = nodeVal(schedNode)
pkg/config/compiler_class_of_service.go:306:				if v := nodeVal(shapingNode); v != "" {
pkg/config/compiler_class_of_service.go:310:					if v := nodeVal(burstNode); v != "" {
pkg/config/compiler_class_of_service.go:316:				unit.SchedulerMap = nodeVal(schedMapNode)
pkg/config/compiler_class_of_service.go:320:					unit.DSCPClassifier = nodeVal(dscpNode)
pkg/config/compiler_class_of_service.go:323:					unit.IEEE8021Classifier = nodeVal(ieeeNode)
pkg/config/compiler_class_of_service.go:328:					unit.DSCPRewriteRule = nodeVal(dscpNode)
pkg/config/compiler_class_of_service.go:360:					if v := nodeVal(grNode); v != "" {
pkg/config/compiler_class_of_service.go:377:				} else if v := nodeVal(oversubNode); v != "" {
pkg/config/compiler_class_of_service.go:383:				if v := nodeVal(minShareNode); v != "" {
pkg/config/compiler_class_of_service.go:472:		return set(kind, nodes, func(n *Node) string { return kind + ":" + nodeVal(n) })
pkg/config/compiler_system.go:66:				if v := nodeVal(thNode); v != "" {
pkg/config/compiler_system.go:77:					sys.NTPThresholdAction = nodeVal(actNode)
pkg/config/compiler_system.go:87:						if v := nodeVal(prop); v != "" {
pkg/config/compiler_system.go:93:						user.Class = nodeVal(prop)
pkg/config/compiler_system.go:98:								if v := nodeVal(authChild); v != "" {
pkg/config/compiler_system.go:135:					sys.RootAuthentication.EncryptedPassword = nodeVal(prop)
pkg/config/compiler_system.go:137:					if v := nodeVal(prop); v != "" {
pkg/config/compiler_system.go:152:					if v := nodeVal(tiNode); v != "" {
pkg/config/compiler_system.go:208:				sys.MasterPassword = nodeVal(prfNode)
pkg/config/compiler_system.go:213:					sys.LicenseAutoUpdate = nodeVal(urlNode)
pkg/config/compiler_system.go:218:				if proc.FindChild("disable") != nil || nodeVal(proc) == "disable" {
pkg/config/compiler_system.go:342:					sys.Services.WebManagement.HTTPInterface = nodeVal(ifNode)
pkg/config/compiler_system.go:351:					sys.Services.WebManagement.HTTPSInterface = nodeVal(ifNode)
pkg/config/compiler_system.go:360:							Password: nodeVal(pwNode),
pkg/config/compiler_system.go:365:					auth.APIKeys = append(auth.APIKeys, nodeVal(ch))
pkg/config/compiler_system.go:438:			cfg.Binary = nodeVal(child)
pkg/config/compiler_system.go:440:			cfg.ControlSocket = nodeVal(child)
pkg/config/compiler_system.go:442:			cfg.StateFile = nodeVal(child)
pkg/config/compiler_system.go:444:			if v := nodeVal(child); v != "" {
pkg/config/compiler_system.go:448:			if v := nodeVal(child); v != "" {
pkg/config/compiler_system.go:452:			if v := nodeVal(child); v == "interrupt" || v == "busy-poll" {
pkg/config/compiler_system.go:465:			if nodeVal(child) == "disable" {
pkg/config/compiler_system.go:473:			if nodeVal(child) == "true" {
pkg/config/compiler_system.go:482:			cfg.CPUGovernor = nodeVal(child)
pkg/config/compiler_system.go:484:			if v := nodeVal(child); v != "" {
pkg/config/compiler_system.go:501:					v := nodeVal(sub)
pkg/config/compiler_system.go:510:					if v := nodeVal(sub); v != "" {
pkg/config/compiler_system.go:514:					if v := nodeVal(sub); v != "" {
pkg/config/compiler_system.go:529:			cfg.Mode = nodeVal(child)
pkg/config/compiler_system.go:531:			if v := nodeVal(child); v != "" {
pkg/config/compiler_system.go:535:			path := nodeVal(child)
pkg/config/compiler_system.go:648:			snmp.Location = nodeVal(child)
pkg/config/compiler_system.go:650:			snmp.Contact = nodeVal(child)
pkg/config/compiler_system.go:652:			snmp.Description = nodeVal(child)
pkg/config/compiler_system.go:654:			commName := nodeVal(child)
pkg/config/compiler_system.go:663:						comm.Authorization = nodeVal(prop)
pkg/config/compiler_system.go:678:			tgName := nodeVal(child)
pkg/config/compiler_system.go:687:						if v := nodeVal(prop); v != "" {
pkg/config/compiler_system.go:731:		userName := nodeVal(child)
pkg/config/compiler_system.go:748:					user.AuthPassword = nodeVal(pw)
pkg/config/compiler_system.go:753:					user.AuthPassword = nodeVal(pw)
pkg/config/compiler_system.go:758:					user.AuthPassword = nodeVal(pw)
pkg/config/compiler_system.go:763:					user.PrivPassword = nodeVal(pw)
pkg/config/compiler_system.go:768:					user.PrivPassword = nodeVal(pw)
pkg/config/compiler_system.go:822:				sched.StartTime = nodeVal(prop)
pkg/config/compiler_system.go:824:				sched.StopTime = nodeVal(prop)
pkg/config/compiler_system.go:826:				sched.StartDate = nodeVal(prop)
pkg/config/compiler_system.go:828:				sched.StopDate = nodeVal(prop)
pkg/config/compiler_system.go:848:		if v := nodeVal(n); v != "" {
pkg/config/compiler_system.go:855:		if v := nodeVal(n); v != "" {
pkg/config/compiler_system.go:862:		if v := nodeVal(rcNode); v != "" {
pkg/config/compiler_system.go:869:		if v := nodeVal(n); v != "" {
pkg/config/compiler_system.go:876:		if v := nodeVal(n); v != "" {
pkg/config/compiler_system.go:886:		if v := nodeVal(n); v != "" {
pkg/config/compiler_system.go:891:		if v := nodeVal(n); v != "" {
pkg/config/compiler_system.go:896:		if v := nodeVal(n); v != "" {
pkg/config/compiler_system.go:901:		if v := nodeVal(n); v != "" {
pkg/config/compiler_system.go:906:		if v := nodeVal(n); v != "" {
pkg/config/compiler_system.go:911:		if v := nodeVal(n); v != "" {
pkg/config/compiler_system.go:925:		if v := nodeVal(n); v != "" {
pkg/config/compiler_system.go:944:		if v := nodeVal(n); v != "" {
pkg/config/compiler_system.go:949:		if v := nodeVal(n); v != "" {
pkg/config/compiler_system.go:972:				if v := nodeVal(child); v != "" {
pkg/config/compiler_system.go:986:					if v := nodeVal(priNode); v != "" {
pkg/config/compiler_system.go:993:				if v := nodeVal(child); v != "" {
pkg/config/compiler_system.go:1016:						if v := nodeVal(wNode); v != "" {
pkg/config/compiler_system.go:1027:					if v := nodeVal(gwNode); v != "" {
pkg/config/compiler_system.go:1034:					if v := nodeVal(gtNode); v != "" {
pkg/config/compiler_system.go:1067:							if v := nodeVal(wNode); v != "" {
pkg/config/compiler_ipsec.go:23:			v := nodeVal(p)
pkg/config/compiler_ipsec.go:50:			v := nodeVal(p)
pkg/config/compiler_ipsec.go:63:							pol.PSK = nodeVal(c)
pkg/config/compiler_ipsec.go:79:			v := nodeVal(p)
pkg/config/compiler_ipsec.go:124:						gw.LocalIDValue = nodeVal(c)
pkg/config/compiler_ipsec.go:134:						gw.RemoteIDValue = nodeVal(c)
pkg/config/compiler_ipsec.go:161:	if v := nodeVal(node); v != "" {
pkg/config/compiler_ipsec.go:170:			if n, err := strconv.Atoi(nodeVal(c)); err == nil {
pkg/config/compiler_ipsec.go:174:			if n, err := strconv.Atoi(nodeVal(c)); err == nil {
pkg/config/compiler_ipsec.go:200:			v := nodeVal(p)
pkg/config/compiler_ipsec.go:225:			v := nodeVal(p)
pkg/config/compiler_ipsec.go:232:						g := strings.TrimPrefix(nodeVal(c), "group")
pkg/config/compiler_ipsec.go:253:			v := nodeVal(p)
pkg/config/compiler_ipsec.go:298:						gw.LocalIDValue = nodeVal(c)
pkg/config/compiler_ipsec.go:308:						gw.RemoteIDValue = nodeVal(c)
pkg/config/compiler_ipsec.go:317:							gw.DynamicHostname = nodeVal(c)
pkg/config/compiler_ipsec.go:330:			v := nodeVal(p)
pkg/config/compiler_ipsec.go:341:					cv := nodeVal(c)
pkg/config/compiler_ipsec.go:371:					ts.LocalIP = nodeVal(p)
pkg/config/compiler_ipsec.go:373:					ts.RemoteIP = nodeVal(p)
pkg/config/compiler_routing.go:12:		if v := nodeVal(asNode); v != "" {
pkg/config/compiler_routing.go:22:			ro.ForwardingTableExport = nodeVal(expNode)
pkg/config/compiler_routing.go:29:		ribName := nodeVal(ribNode)
pkg/config/compiler_routing.go:88:			prefix := nodeVal(routeNode)
pkg/config/compiler_routing.go:94:				gr.Policy = nodeVal(policyNode)
pkg/config/compiler_routing.go:121:					ro.InterfaceRoutesRibGroup = nodeVal(rgChild)
pkg/config/compiler_routing.go:123:					ro.InterfaceRoutesRibGroupV6 = nodeVal(rgChild)
pkg/config/compiler_routing.go:199:				nh.Address = nodeVal(prop)
pkg/config/compiler_routing.go:203:						nh.Interface = nodeVal(child)
pkg/config/compiler_routing.go:217:				if v := nodeVal(prop); v != "" {
pkg/config/compiler_routing.go:224:				nh.Address = nodeVal(prop)
pkg/config/compiler_routing.go:233:					nh.Interface = nodeVal(ifNode)
pkg/config/compiler_routing.go:237:				if v := nodeVal(prop); v != "" {
pkg/config/compiler_routing.go:292:				ri.Description = nodeVal(prop)
pkg/config/compiler_routing.go:294:				ri.InstanceType = nodeVal(prop)
pkg/config/compiler_routing.go:296:				if v := nodeVal(prop); v != "" {
pkg/config/compiler_routing.go:312:								ri.InterfaceRoutesRibGroup = nodeVal(rgChild)
pkg/config/compiler_routing.go:314:								ri.InterfaceRoutesRibGroupV6 = nodeVal(rgChild)
pkg/config/compiler_routing.go:377:				if v := nodeVal(entry); v != "" {
pkg/config/compiler_routing.go:480:					if v := nodeVal(fc); v != "" {
pkg/config/compiler_routing.go:492:					if v := nodeVal(fc); v != "" {
pkg/config/compiler_routing.go:496:					if v := nodeVal(fc); v != "" {
pkg/config/compiler_routing.go:509:					term.NextHop = nodeVal(ac)
pkg/config/compiler_routing.go:511:					term.LoadBalance = nodeVal(ac)
pkg/config/compiler_routing.go:513:					if v := nodeVal(ac); v != "" {
pkg/config/compiler_routing.go:519:					if v := nodeVal(ac); v != "" {
pkg/config/compiler_routing.go:525:					if v := nodeVal(ac); v != "" {
pkg/config/compiler_routing.go:531:					term.Community = nodeVal(ac)
pkg/config/compiler_routing.go:533:					term.Origin = nodeVal(ac)
pkg/config/compiler_services.go:69:				if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:73:				poolName := nodeVal(prop)
pkg/config/compiler_services.go:88:							pool.Subnet = nodeVal(pp)
pkg/config/compiler_services.go:90:							pool.Router = nodeVal(pp)
pkg/config/compiler_services.go:92:							if v := nodeVal(pp); v != "" {
pkg/config/compiler_services.go:96:							if v := nodeVal(pp); v != "" {
pkg/config/compiler_services.go:102:							pool.Domain = nodeVal(pp)
pkg/config/compiler_services.go:129:				fs.URL = nodeVal(prop)
pkg/config/compiler_services.go:131:				fs.Hostname = nodeVal(prop)
pkg/config/compiler_services.go:133:				if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:139:				if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:145:				fnName := nodeVal(prop)
pkg/config/compiler_services.go:150:							fe.Path = nodeVal(c)
pkg/config/compiler_services.go:168:					if fn := nodeVal(c); fn != "" {
pkg/config/compiler_services.go:202:		if v := nodeVal(probeLimitNode); v != "" {
pkg/config/compiler_services.go:223:					test.ProbeType = nodeVal(prop)
pkg/config/compiler_services.go:229:						test.Target = nodeVal(urlChild)
pkg/config/compiler_services.go:231:						test.Target = nodeVal(prop)
pkg/config/compiler_services.go:234:					test.SourceAddress = nodeVal(prop)
pkg/config/compiler_services.go:236:					test.RoutingInstance = nodeVal(prop)
pkg/config/compiler_services.go:238:					if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:246:					if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:254:					if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:264:							if v := nodeVal(th); v != "" {
pkg/config/compiler_services.go:274:					if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:282:					if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:322:					if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:328:					if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:334:					if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:340:						if v := nodeVal(secNode); v != "" {
pkg/config/compiler_services.go:364:					if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:370:					if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:376:					if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:382:						if v := nodeVal(secNode); v != "" {
pkg/config/compiler_services.go:420:				fo.FamilyInet6Mode = nodeVal(modeNode)
pkg/config/compiler_services.go:444:				if v := nodeVal(rateNode); v != "" {
pkg/config/compiler_services.go:453:						if v := nodeVal(child); v != "" {
pkg/config/compiler_services.go:463:				mi.Output = nodeVal(ifNode)
pkg/config/compiler_services.go:486:					if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:536:			fsAddr := nodeVal(child)
pkg/config/compiler_services.go:546:						if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:552:						fs.Version9Template = nodeVal(prop)
pkg/config/compiler_services.go:557:							if v := nodeVal(tmplNode); v != "" {
pkg/config/compiler_services.go:564:						sf.SourceAddress = nodeVal(prop)
pkg/config/compiler_services.go:572:				sf.InlineJflowSourceAddress = nodeVal(saNode)
pkg/config/compiler_services.go:607:				if v := nodeVal(prop); v != "" {
pkg/config/compiler_services.go:611:				g.ActiveServerGroup = nodeVal(prop)
pkg/config/compiler_services.go:642:				if v := nodeVal(child); v != "" {
pkg/config/compiler_services.go:663:						if v := nodeVal(onNode); v != "" {
pkg/config/compiler_services.go:670:						if v := nodeVal(untilNode); v != "" {
pkg/config/compiler_services.go:713:			valStr := nodeVal(vlanNode)
pkg/config/compiler_services.go:729:			bd.RoutingInterface = nodeVal(riNode)
pkg/config/compiler_services.go:734:			bd.DomainType = nodeVal(dtNode)

exec
/bin/bash -lc "rg -n \"func namedInstances|namedInstances\\(\" pkg/config -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/config/compiler_ipsec.go:20:	for _, inst := range namedInstances(node.FindChildren("proposal")) {
pkg/config/compiler_ipsec.go:47:	for _, inst := range namedInstances(node.FindChildren("policy")) {
pkg/config/compiler_ipsec.go:73:	for _, inst := range namedInstances(node.FindChildren("gateway")) {
pkg/config/compiler_ipsec.go:197:	for _, inst := range namedInstances(node.FindChildren("proposal")) {
pkg/config/compiler_ipsec.go:222:	for _, inst := range namedInstances(node.FindChildren("policy")) {
pkg/config/compiler_ipsec.go:247:	for _, inst := range namedInstances(node.FindChildren("gateway")) {
pkg/config/compiler_ipsec.go:327:	for _, inst := range namedInstances(node.FindChildren("vpn")) {
pkg/config/compiler_ipsec.go:363:		for _, tsInst := range namedInstances(inst.node.FindChildren("traffic-selector")) {
pkg/config/compiler_class_of_service.go:123:		for _, inst := range namedInstances(classifiersNode.FindChildren("dscp")) {
pkg/config/compiler_class_of_service.go:156:		for _, inst := range namedInstances(classifiersNode.FindChildren("ieee-802.1")) {
pkg/config/compiler_class_of_service.go:192:		for _, inst := range namedInstances(rewriteRulesNode.FindChildren("dscp")) {
pkg/config/compiler_class_of_service.go:227:	for _, inst := range namedInstances(node.FindChildren("schedulers")) {
pkg/config/compiler_class_of_service.go:267:	for _, inst := range namedInstances(node.FindChildren("scheduler-maps")) {
pkg/config/compiler_class_of_service.go:291:	for _, inst := range namedInstances(node.FindChildren("interfaces")) {
pkg/config/compiler_services.go:63:	for _, groupInst := range namedInstances(node.FindChildren("group")) {
pkg/config/compiler_services.go:123:	for _, inst := range namedInstances(node.FindChildren("feed-server")) {
pkg/config/compiler_services.go:163:	for _, inst := range namedInstances(node.FindChildren("address-name")) {
pkg/config/compiler_services.go:211:	for _, probeInst := range namedInstances(node.FindChildren("probe")) {
pkg/config/compiler_services.go:217:		for _, testInst := range namedInstances(probeInst.node.FindChildren("test")) {
pkg/config/compiler_services.go:317:		for _, tmplInst := range namedInstances(v9Node.FindChildren("template")) {
pkg/config/compiler_services.go:359:		for _, tmplInst := range namedInstances(ipfixNode.FindChildren("template")) {
pkg/config/compiler_services.go:439:	for _, inst := range namedInstances(node.FindChildren("instance")) {
pkg/config/compiler_services.go:479:	for _, sampInst := range namedInstances(node.FindChildren("instance")) {
pkg/config/compiler_services.go:592:	for _, sgInst := range namedInstances(node.FindChildren("server-group")) {
pkg/config/compiler_services.go:602:	for _, gInst := range namedInstances(node.FindChildren("group")) {
pkg/config/compiler_services.go:622:	for _, pInst := range namedInstances(node.FindChildren("policy")) {
pkg/config/compiler_security.go:57:			for _, hostInst := range namedInstances(child.FindChildren("host")) {
pkg/config/compiler_security.go:89:	for _, inst := range namedInstances(node.FindChildren("security-zone")) {
pkg/config/compiler_security.go:149:			for _, polInst := range namedInstances(child.FindChildren("policy")) {
pkg/config/compiler_security.go:185:				for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
pkg/config/compiler_security.go:272:	for _, inst := range namedInstances(node.FindChildren("ids-option")) {
pkg/config/compiler_security.go:481:	for _, inst := range namedInstances(node.FindChildren("stream")) {
pkg/config/compiler_security.go:715:		for _, pfInst := range namedInstances(toNode.FindChildren("packet-filter")) {
pkg/config/compiler_nat.go:57:		for _, inst := range namedInstances(proxyNode.FindChildren("interface")) {
pkg/config/compiler_nat.go:105:	for _, inst := range namedInstances(node.FindChildren("rule-set")) {
pkg/config/compiler_nat.go:200:	for _, inst := range namedInstances(node.FindChildren("pool")) {
pkg/config/compiler_nat.go:422:	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
pkg/config/compiler_nat.go:442:		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
pkg/config/compiler_nat.go:556:	for _, inst := range namedInstances(node.FindChildren("pool")) {
pkg/config/compiler_nat.go:576:	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
pkg/config/compiler_nat.go:595:		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
pkg/config/compiler_nat.go:741:	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
pkg/config/compiler_nat.go:755:		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
pkg/config/compiler.go:1174:	for _, inst := range namedInstances(node.FindChildren("application")) {
pkg/config/compiler.go:1227:	for _, inst := range namedInstances(node.FindChildren("application-set")) {
pkg/config/compiler_interfaces.go:185:		for _, unitInst := range namedInstances(child.FindChildren("unit")) {
pkg/config/compiler_interfaces.go:307:						for _, addrInst := range namedInstances(afNode.FindChildren("address")) {
pkg/config/compiler_interfaces.go:317:							for _, vrrpInst := range namedInstances(addrInst.node.FindChildren("vrrp-group")) {
pkg/config/compiler_interfaces.go:412:						for _, addrInst := range namedInstances(afNode.FindChildren("address")) {
pkg/config/compiler_protocols.go:77:		for _, areaInst := range namedInstances(ospfNode.FindChildren("area")) {
pkg/config/compiler_protocols.go:80:			for _, ifInst := range namedInstances(areaInst.node.FindChildren("interface")) {
pkg/config/compiler_protocols.go:158:			for _, vlInst := range namedInstances(areaInst.node.FindChildren("virtual-link")) {
pkg/config/compiler_protocols.go:247:		for _, groupInst := range namedInstances(bgpNode.FindChildren("group")) {
pkg/config/compiler_protocols.go:464:		for _, areaInst := range namedInstances(ospf3Node.FindChildren("area")) {
pkg/config/compiler_protocols.go:467:			for _, ifInst := range namedInstances(areaInst.node.FindChildren("interface")) {
pkg/config/compiler_protocols.go:622:	for _, inst := range namedInstances(node.FindChildren("interface")) {
pkg/config/compiler_protocols.go:724:func namedInstances(nodes []*Node) []struct {
pkg/config/compiler_firewall.go:20:	for _, polInst := range namedInstances(node.FindChildren("policer")) {
pkg/config/compiler_firewall.go:68:	for _, tcpInst := range namedInstances(node.FindChildren("three-color-policer")) {
pkg/config/compiler_firewall.go:187:			for _, filterInst := range namedInstances(afNode.FindChildren("filter")) {
pkg/config/compiler_firewall.go:190:				for _, termInst := range namedInstances(filterInst.node.FindChildren("term")) {
pkg/config/compiler_firewall.go:317:			for _, rangeInst := range namedInstances(child.FindChildren("range")) {
pkg/config/compiler_system.go:82:			for _, userInst := range namedInstances(child.FindChildren("user")) {
pkg/config/compiler_system.go:258:			for _, slInst := range namedInstances(child.FindChildren("host")) {
pkg/config/compiler_system.go:275:			for _, fileInst := range namedInstances(child.FindChildren("file")) {
pkg/config/compiler_system.go:286:			for _, userInst := range namedInstances(child.FindChildren("user")) {
pkg/config/compiler_system.go:356:				for _, inst := range namedInstances(authNode.FindChildren("user")) {
pkg/config/compiler_system.go:816:	for _, inst := range namedInstances(node.FindChildren("scheduler")) {
pkg/config/compiler_system.go:956:	for _, rgInst := range namedInstances(clusterNode.FindChildren("redundancy-group")) {
pkg/config/compiler_routing.go:47:		for _, inst := range namedInstances(rgNode.FindChildren("")) {
pkg/config/compiler_routing.go:150:	for _, routeInst := range namedInstances(staticNode.FindChildren("route")) {
pkg/config/compiler_routing.go:358:	for _, inst := range namedInstances(node.FindChildren("prefix-list")) {
pkg/config/compiler_routing.go:369:	for _, inst := range namedInstances(node.FindChildren("community")) {
pkg/config/compiler_routing.go:414:	for _, inst := range namedInstances(node.FindChildren("policy-statement")) {

exec
/bin/bash -lc "nl -ba pkg/config/compiler_protocols.go | sed -n '724,770p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   724	func namedInstances(nodes []*Node) []struct {
   725		name string
   726		node *Node
   727	} {
   728		var result []struct {
   729			name string
   730			node *Node
   731		}
   732		for _, child := range nodes {
   733			if len(child.Keys) >= 2 {
   734				result = append(result, struct {
   735					name string
   736					node *Node
   737				}{child.Keys[1], child})
   738			} else {
   739				for _, sub := range child.Children {
   740					result = append(result, struct {
   741						name string
   742						node *Node
   743					}{sub.Name(), sub})
   744				}
   745			}
   746		}
   747		return result
   748	}
   749	
   750	// nodeVal returns the value for a property node, handling both AST shapes.
   751	// Hierarchical: Keys: ["prop", "value"] → returns "value"
   752	// Flat set:     Keys: ["prop"], Children: [Node{Keys:["value"]}] → returns "value"
   753	// parsePrefixLimit extracts the maximum prefix count from a family inet/inet6 node.
   754	// Walks: inet -> unicast -> prefix-limit -> maximum -> value
   755	func parsePrefixLimit(famNode *Node) int {
   756		unicast := famNode.FindChild("unicast")
   757		if unicast == nil {
   758			return 0
   759		}
   760		pl := unicast.FindChild("prefix-limit")
   761		if pl == nil {
   762			return 0
   763		}
   764		mx := pl.FindChild("maximum")
   765		if mx == nil {
   766			return 0
   767		}
   768		if v := nodeVal(mx); v != "" {
   769			if n, err := strconv.Atoi(v); err == nil {
   770				return n

exec
/bin/bash -lc "nl -ba pkg/config/compiler.go | sed -n '1408,1435p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
  1408			return fmt.Errorf("invalid protocol %q", proto)
  1409		}
  1410		if n < 0 || n > 255 {
  1411			return fmt.Errorf("invalid protocol number %d: must be 0-255", n)
  1412		}
  1413		return nil
  1414	}
  1415	
  1416	func nodeVal(n *Node) string {
  1417		if len(n.Keys) >= 2 {
  1418			return n.Keys[1]
  1419		}
  1420		if len(n.Children) > 0 {
  1421			return n.Children[0].Name()
  1422		}
  1423		return ""
  1424	}

exec
/bin/bash -lc "rg -n \"CompleteSetPathWithValues\\(|completeConfigWithDesc\\(|completeConfigPairs\\(\" pkg/*/*_test.go" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/grpcapi/completion_test.go:16:	pairs := s.completeConfigPairs([]string{"commit"}, "")
pkg/grpcapi/completion_test.go:24:	pairs := s.completeConfigPairs([]string{"load"}, "")
pkg/grpcapi/completion_test.go:40:	pairs := s.completeConfigPairs([]string{"com"}, "")
pkg/grpcapi/completion_test.go:48:	pairs := s.completeConfigPairs([]string{"co"}, "")
pkg/grpcapi/completion_test.go:56:	_ = s.completeConfigPairs([]string{"set", "security", "policies", "from-zone"}, "")
pkg/config/completion_prefix_test.go:27:	results := CompleteSetPathWithValues(resolved, nil)
pkg/config/completion_prefix_test.go:34:	results := CompleteSetPathWithValues([]string{"security", "s"}, nil)
pkg/config/completion_prefix_test.go:41:	results := CompleteSetPathWithValues([]string{"services", "rpm", "probe", "monitor", "test", "ping-test"}, nil)
pkg/config/completion_prefix_test.go:46:	targetResults := CompleteSetPathWithValues([]string{"services", "rpm", "probe", "monitor", "test", "ping-test", "target"}, nil)
pkg/config/parser_ast_test.go:5097:			results := CompleteSetPathWithValues(tc.tokens, nil)

exec
/bin/bash -lc "rg -n \"FindChildren\\(\\\"\\\"\\)|wildcard\" pkg/config/compiler_*.go pkg/config/compiler.go" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/config/compiler_routing.go:47:		for _, inst := range namedInstances(rgNode.FindChildren("")) {

exec
/bin/bash -lc "nl -ba pkg/config/ast.go | sed -n '1628,1667p;1915,1955p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
  1628						"bfd-liveness-detection": {children: map[string]*schemaNode{
  1629							"minimum-interval": {args: 1, children: nil},
  1630							"multiplier":       {args: 1, children: nil},
  1631						}},
  1632					}},
  1633					"authentication-key":  {args: 1, children: nil},
  1634					"authentication-type": {args: 1, children: nil},
  1635					"wide-metrics-only":   {children: nil},
  1636					"overload":            {children: nil},
  1637				}},
  1638			}},
  1639		}}},
  1640	}}
  1641	
  1642	func init() {
  1643		// Wire groups wildcard to mirror top-level schema children.
  1644		// This allows "set groups <name> security ..." etc. to parse correctly.
  1645		groupWild := setSchema.children["groups"].wildcard
  1646		groupWild.children = make(map[string]*schemaNode)
  1647		for k, v := range setSchema.children {
  1648			if k == "groups" || k == "apply-groups" {
  1649				continue
  1650			}
  1651			groupWild.children[k] = v
  1652		}
  1653	}
  1654	
  1655	// keysEqual returns true if two key slices are identical.
  1656	func keysEqual(a, b []string) bool {
  1657		if len(a) != len(b) {
  1658			return false
  1659		}
  1660		for i := range a {
  1661			if a[i] != b[i] {
  1662				return false
  1663			}
  1664		}
  1665		return true
  1666	}
  1667	
  1915	
  1916			if childSchema.multi && childSchema.children == nil {
  1917				continue
  1918			}
  1919			schema = childSchema
  1920		}
  1921	
  1922		return resolved, true
  1923	}

exec
/bin/bash -lc "rg -n \"func init\\(|setSchema.*groups|groups\" pkg/config/ast.go pkg/config/ast_groups.go | head -80" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
exec
/bin/bash -lc "nl -ba pkg/config/compiler_routing.go | sed -n '1,70p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
     1	package config
     2	
     3	import (
     4		"fmt"
     5		"strconv"
     6		"strings"
     7	)
     8	
     9	func compileRoutingOptions(node *Node, ro *RoutingOptionsConfig) error {
    10		// Parse autonomous-system
    11		if asNode := node.FindChild("autonomous-system"); asNode != nil {
    12			if v := nodeVal(asNode); v != "" {
    13				if n, err := strconv.ParseUint(v, 10, 32); err == nil {
    14					ro.AutonomousSystem = uint32(n)
    15				}
    16			}
    17		}
    18	
    19		// Parse forwarding-table { export <policy>; }
    20		if ftNode := node.FindChild("forwarding-table"); ftNode != nil {
    21			if expNode := ftNode.FindChild("export"); expNode != nil {
    22				ro.ForwardingTableExport = nodeVal(expNode)
    23			}
    24		}
    25	
    26		// Parse rib inet6.0 { static { route ... } }
    27		// In routing-instances, the rib name is "<instance>.inet6.0" (e.g., "ATT.inet6.0").
    28		for _, ribNode := range node.FindChildren("rib") {
    29			ribName := nodeVal(ribNode)
    30			if ribName == "inet6.0" || strings.HasSuffix(ribName, ".inet6.0") {
    31				if ribStatic := ribNode.FindChild("static"); ribStatic != nil {
    32					ro.Inet6StaticRoutes = compileStaticRoutes(ribStatic, ro.Inet6StaticRoutes)
    33				}
    34			}
    35		}
    36	
    37		staticNode := node.FindChild("static")
    38		if staticNode != nil {
    39			ro.StaticRoutes = compileStaticRoutes(staticNode, ro.StaticRoutes)
    40		}
    41	
    42		// Parse rib-groups
    43		if rgNode := node.FindChild("rib-groups"); rgNode != nil {
    44			if ro.RibGroups == nil {
    45				ro.RibGroups = make(map[string]*RibGroup)
    46			}
    47			for _, inst := range namedInstances(rgNode.FindChildren("")) {
    48				rg := &RibGroup{Name: inst.name}
    49				if irNode := inst.node.FindChild("import-rib"); irNode != nil {
    50					// import-rib [ rib1 rib2 ... ] or import-rib rib1;
    51					for i := 1; i < len(irNode.Keys); i++ {
    52						if irNode.Keys[i] == "[" || irNode.Keys[i] == "]" {
    53							continue
    54						}
    55						rg.ImportRibs = append(rg.ImportRibs, irNode.Keys[i])
    56					}
    57					for _, child := range irNode.Children {
    58						rg.ImportRibs = append(rg.ImportRibs, child.Name())
    59					}
    60				}
    61				ro.RibGroups[rg.Name] = rg
    62			}
    63			// Also handle direct children (non-named instances)
    64			for _, child := range rgNode.Children {
    65				name := child.Name()
    66				if _, exists := ro.RibGroups[name]; exists {
    67					continue
    68				}
    69				rg := &RibGroup{Name: name}
    70				if irNode := child.FindChild("import-rib"); irNode != nil {

exec
/bin/bash -lc "rg -n \"children: map\\[string\\]\\*schemaNode\\{\\}\" pkg/config/ast.go" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 105ms:
pkg/config/ast_groups.go:8:// ExpandGroups resolves all "apply-groups" references in the tree.
pkg/config/ast_groups.go:9:// It collects group definitions from the "groups" stanza, then for each
pkg/config/ast_groups.go:10:// "apply-groups <name>" node, clones the referenced group's children and
pkg/config/ast_groups.go:11:// merges them into the parent. After expansion, both "groups" and
pkg/config/ast_groups.go:12:// "apply-groups" nodes are removed from the tree.
pkg/config/ast_groups.go:24:// in apply-groups names before lookup. This supports Junos-style per-node
pkg/config/ast_groups.go:25:// group selection, e.g. apply-groups "${node}" with vars {"node": "node0"}.
pkg/config/ast_groups.go:42:	// Collect group definitions: groups { <name> { ... } }
pkg/config/ast_groups.go:43:	groups := make(map[string]*Node)
pkg/config/ast_groups.go:45:		if child.Name() == "groups" {
pkg/config/ast_groups.go:54:				groups[name] = g
pkg/config/ast_groups.go:59:	// If no groups defined, just strip any stale apply-groups references.
pkg/config/ast_groups.go:60:	if len(groups) == 0 {
pkg/config/ast_groups.go:64:	// Recursively resolve apply-groups at all levels.
pkg/config/ast_groups.go:66:	if err := expandGroupsRecursive(&t.Children, groups, nil, nil, tagInherited, vars); err != nil {
pkg/config/ast_groups.go:70:	// Remove the "groups" stanza itself.
pkg/config/ast_groups.go:73:		if child.Name() != "groups" {
pkg/config/ast_groups.go:91:// if any apply-groups node still references an undefined group. vars is used
pkg/config/ast_groups.go:99:		if child.Name() == "apply-groups" {
pkg/config/ast_groups.go:104:			return fmt.Errorf("apply-groups references undefined group %q", name)
pkg/config/ast_groups.go:142:// expandGroupsRecursive processes apply-groups nodes within a node list,
pkg/config/ast_groups.go:143:// then recurses into all children to handle nested apply-groups.
pkg/config/ast_groups.go:145:// groups to be walked down to the matching context for nested apply-groups.
pkg/config/ast_groups.go:149:func expandGroupsRecursive(nodes *[]*Node, groups map[string]*Node, ancestorPath [][]string, seen map[string]bool, tagInherited bool, vars map[string]string) error {
pkg/config/ast_groups.go:150:	// First, collect apply-groups references at this level.
pkg/config/ast_groups.go:151:	// Support bracket-list syntax: apply-groups [ name1 name2 ] produces
pkg/config/ast_groups.go:152:	// Keys = ["apply-groups", "name1", "name2"].
pkg/config/ast_groups.go:155:		if n.Name() == "apply-groups" {
pkg/config/ast_groups.go:164:		g, ok := groups[name]
pkg/config/ast_groups.go:166:			return fmt.Errorf("apply-groups references undefined group %q", name)
pkg/config/ast_groups.go:173:			return fmt.Errorf("apply-groups circular reference: group %q", name)
pkg/config/ast_groups.go:197:	// Remove apply-groups nodes.
pkg/config/ast_groups.go:200:		if n.Name() != "apply-groups" {
pkg/config/ast_groups.go:206:	// Recurse into children to handle nested apply-groups.
pkg/config/ast_groups.go:212:			if err := expandGroupsRecursive(&n.Children, groups, childPath, seen, tagInherited, vars); err != nil {
pkg/config/ast.go:402:	"groups":       {wildcard: &schemaNode{}}, // children set in init()
pkg/config/ast.go:403:	"apply-groups": {args: 1, multi: true, children: nil},
pkg/config/ast.go:836:		"rib-groups": {desc: "RIB groups", wildcard: &schemaNode{children: map[string]*schemaNode{
pkg/config/ast.go:1642:func init() {
pkg/config/ast.go:1643:	// Wire groups wildcard to mirror top-level schema children.
pkg/config/ast.go:1644:	// This allows "set groups <name> security ..." etc. to parse correctly.
pkg/config/ast.go:1645:	groupWild := setSchema.children["groups"].wildcard
pkg/config/ast.go:1648:		if k == "groups" || k == "apply-groups" {

 exited 1 in 112ms:
exec
/bin/bash -lc "nl -ba pkg/config/schema_validate_test.go | sed -n '60,115p;286,314p;326,345p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
    60		if !strings.Contains(err.Error(), "asd") {
    61			t.Fatalf("error should quote bad input: %v", err)
    62		}
    63	}
    64	
    65	func TestSchemaValidate_TransmitRate_AcceptsValid(t *testing.T) {
    66		if err := schemaCheck(t, `class-of-service {
    67	    schedulers {
    68	        be {
    69	            transmit-rate 1g;
    70	        }
    71	    }
    72	}`); err != nil {
    73			t.Fatalf("unexpected error: %v", err)
    74		}
    75	}
    76	
    77	func TestSchemaValidate_TransmitRate_AcceptsExactModifier(t *testing.T) {
    78		if err := schemaCheck(t, `class-of-service {
    79		    schedulers {
    80		        be {
    81	            transmit-rate 1g {
    82	                exact;
    83	            }
    84	        }
    85	    }
    86	}`); err != nil {
    87			t.Fatalf("unexpected error: %v", err)
    88		}
    89	}
    90	
    91	func TestSchemaValidate_TransmitRate_AcceptsSplitExactModifier(t *testing.T) {
    92		if err := flatSchemaCheck(t,
    93			"set class-of-service schedulers be transmit-rate 1g",
    94			"set class-of-service schedulers be transmit-rate exact",
    95		); err != nil {
    96			t.Fatalf("unexpected error: %v", err)
    97		}
    98	}
    99	
   100	func TestSchemaValidate_TransmitRate_RejectsSplitExactWithoutRate(t *testing.T) {
   101		err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate exact")
   102		if err == nil {
   103			t.Fatal("expected error for transmit-rate exact without a sibling rate, got nil")
   104		}
   105		if !strings.Contains(err.Error(), "transmit-rate") {
   106			t.Fatalf("error should reference transmit-rate: %v", err)
   107		}
   108	}
   109	
   110	func TestSchemaValidate_TransmitRate_RejectsTooSmall(t *testing.T) {
   111		err := schemaCheck(t, `class-of-service {
   112	    schedulers {
   113	        be {
   114	            transmit-rate 1;
   115	        }
   286		}
   287		if !strings.Contains(err.Error(), "transmit-rate") {
   288			t.Fatalf("error should reference transmit-rate: %v", err)
   289		}
   290	}
   291	
   292	func TestSchemaValidate_FlatSetSyntax_AcceptsValid(t *testing.T) {
   293		cmds := []string{
   294			"set class-of-service schedulers be transmit-rate 1g",
   295			"set class-of-service schedulers be priority strict-high",
   296			"set class-of-service schedulers be buffer-size 16m",
   297		}
   298		if err := flatSchemaCheck(t, cmds...); err != nil {
   299			t.Fatalf("expected no error, got %v", err)
   300		}
   301	}
   302	
   303	func TestSchemaValidate_AcceptedSchedulerValuesCompileAsValidated(t *testing.T) {
   304		tree := &config.ConfigTree{}
   305		cmds := []string{
   306			"set class-of-service schedulers be transmit-rate 8",
   307			"set class-of-service schedulers be transmit-rate exact",
   308			"set class-of-service schedulers be buffer-size 16m",
   309		}
   310		for _, cmd := range cmds {
   311			path, err := config.ParseSetCommand(cmd)
   312			if err != nil {
   313				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
   314			}
   326		sched := cfg.ClassOfService.Schedulers["be"]
   327		if sched == nil {
   328			t.Fatal("expected be scheduler")
   329		}
   330		if got := sched.TransmitRateBytes; got != 1 {
   331			t.Fatalf("transmit-rate bytes/sec = %d, want 1", got)
   332		}
   333		if !sched.TransmitRateExact {
   334			t.Fatal("expected transmit-rate exact")
   335		}
   336		if got := sched.BufferSizeBytes; got != 16000000 {
   337			t.Fatalf("buffer-size bytes = %d, want 16000000", got)
   338		}
   339	}
   340	
   341	func TestSchemaValidate_PercentBufferSizeCompilesAsPercentNotZeroBytes(t *testing.T) {
   342		tree := &config.ConfigTree{}
   343		cmds := []string{
   344			"set class-of-service schedulers be transmit-rate 8",
   345			"set class-of-service schedulers be buffer-size 10%",

exec
/bin/bash -lc "nl -ba pkg/cmdtree/schema_validate_test.go | sed -n '1,120p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
     1	package cmdtree
     2	
     3	import (
     4		"testing"
     5	
     6		"github.com/psaab/xpf/pkg/config"
     7	)
     8	
     9	// TestSchemaValidate_AcceptsLegacyDPDKSubStanza is the Codex r6 v3.3
    10	// fixture-strength regression gate for #1528. The plan v3.3 §4.7
    11	// contract requires that any future expansion of SchemaValidate
    12	// which walks `system dataplane` tolerates orphaned legacy DPDK
    13	// sub-stanzas that survive the `rewriteRetiredDataplaneType` bridge
    14	// (pkg/configstore/dataplane_retire.go, invoked from both Store.Load
    15	// and Store.SyncApply before compile + schema validation). The
    16	// bridge strips the `dataplane-type dpdk` leaf, but any nested
    17	// `system dataplane ...` sub-stanza remains; if a future
    18	// SchemaValidate walker rejects those orphaned leaves it would
    19	// preempt the operator-facing commit-time `ErrDPDKDataplaneRetired`
    20	// rejection AND break stored-config rolling upgrade (operational
    21	// blackout for pre-#1526 persisted DPDK configs).
    22	//
    23	// This test exercises the positive-path walker by including a valid
    24	// class-of-service schedulers block (defeating SchemaValidate's
    25	// "class-of-service absent" early return at schema_validate.go:43-46)
    26	// alongside the comprehensive legacy DPDK shape. The cos block
    27	// forces the walker to fire; the DPDK leaves must be ignored.
    28	//
    29	// Regression scenarios this gate catches:
    30	//
    31	//   - Unconditional system-dataplane walker added to SchemaValidate.
    32	//     The cos block still triggers the existing walker; if a new
    33	//     walker rejects the DPDK fixture, this test fires.
    34	//   - Removal of the class-of-service early-return so SchemaValidate
    35	//     walks all subtrees. The cos block exercises the real walker;
    36	//     any new system-dataplane validator without retired-backend
    37	//     tolerance rejects the DPDK leaves and fires this test.
    38	//   - New independent walker that fires only when cos is present.
    39	//     The cos block guarantees this regression class is hit.
    40	//
    41	// A pre-condition assertion confirms the fixture is structurally
    42	// valid (cos node present) even if a future refactor changes the
    43	// walker shape.
    44	func TestSchemaValidate_AcceptsLegacyDPDKSubStanza(t *testing.T) {
    45		tree := &config.ConfigTree{}
    46		for _, line := range []string{
    47			// class-of-service schedulers block — triggers the walker.
    48			"set class-of-service schedulers be-sched transmit-rate 1g",
    49			"set class-of-service schedulers be-sched priority low",
    50			"set class-of-service schedulers be-sched buffer-size 10%",
    51			// Legacy DPDK shape — must NOT be rejected.
    52			"set system dataplane-type dpdk",
    53			"set system dataplane cores 2-5",
    54			"set system dataplane memory 2048",
    55			"set system dataplane socket-mem \"1024,1024\"",
    56			"set system dataplane rx-mode adaptive",
    57			"set system dataplane rx-mode idle-threshold 256",
    58			"set system dataplane rx-mode resume-threshold 32",
    59			"set system dataplane rx-mode sleep-timeout 100",
    60			"set system dataplane ports 0000:03:00.0 interface wan0",
    61			"set system dataplane ports 0000:03:00.0 rx-mode polling",
    62			"set system dataplane ports 0000:03:00.0 cores 2-3",
    63			"set system dataplane ports 0000:06:00.0 interface trust0",
    64		} {
    65			path, err := config.ParseSetCommand(line)
    66			if err != nil {
    67				t.Fatalf("ParseSetCommand(%q): %v", line, err)
    68			}
    69			if err := tree.SetPath(path); err != nil {
    70				t.Fatalf("SetPath(%q): %v", line, err)
    71			}
    72		}
    73	
    74		// Pre-condition: the walker MUST actually fire. If a future
    75		// refactor changes the early-return condition such that the cos
    76		// node no longer triggers walking, this assertion catches it.
    77		if tree.FindChild("class-of-service") == nil {
    78			t.Fatal("fixture invalid: class-of-service subtree missing — walker would early-return; gate is useless")
    79		}
    80	
    81		// Assertion: SchemaValidate walks the cos block AND ignores the
    82		// legacy DPDK shape. If a future PR adds a top-level
    83		// system-dataplane walker without retired-backend tolerance,
    84		// this test fires.
    85		if err := SchemaValidate(tree, nil); err != nil {
    86			t.Fatalf("SchemaValidate rejected legacy DPDK sub-stanza alongside valid cos block: %v", err)
    87		}
    88	}

exec
/bin/bash -lc 'rg -n "transmit-rate exact|transmit-rate 1g;|transmit-rate 10m;|exact;" pkg/config/schema_validate_test.go pkg/cmdtree/schema_validate_test.go pkg/config/parser_class_of_service_test.go' in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/config/parser_class_of_service_test.go:95:		"set class-of-service schedulers be-sched transmit-rate exact",
pkg/config/parser_class_of_service_test.go:143:		t.Fatal("expected be-sched transmit-rate exact")
pkg/config/parser_class_of_service_test.go:279:				"set class-of-service schedulers ef-sched transmit-rate exact",
pkg/config/parser_class_of_service_test.go:301:			if !strings.Contains(err.Error(), "equal-flow-enforcement requires positive transmit-rate exact") {
pkg/config/parser_class_of_service_test.go:693:		t.Fatal("expected inline transmit-rate exact")
pkg/config/parser_class_of_service_test.go:701:		"set class-of-service schedulers iperf-a transmit-rate exact",
pkg/config/parser_class_of_service_test.go:729:		t.Fatal("expected transmit-rate exact")
pkg/config/parser_class_of_service_test.go:763:		t.Fatal("expected transmit-rate exact")
pkg/config/parser_class_of_service_test.go:778:            transmit-rate 1g exact;
pkg/config/parser_class_of_service_test.go:822:// without transmit-rate exact (#1183 lesson — runtime never sees
pkg/config/parser_class_of_service_test.go:883:		"set class-of-service schedulers iperf-a transmit-rate exact",
pkg/config/parser_class_of_service_test.go:885:		"set class-of-service schedulers iperf-b transmit-rate exact",
pkg/config/parser_class_of_service_test.go:929:		"set class-of-service schedulers iperf-a transmit-rate exact",
pkg/config/parser_class_of_service_test.go:931:		"set class-of-service schedulers iperf-b transmit-rate exact",
pkg/config/parser_class_of_service_test.go:1307:		"set class-of-service schedulers scheduler-iperf-b transmit-rate exact",
pkg/config/parser_class_of_service_test.go:1309:		"set class-of-service schedulers scheduler-iperf-c transmit-rate exact",
pkg/config/parser_class_of_service_test.go:1404:		"set class-of-service schedulers scheduler-iperf-a transmit-rate exact",
pkg/config/schema_validate_test.go:69:            transmit-rate 1g;
pkg/config/schema_validate_test.go:82:                exact;
pkg/config/schema_validate_test.go:94:		"set class-of-service schedulers be transmit-rate exact",
pkg/config/schema_validate_test.go:101:	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate exact")
pkg/config/schema_validate_test.go:103:		t.Fatal("expected error for transmit-rate exact without a sibling rate, got nil")
pkg/config/schema_validate_test.go:307:		"set class-of-service schedulers be transmit-rate exact",
pkg/config/schema_validate_test.go:334:		t.Fatal("expected transmit-rate exact")

exec
/bin/bash -lc 'rg -n "destination-port .* to|source-port .* to|range|multi-value leaf|trailing values" pkg/config/*test.go pkg/config/*.go' in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/config/parser_system_test.go:12:	for _, cmd := range setCommands {
pkg/config/parser_system_test.go:47:	for _, cmd := range setCommands {
pkg/config/parser_system_test.go:159:                    address-range low 10.0.1.100 high 10.0.1.200;
pkg/config/parser_system_test.go:171:                    address-range low 10.0.2.50 high 10.0.2.150;
pkg/config/parser_system_test.go:213:		t.Errorf("pool range: %s - %s", pool.RangeLow, pool.RangeHigh)
pkg/config/parser_system_test.go:228:	setCommands := []string{"set system services dhcp-local-server group test interface eth3.0", "set system services dhcp-local-server group test pool p1 subnet 172.16.0.0/24", "set system services dhcp-local-server group test pool p1 address-range low 172.16.0.10 high 172.16.0.50", "set system services dhcp-local-server group test pool p1 router 172.16.0.1"}
pkg/config/parser_system_test.go:229:	for _, cmd := range setCommands {
pkg/config/parser_system_test.go:259:	for _, cmd := range []string{"set system host-name test-fw", "set system backup-router 192.168.50.1 destination 192.168.0.0/16", "set system internet-options no-ipv6-reject-zero-hop-limit", "set system services ssh root-login allow", "set system services web-management http", "set system services web-management https", "set system syslog host 192.168.99.3 daemon info", "set system syslog file messages any any"} {
pkg/config/parser_system_test.go:452:	for _, tc := range cases {
pkg/config/parser_system_test.go:486:		for _, line := range setLines {
pkg/config/parser_system_test.go:521:	for _, s := range a {
pkg/config/parser_system_test.go:524:	for _, s := range b {
pkg/config/parser_system_test.go:621:	for _, u := range wm.APIAuth.Users {
pkg/config/parser_system_test.go:634:	for _, cmd := range cmds {
pkg/config/parser_system_test.go:719:	for i, exp := range expected {
pkg/config/parser_system_test.go:729:	for _, cmd := range cmds {
pkg/config/parser_system_test.go:886:	for _, line := range lines {
pkg/config/parser_system_test.go:1128:	for _, input := range tests {
pkg/config/parser_system_test.go:1142:		for _, w := range cfg.Warnings {
pkg/config/parser_system_test.go:1182:	for _, w := range cfg.Warnings {
pkg/config/parser_system_test.go:1278:	for _, line := range lines {
pkg/config/parser_system_test.go:1320:	for _, cmd := range setCommands {
pkg/config/parser_system_test.go:1347:	for _, cmd := range setCommands {
pkg/config/parser_system_test.go:1367:	for _, cmd := range []string{
pkg/config/parser_system_test.go:1403:	for _, cmd := range []string{
pkg/config/parser_system_test.go:1433:	for _, dataplaneType := range []string{"userspace"} {
pkg/config/parser_system_test.go:1461:		for _, cmd := range []string{
pkg/config/compiler_ipsec.go:20:	for _, inst := range namedInstances(node.FindChildren("proposal")) {
pkg/config/compiler_ipsec.go:22:		for _, p := range inst.node.Children {
pkg/config/compiler_ipsec.go:47:	for _, inst := range namedInstances(node.FindChildren("policy")) {
pkg/config/compiler_ipsec.go:49:		for _, p := range inst.node.Children {
pkg/config/compiler_ipsec.go:61:					for _, c := range p.Children {
pkg/config/compiler_ipsec.go:73:	for _, inst := range namedInstances(node.FindChildren("gateway")) {
pkg/config/compiler_ipsec.go:78:		for _, p := range inst.node.Children {
pkg/config/compiler_ipsec.go:122:					for _, c := range p.Children {
pkg/config/compiler_ipsec.go:132:					for _, c := range p.Children {
pkg/config/compiler_ipsec.go:142:					for _, c := range p.Children {
pkg/config/compiler_ipsec.go:165:	for _, c := range node.Children {
pkg/config/compiler_ipsec.go:197:	for _, inst := range namedInstances(node.FindChildren("proposal")) {
pkg/config/compiler_ipsec.go:199:		for _, p := range inst.node.Children {
pkg/config/compiler_ipsec.go:222:	for _, inst := range namedInstances(node.FindChildren("policy")) {
pkg/config/compiler_ipsec.go:224:		for _, p := range inst.node.Children {
pkg/config/compiler_ipsec.go:230:				for _, c := range p.Children {
pkg/config/compiler_ipsec.go:247:	for _, inst := range namedInstances(node.FindChildren("gateway")) {
pkg/config/compiler_ipsec.go:252:		for _, p := range inst.node.Children {
pkg/config/compiler_ipsec.go:296:					for _, c := range p.Children {
pkg/config/compiler_ipsec.go:306:					for _, c := range p.Children {
pkg/config/compiler_ipsec.go:315:					for _, c := range p.Children {
pkg/config/compiler_ipsec.go:327:	for _, inst := range namedInstances(node.FindChildren("vpn")) {
pkg/config/compiler_ipsec.go:329:		for _, p := range inst.node.Children {
pkg/config/compiler_ipsec.go:340:				for _, c := range p.Children {
pkg/config/compiler_ipsec.go:363:		for _, tsInst := range namedInstances(inst.node.FindChildren("traffic-selector")) {
pkg/config/compiler_ipsec.go:368:			for _, p := range tsInst.node.Children {
pkg/config/parser_class_of_service_test.go:110:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:177:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:213:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:226:	for _, want := range []string{"sum of buffer-size percent", "150", "100"} {
pkg/config/parser_class_of_service_test.go:244:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:285:	for _, tc := range tests {
pkg/config/parser_class_of_service_test.go:288:			for _, line := range tc.lines {
pkg/config/parser_class_of_service_test.go:315:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:347:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:376:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:397:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:455:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:482:	for _, tt := range tests {
pkg/config/parser_class_of_service_test.go:493:	for _, line := range []string{
pkg/config/parser_class_of_service_test.go:516:	for _, line := range []string{
pkg/config/parser_class_of_service_test.go:575:	for _, raw := range strings.Split(string(data), "\n") {
pkg/config/parser_class_of_service_test.go:672:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:708:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:745:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:835:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:852:	for _, w := range cfg.Warnings {
pkg/config/parser_class_of_service_test.go:893:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:908:	for _, w := range cfg.Warnings {
pkg/config/parser_class_of_service_test.go:940:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:954:	for _, w := range cfg.Warnings {
pkg/config/parser_class_of_service_test.go:1283:	if !strings.Contains(warnings, `forwarding-class "invalid-class" uses out-of-range queue 300`) {
pkg/config/parser_class_of_service_test.go:1284:		t.Fatalf("expected queue range warning, got: %s", warnings)
pkg/config/parser_class_of_service_test.go:1317:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:1363:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:1409:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:1452:	for _, line := range lines {
pkg/config/xfrmi_test.go:23:	for _, tt := range tests {
pkg/config/parser_ast_test.go:26:	for i, exp := range expected {
pkg/config/parser_ast_test.go:270:	for i := range expected {
pkg/config/parser_ast_test.go:280:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:366:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:480:	for _, child := range sysNode.Children {
pkg/config/parser_ast_test.go:493:	for _, child := range sysNode.Children {
pkg/config/parser_ast_test.go:506:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:570:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:582:		for _, c := range tree.Children {
pkg/config/parser_ast_test.go:584:				for _, c2 := range c.Children {
pkg/config/parser_ast_test.go:586:						for _, c3 := range c2.Children {
pkg/config/parser_ast_test.go:600:		for _, p := range *policies {
pkg/config/parser_ast_test.go:644:	for _, zp := range cfg.Security.Policies {
pkg/config/parser_ast_test.go:664:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:765:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:827:	for _, a := range expanded {
pkg/config/parser_ast_test.go:973:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:1060:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:1097:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:1227:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:1240:	for _, child := range unit0.Children {
pkg/config/parser_ast_test.go:1304:	for _, cmd := range deepCommands {
pkg/config/parser_ast_test.go:1366:	for _, w := range cfg.Warnings {
pkg/config/parser_ast_test.go:1492:	for _, w := range cfg.Warnings {
pkg/config/parser_ast_test.go:1660:	for _, name := range as.Applications {
pkg/config/parser_ast_test.go:1677:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:1695:	for _, name := range as.Applications {
pkg/config/parser_ast_test.go:1709:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:1833:	for _, cmd := range []string{"set security zones security-zone trust interfaces trust0", "set security zones security-zone trust host-inbound-traffic protocols router-discovery", "set security zones security-zone trust host-inbound-traffic protocols ospf"} {
pkg/config/parser_ast_test.go:1854:	for _, p := range protos {
pkg/config/parser_ast_test.go:1983:	for _, cmd := range cmds {
pkg/config/parser_ast_test.go:2284:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_ast_test.go:2291:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_ast_test.go:2324:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_ast_test.go:2341:	for _, line := range lines {
pkg/config/parser_ast_test.go:2359:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_ast_test.go:2605:	for _, cmd := range []string{"set system domain-name example.org", "set system domain-search corp.example.org", "set system domain-search dev.example.org"} {
pkg/config/parser_ast_test.go:2634:	for _, line := range lines {
pkg/config/parser_ast_test.go:2676:	for _, line := range lines {
pkg/config/parser_ast_test.go:2748:	for _, tt := range tests {
pkg/config/parser_ast_test.go:2790:	for _, line := range lines {
pkg/config/parser_ast_test.go:2955:	for _, line := range []string{
pkg/config/parser_ast_test.go:2976:	for _, w := range cfg.Warnings {
pkg/config/parser_ast_test.go:3007:	for _, line := range lines {
pkg/config/parser_ast_test.go:3063:	for _, line := range lines {
pkg/config/parser_ast_test.go:3120:	for _, line := range lines {
pkg/config/parser_ast_test.go:3190:	for _, line := range lines {
pkg/config/parser_ast_test.go:3225:	for _, value := range values {
pkg/config/parser_ast_test.go:3248:	for _, tc := range cases {
pkg/config/parser_ast_test.go:3259:			for _, line := range base {
pkg/config/parser_ast_test.go:3301:	for _, line := range lines {
pkg/config/parser_ast_test.go:3351:	for _, line := range base {
pkg/config/parser_ast_test.go:3385:	for _, line := range base {
pkg/config/parser_ast_test.go:3417:	for _, cmd := range cmds {
pkg/config/parser_ast_test.go:3445:	for _, cmd := range cmds {
pkg/config/parser_ast_test.go:3479:	for _, cmd := range cmds {
pkg/config/parser_ast_test.go:3544:	for _, cmd := range cmds {
pkg/config/parser_ast_test.go:3649:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3748:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3777:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3798:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3815:		for _, zp := range cfg.Security.Policies {
pkg/config/parser_ast_test.go:3827:	for _, p := range trustUntrust.Policies {
pkg/config/parser_ast_test.go:3843:	for _, p := range dmzUntrust.Policies {
pkg/config/parser_ast_test.go:3856:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3878:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3916:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3956:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3973:	for _, w := range cfg.Warnings {
pkg/config/parser_ast_test.go:3986:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:4007:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:4189:	for _, pol := range pair.Policies {
pkg/config/parser_ast_test.go:4276:	for i, pol := range pair.Policies {
pkg/config/parser_ast_test.go:4281:	for _, n := range names {
pkg/config/parser_ast_test.go:4362:	for _, pol := range pair.Policies {
pkg/config/parser_ast_test.go:4438:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:4456:	for _, pol := range pair.Policies {
pkg/config/parser_ast_test.go:4486:	for _, zpp := range cfg.Security.Policies {
pkg/config/parser_ast_test.go:4537:	for i, line := range lines {
pkg/config/parser_ast_test.go:4563:	for _, tt := range tests {
pkg/config/parser_ast_test.go:4576:	for _, tt := range tests {
pkg/config/parser_ast_test.go:4593:	for _, w := range warnings {
pkg/config/parser_ast_test.go:4634:	for _, w := range warnings {
pkg/config/parser_ast_test.go:4688:	for _, line := range lines {
pkg/config/parser_ast_test.go:4710:	for _, line := range lines {
pkg/config/parser_ast_test.go:4730:	for _, p := range protos {
pkg/config/parser_ast_test.go:4873:	for _, line := range lines {
pkg/config/parser_ast_test.go:4971:	for _, tt := range tests {
pkg/config/parser_ast_test.go:4974:			for _, line := range tt.lines {
pkg/config/parser_ast_test.go:5058:	for _, tc := range tests {
pkg/config/parser_ast_test.go:5080:	for _, tc := range tests {
pkg/config/parser_ast_test.go:5095:	for _, tc := range tests {
pkg/config/parser_ast_test.go:5105:			for _, r := range results {
pkg/config/parser_ast_test.go:5113:				for i, r := range results {
pkg/config/parser_security_test.go:11:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:201:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:229:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:315:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:340:        filter port-range-test {
pkg/config/parser_security_test.go:341:            term block-range {
pkg/config/parser_security_test.go:364:	f, ok := cfg.Firewall.FiltersInet["port-range-test"]
pkg/config/parser_security_test.go:366:		t.Fatal("expected port-range-test filter")
pkg/config/parser_security_test.go:442:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:467:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:501:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:613:	for _, line := range lines {
pkg/config/parser_security_test.go:721:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:935:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1024:	for _, w := range cfg.Warnings {
pkg/config/parser_security_test.go:1034:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1082:	for _, w := range cfg.Warnings {
pkg/config/parser_security_test.go:1141:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1261:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1376:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1468:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1745:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1780:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1907:	for _, line := range lines {
pkg/config/parser_security_test.go:1963:	for _, svc := range services {
pkg/config/parser_security_test.go:1968:	for svc, found := range expected {
pkg/config/parser_security_test.go:2022:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:2152:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:2184:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:2238:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:2278:	for _, cmd := range []string{"set security zones security-zone trust interfaces trust0", "set security zones security-zone trust interfaces trust1", "set security zones security-zone trust screen untrust-screen", "set security zones security-zone trust host-inbound-traffic system-services ping", "set security zones security-zone trust host-inbound-traffic system-services ssh", "set security zones security-zone trust host-inbound-traffic protocols ospf", "set security zones security-zone untrust interfaces untrust0"} {
pkg/config/parser_security_test.go:2323:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:2355:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:2383:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:2410:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:2432:	for _, cmd := range []string{"set security screen ids-option untrust-screen icmp ping-death", "set security screen ids-option untrust-screen tcp land", "set security screen ids-option untrust-screen tcp syn-flood alarm-threshold 1000", "set security screen ids-option untrust-screen tcp syn-flood attack-threshold 500", "set security screen ids-option untrust-screen ip source-route-option"} {
pkg/config/parser_security_test.go:2467:	for _, cmd := range []string{"set security nat source pool snat-pool address 203.0.113.0/24", "set security nat source rule-set trust-to-untrust from zone trust", "set security nat source rule-set trust-to-untrust to zone untrust", "set security nat source rule-set trust-to-untrust rule snat-rule match source-address 10.0.0.0/8", "set security nat source rule-set trust-to-untrust rule snat-rule then source-nat interface"} {
pkg/config/parser_security_test.go:2513:	for _, cmd := range []string{"set security policies from-zone trust to-zone untrust policy allow-all match source-address any", "set security policies from-zone trust to-zone untrust policy allow-all match destination-address any", "set security policies from-zone trust to-zone untrust policy allow-all match application any", "set security policies from-zone trust to-zone untrust policy allow-all then permit", "set security policies from-zone trust to-zone untrust policy allow-all then log session-init", "set security policies from-zone trust to-zone untrust policy allow-all then count"} {
pkg/config/parser_security_test.go:2555:	for _, cmd := range []string{"set security policies from-zone lan to-zone wan policy allow-ps match destination-address any source-address any application any", "set security policies from-zone lan to-zone wan policy allow-ps then permit"} {
pkg/config/parser_security_test.go:2647:	for _, cmd := range []string{"set security policies global policy allow-icmpv6 match source-address any-ipv6", "set security policies global policy allow-icmpv6 match destination-address any-ipv6", "set security policies global policy allow-icmpv6 match application junos-icmp6-all", "set security policies global policy allow-icmpv6 then permit"} {
pkg/config/parser_security_test.go:2670:	for _, cmd := range []string{"set applications application my-http protocol tcp", "set applications application my-http destination-port 8080", "set applications application-set web-apps application my-http", "set applications application-set web-apps application junos-https"} {
pkg/config/parser_security_test.go:2832:	for _, rs := range cfg.Security.NAT.Source {
pkg/config/parser_security_test.go:2838:	for _, pair := range []string{"guest->Internet-ATT", "guest->Internet-BCI", "lan->Internet-ATT", "lan->Internet-BCI", "dmz->Internet-ATT", "dmz->Internet-BCI"} {
pkg/config/parser_security_test.go:2850:	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
pkg/config/parser_security_test.go:2860:	for _, cmd := range []string{"set security nat source rule-set internal-to-internet from zone [ guest lan ]", "set security nat source rule-set internal-to-internet to zone Internet-ATT", "set security nat source rule-set internal-to-internet rule catch-all match source-address 0.0.0.0/0", "set security nat source rule-set internal-to-internet rule catch-all then source-nat interface"} {
pkg/config/parser_security_test.go:2877:	for _, rs := range cfg.Security.NAT.Source {
pkg/config/parser_security_test.go:2957:	for _, cmd := range []string{"set security nat source rule-set exempt from zone internal", "set security nat source rule-set exempt to zone Internet", "set security nat source rule-set exempt rule no-nat match source-address 192.203.228.0/24", "set security nat source rule-set exempt rule no-nat then source-nat off"} {
pkg/config/parser_security_test.go:3097:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:3136:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:3390:	for _, p := range policies {
pkg/config/parser_security_test.go:3401:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:3517:	for _, line := range lines {
pkg/config/parser_security_test.go:3549:                rule port-range {
pkg/config/parser_security_test.go:3591:	lines := []string{"set security nat destination pool web1 address 10.0.30.100", "set security nat destination rule-set wan-dnat from zone untrust", "set security nat destination rule-set wan-dnat rule r1 match destination-address 50.0.0.1/32", "set security nat destination rule-set wan-dnat rule r1 match destination-port 80", "set security nat destination rule-set wan-dnat rule r1 match destination-port 443", "set security nat destination rule-set wan-dnat rule r1 match destination-port 20000 to 20003", "set security nat destination rule-set wan-dnat rule r1 then destination-nat pool web1"}
pkg/config/parser_security_test.go:3593:	for _, line := range lines {
pkg/config/parser_security_test.go:3730:	for i, w := range want {
pkg/config/parser_security_test.go:3740:	for _, line := range lines {
pkg/config/parser_security_test.go:3764:	for i, w := range want {
pkg/config/parser_security_test.go:3931:	for i, w := range want {
pkg/config/parser_security_test.go:3941:	for _, line := range lines {
pkg/config/parser_security_test.go:3962:	for i, w := range wantSrc {
pkg/config/parser_security_test.go:3971:	for i, w := range wantDst {
pkg/config/parser_security_test.go:4038:	for _, line := range lines {
pkg/config/parser_security_test.go:4120:	for _, line := range lines {
pkg/config/parser_security_test.go:4178:	for _, line := range lines {
pkg/config/parser_security_test.go:4205:                    flexible-match-range {
pkg/config/parser_security_test.go:4206:                        range proto-check {
pkg/config/parser_security_test.go:4259:	lines := []string{"set firewall family inet filter flex-set term t1 from flexible-match-range range r1 match-start layer-3", "set firewall family inet filter flex-set term t1 from flexible-match-range range r1 byte-offset 12", "set firewall family inet filter flex-set term t1 from flexible-match-range range r1 bit-length 32", "set firewall family inet filter flex-set term t1 from flexible-match-range range r1 range 0x0a000000/0xff000000", "set firewall family inet filter flex-set term t1 then discard"}
pkg/config/parser_security_test.go:4261:	for _, line := range lines {
pkg/config/parser_security_test.go:4297:	for _, cmd := range setCommands {
pkg/config/parser_services_test.go:175:			name: "destination port range validated",
pkg/config/parser_services_test.go:192:	for _, tc := range tests {
pkg/config/parser_services_test.go:261:	for _, cmd := range setCommands {
pkg/config/parser_services_test.go:454:	for _, cmd := range commands {
pkg/config/parser_services_test.go:563:	for _, cmd := range setCommands {
pkg/config/parser_services_test.go:664:	for _, cmd := range setCommands {
pkg/config/parser_services_test.go:712:	for _, cmd := range setCommands {
pkg/config/parser_services_test.go:786:	for _, cmd := range cmds {
pkg/config/parser_services_test.go:859:	for _, cmd := range []string{"set security nat proxy-arp interface trust0.0 address 10.0.1.100/32", "set security nat proxy-arp interface trust0.0 address 10.0.1.101/32 to 10.0.1.110/32"} {
pkg/config/parser_services_test.go:882:	for _, cmd := range []string{"set security nat proxy-arp interface untrust0.0 address 203.0.113.5/32"} {
pkg/config/parser_services_test.go:908:	for _, cmd := range []string{"set security nat proxy-arp interface trust0.0 address 10.0.1.50"} {
pkg/config/parser_services_test.go:1019:	for _, line := range lines {
pkg/config/parser_services_test.go:1118:	for _, line := range lines {
pkg/config/parser_services_test.go:1135:	for _, w := range cfg.Warnings {
pkg/config/parser_services_test.go:1156:	for _, line := range lines {
pkg/config/parser_services_test.go:1169:	for _, w := range cfg.Warnings {
pkg/config/compiler_interfaces.go:10:	for _, child := range node.Children {
pkg/config/compiler_interfaces.go:114:				for _, m := range miNode.Children {
pkg/config/compiler_interfaces.go:135:			for _, prop := range tunnelNode.Children {
pkg/config/compiler_interfaces.go:185:		for _, unitInst := range namedInstances(child.FindChildren("unit")) {
pkg/config/compiler_interfaces.go:221:				for _, prop := range tunnelNode.Children {
pkg/config/compiler_interfaces.go:293:			for _, familyNode := range unitInst.node.FindChildren("family") {
pkg/config/compiler_interfaces.go:300:				for _, afNode := range afNodes {
pkg/config/compiler_interfaces.go:307:						for _, addrInst := range namedInstances(afNode.FindChildren("address")) {
pkg/config/compiler_interfaces.go:317:							for _, vrrpInst := range namedInstances(addrInst.node.FindChildren("vrrp-group")) {
pkg/config/compiler_interfaces.go:326:								for _, prop := range vrrpInst.node.Children {
pkg/config/compiler_interfaces.go:367:								for _, prop := range dhcpNode.Children {
pkg/config/compiler_interfaces.go:412:						for _, addrInst := range namedInstances(afNode.FindChildren("address")) {
pkg/config/compiler_interfaces.go:455:							for _, prop := range dcNode.Children {
pkg/config/types_test.go:66:	for _, tt := range tests {
pkg/config/types_test.go:122:	for _, tt := range tests {
pkg/config/types_test.go:154:	for _, tt := range tests {
pkg/config/types_test.go:189:	for _, tt := range tests {
pkg/config/types_test.go:328:	for _, tt := range tests {
pkg/config/types_test.go:382:	for _, tt := range tests {
pkg/config/compiler_firewall.go:20:	for _, polInst := range namedInstances(node.FindChildren("policer")) {
pkg/config/compiler_firewall.go:28:			for _, child := range ifExceeding.Children {
pkg/config/compiler_firewall.go:44:			for _, child := range thenNode.Children {
pkg/config/compiler_firewall.go:68:	for _, tcpInst := range namedInstances(node.FindChildren("three-color-policer")) {
pkg/config/compiler_firewall.go:83:		for _, sr := range singleRates {
pkg/config/compiler_firewall.go:91:			for _, child := range sr.Children {
pkg/config/compiler_firewall.go:114:		for _, tr := range twoRates {
pkg/config/compiler_firewall.go:122:			for _, child := range tr.Children {
pkg/config/compiler_firewall.go:145:			for _, child := range thenNode.Children {
pkg/config/compiler_firewall.go:158:	for _, familyNode := range node.FindChildren("family") {
pkg/config/compiler_firewall.go:168:			for _, child := range familyNode.Children {
pkg/config/compiler_firewall.go:173:		for _, afNode := range afNodes {
pkg/config/compiler_firewall.go:187:			for _, filterInst := range namedInstances(afNode.FindChildren("filter")) {
pkg/config/compiler_firewall.go:190:				for _, termInst := range namedInstances(filterInst.node.FindChildren("term")) {
pkg/config/compiler_firewall.go:218:	for _, child := range node.Children {
pkg/config/compiler_firewall.go:233:			for _, addrNode := range child.Children {
pkg/config/compiler_firewall.go:242:			for _, addrNode := range child.Children {
pkg/config/compiler_firewall.go:250:				for _, k := range child.Keys[1:] {
pkg/config/compiler_firewall.go:255:			for _, portNode := range child.Children {
pkg/config/compiler_firewall.go:262:			for _, plNode := range child.Children {
pkg/config/compiler_firewall.go:270:			for _, plNode := range child.Children {
pkg/config/compiler_firewall.go:279:				for _, k := range child.Keys[1:] {
pkg/config/compiler_firewall.go:283:			for _, portNode := range child.Children {
pkg/config/compiler_firewall.go:305:				for _, k := range child.Keys[1:] {
pkg/config/compiler_firewall.go:309:			for _, flagNode := range child.Children {
pkg/config/compiler_firewall.go:316:		case "flexible-match-range":
pkg/config/compiler_firewall.go:317:			for _, rangeInst := range namedInstances(child.FindChildren("range")) {
pkg/config/compiler_firewall.go:319:				for _, rc := range rangeInst.node.Children {
pkg/config/compiler_firewall.go:337:					case "range", "match-value":
pkg/config/compiler_firewall.go:376:				break // only first range supported per term
pkg/config/compiler_firewall.go:386:		for _, k := range node.Keys[1:] {
pkg/config/compiler_firewall.go:403:	for _, child := range node.Children {
pkg/config/compiler_class_of_service.go:82:		for _, queueNode := range fcNode.FindChildren("queue") {
pkg/config/compiler_class_of_service.go:123:		for _, inst := range namedInstances(classifiersNode.FindChildren("dscp")) {
pkg/config/compiler_class_of_service.go:125:			for _, fcNode := range inst.node.FindChildren("forwarding-class") {
pkg/config/compiler_class_of_service.go:133:				for _, lpNode := range fcNode.FindChildren("loss-priority") {
pkg/config/compiler_class_of_service.go:156:		for _, inst := range namedInstances(classifiersNode.FindChildren("ieee-802.1")) {
pkg/config/compiler_class_of_service.go:158:			for _, fcNode := range inst.node.FindChildren("forwarding-class") {
pkg/config/compiler_class_of_service.go:166:				for _, lpNode := range fcNode.FindChildren("loss-priority") {
pkg/config/compiler_class_of_service.go:192:		for _, inst := range namedInstances(rewriteRulesNode.FindChildren("dscp")) {
pkg/config/compiler_class_of_service.go:194:			for _, fcNode := range inst.node.FindChildren("forwarding-class") {
pkg/config/compiler_class_of_service.go:202:				for _, lpNode := range fcNode.FindChildren("loss-priority") {
pkg/config/compiler_class_of_service.go:227:	for _, inst := range namedInstances(node.FindChildren("schedulers")) {
pkg/config/compiler_class_of_service.go:229:		for _, child := range inst.node.Children {
pkg/config/compiler_class_of_service.go:267:	for _, inst := range namedInstances(node.FindChildren("scheduler-maps")) {
pkg/config/compiler_class_of_service.go:272:		for _, child := range inst.node.Children {
pkg/config/compiler_class_of_service.go:291:	for _, inst := range namedInstances(node.FindChildren("interfaces")) {
pkg/config/compiler_class_of_service.go:296:		for _, unitNode := range inst.node.FindChildren("unit") {
pkg/config/compiler_class_of_service.go:402:			for _, ifindexNode := range rssNode.FindChildren("ifindex") {
pkg/config/compiler_class_of_service.go:410:				for _, queueNode := range ifindexNode.FindChildren("queue") {
pkg/config/compiler_class_of_service.go:469:		for _, name := range names {
pkg/config/compiler_class_of_service.go:498:	for _, key := range node.Keys[1:] {
pkg/config/compiler_class_of_service.go:516:	for _, child := range node.FindChildren("code-points") {
pkg/config/compiler_class_of_service.go:517:		for _, raw := range child.Keys[1:] {
pkg/config/compiler_class_of_service.go:518:			for _, value := range expandCoSCodePointToken(raw) {
pkg/config/compiler_class_of_service.go:533:	for _, child := range node.FindChildren("code-points") {
pkg/config/compiler_class_of_service.go:534:		for _, raw := range child.Keys[1:] {
pkg/config/compiler_class_of_service.go:555:	for _, child := range node.FindChildren("code-point") {
pkg/config/compiler_class_of_service.go:563:	for _, child := range node.FindChildren("code-points") {
pkg/config/compiler_class_of_service.go:564:		for _, raw := range child.Keys[1:] {
pkg/config/completion_prefix_test.go:7:	for i, result := range results {
pkg/config/completion_prefix_test.go:14:	for _, result := range results {
pkg/config/schema_validators.go:108:		return 0, fmt.Errorf("percent out of range (0,100] (got %s); note: 0%% is not supported -- omit buffer-size to use the default burst", orig)
pkg/config/schema_validators.go:114:// [min, max] inclusive. min > max disables the range check.
pkg/config/schema_validators.go:125:			return fmt.Errorf("integer out of range [%d..%d] (got %d)", min, max, v)
pkg/config/schema_validators.go:137:	for _, a := range sorted {
pkg/config/schema_validators.go:160:			return fmt.Errorf("percent out of range [%.2f..%.2f] (got %s)", min, max, raw)
pkg/config/types.go:55:	for _, ifc := range c.Interfaces.Interfaces {
pkg/config/types.go:361:	for _, bd := range bds {
pkg/config/types.go:1103:	SourcePorts       []string        // source port numbers or ranges
pkg/config/types.go:1116:	FlexMatch         *FlexMatchConfig // flexible-match-range configuration
pkg/config/types.go:1378:	Addresses []string // /32 CIDRs (expanded from ranges)
pkg/config/types.go:1463:	PortLow       int      // source pool port range low (default 1024)
pkg/config/types.go:1464:	PortHigh      int      // source pool port range high (default 65535)
pkg/config/types.go:1928:	for ifName, ifc := range c.Interfaces.Interfaces {
pkg/config/types.go:1932:			for unitNum := range ifc.Units {
pkg/config/types.go:1939:		for unitNum, unit := range ifc.Units {
pkg/config/parser_cluster_test.go:74:	for _, cmd := range commands {
pkg/config/parser_cluster_test.go:161:	for i, rg := range cl.RedundancyGroups {
pkg/config/parser_cluster_test.go:180:	for _, cmd := range commands {
pkg/config/parser_cluster_test.go:215:	for i, rg := range cl.RedundancyGroups {
pkg/config/parser_cluster_test.go:234:	for _, cmd := range commands {
pkg/config/parser_cluster_test.go:299:	for _, cmd := range commands {
pkg/config/parser_cluster_test.go:346:	for _, line := range sets {
pkg/config/parser_cluster_test.go:415:	for _, line := range sets {
pkg/config/parser_cluster_test.go:543:	for _, cmd := range commands {
pkg/config/parser_cluster_test.go:629:	for _, cmd := range commands {
pkg/config/parser_cluster_test.go:688:	for _, line := range sets {
pkg/config/parser_cluster_test.go:757:	for _, line := range sets {
pkg/config/parser_cluster_test.go:850:	for _, w := range warnings {
pkg/config/parser_cluster_test.go:864:	for _, w := range warnings {
pkg/config/parser_cluster_test.go:878:	for _, w := range warnings {
pkg/config/parser_cluster_test.go:891:	for _, w := range warnings {
pkg/config/parser_cluster_test.go:903:	for _, tt := range tests {
pkg/config/parser_cluster_test.go:927:	for _, tt := range tests {
pkg/config/parser_cluster_test.go:938:	for _, cmd := range cmds {
pkg/config/parser_cluster_test.go:970:	for _, cmd := range cmds {
pkg/config/parser_cluster_test.go:1002:	for _, cmd := range cmds {
pkg/config/parser_cluster_test.go:1030:	for _, cmd := range cmds {
pkg/config/parser_cluster_test.go:1061:	for _, cmd := range cmds {
pkg/config/parser_cluster_test.go:1092:	for _, cmd := range cmds {
pkg/config/parser_cluster_test.go:1120:	for _, cmd := range cmds {
pkg/config/parser_cluster_test.go:1145:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:11:	for _, cmd := range setCommands {
pkg/config/parser_routing_test.go:162:	for _, cmd := range setCommands {
pkg/config/parser_routing_test.go:222:	for _, cmd := range setCommands {
pkg/config/parser_routing_test.go:352:	for _, a := range expanded {
pkg/config/parser_routing_test.go:355:	for _, expected := range []string{"srv1", "srv2", "srv3"} {
pkg/config/parser_routing_test.go:362:	for _, cmd := range setCommands {
pkg/config/parser_routing_test.go:405:	for _, cmd := range setCommands {
pkg/config/parser_routing_test.go:425:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_routing_test.go:538:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_routing_test.go:568:	for _, cmd := range []string{"set routing-instances vpn-fwd instance-type forwarding", "set routing-instances vpn-fwd routing-options static route 10.99.0.0/16 next-hop 10.0.40.1", "set routing-instances normal-vr instance-type virtual-router", "set routing-instances normal-vr interface trust0"} {
pkg/config/parser_routing_test.go:582:	for _, ri := range cfg2.RoutingInstances {
pkg/config/parser_routing_test.go:598:	for _, cmd := range setCommands {
pkg/config/parser_routing_test.go:616:	for _, ra := range cfg.Protocols.RouterAdvertisement {
pkg/config/parser_routing_test.go:769:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:862:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:920:	for _, cmd := range []string{"set protocols bgp local-as 64701", "set protocols bgp group ebgp-peer family inet unicast", "set protocols bgp group ebgp-peer family inet6 unicast", "set protocols bgp group ebgp-peer export my-export-policy", "set protocols bgp group ebgp-peer peer-as 65002", "set protocols bgp group ebgp-peer neighbor 10.1.0.1", "set protocols bgp group ebgp-peer neighbor 10.2.0.1"} {
pkg/config/parser_routing_test.go:1039:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1083:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1111:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1142:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1168:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1205:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1248:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1282:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1310:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1352:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1380:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1399:	for _, cmd := range cmds2 {
pkg/config/parser_routing_test.go:1420:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1449:	for _, iface := range area.Interfaces {
pkg/config/parser_routing_test.go:1468:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1487:	for _, iface := range area.Interfaces {
pkg/config/parser_routing_test.go:1506:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1531:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1559:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1587:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1615:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1640:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1668:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1696:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1724:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1752:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1810:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1851:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1888:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1926:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1955:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1991:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2024:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2094:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2167:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2202:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2276:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2314:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2343:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2372:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2449:	for _, line := range lines {
pkg/config/parser_routing_test.go:2485:	for _, line := range lines {
pkg/config/parser_routing_test.go:2565:	for _, line := range lines {
pkg/config/parser_routing_test.go:2585:	for _, iface := range cfg.Protocols.LLDP.Interfaces {
pkg/config/parser_routing_test.go:2642:	for _, line := range lines {
pkg/config/parser_routing_test.go:2659:	for _, gr := range cfg.RoutingOptions.GenerateRoutes {
pkg/config/parser_routing_test.go:2705:	for _, bd := range cfg.BridgeDomains {
pkg/config/parser_routing_test.go:2739:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2756:	for _, bd := range cfg.BridgeDomains {
pkg/config/parser_routing_test.go:2790:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2841:	if !strings.Contains(err.Error(), "out of range") {
pkg/config/parser_routing_test.go:2863:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2895:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2930:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2964:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:3008:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:3036:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:3064:	for _, line := range lines {
pkg/config/parser_routing_test.go:3136:	for _, line := range lines {
pkg/config/compiler.go:114:	for _, node := range tree.Children {
pkg/config/compiler.go:202:		for ifName, ifc := range cfg.Interfaces.Interfaces {
pkg/config/compiler.go:206:			for _, member := range ifc.FabricMembers {
pkg/config/compiler.go:239:					for _, addr := range u0.Addresses {
pkg/config/compiler.go:298:		for _, w := range warnings {
pkg/config/compiler.go:316:	for name, pol := range policers {
pkg/config/compiler.go:401:	for _, zpp := range cfg.Security.Policies {
pkg/config/compiler.go:405:		for _, pol := range zpp.Policies {
pkg/config/compiler.go:411:	for _, pol := range cfg.Security.GlobalPolicies {
pkg/config/compiler.go:423:	for _, sched := range cos.Schedulers {
pkg/config/compiler.go:461:	for _, schedMap := range cos.SchedulerMaps {
pkg/config/compiler.go:466:		for _, entry := range schedMap.Entries {
pkg/config/compiler.go:530:	for name := range cfg.Security.Zones {
pkg/config/compiler.go:537:		for name := range ab.Addresses {
pkg/config/compiler.go:540:		for name := range ab.AddressSets {
pkg/config/compiler.go:547:	for name := range cfg.Applications.Applications {
pkg/config/compiler.go:550:	for name := range cfg.Applications.ApplicationSets {
pkg/config/compiler.go:560:	for _, b := range builtins {
pkg/config/compiler.go:565:	for name, app := range cfg.Applications.Applications {
pkg/config/compiler.go:580:	for _, zpp := range cfg.Security.Policies {
pkg/config/compiler.go:589:		for _, p := range zpp.Policies {
pkg/config/compiler.go:590:			for _, addr := range p.Match.SourceAddresses {
pkg/config/compiler.go:596:			for _, addr := range p.Match.DestinationAddresses {
pkg/config/compiler.go:602:			for _, app := range p.Match.Applications {
pkg/config/compiler.go:612:	for _, rs := range cfg.Security.NAT.Source {
pkg/config/compiler.go:624:	for name, zone := range cfg.Security.Zones {
pkg/config/compiler.go:635:		for name, entry := range ab.Addresses {
pkg/config/compiler.go:646:		for setName, as := range ab.AddressSets {
pkg/config/compiler.go:647:			for _, m := range as.Addresses {
pkg/config/compiler.go:653:			for _, m := range as.AddressSets {
pkg/config/compiler.go:663:	for _, sr := range cfg.RoutingOptions.StaticRoutes {
pkg/config/compiler.go:674:		for _, rs := range dnat.RuleSets {
pkg/config/compiler.go:675:			for _, rule := range rs.Rules {
pkg/config/compiler.go:688:	for _, rs := range cfg.Security.NAT.Source {
pkg/config/compiler.go:689:		for _, rule := range rs.Rules {
pkg/config/compiler.go:702:	for name := range cfg.Interfaces.Interfaces {
pkg/config/compiler.go:705:	for zoneName, zone := range cfg.Security.Zones {
pkg/config/compiler.go:706:		for _, ifName := range zone.Interfaces {
pkg/config/compiler.go:720:	for _, zpp := range cfg.Security.Policies {
pkg/config/compiler.go:721:		for _, p := range zpp.Policies {
pkg/config/compiler.go:730:	for _, p := range cfg.Security.GlobalPolicies {
pkg/config/compiler.go:740:	for _, ri := range cfg.RoutingInstances {
pkg/config/compiler.go:741:		for _, ifName := range ri.Interfaces {
pkg/config/compiler.go:755:	for ifName, ifc := range cfg.Interfaces.Interfaces {
pkg/config/compiler.go:756:		for unitNum, unit := range ifc.Units {
pkg/config/compiler.go:795:		for _, pair := range [][2]string{
pkg/config/compiler.go:818:				for _, m := range f0.FabricMembers {
pkg/config/compiler.go:823:				for _, m := range f1.FabricMembers {
pkg/config/compiler.go:836:		for _, rg := range cc.RedundancyGroups {
pkg/config/compiler.go:857:	for _, proc := range cfg.System.DisabledProcesses {
pkg/config/compiler.go:869:		for _, url := range cfg.System.Archival.ArchiveSitesWithPassword {
pkg/config/compiler.go:881:			for _, ext := range exts {
pkg/config/compiler.go:889:			for _, tmpl := range fm.Version9.Templates {
pkg/config/compiler.go:894:			for _, tmpl := range fm.VersionIPFIX.Templates {
pkg/config/compiler.go:903:		for _, class := range cos.ForwardingClasses {
pkg/config/compiler.go:909:					"class-of-service forwarding-class %q uses out-of-range queue %d (expected 0..255)",
pkg/config/compiler.go:916:		for _, sched := range cos.Schedulers {
pkg/config/compiler.go:927:		for _, schedMap := range cos.SchedulerMaps {
pkg/config/compiler.go:931:			for className, entry := range schedMap.Entries {
pkg/config/compiler.go:947:		for _, classifier := range cos.DSCPClassifiers {
pkg/config/compiler.go:951:			for _, entry := range classifier.Entries {
pkg/config/compiler.go:966:		for _, classifier := range cos.IEEE8021Classifiers {
pkg/config/compiler.go:970:			for _, entry := range classifier.Entries {
pkg/config/compiler.go:985:		for _, rewriteRule := range cos.DSCPRewriteRules {
pkg/config/compiler.go:989:			for _, entry := range rewriteRule.Entries {
pkg/config/compiler.go:1004:		for _, iface := range cos.Interfaces {
pkg/config/compiler.go:1008:			for _, unit := range iface.Units {
pkg/config/compiler.go:1071:	for ifaceName, iface := range cos.Interfaces {
pkg/config/compiler.go:1075:		for unitID, unit := range iface.Units {
pkg/config/compiler.go:1084:			for _, entry := range schedMap.Entries {
pkg/config/compiler.go:1140:	for _, zone := range cfg.Security.Zones {
pkg/config/compiler.go:1174:	for _, inst := range namedInstances(node.FindChildren("application")) {
pkg/config/compiler.go:1179:		for _, prop := range inst.node.Children {
pkg/config/compiler.go:1206:				for _, c := range prop.Children {
pkg/config/compiler.go:1216:			for _, t := range terms {
pkg/config/compiler.go:1227:	for _, inst := range namedInstances(node.FindChildren("application-set")) {
pkg/config/compiler.go:1230:		for _, member := range inst.node.Children {
pkg/config/compiler.go:1297:	for _, p := range protocols {
pkg/config/compiler.go:1305:	for _, proto := range unique {
pkg/config/compiler.go:1369:			return fmt.Errorf("invalid port range %q: non-numeric", spec)
pkg/config/compiler.go:1378:			return fmt.Errorf("invalid port range %q: start > end", spec)
pkg/config/compiler_test.go:44:	for _, line := range lines {
pkg/config/compiler_test.go:112:	for _, line := range lines {
pkg/config/compiler_test.go:204:	for _, line := range lines {
pkg/config/ast_groups.go:35:	for k, v := range vars {
pkg/config/ast_groups.go:44:	for _, child := range t.Children {
pkg/config/ast_groups.go:46:			for _, g := range child.Children {
pkg/config/ast_groups.go:72:	for _, child := range t.Children {
pkg/config/ast_groups.go:84:	for _, n := range nodes {
pkg/config/ast_groups.go:98:	for _, child := range nodes {
pkg/config/ast_groups.go:122:	for _, pathKeys := range ancestorPath {
pkg/config/ast_groups.go:124:		for _, child := range current {
pkg/config/ast_groups.go:154:	for _, n := range *nodes {
pkg/config/ast_groups.go:156:			for _, key := range n.Keys[1:] {
pkg/config/ast_groups.go:163:	for _, name := range applyNames {
pkg/config/ast_groups.go:199:	for _, n := range *nodes {
pkg/config/ast_groups.go:207:	for _, n := range *nodes {
pkg/config/ast_groups.go:226:	for _, s := range src {
pkg/config/ast_groups.go:238:			for _, d := range *dst {
pkg/config/ast_groups.go:249:		for _, d := range *dst {
pkg/config/ast_groups.go:265:	for _, k := range keys {
pkg/config/ast_groups.go:279:	for i := range src {
pkg/config/ast_groups.go:294:	for _, n := range nodes {
pkg/config/schema_validate_test.go:34:	for _, cmd := range cmds {
pkg/config/schema_validate_test.go:310:	for _, cmd := range cmds {
pkg/config/schema_validate_test.go:347:	for _, cmd := range cmds {
pkg/config/schema_validate_test.go:401:	for _, g := range good {
pkg/config/schema_validate_test.go:407:	for _, b := range bad {
pkg/config/schema_validate_test.go:416:	for _, g := range good {
pkg/config/schema_validate_test.go:422:	for _, b := range bad {
pkg/config/schema_validate_test.go:431:	for _, g := range good {
pkg/config/schema_validate_test.go:437:	for _, b := range bad {
pkg/config/schema_validate_test.go:463:		t.Errorf("ValidateInteger 200: expected out-of-range error")
pkg/config/schema_validate_test.go:479:		t.Errorf("ValidatePercent 150: expected out-of-range error")
pkg/config/parser_class_of_service_test.go:110:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:177:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:213:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:226:	for _, want := range []string{"sum of buffer-size percent", "150", "100"} {
pkg/config/parser_class_of_service_test.go:244:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:285:	for _, tc := range tests {
pkg/config/parser_class_of_service_test.go:288:			for _, line := range tc.lines {
pkg/config/parser_class_of_service_test.go:315:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:347:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:376:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:397:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:455:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:482:	for _, tt := range tests {
pkg/config/parser_class_of_service_test.go:493:	for _, line := range []string{
pkg/config/parser_class_of_service_test.go:516:	for _, line := range []string{
pkg/config/parser_class_of_service_test.go:575:	for _, raw := range strings.Split(string(data), "\n") {
pkg/config/parser_class_of_service_test.go:672:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:708:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:745:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:835:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:852:	for _, w := range cfg.Warnings {
pkg/config/parser_class_of_service_test.go:893:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:908:	for _, w := range cfg.Warnings {
pkg/config/parser_class_of_service_test.go:940:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:954:	for _, w := range cfg.Warnings {
pkg/config/parser_class_of_service_test.go:1283:	if !strings.Contains(warnings, `forwarding-class "invalid-class" uses out-of-range queue 300`) {
pkg/config/parser_class_of_service_test.go:1284:		t.Fatalf("expected queue range warning, got: %s", warnings)
pkg/config/parser_class_of_service_test.go:1317:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:1363:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:1409:	for _, line := range lines {
pkg/config/parser_class_of_service_test.go:1452:	for _, line := range lines {
pkg/config/predefined.go:184:	for _, memberName := range as.Applications {
pkg/config/predefined.go:191:			for _, a := range expanded {
pkg/config/predefined.go:240:	for _, addrName := range as.Addresses {
pkg/config/predefined.go:248:	for _, setName := range as.AddressSets {
pkg/config/predefined.go:253:		for _, a := range expanded {
pkg/config/ast_format.go:37:	for _, n := range matches {
pkg/config/ast_format.go:52:	for _, n := range nodes {
pkg/config/ast_format.go:85:	for i, n := range nodes {
pkg/config/ast_format.go:100:	for i, n := range nodes {
pkg/config/ast_format.go:115:	for _, n := range nodes {
pkg/config/ast_format.go:142:	for _, n := range matches {
pkg/config/ast_format.go:174:	for _, p := range path {
pkg/config/ast_format.go:181:	for _, n := range matches {
pkg/config/ast_format.go:193:	for _, n := range canonicalOrder(nodes) {
pkg/config/ast_format.go:206:	for i, k := range keys {
pkg/config/ast_format.go:226:	for _, n := range oldNodes {
pkg/config/ast_format.go:230:	for _, n := range newNodes {
pkg/config/ast_format.go:243:	for _, n := range canonicalOrder(newNodes) {
pkg/config/ast_format.go:251:	for _, n := range canonicalOrder(oldNodes) {
pkg/config/ast_format.go:265:	for _, e := range entries {
pkg/config/ast_format.go:278:		for _, e := range entries {
pkg/config/ast_format.go:294:	for _, n := range canonicalOrder(newNodes) {
pkg/config/ast_format.go:299:	for _, n := range canonicalOrder(oldNodes) {
pkg/config/ast_format.go:306:	for _, e := range allEntries {
pkg/config/ast_format.go:350:	for _, n := range b.Children {
pkg/config/ast_format.go:353:	for _, ac := range a.Children {
pkg/config/ast_format.go:378:	for _, n := range canonicalOrder(nodes) {
pkg/config/ast_format.go:439:	for _, n := range nodes {
pkg/config/ast_format.go:446:			for _, k := range n.Keys[1:] {
pkg/config/ast_format.go:469:		for _, k := range n.Keys[1:] {
pkg/config/ast_format.go:493:	for _, n := range nodes {
pkg/config/compiler_services.go:63:	for _, groupInst := range namedInstances(node.FindChildren("group")) {
pkg/config/compiler_services.go:66:		for _, prop := range groupInst.node.Children {
pkg/config/compiler_services.go:80:					for _, pp := range poolChildren {
pkg/config/compiler_services.go:82:						case "address-range":
pkg/config/compiler_services.go:123:	for _, inst := range namedInstances(node.FindChildren("feed-server")) {
pkg/config/compiler_services.go:126:		for _, prop := range inst.node.Children {
pkg/config/compiler_services.go:148:					for _, c := range prop.Children {
pkg/config/compiler_services.go:163:	for _, inst := range namedInstances(node.FindChildren("address-name")) {
pkg/config/compiler_services.go:166:			for _, c := range profile.Children {
pkg/config/compiler_services.go:211:	for _, probeInst := range namedInstances(node.FindChildren("probe")) {
pkg/config/compiler_services.go:217:		for _, testInst := range namedInstances(probeInst.node.FindChildren("test")) {
pkg/config/compiler_services.go:220:			for _, prop := range testInst.node.Children {
pkg/config/compiler_services.go:262:					for _, th := range prop.Children {
pkg/config/compiler_services.go:317:		for _, tmplInst := range namedInstances(v9Node.FindChildren("template")) {
pkg/config/compiler_services.go:319:			for _, prop := range tmplInst.node.Children {
pkg/config/compiler_services.go:359:		for _, tmplInst := range namedInstances(ipfixNode.FindChildren("template")) {
pkg/config/compiler_services.go:361:			for _, prop := range tmplInst.node.Children {
pkg/config/compiler_services.go:439:	for _, inst := range namedInstances(node.FindChildren("instance")) {
pkg/config/compiler_services.go:451:				for _, child := range ingressNode.Children {
pkg/config/compiler_services.go:479:	for _, sampInst := range namedInstances(node.FindChildren("instance")) {
pkg/config/compiler_services.go:484:			for _, prop := range inputNode.Children {
pkg/config/compiler_services.go:495:		for _, familyNode := range sampInst.node.FindChildren("family") {
pkg/config/compiler_services.go:502:			for _, afNode := range afNodes {
pkg/config/compiler_services.go:533:	for _, child := range outputNode.Children {
pkg/config/compiler_services.go:543:				for _, prop := range fsChildren {
pkg/config/compiler_services.go:592:	for _, sgInst := range namedInstances(node.FindChildren("server-group")) {
pkg/config/compiler_services.go:594:		for _, child := range sgInst.node.Children {
pkg/config/compiler_services.go:602:	for _, gInst := range namedInstances(node.FindChildren("group")) {
pkg/config/compiler_services.go:604:		for _, prop := range gInst.node.Children {
pkg/config/compiler_services.go:622:	for _, pInst := range namedInstances(node.FindChildren("policy")) {
pkg/config/compiler_services.go:627:		for _, child := range pInst.node.Children {
pkg/config/compiler_services.go:637:				for _, evtChild := range child.Children {
pkg/config/compiler_services.go:680:				for _, amChild := range child.Children {
pkg/config/compiler_services.go:687:						for _, cmdChild := range cmdsNode.Children {
pkg/config/compiler_services.go:702:	for _, child := range node.Children {
pkg/config/compiler_services.go:711:		// Collect VLAN IDs — multi-value leaf: each "vlan-id-list" child is a separate leaf
pkg/config/compiler_services.go:712:		for _, vlanNode := range child.FindChildren("vlan-id-list") {
pkg/config/compiler_services.go:722:				return fmt.Errorf("bridge-domain %s: vlan-id %d out of range (1-4094)", bdName, v)
pkg/config/ast_edit.go:89:	for i, c := range *parentChildren {
pkg/config/ast_edit.go:102:	for i, c := range *parentChildren {
pkg/config/ast_edit.go:155:			for _, n := range *current {
pkg/config/ast_edit.go:203:				for _, n := range *current {
pkg/config/ast_edit.go:222:				// Flag leaf (args == 0) or multi-value leaf: skip if exact duplicate.
pkg/config/ast_edit.go:223:				for _, n := range *current {
pkg/config/ast_edit.go:237:		// More tokens follow. If the schema says this is a multi-value leaf
pkg/config/ast_edit.go:243:		// are trailing values for this leaf (e.g. "destination-port 20000 to 20003").
pkg/config/ast_edit.go:253:				for _, n := range *current {
pkg/config/ast_edit.go:273:		for _, n := range *current {
pkg/config/ast_edit.go:353:	for _, n := range *current {
pkg/config/ast_edit.go:365:	for i, n := range *nodes {
pkg/config/ast_edit.go:380:	for i, tk := range targetKeys {
pkg/config/completion_prefix_test.go:7:	for i, result := range results {
pkg/config/completion_prefix_test.go:14:	for _, result := range results {
pkg/config/parser_system_test.go:12:	for _, cmd := range setCommands {
pkg/config/parser_system_test.go:47:	for _, cmd := range setCommands {
pkg/config/parser_system_test.go:159:                    address-range low 10.0.1.100 high 10.0.1.200;
pkg/config/parser_system_test.go:171:                    address-range low 10.0.2.50 high 10.0.2.150;
pkg/config/parser_system_test.go:213:		t.Errorf("pool range: %s - %s", pool.RangeLow, pool.RangeHigh)
pkg/config/parser_system_test.go:228:	setCommands := []string{"set system services dhcp-local-server group test interface eth3.0", "set system services dhcp-local-server group test pool p1 subnet 172.16.0.0/24", "set system services dhcp-local-server group test pool p1 address-range low 172.16.0.10 high 172.16.0.50", "set system services dhcp-local-server group test pool p1 router 172.16.0.1"}
pkg/config/parser_system_test.go:229:	for _, cmd := range setCommands {
pkg/config/parser_system_test.go:259:	for _, cmd := range []string{"set system host-name test-fw", "set system backup-router 192.168.50.1 destination 192.168.0.0/16", "set system internet-options no-ipv6-reject-zero-hop-limit", "set system services ssh root-login allow", "set system services web-management http", "set system services web-management https", "set system syslog host 192.168.99.3 daemon info", "set system syslog file messages any any"} {
pkg/config/parser_system_test.go:452:	for _, tc := range cases {
pkg/config/parser_system_test.go:486:		for _, line := range setLines {
pkg/config/parser_system_test.go:521:	for _, s := range a {
pkg/config/parser_system_test.go:524:	for _, s := range b {
pkg/config/parser_system_test.go:621:	for _, u := range wm.APIAuth.Users {
pkg/config/parser_system_test.go:634:	for _, cmd := range cmds {
pkg/config/parser_system_test.go:719:	for i, exp := range expected {
pkg/config/parser_system_test.go:729:	for _, cmd := range cmds {
pkg/config/parser_system_test.go:886:	for _, line := range lines {
pkg/config/parser_system_test.go:1128:	for _, input := range tests {
pkg/config/parser_system_test.go:1142:		for _, w := range cfg.Warnings {
pkg/config/parser_system_test.go:1182:	for _, w := range cfg.Warnings {
pkg/config/parser_system_test.go:1278:	for _, line := range lines {
pkg/config/parser_system_test.go:1320:	for _, cmd := range setCommands {
pkg/config/parser_system_test.go:1347:	for _, cmd := range setCommands {
pkg/config/parser_system_test.go:1367:	for _, cmd := range []string{
pkg/config/parser_system_test.go:1403:	for _, cmd := range []string{
pkg/config/parser_system_test.go:1433:	for _, dataplaneType := range []string{"userspace"} {
pkg/config/parser_system_test.go:1461:		for _, cmd := range []string{
pkg/config/compiler_security.go:9:	for _, child := range node.Children {
pkg/config/compiler_security.go:57:			for _, hostInst := range namedInstances(child.FindChildren("host")) {
pkg/config/compiler_security.go:59:				for _, kp := range hostInst.node.Children {
pkg/config/compiler_security.go:89:	for _, inst := range namedInstances(node.FindChildren("security-zone")) {
pkg/config/compiler_security.go:92:		for _, prop := range inst.node.Children {
pkg/config/compiler_security.go:95:				for _, iface := range prop.Children {
pkg/config/compiler_security.go:102:				for _, hit := range prop.Children {
pkg/config/compiler_security.go:105:						for _, svc := range hit.Children {
pkg/config/compiler_security.go:110:						for _, proto := range hit.Children {
pkg/config/compiler_security.go:129:	for _, child := range node.Children {
pkg/config/compiler_security.go:149:			for _, polInst := range namedInstances(child.FindChildren("policy")) {
pkg/config/compiler_security.go:168:				for _, fzSub := range child.Children {
pkg/config/compiler_security.go:173:					for _, tzSub := range tzNode.Children {
pkg/config/compiler_security.go:179:			for _, zp := range pairs {
pkg/config/compiler_security.go:185:				for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
pkg/config/compiler_security.go:205:		for _, m := range matchNode.Children {
pkg/config/compiler_security.go:211:					for _, c := range m.Children {
pkg/config/compiler_security.go:219:					for _, c := range m.Children {
pkg/config/compiler_security.go:227:					for _, c := range m.Children {
pkg/config/compiler_security.go:237:		for _, t := range thenNode.Children {
pkg/config/compiler_security.go:247:				for _, logOpt := range t.Children {
pkg/config/compiler_security.go:272:	for _, inst := range namedInstances(node.FindChildren("ids-option")) {
pkg/config/compiler_security.go:277:			for _, opt := range icmpNode.Children {
pkg/config/compiler_security.go:297:			for _, opt := range ipNode.Children {
pkg/config/compiler_security.go:304:					for _, swOpt := range opt.Children {
pkg/config/compiler_security.go:321:			for _, opt := range tcpNode.Children {
pkg/config/compiler_security.go:337:					for _, sfOpt := range opt.Children {
pkg/config/compiler_security.go:360:					for _, psOpt := range opt.Children {
pkg/config/compiler_security.go:377:			for _, opt := range udpNode.Children {
pkg/config/compiler_security.go:395:			for _, opt := range limitNode.Children {
pkg/config/compiler_security.go:428:	for _, child := range globalNode.Children {
pkg/config/compiler_security.go:441:				for _, member := range child.Children {
pkg/config/compiler_security.go:481:	for _, inst := range namedInstances(node.FindChildren("stream")) {
pkg/config/compiler_security.go:486:		for _, prop := range inst.node.Children {
pkg/config/compiler_security.go:494:				for _, hc := range prop.Children {
pkg/config/compiler_security.go:526:				for _, tc := range prop.Children {
pkg/config/compiler_security.go:546:		for _, opt := range agingNode.Children {
pkg/config/compiler_security.go:568:		for _, opt := range tcpNode.Children {
pkg/config/compiler_security.go:603:		for _, opt := range udpNode.Children {
pkg/config/compiler_security.go:614:		for _, opt := range icmpNode.Children {
pkg/config/compiler_security.go:626:		for _, opt := range mssNode.Children {
pkg/config/compiler_security.go:710:		for _, flagNode := range toNode.FindChildren("flag") {
pkg/config/compiler_security.go:715:		for _, pfInst := range namedInstances(toNode.FindChildren("packet-filter")) {
pkg/config/compiler_test.go:44:	for _, line := range lines {
pkg/config/compiler_test.go:112:	for _, line := range lines {
pkg/config/compiler_test.go:204:	for _, line := range lines {
pkg/config/parser_services_test.go:175:			name: "destination port range validated",
pkg/config/parser_services_test.go:192:	for _, tc := range tests {
pkg/config/parser_services_test.go:261:	for _, cmd := range setCommands {
pkg/config/parser_services_test.go:454:	for _, cmd := range commands {
pkg/config/parser_services_test.go:563:	for _, cmd := range setCommands {
pkg/config/parser_services_test.go:664:	for _, cmd := range setCommands {
pkg/config/parser_services_test.go:712:	for _, cmd := range setCommands {
pkg/config/parser_services_test.go:786:	for _, cmd := range cmds {
pkg/config/parser_services_test.go:859:	for _, cmd := range []string{"set security nat proxy-arp interface trust0.0 address 10.0.1.100/32", "set security nat proxy-arp interface trust0.0 address 10.0.1.101/32 to 10.0.1.110/32"} {
pkg/config/parser_services_test.go:882:	for _, cmd := range []string{"set security nat proxy-arp interface untrust0.0 address 203.0.113.5/32"} {
pkg/config/parser_services_test.go:908:	for _, cmd := range []string{"set security nat proxy-arp interface trust0.0 address 10.0.1.50"} {
pkg/config/parser_services_test.go:1019:	for _, line := range lines {
pkg/config/parser_services_test.go:1118:	for _, line := range lines {
pkg/config/parser_services_test.go:1135:	for _, w := range cfg.Warnings {
pkg/config/parser_services_test.go:1156:	for _, line := range lines {
pkg/config/parser_services_test.go:1169:	for _, w := range cfg.Warnings {
pkg/config/compiler_routing.go:28:	for _, ribNode := range node.FindChildren("rib") {
pkg/config/compiler_routing.go:47:		for _, inst := range namedInstances(rgNode.FindChildren("")) {
pkg/config/compiler_routing.go:57:				for _, child := range irNode.Children {
pkg/config/compiler_routing.go:64:		for _, child := range rgNode.Children {
pkg/config/compiler_routing.go:77:				for _, child := range irNode.Children {
pkg/config/compiler_routing.go:87:		for _, routeNode := range genNode.FindChildren("route") {
pkg/config/compiler_routing.go:118:			for _, rgChild := range rgNode.Children {
pkg/config/compiler_routing.go:146:	for i, sr := range existing {
pkg/config/compiler_routing.go:150:	for _, routeInst := range namedInstances(staticNode.FindChildren("route")) {
pkg/config/compiler_routing.go:195:		for _, prop := range routeInst.node.Children {
pkg/config/compiler_routing.go:201:				for _, child := range prop.Children {
pkg/config/compiler_routing.go:278:	for _, child := range node.Children {
pkg/config/compiler_routing.go:289:		for _, prop := range child.Children {
pkg/config/compiler_routing.go:309:						for _, rgChild := range rgNode.Children {
pkg/config/compiler_routing.go:358:	for _, inst := range namedInstances(node.FindChildren("prefix-list")) {
pkg/config/compiler_routing.go:360:		for _, entry := range inst.node.Children {
pkg/config/compiler_routing.go:369:	for _, inst := range namedInstances(node.FindChildren("community")) {
pkg/config/compiler_routing.go:375:		for _, entry := range inst.node.Children {
pkg/config/compiler_routing.go:392:	for _, child := range node.FindChildren("as-path") {
pkg/config/compiler_routing.go:404:			for _, entry := range child.Children {
pkg/config/compiler_routing.go:414:	for _, inst := range namedInstances(node.FindChildren("policy-statement")) {
pkg/config/compiler_routing.go:418:		for _, prop := range inst.node.Children {
pkg/config/compiler_routing.go:447:				for _, ac := range prop.Children {
pkg/config/compiler_routing.go:470:	for _, tc := range children {
pkg/config/compiler_routing.go:473:			for _, fc := range tc.Children {
pkg/config/compiler_routing.go:502:			for _, ac := range tc.Children {
pkg/config/xfrmi_test.go:23:	for _, tt := range tests {
pkg/config/compiler_system.go:20:	for _, child := range node.Children {
pkg/config/compiler_system.go:38:			for _, d := range child.Children {
pkg/config/compiler_system.go:54:			for _, ns := range child.Children {
pkg/config/compiler_system.go:60:			for _, ntpChild := range child.FindChildren("server") {
pkg/config/compiler_system.go:82:			for _, userInst := range namedInstances(child.FindChildren("user")) {
pkg/config/compiler_system.go:84:				for _, prop := range userInst.node.Children {
pkg/config/compiler_system.go:95:						for _, authChild := range prop.Children {
pkg/config/compiler_system.go:112:			for i, k := range child.Keys {
pkg/config/compiler_system.go:122:			for _, key := range child.Keys[1:] {
pkg/config/compiler_system.go:132:			for _, prop := range child.Children {
pkg/config/compiler_system.go:156:				for _, asNode := range cfgNode.FindChildren("archive-sites") {
pkg/config/compiler_system.go:173:						for _, child := range asNode.Children {
pkg/config/compiler_system.go:186:					for _, site := range asNode.Children {
pkg/config/compiler_system.go:217:			for _, proc := range child.Children {
pkg/config/compiler_system.go:258:			for _, slInst := range namedInstances(child.FindChildren("host")) {
pkg/config/compiler_system.go:260:				for _, prop := range slInst.node.Children {
pkg/config/compiler_system.go:275:			for _, fileInst := range namedInstances(child.FindChildren("file")) {
pkg/config/compiler_system.go:277:				for _, prop := range fileInst.node.Children {
pkg/config/compiler_system.go:286:			for _, userInst := range namedInstances(child.FindChildren("user")) {
pkg/config/compiler_system.go:288:				for _, prop := range userInst.node.Children {
pkg/config/compiler_system.go:356:				for _, inst := range namedInstances(authNode.FindChildren("user")) {
pkg/config/compiler_system.go:364:				for _, ch := range authNode.FindChildren("api-key") {
pkg/config/compiler_system.go:384:	for _, child := range node.Children {
pkg/config/compiler_system.go:403:	for _, child := range node.Children {
pkg/config/compiler_system.go:412:	for _, child := range node.Children {
pkg/config/compiler_system.go:492:			for _, sub := range child.Children {
pkg/config/compiler_system.go:526:	for _, child := range node.Children {
pkg/config/compiler_system.go:578:	for _, key := range []string{"selected_interfaces", "interfaces"} {
pkg/config/compiler_system.go:583:	for _, key := range []string{
pkg/config/compiler_system.go:606:	for i, value := range values {
pkg/config/compiler_system.go:627:	for ifname, value := range values {
pkg/config/compiler_system.go:645:	for _, child := range node.Children {
pkg/config/compiler_system.go:661:				for _, prop := range commChildren {
pkg/config/compiler_system.go:685:				for _, prop := range tgChildren {
pkg/config/compiler_system.go:727:	for _, child := range engineNode.Children {
pkg/config/compiler_system.go:743:		for _, prop := range userChildren {
pkg/config/compiler_system.go:816:	for _, inst := range namedInstances(node.FindChildren("scheduler")) {
pkg/config/compiler_system.go:819:		for _, prop := range inst.node.Children {
pkg/config/compiler_system.go:956:	for _, rgInst := range namedInstances(clusterNode.FindChildren("redundancy-group")) {
pkg/config/compiler_system.go:967:		for _, child := range rgInst.node.Children {
pkg/config/compiler_system.go:1003:				for _, ifChild := range child.Children {
pkg/config/compiler_system.go:1040:				for _, familyNode := range child.Children {
pkg/config/compiler_system.go:1054:					for _, addrChild := range inetNode.Children {
pkg/config/parser_ast_test.go:26:	for i, exp := range expected {
pkg/config/parser_ast_test.go:270:	for i := range expected {
pkg/config/parser_ast_test.go:280:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:366:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:480:	for _, child := range sysNode.Children {
pkg/config/parser_ast_test.go:493:	for _, child := range sysNode.Children {
pkg/config/parser_ast_test.go:506:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:570:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:582:		for _, c := range tree.Children {
pkg/config/parser_ast_test.go:584:				for _, c2 := range c.Children {
pkg/config/parser_ast_test.go:586:						for _, c3 := range c2.Children {
pkg/config/parser_ast_test.go:600:		for _, p := range *policies {
pkg/config/parser_ast_test.go:644:	for _, zp := range cfg.Security.Policies {
pkg/config/parser_ast_test.go:664:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:765:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:827:	for _, a := range expanded {
pkg/config/parser_ast_test.go:973:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:1060:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:1097:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:1227:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:1240:	for _, child := range unit0.Children {
pkg/config/parser_ast_test.go:1304:	for _, cmd := range deepCommands {
pkg/config/parser_ast_test.go:1366:	for _, w := range cfg.Warnings {
pkg/config/parser_ast_test.go:1492:	for _, w := range cfg.Warnings {
pkg/config/parser_ast_test.go:1660:	for _, name := range as.Applications {
pkg/config/parser_ast_test.go:1677:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:1695:	for _, name := range as.Applications {
pkg/config/parser_ast_test.go:1709:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:1833:	for _, cmd := range []string{"set security zones security-zone trust interfaces trust0", "set security zones security-zone trust host-inbound-traffic protocols router-discovery", "set security zones security-zone trust host-inbound-traffic protocols ospf"} {
pkg/config/parser_ast_test.go:1854:	for _, p := range protos {
pkg/config/parser_ast_test.go:1983:	for _, cmd := range cmds {
pkg/config/parser_ast_test.go:2284:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_ast_test.go:2291:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_ast_test.go:2324:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_ast_test.go:2341:	for _, line := range lines {
pkg/config/parser_ast_test.go:2359:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_ast_test.go:2605:	for _, cmd := range []string{"set system domain-name example.org", "set system domain-search corp.example.org", "set system domain-search dev.example.org"} {
pkg/config/parser_ast_test.go:2634:	for _, line := range lines {
pkg/config/parser_ast_test.go:2676:	for _, line := range lines {
pkg/config/parser_ast_test.go:2748:	for _, tt := range tests {
pkg/config/parser_ast_test.go:2790:	for _, line := range lines {
pkg/config/parser_ast_test.go:2955:	for _, line := range []string{
pkg/config/parser_ast_test.go:2976:	for _, w := range cfg.Warnings {
pkg/config/parser_ast_test.go:3007:	for _, line := range lines {
pkg/config/parser_ast_test.go:3063:	for _, line := range lines {
pkg/config/parser_ast_test.go:3120:	for _, line := range lines {
pkg/config/parser_ast_test.go:3190:	for _, line := range lines {
pkg/config/parser_ast_test.go:3225:	for _, value := range values {
pkg/config/parser_ast_test.go:3248:	for _, tc := range cases {
pkg/config/parser_ast_test.go:3259:			for _, line := range base {
pkg/config/parser_ast_test.go:3301:	for _, line := range lines {
pkg/config/parser_ast_test.go:3351:	for _, line := range base {
pkg/config/parser_ast_test.go:3385:	for _, line := range base {
pkg/config/parser_ast_test.go:3417:	for _, cmd := range cmds {
pkg/config/parser_ast_test.go:3445:	for _, cmd := range cmds {
pkg/config/parser_ast_test.go:3479:	for _, cmd := range cmds {
pkg/config/parser_ast_test.go:3544:	for _, cmd := range cmds {
pkg/config/parser_ast_test.go:3649:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3748:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3777:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3798:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3815:		for _, zp := range cfg.Security.Policies {
pkg/config/parser_ast_test.go:3827:	for _, p := range trustUntrust.Policies {
pkg/config/parser_ast_test.go:3843:	for _, p := range dmzUntrust.Policies {
pkg/config/parser_ast_test.go:3856:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3878:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3916:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3956:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:3973:	for _, w := range cfg.Warnings {
pkg/config/parser_ast_test.go:3986:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:4007:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:4189:	for _, pol := range pair.Policies {
pkg/config/parser_ast_test.go:4276:	for i, pol := range pair.Policies {
pkg/config/parser_ast_test.go:4281:	for _, n := range names {
pkg/config/parser_ast_test.go:4362:	for _, pol := range pair.Policies {
pkg/config/parser_ast_test.go:4438:	for _, cmd := range setCommands {
pkg/config/parser_ast_test.go:4456:	for _, pol := range pair.Policies {
pkg/config/parser_ast_test.go:4486:	for _, zpp := range cfg.Security.Policies {
pkg/config/parser_ast_test.go:4537:	for i, line := range lines {
pkg/config/parser_ast_test.go:4563:	for _, tt := range tests {
pkg/config/parser_ast_test.go:4576:	for _, tt := range tests {
pkg/config/parser_ast_test.go:4593:	for _, w := range warnings {
pkg/config/parser_ast_test.go:4634:	for _, w := range warnings {
pkg/config/parser_ast_test.go:4688:	for _, line := range lines {
pkg/config/parser_ast_test.go:4710:	for _, line := range lines {
pkg/config/parser_ast_test.go:4730:	for _, p := range protos {
pkg/config/parser_ast_test.go:4873:	for _, line := range lines {
pkg/config/parser_ast_test.go:4971:	for _, tt := range tests {
pkg/config/parser_ast_test.go:4974:			for _, line := range tt.lines {
pkg/config/parser_ast_test.go:5058:	for _, tc := range tests {
pkg/config/parser_ast_test.go:5080:	for _, tc := range tests {
pkg/config/parser_ast_test.go:5095:	for _, tc := range tests {
pkg/config/parser_ast_test.go:5105:			for _, r := range results {
pkg/config/parser_ast_test.go:5113:				for i, r := range results {
pkg/config/compiler_protocols.go:23:		for _, child := range lldpNode.Children {
pkg/config/compiler_protocols.go:56:		for _, child := range ospfNode.Children {
pkg/config/compiler_protocols.go:77:		for _, areaInst := range namedInstances(ospfNode.FindChildren("area")) {
pkg/config/compiler_protocols.go:80:			for _, ifInst := range namedInstances(areaInst.node.FindChildren("interface")) {
pkg/config/compiler_protocols.go:82:				for _, prop := range ifInst.node.Children {
pkg/config/compiler_protocols.go:97:						for _, authChild := range prop.Children {
pkg/config/compiler_protocols.go:106:								for _, kc := range authChild.Children {
pkg/config/compiler_protocols.go:118:						for _, bc := range prop.Children {
pkg/config/compiler_protocols.go:141:				for _, atChild := range atNode.Children {
pkg/config/compiler_protocols.go:158:			for _, vlInst := range namedInstances(areaInst.node.FindChildren("virtual-link")) {
pkg/config/compiler_protocols.go:180:		for _, child := range bgpNode.Children {
pkg/config/compiler_protocols.go:202:				for _, mc := range child.Children {
pkg/config/compiler_protocols.go:209:				for _, dc := range child.Children {
pkg/config/compiler_protocols.go:247:		for _, groupInst := range namedInstances(bgpNode.FindChildren("group")) {
pkg/config/compiler_protocols.go:261:			for _, child := range groupInst.node.Children {
pkg/config/compiler_protocols.go:296:						for _, fc := range child.Children {
pkg/config/compiler_protocols.go:321:					for _, bc := range child.Children {
pkg/config/compiler_protocols.go:360:						for _, prop := range child.Children {
pkg/config/compiler_protocols.go:384:								for _, bc := range prop.Children {
pkg/config/compiler_protocols.go:423:									for _, fc := range prop.Children {
pkg/config/compiler_protocols.go:451:		for _, child := range ospf3Node.Children {
pkg/config/compiler_protocols.go:464:		for _, areaInst := range namedInstances(ospf3Node.FindChildren("area")) {
pkg/config/compiler_protocols.go:467:			for _, ifInst := range namedInstances(areaInst.node.FindChildren("interface")) {
pkg/config/compiler_protocols.go:469:				for _, prop := range ifInst.node.Children {
pkg/config/compiler_protocols.go:491:		for _, child := range ripNode.Children {
pkg/config/compiler_protocols.go:494:				for _, gc := range child.Children {
pkg/config/compiler_protocols.go:533:		for _, child := range isisNode.Children {
pkg/config/compiler_protocols.go:566:					for _, prop := range child.Children {
pkg/config/compiler_protocols.go:586:							for _, bc := range prop.Children {
pkg/config/compiler_protocols.go:605:					for _, k := range child.Keys[2:] {
pkg/config/compiler_protocols.go:622:	for _, inst := range namedInstances(node.FindChildren("interface")) {
pkg/config/compiler_protocols.go:627:		for _, prop := range inst.node.Children {
pkg/config/compiler_protocols.go:686:					for _, child := range pfxChildren {
pkg/config/compiler_protocols.go:732:	for _, child := range nodes {
pkg/config/compiler_protocols.go:739:			for _, sub := range child.Children {
pkg/config/compiler_protocols.go:781:	for _, child := range prop.Children {
pkg/config/ast.go:56:	for i, k := range n.Keys {
pkg/config/ast.go:79:	for _, child := range n.Children {
pkg/config/ast.go:90:	for _, child := range n.Children {
pkg/config/ast.go:105:	for _, child := range t.Children {
pkg/config/ast.go:128:	for i, n := range nodes {
pkg/config/ast.go:154:			for _, n := range current {
pkg/config/ast.go:169:					for _, n := range matched {
pkg/config/ast.go:190:		for _, n := range current {
pkg/config/ast.go:239:		for _, child := range children {
pkg/config/ast.go:277:		for i, child := range *parentChildren {
pkg/config/ast.go:307:		for _, child := range *children {
pkg/config/ast.go:335:		for _, child := range *parentChildren {
pkg/config/ast.go:1259:							"flexible-match-range": {children: map[string]*schemaNode{
pkg/config/ast.go:1260:								"range": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1264:									"range":       {args: 1, children: nil},
pkg/config/ast.go:1303:							"flexible-match-range": {children: map[string]*schemaNode{
pkg/config/ast.go:1304:								"range": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1308:									"range":       {args: 1, children: nil},
pkg/config/ast.go:1647:	for k, v := range setSchema.children {
pkg/config/ast.go:1660:	for i := range a {
pkg/config/ast.go:1678:	for i, r := range results {
pkg/config/ast.go:1710:				for name := range schema.children {
pkg/config/ast.go:1720:					for _, name := range matches {
pkg/config/ast.go:1734:				for name, node := range schema.children {
pkg/config/ast.go:1823:		for name, node := range schema.children {
pkg/config/ast.go:1864:				for name := range schema.children {
pkg/config/ast.go:1902:				for name := range childSchema.children {
pkg/config/types_test.go:66:	for _, tt := range tests {
pkg/config/types_test.go:122:	for _, tt := range tests {
pkg/config/types_test.go:154:	for _, tt := range tests {
pkg/config/types_test.go:189:	for _, tt := range tests {
pkg/config/types_test.go:328:	for _, tt := range tests {
pkg/config/types_test.go:382:	for _, tt := range tests {
pkg/config/schema_validate_test.go:34:	for _, cmd := range cmds {
pkg/config/schema_validate_test.go:310:	for _, cmd := range cmds {
pkg/config/schema_validate_test.go:347:	for _, cmd := range cmds {
pkg/config/schema_validate_test.go:401:	for _, g := range good {
pkg/config/schema_validate_test.go:407:	for _, b := range bad {
pkg/config/schema_validate_test.go:416:	for _, g := range good {
pkg/config/schema_validate_test.go:422:	for _, b := range bad {
pkg/config/schema_validate_test.go:431:	for _, g := range good {
pkg/config/schema_validate_test.go:437:	for _, b := range bad {
pkg/config/schema_validate_test.go:463:		t.Errorf("ValidateInteger 200: expected out-of-range error")
pkg/config/schema_validate_test.go:479:		t.Errorf("ValidatePercent 150: expected out-of-range error")
pkg/config/parser_security_test.go:11:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:201:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:229:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:315:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:340:        filter port-range-test {
pkg/config/parser_security_test.go:341:            term block-range {
pkg/config/parser_security_test.go:364:	f, ok := cfg.Firewall.FiltersInet["port-range-test"]
pkg/config/parser_security_test.go:366:		t.Fatal("expected port-range-test filter")
pkg/config/parser_security_test.go:442:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:467:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:501:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:613:	for _, line := range lines {
pkg/config/parser_security_test.go:721:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:935:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1024:	for _, w := range cfg.Warnings {
pkg/config/parser_security_test.go:1034:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1082:	for _, w := range cfg.Warnings {
pkg/config/parser_security_test.go:1141:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1261:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1376:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1468:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1745:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1780:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:1907:	for _, line := range lines {
pkg/config/parser_security_test.go:1963:	for _, svc := range services {
pkg/config/parser_security_test.go:1968:	for svc, found := range expected {
pkg/config/parser_security_test.go:2022:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:2152:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:2184:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:2238:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:2278:	for _, cmd := range []string{"set security zones security-zone trust interfaces trust0", "set security zones security-zone trust interfaces trust1", "set security zones security-zone trust screen untrust-screen", "set security zones security-zone trust host-inbound-traffic system-services ping", "set security zones security-zone trust host-inbound-traffic system-services ssh", "set security zones security-zone trust host-inbound-traffic protocols ospf", "set security zones security-zone untrust interfaces untrust0"} {
pkg/config/parser_security_test.go:2323:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:2355:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:2383:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:2410:	for _, cmd := range setCommands {
pkg/config/parser_security_test.go:2432:	for _, cmd := range []string{"set security screen ids-option untrust-screen icmp ping-death", "set security screen ids-option untrust-screen tcp land", "set security screen ids-option untrust-screen tcp syn-flood alarm-threshold 1000", "set security screen ids-option untrust-screen tcp syn-flood attack-threshold 500", "set security screen ids-option untrust-screen ip source-route-option"} {
pkg/config/parser_security_test.go:2467:	for _, cmd := range []string{"set security nat source pool snat-pool address 203.0.113.0/24", "set security nat source rule-set trust-to-untrust from zone trust", "set security nat source rule-set trust-to-untrust to zone untrust", "set security nat source rule-set trust-to-untrust rule snat-rule match source-address 10.0.0.0/8", "set security nat source rule-set trust-to-untrust rule snat-rule then source-nat interface"} {
pkg/config/parser_security_test.go:2513:	for _, cmd := range []string{"set security policies from-zone trust to-zone untrust policy allow-all match source-address any", "set security policies from-zone trust to-zone untrust policy allow-all match destination-address any", "set security policies from-zone trust to-zone untrust policy allow-all match application any", "set security policies from-zone trust to-zone untrust policy allow-all then permit", "set security policies from-zone trust to-zone untrust policy allow-all then log session-init", "set security policies from-zone trust to-zone untrust policy allow-all then count"} {
pkg/config/parser_security_test.go:2555:	for _, cmd := range []string{"set security policies from-zone lan to-zone wan policy allow-ps match destination-address any source-address any application any", "set security policies from-zone lan to-zone wan policy allow-ps then permit"} {
pkg/config/parser_security_test.go:2647:	for _, cmd := range []string{"set security policies global policy allow-icmpv6 match source-address any-ipv6", "set security policies global policy allow-icmpv6 match destination-address any-ipv6", "set security policies global policy allow-icmpv6 match application junos-icmp6-all", "set security policies global policy allow-icmpv6 then permit"} {
pkg/config/parser_security_test.go:2670:	for _, cmd := range []string{"set applications application my-http protocol tcp", "set applications application my-http destination-port 8080", "set applications application-set web-apps application my-http", "set applications application-set web-apps application junos-https"} {
pkg/config/parser_security_test.go:2832:	for _, rs := range cfg.Security.NAT.Source {
pkg/config/parser_security_test.go:2838:	for _, pair := range []string{"guest->Internet-ATT", "guest->Internet-BCI", "lan->Internet-ATT", "lan->Internet-BCI", "dmz->Internet-ATT", "dmz->Internet-BCI"} {
pkg/config/parser_security_test.go:2850:	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
pkg/config/parser_security_test.go:2860:	for _, cmd := range []string{"set security nat source rule-set internal-to-internet from zone [ guest lan ]", "set security nat source rule-set internal-to-internet to zone Internet-ATT", "set security nat source rule-set internal-to-internet rule catch-all match source-address 0.0.0.0/0", "set security nat source rule-set internal-to-internet rule catch-all then source-nat interface"} {
pkg/config/parser_security_test.go:2877:	for _, rs := range cfg.Security.NAT.Source {
pkg/config/parser_security_test.go:2957:	for _, cmd := range []string{"set security nat source rule-set exempt from zone internal", "set security nat source rule-set exempt to zone Internet", "set security nat source rule-set exempt rule no-nat match source-address 192.203.228.0/24", "set security nat source rule-set exempt rule no-nat then source-nat off"} {
pkg/config/parser_security_test.go:3097:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:3136:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:3390:	for _, p := range policies {
pkg/config/parser_security_test.go:3401:	for _, cmd := range cmds {
pkg/config/parser_security_test.go:3517:	for _, line := range lines {
pkg/config/parser_security_test.go:3549:                rule port-range {
pkg/config/parser_security_test.go:3591:	lines := []string{"set security nat destination pool web1 address 10.0.30.100", "set security nat destination rule-set wan-dnat from zone untrust", "set security nat destination rule-set wan-dnat rule r1 match destination-address 50.0.0.1/32", "set security nat destination rule-set wan-dnat rule r1 match destination-port 80", "set security nat destination rule-set wan-dnat rule r1 match destination-port 443", "set security nat destination rule-set wan-dnat rule r1 match destination-port 20000 to 20003", "set security nat destination rule-set wan-dnat rule r1 then destination-nat pool web1"}
pkg/config/parser_security_test.go:3593:	for _, line := range lines {
pkg/config/parser_security_test.go:3730:	for i, w := range want {
pkg/config/parser_security_test.go:3740:	for _, line := range lines {
pkg/config/parser_security_test.go:3764:	for i, w := range want {
pkg/config/parser_security_test.go:3931:	for i, w := range want {
pkg/config/parser_security_test.go:3941:	for _, line := range lines {
pkg/config/parser_security_test.go:3962:	for i, w := range wantSrc {
pkg/config/parser_security_test.go:3971:	for i, w := range wantDst {
pkg/config/parser_security_test.go:4038:	for _, line := range lines {
pkg/config/parser_security_test.go:4120:	for _, line := range lines {
pkg/config/parser_security_test.go:4178:	for _, line := range lines {
pkg/config/parser_security_test.go:4205:                    flexible-match-range {
pkg/config/parser_security_test.go:4206:                        range proto-check {
pkg/config/parser_security_test.go:4259:	lines := []string{"set firewall family inet filter flex-set term t1 from flexible-match-range range r1 match-start layer-3", "set firewall family inet filter flex-set term t1 from flexible-match-range range r1 byte-offset 12", "set firewall family inet filter flex-set term t1 from flexible-match-range range r1 bit-length 32", "set firewall family inet filter flex-set term t1 from flexible-match-range range r1 range 0x0a000000/0xff000000", "set firewall family inet filter flex-set term t1 then discard"}
pkg/config/parser_security_test.go:4261:	for _, line := range lines {
pkg/config/parser_security_test.go:4297:	for _, cmd := range setCommands {
pkg/config/parser_cluster_test.go:74:	for _, cmd := range commands {
pkg/config/parser_cluster_test.go:161:	for i, rg := range cl.RedundancyGroups {
pkg/config/parser_cluster_test.go:180:	for _, cmd := range commands {
pkg/config/parser_cluster_test.go:215:	for i, rg := range cl.RedundancyGroups {
pkg/config/parser_cluster_test.go:234:	for _, cmd := range commands {
pkg/config/parser_cluster_test.go:299:	for _, cmd := range commands {
pkg/config/parser_cluster_test.go:346:	for _, line := range sets {
pkg/config/parser_cluster_test.go:415:	for _, line := range sets {
pkg/config/parser_cluster_test.go:543:	for _, cmd := range commands {
pkg/config/parser_cluster_test.go:629:	for _, cmd := range commands {
pkg/config/parser_cluster_test.go:688:	for _, line := range sets {
pkg/config/parser_cluster_test.go:757:	for _, line := range sets {
pkg/config/parser_cluster_test.go:850:	for _, w := range warnings {
pkg/config/parser_cluster_test.go:864:	for _, w := range warnings {
pkg/config/parser_cluster_test.go:878:	for _, w := range warnings {
pkg/config/parser_cluster_test.go:891:	for _, w := range warnings {
pkg/config/parser_cluster_test.go:903:	for _, tt := range tests {
pkg/config/parser_cluster_test.go:927:	for _, tt := range tests {
pkg/config/parser_cluster_test.go:938:	for _, cmd := range cmds {
pkg/config/parser_cluster_test.go:970:	for _, cmd := range cmds {
pkg/config/parser_cluster_test.go:1002:	for _, cmd := range cmds {
pkg/config/parser_cluster_test.go:1030:	for _, cmd := range cmds {
pkg/config/parser_cluster_test.go:1061:	for _, cmd := range cmds {
pkg/config/parser_cluster_test.go:1092:	for _, cmd := range cmds {
pkg/config/parser_cluster_test.go:1120:	for _, cmd := range cmds {
pkg/config/parser_cluster_test.go:1145:	for _, cmd := range cmds {
pkg/config/compiler_nat.go:57:		for _, inst := range namedInstances(proxyNode.FindChildren("interface")) {
pkg/config/compiler_nat.go:59:			for _, prop := range inst.node.Children {
pkg/config/compiler_nat.go:63:				// Hierarchical range: Keys=["address","addr1","to","addr2"]
pkg/config/compiler_nat.go:73:				// Set syntax range: Keys=["address","addr1"], child Keys=["to","addr2"]
pkg/config/compiler_nat.go:105:	for _, inst := range namedInstances(node.FindChildren("rule-set")) {
pkg/config/compiler_nat.go:108:		for _, child := range inst.node.Children {
pkg/config/compiler_nat.go:135:	for _, child := range node.Children {
pkg/config/compiler_nat.go:141:			for _, grandchild := range child.Children {
pkg/config/compiler_nat.go:173:		return nil, fmt.Errorf("address range only supports IPv4")
pkg/config/compiler_nat.go:182:		return nil, fmt.Errorf("address range too large: %d IPs (max 256)", count)
pkg/config/compiler_nat.go:200:	for _, inst := range namedInstances(node.FindChildren("pool")) {
pkg/config/compiler_nat.go:203:		for _, prop := range inst.node.Children {
pkg/config/compiler_nat.go:206:				// Check for address range: "addr1 to addr2"
pkg/config/compiler_nat.go:210:						return fmt.Errorf("pool %q address range: %w", pool.Name, err)
pkg/config/compiler_nat.go:217:				for _, addrChild := range prop.Children {
pkg/config/compiler_nat.go:221:							return fmt.Errorf("pool %q address range: %w", pool.Name, err)
pkg/config/compiler_nat.go:229:				// "port range low N high M" or "port N"
pkg/config/compiler_nat.go:230:				if len(prop.Keys) >= 6 && prop.Keys[1] == "range" &&
pkg/config/compiler_nat.go:245:				for _, portChild := range prop.Children {
pkg/config/compiler_nat.go:248:						for _, detProp := range portChild.Children {
pkg/config/compiler_nat.go:263:								for _, hc := range detProp.Children {
pkg/config/compiler_nat.go:286:					for _, portChild := range prop.Children {
pkg/config/compiler_nat.go:291:							for _, hc := range portChild.Children {
pkg/config/compiler_nat.go:304:				for _, pnProp := range prop.Children {
pkg/config/compiler_nat.go:333:		for _, ap := range alarmNode.Children {
pkg/config/compiler_nat.go:366:	for _, pool := range sec.NAT.SourcePools {
pkg/config/compiler_nat.go:392:			return fmt.Errorf("pool %q: block-size %d exceeds port range %d", pool.Name, det.BlockSize, portRange)
pkg/config/compiler_nat.go:422:	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
pkg/config/compiler_nat.go:425:		for _, child := range rsInst.node.Children {
pkg/config/compiler_nat.go:442:		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
pkg/config/compiler_nat.go:447:				for _, m := range matchNode.Children {
pkg/config/compiler_nat.go:454:							for _, child := range m.Children {
pkg/config/compiler_nat.go:466:							for _, child := range m.Children {
pkg/config/compiler_nat.go:477:							for _, child := range m.Children {
pkg/config/compiler_nat.go:499:				for _, t := range thenNode.Children {
pkg/config/compiler_nat.go:533:		for _, fz := range fromZones {
pkg/config/compiler_nat.go:534:			for _, tz := range toZones {
pkg/config/compiler_nat.go:556:	for _, inst := range namedInstances(node.FindChildren("pool")) {
pkg/config/compiler_nat.go:559:		for _, prop := range inst.node.Children {
pkg/config/compiler_nat.go:576:	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
pkg/config/compiler_nat.go:579:		for _, child := range rsInst.node.Children {
pkg/config/compiler_nat.go:595:		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
pkg/config/compiler_nat.go:600:				for _, m := range matchNode.Children {
pkg/config/compiler_nat.go:607:							for _, child := range m.Children {
pkg/config/compiler_nat.go:626:							for _, child := range m.Children {
pkg/config/compiler_nat.go:645:				for _, t := range thenNode.Children {
pkg/config/compiler_nat.go:662:		for _, fz := range fromZones {
pkg/config/compiler_nat.go:663:			for _, tz := range toZones {
pkg/config/compiler_nat.go:678:// Handles single port, multiple ports as children, and port ranges ("20000 to 30000").
pkg/config/compiler_nat.go:680://   - Hierarchical multi-port: destination-port { 80; 443; 20000 to 30000; }
pkg/config/compiler_nat.go:682://   - Set syntax range: destination-port 20000 { to 30000; } (args=1 consumes low, "to N" is child)
pkg/config/compiler_nat.go:686:		// Check for set-syntax port range: Keys=["destination-port","20000"] + child "to 30000"
pkg/config/compiler_nat.go:689:				// Look for "to" child indicating a range
pkg/config/compiler_nat.go:699:				// No range — just a port with non-range children (shouldn't happen, but be safe)
pkg/config/compiler_nat.go:703:		// Multiple ports/ranges as children: destination-port { 80; 443; 20000 to 30000; }
pkg/config/compiler_nat.go:710:			// Hierarchical range: "20000 to 30000" → leaf Keys=["20000", "to", "30000"]
pkg/config/compiler_nat.go:719:			// Sibling-node range: child[i]="20000", child[i+1]="to", child[i+2]="30000"
pkg/config/compiler_nat.go:741:	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
pkg/config/compiler_nat.go:744:		for _, child := range rsInst.node.Children {
pkg/config/compiler_nat.go:755:		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
pkg/config/compiler_nat.go:760:				for _, m := range matchNode.Children {
pkg/config/compiler_nat.go:772:				for _, t := range thenNode.Children {
pkg/config/compiler_nat.go:798:		for _, fz := range fromZones {
pkg/config/parser_routing_test.go:11:	for _, cmd := range setCommands {
pkg/config/parser_routing_test.go:162:	for _, cmd := range setCommands {
pkg/config/parser_routing_test.go:222:	for _, cmd := range setCommands {
pkg/config/parser_routing_test.go:352:	for _, a := range expanded {
pkg/config/parser_routing_test.go:355:	for _, expected := range []string{"srv1", "srv2", "srv3"} {
pkg/config/parser_routing_test.go:362:	for _, cmd := range setCommands {
pkg/config/parser_routing_test.go:405:	for _, cmd := range setCommands {
pkg/config/parser_routing_test.go:425:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_routing_test.go:538:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_routing_test.go:568:	for _, cmd := range []string{"set routing-instances vpn-fwd instance-type forwarding", "set routing-instances vpn-fwd routing-options static route 10.99.0.0/16 next-hop 10.0.40.1", "set routing-instances normal-vr instance-type virtual-router", "set routing-instances normal-vr interface trust0"} {
pkg/config/parser_routing_test.go:582:	for _, ri := range cfg2.RoutingInstances {
pkg/config/parser_routing_test.go:598:	for _, cmd := range setCommands {
pkg/config/parser_routing_test.go:616:	for _, ra := range cfg.Protocols.RouterAdvertisement {
pkg/config/parser_routing_test.go:769:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:862:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:920:	for _, cmd := range []string{"set protocols bgp local-as 64701", "set protocols bgp group ebgp-peer family inet unicast", "set protocols bgp group ebgp-peer family inet6 unicast", "set protocols bgp group ebgp-peer export my-export-policy", "set protocols bgp group ebgp-peer peer-as 65002", "set protocols bgp group ebgp-peer neighbor 10.1.0.1", "set protocols bgp group ebgp-peer neighbor 10.2.0.1"} {
pkg/config/parser_routing_test.go:1039:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1083:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1111:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1142:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1168:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1205:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1248:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1282:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1310:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1352:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1380:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1399:	for _, cmd := range cmds2 {
pkg/config/parser_routing_test.go:1420:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1449:	for _, iface := range area.Interfaces {
pkg/config/parser_routing_test.go:1468:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1487:	for _, iface := range area.Interfaces {
pkg/config/parser_routing_test.go:1506:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1531:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1559:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1587:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1615:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1640:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1668:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1696:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1724:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1752:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1810:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1851:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1888:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1926:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1955:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:1991:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2024:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2094:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2167:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2202:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2276:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2314:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2343:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2372:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2449:	for _, line := range lines {
pkg/config/parser_routing_test.go:2485:	for _, line := range lines {
pkg/config/parser_routing_test.go:2565:	for _, line := range lines {
pkg/config/parser_routing_test.go:2585:	for _, iface := range cfg.Protocols.LLDP.Interfaces {
pkg/config/parser_routing_test.go:2642:	for _, line := range lines {
pkg/config/parser_routing_test.go:2659:	for _, gr := range cfg.RoutingOptions.GenerateRoutes {
pkg/config/parser_routing_test.go:2705:	for _, bd := range cfg.BridgeDomains {
pkg/config/parser_routing_test.go:2739:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2756:	for _, bd := range cfg.BridgeDomains {
pkg/config/parser_routing_test.go:2790:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2841:	if !strings.Contains(err.Error(), "out of range") {
pkg/config/parser_routing_test.go:2863:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2895:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2930:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:2964:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:3008:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:3036:	for _, cmd := range cmds {
pkg/config/parser_routing_test.go:3064:	for _, line := range lines {
pkg/config/parser_routing_test.go:3136:	for _, line := range lines {

exec
/bin/bash -lc "nl -ba pkg/config/parser_security_test.go | sed -n '3540,3605p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
  3540	func TestDNATPortRange(t *testing.T) {
  3541		input := `security {
  3542	    nat {
  3543	        destination {
  3544	            pool host1 {
  3545	                address 10.0.30.100;
  3546	            }
  3547	            rule-set wan-dnat {
  3548	                from zone untrust;
  3549	                rule port-range {
  3550	                    match {
  3551	                        destination-address 50.220.171.30/32;
  3552	                        destination-port {
  3553	                            80;
  3554	                            443;
  3555	                            20000 to 20005;
  3556	                        }
  3557	                    }
  3558	                    then {
  3559	                        destination-nat pool host1;
  3560	                    }
  3561	                }
  3562	            }
  3563	        }
  3564	    }
  3565	}`
  3566		p := NewParser(input)
  3567		tree, errs := p.Parse()
  3568		if errs != nil {
  3569			t.Fatal(errs)
  3570		}
  3571		cfg, err := CompileConfig(tree)
  3572		if err != nil {
  3573			t.Fatal(err)
  3574		}
  3575		rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
  3576		if len(rule.Match.DestinationPorts) != 8 {
  3577			t.Fatalf("DestinationPorts = %v (len %d), want 8", rule.Match.DestinationPorts, len(rule.Match.DestinationPorts))
  3578		}
  3579		if rule.Match.DestinationPort != 80 {
  3580			t.Errorf("DestinationPort = %d, want 80", rule.Match.DestinationPort)
  3581		}
  3582		if rule.Match.DestinationPorts[2] != 20000 {
  3583			t.Errorf("port[2] = %d, want 20000", rule.Match.DestinationPorts[2])
  3584		}
  3585		if rule.Match.DestinationPorts[7] != 20005 {
  3586			t.Errorf("port[7] = %d, want 20005", rule.Match.DestinationPorts[7])
  3587		}
  3588	}
  3589	
  3590	func TestDNATPortRangeSetSyntax(t *testing.T) {
  3591		lines := []string{"set security nat destination pool web1 address 10.0.30.100", "set security nat destination rule-set wan-dnat from zone untrust", "set security nat destination rule-set wan-dnat rule r1 match destination-address 50.0.0.1/32", "set security nat destination rule-set wan-dnat rule r1 match destination-port 80", "set security nat destination rule-set wan-dnat rule r1 match destination-port 443", "set security nat destination rule-set wan-dnat rule r1 match destination-port 20000 to 20003", "set security nat destination rule-set wan-dnat rule r1 then destination-nat pool web1"}
  3592		tree := &ConfigTree{}
  3593		for _, line := range lines {
  3594			cmd, err := ParseSetCommand(line)
  3595			if err != nil {
  3596				t.Fatalf("ParseSetCommand(%q): %v", line, err)
  3597			}
  3598			if err := tree.SetPath(cmd); err != nil {
  3599				t.Fatalf("SetPath(%v): %v", cmd, err)
  3600			}
  3601		}
  3602		cfg, err := CompileConfig(tree)
  3603		if err != nil {
  3604			t.Fatal(err)
  3605		}

exec
/bin/bash -lc "rg -n \"cmdtree\\.\" pkg/configstore/store.go pkg/configstore -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/configstore/store.go:182:		return cmdtree.SchemaValidate(expanded, nil)
pkg/configstore/store.go:194:	return cmdtree.SchemaValidate(expanded, nil)
pkg/configstore/store.go:182:		return cmdtree.SchemaValidate(expanded, nil)
pkg/configstore/store.go:194:	return cmdtree.SchemaValidate(expanded, nil)
pkg/configstore/store_test.go:1575:// If a future PR expands cmdtree.SchemaValidate to walk

exec
/bin/bash -lc "nl -ba pkg/config/ast.go | sed -n '496,510p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   496						"from": {children: map[string]*schemaNode{
   497							"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
   498						}},
   499						"to": {children: map[string]*schemaNode{
   500							"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
   501						}},
   502						"rule": {args: 1, children: map[string]*schemaNode{
   503							"match": {children: map[string]*schemaNode{
   504								"source-address":      {args: 1, multi: true, children: nil},
   505								"source-address-name": {args: 1, multi: true, children: nil},
   506								"destination-address": {args: 1, multi: true, children: nil},
   507								"destination-port":    {args: 1, multi: true, children: nil},
   508								"protocol":            {args: 1, multi: true, children: nil},
   509								"application":         {args: 1, multi: true, children: nil},
   510							}},

exec
/bin/bash -lc "nl -ba pkg/config/compiler_nat.go | sed -n '678,724p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   678	// Handles single port, multiple ports as children, and port ranges ("20000 to 30000").
   679	// AST shapes handled:
   680	//   - Hierarchical multi-port: destination-port { 80; 443; 20000 to 30000; }
   681	//   - Single port leaf: destination-port 8080;
   682	//   - Set syntax range: destination-port 20000 { to 30000; } (args=1 consumes low, "to N" is child)
   683	func parseDNATPortList(m *Node) []int {
   684		var ports []int
   685		if len(m.Children) > 0 {
   686			// Check for set-syntax port range: Keys=["destination-port","20000"] + child "to 30000"
   687			if len(m.Keys) >= 2 {
   688				if low, err := strconv.Atoi(m.Keys[1]); err == nil {
   689					// Look for "to" child indicating a range
   690					toChild := m.FindChild("to")
   691					if toChild != nil {
   692						if high, err2 := strconv.Atoi(nodeVal(toChild)); err2 == nil && high >= low {
   693							for p := low; p <= high; p++ {
   694								ports = append(ports, p)
   695							}
   696							return ports
   697						}
   698					}
   699					// No range — just a port with non-range children (shouldn't happen, but be safe)
   700					ports = append(ports, low)
   701				}
   702			}
   703			// Multiple ports/ranges as children: destination-port { 80; 443; 20000 to 30000; }
   704			for i := 0; i < len(m.Children); i++ {
   705				child := m.Children[i]
   706				low, err := strconv.Atoi(child.Name())
   707				if err != nil {
   708					continue
   709				}
   710				// Hierarchical range: "20000 to 30000" → leaf Keys=["20000", "to", "30000"]
   711				if len(child.Keys) >= 3 && child.Keys[1] == "to" {
   712					if high, err2 := strconv.Atoi(child.Keys[2]); err2 == nil && high >= low {
   713						for p := low; p <= high; p++ {
   714							ports = append(ports, p)
   715						}
   716						continue
   717					}
   718				}
   719				// Sibling-node range: child[i]="20000", child[i+1]="to", child[i+2]="30000"
   720				if i+2 < len(m.Children) && m.Children[i+1].Name() == "to" {
   721					if high, err2 := strconv.Atoi(m.Children[i+2].Name()); err2 == nil && high >= low {
   722						for p := low; p <= high; p++ {
   723							ports = append(ports, p)
   724						}

exec
/bin/bash -lc "nl -ba pkg/config/schema_validators.go | sed -n '1,45p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
     1	package config
     2	
     3	import (
     4		"fmt"
     5		"math"
     6		"sort"
     7		"strconv"
     8		"strings"
     9	)
    10	
    11	// Schema validators used by #1319 SchemaValidate. Each returns nil for
    12	// accepted input and a descriptive error otherwise. They run at commit
    13	// check time only — the existing compiler parsers (parseBandwidthLimit,
    14	// parseBurstSizeLimit, ...) keep their zero-return-on-error contract so
    15	// downstream callers don't need to learn new error paths.
    16	//
    17	// Validators take a (raw string, cfg *Config) pair so future validators
    18	// can cross-reference compiled state (e.g. "scheduler X must exist").
    19	// Today the schedulers leaves don't need cfg, so they ignore it.
    20	
    21	// LeafValidator is the function signature for typed-leaf validators.
    22	// The mirrored cmdtree.LeafValidator alias has the same shape so
    23	// cmdtree Nodes can hold one of these directly. We define it here too
    24	// (rather than importing cmdtree) to avoid a config→cmdtree→config
    25	// import cycle.
    26	type LeafValidator func(raw string, cfg *Config) error
    27	
    28	// validateRate accepts a Junos bandwidth value (bits/sec) like
    29	// "100k", "10m", "1g", or a bare positive integer. Empty input is
    30	// rejected — a typed leaf with no value is meaningless. Values below
    31	// 8 bps are rejected because the compiler stores scheduler rates in
    32	// bytes/sec; accepting 1..7 bps would round-trip as 0 and silently
    33	// disable the configured rate.
    34	func ValidateRate(raw string, _ *Config) error {
    35		if strings.TrimSpace(raw) == "" {
    36			return fmt.Errorf("missing value (expected bandwidth, e.g. 100k, 10m, 1g)")
    37		}
    38		bps, err := parseScaledDecimalUnitStrict(raw)
    39		if err != nil {
    40			return fmt.Errorf("not a valid bandwidth (expected k/m/g suffix, e.g. 10m): %w", err)
    41		}
    42		if bps < 8 {
    43			return fmt.Errorf("bandwidth must be at least 8 bps so it compiles to a non-zero byte/sec rate (got %q)", raw)
    44		}
    45		return nil

exec
/bin/bash -lc "rg -n \"schemaNode\\{|children == nil|children==nil|childSchema\\.children|childSchema\\.multi|compoundKey|wildcard|midKeyword\" pkg/config/ast_edit.go pkg/config/ast.go" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/config/ast.go:388:	wildcard     *schemaNode            // matches any keyword not in children (for dynamic names)
pkg/config/ast.go:393:	midKeyword   string                 // fixed keyword in the middle of args (e.g., "to-zone")
pkg/config/ast.go:394:	midKeywordAt int                    // 1-based arg position where midKeyword appears (e.g., 2 for "from-zone X to-zone Y")
pkg/config/ast.go:395:	compoundKey  bool                   // children form compound key (e.g., "family inet6" → Keys=["family","inet6"])
pkg/config/ast.go:401:var setSchema = &schemaNode{children: map[string]*schemaNode{
pkg/config/ast.go:402:	"groups":       {wildcard: &schemaNode{}}, // children set in init()
pkg/config/ast.go:404:	"security": {desc: "Security configuration", children: map[string]*schemaNode{
pkg/config/ast.go:405:		"zones": {desc: "Security zones", children: map[string]*schemaNode{
pkg/config/ast.go:406:			"security-zone": {desc: "Security zone name", args: 1, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: map[string]*schemaNode{
pkg/config/ast.go:411:				"host-inbound-traffic": {desc: "Host inbound traffic", children: map[string]*schemaNode{
pkg/config/ast.go:417:		"policies": {desc: "Security policies", children: map[string]*schemaNode{
pkg/config/ast.go:418:			"from-zone": {desc: "From zone", args: 3, valueHint: ValueHintZoneName, midKeyword: "to-zone", midKeywordAt: 2, placeholder: "<zone-name>", children: map[string]*schemaNode{
pkg/config/ast.go:419:				"policy": {desc: "Policy name", args: 1, valueHint: ValueHintPolicyName, placeholder: "<policy-name>", children: map[string]*schemaNode{
pkg/config/ast.go:421:					"match": {desc: "Match criteria", children: map[string]*schemaNode{
pkg/config/ast.go:426:					"then": {desc: "Action", children: map[string]*schemaNode{
pkg/config/ast.go:432:			"global": {desc: "Global policies", children: map[string]*schemaNode{
pkg/config/ast.go:433:				"policy": {desc: "Policy name", args: 1, valueHint: ValueHintPolicyName, placeholder: "<policy-name>", children: map[string]*schemaNode{
pkg/config/ast.go:435:					"match": {desc: "Match criteria", children: map[string]*schemaNode{
pkg/config/ast.go:440:					"then": {desc: "Action", children: map[string]*schemaNode{
pkg/config/ast.go:446:		"screen": {desc: "Screen options", children: map[string]*schemaNode{
pkg/config/ast.go:447:			"ids-option": {desc: "Screen profile name", args: 1, valueHint: ValueHintScreenProfile, placeholder: "<screen-name>", children: map[string]*schemaNode{
pkg/config/ast.go:449:				"tcp": {desc: "TCP screening", children: map[string]*schemaNode{
pkg/config/ast.go:454:				"ip": {desc: "IP screening", children: map[string]*schemaNode{
pkg/config/ast.go:459:				"limit-session": {desc: "Session limits", children: map[string]*schemaNode{
pkg/config/ast.go:465:		"nat": {children: map[string]*schemaNode{
pkg/config/ast.go:466:			"source": {children: map[string]*schemaNode{
pkg/config/ast.go:469:				"rule-set": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:470:					"from": {children: map[string]*schemaNode{
pkg/config/ast.go:473:					"to": {children: map[string]*schemaNode{
pkg/config/ast.go:476:					"rule": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:477:						"match": {children: map[string]*schemaNode{
pkg/config/ast.go:483:						"then": {children: map[string]*schemaNode{
pkg/config/ast.go:484:							"source-nat": {children: map[string]*schemaNode{
pkg/config/ast.go:493:			"destination": {children: map[string]*schemaNode{
pkg/config/ast.go:495:				"rule-set": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:496:					"from": {children: map[string]*schemaNode{
pkg/config/ast.go:499:					"to": {children: map[string]*schemaNode{
pkg/config/ast.go:502:					"rule": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:503:						"match": {children: map[string]*schemaNode{
pkg/config/ast.go:511:						"then": {children: map[string]*schemaNode{
pkg/config/ast.go:512:							"destination-nat": {children: map[string]*schemaNode{
pkg/config/ast.go:519:			"static": {children: map[string]*schemaNode{
pkg/config/ast.go:520:				"rule-set": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:521:					"rule": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:523:						"then": {children: map[string]*schemaNode{
pkg/config/ast.go:529:			"nat64": {children: map[string]*schemaNode{
pkg/config/ast.go:530:				"rule-set": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:535:			"natv6v4": {children: map[string]*schemaNode{
pkg/config/ast.go:538:			"proxy-arp": {children: map[string]*schemaNode{
pkg/config/ast.go:539:				"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
pkg/config/ast.go:544:		"address-book": {children: map[string]*schemaNode{
pkg/config/ast.go:545:			"global": {children: map[string]*schemaNode{
pkg/config/ast.go:547:				"address-set": {args: 1, valueHint: ValueHintAddressName, children: map[string]*schemaNode{
pkg/config/ast.go:554:		"log": {children: map[string]*schemaNode{
pkg/config/ast.go:558:			"stream": {args: 1, valueHint: ValueHintStreamName, children: map[string]*schemaNode{
pkg/config/ast.go:568:		"flow": {children: map[string]*schemaNode{
pkg/config/ast.go:578:			"traceoptions": {children: map[string]*schemaNode{
pkg/config/ast.go:581:				"packet-filter": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:587:		"alg": {children: map[string]*schemaNode{
pkg/config/ast.go:593:		"ike": {children: map[string]*schemaNode{
pkg/config/ast.go:595:			"policy": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:600:			"gateway": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:609:				"dead-peer-detection": {children: map[string]*schemaNode{
pkg/config/ast.go:621:		"ipsec": {children: map[string]*schemaNode{
pkg/config/ast.go:623:			"policy": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:627:			"gateway": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:636:				"dead-peer-detection": {children: map[string]*schemaNode{
pkg/config/ast.go:647:			"vpn": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:655:				"traffic-selector": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:659:				"ike": {children: map[string]*schemaNode{
pkg/config/ast.go:665:		"dynamic-address": {children: map[string]*schemaNode{
pkg/config/ast.go:666:			"feed-server": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:671:				"feed-name": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:675:			"address-name": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:676:				"profile": {children: map[string]*schemaNode{
pkg/config/ast.go:681:		"ssh-known-hosts": {children: map[string]*schemaNode{
pkg/config/ast.go:684:		"policy-stats": {children: map[string]*schemaNode{
pkg/config/ast.go:687:		"pre-id-default-policy": {children: map[string]*schemaNode{
pkg/config/ast.go:688:			"then": {children: map[string]*schemaNode{
pkg/config/ast.go:689:				"log": {children: map[string]*schemaNode{
pkg/config/ast.go:696:	"interfaces": {desc: "Interface configuration", wildcard: &schemaNode{valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
pkg/config/ast.go:706:		"gigether-options": {desc: "Gigabit Ethernet interface options", children: map[string]*schemaNode{
pkg/config/ast.go:710:		"aggregated-ether-options": {desc: "Aggregated Ethernet interface options", children: map[string]*schemaNode{
pkg/config/ast.go:711:			"lacp": {desc: "LACP parameters", children: map[string]*schemaNode{
pkg/config/ast.go:719:		"redundant-ether-options": {desc: "Redundant Ethernet interface options", children: map[string]*schemaNode{
pkg/config/ast.go:722:		"fabric-options": {desc: "Fabric interface options", children: map[string]*schemaNode{
pkg/config/ast.go:725:		"tunnel": {desc: "Tunnel parameters", children: map[string]*schemaNode{
pkg/config/ast.go:733:			"routing-instance": {desc: "Routing instance", children: map[string]*schemaNode{
pkg/config/ast.go:737:		"unit": {desc: "Logical unit number", args: 1, valueHint: ValueHintUnitNumber, placeholder: "<unit-number>", children: map[string]*schemaNode{
pkg/config/ast.go:742:			"tunnel": {desc: "Tunnel parameters", children: map[string]*schemaNode{
pkg/config/ast.go:750:				"routing-instance": {desc: "Routing instance", children: map[string]*schemaNode{
pkg/config/ast.go:754:			"family": {desc: "Protocol family", compoundKey: true, children: map[string]*schemaNode{
pkg/config/ast.go:755:				"inet": {desc: "IPv4 protocol", children: map[string]*schemaNode{
pkg/config/ast.go:757:					"address": {desc: "IPv4 address", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
pkg/config/ast.go:761:					"dhcp": {desc: "DHCP client", children: map[string]*schemaNode{
pkg/config/ast.go:767:					"sampling": {desc: "Traffic sampling", children: map[string]*schemaNode{
pkg/config/ast.go:771:					"filter": {desc: "Firewall filter", children: map[string]*schemaNode{
pkg/config/ast.go:776:				"inet6": {desc: "IPv6 protocol", children: map[string]*schemaNode{
pkg/config/ast.go:779:					"address": {desc: "IPv6 address", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
pkg/config/ast.go:783:					"sampling": {desc: "Traffic sampling", children: map[string]*schemaNode{
pkg/config/ast.go:787:					"filter": {desc: "Firewall filter", children: map[string]*schemaNode{
pkg/config/ast.go:791:					"dhcpv6-client": {desc: "DHCPv6 client", children: map[string]*schemaNode{
pkg/config/ast.go:794:						"prefix-delegating": {desc: "Prefix delegation", children: map[string]*schemaNode{
pkg/config/ast.go:798:						"client-identifier": {desc: "Client identifier", children: map[string]*schemaNode{
pkg/config/ast.go:802:						"update-router-advertisement": {desc: "Update router advertisement", children: map[string]*schemaNode{
pkg/config/ast.go:810:	"applications": {desc: "Applications", children: map[string]*schemaNode{
pkg/config/ast.go:811:		"application": {desc: "Application name", args: 1, valueHint: ValueHintAppName, placeholder: "<name>", children: map[string]*schemaNode{
pkg/config/ast.go:823:	"routing-options": {desc: "Routing options", children: map[string]*schemaNode{
pkg/config/ast.go:824:		"static": {desc: "Static routes", children: map[string]*schemaNode{
pkg/config/ast.go:827:		"rib": {desc: "Routing information base", args: 1, placeholder: "<rib-name>", children: map[string]*schemaNode{
pkg/config/ast.go:828:			"static": {desc: "Static routes", children: map[string]*schemaNode{
pkg/config/ast.go:833:		"forwarding-table": {desc: "Forwarding table", children: map[string]*schemaNode{
pkg/config/ast.go:836:		"rib-groups": {desc: "RIB groups", wildcard: &schemaNode{children: map[string]*schemaNode{
pkg/config/ast.go:839:		"interface-routes": {desc: "Interface routes", children: map[string]*schemaNode{
pkg/config/ast.go:840:			"rib-group": {desc: "RIB group", children: map[string]*schemaNode{
pkg/config/ast.go:845:		"generate": {desc: "Generated routes", children: map[string]*schemaNode{
pkg/config/ast.go:846:			"route": {desc: "Generated route", args: 1, placeholder: "<destination>", children: map[string]*schemaNode{
pkg/config/ast.go:852:	"snmp": {desc: "SNMP configuration", children: map[string]*schemaNode{
pkg/config/ast.go:853:		"community": {desc: "SNMP community", args: 1, placeholder: "<community-name>", children: map[string]*schemaNode{
pkg/config/ast.go:857:		"v3": {desc: "SNMPv3", children: map[string]*schemaNode{
pkg/config/ast.go:858:			"usm": {desc: "USM", children: map[string]*schemaNode{
pkg/config/ast.go:859:				"local-engine": {desc: "Local engine", children: map[string]*schemaNode{
pkg/config/ast.go:860:					"user": {desc: "User name", args: 1, placeholder: "<user-name>", children: map[string]*schemaNode{
pkg/config/ast.go:861:						"authentication-md5":    {desc: "MD5 authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
pkg/config/ast.go:862:						"authentication-sha":    {desc: "SHA authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
pkg/config/ast.go:863:						"authentication-sha256": {desc: "SHA256 authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
pkg/config/ast.go:864:						"privacy-des":           {desc: "DES privacy", children: map[string]*schemaNode{"privacy-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
pkg/config/ast.go:865:						"privacy-aes128":        {desc: "AES128 privacy", children: map[string]*schemaNode{"privacy-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
pkg/config/ast.go:871:	"policy-options": {desc: "Policy options", children: map[string]*schemaNode{
pkg/config/ast.go:873:		"community": {desc: "Community", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
pkg/config/ast.go:877:		"policy-statement": {desc: "Policy statement", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
pkg/config/ast.go:878:			"term": {desc: "Term name", args: 1, placeholder: "<term-name>", children: map[string]*schemaNode{
pkg/config/ast.go:879:				"from": {desc: "Match condition", children: map[string]*schemaNode{
pkg/config/ast.go:886:				"then": {desc: "Action", children: map[string]*schemaNode{
pkg/config/ast.go:901:	"protocols": {desc: "Protocols configuration", children: map[string]*schemaNode{
pkg/config/ast.go:902:		"ospf": {desc: "OSPF configuration", children: map[string]*schemaNode{
pkg/config/ast.go:907:			"area": {desc: "OSPF area", args: 1, placeholder: "<area-id>", children: map[string]*schemaNode{
pkg/config/ast.go:908:				"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
pkg/config/ast.go:913:					"authentication": {desc: "Authentication", children: map[string]*schemaNode{
pkg/config/ast.go:914:						"md5": {desc: "MD5 authentication", args: 1, placeholder: "<key-id>", children: map[string]*schemaNode{
pkg/config/ast.go:919:					"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
pkg/config/ast.go:924:				"area-type": {desc: "Area type", children: map[string]*schemaNode{
pkg/config/ast.go:925:					"stub": {desc: "Stub area", children: map[string]*schemaNode{
pkg/config/ast.go:928:					"nssa": {desc: "NSSA area", children: map[string]*schemaNode{
pkg/config/ast.go:932:				"virtual-link": {desc: "Virtual link", args: 1, placeholder: "<router-id>", children: map[string]*schemaNode{
pkg/config/ast.go:937:		"ospf3": {desc: "OSPFv3 configuration", children: map[string]*schemaNode{
pkg/config/ast.go:940:			"area": {desc: "OSPFv3 area", args: 1, placeholder: "<area-id>", children: map[string]*schemaNode{
pkg/config/ast.go:941:				"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
pkg/config/ast.go:947:		"bgp": {desc: "BGP configuration", children: map[string]*schemaNode{
pkg/config/ast.go:953:			"multipath": {desc: "Multipath", children: map[string]*schemaNode{
pkg/config/ast.go:956:			"damping": {desc: "Route damping", children: map[string]*schemaNode{
pkg/config/ast.go:963:			"group": {desc: "BGP group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
pkg/config/ast.go:972:				"family": {desc: "Address family", compoundKey: true, children: map[string]*schemaNode{
pkg/config/ast.go:973:					"inet": {desc: "IPv4", children: map[string]*schemaNode{
pkg/config/ast.go:974:						"unicast": {desc: "Unicast", children: map[string]*schemaNode{
pkg/config/ast.go:975:							"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
pkg/config/ast.go:980:					"inet6": {desc: "IPv6", children: map[string]*schemaNode{
pkg/config/ast.go:981:						"unicast": {desc: "Unicast", children: map[string]*schemaNode{
pkg/config/ast.go:982:							"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
pkg/config/ast.go:988:				"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
pkg/config/ast.go:992:				"neighbor": {desc: "BGP neighbor", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
pkg/config/ast.go:1001:					"family": {desc: "Address family", compoundKey: true, children: map[string]*schemaNode{
pkg/config/ast.go:1002:						"inet": {desc: "IPv4", children: map[string]*schemaNode{
pkg/config/ast.go:1003:							"unicast": {desc: "Unicast", children: map[string]*schemaNode{
pkg/config/ast.go:1004:								"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
pkg/config/ast.go:1009:						"inet6": {desc: "IPv6", children: map[string]*schemaNode{
pkg/config/ast.go:1010:							"unicast": {desc: "Unicast", children: map[string]*schemaNode{
pkg/config/ast.go:1011:								"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
pkg/config/ast.go:1017:					"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
pkg/config/ast.go:1024:		"rip": {desc: "RIP configuration", children: map[string]*schemaNode{
pkg/config/ast.go:1032:		"isis": {desc: "IS-IS configuration", children: map[string]*schemaNode{
pkg/config/ast.go:1037:			"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
pkg/config/ast.go:1043:				"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
pkg/config/ast.go:1053:		"router-advertisement": {desc: "Router advertisement", children: map[string]*schemaNode{
pkg/config/ast.go:1054:			"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
pkg/config/ast.go:1057:				"nat-prefix": {desc: "NAT prefix", args: 1, placeholder: "<prefix>", children: map[string]*schemaNode{
pkg/config/ast.go:1060:				"nat64prefix": {desc: "NAT64 prefix", args: 1, placeholder: "<prefix>", children: map[string]*schemaNode{
pkg/config/ast.go:1065:		"lldp": {desc: "LLDP configuration", children: map[string]*schemaNode{
pkg/config/ast.go:1066:			"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
pkg/config/ast.go:1074:	"event-options": {children: map[string]*schemaNode{
pkg/config/ast.go:1075:		"policy": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1077:			"within": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1081:			"then": {children: map[string]*schemaNode{
pkg/config/ast.go:1082:				"change-configuration": {children: map[string]*schemaNode{
pkg/config/ast.go:1088:	"chassis": {children: map[string]*schemaNode{
pkg/config/ast.go:1089:		"cluster": {children: map[string]*schemaNode{
pkg/config/ast.go:1096:			"control-ports": {children: map[string]*schemaNode{
pkg/config/ast.go:1097:				"fpc": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1115:			"redundancy-group": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1116:				"node": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1122:				"ip-monitoring": {children: map[string]*schemaNode{
pkg/config/ast.go:1125:					"family": {compoundKey: true, children: map[string]*schemaNode{
pkg/config/ast.go:1126:						"inet": {wildcard: &schemaNode{children: map[string]*schemaNode{
pkg/config/ast.go:1134:	"class-of-service": {desc: "Class of service configuration", children: map[string]*schemaNode{
pkg/config/ast.go:1135:		"forwarding-classes": {children: map[string]*schemaNode{
pkg/config/ast.go:1138:		"classifiers": {children: map[string]*schemaNode{
pkg/config/ast.go:1139:			"dscp": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1140:				"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1141:					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1146:			"ieee-802.1": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1147:				"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1148:					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1154:		"rewrite-rules": {children: map[string]*schemaNode{
pkg/config/ast.go:1155:			"dscp": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1156:				"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1157:					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1164:		"schedulers": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1165:			"transmit-rate": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1173:		"scheduler-maps": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1174:			"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1178:		"interfaces": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1179:			"unit": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1180:				"classifiers": {children: map[string]*schemaNode{
pkg/config/ast.go:1184:				"rewrite-rules": {children: map[string]*schemaNode{
pkg/config/ast.go:1187:				"shaping-rate": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1193:		"fairness": {children: map[string]*schemaNode{
pkg/config/ast.go:1194:			"rss-expectation": {children: map[string]*schemaNode{
pkg/config/ast.go:1195:				"ifindex": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1196:					"queue": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1209:	"firewall": {children: map[string]*schemaNode{
pkg/config/ast.go:1210:		"policer": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1211:			"if-exceeding": {children: map[string]*schemaNode{
pkg/config/ast.go:1216:			"then": {children: map[string]*schemaNode{
pkg/config/ast.go:1221:		"three-color-policer": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1222:			"single-rate": {children: map[string]*schemaNode{
pkg/config/ast.go:1229:			"two-rate": {children: map[string]*schemaNode{
pkg/config/ast.go:1237:			"then": {children: map[string]*schemaNode{
pkg/config/ast.go:1242:		"family": {compoundKey: true, children: map[string]*schemaNode{
pkg/config/ast.go:1243:			"inet": {children: map[string]*schemaNode{
pkg/config/ast.go:1244:				"filter": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1245:					"term": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1246:						"from": {children: map[string]*schemaNode{
pkg/config/ast.go:1259:							"flexible-match-range": {children: map[string]*schemaNode{
pkg/config/ast.go:1260:								"range": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1270:						"then": {children: map[string]*schemaNode{
pkg/config/ast.go:1287:			"inet6": {children: map[string]*schemaNode{
pkg/config/ast.go:1288:				"filter": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1289:					"term": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1290:						"from": {children: map[string]*schemaNode{
pkg/config/ast.go:1303:							"flexible-match-range": {children: map[string]*schemaNode{
pkg/config/ast.go:1304:								"range": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1314:						"then": {children: map[string]*schemaNode{
pkg/config/ast.go:1333:	"system": {desc: "System configuration", children: map[string]*schemaNode{
pkg/config/ast.go:1340:		"backup-router": {desc: "Backup router", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
pkg/config/ast.go:1343:		"root-authentication": {desc: "Root authentication", children: map[string]*schemaNode{
pkg/config/ast.go:1349:		"archival": {desc: "Configuration archival", children: map[string]*schemaNode{
pkg/config/ast.go:1350:			"configuration": {desc: "Configuration archival", children: map[string]*schemaNode{
pkg/config/ast.go:1355:		"master-password": {desc: "Master password", children: map[string]*schemaNode{
pkg/config/ast.go:1358:		"license": {desc: "License configuration", children: map[string]*schemaNode{
pkg/config/ast.go:1359:			"autoupdate": {desc: "Autoupdate", children: map[string]*schemaNode{
pkg/config/ast.go:1364:		"internet-options": {desc: "Internet options", children: map[string]*schemaNode{
pkg/config/ast.go:1367:		"ntp": {desc: "NTP configuration", children: map[string]*schemaNode{
pkg/config/ast.go:1369:			"threshold": {desc: "Threshold", args: 1, placeholder: "<seconds>", children: map[string]*schemaNode{
pkg/config/ast.go:1373:		"syslog": {desc: "Syslog configuration", children: map[string]*schemaNode{
pkg/config/ast.go:1378:		"login": {desc: "Login configuration", children: map[string]*schemaNode{
pkg/config/ast.go:1379:			"user": {desc: "User name", args: 1, placeholder: "<username>", children: map[string]*schemaNode{
pkg/config/ast.go:1386:		"dataplane": {desc: "Dataplane configuration", children: map[string]*schemaNode{
pkg/config/ast.go:1396:			"shared-umem": {desc: "AF_XDP shared-UMEM policy override", children: map[string]*schemaNode{
pkg/config/ast.go:1406:			"coalescence": {desc: "NIC interrupt-coalescence tuning (mlx5)", children: map[string]*schemaNode{
pkg/config/ast.go:1411:			"rx-mode": {children: map[string]*schemaNode{
pkg/config/ast.go:1416:			"ports": {wildcard: &schemaNode{children: map[string]*schemaNode{
pkg/config/ast.go:1422:		"services": {desc: "System services", children: map[string]*schemaNode{
pkg/config/ast.go:1423:			"ssh": {desc: "SSH service", children: map[string]*schemaNode{
pkg/config/ast.go:1426:			"netconf": {desc: "NETCONF service", children: map[string]*schemaNode{
pkg/config/ast.go:1429:			"web-management": {desc: "Web management", children: map[string]*schemaNode{
pkg/config/ast.go:1430:				"http": {desc: "HTTP service", children: map[string]*schemaNode{
pkg/config/ast.go:1433:				"https": {desc: "HTTPS service", children: map[string]*schemaNode{
pkg/config/ast.go:1437:				"api-auth": {desc: "API authentication", children: map[string]*schemaNode{
pkg/config/ast.go:1438:					"user": {desc: "User name", wildcard: &schemaNode{placeholder: "<username>", children: map[string]*schemaNode{
pkg/config/ast.go:1445:			"dhcp-local-server": {desc: "DHCP local server", children: map[string]*schemaNode{
pkg/config/ast.go:1446:				"group": {desc: "DHCP group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
pkg/config/ast.go:1450:			"dhcpv6-local-server": {desc: "DHCPv6 local server", children: map[string]*schemaNode{
pkg/config/ast.go:1451:				"group": {desc: "DHCPv6 group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
pkg/config/ast.go:1457:	"services": {desc: "Services configuration", children: map[string]*schemaNode{
pkg/config/ast.go:1458:		"rpm": {desc: "Real-time Performance Monitoring probes", children: map[string]*schemaNode{
pkg/config/ast.go:1460:			"probe": {args: 1, desc: "RPM probe name", children: map[string]*schemaNode{
pkg/config/ast.go:1461:				"test": {args: 1, desc: "RPM test name", children: map[string]*schemaNode{
pkg/config/ast.go:1463:					"target":           {desc: "Target IP, hostname, or URL", wildcard: &schemaNode{placeholder: "<target>", desc: "Target IP, hostname, or URL"}, children: map[string]*schemaNode{"url": {args: 1, desc: "HTTP target URL", children: nil}}},
pkg/config/ast.go:1469:					"thresholds": {desc: "Failure thresholds for the test", children: map[string]*schemaNode{
pkg/config/ast.go:1477:		"flow-monitoring": {children: map[string]*schemaNode{
pkg/config/ast.go:1478:			"version9": {children: map[string]*schemaNode{
pkg/config/ast.go:1479:				"template": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1482:					"template-refresh-rate": {children: map[string]*schemaNode{
pkg/config/ast.go:1487:			"version-ipfix": {children: map[string]*schemaNode{
pkg/config/ast.go:1488:				"template": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1491:					"template-refresh-rate": {children: map[string]*schemaNode{
pkg/config/ast.go:1494:					"ipv4-template": {children: map[string]*schemaNode{
pkg/config/ast.go:1497:					"ipv6-template": {children: map[string]*schemaNode{
pkg/config/ast.go:1505:	"forwarding-options": {children: map[string]*schemaNode{
pkg/config/ast.go:1506:		"family": {compoundKey: true, children: map[string]*schemaNode{
pkg/config/ast.go:1507:			"inet6": {children: map[string]*schemaNode{
pkg/config/ast.go:1511:		"sampling": {children: map[string]*schemaNode{
pkg/config/ast.go:1512:			"instance": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1514:				"family": {compoundKey: true, children: map[string]*schemaNode{
pkg/config/ast.go:1515:					"inet": {children: map[string]*schemaNode{
pkg/config/ast.go:1516:						"output": {children: map[string]*schemaNode{
pkg/config/ast.go:1521:					"inet6": {children: map[string]*schemaNode{
pkg/config/ast.go:1522:						"output": {children: map[string]*schemaNode{
pkg/config/ast.go:1530:		"port-mirroring": {children: map[string]*schemaNode{
pkg/config/ast.go:1531:			"instance": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1532:				"input": {children: map[string]*schemaNode{
pkg/config/ast.go:1539:	"bridge-domains": {wildcard: &schemaNode{desc: "Bridge domain name", children: map[string]*schemaNode{
pkg/config/ast.go:1544:	"routing-instances": {wildcard: &schemaNode{children: map[string]*schemaNode{
pkg/config/ast.go:1547:		"routing-options": {children: map[string]*schemaNode{
pkg/config/ast.go:1548:			"static": {children: map[string]*schemaNode{
pkg/config/ast.go:1551:			"rib": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1552:				"static": {children: map[string]*schemaNode{
pkg/config/ast.go:1556:			"interface-routes": {children: map[string]*schemaNode{
pkg/config/ast.go:1557:				"rib-group": {children: map[string]*schemaNode{
pkg/config/ast.go:1563:		"protocols": {children: map[string]*schemaNode{
pkg/config/ast.go:1564:			"ospf": {children: map[string]*schemaNode{
pkg/config/ast.go:1567:				"area": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1568:					"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
pkg/config/ast.go:1573:						"authentication": {children: map[string]*schemaNode{
pkg/config/ast.go:1574:							"md5": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1579:						"bfd-liveness-detection": {children: map[string]*schemaNode{
pkg/config/ast.go:1584:					"area-type": {children: map[string]*schemaNode{
pkg/config/ast.go:1585:						"stub": {children: map[string]*schemaNode{
pkg/config/ast.go:1588:						"nssa": {children: map[string]*schemaNode{
pkg/config/ast.go:1592:					"virtual-link": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1597:			"ospf3": {children: map[string]*schemaNode{
pkg/config/ast.go:1600:				"area": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1601:					"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
pkg/config/ast.go:1607:			"bgp": {children: map[string]*schemaNode{
pkg/config/ast.go:1609:				"damping": {children: map[string]*schemaNode{
pkg/config/ast.go:1617:			"isis": {children: map[string]*schemaNode{
pkg/config/ast.go:1622:				"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
pkg/config/ast.go:1628:					"bfd-liveness-detection": {children: map[string]*schemaNode{
pkg/config/ast.go:1643:	// Wire groups wildcard to mirror top-level schema children.
pkg/config/ast.go:1645:	groupWild := setSchema.children["groups"].wildcard
pkg/config/ast.go:1671:// (wildcard or args > 0), it returns nil (user must type a name).
pkg/config/ast.go:1696:		if schema.children == nil && schema.wildcard == nil {
pkg/config/ast.go:1727:		if childSchema == nil && schema.wildcard != nil {
pkg/config/ast.go:1728:			childSchema = schema.wildcard
pkg/config/ast.go:1759:		if childSchema.compoundKey && i < len(tokens) {
pkg/config/ast.go:1760:			if sub, ok := childSchema.children[tokens[i]]; ok {
pkg/config/ast.go:1773:			if childSchema.midKeyword != "" && childSchema.midKeywordAt > 0 {
pkg/config/ast.go:1775:				// If the last consumed token is a partial match for the midKeyword, suggest it.
pkg/config/ast.go:1776:				if nextPos == childSchema.midKeywordAt+1 && consumed > 1 {
pkg/config/ast.go:1778:					if lastToken != childSchema.midKeyword && strings.HasPrefix(childSchema.midKeyword, lastToken) {
pkg/config/ast.go:1779:						return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}
pkg/config/ast.go:1782:				// If we need to complete the midKeyword position, suggest it.
pkg/config/ast.go:1783:				if nextPos == childSchema.midKeywordAt {
pkg/config/ast.go:1784:					return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}
pkg/config/ast.go:1804:		if childSchema.multi && childSchema.children == nil {
pkg/config/ast.go:1816:	// If we're at a leaf with no children/wildcard, hint that Enter completes.
pkg/config/ast.go:1817:	if schema.children == nil && schema.wildcard == nil {
pkg/config/ast.go:1827:	// If this level accepts a wildcard name, provide dynamic values too.
pkg/config/ast.go:1828:	if schema.wildcard != nil {
pkg/config/ast.go:1829:		if provider != nil && schema.wildcard.valueHint != ValueHintNone {
pkg/config/ast.go:1830:			completions = append(completions, provider(schema.wildcard.valueHint, path)...)
pkg/config/ast.go:1833:		if schema.wildcard.placeholder != "" {
pkg/config/ast.go:1834:			completions = append(completions, SchemaCompletion{Name: schema.wildcard.placeholder, Desc: schema.wildcard.desc})
pkg/config/ast.go:1876:		if childSchema == nil && schema.wildcard != nil {
pkg/config/ast.go:1877:			childSchema = schema.wildcard
pkg/config/ast.go:1894:		if childSchema.compoundKey && i < len(tokens) {
pkg/config/ast.go:1896:			if sub, ok := childSchema.children[subKeyword]; ok {
pkg/config/ast.go:1902:				for name := range childSchema.children {
pkg/config/ast.go:1912:				childSchema = childSchema.children[matches[0]]
pkg/config/ast.go:1916:		if childSchema.multi && childSchema.children == nil {
pkg/config/ast_edit.go:146:			} else if schema.wildcard != nil {
pkg/config/ast_edit.go:147:				childSchema = schema.wildcard
pkg/config/ast_edit.go:186:		if childSchema.compoundKey && i < len(path) {
pkg/config/ast_edit.go:187:			if sub, ok := childSchema.children[path[i]]; ok {
pkg/config/ast_edit.go:196:			if childSchema.args > 0 && !childSchema.multi && childSchema.children == nil {
pkg/config/ast_edit.go:244:		if childSchema.children == nil && childSchema.multi && i < len(path) {
pkg/config/ast_edit.go:247:			if !nextIsSibling && schema.wildcard != nil {
pkg/config/ast_edit.go:316:		} else if schema.wildcard != nil {
pkg/config/ast_edit.go:317:			childSchema = schema.wildcard
pkg/config/ast_edit.go:339:	if childSchema.compoundKey && i < len(path) {
pkg/config/ast_edit.go:340:		if sub, ok := childSchema.children[path[i]]; ok {

exec
/bin/bash -lc "nl -ba pkg/cli/cli.go | sed -n '232,256p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   232				}
   233	
   234				words := strings.Fields(text)
   235				trailingSpace := len(text) > 0 && text[len(text)-1] == ' '
   236				var partial string
   237				if !trailingSpace && len(words) > 0 {
   238					partial = words[len(words)-1]
   239					words = words[:len(words)-1]
   240				}
   241				var candidates []completionCandidate
   242				if c.store.InConfigMode() {
   243					candidates = c.completeConfigWithDesc(words, partial)
   244				} else {
   245					// "show configuration <path>" — delegate sub-path to config schema
   246					if subPath, ok := showConfigurationSubPath(words); ok {
   247						if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(subPath); resolved {
   248							subPath = resolvedPath
   249						}
   250						schemaCompletions := config.CompleteSetPathWithValues(subPath, c.valueProvider)
   251						if schemaCompletions != nil {
   252							for _, sc := range schemaCompletions {
   253								if partial == "" || strings.HasPrefix(sc.Name, partial) {
   254									candidates = append(candidates, completionCandidate{name: sc.Name, desc: sc.Desc})
   255								}
   256							}

exec
/bin/bash -lc "nl -ba pkg/grpcapi/completion_test.go | sed -n '1,70p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
     1	package grpcapi
     2	
     3	import "testing"
     4	
     5	func hasPairName(pairs []completionPair, want string) bool {
     6		for _, p := range pairs {
     7			if p.name == want {
     8				return true
     9			}
    10		}
    11		return false
    12	}
    13	
    14	func TestCompleteConfigPairsCommitReturnsAllMatches(t *testing.T) {
    15		s := &Server{}
    16		pairs := s.completeConfigPairs([]string{"commit"}, "")
    17		if !hasPairName(pairs, "check") || !hasPairName(pairs, "confirmed") || !hasPairName(pairs, "comment") {
    18			t.Fatalf("expected all commit completions, got %#v", pairs)
    19		}
    20	}
    21	
    22	func TestCompleteConfigPairsLoadReturnsAllMatches(t *testing.T) {
    23		s := &Server{}
    24		pairs := s.completeConfigPairs([]string{"load"}, "")
    25		if !hasPairName(pairs, "override") || !hasPairName(pairs, "merge") || !hasPairName(pairs, "set") {
    26			t.Fatalf("expected all load completions, got %#v", pairs)
    27		}
    28	}
    29	
    30	func TestCompleteOperationalPairsShowConfigurationResolvesPrefixes(t *testing.T) {
    31		s := &Server{}
    32		pairs := s.completeOperationalPairs([]string{"show", "conf", "sec"}, "po")
    33		if !hasPairName(pairs, "policies") {
    34			t.Fatalf("expected policies completion for prefixed show configuration path, got %#v", pairs)
    35		}
    36	}
    37	
    38	func TestCompleteConfigPairsUniquePrefixDescends(t *testing.T) {
    39		s := &Server{}
    40		pairs := s.completeConfigPairs([]string{"com"}, "")
    41		if !hasPairName(pairs, "check") || !hasPairName(pairs, "confirmed") || !hasPairName(pairs, "comment") {
    42			t.Fatalf("expected commit subtree completions after unique prefix, got %#v", pairs)
    43		}
    44	}
    45	
    46	func TestCompleteConfigPairsAmbiguousPrefixReturnsMatches(t *testing.T) {
    47		s := &Server{}
    48		pairs := s.completeConfigPairs([]string{"co"}, "")
    49		if !hasPairName(pairs, "commit") || !hasPairName(pairs, "copy") {
    50			t.Fatalf("expected ambiguous top-level config matches, got %#v", pairs)
    51		}
    52	}
    53	
    54	func TestCompleteConfigPairsDynamicPathWithoutStoreDoesNotPanic(t *testing.T) {
    55		s := &Server{}
    56		_ = s.completeConfigPairs([]string{"set", "security", "policies", "from-zone"}, "")
    57	}

codex
Verdict: **PLAN-NEEDS-MAJOR**

Four of the five round-1 findings are addressed, but the generic walker contract is still incomplete against real `setSchema`/`SetPath` behavior.

**Major finding: walker contract still misses multi leaf trailing-value/range shapes.**  
v2 says the walker must port every special case from `SetPath`, then reduces `multi` to:

> “`multi` | leaf may repeat; validate each occurrence; do not treat as replace”  
[plan.md:253](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:253)

That is not enough. `SetPath` has a separate rule for `multi && children == nil`: if the next token is not a sibling keyword, the remaining tokens become trailing values under this leaf:

> “If the next token is NOT a known sibling, the remaining tokens are trailing values for this leaf”  
[ast_edit.go:237](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast_edit.go:237)

The live schema has exactly this shape, for example DNAT `destination-port`:

> `"destination-port": {args: 1, multi: true, children: nil}`  
[ast.go:507](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast.go:507)

And production tests rely on set syntax ranges:

> `set security nat destination ... match destination-port 20000 to 20003`  
[parser_security_test.go:3591](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/parser_security_test.go:3591)

The compiler documents the resulting AST shape:

> `Set syntax range: destination-port 20000 { to 30000; }`  
[compiler_nat.go:682](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/compiler_nat.go:682)

So the PR-1 walker contract still needs an explicit row for `multi && children == nil` trailing values: distinguish sibling continuation from value-tail continuation, and define validation behavior for typed multi leaves that consume syntactic tails like `to <high>`. Otherwise PR 1 claims “no walker/infra changes after PR 1” while leaving a real `setSchema` feature undefined.

The other checks pass:

- Import cycle: corrected. `cmdtree` already imports `config` at [tree.go:19](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cmdtree/tree.go:19), while production `pkg/config` does not import `cmdtree`; `ValueType = config.ValueType` alias-back is viable and methods like `Placeholder()` continue to work through the alias.
- Fields-only: corrected. `SetPath` really keys replace behavior on `children == nil` at [ast_edit.go:196](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast_edit.go:196), and v2 bans child-map changes at [plan.md:218](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:218).
- `temporal`/`exact`: corrected. `exact` is compiled in `parseCoSTransmitRate` via both trailing keys and child nodes at [compiler_class_of_service.go:498](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/compiler_class_of_service.go:498) and [compiler_class_of_service.go:507](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/compiler_class_of_service.go:507). `buffer-size` reads only `nodeVal(child)` at [compiler_class_of_service.go:239](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/compiler_class_of_service.go:239), so dropping `temporal` is right.
- Frontend-boundary tests: PR-1 step 6 is correct: it requires `cli.completeConfigWithDesc` and gRPC `completeConfigPairs`, matching real production boundaries at [completion.go:148](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cli/completion.go:148) and [server_cluster.go:568](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/grpcapi/server_cluster.go:568).

Fix the walker contract table for `multi && children == nil` value tails/ranges, and this likely moves to **PLAN-READY**.
tokens used
130,005
Verdict: **PLAN-NEEDS-MAJOR**

Four of the five round-1 findings are addressed, but the generic walker contract is still incomplete against real `setSchema`/`SetPath` behavior.

**Major finding: walker contract still misses multi leaf trailing-value/range shapes.**  
v2 says the walker must port every special case from `SetPath`, then reduces `multi` to:

> “`multi` | leaf may repeat; validate each occurrence; do not treat as replace”  
[plan.md:253](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:253)

That is not enough. `SetPath` has a separate rule for `multi && children == nil`: if the next token is not a sibling keyword, the remaining tokens become trailing values under this leaf:

> “If the next token is NOT a known sibling, the remaining tokens are trailing values for this leaf”  
[ast_edit.go:237](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast_edit.go:237)

The live schema has exactly this shape, for example DNAT `destination-port`:

> `"destination-port": {args: 1, multi: true, children: nil}`  
[ast.go:507](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast.go:507)

And production tests rely on set syntax ranges:

> `set security nat destination ... match destination-port 20000 to 20003`  
[parser_security_test.go:3591](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/parser_security_test.go:3591)

The compiler documents the resulting AST shape:

> `Set syntax range: destination-port 20000 { to 30000; }`  
[compiler_nat.go:682](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/compiler_nat.go:682)

So the PR-1 walker contract still needs an explicit row for `multi && children == nil` trailing values: distinguish sibling continuation from value-tail continuation, and define validation behavior for typed multi leaves that consume syntactic tails like `to <high>`. Otherwise PR 1 claims “no walker/infra changes after PR 1” while leaving a real `setSchema` feature undefined.

The other checks pass:

- Import cycle: corrected. `cmdtree` already imports `config` at [tree.go:19](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cmdtree/tree.go:19), while production `pkg/config` does not import `cmdtree`; `ValueType = config.ValueType` alias-back is viable and methods like `Placeholder()` continue to work through the alias.
- Fields-only: corrected. `SetPath` really keys replace behavior on `children == nil` at [ast_edit.go:196](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast_edit.go:196), and v2 bans child-map changes at [plan.md:218](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:218).
- `temporal`/`exact`: corrected. `exact` is compiled in `parseCoSTransmitRate` via both trailing keys and child nodes at [compiler_class_of_service.go:498](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/compiler_class_of_service.go:498) and [compiler_class_of_service.go:507](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/compiler_class_of_service.go:507). `buffer-size` reads only `nodeVal(child)` at [compiler_class_of_service.go:239](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/compiler_class_of_service.go:239), so dropping `temporal` is right.
- Frontend-boundary tests: PR-1 step 6 is correct: it requires `cli.completeConfigWithDesc` and gRPC `completeConfigPairs`, matching real production boundaries at [completion.go:148](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cli/completion.go:148) and [server_cluster.go:568](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/grpcapi/server_cluster.go:568).

Fix the walker contract table for `multi && children == nil` value tails/ranges, and this likely moves to **PLAN-READY**.
