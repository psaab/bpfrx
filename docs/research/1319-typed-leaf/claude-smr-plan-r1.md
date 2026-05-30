# Claude SMR plan-review r1 — #1319 typed-leaf rollout

**Reviewer:** Claude (domain SMR + SW design). Hostile pass.
**Plan under review:** plan.md v1 @ afdd4b7e9.
**Verdict:** PLAN-NEEDS-MAJOR — direction (Option A) is right; three plan
statements are factually wrong and must be corrected before it is ready.
Converges with Codex (PLAN-NEEDS-MAJOR), diverges from AGY's PLAN-READY
on exactly the three concrete defects below.

## Verified-correct in the plan

- §2.1/§2.2 dual-tree + symptom-1-still-open: independently confirmed.
  `pkg/cli/completion.go:148` and `pkg/grpcapi/server_cluster.go:568`
  both route config-mode `set` through `config.CompleteSetPathWithValues`
  over `setSchema`; `setSchema` transmit-rate (`ast.go:1165`) has no
  `valueHint`/`placeholder`; the cmdtree completion test
  (`tree_test.go:132`) calls a non-production path. Symptom 1 is open.
- Option A is the correct architecture: completion path == validation
  path == `setSchema`. AGY confirms adding non-structural *fields* to
  `schemaNode` has zero SetPath grouping impact (`ast_edit.go` reads only
  `args`/`children`/`compoundKey`/`multi`).

## Defects (must fix to reach PLAN-READY)

### D1 (HIGH) — Import-cycle claim is false. [confirms Codex #1]
Plan §5 says "Type definitions (`ValueType`, `LeafValidator`) already
live in/near `pkg/config`". Verified false: `type ValueType int` is in
`pkg/cmdtree/tree.go:35`, and `pkg/cmdtree` already imports `pkg/config`
(`tree.go:19`). `pkg/config` cannot reference `cmdtree.ValueType` without
a cycle. **Fix:** PR 1 must move `ValueType` + constants + `Placeholder()`
into `pkg/config` (validators already live there); `cmdtree` aliases them
back (`type ValueType = config.ValueType`) for its operational leaves.
This is a clean, mechanical move — but it MUST be an explicit PR-1 step,
not hand-waved.

### D2 (HIGH) — "re-home schedulers" silently changes SetPath shape. [confirms Codex #3]
Plan §6 PR-1 step 2 says "populate the schedulers leaves in setSchema".
The cmdtree overlay gives `transmit-rate` a child `exact` and
`buffer-size` a child `temporal`. `setSchema` today has
`"buffer-size": {args:1, children:nil}` (`ast.go:1169`). SetPath's
replace-vs-container decision keys on `children==nil`
(`ast_edit.go:196`). Adding `children` flips `buffer-size` from
replace-like to container-like → real grouping regression. **Fix:** PR 1
adds *only* the four typed-metadata fields to existing `schemaNode`
entries; it must NOT add/alter `children`. `transmit-rate exact` already
has its child in setSchema (`ast.go:1166`); `buffer-size temporal` must
NOT be added (see D3). A SetPath golden test must assert grouping is
byte-identical pre/post PR 1.

### D3 (HIGH) — compiled-leaf-only invariant is self-contradicted by the migration source. [confirms Codex #2]
The plan elevates "type only compiled leaves" to an invariant (§7) but
the cmdtree overlay it migrates contains `buffer-size temporal`
(`tree.go:1053`) which the compiler never consumes
(`compiler_class_of_service.go` buffer-size case only reads the value).
**Fix:** PR 1 explicitly drops `temporal` (do not carry it into
setSchema). The `exact` modifier IS compiled (transmit-rate exact path
exists), so it stays. The plan must state, per modifier, compiled-or-not.

### D4 (MED) — generic walker contract is hand-waved. [confirms Codex #4]
"Trivial recursion" understates it. The walker must handle: `args>0`
key consumption, hierarchical-vs-flat AST shapes, `compoundKey`,
`midKeyword`/`midKeywordAt`, `multi` siblings, modifier-only lines
(`transmit-rate exact` with no rate must still fail), and `wildcard`
instance names. AGY sketched a recursion but it does NOT handle
`compoundKey`/`midKeyword`/`args>1` and assumes `len(Keys)>=1+args`
distinguishes shapes — incomplete for `from-zone X to-zone Y`. **Fix:**
PR 1 must specify the walker contract as a table (schema feature → AST
match rule) and port every special case that `walkSchedulers` +
`CompleteSetPathWithValues` already encode, proven by the existing
schema_validate tests passing unchanged.

### D5 (MED) — acceptance test must hit the production boundary. [confirms Codex #5]
Plan §9 proposes testing via `CompleteSetPathWithValues`. That is the
shared helper but the regression that opened the issue is at the frontend
boundary. **Fix:** add tests on `cli.completeConfigWithDesc` AND
`grpcapi` `completeConfigPairs`, including trailing-space
(`...transmit-rate ` → value slot) so the same class of "tested the wrong
path" bug (§2.2) cannot recur.

## Design notes (non-blocking)

- Option A's doctrine change is the right call. The honest framing:
  `cmdtree` = operational-tree SSOT; `setSchema` = config-grammar SSOT;
  shared `ValueType`/validators in `pkg/config`. CLAUDE.md +
  `pkg/cmdtree/README.md` line ~3 ("single source of truth for every CLI
  command tree") must be amended, not silently contradicted.
- Retire `cmdtree.ConfigClassOfServiceSchedulers` in PR 1 (AGY agrees) —
  leaving it dead-but-tested perpetuates the false-coverage trap.
- Per-subsystem PRs: keep the Phase-3a chassis range corrections from the
  killed plan (cluster-id 0..15, heartbeat 1000..2000 or documented
  xpf-divergent, priority 1..254, etc.) — that range research is still
  valid and should be cited, not re-derived.

## Bottom line

Same direction as both other reviewers. Promote to PLAN-READY once the
plan doc: (D1) moves `ValueType` to `pkg/config`; (D2) restricts PR 1 to
adding fields only + SetPath golden test; (D3) drops `temporal` and lists
modifier compiled-status; (D4) specifies the walker contract as a feature
table porting all existing special cases; (D5) tests at the frontend
boundary. These are doc edits, not design changes — Option A stands.
