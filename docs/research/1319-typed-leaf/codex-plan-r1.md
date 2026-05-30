OpenAI Codex v0.133.0
--------
workdir: /home/ps/git/bpfrx/.claude/worktrees/1319-research
model: gpt-5.5
provider: openai
approval: never
sandbox: read-only
reasoning effort: xhigh
reasoning summaries: none
session id: 019e7709-7b80-7160-a145-967daf8e2a82
--------
user
You are a hostile plan reviewer (expert in HPC networking, OS internals, data structures, JIT, CPU design, networking protocols, and Junos config semantics). Review this plan ADVERSARIALLY. Do NOT rubber-stamp. Fail the plan if the architecture is wrong. Every finding MUST cite a quoted line from the plan or from the code paths it references. Do NOT issue PLAN-KILL without a verified counter-example.

This is RESEARCH ONLY (no code will be written from this; the deliverable is a converged plan). Issue #1319 wants a typed leaf-value schema driving BOTH CLI `?` completion and commit-check validation, matching Junos vSRX.

Plan to review: docs/research/1319-typed-leaf/plan.md (on branch research/1319-typed-leaf).

KEY CONTEXT you must verify against the real code (read the files):
- PR #1320 already merged Phase 1 (cmdtree.Node typed-leaf fields + pkg/config/schema_validators.go) + Phase 2 (schedulers). Phase 3a (chassis cluster) was PLAN-KILLED.
- pkg/config/ast.go has `setSchema` (~324 nodes, ~539 args-bearing leaves). pkg/cli/completion.go:142-158 and pkg/grpcapi/server_cluster.go:563-578 route config-mode set/delete/show/edit completion through config.CompleteSetPathWithValues over setSchema — NOT through cmdtree typed leaves.
- pkg/cmdtree/schema_validate.go SchemaValidate early-returns unless class-of-service exists and uses a hand-rolled 2-deep walkSchedulers.

CRITICAL CLAIM TO STRESS-TEST (plan §2.2): "Symptom 1 (`?` completion) is effectively STILL OPEN on master through the production config-mode set path" because setSchema's transmit-rate node (ast.go:1164-1167) has no valueHint/placeholder, and the cmdtree typed-leaf completion (tree_test.go:130) is tested via a path the live CLI does not use for `set`. Verify or refute this by reading the code.

ALSO STRESS-TEST: Option A (annotate setSchema) vs Option B (cmdtree-as-real-SSOT) vs Option C (bridge). Is Option A's claim — that completion path == validation path under setSchema — correct? Does adding fields to schemaNode risk changing SetPath flat-set token grouping (the parser depends on setSchema)? Is the migration ordering / "compiled-leaf-only" invariant sound?

Verdict: PLAN-READY | PLAN-NEEDS-MAJOR | PLAN-KILL with quoted-line evidence per finding.

codex
I’ll review this as a code-grounded plan audit. I’m going to read the plan and the referenced production paths first, then verify the key claims against the current checkout before issuing a verdict.
exec
/bin/bash -lc "rg --files | rg '("'^docs/research/1319-typed-leaf/plan'"\\.md"'$|''^pkg/config/ast'"\\.go"'$|''^pkg/cli/completion'"\\.go"'$|''^pkg/grpcapi/server_cluster'"\\.go"'$|''^pkg/cmdtree/schema_validate'"\\.go"'$|''^pkg/cmdtree/tree_test'"\\.go"'$|''^pkg/config/schema_validators'"\\.go"'$)'"'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
docs/research/1319-typed-leaf/plan.md
pkg/cmdtree/tree_test.go
pkg/cmdtree/schema_validate.go
pkg/grpcapi/server_cluster.go
pkg/cli/completion.go
pkg/config/schema_validators.go
pkg/config/ast.go

exec
/bin/bash -lc 'pwd && git status --short && git branch --show-current && git rev-parse HEAD' in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
/home/ps/git/bpfrx/.claude/worktrees/1319-research
research/1319-typed-leaf
afdd4b7e96cba13617337bb8869ccdab10b4888b

codex
The checkout is already on `research/1319-typed-leaf` at `afdd4b7e`. I’ve confirmed the plan and all referenced code paths exist; next I’m pulling exact line evidence for the production completion, schema, and validation paths.
exec
/bin/bash -lc "nl -ba docs/research/1319-typed-leaf/plan.md | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
     1	# #1319 — Typed leaf-value schema: research plan (post Phase 1/2)
     2	
     3	**Status:** PLAN DRAFT v1 (2026-05-29) — research only, no code.
     4	**Branch:** `research/1319-typed-leaf`
     5	**Scope:** decide the architecture for continuing the typed-leaf rollout
     6	after PR #1320 (Phase 1 + schedulers Phase 2, MERGED) and the
     7	PLAN-KILLED Phase 3a (chassis cluster, `refactor/1319-typed-leaf-schema`).
     8	
     9	---
    10	
    11	## 1. Problem restatement
    12	
    13	The issue asks for a typed leaf-value schema driving BOTH:
    14	
    15	- **Symptom 1** — `?` completion shows the value type / format / examples
    16	  (`set ... transmit-rate ?` → `<rate>`, examples, `exact`, ...).
    17	- **Symptom 2** — commit-check rejects garbage typed values
    18	  (`transmit-rate asd` → error, not silent coerce-to-0).
    19	
    20	## 2. Current state of the codebase (load-bearing findings)
    21	
    22	PR #1320 merged Phase 1 + Phase 2. What actually shipped, verified by
    23	reading master:
    24	
    25	- **Phase 1 infra (DONE, solid):** `pkg/cmdtree/tree.go` `Node` carries
    26	  `ValueType`, `ValueDesc`, `ValueExamples`, `Validator`. `ValueType`
    27	  enum: `ValueAny`(default), `ValueRate`, `ValueByteSize`,
    28	  `ValueByteSizeOrPercent`, `ValuePercent`, `ValueInteger`,
    29	  `ValueEnumOf`. `Placeholder()` maps each to a `<rate>`-style token.
    30	- **Validators (DONE, reusable):** `pkg/config/schema_validators.go`
    31	  exports `ValidateRate`, `ValidateByteSize`, `ValidateByteSizeOrPercent`,
    32	  `ValidateInteger(min,max)`, `ValidateEnum([]string)`,
    33	  `ValidatePercent(min,max)`. Integer/enum/percent are generic and ready.
    34	- **Commit-check gate (DONE for schedulers only):**
    35	  `pkg/cmdtree/schema_validate.go` `SchemaValidate(tree, cfg)` is called
    36	  from `pkg/configstore/store.go:182,194` on the apply-groups-expanded
    37	  clone BEFORE compile. It currently **early-returns unless
    38	  `class-of-service` exists** (`schema_validate.go:43-46`), then only
    39	  walks `schedulers` via the hand-rolled `walkSchedulers` (2-deep).
    40	- **Typed schedulers leaves (DONE):**
    41	  `cmdtree.ConfigClassOfServiceSchedulers` types `transmit-rate`
    42	  (`ValueRate`), `priority` (`ValueEnumOf`), `buffer-size`
    43	  (`ValueByteSizeOrPercent`).
    44	
    45	### 2.1 The dual-tree reality (THE central design fact)
    46	
    47	CLAUDE.md and `pkg/cmdtree/README.md` call cmdtree "the single source of
    48	truth" for completion. **For config-mode `set`/`delete`/`show`/`edit`,
    49	this is false today.** There are two parallel trees:
    50	
    51	| Tree | Where | Role | Size |
    52	|------|-------|------|------|
    53	| `cmdtree.ConfigTopLevel` + `ConfigClassOfServiceSchedulers` | `pkg/cmdtree/tree.go` | typed-leaf overlay (schedulers + a few `system dataplane` knobs) | sparse |
    54	| `setSchema` (`schemaNode`) | `pkg/config/ast.go:401` | the **actual** structural completion + SetPath grouping tree | ~324 nodes, **~539 `args`-bearing value leaves**, 206 placeholders |
    55	
    56	The config-mode completer (`pkg/cli/completion.go:142-158`) routes
    57	`set/delete/show/edit` through `config.CompleteSetPathWithValues`, which
    58	walks **`setSchema`** and **never consults the cmdtree typed leaves**.
    59	`CompleteFromTreeWithDesc` (the function that surfaces
    60	`ValueExamples`/`Placeholder`) is reached by the cmdtree unit tests
    61	(`tree_test.go:130-151`) and by operational-mode (`run`) completion — but
    62	**not** by the live config-mode `set` value completion path.
    63	
    64	### 2.2 Consequence: Symptom 1 is effectively STILL OPEN on master
    65	
    66	`setSchema`'s schedulers entry (`ast.go:1164-1167`) is:
    67	```go
    68	"schedulers": {args: 1, multi: true, children: map[string]*schemaNode{
    69	    "transmit-rate": {args: 1, children: map[string]*schemaNode{"exact": ...}},
    70	    "priority":    {args: 1, children: nil},
    71	    "buffer-size": {args: 1, children: nil},
    72	```
    73	No `valueHint`, no `placeholder`. So `set ... transmit-rate ?` in the
    74	real CLI returns **nothing** for the value slot — the exact symptom-1
    75	the issue opened on. Phase 2 only closed symptom 2 (validation). **Any
    76	v1 reviewer claiming symptom 1 is fixed is wrong; the test that "proves"
    77	it (tree_test.go:130) exercises a code path the CLI does not use for
    78	`set`.** This must be in the acceptance criteria.
    79	
    80	### 2.3 Why Phase 3a was killed
    81	
    82	Per the #1319 issue comment (Codex task-mpnhv0ui-j30019 PLAN-NEEDS-MAJOR,
    83	AGY review-mpnhva3y-h1n07y PLAN-KILL): `walkSchedulers` is hand-rolled
    84	for a 2-deep tree and does not generalize to the 5–7-deep chassis-cluster
    85	AST; the `SchemaValidate` early-return on absent class-of-service skips
    86	all other subtrees; AST-shape sketches were wrong; and the Junos numeric
    87	ranges were wrong. Recommended split: (1) generic recursive walker first,
    88	(2) then per-subsystem typed leaves with correct ranges.
    89	
    90	## 3. Blast radius (quantified)
    91	
    92	- **~539** `args>0` value-consuming leaves in `setSchema` across ~18
    93	  top-level subtrees (`security`, `interfaces`, `routing-options`,
    94	  `policy-options`, `protocols`, `chassis`, `class-of-service`,
    95	  `firewall`, `system`, `services`, `forwarding-options`,
    96	  `routing-instances`, ...).
    97	- **3** of those are typed today (schedulers). So **~536 untyped value
    98	  leaves** remain. "Touch every leaf" = ~536-leaf churn — confirmed
    99	  infeasible as one PR; **incremental per-subsystem is mandatory** and is
   100	  what the issue's own migration plan calls for.
   101	- Most-impactful value types by frequency: integer-with-range,
   102	  enum-of-fixed-set, rate/byte-size, IP/CIDR, identifier-cross-ref
   103	  (forwarding-class, scheduler, zone names).
   104	
   105	## 4. Goals / non-goals
   106	
   107	**Goals**
   108	- A single recursive walker that validates any typed subtree (kills the
   109	  per-subtree hand-rolled walker problem).
   110	- Wire typed-leaf value completion into the **production config-mode
   111	  `set` completer** so symptom 1 is actually fixed for typed leaves.
   112	- Reconcile the dual-tree so adding a typed leaf is one edit, not two
   113	  trees kept in sync by hand.
   114	- Correct, defensible value validation per migrated subsystem.
   115	
   116	**Non-goals (defer)**
   117	- Typing all ~536 leaves in one go.
   118	- Schema-aware show/diff formatters; auto-generated config reference;
   119	  cross-cluster schema versioning (issue "out of scope").
   120	- Cross-reference validators that require compiled `cfg` (forwarding-class
   121	  must exist, etc.) — keep as a later sub-phase; today's compiler already
   122	  does some of these.
   123	
   124	## 5. Multiple path options for HOW to attach + reconcile the schema
   125	
   126	The issue proposes "extend cmdtree Node". The killed Phase 3a tried to
   127	extend the cmdtree overlay + hand-rolled walker. The real decision is how
   128	to handle the **dual tree** (§2.1). Three viable architectures:
   129	
   130	### Option A — Annotate `setSchema` directly (single tree, in pkg/config)
   131	
   132	Add `valueType ValueType`, `valueDesc string`, `valueExamples []string`,
   133	`validator LeafValidator` fields to `schemaNode` in `pkg/config/ast.go`.
   134	`CompleteSetPathWithValues` already walks `setSchema` and is the live
   135	completion path — it gains value-slot examples for free. A generic
   136	`SchemaValidate` walks the **same** `setSchema` over the AST. The cmdtree
   137	typed-leaf fields become operational/`run`-only; config-mode typed leaves
   138	live in `setSchema`.
   139	
   140	- **Pros:** one tree, the one the CLI already uses; symptom 1 fixed
   141	  inherently (completion path = validation path); generic walker is a
   142	  natural recursion over `schemaNode.children`; no cross-tree sync;
   143	  validators already in `pkg/config` (no import-cycle gymnastics).
   144	- **Cons:** contradicts the "cmdtree is SSOT" doctrine in CLAUDE.md —
   145	  config-mode typed values would live in `pkg/config`, not `pkg/cmdtree`.
   146	  Needs a doctrine-update note. cmdtree's `ConfigClassOfServiceSchedulers`
   147	  would be migrated/retired (small, 3 leaves).
   148	- **Churn:** moderate; concentrated in `pkg/config/ast.go`.
   149	
   150	### Option B — Make cmdtree the real SSOT; route `set` completion through it
   151	
   152	Build the full config-mode grammar in `cmdtree.ConfigTopLevel`
   153	(today sparse) and switch `pkg/cli/completion.go` + the gRPC completer to
   154	drive `set` completion from cmdtree instead of `setSchema`. `setSchema`
   155	is then derived from (or retired in favor of) cmdtree. Generic walker
   156	lives in cmdtree.
   157	
   158	- **Pros:** makes the doctrine true; one place to add a typed leaf.
   159	- **Cons:** **enormous** — `setSchema` is ~324 nodes with `args`,
   160	  `multi`, `midKeyword`, `compoundKey`, `valueHint`, `wildcard`
   161	  semantics that cmdtree's `Node` does not model. Rebuilding the entire
   162	  config grammar in cmdtree AND re-validating SetPath grouping (the
   163	  parser depends on `setSchema` for flat-set token grouping) is a
   164	  multi-PR rewrite with high regression risk on the parser. Out of
   165	  proportion to the issue.
   166	
   167	### Option C — Bridge: keep both trees, add a lookup from setSchema leaf → cmdtree typed node
   168	
   169	Leave both trees; at the value slot, `CompleteSetPathWithValues` and a
   170	generic `SchemaValidate` look up the consumed `path` in
   171	`cmdtree.ConfigTopLevel` to fetch `ValueType`/`Validator`/examples.
   172	
   173	- **Pros:** no migration of existing trees; cmdtree stays the typed-leaf
   174	  home (doctrine-consistent).
   175	- **Cons:** keeps **two trees in sync by hand** for every typed leaf
   176	  (the exact maintainability failure the issue wants to end); the bridge
   177	  must replicate `setSchema`'s arg/midKeyword/compoundKey path-consumption
   178	  to map a path to a cmdtree node — fragile; doubles the per-leaf edit.
   179	
   180	### Recommendation (to be tested by reviewers)
   181	
   182	**Option A.** It is the only option where the completion path and the
   183	validation path are the same tree (so symptom 1 + symptom 2 are closed
   184	together and cannot drift), the generic walker is a trivial recursion,
   185	and there is no hand-sync. The doctrine cost (config-mode typed values
   186	live in `pkg/config`, not `pkg/cmdtree`) is real but is a documentation
   187	update, and CLAUDE.md's claim is already false for config-mode `set`
   188	today (§2.1) — Option A makes the doctrine *accurate* by stating that
   189	`setSchema` is the config-grammar SSOT and cmdtree is the
   190	operational-tree SSOT, with shared `ValueType`/validator types.
   191	
   192	Type definitions (`ValueType`, `LeafValidator`) already live in/near
   193	`pkg/config`; cmdtree aliases them. Option A keeps the enum where the
   194	validators are and lets cmdtree keep aliasing for its operational leaves.
   195	
   196	## 6. Proposed plan (Option A), staged
   197	
   198	### PR 1 — Generic walker + completion wiring + reconcile (no new subsystems)
   199	
   200	1. Add typed-leaf fields to `schemaNode` (`pkg/config/ast.go`):
   201	   `valueType ValueType`, `valueDesc string`, `valueExamples []string`,
   202	   `validator LeafValidator`. Zero values = today's behavior.
   203	2. Populate the **schedulers** leaves in `setSchema` (the 3 already
   204	   typed in cmdtree) with these fields — single source for CoS now.
   205	3. `CompleteSetPathWithValues`: at the value slot, when the leaf has a
   206	   non-`ValueAny` `valueType`, surface `valueDesc` + `valueExamples` +
   207	   `placeholder` (this is the **symptom-1 fix that actually reaches the
   208	   CLI**).
   209	4. Replace `walkSchedulers`/`SchemaValidate` with a **generic recursive
   210	   `validateAST(astNode, schemaNode, path)`** that descends `setSchema`,
   211	   handles all AST shapes (flat-set `Keys=[...]` vs hierarchical
   212	   children), and invokes `validator` at typed leaves. Remove the
   213	   `class-of-service`-only early-return — fan out across all top-level
   214	   subtrees (a subtree with no typed leaves is a no-op walk).
   215	5. Move `SchemaValidate` to `pkg/config` (it now walks `setSchema`, owned
   216	   by `pkg/config`); `pkg/configstore` calls `config.SchemaValidate`.
   217	   Keep a thin `cmdtree.SchemaValidate` shim or update the one caller.
   218	6. **Parity tests:** existing `pkg/cmdtree/schema_validate_test.go` +
   219	   `pkg/config/schema_validate_test.go` cases must pass against the new
   220	   walker. Add a CLI-path test that `set ... transmit-rate ?` returns
   221	   `<rate>` + examples through `CompleteSetPathWithValues` (the gap in
   222	   §2.2). Retire/migrate `cmdtree.ConfigClassOfServiceSchedulers` (note
   223	   it in README so the doctrine is corrected).
   224	7. Docs: `pkg/cmdtree/README.md` + `pkg/config/README.md` +
   225	   `docs/config-schema.md` (new) state the corrected SSOT split and how
   226	   to add a typed leaf (one `setSchema` edit).
   227	
   228	**Acceptance for PR 1:**
   229	- `set class-of-service schedulers x transmit-rate ?` returns help with
   230	  `<rate>` + examples + `exact` **through the production CLI completer**.
   231	- `transmit-rate asd` still rejected at commit-check (no regression).
   232	- All 880+ tests pass; the parity tests pin both symptoms.
   233	
   234	### PR 2..N — per-subsystem typed leaves (incremental)
   235	
   236	Each PR types one subsystem's leaves in `setSchema` with **Junos-vSRX-
   237	correct** ranges and a fixture proving the silent-coerce gap on master.
   238	Suggested ordering by impact + clarity of Junos spec:
   239	- **chassis cluster** (re-do killed Phase 3a with corrected ranges:
   240	  cluster-id 0..15 with MAC-encoding rationale, heartbeat-interval
   241	  1000..2000 or explicit xpf-divergent range w/ rationale + the 30ms lab
   242	  caveat, heartbeat-threshold 3..8, reth-count 1..128, per-RG priority
   243	  1..254, per-RG `hold-down-interval` only if compiled). Gate per-leaf on
   244	  "is this leaf compiled today" (README invariant: do not type a leaf the
   245	  compiler ignores).
   246	- **interfaces** family inet/inet6 address CIDR validation.
   247	- **firewall** filter terms (forwarding-class cross-ref — needs `cfg`).
   248	- **system / services** numeric knobs.
   249	
   250	Each subsystem PR: types leaves + adds fixtures + updates that
   251	subsystem's doc. No walker/infra changes after PR 1.
   252	
   253	## 7. Hostile questions (answered)
   254	
   255	- **Touch every leaf (huge churn)?** No — PR 1 is infra + schedulers
   256	  re-home only; subsystems are independent incremental PRs. ~536 leaves
   257	  stay `ValueAny` and untouched until their subsystem PR.
   258	- **Consistent across local CLI / remote CLI / gRPC?** Yes under Option
   259	  A: all three config-mode completers already call
   260	  `config.CompleteSetPathWithValues` (cli) / the gRPC completer resolves

exec
/bin/bash -lc "nl -ba pkg/cli/completion.go | sed -n '120,180p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
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
   176			}
   177			return nil
   178	
   179		default:
   180			return nil

exec
/bin/bash -lc "nl -ba pkg/config/ast.go | sed -n '1130,1185p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
  1130					}},
  1131				}},
  1132			}},
  1133		}},
  1134		"class-of-service": {desc: "Class of service configuration", children: map[string]*schemaNode{
  1135			"forwarding-classes": {children: map[string]*schemaNode{
  1136				"queue": {args: 2, multi: true, children: nil},
  1137			}},
  1138			"classifiers": {children: map[string]*schemaNode{
  1139				"dscp": {args: 1, multi: true, children: map[string]*schemaNode{
  1140					"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
  1141						"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
  1142							"code-points": {args: 1, multi: true, children: nil},
  1143						}},
  1144					}},
  1145				}},
  1146				"ieee-802.1": {args: 1, multi: true, children: map[string]*schemaNode{
  1147					"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
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
  1179				"unit": {args: 1, multi: true, children: map[string]*schemaNode{
  1180					"classifiers": {children: map[string]*schemaNode{
  1181						"dscp":       {args: 1, children: nil},
  1182						"ieee-802.1": {args: 1, children: nil},
  1183					}},
  1184					"rewrite-rules": {children: map[string]*schemaNode{
  1185						"dscp": {args: 1, children: nil},

exec
/bin/bash -lc "nl -ba pkg/grpcapi/server_cluster.go | sed -n '540,595p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
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
   591			if len(words) == 1 {
   592				node := cmdtree.ConfigTopLevel[resolvedTop]
   593				if node == nil || node.Children == nil {
   594					return nil
   595				}

codex
The first pass supports the central dual-tree claim: both local CLI and gRPC route config-mode `set/delete/show/edit` through `config.CompleteSetPathWithValues`, while the `setSchema` scheduler leaves have only `args` and children. I’m now checking the internals: how `schemaNode` consumes values, how completion behaves at value slots, and how commit-check currently walks the AST.
exec
/bin/bash -lc 'rg -n "CompleteSetPathWithValues|ResolveConsumedSetPathTokens|SetPath|schemaNode|valueHint|placeholder|compoundKey|midKeyword|wildcard|args|multi" pkg/config/ast.go' in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
143:// When multiple sibling nodes share the same key prefix (e.g., path ["from-zone","untrust"]
151:		// Try multi-key match (keyword + argument pairs).
233:// Multi-key nodes consume multiple path elements at once.
257:// Handles multi-key nodes by consuming multiple path elements per node.
383:// schemaNode defines a container keyword in the Junos config hierarchy.
384:// It tells SetPath how to group flat path tokens into the correct tree structure.
385:type schemaNode struct {
386:	args         int                    // extra tokens consumed as part of this node's key
387:	children     map[string]*schemaNode // known container children
388:	wildcard     *schemaNode            // matches any keyword not in children (for dynamic names)
389:	multi        bool                   // true = multiple leaf values allowed (e.g. source-address); false = replace on set
390:	valueHint    ValueHint              // hint for dynamic value completion (when args > 0)
392:	placeholder  string                 // Junos-style placeholder (e.g., "<interface-name>")
393:	midKeyword   string                 // fixed keyword in the middle of args (e.g., "to-zone")
394:	midKeywordAt int                    // 1-based arg position where midKeyword appears (e.g., 2 for "from-zone X to-zone Y")
395:	compoundKey  bool                   // children form compound key (e.g., "family inet6" → Keys=["family","inet6"])
401:var setSchema = &schemaNode{children: map[string]*schemaNode{
402:	"groups":       {wildcard: &schemaNode{}}, // children set in init()
403:	"apply-groups": {args: 1, multi: true, children: nil},
404:	"security": {desc: "Security configuration", children: map[string]*schemaNode{
405:		"zones": {desc: "Security zones", children: map[string]*schemaNode{
406:			"security-zone": {desc: "Security zone name", args: 1, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: map[string]*schemaNode{
407:				"description": {desc: "Zone description", args: 1, placeholder: "<text>", children: nil},
410:				"screen":      {desc: "Screen profile name", args: 1, placeholder: "<screen-name>", children: nil},
411:				"host-inbound-traffic": {desc: "Host inbound traffic", children: map[string]*schemaNode{
417:		"policies": {desc: "Security policies", children: map[string]*schemaNode{
418:			"from-zone": {desc: "From zone", args: 3, valueHint: ValueHintZoneName, midKeyword: "to-zone", midKeywordAt: 2, placeholder: "<zone-name>", children: map[string]*schemaNode{
419:				"policy": {desc: "Policy name", args: 1, valueHint: ValueHintPolicyName, placeholder: "<policy-name>", children: map[string]*schemaNode{
420:					"description": {desc: "Policy description", args: 1, placeholder: "<text>", children: nil},
421:					"match": {desc: "Match criteria", children: map[string]*schemaNode{
422:						"source-address":      {desc: "Source address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
423:						"destination-address": {desc: "Destination address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
424:						"application":         {desc: "Application", args: 1, multi: true, valueHint: ValueHintPolicyApp, placeholder: "<application>", children: nil},
426:					"then": {desc: "Action", children: map[string]*schemaNode{
432:			"global": {desc: "Global policies", children: map[string]*schemaNode{
433:				"policy": {desc: "Policy name", args: 1, valueHint: ValueHintPolicyName, placeholder: "<policy-name>", children: map[string]*schemaNode{
434:					"description": {desc: "Policy description", args: 1, placeholder: "<text>", children: nil},
435:					"match": {desc: "Match criteria", children: map[string]*schemaNode{
436:						"source-address":      {desc: "Source address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
437:						"destination-address": {desc: "Destination address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
438:						"application":         {desc: "Application", args: 1, multi: true, valueHint: ValueHintPolicyApp, placeholder: "<application>", children: nil},
440:					"then": {desc: "Action", children: map[string]*schemaNode{
446:		"screen": {desc: "Screen options", children: map[string]*schemaNode{
447:			"ids-option": {desc: "Screen profile name", args: 1, valueHint: ValueHintScreenProfile, placeholder: "<screen-name>", children: map[string]*schemaNode{
449:				"tcp": {desc: "TCP screening", children: map[string]*schemaNode{
454:				"ip": {desc: "IP screening", children: map[string]*schemaNode{
459:				"limit-session": {desc: "Session limits", children: map[string]*schemaNode{
460:					"source-ip-based":      {desc: "Source IP based limit", args: 1, placeholder: "<number>", children: nil},
461:					"destination-ip-based": {desc: "Destination IP based limit", args: 1, placeholder: "<number>", children: nil},
465:		"nat": {children: map[string]*schemaNode{
466:			"source": {children: map[string]*schemaNode{
467:				"pool":               {args: 1, valueHint: ValueHintPoolName, children: nil},
469:				"rule-set": {args: 1, children: map[string]*schemaNode{
470:					"from": {children: map[string]*schemaNode{
471:						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
473:					"to": {children: map[string]*schemaNode{
474:						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
476:					"rule": {args: 1, children: map[string]*schemaNode{
477:						"match": {children: map[string]*schemaNode{
478:							"source-address":      {args: 1, multi: true, children: nil},
479:							"destination-address": {args: 1, multi: true, children: nil},
480:							"destination-port":    {args: 1, multi: true, children: nil},
481:							"application":         {args: 1, multi: true, children: nil},
483:						"then": {children: map[string]*schemaNode{
484:							"source-nat": {children: map[string]*schemaNode{
487:								"pool":      {args: 1, valueHint: ValueHintPoolName, children: nil},
493:			"destination": {children: map[string]*schemaNode{
494:				"pool": {args: 1, valueHint: ValueHintPoolName, children: nil},
495:				"rule-set": {args: 1, children: map[string]*schemaNode{
496:					"from": {children: map[string]*schemaNode{
497:						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
499:					"to": {children: map[string]*schemaNode{
500:						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
502:					"rule": {args: 1, children: map[string]*schemaNode{
503:						"match": {children: map[string]*schemaNode{
504:							"source-address":      {args: 1, multi: true, children: nil},
505:							"source-address-name": {args: 1, multi: true, children: nil},
506:							"destination-address": {args: 1, multi: true, children: nil},
507:							"destination-port":    {args: 1, multi: true, children: nil},
508:							"protocol":            {args: 1, multi: true, children: nil},
509:							"application":         {args: 1, multi: true, children: nil},
511:						"then": {children: map[string]*schemaNode{
512:							"destination-nat": {children: map[string]*schemaNode{
513:								"pool": {args: 1, valueHint: ValueHintPoolName, children: nil},
519:			"static": {children: map[string]*schemaNode{
520:				"rule-set": {args: 1, children: map[string]*schemaNode{
521:					"rule": {args: 1, children: map[string]*schemaNode{
523:						"then": {children: map[string]*schemaNode{
529:			"nat64": {children: map[string]*schemaNode{
530:				"rule-set": {args: 1, children: map[string]*schemaNode{
531:					"prefix":      {args: 1, children: nil},
532:					"source-pool": {args: 1, children: nil},
535:			"natv6v4": {children: map[string]*schemaNode{
538:			"proxy-arp": {children: map[string]*schemaNode{
539:				"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
540:					"address": {args: 1, multi: true, children: nil},
544:		"address-book": {children: map[string]*schemaNode{
545:			"global": {children: map[string]*schemaNode{
546:				"address": {args: 2, multi: true, children: nil},
547:				"address-set": {args: 1, valueHint: ValueHintAddressName, children: map[string]*schemaNode{
548:					"address":     {args: 1, multi: true, children: nil},
549:					"address-set": {args: 1, multi: true, valueHint: ValueHintAddressName, children: nil},
550:					"description": {args: 1, children: nil},
554:		"log": {children: map[string]*schemaNode{
555:			"mode":             {args: 1, children: nil},
556:			"format":           {args: 1, children: nil},
557:			"source-interface": {args: 1, valueHint: ValueHintInterfaceName, children: nil},
558:			"stream": {args: 1, valueHint: ValueHintStreamName, children: map[string]*schemaNode{
559:				"host":           {args: 1, children: nil},
560:				"port":           {args: 1, children: nil},
561:				"severity":       {args: 1, children: nil},
562:				"facility":       {args: 1, children: nil},
563:				"format":         {args: 1, children: nil},
564:				"category":       {args: 1, children: nil},
565:				"source-address": {args: 1, children: nil},
568:		"flow": {children: map[string]*schemaNode{
578:			"traceoptions": {children: map[string]*schemaNode{
579:				"file": {args: 1, children: nil},
580:				"flag": {args: 1, children: nil},
581:				"packet-filter": {args: 1, children: map[string]*schemaNode{
582:					"source-prefix":      {args: 1, children: nil},
583:					"destination-prefix": {args: 1, children: nil},
587:		"alg": {children: map[string]*schemaNode{
593:		"ike": {children: map[string]*schemaNode{
594:			"proposal": {args: 1, children: nil},
595:			"policy": {args: 1, children: map[string]*schemaNode{
596:				"mode":           {args: 1, children: nil},
597:				"proposals":      {args: 1, children: nil},
600:			"gateway": {args: 1, children: map[string]*schemaNode{
601:				"address":            {args: 1, children: nil},
602:				"local-address":      {args: 1, children: nil},
603:				"ike-policy":         {args: 1, children: nil},
604:				"external-interface": {args: 1, children: nil},
605:				"local-certificate":  {args: 1, children: nil},
606:				"version":            {args: 1, children: nil},
608:				"nat-traversal":      {args: 1, children: nil},
609:				"dead-peer-detection": {children: map[string]*schemaNode{
613:					"interval":          {args: 1, children: nil},
614:					"threshold":         {args: 1, children: nil},
621:		"ipsec": {children: map[string]*schemaNode{
622:			"proposal": {args: 1, children: nil},
623:			"policy": {args: 1, children: map[string]*schemaNode{
625:				"proposals":               {args: 1, children: nil},
627:			"gateway": {args: 1, children: map[string]*schemaNode{
628:				"address":            {args: 1, children: nil},
629:				"local-address":      {args: 1, children: nil},
630:				"ike-policy":         {args: 1, children: nil},
631:				"external-interface": {args: 1, children: nil},
632:				"local-certificate":  {args: 1, children: nil},
633:				"version":            {args: 1, children: nil},
635:				"nat-traversal":      {args: 1, children: nil},
636:				"dead-peer-detection": {children: map[string]*schemaNode{
640:					"interval":          {args: 1, children: nil},
641:					"threshold":         {args: 1, children: nil},
647:			"vpn": {args: 1, children: map[string]*schemaNode{
648:				"bind-interface":    {args: 1, children: nil},
649:				"df-bit":            {args: 1, children: nil},
650:				"establish-tunnels": {args: 1, children: nil},
651:				"local-identity":    {args: 1, children: nil},
652:				"remote-identity":   {args: 1, children: nil},
653:				"pre-shared-key":    {args: 1, children: nil},
654:				"local-address":     {args: 1, children: nil},
655:				"traffic-selector": {args: 1, children: map[string]*schemaNode{
656:					"local-ip":  {args: 1, children: nil},
657:					"remote-ip": {args: 1, children: nil},
659:				"ike": {children: map[string]*schemaNode{
660:					"gateway":      {args: 1, children: nil},
661:					"ipsec-policy": {args: 1, children: nil},
665:		"dynamic-address": {children: map[string]*schemaNode{
666:			"feed-server": {args: 1, children: map[string]*schemaNode{
667:				"url":             {args: 1, children: nil},
668:				"hostname":        {args: 1, children: nil},
669:				"update-interval": {args: 1, children: nil},
670:				"hold-interval":   {args: 1, children: nil},
671:				"feed-name": {args: 1, children: map[string]*schemaNode{
672:					"path": {args: 1, children: nil},
675:			"address-name": {args: 1, children: map[string]*schemaNode{
676:				"profile": {children: map[string]*schemaNode{
677:					"feed-name": {args: 1, children: nil},
681:		"ssh-known-hosts": {children: map[string]*schemaNode{
682:			"host": {args: 1, children: nil},
684:		"policy-stats": {children: map[string]*schemaNode{
685:			"system-wide": {args: 1, children: nil},
687:		"pre-id-default-policy": {children: map[string]*schemaNode{
688:			"then": {children: map[string]*schemaNode{
689:				"log": {children: map[string]*schemaNode{
696:	"interfaces": {desc: "Interface configuration", wildcard: &schemaNode{valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
697:		"description":           {desc: "Text description of interface", args: 1, children: nil},
698:		"mtu":                   {desc: "Maximum transmit packet size", args: 1, children: nil},
699:		"speed":                 {desc: "Link speed", args: 1, children: nil},
700:		"duplex":                {desc: "Link duplex mode", args: 1, children: nil},
701:		"bandwidth":             {desc: "Interface bandwidth", args: 1, children: nil},
705:		"encapsulation":         {desc: "Physical link-layer encapsulation", args: 1, children: nil},
706:		"gigether-options": {desc: "Gigabit Ethernet interface options", children: map[string]*schemaNode{
707:			"redundant-parent": {desc: "Parent of this redundant interface", args: 1, children: nil},
708:			"802.3ad":          {desc: "Link aggregation group", args: 1, children: nil},
710:		"aggregated-ether-options": {desc: "Aggregated Ethernet interface options", children: map[string]*schemaNode{
711:			"lacp": {desc: "LACP parameters", children: map[string]*schemaNode{
714:				"periodic": {desc: "LACP timer period", args: 1, children: nil},
716:			"link-speed":    {desc: "Member link speed", args: 1, children: nil},
717:			"minimum-links": {desc: "Minimum active member links", args: 1, children: nil},
719:		"redundant-ether-options": {desc: "Redundant Ethernet interface options", children: map[string]*schemaNode{
720:			"redundancy-group": {desc: "Redundancy group for this RETH", args: 1, children: nil},
722:		"fabric-options": {desc: "Fabric interface options", children: map[string]*schemaNode{
725:		"tunnel": {desc: "Tunnel parameters", children: map[string]*schemaNode{
726:			"source":          {desc: "Tunnel source address", args: 1, children: nil},
727:			"destination":     {desc: "Tunnel destination address", args: 1, children: nil},
728:			"mode":            {desc: "Tunnel mode", args: 1, children: nil},
729:			"key":             {desc: "Tunnel key", args: 1, children: nil},
730:			"ttl":             {desc: "Time to live", args: 1, children: nil},
731:			"keepalive":       {desc: "Keepalive interval", args: 1, children: nil},
732:			"keepalive-retry": {desc: "Keepalive retry count", args: 1, children: nil},
733:			"routing-instance": {desc: "Routing instance", children: map[string]*schemaNode{
734:				"destination": {desc: "Destination routing instance", args: 1, children: nil},
737:		"unit": {desc: "Logical unit number", args: 1, valueHint: ValueHintUnitNumber, placeholder: "<unit-number>", children: map[string]*schemaNode{
738:			"description":    {desc: "Text description", args: 1, placeholder: "<text>", children: nil},
740:			"vlan-id":        {desc: "VLAN ID", args: 1, placeholder: "<number>", children: nil},
741:			"inner-vlan-id":  {desc: "Inner VLAN ID", args: 1, placeholder: "<number>", children: nil},
742:			"tunnel": {desc: "Tunnel parameters", children: map[string]*schemaNode{
743:				"source":          {desc: "Tunnel source address", args: 1, placeholder: "<address>", children: nil},
744:				"destination":     {desc: "Tunnel destination address", args: 1, placeholder: "<address>", children: nil},
745:				"mode":            {desc: "Tunnel mode", args: 1, placeholder: "<mode>", children: nil},
746:				"key":             {desc: "Tunnel key", args: 1, placeholder: "<key>", children: nil},
747:				"ttl":             {desc: "Time to live", args: 1, placeholder: "<number>", children: nil},
748:				"keepalive":       {desc: "Keepalive interval", args: 1, placeholder: "<seconds>", children: nil},
749:				"keepalive-retry": {desc: "Keepalive retry count", args: 1, placeholder: "<number>", children: nil},
750:				"routing-instance": {desc: "Routing instance", children: map[string]*schemaNode{
751:					"destination": {desc: "Destination routing instance", args: 1, placeholder: "<name>", children: nil},
754:			"family": {desc: "Protocol family", compoundKey: true, children: map[string]*schemaNode{
755:				"inet": {desc: "IPv4 protocol", children: map[string]*schemaNode{
756:					"mtu": {desc: "Maximum transmit packet size", args: 1, placeholder: "<size>", children: nil},
757:					"address": {desc: "IPv4 address", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
761:					"dhcp": {desc: "DHCP client", children: map[string]*schemaNode{
762:						"lease-time":              {desc: "Lease time", args: 1, placeholder: "<seconds>", children: nil},
763:						"retransmission-attempt":  {desc: "Retransmission attempts", args: 1, placeholder: "<number>", children: nil},
764:						"retransmission-interval": {desc: "Retransmission interval", args: 1, placeholder: "<seconds>", children: nil},
767:					"sampling": {desc: "Traffic sampling", children: map[string]*schemaNode{
771:					"filter": {desc: "Firewall filter", children: map[string]*schemaNode{
772:						"input":  {desc: "Input filter", args: 1, placeholder: "<filter-name>", children: nil},
773:						"output": {desc: "Output filter", args: 1, placeholder: "<filter-name>", children: nil},
776:				"inet6": {desc: "IPv6 protocol", children: map[string]*schemaNode{
777:					"mtu":         {desc: "Maximum transmit packet size", args: 1, placeholder: "<size>", children: nil},
779:					"address": {desc: "IPv6 address", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
783:					"sampling": {desc: "Traffic sampling", children: map[string]*schemaNode{
787:					"filter": {desc: "Firewall filter", children: map[string]*schemaNode{
788:						"input":  {desc: "Input filter", args: 1, placeholder: "<filter-name>", children: nil},
789:						"output": {desc: "Output filter", args: 1, placeholder: "<filter-name>", children: nil},
791:					"dhcpv6-client": {desc: "DHCPv6 client", children: map[string]*schemaNode{
792:						"client-type":    {desc: "Client type", args: 1, placeholder: "<type>", children: nil},
793:						"client-ia-type": {desc: "Client IA type", args: 1, placeholder: "<type>", children: nil},
794:						"prefix-delegating": {desc: "Prefix delegation", children: map[string]*schemaNode{
795:							"preferred-prefix-length": {desc: "Preferred prefix length", args: 1, placeholder: "<length>", children: nil},
796:							"sub-prefix-length":       {desc: "Sub-prefix length", args: 1, placeholder: "<length>", children: nil},
798:						"client-identifier": {desc: "Client identifier", children: map[string]*schemaNode{
799:							"duid-type": {desc: "DUID type", args: 1, placeholder: "<type>", children: nil},
801:						"req-option": {desc: "Request option", args: 1, placeholder: "<option>", children: nil},
802:						"update-router-advertisement": {desc: "Update router advertisement", children: map[string]*schemaNode{
803:							"interface": {desc: "Interface", args: 1, placeholder: "<interface>", children: nil},
810:	"applications": {desc: "Applications", children: map[string]*schemaNode{
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
823:	"routing-options": {desc: "Routing options", children: map[string]*schemaNode{
824:		"static": {desc: "Static routes", children: map[string]*schemaNode{
825:			"route": {desc: "Static route", args: 1, placeholder: "<destination>", children: nil},
827:		"rib": {desc: "Routing information base", args: 1, placeholder: "<rib-name>", children: map[string]*schemaNode{
828:			"static": {desc: "Static routes", children: map[string]*schemaNode{
829:				"route": {desc: "Static route", args: 1, placeholder: "<destination>", children: nil},
832:		"autonomous-system": {desc: "Autonomous system number", args: 1, placeholder: "<as-number>", children: nil},
833:		"forwarding-table": {desc: "Forwarding table", children: map[string]*schemaNode{
834:			"export": {desc: "Export policy", args: 1, multi: true, placeholder: "<policy>", children: nil},
836:		"rib-groups": {desc: "RIB groups", wildcard: &schemaNode{children: map[string]*schemaNode{
839:		"interface-routes": {desc: "Interface routes", children: map[string]*schemaNode{
840:			"rib-group": {desc: "RIB group", children: map[string]*schemaNode{
841:				"inet":  {desc: "IPv4 RIB group", args: 1, placeholder: "<group-name>", children: nil},
842:				"inet6": {desc: "IPv6 RIB group", args: 1, placeholder: "<group-name>", children: nil},
845:		"generate": {desc: "Generated routes", children: map[string]*schemaNode{
846:			"route": {desc: "Generated route", args: 1, placeholder: "<destination>", children: map[string]*schemaNode{
847:				"policy":  {desc: "Policy", args: 1, placeholder: "<policy>", children: nil},
852:	"snmp": {desc: "SNMP configuration", children: map[string]*schemaNode{
853:		"community": {desc: "SNMP community", args: 1, placeholder: "<community-name>", children: map[string]*schemaNode{
854:			"authorization": {desc: "Authorization level", args: 1, placeholder: "<level>", children: nil},
856:		"trap-group": {desc: "Trap group", args: 1, placeholder: "<group-name>", children: nil},
857:		"v3": {desc: "SNMPv3", children: map[string]*schemaNode{
858:			"usm": {desc: "USM", children: map[string]*schemaNode{
859:				"local-engine": {desc: "Local engine", children: map[string]*schemaNode{
860:					"user": {desc: "User name", args: 1, placeholder: "<user-name>", children: map[string]*schemaNode{
861:						"authentication-md5":    {desc: "MD5 authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
862:						"authentication-sha":    {desc: "SHA authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
863:						"authentication-sha256": {desc: "SHA256 authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
864:						"privacy-des":           {desc: "DES privacy", children: map[string]*schemaNode{"privacy-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
865:						"privacy-aes128":        {desc: "AES128 privacy", children: map[string]*schemaNode{"privacy-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
871:	"policy-options": {desc: "Policy options", children: map[string]*schemaNode{
872:		"prefix-list": {desc: "Prefix list", args: 1, placeholder: "<name>", children: nil},
873:		"community": {desc: "Community", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
874:			"members": {desc: "Community members", args: 1, multi: true, placeholder: "<community>", children: nil},
876:		"as-path": {desc: "AS path", args: 2, multi: true, placeholder: "<name>", children: nil},
877:		"policy-statement": {desc: "Policy statement", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
878:			"term": {desc: "Term name", args: 1, placeholder: "<term-name>", children: map[string]*schemaNode{
879:				"from": {desc: "Match condition", children: map[string]*schemaNode{
880:					"protocol":     {desc: "Protocol", args: 1, placeholder: "<protocol>", children: nil},
881:					"prefix-list":  {desc: "Prefix list", args: 1, placeholder: "<list-name>", children: nil},
882:					"route-filter": {desc: "Route filter", args: 2, placeholder: "<prefix>", children: nil},
883:					"community":    {desc: "Community", args: 1, placeholder: "<community>", children: nil},
884:					"as-path":      {desc: "AS path", args: 1, placeholder: "<name>", children: nil},
886:				"then": {desc: "Action", children: map[string]*schemaNode{
889:					"next-hop":         {desc: "Next hop", args: 1, placeholder: "<address>", children: nil},
890:					"load-balance":     {desc: "Load balance", args: 1, placeholder: "<policy>", children: nil},
891:					"local-preference": {desc: "Local preference", args: 1, placeholder: "<value>", children: nil},
892:					"metric":           {desc: "Metric", args: 1, placeholder: "<value>", children: nil},
893:					"metric-type":      {desc: "Metric type", args: 1, placeholder: "<type>", children: nil},
894:					"community":        {desc: "Community", args: 1, placeholder: "<community>", children: nil},
895:					"origin":           {desc: "Origin", args: 1, placeholder: "<origin>", children: nil},
901:	"protocols": {desc: "Protocols configuration", children: map[string]*schemaNode{
902:		"ospf": {desc: "OSPF configuration", children: map[string]*schemaNode{
903:			"router-id":           {desc: "Router ID", args: 1, placeholder: "<address>", children: nil},
904:			"reference-bandwidth": {desc: "Reference bandwidth", args: 1, placeholder: "<bandwidth>", children: nil},
906:			"export":              {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
907:			"area": {desc: "OSPF area", args: 1, placeholder: "<area-id>", children: map[string]*schemaNode{
908:				"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
911:					"interface-type": {desc: "Interface type", args: 1, placeholder: "<type>", children: nil},
912:					"cost":           {desc: "Interface cost", args: 1, placeholder: "<cost>", children: nil},
913:					"authentication": {desc: "Authentication", children: map[string]*schemaNode{
914:						"md5": {desc: "MD5 authentication", args: 1, placeholder: "<key-id>", children: map[string]*schemaNode{
915:							"key": {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
917:						"simple-password": {desc: "Simple password", args: 1, placeholder: "<password>", children: nil},
919:					"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
920:						"minimum-interval": {desc: "Minimum interval", args: 1, placeholder: "<milliseconds>", children: nil},
921:						"multiplier":       {desc: "Multiplier", args: 1, placeholder: "<multiplier>", children: nil},
924:				"area-type": {desc: "Area type", children: map[string]*schemaNode{
925:					"stub": {desc: "Stub area", children: map[string]*schemaNode{
928:					"nssa": {desc: "NSSA area", children: map[string]*schemaNode{
932:				"virtual-link": {desc: "Virtual link", args: 1, placeholder: "<router-id>", children: map[string]*schemaNode{
933:					"transit-area": {desc: "Transit area", args: 1, placeholder: "<area-id>", children: nil},
937:		"ospf3": {desc: "OSPFv3 configuration", children: map[string]*schemaNode{
938:			"router-id": {desc: "Router ID", args: 1, placeholder: "<address>", children: nil},
939:			"export":    {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
940:			"area": {desc: "OSPFv3 area", args: 1, placeholder: "<area-id>", children: map[string]*schemaNode{
941:				"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
943:					"cost":    {desc: "Interface cost", args: 1, placeholder: "<cost>", children: nil},
947:		"bgp": {desc: "BGP configuration", children: map[string]*schemaNode{
948:			"local-as":         {desc: "Local AS number", args: 1, placeholder: "<as-number>", children: nil},
949:			"router-id":        {desc: "Router ID", args: 1, placeholder: "<address>", children: nil},
950:			"cluster-id":       {desc: "Cluster ID", args: 1, placeholder: "<id>", children: nil},
953:			"multipath": {desc: "Multipath", children: map[string]*schemaNode{
954:				"multiple-as": {desc: "Multiple AS", children: nil},
956:			"damping": {desc: "Route damping", children: map[string]*schemaNode{
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
973:					"inet": {desc: "IPv4", children: map[string]*schemaNode{
974:						"unicast": {desc: "Unicast", children: map[string]*schemaNode{
975:							"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
976:								"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
980:					"inet6": {desc: "IPv6", children: map[string]*schemaNode{
981:						"unicast": {desc: "Unicast", children: map[string]*schemaNode{
982:							"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
983:								"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
988:				"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
989:					"minimum-interval": {desc: "Minimum interval", args: 1, placeholder: "<milliseconds>", children: nil},
990:					"multiplier":       {desc: "Multiplier", args: 1, placeholder: "<multiplier>", children: nil},
992:				"neighbor": {desc: "BGP neighbor", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
993:					"description":            {desc: "Description", args: 1, placeholder: "<text>", children: nil},
994:					"peer-as":                {desc: "Peer AS number", args: 1, placeholder: "<as-number>", children: nil},
995:					"multihop":               {desc: "Multihop TTL", args: 1, placeholder: "<ttl>", children: nil},
996:					"authentication-key":     {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
999:					"loops":                  {desc: "Loops", args: 1, placeholder: "<count>", children: nil},
1001:					"family": {desc: "Address family", compoundKey: true, children: map[string]*schemaNode{
1002:						"inet": {desc: "IPv4", children: map[string]*schemaNode{
1003:							"unicast": {desc: "Unicast", children: map[string]*schemaNode{
1004:								"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
1005:									"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
1009:						"inet6": {desc: "IPv6", children: map[string]*schemaNode{
1010:							"unicast": {desc: "Unicast", children: map[string]*schemaNode{
1011:								"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
1012:									"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
1017:					"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
1018:						"minimum-interval": {desc: "Minimum interval", args: 1, placeholder: "<milliseconds>", children: nil},
1019:						"multiplier":       {desc: "Multiplier", args: 1, placeholder: "<multiplier>", children: nil},
1024:		"rip": {desc: "RIP configuration", children: map[string]*schemaNode{
1025:			"group":               {desc: "Group", args: 1, placeholder: "<group-name>", children: nil},
1026:			"neighbor":            {desc: "Neighbor", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: nil},
1027:			"passive-interface":   {desc: "Passive interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: nil},
1028:			"redistribute":        {desc: "Redistribute", args: 1, placeholder: "<protocol>", children: nil},
1029:			"authentication-key":  {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
1030:			"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>", children: nil},
1032:		"isis": {desc: "IS-IS configuration", children: map[string]*schemaNode{
1033:			"net":     {desc: "NET address", args: 1, placeholder: "<net-address>", children: nil},
1034:			"level":   {desc: "Level", args: 1, placeholder: "<level>", children: nil},
1035:			"is-type": {desc: "IS type", args: 1, placeholder: "<type>", children: nil},
1036:			"export":  {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
1037:			"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
1038:				"level":               {desc: "Level", args: 1, placeholder: "<level>", children: nil},
1040:				"metric":              {desc: "Metric", args: 1, placeholder: "<value>", children: nil},
1041:				"authentication-key":  {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
1042:				"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>", children: nil},
1043:				"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
1044:					"minimum-interval": {desc: "Minimum interval", args: 1, placeholder: "<milliseconds>", children: nil},
1045:					"multiplier":       {desc: "Multiplier", args: 1, placeholder: "<multiplier>", children: nil},
1048:			"authentication-key":  {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
1049:			"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>", children: nil},
1053:		"router-advertisement": {desc: "Router advertisement", children: map[string]*schemaNode{
1054:			"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
1055:				"prefix":     {desc: "Prefix", args: 1, placeholder: "<prefix>", children: nil}, // prefix <prefix/len>
1056:				"preference": {desc: "Preference", args: 1, placeholder: "<preference>", children: nil},
1057:				"nat-prefix": {desc: "NAT prefix", args: 1, placeholder: "<prefix>", children: map[string]*schemaNode{
1058:					"lifetime": {desc: "Lifetime", args: 1, placeholder: "<seconds>", children: nil},
1060:				"nat64prefix": {desc: "NAT64 prefix", args: 1, placeholder: "<prefix>", children: map[string]*schemaNode{
1061:					"lifetime": {desc: "Lifetime", args: 1, placeholder: "<seconds>", children: nil},
1065:		"lldp": {desc: "LLDP configuration", children: map[string]*schemaNode{
1066:			"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
1069:			"transmit-interval": {desc: "Transmit interval", args: 1, placeholder: "<seconds>", children: nil},
1070:			"hold-multiplier":   {desc: "Hold multiplier", args: 1, placeholder: "<multiplier>", children: nil},
1074:	"event-options": {children: map[string]*schemaNode{
1075:		"policy": {args: 1, children: map[string]*schemaNode{
1077:			"within": {args: 1, children: map[string]*schemaNode{
1081:			"then": {children: map[string]*schemaNode{
1082:				"change-configuration": {children: map[string]*schemaNode{
1088:	"chassis": {children: map[string]*schemaNode{
1089:		"cluster": {children: map[string]*schemaNode{
1090:			"cluster-id":            {args: 1, children: nil},
1091:			"node":                  {args: 1, children: nil},
1092:			"reth-count":            {args: 1, children: nil},
1093:			"heartbeat-interval":    {args: 1, children: nil},
1094:			"heartbeat-threshold":   {args: 1, children: nil},
1096:			"control-ports": {children: map[string]*schemaNode{
1097:				"fpc": {args: 1, children: map[string]*schemaNode{
1098:					"port": {args: 1, children: nil},
1101:			"control-interface":             {args: 1, children: nil},
1102:			"peer-address":                  {args: 1, children: nil},
1103:			"fabric-interface":              {args: 1, children: nil},
1104:			"fabric-peer-address":           {args: 1, children: nil},
1108:			"reth-advertise-interval":       {args: 1, children: nil},
1110:			"peer-fencing":                  {args: 1, children: nil},
1111:			"takeover-hold-time":            {args: 1, children: nil},
1115:			"redundancy-group": {args: 1, children: map[string]*schemaNode{
1116:				"node": {args: 1, children: map[string]*schemaNode{
1117:					"priority": {args: 1, children: nil},
1119:				"gratuitous-arp-count": {args: 1, children: nil},
1122:				"ip-monitoring": {children: map[string]*schemaNode{
1123:					"global-weight":    {args: 1, children: nil},
1124:					"global-threshold": {args: 1, children: nil},
1125:					"family": {compoundKey: true, children: map[string]*schemaNode{
1126:						"inet": {wildcard: &schemaNode{children: map[string]*schemaNode{
1127:							"weight": {args: 1, children: nil},
1134:	"class-of-service": {desc: "Class of service configuration", children: map[string]*schemaNode{
1135:		"forwarding-classes": {children: map[string]*schemaNode{
1136:			"queue": {args: 2, multi: true, children: nil},
1138:		"classifiers": {children: map[string]*schemaNode{
1139:			"dscp": {args: 1, multi: true, children: map[string]*schemaNode{
1140:				"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
1141:					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
1142:						"code-points": {args: 1, multi: true, children: nil},
1146:			"ieee-802.1": {args: 1, multi: true, children: map[string]*schemaNode{
1147:				"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
1148:					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
1149:						"code-points": {args: 1, multi: true, children: nil},
1154:		"rewrite-rules": {children: map[string]*schemaNode{
1155:			"dscp": {args: 1, multi: true, children: map[string]*schemaNode{
1156:				"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
1157:					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
1158:						"code-point":  {args: 1, children: nil},
1159:						"code-points": {args: 1, multi: true, children: nil},
1164:		"schedulers": {args: 1, multi: true, children: map[string]*schemaNode{
1165:			"transmit-rate": {args: 1, children: map[string]*schemaNode{
1168:			"priority":               {args: 1, children: nil},
1169:			"buffer-size":            {args: 1, children: nil},
1173:		"scheduler-maps": {args: 1, multi: true, children: map[string]*schemaNode{
1174:			"forwarding-class": {args: 1, multi: true, children: map[string]*schemaNode{
1175:				"scheduler": {args: 1, children: nil},
1178:		"interfaces": {args: 1, multi: true, children: map[string]*schemaNode{
1179:			"unit": {args: 1, multi: true, children: map[string]*schemaNode{
1180:				"classifiers": {children: map[string]*schemaNode{
1181:					"dscp":       {args: 1, children: nil},
1182:					"ieee-802.1": {args: 1, children: nil},
1184:				"rewrite-rules": {children: map[string]*schemaNode{
1185:					"dscp": {args: 1, children: nil},
1187:				"shaping-rate": {args: 1, children: map[string]*schemaNode{
1188:					"burst-size": {args: 1, children: nil},
1190:				"scheduler-map": {args: 1, children: nil},
1193:		"fairness": {children: map[string]*schemaNode{
1194:			"rss-expectation": {children: map[string]*schemaNode{
1195:				"ifindex": {args: 1, multi: true, children: map[string]*schemaNode{
1196:					"queue": {args: 1, multi: true, children: map[string]*schemaNode{
1199:						"active-workers":          {args: 1, children: nil},
1200:						"at-least-active-workers": {args: 1, children: nil},
1201:						"max-worker-flow-share":   {args: 1, children: nil},
1202:						"cstruct":                 {args: 1, children: nil},
1203:						"cstruct-max":             {args: 1, children: nil},
1209:	"firewall": {children: map[string]*schemaNode{
1210:		"policer": {args: 1, multi: true, children: map[string]*schemaNode{
1211:			"if-exceeding": {children: map[string]*schemaNode{
1212:				"bandwidth-limit":  {args: 1, children: nil},
1213:				"burst-size-limit": {args: 1, children: nil},
1216:			"then": {children: map[string]*schemaNode{
1218:				"loss-priority": {args: 1, children: nil},
1221:		"three-color-policer": {args: 1, multi: true, children: map[string]*schemaNode{
1222:			"single-rate": {children: map[string]*schemaNode{
1225:				"committed-information-rate": {args: 1, children: nil},
1226:				"committed-burst-size":       {args: 1, children: nil},
1227:				"excess-burst-size":          {args: 1, children: nil},
1229:			"two-rate": {children: map[string]*schemaNode{
1232:				"committed-information-rate": {args: 1, children: nil},
1233:				"committed-burst-size":       {args: 1, children: nil},
1234:				"peak-information-rate":      {args: 1, children: nil},
1235:				"peak-burst-size":            {args: 1, children: nil},
1237:			"then": {children: map[string]*schemaNode{
1239:				"loss-priority": {args: 1, children: nil},
1242:		"family": {compoundKey: true, children: map[string]*schemaNode{
1243:			"inet": {children: map[string]*schemaNode{
1244:				"filter": {args: 1, children: map[string]*schemaNode{
1245:					"term": {args: 1, children: map[string]*schemaNode{
1246:						"from": {children: map[string]*schemaNode{
1247:							"source-address":          {args: 1, multi: true, children: nil},
1248:							"destination-address":     {args: 1, multi: true, children: nil},
1251:							"protocol":                {args: 1, multi: true, children: nil},
1252:							"dscp":                    {args: 1, multi: true, children: nil},
1253:							"destination-port":        {args: 1, multi: true, children: nil},
1254:							"source-port":             {args: 1, multi: true, children: nil},
1255:							"icmp-type":               {args: 1, multi: true, children: nil},
1256:							"icmp-code":               {args: 1, multi: true, children: nil},
1257:							"tcp-flags":               {args: 1, multi: true, children: nil},
1259:							"flexible-match-range": {children: map[string]*schemaNode{
1260:								"range": {args: 1, children: map[string]*schemaNode{
1261:									"match-start": {args: 1, children: nil},
1262:									"byte-offset": {args: 1, children: nil},
1263:									"bit-length":  {args: 1, children: nil},
1264:									"range":       {args: 1, children: nil},
1265:									"match-value": {args: 1, children: nil},
1266:									"match-mask":  {args: 1, children: nil},
1270:						"then": {children: map[string]*schemaNode{
1276:							"routing-instance": {args: 1, children: nil},
1277:							"count":            {args: 1, children: nil},
1278:							"forwarding-class": {args: 1, children: nil},
1279:							"loss-priority":    {args: 1, children: nil},
1280:							"dscp":             {args: 1, children: nil},
1281:							"traffic-class":    {args: 1, children: nil},
1282:							"policer":          {args: 1, children: nil},
1287:			"inet6": {children: map[string]*schemaNode{
1288:				"filter": {args: 1, children: map[string]*schemaNode{
1289:					"term": {args: 1, children: map[string]*schemaNode{
1290:						"from": {children: map[string]*schemaNode{
1291:							"source-address":          {args: 1, multi: true, children: nil},
1292:							"destination-address":     {args: 1, multi: true, children: nil},
1295:							"protocol":                {args: 1, multi: true, children: nil},
1296:							"traffic-class":           {args: 1, multi: true, children: nil},
1297:							"destination-port":        {args: 1, multi: true, children: nil},
1298:							"source-port":             {args: 1, multi: true, children: nil},
1299:							"icmp-type":               {args: 1, multi: true, children: nil},
1300:							"icmp-code":               {args: 1, multi: true, children: nil},
1301:							"tcp-flags":               {args: 1, multi: true, children: nil},
1303:							"flexible-match-range": {children: map[string]*schemaNode{
1304:								"range": {args: 1, children: map[string]*schemaNode{
1305:									"match-start": {args: 1, children: nil},
1306:									"byte-offset": {args: 1, children: nil},
1307:									"bit-length":  {args: 1, children: nil},
1308:									"range":       {args: 1, children: nil},
1309:									"match-value": {args: 1, children: nil},
1310:									"match-mask":  {args: 1, children: nil},
1314:						"then": {children: map[string]*schemaNode{
1320:							"routing-instance": {args: 1, children: nil},
1321:							"count":            {args: 1, children: nil},
1322:							"forwarding-class": {args: 1, children: nil},
1323:							"loss-priority":    {args: 1, children: nil},
1324:							"dscp":             {args: 1, children: nil},
1325:							"traffic-class":    {args: 1, children: nil},
1326:							"policer":          {args: 1, children: nil},
1333:	"system": {desc: "System configuration", children: map[string]*schemaNode{
1334:		"host-name":     {desc: "System hostname", args: 1, placeholder: "<hostname>", children: nil},
1335:		"domain-name":   {desc: "Domain name", args: 1, placeholder: "<domain>", children: nil},
1336:		"domain-search": {desc: "Domain search list", args: 1, multi: true, placeholder: "<domain>", children: nil},
1337:		"time-zone":     {desc: "System time zone", args: 1, placeholder: "<timezone>", children: nil},
1339:		"name-server":   {desc: "DNS name server", args: 1, placeholder: "<address>", children: nil},
1340:		"backup-router": {desc: "Backup router", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
1341:			"destination": {desc: "Destination network", args: 1, placeholder: "<network>", children: nil},
1343:		"root-authentication": {desc: "Root authentication", children: map[string]*schemaNode{
1344:			"encrypted-password": {desc: "Encrypted password", args: 1, placeholder: "<password>", children: nil},
1345:			"ssh-ed25519":        {desc: "SSH ED25519 public key", args: 1, placeholder: "<key>", children: nil},
1346:			"ssh-rsa":            {desc: "SSH RSA public key", args: 1, placeholder: "<key>", children: nil},
1347:			"ssh-dsa":            {desc: "SSH DSA public key", args: 1, placeholder: "<key>", children: nil},
1349:		"archival": {desc: "Configuration archival", children: map[string]*schemaNode{
1350:			"configuration": {desc: "Configuration archival", children: map[string]*schemaNode{
1352:				"archive-sites":      {desc: "Archive site URL", args: 1, placeholder: "<url>", children: nil},
1355:		"master-password": {desc: "Master password", children: map[string]*schemaNode{
1356:			"pseudorandom-function": {desc: "Pseudorandom function", args: 1, placeholder: "<function>", children: nil},
1358:		"license": {desc: "License configuration", children: map[string]*schemaNode{
1359:			"autoupdate": {desc: "Autoupdate", children: map[string]*schemaNode{
1360:				"url": {desc: "Autoupdate URL", args: 1, placeholder: "<url>", children: nil},
1364:		"internet-options": {desc: "Internet options", children: map[string]*schemaNode{
1367:		"ntp": {desc: "NTP configuration", children: map[string]*schemaNode{
1368:			"server": {desc: "NTP server", args: 1, placeholder: "<address>", children: nil},
1369:			"threshold": {desc: "Threshold", args: 1, placeholder: "<seconds>", children: map[string]*schemaNode{
1370:				"action": {desc: "Action on threshold", args: 1, placeholder: "<action>", children: nil},
1373:		"syslog": {desc: "Syslog configuration", children: map[string]*schemaNode{
1374:			"user": {desc: "Syslog user", args: 1, placeholder: "<user>", children: nil},
1375:			"host": {desc: "Syslog host", args: 1, placeholder: "<host>", children: nil},
1376:			"file": {desc: "Syslog file", args: 1, placeholder: "<filename>", children: nil},
1378:		"login": {desc: "Login configuration", children: map[string]*schemaNode{
1379:			"user": {desc: "User name", args: 1, placeholder: "<username>", children: map[string]*schemaNode{
1380:				"uid":            {desc: "User ID", args: 1, placeholder: "<uid>", children: nil},
1381:				"class":          {desc: "Login class", args: 1, placeholder: "<class>", children: nil},
1385:		"dataplane-type": {desc: "Dataplane type", args: 1, placeholder: "<type>", children: nil},
1386:		"dataplane": {desc: "Dataplane configuration", children: map[string]*schemaNode{
1387:			"cores":          {args: 1, desc: "Number of dataplane cores", children: nil},
1388:			"memory":         {args: 1, desc: "Dataplane memory allocation", children: nil},
1389:			"socket-mem":     {args: 1, desc: "Legacy DPDK socket memory (retired, ignored)", children: nil},
1390:			"binary":         {args: 1, desc: "Userspace dataplane helper binary path", children: nil},
1391:			"control-socket": {args: 1, desc: "Unix control socket path", children: nil},
1392:			"state-file":     {args: 1, desc: "Helper state file path", children: nil},
1393:			"workers":        {args: 1, desc: "Worker thread count", children: nil},
1394:			"ring-entries":   {args: 1, desc: "AF_XDP ring entries per queue", children: nil},
1395:			"poll-mode":      {args: 1, desc: "Worker poll mode (busy-poll or interrupt)", children: nil},
1396:			"shared-umem": {desc: "AF_XDP shared-UMEM policy override", children: map[string]*schemaNode{
1397:				"mode":                 {args: 1, desc: "Shared UMEM mode override (auto|off|same-device-debug|cross-nic)", children: nil},
1398:				"interface":            {args: 1, multi: true, desc: "Optional participating Linux interface filter", children: nil},
1399:				"phase0-artifact-file": {args: 1, desc: "Optional machine-readable Phase 0 audit artifact", children: nil},
1400:				"artifact-file":        {args: 1, desc: "Alias for phase0-artifact-file", children: nil},
1402:			"rss-indirection":     {args: 1, desc: "mlx5 RSS indirection reshaping (enable|disable)", children: nil},
1403:			"claim-host-tunables": {args: 1, desc: "Allow xpfd to write host-scope tunables (true|false, default false)", children: nil},
1404:			"cpu-governor":        {args: 1, desc: "Host cpufreq governor (performance|schedutil|default)", children: nil},
1405:			"netdev-budget":       {args: 1, desc: "net.core.netdev_budget value", children: nil},
1406:			"coalescence": {desc: "NIC interrupt-coalescence tuning (mlx5)", children: map[string]*schemaNode{
1407:				"adaptive": {args: 1, desc: "Adaptive coalescing (enable|disable)", children: nil},
1408:				"rx-usecs": {args: 1, desc: "RX coalescing µs", children: nil},
1409:				"tx-usecs": {args: 1, desc: "TX coalescing µs", children: nil},
1411:			"rx-mode": {children: map[string]*schemaNode{
1412:				"idle-threshold":   {args: 1, children: nil},
1413:				"resume-threshold": {args: 1, children: nil},
1414:				"sleep-timeout":    {args: 1, children: nil},
1416:			"ports": {wildcard: &schemaNode{children: map[string]*schemaNode{
1417:				"interface": {args: 1, children: nil},
1418:				"rx-mode":   {args: 1, children: nil},
1419:				"cores":     {args: 1, children: nil},
1422:		"services": {desc: "System services", children: map[string]*schemaNode{
1423:			"ssh": {desc: "SSH service", children: map[string]*schemaNode{
1424:				"root-login": {desc: "Root login permission", args: 1, placeholder: "<permit|deny>", children: nil},
1426:			"netconf": {desc: "NETCONF service", children: map[string]*schemaNode{
1429:			"web-management": {desc: "Web management", children: map[string]*schemaNode{
1430:				"http": {desc: "HTTP service", children: map[string]*schemaNode{
1431:					"interface": {desc: "Interface", args: 1, placeholder: "<interface>", children: nil},
1433:				"https": {desc: "HTTPS service", children: map[string]*schemaNode{
1435:					"interface":                    {desc: "Interface", args: 1, placeholder: "<interface>", children: nil},
1437:				"api-auth": {desc: "API authentication", children: map[string]*schemaNode{
1438:					"user": {desc: "User name", wildcard: &schemaNode{placeholder: "<username>", children: map[string]*schemaNode{
1439:						"password": {desc: "Password", args: 1, placeholder: "<password>", children: nil},
1441:					"api-key": {desc: "API key", args: 1, placeholder: "<key>", children: nil},
1445:			"dhcp-local-server": {desc: "DHCP local server", children: map[string]*schemaNode{
1446:				"group": {desc: "DHCP group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
1447:					"pool": {desc: "Address pool", args: 1, placeholder: "<pool-name>", children: nil},
1450:			"dhcpv6-local-server": {desc: "DHCPv6 local server", children: map[string]*schemaNode{
1451:				"group": {desc: "DHCPv6 group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
1452:					"pool": {desc: "Address pool", args: 1, placeholder: "<pool-name>", children: nil},
1457:	"services": {desc: "Services configuration", children: map[string]*schemaNode{
1458:		"rpm": {desc: "Real-time Performance Monitoring probes", children: map[string]*schemaNode{
1459:			"probe-limit": {args: 1, desc: "Default maximum consecutive failed probes before stopping a test cycle", children: nil},
1460:			"probe": {args: 1, desc: "RPM probe name", children: map[string]*schemaNode{
1461:				"test": {args: 1, desc: "RPM test name", children: map[string]*schemaNode{
1462:					"probe-type":       {args: 1, desc: "Probe type: icmp-ping, tcp-ping, or http-get", children: nil},
1463:					"target":           {desc: "Target IP, hostname, or URL", wildcard: &schemaNode{placeholder: "<target>", desc: "Target IP, hostname, or URL"}, children: map[string]*schemaNode{"url": {args: 1, desc: "HTTP target URL", children: nil}}},
1464:					"source-address":   {args: 1, desc: "Source address for the probe", children: nil},
1465:					"routing-instance": {args: 1, desc: "Routing instance / VRF for the probe", children: nil},
1466:					"probe-interval":   {args: 1, desc: "Seconds between probes within a test", children: nil},
1467:					"probe-count":      {args: 1, desc: "Number of probes per test cycle", children: nil},
1468:					"test-interval":    {args: 1, desc: "Seconds between test cycles", children: nil},
1469:					"thresholds": {desc: "Failure thresholds for the test", children: map[string]*schemaNode{
1470:						"successive-loss": {args: 1, desc: "Consecutive losses before marking the test failed", children: nil},
1472:					"probe-limit":      {args: 1, desc: "Maximum consecutive failed probes before stopping the current test cycle", children: nil},
1473:					"destination-port": {args: 1, desc: "Destination TCP port for tcp-ping probes", children: nil},
1477:		"flow-monitoring": {children: map[string]*schemaNode{
1478:			"version9": {children: map[string]*schemaNode{
1479:				"template": {args: 1, children: map[string]*schemaNode{
1480:					"flow-active-timeout":   {args: 1, children: nil},
1481:					"flow-inactive-timeout": {args: 1, children: nil},
1482:					"template-refresh-rate": {children: map[string]*schemaNode{
1483:						"seconds": {args: 1, children: nil},
1487:			"version-ipfix": {children: map[string]*schemaNode{
1488:				"template": {args: 1, children: map[string]*schemaNode{
1489:					"flow-active-timeout":   {args: 1, children: nil},
1490:					"flow-inactive-timeout": {args: 1, children: nil},
1491:					"template-refresh-rate": {children: map[string]*schemaNode{
1492:						"seconds": {args: 1, children: nil},
1494:					"ipv4-template": {children: map[string]*schemaNode{
1495:						"export-extension": {args: 1, children: nil},
1497:					"ipv6-template": {children: map[string]*schemaNode{
1498:						"export-extension": {args: 1, children: nil},
1505:	"forwarding-options": {children: map[string]*schemaNode{
1506:		"family": {compoundKey: true, children: map[string]*schemaNode{
1507:			"inet6": {children: map[string]*schemaNode{
1508:				"mode": {args: 1, children: nil},
1511:		"sampling": {children: map[string]*schemaNode{
1512:			"instance": {args: 1, children: map[string]*schemaNode{
1514:				"family": {compoundKey: true, children: map[string]*schemaNode{
1515:					"inet": {children: map[string]*schemaNode{
1516:						"output": {children: map[string]*schemaNode{
1517:							"flow-server":  {args: 1, children: nil},
1521:					"inet6": {children: map[string]*schemaNode{
1522:						"output": {children: map[string]*schemaNode{
1523:							"flow-server":  {args: 1, children: nil},
1530:		"port-mirroring": {children: map[string]*schemaNode{
1531:			"instance": {args: 1, children: map[string]*schemaNode{
1532:				"input": {children: map[string]*schemaNode{
1539:	"bridge-domains": {wildcard: &schemaNode{desc: "Bridge domain name", children: map[string]*schemaNode{
1540:		"vlan-id-list":      {args: 1, multi: true, desc: "VLAN IDs in this bridge domain", children: nil},
1541:		"routing-interface": {args: 1, desc: "IRB routing interface (e.g. irb.0)", children: nil},
1542:		"domain-type":       {args: 1, desc: "Bridge domain type", children: nil},
1544:	"routing-instances": {wildcard: &schemaNode{children: map[string]*schemaNode{
1547:		"routing-options": {children: map[string]*schemaNode{
1548:			"static": {children: map[string]*schemaNode{
1549:				"route": {args: 1, children: nil},
1551:			"rib": {args: 1, children: map[string]*schemaNode{
1552:				"static": {children: map[string]*schemaNode{
1553:					"route": {args: 1, children: nil},
1556:			"interface-routes": {children: map[string]*schemaNode{
1557:				"rib-group": {children: map[string]*schemaNode{
1558:					"inet":  {args: 1, children: nil},
1559:					"inet6": {args: 1, children: nil},
1563:		"protocols": {children: map[string]*schemaNode{
1564:			"ospf": {children: map[string]*schemaNode{
1565:				"reference-bandwidth": {args: 1, children: nil},
1567:				"area": {args: 1, children: map[string]*schemaNode{
1568:					"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
1571:						"interface-type": {args: 1, children: nil},
1572:						"cost":           {args: 1, children: nil},
1573:						"authentication": {children: map[string]*schemaNode{
1574:							"md5": {args: 1, children: map[string]*schemaNode{
1575:								"key": {args: 1, children: nil},
1577:							"simple-password": {args: 1, children: nil},
1579:						"bfd-liveness-detection": {children: map[string]*schemaNode{
1580:							"minimum-interval": {args: 1, children: nil},
1581:							"multiplier":       {args: 1, children: nil},
1584:					"area-type": {children: map[string]*schemaNode{
1585:						"stub": {children: map[string]*schemaNode{
1588:						"nssa": {children: map[string]*schemaNode{
1592:					"virtual-link": {args: 1, children: map[string]*schemaNode{
1593:						"transit-area": {args: 1, children: nil},
1597:			"ospf3": {children: map[string]*schemaNode{
1598:				"router-id": {args: 1, children: nil},
1599:				"export":    {args: 1, multi: true, children: nil},
1600:				"area": {args: 1, children: map[string]*schemaNode{
1601:					"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
1603:						"cost":    {args: 1, children: nil},
1607:			"bgp": {children: map[string]*schemaNode{
1609:				"damping": {children: map[string]*schemaNode{
1610:					"half-life":    {args: 1, children: nil},
1611:					"reuse":        {args: 1, children: nil},
1612:					"suppress":     {args: 1, children: nil},
1613:					"max-suppress": {args: 1, children: nil},
1615:				"group": {args: 1, children: nil},
1617:			"isis": {children: map[string]*schemaNode{
1618:				"net":     {args: 1, children: nil},
1619:				"level":   {args: 1, children: nil},
1620:				"is-type": {args: 1, children: nil},
1621:				"export":  {args: 1, multi: true, children: nil},
1622:				"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
1623:					"level":               {args: 1, children: nil},
1625:					"metric":              {args: 1, children: nil},
1626:					"authentication-key":  {args: 1, children: nil},
1627:					"authentication-type": {args: 1, children: nil},
1628:					"bfd-liveness-detection": {children: map[string]*schemaNode{
1629:						"minimum-interval": {args: 1, children: nil},
1630:						"multiplier":       {args: 1, children: nil},
1633:				"authentication-key":  {args: 1, children: nil},
1634:				"authentication-type": {args: 1, children: nil},
1643:	// Wire groups wildcard to mirror top-level schema children.
1645:	groupWild := setSchema.children["groups"].wildcard
1646:	groupWild.children = make(map[string]*schemaNode)
1668:// CompleteSetPath returns possible completions for a partial set/delete path.
1671:// (wildcard or args > 0), it returns nil (user must type a name).
1672:func CompleteSetPath(tokens []string) []string {
1673:	results := CompleteSetPathWithValues(tokens, nil)
1684:// CompleteSetPathWithValues is like CompleteSetPath but uses a ValueProvider
1687:func CompleteSetPathWithValues(tokens []string, provider ValueProvider) []SchemaCompletion {
1696:		if schema.children == nil && schema.wildcard == nil {
1703:		var childSchema *schemaNode
1727:		if childSchema == nil && schema.wildcard != nil {
1728:			childSchema = schema.wildcard
1746:		// Consume keyword + extra args.
1747:		nodeKeyCount := 1 + childSchema.args
1759:		if childSchema.compoundKey && i < len(tokens) {
1768:			// Still consuming args for this node — user needs to type a value.
1772:			// Check for fixed keyword in the middle of args (e.g., "to-zone" in "from-zone X to-zone Y").
1773:			if childSchema.midKeyword != "" && childSchema.midKeywordAt > 0 {
1775:				// If the last consumed token is a partial match for the midKeyword, suggest it.
1776:				if nextPos == childSchema.midKeywordAt+1 && consumed > 1 {
1778:					if lastToken != childSchema.midKeyword && strings.HasPrefix(childSchema.midKeyword, lastToken) {
1779:						return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}
1782:				// If we need to complete the midKeyword position, suggest it.
1783:				if nextPos == childSchema.midKeywordAt {
1784:					return []SchemaCompletion{{Name: childSchema.midKeyword, Desc: "Destination zone"}}
1789:			if provider != nil && childSchema.valueHint != ValueHintNone {
1790:				results := provider(childSchema.valueHint, path)
1791:				// Add placeholder if available.
1792:				if childSchema.placeholder != "" {
1793:					results = append([]SchemaCompletion{{Name: childSchema.placeholder, Desc: childSchema.desc}}, results...)
1797:			// No provider but have a placeholder — show it.
1798:			if childSchema.placeholder != "" {
1799:				return []SchemaCompletion{{Name: childSchema.placeholder, Desc: childSchema.desc}}
1804:		if childSchema.multi && childSchema.children == nil {
1816:	// If we're at a leaf with no children/wildcard, hint that Enter completes.
1817:	if schema.children == nil && schema.wildcard == nil {
1827:	// If this level accepts a wildcard name, provide dynamic values too.
1828:	if schema.wildcard != nil {
1829:		if provider != nil && schema.wildcard.valueHint != ValueHintNone {
1830:			completions = append(completions, provider(schema.wildcard.valueHint, path)...)
1832:		// Add placeholder.
1833:		if schema.wildcard.placeholder != "" {
1834:			completions = append(completions, SchemaCompletion{Name: schema.wildcard.placeholder, Desc: schema.wildcard.desc})
1843:// ResolveConsumedSetPathTokens expands uniquely matching keyword prefixes in a
1846:func ResolveConsumedSetPathTokens(tokens []string) ([]string, bool) {
1858:		var childSchema *schemaNode
1876:		if childSchema == nil && schema.wildcard != nil {
1877:			childSchema = schema.wildcard
1884:		nodeKeyCount := 1 + childSchema.args
1894:		if childSchema.compoundKey && i < len(tokens) {
1916:		if childSchema.multi && childSchema.children == nil {

exec
/bin/bash -lc "nl -ba docs/research/1319-typed-leaf/plan.md | sed -n '253,380p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   253	## 7. Hostile questions (answered)
   254	
   255	- **Touch every leaf (huge churn)?** No — PR 1 is infra + schedulers
   256	  re-home only; subsystems are independent incremental PRs. ~536 leaves
   257	  stay `ValueAny` and untouched until their subsystem PR.
   258	- **Consistent across local CLI / remote CLI / gRPC?** Yes under Option
   259	  A: all three config-mode completers already call
   260	  `config.CompleteSetPathWithValues` (cli) / the gRPC completer resolves
   261	  the same schema; validation runs in `configstore.compileTree` which is
   262	  the single commit path for all frontends. Under Option C this is the
   263	  weak point (two trees). Verify the gRPC completer path in PR 1.
   264	- **Junos-parity scope (which types matter most)?** integer-with-range
   265	  and enum dominate the ~536 leaves; rate/byte-size/percent already done;
   266	  IP/CIDR and identifier-cross-ref are the next most valuable. Defer
   267	  free-form (`description`, URLs) to permanent `ValueAny`.
   268	- **Does the "compiled-leaf-only" invariant hold?** Yes — keep
   269	  `pkg/cmdtree/README.md:47` invariant: only type a leaf the compiler
   270	  actually consumes, else commit-check rejects config the compiler would
   271	  silently ignore (a behavior change beyond the issue's scope).
   272	
   273	## 8. Risks
   274	
   275	- **Parser dependency on `setSchema`.** `setSchema` drives flat-set token
   276	  grouping in SetPath. Adding *fields* to `schemaNode` is additive and
   277	  must not change grouping; PR 1 must assert SetPath grouping is
   278	  byte-identical (run full parser test suite). This is the main regression
   279	  surface and why Option A edits fields rather than restructuring nodes.
   280	- **gRPC completer divergence.** Confirm the gRPC `set` completer reaches
   281	  the same value-slot code; add a test.
   282	- **Doctrine churn.** CLAUDE.md says cmdtree is THE SSOT; Option A
   283	  formalizes a two-SSOT split (operational=cmdtree, config-grammar=
   284	  setSchema). Must be documented, not silently contradicted.
   285	
   286	## 9. Test plan
   287	
   288	- Reuse `pkg/config/schema_validate_test.go` +
   289	  `pkg/cmdtree/schema_validate_test.go` against the generic walker.
   290	- New: CLI-path completion test (`transmit-rate ?` → `<rate>`+examples
   291	  via `CompleteSetPathWithValues`).
   292	- New: SetPath grouping golden test asserting no grouping change.
   293	- Per subsystem PR: fixture showing master silently coerces garbage +
   294	  new walker rejects it.
   295	
   296	## 10. Rollout / ordering
   297	
   298	PR 1 (infra+walker+wiring+schedulers re-home) → merge → PR 2 chassis
   299	cluster → PR 3 interfaces → PR 4 firewall → ... Each independent,
   300	file-zone disjoint, per-subsystem fixtures.
   301	
   302	## 11. Open questions for reviewers
   303	
   304	1. Option A vs C: is moving config-mode typed values out of cmdtree into
   305	   `setSchema` acceptable given the SSOT doctrine, or must typed values
   306	   stay in cmdtree (forcing the Option-C bridge / hand-sync)?
   307	2. Is the symptom-1-still-open finding (§2.2) correct — i.e. does any
   308	   production config-mode path consult the cmdtree typed leaves today? If
   309	   a bridge exists that this research missed, Option A's main win shrinks.
   310	3. Should PR 1 retire `cmdtree.ConfigClassOfServiceSchedulers` outright,
   311	   or leave it as dead-but-tested until all CoS leaves move?

exec
/bin/bash -lc "nl -ba pkg/config/ast.go | sed -n '1,220p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
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
    91			if len(child.Keys) > 0 && child.Keys[0] == name {
    92				result = append(result, child)
    93			}
    94		}
    95		return result
    96	}
    97	
    98	// ConfigTree is the root of a parsed configuration.
    99	type ConfigTree struct {
   100		Children []*Node
   101	}
   102	
   103	// FindChild returns the first top-level child matching name.
   104	func (t *ConfigTree) FindChild(name string) *Node {
   105		for _, child := range t.Children {
   106			if len(child.Keys) > 0 && child.Keys[0] == name {
   107				return child
   108			}
   109		}
   110		return nil
   111	}
   112	
   113	// Clone creates a deep copy of the config tree.
   114	func (t *ConfigTree) Clone() *ConfigTree {
   115		if t == nil {
   116			return nil
   117		}
   118		return &ConfigTree{
   119			Children: cloneNodes(t.Children),
   120		}
   121	}
   122	
   123	func cloneNodes(nodes []*Node) []*Node {
   124		if nodes == nil {
   125			return nil
   126		}
   127		result := make([]*Node, len(nodes))
   128		for i, n := range nodes {
   129			result[i] = &Node{
   130				Keys:          append([]string(nil), n.Keys...),
   131				Children:      cloneNodes(n.Children),
   132				IsLeaf:        n.IsLeaf,
   133				Annotation:    n.Annotation,
   134				InheritedFrom: n.InheritedFrom,
   135				Line:          n.Line,
   136				Column:        n.Column,
   137			}
   138		}
   139		return result
   140	}
   141	
   142	// navigatePath walks the tree following path components and returns matching nodes.
   143	// When multiple sibling nodes share the same key prefix (e.g., path ["from-zone","untrust"]
   144	// matching both ["from-zone","untrust","to-zone","trust"] and
   145	// ["from-zone","untrust","to-zone","dmz"]), all matches are returned.
   146	func navigatePath(nodes []*Node, path []string) []*Node {
   147		current := nodes
   148		i := 0
   149		for i < len(path) {
   150			keyword := path[i]
   151			// Try multi-key match (keyword + argument pairs).
   152			if i+1 < len(path) {
   153				var matched []*Node
   154				for _, n := range current {
   155					if len(n.Keys) >= 2 && n.Keys[0] == keyword && n.Keys[1] == path[i+1] {
   156						matched = append(matched, n)
   157					}
   158				}
   159				if len(matched) > 0 {
   160					consumed := 2
   161					// Continue consuming additional key-value pairs from the path
   162					// that match the node's remaining keys. E.g., path
   163					// ["from-zone","untrust","to-zone","trust"] consumes all 4 keys
   164					// of node Keys=["from-zone","untrust","to-zone","trust"].
   165					for consumed < len(matched[0].Keys) && i+consumed+1 < len(path) {
   166						nextKey := path[i+consumed]
   167						nextVal := path[i+consumed+1]
   168						var filtered []*Node
   169						for _, n := range matched {
   170							if len(n.Keys) > consumed+1 && n.Keys[consumed] == nextKey && n.Keys[consumed+1] == nextVal {
   171								filtered = append(filtered, n)
   172							}
   173						}
   174						if len(filtered) == 0 {
   175							break
   176						}
   177						matched = filtered
   178						consumed += 2
   179					}
   180					i += consumed
   181					if i >= len(path) {
   182						return matched
   183					}
   184					current = matched[0].Children
   185					continue
   186				}
   187			}
   188			// Single-key match.
   189			found := false
   190			for _, n := range current {
   191				if len(n.Keys) > 0 && n.Keys[0] == keyword {
   192					i++
   193					if i >= len(path) {
   194						return []*Node{n}
   195					}
   196					current = n.Children
   197					found = true
   198					break
   199				}
   200			}
   201			if !found {
   202				return nil
   203			}
   204		}
   205		return nil
   206	}
   207	
   208	// matchNodeKeys checks if a node's Keys match path elements starting at pos.
   209	// Returns the number of path elements consumed (len(node.Keys)) on match, 0 otherwise.
   210	func matchNodeKeys(n *Node, path []string, pos int) int {
   211		if len(n.Keys) == 0 || pos >= len(path) {
   212			return 0
   213		}
   214		if n.Keys[0] != path[pos] {
   215			return 0
   216		}
   217		// First key matches; check remaining keys fit within path
   218		nk := len(n.Keys)
   219		if pos+nk > len(path) {
   220			// Partial match: node has more keys than remaining path.

exec
/bin/bash -lc "nl -ba pkg/cmdtree/schema_validate.go | sed -n '1,240p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
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
/bin/bash -lc "nl -ba pkg/config/ast.go | sed -n '1660,1838p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
  1660		for i := range a {
  1661			if a[i] != b[i] {
  1662				return false
  1663			}
  1664		}
  1665		return true
  1666	}
  1667	
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

exec
/bin/bash -lc "nl -ba pkg/config/ast.go | sed -n '360,410p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   360		ValueHintAddressName             // address-set <name>
   361		ValueHintAppName                 // application <name>
   362		ValueHintPoolName                // pool <name>
   363		ValueHintInterfaceName           // interfaces <name>
   364		ValueHintScreenProfile           // ids-option <name>
   365		ValueHintStreamName              // stream <name>
   366		ValueHintAppSetName              // application-set <name>
   367		ValueHintUnitNumber              // unit <number>
   368		ValueHintPolicyAddress           // policy match source/destination-address
   369		ValueHintPolicyApp               // policy match application (any + apps)
   370		ValueHintPolicyName              // policy <name> (from path context)
   371	)
   372	
   373	// SchemaCompletion is a completion candidate from the config schema.
   374	type SchemaCompletion struct {
   375		Name string
   376		Desc string
   377	}
   378	
   379	// ValueProvider returns possible values for a given hint.
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

exec
/bin/bash -lc "nl -ba pkg/cmdtree/tree_test.go | sed -n '110,170p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   110	
   111	func TestConfigTopLevel_SetIncludesClassOfServiceSchedulers(t *testing.T) {
   112		setNode := ConfigTopLevel["set"]
   113		if setNode == nil {
   114			t.Fatal("missing set node")
   115		}
   116		cosNode := setNode.Children["class-of-service"]
   117		if cosNode == nil {
   118			t.Fatalf("set completion tree missing class-of-service: %+v", setNode.Children)
   119		}
   120		schedulersNode := cosNode.Children["schedulers"]
   121		if schedulersNode == nil {
   122			t.Fatalf("class-of-service completion tree missing schedulers: %+v", cosNode.Children)
   123		}
   124		if schedulersNode.Children["<scheduler>"] != ConfigClassOfServiceSchedulers {
   125			t.Fatalf("schedulers completion tree is not wired to typed scheduler schema")
   126		}
   127	}
   128	
   129	func TestSchedulers_TypedLeaf_QuestionHelpShowsPlaceholderAndExamples(t *testing.T) {
   130		// After `sched transmit-rate`, `?` should show the rate placeholder
   131		// plus example values.
   132		cands := CompleteFromTreeWithDesc(
   133			ConfigTopLevel,
   134			[]string{"set", "class-of-service", "schedulers", "be", "transmit-rate"},
   135			"",
   136			nil,
   137		)
   138		if _, ok := containsCand(cands, "<rate>"); !ok {
   139			t.Fatalf("expected <rate> placeholder in `?` candidates, got %+v", cands)
   140		}
   141		if _, ok := containsCand(cands, "1g"); !ok {
   142			t.Fatalf("expected 1g example in `?` candidates, got %+v", cands)
   143		}
   144	}
   145	
   146	func TestSchedulers_TypedLeaf_AfterValueShowsModifiers(t *testing.T) {
   147		// After `sched transmit-rate 1g`, the value is consumed and `?`
   148		// should surface the `exact` modifier child.
   149		cands := CompleteFromTreeWithDesc(
   150			ConfigTopLevel,
   151			[]string{"set", "class-of-service", "schedulers", "be", "transmit-rate", "1g"},
   152			"",
   153			nil,
   154		)
   155		if _, ok := containsCand(cands, "exact"); !ok {
   156			t.Fatalf("expected `exact` modifier after consumed rate, got %+v", cands)
   157		}
   158	}
   159	
   160	func TestSchedulers_TypedLeaf_PriorityEnumExamples(t *testing.T) {
   161		cands := CompleteFromTreeWithDesc(
   162			ConfigTopLevel,
   163			[]string{"set", "class-of-service", "schedulers", "be", "priority"},
   164			"",
   165			nil,
   166		)
   167		for _, want := range []string{"strict-high", "low", "high"} {
   168			if _, ok := containsCand(cands, want); !ok {
   169				t.Fatalf("expected enum example %q for priority, got %+v", want, cands)
   170			}

exec
/bin/bash -lc "nl -ba pkg/config/ast.go | sed -n '1838,1935p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
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
  1916			if childSchema.multi && childSchema.children == nil {
  1917				continue
  1918			}
  1919			schema = childSchema
  1920		}
  1921	
  1922		return resolved, true
  1923	}

exec
/bin/bash -lc "nl -ba pkg/cmdtree/tree.go | sed -n '1,220p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
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
   131	// HasDynamic returns true if the node has any dynamic completion function.
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
   146		}
   147		if n.DynamicFn != nil {
   148			return n.DynamicFn(cfg)
   149		}
   150		return nil
   151	}
   152	
   153	// Candidate holds a command name and its description for display.
   154	type Candidate struct {
   155		Name string
   156		Desc string
   157	}
   158	
   159	// OperationalTree defines tab completion for operational mode.
   160	// This is the canonical source — all other trees derive from this.
   161	var OperationalTree = map[string]*Node{
   162		"configure": {Desc: "Manipulate software configuration information", Children: map[string]*Node{
   163			"exclusive": {Desc: "Enter exclusive configuration mode"},
   164		}},
   165		"show": {Desc: "Show system information", Children: map[string]*Node{
   166			"chassis": {Desc: "Show chassis information", Children: map[string]*Node{
   167				"cluster": {Desc: "Show cluster/HA status", Children: map[string]*Node{
   168					"status":      {Desc: "Show cluster node status"},
   169					"interfaces":  {Desc: "Show cluster interfaces"},
   170					"information": {Desc: "Show cluster configuration details"},
   171					"statistics":  {Desc: "Show cluster statistics"},
   172					"fabric": {Desc: "Show fabric link information", Children: map[string]*Node{
   173						"statistics": {Desc: "Show fabric redirect statistics"},
   174					}},
   175					"control-plane": {Desc: "Show control-plane information", Children: map[string]*Node{
   176						"statistics": {Desc: "Show control-plane statistics"},
   177					}},
   178					"data-plane": {Desc: "Show data-plane information", Children: map[string]*Node{
   179						"statistics": {Desc: "Show data-plane statistics"},
   180						"interfaces": {Desc: "Show data-plane interfaces"},
   181						"fairness":   {Desc: "Show userspace fairness RSS structure"},
   182						"flows": {Desc: "Show userspace flow-to-worker diagnostics", Children: map[string]*Node{
   183							"all":   {Desc: "Show all helper-reported flow-to-worker rows"},
   184							"limit": {Desc: "Limit flow-to-worker rows"},
   185						}},
   186					}},
   187					"ip-monitoring": {Desc: "Show IP monitoring information", Children: map[string]*Node{
   188						"status": {Desc: "Show IP monitoring status"},
   189					}},
   190					"fence-status": {Desc: "Show peer fencing configuration and history"},
   191				}},
   192				"alarms":         {Desc: "Show chassis alarm status"},
   193				"environment":    {Desc: "Show chassis environment"},
   194				"forwarding":     {Desc: "Show forwarding daemon status and utilization"},
   195				"hardware":       {Desc: "Show installed hardware components"},
   196				"routing-engine": {Desc: "Show Routing Engine status"},
   197			}},
   198			"class-of-service": {Desc: "Show class-of-service information", Children: map[string]*Node{
   199				"interface": {Desc: "Show per-interface CoS configuration"},
   200			}},
   201			"configuration": {Desc: "Show active configuration", Children: map[string]*Node{
   202				"applications":       {Desc: "Application protocol definitions"},
   203				"chassis":            {Desc: "Chassis configuration"},
   204				"class-of-service":   {Desc: "Class-of-service configuration"},
   205				"event-options":      {Desc: "Event processing configuration"},
   206				"firewall":           {Desc: "Firewall filter configuration"},
   207				"forwarding-options": {Desc: "Forwarding options configuration"},
   208				"interfaces":         {Desc: "Interface configuration"},
   209				"policy-options":     {Desc: "Policy framework configuration"},
   210				"protocols":          {Desc: "Routing protocol configuration"},
   211				"routing-instances":  {Desc: "Routing instance configuration"},
   212				"routing-options":    {Desc: "Protocol-independent routing options"},
   213				"schedulers":         {Desc: "Scheduler configuration"},
   214				"security":           {Desc: "Security configuration"},
   215				"services":           {Desc: "Service configuration"},
   216				"snmp":               {Desc: "SNMP configuration"},
   217				"system":             {Desc: "System configuration"},
   218			}},
   219			"dhcp": {Desc: "Show DHCP information", Children: map[string]*Node{
   220				"leases":            {Desc: "Show DHCP leases"},

exec
/bin/bash -lc "nl -ba pkg/configstore/store.go | sed -n '160,210p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
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
   206		if len(errs) > 0 {
   207			return nil, fmt.Errorf("sync config parse error: %v", errs[0])
   208		}
   209	
   210		// Let caller patch the tree (e.g. preserve local chassis cluster settings).

exec
/bin/bash -lc "nl -ba pkg/cmdtree/tree.go | sed -n '220,360p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   220				"leases":            {Desc: "Show DHCP leases"},
   221				"client-identifier": {Desc: "Show DHCPv6 DUID(s)"},
   222			}},
   223			"firewall": {Desc: "Show firewall filter configuration", Children: map[string]*Node{
   224				"filter": {Desc: "Show specific filter by name", DynamicFn: func(cfg *config.Config) []string {
   225					if cfg == nil {
   226						return nil
   227					}
   228					names := make([]string, 0, len(cfg.Firewall.FiltersInet)+len(cfg.Firewall.FiltersInet6))
   229					for n := range cfg.Firewall.FiltersInet {
   230						names = append(names, n)
   231					}
   232					for n := range cfg.Firewall.FiltersInet6 {
   233						names = append(names, n)
   234					}
   235					return names
   236				}},
   237			}},
   238			"flow-monitoring": {Desc: "Show flow monitoring/NetFlow configuration"},
   239			"log":             {Desc: "Show daemon log entries [N]"},
   240			"route": {Desc: "Show routing table information", Children: map[string]*Node{
   241				"<destination>": {Desc: "IP address or prefix to look up", Children: map[string]*Node{
   242					"exact":    {Desc: "Exactly match the prefix"},
   243					"longer":   {Desc: "More-specific (longer) prefixes"},
   244					"orlonger": {Desc: "Equal or more-specific prefixes"},
   245				}},
   246				"terse":   {Desc: "Display terse output"},
   247				"detail":  {Desc: "Display detailed output"},
   248				"summary": {Desc: "Show routing table statistics"},
   249				"table": {Desc: "Show routes in named routing table", DynamicFn: func(cfg *config.Config) []string {
   250					if cfg == nil {
   251						return []string{"inet.0", "inet6.0"}
   252					}
   253					// Include main tables plus per-instance tables.
   254					names := []string{"inet.0", "inet6.0"}
   255					for _, ri := range cfg.RoutingInstances {
   256						names = append(names, ri.Name+".inet.0", ri.Name+".inet6.0")
   257					}
   258					return names
   259				}},
   260				"protocol": {Desc: "Show routes learned from named protocol", DynamicFn: func(_ *config.Config) []string {
   261					return []string{"static", "direct", "local", "ospf", "bgp", "rip", "isis", "kernel", "connected"}
   262				}},
   263				"instance": {Desc: "Show routes for a routing instance", DynamicFn: func(cfg *config.Config) []string {
   264					if cfg == nil {
   265						return nil
   266					}
   267					names := make([]string, 0, len(cfg.RoutingInstances))
   268					for _, ri := range cfg.RoutingInstances {
   269						names = append(names, ri.Name)
   270					}
   271					return names
   272				}},
   273			}},
   274			"security": {Desc: "Show security information", Children: map[string]*Node{
   275				"zones": {Desc: "Show security zone information", DynamicFn: func(cfg *config.Config) []string {
   276					if cfg == nil {
   277						return nil
   278					}
   279					names := make([]string, 0, len(cfg.Security.Zones))
   280					for name := range cfg.Security.Zones {
   281						names = append(names, name)
   282					}
   283					return names
   284				}, Children: map[string]*Node{
   285					"detail": {Desc: "Show detailed zone information"},
   286					"terse":  {Desc: "Display terse output"},
   287				}},
   288				"policies": {Desc: "Show security firewall policies", Children: map[string]*Node{
   289					"global":      {Desc: "Show global security policy information"},
   290					"policy-name": {Desc: "Show policy matching a specific name"},
   291					"brief":       {Desc: "Show brief policy summary"},
   292					"detail":      {Desc: "Show detailed policy information"},
   293					"hit-count":   {Desc: "Show policy hit counters [from-zone X to-zone Y]"},
   294					"from-zone": {Desc: "Filter by source zone", DynamicFn: func(cfg *config.Config) []string {
   295						if cfg == nil {
   296							return nil
   297						}
   298						names := make([]string, 0, len(cfg.Security.Zones))
   299						for name := range cfg.Security.Zones {
   300							names = append(names, name)
   301						}
   302						return names
   303					}, Children: map[string]*Node{
   304						"to-zone": {Desc: "Filter by destination zone", DynamicFn: func(cfg *config.Config) []string {
   305							if cfg == nil {
   306								return nil
   307							}
   308							names := make([]string, 0, len(cfg.Security.Zones))
   309							for name := range cfg.Security.Zones {
   310								names = append(names, name)
   311							}
   312							return names
   313						}, Children: map[string]*Node{
   314							"policy": {Desc: "Filter by policy name", ContextDynamicFn: func(cfg *config.Config, words []string) []string {
   315								if cfg == nil {
   316									return nil
   317								}
   318								// Extract from-zone and to-zone from consumed words.
   319								var fromZone, toZone string
   320								for i, w := range words {
   321									if w == "from-zone" && i+1 < len(words) {
   322										fromZone = words[i+1]
   323									}
   324									if w == "to-zone" && i+1 < len(words) {
   325										toZone = words[i+1]
   326									}
   327								}
   328								if fromZone == "" || toZone == "" {
   329									return nil
   330								}
   331								for _, zpp := range cfg.Security.Policies {
   332									if zpp.FromZone == fromZone && zpp.ToZone == toZone {
   333										names := make([]string, 0, len(zpp.Policies))
   334										for _, p := range zpp.Policies {
   335											names = append(names, p.Name)
   336										}
   337										return names
   338									}
   339								}
   340								return nil
   341							}},
   342						}},
   343					}},
   344				}},
   345				"screen": {Desc: "Show screen service information", Children: map[string]*Node{
   346					"ids-option": {Desc: "Show configured screen profile", DynamicFn: func(cfg *config.Config) []string {
   347						if cfg == nil {
   348							return nil
   349						}
   350						names := make([]string, 0, len(cfg.Security.Screen))
   351						for name := range cfg.Security.Screen {
   352							names = append(names, name)
   353						}
   354						return names
   355					}, Children: map[string]*Node{
   356						"detail": {Desc: "Show detailed screen profile with thresholds"},
   357					}},
   358					"statistics": {Desc: "Show screen statistics", Children: map[string]*Node{
   359						"zone": {Desc: "Show per-zone screen counters", DynamicFn: func(cfg *config.Config) []string {
   360							if cfg == nil {

exec
/bin/bash -lc 'rg -n "ConfigClassOfServiceSchedulers|transmit-rate|priority|buffer-size|ValueRate|ValueEnum|ValueByteSize" pkg/cmdtree pkg/config/schema_validators.go pkg/config' in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/config/schema_validators.go:49:// consumes. Reject bare integers here so `buffer-size 50` cannot pass
pkg/config/schema_validators.go:65:// ValidateByteSizeOrPercent accepts the two scheduler buffer-size forms
pkg/config/schema_validators.go:74:			return fmt.Errorf("not a valid percent buffer-size (expected >0%%..100%%; xpf rejects Junos 0%% because zero is the legacy absent-field value): %w", err)
pkg/config/schema_validators.go:103:	// indistinguishable from "no buffer-size configured" -- the runtime
pkg/config/schema_validators.go:108:		return 0, fmt.Errorf("percent out of range (0,100] (got %s); note: 0%% is not supported -- omit buffer-size to use the default burst", orig)
pkg/cmdtree/tree.go:29://     check, so garbage like `transmit-rate asd` fails loud at commit time
pkg/cmdtree/tree.go:40:	// ValueRate is a Junos bandwidth value (bits/sec) with k/m/g suffix.
pkg/cmdtree/tree.go:42:	ValueRate
pkg/cmdtree/tree.go:43:	// ValueByteSize is a byte-count value with k/m/g suffix.
pkg/cmdtree/tree.go:45:	ValueByteSize
pkg/cmdtree/tree.go:46:	// ValueByteSizeOrPercent is a scheduler buffer size: byte-count with
pkg/cmdtree/tree.go:48:	ValueByteSizeOrPercent
pkg/cmdtree/tree.go:56:	// ValueEnumOf is one of a fixed set of names. The allowed set lives
pkg/cmdtree/tree.go:58:	ValueEnumOf
pkg/cmdtree/tree.go:67:	case ValueRate:
pkg/cmdtree/tree.go:69:	case ValueByteSize:
pkg/cmdtree/tree.go:71:	case ValueByteSizeOrPercent:
pkg/cmdtree/tree.go:79:	case ValueEnumOf:
pkg/cmdtree/tree.go:1005:// ConfigClassOfServiceSchedulers is the per-leaf typed-value schema for
pkg/cmdtree/tree.go:1011:// transmit-rate (rate, optional `exact` modifier), priority (enum),
pkg/cmdtree/tree.go:1012:// and buffer-size (byte-size with optional `temporal` modifier per Junos).
pkg/cmdtree/tree.go:1023:// `transmit-rate asd`.
pkg/cmdtree/tree.go:1024:var ConfigClassOfServiceSchedulers = &Node{
pkg/cmdtree/tree.go:1027:		"transmit-rate": {
pkg/cmdtree/tree.go:1029:			ValueType:     ValueRate,
pkg/cmdtree/tree.go:1037:		"priority": {
pkg/cmdtree/tree.go:1038:			Desc:          "Scheduling priority for this queue",
pkg/cmdtree/tree.go:1039:			ValueType:     ValueEnumOf,
pkg/cmdtree/tree.go:1040:			ValueDesc:     "Scheduler priority (low | medium-low | medium-high | high | strict-high)",
pkg/cmdtree/tree.go:1046:		"buffer-size": {
pkg/cmdtree/tree.go:1048:			ValueType:     ValueByteSizeOrPercent,
pkg/cmdtree/tree.go:1073:				"<scheduler>": ConfigClassOfServiceSchedulers,
pkg/cmdtree/README.md:20:- `ConfigClassOfServiceSchedulers` — `tree.go`. Per-leaf typed-value
pkg/cmdtree/README.md:32:  BEFORE compile so garbage like `transmit-rate asd` fails loud at
pkg/cmdtree/README.md:48:(`transmit-rate`, `priority`, `buffer-size`). Every other Node remains
pkg/cmdtree/README.md:54:`transmit-rate exact` is accepted only as the Junos split-modifier form
pkg/cmdtree/README.md:55:when the same scheduler also has a typed `transmit-rate <rate>` value.
pkg/cmdtree/README.md:59:`buffer-size` accepts byte-size values with explicit `k`/`m`/`g` suffixes
pkg/cmdtree/README.md:64:`buffer-size 50` is ambiguous between bytes and percent. The aggregate
pkg/cmdtree/tree_test.go:124:	if schedulersNode.Children["<scheduler>"] != ConfigClassOfServiceSchedulers {
pkg/cmdtree/tree_test.go:130:	// After `sched transmit-rate`, `?` should show the rate placeholder
pkg/cmdtree/tree_test.go:134:		[]string{"set", "class-of-service", "schedulers", "be", "transmit-rate"},
pkg/cmdtree/tree_test.go:147:	// After `sched transmit-rate 1g`, the value is consumed and `?`
pkg/cmdtree/tree_test.go:151:		[]string{"set", "class-of-service", "schedulers", "be", "transmit-rate", "1g"},
pkg/cmdtree/tree_test.go:163:		[]string{"set", "class-of-service", "schedulers", "be", "priority"},
pkg/cmdtree/tree_test.go:169:			t.Fatalf("expected enum example %q for priority, got %+v", want, cands)
pkg/cmdtree/schema_validate.go:8:// transmit-rate asd` currently compiles to zero bps and commits
pkg/cmdtree/schema_validate.go:47:	schedRoot := ConfigClassOfServiceSchedulers
pkg/cmdtree/schema_validate.go:61://   - hierarchical: `schedulers { be-sched { transmit-rate 7g; ... } }`
pkg/cmdtree/schema_validate.go:63://     leaves like Keys=["transmit-rate","7g"].
pkg/cmdtree/schema_validate.go:66://     transmit-rate 7g` ⇒ Keys=["schedulers","be-sched"] with a chain
pkg/cmdtree/schema_validate.go:67://     of leaf Children Keys=["transmit-rate","7g"].
pkg/cmdtree/schema_validate.go:114:// in Keys[N+] (flat set form: Keys=["transmit-rate","1g","exact"]) or
pkg/cmdtree/schema_validate.go:138:	// Keys[0] is the value (hierarchical shape `transmit-rate 1g;` may
pkg/cmdtree/schema_validate.go:139:	// also appear as Keys=["transmit-rate"] with one child Keys=["1g"]).
pkg/cmdtree/schema_validate.go:151:		if len(leaf.Keys) == 0 || leaf.Keys[0] != "transmit-rate" {
pkg/cmdtree/schema_validate.go:167:// transmit-rate accepts <rate> followed optionally by `exact` — the
pkg/cmdtree/schema_validate.go:168:// chain is [<rate>, "exact"]. priority accepts a single enum value. We
pkg/cmdtree/schema_validate.go:233:	return leafName == "transmit-rate" && tok == "exact"
pkg/cmdtree/schema_validate_test.go:48:		"set class-of-service schedulers be-sched transmit-rate 1g",
pkg/cmdtree/schema_validate_test.go:49:		"set class-of-service schedulers be-sched priority low",
pkg/cmdtree/schema_validate_test.go:50:		"set class-of-service schedulers be-sched buffer-size 10%",
pkg/config/parser_ast_test.go:2867:            loss-priority high then discard;
pkg/config/parser_ast_test.go:2897:            loss-priority high then discard;
pkg/config/compiler_interfaces.go:332:									case "priority":
pkg/config/compiler_interfaces.go:350:									case "track-priority-cost":
pkg/config/parser_cluster_test.go:13:            node 0 priority 100;
pkg/config/parser_cluster_test.go:14:            node 1 priority 1;
pkg/config/parser_cluster_test.go:17:            node 0 priority 100;
pkg/config/parser_cluster_test.go:18:            node 1 priority 1;
pkg/config/parser_cluster_test.go:51:		t.Errorf("rg0 node 0 priority = %d, want 100", rg0.NodePriorities[0])
pkg/config/parser_cluster_test.go:54:		t.Errorf("rg0 node 1 priority = %d, want 1", rg0.NodePriorities[1])
pkg/config/parser_cluster_test.go:72:	commands := []string{"set chassis cluster reth-count 3", "set chassis cluster redundancy-group 0 node 0 priority 100", "set chassis cluster redundancy-group 0 node 1 priority 50", "set chassis cluster redundancy-group 1 node 0 priority 200", "set chassis cluster redundancy-group 1 gratuitous-arp-count 16"}
pkg/config/parser_cluster_test.go:102:		t.Errorf("rg1 node 0 priority = %d, want 200", rg1.NodePriorities[0])
pkg/config/parser_cluster_test.go:118:            node 0 priority 200;
pkg/config/parser_cluster_test.go:119:            node 1 priority 100;
pkg/config/parser_cluster_test.go:123:            node 0 priority 200;
pkg/config/parser_cluster_test.go:124:            node 1 priority 100;
pkg/config/parser_cluster_test.go:166:			t.Errorf("rg%d node 0 priority = %d, want 200", i, rg.NodePriorities[0])
pkg/config/parser_cluster_test.go:169:			t.Errorf("rg%d node 1 priority = %d, want 100", i, rg.NodePriorities[1])
pkg/config/parser_cluster_test.go:178:	commands := []string{"set chassis cluster cluster-id 1", "set chassis cluster node 0", "set chassis cluster heartbeat-interval 500", "set chassis cluster heartbeat-threshold 5", "set chassis cluster reth-count 2", "set chassis cluster redundancy-group 0 node 0 priority 200", "set chassis cluster redundancy-group 0 node 1 priority 100", "set chassis cluster redundancy-group 0 preempt", "set chassis cluster redundancy-group 1 node 0 priority 200", "set chassis cluster redundancy-group 1 node 1 priority 100", "set chassis cluster redundancy-group 1 preempt", "set chassis cluster redundancy-group 1 gratuitous-arp-count 4"}
pkg/config/parser_cluster_test.go:220:			t.Errorf("rg%d node 0 priority = %d, want 200", i, rg.NodePriorities[0])
pkg/config/parser_cluster_test.go:223:			t.Errorf("rg%d node 1 priority = %d, want 100", i, rg.NodePriorities[1])
pkg/config/parser_cluster_test.go:487:            node 0 priority 200;
pkg/config/parser_cluster_test.go:541:	commands := []string{"set chassis cluster cluster-id 1", "set chassis cluster node 0", "set chassis cluster redundancy-group 0 node 0 priority 200", "set chassis cluster redundancy-group 0 ip-monitoring global-weight 255", "set chassis cluster redundancy-group 0 ip-monitoring global-threshold 200", "set chassis cluster redundancy-group 0 ip-monitoring family inet 10.0.1.1 weight 100", "set chassis cluster redundancy-group 0 ip-monitoring family inet 10.0.2.1 weight 80"}
pkg/config/parser_cluster_test.go:592:            node 0 priority 200;
pkg/config/parser_cluster_test.go:593:            node 1 priority 100;
pkg/config/parser_cluster_test.go:596:            node 0 priority 200;
pkg/config/parser_cluster_test.go:597:            node 1 priority 100;
pkg/config/parser_cluster_test.go:627:	commands := []string{"set chassis cluster cluster-id 1", "set chassis cluster reth-count 2", "set chassis cluster redundancy-group 0 node 0 priority 200", "set chassis cluster redundancy-group 0 node 1 priority 100", "set chassis cluster redundancy-group 1 node 0 priority 200", "set chassis cluster redundancy-group 1 node 1 priority 100", "set chassis cluster redundancy-group 1 strict-vip-ownership"}
pkg/config/parser_cluster_test.go:661:            node 0 priority 200;
pkg/config/parser_class_of_service_test.go:18:            transmit-rate 7g;
pkg/config/parser_class_of_service_test.go:19:            priority low;
pkg/config/parser_class_of_service_test.go:20:            buffer-size 16m;
pkg/config/parser_class_of_service_test.go:23:            transmit-rate 3g;
pkg/config/parser_class_of_service_test.go:24:            priority strict-high;
pkg/config/parser_class_of_service_test.go:25:            buffer-size 4m;
pkg/config/parser_class_of_service_test.go:69:		t.Fatalf("ef-sched transmit-rate = %d, want %d", got, parseBandwidthLimit("3g"))
pkg/config/parser_class_of_service_test.go:72:		t.Fatalf("ef-sched priority = %q, want strict-high", got)
pkg/config/parser_class_of_service_test.go:92:		"set class-of-service classifiers dscp wan-classifier forwarding-class best-effort loss-priority low code-points be",
pkg/config/parser_class_of_service_test.go:93:		"set class-of-service classifiers ieee-802.1 wan-pcp forwarding-class best-effort loss-priority low code-points 0",
pkg/config/parser_class_of_service_test.go:94:		"set class-of-service schedulers be-sched transmit-rate 5g",
pkg/config/parser_class_of_service_test.go:95:		"set class-of-service schedulers be-sched transmit-rate exact",
pkg/config/parser_class_of_service_test.go:96:		"set class-of-service schedulers be-sched priority low",
pkg/config/parser_class_of_service_test.go:97:		"set class-of-service schedulers be-sched buffer-size 8m",
pkg/config/parser_class_of_service_test.go:105:		"set class-of-service rewrite-rules dscp wan-rewrite forwarding-class best-effort loss-priority low code-point ef",
pkg/config/parser_class_of_service_test.go:143:		t.Fatal("expected be-sched transmit-rate exact")
pkg/config/parser_class_of_service_test.go:173:		"set class-of-service schedulers be-sched transmit-rate 5g",
pkg/config/parser_class_of_service_test.go:174:		"set class-of-service schedulers be-sched buffer-size 10%",
pkg/config/parser_class_of_service_test.go:207:		"set class-of-service schedulers be-sched buffer-size 75%",
pkg/config/parser_class_of_service_test.go:208:		"set class-of-service schedulers ef-sched buffer-size 75%",
pkg/config/parser_class_of_service_test.go:224:		t.Fatal("expected aggregate percent buffer-size error, got nil")
pkg/config/parser_class_of_service_test.go:226:	for _, want := range []string{"sum of buffer-size percent", "150", "100"} {
pkg/config/parser_class_of_service_test.go:238:		"set class-of-service schedulers be-sched buffer-size 25%",
pkg/config/parser_class_of_service_test.go:239:		"set class-of-service schedulers ef-sched buffer-size 75%",
pkg/config/parser_class_of_service_test.go:272:				"set class-of-service schedulers ef-sched transmit-rate 10m",
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
pkg/config/parser_class_of_service_test.go:690:		t.Fatalf("transmit-rate = %d, want %d", got, parseBandwidthLimit("5g"))
pkg/config/parser_class_of_service_test.go:693:		t.Fatal("expected inline transmit-rate exact")
pkg/config/parser_class_of_service_test.go:700:		"set class-of-service schedulers iperf-a transmit-rate 10.0g",
pkg/config/parser_class_of_service_test.go:701:		"set class-of-service schedulers iperf-a transmit-rate exact",
pkg/config/parser_class_of_service_test.go:726:		t.Fatalf("transmit-rate = %d, want %d", got, parseBandwidthLimit("10.0g"))
pkg/config/parser_class_of_service_test.go:729:		t.Fatal("expected transmit-rate exact")
pkg/config/parser_class_of_service_test.go:737:		"set class-of-service schedulers iperf-a transmit-rate 1g exact",
pkg/config/parser_class_of_service_test.go:763:		t.Fatal("expected transmit-rate exact")
pkg/config/parser_class_of_service_test.go:778:            transmit-rate 1g exact;
pkg/config/parser_class_of_service_test.go:822:// without transmit-rate exact (#1183 lesson — runtime never sees
pkg/config/parser_class_of_service_test.go:827:		"set class-of-service schedulers iperf-a transmit-rate 1g",
pkg/config/parser_class_of_service_test.go:873:// the sum of exact-class transmit-rates on an interface unit exceeds
pkg/config/parser_class_of_service_test.go:882:		"set class-of-service schedulers iperf-a transmit-rate 12g",
pkg/config/parser_class_of_service_test.go:883:		"set class-of-service schedulers iperf-a transmit-rate exact",
pkg/config/parser_class_of_service_test.go:884:		"set class-of-service schedulers iperf-b transmit-rate 9g",
pkg/config/parser_class_of_service_test.go:885:		"set class-of-service schedulers iperf-b transmit-rate exact",
pkg/config/parser_class_of_service_test.go:909:		if strings.Contains(w, "sum of exact-class transmit-rates") &&
pkg/config/parser_class_of_service_test.go:928:		"set class-of-service schedulers iperf-a transmit-rate 12g",
pkg/config/parser_class_of_service_test.go:929:		"set class-of-service schedulers iperf-a transmit-rate exact",
pkg/config/parser_class_of_service_test.go:930:		"set class-of-service schedulers iperf-b transmit-rate 9g",
pkg/config/parser_class_of_service_test.go:931:		"set class-of-service schedulers iperf-b transmit-rate exact",
pkg/config/parser_class_of_service_test.go:955:		if strings.Contains(w, "sum of exact-class transmit-rates") &&
pkg/config/parser_class_of_service_test.go:992:                loss-priority low {
pkg/config/parser_class_of_service_test.go:999:                loss-priority low {
pkg/config/parser_class_of_service_test.go:1030:                loss-priority low {
pkg/config/parser_class_of_service_test.go:1069:	if !strings.Contains(warnings, "dscp/802.1p classifier loss-priority is accepted for compatibility but not yet enforced") {
pkg/config/parser_class_of_service_test.go:1070:		t.Fatalf("expected classifier loss-priority warning, got: %s", warnings)
pkg/config/parser_class_of_service_test.go:1072:	if !strings.Contains(warnings, "dscp rewrite-rule loss-priority is accepted for compatibility but not yet enforced") {
pkg/config/parser_class_of_service_test.go:1073:		t.Fatalf("expected rewrite-rule loss-priority warning, got: %s", warnings)
pkg/config/parser_class_of_service_test.go:1089:                loss-priority low {
pkg/config/parser_class_of_service_test.go:1094:                loss-priority low {
pkg/config/parser_class_of_service_test.go:1150:                loss-priority low {
pkg/config/parser_class_of_service_test.go:1155:                loss-priority low {
pkg/config/parser_class_of_service_test.go:1211:                loss-priority low {
pkg/config/parser_class_of_service_test.go:1216:                loss-priority low {
pkg/config/parser_class_of_service_test.go:1306:		"set class-of-service schedulers scheduler-iperf-b transmit-rate 10g",
pkg/config/parser_class_of_service_test.go:1307:		"set class-of-service schedulers scheduler-iperf-b transmit-rate exact",
pkg/config/parser_class_of_service_test.go:1308:		"set class-of-service schedulers scheduler-iperf-c transmit-rate 25g",
pkg/config/parser_class_of_service_test.go:1309:		"set class-of-service schedulers scheduler-iperf-c transmit-rate exact",
pkg/config/parser_class_of_service_test.go:1403:		"set class-of-service schedulers scheduler-iperf-a transmit-rate 1g",
pkg/config/parser_class_of_service_test.go:1404:		"set class-of-service schedulers scheduler-iperf-a transmit-rate exact",
pkg/config/schema_validators.go:49:// consumes. Reject bare integers here so `buffer-size 50` cannot pass
pkg/config/schema_validators.go:65:// ValidateByteSizeOrPercent accepts the two scheduler buffer-size forms
pkg/config/schema_validators.go:74:			return fmt.Errorf("not a valid percent buffer-size (expected >0%%..100%%; xpf rejects Junos 0%% because zero is the legacy absent-field value): %w", err)
pkg/config/schema_validators.go:103:	// indistinguishable from "no buffer-size configured" -- the runtime
pkg/config/schema_validators.go:108:		return 0, fmt.Errorf("percent out of range (0,100] (got %s); note: 0%% is not supported -- omit buffer-size to use the default burst", orig)
pkg/config/compiler_firewall.go:48:				case "loss-priority":
pkg/config/compiler_firewall.go:50:						pol.ThenAction = "loss-priority " + v
pkg/config/compiler_firewall.go:149:				case "loss-priority":
pkg/config/compiler_firewall.go:151:						tcp.ThenAction = "loss-priority " + v
pkg/config/compiler_firewall.go:427:		case "loss-priority":
pkg/config/compiler_protocols.go:852:// reject `transmit-rate asd` instead of writing 0 bps under the hood.
pkg/config/compiler.go:429:				"class-of-service scheduler %q equal-flow-enforcement requires positive transmit-rate exact",
pkg/config/compiler.go:437:		// Both buffer-size forms set simultaneously is ambiguous. The compiler
pkg/config/compiler.go:439:		// buffer-size case), so this can only arise in constructed or
pkg/config/compiler.go:444:				"class-of-service scheduler %q has both buffer-size bytes (%d) "+
pkg/config/compiler.go:445:					"and buffer-size percent (%.4g%%) set; use one form only",
pkg/config/compiler.go:479:					"sum of buffer-size percent across all schedulers is %.4g%% "+
pkg/config/compiler.go:913:		// #915: surplus-sharing is meaningful only on transmit-rate
pkg/config/compiler.go:922:					"class-of-service scheduler %q surplus-sharing is meaningful only with transmit-rate exact; ignored",
pkg/config/compiler.go:961:					warnings = append(warnings, "class-of-service dscp/802.1p classifier loss-priority is accepted for compatibility but not yet enforced by the userspace dataplane")
pkg/config/compiler.go:980:					warnings = append(warnings, "class-of-service dscp/802.1p classifier loss-priority is accepted for compatibility but not yet enforced by the userspace dataplane")
pkg/config/compiler.go:999:					warnings = append(warnings, "class-of-service dscp rewrite-rule loss-priority is accepted for compatibility but not yet enforced by the userspace dataplane")
pkg/config/compiler.go:1051:		// interface unit's exact-class transmit-rates exceeds the
pkg/config/compiler.go:1105:				"class-of-service interfaces %s unit %d: sum of exact-class transmit-rates (%d B/s) exceeds shaping-rate (%d B/s); under oversubscription the configured oversubscription-policy=%s",
pkg/config/compiler_class_of_service.go:133:				for _, lpNode := range fcNode.FindChildren("loss-priority") {
pkg/config/compiler_class_of_service.go:166:				for _, lpNode := range fcNode.FindChildren("loss-priority") {
pkg/config/compiler_class_of_service.go:202:				for _, lpNode := range fcNode.FindChildren("loss-priority") {
pkg/config/compiler_class_of_service.go:231:			case "transmit-rate":
pkg/config/compiler_class_of_service.go:237:			case "priority":
pkg/config/compiler_class_of_service.go:239:			case "buffer-size":
pkg/config/compiler_class_of_service.go:381:			// #1614 A2: priority-low-min-share <bps>
pkg/config/compiler_class_of_service.go:382:			if minShareNode := unitNode.FindChild("priority-low-min-share"); minShareNode != nil {
pkg/config/compiler_system.go:970:				// node <id> priority <value>
pkg/config/compiler_system.go:977:				// Look for "priority" in inline keys or children
pkg/config/compiler_system.go:979:					if child.Keys[i] == "priority" {
pkg/config/compiler_system.go:985:				if priNode := child.FindChild("priority"); priNode != nil {
pkg/config/compiler_test.go:17://     equal-flow-enforcement` without `transmit-rate exact`
pkg/config/compiler_test.go:177://   - CoS: equal-flow-enforcement without transmit-rate exact
pkg/config/README.md:40:  `transmit-rate asd` fails loud instead of silently zeroing in the
pkg/config/README.md:41:  existing parsers. Scheduler `buffer-size` validation accepts byte
pkg/config/ast.go:1117:					"priority": {args: 1, children: nil},
pkg/config/ast.go:1141:					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1148:					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1157:					"loss-priority": {args: 1, multi: true, children: map[string]*schemaNode{
pkg/config/ast.go:1165:			"transmit-rate": {args: 1, children: map[string]*schemaNode{
pkg/config/ast.go:1168:			"priority":               {args: 1, children: nil},
pkg/config/ast.go:1169:			"buffer-size":            {args: 1, children: nil},
pkg/config/ast.go:1218:				"loss-priority": {args: 1, children: nil},
pkg/config/ast.go:1239:				"loss-priority": {args: 1, children: nil},
pkg/config/ast.go:1279:							"loss-priority":    {args: 1, children: nil},
pkg/config/ast.go:1323:							"loss-priority":    {args: 1, children: nil},
pkg/config/types.go:306:	NodePriorities     map[int]int // node-id -> priority
pkg/config/types.go:508:	// transmit-rate exact queues so they can draw from the root
pkg/config/types.go:513:	// EqualFlowEnforcement opts a positive transmit-rate exact
pkg/config/types.go:515:	// Validation fails closed unless the scheduler has transmit-rate
pkg/config/types.go:557:	// behaviour when sum of exact-class transmit-rates exceeds the
pkg/config/types.go:568:	// PriorityLowMinShareBytes (#1614 A2) is the priority-low
pkg/config/types.go:1065:	ThenAction              string // "discard" or "loss-priority high/medium-high/medium-low/low"
pkg/config/types.go:1084:	ThenAction           string // action on exceed/violate: "discard" or "loss-priority"
pkg/config/types.go:1113:	LossPriority      string           // loss-priority (low, medium-low, medium-high, high)
pkg/config/types.go:1637:	TrackInterface     string // lower priority if interface is down
pkg/config/types.go:1638:	TrackPriorityDelta int    // how much to lower priority
pkg/config/schema_validate_test.go:50:            transmit-rate asd;
pkg/config/schema_validate_test.go:55:		t.Fatal("expected error for transmit-rate asd, got nil")
pkg/config/schema_validate_test.go:57:	if !strings.Contains(err.Error(), "transmit-rate") {
pkg/config/schema_validate_test.go:58:		t.Fatalf("error should reference transmit-rate: %v", err)
pkg/config/schema_validate_test.go:69:            transmit-rate 1g;
pkg/config/schema_validate_test.go:81:            transmit-rate 1g {
pkg/config/schema_validate_test.go:93:		"set class-of-service schedulers be transmit-rate 1g",
pkg/config/schema_validate_test.go:94:		"set class-of-service schedulers be transmit-rate exact",
pkg/config/schema_validate_test.go:101:	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate exact")
pkg/config/schema_validate_test.go:103:		t.Fatal("expected error for transmit-rate exact without a sibling rate, got nil")
pkg/config/schema_validate_test.go:105:	if !strings.Contains(err.Error(), "transmit-rate") {
pkg/config/schema_validate_test.go:106:		t.Fatalf("error should reference transmit-rate: %v", err)
pkg/config/schema_validate_test.go:114:            transmit-rate 1;
pkg/config/schema_validate_test.go:119:		t.Fatal("expected error for transmit-rate 1, got nil")
pkg/config/schema_validate_test.go:124:	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate")
pkg/config/schema_validate_test.go:126:		t.Fatal("expected error for transmit-rate with no value, got nil")
pkg/config/schema_validate_test.go:134:	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate 1g typo")
pkg/config/schema_validate_test.go:136:		t.Fatal("expected error for unknown transmit-rate modifier, got nil")
pkg/config/schema_validate_test.go:147:            priority strict-high;
pkg/config/schema_validate_test.go:159:            priority foo;
pkg/config/schema_validate_test.go:164:		t.Fatal("expected error for priority foo, got nil")
pkg/config/schema_validate_test.go:166:	if !strings.Contains(err.Error(), "priority") {
pkg/config/schema_validate_test.go:167:		t.Fatalf("error should reference priority: %v", err)
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
pkg/config/schema_validate_test.go:280:// + tree.SetPath produces: Keys=["schedulers","be","transmit-rate","1g"]
pkg/config/schema_validate_test.go:281:// (when input is `set class-of-service schedulers be transmit-rate 1g`).
pkg/config/schema_validate_test.go:283:	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate asd")
pkg/config/schema_validate_test.go:285:		t.Fatal("expected error for flat-set transmit-rate asd, got nil")
pkg/config/schema_validate_test.go:287:	if !strings.Contains(err.Error(), "transmit-rate") {
pkg/config/schema_validate_test.go:288:		t.Fatalf("error should reference transmit-rate: %v", err)
pkg/config/schema_validate_test.go:294:		"set class-of-service schedulers be transmit-rate 1g",
pkg/config/schema_validate_test.go:295:		"set class-of-service schedulers be priority strict-high",
pkg/config/schema_validate_test.go:296:		"set class-of-service schedulers be buffer-size 16m",
pkg/config/schema_validate_test.go:306:		"set class-of-service schedulers be transmit-rate 8",
pkg/config/schema_validate_test.go:307:		"set class-of-service schedulers be transmit-rate exact",
pkg/config/schema_validate_test.go:308:		"set class-of-service schedulers be buffer-size 16m",
pkg/config/schema_validate_test.go:331:		t.Fatalf("transmit-rate bytes/sec = %d, want 1", got)
pkg/config/schema_validate_test.go:334:		t.Fatal("expected transmit-rate exact")
pkg/config/schema_validate_test.go:337:		t.Fatalf("buffer-size bytes = %d, want 16000000", got)
pkg/config/schema_validate_test.go:344:		"set class-of-service schedulers be transmit-rate 8",
pkg/config/schema_validate_test.go:345:		"set class-of-service schedulers be buffer-size 10%",
pkg/config/schema_validate_test.go:368:		t.Fatalf("buffer-size percent = %v, want 10", got)
pkg/config/schema_validate_test.go:371:		t.Fatalf("buffer-size bytes = %d, want 0 for percent form", got)
pkg/config/schema_validate_test.go:378:	// `buffer-size purple` under a different parent should not error

exec
/bin/bash -lc "nl -ba pkg/cmdtree/README.md | sed -n '1,90p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
     1	# pkg/cmdtree
     2	
     3	Single source of truth for every CLI command tree (operational +
     4	configuration). Used by the local CLI, the remote CLI, and the gRPC
     5	tab-completion RPC. Adding a command here automatically propagates to all
     6	three frontends.
     7	
     8	## Entry points
     9	
    10	- `Node` — `tree.go`. Tree node: description, static children,
    11	  `DynamicFn`/`ContextDynamicFn` for config-aware completions. Optional
    12	  typed-leaf fields (`ValueType`, `ValueDesc`, `ValueExamples`,
    13	  `Validator`) describe the value a leaf accepts — see "Typed leaves"
    14	  below.
    15	- `Candidate` — `tree.go`. `(name, desc)` pair surfaced during tab
    16	  completion.
    17	- `OperationalTree` — `tree.go`. Canonical root for `show`, `clear`,
    18	  `request`, `monitor`, `ping`, `traceroute`, etc.
    19	- `ConfigTopLevel` — root for the `set`/`delete` configuration grammar.
    20	- `ConfigClassOfServiceSchedulers` — `tree.go`. Per-leaf typed-value
    21	  schema for `set class-of-service schedulers <name> { ... }` (#1319
    22	  Phase 2). Reused by the config-mode `set` completion tree and by
    23	  `SchemaValidate`.
    24	- `KeysFromTree(tree)` — `tree.go`. Used by `pkg/cli` and `pkg/grpcapi`
    25	  for Junos-style prefix matching.
    26	- `WriteHelp`, `LookupDesc`, `PrintTreeHelp`, `CompleteFromTree` — the
    27	  helper API the three frontends consume.
    28	- `SchemaValidate(tree, cfg)` — `schema_validate.go`. The commit-check
    29	  gate (#1319). Walks the AST against typed-leaf cmdtree Nodes and
    30	  invokes their `Validator` on each value; called by
    31	  `pkg/configstore.compileTree` against an apply-groups-expanded clone
    32	  BEFORE compile so garbage like `transmit-rate asd` fails loud at
    33	  `commit check`, including when it arrives through `groups { ... }`.
    34	
    35	## Typed leaves (#1319)
    36	
    37	A `Node` with `ValueType != ValueAny` is a typed leaf: it expects
    38	exactly one value of the declared kind at the next slot.
    39	
    40	- `?` completion surfaces `ValueDesc` + `ValueExamples` so the operator
    41	  sees what's accepted instead of an empty cursor.
    42	- `SchemaValidate` invokes the leaf's `Validator` at commit-check.
    43	  Validators are stateless string-checkers (`config.ValidateRate`,
    44	  `config.ValidateByteSize`, ...) declared in `pkg/config` so they
    45	  share the same parsers the compiler uses.
    46	
    47	This PR ships typed leaves only for `class-of-service schedulers`
    48	(`transmit-rate`, `priority`, `buffer-size`). Every other Node remains
    49	on `ValueAny` (zero value) — no behaviour change. Leaves are only typed
    50	when the compiler consumes them today; scheduler-level `shaping-rate`
    51	is intentionally not listed because shaping is implemented under
    52	`class-of-service interfaces ... unit ... shaping-rate`.
    53	
    54	`transmit-rate exact` is accepted only as the Junos split-modifier form
    55	when the same scheduler also has a typed `transmit-rate <rate>` value.
    56	An exact-only scheduler line still fails commit-check because the compiler
    57	would otherwise treat it as exact-with-zero-rate.
    58	
    59	`buffer-size` accepts byte-size values with explicit `k`/`m`/`g` suffixes
    60	or Junos percent values with an explicit `%` suffix. Percent values are
    61	compiled into a distinct `buffer_size_percent` snapshot field (#1336);
    62	the userspace runtime converts them to bytes per interface using the
    63	resolved CoS burst pool. Bare integers remain rejected because
    64	`buffer-size 50` is ambiguous between bytes and percent. The aggregate
    65	percent buffers for scheduler-map entries bound to one interface unit
    66	must be `<= 100%`. xpf also rejects Junos `0%` because zero is the
    67	legacy absent-field value on the additive userspace protocol field.
    68	
    69	Adding a new typed subtree means:
    70	
    71	1. populate `ValueType` + `Validator` on the relevant Node(s);
    72	2. add a small walker entry to `schema_validate.go` (one per top-level
    73	   subtree we want gated);
    74	3. nothing else — no compiler changes, no parser changes.
    75	
    76	## Callers
    77	
    78	`pkg/cli`, `pkg/grpcapi`, `cmd/cli`.
    79	
    80	## Dependencies
    81	
    82	`pkg/config` only.
    83	
    84	## Gotchas
    85	
    86	- `DynamicFn` and `ContextDynamicFn` run inside the interactive readline
    87	  loop — they must not block on I/O, locks held by long operations, or
    88	  network calls. Snapshot the candidate config once; iterate.
    89	- `ContextDynamicFn` receives the words consumed so far, so completions
    90	  can depend on earlier args (e.g. zone-pair → policy-name suggestions).

exec
/bin/bash -lc "nl -ba pkg/config/schema_validators.go | sed -n '1,180p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
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
    46	}
    47	
    48	// validateByteSize accepts the byte-size form the current CoS compiler
    49	// consumes. Reject bare integers here so `buffer-size 50` cannot pass
    50	// validation and compile as a 50-byte queue.
    51	func ValidateByteSize(raw string, _ *Config) error {
    52		trimmed := strings.TrimSpace(raw)
    53		if trimmed == "" {
    54			return fmt.Errorf("missing value (expected byte-size with k/m/g suffix, e.g. 16m)")
    55		}
    56		if _, err := strconv.ParseUint(trimmed, 10, 64); err == nil {
    57			return fmt.Errorf("bare byte-size %q is ambiguous; use an explicit suffix like 50k or 16m", raw)
    58		}
    59		if _, err := parseBurstSizeLimitStrict(trimmed); err != nil {
    60			return fmt.Errorf("not a valid byte-size (expected 16m, 256k, or 1g): %w", err)
    61		}
    62		return nil
    63	}
    64	
    65	// ValidateByteSizeOrPercent accepts the two scheduler buffer-size forms
    66	// that the CoS runtime can represent: explicit byte sizes with k/m/g
    67	// suffixes, or Junos percent values with a trailing percent sign. Bare
    68	// integers stay rejected because they are ambiguous between bytes and
    69	// percent.
    70	func ValidateByteSizeOrPercent(raw string, _ *Config) error {
    71		trimmed := strings.TrimSpace(raw)
    72		if strings.HasSuffix(trimmed, "%") {
    73			if _, err := parsePercentWithSuffixStrict(trimmed); err != nil {
    74				return fmt.Errorf("not a valid percent buffer-size (expected >0%%..100%%; xpf rejects Junos 0%% because zero is the legacy absent-field value): %w", err)
    75			}
    76			return nil
    77		}
    78		return ValidateByteSize(raw, nil)
    79	}
    80	
    81	func parsePercentWithSuffixStrict(raw string) (float64, error) {
    82		orig := raw
    83		trimmed := strings.TrimSpace(raw)
    84		if trimmed == "" {
    85			return 0, fmt.Errorf("empty value")
    86		}
    87		if !strings.HasSuffix(trimmed, "%") {
    88			return 0, fmt.Errorf("missing percent suffix in %q", orig)
    89		}
    90		number := strings.TrimSpace(strings.TrimSuffix(trimmed, "%"))
    91		if number == "" {
    92			return 0, fmt.Errorf("empty percent in %q", orig)
    93		}
    94		v, err := strconv.ParseFloat(number, 64)
    95		if err != nil {
    96			return 0, fmt.Errorf("invalid percent %q: %w", orig, err)
    97		}
    98		if math.IsNaN(v) || math.IsInf(v, 0) {
    99			return 0, fmt.Errorf("invalid percent %q: non-finite", orig)
   100		}
   101		// xpf intentionally rejects 0% even though Junos allows it.
   102		// A 0% buffer allocation compiles to zero bytes at runtime and is
   103		// indistinguishable from "no buffer-size configured" -- the runtime
   104		// would silently fall back to the default 10 ms burst calculation.
   105		// Using the default path directly is unambiguous; disallowing 0%
   106		// avoids silent no-op configs that look correct but do nothing.
   107		if v <= 0 || v > 100 {
   108			return 0, fmt.Errorf("percent out of range (0,100] (got %s); note: 0%% is not supported -- omit buffer-size to use the default burst", orig)
   109		}
   110		return v, nil
   111	}
   112	
   113	// validateInteger returns a closure that accepts a bare integer in
   114	// [min, max] inclusive. min > max disables the range check.
   115	func ValidateInteger(min, max int64) LeafValidator {
   116		return func(raw string, _ *Config) error {
   117			if strings.TrimSpace(raw) == "" {
   118				return fmt.Errorf("missing value (expected integer)")
   119			}
   120			v, err := strconv.ParseInt(raw, 10, 64)
   121			if err != nil {
   122				return fmt.Errorf("not an integer: %q", raw)
   123			}
   124			if min <= max && (v < min || v > max) {
   125				return fmt.Errorf("integer out of range [%d..%d] (got %d)", min, max, v)
   126			}
   127			return nil
   128		}
   129	}
   130	
   131	// validateEnum returns a closure that accepts only one of the listed
   132	// names (case-sensitive, exact match).
   133	func ValidateEnum(allowed []string) LeafValidator {
   134		sorted := append([]string(nil), allowed...)
   135		sort.Strings(sorted)
   136		set := make(map[string]struct{}, len(sorted))
   137		for _, a := range sorted {
   138			set[a] = struct{}{}
   139		}
   140		return func(raw string, _ *Config) error {
   141			if _, ok := set[raw]; ok {
   142				return nil
   143			}
   144			return fmt.Errorf("invalid value %q (expected one of: %s)", raw, strings.Join(sorted, ", "))
   145		}
   146	}
   147	
   148	// validatePercent returns a closure that accepts a real number in
   149	// [min, max] inclusive. The input must parse as a float.
   150	func ValidatePercent(min, max float64) LeafValidator {
   151		return func(raw string, _ *Config) error {
   152			if strings.TrimSpace(raw) == "" {
   153				return fmt.Errorf("missing value (expected percent %.0f..%.0f)", min, max)
   154			}
   155			v, err := strconv.ParseFloat(raw, 64)
   156			if err != nil {
   157				return fmt.Errorf("not a number: %q", raw)
   158			}
   159			if v < min || v > max {
   160				return fmt.Errorf("percent out of range [%.2f..%.2f] (got %s)", min, max, raw)
   161			}
   162			return nil
   163		}
   164	}

exec
/bin/bash -lc "nl -ba pkg/config/README.md | sed -n '1,80p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
     1	# pkg/config
     2	
     3	Junos configuration parser, AST, typed data model, and compilation
     4	pipeline. Three phases: text → AST (`ConfigTree`) → typed `Config` struct.
     5	Handles both hierarchical (`family inet { dhcp; }`) and flat set
     6	(`set interfaces eth0 unit 0 family inet dhcp`) syntaxes.
     7	
     8	This is the foundation almost every other package imports. It depends on
     9	nothing internal.
    10	
    11	## Entry points
    12	
    13	- `Lexer` — `lexer.go`.
    14	- `Parser` — `parser.go`. **Hierarchical** input.
    15	- `ParseSetCommand(input string) ([]string, error)` — `parser.go`.
    16	  Parses one flat-set line into the path components. The caller then
    17	  applies that path with `tree.SetPath()` to build the AST.
    18	- `ConfigTree` — `ast.go`. Hierarchical node tree built by both shapes.
    19	- `Config` — `types.go`. The fully typed result every consumer wants.
    20	- `CompileConfig(tree) (*Config, error)` — `compiler.go`. AST-to-typed-
    21	  struct walker. Clones the tree, expands `apply-groups` (with
    22	  `${node}` fallback for cluster mode), then dispatches over AST
    23	  nodes via a switch statement to fill the typed `Config`. Eleven
    24	  `compiler*.go` files in this package, ~7.6K LOC total
    25	  (`compiler.go` + `compiler_interfaces.go`, `compiler_routing.go`,
    26	  `compiler_security.go`, `compiler_services.go`, `compiler_system.go`,
    27	  `compiler_firewall.go`, `compiler_nat.go`, `compiler_ipsec.go`,
    28	  `compiler_protocols.go`, `compiler_class_of_service.go`).
    29	  Note: this is the **AST → typed Go struct** stage; the BPF-map
    30	  compilation (zones, policies, NAT IDs, etc.) happens later in
    31	  `pkg/dataplane.Manager.Compile`.
    32	- `Validate*` functions — `schema_validators.go`. Stateless string
    33	  validators (`ValidateRate`, `ValidateByteSize`,
    34	  `ValidateByteSizeOrPercent`,
    35	  `ValidateInteger(min,max)`, `ValidateEnum(allowed)`,
    36	  `ValidatePercent(min,max)`) for the #1319 typed-leaf gate. Attached
    37	  to `cmdtree.Node.Validator` fields and dispatched by
    38	  `cmdtree.SchemaValidate` at commit-check time, on the same
    39	  apply-groups-expanded tree the compiler consumes, so garbage like
    40	  `transmit-rate asd` fails loud instead of silently zeroing in the
    41	  existing parsers. Scheduler `buffer-size` validation accepts byte
    42	  sizes with explicit suffixes and percent values with an explicit `%`
    43	  suffix. The compiler stores percent values separately from
    44	  `BufferSizeBytes`; the userspace snapshot adds `buffer_size_percent`
    45	  while preserving the legacy `buffer_size_bytes` field. The Rust
    46	  userspace dataplane resolves percent buffers against the interface CoS
    47	  burst pool when a scheduler is bound to an interface queue. The strict
    48	  config pass rejects scheduler-map percent totals above 100% on one
    49	  interface unit. xpf rejects Junos `0%` intentionally because the
    50	  additive wire field uses zero as the legacy absent value.
    51	  `parseBandwidthLimitStrict` / `parseBurstSizeLimitStrict` /
    52	  `parseScaledDecimalUnitStrict` in `compiler_protocols.go` are the
    53	  error-returning siblings of the legacy zero-return parsers — the legacy
    54	  versions keep their "unset = 0" contract for compatibility.
    55	
    56	## Callers
    57	
    58	Almost everyone. The package has no internal dependencies.
    59	
    60	## Gotchas
    61	
    62	The compiler must accept both AST shapes:
    63	
    64	- Hierarchical `family inet { dhcp; }` lowers to `Node{Keys:["family","inet"]}`
    65	  with a child `Node{Keys:["dhcp"]}`.
    66	- Flat `set interfaces eth0 unit 0 family inet dhcp` lowers to
    67	  `Node{Keys:["family"]}` with child `Node{Keys:["inet"]}`.
    68	
    69	If you only handle one shape, set-syntax tests will look fine but real
    70	hierarchical commits will break (or vice versa).
    71	
    72	**Testing flat-set syntax:** ALWAYS use `ParseSetCommand()` + a
    73	`tree.SetPath()` loop, NEVER `NewParser()` on a multi-line set blob. The
    74	parser treats newlines as whitespace and merges multiple set lines into
    75	one giant node. This trap has bitten the project repeatedly — see
    76	CLAUDE.md.
    77	
    78	**C struct alignment:** when mirroring C BPF structs in Go, match `sizeof`
    79	exactly with trailing `Pad [N]byte` fields. cilium/ebpf serializes map
    80	values in native endian, not big-endian, so use `binary.NativeEndian`

exec
/bin/bash -lc "rg -n \"cmdtree|single source|SSOT|source of truth|SetPath|setSchema|schema_validate|SchemaValidate|CompleteSetPath\" CLAUDE.md pkg/cmdtree/README.md pkg/config/README.md docs -g '*.md'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/config/README.md:17:  applies that path with `tree.SetPath()` to build the AST.
pkg/config/README.md:37:  to `cmdtree.Node.Validator` fields and dispatched by
pkg/config/README.md:38:  `cmdtree.SchemaValidate` at commit-check time, on the same
pkg/config/README.md:73:`tree.SetPath()` loop, NEVER `NewParser()` on a multi-line set blob. The
CLAUDE.md:141:- **Command Trees** — `pkg/cmdtree/tree.go` is single source of truth for all CLI command trees, tab completion, and `?` help across local CLI, remote CLI, and gRPC server
CLAUDE.md:148:| `pkg/cmdtree/` | Single source of truth for all CLI command trees |
CLAUDE.md:193:- **Testing flat set syntax:** ALWAYS use `ParseSetCommand()` + `tree.SetPath()` loop, NEVER `NewParser()` — the parser treats newlines as whitespace and will merge all set lines into one giant node
pkg/cmdtree/README.md:1:# pkg/cmdtree
pkg/cmdtree/README.md:3:Single source of truth for every CLI command tree (operational +
pkg/cmdtree/README.md:23:  `SchemaValidate`.
pkg/cmdtree/README.md:28:- `SchemaValidate(tree, cfg)` — `schema_validate.go`. The commit-check
pkg/cmdtree/README.md:29:  gate (#1319). Walks the AST against typed-leaf cmdtree Nodes and
pkg/cmdtree/README.md:42:- `SchemaValidate` invokes the leaf's `Validator` at commit-check.
pkg/cmdtree/README.md:72:2. add a small walker entry to `schema_validate.go` (one per top-level
docs/userspace-capture-plan.md:458:| `pkg/cmdtree/tree.go` | `monitor traffic` command |
docs/shared-umem-plan.md:338:runtime source of truth is the actual worker-local bind result.
docs/fairness-regimes.md:962:source of truth for the contract. Updates require:
docs/memory.md:59:- **Single source of truth:** `pkg/cmdtree/tree.go` defines `OperationalTree` and `ConfigTopLevel`
docs/memory.md:60:  - `pkg/cli` imports via type alias `completionNode = cmdtree.Node`
docs/memory.md:61:  - `pkg/grpcapi` imports `cmdtree.CompleteFromTree()` directly
docs/memory.md:62:  - `cmd/cli` imports `cmdtree.LookupDesc()` and `cmdtree.PrintTreeHelp()`
docs/memory.md:63:  - Adding a command to `pkg/cmdtree/tree.go` auto-propagates to ALL CLIs
docs/memory.md:65:- **Junos-style prefix matching:** `resolveCommand()` + `cmdtree.KeysFromTree()` — no hardcoded lists
docs/memory.md:67:- **Tab descriptions:** Multi-match tab shows descriptions above prompt via `cmdtree.WriteHelp()`
docs/memory.md:120:- **Flat set tests:** Use `ParseSetCommand()` + `tree.SetPath()`, NOT `NewParser()` (newlines are whitespace in parser)
docs/engineering-style.md:25:3. **One source of truth for every formula.** If two code paths compute
docs/refactoring-audit.md:102:single source of truth for which files are `[REFACTOR]`/`[WATCH]` tier.
docs/feature-gaps.md:184:| **Session Limiting (source-ip)** | `security screen ids-option ... limit-session source-ip-based N` | Limit max concurrent sessions from single source IP (1-8M). Prevents session table exhaustion. | High | **Done** -- GC sweep counts active sessions per source IP, pushes to BPF LRU maps, xdp_screen enforces limits on TCP SYN. |
docs/userspace-ha-validation.md:268:as the source of truth.
docs/ha-cluster-test-plan.md:28:per-node configuration from a single source file.
docs/phases.md:306:- Test fix: flat set syntax tests must use `ParseSetCommand()` + `SetPath()`, NOT `NewParser()`
docs/phases.md:317:- cmdtree package extracted as single source of truth for all CLI trees
docs/phases.md:430:- cmdtree updated with `brief` and `interface` entries under session
docs/phases.md:516:- All wired to local CLI, remote CLI, gRPC, cmdtree
docs/phases.md:586:  - cmdtree entry under operational tree
docs/phases.md:588:- Files: pkg/dhcp/dhcp.go, pkg/daemon/daemon.go, pkg/cli/cli.go, pkg/grpcapi/server.go, pkg/frr/frr.go, cmd/cli/main.go, pkg/cmdtree/tree.go, pkg/dataplane/compiler.go, proto/xpf/v1/xpf.proto
docs/phases.md:617:  - `show snmp v3` CLI command, gRPC snmp-v3 topic, cmdtree entry
docs/phases.md:620:  - Files: pkg/snmp/v3.go, pkg/snmp/agent.go, pkg/config/types.go, pkg/config/compiler.go, pkg/cli/cli.go, pkg/grpcapi/server.go, pkg/cmdtree/tree.go
docs/phases.md:646:- Files: 24 files, 1879 insertions — pkg/lldp/, pkg/api/auth.go, bpf/{headers,xdp,tc}/, pkg/{config,cli,cmdtree,daemon,dataplane,grpcapi}/
docs/phases.md:649:- **Session sorting/top-talkers:** Sort by bytes or packets (forward+reverse) descending; CLI `show security flow session sort-by bytes/packets`; gRPC ShowText topics `sessions-top:bytes`/`sessions-top:packets`; cmdtree sort-by node
docs/phases.md:654:- Files: 14 files, 705 insertions — pkg/{api,cli,cmdtree,config,configstore,dataplane,grpcapi}/, cmd/cli/, proto/
docs/phases.md:658:- **test policy/routing/zone commands:** `test policy from-zone X to-zone Y ...` walks compiled policies; `test routing destination <prefix>` queries FRR; `test security-zone interface <name>` shows zone membership; all wired to gRPC, remote CLI, cmdtree
docs/phases.md:660:- Files: 12 files, 1884 insertions — pkg/{api,cli,cmdtree,config,grpcapi,logging}/, cmd/cli/
docs/phases.md:666:- Files: 10 files, 824 insertions — pkg/{cli,cmdtree,config,configstore,daemon,grpcapi}/, cmd/cli/
docs/phases.md:672:- Files: 8 files, 789 insertions — pkg/{cli,cmdtree,config,configstore,grpcapi}/, cmd/cli/
docs/phases.md:678:- Files: 5 files, 266 insertions — pkg/{cli,cmdtree,frr,grpcapi}/, cmd/cli/
docs/phases.md:681:- **load set terminal:** Paste multiple set commands in configure mode; ParseSetCommand+SetPath per line; file mode; LoadSet() in configstore with tests
docs/phases.md:685:- Files: 10 files, 405 insertions — pkg/{cli,cmdtree,config,configstore,grpcapi}/, cmd/cli/, proto/
docs/phases.md:692:- Files: 11 files, 518 insertions — pkg/{api,cli,cmdtree,configstore,grpcapi}/, cmd/cli/, proto/
docs/phases.md:701:- Files: 11 files, 1440 insertions — pkg/{cluster,config,cli,cmdtree,daemon,grpcapi}/, cmd/cli/
docs/phases.md:1198:- **cmdtree:** `request > system > software > in-service-upgrade` node
docs/phases.md:1284:| `pkg/cmdtree/tree.go` | +3 | ISSU command tree entry |
docs/phases.md:1555:| `pkg/cmdtree/tree.go` | `nptv6` command node |
docs/phases.md:2101:New screen check — prevents session table exhaustion from single source/destination.
docs/bugs.md:354:- **Fix:** Use `ParseSetCommand()` + `tree.SetPath()` (standard pattern for all flat set tests)
docs/bugs.md:355:- **Gotcha:** NEVER use `NewParser()` for flat `set` syntax — always use SetPath loop
docs/bugs.md:389:### SetPath leaf duplication bug (FIXED, `13daf45`)
docs/bugs.md:390:- `SetPath()` always appended leaf nodes without checking for existing leaves with same keyword
docs/pr/1546-filter-engine-split/plan.md:75:runtime. The repo's `pkg/cmdtree/tree.go`-style "single source of
docs/research/1319-typed-leaf/plan.md:25:- **Phase 1 infra (DONE, solid):** `pkg/cmdtree/tree.go` `Node` carries
docs/research/1319-typed-leaf/plan.md:35:  `pkg/cmdtree/schema_validate.go` `SchemaValidate(tree, cfg)` is called
docs/research/1319-typed-leaf/plan.md:38:  `class-of-service` exists** (`schema_validate.go:43-46`), then only
docs/research/1319-typed-leaf/plan.md:41:  `cmdtree.ConfigClassOfServiceSchedulers` types `transmit-rate`
docs/research/1319-typed-leaf/plan.md:47:CLAUDE.md and `pkg/cmdtree/README.md` call cmdtree "the single source of
docs/research/1319-typed-leaf/plan.md:53:| `cmdtree.ConfigTopLevel` + `ConfigClassOfServiceSchedulers` | `pkg/cmdtree/tree.go` | typed-leaf overlay (schedulers + a few `system dataplane` knobs) | sparse |
docs/research/1319-typed-leaf/plan.md:54:| `setSchema` (`schemaNode`) | `pkg/config/ast.go:401` | the **actual** structural completion + SetPath grouping tree | ~324 nodes, **~539 `args`-bearing value leaves**, 206 placeholders |
docs/research/1319-typed-leaf/plan.md:57:`set/delete/show/edit` through `config.CompleteSetPathWithValues`, which
docs/research/1319-typed-leaf/plan.md:58:walks **`setSchema`** and **never consults the cmdtree typed leaves**.
docs/research/1319-typed-leaf/plan.md:60:`ValueExamples`/`Placeholder`) is reached by the cmdtree unit tests
docs/research/1319-typed-leaf/plan.md:66:`setSchema`'s schedulers entry (`ast.go:1164-1167`) is:
docs/research/1319-typed-leaf/plan.md:85:AST; the `SchemaValidate` early-return on absent class-of-service skips
docs/research/1319-typed-leaf/plan.md:92:- **~539** `args>0` value-consuming leaves in `setSchema` across ~18
docs/research/1319-typed-leaf/plan.md:126:The issue proposes "extend cmdtree Node". The killed Phase 3a tried to
docs/research/1319-typed-leaf/plan.md:127:extend the cmdtree overlay + hand-rolled walker. The real decision is how
docs/research/1319-typed-leaf/plan.md:130:### Option A — Annotate `setSchema` directly (single tree, in pkg/config)
docs/research/1319-typed-leaf/plan.md:134:`CompleteSetPathWithValues` already walks `setSchema` and is the live
docs/research/1319-typed-leaf/plan.md:136:`SchemaValidate` walks the **same** `setSchema` over the AST. The cmdtree
docs/research/1319-typed-leaf/plan.md:138:live in `setSchema`.
docs/research/1319-typed-leaf/plan.md:144:- **Cons:** contradicts the "cmdtree is SSOT" doctrine in CLAUDE.md —
docs/research/1319-typed-leaf/plan.md:145:  config-mode typed values would live in `pkg/config`, not `pkg/cmdtree`.
docs/research/1319-typed-leaf/plan.md:146:  Needs a doctrine-update note. cmdtree's `ConfigClassOfServiceSchedulers`
docs/research/1319-typed-leaf/plan.md:150:### Option B — Make cmdtree the real SSOT; route `set` completion through it
docs/research/1319-typed-leaf/plan.md:152:Build the full config-mode grammar in `cmdtree.ConfigTopLevel`
docs/research/1319-typed-leaf/plan.md:154:drive `set` completion from cmdtree instead of `setSchema`. `setSchema`
docs/research/1319-typed-leaf/plan.md:155:is then derived from (or retired in favor of) cmdtree. Generic walker
docs/research/1319-typed-leaf/plan.md:156:lives in cmdtree.
docs/research/1319-typed-leaf/plan.md:159:- **Cons:** **enormous** — `setSchema` is ~324 nodes with `args`,
docs/research/1319-typed-leaf/plan.md:161:  semantics that cmdtree's `Node` does not model. Rebuilding the entire
docs/research/1319-typed-leaf/plan.md:162:  config grammar in cmdtree AND re-validating SetPath grouping (the
docs/research/1319-typed-leaf/plan.md:163:  parser depends on `setSchema` for flat-set token grouping) is a
docs/research/1319-typed-leaf/plan.md:167:### Option C — Bridge: keep both trees, add a lookup from setSchema leaf → cmdtree typed node
docs/research/1319-typed-leaf/plan.md:169:Leave both trees; at the value slot, `CompleteSetPathWithValues` and a
docs/research/1319-typed-leaf/plan.md:170:generic `SchemaValidate` look up the consumed `path` in
docs/research/1319-typed-leaf/plan.md:171:`cmdtree.ConfigTopLevel` to fetch `ValueType`/`Validator`/examples.
docs/research/1319-typed-leaf/plan.md:173:- **Pros:** no migration of existing trees; cmdtree stays the typed-leaf
docs/research/1319-typed-leaf/plan.md:177:  must replicate `setSchema`'s arg/midKeyword/compoundKey path-consumption
docs/research/1319-typed-leaf/plan.md:178:  to map a path to a cmdtree node — fragile; doubles the per-leaf edit.
docs/research/1319-typed-leaf/plan.md:186:live in `pkg/config`, not `pkg/cmdtree`) is real but is a documentation
docs/research/1319-typed-leaf/plan.md:189:`setSchema` is the config-grammar SSOT and cmdtree is the
docs/research/1319-typed-leaf/plan.md:190:operational-tree SSOT, with shared `ValueType`/validator types.
docs/research/1319-typed-leaf/plan.md:193:`pkg/config`; cmdtree aliases them. Option A keeps the enum where the
docs/research/1319-typed-leaf/plan.md:194:validators are and lets cmdtree keep aliasing for its operational leaves.
docs/research/1319-typed-leaf/plan.md:203:2. Populate the **schedulers** leaves in `setSchema` (the 3 already
docs/research/1319-typed-leaf/plan.md:204:   typed in cmdtree) with these fields — single source for CoS now.
docs/research/1319-typed-leaf/plan.md:205:3. `CompleteSetPathWithValues`: at the value slot, when the leaf has a
docs/research/1319-typed-leaf/plan.md:209:4. Replace `walkSchedulers`/`SchemaValidate` with a **generic recursive
docs/research/1319-typed-leaf/plan.md:210:   `validateAST(astNode, schemaNode, path)`** that descends `setSchema`,
docs/research/1319-typed-leaf/plan.md:215:5. Move `SchemaValidate` to `pkg/config` (it now walks `setSchema`, owned
docs/research/1319-typed-leaf/plan.md:216:   by `pkg/config`); `pkg/configstore` calls `config.SchemaValidate`.
docs/research/1319-typed-leaf/plan.md:217:   Keep a thin `cmdtree.SchemaValidate` shim or update the one caller.
docs/research/1319-typed-leaf/plan.md:218:6. **Parity tests:** existing `pkg/cmdtree/schema_validate_test.go` +
docs/research/1319-typed-leaf/plan.md:219:   `pkg/config/schema_validate_test.go` cases must pass against the new
docs/research/1319-typed-leaf/plan.md:221:   `<rate>` + examples through `CompleteSetPathWithValues` (the gap in
docs/research/1319-typed-leaf/plan.md:222:   §2.2). Retire/migrate `cmdtree.ConfigClassOfServiceSchedulers` (note
docs/research/1319-typed-leaf/plan.md:224:7. Docs: `pkg/cmdtree/README.md` + `pkg/config/README.md` +
docs/research/1319-typed-leaf/plan.md:225:   `docs/config-schema.md` (new) state the corrected SSOT split and how
docs/research/1319-typed-leaf/plan.md:226:   to add a typed leaf (one `setSchema` edit).
docs/research/1319-typed-leaf/plan.md:236:Each PR types one subsystem's leaves in `setSchema` with **Junos-vSRX-
docs/research/1319-typed-leaf/plan.md:260:  `config.CompleteSetPathWithValues` (cli) / the gRPC completer resolves
docs/research/1319-typed-leaf/plan.md:269:  `pkg/cmdtree/README.md:47` invariant: only type a leaf the compiler
docs/research/1319-typed-leaf/plan.md:275:- **Parser dependency on `setSchema`.** `setSchema` drives flat-set token
docs/research/1319-typed-leaf/plan.md:276:  grouping in SetPath. Adding *fields* to `schemaNode` is additive and
docs/research/1319-typed-leaf/plan.md:277:  must not change grouping; PR 1 must assert SetPath grouping is
docs/research/1319-typed-leaf/plan.md:282:- **Doctrine churn.** CLAUDE.md says cmdtree is THE SSOT; Option A
docs/research/1319-typed-leaf/plan.md:283:  formalizes a two-SSOT split (operational=cmdtree, config-grammar=
docs/research/1319-typed-leaf/plan.md:284:  setSchema). Must be documented, not silently contradicted.
docs/research/1319-typed-leaf/plan.md:288:- Reuse `pkg/config/schema_validate_test.go` +
docs/research/1319-typed-leaf/plan.md:289:  `pkg/cmdtree/schema_validate_test.go` against the generic walker.
docs/research/1319-typed-leaf/plan.md:291:  via `CompleteSetPathWithValues`).
docs/research/1319-typed-leaf/plan.md:292:- New: SetPath grouping golden test asserting no grouping change.
docs/research/1319-typed-leaf/plan.md:304:1. Option A vs C: is moving config-mode typed values out of cmdtree into
docs/research/1319-typed-leaf/plan.md:305:   `setSchema` acceptable given the SSOT doctrine, or must typed values
docs/research/1319-typed-leaf/plan.md:306:   stay in cmdtree (forcing the Option-C bridge / hand-sync)?
docs/research/1319-typed-leaf/plan.md:308:   production config-mode path consult the cmdtree typed leaves today? If
docs/research/1319-typed-leaf/plan.md:310:3. Should PR 1 retire `cmdtree.ConfigClassOfServiceSchedulers` outright,
docs/deterministic-nat-cgnat.md:126:| `pkg/cmdtree/tree.go` | `deterministic-nat nat-table` show command |
docs/cos/cos-traffic-shaping-review-v4-many-core.md:41:That means a single source host can get:
docs/pr/1521-maps-sync-decouple/plan.md:99:**Go-side single source of truth for the userspace package** — it
docs/pr/1521-maps-sync-decouple/plan.md:118:// becomes the sole source of truth.
docs/pr/1521-maps-sync-decouple/plan.md:151:a single source of truth. This is intentional: the constants are
docs/pr/1521-maps-sync-decouple/plan.md:376:   source of truth on the userspace package boundary only. Until
docs/session-history.md:372:**Self-Generating Help** (`461cbc8`): CLI help now generated from `operationalTree` -- single source of truth for all commands, descriptions, and completion.
docs/session-history.md:374:**cmdtree Package** (`b75f047`): Extracted `pkg/cmdtree/tree.go` as single source of truth for all CLI command trees. Both local CLI, remote CLI, and gRPC server import from here.
docs/session-history.md:507:**SetPath Fix** (`13daf45`, `b5827da`): Fixed SetPath leaf duplication for single-value and multi-value keywords.
docs/session-history.md:643:**CLI Help/Completion** (`4369c85`): Comprehensive update to `pkg/cmdtree/tree.go` -- added sub-command children to `ping`, `traceroute`, `monitor traffic`; filter sub-commands for session/log/clear commands; full argument chain for `test policy`; ~40 description updates to match Junos wording; DynamicFn closures for zones, interfaces, routing instances; terse/global/policy-name options.
docs/session-history.md:736:- Single source of truth: `pkg/cmdtree/tree.go`
docs/pr/814-max-interfaces/codex-plan-review.md:43:**Mitigation:** Use the real build command in the plan, or delete this redundant step and make `make generate` plus explicit artifact review the only source of truth.
docs/pr/1540-rest-api-split/plan.md:268:   block in `NewServer` is the single source of truth. This PR
docs/pr/1528-dpdk-mechanical-removal/reviewer-ids.md:35:  - **MINOR (blocking)**: schema-validate edge — Store.Load runs schemaValidateExpandedTree before compileTreeForLoad. If cmdtree.SchemaValidate ever expands to walk `system dataplane`, the load-blackout returns.
docs/pr/1528-dpdk-mechanical-removal/reviewer-ids.md:36:  - Verified against actual source (pkg/cmdtree/schema_validate.go:35-57): SchemaValidate is currently scoped to class-of-service schedulers only, so the concern is unfounded TODAY. v3.2 adds explicit tests + §4.7 contract to lock in the scope.
docs/pr/1528-dpdk-mechanical-removal/reviewer-ids.md:55:  - One finding: TestSchemaValidate_AcceptsLegacyDPDKSubStanza fixture has no class-of-service subtree, so the test only proves the early-return behavior. A future PR adding a top-level system-dataplane walker independently of the cos early-return would silently bypass the gate.
docs/pr/547-rss-skew-fixture/plan.md:19:   source of truth *internally* (called by `fairness-eval` itself),
docs/pr/547-rss-skew-fixture/plan.md:402:- `compute_cstruct` is the single source of truth for Cstruct math
docs/pr/797-d3/go-review.md:220:   `disable`/`enable` and uses `ParseSetCommand`+`SetPath` as required
docs/pr/915-exact-surplus-sharing/plan.md:89:  `pkg/cmdtree/tree.go`. Validation belongs in `ValidateConfig`
docs/pr/915-exact-surplus-sharing/plan.md:198:  `cmdtree`). Mirror the existing `exact` leaf's shape on
docs/pr/915-exact-surplus-sharing/plan.md:219:- `pkg/cmdtree/tree.go`: add the new leaf under
docs/pr/1528-dpdk-mechanical-removal/plan.md:4:TestSchemaValidate_AcceptsLegacyDPDKSubStanza fixture strength
docs/pr/1528-dpdk-mechanical-removal/plan.md:10:`TestSchemaValidate_AcceptsLegacyDPDKSubStanza` fixture has no
docs/pr/1528-dpdk-mechanical-removal/plan.md:11:`class-of-service` subtree. Because `pkg/cmdtree/schema_validate.go:43-46`
docs/pr/1528-dpdk-mechanical-removal/plan.md:14:incorrectly pass under a future regression where SchemaValidate
docs/pr/1528-dpdk-mechanical-removal/plan.md:21:`TestSchemaValidate_AcceptsLegacyDPDKSubStanza` to ALSO include a
docs/pr/1528-dpdk-mechanical-removal/plan.md:33:func TestSchemaValidate_AcceptsLegacyDPDKSubStanza(t *testing.T) {
docs/pr/1528-dpdk-mechanical-removal/plan.md:36:        // class-of-service block — triggers the SchemaValidate walker.
docs/pr/1528-dpdk-mechanical-removal/plan.md:58:        if err := tree.SetPath(path); err != nil {
docs/pr/1528-dpdk-mechanical-removal/plan.md:59:            t.Fatalf("SetPath(%q): %v", line, err)
docs/pr/1528-dpdk-mechanical-removal/plan.md:66:    // Assertion: SchemaValidate walks the cos block AND ignores the
docs/pr/1528-dpdk-mechanical-removal/plan.md:69:    if err := cmdtree.SchemaValidate(tree, nil); err != nil {
docs/pr/1528-dpdk-mechanical-removal/plan.md:70:        t.Fatalf("SchemaValidate rejected legacy DPDK sub-stanza alongside valid cos block: %v", err)
docs/pr/1528-dpdk-mechanical-removal/plan.md:79:| Current SchemaValidate (cos-only walker) | Passes via early-return | Passes via positive-path walk |
docs/pr/1528-dpdk-mechanical-removal/plan.md:105:`compileTreeForLoad`. If the cmdtree-side `SchemaValidate` rejects
docs/pr/1528-dpdk-mechanical-removal/plan.md:110:current `SchemaValidate`, but locking in the behavior with an explicit
docs/pr/1528-dpdk-mechanical-removal/plan.md:113:1. `pkg/cmdtree/schema_validate.go:35-57`: `SchemaValidate` is opt-in
docs/pr/1528-dpdk-mechanical-removal/plan.md:117:   *"Walking the whole AST against the (still-mostly-untyped) cmdtree
docs/pr/1528-dpdk-mechanical-removal/plan.md:120:2. `pkg/cmdtree/tree.go:986-1003` `ConfigSetDataplaneKnobs` covers
docs/pr/1528-dpdk-mechanical-removal/plan.md:126:   flat leaves). The cmdtree schema does not REJECT unrecognized
docs/pr/1528-dpdk-mechanical-removal/plan.md:131:0000:03:00.0 interface wan0` (etc) passes `SchemaValidate` cleanly
docs/pr/1528-dpdk-mechanical-removal/plan.md:152:a future `SchemaValidate` expansion doesn't silently break the
docs/pr/1528-dpdk-mechanical-removal/plan.md:194:   `DeletePath`, `SetPath` exist. v2's helper signature was imprecise.
docs/pr/1528-dpdk-mechanical-removal/plan.md:661:- `pkg/cmdtree/schema_validate_test.go` (new file): new test
docs/pr/1528-dpdk-mechanical-removal/plan.md:662:  `TestSchemaValidate_AcceptsLegacyDPDKSubStanza` (Codex r5 v3.2 minor)
docs/pr/1528-dpdk-mechanical-removal/plan.md:664:  `cmdtree.SchemaValidate` to walk `system dataplane`, forcing the
docs/pr/1528-dpdk-mechanical-removal/plan.md:694:BEFORE `compileTreeForLoad`'s compile-mode bypass. If the cmdtree-side
docs/pr/1528-dpdk-mechanical-removal/plan.md:695:`SchemaValidate` (pkg/cmdtree/schema_validate.go) ever expands to walk
docs/pr/1528-dpdk-mechanical-removal/plan.md:700:**Current state (verified pkg/cmdtree/schema_validate.go:35-57):**
docs/pr/1528-dpdk-mechanical-removal/plan.md:701:`SchemaValidate` is opt-in per subtree, scoped to `class-of-service
docs/pr/1528-dpdk-mechanical-removal/plan.md:729:2. Add `TestSchemaValidate_AcceptsLegacyDPDKSubStanza` in
docs/pr/1528-dpdk-mechanical-removal/plan.md:730:   `pkg/cmdtree/schema_validate_test.go` (new file). Test fixture
docs/pr/1528-dpdk-mechanical-removal/plan.md:734:   `pkg/cmdtree/schema_validate.go:43-46` early-return so the test
docs/pr/1528-dpdk-mechanical-removal/plan.md:740:   shape), then `cmdtree.SchemaValidate(tree, nil)` returns nil error.
docs/pr/1528-dpdk-mechanical-removal/plan.md:742:   `SchemaValidate` to walk `system dataplane` (either unconditionally
docs/pr/1528-dpdk-mechanical-removal/plan.md:747:   > *Any expansion of `cmdtree.SchemaValidate` that walks `system
docs/pr/1528-dpdk-mechanical-removal/plan.md:859:  GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test -run TestSchemaValidate_AcceptsLegacyDPDKSubStanza ./pkg/cmdtree/ 2>&1 | grep -E "PASS|FAIL|ok " | tail -1
docs/pr/879-cluster-peer-rendering/plan.md:100:clients; cmdtree gates the user-facing CLI but not direct gRPC.) The
docs/pr/1538-multierror-validation/plan.md:344:   `ParseSetCommand` + `tree.SetPath` loop per CLAUDE.md "Parser
docs/pr/1538-multierror-validation/plan.md:386:   path `ParseSetCommand` → `tree.SetPath` → `CompileConfig`
docs/pr/1649-doc-floor-curve/claude-smr-accuracy.md:5:source of truth. The #1647 lesson (Copilot caught a wrong doc *correction*)
docs/pr/816-step1-rerun/codex-plan-review.md:259:6. **BUCKET RANGE TABLE §4.7.1 — verified against implementation, with one source-note.** The table at `docs/pr/816-step1-rerun/plan.md:631-653` matches the actual bucket mapping in `userspace-dp/src/afxdp/umem.rs:114-118,178-181`: bucket 0 is `< 1024 ns`, bucket `N >= 1` is `[2^(N+9), 2^(N+10))`, and bucket 15 saturates at `>= 2^24 ns`. `userspace-dp/src/protocol.rs:1415-1425` only carries the histogram fields; it does not define the bucket boundaries. So the table is correct, but the source of truth for boundaries is `umem.rs`, not `protocol.rs`.
docs/pr/827-p3-captures/codex-plan-review.md:76:2. **The plan still does not positively pin that step1 writes correct `tx_kick_*_delta` fields into `hist-blocks.jsonl`.** Quote: step1 is now the `“Sole source of truth for per-block kick deltas”` ([plan §3.2, lines 54-67](/home/ps/git/bpfrx/.claude/worktrees/pr-827-p3-captures/docs/pr/827-p3-captures/plan.md:54)), and Issue B's acceptance criterion remains `“step1-histogram-classify.py parses the new histogram and counter into per-block deltas”` ([#819 Issue B, lines 857-861](/home/ps/git/bpfrx/.claude/worktrees/pr-827-p3-captures/docs/pr/819-step2-discriminator-design/design.md:857)). But the step1 test list covers aggregation/invariants and submit-path regression only ([plan §5.2, lines 337-369](/home/ps/git/bpfrx/.claude/worktrees/pr-827-p3-captures/docs/pr/827-p3-captures/plan.md:337)); none of those tests explicitly assert that a valid 13-snapshot stream produces the expected `tx_kick_count_delta`, `tx_kick_sum_ns_delta`, `tx_kick_retry_delta`, and `tx_kick_hist_delta` fields in emitted block output. Fix: add one positive-path step1 test that drives a small 13-snapshot fixture through block computation and asserts the emitted per-block `tx_kick_*_delta` values exactly.
docs/pr/827-p3-captures/codex-plan-review.md:93:R4 closes the last substantive blockers. The plan is now unambiguous that `step1-histogram-classify.py` is the sole source of truth for `tx_kick_*_delta`, that K0 requires both non-empty `per_binding` and all four kick keys on every entry, and that step3 consumes `hist-blocks.jsonl` only. I did not find any remaining correctness, completeness, or edge-case gaps that would block implementation. A few editorial inconsistencies remain, but they do not affect the technical contract.
docs/pr/1612-scale-target-measurement/plan.md:667:   source of truth).
docs/pr/827-p3-captures/plan.md:55:  R1 HIGH-2 and R2 MED-2. **Sole source of truth for per-block
docs/pr/wireguard-clean/plan.md:99:The forwarding decision is the **sole** source of truth for which
docs/pr/1219-fairness-harness/plan.md:131:D. Rust↔Go formula drift. Suggestion: CGo / single source of truth.
docs/pr/1219-fairness-harness/plan.md:470:This is the **single source of truth** for the fairness math —
docs/pr/821-p1-sched-switch-capture/codex-code-review.md:5:- [HIGH] Stale `worker-tids.txt` race on reruns. `test/incus/step2-sched-switch-capture.sh:148-180` launches `step1-capture.sh` and immediately accepts any pre-existing `"$STEP1_OUTDIR/worker-tids.txt"` via `[[ -s ... ]]`; `test/incus/step1-capture.sh:257-259` only rewrites that file later in the new run. Plan §3.1 step 3 says the rendezvous file is the single source of truth for this capture (`docs/pr/821-p1-sched-switch-capture/plan.md:67-68`). In a reused evidence dir, the harness can attach `perf record -t` to stale TIDs and capture the wrong threads.
docs/pr/821-p1-sched-switch-capture/codex-plan-review.md:11:Recommendation: Introduce an explicit `STEP1_OUTDIR="$REPO_ROOT/docs/pr/line-rate-investigation/step1-evidence/$COS/p${PORT}-${DIR}"` and poll `"$STEP1_OUTDIR/worker-tids.txt"`. Better: use that file’s contents as the perf `-t` source of truth instead of enumerating TIDs twice.
docs/pr/821-p1-sched-switch-capture/codex-plan-review.md:100:**CLOSED.** §3.1 introduces explicit `STEP1_OUTDIR` pointing at step1-capture.sh:90's actual output path (`docs/pr/line-rate-investigation/step1-evidence/$COS/p${PORT}-${DIR}/`). Rendezvous polls `$STEP1_OUTDIR/worker-tids.txt`. WORKER_TIDS read from the file (single source of truth, no re-enumeration). STEP2_OUTDIR remains the sister-harness sink at `docs/pr/819-step2-discriminator-design/evidence/...`. Step1 final artifacts copied from STEP1 to STEP2 for locality.
docs/pr/821-p1-sched-switch-capture/plan.md:67:4. **Step 3 — rendezvous (FIXED in R2, HIGH-1).** Poll `"$STEP1_OUTDIR/worker-tids.txt"` with 60 s timeout (step1 writes it at line 254 between daemon checks and during-run spawn; usually appears within 2-5 s). Read `WORKER_TIDS=$(cat "$STEP1_OUTDIR/worker-tids.txt")` as the single source of truth.
docs/pr/812-tx-latency-histogram/codex-code-review.md:55:- Mitigation: Keep the named const assert as the source of truth; if you trim anything, trim the runtime duplicate, not the compile-time guard.
docs/pr/812-tx-latency-histogram/plan.md:1506:   "source of truth" rule (`engineering-style.md:17-20`)
docs/pr/1197-neighbor-snapshot/plan.md:44:- **Trust the kernel** as the source of truth on the current MAC.
docs/pr/1444-cli-presenters/plan.md:177:- `completion.go` (extend): add cmdtree, sort imports if missing.
docs/pr/1473-xdp-shim-decouple/plan.md:134:  source of truth or stays as a small retained shared constants
docs/issues/issue-history.md:149:- Command tree advertises `nat-only`: `pkg/cmdtree/tree.go:266` and `pkg/cmdtree/tree.go:498`.
docs/issues/issue-history.md:172:- `global` exists in tree: `pkg/cmdtree/tree.go:158`.
docs/issues/issue-history.md:553:- Command tree lacks `status` child under `alg`: `pkg/cmdtree/tree.go:243`.
docs/issues/issue-history.md:2783:1. Replace inconsistent one-off checks with a single source of truth for mode behavior.
docs/issues/issue-history.md:14852:Security audit #856 noted that ACK-only TCP packets take the `resolve_ingress_xdp_target` fast-path (tail-call directly to `XDP_PROG_ZONE`), bypassing `xdp_screen` and therefore skipping IP_SWEEP accounting in `ip_sweep_track`. An attacker scanning many hosts from a single source using ACK-only probes evades sweep detection.
docs/issues/issue-history.md:17172:- `cli/completion.go` — tab + ? handlers (calls into pkg/cmdtree)
docs/issues/issue-history.md:20025:**Layer 1: \`pkg/cmdtree/tree.go\` doesn't model leaf values.** The \`schedulers\` node has \`{Desc: \"Scheduler configuration\"}\` and nothing under it. The \`Node\` struct exposes \`DynamicFn\` and \`ContextDynamicFn\` for instance-name completion (zones, interfaces, routing-instances), but has no \`ValueType\` / \`ValuePattern\` / \`ValueDesc\` / \`Validator\` fields for leaf values.
docs/issues/issue-history.md:21698:## eBPF implementation (source of truth)
docs/issues/issue-history.md:21746:## eBPF implementation (source of truth)
docs/issues/issue-history.md:21794:## eBPF implementation (source of truth)
docs/issues/issue-history.md:21842:## eBPF implementation (source of truth)
docs/issues/issue-history.md:21890:## eBPF implementation (source of truth)
docs/issues/issue-history.md:21933:## eBPF implementation (source of truth)
docs/issues/issue-history.md:21977:## eBPF implementation (source of truth)
docs/issues/issue-history.md:22025:## eBPF implementation (source of truth)
docs/issues/issue-history.md:22071:Current source of truth:
docs/issues/issue-history.md:22209:## #1419 — Auto-generate cmdtree help text from config schema for 100% ? completion coverage [CLOSED] (closed 2026-05-18)
docs/issues/issue-history.md:22225:`pkg/cmdtree/tree.go` has 432 nodes but only **3 nodes** have typed leaf metadata (`ValueType`, `ValueDesc`, `ValueExamples`, `Validator`) — specifically the `class-of-service schedulers` subtree added in #1319.
docs/issues/issue-history.md:22231:**Auto-generate `pkg/cmdtree/tree.go` nodes from config schema** to provide 100% help coverage with zero maintenance burden.
docs/issues/issue-history.md:22240:2. **Build generator**: `scripts/gen-cmdtree/main.go`
docs/issues/issue-history.md:22241:   - Walk `setSchema` + `operationalSchema` trees
docs/issues/issue-history.md:22247:   - Output to `pkg/cmdtree/tree_generated.go` (gitignored)
docs/pr/708-enqueue-pacing/plan.md:239:- **Single source of truth for per-bucket rate.**
docs/pr/1440-header-serialization-consolidate/plan.md:140:| Single source of truth for IPv4 / IPv6 / UDP layout | structural | The bite-prone "offset 12-15 is src" stuff is collected in one place. |
docs/pr/1440-header-serialization-consolidate/plan.md:153:argument FOR shipping anyway is the "single source of truth for
docs/pr/1440-header-serialization-consolidate/plan.md:189:└── headers.rs              (NEW — single source of truth for
docs/pr/1440-header-serialization-consolidate/plan.md:871:   = perf win" argument is weak; the real win is **single source
docs/pr/1526-dpdk-reject/plan.md:78:    the answer: no static `dpdk` completion in `pkg/cmdtree`. v2
docs/pr/1526-dpdk-reject/plan.md:176:  `pkg/cmdtree` (per Antigravity v1 verification). No CLI
docs/pr/1526-dpdk-reject/plan.md:257:   succeeds. Calls `ParseSetCommand` + `tree.SetPath` for
docs/pr/1526-dpdk-reject/plan.md:302:    fail post-rejection). Keep the parse loop (`tree.SetPath`
docs/pr/1526-dpdk-reject/plan.md:396:- CLI tab completion in `pkg/cmdtree` — no change (Antigravity
docs/pr/1526-dpdk-reject/plan.md:404:| `tree.SetPath(["system", "dataplane-type", "dpdk"])` | succeeds | succeeds |
docs/pr/877-chassis-forwarding/plan.md:31:- New CLI leaf `show chassis forwarding` in `pkg/cmdtree/tree.go`.
docs/pr/877-chassis-forwarding/plan.md:104:| `pkg/cmdtree/tree.go` | Add `forwarding` leaf under `show → chassis`. Auto-propagates to `?` help and tab completion in both CLIs. |
docs/pr/803-tunables/codex-review.md:76:`pkg/cmdtree/tree.go` has no diff on this branch for
docs/pr/803-tunables/codex-review.md:81:**Mitigation**: add the three knobs to `pkg/cmdtree/tree.go` under
docs/pr/803-tunables/codex-review.md:83:CLAUDE.md this is the single source of truth; without it the knobs
docs/pr/803-tunables/codex-review.md:122:**M3**: CLOSED — `claim-host-tunables` is present in `ConfigSetDataplaneKnobs` with description text and is wired into the `set system dataplane` help tree. `pkg/cmdtree/tree.go:869`, `pkg/cmdtree/tree.go:871`, `pkg/cmdtree/tree.go:896`
docs/pr/1373-retire-ebpf-dataplane/source-removal-manifest-1476.md:187:  source of truth or are still retained intentionally; and
docs/pr/803-tunables/go-review.md:31:- Summary: `pkg/cmdtree/tree.go` is the project's single source of
docs/pr/803-tunables/go-review.md:35:  but `pkg/cmdtree/tree.go` was not touched — and grepping it shows it
docs/pr/803-tunables/go-review.md:38:  /home/ps/git/bpfrx/pkg/cmdtree/tree.go` → 0 hits. `pkg/config/ast.go:1380-1386`.
docs/pr/803-tunables/go-review.md:41:  follow-up (`#systemdataplane cmdtree entries`) so the next PR adds
docs/pr/803-tunables/go-review.md:168:- **F1 cmdtree — CLOSED.** `ConfigSetDataplaneKnobs` added in
docs/pr/803-tunables/go-review.md:169:  `pkg/cmdtree/tree.go:869-879`, wired at `tree.go:896` under
docs/pr/1373-retire-ebpf-dataplane/plan-1377-snat-pools.md:328:- Existing reverse-session NAT behavior remains the source of truth for return
docs/pr/956-phase3-admission/plan.md:357:source of truth.
docs/pr/1373-retire-ebpf-dataplane/plan-1375-three-color-policers.md:53:  the RFC contract below as the source of truth.
docs/issues/pr-history.md:324:- unify local CLI completion to use canonical `cmdtree` completion logic so local CLI and gRPC CLI stay in sync
docs/issues/pr-history.md:331:- add regression tests for cmdtree completion behavior and gRPC completion candidate sets
docs/issues/pr-history.md:334:- `go test ./pkg/cmdtree ./pkg/grpcapi ./pkg/cli ./cmd/cli`
docs/issues/pr-history.md:383:Current docs contain drift and contradictions (for example summary totals vs row-level gap counts, and proposal docs for items already shipped). This provides one source of truth for backlog planning and cleanup.
docs/issues/pr-history.md:5832:- go test ./pkg/cmdtree ./pkg/config ./pkg/grpcapi ./pkg/cli ./cmd/cli -count=1
docs/issues/pr-history.md:7351:- First principles (latency > memory, correctness > perf > convenience, one source of truth per formula, honest framing, narrow scope).
docs/issues/pr-history.md:10022:- Wire-up: extends `step1-histogram-classify.py` with K0-K3 invariants on the post-#826 `tx_kick_*` counters and emits per-block `tx_kick_*_delta` fields into `hist-blocks.jsonl` (sole source of truth per #827 plan R2 MED-2).
docs/issues/pr-history.md:10646:- `pkg/cmdtree/tree.go`: new `forwarding` leaf under `show → chassis`.
docs/issues/pr-history.md:16707:Per design doc revision 4 (`docs/pr/963-frame-editor-redux/design.md` §5.2, PROCEED-AS-PROPOSED from Codex round 3 + Gemini round 3): extract L3/L4 byte-mutation kernels into a dedicated `frame/byte_writes.rs` module. Six `#[inline(always)]` helpers; one source of truth for "byte 12-15 is the IPv4 source address" etc.
docs/issues/pr-history.md:17676:The `cmdtree` import migrates to `cli_show.go`; `cli_show_system.go`
docs/issues/pr-history.md:18923:Add `show services application-identification status` command. Local CLI in \`pkg/cli/cli_show_services.go\`; remote CLI dispatch in \`cmd/cli/show.go\`; gRPC server-side renderer in new \`pkg/grpcapi/server_show_appid.go\`. cmdtree leaf added under \`show services\`.
docs/issues/pr-history.md:20132:api, appid, cli, cluster, cmdtree, config, configstore, conntrack, daemon, dataplane, dhcp, dhcprelay, dhcpserver, eventengine, feeds, flowexport, frr, fwdstatus, grpcapi, ipsec, lldp, logging, monitoriface, networkd, nftables, ra, routing, rpm, scheduler, snmp, vrrp.
docs/issues/pr-history.md:20151:Concise. No marketing language, no emojis. Where possible the README points at a single canonical file (e.g. \`pkg/cmdtree\` → \`tree.go\`) and tells the reader what to read first.
docs/issues/pr-history.md:20462:- `go test ./pkg/api ./pkg/dataplane/userspace ./pkg/cmdtree ./pkg/cli ./pkg/grpcapi`
docs/issues/pr-history.md:20483:- `go test ./pkg/fairness ./pkg/config ./pkg/api ./pkg/dataplane/userspace ./pkg/cmdtree ./pkg/cli ./pkg/grpcapi`
docs/issues/pr-history.md:21357:**Phase 1 — schema infrastructure (`pkg/cmdtree.Node`):**
docs/issues/pr-history.md:21581:- `go test -count=1 ./pkg/cmdtree/... ./pkg/config/... ./pkg/configstore/...`
docs/issues/pr-history.md:22201:- `go test ./pkg/config ./pkg/cmdtree ./pkg/dataplane/userspace`
docs/issues/pr-history.md:25357:  defeat the `SchemaValidate` early-return.
docs/pr/965-session-gc-timer-wheel/plan.md:531:the single source of truth for what we will measure.
docs/pr/965-session-gc-timer-wheel/plan.md:894:   single source of truth; any other section that mentions "the
docs/pr/1621-cold-path-wire-prometheus/claude-smr-code-r1.md:39:- A=K, B=0: merged stays K, alias unchanged. Correct (single source).

codex
The schema internals matter here: `schemaNode` is not just completion metadata; it drives `SetPath` grouping via `args`, `wildcard`, `multi`, `midKeyword`, and `compoundKey`. I’m checking the exact `SetPath` implementation now because that determines whether Option A’s “add fields only” migration is actually safe.
exec
/bin/bash -lc "nl -ba pkg/config/ast.go | sed -n '220,360p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   220			// Partial match: node has more keys than remaining path.
   221			// Accept if we're at the last path segment (allows matching by first key only).
   222			return 1
   223		}
   224		for j := 1; j < nk; j++ {
   225			if n.Keys[j] != path[pos+j] {
   226				return 1 // first key matched but subsequent didn't; still a 1-key match
   227			}
   228		}
   229		return nk
   230	}
   231	
   232	// navigateToNode walks the tree following path, returning the target node.
   233	// Multi-key nodes consume multiple path elements at once.
   234	func navigateToNode(children []*Node, path []string) (*Node, error) {
   235		var current *Node
   236		pos := 0
   237		for pos < len(path) {
   238			found := false
   239			for _, child := range children {
   240				consumed := matchNodeKeys(child, path, pos)
   241				if consumed > 0 {
   242					current = child
   243					children = child.Children
   244					pos += consumed
   245					found = true
   246					break
   247				}
   248			}
   249			if !found {
   250				return nil, fmt.Errorf("path element %q not found", path[pos])
   251			}
   252		}
   253		return current, nil
   254	}
   255	
   256	// findNode navigates the tree to find a node at the given path.
   257	// Handles multi-key nodes by consuming multiple path elements per node.
   258	func (t *ConfigTree) findNode(path []string) (*Node, error) {
   259		return navigateToNode(t.Children, path)
   260	}
   261	
   262	// removeNode removes and returns a node at the given path.
   263	func (t *ConfigTree) removeNode(path []string) (*Node, error) {
   264		if len(path) == 0 {
   265			return nil, fmt.Errorf("empty path")
   266		}
   267		// Navigate to the parent, then find and remove the target child.
   268		parentChildren := &t.Children
   269		pos := 0
   270		// We need to find where the last node starts.
   271		// Walk until we can identify the target node at the end.
   272		for pos < len(path) {
   273			// Try to match a child and see if it's the final node.
   274			var bestChild *Node
   275			bestConsumed := 0
   276			bestIdx := -1
   277			for i, child := range *parentChildren {
   278				consumed := matchNodeKeys(child, path, pos)
   279				if consumed > 0 {
   280					bestChild = child
   281					bestConsumed = consumed
   282					bestIdx = i
   283					break
   284				}
   285			}
   286			if bestChild == nil {
   287				return nil, fmt.Errorf("path element %q not found", path[pos])
   288			}
   289			if pos+bestConsumed >= len(path) {
   290				// This is the target node — remove it.
   291				*parentChildren = append((*parentChildren)[:bestIdx], (*parentChildren)[bestIdx+1:]...)
   292				return bestChild, nil
   293			}
   294			// Descend into this child's children.
   295			parentChildren = &bestChild.Children
   296			pos += bestConsumed
   297		}
   298		return nil, fmt.Errorf("path not found")
   299	}
   300	
   301	// insertNode inserts a node as a child at the given parent path.
   302	func (t *ConfigTree) insertNode(parentPath []string, node *Node) error {
   303		children := &t.Children
   304		pos := 0
   305		for pos < len(parentPath) {
   306			found := false
   307			for _, child := range *children {
   308				consumed := matchNodeKeys(child, parentPath, pos)
   309				if consumed > 0 {
   310					children = &child.Children
   311					pos += consumed
   312					found = true
   313					break
   314				}
   315			}
   316			if !found {
   317				return fmt.Errorf("destination parent path element %q not found", parentPath[pos])
   318			}
   319		}
   320		*children = append(*children, node)
   321		return nil
   322	}
   323	
   324	// findNodeWithParent navigates the tree and returns the target node
   325	// plus the parent's children slice (for insertion/removal at the correct level).
   326	func (t *ConfigTree) findNodeWithParent(path []string) (*Node, *[]*Node, error) {
   327		parentChildren := &t.Children
   328		pos := 0
   329		for pos < len(path) {
   330			// Try all children; prefer full-key matches over partial ones.
   331			// This handles siblings like [policy first], [policy second], [policy third]
   332			// where the first key "policy" matches all but we need the full key match.
   333			var bestChild *Node
   334			bestConsumed := 0
   335			for _, child := range *parentChildren {
   336				consumed := matchNodeKeys(child, path, pos)
   337				if consumed > bestConsumed {
   338					bestChild = child
   339					bestConsumed = consumed
   340				}
   341			}
   342			if bestChild == nil {
   343				return nil, nil, fmt.Errorf("path element %q not found", path[pos])
   344			}
   345			if pos+bestConsumed >= len(path) {
   346				return bestChild, parentChildren, nil
   347			}
   348			parentChildren = &bestChild.Children
   349			pos += bestConsumed
   350		}
   351		return nil, nil, fmt.Errorf("path not found")
   352	}
   353	
   354	// ValueHint identifies what kind of dynamic value is expected at a schema position.
   355	type ValueHint int
   356	
   357	const (
   358		ValueHintNone          ValueHint = iota
   359		ValueHintZoneName                // security-zone <name>
   360		ValueHintAddressName             // address-set <name>

exec
/bin/bash -lc "rg -n \"func \\(.*\\) SetPath|SetPath\\(\" pkg/config -g '*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/config/parser_services_test.go:266:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_services_test.go:459:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_services_test.go:568:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_services_test.go:569:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_services_test.go:669:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_services_test.go:670:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_services_test.go:717:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_services_test.go:718:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_services_test.go:791:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_services_test.go:792:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_services_test.go:860:		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_services_test.go:861:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_services_test.go:883:		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_services_test.go:884:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_services_test.go:909:		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_services_test.go:910:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_services_test.go:1024:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_services_test.go:1123:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_services_test.go:1124:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_services_test.go:1161:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_services_test.go:1162:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_cluster_test.go:79:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_cluster_test.go:185:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_cluster_test.go:186:			t.Fatalf("SetPath(%q) failed: %v", cmd, err)
pkg/config/parser_cluster_test.go:239:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_cluster_test.go:304:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_cluster_test.go:351:		if err := tree.SetPath(cmd); err != nil {
pkg/config/parser_cluster_test.go:420:		if err := tree.SetPath(cmd); err != nil {
pkg/config/parser_cluster_test.go:548:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_cluster_test.go:634:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_cluster_test.go:693:		if err := tree.SetPath(cmd); err != nil {
pkg/config/parser_cluster_test.go:762:		if err := tree.SetPath(cmd); err != nil {
pkg/config/parser_cluster_test.go:943:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_cluster_test.go:975:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_cluster_test.go:1007:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_cluster_test.go:1035:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_cluster_test.go:1066:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_cluster_test.go:1097:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_cluster_test.go:1125:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_cluster_test.go:1150:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_cluster_test.go:1151:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:282:		tree.SetPath(parts)
pkg/config/parser_ast_test.go:371:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:372:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:475:	if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:511:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:575:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:669:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:770:		if err := tree2.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:978:		if err := tree2.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:979:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_ast_test.go:1065:		if err := tree2.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:1066:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_ast_test.go:1102:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:1103:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_ast_test.go:1232:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:1233:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_ast_test.go:1309:		if err := tree3.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:1682:		tree.SetPath(parts)
pkg/config/parser_ast_test.go:1714:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:1715:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:1834:		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_ast_test.go:1835:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_ast_test.go:1988:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:1989:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_ast_test.go:2346:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:2347:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:2606:		if err := tree2.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_ast_test.go:2607:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_ast_test.go:2639:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:2640:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:2681:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:2682:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:2712:	if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:2795:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:2796:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:2963:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:2964:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3012:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3013:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3068:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3069:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3125:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3126:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3195:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3196:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3264:				if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3265:					t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3306:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3307:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3356:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3357:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3390:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3391:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3422:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3423:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3450:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3451:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3484:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3485:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_ast_test.go:3549:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3550:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_ast_test.go:3654:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3655:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3753:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3754:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3782:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3783:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3803:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3804:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3858:		tree.SetPath(parts)
pkg/config/parser_ast_test.go:3883:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3884:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3921:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3922:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:3961:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3962:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_ast_test.go:3991:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:3992:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_ast_test.go:4009:		tree.SetPath(parts)
pkg/config/parser_ast_test.go:4443:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_ast_test.go:4444:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_ast_test.go:4693:		tree.SetPath(cmd)
pkg/config/parser_ast_test.go:4715:		tree.SetPath(cmd)
pkg/config/parser_ast_test.go:4878:		tree.SetPath(cmd)
pkg/config/parser_ast_test.go:4979:				if err := tree.SetPath(cmd); err != nil {
pkg/config/parser_ast_test.go:4980:					t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:115:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:116:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:182:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:183:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:218:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:219:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:249:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:250:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:293:				if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:294:					t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:320:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:321:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:352:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:353:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:381:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:382:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:402:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:403:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:460:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:461:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:501:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:502:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:524:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:525:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:584:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:585:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:677:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:678:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:713:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:714:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:750:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:751:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:840:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:841:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:898:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:899:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:945:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:946:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:1322:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:1323:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:1368:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:1369:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:1414:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:1415:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_class_of_service_test.go:1457:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_class_of_service_test.go:1458:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/schema_validate_test.go:39:		if err := tree.SetPath(path); err != nil {
pkg/config/schema_validate_test.go:40:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/schema_validate_test.go:315:		if err := tree.SetPath(path); err != nil {
pkg/config/schema_validate_test.go:316:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/schema_validate_test.go:352:		if err := tree.SetPath(path); err != nil {
pkg/config/schema_validate_test.go:353:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/ast_edit.go:129:func (t *ConfigTree) SetPath(path []string) error {
pkg/config/compiler_test.go:49:		if err := tree.SetPath(path); err != nil {
pkg/config/compiler_test.go:50:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/compiler_test.go:117:		if err := tree.SetPath(path); err != nil {
pkg/config/compiler_test.go:118:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/compiler_test.go:209:		if err := tree.SetPath(path); err != nil {
pkg/config/compiler_test.go:210:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_system_test.go:14:		if err := tree.SetPath(fields[1:]); err != nil {
pkg/config/parser_system_test.go:15:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_system_test.go:49:		if err := tree.SetPath(fields[1:]); err != nil {
pkg/config/parser_system_test.go:50:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_system_test.go:234:		if err := tree2.SetPath(path); err != nil {
pkg/config/parser_system_test.go:235:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_system_test.go:260:		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_system_test.go:261:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_system_test.go:491:			if err := tree.SetPath(path); err != nil {
pkg/config/parser_system_test.go:635:		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_system_test.go:636:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_system_test.go:734:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_system_test.go:735:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_system_test.go:891:		if err := tree.SetPath(parts); err != nil {
pkg/config/parser_system_test.go:892:			t.Fatalf("SetPath(%v): %v", parts, err)
pkg/config/parser_system_test.go:1283:		if err := tree.SetPath(cmd); err != nil {
pkg/config/parser_system_test.go:1284:			t.Fatalf("SetPath(%v): %v", cmd, err)
pkg/config/parser_system_test.go:1322:		if err := tree.SetPath(fields[1:]); err != nil {
pkg/config/parser_system_test.go:1323:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_system_test.go:1349:		if err := tree.SetPath(fields[1:]); err != nil {
pkg/config/parser_system_test.go:1350:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_system_test.go:1371:		if err := tree.SetPath(fields[1:]); err != nil {
pkg/config/parser_system_test.go:1372:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_system_test.go:1407:		if err := tree.SetPath(fields[1:]); err != nil {
pkg/config/parser_system_test.go:1408:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_system_test.go:1438:			if err := tree.SetPath(fields[1:]); err != nil {
pkg/config/parser_system_test.go:1439:				t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_system_test.go:1466:			if err := tree.SetPath(fields[1:]); err != nil {
pkg/config/parser_system_test.go:1467:				t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/ast.go:1672:func CompleteSetPath(tokens []string) []string {
pkg/config/parser_routing_test.go:16:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:17:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:164:		if err := tree.SetPath(fields[1:]); err != nil {
pkg/config/parser_routing_test.go:165:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_routing_test.go:224:		if err := tree.SetPath(fields[1:]); err != nil {
pkg/config/parser_routing_test.go:225:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_routing_test.go:367:		if err := tree2.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:410:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:573:		if err := tree2.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:574:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_routing_test.go:603:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:774:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:775:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:867:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:868:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:921:		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_routing_test.go:922:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_routing_test.go:1044:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1045:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1088:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1089:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1116:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1117:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1147:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1148:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1173:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1174:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1210:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1211:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1253:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1254:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1287:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1288:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1315:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1316:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1357:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1358:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1385:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1386:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1404:		if err := tree2.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1405:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1425:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1426:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1473:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1474:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1511:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1512:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1536:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1537:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1564:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1565:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1592:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1593:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1620:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1621:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1645:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1646:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1673:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1674:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1701:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1702:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1729:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1730:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1757:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1758:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1815:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1816:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1856:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1857:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_routing_test.go:1893:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1894:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1931:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1932:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1960:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1961:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:1996:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:1997:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:2029:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:2030:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:2099:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:2100:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:2172:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:2173:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:2207:		if err := tree.SetPath(tokens); err != nil {
pkg/config/parser_routing_test.go:2281:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:2282:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:2319:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:2320:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:2348:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:2349:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:2377:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:2378:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:2454:		tree.SetPath(cmd)
pkg/config/parser_routing_test.go:2490:		tree.SetPath(cmd)
pkg/config/parser_routing_test.go:2570:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:2571:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:2647:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:2648:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:2744:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:2745:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:2795:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:2796:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:2868:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:2869:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:2900:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:2901:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:2935:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:2936:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:2969:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:2970:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:3013:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:3014:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:3041:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_routing_test.go:3042:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_routing_test.go:3069:		if err := tree.SetPath(tokens); err != nil {
pkg/config/parser_routing_test.go:3070:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_routing_test.go:3141:		if err := tree.SetPath(tokens); err != nil {
pkg/config/parser_routing_test.go:3142:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_security_test.go:16:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:17:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:206:		if err := tree2.SetPath(path); err != nil {
pkg/config/parser_security_test.go:207:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:234:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:235:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:320:		if err := tree2.SetPath(path); err != nil {
pkg/config/parser_security_test.go:321:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:447:		if err := tree2.SetPath(path); err != nil {
pkg/config/parser_security_test.go:448:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:472:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:473:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:506:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:507:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:618:		tree.SetPath(cmd)
pkg/config/parser_security_test.go:726:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:727:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:940:		if err := tree2.SetPath(path); err != nil {
pkg/config/parser_security_test.go:941:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:1039:		if err := tree2.SetPath(path); err != nil {
pkg/config/parser_security_test.go:1040:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:1146:		if err := tree2.SetPath(path); err != nil {
pkg/config/parser_security_test.go:1147:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:1266:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:1381:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:1382:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_security_test.go:1473:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:1474:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_security_test.go:1750:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:1751:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_security_test.go:1785:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:1786:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_security_test.go:1912:		tree.SetPath(cmd)
pkg/config/parser_security_test.go:2027:		if err := tree2.SetPath(path); err != nil {
pkg/config/parser_security_test.go:2157:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:2158:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_security_test.go:2189:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:2190:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_security_test.go:2243:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:2244:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_security_test.go:2279:		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_security_test.go:2280:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:2328:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:2329:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:2360:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:2361:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:2388:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:2389:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:2415:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:2416:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:2433:		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_security_test.go:2434:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:2468:		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_security_test.go:2469:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:2514:		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_security_test.go:2515:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:2556:		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_security_test.go:2557:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:2648:		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_security_test.go:2649:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:2671:		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_security_test.go:2672:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:2865:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:2866:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:2958:		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
pkg/config/parser_security_test.go:2959:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:3102:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:3103:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:3141:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:3142:			t.Fatalf("SetPath(%q): %v", cmd, err)
pkg/config/parser_security_test.go:3406:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:3407:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_security_test.go:3522:		if err := tree.SetPath(cmd); err != nil {
pkg/config/parser_security_test.go:3523:			t.Fatalf("SetPath(%v): %v", cmd, err)
pkg/config/parser_security_test.go:3598:		if err := tree.SetPath(cmd); err != nil {
pkg/config/parser_security_test.go:3599:			t.Fatalf("SetPath(%v): %v", cmd, err)
pkg/config/parser_security_test.go:3745:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:3746:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_security_test.go:3946:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:3947:			t.Fatalf("SetPath(%v): %v", path, err)
pkg/config/parser_security_test.go:4043:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:4044:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_security_test.go:4125:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:4126:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_security_test.go:4183:		if err := tree.SetPath(path); err != nil {
pkg/config/parser_security_test.go:4184:			t.Fatalf("SetPath(%q): %v", line, err)
pkg/config/parser_security_test.go:4266:		tree.SetPath(cmd)
pkg/config/parser_security_test.go:4302:		if err := tree.SetPath(path); err != nil {

exec
/bin/bash -lc "nl -ba pkg/cmdtree/tree.go | sed -n '960,1090p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   960				}
   961				names := make([]string, 0, len(cfg.RoutingInstances))
   962				for _, ri := range cfg.RoutingInstances {
   963					names = append(names, ri.Name)
   964				}
   965				return names
   966			}},
   967		}},
   968		"traceroute": {Desc: "Trace route to remote host", Children: map[string]*Node{
   969			"<host>": {Desc: "Hostname or IP address of remote host"},
   970			"source": {Desc: "Source address to use"},
   971			"routing-instance": {Desc: "Routing instance for route lookup", DynamicFn: func(cfg *config.Config) []string {
   972				if cfg == nil {
   973					return nil
   974				}
   975				names := make([]string, 0, len(cfg.RoutingInstances))
   976				for _, ri := range cfg.RoutingInstances {
   977					names = append(names, ri.Name)
   978				}
   979				return names
   980			}},
   981		}},
   982		"quit": {Desc: "Exit CLI"},
   983		"exit": {Desc: "Exit CLI"},
   984	}
   985	
   986	// ConfigSetDataplaneKnobs is the `?` help surface for `set system
   987	// dataplane <knob>`. Codex M3 / Go F1: the schema in pkg/config/ast.go
   988	// already backs tab completion for these knobs, but `?` help and the
   989	// explicit per-knob description live in cmdtree. Keeping this map tiny
   990	// and focused lets us grow it without restating the full config
   991	// schema here — tab-completion for siblings still falls through to
   992	// the schema walker.
   993	var ConfigSetDataplaneKnobs = map[string]*Node{
   994		"rss-indirection":     {Desc: "mlx5 RSS indirection reshaping (enable|disable)"},
   995		"claim-host-tunables": {Desc: "Allow xpfd to write host-scope tunables (true|false; default false)"},
   996		"cpu-governor":        {Desc: "Host cpufreq governor (performance|schedutil|default)"},
   997		"netdev-budget":       {Desc: "net.core.netdev_budget value"},
   998		"coalescence": {Desc: "NIC interrupt-coalescence tuning (mlx5)", Children: map[string]*Node{
   999			"adaptive": {Desc: "Adaptive coalescing (enable|disable)"},
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
  1066		"annotate": {Desc: "Annotate the configuration statement"},
  1067		"copy":     {Desc: "Copy a configuration statement"},
  1068		"insert":   {Desc: "Insert a new ordered configuration statement"},
  1069		"rename":   {Desc: "Rename a configuration statement"},
  1070		"set": {Desc: "Set a configuration parameter", Children: map[string]*Node{
  1071			"class-of-service": {Desc: "Class-of-service configuration", Children: map[string]*Node{
  1072				"schedulers": {Desc: "Scheduler definitions", Children: map[string]*Node{
  1073					"<scheduler>": ConfigClassOfServiceSchedulers,
  1074				}},
  1075			}},
  1076			"system": {Desc: "System configuration", Children: map[string]*Node{
  1077				// Codex M3: surface the #785/#801 dataplane knobs so `?`
  1078				// help and tab completion show descriptions for
  1079				// rss-indirection / claim-host-tunables / cpu-governor /
  1080				// netdev-budget / coalescence without the operator having
  1081				// to guess at the spelling from the issue body. The schema
  1082				// walker handles completion for every other `set system`
  1083				// path; this hierarchy only supplies extra descriptions.
  1084				"dataplane": {Desc: "Userspace dataplane tunables", Children: ConfigSetDataplaneKnobs},
  1085			}},
  1086		}},
  1087		"delete": {Desc: "Delete a configuration statement"},
  1088		"show":   {Desc: "Show configuration"},
  1089		"commit": {Desc: "Commit current set of changes", Children: map[string]*Node{
  1090			"check":     {Desc: "Check correctness of syntax; do not apply changes"},

exec
/bin/bash -lc "nl -ba pkg/cmdtree/complete.go | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
nl: pkg/cmdtree/complete.go: No such file or directory

exec
/bin/bash -lc "nl -ba pkg/config/ast_edit.go | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
     1	package config
     2	
     3	import (
     4		"fmt"
     5		"strings"
     6	)
     7	
     8	// CopyPath copies a subtree from src to dst path.
     9	// The destination's last N keys (where N = len(sourceNode.Keys)) replace the source keys.
    10	func (t *ConfigTree) CopyPath(src, dst []string) error {
    11		if len(src) == 0 || len(dst) == 0 {
    12			return fmt.Errorf("empty path")
    13		}
    14		srcNode, _, err := t.findNodeWithParent(src)
    15		if err != nil {
    16			return fmt.Errorf("source not found: %s", strings.Join(src, " "))
    17		}
    18		cloned := cloneNodes([]*Node{srcNode})[0]
    19		nk := len(srcNode.Keys)
    20		if len(dst) < nk {
    21			return fmt.Errorf("destination path too short")
    22		}
    23		cloned.Keys = append([]string(nil), dst[len(dst)-nk:]...)
    24		// Find the parent for the destination
    25		dstParentPath := dst[:len(dst)-nk]
    26		return t.insertNode(dstParentPath, cloned)
    27	}
    28	
    29	// RenamePath moves a subtree from src to dst path.
    30	func (t *ConfigTree) RenamePath(src, dst []string) error {
    31		if len(src) == 0 || len(dst) == 0 {
    32			return fmt.Errorf("empty path")
    33		}
    34		srcNode, err := t.removeNode(src)
    35		if err != nil {
    36			return fmt.Errorf("source not found: %s", strings.Join(src, " "))
    37		}
    38		nk := len(srcNode.Keys)
    39		if len(dst) < nk {
    40			return fmt.Errorf("destination path too short")
    41		}
    42		srcNode.Keys = append([]string(nil), dst[len(dst)-nk:]...)
    43		dstParentPath := dst[:len(dst)-nk]
    44		return t.insertNode(dstParentPath, srcNode)
    45	}
    46	
    47	// InsertBefore moves an existing element before another element in the same
    48	// parent's children list. Both elements must exist under the same parent.
    49	// elementPath is the full path to the element to move.
    50	// refPath is the full path to the reference element.
    51	func (t *ConfigTree) InsertBefore(elementPath, refPath []string) error {
    52		return t.insertRelative(elementPath, refPath, false)
    53	}
    54	
    55	// InsertAfter moves an existing element after another element in the same
    56	// parent's children list.
    57	func (t *ConfigTree) InsertAfter(elementPath, refPath []string) error {
    58		return t.insertRelative(elementPath, refPath, true)
    59	}
    60	
    61	func (t *ConfigTree) insertRelative(elementPath, refPath []string, after bool) error {
    62		if len(elementPath) == 0 || len(refPath) == 0 {
    63			return fmt.Errorf("empty path")
    64		}
    65	
    66		// Find the element and its parent children slice.
    67		elem, parentChildren, err := t.findNodeWithParent(elementPath)
    68		if err != nil {
    69			return fmt.Errorf("element not found: %s", strings.Join(elementPath, " "))
    70		}
    71	
    72		// Find the reference element — must be in the same parent.
    73		refNode, refParent, err := t.findNodeWithParent(refPath)
    74		if err != nil {
    75			return fmt.Errorf("reference not found: %s", strings.Join(refPath, " "))
    76		}
    77	
    78		// Both must share the same parent (same children slice).
    79		if parentChildren != refParent {
    80			return fmt.Errorf("elements must be siblings (same parent)")
    81		}
    82	
    83		if elem == refNode {
    84			return nil // already in position
    85		}
    86	
    87		// Find and remove the element from the children slice.
    88		elemIdx := -1
    89		for i, c := range *parentChildren {
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

exec
/bin/bash -lc "rg -n \"func CompleteFromTree|func CompleteFromTreeWithDesc|ValueExamples|Placeholder\\(\" pkg/cmdtree -g '*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/cmdtree/tree_test.go:99:// #1319: typed-leaf `?` completion surfaces placeholder + ValueExamples
pkg/cmdtree/tree.go:27://   - `?` completion surfacing ValueDesc + ValueExamples for the value slot;
pkg/cmdtree/tree.go:65:func (v ValueType) Placeholder() string {
pkg/cmdtree/tree.go:102:// ValueExamples, Validator) describe the value a leaf accepts. The zero
pkg/cmdtree/tree.go:121:	// ValueExamples lists illustrative values surfaced in `?` completion.
pkg/cmdtree/tree.go:125:	ValueExamples []string
pkg/cmdtree/tree.go:1031:			ValueExamples: []string{"100k", "10m", "1g", "10g"},
pkg/cmdtree/tree.go:1041:			ValueExamples: []string{"low", "medium-low", "medium-high", "high", "strict-high"},
pkg/cmdtree/tree.go:1050:			ValueExamples: []string{"16m", "256k", "10%"},
pkg/cmdtree/tree.go:1131:func isPlaceholder(name string) bool {
pkg/cmdtree/tree.go:1136:func findPlaceholder(tree map[string]*Node) *Node {
pkg/cmdtree/tree.go:1138:		if isPlaceholder(name) {
pkg/cmdtree/tree.go:1172:func CompleteFromTree(tree map[string]*Node, words []string, partial string, cfg *config.Config) []string {
pkg/cmdtree/tree.go:1197:			if ph := findPlaceholder(current); ph != nil {
pkg/cmdtree/tree.go:1233:		candidates = append(candidates, currentNode.ValueExamples...)
pkg/cmdtree/tree.go:1234:		if ph := currentNode.ValueType.Placeholder(); ph != "" {
pkg/cmdtree/tree.go:1245:func CompleteFromTreeWithDesc(tree map[string]*Node, words []string, partial string, cfg *config.Config) []Candidate {
pkg/cmdtree/tree.go:1264:			if ph := findPlaceholder(current); ph != nil {
pkg/cmdtree/tree.go:1330:	if ph := node.ValueType.Placeholder(); ph != "" {
pkg/cmdtree/tree.go:1339:	for _, ex := range node.ValueExamples {
pkg/cmdtree/tree.go:1402:			if ph := findPlaceholder(current); ph != nil {

exec
/bin/bash -lc "nl -ba pkg/cmdtree/tree.go | sed -n '1270,1450p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
  1270					continue
  1271				}
  1272				if wi == len(words)-1 && len(matches) > 0 {
  1273					var candidates []Candidate
  1274					for _, name := range matches {
  1275						candidates = append(candidates, Candidate{Name: name, Desc: current[name].Desc})
  1276					}
  1277					return candidates
  1278				}
  1279				return nil
  1280			}
  1281			currentNode = node
  1282			parentTyped = node.IsTypedLeaf()
  1283			if node.Children == nil {
  1284				if node.HasDynamic() && wi < len(words)-1 {
  1285					dynamicConsumed = true
  1286					continue
  1287				}
  1288				if node.HasDynamic() && cfg != nil {
  1289					var candidates []Candidate
  1290					for _, name := range node.DynamicValues(cfg, words) {
  1291						if strings.HasPrefix(name, partial) {
  1292							candidates = append(candidates, Candidate{Name: name, Desc: "(configured)"})
  1293						}
  1294					}
  1295					return candidates
  1296				}
  1297				// Pure typed leaf with no children: surface placeholder + examples.
  1298				if parentTyped {
  1299					return typedLeafCandidates(node, partial)
  1300				}
  1301				return nil
  1302			}
  1303			current = node.Children
  1304		}
  1305	
  1306		var candidates []Candidate
  1307		for name, node := range current {
  1308			if strings.HasPrefix(name, partial) {
  1309				candidates = append(candidates, Candidate{Name: name, Desc: node.Desc})
  1310			}
  1311		}
  1312		if parentTyped && currentNode != nil {
  1313			candidates = append(candidates, typedLeafCandidates(currentNode, partial)...)
  1314		}
  1315		if !dynamicConsumed && currentNode != nil && currentNode.HasDynamic() && cfg != nil {
  1316			for _, name := range currentNode.DynamicValues(cfg, words) {
  1317				if strings.HasPrefix(name, partial) {
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
  1339		for _, ex := range node.ValueExamples {
  1340			if strings.HasPrefix(ex, partial) {
  1341				out = append(out, Candidate{Name: ex, Desc: "example"})
  1342			}
  1343		}
  1344		return out
  1345	}
  1346	
  1347	// LookupDesc finds the description for a candidate name given the command path words.
  1348	// Works for both operational and config mode.
  1349	func LookupDesc(words []string, name string, configMode bool) string {
  1350		var tree map[string]*Node
  1351		if configMode {
  1352			if len(words) == 0 {
  1353				if node, ok := ConfigTopLevel[name]; ok {
  1354					return node.Desc
  1355				}
  1356				return ""
  1357			}
  1358			resolvedTop, ok := ResolveUniquePrefix(KeysFromTree(ConfigTopLevel), words[0])
  1359			if !ok {
  1360				return ""
  1361			}
  1362			if resolvedTop == "run" {
  1363				tree = OperationalTree
  1364				words = words[1:]
  1365			} else {
  1366				// Walk config top-level children (e.g. "commit" → "check")
  1367				node, ok := ConfigTopLevel[resolvedTop]
  1368				if !ok {
  1369					return ""
  1370				}
  1371				for _, w := range words[1:] {
  1372					if node.Children == nil {
  1373						return ""
  1374					}
  1375					_, node, _, ok = resolveTreeWord(node.Children, w)
  1376					if !ok {
  1377						return ""
  1378					}
  1379				}
  1380				if node.Children != nil {
  1381					if child, ok := node.Children[name]; ok {
  1382						return child.Desc
  1383					}
  1384				}
  1385				return ""
  1386			}
  1387		} else {
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
  1413				return ""
  1414			}
  1415			current = node.Children
  1416		}
  1417		if node, ok := current[name]; ok {
  1418			return node.Desc
  1419		}
  1420		return ""
  1421	}
  1422	
  1423	// WriteHelp prints aligned completion candidates to w.
  1424	// The entire output is built as a single string and written in one call
  1425	// so that readline's wrapWriter triggers only one Refresh cycle.
  1426	func WriteHelp(w io.Writer, candidates []Candidate) {
  1427		sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
  1428		maxWidth := 20
  1429		for _, c := range candidates {
  1430			if len(c.Name)+2 > maxWidth {
  1431				maxWidth = len(c.Name) + 2
  1432			}
  1433		}
  1434		var sb strings.Builder
  1435		sb.WriteString("Possible completions:\n")
  1436		for _, c := range candidates {
  1437			if c.Desc != "" {
  1438				fmt.Fprintf(&sb, "  %-*s %s\n", maxWidth, c.Name, c.Desc)
  1439			} else {
  1440				fmt.Fprintf(&sb, "  %s\n", c.Name)
  1441			}
  1442		}
  1443		io.WriteString(w, sb.String())
  1444	}
  1445	
  1446	// PrintTreeHelp prints self-generating help from a tree path.
  1447	func PrintTreeHelp(header string, tree map[string]*Node, path ...string) {
  1448		fmt.Println(header)
  1449		current := tree
  1450		for _, p := range path {

exec
/bin/bash -lc "nl -ba pkg/cmdtree/tree.go | sed -n '1090,1270p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
  1090			"check":     {Desc: "Check correctness of syntax; do not apply changes"},
  1091			"comment":   {Desc: "Add comment to commit"},
  1092			"confirmed": {Desc: "Automatically rollback if not confirmed"},
  1093		}},
  1094		"load": {Desc: "Load configuration from ASCII file", Children: map[string]*Node{
  1095			"override": {Desc: "Override existing configuration"},
  1096			"merge":    {Desc: "Merge contents with existing configuration"},
  1097			"set":      {Desc: "Execute set commands from terminal"},
  1098		}},
  1099		"edit":     {Desc: "Edit a sub-level of configuration"},
  1100		"top":      {Desc: "Exit to top level of configuration"},
  1101		"up":       {Desc: "Exit one level of configuration"},
  1102		"rollback": {Desc: "Roll back to a previous committed configuration"},
  1103		"run":      {Desc: "Run an operational-mode command"},
  1104		"exit":     {Desc: "Exit configuration mode"},
  1105		"quit":     {Desc: "Exit configuration mode"},
  1106	}
  1107	
  1108	// --- Helper functions ---
  1109	
  1110	// KeysFromTree returns a sorted list of keys from a Node map.
  1111	func KeysFromTree(tree map[string]*Node) []string {
  1112		keys := make([]string, 0, len(tree))
  1113		for k := range tree {
  1114			keys = append(keys, k)
  1115		}
  1116		sort.Strings(keys)
  1117		return keys
  1118	}
  1119	
  1120	// HelpCandidates returns Candidates from a tree's children for help display.
  1121	func HelpCandidates(tree map[string]*Node) []Candidate {
  1122		candidates := make([]Candidate, 0, len(tree))
  1123		for name, node := range tree {
  1124			candidates = append(candidates, Candidate{Name: name, Desc: node.Desc})
  1125		}
  1126		return candidates
  1127	}
  1128	
  1129	// isPlaceholder returns true for angle-bracket nodes like "<host>" that act as
  1130	// positional argument wildcards in the tree.
  1131	func isPlaceholder(name string) bool {
  1132		return len(name) > 2 && name[0] == '<' && name[len(name)-1] == '>'
  1133	}
  1134	
  1135	// findPlaceholder returns the placeholder node in a tree level, if any.
  1136	func findPlaceholder(tree map[string]*Node) *Node {
  1137		for name, node := range tree {
  1138			if isPlaceholder(name) {
  1139				return node
  1140			}
  1141		}
  1142		return nil
  1143	}
  1144	
  1145	// ResolveUniquePrefix returns the exact item, or a uniquely matching prefix.
  1146	func ResolveUniquePrefix(items []string, input string) (string, bool) {
  1147		for _, item := range items {
  1148			if item == input {
  1149				return item, true
  1150			}
  1151		}
  1152		matches := FilterPrefix(items, input)
  1153		if len(matches) != 1 {
  1154			return "", false
  1155		}
  1156		return matches[0], true
  1157	}
  1158	
  1159	func resolveTreeWord(tree map[string]*Node, word string) (string, *Node, []string, bool) {
  1160		if node, ok := tree[word]; ok {
  1161			return word, node, nil, true
  1162		}
  1163		matches := FilterPrefix(KeysOf(tree), word)
  1164		if len(matches) == 1 {
  1165			name := matches[0]
  1166			return name, tree[name], matches, true
  1167		}
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
  1243	
  1244	// CompleteFromTreeWithDesc walks the tree returning name+description pairs.
  1245	func CompleteFromTreeWithDesc(tree map[string]*Node, words []string, partial string, cfg *config.Config) []Candidate {
  1246		current := tree
  1247		var currentNode *Node
  1248		parentTyped := false
  1249		dynamicConsumed := false
  1250		for wi, w := range words {
  1251			dynamicConsumed = false
  1252			_, node, matches, ok := resolveTreeWord(current, w)
  1253			if !ok {
  1254				if parentTyped {
  1255					parentTyped = false
  1256					dynamicConsumed = true
  1257					continue
  1258				}
  1259				if currentNode != nil && currentNode.HasDynamic() {
  1260					dynamicConsumed = true
  1261					continue
  1262				}
  1263				// Check for placeholder node that consumes any value
  1264				if ph := findPlaceholder(current); ph != nil {
  1265					if ph.Children != nil {
  1266						currentNode = ph
  1267						current = ph.Children
  1268					}
  1269					dynamicConsumed = true
  1270					continue

exec
/bin/bash -lc "nl -ba pkg/config/ast_edit.go | sed -n '236,360p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
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
   331			leafKeys := path[i:]
   332			return removeMatchingNode(current, leafKeys)
   333		}
   334	
   335		nodeKeys := path[i : i+nodeKeyCount]
   336		i += nodeKeyCount
   337	
   338		// Compound key: consume child token as part of key.
   339		if childSchema.compoundKey && i < len(path) {
   340			if sub, ok := childSchema.children[path[i]]; ok {
   341				nodeKeys = append(append([]string(nil), nodeKeys...), path[i])
   342				i++
   343				childSchema = sub
   344			}
   345		}
   346	
   347		if i >= len(path) {
   348			// No more tokens: this container node itself is the target.
   349			return removeMatchingNode(current, nodeKeys)
   350		}
   351	
   352		// More tokens remain: find matching container and descend.
   353		for _, n := range *current {
   354			if !n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
   355				return deletePath(&n.Children, path, childSchema, i)
   356			}
   357		}
   358	
   359		return fmt.Errorf("path not found: container %q does not exist", strings.Join(nodeKeys, " "))
   360	}

exec
/bin/bash -lc "rg -n \"CompleteSetPathWithValues|CompleteSetPath\\(|transmit-rate \\?|SchemaCompletion|completion.*transmit|CompleteFromTreeWithDesc\" pkg/config pkg/cli pkg/grpcapi pkg/cmdtree -g '*_test.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/cmdtree/tree_test.go:132:	cands := CompleteFromTreeWithDesc(
pkg/cmdtree/tree_test.go:149:	cands := CompleteFromTreeWithDesc(
pkg/cmdtree/tree_test.go:161:	cands := CompleteFromTreeWithDesc(
pkg/config/parser_ast_test.go:5097:			results := CompleteSetPathWithValues(tc.tokens, nil)
pkg/config/completion_prefix_test.go:5:func completionNames(results []SchemaCompletion) []string {
pkg/config/completion_prefix_test.go:13:func containsCompletionName(results []SchemaCompletion, want string) bool {
pkg/config/completion_prefix_test.go:27:	results := CompleteSetPathWithValues(resolved, nil)
pkg/config/completion_prefix_test.go:33:func TestCompleteSetPathWithValuesReturnsAmbiguousLastPrefixMatches(t *testing.T) {
pkg/config/completion_prefix_test.go:34:	results := CompleteSetPathWithValues([]string{"security", "s"}, nil)
pkg/config/completion_prefix_test.go:40:func TestCompleteSetPathWithValuesReturnsRPMProbeCompletions(t *testing.T) {
pkg/config/completion_prefix_test.go:41:	results := CompleteSetPathWithValues([]string{"services", "rpm", "probe", "monitor", "test", "ping-test"}, nil)
pkg/config/completion_prefix_test.go:46:	targetResults := CompleteSetPathWithValues([]string{"services", "rpm", "probe", "monitor", "test", "ping-test", "target"}, nil)

exec
/bin/bash -lc "rg -n \"ConfigSetDataplaneKnobs|dataplane\" pkg/cmdtree pkg/cli pkg/grpcapi -g '*_test.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/cmdtree/schema_validate_test.go:12:// which walks `system dataplane` tolerates orphaned legacy DPDK
pkg/cmdtree/schema_validate_test.go:14:// (pkg/configstore/dataplane_retire.go, invoked from both Store.Load
pkg/cmdtree/schema_validate_test.go:16:// bridge strips the `dataplane-type dpdk` leaf, but any nested
pkg/cmdtree/schema_validate_test.go:17:// `system dataplane ...` sub-stanza remains; if a future
pkg/cmdtree/schema_validate_test.go:31://   - Unconditional system-dataplane walker added to SchemaValidate.
pkg/cmdtree/schema_validate_test.go:36://     any new system-dataplane validator without retired-backend
pkg/cmdtree/schema_validate_test.go:52:		"set system dataplane-type dpdk",
pkg/cmdtree/schema_validate_test.go:53:		"set system dataplane cores 2-5",
pkg/cmdtree/schema_validate_test.go:54:		"set system dataplane memory 2048",
pkg/cmdtree/schema_validate_test.go:55:		"set system dataplane socket-mem \"1024,1024\"",
pkg/cmdtree/schema_validate_test.go:56:		"set system dataplane rx-mode adaptive",
pkg/cmdtree/schema_validate_test.go:57:		"set system dataplane rx-mode idle-threshold 256",
pkg/cmdtree/schema_validate_test.go:58:		"set system dataplane rx-mode resume-threshold 32",
pkg/cmdtree/schema_validate_test.go:59:		"set system dataplane rx-mode sleep-timeout 100",
pkg/cmdtree/schema_validate_test.go:60:		"set system dataplane ports 0000:03:00.0 interface wan0",
pkg/cmdtree/schema_validate_test.go:61:		"set system dataplane ports 0000:03:00.0 rx-mode polling",
pkg/cmdtree/schema_validate_test.go:62:		"set system dataplane ports 0000:03:00.0 cores 2-3",
pkg/cmdtree/schema_validate_test.go:63:		"set system dataplane ports 0000:06:00.0 interface trust0",
pkg/cmdtree/schema_validate_test.go:83:	// system-dataplane walker without retired-backend tolerance,
pkg/cli/session_display_test.go:7:	"github.com/psaab/xpf/pkg/dataplane"
pkg/cli/session_display_test.go:120:		key := dataplane.SessionKey{Protocol: 6}
pkg/cli/session_display_test.go:121:		val := dataplane.SessionValue{IngressZone: 1, EgressZone: 2, FibIfindex: 10}
pkg/cli/session_display_test.go:133:		key := dataplane.SessionKey{Protocol: 6}
pkg/cli/session_display_test.go:134:		val := dataplane.SessionValue{IngressZone: 1, EgressZone: 2, FibIfindex: 10}
pkg/cli/session_display_test.go:146:		key := dataplane.SessionKey{Protocol: 6}
pkg/cli/session_display_test.go:147:		val := dataplane.SessionValue{IngressZone: 1, EgressZone: 2, FibIfindex: 10}
pkg/cli/session_display_test.go:159:		key := dataplane.SessionKey{Protocol: 6}
pkg/cli/session_display_test.go:161:		val := dataplane.SessionValue{IngressZone: 1, EgressZone: 2, FibIfindex: 20}
pkg/cli/session_display_test.go:172:		key := dataplane.SessionKey{Protocol: 6}
pkg/cli/session_display_test.go:173:		val := dataplane.SessionValue{IngressZone: 1, EgressZone: 2, FibIfindex: 10}
pkg/grpcapi/pagination_test.go:6:	"github.com/psaab/xpf/pkg/dataplane"
pkg/grpcapi/pagination_test.go:10:	key := dataplane.SessionKey{
pkg/grpcapi/pagination_test.go:47:	key := dataplane.SessionKeyV6{
pkg/grpcapi/pagination_test.go:122:	key := dataplane.SessionKey{
pkg/grpcapi/pagination_test.go:129:	val := dataplane.SessionValue{
pkg/cli/cli_show_system_buffers_test.go:7:	"github.com/psaab/xpf/pkg/dataplane"
pkg/cli/cli_show_system_buffers_test.go:8:	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
pkg/cli/cli_show_system_buffers_test.go:12:	*dataplane.Manager
pkg/cli/cli_show_system_buffers_test.go:29:			Manager: dataplane.New(),
pkg/grpcapi/server_diag_monitor_test.go:6:	"github.com/psaab/xpf/pkg/dataplane"
pkg/grpcapi/server_diag_monitor_test.go:11:	dataplane.DataPlane
pkg/grpcapi/server_diag_monitor_test.go:14:	counters   dataplane.InterfaceCounterValue
pkg/grpcapi/server_diag_monitor_test.go:22:func (f *monitorInterfaceServerTestDP) ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error) {
pkg/grpcapi/server_diag_monitor_test.go:30:		counters: dataplane.InterfaceCounterValue{
pkg/grpcapi/server_show_firewall_test.go:10:	"github.com/psaab/xpf/pkg/dataplane"
pkg/grpcapi/server_show_firewall_test.go:11:	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
pkg/grpcapi/server_show_firewall_test.go:16:	*dataplane.Manager
pkg/grpcapi/server_show_firewall_test.go:55:			Manager: dataplane.New(),
pkg/grpcapi/server_show_firewall_test.go:95:			Manager: dataplane.New(),
pkg/cli/cli_commit_test.go:5:// only dataplane/FRR/IPsec.
pkg/cli/cli_commit_test.go:38:// applyConfigFn is set — double-invoking would re-run dataplane compile.
pkg/cli/cli_commit_test.go:55:// dataplane set, that is a no-op — no panic, no error leak.
pkg/grpcapi/server_show_zones_test.go:9:	"github.com/psaab/xpf/pkg/dataplane"
pkg/grpcapi/server_show_zones_test.go:14:	*dataplane.Manager
pkg/grpcapi/server_show_zones_test.go:15:	counters map[uint32]dataplane.CounterValue
pkg/grpcapi/server_show_zones_test.go:22:func (d *schedulerCounterGRPCDP) ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error) {
pkg/grpcapi/server_show_zones_test.go:90:				return uint32(setID)*dataplane.MaxRulesPerPolicy + uint32(ruleIndex)
pkg/grpcapi/server_show_zones_test.go:104:			Manager: dataplane.New(),
pkg/grpcapi/server_show_zones_test.go:105:			counters: map[uint32]dataplane.CounterValue{
pkg/grpcapi/server_show_zones_test.go:108:				dataplane.MaxRulesPerPolicy * 2: {Packets: 31, Bytes: 3100},
pkg/grpcapi/server_show_zones_test.go:143:			Manager: dataplane.New(),
pkg/grpcapi/server_show_zones_test.go:144:			counters: map[uint32]dataplane.CounterValue{
pkg/grpcapi/server_show_zones_test.go:145:				dataplane.MaxRulesPerPolicy * 2: {Packets: 31, Bytes: 3100},
pkg/grpcapi/runtime_canary_test.go:4:	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
pkg/grpcapi/runtime_canary_test.go:9:// pkg/dataplane/userspace/legacy_dataplane.go only verifies that
pkg/grpcapi/runtime_canary_test.go:17:// pkg/grpcapi CAN import pkg/dataplane/userspace (the dependency
pkg/cli/monitor_test.go:10:	"github.com/psaab/xpf/pkg/dataplane"
pkg/cli/monitor_test.go:11:	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
pkg/cli/monitor_test.go:17:	dataplane.DataPlane
pkg/cli/monitor_test.go:20:	counters   dataplane.InterfaceCounterValue
pkg/cli/monitor_test.go:28:func (f *monitorInterfaceCLITestDP) ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error) {
pkg/cli/monitor_test.go:48:		counters: dataplane.InterfaceCounterValue{
pkg/cli/monitor_test.go:472:		"Userspace dataplane:",
pkg/grpcapi/server_show_chassis_forwarding_test.go:20:// handler requires a Server with a live cluster manager + dataplane,
pkg/grpcapi/server_nat_test.go:9:	"github.com/psaab/xpf/pkg/dataplane"
pkg/grpcapi/server_nat_test.go:14:	*dataplane.Manager
pkg/grpcapi/server_nat_test.go:15:	result *dataplane.ApplyResult
pkg/grpcapi/server_nat_test.go:23:func (d *natApplyResultGRPCDP) LastApplyResult() *dataplane.ApplyResult {
pkg/grpcapi/server_nat_test.go:28:func (d *natApplyResultGRPCDP) Telemetry() dataplane.Telemetry {
pkg/grpcapi/server_nat_test.go:29:	return dataplane.NewDataPlaneTelemetry(d)
pkg/grpcapi/server_nat_test.go:32:func (d *natApplyResultGRPCDP) ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error) {
pkg/grpcapi/server_nat_test.go:33:	return dataplane.CounterValue{Packets: uint64(counterID), Bytes: uint64(counterID) * 100}, nil
pkg/grpcapi/server_nat_test.go:37:	*dataplane.Manager
pkg/grpcapi/server_nat_test.go:38:	result *dataplane.ApplyResult
pkg/grpcapi/server_nat_test.go:39:	store  dataplane.SessionStore
pkg/grpcapi/server_nat_test.go:46:func (d *natSessionProviderGRPCDP) LastApplyResult() *dataplane.ApplyResult {
pkg/grpcapi/server_nat_test.go:50:func (d *natSessionProviderGRPCDP) Sessions() dataplane.SessionStore {
pkg/grpcapi/server_nat_test.go:55:	dataplane.SessionStore
pkg/grpcapi/server_nat_test.go:56:	v4 []dataplane.SessionValue
pkg/grpcapi/server_nat_test.go:57:	v6 []dataplane.SessionValueV6
pkg/grpcapi/server_nat_test.go:60:func (s *natSessionGRPCStore) ForEachV4(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
pkg/grpcapi/server_nat_test.go:62:		if !fn(dataplane.SessionKey{}, val) {
pkg/grpcapi/server_nat_test.go:69:func (s *natSessionGRPCStore) ForEachV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
pkg/grpcapi/server_nat_test.go:71:		if !fn(dataplane.SessionKeyV6{}, val) {
pkg/grpcapi/server_nat_test.go:101:		Manager: dataplane.New(),
pkg/grpcapi/server_nat_test.go:102:		result: &dataplane.ApplyResult{
pkg/grpcapi/server_nat_test.go:132:		Manager: dataplane.New(),
pkg/grpcapi/server_nat_test.go:133:		result: &dataplane.ApplyResult{
pkg/grpcapi/server_nat_test.go:140:			v4: []dataplane.SessionValue{
pkg/grpcapi/server_nat_test.go:141:				{Flags: dataplane.SessFlagSNAT, IngressZone: 1, EgressZone: 2},
pkg/grpcapi/server_nat_test.go:142:				{Flags: dataplane.SessFlagSNAT, IsReverse: 1, IngressZone: 1, EgressZone: 2},
pkg/grpcapi/server_nat_test.go:143:				{Flags: dataplane.SessFlagDNAT, IngressZone: 1, EgressZone: 2},
pkg/grpcapi/server_nat_test.go:145:			v6: []dataplane.SessionValueV6{
pkg/grpcapi/server_nat_test.go:146:				{Flags: dataplane.SessFlagSNAT, IngressZone: 1, EgressZone: 2},
pkg/cli/cli_show_cluster_test.go:8:	"github.com/psaab/xpf/pkg/dataplane"
pkg/cli/cli_show_cluster_test.go:12:	dataplane.DataPlane
pkg/cli/cli_show_cluster_test.go:32:			dataplane.GlobalCtrFabricRedirect:     100,
pkg/cli/cli_show_cluster_test.go:33:			dataplane.GlobalCtrFabricRedirectFab0: 40,
pkg/cli/cli_show_cluster_test.go:34:			dataplane.GlobalCtrFabricRedirectFab1: 50,
pkg/cli/cli_show_cluster_test.go:35:			dataplane.GlobalCtrFabricRedirectZone: 10,
pkg/cli/cli_show_cluster_test.go:36:			dataplane.GlobalCtrFabricFwdDrop:      3,
pkg/cli/cli_show_cluster_test.go:48:		dataplane.GlobalCtrFabricRedirect,
pkg/cli/cli_show_cluster_test.go:49:		dataplane.GlobalCtrFabricRedirectFab0,
pkg/cli/cli_show_cluster_test.go:50:		dataplane.GlobalCtrFabricRedirectFab1,
pkg/cli/cli_show_cluster_test.go:51:		dataplane.GlobalCtrFabricRedirectZone,
pkg/cli/cli_show_cluster_test.go:52:		dataplane.GlobalCtrFabricFwdDrop,
pkg/grpcapi/server_show_nat_test.go:9:	"github.com/psaab/xpf/pkg/dataplane"
pkg/grpcapi/server_show_nat_test.go:16:	dp := dataplane.New()
pkg/grpcapi/server_show_nat_test.go:25:	pnat.Save(&dataplane.PersistentNATBinding{
pkg/cli/cli_show_chassis_adapter_test.go:7:	"github.com/psaab/xpf/pkg/dataplane"
pkg/cli/cli_show_chassis_adapter_test.go:8:	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
pkg/cli/cli_show_chassis_adapter_test.go:13:	dataplane.DataPlane
pkg/cli/cli_show_chassis_adapter_test.go:16:	mapStats []dataplane.MapStats
pkg/cli/cli_show_chassis_adapter_test.go:23:func (f *forwardingStatusCLITestDP) GetMapStats() []dataplane.MapStats {
pkg/cli/cli_show_chassis_adapter_test.go:42:		mapStats: []dataplane.MapStats{
pkg/grpcapi/server_config_test.go:17:// newGRPCEBPFRejectStore stages `set system dataplane-type ebpf` so
pkg/grpcapi/server_config_test.go:29:	if _, err := store.LoadSet("set system dataplane-type ebpf"); err != nil {
pkg/grpcapi/server_config_test.go:53:	if !strings.Contains(st.Message(), "legacy eBPF dataplane backend has been retired") {
pkg/grpcapi/server_config_test.go:80:	if !strings.Contains(st.Message(), "legacy eBPF dataplane backend has been retired") {
pkg/grpcapi/server_config_test.go:108:	if !strings.Contains(st.Message(), "legacy eBPF dataplane backend has been retired") {
pkg/grpcapi/server_config_test.go:134:		"set system dataplane-type userspace",
pkg/grpcapi/system_action_test.go:9:	"github.com/psaab/xpf/pkg/dataplane"
pkg/grpcapi/system_action_test.go:10:	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
pkg/grpcapi/system_action_test.go:18:	dataplane.DataPlane
pkg/cli/cli_show_nat_test.go:8:	"github.com/psaab/xpf/pkg/dataplane"
pkg/cli/cli_show_nat_test.go:12:	*dataplane.Manager
pkg/cli/cli_show_nat_test.go:13:	result *dataplane.ApplyResult
pkg/cli/cli_show_nat_test.go:21:func (d *natApplyResultCLIDP) LastApplyResult() *dataplane.ApplyResult {
pkg/cli/cli_show_nat_test.go:26:func (d *natApplyResultCLIDP) ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error) {
pkg/cli/cli_show_nat_test.go:27:	return dataplane.CounterValue{Packets: uint64(counterID), Bytes: uint64(counterID) * 100}, nil
pkg/cli/cli_show_nat_test.go:32:		Manager: dataplane.New(),
pkg/cli/cli_show_nat_test.go:33:		result: &dataplane.ApplyResult{
pkg/cli/cli_show_security_test.go:9:	"github.com/psaab/xpf/pkg/dataplane"
pkg/cli/cli_show_security_test.go:10:	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
pkg/cli/cli_show_security_test.go:14:	*dataplane.Manager
pkg/cli/cli_show_security_test.go:53:			Manager: dataplane.New(),
pkg/cli/cli_show_security_test.go:95:			Manager: dataplane.New(),
pkg/grpcapi/server_show_system_buffers_test.go:9:	"github.com/psaab/xpf/pkg/dataplane"
pkg/grpcapi/server_show_system_buffers_test.go:10:	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
pkg/grpcapi/server_show_system_buffers_test.go:15:	*dataplane.Manager
pkg/grpcapi/server_show_system_buffers_test.go:33:			Manager: dataplane.New(),
pkg/grpcapi/server_show_system_buffers_test.go:93:			Manager: dataplane.New(),
pkg/grpcapi/server_sessions_test.go:8:	"github.com/psaab/xpf/pkg/dataplane"
pkg/grpcapi/server_sessions_test.go:12:	key := dataplane.SessionKey{
pkg/grpcapi/server_sessions_test.go:19:	val := dataplane.SessionValue{
pkg/grpcapi/server_sessions_test.go:20:		Flags:      dataplane.SessFlagSNAT | dataplane.SessFlagDNAT,
pkg/grpcapi/server_sessions_test.go:53:	key := dataplane.SessionKeyV6{
pkg/grpcapi/server_sessions_test.go:60:	val := dataplane.SessionValueV6{
pkg/grpcapi/server_sessions_test.go:61:		Flags:      dataplane.SessFlagSNAT | dataplane.SessFlagDNAT,
pkg/cli/cli_config_test.go:11:// newCLIEBPFRejectStore stages `set system dataplane-type ebpf` so the
pkg/cli/cli_config_test.go:22:	if _, err := store.LoadSet("set system dataplane-type ebpf"); err != nil {
pkg/cli/cli_config_test.go:29:// against a candidate carrying the retired `dataplane-type ebpf`
pkg/cli/cli_config_test.go:50:	if !strings.Contains(combined, "legacy eBPF dataplane backend has been retired") {
pkg/cli/cli_config_test.go:72:	if !strings.Contains(combined, "legacy eBPF dataplane backend has been retired") {
pkg/grpcapi/server_show_forwarding_adapter_test.go:7:	"github.com/psaab/xpf/pkg/dataplane"
pkg/grpcapi/server_show_forwarding_adapter_test.go:8:	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
pkg/grpcapi/server_show_forwarding_adapter_test.go:13:	dataplane.DataPlane
pkg/grpcapi/server_show_forwarding_adapter_test.go:16:	mapStats []dataplane.MapStats
pkg/grpcapi/server_show_forwarding_adapter_test.go:23:func (f *forwardingStatusServerTestDP) GetMapStats() []dataplane.MapStats {
pkg/grpcapi/server_show_forwarding_adapter_test.go:42:		mapStats: []dataplane.MapStats{

exec
/bin/bash -lc "rg -n \"func Test.*Complete|CompleteSetPathWithValues|valueProvider|completeConfigWithDesc|completeConfigPairs\" pkg/cli pkg/grpcapi pkg/config -g '*_test.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/config/parser_ast_test.go:5088:func TestCompleteSetPathFromZoneToZone(t *testing.T) {
pkg/config/parser_ast_test.go:5097:			results := CompleteSetPathWithValues(tc.tokens, nil)
pkg/config/completion_prefix_test.go:27:	results := CompleteSetPathWithValues(resolved, nil)
pkg/config/completion_prefix_test.go:33:func TestCompleteSetPathWithValuesReturnsAmbiguousLastPrefixMatches(t *testing.T) {
pkg/config/completion_prefix_test.go:34:	results := CompleteSetPathWithValues([]string{"security", "s"}, nil)
pkg/config/completion_prefix_test.go:40:func TestCompleteSetPathWithValuesReturnsRPMProbeCompletions(t *testing.T) {
pkg/config/completion_prefix_test.go:41:	results := CompleteSetPathWithValues([]string{"services", "rpm", "probe", "monitor", "test", "ping-test"}, nil)
pkg/config/completion_prefix_test.go:46:	targetResults := CompleteSetPathWithValues([]string{"services", "rpm", "probe", "monitor", "test", "ping-test", "target"}, nil)
pkg/grpcapi/completion_test.go:14:func TestCompleteConfigPairsCommitReturnsAllMatches(t *testing.T) {
pkg/grpcapi/completion_test.go:16:	pairs := s.completeConfigPairs([]string{"commit"}, "")
pkg/grpcapi/completion_test.go:22:func TestCompleteConfigPairsLoadReturnsAllMatches(t *testing.T) {
pkg/grpcapi/completion_test.go:24:	pairs := s.completeConfigPairs([]string{"load"}, "")
pkg/grpcapi/completion_test.go:30:func TestCompleteOperationalPairsShowConfigurationResolvesPrefixes(t *testing.T) {
pkg/grpcapi/completion_test.go:38:func TestCompleteConfigPairsUniquePrefixDescends(t *testing.T) {
pkg/grpcapi/completion_test.go:40:	pairs := s.completeConfigPairs([]string{"com"}, "")
pkg/grpcapi/completion_test.go:46:func TestCompleteConfigPairsAmbiguousPrefixReturnsMatches(t *testing.T) {
pkg/grpcapi/completion_test.go:48:	pairs := s.completeConfigPairs([]string{"co"}, "")
pkg/grpcapi/completion_test.go:54:func TestCompleteConfigPairsDynamicPathWithoutStoreDoesNotPanic(t *testing.T) {
pkg/grpcapi/completion_test.go:56:	_ = s.completeConfigPairs([]string{"set", "security", "policies", "from-zone"}, "")

exec
/bin/bash -lc "rg -n \"CompleteFromTreeWithDesc\\(|CompleteFromTree\\(\" pkg/cli pkg/grpcapi pkg/cmdtree cmd -g '*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/cli/completion.go:234:	treeCands := cmdtree.CompleteFromTreeWithDesc(tree, words, partial, cfg)
pkg/cmdtree/tree.go:1172:func CompleteFromTree(tree map[string]*Node, words []string, partial string, cfg *config.Config) []string {
pkg/cmdtree/tree.go:1245:func CompleteFromTreeWithDesc(tree map[string]*Node, words []string, partial string, cfg *config.Config) []Candidate {
pkg/cmdtree/tree_test.go:19:	cands := CompleteFromTree(OperationalTree, []string{"show", "route", "10.0.0.1"}, "", nil)
pkg/cmdtree/tree_test.go:29:	cands := CompleteFromTree(OperationalTree, []string{"ping", "8.8.8.8"}, "", nil)
pkg/cmdtree/tree_test.go:46:	cands := CompleteFromTree(
pkg/cmdtree/tree_test.go:64:	cands := CompleteFromTree(OperationalTree, []string{"show", "route", "table"}, "", cfg)
pkg/cmdtree/tree_test.go:74:	cands := CompleteFromTree(OperationalTree, []string{"sh", "sec"}, "", nil)
pkg/cmdtree/tree_test.go:81:	cands := CompleteFromTree(OperationalTree, []string{"show", "s"}, "", nil)
pkg/cmdtree/tree_test.go:132:	cands := CompleteFromTreeWithDesc(
pkg/cmdtree/tree_test.go:149:	cands := CompleteFromTreeWithDesc(
pkg/cmdtree/tree_test.go:161:	cands := CompleteFromTreeWithDesc(
pkg/grpcapi/server_cluster.go:541:	candidates := cmdtree.CompleteFromTreeWithDesc(cmdtree.OperationalTree, words, partial, cfg)
pkg/grpcapi/server_cluster.go:584:		names := cmdtree.CompleteFromTree(cmdtree.OperationalTree, words[1:], partial, cfg)

exec
/bin/bash -lc "nl -ba pkg/cli/completion.go | sed -n '1,120p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
     1	package cli
     2	
     3	import (
     4		"fmt"
     5		"io"
     6		"sort"
     7		"strings"
     8	
     9		"github.com/psaab/xpf/pkg/cmdtree"
    10		"github.com/psaab/xpf/pkg/config"
    11	)
    12	
    13	// completionNode is an alias for the canonical cmdtree.Node type.
    14	type completionNode = cmdtree.Node
    15	
    16	// operationalTree references the canonical tree in pkg/cmdtree.
    17	var operationalTree = cmdtree.OperationalTree
    18	
    19	// configTopLevel references the canonical config tree in pkg/cmdtree.
    20	var configTopLevel = cmdtree.ConfigTopLevel
    21	
    22	// completionCandidate holds a command name and its description.
    23	type completionCandidate struct {
    24		name string
    25		desc string
    26	}
    27	
    28	// cliCompleter implements readline.AutoCompleter.
    29	type cliCompleter struct {
    30		cli         *CLI
    31		helpWritten bool // set by ? Listener to suppress duplicate help from Do()
    32	}
    33	
    34	func (cc *cliCompleter) Do(line []rune, pos int) ([][]rune, int) {
    35		// If the ? Listener already wrote help, suppress duplicate output.
    36		if cc.helpWritten {
    37			cc.helpWritten = false
    38			return nil, 0
    39		}
    40	
    41		text := string(line[:pos])
    42	
    43		// Pipe filter completion: "show ... | <tab>"
    44		if pipeCandidates, handled := completePipeFilter(text); handled {
    45			if len(pipeCandidates) == 0 {
    46				return nil, 0
    47			}
    48			// Determine partial (text after "| ")
    49			idx := strings.LastIndex(text, "|")
    50			after := strings.TrimLeft(text[idx+1:], " ")
    51			partial := after
    52	
    53			sort.Slice(pipeCandidates, func(i, j int) bool { return pipeCandidates[i].name < pipeCandidates[j].name })
    54			if len(pipeCandidates) == 1 {
    55				suffix := pipeCandidates[0].name[len(partial):]
    56				return [][]rune{[]rune(suffix + " ")}, len(partial)
    57			}
    58			writeCompletionHelp(cc.cli.rl.Stdout(), pipeCandidates)
    59			names := make([]string, len(pipeCandidates))
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

exec
/bin/bash -lc "nl -ba pkg/cli/completion.go | sed -n '180,270p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   180			return nil
   181		}
   182	}
   183	
   184	// resolveCommand performs Junos-style prefix matching.
   185	// Given a partial input and a list of valid commands, it returns:
   186	// - The full command name if exactly one match
   187	// - "" and an error if ambiguous (multiple matches)
   188	// - "" and an error if no match
   189	func resolveCommand(input string, validCommands []string) (string, error) {
   190		if input == "" {
   191			return "", fmt.Errorf("missing command")
   192		}
   193		// Exact match first
   194		for _, cmd := range validCommands {
   195			if cmd == input {
   196				return cmd, nil
   197			}
   198		}
   199		// Prefix match
   200		var matches []string
   201		for _, cmd := range validCommands {
   202			if strings.HasPrefix(cmd, input) {
   203				matches = append(matches, cmd)
   204			}
   205		}
   206		switch len(matches) {
   207		case 0:
   208			return "", fmt.Errorf("unknown command: %s", input)
   209		case 1:
   210			return matches[0], nil
   211		default:
   212			sort.Strings(matches)
   213			return "", fmt.Errorf("'%s' is ambiguous.\nPossible completions:\n%s",
   214				input, formatAmbiguousMatches(matches))
   215		}
   216	}
   217	
   218	func formatAmbiguousMatches(matches []string) string {
   219		var sb strings.Builder
   220		maxWidth := 0
   221		for _, m := range matches {
   222			if len(m) > maxWidth {
   223				maxWidth = len(m)
   224			}
   225		}
   226		for _, m := range matches {
   227			sb.WriteString(fmt.Sprintf("  %s\n", m))
   228		}
   229		return sb.String()
   230	}
   231	
   232	// completeFromTreeWithDesc mirrors completeFromTree but returns name+desc pairs.
   233	func completeFromTreeWithDesc(tree map[string]*completionNode, words []string, partial string, cfg *config.Config) []completionCandidate {
   234		treeCands := cmdtree.CompleteFromTreeWithDesc(tree, words, partial, cfg)
   235		candidates := make([]completionCandidate, 0, len(treeCands))
   236		for _, c := range treeCands {
   237			candidates = append(candidates, completionCandidate{name: c.Name, desc: c.Desc})
   238		}
   239		return candidates
   240	}
   241	
   242	// writeCompletionHelp prints aligned completion candidates to w.
   243	// The entire output is built as a single string and written in one call
   244	// so that the readline wrapWriter triggers only one Refresh cycle,
   245	// cleanly re-drawing the prompt+line below.
   246	func writeCompletionHelp(w io.Writer, candidates []completionCandidate) {
   247		sort.Slice(candidates, func(i, j int) bool { return candidates[i].name < candidates[j].name })
   248		maxWidth := 20
   249		for _, c := range candidates {
   250			if len(c.name)+2 > maxWidth {
   251				maxWidth = len(c.name) + 2
   252			}
   253		}
   254		var sb strings.Builder
   255		sb.WriteString("Possible completions:\n")
   256		for _, c := range candidates {
   257			if c.desc != "" {
   258				fmt.Fprintf(&sb, "  %-*s %s\n", maxWidth, c.name, c.desc)
   259			} else {
   260				fmt.Fprintf(&sb, "  %s\n", c.name)
   261			}
   262		}
   263		io.WriteString(w, sb.String())
   264	}
   265	
   266	// keysFromTree returns a sorted list of keys from a completionNode map.
   267	// Delegates to cmdtree.KeysFromTree.
   268	func keysFromTree(tree map[string]*completionNode) []string {
   269		return cmdtree.KeysFromTree(tree)
   270	}

exec
/bin/bash -lc "nl -ba pkg/grpcapi/completion_test.go | sed -n '1,90p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
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

exec
/bin/bash -lc "nl -ba pkg/config/completion_prefix_test.go | sed -n '1,80p' && nl -ba pkg/config/parser_ast_test.go | sed -n '5080,5115p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
     1	package config
     2	
     3	import "testing"
     4	
     5	func completionNames(results []SchemaCompletion) []string {
     6		names := make([]string, len(results))
     7		for i, result := range results {
     8			names[i] = result.Name
     9		}
    10		return names
    11	}
    12	
    13	func containsCompletionName(results []SchemaCompletion, want string) bool {
    14		for _, result := range results {
    15			if result.Name == want {
    16				return true
    17			}
    18		}
    19		return false
    20	}
    21	
    22	func TestResolveConsumedSetPathTokensResolvesPrefixes(t *testing.T) {
    23		resolved, ok := ResolveConsumedSetPathTokens([]string{"secu", "na", "sou"})
    24		if !ok {
    25			t.Fatal("ResolveConsumedSetPathTokens() returned false")
    26		}
    27		results := CompleteSetPathWithValues(resolved, nil)
    28		if !containsCompletionName(results, "pool") || !containsCompletionName(results, "rule-set") {
    29			t.Fatalf("expected source NAT subtree completions after consumed prefixes, got %v", completionNames(results))
    30		}
    31	}
    32	
    33	func TestCompleteSetPathWithValuesReturnsAmbiguousLastPrefixMatches(t *testing.T) {
    34		results := CompleteSetPathWithValues([]string{"security", "s"}, nil)
    35		if !containsCompletionName(results, "screen") || !containsCompletionName(results, "ssh-known-hosts") {
    36			t.Fatalf("expected ambiguous security subtree matches, got %v", completionNames(results))
    37		}
    38	}
    39	
    40	func TestCompleteSetPathWithValuesReturnsRPMProbeCompletions(t *testing.T) {
    41		results := CompleteSetPathWithValues([]string{"services", "rpm", "probe", "monitor", "test", "ping-test"}, nil)
    42		if !containsCompletionName(results, "probe-type") || !containsCompletionName(results, "target") || !containsCompletionName(results, "thresholds") {
    43			t.Fatalf("expected RPM test subtree completions, got %v", completionNames(results))
    44		}
    45	
    46		targetResults := CompleteSetPathWithValues([]string{"services", "rpm", "probe", "monitor", "test", "ping-test", "target"}, nil)
    47		if !containsCompletionName(targetResults, "url") || !containsCompletionName(targetResults, "<target>") {
    48			t.Fatalf("expected RPM target completions, got %v", completionNames(targetResults))
    49		}
    50	}
  5080		for _, tc := range tests {
  5081			got := parseBandwidthLimit(tc.input)
  5082			if got != tc.want {
  5083				t.Errorf("parseBandwidthLimit(%q) = %d, want %d", tc.input, got, tc.want)
  5084			}
  5085		}
  5086	}
  5087	
  5088	func TestCompleteSetPathFromZoneToZone(t *testing.T) {
  5089		tests := []struct {
  5090			name   string
  5091			tokens []string
  5092			want   string
  5093		}{{name: "from-zone value shows zone hint", tokens: []string{ // expected completion name (single match)
  5094			"security", "policies", "from-zone"}, want: ""}, {name: "after from-zone value shows to-zone keyword", tokens: []string{"security", "policies", "from-zone", "trust"}, want: "to-zone"}, {name: "partial to-zone completes", tokens: []string{"security", "policies", "from-zone", "trust", "to"}, want: "to-zone"}, {name: "show configuration sub-path policies", tokens: []string{"security", "po"}, want: "policies"}, {name: "show configuration sub-path nat", tokens: []string{"security", "na"}, want: "nat"}}
  5095		for _, tc := range tests {
  5096			t.Run(tc.name, func(t *testing.T) {
  5097				results := CompleteSetPathWithValues(tc.tokens, nil)
  5098				if tc.want == "" {
  5099					return
  5100				}
  5101				if results == nil {
  5102					t.Fatalf("got nil completions, want %q", tc.want)
  5103				}
  5104				found := false
  5105				for _, r := range results {
  5106					if r.Name == tc.want {
  5107						found = true
  5108						break
  5109					}
  5110				}
  5111				if !found {
  5112					names := make([]string, len(results))
  5113					for i, r := range results {
  5114						names[i] = r.Name
  5115					}

exec
/bin/bash -lc "nl -ba pkg/config/compiler_class_of_service.go | sed -n '210,270p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   210						codePoint, ok := collectCoSDSCPRewriteCodePoint(lpNode)
   211						if !ok {
   212							continue
   213						}
   214						rewriteRule.Entries = append(rewriteRule.Entries, &CoSDSCPRewriteRuleEntry{
   215							ForwardingClass: className,
   216							LossPriority:    lossPriority,
   217							DSCPValue:       codePoint,
   218						})
   219					}
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

exec
/bin/bash -lc "nl -ba pkg/config/schema_validate_test.go | sed -n '1,180p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
     1	package config_test
     2	
     3	// Tests for the #1319 typed-leaf schema gate. SchemaValidate itself
     4	// lives in pkg/cmdtree (the validators it dispatches to live in
     5	// pkg/config); we exercise it end-to-end through configstore.Commit /
     6	// CommitCheck in the configstore tests, and exercise the validators +
     7	// AST walker here against parsed AST trees.
     8	
     9	import (
    10		"strings"
    11		"testing"
    12	
    13		"github.com/psaab/xpf/pkg/cmdtree"
    14		"github.com/psaab/xpf/pkg/config"
    15	)
    16	
    17	// schemaCheck parses a Junos hierarchical config snippet and runs
    18	// SchemaValidate against the resulting AST. apply-groups expansion is
    19	// exercised through configstore tests because configstore owns the
    20	// commit/load ordering relative to the compiler.
    21	func schemaCheck(t *testing.T, input string) error {
    22		t.Helper()
    23		p := config.NewParser(input)
    24		tree, errs := p.Parse()
    25		if len(errs) > 0 {
    26			t.Fatalf("parse errors: %v", errs)
    27		}
    28		return cmdtree.SchemaValidate(tree, nil)
    29	}
    30	
    31	func flatSchemaCheck(t *testing.T, cmds ...string) error {
    32		t.Helper()
    33		tree := &config.ConfigTree{}
    34		for _, cmd := range cmds {
    35			path, err := config.ParseSetCommand(cmd)
    36			if err != nil {
    37				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
    38			}
    39			if err := tree.SetPath(path); err != nil {
    40				t.Fatalf("SetPath(%q): %v", cmd, err)
    41			}
    42		}
    43		return cmdtree.SchemaValidate(tree, nil)
    44	}
    45	
    46	func TestSchemaValidate_TransmitRate_RejectsGarbage(t *testing.T) {
    47		err := schemaCheck(t, `class-of-service {
    48	    schedulers {
    49	        be {
    50	            transmit-rate asd;
    51	        }
    52	    }
    53	}`)
    54		if err == nil {
    55			t.Fatal("expected error for transmit-rate asd, got nil")
    56		}
    57		if !strings.Contains(err.Error(), "transmit-rate") {
    58			t.Fatalf("error should reference transmit-rate: %v", err)
    59		}
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
   116	    }
   117	}`)
   118		if err == nil {
   119			t.Fatal("expected error for transmit-rate 1, got nil")
   120		}
   121	}
   122	
   123	func TestSchemaValidate_TransmitRate_RejectsMissingValue(t *testing.T) {
   124		err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate")
   125		if err == nil {
   126			t.Fatal("expected error for transmit-rate with no value, got nil")
   127		}
   128		if !strings.Contains(err.Error(), "missing value") {
   129			t.Fatalf("error should describe missing value: %v", err)
   130		}
   131	}
   132	
   133	func TestSchemaValidate_TransmitRate_RejectsUnknownModifier(t *testing.T) {
   134		err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate 1g typo")
   135		if err == nil {
   136			t.Fatal("expected error for unknown transmit-rate modifier, got nil")
   137		}
   138		if !strings.Contains(err.Error(), "unknown modifier") {
   139			t.Fatalf("error should describe unknown modifier: %v", err)
   140		}
   141	}
   142	
   143	func TestSchemaValidate_Priority_AcceptsStrictHigh(t *testing.T) {
   144		if err := schemaCheck(t, `class-of-service {
   145		    schedulers {
   146	        be {
   147	            priority strict-high;
   148	        }
   149	    }
   150	}`); err != nil {
   151			t.Fatalf("unexpected error: %v", err)
   152		}
   153	}
   154	
   155	func TestSchemaValidate_Priority_RejectsUnknown(t *testing.T) {
   156		err := schemaCheck(t, `class-of-service {
   157	    schedulers {
   158	        be {
   159	            priority foo;
   160	        }
   161	    }
   162	}`)
   163		if err == nil {
   164			t.Fatal("expected error for priority foo, got nil")
   165		}
   166		if !strings.Contains(err.Error(), "priority") {
   167			t.Fatalf("error should reference priority: %v", err)
   168		}
   169	}
   170	
   171	func TestSchemaValidate_BufferSize_AcceptsBytes(t *testing.T) {
   172		if err := schemaCheck(t, `class-of-service {
   173	    schedulers {
   174	        be {
   175	            buffer-size 16m;
   176	        }
   177	    }
   178	}`); err != nil {
   179			t.Fatalf("unexpected error: %v", err)
   180		}

exec
/bin/bash -lc 'rg -n "transmit-rate|buffer-size|priority" pkg/config/compiler_class_of_service.go | head -80' in /home/ps/git/bpfrx/.claude/worktrees/1319-research
exec
/bin/bash -lc 'rg -n "buffer-size.*temporal|temporal" pkg/config pkg/cmdtree docs/research/1319-typed-leaf/plan.md' in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
133:				for _, lpNode := range fcNode.FindChildren("loss-priority") {
166:				for _, lpNode := range fcNode.FindChildren("loss-priority") {
202:				for _, lpNode := range fcNode.FindChildren("loss-priority") {
231:			case "transmit-rate":
237:			case "priority":
239:			case "buffer-size":
381:			// #1614 A2: priority-low-min-share <bps>
382:			if minShareNode := unitNode.FindChild("priority-low-min-share"); minShareNode != nil {

 succeeded in 0ms:
pkg/cmdtree/tree.go:1012:// and buffer-size (byte-size with optional `temporal` modifier per Junos).
pkg/cmdtree/tree.go:1053:				"temporal": {Desc: "Temporal buffer interpretation (Junos)"},
pkg/config/types.go:342:// EventWithin defines a temporal trigger clause.

exec
/bin/bash -lc "rg -n \"Complete|completion|ConfigTopLevel|CompleteSetPathWithValues|cmdtree\" cmd/cli pkg/grpcapi proto -g '*.go' -g '*.proto'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
proto/xpf/v1/xpf.proto:74:  // Tab completion
proto/xpf/v1/xpf.proto:75:  rpc Complete(CompleteRequest) returns (CompleteResponse);
proto/xpf/v1/xpf.proto:597:message CompleteRequest {
proto/xpf/v1/xpf.proto:602:message CompleteResponse {
cmd/cli/shared.go:19:	"github.com/psaab/xpf/pkg/cmdtree"
cmd/cli/shared.go:52:type remoteCompleter struct {
cmd/cli/shared.go:493:	cmdtree.WriteHelp(os.Stdout, cmdtree.HelpCandidates(cmdtree.OperationalTree))
cmd/cli/shared.go:497:	cmdtree.WriteHelp(os.Stdout, cmdtree.HelpCandidates(cmdtree.ConfigTopLevel))
cmd/cli/shared.go:500:func (rc *remoteCompleter) Do(line []rune, pos int) ([][]rune, int) {
cmd/cli/shared.go:511:	resp, err := rc.ctl.client.Complete(ctx, &pb.CompleteRequest{
cmd/cli/shared.go:545:	candidates := make([]cmdtree.Candidate, len(resp.Candidates))
cmd/cli/shared.go:555:		candidates[i] = cmdtree.Candidate{Name: name, Desc: desc}
cmd/cli/shared.go:557:	cmdtree.WriteHelp(rc.ctl.rl.Stdout(), candidates)
cmd/cli/shared.go:559:	cp := cmdtree.CommonPrefix(resp.Candidates)
cmd/cli/shared.go:568:// the canonical command tree in pkg/cmdtree. No manual desc map needed.
cmd/cli/shared.go:570:	return cmdtree.LookupDesc(words, name, configMode)
cmd/cli/shared.go:576:	cmdtree.PrintTreeHelp(header, cmdtree.OperationalTree, path...)
cmd/cli/shared.go:581:	cmdtree.PrintTreeHelp(header, cmdtree.ConfigTopLevel, path...)
pkg/grpcapi/server_show.go:947:		// consistent with the cmdtree leaf
pkg/grpcapi/completion_test.go:5:func hasPairName(pairs []completionPair, want string) bool {
pkg/grpcapi/completion_test.go:14:func TestCompleteConfigPairsCommitReturnsAllMatches(t *testing.T) {
pkg/grpcapi/completion_test.go:18:		t.Fatalf("expected all commit completions, got %#v", pairs)
pkg/grpcapi/completion_test.go:22:func TestCompleteConfigPairsLoadReturnsAllMatches(t *testing.T) {
pkg/grpcapi/completion_test.go:26:		t.Fatalf("expected all load completions, got %#v", pairs)
pkg/grpcapi/completion_test.go:30:func TestCompleteOperationalPairsShowConfigurationResolvesPrefixes(t *testing.T) {
pkg/grpcapi/completion_test.go:34:		t.Fatalf("expected policies completion for prefixed show configuration path, got %#v", pairs)
pkg/grpcapi/completion_test.go:38:func TestCompleteConfigPairsUniquePrefixDescends(t *testing.T) {
pkg/grpcapi/completion_test.go:42:		t.Fatalf("expected commit subtree completions after unique prefix, got %#v", pairs)
pkg/grpcapi/completion_test.go:46:func TestCompleteConfigPairsAmbiguousPrefixReturnsMatches(t *testing.T) {
pkg/grpcapi/completion_test.go:54:func TestCompleteConfigPairsDynamicPathWithoutStoreDoesNotPanic(t *testing.T) {
pkg/grpcapi/server_helpers.go:18:// Command trees are defined in pkg/cmdtree (single source of truth).
pkg/grpcapi/server_helpers.go:19:// gRPC completion uses cmdtree.CompleteFromTree directly.
cmd/cli/main.go:21:	"github.com/psaab/xpf/pkg/cmdtree"
cmd/cli/main.go:78:	rc := &remoteCompleter{ctl: c}
cmd/cli/main.go:85:		AutoComplete:    rc,
cmd/cli/main.go:99:			resp, err := c.client.Complete(ctx, &pb.CompleteRequest{
cmd/cli/main.go:109:			candidates := make([]cmdtree.Candidate, len(resp.Candidates))
cmd/cli/main.go:119:				candidates[i] = cmdtree.Candidate{Name: name, Desc: desc}
cmd/cli/main.go:122:			cmdtree.WriteHelp(c.rl.Stdout(), candidates)
cmd/cli/monitor.go:12:	"github.com/psaab/xpf/pkg/cmdtree"
cmd/cli/monitor.go:60:		cmdtree.PrintTreeHelp("monitor:", cmdtree.OperationalTree, "monitor")
cmd/cli/monitor.go:280:		cmdtree.PrintTreeHelp("monitor security:", cmdtree.OperationalTree, "monitor", "security")
pkg/grpcapi/server_cluster.go:12:	"github.com/psaab/xpf/pkg/cmdtree"
pkg/grpcapi/server_cluster.go:409:func (s *Server) Complete(_ context.Context, req *pb.CompleteRequest) (*pb.CompleteResponse, error) {
pkg/grpcapi/server_cluster.go:415:	// Pipe filter completion: "show ... | <tab>"
pkg/grpcapi/server_cluster.go:418:		return &pb.CompleteResponse{Candidates: candidates}, nil
pkg/grpcapi/server_cluster.go:430:	var pairs []completionPair
pkg/grpcapi/server_cluster.go:438:	resp := &pb.CompleteResponse{
pkg/grpcapi/server_cluster.go:449:// pipeFilterNames lists available pipe filters for completion.
pkg/grpcapi/server_cluster.go:453:// Returns nil if no pipe is present (caller should proceed with normal completion).
pkg/grpcapi/server_cluster.go:467:	// User has typed a complete filter + space — no more completions (freeform arg)
pkg/grpcapi/server_cluster.go:482:func filterCompletionPairs(tree map[string]*cmdtree.Node, prefix string) []completionPair {
pkg/grpcapi/server_cluster.go:483:	pairs := make([]completionPair, 0, len(tree))
pkg/grpcapi/server_cluster.go:486:			pairs = append(pairs, completionPair{name: name, desc: node.Desc})
pkg/grpcapi/server_cluster.go:496:	show, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(cmdtree.OperationalTree), words[0])
pkg/grpcapi/server_cluster.go:500:	showNode := cmdtree.OperationalTree[show]
pkg/grpcapi/server_cluster.go:504:	conf, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(showNode.Children), words[1])
pkg/grpcapi/server_cluster.go:511:func (s *Server) completionValueProvider() config.ValueProvider {
pkg/grpcapi/server_cluster.go:518:func (s *Server) completeOperationalPairs(words []string, partial string) []completionPair {
pkg/grpcapi/server_cluster.go:524:		schemaCompletions := config.CompleteSetPathWithValues(subPath, s.completionValueProvider())
pkg/grpcapi/server_cluster.go:526:			var pairs []completionPair
pkg/grpcapi/server_cluster.go:529:					pairs = append(pairs, completionPair{name: sc.Name, desc: sc.Desc})
pkg/grpcapi/server_cluster.go:541:	candidates := cmdtree.CompleteFromTreeWithDesc(cmdtree.OperationalTree, words, partial, cfg)
pkg/grpcapi/server_cluster.go:542:	pairs := make([]completionPair, len(candidates))
pkg/grpcapi/server_cluster.go:544:		pairs[i] = completionPair{name: c.Name, desc: c.Desc}
pkg/grpcapi/server_cluster.go:549:func (s *Server) completeConfigPairs(words []string, partial string) []completionPair {
pkg/grpcapi/server_cluster.go:551:		return filterCompletionPairs(cmdtree.ConfigTopLevel, partial)
pkg/grpcapi/server_cluster.go:554:	resolvedTop, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(cmdtree.ConfigTopLevel), words[0])
pkg/grpcapi/server_cluster.go:557:			return filterCompletionPairs(cmdtree.ConfigTopLevel, words[0])
pkg/grpcapi/server_cluster.go:568:		schemaCompletions := config.CompleteSetPathWithValues(pathWords, s.completionValueProvider())
pkg/grpcapi/server_cluster.go:572:		var pairs []completionPair
pkg/grpcapi/server_cluster.go:575:				pairs = append(pairs, completionPair{name: sc.Name, desc: sc.Desc})
pkg/grpcapi/server_cluster.go:584:		names := cmdtree.CompleteFromTree(cmdtree.OperationalTree, words[1:], partial, cfg)
pkg/grpcapi/server_cluster.go:585:		var pairs []completionPair
pkg/grpcapi/server_cluster.go:587:			pairs = append(pairs, completionPair{name: name})
pkg/grpcapi/server_cluster.go:592:			node := cmdtree.ConfigTopLevel[resolvedTop]
pkg/grpcapi/server_cluster.go:596:			var pairs []completionPair
pkg/grpcapi/server_cluster.go:599:					pairs = append(pairs, completionPair{name: name, desc: child.Desc})
pkg/grpcapi/server_cluster.go:790:// completionPair holds a candidate name and optional description.
pkg/grpcapi/server_cluster.go:791:type completionPair struct {
cmd/cli/show.go:296:		// cmdtree the only valid leaf is `application-identification
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:71:	BpfrxService_Complete_FullMethodName                  = "/xpf.v1.BpfrxService/Complete"
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:137:	// Tab completion
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:138:	Complete(ctx context.Context, in *CompleteRequest, opts ...grpc.CallOption) (*CompleteResponse, error)
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:675:func (c *bpfrxServiceClient) Complete(ctx context.Context, in *CompleteRequest, opts ...grpc.CallOption) (*CompleteResponse, error) {
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:677:	out := new(CompleteResponse)
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:678:	err := c.cc.Invoke(ctx, BpfrxService_Complete_FullMethodName, in, out, cOpts...)
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:748:	// Tab completion
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:749:	Complete(context.Context, *CompleteRequest) (*CompleteResponse, error)
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:907:func (UnimplementedBpfrxServiceServer) Complete(context.Context, *CompleteRequest) (*CompleteResponse, error) {
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:908:	return nil, status.Error(codes.Unimplemented, "method Complete not implemented")
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:1785:func _BpfrxService_Complete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:1786:	in := new(CompleteRequest)
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:1791:		return srv.(BpfrxServiceServer).Complete(ctx, in)
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:1795:		FullMethod: BpfrxService_Complete_FullMethodName,
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:1798:		return srv.(BpfrxServiceServer).Complete(ctx, req.(*CompleteRequest))
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:1991:			MethodName: "Complete",
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:1992:			Handler:    _BpfrxService_Complete_Handler,
pkg/grpcapi/xpfv1/xpf.pb.go:6280:type CompleteRequest struct {
pkg/grpcapi/xpfv1/xpf.pb.go:6289:func (x *CompleteRequest) Reset() {
pkg/grpcapi/xpfv1/xpf.pb.go:6290:	*x = CompleteRequest{}
pkg/grpcapi/xpfv1/xpf.pb.go:6296:func (x *CompleteRequest) String() string {
pkg/grpcapi/xpfv1/xpf.pb.go:6300:func (*CompleteRequest) ProtoMessage() {}
pkg/grpcapi/xpfv1/xpf.pb.go:6302:func (x *CompleteRequest) ProtoReflect() protoreflect.Message {
pkg/grpcapi/xpfv1/xpf.pb.go:6314:// Deprecated: Use CompleteRequest.ProtoReflect.Descriptor instead.
pkg/grpcapi/xpfv1/xpf.pb.go:6315:func (*CompleteRequest) Descriptor() ([]byte, []int) {
pkg/grpcapi/xpfv1/xpf.pb.go:6319:func (x *CompleteRequest) GetLine() string {
pkg/grpcapi/xpfv1/xpf.pb.go:6326:func (x *CompleteRequest) GetPos() int32 {
pkg/grpcapi/xpfv1/xpf.pb.go:6333:func (x *CompleteRequest) GetConfigMode() bool {
pkg/grpcapi/xpfv1/xpf.pb.go:6340:type CompleteResponse struct {
pkg/grpcapi/xpfv1/xpf.pb.go:6348:func (x *CompleteResponse) Reset() {
pkg/grpcapi/xpfv1/xpf.pb.go:6349:	*x = CompleteResponse{}
pkg/grpcapi/xpfv1/xpf.pb.go:6355:func (x *CompleteResponse) String() string {
pkg/grpcapi/xpfv1/xpf.pb.go:6359:func (*CompleteResponse) ProtoMessage() {}
pkg/grpcapi/xpfv1/xpf.pb.go:6361:func (x *CompleteResponse) ProtoReflect() protoreflect.Message {
pkg/grpcapi/xpfv1/xpf.pb.go:6373:// Deprecated: Use CompleteResponse.ProtoReflect.Descriptor instead.
pkg/grpcapi/xpfv1/xpf.pb.go:6374:func (*CompleteResponse) Descriptor() ([]byte, []int) {
pkg/grpcapi/xpfv1/xpf.pb.go:6378:func (x *CompleteResponse) GetCandidates() []string {
pkg/grpcapi/xpfv1/xpf.pb.go:6385:func (x *CompleteResponse) GetDescriptions() []string {
pkg/grpcapi/xpfv1/xpf.pb.go:7365:	"\x0fCompleteRequest\x12\x12\n" +
pkg/grpcapi/xpfv1/xpf.pb.go:7370:	"\x10CompleteResponse\x12\x1e\n" +
pkg/grpcapi/xpfv1/xpf.pb.go:7476:	"\bComplete\x12\x17.xpf.v1.CompleteRequest\x1a\x18.xpf.v1.CompleteResponseB(Z&github.com/psaab/xpf/pkg/grpcapi/xpfv1b\x06proto3"
pkg/grpcapi/xpfv1/xpf.pb.go:7602:	(*CompleteRequest)(nil),                   // 109: xpf.v1.CompleteRequest
pkg/grpcapi/xpfv1/xpf.pb.go:7603:	(*CompleteResponse)(nil),                  // 110: xpf.v1.CompleteResponse
pkg/grpcapi/xpfv1/xpf.pb.go:7692:	109, // 75: xpf.v1.BpfrxService.Complete:input_type -> xpf.v1.CompleteRequest
pkg/grpcapi/xpfv1/xpf.pb.go:7742:	110, // 125: xpf.v1.BpfrxService.Complete:output_type -> xpf.v1.CompleteResponse

exec
/bin/bash -lc "rg -n \"Completion|Complete\" proto pkg/grpcapi -g '*.proto' -g '*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
proto/xpf/v1/xpf.proto:75:  rpc Complete(CompleteRequest) returns (CompleteResponse);
proto/xpf/v1/xpf.proto:595:// --- Completion messages ---
proto/xpf/v1/xpf.proto:597:message CompleteRequest {
proto/xpf/v1/xpf.proto:602:message CompleteResponse {
pkg/grpcapi/completion_test.go:14:func TestCompleteConfigPairsCommitReturnsAllMatches(t *testing.T) {
pkg/grpcapi/completion_test.go:22:func TestCompleteConfigPairsLoadReturnsAllMatches(t *testing.T) {
pkg/grpcapi/completion_test.go:30:func TestCompleteOperationalPairsShowConfigurationResolvesPrefixes(t *testing.T) {
pkg/grpcapi/completion_test.go:38:func TestCompleteConfigPairsUniquePrefixDescends(t *testing.T) {
pkg/grpcapi/completion_test.go:46:func TestCompleteConfigPairsAmbiguousPrefixReturnsMatches(t *testing.T) {
pkg/grpcapi/completion_test.go:54:func TestCompleteConfigPairsDynamicPathWithoutStoreDoesNotPanic(t *testing.T) {
pkg/grpcapi/server_helpers.go:19:// gRPC completion uses cmdtree.CompleteFromTree directly.
pkg/grpcapi/server_cluster.go:409:func (s *Server) Complete(_ context.Context, req *pb.CompleteRequest) (*pb.CompleteResponse, error) {
pkg/grpcapi/server_cluster.go:418:		return &pb.CompleteResponse{Candidates: candidates}, nil
pkg/grpcapi/server_cluster.go:438:	resp := &pb.CompleteResponse{
pkg/grpcapi/server_cluster.go:482:func filterCompletionPairs(tree map[string]*cmdtree.Node, prefix string) []completionPair {
pkg/grpcapi/server_cluster.go:524:		schemaCompletions := config.CompleteSetPathWithValues(subPath, s.completionValueProvider())
pkg/grpcapi/server_cluster.go:525:		if schemaCompletions != nil {
pkg/grpcapi/server_cluster.go:527:			for _, sc := range schemaCompletions {
pkg/grpcapi/server_cluster.go:541:	candidates := cmdtree.CompleteFromTreeWithDesc(cmdtree.OperationalTree, words, partial, cfg)
pkg/grpcapi/server_cluster.go:551:		return filterCompletionPairs(cmdtree.ConfigTopLevel, partial)
pkg/grpcapi/server_cluster.go:557:			return filterCompletionPairs(cmdtree.ConfigTopLevel, words[0])
pkg/grpcapi/server_cluster.go:568:		schemaCompletions := config.CompleteSetPathWithValues(pathWords, s.completionValueProvider())
pkg/grpcapi/server_cluster.go:569:		if schemaCompletions == nil {
pkg/grpcapi/server_cluster.go:573:		for _, sc := range schemaCompletions {
pkg/grpcapi/server_cluster.go:584:		names := cmdtree.CompleteFromTree(cmdtree.OperationalTree, words[1:], partial, cfg)
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
pkg/grpcapi/server_cluster.go:788:// --- Completion RPC ---
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:71:	BpfrxService_Complete_FullMethodName                  = "/xpf.v1.BpfrxService/Complete"
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:138:	Complete(ctx context.Context, in *CompleteRequest, opts ...grpc.CallOption) (*CompleteResponse, error)
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:675:func (c *bpfrxServiceClient) Complete(ctx context.Context, in *CompleteRequest, opts ...grpc.CallOption) (*CompleteResponse, error) {
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:677:	out := new(CompleteResponse)
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:678:	err := c.cc.Invoke(ctx, BpfrxService_Complete_FullMethodName, in, out, cOpts...)
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:749:	Complete(context.Context, *CompleteRequest) (*CompleteResponse, error)
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:907:func (UnimplementedBpfrxServiceServer) Complete(context.Context, *CompleteRequest) (*CompleteResponse, error) {
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:908:	return nil, status.Error(codes.Unimplemented, "method Complete not implemented")
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:1785:func _BpfrxService_Complete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:1786:	in := new(CompleteRequest)
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:1791:		return srv.(BpfrxServiceServer).Complete(ctx, in)
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:1795:		FullMethod: BpfrxService_Complete_FullMethodName,
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:1798:		return srv.(BpfrxServiceServer).Complete(ctx, req.(*CompleteRequest))
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:1991:			MethodName: "Complete",
pkg/grpcapi/xpfv1/xpf_grpc.pb.go:1992:			Handler:    _BpfrxService_Complete_Handler,
pkg/grpcapi/xpfv1/xpf.pb.go:6280:type CompleteRequest struct {
pkg/grpcapi/xpfv1/xpf.pb.go:6289:func (x *CompleteRequest) Reset() {
pkg/grpcapi/xpfv1/xpf.pb.go:6290:	*x = CompleteRequest{}
pkg/grpcapi/xpfv1/xpf.pb.go:6296:func (x *CompleteRequest) String() string {
pkg/grpcapi/xpfv1/xpf.pb.go:6300:func (*CompleteRequest) ProtoMessage() {}
pkg/grpcapi/xpfv1/xpf.pb.go:6302:func (x *CompleteRequest) ProtoReflect() protoreflect.Message {
pkg/grpcapi/xpfv1/xpf.pb.go:6314:// Deprecated: Use CompleteRequest.ProtoReflect.Descriptor instead.
pkg/grpcapi/xpfv1/xpf.pb.go:6315:func (*CompleteRequest) Descriptor() ([]byte, []int) {
pkg/grpcapi/xpfv1/xpf.pb.go:6319:func (x *CompleteRequest) GetLine() string {
pkg/grpcapi/xpfv1/xpf.pb.go:6326:func (x *CompleteRequest) GetPos() int32 {
pkg/grpcapi/xpfv1/xpf.pb.go:6333:func (x *CompleteRequest) GetConfigMode() bool {
pkg/grpcapi/xpfv1/xpf.pb.go:6340:type CompleteResponse struct {
pkg/grpcapi/xpfv1/xpf.pb.go:6348:func (x *CompleteResponse) Reset() {
pkg/grpcapi/xpfv1/xpf.pb.go:6349:	*x = CompleteResponse{}
pkg/grpcapi/xpfv1/xpf.pb.go:6355:func (x *CompleteResponse) String() string {
pkg/grpcapi/xpfv1/xpf.pb.go:6359:func (*CompleteResponse) ProtoMessage() {}
pkg/grpcapi/xpfv1/xpf.pb.go:6361:func (x *CompleteResponse) ProtoReflect() protoreflect.Message {
pkg/grpcapi/xpfv1/xpf.pb.go:6373:// Deprecated: Use CompleteResponse.ProtoReflect.Descriptor instead.
pkg/grpcapi/xpfv1/xpf.pb.go:6374:func (*CompleteResponse) Descriptor() ([]byte, []int) {
pkg/grpcapi/xpfv1/xpf.pb.go:6378:func (x *CompleteResponse) GetCandidates() []string {
pkg/grpcapi/xpfv1/xpf.pb.go:6385:func (x *CompleteResponse) GetDescriptions() []string {
pkg/grpcapi/xpfv1/xpf.pb.go:7365:	"\x0fCompleteRequest\x12\x12\n" +
pkg/grpcapi/xpfv1/xpf.pb.go:7370:	"\x10CompleteResponse\x12\x1e\n" +
pkg/grpcapi/xpfv1/xpf.pb.go:7476:	"\bComplete\x12\x17.xpf.v1.CompleteRequest\x1a\x18.xpf.v1.CompleteResponseB(Z&github.com/psaab/xpf/pkg/grpcapi/xpfv1b\x06proto3"
pkg/grpcapi/xpfv1/xpf.pb.go:7602:	(*CompleteRequest)(nil),                   // 109: xpf.v1.CompleteRequest
pkg/grpcapi/xpfv1/xpf.pb.go:7603:	(*CompleteResponse)(nil),                  // 110: xpf.v1.CompleteResponse
pkg/grpcapi/xpfv1/xpf.pb.go:7692:	109, // 75: xpf.v1.BpfrxService.Complete:input_type -> xpf.v1.CompleteRequest
pkg/grpcapi/xpfv1/xpf.pb.go:7742:	110, // 125: xpf.v1.BpfrxService.Complete:output_type -> xpf.v1.CompleteResponse

exec
/bin/bash -lc "nl -ba pkg/grpcapi/server_cluster.go | sed -n '500,540p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
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
   512		if s == nil || s.store == nil {
   513			return nil
   514		}
   515		return s.valueProvider
   516	}
   517	
   518	func (s *Server) completeOperationalPairs(words []string, partial string) []completionPair {
   519		// "show configuration <path>" — delegate sub-path to config schema
   520		if subPath, ok := resolveShowConfigurationWords(words); ok {
   521			if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(subPath); resolved {
   522				subPath = resolvedPath
   523			}
   524			schemaCompletions := config.CompleteSetPathWithValues(subPath, s.completionValueProvider())
   525			if schemaCompletions != nil {
   526				var pairs []completionPair
   527				for _, sc := range schemaCompletions {
   528					if partial == "" || strings.HasPrefix(sc.Name, partial) {
   529						pairs = append(pairs, completionPair{name: sc.Name, desc: sc.Desc})
   530					}
   531				}
   532				if len(pairs) > 0 {
   533					return pairs
   534				}
   535			}
   536		}
   537		var cfg *config.Config
   538		if s.store != nil {
   539			cfg = s.store.ActiveConfig()
   540		}

exec
/bin/bash -lc "rg -n \"completeConfig|Completion\" cmd/cli -g '*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 exited 1 in 0ms:
exec
/bin/bash -lc "nl -ba pkg/grpcapi/server_cluster.go | sed -n '409,449p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   409	func (s *Server) Complete(_ context.Context, req *pb.CompleteRequest) (*pb.CompleteResponse, error) {
   410		text := req.Line
   411		if int(req.Pos) < len(text) {
   412			text = text[:req.Pos]
   413		}
   414	
   415		// Pipe filter completion: "show ... | <tab>"
   416		if candidates := s.completePipeFilter(text); candidates != nil {
   417			sort.Strings(candidates)
   418			return &pb.CompleteResponse{Candidates: candidates}, nil
   419		}
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

exec
/bin/bash -lc 'rg -o "placeholder:" pkg/config/ast.go | wc -l' in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
206

exec
/bin/bash -lc 'rg -o "args:" pkg/config/ast.go | wc -l' in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
544

exec
/bin/bash -lc "rg -o \"&schemaNode|schemaNode\\{\" pkg/config/ast.go | wc -l" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
exec
/bin/bash -lc 'rg -n "args:" pkg/config/ast.go | wc -l' in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
333

 succeeded in 0ms:
544

exec
/bin/bash -lc "rg -n \"compileTree|compileTreeForLoad|Commit|LoadSet|Load\\(\" pkg/configstore -g '*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
pkg/configstore/store.go:35:	// Commit confirmed state
pkg/configstore/store.go:84:func (s *Store) Load() error {
pkg/configstore/store.go:99:	// this rewrite, compileTree below returns
pkg/configstore/store.go:106:	compiled, err := s.compileTree(tree)
pkg/configstore/store.go:126:// mutations (EnterConfigure, Commit, Load, Set, Delete) are rejected.
pkg/configstore/store.go:149:// compileTree compiles a config tree using the appropriate method based on
pkg/configstore/store.go:162:func (s *Store) compileTree(tree *config.ConfigTree) (*config.Config, error) {
pkg/configstore/store.go:223:	compiled, err := s.compileTree(tree)
pkg/configstore/store.go:640:// LoadSet applies multiple set commands to the candidate config.
pkg/configstore/store.go:642:func (s *Store) LoadSet(content string) (int, error) {
pkg/configstore/store.go:670:// CommitCheck validates the candidate configuration without applying it.
pkg/configstore/store.go:671:func (s *Store) CommitCheck() (*config.Config, error) {
pkg/configstore/store.go:679:	compiled, err := s.compileTree(s.candidate)
pkg/configstore/store.go:687:// Commit validates, compiles, and applies the candidate configuration.
pkg/configstore/store.go:689:func (s *Store) Commit() (*config.Config, error) {
pkg/configstore/store.go:697:	compiled, err := s.compileTree(s.candidate)
pkg/configstore/store.go:745:// CommitWithDescription validates, compiles, and applies the candidate configuration
pkg/configstore/store.go:747:func (s *Store) CommitWithDescription(description string) (*config.Config, error) {
pkg/configstore/store.go:755:	compiled, err := s.compileTree(s.candidate)
pkg/configstore/store.go:811:// CommitConfirmed validates, compiles, and applies the candidate with an
pkg/configstore/store.go:814:func (s *Store) CommitConfirmed(minutes int) (*config.Config, error) {
pkg/configstore/store.go:822:	compiled, err := s.compileTree(s.candidate)
pkg/configstore/store.go:876:// ConfirmCommit cancels the auto-rollback timer, confirming the config.
pkg/configstore/store.go:877:func (s *Store) ConfirmCommit() error {
pkg/configstore/store.go:1045:// ListCommitHistory returns recent commit journal entries (most recent last).
pkg/configstore/store.go:1046:func (s *Store) ListCommitHistory(limit int) ([]*JournalEntry, error) {
pkg/configstore/store.go:1062:// CommitDiffSummary returns a human-readable summary of changes between
pkg/configstore/store.go:1064:func (s *Store) CommitDiffSummary() string {
pkg/configstore/dataplane_retire_test.go:11:// TestRewriteRetiredDataplaneType_EBPF covers the Store.Load() and
pkg/configstore/dataplane_retire_test.go:253:// Store.Load() path: a persisted active config carrying
pkg/configstore/dataplane_retire_test.go:260:// added to Store.Load().
pkg/configstore/dataplane_retire_test.go:274:	if err := store.Load(); err != nil {
pkg/configstore/dataplane_retire.go:13://   - Store.Load() — local boot reads the persisted active config
pkg/configstore/dataplane_retire.go:16://     compileTree, returns nil compiled, and bootstraps from the
pkg/configstore/dataplane_retire.go:25://     that Store.Load() alone does not cover.
pkg/configstore/dataplane_retire.go:71:// Both passes are needed even though `compileTree` later expands
pkg/configstore/dataplane_retire.go:80://   - LoadCaller ("Store.Load()"):       review and `commit` locally.
pkg/configstore/dataplane_retire.go:235:	// LoadCaller: rewrite invoked from Store.Load() during local
pkg/configstore/store_test.go:21:// #1319: end-to-end gate — CommitCheck/Commit must reject typed-leaf
pkg/configstore/store_test.go:27:func TestCommitCheck_RejectsInvalidTransmitRate(t *testing.T) {
pkg/configstore/store_test.go:35:	_, err := s.CommitCheck()
pkg/configstore/store_test.go:37:		t.Fatal("expected CommitCheck to reject transmit-rate asd, got nil")
pkg/configstore/store_test.go:40:		t.Fatalf("CommitCheck error should reference transmit-rate: %v", err)
pkg/configstore/store_test.go:42:	// Commit should refuse the same way.
pkg/configstore/store_test.go:43:	if _, err := s.Commit(); err == nil {
pkg/configstore/store_test.go:44:		t.Fatal("expected Commit to reject transmit-rate asd, got nil")
pkg/configstore/store_test.go:48:func TestCommitCheck_RejectsInvalidTransmitRateFromApplyGroups(t *testing.T) {
pkg/configstore/store_test.go:61:	_, err := s.CommitCheck()
pkg/configstore/store_test.go:63:		t.Fatal("expected CommitCheck to reject grouped transmit-rate asd, got nil")
pkg/configstore/store_test.go:66:		t.Fatalf("CommitCheck error should reference transmit-rate: %v", err)
pkg/configstore/store_test.go:70:func TestCommitCheck_AcceptsValidScheduler(t *testing.T) {
pkg/configstore/store_test.go:84:	if _, err := s.CommitCheck(); err != nil {
pkg/configstore/store_test.go:85:		t.Fatalf("CommitCheck: unexpected error: %v", err)
pkg/configstore/store_test.go:89:func TestCommitCheck_RejectsAmbiguousThreeColorPolicer(t *testing.T) {
pkg/configstore/store_test.go:105:	_, err := s.CommitCheck()
pkg/configstore/store_test.go:107:		t.Fatal("expected CommitCheck to reject ambiguous three-color policer, got nil")
pkg/configstore/store_test.go:110:		t.Fatalf("CommitCheck error = %v", err)
pkg/configstore/store_test.go:114:func TestCommitCheck_RejectsAmbiguousThreeColorPolicerAcrossLoadOverrideBlocks(t *testing.T) {
pkg/configstore/store_test.go:141:	_, err := s.CommitCheck()
pkg/configstore/store_test.go:143:		t.Fatal("expected CommitCheck to reject duplicate hierarchical single-rate/two-rate blocks")
pkg/configstore/store_test.go:146:		t.Fatalf("CommitCheck error = %v", err)
pkg/configstore/store_test.go:150:func TestCommitCheck_RejectsAmbiguousThreeColorPolicerAcrossLoadOverrideSameModeSiblings(t *testing.T) {
pkg/configstore/store_test.go:171:	_, err := s.CommitCheck()
pkg/configstore/store_test.go:173:		t.Fatal("expected CommitCheck to reject duplicate hierarchical single-rate color mode ambiguity")
pkg/configstore/store_test.go:176:		t.Fatalf("CommitCheck error = %v", err)
pkg/configstore/store_test.go:180:func TestCommitCheck_RejectsThreeColorPolicerPeakBelowCommitted(t *testing.T) {
pkg/configstore/store_test.go:196:	_, err := s.CommitCheck()
pkg/configstore/store_test.go:198:		t.Fatal("expected CommitCheck to reject peak-information-rate below committed-information-rate")
pkg/configstore/store_test.go:201:		t.Fatalf("CommitCheck error = %v", err)
pkg/configstore/store_test.go:230:func TestSetAndCommit(t *testing.T) {
pkg/configstore/store_test.go:252:	// CommitCheck should succeed
pkg/configstore/store_test.go:253:	cfg, err := s.CommitCheck()
pkg/configstore/store_test.go:255:		t.Fatalf("CommitCheck: %v", err)
pkg/configstore/store_test.go:258:		t.Fatal("CommitCheck returned nil config")
pkg/configstore/store_test.go:264:	// Commit
pkg/configstore/store_test.go:265:	cfg, err = s.Commit()
pkg/configstore/store_test.go:267:		t.Fatalf("Commit: %v", err)
pkg/configstore/store_test.go:332:	// Commit and verify
pkg/configstore/store_test.go:333:	cfg, err := s.Commit()
pkg/configstore/store_test.go:335:		t.Fatalf("Commit: %v", err)
pkg/configstore/store_test.go:354:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:373:	// Commit 1: trust zone
pkg/configstore/store_test.go:378:	cfg1, err := s.Commit()
pkg/configstore/store_test.go:386:	// Commit 2: add untrust zone
pkg/configstore/store_test.go:388:	cfg2, err := s.Commit()
pkg/configstore/store_test.go:404:	// Commit the rollback
pkg/configstore/store_test.go:405:	cfg3, err := s.Commit()
pkg/configstore/store_test.go:424:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:464:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:472:func TestCommitConfirmedAutoRollback(t *testing.T) {
pkg/configstore/store_test.go:480:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:490:	// Commit confirmed with very short timeout (use CommitConfirmed with 1 min)
pkg/configstore/store_test.go:498:	_, err := s.CommitConfirmed(1)
pkg/configstore/store_test.go:500:		t.Fatalf("CommitConfirmed: %v", err)
pkg/configstore/store_test.go:504:		t.Error("should have pending confirm after CommitConfirmed")
pkg/configstore/store_test.go:508:	if err := s.ConfirmCommit(); err != nil {
pkg/configstore/store_test.go:509:		t.Fatalf("ConfirmCommit: %v", err)
pkg/configstore/store_test.go:513:		t.Error("should not have pending confirm after ConfirmCommit")
pkg/configstore/store_test.go:523:	err := s.ConfirmCommit()
pkg/configstore/store_test.go:540:	if _, err := s1.Commit(); err != nil {
pkg/configstore/store_test.go:546:	if err := s2.Load(); err != nil {
pkg/configstore/store_test.go:565:	if err := s.Load(); err != nil {
pkg/configstore/store_test.go:579:	// Commit 1
pkg/configstore/store_test.go:581:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:585:	// Commit 2
pkg/configstore/store_test.go:587:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:599:	if err := s2.Load(); err != nil {
pkg/configstore/store_test.go:615:	// Commit 1
pkg/configstore/store_test.go:617:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:621:	// Commit 2
pkg/configstore/store_test.go:623:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:688:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:719:	// Commit and verify
pkg/configstore/store_test.go:720:	cfg, err := s.Commit()
pkg/configstore/store_test.go:722:		t.Fatalf("Commit: %v", err)
pkg/configstore/store_test.go:762:	cfg, err := s.Commit()
pkg/configstore/store_test.go:764:		t.Fatalf("Commit: %v", err)
pkg/configstore/store_test.go:787:	cfg, err := s.Commit()
pkg/configstore/store_test.go:789:		t.Fatalf("Commit: %v", err)
pkg/configstore/store_test.go:842:	// Commit 1: trust zone
pkg/configstore/store_test.go:844:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:848:	// Commit 2: add untrust
pkg/configstore/store_test.go:850:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:873:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:900:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:916:func TestCommitDiffSummary(t *testing.T) {
pkg/configstore/store_test.go:924:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:932:	summary := s.CommitDiffSummary()
pkg/configstore/store_test.go:940:	// Commit and verify summary clears
pkg/configstore/store_test.go:941:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:944:	summary = s.CommitDiffSummary()
pkg/configstore/store_test.go:950:func TestListCommitHistory(t *testing.T) {
pkg/configstore/store_test.go:957:	entries, err := s.ListCommitHistory(10)
pkg/configstore/store_test.go:965:	// Commit and check history
pkg/configstore/store_test.go:967:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:971:	entries, err = s.ListCommitHistory(10)
pkg/configstore/store_test.go:1005:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:1047:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:1086:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:1110:func TestAutoArchiveOnCommit(t *testing.T) {
pkg/configstore/store_test.go:1121:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:1172:func TestLoadSet(t *testing.T) {
pkg/configstore/store_test.go:1178:	count, err := s.LoadSet(input)
pkg/configstore/store_test.go:1197:	count2, err := s.LoadSet(input2)
pkg/configstore/store_test.go:1207:	_, err = s.LoadSet("set system host-name bad")
pkg/configstore/store_test.go:1250:func TestCommitWithDescription(t *testing.T) {
pkg/configstore/store_test.go:1257:	cfg, err := s.CommitWithDescription("initial trust zone setup")
pkg/configstore/store_test.go:1259:		t.Fatalf("CommitWithDescription: %v", err)
pkg/configstore/store_test.go:1269:	entries, err := s.ListCommitHistory(10)
pkg/configstore/store_test.go:1294:	cfg2, err := s.Commit()
pkg/configstore/store_test.go:1296:		t.Fatalf("Commit (no desc): %v", err)
pkg/configstore/store_test.go:1302:	entries, err = s.ListCommitHistory(10)
pkg/configstore/store_test.go:1390:	_, err := s.Commit()
pkg/configstore/store_test.go:1392:		t.Fatalf("Commit: %v", err)
pkg/configstore/store_test.go:1425:	_, err := s.Commit()
pkg/configstore/store_test.go:1427:		t.Fatalf("Commit: %v", err)
pkg/configstore/store_test.go:1455:// for both CommitCheck (raw error) and Commit (wrapped error). The
pkg/configstore/store_test.go:1456:// gRPC and REST surfaces both forward Commit's wrapped text, so we
pkg/configstore/store_test.go:1458:// the "commit check failed: " prefix from Commit or changes the
pkg/configstore/store_test.go:1462:func TestCommit_RejectsDPDKDataplaneType(t *testing.T) {
pkg/configstore/store_test.go:1471:	// CommitCheck returns the raw compile-error text.
pkg/configstore/store_test.go:1472:	_, ccErr := s.CommitCheck()
pkg/configstore/store_test.go:1474:		t.Fatal("CommitCheck succeeded for dataplane-type dpdk; expected retirement reject")
pkg/configstore/store_test.go:1477:		t.Fatalf("CommitCheck error = %q, want substring %q", ccErr.Error(), dpdkRetirementSubstr)
pkg/configstore/store_test.go:1479:	// CommitCheck should NOT prepend "commit check failed: " — the
pkg/configstore/store_test.go:1480:	// wrapping happens in Commit, not CommitCheck.
pkg/configstore/store_test.go:1482:		t.Fatalf("CommitCheck unexpectedly wrapped its error with 'commit check failed:' prefix: %q", ccErr.Error())
pkg/configstore/store_test.go:1485:	// Commit wraps the same compile error as "commit check failed: ...".
pkg/configstore/store_test.go:1486:	_, cmErr := s.Commit()
pkg/configstore/store_test.go:1488:		t.Fatal("Commit succeeded for dataplane-type dpdk; expected retirement reject")
pkg/configstore/store_test.go:1491:		t.Fatalf("Commit error = %q, want substring %q", cmErr.Error(), dpdkRetirementSubstr)
pkg/configstore/store_test.go:1495:		t.Fatalf("Commit error missing 'commit check failed:' wrap prefix: %q", cmErr.Error())
pkg/configstore/store_test.go:1499:// TestCommit_AcceptsUserspaceDataplaneType is the negative control:
pkg/configstore/store_test.go:1502:func TestCommit_AcceptsUserspaceDataplaneType(t *testing.T) {
pkg/configstore/store_test.go:1510:	if _, err := s.CommitCheck(); err != nil {
pkg/configstore/store_test.go:1511:		t.Fatalf("CommitCheck for userspace dataplane-type: %v", err)
pkg/configstore/store_test.go:1513:	if _, err := s.Commit(); err != nil {
pkg/configstore/store_test.go:1514:		t.Fatalf("Commit for userspace dataplane-type: %v", err)
pkg/configstore/store_test.go:1522:// Store.Load() so the daemon can come up rather than failing to
pkg/configstore/store_test.go:1527:func TestLoad_PersistedDPDKDataplaneTypeRewrittenByLoad(t *testing.T) {
pkg/configstore/store_test.go:1546:	// Fresh reader store on the same disk path. Load() must succeed
pkg/configstore/store_test.go:1551:	if err := reader.Load(); err != nil {
pkg/configstore/store_test.go:1552:		t.Fatalf("Load() rejected persisted dpdk dataplane-type: %v", err)
pkg/configstore/store_test.go:1578:func TestLoad_PersistedDPDKDataplaneTypeWithSubStanzaRewrittenByLoad(t *testing.T) {
pkg/configstore/store_test.go:1611:	if err := reader.Load(); err != nil {
pkg/configstore/store_test.go:1612:		t.Fatalf("Load() rejected persisted full DPDK sub-stanza: %v", err)

exec
/bin/bash -lc "nl -ba pkg/configstore/store.go | sed -n '1,170p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
     1	// Package configstore implements the Junos-style candidate/active
     2	// configuration management with commit and rollback support.
     3	package configstore
     4	
     5	import (
     6		"encoding/json"
     7		"fmt"
     8		"log/slog"
     9		"os"
    10		"path/filepath"
    11		"sort"
    12		"strings"
    13		"sync"
    14		"time"
    15	
    16		"github.com/psaab/xpf/pkg/cmdtree"
    17		"github.com/psaab/xpf/pkg/config"
    18	)
    19	
    20	// Store manages the candidate and active configuration.
    21	type Store struct {
    22		mu        sync.RWMutex
    23		active    *config.ConfigTree
    24		candidate *config.ConfigTree
    25		compiled  *config.Config // compiled active config
    26		history   *History
    27		dirty     bool
    28		configDir bool // true if in configuration mode
    29		filePath  string
    30	
    31		// Persistent storage
    32		db      *DB
    33		journal *Journal
    34	
    35		// Commit confirmed state
    36		confirmTimer      *time.Timer
    37		confirmPrevTree   *config.ConfigTree   // active tree before confirmed commit
    38		confirmPrevCfg    *config.Config       // compiled config before confirmed commit
    39		centralRollbackFn func(*config.Config) // callback for dataplane central-apply
    40	
    41		// Exclusive configuration mode
    42		exclusiveHolder string // who holds exclusive lock (empty = unlocked)
    43	
    44		// Config lock tracking: session ID of the holder (for auto-release on disconnect)
    45		configHolder string    // unique session ID of the config lock holder
    46		configLockAt time.Time // when the lock was acquired
    47	
    48		// Cluster read-only mode: secondary nodes reject config mutations
    49		clusterReadOnly bool
    50	
    51		// Cluster node ID for ${node} variable expansion in apply-groups.
    52		// -1 means non-cluster (use CompileConfig), >= 0 means use CompileConfigForNode.
    53		nodeID int
    54	
    55		// Edit path for hierarchical navigation (edit/top/up)
    56		editPath []string
    57	
    58		// Archival settings
    59		archiveDir string // local archive directory (empty = disabled)
    60		archiveMax int    // max archives to keep
    61	}
    62	
    63	// New creates a new config store.
    64	func New(filePath string) *Store {
    65		dbDir := filepath.Join(filepath.Dir(filePath), ".configdb")
    66		db, err := NewDB(dbDir)
    67		if err != nil {
    68			slog.Warn("failed to create config db, falling back to file-only", "err", err)
    69		}
    70	
    71		journalPath := filepath.Join(filepath.Dir(filePath), ".config.journal")
    72	
    73		return &Store{
    74			active:   &config.ConfigTree{},
    75			history:  NewHistory(50),
    76			filePath: filePath,
    77			db:       db,
    78			journal:  NewJournal(journalPath),
    79			nodeID:   -1,
    80		}
    81	}
    82	
    83	// Load builds the configuration from disk.
    84	func (s *Store) Load() error {
    85		s.mu.Lock()
    86		defer s.mu.Unlock()
    87	
    88		tree, err := s.db.ReadActive()
    89		if err != nil {
    90			return fmt.Errorf("read config: %w", err)
    91		}
    92		if tree == nil {
    93			return nil // start fresh with empty config
    94		}
    95	
    96		// Rolling-upgrade tolerance (#1373 / #1525): a node may boot
    97		// with `system dataplane-type ebpf` or `... dpdk` persisted
    98		// from before the retirement-strict validator landed. Without
    99		// this rewrite, compileTree below returns
   100		// ErrEBPFDataplaneRetired / ErrDPDKDataplaneRetired, the daemon
   101		// gets nil active config, and bootstraps blind. Rewriting the
   102		// leaf to absent (defaults to userspace) lets the daemon come
   103		// up so the operator can fix the config from CLI.
   104		rewriteRetiredDataplaneType(tree, LoadCaller)
   105	
   106		compiled, err := s.compileTree(tree)
   107		if err != nil {
   108			return fmt.Errorf("compile config: %w", err)
   109		}
   110	
   111		s.active = tree
   112		s.compiled = compiled
   113		s.loadRollbackHistory()
   114		return nil
   115	}
   116	
   117	// Save persists the active configuration to disk.
   118	func (s *Store) Save() error {
   119		s.mu.RLock()
   120		defer s.mu.RUnlock()
   121	
   122		return s.db.WriteActive(s.active)
   123	}
   124	
   125	// SetClusterReadOnly toggles cluster read-only mode. When enabled, config
   126	// mutations (EnterConfigure, Commit, Load, Set, Delete) are rejected.
   127	// Used to prevent config changes on secondary cluster nodes.
   128	func (s *Store) SetClusterReadOnly(ro bool) {
   129		s.mu.Lock()
   130		defer s.mu.Unlock()
   131		s.clusterReadOnly = ro
   132	}
   133	
   134	// ClusterReadOnly returns whether the store is in cluster read-only mode.
   135	func (s *Store) ClusterReadOnly() bool {
   136		s.mu.RLock()
   137		defer s.mu.RUnlock()
   138		return s.clusterReadOnly
   139	}
   140	
   141	// SetNodeID sets the cluster node ID for ${node} variable expansion in
   142	// apply-groups. Use -1 (default) for non-cluster mode.
   143	func (s *Store) SetNodeID(id int) {
   144		s.mu.Lock()
   145		defer s.mu.Unlock()
   146		s.nodeID = id
   147	}
   148	
   149	// compileTree compiles a config tree using the appropriate method based on
   150	// whether the store is in cluster mode (nodeID >= 0) or standalone.
   151	//
   152	// Order of operations (#1319): the typed-leaf SchemaValidate gate runs
   153	// BEFORE compile, but against the same apply-groups-expanded view the
   154	// compiler consumes. Running on the raw candidate tree would let invalid
   155	// typed leaves inside `groups { ... }` bypass the gate while still reaching
   156	// the compiler after expansion. We still validate at commit/load time rather
   157	// than at `set` time so the candidate-edit flow stays permissive —
   158	// operators can stage half-typed values without each `set` line being
   159	// rejected — and `commit check` is the one place that fails loud on garbage
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

exec
/bin/bash -lc "nl -ba pkg/configstore/store.go | sed -n '210,360p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   210		// Let caller patch the tree (e.g. preserve local chassis cluster settings).
   211		if chassisPreserve != nil {
   212			chassisPreserve(tree)
   213		}
   214	
   215		// Rolling-upgrade tolerance (AGY r4 finding on #1476): an
   216		// un-upgraded primary may push a config that still selects
   217		// the retired DPDK or eBPF dataplane. Strict-validator-driven
   218		// sync rejection would alarm-loop the cluster. Rewrite the
   219		// retired leaf so the standby boots through cleanly while the
   220		// operator updates the primary.
   221		rewriteRetiredDataplaneType(tree, SyncCaller)
   222	
   223		compiled, err := s.compileTree(tree)
   224		if err != nil {
   225			return nil, fmt.Errorf("sync config compile error: %w", err)
   226		}
   227	
   228		// Push current active to history.
   229		s.history.Push(&HistoryEntry{
   230			Config:    s.active.Clone(),
   231			Timestamp: time.Now(),
   232		})
   233	
   234		s.active = tree
   235		s.compiled = compiled
   236		s.dirty = false
   237	
   238		// If in config mode, update candidate too.
   239		if s.configDir {
   240			s.candidate = s.active.Clone()
   241		}
   242	
   243		if err := s.db.WriteActive(s.active); err != nil {
   244			slog.Warn("failed to save synced config", "err", err)
   245		}
   246	
   247		s.journal.Log(&JournalEntry{
   248			Timestamp: time.Now(),
   249			Action:    "config_sync",
   250			After:     compiled,
   251		})
   252	
   253		s.saveRollbackFiles()
   254		return compiled, nil
   255	}
   256	
   257	// EnterConfigure enters configuration mode by cloning the active config.
   258	// Returns an error if another session is already in config mode.
   259	func (s *Store) EnterConfigure() error {
   260		return s.EnterConfigureSession("")
   261	}
   262	
   263	// EnterConfigureSession enters configuration mode with a session identifier.
   264	// If the same session already holds the lock, it's a no-op.
   265	func (s *Store) EnterConfigureSession(sessionID string) error {
   266		s.mu.Lock()
   267		defer s.mu.Unlock()
   268		if s.clusterReadOnly {
   269			return fmt.Errorf("configuration database is not writable (secondary node)")
   270		}
   271		if s.configDir {
   272			// Allow re-entry by same session.
   273			if sessionID != "" && s.configHolder == sessionID {
   274				return nil
   275			}
   276			return fmt.Errorf("configuration is locked by another user")
   277		}
   278		s.candidate = s.active.Clone()
   279		s.configDir = true
   280		s.dirty = false
   281		s.configHolder = sessionID
   282		s.configLockAt = time.Now()
   283		return nil
   284	}
   285	
   286	// EnterConfigureExclusive enters exclusive configuration mode.
   287	func (s *Store) EnterConfigureExclusive(holder string) error {
   288		s.mu.Lock()
   289		defer s.mu.Unlock()
   290		if s.clusterReadOnly {
   291			return fmt.Errorf("configuration database is not writable (secondary node)")
   292		}
   293		if s.configDir {
   294			return fmt.Errorf("configuration is locked by another user")
   295		}
   296		s.candidate = s.active.Clone()
   297		s.configDir = true
   298		s.dirty = false
   299		s.exclusiveHolder = holder
   300		s.configLockAt = time.Now()
   301		return nil
   302	}
   303	
   304	// ExitConfigureSession exits configuration mode only if the given session holds
   305	// the lock. Returns true if the lock was released.
   306	func (s *Store) ExitConfigureSession(sessionID string) bool {
   307		s.mu.Lock()
   308		defer s.mu.Unlock()
   309		if !s.configDir {
   310			return false
   311		}
   312		if sessionID != "" && s.configHolder != sessionID {
   313			return false
   314		}
   315		s.candidate = nil
   316		s.configDir = false
   317		s.dirty = false
   318		s.exclusiveHolder = ""
   319		s.configHolder = ""
   320		s.editPath = nil
   321		return true
   322	}
   323	
   324	// ForceExitConfigure exits configuration mode regardless of who holds the lock.
   325	// Used for stale lock cleanup.
   326	func (s *Store) ForceExitConfigure() {
   327		s.mu.Lock()
   328		defer s.mu.Unlock()
   329		if !s.configDir {
   330			return
   331		}
   332		slog.Warn("force-releasing stale config lock", "holder", s.configHolder,
   333			"held_for", time.Since(s.configLockAt).Round(time.Second))
   334		s.candidate = nil
   335		s.configDir = false
   336		s.dirty = false
   337		s.exclusiveHolder = ""
   338		s.configHolder = ""
   339		s.editPath = nil
   340	}
   341	
   342	// ConfigHolder returns the session ID of the current config lock holder
   343	// and whether the lock is held.
   344	func (s *Store) ConfigHolder() (string, bool) {
   345		s.mu.RLock()
   346		defer s.mu.RUnlock()
   347		return s.configHolder, s.configDir
   348	}
   349	
   350	// IsExclusiveLocked returns true if exclusive mode is active.
   351	func (s *Store) IsExclusiveLocked() bool {
   352		s.mu.RLock()
   353		defer s.mu.RUnlock()
   354		return s.exclusiveHolder != ""
   355	}
   356	
   357	// ExitConfigure exits configuration mode, discarding the candidate.
   358	func (s *Store) ExitConfigure() {
   359		s.mu.Lock()
   360		defer s.mu.Unlock()

exec
/bin/bash -lc "nl -ba pkg/configstore/store.go | sed -n '360,520p'" in /home/ps/git/bpfrx/.claude/worktrees/1319-research
 succeeded in 0ms:
   360		defer s.mu.Unlock()
   361		s.candidate = nil
   362		s.configDir = false
   363		s.dirty = false
   364		s.exclusiveHolder = ""
   365		s.editPath = nil
   366	}
   367	
   368	// SetEditPath sets the edit path for hierarchical navigation.
   369	func (s *Store) SetEditPath(path []string) {
   370		s.mu.Lock()
   371		defer s.mu.Unlock()
   372		s.editPath = path
   373	}
   374	
   375	// GetEditPath returns a copy of the current edit path.
   376	func (s *Store) GetEditPath() []string {
   377		s.mu.RLock()
   378		defer s.mu.RUnlock()
   379		return append([]string{}, s.editPath...)
   380	}
   381	
   382	// NavigateUp moves the edit path up one level.
   383	func (s *Store) NavigateUp() {
   384		s.mu.Lock()
   385		defer s.mu.Unlock()
   386		if len(s.editPath) > 0 {
   387			s.editPath = s.editPath[:len(s.editPath)-1]
   388		}
   389	}
   390	
   391	// NavigateTop resets the edit path to the root.
   392	func (s *Store) NavigateTop() {
   393		s.mu.Lock()
   394		defer s.mu.Unlock()
   395		s.editPath = nil
   396	}
   397	
   398	// InConfigMode returns true if currently in configuration mode.
   399	func (s *Store) InConfigMode() bool {
   400		s.mu.RLock()
   401		defer s.mu.RUnlock()
   402		return s.configDir
   403	}
   404	
   405	// IsDirty returns true if the candidate differs from active.
   406	func (s *Store) IsDirty() bool {
   407		s.mu.RLock()
   408		defer s.mu.RUnlock()
   409		return s.dirty
   410	}
   411	
   412	// Set applies a "set" command to the candidate configuration.
   413	func (s *Store) Set(path []string) error {
   414		s.mu.Lock()
   415		defer s.mu.Unlock()
   416	
   417		if s.candidate == nil {
   418			return fmt.Errorf("not in configuration mode")
   419		}
   420	
   421		if err := s.candidate.SetPath(path); err != nil {
   422			return err
   423		}
   424		s.dirty = true
   425		return nil
   426	}
   427	
   428	// SetFromInput parses a "set ..." command string and applies it.
   429	func (s *Store) SetFromInput(input string) error {
   430		path, err := config.ParseSetCommand("set " + input)
   431		if err != nil {
   432			return err
   433		}
   434		return s.Set(path)
   435	}
   436	
   437	// Delete removes a node at the given path from the candidate configuration.
   438	func (s *Store) Delete(path []string) error {
   439		s.mu.Lock()
   440		defer s.mu.Unlock()
   441	
   442		if s.candidate == nil {
   443			return fmt.Errorf("not in configuration mode")
   444		}
   445	
   446		if err := s.candidate.DeletePath(path); err != nil {
   447			return err
   448		}
   449		s.dirty = true
   450		return nil
   451	}
   452	
   453	// DeleteFromInput parses a "delete ..." command string and applies it.
   454	func (s *Store) DeleteFromInput(input string) error {
   455		path, err := config.ParseSetCommand("delete " + input)
   456		if err != nil {
   457			return err
   458		}
   459		return s.Delete(path)
   460	}
   461	
   462	// Copy duplicates a config subtree from srcPath to dstPath.
   463	func (s *Store) Copy(srcPath, dstPath []string) error {
   464		s.mu.Lock()
   465		defer s.mu.Unlock()
   466		if s.candidate == nil {
   467			return fmt.Errorf("not in configuration mode")
   468		}
   469		if err := s.candidate.CopyPath(srcPath, dstPath); err != nil {
   470			return err
   471		}
   472		s.dirty = true
   473		return nil
   474	}
   475	
   476	// Rename moves a config subtree from srcPath to dstPath.
   477	func (s *Store) Rename(srcPath, dstPath []string) error {
   478		s.mu.Lock()
   479		defer s.mu.Unlock()
   480		if s.candidate == nil {
   481			return fmt.Errorf("not in configuration mode")
   482		}
   483		if err := s.candidate.RenamePath(srcPath, dstPath); err != nil {
   484			return err
   485		}
   486		s.dirty = true
   487		return nil
   488	}
   489	
   490	// Insert moves an element before or after a reference element within the
   491	// same parent's ordered children list.
   492	func (s *Store) Insert(elementPath, refPath []string, before bool) error {
   493		s.mu.Lock()
   494		defer s.mu.Unlock()
   495		if s.candidate == nil {
   496			return fmt.Errorf("not in configuration mode")
   497		}
   498		var err error
   499		if before {
   500			err = s.candidate.InsertBefore(elementPath, refPath)
   501		} else {
   502			err = s.candidate.InsertAfter(elementPath, refPath)
   503		}
   504		if err != nil {
   505			return err
   506		}
   507		s.dirty = true
   508		return nil
   509	}
   510	
   511	// Annotate sets a comment on a configuration node in the candidate config.
   512	func (s *Store) Annotate(path []string, comment string) error {
   513		s.mu.Lock()
   514		defer s.mu.Unlock()
   515	
   516		if s.candidate == nil {
   517			return fmt.Errorf("not in configuration mode")
   518		}
   519	
   520		children := s.candidate.Children

codex
**Verdict: PLAN-NEEDS-MAJOR**

Not `PLAN-KILL`: I did not find a verified counterexample that invalidates Option A. The central diagnosis is correct, but the plan has material gaps that must be fixed before implementation.

**Verified Claim**

§2.2 is correct. Production config-mode completion does not use the cmdtree typed leaves today.

Evidence:

- Local CLI routes config `set/delete/show/edit` through `setSchema`: “`case "set", "delete", "show", "edit":`” then “`config.CompleteSetPathWithValues(pathWords, c.valueProvider)`” in [pkg/cli/completion.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cli/completion.go:142).
- gRPC does the same: “`schemaCompletions := config.CompleteSetPathWithValues(pathWords, s.completionValueProvider())`” in [pkg/grpcapi/server_cluster.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/grpcapi/server_cluster.go:568).
- `setSchema` has no scheduler value metadata: “`"transmit-rate": {args: 1, children: map[string]*schemaNode{`” in [pkg/config/ast.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast.go:1165).
- The existing typed-leaf test is on the non-production config path: “`cands := CompleteFromTreeWithDesc(ConfigTopLevel, ... "transmit-rate")`” in [pkg/cmdtree/tree_test.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cmdtree/tree_test.go:132).

So the plan is right that symptom 1 is still open for the live `set` completion path.

**Findings**

1. **HIGH: Option A has an unresolved type-ownership/import-cycle hole.**

The plan says: “`Type definitions (ValueType, LeafValidator) already live in/near pkg/config; cmdtree aliases them`” in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:192). That is false for `ValueType`.

Actual code: “`type ValueType int`” lives in [pkg/cmdtree/tree.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cmdtree/tree.go:35), while cmdtree already imports config: “`github.com/psaab/xpf/pkg/config`” in [pkg/cmdtree/tree.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cmdtree/tree.go:19). Only `LeafValidator` lives in config: “`type LeafValidator func(raw string, cfg *Config) error`” in [pkg/config/schema_validators.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/schema_validators.go:26).

`pkg/config` cannot add `valueType cmdtree.ValueType` without an import cycle. PR1 must explicitly move `ValueType`, constants, and `Placeholder()` into `pkg/config` or a neutral schema package, then alias from cmdtree.

2. **HIGH: The compiled-leaf-only invariant is already contradicted by the subtree the plan wants to migrate.**

The plan says: “`only type a leaf the compiler actually consumes`” in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:269). But current cmdtree scheduler metadata includes an uncompiled modifier: “`"temporal": {Desc: "Temporal buffer interpretation (Junos)"}`” in [pkg/cmdtree/tree.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cmdtree/tree.go:1053).

The compiler’s `buffer-size` case only reads the value: “`if v := nodeVal(child); v != "" { ... }`” in [pkg/config/compiler_class_of_service.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/compiler_class_of_service.go:240). There is no compiled `temporal` handling.

Do not “migrate” `ConfigClassOfServiceSchedulers` wholesale. PR1 must explicitly drop or defer `buffer-size temporal`, or compile it first. Otherwise Option A imports dead Junos syntax into the real schema.

3. **HIGH: Copying cmdtree modifier children into `setSchema` can change `SetPath` behavior.**

The plan claims additive schema fields are safe: “`Adding fields to schemaNode is additive and must not change grouping`” in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:276). Fields alone are safe. Changing `children` is not.

Today `setSchema` has “`"buffer-size": {args: 1, children: nil}`” in [pkg/config/ast.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast.go:1169). `SetPath` replacement for single-value leaves depends on `children == nil`: “`childSchema.args > 0 && !childSchema.multi && childSchema.children == nil`” in [pkg/config/ast_edit.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast_edit.go:196).

If PR1 adds `children: {"temporal": ...}` to `buffer-size`, repeated `set ... buffer-size X` behavior changes from replace-like to container-like. The plan needs an explicit rule: typed metadata fields only in PR1; no child-shape changes except with SetPath golden coverage and compiler support.

4. **MEDIUM: “Generic recursion” is underspecified; the current special cases are not accidental.**

The plan says: “`generic walker is a trivial recursion`” in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:184). Current validation has scheduler-specific shape handling: “`walkSchedulers handles both AST shapes`” in [pkg/cmdtree/schema_validate.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cmdtree/schema_validate.go:59), plus split `exact` logic: “`allowsModifierOnlyTypedLeaf(leafName, tok)`” in [pkg/cmdtree/schema_validate.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cmdtree/schema_validate.go:190).

`SetPath` also has nontrivial schema semantics: “`midKeyword`”, “`compoundKey`” in [pkg/config/ast.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast.go:393), and multi-value sibling handling in [pkg/config/ast_edit.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast_edit.go:237).

The plan needs a concrete walker contract before it is ready: how `args`, hierarchical child-args, flat `Keys`, `compoundKey`, `midKeyword`, `multi`, modifier-only lines, and `groups` are matched.

5. **MEDIUM: The proposed completion test risks repeating the same class of mistake.**

The plan correctly attacks the old test because it “`exercises a code path the CLI does not use for set`” in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:77). But then it proposes: “`Add a CLI-path test ... through CompleteSetPathWithValues`” in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:220).

That helper is necessary but not sufficient. Add tests at the actual local/gRPC production boundary: local `completeConfigWithDesc` and gRPC `completeConfigPairs`/`Complete`, including trailing-space behavior for `set class-of-service schedulers x transmit-rate `.

**Bottom Line**

Option A is still the right direction: `setSchema` is the real config-mode grammar path. But the plan is not ready until it fixes type ownership, forbids accidental schema-shape changes, resolves the `buffer-size temporal` contradiction, and specifies the generic AST/schema walker precisely.
tokens used
162,653
**Verdict: PLAN-NEEDS-MAJOR**

Not `PLAN-KILL`: I did not find a verified counterexample that invalidates Option A. The central diagnosis is correct, but the plan has material gaps that must be fixed before implementation.

**Verified Claim**

§2.2 is correct. Production config-mode completion does not use the cmdtree typed leaves today.

Evidence:

- Local CLI routes config `set/delete/show/edit` through `setSchema`: “`case "set", "delete", "show", "edit":`” then “`config.CompleteSetPathWithValues(pathWords, c.valueProvider)`” in [pkg/cli/completion.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cli/completion.go:142).
- gRPC does the same: “`schemaCompletions := config.CompleteSetPathWithValues(pathWords, s.completionValueProvider())`” in [pkg/grpcapi/server_cluster.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/grpcapi/server_cluster.go:568).
- `setSchema` has no scheduler value metadata: “`"transmit-rate": {args: 1, children: map[string]*schemaNode{`” in [pkg/config/ast.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast.go:1165).
- The existing typed-leaf test is on the non-production config path: “`cands := CompleteFromTreeWithDesc(ConfigTopLevel, ... "transmit-rate")`” in [pkg/cmdtree/tree_test.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cmdtree/tree_test.go:132).

So the plan is right that symptom 1 is still open for the live `set` completion path.

**Findings**

1. **HIGH: Option A has an unresolved type-ownership/import-cycle hole.**

The plan says: “`Type definitions (ValueType, LeafValidator) already live in/near pkg/config; cmdtree aliases them`” in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:192). That is false for `ValueType`.

Actual code: “`type ValueType int`” lives in [pkg/cmdtree/tree.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cmdtree/tree.go:35), while cmdtree already imports config: “`github.com/psaab/xpf/pkg/config`” in [pkg/cmdtree/tree.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cmdtree/tree.go:19). Only `LeafValidator` lives in config: “`type LeafValidator func(raw string, cfg *Config) error`” in [pkg/config/schema_validators.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/schema_validators.go:26).

`pkg/config` cannot add `valueType cmdtree.ValueType` without an import cycle. PR1 must explicitly move `ValueType`, constants, and `Placeholder()` into `pkg/config` or a neutral schema package, then alias from cmdtree.

2. **HIGH: The compiled-leaf-only invariant is already contradicted by the subtree the plan wants to migrate.**

The plan says: “`only type a leaf the compiler actually consumes`” in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:269). But current cmdtree scheduler metadata includes an uncompiled modifier: “`"temporal": {Desc: "Temporal buffer interpretation (Junos)"}`” in [pkg/cmdtree/tree.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cmdtree/tree.go:1053).

The compiler’s `buffer-size` case only reads the value: “`if v := nodeVal(child); v != "" { ... }`” in [pkg/config/compiler_class_of_service.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/compiler_class_of_service.go:240). There is no compiled `temporal` handling.

Do not “migrate” `ConfigClassOfServiceSchedulers` wholesale. PR1 must explicitly drop or defer `buffer-size temporal`, or compile it first. Otherwise Option A imports dead Junos syntax into the real schema.

3. **HIGH: Copying cmdtree modifier children into `setSchema` can change `SetPath` behavior.**

The plan claims additive schema fields are safe: “`Adding fields to schemaNode is additive and must not change grouping`” in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:276). Fields alone are safe. Changing `children` is not.

Today `setSchema` has “`"buffer-size": {args: 1, children: nil}`” in [pkg/config/ast.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast.go:1169). `SetPath` replacement for single-value leaves depends on `children == nil`: “`childSchema.args > 0 && !childSchema.multi && childSchema.children == nil`” in [pkg/config/ast_edit.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast_edit.go:196).

If PR1 adds `children: {"temporal": ...}` to `buffer-size`, repeated `set ... buffer-size X` behavior changes from replace-like to container-like. The plan needs an explicit rule: typed metadata fields only in PR1; no child-shape changes except with SetPath golden coverage and compiler support.

4. **MEDIUM: “Generic recursion” is underspecified; the current special cases are not accidental.**

The plan says: “`generic walker is a trivial recursion`” in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:184). Current validation has scheduler-specific shape handling: “`walkSchedulers handles both AST shapes`” in [pkg/cmdtree/schema_validate.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cmdtree/schema_validate.go:59), plus split `exact` logic: “`allowsModifierOnlyTypedLeaf(leafName, tok)`” in [pkg/cmdtree/schema_validate.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/cmdtree/schema_validate.go:190).

`SetPath` also has nontrivial schema semantics: “`midKeyword`”, “`compoundKey`” in [pkg/config/ast.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast.go:393), and multi-value sibling handling in [pkg/config/ast_edit.go](/home/ps/git/bpfrx/.claude/worktrees/1319-research/pkg/config/ast_edit.go:237).

The plan needs a concrete walker contract before it is ready: how `args`, hierarchical child-args, flat `Keys`, `compoundKey`, `midKeyword`, `multi`, modifier-only lines, and `groups` are matched.

5. **MEDIUM: The proposed completion test risks repeating the same class of mistake.**

The plan correctly attacks the old test because it “`exercises a code path the CLI does not use for set`” in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:77). But then it proposes: “`Add a CLI-path test ... through CompleteSetPathWithValues`” in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1319-research/docs/research/1319-typed-leaf/plan.md:220).

That helper is necessary but not sufficient. Add tests at the actual local/gRPC production boundary: local `completeConfigWithDesc` and gRPC `completeConfigPairs`/`Complete`, including trailing-space behavior for `set class-of-service schedulers x transmit-rate `.

**Bottom Line**

Option A is still the right direction: `setSchema` is the real config-mode grammar path. But the plan is not ready until it fixes type ownership, forbids accidental schema-shape changes, resolves the `buffer-size temporal` contradiction, and specifies the generic AST/schema walker precisely.
