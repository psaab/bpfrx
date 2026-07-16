# #5878 — Peer-only numeric interface-unit aliases bypass strict canonical collision validation

**Status:** RESEARCH / PLAN-DEFERRED. No production code in this branch —
deliverable is this design doc only.

**Labels:** audit, bug, security (HIGH)

**Branch:** `research/5878-unit-canonical-collision` off `origin/master`
(base `13fad1d31`).

---

## 1. Problem restatement

A logical interface unit has an *integer* identity, but the config grammar
admits several textual spellings that all normalize to the same integer:

| spelling | `strconv.Atoi` result |
|----------|-----------------------|
| `1`      | 1 |
| `01`, `001` | 1 (leading zeros) |
| `+1`     | 1 (signed) |
| `0`, `00`, `-0`, `+0` | 0 |

The #5631 gate (`validateInterfaceUnitAliasCollisionsAST`) already rejects two
distinct spellings of the same unit **when they both appear in the view being
compiled**. The residual #5878 defect is that the gate runs on the
**submitting node's** effective view only. Peer-only `groups node1 { … }` blocks
applied through `apply-groups "${node}"`, or any node-inverted / inherited /
generated statement, can introduce the aliasing spelling **only in the standby
node's** effective view. The active node commits green; the standby's compiled
config then diverges — the unit's firewall filter, addresses, zone/NAT/policy
binding, or tunnel address set differ — and a failover silently changes
forwarding or security posture despite a "synchronized" commit.

This is the same class of both-node-symmetry defect that was already closed for
stable tunnel IDs (#1873/#1914), stable zone IDs (#3075), routing-instance
table IDs (#3855), and duplicate named blocks (#5180). Those gates run as a
**pre-expansion union across every group** *plus*, for tunnel IDs, per-node
expansions of **both** node0 and node1 (`validateTunnelEndpointIDCollisionAST`,
`pkg/config/tunnelid.go`). The unit-alias gate never received that treatment.

---

## 2. Blast radius — where unit identity is parsed, canonicalized, and bound

### 2.1 The canonical-identity substrate (mostly present, not reusable)

- **`ValidateLogicalUnit(raw, cfg)`** (`pkg/config/schema_validators.go:156`)
  is documented as *"the ONE canonical numeric-identity validator"*, but it is
  `ValidateInteger(0, MaxLogicalUnit)` — it only **validates** that `raw`
  parses to an int in `[0..16385]`. It returns `error`; it does **not** return
  or expose the canonical integer/string. `01` and `1` both pass; nothing keys
  off a shared canonical form here.
- **`compileInterfaces`** (`pkg/config/compiler_interfaces.go:222`) is where a
  unit acquires its true runtime identity: `unitNum, err := strconv.Atoi(unitInst.name)`
  then `ifc.Units[unitNum] = unit`. The typed struct **is** keyed by canonical
  int — so `01` and `1` land on the same map key with last-writer-wins for the
  unit body and append-only accumulation for `ifc.Tunnel.Addresses` (the #5631
  order-dependent fail-open). Canonicalization exists here but is *ad hoc*
  (`strconv.Atoi` inline), duplicated at ~10 call sites in this file alone.
- **`namedInstances`** (`pkg/config/compiler_protocols.go:983`) splits the AST
  into per-unit instances by raw `Keys[1]` / child name — it preserves each raw
  spelling, so `unit 01` and `unit 1` arrive as two separate instances that
  then collide on the canonical int. This is why the alias detection must be an
  AST pre-walk: the raw spellings survive only in the AST, not in `ifc.Units`.

### 2.2 The existing collision gate (node-local — the gap)

- **`validateInterfaceUnitAliasCollisionsAST`**
  (`pkg/config/compiler_interface_unit_alias.go:75`) groups the distinct raw
  spellings under each interface by `strconv.Atoi` and rejects (strict) / warns
  (lenient) when ≥2 spellings map to one int. Correct *for one view*.
- It is invoked from **`runPreWalkGates`** (`pkg/config/compiler_prewalk.go:458`),
  which runs **inside `compileExpanded`** (`pkg/config/compiler.go:2504`).
  `compileExpanded` is reached only **after**
  `tree.ExpandGroupsWithVars({node: nodeN})` in
  `compileConfigForNodeWithOpts` (`pkg/config/compiler.go:2470-2483`). ⇒ the
  alias gate sees exactly one node's post-`${node}` effective tree.
- **Commit compiles one node.** `Store.compileTree` →
  `compileTreeStrict(tree, s.nodeID)` (`pkg/configstore/store.go:336-343`) calls
  `config.CompileConfigForNode(tree, nodeID)` with the **local** `s.nodeID`
  only. The peer node's effective view is never compiled on the committing
  node. So a `groups node1`-scoped alias that folds onto a base `unit 1` is
  invisible at a node0 commit.

Contrast — the gates that got this right (`compileConfigForNodeWithOpts`,
`pkg/config/compiler.go:2438-2468`) run **before** `ExpandGroupsWithVars` as a
union across all groups: `validateTunnelEndpointIDCollisionAST`,
`validateZoneIDCollisionAST`, `validateRoutingInstanceTableIDCollisionAST`,
`validateDuplicateNamedBlockAST`. The unit-alias gate is conspicuously *not*
in this pre-expansion block; it sits inside the post-expansion pre-walk.

### 2.3 Cross-subsystem references — canonicalization *not* threaded

References that carry a `.unit` suffix are validated for *syntactic* legality
(`validateInterfaceUnitReferencesStrict`,
`pkg/config/compiler_validate_strict_unitref.go`, invoked from
`compiler_uniformgates.go:504` on the compiled `cfg`) but the suffix is bound
by **raw string**, not canonical int:

- **Security zones** — `zoneIfaceLogicalKeys`
  (`pkg/config/compiler_validate_strict_zones.go:203`) returns
  `base + "." + unit` where `unit` is the **raw** `strings.Cut(".")` suffix for
  an explicit ref, but `fmt.Sprintf("%s.%d", base, unitNum)` (canonical int)
  when expanding the interface's own units. So a zone member `ge-0/0/0.01`
  produces the key `ge-0/0/0.01` while the interface's canonical unit produces
  `ge-0/0/0.1` — **they do not match**. The dataplane-side
  `buildInterfaceZoneMap` keys by raw string first-writer-wins as well.
- **class-of-service** `interfaces <if>.<unit>` — map key carries the raw
  suffix inline (`cfg.ClassOfService.Interfaces[name]`).
- **routing-instances** `interface <if>.<unit>` — `strings.Cut` + `strconv.Atoi`
  → `continue` on mismatch (route-leak member silently dropped).
- **NAT** interface refs, **snapshot/status** paths — same raw-suffix pattern.

Because each reference normalizes independently on each node's effective view,
even without a *duplicate*-spelling collision a peer-only `${node}` rewrite that
emits `.01` on the standby (vs `.1` on the active) can bind a zone/NAT/policy to
a **different** runtime unit on standby — the second, subtler half of #5878.

### 2.4 The peer-only injection vector

`ExpandGroupsWithVars` (`pkg/config/ast_groups.go:51`) resolves
`apply-groups "${node}"` to `groups node0` on node0 and `groups node1` on
node1. A `groups node1 { interfaces ge-0/0/0 unit 01 { … } }` deep-merges onto
the base `interfaces ge-0/0/0` **only when compiling for node1**. This — plus
node-inverted forms and interface-range/wildcard expansion — is the mechanism
by which the alias appears in exactly one node's view.

---

## 3. The canonical-identity gap, precisely

1. **No single normalizer.** Canonicalization is `strconv.Atoi` scattered across
   the interface compiler, the alias gate, the zone/NAT/routing reference
   binders, and the dataplane map builders. `ValidateLogicalUnit` validates but
   does not *emit* the canonical form, so no caller can share one identity.
2. **Collision detection is single-view.** The one gate that folds spellings to
   a canonical int (`validateInterfaceUnitAliasCollisionsAST`) runs post-`${node}`
   expansion for the local node only. There is **no both-node / compile-parity
   check** anywhere in the commit path (confirmed: no such symbol in
   `pkg/configstore` or `pkg/config` outside the tunnel/zone/table-id gates).
3. **Reference identity is raw-string, per node.** Zone/CoS/routing/NAT bind on
   the raw `.unit` suffix, which differs from the interface's canonical int and
   can differ between node views.

Aliasing forms admitted today (all via `strconv.Atoi`, base-10, bitsize 0):
leading zeros (`01`), redundant sign (`+1`), signed zero (`-0`/`+0`→0). The
instance-key path additionally guards range via `ValidateInteger` (`-1` is
rejected as out-of-range at commit, so negative non-zero is not a live alias
vector on the strict path — but `-0` still aliases `0`, and the *lenient*
load/peer-sync path uses `lenientNonNumericUnit` and does not range-check the
same way). Intra-token whitespace is not a live vector (the lexer splits on
whitespace) **except** on the reference-suffix `strings.Cut` path, which does
not `TrimSpace`.

---

## 4. Design options

### Option A (RECOMMENDED) — canonical normalizer + both-node-effective collision gate at commit

1. **One canonical normalizer.** Add
   `CanonicalLogicalUnit(raw string) (num int, canon string, err error)` beside
   `ValidateLogicalUnit` in `schema_validators.go`: the single function that
   maps any accepted spelling to `(int, strconv.Itoa(int))`. `ValidateLogicalUnit`
   delegates to it. Replace the ad-hoc `strconv.Atoi(unitInst.name)` sites in
   the alias gate (and, incrementally, the reference binders) with it.
2. **Promote the alias gate to a both-node union**, modeled *exactly* on
   `validateTunnelEndpointIDCollisionAST`:
   - **View 1** — pre-expansion presence union across the main `interfaces`
     hierarchy **and every `groups` block**, grouping raw spellings under each
     interface by canonical int (catches a collision *inside* an un-expandable
     group).
   - **Views 2 & 3** — the concrete per-interface unit spellings after expanding
     the candidate for node0 and for node1 (`ExpandGroupsWithVars`), non-fatal
     per-node expansion errors contribute the empty set (mirrors
     `emitNodeExpandedTunnelNames`).
   - Reject (strict) when the **union** shows ≥2 spellings folding to one unit
     under one interface, reporting **both source paths + the canonical
     identity**. Because all three views are pure functions of the same
     candidate config, the verdict is **identical on both nodes** (no
     originator-accepts/peer-rejects split), and the union is **monotone** over
     today's single-view gate (only adds rejects) — the same safety argument
     tunnelid.go makes.
   - Move the call into the **pre-expansion** block of
     `compileConfigForNodeWithOpts` / `compileConfigWithOpts` (beside the
     tunnel/zone/table-id gates) so it runs once, identically, regardless of
     which node commits. Keep the lenient (load/peer-sync) path as **warn**, so
     an already-persisted or peer-synced config an older binary accepted still
     boots (#1960 doctrine).
3. **Phase 2 (deferred):** thread `CanonicalLogicalUnit` through the reference
   binders — `zoneIfaceLogicalKeys`, `buildInterfaceZoneMap`,
   `cfg.ClassOfService.Interfaces` keys, routing-instance interface refs, NAT
   interface refs, and the snapshot/status emitters — so `.01` and `.1` resolve
   to one runtime unit everywhere.

- **Security:** closes the fail-open at commit (hard reject) *and* eliminates
  the standby-only divergence (both-node verdict).
- **Blast radius (phase 1):** `schema_validators.go` (+1 function),
  `compiler_interface_unit_alias.go` (union rewrite), two call-site moves in
  `compiler.go`. No parser / set-path / hot-path change. No dataplane change.
- **Migration / mixed-version:** additive + monotone; lenient warn on
  load/peer-sync means no boot regression for a config an older binary already
  persisted. A newly-authored aliased config is rejected at commit as intended.

### Option B — canonicalize-on-ingest (collapse aliases before storage)

Rewrite every `unit <alias>` and every `.unit` reference suffix to canonical
decimal at parse/`set`/persist time so the stored candidate tree carries only
canonical spellings; a normal single-node compile then never sees two spellings.

- **Pro:** one identity everywhere; references auto-match; no post-hoc gate.
- **Con (disqualifying for the core case):** the #5878 alias is introduced by
  **group expansion**, not by a raw stored spelling. A base `unit 1` plus a
  peer-only `groups node1 { unit 01 }` still only collides **after**
  `ExpandGroupsWithVars` — so ingest-canonicalization of the stored tree does
  **not** catch it unless you *also* canonicalize post-expansion, which is
  Option A's gate. Ingest rewriting alone is insufficient.
- **Con:** mutates operator input — `show | compare`, rollback diffs, and
  archived config would show a spelling the operator never typed (violates the
  Junos "config echoes what you set" contract); cannot canonicalize an
  unexpanded `${var}` inside a group body; touches the hot parser/`set` path
  (higher regression risk).

### Option C — Option A phased (this is the recommendation's shape)

Ship Option A's normalizer + both-node gate first (minimal, self-contained),
defer the reference-identity threading (2.3) to phase 2. Documented here as the
recommended sequencing, not a separate design.

---

## 5. Recommendation

**Option A, phased.**

**Minimal first increment (phase 1):**
1. `CanonicalLogicalUnit` normalizer in `pkg/config/schema_validators.go`;
   `ValidateLogicalUnit` delegates to it.
2. Rewrite `validateInterfaceUnitAliasCollisionsAST` into a both-node union gate
   (View 1 pre-expansion group-union + Views 2/3 per-node expansions), reporting
   both source paths + canonical unit, and relocate its invocation into the
   pre-expansion gate block of `compileConfigForNodeWithOpts` and
   `compileConfigWithOpts` so the accept/reject verdict is identical on node0
   and node1. Lenient path stays warn-only.

**Phase 2 (deferred, larger):** thread `CanonicalLogicalUnit` through
zone/CoS/routing/NAT reference binding + snapshot/status so the same canonical
identity is used everywhere (closes 2.3). Sized separately because it touches
`pkg/dataplane/userspace` map builders and the status/snapshot emitters.

This mirrors the accepted doctrine already proven for tunnel/zone/table IDs, so
the review surface is a known quantity and the HA-symmetry argument (pure
function of config, monotone over the existing gate) carries over verbatim.

### Invariant coverage (issue §"Required invariants")

| Invariant | Phase | Mechanism |
|-----------|-------|-----------|
| Canonicalize every identifier before map insertion / ref binding | 1 (units) / 2 (refs) | `CanonicalLogicalUnit` at the alias gate; threaded to binders in phase 2 |
| Validate collisions over each node-effective compiled view (incl. peer-only groups + inherited/generated) | 1 | Views 1/2/3 union across groups + both node expansions |
| Report both source paths + canonical identity | 1 | union gate error message |
| Reject before active promotion/sync; not last-write/map-iteration | 1 | hard reject at commit-check on the pre-expansion gate; identical on both nodes |
| Same canonical identity in zone/NAT/routing/snapshot/status | 2 | reference-binder threading |

---

## 6. Two-node compile-parity test design (issue §Validation)

New table-driven test `interface_unit_parity_5878_test.go` in `pkg/config`.

**6.1 Core RED (pre-fix) case — peer-only alias.**
Author a shared cluster tree via `ParseSetCommand()` + `tree.SetPath()`:

```
set interfaces ge-0/0/0 unit 1 family inet address 10.0.0.1/24
set interfaces ge-0/0/0 unit 1 family inet filter input good
set groups node1 interfaces ge-0/0/0 unit 01 family inet filter input evil
set apply-groups "${node}"
```

- Assert **pre-fix**: `CompileConfigForNode(tree, 0)` succeeds (node0 never sees
  `unit 01`); `CompileConfigForNode(tree, 1)` folds `01`/`1` onto one unit with
  order-dependent filter selection (`good` vs `evil`) — i.e. node views diverge.
- Assert **post-fix**: the commit gate (`compileTreeStrict(tree, 0)` **and**
  `compileTreeStrict(tree, 1)`) both **reject** with the *same* error naming
  interface `ge-0/0/0`, spellings `` `unit 01` `` + `` `unit 1` ``, and canonical
  unit `1` — verdict parity across nodes.

**6.2 Alias-form matrix.** For each of `{.01 vs .1, +1 vs 1, 00 vs 0, -0 vs 0}`,
inject the aliasing spelling via a peer-only `groups node1` block and assert the
both-node gate rejects identically on node0 and node1.

**6.3 Injection-vector matrix.** peer-only group; group inheritance
(`apply-groups g` where `g` sets the alias); node inversion (aliasing spelling
in `groups node0` while base uses the other spelling); interface-range /
wildcard expansion; rollback/load (lenient path → warn, not reject, and boots).

**6.4 Compile-parity harness (generalized).** A helper that, for a given tree,
compiles **both** node views and asserts:
- (a) the accept/reject **verdict is identical** across node0 and node1;
- (b) when accepted, the set of runtime unit identities per interface, and the
  reference bindings from zones/NAT/routing, are **byte-identical after
  canonicalization** across the two node views.
Any divergence in (a) or (b) fails the test. Run the whole 6.2/6.3 matrix
through it.

**6.5 Reference-parity assertion (phase 2 gate).** Assert a zone member
`ge-0/0/0.01` binds to the **same** runtime unit as the interface's canonical
`ge-0/0/0.1` (drives the phase-2 reference threading; expected-RED until phase 2
lands, so land it disabled/skipped or alongside phase 2).

**6.6 Regression guards.** A single canonical `unit 0` (the common case) and a
legitimate VLAN split (`ge-0/0/0.0` in trust, `ge-0/0/0.1` in untrust) must
**not** trip the gate on either node.

---

## 7. Files to touch (phase 1) — for the eventual implementer

- `pkg/config/schema_validators.go` — add `CanonicalLogicalUnit`.
- `pkg/config/compiler_interface_unit_alias.go` — union rewrite (Views 1/2/3),
  both-node symmetry, both-source-path + canonical-identity message.
- `pkg/config/compiler.go` — relocate the gate call into the pre-expansion gate
  block of `compileConfigForNodeWithOpts` **and** `compileConfigWithOpts`;
  remove it from `runPreWalkGates` (or leave a node-local fast path — decide at
  implementation, but the *authoritative* verdict must be the union gate).
- `pkg/config/compiler_prewalk.go` — drop/relocate the `#5631` call site.
- `pkg/config/interface_unit_parity_5878_test.go` — new (§6).
- **Docs:** update `docs/config-schema.md` (multi-value/unit-identity section)
  and any module doc that describes the #5631 gate to state the both-node
  union semantics. `pkg/config` has no README; the gate's own file-level
  comment is the module doc and must be updated in phase 1.

No production code is modified on this research branch.
