# #1979 — Flow/flow-export NUM_WIDTH: commit-time ValidateInteger (Layer B of #1977)

**Status:** PLAN v3 — **PLAN-READY (3-way converged).** SMR r2 = PLAN-READY,
AGY r2 = PLAN-READY, Codex r2 = PLAN-NEEDS-MINOR (2 doc/test-contract nits, no
architectural blocker — both folded into v3: §8 item 1 now routes Tier-3
`tcp-mss` accept/reject through `CompileConfig`/`compileTreeStrict` not
`SchemaValidate`; §8 item 5 reworded to the directional "Layer B never rejects
what Layer A accepts" invariant with the sampling-`0` normalization exception).
Awaiting manual approval — type `/engineer 1979` to implement.
**Base:** origin/master (`a75c970d8`, post-#1977/#1978 Layer A merge). NOTE:
master has since advanced (e.g. `86435d4a1`) in unrelated subsystems (ipsec,
snmp, flowexport — NOT pkg/config schema), shifting some LINE numbers below
(`tcp-session`/`tcp-mss` are now ~schema_security.go:218-221; the VRRP pre-walk
is ~compiler.go:260). All SYMBOLIC references (node names, function names,
`parseMSSValue`/`validateVRRPTrackInterfaceAST`/`SetFlowTimeout` stub) are
canonical and stable; /engineer should resolve line numbers freshly against the
then-current master. No schema-package conflict exists with the moved commits.
**Issue:** #1979 (follow-up to #1977 / PR #1978)
**Branch:** research/1979-layerb-validate
**Mode:** /research — STOP at PLAN-READY/PLAN-KILL; no production code, no PR.

---

## 1. Issue framing

#1977 (Layer A, shipped PR #1978, master `a963273e8`) added build-boundary
coercion in `buildFlowSnapshot`/`buildFlowExportSnapshot`
(`pkg/dataplane/userspace/flow.go`) that **guarantees** every flow/flow-export
wire field lands in its Rust `u16`/`u32`/`u64` range on every input path
(CLI/gRPC/file). That closed the dataplane-safety hole: an out-of-range value
(operator typo `tcp-mss-gre-in 70000`, negative timeout, oversize sampling
rate) can no longer abort the whole `apply_snapshot` decode and silently
disable forwarding (the #1961 failure class).

**Layer B is operator UX, NOT safety.** Today those out-of-range values are
*accepted at `commit check`* and only silently coerced + `slog.Warn`-logged at
the wire boundary. Layer B adds commit-time `ValidateInteger` typed-leaf
validators so the bad value is rejected at `commit check` with a clear error
("integer out of range [0..65535]") before it is ever committed.

The #1977 plan-review (Codex r1/r2, AGY) explicitly **deferred** Layer B because
the target schema nodes are `children: nil` (opaque/free-form) and require
non-trivial expansion before `SchemaValidate` can descend and attach a
validator. This research confirms that assessment, quantifies the difficulty
per leaf (it is NOT uniform — three difficulty tiers), and surfaces a real
correctness trap in the hardest tier.

---

## 2. Honest scope / value framing

- **Value:** clear `commit check` error instead of silent coercion. Pure UX
  improvement. Layer A already makes every one of these values *safe*.
- **Risk:** the change touches the SSOT config grammar (`setSchema`) that drives
  four behaviours off one tree (completion, flat-set grouping, value-slot `?`
  help, validation — schema.go:1-30). The central documented invariant
  (schema.go:56-62, golden test `TestSetPathGrouping_Golden`) is: **adding
  typed-leaf metadata must NOT add/alter a `children` map on a node that is a
  single-value leaf, because SetPath's replace-vs-container decision keys on
  `children == nil` (ast_edit.go:196).** Layer B inherently expands opaque
  containers, so it must be done carefully tier by tier and proven
  round-trip-stable.
- **PLAN-KILL is acceptable.** If reviewers conclude the UX gain does not
  justify the grammar churn (especially Tier 3's custom MSS handling), the
  honest outcome is: ship Tier 1 only (trivial, zero-risk), or ship nothing —
  Layer A already removed the dataplane danger. This plan recommends a scoped
  subset (Tiers 1+2), with Tier 3 as an explicit decision point.

---

## 3. What's already shipped (Layer A — the caps Layer B must agree with)

`pkg/dataplane/userspace/flow.go` (master, verified) coerces, per field:

| Field | Rust | Layer-A coercion | ⇒ Layer-B validator bound |
|---|---|---|---|
| TCPMSSIPsecVPN / GreIn / GreOut (/ AllTCP) | u16 | `<0 \|\| >65535 → 0` | **`[0, 65535]`** |
| TCPSessionTimeout (`established-timeout`) | u64 | `<0→0`, `>MaxDurationSeconds→MaxDurationSeconds` | **`[0, MaxDurationSeconds]`** |
| UDPSessionTimeout (`udp-session timeout`) | u64 | same | **`[0, MaxDurationSeconds]`** |
| ICMPSessionTimeout (`icmp-session timeout`) | u64 | same | **`[0, MaxDurationSeconds]`** |
| CollectorPort (`flow-server … port`) | u16 | `<1 \|\| >65535 → skip server` | **`[1, 65535]`** |
| SamplingRate (`input rate`) | u32 | `<=0→1`, `>u32max→u32max` | see Q-RATE below |
| ActiveTimeout (`flow-active-timeout`) | u32 | `<0→0`, `>u32max→u32max` | **`[0, 4294967295]`** |
| InactiveTimeout (`flow-inactive-timeout`) | u32 | same | **`[0, 4294967295]`** |

`MaxDurationSeconds = math.MaxInt64/1e9 ≈ 9.22e9` (schema_validators.go:132).
The session-timeout cap is **not** u64-max: Rust `SessionTimeouts::from_seconds`
multiplies `secs*1e9` unchecked, so `MaxDurationSeconds` is the overflow-safe
ceiling. The existing `hold-down` leaf (schema_system.go:420) already uses
`ValidateInteger(0, MaxDurationSeconds)` for exactly this reason — Layer B
reuses that established bound verbatim.

**Q-RATE (sampling input rate lower bound) — USER DECISION, Codex r1 #5:** the
config type documents `InputRate ... 0 = sample all` (types_system.go:569) and
Layer A ACCEPTS 0 (normalizes `rate <= 0 → 1`, flow.go). So:
- (a) `[1, 4294967295]` — reject 0 at commit. Clearer UX, BUT this is genuine
  **behavior drift** (stricter than Layer A, which accepts a documented `0`).
- (b) `[0, 4294967295]` — accept 0, let Layer A normalize. **Exact Layer-A
  mirror**, no drift; only catches the actual decode-aborting case (>u32max).
Codex r1 (precise) flagged (a) as drift needing explicit sign-off; AGY r1 read
(a) as a Layer-A match (it is not — Layer A accepts 0). **This plan now defers
the choice to the user.** Default recommendation: **(b) `[0, 4294967295]`** to
keep Layer A and Layer B in EXACT agreement (the §6 invariant: Layer B must not
reject what Layer A accepts), unless the user prefers the stricter (a) UX and
accepts documenting the `0 = sample all` drift.

---

## 4. The enumerated bounded leaves (verified by Explore agent + compiler read)

Eight distinct config leaves feed the 11 wire fields. `TCPMSSAllTCP` is **not a
distinct config leaf** — `tcp-mss all-tcp <n>` fans out into the three MSS
fields in the compiler (compiler_security.go:640-645); the wire `TCPMSSAllTCP`
field is never builder-populated. `parseMSSValue` has exactly four callers — all
the `tcp-mss` switch arms in compiler_security.go — so there is NO interface- or
per-unit `tcp-mss` feeding any of these flow fields; the surface below is the
complete reachable set (Q1 resolved). The config surface to validate is:

| # | Config leaf (set path) | Wire field(s) | Schema node | Currently | Tier |
|---|---|---|---|---|---|
| 1 | `services flow-monitoring version9 template <t> flow-active-timeout <n>` | ActiveTimeout (u32) | schema_system.go:434 | `args:1, children:nil` (value slot exists) | **1** |
| 2 | `… version9 template <t> flow-inactive-timeout <n>` | InactiveTimeout (u32) | schema_system.go:435 | `args:1, children:nil` | **1** |
| 3 | `security flow tcp-session established-timeout <n>` (+ `initial-timeout`/`closing-timeout`/`time-wait-timeout` — see §4a) | TCPSessionTimeout (u64) | schema_security.go:177 `tcp-session` | **opaque `children:nil`** | **2** |
| 4 | `security flow udp-session timeout <n>` | UDPSessionTimeout (u64) | schema_security.go:178 `udp-session` | **opaque `children:nil`** | **2** |
| 5 | `security flow icmp-session timeout <n>` | ICMPSessionTimeout (u64) | schema_security.go:179 `icmp-session` | **opaque `children:nil`** | **2** |
| 6 | `forwarding-options sampling instance <i> input rate <n>` | SamplingRate (u32) | schema_routing.go:252 `input` | **opaque `children:nil`** | **2** |
| 7 | `… sampling … family {inet\|inet6} output flow-server <addr> port <n>` | CollectorPort (u16) | schema_routing.go:256/262 `flow-server` (args:1) | **opaque `children:nil`** | **2** |
| 8 | `security flow tcp-mss {ipsec-vpn\|gre-in\|gre-out\|all-tcp} <n>` **OR** `… { mss <n>; }` | TCPMSS{IPsecVPN,GreIn,GreOut} (u16) | schema_security.go:180 `tcp-mss` | **opaque `children:nil`** | **3 (dual value-location)** |

### §4a — Sibling timeouts that ALSO need validation for consistency

`tcp-session` compiles four timeout sub-leaves (compiler_security.go:589-597):
`established-timeout`, `initial-timeout`, `closing-timeout`, `time-wait-timeout`.
Only `established-timeout` reaches the wire `FlowSnapshot.TCPSessionTimeout`. The
other three are stored in `TCPSessionConfig`. For UX consistency — and because
expanding `tcp-session` to a container *requires* declaring its known children
anyway (otherwise completion regresses, see §6) — **all four `tcp-session`
integer sub-leaves should be typed** with `[0, MaxDurationSeconds]` (the same
Duration-overflow ceiling). The three non-wire ones are config-correctness, not
a wire-decode defense, but they share the bound and cost nothing extra.

**AGY r1 #2 — BPF `uint32` truncation of the siblings: VERIFIED DEAD PATH, keep
`[0, MaxDurationSeconds]`.** AGY noted `compileFlowTimeouts` casts the four TCP
timeouts (and UDP/ICMP) to `uint32` at pkg/dataplane/compiler.go:1006-1012 →
`dp.SetFlowTimeout`, arguing a `MaxDurationSeconds`-bounded value would silently
truncate. I traced it: the LIVE userspace implementation of `SetFlowTimeout` is a
NO-OP STUB — `func (d userspaceShimCompileDataplane) SetFlowTimeout(uint32,
uint32) error { return nil }` (pkg/dataplane/loader.go:391). That u32 map-write
was the legacy eBPF path retired in #1476; on the only live dataplane it does
nothing, and the three siblings don't reach FlowSnapshot either, so there is NO
live u32 consumer to truncate. The three WIRE-reaching session timeouts
(`established`/`udp`/`icmp`) ARE Rust **u64** (snapshot.rs:151-155), so
`[0, MaxDurationSeconds]` is REQUIRED there to match Layer A — AGY's `[0,u32max]`
would be WRONG for those (rejecting valid u64 values Layer A accepts). DECISION:
`[0, MaxDurationSeconds]` for ALL six; note the dead-path cast (Q8) so a
hypothetical eBPF revival (none planned) would re-tighten the non-wire siblings.

### §4b — version-ipfix (parallel but NOT wired)

`flow-active-timeout`/`flow-inactive-timeout` ALSO exist under
`version-ipfix template` (schema_system.go:443/444). `buildFlowExportSnapshot`
reads **only `fm.Version9`**, so the IPFIX timeouts do NOT reach the wire.
However they ARE already `args:1` leaves and typing them is the same one-line
change as the version9 ones, giving consistent UX. **Recommended: type the
version-ipfix pair too** (Tier 1, identical treatment). It is not a wire-decode
defense (those values never hit the snapshot) but is free UX parity. Reviewer
Q5.

---

## 5. Concrete design — three difficulty tiers

### Tier 1 — pure typed-leaf metadata add (TRIVIAL, zero grouping risk)

Leaves #1, #2 (and the version-ipfix pair, §4b). These are already
`args:1, children:nil` leaves with a `<seconds>` value slot. Add four fields,
leave `args`/`children` untouched, following the exact `hold-down` pattern
(schema_system.go:420-428):

```go
"flow-active-timeout": {
    args: 1, desc: "...", placeholder: "<seconds>",
    valueType:     ValueInteger,
    valueDesc:     "Active flow export timeout in seconds (0..4294967295)",
    valueExamples: []string{"60"},
    validator:     ValidateInteger(0, math.MaxUint32),
    children:      nil,
},
```

**Experimentally verified** (in-place schema mutation test, this research):
`flow-active-timeout 60` passes; `-1` and `5000000000` (>u32) are rejected with
a clear range error; round-trip byte-stable. No `children` map added.

### Tier 2 — opaque container → container with typed-leaf children (LOW RISK)

Leaves #3-#7. The opaque node becomes a real container whose **value-bearing
sub-leaves** are typed leaves and whose **flag/keyword children** are declared
presence-only nodes. Example for `udp-session`:

```go
"udp-session": {desc: "...", children: map[string]*schemaNode{
    "timeout": {args: 1, valueType: ValueInteger,
        valueDesc: "UDP session timeout in seconds",
        validator: ValidateInteger(0, MaxDurationSeconds), children: nil},
}},
```

`tcp-session` additionally declares the four FULLY-SPELLED timeout keys
`established-timeout`, `initial-timeout`, `closing-timeout`, `time-wait-timeout`
(all typed `[0, MaxDurationSeconds]` — AGY r1 #1: spell them out, the compiler
matches the full `-timeout` names, compiler_security.go:589-597) plus the three
presence flags `no-syn-check`, `no-syn-check-in-tunnel`, `rst-invalidate-session`
(declared `{children: nil}` so completion still offers them and the walker
accepts them).
`input` declares `rate` (typed u32). `flow-server` (keeps `args:1` for the
address) declares `port` (typed `[1,65535]`) plus the existing free-form
children `version9-template`, `version9 { template }`, `source-address`.

**Why this is safe for both AST shapes:** the typed VALUE always lands in the
sub-leaf's `Keys[1]`, whether the operator wrote the flat form (`udp-session
timeout 60` → SetPath nests `timeout 60` under `udp-session`) or the
hierarchical form (`udp-session { timeout 60; }`). The container itself is NOT a
typed leaf, so the walker descends into it normally in both shapes.
**Experimentally verified** (this research): flat AND hierarchical
`flow-server … port` / `input rate` / session-timeout all validate correctly;
out-of-range rejected with clear errors; round-trip byte-stable; two bare
`flow-server` entries still append (not replace) — which is correct, multiple
collectors are valid.

**SetPath grouping note (flow-server) — scoped per Codex r1 #4:** `flow-server`
already has `args:1`. Adding a `children` map flips its `i >= len(path)` TERMINAL
behaviour (ast_edit.go:194-196) — but ONLY for a *bare* terminal
`set … flow-server <addr>` with no trailing tokens — from "single-value REPLACE"
to "named-container APPEND". This flip is NOT load-bearing for normal use:
- Real collectors carry sub-tokens (`flow-server <addr> port <n>`), so they
  ALREADY take the container-creation path (ast_edit.go:270-280) and the
  compiler already appends each (`FlowServers = append(...)`,
  compiler_services.go:900) — multi-collector support does not depend on this
  flip.
- A bare no-port `flow-server <addr>` compiles `Port == 0` and the snapshot
  builder skips it (flow.go port==0 skip) — so it is a harmless no-op either way.
The flip is therefore a benign side-effect to PIN (extended golden), not a
feature to sell. `input`/`tcp-session`/`udp-session`/`icmp-session` have
`args:0`, so the line-196 REPLACE branch never applied (it requires `args > 0`);
adding children only changes them from "flag leaf" to "container", correct since
they were always traversed deeper.

### Tier 3 — `tcp-mss` dual value-location (THE HARD CASE — design decision)

Leaf #8 is **uniquely hard**: the MSS value can live in EITHER position, and
**both are valid, tested configs**:

- **Flat:** `set security flow tcp-mss gre-in 1400` — value in `gre-in`'s own
  `Keys[1]`. Used by parser_security_test.go:1097/1140, dual_ast_differential_
  test.go:406, docs/ha-cluster.conf (`all-tcp 1396`), test/incus/xpf-test.conf,
  docs/test_env.md (`ipsec-vpn 1350`).
- **Hierarchical:** `gre-in { mss 1360; }` — value in an `mss` SUB-child. Used
  by `TestTCPMSSHierarchical` (parser_ast_test.go:1793) — an explicit,
  compiled, asserted test. `parseMSSValue` (compiler_interfaces.go:729-744)
  reads both.

**The trap (experimentally proven):** neither naive schema model covers both:
- *Model gre-in as a typed leaf* → flat `gre-in 70000` correctly rejected, but
  hierarchical `gre-in { mss 1360; }` FALSE-REJECTED with "missing value" (the
  walker demands a value on `gre-in` itself; the value is in the `mss` child).
  **This is a correctness regression — it rejects a valid config that compiles
  today.**
- *Model gre-in as a container with a typed `mss` child* → hierarchical
  `gre-in { mss 70000; }` correctly rejected, but flat `gre-in 70000` SILENTLY
  IGNORED (the container contract — walkSchemaNode lines 270-284 — ignores
  tokens packed into a container node's own Keys beyond its identity). **This
  misses the issue's headline operator-typo path `tcp-mss-gre-in 70000`.**

So Tier 3 requires a mechanism that validates whichever position carries the
value. **Three path options (§5-OPT).**

---

## 5-OPT. Path options for Tier 3 (`tcp-mss`)

### Option T3-A — compiler-side AST pre-walk validator (RECOMMENDED)

**There is an established project precedent for exactly this "the schema walker
cannot express it" case: `validateVRRPTrackInterfaceAST`** (compiler_interfaces.go:746),
wired into `CompileConfig` at compiler.go:225 — it walks the (group-expanded)
AST BEFORE section compilation and returns an `error` that aborts the commit
(which surfaces as the `commit check` failure). Layer B's Tier 3 follows that
pattern verbatim:

```go
// compiler.go, alongside the VRRP pre-walk (~line 225):
if err := validateTCPMSSRanges(tree.Children); err != nil {
    return nil, err
}
```

`validateTCPMSSRanges` finds every `security flow tcp-mss` node (recursing /
filtering ALL `security`→`flow`→`tcp-mss` occurrences in the candidate AST — NOT
`FindChild`-first-match, which would miss a second block in a pre-merge
candidate; AGY r1 note) and, for each
`ipsec-vpn`/`gre-in`/`gre-out`/`all-tcp` child, range-checks `[0, 65535]`
against **the value the compiler would actually select** — it MUST mirror
`parseMSSValue`'s exact PRECEDENCE (compiler_interfaces.go:729-744): the `mss`
sub-child's `Keys[1]` **first** (if it parses), and only **fall back** to the
node's own flat `Keys[1]` otherwise.

**Codex r1 #3 — the precedence trap (experimentally confirmed):**
`parseMSSValue` prefers the `mss` child and returns immediately if it parses,
ignoring any flat value. So `gre-in 70000 { mss 1360; }` compiles
`TCPMSSGreIn = 1360` (the child wins; the flat 70000 is DISCARDED) — verified by
compiling that exact config. A naive "validate BOTH positions" helper would
**wrongly reject** that config on the discarded 70000. The fix: validate ONLY
the compiler-selected value — ideally by SHARING `parseMSSValue`'s selection
(extract a `selectMSSToken(node) (string, bool)` from `parseMSSValue` so the
compiler and validator can never diverge), then `ValidateInteger(0, 65535)` on
the chosen token. Unlike `parseMSSValue` (which silently returns 0 on a bad
value), the validator returns a descriptive error. A mixed-shape test
(`gre-in 70000 { mss 1360 }` PASSES — selected value 1360;
`gre-in 1360 { mss 70000 }` REJECTS — selected value 70000) pins the precedence.

- **Pros:** validates BOTH valid shapes and rejects neither; mirrors
  `parseMSSValue` precisely (same value-location logic, so it can never diverge
  from what the compiler reads); **zero `setSchema` structural change** for
  `tcp-mss` ⇒ zero SSOT-grouping/completion blast radius for Tier 3; uses an
  EXISTING, reviewed project pattern (no new walker concept). Runs on the
  group-expanded tree like the VRRP walk, so apply-groups-inherited MSS values
  are covered.
- **Cons:** Tier 3 validation lives in the compiler, not the schema walker, so
  it does NOT also give value-slot `?` completion for the MSS leaves (the
  schema node stays opaque). Completion typing for `tcp-mss` is a separable,
  optional follow-up and is explicitly out of scope here (§9).
- **Why not the schema-walker route for Tier 3:** the walker's typed-leaf
  contract (validateTypedLeaf, schema_walk.go:464) requires the value in the
  leaf's own `Keys[1]`; the container contract (walkSchemaNode:270-284)
  deliberately IGNORES tokens packed into a container's Keys beyond its
  identity. Neither expresses "value may live in self OR a named child." Adding
  a new schemaNode field/walker branch to express it (the earlier "T3-A(i)"
  idea) would touch the schemaNode type + golden + docs/config-schema.md for a
  single leaf family — strictly worse than reusing the VRRP-style AST pre-walk.
  REJECTED in favour of the compiler pre-walk.

### Option T3-B — flat-only validation (cover the headline typo, skip hierarchical)

Model the MSS leaves as typed leaves BUT teach the walker to treat a leaf that
has children-supplying-the-value as value-optional (skip "missing value" when an
`mss` child is present). This validates flat `gre-in 70000` and accepts the
hierarchical form without validating its `mss` value.

- **Pros:** catches the issue's headline path (`gre-in 70000` flat typo).
- **Cons:** the hierarchical `gre-in { mss 70000; }` typo is NOT caught
  (inconsistent UX, the kind of half-fix that confuses operators); needs a
  walker change anyway. Inferior to T3-A(ii).

### Option T3-C — defer Tier 3 entirely (ship Tiers 1+2 only)

Type leaves #1-#7 (all the clean tiers). Leave `tcp-mss` opaque/unvalidated at
commit; Layer A continues to coerce its values safely. File a follow-up if the
MSS commit-UX is later wanted.

- **Pros:** zero risk, zero custom code, covers 7 of 8 leaves and 8 of 11 wire
  fields with purely declarative schema; the MSS fields remain *safe* (Layer A).
- **Cons:** the issue's single most-cited example (`tcp-mss-gre-in 70000`) is
  the one path left un-validated at commit — arguably the most operator-reachable
  typo. Half the headline value.

**This plan's recommendation:** **Option T3-A** (compiler-side AST pre-walk
`validateTCPMSSRanges`, modeled on `validateVRRPTrackInterfaceAST`, ~25 lines,
fully testable, zero SSOT-grouping/completion risk). Fallback to **T3-C** only
if reviewers judge even that focused helper not worth it — but note T3-C leaves
the issue's HEADLINE example (`tcp-mss gre-in 70000`, the flat shape) unvalidated
at commit, so it is an explicit partial, not a full close.

### Architecture note — two validation families (which leaf goes where)

Layer B uses BOTH of xpf's existing commit-check validation mechanisms,
choosing per-leaf by whether the value sits in a normal single slot:

- **Schema-walker declarative typed leaves (Tiers 1+2):** the value always lands
  in a sub-leaf's `Keys[1]` (both AST shapes), so the `#1319` typed-leaf path
  expresses it cleanly AND gives free value-slot `?`/tab completion. This is the
  preferred path and covers 7 of 8 leaves.
- **Compiler AST pre-walk (Tier 3 only):** `tcp-mss`'s dual value-location can
  NOT be expressed in the walker, so it uses the `validateVRRPTrackInterfaceAST`
  precedent — an AST validator in `CompileConfig` returning a commit error.
  Covers the 1 remaining leaf family.

Both run before the snapshot is built, so both reject the bad value at `commit
check` before Layer A's coercion would ever see it.

### Strict vs lenient — the MANDATORY boot/HA-safety split (verified)

xpf already separates the operator-commit path from the tolerant ingress path,
and Layer B MUST respect it (this is non-negotiable — getting it wrong
blackout-boots an upgraded node):

- **Strict** (`compileTreeStrict`, store.go:446 — every operator commit /
  `commit check` / `xpfd check-config`): SchemaValidate violations
  **hard-reject**. This is where Layer B's clear error fires.
- **Lenient** (`compileTreeLenient`, store.go:475 — `Store.Load` on boot and
  `Store.SyncApply` HA peer-sync): SchemaValidate violations **downgrade to a
  `slog.Warn` and continue** (store.go:488-490). Rationale (store.go:463-470): a
  persisted/peer config authored by an OLDER binary (before this leaf's range
  was typed) may carry a value the new gate rejects; hard-failing would
  blackout-boot the node or alarm-loop HA config sync. The operator's next
  strict commit rejects it loudly. Same doctrine as #1798/#1814/#1319.

**Consequence per mechanism:**
- **Tiers 1+2 (schema-walker typed leaves):** get the strict/lenient split
  **for free** — `schemaValidateExpandedTree` is already downgraded on the
  lenient path (store.go:488). No extra work; a legacy `flow-active-timeout -1`
  warns-and-loads on boot/sync, rejects on the next commit. ✓
- **Tier 3 (`validateTCPMSSRanges` compiler pre-walk):** MUST take a `lenient`
  flag exactly like `validateVRRPTrackInterfaceAST(…, lenient)` and, on the
  lenient path, **warn (and let Layer A coerce) instead of returning an error**.
  This is precisely why the VRRP precedent is the right model — it already
  carries the strict/lenient mechanism (`opts.lenientVRRPTrackDuplicates`,
  compiler.go:225). A naive hard-reject `validateTCPMSSRanges` would blackout an
  upgraded node loading a legacy `tcp-mss gre-in 70000`. **This is a first-class
  acceptance requirement, pinned by a lenient-load test.**

---

## 6. Hidden invariants / things that must not regress

1. **SSOT grouping (the headline invariant):** schema.go:56-62 +
   `TestSetPathGrouping_Golden` (schema_validate_test.go:604). Tiers 1 and the
   `args:0` Tier-2 nodes add NO `children` to a single-value leaf, so the
   line-196 REPLACE path is untouched. `flow-server` (args:1) does gain
   children, deliberately flipping it to container/APPEND — correct for
   multi-collector configs; must be pinned by an extended golden. Under T3-A(ii)
   `tcp-mss` stays opaque ⇒ no grouping change at all for Tier 3.
2. **Completion must not regress (#1319 two-SSOT):** expanding an opaque node to
   a container means `?`/tab completion now offers ONLY the declared children.
   Every child the compiler reads under THE EXPANDED NODE must be declared, or
   completion silently drops a previously-completable keyword. **Scope note
   (Codex r1 #7):** this claim covers ONLY the nodes Layer B expands — Layer B
   does NOT touch the `flow` node itself, so a pre-existing `flow`-level
   completion gap (`syn-flood-protection-mode` is read by
   compiler_security.go:702 but not declared as a `flow` child today) is
   PRE-EXISTING and OUT OF SCOPE; do not claim "all compiler-read children are
   declared" repo-wide. Per expanded node, the full child keys to declare are
   (spelled out fully — AGY r1 #1, no shorthand):
   - `tcp-session`: `established-timeout`, `initial-timeout`, `closing-timeout`,
     `time-wait-timeout` (typed), plus presence flags `no-syn-check`,
     `no-syn-check-in-tunnel`, `rst-invalidate-session`.
   - `udp-session` / `icmp-session`: `timeout`.
   - `input`: `rate`.
   - `flow-server`: `port`, `version9-template`, `version9` (→ `template`),
     `source-address`.
   (`tcp-mss` stays opaque under T3-A — the compiler-pre-walk needs no schema
   children; MSS completion parity is a separable optional follow-up, §9.)
3. **No valid config may start failing commit.** Both AST shapes (flat +
   hierarchical) of every leaf must still pass. This is THE acceptance gate —
   the Tier-3 trap is exactly a violation of it, which is why T3-A is required
   over the naive model. Round-trip + dual-shape tests pin it.
4. **Validator bounds must equal Layer-A caps** (§3 table) so commit-validation
   and build-coercion never disagree (a value Layer B accepts must be one Layer A
   leaves unchanged; a value Layer B rejects is one Layer A would have coerced).
5. **`SchemaValidate` cfg is always nil in production** (schema_walk.go:36-44) —
   all validators here are pure range checks (no cfg/cross-ref), so this is a
   non-issue.

---

## 7. Risk assessment

| Class | Tier 1 | Tier 2 | Tier 3 (T3-A ii) | Notes |
|---|---|---|---|---|
| Grouping regression | NONE | LOW (`flow-server` APPEND, pinned) | NONE (stays opaque) | golden test extended |
| Completion regression | NONE | LOW (declare all compiler-read children) | NONE | completion test added |
| Reject-valid-config | NONE | NONE (both shapes verified) | NONE (dual-read helper) | the acceptance gate |
| Bound/Layer-A drift | NONE | NONE | NONE | bounds taken verbatim from §3 |
| Wire / HA / runtime | NONE | NONE | NONE | schema-only; no compiler/coercion/Rust change |

No Rust change. No `buildFlowSnapshot`/`buildFlowExportSnapshot` change (Layer A
untouched — Layer B is purely additive commit-time validation). No wire-shape
change.

---

## 8. Test plan

1. **Tier 1/2/3 acceptance (the gate):** for every leaf, assert the **valid**
   value (both flat and hierarchical AST shapes where the leaf supports both)
   is ACCEPTED and the **out-of-range** value (negative, >u16/u32,
   >MaxDurationSeconds) is REJECTED with a range error. **Use the correct
   harness per tier (Codex r2 #1):** Tier 1/2 are typed `setSchema` leaves, so
   accept/reject is asserted through `SchemaValidate`. Tier 3 (`tcp-mss`) stays
   OPAQUE in `setSchema` by design — its validation runs in the compiler
   AST pre-walk (`validateTCPMSSRanges`), so its accept/reject MUST be asserted
   through `CompileConfig` / `compileTreeStrict`, NOT `SchemaValidate` (which
   never descends into the opaque `tcp-mss` node). Drive input via
   `ParseSetCommand`+`SetPath` (flat) and `NewParser().Parse()` (hierarchical) —
   never `NewParser` for set-syntax per the dual-AST testing rule (CLAUDE.md).
2. **Tier 3 dual-shape, both positions:** `gre-in 70000` (flat) REJECTED;
   `gre-in { mss 70000; }` (hierarchical) REJECTED; `gre-in 1400` and
   `gre-in { mss 1360; }` both PASS. `all-tcp 70000` rejected; `all-tcp 1396`
   (the ha-cluster.conf value) passes.
3. **Round-trip stability:** extend `TestSetPathGrouping_Golden` to include a
   representative flow/flow-export config; assert byte-stable FormatSet().
4. **Completion parity:** assert `?`/tab completion at each expanded container
   still offers every compiler-read child (no silent drop).
5. **Layer-A agreement:** a property test feeding the SAME boundary values
   (65535, 65536, MaxDurationSeconds, MaxDurationSeconds+1, u32max, u32max+1)
   to BOTH the Layer-B validators and the Layer-A coercion, asserting: **Layer B
   never rejects a value Layer A accepts** (the directional invariant — Codex
   r2 #2), and every value Layer B rejects is one Layer A coerces. NOTE the
   asymmetry under the Q3 default `[0,u32max]`: Layer B ACCEPTS sampling `0` but
   Layer A NORMALIZES `0 → 1` (flow.go:138), so the invariant is "does not
   reject what Layer A accepts", NOT "leaves accepted values unchanged" —
   sampling `0` is the explicit, documented exception (sample-all sentinel). If
   the user instead chooses the stricter Q3 `[1,u32max]`, Layer B rejects `0`
   and no exception is needed. **Scope (Codex r1 #6):** this test covers
   ONLY the wire-reaching fields (the 8 leaves / 11 fields). version-ipfix
   timeouts do NOT reach Layer A (builder reads `fm.Version9` only,
   flow.go:176), so they are EXCLUDED from the Layer-A-agreement test — their
   typing is UX parity only, validated by the plain accept/reject test (item 1),
   not the agreement property. (Pins the §3 contract.)
6. **Strict-vs-lenient (boot/HA safety — MANDATORY):** an out-of-range value
   (e.g. `tcp-mss gre-in 70000`, `flow-active-timeout -1`) (a) HARD-REJECTS on
   the strict path (`compileTreeStrict` / `commit check`) with a clear error,
   AND (b) WARN-LOADS (does NOT error) on the lenient path
   (`compileTreeLenient` — `Store.Load` / `Store.SyncApply`). For Tier 3 this
   requires `validateTCPMSSRanges` to honor the `lenient` flag like the VRRP
   validator; a test must prove a legacy out-of-range MSS config still loads.
7. **Regression:** existing `TestTCPMSSHierarchical`, parser_security_test.go
   MSS tests, dual_ast_differential_test.go, schema_validate_* suites all pass.
8. `go build ./...` + `go test ./pkg/config/... ./pkg/cli/...` green.
9. **No smoke needed** (commit-time-only, no dataplane/wire change) — but a
   `commit check` on docs/ha-cluster.conf + test/incus/xpf-test.conf (both carry
   real tcp-mss configs) must pass unchanged.

---

## 9. Out of scope

- Any change to Layer A (`flow.go`), the Rust types, or the wire shape.
- Tighter-than-wire *Junos-semantic* MSS ranges (real MSS min/MTU-derived max) —
  a config-correctness nicety, not needed; `[0,65535]` matches Layer A.
- Validating non-flow opaque schema nodes (this is the flow/flow-export slice
  only; a broader "type every opaque leaf" sweep is a separate effort).
- Completion expansion for `tcp-mss` under Option T3-A(ii) (optional follow-up;
  validation does not require it).

---

## 10. Recommendation

Ship **Tiers 1 + 2** (leaves #1-#7, declarative schema typed leaves; bounds =
Layer-A caps) plus **Tier 3 via Option T3-A** (compiler-side
`validateTCPMSSRanges` AST pre-walk modeled on `validateVRRPTrackInterfaceAST`,
zero SSOT-grouping change). This validates all 8 config leaves / 11 wire fields
at commit with clear errors, rejects no valid config, and keeps the grammar
blast radius minimal. Locked decisions (from Q3/Q4/Q5, see §11):

- Sampling `input rate`: **USER DECISION pending** — default **`[0, 4294967295]`**
  (exact Layer-A mirror; rejects only the decode-aborting >u32max). Switch to
  `[1, u32max]` only if the user wants the stricter reject-0 UX (documented
  drift from `0 = sample all`). See Q3.
- `tcp-session`: type **all four** timeouts — `established-timeout`,
  `initial-timeout`, `closing-timeout`, `time-wait-timeout` (FULL keys, AGY r2) —
  at `[0, MaxDurationSeconds]` (declaring them is required for completion anyway;
  only `established-timeout` is wire-reaching).
- version-ipfix `flow-active/inactive-timeout`: **type them too** (UX parity;
  not wire-reaching).

If reviewers reject the Tier-3 helper, fall back to **T3-C** (Tiers 1+2 only) —
still a clean win and MSS stays safe via Layer A, but it is an explicit partial
(the headline `tcp-mss gre-in 70000` flat typo stays unvalidated at commit).

---

## 11. Open questions for adversarial review

- **Q1 (completeness) — RESOLVED.** `all-tcp` is a fan-out into the three MSS
  fields (compiler_security.go:640-645), not a distinct wire field; `TCPMSSAllTCP`
  is never builder-populated. `parseMSSValue` has exactly four callers, ALL in
  compiler_security.go's `security flow tcp-mss` switch — there is NO
  interface-level/per-unit `tcp-mss` feeding any of these 11 flow fields. The
  8-leaf / 11-field set is the complete reachable surface. (Confirmed by SMR r1
  + independent grep of all `parseMSSValue` call sites.)
- **Q2 (Tier 3 mechanism) — DECIDED + hook specified (Codex r1 #2/#3 folded).**
  Compiler-side AST pre-walk `validateTCPMSSRanges` wired in `CompileConfig`
  alongside `validateVRRPTrackInterfaceAST` (compiler.go:225), taking the
  `lenient` flag — NOT a SchemaValidate addition (SchemaValidate is generic and
  `tcp-mss` stays opaque, so the declarative walker would never reach it; Codex
  #2). It validates the COMPILER-SELECTED MSS value via the same precedence as
  `parseMSSValue` (mss-child-first, flat-fallback — shared selector so it can
  never diverge; Codex #3), not "both positions." Chosen over a
  schemaNode-field/walker hook and over deferring. Remaining reviewer question:
  is `CompileConfig` the right home vs a configstore-level call beside
  SchemaValidate?
- **Q3 (sampling rate) — USER DECISION (Codex r1 #5 reopened my earlier
  "decided").** `InputRate 0 = sample all` is documented (types_system.go:569)
  and Layer A ACCEPTS 0 → rejecting it at commit is real drift, not a mirror.
  Default recommend **`[0, u32max]`** (exact Layer-A agreement); choose
  `[1, u32max]` only with explicit sign-off on the reject-0 UX drift.
- **Q4 (§4a tcp-session) — DECIDED: type all four timeouts.** Declaring the
  container's children is required for completion parity anyway; the three
  non-wire timeouts share `[0, MaxDurationSeconds]`. Reviewers: agree?
- **Q5 (§4b version-ipfix) — DECIDED: type the pair too.** Same one-line change,
  UX parity, future-proofs IPFIX wiring. Reviewers: agree, or version9-only?
- **Q6 (grouping) — scoped (Codex r1 #4).** The `flow-server` REPLACE→APPEND
  flip affects ONLY a bare terminal `set … flow-server <addr>` (no trailing
  tokens). Real collectors (with `port`) already append via the container path;
  bare no-port servers compile `Port==0` and the builder skips them. Benign;
  pin in the extended golden, do not sell as load-bearing. Reviewers: agree it
  is a no-op-in-practice side effect?
- **Q7 (PLAN-KILL):** Given Layer A already closed the safety hole, is the UX
  gain worth the (now minimal, mostly-declarative) grammar churn? Honest framing:
  UX-only. Recommended scope is justified because the issue headline case is the
  Tier-3 flat path — a Tier-1-only or T3-C scope would read as a half-fix.
- **Q8 (BPF dead-path cast) — NOTED, no action.** `compileFlowTimeouts` casts
  the session timeouts to `uint32` (pkg/dataplane/compiler.go:1006-1012), but the
  live userspace `SetFlowTimeout` is a no-op stub (loader.go:391) — a legacy
  eBPF artifact (#1476). No live truncation; `[0, MaxDurationSeconds]` stands. If
  the eBPF path is ever revived (not planned), re-tighten the non-wire siblings.
