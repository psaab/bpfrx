# #1979 — Flow/flow-export NUM_WIDTH: commit-time ValidateInteger (Layer B of #1977)

**Status:** PLAN DRAFT v1 (research, not yet reviewer-converged)
**Base:** origin/master (`a75c970d8`, post-#1977/#1978 Layer A merge)
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

**Q-RATE (sampling input rate lower bound):** Layer A normalizes `rate <= 0 →
1` (a documented Junos semantic: 1-in-1 = sample every packet). Layer B has a
choice: (a) validate `[1, 4294967295]` (reject 0/negative as a clear error), or
(b) `[0, 4294967295]` (accept 0 and let Layer A normalize it to 1, preserving
the current silent behaviour). **Recommended: (a) `[1, 4294967295]`** — a `rate
0` is meaningless and Junos itself rejects it; rejecting at commit is the
clearer UX and Layer A still defends the gRPC/file path. This is an explicit
reviewer question (Q3).

---

## 4. The enumerated bounded leaves (verified by Explore agent + compiler read)

Eight distinct config leaves feed the 11 wire fields. `TCPMSSAllTCP` is **not a
distinct config leaf** — `tcp-mss all-tcp <n>` fans out into the three MSS
fields in the compiler (compiler_security.go:640-645); the wire `TCPMSSAllTCP`
field is never builder-populated. So the config surface to validate is:

| # | Config leaf (set path) | Wire field(s) | Schema node | Currently | Tier |
|---|---|---|---|---|---|
| 1 | `services flow-monitoring version9 template <t> flow-active-timeout <n>` | ActiveTimeout (u32) | schema_system.go:434 | `args:1, children:nil` (value slot exists) | **1** |
| 2 | `… version9 template <t> flow-inactive-timeout <n>` | InactiveTimeout (u32) | schema_system.go:435 | `args:1, children:nil` | **1** |
| 3 | `security flow tcp-session established-timeout <n>` (+ initial/closing/time-wait — see §4a) | TCPSessionTimeout (u64) | schema_security.go:177 `tcp-session` | **opaque `children:nil`** | **2** |
| 4 | `security flow udp-session timeout <n>` | UDPSessionTimeout (u64) | schema_security.go:178 `udp-session` | **opaque `children:nil`** | **2** |
| 5 | `security flow icmp-session timeout <n>` | ICMPSessionTimeout (u64) | schema_security.go:179 `icmp-session` | **opaque `children:nil`** | **2** |
| 6 | `forwarding-options sampling instance <i> input rate <n>` | SamplingRate (u32) | schema_routing.go:252 `input` | **opaque `children:nil`** | **2** |
| 7 | `… sampling … family {inet\|inet6} output flow-server <addr> port <n>` | CollectorPort (u16) | schema_routing.go:256/262 `flow-server` (args:1) | **opaque `children:nil`** | **2** |
| 8 | `security flow tcp-mss {ipsec-vpn\|gre-in\|gre-out\|all-tcp} <n>` **OR** `… { mss <n>; }` | TCPMSS{IPsecVPN,GreIn,GreOut} (u16) | schema_security.go:180 `tcp-mss` | **opaque `children:nil`** | **3 (dual value-location)** |

### §4a — Sibling timeouts that ALSO need validation for consistency

`tcp-session` compiles four timeout sub-leaves (compiler_security.go:589-597):
`established-timeout`, `initial-timeout`, `closing-timeout`, `time-wait-timeout`.
Only `established-timeout` reaches the wire `FlowSnapshot.TCPSessionTimeout`. The
other three are stored in `TCPSessionConfig` and consumed elsewhere (or not yet
wired). For UX consistency — and because expanding `tcp-session` to a container
*requires* declaring its known children anyway (otherwise completion regresses,
see §6) — **all four `tcp-session` integer sub-leaves should be typed** with
`[0, MaxDurationSeconds]` (the same Duration-overflow ceiling). The three
non-wire ones are config-correctness, not a wire-decode defense, but they share
the bound and cost nothing extra. Reviewer Q4 confirms this scope is intended.

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

`tcp-session` additionally declares `established/initial/closing/time-wait-timeout`
(all typed `[0, MaxDurationSeconds]`) plus the three presence flags
`no-syn-check`, `no-syn-check-in-tunnel`, `rst-invalidate-session` (declared as
`{children: nil}` so completion still offers them and the walker accepts them).
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

**SetPath grouping note (flow-server):** `flow-server` already has `args:1`.
Adding a `children` map flips its `i >= len(path)` terminal behaviour
(ast_edit.go:196) from "single-value REPLACE" to "named-container APPEND". For
`flow-server`, APPEND is the *desired* behaviour (an operator can configure
multiple collectors), and a bare `flow-server <addr>` with no port is a
degenerate config the compiler skips anyway (port is required). The
golden-grouping test will be extended to pin this. `input`/`tcp-session`/
`udp-session`/`icmp-session` have `args:0`, so the line-196 REPLACE branch never
applied to them (it requires `args > 0`); adding children only changes them from
"flag leaf" to "container", which is correct since they were always traversed
deeper.

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

### Option T3-A — custom dual-shape validator for the MSS leaves (RECOMMENDED)

Model `gre-in`/`gre-out`/`ipsec-vpn`/`all-tcp` as **containers** with a typed
`mss` child (covers the hierarchical form), AND add a small **node-level custom
validator hook** that the walker invokes for these containers to validate a flat
value packed in the container's own `Keys[1]`. Minimal, surgical: either
(i) a new optional `schemaNode` field — e.g. `selfValueValidator LeafValidator`
— that the container branch of `walkSchemaNode` runs against `Keys[1]` when
present (a few lines, additive, opt-in, no effect on any node that doesn't set
it); or (ii) a dedicated AST pre-pass in `compileSecurity`/`SchemaValidate` that
walks `tcp-mss` children and runs `ValidateInteger(0,65535)` over both positions
(self-contained, no walker change, mirrors `parseMSSValue`'s dual read exactly).

- **Pros:** validates BOTH shapes; rejects neither valid form; matches
  `parseMSSValue` semantics precisely. Option (ii) needs zero walker change.
- **Cons:** the only tier needing more than declarative schema; (i) adds a
  schemaNode field (must be documented + golden-tested); (ii) duplicates the
  dual-shape read logic (acceptable — it is small and mirrors the compiler).
- **Recommendation:** Option (ii) — a focused `validateTCPMSS(node)` helper
  invoked from the security-flow walk, reusing `parseMSSValue`'s exact dual
  read but range-checking instead of silently returning 0. No `setSchema`
  structural change for `tcp-mss` is strictly required for *validation* under
  (ii); the schema node can stay opaque, or be expanded only for completion
  (a separable, optional improvement). This keeps the SSOT-grouping blast radius
  zero for Tier 3.

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

**This plan's recommendation:** **Option T3-A(ii)** if reviewers accept the
small focused `validateTCPMSS` helper (it is ~20 lines mirroring the existing
`parseMSSValue`, fully testable, no SSOT-grouping risk). Fallback to **T3-C** if
reviewers judge the custom helper not worth it — Tiers 1+2 alone are a clean,
low-risk, high-coverage win and Layer A keeps MSS safe.

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
   Every child the compiler reads MUST be declared, or completion silently drops
   a previously-completable keyword. Verified compiler-read children to declare:
   - `tcp-session`: established/initial/closing/time-wait-timeout, no-syn-check,
     no-syn-check-in-tunnel, rst-invalidate-session.
   - `udp-session`/`icmp-session`: timeout.
   - `input`: rate.
   - `flow-server`: port, version9-template, version9{template}, source-address.
   (`tcp-mss` children only need declaring if Option T3-A(i) or completion
   parity for MSS is pursued; T3-A(ii) leaves it opaque.)
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

1. **Tier 1/2/3 acceptance (the gate):** for EVERY leaf, assert the **valid**
   value (both flat and hierarchical AST shapes where the leaf supports both)
   PASSES `SchemaValidate`, and the **out-of-range** value (negative, >u16/u32,
   >MaxDurationSeconds) is REJECTED with a range error. Drive via
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
   to BOTH `SchemaValidate` and the Layer-A coercion, asserting: every value
   Layer B accepts is left unchanged by Layer A; every value Layer B rejects is
   one Layer A coerces. (Pins the §3 contract.)
6. **Regression:** existing `TestTCPMSSHierarchical`, parser_security_test.go
   MSS tests, dual_ast_differential_test.go, schema_validate_* suites all pass.
7. `go build ./...` + `go test ./pkg/config/... ./pkg/cli/...` green.
8. **No smoke needed** (commit-time-only, no dataplane/wire change) — but a
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

Ship **Tiers 1 + 2** (leaves #1-#7, declarative schema + bounds = Layer-A caps)
plus **Tier 3 via Option T3-A(ii)** (focused `validateTCPMSS` dual-shape helper,
no SSOT grouping change). This validates all 8 config leaves / 11 wire fields at
commit with clear errors, rejects no valid config, and keeps the grammar blast
radius minimal. If reviewers reject the Tier-3 helper, fall back to **T3-C**
(Tiers 1+2 only) — still a clean win; MSS stays safe via Layer A.

---

## 11. Open questions for adversarial review

- **Q1 (completeness):** Is leaf #8's `all-tcp` correctly handled as a fan-out
  (not a distinct wire field)? Any OTHER config path to these 11 wire fields I
  missed (e.g. a gRPC-only setter, an interface-level tcp-mss)? [Explore agent
  found interface-level `family inet tcp-mss` exists for INTERFACE MSS — does it
  reach any of THESE flow fields, or a separate per-unit field? Confirm it is
  out of scope.]
- **Q2 (Tier 3 trap):** Is the experimentally-proven dual-value-location trap
  correctly characterized, and is T3-A(ii) (focused helper mirroring
  `parseMSSValue`) the right resolution vs T3-A(i) (schemaNode field) vs T3-C
  (defer)? Does adding a `validateTCPMSS` pre-pass fit the SchemaValidate
  architecture, or should it be a schemaNode-level hook for consistency?
- **Q3 (Q-RATE):** sampling `input rate` bound — `[1, u32max]` (reject 0 at
  commit, recommended) vs `[0, u32max]` (accept 0, let Layer A normalize)?
- **Q4 (§4a):** Type all four `tcp-session` timeouts (only `established-timeout`
  is wire-reaching) for UX consistency — agreed, or restrict to the wire-reaching
  one?
- **Q5 (§4b):** Type the version-ipfix `flow-active/inactive-timeout` pair too
  (NOT wire-reaching) for UX parity — agreed, or version9 only?
- **Q6 (grouping):** Is flipping `flow-server` to container/APPEND acceptable
  (it enables multiple collectors, matches compiler `FindChildren`), and is the
  extended golden the right pin?
- **Q7 (PLAN-KILL):** Given Layer A already closed the safety hole, is the UX
  gain worth ANY grammar churn? Is Tier 1 (zero-risk) the only justified slice,
  or is the full Tier 1+2+3-A scope warranted?
