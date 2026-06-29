# Config schema: the two-SSOT split (#1319)

xpf has **two** command-tree sources of truth. Knowing which one to edit
is the single most common mistake when adding CLI completion or config
validation.

## Operational tree → `pkg/cmdtree`

`run` / `show` / `clear` / `request` / `monitor` / `ping` / `traceroute`
and friends are defined in `pkg/cmdtree/tree.go` (`OperationalTree`).
Adding an operational command there propagates to all three frontends
(local CLI, remote CLI, gRPC) for tab completion and `?` help. Operational
leaves may be typed (`Node.ValueType` / `ValueDesc` / `ValueExamples` /
`Validator`).

## Config-mode grammar → `pkg/config` `setSchema`

The `set` / `delete` / `show` / `edit` configuration grammar is owned by
`config.setSchema` (a tree of `schemaNode` rooted in `pkg/config/schema.go`),
NOT by cmdtree. Since the #1891 domain split, `schema.go` holds the
`schemaNode` type and the root composition; the per-domain subtrees live in
sibling aspect files in the same package (`schema_security.go`,
`schema_interfaces.go`, `schema_routing.go`, `schema_system.go`,
`schema_chassis.go`, `schema_cos.go` — see the file map in `schema.go`).
`setSchema` drives **four** things off one tree:

1. **Structural completion** — what keywords are valid at each position.
2. **Flat-set token grouping** — how `set a b c d` packs into AST
   `Node.Keys` (`SetPath`, `ast_edit.go`). This is parser-critical: the
   replace-vs-container decision keys on `children == nil`.
3. **Value-slot `?` completion** — for a typed leaf, the placeholder
   (`<rate>`) + example values (`CompleteSetPathWithValues`,
   `schema_complete.go`).
4. **Commit-check validation** — the typed-leaf gate
   (`SchemaValidate` + the generic walker in `schema_walk.go`). Strict
   ONLY on the operator-driven commit / commit-check path
   (`configstore.compileTree`); the tolerant `Store.Load` /
   `Store.SyncApply` ingress (`compileTreeLenient`) downgrades a
   violation to a `slog.Warn` so an already-persisted or peer-synced
   config carrying a value that was typed (or range-tightened) later
   cannot blackout-boot a node or alarm-loop HA config sync. Boot
   safety is non-negotiable: when you tighten a range, any legacy value
   the compiler accepted MUST still load (`TestLoad_ToleratesStored*`
   in `pkg/configstore`).

Because completion (3) and validation (4) read the SAME node, they cannot
drift — typing a leaf fixes both `set ... ?` help and `commit check`
rejection together.

The live config-mode completers — `pkg/cli` `completeConfigWithDesc` and
`pkg/grpcapi` `completeConfigPairs` — route `set` paths through
`config.CompleteSetPathWithValues` over `setSchema`. `cmdtree.ConfigTopLevel`
only supplies the config-mode TOP-LEVEL keywords (`set`/`delete`/`commit`/
`load`/...) plus the retained `set system dataplane` description overlay.

## Multi-value leaves and bracketed lists (the dual-AST contract)

A `multi: true` leaf with `children: nil` (e.g. `from protocol`,
`from source-address`, `from destination-port`) accepts a Junos bracketed
list value:

```
from protocol [ tcp udp icmp ];                     # hierarchical block
set ... from protocol [ tcp udp icmp ]              # flat-set command
```

The **lexer strips the brackets** (`lexer.go` `[`/`]` cases just advance and
recurse), so by the time either parser sees the tokens the list value is
flat: `protocol tcp udp icmp`. Both AST shapes MUST converge on a single
leaf whose Keys carry every value:

```
Keys=[protocol tcp udp icmp]   IsLeaf=true   (no children)
```

- The **hierarchical** parser already does this — `parseKeys` appends every
  identifier on the line to one node's Keys.
- The **flat-set** path (`ParseSetCommand` → `SetPath`) had a dual-AST gap
  (#2419): the schema-walk consumed only `args` tokens onto the node key
  (`Keys=[protocol tcp]`) and split the tail into an ORPHAN child leaf
  (`Keys=[udp icmp]`), so the compiler — reading the node key only — dropped
  every list member after the first. `SetPath` now, for a
  `children == nil && multi` leaf, ABSORBS every following non-sibling token
  onto the node's own Keys (`ast_edit.go`), emitting the same single leaf as
  the hierarchical parser. The `low to high` range spelling
  (`destination-port 20000 to 20003`) is absorbed identically (none of
  `20000`/`to`/`20003` is a sibling keyword), matching the hierarchical
  `Keys=[destination-port 20000 to 20003]`.

**Compiler contract for multi-value leaves.** Because both shapes now deliver
the values on `child.Keys[1:]` (with the hierarchical-block-with-children
shape still possible for nested forms), a compiler reading a multi-value leaf
MUST read BOTH `child.Keys[1:]` AND `child.Children` and ACCUMULATE — never
read only `child.Keys[1]`. `firewallMatchValues` (`compiler_firewall.go`) is
the canonical helper; `parseDNATPortList` (`compiler_nat.go`) and
`descriptionText` (`compiler_security.go`) parse the unified single-leaf
shape directly off the node keys. `parseZoneList` (`compiler_nat.go`, the
static/source/destination-NAT `from`/`to` zone reader) and the WireGuard
peer `allowed-ips` reader (`parseTunnelWireguardPeer`,
`compiler_interfaces.go`) also follow the contract — both were silently
dropping all but the first bracketed value before the #2419 fold (static-NAT
`from zone [ trust dmz ]` lost the `dmz` rule-set entirely, FAIL-OPEN NAT).
Reading only `Keys[1]` silently drops all but the first list value — the
#2419 bug class. The flat-set bracket list is pinned to the hierarchical
shape by `TestFlatSetBracketListMatchesHierarchical` in
`pkg/config/parser_bracket_list_2419_test.go`; the static-NAT multi-zone and
allowed-ips folds are covered by the `security-nat-static-multi-zone` and
`interfaces-wireguard-allowed-ips-multi` dual-AST fixtures plus
`TestWireguardAllowedIPsBracketList{FlatSet,Hierarchical}`.

## Trailing-token arity on scalar value leaves (#3332)

The mirror image of the multi-value contract is the **scalar** value leaf: a
keyword that consumes EXACTLY `args` value token(s) and models no
sub-structure (`description`, `host-name`, `peer-address`, `scheduler-map`,
`port`, …). In the flat-set grammar a recognized non-multi leaf parks any
trailing token its arity does not expect as a CHILD node rather than on Keys
— `set interfaces ge-0-0-0 description hello bogus` becomes
`Keys=[description hello]` with an orphan child `Keys=[bogus]` (`SetPath`,
`ast_edit.go`). The compiler reads only the declared value span, so before
#3332 the orphan was silently DROPPED: a typo'd extra token committed cleanly
and the operator's garbage was discarded with no warning. (This is distinct
from the #3318 unknown-KEYWORD gate — here the leaf keyword itself IS
supported; only the trailing token is not. The screen subset was closed
earlier by #3411's `compileScreen` `recordKeyExtras`/`recordChildExtras`;
#3332 is the general schema-walk gate.)

`SchemaValidate` (`schema_walk.go`) now rejects the excess —
`validateScalarValueLeaf` rejects the first Keys token past `1+args` AND the
first AST child, with a value-arity message ("the extra token would be
silently dropped"). The gate fires only on an EXACT keyword match (a wildcard
match means the keyword is a dynamic instance NAME, not this leaf's value
slot) and only on a leaf the `schemaNode.isScalarValueLeaf` predicate
(`schema.go`) admits.

**Why an explicit `scalar: true` opt-in, not structural inference.** An
`args > 0, children: nil` node is NOT reliably a value leaf: several are
deliberately-OPAQUE CONTAINERS whose body is left to the compiler and parsed
off the node's AST children — `applications application-set <name> {
application <member>; }`, `applications application <name> { ... }`, `system
syslog file <name> { ... }`. Their legitimate body lands on Keys/Children
exactly like a typo would, so a structural-only gate would false-reject real
config (caught in review: `application-set my-set application junos-http`).
The arity contract therefore lives on an explicit per-leaf `scalar: true`
tag, asserted only on leaves audited to take a fixed value and NO body
(`description` across the tree, `system host-name`, dynamic-peer/feed
`hostname`). This is the "design pass on the value-arity contract" the #3332
body called for; new scalar leaves opt in as they are audited.

`isScalarValueLeaf` also carries belt-and-braces structural guards, so a
future mis-tag on a node that is actually multi / typed / a container
degrades to a no-op rather than a surprise rejection. It exempts:

- **`!scalar`** — un-tagged leaves are untouched (the opt-in default).
- **`multi`** — bracketed lists / value tails (#2419, above) absorb every
  trailing value by design.
- **`children != nil` / `wildcard != nil`** — named-instance / modifier
  containers (`address <cidr> { primary; }`, `transmit-rate 1g exact`): the
  trailing tokens are real sub-structure the container path validates.
- **`compoundKey` / `midKeyword`** — the trailing token is part of the node
  key (`family inet6`, `from-zone X to-zone Y`).
- **`isTypedLeaf`** — `validateTypedLeaf` already rejects unknown trailing
  tokens and unexpected children for typed leaves.
- **`args == 0`** — a childless, untyped, zero-arg node is AMBIGUOUS between
  a presence-only flag (`dhcp`) and a deliberately-OPAQUE leaf whose subtree
  the compiler reads despite no schema children (`tcp-mss <mode> <value>`,
  #1979; the unmodeled NAT pool `address`/`port`/`host` leaves). The screen
  flag subset (`tcp land`, …) is handled by #3411 instead.

A quoted multi-word value (`description "trust zone"`) arrives as ONE token,
so it is unaffected — only an UNQUOTED trailing token (`description trust
zone`, invalid Junos) is rejected. Minimum arity is NOT enforced — a missing
value is still left to the compiler; the gate is scoped strictly to EXCESS
trailing tokens, the silent-drop bug class. Pinned by
`pkg/config/schema_validate_trailing_token_3332_test.go`
(`TestSchema3332_*`, including the `application-set` opaque-container guard).

### `firewall ... from tcp-flags` — semantic validation, not just a list (#3076)

`from tcp-flags` is a `multi: true` leaf, so the dual-AST contract above
delivers its tokens uniformly (`firewallMatchValues`). But unlike a plain
value list, the tokens form a Junos logical *expression* — `"syn & !ack"`,
`"(syn & ack)"`, `"ack | rst"` — where `&`/`|`/`!`/`(`/`)` carry meaning.
A quoted expression arrives as a single token string; a bracket/space list
(`[ syn ack ]`, `"syn ack"`) is an implicit conjunction.

`ParseTCPFlagsExpression` (`pkg/config/tcp_flags.go`) parses the joined tokens
into a **required-bits** mask and a **forbidden-bits** mask over the TCP flags
byte (`(flags & required) == required && (flags & forbidden) == 0`). The
conjunctive AF_XDP matcher can carry one required set and one forbidden set, so
the following are **rejected at commit** (`compileFirewall` returns an error)
rather than silently dropped:

- disjunction (`|`, e.g. `"ack | rst"`) — not a single required/forbidden pair;
- a negated parenthesized group (`!(...)`) — a disjunction by De Morgan;
- an unrecognized flag token;
- a flag that is both required and forbidden (the term could never match).

This is the #3076 fix: before it, the schema accepted any `tcp-flags` token
(the leaf is `multi: true` with no value validator) and the snapshot builder's
bare-name-only lookup silently dropped any expression it could not map — the
filter term then matched **regardless** of TCP flags (a fail-open security
hole). Validation is now fail-closed: an unenforceable constraint is refused at
commit, and a representable one (including `syn & !ack`) is carried to the
dataplane via the `tcp_flags` / `tcp_flags_forbidden` wire fields.

### `firewall ... from icmp-type` / named ports — resolve + fail closed (#3205)

`from icmp-type` / `icmp-code` and the four port leaves (`source-port`,
`destination-port`, `source-port-except`, `destination-port-except`) accept
SYMBOLIC Junos match values: icmp-type names (`echo-request`, `echo-reply`,
`destination-unreachable`, ...) and service/port names (`ssh`, `http`,
`domain`, ...). `pkg/config/filter_match_resolve.go` is the SSOT that resolves
these to numbers at compile time — the icmp-type table is **family-selected**
(ICMPv4 for `family inet`, ICMPv6 for `family inet6`: `echo-request` = 8 vs
128), and the port table is the canonical Junos service-name set (e.g.
`domain` = 53). Resolved ports are rewritten to numeric form so the dataplane
only ever sees numerics.

This is the #3205 fix (agy-070 #07/#08). Before it:

- `icmp-type`/`icmp-code` were parsed with `strconv.Atoi` and the error was
  IGNORED, so a symbolic name was silently dropped — the type/code set went
  empty, and an empty set matches **ALL** ICMP, so an `accept` term meant to
  permit only `echo-request` silently permitted every ICMP type (a policy
  bypass);
- an unknown named port left the port set constrained-but-empty, and a
  `*-port-except` term then matched **ALL** ports (fail open — it permitted the
  very port it was meant to exclude).

`validateFilterMatchValuesStrict` (`compiler_validate_strict.go`) **rejects at
commit** any term whose icmp-type/icmp-code name or port name could not be
resolved (the unresolved token is recorded on the term as
`UnknownICMPTypes`/`UnknownICMPCodes`/`UnknownPorts`, mirroring
`UnknownActions`). On the tolerant load / peer-sync path the error is
downgraded to a warning (#1960 no-brick) and the token is kept verbatim so the
dataplane fails CLOSED independently (the Rust `port_match` constrained+empty
guard now fails closed for `except` too — see `userspace-dp/src/filter/
README.md`). Symbolic icmp-CODE names are not resolved (Junos code names are
type-dependent) — a numeric 0-255 is required and a symbolic code is rejected.
Fail-on-revert: `TestFilterICMPTypeNameResolves{V4,V6}_3205`,
`TestFilterUnknown{ICMPType,Port}Rejected_3205`,
`TestFilterNamedPortExceptResolves_3205` in
`pkg/config/firewall_symbolic_match_3205_test.go`.

The `system domain-search` and `system name-server` readers
(`compileSystem`, `compiler_system.go`) are also contract-compliant via
`firewallMatchValues`. Both are `multi:true`; before the second #2419 fold
they read only `child.Keys[1]` plus orphan leaf children. That orphan-children
path worked on flat-set BEFORE #2419 (the bracket split into child leaves), so
#2419's collapse onto `Keys[1:]` (no children) silently dropped every value but
the first — a #2419 regression (search domains lost; the DNS resolver drop-in
written from `name-server` lost every server but the first). Fail-on-revert
covered by `TestSystemDomainSearchBracketList{FlatSet,Hierarchical}` and
`TestSystemNameServer{BracketListFlatSet,BlockListHierarchical}` in
`pkg/config/system_multileaf_test.go`.

The routing-protocol export/import readers and the policy-options community
`members` reader were brought onto the contract in #2587. The schema leaves
were already `multi:true` (`schema_routing.go`: `protocols ospf export`,
`protocols ospf3 export`, `protocols bgp export`/`import`, `protocols isis
export`, `policy-options community <name> members`), but the compilers
(`compileProtocols`, `compiler_protocols.go`; `compilePolicyOptions`,
`compiler_routing.go`) read only `child.Keys[1]` with no children iteration,
so `protocols ospf export [ connected static ]` redistributed only
`connected` and `community c1 members [ 65000:1 65000:2 ]` truncated to the
first member. All six now route through `firewallMatchValues`.

The BGP **group** and **neighbor** export/import readers
(`compiler_protocols.go`, #2490) were NOT on the contract: they used the
`nodeVal(child)`-first pattern (`if v := nodeVal(child); v != "" { append v }
else if len(Keys) >= 2 { append Keys[1:] }`). Because `nodeVal` returns
`Keys[1]` (non-empty for a bracket list), the `v != ""` branch fired and
appended ONLY the first policy — the `Keys[1:]` fallback never ran, so
`group g1 export [ OUT-A OUT-B ]` and `neighbor 10.0.0.1 export [ N-A N-B ]`
silently dropped every policy past the first (#2702; an earlier #2690 review
note that these readers were "already correct" was wrong). All four
(group export/import, neighbor export/import) now route through
`firewallMatchValues`, matching the top-level readers. Fail-on-revert covered
by the `TestOSPFExport*`, `TestBGPExportImport*`,
`TestBGPGroupExportImport*`, `TestBGPNeighborExportImport*`,
`TestOSPFv3Export*`, `TestISISExport*`, and `TestCommunityMembers*` cases in
`pkg/config/protocols_multileaf_2587_test.go`.

The policy-statement `from community`, `from prefix-list`, and `from as-path`
match readers were the same class and were brought onto the contract in #2689
(`as-path` folded in during review). All three leaves are `multi:true`
(`schema_routing.go`: `policy-options policy-statement <name> term <name> from
prefix-list`/`community`/`as-path`), but `parsePolicyTermChildren`
(`compiler_routing.go`) read only `nodeVal(fc)` = `child.Keys[1]`, so
`from community [ c1 c2 ]` matched only `c1`, `from prefix-list [ p1 p2 ]`
matched only `p1`, and `from as-path [ a1 a2 ]` matched only `a1` (the dropped
as-path was silently absent from the `policy_render.go` cartesian OR product).
All three now route through `firewallMatchValues`. This composes with the #2642
repeated-sibling append below — a term carrying BOTH a bracket list AND a
separate `from community c3` sibling keeps every value (`[c1 c2 c3]`).
Fail-on-revert covered by `TestPolicyFromCommunity*`, `TestPolicyFromPrefixList*`,
and `TestPolicyFromASPath*` in `pkg/config/policy_from_multileaf_2689_test.go`.

The policy-statement ACTION `then as-path-prepend "<asn> <asn> ..."` (#2892) is
the same class on the `then` side. The leaf is `multi:true`
(`schema_routing.go`: `policy-options policy-statement <name> term <name> then
as-path-prepend`) so a quoted `"65001 65001"` or bracketed `[ 65001 65001 ]`
list — the lexer strips quotes and brackets alike — flattens onto the node's
`Keys`/`Children` rather than collapsing to last-only. `parsePolicyTermChildren`
and `parsePolicyTermInlineKeys` (`compiler_routing.go`) read EVERY ASN via
`firewallMatchValues` (reading only `Keys[1]` would drop all but the first
prepend — and dropping the repeats defeats the AS-path-prepend mechanism, which
is exactly the repetition). The ordered list lands in `PolicyTerm.ASPathPrepend
[]string` and renders as the FRR `set as-path prepend <asn> <asn> ...` clause
(`policy_render.go`). Fail-on-revert covered by `TestASPathPrepend_*` in
`pkg/config/compiler_as_path_prepend_2892_test.go` (parse) and
`TestGeneratePolicyOptions_ASPathPrepend` in
`pkg/frr/policy_as_path_prepend_2892_test.go` (render).

## Repeated same-type sibling matches (NOT bracketed multi-value)

The dual-AST contract above covers a single leaf carrying a bracketed list
(`from community [ c1 c2 ]`). A SEPARATE phenomenon is the same match
statement REPEATED as sibling leaves in one block:

```
policy-options policy-statement P term t1 {
    from {
        community c1;        # repeated sibling leaves, NOT a bracket list
        community c2;
        prefix-list pl1;
        prefix-list pl2;
        as-path a1;
        as-path a2;
    }
    then accept;
}
```

Junos OR's repeated same-type `from` matches ("match any"). `PolicyTerm`
holds these as `[]string` (`PrefixList` / `FromCommunity` / `FromASPath`) and
the compiler (`parsePolicyTermChildren`, `parsePolicyTermInlineKeys` in
`compiler_routing.go`) APPENDS every value rather than overwriting — the
pre-#2642 single-string field silently kept only the LAST. The FRR renderer
turns each value into its own route-map sequence (OR semantics; FRR replaces
a same-type `match` rule in one index, so multiple match lines cannot OR) —
see `pkg/frr/README.md` (`policy_render.go`, #2642).

**Dual-AST convergence (#2630, fixed):** the HIERARCHICAL (brace) parser has
always accumulated every sibling correctly. The FLAT-SET path used to be
LIMITED — `ConfigTree.SetPath` collapsed repeated `set ... from community c1` /
`from community c2` sibling paths onto ONE AST node before the compiler ran, so
only the last value reached the compiler (silently dropping all but the last
`route-filter` / `prefix-list` / `community` / `as-path`). #2630 fixes this by
marking those four `from` leaves `multi: true` in `setSchema`
(`schema_routing.go`): the same `SetPath` multi-value-leaf logic that keeps
`from protocol` siblings distinct now keeps each repeated `set` line as its own
sibling leaf, so the two AST shapes CONVERGE on the same typed config.
`route-filter` is `args: 2` (prefix + match-type); a trailing
`upto /N` / `prefix-length-range /lo-/hi` / `through <cidr>` arg is absorbed as
a fourth packed key by the multi value-tail logic, matching the brace AST the
compiler reads via `routeFilterTrailingToken`. Proven by
`TestRouteFilterFlatSetMultipleAccumulate` + `TestRouteFilterFlatSetBraceParity`
(`compiler_route_filter_range_2525_test.go`) and
`TestPolicyTermMultiMatch_FlatSet_2630` /
`TestPolicyTermMultiMatch_Hierarchical_2642`
(`compiler_policy_term_multimatch_2642_test.go`).

## Repeated definition blocks merge (prefix-list, community)

A named policy-options DEFINITION can be authored across multiple separate
blocks — two `prefix-list NAME { ... }` braces, or two
`set policy-options prefix-list NAME ...` set groups (and likewise for
`community NAME`). `compilePolicyOptions` (`compiler_routing.go`) MERGES these
by reusing the existing `po.PrefixLists[name]` / `po.Communities[name]` map
entry and APPENDING each block's prefixes/members, rather than allocating a
fresh struct and overwriting `po.PrefixLists[name]` (which discarded the
earlier block — the #2641 prefix-list bug; the community loop already merged).
The two AST shapes converge: flat-set `SetPath` collapses repeated same-name
set groups onto one AST node so they accumulate naturally; the hierarchical
parser keeps two same-name brace blocks as distinct `namedInstances`, and the
map-reuse merge keeps both. Fail-on-revert covered by
`TestPrefixListMergeDuplicateBlocksFlatSet` /
`TestPrefixListMergeDuplicateBlocksHierarchical`
(`compiler_prefix_list_merge_2641_test.go`).

## `then community` operations: add / delete / set / none (#2848)

The policy-term action `then community` supports the Junos/vSRX community
operations in addition to the legacy bare replace form. Junos grammar is
`then community (add | delete | set) <community-name>` plus `then community none`;
the bare `then community <value>` is the historical whole-attribute replace and
stays valid for back-compat.

| Junos `then community ...` | xpf `CommunityOp` | FRR route-map set clause |
|----------------------------|-------------------|--------------------------|
| `add <value>`              | `add`             | `set community <value> additive` |
| `delete <name>`            | `delete`          | `set comm-list <name> delete`    |
| `delete [ <a> <b> ... ]`   | `delete`          | one `set comm-list <name> delete` PER list (#2902) |
| `set <value>`              | `set`             | `set community <value>`          |
| `<value>` (bare)           | `""`              | `set community <value>`          |
| `none`                     | `none`            | `set community none`             |

`add` APPENDS to (does not overwrite) the existing community attribute — the
parity gap that motivated #2848: emitting only `set community <value>` wiped
upstream-set communities, breaking community-based traffic engineering and tag
propagation in transit networks. `delete <name>` references a named
`policy-options community <name>` (which xpf already renders as a
`bgp community-list <name>`), so FRR's `set comm-list <name> delete` strips
exactly its members. `none` strips all communities.

**Multi-list delete (#2902):** `then community delete [ listA listB ]` references
MULTIPLE community-lists. FRR's `set comm-list <name> delete` strips ONE list per
line, so `PolicyTerm.CommunityDelete` is a `[]string`: the compiler accumulates
every name in `vals[1:]` (the lexer strips the brackets, so the clause flattens
to `delete listA listB` — the #2419 multi-value shape) and the renderer emits one
`set comm-list <name> delete` clause per list. The pre-#2902 code stored only
`vals[1]`, silently dropping `listB...` so the communities the operator meant to
strip leaked into advertised prefixes.

Schema (`schema_routing.go`): `then community` is a `multi: true` leaf that
packs the optional operation keyword plus the value onto one leaf's Keys
(`community add 65000:111`, `community none`, `community 65000:111`). The
compiler's `applyCommunityAction` (`compiler_routing.go`) reads every token via
the `firewallMatchValues` SSOT and interprets the first token: `add`/`delete`/
`set`/`none` select the operation, any other first token is a bare replace
value. Both AST shapes converge — `SetPath`/block parse both nest `then` as a
child node, so the hierarchical compile path is the one exercised; the flat
inline path carries belt-and-suspenders handling for the same forms.

Fail-on-revert: compiler-level
`TestPolicyCommunityOperationsCompile` and
`TestPolicyCommunityDeleteMultiListCompile` (`pkg/config/parser_security_test.go`)
and end-to-end `TestPolicyCommunityOperations` +
`TestPolicyCommunityDeleteMultiList` (`pkg/frr/frr_test.go`, full
ParseSetCommand + SetPath + CompileConfig + `generatePolicyOptions`).

## How to add a config-mode typed leaf

Edit the leaf's `schemaNode` in `setSchema` (in the domain's
`pkg/config/schema_<domain>.go` aspect file). Set:

```go
"transmit-rate": {
    args:          1,
    valueType:     ValueRate,                // placeholder + opt-in
    valueDesc:     "Bandwidth (e.g. 100k, 10m, 1g) ...",
    valueExamples: []string{"100k", "10m", "1g"},
    validator:     ValidateRate,             // commit-check
    children:      map[string]*schemaNode{   // modifiers ONLY if pre-existing
        "exact": {children: nil},
    },
},
```

Rules:

- **Range policy: runtime first, Junos second.** The binding bound is
  what the xpf runtime actually consumes — the narrowest binary encoding
  (e.g. `cluster-id` is one byte of the RETH virtual MAC;
  `reth-advertise-interval` must encode into the 12-bit VRRPv3
  centisecond field) or an explicit runtime clamp/ignore. Check the
  Junos vSRX range second and call out deliberate divergences in the
  annotation comment: xpf's own defaults sit OUTSIDE the Junos ranges
  for several chassis knobs (heartbeat-interval default 100 ms vs Junos
  1000..2000), and the killed #1319 Phase-3a plan copied Junos ranges
  blindly — it would have rejected deployed configs. **No schema-only
  caps** (Codex review, PR #1845): if the runtime accepts any value, use
  min-only semantics (`ValidateIntegerMin`) or the runtime-derived
  ceiling (`MaxDurationMillis` for millisecond knobs that convert to
  `time.Duration`); a sanity cap must be enforced in the runtime FIRST,
  never in the schema alone. Cite the source file:line for every bound
  next to the annotation.
- **Fields only, do not add a `children` map just to type a leaf.** SetPath's
  grouping keys on `children == nil` (`ast_edit.go:196`); flipping a leaf to
  a container changes flat-set grouping for existing configs. The
  `TestSetPathGrouping_Golden` test in
  `pkg/config/schema_validate_test.go` guards this.
- **Only type a leaf the compiler actually consumes.** Typing a leaf the
  compiler ignores would make `commit check` reject config the compiler
  would have silently dropped — a behaviour change beyond completion/
  validation. (This is why scheduler `buffer-size temporal` was NOT carried
  over: the compiler never reads it.)
- **Validators live in `pkg/config/schema_validators.go`** and are stateless
  string-checkers reusing the compiler's parsers. Add a generic one
  (`ValidateInteger(min,max)`, `ValidateEnum([...])`, the IP family
  validators `ValidateIPAddress` / `ValidateIPv6Address` /
  `ValidateIPv4CIDR` / `ValidateIPv6CIDR` / `ValidatePREF64CIDR`)
  or a bespoke `ValidateX(raw string, cfg *Config) error`. **cfg is always
  nil in production** — both call sites run the gate BEFORE compile
  (`configstore.compileTree` / `compileTreeLenient`), so a validator must
  never depend on compiled state. Cross-reference validators use the
  TREE-based `treeValidator` field instead: `SchemaValidate` pre-collects
  referenceable definitions from the candidate tree into `schemaRefs`
  (`collectSchemaRefs`, e.g. the forwarding-class names) and hands them to
  the validator, so a definition + reference in the same commit validate
  atomically. The refs union includes group bodies (applied or not) so
  node-variable configs never false-reject.
- **Typed KEY slots (named-instance containers).** A container whose value
  is its IDENTITY token (`family inet address <cidr> { primary; }`) cannot
  use `valueType`/`validator` — that would flip the walker into the
  typed-LEAF branch and mis-validate the container's real block children.
  Set `keyValueType`/`keyValueDesc`/`keyValueExamples`/`keyValidator`
  instead: the walker validates the identity arg token(s) in both the
  packed-Keys and the nested instance-name shapes (both of which
  `namedInstances` compiles), and `?` completion surfaces the key
  placeholder + examples at the empty identity slot.
- **Multi value-tail leaves accept the block-list spelling.** A
  `multi && children == nil` typed leaf is compiled from BOTH the packed
  Keys (`name-server 1.1.1.1`, ranges with the `to` separator) and the
  hierarchical block list (`name-server { 1.1.1.1; 8.8.8.8; }`) — the
  walker's `validateMultiValueLeaf` validates each block child's FIRST
  token, exactly what the compilers read.
- The generic walker (`schema_walk.go`) needs **no** changes per leaf — it
  descends `setSchema` and validates any typed leaf it finds. Walker rows it
  handles: container/args/compoundKey/midKeyword/wildcard, the standard
  typed leaf (first token is the value, remaining tokens must be known
  modifier children), the `multi && children == nil` value-tail/range shape
  (`destination-port 20000 to 20003`, rejecting dangling/all-separator
  tails), and the cross-sibling modifier-only line (`transmit-rate exact`
  valid only when a sibling leaf supplies the rate).
- **Compiler-faithful rule (important).** The walker validates typed leaves
  exactly where the per-subsystem compiler reads them. For a named-instance
  container (e.g. `class-of-service schedulers <name> { ... }`) the compiler
  reads leaves from the instance node's CHILDREN; tokens packed into the
  instance node's own Keys beyond the name are NOT compiled, so the walker
  ignores them — it never validates, nor mis-attributes block children to,
  such packed tokens. This means malformed shorthand the compiler silently
  discards (e.g. `schedulers be transmit-rate asd` as a single node with no
  children) is intentionally NOT rejected: rejecting config the compiler
  ignores is a behaviour change beyond #1319's compiled-leaf-only scope. The
  real symptom-2 path — `set class-of-service schedulers be transmit-rate
  asd` — lands the leaf as a CHILD, where it IS compiled and IS rejected.
  This contract was converged across 7 hostile Codex review rounds; do not
  re-add packed-tail validation without re-checking compiler reachability.

## Help-text discipline (#1892)

Every `schemaNode` in `setSchema` MUST carry a `desc:` — an empty desc
renders as a blank line in `?` completion across all three frontends.
The #1892 audit filled all 493 previously-empty nodes; do not add new
nodes without one. Rules:

- **Verified behavior only.** A wrong help text is worse than a missing
  one. Write the desc from the compiler/runtime consumer, not from what
  the keyword sounds like. Containers get structural descs ("Source NAT
  configuration"); behavior-bearing leaves state what the consumer does,
  with enum values / units / defaults in parens ONLY when read from
  code (model: `claim-host-tunables` — "Allow xpfd to write host-scope
  tunables (true|false, default false)").
- **desc / placeholder are display-only.** They never affect SetPath
  grouping, so help fixes are always grouping-safe. Structure fields
  (`args`, `children`, `wildcard`, `multi`) are NOT — see the typed-leaf
  rules above.
- **`groups <*>` mirrors the top level by pointer** (`init()` in
  `schema.go`), so a top-level desc automatically documents the same
  path under `groups <name> ...`. Never duplicate nodes to add help.

## Retired knobs (#1525 / #1892)

Retired DPDK-era `system dataplane` knobs — `cores`, `memory`,
`socket-mem`, `rx-mode {idle-threshold, resume-threshold,
sleep-timeout}`, `ports <name> {interface, rx-mode, cores}` — remain
parseable for stored-config compatibility (a stanza that committed once
must never stop loading), but have NO consumer:
`compileUserspaceDataplane` records them in
`UserspaceConfig.RetiredKnobsSeen` and `userspaceRetiredKnobWarnings`
emits a per-knob commit warning ("retired DPDK-era knob (#1525),
accepted for config compatibility but ignored") on both the strict and
lenient compile paths. Their schema descs say "(retired, ignored)" so
completion stops advertising them as live. Follow this pattern —
keep-parsing + warn + honest desc — when retiring any future knob;
hard-reject (the `dataplane-type dpdk` / `ebpf` sentinel errors) is
reserved for whole-dataplane selection where a rewrite shim
(`rewriteRetiredDataplaneType`) protects stored configs.

## Rollout (#1319)

- **PR 1 (merged, #1682):** moved `ValueType` to `pkg/config`; added the
  typed fields to `schemaNode`; wired typed-value `?` completion into
  `CompleteSetPathWithValues`; replaced the schedulers-only hand-rolled
  walker + class-of-service early-return with the generic
  `config.SchemaValidate` walker; re-homed the schedulers typed leaves onto
  `setSchema`; retired the cmdtree config-mode overlay. 3 typed leaves
  (schedulers transmit-rate / priority / buffer-size).
- **PR 2 (this work, chassis cluster):** downgraded the gate to a warning
  on the tolerant Load/SyncApply paths (boot safety — PR 1 had wired it
  strict there too); typed 13 chassis-cluster leaves (cluster-id, node,
  reth-count, heartbeat-interval/-threshold, reth-advertise-interval,
  takeover-hold-time, peer-fencing, RG node priority,
  gratuitous-arp-count, ip-monitoring global-weight / global-threshold /
  target weight) with runtime-derived, source-cited ranges. Deliberately
  NOT typed, with reasons in the `schema_chassis.go` comments: the
  `redundancy-group <id>` / RG-scoped `node <id>` instance-name slots
  (the walker's compiler-faithful contract consumes identity tokens
  without validation — typing them needs a new walker feature),
  `interface-monitor <if> weight <n>` (tokens pack inline into a
  `children==nil` leaf; typing the weight needs a children map, which
  would flip SetPath grouping), `control-ports` (not compiled), and the
  address/interface string leaves (IP value types arrive with the
  interfaces PR). Known residual: the hierarchical packed one-liner
  `node 0 priority <v>;` bypasses the gate (identity-token rule) even
  though `compileChassis` reads its inline tokens — pinned by
  `TestSchemaValidate_ChassisCluster_PackedOneLinerBypassesGate`.
- **PR 3 (this work):** the remaining converged-plan sections in one PR —
  (a) **interfaces**: `ValueIPAddress`/`ValueCIDR` value types, the typed
  KEY-slot walker feature, and 16 typed slots (mtu ×3, vlan-id,
  inner-vlan-id, family inet/inet6 `address` CIDR key slots, vrrp-group
  priority / advertise-interval / virtual-address, tunnel
  source/destination/ttl/key, wireguard listen-port /
  persistent-keepalive). **#2384 — IPv6 VRRP:** the `vrrp-group <id>`
  subtree now exists under **both** family `inet` and family `inet6`
  (built by the shared `vrrpGroupSchemaNode(v6 bool)` helper in
  `schema_interfaces.go`, parsed by the shared `parseVRRPGroups` helper in
  `compiler_interfaces.go` from both family arms). The only difference is
  the `virtual-address` validator: `ValidateIPv4CIDR` under `inet`,
  `ValidateIPv6CIDR` under `inet6` — so a v6 VIP commits cleanly under
  `inet6` and is rejected under `inet` (and vice versa). The native VRRP
  engine already family-detects each VIP at parse (`ip.To4()==nil`,
  `pkg/vrrp/instance.go`), so no runtime change was needed. Compiled
  groups are keyed `<address-CIDR>_grp<id>`, so a dual-stack unit may
  carry an `inet` AND an `inet6` vrrp-group with the SAME group id without
  collision (the address strings differ → two distinct
  `unit.VRRPGroups` entries). **#2850 — `preempt hold-time`:** the
  `vrrp-group <id> preempt` leaf gained a nested `hold-time <seconds>`
  child (`schema_interfaces.go`, typed `ValidateInteger(1, 3600)`), Junos
  `set interfaces <if> unit <n> family inet vrrp-group <id> preempt
  { hold-time <s>; }`. It compiles to `VRRPGroup.PreemptHoldTime`
  (seconds; `compiler_interfaces.go` parses both the braced child and the
  flat-set `preempt hold-time <n>` Keys-run), plumbed to
  `vrrp.Instance.PreemptHoldTime`. Bare `preempt` (no hold-time) keeps
  PreemptHoldTime 0 = immediate preemption (unchanged). At runtime a
  higher-priority backup reclaiming mastership from a STILL-LIVE
  lower-priority master defers the takeover by hold-time seconds (so
  dynamic routing converges before failback); a dead/silent master or a
  graceful priority-0 resignation is never delayed
  (`pkg/vrrp/instance.go` `preemptHoldDuration` /
  `preemptingLiveLowerMaster`). **#2900 — armed-hold re-validation:** an
  armed hold is re-validated at two points the original #2850 arming did
  not cover. (1) At expiry, before promoting, the hold-elapsed case re-runs
  `shouldPreemptObservedMaster` (the same RFC 5798 §6.4.2 gate the
  force/sync-hold path uses): preemption must still be enabled AND, while a
  live master is still present, our effective priority must still be
  strictly higher than its last advert. If preempt was disabled or our
  priority was demoted below the live master (track-interface link-down)
  during the hold, the node does NOT take over — it returns to a normal
  BACKUP tenure by re-arming `masterDownTimer`. A master that went silent
  during the hold reads as stale and still triggers a dead-master takeover.
  (2) `updateConfig` (manager goroutine) signals the run loop via
  `configUpdatedCh` after mutating cfg; the BACKUP select tears any in-flight
  hold down (`disarmPreemptHold`) and re-arms `masterDownTimer`, so the next
  expiry re-evaluates against the fresh config — a changed `hold-time` arms
  the NEXT countdown with the new duration, and a disabled preempt /
  demotion no longer fires a spurious takeover at the old expiry. All
  `preemptHoldTimer` Stop/Reset calls stay on the single run-loop goroutine;
  `preemptHoldArmed` (mu-guarded) tracks the armed state across the two
  goroutines. The WireGuard `peer` node is a NAMED-INSTANCE
  container keyed by the peer public key (#1434 multi-peer):
  `set interfaces <wg> tunnel wireguard peer <public-key>
  { allowed-ips <cidr>; endpoint <ip:port>; persistent-keepalive <s>;
  preshared-key <hex>; }`. A WG interface may terminate N peers on one
  listen port; the pubkey is the instance identity (modeled on
  `vrrp-group <id>`, dual-AST via `namedInstances`). A commit-time gate
  (`validateWireguardPeersStrict`, `compiler_validate_wireguard.go`)
  hard-rejects a WG tunnel with zero peers, a duplicate or malformed
  (non-64-hex) peer pubkey, a malformed preshared-key,
  endpoint-bearing peers that disagree on outer transport family (one
  UDP socket = one outer family), or an EXACT-duplicate `allowed-ips`
  prefix across two peers (#2445 — the cryptokey routing table maps a
  prefix to exactly one peer, so an exact tie has no longest-prefix
  winner and the engine LPM resolves it by insertion order, silently
  blackholing the loser; the check canonicalizes each CIDR to its masked
  network so `10.0.0.5/24` and `10.0.0.0/24` collide, while a
  broader/narrower OVERLAP — a `0.0.0.0/0` catch-all peer plus a
  more-specific peer — stays valid because LPM resolves it
  deterministically); the tolerant load / peer-sync path
  (`lenientWireguardPeers`) downgrades these to warnings so an
  already-persisted or peer-synced config still boots (#1960). The
  compiler sorts `WgPeers` by pubkey at the snapshot-builder boundary so
  both HA nodes serialize byte-identical snapshots. The pubkey is
  lowercased at parse so the canonical form drives the dedup key, the
  wire bytes, and the documented "64-char lowercase hex" contract
  together (a `AA..`/`aa..` pair collides at commit instead of orphaning
  a peer in the engine's release-build reconcile). **Syntax-migration
  note:** the pre-#1434 leaf form `peer { public-key <key>; ... }`
  (#1432 S2a) is NOT auto-migrated to the named-instance form `peer
  <key> { ... }`. There is no production persisted old-form WG config
  (WG was experimental and live interop is deferred to #1703), but an
  old-form config reloaded leniently parses the literal token
  `public-key` as a bogus peer name, fails the hex validator, and
  downgrades to a load-time warning — fail-safe (no brick, #1960), but
  the tunnel silently loses its real peer until re-authored in the new
  syntax. (b) **firewall**:
  the `then forwarding-class`
  tree-based cross-ref for both families (dangling references reject at
  commit; same-commit definition + reference passes; `best-effort` is
  always resolvable; the other Junos default classes are deliberately NOT
  implicit — xpf's runtime does not define them); (c) **system/services**:
  22 typed slots (name-server, ssh root-login enum, ssh key-exchange
  multi-value list (H5/#2008; renders to sshd `KexAlgorithms` —
  `pkg/daemon/daemon_system.go` `buildSSHDConfig`; left untyped/no enum
  because sshd validates the algorithm spellings at reload), the dataplane
  workers/ring-entries/poll-mode/rss-indirection/claim-host-tunables/
  netdev-budget/coalescence knobs, the rpm probe knobs, ip-monitoring
  hold-down / preferred-metric) plus the `validateMultiValueLeaf`
  block-list walker extension the deployed `name-server { 1.1.1.1; }`
  shape requires. Deliberately untyped, with reasons in
  `schema_system.go` / `schema_interfaces.go`:
  `unit <n>` / `vrrp-group <id>` instance ids (cross-referenced from other
  subsystems — one dedicated pass later), `track-interface priority-cost`
  (#1814 pre-walk owns it), `cpu-governor` (pass-through by design), dhcp
  client knobs, tunnel keepalives.
- **#2524 (ring-entries bound):** `system dataplane ring-entries` was
  min-only (`ValidateIntegerMin(1)`) — any large value committed and was
  handed to the Rust helper, which preallocates ~3×ring_entries UMEM frames
  per binding (~96 MB/binding at ring_entries=8192), so an out-of-range
  value OOM'd at bring-up instead of failing as a clean commit error. The
  leaf now uses `ValidateRingEntries`: bounded `[1..MaxRingEntries]`
  (`MaxRingEntries = 16384`) AND required power-of-two (the helper rounds
  ring sizes up to a power of two, so the configured number stays honest
  about the depth allocated). A matching helper-side backstop clamps at
  bring-up (`afxdp::MAX_RING_ENTRIES`,
  `coordinator/reconcile/bringup.rs`) and rejects out-of-range /
  non-power-of-two values at the `--ring-entries` CLI boundary
  (`server/lifecycle.rs validate_ring_entries_arg`). Go and Rust ceilings
  must stay equal.
- **#1746:** added the `class-of-service schedulers <s>
  equal-flow-target-policy (slowest | mean | ideal-share)` typed enum
  leaf (ValueEnumOf + `ValidateEnum`, same recipe as the scheduler
  `priority` leaf): value-slot completion, flat-set commit-check
  rejection of unknown values, plus a strict-compile re-check
  (`validateClassOfServiceStrict`) for externally-assembled configs.
- **#2458 (Rust fail-closed backstop):** the helper-side
  `EqualFlowTargetPolicy::parse` previously mapped any unrecognized
  wire string to `Slowest` via a catch-all match arm — identically to
  the empty (legacy/unset) string — so a typo or a mixed-version
  snapshot that slipped past the Go gate silently changed queue
  fairness with no failure surfaced. The parse is now fallible: the
  EMPTY string still decodes to the byte-unchanged `Slowest` default,
  but a NON-EMPTY unknown value fails the snapshot CLOSED with
  `SnapshotIntegrityError::CosUnknownEqualFlowTargetPolicy` naming the
  offending forwarding-class and value (preflight keeps the previous
  live CoS state). The Go commit-time gate above stays the PRIMARY
  defense; this is the helper-boundary backstop against version /
  snapshot drift, consistent with the #2447 CoS fail-closed family.
- **#1956 (chassis device-map):** added the bare-metal stable-identity
  managed allowlist under `chassis device-map` (a SIBLING of `cluster`, so
  per-node apply-groups compose). New value types `ValuePCIAddr` /
  `ValueMAC` with `ValidatePCIAddr` (canonical `DDDD:BB:DD.F`) /
  `ValidateMAC` (6-octet unicast, non-zero); a named-instance
  `interface <logical-name>` container using the typed-KEY-slot recipe
  (`keyValueType` + `ValidateDeviceMapLogicalName`) carrying typed `pci` /
  `mac` / `key` leaves; and the `unmapped-interface-policy` enum leaf
  (`leave-alone` default / `manage-down`). Compile lives in
  `compiler_chassis.go` (`compileDeviceMap`), independent of `cluster`
  (`compileChassis` compiles the device-map subtree even with no cluster —
  a standalone box). Cross-entry invariants that a single typed-leaf
  validator cannot express (duplicate logical name / PCI / MAC FATAL,
  RETH-member-must-be-PCI, FPC/node alignment in cluster mode) live in
  `validateDeviceMapStrict`, wired into the strict accumulator group in
  `compiler.go` and DOWNGRADED to a warning on the lenient load / peer-sync
  paths via the `lenientDeviceMap` compile opt (so a peer-node section with
  different hardware does not stall config sync — #1956 V-1). Device-map
  MODE is selected on `len(Entries) > 0`, never `DeviceMap != nil`, so an
  empty `device-map {}` block is positional mode (closes the
  empty-tree-compiles-non-nil trap). The pure identity resolver +
  host-NIC enumeration live in `pkg/devicemap` (shared by the daemon rename
  / pre-flight and the CLI `show`).
- **#2008 (Tier-1.5 schema-hardening sweep):** declared typed children on
  five subtrees whose leaves were fully parsed + compiled + honored at
  runtime but whose `setSchema` node carried `children: nil`, so the gate
  skipped them and an invalid value committed silently:
  - `security log stream transport` — `protocol` (enum `udp|tcp|tls`,
    matching the `pkg/logging/syslog.go` dial switch) + `tls-profile`.
    - **#3350 (tls-profile reject):** `transport tls-profile <name>` is
      parsed/stored but was NEVER resolved into a `*tls.Config` at runtime
      (`daemon_system.go` applyLogStreams passes a nil `*tls.Config`, and
      there is no TLS profile definition stanza — cert / trusted-ca / SNI —
      to resolve it to; only IPsec/IKE define certs). A TLS syslog stream
      therefore silently used the system CA roots instead of the named
      profile — a secure-syslog posture silently downgraded (fail-open). It
      is now REJECTED at commit by `validateSecurityLogStreamTLSProfileAST`
      (compiler.go), the strict-reject + lenient-downgrade (#1960/#3261)
      AST-gate pattern shared with the #3349 stream-port gate (the token
      lives under the `transport` block, a location SchemaValidate cannot
      express, so it is gated in the compiler not setSchema). A plain
      `transport protocol tls` stream that trusts the system CA roots stays
      valid; only the named-but-unapplied profile is rejected. If profile
      resolution is implemented later, build the `*tls.Config` in
      `daemon_system.go` and lift the compiler reject.
  - IKE (`security ike proposal`) and IPsec (`security ipsec proposal`)
    crypto leaves — `authentication-method` (IKE only, enum
    `pre-shared-keys|rsa-signatures|ecdsa-signatures`, matching
    `authMethodToSwan`), `dh-group`, and `lifetime-seconds`
    (`ValidateIntegerMin(1)` — 0/garbage previously silently compiled to
    0). Both `dh-group` leaves use `ValueDHGroup` + `ValidateDHGroup` and
    accept the bare-integer (`14`) and the Junos `group<N>` (`group14`)
    spellings identically (#2639):
    - IKE `dh-group` — the IKE compiler loop (`compiler_ipsec.go`
      `compileIKE`) strips a leading `group` prefix before `strconv.Atoi`.
    - IPsec Phase-2 `dh-group` — the Phase-2 compiler loop (`compileIPsec`)
      ALSO strips the `group` prefix, via the shared `parseDHGroup` helper
      that both loops (and the PFS `keys` stanza) now call. Before #2639
      the Phase-2 loop used a bare `strconv.Atoi` that left `group14` at
      `DHGroup=0`, silently dropping the PFS/modp term from the ESP
      proposal; the schema deliberately rejected the prefixed spelling to
      stay compiler-faithful. The compiler fix makes both gates accept
      `group<N>`, and the shared helper keeps the two sites from drifting
      again. The validator still rejects 0/garbage that would drop the
      modp/ecp term.
    `protocol` and `encryption-algorithm` / `authentication-algorithm` stay
    UNTYPED: the swanctl renderer normalizes arbitrary algorithm spellings
    by string substitution, so an enum there would false-reject valid
    configs.
  - **#2404 (responder-only / dynamic-IP peer):** the `security ike gateway
    <g> dynamic` node now declares a `hostname <fqdn>` child (it was a
    `children: nil` leaf in both the `ike` and `ipsec` stanza copies of the
    gateway schema). The semantics: `dynamic hostname <fqdn>` is a peer with
    a dynamic IP but a resolvable DNS name (renders `remote_addrs = <fqdn>`,
    unchanged); a BARE `dynamic` block — no address, no hostname — marks a
    responder-only peer that dials in from an unknown source address. The
    compiler (`compileIKE` / `compileIPsec`) sets `IPsecGateway.ResponderOnly`
    when the `dynamic` block resolves no hostname; the strict commit-time
    validator (`validateIPsecGatewayReferencesStrict`) accepts such a gateway
    instead of rejecting it as addressless; and the swanctl render
    (`resolveRemoteAddr`, `pkg/ipsec/policy.go`) emits `remote_addrs = %any`
    so strongSwan listens for the inbound IKE rather than skipping the
    connection. `local-address` (or `external-interface`) still pins the
    local endpoint as usual.
  - `security nat static rule-set rule match` — declared the
    `source-address` / `destination-address` children the static-NAT
    compiler reads (the subtree was previously unreachable by the walker).
    #2491 added `match destination-port` as a typed `ValueInteger`
    (1..65535) leaf: it is the external (pre-translation) port a
    port-mapped static-NAT rule matches on. The companion
    `then static-nat prefix <ip> mapped-port <port>` carries the internal
    (post-translation) port. `static-nat` deliberately stays a
    `children: nil` free-form leaf (so `prefix <ip> mapped-port <port>`
    collapses onto ONE leaf node and SetPath grouping is preserved); the
    `mapped-port` token therefore bypasses the schema value validator and
    is range-checked in the compiler (`validateNATHostMaskStrict`,
    `compiler_nat.go`), which ALSO rejects a `mapped-port` with no
    matching `match destination-port` (the reverse SNAT could not recover
    the original port) AND the mirror half-config — a `match
    destination-port` with no `mapped-port` (#2769). The port-match-without-
    mapped-port form is a port-scoped 1:1 (no port translation); rejecting
    it at strict commit-check forces the operator to either drop the port
    match (a whole-address 1:1) or add a `mapped-port` (a port forward). If
    such a rule slips through the lenient load / peer-sync path, the Rust
    dataplane backstop (`static_nat.rs from_snapshots`) keys the reverse
    SNAT on `(internal_ip, Some(match_dst_port))` rather than
    `(internal_ip, None)`, keeping the source translation scoped to the one
    matched port instead of broadening it to every source port on the
    internal host. The snapshot fields `match_destination_port` /
    `mapped_port` (`StaticNATRuleSnapshot`, both Go `omitempty` + Rust
    `#[serde(default)]`, default 0) are an additive, backward-compatible
    wire change; a single external IP can host several per-port mappings
    plus a port-less whole-address 1:1 rule (the dataplane keys the
    static-NAT tables by `(IP, Option<port>)` and falls back to the
    port-less entry).
  - `security nat source/destination rule-set rule match
    destination-address-name <book-entry>` (#3229) — the destination twin
    of the `source-address-name` leaf (#2416). It references an
    `security address-book` address / address-set instead of a literal
    prefix; the snapshot builder
    (`appendNATDestinationAddressName`, `pkg/dataplane/userspace/nat.go`)
    resolves the name through the same address-book expander the policy +
    source-address-name paths use and feeds the resolved prefixes into the
    existing destination list (no new wire field). For DNAT each resolved
    host installs its own exact-host `DnatTable` entry; a non-host prefix is
    stripped to its network address exactly like a literal `match
    destination-address` CIDR. An undefined name is hard-rejected at commit
    (`validateNATSourceAddressNameReferencesStrict`, which gates BOTH the
    source and destination name leaves) and fails closed on the lenient
    load / peer-sync path (the unresolved raw token cannot parse as an IP,
    so the rule matches NOTHING rather than broadening to match-any).
  - `protocols router-advertisement interface` — typed the
    second-denominated leaves (`max/min-advertisement-interval`,
    `default-lifetime`, `link-mtu`; the latter was tightened from
    `ValidateIntegerMin(1)` to `ValidateIntegerMin(1280)` in #2497, see
    below) and declared the remaining compiler-consumed structural children
    (managed/other-stateful-configuration, dns-server-address, prefix
    flags). The per-`prefix` `valid-lifetime` / `preferred-lifetime` leaves
    are typed as non-negative integers (`ValidateIntegerMin(0)`): the
    compiler parses them with a bare `strconv.Atoi` and 0 means "use the
    SLAAC default" (`pkg/ra` clamps `<=0`), so 0 is accepted but garbage
    (e.g. `valid-lifetime abc`, which previously silently became 0) now
    fails at commit.
  - `system syslog host/file/user` — a wildcard `<facility>` child (the
    facility namespace is open-ended) whose value slot is the fixed Junos
    severity vocabulary (`syslogFacilitySeverityLeaf`), so a misspelled
    severity that `ParseSeverity` would silently treat as "no filter" now
    fails at commit; `allow-duplicates` is an explicit presence-only flag.
  Pure schema hardening — no runtime behavior change. Regression coverage:
  `pkg/config/schema_validate_2008_test.go`.
- **#2497 (router-advertisement string/identity leaves):** #2008 typed
  only the RA integer leaves; the five string/identity leaves below were
  still accepted untyped and then silently skipped or mis-advertised by
  the RA sender (`pkg/ra/sender.go buildRA`). Wired at commit:
  - `prefix` — the prefix value is the named-instance identity arg, so it
    uses `keyValidator: ValidateIPv6CIDR` (not the typed-leaf `validator`,
    which would mis-treat the on-link/autonomous flag children as
    modifiers). A typo'd or IPv4 prefix previously committed and the
    sender's `netip.ParsePrefix` error path logged-and-skipped it, so
    hosts got no PrefixInformation option and SLAAC silently broke.
  - `nat-prefix` / `nat64prefix` — `keyValidator: ValidatePREF64CIDR`,
    which reuses `ValidateIPv6CIDR` and then enforces the RFC 8781 §4
    PREF64 length set `{32,40,48,56,64,96}` (the only lengths the 3-bit
    PLC wire field encodes). The `lifetime` child is now
    `ValidateIntegerMin(0)` (was an Atoi-on-error-zero leaf).
  - `preference` — `ValueEnumOf` + `ValidateEnum(high|medium|low)`. A
    typo fell through the sender's `switch` default and silently
    advertised Medium, perturbing host default-router selection.
  - `dns-server-address` — `ValueIPAddress` + `ValidateIPv6Address` (a
    new validator: bare IPv6 literal, IPv4 rejected). The RDNSS option
    (RFC 8106) is IPv6-only; the sender skipped unparseable strings but
    did NOT family-gate, so a valid IPv4 literal reached the wire.
  - `link-mtu` — floor raised to `ValidateIntegerMin(1280)` (RFC 8200 §5
    IPv6 minimum link MTU); a smaller value was advertised verbatim and
    blackholes hosts that honor it.
  Pure schema hardening — no runtime behavior change (the sender's
  parse-and-skip / default paths are now unreachable for committed
  configs). New validators `ValidateIPv6Address` / `ValidatePREF64CIDR`
  live in `schema_validators.go`. Regression coverage:
  `pkg/config/schema_validate_2497_test.go`.
- **#2008 H7 (security log profile):** declared the `security log
  profile <name>` stanza — `stream-name` (`ValueHintStreamName`
  completion), `default-profile` (presence flag), and
  `category session field-extra-name`. Before H7 the whole stanza parsed
  but was silently dropped (no schema child, no compiler case), so a real
  imported config such as `vsrx-ha.conf`'s `profile default-syslog {
  stream-name syslog-container; default-profile; }` committed with no
  validation and no effect. It now compiles to typed `LogConfig.Profiles`
  (`LogProfile{Name, StreamName, DefaultProfile}`) and the compiler
  cross-references `stream-name` against the configured streams
  (`validateLogProfileStreamReferencesStrict`): a profile naming an
  undefined stream is rejected at commit / commit-check (strict) and
  downgraded to a warning on the tolerant load / peer-sync paths
  (`lenientLogProfileStreamRef`, mirroring the IPsec proposal/gateway
  cross-ref gates and the #1960 fail-closed-on-load doctrine). **No
  runtime/dataplane change:** xpf per-stream routing is already a Junos
  superset (every stream whose category/severity filter matches receives
  the event), so a profile's `stream-name` designates the stream that
  carries its events; the `default-profile` flag records the operator's
  default designation and `category field-extra-name` is accepted for
  parity but not yet used to alter the emitted structured-data field set.
  Regression coverage: `pkg/config/log_profile_test.go` +
  `pkg/config/log_profile_schema_test.go`.
- **#3349 (security log stream/top-level field validation):** the remaining
  `security log` leaves were untyped (`children: nil`, no `valueType`), so a
  typo committed cleanly and then silently widened / remapped / fell back at
  runtime — a fail-open for an audit path. Typed as enum/value schema leaves
  (validated by `SchemaValidate`, strict on commit / commit-check, downgraded
  to a warning on the tolerant load / peer-sync paths exactly like every other
  typed leaf): `security log mode` (`stream|event`), `format` and `stream
  <s> format` (`sd-syslog|syslog|binary|structured`), `stream <s> severity`
  (`error|warning|info`, matching `pkg/logging` `ParseSeverity`), `facility`
  (the `ParseFacility` set incl. `local0..7`/`change-log`), `category`
  (`all|session|policy|screen|firewall`, matching `ParseCategory`), and
  `source-address` (`ValueIPAddress`). `source-interface` uses
  `ValidateSyslogSourceInterface`, which rejects a non-numeric `.<unit>`
  suffix (`resolveSourceAddr` silently `Atoi`-fell-back to unit 0, binding the
  wrong source IP). The enum value sets live in `schema_security.go`
  (`syslogLogModes`/`syslogLogFormats`/`syslogSeverities`/`syslogFacilities`/
  `syslogCategories`) and MUST stay in sync with those `pkg/logging` parsers —
  a value the validator allows but the runtime does not recognize would
  reintroduce the silent-fallback bug. **Port** (`stream <s> port` AND the
  nested `host { port }`) is range-checked `[1..65535]` by the
  `validateSecurityLogStreamPortsAST` compiler pass instead of a schema leaf,
  because the value has two AST locations the declarative schema walker cannot
  express — the same dual-location rationale as `tcp-mss`
  (`validateTCPMSSRanges`); strict on commit, `lenientLogStreamPort`-downgraded
  to a warning on load/peer-sync. Before this change a bad port was ignored by
  `compileLog` and silently kept the default 514. No runtime/dataplane change.
  Regression coverage: `pkg/config/log_stream_config_3349_test.go`.

  **Event-mode format compatibility (cross-field).** The top-level
  `security log format` value feeds two different runtimes depending on
  `security log mode`, and they honor different format sets. The schema leaf
  validates the value to a known format in *any* mode; a second compiler pass
  (`validateLogEventModeFormatStrict`, post-compile on `cfg.Security.Log`,
  strict on commit / `lenientLogEventModeFormat`-downgraded on load/peer-sync)
  rejects an event-mode-incompatible format because the event-mode local-file
  writer (`pkg/logging` `LocalLogWriter`, driven by the `ringbuf.go`
  local-writer fanout) only branches on `binary` and otherwise writes standard
  text — so `structured` / `sd-syslog` would validate at commit and then
  silently fall back to text (the exact #3349 failure). Support matrix:

  | `format` | `mode stream` (remote syslog) | `mode event` (local file) |
  |---|---|---|
  | `binary` | binary records | binary records |
  | `structured` | Junos RT_FLOW | **rejected at commit** (silently fell back to text) |
  | `sd-syslog` | RFC 5424 envelope | **rejected at commit** (silently fell back to text) |
  | `syslog` / unset | standard RFC 3164 text | standard RFC 3164 text |

  Event-mode `structured` / `sd-syslog` is a feature gap, not a deliberate
  exclusion — tracked in #3409 (widen the event-honorable set once the
  `LocalLogWriter` implements those formats). The event-honorable set in
  `validateLogEventModeFormatStrict` MUST stay in sync with the `ringbuf.go`
  local-writer fanout.
- **#2008 H9/H10 (interface silent-drop reject):** two interface stanzas
  that parsed-accepted and were silently dropped (no schema child, no
  compiler case, no dataplane consumer) are now hard-rejected at commit /
  commit-check by an AST pre-walk
  (`validateUnsupportedInterfaceStanzasAST`,
  `compiler_interfaces_unsupported.go`):
    - **H9** `interfaces <if> unit <n> family inet|inet6 policer arp
      <name>` — xpf has no per-interface ARP policer (`feature-gaps.md`
      "Interface Policer ... Missing").
    - **H10** `interfaces <if> [unit <n>] mac <addr>` — the interface MAC
      is read-only (cluster RETH MAC is computed deterministically per
      node via `programRethMAC`), so a static override diverges from
      Junos and is unimplemented.
  Unlike H7 these are NOT given schema children — advertising a stanza
  that is rejected would be misleading; the honest contract for an
  unenforceable stanza is a commit rejection. Strict on commit /
  commit-check, downgraded to a warning on the tolerant load / peer-sync
  paths (`lenientUnsupportedInterfaceStanzas`, #1960 fail-closed-on-load
  doctrine) so an older-binary-persisted or peer-synced config that
  silently accepted these stanzas still boots, and an `inactive:` /
  apply-groups-inherited stanza is handled correctly (the walk runs after
  the inactive prune + group expansion). Detection is scoped to the
  `interfaces` stanza so the firewall `policer <name>` definition and the
  chassis `device-map interface ... mac` identity key are untouched. M1
  (`commit persist-groups-inheritance`) stays warn-only — it is a daemon
  no-op knob, not a false dataplane/identity promise — and its real
  implementation is split to /research. Regression coverage:
  `pkg/config/compiler_interfaces_unsupported_test.go`.
- **#3200 (host-inbound-traffic token validation):** `security zones <z>
  host-inbound-traffic { system-services <tok>; protocols <tok>; }` keeps its
  untyped-container schema shape (the leaves stay `children: nil` so flat-set
  grouping and `?` completion are unaffected), but the token VALUE is now
  validated in the compiler by `validateHostInboundTokensStrict`
  (`compiler_validate_strict.go`) against the recognized-token SSOT in
  `host_inbound_tokens.go` (`KnownHostInboundSystemServices` /
  `KnownHostInboundProtocols`). An unknown/typo token is hard-rejected at
  commit / commit-check. This is the SAME doctrine as the IPsec/log/scheduler
  reference validators above — a value the runtime cannot honor is a commit
  rejection rather than a schema enum (an enum would have to be re-derived from
  the dataplane classifier anyway, and the SSOT keeps the nft kernel mirror +
  the Rust AF_XDP classifier in agreement so a committed token never enforces
  inconsistently). Strict on commit, downgraded to a warning on the tolerant
  load / peer-sync paths (`lenientHostInboundTokens`, #1960 no-brick). Matching
  is case-sensitive against the canonical lowercase spellings (the nft matcher
  switch is case-sensitive). Regression coverage:
  `pkg/config/host_inbound_tokens_test.go` (commit reject + accept + lenient
  downgrade) and `pkg/daemon/host_inbound_parity_test.go` (nft-matcher-domain
  == SSOT parity + zero-match-zone fail-closed).
- **#1387 (DHCP dynamic-DNS — live rfc2136 backend):** added an opt-in
  `dynamic-dns` subtree under BOTH `services dhcp-local-server` and
  `services dhcpv6-local-server` (a single shared `config.DHCPDynamicDNSConfig`
  on `DHCPServerConfig`; absent block == nil == today's behaviour). The
  schema tree is built by `dhcpDynamicDNSSchema()` in `schema_system.go`
  and shared by both parents (returned fresh per call so the two parents
  do not alias a mutable map). Typed leaves, validated where the
  reconciler/runtime consume them:
  - `enable` — presence-only flag (turns the reconciler on).
  - `ttl` — `ValueInteger` + `ValidateIntegerMin(1)` (record TTL seconds;
    the runtime defaults an unset/<=0 value to 300 in `policyFromConfig`,
    so the schema enforces only the positive floor).
  - `hostname-source` — `ValueEnumOf` + `ValidateEnum(client-hostname |
    fqdn | mac-fallback)`, matching `deriveFQDN`'s three modes.
  - `conflict-policy` — `ValueEnumOf` + `ValidateEnum(replace-owned |
    skip-existing | strict-fail)`.
  - `backend` — `ValueEnumOf` + `ValidateEnum(rfc2136 | kea-d2)`. `rfc2136`
    is LIVE (#1387 inc-2: the always-on reconcile loop publishes/withdraws
    records over real RFC 2136 UPDATE). `kea-d2` is a RESERVED enum value
    that is NOT implemented (Kea D2 is not in the image); the enum accepts it
    so a config naming it commits, but selecting it warns at commit and
    publishes nothing.
  Deliberately UNTYPED (free-form `args:1` leaves), with reasons in
  `schema_system.go`: `domain`, `update-server`, `tsig-key`,
  `tsig-algorithm`, `tsig-secret`. These are not rejected at the typed-schema
  layer (a hostname / base64 secret is not validatable by the existing
  IP/identifier validators without false-rejecting valid input); instead the
  live rfc2136 backend warn-validates them at commit
  (`validateDDNSBackendWarnings` in `compiler_validate_warn.go`): an enabled
  rfc2136 backend with no/garbage `update-server`, an unsupported
  `tsig-algorithm`, or an incomplete TSIG tuple (`tsig-key` without
  `tsig-secret`, or `tsig-secret` without `tsig-key`) each emit a WARN-only
  commit message (#2666) — never a hard reject, and the backend degrades
  safely at runtime. `tsig-secret` is
  SENSITIVE: it is redacted in `DHCPDynamicDNSConfig.String()` (logging) AND,
  since #2053, by its `config.Secret` field type on every JSON/YAML marshal
  (so the compiled-config dump on `GET /api/v1/config` never leaks it — see
  "Config secret redaction" below). Compile lives in `compileDHCPDynamicDNS`
  (`compiler_services.go`), handling both the hierarchical and flat-set AST
  shapes (walk + first-value-wins, mirroring `collectDeviceMapProps`); an
  empty/garbage block returns nil (positional/disabled, closing the
  empty-tree-compiles-non-nil trap). Regression coverage:
  `pkg/config/compiler_dhcp_ddns_test.go` (dual-AST equality, absent-default,
  TSIG redaction, enum/ttl accept+reject).
- **#2691 P1b (DDNS ScopeKey + independent v4/v6 policy + source binding):**
  three additions to the `dynamic-dns` subtree above.
  - **#2663 — independent v4/v6 policy.** The v4 (`dhcp-local-server`) and v6
    (`dhcpv6-local-server`) blocks now compile to SEPARATE fields —
    `DHCPServerConfig.DynamicDNS` (v4) and `DHCPServerConfig.DynamicDNSv6`
    (v6) — instead of one field-merged struct. Each family keeps its OWN
    `domain` / `update-server` / `tsig-*` / `ttl` / `conflict-policy` /
    source-binding, so v4 leases and v6 leases can target different zones /
    servers / TSIG keys, and a v4 conflict or v4 turn-off never affects v6.
    Backward compatibility: a config that sets the block under only ONE family
    still works — the engine (`ReconcileScoped`) INHERITS that single policy for
    the other family at reconcile time, so committed single-block configs are
    byte-for-byte unchanged; the moment BOTH families set their own block they
    are fully independent. The pre-P1b field-merge (`mergeDHCPDynamicDNS`) is
    retained only as a defensive same-family-block-seen-twice no-op.
  - **#2665 — source / interface / VRF binding** (three new free-form
    `args:1` leaves on the `dynamic-dns` subtree, per family):
    - `source-address <ip>` — bind the RFC 2136 UPDATE socket's source IP.
    - `destination-interface <if>` — pin egress to an interface
      (`SO_BINDTODEVICE`).
    - `routing-instance <name>` — egress from a routing-instance / VRF (binds
      to the VRF master device, which shares the routing-instance name).
    They are free-form (an IP / interface / instance name is not rejected at the
    typed-schema layer) and FAIL-OPEN at runtime: an invalid `source-address`
    makes the live backend fall back to no-op for that family (logged + counted),
    never a hard commit brick — matching the existing `update-server` / `tsig-*`
    posture. The live rfc2136 backend (`pkg/ddns/backend_bind.go`) builds a
    custom `net.Dialer` (a single `Control` hook does `unix.Bind` for the source
    IP and `SO_BINDTODEVICE` for the interface/VRF, so the bind works for both
    the UDP-first and the TCP-retry exchange); a config with no binding leaves
    the default transport unchanged. `destination-interface` wins over
    `routing-instance` for `SO_BINDTODEVICE` (the more specific pin).
  - **ScopeKey (#2663/#2664).** Ownership records now carry a `ScopeKey`
    `{Family, Interface, Unit, RoutingInstance, RGOwner, PolicyID}`
    (`pkg/ddns/state.go`) and are keyed by `{ScopeKey, identity, address}`. The
    ZERO scope reproduces the pre-P1b `identity|address` key byte-for-byte, so a
    pre-P1b ownership store loads with no migration (the `scope` JSON field is a
    pointer, omitted for the global lease scope). This is the load-bearing
    primitive the per-RG HA gate and (future) Surface-A router publish build on.
  Regression coverage: `pkg/config/compiler_dhcp_ddns_test.go`
  (independent-policy, single-family-applies-to-both, source-binding-leaves),
  `pkg/ddns/scope_test.go` (ScopeKey distinctness + pre-P1b round-trip +
  independent v4/v6 + per-RG gate), `pkg/ddns/backend_bind_test.go` (dial
  config), `pkg/daemon/daemon_ddns_scope_test.go` (per-RG resolver + gate).
- **#2691 P2 (Surface A — router/interface-address DDNS):** added the
  operator-facing `system services dynamic-dns` provider catalog + a
  per-interface per-family `dynamic-dns` binding so the firewall can publish its
  OWN learned address (DHCP-lease / static / netlink) as a configured FQDN.
  - **Provider catalog** (`services dynamic-dns provider <name>`, a repeatable
    named instance built by `ddnsServicesSchema()` in `schema_system.go`,
    compiled by `compileDDNSServices`/`compileDDNSProvider` in
    `compiler_system.go` into `config.DDNSServicesConfig`/`DDNSProvider` on
    `System.Services.DynamicDNS`): credentials configured ONCE, referenced by
    scope. Leaves: `backend` (enum: `rfc2136`/`dyndns2`/`duckdns`/`cloudflare`/
    `route53`/`generic` — all live), `update-server`, `tsig-key`,
    `tsig-algorithm`, `tsig-secret` (`config.Secret`-redacted), and the
    `source-address` / `destination-interface` / `routing-instance` transport
    binding (#2665, reused). Plus the engine tunables `forced-refresh` and
    `error-backoff-max` (a Go duration like `24h` OR a bare-seconds integer,
    parsed by `parseDurationSeconds`).
  - **Per-interface binding** (`interfaces <if> unit <n> family <af>
    dynamic-dns`, schema `interfaceDynamicDNSSchema()` in `schema_interfaces.go`,
    compiled by `compileInterfaceDynamicDNS` in `compiler_interfaces.go` into
    `InterfaceUnit.DynamicDNSInet` / `.DynamicDNSInet6`): `provider <name>`
    (catalog reference), `hostname <fqdn>`, `address-source` (enum:
    `interface` default | `dhcp`), `ttl`, and a per-binding `source-address`
    override. v4 and v6 are INDEPENDENT (distinct fields), like the Surface B
    per-family policy split (#2663).
    - **`hostname` is a TYPED leaf (#2779, `ValueHostname` + `ValidateDDNSHostname`).**
      Unlike the DHCP-lease path (where the CLIENT supplies the name and
      sanitizing untrusted input is reasonable), a router-owned Surface A
      hostname is OPERATOR INTENT. The publish path (`surfaceAName` →
      `sanitizeFQDN`) silently lower-cases + strips non-LDH characters + drops
      empty-sanitizing labels, so a name with an underscore / space / `@` /
      non-ASCII char / empty label / leading-or-trailing-dash label would be
      published as a DIFFERENT public DNS name with no error (e.g.
      `wan_1.example.net` → `wan1.example.net`). The validator REJECTS such a
      name at commit, naming the offending hostname, so the operator fixes it.
      ACCEPTED unchanged: LDH labels (`[A-Za-z0-9-]`) joined by single dots,
      with case-folding and a single trailing dot treated as benign DNS
      canonicalization. Contract: every name that passes commit is a fixed
      point of `sanitizeFQDN` (cross-package test
      `pkg/ddns/surface_a_hostname_2779_test.go`).
    - **`source-address` is a TYPED leaf (#2780, `ValueIPAddress` +
      `ValidateIPAddress`, reusing the GRE/tunnel IP-literal validator).** It
      was free-form. The runtime feeds it to `netip.ParseAddr`
      (`pkg/ddns/backend_bind.go` `resolveBindConfig`), where an unparseable
      value is a HARD error: the backend then falls back to a no-op for that
      scope and the binding SILENTLY stops emitting UPDATEs. Typing the leaf
      rejects a non-IP literal at commit (naming the `source-address` leaf)
      instead of committing garbage that disables the scope at runtime. A bare
      IP only (v4 or v6, no prefix length) — matching `netip.ParseAddr`. The
      validator has no family context (the leaf closure receives only the raw
      value), so either family literal commits under either `inet`/`inet6`
      parent; a genuine v4-record / v6-bind family mismatch is left to the
      runtime + Surface A status (not a commit-time gate). Regression coverage:
      `pkg/config/schema_validate_ddns_source_address_2780_test.go`
      (fail-on-revert accept/reject table).
  - **Reuses the pkg/ddns spine** (`pkg/ddns/surface_a.go`,
    `SurfaceAManager`): the SAME `DNSUpdater`/rfc2136 backend (self-ownership —
    no DHCID), the SAME `ScopeKey`, and the SAME durable-state shape (a separate
    file, `interface-ddns-state.json`). The engine adds change-detection,
    forced-refresh (a wire floor), and per-scope error backoff. The per-RG HA
    gate is the SAME one Surface B uses (publish only on the RG master;
    stop-writing-never-withdraw on a partial demotion). Warn-only validation:
    `validateSurfaceADDNSWarnings` (undefined provider, missing hostname,
    rfc2136 provider with no update-server, P3-reserved backend). Observability:
    `show services dynamic-dns [detail]` (CLI + gRPC), the
    `xpf_ddns_surface_a_*` Prometheus family. Regression coverage:
    `pkg/config/compiler_surface_a_ddns_test.go` (flat-set + hierarchical +
    warnings), `pkg/ddns/surface_a_test.go` (change-detect / forced-refresh /
    replace / withdraw / per-RG gate / backoff), and
    `pkg/daemon/daemon_ddns_surface_a_test.go` (scope build + RG attribution +
    gate).
- **#2691 P3 (HTTP provider backends + checkip — completes #2679):** added the
  consumer/SaaS DNS backends behind the SAME `services dynamic-dns provider
  <name>` catalog, so a provider is `backend dyndns2|duckdns|cloudflare|route53|generic`
  instead of `rfc2136`, with per-backend leaves. Every HTTP backend implements
  the SAME `DNSUpdater` interface the rfc2136 backend does — the Surface A engine
  (change-detection, forced-refresh, per-RG HA gate, error backoff) drives them
  identically; only the wire mechanism differs (`pkg/ddns/backend_dyndns2.go`,
  `backend_duckdns.go`, `backend_cloudflare.go`, `backend_route53.go`,
  `backend_generic.go`, the shared `backend_http.go`, the minimal SigV4 signer
  `sigv4.go`).
  - **New provider leaves** (all on `services dynamic-dns provider <name>`,
    schema `ddnsServicesSchema()`, compiled by `compileDDNSProvider` —
    credentials are `config.Secret`-redacted):
    - dyndns2: `server` (endpoint host/URL; a known provider NAME like `no-ip`
      / `dyn` resolves a built-in endpoint), `username`, `password`.
    - duckdns (#2960; its OWN backend, NOT a dyndns2 alias — DuckDNS is not
      dyndns2-protocol-compatible): `api-token` (the DuckDNS token, sent as a
      query param not HTTP Basic), `server` optional (defaults to
      `https://www.duckdns.org/update`). `UpsertLease` ⇒
      `?domains=<label>&token=&ip=`/`&ipv6=`; success on the literal `OK` body
      (`KO` ⇒ hard error); withdraw ⇒ `&clear=true` (removes both A and AAAA).
    - cloudflare: `api-token` (Bearer), `zone` (zone NAME; the zone id is
      resolved at update time).
    - route53: `aws-access-key`, `aws-secret-key`, `aws-region` (default
      us-east-1), `hosted-zone-id` (SigV4-signed `ChangeResourceRecordSets`
      UPSERT/DELETE).
    - generic templated (config-only — no Go code per provider): `url-template`
      (`%h` host, `%i` IP, `%u` user, `%p` pass, `%%` literal; quote the value —
      `?`/`&`/`%` need quoting in a `set` command), `ok-response`
      (success-substring matcher; default good/nochg/ok/true/updated).
    - checkip (opt-in, behind-NAT address source): `checkip-url` +
      `checkip-allowlist` (comma/space bogus addresses to ignore, e.g. the
      embedded `1.1.1.1` in a /cdn-cgi/trace page; a malformed token is no
      longer silently dropped — it warns at commit, naming the token, #2839).
      The per-interface binding's `address-source` enum gains `checkip`.
  - **Security** (plan §8.1): every credential is `config.Secret` (revealed only
    at the transport boundary, never in a URL/error/log; `DDNSProvider.String()`
    redacts all of them); HTTPS with system-trust cert+hostname verification
    (no InsecureSkipVerify); bounded request timeout; capped response body.
  - **Commit warnings** (`validateSurfaceADDNSWarnings`): an incomplete HTTP
    provider (dyndns2 with no server + unknown name, duckdns missing api-token
    (#2960), cloudflare missing
    api-token/zone, route53 missing keys/hosted-zone-id, generic missing
    url-template) warns and publishes nothing at runtime (fail-open, never a
    hard reject). A malformed `checkip-url` (not an http(s) URL with a host —
    e.g. `ftp://`, `not a url`, host-less `http://`) also warns at commit
    (#2773); the scheme check is case-INSENSITIVE per RFC 3986 §3.1, so an
    uppercase/mixed-case `HTTPS://host` is accepted, not warned (#2842). A
    malformed generic `url-template` (no host / wrong scheme) likewise warns at
    commit (#2841, mirror `ddnsGenericURLTemplateValid`) — previously it was
    validated PREFIX-ONLY (a bare `HasPrefix` http(s):// with no host parse), so
    a host-less template committed silently and only failed at the first publish.
    That validator is deliberately TEMPLATE-AWARE and string-based (not
    `net/url`): it extracts the scheme + host and tolerates the inadyn
    `%h/%i/%u/%p` specifiers (including a credential in the userinfo, e.g.
    `https://user:%p@host/upd`, which would make `url.Parse` fail) and `{{...}}`
    placeholders in the rest of the URL — same rationale as `RedactURL` (#2781).
    Both the commit mirror and the runtime gate `TrimSpace` the template before
    validating so they stay byte-for-byte in lockstep (a leading-whitespace
    template must not warn while the runtime trims+accepts it). The malformed
    template is `RedactURL`'d in the warning message (it may carry a credential).
    Without the commit-time check the typo committed silently and the runtime
    fetch then masqueraded forever as a transient observation failure,
    suppressing publishing indefinitely. The runtime `ddns.CheckIP` gate
    (`validateCheckIPURL`) and the generic backend's `validateGenericURLTemplate`
    (in `newGenericBackend`) fail closed on the same malformed URL regardless, so
    a URL that slips past commit cannot reach a fetch. A malformed
    `checkip-allowlist` token (operator typo, e.g. `8.8.8.8x`) also warns at
    commit and NAMES the offending token (#2839); the allowlist is a bogus-IP
    safety gate, so a token that was previously SILENTLY DROPPED shrank the gate
    and let the checkip parser admit the very IP the operator meant to suppress.
    Valid tokens are still retained; the runtime parse
    (`ddns.ParseAllowlistChecked`) mirrors this and fails lenient — it drops the
    bad token, keeps the valid entries, and logs ONCE per `(provider, allowlist)`
    in the surface-A observer (the per-poll-tick path must not flood). The
    commit-warn parse is mirrored in `ddnsAllowlistMalformedTokens`
    (`compiler_validate_warn.go`) because `pkg/ddns` imports `pkg/config`.
    Regression coverage:
    `pkg/config/compiler_p3_http_providers_test.go`,
    `pkg/ddns/backend_http_test.go` / `backend_cloudflare_test.go` /
    `backend_route53_test.go` / `sigv4_test.go` / `checkip_test.go` /
    `surface_a_http_test.go` (mock-server tests through the real backends).
  - **Live-provider verify is the deferred lab gate** (no provider creds/network
    in CI) — the mock-server tests are the merge gate.
- **#2243 (DHCP-server static / fixed / reserved host bindings):** added a
  `static-binding <mac>` named-instance subtree under `services
  dhcp-local-server group <g> pool <p>` AND `services dhcpv6-local-server
  group <g> pool <p>`. The schema tree is built by `dhcpStaticBindingSchema()`
  in `schema_system.go` (returned fresh per call so the v4/v6 parents do not
  alias a mutable map). The instance key is the client hardware (MAC)
  address — `keyValueType: ValueMAC` + `keyValidator: ValidateMAC`, so a
  malformed MAC fails at `?` completion and commit-check. Typed children:
  - `fixed-address` — `ValueIPAddress` + `ValidateIPAddress` (the reserved
    IP the matching client always receives).
  - `host-name` — free-form `args:1` (optional Kea reservation hostname).
  Compile lives in the `static-binding` case of `compileDHCPLocalServer`
  (`compiler_services.go`), handling both AST shapes via
  `namedInstances([]*Node{pp})` (the MAC is `Keys[1]` in flat-set and
  hierarchical alike; the leaves are the instance node's children). It
  populates `DHCPPool.StaticBindings []*DHCPStaticBinding`
  (`types_system.go`). Cross-binding semantics that need the compiled pool
  (subnet) live in `validateDHCPStaticBindingsStrict`
  (`compiler_validate_strict.go`): it rejects a missing/malformed
  fixed-address, a family-mismatched literal (v6 under v4 or vice-versa),
  an address outside the pool subnet (Kea would silently drop it), and a
  duplicate MAC identity or duplicate fixed-address within the same pool.
  **Strict/lenient split (#2243 review, flag `lenientDHCPStaticBindings`):**
  the gate is strict on the commit / commit-check path (`CompileConfig` —
  hard-reject) and downgraded to a `cfg.Warnings` entry on the tolerant
  load / peer-sync paths (`CompileConfigLenient` /
  `CompileConfigForNodeLenient`) so an already-persisted or peer-synced
  config carrying a bad binding still BOOTS (#1960 fail-closed-on-load
  doctrine). It runs AFTER the strict accumulator (mirroring
  `validatePolicyMatchAddressesStrict`), not inside it — the original
  in-accumulator placement hard-rejected the whole tolerant config-load,
  inconsistent with every sibling fail-open validator.
  The Kea renderer (`generateKea4Config`/`generateKea6Config`,
  `pkg/dhcpserver/dhcpserver.go`) emits a per-subnet `reservations` array
  (`hw-address` → `ip-address` for v4; `hw-address` → `ip-addresses[]` for
  v6, plus optional `hostname`). The MAC is canonicalized to Kea's accepted
  colon-lowercase form via `canonicalMAC` (`net.ParseMAC().String()`) at
  both render sites — `ValidateMAC` accepts the Cisco dotted-triplet and
  uppercase, which Kea's hw-address parser rejects, so a clean-committing
  config would otherwise break the Kea reconfigure. Reservations derive
  entirely from the committed config, so an HA pair serving identical
  subnets is reservation-consistent by construction via the existing
  cluster config-sync — no per-lease replication is needed for the static
  case (the dynamic-lease HA gap is the separate companion #2239).
  Regression coverage: `pkg/config/dhcp_static_binding_test.go` (dual-AST
  compile, schema MAC/IP rejection, strict out-of-subnet / duplicate /
  family / missing-address rejection, **strict-reject-vs-lenient-warn
  gate**) and `pkg/dhcpserver/reservations_test.go` (v4 + v6 Kea
  `reservations` render, **dotted/uppercase MAC canonicalization**,
  no-binding omits the key).

### #3043 — Security-policy missing/conflicting terminal action (commit fail-closed)

`PolicyAction`'s zero value is `PolicyPermit` (`types_security.go`:
`PolicyPermit PolicyAction = iota`). `compilePolicy` builds the typed
`Policy` and only mutates `Action` when it sees `then permit` / `then deny`
/ `then reject`; `then log` / `then count` set modifiers only. So a policy
whose `then` stanza carried ONLY modifiers (an audit/drop placeholder such
as `then log session-init`) — or whose terminal action was dropped or
typo'd — compiled with `Action == PolicyPermit` and silently **PERMITTED**
every packet matching its match conditions: a zone-pair-wide silent
fail-OPEN. Symmetrically, a policy that named MORE than one terminal action
(e.g. a group-merged `then permit` + `then deny`) resolved last-wins by
child visitation order rather than failing the commit, so the enforced
action depended on parse order. Junos requires every policy term to specify
exactly one terminal action.

**`validatePolicyTerminalActionStrict`** (`compiler_validate_strict.go`)
restores that fail-CLOSED parity. `compilePolicy` records the terminal
action tokens it sees in the unexported `Policy.terminalActions` slice (the
typed `Config` is never serialized, so the field carries no persistence /
back-compat obligation); the validator requires exactly one such token per
per-zone-pair policy AND per global policy, rejecting zero (no terminal
action) and more than one (conflicting actions). It iterates
`cfg.Security.Policies` then `cfg.Security.GlobalPolicies` in deterministic
order, so the first-reported error is stable.

**Runtime fail-closed default:** `compilePolicy` now defaults an actionless
policy's `Action` to **`PolicyDeny`** (not the `PolicyPermit` zero value).
This makes the tolerant load / HA-sync path safe: a leniently-loaded
actionless policy DENIES rather than fails open. The `PolicyAction` enum
zero value is left unchanged (changing it is invasive and unnecessary once
the actionless policy is explicitly set to deny at compile).

**Strict/lenient split (flag `lenientPolicyTerminalAction`):** strict on the
commit / commit-check path (`CompileConfig` — hard-reject), downgraded to a
`cfg.Warnings` entry on the tolerant load / peer-sync paths
(`CompileConfigLenient` / `CompileConfigForNodeLenient`) so an
already-persisted or peer-synced config that an older binary accepted still
BOOTS (#1960 fail-closed-on-load doctrine) — the runtime default-to-deny
keeps a leniently-loaded actionless policy fail-closed. The gate runs AFTER
`validatePolicyZoneReferencesStrict`, mirroring the sibling fail-open
validators, so a structural error, a bad match-address, and a bad zone
reference still win the first-error slot.
Regression coverage: `pkg/config/policy_terminal_action_3043_test.go`
(`TestPolicyNoTerminalActionFailsCommit` and
`TestGlobalPolicyNoTerminalActionFailsCommit` — fail-on-revert reject
guards, `TestPolicyConflictingTerminalActionsFailsCommit` — last-wins
conflict guard, `TestPolicyNoTerminalActionLenientDefaultsDeny` — lenient
warn + default-to-deny, `TestPolicyExactlyOneTerminalActionCommits` —
positive control).

### #3065 — Unspecified `default-policy` is fail-closed (deny-all) + `reject-all` + schema leaf

The sibling of #3043 for the IMPLICIT fallback. When a flow matches no
zone-pair policy, no global policy, and no explicit term, the verdict is the
*default policy*, held in `SecurityConfig.DefaultPolicy`. Because
`PolicyAction`'s zero value is `PolicyPermit` (`types_security.go`), a config
that omits the `security policies default-policy` stanza compiled to the zero
value and shipped **permit-all** — a silent fail-OPEN that is the opposite of
the Junos SRX `default-security-policy`, which denies all unmatched traffic.
(`compiler_validate_strict.go`'s own comment flagged this.) Two adjacent
gaps: `compilePolicies` (`compiler_security.go`) handled only `permit-all` /
`deny-all`, so the valid Junos `reject-all` fell through the switch and was
silently ignored; and the `default-policy` leaf was absent from
`schema_security.go`, so a misspelled value was accepted unchecked by the
schema walker.

**Fail-closed default:** `CompileConfig` (`compiler.go`) now initializes
`SecurityConfig.DefaultPolicy = PolicyDeny` when it constructs the typed
`Config`. An absent stanza therefore denies unmatched zone-pair traffic
(Junos parity). The `PolicyAction` enum zero value is left unchanged
(matching the #3043 decision) — the default is set explicitly at construction
rather than by flipping `iota`.

**Explicit override:** an operator restores the legacy permit-all behaviour
with `set security policies default-policy permit-all`; `deny-all` and
`reject-all` are the other accepted values, with `reject-all` now mapped to
`PolicyReject` in the `compilePolicies` switch.

**Dataplane plumbing:** the value flows to the userspace dataplane unchanged
via the snapshot string — `policyActionString(cfg.Security.DefaultPolicy)`
(`pkg/dataplane/userspace/builder.go`) → `ConfigSnapshot.DefaultPolicy` →
Rust `parse_action` → `PolicyState.default_action`
(`userspace-dp/src/policy.rs`), which is the no-match verdict. The Rust
struct default was already `Deny`; the Go zero value was overriding it with
`"permit"`, so the Go init is the operative fix.

**Schema leaf:** `default-policy` is a typed `ValueEnumOf` child of
`policies` (`schema_security.go`) validated by
`ValidateEnum([]string{"permit-all","deny-all","reject-all"})`, so a bogus
value (`allow-everything`) fails `commit check` instead of being silently
accepted.

Regression coverage: `pkg/config/compiler_default_policy_3065_test.go`
(`TestDefaultPolicyFailsClosed` — fail-on-revert: unset stanza must compile
to `PolicyDeny`; `TestDefaultPolicyExplicitOverrides` — permit-all/deny-all/
reject-all mapping; `TestDefaultPolicySchemaValidation` — enum accept/reject)
and `pkg/dataplane/userspace/default_policy_3065_test.go`
(`TestSnapshotDefaultPolicyFailsClosed` — the snapshot string the Rust verdict
reads is `"deny"` for an unset config, `"permit"`/`"reject"` for the explicit
overrides).

### #2401 — Security-policy undefined-zone references (commit fail-closed)

A `set security policies from-zone <a> to-zone <b> { policy ... }` stanza
whose `from-zone` or `to-zone` names a security zone the configuration
never defines (a typo, or a zone deleted out from under the policy) was
historically only a `ValidateConfig` **warning** — the commit succeeded.
The rule was compiled and KEPT, but the userspace dataplane resolves the
unknown zone name to no zone-id and so never indexes the rule into its
zone-pair lookup table (`userspace-dp/src/policy.rs` logs `"policy rule
references unknown zone(s) ... (rule kept, but not indexed)"`). At match
time the zone pair has no indexed rule, so evaluation falls through to
`state.default_action`: under a **permit** default this is a silent
fail-OPEN (a deny rule the operator wrote against a mistyped zone does
nothing); under a deny default it blackholes with no operator signal
beyond a stderr line. Junos rejects an undefined zone reference at commit.

**`validatePolicyZoneReferencesStrict`** (`compiler_validate_strict.go`)
restores that fail-CLOSED parity. It hard-rejects any zone-pair policy
whose from/to-zone is not a defined `security zones security-zone` and is
not one of the reserved special tokens **`any`** (Junos wildcard zone),
**`junos-host`** (reserved self-traffic context), or the empty token (see
`policyZoneSpecialTokens`). A global policy's STRUCTURAL from/to-zone is always
the `junos-global` sentinel (mapped only at snapshot-build time), so it never
names an undefined structural zone. As of **#3148** a global policy MAY carry
an optional `match from-zone`/`match to-zone` context (all-zones when absent);
`validatePolicyZoneReferencesStrict` now validates those match zones against the
same special-token + defined-zone gate. The dataplane fails CLOSED for an
undefined global match zone (`GlobalZoneScope::Unresolved` matches nothing) — a
silent never-match rather than a fail-open — but the commit gate rejects it
anyway for operator-visible parity.

**Strict/lenient split (flag `lenientPolicyZoneRefs`):** strict on the
commit / commit-check path (`CompileConfig` — hard-reject), downgraded to
a `cfg.Warnings` entry on the tolerant load / peer-sync paths
(`CompileConfigLenient` / `CompileConfigForNodeLenient`) so an
already-persisted or peer-synced config carrying a stale zone reference
still BOOTS (#1960 fail-closed-on-load doctrine) — the dataplane drops the
unindexed rule on its own, so a leniently-loaded bad config is inert. The
gate runs AFTER `validatePolicyMatchAddressesStrict`, mirroring the sibling
fail-open validators, so a structural CoS/policer/device-map error and a
bad match-address still win the first-error slot.
Regression coverage: `pkg/config/policy_zone_ref_test.go`
(`TestPolicyUndefinedZoneFailsCommit` — the fail-on-revert guard for both
an undefined from-zone and to-zone, `TestPolicySpecialZoneTokensCommit` —
`any`/`junos-host`/global anti-over-reject, `TestPolicyDefinedZonesCommit`,
`TestPolicyUndefinedZoneLenientDowngradesToWarning`).

### #3300 — Dynamic-address `address-name … feed-name` cross-reference gate

A `security dynamic-address address-name <addr> profile feed-name <feed>`
binding records `<feed>` verbatim into `AddressBinding.FeedNames`
(`compileDynamicAddress`, `compiler_services.go`) with no cross-reference
against the configured `feed-server`s. The `feed-name` schema leaf is a
free-form value (`schema_security.go`), so the #2008/#2009 undefined-token
gate does NOT catch a typo. At runtime an unknown feed name resolves to a
non-nil EMPTY prefix set (`feeds.Manager.SnapshotForBindings`, `feeds.go`),
so the AF_XDP address book gets a book ID matching NOTHING — fail-closed,
which is correct for a "declared but not yet fetched" feed but
indistinguishable from a typo. A feed-backed deny policy then silently
denies nothing, with no commit error.

**`validateDynamicAddressFeedReferencesStrict`** (`compiler_validate_strict.go`)
restores Junos commit-time parity: a binding whose `feed-name` resolves to no
declared feed is hard-rejected at commit / commit-check, with a message
naming both the address-name and the unknown feed-name. The valid feed-name
set is computed exactly as `feeds.Manager` keys feeds (`feeds.go` Start): each
`feed-server`'s `feed-name` entries, or — for a single-feed server with no
explicit `feed-name` — the server name itself.

A second gate closes the same fail-open at the feed-server **root**:
**`validateDynamicAddressFeedServerEndpointStrict`** (run just before the
cross-reference gate) hard-rejects a `feed-server` with neither `url` nor
`hostname`. `feeds.Manager.Apply` derives a server's base URL via
`resolveBaseURL` (explicit `url`, else `https://<hostname>`, else `""`) and
SKIPS a server whose base URL is empty — it registers NONE of its feeds. Such
a server still compiles into `DynamicAddress.FeedServers`, so its feed names
are syntactically "declared", but no feed exists at runtime: a bound
address-name resolves to a match-nothing book exactly as a typo'd feed-name
would. Rejecting the endpoint-less server at its root ALSO makes the
cross-reference gate's declared-feed set EXACT — every server it trusts is one
`Apply` would actually register. The gate replicates `resolveBaseURL`'s
emptiness condition (`feedServerBaseURLEmpty`) directly on the `FeedServer`
struct rather than importing `pkg/feeds` (no import cycle), mirroring it
BRANCH-FOR-BRANCH: `resolveBaseURL` prefers `url` and returns
`strings.TrimRight(url, "/")` BEFORE it ever falls back to `hostname`, so a
slash-only `url` (`/`, `//`) trims to `""` and the server is skipped EVEN when
a hostname is also set — a flat `url=="" && hostname==""` check would miss it
(`/` is a valid lexer identifier char, accepted by the schema with no
url-format validation). No whitespace trimming is performed (resolveBaseURL
only `TrimRight`s `"/"`). Keep `feedServerBaseURLEmpty` in sync with
`resolveBaseURL`.

**Strict/lenient split (flag `lenientDynamicAddressFeedRef`, shared by both
gates):** strict on the commit / commit-check path (`CompileConfig` —
hard-reject), downgraded to a `cfg.Warnings` entry on the tolerant load /
peer-sync paths (`CompileConfigLenient` / `CompileConfigForNodeLenient`) so an
already-persisted config (older binaries never validated the reference) or a
peer-synced config still BOOTS (#1960 / #3261 fail-closed-on-load doctrine) —
the runtime stays fail-closed (match-none) for the unknown feed or skipped
server, so a leniently-loaded typo/endpoint-less server denies nothing rather
than bricking. Regression coverage:
`pkg/config/compiler_dynamic_address_feed_ref_3300_test.go`
(`TestValidateDynamicAddressFeedReferences` — the fail-on-revert guard plus
feed-entry / single-feed / server-name positive controls and the lenient
downgrade; `TestValidateDynamicAddressFeedServerEndpoint` — endpoint-less
reject, url / hostname-only positive controls, lenient downgrade).

### #3117 — Security-policy `scheduler-name` schema leaf (completion parity)

A security-policy `scheduler-name <name>` binds a class-of-service scheduler
to the policy. It is compiled — `compiler_security.go`
(`polInst.node.FindChild("scheduler-name")` → `nodeVal`, read for BOTH
zone-pair and global policies) — and an undefined reference is strict-rejected
at commit by `validatePolicySchedulerReferencesStrict`
(`compiler_validate_strict.go`, downgraded to a warning on the tolerant load /
peer-sync paths via `compiler_validate_warn.go`). The leaf was nonetheless
ABSENT from `setSchema`, so `set security policies ... policy <p> scheduler-name`
had no structural / value-slot `?` completion — a violation of the two-SSOT
rule that every compiled + validated leaf is declared in the schema tree.

The fix declares `scheduler-name` under both the zone-pair policy node and the
global policy node in `pkg/config/schema_security.go`, as a sibling of
`description`/`match`/`then`. It is an **untyped (plain string) leaf** like
`description`: the compiler consumes the raw token, and the strict
undefined-scheduler reference check remains the SSOT for rejection (no
`treeValidator` is added, so completion and validation stay in agreement and
no compiler/validator behaviour changes). Regression coverage:
`pkg/config/schema_scheduler_name_3117_test.go` — the leaf is offered by
`CompleteSetPathWithValues` for zone-pair and global policies (fail-on-revert),
and the declared form passes `SchemaValidate` without a false reject.

### #3148 — Global-policy `match from-zone`/`to-zone` zone context

A Junos global policy may carry optional `set security policies global policy
<p> match from-zone <z>` / `match to-zone <z>` so one global policy applies to a
chosen zone pair (or one wildcard side) instead of every zone pair. xpf
previously modeled a global policy as an all-zones fallback only — the context
was unrepresentable, so an imported vSRX policy like "apply this global deny to
all Internet-egress zones but not management" had to be hand-duplicated.

The two leaves are declared **only under the global policy `match` node** in
`pkg/config/schema_security.go` (zone-pair policies take their zones from the
surrounding from-zone/to-zone stanza, so the `match`-level leaves are
global-only — `globalOnlyPolicyMatchLeaves` in `compiler_policy_match.go`
admits them through the #3113 unsupported-leaf gate for global scope and the
gate still rejects them under a zone-pair policy). `compilePolicy` reads them
into `Policy.Match.FromZone`/`.ToZone` (empty = all zones).

On the wire the global policy keeps the `junos-global` sentinel on its
structural from/to-zone (so the dataplane classifier keeps it in the global
tier and preserves global config order) and carries the context on the additive
fields `match_from_zone` / `match_to_zone` (`PolicyRuleSnapshot`,
`omitempty` + `serde(default)` — #1961 additive; the wire fixture
`protocol_wire_v1.json` was regenerated). The dataplane resolves them into a
`GlobalZoneScope` and consults it inside the `junos-global` tier loop, so a
zone-scoped global policy is evaluated in the global ordering (after the exact
zone-pair and the #3090 `from-zone any`/`to-zone any` wildcard tiers), not
promoted ahead of them. An undefined match zone is strict-rejected at commit
(`validatePolicyZoneReferencesStrict`, downgraded to a warning on the tolerant
load path) and independently fails closed in the dataplane
(`GlobalZoneScope::Unresolved` matches nothing).

**Special-token semantics (commit gate ⇔ dataplane parity).** An OMITTED
`from-zone`/`to-zone` and an explicit `match from-zone any` / `to-zone any` are
the SAME thing — the Junos all-zones default. Both commit clean (`any` is a
reserved special token) and `build_global_zone_scope` (policy.rs) short-circuits
`""` and `"any"` to `GlobalZoneScope::Any`; without that short-circuit `"any"`
would route through `resolve_policy_zone_id` → `None` → `Unresolved` and a
`permit` global would silently over-restrict / a `deny` global silently no-op —
a commit-vs-dataplane divergence on a security leaf. The reserved `junos-host`
zone is the one special token that is NOT accepted here: a zone-scoped global
policy is not evaluated on the host-bound (LocalDelivery) path, so
`validatePolicyZoneReferencesStrict` hard-rejects `match from-zone junos-host` /
`to-zone junos-host` at commit (rather than committing a silent never-match);
real junos-host global-zone-context support is a follow-up.

**Zone-local address books in a scoped global (#3287).** A scoped global
(`match from-zone <z>` / `match to-zone <z>`) resolves a zone-local
address-book reference (#3061) against that zone's local book — the same
zone-qualified resolution `resolveZoneLocalAddressBooks` already applied to
zone-pair policies. It rewrites a scoped global's `source-address` tokens under
its `match from-zone` scope and `destination-address` tokens under its `match
to-zone` scope to the `zone-local/<zone>/<name>` qualified entry. Without this,
the bare token kept pointing at the global book (which holds the entry only
under its qualified name), so the constraint silently resolved to match-none and
legitimate zone-scoped global traffic fell through to default-deny (or was
rejected at commit as an undefined address). An UNSCOPED global (empty / `any`
scope) names no single zone-local book and is left to resolve against the global
book. Because the simulator (`pkg/policymatch`) and the dataplane snapshot
builder both consume the post-fold compiled book, this keeps them in agreement.

Regression coverage:
`pkg/config/compiler_policy_global_zone_3148_test.go`,
`pkg/dataplane/userspace/policy_global_zone_3148_test.go`, the Rust
`global_policy_*` tests in `userspace-dp/src/policy_tests.rs`, and
`pkg/policymatch/scoped_global_zonelocal_test.go` (#3287).

### #2391 — Security-zone count cap (commit fail-closed)

Security-zone ids are assigned sequentially `1..N` over the sorted zone names
(`pkg/dataplane/compiler.go`) and reach the live AF_XDP userspace dataplane two
ways: as the per-flow ingress/egress zone in the event-stream wire record (a
**u8** field — `userspace-dp/src/event_stream/codec.rs`, `"[21] IngressZoneID
u8"`) and as the zone-table key in the forwarding snapshot. The forwarding
builder (`userspace-dp/src/afxdp/forwarding_build/zones.rs`) rejects any zone id
`>= ZONE_ID_RESERVED_MIN` (`u16::MAX-1`, reserved for the
`JUNOS_GLOBAL_ZONE_ID` sentinel) and any id `> u8::MAX`. The binding constraint
is therefore the **u8 wire field**, not the reserved sentinel: the usable range
is `[1, min(255, ZONE_ID_RESERVED_MIN-1)] = [1, 255]`, so the cap is
**`MaxUsableZoneID = 255`**. With more than 255 zones the 256th+ ids overflowed
the u8 field, the builder dropped those zones, and every interface referencing a
dropped zone silently collapsed to zone 0 ("unknown") — a silent
fail-open/fail-closed mis-attribution instead of a commit rejection.

**`validateZoneCountStrict`** (`compiler_validate_strict.go`) is the PRIMARY
gate: it hard-rejects any config defining more than `MaxUsableZoneID` security
zones. Bounding `N` at the cap guarantees no out-of-range id is ever produced,
so the dataplane's defense-in-depth skip path is never reached for a clean
commit.

**Rust fail-closed backstop (load-bearing for unknown-name references).**
`populate_interfaces` / `populate_egress`
(`userspace-dp/src/afxdp/forwarding_build/interfaces.rs`) previously resolved a
missing zone NAME to `zone_id == 0` via `unwrap_or(0)`. They now return
`SnapshotIntegrityError::InterfaceUnknownZone` when an interface names a
non-empty zone absent from the zone table, so the snapshot load fails closed
(the apply preflight keeps the previous good state) rather than collapsing the
interface to "unknown". An interface with NO zone (empty string) stays the
legitimate "unzoned" case mapping to 0. This is load-bearing because the Go cap
only bounds the COUNT — it does not catch a version-drifted or hostile snapshot
whose interface references a zone name the snapshot never defines.

**Strict/lenient split (flag `lenientZoneCount`):** strict on the
commit / commit-check path (`CompileConfig` — hard-reject), downgraded to a
`cfg.Warnings` entry on the tolerant load / peer-sync paths
(`CompileConfigLenient` / `CompileConfigForNodeLenient`) so an
already-persisted or peer-synced over-cap config that an older binary accepted
still BOOTS (#1960 fail-closed-on-load doctrine) — the dataplane fails closed on
every overflowing zone, so a leniently-loaded over-cap config is inert (the
overflow zones do not forward). The gate runs AFTER
`validatePolicyZoneReferencesStrict`, mirroring the sibling fail-open
validators, so a structural error and a bad zone reference still win the
first-error slot. Regression coverage: `pkg/config/zone_count_cap_test.go`
(`TestZoneCountOverCapFailsCommit` — fail-on-revert guard,
`TestZoneCountAtCapCommits` — inclusive boundary anti-over-reject,
`TestZoneCountNormalConfigUnaffected`,
`TestZoneCountOverCapLenientDowngradesToWarning`) and the Rust
`interface_pointing_at_skipped_zone_fails_closed`,
`interface_with_unknown_zone_name_fails_closed`,
`interface_with_empty_zone_builds_with_zone_zero` tests in
`userspace-dp/src/afxdp/forwarding_build/tests.rs`.

### #3061 — Zone-local address books

Junos supports a per-zone address book attached inline under the zone, in
addition to the global `security address-book global`:

```
set security zones security-zone trust address-book address web-server 10.0.1.100/32
set security zones security-zone trust address-book address-set servers address web-server
```

The entry grammar is identical to the global book (`address` / `address-set`),
only the attachment point differs (no `global` wrapper). The schema leaf lives
under `security-zone` in `setSchema` (`schema_security.go`); `compileZones`
parses it into `ZoneConfig.AddressBook` via the shared
`parseAddressBookEntries`.

**Resolution order (Junos scoping):** a policy's `match source-address`
resolves against its FROM-zone book first, `match destination-address` against
its TO-zone book first, then both fall back to the global book.
`resolveZoneLocalAddressBooks` (run from `compileExpanded` after the name gate
below) folds every zone-local entry into the global
`SecurityConfig.AddressBook` under a zone-qualified internal name
(`zone-local/<zone>/<name>`) and rewrites each policy match token that resolves
zone-locally to that qualified name. A token NOT defined in the policy's zone
book is left unchanged so it resolves against the global book; when a name
exists in BOTH, the zone-local value WINS.

**Collision-proof synthetic namespace:** the lexer permits `/` in an identifier
token (it is needed for IP-literal VALUES like `10.0.0.0/24`), so without a
guard an operator could name a global address `zone-local/trust/web-server` and
have it silently clobbered by the fold. `validateAddressBookEntryNamesStrict`
(run BEFORE the fold, on the pristine global book) hard-rejects `/` in any
address-book entry NAME (global or zone-local `address`/`address-set`) and any
security-zone NAME at commit — matching Junos object-naming rules — so no
operator name can contain `/` and none can equal a synthetic `zone-local/...`
name. Only the NAME is checked, never the address VALUE/prefix. Strict on
commit / commit-check; the tolerant load / peer-sync path (`lenientAddressBookNames`)
downgrades to a warning (#1960 no-brick), backstopped by the fold's
no-clobber guard (it skips a global-book key that already exists).

After this pass the whole downstream resolution path
(wire snapshot, `nameToID`, `classifyPolicyAddresses`, the strict/warn
validators, the `resolveUserspaceAddressBookEntry` runtime resolver) keeps
operating on a single flat global book.

**Scoping:** a name present only in zone A's book is invisible to a policy in
zone B. If B's policy references it and the global book has no such entry,
`validatePolicyMatchAddressesStrict` (#2008) rejects it at commit, exactly as
Junos treats an undefined reference. NAT rule address-name references
(`source-address-name` etc.) remain global-only; zone-local resolution is
scoped to security-policy match addresses. Regression coverage:
`pkg/dataplane/userspace/zone_local_addressbook_3061_test.go`
(`TestZoneLocalAddressBookResolves` — fail-on-revert resolution guard,
`TestZoneLocalAddressBookScoping` — precedence + cross-zone isolation) and
`pkg/config/addressbook_name_slash_3061_test.go`
(`TestAddressBookGlobalNameSlashRejected`,
`TestAddressBookZoneLocalNameSlashRejected`,
`TestSecurityZoneNameSlashRejected` — collision-safety fail-on-revert guards,
`TestAddressBookNameSlashNormalConfigUnaffected` — prefix-value anti-over-reject,
`TestAddressBookNameSlashLenientDowngrades` — tolerant-path warning).

### #2399 — firewall-filter unknown `then` action + unsupported `from protocol` (commit fail-closed)

Two fail-OPEN behaviors in the firewall-filter compiler, both now rejected
at commit (the firewall-FILTER analog of the #2401 policy fail-closed
pattern). Provenance: codex review-032 findings 032-16 / 032-17.

**(032-16) Unknown `then` action → silent ACCEPT.** A filter term whose
`then` block carries a token that is neither a recognized terminating
action (`accept`/`reject`/`discard`) nor a recognized modifier
(`count`/`log`/`syslog`/`forwarding-class`/`loss-priority`/`dscp`/
`traffic-class`/`policer`/`routing-instance`) was historically DROPPED by
`compileFilterThen` (no default arm). The term's `Action` stayed `""`,
which the dataplane compiler (`pkg/dataplane/compiler_filter.go`) and the
Rust filter (`userspace-dp/src/filter/compiler.rs` `parse_term`) both map
to `FilterAction::Accept` — a term the operator meant to DENY (a misspelled
`then accpet`, or a newer action a peer node understands) silently became a
PERMIT, and commit reported SUCCESS. Junos rejects an unknown filter action
at commit. `compileFilterThen` now records the unrecognized token on
`FirewallFilterTerm.UnknownActions`, and **`validateFilterActionsStrict`**
(`compiler_validate_strict.go`) hard-rejects any term carrying one, naming
the family / filter / term / offending token. Note that an EMPTY action
(`Action == ""`) is the legitimate "no terminating action" case (a term
with only modifiers falls through to the next term) and is NOT flagged.
Two more VALID Junos constructs are recognized so a real config import is
NOT over-rejected: `then reject <message-type>` (the standard ICMP-unreachable
codes plus `tcp-reset`) commits as a plain reject and captures the type on
`FirewallFilterTerm.RejectMessageType` for fidelity — the dataplane acts only
on `FilterAction::Reject` today, so the type is compile-time-only (no wire
field); and `then next term` / `then next` (explicit fall-through) commits as
a no-op, marked `FirewallFilterTerm.NextTerm`. A token after `reject` that is
NOT a known message-type is still a typo and IS flagged.
Defense-in-depth in the Rust filter: a NON-EMPTY unrecognized action (only
reachable via a mixed-version snapshot now that commit rejects it) fails
CLOSED to `Discard`, never `Accept`; the empty string keeps the
fall-through `Accept` semantics.

**(032-17) Unsupported `from protocol` alias → dropped constraint.**
Already handled by #2175 — **`validateFilterProtocolsStrict`** rejects a
`from protocol <token>` that the centralized `appid.ProtocolNumber` SSOT
cannot resolve (a name, a `junos-*` alias, or a 0..255 number). Without the
gate an unresolvable alias was silently dropped from the protocol set, so
the term matched ALL protocols. Documented here for completeness; no new
code in #2399.

**Strict/lenient split (flag `lenientFilterActions`, sibling of
`lenientFilterProtocols`):** strict on the commit / commit-check path
(`CompileConfig` — hard-reject), downgraded to a `cfg.Warnings` entry on
the tolerant load / peer-sync paths (`CompileConfigLenient` /
`CompileConfigForNodeLenient`) so an already-persisted or peer-synced
config carrying an unknown action still BOOTS (#1960 fail-closed-on-load
doctrine). The gate runs immediately after `validateFilterProtocolsStrict`.
Regression coverage: `pkg/config/compiler_filter_action_test.go`
(`TestFilterAction_UnknownAction_RejectsAtCommit` and the
misspelled/inet6 variants — fail-on-revert guards,
`TestFilterAction_ValidActions_Commit` — anti-over-reject across every
terminating action and modifier + a modifier-only fall-through term + the
reject message-types + `next term`, `TestFilterAction_RejectMessageType_-
CommitsAndCaptures`, `TestFilterAction_NextTerm_CommitsAndMarks`,
`TestFilterAction_UnknownRejectMessageType_RejectsAtCommit` — a typo after
reject still rejects, `TestFilterAction_Unknown_LenientWarns`,
`TestFilterAction_CompileCapturesUnknownToken`) and, on the Rust side,
`userspace-dp/src/filter/tests.rs`
(`unknown_nonempty_action_fails_closed_discard`,
`empty_action_falls_through_to_accept`).

### #2545 — firewall-filter `from protocol`/`dscp`/`icmp-type`/`icmp-code` are multi-value (match-ANY)

`protocol`, `dscp`/`traffic-class`, `icmp-type`, and `icmp-code` are all
schema-declared `multi: true` (`schema_cos.go`), and Junos accepts the
match criterion repeated within one `from` block. Historically the typed
term stored them as SCALARS (`Protocol string`, `DSCP string`,
`ICMPType int`, `ICMPCode int`), and `compileFilterFrom` OVERWROTE on each
repeated child — the LAST value won and earlier constraints were silently
dropped. `from protocol tcp; from protocol udp` compiled to
`Protocol == "udp"`, losing the TCP constraint with no commit error.

The typed term now carries SLICES — `Protocols []string`, `DSCPs []string`,
`ICMPTypes []int`, `ICMPCodes []int` (the existing `SourcePorts`/`TCPFlags`
shape) — and `compileFilterFrom` APPENDS every value across both parser AST
shapes (repeated hierarchical children, a bracket list `[ tcp udp ]`, and
repeated flat-set commands), via the `firewallMatchValues` helper. An EMPTY
slice means the criterion is unconstrained (matches any), exactly like the
prior empty-string / `-1` sentinels.

**Wire + dataplane.** `protocol` and `dscp` were ALREADY vectors on the
wire (`FirewallTermSnapshot.Protocols []string` → Rust `protocol_bitmap`;
`DSCPValues WireUint8List` → Rust `dscp_bitmap`) — the chokepoint was only
the Go typed config, which now populates the full set. `icmp-type` /
`icmp-code` were SCALAR on the wire (`*uint8` / `Option<u8>`, exact
equality) and are extended to vectors: `ICMPTypes`/`ICMPCodes`
(`WireUint8List`, JSON `icmp_types`/`icmp_codes`) on the Go side and
`Vec<u8>` → 256-bit `icmp_type_bitmap`/`icmp_code_bitmap` set-membership on
the Rust side (`per_packet_l4_matches`). The wire specimen
`userspace-dp/tests/fixtures/protocol_wire_v1.json` was regenerated for the
field rename. Match semantics: a term matches if the packet's protocol /
dscp / icmp-type / icmp-code is IN the corresponding set (match-ANY within
a field), AND across fields; an empty set leaves the field unconstrained
(the `l4_present` fail-closed gate for icmp on non-first fragments is
preserved). The retired-eBPF `pkg/dataplane/compiler_filter.go` (no longer
the runtime path) keeps the first value of each set so it still compiles.
Regression coverage: `pkg/config/firewall_multivalue_2545_test.go` (both
AST shapes + bracket list, fail-on-revert), the snapshot emit test
`pkg/dataplane/userspace/filters_multivalue_2545_test.go`, and the Rust
matcher `icmp_type_multi_value_matches_any_in_set_2545` /
`icmp_type_empty_set_matches_any_2545`.

### #2622 — firewall-filter `source-port-except` / `destination-port-except` (negated port match)

Junos firewall filters accept the negated port match conditions
`from source-port-except` / `from destination-port-except`: match every
port EXCEPT the listed ones (the inverse of the positive `source-port` /
`destination-port`). xpf previously had no schema leaf, so migrating a
config carrying a port exclusion failed to parse / silently dropped the
condition. The two leaves are added to `schemaFirewall`'s `from` block in
`schema_cos.go` (BOTH `family inet` and `family inet6`), `multi: true` so a
bracketed list `[ 80 443 ]` collapses onto one leaf per #2419.

The typed term carries `SourcePortsExcept []string` /
`DestPortsExcept []string` (`types_system.go`), populated by
`compileFilterFrom` via `firewallMatchValues` (same accumulation as the
positive port slices, both AST shapes).

**Wire + dataplane.** Two additive wire fields on `FirewallTermSnapshot` —
`source_ports_except` / `destination_ports_except` (Go
`pkg/dataplane/userspace/protocol.go`, Rust `protocol/security.rs`,
`serde(default)` for #1961 mixed-version parity). The Rust compiler
(`filter/compiler.rs`) selects ONE port spec list per direction — the
positive list if it carries real entries, otherwise the `-except` list — and
sets a per-direction `source_port_except` / `dest_port_except` inversion flag
on `FilterTerm` (positive wins if both are somehow present). The matcher
`port_match` (`filter/engine/matching.rs`) now evaluates
`matcher.matches(port) XOR except`, mirroring the address `nets_match_v4` /
`nets_match_v6` `except` semantics: an except term whose port list ALL
fails to parse means "match all ports except {}" = match ALL (vs the
positive all-malformed fail-closed = match NOTHING). The wire specimen
`userspace-dp/tests/fixtures/protocol_wire_v1.json` was regenerated for the
two new fields. Regression coverage:
`pkg/config/firewall_port_except_2622_test.go` (hierarchical + flat-set
bracket list + inet6, fail-on-revert) and the Rust matcher
`destination_port_except_negation` / `source_port_except_negation`
(a port IN the except list does NOT match; a port NOT in it DOES —
fail-on-revert). Scope: ports only; `packet-length` from the same
review-039 finding is NOT implemented here.

### #2053 — Config secret redaction at JSON/YAML marshal time

The compiled `*config.Config` carries every operator secret verbatim in
memory (it must — the reconciler/render paths need the cleartext). The
hazard is that a *marshaller* of that struct leaks it. There was a live
leak: `GET /api/v1/config` (`pkg/api/config.go` `configHandler` →
`writeOK(w, store.ActiveConfig())`) JSON-encodes the whole compiled config,
so before #2053 it returned every secret in plaintext to any authorized
REST client (loopback by default, but bindable non-loopback over HTTPS via
`web-management https interface`). The per-struct `String()` redaction
(logging hygiene) did NOT close this — `encoding/json` ignores `Stringer`.

The fix is type-enforced, not by-convention. **`config.Secret`**
(`pkg/config/secret.go`) is a named `string` type whose value-receiver
`MarshalJSON` / `MarshalYAML` emit the sentinel `config.SecretRedacted`
(`<redacted>`) for a non-empty value and `""` for empty (so unset stays
distinguishable). `Reveal()` returns the cleartext for render/reconcile
sites; `String()` redacts for `%v`/`%s`/slog; `UnmarshalJSON` accepts a
plain string but REFUSES the sentinel (fail-closed if a compiled-config
JSON ingest is ever added — none exists today, the SSOT is the `*ConfigTree`
AST). Because the receiver is a value, redaction fires for a `Secret` struct
field, in a `[]Secret` slice (`APIKeys`), and as a map value.

**Converted fields (16):** `IKEPolicy.PSK`, `IPsecVPN.PSK`
(`types_security.go`); `OSPFInterface.AuthKey`, `RIPConfig.AuthKey`,
`ISISConfig.AuthKey`, `ISISInterface.AuthKey`, `BGPNeighbor.AuthPassword`,
`TunnelConfig.WgLocalPrivkeyHex` (`types_routing.go`); `VRRPGroup.AuthKey`
(`types_interfaces.go`); `RootAuthConfig.EncryptedPassword`,
`LoginUser.EncryptedPassword`, `APIAuthUser.Password`, `APIAuthConfig.APIKeys`
(`[]Secret`), `SNMPv3User.AuthPassword`, `SNMPv3User.PrivPassword`,
`DHCPDynamicDNSConfig.TSIGSecret` (`types_system.go`).

**SNMP community string** is a special case: it is the secret AND the
`SNMPConfig.Communities` map key, so `SNMPCommunity.Name` stays a plain
`string` (map lookup in `pkg/snmp` is by the on-wire community string) and
redaction is done with targeted marshallers — `SNMPCommunity.MarshalJSON`
redacts the `Name` field, and `SNMPConfig.MarshalJSON` renders the
`Communities` map as a sorted slice so the secret never leaks as a JSON
object key. Text `show snmp` / `show configuration` print the map key, not
the marshalled struct, and are deliberately OUT OF SCOPE (operators read
their own secrets — Junos parity; `show configuration` redaction is a
separate concern).

**Borderline fields left as plain string** (rulings): `MasterPassword`
(commit-encryption PRF selector, not a user secret), `ArchiveSitesWithPassword`
(URLs whose inline password was already discarded), `SSHKeys` /
`LoginUser.SSHKeys` (public keys). **Round-trip is safe** — nothing
unmarshals a compiled `*config.Config` (persistence/HA-sync ship the AST
tree, not the compiled struct), so a redacting marshaller cannot starve any
consumer. **Adding a new secret config field is one annotation:** type it
`config.Secret` and call `.Reveal()` at the render site (the compiler finds
every reader). Do NOT feed `Reveal()` output into a log line. Regression
coverage: `pkg/config/secret_test.go` (marshal/unmarshal/slice/map/SNMP) and
`pkg/api/config_secret_redaction_test.go` (the live `GET /api/v1/config`
leak net + in-memory-cleartext-preserved render guard).

### #1979 — flow / flow-export NUM_WIDTH commit-time validation (Layer B)

Layer A (#1977, `pkg/dataplane/userspace/flow.go` `buildFlowSnapshot` /
`buildFlowExportSnapshot`) coerces every flow/flow-export wire field into its
Rust `u16`/`u32`/`u64` range at the snapshot boundary so an out-of-range value
cannot abort the `apply_snapshot` decode (the #1961 failure class). Layer B
adds the commit-time companion: reject the bad value at `commit check` with a
clear range error instead of silently coercing it. The bounds equal the
Layer-A caps EXACTLY (a value Layer B accepts is one Layer A leaves unchanged;
a value Layer B rejects is one Layer A would have coerced).

Layer B uses BOTH commit-check validation families, chosen per leaf by whether
the value sits in a single typed slot:

- **Typed `setSchema` leaves (Tiers 1+2 — the declarative `#1319` path):**
  - `services flow-monitoring version9 template <t> flow-active-timeout` /
    `flow-inactive-timeout` — `ValidateInteger(0, maxWireU32)` (Rust u32
    ActiveTimeout/InactiveTimeout). The parallel `version-ipfix` pair is typed
    identically for UX parity even though it does NOT reach the wire
    (`buildFlowExportSnapshot` reads `fm.Version9` only).
  - `security flow tcp-session` expanded to a container: `established-timeout`
    (Rust u64 TCPSessionTimeout), `initial-timeout`, `closing-timeout`,
    `time-wait-timeout` (config-only, not wire-reaching) all
    `ValidateInteger(0, MaxDurationSeconds)` — the Duration-overflow ceiling,
    NOT u64-max. This is the operator-facing reject; it stays in lockstep with
    the runtime saturation backstop `SessionTimeouts::from_seconds` (#2441),
    which converts `secs → ns` with `checked_mul` and saturates at
    `MAX_SESSION_TIMEOUT_NS` (`MAX_SESSION_TIMEOUT_SECS == MaxDurationSeconds ==
    i64::MAX / 1e9`) so an out-of-band snapshot or future caller that bypasses
    this gate can never wrap `secs*1e9` into a tiny premature-expiry timeout;
    plus the
    presence flags `no-syn-check`, `no-syn-check-in-tunnel`,
    `rst-invalidate-session`, and `no-sequence-check` (#2008 M9) declared
    presence-only for completion parity. The presence flags compile into
    `TCPSessionConfig` (NoSynCheck / NoSynCheckInTunnel / RstInvalidateSession
    / NoSequenceCheck) but are typed-config only — the userspace dataplane does
    not read them. The session table is a pure 5-tuple flow entry with no TCP
    state machine and no sequence/window tracking, so there is nothing for any
    of these knobs to enforce or skip. **#2078:** setting any of them emits a
    single accepted-only commit advisory (`pkg/config/compiler.go`,
    `security flow tcp-session ... accepted-only`) so an operator is not
    silently misled; research #2078 converged PLAN-KILL on enforcement.
    The RST design rationale (suppress RST→CLOSED for ESTABLISHED, keep
    `rst-invalidate-session` as the opt-in override) is in
    `docs/active-active-new-connections.md`. The dead legacy `flow_config_map`
    `TCPFlags` write was removed in #2078 (the map was retired with the eBPF
    dataplane, #1373/#1476).
  - `security flow udp-session` / `icmp-session` expanded to a container with a
    typed `timeout` (`ValidateInteger(0, MaxDurationSeconds)`).
  - `security flow aging` expanded from an opaque untyped node (#3440 H2) to a
    container with three typed integer leaves: `early-ageout`
    (`ValidateInteger(0, 86400)`, seconds, 0 = disabled), `high-watermark` and
    `low-watermark` (`ValidateInteger(0, 100)`, percent of max sessions, 0 =
    disabled). The cross-field rule (`low-watermark < high-watermark` when both
    nonzero) and unknown-leaf rejection live in `validateFlowAgingStrict`
    (`compiler_validate_strict.go`, dispatched from `compiler.go` with a
    `lenientFlowAging` no-brick downgrade) because the schema walker is
    single-leaf. **#3440 H1:** watermark aging drives only the Go-side
    conntrack GC hysteresis, which is skipped on the userspace AF_XDP
    dataplane (the only runtime forwarding path), so setting any aging knob
    emits an accepted-only commit advisory (`compiler_validate_warn.go`,
    `security flow aging ... accepted-only`) — typing the schema only stops
    invalid values from persisting, it does not make the knob enforced.
    Per-application `inactivity-timeout` (#3227) is a separate, fully-enforced
    idle-timeout knob and is unaffected.
  - `forwarding-options sampling instance <i> input rate` —
    `ValidateInteger(0, maxWireU32)`. **0 is accepted** (the documented
    `0 = sample all` sentinel, `types_system.go`; Layer A normalizes
    `rate<=0 -> 1`) — EXACT Layer-A agreement, rejecting only the
    decode-aborting `>u32max`.
  - `forwarding-options sampling … output flow-server <addr> port` —
    `ValidateInteger(1, maxWireU16)` (Rust u16 CollectorPort; Layer A skips a
    server whose port is `<1` or `>65535`). `flow-server` keeps `args:1` for
    the collector address and gains a children map (the typed `port` plus the
    other compiler-read children `version9-template`, `version9 { template }`,
    `version-ipfix-template`, `version-ipfix { template }`, `source-address`),
    which deliberately flips a BARE `flow-server <addr>` from single-value
    REPLACE to named-container APPEND — benign: a bare no-port server compiles
    `Port==0` and the snapshot builder skips it, and real multi-collector
    configs already take the container path. The `version9` / `version-ipfix`
    per-server selectors bind the collector to exactly one export protocol
    (Junos semantics, #2136); the live Go exporter routes each flow-server to a
    single version's collector set so a collector configured under both global
    version stanzas is never double-exported (an unbound server resolves to
    IPFIX when both globals are set — see `pkg/flowexport/README.md`).
  - `forwarding-options sampling … family <af> output source-address <addr>`
    (#2605) — the **output-level** flow-export source-address: the standard
    Junos hierarchy where `source-address` is a sibling of `flow-server`
    directly under `output { ... }` (not nested inside a flow-server). It is
    the per-output default that every flow-server in that family inherits.
    A `source-address` nested INSIDE an individual flow-server is the
    per-collector override and **wins** over the output-level default
    (more-specific precedence); both resolve into the single per-family
    `SamplingFamily.SourceAddress`, which `pkg/flowexport` applies as the
    local bind address of every collector in that family. The output-level
    value also seeds `inline-jflow`'s source when inline-jflow sets none. The
    output-level form was previously dropped silently (no compile error and no
    completion entry) — `compileSamplingFamily` only read the
    flow-server-nested / inline-jflow-nested forms before #2605.
  - `forwarding-options allow-dataplane-sleep` (#2008 H13 Stage 1) — a
    presence-only flag (no value, `children: nil`). Previously accepted via the
    no-schema-match fall-through and silently dropped; now a typed leaf that
    compiles into `ForwardingOptionsConfig.AllowDataplaneSleep` and emits an
    accepted-but-unenforced commit warning (the userspace workers busy-poll;
    the idle-yield runtime is Stage 2, lab-gated). Same shape as the
    `security flow power-mode-disable` presence flag.

- **Compiler AST pre-walk (Tier 3 — the `validateVRRPTrackInterfaceAST`
  precedent):** `security flow tcp-mss {ipsec-vpn|gre-in|gre-out|all-tcp}`
  stays OPAQUE in `setSchema` because its MSS value can live in EITHER the
  kind node's flat `Keys[1]` (`gre-in 1400`) OR a hierarchical `mss` sub-child
  (`gre-in { mss 1360; }`) — a dual value-location the declarative walker
  cannot express. `validateTCPMSSRanges` (`compiler_security.go`, wired into
  `compileExpanded` next to the VRRP pre-walk) range-checks the
  COMPILER-SELECTED token via `selectMSSToken` (shared with `parseMSSValue` so
  it can never diverge: `mss` child first, flat fallback) against
  `[0, 65535]`. A mixed shape `gre-in 70000 { mss 1360; }` therefore PASSES
  (the compiler selects the child 1360 and discards the flat 70000).

**Strict vs lenient (boot/HA safety):** Tiers 1+2 get the strict/lenient split
for free (a typed-leaf `SchemaValidate` violation hard-rejects on the strict
commit path and downgrades to a warning on `Store.Load` / `Store.SyncApply`,
`configstore.compileTreeLenient`). Tier 3's `validateTCPMSSRanges` takes a
`lenient` flag (the `lenientTCPMSSRange` `compileOpt`, set by
`CompileConfigLenient` / `CompileConfigForNodeLenient`) exactly like the VRRP
validator: strict commit hard-rejects, but the tolerant load/peer-sync path
WARNS and lets Layer A coerce, so an upgraded node loading a legacy
`tcp-mss gre-in 70000` (a value an older binary accepted) still boots.

Pure commit-time validation — no Layer A / Rust / wire change. Regression
coverage: `pkg/config/schema_validate_flow_numwidth_test.go` (Tiers 1+2 via
`SchemaValidate`), `pkg/config/compiler_tcp_mss_range_test.go` (Tier 3 via
`CompileConfig`, dual-shape + mixed-shape precedence + strict/lenient), and
`pkg/dataplane/userspace/flow_numwidth_agreement_test.go` (the directional
Layer-A agreement property).

### #2079 — NAT pool-utilization-alarm threshold validation

`security nat source pool-utilization-alarm raise-threshold/clear-threshold` is
a Tier-3 compiler-side validation with the standard **strict-vs-lenient** split
(same doctrine as #1979 / tcp-mss). `validatePoolUtilizationAlarm`
(`pkg/config/compiler_nat.go`, invoked from the typed-config phase of
`compileExpanded` in `compiler.go`) requires `0 < clear-threshold <
raise-threshold <= 100`:

- **Strict (`commit` / `commit check`):** a bare `pool-utilization-alarm;`
  (raise=0/clear=0, an always-firing alarm) and inverted/equal thresholds are
  HARD commit errors (Junos itself requires raise > clear).
- **Lenient (`Store.Load` / HA peer-sync — `CompileConfigLenient` /
  `CompileConfigForNodeLenient`, flag `lenientNATPoolAlarmThreshold`):** the
  violation downgrades to a `cfg.Warnings` entry so a node that committed a
  legacy/loose alarm config BEFORE this gate existed still BOOTS after upgrade
  instead of failing closed (#1960 fail-closed-on-compile-failure would
  otherwise brick the daemon on restart). The runtime monitor treats
  `raise-threshold <= 0` as "feature disabled", so a leniently-loaded bad config
  is inert (not always-firing), and the operator's next strict commit rejects it
  loudly.

The thresholds are a single GLOBAL pair (no per-pool override syntax in the
parsed Junos grammar). Regression coverage:
`pkg/config/compiler_nat_pool_alarm_test.go` (strict reject + lenient
accept-with-warning + valid-no-warning). The runtime consumer (#2079) is
documented in `docs/deterministic-nat-cgnat.md`.

NOTE: `pool-utilization-alarm` is not yet a typed `setSchema` leaf (no
config-mode value-slot completion); the validation is compiler-side only. Adding
schema completion is a separate, optional UX follow-up.

### #2173 — static-NAT / NAT64 host-mask validation

Static NAT is strictly host-1:1 and NAT64 source-pool entries are discrete host
source IPs, so the ONLY meaningful mask on a static-NAT match/prefix or a NAT64
pool address is the canonical host mask (`/32` for IPv4, `/128` for IPv6; a bare
address is a host too). #2122/#2123 (PR #2132) made the Rust dataplane TOLERATE
the canonical host mask; PR #2167 then hardened the Rust parser
(`parse_nat_addr` in `userspace-dp/src/nat/static_nat.rs`, `parse_pool_v4` in
`userspace-dp/src/nat64.rs`) to REJECT a non-host mask (`/24`, `/64`, garbage
suffix, ...). The net effect before #2173 was a SILENT dataplane drop: a
misconfigured `/24` match/prefix was parsed-out and the rule was never installed,
with no operator feedback.

`validateNATHostMaskStrict` (`pkg/config/compiler_nat.go`, invoked from the
typed-config phase of `compileExpanded` in `compiler.go`, alongside the other
strict-vs-lenient gates) closes that gap. The host-route rule mirrors the Rust
gate EXACTLY (shared predicate `isHostMaskAddress`):

- **Scope:** static-NAT rules' `match destination-address` (→ snapshot
  `ExternalIP`) and `then static-nat prefix` (→ `InternalIP`) are checked with
  the family-aware `isHostMaskAddress` (matching `parse_nat_addr`). A NAT64
  `rule-set ... source-pool` pool's addresses are checked with the **IPv4-only**
  `isNAT64PoolHostAddress` (matching `parse_pool_v4`, which is `Ipv4Addr`-only):
  the pool translates to IPv4 source addresses, so an IPv6 pool entry — even a
  `/128` — is silently dropped by the dataplane and is rejected at commit too.
  Both predicates classify address family **textually** (`natAddrFamily`: a
  colon means IPv6) to match the Rust `from_str` parsers exactly — Go's
  `net.ParseIP(...).To4()` folds the IPv4-mapped `::ffff:1.2.3.4` form to v4,
  but Rust `Ipv4Addr::from_str` rejects it and `IpAddr::from_str` classifies it
  as V6, so the mapped form is treated as IPv6 here (never accepted as a v4 host
  the dataplane would then silently drop).
- **Exempt:** `then static-nat nptv6-prefix` rules (genuine RFC 6296 prefix
  translation, never host-checked by the Rust parser) and `then static-nat
  inet` rules (a NAT64 translation whose `match` is the well-known prefix, e.g.
  `64:ff9b::/96`, driven by the separate NAT64 snapshot, not the static_nat
  table). NPTv6 prefixes are exempt from the *host-mask* gate (a prefix is
  expected, not a host), but they have their own strict gate
  (`validateNPTv6Strict`, #2240/#2241/#2380): prefix-length equality, supported
  length (`/48` or `/64`), IPv6 family, overlap rejection, and — #2380 — a
  **host-bits-zero** check on BOTH the `match` and `nptv6-prefix` slots.
  `net.ParseCIDR` silently masks the address to the prefix length, so a prefix
  with bits set beyond the prefix length (e.g. `2001:db8:1:2::/48`) would
  otherwise compile as a DIFFERENT prefix (`2001:db8:1::/48`) than the operator
  wrote, with no feedback; the Rust `parse_prefix` (`userspace-dp/src/nptv6.rs`)
  discards the same extra words. Both planes agree on the masked result (no
  traffic-correctness bug), but Junos rejects host bits on a prefix and so does
  the strict gate. `parse_prefix` carries a `debug_assert!` tripwire that aborts
  a debug build if a host-bits-bearing prefix ever reaches the helper (i.e. if
  the Go gate is weakened); release builds keep the historical masking. This
  routes through the SAME strict/lenient `emit` as the other NPTv6 checks: a
  hard commit error under strict, a `cfg.Warnings` entry under
  `CompileConfigLenient` (the helper independently rejects the snapshot and
  keeps the prior live state).
- **Strict (`commit` / `commit check`):** a non-host mask is a HARD commit error
  naming the rule-set, rule, slot, and offending prefix.
- **Lenient (`Store.Load` / HA peer-sync — `CompileConfigLenient` /
  `CompileConfigForNodeLenient`, flag `lenientNATHostMask`):** the violation
  downgrades to a `cfg.Warnings` entry so a node that committed a non-host
  static-NAT mask BEFORE this gate existed (or a peer-synced config) still BOOTS
  after upgrade instead of failing closed (#1960
  fail-closed-on-compile-failure). The dataplane drops the bad entry
  independently, so a leniently-loaded config is already inert for that rule —
  and the operator's next strict commit rejects it loudly.

**#3206 — unparseable static-NAT match/prefix.** The host-mask check above
fires only when the value *parses* as an IP (`parsed && !host`). A
`match destination-address` or `then static-nat prefix` that is NOT a parseable
literal IP/CIDR (an address-book name like `web-server`, or a typo'd prefix like
`10.0.0.300`) therefore skipped both the host-mask and block-pair checks and
fell through to the Rust dataplane, where `parse_nat_prefix`
(`userspace-dp/src/nat/static_nat.rs`) returns `None` and `from_snapshots` does
`continue`, SILENTLY dropping the WHOLE static-NAT mapping with no commit error
or runtime feedback — the operator authored a rule that does not exist at
runtime. `validateNATHostMaskStrict` now rejects an unparseable match/prefix
FIRST (before the block-pair / host-mask checks) via `natStaticPrefixInfo`'s
`parsedIP == false` signal, naming the rule-set, rule, slot, and offending
value. Static NAT takes literal IP/CIDR endpoints, not address-book references.
Strict = hard commit error; lenient = `cfg.Warnings` entry (the Rust
`from_snapshots` drop remains the lenient/peer-sync backstop). Same exemptions
apply (NPTv6, `then static-nat inet`).

Regression coverage: `pkg/config/compiler_nat_host_mask_test.go` (bare/​/32/​/128
accept; v4 + v6 non-host match/prefix reject with asserted message; NPTv6 and
`inet` exemptions; NAT64 source-pool host vs non-host; strict-reject /
lenient-warn / valid-no-warning; `isHostMaskAddress` table; #3206 unparseable
match/prefix reject + parseable host/​block still-compile + lenient-warn). Like
`pool-utilization-alarm`, this is compiler-side only — not yet a typed
`setSchema` leaf.

### #2217 — firewall / application undefined-reference validation

Three firewall/application cross-references compiled cleanly with no operator
feedback and then silently FAILED OPEN at the dataplane. The schema declared the
relevant leaves with `args:1` and no validator, and `ValidateConfig` checked the
neighbouring references (SNAT/DNAT pools, forwarding-class, routing-instance
interface membership) but not these three. Each gap is closed by a strict
commit-time gate in `pkg/config/compiler_validate_strict.go`, invoked from the
typed-config phase of `compileExpanded` (`compiler.go`) alongside the other
strict-vs-lenient gates:

- **Finding A — `then policer <name>` →
  `validateFirewallPolicerReferencesStrict`.** A firewall-filter term whose
  `then policer` names a policer defined under neither `firewall policer` nor
  `firewall three-color-policer` is rejected. Pre-fix the term kept
  `Policer="no-such-policer"` and the rate-limit silently never applied
  (fail-open — the term's traffic passed unpoliced).
- **Finding B — application-set member →
  `validateApplicationSetMembersStrict`.** An `applications application-set
  <set>` member that resolves to neither a defined application (user-defined or
  `junos-*` predefined) nor a defined nested application-set is rejected. It
  reuses `ExpandApplicationSet` — the SAME resolver the compiler already uses —
  so no new definedness table is introduced (it also surfaces the existing
  max-depth-3 nesting bound at commit). Implicit application-sets minted for
  multi-term user applications are skipped (their members are
  compiler-synthesized, not operator references). Pre-fix a policy matching the
  set silently failed to match the intended traffic (the unresolved member never
  matches — an effective no-op term).
- **Finding C — `then routing-instance <name>` (FBF) →
  `validateFirewallRoutingInstanceReferencesStrict`.** A firewall-filter term
  whose filter-based-forwarding steer names a routing-instance not defined under
  `routing-instances` is rejected. Any defined instance is a valid steer target
  (virtual-router / vrf / forwarding alike), so instance-type is intentionally
  not constrained — only the dangling-name case is closed. Pre-fix the FBF
  snapshot carried the unknown name and the dataplane steered matched packets
  toward a routing table that does not exist (silent blackhole / fall-through to
  the default table).

All three walk both filter families (`inet` + `inet6`) / both AST shapes
(hierarchical and flat-set), sorted for a deterministic first-error message.

**Strict (`commit` / `commit check`):** a dangling reference is a HARD commit
error naming the filter/term (or application-set) and the offending name.
**Lenient (`Store.Load` / HA peer-sync — `CompileConfigLenient` /
`CompileConfigForNodeLenient`, flags `lenientFirewallRefs` and
`lenientApplicationSetMembers`):** the violation downgrades to a `cfg.Warnings`
entry so a node that committed a dangling reference BEFORE this gate existed (or
a peer-synced config) still BOOTS after upgrade instead of failing closed (#1960
fail-closed-on-compile-failure). The dataplane behaves exactly as before for the
leniently-loaded reference (term unpoliced / steered to a missing table /
unresolved member dropped), so it is already inert — and the operator's next
strict commit rejects it loudly.

Regression coverage: `pkg/config/compiler_undefined_ref_2217_test.go` (per
finding: undefined-reject in both AST shapes, defined-commits-cleanly,
lenient-warns; plus three-color-policer + `junos-*` predefined + nested-set +
implicit-multi-term-not-false-rejected cases). Like the gates above, these are
compiler-side only — not yet typed `setSchema` leaves.

### #3339 — application / application-set name-collision validation

`compileApplications` (`compiler_applications.go`) collects user applications and
application-sets into two name-keyed maps with **last-write-wins** semantics, and
a multi-term `applications application <X>` additionally MINTS an implicit
application-set under the application's own name
(`apps.ApplicationSets[appName] = implicitSet`). Every one of these writes
silently overwrote a colliding earlier definition with no commit error
(Codex review 080, M07 + M08):

- **Application vs application-set sharing a name (M07).** An explicit
  `applications application-set <X>` silently replaced the implicit set minted
  for a multi-term `applications application <X>` (and, generally, an application
  and an application-set are one flat Junos namespace). A policy referencing `<X>`
  then enforced whichever definition won the map-write race — and the two
  resolvers DISAGREE on which that is: policy expansion
  (`resolveUserspaceApplicationNames`) resolves application-first, while the
  AppID catalog (`addPolicyApps`) resolves application-set-first, so a session
  could be admitted by one definition but cataloged/labeled by the other.
- **Duplicate term-generated application name (M08).** Two `term`s under one
  application generating the same per-term name (`<parent>-<term>`, with a
  protocol suffix only when one term carries multiple protocols) made the later
  `apps.Applications[name] = t` overwrite the earlier while the implicit set
  still listed the duplicate member — ambiguous and silent.
- **Duplicate application / application-set definition** (the same name authored
  twice in one namespace) is also rejected. Such duplicates survive as distinct
  AST siblings only on a hierarchical file parse (the set-command config tree
  merges same-named siblings), but rejecting them keeps the gate honest for
  either representation.

The gate `validateApplicationNameCollisionsAST`
(`pkg/config/compiler_applications_collision.go`) is an **AST pre-walk** run on
the group-expanded, inactive-pruned tree in `compileExpanded` (alongside
`validateUnsupportedInterfaceStanzasAST`), NOT a post-compile check on the typed
`*Config`: by the time the maps are built the colliding definitions have already
been merged away by last-write-wins — only the raw AST still carries every
definition. It aggregates counts across EVERY top-level `applications {}` node (a
hierarchical parse can emit several sibling blocks and `compileExpanded` compiles
all of them), so a collision SPLIT across two `applications {}` blocks is caught
just like one inside a single block — the walk must not stop at the first node.
The predefined `junos-*` table lives outside the AST, so a user
`application junos-http` that merely SHADOWS a predefined application is not a
collision (one AST stanza, no peer) and is left untouched; a multi-term
application minting an implicit set under its own name is likewise not a
self-collision.

**Strict (`commit` / `commit check`):** the first collision is a HARD commit
error naming the offending name. **Lenient (`Store.Load` / HA peer-sync —
`CompileConfigLenient` / `CompileConfigForNodeLenient`, flag
`lenientApplicationNameCollisions`):** the violation downgrades to a
`cfg.Warnings` entry so a node that committed a colliding config BEFORE this gate
existed (or a peer-synced config) still BOOTS after upgrade instead of failing
closed (#1960 / #3261 fail-closed-on-load doctrine); `compileApplications` keeps
producing the same (arbitrary but stable) last-write-wins maps on that path.

Regression coverage: `pkg/config/compiler_applications_collision_3339_test.go`
(app-vs-set collision, implicit-set-overwrite, duplicate application / set
definition, duplicate term-generated name, distinct-names-commit incl. a
predefined shadow, lenient-warns). Compiler-side only — not a typed `setSchema`
leaf (applications stay opaque to `SchemaValidate`).

### #2226 — rib-group `import-rib` undefined-reference validation

`routing-options rib-groups <group> import-rib <rib>` was unvalidated: an
import-rib naming a rib that resolves to no real routing table (a typo, a
non-existent routing-instance, or unparseable garbage) compiled cleanly. At apply
time `resolveRibTable` (`pkg/routing/rules.go`) mapped any unresolvable name to a
bare table **0**. Because a routing-instance's source table is always `>= 100`,
the unresolvable name yielded `targetTable(0) != sourceTable`, which set
`needsLeak` and installed an `ip rule from all lookup <sourceTable> pref 33000`
for a rib that does not exist — a silent mis-leak of the source table into the
main lookup, with no diagnostic. (`ValidateConfig` only ever emitted an
over-limit *warning* for rib-groups; it never checked that an import-rib names a
real rib.)

Two layers close the gap:

- **Commit-time gate (preferred) — `validateRibGroupImportRibReferencesStrict`**
  in `pkg/config/compiler_validate_strict.go`, invoked from `compileExpanded`
  (`compiler.go`) alongside the other strict gates. A valid import-rib names
  `inet.0` / `inet6.0` (the main table) or `"<instance>.inet.0"` /
  `"<instance>.inet6.0"` for a defined routing-instance. Any other name is a HARD
  commit error naming the rib-group and the offending rib. Every defined
  rib-group is validated (not only ones referenced by an instance's
  interface-routes rib-group), mirroring Junos, which rejects an undefined rib
  regardless of whether the group is in use. Rib-groups are iterated in sorted
  order for a deterministic first-error.
- **Runtime backstop — `resolveRibTable` now returns `(tableID int, ok bool)`.**
  The `Apply` `needsLeak` loop treats `ok == false` as "unknown rib": it skips
  the entry (with a `slog.Warn`) and never sets `needsLeak` from it, so no rule
  is installed for a phantom rib and nothing is ever installed into table 0 from
  an unresolved name. This guards any reference that still reaches apply via the
  tolerant load / peer-sync path.

**Strict (`commit` / `commit check`):** a dangling import-rib is a hard commit
error. **Lenient (`Store.Load` / HA peer-sync — `CompileConfigLenient` /
`CompileConfigForNodeLenient`, flag `lenientRibGroupRefs`):** downgraded to a
`cfg.Warnings` entry so a node that committed a dangling import-rib BEFORE this
gate existed (or a peer-synced config) still BOOTS (#1960
fail-closed-on-compile-failure). The runtime backstop keeps a leniently-loaded
reference inert (the phantom rib is skipped, no rule installed), matching the
post-fix behaviour, and the operator's next strict commit rejects it loudly.

Regression coverage: `pkg/config/compiler_ribgroup_ref_2226_test.go`
(undefined-reject in both AST shapes, garbage-token reject, defined-ribs +
inet6-ribs commit cleanly, lenient-warns) and `pkg/routing/rules_test.go`
(`TestRibGroupRulesApply_UnknownRibNoLeak` — an all-unknown rib-group installs
ZERO rules; `TestRibGroupRulesApply_DefinedRibStillLeaks` — a defined rib still
leaks correctly). Like the gates above, this is compiler-side only — not yet a
typed `setSchema` leaf.

## The `inactive:` universal node modifier (#2008 H1)

`inactive:` is the Junos deactivate-without-delete marker and is NOT a
schema leaf — it is a UNIVERSAL node modifier that can prefix ANY statement
at ANY position, so it lives OUTSIDE `setSchema` entirely. The parser
(`parser.go`) recognizes a leading `inactive:` token, lifts it into
`Node.Inactive`, and leaves the node's real `Keys` intact. Because the
modifier never appears in the node's identity, the `setSchema` walk, the
flat-set token grouping, and the value-slot `?` completion are all
unaffected — they continue to see the node's real keyword.

**Strip-before-validate / strip-before-compile contract.** A deactivated
statement must be excluded from BOTH the typed-leaf gate and the compiler,
and Junos accepts a deactivated leaf even when its value would be rejected
if active (it parks work-in-progress). The single centralized strip,
`ConfigTree.WithoutInactive` (`pkg/config/inactive.go`), prunes inactive
subtrees and runs at two coordinated entry points:

1. `SchemaValidateWithDefinitions` (`schema_walk.go`) strips both the tree
   and the cross-reference `defsSource` BEFORE the typed-leaf walk, so a
   deactivated typed leaf with a deliberately-invalid value does not fail
   `commit check`, and a deactivated definition neither satisfies an active
   reference nor is itself validated.
2. The commit-check / schema gate in `configstore`
   (`schemaValidateExpandedTreeForNode`, `store.go`) strips inactive
   subtrees BEFORE group expansion, mirroring the compile path. This matters
   because `ExpandGroups` (`ast_groups.go`) collects every `apply-groups`
   node by name WITHOUT checking `Inactive`: stripping only inside
   `SchemaValidateWithDefinitions` (which runs AFTER expansion) would let an
   `inactive: apply-groups missing` still fail commit-check as an undefined
   group, and an `inactive: apply-groups g` still schema-validate inherited
   content the compiler will never apply. Strip → expand → validate now
   holds everywhere a tree is compiled OR schema-validated.
3. Both `compileConfig*` entry points (`compiler.go`) strip FIRST — before
   the pre-expansion tunnel-id collision gate, group expansion, and section
   compilation — so `inactive: apply-groups foo` suppresses the inherited
   config, inactive nodes inside `groups {}` bodies are pruned, and the
   ~15 compiler files never observe an inactive node. Centralizing the
   strip in the shared node-aware `compileConfigForNodeWithOpts` guarantees
   BOTH cluster nodes compile the identical active set from the same
   JSON-synced (`Inactive`-flag-carrying) tree — no split-brain posture.

Strip only REMOVES nodes from the compiled set, but that is NOT a guarantee
that a previously-compiling config stays compilable: deactivating a
*referenced definition* (an address-book entry a policy still matches, a
group an active `apply-groups` still applies, a scheduler a scheduler-map
still names, etc.) can leave that active reference dangling and surface a
dangling-reference commit error. That behavior is correct and expected —
deactivating an object an active statement depends on is operator intent,
and the schema gate deliberately enforces it for schema cross-references and
policy address references (the active reference is validated against the
stripped definitions, so a deactivated definition no longer satisfies it).
`WithoutInactive` is a clone-free no-op when nothing is deactivated, so the
all-active path is unchanged. Regression coverage:
`pkg/config/inactive_test.go`, `pkg/configstore/inactive_test.go`.

**Round-trippable `deactivate` / `activate`.** `show | display set` emits a
`deactivate <path>` line after each inactive node's `set` line(s)
(`ast_format.go`). `ParseSetVerb` (`parser.go`) recognizes `deactivate` and
`activate` as real verbs alongside `set` / `delete`, and the configstore
replay paths (`LoadSet`, `LoadMerge`, and the hierarchical
`FormatSet`-replay inside `LoadMerge`) apply them via
`ConfigTree.DeactivatePath` / `ActivatePath` (`ast_edit.go`). So display-set
output round-trips: an inactive node reloads inactive rather than being
skipped (and silently reactivated) or parsed as a junk path beginning
"deactivate".

**Interactive `activate` / `deactivate` config-mode verbs (#2051).** The two
verbs are first-class config-mode edits on all four surfaces. The store
exposes `DeactivateFromInput` / `ActivateFromInput` (`configstore/store.go`),
thin wrappers that prepend the verb and route through the same
`applyEditLine` switch the replay paths use, so the verb logic lives in one
place. Local CLI (`cli_dispatch.go`) and remote CLI (`cmd/cli/shared.go`
`dispatchConfig`) dispatch the verbs; the remote CLI rides the gRPC `Set` RPC
with the verb kept as the input prefix, and `Server.Set`
(`grpcapi/server_config.go`) prefix-routes `deactivate `/`activate ` to the
store wrappers BEFORE the `SetFromInput` fall-through — otherwise the
fall-through would parse `set deactivate <path>` and create a junk node named
"deactivate". REST exposes `POST /api/v1/config/deactivate` and
`/config/activate`. Path completion has schema parity with `delete` (paths to
existing nodes via `CompleteSetPathWithValues`); cmdtree lists both verbs in
`ConfigTopLevel`.

**`load set` is a real service-mode op (#2052).** `load set` now works on the
remote CLI, gRPC, and REST (previously local-CLI-only) via
`LoadRequest.mode == "set"` → `store.LoadSet`. The applied-count is logged
(no response field). This makes `show | display set` output — including the
`deactivate <path>` lines above — round-trippable through every service
surface.

### #2447 — class-of-service DSCP/802.1p code-points are domain-validated at commit

`class-of-service` classifier (and DSCP rewrite-rule) code-points are now
range-checked at commit, not silently aliased into a different traffic class.

- **DSCP** (`classifiers dscp ...`, `rewrite-rules dscp ...`) — domain `0..63`
  (the 6-bit DiffServ field). A symbolic alias (`be`, `ef`, `af11`, `cs6`, …)
  resolves through `coSDSCPValues`; a numeric token outside `0..63` is a
  **commit error** (`compileClassOfService`, `expandCoSCodePointToken` in
  `pkg/config/compiler_class_of_service.go`).
- **802.1p / IEEE 802.1** (`classifiers ieee-802.1 ...`) — domain `0..7` (the
  3-bit PCP field). A numeric token outside `0..7` is a **commit error**
  (`collectCoS8021CodePoints`).

Before #2447 these were **silently dropped** at the Go parse layer (no commit
error) and, on a version/snapshot-drifted helper, the dataplane builder masked
`dscp & 0x3f` / clamped `pcp.min(7)` — so a configured DSCP 110 installed a
classifier for DSCP 46 (a DIFFERENT class) and PCP 9 installed one for PCP 7,
with no failure surfaced. A non-numeric, non-alias token (a typo) is still
skipped (not an error), preserving Junos-compatibility for unknown spellings.

The Rust forwarding-build is the second trust boundary: an out-of-range
code-point reaching `build_cos_dscp_queue_table` / `build_cos_ieee8021_queue_table`
fails the snapshot CLOSED (`SnapshotIntegrityError::CosDscpCodePointOutOfRange`
/ `CosIeee8021CodePointOutOfRange`) — the apply preflight keeps the previous
live CoS state rather than building a classifier for the wrong class. This is
the same fail-closed posture as #2410/#2696/#2713 (queue id, scheduler-map
class, interface MTU). Runtime packet-field masking is retained where it
belongs: `resolve_cos_dscp_classifier_queue_id` / `resolve_cos_ieee8021_classifier_queue_id`
(`tx/cos_classify.rs`) still mask the LIVE packet's DSCP/PCP to index the
fixed-size table — the table is now built only from validated indices, so the
mask just bounds the physically-limited wire field, it no longer aliases config.

### #2448 — static-route destination + next-hop typed at commit

`routing-options static route <destination>` and its `next-hop <gateway>`
child are now typed so a malformed prefix or gateway fails the commit instead
of installing silently and then vanishing from the dataplane.

- **destination** — the `route` identity arg uses `keyValidator:
  ValidateRouteDestination` (`keyValueType: ValueCIDR`), a family-agnostic
  CIDR with a REQUIRED `/prefix-length`. The default routes `0.0.0.0/0` and
  `::/0` parse via `net.ParseCIDR` and are accepted; a bare IP (no length), an
  out-of-range mask (`/99`), or outright garbage is a commit error. v4 and v6
  both pass because a static block holds either family.
- **next-hop** — the `next-hop` gateway uses `keyValidator:
  ValidateStaticNextHop` (`keyValueType: ValueIPAddress`). next-hop is modeled
  as a CONTAINER node (like `qualified-next-hop`), NOT a typed value-leaf, so
  the gateway is validated through the identity-arg keyValidator while the
  optional `interface <iface>` CHILD still walks as a normal value-bearing
  child. This matters: the compiler accepts an EXPLICIT egress interface on a
  plain next-hop (for IPv6 link-local gateways) in BOTH the hierarchical
  `next-hop fe80::50 { interface reth0.50; }` and the flat/inline
  `next-hop fe80::50 interface reth0.50` shapes (compiler_routing.go). A
  typed value-leaf would route the `interface` child through the presence-only
  modifier path and reject the value token after `interface` as `unknown
  modifier` — the #2448 over-rejection regression caught in review. Accepted
  gateway values: a bare IPv4/IPv6 address (the FRR renderer emits it
  verbatim, the Rust FIB parses it), a bare interface name (`ge-0-0-0.0`,
  `reth0.50`, `eth1` — a valid Junos interface next-hop that FRR renders as an
  interface route), and the Rust-FIB `ip@interface` / `@interface` spec (the
  Junos lexer rejects `@`, so this form reaches only a programmatic caller,
  but the validator classifies it correctly: the IP part, when present, must
  parse, else the spec silently degrades to interface-only). Rejected: a
  botched IP literal (`1.2.3.999`, `2001:db8::garbage`), an `ip@iface` whose
  IP part does not parse, and any value that is neither a valid IP nor a
  plausible interface name (`[A-Za-z0-9._-]`, at least one ASCII letter so a
  numeric-only dotted token cannot masquerade as a name). The gateway is still
  validated when an explicit `interface` is present — the keyValidator runs on
  the gateway identity arg regardless of the child.
- **what is NOT rejected** — a plain `next-hop <ip> interface <iface>` (the
  link-local form above, both shapes); `discard` / `reject` / `next-table` /
  `qualified-next-hop ... interface ...` are declared children of the `route`
  node, so a no-next-hop blackhole/leak route and the link-local-IPv6
  qualified-next-hop form still commit. `preference` is likewise declared.

Before #2448 both leaves were accepted untyped: the Rust FIB builder
(`userspace-dp forwarding_build/fib.rs populate_routes`) soft-skips a
destination that parses as neither v4 nor v6 (no error, no counter), and the
next-hop resolver falls back to ifindex 0 / interface-only on an unparseable
spec — so an operator typo committed cleanly and then either never installed
or installed a blackhole, with no signal. The SSOT is `staticRouteNode()` in
`schema_routing.go`, shared by the `routing-options`, per-`rib`, and
`routing-instances` static blocks. Regression + fail-on-revert tests:
`pkg/config/schema_validate_route_2448_test.go`.

### #2978 — BGP `multipath ibgp` (iBGP ECMP / `maximum-paths ibgp`)

`set protocols bgp multipath ibgp` enables iBGP equal-cost multipath. FRR's
`maximum-paths N` line (rendered from the existing `protocols bgp multipath`
knob, `BGPConfig.Multipath`) applies ONLY to eBGP-learned routes — iBGP
multipath requires the SEPARATE `maximum-paths ibgp N` command. Without it FRR
installs a single best-path for any iBGP-learned prefix, so ECMP is silently
disabled for iBGP routes in redundant leaf-spine / route-reflector topologies
(agy-review-057 finding 057-04).

- **schema** — `multipath ibgp` is a flag child of the `protocols bgp
  multipath` node (`schema_routing.go`), a sibling of the existing
  `multiple-as`, mirroring its shape.
- **typed field** — `BGPConfig.MultipathIBGP bool` (`types_routing.go`); the
  compiler (`compiler_protocols.go`) sets it from the `ibgp` child the same way
  it sets `MultipathMultipleAS` from `multiple-as`. The count comes from the
  same `Multipath` value (default 64 when `multipath` is present).
- **render** — when `bgpMaxPaths > 1` AND `MultipathIBGP` is set, the BGP
  address-family blocks (`policy_render.go`, both ipv4 and ipv6 unicast) emit
  `maximum-paths ibgp <n>` directly after the existing eBGP `maximum-paths
  <n>` line. Without the flag the render is byte-identical to pre-#2978
  (eBGP-only), so existing configs are unaffected.
- **tests** — parse: `TestBGPMultipathIBGPSetSyntax` (`parser_routing_test.go`);
  render fail-on-revert: `TestGenerateProtocols_BGPMultipathIBGP` +
  `TestGenerateProtocols_BGPMultipathNoIBGP` (`frr_test.go`).

### #2823 — Source-NAT pool `persistent-nat permit` three-way enum

Junos `persistent-nat permit` is a three-way enum
(`any-remote-host | target-host | target-host-port`), not a binary flag. The
pre-#2823 model parsed only `permit any-remote-host` into a
`PermitAnyRemoteHost bool`, so `target-host` (remote-IP-only lease scope) was
unreachable, and the source-NAT `pool <name>` node carried NO schema body — the
whole pool stanza (address, port, persistent-nat) was unmodeled, so
`set ... persistent-nat permit target-host?` neither completed nor validated.

- **schema** — the `pool` node under `security nat source`
  (`schema_security.go`) gains a `children` map (it is a real container, so the
  SetPath replace-vs-container decision is unaffected — trailing tokens always
  descend, and a bare `pool <name>` still emits a leaf). The `persistent-nat`
  subtree declares `permit` as a `ValueEnumOf` + `ValidateEnum(any-remote-host
  | target-host | target-host-port)` typed leaf (same recipe as
  `default-policy`) and `inactivity-timeout` as a `ValueInteger` +
  `ValidateInteger(1,86400)` leaf. Other pool leaves (address/port/host) stay
  unmodeled and are left to the compiler per the opt-in-gate contract
  (`schema_walk.go`: unknown keywords return nil, never reject).
- **typed field** — `PersistentNATConfig.Permit PersistentNATPermit`
  (`types_security.go`) replaces the `PermitAnyRemoteHost bool`. The default
  (persistent-nat configured with no `permit`) is `target-host-port`, the
  byte-identical equivalent of the pre-#2823/#2819 false-flag `(dst_ip,
  dst_port)` keying. The parser (`compiler_nat.go`) accepts all three values in
  BOTH the flat-set (Keys) and hierarchical (Children) AST shapes.
- **wire** — `SourceNATRuleSnapshot.PersistentNATPermit` (string,
  `persistent_nat_permit`) carries the enum to the helper; the legacy
  `persistent_nat_permit_any_remote_host` bool is still emitted for skew
  against an older helper, which falls back to it. Additive — the only
  `protocol_wire_v1.json` change is the new key.
- **lease keying** (Rust, `userspace-dp/src/nat/source.rs`,
  `PersistentNatPermit`) — `any-remote-host`→`remote=None` (source-tuple-only),
  `target-host`→`remote=Some((dst_ip,0))` (port dropped, new remote port on the
  same host reuses), `target-host-port`→`remote=Some((dst_ip,dst_port))`.
- **tests** — Go parse/default/schema:
  `pkg/config/compiler_nat_persistent_permit_test.go`. Rust per-mode reuse
  fail-on-revert: `pool_snat_persistent_target_host_reuses_across_remote_ports`,
  `pool_snat_persistent_target_host_port_distinct_per_remote_port`,
  `pool_snat_persistent_any_remote_host_reuses_everywhere`,
  `pool_snat_persistent_permit_empty_string_falls_back_to_legacy_bool`
  (`userspace-dp/src/nat/tests.rs`).
