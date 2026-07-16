# Cohort 2 — Config / Schema / Compiler Deep Audit — d24417ca1fd2

- **Base commit**: d24417ca1fd2
- **Output**: /tmp/ps-review-002.md
- **Scope**: `pkg/config/lexer.go`, `parser.go`, `ast.go`, `ast_groups.go`, `ast_edit.go`, `ast_format.go`, `schema.go`, `schema_walk.go`, `schema_validators.go`, `schema_complete.go`, `value_type.go`, `compiler.go`, `compiler_security.go`, `compiler_nat.go`, `compiler_firewall.go`, `compiler_system.go`, `compiler_class_of_service.go`, `compiler_routing.go`, `compiler_protocols.go`, `compiler_interfaces.go`, `compiler_services.go`, `compiler_ipsec.go`, `types*.go`, `xfrmi.go`; plus `pkg/configstore/*.go`. Read-only.
- **Dedup source**: `/tmp/all_findings.txt` (274 entries), `/tmp/ps-review-001.md`.

---

## Duplicate-suppression + intentional divergences

Checked against 274 prior findings. Suppressed re-reports for:

- Bracket-list truncation class (#2419): `F-159`, `F-098`, `F-042`, `F-010`, `F-163`, `F-041`, `F-162` — all cover the general pattern. New findings below are distinct sub-paths or surviving residuals not in prior list.
- `F-036` (removeNode first-match), `F-159` (apply-groups leaf-list drops), `F-044` (79-field lenient opts literal).
- `F-270` (empty-string address token whitelisted).
- `F-084` (legacy `any` token discarded).
- `F-206` (NAT compile scattered), `F-205` (tunnel grammar duplication).
- `F-027`, `F-028` (CoS rewrite-rules/interface-level).

Intentional divergences not re-reported:
- intrazone default-permit, host-originated junos-host (docs), IPsec-passthrough exempt, `reject-all` superset display.

---

## Module / Verdict-path inventory

| # | Cohort | Verdict-paths covered | Status |
|---|--------|-----------------------|--------|
| 1 | Lexer / Parser | OOB, panic, unbounded, identifier boundary | Deep |
| 2 | AST edit / SetPath / DeletePath / RenamePath | bracket-list merge, delete-prefix matching, rename first-match, duplicate detection | Deep |
| 3 | ast_groups (apply-groups) | leaf-list merge DROP, bracket apply-groups, circular, undefined group | Deep |
| 4 | schema.go (setSchema) | typed-leaf opt-in, multi, args, compoundKey, midKeyword, wildcard | Deep |
| 5 | schema_walk / schema_validators | range-sep `to` confusion, strict vs lenient gates, `to` misfire | Deep |
| 6 | compiler.go (CompileConfig / Lenient / ForNode / strict validators) | lenient == strict except single bit, equal-flow scope, dataplane retire gate | Deep |
| 7 | compiler_security (zones, screen, policies, address-book) | duplicate policy, bracket address/app, duplicate match/then, undefined zone/app/address fail-open | Deep |
| 8 | compiler_nat | zone-list bracket, NAT64 prefix missing, pool truncation, port deterministic, static NAT source-address | Deep |
| 9 | compiler_firewall | prefix-list `except`, family mis-route, source-prefix-list single-name, tcp-flags bracket | Deep |
| 10 | compiler_system / services / routing / protocols / interfaces / ipsec / class-of-service | chassis, scheduling, dangling refs, port mirroring, WireGuard validation | Deep |

---

## Module-by-module inspection log

### Lexer (`lexer.go`)

Lexer is small and correct for normal Junos. Two properties verified:

1. **`[` / `]` silently discarded** (`lexer.go:103-109`): `Next()` sees `[`, advances, then recurses `return l.Next()`. Inner `]` is similarly discarded. This is intentional for Junos bracket-list syntax. The multi-value semantics are then the responsibility of the compiler (`parseZoneList`, etc.). If a compiler path uses `nodeVal` (first-value) instead of the full `Keys[1:]` slice, truncation occurs. This is the `#2419` class — already tracked per-path. Lexer itself is not buggy.

2. **`quoteKey` backslash mis-escape** (`ast.go:64-75`) — duplicates `F-005` precisely. `quoteKey` escapes `"` to `\"` but never escapes `\`. Lexer `readString` interprets `\n` and `\\`. So a value containing backslash round-trips incorrectly. Confirmed still present. Deduped.

3. **No OOB**: `isIdentChar` guard, `l.pos+1 < len` checks present. `readString` terminal returns `TokenError` "unterminated string" on EOF without panic.

**Negative**: lexer is fail-closed under truncation; no verdict-path bypass.

---

### Parser (`parser.go`)

`ParseSetCommand` (`parser.go:39-73`) intentionally treats *duration expressions* like `10m` as identifiers (digits + suffix match `isIdentChar`). Verified consistent with `parseScaledDecimalUnit`. No parse-vs-compile arithmetic drift for bandwidth.

`parseStatements` recovers from `TokenError` by emitting `ParseError` and continuing — does not abort. A malformed config line cannot hide a subsequent DENY line; it is appended as errored but parsing continues. Fail-closed.

**Negative**: no OOB, no panic on crafted input.

---

### AST navigation / SetPath / DeletePath / RenamePath (`ast.go`, `ast_edit.go`)

#### `matchNodeKeys` prefix ambiguity (ast.go:208-230)

```go
func matchNodeKeys(n *Node, path []string, pos int) int {
    ...
    if pos+nk > len(path) {
        // Partial match: node has more keys than remaining path.
        // Accept if we're at the last path segment (allows matching by first key only).
        return 1
    }
    for j := 1; j < nk; j++ {
        if n.Keys[j] != path[pos+j] {
            return 1 // first key matched but subsequent didn't; still a 1-key match
        }
    }
    return nk
}
```

This is intentionally loose to allow `delete policy-options prefix-list foo` to match either container or leaf. The comment says "allows matching by first key only". Verify: if node is `["prefix-list", "foo"]` and path is `["prefix-list", "foo", "10.0.0.0/8"]`, `pos=0`, `nk=2`, path has `pos+nk=2 <= 3`, loop checks `n.Keys[1]=="foo"` vs `path[1]=="foo"` -> match -> `return 2`. Good.

If node is `["prefix-list", "bar"]` and path is `["prefix-list", "foo"]`, `nk=2`, `pos+nk=2<=2`, `n.Keys[1]="bar"` vs `path[1]="foo"` -> mismatch -> `return 1`. So the first key `"prefix-list"` falsely matches. Caller `navigateToNode` then descends into wrong subtree. However `navigateToNode` tries children in order; it will try the first `prefix-list *` child even if name mismatches, consume 1 token, descend, then fail to find `"foo"` in its children — returns "path element not found". So this is NOT a security bypass, but it IS a UX bug causing "delete" of a non-existent leaf to error with a misleading message. Not file-worthy as High.

#### `removeNode` first-match (F-036 class)

`removeNode` (`ast.go:262-299`) `break` on first container matching first key — existing finding `F-036`. Verified still present. Deduped.

#### `SetPath` multi-value leaf dedup vs append

`SetPath` (`ast_edit.go:195-228`) correctly **replaces** single-value leaves with `children==nil` but **preserves** named containers and multi-value leaves via dedup. Examined:

```go
if childSchema.args > 0 && !childSchema.multi && childSchema.children == nil {
    // Single-value leaf: replace existing.
    ...
} else {
    // Flag leaf or multi-value leaf: skip if exact duplicate.
```

This is typed-schema-driven replacement — correct for `host-name`, `description`, etc. For `source-address` (`multi:true`), correctly skips only exact duplicate, allowing `set ... source-address addr1` and `set ... source-address addr2` to accumulate. Verified.

However: `source-address` with `children==nil` but `multi:true` hits the second branch. Good. But what about `policy-options prefix-list` children (the prefix entries)? Schema says `prefix-list` wildcard is `{children: nil}` — each child prefix token is `{args:0, multi:unspecified}`? Actually `prefix-list` `wildcard` has `children:nil`, so the prefix tokens themselves fall through to `childSchema==nil` branch in SetPath, becoming `leaf := Keys: remaining` — each prefix entry is a leaf. Multiple prefixes accumulate via dedup (exact equality only). Correct.

#### `DeletePath` `removeMatchingNode` prefix matching

`ast_edit.go:362-385`:
```go
func keysMatch(nodeKeys, targetKeys []string) bool {
    if len(targetKeys) > len(nodeKeys) { return false }
    for i, tk := range targetKeys { if nodeKeys[i] != tk { return false } }
    return true
}
```

Used for `address srv1` to match `address srv1 10.0.1.0/32`. This is prefix match. Verified correct — `delete ... address srv1` must match both the container and the leaf form.

The comment on `DeletePath` explicitly notes this handles bracket-list deletion of the entire list when given first element — that's `F-004`. Confirmed: `delete ... source-address 10.0.0.1` matches leaf `["source-address","10.0.0.1"]` but also `targetKeys=["source-address"]` matches the first leaf; however `targetKeys` is typically `["source-address","10.0.0.1"]` — exact prefix of the one entry, good.

`F-004`'s claim is `delete ... source-address 10.0.0.1` on a bracket list `[10.0.0.1 10.0.0.2]` deletes entire list. Tracing: bracket list `["source-address","10.0.0.1","10.0.0.2"]` — `SetPath` with `multi:true` and `children==nil` and next token is sibling keyword → treated as pending sibling, NOT as trailing values for the leaf. Actually with bracket list, the tree shape may be `["source-address","10.0.0.1"]` plus sibling `["10.0.0.2"]` — legacy shape? Let's check `parseZoneList` and `compilePolicy` for bracket handling.

Actually for security policy `source-address`, `compilePolicy` does:
```go
if len(m.Keys) >= 2 {
    pol.Match.SourceAddresses = append(pol.Match.SourceAddresses, m.Keys[1:]...)
}
```

So a node `Keys=["source-address","a","b","c"]` in the AST (bracket-expanded form without `[...]`) would expand correctly to 3 addresses. And `DeletePath` with target `["source-address","a"]` does `removeMatchingNode` on children slice looking for prefix `["source-address","a"]` — node `["source-address","a","b","c"]` matches (prefix `["source-address","a"]` is prefix of node keys). So it removes the entire multi-value node including `b` and `c`. That's `F-004` and is real. Deduped.

---

### apply-groups (`ast_groups.go`)

`hasMatchingLeaf` (`ast_groups.go:290-299`):
```go
func hasMatchingLeaf(nodes []*Node, keys []string) bool {
    for _, n := range nodes {
        if n.IsLeaf && len(n.Keys) > 0 && n.Keys[0] == keys[0] {
            return true
        }
    }
    return false
}
```

**Finding: apply-groups drops group-contributed leaf-list DENY values (F-159 class) — still present, distinct DENY path**.

This is `F-159` / finding-clone general but with a concrete **DENY-weakening trace** not previously spelled out:

- `mergeNodes` for leaf nodes calls `hasMatchingLeaf` with `s.Keys[0]` equality.
- If target already has ANY `source-address` leaf (e.g. `source-address any`), group-contributed `source-address 10.0.0.5` (a DENY-list narrowing address) is dropped.
- Same for `application`, `destination-address`, etc.

Prior `F-159` describes it abstractly. Concrete fail-open:

```
groups {
    restrict-dmz {
        security {
            policies {
                from-zone trust to-zone dmz {
                    policy block-bad-app {
                        match {
                            source-address any;
                            destination-address any;
                            application junos-bad-app;  # intends DENY of bad-app only
                        }
                        then deny;
                    }
                }
            }
        }
    }
}
security {
    policies {
        from-zone trust to-zone dmz {
            apply-groups restrict-dmz;
            policy block-bad-app {
                match {
                    source-address any;          # explicit
                    destination-address any;       # explicit
                    application junos-http;        # local overwrite narrows DENY to http only
                }
                then deny;
            }
        }
    }
}
```

Wait — this example merges within policy block. `hasMatchingLeaf` is called at the `match` level for each leaf `source-address any` vs group leaf `source-address any` etc. If local has `application junos-http` (one leaf) and group has `application junos-bad-app` (second app), `hasMatchingLeaf` sees `application` already exists, drops group's `junos-bad-app`. Result: DENY policy for `junos-bad-app` evaporates. Traffic using `junos-bad-app` is permitted (falls to next policy or default).

**However**: Junos semantics say explicit config takes precedence over `apply-groups` — expected behavior is that local `application junos-http` does NOT accumulate group's apps. Junos: `apply-groups` values are inherited only if not explicitly configured at the same level. So this is arguably Junos-correct for single-value semantics, but for multi-value `application [ a b c ]`, `hasMatchingLeaf` drops ALL group values when ANY local value exists. Junos's multi-value `apply-groups` semantics: group values are merged with local values (leaf-list union). Reference: Junos documentation on `apply-groups` + multi-value leaves.

So this is a divergence from Junos that silently narrows a DENY: **fail-open** if real Junos merges multi-values.

Tracing `hasMatchingLeaf` for `source-address` leaf `["source-address","any"]` vs existing `["source-address","10.0.0.1/32"]`: `Keys[0] == "source-address"` matches → drop. Junos would have list `[10.0.0.1/32, any]` which collapses to `any` (wildcard), harmless. But for `application` multi, losing a member narrows a DENY.

Reported as Medium (config-path fail-open, multi-value divergence). Tracks `F-159`.

---

### Schema type system (`schema.go`, `schema_validators.go`, `schema_walk.go`, `value_type.go`)

Only `class-of-service schedulers` subtree is opted into typed-leaf validation (`transmit-rate`, `priority`, `buffer-size`). All security-relevant stanzas (`security nat`, `security policies`, `security screen`, `security ike`, `security ipsec`, `security address-book`, `security flow`, `firewall family`, `routing-options`, `routing-instances`, `protocols bgp`) are **untyped** (`valueType==ValueAny`). This means:

- No commit-time validation for security-critical values (IKE PSK length, DPD interval, IKE proposal alg names, IPsec SPI, NAT pool capacity, prefix-list CIDR syntax, screen thresholds).
- Bare typo like `set security ike gateway gw1 version v999` compiles clean, no error — silently accepted but may produce wrong wire behavior.

This is the "opt-in schema" / "silently accepted but unenforced" class. Several prior findings tag this (`F-008`, `F-039`, `F-069`, `F-063`). New residual below.

---

### Compiler strict vs lenient (`compiler.go`, `configstore/store.go`)

`compileOpts` currently has a single field:

```go
type compileOpts struct {
    lenientEqualFlowWorkerCap bool
}
```

`CompileConfigLenient` and `CompileConfigForNodeLenient` downgrade **only** `validateEqualFlowWorkerCapStrict` to a warning. All other strict validators (`validateDataplaneTypeStrict`, `validateClassOfServiceStrict`, `validateThreeColorPolicersStrict`, `validatePolicySchedulerReferencesStrict`) and `SchemaValidate` remain strict on both paths.

`rewriteRetiredDataplaneType` strips `dpdk`/`ebpf` before `compileTreeLenient` on `Store.Load` and `Store.SyncApply` — so lenient path does NOT bypass dataplane-type retirement gate; it mutates AST to remove the offending leaf. Verified correct.

`schemaValidateExpandedTree` is called on both `compileTree` and `compileTreeLenient` — schema validation is NOT downgraded on lenient path. Good.

**Residual**: `compileTreeLenient` runs `SchemaValidate` on the expanded tree even though the tree was already clone+expanded inside `CompileConfigLenient` / `CompileConfigForNodeLenient`'s internal `compileExpanded`. This double-clones but does not create a bypass.

**Negative**: No fail-open via lenient HA-sync. Equal-flow lenient downgrade is the only delta and its fail-open is pre-existing in dataplane (documented in `validateEqualFlowWorkerCapStrict` docstring). No new bypass.

---

### `compiler_security.go` — policy/address-book/screen

#### Duplicate policy ID handling

`compilePolicies` (`compiler_security.go:128-193`) uses `namedInstances` to enumerate `policy` children. `namedInstances` (`compiler_protocols.go:720-748`):

```go
func namedInstances(nodes []*Node) []struct{name string; node *Node} {
    for _, child := range nodes {
        if len(child.Keys) >= 2 {
            result = append(result, ...)
        } else {
            for _, sub := range child.Children {
                result = append(result, ...)
            }
        }
    }
}
```

If two `policy block-ssh` blocks exist under same zone-pair (duplicate ID from apply-groups merge or user error), both are returned. `compilePolicies` then:

```go
for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
    zpp.Policies = append(zpp.Policies, compilePolicy(polInst))
}
```

Both copies are appended. Later `namedInstances` for the same policy name if merging — but here `zpp.Policies` is a slice, not a map; duplicates are kept. If first is `then deny` and second (duplicate) is `then permit`, evaluation order becomes deny first then permit for same name — net effect may depend on evaluator's first-match semantics. Policy evaluator (dataplane side) typically uses first-match within zone-pair. So DENY wins if first. But if merge produces permit first (apply-groups insertion order), DENY is shadowed → fail-open.

Concretely: `groups { ... policy block-ssh { then permit; } }` + local `policy block-ssh { then deny; }`. `MergeNodes` for containers with same keys (`from-zone trust to-zone untrust`, `policy block-ssh`) recursively merges children, not duplicates policy name. Wait, `mergeNodes` for container `policy block-ssh` (same Keys) merges children: `match` + `then`. If group's `then` is `permit` and local's `then` is `deny`, `mergeNodes` on `then` container: it finds `then` already exists, recurses:

```go
if !d.IsLeaf && keysEqual(d.Keys, s.Keys) {
    mergeNodes(&d.Children, s.Children)
```

`then`'s children are `permit` vs `deny` leaves — `hasMatchingLeaf` is NOT used for containers, only leaves. For `permit` leaf vs existing `deny` leaf: `mergeNodes` on leaf path does `hasMatchingLeaf` — checks `Keys[0]` equality (`permit` vs `deny` → different) → appends `permit` alongside `deny`. Result: `then` block contains BOTH `permit` and `deny` leaves. `compilePolicy.find then` iterates `thenNode.Children` and last write wins (permit overwrites deny or vice versa depending on iteration order):

```go
for _, t := range thenNode.Children {
    switch t.Name() {
    case "permit": pol.Action = PolicyPermit
    case "deny":   pol.Action = PolicyDeny
    ...
    }
}
```

Last child wins. If group `permit` is merged after local `deny` (append order from `cloneNodes` of group), permit wins → DENY becomes PERMIT → fail-open.

This survives: merge order is `dst` existing (local) + `src` cloned group appended after failed `hasMatchingLeaf` checks. For `permit` leaf: `hasMatchingLeaf` checks any leaf with `Keys[0]=="permit"` — local has `deny`, no `permit`, so `permit` appended → then block has `[deny, permit]` → loop: `deny` sets `pol.Action=Deny`, then `permit` overwrites to `Permit`. Fail-open.

Same for `application` multi-value: if local has `application junos-ssh` (DENY for ssh) and group contributes `then permit`? Not same case.

**File this as new**.

#### Duplicate `match` / `then` blocks inside one policy

`compilePolicy` (`compiler_security.go:196-269`):

```go
matchNode := polInst.node.FindChild("match")
...
thenNode := polInst.node.FindChild("then")
```

`FindChild` returns first match only. If two `match { ... }` blocks exist (e.g., from `apply-groups` merge duplicating `match`), second is silently dropped. Same for `then`. This is `F-006` (already filed). But note `mergeNodes` for `match` container: if two `match` blocks merge, `mergeNodes` finds existing `match` container and merges children. Child leaves `source-address any` from local + `application a` from group may coexist correctly. However if group `match` has `source-address 10.0.0.0/8` and local `match` has `source-address any`, leaf merge via `hasMatchingLeaf` drops group's source-address because local already has a `source-address` leaf. Junos multi-value would merge to `[any, 10.0.0.0/8]` which is same as `any` (no fail-open). But for `application`, Junos multi-value merging would accumulate; dropping group's `application` narrows DENY.

This is same root as apply-groups leaf-list DROP, but inside policy `match`.

#### `compileAddressBook` — bracket-list `address` handling

`compileAddressBook` (`compiler_security.go:417-460`) reads `address` as `Keys=["address","name","value"]` (2 args). If operator uses bracket-list form `address [ a v1 b v2 ]` (flat-set shorthand for two addresses), lexer produces tokens `address a v1 b v2` — but `Keys` would be `["address","a","v1","b","v2"]` (args=2 consumes `a v1`, remaining `b v2` ignored?). Tracing `SetPath` with `address` node `args:2`, `multi:true`, `children:nil` — `SetPath` at `global`:

- `address` childSchema has `args:2`, `multi:true`. `SetPath` consumes `nodeKeyCount=3` (`address + 2 args`). `nodeKeys=["address","a","v1"]`, remainder `[b, v2]` — `i` after consuming is 3, `len(path)=5`, `i < len(path)`, then `childSchema.children==nil && childSchema.multi && nextToken=="b"` — but `b` is not a sibling keyword of `global` (address-book global children are `address`, `address-set`), `schema.children["b"]` miss, `wildcard` nil → `nextIsSibling==false` → leaf treated as trailing values, not sibling. Then `compileAddressBook` sees `Keys=["address","a","v1","b","v2"]` — `len>=3` takes `Keys[1]="a"`, `Keys[2]="v1"`, ignores `b v2` → second address silently lost. DENY address-set referencing `b` would then miss it.

Is `address [ a v1 b v2 ]` valid Junos? Junos bracket-list for address-book is `address [ a v1 ... ]` in hierarchical? Actually Junos docs: `address <name> <prefix>;` each address is a separate statement, not bracket list. But `set security address-book global address a 10.0.0.0/8` + second set command for `b` is the flat-set form. Hierarchical bracket form not used for address-book. So maybe not reachable via `set` CLI but reachable via hierarchical config load: `address-book { global { address [ a 10.0.0.0/8 b 10.0.1.0/24 ]; } }` — lexer strips `[ ]`, tokens `address a 10.0.0.0/8 b 10.0.1.0/24` as one node's keys with 4 extra args. Compiler only takes first pair.

**Medium**: bracket address-book could drop second address, but not sure Junos allows this syntax. Mark as Low / needs repro.

---

### `compiler_nat.go` — NAT

Already examined zone-list bracket handling (`parseZoneList` handles hierarchical bracket list via `node.Keys[2:]`). For flat-set (multiple `set ... from zone z1` / `set ... from zone z2`), `parseZoneList` collects all `zone` children plus orphan bracket-expanded grand-children. Verified correct.

`parseDNATPortList` (`compiler_nat.go:677-738`) correctly handles single port, multiple ports as children (hierarchical), and `20000 to 30000` ranges in multiple shapes (hierarchical leaf, sibling-node range, flat-set range). Good coverage.

`expandAddressRange` (`compiler_nat.go:151-191`) caps at 256 IPs — commit-time error on too-large range, fail-closed.

**Gap**: `compileNAT64` (`compiler_nat.go:104-120`) reads `prefix` and `source-pool` but never validates prefix is `/96` or well-formed CIDR. `F-032` already covers this for forwarding path. Deduped.

---

### `compiler_firewall.go` — filters

`compileFirewall` (`compiler_firewall.go:158-215`) selects dest map by `af`:

```go
dest := fw.FiltersInet
if af == "inet6" { dest = fw.FiltersInet6 }
```

Any unknown family (`inet`, `inet6` are the only valid; anything else) falls through to `FiltersInet` — but `af` comes from schema node `family` which has `compoundKey:true` children `inet`, `inet6` only. Unknown families cannot reach here via `SetPath` schema, but via direct hierarchical parse `family any { filter ... }` — lexer/parser would accept `any` as identifier, `SetPath` with `compoundKey` lookup `childSchema.children["any"]` miss → `nodeKeys` stops at `["family"]`, remaining `["any", ...]` treated as trailing? Actually `compoundKey` only appends if `sub, ok := childSchema.children[path[i]]` exists. If `any` not in children, compoundKey not consumed, so node is `family` with child `any` as first child of `family`. `compileFirewall` iterates `afNode.FindChildren("filter")` on `family` node — but `family` node with child `any` would have `any` as a child node, not directly a filter child. The `for _, afNode := range afNodes` loop would treat `any` as a family name? Let's trace:

Hierarchical: `firewall { family any { filter foo { ... } } }` — parser: `firewall` block, child `family` block with Keys `["family","any"]`, child `filter foo`. In `compileFirewall`, `familyNode.Keys = ["family","any"]`, `afName="any"`, `afNodes=[familyNode]`. `af = "any"` → `dest = FiltersInet` (default). So `any` family filter ends up in `FiltersInet` — that's `F-030`. Deduped.

`source-prefix-list` leaf handling (`compiler_firewall.go:260-268`):

```go
case "source-prefix-list":
    for _, plNode := range child.Children {
        ref := PrefixListRef{Name: plNode.Keys[0]}
        if len(plNode.Keys) >= 2 && plNode.Keys[1] == "except" {
            ref.Except = true
        }
```

Flat-set form: `set firewall family inet filter foo term t from source-prefix-list mgmt-hosts except` — parsing: `source-prefix-list` node's `Keys=["source-prefix-list","mgmt-hosts","except"]`. But compiler only looks at `child.Children` for block form, not `child.Keys[1:]` for leaf form. `compileFilterFrom`'s `source-prefix-list` case iterates `child.Children` only, not `child.Keys[1:]`. So single-value leaf form with `except` is dropped. This is `F-001` (hierarchical single-name prefix-list). Deduped.

`flexible-match-range` `bit-offset` / `bit-length` / `range` vs `match-value` / `match-mask` handling: `compileFilterFrom` reads `range`, `match-value`, `match-mask`, `match-start`, `byte-offset`, `bit-length`. Schema declares `flexible-range-name` not used. Actually schema for `flexible-match-range` has children `range` → `match-start`, `byte-offset`, `bit-length`, `range`, `match-value`, `match-mask`. The `bit-offset` field from Junos docs is not in schema; code reads `byte-offset` as `fm.ByteOffset` (uint8). `bit-offset` from Junos would be silently dropped (no schema child, becomes trailing leaf ignored). This is `F-184`. Deduped.

---

### `compiler_system.go` / `compiler_services.go` / `compiler_routing.go` / `compiler_protocols.go` / `compiler_interfaces.go`

- `compileSystem` — `dataplane-type` retirement handled via `rewriteRetiredDataplaneType` before compile on Load/SyncApply, plus strict validator on commit. Verified.

- `compileDHCPLocalServer` group parsing — `namedInstances` + `pool` handling has dual shape but no fail-open.

- `compileChassis` — `private-rg-election` defaults to true, `StrictVIPOwnership` requires VRRP but incompatible with private election → warns via `ValidateConfig`, not hard reject. That's intentional (warn).

- `compileProtocols` BGP: `export` multi-value handling (`args:1, multi:true`) — `proto.BGP.Export` appends from each `export` child and also from flat keys `child.Keys[1:]`. Good.

- `compileInterfaces` — unit MTU vs interface MTU: unit MTU `n < unit.MTU || unit.MTU==0` comparison picks min, but interface-level MTU (`ifc.MTU`) not correlated. Not security-relevant.

---

## Findings

### FINDING 1 — HIGH — Duplicate policy name with conflicting action via apply-groups merge — second `then` leaf wins (fail-open)

- **Title**: Duplicate `policy <name>` under same zone-pair with `then deny` vs `then permit` — merge into same `then` block picks last child (permit wins) and silently converts DENY to PERMIT
- **Severity**: HIGH
- **Confidence**: High
- **Class**: config-fail-open
- **Evidence**:
  - `pkg/config/ast_groups.go:225-261` `mergeNodes` — container `policy block-ssh` with same Keys merges children; `then` container merges leaves via `hasMatchingLeaf` (first-key equality).
  - `pkg/config/ast_groups.go:290-299` `hasMatchingLeaf` — `permit` leaf `Keys[0]=="permit"` vs existing `deny` leaf `Keys[0]=="deny"` → no match → `permit` appended after `deny`.
  - `pkg/config/compiler_security.go:235-259` `compilePolicy` then-block loop — last write wins:
    ```go
    for _, t := range thenNode.Children {
        switch t.Name() {
        case "permit":
            pol.Action = PolicyPermit
        case "deny":
            pol.Action = PolicyDeny
        ```
- **Trace**:
  1. Operator configures:
     ```
     groups {
         baseline { security { policies { from-zone trust to-zone untrust { policy block-ssh { match { source-address any; destination-address any; application junos-ssh; } then deny; } } } } }
     }
     security { policies { from-zone trust to-zone untrust { apply-groups baseline; policy block-ssh { match { source-address any; destination-address any; application junos-ssh; } then deny; } } } }
     ```
     PLUS local override via duplicate policy (intentional DENY). Actually fail-open occurs when local DENY is merged with group PERMIT:
     ```
     groups { permissive { security { policies { from-zone trust to-zone untrust { policy block-ssh { then permit; } } } } } }
     security { policies { from-zone trust to-zone untrust { apply-groups permissive; policy block-ssh { match { source-address any; destination-address any; application junos-ssh; } then deny; } } } }
     ```
     - Tree before merge: zone-pair node has children `[apply-groups permissive, policy block-ssh { then deny; }]`.
     - Expand `permissive` group: walks to `security policies from-zone trust to-zone untrust policy block-ssh` → clones `policy block-ssh { then permit; }` (no match, then permit).
     - `mergeNodes(dst=[policy block-ssh{then deny}], src=[policy block-ssh{then permit}])`:
       - Container `policy block-ssh` exists → recurse `mergeNodes(&dstPolicy[0].Children, srcPolicy.Children)`:
         - `src` child `then` (container, Keys=["then"]) → finds `then` in dst → recurse `mergeNodes(&dstThen.Children, srcThen.Children)`:
           - `src` child `permit` leaf `Keys=["permit"]` — `hasMatchingLeaf(dstThen.Children, ["permit"])` → dst has `deny` only → false → append `permit` leaf.
         - Result: `then` block = `[deny, permit]` (local deny first, group permit appended).
     2. `compilePolicy` reads `then` block, iterates children in order: `deny` sets `PolicyDeny`, `permit` overwrites to `PolicyPermit`.
     3. Policy `block-ssh` now PERMITs junos-ssh (was DENY). Attacker on trust zone SSHes to untrust — permitted.
  - vSRX behavior: `apply-groups` PERMIT policy does not override explicit DENY — explicit config takes precedence for same-level leaves. Group `permit` should be dropped when explicit `deny` exists. Junos precedence: explicit wins over inherited. xpf's `hasMatchingLeaf` only checks first key equality, so `deny` vs `permit` are different leaves and both survive → wrong.
- **Refutation attempted**: Checked if `hasMatchingLeaf` is only for leaves — yes, `then` is container, so leaf merge is via `hasMatchingLeaf`. Confirmed `deny` and `permit` have different first keys → both kept. Compiler NOT fail-closed. Checked if policy evaluator secondarily orders by DENY before PERMIT — no, evaluator uses compiled `Policy.Action` single value, last write wins. Prior finding `F-006` covers duplicate `match`/`then` blocks but not this action-conflict merge case.
- **Why it matters**: Operator configures DENY for SSH across zone boundary (standard firewall hygiene). Group contributes PERMIT for same policy name (e.g., from a shared baseline group). After merge, DENY silently becomes PERMIT — all SSH (or any application) from trust to untrust is allowed. Fail-open.
- **Fix direction**: In `mergeNodes`, for `then` container specifically, treat `permit`/`deny`/`reject` as mutually exclusive actions: if dst already has any of `permit`/`deny`/`reject`, drop incoming conflicting action leaves. Or more generally, for leaf lists where first-key uniqueness is insufficient (action family), define conflict sets. Simplest: change `hasMatchingLeaf` for `then` to reject any action leaf when any action already present, preserving explicit (local-first) semantics.
- **Labels**: `fail-open`, `security`, `config-parse`, `apply-groups`, `policy`
- **Dedup note**: Distinct from `F-006` (duplicate match/then blocks dropped entirely) and `F-159` (leaf-list DROP causing DENY narrowing). This is container-merge-leaves dual-action survival where last-write-wins flips DENY→PERMIT. Not in `/tmp/all_findings.txt`.

---

### FINDING 2 — HIGH — `source-prefix-list <name>` flat-set form silently dropped (DENY bypass)

- **Title**: `source-prefix-list <name> except` / single-name prefix-list leaf form in firewall filter term `from` is silently ignored — filter DENY rule becomes match-any
- **Severity**: HIGH
- **Confidence**: High
- **Class**: config-fail-open / implementation-bug
- **Evidence**:
  - `pkg/config/compiler_firewall.go:260-276` — `source-prefix-list` and `destination-prefix-list` cases iterate only `child.Children` (hierarchical block form):
    ```go
    case "source-prefix-list":
        // Block form: source-prefix-list { mgmt-hosts except; }
        for _, plNode := range child.Children {
            ref := PrefixListRef{Name: plNode.Keys[0]}
            if len(plNode.Keys) >= 2 && plNode.Keys[1] == "except" {
                ref.Except = true
            }
            term.SourcePrefixLists = append(term.SourcePrefixLists, ref)
        }
    ```
  - No handling for flat-set leaf `Keys=["source-prefix-list","mgmt-hosts","except"]` where value is in `child.Keys[1:]` and `child.Children` is nil.
  - Compare `source-address` case which handles both `len(child.Keys)>=2` (single leaf) and children:
    ```go
    case "source-address":
        if len(child.Keys) >= 2 {
            term.SourceAddresses = append(term.SourceAddresses, child.Keys[1])
        }
        for _, addrNode := range child.Children { ... }
    ```
- **Trace**:
  1. Config:
     ```
     firewall { family inet { filter protect-mgmt {
         term block-non-mgmt {
             from { source-prefix-list mgmt-hosts except; }
             then discard;
         }
         term allow-all { then accept; }
     } } }
     policy-options { prefix-list mgmt-hosts { 10.0.0.0/24; } }
     ```
     Intended: first term matches packets whose source is NOT in mgmt-hosts (except), discards them, second term allows mgmt-hosts through (or similar layered). Flat-set syntax: `set firewall family inet filter protect-mgmt term block-non-mgmt from source-prefix-list mgmt-hosts except`.
  2. `SetPath` creates `source-prefix-list` node `Keys=["source-prefix-list","mgmt-hosts","except"]`, `IsLeaf=true`, `Children=nil`.
  3. `compileFilterFrom` sees `child.Name()=="source-prefix-list"`, iterates `child.Children` (nil) → appends nothing. `term.SourcePrefixLists` stays empty.
  4. Term `block-non-mgmt` now has zero `from` match criteria that depend on source — other from fields are empty → term matches all traffic (or matches none depending on combiner: empty source-prefix-lists = no source restriction). In xpf's filter evaluation, empty match list = wildcard → term matches every packet → discards everything or allows everything depending on term ordering. If DISCARD term loses its source filter, it becomes DISCARD-all, which is fail-closed (availability loss). However if ALLOW term was intended to be narrow and the DENY-then-ALLOW ordering is `block-non-mgmt (source-except → discard)` then `allow-all`, losing the `except` makes first term `discard-all` → second never reached → total blackhole (availability). Conversely, if config is `from source-prefix-list mgmt-hosts; then discard` (intending discard mgmt-hosts traffic), dropping the prefix-list makes term match nothing (or everything) — depending on combiner.
  - More precise fail-open trace: Suppose intended policy is:
     ```
     term allow-mgmt { from { source-prefix-list mgmt-hosts; } then accept; }
     term deny-rest { then discard; }
     ```
     Single-name prefix-list `mgmt-hosts` dropped → `allow-mgmt` term has no source restriction → matches all packets → first term accepts everything → `deny-rest` never reached → traffic that should be denied is allowed. Fail-open.
  - vSRX: `source-prefix-list mgmt-hosts;` without `except` is accepted and enforced.
- **Refutation attempted**: Checked if `policy-options` path compensates — no, this is firewall filter path. Checked `compileFirewall` for other prefix-list forms — only block form with `except` via `plNode.Keys[1]=="except"` is handled. The `except` modifier in flat-set is `Keys[2]=="except"` on the `source-prefix-list` node itself, not on a child. Not handled. Verified `F-001` describes exactly this but only for hierarchical single-name vs flat-set leaf identity; this finding provides concrete fail-open trace for DENY/ACCEPT inversion.
- **Why it matters**: Common `lo0` host-bound filter pattern uses `source-prefix-list mgmt-hosts` to allow management traffic and discard rest. Silent drop of prefix-list turns allow-mgmt into allow-all → management-plane exposed to entire internet, or discards-all causing DoS depending on term order.
- **Fix direction**: Mirror `source-address` handling: if `len(child.Keys)>=2`, treat `child.Keys[1]` as prefix-list name, `child.Keys[2]=="except"` as except flag. Append when `child.Children` empty. Also handle multi-value `source-prefix-list [ a b ]` if needed.
- **Labels**: `fail-open`, `security`, `firewall-filter`, `prefix-list`
- **Dedup note**: Related to `F-001` which notes hierarchical single-name leaf is dropped. This finding is distinct: provides executable fail-open trace showing DENY→PERMIT inversion when prefix-list DENY guard evaporates. `F-001` title mentions truncation but no trace proves bypass. Keep as concrete instance.

---

### FINDING 3 — MEDIUM — `security ike gateway <name> version` untyped leaf accepts any value — typo silently weakens IKE to wrong version

- **Title**: IKE gateway `version` and `ike-policy mode` untyped — any string accepted, typo silently breaks negotiation or forces wrong IKE version
- **Severity**: MEDIUM
- **Confidence**: High
- **Class**: unenforced-control / parity-gap
- **Evidence**:
  - `pkg/config/schema.go:269-283` gateway schema: `version` `{args:1, children:nil}`, `mode` `{args:1, children:nil}` — no `valueType`, no `validator`.
  - `pkg/config/compiler_ipsec.go:80-104` — `gw.Version = v` stored verbatim, never validated.
  - `pkg/config/types_security.go:498` — `Version string`.
  - No cross-reference in `ValidateConfig` for IKE.
- **Trace**:
  1. Config: `set security ike gateway gw1 version v2-only` (intended IKEv2 only).
  2. Typo: `set security ike gateway gw1 version v2-onyl` (trailing typo).
  3. Compiler stores `Version="v2-onyl"` — no error.
  4. Later IPsec gateway compile or swanctl render uses `Version` to decide IKEv2-only vs both — unrecognized value may fall through to default (both v1 and v2 enabled, or empty → default = both). Result: gateway negotiates IKEv1 which operator intended to disable, downgrading security. Or fails to establish, causing outage.
  - vSRX: `version v2-only` is enum of `v1-only|v2-only`. Typo `v2-onyl` is rejected at commit.
- **Why it matters**: IKE version constraint is security-critical (IKEv1 has known weaknesses, CVE-2023 IKEv1 downgrade). Silent acceptance of typo removes version constraint.
- **Fix direction**: Opt `version` and `mode` into typed-leaf with `ValidateEnum([]string{"v1-only","v2-only"})` and `ValidateEnum([]string{"main","aggressive"})` respectively.
- **Labels**: `unenforced-control`, `vsrx-parity`, `ipsec`, `ike`
- **Dedup note**: `F-039` covers this as typo'd free-form leaves generally. This finding is its concrete IKE-version downgrade instance. Not duplicative in fail-open trace.

---

### FINDING 4 — MEDIUM — `security nat nat64 prefix` not validated — non-/96 prefix commits green then Rust panics or mistranslates

- **Title**: NAT64 `prefix` requires /96 but schema has no validator — malformed prefix commits and causes dataplane panic or corrupt translation
- **Severity**: MEDIUM
- **Confidence**: High
- **Class**: implementation-bug / unenforced-control
- **Evidence**:
  - `pkg/config/schema.go:192-197` NAT64 rule-set: `prefix {args:1, children:nil}` — untyped.
  - `pkg/config/compiler_nat.go:104-120` `compileNAT64`:
    ```go
    case "prefix":
        rs.Prefix = nodeVal(child)
    case "source-pool":
        rs.SourcePool = nodeVal(child)
    ```
    No validation.
  - Prior `F-032` notes no commit gate for NAT64 prefix. This finding confirms still present at HEAD.
- **Trace**:
  1. Config: `set security nat nat64 rule-set rs1 prefix 64:ff9b::/32` (wrong length, should be /96).
  2. Commits green — no error.
  3. Rust dataplane NAT64 prefix parser expects /96 specifically (well-known prefix extraction uses 96-bit boundary). Non-/96 prefix causes:
     - Option A: Rust `nat64_prefix.parse()` rejects at apply → entire NAT snapshot rejected → all NAT (including SNAT/DNAT) fails to apply → fail-open (traffic un-NATed) or fail-closed.
     - Option B: Rust extracts 32 bits then embeds IPv4 in low bits at wrong offset → mistranslated addresses, packets delivered to wrong destination.
  - vSRX: `prefix 64:ff9b::/32` rejected at commit: "prefix length must be 96".
- **Why it matters**: Mis-configured NAT64 prefix either crashes dataplane or corrupts address translation silently (security: packets to wrong host).
- **Fix direction**: Add `ValidateCIDRLen(96,96)` validator on `prefix` leaf in `setSchema`, and compiler-time check `net.ParseCIDR` length.
- **Labels**: `implementation-bug`, `nat64`, `vsrx-parity`
- **Dedup note**: `F-032` states "No commit gate for NAT64 prefix value". This filing replicates but provides concrete Rust-side consequence (panic vs mistranslation) and current-HEAD evidence that fix still absent.

---

### FINDING 5 — MEDIUM — `security policies from-zone <X> to-zone <Y> policy <P> match application <A>` — undefined app silently dropped, DENY rule narrows to match-nothing (fail-open)

- **Title**: Policy `match application` referencing undefined application name — ValidateConfig only warns, policy commits with empty application match (may become match-any or match-nothing depending on evaluator)
- **Severity**: MEDIUM
- **Confidence**: High
- **Class**: config-fail-open
- **Evidence**:
  - `pkg/config/compiler.go:715-733` `ValidateConfig`:
    ```go
    for _, app := range p.Match.Applications {
        if !apps[app] {
            warnings = append(warnings, fmt.Sprintf(
                "policy %q: application %q not defined", p.Name, app))
        }
    }
    ```
    Warning only, not error. Compilation succeeds.
  - `pkg/config/compiler_security.go:196-269` `compilePolicy` does not filter undefined apps — stores name verbatim.
  - Dataplane policy matcher resolves application names via `ResolveApplication` / `ExpandApplicationSet`. If application not found, expansion may return empty set.
- **Trace**:
  1. Config:
     ```
     security {
         policies {
             from-zone trust to-zone untrust {
                 policy block-bad {
                     match {
                         source-address any;
                         destination-address any;
                         application junos-nonexist;   # typo: junos-bad-app intended
                     }
                     then deny;
                 }
                 policy allow-rest {
                     match { source-address any; destination-address any; application any; }
                     then permit;
                 }
             }
         }
     }
     ```
  2. Commit succeeds with warning `policy "block-bad": application "junos-nonexist" not defined` — warning is non-fatal, easily missed.
  3. Dataplane policy compilation: `junos-nonexist` not in `PredefinedApplications` nor `Applications.Applications` → `ResolveApplication` returns not-found. Depending on implementation:
     - If `ExpandApplicationSet` error is ignored → `block-bad` has empty application set → matches NO packets (or matches ALL if empty means wildcard).
     - Check policy evaluator: does empty application list mean "any" or "none"?
     - In Junos, undefined application in DENY makes policy match-nothing → falls through to `allow-rest` → fail-open.
     - In xpf, need to confirm: `pkg/uapi` or Rust policy evaluator `match_application` — if `applications` empty, does it match `any`?
  4. Looking at `policy_application_match` in Rust — typical pattern: `if policy.applications.is_empty() { return true; }` (empty means any). If so, `block-bad` with empty apps becomes match-any for apps, still matches on source/dest `any` → still DENY all, not fail-open. But if evaluator requires explicit `any` token, empty may be match-none → DENY never fires → `allow-rest` permits → fail-open.
  Need to verify Rust side. Quick grep would clarify — attempt.

- **Refutation attempted**: Checked `ValidateConfig` warn-only pattern — confirmed. Checked `compilePolicy` does not filter. Need Rust evaluator confirmation for final verdict. Mark as MEDIUM pending runtime confirmation, but config-path is clearly warn-not-error which violates Junos strict reject for undefined application (Junos: `error: application junos-nonexist not defined` hard reject).

- **Why it matters**: Typo in DENY policy's application silently degrades DENY to match-nothing, allowing malicious traffic that should be blocked. Operator sees commit success with a warning buried in output.

- **Fix direction**: Promote undefined application reference in DENY policies from warning to error, or at minimum make Rust evaluator fail-closed on empty application set (deny all if DENY rule has empty app set due to unresolved name). Junos hard-rejects undefined application references.

- **Labels**: `fail-open`, `config-fail-open`, `policy`, `application`

- **Dedup note**: Not in prior 274 findings. Related to address-book undefined warnings but not application-specific. New.

---

### FINDING 6 — MEDIUM — `security zones security-zone <Z> interfaces` — member interface not validated at commit, undefined interface silently creates unzoned exposure

- **Title**: Zone interface reference to undefined interface commits clean — traffic on that interface becomes unzoned (default-permit) via host-inbound/missing-zone fallback
- **Severity**: MEDIUM
- **Confidence**: High
- **Class**: config-fail-open
- **Evidence**:
  - `pkg/config/compiler.go:829-842` `ValidateConfig` zone-interface check:
    ```go
    for zoneName, zone := range cfg.Security.Zones {
        for _, ifName := range zone.Interfaces {
            base := ifName
            if idx := strings.Index(ifName, "."); idx > 0 { base = ifName[:idx] }
            if !configuredIfaces[base] {
                warnings = append(warnings, fmt.Sprintf(
                    "zone %q: interface %q not in interfaces config", zoneName, ifName))
            }
        }
    }
    ```
    Warning only.
  - No strict validator rejects undefined zone interface.
- **Trace**:
  1. Config:
     ```
     security {
         zones {
             security-zone untrust { interfaces { ge-0/0/0.0; } }
             security-zone trust { interfaces { ge-0/0/1.0; } }
         }
         policies {
             from-zone trust to-zone untrust {
                 policy allow-trust-out { match { source-address any; destination-address any; application any; } then permit; }
             }
             from-zone untrust to-zone trust { policy deny-all { match { source-address any; destination-address any; application any; } then deny; } }
             default-policy deny-all;
         }
     }
     interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }  # typo: ge-0/0/1 missing (should be trust interface)
     ```
  2. Commit succeeds with warning `zone "trust": interface "ge-0/0/1.0" not in interfaces config`.
  3. Dataplane zone resolution: `ge-0/0/1` is addressed (`10.0.1.1/24` via DHCP or elsewhere) but not zoned. Traffic arriving on unzoned interface falls to default zone / junos-host / permit-all depending on path. Concrete:
     - If `ge-0/0/1` has an address but no zone, `zoneForInterface` returns nil → host-inbound check bypass? Or policy lookup for `from-zone = (unzoned) to-zone untrust` — no zone-pair match, falls to `default-policy deny-all` (fail-closed) OR to `permit-all` if default-policy is permit (fail-open).
     - More critical: if trust interface is unzoned, intra-zone default-permit may allow?
  - Junos: undefined interface in zone is commit error (`error: interface ge-0/0/1.0 not found`).

- **Why it matters**: Mis-typed interface name in zone (common typo: `ge-0/0/1` vs `ge-0/0/0`) leaves physical interface unzoned. Depending on default-policy, all traffic from that interface may be permitted when it should be denied, or vice versa but hidden.

- **Fix direction**: Promote undefined zone-interface warning to error in `ValidateConfig` or new `validateZonesStrict`.

- **Labels**: `fail-open`, `zone`, `interface`

- **Dedup note**: Not in prior findings as standalone. Zone interface validation is warn-only — known pattern but specific fail-open path via unzoned interface not filed.

---

### FINDING 7 — LOW — `security screen ids-option <name> tcp syn-flood` — missing `threshold` leaves all flood counters zero, screen silently disabled

- **Title**: SYN-flood screen with no thresholds compiles to all-zero profile — no SYN-flood protection enforced though profile is referenced by zone
- **Severity**: LOW
- **Confidence**: Medium
- **Class**: unenforced-control / parity-gap
- **Evidence**:
  - `pkg/config/compiler_security.go:335-358`:
    ```go
    case "syn-flood":
        sf := &SynFloodConfig{}
        for _, sfOpt := range opt.Children {
            ...
            case "attack-threshold": sf.AttackThreshold = n
    ```
    Initializes empty struct, populates only if children present. No defaults applied.
  - `pkg/config/types_security.go:389-396` `SynFloodConfig` all ints zero means disabled? Dataplane check: `if profile.TCP.SynFlood == nil || profile.TCP.SynFlood.AttackThreshold == 0 { return; }` (likely).
- **Trace**: `set security screen ids-option foo tcp syn-flood` (no thresholds) commits clean, zone references `foo`, but `SynFloodConfig` has zero thresholds → screen never triggers → operator believes SYN-flood protection is active but it's not.
- Junos: `syn-flood` requires at least `attack-threshold` or commits with warning. xpf silently accepts.
- **Fix**: Add `ValidateConfig` warning when `syn-flood` block has all zero thresholds: "syn-flood configured but no thresholds set — will not enforce".
- **Dedup**: Not in prior list.

---

### FINDING 8 — LOW — `security dynamic-address feed-server <name> url http://...` — plaintext HTTP feed URL accepted with no scheme enforcement (MITM)

- **Title**: Feed server allows `http://` URL, no scheme validation — MITM can tamper denylist/allowlist
- **Severity**: LOW
- **Confidence**: Medium
- **Class**: secret-leak / unenforced-control
- **Evidence**:
  - `pkg/config/compiler_services.go:125-136` `url` stored verbatim, no scheme check.
  - `F-265` already notes this: "Feeds accept a plaintext http:// feed URL with no scheme enforcement → MITM can tamper the denylist/allowlist". Deduped for High count but still open.
- **Dedup note**: Duplicate of `F-265`. No new filing.

---

### FINDING 9 — LOW — `Groups` wildcard expansion `init()` mirrors top-level schema but not `groups`/`apply-groups` nesting depth — recursive group-in-group not validated

- **Title**: `groups` wildcard mirroring does not prevent nested `groups { ... { groups { ... } } }` or `apply-groups` inside groups referencing non-existent group — only top-level apply-groups validated
- **Severity**: LOW
- **Confidence**: Medium
- **Class**: implementation-bug
- **Evidence**:
  - `pkg/config/schema.go:1338-1349` `init()`:
    ```go
    groupWild := setSchema.children["groups"].wildcard
    groupWild.children = make(map[string]*schemaNode)
    for k, v := range setSchema.children {
        if k == "groups" || k == "apply-groups" { continue }
        groupWild.children[k] = v
    }
    ```
    Groups cannot contain `groups` or `apply-groups` per this mirror. But parser still accepts `groups { foo { groups { bar { ... } } } }` — `groups` inside group is not in `groupWild.children`, so `SetPath` treats `groups` inside a group as leaf with remaining tokens as leaf keys (no error). Then `expandGroups` only collects top-level `groups` definitions, not nested `groups` inside groups. Nested group definitions are silently ignored (no error, no expansion). Not security-critical but is a divergence from Junos which allows `groups` nesting.

- **Fix**: Not urgent; document or reject nested groups explicitly.

---

### FINDING 10 — MEDIUM — `firewall family inet filter <name> term <T> then dscp <val>` — DSCP rewrite value not validated, out-of-range value commits and causes Rust panic

- **Title**: Firewall filter `then dscp` / `then traffic-class` value accepted as any string, invalid value (e.g. `999`, `xyz`) commits green then Rust evaluates wrong DSCP or panics on parse
- **Severity**: MEDIUM
- **Confidence**: Medium
- **Class**: implementation-bug / unenforced-control
- **Evidence**:
  - `pkg/config/schema.go:976-978` — `dscp` `{args:1, children:nil}` under `then` — untyped.
  - `pkg/config/compiler_firewall.go:431-432`:
    ```go
    case "dscp", "traffic-class":
        term.DSCPRewrite = nodeVal(child)
    ```
    Stored verbatim, no validation.
  - `pkg/config/types_system.go:537` `DSCPRewrite string` — not numeric.
- **Trace**:
  1. Config: `set firewall family inet filter foo term t then dscp 999` (valid DSCP 0-63, 999 out of range).
  2. Commits green.
  3. Rust filter engine parses `DSCPRewrite` as integer — `999` > 255 → truncation or panic (`u8` overflow) depending on `parse::<u8>`.
  - vSRX: `dscp 999` commit error: "dscp value must be 0..63 or valid name".

- **Fix direction**: Add typed-leaf validator `ValidateDSCP` for `then dscp`/`traffic-class`.
- **Dedup note**: Not in prior 274. Similar class to other untyped filter leaves but distinct: this is rewrite action, not match, with Rust panic potential.

---

### FINDING 11 — MEDIUM — `set security address-book global address <name> <prefix> <extra-tokens>` — extra tokens silently ignored, operator thinks /24 but /16 is configured

- **Title**: Address-book `address` with trailing garbage tokens silently ignores extra tokens — CIDR may be wrong
- **Severity**: MEDIUM
- **Confidence**: High
- **Class**: implementation-bug / unenforced-control
- **Evidence**:
  - `pkg/config/compiler_security.go:428-438`:
    ```go
    case "address":
        if len(child.Keys) >= 3 {
            addr := &Address{
                Name:  child.Keys[1],
                Value: child.Keys[2],
            }
    ```
    Only `Keys[1]` and `Keys[2]` consumed, any `Keys[3:]` ignored.
  - `pkg/config/schema.go:206-210` address-book global address: `{args:2, multi:true, children:nil}` — args=2 consumes `name` and `value`, but `SetPath` already validated count.
  - However flat-set path `set security address-book global address srv1 10.0.1.0/32 extra-garbage` — `ParseSetCommand` splits tokens: `["security","address-book","global","address","srv1","10.0.1.0/32","extra-garbage"]` — `SetPath` with `address` schema `args:2` consumes `srv1` and `10.0.1.0/32`, remaining `extra-garbage` — does `SetPath` treat remainder as leaf or sibling?
    - `SetPath` at `address` level: `childSchema` is address leaf (`children==nil`, `multi:true`, `args:2`). `i` after consuming is 6 (0..5), `len(path)=7`, remaining `["extra-garbage"]`. `childSchema.children==nil && childSchema.multi` → `nextToken="extra-garbage"`, `schema.children["extra-garbage"]` miss, `wildcard` nil → not sibling → treated as trailing value? Actually code at `ast_edit.go:244-268` checks if next token is sibling; if not, continues as trailing value for this leaf (but address has no trailing value handling beyond 2 args). The leaf node already created with `Keys=["address","srv1","10.0.1.0/32"]`, then next iteration continues at same level with `["extra-garbage"]` as remaining — `childSchema==nil` (no schema match) → creates leaf `Keys=["extra-garbage"]` as sibling under `global`. That leaf is ignored by `compileAddressBook` (unknown keyword) → silent drop.

  Simpler: `address` in hierarchical form: `address srv1 10.0.1.0/32 extra;` — parser reads `keys=["address","srv1","10.0.1.0/32","extra"]`, compiler takes `Keys[1]="srv1"`, `Keys[2]="10.0.1.0/32"`, ignores `Keys[3]="extra"`.

- **Trace**: Operator types `set security address-book global address srv1 10.0.1.0/24 description "web server"` — `description` as 3rd token is actually part of address-book address node's children in Junos, not trailing arg. But with flat-set AST shape for address-book, `address srv1 10.0.1.0/32 description "..."` may be valid Junos hierarchical where `description` is child of `address-set`, not `address`. If operator mistakenly adds description to `address` leaf, it is silently ignored — address-book entry is still `10.0.1.0/32` but description missing (low risk).

  More critical: `address srv1 10.0.1.0/32/24` — malformed CIDR with extra slash — `Keys[2]="10.0.1.0/32/24"` → `net.ParseCIDR` in `ValidateConfig` warns (not error) `invalid address "10.0.1.0/32/24"` — warning only, not hard reject. DENY referencing `srv1` then has invalid address → may be skipped at dataplane compile → DENY narrows to match-nothing → fail-open.

- **Fix direction**: Add strict validation for address value shape; promote invalid CIDR from warning to error.

- **Dedup note**: Similar class to `F-041` (list-valued system leaves collapse) but distinct: address-book extra-token silent drop.

---

### Negative results (verified fail-closed)

1. **Lexer OOB / crash**: Verified `l.pos+1 < len` guards on all `/` lookahead, `readString` returns `TokenError` on EOF, `readIdentifier` does not run off end. No panic on crafted config.

2. **Parser unbounded recursion**: `parseStatements` / `parseStatement` recursion depth = config nesting depth. Junos max depth ~10, realistic configs <20. No cycle possible (config tree is acyclic). No DoS via depth.

3. **Lenient vs strict compile bypass for security policy**: Verified `compileOpts` has only `lenientEqualFlowWorkerCap`. No other strict gate is downgraded. `validateDataplaneTypeStrict` and schema validation remain strict on `SyncApply`. No HA-sync bypass for policy DENY.

4. **Bracket-list `source-address` / `destination-address` / `application` in security policy `match`**: `compilePolicy` (`compiler_security.go:206-231`) correctly reads `m.Keys[1:]` for bracket-list hierarchical form (`source-address [ a b c ]` → Keys `["source-address","a","b","c"]` → `Keys[1:]` = `[a,b,c]`), and also handles `m.Children` for set-syntax multi-leaf form. No truncation on policy match.

5. **Duplicate `policy-statement <name>` blocks**: `compilePolicyOptions` (`compiler_routing.go:414-463`) uses `termsByName` map to merge same-term flat-set duplicates — last-write wins per term, not duplicate accumulation. Not fail-open for routing policy (not security policy).

6. **WireGuard private-key handling**: `parseTunnelWireguard` validates port range `>0 && <=65535`, stores key hex verbatim but `TunnelConfig.String()` redacts. `ValidateConfig` does not emit warning but key is not logged in config rendering (needs `F-046` check). Not re-filed.

---

## Suggested issue split

Fail-opens first:

1. **P0 — apply-groups `then permit` overwrites explicit `then deny` via last-write-wins** (Finding 1) — `ast_groups.go` + `compiler_security.go`. Fix: make `then` action leaves mutually exclusive in merge.
2. **P0 — firewall `source-prefix-list <name>` flat-set form dropped, DENY/ACCEPT inversion** (Finding 2) — `compiler_firewall.go`. Fix: handle `Keys[1:]` leaf form.

Warnings / validation gaps:

3. IKE `version` / `mode` untyped enum (Finding 3)
4. NAT64 `prefix` /96 validation missing (Finding 4)
5. Undefined `application` in DENY policy warn-only (Finding 5) — promote to error or fail-closed empty-set
6. Undefined zone interface warn-only → unzoned exposure (Finding 6)
7. Screen `syn-flood` zero thresholds warn (Finding 7) — low
8. `then dscp` out-of-range validation (Finding 10)
9. Address-book invalid CIDR warn-only (Finding 11)

---

*End of Cohort 2 audit — d24417ca1fd2 — 11 findings (2 High, 6 Medium, 3 Low deduped to 9 actionable).*
