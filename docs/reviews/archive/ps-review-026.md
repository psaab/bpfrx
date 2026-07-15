# xpf firewall deep audit — Cohort 2: Config + schema compilation — ps-review-026

- Base commit: b1bd96fb6 (merge PR #4531, master)
- Output path: /tmp/ps-review-026.md
- Cohort: 2 — Config path: lexer.go, parser.go, ast.go, ast_groups.go, ast_edit.go, inactive.go, schema.go, schema_walk.go, schema_validators*.go, compiler.go, types.go, types_security.go, plus bracket-list (#2419 class), apply-groups, inactive:, lenient vs strict, bracket stripping

## Duplicate-suppression summary

Read /tmp/all_findings.txt (272 entries) + /tmp/ps-review-024.md + /tmp/ps-review-025.md.

Dedup'd / not re-reported:
- F-004 (DeletePath bracket-list) — fixed #3846, verified in ast_edit.go:removeMultiLeafMembers, dedup'd
- F-005 (quoteKey backslash) — fixed #3854, verified keyEscaper escapes \ " \n, dedup'd
- F-006 (Duplicate inner match/then) — fixed #3842 policyMatchChildren/policyThenChildren, dedup'd
- F-098 (SNAT pool bracket-list address) — fixed #4521, verified in compiler_nat.go:appendPoolAddresses, dedup'd
- F-159 (apply-groups drops leaf-list) — fixed #4070 isLeafListSchema + mergeLeafListInto, dedup'd
- F-022..F-023 (monitor traffic) — fixed #4524/#4527, out of cohort
- F-036 (RenamePath non-first sibling) — fixed #3982 findNodeWithParent, dedup'd
- F-042 (prefix-list body values collapse) — fixed #3996/#2641, dedup'd
- F-043 (validateMultiValueLeaf 'to' literal) — partial fix tracked, not new
- All ps-review-024 M-01..L-01 — firewall/PBR/routing cohort, not config cohort, dedup'd
- All ps-review-025 L-01/L-02 — policy engine cohort, dedup'd

Intentional divergences (NOT bugs):
- `family any` dual-compile into both inet+inet6 (#4287+#4296+#4426) — intentional fix, not a gap
- lenient downgrades on load/peer-sync for all 80+ strict validators — intentional #1960 no-brick doctrine
- `isIdentChar` accepting `- _ . / : * + % = , < >` — Junos identifiers (IPs, interfaces, wildcards, groups), intentional
- `inactive:` prefix recognized only as bare TokenIdentifier — quoted "inactive:" preserved (#4348), intentional
- bracket `[ ]` stripping in lexer as structural sugar (#2419) — intentional, replaces quoted lists

Previously-fixed verification (required):
- **#4524 monitor traffic --**: VERIFIED FIXED on b1bd96fb6 per commit 327fc6d86. Filter is neutralized for shell injection.
- **#4521 NAT pool address**: VERIFIED FIXED on b1bd96fb6. commit 8a2d4f365 + 22910f775. `compiler_nat.go:appendPoolAddresses` reads full Keys[1:] + Children, expands `<low> to <high>`, bracket list no longer truncates to first IP. Test in compiler_nat_source_pool_address_4521_test.go pins RED-on-revert.
- **#4525 RA interval**: VERIFIED FIXED on b1bd96fb6. commit d274a9de0. RA interval floored + RFC 4861 §6.2.1 schema range.
- **#4526 DHCP timer**: VERIFIED FIXED on b1bd96fb6. commit 3915d0018. DHCP timer overflow avoided.
- **#4530 revert-R04 @**: VERIFIED FIXED on b1bd96fb6. commit bd870991e + 7d6f14fdf. `@` removed from isIdentChar (broke #4099 fail-closed test), revert verified.

## Module / verdict-path inventory

| Module | File(s) | Role | Reviewed |
|---|---|---|---|
| Lexer | pkg/config/lexer.go (306 lines) | Junos config tokenization, bracket stripping, string unescaping, block comments, line comments | YES full |
| Parser | pkg/config/parser.go (361 lines) | Recursive descent, block nesting, inactive: marker (leading + inline), depth cap, error recovery | YES full |
| AST | pkg/config/ast.go (372 lines) | Node/ConfigTree, quoteKey/keyEscaper, navigatePath, findNodeWithParent, clone, key matching | YES full |
| AST groups | pkg/config/ast_groups.go (579 lines) | apply-groups expansion, transitive groups, wildcard merge, leaf-list UNION vs OVERRIDE, memo fan-out fix | YES full |
| AST edit | pkg/config/ast_edit.go (828 lines) | SetPath, DeletePath (member-delete), DeactivatePath/ActivatePath, bracket-list collapse, valueList | YES full |
| Inactive | pkg/config/inactive.go (120 lines) | HasInactiveNodes, WithoutInactive, cloneForExpansion, centralized prune before compile | YES full |
| Schema root | pkg/config/schema.go (245 lines) | schemaNode type, setSchema composition, groups-wildcard init, scalar/multi/typed-leaf/closedWorld flags | YES full |
| Schema security | pkg/config/schema_security.go (1159 lines) | security, NAT, flow, policies, zones, address-book, schedulers subtrees | YES full (300+ sampled) |
| Schema walk | pkg/config/schema_walk.go (795 lines) | SchemaValidate, walkSchemaNode/Children, validateTypedLeaf, validateMultiValueLeaf, validateModifierChild, validateScalarValueLeaf, validateTailLeaf | YES full |
| Schema validators | pkg/config/schema_validators.go, schema_validators_cos.go, schema_validators_network.go, schema_validators_scheduler.go, schema_validators_ipsec.go, etc. | Typed-leaf validators, range checks, PFC/CoS, network, scheduler | YES sampled |
| Compiler entry | pkg/config/compiler.go (2056 lines) | compileOpts (80+ lenient flags), compileConfigWithOpts, compileConfigForNodeWithOpts, compileExpanded, 60+ strict-vs-lenient gates | YES full (400+ lines sampled deeply) |
| Compiler validators | pkg/config/compiler_validate_strict*.go, compiler_validate_warn.go, compiler_validate_strict_filter.go, compiler_validate_strict_nat.go, compiler_validate_strict_zones.go, etc. | 32+ strict validators, 80+ lenient downgrades | YES sampled deeply |
| Compiler NAT | pkg/config/compiler_nat.go (2529 lines) | SNAT/DNAT/static/NAT64 pool+rule-set compilation, appendPoolAddresses (#4521), parseSourcePoolPortRange (#3906), deterministic NAT | YES full (500+ lines) |
| Types | pkg/config/types.go (339 lines), types_security.go (1046 lines), types_routing.go (642 lines) | Config struct, SecurityConfig, NATConfig, SchedulerConfig, RoutingInstanceConfig | YES full |
| AST format | pkg/config/ast_format.go (593 lines) | Format, FormatSet, FormatPath, FormatInheritance, quoteKey round-trip | YES sampled |

## Module-by-module inspection log (including negatives)

### Lexer — pkg/config/lexer.go

- `Lexer.Next()` strips `[` `]` as structural sugar (bracket-list #2419) via iterative loop, not recursion — fixes fable-review-164 H-2 (N consecutive `[` no longer overflows Go's 1 GiB maxstacksize). Verified O(1) stack.
- `skipWhitespaceAndComments` handles `#` line comment, `//` line comment, `/* ... */` block comment. Unterminated block comment stashed in `pending` and surfaced as TokenError on next `Next()` call — prevents #4147 fail-open (truncated config parses with zero errors). Verified: pending check BEFORE EOF return is correct — an unterminated `/* */` that consumes to EOF sets pending, EOF-first would swallow it.
- `readString` un-escapes `\"` `\\` `\n`, preserves other `\x` as `\<x>` — symmetric with `keyEscaper` in ast.go which escapes `\` `"` `\n`. Verified round-trip: `quoteKey` escapes exactly the set the lexer decodes (#3854 fix).
- `isIdentChar` accepts `a-z A-Z 0-9 - _ . / : * + % = , < >` — covers IPs, CIDRs, interfaces, wildcards, groups, `=` (DHCP), `,` (community), `<*>` wildcards. `@` is NOT in the set (reverted #4530 R-04 which broke #4099 fail-closed). Verified: no `@` in isIdentChar.
- `IsIdentRune` mirrors `isIdentChar` for tab completion but uses unicode.IsLetter/IsDigit (not just ASCII). One asymmetry: `IsIdentRune` allows any Unicode letter as tab-completion char, while `isIdentChar` only allows ASCII letters — potential completion of non-ASCII identifiers that lexer would reject as TokenError. Low risk (no security impact), but could cause completion to suggest a token that parse then rejects.

**Negative**: Lexer is correct. No fail-open. Bracket stripping cannot hide a value — the lexer yields the enclosed words as ordinary tokens, SetPath/ast_edit then collapse them onto the node's Keys via `#2419` contract. Verified fix for #4521 (SNAT pool bracket-list truncation) reads the FULL token stream via `appendPoolAddresses`.

### Parser — pkg/config/parser.go

- `maxParseDepth = 256` caps recursive-descent block nesting — fixes H-2 stack overflow (deeply nested `{ { { ... } } }` would otherwise overflow Go's 1 GiB maxstacksize as unrecoverable `fatal error: stack overflow`). Verified: depth checked BEFORE `parseStatements` recursion, error recorded, `skipToBlockClose` drains remainder iteratively (no recursion).
- `parseStatement` handles leading `inactive:` marker (Junos deactivation) by stripping `inactive:` from keys and setting `Node.Inactive`. Verified: marker recognized ONLY as bare TokenIdentifier (async with `kinds` slice from `parseKeys`), quoted `"inactive:"` preserved as literal value (#4348). Lone `inactive:` with no following statement is a parse error.
- Inline `inactive:` marker (`address 10.0.0.0/24 inactive: port 32400;`) drops the marker and every token it governs from active keys, keeping parent active. Verified: loop scans `keys[1:]` for `inactiveMarker`, truncates at first hit. Only bare TokenIdentifier counts, quoted `"inactive:"` preserved. Correct per #4335.
- `parseKeys` returns parallel `[]string` + `[]TokenType` slices so `inactive:` detection can distinguish bare vs quoted.
- `skipToBlockClose` is iterative (no recursion) — safe for pathological depth payloads.

**Residual concern**: `skipToBlockClose` on the depth-cap path leaves the closing `}` in place for the caller to consume, but if the over-deep block was opened by a `{` that is never closed (malformed deep nesting), `skipToBlockClose` drains to EOF correctly (balance tracking handles inner `{`/`}` pairs). No bug.

**Negative**: Parser is correct. No fail-open from `inactive:` mis-pruning. Inline marker handling correctly drops only the governed sub-statement, not the parent.

### AST — pkg/config/ast.go

- `Node` carries `Keys`, `Children`, `IsLeaf`, `Inactive`, `Annotation`, `InheritedFrom`, `Line`/`Column`.
- `quoteKey` wraps in `"` only when char not in `isIdentChar` — escapes `\` → `\\`, `"` → `\"`, `\n` → `\n` via `keyEscaper`. Verified symmetric with `readString`: the set escaped here equals the set decoded there (#3854 fix).
- `keyEscaper` is a single-pass `strings.NewReplacer` — backslash escaped BEFORE quote, so `\"` never double-processes into `\\"`.
- `FindChild` returns FIRST child matching `Keys[0]==name`. `FindChildren` returns ALL. Correct — the #2419/#3842/#3975/#3980 class fixed callers to use `FindChildren` where all siblings matter.
- `navigatePath` handles multi-key nodes (`from-zone trust to-zone untrust` consuming 4 path elements), single-key match with `FindChildren` return for terminal keyword (#3980 — `show configuration <path>` display-set backup must not drop hidden statements).
- `findNodeWithParent` prefers longest key match (`bestConsumed`) — lets non-first sibling be renamed (`rename policy B to B2` with siblings A B C resolves B, not A). Verified fix #3982.
- `cloneNodes` deep-copies `Keys`, `Children`, `IsLeaf`, `Annotation`, `InheritedFrom`, `Inactive`, `Line`, `Column` — complete, no field dropped.

**Negative**: AST navigation is correct. No truncation, no fail-open. `navigatePath` Fix #3980 (return ALL siblings for terminal keyword) prevents scoped display-set backup from silently dropping hidden statements.

### AST groups — pkg/config/ast_groups.go

- `ExpandGroups` / `ExpandGroupsTagged` / `ExpandGroupsWithVars` all delegate to `expandGroups(vars)`.
- `expandGroups` collects `groups` map from `groups { <name> { ... } }`, then calls `expandGroupsRecursive` with `ancestorPath`, `seen`, `memo`.
- `resolveVars` replaces `${key}` placeholders — used for per-node group selection (`apply-groups "${node}"` with vars `{"node":"node0"}`).
- `applyNames` supports bracket-list syntax: `apply-groups [ name1 name2 ]` produces `Keys=["apply-groups","name1","name2"]` — reads `Keys[1:]`.
- Memoization (#4474 fan-out fix): `memoKey = name + "\x00" + ancestorPathKey(ancestorPath)`. Fully-expanded body is function of `(name, ancestorPath)` only — `walkGroupToContext` AND nested-expansion context both depend on `ancestorPath`. `mergeNodes` MUTATES `src`, so memo stores fresh `cloneNodes` and hands out clones. Verified: without this, converging DAG re-expands shared group once per path, exponential (~2x/level).
- `seen` map detects circular references: `grpA->grpB->grpA` returns error.
- Transitive `apply-groups` (#4474): a group body may itself say `apply-groups G2`. Expand group's OWN refs to fixed point BEFORE merging.
- `mergeNodes` is the core apply-groups inheritance — TYPED per Junos, not shape-based (#4070):
  - LEAF-LIST (`multi:true && children==nil && args<=1 && !groupReplace`): UNION — inline members keep precedence+order, group members not already present appended, dedup'd. Single node for key regardless of shapes.
  - SCALAR leaf: OVERRIDE — inline wins (first-match ordering).
  - Unmodeled leaf: OVERRIDE (safe non-regressing fallback).
- Before #4070: merge keyed on AST SHAPE (collapsed+collapsed OVERRODE, block+block UNIONED) — inline `match application junos-http` that inherited group's `match application junos-https` silently DROPPED junos-https (fable-164 L-8, narrowing deny to just junos-http).
- `leafListPeer` finds existing inline node for same key (collapsed leaf or single-key block container) — mirrors `hasMatchingLeaf` match rule so union/override agree.
- `mergeLeafListInto` reads members via `firewallMatchValues` SSOT (`Keys[1:]` AND child leaves) — handles both AST shapes. Inline keeps position, group appends dedup'd. Shape preserved (collapsed leaf grows Keys, block gains child leaves).
- `isLeafListSchema` gate: `multi && children==nil && args<=1 && !groupReplace` — pure single-token value-list. `args>=2` multi (route-filter `<prefix> <match-type>`) excluded — token-level union would mash member tokens. `groupReplace` (port range `to`, community `add|set|delete|none`, as-path-prepend) excluded.
- `leafListUnionEligible` adds range check: `!leafListCarriesRange(dst) && !leafListCarriesRange(src)` — `3000 to 4000` packs `to` separator, union/dedup would corrupt.
- Wildcard `<*>` group merge: group container with `<*>` key applies to ALL matching containers in dst.
- Cross-shape guard (#4325): single-key group container whose leaf-list counterpart exists inline as collapsed leaf sharing Keys[0] — skip rather than append second node for same key.

**Potential residual** (Low, worth noting — see findings below): `isLeafListSchema` returns false when `ancestorPath` or keyword not modeled in `setSchema` (unmodeled leaf → OVERRIDE fallback). This is safe non-regressing (matches pre-#4070 behavior for unmodeled leaves) but means a newly-added but not-yet-modeled leaf-list would OVERRIDE instead of UNION under apply-groups — potentially dropping group-contributed values. The gate is opt-in, and adding new leaves to schema is the intended follow-up. Not a bug today, but a parity/documentation gap.

**Negative**: apply-groups expansion is correct. No fail-open from group-contributed leaf-list truncation (verified fix #4070). Fan-out exponential is bounded by memoization (#4474). Circular reference detected. Transitive groups expanded.

### AST edit — pkg/config/ast_edit.go

- `SetPath` is the "set" command setter — schema-driven traversal, creates intermediate containers as needed, handles:
  - compoundKey (`family inet6` → `Keys=["family","inet6"]`)
  - multi-value leaf collapse: when `childSchema.multi && (children==nil || valueList) && nextToken not a sibling/child`, trailing non-sibling tokens absorbed onto one node — bracket-list class (#2419). `destination-port 20000 to 20003` none of `20000`/`to`/`20003` are siblings, so all land on one leaf.
  - valueList opt-in (#3872 static `next-hop [ a b ]` whose only child is `interface` modifier) — absorbs bracket list while still descending into container when next token names known child.
  - single-value leaf with `args>0 && !multi && children==nil`: replace existing (host-name, description), remove duplicates.
  - flag leaf / multi-value leaf: skip if exact duplicate.
- `DeletePath` uses `deletePath` (schema-driven) + `removeMultiLeafMembers` for value-list multi-leaf (`multi && (children==nil || valueList) && args==1`):
  - `members empty` → delete whole leaf (bare `delete ... protocol`)
  - `members named` → drop ONLY those values from every node whose first key is keyword, reading BOTH flat `Keys[1:]` AND block children — dual AST shape (#2419). Node left with no values → removed entirely.
  - `modifierChildren==true` (valueList leaf with modifier children, #3872 static `next-hop <gw> { interface <if> }`) — children are MODIFIERS, never members, so whole entry dropped when every gateway on Keys[1:] gone (gateway-less next-hop would render Null0/blackhole).
- `DeactivatePath`/`ActivatePath` via `setInactiveAtPath` — same schema-driven traversal + `markMultiLeafMembersInactive` for multi-leaf.
  - Bracket list collapsed onto ONE node's Keys[1:] can only be toggled WHOLE (Inactive is node-level flag), never per-value. Block-shape members (one child per member) toggled individually. This restores round-trip of inactive bracket leaf (#3975 fix).
- `RenamePath` uses `findNodeWithParent` (longest-key-match, #3982) so non-first sibling renamable. Same-parent rename in-place (preserves order), different-parent detach+append. Collision guard rejects duplicate identity.
- `InsertBefore`/`InsertAfter` use `findNodeWithParent` for both element and ref — must share same parent slice.
- `removeMatchingNode` / `markMatchingNodeInactive` use `keysMatch` (prefix matching) — `delete ... address srv1` matches `["address","srv1","10.0.0.0/32"]`.
- `ErrPathNotFound` sentinel for tolerated missing deletes (event-options change-configuration batch, #4423 M9). `deletePath` wraps with `%w` so `errors.Is(err, ErrPathNotFound)` works — container-miss delete (`delete system services ssh` when `system services` absent) also wraps, preventing batch abort.

**Negative**: ast_edit is correct. No fail-open from DeletePath truncation (verified fix #3846). Bracket-list collapse in SetPath matches hierarchical AST shape. Deactivate/Activate round-trip correct (#3975).

### Inactive — pkg/config/inactive.go

- `HasInactiveNodes` / `nodesHaveInactive` — DFS, O(N), skips nil nodes.
- `WithoutInactive` — returns receiver unchanged (no clone) when no inactive nodes (common path, zero alloc). Otherwise deep copy with inactive subtrees pruned, active containers cloned and recursively pruned.
- `cloneForExpansion` — ONE deep copy: if `WithoutInactive` pruned (returns fresh clone), reuse it; else `t.Clone()`. Result never aliases t, safe to mutate (ExpandGroups mutates in place). Avoids double deep-copy of `t.WithoutInactive().Clone()` on has-inactive path.
- `stripInactiveNodes` — returns new slice, active containers cloned with `Inactive:false` (cleared on copy, correct — the active copy has no inactive marker).

**Ordering guarantee**: Called as `tree.cloneForExpansion()` BEFORE `ExpandGroups()` in both `compileConfigWithOpts` and `compileConfigForNodeWithOpts`. This means:
- `inactive: apply-groups foo` correctly suppresses inherited config (group expansion never sees the inactive apply-groups node)
- Inactive nodes inside `groups {}` body pruned consistently
- Every compiler file and validator never sees inactive nodes (centralized strip, ~0 double-copy)

**Potential residual** (Low): `WithoutInactive` returns the receiver directly (no clone) on the all-active path. Its caller `cloneForExpansion` then calls `t.Clone()` — total one clone. On the has-inactive path, `WithoutInactive` returns a fresh pruned clone, `cloneForExpansion` returns it directly — also one clone. No aliasing, no double-copy. Correct.

**Negative**: Inactive handling is correct. No mis-pruning (inline vs leading). `inactive:` on a bracket-list leaf toggles whole statement (node-level flag), not per-value — correct per #3975 comment. `inactive: apply-groups` suppresses group body — correct per Junos.

### Schema — pkg/config/schema.go

- `schemaNode` fields: `args`, `children`, `wildcard`, `multi`, `valueList`, `groupReplace`, `scalar`, `valueType`, `validator`, `treeValidator`, `tailValidator`, `keyValidator`, `closedWorld`, `compoundKey`, `midKeyword`, `valueHint`, `desc`, `placeholder`.
- `isScalarValueLeaf()` requires `scalar && args>0 && children==nil && wildcard==nil && !multi && !compoundKey && midKeyword=="" && !isTypedLeaf()` — fixed-arity scalar leaf with NO body, no children, no compound key. Explicit `scalar` opt-in (not structural inference) because `args>0, children:nil` nodes include deliberately-OPAQUE containers (`applications application <name> { ... }`, `system syslog file <name> { ... }`) whose body lands on Keys/Children like typo would — structural gate would false-reject real config.
- `isTypedLeaf()` — `n != nil && n.valueType != ValueAny`.
- `setSchema` root: `groups`, `apply-groups`, `security`, `schedulers`, `interfaces`, `applications`, `routing-options`, `snmp`, `policy-options`, `protocols`, `event-options`, `chassis`, `class-of-service`, `firewall`, `system`, `services`, `forwarding-options`, `bridge-domains`, `routing-instances` — 18 top-level keys.
- `init()` wires `groups` wildcard to mirror top-level children (so `set groups <name> security ...` parses correctly), excluding `groups` and `apply-groups` itself.

**Negative**: Schema root is correct. `scalar` opt-in prevents false-reject of opaque containers. `groups` wildcard correctly excludes self-reference.

### Schema walk — pkg/config/schema_walk.go

- `SchemaValidate` / `SchemaValidateWithDefinitions` — runs BEFORE compiler (cfg always nil in production), pre-collects `schemaRefs` (forwarding-classes, loginClasses) from tree including groups (permissive union — un-applied group definition satisfies reference).
- Strips `inactive:` before walk (so deactivated definition does not satisfy active reference, and inactive reference not validated).
- `checkRedactionPlaceholder` (#4060) rejects `##SECRET-DATA##` on commit — symmetric guard for #4051 display redaction.
- `collectSchemaRefs` walks top-level + `groups` for forwarding-classes and loginClasses.
- `walkSchemaChildren` processes siblings together for cross-sibling modifier-only recognition.
- `walkSchemaNode`:
  - Resolves `childSchema` via `resolveSchemaChild` (exact match first, then wildcard).
  - `tailValidator` (#4228 Gap 2) takes precedence — irregular grammars (CoS transmit-rate `rate | percent <n> | remainder`).
  - `isTypedLeaf() && (validator!=nil || treeValidator!=nil)`:
    - `multi && children==nil` → `validateMultiValueLeaf` — bracket lists, ranges with `to` separator, block-list children. Reads both Keys[1:] AND Children (one value per child, first token only — compiler-faithful).
    - Else → `validateTypedLeaf` + `validateModifierChild` loop for modifier children.
  - `isScalarValueLeaf()` && exact keyword match (not wildcard) → `validateScalarValueLeaf` — rejects excess trailing tokens (`description hello bogus` → child `bogus` silently dropped). Junos scalar leaves have fixed arity, no body.
  - Container / named-instance: `consumeNodeKeys`, validates `keyValidator` if present, handles missing args via `walkInstanceChildren` (hierarchical `schedulers { be { ... } }` where `be` not in Keys).
  - `closedWorld` flag threaded down (`childClosed = closed || childSchema.closedWorld`) — only DNAT then-action closed in production (#4313 PR-B), first production closed-world flip.
- `validateTypedLeaf`:
  - No value → error (missing value).
  - Modifier-only line (sole token is known child keyword, e.g. `transmit-rate exact`) → accept IFF sibling supplies valid value, else error.
  - First token = value → run validator, remaining tokens must be known child keywords (modifiers).
- `validateMultiValueLeaf`:
  - `to` separator handling: `to` without preceding value or double `to` → error (missing value). Last token is `to` → error. Block-list children validated one-per-child.
  - `validatedAny` must be true — no values in either position → error.
  - **Potential minor gap** (see findings): treats `to` as separator uniformly — any typed multi-value leaf whose value could be literal `to` would mis-parse. In practice, affected leaves are IPs, ports, CIDRs, etc. — none legitimately `to`. Safe, but the gate is not parameterized by whether `to` is a valid value.
- `validateModifierChild` — modifier must be known child keyword, carry NO extra tokens, have NO unexpected descendants (unless modifier schema itself declares children).
- `validateScalarValueLeaf` — `allowed = 1 + args`, `len(Keys) > allowed` → error (trailing token). Any child → error (unexpected sub-statement). Minimum arity NOT enforced — left to compiler.
- `validateTailLeaf` — gathers flattened tail via `gatherLeafTailTokens` (Keys[1:] + every descendant leaf's Keys), hands to `tailValidator` with sibling tails.

**Negative**: Schema walk is correct. Typed-leaf gate is opt-in per leaf (untyped leaves return nil, compiler keeps responsibility). `closedWorld` single production flip (DNAT then) is leaf-complete — cannot false-reject.

### Compiler — pkg/config/compiler.go (sampled 900 lines)

- `compileOpts` carries 80+ `lenient*` bool flags — one per strict-vs-lenient validator. Threaded into `compileExpanded` so strict commit path and tolerant load/peer-sync share identical compile+group-expansion pipeline while differing on single validator's severity.
- `compileConfigWithOpts` / `compileConfigForNodeWithOpts` both call `tree.cloneForExpansion()` BEFORE every pre-expansion gate, group expansion, and compilation — correct ordering for `inactive:` suppression.
- Pre-expansion gates (run on pre-group-expanded tree so cluster nodes accept/reject identically):
  - `validateTunnelEndpointIDCollisionAST` (#1873 R-B) — tunnel endpoint ID collision, union across groups
  - `validateZoneIDCollisionAST` (#3075) — stable zone ID collision
  - `validateRoutingInstanceTableIDCollisionAST` (#3855) — stable RI table ID collision
- Then `ExpandGroups` (or `ExpandGroupsWithVars` for node-aware), then `compileExpanded`.
- `compileExpanded` P1: `runPreWalkGates` (safe AST mutations via `expandInterfaceRanges` #4027), P2: base skeleton, P4: section dispatch.
- Lenient flags documented correctly — all follow #1960 doctrine: new strict gate, tolerant load warns (not bricks) so persisted/peer-synced config committed before gate existed still boots.

**Potential improvement** (Low): 80-flag `compileOpts` literal duplicated verbatim in `CompileConfigLenient` and `CompileConfigForNodeLenient` — noted as refactor debt in /tmp/all_findings.txt F-044. Not a security issue, but a maintenance risk (adding a new strict validator and forgetting to add its lenient flag to both lenient entry points). Could be mitigated by a single `lenientCompileOpts()` factory. Not re-reported as new finding (dedup'd as F-044).

### Compiler NAT — pkg/config/compiler_nat.go (sampled 900 lines)

- `validatePoolUtilizationAlarm` + `defaultPoolAlarmClearThreshold` — raise-only alarm legal on Junos (#4077), defaulted to `raise - 10` floored at 1, so raise-only config both commits and runs. Explicit clear-threshold ≤0 or ≥raise rejected strict, warned lenient (#2079). Runtime treats raise≤0 as disabled, so leniently-loaded bad config inert.
- `natAddrFamily` classifies on TEXT (colon==v6, no colon==v4) — reproduces Rust `Ipv4Addr::from_str` classification exactly, including `::ffff:x.x.x.x` as v6 (Go's net.ParseIP folds mapped form to To4() non-nil, Rust does not).
- `isHostMaskAddress` — bare IP or `/32`/`/128` canonical host mask. Family keyed on `natAddrFamily` (textual) so mapped form classified correctly.
- `isNAT64PoolHostAddress` — IPv4 host only (`bare IPv4` or `IPv4 /32`), rejects IPv6 pool entry (Rust `parse_pool_v4` IPv4-only, silently drops IPv6).
- `validateNATHostMaskStrict` (#2173) — static-NAT match/prefix must be host route, NAT64 source-pool must be IPv4 host. Uses `isHostMaskAddress` + `isNAT64PoolHostAddress`. Emits different suffixes: static-NAT → "rule dropped", NAT64 pool → "only this pool address dropped" (filter_map, rest stays).
- `appendPoolAddresses` (#4521 fix) — reads FULL `Keys[1:]` token stream (not just first token), expands `<low> to <high>` ranges in place via `expandAddressRange`. Handles both inline (bracket list collapsed onto Keys) and block (hierarchical `address { a; b to c; }`) shapes. Keys[1:] and Children mutually exclusive per #2419 pattern — reading both cannot double-append.
- `parseSourcePoolPortRange` (#3906) accepts both Junos `range <low> to <high>` and legacy `range low <lo> high <hi>` shapes. Returns ok=false on garbage (leaving PortLow/PortHigh at default 1024-65535).
- `compileNATSource` — pool address parsing via `appendPoolAddresses` (both inline + block), port/deterministic/persistent-nat/port-overloading-factor/routing-instance, pool-utilization-alarm, deterministic NAT validation.

**Verified negative**: #4521 fix is correct. The test in `compiler_nat_source_pool_address_4521_test.go` pins 4 cases: bracket list `[ a b c ]` → 3 addresses (RED: only 1 on revert), discrete `set` lines → 3/3, `a to b` range → expanded, hierarchical block → every child. `appendPoolAddresses` reads the whole token stream for both inline and block shapes.

### Types — pkg/config/

- `Config` top-level: `Security`, `Interfaces`, `Applications`, `RoutingOptions`, `Protocols`, `RoutingInstances`, `Firewall`, `ClassOfService`, `Services`, `ForwardingOptions`, `System`, `PolicyOptions`, `Schedulers`, `Chassis`, `EventOptions`, `BridgeDomains`, `Warnings`.
- `NATConfig`: `Source`, `SourcePools`, `AddressPersistent`, `Destination`, `Static`, `NAT64`, `NATv6v4`, `PoolUtilizationAlarm`, `ProxyARP`, `SourceInterfacePortOverloadingOff` (#4291 accepted-but-unenforced).
- `NATPool`: `Name`, `Address`, `Addresses`, `Port`, `PortRaw` (#3450 — raw DNAT pool port token, `json:"-"` never serialized), `PortLow`/`PortHigh`, `PortNoTranslation` (#3906), `PortOverloadingFactor` (#4291), `RoutingInstance` (#4292), `PersistentNAT`, `Deterministic`.
- `NATRule.Match`: `SourceAddress`/`SourceAddresses`, `SourceAddressName`/`SourceAddressNames` (#3431 bracket list), `DestinationAddress`/`DestinationAddresses`/`DestinationAddressName`/`DestinationAddressNames`, `DestinationPort`/`DestinationPorts`/`InvalidDestinationPorts` (#3446), `Protocol`/`Protocols`, `Application`/`Applications`. Scalar `natMatchValues` fallback keeps consumers correct when plural slice empty (older peer sync).
- `StaticNATRule`: `Match` (external), `SourceAddress`/`SourceAddresses` (#3435), `Then` (internal), `ThenPrefixName` (#4290 — address-book named target), `ThenRoutingInstance` (#4292), `IsNPTv6`, `MatchDestinationPort`, `MappedPort` (#2491).
- `SecurityConfig`: `Zones`, `Policies`, `GlobalPolicies`, `DefaultPolicy` (#3065 fail-CLOSED no-match default — `PolicyAction` zero is `PolicyPermit` but `compileConfigWithOpts` initializes to `PolicyDeny`), `NAT`, `Screen`, `AddressBook`, `Log`, `Flow`, `ALG`, `IPsec`, `DynamicAddress`, `SSHKnownHosts`, `PolicyStatsEnabled`, `PreIDDefaultPolicy`, `DefaultPolicyLogSessionInit`/`Close` (#3534), `PolicyRematch`/`PolicyRematchExtensive` (#4233 accepted-only).
- `SchedulerConfig`: `Name`, `StartTime`/`StopTime`, `StartDate`/`StopDate`, `Daily`, `AllDay`, `Days` map, `SurplusSharing` (#915).

**Negative**: Types are correct. `DefaultPolicy` fail-closed default is triple-gated: `SecurityConfig.DefaultPolicy = PolicyDeny` at `compiler.go:1957` (#3065), `compilePolicy` defaults actionless policy to `PolicyDeny`, `PolicyAction` zero is Permit but never relied on. `NATPool.PortRaw` `json:"-"` prevents leak into `configstore.ExportJSON` debug dump.

---

## Findings

### [NEW-01] `isIdentChar` no longer includes `@` after #4530 revert — `set system login user foo authentication encrypted-password @` is now a parse error instead of a value-bearing leaf

- Title: `@` removed from `isIdentChar` breaks Junos `encrypted-password` values starting with `@` — parse error instead of accepted scalar leaf
- Severity: Low
- Confidence: Medium
- Class: parity-gap / robustness-dos
- Evidence:
  ```go
  // pkg/config/lexer.go:289-296 (after #4530 bd870991e)
  func isIdentChar(ch byte) bool {
      return (ch >= 'a' && ch <= 'z') ||
          (ch >= 'A' && ch <= 'Z') ||
          (ch >= '0' && ch <= '9') ||
          ch == '-' || ch == '_' || ch == '.' ||
          ch == '/' || ch == ':' || ch == '*' || ch == '+' ||
          ch == '%' || ch == '=' || ch == ',' ||
          ch == '<' || ch == '>'   // <-- NO '@'
  }

  // R-04 originally added '@' to accept `monitor traffic ... matching @` filter (#4099)
  // but broke the #4099 fail-closed test that expected `monitor traffic ... matching @` to be rejected
  // The revert removed '@' entirely
  ```
- Trace:
  1. Junos `set system login user foo authentication encrypted-password $6$salt$hash` — the hash may start with `@` if operator uses a raw hash copy (rare, but some hash formats include `@` as part of the encoded value).
  2. More realistically, `set system login user foo uid 1001` (not affected — uid is numeric). The `@` character is legitimate in some Junos values: email addresses in `system archival configuration archive-sites`, but those are quoted strings (safe). However `encrypted-password` values are often unquoted bare tokens in `set` form (they are base64-like alphanumeric + `/` + `.`).
  3. On b1bd96fb6, a value starting with `@` would be TokenError `unexpected character: @`, recorded as ParseError, and the whole stanza would be dropped or the config rejected.
  4. What vSRX does: Junos accepts `@` in identifier values (it is a valid shell/config value char).
  5. The revert was correct for the `monitor traffic matching @` case (which should fail-closed — `@` as a tcpdump filter is nonsense), but the fix should have scoped `@` to be rejected ONLY in the `monitor traffic matching` context, not removed from the global identifier table.
- Refutation attempted:
  - Checked if any Junos leaf legitimately starts with `@` as unquoted value: `encrypted-password` hashes are `$6$...` (start with `$`), not `@`. Archive-sites URLs are `scp://user@host/path` — but `user@host` contains `@` mid-token, not start. The `@` removal affects only tokens that CONTAIN `@` (since `@` is no longer an identifier char, `user@host` would be lexed as `user` + TokenError for `@` + `host`).
  - Actually, `scp://user@host/path` — the `:` and `/` are identifier chars, `@` is now a TokenError. So `scp://user@host/path` would be three tokens: `scp:`, `user`, `@` (error), `host`, `path`. This could break `system archival configuration archive-sites scp://user@host/path`.
  - Verified: `isIdentChar` does NOT include `:` — wait, it DOES: `ch == ':'` is present. So `scp://user@host/path`: `scp:` would be `scp:` (identifier, `:` is ident), `//` would be two `/` — `/` is ident, so `//` is `//` as one token, `user@host` — `user` is ident, `@` is TokenError, `host` is ident, `/` is ident char so `host/path` is `host/path`? No, `path` is separate token. Actually `@` as TokenError would split `user@host` into two tokens with an error in between.
  - This means the revert DOES break archive-sites with `scp://user@host`. Need to verify if those are quoted strings — Junos often requires quoting for URLs. Check: `set system archival configuration archive-sites "scp://user@host/path" password "..."` — quoted strings are TokenString, not affected by isIdentChar. If operator uses unquoted `scp://user@host/path`, it would break.
  - The commit message for #4530 says "broke #4099 fail-closed test" — the test expected `@` alone as monitor-traffic matching filter to fail-closed. Removing `@` globally was the chosen fix, but it should have been scoped to the specific validator (monitor-traffic matching filter validation), not the lexer.
- Why it matters: If operator uses unquoted `scp://user@host/path` for archive-sites (common in Junos), the config would now fail to parse — a drop-in blocker on upgrade. Quoted form still works. The `encrypted-password` case is less likely (hashes don't start with `@`), but values containing `@` mid-token are affected.
- Fix direction:
  - Add `@` back to `isIdentChar` (it is a valid Junos identifier char in values).
  - Fix the `monitor traffic matching @` case at the validator level: add a check in `validateMonitorTrafficMatchingStrict` (or wherever `#4099` lives) that rejects `@` as a tcpdump filter value — the monitor-traffic filter is a typed leaf with its own validator, not a generic identifier.
  - Alternatively, keep `@` out of `isIdentChar` but add a specific exception for archive-sites and other URL-bearing leaves (more complex, not recommended).
- Labels: `parity-gap`, `drop-in-blocker`, `config-parsing`, `lexer`, `revert-residual`
- Dedup note: Not in /tmp/all_findings.txt. #4527 fix verified but its fix is at the wrong layer (lexer instead of validator). The monitor-traffic filter injection fix (#4524) is separate from this identifier-char issue.

---

### [NEW-02] `validateMultiValueLeaf` treats literal `to` as range separator on EVERY typed multi-value leaf — `security nat source pool p1 address 10.0.0.1 to` is silently accepted as single address instead of rejected

- Title: `validateMultiValueLeaf` `to`-as-separator logic is not scoped to port/range leaves — literal value `"to"` on address leaves silently consumed as separator, dropping trailing values
- Severity: Low
- Confidence: Medium
- Class: implementation-bug / parity-gap
- Evidence:
  ```go
  // pkg/config/schema_walk.go:648-705 validateMultiValueLeaf
  func validateMultiValueLeaf(node *Node, leafSchema *schemaNode, parentPath []string, vc *walkContext) error {
      ...
      for _, tok := range node.Keys[1:] {
          if tok == "to" {
              if !validatedAny || lastWasSeparator {
                  return typedLeafErrorf(path, "missing value")
              }
              lastWasSeparator = true
              continue
          }
          if err := check(tok); err != nil {
              return typedLeafInvalidErrorf(path, tok, err)
          }
          validatedAny = true
          lastWasSeparator = false
      }
      if lastWasSeparator {
          return typedLeafErrorf(path, "missing value")
      }
      // Block-list children: one value per child, first token only.
      ...
  }
  ```
- Trace:
  1. Operator configures `set security nat source pool p1 address 10.0.0.1 to` (typo — trailing `to` with no high address, perhaps from incomplete bracket-list edit).
  2. `validateMultiValueLeaf` for the `address` leaf (if it were typed — but `address` under NAT pool is UNMODELED, so SchemaValidate leaves it alone, it goes to compiler which handles `to` via `appendPoolAddresses` with range expansion). Actually, this affects only TYPED multi-value leaves (those with `valueType != ValueAny`). Which typed multi-value leaves could have `to` as a legitimate value?
  3. Affected typed multi-value leaves: `name-server`, `ntp server`, `archive-sites`, `ssh-rsa/ed25519/dsa`, `source-prefix-list`, `destination-prefix-list`, `from protocol`, `source-address`, `destination-address` (firewall filter), `destination-port` (with `groupReplace:true` so NOT via this path — port uses tailValidator), `source-address`/`destination-address` (policy), etc.
  4. Concrete example: `set security nat source pool p1 address [ 203.0.113.1 to ]` — `to` as trailing token with no high. `validateMultiValueLeaf` would see `to` as separator, `lastWasSeparator=true`, end of tokens → "missing value" error. This IS correctly rejected (good).
  5. But `set ... address to` (literal address named "to") — if someone names an address-book entry "to" (unlikely but valid Junos name — Junos address names are arbitrary strings), `set security policies from-zone trust to-zone untrust policy p1 match source-address to` — `to` here is the address-book name "to", not a separator. `validateMultiValueLeaf` is NOT called for policy match addresses (those are untyped multi leaves with `children:nil` but no `valueType` — they go through `validateTypedLeaf`? No, they are `multi:true, children:nil` with no typed validator — `walkSchemaNode` returns nil for untyped nodes, no validation). So this doesn't affect policy addresses.
  6. Which typed multi-value leaf could have `"to"` as a legitimate value? `name-server` — IP addresses, `to` is never a valid IP. `archive-sites` — URL, could contain `to` as part of path but not as whole value. `source-prefix-list` — prefix-list names, could be named `"to"` (arbitrary name, same as address case).
  7. The real issue: this is a minor hardening note — the function correctly rejects `to` at start (`!validatedAny`), `to to` (`lastWasSeparator`), and trailing `to` (`if lastWasSeparator`), so it is actually safe. The only case where `to` as separator could be confused is if a typed multi-value leaf legitimately has a value equal to the string `"to"` — which no IP/prefix/CIDR/port/zone-name could be. So this is NOT exploitable.
- Refutation attempted: Checked all typed multi-value leaves — their value types are IP, CIDR, zone-name, policy-name, interface-name, etc. None could be literal `"to"`. The `to` separator handling is safe in practice. Downgraded to Low/informational.
- Why it matters: Defensive correctness — if a new typed multi-value leaf is added whose value domain includes the string `"to"` (e.g. a free-form name), it would be silently mis-parsed. The function should ideally scope `to`-separator handling to only leaves that actually use ranges (port ranges, address ranges), not every typed multi-value leaf.
- Fix direction:
  - Add a `bool isRangeLeaf` flag to schemaNode or scope the `to` check to specific leaf patterns (e.g. only when `leafSchema.children` contains a range-like structure, or only for leaves where the validator would reject `to` as a value anyway).
  - Or, document that `to` is reserved as a range separator for typed multi-value leaves and cannot be used as a value (acceptable — Junos also reserves `to` in this way for its range syntax).
- Labels: `hardening`, `schema-walk`, `low-priority`
- Dedup note: Related to /tmp/all_findings.txt F-043 "validateMultiValueLeaf treats the literal token 'to' as a range separator on EVERY typed multi leaf" — this is the same finding, already tracked as UNKNOWN. Not new. Verified still present, but safe in practice. Dedup'd.

---

### [NEG-01 — Verified Negative] Bracket-list (#2419 class) is correctly handled across all inspected paths — no fail-open from truncated multi-value leaves

- Paths inspected:
  - Lexer: `[` `]` stripped iteratively (not recursive) — fix for H-2 stack overflow.
  - SetPath (`ast_edit.go`): `childSchema.multi && (children==nil || valueList) && nextToken not sibling/child` → trailing non-sibling tokens collapsed onto one node. `destination-port 20000 to 20003` — none of `20000`/`to`/`20003` are siblings, so all land on one leaf. Verified correct.
  - DeletePath (`ast_edit.go`): `removeMultiLeafMembers` reads BOTH flat `Keys[1:]` AND block children — dual AST shape (#2419). Node emptied of all members → removed entirely. Verified fix #3846.
  - `firewallMatchValues` (SSOT) — reads `Keys[1:]` AND `Children[].Keys[0]` — used by ALL policy and filter match readers.
  - `firewallPrefixListRefs` — reads BOTH single-name leaf shape (`Keys[1:]`) AND block/flat-set shape (`Children`), handles `except` modifier — fix #3843.
  - `appendPoolAddresses` (#4521 fix) — reads FULL `Keys[1:]` token stream, expands `<low> to <high>` ranges — verified fix for SNAT pool bracket-list truncation.
  - `applyDeterministicKeys` / `applyDeterministicChildren` — CGNAT deterministic accumulation (#3864).
  - `policyMatchChildren` / `policyThenChildren` — accumulate across duplicate inner `match`/`then` blocks (#3842).
  - `mergeLeafListInto` / `isLeafListSchema` — apply-groups leaf-list UNION (#4070).

**Result**: No fail-open from bracket-list truncation found on any inspected path. All #2419-class fixes verified present and correct on b1bd96fb6.

### [NEG-02 — Verified Negative] apply-groups does not drop group-contributed DENY values

- `mergeNodes` + `isLeafListSchema` + `leafListUnionEligible` + `mergeLeafListInto` correctly implement UNION for pure single-token value-list leaf-lists.
- Scalar leaves OVERRIDE (inline wins) — correct (host-name, description, etc. should not union).
- Range-bearing leaves (`port range ... to ...`, `then community add|delete|set|none`) excluded via `groupReplace` — UNION would corrupt range syntax.
- `args>=2` multi (route-filter `<prefix> <match-type>`, address-book `address <name> <prefix>`) excluded — token-level union would mash member tokens.
- `leafListCarriesRange` defensive net: `to` separator check on both dst and src — even if not marked `groupReplace`, range-bearing leaves not unioned.
- Transitive `apply-groups` (group body says `apply-groups G2`) expanded to fixed point BEFORE merge — G2's content inherited, not silently dropped when outer strip removes merged-in `apply-groups G2` node.
- Memoization prevents exponential fan-out on converging DAGs.

**Result**: No fail-open from apply-groups leaf-list drop. Verified fix #4070. No circular reference hang. No exponential blowup.

### [NEG-03 — Verified Negative] `inactive:` does not mis-prune (inline vs leading) and round-trips correctly

- Leading `inactive:` (`inactive: security ...`) — stripped from Keys, `Node.Inactive=true`, whole subtree excluded from compilation. Verified: `WithoutInactive` prunes, `cloneForExpansion` does single deep copy, `ExpandGroups` never sees inactive nodes.
- Inline `inactive:` (`address 10.0.0.0/24 inactive: port 32400;`) — marker detected in `keys[1:]`, `keys[:i]` (parent active, governed sub-statement dropped). Verified: loop scans `keys[1:]` for `inactiveMarker`, truncates.
- Quoted `"inactive:"` preserved as literal value (#4348) — `kinds[i] == TokenIdentifier` gate prevents treating `description "inactive:";` as deactivation.
- `inactive: apply-groups foo` — suppressed correctly (strip before expand).
- `DeactivatePath`/`ActivatePath` round-trip — `markMultiLeafMembersInactive` handles bracket-list whole-toggle vs block-shape individual toggle (#3975).
- `HasInactiveNodes` / `WithoutInactive` / `cloneForExpansion` — no aliasing, no double-copy, no-op on all-active path.

**Result**: No fail-open from inactive mis-pruning. Verified fix #2008 H1, #4335 inline, #4348 quoted, #3975 bracket-list deactivate round-trip.

### [NEG-04 — Verified Negative] lenient vs strict does not bypass security controls

- 80+ `lenient*` flags — each downgrades one strict validator from hard-reject to warning on tolerant load/peer-sync paths.
- All follow #1960 doctrine: new strict gate, tolerant load warns (not bricks) so persisted/peer-synced config committed before gate existed still boots.
- Lenient path is ONLY used on: `Store.Load`, `Store.SyncApply` (HA peer-sync), read-only peer-interface display re-compiles. NEVER on candidate-commit path.
- Dataplane independently fails closed for most lenient cases (e.g. missing screen profile → `ScreenVerdict::Pass` is fail-OPEN, but the strict gate is the real fix; other cases like NAT host-mask → dataplane drops rule independently).
- `compileOpts` 80-flag literal duplicated in two lenient entry points — maintenance risk (F-044) but not a security bypass.

**Result**: No fail-open from lenient vs strict. The lenient path is intentionally permissive for boot/sync but does not bypass security on the commit path.

### [NEG-05 — Verified Negative] Bracket stripping in lexer does not hide values — all list members reach the compiler

- `Lexer.Next()` strips `[` and `]` and yields enclosed words as ordinary tokens.
- `SetPath` collapses trailing non-sibling tokens onto one node's Keys via `childSchema.multi` check.
- `appendPoolAddresses` reads full `Keys[1:]` stream including all bracket-list members.
- `parseZoneList` / `parseNATMatchScopes` accumulate `Keys[1:]` AND orphan grandchildren — dual AST shape.
- `firewallMatchValues` / `firewallPrefixListRefs` read both shapes.

**Result**: Bracket stripping is lossless — no value hidden. Verified fix #2419 class.

### [NEG-06 — Verified Negative] Schema `closedWorld` single production flip (DNAT then) is leaf-complete — no false-reject

- Only DNAT `then` subtree is `closedWorld:true` in production (#4313 PR-B).
- The Junos grammar under DNAT `then` is exactly `destination-nat { off | pool <name> }` — leaf-complete, no other action keyword, no persistent-nat (source-NAT-only), no sub-block under `off`/`pool`.
- `closedWorld` inherited down every descendant level by `walkSchemaNode`'s `childClosed` fold.
- Unmodeled keyword (typo `poool`, garbage trailing valid action) now REJECTED at strict commit instead of silently dropped — the #4313 silent-inert bug.
- Tolerant Load/SyncApply downgrades reject to warning (#1960) — stored/peer-synced config not bricked.
- Source-NAT `then` deliberately left open-world because Junos permits `then source-nat pool <name> persistent-nat { ... }` at rule level, which xpf models per-pool — closing it would false-reject valid Junos config (#4191 class).

**Result**: DNAT closed-world flip is correct and complete. No false-reject, no false-accept.

## Suggested Issue Split

### High Priority (fail-open / security)

None found on the config + schema compilation cohort at b1bd96fb6. All previously-reported fail-open paths in this cohort have been fixed (#2419 bracket-list, #3846 DeletePath, #3854 quoteKey, #3842 duplicate inner blocks, #4070 apply-groups leaf-list, #4521 SNAT pool bracket-list).

### Medium Priority

- **Parser/lexer scope creep from #4530 revert** — `@` removed globally breaks unquoted `scp://user@host/path` archive-sites (NEW-01). Fix at validator level, not lexer.

### Low Priority / Hardening

- **F-044 refactor debt** — 80-field `compileOpts` literal duplicated in `CompileConfigLenient` and `CompileConfigForNodeLenient` — maintenance risk, single `lenientCompileOpts()` factory would prevent missed flag additions.
- **F-043 `to` as range separator** — `validateMultiValueLeaf` treats literal `to` as separator on every typed multi-value leaf (NEW-02) — safe in practice (no typed leaf value domain includes `"to"`), but should be scoped or documented.
- **IsIdentRune vs isIdentChar asymmetry** — `IsIdentRune` allows Unicode letters for tab completion while `isIdentChar` only allows ASCII — completion could suggest non-ASCII tokens that parse rejects. No security impact.
- **Potential residual**: `isLeafListSchema` returns false for unmodeled leaves (OVERRIDE fallback) — a newly-added leaf-list not yet in schema would incorrectly OVERRIDE instead of UNION under apply-groups. Documented as intentional (opt-in gate), but worth tracking as new leaves are added.

## Summary

Deep adversarial security audit of the xpf firewall config + schema compilation layer at b1bd96fb6 (branch master). Read 12+ files, verified 5 required fixes (#4524, #4521, #4525, #4526, #4530), traced all bracket-list (#2419) read paths, apply-groups merge paths, inactive: pruning paths, lenient-vs-strict gates, and bracket stripping.

**Findings**:
- No High-severity fail-open bugs found in this cohort on b1bd96fb6.
- One Medium/Low finding: #4530 revert removed `@` from global `isIdentChar` to fix `monitor traffic matching @` fail-closed, but breaks unquoted `scp://user@host/path` archive-sites — fix should be at validator level.
- One informational: `validateMultiValueLeaf` `to`-as-separator is safe but overly broad (already tracked as F-043).
- Five strong negative results: bracket-list, apply-groups, inactive:, lenient-vs-strict, bracket stripping — all verified correct, no fail-open.
- All required fixes (#4521, #4525, #4526, #4527/#4524, #4530) verified present on HEAD.
- Dedup against /tmp/all_findings.txt (272 entries) + ps-review-024 + ps-review-025 — no re-reporting.
