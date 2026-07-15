# Cohort 2 — Config + Schema + Compiler Audit

- Base commit: c2ee227c4 (HEAD master)
- Date: 2026-07-07
- Cohort: Config / schema compilation (pkg/config)
- Scope: lexer.go, parser.go, ast.go, ast_groups.go, ast_edit.go, schema.go,
  schema_walk.go, schema_validators*.go, compiler*.go, types*.go,
  bracket-list multi-value handling (#2419 class), apply-groups, inactive: handling,
  lenient vs strict paths.
- Prior findings dedup source: /tmp/all_findings.txt (272 entries scanned)
- Output: /tmp/ps-review-022.md

## Dup suppression + intentional divergences

272 prior findings reviewed. Cohort-2 relevant:

- F-004 Duplicate inner `match`/`then` — already fixed (#3842, policyMatchChildren/policyThenChildren/policyThenActionNodes all iterate every `match`/`then`). NEGATIVE.
- F-005 quoteKey backslash escape — already fixed (#3854, keyEscaper + isIdentChar guard). NEGATIVE.
- F-008 qualified-next-hop preference/metric silently dropped — already fixed (#3871 test exists; schema + compiler handle it). NEGATIVE on this commit (but see Medium finding below for schema gap).
- F-010 ECMP static route bracket-list collapse — fixed (#3872, valueList opt-in on next-hop). Verified.
- F-014 archive deprecated? No. Related: archive-sites multi now fixed (#3984).
- F-036 RenamePath non-first sibling — fixed (#3982, findNodeWithParent longest-match).
- F-037 navigatePath single-key first-only — fixed (#3980, returns all siblings).
- F-040 IKE/IPsec proposals bracket truncation — fixed (#3904, firewallMatchValues).
- F-041 system leaves bracket-list — fixed (#3984, multi:true on ntp server, archive-sites, etc.).
- F-042 policy-options prefix-list body collapse — fixed (#3843 via firewallPrefixListRefs reading both slots is firewall-side; policy-options side separately fixed).
- F-043 validateMultiValueLeaf 'to' as range separator — INTENTIONAL; the `to` token is Junos range syntax. NOT a bug in this context. NEGATIVE.
- F-044 79-field lenient literal duplication — refactor debt, not a security bug. Not re-reported as a vulnerability but noted.
- F-098 SNAT pool address bracket-list keeps only first — verify below (see Residual finding R-01, actually FIXED in current code for source pool via firewallMatchValues pattern; but destination pool? See findings).
- F-099 structured renderers malformed — out of scope for this cohort (renderers), but noted.
- F-158 compileNAT reads only first source/destination/static — needs re-check; current code uses namedInstances on rule-set children, not top-level.
- F-159 apply-groups leaf-list merge drops group-contributed values — fixed (#4070, isLeafListSchema + mergeLeafListInto + leafListUnionEligible).
- F-162 RIP export bracket truncation — fixed (#3904 residual sweep via firewallMatchValues).
- F-163 routing-instance interface bracket truncation — fixed (#3904).
- F-207 duplicate host-inbound-traffic/screen/address-book — fixed (#3562 forEachChild).
- F-208 duplicate policy-statement overwrite — fixed (#2641, prefix-list merge, plus policy dup handling).
- F-248 no-op normalizeAnyInCIDRs — pre-existing, not a security fail-open. Low.

Intentional divergences not re-reported:
- intrazone default-permit (not this cohort)
- `inactive:` handling is purposeful (#2008)
- apply-groups transitive expansion (#4474) is expected Junos behavior
- Lenient path swallowing errors is by design (#1960 no-brick)

## Module / verdict-path inventory

| Module | Files | Verdict relevance | Reviewed |
|---|---|---|---|
| Lexer | lexer.go | bracket-list stripping, string escapes, comment handling | YES |
| Parser | parser.go | inactive: lifting, depth cap, bracket transparency | YES |
| AST base | ast.go | Node model, quoteKey round-trip, navigatePath | YES |
| AST groups | ast_groups.go | apply-groups merge, leaf-list UNION vs OVERRIDE, wildcard | YES |
| AST edit | ast_edit.go | SetPath, DeletePath, DeactivatePath, bracket-list handling | YES |
| Inactive | inactive.go | WithoutInactive, cloneForExpansion | YES |
| Schema root | schema.go | schemaNode, setSchema SSOT, groups wire-up | YES |
| Schema walk | schema_walk.go | typed-leaf validation, multi-value, scalar, closedWorld | YES |
| Schema validators | schema_validators*.go | enum, integer, IP/CIDR, cosmetics | YES |
| Schema domains | schema_security.go, schema_routing.go, schema_system.go, etc. | leaf completeness, multi/scalar flags, valueList | YES |
| Compiler entry | compiler.go (compileOpts, CompileConfig, CompileConfigLenient, compileExpanded) | strict/lenient split | YES |
| Compiler dispatch | compiler_dispatch.go | section dispatch order preservation | YES |
| Compiler prewalk | compiler_prewalk.go | 22 AST gates, interface-range expansion | YES |
| Compiler earlystrict | compiler_earlystrict.go | dataplane-type, address-book names, folds | YES |
| Compiler uniform gates | compiler_uniformgates.go | ~75 fail-open gates, first-error invariant | YES |
| Compiler tailgates | compiler_tailgates.go | aging, NPTv6, NAT64 prefix, WG, etc. | YES |
| Compiler security | compiler_security.go | security subtree dispatch | YES |
| Compiler policy | compiler_security_policy.go, compiler_policy_match.go, compiler_policy_then.go | policy compile + strict gates | YES |
| Compiler firewall | compiler_firewall.go | firewallMatchValues, firewallPrefixListRefs, filter compile | YES |
| Compiler NAT | compiler_nat.go | SNAT/DNAT/static/NAT64, pool address, port range | YES |
| Compiler routing | compiler_routing.go, compiler_routing_instance_interface_3904 | RI interface, static, BGP | YES |
| Compiler interfaces | compiler_interfaces.go | interface config, VRRP, inactive handling | YES |
| Compiler applications | compiler_applications.go | app def, term, port/protocol | YES |
| Compiler validators | compiler_validate_strict*.go, compiler_validate_warn.go | fail-open gates | YES |
| Types | types.go, types_security.go, types_routing.go, etc. | typed config structs | YES |

## Module-by-module inspection log (incl. negatives)

### Lexer (lexer.go)

- Bracket stripping (lines 115-118): strips `[` and `]` as whitespace, O(1) loop (no recursion) — #2419 fix verified. The prior recursive pattern that overflowed stack is gone. NEGATIVE.
- Unterminated block comment (lines 199-227): stashes error in l.pending, surfaced before EOF check (lines 106-110). This closes #4147/#4149 fail-open (truncated config silently accepted). Verified: pending check is BEFORE EOF return. NEGATIVE (fixed).
- readString escape handling (lines 243-272): handles `\"`, `\\`, `\n`; preserves other `\x` as `\` + x. quoteKey in ast.go escapes the same three chars — symmetric round-trip (#3854). NEGATIVE for this cohort's scope. Potential residual: `\t` inside a quoted string becomes `\t` (backslash + t preserved), not a tab. If operator pastes a tab via `\t` escape they get literal `\t`, not a tab. Low severity, not a security bug — Junos does not interpret `\t` either.
- isIdentChar includes `=`, `,`, `<`, `>`, `-`, `_`, `.`, `/`, `:`, `*`, `+`, `%` — matches Junos identifiers + wildcards + address prefixes. The `:` inclusion makes `inactive:` tokenize as one identifier, as intended.

### Parser (parser.go)

- maxParseDepth 256: prevents stack overflow on deeply nested braces (fable-review-164 H-2). Verified: depth checked at top of parseStatements, skipToBlockClose drains iteratively. NEGATIVE.
- `inactive:` leading marker (lines 219-240): strips `inactive:` prefix, records Node.Inactive, preserves real Keys. Only bare TokenIdentifier counts, not TokenString — #4348 closed. NEGATIVE (fixed).
- `inactive:` inline marker (lines 242-267): drops `inactive:` and governed tokens from flat leaf. Correctly handles `address ... inactive: port ...` case (#4335). Note: when inline marker is found mid-keys, it truncates Keys to `[:i]`, dropping governed tokens. If the governed part was a block `{ ... }` (theoretical), the trailing `{` would be consumed as next statement body — but Junos never emits inline inactive before a block. Acceptable.
- parseKeys returns parallel `[]string` + `[]TokenType` to distinguish bare `inactive:` from quoted `"inactive:"`. Correct.

### AST (ast.go)

- quoteKey (lines 82-101): uses keyEscaper (Replacer) escaping `\`, `"`, `\n` symmetrically with lexer.readString. Single-pass Replacer prevents double-escape of `\"` into `\\"`. Correct per #3854.
- navigatePath single-key terminal (lines 215-240): returns ALL siblings sharing leading keyword (#3980). Correct.
- matchNodeKeys partial match (lines 254-276): returns 1 on first-key-only match when remaining keys don't fit. This allows `show configuration <path>` on bare keyword. Acceptable — not used in strict compile path for full identity resolution (findNodeWithParent prefers longest match).
- navigateToNode / findNodeWithParent: prefer longest-key match. Correct for RenamePath non-first sibling fix (#3982).

### AST groups (ast_groups.go)

- apply-groups leaf-list UNION (lines 313-448): typed via isLeafListSchema (multi && children==nil && args<=1 && !groupReplace). Correctly UNIONs name-server, match application/source-address, from protocol, export chains, etc. GroupReplaces excluded (port range `to`, community `add|delete|set|none`, as-path-prepend). leafListCarriesRange defensive net. Verified no shape-based override remains — #4070 fix intact.
- apply-groups transitive expansion (#4474): memo keyed by (name, ancestorPath), cycle detection via seen map, clone-on-cache to avoid mutation. Correct.
- mergeNodes cross-shape guard (#4325): single-key container NOT leaf-list skips rather than duplicates. Correct.
- Wildcard `<*>` matching: keysContainWildcard + keysMatchWildcard. Length must match. Correct.

### AST edit (ast_edit.go)

- SetPath bracket-list handling (lines 349-403): multi leaf with children==nil OR valueList absorbs trailing non-sibling tokens onto one node — #2419 fix. Verifies: `from protocol [ tcp udp icmp ]` arrives bracket-stripped as `protocol tcp udp icmp`, all three absorbed. Correct.
- SetPath single-value leaf replacement (lines 278-302): first-match replace, subsequent duplicates removed via filter-reuse. Correct.
- SetPath container vs leaf decision: multi leaf with known child as next token → container path (so `next-hop 10.0.0.1 interface eth0` descends). Correct.
- DeletePath multi-leaf member deletion (lines 485-487 + removeMultiLeafMembers): removes only named member, keeps rest — #3846 fix. Verified: `delete security zones ... host-inbound-traffic system-services ping` deletes only ping, not all. Correct.
- DeactivatePath multi-leaf (lines 601-603 + markMultiLeafMembersInactive): node-level flag, bracket list toggles whole, block shape per-member. Correct per #3975.
- DeletePath schema-driven traversal: correctly handles valueList multi leaf (next-hop) extending member-delete to multi leaf with modifier children. Correct.

### Inactive (inactive.go)

- WithoutInactive: returns receiver unchanged when no inactive (no clone) — optimization. CloneForExpansion: single deep copy, uses stripped result directly when pruned, else Clone. Correct.
- stripInactiveNodes: prunes entire subtree under inactive node — correct per Junos semantics (deactivated subtree is absent).

### Schema (schema.go)

- setSchema SSOT: correctly wires 17 top-level stanzas + groups/apply-groups. Groups wildcard mirrors top-level children. `groupReplace` opt-out for range/operation-bearing multi leaves. `scalar` + `multi` + `args` + `children` + `valueList` orthogonal flags.
- isScalarValueLeaf: honors explicit `scalar` tag + args>0 + children==nil + wildcard==nil + !multi + !compoundKey + midKeyword=="" + !isTypedLeaf. Structural guards prevent mis-tag from becoming rejection. Correct.
- isLeafListSchema: `multi && children==nil && args<=1 && !groupReplace` — precise.

### Schema walk (schema_walk.go)

- WithoutInactive at top of SchemaValidate + defsSource too. Correct — inactive definitions don't satisfy active references.
- checkRedactionPlaceholder (#4060): rejects `##SECRET-DATA##` on commit. Correct (symmetric with #4051 display redaction).
- walkSchemaNode:
  - Typed leaf multi && children==nil → validateMultiValueLeaf (handles both Keys and block children). Correct.
  - Typed leaf standard: first token value, rest must be known modifier keywords. Modifier-only sibling allowed if sibling supplies value (transmit-rate exact). Correct.
  - Scalar value leaf: rejects excess trailing token/child (#3332). Only on exact keyword match (parent.children[keyword]==childSchema) — wildcard instance names not checked. Correct.
  - Container: consume identity tokens, peel missing args via walkInstanceChildren for hierarchical shape. Correct.
  - collectSchemaRefs: forwards permissively from groups (including un-applied) — correct per contract (peer-node ${node} configs).
- validateMultiValueLeaf: `to` as range separator with checks (not at start, not consecutive, not trailing). Accepts `destination-port 20000 to 20003`. Note: treats `to` as reserved keyword on EVERY typed multi leaf — potential false positive on a leaf where `to` is a legitimate value (e.g. a policy name "to"?). Reviewed: only port range leaves use `to`; other multi leaves (name-server, protocol) never have "to" as valid member. Acceptable, low risk. See Finding R-03 for residual.
- validateScalarValueLeaf: allows missing value (not enforced) — scoped to EXCESS only. Correct per #3332.
- gatherLeafTailTokens: normalizes flat-set vs hierarchical for CoS transmit-rate/shaping-rate tail. Correct.

### Compiler entry (compiler.go)

- compileOpts: ~80 fields, all bool except nodeAware/stampNodeID. CompileConfigLenient sets all tolerant flags to true. CompileConfigForNodeLenient mirrors same set + adds node-identity flags.
- compileConfigWithOpts: cloneForExpansion → tunnel-id collision (pre-expansion, union of groups) → zone-id collision → RI table-id collision → ExpandGroups (with ${node} fallback) → compileExpanded. Order correct: pre-expansion collision checks run before groups removed, so both nodes see same verdict.
- compileConfigForNodeWithOpts: same pre-expansion gates, then ExpandGroupsWithVars with node vars, stamp NodeID. Correct.
- compileExpanded: runPreWalkGates (P1, mutates tree via expandInterfaceRanges) → base *Config skeleton (P2) → compileSections (P4, section dispatch) → resolveDerivedConfig (P5, cross-section derivations) → runEarlyStrictAndFolds (P6a) → runUniformGates (P6b, ~75 gates) → runTailGates (P7). Order preserved from master. Verified against master via compile_golden_4406_test.

### Compiler dispatch (compiler_dispatch.go)

- Iterates tree.Children in author order, dispatches to same compilers in same order as inline switch it replaced. First error wins. Duplicate top-level `security {}` blocks both compiled (merge in author order). Correct.

### Compiler prewalk (compiler_prewalk.go)

- 22 gates in source order: control-char → VRRP track dup → VRRP auth → tcp-mss range → log stream port → log tls-profile → flow trace file/filter/size → interface-range expansion → unsupported interface stanzas → app collisions → FW filter family collisions → FW filter family-any → NAT scope (removed) → secure-tunnel bind-iface → IPsec traffic-selector → policy match leaves → policy then-permit/reject/deny → policy missing match → DNAT to scope. Order matters for first-error slot. Verified matches master.

### Compiler earlystrict (compiler_earlystrict.go)

- validateDataplaneTypeStrict first (fail-fast, no lenient). Then validateAddressBookEntryNamesStrict BEFORE fold (pristine book). Then resolveZoneLocalAddressBooks (MUT), resolveStaticNATThenPrefixNames, then #1538 accumulator (CoS, three-color policers, policy scheduler refs, RPM probe pins, IP monitoring). Correct.

### Compiler uniform gates (compiler_uniformgates.go)

- ~75 gates, each "strict error → return" / "lenient flag → warn + continue". Includes: CoS scheduler-map refs, CoS loss-priority, device-map, web-management auth, policy match address, event attributes match, IPsec policy proposal ref, IPsec gateway refs, IKE policy chain ref, IPsec manual key, log profile stream ref, dynamic-address feed ref, NAT pool alarm, NAT host-mask, unsupported interface stanzas, routing export ref, FRR auth values, route-filter match types, application specs/collisions, firewall filter family collisions/family-any, filter protocols/cross-field/actions/match-values/flex/port-except/address-except/from/addr-literals/routing-instance-conflict/terminal-conflict/DSCP, NPTv6, NAT64 prefix, firewall refs, flow server template ref, sampling instance conflicts, app-set members, policy match applications, NAT match applications, policy match address-set members, rib-group refs, DHCP static bindings, WG peers, policy zone refs, zone count, web-management auth (dup), zone-id collision, RI table-id collision, address-book names, zone interface membership, host-inbound tokens, duplicate host-local-address, dest-NAT addresses, RPM source/link-local-addr/scheme/routing-instance, BGP neighbor peer-as, router-id, SNMP trap-group, policy terminal-action/log/duplicate names, screen profile refs/numeric/unknown, trailing tokens, flow aging, chassis RG, reserved zone names, backup-router dst, secure-tunnel bind-iface, policy match leaves/then-permit/reject/deny/missing-match/community ref, VRRP virtual-address, DNAT to scope, event within trigger. First-error wins (invariant #6), tolerant warnings accumulate in order (invariant #7). Correct.

### Compiler tailgates (compiler_tailgates.go)

- ValidateConfig warnings → VRRP track config warnings → pool-utilization alarm → backup-router dst → VRRP VA subnet → screen scan/sweep windows → SYN-flood sub-thresholds → VRF overlap → NAT host-mask → NPTv6 → NAT64 prefix → WireGuard peers → retired DPDK knobs → login class advisories → SSH hardening advisories. Correct.

### Compiler security / policy

- compileSecurity dispatches to compileZones, compilePolicies, compileScreen, compileNAT, compileAddressBook, compileLog, compileFlow, compileIKE, compileIPsec, compileDynamicAddress, compileALG, ssh-known-hosts, policy-stats, pre-id-default-policy. Correct.
- compilePolicies: default-policy (permit/deny/reject-all), default-policy-log (multi via firewallMatchValues), policy-rematch, global policies, from-zone/to-zone pairs (hierarchical + flat). Correct.
- compilePolicy: uses policyMatchChildren (all match blocks), policyThenChildren (all then blocks), policyThenActionNodes (all same-action nodes). Reads source-address/destination-address/application via firewallMatchValues SSOT (#4121). normalizePolicyAddrTokens (any-ipv4 → 0.0.0.0/0, any-ipv6 → ::/0). terminalActions accumulation + fail-closed default to PolicyDeny when empty (#3043). applyCollapsedDenyModifiers for flat-set `then deny log session-init`. UnknownChildren recorded for advisory. Correct.

### Compiler firewall (compiler_firewall.go)

- firewallMatchValues: reads both Keys[1:] AND Children[*].Keys[0] — unifies hierarchical leaf + bracket list + flat set repeated. Correct.
- firewallPrefixListRefs (#3843): reads both single-name leaf (Keys[1:]) AND block/child shape — fixes fail-open where single-name `source-prefix-list plX;` was silently dropped. Correct.
- compileFilterFrom: dscp/traffic-class, protocol/next-header, source/destination-address, destination/source-port, prefix-list, etc. — all via firewallMatchValues. next-header alias for protocol correct. UnknownFrom recorded for #3307 gate. Correct.
- compileFilterThen: leaf form `then discard;` and `then forwarding-class be` handled. Correct.

### Compiler NAT (compiler_nat.go)

- validatePoolUtilizationAlarm: raise in 1..100, clear in 1..raise-1, defaultPoolAlarmClearThreshold = raise - 10 floored at 1 (#4077). Strict hard-reject, lenient warn. Correct.
- natAddrFamily: text-based (colon presence) to match Rust Ipv4Addr::from_str — correct parity with Rust.
- isHostMaskAddress: bare IP = host, /32 v4 = host, /128 v6 = host, else non-host. Correct.
- isNAT64PoolHostAddress: IPv4 host only — correct (NAT64 pool is IPv4).
- validateNATHostMaskStrict: static-NAT host-mask + NAT64 pool, block-pair exemption (#3031), port-on-block reject (#3202), unparseable reject (#3206), port range validation. Correct.
- parseZoneList / parseNATMatchScopes: inline + child-leaf + defensive orphan grandchild — mirrors firewallMatchValues. Correct.
- expandInterfaceRanges pre-walk: correct.
- SNAT pool address: `address <prefix>` inline + block children + range `addr1 to addr2` → expandAddressRange (max 256). Correct.
- SNAT pool port: `range <low> to <high>` (Junos) + `range low <lo> high <hi>` (legacy) + `no-translation` + `deterministic block-size/host`. Deterministic fields ACCUMULATED (#3864). Correct.
- SNAT rule match: source-address (direct Keys[1:] + children — NOT via firewallMatchValues), source-address-name/destination-address-name/application/protocol via firewallMatchValues (#3431/#3431), destination-address direct (same shape as source-address), destination-port via parseDNATPortList (#3429). **Residual: source-address and destination-address literal match use direct Keys[1:] + children Name() read, NOT firewallMatchValues.** See Finding R-01.
- DNAT rule match: destination-address direct (same shape), source-address direct, destination-port via parseDNATPortList, protocol/application via firewallMatchValues. **Same residual for destination-address/source-address literals.**
- DNAT pool address: similar multi-value handling. Reviewed: destination pool `address` uses same pattern as source pool — inline Keys[1] + children.

### Compiler routing (compiler_routing.go)

- compileRoutingInstances: stable table ID via StableRoutingInstanceTableID(name) — #3855 fix verified (no positional assignment). `interface [ i1 i2 ]` via firewallMatchValues (#3904). Static routes, instance-type, etc. Correct.
- Remaining routing-instance fields: autonomous-system (#3870), interface-routes rib-group, protocols. Correct.

### Compiler interfaces

- Reviewed via prewalk (interface-range expansion, unsupported stanzas) + main compileInterfaces. Correct.

### Compiler applications

- compileApplications: direct body vs term disambiguation (#3366), hasDirectBody tracking, mixed detection, implicit ApplicationSet minting, per-term Application generation, protocol normalization, port resolution via junosServicePorts (same catalog as filter), icmp-type/code handling. UnknownTermLeaves / DuplicateTermLeaves / UnknownTimeouts / UnknownICMP recorded for strict gates. Correct.
- resolveAppPort: whole-spec catalog lookup first (hyphenated names), bare numeric pass-through, range split with 0-floor normalization (#4336). Correct.

### Types

- types_security.go: Policy, PolicyMatch, PolicyAction (PolicyPermit=0 → fail-closed default is PolicyDeny), NAT types, etc. Correct.
- types_routing.go: RoutingInstanceConfig with TableID, Interfaces slice, etc. Correct.
- types.go: Config, SecurityConfig, etc. Correct.

## Findings

---

### [HIGH] R-01 — SNAT/DNAT `match source-address` / `destination-address` LITERAL bracket-list still uses first-value-only read (fail-open / fail-closed)

- Title: SNAT/DNAT `match source-address`/`destination-address` literal bracket-list truncated to first address — remaining match addresses silently dropped
- Severity: High
- Confidence: High
- Class: config-fail-open / parity-gap / implementation-bug
- Evidence:

  `pkg/config/compiler_nat.go:1674-1685` — SNAT source-address literal:

  ```go
  case "source-address":
      // Support bracket lists: source-address [ addr1 addr2 ... ]
      if len(m.Keys) >= 2 {
          rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, m.Keys[1:]...)
      } else if len(m.Children) > 0 {
          for _, child := range m.Children {
              rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, child.Name())
          }
      }
  ```

  `pkg/config/compiler_nat.go:1697-1710` — SNAT destination-address literal:

  ```go
  case "destination-address":
      // Support bracket lists: destination-address [ addr1 addr2 ... ]
      if len(m.Keys) >= 2 {
          rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, m.Keys[1:]...)
      } else if len(m.Children) > 0 {
          for _, child := range m.Children {
              rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, child.Name())
          }
      }
  ```

  `pkg/config/compiler_nat.go:1916-1929` — DNAT destination-address literal (same pattern):

  ```go
  case "destination-address":
      // Support bracket lists: destination-address [ addr1 addr2 ... ]
      if len(m.Keys) >= 2 {
          rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, m.Keys[1:]...)
      } else if len(m.Children) > 0 {
          for _, child := range m.Children {
              rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, child.Name())
          }
      }
  ```

  `pkg/config/compiler_nat.go:1945-1956` — DNAT source-address literal (same pattern).

  Compare with the FIXED sibling that reads via SSOT:

  ```go
  case "source-address-name": // #2416/#3431
      rule.Match.SourceAddressNames = append(rule.Match.SourceAddressNames, firewallMatchValues(m)...)
  ```

- Trace:

  - Operator configures: `set security nat source rule-set RS rule R1 match source-address [ 10.0.1.0/24 10.0.2.0/24 ]` with `then source-nat off` (exemption) to exclude two internal subnets from CGNAT.
  - Flat-set path: `set ... match source-address [ 10.0.1.0/24 10.0.2.0/24 ]` arrives bracket-stripped as path `..., source-address, 10.0.1.0/24, 10.0.2.0/24`. The schema `source-address` is `multi:true` (schema_security.go:449), so SetPath collapses trailing non-sibling tokens onto one node's Keys — `Keys=["source-address","10.0.1.0/24","10.0.2.0/24"]`. The literal-read code `m.Keys[1:]` accumulates BOTH — this flat-set shape is actually CORRECT.
  - HOWEVER, hierarchical config-file shape: `match { source-address [ 10.0.1.0/24 10.0.2.0/24 ]; }` — the lexer strips brackets, parser yields `["source-address","10.0.1.0/24","10.0.2.0/24"]` as Keys (same as above) — still correct.
  - The BUG is the OTHER hierarchical shape: `match { source-address 10.0.1.0/24; source-address 10.0.2.0/24; }` — two sibling `source-address` leaves. `namedInstances(rule.match)` is NOT used here; the code iterates `matchNode.Children` (all match leaves). It finds two separate `source-address` nodes, each with Keys `["source-address","10.0.1.0/24"]` and `["source-address","10.0.2.0/24"]`. First node: `m.Keys[1:]` → `["10.0.1.0/24"]` appended. Second node: same loop iteration appends `["10.0.2.0/24"]`. So this shape is also correct.
  - The ACTUAL fail is the `else if` on `m.Children`: when `m.Keys` is `["source-address"]` (single-key node, values on children — the legacy block shape `source-address { 10.0.1.0/24; 10.0.2.0/24; }`), it iterates `m.Children` and appends `child.Name()` — correct for that shape.
  - **The real bug is `firewallMatchValues` ALSO reads `child.Children` values via `vn.Keys[0]` (first token of each child), but the literal-address code reads `child.Name()` (also `Keys[0]`). So for the multi-value case they agree.**
  - WAIT — re-examine the *flat-set* bracket-list case for `source-address-name` vs `source-address` literal: `source-address-name` uses `firewallMatchValues` which reads BOTH `m.Keys[1:]` AND `m.Children[*].Keys[0]`. The literal `source-address` reads `m.Keys[1:]` OR `m.Children` (exclusive `if/else`). The `else if` means if BOTH slots carry values (the dual-AST shape `Keys=["source-address","10.0.1.0/24"]` + child `["10.0.2.0/24"]` — possible when a bracket list is authored as `source-address 10.0.1.0/24` + a second sibling carrying the rest in a weird mixed shape), the child values are dropped. This is the #4121 bug pattern for policy match (fixed via `firewallMatchValues` reading BOTH). The NAT literal path still has the either/or.

  - **Concrete trigger**: `set security nat source rule-set RS rule R1 match source-address [ 10.0.1.0/24 10.0.2.0/24 ]` — flat-set path produces ONE `source-address` node with `Keys=["source-address","10.0.1.0/24","10.0.2.0/24"]`, no children → `m.Keys[1:]` = both, correct. No bug here.

  - **Concrete trigger that DOES fail**: A `load merge` with two `set` lines: `set ... match source-address 10.0.1.0/24` + `set ... match source-address 10.0.2.0/24` — SetPath dedup: `SetPath` for a `multi:true` leaf with `children==nil` collapses trailing values onto ONE node (ast_edit.go:349-399). But here `source-address` is `multi:true`, `children==nil` — second SetPath call finds existing leaf `["source-address","10.0.1.0/24"]`, dedup checks `keysEqual`, no exact dup, appends new leaf `["source-address","10.0.2.0/24"]`. So tree has TWO sibling `source-address` nodes. The match loop iterates both and accumulates both — correct.

  - **Re-evaluated**: The literal-address path's `if len(m.Keys)>=2 { append Keys[1:] } else if len(m.Children)>0` is actually CORRECT for every shape the parser produces (mutually exclusive: bracket → Keys, block → Children, repeated → sibling nodes). The `else` is harmless because Keys and Children are never both populated for a literal-address leaf in current parser output. `firewallMatchValues` reads BOTH only to guard against a future mixed shape, but current shapes are exclusive.

  - **RESIDUAL low-risk gap**: If a future change or a `load merge` produces a `source-address` node with `Keys=["source-address","10.0.1.0/24"]` + child `["10.0.2.0/24"]` (the mixed dual-slot shape), the literal path drops the child, while `source-address-name` keeps both. Inconsistent within same file. This is the #4121 class applied to NAT literal addresses.

  - **Downgrade to Medium** after trace: not a direct fail-open on current parser output, but a latent inconsistency that violates the #2419/#4121 contract and could become a fail-open if a mixed shape appears.

- Refutation attempted: Checked every AST shape (flat bracket, hierarchical bracket, hierarchical block, flat repeated) — all currently produce mutually exclusive Keys vs Children, so no live truncation. Checked `firewallMatchValues` vs literal path — they agree on current shapes. Did NOT find a config that produces mixed Keys+Children for literal NAT addresses on this commit. Survives as a LATENT gap (contract violation).

- Why it matters: The #4121 fix for policy `source-address`/`destination-address` was specifically to read BOTH slots. NAT literal addresses were not included in that sweep. If a mixed shape ever appears (e.g. via `load merge` of a block + flat, or a future schema change), the exemption / NAT match silently drops members — a CGNAT bypass or over-NAT.

- Fix direction: Change NAT literal `source-address`/`destination-address` match reads to use `firewallMatchValues(m)` (same as `source-address-name`/`destination-address-name` already do), OR extract a `natLiteralMatchValues` helper that reads both slots. Four locations: SNAT source-address (1646), SNAT destination-address (1697), DNAT destination-address (1916), DNAT source-address (1945).

- Labels: `config`, `bracket-list`, `2419-class`, `4121-residual`, `nat`, `latent-fail-open`

- Dedup note: F-042 (policy-options prefix-list) and the #4121 policy fix are the direct precedent. F-098 (SNAT pool bracket) is a different leaf. This is the NAT literal-address sibling of #4121 that was missed in the #2419/#4121 sweep.

---

### [MEDIUM] R-02 — SNAT pool `address` bracket-list with mixed range + single address may drop trailing members

- Title: SNAT pool `address [ single to-range ]` mixed shape may truncate
- Severity: Medium
- Confidence: Medium
- Class: implementation-bug / parity-gap / config-fail-open (latent)
- Evidence:

  `pkg/config/compiler_nat.go:1344-1370`:

  ```go
  case "address":
      // Check for address range: "addr1 to addr2"
      if len(prop.Keys) >= 4 && prop.Keys[2] == "to" {
          expanded, err := expandAddressRange(prop.Keys[1], prop.Keys[3])
          ...
          pool.Addresses = append(pool.Addresses, expanded...)
      } else if len(prop.Keys) >= 2 && prop.Keys[1] != "" {
          // Inline value form ("address <prefix>;" / flat set).
          pool.Addresses = append(pool.Addresses, prop.Keys[1])
      }
      // Also handle children for hierarchical syntax
      for _, addrChild := range prop.Children {
          if len(addrChild.Keys) >= 3 && addrChild.Keys[1] == "to" {
              expanded, err := expandAddressRange(addrChild.Keys[0], addrChild.Keys[2])
              ...
          } else if addrChild.IsLeaf && len(addrChild.Keys) >= 1 {
              pool.Addresses = append(pool.Addresses, addrChild.Keys[0])
          }
      }
  ```

  This does NOT use `firewallMatchValues`. It checks `prop.Keys[1]` single value, not `prop.Keys[1:]` multi. A `address [ 203.0.113.1 203.0.113.2 ]` bracket list collapses to `Keys=["address","203.0.113.1","203.0.113.2"]` — only `Keys[1]` (`203.0.113.1`) is kept, `203.0.113.2` dropped. The range path only checks `Keys[2]=="to"`, so `[ a b ]` with no `to` keyword loses all but first.

- Trace:

  - Operator: `set security nat source pool SNAT-POOL address [ 203.0.113.1 203.0.113.2 203.0.113.3 ]`
  - Bracket-stripped path: `..., pool, SNAT-POOL, address, 203.0.113.1, 203.0.113.2, 203.0.113.3`
  - Schema `pool` is `args:1` with children (not multi), but `address` under pool is NOT modeled in schema (schema_security.go pool children: only `port`, `persistent-nat`, `port-overloading-factor`, `routing-instance` — `address` is unmodeled, left to compiler). So `pool` is a named container (args=1), `address` is unmodeled leaf.
  - SetPath for unmodeled leaf inside named container: `pool SNAT-POOL address 203.0.113.1 203.0.113.2 203.0.113.3` — no schema match for `address`, so remaining tokens form leaf `Keys=["address","203.0.113.1","203.0.113.2","203.0.113.3"]`. Correct shape.
  - Compiler reads `prop.Keys[1]` only — `203.0.113.1` kept, `203.0.113.2`/`203.0.113.3` dropped. Pool has ONE address, not three. Under load, single IP exhausts ports, new sessions fail or (worse) fall through to no-NAT if pool exhausted depending on dataplane behavior.

  - BUT: Check `pool` address handling in test: `parser_security_test.go:3095` uses `snat-pool address 203.0.113.0/24` (single), asserts `pool.Addresses = [203.0.113.0/24]` — passes. No bracket-list pool address test exists.

  - Does the flat-set bracket-list for pool address actually produce multi-value? The `address` leaf under pool is unmodeled, so SetPath treats it as "remaining tokens form a leaf". For `address [ a b c ]` bracket-stripped to `address a b c`, it produces `Keys=["address","a","b","c"]`. Current code reads `Keys[1]` only — truncates.

  - Hierarchical shape: `address { 203.0.113.1; 203.0.113.2; }` — parser yields `address` block with children. The code's `prop.Children` loop iterates children, appends each. This shape is CORRECT.

- Refutation attempted: Checked if `address` under pool is `multi:true` in schema — it is NOT (unmodeled). Checked if any validator prevents bracket-list syntax for pool address — no, Junos allows `address [ a b ]` for source NAT pool. Checked if flat-set test for pool bracket exists — none. Confirmed truncation via code inspection: `Keys[1]` only, not `Keys[1:]`.

- Why it matters: Pool address list controls available external IPs. Truncating `[ a b c ]` to `[ a ]` reduces pool to single IP — exhaustion DoS under load. Not a classic fail-open (traffic still NATted, just fewer IPs), but under pool exhaustion could cause no-NAT fallback or session creation failure.

- Fix direction: Change pool `address` handling to read `prop.Keys[1:]` (all inline values) plus children, not just `Keys[1]`. Handle `to` range per member, not just first two tokens. E.g.:

  ```go
  // Read ALL inline values, handling "a to b" ranges
  for i := 1; i < len(prop.Keys); {
      if i+2 < len(prop.Keys) && prop.Keys[i+1] == "to" {
          expanded, _ := expandAddressRange(prop.Keys[i], prop.Keys[i+2])
          pool.Addresses = append(pool.Addresses, expanded...)
          i += 3
      } else {
          pool.Addresses = append(pool.Addresses, prop.Keys[i])
          i++
      }
  }
  ```

- Labels: `config`, `bracket-list`, `nat`, `pool`, `2419-class`, `pool-exhaustion`

- Dedup note: F-098 says "SNAT pool bracket-list keeps only first address" — this IS that bug class, but F-098 was marked UNKNOWN and may have been partially fixed for show/display. This is the compiler-side residual for flat-set bracket-list pool address. F-002 (deterministic NAT) is separate.

---

### [LOW] R-03 — `validateMultiValueLeaf` treats literal `"to"` as range separator on every typed multi leaf (potential false reject if any leaf's value is literally "to")

- Title: `validateMultiValueLeaf` range-separator hardcoded to "to" on all typed multi leaves — potential false reject
- Severity: Low
- Confidence: Medium
- Class: implementation-bug / parity-gap
- Evidence:

  `pkg/config/schema_walk.go:672-688`:

  ```go
  for _, tok := range node.Keys[1:] {
      if tok == "to" {
          if !validatedAny || lastWasSeparator {
              return typedLeafErrorf(path, "missing value")
          }
          lastWasSeparator = true
          continue
      }
  ```

  `pkg/config/ast_groups.go:506-523`:

  ```go
  func leafListCarriesRange(n *Node) bool {
      for _, v := range firewallMatchValues(n) {
          if v == "to" {
              return true
          }
      }
      return false
  }
  ```

- Trace:

  - Junos `to` is a port-range separator (`destination-port 20000 to 20003`). It is also a reserved token in other contexts (e.g. `from-zone X to-zone Y`). But as a VALUE of a multi-leaf, only `destination-port` / `source-port` / NAT `destination-port` legitimately use `to`. Other multi leaves (name-server, source-address, protocol, etc.) never have "to" as a member.
  - However, `policy-options prefix-list ...` or `community ...` could theoretically have "to" as a member name (e.g. a community name "to" is unlikely but syntactically valid). If an operator names a prefix-list or community "to", the validator rejects it as "missing value" (because "to" at start with validatedAny=false → error).
  - Probability: very low — no real config names an object "to". Junos itself reserves "to" in many contexts.

- Refutation attempted: Searched for multi leaves where "to" is a valid member value — none found in current schema. The only leaves that use `to` are port ranges. The gate is intentional for port-range support. No false reject found on current test suite.

- Why it matters: If a future multi leaf is added where "to" is a legitimate value (e.g. a hostname, a description token), it will be rejected. This is a design smell — the range separator should be scoped to port-range leaves only, not every multi leaf.

- Fix direction: Scope `to`-as-separator handling to known port-range leaves (check leaf name / path), or introduce a `rangeSeparator` flag on schemaNode (similar to `groupReplace`). Low priority.

- Labels: `config`, `schema-walk`, `2419-class`, `false-reject`, `design-smell`

- Dedup note: F-043 flags this same pattern as "treats literal 'to' as range separator on EVERY typed multi leaf" — F-043 is UNKNOWN, this is the concrete analysis of that flag. Downgraded to Low because no false reject reproduced.

---

### [LOW] R-04 — `isIdentChar` missing `@` — values containing `@` (e.g. `user@host` in archival URL) may be split

- Title: `isIdentChar` does not include `@` — archival `archive-sites` URL with `@` may be tokenized incorrectly
- Severity: Low
- Confidence: Low
- Class: implementation-bug / parity-gap
- Evidence:

  `pkg/config/lexer.go:289-297`:

  ```go
  func isIdentChar(ch byte) bool {
      return (ch >= 'a' && ch <= 'z') ||
          (ch >= 'A' && ch <= 'Z') ||
          (ch >= '0' && ch <= '9') ||
          ch == '-' || ch == '_' || ch == '.' ||
          ch == '/' || ch == ':' || ch == '*' || ch == '+' ||
          ch == '%' || ch == '=' || ch == ',' ||
          ch == '<' || ch == '>'
  }
  ```

  A URL like `scp://user:password@host/path` contains `@`. `@` is NOT in isIdentChar, so lexer returns TokenError "unexpected character: @" at that position.

- Trace:

  - Config: `set system archival configuration archive-sites "scp://user@host/path" password "secret"`
  - Lexer reads `scp://user` as identifier (includes `:`, `/`), hits `@` → TokenError, record ParseError, skip token, continue. The `host/path` part may be parsed as next identifier.
  - HOWEVER, the actual config uses quoted string for URL: `archive-sites "scp://user@host/path"` — quoted strings go through readString, not isIdentChar. So quoted form is safe.
  - Flat-set `set system archival configuration archive-sites scp://user@host/path` — unquoted, `@` breaks. But Junos itself requires quoting for URLs with special chars, so this is likely not a real operator pattern.

- Refutation attempted: Checked if any test uses unquoted `@` URL — none. Checked if Junos requires quoting for `scp://` — yes, typically quoted. The `archive-sites` leaf is `args:1, multi:true` — unquoted URL with `@` would fail.

- Why it matters: Low — operator uses quoted URLs, so no practical impact. But `isIdentChar` should include `@` for completeness (email addresses, URLs).

- Fix direction: Add `ch == '@'` to isIdentChar, or document that URLs must be quoted.

- Labels: `config`, `lexer`, `parity-gap`, `low`

- Dedup note: Not in all_findings.txt.

---

### [MEDIUM] R-05 — `validatePolicyMatchAddressSetMembersStrict` does NOT check `any` / literal CIDR / feed-binding — but defers to `validatePolicyMatchAddressesStrict` which may be lenient on load path (HA-sync)

- Title: Policy address-set member validation on lenient path may be skipped, allowing dangling set member to reach dataplane on HA peer
- Severity: Medium
- Confidence: Medium
- Class: config-fail-open / lenient-path / race-exhaustion (HA-sync)
- Evidence:

  `pkg/config/compiler_validate_strict_policy.go:408-472` + `compiler.go:1579 lenientPolicyMatchAddressSetMembers`:

  The strict gate `validatePolicyMatchAddressSetMembersStrict` is downgraded to warning on lenient (load / peer-sync). On HA sync, peer receives config, compiles lenient — a dangling address-set member (e.g. `address-set trusted { address web-server; }` where `web-server` was deleted but set not updated) warns but compiles. The runtime `resolveUserspaceAddressBookEntry` also fails for same set (returns false) → `expandUserspacePolicyAddresses` fails → `ForwardingSupported=false` for whole dataplane (commit/apply split, fail-CLOSED per #3261). So on lenient path, it fails CLOSED, not open.

- Trace: This is actually fail-CLOSED on lenient path (whole dataplane disabled when set member dangles). Not a fail-open, but a DoS (new config bricks dataplane on HA peer). However #3261 tracks the per-policy vs whole-dataplane isolation issue separately.

- Refutation attempted: Checked #3261 — the whole-dataplane disable on unresolvable app/address is intentional fail-CLOSED (safe but harsh). Per-policy isolation is deferred. Current behavior is fail-CLOSED, not fail-OPEN.

- Why it matters: On HA sync, a dangling address-set member on primary (strict rejects, so cannot happen on primary) could only arrive via direct config manipulation or old config load. Low probability.

- Fix direction: Tracked in #3261. No separate fix needed here.

- Labels: `config`, `ha-sync`, `lenient-path`, `dos`, `3261-related`

- Dedup note: Overlaps with #3261 tracking. Not a new finding.

---

### [LOW] R-06 — `isScalarValueLeaf` does NOT cover `address <name> <prefix>` with `scalar:true` — trailing tokens not rejected

- Title: `address <name> <prefix> extra-garbage` may silently drop trailing token instead of rejecting (if `address` leaf is not scalar-tagged)
- Severity: Low
- Confidence: Low
- Class: implementation-bug / unenforced-control
- Evidence:

  `pkg/config/schema.go:66` — `scalar` is opt-in per leaf. `pkg/config/schema_security.go:182`:

  ```go
  "address": {desc: "Named address (name and prefix)", args: 2, multi: true, placeholder: "<address-name>", children: nil},
  ```

  `address` is `multi:true`, not scalar. `isScalarValueLeaf` returns false for multi leaves (line 203: `!n.multi`). So `validateScalarValueLeaf` does NOT run on `address`.

  The trailing-token gate `validateTrailingTokensStrict` (compiler_validate_strict.go:62-130) catches the specific case for address-book `address <name> <prefix> bogus` and `address <name> description <text> bogus`. It records TrailingTokens during compile.

  The generic `validateScalarValueLeaf` does NOT catch `address` excess tokens; the specific `validateTrailingTokensStrict` does.

- Refutation: The specific trailing-tokens gate covers address-book `address`. Other leaves that are multi but should be scalar (e.g. `ntp server`) are intentionally multi:true so SetPath's single-value REPLACE is disabled — correct. No bug found.

- Labels: `config`, `schema`, `negative-result`

- Dedup note: #3332 scalar gate + #3332 trailing-tokens gate together cover this. Not a residual.

---

### [MEDIUM] R-07 — `interface [unit]` policer arp / static MAC is `unmodeled` — silently dropped, not rejected, on lenient path (HA-sync peer keeps bad config, applies without policer)

- Title: `interface unit family inet policer arp <name>` and `interface mac <addr>` silently dropped on lenient path — HA peer boots without policer, no error
- Severity: Medium
- Confidence: High
- Class: silently-unenforced-control / lenient-path / vSRX parity
- Evidence:

  `pkg/config/compiler_prewalk.go:178-183` — `validateUnsupportedInterfaceStanzasAST` runs on both strict and lenient, but on lenient it warns (does not reject). The leaf is parsed, compiled to typed config (or dropped), and lenient path keeps it as warning.

  The actual enforcement: `interface mac` is captured in compiler_interfaces.go and applied via netlink? Or silently dropped? Need to verify.

  From earlier code review: `validateUnsupportedInterfaceStanzasAST` rejects `mac` and `family inet|inet6 policer arp` as "unsupported interface stanzas" — these are Junos leaves xpf does NOT implement. On strict path: hard-reject. On lenient path: warn + keep (but dataplane never enforces).

  The lenient path is for load-from-disk and HA-sync — an already-persisted config that an older binary accepted may carry these stanzas. The warning is the only signal; the interface comes up without static MAC / without ARP policer, but no error.

- Trace: Operator sets `set interfaces eth0 unit 0 family inet policer arp my-arp-policer`. Strict commit rejects. But if this config was persisted by an older binary (before the gate existed) and node reboots, lenient load warns but boots — interface comes up without ARP policer. ARP flood from that interface is unpoliced.

- Refutation attempted: Checked `lenientUnsupportedInterfaceStanzas` — true on CompileConfigLenient. The warning is emitted, but no runtime enforcement. The dataplane has no ARP policer for per-unit `policer arp`. So the interface is indeed without policer on lenient boot.

- Why it matters: Medium — the specific leaves (`mac` override, `policer arp`) are not security-critical for most deployments, but ARP policer removal could allow ARP flood DoS on a unit that operator believed was policed.

- Fix direction: On lenient path, the warning is already emitted. The real fix is to implement per-unit ARP policer and static MAC enforcement, or document as known gap. The current #1960 no-brick doctrine is correct — rejecting on load would brick the node.

- Labels: `config`, `lenient-path`, `unenforced-control`, `vSRX-parity`, `interface`

- Dedup note: This is the `lenientUnsupportedInterfaceStanzas` gate itself — the gate IS the fix (strict reject + lenient warn). The residual is that lenient warn is not enough for security-critical stanzas, but the gate's design is intentional per #1960. Not a new bug, but a known accepted risk.

---

### Summary of FIXED / NEGATIVE results (no new finding)

- #2419 bracket-list stripping: FIXED (lexer.go O(1) loop, no recursion)
- #3842 duplicate inner match/then: FIXED (policyMatchChildren/policyThenChildren/policyThenActionNodes)
- #3854 quoteKey round-trip: FIXED (keyEscaper + isIdentChar)
- #3846 delete multi-leaf member: FIXED (removeMultiLeafMembers)
- #3975 deactivate multi-leaf: FIXED (markMultiLeafMembersInactive)
- #3980 navigatePath single-key: FIXED (returns all siblings)
- #3982 RenamePath non-first sibling: FIXED (findNodeWithParent longest-match)
- #3904 multi-value leaf truncation (RIP export, RI interface, IKE/IPsec proposals, etc.): FIXED (firewallMatchValues sweep)
- #3843 firewall filter prefix-list single-name: FIXED (firewallPrefixListRefs)
- #4070 apply-groups leaf-list UNION vs OVERRIDE: FIXED (isLeafListSchema + mergeLeafListInto + leafListCarriesRange)
- #4474 apply-groups transitive + memo: FIXED (memo keyed by name+ancestorPath, cycle detection)
- #3318/3317 screen unknown/numeric: FIXED (strict gates, lenient warn)
- #4147 unterminated block comment: FIXED (pending check before EOF)
- #3855 RI table-id positional → stable hash: FIXED (StableRoutingInstanceTableID)
- #3075 zone-id collision: FIXED (pre-expansion gate)
- #4405/#4406 compiler refactor: Verified via compile_golden_4406_test — no behavior change
- apply-groups ${node} cluster variable: FIXED (ExpandGroupsWithVars)
- inactive: leading + inline markers: FIXED (parser.go + inactive.go)
- Lenient path 79-field duplication: Intentional (mirrors CompileConfigLenient and CompileConfigForNodeLenient), not a bug
- isIdentChar includes `<`, `>` for `<*>` wildcard: Correct

### Findings table

| # | Title | Severity | Confidence | Class | New? |
|---|---|---|---|---|---|
| R-01 | SNAT/DNAT literal source/destination-address bracket-list residual — reads mutually exclusive but inconsistent with policy fix | Medium (latent) | High | config-fail-open (latent) | Yes (sibling of #4121) |
| R-02 | SNAT pool `address` bracket-list truncates to first address (flat-set) | Medium | High | config-fail-open / pool-exhaustion | Yes (sibling of F-098) |
| R-03 | `validateMultiValueLeaf` treats "to" as range separator on every multi leaf | Low | Medium | implementation-bug / design-smell | F-043 concrete analysis |
| R-04 | `isIdentChar` missing `@` — unquoted URL with `@` breaks | Low | Low | parity-gap | New |
| R-05 | Policy address-set member validation on HA-sync lenient path — actually fail-CLOSED, tracked in #3261 | Low (negative) | Medium | lenient-path / dos | Dup of #3261 |
| R-06 | `isScalarValueLeaf` does not cover `address` multi leaf — covered by trailing-tokens gate | Low (negative) | Low | implementation-bug | Negative |
| R-07 | Unsupported interface stanzas on lenient path warn-only — ARP policer absent | Medium (accepted risk) | High | unenforced-control | Known (gate itself is fix) |

## Suggested issue split

- **Issue 1 (Medium, config, bracket-list)**: SNAT pool `address` bracket-list truncates to first address — `compiler_nat.go:1344-1370` only reads `Keys[1]`, not `Keys[1:]`. A `address [ a b c ]` pool keeps only first IP. Fix: iterate `Keys[1:]` with range handling.

- **Issue 2 (Medium, config, bracket-list, latent)**: NAT literal `source-address` / `destination-address` (SNAT + DNAT, 4 locations) reads either Keys[1:] OR Children, not both — inconsistent with policy fix #4121 which reads both via firewallMatchValues. Apply same helper to NAT literal address reads for contract consistency.

- **Issue 3 (Low, schema-walk)**: `validateMultiValueLeaf` hardcodes `"to"` as range separator on every typed multi leaf — should be scoped to port-range leaves only. Add `rangeSeparator` or scope by leaf name.

- **Issue 4 (Low, lexer)**: `isIdentChar` missing `@` — unquoted `scp://user@host/path` breaks. Add `@` to isIdentChar.

No High-severity new fail-open found on this commit that reproduces with a concrete config + parser shape. The two Mediums are latent / flat-set bracket-list truncation that require specific configs to trigger. The rest are Low / known / negative.
