# xpf Deep Review — Campaign 161 (fable, ultracode)

> Quota-campaign adversarial audit. Every finding below survived a two-phase
> pipeline: an independent verifier re-derived it from source (CONFIRMED /
> REFUTED / duplicate), and every High-severity finding additionally got a
> standalone repro-trace agent. Findings that were duplicates of existing
> tracker issues or refuted by all verifiers are listed in the suppression
> summary, not the findings body.

## 1. Base commit reviewed

- **Commit:** `ddf9f58701eff03e2c696d9d4449337b6593e0b3`
- **Branch:** `master`
- **Tree state:** clean (read-only review; no repo files modified)

## 2. Output path

- `/tmp/fable-review-161.md`

## 3. Duplicate-suppression summary

Dedup corpus assembled before review and handed to every reviewer + verifier:

- **1,915** tracker issue titles (open **and** closed) — `issues-all.txt`
- **~160** prior review campaigns compressed to a findings index — `prior-findings.md` (677 lines)
- Known feature-gap notes — `known-gaps.md`
- **1,200** recent commit subjects — `recent-commits.txt`

Every candidate finding carries a `dedup_note` justifying why it is *not* a
restatement of a known issue (e.g. #2419, #3703, #3315). The verifier pass
independently re-checked each against the corpus and could mark
`is_duplicate`. Net result:

- **274** raw candidate findings across 42 modules
- **272** kept after verification
- **2** suppressed (see below)

| Module | Suppressed finding | Reason |
|---|---|---|
| `go-usdp-ha-events` | Session-frame decode error is silently skipped without gap/ack handling — the unacked hole guarantees a spurious session-sync resync on the next frame, and a persistent decode failure (version skew) becomes an infinite resync/reconnect loop | refuted by all verifiers |
| `x-default-deny` | Policy `then count` modifier is parsed (pol.Count) but never serialized to the dataplane snapshot — a config knob that models no enforcement/wire state | duplicate of #3074 |

One finding — *dynamic (FRR-learned) routes never reach the AF_XDP FIB*
(`rs-forwarding`) — was **contested**: one verifier CONFIRMED and one
REFUTED. It is retained but demoted to **low confidence** and flagged
**DISPUTED**; treat it as a validation task, not an established bug.

### Finding counts

| | High sev | Medium sev | Low sev | Total |
|---|---:|---:|---:|---:|
| **High confidence** | 19 | 74 | 56 | 149 |
| **Medium confidence** | 5 | 42 | 61 | 108 |
| **Low confidence** | 0 | 2 | 13 | 15 |
| **All** | 24 | 118 | 130 | 272 |

## 4. Module / feature checklist

42 named modules inspected. Each was covered on all five axes required by the
campaign: correctness/security, vSRX feature-parity gaps, performance/latency,
modularity/refactor, and test coverage. Per-module inspection logs are in §5.

| # | Module | Raw | Kept | Focus |
|---:|---|---:|---:|---|
| 1 | `go-config-parse` | 8 | 8 | Junos parser / AST edit / flat-set |
| 2 | `go-config-schema` | 8 | 8 | setSchema typed leaves + completion |
| 3 | `go-config-policy` | 3 | 3 | zone & global policy compile |
| 4 | `go-config-nat` | 7 | 7 | SNAT/DNAT/static/NAT64 compile |
| 5 | `go-config-ifaces-cos-fw` | 8 | 8 | interfaces, CoS, firewall filters |
| 6 | `go-config-routing-services` | 8 | 8 | routing-options, services, ip-monitoring |
| 7 | `go-config-validate` | 7 | 7 | commit-time schema validation |
| 8 | `go-configstore` | 8 | 8 | candidate/active/commit/rollback/journal |
| 9 | `go-cli` | 7 | 7 | interactive CLI, completion, pipes |
| 10 | `go-usdp-core` | 5 | 5 | userspace-dp Go manager core |
| 11 | `go-usdp-programs` | 7 | 7 | control-message program build |
| 12 | `go-usdp-ha-events` | 8 | 7 | HA event plumbing to dataplane |
| 13 | `go-daemon-lifecycle` | 6 | 6 | daemon start/stop/signals |
| 14 | `go-daemon-net` | 8 | 8 | interface enumerate/rename/networkd |
| 15 | `go-daemon-ha` | 8 | 8 | daemon HA wiring |
| 16 | `go-daemon-svc` | 8 | 8 | service supervision |
| 17 | `go-cluster-core` | 5 | 5 | cluster state machine |
| 18 | `go-cluster-sync` | 8 | 8 | session/config/SA sync |
| 19 | `go-vrrp-ra` | 6 | 6 | VRRPv3 + RA sender |
| 20 | `go-conntrack-appid` | 8 | 8 | conntrack GC + app-id |
| 21 | `go-frr-routing` | 8 | 8 | FRR config gen + managed section |
| 22 | `go-networkd-mon` | 6 | 6 | networkd monitor/reconcile |
| 23 | `go-ipsec-wg` | 8 | 8 | strongSwan/IPsec + WireGuard |
| 24 | `go-api-grpc` | 5 | 5 | gRPC + REST surface |
| 25 | `go-dhcp` | 5 | 5 | DHCPv4/v6 clients |
| 26 | `go-obs` | 7 | 7 | syslog/netflow/prometheus/rpm |
| 27 | `go-ops` | 8 | 8 | operational show/clear/request |
| 28 | `rs-policy` | 8 | 8 | AF_XDP policy match |
| 29 | `rs-session` | 3 | 3 | conntrack session table |
| 30 | `rs-worker` | 5 | 5 | per-queue worker loop |
| 31 | `rs-poll-descriptor` | 4 | 4 | poll/descriptor ring |
| 32 | `rs-umem-frame` | 7 | 7 | UMEM frame allocator |
| 33 | `rs-forwarding` | 5 | 5 | forwarding / FIB / fabric |
| 34 | `rs-nat` | 8 | 8 | AF_XDP NAT engine |
| 35 | `rs-screen` | 4 | 4 | screen/IDS checks |
| 36 | `rs-filter` | 6 | 6 | firewall filter fast path |
| 37 | `rs-cos-tx` | 6 | 6 | CoS shaping / TX |
| 38 | `rs-server` | 5 | 5 | control socket server |
| 39 | `rs-wg-coord` | 5 | 5 | WireGuard coordination |
| 40 | `x-default-deny` | 6 | 5 | cross-cutting default-deny audit |
| 41 | `x-hpc` | 6 | 6 | HPC invariants (atomics/align/endian) |
| 42 | `x-tests-build` | 8 | 8 | test coverage + build hygiene |

## 5. Module-by-module inspection log

### `go-config-parse`  — 8 kept / 8 raw

READ (full): pkg/config/lexer.go, parser.go, ast.go, ast_edit.go, ast_format.go, ast_groups.go, freetext.go, inactive.go, secret.go. READ (supporting): configstore/store_command.go (Set/Delete/Annotate/LoadSet/applyEditLine), store_commit.go (saveRollbackFiles/loadRollbackHistory — rollback slots persist via Format() and re-parse with NewParser at boot), store.go SyncApply, daemon/daemon_ha_sync.go (pushConfigToPeer sends ShowActive()=Format() text; handleConfigSync re-parses on the standby — so Format→Parse round-trip fidelity is load-bearing for HA config sync AND rollback history), cli wiring for display xml/json and annotate, schema_security.go multi:true leaves. EMPIRICAL VERIFICATION: built an external probe module (scratchpad/probe-goparse, replace-directive on the repo; repo untouched) and ran 10 behavioral probes against HEAD — all 8 reported findings are runtime-confirmed, with probe output quoted in traces. LENSES: (a) correctness/security — findings 1-5; (b) vSRX parity — findings 1,4,6,8 (leaf-list delete semantics, deactivate round-trip, apply-groups leaf-list merge, display xml/json shape); (c) performance — Peek() re-lexes every token (parser peeks then consumes, so each token is lexed twice) and FormatCompare/nodesEqual rebuild KeyPath strings and maps per level: both negligible at config scale, NOT reported; (d) refactor debt — decomposing parser/AST into pkg/config/ast/ is DISCARDED as duplicate of closed backlog #2002 (and #555 test split); (e) test gaps — no test exercises delete/deactivate against bracket-collapsed multi leaves or Format→Parse round-trip of backslash values (covered inside findings 1,2,4 fixes). DISCARDED AS DUPLICATES: (i) flat-set bracket-list SET-side collapse — #2419/#3703/#2630/#2689/#2702 all fixed at HEAD (SetPath's case-(b) absorb verified present and working in probe 1); (ii) `\n`-escape control-char INJECTION into rendered files — #1798 (three defense layers verified in freetext.go; my finding 2 is the inverse serializer-side defect); (iii) PSK quoting breakage — #2126 is the swanctl render layer, distinct from the AST round-trip layer; (iv) name-server second-set-replaces-first — #1810 fixed (schema now multi; probe 4 shows both leaves stored); (v) pkg/config decompose refactor — #2002; (vi) secret redaction gaps — #2053 verified sound at HEAD (type-enforced MarshalJSON/MarshalYAML value receivers, sentinel refusal on unmarshal, RedactURL #2781 handles userinfo+query correctly) — module clean, no finding; (vii) inactive strip-before-expand ordering (#2008 H1) verified correct in inactive.go (WithoutInactive/cloneForExpansion aliasing rules sound). NEGATIVE RESULTS: expandGroupsRecursive's circular-reference `seen` map is effectively dead code (a group's expansion at one level never re-enters before `delete(seen,name)`), but I could not construct a non-terminating A↔B or self-reference shape — idempotent mergeNodes + context-walk convergence bounds growth — so not reported as a bug; FormatPathSet parent-prefix computation scans path by string equality with the matched node's first key and drops a path token when a user name collides with a keyword (probe 9: zone literally named "interfaces" loses the zone name in display-set output) — confirmed but trigger too contrived to spend quota on; nodesEqual ignores Annotation so an annotate-only edit shows an empty `show | compare` diff (minor, display-only); Annotate path-navigation matches ANY key of a node (not first-key) which can annotate the wrong sibling — low impact, not reported for quota.

### `go-config-schema`  — 8 kept / 8 raw

MODULE: go-config-schema (pkg/config/schema.go, schema_complete.go, schema_walk.go, schema_validators.go, schema_security.go, schema_system.go, schema_routing.go, schema_interfaces.go, schema_chassis.go, schema_cos.go, predefined.go) at HEAD ddf9f58.

READ (full): all 11 assigned files, plus grounding reads of ast_edit.go SetPath/DeletePath (grouping SSOT), ast_groups.go (apply-groups expansion), compiler_system.go (ntp/archival/ssh/name-server/snmp/dataplane), compiler_routing.go (static routes, policy-options), compiler_ipsec.go + pkg/ipsec/policy.go+ike.go (proposals/version/mode consumers), compiler_services.go (dhcp-relay, event-options), compiler_firewall.go (firewallMatchValues), inactive.go (WithoutInactive nil-safety), schema_validate_test.go (TestSetPathGrouping_Golden). Key functions traced: SetPath (replace-vs-container-vs-multi-absorb branches), walkSchemaNode/validateTypedLeaf/validateMultiValueLeaf/validateScalarValueLeaf/walkInstanceChildren, CompleteSetPathWithValues/ResolveConsumedSetPathTokens, collectSchemaRefs.

EMPIRICAL VERIFICATION: wrote temporary probe tests in the package (deleted afterwards; git tree clean) that CONFIRMED at runtime: ECMP bracket next-hop compiles 1 of 2 gateways; ntp server/archive-sites/ssh-ed25519 second set replaces first (NTPServers=[2.2.2.2] etc.); `name-server 8.8.8.8 to 8.8.4.4` passes SchemaValidate and compiles literal 'to' as a nameserver; `then log session-init to session-close` passes while `sesion-init` is rejected; `prefix-list pl1 [ a b ];` compiles EMPTY and flat one-liner keeps only first; `proposals [ prop-a prop-b ]` compiles \"prop-a\"; `set snmp ?` offers only community/trap-group/v3.

LENSES: (a) correctness — findings 1-6; (b) vSRX parity — findings 1,2,3,5,7,8 + discarded items below; (c) performance — no hot-path code in this module (schema walk runs once per commit; ValidateEnum pre-builds a set; append-heavy path copies are commit-time only) — nothing material; (d) refactor debt — #1891 domain split into sibling files is a documented deliberate decision (setSchema unexported, consumed in-package), so a subpackage proposal would contradict the recorded contract; the real structural debt is per-arg-slot completion metadata (finding 8) and the lack of a generic multi-leaf/compiler-reader agreement canary (folded into findings 3/7 fixes); (e) test gaps — TestSetPathGrouping_Golden pins replace semantics only for CoS priority; no coverage for list-valued system leaves, no test for the 'to' separator, no schema<->compileSNMP canary (folded into findings).

DISCARDED AS DUPLICATES: (1) predefined junos-tftp/junos-sip lacking ALG tags — duplicate of #3353 (per-application alg is inert end-to-end; comment at compiler_applications.go:636 confirms); (2) host-inbound bracket/flat list collapse — #3703 fixed at HEAD (hostInboundSchemaChildren multi leaves verified) + prior-finding line 639; (3) unknown screen leaves silently committing — #3318; (4) default-policy fail-open / missing schema leaf — #3065 fixed (typed enum verified at HEAD); (5) session-log container mis-nesting — #3703 fixed via sessionLogModeLeaf (only the 'to' residual is new, finding 4); (6) trap-group children:nil — #2990 fixed (targets/version/categories declared + compiler unknown-key reject verified); (7) policy then permit/deny/reject drift — #3377 fixed + canary test present; (8) scheduler-name absent from schema — #3117 fixed; (9) route-filter match-type-in-prefix-slot acceptance — documented known limitation in ValidateRouteFilterArg (#2105); (10) tls-profile offered-but-rejected — deliberate #3350 design; (11) unbounded ValidateDHGroup (modp999 renders invalid swanctl) — adjacent to the closed #2604/#2392 invalid-render class, discarded as likely-dup; (12) flow aging opaque/typed — #3440 fixed at HEAD; (13) duplicate top-level security blocks bypassing validators — #3562 (walkSchemaChildren iterates all siblings, not affected); (14) 493 empty-help nodes — #1892.

NEGATIVE RESULTS: walker modifier/sibling logic (validateTypedLeaf cross-sibling rule, validateModifierChild recursion) is consistent with SetPath grouping — no over/under-rejection found beyond documented contracts; consumeNodeKeys compoundKey descent is sound (unknown sub-token degrades to parent schema, no crash); groups wildcard aliasing of live schemaNode pointers is safe (tree is read-only post-init); WithoutInactive is nil-receiver-safe on defsSource; SchemaValidateWithDefinitions merges only forwardingClasses from defsSource but that is currently the ONLY schemaRefs set (no silent loss today — would become a bug when a second ref set is added, noted but not reported as no current defect); completion prefix-resolution vs SetPath exact+wildcard lookup can theoretically diverge at levels with both children and a wildcard (rpm target, syslog host) but no realistic colliding token found; apply-groups at nested levels works via the unknown-leaf fallback (expander reads Keys) so only completion is missing — judged below reporting threshold given quota.

### `go-config-policy`  — 3 kept / 3 raw

Read all 10 assigned files in full plus supporting code: compiler_security.go (compilePolicy/compilePolicies/compileZones/compileScreen/compileFlow/resolveZoneLocalAddressBooks), compiler_policy_match.go (#3113/#3142/#3673 gate), compiler_policy_then.go (#3114/#3115/#3141/#3374 gates + collapsedThenActionTokens), compiler_policy_missing_match.go (#3044), compiler_applications.go (compileApplications/parseApplicationTerms/resolveAppPort/validatePortSpec/validateProtocol), compiler_applications_collision.go (#3339/#3472), host_inbound_tokens.go, host_inbound_view.go, screen_inventory.go, types_security.go. Cross-checked helpers: ast.go FindChild/FindChildren (first-match/all-match), parser.go parseStatements (APPENDS duplicate sibling blocks at every level), ast_groups.go mergeNodes (apply-groups DEEP-MERGES same-key containers, so groups do NOT create sibling dups), configstore/store_command.go LoadOverride (sets candidate = raw hierarchical tree, preserving duplicate sibling blocks) vs LoadMerge (flattens via FormatSet→set-commands→merge), store_commit.go Commit→compileTree→compileTreeStrict→CompileConfig (compiles the raw candidate), compiler.go (SecurityConfig.DefaultPolicy initialized to PolicyDeny #3065 — fail-closed), schema_security.go (default-policy ValidateEnum; application-set children:nil = opaque subtree; term children:nil opaque), compiler_validate_strict.go validateApplicationSetMembersStrict/filterProtocolResolvable, appid/catalog.go ProtocolNumber (junos-ping→1), dataplane/userspace/capabilities.go normalizeUserspaceApplicationProtocol.

Lenses covered: (a) correctness/security — 3 fail-open/parity bugs found and RUNTIME-CONFIRMED via standalone programs importing pkg/config; (b) parity — duplicate-block additive merge + application-set membership; (c) perf — collapsedThenActionTokens per-policy alloc is negligible, no finding; (d) refactor — the FindChild-first-block pattern is duplicated across compilePolicy + 4 gate checkPolicy closures (root of finding 1); (e) test gaps — no test exercises duplicate inner match/then blocks or typo'd application-set member keywords.

CONFIRMED via execution: (F1) a 2nd `match { dynamic-application ... }` block bypasses the #3113 strict gate (compile ACCEPTED, L7 constraint silently dropped → permit-all-apps); a 2nd `then { deny }` after `then { permit }` is dropped and #3043 conflict is NOT detected (Action=PolicyPermit despite operator deny). (F2) a typo'd application-set member keyword (`aplication other-evil`) is silently dropped, set 'blocked' compiles to [evil-app] with NO commit error.

Candidates DISCARDED as duplicates: default-policy typo fail-open — NOT a bug (SecurityConfig.DefaultPolicy inits to PolicyDeny, compiler.go:1872, #3065; enum gate + fail-closed init). Direct-app `protocol junos-ping` unnormalized (app.Protocol kept raw at compiler_security-adjacent compiler_applications.go:64) — NOT a bug (appid.ProtocolNumber resolves junos-ping→1 and ICMPType=8 is set; strict gate filterProtocolResolvable rejects junos-* typos). Application-set nested-member drop — FIXED (#2068, arm added). Undefined application-set member reference — COVERED (#2217 validateApplicationSetMembersStrict, but only for STORED members — see finding 2 for the residual). Excluded-address display/semantics — prior findings + #3023/#3336/#3356, not re-reported. Duplicate top-level security{}/policies{} blocks — FIXED (#3562); flow/log sub-blocks — FIXED (#3566); finding 1 is the INNER match/then residual those fixes did not reach. Screen inventory drift — #3327 (ScreenChecks documented superset, no enforced-but-missing check found).

### `go-config-nat`  — 7 kept / 7 raw

READ: pkg/config/compiler_nat.go (all 1875 lines: validatePoolUtilizationAlarm, natAddrFamily/isHostMaskAddress/natStaticPrefixInfo, validateNATHostMaskStrict, validateNPTv6Strict, compileNAT/compileNAT64/compileNATSource/compileNATDestination/compileNATStatic, parseZoneList/parseNATMatchScopes/collectNATScopes, expandAddressRange, parseDNATPoolAddress, parseDNATPortList/appendDNATPortRange, staticNATMappedPortFromKeys); pkg/config/compiler_nat_dnat_to.go (validateDNATRuleSetToScopeAST, forEachChild); pkg/config/natpool.go (SourceNATPoolNets, parsePoolAddr, IPInNets); NAT sections of pkg/config/compiler_validate_strict.go (validateDNATPoolStrict #3450 at 5573-5657, validateNATMatchApplicationsStrict 2178-2300, NAT-referenced application validation ~3890); pkg/config/schema_security.go NAT stanza (303-467); pkg/config/ast_edit.go SetPath grouping (129-323); pkg/dataplane/userspace/nat.go (SNAT/DNAT/NAT64/NPTv6 snapshot builders, sourceNATPoolPortRange, DNAT rule skip at :681); userspace-dp/src/nat/source.rs (expand_pool_address #3049, parse_source_nat_rules, pool_failure -> Unavailable at :825), userspace-dp/src/nat64.rs (try_from_snapshots /96 integrity reject), userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs (build_reconcile_forwarding abort-without-publish); pkg/dataplane/proxyarp.go (ReconcileProxyARP). EMPIRICAL VERIFICATION: built a scratchpad Go program importing github.com/psaab/xpf/pkg/config via replace; reproduced (a) documented CGNAT flat-set config REJECTED at compile in both orders ("deterministic block-size must be > 0" / "deterministic host address required") while hierarchical block form compiles, (b) `then destination-nat off` passes SchemaValidate+CompileConfig and yields Then.Type=0/pool="" (builder skips at nat.go:681), (c) Junos-syntax `port range 5000 to 6000` and `port no-translation` compile green with PortLow/High=1024/65535, (d) NAT64 `prefix 64:ff9b::/64` commits green, (e) duplicate `source {}` block under one `nat {}` silently drops its rule-set (ruleSets=0), (f) `address [ a b c ]` bracket pool keeps only first address. LENSES: correctness/security (F1,F2,F5), vSRX parity (F2,F3), perf (checked appendDNATPortRange bound #3449 fix present; expandAddressRange bounded 256; no hot-path concerns in this compile-time module), refactor debt (F7), test gaps (deterministic NAT has ZERO compile tests — folded into F1). DISCARDED AS DUPLICATES: proxy-ARP v6 pneigh/per-address narrowing + CIDR-base-only install -> OPEN #2197; proxy-ARP sysctl teardown -> #2475 fixed; NPTv6 overlap/host-bits/fail-open -> #2240/#2241/#2380 fixed at HEAD (validateNPTv6Strict present); SNAT subnet pool truncation -> #3049 fixed (expand_pool_address at HEAD); DNAT pool port/address validation -> #3450 fixed (validateDNATPoolStrict present); DNAT dport wildcard/amplification -> #3446/#3449 fixed; multi-value match lists -> #3431 fixed for match leaves (residual pool-address leaf reported as F6 with mechanism distinction); reversed app port range -> OPEN #3726 (known, excluded); static-NAT external-key shadowing -> prior finding on static_nat.rs from_snapshots; persistent-nat modeled under pool instead of Junos rule-then placement -> deliberate #2823 modeling, treated as accepted deviation; NAT hit-counter semantics -> known-gaps #2218; Twice NAT -> known-gaps #645; NAT64 pool range-form -> #2123 fixed. NEGATIVE RESULTS: natpool.go is clean (nil-safe, unknown-pool vs empty-pool distinguished, Address+Addresses both covered, unparseable entries skipped without widening the clear-filter); validateDNATRuleSetToScopeAST correctly descends with forEachChild at every level (no #3562-style bypass); appendDNATPortRange correctly bounds expansion and preserves out-of-range endpoints for the strict gate; validateNATHostMaskStrict/#3206/#3202/#3031 static-NAT paths are coherent with Rust static_nat.rs semantics.

### `go-config-ifaces-cos-fw`  — 8 kept / 8 raw

READ AT HEAD ddf9f58: pkg/config/compiler_interfaces.go (compileInterfaces, parseTunnelWireguard/Peer, selectMSSToken, parseVRRPGroups, validateVRRPTrackInterfaceAST, checkVRRPGroupTrackShape, vrrpTrackConfigWarnings, compileInterfaceDynamicDNS), compiler_interfaces_unsupported.go (#2008 H9/H10 gate), compiler_class_of_service.go (compileClassOfService, collectCoSDSCP/8021CodePoints, collectCoSDSCPRewriteCodePoint, parseCoSTransmitRate, fairness collector), compiler_firewall.go (compileFirewall, firewallMatchValues, compileFilterFrom/Then), filter_match_resolve.go, firewall_filter_expand.go, tcp_flags.go, types_cos.go, types_interfaces.go. Supporting reads: ast_edit.go SetPath grouping, schema_cos.go, schema_interfaces.go, compiler_protocols.go parse helpers, schema_validators.go, configstore/store.go SchemaValidate wiring, pkg/dataplane/compiler_filter.go + userspace/filters.go, pkg/routing/tunnel.go. VERIFICATION: built an external Go probe module (scratchpad, replace-directive to repo) and ran 8 runtime probes through NewParser+CompileConfig(+Lenient)+SchemaValidate at HEAD; every reported bug finding is probe-confirmed, not speculated. LENSES: (a) correctness/security F1/F2/F3; (b) vSRX parity F4/F5/F6/F7; (c) performance — module is compile-time only; checked FilterTermExpansionCount arithmetic (uint32 cast needs ~4G rules to overflow, unreachable) and counter-slot stride (#3459 contract intact) — no hot-path issues; (d) refactor F8; (e) test gaps folded into findings. DISCARDED AS DUPLICATES: cross-field protocol/port/tcp-flags/icmp contradiction gate (#3723 + prior findings on compiler_firewall.go); DSCP/port-except handling at the Rust boundary (#3715/#3716, prior findings on filter/compiler.rs dscp_rewrite masking); tcp-flags disjunction/negated-group fail-closed (#3076 — verified sound; Junos numeric/hex tcp-flags like 0x12 are rejected LOUDLY, a fail-closed parity nuance I chose not to report separately); bracket-list collapse of from-match values (#2419/#2545 — verified firewallMatchValues reads Keys[1:]+children); prefix-list refs dropped in the dataplane snapshot (#2506 — fixed; my F1 is a different, compile-side AST-shape mechanism); mixed positive+except folding (#3359); DSCP/802.1p out-of-range aliasing (#2447 — verified rejected); classifier inline loss-priority leaf (#1809 — fixed for classifiers; F6 reports the MISSED rewrite-rules arm as a named residual); flexible-match-range value fail-closed (#3203/#3232 — verified; the silent 'break' on a second range instance is documented single-range-by-design, not reported); filter counter stride (#3459 — verified); MaxFilterRules=512 legacy truncation investigated and dropped: the legacy compile runs against a no-op shim DataPlane and the Rust helper enforces from uncapped snapshots with its own per-term counters, no concrete runtime harm established (negative result); VRRP track-interface shape gates (#1814/#1821 — sound); vlan-id/inner-vlan-id gated by schema ValidateInteger(1,4094) — sound; FC-to-queue bijection (#785/#787) — sound; pkg/config file-split refactors (#2002/#1699/#1701, prior compiler_security.go split finding) — F8 proposes a different mechanism (shared dual-AST-shape prop-walk helpers) anchored by two confirmed bugs. NEGATIVE RESULTS: compileInterfaceDynamicDNS walker (bounded, first-wins, both shapes) clean; parseTunnelWireguardPeer multi-shape accumulate clean; selectMSSToken precedence (#1979) clean; DHCPv6 client parse clean; fairness rss-expectation duplicate detection clean; no interface-range dedup hits anywhere in issues/prior findings/docs (not even documented as a gap).

### `go-config-routing-services`  — 8 kept / 8 raw

READ (full): pkg/config/compiler_routing.go (935L: compileRoutingOptions, compileStaticRoutes, compileRoutingInstances, compilePolicyOptions, parsePolicyTermChildren/InlineKeys, applyCommunityAction), compiler_protocols.go (1073L: compileProtocols OSPF/BGP/OSPFv3/RIP/ISIS, compileRouterAdvertisement, namedInstances/nodeVal helpers, bandwidth parsers), compiler_services.go (1728L: RPM validators, DHCP local-server/relay, ip-monitoring + resolveIPMonitoringInterfaceNextHop, flow-monitoring, sampling, port-mirroring, event-options, bridge-domains), compiler_system.go (1417L: compileSystem, DDNS services, userspace dataplane knobs, SNMP/v3, compileChassis cluster, validateBackupRouterDst), compiler_ipsec.go (589L), compiler_ipsec_bindiface.go, compiler_chassis.go, tunnelemit.go, tunnelid.go, types_routing.go, event_options_match.go, lifeline.go. Cross-verified consumers: pkg/frr/policy_render.go (router bgp gate line 622, RIP render 918-935, redistribute), pkg/frr/config_render.go (generateStaticRouteInTable 99-170), pkg/routing/vrf.go (table-mismatch recreate 239-249), pkg/ipsec/ike.go (deriveDPD 137-179, proposal lookups 57/86-90), pkg/ipsec/policy.go (dpd_action emit 195-196), pkg/config/schema_routing.go (staticRouteNode qualified-next-hop preference/metric children 86-90, routing-options autonomous-system 108, RIP subtree 326-333, schemaRoutingInstances 546-564), schema_system.go (syslog wildcard). LENSES: correctness (F1-F4,F6-F8), vSRX parity (F1,F3,F5,F6), performance/outage (F2), refactor debt (F2 = positional-identity class; ad-hoc dual-AST readers noted), test gaps (no test pins routing-options AS to FRR render; no floating-static qualified-NH test).

DISCARDED AS DUPLICATES / KNOWN: (1) rib-group Apply error swallowing — OPEN #3731 (module notes flag it). (2) rib-group import-rib loose name matching — CLOSED #2253/#2226, HEAD reflects behavior as accepted. (3) OSPF/BGP/OSPFv3/ISIS export multi-value + community members — fixed #2587/#2689/#2702, HEAD uses firewallMatchValues. (4) IPsec dh-group "groupN" — fixed #2639 (parseDHGroup SSOT at HEAD). (5) isPlausibleHostname trailing-dot cap — fixed #2596. (6) bind-interface if_id alias collision — #2933/#2929/#3562, gate present at HEAD. (7) tunnel-endpoint positional ids / gate drift — #1873/#1910/#1914, tunnelid.go+tunnelemit.go carry the parity emitter and tests; clean. (8) event-options — #3753-#3755 fresh, avoided per instructions; event_options_match.go validators are dense and issue-referenced (#2141/#2124). (9) lifeline.go fab*/em0 prefix-match overreach — already documented as an open design question inside #3682's own comment. (10) SNMP trap-group unknown-key/zero-target — fixed #2990 at HEAD. (11) backup-router family mismatch — fixed #2911/#2907. (12) RPM routing-instance/source/link-local/scheme gates — #2492-#2496/#2614 all fixed at HEAD. (13) device-map validation — #1956 + AGY review, clean. (14) sampling one-SourceAddress-per-family limitation — documented in-code (#2605 comment), accepted.

NOTED BUT NOT REPORTED (quota, weaker or partially schema-guarded): (a) RA dns-server-address bracket list keeps only first RDNSS (nodeVal at compiler_protocols.go:742-745) — same #2419 class as F5/F8, lower blast radius; (b) rib-groups import-rib flat-chain children read only child.Name() (compiler_routing.go:57-59), drops later keys of a chained node; (c) `system syslog host <h> port/source-address/transport` not modeled — wildcard severity-enum rejects them at commit (fail-closed parity gap only); (d) IKE `pre-shared-key hexadecimal <hex>` would be stored as ascii text (compiler_ipsec.go:80-81) but schema does not model hexadecimal so path is schema-gated; (e) per-instance routing-options rib-groups/generate/forwarding-table are dropped by compileRoutingInstances but also not schema-declared per-instance (consistent fail-closed); (f) duplicate routing-instance blocks would compile two same-named RoutingInstanceConfig with different TableIDs (parser append semantics per #3562), subsumed by F2's stable-identity fix direction.

NEGATIVE RESULTS: tunnelemit.go/tunnelid.go and compiler_ipsec_bindiface.go are genuinely mined out — every non-trivial branch carries an issue-referenced invariant and parity tests (TestEmitTunnelEndpointNamesMatchesBuilder). lifeline.go is 83 lines of documented, issue-referenced logic. compiler_chassis.go device-map validation covers all cross-entry invariants I could construct (dup name/PCI/MAC, key-order sanity, RETH PCI-keying, FPC/node alignment).

### `go-config-validate`  — 7 kept / 7 raw

MODULE: go-config-validate (pkg/config/compiler.go 3604L, compiler_validate_strict.go 6211L, compiler_validate_warn.go 1810L, compiler_validate_wireguard.go 221L) at HEAD ddf9f58.

READ/COVERED: compiler.go — compileOpts, CompileConfig/Lenient, CompileConfigForNode/Lenient, full compileExpanded validator chain (lines 1260-3604: AST pre-walks #1798/#1814/#1979/#3349/#3350/#3420/#3422/#3424/#2008/#3339/#2933/#3113/#3114/#3115/#3141/#3044/#3444; strictErrs accumulator; ~70 strict-with-lenient-downgrade gates; ValidateConfig + VRRP/pool-alarm/backup-router/VRRP-VIP/host-mask/NPTv6/WG tails). compiler_validate_strict.go — sampled systematically: lines 1-500 (log format, three-color policers, dataplane type, scheduler refs, IPsec/IKE chains, log-profile streams, feed-server endpoint), 562-900 (feed refs, flow-server templates, sampling conflicts), 1079-1964 (community refs, frrTokenUnsafeIndex, FRR auth — verified ALL AuthKey fields covered incl. RIP/ISIS area+iface, BGP peer-as, router-id, policer/prefix-list/routing-instance/filter refs, filter output-FBF direction, app-set members), 1964-2523 (policy match addresses/applications, NAT match applications, policyMatchAddressBookResolves cycle semantics — verified pure-cycle rejected via count==0), 2625-3480 (reserved zones, zone refs incl. #3639 junos-host direction split, dup policy names, screens, trailing tokens, flow aging, terminal/log action, zone count/membership + zoneIfaceLogicalKeys unit-split semantics), 3481-3755 (application specs #3109/#3150/#3373/#3320/#3348), 4280-4660 (port/address except, address literals + classifyFilterAddrFamily, from-match, RI conflict), 5125-5913 (rib-group refs + ribInstanceFromName exact-suffix, DHCP static bindings, DNAT addresses/protocol/dport/pool, route-filter through/prefix-length-range, NAT address-name refs incl. #3425 resolvability + feed carve-out, VRRP VIP subnet, host-inbound tokens, address-book '/' names). compiler_validate_warn.go — read in full. compiler_validate_wireguard.go — read in full; traced end-to-end into compiler_interfaces.go parseTunnelWireguard/parseTunnelWireguardPeer, pkg/dataplane/userspace/tunnels.go snapshot builder, and userspace-dp forwarding_build/tunnels.rs hydrate_wg_identity + wg_control.rs.

LENSES: (a) correctness/security — findings 1,2,3,5; (b) vSRX parity — findings 1,2 (commit/apply split doctrine); (c) performance — validators are commit-path only (cold), no hot-path issues; the only perf-adjacent item is compileExpanded's O(validators × config) linear chain which is acceptable at commit frequency — no finding; (d) modularity — findings 4,7 (proposed a pkg/config/validate/ registry, not more sibling files); (e) test gaps — finding 6.

DISCARDED AS DUPLICATES (dedup corpus refs): lenient feed-server slash-only URL bypass (prior-findings lines 614/629 — same mechanism); host-inbound bracket-list tail bypass (prior-findings 245/640); `then log [ session-init bogus ]` tail (prior-findings 247/646); global-policy junos-host context reject (prior-findings 12; the to-zone half was LIFTED in #3639, verified at HEAD lines 2715-2737 — from-zone reject remains deliberate #3611 Piece A); stale tolerant-DSCP comment (prior-findings 326); missing cross-field filter semantic pass (prior-findings 405); duplicate firewall local-address validator (prior-findings 375/390); ICMP code-without-type filter asymmetry (prior-findings 398); zone-name transport-safety contract (prior-findings 286); lo0 `then routing-instance` no-warning (prior-findings 399 — FIXED at HEAD, #3724 M04 warning present at warn.go:1055); WG exact-duplicate AllowedIPs (#2445 CLOSED, fix verified at HEAD); WG case-differing duplicate pubkey (handled: parseTunnelWireguardPeer lowercases at compiler_interfaces.go:569 + TestWireguardDuplicatePubkeyCaseInsensitive).

NEGATIVE RESULTS (checked, sound): dnatProtocolResolvable accepting '+6'/'007' via Atoi — matches Rust u8 FromStr (also accepts leading '+'/zeros), no divergence; #3606 canonical-port gate is port-specific and separate; validateFRRAuthValuesStrict covers every Secret auth field in types_routing.go (OSPF iface, RIP, ISIS area+iface, BGP neighbor) — doc mention of message-digest-key maps to the same AuthKey field; FirewallConfig has only FiltersInet/FiltersInet6 maps so the filter gates' two-family walk is complete; zoneIfaceLogicalKeys unit-vs-bare claim semantics match buildInterfaceZoneMap; validateDHCPStaticBindingsStrict family/subnet/dup checks correct incl. Masked() prefix; validatePrefixLengthRange strictly-greater-than-base matches FRR ge semantics; WG hostname endpoint is REJECTED at commit (fail-loud, matches documented ip:port grammar and Rust SocketAddr-only consumption) — not reported as a bug; ValidateConfig nil-guard sweep (#3494) is thorough across the warn pass; policyMatchAddressBookResolves mirrors runtime seenSets persistence correctly. SchemaValidate confirmed strict on commit (configstore/store.go:281), so WG listen-port MALFORMED-value is schema-caught — finding 1 scoped to absence + private-key (which has no schema validator).

### `go-configstore`  — 8 kept / 8 raw

READ (all non-test .go at HEAD ddd9f58): pkg/configstore/{store.go (New, SyncApply, compileTree*), store_commit.go (Commit/CommitWithDescription/CommitConfirmed/ConfirmCommit/fireConfirmTimer/PromoteRollback/performAutoRollback/Rollback/saveRollbackFiles/cleanupRollbackFiles/loadRollbackHistory), store_persist.go (Load/Save/writeActive*/journalLog/persistRetryLoop/ArchiveConfig/writeArchive/rotateArchives/rescue*), store_lock.go (EnterConfigure*/Exit*/ForceExit/edit-path), store_command.go (Set/Delete/Load*/applyEditLine/hasFlatVerb), store_format.go (Show* family), db.go, envelope.go, crypto.go, history.go, check.go, test_seams.go, dataplane_retire.go}, journal/journal.go (Log/maybeRotateLocked/Tail/tailScan/parseLine), fsatomic/fsatomic.go (writeFile/SyncDir/MkdirAllDurable/options), linuxsock/linuxsock.go. Cross-checked callers: pkg/daemon/daemon_apply.go (commitAndApply/commitConfirmedAndApply/executeConfirmedRollback/syncAndApply), daemon_ha.go (SetClusterReadOnly transitions), daemon_run.go (eventengine commitFn wiring), pkg/grpcapi/server_config.go + server.go (configLockInterceptor/peerSessionID) + server_diag.go (clear-config-lock), pkg/api/config.go, pkg/cli/cli_config.go + cli_dispatch.go + cli_clear.go, pkg/eventengine/engine.go (applyOnce), cmd/cli/shared.go. LENSES: (a) correctness — confirm-timer state machine, lock/session semantics, clusterReadOnly gate; (b) parity — Junos commit-confirmed/rollback-1 semantics, master-password; (c) perf — saveRollbackFiles write amplification under s.mu, journal tail-scan boundedness (verified bounded and correct incl. pending-cap resync); (d) refactor — dead DB candidate/rollback API; (e) tests — store_test.go confirm coverage (no test commits plain while a confirm window is pending; no test exercises ExitConfigureSession on an exclusive session). DEDUP SEARCHES: grepped issues-all.txt and prior-findings.md for configstore, fsatomic, linuxsock, journal, envelope, crypto, master-password/master.key/encrypt, commit confirmed/confirm, rollback, persist, exclusive, read-only, candidate; grepped recent-commits.txt for configstore/fsatomic/journal/rollback. DISCARDED AS DUPLICATES/ALREADY-FIXED AT HEAD: (1) commit-success-but-lost-on-restart — #1799 fixed, persist-before-promote verified in CommitWithDescription; (2) no-fsync durable state — #1894 fixed via pkg/fsatomic, classes verified; (3) nil-DB fallback panic — #1893 fixed (New fails closed, store.go:174-192); (4) journal O(lifetime) reads / fat payloads — #1896 fixed (v2 compact + bounded tailScan, verified the reverse-scan cap logic sound including the terminating-newline resync); (5) auto-archive wrong-commit/overwrite + rollback durability + loader/cleanup contiguity — #3441 fixed (seq+capture-under-lock, rbWriteFileDurable slot 1, degraded bit) — did NOT re-report; (6) malformed flat-load lines fail-open — #3442 fixed (hasFlatVerb gate in LoadSet/LoadMerge); (7) rollback selector strict parsing — #3443/#3447 fixed in api/cli; (8) store.go >2k LOC split — #2158 done; (9) journal rotation crash-gap and fsatomic post-rename dir-fsync ambiguity — documented accepted trades in package docs, not re-reported; (10) eventengine "path not found" string-match — prior finding (codex corpus), not re-reported. NEGATIVE RESULTS: linuxsock is clean (single CLOEXEC-forcing wrapper + canary, no callers bypass found); fsatomic writeFile error paths all remove the temp and the option precedence (WithOwner vs WithPreserveExisting) matches its doc; envelope min-reader/committed-marker parse fails closed on malformed fields; crypto.go key-before-ciphertext durability ordering is structurally sound (readOrCreateMasterKey durable-writes inside the encrypt step); History ring-buffer index math verified for wrap; persistRetryLoop singleton/backoff logic verified (marker re-write honors persistMarkerCommitted). Considered and dropped as too-thin: CommitCheck not confirming a pending confirm (Junos `commit check` confirms — folded into finding 1's fix direction); confirm timer not surviving daemon restart (matches Junos-ish behavior, #1922 Item 1b covers the dangerous first-commit case); ExitConfigure not clearing configHolder (gated by configDir, cosmetic only — surfaced inside the exclusive-lock finding since ConfigHolder() prints an empty holder for exclusive sessions).

### `go-cli`  — 7 kept / 7 raw

Read at HEAD ddf9f58: pkg/cli/permissions.go, cli_dispatch.go (pipe/pager/dispatch), cli.go (Run loop, SIGINT, completer listener), completion.go, cli_show.go (display-pipe handling), monitor.go (full flow-trace hardening #3378-3382), monitor_interface.go (full-screen views), cli_request.go (ping/traceroute/test/monitor/request handlers), session_filter.go, cmdtree/tree.go (operational + config trees), diagcmd/diagcmd.go. Cross-checked pkg/config/types_system.go (LoginClassPermissions), pkg/api/system.go + pkg/grpcapi/server_diag.go (ping count clamp) to substantiate CLI/REST/gRPC divergence.

Lenses covered: (a) correctness — found stdin goroutine leak in monitor_interface.go, tcpdump matching-filter truncation, unclamped ping count; (b) parity — config-mode prefix abbreviation gap, pipe substring-vs-regex, monitor-under-view privilege; (c) perf — nothing new (monitor loops are 1s-tick, delegate to monitoriface); (d) modularity — monitor.go is 949 LOC mixing trace rotation/writer/parse/format but recently hardened and cohesive, not worth a refactor finding; (e) test-gaps — sort-by unvalidated.

DISCARDED as duplicates:
- monitor flow file path traversal / mode 0644 / symlink → #3378 (CLOSED, fixed: sanitizeTraceFilename + O_NOFOLLOW + 0600 present at HEAD).
- monitor flow/packet-drop fail-open parsing (empty filter match-all, missing values, unknown tokens) → #3380 (CLOSED, atomic-commit parsers present).
- monitor flow rotation limits unenforced → #3379 (CLOSED, traceWriter enforces).
- monitor nil event buffer panic → #3381 (CLOSED, eventBuf nil guards present).
- rollback malformed arg → rollback 0 → #3447 (CLOSED, strict Atoi at dispatchConfig present).
- completion cp[len(partial):] slice panic + dead monitor 'match' regex → #2288 (CLOSED, completionSuffix guard + traceLineMatches present).
- nil zone/policy completion panic → #3476/#3493 (CLOSED, nil guards present in valueProvider/tree DynamicFn).
- pipe filter case-insensitive vs case-sensitive → #18 (CLOSED). My regex-vs-substring finding names it and differs in mechanism (regex support, not case).
- policy-match selector strictness / display drift → #3696/#3628/#3357 etc. (out-of-scope, already mined).
- session iterator partial-success → #2469 (not in my files).

Negative results: local-CLI RBAC (checkPermission) IS enforced on every operational path including pipe (dispatchWithPipe recurses into dispatch→dispatchOperational→checkPermission) and pager (dispatchWithPager→dispatchOperational); config-mode is gated because only super-user (PermAll) holds PermConfig; `run` inside config re-checks permission. No permission-bypass on the local shell. display-pipe (| display set/xml/json/inheritance) is correctly handled inside handleShow/handleConfigShow (not via extractPipe), verified no drift.

### `go-usdp-core`  — 5 kept / 5 raw

Read in full: manager.go (1693 lines), process.go (1153), control.go, boot_probe.go, controllers.go, capabilities.go, builder.go, legacy_dataplane.go, loader_userspace_shim.go, dataplane.go; plus protocol.go head + ProcessStatus/UserspaceCapabilities/ConfigSnapshot structs; plus Rust userspace-dp/src/server/handlers/mod.rs (read timeout), protocol/control.rs (MAX_CONTROL_REQUEST_BYTES + #2744 rationale), protocol/snapshot.rs (ConfigSnapshot mirror), server/helpers.rs (write_state). Cross-referenced daemon_run.go apply sites, daemon_ha_userspace.go reconcile loops, daemon_health.go compile-health, userspace-xdp/src/lib.rs ctrl gate.

Lenses covered: (a) correctness — control-socket RPC deadline vs #2744 64MB body; readiness-loop dead early-exit branch; helper-crash respawn. (b) parity — no new gaps in these files (capability gating for screen/3-color/persistent-SNAT-HA is present and correct). (c) perf/latency — 3s deadline mismatch, 5s spin on start-crash. (d) refactor/dead-code — reEnableUserspaceCtrlLocked and userspaceSupportsSourceNAT are unreferenced. (e) test-gap — no test exercises a >16MB/near-64MB apply_snapshot round-trip against the 3s deadline (control_request_cap_2744_test.go only checks the byte pre-flight, not the transport deadline).

DEDUP — candidates discarded as duplicates:
- Control-socket single-thread starvation during HA bulk sync = prior finding #675 (Rust coordinator handle_control_conn sequential) + closed #452/#2549 — DIFFERENT mechanism from my finding 1 (mine is the Go-side fixed 3s deadline vs the raised 64MB body cap, a transport-timeout/body-size arithmetic mismatch, not concurrent-connection blocking).
- #2744 (control-socket 16→64MB cap + Go pre-flight) is CLOSED and HEAD reflects it (MaxControlRequestBytes=64MB, pre-flight present). My finding 1 is the NEW residual: #2744 raised the cap and added a size pre-flight but left requestDetailedLocked's 3s SetDeadline untouched, so the same large-feed input it was meant to admit can now time out mid-apply.
- #2523 (byte cap before read_line) CLOSED, reflected. Not my finding.
- PublishRouteOverlaySnapshot overlay-before-apply mutation = prior-findings.md line 555 (already recorded) — NOT re-reported.
- HA watchdog IPC throttle vs stale window = #349/#2549 CLOSED — not touched.
- Helper restart resets persistent-NAT leases = known-gaps (#1448 accepted) — not re-reported.
- No prior finding/issue covers: the dead cmd.ProcessState early-exit branch (Wait never called), reEnableUserspaceCtrlLocked being unreferenced, userspaceSupportsSourceNAT dead code, or the absence of manager-side crashed-helper respawn (#925 covers Rust WORKER-thread respawn inside the helper, not a full helper PROCESS crash seen from Go).

Negative results: dataplane.go retirement sentinels, loader_userspace_shim.go map-spec drift guards, controllers.go HA/link adapters, boot_probe.go ProbeForwardingArmed are all sound. configEqual omitting UserspaceConfig.SharedUMEM/RSSIndirection/host-tunables is correct (those are snapshot- or host-tunable-delivered, not helper cmd args, so they must NOT force a restart). Wire structs mirror Rust with matching json tags and additive/omitempty skew tolerance.

### `go-usdp-programs`  — 7 kept / 7 raw

READ (all 15 assigned files at HEAD ddf9f58, full contents): policies.go (buildPolicySnapshots*/walkPolicyRuleSlots/buildOneRuleSnapshot/nameRepresentability/buildAddressBookTableWithFeeds/canonicalize+sort helpers), nat.go (SNAT/DNAT/static/NAT64/NPTv6 builders, coalescePortRanges, sourceNATDestPortRanges, buildSourceNATAppTerms, dnatDestinationParts/dnatPoolHostIP, appPortsFromSpec), zones.go (BuildZoneHostInboundViews, AddresslessEnforcingZones, unionHostInboundTokens, buildZoneSnapshots/StableZoneID, buildInterfaceZoneMap), filters.go (term lowering, prefix-list resolution, DSCP/tcp-flags/flex-match fail-closed marks, policer builders), screens.go (buildScreenSnapshots, missing-profile refs, SYN-cookie key), maps_sync.go (ctrl/bindings/heartbeat programming, applyHelperStatusLocked gates, local/interface-NAT address map sync + prune, watchdog, ingress ifindex/alias builders), interfaces.go (snapshot builder, bind-target SSOT, synthetic ifindex), flow.go (wire coercions, ALG flags, app catalog, flow export), routes.go (FIB derivation, overlay replacement, ip-rule leaks), neighbors.go, tunnels.go, cos.go, applied_nat_view.go, wire_uint8list.go, runtime_delta.go. Also read supporting context: builder.go (snapshotContentHash), manager.go apply/overlay/scheduler publish paths, process.go syncSnapshotLocked dedup gate, pkg/config compiler_applications.go, compiler_nat.go parse sites, compiler_validate_strict.go NAT gates, types_security.go NATMatch, predefined.go.\n\nLENSES: (a) correctness/security — findings 1,3 (+2's dedup-gate correctness); (b) vSRX parity — finding 1 (AND semantics of NAT match axes; DNAT diverges from the repo's own SNAT contract); checked screen coverage, host-inbound, NAT64 no-v6-frag, NPTv6 — no new parity gaps beyond documented ones; (c) performance — findings 2,4,5,6; (d) refactor debt — findings 5,7 (kept scoped; big-directory split of pkg/dataplane/userspace host-inbound model already proposed in prior findings); (e) test gaps — folded into findings 1 (app+dest-port combos untested) and 2 (no snapshot byte-determinism test). Low-level invariants checked: endianness (binary.BigEndian.Uint32 on IP bytes in maps_sync is correct — keys built/read symmetrically Go-side; NativeEndian used for cpumap struct fields per convention), integer truncation (clampPort/coerceWire*/flex-match ceil all sound at HEAD), u32 policy-ID namespace math (walkPolicyRuleSlots overflow guard correct), atomic/lock use in applied_nat_view (m.mu held; defer-window coherency HOLD verified sound).\n\nDISCARDED AS DUPLICATES (candidate -> collision): IPv6 ip-rule leak emits NextTable \"<ri>.inet.0\" in the AF_INET6 loop -> prior-findings.md routes.go entry (verbatim same mechanism); netlink.RuleList failure silently skipped per family in routes.go -> prior finding; route snapshot dedupe key omitting Discard/Preference and unstable sort ECMP churn -> prior findings; appPortsFromSpec reversed range '200-100' -> [200] -> prior finding line 414 (my finding 6 reports only the distinct allocation-amplification mechanism and names 414); SNAT/DNAT application-SET partial drop -> prior findings 415/416; zones.go physical-vs-unit override precedence + cross-zone override leak -> OPEN #3720; token-order-sensitive host-inbound group signatures -> prior finding; addressless-zone admit window -> #3698 + known-gaps (accepted); nil-zone positional zone-ID shift -> fixed #3704 at HEAD (verified StableZoneID in buildZoneSnapshots); summary PolicyCount set-count bug -> fixed #3625 at HEAD; next-table/rib-group RuleAdd swallow -> OPEN #3731 (pkg/routing, out of module); screen rate-counter over-throttle -> OPEN #3607 (Rust side); walkPolicyRuleSlots no default-permit rows -> prior findings 77/83; RuntimePolicyIDs partial-map fallback -> prior finding 257.\n\nNEGATIVE RESULTS (checked, judged sound): wire_uint8list.go — numeric-array marshal never delegates to stdlib base64 path, unmarshal range-checks via []uint16 and accepts legacy base64/null (#1961 contract holds); applied_nat_view.go — defer-window capture skip + coherency AND is correct against the r11 reconcile-skew scenario; runtime_delta.go — Truncated >=max boundary false-positive exists but the field has no consumer outside the type definition (grep pkg/dataplane/runtime + pkg/cluster), so inert; tunnels.go — TTL-0 default, WG peer sorting, stable content-derived IDs with deterministic collision drop all correct; cos.go — every map sorted, #2704/#2409 skip+warn consistent across classifier/rewrite/scheduler-map; screens.go SYN-cookie key — sorts zone material before hashing (HA-deterministic); neighbors.go — publishable predicate mirrors Rust substring semantics, sorted output; multi-term applications ARE handled by NAT builders (compileApplications lowers terms to an implicit ApplicationSet, so the isSet branch expands them); three-color policer single-rate EBS maps correctly (compiler stores excess-burst-size into PBS; snapshot emits PeakOrExcessBurstBytes); DNAT strict gates confirmed to NOT reject the application+destination-port combination (finding 1 shapes b/c are commit-valid).

### `go-usdp-ha-events`  — 7 kept / 8 raw

READ (full): pkg/dataplane/userspace/manager_ha.go (1365 LOC: syncHAStateLocked, UpdateRGActive, UpdateHAWatchdog+IPC throttle, sumBindingCounters/syncBPFCountersLocked/safeDelta, SetSessionV4/V6, SetClusterSynced*, DeleteSession*, buildSessionSyncRequest*, sessionSyncEgressLocked), eventstream.go (1155 LOC: acceptLoop/readLoop/ackLoop, gap classification, pendingCallbackFrames queue/flush, decoders), fairness.go, fairness_throughput.go, inject.go, mirrors.go, natcounters.go, policycounters.go, filtercounters.go. READ (supporting, to verify cross-layer contracts): userspace-dp/src/event_stream/{mod.rs,producer.rs} (seq allocation, lossless/lossy producers, replay_buffered, queue budget), afxdp/session_delta.rs (flush_session_deltas lossless push + design-intent comment), afxdp/coordinator/reconcile/{mod.rs,reset.rs} (reset_binding_counters), server/handlers/sync_session.rs + afxdp/ha.rs (unconditional gen-0 delete), process.go (statusLoop, requestSessionSync per-request dial), daemon_ha_userspace.go (handleEventStreamFullResync), pkg/config/compiler_services.go (compilePortMirroring — no validation), pkg/api/metrics_counters.go (per-rule ReadPolicyCounters loop), eventstream_test.go test inventory. LENSES: (a) correctness — seq-space gap classification, decode-error handling, mirror-pair atomicity, counter reset semantics; (b) parity — port-mirroring commit validation vs Junos; (c) performance — O(P^2) policy-counter reads, per-request session-socket dials, resync-storm feedback; (d) refactor — counter-index rebuild per call; (e) tests — TestEventStreamSequenceGapDetection/SessionGapTriggersResync/TelemetryGapDoesNotTriggerResync exist but no cross-type (telemetry-hole-before-session-frame) or out-of-order-arrival coverage. DISCARDED AS DUPLICATES/RESOLVED: DrainRequest dormant (documented #2930); helper ACK-watermark validation (#2959 fixed helper-side — also defends the pendingFlush-vs-reconnect watermark pollution I traced and found benign); reverse sessions deliberately not mirrored on cluster-sync (#518/#316); zoneNameByID duplicate-zone-ID misattribution (prior-findings.md:374); ack-before-callback (#268 fixed via lastAppliedSeq); stale watermark across reconnect (#280 fixed by reset in acceptLoop); inject packet-length DoS (#2443 fixed, bound present at inject.go:100); ReadPolicyCounters wrong-slot after app-set expansion (#3143/#3145 fixed — resolver now slice-index with #3474 nil-slot alignment); UpdateRGActive/statusLoop demotion-delta race (#356/#283/#457 fixed via lock ordering + 2s/5s throttles, verified sound since requestLocked holds m.mu); watchdog IPC flood (fixed by 3s backstop commit b25d58131, verified). NEGATIVE RESULTS: fairness.go weighted-CoV math verified (West's algorithm, per-flow-share weighting correct; min-sentinel safe because zero rows are skipped); fairness_throughput prune/window accounting verified consistent (only minor unbounded w.queues map growth for ever-seen queue keys — discarded as bounded-by-config); safeDelta binding-REMOVAL inflation hypothesis investigated and DISCARDED: helper reconcile zeroes ALL binding counters (reset.rs), so no partial-decrease path exists — the residual bounded loss is reported as the low-severity finding 8; concurrent writeFrame interleaving discarded (net.Conn concurrent-safe, sub-SO_SNDBUF frames atomic in practice); pendingCallbackFrames flush/clear/dequeue race matrix traced — safe under pendingFlushMu ordering.

### `go-daemon-lifecycle`  — 6 kept / 6 raw

Read all 14 assigned files in full: daemon.go, daemon_run.go (2172 LOC), bootstrap.go, coalescence.go, daemon_apply.go (1629 LOC), daemon_system.go (1149 LOC), host_tunables.go, host_tunables_daemon.go, exec_timeout.go, kernel_selfrecover.go, runtime_probes.go, login_password.go, daemon_gc.go, daemon_health.go. Traced the commit/apply/sync/rollback control flow (commitAndApply / commitConfirmedAndApply / syncAndApply / executeConfirmedRollback), the bootstrap 5-case predicate + fail-closed FRR clear, host-tunable capture/restore state machine, and the applyConfigLocked reconcile ordering (C1/C2/C3 abort boundaries, tail errors.Join). Cross-checked configstore (SyncApply has no confirm timer; store_commit.go confirmTimer is store-local) and daemon_ha_sync.go (handleConfigSync -> syncAndApply -> SyncApply promotes as permanent active).

DEDUP performed against issues-all.txt, prior-findings.md, known-gaps.md:
- Config-apply lock over-scoping is prior-finding [daemon_apply.go] "ApplyConfig holds applyLock across whole compile" (#846-adjacent). My fabric-IPVLAN 5s-sleep-under-applySem (F5) is a DISTINCT concrete instance (a synchronous retry sleep inside the held lock), so reported narrowly, not as the general theme.
- networkd/host-inbound/lo0 fail-closed reporting are CLOSED #2987/#3333/#3392 — HEAD reflects those (errors.Join tail). My F3 (peer config-sync SKIPPED when that joined error is non-nil) is a different mechanism (HA propagation, not local reporting) and not covered by those issues.
- #1944 (login encrypted-password) CLOSED and implemented (login_password.go); docs/system-login.md documents password-lock-on-removal and frames keys/sudo as "additive". My F2 (super-user sudoers NOT revoked on class DOWNGRADE) is NOT covered: the doc rationale only addresses password-vs-key asymmetry on encrypted-password removal, never the class-change privilege-retention case, and CLI RBAC class IS reconciled (SetUserClass) while OS sudo is not.
- prior-finding metrics.go "Prometheus scrape netlink storm" (#669) — I saw the same uncached netlink.LinkList() pattern in Run()'s SNMP SetIfDataFn (daemon_run.go:1013); DISCARDED as effectively a duplicate mechanism at a lower-frequency (SNMP poll) call site.
- computeBootClass / fail-closed FRR clear / lifeline protected-set reviewed against #1922/#1960/#1993 (all CLOSED, HEAD matches) — no residual found; logic is sound.
- host_tunables capture/restore, coalescence parsing, kernel_selfrecover election-hold reconcile: reviewed, no defect (restore-on-shutdown covers all three pipelines; hold release predicate is marker==running which is correct).

Negative results: exec_timeout.go (WaitDelay + 15s ctx) correct; login_password.go passwordAction fail-open/closed table is sound; runtime_probes.go is pure interface shapes.

### `go-daemon-net`  — 8 kept / 8 raw

READ (full): pkg/daemon/linksetup.go, device_map.go, rss_indirection.go, daemon_neighbor.go, daemon_neighbor_listener.go, daemon_proxyarp.go, daemon_nft.go (all 1334 lines), daemon_reth.go, daemon_dns.go, daemon_ra.go, pkg/devicemap/devicemap.go, pkg/nftables/{host_inbound_counters,rst_suppress,lo0_counters}.go. READ (targeted callers/cross-checks): daemon_apply.go RETH-MAC block (860-1010) + RSS reapply site (1400-1470) + proxy-arp call site (1024-1027), daemon_ha.go reconcileRGStateLoop, daemon_run.go loop start sites, cluster/reth.go HandleStateChange, userspace-xdp/src/lib.rs (binding-missing/redirect-err fallback, select_userspace_queue), userspace-dp/src/server/helpers.rs replan_queues (queue_count = min(rx_queues), worker_id = queue_id % workers — proved workers=1 still binds every queue, which downgraded a suspected blackhole to a perf-skew finding), pkg/networkd naming (filePrefix "10-xpf-" — confirms teardownUnmappedManaged removes the right .network), pkg/dhcp reconcile.go/dhcp.go (RAIface name-form consistency), rss_indirection_test.go fixtures (hash-key lines never start with two decimal digits — confirms the misparse is untested).

LENSES: (a) correctness — findings 1,2,3,5; (b) vSRX parity — nothing new: host-inbound/lo0 parity surface is exhaustively mined (see discards); (c) performance — findings 2,4; (d) refactor — finding 8 (real module proposal); (e) test gaps — folded into findings 2 (fixture gap) and 6 (test pins unreachable production semantics).

DISCARDED AS DUPLICATES (issue#/prior-finding named): daemon_nft.go daddr-only zone collisions & VRF-blindness (open #3718 + prior findings 362/368/370/387); host-inbound token-order duplicate rule blocks (open #3721); addressless-zone fail-open window (#3698 closed, accepted per known-gaps); ESP/AH global accept before per-zone policy (prior finding 225/237, open decision #3616); nftLo0LogPrefix control bytes/mid-rune truncation (prior 404, #3724 M09 deliberately open); lo0 nft log rate-limit + counter scrape (prior 401/402, #3724 M06/M07 deliberately open); host-inbound Go/Rust SSOT drift (prior 378/379, #3486 closed); nft feed-set chunking (prior 631); REST counter zero-collapse (prior 185/#3681); physical-vs-unit override precedence (#3720 open); `system-services all` packet-wide admit (#3226 open); proxy-arp per-address narrowing + v6 pneigh (#2197 open — my finding 3 is a different mechanism: missing applySem serialization of the loop that issue itself introduced); renamed-but-DOWN in linksetup.renameInterface (#2083 closed and fixed at HEAD — finding 1 is the sibling function daemon_reth.renameRethMember which never calls LinkSetUp at all); RSS stale-table on workers→=queues (#805 closed and fixed — finding 4 is the excluded workers→1/→0 arms); planned-vs-bound RSS divergence (#3091 closed, different mechanism); RETH .link MACAddress drift (handled by ensureRethLinkOriginalName; docs/bugs.md FIXING entry per known-gaps); networkd write-failure swallow (#2987 closed, verified errors now joined into commit result at daemon_apply.go:1470).

NEGATIVE RESULTS (checked, sound): device_map.go phase-1/2/3 collision-safe multi-pass — traced an A↔B name-swap and stale-udev squatter; correct, temp-name EEXIST avoided via inUse set; originalByCurrent correctly carried across temp renames. devicemap.Resolve order-independent refusals (pre-loop PCI-ambiguity + swapped-card) are deliberate reviewed design (Codex HIGH-1/r2 HIGH-B markers in code); cross-key double-claim post-pass refuses correctly. deviceMapCommitPreflight invariants 1+2 handled deliberate-swap and steal cases. teardownUnmappedManaged honors the #1922 protected set and desiredNames includes UNBOUND entries (conservative). daemon_dns reconcile: boot empty-repair gate, bind-mount EXDEV fallback, masked-unit idempotence all correct; dedup/order determinism in mergeDNSInput correct. daemon_ra: PD prefixes append onto clones (no shared-config mutation), #2996 unit scan fixed at HEAD, RAIface name form consistent between DHCP options and Protocols.RouterAdvertisement. neighbor listener: debouncer timer pattern race-free, runOneSubscription done-channel lifetime correct, shouldTriggerRegen composite-state logic correct. rst_suppress.go netlink expressions verified (nfproto guard, saddr offsets 12/8, TCP flag byte 13 mask 0x04, atomic delete+create batch). host_inbound_counters name encoding round-trips (length-prefix reverse-parse); sanitizeNftIdent collision is documented in-code as accepted. nftDeleteTable add+delete idempotency idiom sound.

### `go-daemon-ha`  — 8 kept / 8 raw

READ (full): pkg/daemon/daemon_ha.go (1351 ln: watchClusterEvents, watchVRRPEvents, reconcileRGState, blackhole inject/remove/reconcile, applyRethServicesForRG/clearRethServicesForRG, filterDHCPConfigForMasterRGs, warmNeighborCache, syncIPsecSAPeriodic), daemon_ha_fabric.go (863 ln: ensureFabricIPVLAN, reconcileIPVLANAddrs, populateFabricFwd/1, refreshFabricFwd/1, probe/ICMP senders, monitorFabricState, triggerFabricRefresh), daemon_ha_sync.go (890 ln: sync-ready timer, peer connect/disconnect/bulk callbacks, hb-suppression, prime-retry loop, startClusterComms/stopClusterComms, fence wiring), daemon_ha_userspace.go (1094 ln: delta→session conversion, wire-alias keys, event-stream wiring, FullResync, demotion prep/barrier, transfer readiness), daemon_ha_vip.go (636 ln: VIP readiness, direct VIP add/remove, stable LL, directSendGARPs + #2898 gating), rg_state.go (365 ln: epoch/applied tracking, strict mode, posture check), daemon_cluster_bind.go (133 ln: bind-address selection). Cross-checked: pkg/cluster/heartbeat_manager.go (StartHeartbeat replace-without-stop), pkg/vrrp/instance.go gatewayProbeTarget (#2377 fix), userspace-dp/src/afxdp/ha.rs + types/runtime.rs (watchdog lease semantics), pkg/config/schema_chassis.go + compiler_system.go (RG-id validation absent; PrivateRGElection default TRUE), daemon_apply.go:1395-1413 (transport-only comms restart), netlink v1.3.1 linkSubscribeAt (close(ch) on Receive error). LENSES: (a) correctness/security — findings 1-6; (b) vSRX parity — direct-mode GARP probe (finding 1) is a parity-relevant failover-quality gap, no new whole-feature gaps in this module; (c) performance — applyDirectVIPOwnership holds directVIPMu across RA apply + Kea memfile pre-seed + netlink AddrAdd, contending with directBurstStillValid between 50ms GARP frames (candidate, dropped for quota — bounded, no deadlock: lock order directVIPMu→directAnnounceMu is never nested in reverse); waitLocalFailoverCommitReady 10ms poll acceptable; (d) modularity — daemon_ha* sibling-file sprawl already tracked/closed as #370, DISCARDED as duplicate; (e) test gaps — daemon_ha_fabric_test.go is 1.3KB with zero coverage of dual-fabric refresh delivery or monitor death (folded into findings 3/5), warmNeighborCache filter untested (finding 8). DISCARDED AS DUPLICATES: fabric ARP probing parent-vs-overlay (#129 CLOSED, fixed at HEAD); dead-link fabric programming (#122 fixed — oper-state check present); stale fabric_fwd clear (#121 fixed — clearFabricFwd0/1 present); blackhole routes in userspace mode (#354/#410 fixed — userspaceDataplaneActive guard); wall-clock hb suppression (#1792 fixed — MonotonicNanos + cap); GARP follow-up gating after abdication (#2867/#2894/#2898 fixed — directBurstStillValid present); IPVLAN address reconcile (#127 fixed); rg_active partial-VRRP activation (#132 fixed — allMasterLocked); stale-transition side effects (#66 fixed — epoch/ApplyIfCurrent); prior finding [pkg/daemon/ha/watchdog.go] heartbeat false-positive under CPU congestion — different file/mechanism than my finding 2. NEGATIVE RESULTS: (1) suspected stale-RG-list HA watchdog goroutine (captures cc.RedundancyGroups at comms start) is neutralized — Rust update_ha_state refreshes the lease with watchdog.max(now)+10s on every active update, so per-RG watchdog omission doesn't expire forwarding; documented, not reported. (2) d.sessionSync is assigned in the comms goroutine and read unsynchronized by heartbeat-suppression/delta paths — technically racy but pointer-swap-once-per-comms-start with pervasive nil-guards; adjacent to #76-class sync races, judged below quota threshold. (3) reconcileRGState fabric-readiness gate checks only fabricPopulated (key 0), ignoring fabric1Populated — conservative-only effect (blocks takeover when fab0 down but fab1 up), adjacent to closed #186, judged deliberate primary-path semantics. (4) retainFabricFwdOnNeighborMiss keeping a stale peer MAC is deliberate fail-open (logged, #121-aware). (5) refreshFabricFwd's parent-NDP fallback picks the FIRST non-local link-local neighbor — wrong-MAC risk on a shared (>2-node) fabric L2, but the fabric is a point-to-point contract per docs; noted, not reported (low value). (6) selectClusterBindAddr first-candidate pick with multiple same-family addresses — deterministic-enough, no defect demonstrated. (7) rg_state.go epoch/log-once/posture logic checked for wrap and lock issues — sound (uint64 epoch, all access under mu).

### `go-daemon-svc`  — 8 kept / 8 raw

READ (all 13 assigned files, full): daemon_dhcp.go (buildDHCPClientSpecs, onDHCPAddressChange, reapplyIPsecForLeaseChange, relayMasterGateOpen, resolveConfigSubnetLinuxName), daemon_dhcp_lease_sync.go (push loop, fingerprint, pre-seed/seed), daemon_ddns.go (reconcile loop, per-RG gate, subnet-RG map), daemon_ddns_surface_a.go (scopes, observer, selectInterfaceAddr, RG0 writer), daemon_flowexport.go (reconcile, bundles, flowExportCallback/ipfixExportCallback), daemon_flow.go (collectDHCPRoutes, applyMgmtVRFRoutes, stopFlowExporter, parseHost/parseSrcPort/parseProtocol, archiveConfig, apply/updateFlowTrace, monitorLinkState), daemon_rpm.go, daemon_ipmon.go, daemon_scheduler.go, daemon_natpoolalarm.go, daemon_forwarding_status.go, daemon_feeds.go, daemon_dns.go. Cross-checked supporting code: pkg/logging/ringbuf.go (AddCallback/ClearCallbacks/CallbackCount, EventRecord.ProtocolNum, protoName #3040), pkg/logging/trace.go (TraceWriter.Close/HandleEvent), pkg/snmp/agent.go+traps.go (UpdateConfig, enqueueTrap #2991), pkg/configstore/store*.go (writeActive → DB only; nothing writes opts.ConfigFile), pkg/config/types_system.go (ArchivalConfig.TransferInterval), pkg/config/types_security.go (SchedulerConfig fields), pkg/daemon/daemon_run.go (SNMP boot gating 1010/1079), daemon_apply.go (updateFlowTrace call 1326, snmpAgent UpdateConfig 432, mgmtVRFInterfaces 542), daemon_neighbor_listener.go (resubscribe precedent), vendored netlink v1.3.1 linkSubscribeAt (close(ch) on Receive error). LENSES: (a) correctness — findings 1,2,3,5,7; (b) vSRX parity — findings 4,6; (c) performance — finding 2 (per-event O(commits) formatting overhead); (d) refactor debt — finding 8 (daemon_flow.go grab-bag + dead helper); (e) test gaps — folded into findings 2/8 (no direct tests for archiveConfig, monitorLinkState, applyMgmtVRFRoutes, updateFlowTrace). DISCARDED AS DUPLICATES: ipmon FRR-vs-snapshot divergence on publish failure + pendingFIBBump retry-only-on-next-actuation + actuateRouteOverlay shutdown block (prior-findings.md daemon_ipmon.go entries); ipmonPublishAllowed/rpm lowestDataRG wrong-RG gating in split-primaryship (prior findings daemon_ipmon/daemon_rpm entries); flowexport stop-before-start reconcile window and transient-create teardown (open #3742 + prior findings daemon_flowexport entries); SNMP synchronous trap delivery in link monitor (fixed #2991 — verified enqueueTrap at HEAD); all ddns/surface-a candidates (e.g. staticUnitAddr per-pass WARN flood, checkip issues) skipped as danger-zone-adjacent to fresh #3731-#3739; Kea lease-sync push-after-fingerprint-update loss (bounded by 30s force heartbeat, documented Q1/Q7 design). NEGATIVE RESULTS: daemon_natpoolalarm.go clean (atomic pointer lifecycle #2114 sound, sampler does no control-socket I/O per #2079); daemon_forwarding_status.go clean (thin probe adapters, nil-safe); daemon_scheduler.go hash covers every SchedulerConfig field (verified struct) and epoch guard is sound under applySem; daemon_dns.go #1715 single-owner model sound incl. bind-mount EXDEV fallback and masked-unit idempotence; daemon_feeds.go trivially correct; assembleFRRConfig ConsistentHash is set as documented side effect of frr.ApplyFull (config_render.go:350) — not a missed assignment.

### `go-cluster-core`  — 5 kept / 5 raw

Read all 15 assigned files at HEAD (election.go, failover.go, garp.go, group_state.go, heartbeat.go, heartbeat_manager.go, hooks.go, kernel_selfrecover.go, manager.go, monitor.go, peer_state.go, readiness.go, reth.go, runtime.go, status.go) plus cross-file context: daemon_ha_sync.go (heartbeat/remote-failover wiring, startClusterComms/stopClusterComms), daemon_ha.go (DualActiveWin handling), sync_failover.go/sync_conn.go (fence + remote-failover receive path), compiler_system.go + schema_chassis.go (RG-instance-ID parsing, confirmed unvalidated), monitor_test.go/cluster_test.go (probe + monitor test coverage).

Lenses covered: (a) correctness — election/weight math, GARP suppression gates, heartbeat threshold/staleness, monitor weight application, manual-failover vs automatic races; (b) parity — VRRP-priority mapping, RG-threshold model; (c) perf/latency — heartbeat send path, GARP burst goroutines; (d) modularity — timer lifecycle; (e) test gaps.

FINDINGS KEPT: (1) UpdateConfig never reconciles per-RG monitor failure state (rg.MonitorFails + m.monitorWeights) when an interface-monitor is removed/re-weighted on a surviving RG — stranded weight penalty; verified only SetMonitorWeight mutates those, and UpdateConfig's existing-group branch only touches LocalPriority/Preempt (group_state.go:36-40). (2) monitor.probeICMP validates only reply Type, never echo ID/Seq or source address (monitor.go:406, ReadFrom source discarded at :397). (3) heartbeat GroupID/RGID are uint8 on the wire while RG instance IDs are unvalidated at commit → truncation for IDs>=256. (4) StartHeartbeat is not self-stopping/idempotent (unlike Monitor.Start). (5) readiness.holdTimer is leaked when its RG is deleted by UpdateConfig.

CANDIDATES DISCARDED AS DUPLICATES / NON-ISSUES:
- handlePeerTimeout re-checking staleness vs peerAlive after guard window: implemented correctly at heartbeat_manager.go:342 — this is exactly the fix for #2080 (CLOSED), HEAD reflects it. Discarded.
- GARP/NA burst follow-up ignoring send errors: fixed (#2623), burstSendErrors counter present (garp.go:22-28). Discarded.
- GARP/NA burst re-poisoning after abdication: fixed (#2867/#2898), BurstStillValid gate present (garp.go:140,238). Discarded.
- VRRP ARP-probe using primary IP not VIP: fixed (#2152), SendARPProbe takes explicit senderIP (garp.go:274). Discarded.
- Heartbeat wall-clock peer-loss: fixed (#1792), MonotonicNanos + heartbeatStale used (heartbeat.go:494). Discarded.
- Stale peer RG entries across heartbeats: fixed (#92), newPeerGroups rebuilt from scratch (heartbeat_manager.go:255). Discarded.
- Interface-monitor carrier-down reported UP: fixed (#2070), LinkAttrsUp reads OperState (monitor.go:507). Discarded.
- ForceSecondary weight=0 being undone by a later recalcWeight: traced — ManualFailover flag keeps the RG SECONDARY regardless of the restored weight (electRG:65-70), so no failover regression. Not reported.
- kernelUpgradeHold / dual-active / manual-vs-auto races: traced electRG + failover.go end-to-end against #611/#612/#464 (all CLOSED) — HEAD guards (2s manual-failover guard, transfer-commit grace, IsLocalPrimary guard in daemon OnRemoteFailover) match the closed fixes. Not reported.

### `go-cluster-sync`  — 8 kept / 8 raw

Read in full at HEAD ddd9f58~ (ddf9f5870): pkg/cluster/sync.go (889 ln: SyncStats, TransferReadiness, gen-state init, reconcileStaleSessions, IPsec/DHCP-lease peers), sync_bulk.go (429 ln: doBulkSync/sendBulkMarkers/BulkSync, barrier/bulk acks, WaitForPeerBarrier), sync_conn.go (1589 ln: gen guard #2170/#2198/#2221, conn lifecycle, sweep, delete journal, handleMessage dispatch, handleDisconnect), sync_failover.go (607 ln: failover req/ack/commit waiters), sync_protocol.go (757 ln: wire codecs incl. #3301 trailing fields, #2239 lease codec), sync_state.go (75 ln). Cross-checked daemon wiring (pkg/daemon/daemon_ha_sync.go handleConfigSync/OnConfigReceived/BulkSyncOverride/OnRemoteFailover, daemon_ha_userspace.go transfer readiness) and pkg/cluster/failover.go ManualFailover gating. Lenses: (a) correctness/races — 5 findings; (b) parity — IPsec SA sync carries only connection names (design: standby re-establishes; documented, not reported); (c) perf — bulk write starvation already mitigated (Gosched every 64); (d) refactor — 1 finding (gen-guard extraction); (e) test gaps — folded into findings (sync_test.go covers journal flush-on-reconnect, PendingBulkAck happy paths, epoch mismatch, but nothing for ack-before-store, connected-queue-full journal starvation, partial-fabric bulk latch, cross-conn same-key concurrency). DISCARDED as duplicates/fixed-at-HEAD: flushDeleteJournal drop-on-full (#2121 — rejournalTail present); bulk re-prime on reconnect/fabric change (#466 — now cold-start-only, but that fix CREATED finding 3's no-retry gap, reported as new residual); per-tick slog.Info in sweep (#1795 — now Debug); wall-clock liveness (#1792 — MonotonicNanos used); same-gen install/delete reorder (#2221 — fresh delete gen present); stale journaled delete kills replacement (#2170 — guard present); gen map clear-on-overflow (#2198 F1 — putGenBounded skip-record); Stats copylocks (#120 — snapshot struct); unsynchronized conn writers/short writes (#76/#90 — writeMu + writeFull); stale receive loop tearing down newer conn (#69/#89 — pointer-identity check in handleDisconnect); config authority on reconnect (#78 — RG0-primary reject in daemon); identical-config reapply teardown (#606 — skip-if-matches); malicious DHCP lease count prealloc (already clamped in decodeDHCPLeasePayload); responder-side concurrent remote-failover dedup — discarded after verifying Manager.ManualFailover failoverInProgress[rgID] guard (failover.go:47-52); peerHeartbeatAckEver never reset on peer downgrade — discarded (downgraded peer still emits type-7 heartbeats on its own 10s read-timeout path, resetting missedHeartbeats); sendBulkMarkers racing ahead of event-stream sessions — documented deliberate ('peer sees an empty bulk'). Negative results: v4/v6 session codec offsets sum correctly to the 160-byte layout with symmetric length-gated trailing fields (#2170 gen, #3301 AppTimeout/PolicyCounterIdx) and consistent LittleEndian on both ends (wire is homogeneous LE, no NativeEndian boundary issue here); rejournalTail overflow accounting verified correct; barrier ack CAS is monotonic; failover waiter reqID matching sound against late/stale acks.

### `go-vrrp-ra`  — 6 kept / 6 raw

Read all non-test source in pkg/vrrp (vrrp.go, packet.go, instance.go [2088 lines, full], manager.go, track.go, addrwatch.go) and pkg/ra (ra.go, sender.go, filter.go). Also read the vendored mdlayher/ndp@v1.1.0 option.go/message.go to confirm marshal error semantics, and pkg/config/schema_routing.go + schema_validators.go to confirm what the commit-time gate does/does not bound.

Lenses covered: (a) correctness/security — PREF64 marshal-abort RA blackhole, Status() data race, default-lifetime uint16 wrap; (b) vSRX parity — accept-data unimplemented, RFC 5798 Master_Adver_Interval not adopted; (c) perf/latency — randomAdvInterval 0-second busy loop, ReconcileVIPs synchronous GARP under RLock (judged too weak, see below); (d) modularity — noted but not reported (files already well factored; issue #2006 tracks the manager/instance/packet/track split which HAS since happened); (e) test gaps — folded into fix directions.

DEDUP performed against issues-all.txt, prior-findings.md, known-gaps.md:
- PREF64 prefix LENGTH: covered by CLOSED #2497 (ValidatePREF64CIDR added, HEAD reflects it). My finding is the LIFETIME (scaled-lifetime >8191) which #2497 explicitly typed only as ValidateIntegerMin(0) — NO upper bound. Distinct mechanism, not a dup.
- PreferredLifetime>ValidLifetime: CLOSED #2271, fixed by the clamp at sender.go:732 (verified present). Not my finding.
- localIP/localIPv6 race #2258, lastDropWarn race #2225: both fixed with atomics (verified). My Status() race is a DIFFERENT field (cfg.Priority, a plain int mutated by ResignRG/UpdateRGPriority under vi.mu) read UNLOCKED by Status() — not covered by #2258/#2225.
- accept-data: grep of issues-all.txt/prior-findings.md/known-gaps.md for accept-data/accept-mode returned ZERO hits. Novel.
- Master_Adver_Interval adoption: grep for master.advert.interval/MaxAdvertInt/adopt returned ZERO hits. Novel.
- IPv6 checksum-source #2644, VLAN SO_BINDTODEVICE #2786, mcast-join #2870, track-rename #2944, preempt-hold #2850/#2900/#2082, dead-sender rebuild #2865, goodbye ordering #2033/#2834: all verified present/fixed at HEAD — not re-reported.

DISCARDED candidates: (1) ReconcileVIPs calls vi.sendGARP(true) synchronously while holding m.mu.RLock (manager.go:597) vs becomeMaster's `go vi.sendGARP` — the burst helper sends only the first frame synchronously per VIP, sub-millisecond, so RLock hold is negligible; discarded as too weak. (2) QinQ 0x88a8 handled in Go receiverAfPacket but rejected by the cBPF at instruction 3 — dead code, but xpf is 802.1Q-only, no functional impact; discarded. (3) parseAfPacketIPv4 does not verify the 224.0.0.18 destination — VRID+TTL255+self-filter gate adequately; discarded. (4) Modularity refactor — files are already split per #2006; nothing to propose.

Negative results: the checksum math (onesComplementChecksum, vrrpIPv6Checksum pseudo-header) is correct; centisecond wire encoding in sendAdvert (AdvertiseInterval/10) is correct for the 30ms RETH default (=3cs); walkIPv6ExtHeaders is bounds-safe and iteration-capped; the preempt-hold/sync-hold/GARP-epoch state machine is heavily and correctly guarded.

### `go-conntrack-appid`  — 8 kept / 8 raw

READ (all non-test .go at HEAD ddf9f58): pkg/conntrack/gc.go (full: NewGC/sweep/nextSweepDelayAt/monotonicSeconds + GCStats); pkg/scheduler/scheduler.go (full: New/NewPrimed/Run/evaluate/wallClockDiscontinuousLocked/isWithinWindow/parseTimeOfDay) + README; pkg/appid/runtime.go, catalog.go, textrender.go; pkg/policymatch/policymatch.go (full, 1413 lines: ParseSelectorArgs/Match tiers/matchJunosHost/matchAddr/resolveToken/expandBookName/matchApp/matchSingleApp/portMatches), zone_detail_summary.go; pkg/fairness/expectation.go (full). Cross-checked callers/ground truth: pkg/daemon/daemon_run.go (GC wiring 740-830), daemon_apply.go (802-818), daemon_gc.go, daemon_scheduler.go, daemon_system.go (time-zone apply); pkg/config schema.go root + schema_cos.go/schema_security.go/schema_system.go, ast_edit.go SetPath, schema_walk.go walker, compiler.go dispatch + compileApplications, compiler_system.go compileSchedulers, compiler_validate_strict.go (scheduler refs, application protocol/port gates), compiler_applications.go (resolveAppPort/validatePortSpec); pkg/dataplane/session_store.go DeleteBatchKnownV4; pkg/dataplane/userspace/flow.go + fairness.go; pkg/api/health.go + metrics_sessions.go + metrics_descriptors.go; pkg/grpcapi/server_show_status.go; userspace-dp/src/policy.rs parse_port_spec. EMPIRICAL: built a scratchpad module and ran the repo's parser+compiler — confirmed (a) `set schedulers scheduler s4 start-time 09:00:00` compiles to zero schedulers (one-leaf collapse), (b) hierarchical `daily { start-time; stop-time; }` compiles to StartTime==\"\"/Daily=true (always-active), (c) dotted Junos start-date stored verbatim (runtime parse fails). LENSES: correctness/security (scheduler fail-open/fail-closed, appid mislabel), parity (Junos scheduler grammar/day-of-week, zone-detail wildcard tier), perf (fairness math + GC fast paths reviewed — GC hot path is dead in production so no live perf issue; fairness is low-frequency status math, no findings), refactor (dead GC machinery), test gaps (scheduler compile path, UTC-only date tests). DISCARDED AS DUPLICATES: policymatch matchApp app-set expansion error skip -> fresh #3727; policymatch portMatches Atoi '+80' acceptance + reversed-range never-match -> same class as fresh #3725/#3726 and prior findings 408-413; catalog bad source-port -> unconstrained + AppNames stale id for malformed app + reversed catalog ranges -> #3725 / prior findings 410-412; appid port-parsing duplication across packages -> prior finding 418; GC aging early-ageout/watermark accepted-but-unenforced on userspace -> documented #3440 + feature-gaps.md row (my GC findings are the DIFFERENT zero-stats surface and the untracked dead-machinery refactor); GC aging-config data races -> #3604 fixed at HEAD (verified mu-snapshot in sweep); ProtocolName not full inverse of ProtocolNumber -> prior finding 115; AppID overlap lowest-id-wins vs specificity -> prior findings 13/24/422; zone-detail scheduler-inactive/log/count modifiers -> #3684 fixed at HEAD. NEGATIVE RESULTS: pkg/fairness/expectation.go clean — parser normalization (<=/>=/=), percent handling, NaN/Inf/negative rejection, balanced/min-max logic, uint32/uint64 accumulation all checked, no wrap or fail-open paths (package has no production callers beyond low-frequency status math in dataplane/userspace/fairness.go); named port aliases are NOT a catalog gap because resolveAppPort resolves them to numerics at compile before appid.parsePortRange runs; policymatch normalizePortAlias table matches policy.rs parse_port_spec byte-for-byte (no simulator/runtime alias drift); Match tier precedence (exact/single-wildcard-merge/both-any/global/default + junos-host gate) re-verified against the documented policy.rs contract with no new drift; ParseSelectorArgs duplicate/missing-value handling verified per #3696/#3709; GC DeleteBatchKnown error-branch prefix-callback asymmetry noted but unreachable in production (SkipSweep) and low value beyond the reported refactor finding.

### `go-frr-routing`  — 8 kept / 8 raw

READ (all non-test .go at HEAD ddf9f58): pkg/frr/manager.go (ApplyFull/buildManagedSection/writeManagedSection/reload+degraded-retry), config_render.go (generateStaticRouteInTable, renderDHCPDefaults/BackupRouter/PreferredRoutes, resolveECMP), policy_render.go (all 1744 lines: resolveRedistribute, generateProtocols OSPF/OSPFv3/BGP/RIP/ISIS, bfdSection, renderRouteFilterEntry, generatePolicyOptions), vtysh.go (executor, Get* shells), status_parse.go (GetRIPRoutes/GetISISAdjacency/GetOSPFNeighbors/GetBGPSummary/GetBGPRoutes/parseRouteJSON); pkg/routing/routing.go, routes.go (routeReader/rtProtoName), routeformat.go, rules.go (nextTable/ribGroup/pbr managers, BuildPBRRules/resolvePBRDirection), vrf.go, xfrm.go, bond.go+reth.go (skimmed), monitor.go, probe_pin.go, tunnel.go (full: Apply reconcile, anchor/legacy/WG branches, keepalive lifecycle), tunnel_keepalive.go (icmpProber); pkg/ipmon/ipmon.go + display.go. Cross-checked callers: pkg/daemon/daemon_apply.go (steps 3b-3d, 18-19), daemon_run.go collectAppliedTunnels, pkg/config/compiler_routing.go + compiler_protocols.go, pkg/dataplane/userspace/routes.go leak loop, pkg/cluster/monitor.go (live SetMonitorWeight feeder exists — routing/monitor.go poll-at-apply is only the seed, no gap). Lenses: correctness (findings 1,2,4,6,7), vsrx-parity (3,5, parts of 1,2), perf (nothing hot-path here; rule-walk cost already prior-found), refactor debt (nothing new beyond prior finding 443), test gaps (4: GetBGPSummary has zero tests). DISCARDED AS DUPLICATES: PBR L4/iif predicate widening (#3730 + prior findings 425-439); nextTable/ribGroup RuleAdd swallow (#3731, prior 428/429); clear() error propagation drift (#2273; PBR leg fixed by #3430 H3 at HEAD); writeManagedSection marker corruption (#2908/#1646 — fixed at HEAD, verified anchored end-search present); IPv6 link-local preferred-route missing FRR interface inference (prior finding 554); ipmon lifecycle/dirty-bit/resolver-under-mu/hold-down/display defects (prior findings 556-579 — package fully mined; concurrent Stop() double-close discarded as adjacent to prior 558); plain policy-options prefix-list lacks the #2105 malformed-prefix render belt (route-filter leg fixed) — discarded as same defect mechanism as closed #2105, noted here only; rtProtoName mislabels (#2127 fixed at HEAD); xfrm rebuild-per-commit (#2546 fixed, differential reconcile verified); xfrm if_id collision (#2909 guard present); VRF orphan reap (#847 implemented). NEGATIVE RESULTS: frr/manager.go degraded-retry state machine is sound (confGen invariant, episode identity-guard, Stop-before-Wait ordering all correct); vrf.go reconcile partial-failure contract correct incl. transient-lookup ownership retention; tunnel.go WG/anchor reconcile survived line-by-line read (ownedNames handoff, appliedAddrs link-local gating, keepalive drain-before-recreate all consistent); tunnel_keepalive.go prober errno classification correct. GetRouteDetailJSON swallowing both-family vtysh errors (returns nil,nil) and FormatRouteDetail's double-indented "Resolved" label noted but below quota cutoff.

### `go-networkd-mon`  — 6 kept / 6 raw

Read in full: pkg/networkd/networkd.go (674L), pkg/lldp/lldp.go (720L), pkg/monitoriface/monitor.go (952L). Traced callers: pkg/dataplane/compiler_iface.go (InterfaceConfig construction, unmanaged bring-down, MTU/VLAN device creation), pkg/config/compiler_protocols.go (LLDP compile), pkg/config/schema_routing.go (LLDP schema), pkg/daemon/daemon_apply.go (networkd.Apply + reconcileLLDP + effectiveLLDPConfig), pkg/daemon/daemon_run.go (lldpMgr construction + neighbor fns), pkg/cli/cli_show_services.go + pkg/grpcapi/server_show_dhcp_lldp_snmp.go (LLDP neighbor render), pkg/dhcp/dhcp.go (applyAddress netlink foreign-address install).

Lenses covered: (a) correctness/security — LLDP untrusted-input parsing + interface-name resolution + render sinks; (b) vSRX parity — LLDP interface naming, transmit-interval/hold-multiplier bounds; (c) perf — neighbor-map cardinality; (d) modularity — noted RenderSingleInterface's 100-line manual delta block but not novel; (e) test gaps — LLDP slash-name path untested (parser_routing_test.go:2232 uses trust0/untrust0; socket_test.go uses lo.Name), transmit-interval range untested.

Dedup performed against issues-all.txt + prior-findings.md + known-gaps.md + recent-commits.txt:
- LLDP self-frame #2992 (CLOSED, fixed at lldp.go:483 PACKET_OUTGOING) — DISCARDED, HEAD reflects fix.
- LLDP truncated mandatory TLV #2551 (CLOSED, gating at 673-699) — DISCARDED, HEAD reflects fix.
- LLDP overlength TLV #2036 (CLOSED, EncodeTLV fail-closed) — DISCARDED.
- LLDP socket lifecycle #2035 / day-2 reconcile #2372 / CLOEXEC #2608 — DISCARDED, all present at HEAD.
- networkd empty-set sweep #2988, write-fail propagation #2987, per-family DHCP #2986, newline-in-description #1798, rp_filter #2378/#440 — all CLOSED and HEAD reflects fixes — DISCARDED.
- port-mirroring LinuxIfName #35 (CLOSED) — SAME CLASS as my finding #1 but DIFFERENT module (port-mirroring vs LLDP); LLDP interface-name normalization is not tracked by any of the 6 LLDP issues — reported as novel.
- monitor summary fab/reth aliases #478/#477/#135/#136/#138 (CLOSED) — DISCARDED, distinct from my traffic findings (I found none novel in monitoriface).
- Screen unbounded trackers #2128/#2209 — different module; LLDP neighbor-map cardinality not covered — reported.
Negative results: monitoriface is largely display/formatting glue with careful deltaU64 wrap-guards and hasUserspaceTrafficSource gating; the kernel+userspace fold is intentional (documented). networkd generation edge cases (#2986/#2987/#2988/#1798) are all freshly fixed and solid. No novel monitoriface bug survived.

### `go-ipsec-wg`  — 8 kept / 8 raw

READ (all non-test .go at HEAD ddd f9f58): pkg/ipsec/manager.go (Apply/Clear/reload/runSwanctl), pkg/ipsec/ike.go (resolveIKESettings/resolveESPSettings/deriveDPD/normalizeEncAlg/gcmPRF/normalizeAuthAlg/buildIKEProposal*/buildESPProposal/dhGroupBits/formatDHGroup/TerminateAllSAs/ActiveConnectionNames/InitiateConnection/GetSAStatus/parseSAOutput), pkg/ipsec/policy.go (renderConfig/resolveRemoteAddr/effectiveTrafficSelectors/sanitizeSwanctlValue/escapeSwanctlQuoted/formatIdentity/authMethodToSwan/xfrmiIfID/PrepareConfig/HasDHCPBoundGateway/resolveInterfaceAddress*/selectFamilyAddress/matchFamily/zoneQualify), pkg/ipsec/crypto.go ($9$ decoder), pkg/wgkey/wgkey.go (Generate/PublicKeyFromPrivate/HexToBase64/clamp). Context: pkg/config/compiler_ipsec.go, pkg/config/types_security.go, pkg/config/schema_security.go, pkg/config/schema_walk.go, pkg/cli/cli_show_security_ipsec.go, docs/pr/2073-ipsec-pfs/plan.md, pkg/ipsec test fixtures. External verification: downloaded strongswan-swanctl 6.0.7 + libstrongswan .debs and inspected binary format/keyword strings to confirm (a) swanctl --list-sas pretty output uses "local  '%s' @ %s[%s]" / "  %s: #%s, reqid %s" / ", %6s bytes, %5s packets" / "    local  %s" — none of the parser's "===", "local_ts", "bytes_in=" tokens exist; (b) proposal keyword table has sha2_256/sha256_96/md5_128 etc. but NO sha256128/sha196/md596. LENSES: (a) correctness/security — findings 1-5; (b) vSRX parity — findings 2,3,5,6; (c) performance — PrepareConfig synchronous DNS is bounded 2s and documented (#2757), swanctl shell-outs bounded by swanctlTimeout (#1794/#1800): no new perf finding; (d) refactor — finding 8 (policy.go regrowth); (e) test gaps — folded into findings 1/2/3 (tests actively pin the fictional SA format, the invalid sha256128 token, and the inverted df-bit mapping). DISCARDED AS DUPLICATES: matchFamily link-local + zone qualify (#2885 fixed at HEAD); ECP/RFC5114 DH keyword rendering (#2392/#2604 — formatDHGroup table present); empty-proposal fail-closed (#2270); PFS fallback on dangling proposal (#2073); remote_addrs gateway-name leak + orphan secrets (#2074); %any responder-only (#2404); dual-stack local-address family (#2757); PSK quote escaping (#2126) and control-char injection (#1798) — both belts present; GCM ICV suffix + explicit PRF (#2125); $9$ passthrough (#157); DPD hardcode (#156); lifetime-seconds (#155); external-interface local_addrs (#154); auth-method hardcode (#158); DHCP-lease re-render (#2884 — HasDHCPBoundGateway present + tested); st0 vs st0.0 if_id collision (#2909/#2933 — lives in pkg/config); XFRM teardown-rebuild (#2546 — pkg/routing); secret redaction at marshal (#2053 — Secret type used); pkg/ipsec decomposition (#1989 done; finding 8 is the NEW post-#2757/#2885 regrowth, explicitly differentiated); IPsec/ESP host-inbound bypass (#3616 OPEN — userspace-dp, out of module); effectiveTrafficSelectors nil-deref (#2022 fixed at HEAD). NEGATIVE RESULTS: crypto.go $9$ decoder is bounds-safe (skip>len guard, alphabet membership check before table index, modulo math matches upstream jcrypt); fsatomic 0600 write + no secret values in slog output; GetSAStatus/runSwanctl WaitDelay=5s caps post-SIGKILL pipe drain; pkg/wgkey is clean — stateless, validates hex length both pre- and post-decode, keys are print-only (cmd/cli/request.go + pkg/cli/cli_request.go) and never persisted, so no storage/permission surface exists; only theoretical nit is no zeroization of the private-key buffer in a short-lived CLI process (not reported).

### `go-api-grpc`  — 5 kept / 5 raw

Read at HEAD: pkg/api/api.go (query helpers, apiRuntimeDataPlane), server.go (NewServer routing, TLS cert persistence, auth wiring gate at :389), auth.go (Basic/Bearer/X-API-Key middleware), sse.go (event/log SSE + parseCategories/matchCategory/severity), system.go (systemInfo/ping/traceroute/buffers/systemAction reboot|halt), exec_timeout.go (diag budgets), config.go (all config-mode + show/export/search/compare/rollback handlers), sessions.go (offset+cursor pagination, enrich/merge, page-token codec, filters), stats.go (global/iface/zone stats, clearCounters), nat.go (source/dest/pool/rule stats), routing.go, ipsec.go, vrrp.go, health.go, metrics.go (collector struct+Describe+Collect gating), metrics_counters.go (global/iface/policy/filter collectors), metrics_userspace.go (dispatch), metrics_descriptors.go (label sets scanned for cardinality). grpcapi: server_diag.go (Ping/Traceroute/streamDiagCmd, MonitorPacketDrop validation, MonitorInterface/proxy/dialPeer, SystemAction incl zeroize), server_config.go (Set/Delete/Load/Commit/ShowConfig/ShowCompare/ShowRollback). Cross-checked configstore/store_format.go (Show* render from raw AST tree) and config/ast_format.go (Format/FormatSet/FormatJSON/FormatXML — no redaction) and config/types_system.go (#2053 Secret type redacts on typed-struct marshal only). Confirmed daemon_run.go:1337-1371 resolves non-loopback binds and wires Auth only when APIAuth configured, and logging/eventbuf.go Add() drops on full subscriber (SSE backpressure is producer-drop, not blocking — no goroutine leak; negative result).\n\nLenses covered: (a) correctness/security — findings 1,2,3,4; (b) vSRX parity — finding 1 (Junos $9$ vs cleartext); (c) perf/latency — none novel (metrics scrape recompute #285 already tracked; SNAT status one-call-per-scrape is already optimized); (d) modularity — noted but not reported (metrics.go 929-line collector struct is already tracked by #1540/#1726); (e) test-gap — findings 1 (no text-surface redaction test) and 5.\n\nDISCARDED as duplicates: flowexport {protocol,collector} label duplicate at metrics_descriptors.go:1705 == OPEN #3741 (do not re-report). MonitorPacketDrop validation gaps == CLOSED #3382 (HEAD reflects the fix: node/count/port/proto/zone/iface all validated). Session offset/pagination/filter fail-closed == CLOSED #3421/#3419/#3423/#3592 (HEAD reflects). REST match-policies fail-open + dup params == CLOSED #2934/#3606/#3679/#3709. Counter-read-error skip-not-zero == CLOSED #3345/#3408/#3464/#3681. nil zone-value panics == CLOSED #3493/#3476 (allInterfaceNames/buildSessionView/ifaceStats guard `zone==nil`). rollback selector fail-closed == CLOSED #3443. dynamicNeighborPresent {ifindex,ip} unbounded-cardinality label is DEBUG-ONLY (XPF_DEBUG_NEIGHBOR_KEYS, absent by default) — not reported. zoneStatsHandler calling zonesHandler(w,nil) is safe because zonesHandler takes `_ *http.Request` (verified) — negative result. TLS cert persistence (#1916) verified sound. SSE producer-drop verified (eventbuf Add default-case) so no backpressure DoS."}

### `go-dhcp`  — 5 kept / 5 raw

Read at HEAD ddf9f58: pkg/dhcp/{dhcp.go(1575),commit.go,renew.go,reconcile.go,test_seams.go}; pkg/dhcprelay/{relay.go(1342),l2send_linux.go}; pkg/dhcpserver/{dhcpserver.go(1034),lease_sync.go(853),ddns_leases.go(419),ddns.go}; pkg/ddns/hostname.go; plus vendored insomniacslk/dhcp v0.0.0-20251020 nclient4/nclient6 to verify wire behavior (raw-socket broadcast, NewSolicit IAID, WithClientID/UpdateOption replace semantics, Request/DiscoverOffer defaults). Confirmed daemon wiring: daemon_apply.go:1527 reconcileDHCPRelay -> Manager.Apply (spec diff only, no address in relaySpec).

Lenses: (a) correctness — relay giaddr address-drift (F1, verified README documents only ifindex drift, Apply diffs relaySpec={servers,alwaysBroadcast} only, ifindex watcher can't see address change); DHCPv4 NAK-vs-timeout conflation in RENEWING (F2, doDHCPv4 returns undifferentiated error, run loop waits for T2 keeping the revoked addr); DHCPv6 valid-lifetime-0 floored to 3600s (F4). (b) parity — server T1/T2 (opt 58/59, IA T1/T2) ignored (F3); non-zero giaddr overwrite + missing remote-id (F5). (c) perf — none material; discoverIPv6Router 10x1s is ctx-aware and short-circuits when RA neighbor exists. (d) modularity — dhcp.go 1575 / relay.go 1342 / ddns manager 1359 all under the 2000-LOC gate; consolidation already tracked by #1987 (CLOSED/backlog) — not re-reported. (e) test-gaps — folded into F1/F2 (no test for relay address-drift; no test asserting NAK->immediate re-DORA since the code can't distinguish it).

Verified endianness/byte-order in l2send_linux.go (htonsLocal via NativeEndian, BigEndian wire fields, UDP checksum 0 legal) — clean, no finding. Verified v6 memfile CSV column counts in writeMemfile4/6 (12/18 fields) match Kea headers — correct, no finding. Verified stableGroups/stablePools subnet_id determinism (#2668 fix present).

Candidates DISCARDED as duplicates or non-issues:
- Kea display/DDNS lease parser leniency/duplicate-column/ragged-row/tombstone-reclaim — exhaustively hardened by #2085/#2154/#1387/#2262/#2379 (all CLOSED, HEAD reflects fixes); no residual.
- Kea memfile ownership/perms on takeover — #2450 (CLOSED, WithOwner chown present).
- DHCP relay buffer truncation — #3012 (CLOSED, readBufSize=65535 present).
- DHCP relay INFORM/DECLINE/NAK/FORCERENEW relaying — #2153/#2789/#2606/#2645 (CLOSED, clientRequestRelayable + reply switch present).
- DHCP relay HA master gate / backup dup-forward — #2456 (CLOSED, shouldRelay present).
- DHCP client T1/T2 full-DORA and discarded-renewal — #2994/#1777 (CLOSED); F2/F3 are NEW residual shapes (NAK classification, timer source) and cite #2994 explicitly.
- DHCPv6 IATA round-trip / IAID-swallow / lease-type mis-seed — #2268/#2379/#2262 (CLOSED, shared inverse pair present).
- Kea subnet_id map-iteration nondeterminism — #2668 (CLOSED, stableGroups/stablePools present).
- ddns hostname sanitization / public-address gate — heavily mined (#2841/#2842/#2846/#3732 etc.); per module notes only clearly-new mechanisms considered; none found.

### `go-obs`  — 7 kept / 7 raw

Read at HEAD ddf9f58: pkg/logging/{syslog.go, ringbuf.go, eventbuf.go, locallog.go, aggregator.go, slog_handler.go, trace.go, goid.go, event_filter_args.go}; pkg/feeds/feeds.go; pkg/rpm/{rpm.go, icmp.go}; pkg/snmp/{agent.go, traps.go}; skimmed pkg/eventengine/engine.go head + prior-findings coverage; cross-checked pkg/config/{types_system.go, schema_system.go} and pkg/daemon/{daemon_run.go SNMP ifDataFn wiring, daemon_system.go syslog lifecycle}. Lenses covered: (a) correctness/security — syslog stream framing, feeds body cap, SNMP BER/GETBULK, trap version/categories; (b) vSRX parity — trap version/categories, RT_FLOW session-id correlation; (c) performance — GETBULK netlink storm; (d) modularity — noted but not reported (logging/ringbuf.go is a 1369-line monolith mixing decode+fanout+binary-encode, and flowexport package monolith is already tracked as prior-finding [pkg/flowexport] 'Package monolith' + #1988); (e) test-gaps — syslog partial-write desync has no test (folded into finding 1 fix), trap version/categories have no compile-drop test.

DISCARDED as duplicates / already-fixed at HEAD:
- Syslog reconnect cooldown / accept-then-reset dial storm — #2302 CLOSED, fix present (armReconnectCooldown, syslog.go:326).
- Syslog re-entrant slog deadlock + goID per-record on no-client path — #2287/#2295 CLOSED, guard present (slog_handler.go:83-100, goid.go).
- Syslog non-closing SetSyslogClients conn leak — #3579 CLOSED, ReplaceSyslogClients present (ringbuf.go:367; daemon uses it).
- TLS tls-profile nil config / stream unreachable-at-apply — #3350/#3351 CLOSED, handled (syslog.go:156-197).
- EventBuffer.Latest negative-n panic, zero-size ring — #3342 CLOSED, guarded (eventbuf.go:107/230).
- Event-mode local writer format/hardening/rotation-failure counters — #3409/#3477/#3478 CLOSED, present (locallog.go, trace.go openHardenedAuditLog).
- Session aggregator unbounded cardinality / Space-Saving top-K — #2936/#3099 CLOSED, present (aggregator.go).
- Trace path traversal / invalid-flag broadening / rotation CPU storm — #3420/#3422/#3424 CLOSED, present (trace.go).
- protoName GRE/ESP numeric — #3040 CLOSED, uses appid.ProtocolName (ringbuf.go:1210).
- Feeds partial-set invalid-line counter, retain-last-good — #2993/#2050 CLOSED, present.
- RPM source-address wildcard bind, http scheme heuristic, VRF DNS, ctx threading, IPv6 zone, pin gating — #2492/#2495/#2614/#2647/#2494/#1895 CLOSED, all present (rpm.go/icmp.go). RPM boot-cycle-before-callback is OPEN #3755 (daemon-owned, not pkg/rpm), left alone.
- SNMP engineBoots fail-closed, USM timeliness, GETBULK msgMaxSize trim, v2c community determinism, trap async delivery — #2649/#2610/#2612/#2989/#2991 CLOSED, all present (agent.go/traps.go).
- flowexport identity/reverse-counter/routemask/batch — #3739-#3748 just filed (module mined per notes); not re-reported.

Negative results: eventengine engine.go — the queued-action revision/cooldown/shutdown-drain surface is densely covered by prior-findings #517-549 and issues #2139/#2216/#2866-#2890/#2926; no clearly-new mechanism found in the head I reviewed, so not reported. SNMP BER decoders (berDecodeLength caps numBytes<=4, header truncation checks present) looked sound on the paths I traced; berDecodeInteger sign-extension is intentional and bounded.

### `go-ops`  — 8 kept / 8 raw

READ (all non-test .go at HEAD ddd9f58): pkg/fwdstatus/{fwdstatus.go,builder.go,sampler.go,procreader.go,README.md}; pkg/natshow/{natshow.go,source.go,dest.go,persistent.go,static.go}; pkg/natpoolalarm/{natpoolalarm.go,render.go,README.md}; pkg/upgrade/{runner.go,cutover.go,flip.go,state.go,version.go,imageversions.go,rolling.go,cluster_cli.go,kernel.go,kernel_run.go,kernel_linux.go,kernel_drain.go,kernel_selfrecover.go,system_linux.go} and subpackages lock/lock.go, manifest/manifest.go, runtime/seed.go, stagedgen/stagedgen.go. Cross-read supporting code: pkg/dataplane/userspace/{manager.go Status(), process.go statusLoop(), legacy_dataplane.go, protocol.go ProcessStatus}, pkg/daemon/{daemon_forwarding_status.go,daemon_natpoolalarm.go,daemon_run.go:1370-1410}, pkg/config/compiler_nat.go (validatePoolUtilizationAlarm + parse).

LENSES: (a) correctness/security — journal/flip/rollback crash windows, lock semantics, parser fail-closed behavior, watchdog magic-close semantics, endianness in natshow/persistent.go (correct NativeEndian per repo convention); (b) vSRX parity — pool-utilization-alarm thresholds, per-rule session counts, FWDD uptime semantics; (c) perf — control-socket call budget (found duplicate 1 Hz status poll), Manager.mu hold across socket round trips, ring-copy allocation (fine at 1/s); (d) modularity — kernel channel vs binary-cut cohabitation, FreeBytes copy-paste; (e) test gaps — noted inline in findings.

DISCARDED AS DUPLICATES: natpoolalarm "no consumer" (#2079 CLOSED, fixed at HEAD — monitor exists); monitor-vs-bootstrap d.dp race (#2114 CLOSED — atomic.Pointer + Swap wiring verified in daemon_natpoolalarm.go); upgrade lock stale-owner metadata (#1984 CLOSED — truncate-on-acquire/release-under-flock present); --rolling --unit wrong-daemon control (#1983 CLOSED — NewCLICluster rejects non-default unit); dpkg-unpack vs cut torn-read (#1981 CLOSED — stagedgen pinned generations verified); no-rollback first cut / seed (#1964 CLOSED); journal/copyTree durability hardening (#1967/#1968 CLOSED — fsyncDirsDeepestFirst etc. present); NAT pool stats capacity from config text (#2938 CLOSED — different site from my natshow rule-detail finding); interface-mode SNAT pool stats global-per-row (#3417 CLOSED — pool-stats renderer, NOT the rule-detail session counter I report); IPv6 persistent-NAT panic (#1152 CLOSED — persistent.go netip unified-key fix verified); Rust control-conn sequential starvation (prior finding userspace-dp/coordinator — Rust side; my sampler finding is a NEW Go-side redundant caller); PollStatus decoder churn (prior finding pkg/daemon/status.go — file no longer exists at HEAD).

NEGATIVE RESULTS (checked, sound): lock/lock.go flock-inode discipline (no split-mutex, no rm), stagedgen ResolveCurrent path-escape guards + GC additive protection, manifest SSOT accessors return fresh slices, runtime/seed idempotence + version-token validation parity, cluster_cli.go parsers fail-closed (drain per-RG pairing, sync-link section scoping, token-after-colon), imageversions u16 fail-closed gate, kernel_run ARMED-journal-before-BootNext ordering, revert reboot-loop bounding (maxPromoteAttempts + restoreKnownGood), ArmWatchdog/DisarmWatchdog magic-close semantics correct, natshow persistent.go byte-order (NativeEndian, matches conntrack/gc.go). userHZ=100 comment cites CONFIG_HZ wrongly but USER_HZ is 100 on Linux regardless — value correct, doc nit only. ticksToNanos uint64 overflow needs ~5.7 CPU-years and the monotonic guard absorbs the wrap tick — not reported. ForwardBeacon mgmt-path false-pass is explicitly documented as an accepted weakness in the code comment — not reported.

### `rs-policy`  — 8 kept / 8 raw

READ (full): userspace-dp/src/policy.rs (all 3625 lines — SnapshotIntegrityError enum+Display, zone map/reserved-id constants, PolicyRule/PolicyState, counter store + #3073 per-worker coalescer + #3448 epochs, CompiledApplications/#3346 cross-class precedence, AppCatalog/#3612 tiers, parse_policy_state_with_counters, legacy/v3/book address parsers, evaluate_policy_result_l3_aware 5-tier precedence, evaluate_junos_host_policy_l3_aware, try_match_rule incl. excluded/NAT64-mixed arms, parse_action/parse_applications/parse_protocol/parse_port_spec); prefix.rs (112), prefix_set.rs (322), ip_proto.rs (113), tcp_flags.rs (121); test inventories of policy_tests.rs (5958 lines, ~130 tests) and prefix_set_tests.rs. Cross-checked Go producers/gates: pkg/dataplane/userspace/capabilities.go (expandUserspacePolicyApplications, rustParsedProtocolBeforeFix, userspacePortSpecRepresentable, expandUserspacePolicyAddresses, normalizeUserspaceApplicationProtocol), policies.go (buildOneRuleSnapshot, classifyPolicyAddresses, feed overlay), pkg/appid/catalog.go (ProtocolNumber/Lenient), pkg/feeds (no entry cap), and the three Rust preflight sites (server/handlers/snapshot.rs, coordinator/snapshot_refresh.rs, coordinator/reconcile/mod.rs). LENSES: (a) correctness/security — findings 1,3,5,6; (b) parity — policy-rematch checked and DISCARDED (documented gap, docs/feature-gaps.md:63); junos-host/intrazone parity all mined; (c) performance — findings 2,4; (d) refactor — findings 7,8; (e) test gaps — folded into findings 1/3/5/6 (no mixed-any legacy test, no exact-tier order test, no all-placeholder test, no orphan-Arc test; standalone matrix gaps already mined as prior findings 56/84/93/94/361). DISCARDED AS DUPLICATES: from-zone junos-host not enforced + global junos-host context (open #3611, prior findings 4/12); host path skipping to-any/both-any/unscoped-global tiers + no configured-pair default-deny (prior findings 10/11 — also verified this matches Juniper's documented 'any excludes junos-host'); to-zone junos-host permit log/policy-id discarded on local delivery incl. its hit-counter side effect (open #3706, prior 250/251/636/637); icmp_type on non-ICMP terms and icmp_code-without-type (open #3712, prior 337); duplicate rule_id/policy_id aliasing incl. shared counter Arcs (open #3713); uncapped inactivity_timeout (open #3714); duplicate zone ids/names overwrite (open #3719 — also covers zone_name_to_id last-wins); global-rule full scan without scoped index (prior 343) and zone-pair bucket linear scan (prior 344); per-eval repeated book walks (prior 345); AppCatalog linear scan (prior 14) and enabled-vs-fallback precedence (prior 13/24, fixed by #3612 at HEAD); policy.rs module split (prior 348) and AppCatalog→appid move (prior 30); intrazone default-permit corpus (prior 70-95) — also discarded my 'unzoned flows counted under default_counter' candidate as a sibling of prior 72's conflation finding; reversed app port range (open #3726, NAT-side); simulator malformed-app-set divergence (open #3727). NEGATIVE RESULTS (checked, sound): #3711 malformed-literal + wrong-family book rejects present and ordered after the #3261 sentinel check per #3729; preflight counter-store leak already fixed (Codex F2 scratch stores at all three sites); trie /0 debug_assert bypass is safe (contains never reads root.covers); mask_v4/v6 shift underflow unreachable (ipnet validates prefix_len); v4-mapped-v6 literals land in the v6 family consistently (wire parser never produces mapped v6 for v4 packets); excluded-address fail-closed matrix (#2008/#3023) correct in all four family arms incl. NAT64 mixed arm; #3346 cross-class app-term precedence correct (tests 5674-5713); two-pointer wildcard merge order correct and tested; wire-boundary endianness not applicable here (string-carried addresses, host-order u16 ids); counter atomics follow the accepted #3451 relaxed-pair convention; Go Atoi('-0') vs Rust parse::<u8> numeric-protocol divergence judged too marginal to report ('+N' agrees on both sides; '-0' is the only splitting token). Quota: 8 findings reported, best-first, including low-confidence residual (#3711 empty-token pinhole) per campaign instructions.

### `rs-session`  — 3 kept / 3 raw

READ IN FULL: session/{mod.rs(1761L), key.rs, wheel.rs, expire.rs, install.rs, lookup.rs, ctx.rs, entry.rs}; afxdp/session_glue/mod.rs(1268L); afxdp/flow_cache.rs(955L); afxdp/poll_descriptor/flow_cache_hit.rs; afxdp/poll_descriptor/mod.rs forward-build+cache-populate (3300-3760); afxdp/worker/loop_body/mod.rs expiry+HA-gate consumer (430-810); afxdp/worker/lifecycle.rs invalidate_slot site (195-251); afxdp/forwarding/mod.rs cached_flow_decision_valid (675-733); slowpath.rs (1-500). Also grepped every flow_cache.insert/invalidate_slot/lookup call site, dscp derivation (frame/generated.rs:78 confirms dscp=ToS>>2 so <=63), and the flow_cache_tests.rs coverage matrix.

LENSES: (a) correctness — found the flow-cache-outlives-reaped-session coherence hole (F1); (b) parity — per-app inactivity_timeout not capped to 86400s lives in session/mod.rs app_inactivity_timeout_ns/secs_to_ns_saturating but is ALREADY tracked OPEN as #3714/#3741-adjacent (DISCARDED as dup); 5-tuple omits logical ingress = OPEN #2387 (DISCARDED); (c) perf — standby HOLD re-bucket is O(held)/GC-tick (F2); reverse-direction account_packet double-probe is documented/intended (DISCARDED); (d) modularity — session module cleanly split already (#2005/#1047), no new debt worth a slot; (e) test-gap — no test for session-expiry↔flow-cache coherence (F3).

DEDUP corpus checked (issues-all.txt + prior-findings.md + known-gaps.md):
- F1 vs #3048 (MAC-change eviction) DIFFERENT: #3048 fires neighbor_mac_epoch on a MAC change; F1 is idle-GC session reap with UNCHANGED mac/config/fib/epoch/lease, so no invalidation trigger exists at all.
- F1 vs #429 (flow cache outlives HA lease) DIFFERENT: #429 is HA-lease-expiry driven and only bites owner_rg_lease_until!=0; F1 bites standalone/active flows where lease==0, driven by session idle-expiry + 5-tuple reuse; the reverse blackhole comes from session-map delete + SNAT-alloc release, not lease.
- F1 vs #2363 (control segment seeds cache), #327 (epoch design), #417 (owner_rg_id=0 epoch bypass), #2466 (RG>=16 epoch), #2220 (active flow expiring) — all DIFFERENT mechanisms; #2220 is the OPPOSITE case (keep active flows alive) and its touch_if_stale fix does nothing for idle-then-resume.
- F2 vs #2120 (standby retention gate, CLOSED) — F2 is the un-flagged O(N)/sec residual of #2120's now_tick re-bucket, not the retention correctness itself.
- Discarded dscp<<2 truncation: frame/generated.rs:78 masks dscp to 6 bits, so no truncation in practice.
- Discarded per-IP session-limit inc/dec direction-flip leak: requires is_reverse to flip on update_session refresh, not reachable from any real caller — too speculative.
NEGATIVE RESULTS: key canonicalization endianness OK (Rust IpAddr native, no wire boundary in session/); slab handle u32 truncation bounded by max_sessions=131072; wheel bucket-skip prior-finding #621 is WRONG at HEAD (drain walks cursor_tick→now_tick, no skip); SessionTable is per-worker &mut-exclusive so no intra-table atomic/ABA race.

### `rs-worker`  — 5 kept / 5 raw

FILES READ AT HEAD ddf9f58: worker/mod.rs (BindingWorker, fabric_queue_hash_seeded, apply_worker_shaped_tx_requests, refresh_worker_cos_queue_lease_runtime_counters, load_arc_if_changed, BindingLiveSnapshot), worker/loop_body/mod.rs (worker_loop hot loop, fabric refresh, cold-path merge/publish, session-delta drain/resync, count_local_session_expiries, idle regulation), worker/loop_body/setup.rs (one-shot setup, TSC calibration), worker/lifecycle.rs (poll_binding RX/TX orchestrator, backpressure early-return), worker/cos/{mod,status,interface_row,queue_row}.rs, worker/{telemetry,timers,tx_pipeline,cos_state,scratch}.rs, poll_stages.rs (stages 5-11 incl. IPsec passthrough + screen), shared_ops.rs (shared-session HA prewarm/demote/publish/remove + NAT reverse-key displacement), cold_path_hist.rs (TSC histogram, seqlock publish/snapshot). Cross-read: forward_request.rs (fabric_queue_hash call site), flow_cache_hit.rs:267 (session-hit fabric hash), frame/inspect.rs (frame_is_non_first_fragment, parse_session_flow_from_bytes), gre.rs, coordinator/{snapshot_refresh,mod}.rs (shared_forwarding/shared_fabrics store sites), forwarding/mod.rs (is_ipsec_traffic), ha.rs (RG activation → prewarm), types/tx.rs (TxRequest owns Vec<u8> not a UMEM frame).

LENSES COVERED: (a) correctness — fabric queue-hash fragment consistency, seqlock ordering (sound), fabric ArcSwap ping-pong (DISCARDED, see below), shaped-TX no-owner frame leak (DISCARDED — TxRequest.bytes is an owned Vec, not a UMEM frame, dropping it frees heap, no leak); (b) parity — IPsec passthrough vs host-inbound (DISCARDED as dup #3616); (c) perf — quadratic prewarm dedup, redundant cold-path zone re-resolution; (d) refactor — cold-path merge duplication; (e) test gaps — first-vs-non-first fragment fabric hash, poll_binding backpressure path.

DISCARDED AS DUPLICATES:
- IPsec passthrough (stage 11) bypassing per-zone host-inbound + zeroed synthetic ifindexes → OPEN issue #3616 and prior-findings poll_stages.rs entries (lines 38/48/62 of prior-findings.md). Both angles (host-inbound bypass, L15 telemetry ifindex=0) are already tracked. Not re-reported.
- is_ipsec_traffic AH(51) omission → CLOSED #2385, HEAD includes PROTO_AH (forwarding/mod.rs:1061) + regression test. Fixed.
- WorkerStats/telemetry cache-line false sharing → prior-finding [worker/telemetry.rs] already filed; not re-reported.
- lookup_session_across_scopes global Mutex contention → prior-finding [types/runtime.rs]; not re-reported.
- Non-first fragment CoS/fabric queue on payload ports → CLOSED #2357/#2344; HEAD gates non-first fragments port-less. My finding #2 is a NAMED RESIDUAL of #2357 in a new shape (first-fragment vs rest), not the closed defect.

NEGATIVE RESULTS (checked, sound, not reported):
- Fabric ArcSwap ping-pong: I traced whether the worker_loop fabric-refresh clone (loop_body/mod.rs:771-778) could ping-pong every tick when shared_forwarding.fabrics diverges from shared_fabrics. It cannot: every coordinator store site (snapshot_refresh.rs:35/200+230, mod.rs:379, disarm mod.rs:494) keeps shared_forwarding.fabrics == self.forwarding.fabrics == shared_fabrics (snapshot refresh preserves fabrics at lines 183-198 before both stores). No persistent divergence → block fires at most once per real fabric change.
- cold_path seqlock (publish_from_local / snapshot): even/odd gen with AcqRel/Release brackets + reader Acquire/fence(Acquire)/Relaxed re-check is a correct seqlock; calibration fields are set-once pre-publish. Sound.
- count_local_session_expiries: exhaustive match (no wildcard) over the 8 SessionOrigin variants; a bindingless worker can't own create-counted locals so the bindings.first() guard dropping the increment is harmless. Sound.

### `rs-poll-descriptor`  — 4 kept / 4 raw

FILES READ AT HEAD ddf9f58: poll_descriptor/mod.rs (systematic sampling: header+imports 1-200; junos_host/flowless helpers 200-515; poll_binding_process_descriptor session-HIT LocalDelivery gate 790-1108; session-MISS LocalDelivery gate 1790-2010; transit deny_reply_and_emit 2870-3022; flowless transit/LocalDelivery arms 3050-3288; forward-build + MissingNeighbor policy arm 3720-4050; test modules 5016-5330 skimmed), filter.rs (full 1-1159), reject_reply.rs (full 1-1772). SUPPORTING: icmp.rs (build_local_icmp_error_v4/v6 326-499, build_reject_icmp_unreachable 541-563, build_local_time_exceeded_request 162-276, reject_icmp_reply_suppressed/is_icmp_error), forwarding_build/interfaces.rs (populate_egress 189-266 — confirmed egress keyed by LOGICAL iface.ifindex with bind_ifindex=physical parent, addresses via pick_interface_v4/v6), worker/mod.rs identity() (binding.ifindex copied verbatim into BindingIdentity.ifindex), poll_stages.rs, tx/drain/mod.rs (TxRequest.egress_ifindex consumption), docs/ha-cluster-userspace.conf (reth0 vlan-tagging; addresses only on units 50/80).\n\nLENSES: (a) correctness/security — found the reject-build physical-ifindex source-IP miss (F1) and the flowless MissingNeighbor policy bypass (F4); (b) vSRX parity — F1 (reject→silent drop on VLAN), F4 (fragment policy); (c) perf — reject/filter bodies are correctly #[cold]#[inline(never)], hot session-hit filter guards fold; no new perf finding; (d) modularity — mod.rs is 5321 lines with the poll loop still one giant body (tracked as #55 in prior-findings 'Oversized poll loop'), not re-reported; (e) test-coverage — F3 (no VLAN ICMP-build test) and F2 observability.\n\nDISCARDED AS DUPLICATES: mirror_clone:false at reject_reply.rs:360 — prior-finding #40 + #3617 CLOSED, HEAD still hard-false but already tracked, not re-reported. Reject token bucket consumed before build — #3656 CLOSED, code at 243-253 now builds before consume (fix present). Single global reject bucket cross-zone starvation — #3618 OPEN / prior-finding #648, tracked. Host-inbound-before-lo0 ordering — #3485 CLOSED, correct at filter.rs:559-591. RT_FLOW REJECT-before-reply truthfulness — #3615 CLOSED, correct (enqueue-then-emit) at reject_reply.rs:185-209 and filter_terminal. VLAN host-inbound gate probes physical ifindex — #3609 CLOSED, gate now takes resolved logical (filter.rs:547-591); F2 is the distinct lo0 filter-LOG zone-hint arg, not the gate. dbg.policy_deny conflation for host-inbound — prior-finding #16, now split to dbg.host_inbound_deny (mod.rs:961,1864,3267). Flowless LocalDelivery bypass — #3292 CLOSED, routed through flowless_local_delivery_verdict.\n\nNEGATIVE RESULTS: reject rate-limit/budget ordering, per-source counter split (#3661/#3657), and reject event truthfulness are all correctly implemented with RED-on-revert tests; inbound-RST/ICMP-error/non-first-fragment unreplyable suppression is correct (build-first feasibility). TCP RST reflection L2-group guard lives in build_reject_rst_frame (not re-audited; #3204 CLOSED). Endianness at wire boundaries in the reflected builders uses to_be_bytes for ports/lengths — correct."

### `rs-umem-frame`  — 7 kept / 7 raw

READ (full or targeted): userspace-dp/src/afxdp/umem/mod.rs (all 1311 lines: WorkerUmem/WorkerUmemPool, BindingLiveState + ~100 counters, PendingTxAdmission, push_redirect_inbox/try_acquire/release admission, take_pending_tx_into, session-delta queues, bucket_index_for_ns); umem/mmap.rs (hugepage mmap, slice/slice_mut_unchecked bounds); frame/mod.rs (all 1563: v6_rel_l4_offset, apply_dscp_rewrite, build_nat64/forwarded frame, RewritePrep + classify_in_place_l2_rewrite + descriptor_view_in_same_umem_frame, rewrite_apply_v4/v6, trim_l3_payload, apply_nat_ipv4/ipv6, apply_nat_port_rewrite, enforce_expected_ports(_at), restore_l4_tuple_from_meta, build_injected_ipv4/6, verify_built_frame_checksums); frame/inspect.rs (all 1770: l3/l4 offset walkers, fragment predicates, term_match_extra_* (#2449/#3008 gates), declared_l3_end (#2361), icmp_identifier_bearing (#3067/#3290), parse_session_flow_* chain, fabric zone MAC decode, try_parse_metadata read_unaligned); frame/wg.rs (encap path lines 1-573 + test skim: outer_physical_egress_ifindex/mtu #2680/#2701, wg_peer_outer_dst #2845, wg_encap_frame #2792 in-place encrypt, udp6 checksum #2651); xsk_ffi.rs (all 1462 + csrc/xsk_bridge.c all 263: ring struct ABI vs libxdp, reserve_up_to partial-reservation, WriteTx/WriteFill/ReadRx/ReadComplete lifecycle incl. Drop cancel semantics, DeviceQueueRings borrow-vs-own, create_xsk_binding_impl); io_uring_write.rs (all 881 incl. FakeRing tests); hot_hash_seed.rs (all 141). Cross-checked callers: tx/rings.rs reap/fill, tx/transmit/mod.rs, tx/dispatch/cos.rs, bind.rs try_open_bind, slowpath.rs/state_writer.rs io_uring usage, mirror resolver, types/tx.rs TxRequest, mpsc_inbox.rs CachePadded layout, userspace-xdp/src/lib.rs pkt_len stamping, gre.rs decap meta stamping. LENSES: (a) correctness/security — findings 1, 4, 6; (b) vSRX parity — nothing new (frame module is mechanics; WG pad-to-16 vs spec min(16,MTU) is universal practice and MTU-guard-safe); (c) performance — findings 2, 3; (d) refactor/modularity — findings 4, 5, 7 (module split itself is healthy post-#1352/#988/#1351); (e) test gaps — folded into findings 1 and 4 (cross-call stale-CQE untested; consumer-ring cursor semantics untested). LOW-LEVEL INVARIANT CHECKS (negative results): bucket_index_for_ns verified at 0/1023/1024/2^24 boundaries — correct; XskRingProd/Cons #[repr(C)] layout matches libxdp struct field-for-field; Umem::frame Option-ordering bounds check correct (None < Some); reserve_up_to nb_free-refresh-then-reserve is sound for single producer; WriteTx/Drop submit+cancel accounting consistent with libxdp cached_prod semantics; ReadRx/ReadComplete drop cancel arithmetic cannot underflow (read_count<=peeked guarded); pending_tx_admitted AcqRel CAS/underflow debug_assert sound; MmapArea #1020 checked_add alignment overflow guard present; try_parse_metadata uses read_unaligned (no misaligned-load UB); VLAN push tx_addr=rx_addr-4 stays in-chunk via descriptor_view_in_same_umem_frame and only clobbers the tail of already-copied metadata (meta parsed by value at RX — safe); endianness at wire boundaries uses from_be_bytes/to_be_bytes consistently in frame/*. DISCARDED AS DUPLICATES/KNOWN: (1) enqueue_tx/enqueue_tx_owned swallowing overflow with dead Err arms — explicitly documented as accepted at tx/dispatch/cos.rs:80-88 under #2208; (2) UMEM frame leak classes — #203, #625, #2374, #1307 all verified fixed at HEAD; prior-finding (umem/profile.rs transmit_redirect leak) already filed; (3) trim_l3_payload dual pkt_len semantics (shim=frame-len at userspace-xdp/lib.rs:686 vs GRE-decap=L3-len at gre.rs:755) — arithmetically disambiguated and the padded-frame padding-retention tradeoff is documented in-function; (4) eprintln diagnostics at socket create/bind — journald pattern accepted by project logging rules (rare, create-time only); (5) io_uring in-call misattribution/UAF/tight-spin — #2297/#2312/#2407/#2477/#2478 all verified fixed at HEAD (residual reported as finding 1 with mechanism distinction); (6) all WG encap prior issues (#2680, #2701, #2684, #2836, #2837-nonrepro, #2845, #2792, #2651, #2303, #2703) verified present/fixed in wg.rs at HEAD; (7) inspect.rs hardening (#2344, #2361, #2292, #3067, #3290, #2449, #3008, #3077, #3232, #3075) verified — probed each gate for bypasses (meta-led offsets, declared-end clamps, fragment predicates) and found none; (8) generic false-sharing/missing repr(align) on hot counter structs — already in prior-findings (rows 618/670); finding 3 is narrowed to the distinct per-item-RMW mechanism; (9) BindingLiveState god-struct refactor — #1351/#986 already restructured umem/, remaining counter sprawl is telemetry-driven and tracked by the wire contract. NEGATIVE RESULT: no frame-descriptor double-free or fill/comp accounting error found on current error paths (transmit_batch partial-insert requeue returns frames to free_tx_frames before requeueing reqs; prime_fill_ring returns uninserted suffix per #2374; reap path release/cancel balanced).

### `rs-forwarding`  — 5 kept / 5 raw

READ (full or targeted): userspace-dp/src/afxdp/forwarding/mod.rs (all 2249 lines — classify_metadata, canonical_route_table, resolve_forwarding, fabric redirect family, HA enforcement, cached_flow_decision_valid, MSS/MTU helpers, lookup_forwarding_resolution_v4/v6, ECMP select_route_next_hop + hashes, tunnel outer resolution, neighbor lookup); forwarding_build/{mod.rs, fib.rs, interfaces.rs, tunnels.rs} full, cos/validated/wg/zones skimmed via mod.rs orchestrator; forwarding/host_inbound.rs skipped in depth (saturated by ~30 prior findings); neighbor.rs (full: probe sockets, warmer loop, netlink dump/monitor, ENOBUFS re-dump); neighbor_resolver.rs (lines 1-1116: resolver loop, epoch guard, classify_nud, rate limiting); neighbor_dispatch.rs (full: retry_pending_neigh, learn_dynamic_neighbor, admission); mirror/{mod.rs, fast_path.rs, resolver.rs} full; bpf_map/{mod.rs, publish_conntrack.rs} full, ha/metrics/pin skimmed (small, post-#2003 code motion); supporting reads: umem/mod.rs PendingTxAdmission (Drop releases reservation — no leak), poll_descriptor/mod.rs NoRoute arm + flow_cache_hit.rs mirror/validation path, tx/dispatch/mod.rs mirror call site + cos.drop handling, disposition.rs, rst.rs, server/handlers/forwarding.rs, pkg/dataplane/userspace/{routes.go, fabric.go, manager_ha.go, process.go}, pkg/cluster/sync_conn.go (fab1 failover), forwarding/README.md. LENSES: (a) correctness/security — findings 1,2,4; (b) vSRX parity — findings 1,2,4; (c) performance — finding 3 (per-packet allocs/double lookups); (d) refactor — table-name interning proposed in finding 3; a forwarding/mod.rs split proposal was DISCARDED as colliding with #2158's over-2000-LOC watch-list (which already names the forwarding watch-list); (e) test gaps — folded into findings 2 (no multi-fabric selection test) and 5 (missing same-worker sampler test). DISCARDED AS DUPLICATES: (i) local_v4/local_v6 being a global, non-table-scoped set (cross-VRF local-delivery leak with ifindex-0 fallback) — prior finding 588 + #3151 attribution fix cover the mechanism; (ii) recursive next_table lookup without per-family canonicalization — prior finding 594; (iii) A->B->A next-table cycles recursing to MAX_NEXT_TABLE_DEPTH — prior finding 595; (iv) neighbor_state_usable free-form denylist (and its numeric sibling: parse_neighbor_msg upserting a NUD_NONE-state RTM_NEWNEIGH) — prior finding 601, same defect class; (v) canonical_route_table silently rewriting cross-family names — prior finding 604; (vi) fe80::1%iface next-hop parse failure — prior finding 605; (vii) LocalDelivery with ifindex 0 unobserved — prior finding 607; (viii) infer_connected_route_target being global not table-scoped — prior finding 592 (code now carries an 'intentional' comment); (ix) tunnel transport_table canonicalized by outer_family while lookup family follows destination (mismatch -> NoRoute) — same family-canonicalization drift class as prior findings 593/594, discarded; (x) fabric links silently skipped on malformed MAC/peer — prior finding 602; (xi) equal-prefix route rows not merged for ECMP — subsumed by prior findings 589/599 (Go dedupe/sort at the same boundary); (xii) NAT/DNAT external IPs in global local sets — prior finding 588. NEGATIVE RESULTS: PendingTxAdmission cannot leak reservations (Drop impl at umem/mod.rs:764 releases); sort_routes ordering (prefix-len desc, preference asc, stable) is correct per #2390; choose_v4/v6_route connected-vs-static tie-break matches Junos preference (direct 0 < static 5) at equal prefix length; select_route_next_hop single-pass liveness (#2922) and tunnel liveness (#2923) verified sound including the depth threading; ecmp_hash_flow per-boot seeding is correctly node-local (not HA-synced); fabric redirect cannot loop (redirect_via_fabric_if_needed refuses when ingress is already fabric); resolver epoch guard + in-lock re-check verified against the #1769/#2919 race matrix and is heavily test-pinned; neigh monitor 8192-byte recv is safe for dumps (kernel caps dump skbs at the socket's max seen recvmsg len) — not reported as truncation risk; publish_conntrack endianness follows the repo NativeEndian convention for __be32 (u32::from_ne_bytes over already-network-order octets) — correct; retry_pending_neigh cos.drop silent recycle equals the immediate path's behavior (dispatch/mod.rs:136 also silent; filter-term counters account) so no divergence to report; mirror pre-rewrite cloning (ingress-side mirror semantics) is consistent across immediate/pending/flow-cache paths and test-pinned.

### `rs-nat`  — 8 kept / 8 raw

READ (full): userspace-dp/src/nat/allocator.rs (claim_free_port_locked, allocate_translation, release_flow, rollback_flow, gc_expired_locked/for_addr, release_expired_lease_locked, sticky_pool_index), nat/source.rs (rule parse, expand_pool_address, l4_matches/scope_matches, match_source_nat_result_for_tuple, release/rollback entry points), nat/destination.rs (DnatTable build/lookup tiers, LPM slots, destination_ips), nat/static_nat.rs (SourceConstraint, pick_scoped, block remap, from_snapshots, match_dnat/snat scoped), nat/mod.rs + status.rs (NatDecision reverse/merge, counters), nat64.rs (both _into translators, ext-header walkers, fragment paths, ICMP error maps + embedded translation, checksum helpers, frame builders), nptv6.rs (adjustment computation, translate in/out, overlap rejection), afxdp/icmp_embed/{mod,parse,builders,nat_match_v4,nat_match_v6,return_resolution,session_match}.rs. Also verified caller-side TTL handling (poll_descriptor/mod.rs:1076-1100 session-hit and :2412 session-miss both call build_local_time_exceeded_request before NAT64 translation) and NAT64 frame-builder call site (afxdp/frame/mod.rs:213-262). RFC texts fetched and checked: RFC 6296 (§3.2 discard, §3.5 word-selection), RFC 7915 (§1.2 fragmented-ICMP exclusion, §4.2 code table incl. 'Code 14 silently drop', §4.3 inner-packet translation, TTL MUST-send-error), RFC 7915 has no explicit 1280/576 clamp (finding 6 rests on RFC 4443 §2.4(c) — confidence set accordingly).

LENSES: (a) correctness/security — findings 1,3,5,6,7,8 + allocator state-machine audit (reuse/rollback/GC index symmetry traced clean: remove/insert expiration helpers are paired, retained-recycled-port loop terminates, rollback restores previous expiry correctly); (b) vSRX parity — finding 2 (ICMP query-ID PAT); (c) performance — allocation paths re-audited: mutex serialization already OPEN as #2852 (release-side O(rules) mutex passes judged same family, discarded); hot paths allocation-free per #2211/#3025, verified; (d) modularity — nat64.rs carries three private bounded ext-header walkers + a fourth in icmp_embed/parse.rs mirroring afxdp/frame/inspect.rs; unification was adjudicated in #2292 (closed) and the in-code comments deliberately keep local walkers to avoid a crate-cycle, so not re-reported; #1542 module split verified done; (e) test gaps — folded into findings 1 (no RFC 6296 §3.5/§3.2 pin; nptv6_tests.rs:494-496 hard-codes the misconception), 3 (no allocator-reuse timeout test) and 4 (fail-on-revert test exists only on the unmerged branch).

DISCARDED AS DUPLICATES / NON-ISSUES: (1) NAT64 non-first-fragment drop → dup #2562 (OPEN, deferred from #2488). (2) SNAT allocator global-mutex serialization (alloc + release side) → dup #2852 (OPEN) / #2905. (3) Interface-mode SNAT lacks PAT → reverse-key collision class named and adjudicated in #1760 (closed at session-index level). (4) NAT64 lacks RFC 6146 source-port translation (v4-side tuple collisions) → adjacent to closed #858 + #1760; judged known design territory. (5) Embedded quoted L4 checksum not updated in NAT64 error translation → #2371 closed as the documented leave-as-is decision (nat64.rs:1473-1475). (6) ICMPv6→ICMPv4 dest-unreach codes 5/6 dropped → RFC 7915 §5.2 'other codes: silently drop' — HEAD is conformant, discarded after RFC check. (7) NPTv6 overlap/first-match nondeterminism → fixed #2241, verified at HEAD (find_overlap). (8) NPTv6/NAT64 fail-open parsing → fixed #2240/#2212, verified try_from_snapshots fail-closed. (9) expand_pool_address including network/broadcast of a v4 pool prefix → deliberate #3049 decision documented in code. (10) sticky_pool_index FxHash → #2349 decided. (11) Recycled-port FIFO starvation/discard → fixed #3047/#3011, verified retain-requeue loop. (12) Static-NAT split-horizon overwrite → fixed #3605, verified per-key Vec + pick_scoped. (13) DNAT PROTO_ANY/HOPOPT aliasing → fixed #2396 (u16 sentinel 256), verified. (14) Translator silent drop on TTL<=1 without Time Exceeded → NOT a bug: callers generate TE before translation on both session-hit and session-miss paths (#2237 facility), verified. (15) NAT64 pool_index reset on refresh (round-robin restart) → harmless, discarded. (16) #3726 (module notes) → reversed-app-port-range in Go builder, out of this module's Rust files; verified the Rust side preserves never-match sentinels verbatim (source.rs:550-576, destination.rs:384-399).

### `rs-screen`  — 4 kept / 4 raw

Read all target files at HEAD: screen/mod.rs (1049L), syncookie.rs (600L), scan.rs (890L), stateless.rs (263L), extract.rs (303L), packet.rs (153L), rate.rs (238L), syn_rate.rs (343L), plus the production call sites in afxdp/poll_stages.rs (stage_screen_check ~300-543, stage_screen_syn_cookie_ack ~556-663), afxdp/poll_descriptor/mod.rs (new-flow scan/sweep hook ~1600-1720), afxdp/frame/inspect.rs (parse_session_flow_from_bytes ~1220-1358, icmp_identifier_bearing ~960, meta_icmp_identifier_bearing ~990), afxdp/mod.rs (record_screen_drop ~576), afxdp/worker/loop_body/mod.rs (config-swap site ~397-408), compiler_security.go (syn-flood default ~1052-1096).

Lenses covered: (a) correctness/security — traced the pre-session screen dispatch for every flow/flowless class; (b) vSRX parity — LAND/icmp-flood/source-route coverage vs Junos intent; (c) perf — SipHash streaming, CMS cost, per-packet borrow (all clean); (d) modularity — SYN-flood inline block; (e) test-gap — icmp-flood integration coverage.

DISCARDED as duplicates:
- rate.rs two-bucket over-throttle → #3607 OPEN / prior-findings rate.rs entry (told it is known; confirmed HEAD still two-bucket, not re-reported).
- SYN-flood sub-thresholds reaching dataplane, timeout enforcement → #3315 / #3527 CLOSED, HEAD reflects (syn_dst_sketch/syn_src_sketch/alarm present; timeout in session opening overrides). Not re-reported.
- non-first fragment bypassing fragment screens → #3064 CLOSED (flowless L3 fragment path added). My F1 is the RESIDUAL: that flowless path omits the src-independent screens; distinct shape (see F1 dedup).
- ICMP fake sessions via meta fallback → #3290 CLOSED. My F1 uses #3290's fix as the REACHABILITY widener for a different defect (icmp-flood/land bypass), named explicitly.
- SYN-cookie epoch per-packet clock read → #3032 CLOSED, HEAD caches wall secs once/mono-sec (verified current_syn_cookie_full_epoch). Clean.
- validated-cache survives profile change → #2446 CLOSED, profile_gen stamped in key (verified). Clean.
- scan/sweep global/unbounded/cross-zone → #2209/#2234/#2227 CLOSED, ScanCore per-(zone,src) bounded+evicting (verified). Clean.
- source-route IHL>5 false drop / IPv6 RH → #2973 CLOSED, extract.rs TLV walk + RH0/1 detection present. Clean.
- config swap race → per-worker single-thread; update_profiles/update_missing_profiles/update_syn_cookie_master_key applied together between batches (loop_body:397-402). No race. NEGATIVE result.
- SYN-flood source/dest-threshold dead when attack-threshold==0 → compiler defaults AttackThreshold=200 whenever the syn-flood stanza exists (compiler_security.go:1093, #3024). Not reachable. NEGATIVE result.
- fixed ROW_SEEDS CMS targeted-collision false-positive → explicitly acknowledged/accepted in syn_rate.rs module doc (lines 93-99). Known/accepted, not re-reported.
- SipHash24 streaming correctness, 24-bit MAC brute-force (bounded by 64s epoch + 4096/s standby limiter), MSS 3-bit quantization → all verified sound. NEGATIVE results.

### `rs-filter`  — 6 kept / 6 raw

READ (all at HEAD ddd9f58): userspace-dp/src/filter/{mod.rs(911L),policer.rs(566L),compiler.rs(831L)}, filter/engine/{mod.rs,eval.rs(1026L),matching.rs,tx_selection.rs,cache_sensitive.rs,policer.rs} in full; consumers traced: afxdp/tx/cos_classify.rs (resolve_cos_tx_selection_internal, resolve_cached_cos_tx_selection), afxdp/poll_descriptor/filter.rs (verdict/lo0/host-inbound paths), poll_descriptor/mod.rs:830-910 (session-hit re-eval), poll_descriptor/flow_cache_hit.rs:100-230 (cached replay), afxdp/forward_request.rs:120-235, afxdp/tx/dispatch/cos.rs, afxdp/worker/loop_body/mod.rs:280-530 (rotation purge + counter flush), afxdp/flow_cache.rs (config_generation stamp), afxdp/forwarding/mod.rs (cached_flow_decision_valid); Go side: pkg/dataplane/userspace/filters.go (buildPolicerSnapshots/buildThreeColorPolicerSnapshots, flex lowering), pkg/config/compiler_firewall.go:330-470 (flex range parser), pkg/config/compiler_validate_strict.go:4207+ (validateFilterFlexMatchStrict), pkg/config/filter_match_resolve.go (port-0 policy). LENSES: (a) correctness/security — findings 1,2,6; (b) parity — findings 2,3 (+ discarded plain-policer gap); (c) performance — findings 3,5; (d) refactor — finding 4 (SSOT equality predicate) — no new sibling-file sprawl proposed since prior finding already covers the compiler.rs split; (e) test gaps — folded into findings 1 and 4 (single-count-per-packet ownership test; FilterTerm exhaustiveness guard). DISCARDED AS DUPLICATES/KNOWN: plain two-color policer (`then policer` + PolicerSnapshot) never metered in userspace-dp (PolicerState::consume dead outside tests, FilterResult.policer_name has zero consumers) — documented accepted gap in docs/feature-gaps.md:608 'Policer (Rate Limiting) ... Partial' + known-gaps.md dataplane note; DSCP rewrite masking / out-of-range dscp bitmap drops — OPEN #3715; port-except comment contradiction + positive+except positive-wins at Rust boundary — OPEN #3716; cross-field protocol/port/tcp-flags incompatibility never-match — OPEN #3723; kernel FBF mirror ignoring L4/flex predicates — OPEN #3730; unsupported three-color shape installing drop-all instead of rejecting snapshot — prior-finding (compiler.rs, corpus line 315); Rust service-name port table drift/normalization/partial-malformed narrowing — prior findings 310-312/327 (#3205 family); meta-only l4_present icmp-0 false-match — #3008 CLOSED, fix present at HEAD; three-color Mutex-per-policer contention/sharding — known-gaps.md line 15; input filter evaluated against POST-NAT wire key on the TX leg — documented accepted corner in filter/README.md (#3642 paragraph). NEGATIVE RESULTS: policer token-bucket math verified sound (srTCM/trTCM conform to RFC 2697/2698 incl. green-decrements-both trTCM rule; u128 TOKEN_SCALE cannot overflow at u64::MAX rate*elapsed (~3.4e38 headroom); capped_add saturates; refill skips on non-monotonic now_ns; overflow-to-excess srTCM refill correct; boundary test u128_bucket_math_boundary_inputs exists); port 0 rejection in parse_port_spec is deliberate and gate-consistent (pkg/config/filter_match_resolve.go:220 documents 'Port 0 is rejected'); #2620 count-policy (verdict vs routing evaluator) re-verified consistent on all four exits — no residual; filter_id positional identity across rotations is bounded by the flow-cache config_generation stamp (flow_cache.rs:827); the no-meter now_ns=None TX-selection variant (resolve_cos_queue_id) has no production callers, so no missed-policing hole there; record_filter_counter thread-local coalescer is flushed per poll tick (loop_body:831/1295).

### `rs-cos-tx`  — 6 kept / 6 raw

READ (all at HEAD ddf9f58): cos/queue_service/{mod.rs (1881 L, both pages), drain.rs, service.rs, submit_local.rs}, cos/queue_ops/{mod.rs, push.rs, pop.rs, accounting.rs, v_min.rs, drain.rs, active_buckets.rs}, cos/admission.rs, cos/token_bucket.rs, cos/fairness.rs, cos/tx_completion.rs (fn cluster 370-996), tx/dispatch/{mod.rs, cos.rs}, tx/cos_classify.rs (classify + enqueue_cos_item + admission accounting), types/cos.rs (lines 1-948: FlowRrRing, CoSQueueRuntime/HotState, FlowFairState, waterfill fields), types/shared_cos_lease/{lease.rs full, epoch.rs, rotate_epoch_v8.rs, publish_equal_flow_epoch_v8.rs, vtime.rs, backlog.rs}, src/fairness.rs, fairness_eval/windowing.rs. LENSES: (a) correctness — traced push/pop/settle/rollback accounting (queued_bytes, local_item_count, snapshot stack, UMEM frame offsets), lease acquire/rollback (Step A/B/C tag-checked CAS), seqlock rotation; (b) parity — CoS scheduler priorities/exact/surplus semantics match documented Junos model, remaining CoS parity rows tracked in docs/feature-gaps (skipped as known); (c) perf — EWMA overflow (u128 intermediates OK), refill token wrap (saturating + u128, OK), cache-line padding (PaddedVtimeSlot/PackedEpochGrant/PaddedAtomicU64 all repr(align(64)), verified), wakeup-tick estimator; (d) refactor — dispatch orchestrator deferral; (e) test gaps — folded into findings 2/3. DISCARDED AS DUPLICATES: (1) vtime overflow on scheduler pause — prior-findings.md L657 (vtime class already reported; current vtime.rs slots are publish-only, no multiply); (2) seqlock reader torn-read — #1643 CLOSED, fix (fence(Acquire) before seq re-read) verified present at lease.rs:1067; (3) V_min throttle floor on unshaped shared-exact — #2981 CLOSED, exemption present v_min.rs:186; (4) V_min cadence burn on no-pop — #2646 CLOSED, deferred-commit present drain.rs:228/518; (5) TX dispatch ingress-descriptor leak on congested/oversized forward — #2208 CLOSED, finalizer fallthrough present (dispatch/mod.rs:757/786/1057/1083); (6) queue_service/shared_cos_lease >2000-LOC splits — #2158 CLOSED (done); (7) equal-flow fail-open via banked tokens / >32 workers — #1745/#1733/#1830 CLOSED, sticky-max samples + heap scratch present; (8) mirror_clone sidecar prefix-attribution defect in submit_local — explicitly documented in-code as tracked carry-over (submit_local.rs:3-6), not re-reported; (9) unkeyed hot-path hash — #2364; CoS flow hash is OS-seeded per promotion (admission.rs:529), clean; (10) min-finish O(N) scan — #1763 CLOSED (fused select+pop present); (11) waterfill Phase-2 lock-in / honored-bitset bugs — #1627/#1732/#1743 CLOSED, fixes verified in the selector. NEGATIVE RESULTS: shared_cos_lease ABA — PackedEpochGrant tag-equality checks are wrap-safe (documented 9.94-day u32 tag wrap analysis at lease.rs:1174, verified); lease leak — Step-B failure rolls back Step-A via tag_checked_rollback, granted bytes always land in caller tokens and are consumed/release_unused (refresh_cos_interface_activity:713 releases banked tokens of emptied exact queues); refill races in refill_shared_cos_lease_state/refill_residual_surplus_budget lose at most one interval on CAS loss (retried), no double-credit; priority inversion — strict exact-over-nonexact with residual-rate reservation (nonexact_surplus_budget_under_exact_demand) is coherent incl. peer masks; per-class stats — all four apply_* sites call account_queue_drain_sent_bytes (the historical 4th-site miss is fixed); admission drop accounting attributes flow-share vs buffer correctly and recycles prepared offsets (cos_classify.rs:1010-1072); src/fairness.rs pure fns match the doc worked examples; fairness_eval/windowing.rs zero-throughput streams deliberately routed to starved-count not CoV (documented Codex finding).

### `rs-server`  — 5 kept / 5 raw

Read at HEAD ddf9f58: server/lifecycle.rs, state.rs, mod.rs, helpers.rs, all handlers/*.rs; protocol/{control,snapshot,security(head),cos(head),resolution,binding(head),mod}.rs; event_stream/{codec,mod,producer}.rs; state_writer.rs; main.rs. Cross-checked Go peers: pkg/dataplane/userspace/{process.go,manager_ha.go,eventstream.go,screens.go,capabilities.go}, pkg/daemon/daemon_ha_sync.go.

DEDUP (grep issues-all.txt + prior-findings.md + known-gaps):
- apply_snapshot/bump_fib partial-failure + version-gate + persist-on-reject + fib rollback: ALL PRIOR (prior-findings lines 582/585/586/590/591) — DISCARDED, not re-reported.
- #2523/#2744 control-socket read cap: verified correct at HEAD (handlers/mod.rs read_until + take(cap+1)); DISCARDED (fixed).
- #2974 remove_stale_socket fail-closed: verified present; DISCARDED (fixed).
- #2970 raise-only sysctl: verified; DISCARDED.
- #2957/#2958/#3009/#2705/#2714/#2147 state_writer (orphan sweep pid+starttime, io_uring demotion, unique temp, fsync file+dir): verified all present at HEAD; DISCARDED (fixed).
- #2875 paused-drain session-eviction poison: verified present; pause/resume ARE production-reachable (prepareUserspaceRGDemotionWithTimeout); DISCARDED.
- #2959 event-stream ACK window validation: verified present; DISCARDED.
- #2381/#2382 write-backlog cap + replay evictions: verified; DISCARDED.
- #2962 export_owner_rg_sessions off-lock two-phase: verified present for owner_rg — BUT export_all_sessions still inline under lock => NEW residual (finding 1).
- WG key skip_serializing hygiene (snapshot.rs 492/531) verified — BUT syn_cookie_master_key (306) has NO skip_serializing => NEW leak (finding 2). #2446 (cookie cache vs profile) is a different mechanism.

NEGATIVE RESULTS: codec.rs frame encoders bounds-checked (max v6 SESSION_OPEN payload 136B, RT_FLOW 152B, both << 256 buffer); no truncation in wire ports/ifindex casts that reaches a live reader (owner_rg i16 cast is `let _ =`'d unwritten in RT_FLOW close). process_control_frames MAX_CONTROL_PAYLOAD_LEN=0 cap correct. next_seq/acked ordering benign. Control-socket file mode is umask-dependent (systemd 022 => 0755 => connect needs write => root-only) — NOT reported (not provably world-connectable). event_stream keepalive/backpressure verified sound.

FINDINGS: 1) export_all_sessions bulk export under global lock (the #2962 residual for a different verb+blocking-mechanism); 2) syn_cookie_master_key serialized into world-readable state.json; 3) write_state failure masks a successful control op; 4) wait_for_binding_settle 2s under the global lock (forwarding/queue/binding); 5) redundant refresh_status 2-3x per mutating request.

### `rs-wg-coord`  — 5 kept / 5 raw

Read in full: wg/handshake.rs, wg/session.rs, wg/timers.rs, wg/handshake_session.rs, wg/tai64n.rs, wg/peer.rs, wg/counters.rs, wg/engine.rs (encap/decap hot paths + reconcile/install/accessors), coordinator/wg_control.rs (control loop, dispatch_inbound, attempt machine, keepalive, bind/recvmsg), coordinator/tunnel_supervision.rs (spawn/stale-prune/reuse), forwarding_build/wg.rs (engine (re)build), coordinator/status.rs (WG status rows), and skimmed event_emit.rs. Cross-checked docs/wireguard-interop.md and the #1865/#1709/#1432/#1888 plan docs.\n\nLenses: (a) correctness/security — found the 2-slot immediate-promotion egress-blackhole (finding 1), missing responder TAI64N anti-replay (finding 2), MAC1-only responder crypto flood (finding 3); (b) vSRX/WG parity — findings 1-3 are all reference-WG parity gaps (3-slot keypairs, §5.4.4 anti-replay, cookie/MAC2); (c) perf/latency — finding 3 (single control-thread crypto saturation); (d) modularity/robustness — finding 5 (predicate/ordering coupling); (e) test-coverage — finding 4 (no rekey-egress-continuity test).\n\nLow-level invariants checked and found SOUND (negative results): ReplayState RFC-6479 bitmap (in-order/gap-fill/edge/jump arms + definitely_out_of_window bound `c+64<=highest` matches `age>=64`) is correct and well-tested; tx_counter fetch_update stops at REJECT_AFTER_MESSAGES without advancing; TAI64N encode/whiten/carry-at-1e9 and strict-monotonic clock are correct and KAT-pinned; encap MaybeUninit staging soundness is properly justified; decap ShortRecord guard (ciphertext<TAG) closes the snow underflow; per-session replay windows are correctly independent across current/previous keypairs; endianness at wire boundaries (LE sender/receiver index, BE TAI64N) is correct; counter reason-mapping is exhaustive and tested; ArcSwap PeerTable publish + reconcile_lock serialization of reserve/install/expire is race-free for the demux map; recvmsg cmsg buffer over-alignment (#2334) is fixed.\n\nDISCARDED as duplicates / fixed-at-HEAD: link-local sin6_scope_id (#2995 CLOSED, fixed via sockaddr_storage_to_socketaddr); keepalive-storm give-up pacing (#2961 CLOSED, note_t8_attempt give-up stamp present); stale outer_mtu capture (#2921 CLOSED, outer_mtu_changed restart present); per-peer PTB MTU (#2845), outer-source resolution (#2837/#2701), peer-table snapshot atomicity (#2836, PeerConfig immutable bundle present), AEAD padding decap (#2910), dup AllowedIPs prefix (#2445), busy-poll→poll(2) (#1889, poll loop present), control-thread/port leak on removal (#1866, reconcile pending-drain present), engine>2000 LOC split (#2158/#1441 done). coordinator/mod.rs control-socket starvation + snapshot_refresh generation ordering (prior-findings.md lines 583-586,675) are in files outside this module's non-test scope and already recorded.\n\nnegative: event_emit.rs is a shared RT_FLOW/screen emit file (not WG-specific); its casts (ifindex clamp to i32::MAX, owner_rg_id clamp to i16) are saturating/clamped, timestamps monotonic-guarded — no defect surfaced within this module's remit."

### `x-default-deny`  — 5 kept / 6 raw

FILES READ (HEAD ddf9f58): pkg/config/compiler_security.go (compileSecurity, compilePolicies, compilePolicy, resolveZoneLocalAddressBooks, parseHostInboundNode, compileScreen, default-policy/default-policy-log parsing, applyCollapsedDenyModifiers); pkg/dataplane/userspace/policies.go (buildPolicySnapshotsWithSchedulerStateAndFeeds, buildOneRuleSnapshot, walkPolicyRuleSlots, addrRepresentable/nameRepresentable/nameRepresentability, classifyPolicyAddresses, buildAddressBookTableWithFeeds, expandBookNameRecursive, normalizeAnyInCIDRs, policyRuleInactive); pkg/dataplane/userspace/zones.go (BuildZoneHostInboundViews, AddresslessEnforcingZones, buildZoneSnapshots, unionHostInboundTokens, buildInterfaceHostInboundMap); pkg/dataplane/userspace/capabilities.go (expandUserspacePolicyApplications, resolveUserspaceApplicationNames); pkg/dataplane/userspace/interfaces.go (per-interface host-inbound override stamping); pkg/dataplane/userspace/maps_sync.go (buildDesiredLocalAddressSets, syncLocalAddressMapsLocked); userspace-dp/src/protocol/security.rs (PolicyRuleSnapshot, ScreenProfileSnapshot, ZoneHostInbound DTO wire); userspace-dp/src/policy.rs (parse_policy_state_with_counters, evaluate_policy_result_l3_aware, evaluate_junos_host_policy_l3_aware, try_match_rule, CompiledApplications::matches, parse_legacy/v3_address_set, parse_book_prefix_into, PolicyState, sentinels); userspace-dp/src/afxdp/forwarding/host_inbound.rs (classify_system_service/protocol, host_inbound_admits[_iface], is_icmp_host_inbound_global_accept, tests); userspace-dp/src/afxdp/types/forwarding.rs (ZoneHostInbound::admits); userspace-dp/src/afxdp/poll_descriptor/mod.rs (LocalDelivery host-inbound->lo0->junos-host ordering, transit evaluate_policy_result_with_icmp, deny_reply_and_emit); userspace-dp/src/afxdp/poll_descriptor/filter.rs (host_inbound_gated_lo0_action); userspace-dp/src/afxdp/event_emit.rs (emit_policy_deny_event); userspace-xdp/src/lib.rs (is_local_destination -> cpumap_or_pass shunt); pkg/daemon/daemon_nft.go (chain priorities, host-inbound + lo0 chains only — no junos-host mirror); pkg/config/compiler.go/zoneid.go (StableZoneID, base DefaultPolicy=Deny). LENSES: (a) correctness/security — Findings 1,2,3; (d) refactor/dead-code — Findings 4,5; (e) test gaps — Finding 6; (b) parity woven through 1,3,5,6; (c) perf — deny-event amplification noted in 3. NEGATIVE RESULTS (checked, sound, NOT reported): default-policy unknown-value fail-open is safe (base config initializes DefaultPolicy=PolicyDeny, compiler.go:1872, and unknown enum rejected by schema); junos-host id (65534)/StableZoneID(max 65533) can never collide (verified ZONE_ID_RESERVED_MIN math); zone-pair vs from-any/to-any/both-any/global precedence merge is correct (unique indices per bucket, two-pointer ascending); application 'any' overlap collapses to match-any in both expansion and Span count consistently; *-excluded empty-set fail-closed handling parity holds across same-family + NAT64 arms; scheduler nil-map fail-closed is transient-safe (initial apply seeds state before first build). DISCARDED AS DUPLICATES: intrazone default-permit missing (prior-findings 70-95, heavily tracked); policy.rs module split (prior-findings 260); from-zone junos-host host-originated not enforced (#3611 OPEN, known-gaps 12); to-any/both-any/global not consulted on host path (known-gaps 10 — and it is arguably correct vSRX); host-inbound system-services 'all' packet-wide admit (#3226 OPEN); ICMPv6 Redirect global admit (known-gaps 21); ident-reset drop-vs-reset (#3310, known-gaps 39); addressless-zone transient fail-open (#3698 accepted); flowless LocalDelivery bypass (#3292 CLOSED, code now gates it); junos-host permit-log/policy_id-0 discard (#3706 OPEN, prior-findings 250/636); AppID overlap precedence + linear scan (prior-findings 13/14); unknown-zone id-0 guard (#3110/#3402/#3355 CLOSED)."

### `x-hpc`  — 6 kept / 6 raw

MODULE x-hpc (cross-cutting low-level invariant sweep of the userspace-dp hot path) at HEAD ddf9f58701eff.

READ (files + key functions):
- afxdp/worker/loop_body/mod.rs (full 1449 lines: worker_loop per-tick orchestrator, publish cadence, delta drain/resync macros, count_local_session_expiries), loop_body/setup.rs listing, worker/telemetry.rs, worker/tx_pipeline.rs headers, worker_runtime.rs publish/seqlock, cold_path_hist.rs publish/snapshot seqlock.
- afxdp/poll_stages.rs (stages 5-11 + SYN-cookie ACK stage; lines 1-720 production, 717+ tests).
- session/lookup.rs (full), session/wheel.rs (full), session/entry.rs (types), session/mod.rs delta ring constants.
- afxdp/frame/mod.rs (lines 1-1260: v6_rel_l4_offset, DSCP rewrite, rewrite_prepare_eth/classify_in_place_l2_rewrite, rewrite_apply_v4/v6, apply_nat_ipv4/ipv6, apply_nat_port_rewrite, adjust_l4_checksum_port, enforce_expected_ports*, restore_l4_tuple_from_meta), frame/checksum.rs (scalar/AVX2 sum, zero-checksum predicates), frame/inspect.rs try_parse_metadata (read_unaligned — correct).
- afxdp/umem/mod.rs (full: BindingLiveState 100+ atomics, MPSC admission gate, session-delta buffer, bucket_index_for_ns), umem/profile.rs (full: #746 cacheline-isolated owner/peer telemetry + const asserts).
- afxdp/forwarding/mod.rs (classify_metadata, canonical_route_table, lookup_forwarding_resolution_* v4/v6, ECMP hash/select_route_next_hop, cached_flow_decision_valid, prefer_local_forward_candidate_for_fabric_ingress, lookup_neighbor_entry, IcmpTeRateLimiter).
- afxdp/mpsc_inbox.rs (full Vyukov ring), afxdp/sharded_neighbor.rs (epoch protocol), afxdp/flow_cache.rs (stamps/epochs), afxdp/poll_descriptor/flow_cache_hit.rs (hit-path guards), poll_descriptor/mod.rs flow-cache population site, afxdp/icmp_ratelimit.rs (full, #2955 GCRA), afxdp/ha.rs update_ha_state (rg_epochs bump-before-publish), types/shared_cos_lease/backlog.rs (full) + vtime.rs/rotate_epoch_v8.rs orderings, cos/queue_service/mod.rs surplus budget callers, cos/tx_completion.rs consume sites, xsk_ffi.rs ring wrappers (RingRx/RingTx/ReadRx/WriteTx), docs/engineering-style.md hot-path rules.

LENSES: (a) correctness/concurrency — findings 1,2; (c) performance/latency — findings 3,4,5; (d) refactor debt — finding 6 (+3's fix); (e) test gaps — folded into findings 1,2 (no concurrency test for the backlog bucket; no interleaving test for the epoch stamp). (b) vSRX parity: not applicable to this low-level sweep; nothing new beyond known-gaps.md.

DISCARDED AS DUPLICATES (corpus refs):
- WorkerStats/telemetry counters share cache lines -> prior-findings:670 (worker/telemetry.rs) — dup; telemetry.rs header even notes Phase 2 may add repr(align(64)).
- SessionKey/SessionEntry missing #[repr(align(64))] -> prior-findings:618 — dup.
- HA synced-session u32 seq wrap (is_stale_update) -> prior-findings:662 — dup.
- UMEM frame leak on tx-ring push failure -> prior-findings:668 (umem/profile.rs) — dup.
- session/lookup.rs reverse-map mutation -> prior-findings:632 — dup (and at HEAD SessionTable is per-worker &mut, so moot).
- Policy hit-counter non-atomic pair -> #3451 CLOSED; generated-error split-atomic -> #2955 CLOSED (fix verified present in icmp_ratelimit.rs incl. hammer test); forwarding_build unchecked narrowing -> #2410 CLOSED.
- Oversized poll loop / poll_descriptor god-file -> prior-findings:55; IPsec-passthrough-vs-host-inbound + zeroed ifindexes -> prior-findings:38/48/62; next-table canonicalization/cycle/denylist/LocalDelivery-ifindex0 in forwarding/mod.rs -> prior-findings:594/595/601/604/607 — all dups, not re-reported.

NEGATIVE RESULTS (checked clean, with reasoning):
- MpscInbox (Vyukov): seq Acquire loads, Release publish, Relaxed head CAS, single-consumer pop contract, CachePadded head/tail — textbook-correct; Drop drains safely.
- Seqlocks: worker_runtime window_gen (AcqRel odd-enter via RMW, Relaxed payload, even-exit) and cold_path_hist cold_window_gen (AcqRel enter, Release exit; reader Acquire s1 + Acquire fence + s2, offset-of asserts vs false sharing) — both correct seqlock idioms.
- rg_epochs protocol (ha.rs:39-72): Release bumps sequenced before ArcSwap rg_runtime.store; worker's ArcSwap Acquire load establishes happens-before, so the Relaxed epoch reads in flow_cache.rs/loop_body are sound.
- session_export_ack: Release store (loop_body:960) paired with Acquire loads in OwnerRgExportWait::wait_and_collect — correct.
- icmp_ratelimit GCRA: single-word TAT CAS, deny-without-mutate, interval round-up, zero-rate opt-out, 2000-trial concurrency test — correct (this is what makes the backlog.rs sibling stand out).
- checksum16 accumulation: u32 partial sum cannot overflow for max-length frames (32K words × 0xFFFF < 2^31); scalar/AVX2 bit-identity asserted by differential tests; RFC 768/8200 zero-checksum predicates single-sourced.
- try_parse_metadata: ptr::read_unaligned with magic/version/length guards — no unaligned-deref UB.
- bucket_index_for_ns branchless math verified at boundaries (0, 1023, 1024, 2^24).
- Session wheel: power-of-two const assert, saturating tick math, FAR_FUTURE clamp — no wrap hazard; flow-cache u16 epoch wrap handled (#1741 sentinel-clear).
- mac_change_epoch u32 wrap: compared with != (equality), so wrap is harmless per se — the defect found is the stamp ordering, not the wrap.
- xsk_ffi rings: peek/release/cancel go through libxdp C bridge (kernel-barrier semantics live there); RingRx::needs_wakeup does a plain raw deref of the mmap flags word but has no production caller (only DeviceQueue/RingTx variants, which use the bridge) — not reported.
- classify_in_place_l2_rewrite VLAN-push descriptor shift (rx_addr-4) overlaps the tail of the already-consumed metadata region only — meta is copied by value at RX; safe.

Candidate found then self-rejected: 'refill_residual_surplus_budget double-credit' — unlike pre-#2955 icmp code, the interval claim IS CAS-protected on last_refill_ns, so pure refill double-credit cannot happen; the reportable defect is the read-then-consume admission race + split-window (finding 2).

### `x-tests-build`  — 8 kept / 8 raw

READ (full or targeted): Makefile (all 402 lines); scripts/image/bake.py (all 659); scripts/image/grub.d/09_xpf; scripts/image/xpf-uefi-slots (first 120); scripts/dist/publish.py (header + gate logic); pkg/dataplane/build-userspace-xdp.sh (all, the #1864 make-generate verifier gate); test/incus/deploy-lib.sh (all); test/incus/cluster-lock.sh (all); test/incus/with-cluster.sh (all); test/incus/cluster-setup.sh (all 1090); test/incus/setup.sh (all 774); test/incus/apply-cos-config.sh (all); test/incus/cluster-env.sh (all); test/incus/loss-userspace-cluster.env; test/incus/test-failover.sh (header + phases); grep sweep of test-ha-crash/double-failover/stress/chained/restart/active-active for lock usage; pkg/cluster/status.go FormatStatus (to verify the "secondary:node0" grep can never match); pkg/upgrade (verify-dataplane usage in kernel_run.go); debian/rules (dh_auto_test override). No .github/workflows/ exists — confirmed no CI.

LENSES: (a) correctness — F1 (rolling-deploy secondary detection dead grep), F4 (sign-before-validate ordering); (b) parity/protocol — F2 (destructive HA smokes bypass the #1875 cluster lock), F5 (standalone deploy missing the #1864 preflight the cluster path has); (c) security/supply-chain — F4, F6, F7, F8 (provenance + unsigned-upstream-checksum); (d) refactor debt — noted but NOT reported as a finding: cluster-setup.sh is a 1090-line monolith mixing env resolution, VM provisioning, VF plumbing and deploy; deploy-lib.sh extraction is the right direction and should absorb the preflight + rolling-order logic so setup.sh/cluster-setup.sh cannot drift (drift is exactly F1/F5); (e) test gaps — F3 plus the coverage assessment below.

COVERAGE-GAP ASSESSMENT (safety-critical paths): policy eval, session install, NAT alloc all live in userspace-dp Rust — 3393 #[test] functions exist (policy_tests.rs, session/, nat/) but NOTHING invokes `cargo test` (grep across Makefile/scripts/debian: zero hits; debian/rules explicitly overrides dh_auto_test to skip) → F3. HA failover is validated only by manual incus scripts (test-failover.sh etc.), which additionally bypass the shared-cluster lock → F2. Commit/rollback: pkg/configstore Go tests run under `make test`; cc-rollback-functional.sh covers commit-confirmed on-cluster. Deploy sha-verify helpers have a real selftest (deploy-lib-selftest.sh via make test-deploy-lib) but it is standalone, not part of `make test`; same for the test/incus/*_test.py harness unit tests — the default gate never runs either.

DISCARDED AS DUPLICATES / KNOWN: (1) standalone deploy not pushing xpf-userspace-dp — #1962/#2162 CLOSED and HEAD has push + sha-verify (setup.sh:632-638); (2) stale #1917 ExecStart pin / dangling sbin symlink deploy hazards — #2176 CLOSED, HEAD reconciles via deploy-lib.sh; (3) deploy wiping CoS config — documented accepted gotcha (CLAUDE.md, apply-cos-config.sh exists for it); (4) `go vet` scoped to pkg/flowexport only — explicitly documented decision in Makefile:71-77 (#2224); (5) gcc-15 cluster-deploy link failure — #3595 CLOSED; (6) apply-cos-config post-commit shaper verify flake — #2575 CLOSED; (7) test env Debian/Ubuntu drift — #1943 CLOSED, HEAD aligned; (8) multi-firewall gateway-ARP hazard — #1992 CLOSED, assert_sole_dataplane_owner present; (9) make generate verifier-gate weaknesses — #1864 CLOSED and build-userspace-xdp.sh is sound (verify-then-install, toolchain+bpf-linker pins, rc=99 fail-closed, no unverified-install path; negative result); (10) cluster-lock/with-cluster protocol — heavily reviewed (Codex r1/r2, AGY), re-derived the append-only open, dev:ino revalidation, split-mutex fd-9 probe, ancestry walk: no defect found (negative result); (11) bake.py kernel purge/hold/single-kernel logic and 09_xpf/xpf-uefi-slots A/B substrate — r1-r5 AGY/Codex hardened; label-dedup, wrong-path deletion, locale pinning, $cmdpath selector all check out (negative result); (12) apply-cos-config.sh stale comment about `|| true` after deletes (no such suffix exists in the heredoc) — cosmetic, not reported.

## 6. Findings

Grouped by confidence tier (campaign requirement), most-severe first within
each tier. IDs `F-NNN` are stable and referenced by the issue split in §7.

## 6.1 High-confidence findings (149)

> Directly evidenced bugs — verifier re-derived the defect from source and (for High severity) an independent repro-trace agent reproduced the trigger.
> Severity mix: 19 high · 74 medium · 56 low.

#### F-001 · Hierarchical single-name `source-prefix-list <name>;` leaf is silently dropped from filter terms — term compiles unscoped with a clean strict commit

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-config-ifaces-cos-fw`  ·  **Location:** `pkg/config/compiler_firewall.go`:287
- **Labels:** `bug`, `security`

```
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

**Runtime trace**

Operator loads a hand-authored hierarchical config (load merge / file load): `term t1 { from { source-prefix-list mgmt-hosts; } then discard; }`. The parser produces a LEAF Node{Keys:["source-prefix-list","mgmt-hosts"], IsLeaf:true} with NO children (the flat-set path via SetPath produces the container+child shape, which is why set-syntax works). compileFilterFrom's case matches the keyword so the default UnknownFrom arm never fires, but the loop body iterates only child.Children (empty) — term.SourcePrefixLists stays empty and nothing is recorded for the strict gate. PROBE AT HEAD: CompileConfigLenient AND strict CompileConfig both succeed ("strict compile OK (commit would succeed)"), term t1 compiles with srcPrefixLists=[] unknownFrom=[]. The #2506 cross-ref validator never fires (no ref exists) and the dataplane snapshot builds the term with NO source constraint: the discard term now drops ALL traffic; with an accept action it permits every source it was authored to scope (fail-open). Same defect in the destination-prefix-list arm at line 296.

**Why it matters** — This is exactly the silent-constraint-drop class the project treats as commit-reject-worthy (#3205/#3307 doctrine): a security scoping statement vanishes with a clean commit and no warning, corrupting filter semantics in whichever direction (over-drop or over-permit) the term's action implies. The set-command path works, so the bug only bites imported/hand-edited configs — the least-tested, highest-blast-radius path.

**Fix direction** — In the source/destination-prefix-list cases, also read the leaf spelling: when len(child.Keys) >= 2, take child.Keys[1] as the name (and Keys[2]=="except"), mirroring firewallMatchValues' dual-shape contract; alternatively record the empty-body case on term.UnknownFrom so validateFilterFromMatchStrict fails the commit closed. Add a hierarchical-shape regression test alongside the existing flat-set tests.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for 'prefix-list': #2506 (dataplane snapshot dropped the refs — fixed, and my probe shows the TYPED refs never get populated here, a compile-side AST-shape hole, different mechanism), #3359 (mixed except folding), #2689/#2642 (policy-options prefix-list, different subsystem). No prior finding covers the hierarchical single-name leaf shape in compileFilterFrom.

---

#### F-002 · Deterministic NAT (CGNAT) is un-configurable via flat-set commands: sibling `port deterministic ...` leaves overwrite each other and `host address` is never parsed from Keys — the project's own documented quick-start config fails commit

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-config-nat`  ·  **Location:** `pkg/config/compiler_nat.go`:1104
- **Labels:** `bug`, `test-gap`

```
				// Flat set: "port deterministic block-size 2016"
				if len(prop.Keys) >= 2 && prop.Keys[1] == "deterministic" {
					detCfg := &DeterministicNATConfig{}
					for i := 2; i < len(prop.Keys); i++ {
						if prop.Keys[i] == "block-size" && i+1 < len(prop.Keys) {
							if n, err := strconv.Atoi(prop.Keys[i+1]); err == nil {
								detCfg.BlockSize = n
							}
						}
					}
...
					pool.Deterministic = detCfg
```

**Runtime trace**

Input: the exact set commands from docs/deterministic-nat-cgnat.md:18-23 (`set security nat source pool CGNAT-POOL port deterministic block-size 2016` + `set ... port deterministic host address 100.64.0.0/25`). (1) SetPath (ast_edit.go:151-165): `port` is not in the pool schema (schema_security.go:313 declares only `persistent-nat`), so EACH set line becomes a separate sibling leaf under the pool node: Keys=[port,deterministic,block-size,2016] and Keys=[port,deterministic,host,address,100.64.0.0/25]. (2) compileNATSource iterates pool children; both leaves hit the flat branch at compiler_nat.go:1104. The flat branch scans Keys ONLY for `block-size` (1106-1111); `host address` tokens on Keys are never read (host is read only from prop.Children at 1114-1127, which are empty in flat form). (3) Each leaf assigns `pool.Deterministic = detCfg` (line 1128), so the LAST leaf wins with a partially-empty config: block-size-last order leaves HostAddress="", host-last order leaves BlockSize=0. (4) Validation at 1231-1235 then hard-rejects: reproduced both `deterministic block-size must be > 0` and `deterministic host address required` (empirically, via ParseSetCommand+SetPath+CompileConfig). A single combined line (`port deterministic block-size 2016 host address X`) also fails: host still never read from Keys. Only a hierarchical `port { deterministic { block-size; host address; } }` block (load override) compiles. There are ZERO config-compile tests for deterministic NAT (grep block-size *_test.go: none), which is why this has gone unnoticed.

**Why it matters** — A headline CGNAT feature (deterministic port-block allocation for ISP compliance logging) cannot be configured through the CLI/set interface at all — the documented operator procedure produces a hard commit error, and the error message (`block-size must be > 0`) actively gaslights the operator who just set block-size 2016. Note the doc example is also self-inconsistent (100.64.0.0/22 = 1024 hosts vs 128 blocks fails the capacity validator even hierarchically).

**Fix direction** — In compileNATSource, merge deterministic fragments instead of overwriting: reuse (or lazily create) pool.Deterministic across sibling `port` leaves, and parse `host address <X>` from the flat Keys scan (look for `host`,`address`,value triple) in the same loop as `block-size`. Add compile tests for both set-line orders plus the single-line form, and fix the /22 example in docs/deterministic-nat-cgnat.md.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for 'deterministic', 'block-size', 'cgnat', 'natpool', 'compiler_nat': only #2823/#3193 (persistent-nat permit modes), #2079 (pool-utilization-alarm), #3049 (subnet pool expansion) — none touch the deterministic flat-set parse. recent-commits.txt has no deterministic-NAT commits. Nearest relative is the general #2419 multi-leaf collapse class, but this is a distinct overwrite-across-sibling-leaves mechanism plus a never-parsed keyword, not a bracket-list collapse.

---

#### F-003 · `then destination-nat off` is accepted at commit but silently dropped — DNAT exemption rules fail open and the 'exempted' traffic is still translated by later rules

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-config-nat`  ·  **Location:** `pkg/config/compiler_nat.go`:1587
- **Labels:** `bug`, `security`, `vsrx-parity`

```
				for _, t := range thenNode.Children {
					if t.Name() == "destination-nat" {
						if len(t.Keys) >= 3 && t.Keys[1] == "pool" {
							rule.Then.Type = NATDestination
							rule.Then.PoolName = t.Keys[2]
						} else if poolNode := t.FindChild("pool"); poolNode != nil {
							rule.Then.Type = NATDestination
							rule.Then.PoolName = nodeVal(poolNode)
						}
					}
				}
```

**Runtime trace**

Junos DNAT rule actions are `then destination-nat (off | pool <name>)`; `off` is the standard way to exempt a subset (e.g. VPN/hairpin sources) from a broader translation. Input: `rule EXEMPT match source-address 192.0.2.0/24, destination-address 203.0.113.10/32, then destination-nat off` followed by `rule ALL match destination-address 203.0.113.10/32 then destination-nat pool DP`. (1) setSchema (schema_security.go:396-400) declares only `pool` under destination-nat; `off` is an unknown keyword, and SchemaValidate's opt-in gate accepts unknown keywords by design (schema_walk.go) — empirically verified: SchemaValidate + CompileConfig both pass green. (2) compileNATDestination's then-parse (compiler_nat.go:1587-1594) recognizes only `pool`, so rule EXEMPT compiles with Then.Type=0, PoolName="" (verified: thenType=0 pool=""). (3) buildDestinationNATSnapshotsWithFeeds skips it entirely: pkg/dataplane/userspace/nat.go:681 `if rule == nil || rule.Then.PoolName == "" { continue }`. (4) The Rust DnatTable never sees the EXEMPT rule, so packets from 192.0.2.0/24 to 203.0.113.10 match rule ALL and are translated to pool DP — the operator's exemption is inverted into a translation, with a green commit and no warning. Source NAT gets this right (`off` is modeled at schema_security.go:362 and compiled at compiler_nat.go:1384-1398, and the Rust side honors Off before translating).

**Why it matters** — Fail-open on a security-relevant NAT exemption: traffic the operator explicitly excluded from DNAT is silently steered to the DNAT backend. On a firewall this can bypass intended routing/policy (e.g. management or VPN traffic redirected into a DMZ server) with zero operator signal. Also a direct vSRX parity break: docs/feature-gaps.md advertises 'source-nat off bypass' and 'exemption rules' but the DNAT counterpart neither works nor is rejected.

**Fix direction** — Implement `off` for DNAT end-to-end (add to setSchema, compile to Rule.Then.Off, carry an `off` flag in DestinationNATRuleSnapshot, terminate DNAT lookup on match in destination.rs — mirroring the SNAT Off path). If deferring the dataplane work, at minimum hard-reject `then destination-nat off` (and any DNAT rule with no recognizable then-action) at strict commit like validateDNATRuleSetToScopeAST does for the `to` scope.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'destination-nat off', 'nat off', 'exempt', 'dnat': #3444 (DNAT `to` scope silently dropped — same family, different clause: that gate covers rule-set scope, not the rule then-action), #3450 (DNAT pool value validation), #3434 (empty application wildcard). No issue or finding covers the `off` action; feature-gaps.md/vsrx-gaps.md do not list it as a known gap.

---

#### F-004 · DeletePath on a bracket-list (multi-value) leaf silently deletes the ENTIRE list when given the first member, and errors on any other member — filter/policy match constraints vanish (fail-wide)

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-config-parse`  ·  **Location:** `pkg/config/ast_edit.go`:492
- **Labels:** `bug`, `vsrx-parity`, `security`

```
// removeMatchingNode removes the first node whose keys match targetKeys
// (using prefix matching) from the nodes slice.
func removeMatchingNode(nodes *[]*Node, targetKeys []string) error {
	for i, n := range *nodes {
		if keysMatch(n.Keys, targetKeys) {
			*nodes = append((*nodes)[:i], (*nodes)[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("path not found: no node matching %q", strings.Join(targetKeys, " "))
```

**Runtime trace**

Config: `set firewall family inet filter F term T from protocol [ tcp udp icmp ]` -> lexer strips brackets, SetPath #2419 absorb creates ONE leaf Keys=[protocol tcp udp icmp]. Operator runs `delete firewall family inet filter F term T from protocol tcp` (Junos semantics: remove just tcp from the leaf-list). Runtime path: Store.Delete -> tree.DeletePath -> deletePath consumes schema leaf {args:1,multi:true} into nodeKeys=[protocol,tcp], i>=len(path) -> removeMatchingNode(current, [protocol,tcp]) -> keysMatch does PREFIX matching, leaf Keys=[protocol,tcp,udp,icmp] starts with [protocol,tcp] -> the WHOLE leaf is removed. Empirically confirmed (probe): after `delete ... protocol tcp`, FormatSet is empty — udp and icmp constraints silently deleted too; the term now has no `from protocol` and matches ALL protocols, so a discard/accept term applies to traffic it was never meant to touch. Conversely `delete ... protocol udp` (non-first member) returns `path not found: no node matching "protocol udp"` because prefix matching only sees Keys[1]=tcp — non-first members are undeletable without deleting the whole term. Same defect for every multi:true leaf (policy `then log`, host-inbound lists, bgp export, policy-statement from protocol, ...).

**Why it matters** — An operator narrowing a firewall filter or policy match by removing one protocol/value instead silently removes the entire match dimension at the next commit — a fail-wide change on a production security appliance that the diff shows only if the operator inspects it carefully; on vSRX the identical command removes exactly one list member.

**Fix direction** — In deletePath, when childSchema is a multi leaf, locate the leaf whose Keys CONTAIN the requested value(s) and remove only those values from Keys (deleting the node only when no values remain); require an exact-values or bare-keyword path to delete the whole leaf, mirroring Junos leaf-list delete semantics. Add a bracket-list delete corpus test alongside the #3703 set-side tests.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for bracket/list/multi/collapse/delete: #2419, #3703, #2630, #2689, #2702, #3673 and prior findings all cover the SET/compile side (values dropped when reading or building the tree). No issue or finding covers DELETE semantics on an already-collapsed multi-value leaf; deletePath/removeMatchingNode prefix over-deletion is a new mechanism.

---

#### F-005 · quoteKey never escapes backslashes but the lexer interprets \n and \\ inside quoted strings — values containing backslashes corrupt on every Format->Parse round-trip (HA config sync, rollback files)

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-config-parse`  ·  **Location:** `pkg/config/ast.go`:78
- **Labels:** `bug`, `security`, `ha`

```
func quoteKey(s string) string {
	if s == "" {
		return `""`
	}
	for i := 0; i < len(s); i++ {
		if !isIdentChar(s[i]) {
			// Escape any internal quotes.
			return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
		}
	}
	return s
}
```

**Runtime trace**

Operator commits `set security ike policy P pre-shared-key ascii-text "aX\\nZ9"` -> readString unescapes \\ -> tree value `aX\nZ9` (literal backslash+n, no control chars, passes #1798 strict commit). HA sync: pushConfigToPeer (daemon_ha_sync.go:336) sends d.store.ShowActive() = active.Format(); formatNodes -> QuotedKeyPath -> quoteKey emits "aX\nZ9" WITHOUT re-escaping the backslash. Standby: handleConfigSync -> SyncApply -> NewParser -> readString maps the `\n` byte pair to a REAL NEWLINE (lexer.go:207) -> value `aX<LF>Z9` -> #1798 lenient scrub replaces it with a space. Empirically confirmed (probe): psk formatted "aX\nZ9" reparses to "aX\nZ9" with a literal newline, then SanitizeTreeControlChars yields `aX Z9` with warning `security ike policy P pre-shared-key ascii-text aX Z9`. Standby now holds a silently different PSK -> IKE authentication fails only after failover. Same corruption hits rollback: saveRollbackFiles persists Format() text (store_commit.go:537) and loadRollbackHistory re-parses it (line 616), so `rollback 1` restores the newline-corrupted value and the next STRICT commit is rejected by validateNodesControlChars with a baffling control-character error the operator never typed. Any value containing `\\` also silently collapses to `\` on round-trip (descriptions with Windows/UNC paths, syslog match regexes, secrets).

**Why it matters** — Format()->Parse() is load-bearing on two production paths (HA config sync and rollback history); an asymmetric escape grammar silently diverges the standby's config from the primary's — including IKE pre-shared keys — and poisons rollback slots into uncommittable states.

**Fix direction** — Make quoteKey escape `\` as `\\` (and force-quote any key containing a backslash) so serializer and readString are inverse functions; add a property/round-trip test that Format->Parse is identity over keys containing \\, \n pairs, and quotes.

**Not a duplicate** — Searched issues/prior findings for backslash/escape/round-trip/quote: #1798 is the INVERSE defect (operator-injected \n escape producing control chars — its 3 defense layers are all present at HEAD); #2126 is PSK double-quote breakage in the swanctl RENDER layer (quoteKey does escape quotes). No issue or finding covers the serializer failing to escape literal backslashes so the AST round-trip corrupts values.

---

#### F-006 · Duplicate inner `match`/`then` blocks in one security policy are silently dropped by the compiler AND bypass every policy strict gate (#3113/#3114/#3115/#3141/#3044/#3043) — fail-open reachable via `load override`

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-config-policy`  ·  **Location:** `pkg/config/compiler_security.go`:706
- **Labels:** `bug`, `security`, `vsrx-parity`, `config-fail-open`

```
	thenNode := polInst.node.FindChild("then")
	if thenNode != nil {
		for _, t := range thenNode.Children {
			switch t.Name() {
			case "permit":
				pol.Action = PolicyPermit
				pol.terminalActions = append(pol.terminalActions, PolicyPermit)
```

**Runtime trace**

Input: operator runs `load override <file>` where the hierarchical file has a policy with TWO `match` blocks and/or TWO `then` blocks, e.g. `policy p { match {src any; dst any; app any;} match {dynamic-application junos:FACEBOOK;} then {permit;} then {deny;} }`. (1) parser.go parseStatements APPENDS each block as a sibling Node under policy p (it never merges same-key hierarchical siblings — the exact premise of the #3562/#3566 fixes). (2) LoadOverride (configstore/store_command.go:186) sets s.candidate = the raw tree verbatim, preserving both sibling match/then nodes (unlike LoadMerge which flattens through set-commands). (3) `commit` → store_commit.go CommitWithDescription → compileTree → compileTreeStrict → CompileConfig → compileExpanded. (4) compileSecurity→compilePolicies→compilePolicy: line 652 `matchNode := polInst.node.FindChild("match")` returns only the FIRST match block; line 706 `thenNode := ...FindChild("then")` returns only the FIRST then block. The second match (dynamic-application) and second then (deny) are never read. terminalActions gets only [PolicyPermit], so the #3043 conflicting-terminal-action gate sees no conflict; Action=PolicyPermit. (5) The strict AST gates that were supposed to reject the L7 leaf ALSO only inspect the first block: validatePolicyMatchLeavesStrict checkPolicy (compiler_policy_match.go:210 `matchNode := polNode.FindChild("match")`), validatePolicyThenPermitStrict/RejectStrict/DenyStrict (compiler_policy_then.go:101/256/458 `thenNode := polNode.FindChild("then")`), and validatePolicyRequiredMatchStrict (compiler_policy_missing_match.go:110). RUNTIME-CONFIRMED: the dynamic-application config compiled with NO error (#3113 bypassed, L7 constraint dropped → permit-all-apps); the permit-then-deny config compiled to Action=PolicyPermit (operator's deny silently discarded). Result: the committed policy is broader than authored — a security fail-open.

**Why it matters** — On a security appliance an unsupported/unimplemented match constraint or a conflicting terminal action that is silently discarded turns a constrained rule into an over-broad one. The #3113/#3114/#3044 gates exist specifically to REJECT such fail-opens at commit; they are defeated by the same duplicate-sibling-block mechanism the #3562/#3566 gates were written to defend against, one AST level deeper. `load override` of a hierarchical config is a standard operator/automation workflow, so this is reachable in normal operation, not a contrived edge case.

**Fix direction** — Make compilePolicy and all five gate checkPolicy closures iterate ALL `match` and ALL `then` sibling nodes (FindChildren, not FindChild) and either (a) reject a policy carrying more than one match/then block at commit (simplest, Junos-parity since Junos merges them so duplicates indicate a load-override anomaly), or (b) union every match/then block's children before the switch. Factor the ALL-blocks iteration into one shared helper so the compiler and the gates cannot disagree — the FindChild-first-block pattern is currently copy-pasted across six call sites.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for duplicate match/then, first match block, inner block, 3562, 3566. #3562 fixed duplicate TOP-LEVEL security{}/policies{} blocks and #3566 fixed flow/traceoptions + log/stream sub-blocks — both by descending with forEachChild at the security/policies/flow/log CONTAINER level. Neither touched the per-policy leaf readers: compilePolicy and every gate's checkPolicy still call FindChild("match")/FindChild("then") which take only the first sibling. This is the INNER-block residual in a genuinely new shape (a duplicate match/then WITHIN one policy node), reached by the identical parser-appends-siblings mechanism #3562/#3566 accept as real. #3473 (duplicate policy NAMES) and #2642 (routing policy-term multi-match) are different subsystems/mechanisms.

---

#### F-007 · Routing-instance kernel table IDs are positional — deleting/reordering one instance renumbers the rest and forces delete+recreate of unrelated live VRF devices

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-config-routing-services`  ·  **Location:** `pkg/config/compiler_routing.go`:276
- **Labels:** `bug`, `performance`, `refactor`

```
func compileRoutingInstances(node *Node, cfg *Config) error {
	// Auto-assign VRF table IDs starting from 100
	tableID := 100

	for _, child := range node.Children {
		if child.IsLeaf || len(child.Keys) == 0 {
			continue
		}
		instanceName := child.Keys[0]
		ri := &RoutingInstanceConfig{
			Name:    instanceName,
			TableID: tableID,
		}
		tableID++
```

**Runtime trace**

Config declares routing-instances A, B, C in order → TableIDs 100/101/102; kernel holds vrf-A(100), vrf-B(101), vrf-C(102) with enslaved interfaces, FRR `vrf` stanzas, PBR rules and dataplane `<ri>.inet.0` tables keyed to those IDs. Operator runs `delete routing-instances A` + commit. compileRoutingInstances re-walks the remaining children: B→100, C→101. VRF reconcile (pkg/routing/vrf.go:231-249): vrf-B current table 101 != desired 100 → 'VRF table ID mismatches desired, recreating' (vrf.go:240) → the vrf-B netdev is DELETED and recreated: all enslaved interfaces are released, every route in table 101 is flushed, sockets bound to the VRF break (the #844 orphaned-listener class), FRR neighbors in that VRF flap; same again for vrf-C. Two routing instances the commit never touched take a forwarding outage. The same renumber fires if an operator inserts a new instance block ABOVE existing ones in a loaded config file.

**Why it matters** — This is exactly the positional-identity defect class this project has already had to fix four times (#3075 zone IDs, #3322 policy counter handles, #1873 tunnel endpoint IDs, #1956 NIC naming) — production traffic through untouched VRFs blackholes mid-commit, and on an HA pair both nodes churn simultaneously since config-sync ships the same text.

**Fix direction** — Derive TableID as a stable function of the instance NAME (hash into a reserved band with commit-time collision gate, mirroring StableTunnelEndpointID/StableZoneID), or persist name→table allocations in the configstore so existing instances never renumber; keep the RPM probe-band collision check (compiler_services.go:330) against the new allocator.

**Not a duplicate** — Grepped 'table id', 'renumber', 'positional', 'vrf recreate' in issues-all.txt/prior-findings.md: #3075/#3322/#1873/#1956 fixed the class for zones/policies/tunnels/NICs; #844 is a downstream symptom (listener orphaned by VRF delete+recreate at startup). No issue or prior finding covers routing-instance TableID assignment; #3731 (nearest routing issue) is about netlink error swallowing in rib-group/next-table Apply, a different mechanism.

---

#### F-008 · qualified-next-hop `preference`/`metric` are schema-declared but silently dropped by the compiler — Junos floating static route becomes active ECMP over the backup path

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-config-routing-services`  ·  **Location:** `pkg/config/compiler_routing.go`:222
- **Labels:** `vsrx-parity`, `bug`

```
			case "qualified-next-hop":
				nh := NextHopEntry{}
				nh.Address = nodeVal(prop)
				// Check for "interface <name>" among remaining keys
				for j := 2; j < len(prop.Keys)-1; j++ {
					if prop.Keys[j] == "interface" {
						nh.Interface = prop.Keys[j+1]
					}
				}
				// Also check children for flat set syntax
				if ifNode := prop.FindChild("interface"); ifNode != nil {
					nh.Interface = nodeVal(ifNode)
				}
				route.NextHops = append(route.NextHops, nh)
```

**Runtime trace**

Standard Junos multi-WAN floating static: `set routing-options static route 0.0.0.0/0 next-hop 10.0.1.1` + `set routing-options static route 0.0.0.0/0 qualified-next-hop 10.0.2.1 preference 250`. The schema explicitly offers `preference` and `metric` as qualified-next-hop children (schema_routing.go:86-90), so commit-check accepts and tab-completion advertises them. compileStaticRoutes' qualified-next-hop case (compiler_routing.go:222-235) reads ONLY Address and Interface — the preference child node is ignored, and NextHopEntry (types_routing.go:164-167) has no Preference field to carry it. The two lines merge into one StaticRoute{NextHops:[10.0.1.1, 10.0.2.1], Preference:5}. FRR render (pkg/frr/config_render.go:125-167) emits one line per next-hop with the SAME distance: `ip route 0.0.0.0/0 10.0.1.1 5` + `ip route 0.0.0.0/0 10.0.2.1 5` → FRR installs ECMP → up to half of all traffic egresses the distance-250 cold-standby link while the primary is healthy. On Junos the qualified next-hop carries zero traffic until the primary next-hop dies. (The Rust FIB gets the same collapsed view via the route snapshot.)

**Why it matters** — The floating-static qualified-next-hop is THE canonical Junos backup-uplink pattern; xpf silently load-balances production traffic onto a metered/slow/asymmetric backup path, and NAT/policy asymmetry on the backup path can hard-drop flows — with the config having passed schema validation that explicitly names the dropped knob.

**Fix direction** — Add Preference (and Metric) to NextHopEntry, parse them in both the hierarchical-children and inline-keys branches, and render per-next-hop distance lines in generateStaticRouteInTable (FRR supports per-static distance, giving true floating behavior). Propagate per-NH preference into the dataplane route snapshot or, minimally, exclude higher-preference NHs from the ECMP set.

**Not a duplicate** — Grepped 'qualified', 'static route', 'preference', 'floating': only #98 (HA warmup skips interface-qualified next-hops, closed) and #2390/#2389 (route-LEVEL preference / ECMP collapse at the Go→Rust boundary, both closed) — none cover per-next-hop preference being dropped at the compiler. Module notes list 'static route qualifiers' as in-scope with no tracked issue.

---

#### F-009 · routing-options autonomous-system is parsed but never feeds BGP — canonical vSRX BGP config silently renders no `router bgp` at all

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-config-routing-services`  ·  **Location:** `pkg/config/compiler_routing.go`:11
- **Labels:** `vsrx-parity`, `bug`

```
func compileRoutingOptions(node *Node, ro *RoutingOptionsConfig) error {
	// Parse autonomous-system
	if asNode := node.FindChild("autonomous-system"); asNode != nil {
		if v := nodeVal(asNode); v != "" {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				ro.AutonomousSystem = uint32(n)
			}
		}
	}
```

**Runtime trace**

Operator loads a canonical vSRX config: `set routing-options autonomous-system 65001` (schema-declared, schema_routing.go:108) + `set protocols bgp group ebgp neighbor 10.0.2.1 peer-as 65002`. Commit: compileRoutingOptions stores ro.AutonomousSystem=65001 (compiler_routing.go:11-16); compileProtocols builds BGPConfig with LocalAS=0 — only the `protocols bgp local-as` leaf sets it (compiler_protocols.go:184-189). Repo-wide grep shows ro.AutonomousSystem is consumed ONLY by display code (pkg/grpcapi/server_show_routes_text.go:259, pkg/cli/cli_show_routing.go:882); no validator requires LocalAS. FRR render: pkg/frr/policy_render.go:622 `if bgp != nil && bgp.LocalAS > 0` is false → the entire `router bgp` block (neighbors, AFs, policies) is skipped. Observable: commit succeeds with zero warnings, FRR never starts BGP, no sessions form; the only trace of the operator's intent is `show route summary` printing 'Autonomous system: 65001'. On Junos/vSRX the router AS comes from routing-options autonomous-system (bgp-level local-as is the AS-migration knob), so every straight vSRX config migration hits this. The same drop occurs per-instance: compileRoutingInstances (compiler_routing.go:299-305) copies only StaticRoutes/Inet6StaticRoutes from the instance routing-options, discarding ro.AutonomousSystem.

**Why it matters** — BGP silently absent on a firewall whose committed config fully describes working BGP is a routing outage with no diagnostic — the worst failure mode for a vSRX-parity appliance (peers never come up, default route may vanish, failover paths dead).

**Fix direction** — Fall back to RoutingOptions.AutonomousSystem when BGPConfig.LocalAS==0 (both main instance and per-instance, mirroring Junos inheritance), and add a strict commit check rejecting `protocols bgp` with neighbors when neither local-as nor routing-options autonomous-system is set (Junos errors with 'Autonomous system number required'). Pin with an FRR-render test.

**Not a duplicate** — Grepped issues-all.txt + prior-findings.md for 'autonomous', 'local-as', 'router bgp': only #3754 (event-options wording) and #2963/#2980 (remote-as/router-id render, both assume explicit local-as) — nothing covers routing-options AS inheritance. feature-gaps.md BGP rows (import policy #2490, policy enhancements) do not mention it.

---

#### F-010 · ECMP static route `next-hop [ gw1 gw2 ]` bracket list silently collapses to a single next-hop (canonical Junos ECMP spelling loses multipath)

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-config-schema`  ·  **Location:** `pkg/config/schema_routing.go`:80
- **Labels:** `bug`, `vsrx-parity`, `routing`

```
			"next-hop": {desc: "Next-hop gateway (IP, ip@interface, or interface name)", args: 1, placeholder: "<gateway>",
				keyValueType: ValueIPAddress, keyValueDesc: "next-hop IP address, ip@interface, or interface name",
				keyValueExamples: []string{"192.168.1.1", "2001:db8::1"}, keyValidator: ValidateStaticNextHop,
				children: map[string]*schemaNode{
					"interface": {desc: "Egress interface for this next-hop", args: 1, placeholder: "<interface-name>", children: nil},
				}},
```

**Runtime trace**

Input config (canonical Junos ECMP form, also what `show configuration` displays on a vSRX): `routing-options { static { route 0.0.0.0/0 { next-hop [ 10.0.0.1 10.0.0.2 ]; } } }`. (1) The lexer strips `[`/`]`, so the hierarchical parser emits ONE leaf Keys=["next-hop","10.0.0.1","10.0.0.2"] (the #2419 contract). (2) compileStaticRoutes (compiler_routing.go:197-213) hits `case "next-hop"`: `nh.Address = nodeVal(prop)` reads only Keys[1]="10.0.0.1"; the remaining loop `for j := 2; j < len(prop.Keys)-1; j++` only looks for the literal "interface" keyword, so "10.0.0.2" is silently discarded; exactly one NextHopEntry is appended. (3) SchemaValidate does not object either: next-hop's keyValidator validates only the declared arg span Keys[1:2] (walkSchemaNode, schema_walk.go:317-328), and the extra token is "ignored per the compiler-faithful contract". Empirically confirmed at HEAD: compiled route has next-hops=1 [{Address:10.0.0.1}]. Observable behavior: an imported/loaded vSRX config with ECMP static routes installs a single-path route in FRR and the Rust FIB — traffic that was load-balanced across two gateways all goes to gw1, and if gw1 dies there is no second path (blackhole), with zero commit diagnostics. The flat-set equivalent `set ... next-hop 10.0.0.1 next-hop 10.0.0.2` also mis-nests (the second next-hop becomes an unread child of the first); only two separate `set` lines work.

**Why it matters** — xpf advertises ECMP multipath as a supported feature, and the bracket list is THE canonical Junos spelling for multiple next-hops (it is what Junos itself renders). A firewall/router that silently degrades a redundant default route to single-path changes failover behavior and creates an unnoticed single point of failure.

**Fix direction** — Teach the config layer to land all bracket values: either read the value-tail in compileStaticRoutes (iterate prop.Keys[1:] treating each non-"interface" token as a gateway, mirroring the qualified-next-hop key scan), or restructure the schema/compiler pair so next-hop is a multi value-tail (would need the `interface` modifier handled like the tcp-mss dual-location AST pre-walk). Add a strict-commit rejection for tokens the reader cannot attribute. Extend the #2448 tests with the bracket form.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for 'ecmp', 'next-hop', 'bracket', 'static route'. Nearest: #2389 [CLOSED] 'ECMP static routes collapse to the first next-hop in the Rust FIB' — that was the FIB builder collapsing an already-compiled multi-NH list; this defect is one layer earlier (parser/compiler never produces the second NextHopEntry from the bracket form, so the #2389 fix never sees it). #2448 covered malformed dest/NH silent drops (introduced staticRouteNode), not list collapse. #2419/#3703 fixed bracket collapse on other surfaces; static-route next-hop was never converted.

---

#### F-011 · WireGuard tunnel local identity (listen-port / private-key) never validated at commit — missing/malformed identity commits cleanly and the dataplane silently drops the whole tunnel

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-config-validate`  ·  **Location:** `pkg/config/compiler_validate_wireguard.go`:112
- **Labels:** `bug`, `vsrx-parity`, `commit-apply-split`

```
func validateOneWireguardTunnel(tc *TunnelConfig) error {
	if len(tc.WgPeers) == 0 {
		return fmt.Errorf("tunnel has no peer (a peerless WireGuard tunnel can never handshake; configure at least one `peer <public-key>`)")
	}
	seen := make(map[string]struct{}, len(tc.WgPeers))
```

**Runtime trace**

Operator commits `set interfaces wg0 unit 0 tunnel mode wireguard` + a `wireguard { peer <64hex> { allowed-ips ...; } }` block but omits `listen-port`, or omits/typos `private-key` (e.g. 63 hex chars). Path: parseTunnelWireguard (compiler_interfaces.go:532-545) leaves tc.WgListenPort=0 (absence is unchecked; the schema ValidateInteger(1,65535) on listen-port only fires when the leaf is PRESENT) and stores private-key verbatim (schema_interfaces.go:408 has NO validator for private-key) -> compileExpanded calls validateWireguardPeersStrict (compiler.go:3582) -> validateOneWireguardTunnel checks ONLY tc.WgPeers (zero-peer, dup/malformed pubkey, PSK, endpoint family) and never tc.WgListenPort or tc.WgLocalPrivkeyHex -> commit SUCCEEDS with zero warnings -> snapshot carries WgListenPort=0 / bad WgLocalPrivkeyHex (pkg/dataplane/userspace/tunnels.go:136-137) -> Rust hydrate_wg_identity (userspace-dp/src/afxdp/forwarding_build/tunnels.rs:218 `if row.wg_listen_port == 0 { return None; }`, :222 `decode_wg_key_hex(&row.wg_local_privkey_hex,..).is_err() -> None`) drops the WHOLE row -> no UDP socket is bound, no control thread spawns (tunnel_supervision.rs:949 filters on hydrate_wg_identity), the tunnel never handshakes. Observable: green commit, tunnel permanently dead, no warning, no error — the exact commit/apply silent-drop class this file's own header (lines 23-25: 'A bad key today fails silently at the dataplane (hydrate_wg_identity drops the whole row)') was written to kill, but only for PEER keys.

**Why it matters** — A VPN tunnel that is configured and committed but silently never comes up is a availability/operations trap on a production firewall: traffic intended for the encrypted path blackholes (or falls to whatever default route exists), and the operator has no commit-time or runtime signal distinguishing 'peer down' from 'my config is unusable'. Every sibling silent-drop (#2396, #3109, #3150, #3300...) was hard-rejected at commit; the WG local identity is the one leg left open.

**Fix direction** — In validateWireguardPeersStrict / validateOneWireguardTunnel, additionally reject (strict) or warn (lenient): WgListenPort == 0 ('a WireGuard tunnel requires listen-port; the dataplane drops a port-0 tunnel'), empty WgLocalPrivkeyHex, and !isWireguardKeyHex(tc.WgLocalPrivkeyHex.Reveal()) — mirroring the same decode_wg_key_hex contract already mirrored for peer keys.

**Not a duplicate** — Grepped issues-all.txt for wireguard/keyless/identity/listen-port/private-key and prior-findings.md for wg/wireguard: #1434 added the zero-peer/dup-pubkey/PSK/endpoint-family gates, #2445 the dup-AllowedIPs gate, #1866 covered control-thread/port leak on removal — none covers the LOCAL identity (listen-port/privkey) commit gap. userspace-dp/src/afxdp/test_fixtures.rs:203 documents 'a peerless / keyless WG row is dropped by hydrate_wg_identity' as runtime behavior only; no issue tracks the missing commit gate.

---

#### F-012 · Plain Store.Commit during a pending commit-confirmed window leaves the auto-rollback timer armed — the timer later reverts the newer committed config (eventengine remediation path is fully exposed)

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-configstore`  ·  **Location:** `pkg/configstore/store_commit.go`:63
- **Labels:** `bug`, `vsrx-parity`, `test-gap`

```
func (s *Store) CommitWithDescription(description string) (*config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}

	compiled, err := s.compileTree(s.candidate)
```

**Runtime trace**

1) Operator: `commit confirmed 10` -> CommitConfirmed (store_commit.go:171) persists+promotes T1, saves confirmPrevTree=T0/confirmPrevCfg, arms timer with gen=confirmGen (line 236-240), operator exits config mode. 2) An event-options remediation fires: eventengine applyOnce (pkg/eventengine/engine.go:592) EnterConfigure succeeds (lock free), stages edits, calls commitFn -> daemon.commitAndApply (daemon_apply.go:158) -> store.Commit() -> CommitWithDescription. This function never touches confirmTimer/confirmGen/confirmPrev* — it persists+promotes T2 and returns success. Only the three FRONTENDS (cli_config.go:235, grpcapi/server_config.go:188, api/config.go:121) do a racy IsConfirmPending->ConfirmCommit dance; the daemon commit primitive used by eventengine (daemon_run.go:973-974) does not. 3) T+10min: timer fires -> fireConfirmTimer(gen) -> executeConfirmedRollback -> PromoteRollback(gen) (store_commit.go:325): gen==s.confirmGen still holds (Commit never bumped it, only CommitConfirmed/ConfirmCommit do) and confirmPrevTree!=nil, so the store promotes active back to T0, persists it (committed=1), and the daemon re-applies T0 to the dataplane. 4) Observable: the remediation commit that reported success — and the operator's T1 — are silently reverted store+disk+dataplane; journal shows only auto_rollback. Same stale-timer exposure applies to SyncApply (store.go:356), which also never clears confirm state: a node that armed a timer as primary, failed over, and then received a peer sync gets that synced config reverted to its stale local T0. No test in store_test.go commits plain while a window is pending (TestCommitConfirmedAutoRollback only tests ConfirmCommit).

**Why it matters** — A production security appliance loses a successfully-reported config commit minutes after the fact: firewall policy/NAT/remediation changes vanish from the running dataplane and from disk with no operator action, and in the HA case the reverted node silently diverges from the cluster primary. This defeats both the commit-confirmed safety feature and event-driven remediation.

**Fix direction** — Make confirmation a store-level invariant: in CommitWithDescription (and SyncApply), on successful persist+promote, stop s.confirmTimer, bump s.confirmGen, and clear confirmPrevTree/confirmPrevCfg (Junos semantics: any subsequent successful commit confirms the pending one). The frontend IsConfirmPending checks then become UX sugar rather than the only line of defense. Add a regression test: CommitConfirmed -> Commit -> fireConfirmTimer(gen) must be a no-op.

**Not a duplicate** — Grepped issues-all.txt for 'confirm', 'commit confirmed', 'rollback', 'configstore' — nearest are #3441 (archive/rollback-file durability, different mechanism) and #1817/#1922 (confirmGen staleness guard for nested CommitConfirmed/ConfirmCommit races — that guard is exactly what does NOT cover plain Commit, which never bumps the gen). prior-findings.md has no configstore confirm-timer findings. Novel mechanism: stale timer surviving a plain commit.

---

#### F-013 · CLI `set schedulers ...` silently compiles to ZERO schedulers: top-level `schedulers` stanza is missing from setSchema, so flat-set tokens collapse onto one garbage leaf (feature un-authorable via set grammar; set-format save/reload destroys all schedulers)

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-conntrack-appid`  ·  **Location:** `pkg/config/schema.go`:153
- **Labels:** `bug`, `vsrx-parity`, `config-schema`

```
var setSchema = &schemaNode{children: map[string]*schemaNode{
	"groups":             {desc: "Configuration groups", wildcard: &schemaNode{desc: "Group name", placeholder: "<group-name>"}}, // wildcard children set in init()
	"apply-groups":       {desc: "Groups from which to inherit configuration data", args: 1, multi: true, placeholder: "<group-name>", children: nil},
	"security":           schemaSecurity,
	"interfaces":         schemaInterfaces,
	"applications":       schemaApplications,
	...
	"routing-instances":  schemaRoutingInstances,
}}
```

**Runtime trace**

1) Operator types `set schedulers scheduler weekdays start-time 09:00:00` (+ stop-time line) and `set security policies ... policy allow-web scheduler-name weekdays`. 2) configstore LoadSet / interactive set -> ParseSetCommand -> ConfigTree.SetPath (pkg/config/ast_edit.go:129). The root setSchema has NO "schedulers" child and no root wildcard, so SetPath hits the childSchema==nil branch (ast_edit.go:152 'No schema match: all remaining tokens form a leaf node') and stores ONE leaf Node{Keys:["schedulers","scheduler","weekdays","start-time","09:00:00"]}. 3) Commit: SchemaValidate ignores unknown keywords (schema_walk.go:238 'Unknown keywords are not our concern'); CompileConfig dispatches on Keys[0] (compiler.go:1954 case "schedulers") into compileSchedulers, which does node.FindChildren("scheduler") on a CHILDLESS leaf -> zero instances -> cfg.Schedulers stays empty. Empirically verified at HEAD with ParseSetCommand+SetPath+CompileConfig: `set schedulers scheduler s4 start-time 09:00:00` compiles to `schedulers: 0`. 4) validatePolicySchedulerReferencesStrict (compiler_validate_strict.go:138-152) then REJECTS the commit with 'policy "allow-web" references undefined scheduler "weekdays"' even though the operator just defined it — the whole time-based-policy feature is un-authorable through the standard CLI set path. Without a policy binding the stanza just vanishes (`show security schedulers` empty). Worse: a config saved as `show configuration | display set` output and re-imported via `load set` loses every scheduler definition, and the reload then hard-fails on the surviving scheduler-name references.

**Why it matters** — Time-based policy scheduling is a fully built feature (runtime engine pkg/scheduler, dataplane inactive gating #3104/#3414, display surfaces #3062/#3624/#3684), yet the primary operator interface cannot create a scheduler at all, and set-format config round-trips destroy existing ones. On a production firewall this blocks time-gated policy deployment and can brick a config restore.

**Fix direction** — Add a typed `schedulers` subtree to setSchema (scheduler <name> with start-time/stop-time/start-date/stop-date/daily leaves + validators per docs/config-schema.md), so SetPath groups tokens correctly, completion offers the stanza, and SchemaValidate can bound the time/date formats. Add a round-trip test: set-lines -> SetPath -> CompileConfig -> cfg.Schedulers populated.

**Not a duplicate** — Searched issues-all.txt + prior-findings.md for scheduler/schedulers/start-time/daily/isWithinWindow. #3117 (CLOSED) added only the POLICY-side `scheduler-name` leaf to setSchema, not the top-level schedulers stanza; #1378 (CLOSED) was dataplane propagation; #3104/#3414/#3684 are runtime-gating/display. No issue or prior finding covers the set-grammar collapse of the schedulers stanza itself; grep -n '"schedulers"' over pkg/config schema files confirms only the class-of-service CoS schedulers node exists.

---

#### F-014 · compileSchedulers drops the Junos `daily { start-time/stop-time }` container (and all day-of-week containers): a real-Junos scheduler compiles to ALWAYS-ACTIVE — time-bounded permit policy is permanently open (fail-open)

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-conntrack-appid`  ·  **Location:** `pkg/config/compiler_system.go`:1089
- **Labels:** `bug`, `vsrx-parity`, `security`

```
		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "start-time":
				sched.StartTime = nodeVal(prop)
			case "stop-time":
				sched.StopTime = nodeVal(prop)
			case "start-date":
				sched.StartDate = nodeVal(prop)
			case "stop-date":
				sched.StopDate = nodeVal(prop)
			case "daily":
				sched.Daily = true
			}
		}
```

**Runtime trace**

1) Operator ports a vSRX config: `schedulers { scheduler work { daily { start-time 09:00:00; stop-time 17:00:00; } } }` via load merge, binds `scheduler-name work` to a permit policy intended for business hours only. 2) compileSchedulers iterates only DIRECT children of the scheduler node: `daily` matches the case arm and sets Daily=true, but the compiler never descends into the daily container, so its start-time/stop-time children are silently dropped -> StartTime=="" && StopTime=="". Empirically verified at HEAD: hierarchical parse + CompileConfig yields `s1: start="" stop="" daily=true`. 3) Commit succeeds (no scheduler time/date format validation exists anywhere). 4) Runtime: pkg/scheduler isWithinWindow (scheduler.go:205-208) returns true when both times are empty -> scheduler ALWAYS active -> the permit rule is enforced 24/7 instead of 9-17: fail-open. 5) Same silent drop for the Junos day-of-week containers (monday..sunday with start-time/stop-time/all-day/exclude) — no case arms at all, so per-day windows are not even representable. 6) Mirror failure the other way: the real Junos dotted date form `start-date 2026-07-01.09:00` compiles into StartDate verbatim (verified: `startDate="2026-07-01.09:00"`), then isWithinWindow's time.Parse("2006-01-02", ...) fails every 60s tick -> returns false -> the policy is PERMANENTLY inactive (fail-closed) with only a repeating slog.Warn.

**Why it matters** — An operator migrating a genuine vSRX scheduler config gets the opposite of the configured semantics with a clean commit: a time-restricted permit is open around the clock (security exposure), or a scheduled rule never activates (availability). This is a security appliance whose stated goal is native Junos syntax parity.

**Fix direction** — In compileSchedulers, descend into `daily` (and monday..sunday) containers and read their start-time/stop-time/all-day/exclude children into the typed config (extend SchedulerConfig with per-day windows); reject-at-commit any scheduler whose StartTime/StopTime/StartDate/StopDate fail the exact parse the runtime uses (parseTimeOfDay / date layout), and accept the Junos `YYYY-MM-DD.HH:MM` date-time form.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for daily/day-of-week/monday/all-day/exclude/time-window/scheduler. Zero hits on the daily-container drop or day-of-week gap. #1378 (CLOSED) covered propagating scheduler state to userspace-dp, #3104/#3414 covered runtime inactive gating — all assume the compiled window is correct. Nearest prior findings are scheduler DISPLAY omissions (#3624/#3684), a different layer.

---

#### F-015 · archiveConfig (transfer-on-commit) scps the stale boot-time xpf.conf — remote archives never contain the committed config

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-daemon-svc`  ·  **Location:** `pkg/daemon/daemon_flow.go`:248
- **Labels:** `bug`, `vsrx-parity`

```
	configFile := d.opts.ConfigFile
	for _, site := range cfg.System.Archival.ArchiveSites {
		go func(dest string) {
			slog.Info("archiving config", "destination", dest)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, "scp",
				"-o", "StrictHostKeyChecking=no",
				"-o", "BatchMode=yes",
				configFile, dest,
```

**Runtime trace**

Operator sets `system archival configuration transfer-on-commit` + archive-sites, then commits any change (e.g. a new policy). commitAndApply → applyConfigLocked step 15 (daemon_apply.go:1308) → archiveConfig(cfg) → scp of d.opts.ConfigFile (/etc/xpf/xpf.conf). But since the configstore became DB-canonical, commits persist ONLY to .configdb/active.json via Store.writeActive → s.db.WriteActive (store_persist.go:125-129) and to the numbered rollback files xpf.conf.1..N (store_commit.go rollbackPath); repo-wide grep shows NOTHING ever writes d.opts.ConfigFile after boot — it is a bootstrap-only input (daemon_apply.go:56 bootstrapFromFile reads it once when the DB is empty). So every transfer-on-commit push uploads the config frozen at first-boot/factory bake; the change that triggered the archival is never in the archive. Observable: collector-side archive of a box that has run for months of commits still shows the day-0 config, silently — scp succeeds, 'config archived successfully' is logged.

**Why it matters** — Config archival exists for disaster recovery and compliance audit. A firewall restored from these archives loses every post-deployment policy/NAT/VPN change, and a compliance diff against the archive is systematically wrong — with a success log asserting the opposite.

**Fix direction** — In archiveConfig, render the just-committed tree (it already receives cfg; or use d.store's active ConfigTree.Format()) to a temp file in the scratchdir and scp that (with a Junos-style timestamped name), instead of d.opts.ConfigFile. Add a test asserting the uploaded content equals the committed config text.

**Not a duplicate** — Searched issues-all.txt for 'archival', 'transfer', 'archive', 'scp', 'ConfigFile': only #651 (archive-sites password warning, CLOSED) and #3441 (LOCAL auto-archive wrong-commit/rollback-file durability in configstore, CLOSED — different file set: DB-side archive slots, not the remote scp source). prior-findings.md has zero archival entries. The stale-boot-file-as-scp-source mechanism is unfiled.

---

#### F-016 · rib-group kernel ip-rule mirror (pref 33000) is unreachable behind any main-table default route — imported interface routes are never consulted, and the dst-less rule is also skipped by the userspace leak snapshot

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-frr-routing`  ·  **Location:** `pkg/routing/rules.go`:34
- **Labels:** `bug`, `vsrx-parity`, `routing`

```
// ribGroupRulePriority is the base priority for rib-group ip rules.
// Must be AFTER the main table (32766) so VRF routes supplement rather
// than override main table routing. We use 33000-33099 range.
const ribGroupRulePriority = 33000
...
		// Add IPv4 rule
		rule := netlink.NewRule()
		rule.Table = sourceTable
		rule.Priority = prio
		rule.Family = unix.AF_INET
```

**Runtime trace**

Config: `routing-instances dmz-vr { instance-type virtual-router; interface ge-0-0-2; routing-options { interface-routes { rib-group inet dmz-leak } } }` + `routing-options rib-groups dmz-leak import-rib [ dmz-vr.inet.0 inet.0 ]` + any default route in inet.0 (static or DHCP — present in essentially every deployment). Apply path: daemon_apply.go:1093 ApplyRibGroupRules -> ribGroupManager.Apply (rules.go:178) -> RuleAdd of a dst-less `from all lookup 101 pref 33000` rule (rules.go:267-272). Kernel packet path (host-originated or slow-path/XDP_PASS traffic) to 10.0.61.5, a connected /24 inside dmz-vr's table 101: fib rule walk hits pref 32766 (main) first; main contains 0.0.0.0/0 so the lookup SUCCEEDS and rule evaluation TERMINATES — the pref-33000 rule is never consulted. The packet egresses the default-route WAN instead of the dmz-vr connected interface. Junos semantics: import-rib merges the VRF's interface routes INTO inet.0 with normal LPM, so the /24 must beat the /0. Userspace dataplane does not compensate: pkg/dataplane/userspace/routes.go leak loop skips every rule with `rule.Dst == nil` (line ~120 `if rule.Dst == nil || rule.Table <= 0 { continue }`), so the dst-less rib-group rule produces no synthetic NextTable route either — the imported routes exist in NO consulted FIB. Observable: `show route` shows the leak tables, but traffic to VRF-connected destinations from inet.0 context blackholes/mis-routes via default.

**Why it matters** — rib-group route leaking is an advertised feature (README/feature-gaps list it as Done). In any firewall with a default route — i.e., production — the kernel mirror is a silent no-op and the userspace FIB never sees the leak at all, so inter-VRF reachability the operator explicitly configured does not exist. This is a correctness/parity failure of a whole feature, not an error-path edge.

**Fix direction** — Realize rib-group import by copying the imported table's routes into the target table (netlink RouteAdd with per-route reconcile, like Junos secondary-rib semantics) or emit per-prefix dst-scoped rules ordered BEFORE main (a dedicated pref band < 32766 with per-prefix Dst so LPM order is preserved); mirror the same entries into the userspace RouteSnapshot (dst-less rules can never be represented there). At minimum document/warn at commit that rib-group import is inert when a default route exists.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for 'rib-group', '33000', 'import-rib', 'supplement', 'route-leak': #3731 (RuleAdd error swallow, OPEN) is about error propagation, not rule ordering/reachability; #2253/#2226 (CLOSED) are name-resolution bugs; prior findings 428/429/443 are error-handling drift; prior finding 598 is RuleList failure handling in the userspace snapshot. No prior item covers the pref-33000-after-main shadowing or the rule.Dst==nil skip making the leak absent from both FIBs.

---

#### F-017 · normalizeAuthAlg renders canonical Junos truncation-suffixed integrity names (hmac-sha-256-128, hmac-sha1-96, hmac-md5-96) as strongSwan-invalid tokens — whole proposal rejected, tunnel never loads (never-filed follow-up promised in #2073 review)

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-ipsec-wg`  ·  **Location:** `pkg/ipsec/ike.go`:256
- **Labels:** `bug`, `vsrx-parity`, `test-gap`

```
// normalizeAuthAlg maps a Junos authentication-algorithm name to its
// swanctl integrity token (hmac-sha-256 -> sha256).
func normalizeAuthAlg(authAlg string) string {
	a := strings.ReplaceAll(authAlg, "hmac-", "")
	a = strings.ReplaceAll(a, "-", "")
	return a
}
```

**Runtime trace**

Operator commits `set security ipsec proposal p2 encryption-algorithm aes-256-cbc authentication-algorithm hmac-sha-256-128` — the exact example xpf's own CLI help suggests (pkg/config/schema_security.go:751: "e.g. hmac-sha-256-128"); these suffixed spellings are the canonical SRX/vSRX Phase-2 names -> compiler stores AuthAlg verbatim (compiler_ipsec.go:242) -> renderConfig -> buildESPProposal (ike.go:337) -> normalizeAuthAlg strips "hmac-" and every dash -> "sha256128" -> `esp_proposals = aes256-sha256128-modp2048` written to /etc/swanctl/conf.d/xpf.conf -> `swanctl --load-all` -> charon's proposal keyword table has only sha256/sha2_256/sha256_96 (verified: libstrongswan 6.0.7 binary contains sha2_256/sha256_96/md5_128 and NO sha256128/sha196/md596) -> the entire proposal string is rejected and the child fails to load -> tunnel permanently down. Same failure for hmac-sha1-96 -> "sha196" and hmac-md5-96 -> "md596". Tests pin the invalid spelling as EXPECTED output (dhgroup_roundtrip_test.go:44 `want = "aes256-sha256128-modp2048"`, swanctl_render_test.go:64,104, ipsec_test.go:73).

**Why it matters** — A vSRX config pasted verbatim — using Junos' only spelling for SHA-256/SHA-1/MD5 ESP integrity — produces a swanctl config strongSwan refuses to load, with no commit-time diagnostic. docs/pr/2073-ipsec-pfs/plan.md:385-395 explicitly acknowledged this and promised to file it 'together with the ECP modp fix' — the ECP half became #2392/#2604 and was fixed, but no issue for sha256128 exists and ike.go:113 still says 'tracked outside #2073' pointing at nothing.

**Fix direction** — Give normalizeAuthAlg an explicit table like formatDHGroup: hmac-sha-256-128/sha-256-128 -> sha256, hmac-sha1-96 -> sha1, hmac-md5-96 -> md5, hmac-sha-256-96 -> sha256_96, etc.; update the tests that pin sha256128; optionally validate the rendered token set at commit.

**Not a duplicate** — Grepped issues-all.txt for sha256128/sha-256-128/authentication-algorithm/normalizeAuthAlg/integrity: zero hits. #2073 (PFS fallback), #2392 (ECP groups), #2604 (RFC 5114 groups), #2125 (GCM ICV) all fixed adjacent keyword bugs but the integrity-token half was never filed — docs/pr/2073-ipsec-pfs/plan.md:385 confirms it was deferred 'as its own issue' that does not exist. Residual reported per protocol, mechanism distinct from all four prior fixes (integrity keyword, not DH or cipher).

---

#### F-018 · DNAT: rule-level `match destination-port` mishandled whenever `match application` is also configured — invalid tokens widen to wildcard-port (bypasses #3446 guard), valid ports are silently ignored or collapsed to the first port

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `go-usdp-programs`  ·  **Location:** `pkg/dataplane/userspace/nat.go`:908
- **Labels:** `bug`, `security`, `vsrx-parity`, `test-gap`

```
				portRanges := coalescePortRanges(term.ports)
				// Did this rule CONFIGURE a destination-port at all? A configured
				// port that survived to no valid value must not become wildcard.
				portConfigured := len(term.ports) > 0 ||
					(explicitFallback && (rule.Match.DestinationPort != 0 || len(rule.Match.InvalidDestinationPorts) > 0))
				if len(portRanges) == 0 {
					switch {
					case rule.Match.DestinationPort >= 1 && rule.Match.DestinationPort <= 65535:
						p := uint16(rule.Match.DestinationPort)
						portRanges = []NatPortRangeWire{{Low: p, High: p}}
					case portConfigured:
						continue
					default:
						portRanges = []NatPortRangeWire{{Low: 0, High: 0}}
```

**Runtime trace**

The DNAT parser (pkg/config/compiler_nat.go cases at 1541 `destination-port` and 1574 `application`) accepts BOTH leaves in one rule's match block, so a rule can carry Applications plus DestinationPort(s)/InvalidDestinationPorts. In buildDestinationNATSnapshotsWithFeeds: (a) FAIL-OPEN, lenient/peer-sync path — config `match application my-udp-app` (protocol udp, no port spec) + `match destination-port http` (non-numeric, parser stores InvalidDestinationPorts=["http"], DestinationPort=0). appConfigured=true -> appTerms=[{proto:"udp", ports:nil}], explicitFallback stays false (nat.go:862/879). In the term loop: term.ports=nil -> portRanges=nil (905); portConfigured = len(term.ports)>0 || (explicitFallback && ...) = false (908-909) because the rule-level invalid tokens are only consulted when explicitFallback is true; switch: DestinationPort==0 fails case 1, portConfigured=false skips the fail-closed `continue`, default emits the wildcard [0,0] range (921-923) -> dstPort=0 wildcard entry installs -> the Rust DnatTable translates EVERY UDP port to the pool VIP instead of matching nothing. Removing the application line flips explicitFallback=true and the same bad port fails CLOSED — the exact asymmetry #3446 was supposed to eliminate. (b) COMMIT-VALID widening — `match application junos-http` + `match destination-port 8080` passes both strict gates (validateNATMatchDestinationPortStrict only checks range/numeric; validateNATMatchApplicationsStrict only checks resolvability). term.ports=[80] -> portRanges=[{80,80}]; the switch never runs, rule.Match.DestinationPort(8080) is never carried to any wire field on the app-term path, so an entry keyed to port 80 installs — traffic to port 80 is translated although the operator constrained the rule to 8080 (AND semantics would match nothing). The SNAT builder handles the identical combination correctly by carrying MatchDestinationPorts and MatchApplications as independent AND-ed wire axes (nat.go:236-237). (c) COMMIT-VALID narrowing — protocol-only app + `match destination-port [ 8080 8081 ]`: term.ports empty -> case 1 reads only the SINGULAR back-compat DestinationPort (first list element 8080); 8081 is silently dropped (a #3431-class multi-value loss on the app-term path).

**Why it matters** — Shape (a) is a destination-NAT fail-open on the tolerant-load / HA peer-sync path: an internal VIP scoped to one port gets published on every port of the protocol — the same exposure class #3446/#3546 were filed and fixed for, resurrected by adding an application to the rule. Shapes (b)/(c) mistranslate configs that commit cleanly today: (b) translates traffic the operator excluded (widening), (c) breaks half the configured port set (service outage). All three diverge from the repo's own SNAT AND-semantics contract.

**Fix direction** — Mirror the SNAT builder: carry the rule-level destination-port constraint as an independent AND axis (extend DestinationNATRuleSnapshot.MatchDestinationPorts with the rule-level coalesced ranges alongside app-term ports) instead of folding it into per-term port selection; and make portConfigured include rule-level DestinationPorts/InvalidDestinationPorts unconditionally (not only under explicitFallback) so a configured-but-unresolvable port fails closed on app-term rules too. Add builder tests for app+valid-port, app+invalid-token, and app+multi-port-list combinations.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for 3446/3434/3437/3446/3449/3450/3431/3546, 'destination-port', 'portConfigured', 'explicitFallback', 'wildcard port', and all nat.go prior findings. #3446 fixed only the NO-application (explicitFallback) path; #3546 is the SNAT sourceNATDestPortRanges analog; #3434 covers app-resolves-to-zero-terms; #3437 covers source-port/ICMP axes; prior findings 415/416 cover application-SET partial drops. None covers the rule-level destination-port x application interplay (portConfigured gated on explicitFallback; rule port ignored/collapsed for app terms) — mechanism-distinct residual.

---

#### F-019 · Responder rekey promotes an UNCONFIRMED session straight to `current` (no WG `next` keypair slot) → egress blackhole on every peer-initiated rekey, replay-amplifiable to a persistent egress DoS

- **Severity:** 🔴 high  ·  **Confidence:** high
- **Module:** `rs-wg-coord`  ·  **Location:** `userspace-dp/src/afxdp/wg/engine.rs`:901
- **Labels:** `bug`, `security`, `vsrx-parity`

```
        by_index.insert(new_local_index, session.clone());
        let dropped_previous = peer.rotate_session(session);
        if let Some(old) = dropped_previous {
            debug_assert_ne!(old.local_index, new_local_index);
            by_index.remove(&old.local_index);
        }
```

**Runtime trace**

Established tunnel, xpf holds a CONFIRMED current session S1 (egress works). Peer initiates a rekey (its REKEY_AFTER_TIME, or any fresh handshake) and sends msg1. wg_control_loop RX → dispatch_inbound → WG_TYPE_INITIATION → consume_initiation_create_response_inner: builds S2 via WgSession::new_with_role(..., SessionRole::Responder, ...) so confirmed=false (session.rs:193), then install_session_locked (handshake_session.rs:558) → engine.rs:900-901 inserts S2 in the demux map and rotate_session() moves S1(confirmed)→previous, S2(unconfirmed)→current (peer.rs:218-225 unconditional replace). xpf sends msg2 to the peer. Next egress packet off wgN TUN → encap_and_send → try_encap → encap_inner reads peer.current = S2 (engine.rs:957) and hits the unconfirmed gate (engine.rs:974) → returns NoSession → packet DROPPED. Because encap NEVER falls back to `previous`, the still-valid confirmed S1 can no longer send. In a legit rekey the peer's post-completion confirmation keepalive arrives on S2 and confirms it (~1 RTT blackhole). REPLAY amplification (see companion TAI64N finding): an attacker replays one captured msg1 → xpf re-rotates a fresh unconfirmed session into current each time; the real peer receives an unsolicited msg2 and drops it, so it never sends data to confirm → xpf's egress to that peer stays NoSession. xpf self-heals by initiating its own handshake, but sustained replay re-rotates faster than recovery → continuous egress blackhole.

**Why it matters** — WireGuard (kernel + wireguard-go) uses a 3-slot keypair model (previous/current/next): a responder's freshly-derived keypair goes into `next`, and the node KEEPS SENDING on `current` until `next` is confirmed by a received transport packet — so a re-handshake never interrupts egress and a replayed initiation only churns `next`. xpf's 2-slot model (current/previous) with immediate promotion violates this: every peer-initiated rekey interrupts xpf→peer forwarding, and combined with the missing handshake anti-replay it is a trivially reachable egress DoS against an established tunnel on a security appliance.

**Fix direction** — Add a `next` session slot to Peer. Install an unconfirmed responder session into `next` (not `current`); keep `current` as the sending keypair; promote next→current (and current→previous) only when try_decap authenticates a transport record on the next session (mark_confirmed path). encap must continue using the last confirmed `current`. This matches kernel WG `wg_noise_keypair_add(..., false)` + `wg_noise_received_with_keypair` promotion.

**Not a duplicate** — Searched issues-all.txt for wireguard/handshake/rekey/confirm/keypair/churn and prior-findings.md for rotate_session/next-session/unconfirmed/blackhole/three-slot — no hit. Closest is engine.rs's own `confirmed` gate (added by 'Codex final pre-merge finding 2') which prevents SENDING on an unconfirmed responder session but does NOT add a `next` slot, so it introduced the displacement. #1888 (timers) and #1434 (multi-peer) are unrelated mechanisms. This specific defect (displacement of the live confirmed sender by an unconfirmed responder session for lack of a 3rd slot) is not in any open issue or prior finding.

---

#### F-020 · Config secret redaction (#2053) is bypassed by every raw-AST render surface (REST /config/show|export|search|show-rollback|compare and gRPC ShowConfig) — cleartext PSK/auth-key/community leaks

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-api-grpc`  ·  **Location:** `pkg/api/config.go`:257
- **Labels:** `security`, `vsrx-parity`, `test-gap`

```
func (s *Server) configSearchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		writeError(w, http.StatusBadRequest, "missing q parameter")
		return
	}
	text := s.store.ShowActive()
	var results []ConfigSearchResult
	for i, line := range strings.Split(text, "\n") {
		if strings.Contains(line, query) {
```

**Runtime trace**

Operator commits `set security ike policy p pre-shared-key ascii-text SECRET`. This stores the cleartext token in the configstore ConfigTree (AST leaf) AND in the typed *config.Config as a config.Secret (which redacts on JSON/YAML marshal, #2053). (1) GET /api/v1/config -> configHandler -> writeOK(cfg) -> json.Encode(*config.Config) -> Secret.MarshalJSON emits the redaction sentinel: SAFE, and TestConfigHandlerRedactsSecrets only covers this path. (2) GET /api/v1/config/show?format=set -> configShowHandler -> s.store.ShowActiveSet() -> ConfigTree.FormatSet() (ast_format.go) walks the RAW AST and emits `set security ike policy p pre-shared-key ascii-text SECRET` verbatim. (3) GET /api/v1/config/search?q=pre-shared-key -> configSearchHandler -> text := s.store.ShowActive() (cleartext) -> returns matched lines containing SECRET — a targeted exfiltration primitive. (4) GET /api/v1/config/export, /config/show-rollback, /config/compare and gRPC ShowConfig (server_config.go:262) all route through the same ShowActive*/FormatJSON/FormatXML tree renderers. None of these redact. So the SAME secret is redacted on one endpoint and cleartext on its siblings.

**Why it matters** — On a security appliance the #2053 redaction is a compliance/secret-handling control; a monitoring tool or support-bundle collector that trusts the redacted /api/v1/config is silently defeated by /config/show?format=json. Junos encrypts these fields ($9$) in `show configuration`; xpf emits cleartext IKE/IPsec PSKs, OSPF/RIP/IS-IS/BGP auth keys, VRRP auth keys, SNMP community/v3 passwords, TSIG secrets and API keys to any authenticated (or, per finding 2, unauthenticated) reader.

**Fix direction** — Apply redaction at the render boundary, not only the typed-struct marshal: give the configstore Show*/Format* helpers a redacting variant (walk the AST replacing known secret-bearing leaf paths with the SecretRedacted sentinel, driven by the same SSOT the Secret type uses) and route the REST/gRPC operator surfaces through it, keeping a raw variant only for the encrypted-at-rest DB path. Add a text/JSON/XML-surface analogue of TestConfigHandlerRedactsSecrets.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for redact/secret/leak/psk/password: only #2053 [CLOSED] 'redact all sensitive secrets at JSON/YAML marshal time' matches, and the redaction test (config_secret_redaction_test.go) only drives GET /api/v1/config. This is the explicit RESIDUAL: #2053 fixed typed-struct marshal (config.Secret.MarshalJSON); the raw-AST ConfigTree render path used by show/export/search/rollback/compare and gRPC ShowConfig was never covered and still emits cleartext. Not in prior-findings pkg/api list (which is entirely policy/host-inbound/counter parity).

---

#### F-021 · Full-screen `monitor interface` leaks a stdin-reading goroutine that races the main readline loop on exit, stealing subsequent keystrokes

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-cli`  ·  **Location:** `pkg/cli/monitor_interface.go`:199
- **Labels:** `bug`, `correctness`

```
	keyCh := make(chan byte, 8)
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				return
			}
			keyCh <- buf[0]
		}
	}()
```

**Runtime trace**

Operator runs `monitor interface ge-0-0-0`. monitorInterfaceSingle starts the key-reader goroutine (line 199) blocked in os.Stdin.Read. User presses 'q' (line 244) -> the function returns nil; restoreTermMode reverts to canonical mode, BUT nothing signals or closes the goroutine — it loops back to os.Stdin.Read and stays blocked on the same fd. Control returns to CLI.Run which calls c.rl.Readline(), which ALSO reads os.Stdin. Both readers are now pending on stdin. On the next keystroke the kernel wakes exactly one reader nondeterministically: bytes routed to the leaked goroutine are pushed into keyCh (cap 8) and never drained, so up to 8 of the user's next keystrokes are silently swallowed before the goroutine blocks on the channel send. monitorInterfaceTraffic (line 287) has the identical leak. Each monitor invocation adds another permanently-blocked goroutine + another transient stdin thief.

**Why it matters** — After using the interactive monitor views the operator's next command line is corrupted (missing characters) with no error — on a firewall CLI this produces mistyped `clear`/`commit`/`set` commands. It is also an unbounded goroutine leak across a long CLI session.

**Fix direction** — Give the reader goroutine a done channel (or context) closed on return, and select on it in both the reader loop and the render loop; or restructure to a single input owner. At minimum drain/close keyCh and stop the goroutine before returning.

**Not a duplicate** — Searched prior-findings.md/issues for 'goroutine leak'/'stdin'/'monitor interface'/'raw mode'. Only #677 (gRPC MonitorSessions goroutine leak in pkg/api/service.go) exists — different surface and mechanism. #421/#423/#477/#478 are feature/keystroke-mode issues, not the stdin-vs-readline race. Novel.

---

#### F-022 · `monitor traffic ... matching <expr>` truncates the tcpdump filter to the first token, silently dropping the rest of the expression

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-cli`  ·  **Location:** `pkg/cli/cli_request.go`:493
- **Labels:** `bug`, `correctness`, `vsrx-parity`

```
		case "matching":
			if i+1 < len(args) {
				i++
				filter = args[i]
			}
...
	if filter != "" {
		cmdArgs = append(cmdArgs, filter)
	}
```

**Runtime trace**

Operator runs `monitor traffic interface ge-0-0-0 matching tcp port 80`. dispatch -> strings.Fields splits into args = [interface ge-0-0-0 matching tcp port 80]. handleMonitorTraffic loop: at i="matching" it consumes only args[i+1]="tcp" into `filter`; the loop then reaches "port" and "80" which match no case (switch has no default) and are silently ignored. cmdArgs becomes `tcpdump -i ge-0-0-0 -n -l tcp` — the `port 80` predicate is gone, so the capture is far broader than requested (all TCP instead of TCP/80). Quoting cannot help because strings.Fields in dispatch already discarded the quotes.

**Why it matters** — Operators use `monitor traffic matching "..."` to isolate a specific flow during incident response; silently widening the BPF filter floods the terminal and hides the targeted traffic, and there is no error to signal the truncation.

**Fix direction** — Collect all remaining tokens after `matching` (join args[i+1:]) into the filter, or reject trailing unknown tokens; ideally preserve the quoted expression through dispatch (a raw-tail parse) so multi-word BPF filters reach tcpdump intact.

**Not a duplicate** — Searched issues/prior-findings for tcpdump/monitor traffic/matching/multi-token. #135/#136/#138 cover fabric-overlay visibility, not filter truncation. No prior finding on the matching-filter token loss. Novel.

---

#### F-023 · read-only / config-viewer login classes can run `monitor traffic` (root tcpdump full packet capture) and write flow-trace files — `monitor` mapped to PermView

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-cli`  ·  **Location:** `pkg/cli/permissions.go`:28
- **Labels:** `security`, `vsrx-parity`, `bug`

```
	switch action {
	case "show", "ping", "traceroute", "monitor":
		required = config.PermView
	case "clear":
		required = config.PermClear
	case "request", "test":
		required = config.PermControl
```

**Runtime trace**

userClass="read-only" (LoginClassPermissions["read-only"]={PermView}). Operator types `monitor traffic interface ge-0-0-0`. dispatchOperational resolves parts[0]="monitor", calls checkPermission("monitor") -> required=PermView -> read-only has PermView -> returns nil (allowed). handleMonitor -> handleMonitorTraffic builds `tcpdump -i <if> -n -l` and exec.CommandContext runs it as the daemon's root uid, streaming every packet (including cleartext payloads) to the read-only user's terminal. Same path admits `monitor security flow file X start`, which openTraceFile creates a root-owned file under /var/log and writes session tuples/zones/policy names. A read-only account is thereby able to sniff the entire dataplane and create files on disk — capability far beyond viewing operational state.

**Why it matters** — In vSRX/Junos `monitor traffic` (packet capture) requires the trace/maintenance permission, not bare `view`; lumping all `monitor` verbs under PermView lets the lowest-privilege class read all forwarded traffic (confidentiality escalation) and consume control-plane disk. This defeats the purpose of a read-only class on a security appliance.

**Fix direction** — Split the coarse map: gate `monitor traffic` and `monitor security flow file/start` behind PermControl (or a new PermTrace), leaving `monitor interface` under PermView. Mirror the Junos permission bits so read-only cannot invoke packet capture.

**Not a duplicate** — Searched issues-all.txt + prior-findings.md for permission/privilege/monitor/PermView/read-only. Prior RBAC work (#3378-3382) hardened monitor parsing/file-safety but never questioned the permission CLASS that gates monitor. No open issue or prior finding covers monitor being reachable by PermView; distinct from all monitor-parsing issues.

---

#### F-024 · Removing or re-weighting an interface-monitor on a surviving RG strands its weight penalty — node can stay stuck SECONDARY

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-cluster-core`  ·  **Location:** `pkg/cluster/group_state.go`:36
- **Labels:** `bug`, `correctness`, `ha`

```
		} else {
			existing.LocalPriority = rg.NodePriorities[m.nodeID]
			existing.Preempt = rg.Preempt
		}
	}
```

**Runtime trace**

1) RG1 has interface-monitor ge-0/0/5 weight 100. 2) ge-0/0/5 goes carrier-down; Monitor.pollInterfaceMonitors -> SetMonitorWeight(1,"ge-0/0/5",down=true,100): m.monitorWeights[{1,ge-0/0/5}]=100, rg.MonitorFails=["ge-0/0/5"], recalcWeight -> rg.Weight=155. 3) Operator removes that interface-monitor from config and commits. 4) UpdateConfig runs: RG1 is still present (seen[1]=true) so only the else-branch at group_state.go:36-38 executes (updates LocalPriority/Preempt); m.monitor.UpdateGroups(newGroups) at :87 drops ge-0/0/5 from the poll set. 5) rg.MonitorFails and m.monitorWeights are NEVER reconciled — recalcWeight (election.go:389-399) still sums monitorWeights over the stale rg.MonitorFails, and no future poll can ever call SetMonitorWeight(down=false) for ge-0/0/5 because the monitor no longer probes it. 6) rg.Weight is pinned at 155 forever; EffectivePriority stays degraded and, if the residual penalty is large enough, the node cannot win election and is stuck SECONDARY even though the monitored interface is no longer in the config. The same stranding hits a pure weight change (100->50 while down): monitorWeights keeps the old 100 because SetMonitorWeight only rewrites it on a fresh down-transition.

**Why it matters** — In an HA firewall, a stranded monitor penalty silently prevents a node from ever reclaiming primary after the operator has explicitly removed the failing monitor — an unrecoverable-without-restart split-ownership / degraded-cluster state driven purely by a routine config edit.

**Fix direction** — In UpdateConfig, after refreshing each existing RG, reconcile rg.MonitorFails and m.monitorWeights against the new interface-monitor/IP-monitor set: drop entries whose iface is no longer configured (and prune the same keys from monitor.ifaceState/ipState), then call recalcWeight(rg) so the effective weight is recomputed from the current monitor set before re-election.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for interface-monitor / monitor-weight / config-change / stale-weight. Nearest is #2070 (CLOSED: carrier-down link reported UP) which is a link-state read bug, not a config-reconcile gap. No open issue or prior finding covers UpdateConfig failing to reconcile rg.MonitorFails/monitorWeights on monitor removal or weight change.

---

#### F-025 · Bulk-ack-before-pending-store race latches PendingBulkAck and permanently blocks manual failover

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-cluster-sync`  ·  **Location:** `pkg/cluster/sync_bulk.go`:206
- **Labels:** `bug`, `ha`, `race`

```
	s.writeMu.Lock()
	err = writeMsg(conn, syncMsgBulkEnd, epochBuf[:])
	s.writeMu.Unlock()
	if err != nil {
		s.pendingBulkAckEpoch.Store(0)
		s.pendingBulkAckSince.Store(0)
		s.handleDisconnect(conn)
		return err
	}
	s.pendingBulkAckEpoch.Store(epoch)
	s.pendingBulkAckSince.Store(time.Now().UnixNano())
```

**Runtime trace**

1) Cold-start connect: handleNewConnection (sync_conn.go:516) runs doBulkSync in the accept/dial goroutine. sendBulkMarkers (override path, sync_bulk.go:57-72) or BulkSync (:198) writes syncMsgBulkEnd; writeMsg returns once bytes hit the kernel buffer. 2) Sender goroutine is descheduled (GC pause/preemption) BEFORE executing pendingBulkAckEpoch.Store(epoch) at :206 (:72 for markers). 3) Peer receiveLoop processes BulkEnd — for the marker path the bulk is empty so reconcileStaleSessions returns immediately — and sendBulkAck replies within one fabric RTT. 4) Sender's receiveLoop handles syncMsgBulkAck (sync_conn.go:1307): `if pending := s.pendingBulkAckEpoch.Load(); pending != 0 && epoch >= pending` — pending is still 0, so the clear is SKIPPED. 5) Sender goroutine resumes and stores epoch into pendingBulkAckEpoch. No further ack will ever arrive (bulk done). 6) Every later `request chassis cluster failover`: Manager.ManualFailover → transferReadyFn (failover.go:233-242) → TransferReadiness → ReadyForManualFailover()==false (PendingBulkAckEpoch!=0) → hard error "peer still receiving outbound bulk epoch=N age=..." with no timeout override, until a full disconnect (handleDisconnect :1568) resets it.

**Why it matters** — A one-scheduling-quantum race at bulk completion wedges the explicit-failover admission gate for the lifetime of the connection on a production HA pair; the operator cannot fail over gracefully (only disruptive disconnect/reboot clears it), and the sendBulkMarkers empty-bulk path used by the loss userspace cluster makes the peer's ack fast enough to realistically win the race.

**Fix direction** — Store pendingBulkAckEpoch/Since BEFORE writing BulkEnd (clearing them on write error, as the error branch already does), or have the ack handler record the highest acked epoch and have PendingBulkAck() treat epoch<=lastAcked as satisfied.

**Not a duplicate** — Grepped issues-all.txt for 'bulk', 'BulkAck', 'pendingBulkAck', 'failover': #339 (CLOSED) ADDED this pending-ack gate for graceful demotion; #398/#403 (CLOSED) were about failover during a legitimately in-progress bulk. No issue or prior finding covers the ack-arrives-before-store TOCTOU that latches a phantom pending epoch. prior-findings.md has no pkg/cluster bulk entries.

---

#### F-026 · Deletes journaled while connected (sendCh full) are never flushed until a full disconnect/reconnect — standby keeps dead sessions

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-cluster-sync`  ·  **Location:** `pkg/cluster/sync_conn.go`:840
- **Labels:** `bug`, `ha`, `test-gap`

```
func (s *SessionSync) QueueDeleteV4(key dataplane.SessionKey) {
	gen := s.takeDeleteGenV4(key)
	msg := encodeDeleteV4(key, gen)
	if !s.queueMessage(msg, &s.stats.DeletesSent, "delete_v4") {
		s.journalDelete(msg)
	}
}
```

**Runtime trace**

1) Under load (e.g. sweep replay after an overflow, or bulk drain via sendCh on the event-stream path), sendCh (cap 4096) momentarily fills. 2) Conntrack GC close callbacks call QueueDeleteV4/V6; queueMessage (sync_conn.go:795-810) hits the `default:` branch while Connected==true and returns false. 3) The delete is journalDelete()'d (:857). 4) The ONLY caller of flushDeleteJournal is handleNewConnection's `wasDisconnected` branch (sync_conn.go:509) — it never runs while the connection stays up. The queue-full path only sets syncBackfillNeeded, and syncSweep replays INSTALLS (Created >= threshold), never deletes. 5) One second later sendCh has room, but the journaled deletes sit until the next full fabric disconnect, which on a healthy cluster may be weeks away. 6) The standby retains the closed sessions until their idle timeout (established TCP: tens of minutes); those peer-synced sessions also count toward per-IP session limits (#3122), so after a failover the new master both forwards on stale state and can refuse new legitimate flows against the per-IP cap.

**Why it matters** — Session-table divergence between HA nodes is exactly what the delete-sync path exists to prevent; a transient one-tick queue burst silently converts into hours of standby staleness with no counter distinguishing 'journaled awaiting reconnect' from 'journaled while connected'.

**Fix direction** — Opportunistically drain the delete journal while connected — e.g. call flushDeleteJournal (it already re-journals an un-sent tail) from the sweep tick or whenever queueMessage transitions back to non-full — instead of only from the reconnect path.

**Not a duplicate** — Grepped for 'journal': #119 (CLOSED) added the disconnect replay journal; #2121 (CLOSED) fixed flushDeleteJournal dropping the un-sent tail (rejournalTail now present at HEAD). Neither covers deletes journaled on the connected-but-queue-full branch never being flushed while the connection stays up; sync_test.go only tests flush-on-reconnect.

---

#### F-027 · CoS rewrite-rules drop the Junos-canonical inline `loss-priority low code-point ef;` leaf — the #1809 fix was applied to both classifier collectors but not to collectCoSDSCPRewriteCodePoint

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-ifaces-cos-fw`  ·  **Location:** `pkg/config/compiler_class_of_service.go`:621
- **Labels:** `bug`, `vsrx-parity`

```
func collectCoSDSCPRewriteCodePoint(node *Node) (uint8, bool, error) {
	for _, child := range node.FindChildren("code-point") {
		if len(child.Keys) < 2 {
			continue
		}
		values, err := expandCoSCodePointToken(child.Keys[1])
		if err != nil {
			return 0, false, err
		}
		if len(values) > 0 {
			return values[0], true, nil
		}
	}
```

**Runtime trace**

Junos emits rewrite rules hierarchically as one-line leaves: `rewrite-rules { dscp my-rw { forwarding-class expedited { loss-priority low code-point ef; } } }`. The parser yields lpNode Keys=["loss-priority","low","code-point","ef"] with no children. collectCoSDSCPRewriteCodePoint scans only FindChildren("code-point"/"code-points") — it lacks the inline Keys scan that #1809 added to collectCoSDSCPCodePoints (lines 552-562) and collectCoS8021CodePoints (lines 607-617) — so it returns ok=false, the entry is skipped (line 220-222), the rule ends with 0 entries and is dropped by the `len(rewriteRule.Entries) > 0` gate (line 230). PROBE AT HEAD: the classifier in the same shape resolves (dscp=[46], proving the #1809 fix) while `rewrite rules: 0` with a clean strict compile. Result: egress DSCP rewrite silently absent — packets leave with unrewritten code points and downstream QoS misclassifies them.

**Why it matters** — A committed rewrite-rule that never installs is a silent QoS contract violation on a Junos-import path; the asymmetry (classifiers fixed, rewrite missed) makes it invisible to the tests added for #1809.

**Fix direction** — Add the same inline-Keys scan (`for i := 2; i < len(node.Keys); i++ { if node.Keys[i] == "code-point" || node.Keys[i] == "code-points" { ... } }`) to collectCoSDSCPRewriteCodePoint, and add a hierarchical-shape rewrite-rules regression test mirroring the #1809 classifier test.

**Not a duplicate** — This is an explicitly-named residual of CLOSED #1809 ('CoS classifier inline loss-priority leaf dropped in hierarchical form'): HEAD reflects the fix for both classifier collectors but the identical mechanism persists in the rewrite-rules collector, a different function the fix never touched. Distinct from #3715/#3716 and prior findings on dscp_rewrite masking (Rust boundary, filter `then dscp`), and from #2704 (undefined FC references).

---

#### F-028 · Interface-level CoS binding (`class-of-service interfaces <if> scheduler-map/shaping-rate` without `unit`) — the canonical Junos attach form — is silently dropped at commit with no warning

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-ifaces-cos-fw`  ·  **Location:** `pkg/config/compiler_class_of_service.go`:309
- **Labels:** `vsrx-parity`, `bug`

```
	for _, inst := range namedInstances(node.FindChildren("interfaces")) {
		iface := &CoSInterface{
			Name:  inst.name,
			Units: make(map[int]*CoSInterfaceUnit),
		}
		for _, unitNode := range inst.node.FindChildren("unit") {
			if len(unitNode.Keys) < 2 {
				continue
			}
```

**Runtime trace**

vSRX operators canonically write `set class-of-service interfaces ge-0/0/1 scheduler-map my-map` (physical-interface scope; unit scope requires per-unit-scheduler on Junos). The setSchema `interfaces` node's only child is `unit` (schema_cos.go:102-116), so SetPath stores scheduler-map/shaping-rate as unknown-child leaves under the interface node; hierarchical import produces the same non-unit children. compileClassOfService reads ONLY FindChildren("unit") (line 309), leaving iface.Units empty, and the `len(iface.Units) > 0` gate (line 407) discards the whole interface. PROBE AT HEAD: strict CompileConfig succeeds and cos.Interfaces=map[] — no shaper, no scheduler binding, no classifier attach. The warn validator (compiler_validate_warn.go:738) only checks per-unit references, so nothing is emitted anywhere. The interface runs completely unshaped while the operator believes CoS is active.

**Why it matters** — This is the exact 'silent functional lie at commit' class the repo formalized in #2008 H9/H10 (compiler_interfaces_unsupported.go): the config claims QoS enforcement the running firewall does not deliver. It also breaks import of essentially every real vSRX CoS config, since the no-unit form is the Junos default spelling.

**Fix direction** — Either compile the interface-level binding by applying it to unit 0 / all configured units (Junos-compatible), or add it to the #2008-style reject-at-commit pre-walk (strict error, lenient warning) and to the schema so completion offers it. Update docs/feature-gaps.md row 631 accordingly.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'scheduler-map', 'shaping-rate', 'cos interface': #2409 (dataplane forwarding-build skips unresolved scheduler-map classes — post-compile), #2704 (undefined FC refs), #2575 (cluster verify script). feature-gaps.md:631 marks 'Interface CoS Binding' Partial but names no silent-drop of the no-unit form. No prior finding covers compileClassOfService ignoring non-unit children.

---

#### F-029 · Junos `interfaces interface-range` compiles into a phantom interface literally named "interface-range"; member NICs stay unconfigured and are forced admin-down by the claim-all reconcile

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-ifaces-cos-fw`  ·  **Location:** `pkg/config/compiler_interfaces.go`:30
- **Labels:** `vsrx-parity`, `bug`

```
func compileInterfaces(node *Node, ifaces *InterfacesConfig) error {
	for _, child := range node.Children {
		if child.IsLeaf {
			continue
		}
		ifName := child.Name()
		ifc := &InterfaceConfig{
			Name:  ifName,
			Units: make(map[int]*InterfaceUnit),
		}
```

**Runtime trace**

Import a common enterprise Junos config: `interfaces { interface-range access-ports { member ge-0/0/1; member ge-0/0/2; unit 0 { family inet address 10.1.0.1/24; } } }`. compileInterfaces treats every non-leaf child of `interfaces` as a physical interface and uses child.Name()==Keys[0], so the block compiles to InterfaceConfig{Name:"interface-range"} carrying unit 0 (PROBE AT HEAD: iface "interface-range" units=1, addrs=[10.1.0.1/24]; strict compile passes). Consequences: (1) members ge-0/0/1 and ge-0/0/2 have no InterfaceConfig, so in positional mode the bring-down reconcile (compiler_iface.go, 'interfaces not in the config are brought down and marked ActivationPolicy=always-down') forces both live ports admin-down — an outage from a clean commit; (2) networkd/zone plumbing is generated for a nonexistent netdev named after the keyword; (3) two interface-range blocks collide on the single map key `ifaces.Interfaces["interface-range"]`, second-overwrites-first, since the range NAME is Keys[1] and ignored.

**Why it matters** — interface-range is a staple of real Junos configs; importing one on this claim-all firewall does not degrade gracefully — it takes member ports down with zero diagnostics. Not documented anywhere as a gap (no hit in feature-gaps.md, issues, or prior findings).

**Fix direction** — Minimum: reject `interface-range` at commit via the #2008-style unsupported-stanza pre-walk (lenient-warn on load) so it can never silently down ports. Better: expand ranges at compile time — clone the range body onto each `member`/`member-range` interface before per-interface compilation (Junos semantics), keyed off child.Name()=="interface-range".

**Not a duplicate** — grep 'interface-range' across issues-all.txt (1915 titles), prior-findings.md, known-gaps.md, and the repo (code+docs) returned zero hits — the construct is entirely unhandled and undocumented. Nearest neighbor is the #2008 H9/H10 unsupported-interface-stanza gate, which this deliberately mirrors as the fix direction.

---

#### F-030 · Non-inet6 firewall families (any/mpls/ethernet-switching/...) are folded into FiltersInet — a same-name cross-family filter silently overwrites the real IPv4 filter (fail-open)

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-ifaces-cos-fw`  ·  **Location:** `pkg/config/compiler_firewall.go`:183
- **Labels:** `bug`, `security`, `vsrx-parity`

```
			dest := fw.FiltersInet
			if af == "inet6" {
				dest = fw.FiltersInet6
			}

			for _, filterInst := range namedInstances(afNode.FindChildren("filter")) {
				filter := &FirewallFilter{Name: filterInst.name}
```

**Runtime trace**

Import a Junos config carrying `firewall { family inet { filter f1 { term t { from source-address 10.0.0.0/8; then discard; } } } family mpls { filter f1 { term t { then accept; } } } }`. compileFirewall's family loop computes af="mpls" but the dest selection only distinguishes inet6, so the mpls filter compiles into fw.FiltersInet and `dest[filter.Name] = filter` (line 223) replaces the genuine IPv4 f1. PROBE AT HEAD: strict CompileConfig + SchemaValidate both pass ('SchemaValidate2 OK') and the surviving inet f1 term is `src=[] action=accept` — the authored IPv4 discard with source scoping became an unconditional accept. Junos treats each family as a separate filter namespace, so same-name filters across families are legal and common in real configs. Even without a collision, a `family any` filter (Junos: applies to all families) silently becomes IPv4-only.

**Why it matters** — A clean commit that swaps a discard filter for an accept-all is a direct security fail-open triggered by legal Junos input. The family fold also violates namespace semantics vSRX guarantees, so real-config imports are corrupted rather than rejected.

**Fix direction** — Restrict compilation to af in {inet, inet6} and hard-reject (or lenient-warn per the #1960 doctrine) any other family token at commit — same pattern as validateUnsupportedInterfaceStanzasAST; `family any` should be rejected with a clear 'unsupported family' error until it can be compiled into both tables under collision-checked names.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for 'family any', 'family mpls', 'firewall family', 'ethernet-switching' — zero hits. Nearest relatives are the #3307 unknown-from-leaf gate and #2399 unknown-then gate (token-level fail-closed inside a term); this is a family-level namespace fold with an overwrite mechanism no prior issue covers.

---

#### F-031 · Per-unit tunnel inheritance copies the shared interface-level TunnelConfig by value — the unit tunnel inherits sibling units' addresses (duplicate IPs on two tunnel netdevs) and aliases WgPeers/Addresses slices

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-ifaces-cos-fw`  ·  **Location:** `pkg/config/compiler_interfaces.go`:236
- **Labels:** `bug`

```
				tc := &TunnelConfig{Name: linuxName, Mode: defaultMode}
				// Inherit from interface-level tunnel if present
				if ifc.Tunnel != nil {
					*tc = *ifc.Tunnel
					tc.Name = linuxName
				}
```

**Runtime trace**

Config: `gr-0/0/0 { tunnel { source S; destination A; } unit 0 { family inet address 10.0.0.1/30; } unit 1 { tunnel { destination B; } family inet address 10.0.1.1/30; } }`. Unit 0 compiles first and (line 496) appends 10.0.0.1/30 to ifc.Tunnel.Addresses. Unit 1 has its own tunnel block, so line 236 `*tc = *ifc.Tunnel` shallow-copies the WHOLE struct — including the Addresses slice header that already carries unit 0's address — then line 493 appends unit 1's own address. PROBE AT HEAD: `unit 1 tunnel: name=gr-0-0-0u1 ... addrs=[10.0.0.1/30 10.0.1.1/30]`. At apply, pkg/routing/tunnel.go:851 reconciles tc.Addresses onto the netdev, so 10.0.0.1/30 is assigned to BOTH gr-0-0-0 and gr-0-0-0u1: two identical connected /30 routes on different devices, nondeterministic egress selection, and traffic for unit-0's subnet can be encapsulated toward destination B (cross-tunnel leak). The same shallow copy aliases the WgPeers backing array between the interface tunnel and every per-unit tunnel, so later appends on one config object can clobber the other's peers.

**Why it matters** — The compiled dataplane/kernel state diverges from the authored config with no error: duplicate addresses across tunnel interfaces cause route ambiguity and traffic egressing the wrong encrypted/encapsulated path — a correctness and potential confidentiality problem on a firewall.

**Fix direction** — Inherit only scalar endpoint properties (Source, Destination, Mode, Key, TTL, keepalives, RoutingInstance, WG scalar fields) with an explicit field copy; never copy Addresses (unit addresses are appended per-unit at line 491) and deep-copy or exclude WgPeers. Extract one shared tunnel-property parser so the interface-level and unit-level switches cannot diverge (see refactor finding).

**Not a duplicate** — Searched issues-all.txt for 'tunnel'+'unit': #1904 (daemon binds literal .N names for unit>0 tunnels — bind-time, different), #1873/#1884/#1919 (endpoint IDs/anchors/address leaks — runtime reconcile). No issue or prior finding covers compile-time cross-unit address inheritance via the shallow struct copy.

---

#### F-032 · No commit gate for the NAT64 `prefix` value: a non-/96 or malformed prefix commits green, then the Rust helper rejects the ENTIRE forwarding rebuild — the whole commit (and every later one until fixed) never reaches the dataplane

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-nat`  ·  **Location:** `pkg/config/compiler_nat.go`:789
- **Labels:** `bug`, `vsrx-parity`

```
func compileNAT64(node *Node, sec *SecurityConfig) error {
	for _, inst := range namedInstances(node.FindChildren("rule-set")) {
		rs := &NAT64RuleSet{Name: inst.name}

		for _, child := range inst.node.Children {
			switch child.Name() {
			case "prefix":
				rs.Prefix = nodeVal(child)
			case "source-pool":
				rs.SourcePool = nodeVal(child)
```

**Runtime trace**

Input: `set security nat nat64 rule-set N prefix 64:ff9b::/64` (or `/95`, or a typo like `64:ff9b:/96`). (1) The schema leaf (schema_security.go:455) is untyped — desc says 'must be /96' but there is no validator; SchemaValidate passes. (2) compileNAT64 stores the string verbatim (compiler_nat.go:789); NO strict validator anywhere checks it (validateNATHostMaskStrict covers only the NAT64 source-pool addresses; grep of compiler_validate_strict.go for nat64/96: nothing). Empirically verified: SchemaValidate+CompileConfig green with Prefix="64:ff9b::/64". (3) buildNAT64Snapshots forwards the raw string (pkg/dataplane/userspace/nat.go:1047-1052). (4) Rust Nat64State::try_from_snapshots hard-rejects anything but a parseable IPv6 with exactly /96 (userspace-dp/src/nat64.rs:247-266, SnapshotIntegrityError::Nat64UnparseableRule). (5) That error aborts the whole reconcile before publish: build_reconcile_forwarding (userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs:189-219) returns Err and 'the orchestrator aborts WITHOUT teardown or publish' — the prior forwarding generation stays live. Net effect: the operator's commit reports success, but NONE of the changes in that snapshot (policies, zones, other NAT — everything in the config snapshot) ever applies, and every subsequent commit keeps failing at apply until the NAT64 prefix is corrected; the only signals are helper logs and last_reconcile_stage=snapshot_integrity_error.

**Why it matters** — The repo's own doctrine (#2240, #3444, #3450) is that anything the dataplane will reject or drop must be rejected at commit/commit-check. A one-character NAT64 prefix typo silently freezes ALL dataplane config application on a production firewall while the CLI keeps reporting green commits — an especially confusing failure mode during incident response.

**Fix direction** — Add a validateNAT64PrefixStrict gate: prefix must parse as an IPv6 CIDR with prefix length exactly 96 (mirror the Rust classification: textual colon check + net.ParseCIDR + ones==96), hard-reject at commit, lenient-warn on load/peer-sync (#1960). Optionally also validate that a rule-set has a resolvable source-pool reference.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'nat64 prefix', '/96', 'Nat64Unparseable', 'snapshot integrity': #2212 (Rust-side fail-closed parse — the helper half, CLOSED) and #2291/#2214 (pool fallthrough / JSON null) are the nearest; none adds the Go commit-time gate, and the #2212 fix is precisely what turned this from silent-drop into whole-reconcile-abort, making the missing Go gate consequential in a new way.

---

#### F-033 · SNAT pool `port` stanza: Junos-native `port range <low> to <high>` and `port no-translation` are silently ignored (defaults 1024-65535 PAT applied), and out-of-range/reversed low/high values commit green then kill the rule at runtime

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-nat`  ·  **Location:** `pkg/config/compiler_nat.go`:1058
- **Labels:** `vsrx-parity`, `bug`

```
			case "port":
				// "port range low N high M" or "port N"
				if len(prop.Keys) >= 6 && prop.Keys[1] == "range" &&
					prop.Keys[2] == "low" && prop.Keys[4] == "high" {
					if v, err := strconv.Atoi(prop.Keys[3]); err == nil {
						pool.PortLow = v
					}
					if v, err := strconv.Atoi(prop.Keys[5]); err == nil {
						pool.PortHigh = v
					}
				} else if v := nodeVal(prop); v != "" {
```

**Runtime trace**

(a) Junos grammar: real vSRX syntax is `set security nat source pool P port range 5000 to 6000` and `set ... port no-translation`. xpf only recognizes its own `port range low N high M` spelling (documented in docs/deterministic-nat-cgnat.md:21). For the Junos form, Keys=[port,range,5000,to,6000] fails the low/high pattern; the fallback nodeVal(prop) returns "range" (compiler_applications.go:684-687 returns Keys[1]), Atoi fails, and PortLow/PortHigh stay 0 -> defaulted to 1024/65535 at compiler_nat.go:1181-1186. Empirically verified: `port range 5000 to 6000` compiles green with portLow=1024 portHigh=65535; `port no-translation` likewise compiles green with full PAT 1024-65535. Runtime effect: SNAT allocates translated source ports from the WRONG range (breaking upstream port-based ACLs/compliance logging), and a no-translation pool (needed for protocols requiring a preserved source port) still gets ports rewritten. (b) Missing strict gate: with the xpf spelling, `port range low 6000 high 5000` or `high 70000` also commits green — there is no SNAT analogue of validateDNATPoolStrict (#3450). The snapshot builder only slog.Warns and marks the rule PoolUnusable (pkg/dataplane/userspace/nat.go:199-206, sourceNATPoolPortRange at 491-507), and the Rust side returns SourceNatLookup::Unavailable (source.rs:825-827) — every flow matching the rule is dropped fail-closed after a green commit.

**Why it matters** — This is a Junos-syntax-clone project: pasting a working vSRX pool config silently degrades to default-PAT behavior with no commit error — an actively wrong translation identity, not a fail-closed stop. The unvalidated low/high case is a silent runtime outage (rule drops all matching flows) that DNAT pools were already hardened against in #3450, so the strict-gate coverage is asymmetric.

**Fix direction** — Accept the Junos `range <low> to <high>` token shape (and either implement or hard-reject `no-translation` and other unrecognized `port ...` tokens instead of silently defaulting), and add a validateSNATPoolPortStrict gate (1<=low<=high<=65535) mirroring validateDNATPoolStrict, lenient-warn on load/peer-sync per #1960/#1979.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'port range', 'pool port', 'no-translation', 'low high', 'unusable': #3449/#3446 are DNAT match destination-port; #3450 is the DNAT pool port gate (SNAT pool was not covered); #3049 is pool ADDRESS expansion. No issue covers the SNAT pool port grammar or a strict range gate; known-gaps.md NAT entries (#1448-1450, #645, #2218) are unrelated.

---

#### F-034 · #2008/#2051 display-set round-trip is broken for deactivated multi-value leaves: FormatSet emits `deactivate <full list>` but DeactivatePath/deletePath lack SetPath's #2419 absorb and fail with 'container does not exist' on replay

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-parse`  ·  **Location:** `pkg/config/ast_edit.go`:469
- **Labels:** `bug`, `vsrx-parity`, `test-gap`

```
	if i >= len(path) {
		// No more tokens: this node itself is the target.
		return markMatchingNodeInactive(current, nodeKeys, inactive)
	}

	// More tokens remain: find matching container and descend.
	for _, n := range *current {
		if !n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
			return setInactiveAtPath(&n.Children, path, childSchema, i, inactive)
		}
	}

	return fmt.Errorf("path not found: container %q does not exist", strings.Join(nodeKeys, " "))
```

**Runtime trace**

Config holds leaf Keys=[protocol tcp udp] (bracket list), deactivated. FormatSet (ast_format.go:219-231, per #2008 H1 contract 'Loading such output replays the set then the deactivate, restoring the Inactive flag') emits `set ... from protocol tcp udp` + `deactivate ... from protocol tcp udp`. Replay (configstore LoadSet -> applyEditLine -> ParseSetVerb verb=deactivate -> DeactivatePath): setInactiveAtPath consumes schema leaf {args:1} into nodeKeys=[protocol,tcp]; token `udp` remains -> it searches for a CONTAINER Keys=[protocol,tcp] -> none exists (the node is a leaf) -> error. Empirically confirmed (probe 10): replaying the tool's own FormatSet output fails `replay deactivate err: path not found: container "protocol tcp" does not exist`, and the resulting tree has the leaf ACTIVE — the deactivation is silently lost if the caller ignores per-line errors, or `load set` aborts if it doesn't. deletePath has the identical hole: `delete ... from protocol tcp udp` (the exact full-path spelling FormatSet prints) also errors, so the only accepted delete spelling is the prefix form that over-deletes (finding 1). SetPath solved exactly this with its case-(b) trailing-value absorb (ast_edit.go:260-300); the two sibling traversals never got it.

**Why it matters** — The #2008/#2051 design guarantee — `show | display set` output is replayable and restores Inactive — is violated for every deactivated bracket-list leaf; config export/import and set-mode replay of such configs either error out or silently re-activate a statement the operator deactivated, changing enforcement behavior.

**Fix direction** — Factor SetPath's multi-leaf trailing-value absorb into a shared helper and use it in deletePath and setInactiveAtPath so all three schema-driven traversals tokenize identically; add a round-trip test that FormatSet output replays cleanly for inactive multi-value leaves.

**Not a duplicate** — Searched for deactivate/activate/inactive/display set: #2008 H1 and #2051 IMPLEMENTED the verbs and explicitly claim round-trippability; #2419/#3703 fixed the absorb only in SetPath. No issue/finding covers the missing absorb in setInactiveAtPath/deletePath breaking the documented replay contract — a genuinely new residual shape of the #2419 class, named per protocol.

---

#### F-035 · Annotations are emitted verbatim into /* */ block comments — an annotation containing */ silently injects tokens/statements into the re-parsed config on HA sync and rollback reload (and all annotations are dropped on any text round-trip)

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-parse`  ·  **Location:** `pkg/config/ast_format.go`:135
- **Labels:** `bug`, `security`, `ha`, `vsrx-parity`

```
	for _, n := range nodes {
		if n.Annotation != "" {
			fmt.Fprintf(b, "%s/* %s */\n", prefix, n.Annotation)
		}
		if n.IsLeaf {
			fmt.Fprintf(b, "%s%s%s;\n", prefix, inactivePrefix(n), n.QuotedKeyPath())
```

**Runtime trace**

Operator runs `annotate system host-name "temp */ system services telnet"` -> cli_dispatch.go:375 -> Store.Annotate stores the comment with NO content validation (freetext.go #1798 only rejects CONTROL characters at commit; `*/` is printable). Format() emits `/* temp */ system services telnet */` -> on the HA standby (handleConfigSync -> SyncApply -> NewParser) the lexer closes the comment at the FIRST `*/` and the remaining tokens become config: empirically confirmed (probe) — the standby tree becomes `system { system services telnet */ host-name fw0; ... }`: the injected tokens and the victim `host-name fw0` leaf are fused into one junk statement with ZERO parse errors, so the standby silently applies a corrupted config (host-name lost). A crafted annotation ending in `/*` can additionally comment out the following real statement. The same corruption round-trips through rollback files (store_commit.go:537/616). Separately, because the parser skips comments and never re-attaches them, ALL annotations are silently lost on the standby and in every rollback slot even when benign.

**Why it matters** — Config annotations are an operator-facing feature whose content flows unescaped into a re-parsed serialization surface used by HA sync and rollback — silent cross-node config divergence in an HA firewall pair, with no error anywhere.

**Fix direction** — Reject or escape `*/` (and leading `/*`) in Store.Annotate and in formatNodes (e.g. render annotations with each `*/` broken as `*\/` or emit Junos-style `/* ... */` with sanitization); longer term, re-attach leading block comments to the following node at parse time so annotations survive the text round-trip like Junos.

**Not a duplicate** — Searched issues-all.txt for annotate/annotation/comment and prior-findings.md likewise: zero hits for annotation handling. #1798 (control chars in values AND annotations) is the nearest but only covers C0/DEL bytes — `*/` is printable and passes all three #1798 layers; the comment-terminator injection mechanism is new.

---

#### F-036 · RenamePath cannot rename any non-first sibling: removeNode takes the FIRST first-key match instead of preferring full-key matches, so `rename ... policy second to policy X` fails 'source not found'

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-parse`  ·  **Location:** `pkg/config/ast.go`:298
- **Labels:** `bug`, `vsrx-parity`, `refactor`

```
		for i, child := range *parentChildren {
			consumed := matchNodeKeys(child, path, pos)
			if consumed > 0 {
				bestChild = child
				bestConsumed = consumed
				bestIdx = i
				break
			}
		}
```

**Runtime trace**

Tree: from-zone trust to-zone untrust { policy first {...} policy second {...} }. Operator: `rename security policies from-zone trust to-zone untrust policy second to policy renamed` -> Store.Rename -> RenamePath -> removeNode. At the policy level, the loop calls matchNodeKeys(child=[policy first], path, pos): Keys[0]=="policy" matches, Keys[1]="first" != "second" -> returns 1 ("still a 1-key match") -> consumed>0 -> break IMMEDIATELY (no best-match comparison, unlike findNodeWithParent which was explicitly fixed for 'siblings like [policy first], [policy second]'). pos+1 < len(path) so it descends INTO [policy first].Children looking for a child named "second" -> not found -> RenamePath returns `source not found`. Empirically confirmed (probe 3): rename errs 'source not found: security policies ... policy second' while CopyPath of the same path succeeds (it uses findNodeWithParent's best-match loop). Only the alphabetically/positionally FIRST sibling of any named collection (policies, zones, terms, rules) can ever be renamed.

**Why it matters** — The Junos `rename` config command — routine for reordering/renaming policies in place — is broken in the common case (more than one policy/term/rule under a parent) on a firewall whose primary object model is named siblings; the identical bug pattern was already found and fixed in findNodeWithParent but removeNode kept the first-match break.

**Fix direction** — Make removeNode use the same prefer-longest-consumed scan as findNodeWithParent (or reimplement removeNode via findNodeWithParent + index removal); add a rename-non-first-sibling regression test.

**Not a duplicate** — Searched issues for rename/copy/insert: #3735 (ddns provider rename), #2944/#847 (interface/VRF renames) are unrelated subsystems; no tracker issue or prior finding touches ConfigTree.RenamePath/removeNode. The findNodeWithParent comment shows the sibling-collision class was known and fixed there only — this is the unfixed twin.

---

#### F-037 · navigatePath's single-key branch returns only the FIRST matching node, so `show configuration <path>` ending at a repeated keyword (name-server, security-zone, ...) silently hides all other instances across text/set/json/xml renderers

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-parse`  ·  **Location:** `pkg/config/ast.go`:209
- **Labels:** `bug`, `vsrx-parity`

```
		// Single-key match.
		found := false
		for _, n := range current {
			if len(n.Keys) > 0 && n.Keys[0] == keyword {
				i++
				if i >= len(path) {
					return []*Node{n}
				}
				current = n.Children
				found = true
				break
```

**Runtime trace**

Config: `set system name-server 8.8.8.8` + `set system name-server 8.8.4.4` (two sibling leaves). Operator: `show configuration system name-server` -> configstore ShowActivePath -> FormatPath([system,name-server]) -> navigatePath: at `name-server`, i+1 >= len(path) so the pair-match branch (which returns ALL matches) is skipped; the single-key branch takes the FIRST leaf and returns []*Node{n}. Empirically confirmed (probe 4): output is only `name-server 8.8.8.8;` — 8.8.4.4 is not displayed; FormatPathSet prints only one `set` line; same truncation for `show configuration security zones security-zone` (only zone `trust` shown, `untrust` hidden). The identical navigatePath feeds FormatPath, FormatPathSet, FormatPathJSON, FormatPathXML and FormatPathInheritance, so every path-scoped display surface (local CLI, remote CLI, gRPC/REST show-config) under-reports the active security config.

**Why it matters** — An operator auditing a firewall by path (`show configuration security zones security-zone`, `... system name-server`) is shown a strict subset of what is actually enforced — dangerous when verifying zone or DNS posture; vSRX displays all instances for a keyword-terminated path.

**Fix direction** — Make the single-key terminal case collect ALL children whose Keys[0]==keyword (mirroring the multi-key branch's return of `matched`), and when descending with remaining path, iterate every first-key match rather than breaking on the first.

**Not a duplicate** — Searched for name-server/display/show configuration truncation: #1810 (name-server SetPath replace, fixed) is the nearest tracker item but concerns storage, not display; prior findings on display gaps are all in cli/grpc presenters (e.g. #3672 policy fields), none in navigatePath. New mechanism.

---

#### F-038 · IKE dead-peer-detection: bare statement disables DPD entirely, and an interval/threshold-only block sets the DPD mode to the literal string "interval" — dpd_action silently degrades to strongSwan's clear

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-routing-services`  ·  **Location:** `pkg/config/compiler_ipsec.go`:197
- **Labels:** `bug`, `vsrx-parity`

```
	if v := nodeVal(node); v != "" {
		gw.DeadPeerDetect = v
	}

	for _, c := range node.Children {
		switch c.Name() {
		case "always-send", "optimized", "probe-idle-tunnel":
			gw.DeadPeerDetect = c.Name()
...
	if gw.DeadPeerDetect == "" && (len(node.Children) > 0 || len(node.Keys) > 1) {
		gw.DeadPeerDetect = "always-send"
	}
```

**Runtime trace**

Shape (b): `set security ike gateway hub-gw dead-peer-detection interval 10` + `... threshold 3` → the dead-peer-detection node has Keys=["dead-peer-detection"] and children [interval, threshold]. parseDeadPeerDetectionNode line 197: nodeVal(node) falls back to Children[0].Name() (compiler_applications.go:688-690) → gw.DeadPeerDetect="interval"; the children loop then fills DPDInterval/DPDThreshold, and the line-216 default-to-"always-send" guard is skipped because DeadPeerDetect is non-empty (that guard is dead code for ANY node with children). deriveDPD (pkg/ipsec/ike.go:153-172): switch on "interval" hits default → action="" (EstablishTunnels != immediately) → policy.go:195-196 omits dpd_action → strongSwan applies its default (clear): after a transient peer outage the SA is torn down and never re-initiated — a silently-down tunnel — instead of the restart the compiler's own "always-send" default intends. Shape (a): a bare `dead-peer-detection;` leaf has no children and 1 key → line 216 guard also fails → DeadPeerDetect stays "" → deriveDPD (ike.go:139-141) returns zero dpdSettings → no dpd_delay rendered → DPD is entirely OFF despite being configured (Junos enables optimized-mode DPD for the bare statement).

**Why it matters** — DPD is the liveness mechanism that recovers IPsec tunnels after peer reboots/path failures; both shapes make a committed DPD config either inert or downgrade its recovery action, producing tunnels that stay down until manual intervention on a production VPN appliance.

**Fix direction** — In parseDeadPeerDetectionNode, only accept nodeVal(node) as a mode when it is one of the known mode keywords (always-send/optimized/probe-idle-tunnel); treat interval/threshold/other child names as non-modes so the always-send fallback fires; make the bare `dead-peer-detection` statement also set the default mode (drop the len(Children)>0||len(Keys)>1 gate or extend it to the bare case).

**Not a duplicate** — Grepped 'dead-peer', 'dpd': only #156 (closed: all modes collapsed to hardcoded dpd_delay=10) — that fix ADDED interval/threshold parsing, which is what created this residual: the mechanism here is nodeVal's first-child-name fallback misclassifying a child leaf as the DPD MODE plus the dead default guard, a new shape not covered by #156 or any prior finding.

---

#### F-039 · IKE gateway `version` and IKE policy `mode` are untyped free-form leaves — a typo silently weakens crypto posture (v2-only pin lost, aggressive→main fallback)

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-schema`  ·  **Location:** `pkg/config/schema_security.go`:713
- **Labels:** `bug`, `security`, `vsrx-parity`

```
			"version":            {desc: "IKE version (v1-only|v2-only)", args: 1, placeholder: "<version>", children: nil},
			"no-nat-traversal":   {desc: "Disable NAT traversal (UDP encapsulation)", children: nil},
			"nat-traversal":      {desc: "NAT traversal (enable|disable|force)", args: 1, placeholder: "<mode>", children: nil},
```

**Runtime trace**

(1) Operator commits `set security ike gateway gw1 version v2only` (or `ikev2`, `2`). The schema leaf is untyped (no validator), so SchemaValidate passes and compiler_ipsec.go:123 stores the raw string. (2) The swanctl renderer (pkg/ipsec/policy.go:93-97) pins the IKE version ONLY on exact matches: `if gw.Version == "v2-only" { version = 2 } else if gw.Version == "v1-only" { version = 1 }` — any other spelling emits NO version line, so strongSwan defaults to accepting BOTH IKEv1 and IKEv2. A config that intended to forbid IKEv1 (downgrade-resistance) silently accepts it. (3) Same class for `mode`: resolveIKESettings (pkg/ipsec/ike.go:56) computes `aggressive = ikePol.Mode == "aggressive"`; a typo ('agressive', 'Aggressive') silently negotiates main mode. nat-traversal ('enable|disable|force') and vpn `establish-tunnels`/`df-bit` follow the same exact-string-match pattern. This is precisely the enum-typo silent-fallback class this module already closed for security log (#3349), RA preference (#2497), poll-mode/rss-indirection (#1319 PR3) — the IKE/IPsec enum-ish leaves were left behind.

**Why it matters** — Silent IKE-version un-pinning is a downgrade-attack surface on a security appliance; the schema already has the exact machinery (ValueEnumOf + ValidateEnum) used on a dozen sibling leaves.

**Fix direction** — Type the closed-vocabulary IKE/IPsec leaves: version → ValidateEnum([v1-only, v2-only]), mode → ValidateEnum([main, aggressive]), nat-traversal → ValidateEnum([enable, disable, force]), establish-tunnels/df-bit similarly, on both the ike and ipsec gateway subtrees (schema_security.go:703-715, 769-771, 787-788). Keep algorithm leaves untyped per the documented renderer-normalization rationale.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'ike', 'version', 'aggressive', 'enum', 'mode'. #2270/#2073 cover dangling proposal references; #3349/#2497 established the enum-typing pattern on OTHER subsystems; #2277/#2279 added IKE chain reference validation only. No issue or prior finding covers untyped version/mode/nat-traversal enum leaves.

---

#### F-040 · IKE/IPsec policy `proposals [ a b ]` leaf-list truncates to the first proposal (silent crypto-negotiation narrowing)

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-schema`  ·  **Location:** `pkg/config/schema_security.go`:704
- **Labels:** `bug`, `vsrx-parity`, `ipsec`

```
		"policy": {desc: "IKE policy name", args: 1, placeholder: "<policy-name>", children: map[string]*schemaNode{
			"mode":           {desc: "IKE phase 1 mode (main|aggressive)", args: 1, placeholder: "<mode>", children: nil},
			"proposals":      {desc: "IKE proposal reference", args: 1, placeholder: "<proposal-name>", children: nil},
			"pre-shared-key": {desc: "Pre-shared key (ascii-text <key>)", children: nil},
		}},
```

**Runtime trace**

Junos `proposals` is a leaf-list; vSRX renders multi-proposal policies as `proposals [ prop-a prop-b ];`. (1) Hierarchical parse of `security { ike { policy pol1 { proposals [ prop-a prop-b ]; } } }` collapses the bracket list onto one leaf Keys=["proposals","prop-a","prop-b"]. (2) compileIKE (compiler_ipsec.go:76) does `pol.Proposals = v` where v = nodeVal(p) = Keys[1] = "prop-a" — IKEPolicy.Proposals is a scalar string, prop-b is silently discarded. Empirically confirmed at HEAD: proposals="prop-a". (3) The renderer resolves a single name (pkg/ipsec/ike.go:57 `cfg.IKEProposals[ikePol.Proposals]`), so swanctl gets one transform set. Same shape for Phase 2: schema_security.go:761 `proposals` under ipsec policy, compiler_ipsec.go:266 `pol.Proposals = v`. (4) Flat-set repeated lines are also lossy: `proposals` is args:1 non-multi children:nil, so the SetPath replace branch (ast_edit.go:196) makes a second `set ... proposals prop-b` REPLACE prop-a. Observable behavior: a peer that only accepts the second proposal fails IKE negotiation; a config intending a preference-ordered proposal list silently offers only the first — with no commit warning (the #2277 chain validator validates the single surviving name and passes).

**Why it matters** — Multi-proposal IKE/IPsec policies are common in real vSRX estates (migration windows, mixed-peer hubs). Silent truncation either breaks tunnel establishment with no diagnostic or unknowingly narrows the offered crypto suites.

**Fix direction** — Model `proposals` as a multi value-tail leaf (multi:true, children:nil) in both ike and ipsec policy subtrees, change IKEPolicy.Proposals/IPsecPolicyDef.Proposals to []string read via firewallMatchValues, and render comma-joined swanctl proposal lists (strongSwan supports proposal lists natively). Extend the #2277 chain validator to check every referenced name.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'proposal', 'ike', 'ipsec'. Nearest: #2270 [CLOSED] broken ike-policy chain emits no proposals (dangling reference, different mechanism), #2073 (missing reference drops PFS), #2639/#2604/#2392 (dh-group parsing/rendering). No prior issue covers multi-proposal leaf-list truncation; #2419/#3703 bracket-collapse fixes never touched these leaves.

---

#### F-041 · List-valued system leaves (ntp server, archival archive-sites, ssh-rsa/ed25519/dsa authorized keys) modeled single-value — a second flat-set silently deletes the first

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-schema`  ·  **Location:** `pkg/config/schema_system.go`:87
- **Labels:** `bug`, `vsrx-parity`, `config-loss`

```
	"ntp": {desc: "NTP configuration", children: map[string]*schemaNode{
		"server": {desc: "NTP server", args: 1, placeholder: "<address>", children: nil},
		"threshold": {desc: "Threshold", args: 1, placeholder: "<seconds>", children: map[string]*schemaNode{
			"action": {desc: "Action on threshold", args: 1, placeholder: "<action>", children: nil},
		}},
	}},
```

**Runtime trace**

Compilers treat all of these as append-lists: compiler_system.go:64-67 `for _, ntpChild := range child.FindChildren("server") { sys.NTPServers = append(...) }`, :163 `for _, asNode := range cfgNode.FindChildren("archive-sites")`, :106/:145 `SSHKeys = append(...)`. But the schema marks each leaf args:1, multi:false, children:nil, so SetPath's replace branch (ast_edit.go:196-220: `childSchema.args > 0 && !childSchema.multi && childSchema.children == nil` filters on `n.Keys[0] == nodeKeys[0]`) REPLACES the existing leaf. Empirically confirmed at HEAD: after `set system ntp server 1.1.1.1` + `set system ntp server 2.2.2.2`, the tree holds only `server 2.2.2.2` and CompileConfig yields NTPServers=[2.2.2.2]; likewise ArchiveSites=[scp://b...] and RootAuthentication.SSHKeys=[KEY-TWO] after two sets each. Observable behavior: an operator adding a second NTP server / archive site / authorized SSH key via the CLI silently loses the first (a locked-out admin whose old key vanished, single-NTP time source, single archive target); a `show | display set` dump of a hierarchical multi-entry config re-imported via load-set collapses to the LAST entry only. Junos appends to leaf-lists / named statements in all three cases.

**Why it matters** — Silent config loss on the interactive commit path for security-relevant objects (authorized SSH keys) and resilience objects (NTP redundancy, archival). The hierarchical file form works, making the flat-set loss especially hard to notice.

**Fix direction** — Mark `system ntp server`, `system archival configuration archive-sites`, and the ssh-rsa/ssh-ed25519/ssh-dsa leaves under root-authentication AND login user authentication (schema_system.go:64-66, 132-134) as multi:true (compilers already accumulate via FindChildren and read Keys[1], so also route them through firewallMatchValues to absorb the value-tail shape). Add a SetPath golden covering repeated sets on each.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'ntp', 'archive', 'ssh-rsa', 'name-server', 'multi'. This is the residual of the #1810 class ('setSchema models system name-server as single-value — second set REPLACES the first', CLOSED): #1810 fixed only name-server (verified multi:true at HEAD); ntp server / archive-sites / ssh-key leaves have the identical mechanism and were never converted. #148 (ntp threshold action ignored) is unrelated.

---

#### F-042 · policy-options prefix-list body values collapse: single-line bracket form compiles an EMPTY prefix-list; flat one-line form keeps only the first prefix

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-schema`  ·  **Location:** `pkg/config/schema_routing.go`:130
- **Labels:** `bug`, `vsrx-parity`, `routing`

```
var schemaPolicyOptions = &schemaNode{desc: "Policy options", children: map[string]*schemaNode{
	"prefix-list": {desc: "Prefix list", args: 1, placeholder: "<name>", children: nil},
	"community": {desc: "Community", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
		"members": {desc: "Community members", args: 1, multi: true, placeholder: "<community>", children: nil},
	}},
```

**Runtime trace**

compilePolicyOptions (compiler_routing.go:362-372) reads prefix-list entries ONLY from instance children: `for _, entry := range inst.node.Children { pl.Prefixes = append(pl.Prefixes, entry.Keys[0]) }`. Empirically confirmed at HEAD: (1) hierarchical `prefix-list pl1 [ 10.0.0.0/24 10.1.0.0/24 ];` — the lexer strips brackets, so BOTH prefixes land on the instance node's own Keys (["prefix-list","pl1","10.0.0.0/24","10.1.0.0/24"]) with zero children → compiled Prefixes=[] (EMPTY — even the first prefix is lost). (2) flat `set policy-options prefix-list pl2 10.0.0.0/24 10.1.0.0/24` — SetPath descends into container ["prefix-list","pl2"], the schema below is children:nil/wildcard:nil so the remaining tokens form ONE child leaf Keys=["10.0.0.0/24","10.1.0.0/24"]; the compiler reads entry.Keys[0] only → Prefixes=[10.0.0.0/24], second prefix dropped. No commit diagnostic in either case (the #2506 strict validator checks only dangling REFERENCES). Observable behavior: a firewall-filter or routing policy `from prefix-list pl1` matches nothing (empty FRR prefix-list / empty filter set) — route filtering or packet matching silently disabled; the normal multi-line forms (one prefix per hierarchical statement or per set line) still work, hiding the loss.

**Why it matters** — Prefix-lists gate route import/export and firewall-filter matching; an unexpectedly-empty list fails open or closed depending on policy polarity, silently.

**Fix direction** — In compilePolicyOptions, also consume inst.node.Keys[2:] as prefixes (mirroring compileDHCPRelay server-group's dual read of Keys[2:] + child.Keys...), and read each child's full Keys instead of Keys[0]. Optionally add a commit warning for an empty prefix-list. Anchor tests on both single-line shapes.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'prefix-list', 'bracket', '#2419'. Nearest: #2689 [CLOSED] 'from community / from prefix-list bracket-list collapses' — that fixed policy-statement FROM-clause REFERENCES (multi:true reader); this defect is the prefix-list DEFINITION body, a different node and reader (compiler_routing.go:368). #2506 validates references only. #3703's unfixed-leaves framing applies: this surface was never converted.

---

#### F-043 · validateMultiValueLeaf treats the literal token 'to' as a range separator on EVERY typed multi leaf — validation bypass lets 'to' commit as a DNS name-server / VRRP VIP / session-log mode

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-schema`  ·  **Location:** `pkg/config/schema_walk.go`:584
- **Labels:** `bug`, `security`, `test-gap`

```
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
```

**Runtime trace**

The 'to' skip exists for range leaves (`destination-port 20000 to 20003`), but every typed multi leaf shares validateMultiValueLeaf, and NONE of the currently-typed multi leaves legitimately takes a range: system name-server (ValidateIPAddress), vrrp-group virtual-address (ValidateIPv4/IPv6CIDR), RA dns-server-address (ValidateIPv6Address), and the #3703 sessionLogModeLeaf enum (then log / then deny log / default-policy-log / pre-id-default-policy then log). Empirically confirmed at HEAD: (1) `set system name-server 8.8.8.8 to 8.8.4.4` — SchemaValidate PASSES ('to' skipped as separator), then compiler_system.go name-server reads firewallMatchValues → NameServers=[8.8.8.8 to 8.8.4.4]; the literal string 'to' is written into the resolver drop-in by pkg/daemon/daemon_dns.go — exactly the 'garbage server string silently produced broken DNS configuration' the typed leaf was added to prevent (schema_system.go:41-43 comment). (2) `set security policies ... then permit` + `then log session-init to session-close` — SchemaValidate PASSES, while the control typo `log sesion-init` is correctly rejected: the #3703 strict unknown-token guarantee has a one-token hole. Observable behavior: garbage commits cleanly and silently corrupts runtime config (broken DNS resolution; unrecognized log token ignored).

**Why it matters** — The typed-leaf gate is this project's central defense against silently-corrupting values; a universal escape token undermines the exact guarantees documented on the affected leaves (#1319 PR3, #3703).

**Fix direction** — Make range-separator support opt-in per leaf (e.g. a `rangeValues bool` field on schemaNode set only on genuine range leaves) so validateMultiValueLeaf validates 'to' as an ordinary value everywhere else; alternatively require the leaf's validator to accept the neighboring tokens as a typed range. Add red tests for 'to' on name-server and sessionLogModeLeaf surfaces.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'validateMultiValueLeaf', 'separator', 'multi-value', 'name-server', '#3703'. #3703 (bracket-list collapse + strict validation on session-log surfaces) and #2419 are the nearest but cover list-value LOSS, not this validation-bypass token; no prior issue or finding mentions the 'to' skip. #1810/#2008 name-server work predates validateMultiValueLeaf.

---

#### F-044 · Refactor debt: 79-field lenient compileOpts literal duplicated verbatim in CompileConfigLenient and CompileConfigForNodeLenient with no drift guard; compileExpanded is ~2000 lines of copy-pasted downgrade blocks

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-validate`  ·  **Location:** `pkg/config/compiler.go`:1275
- **Labels:** `refactor`, `ha-risk`, `maintainability`

```
func CompileConfigLenient(tree *ConfigTree) (*Config, error) {
	return compileConfigWithOpts(tree, compileOpts{
		sanitizeFreeTextControlChars:         true,
		lenientVRRPTrackDuplicates:           true,
		lenientDeviceMap:                     true,
		lenientPolicyMatchAddress:            true,
```

**Runtime trace**

compileOpts (compiler.go:44) has 79 boolean fields. CompileConfigLenient (lines 1276-1356) and CompileConfigForNodeLenient (lines 1438-1518) each hand-list all 79 as true; I diffed the two lists at HEAD — currently identical, and no test pins them together (no reflect-based drift guard exists in pkg/config). Failure mode: a future gate #N adds lenientFooBar and sets it in CompileConfigLenient (Store.Load path) but forgets CompileConfigForNodeLenient (Store.SyncApply HA peer-sync + peer-interface display path). An upgraded standby then receives a peer-synced legacy config carrying the newly-gated construct: the load path on the primary tolerates it (warning), but SyncApply on the standby HARD-REJECTS -> the standby cannot apply the cluster config -> config split-brain across the HA pair during a rolling upgrade — precisely the #1960 no-brick scenario the flags exist for. Each of the ~70 call sites in compileExpanded also hand-rolls the identical 7-line 'if err != nil { if opts.lenientX { warn } else { return } }' block, so every new gate touches 3 places.

**Why it matters** — This module grows by one gate per review campaign (70+ so far); the duplication is the single most likely mechanism by which a future gate silently breaks HA rolling upgrades, and it makes the 3600-line compiler.go progressively unreviewable.

**Fix direction** — Introduce a single allLenientOpts() constructor used by both entry points (or make leniency a single enum: strict|tolerant, since every flag is set identically), and a table-driven []struct{validate func(*Config) error; lenient func(compileOpts) bool; label string} registry that compileExpanded iterates — plus a reflect-based test asserting every compileOpts field is exercised. Prefer a new pkg/config/validate/ module directory over more sibling compiler_validate_*.go files.

**Not a duplicate** — Grepped prior-findings.md for compileOpts/lenient-duplication/table-driven and issues-all.txt for compileOpts: no prior finding or issue covers the duplicated lenient-opts literals or proposes the validator registry; prior 'table-driven' findings are Rust policy test matrices (unrelated).

---

#### F-045 · ValidateConfig warn pass uses a stale policy-address token model: literal CIDR/IP, normalized any-ipv4/any-ipv6, and dynamic-address feed names all emit spurious 'not in address-book' warnings — which surface as active system ALARMS

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-validate`  ·  **Location:** `pkg/config/compiler_validate_warn.go`:151
- **Labels:** `bug`, `observability`

```
			for _, addr := range p.Match.SourceAddresses {
				if addr != "any" && !addrs[addr] {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: source-address %q not in address-book", p.Name, addr))
				}
			}
```

**Runtime trace**

Operator commits a valid policy `match source-address any-ipv4` (or a literal `10.0.0.0/24`, or a #3294 dynamic-address feed-binding name). compilePolicy normalizes any-ipv4 -> "0.0.0.0/0" into Match.SourceAddresses (compiler_security.go:628-630); the strict gate validatePolicyMatchAddressesStrict (compiler_validate_strict.go:1992-2004) accepts "any-ipv4"/"any-ipv6", literal ParseCIDR/ParseIP tokens, AND DynamicAddress.AddressBindings names — so the config commits cleanly and the userspace dataplane enforces the literal (capabilities.go:190-193). But ValidateConfig (called on EVERY compile at compiler.go:3470) only exempts the exact string "any" and only knows global address-book names, so it appends `policy "p": source-address "0.0.0.0/0" not in address-book` to cfg.Warnings on every commit. Worse: grpcapi showAlarms (server_show_system.go:110-118) and showSecurityAlarms (server_show_security_text.go:342-350) render every ValidateConfig warning as an ACTIVE ALARM — so a perfectly valid, fully-enforced config permanently shows security alarms in `show system alarms` / `show security alarms`.

**Why it matters** — Persistent false alarms on a security appliance train operators to ignore the alarm surface, masking real dangling-reference warnings; the warn pass and the strict gate disagreeing on the same token grammar is exactly the commit-check-vs-runtime divergence class this module exists to prevent (here warn-vs-strict).

**Fix direction** — Reuse the strict gate's token model in the warn pass: exempt "any"/"any-ipv4"/"any-ipv6", tokens that parse via net.ParseCIDR/net.ParseIP, and cfg.Security.DynamicAddress.AddressBindings names (or simply delete this warn loop — validatePolicyMatchAddressesStrict fully subsumes it, same as the #3296 filter-reference loop that was removed with a comment at line 386-392).

**Not a duplicate** — Grepped prior-findings.md and issues-all.txt for 'address-book', 'any-ipv4', 'not in address-book', 'spurious/false warning': nearest are #3294 (feed-in-policy strict/dataplane divergence — CLOSED, added the strict carve-out that this warn pass never learned) and prior warn-file findings about DDNS provider warnings; no prior finding covers the warn-pass/strict-gate token-model divergence or the alarm-surface amplification.

---

#### F-046 · WG peer `endpoint` accepted at commit in forms the Rust dataplane cannot parse (bare IP, port-stripped v6, out-of-range port) — peer silently degrades to responder-only

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-config-validate`  ·  **Location:** `pkg/config/compiler_validate_wireguard.go`:211
- **Labels:** `bug`, `commit-apply-split`, `vsrx-parity`

```
func endpointIsV6(endpoint string) (bool, error) {
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.To4() == nil, nil
		}
	}
	if ip := net.ParseIP(endpoint); ip != nil {
		return ip.To4() == nil, nil
	}
	return false, fmt.Errorf("endpoint %q is not an IP[:port] literal", endpoint)
}
```

**Runtime trace**

Operator commits `peer <key> endpoint 203.0.113.5` (no port), or a v6 endpoint as config TEXT (`endpoint [2001:db8::1]:51820` — the lexer strips brackets and inner-colon-splits, so per this function's own doc comment the value arrives as bare `2001:db8::1`, port LOST), or `endpoint 203.0.113.5:99999` (SplitHostPort does not range-check the port). endpointIsV6 classifies all three as valid (bare-IP acceptance is deliberate), validateOneWireguardTunnel only uses it for the outer-family gate -> commit SUCCEEDS. The endpoint string flows verbatim: WgPeerConfig.Endpoint -> TunnelEndpointSnapshot WgEndpoint (pkg/dataplane/userspace/tunnels.go:147) -> Rust hydrate_wg_identity does `wire.wg_endpoint.parse::<SocketAddr>().ok()` (userspace-dp/src/afxdp/forwarding_build/tunnels.rs:249-253): a bare IP / portless / port>65535 string FAILS SocketAddr parse and `.ok()` swallows it -> endpoint = None -> the peer is treated as RESPONDER-ONLY. Observable: the local node never initiates a handshake and persistent-keepalive has no target; if the remote peer is behind NAT or also configured to wait, the tunnel never establishes — with a clean commit and no warning. Every text-authored (hierarchical-config) v6 endpoint hits this unconditionally because the port is stripped at parse.

**Why it matters** — The operator explicitly configured an endpoint precisely to make this node the initiator; silently discarding it inverts the connection topology. For the v6 case this is not even an operator error — a correctly-typed config is silently broken by the lexer, and the commit gate (which knows about the stripping, per its own comment) blesses it instead of flagging that initiation will be lost.

**Fix direction** — In validateOneWireguardTunnel, reject (strict)/warn (lenient) an endpoint the dataplane cannot use to initiate: require host:port with port 1..65535 for v4; for the v6 bare-host shape either reject with a message explaining the port was lost and no initiation will occur, or fix the pipeline (store host+port separately / have the snapshot builder append a port) so a v6 endpoint round-trips. At minimum validate the port range that SplitHostPort ignores.

**Not a duplicate** — Grepped issues-all.txt for 'endpoint' and prior-findings for endpoint/responder: #2995 (scope_id EINVAL on send), #2845 (PMTU per-endpoint), #2836 (peer-table atomicity) are runtime WG endpoint issues; none covers commit accepting an endpoint the SocketAddr parse drops to responder-only. The function's own comment calls the port-strip 'a pre-existing parser limitation, orthogonal to #1434' but no tracker issue exists for it.

---

#### F-047 · Bare commit while a confirm is pending returns success WITHOUT committing staged candidate edits, on all three service surfaces (gRPC/REST/CLI)

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-configstore`  ·  **Location:** `pkg/grpcapi/server_config.go`:188
- **Labels:** `bug`, `vsrx-parity`

```
func (s *Server) Commit(ctx context.Context, req *pb.CommitRequest) (*pb.CommitResponse, error) {
	// If a confirmed commit is pending, confirm it
	if s.store.IsConfirmPending() {
		if err := s.store.ConfirmCommit(); err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		return &pb.CommitResponse{}, nil
	}
```

**Runtime trace**

1) Operator: `commit confirmed 10` (window opens). 2) Operator stages MORE edits in the candidate (Set/Delete — allowed, dirty=true). 3) Operator issues plain `commit` to lock everything in: gRPC Commit (server_config.go:188-193), REST configCommitHandler (pkg/api/config.go:121-128), and interactive CLI (cli_config.go:235-241) all take the IsConfirmPending branch — they call ConfirmCommit() and RETURN SUCCESS immediately, never invoking commitFn, so the staged edits are NOT committed. 4) The client/operator sees a successful commit response (CLI prints 'commit confirmed'), believes the edits are active, exits configuration mode -> ExitConfigure discards the candidate -> the edits are silently lost. Junos semantics: a commit during the window both confirms the pending commit AND commits new candidate changes. The dirty flag (IsDirty) is available at all three call sites but is never consulted.

**Why it matters** — Silently dropping staged firewall/NAT/policy changes while reporting success is a config-integrity failure; the natural operator flow after a `commit confirmed` (tweak, then plain `commit`) hits it every time on a production box.

**Fix direction** — After ConfirmCommit succeeds, if store.IsDirty() proceed to the normal commitFn path instead of returning (matching Junos: confirm + commit). If finding #1's store-level implicit confirmation is adopted, these three branches collapse into a plain commit call and the bug disappears structurally.

**Not a duplicate** — Grepped issues-all.txt for 'confirm', 'commit' surface issues — #3447/#3443 are rollback-selector parsing, #3441 is durability; prior-findings.md has no commit-confirmed frontend findings. Distinct from finding #1: that is a stale timer reverting a committed config via paths that skip the dance; this is the dance itself discarding candidate edits while reporting success.

---

#### F-048 · clusterReadOnly is enforced only at EnterConfigure* — a config session open across a primary->secondary RG0 transition can still Set/Delete/Load and Commit on the read-only secondary

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-configstore`  ·  **Location:** `pkg/configstore/store_command.go`:11
- **Labels:** `bug`, `vsrx-parity`, `test-gap`

```
func (s *Store) Set(path []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	if err := s.candidate.SetPath(path); err != nil {
```

**Runtime trace**

1) Node0 is RG0 primary; operator enters config mode (EnterConfigureSession passes the clusterReadOnly check at store_lock.go:20) and stages edits. 2) RG0 fails over (manual failover or link weight): daemon_ha.go:351 'became secondary for RG0, disabling config writes' -> SetClusterReadOnly(true). 3) The operator's session still has s.candidate != nil, and NONE of the mutation verbs re-check the flag: Set/Delete/Deactivate/Copy/Rename/Insert/Annotate (store_command.go), LoadOverride/LoadMerge/LoadSet, Rollback, and critically Commit/CommitWithDescription/CommitConfirmed (store_commit.go:63 checks only candidate==nil). grpcapi's extra IsLocalPrimary(0) gate exists only on EnterConfigure (server_config.go:19), not on Set/Commit RPCs. 4) The commit persists+promotes a new active config on the SECONDARY and applies it to the dataplane (commitAndApply), and with syncPeer wiring can even push it to the peer — while the actual primary is concurrently syncing ITS config down, producing silent cluster config divergence (last writer wins). The doc comment on SetClusterReadOnly (store.go:202-204) explicitly claims 'config mutations (EnterConfigure, Commit, Load, Set, Delete) are rejected' — only the two Enter* functions check.

**Why it matters** — HA config authority is a correctness invariant: a secondary that accepts a commit diverges its active config and dataplane from the primary, and the divergence is invisible until the next sync overwrites one side. The code's own documented contract says these verbs are rejected.

**Fix direction** — Re-check s.clusterReadOnly at the top of Commit/CommitWithDescription/CommitConfirmed (the promotion points) and ideally in the candidate mutation verbs; alternatively have SetClusterReadOnly(true) force-exit an open config session (with a logged warning) so the stale candidate cannot be committed. Update the doc comment to match whichever gate is chosen and add a transition test.

**Not a duplicate** — Grepped issues-all.txt/prior-findings.md for 'read-only', 'readonly', 'secondary', 'clusterReadOnly' — no hits on this mechanism. Nearest: the general HA config-sync issues (#1799 persist semantics, reverse-sync issues) which are about persistence/sync, not about the read-only gate being enter-only.

---

#### F-049 · gRPC/remote-CLI `configure exclusive` lock can never be released by its own session — EnterConfigureExclusive sets exclusiveHolder but not configHolder, so ExitConfigureSession always fails

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-configstore`  ·  **Location:** `pkg/configstore/store_lock.go`:54
- **Labels:** `bug`

```
	s.candidate = s.active.Clone()
	s.configDir = true
	s.dirty = false
	s.exclusiveHolder = holder
	s.configLockAt = time.Now()
	return nil
}

// ExitConfigureSession exits configuration mode only if the given session holds
// the lock. Returns true if the lock was released.
```

**Runtime trace**

1) Remote CLI: `configure exclusive` -> gRPC EnterConfigure{Exclusive:true} -> server_config.go:26 EnterConfigureExclusive(sessionID) — stores sessionID in exclusiveHolder ONLY; configHolder stays "". 2) Operator finishes and types `exit` -> ExitConfigure RPC -> server_config.go:38 ExitConfigureSession(sessionID) -> store_lock.go:67: sessionID != "" && s.configHolder ("") != sessionID -> returns false, lock retained. 3) The disconnect auto-release path (grpcapi/server.go:281 configLockInterceptor) calls the same ExitConfigureSession and also fails. 4) Every subsequent `configure` from ANY session (local or remote) returns ErrConfigLocked ('configuration is locked by another user') until an operator discovers `clear system config-lock` (server_diag.go:775 / cli_clear.go:60) or restarts the daemon; that recovery even prints 'was held by ' with an EMPTY holder because ConfigHolder() returns configHolder, which exclusive mode never set. cmd/cli/shared.go:226-229 documents this exact defect in a comment ('even an explicit teardown call wouldn't recover them') but only guards the non-TTY -c mode; the interactive remote flow hits it every time.

**Why it matters** — A completely normal operator workflow (remote `configure exclusive`, edit, exit) wedges the appliance's configuration plane daemon-wide. In an HA pair this also blocks event-options remediation commits (EnterConfigure fails with ErrConfigLocked forever, exhausting its retry budget).

**Fix direction** — Set s.configHolder = holder in EnterConfigureExclusive, and make ExitConfigureSession/ForceExitConfigure clear configHolder consistently (ExitConfigure at store_lock.go:113 also leaves configHolder stale). Add a test: EnterConfigureExclusive(id) then ExitConfigureSession(id) must return true and release the lock.

**Not a duplicate** — Grepped issues-all.txt and prior-findings.md for 'exclusive' — zero hits; #1563 (referenced by the code comment) is only the readline nil segfault in `cli -c` non-TTY mode, closed, and its fix (hard-error in -c mode) does not touch the release mismatch. The defect is acknowledged in a code comment but has no tracker issue and is unfixed at HEAD.

---

#### F-050 · master-password at-rest encryption is defeated by plaintext sibling copies: rollback slots, archives and rescue.conf carry the full config (IKE PSKs etc.) in 0644 world-readable plaintext

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-configstore`  ·  **Location:** `pkg/configstore/store_commit.go`:540
- **Labels:** `security`, `bug`, `vsrx-parity`

```
	entries := s.history.List() // most-recent-first
	degraded := false
	for i, entry := range entries {
		path := s.rollbackPath(i + 1)
		data := entry.Config.Format()
		var err error
		if i == 0 {
			err = rbWriteFileDurable(path, []byte(data), 0644)
		} else {
			err = rbWriteFileAtomic(path, []byte(data), 0644)
```

**Runtime trace**

1) Operator configures `system master-password pseudorandom-function ...` -> every DB write (db.go writeTreeMarked -> maybeEncryptTreeJSON, crypto.go:70) AES-GCM-encrypts active.json/candidate.json. 2) The same commit then calls saveRollbackFiles (store_commit.go:106->528), which writes entry.Config.Format() — the full config TEXT including `security ike ... pre-shared-key ascii-text <secret>` (xpf has no $9$ obfuscation; compiler_ipsec.go reads the literal from the tree) — to xpf.conf.1..N with mode 0644 and NO encryption. writeArchive (store_persist.go:320) and SaveRescueConfig (store_persist.go:389) do the same for archives and rescue.conf. 3) The encrypted DB rollback slots that WOULD honor the contract (db.WriteRollback/ReadRollback, db.go:125-133) have zero production callers — store_commit.go:520 itself notes 'the DB rollback slots have no production callers'; the plaintext text files are the canonical rollback history loaded at boot. 4) Result: any local user (files are 0644) or disk-image thief reads every secret the master-password feature claims to protect, and docs/feature-gaps.md:703 asserts the feature is 'Done (active/candidate/rollback config trees are encrypted at rest...)' — false for the rollback history actually in use.

**Why it matters** — The feature's entire threat model (secrets unreadable from stolen disk/backup or by non-root local users) is nullified by up to 50 plaintext copies of the same tree sitting next to the encrypted DB, on a security appliance whose config routinely contains VPN pre-shared keys, BGP/SNMP secrets, and user credentials.

**Fix direction** — When masterPasswordPRF(active)!="", route rollback slots/archives/rescue through the same encrypt step (or store them as encrypted DB slots via the existing dead WriteRollback API), and at minimum tighten modes to 0600. Correct feature-gaps.md:703 to describe what is actually encrypted.

**Not a duplicate** — Grepped issues-all.txt/prior-findings.md/known-gaps.md for 'master-password', 'master.key', 'encrypt' — only #1894 (fsync durability, mentions master.key ordering, fixed) and unrelated IPsec/GCM naming issues. No prior issue or finding covers the plaintext rollback/archive/rescue side channel or the feature-gaps.md contradiction.

---

#### F-051 · GC stats never update on the userspace dataplane: REST/gRPC status SessionCount and Prometheus xpf_sessions_active/xpf_sessions_established are permanently 0 while sibling gauges show real sessions

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-conntrack-appid`  ·  **Location:** `pkg/conntrack/gc.go`:230
- **Labels:** `bug`, `observability`

```
func (gc *GC) sweep() time.Duration {
	// When userspace dataplane is active, skip the BPF session map scan
	// entirely — sessions are managed in user-space. Without this, the
	// batch lookup burns ~19% CPU scanning maps not used for forwarding.
	if gc.SkipSweep != nil && gc.SkipSweep() {
		return gc.interval
	}
```

**Runtime trace**

1) Every production daemon runs the userspace AF_XDP dataplane (the only runtime forwarding path post-#1476); daemon_run.go:764-766 unconditionally installs `gc.SkipSweep = func() bool { return true }`. 2) gc.Run ticks every 10s; sweep() returns at gc.go:230-232 BEFORE the only code that writes gc.stats (gc.go:495-504), so GCStats stays the zero value forever (TotalEntries=0, EstablishedSessions=0, LastSweepTime zero). 3) REST GET /status (pkg/api/health.go:83-86 `resp.SessionCount = stats.TotalEntries`) and gRPC GetStatus (pkg/grpcapi/server_show_status.go:28-31) report SessionCount 0 regardless of the real session table. 4) Prometheus scrape (pkg/api/metrics_sessions.go:10-19) publishes xpf_sessions_active=0, xpf_sessions_established=0 and a 0 GC sweep duration, while the SAME function computes xpf_sessions_ipv4/ipv6/snat/dnat from dp.IterateSessions (the helper-mirrored BPF conntrack map) and reports the true counts — self-contradictory telemetry on every scrape. Capacity dashboards/alerts keyed on xpf_sessions_active can never fire.

**Why it matters** — Session-table monitoring is a first-class operational signal for a stateful firewall (table exhaustion, flood detection, HA sizing). Publishing a confident 0 for the headline gauge while breakdown gauges show real load poisons dashboards and can mask a session-table flood.

**Fix direction** — When SkipSweep is active, still refresh GCStats cheaply — e.g. count entries via the same IterateSessions/mirror source the breakdown gauges use (or a helper status field) on the sweep tick; or drop the GC-stats dependency from health/status/metrics and read the session store directly.

**Not a duplicate** — Searched issues/prior findings for SkipSweep, sessions_active, SessionCount, GetStatus, gc stats. #3604 (CLOSED) was the aging-config data race (fixed at HEAD via the mu-snapshot); #333 established SkipSweep itself; feature-gaps.md documents only the AGING enforcement gap (#3440), not the zero-stats status/metrics surface. No issue or prior finding covers GCStats never being written on the userspace path.

---

#### F-052 · Scheduler date windows evaluated in UTC while `now` and time-of-day run in local time: with `set system time-zone` applied, start/stop-date boundaries shift by the UTC offset (window opens hours early or late)

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-conntrack-appid`  ·  **Location:** `pkg/scheduler/scheduler.go`:212
- **Labels:** `bug`, `vsrx-parity`

```
	if sched.StartDate != "" {
		startDate, err := time.Parse("2006-01-02", sched.StartDate)
		if err != nil {
			slog.Warn("scheduler: invalid start date", "name", sched.Name, "date", sched.StartDate, "err", err)
			return false
		}
		if now.Before(startDate) {
			return false
		}
	}
```

**Runtime trace**

1) Operator sets `set system time-zone America/Los_Angeles` (supported and applied by daemon_system.go:533-586) and a campaign scheduler `start-date 2026-03-01 stop-date 2026-03-31` bound to a permit policy. 2) scheduler.Run ticks with time.Now() in local time (PST, UTC-8). 3) isWithinWindow parses the date with time.Parse("2006-01-02", ...) which yields 2026-03-01T00:00:00 UTC == 2026-02-28 16:00 PST. 4) `now.Before(startDate)` compares absolute instants, so the window opens at 16:00 local on Feb 28 — 8 hours EARLY (fail-open on the start edge); the stop edge similarly extends 8h past the configured end. In a UTC+9 zone the window instead opens 9h LATE (policy off during intended hours). 5) Meanwhile timeOfDay(now) (scheduler.go:285-287) uses now.Hour() — LOCAL — so the time-of-day constraint and the date constraint are evaluated in two different frames within the same function. 6) Every existing date test passes `now` constructed with time.UTC (scheduler_test.go:110/125/138/151), so the mismatch is invisible to the suite. Junos evaluates schedulers in the device's configured local time.

**Why it matters** — Time-based security policy boundaries that drift by up to 12-14 hours from the operator's intent are a silent policy-exposure window on any appliance not running UTC — and xpf explicitly supports configuring a local time zone.

**Fix direction** — Parse dates with time.ParseInLocation("2006-01-02", s, now.Location()) (and the Junos dotted date-time form), so date and time-of-day constraints share the local frame; add tests running in a non-UTC location.

**Not a duplicate** — Searched issues/prior findings for timezone/UTC/wall-clock/start-date. #1792/#2332 (CLOSED) are HA wall-clock liveness, unrelated; the scheduler wall-clock-discontinuity fail-closed logic (scheduler.go:155-181) covers clock STEPS, not the parse-frame mismatch. No issue or prior finding covers UTC-parsed scheduler dates vs local now.

---

#### F-053 · Dual-fabric event-driven refresh loses events: single-token fabricRefreshCh is consumed by only ONE of the fab0/fab1 loops per trigger

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-daemon-ha`  ·  **Location:** `pkg/daemon/daemon_ha_fabric.go`:859
- **Labels:** `bug`, `ha`, `test-gap`

```
func (d *Daemon) triggerFabricRefresh() {
	select {
	case d.fabricRefreshCh <- struct{}{}:
	default:
		// Already pending — no need to queue another.
	}
}
// consumers (two separate goroutines):
//   populateFabricFwd  line 232: case <-d.fabricRefreshCh:
//   populateFabricFwd1 line 625: case <-d.fabricRefreshCh:
```

**Runtime trace**

Config: dual fabric (fab0 + fab1, cc.Fabric1Interface set) → startClusterComms launches BOTH populateFabricFwd (selects on d.fabricRefreshCh at line 232) and populateFabricFwd1 (line 625). Runtime: fab1's peer neighbor entry changes (e.g. peer RETH MAC reprogram after crash recovery) → monitorFabricState receives the NeighUpdate → triggerFabricRefresh() sends exactly ONE token into the capacity-1 channel. The Go runtime hands that token to ONE arbitrary waiting receiver — ~50% of the time the fab0 loop wins, runs refreshFabricFwd (key=0 only), and the fab1 entry that actually changed is left stale until the 30s safety ticker. Same for reconcileRGState's triggerFabricRefresh at daemon_ha.go:597 (meant to repopulate fab0): it may instead wake the fab1 loop. During a failover in this window, fabric-redirected packets for the affected fabric carry the stale peer MAC → dropped on the wire, partially reintroducing the 'up to 30s redirect blackhole' that #124 was filed to eliminate.

**Why it matters** — #124's event-driven refresh is the mechanism that bounds fabric-redirect blackholes during failback; in dual-fabric deployments it silently degrades to coin-flip delivery, so the 30s worst case #124 fixed still exists for one of the two fabric paths.

**Fix direction** — Give each populate loop its own channel (fabricRefreshCh0/fabricRefreshCh1) and have triggerFabricRefresh send to both non-blockingly, or replace the channel with a sync.Cond/notify-both helper; add a unit test that a single trigger refreshes both entries.

**Not a duplicate** — Searched 'fabricRefresh', 'populateFabricFwd', 'monitorFabricState', 'triggerFabricRefresh', 'fabric' in the corpus. #124 [CLOSED] added this event-driven refresh (feature), #123 covered sync-conn flapping between fabrics, #125 gRPC single-address, #79 startup population — none cover the two-consumers-one-token delivery defect introduced by #124's implementation.

---

#### F-054 · directSendGARPs gateway ARP probe still uses pre-#2377 'force last octet to .1' target — broken on /25+ subnets in the DEFAULT private-rg-election mode

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-daemon-ha`  ·  **Location:** `pkg/daemon/daemon_ha_vip.go`:565
- **Labels:** `bug`, `ha`, `vsrx-parity`

```
					// Send ARP probe to gateway (.1) to update upstream ARP caches.
					_, ipNet, _ := net.ParseCIDR(cidr)
					if ipNet != nil {
						gw := make(net.IP, len(ipNet.IP))
						copy(gw, ipNet.IP)
						gw[len(gw)-1] = 1
						// Skip when the VIP is itself the subnet .1 — otherwise we
						// would probe ourselves. Mirrors the guard in
						// vrrp.sendGARP (Codex/AGY #2152 review).
						if !gw.Equal(ip.To4()) {
```

**Runtime trace**

Config: chassis cluster with default election (compiler_system.go:1211 sets PrivateRGElection=true, so isNoRethVRRP()==true and directSendGARPs is the production announce path) and a RETH VIP on a >/24 subnet, e.g. reth0.0 10.0.61.18/28 (network 10.0.61.16, hosts .16-.31). Runtime: RG failover → applyDirectVIPOwnership(want=true) → scheduleDirectAnnounce → directSendGARPs(rgID). For the v4 VIP the code takes ipNet.IP (the MASKED network address 10.0.61.16 from ParseCIDR), copies it and forces the last octet to 1 → gw=10.0.61.1, which is OUTSIDE the .16-.31 subnet. cluster.SendARPProbe(ifName, VIP, 10.0.61.1) then emits the directed who-has to a foreign/absent address, so the real gateway (e.g. 10.0.61.17) never receives the targeted VIP→new-MAC refresh. Routers that ignore broadcast GARPs (the exact motivation for the #2152 probe) keep the stale VIP→old-MAC binding until ARP ageout → minutes of post-failover blackhole for return traffic. Additionally /31 and /32 VIPs are not skipped (vrrp gatewayProbeTarget returns ok=false for ones>=31; this path has no such guard).

**Why it matters** — This is the identical defect fixed as #2377, but #2377's commit 17255f1d3 touched only pkg/vrrp (gatewayProbeTarget = network+1, skip /31 and /32). private-rg-election is the DEFAULT election mode since the schema change, so the unfixed direct-mode copy — not the fixed VRRP copy — is what production clusters execute on failover.

**Fix direction** — Export vrrp.gatewayProbeTarget (or move it to pkg/cluster) and call it from directSendGARPs instead of the hand-rolled gw[len(gw)-1]=1; add a direct-mode sibling of instance_garp_probe_target_test.go covering /28, /31, /32.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'GARP', 'gratuitous', 'gateway probe', '2377', 'directSendGARPs'. #2377 [CLOSED] fixed exactly this in pkg/vrrp only (verified via git show 17255f1d3 --stat: pkg/vrrp files only); #2898 [CLOSED] gated the direct-mode burst follow-ups but did not touch the probe target; #2152 added the probe. This is the unfixed direct-mode residual of closed #2377 — same mechanism, different (now default) call path.

---

#### F-055 · super-user sudoers NOPASSWD grant is never revoked when a login user's class is downgraded or the user is removed from config

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-daemon-lifecycle`  ·  **Location:** `pkg/daemon/daemon_system.go`:778
- **Labels:** `security`, `bug`

```
		if user.Class == "super-user" {
			sudoFile := fmt.Sprintf("/etc/sudoers.d/xpf-%s", user.Name)
			sudoLine := fmt.Sprintf("%s ALL=(ALL) NOPASSWD: ALL\n", user.Name)
			current, _ := os.ReadFile(sudoFile)
			if string(current) != sudoLine {
				if err := fsatomic.WriteFileDurable(sudoFile, []byte(sudoLine), 0440); err != nil {
```

**Runtime trace**

applySystemLogin iterates cfg.System.Login.Users. When user.Class=="super-user" it writes /etc/sudoers.d/xpf-<name> granting NOPASSWD:ALL. On a day-2 commit that changes the SAME user's class from super-user to e.g. `operator`/`read-only`, the `if user.Class == "super-user"` branch is now false so the block is skipped — but there is NO else/removal branch, and no code anywhere removes a stale /etc/sudoers.d/xpf-* file (grep confirms the file is only ever written, never removed). Same for a user deleted from config entirely: the loop no longer visits that name, so the sudoers file is orphaned. Meanwhile the interactive CLI RBAC class IS reconciled at runtime (daemon_run.go:1628 shell.SetUserClass(u.Class)), so the box reports the user as downgraded while the OS still grants passwordless root via sudo.

**Why it matters** — A firewall operator who deliberately demotes an account from super-user to a read-only class (an offboarding / least-privilege action) reasonably expects the account to lose root. Instead the account keeps `NOPASSWD: ALL` and can `sudo -i` to full root, completely bypassing the CLI RBAC downgrade. This is a silent privilege-retention / audit-integrity defect in a security appliance.

**Fix direction** — Reconcile the sudoers drop-in declaratively: when user.Class != super-user (or the user is absent from config), os.Remove(/etc/sudoers.d/xpf-<name>). Track xpf-provisioned sudoers files (mirroring the #1944 provisioned-users marker) so out-of-band sudoers files are left alone, and sweep orphans for users no longer in config.

**Not a duplicate** — grep of issues/prior-findings for sudoers|super-user|NOPASSWD|privilege returned nothing. docs/system-login.md frames sudo as 'additive' only in the encrypted-password-removal context (password-vs-key asymmetry); it never addresses class downgrade or the CLI-class-vs-OS-sudo divergence. Not covered by #1944 (which is about the password, not sudo).

---

#### F-056 · RSS idempotence probes misparse the ethtool -x 'RSS hash key' line when the random key's first byte is decimal — table falsely reported non-matching/non-default, spurious ethtool -X rewrite on every commit (~39% of boots)

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-daemon-net`  ·  **Location:** `pkg/daemon/rss_indirection.go`:386
- **Labels:** `bug`, `performance`, `test-gap`

```
		colon := bytes.IndexByte(trimmed, ':')
		if colon <= 0 {
			continue
		}
		rowIdx, err := strconv.Atoi(string(trimmed[:colon]))
		if err != nil {
			continue
		}
		for j, tok := range bytes.Fields(trimmed[colon+1:]) {
			q, err := strconv.Atoi(string(tok))
			if err != nil {
				return false
			}
```

**Runtime trace**

(1) `ethtool -x <iface>` output ends with 'RSS hash key:' followed by the key on one line, e.g. '25:5b:0e:c2:...'. The kernel fills this key via netdev_rss_key_fill() — random once per boot; with probability 100/256 (~39%) the FIRST byte's hex form is two decimal digits (both nibbles 0-9, e.g. '25'). (2) indirectionTableIsDefault (line 365) and indirectionTableMatches (line 443) both parse every line shaped '<int>:<fields>'. For key line '25:5b:0e:...': colon=2, Atoi("25") SUCCEEDS, so the key line is treated as a table row; bytes.Fields yields the single token '5b:0e:...', Atoi fails → `return false` (line 386 / line 478). (3) On the loss-cluster production shape (workers=6, queues=6) applyRSSIndirectionOne skips reshaping and calls maybeRestoreDefault on EVERY applyConfig (reapplyRSSIndirection, daemon_apply.go:1460); indirectionTableIsDefault now returns false even though the table IS default → `ethtool -X <iface> default` is executed on every commit and every daemon start, mid-traffic, plus a false 'restored default round-robin rss indirection' INFO log each time. (4) In workers<queues deployments the same misparse defeats indirectionTableMatches → the weight vector is rewritten via `ethtool -X ... weight ...` on every commit. Both directly violate the function's stated invariant ('Idempotent: if the live indirection table already matches ... no write is issued') and the documented #M4 no-mid-traffic-re-hash concern. Test fixtures (rss_indirection_test.go:190,408,718) only use keys starting '6d:'/'0a:'/'...' — never a two-decimal-digit first byte — so the misparse is invisible to the suite.

**Why it matters** — The idempotency probe is the load-bearing guard that keeps the reconcile path from reshaping live mlx5 RSS state on every commit. On ~4 of 10 boots it silently degrades to write-every-commit: repeated ETHTOOL_SRSSH driver ops on the hot WAN/LAN NICs during traffic, misleading operator logs claiming a stale table was restored, and masking of the real #805 restore signal.

**Fix direction** — Stop parsing after the indirection-table section: break out of the line loop at the first line matching 'RSS hash key' (or only accept rows whose pre-colon index is a multiple of 8 AND whose post-colon fields ALL parse, treating a non-parsing field row as 'skip line' rather than 'return false'). Add a test fixture whose hash key starts with a decimal-only byte (e.g. '25:5b:...').

**Not a duplicate** — Searched issues-all.txt + prior-findings.md for 'hash key', 'ethtool -x', 'indirectionTable', 'rss' (37 rss hits reviewed): #805 (workers-change refresh), #3091 (planned-vs-bound), #840/#898/#897 (rebalance) all concern WHICH table to program, not the -x output parser. No issue or prior finding touches the hash-key-line misparse; nearest is #805 whose fix ADDED the vulnerable indirectionTableIsDefault.

---

#### F-057 · renameRethMember downs the RETH member for rename and never brings it back up — recovery path leaves the data-path link DOWN (sibling of fixed #2083, uncovered function)

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-daemon-net`  ·  **Location:** `pkg/daemon/daemon_reth.go`:156
- **Labels:** `bug`, `ha`, `vsrx-parity`

```
		link, err := netlink.LinkByIndex(iface.Index)
		if err != nil {
			return ""
		}
		// Ensure interface is DOWN for rename.
		netlink.LinkSetDown(link)
		if err := netlink.LinkSetName(link, targetName); err != nil {
			slog.Warn("failed to rename RETH member",
				"from", iface.Name, "to", targetName, "err", err)
			return ""
		}
		return iface.Name
```

**Runtime trace**

(1) HA node applies config; in daemon_apply.go:882-888 the RETH member's configured Linux name is missing (stale/lost 10-xpf-*.link after a crash, device-map leave-alone left the NIC unmapped, or operator re-pinned the member name), so `netlink.LinkByName(linuxName)` fails. (2) renameRethMember (daemon_reth.go:142) finds the NIC by its RETH virtual MAC, calls LinkSetDown (line 156) + LinkSetName, returns the old name — with NO LinkSetUp. (3) Caller proceeds to programRethMAC (daemon_apply.go:899); since the NIC was located BY the expected virtual MAC, `bytes.Equal(current, mac)` is guaranteed true and programRethMAC returns (false, nil) at daemon_reth.go:177 — linkCycled=false, so none of the 2.6b link-cycle recovery (ReconcileVIPs / NotifyLinkCycle) runs and no networkctl reload follows (networkd.Apply already ran BEFORE step 2.6). (4) The member interface is now correctly named but administratively DOWN: VRRP adverts stop on it, link-tracking demotes the RG, transit on that member blackholes. The only automatic recovery is cluster.RethController.HandleStateChange (pkg/cluster/reth.go:72) which LinkSetUp's members ONLY on a ClusterEvent for that RG — i.e. the node must first suffer the failover the DOWN link causes; if the peer is dead there is no event and the outage persists until operator `ip link set <member> up`.

**Why it matters** — This is the exact defect class audit #2083 fixed in linksetup.renameInterface (down→rename→up with retry + actionable error), but daemon_reth.go carries an independent hand-rolled rename that predates that fix and was never hardened. It fires on the HA recovery path — precisely when the system is already degraded — and converts a name-recovery action into a member-link outage plus spurious RG failover on a production cluster.

**Fix direction** — After a successful LinkSetName, call netlink.LinkSetUp(link) (with the same one-retry + actionable-error contract as linksetup.renameInterface), or better: delete renameRethMember's bespoke down/rename sequence and route it through the hardened renameInterface primitive (see refactor finding). Also stop ignoring the LinkSetDown error (a failed down makes the subsequent rename fail with the link left untouched, currently indistinguishable).

**Not a duplicate** — Searched issues-all.txt for 'renameRethMember', 'reth member', 'renamed-but-DOWN', 'rename'; only hit is CLOSED #2083 which fixed linksetup.go renameInterface (LinkSetUp-failure path). HEAD reflects that fix (linksetup.go:391-405). renameRethMember is a different function that attempts NO LinkSetUp at all, and its caller's programRethMAC early-return guarantees the link-cycle recovery is skipped — a mechanism #2083 never covered. prior-findings.md has zero entries for daemon_reth.go.

---

#### F-058 · NetFlow v9/IPFIX export protocolIdentifier is 0 for every non-TCP/UDP/ICMP session — callbacks re-parse the rendered protocol name instead of using EventRecord.ProtocolNum

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-daemon-svc`  ·  **Location:** `pkg/daemon/daemon_flowexport.go`:363
- **Labels:** `bug`, `vsrx-parity`

```
	sd := flowexport.SessionCloseData{
		SrcPort:  parseSrcPort(rec.SrcAddr),
		DstPort:  parseSrcPort(rec.DstAddr),
		Protocol: parseProtocol(rec.Protocol),
...
// daemon_flow.go:224
func parseProtocol(proto string) uint8 {
	switch proto {
	case "TCP":
		return 6
```

**Runtime trace**

A GRE (proto 47) or ESP (proto 50) session closes. The dataplane close event carries the numeric protocol; ringbuf.go builds EventRecord with ProtocolNum: evt.Protocol (ringbuf.go:871) AND a rendered name via protoName() which since #3040 returns "GRE"/"ESP"/"IPIP"/"IPV6" (SSOT, ringbuf.go:1210-1218) or a numeric string ("99") for unknowns. flowExportCallback/ipfixExportCallback (daemon_flowexport.go:363, 417) ignore rec.ProtocolNum and call parseProtocol(rec.Protocol) (daemon_flow.go:224-236), which maps ONLY "TCP"/"UDP"/"ICMP"/"ICMPv6" and returns 0 for everything else — no named-SSOT reverse lookup, no numeric fallback. Result: the NetFlow/IPFIX record for any GRE/ESP/IPIP/41-in-4/unknown-protocol flow is exported with protocolIdentifier=0 (IANA HOPOPT), so collectors misclassify or drop these flows. (Pre-#3040 the string was "47" — also unparsed — so this has never worked; #3040's rename just changed which wrong string is fed in.)

**Why it matters** — Flow telemetry for tunnel/VPN traffic (GRE, ESP) is exactly what security operators pivot on; protocol 0 makes those flows unqueryable and corrupts collector-side protocol breakdowns on a security appliance.

**Fix direction** — Use rec.ProtocolNum directly in both callbacks (the field exists since #3382 and is populated on close records); delete parseProtocol or keep it only as a fallback via appid.ProtocolNumber + strconv for legacy strings. Extend daemon_flowexport tests with a GRE/ESP close record asserting Protocol==47/50.

**Not a duplicate** — Read all fresh flowexport issues #3740-#3748 (template IDs, prom labels, reconcile window, netlink route-mask, source-address, reverse counters, batch queue, active-timeout) — none touch protocol identity. Also checked #2613/#2749 (TOS/TCPFlags/InIf/OutIf zeros, CLOSED), #3040 (RT_FLOW rendering SSOT — changed the producer, never the daemon-side parser), #3382 (added ProtocolNum for the event MATCHER, not flowexport). Mechanism (rendered-name re-parse with 4-entry map vs available numeric field) is unfiled.

---

#### F-059 · SNMP agent and linkUp/linkDown trap monitor are boot-gated only — day-2 commit adding snmp or trap-groups is inert until daemon restart

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-daemon-svc`  ·  **Location:** `pkg/daemon/daemon_run.go`:1010
- **Labels:** `bug`, `vsrx-parity`

```
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.System.SNMP != nil && (len(cfg.System.SNMP.Communities) > 0 || len(cfg.System.SNMP.V3Users) > 0) && !isProcessDisabled(cfg, "snmpd") {
		d.snmpAgent = snmp.NewAgent(cfg.System.SNMP)
...
		// Start link state monitor for SNMP traps.
		if len(cfg.System.SNMP.TrapGroups) > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.monitorLinkState(ctx)
```

**Runtime trace**

Case A: box boots with no `snmp` stanza → daemon_run.go:1010 gate false → d.snmpAgent stays nil forever. Operator later commits `set snmp community public`; the only apply-path hook is daemon_apply.go:432 `if d.snmpAgent != nil { d.snmpAgent.UpdateConfig(...) }` — nil, so nothing happens: no UDP listener, no MIB, no traps, and no warning. Case B: box boots with communities but no trap-group → agent starts, but the monitorLinkState goroutine gate (daemon_run.go:1079, boot cfg) is false. Day-2 commit adds `snmp trap-group tg targets 10.0.0.9`; UpdateConfig hands the agent the trap groups (other trap sources would work) but the netlink link monitor (daemon_flow.go:316) was never started, so linkUp/linkDown traps — the primary trap type — never fire until restart. Junos activates snmp/trap-groups on commit.

**Why it matters** — Same stored-but-never-enforced class the project has repeatedly had to fix (#2075 flowexport, #2348 DHCP relay, #2372 LLDP, open #3752 event-options): a monitoring integration silently dead after a clean commit on a security appliance, discovered only during an outage post-mortem.

**Fix direction** — Add a reconcileSNMP step in applyConfigLocked: create/start the agent when config appears (and stop it on removal / processes-disable), and start/stop the link-state monitor keyed on len(TrapGroups)>0 with a cancel func, mirroring the flowexport reconcile pattern.

**Not a duplicate** — Searched issues-all.txt for 'snmp' (12 issues: trap sync #2991, community #2989, v3 crypto #2681/#2640/#2610-#2612, engineBoots #2649 — all agent-internal), 'day-2', 'boot-only', 'until restart': the boot-only lifecycle issues are per-service (#2372 LLDP, #2348 relay, #3752 event-options); no SNMP-lifecycle issue exists. prior-findings.md day-2 entry covers only the event-options engine.

---

#### F-060 · system archival configuration transfer-interval is parsed and typed but never implemented — periodic archival silently does nothing

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-daemon-svc`  ·  **Location:** `pkg/daemon/daemon_flow.go`:241
- **Labels:** `vsrx-parity`, `bug`

```
func (d *Daemon) archiveConfig(cfg *config.Config) {
	if cfg.System.Archival == nil || !cfg.System.Archival.TransferOnCommit {
		return
	}
// pkg/config/types_system.go:171
	TransferInterval int // minutes between auto-archives (0 = on commit only)
```

**Runtime trace**

Operator commits `set system archival configuration transfer-interval 60 archive-sites "scp://backup@host/cfg"` (the Junos way to get hourly off-box config backups WITHOUT transfer-on-commit). compiler_system.go:158-161 parses it into ArchivalConfig.TransferInterval; commit succeeds with no warning. Repo-wide grep for TransferInterval outside pkg/config returns nothing — no timer loop exists anywhere; archiveConfig gates solely on TransferOnCommit (daemon_flow.go:241) and is only invoked from applyConfigLocked step 15. Result: zero transfers ever occur; the operator believes hourly config backups are running. Junos semantics: transfer-interval uploads the current config every N minutes independent of commits.

**Why it matters** — A silently-inert accepted knob is the project's own worst-severity config class (fail-open/stored-but-never-enforced); for archival it means the off-box backup strategy an operator explicitly configured produces nothing.

**Fix direction** — Either implement a supervised ticker goroutine (reconciled on commit, interval from config, reusing the corrected archive source from finding 1) or hard-reject/warn transfer-interval at commit until implemented (strict-validate precedent, e.g. #3751 style).

**Not a duplicate** — Searched issues-all.txt for 'transfer-interval', 'archival', 'archive': #651 (password warning) and #3441 (local configstore auto-archive durability) are the only archival issues; neither concerns the periodic-transfer knob. feature-gaps.md/known-gaps.md do not list archival as a gap. Unfiled.

---

#### F-061 · updateFlowTrace leaks one EventReader callback per commit — stale closed TraceWriters keep formatting every event and spam a misleading 'failed rotation' warning

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-daemon-svc`  ·  **Location:** `pkg/daemon/daemon_flow.go`:308
- **Labels:** `bug`, `performance`, `test-gap`

```
func (d *Daemon) updateFlowTrace(cfg *config.Config) {
	if d.traceWriter != nil {
		d.traceWriter.Close()
		d.traceWriter = nil
	}
...
	tw, err := logging.NewTraceWriter(cfg.Security.Flow.Traceoptions)
...
	d.traceWriter = tw
	d.eventReader.AddCallback(tw.HandleEvent)
```

**Runtime trace**

Config has `security flow traceoptions file ...`. Boot: applyFlowTrace (daemon_run.go:871) registers callback #1. EVERY subsequent commit — even one not touching traceoptions — runs applyConfigLocked step 16 (daemon_apply.go:1326) → updateFlowTrace: Close() the old writer (trace.go:337-344 sets tw.file=nil) then AddCallback(new tw.HandleEvent). EventReader.AddCallback only appends (ringbuf.go:307-311) and the only removal primitive is ClearCallbacks (never called in production — verified by grep). After N commits there are N+1 registered callbacks. For every matching flow event, each of the N stale callbacks runs matchFlags → matchFilters → formatTrace (string allocation) → takes tw.mu → hits the tw.file==nil branch (trace.go:364-371) → droppedWrites.Add(1) + rate-limited WARN 'flow-trace write dropped: file unavailable after failed rotation'. Observable: per-event CPU grows linearly with commit count on a long-lived box with tracing on; DroppedWrites counter inflates; operators chase a nonexistent rotation failure. daemon_flowexport.go's own header comment (lines 20-27) documents exactly this hazard and fixed it for exporters with the atomic-bundle indirection (#2075) — the trace writer was left on the naive pattern.

**Why it matters** — Flow traceoptions is a diagnostic used precisely on busy production boxes; an O(commits) multiplier on the per-event hot path of the EventReader (which also feeds syslog, NetFlow and HA consumers) plus a false 'rotation failed' alarm degrades the box the longer it runs.

**Fix direction** — Mirror the #2075 pattern: register ONE stable indirection callback via sync.Once that reads the live *TraceWriter from an atomic.Pointer; updateFlowTrace swaps the pointer (and is hash-gated on the rendered traceoptions so unrelated commits don't bounce the writer). Add a CallbackCount regression test like the flowexport one.

**Not a duplicate** — Searched issues-all.txt for 'callback', 'trace', 'traceoptions', 'AddCallback' and prior-findings.md for 'trace'/'tracewriter'/'callback': #3478 (silent write/rotation failures — added the very warn this leak now mis-fires), #3424/#3422/#3420 (size/filter/path), #3743 (netlink inside flowexport callback) — none cover callback-list growth from updateFlowTrace. #2075 fixed the identical mechanism for flow exporters only.

---

#### F-062 · FRR IS-IS render drops the per-interface `level` override (no `isis circuit-type`) and never activates IPv6 (`ipv6 router isis` missing) — IS-IS is IPv4-only and interface level statements are silently ignored

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-frr-routing`  ·  **Location:** `pkg/frr/policy_render.go`:983
- **Labels:** `vsrx-parity`, `bug`, `config-truth`

```
		for _, iface := range isis.Interfaces {
			fmt.Fprintf(&b, "interface %s\n", iface.Name)
			fmt.Fprintf(&b, " ip router isis xpf\n")
			if iface.Passive {
				b.WriteString(" isis passive\n")
			}
			if iface.Metric > 0 {
				fmt.Fprintf(&b, " isis metric %d\n", iface.Metric)
			}
```

**Runtime trace**

Config: `set protocols isis interface ge-0/0/1 level 1` (compiled by compiler_protocols.go:654-657 into ISISInterface.Level) on a router with `is-type level-1-2`. generateProtocols' IS-IS interface loop (policy_render.go:981-1014) renders name/passive/metric/auth/BFD but never references iface.Level — grep confirms zero uses of `iface.Level`, `circuit-type`, or `ipv6 router isis` in pkg/frr. Result 1: the interface forms adjacencies at the router-wide is-type instead of the configured circuit level (on vSRX, `level 1 disable`/interface level statements constrain the adjacency; here L2 hellos keep flowing on an interface the operator restricted to L1). Result 2: because only `ip router isis xpf` is emitted, frr isisd never enables the IPv6 topology on any interface — IS-IS learns/advertises no IPv6 routes even though the compiler accepts IS-IS config on dual-stack interfaces and knownRedistProtocols was extended for IPv6 IGPs (#2943). The struct field is dead config: accepted at commit, never enforced.

**Why it matters** — Config-truth violation on a routing protocol: accepted `level` statements that don't constrain adjacencies can form unintended L2 adjacencies across area boundaries, and the silent IPv4-only limitation contradicts the dual-stack posture (IPv6 is called out as important) with no commit warning or documented gap.

**Fix direction** — Emit `isis circuit-type level-1|level-1-2|level-2-only` from ISISInterface.Level inside the interface block, and emit `ipv6 router isis xpf` (gated on the interface having family inet6, or unconditionally like FRR defaults) alongside `ip router isis`. Alternatively reject/warn the unsupported leaves at commit.

**Not a duplicate** — Searched 'isis' across issues-all.txt/prior-findings.md/known-gaps.md/recent-commits.txt: #2942 (CLOSED) = interface BFD emitted after exit (fixed at HEAD, verified); #3311 = host-inbound isis token; #2127 = rtProtoName; prior findings cover the IS-IS LLC parser and host-inbound gate only. docs/feature-gaps.md rows for IS-IS mention only BFD as Done; neither the dropped per-interface level nor missing IPv6 activation is tracked anywhere.

---

#### F-063 · GRE tunnel `keepalive` is a silent no-op on the production userspace dataplane: every tunnel is AnchorOnly and applyAnchorLocked never starts (and actively stops) keepalive runners; no Rust-side GRE keepalive exists and commit accepts the knob without warning

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-frr-routing`  ·  **Location:** `pkg/routing/tunnel.go`:495
- **Labels:** `vsrx-parity`, `bug`, `config-truth`

```
func (t *tunnelManager) applyAnchorLocked(tc *config.TunnelConfig, adopting bool) {
	// A leftover keepalive runner (legacy→anchor mode change) must not
	// keep probing: anchors never run keepalives (probes LinkSetDown
	// the device on failure — a behavior the anchor path never had).
	t.stopKeepaliveLocked(tc.Name)
```

**Runtime trace**

Config: `set interfaces gr-0/0/0 unit 0 tunnel source A destination B keepalive 5 keepalive-retry 3` on the production daemon (dataplane-type userspace — the only runtime dataplane since #1373/#1476). compiler_interfaces.go:180/186 populates TunnelConfig.Keepalive/KeepaliveRetry; daemon_run.go:120 `anchorOnly := dataplane.EffectiveType(...) == dataplane.TypeUserspace` sets tc.AnchorOnly=true for EVERY tunnel; tunnelManager.Apply -> applyAnchorLocked (tunnel.go:459-460), which calls stopKeepaliveLocked and never consults tc.Keepalive — the entire keepalive machinery (startKeepalive, keepaliveLoop, tunnel_keepalive.go icmpProber, ~600 hardened lines from #1918/#1947) is reachable only on the legacy standalone-CLI branch. grep of userspace-dp/src shows no GRE keepalive implementation (only WG persistent-keepalive and event-stream heartbeats). No commit-time validation warns. Observable: remote GRE peer dies; the tunnel stays admin-up, static routes over gr-X keep forwarding into the dead tunnel (traffic blackhole with no failover), and `show interfaces tunnel`/gRPC GetTunnelStatus renders KeepaliveInfo as empty (not configured) rather than probing state.

**Why it matters** — On vSRX, `keepalive` on a gr- interface is precisely the mechanism that downs the logical interface and triggers route failover when the tunnel peer dies. Operators migrating configs get a firewall that accepts the knob and does nothing — the same config-truth class as #3360 (gre-performance-acceleration) but on a liveness/failover-critical feature.

**Fix direction** — Either run the existing keepalive runner on the anchor branch too (the anchor TUN is exactly the 'host-originated traffic anchor' the GRE plan describes; on probe-fail LinkSetDown the anchor so FRR/static routes withdraw), or implement GRE keepalives in userspace-dp; until then reject/warn `keepalive` under dataplane-type userspace at commit and surface 'keepalive: unsupported on userspace dataplane' in tunnel status. File a tracked parity issue.

**Not a duplicate** — Searched 'keepalive', 'anchor', 'gre keepalive' in issues-all.txt/prior-findings.md/known-gaps.md: #1918 (CLOSED) fixed the probe implementation itself (route-existence vs liveness) on the legacy branch — this finding is that the fixed prober is UNREACHABLE in production; #1884 is anchor flap; #2961/#2836 are WG. pkg/routing/README.md:237 does document 'legacy branch only — anchors never probe' as internal behavior, but no operator-facing gap, commit warning, or tracker issue exists (absent from known-gaps.md and docs/feature-gaps.md).

---

#### F-064 · GetBGPSummary parses FRR table trailers and second-address-family preambles as BGP peers ('Total number of neighbors 1' → bogus peer row), never populates PfxRcd, and has zero test coverage

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-frr-routing`  ·  **Location:** `pkg/frr/status_parse.go`:187
- **Labels:** `bug`, `observability`, `test-gap`

```
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		p := BGPPeerSummary{
			Neighbor: fields[0],
			AS:       fields[2],
		}
		if len(fields) >= 10 {
			p.MsgRcvd = fields[3]
```

**Runtime trace**

Real FRR 10.x `show bgp summary` output with one IPv4 peer and an IPv6 section: after the 'Neighbor' header sets inTable=true (status_parse.go:174-176), the loop never resets it. Trailer line 'Total number of neighbors 1' has 5 fields -> passes len>=5 -> appended as BGPPeerSummary{Neighbor:"Total", AS:"of"}. The following 'IPv6 Unicast Summary:' section's preamble 'BGP router identifier 10.0.1.10, local AS number 65001 vrf-id 0' has 10 fields -> appended as {Neighbor:"BGP", AS:"identifier", MsgRcvd:"10.0.1.10,", ...}; 'BGP table version N'/'RIB entries ...' lines similarly slip through when they have >=5 fields. Consumers pkg/cli/cli_show_routing.go:348, pkg/grpcapi/server_routing.go:157, pkg/api/routing.go:95 render these garbage rows in `show bgp summary` on all three surfaces. Additionally the exported PfxRcd field is never assigned (dead), so structured consumers always see "". frr_test.go has no GetBGPSummary test (grep: zero hits), so nothing pins the parser to real FRR output shapes.

**Why it matters** — Operator-facing routing status on CLI/gRPC/REST shows phantom neighbors ('Total', 'BGP') in every dual-AF or multi-peer deployment, and monitoring built on the REST/gRPC peer list miscounts sessions — exactly the kind of parser drift a status surface on a production appliance must not have.

**Fix direction** — Reset inTable on blank lines / 'Total number of' / '*Summary:' markers, whitelist rows whose fields[0] parses as an IP (or hostname per neighbor config), populate PfxRcd from the State/PfxRcd column when numeric, and add table-driven tests with verbatim FRR 10.x single-AF and dual-AF outputs.

**Not a duplicate** — Searched 'bgp summary', 'GetBGPSummary', 'status_parse', 'PfxRcd' in issues-all.txt and prior-findings.md: only #17 (CLOSED, CLI alias for the command) exists. No prior finding touches pkg/frr/status_parse.go parsers at all.

---

#### F-065 · show route (CLI/gRPC/REST) renders kernel ECMP/multipath routes with no next-hops: routeToEntry ignores netlink Route.MultiPath, so FRR maximum-paths and multi-next-hop static routes display as a bare 'direct' entry

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-frr-routing`  ·  **Location:** `pkg/routing/routes.go`:184
- **Labels:** `bug`, `observability`, `vsrx-parity`

```
	if r.Gw != nil {
		entry.NextHop = r.Gw.String()
	} else if r.Type == unix.RTN_BLACKHOLE {
		entry.NextHop = "discard"
	} else {
		entry.NextHop = "direct"
	}

	if r.LinkIndex > 0 {
		link, err := rr.ops.LinkByIndex(r.LinkIndex)
```

**Runtime trace**

Config: `set routing-options static route 0.0.0.0/0 next-hop 10.0.2.1` + `next-hop 10.0.3.1` (config_render.go emits one FRR line per next-hop -> 'FRR creates ECMP'), or any BGP/OSPF multipath route with `maximum-paths` enabled via forwarding-table export. FRR/zebra installs ONE kernel route carrying RTA_MULTIPATH; vishvananda/netlink deserializes it with Gw=nil, LinkIndex=0 and the hops in Route.MultiPath ([]*NexthopInfo). Path: CLI `show route` -> routeReader.GetAllTableRoutes -> routeToEntry (routes.go:168) which never reads r.MultiPath: NextHop becomes "direct", Interface stays "". formatTableJunos (routeformat.go:250-254) then prints only the `*[Static/5]` header — no `> to <nh> via <if>` line at all (NextHop=="direct" && Interface==""). Same for grpcapi/server_show_routes_text.go and FormatRouteTerse (prints '>' with empty interface). The operator cannot see which next-hops an ECMP route resolves to — the exact information needed when debugging the multi-WAN/ECMP features this firewall advertises.

**Why it matters** — ECMP is a first-class supported feature (forwarding-table export, per-flow hashing on the Rust side); its primary operational surface — `show route` on CLI, gRPC and REST — hides every next-hop of any multipath route, making dead-gateway/uneven-hashing triage impossible from the firewall itself.

**Fix direction** — In routeToEntry, when len(r.MultiPath) > 0 emit one RouteEntry per NexthopInfo (Gw + LinkIndex per hop), or extend RouteEntry with a NextHops slice and update the Junos formatter to print the multi-line `to X via Y` block Junos uses for ECMP routes.

**Not a duplicate** — Searched 'multipath', 'MultiPath', 'ecmp', 'show route' across the corpus: #2389 (CLOSED, Rust FIB collapsed ECMP — fixed) and prior findings 599/608 (userspace snapshot ordering / overlay ECMP expressiveness) are dataplane-side; #29/#16/#15 are old show-route formatting issues that don't touch multipath. grep -rn MultiPath pkg/routing pkg/dataplane/userspace/routes.go confirms zero handling anywhere in this module. No prior coverage of the display-path multipath gap.

---

#### F-066 · df-bit 'set' and 'clear' are mapped to the wrong copy_df values — 'clear' silently copies the inner DF bit and 'set' clears it (mapping inverted, pinned by tests)

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-ipsec-wg`  ·  **Location:** `pkg/ipsec/policy.go`:187
- **Labels:** `bug`, `vsrx-parity`, `test-gap`

```
			if vpn.DFBit == "copy" {
				fmt.Fprintf(&b, "        copy_df = yes\n")
			} else if vpn.DFBit == "set" {
				fmt.Fprintf(&b, "        copy_df = no\n")
			}
```

**Runtime trace**

Operator commits `set security ipsec vpn to-hub df-bit clear` (the vSRX default and the standard remedy for PMTUD-blackholed paths) -> compiler stores DFBit="clear" (compiler_ipsec.go:383) -> renderConfig child block: neither branch matches, no copy_df line emitted -> strongSwan child option copy_df defaults to YES ('copy the DF bit to the outer IPv4 header in tunnel mode') -> inner packets with DF=1 produce outer ESP packets with DF=1 -> a sub-MTU transit hop drops them; if ICMP frag-needed is filtered the tunnel blackholes — exactly the failure `df-bit clear` exists to prevent. Conversely `df-bit set` (operator wants outer DF forced for PMTUD) emits `copy_df = no`, which CLEARS the outer DF bit and permits outer fragmentation. Only "copy" is correct. ipsec_test.go:791-794 pins the inverted mapping ({"set","copy_df = no"}, {"clear","",...}) so tests certify the bug.

**Why it matters** — df-bit is the operator's tool for controlling tunnel-path fragmentation behavior on a production appliance; both non-default settings do the opposite (or nothing) versus their Junos semantics, causing PMTUD blackholes ('clear' ignored) or unwanted outer fragmentation ('set').

**Fix direction** — Map clear -> `copy_df = no` (and consider `copy_df = no` as the emitted default to match Junos' default of clear); for 'set' emit `copy_df = yes` plus a rendered comment/warning that strongSwan cannot force-set DF on DF=0 inner packets; fix the pinned expectations in TestGenerateConfig_DFBit.

**Not a duplicate** — Grepped issues-all.txt and prior-findings.md for df-bit/copy_df/'df bit'/fragmentation+ipsec: zero hits. Nearest related work is #2125 (GCM proposal render) and #2330 (PMTUD in userspace-dp) — different files and mechanisms; no prior coverage of the swanctl copy_df mapping.

---

#### F-067 · parseSAOutput parses a fictional SA format — real `swanctl --list-sas` output never populates LocalAddr/RemoteAddr/TS/byte counters, so every SA-status surface (CLI/gRPC/REST) is blank

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-ipsec-wg`  ·  **Location:** `pkg/ipsec/ike.go`:586
- **Labels:** `bug`, `vsrx-parity`, `test-gap`

```
		if strings.Contains(trimmed, "local") && strings.Contains(trimmed, "===") {
			parts := strings.Split(trimmed, "===")
...
		if strings.Contains(trimmed, "local_ts") {
			if idx := strings.Index(trimmed, "="); idx >= 0 {
				target.LocalTS = strings.TrimSpace(trimmed[idx+1:])
...
		if strings.HasPrefix(trimmed, "bytes_in") || strings.Contains(trimmed, " bytes_in") {
				if strings.HasPrefix(field, "bytes_in=") {
```

**Runtime trace**

Operator runs `show security ipsec security-associations detail` with an established tunnel -> pkg/cli/cli_show_security_ipsec.go:16 GetSAStatus() -> exec `swanctl --list-sas` (ike.go:511) -> real strongSwan 5.x/6.x pretty output is `home: #1, ESTABLISHED, IKEv2, ..._i ..._r` / `  local  'id' @ 192.168.0.1[4500]` / `  home: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-128` / `    in  cbcdac0b,    676 bytes,     8 packets` / `    local  10.1.0.0/16` (verified against strongswan-swanctl 6.0.7 binary format strings: `%s: #%s, %s, IKEv%s`, `  local  '%s' @ %s[%s]`, `, %6s bytes, %5s packets`, `    local  %s`) -> parseSAOutput's address branch requires "===" (line 586), TS branch requires the token "local_ts" (line 607), byte branch requires "bytes_in=" (line 617) — none of these strings ever appear in any swanctl output mode (pretty uses spaces, --raw uses `local-ts = [...]`) -> LocalAddr/RemoteAddr/LocalTS/RemoteTS/InBytes/OutBytes stay "" -> CLI prints only `SA: name / State: ...` and detail always prints `Bytes transferred In/Out: 0/0`; grpcapi server_routing.go:236, server_show_security_text.go:60 and REST api/ipsec.go:14 return the same empty fields. The unit tests (ipsec_test.go:294-324) feed the invented `local: A === B` / `local_ts =` format, pinning the parser to output no strongSwan version has ever produced.

**Why it matters** — IPsec SA observability is effectively non-functional on a production firewall: operators cannot see tunnel endpoints, negotiated traffic selectors, or traffic counters from any of the four operator surfaces, and cannot distinguish an idle tunnel from a blackholed one (bytes always 0/0). The test suite actively certifies the broken behavior, so no regression will ever catch it.

**Fix direction** — Rewrite parseSAOutput against the real pretty format (IKE `local  '<id>' @ <ip>[<port>]` lines, child `in <spi>, N bytes, M packets` lines, child `local/remote <ts>` lines), or better, switch GetSAStatus to `swanctl --list-sas --raw` / the vici socket for a stable machine-readable schema; replace test fixtures with captured real swanctl output.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for list-sas/parseSA/security-associations/statusall/SA status: only #13 [CLOSED] ('detail is ignored' — a CLI arg-plumbing fix, not the parser) and #2884 (local_addrs re-render). No prior issue or finding covers the parser expecting a format swanctl never emits.

---

#### F-068 · LLDP never starts on Junos slash-named interfaces (ge-0/0/1) — interface name passed to net.InterfaceByName without LinuxIfName normalization

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-networkd-mon`  ·  **Location:** `pkg/lldp/lldp.go`:249
- **Labels:** `bug`, `vsrx-parity`, `test-gap`

```
		iface, err := net.InterfaceByName(lldpIf.Name)
		if err != nil {
			slog.Warn("LLDP: interface not found", "interface", lldpIf.Name, "err", err)
			continue
		}
```

**Runtime trace**

Operator: `set protocols lldp interface ge-0/0/1`. compileProtocols (compiler_protocols.go:26-27) stores the RAW value: `iface := LLDPInterface{Name: v}` where v="ge-0/0/1" (no LinuxIfName). effectiveLLDPConfig (daemon_apply.go:1541-1545) copies it verbatim: `Name: iface.Name`. lldp.Manager.Apply calls net.InterfaceByName("ge-0/0/1"). Linux interface names cannot contain '/', and xpf renamed the NIC to "ge-0-0-1" (LinuxIfName replaces '/'→'-'), so InterfaceByName ALWAYS returns ENODEV. The loop logs 'interface not found' and `continue`s, so no TX/RX session is created. Result: LLDP is a silent no-op on every canonically-named ge-/xe-/et- interface — exactly the Junos naming this product exists to clone. Works only if the operator uses the non-Junos dash form ge-0-0-1.

**Why it matters** — vSRX accepts ge-0/0/1 and runs LLDP; xpf silently does nothing on the standard interface-naming form. Neighbor discovery (used for topology/troubleshooting and cabling verification) is dead for the primary naming convention, with only an easily-missed warn log.

**Fix direction** — Normalize with config.LinuxIfName when building lldp.LLDPInterface (in effectiveLLDPConfig, mirroring how compiler_iface.go/daemon_apply.go route every other interface name through LinuxIfName), or normalize at compile in compiler_protocols.go. Add a slash-notation LLDP test — current tests only use trust0/untrust0/lo which have no slash.

**Not a duplicate** — Searched issues-all.txt for lldp -> #2992/#2608/#2551/#2372/#2036/#2035, none about interface-name normalization. #35 (CLOSED) is the same class 'port-mirroring interface lookup skips LinuxIfName normalization' but a DIFFERENT module; the LLDP path was never fixed. prior-findings.md has no lldp entries. Novel for LLDP.

---

#### F-069 · SNMP trap-group `version` is parsed by the schema but has no typed-config field → v1 trap-groups always emit v2c traps

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-obs`  ·  **Location:** `pkg/config/types_system.go`:518
- **Labels:** `bug`, `vsrx-parity`, `config-drop`

```
type SNMPTrapGroup struct {
	Name    string
	Targets []string // IP addresses
}
```

**Runtime trace**

Config: `set snmp trap-group managers version v1` plus targets. schemaSNMP (schema_system.go:845) accepts `version` with ValidateEnum{v1,v2,all}, so commit succeeds. The compiler builds SNMPTrapGroup, which has ONLY Name and Targets — there is no Version field, so the v1 selection is silently discarded. Runtime: a link flap → daemon monitorLinkState → Agent.NotifyLinkDown → sendLinkTraps (traps.go:142) → buildLinkTrap, which hardcodes the SNMPv2-Trap PDU (pduSNMPv2Trap 0xa7) and version(v2c) (traps.go:96) for every group unconditionally. A manager configured/expecting SNMPv1 traps (Trap-PDU 0xa4 with enterprise/generic-trap/specific-trap/agent-addr) receives an SNMPv2c datagram it does not parse and drops it — the operator sees no traps despite a committed, validated config.

**Why it matters** — Trap delivery is the appliance's asynchronous alerting path (link up/down today, security alarms per the roadmap). Silently downgrading a `version v1` trap-group to v2c means an SNMPv1-only NMS never receives alerts, and the misconfiguration is invisible (config commits clean). It is a Junos parity divergence: Junos honors trap-group version.

**Fix direction** — Add Version to SNMPTrapGroup, compile the parsed value, and either emit a v1 Trap-PDU when version==v1 (and both for `all`), or reject `version v1` at commit as explicitly unsupported so the drop is loud rather than silent.

**Not a duplicate** — Searched issues-all.txt for snmp/trap. #2990 (typoed trap-group child key / zero-target rejection) and #2989 (nondeterministic v2c community) touch trap-group compilation but not the version field; #1714 was doc-only (SNMP traps 'not implemented' note). The compiler_snmp_trapgroup_2990_test only asserts targets land — it never checks version. No prior finding covers version being parsed-but-dropped.

---

#### F-070 · fwdstatus Sampler issues a second, redundant 1 Hz 'status' control-socket request instead of reading the manager's cached status

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-ops`  ·  **Location:** `pkg/fwdstatus/sampler.go`:105
- **Labels:** `performance`, `control-socket-contention`, `refactor`

```
	// Worker counters — userspace-dp only.
	workerThread, workerWall := s.lastWorkerThread, s.lastWorkerWall
	if s.dp != nil {
		if us, ok := s.dp.(interface {
			Status() (userspace.ProcessStatus, error)
		}); ok {
			if st, err := us.Status(); err == nil {
```

**Runtime trace**

daemon_run.go:1387-1388 constructs the sampler at boot and calls fwdSampler.Start(ctx); Start primes one sample then ticks every SampleInterval=1s (sampler.go:17,64-80). Each sample() calls us.Status() (sampler.go:105) -> forwardingStatusDaemonUserspaceDataPlane.Status -> LegacyDataPlaneAdapter.Status (legacy_dataplane.go:449) -> Manager.Status() (manager.go:1515), which takes Manager.mu and performs a FULL control-socket round trip: requestLocked(ControlRequest{Type: "status"}) (manager.go:1527). Meanwhile Manager.statusLoop (process.go:448-465) ALREADY polls the same "status" request on its own 1s ticker and caches the result in m.lastStatus via applyHelperStatusLocked. Net effect: 2 status requests/second on the shared control socket forever while the helper runs, and Manager.mu is held across a socket round trip twice per second. During HA bulk session sync — where the Rust helper processes control connections sequentially — the extra 1/s request queues ahead of session installs, directly violating the CLAUDE.md budget ('Adding a new control socket request at >1/s will starve session installs during bulk sync'). The #2079 natpoolalarm monitor was explicitly designed around this rule (its sampler reads only cached AppliedNATView state, no socket I/O); the older #881 fwdstatus sampler was never retrofitted.

**Why it matters** — The control socket is the single serialization point for session installs, HA sync, snapshot sync and forwarding sync on a production firewall. Doubling the steady-state status traffic and holding Manager.mu across an extra socket round trip every second measurably worsens session-install latency exactly when it matters (bulk sync after failover), for zero information gain — the same counters were fetched by statusLoop within the last second.

**Fix direction** — Add a Manager.CachedStatus() (returns m.lastStatus under mu, no socket I/O — the AppliedNATView precedent) and have the fwdstatus Sampler consume it; the sampler only needs the cumulative WorkerRuntime thread_cpu_ns/wall_ns counters, which the 1 Hz statusLoop already refreshes. Keep the live Status() only in Build() (rare, query-time).

**Not a duplicate** — Searched issues-all.txt for fwdstatus/status poll/control socket/sampler — only closed feature issues #877/#878/#879/#881 (which ADDED this sampler) and #2608 (CLOEXEC, unrelated). prior-findings.md nearest hits: 'pkg/daemon/status.go PollStatus decoder churn' (that file no longer exists at HEAD; alloc-churn mechanism, not a duplicate poller) and 'userspace-dp coordinator control-socket starvation during HA bulk sync' (Rust-side sequential handling — this finding is a NEW Go-side redundant 1 Hz caller that aggravates it). #2114/#2079 natpoolalarm work codified the cached-read pattern but never touched fwdstatus.

---

#### F-071 · natshow rule detail prints per-zone-pair SNAT/DNAT session totals as the per-rule 'Number of sessions', misattributing counts to every rule

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-ops`  ·  **Location:** `pkg/natshow/source.go`:41
- **Labels:** `bug`, `vsrx-parity`

```
		_ = dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
```

**Runtime trace**

Config: rule-set trust-to-untrust (from trust, to untrust) with rule R1 (source 10.0.1.0/24 -> pool A) and rule R2 (source 10.0.2.0/24 -> interface). 100 live SNAT sessions, all translated by R1, none by R2. Operator runs `show security nat source rule all` -> RenderSourceRuleDetail: rsSessions is keyed ONLY by (IngressZone,EgressZone) (source.go:32-51), so rsSessions[{trust,untrust}] = 100. The per-rule print at source.go:112-113 (`sessions := rsSessions[ruleSetKey{rs.FromZone, rs.ToZone}]`) emits 'Number of sessions:      100' for BOTH R1 and R2. On vSRX the same command reports per-rule counts (100 / 0). The identical shape exists for DNAT in dest.go:42-54 + 104-105. Counts also conflate pool-SNAT and interface-SNAT sessions in the same zone pair, and any 'off' rule shows the full total.

**Why it matters** — Operators use per-rule session counts to verify which NAT rule traffic actually hits (rule-ordering/shadowing debugging) and to audit before deleting a rule. Showing the rule-set total on every rule tells an operator a dead rule is carrying 100 sessions — a directly misleading operational answer that diverges from the vSRX contract the renderer claims to clone.

**Fix direction** — Attribute sessions per rule: either stamp the matched NAT rule/counter ID into SessionValue at install time (the NAT counter ID already exists per rule in ApplyResult.NATCounterIDs) and key rsSessions by it, or as a stopgap re-match each forward session's pre-NAT tuple against the rule match criteria; at minimum relabel the row 'Number of sessions (rule-set):' so the output does not lie.

**Not a duplicate** — Searched issues-all.txt for 'show security nat', 'persistent-nat', 'rule detail', 'session count' and prior-findings.md for 'Number of sessions'/natshow/RenderSource — nearest: #3417 (CLOSED, interface-mode SNAT pool STATS reporting the global SNAT total per row — the pool-stats renderer, a different site/mechanism) and #2938 (CLOSED, pool capacity from config text). No issue or prior finding covers the rule-detail per-rule session misattribution in pkg/natshow.

---

#### F-072 · Port-mirroring config with duplicate ingress interface (or negative rate) passes commit, then silently disables ALL mirror instances at snapshot build (fail-closed whole-table drop with only a Warn)

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-usdp-ha-events`  ·  **Location:** `pkg/dataplane/userspace/mirrors.go`:75
- **Labels:** `bug`, `vsrx-parity`

```
			if previous, ok := seenIngress[ingressIfindex]; ok {
				return nil, fmt.Errorf("duplicate port-mirroring ingress ifindex %d in instances %q and %q", ingressIfindex, previous, name)
			}
			if inst.InputRate < 0 {
				return nil, fmt.Errorf("port-mirroring instance %q has negative input rate %d", name, inst.InputRate)
			}
			seenIngress[ingressIfindex] = name
			out = append(out, MirrorConfigSnapshot{
				IngressIfindex: ingressIfindex,
				OutputIfindex:  outputIfindex,
				Rate:           uint32(inst.InputRate),
```

**Runtime trace**

1) Operator commits: instance A input ge-0/0/1, instance B also input ge-0/0/1 (or 'input rate -5'). compilePortMirroring (pkg/config/compiler_services.go:1295-1333) performs NO validation — Atoi errors are ignored and duplicates/negatives are stored as-is; no strict-commit check exists for port-mirroring (grep of compiler_validate_strict.go confirms). Commit succeeds. 2) On snapshot publish, buildMirrorConfigSnapshots returns the duplicate/negative error, and buildMirrorConfigSnapshotsFailClosed (mirrors.go:11-21) catches it and returns nil with only slog.Warn — the snapshot ships with an EMPTY mirror table. 3) Every instance, including previously-working unrelated ones, stops mirroring; the analyzer port goes dark with no commit error, no degraded status flag, no metric. 4) Contrast: an unresolvable input/output interface is skipped per-instance (mirrors.go:51-73) — so the blast radius of a duplicate is uniquely global. Junos rejects overlapping mirror input bindings at commit; xpf commits them and drops everything at runtime.

**Why it matters** — Silent loss of traffic-visibility on a production security appliance: operators rely on port mirroring for IDS/forensics taps; a one-line config typo removes all mirroring with no commit-time feedback. The error is detected at exactly the layer that can only log, not reject.

**Fix direction** — Move the duplicate-ingress and negative/oversized-rate checks to strict commit validation (pkg/config/compiler_validate_strict.go) so the commit fails with a pointed error; keep the snapshot-time check as a backstop but degrade per-instance (drop only the conflicting instance, keep others) and surface a degraded-state counter/status field instead of only a Warn.

**Not a duplicate** — Searched mirror/port-mirroring in both corpora: #35 (LinuxIfName lookup, closed), #1376 (userspace mirroring implemented), #1545 (clone alloc perf), #1986 (mirror.rs refactor), #3617 (reject replies not mirror-cloned), #854 (eBPF-era memset). No issue covers commit-time validation absence or the whole-table fail-closed drop on duplicate ingress.

---

#### F-073 · ReadPolicyCounters rebuilds the full rule-counter index map and walks the whole policy config per call, under the manager mutex — O(P*(P+C)) per Prometheus scrape / CLI show, contending with the HA status/snapshot path

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-usdp-ha-events`  ·  **Location:** `pkg/dataplane/userspace/policycounters.go`:135
- **Labels:** `performance`, `refactor`

```
	cfg := (*config.Config)(nil)
	if m.lastSnapshot != nil {
		cfg = m.lastSnapshot.Config
	}
	ruleID := policyRuleIDForCounter(cfg, policyID)
	if ruleID == "" {
		if innerErr != nil {
			return dataplane.CounterValue{}, innerErr
		}
		return total, nil
	}
	counter, ok := buildPolicyRuleCounterIndex(&m.lastStatus)[ruleID]
```

**Runtime trace**

1) pkg/api/metrics_counters.go:225-252 loops over EVERY configured policy rule (zone-pair + global) and calls dp.ReadPolicyCounters(policyID) once per rule on every Prometheus scrape; pkg/cli/cli_show_security.go:81/:119 and pkg/grpcapi/server_show_zones.go:218/:290 do the same per show. 2) Each call takes m.mu (policycounters.go:121-122) — the same mutex serializing the 1/s status poll, snapshot publishes, HA state sync, and UpdateRGActive — then (a) policyRuleIDForCounter walks all of cfg.Security.Policies O(P) and (b) buildPolicyRuleCounterIndex(&m.lastStatus) allocates and fills a fresh map over ALL PolicyRuleCounters O(C) (policycounters.go:10-22), discarding it immediately. 3) With 1000 rules that is ~1000 lock acquisitions and ~1,000,000 map inserts + 1000 config walks per scrape (15s default), plus the same again for any 'show security policies' — measurable GC pressure and mutex contention that lands on the HA-critical manager lock during failover, when scrapes and shows are most likely.

**Why it matters** — Control-plane latency on a shared lock: the manager mutex gates snapshot publication and HA state updates; quadratic per-scrape work under it grows with policy count and degrades exactly the operations CLAUDE.md flags as contention-sensitive.

**Fix direction** — Cache the ruleID→counter index once per status poll (invalidate in recordHelperStatusLocked) and cache the policyID→ruleID resolution per snapshot generation; or add a batch ReadAllPolicyCounters() that builds the index once and lets metrics/CLI iterate without re-locking per rule.

**Not a duplicate** — Searched policy counter/ReadPolicyCounters/scrape in both corpora: #3143/#3145/#3474/#3322 concern slot-resolution correctness (fixed at HEAD); #2118 counters stuck at 0 (fixed); prior perf findings about scrape recompute target host-inbound netlink views (pkg/api/metrics_counters.go), not the per-rule counter index rebuild under m.mu. No duplicate.

---

#### F-074 · buildScreenSnapshots/buildScreenMissingProfileRefs iterate the zones map unsorted — nondeterministic Screens wire order defeats the snapshot content-hash dedup gate and breaks snapshot byte-determinism

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-usdp-programs`  ·  **Location:** `pkg/dataplane/userspace/screens.go`:16
- **Labels:** `bug`, `performance`

```
func buildScreenSnapshots(cfg *config.Config) []ScreenProfileSnapshot {
	if cfg == nil || len(cfg.Security.Screen) == 0 || len(cfg.Security.Zones) == 0 {
		return nil
	}
	var out []ScreenProfileSnapshot
	for _, zone := range cfg.Security.Zones {
		if zone == nil || zone.ScreenProfile == "" {
			continue
		}
```

**Runtime trace**

cfg.Security.Zones is a map; Go randomizes range order per iteration. With >=2 screen-bound zones (e.g. trust and untrust each referencing a profile), each buildSnapshot call emits ConfigSnapshot.Screens in a different order (builder.go:101). snapshotContentHash (builder.go:137-156) JSON-marshals the snapshot including Screens, so two builds of the IDENTICAL config hash differently with probability 1-1/N!. Concrete miss: during the XSK-startup deferral window, ApplyConfig (manager.go:648) stores a fresh-built snapshot without publishing; the status loop's syncSnapshotLocked then reaches the content-hash dedup at process.go:381 (`hash == m.lastSnapshotHash`) whose stated purpose is 'skip the control socket publish if the snapshot's forwarding-relevant content hasn't changed'. Because the fresh build's Screens order differs from the previously published build, the hashes mismatch even for content-identical rebuilds -> a redundant full apply_snapshot is pushed to the helper mid-startup — exactly the back-to-back AF_XDP reconcile self-collision the deferral logic exists to prevent. Same defect in buildScreenMissingProfileRefs (screens.go:107). The route-overlay (manager.go:967) and scheduler-republish paths copy the existing Screens slice so they are unaffected, which is why the miss is confined to full-rebuild-vs-previous-hash comparisons. It also violates the repo's snapshot byte-determinism doctrine (tunnels.go sorts WG peers specifically so 'both HA nodes serialize byte-identical snapshots', #1434 §5.4) — every other builder in the package (zones, cos, filters, neighbors, interfaces) sorts map keys first.

**Why it matters** — The content-dedup optimization exists because redundant apply_snapshot publishes force full helper-side snapshot rebuilds and can self-collide with XSK bringup on a production HA appliance; it is silently defeated for any multi-zone screen config. Nondeterministic wire bytes also make HA-peer snapshot diffs and wire fixtures unreproducible.

**Fix direction** — Collect and sort zone names before iterating (exactly as buildZoneSnapshots does at zones.go:500-506) in both buildScreenSnapshots and buildScreenMissingProfileRefs; add a determinism test asserting two builds of one config produce identical JSON (or identical snapshotContentHash).

**Not a duplicate** — Searched issues-all.txt for 'screen', 'deterministic', 'hash churn' and prior-findings.md for 'screens', 'buildScreen', 'snapshotContentHash', 'map iteration', 'nondeterministic'. Prior nondeterminism findings cover snmp trap communities (#2989), ddns scope iteration, and host-inbound token-order signatures (prior finding on zones.go grouping); ~40 screen issues (#3315-#3607 etc.) are all Rust-runtime or config-parse defects. No prior issue/finding covers screen-snapshot wire ordering or the content-hash dedup miss.

---

#### F-075 · A router-advertisement nat64prefix lifetime > 65528s (or an inherited router default-lifetime that large) makes ndp.PREF64 marshal fail, aborting the ENTIRE RA — the interface silently stops advertising prefixes, RDNSS, and the router itself

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-vrrp-ra`  ·  **Location:** `pkg/ra/sender.go`:774
- **Labels:** `bug`, `vsrx-parity`, `config`, `ipv6`, `test-gap`

```
	if s.cfg.NAT64Prefix != "" {
		prefix, err := netip.ParsePrefix(s.cfg.NAT64Prefix)
		if err == nil {
			pref64Life := s.cfg.NAT64PrefixLife
			if pref64Life <= 0 {
				pref64Life = lifetime
			}
			ra.Options = append(ra.Options, &ndp.PREF64{
				Lifetime: time.Duration(pref64Life) * time.Second,
				Prefix:   prefix,
			})
```

**Runtime trace**

Config `set protocols router-advertisement interface ge-0-0-1 nat64prefix 64:ff9b::/96 lifetime 100000` commits cleanly: the schema leaf uses ValidateIntegerMin(0) (schema_routing.go:447) with NO upper bound. At runtime buildRA() sets pref64Life=100000 and appends ndp.PREF64{Lifetime:100000s}. sendRA() (line 633) calls conn.WriteTo(ra,...) → ndp marshalOptions (option.go:1067) → PREF64.marshal (option.go:803): scaledLifetime = round(100000/8) = 12500 > 8191 → returns error 'pref64 scaled lifetime is too large'. marshalOptions returns that error, RouterAdvertisement.MarshalBinary returns it (message.go:312-314), WriteTo returns it, sendRA logs 'ra: failed to send RA' and returns having emitted NOTHING. Every periodic RA (advTimer), every RS-solicited RA, and the startup burst on that interface fail identically → the link gets no PIO/RDNSS/router-lifetime at all, so hosts lose SLAAC and default-router. Same trap on the default path: pref64Life<=0 inherits `lifetime` (router default-lifetime), so a committed default-lifetime>=65529 (also unbounded, schema_routing.go:376) plus any nat64prefix trips the identical abort.

**Why it matters** — A NAT64/PREF64 lifetime the operator can commit turns into a total, silent RA blackhole for the whole interface (not just the PREF64 option) — the firewall stops being a default IPv6 router for that segment, which is a hard connectivity outage visible only as a repeated warn log.

**Fix direction** — Cap the PREF64 scaled lifetime at commit (ValidatePREF64Lifetime: reject >65528s, or the value must be a <=8191 multiple of 8s) AND make buildRA defensive: pre-check the PREF64 (and each option's) marshalability, dropping only the offending option rather than letting one bad option abort the whole RA. Also cap router default-lifetime at 65535 (uint16). Add an RA-sender test asserting a bad PREF64 lifetime does not suppress the prefix/RDNSS options.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for pref64/scaled lifetime/NAT64 lifetime. CLOSED #2497 added ValidatePREF64CIDR for the prefix LENGTH and typed the lifetime as ValidateIntegerMin(0) only — it never bounded the lifetime's upper end, which is the exact defect here. #2271 (PreferredLifetime>ValidLifetime) is a different option. Not a duplicate.

---

#### F-076 · RFC 5798 §6.4.2 violation: a BACKUP never adopts the Master's advertised interval — masterDownInterval always uses the LOCAL advert interval, so an interval mismatch flaps instead of converging

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-vrrp-ra`  ·  **Location:** `pkg/vrrp/instance.go`:599
- **Labels:** `vsrx-parity`, `bug`, `rfc-conformance`, `test-gap`

```
func (vi *vrrpInstance) masterDownInterval() time.Duration {
	advert := vi.advertInterval()
	skew := time.Duration(256-vi.getPriority()) * advert / 256
	return 3*advert + skew
}
```

**Runtime trace**

ParseVRRPPacket decodes the Max Advertisement Interval into VRRPPacket.MaxAdvertInt (packet.go:105,152), but neither handleBackupRx, handleMasterRx, nor recordMasterAdvert ever reads it. masterDownInterval() computes 3*Advert+Skew purely from vi.advertInterval() (the LOCAL cfg.AdvertiseInterval). RFC 5798 §6.4.2 requires a BACKUP to Set Master_Adver_Interval to the Adver Interval field from the received ADVERTISEMENT and recompute Master_Down_Interval from it. Scenario: master configured advertise-interval 3 (3s), backup configured 1 (1s). Master emits every 3s; backup's master-down horizon is ~3.6s (own 1s), which is fine — but if the backup is the one with the SHORTER interval and the master's is longer, the backup's timer expires before the next master advert arrives and it wrongly becomes a second MASTER → dual-master flap. keepalived/vSRX tolerate an interval skew by adopting the master's value; xpf does not.

**Why it matters** — A benign asymmetric-interval config (or a mid-upgrade node running a different interval) produces split-brain/flapping instead of stable election — the opposite of what an HA feature should do under partial misconfiguration.

**Fix direction** — On each received advert in BACKUP, adopt pkt.MaxAdvertInt (centiseconds→ms) as the effective master interval for the master-down computation (store it on the instance and use it in masterDownInterval when in BACKUP), per RFC 5798 §6.4.2. Add a test with mismatched intervals asserting no spurious MASTER transition.

**Not a duplicate** — grep for master.advert.interval/MaxAdvertInt/adopt/advertised interval in issues-all.txt/prior-findings.md returned zero hits. The prior VRRP fixes (#2082 preempt gate, #2850 hold-time) concern preemption timing, not adoption of the peer's advertised interval. Novel.

---

#### F-077 · VRRP accept-data is parsed and stored but never enforced — the VIP is always a live kernel address, so xpf always accepts data to the VIP regardless of the configured (or defaulted-off) accept-data setting

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `go-vrrp-ra`  ·  **Location:** `pkg/vrrp/vrrp.go`:44
- **Labels:** `vsrx-parity`, `security`, `bug`

```
					AcceptData:        vg.AcceptData,
					AdvertiseInterval: vg.AdvertiseInterval,
					VirtualAddresses:  vg.VirtualAddresses,
```

**Runtime trace**

The compiler fills Instance.AcceptData from `accept-data` (compiler_interfaces.go:709). becomeMaster() → addVIPs() (instance.go:1769) does netlink.AddrAdd of every VIP as a real kernel address, so the kernel unconditionally answers ICMP echo / TCP / UDP destined to the VIP. Grep confirms AcceptData is READ nowhere in pkg/vrrp/{instance,manager,track}.go — it is dead once collected. Junos/RFC 5798 semantics: a non-owner MASTER (priority<255) must NOT accept data addressed to the VIP unless accept-data/Accept_Mode is set (ARP/ND for the VIP is still answered). xpf behaves as accept-data=true always: configuring `accept-data` is a silent no-op AND the Junos default (do-not-accept) is not honored.

**Why it matters** — Silent divergence from documented vSRX behavior: an operator relying on the accept-data default to keep the VIP from answering probes on the backup-facing side, or who explicitly toggles it, gets neither behavior — a security/parity surprise on a firewall where VIP reachability is a policy decision.

**Fix direction** — Either implement enforcement (nftables/ip-rule to drop non-ARP/ND/VRRP traffic to a VIP whose instance has AcceptData=false and priority!=255) or, at minimum, reject/warn at commit that accept-data is unimplemented so the config is not silently misleading. Add a test asserting the chosen semantics.

**Not a duplicate** — grep of issues-all.txt/prior-findings.md/known-gaps.md for accept-data/accept-mode/accept_data returned zero hits. Novel.

---

#### F-078 · build_cos_batch_from_queue never clears pop_snapshot_stack at batch start — lazily-promoted non-exact flow-fair queues violate the documented TX_BATCH_SIZE stack bound (debug panic, unbounded release-build growth)

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `rs-cos-tx`  ·  **Location:** `userspace-dp/src/afxdp/cos/queue_service/mod.rs`:1633
- **Labels:** `bug`, `performance`, `test-gap`

```
            let mut items = VecDeque::new();
            let mut remaining_root = root_budget;
            let mut remaining_secondary = secondary_budget;
            let mut batch_bytes = 0u64;
            while items.len() < TX_BATCH_SIZE {
                // #1763 Lever A — fused select+pop. ...
                let Some((bucket, front)) = cos_queue_peek_min_bucket(queue, u64::MAX) else {
                    break;
                };
                ...
                match cos_queue_pop_known_bucket(queue, bucket, u64::MAX) {
```

**Runtime trace**

Config: any non-exact shaped queue (best-effort/scheduler class without `exact`) that #1735 lazily promotes to flow-fair once a second distinct flow enqueues. Traffic: a burst of >2*TX_BATCH_SIZE (129+) packets backlogs the queue, then the producer pauses. Service path: drain_shaped_tx -> build_nonexact_cos_batch -> select_nonexact_cos_guarantee_batch (or select_cos_surplus_batch_filtered) -> build_cos_batch_from_queue. Batch 1: 64 pops via cos_queue_pop_known_bucket(push_snapshot=true), each pushing a CoSQueuePopSnapshot; transmit fully commits; NOTHING pops or clears the 64 snapshots (only cos_queue_push_back and the EXACT drain_* fns clear, and maybe_demote_drained_best_effort skips a non-quiescent queue). Batch 2 on the still-backlogged queue with no interleaving enqueue: first cos_queue_pop_known_bucket_inner hits `debug_assert!(ff.pop_snapshot_stack.len() < TX_BATCH_SIZE)` (pop.rs:204) with len==64 -> PANIC in any debug/dev build (worker thread dies, bindings served by it stall). In release: Vec::push reallocs past its preallocated TX_BATCH_SIZE capacity on the hot path and the stack grows by up to 64 stale entries per committed batch, bounded only by the queue backlog (a flow-aware buffer of ~65K packets -> ~65K snapshots) until a new enqueue or the 4-settle demotion clears it. The exact-queue drains got this batch-start clear explicitly (drain.rs:162-164 and 461-463, '#785 Codex round-3 NEW-2'); the non-exact batch builder became a flow-fair pop site only when #1735 generalized promotion and never received the same clear.

**Why it matters** — The pop-snapshot stack bound is a documented invariant ('Stack capacity is preallocated to TX_BATCH_SIZE ... push is amortized O(1) and allocation-free'); violating it panics the worker in every debug/test build that drives two consecutive committed batches, causes hot-path allocation in release, and leaves large stale-snapshot state alive on production best-effort queues. It also means no dev-build soak of bursty best-effort CoS traffic can pass, masking other testing.

**Fix direction** — Clear ff.pop_snapshot_stack at the top of build_cos_batch_from_queue (both Local and Prepared arms run peek/pop with no prior rollback dependency, mirroring the exact drains), and add a regression test that services two full committed batches from a lazily-promoted non-exact queue without interleaving enqueues.

**Not a duplicate** — Grepped issues/prior-findings/recent-commits for pop_snapshot/snapshot_stack/snapshot — zero hits on this mechanism. Nearest related: #1355 (CLOSED, push_front snapshot-axis refactor), #913/#785 in-code snapshot design notes (batch-start clears added only to the exact drain fns), #1735 (CLOSED, introduced the lazy non-exact promotion that makes this path reachable). No issue covers the non-exact batch builder missing the clear.

---

#### F-079 · dispatch direct-TX debug-log tuple-mismatch path pushes the same UMEM tx_offset onto free_tx_frames twice — duplicate free-list entry aliases two in-flight TX frames

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `rs-cos-tx`  ·  **Location:** `userspace-dp/src/afxdp/tx/dispatch/mod.rs`:915
- **Labels:** `bug`, `security`, `dataplane`

```
                                    target_binding
                                        .tx_pipeline
                                        .free_tx_frames
                                        .push_front(tx_offset);
                                    record_exception(...);
                                    build_failed = true;
                                }
                            }
                            if build_failed {
                                target_binding
                                    .tx_pipeline
                                    .free_tx_frames
                                    .push_front(tx_offset);
                                true
```

**Runtime trace**

Input: a debug-log feature build (used for live diagnosis) forwarding a packet on the direct-TX path (owner matches target, free TX frame available). enqueue_pending_forwards -> direct-TX build writes the frame into tx_offset -> build_forwarded_frame_into_from_frame returns Some(written) -> cfg!(feature="debug-log") block re-parses the built frame; forward_tuple_mismatch_reason returns Some (built L4 ports differ from expected_ports, e.g. a NAT builder edge or unparsable built frame) -> line 898-901 pushes tx_offset onto free_tx_frames AND sets build_failed=true -> control falls to line 914 `if build_failed` which pushes tx_offset onto free_tx_frames A SECOND TIME (lines 915-918). free_tx_frames now contains the same offset twice. The next two direct-TX/prepared builds pop_front the same offset for two different packets: the second memcpy overwrites the first frame's bytes while the first may already sit in the kernel TX ring -> corrupted or cross-flow bytes transmitted on the wire. Both PreparedTxRequests carry PreparedTxRecycle::FreeTxFrame, so on completion both recycle the offset again and the duplication persists indefinitely (permanent frame aliasing for the binding's lifetime). build_failed cannot be true on entry to line 914 from any other path (the only earlier setter, the segmentation debug check at line 421, forces copied_source_frame=true which skips this block), so the second push is exactly the duplicate.

**Why it matters** — On a security appliance a duplicated UMEM frame offset means two independent packets share one 4 KB frame: transmitted frames can carry another flow's payload bytes (cross-flow data leak on the wire) and checksum/parse-corrupted packets. debug-log builds are deployed to live clusters for diagnosis, and the trigger (tuple mismatch) is precisely the condition where an underlying builder bug already exists — the error handler converts a diagnostic event into persistent dataplane corruption.

**Fix direction** — Delete the push_front at lines 898-901 inside the mismatch branch (let the common `if build_failed` push at 914-918 own the recycle), or make the mismatch branch `continue`-style exclusive. Add a debug assertion (test-only) that free_tx_frames never contains duplicate offsets after a dispatch pass.

**Not a duplicate** — Grepped issues-all.txt + prior-findings.md for free_tx_frames/double/dup/tuple mismatch/debug-log. Nearest: #2208 (CLOSED — ingress descriptor LEAK on bare continue in the same function; opposite defect direction, fixed at HEAD and its fix comments surround this site) and prior finding 'debug-log lab selectors' (poll_descriptor, unrelated). No issue or prior finding covers a double-push/duplicate free-list entry.

---

#### F-080 · Input-filter `then count` terms double-count: verdict evaluator and TX-selection evaluator both record the same term for the same packet (2x per packet on DSCP/L4-sensitive CoS filters)

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `rs-filter`  ·  **Location:** `userspace-dp/src/filter/engine/tx_selection.rs`:140
- **Labels:** `bug`, `vsrx-parity`, `observability`

```
        if !term_matches_v4(
            term, src_ip, dst_ip, protocol, src_port, dst_port, dscp, extra,
        ) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        merge_matched_tx_modifiers(&mut acc, filter, term, now_ns, packet_bytes);
```

**Runtime trace**

Config: `filter CLASSIFY term t1 { from dscp af41; then { count af41-pkts; forwarding-class video; accept } }` applied `input` on ge-0-0-1, no output filter on egress. Compiler sets has_dscp_match_terms=true (cache-sensitive, flow-cache declines) AND affects_tx_selection=true (forwarding-class term). Per packet of an established session: (1) session-hit slow path -> poll_descriptor/mod.rs:842 evaluate_dscp_sensitive_input_filter_on_session_hit -> poll_descriptor/filter.rs:229 evaluate_interface_filter_non_routing_counted(count_policy=Always) -> eval.rs:333 record_filter_counter(af41-pkts) [count #1]; (2) verdict Accept -> forward_request.rs:186 resolve_cos_tx_selection_at -> cos_classify.rs:431 ingress gate `(!has_output_filter && filter.affects_tx_selection) || filter.has_three_color_policer_terms` passes -> cos_classify.rs:435 evaluate_filter_ref_tx_selection_runtime_counted -> tx_selection.rs:140 record_filter_counter(af41-pkts) [count #2]. Result: packets and bytes 2x on EVERY packet of the flow. For a non-cache-sensitive filter the same pair fires on every session-MISS packet (first packet of every flow counted twice: eval.rs Always count + tx-selection count; subsequent packets replay CachedFilterCounters once — flow_cache_hit.rs:135). Additional divergence: when an output filter exists AND the ingress filter has three-color policer terms, the LIVE path still counts ingress `then count` terms (gate's `|| has_three_color_policer_terms` arm) while the CACHED descriptor takes only output counters (cos_classify.rs:210-213), so cached vs uncached flows report different counts.

**Why it matters** — Filter term counters feed `show firewall`, gRPC, and Prometheus xpf_filter_hits_total; operators use them for billing/capacity/diagnostics. A DSCP-classification filter with a counter — the canonical Junos CoS pattern — inflates 2x on every packet, and every flow gets a first-packet off-by-one. Junos counts a term once per packet traversing the filter. The #2620 fix built explicit counter-ownership machinery for the verdict-vs-routing-evaluator pair but the verdict-vs-TX-selection pair has no ownership policy at all.

**Fix direction** — Extend the #2620 NonRoutingCountPolicy idea across the verdict/TX-selection boundary: make exactly one evaluator own `then count` per packet — e.g. the TX-selection eval (which runs per forwarded packet) owns counting when the filter affects_tx_selection/has policers, and the verdict eval skips counting in that case (but still counts on its terminal discard/reject exits, which never reach TX). Align resolve_cached_cos_tx_selection's counter set with the live gate. Add a test driving a dscp-match + forwarding-class + count filter through verdict + TX-selection and asserting exactly one increment per packet.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'double-count', 'then count', 'counter', 'tx_selection'. Nearest: #2620 (CLOSED, non-PBR precheck vs PBR routing evaluator double-count — different evaluator pair, its OnlyTerminalNonAccept machinery does not gate the TX-selection eval), #2573 (CLOSED, cached path UNDER-count of fall-through counters), #3448/#3461 (counter clear/scrape). No prior issue/finding covers the verdict-evaluator + CoS-TX-selection-evaluator pair recording the same term twice.

---

#### F-081 · Dual-fabric HA: dataplane fabric redirect always pins to the first fabric link — no liveness check and no failover to fab1

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `rs-forwarding`  ·  **Location:** `userspace-dp/src/afxdp/forwarding/mod.rs`:405
- **Labels:** `bug`, `vsrx-parity`, `test-gap`

```
pub(super) fn resolve_fabric_redirect_from_list(
    fabrics: &[FabricLink],
) -> Option<ForwardingResolution> {
    let fabric = fabrics
        .iter()
        .find(|fabric| fabric.parent_ifindex > 0)
        .copied()?;
    Some(ForwardingResolution {
        disposition: ForwardingDisposition::FabricRedirect,
```

**Runtime trace**

Config: dual fabric per #107 (`fabric-options ... fab0 + fab1`). Go buildFabricSnapshots (pkg/dataplane/userspace/fabric.go:11-64) emits BOTH fabrics sorted by name (fab0 first) with NO operstate/carrier check — parentIfindex stays >0 for a down link. Rust populate_fabrics/resolve_fabric_links_from_snapshots preserve that order. State: split-RG or failback window — node B receives a packet for a session owned by node A -> enforce_ha_resolution_snapshot -> HAInactive -> redirect_via_fabric_if_needed -> resolve_fabric_redirect -> resolve_fabric_redirect_from_list picks fabrics[0] (fab0) unconditionally. Failure: fab0 parent cable pulled / link down while fab1 healthy -> every redirected frame is TXed into the dead fab0 parent XSK (or drops at bind) -> peer-owned TCP sessions die, the exact failure class fabric forwarding exists to prevent (#1946/docs/fabric-cross-chassis-fwd.md). Meanwhile the CONTROL plane does fail over (pkg/cluster/sync_conn.go:405 'fab1 is used only when fab0 is down'), so session-sync stays up and masks the dataplane blackhole.

**Why it matters** — vSRX dual-fabric exists precisely for fabric-link redundancy. xpf implemented dual fabric for config/sync (#107, #123, #125) but the userspace dataplane redirect — the actual packet path — is single-link with no health gate. A single fabric cable failure during any RG-split window silently blackholes cross-chassis traffic despite full redundancy.

**Fix direction** — Thread fabric-link liveness into FabricLink (Go: include operstate/carrier in FabricSnapshot and re-SyncFabricState on link events; Rust: select the first fabric whose parent link is up, falling back to the next). Add a forwarding test that builds two FabricLinks and asserts selection fails over when the first is marked down (today no test covers multi-fabric selection at all — tests.rs only exercises single-fabric snapshots).

**Not a duplicate** — Searched 'fab1', 'dual fabric', 'fabric link down', 'fabric redirect' in issues-all.txt/prior-findings.md. #121 (eBPF-era fabric_fwd staleness, closed pre-retirement), #123/#125 (control-plane sync/gRPC fab1 failover — fixed for control plane only), #139 (per-link counters), prior findings 602 (fabric links silently skipped on malformed MAC — build-time observability) and 606 (update_fabrics not persisted). None cover the userspace dataplane redirect selecting only the first FabricLink with no liveness/failover.

---

#### F-082 · Per-packet heap allocations and duplicate full route lookups on the fabric flow-cache-hit fast path (cached_flow_decision_valid)

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `rs-forwarding`  ·  **Location:** `userspace-dp/src/afxdp/forwarding/mod.rs`:700
- **Labels:** `performance`

```
    if resolution.disposition == ForwardingDisposition::FabricRedirect {
        let local_resolution = enforce_ha_resolution_snapshot(
            forwarding,
            ha_state,
            now_secs,
            lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, target_ip),
        );
```

**Runtime trace**

poll_descriptor/flow_cache_hit.rs:112 calls cached_flow_decision_valid on EVERY flow-cache hit. For a cached FabricRedirect decision (split-RG steady state: RG owned by peer) each packet runs lookup_forwarding_resolution_with_dynamic -> lookup_forwarding_resolution_inner_ecmp (mod.rs:1130-1217), which allocates: `table.map(canonical_route_table).unwrap_or_else(|| DEFAULT_V4_TABLE.to_string())` (mod.rs:1141 — one String per packet), does a HashMap<String, Vec<RouteEntry>> lookup, a linear `routes.iter().find(prefix.contains)` scan of the whole per-table Vec, a linear connected_v4 scan with per-entry String compares, plus sharded-neighbor-map probes. For fabric-INGRESS packets (owner node receiving redirected traffic) mod.rs:719-731 additionally calls prefer_local_forward_candidate_for_fabric_ingress, which performs a SECOND full lookup_forwarding_resolution_with_dynamic per packet (mod.rs:497). Net: 1-2 heap allocations + 1-2 O(routes) scans + neighbor shard probes per packet for all fabric-involved traffic, sustained for as long as an RG is peer-owned (a legitimate active/active split-RG steady state), on the mlx5 zero-copy fast path.

**Why it matters** — Violates the project's hot-path allocation rule (docs/engineering-style.md); the code comment at mod.rs:689-692 shows awareness ('instead of taking a neighbor-map lock on every cache hit') for the RG-reactivation early-out, but the FabricRedirect / fabric-ingress branches still pay full lookups + String allocation per packet. Under HA failover load (exactly when fabric forwarding carries production traffic) this adds allocator pressure and cache misses per frame across 6 workers.

**Fix direction** — Intern route-table names to u16 ids at forwarding-build time (routes_v4: FastMap<TableId, Vec<...>>, ConnectedRoute.table: TableId) so lookups are integer-keyed with zero allocation; cache the local re-resolution result on the flow-cache entry stamped with the neighbor/FIB generation (re-validate only on generation change, mirroring the #3048 mac_change_epoch pattern) instead of re-running full lookups per packet.

**Not a duplicate** — Searched prior-findings.md/issues-all.txt for 'linear', 'LPM', 'trie', 'allocat', 'cached_flow_decision', 'route lookup'. Nearest: prior findings on policy linear scan (#1609 class), NAT rule linear scans, AppCatalog linear scan, and shared-session-map mutex on cache MISS — none cover the per-HIT full route lookup + String allocation in cached_flow_decision_valid/prefer_local_forward_candidate_for_fabric_ingress or the String-keyed route tables.

---

#### F-083 · NPTv6 silently mistranslates addresses whose adjusted word is 0xFFFF instead of RFC 6296-mandated discard (/48) or next-word selection (/64) — reply collapses onto the 0x0000 host

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `rs-nat`  ·  **Location:** `userspace-dp/src/nptv6.rs`:347
- **Labels:** `bug`, `rfc-conformance`, `vsrx-parity`

```
                // Adjust the word after the prefix: outbound uses adjustment directly.
                // #3233: skip the fixup entirely for a checksum-neutral prefix
                // pair (ones-complement-zero adjustment) — the prefix swap is
                // already checksum-neutral, and applying adjust_word would fold
                // a valid 0xFFFF host-ID word to 0x0000.
                if !is_zero_adjustment(rule.adjustment) {
                    let adj_word = if rule.prefix_words >= 4 { 4 } else { 3 };
                    words[adj_word] = adjust_word(words[adj_word], rule.adjustment);
                }
                *src = words_to_ipv6(&words);
```

**Runtime trace**

Config: NPTv6 rule internal fd00:1:1::/64 -> external 2001:db8:9::/64 with a NON-checksum-neutral pair (adjustment A, not ones-complement zero). Internal host H = fd00:1:1:0:ffff::10 (IID word[4] = 0xFFFF) opens an outbound TCP flow. (1) translate_outbound (nptv6.rs:332-354) rewrites the prefix, is_zero_adjustment(A) is false, adjust_word(0xFFFF, A) at line 347: 0xFFFF is ones-complement negative zero so the fold yields A (no 0xFFFF->0x0000 remap fires) -> wire source 2001:db8:9:0:A::10. (2) The reply's dst hits translate_inbound (nptv6.rs:304-327): inv_adj = !A, adjust_word(A, !A) = A + !A = 0xFFFF -> remapped to 0x0000 (nptv6.rs:110) -> internal dst fd00:1:1:0:0::10 — the WRONG host (word 0x0000, not 0xFFFF). (3) The reverse session key installed from the forward direction carries the 0xFFFF host, so the rewritten reply misses the session, gets policy-evaluated as a fresh inbound flow to the 0x0000 host, and is dropped or misdelivered — H's connectivity through NPTv6 is silently broken. RFC 6296 §3.2 requires the datagram be DISCARDED (SHOULD emit ICMPv6 Destination Unreachable) when the subnet word is unmappable (0xFFFF, /48 case), and §3.5 requires /49-or-longer mappings to inspect words at bits 64..79/80..95/96..111/112..127 in sequence and adjust the FIRST word not initially 0xFFFF — under which H is fully translatable via word 5. HEAD does neither: it always adjusts word[3]//word[4] unconditionally.

**Why it matters** — A firewall doing prefix translation must never silently deliver one customer host's return traffic to a different host. Any internal host with 0xFFFF in the fixed adjustment word gets a broken, asymmetric translation (blackholed replies or cross-host misdelivery) with no counter, no log, and no commit-time rejection — and for /64 rules the RFC provides a correct translation the implementation refuses to perform. nptv6_tests.rs:494-496 even hard-codes the misconception ('0xFFFF maps to 0x0000 irreversibly per RFC 6296 — avoid such addresses in round-trip tests').

**Fix direction** — In translate_outbound/translate_inbound for prefix_words==4 (/64), scan words 4..8 and adjust the first word != 0xFFFF (both directions must derive the same word — per RFC 6296 §3.5 the choice is on the ORIGINAL/internal-side value, so inbound must locate the word by inverse mapping); for prefix_words==3 (/48), return false (drop) when words[3]==0xFFFF and bump a counter (optionally emit ICMPv6 dest-unreach via the existing generated-error path). Add fail-on-revert tests for both cases and fix the nptv6_tests.rs comment.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for 'nptv6', '0xFFFF', '6296'. Nearest is #3233 (CLOSED): it fixed ONLY the checksum-neutral (ones-complement-zero adjustment) pair by skipping the fixup. This finding is the GENERAL non-neutral-adjustment case with a 0xFFFF input word — a different mechanism (input-word value, not adjustment value) that #3233's is_zero_adjustment guard does not reach. #2241 (overlap rejection) and #2240 (fail-closed parsing) are unrelated. RFC 6296 §3.2/§3.5 text fetched and verified.

---

#### F-084 · Legacy address list silently discards a bare `any` token when mixed with other tokens — deny rule narrows instead of matching all (fail-open on drifted/hand-built snapshots)

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `rs-policy`  ·  **Location:** `userspace-dp/src/policy.rs`:2544
- **Labels:** `bug`, `security`

```
    for tok in addresses {
        match tok.as_str() {
            // Bare `any` is the unconstrained both-families wildcard;
            // it leaves no per-family scoping and falls through to the
            // legacy empty→MatchAny convention below for both families.
            "any" | "" => {}
            "any-ipv4" => any_v4 = true,
            "any-ipv6" => any_v6 = true,
            s => {
                if !parse_address(s, &mut v4, &mut v6) && malformed.is_none() {
```

**Runtime trace**

Input: a legacy-shaped rule snapshot (source_book_ids/source_literals both empty — a version-drifted or hand-built producer, the exact threat model #3367 hardened this same function against) with action="deny", from trust to untrust, source_addresses=["198.51.100.0/24","any"]. Note the CURRENT Go emitter produces exactly this mixed shape on the legacy field (expandUserspacePolicyAddresses addUnique("any") + literals, then sort.Strings — pkg/dataplane/userspace/capabilities.go:147-183) for `source-address [ X any ]`. Path: parse_policy_state_with_counters → source_is_v3_shaped=false → parse_legacy_address_set (policy.rs:2533): token "198.51.100.0/24" pushes a v4 prefix; token "any" hits the no-op arm at line 2544 and is DISCARDED; any_family_scoped=false → v4_set = PrefixSetV4::from_prefixes([198.51.100.0/24]) = Linear, NOT MatchAny. The in-function comment (lines 2541-2543) claims `any` "falls through to the legacy empty→MatchAny convention" — that only holds when the vec stays empty; with any other literal present the `any` is simply lost. Runtime: packet trust→untrust src=203.0.113.5 → evaluate_policy_result_l3_aware zone-pair tier → try_match_rule → source_literal_v4.contains fails, match_any=false → rule does not match → falls through to default-policy. Under permit-all (or a later broad permit) traffic the operator denied with `source-address [ X any ]` is FORWARDED. Same tokens on the v3 path do the right thing: parse_v3_literal_set line 2602-2605 sets any_v4=any_v6=true → MatchAny (Codex r5 F-r5-1 fix). Sub-case: legacy ["any","any-ipv4"] → any_family_scoped=true → v6 collapses to from_v3_literals(empty)=MatchNone even though `any` was listed.

**Why it matters** — A deny rule whose address side silently narrows is the exact deny-fail-open class this codebase treats as reportable even on drift-only paths — #3367 (UnrepresentableLegacyAddress) and #3711 (UnrepresentableV3Address) hardened THIS function and its v3 sibling against malformed tokens under the identical 'corrupt / hand-built / version-drifted snapshot' threat model, but a perfectly VALID `any` token mixed with literals still silently drops its semantics on the legacy path only.

**Fix direction** — Mirror the v3 parser: in parse_legacy_address_set, a bare `any` token should set both any_v4 and any_v6 (forcing MatchAny on both families) instead of the no-op arm; keep `""` as a no-op for the Go legacy ""→any mapping or route it through the same flag. Add a test pinning legacy mixed ["any", literal] → MatchAny both families.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for 'legacy address', 'match-any', 'any-ipv4', '3367', '3711', 'parse_legacy'. #3367 (closed) covers MALFORMED legacy tokens silently dropped→MatchAny widening; #3711 covers malformed v3 literals→MatchNone; #2008 H11 covers family-wildcard cross-family leak on this path; Codex r5 F-r5-1 fixed bare-`any` handling for the V3 parser only. No prior issue/finding covers a VALID bare `any` token being discarded when mixed with literals on the legacy path (narrowing, not widening/malformed) — mechanism-distinct from all four.

---

#### F-085 · Flowless screen branch bypasses src-independent screens (LAND anti-spoof, icmp-flood, udp-flood, ip-source-route) for non-query ICMP and non-first fragments

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `rs-screen`  ·  **Location:** `userspace-dp/src/afxdp/poll_stages.rs`:438
- **Labels:** `bug`, `security`, `vsrx-parity`

```
        return match screen.check_fragment_screens_l3(zone_name, &screen_pkt) {
            ScreenVerdict::Drop(reason) => {
                emit_screen_drop_event(
                    worker_ctx.event_stream,
                    &screen_pkt,
                    meta,
                    zone_id,
                    reason,
                    event_now_ns_from_secs(now_secs),
                );
                counters.record_screen_drop(reason);
```

**Runtime trace**

Config: zone untrust has `tcp land` and `icmp flood threshold 100`. (1) Attacker sends a flood of non-fragmented ICMP Dest-Unreachable (type 3) packets (or one spoofed src_ip==dst_ip ICMP type-3). (2) poll_stages stage 1 calls parse_session_flow_from_bytes; inspect.rs:1250-1253 sees PROTO_ICMP with meta_icmp_identifier_bearing==false (type 3 is not 0/8/13/14/15/16), so meta_flow=None and the frame parser also gates it -> returns None -> flow=None. (3) stage_screen_check (poll_stages.rs:312) has_profiles==true, zone resolves to untrust, then `let Some(flow)=flow else{` (line 389) takes the FLOWLESS branch. (4) extract_screen_info is called with placeholder UNSPECIFIED addrs and tcp_flags=0; is_fragment=false. (5) check_fragment_screens_l3 (mod.rs:800-818) runs ONLY check_ping_of_death/check_teardrop/check_icmp_fragment — every one is gated on pkt.is_fragment, so all return None -> Pass. (6) check_land, the icmp_counters.increment flood counter, udp flood, and check_source_route are NEVER invoked on this branch. Result: the icmp-flood counter stays at 0 under an ICMP-error flood (screen silently ineffective), and a src==dst ICMP frame is admitted, directly contradicting stateless.rs:16-28 (#2215) which states LAND drops src==dst 'regardless of L4 ports (and need not even be TCP/UDP)'. #3290 WIDENED reachability: before it, non-query ICMP carried a metadata flow and DID reach check_packet_with_zone_id (which runs land+icmp-flood); making them flowless routed them to this incomplete branch.

**Why it matters** — Two configured security screens are silently defeated on a production firewall. An attacker floods with ICMP error/control types (type 3/5/11/12, ICMPv6 errors, ND/MLD) to completely evade the icmp-flood screen, and a spoofed src==dst ICMP frame bypasses the LAND anti-spoof screen the code documents as an unconditional, protocol-independent invariant. udp-flood and ip-source-route are likewise skipped for non-first fragments that reach this branch.

**Fix direction** — On the flowless branch, resolve the real src/dst from the IP header and run the src-independent screens that do not need an L4 flow — check_land, the icmp/udp flood rate counters (keyed on protocol + zone only), and check_source_route — in addition to the three L3 fragment screens. Equivalently, split check_fragment_screens_l3 into check_flowless_screens that also evaluates land/flood/source-route. The mod.rs:796-799 rationale ('they require a flow') is false for these screens.

**Not a duplicate** — Searched issues-all.txt + prior-findings.md for screen/icmp-flood/land/flowless/3064/3290. #3064 CLOSED added the flowless L3-fragment path but this is the RESIDUAL: that path omits the src-independent screens. #3290 CLOSED made non-query ICMP flowless; this is its unintended SIDE EFFECT on screen coverage — different defect/mechanism, both named. No open issue or prior finding covers icmp-flood/land bypass on the flowless branch.

---

#### F-086 · export_all_sessions HA bulk export runs entirely under the global ServerState lock with per-frame lossless backpressure — the #2962 fix was applied only to owner-RG export

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `rs-server`  ·  **Location:** `userspace-dp/src/server/handlers/mod.rs`:191
- **Labels:** `bug`, `performance`, `ha`, `vsrx-parity`

```
            "export_owner_rg_sessions" => {
                // #2962: locked phase only — enqueue + capture the wait
                // handle. The blocking ack-wait runs after the lock drops.
                export_wait = Some(export::owner_rg_kick(&mut guard, request.session_export));
            }
            "export_all_sessions" => export::all(&mut guard, &mut response),
```

**Runtime trace**

Go HA sync (pkg/daemon/daemon_ha_sync.go:293 exporter.ExportAllSessionsViaEventStream) -> pkg/dataplane/userspace/manager_ha.go:129 requestLocked(ControlRequest{Type:"export_all_sessions"}) over the CONTROL socket -> helper handle_stream acquires state.lock() (mod.rs:115, the single global ServerState mutex) -> match arm hits export::all(&mut guard) (mod.rs:191) WHILE STILL HOLDING THE LOCK -> ha.rs:612 export_all_sessions_to_event_stream builds `deltas`, drops the sessions sub-lock, then loops `handle.push_delta_lossless(delta, ...)` per session (ha.rs:682) -> send_frame_lossless (event_stream/mod.rs:516-551) blocks up to LOSSLESS_QUEUE_TIMEOUT (5s) PER FRAME retrying try_send while the bounded 8192-frame channel is full. If the daemon's event listener is slow/backlogged the channel stays full, so the whole export loop holds the global lock for an extended, session-count-scaled time. Concurrent control requests (1/s status poll, apply_snapshot, set_forwarding_state, update_ha_state) all block on state.lock(); Go's 3s control deadline (process.go:238) trips, and the manager can treat the timeout as a dataplane failure and restart the helper -> forwarding outage during HA bulk sync. This is precisely the starvation class #2962 fixed for export_owner_rg_sessions via the two-phase kick/collect, but export_all_sessions was left inline under the lock.

**Why it matters** — HA bulk resync (FullResync path) is exactly when the control plane must stay responsive; a bulk export that freezes status polls and session installs under the lock triggers the false dataplane-failure restart the project explicitly warns about (CLAUDE.md control-socket contention note; #2962). On a firewall this is a self-inflicted forwarding blip during failover.

**Fix direction** — Apply the #2962 two-phase pattern to export_all_sessions: snapshot the exportable session set under the lock, DROP the lock, then run push_delta_lossless off-lock (or route it through a kick/collect handle like owner_rg). At minimum, do not call push_delta_lossless while holding the global ServerState mutex.

**Not a duplicate** — Searched issues-all.txt + prior-findings.md for export_all/export_owner/bulk export/lock. Nearest is #2962 [CLOSED] 'export_owner_rg_sessions blocks up to 15s holding the global ServerState lock', whose fix (two-phase kick/collect in handlers/mod.rs) covers ONLY the owner_rg verb via a worker-ack wait. This is a DIFFERENT verb (export_all_sessions), a DIFFERENT blocking mechanism (push_delta_lossless per-frame 5s backpressure, not a worker ack), and the handler is still inline under the lock at HEAD — a genuine residual, not the same defect.

---

#### F-087 · syn_cookie_master_key is serialized into the on-disk state.json (world-readable) — unlike the WG private/preshared keys which are skip_serializing

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `rs-server`  ·  **Location:** `userspace-dp/src/protocol/snapshot.rs`:306
- **Labels:** `security`, `bug`, `test-gap`

```
    #[serde(rename = "syn_cookie_master_key", default)]
    pub syn_cookie_master_key: String,
```

**Runtime trace**

Go buildSYNCookieMasterKey (pkg/dataplane/userspace/screens.go:125) derives the key = SHA256(root-auth-encrypted-password material + cluster id + configured syn-flood zones) and sets ConfigSnapshot.syn_cookie_master_key -> apply_snapshot delivers it -> helper stores guard.snapshot = Some(snapshot) (server/handlers/snapshot.rs) -> any persisting request calls write_state (server/helpers.rs:1164), which serializes `Payload { status, snapshot: &guard.snapshot }` via serde_json::to_vec_pretty (helpers.rs:1173-1177). The syn_cookie_master_key field has NO skip_serializing (contrast wg_local_privkey_hex at snapshot.rs:492 and wg_preshared_key_hex at :531, both `skip_serializing` precisely because write_state persists the snapshot to disk) -> the key is written verbatim into state.json. state_writer opens the temp with OpenOptions::new().create_new(true).write(true) and NO .mode() (state_writer.rs:380-384/395-399) -> default 0644 (world-readable), inside a 0755 dir under os.TempDir()/xpf-userspace-dp (Go process.go:50, capabilities.go:21). Any local unprivileged user reads /tmp/xpf-userspace-dp/state.json and recovers the SYN-cookie master key.

**Why it matters** — The master key is the secret the SYN-cookie source-validation depends on: knowing it lets an attacker compute valid SYN-cookie ACKs for spoofed source addresses, defeating the SYN-flood protection (and it is derived from the root encrypted-password material). The state.json is never read back by the helper (pure diagnostic artifact), so it exposes the secret for zero runtime benefit — a strict regression relative to the deliberate WG-key hygiene in the same struct.

**Fix direction** — Add `skip_serializing` to syn_cookie_master_key (mirror wg_local_privkey_hex), and add a unit test asserting it is absent from the serialized snapshot (like wg_local_privkey_hex_is_skipped_in_state_snapshot). Optionally chmod the state file 0600 in state_writer.

**Not a duplicate** — Searched for syn.cookie/master.key/state.json/privkey/secret leak. #2446 [CLOSED] is about the cookie VALIDATION cache surviving profile changes (different mechanism). #1894 is fsync of master.key (durability, not exposure). The WG-key write_state leak was caught by Copilot and fixed via skip_serializing; syn_cookie_master_key was overlooked and is NOT covered by any open issue or prior finding — a NEW field-specific leak.

---

#### F-088 · wg_encap_frame resolves the outer underlay route TWICE per packet — outer_physical_egress_ifindex runs a full FIB LPM lookup once for the MTU guard and again for the outer-source lookup with identical arguments

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `rs-umem-frame`  ·  **Location:** `userspace-dp/src/afxdp/frame/wg.rs`:353
- **Labels:** `performance`

```
    let outer_mtu = outer_physical_egress_mtu(decision, forwarding, endpoint, peer_endpoint.ip());
    let wg_record_len = WG_DATA_HEADER_LEN + pad_to_16(inner_packet.len()) + POLY1305_TAG_LEN;
    if wg_encapped_size(inner_packet.len(), outer_v6) > outer_mtu {
...
    let physical_egress_ifindex =
        outer_physical_egress_ifindex(decision, forwarding, endpoint, peer_endpoint.ip());
    let egress = forwarding.egress.get(&physical_egress_ifindex);
```

**Runtime trace**

Per WG AF_XDP transit packet: wg_encap_frame (frame/wg.rs:290) -> line 353 calls outer_physical_egress_mtu(decision, forwarding, endpoint, peer_endpoint.ip()), which internally calls outer_physical_egress_ifindex (lines 160-174 -> 113-149), performing a full lookup_forwarding_resolution_v4/v6 (LPM route walk + disposition/neighbor resolution) in the endpoint's transport table. Then line 444-445 calls outer_physical_egress_ifindex AGAIN with byte-identical arguments (same decision, same forwarding snapshot, same endpoint, same peer_endpoint.ip()) to derive the outer source address. Two full route resolutions where one suffices; the second is guaranteed to return the same ifindex because nothing mutates between the calls (both read the same immutable ForwardingState snapshot).

**Why it matters** — This is the same per-packet WG egress path that #2792 (CLOSED) optimized by removing two heap Vec allocations — a full LPM route lookup is strictly heavier than a Vec alloc. On a WG-transit workload every encapped packet pays a redundant route walk, and the PTB path (wg_endpoint_physical_outer_mtu) adds a third for MTU-probing flows.

**Fix direction** — Resolve outer_physical_egress_ifindex once in wg_encap_frame, then derive the MTU from `forwarding.egress.get(&ifindex).map(|e| e.mtu)` locally (the body of outer_physical_egress_mtu minus the second lookup). Keep the helpers for the PTB path but add an `_with_ifindex` variant so both consumers share one resolution.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for wg/wireguard/lookup/twice/lpm. Nearest: #2792 (wg_encap_frame per-packet heap Vecs — different mechanism, fixed), #2680/#2701 (which INTRODUCED these two helper call sites), #2734 (per-endpoint vs per-flow ECMP spread). No prior issue/finding covers the duplicated route resolution itself.

---

#### F-089 · Flow-cache neighbor_mac_epoch is stamped AFTER neighbor resolution — TOCTOU re-opens the #3048 stale-MAC blackhole in exactly its target scenario

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `x-hpc`  ·  **Location:** `userspace-dp/src/afxdp/poll_descriptor/mod.rs`:3718
- **Labels:** `bug`, `concurrency`, `ha`

```
                            // #3048: stamp the live neighbor-MAC-change
                            // epoch so a later kernel ARP/NDP MAC change
                            // for this descriptor's next-hop evicts the
                            // cached stale dst_mac on the next fast-path
                            // hit (see neighbor_mac_epoch_stale).
                            entry.neighbor_mac_epoch =
                                worker_ctx.dynamic_neighbors.mac_change_epoch();
```

**Runtime trace**

1) New/re-resolved flow F takes the session-miss slow path on worker W: lookup_forwarding_resolution_v4 -> lookup_neighbor_entry (forwarding/mod.rs:1984) reads dynamic_neighbors and captures MAC_old into decision.resolution.neighbor_mac while mac_change_epoch == E. 2) Concurrently the upstream gateway fails over (VRRP): the netlink monitor or an ARP-reply learn on another worker calls ShardedNeighborMap::insert_if_changed (sharded_neighbor.rs:180-203), which fetch_adds mac_change_epoch E->E+1 and installs MAC_new. 3) Hundreds of lines later in the SAME descriptor pass, W builds the FlowCacheEntry whose RewriteDescriptor holds dst_mac=MAC_old and only THEN executes poll_descriptor/mod.rs:3718: entry.neighbor_mac_epoch = mac_change_epoch() == E+1. 4) Every subsequent packet of F hits stage_flow_cache_hit (flow_cache_hit.rs:109-110): neighbor_mac_epoch_stale(E+1) compares E+1 != E+1 -> false, and cached_flow_decision_valid (forwarding/mod.rs:675) never re-checks the neighbor MAC for a plain ForwardCandidate. 5) All packets of F are transmitted to the dead MAC_old — silent blackhole — until an UNRELATED MAC change bumps the global epoch, a config/FIB generation rotates, or LRU displacement evicts the entry. The race window (resolution -> stamp) is microseconds, but the trigger (gateway MAC change) is exactly correlated with mass flow re-resolution after a failover, so some re-established flows land inside the window.

**Why it matters** — Defeats the #3048 protection precisely in its motivating scenario (upstream VRRP MAC failover): affected flows blackhole indefinitely with no counter, no log, and no self-heal path other than coincidental global epoch churn — on a production firewall this is silent traffic loss on established sessions.

**Fix direction** — Capture the epoch with optimistic-read discipline: read mac_change_epoch() BEFORE resolving the neighbor (at the top of the slow-path resolution, or inside FlowCacheEntry::from_forward_decision before the decision is consulted) and stamp the entry with that pre-resolution value. Then a change landing after the capture makes stamp != current on the first hit -> evict -> re-resolve MAC_new. Add a test that interleaves insert_if_changed between resolution and insert and asserts the first hit is treated as stale.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for 'mac_change', 'stale mac', 'neighbor epoch', '3048', '3169'. #3048 (CLOSED) ADDED this epoch mechanism; #3169 (CLOSED) covered a missed bump at the RX source-MAC learn site. Neither covers the stamp-after-resolve ordering race that lets a bump land between MAC capture and epoch stamp; HEAD reflects both fixes and still has this residual — a genuinely new mechanism (optimistic-read version captured on the wrong side of the data read).

---

#### F-090 · Destructive HA smoke tests (test-failover/ha-crash/double-failover/stress/chained/restart/active-active) reboot the SHARED loss userspace cluster without taking the #1875 cluster lock

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `x-tests-build`  ·  **Location:** `test/incus/test-failover.sh`:200
- **Labels:** `test-infra`, `bug`, `ha`

```
# ── Phase 3: Crash fw0 (sysrq reboot) ───────────────────────────────
#
# sysrq-b is the repo's proven unclean primitive (same as
# test-double-failover.sh): the guest resets instantly, with no unit
# stops, no priority-0 VRRP burst, and no shutdown-job queueing.
...
info "Crashing fw0 (sysrq reboot — unclean shutdown, tests worst-case failover)"
```

**Runtime trace**

Agent A holds /tmp/xpf-cluster.lock inside a with-cluster.sh cell (e.g. a multi-hour fairness capture or a mid-phase cluster-deploy). Agent B runs `make test-failover` — the Makefile default (lines 263-269) sets CLUSTER_ENV=test/incus/loss-userspace-cluster.env, and cluster-env.sh line 10-14 defaults the same way for direct invocation — so test-failover.sh targets loss:xpf-userspace-fw0/fw1. The script sources ONLY cluster-env.sh (line 31); `grep -L 'cluster_lock|with-cluster|flock'` confirms test-failover.sh, test-ha-crash.sh (line 296: `incus stop --force "$FW0"`), test-double-failover.sh, test-stress-failover.sh, test-chained-crash.sh, test-restart-connectivity.sh, and test-active-active.sh contain no lock acquisition or marker check. B proceeds immediately to sysrq-b reboot fw0 while A owns the cluster: A's capture/deploy is corrupted mid-phase (binary swap or measurement across an unexplained failover) and B's own result is invalid too — precisely the #1875 incident ('concurrent agent deploy loop owns the cluster, binary swaps mid-phase') recurring through an unguarded entry point.

**Why it matters** — The #1875 protocol exists because concurrent agents demonstrably clobbered each other's validation runs on this shared cluster. cluster-setup.sh mutating verbs, apply-cos-config.sh and wg-interop all self-lock, but the MOST destructive scripts of all — the ones that hard-crash nodes — were left outside the protocol, so the mutual-exclusion guarantee is only as strong as every agent remembering to wrap `make test-failover` in a lock cell by hand.

**Fix direction** — Add the standard self-lock preamble to each destructive test script (source cluster-lock.sh; if ! xpf_cluster_lock_held then exec with-cluster.sh "<script> <purpose>" -- "$0" "$@"; fi), mirroring apply-cos-config.sh lines 53-59; gate it on the resolved env actually being the shared cluster (INCUS_REMOTE non-empty) so the legacy local xpf-fw0/1 runs stay lock-free.

**Not a duplicate** — Searched issues-all.txt for 'lock', '1875', 'test-failover': #1875 (closed) established the protocol for deploys/apply-cos-config only; #1785 (closed) is a docs pairing issue. prior-findings.md has no entry on lock coverage of the test-*.sh scripts (only an unrelated duplicate-VIP HA smoke gap at [test/incus]). The residual differs from #1875's fix scope: the protocol was never extended to the failover/crash harnesses.

---

#### F-091 · `make test` never runs the 3393 userspace-dp Rust unit tests (no cargo test, no clippy, no CI) — the policy-eval/session-install/NAT-alloc test suite is dead weight in the default gate

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `x-tests-build`  ·  **Location:** `Makefile`:78
- **Labels:** `test-gap`, `build`, `ci`

```
test:
	# go vet gate scoped to pkg/flowexport (#2224): catches the
	# atomic.Uint64-copy regression class (ExportConfig embeds the live
	# 1-in-N sampleCounter and must never be copied by value). NOT
	# tree-wide yet — two pre-existing vet diagnostics live outside this
	# package (cmd/cli protobuf MessageState copy, pkg/cli unreachable
	# code); widen to ./... once those are resolved.
	$(GO) vet ./pkg/flowexport/...
	$(GO) test ./...
```

**Runtime trace**

Developer changes userspace-dp/src/policy.rs (or session/entry.rs, nat/source.rs — the actual packet-verdict code) and runs the documented gate `make test` -> only `go vet ./pkg/flowexport/...` + `go test ./...` execute. `grep -rn 'cargo test|cargo clippy' Makefile scripts/ debian/` = zero hits; debian/rules line 76 explicitly overrides dh_auto_test to a no-op; there is no .github/workflows/. userspace-dp contains 3393 #[test] functions (policy_tests.rs matrix, session slab/eviction, SNAT allocator, screen, MQFQ) that only run if someone remembers to hand-invoke `cargo test --manifest-path userspace-dp/Cargo.toml`. Failure mode already observed: #1855 — cargo test sat RED on master (session inplace_* debug_assert panics) until someone happened to run it; the closed fix repaired the tests but not the mechanism that let them rot. A Rust-side regression in policy evaluation or NAT allocation with a failing unit test still yields a green `make test` and lands on master.

**Why it matters** — The Rust helper IS the dataplane — policy eval, session install, and NAT allocation (three of the five most safety-critical paths) are validated exclusively by these tests. A default gate that structurally cannot go red on dataplane regressions converts every hot-path unit test into documentation, and the #1855 incident proves the rot mode is real, not hypothetical.

**Fix direction** — Add `$(CARGO) test --manifest-path userspace-dp/Cargo.toml --release` (and ideally `cargo clippy -D warnings`) to the `test` target, or add a `test-rust` target and make `test` depend on it; the debug-log feature build (build-userspace-dp-debug-log) could join the same gate. Longer term: a minimal CI workflow running make test + cargo test + the deploy-lib selftest.

**Not a duplicate** — Searched issues-all.txt for 'cargo', 'clippy', 'CI', 'make test': #1855 (closed) fixed the red tests but not the missing gate; #1205 (closed) is a CoS docs-drift check only. prior-findings.md line 355 wants a CI drift canary for the app-grammar parity table (narrow, different). No issue or prior finding proposes wiring cargo test into the default gate; the Makefile's own #1678 comment ('There is no CI in this repo') documents the condition but nothing tracks fixing it.

---

#### F-092 · bake.py signs the image manifest BEFORE the validation gate runs, and publish.py gates on signatures only — a validation-FAILED (or --skip-validate) image is fully publishable

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `x-tests-build`  ·  **Location:** `scripts/image/bake.py`:644
- **Labels:** `security`, `bug`, `supply-chain`, `build`

```
        # 7. validation gate
        if a.skip_validate:
            print("WARNING: --skip-validate — artifacts have NOT passed the in-guest "
                  "verify-dataplane gate; do not publish them.", file=sys.stderr)
        else:
            info("running validation gate (factory boot + in-guest verify-dataplane + "
                 "valid/invalid day-0 drives)...")
            if subprocess.run([sys.executable, os.path.join(HERE, "validate.py"),
                               "--qcow2", qcow_out, "--metadata", meta_out, "all"]).returncode != 0:
                die(f"validation gate FAILED — artifacts in {a.out} are NOT publishable")
```

**Runtime trace**

Operator runs `XPF_SIGN_SECKEY=... make image`. Pipeline order in main(): step 6 exports qcow2+metadata, writes xpf-<ver>.SHA256SUMS (line 569) and SIGNS it with minisign (lines 580-591) -> THEN step 7 runs validate.py (line 644). validate.py fails (e.g. in-guest verify-dataplane REJECT — the #1864 no-dataplane image) -> die() exits, but dist/ now contains qcow2 + metadata + a manifest with a VALID .minisig. Later, `make dist-publish` runs publish.py, whose fail-closed gate checks exactly: (a) manifest minisig verifies + listed files hash-match, (b) apt InRelease, (c) install.sh sig, (d) latest.json sig (docstring lines 4-16; `grep -n valid publish.py` shows no validation-status check) -> all pass -> XPF_PUBLISH_CMD uploads the boot-validation-failed image to the stable channel. The only defense is a human reading a stderr line from a previous shell session. Same hole for --skip-validate (warning only, line 639).

**Why it matters** — The entire point of the #1924 fail-closed publish gate is that no human judgment stands between a bad bake and the hosted channel. The gate keys on 'signed', but signing happens before the only functional test of the image; the property actually enforced is 'checksums match', not 'image validated' — a shipped appliance image whose dataplane never comes up is the worst-case field failure.

**Fix direction** — Reorder: run the validation gate before sign_manifest (sign last), delete/rename the .minisig on validation failure, or write a `validated: yes` line into the signed manifest / a validation stamp file that publish.py fails closed on when absent — mirroring how the mixed-base image-roll gate already fails closed on missing manifest protocol fields.

**Not a duplicate** — Searched issues-all.txt for 'bake', 'publish', 'sign', 'validate.py', '1924', '1930': #1924 is the OPEN umbrella for the signed-distribution feature itself; no issue names the sign-vs-validate ordering or a validation stamp. prior-findings.md has no bake.py/publish.py entries. Distinct from the documented fail-OPEN-at-bake/fail-CLOSED-at-publish design note (bake.py lines 573-576), which covers the UNSIGNED case, not the signed-but-unvalidated case.

---

#### F-093 · deploy_rolling secondary-detection grep can never match — default `make cluster-deploy` deploys node1 first even when node1 is the active primary

- **Severity:** 🟠 medium  ·  **Confidence:** high
- **Module:** `x-tests-build`  ·  **Location:** `test/incus/cluster-setup.sh`:758
- **Labels:** `bug`, `test-infra`, `ha`

```
deploy_rolling() {
	# Determine which node is currently secondary (deploy it first).
	local secondary=1
	local primary=0
	if incus exec "$(r "$VM0")" -- cli -c "show chassis cluster status" 2>/dev/null | grep -q "secondary:node0"; then
		secondary=0
		primary=1
	fi
```

**Runtime trace**

`make cluster-deploy` (XPF_DEPLOY_DEB unset, the default) -> cluster-setup.sh cmd_deploy -> deploy_rolling (line 754). The grep pattern "secondary:node0" is matched against `show chassis cluster status`, but pkg/cluster/status.go FormatStatus emits only space-separated table rows (`fmt.Fprintf(&b, "%-6s %-8d %-14s ...", ...)` -> `node0  100    secondary ...`); the token `secondary:node0` never appears anywhere in the output. So the branch never fires and secondary=1 unconditionally. State: node0 is currently SECONDARY (routine after any prior failover test on the shared cluster). Phase 1 then calls deploy_vm 1 — the ACTIVE PRIMARY — which runs `systemctl stop xpfd; pkill -9 xpf-userspace-dp` (lines 889-894) on the forwarding node: every RG fails over uncleanly mid-deploy, in-flight iperf3/HA-sync traffic drops, and the second phase then bounces the just-promoted node too. Observable: the 'rolling preserves traffic' contract (comment lines 750-753) is violated ~50% of the time; failures get misattributed to VRRP/session-sync regressions. The fixed detection exists ONLY in deploy_rolling_deb (lines 736-742, `Local state: Secondary` from `show chassis cluster information`), whose own comment (line 733) documents that the legacy pattern "never matched" — the fix was never back-ported to the default raw path.

**Why it matters** — The raw rolling deploy is the default deploy mechanism for the shared loss userspace HA cluster (`make cluster-deploy`). Stopping the active primary first is exactly the outage the secondary-first ordering exists to prevent, and on a shared validation cluster it silently corrupts other agents' measurements and produces false HA-regression signals — the #1 false-result hazard class the deploy scripts otherwise defend against.

**Fix direction** — Reuse the deploy_rolling_deb detection in deploy_rolling: query `cli -c "show chassis cluster information"` on node0 and grep '^[[:space:]]*Local state:[[:space:]]+Secondary' (or factor one `detect_secondary_node()` helper into deploy-lib.sh used by both paths, with a selftest in deploy-lib-selftest.sh).

**Not a duplicate** — Searched issues-all.txt for 'rolling', 'deploy', 'secondary' — #1983 (upgrade --rolling --unit, closed) and #2176/#2162 (deploy staleness, closed) are different mechanisms. prior-findings.md has no deploy_rolling/cluster-setup entry. The in-file comment (line 733) records the AGY r1 finding against the DEB path; the residual here is that the default raw path at HEAD still carries the dead grep — a genuinely unfixed sibling, not a re-report.

---

#### F-094 · Local CLI `ping`/`traceroute` do not clamp count/size, diverging from the REST and gRPC surfaces that share the diagcmd builder

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-cli`  ·  **Location:** `pkg/cli/cli_request.go`:37
- **Labels:** `bug`, `vsrx-parity`, `refactor`

```
		case "count":
			count = args[i+1]
			i++
		case "source":
			source = args[i+1]
			i++
		case "size":
			size = args[i+1]
```

**Runtime trace**

diagcmd.go documents that 'validation and clamping stay with the callers.' pkg/api/system.go:109 clamps ping count>100 to 100 and pkg/grpcapi/server_diag.go:77 clamps count>100. handlePing passes the raw string straight into diagcmd.PingArgv with no numeric parse or bound: `ping 8.8.8.8 count 999999999` produces `ping -c 999999999`, which runs until the 120s context timeout (line 54) rather than the ~100-probe ceiling the other two surfaces enforce. `size` is likewise unvalidated. A non-numeric `count abc` yields `ping -c abc` and a raw ping usage error instead of a clean CLI diagnostic.

**Why it matters** — Three control surfaces that deliberately share diagcmd for byte-identical argv now behave differently on the exact input class (probe count) the shared builder's contract says the caller must bound — the inconsistency the diagcmd package exists to prevent, and a small local resource sink.

**Fix direction** — Parse+clamp count (<=100) and size in handlePing/handleTraceroute before calling buildPingArgv/buildTracerouteArgv, matching pkg/api/system.go and pkg/grpcapi/server_diag.go; reject non-numeric values with a usage error.

**Not a duplicate** — Searched for ping/count/clamp/diagcmd. #2143 (double vrf- prefix) and #2084 (-- separator) are the diagcmd items and are fixed. No prior finding on the CLI-vs-REST/gRPC count-clamp divergence. Novel.

---

#### F-095 · Refactor debt: the #2170/#2198/#2221 generation-guard state machine (~370 lines) is embedded in the 1589-line sync_conn.go transport file

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-cluster-sync`  ·  **Location:** `pkg/cluster/sync_conn.go`:45
- **Labels:** `refactor`, `ha`

```
const genGuardMapCap = 200000

// putGenBounded records gen for key in m without ever clearing the map or
// dropping the stored generation of an existing key. An existing key is always
// updated in place; a new key is recorded only while the map is below
// genGuardMapCap. Returns true if the entry was stored. The caller holds the
// map's mutex. Generic over the two wire-key types.
```

**Runtime trace**

sync_conn.go currently interleaves four concerns: (1) the generation-guard state machine (putGenBounded, stamp/take/install/delete guards, resetRecvGen, lines 30-292) whose correctness argument (the :294-310 invariant comment) is subtle enough that finding #5 above disproves it; (2) TCP transport lifecycle (accept/dial/handleNewConnection/handleDisconnect); (3) the 27-case handleMessage wire dispatcher; (4) the delete journal + sweep producers. A change to any one concern forces re-review of the invariant prose of the others; the guard's per-key ordering properties have no isolated unit boundary (tests live in the 3.6k-line sync_test.go + 37k sync_gen_guard_test.go against the whole SessionSync).

**Why it matters** — The gen guard is the correctness core of HA session convergence; keeping it inline with transport plumbing is how the #2198 F3 invariant drifted from reality (finding 5). An isolated module with its own concurrency contract would make such drift a compile-visible seam instead of a comment.

**Fix direction** — Extract a pkg/cluster/sessionsync/ module directory: genguard.go (guard state machine with an explicit same-key-serialization contract), journal.go (delete journal), transport.go (conn lifecycle), dispatch.go (handleMessage) — leaving pkg/cluster/sync.go as the facade. Property-test the guard (install/delete/reorder sequences) in isolation.

**Not a duplicate** — Grepped 'Split', 'refactor' + cluster: #374 (CLOSED) split the original sync.go into transport/bulk-barrier/producer files — but it predates the #2170 gen guard entirely, which was added INTO sync_conn.go afterwards; no issue proposes isolating the guard as its own module with a testable concurrency contract.

---

#### F-096 · Unlocked read of s.bulkRecvEpoch in the BulkEnd mismatched-epoch warning — data race under the Go memory model

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-cluster-sync`  ·  **Location:** `pkg/cluster/sync_conn.go`:1287
- **Labels:** `bug`, `race`

```
		s.bulkMu.Lock()
		if s.bulkInProgress && s.bulkRecvEpoch != epoch {
			s.bulkMu.Unlock()
			slog.Warn("cluster sync: ignoring BulkEnd with mismatched epoch", "expected", s.bulkRecvEpoch, "got", epoch)
			break
		}
		s.bulkMu.Unlock()
```

**Runtime trace**

1) Receiver gets a stale BulkEnd (old epoch) on one fabric's receiveLoop; the guard reads bulkRecvEpoch under bulkMu, unlocks, THEN re-reads s.bulkRecvEpoch in the slog.Warn argument WITHOUT the mutex. 2) Concurrently the other fabric's receiveLoop processes a fresh syncMsgBulkStart, writing s.bulkRecvEpoch under bulkMu (:1273), or handleDisconnect zeroes it (:1573). 3) go test -race / production race detector flags a read/write race on SessionSync.bulkRecvEpoch; the logged 'expected' value can also differ from the value actually compared, misleading incident debugging.

**Why it matters** — An unsynchronized field read in an HA-critical dispatch path is UB under the Go memory model and pollutes -race CI runs the moment a test exercises dual-fabric bulk; trivial to fix and worth closing before it masks a real race.

**Fix direction** — Capture `expected := s.bulkRecvEpoch` inside the locked region and log the captured copy.

**Not a duplicate** — Grepped prior-findings.md and issues for 'bulkRecvEpoch', 'data race', 'copylocks': #120 (CLOSED) was Stats() copying atomics; conntrack GC aging race (prior finding) is a different package. No coverage of this read.

---

#### F-097 · Scheduler `transmit-rate percent <n>` / `remainder` (the most common Junos scheduler forms) are unsupported — rejected at commit despite feature-gaps claiming 'bandwidth %' Done, and the lenient path compiles percent to ~16 bit/s

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-config-ifaces-cos-fw`  ·  **Location:** `pkg/config/compiler_class_of_service.go`:511
- **Labels:** `vsrx-parity`, `test-gap`

```
func parseCoSTransmitRate(node *Node) (uint64, bool) {
	var rate uint64
	exact := false
	for _, key := range node.Keys[1:] {
		if key == "exact" {
			exact = true
			continue
		}
		if parsed := parseBandwidthLimit(key); parsed > 0 {
			rate = parsed
		}
	}
```

**Runtime trace**

PROBE AT HEAD: `schedulers { be-sched { transmit-rate percent 20; } }` → strict SchemaValidate rejects at commit ('transmit-rate: invalid value "percent": not a valid bandwidth') — fail-closed, so the operator path is safe but every real vSRX CoS config using percent/remainder fails to import. However CompileConfig itself accepts the tree and parseCoSTransmitRate iterates Keys[1:] token-wise: "percent" parses to 0 (skipped) and "20" parses via parseBandwidthLimit to 20/8 = 2 BYTES/s, i.e. a 16 bit/s queue cap. On the tolerant paths where SchemaValidate violations are downgraded to warnings (configstore/store.go:281 — persisted-config boot, peer sync), a scheduler authored as 20%-of-interface compiles to effectively zero bandwidth and starves the class. docs/feature-gaps.md:625 marks Scheduler Maps '(bandwidth %, priority, buffer)' as Done, which overstates support; buffer-size has the same issue with the two-token Junos spelling `buffer-size percent 40` (only the '40%' spelling is accepted).

**Why it matters** — Percent-based transmit rates are the dominant spelling in real Junos scheduler configs; import compatibility is a stated project goal and the docs claim the capability. The lenient-path 2-bytes/s compile is a latent starvation hazard.

**Fix direction** — Support `percent <n>` by resolving against the unit shaping-rate/interface bandwidth at compile (fields already exist for buffer-size percent), or hard-reject the token inside parseCoSTransmitRate on ALL paths so the lenient compile cannot produce 2 B/s; fix the feature-gaps.md row either way.

**Not a duplicate** — Searched issues for 'transmit-rate', 'percent': #1336 (percent BUFFER-size semantics — implemented; different leaf), #1337 (schema wiring). No issue/prior finding covers transmit-rate percent/remainder rejection or the lenient-path 2-bytes/s compile; feature-gaps.md:625 claims the capability rather than documenting the gap.

---

#### F-098 · SNAT pool bracket-list `address [ a b c ]` keeps only the first address — remaining pool addresses silently dropped (the #2419/#3431 collapse class on a leaf #3431 missed)

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-config-nat`  ·  **Location:** `pkg/config/compiler_nat.go`:1042
- **Labels:** `bug`, `test-gap`

```
				} else if len(prop.Keys) >= 2 && prop.Keys[1] != "" {
					// Inline value form ("address <prefix>;" / flat set).
					// Deliberately NOT nodeVal: its Children[0] fallback
					// would double-append the block form, whose children
					// are walked below (#1808).
					pool.Addresses = append(pool.Addresses, prop.Keys[1])
				}
```

**Runtime trace**

Input: `set security nat source pool BL address [ 198.51.100.1/32 198.51.100.2/32 198.51.100.3/32 ]`. (1) The lexer strips brackets; SetPath sees path [...pool,BL,address,a,b,c]; `address` is unknown under the pool schema (schema_security.go:313 models only persistent-nat), so ast_edit.go:151-165 emits ONE leaf Keys=[address,198.51.100.1/32,198.51.100.2/32,198.51.100.3/32]. (2) compileNATSource's address case checks the range shape (Keys[2]=="to" — fails, Keys[2] is the second address) then falls to the single-value branch at compiler_nat.go:1042 which appends ONLY Keys[1]. (3) Empirically verified: pool.Addresses=[198.51.100.1/32] — two of three pool addresses silently gone, commit green. Runtime: SNAT capacity is 1/3 of intended (port exhaustion under load; allocator Unavailable drops once the single address' range is consumed), and any traffic engineering expecting the full pool is wrong. Per the #2419 contract (CLAUDE.md, docs/config-schema.md) a multi-value leaf reader MUST consume Keys[1:] AND Children; this reader consumes Keys[1] only. Repeated single-address set lines and the hierarchical block form still work, which hides the bug.

**Why it matters** — Silent pool-capacity loss with a green commit; same fail-silent list-collapse family the project fixed wholesale in #3431 for NAT match leaves but the pool address leaf was not included.

**Fix direction** — Iterate prop.Keys[1:] with the same `to`-range detection used for the child walk (mirror the addrChild loop at 1045-1055), or route through a shared multi-value+range helper used by both shapes. Add a bracket-list pool-address compile test.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for '3431', '2419', 'bracket', 'multi-value', 'pool address', '1808': #3431 (CLOSED) fixed match application/protocol/address-name lists — explicitly rule MATCH leaves, not the pool address leaf; #1808 (CLOSED) fixed the double-append of the block form on this same leaf (its fix comment is in the quoted snippet) but did not add bracket-list handling; #3049 covered subnet expansion in the Rust helper. No prior coverage of the bracket-list drop on pool.Addresses.

---

#### F-099 · Structured renderers are malformed for real configs: FormatXML emits invalid XML element names for value-leaves (e.g. <ge-0/0/0.0/>) and nodesToJSON collapses repeated leaves last-writer-wins, so `| display xml` is unparseable and `| display json` drops list members

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-config-parse`  ·  **Location:** `pkg/config/ast_format.go`:516
- **Labels:** `bug`, `vsrx-parity`

```
	if len(n.Keys) == 1 {
		// Boolean leaf: <keyword/>
		fmt.Fprintf(b, "%s<%s%s/>\n", prefix, xmlTag(n.Keys[0]), attr)
		return
	}
...
			if len(n.Keys) == 1 {
				result[n.Keys[0]] = true
			} else if len(n.Keys) == 2 {
				result[n.Keys[0]] = n.Keys[1]
```

**Runtime trace**

XML: `set security zones security-zone trust interfaces ge-0/0/0.0` stores the unit as a single-key leaf; `show configuration | display xml` -> FormatXML -> formatXMLLeaf emits `<ge-0/0/0.0/>` (empirically confirmed, probe 5) — `/` and a digit-leading position are illegal in XML element names, so any conforming XML consumer (automation pulling config over gRPC/REST/CLI pipe) rejects the ENTIRE document; vSRX wraps values as <name>ge-0/0/0.0</name>. xmlTag (line 535) is a no-op passthrough on the claim 'Junos keywords already use valid XML chars', but Keys[0] of a value-leaf is operator DATA, not a keyword. JSON: two `set system name-server` leaves -> nodesToJSON writes result["name-server"]="8.8.8.8" then overwrites with "8.8.4.4" (empirically confirmed, probe 6: only 8.8.4.4 appears) — `| display json` silently under-reports config; a leaf and container sharing a name likewise drop the container's children (nodesToJSON:580-586 no-else branch).

**Why it matters** — The XML/JSON views exist for machine consumption (parity with Junos display filters); output that is not well-formed XML or that loses leaf-list members makes external automation and audits silently wrong on a security appliance.

**Fix direction** — In formatXMLLeaf/formatXMLNodes, emit value-bearing keys as <name>/<value> child elements (never as element names) and sanitize/validate tags; in nodesToJSON, accumulate repeated leaf first-keys into JSON arrays (Junos display json shape) and handle leaf/container name collisions.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for 'display xml', 'display json', FormatXML/FormatJSON: zero hits — no tracker issue or prior campaign has touched the structured renderers. Nearest related work is display-surface field omissions in CLI/gRPC (#3672/#3624), a different layer.

---

#### F-100 · snmp location/contact/description are compiled but absent from schemaSNMP — compiled-but-not-schema-visible drift (no completion, no trailing-token gate)

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-config-schema`  ·  **Location:** `pkg/config/schema_system.go`:824
- **Labels:** `vsrx-parity`, `refactor`, `test-gap`

```
var schemaSNMP = &schemaNode{desc: "SNMP configuration", children: map[string]*schemaNode{
	"community": {desc: "SNMP community", args: 1, placeholder: "<community-name>", children: map[string]*schemaNode{
		"authorization": {
```

**Runtime trace**

compileSNMP (compiler_system.go:868-873) has explicit cases `"location"`, `"contact"`, `"description"` reading nodeVal into SNMPConfig (surfaced via the SNMP agent's sysLocation/sysContact/sysDescr). schemaSNMP declares only community/trap-group/v3 (empirically confirmed at HEAD: CompleteSetPathWithValues(["snmp"]) returns exactly 'community trap-group v3'). Consequences: (1) `set snmp ?` / tab completion cannot offer the three leaves — the #1319 two-SSOT rule ('every compiled + validated leaf lives in the schema tree') is violated, same drift class as #3377/#3117. (2) Because the keywords are schema-unknown, SetPath packs ALL remaining tokens onto one leaf and the walker skips the subtree, so an unquoted `set snmp location Building 5` commits with '5' silently dropped (nodeVal reads Keys[1] only) — the #3332 trailing-token silent-drop the scalar gate cannot reach for undeclared leaves.

**Why it matters** — Two-SSOT drift re-accumulates the exact operator-facing gaps (#1319/#3377) this schema exists to prevent; sysLocation/sysContact are the first thing NOC tooling reads.

**Fix direction** — Declare location/contact/description under schemaSNMP as args:1 scalar:true leaves (values are quoted strings), matching the compiler cases; consider a canary test comparing schemaSNMP children with compileSNMP's switch tokens, like schema_policy_then_3377_test.go does for policy then.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'snmp', 'schema', 'completion'. #2990 [CLOSED] covered trap-group children:nil (fixed at HEAD — verified targets/version/categories declared); #3117/#3377 are the same drift CLASS on security-policy leaves (both closed, fix did not extend to snmp); #1892 covered empty help text, not missing nodes. No issue names snmp location/contact/description.

---

#### F-101 · Test gap: validateWireguardPeersStrict has zero lenient-path coverage — the warn-downgrade branch (multi-tunnel warning accumulation, first-error-per-tunnel truncation) is untested

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-config-validate`  ·  **Location:** `pkg/config/compiler_validate_wireguard.go`:56
- **Labels:** `test-gap`

```
	emit := func(label string, err error) error {
		if err == nil {
			return nil
		}
		if lenient {
			warnings = append(warnings, fmt.Sprintf("wireguard %s: %v", label, err))
			return nil
		}
		return fmt.Errorf("wireguard %s: %w", label, err)
	}
```

**Runtime trace**

wireguard_multipeer_test.go (20 tests, lines 36-552) exercises only the STRICT path: every reject case asserts a CompileConfig error; `grep -c lenient wireguard_multipeer_test.go` returns 0. The lenient branch is what Store.Load and HA SyncApply actually execute on an upgraded/peer-synced node carrying a pre-#1434/#2445 WG config (CompileConfigLenient -> lenientWireguardPeers=true -> emit appends to warnings and continues). Untested behaviors: (a) warnings actually reach cfg.Warnings via compiler.go:3582-3586 on the lenient path; (b) validateOneWireguardTunnel returns on the FIRST violation per tunnel, so a tunnel with a bad pubkey AND a dup AllowedIPs prefix yields ONE warning on load — a regression that started warning nothing (or bricking the load) here would ship silently; (c) a multi-tunnel config produces one warning per offending tunnel.

**Why it matters** — The lenient path is the HA-upgrade no-brick contract (#1960); it is exactly the path that runs unattended during rolling upgrades and has no operator watching — regressions there surface as a standby that either bricks on boot or loads silently without the flagging warning.

**Fix direction** — Add lenient-path tests mirroring the existing reject cases: CompileConfigLenient over a config with a zero-peer tunnel + a dup-prefix tunnel, asserting compile succeeds and cfg.Warnings contains one 'wireguard <label>: ...' entry per offending tunnel.

**Not a duplicate** — Grepped issues-all.txt and prior-findings.md for wireguard test coverage: #1736 (live kernel-WG interop test) and Rust-side WG tests exist; no issue/finding covers the Go commit-gate lenient branch. Verified absence directly: zero 'lenient' occurrences in wireguard_multipeer_test.go at HEAD.

---

#### F-102 · validateThreeColorPolicersStrict (and warn-pass CoS/DDNS walkers) iterate Go maps unsorted — first-reported commit error / warning order is nondeterministic across runs and HA nodes, violating the module's own determinism doctrine

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-config-validate`  ·  **Location:** `pkg/config/compiler_validate_strict.go`:69
- **Labels:** `bug`, `determinism`, `ha-risk`

```
func validateThreeColorPolicersStrict(policers map[string]*ThreeColorPolicerConfig) error {
	for name, pol := range policers {
		if pol == nil {
			continue
		}
		displayName := pol.Name
		if displayName == "" {
			displayName = name
		}
		if pol.SingleRateConfigured && pol.TwoRateConfigured {
```

**Runtime trace**

Config defines two three-color-policers, each with a distinct violation (policer A: CIR==0; policer B: both single-rate and two-rate). `commit check` -> compileExpanded strictErrs accumulator (compiler.go:2109) -> validateThreeColorPolicersStrict ranges the map directly with NO sort.Strings (contrast every neighbor: sortedScreenNames, the sorted walks in validateDynamicAddressFeedServerEndpointStrict etc., whose comments state 'sorted ... so both HA nodes report identically'). Go randomizes map iteration, so run 1 reports policer A's error and run 2 reports policer B's; on a chassis cluster node0 and node1 can report DIFFERENT first errors for the identical synced candidate. Same pattern in the warn pass: validateCoSOversubscriptionWarnings (compiler_validate_warn.go:1748 `for ifaceName, iface := range cos.Interfaces`, nested unsorted unit map) and validateSurfaceADDNSWarnings (line 1450 `for name, p := range catalog`) emit warnings in random order, so cfg.Warnings ordering — persisted into commit output and the alarms surface — churns run-to-run.

**Why it matters** — Deterministic first-error is an explicit, repeatedly-documented contract of this module (dozens of validators carry the 'deterministic across runs / both nodes report identically' comment); nondeterministic diagnostics break operator scripting, diff-based commit tooling, and HA log correlation.

**Fix direction** — Sort policer names before iterating in validateThreeColorPolicersStrict; sort cos.Interfaces / iface.Units / the DDNS provider catalog keys in the two warn-pass walkers, matching the established sortedScreenNames pattern.

**Not a duplicate** — Grepped prior-findings.md and issues-all.txt for 'determinis'/'nondeterministic': hits are pkg/cli zone-ID reverse maps, SNMP trap community (#2989, fixed), DDNS StatusViews sort — none covers these three config-validator map walks.

---

#### F-103 · db.go candidate/rollback DB API (ReadCandidate/WriteCandidate/DeleteCandidate/ReadRollback/WriteRollback/DeleteRollback) is dead code that implies an encrypted rollback store nobody uses

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-configstore`  ·  **Location:** `pkg/configstore/db.go`:110
- **Labels:** `refactor`, `vsrx-parity`

```
// WriteCandidate persists the candidate configuration to disk atomically.
func (db *DB) WriteCandidate(tree *config.ConfigTree) error {
	return db.writeTreeMarked(db.candidatePath(), tree, true)
}

// DeleteCandidate removes the candidate file from disk.
func (db *DB) DeleteCandidate() error {
	err := os.Remove(db.candidatePath())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete candidate: %w", err)
```

**Runtime trace**

grep across pkg/ and cmd/ shows zero non-test callers of ReadCandidate/WriteCandidate/DeleteCandidate/ReadRollback/WriteRollback/DeleteRollback; store_commit.go:520's own comment concedes 'the DB rollback slots have no production callers'. Consequences: (a) the candidate config is never persisted anywhere, so a daemon restart mid-edit-session silently discards staged work (Junos persists the shared candidate DB) — an undocumented behavioral gap hiding behind an API that looks like it handles it; (b) the encrypted, envelope-stamped rollback persistence path that WOULD fix the plaintext-rollback security finding already exists here, fully written and maintained (it gained the #1922 committed-marker plumbing via writeTreeMarked) but disconnected; (c) docs (feature-gaps.md:703) describe candidate/rollback encryption as done based on this dead surface.

**Why it matters** — Dead persistence API in the config-durability core is actively misleading: reviewers and docs assume candidate/rollback trees are covered by the encrypted DB when the real state machine uses plaintext text files, and the unused code still carries maintenance cost (marker/envelope changes must be threaded through it).

**Fix direction** — Decide and act: either wire the DB slots in (persist candidate on edit for restart recovery; use encrypted DB rollback slots as the canonical history, fixing the master-password leak) or delete the six methods and update README/feature-gaps to state that rollback history is plaintext text files and the candidate is memory-only.

**Not a duplicate** — Grepped issues-all.txt for 'candidate', 'rollback', 'configstore' and prior-findings.md for db.go — #2158 (file split) is code motion only; #3441/#1894 touch the text-file rollback path, not the dead DB API; no issue tracks candidate-persistence loss across restart or the dead encrypted-slot API.

---

#### F-104 · saveRollbackFiles rewrites all ~50 rollback slots (full config re-Format + write) on every commit and every HA config sync, under the store write lock

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-configstore`  ·  **Location:** `pkg/configstore/store_commit.go`:535
- **Labels:** `performance`, `refactor`

```
	entries := s.history.List() // most-recent-first
	degraded := false
	for i, entry := range entries {
		path := s.rollbackPath(i + 1)
		data := entry.Config.Format()
		var err error
		if i == 0 {
			err = rbWriteFileDurable(path, []byte(data), 0644)
		} else {
			err = rbWriteFileAtomic(path, []byte(data), 0644)
```

**Runtime trace**

1) Any commit (CommitWithDescription:106, CommitConfirmed:231) or peer sync (SyncApply, store.go:438) calls saveRollbackFiles while holding s.mu (write). 2) Once history is full (50 entries, NewHistory(50)), the loop calls entry.Config.Format() — a full tree serialization — 50 times and writes 50 files (one fsynced, 49 atomic temp+rename) per commit, even though 49 of those files' contents are byte-identical to what the PREVIOUS commit wrote one slot lower (slot k+1 == old slot k; only slot 1 is new data). For a 200 KB config that is ~10 MB of serialization + write I/O per commit, ~50 temp-file creations/renames, all while every reader (ShowActive/ActiveConfig/gRPC status, which take RLock) is stalled. 3) On the HA secondary this cost is paid on EVERY primary commit via SyncApply, on the config-sync hot path. 4) #3441 already fixed the durability semantics of this loop but kept the O(history x config-size) rewrite.

**Why it matters** — Commit latency on a production appliance grows linearly with history depth x config size and blocks the entire config read plane (status pollers, health, CLI) while doing redundant disk work; on flash-backed appliances it is also gratuitous write amplification.

**Fix direction** — Shift slots by rename (os.Rename slot N-1 -> N, oldest first) and write only slot 1, keeping the single trailing SyncDir — same contiguity invariant the loader assumes, ~50x less serialization/write work; or cache the formatted text per HistoryEntry so unchanged slots skip Format().

**Not a duplicate** — Grepped issues-all.txt/prior-findings.md for 'rollback', 'saveRollbackFiles', 'journal', 'persist' — #1896 fixed the analogous O(lifetime) scaling for the JOURNAL only; #1894/#3441 addressed the durability/fsync classification of this exact loop but not its per-commit O(N) rewrite; no issue covers the rewrite-all-slots cost.

---

#### F-105 · Test gap: zero compile-path coverage for the security `schedulers` stanza — no test parses/compiles any scheduler config shape (flat-set, hierarchical, daily container, date formats), which let the two scheduler-intake bugs land silently

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-conntrack-appid`  ·  **Location:** `pkg/config/compiler_system.go`:1071
- **Labels:** `test-gap`

```
func compileSchedulers(node *Node, cfg *Config) error {
	if cfg.Schedulers == nil {
		cfg.Schedulers = make(map[string]*SchedulerConfig)
	}

	for _, inst := range namedInstances(node.FindChildren("scheduler")) {
		sched := &SchedulerConfig{Name: inst.name}
```

**Runtime trace**

1) grep across pkg/config/*_test.go: every `schedulers {` fixture is the CLASS-OF-SERVICE stanza (inactive_test.go:361, dual_ast_differential_test.go:460, parser_class_of_service_test.go); the only cfg.Schedulers assertion (compiler_equal_flow_target_policy_test.go:97) is CoS. No test anywhere parses `schedulers { scheduler <name> ... }` or a `set schedulers ...` line into compileSchedulers. 2) pkg/scheduler/scheduler_test.go and pkg/policymatch/scheduler_test.go construct config.SchedulerConfig structs DIRECTLY, bypassing the parser/compiler entirely. 3) Consequently the dual-AST differential suite (which pins hierarchical == flat-set for other stanzas) never covers schedulers, so the flat-set one-leaf collapse (compiles to zero schedulers) and the daily-container drop (compiles to always-active) are both invisible to `make test`. 4) The runtime tests also fix `now` in time.UTC (scheduler_test.go:110), leaving the UTC/local date-frame mismatch unpinned.

**Why it matters** — The scheduler feature spans parser -> compiler -> strict validation -> runtime gating -> dataplane inactive flags; the compiler link of that chain has zero coverage, so intake regressions surface only as silent policy-semantics changes on production firewalls.

**Fix direction** — Add compiler tests: (a) hierarchical scheduler with direct start/stop-time, (b) Junos daily-container shape, (c) flat-set lines via ParseSetCommand+SetPath (per CLAUDE.md testing rule), (d) date format variants incl. the dotted Junos form — asserting cfg.Schedulers content; plus a non-UTC isWithinWindow date test.

**Not a duplicate** — Searched prior-findings for scheduler test gaps: only display-layer gaps exist ('No zone-detail tests for scheduler-inactive policy summaries', pkg/cli). No issue or prior finding notes the absent compile-path coverage for the security schedulers stanza. Complements (does not duplicate) my two scheduler-intake bug findings.

---

#### F-106 · Zone-detail policy summary omits wildcard zone-pair sets (`from-zone any` / `to-zone any`, the #3090 tier): summary can print '(no zone-pair or global policies affecting this zone)' while a wildcard rule governs the zone's traffic

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-conntrack-appid`  ·  **Location:** `pkg/policymatch/zone_detail_summary.go`:114
- **Labels:** `bug`, `vsrx-parity`, `observability`

```
	for _, zpp := range cfg.Security.Policies {
		// #3476: skip a nil zone-pair set (tolerant / HA-sync path) while
		// advancing the policy-set ID, rather than dereferencing zpp.FromZone.
		if zpp == nil {
			policySetID++
			continue
		}
		if zpp.FromZone == zone || zpp.ToZone == zone {
```

**Runtime trace**

1) Config carries `security policies from-zone any to-zone dmz policy lockdown then deny` — a single-wildcard zone-pair set the runtime evaluates in the #3090 tier for every flow into dmz (policymatch.Match tier 2, policy.rs from_any bucket). 2) Operator runs `show security zones detail dmz` (local CLI or gRPC-text): ZoneDetailPolicySummary tier 1 only admits sets where `zpp.FromZone == zone || zpp.ToZone == zone`; "any" never equals "dmz", so the wildcard set is skipped. Tier 2 walks only cfg.Security.GlobalPolicies. 3) With no exact-pair or global rules, line 154 prints '    (no zone-pair or global policies affecting this zone)' followed by the [default] row — the operator concludes only the default policy applies to dmz while the dataplane denies via `lockdown`. The GLOBAL tier already fixed this exact shape via IsWildcardZone (config.GlobalPolicyAppliesToZone, types_security.go:376-380); the zone-pair tier was not given the same treatment.

**Why it matters** — The zone-detail summary exists precisely so an operator can audit 'what governs this zone' (#3658/#3684); hiding an enforced deny/permit wildcard tier makes the audit read wrong and undermines trust in the SSOT renderer shared by CLI and gRPC.

**Fix direction** — Match the runtime eligibility: include a set when `config.IsWildcardZone(zpp.FromZone) || zpp.FromZone == zone || config.IsWildcardZone(zpp.ToZone) || zpp.ToZone == zone` (rendering the wildcard axis as 'any'), mirroring GlobalPolicyAppliesToZone; extend zone_detail_summary_test with a from-any/to-any zone-pair case.

**Not a duplicate** — Searched prior-findings/issues for zone-detail/zones detail/wildcard. Prior finding '[pkg/config/types_security.go] GlobalPolicyAppliesToZone treats explicit any as literal' covered GLOBAL match-scope wildcards (fixed at HEAD via IsWildcardZone); #3684/#3658 (CLOSED) added modifiers/default row. No issue or finding covers wildcard ZONE-PAIR sets missing from the zone-detail tier-1 walk.

---

#### F-107 · warmNeighborCache skip condition 'addr.IsPrivate() && addr.IsLoopback()' is dead code (operator precedence — the conjunction is unsatisfiable)

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-daemon-ha`  ·  **Location:** `pkg/daemon/daemon_ha.go`:1243
- **Labels:** `refactor`, `test-gap`, `ha`

```
	for ip4 := range seen {
		addr := netip.AddrFrom4(ip4)
		if !addr.IsGlobalUnicast() || addr.IsPrivate() && addr.IsLoopback() {
			continue
		}
		conn, err := net.DialTimeout("udp4", netip.AddrPortFrom(addr, 1).String(), 50*time.Millisecond)
```

**Runtime trace**

Go precedence makes this '!IsGlobalUnicast || (IsPrivate && IsLoopback)'. netip's IsPrivate (RFC1918/ULA) and IsLoopback are disjoint sets, so the second clause is always false; and loopback is already excluded by !IsGlobalUnicast. Every input therefore reduces to '!IsGlobalUnicast()' — the extra clause never changes the outcome. Whatever the author intended ('|| addr.IsLoopback()' redundancy, or '(IsPrivate || IsLoopback)' which would wrongly skip warming RFC1918 LAN peers — the majority of trust-zone session endpoints), the written expression is inert, and there is no unit test on warmNeighborCache's address filter to pin the intended set (the IPv6 loop at line 1258 has no analogous clause, another asymmetry hint).

**Why it matters** — Dead conditions in HA failover-critical code (neighbor pre-warm feeds first-packet-after-failover forwarding) invite a future 'fix' toward the wrong reading — the (IsPrivate||IsLoopback) interpretation would silently stop warming all private LAN destinations and regress failover first-packet latency.

**Fix direction** — Simplify to 'if !addr.IsGlobalUnicast() { continue }' with a comment noting private addresses are intentionally warmed (Go's IsGlobalUnicast includes RFC1918), and add a small table test over the filter.

**Not a duplicate** — Searched 'warmNeighborCache', 'IsPrivate', 'IsLoopback', 'warmup' in the corpus. Neighbor-warmup issues #75/#80/#98/#347/#491/#598 [all CLOSED] concern staleness/ordering/config-snapshot problems in other warmup paths — none touch this dead boolean in the session-walk filter.

---

#### F-108 · applyKernelTuning never restores redirects / ipv6 zero-hop-limit sysctls when the config leaves are removed (non-declarative)

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-daemon-lifecycle`  ·  **Location:** `pkg/daemon/daemon_system.go`:435
- **Labels:** `bug`, `vsrx-parity`

```
	if cfg.System.NoRedirects {
		sysctls := []string{
			"/proc/sys/net/ipv4/conf/all/send_redirects",
			"/proc/sys/net/ipv4/conf/all/accept_redirects",
			"/proc/sys/net/ipv6/conf/all/accept_redirects",
		}
```

**Runtime trace**

applyKernelTuning runs on every apply. When `system no-redirects` is set it writes 0 to send_redirects/accept_redirects; when `internet-options no-ipv6-reject-zero-hop-limit` is set it writes 0 to icmp/ratelimit. On a later commit that REMOVES either leaf, the `if cfg.System.NoRedirects` / `if ... NoIPv6RejectZeroHopLimit` guards are simply skipped — the previously-written sysctl value (0) is left in place for the daemon lifetime. There is no else-branch restoring the kernel/Junos default, unlike the host_tunables capture/restore machinery used for the #801 knobs.

**Why it matters** — vSRX semantics are declarative: deleting `no-redirects` should re-enable ICMP redirects. Here it does not, so operator intent silently diverges from kernel state until a reboot. Low security impact (the residual state is more restrictive), but it is a correctness/parity gap and a footgun when an operator toggles the leaf to diagnose redirect behavior and sees no change.

**Fix direction** — Make both blocks declarative: on the false branch write the default back (send_redirects/accept_redirects=1, icmp ratelimit to the captured/default value), or capture+restore like host_tunables. Document if the residual-restrictive state is intentional.

**Not a duplicate** — grep for applyKernelTuning|no-redirects|send_redirects|zero-hop in issues/prior-findings returned only unrelated icmp_ratelimit Rust findings. Not previously reported.

---

#### F-109 · #805 residual: workers→1 (and userspace-dp-removal) transitions never restore the concentrated RSS table — stale [1,1,0,...] layout defeats the code's own 'single worker keeps default RSS spreading' intent until reboot

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-daemon-net`  ·  **Location:** `pkg/daemon/rss_indirection.go`:164
- **Labels:** `bug`, `performance`

```
	if workers == 1 {
		slog.Info("linksetup: rss indirection skipped (single worker — keep default RSS)")
		return
	}
...
		// Guard requires queues > 1: with a single-queue NIC there is
		// no possible concentration to undo ...
		if workers > 1 && workers >= queues && queues > 1 {
			maybeRestoreDefault(iface, queues, execer)
		}
```

**Runtime trace**

(1) mlx5 NIC with 6 RX queues, `system dataplane workers 4` → applyRSSIndirectionOne writes weights [1,1,1,1,0,0]; hardware hash now lands only on queues 0-3. (2) Operator commits `workers 1`. reapplyRSSIndirection(true, 1, allowed) → applyRSSIndirection hits the `workers == 1` early return (line 164) BEFORE any per-interface probe, and the #805 restore is additionally gated `workers > 1 && workers >= queues` (line 261) — so `ethtool -X default` is never issued. (3) The helper's queue planner (userspace-dp/src/server/helpers.rs replan_bindings_from_candidates: queue_count = min(rx_queues), worker_id = queue_id % workers) binds XSKs on ALL 6 queues served by the single worker — the design rationale for the skip is that a lone worker should drain all queues/IRQ lines. But the stale concentrated table keeps 100% of traffic on queues 0-3 (4 of 6 IRQ lines, and after a 2→1 transition, 2 of 6), permanently forfeiting the IRQ/queue spreading the comment says workers==1 must keep. Same for a commit that removes the userspace-dp stanza (workers→0, line 160 early return): the concentrated table is inherited by pure-kernel networking. (4) No later commit fixes it unless workers is raised to >=6 or the operator toggles `rss-indirection disable` (which actively restores) — an undocumented escape hatch.

**Why it matters** — The transition matrix is asymmetric: N→M (1<M<Q) rewrites, N→>=Q restores (#805), but N→1 and N→0 silently leak the previous epoch's constrained table across reboots of the workload — an invisible perf skew on the production mlx5 NICs that contradicts the explicitly documented single-worker rationale in the same file.

**Fix direction** — In applyRSSIndirection, route the workers==1 (and workers<=0 with a non-empty allowlist) cases through maybeRestoreDefault per allowlisted mlx5 interface instead of returning early — i.e. make 'keep default RSS' an enforced state, not an assumed one.

**Not a duplicate** — Named residual of CLOSED #805 ('D3 RSS indirection doesn't refresh when workers count changes to equal queue count'): HEAD's fix (maybeRestoreDefault) is explicitly gated `workers > 1 && workers >= queues`, excluding the →1/→0 arms; the →1 arm returns at line 164 before any probe, a code path #805's fix never reaches. Distinct from CLOSED #3091 (planned-vs-bound divergence) and CLOSED #898 (rebalance scoping). No prior-findings.md entry for rss_indirection.go.

---

#### F-110 · Refactor: interface identity/rename discipline is scattered across 4 files with 3 PCI-address extractors, 2 independent rename implementations and 3 predictable-name resolvers — extract a pkg/ifident module

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-daemon-net`  ·  **Location:** `pkg/daemon/daemon_reth.go`:96
- **Labels:** `refactor`, `modularity`

```
// pciAddrFromPath extracts a PCI address (domain:bus:slot.fn) from a sysfs
// path basename. Returns "" if the basename is not a PCI address.
func pciAddrFromPath(path string) string {
	base := filepath.Base(path)
	// PCI addresses look like "0000:08:00.0"
	parts := strings.SplitN(base, ":", 3)
	if len(parts) != 3 {
		return ""
	}
```

**Runtime trace**

Inventory at HEAD: PCI extraction — linksetup.go:extractPCIAddr (index-based, walks all components), devicemap.ExtractPCIAddr (verbatim duplicate, comment admits it 'mirrors the daemon's extractPCIAddr'), daemon_reth.go:pciAddrFromPath (basename-based, different acceptance rules). Rename — linksetup.go:renameInterface (hardened per #2083: down→rename→up, retry, documented recovery contract, injectable netlink seams) vs daemon_reth.go:renameRethMember (hand-rolled down→rename, no up — see finding 1). Kernel-name resolution — device_map.go:udevPredictableName (udevadm properties), daemon_reth.go:deriveKernelName (sysfs synthesis, see finding 7), plus ensureRethLinkOriginalName's AltNames scan. .link writing — linksetup.go:writeLinkFile vs daemon_reth.go:fixRethLinkFile (same format, second implementation, no change-detection). The drift is not hypothetical: findings 1 and 7 in this report are both instances of a hardened primitive existing in one file while a sibling file kept its unhardened twin.

**Why it matters** — Every hardening applied to one copy (#2083 rename recovery, Codex-r3 udevadm resolution, AGY-r2 extractPCIAddr bounds fix — applied to two of the three extractors) must be re-discovered for the others; module notes for this review explicitly flag 'interface rename collision windows' and 'device-map invariants' as recurring risk. pkg/devicemap already proved the pattern works: it was extracted precisely so daemon and CLI 'share ONE resolution discipline'.

**Fix direction** — Create pkg/ifident (or grow pkg/devicemap) owning: PCIAddrFromSysfsPath (one extractor with the hardened bounds), RenameInterface (the #2083-hardened primitive, consumed by both linksetup and the RETH recovery path), KernelNameFor (udevadm-first ladder with sysfs fallback), and WriteLinkFile. Mechanical migration; the injectable seams (nlLink* vars, deriveKernelNameFn, predictableNameLookup) move with it.

**Not a duplicate** — Searched 'refactor', 'consolidate', 'device_map', 'multiqueue' in issues: CLOSED #2004 proposed consolidating device_map + rss_indirection into pkg/daemon/multiqueue/ (multiqueue/RSS scope — different axis, and the files remain siblings at HEAD so it was closed without that shape); #1544 split pkg/routing. Neither covers the identity/rename/PCI-extraction duplication across linksetup/device_map/daemon_reth/devicemap; prior-findings.md's only daemon modularity entries are host-inbound-model centralization (finding 241/377), unrelated.

---

#### F-111 · criticalityNextHop is assigned nowhere in production — the Copilot-mandated next-hop/NAT probe prioritization is dead code and its unit test pins semantics production can never produce

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-daemon-net`  ·  **Location:** `pkg/daemon/daemon_neighbor_listener.go`:320
- **Labels:** `bug`, `test-gap`, `dead-code`

```
// criticality levels for force-probe target prioritization.
// Higher value = probed earlier within a stale-tier bucket.
// Per Copilot review: a single boolean conflated address-book
// hosts with real next-hops, so under cap pressure a large
// address-book could crowd out gateways and fabric peers.
const (
	criticalityNormal    = 0 // snapshot-only entries (already-resolved peers)
	criticalityNextHop   = 1 // configured next-hops, NAT destinations
	criticalityFabric    = 2 // cluster fabric peers (highest)
)
```

**Runtime trace**

(1) collectMonitoredNeighbors builds the force-probe target list from exactly two sources: snapshot keys via addTarget(ip, ifindex, criticalityNormal) (line 475) and fabric peers via addTarget(..., criticalityFabric) (lines 502, 507). The '(Source 2 removed per Copilot review.)' block (line 480) deleted the only would-be assignments of criticalityNextHop. (2) probeTier's tier-2 branch (`state&NUD_REACHABLE != 0 && criticality > criticalityNormal`, line 346) is therefore reachable only for fabric peers; a REACHABLE default gateway present in the snapshot is criticalityNormal → tier 3. (3) With a snapshot larger than the 256-target cap (large address-book /32 churn or many learned peers), forceProbeNeighbors truncates targets[:cap] after tier sort — REACHABLE gateways/next-hops sit in tier 3 and are truncated with everything else, exactly the crowd-out the constant was introduced to prevent. (4) daemon_neighbor_listener_test.go:31 asserts '{"REACHABLE+next-hop is tier 2", ..., criticalityNextHop, 2}' — a green test for a classification no production code path can produce.

**Why it matters** — Dead prioritization plus a test that documents it as live is worse than absence: a future reader trusts the tiering comment and the passing test, while under cap pressure gateway re-validation actually has no priority over bulk snapshot entries. Small blast radius (re-validation of already-REACHABLE entries), but it is a silent divergence between documented/tested and actual behavior in HA-critical plumbing.

**Fix direction** — Either annotate configured next-hop/NAT targets when they appear among snapshot keys (intersect collectNeighborProbeTargets' set with the snapshot enumeration and pass criticalityNextHop), or delete the constant + tier-2-for-next-hop test and update the probeTier doc to fabric-only.

**Not a duplicate** — Searched 'criticalityNextHop', 'force-probe', 'probe cap', '#1197' in both corpora: #1197 (closed) introduced the listener/force-probe design and its plan.md documents the cap; no issue or prior finding covers the orphaned criticality level or the unreachable-tier test. prior-findings.md has no daemon_neighbor_listener.go entries.

---

#### F-112 · daemon_flow.go is a misnamed grab-bag of eight unrelated services with dead code and zero direct tests

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-daemon-svc`  ·  **Location:** `pkg/daemon/daemon_flow.go`:1
- **Labels:** `refactor`, `test-gap`

```
// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"log/slog"
	"net"
	"os/exec"
	"time"
```

**Runtime trace**

The file named 'flow' contains: FRR DHCP-route collection (22), mgmt-VRF netlink routes (47), shutdown counter logging (107), NetFlow/IPFIX shutdown stops (146/162), ip:port string parsers consumed by flowexport callbacks (178-236), remote config archival via scp (240), flow-trace writer lifecycle (270-312), and the SNMP netlink link monitor (316). None share state or domain; four of them (archiveConfig, monitorLinkState, applyMgmtVRFRoutes, updateFlowTrace) have no direct unit tests (no daemon_flow_test.go exists), which is exactly where findings 1, 2, 5 and 7 of this review live — the untested grab-bag is where the bugs pooled. daemon_dhcp.go additionally carries resolveConfigSubnetLinuxName (daemon_dhcp.go:228), whose only callers are a test file (resolve_neighbor_test.go) — dead production code kept alive by its own test.

**Why it matters** — The daemon package's per-feature sibling-file pattern hides ownerless utility code; every recent boot-only-lifecycle bug class (#2075/#2348/#2372/SNMP here) originated in exactly these unowned corners.

**Fix direction** — Split into real modules with seams and tests: pkg/daemon/archival/ (archiveConfig + future transfer-interval loop), move monitorLinkState next to the snmp agent wiring (or a pkg/daemon/snmptrap/ with the resubscribe loop), move parseHost/parseSrcPort/parseProtocol into pkg/flowexport (their only consumer) with table tests, and fold applyMgmtVRFRoutes/collectDHCPRoutes into the routing reconcile module. Delete or relocate resolveConfigSubnetLinuxName.

**Not a duplicate** — Searched prior-findings.md for 'daemon_flow' (only daemon_flowexport entries exist) and issues for daemon-package refactors (#1988 is pkg/flowexport decomposition; #1916 fsatomic canary extraction). No prior finding targets daemon_flow.go's cohesion or its untested helpers.

---

#### F-113 · probePinManager.clear() unconditionally returns nil (all RuleList/RouteListFiltered/Del failures swallowed) — Apply's degraded-clear warning is dead code and a transient dump failure silently converts every pinned RPM test into a held ErrProbeSetup state

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-frr-routing`  ·  **Location:** `pkg/routing/probe_pin.go`:245
- **Labels:** `bug`, `error-hygiene`, `routing`

```
func (p *probePinManager) clear() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := p.ops.RuleList(family)
		if err != nil {
			continue
		}
...
	}
	return nil
}
```

**Runtime trace**

Apply (probe_pin.go:162-165) does `if err := p.clear(); err != nil { slog.Warn(...) }` but clear() can only return nil: RuleList failure -> continue (line 248-249), RouteListFiltered failure -> continue (line 263-264), RuleDel/RouteDel failures -> slog.Debug only. Scenario: config commit re-applies an UNCHANGED pin set while netlink RuleList transiently fails (ENOBUFS under churn). clear() removes nothing, logs nothing above Debug, returns nil. Apply then RuleAdds each pin's fwmark rule — vishvananda RuleAdd uses NLM_F_CREATE|NLM_F_EXCL, so the still-present identical rule returns EEXIST -> fail(pin, ...) for EVERY pin -> the failed-pin map flows into pkg/rpm and all pinned tests hold ErrProbeSetup (per the #1895 contract) even though the kernel state is exactly correct. ip-monitoring loses fresh PASS/FAIL input for all pinned uplink tests until the next apply, i.e. failover detection is suspended by a transient dump error that was supposed to be surfaced. This contradicts the module's own #2273 discipline (rules.go nextTable/ribGroup/pbr clear() all errors.Join and return dump failures).

**Why it matters** — The probe-pin band exists to guarantee probes measure the pinned uplink; the module's other three ip-rule reconcilers were explicitly hardened (#2273/#3430 H3) to surface exactly this failure class. Here the same class is silently absorbed AND flips healthy pins into held probes, degrading multi-WAN failover responsiveness.

**Fix direction** — Mirror rules.go: aggregate RuleList/RouteListFiltered/RuleDel/RouteDel errors with errors.Join and return them; in Apply, treat an EEXIST RuleAdd after a failed clear as idempotent success (or verify the existing rule's mark/table identity) instead of failing the pin.

**Not a duplicate** — Searched 'probe pin', 'ProbePin', '#1895', '#2273' in both corpora: #1895 (CLOSED) added the failed-pin map contract this code implements; #2273 (CLOSED) fixed the identical swallow pattern in rules.go clear() but probe_pin.go was never brought under that contract (no prior finding names probe_pin.go at all). Distinct mechanism from #1895 (which was about Apply-side log-and-continue, not the dead clear() error path and EEXIST-holds-all interaction).

---

#### F-114 · Connection-level `start_action = start` is not a valid swanctl connection key — dead line in every establish-tunnels-immediately config

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-ipsec-wg`  ·  **Location:** `pkg/ipsec/policy.go`:166
- **Labels:** `bug`, `refactor`

```
		// Start immediately?
		if vpn.EstablishTunnels == "immediately" {
			b.WriteString("    start_action = start\n")
		}
```

**Runtime trace**

`set security ipsec vpn v establish-tunnels immediately` -> renderConfig writes `start_action = start` directly inside the connections.<conn> section (line 167) AND inside each child (line 193). In swanctl.conf's schema start_action exists only under connections.<conn>.children.<child>; charon's vici config parser ignores the unknown connection-level key (behavior is saved solely by the duplicate child-level emit). The stray key survives in /etc/swanctl/conf.d/xpf.conf where it misleads operators debugging with swanctl --load-all verbose output, and it would silently change meaning if a future strongSwan ever defines a connection-level key of that name.

**Why it matters** — Generated-config hygiene on a security appliance: every rendered line should be a real knob; dead keys erode trust in the generated file and mask real render bugs during diff review.

**Fix direction** — Delete the connection-level WriteString; keep the per-child start_action (and consider trap/start distinction for on-traffic vs immediately while there).

**Not a duplicate** — Grepped issues/prior findings for start_action/establish-tunnels: only #2270 (proposal-less connection) and DPD issues touch this render block; the invalid connection-scope key has never been reported.

---

#### F-115 · Refactor debt: policy.go (884 lines) fuses swanctl rendering with a ~300-line local-address/DNS-family selection engine — post-#1989 regrowth from #2757/#2885

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-ipsec-wg`  ·  **Location:** `pkg/ipsec/policy.go`:582
- **Labels:** `refactor`

```
func resolveInterfaceAddress(cfg *config.Config, ifaceRef string, family int) string {
	if addr := resolveInterfaceAddressFamily(cfg, ifaceRef, family); addr != "" {
		return addr
	}
	if family != 0 {
		// The remote family has no matching local-address on this
		// interface — fall back to whatever the interface offers rather
		// than rendering an empty local_addrs.
		return resolveInterfaceAddressFamily(cfg, ifaceRef, 0)
	}
```

**Runtime trace**

policy.go today contains three unrelated concerns: (1) swanctl config text rendering + escaping (renderConfig/sanitize/escape, lines 25-450); (2) local-address selection: interface/unit parsing, kernel netlink address enumeration, IPv6 global-vs-link-local scoring, zone qualification (lines 570-884, grown by #2757 and #2885); (3) live DNS resolution on the commit path (defaultResolveHostFamily, lines 613-666, with its own timeout policy and test-injection package var). The #1989 decomposition (manager/ike/crypto/policy) predates this growth; any change to address selection now churns the same file whose diff reviewers scan for secret-rendering regressions, and the package-level `resolveHostFamily` var is mutable global test state.

**Why it matters** — Module boundaries are the review-safety mechanism this project leans on (secret handling in this file is security-sensitive); keeping a DNS resolver and netlink address enumeration in the render file raises the blast radius of every localaddr change and hides commit-path I/O next to pure string building.

**Fix direction** — Split into pkg/ipsec/localaddr.go (or a pkg/ipsec/localaddr sub-package): resolveInterfaceAddress*, selectFamilyAddress, matchFamily, zoneQualify, gatewayRemoteFamilyHint, resolveHostFamily + its tests (matchfamily_linklocal_test.go, dhcp_rebind_test.go already test only this surface); leave policy.go as pure render.

**Not a duplicate** — #1989 [CLOSED] 'decompose pkg/ipsec into manager/ike/crypto/policy (isolate secret decryption)' is the nearest prior item — it was completed before the #2757/#2885 address-selection code landed IN policy.go; this finding targets that newer regrowth (localaddr/DNS vs render), a split #1989 never proposed. No other refactor issue for pkg/ipsec found.

---

#### F-116 · Kernel self-recovery auto-rejoin log line has a %s verb with no argument — prints %!s(MISSING) at the exact audit-critical moment

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-ops`  ·  **Location:** `pkg/upgrade/kernel_selfrecover.go`:242
- **Labels:** `bug`, `logging`

```
	// Condition held for Grace -> the orchestrator is gone and left us drained.
	s.cfg.Logf("kernel self-recovery: drained+orphaned for %s with a healthy peer; " +
		"auto-ResetFailover (rejoin as eligible)")
	if err := s.cl.ResetFailover(); err != nil {
		return false, fmt.Errorf("kernel self-recovery: ResetFailover: %w", err)
	}
```

**Runtime trace**

Orchestrator crashes mid-kernel-roll; the node's lease expires; Tick() observes leaseExpiredOurs + drained + healthy-primary peer continuously for Grace (default 90s); the auto-ResetFailover fires and logs via s.cfg.Logf with a format string containing %s but NO argument (the intended s.cfg.Grace was never passed — note the string concatenation with `+` instead of a trailing arg). The journald line reads 'kernel self-recovery: drained+orphaned for %!s(MISSING) with a healthy peer; auto-ResetFailover...'. This is the ONE log line explaining why a drained HA node spontaneously rejoined election — precisely what an operator greps for when auditing an unexpected failback. go vet's printf checker does not cover a custom Logf func, so nothing catches it; the sibling log at line 233-234 passes s.cfg.Grace correctly.

**Why it matters** — An unexplained automatic ResetFailover on a production HA firewall is an incident-review event; garbling its sole audit log line (and omitting the grace duration) costs real diagnosis time.

**Fix direction** — Pass the argument: s.cfg.Logf("kernel self-recovery: drained+orphaned for %s with a healthy peer; auto-ResetFailover (rejoin as eligible)", s.cfg.Grace). Consider annotating the Logf field for vet (or a printf-wrapper) so future sites are checked.

**Not a duplicate** — Searched issues-all.txt for kernel self-recovery/selfrecover/lease — only #1930 (CLOSED umbrella that added this file). prior-findings.md has no kernel_selfrecover entries. Missing-format-arg defect never reported anywhere.

---

#### F-117 · pkg/upgrade flat package cohabits two unrelated state machines (binary cut + kernel A/B channel) with copy-pasted infrastructure (FreeBytes duplicated verbatim)

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-ops`  ·  **Location:** `pkg/upgrade/kernel_linux.go`:130
- **Labels:** `refactor`, `modularity`

```
func (s *realKernelSystem) FreeBytes(path string) (uint64, error) {
	var st unix.Statfs_t
	// Stat the nearest existing ancestor so a not-yet-created versions dir
	// still yields the backing filesystem's free space.
	p := path
	for {
		if _, err := os.Stat(p); err == nil {
			break
		}
```

**Runtime trace**

pkg/upgrade is ~5300 non-test lines across 15 top-level files mixing three concerns: (1) the binary cut machine (runner.go/cutover.go/flip.go/state.go/rolling.go), (2) the #1930 kernel A/B channel (kernel.go, kernel_run.go, kernel_linux.go, kernel_drain.go, kernel_selfrecover.go — ~1900 lines with its own State enum, Journal, System interface, and journal path), and (3) shared cluster text parsing (cluster_cli.go). The two state machines share almost nothing yet live in one namespace with near-collision naming (State vs KernelState, Journal vs KernelJournal, System vs KernelSystem, realSystem vs realKernelSystem, order()/atLeast() defined twice). Concrete duplication already exists: realKernelSystem.FreeBytes (kernel_linux.go:130-148) is a verbatim copy of realSystem.FreeBytes (system_linux.go:70-89) including the comment; runCmd/captureCmd are shared package-privates that couple the files. The repo has already established the subdirectory pattern for this package (lock/, manifest/, runtime/, stagedgen/).

**Why it matters** — Per the campaign's modularity lens (prefer real module directories over sibling feature_foo.go files): every kernel-channel change currently recompiles/reviews against the cut machine's package-private surface, the doubled State/Journal/System vocabulary invites cross-machine misuse (both journals are JSON files under /var/lib/xpf with different schemas), and the FreeBytes duplication has already begun to drift risk (one copy getting a fix the other misses).

**Fix direction** — Move the kernel channel into pkg/upgrade/kernel/ (KernelRunner, KernelSystem, journal, drain/selfrecover) mirroring the existing lock/manifest/runtime/stagedgen split; hoist FreeBytes + runCmd/captureCmd into a small shared internal (e.g. pkg/upgrade/internal/hostexec or pkg/fsatomic sibling); keep cluster_cli.go's RollingCluster where both consumers can import it.

**Not a duplicate** — Searched issues-all.txt for upgrade refactor/package split — nothing; #1982 (CLOSED) centralized only the managed-binary manifest, explicitly leaving the rest flat. prior-findings.md has no pkg/upgrade structure finding. Module notes say 'nearly zero prior coverage' — confirmed.

---

#### F-118 · ensureProcessLocked readiness loop early-exit on helper start-crash is dead code (cmd.ProcessState is always nil because Wait() is never called), so a helper that dies at startup spins the full 5s instead of failing fast

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-usdp-core`  ·  **Location:** `pkg/dataplane/userspace/process.go`:127
- **Labels:** `bug`, `performance`

```
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	m.stopLocked()
	return fmt.Errorf("userspace dataplane helper did not become ready at %s", cfg.ControlSocket)
```

**Runtime trace**

ensureProcessLocked calls cmd.Start() (process.go:87) and then enters the 5s readiness loop (deadline at line 115). exec.Cmd.ProcessState is populated ONLY by cmd.Wait(), and Wait() is invoked exclusively inside stopLocked's goroutine (process.go:598) which has not run yet. Therefore throughout the readiness loop cmd.ProcessState == nil, so the `cmd.ProcessState != nil && cmd.ProcessState.Exited()` guard can never be true. If the helper exits immediately (bad args, control-socket bind failure, panic on start), the loop does not break early — it Stat()s the socket and pings every 100ms for the full 5 seconds before finally calling stopLocked and returning the 'did not become ready' error.

**Why it matters** — On a firewall, a helper that crash-loops on startup (bad binary, permission, resource) should surface fast so the daemon logs and the operator/systemd reacts; the intended fast-fail is silently inert, adding a fixed 5s stall to every start-crash and masking the true cause behind a generic timeout message.

**Fix direction** — Either reap the child to populate ProcessState (a non-blocking Wait via a goroutine that signals a channel, checked in the loop) or drop the dead branch and rely on a connect-refused signal. At minimum, detect early exit with a SIGCHLD/Wait-backed done channel so the loop breaks immediately on helper death.

**Not a duplicate** — Searched issues-all.txt for 'readiness', 'ProcessState', 'startup/spawn/crash on start' and prior-findings.md — no hit. #1648 (first-SYN drop during bringup) and #582/#525 (HA readiness) are unrelated mechanisms. This dead-branch/5s-spin on start-crash is not previously reported.

---

#### F-119 · userspaceSupportsSourceNAT is dead code — defined but never referenced

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-usdp-core`  ·  **Location:** `pkg/dataplane/userspace/capabilities.go`:484
- **Labels:** `refactor`, `test-gap`

```
func userspaceSupportsSourceNAT(ruleSets []*config.NATRuleSet) bool {
	for _, rs := range ruleSets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			if rule.Then.Interface || rule.Then.Off {
				continue
			}
			return false
```

**Runtime trace**

grep across the whole repo (including *_test.go) finds userspaceSupportsSourceNAT only at its definition (capabilities.go:484). Pool-mode source NAT is now fully supported in the userspace dataplane (see the CLASS (ii) comment at capabilities.go:73-77), so the old 'source NAT unsupported' gate this predicate implemented was removed from deriveUserspaceCapabilities but the function was left behind.

**Why it matters** — Dead capability-gating code in the fail-closed capability module is a correctness trap: a future edit could wire it back in and wrongly disarm forwarding for interface/off SNAT rules, and it obscures which gates are actually load-bearing.

**Fix direction** — Delete userspaceSupportsSourceNAT (and any now-unused config accessors it needed), or, if it is meant to be a gate, wire it into deriveUserspaceCapabilities with a test.

**Not a duplicate** — grep repo-wide (incl tests) confirms zero callers. prior-findings.md capabilities.go entries (line 355 grammar-parity canary; line 613 signed-port-spec split) are different concerns. Not previously reported.

---

#### F-120 · requestSessionSync dials a brand-new Unix connection and allocates fresh JSON codec state for EVERY session mirror operation — 2 connects per session install on the HA bulk-sync hot path

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-usdp-ha-events`  ·  **Location:** `pkg/dataplane/userspace/process.go`:292
- **Labels:** `performance`, `refactor`

```
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return err
	}
```

**Runtime trace**

1) Every SetSessionV4/V6 mirrors a forward upsert AND a pre-installed reverse companion (manager_ha.go:818/:833); every DeleteSession mirrors up to two deletes. Each of these calls syncSessionRequestLocked → requestSessionSync. 2) requestSessionSync performs, per message: sessionMu acquire, unix connect (DialTimeout), SetDeadline, json.NewEncoder alloc+encode, bufio.NewReader+json.NewDecoder alloc+decode, conn.Close. 3) During HA bulk sync (peer reconnect replays the full session table, e.g. 100k sessions) that is ~200k connect/accept/close cycles and ~400k transient codec allocations, serialized on sessionMu — each connect also costs a helper-side accept + per-connection read-loop setup. The dedicated socket already exists precisely because this path is hot (comment at process.go:282-284), but the transport is the most expensive possible shape for it.

**Why it matters** — Session-install throughput bounds failover recovery time (sync-hold release waits on bulk sync). Per-message dial latency (~tens of µs each, plus helper accept scheduling) and GC churn directly stretch the bulk-sync window and the control-plane CPU during exactly the failover-critical period.

**Fix direction** — Hold one persistent connection to userspace-dp-sessions.sock (reconnect on error) with a long-lived json.Encoder/Decoder pair under sessionMu; optionally batch N session-sync requests per write. This also gives the pair-atomicity fix (finding on manager_ha.go:1148) a natural place to enforce ordering.

**Not a duplicate** — Searched dial/session socket/install rate in both corpora: #452 (helper single-threaded loop blocking installs — led to the dedicated session socket) and #2744 (control request cap) are the nearest; neither covers the Go side dialing per-request on the dedicated socket. No prior finding mentions requestSessionSync transport cost.

---

#### F-121 · appPortsFromSpec eagerly expands port ranges into per-port []int (up to 64512 elements) that coalescePortRanges immediately re-merges — allocation amplification on every snapshot build

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-usdp-programs`  ·  **Location:** `pkg/dataplane/userspace/nat.go`:575
- **Labels:** `performance`

```
		if hi > lo {
			var ports []int
			for p := lo; p <= hi; p++ {
				ports = append(ports, int(p))
			}
			return ports
		}
		return []int{int(lo)}
```

**Runtime trace**

An application spec like `source-port 1024-65535` (the canonical Junos ephemeral-range idiom, present in predefined apps like junos-traceroute's 33434-33523) expands to a 64512-element []int (~512KB transient) in appPortsFromSpec; buildSourceNATAppTerms (nat.go:443,458) and the DNAT appTermFor (nat.go:795,804) then feed it straight into coalescePortRanges, which allocates a map[int]struct{} plus a dedup slice and collapses it back to one {Low,High} range. Every SNAT/DNAT rule referencing such an app repeats this on EVERY snapshot build — each commit, scheduler republish, and feed refresh. An application-set expanding to N members with wide ranges multiplies it N-fold. The DNAT compile path was already hardened against exactly this shape (compiler_nat.go:1636 comment: a huge range 'allocated billions of ints at COMPILE'), but the userspace builder still round-trips through the per-port expansion.

**Why it matters** — Unbounded-ish transient allocation and GC pressure in the config-apply path of a production appliance; the repo's engineering style explicitly treats build-path allocation amplification as reportable (#3449 fixed the same class on the snapshot-entry side).

**Fix direction** — Parse the spec directly to (lo,hi) and return ranges (e.g. an appPortRangesFromSpec returning []NatPortRangeWire), keeping coalescePortRanges only for genuinely enumerated port lists; while there, make the reversed-range case (hi<lo) fail closed instead of returning [lo] (already tracked as a prior finding).

**Not a duplicate** — Searched prior-findings.md nat.go entries: line 414 covers the reversed-range semantic bug in this function and #3449 covered per-port SNAPSHOT-entry amplification (fixed via coalesce at emit time). The intermediate per-port []int expansion cost between parse and coalesce is not covered by either; named both as nearest neighbors.

---

#### F-122 · buildFlowExportSnapshot picks the sampling instance via unsorted map iteration — nondeterministic collector/rate selection and snapshot bytes on multi-instance configs

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-usdp-programs`  ·  **Location:** `pkg/dataplane/userspace/flow.go`:206
- **Labels:** `bug`, `refactor`

```
	if cfg.ForwardingOptions.Sampling == nil {
		return nil
	}
	for _, inst := range cfg.ForwardingOptions.Sampling.Instances {
		if inst == nil {
			continue
		}
		rate := inst.InputRate
		if rate <= 0 {
			rate = 1
		}
```

**Runtime trace**

Sampling.Instances is a map[string]*SamplingInstance; the function returns the FIRST instance that yields a flow server (return snap at flow.go:256). With two sampling instances configured (e.g. inet and inet6 instances with different collectors/rates), successive buildSnapshot calls return a FlowExportSnapshot for a randomly chosen instance. The field rides ConfigSnapshot.FlowExport (builder.go:108) into snapshotContentHash, so a content-identical rebuild hashes differently ~50% of the time — the same dedup-gate miss mechanism as the Screens finding, plus an arbitrary (rather than documented-precedence) collector/rate choice should the reserved wire field ever be re-consumed by the helper (it is currently decoded-and-ignored per #2130).

**Why it matters** — Contributes to spurious apply_snapshot publishes on multi-instance sampling configs and leaves a nondeterministic-selection landmine in a documented-reserved wire contract that #1977 tests actively guard.

**Fix direction** — Iterate instance names in sorted order (and document/first-server-wins deterministically), matching the precedence pkg/flowexport.BuildExportConfig resolves for the live exporter.

**Not a duplicate** — Searched prior-findings.md for 'FlowExport', 'sampling', 'flow-server' — prior findings target pkg/flowexport (template ID collisions, transport stalls, compiler source-address collapse) and #2136 per-server version binding; none covers the userspace snapshot builder's map-iteration instance pick. Distinct from the screens finding by file and consumer (reserved wire field vs enforced field).

---

#### F-123 · buildInterfaceSnapshots re-resolves the parent link (2 netlink calls + AddrList + sysfs RX-queue scan) once per UNIT instead of once per physical interface

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-usdp-programs`  ·  **Location:** `pkg/dataplane/userspace/interfaces.go`:241
- **Labels:** `performance`, `refactor`

```
			unitName := fmt.Sprintf("%s.%d", name, unitNum)
			parentLinux := snapshotLinuxName(cfg, name, iface, nil)
			parentIfindex, parentMTU, parentHardwareAddr, _ := buildLinkSnapshot(parentLinux)
			parentRXQueues := userspaceRXQueueCount(parentLinux)
			linuxUnit := snapshotLinuxName(cfg, name, iface, unit)
			ifindex, mtu, hardwareAddr, addresses := buildLinkSnapshot(linuxUnit)
			rxQueues := userspaceRXQueueCount(linuxUnit)
```

**Runtime trace**

For each unit of a physical interface, the loop recomputes parentLinux (identical for all units), calls buildLinkSnapshot(parentLinux) — net.InterfaceByName + netlink.LinkByName + netlink.AddrList(FAMILY_ALL) — and userspaceRXQueueCount(parentLinux) (a /sys/class/net readdir). A trunk port with 100 VLAN units performs ~300 redundant netlink round-trips and 100 redundant sysfs scans per snapshot build. buildInterfaceSnapshots runs on every commit (builder.go:41), on every BuildZoneHostInboundViews call (zones.go:100 — invoked from the host-inbound apply path and, per an existing finding, from Prometheus scrapes), and from UserspaceBoundLinuxInterfaces which builds an ENTIRE snapshot (buildSnapshot at interfaces.go:130) just to derive a name allowlist. Under commit storms / DHCP lease churn this multiplies netlink syscall load on the control plane.

**Why it matters** — Control-plane latency on commit/lease-change reconciles grows superlinearly with trunk size; netlink AddrList under load is also the failure mode that triggers the local-address prune finding above, so gratuitous extra calls raise that exposure.

**Fix direction** — Hoist the parent buildLinkSnapshot/userspaceRXQueueCount out of the unit loop (compute once per physical interface, reuse across units); longer term give UserspaceBoundLinuxInterfaces a netlink-free derivation path instead of a full snapshot build.

**Not a duplicate** — Searched prior-findings.md for 'buildInterfaceSnapshots', 'buildLinkSnapshot', 'netlink round'. The nearest prior finding is Prometheus recomputing netlink-backed host-inbound views per scrape (pkg/api/metrics_counters.go — a caller-side caching issue); this is the intra-builder per-unit redundancy, a different mechanism and file.

---

#### F-124 · normalizeAnyInCIDRs is a dead no-op: computes hasAny4/hasAny6 and discards them, while the call site claims it normalizes 'any'

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-usdp-programs`  ·  **Location:** `pkg/dataplane/userspace/policies.go`:1074
- **Labels:** `refactor`

```
func normalizeAnyInCIDRs(v4, v6 []string) ([]string, []string) {
	hasAny4 := false
	hasAny6 := false
	cleanV4 := v4[:0]
	for _, s := range v4 {
		if s == "0.0.0.0/0" {
			hasAny4 = true
		}
		cleanV4 = append(cleanV4, s)
	}
...
	_ = hasAny4
	_ = hasAny6
	return cleanV4, cleanV6
```

**Runtime trace**

buildAddressBookTableWithFeeds calls it at policies.go:696 under the comment 'Normalise "any" -> 0.0.0.0/0 + ::/0 (Codex r6 refinement)', but the actual any->0.0.0.0/0+::/0 mapping happens earlier in expandBookNameToCIDRs (policies.go:824-827). The function copies each slice element back onto itself (v4[:0] aliasing) and explicitly discards the two flags it computes — a pure identity transform executed for every address-book name on every snapshot build. Any future reader (or the documented intent of collapsing an any-containing bucket) is misled into thinking normalization occurs here; the content-hash canonicalization it sits in front of is load-bearing for cross-HA-peer address-book ID equality, so silent vestigial code in this pipeline is risk, not just noise.

**Why it matters** — Dead code with a misleading comment inside the HA-determinism-critical address-book canonicalization pipeline invites incorrect future edits (e.g. someone 'finishing' the normalization would shift content hashes and split book IDs across mixed-version HA peers).

**Fix direction** — Delete the function and the misleading call-site comment (behavior-preserving), or implement and document the intended normalization behind a wire-versioned change; add a comment noting any->prefix mapping lives in expandBookNameToCIDRs.

**Not a duplicate** — Searched prior-findings.md for 'normalizeAny', 'dead code', 'canonicalizeAddressBook', 'sortV4CIDRs' and issues-all.txt for address-book canonicalization items (#2514, #2229, #3261 lineage) — all cover ID collision, empty-value widening, and sentinel semantics, none flags this vestigial no-op.

---

#### F-125 · Data race: Manager.Status() reads vi.cfg.Priority/Preempt without vi.mu while ResignRG/UpdateRGPriority mutate cfg.Priority under vi.mu (both hold only m.mu.RLock, which does not exclude them)

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `go-vrrp-ra`  ·  **Location:** `pkg/vrrp/manager.go`:743
- **Labels:** `bug`, `data-race`, `concurrency`

```
		sb.WriteString(fmt.Sprintf("  %s: state=%s, priority=%d, preempt=%t, interval=%dms\n",
			vi.key(), state, vi.cfg.Priority, vi.cfg.Preempt, vi.cfg.AdvertiseInterval))
```

**Runtime trace**

Status() takes only m.mu.RLock (line 717) then reads vi.cfg.Priority directly at 743. ResignRG (line 517 m.mu.RLock; line 527 writes vi.cfg.Priority=0 under vi.mu.Lock) and UpdateRGPriority (line 539 m.mu.RLock; line 546 writes vi.cfg.Priority under vi.mu.Lock) both hold only m.mu.RLock, so they run CONCURRENTLY with Status() (shared lock does not exclude shared lock). Status()'s read of the plain int cfg.Priority is not under vi.mu → an unsynchronized read racing a locked write during a cluster failover concurrent with a `show vrrp` / Prometheus status poll. (Preempt is only mutated by suppress/restorePreempt/updateConfig, all of which run under m.mu.Lock and thus cannot race Status(); Priority is the exposed field via the RLock-only mutators.)

**Why it matters** — A genuine Go-memory-model data race: `go test -race` flags it, and on a 32-bit read boundary a torn value could print a nonsense priority in operator-facing status exactly during a failover — the moment operators most trust the display.

**Fix direction** — Snapshot priority/preempt via the existing locked accessors (getPriority()/getPreempt()) inside Status() instead of touching vi.cfg directly, or read them under vi.mu.RLock. Trivial and matches how getState() is already used two lines above.

**Not a duplicate** — Prior VRRP races #2258 (localIP/localIPv6) and #2225 (lastDropWarn) were fixed with atomics; this is a different field (cfg.Priority) on a different path (Status vs ResignRG/UpdateRGPriority). No prior finding references Status()/cfg.Priority. Novel.

---

#### F-126 · Refactor debt: enqueue_pending_forwards remains a ~1,125-line single-function orchestrator; the #1443 'Phase 8 body extraction' follow-up never happened and the F1 double-free hid in its 5-level nesting

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-cos-tx`  ·  **Location:** `userspace-dp/src/afxdp/tx/dispatch/mod.rs`:96
- **Labels:** `refactor`

```
// The orchestrator (`enqueue_pending_forwards`) and Phase 8
// (try_inplace_rewrite_or_build) intentionally stay in `mod.rs` for
// this PR — Phase 8 body extraction is deferred to a follow-up so
// reviewers can compare the in-tree control flow against current
// master without a body-shape diff. See plan.md §"Out of scope".
...
pub(in crate::afxdp) fn enqueue_pending_forwards(
```

**Runtime trace**

dispatch/mod.rs:96-1221: one function carries CoS resolve, prebuilt fast path, mirror clone, TCP segmentation (two builders), PMTUD/PTB generation, in-place rewrite, direct-TX build with three fallback reasons, Vec-copy fallback, PTB finalizer, and the build-failure finalizer — with per-request mutable flags (build_failed, fallback_to_slow_path, copied_source_frame, retained_source_frame, mtu_signalled) whose interactions across ~1,000 lines are the direct cause of the duplicated free at line 915 (finding 1) and were the cause of the #2208 leaks before it. The module header explicitly records the extraction as deferred ('Phase 8 body extraction is deferred to a follow-up', lines 20-24) — no tracker issue exists for that follow-up and it has not landed in the ~1,200 recent commits.

**Why it matters** — This is the highest-blast-radius hot loop in the dataplane (every forwarded packet), and its error/rollback flag lattice has now produced two descriptor-lifetime bug classes (#2208, finding 1). Extracting the direct-TX/copy build into a module with a single RAII-style frame-offset owner would make double-free/leak states unrepresentable.

**Fix direction** — Create tx/dispatch/build_forward/ with the in-place, direct-TX, and copy builders behind a small enum result type that owns the popped tx_offset (returned-to-pool on Drop), leaving enqueue_pending_forwards as a <200-line phase sequencer; file the deferred #1443 Phase-8 follow-up as a tracked issue.

**Not a duplicate** — Nearest: #1443 (CLOSED — performed the cos/shared_recycle/slow_path code-motion split but explicitly deferred the orchestrator/Phase-8 extraction, per the in-file header) and #1016 (CLOSED — decoupled mutation from TX dispatch pre-split). Grepped issues-all.txt for dispatch/enqueue_pending_forwards: no OPEN issue tracks the deferred extraction; this reports the unfiled residual with the new evidence that finding-1's bug hid in it.

---

#### F-127 · CachedThreeColorPolicers hard-caps at 2 runtimes — third+ matched policer silently never meters on the flow-cache hit path (under-policing vs live path)

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-filter`  ·  **Location:** `userspace-dp/src/filter/mod.rs`:455
- **Labels:** `bug`, `performance`, `vsrx-parity`

```
    pub(crate) fn push(&mut self, runtime: Arc<ThreeColorPolicerRuntime>) {
        if self
            .first
            .as_ref()
            .is_some_and(|existing| existing.id == runtime.id)
            ...
        if self.first.is_none() {
            self.first = Some(runtime);
        } else if self.second.is_none() {
            self.second = Some(runtime);
        }
    }
```

**Runtime trace**

Config: egress output filter with two fall-through terms each carrying a distinct three-color policer (`then { three-color-policer ...; next term }`) plus an ingress input filter with a third policer — or a single filter whose fall-through chain matches 3 policer terms (#2544 semantics). Flow-cache install: flow_cache.rs:454 resolve_cached_cos_tx_selection -> cache_sensitive.rs:98 merge_matched_cached_modifiers extends acc.three_color_policers per matched term, and cos_classify.rs:214 extends the ingress policers into the same container. The third push finds first+second occupied and RETURNS SILENTLY (mod.rs:467-471 has no third slot and no spill). Every subsequent packet is a flow-cache hit: flow_cache_hit.rs:158 apply_cached_three_color_policers meters only the two cached runtimes — the third policer's committed/peak buckets never debit, its drop/rewrite treatment never applies, and its green/yellow/red counters stay frozen for the (majority) cached packets, while the rare uncached packets meter all three via tx_selection.rs merge_matched_tx_modifiers. Rate limit silently not enforced = fail-open under-policing.

**Why it matters** — A production rate limit that enforces on slow-path packets but not on the cached hot path is worse than absent — it passes light functional testing (first packets meter) and then fails open exactly under sustained load, when policing matters. The sibling counter container was fixed to an unbounded SmallVec for exactly this shape (#2573); the policer container was left at 2 fixed slots with silent drop.

**Fix direction** — Mirror #2573: back CachedThreeColorPolicers with SmallVec<[Arc<ThreeColorPolicerRuntime>; 2]> (inline 2, heap spill built once at install, off the hot path), or fail the flow-cache install (decline caching) when a third policer is pushed so those flows stay on the fully-metered slow path. Add a 3-policer fall-through replay test.

**Not a duplicate** — grepped 'CachedThreeColorPolicers', 'three.color' in prior-findings.md and issues-all.txt. Prior three-color items are compiler fail-closed shape (prior-finding line 315), status reason codes (line 316), sharding/HA hardening (known-gaps.md line 15), and #2573 which fixed the COUNTER container's identical cap but explicitly left the policer container at first/second. No coverage of the 2-slot silent drop.

---

#### F-128 · Per-evaluation heap allocation in FilterResult::default() (Arc::<str>::from("")) plus per-matched-term String clones on the per-packet DSCP/L4-sensitive re-eval and lo0 host-bound paths

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-filter`  ·  **Location:** `userspace-dp/src/filter/mod.rs`:877
- **Labels:** `performance`

```
impl Default for FilterResult {
    fn default() -> Self {
        Self {
            action: FilterAction::Accept,
            dscp_rewrite: None,
            policer_name: String::new(),
            routing_instance: String::new(),
            forwarding_class: Arc::<str>::from(""),
            log: false,
            log_match: None,
        }
    }
}
```

**Runtime trace**

Every verdict-evaluator invocation builds `let mut acc = FilterResult::default();` (eval.rs:114/201/323/417), and Arc::<str>::from("") is a fresh heap allocation (ArcInner header) each call. Call frequency: once per session-miss packet, once per packet for EVERY packet of a flow whose input filter carries dscp/tcp-flags/icmp/is-fragment/flex terms (poll_descriptor/mod.rs:842 session-hit re-eval -> filter.rs:229 -> eval.rs), and once per host-bound packet through the lo0 filter (filter.rs:478). On a match, merge_matched_modifiers (eval.rs:171) additionally does `acc.policer_name = term.policer_name.clone()` and `acc.routing_instance = term.routing_instance.clone()` — String heap clones per matched term per packet. At multi-Mpps with a DSCP-classifier input filter this is one malloc+free (plus clones) per packet on the hot session-hit path, plus allocator cache-line traffic shared across workers.

**Why it matters** — docs/engineering-style.md hot-path allocation rules prohibit per-packet allocations on the dataplane; the sibling TX-selection result (TxSelectionFilterResult) was already designed allocation-free (Option<&str>/None default). The verdict path predates that discipline and regressed to per-packet mallocs once #2362/#1430 made re-evaluation per-packet instead of per-flow.

**Fix direction** — Use a process-static empty Arc<str> (std::sync::LazyLock<Arc<str>>) cloned into the default (refcount bump, no alloc), or change FilterResult.forwarding_class to Option<Arc<str>> defaulting to None. Replace policer_name/routing_instance String clones with Arc<str>/&str borrows from the term (terms outlive the eval).

**Not a duplicate** — grepped 'alloc', 'FilterResult', 'Arc<str>' in prior-findings.md/issues-all.txt. Nearest: prior finding 'parse_term allocates separate Vecs on snapshot refresh' (compile-time churn, different site) and #919 (SessionMetadata Arc<str> refcounting, session module). No prior coverage of per-packet allocation in the filter verdict evaluator.

---

#### F-129 · filter_term_semantics_match omits all six flex_* fields — the cache-invalidation equality SSOT silently reports flex-only term changes as identical

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-filter`  ·  **Location:** `userspace-dp/src/filter/engine/cache_sensitive.rs`:151
- **Labels:** `bug`, `refactor`, `test-gap`

```
fn filter_term_semantics_match(old: &FilterTerm, new: &FilterTerm) -> bool {
    old.name == new.name
        ...
        && old.icmp_code_match_enabled == new.icmp_code_match_enabled
        && old.action == new.action
        && old.continue_term == new.continue_term
        ...
        && old.forwarding_class == new.forwarding_class
        && old.dscp_rewrite == new.dscp_rewrite
}
```

**Runtime trace**

Every match dimension added since #2400 was accompanied by a comparison here (source_except #2506, port_except #2622, continue_term #2544, tcp_flags_forbidden #3076, icmp bitmaps #2545) because the mod.rs #1431 runbook says per-packet fields must be wired into 'the change-detection / re-eval / rotation-purge machinery in cache_sensitive.rs'. #3077/#3232 added flex_enabled/flex_offset/flex_length/flex_value/flex_mask/flex_match_start to FilterTerm and wired the flow-cache decline + per-packet re-eval, but NOT this comparison. Config rotation changing ONLY flex parameters (e.g. flex_value 0x11 -> 0x22 on a discard term): worker/loop_body/mod.rs:388 input_per_packet_l4_filter_families_changed -> dscp_sensitive_filter_semantics_match -> filter_term_semantics_match returns TRUE -> no purge. TODAY this is masked: both old and new filters set has_per_packet_l4_match_terms, so the flow-cache never held entries for them and the per-packet session-hit re-eval picks up the new value immediately — no observable misbehavior. But the predicate is the declared structural-equality SSOT and now silently lies about six fields; any future consumer (e.g. a cached-decision reuse keyed on 'filter unchanged', or a flow-cache policy change) inherits a stale-verdict bug.

**Why it matters** — The module's own documented invariant (mod.rs #1431 block and the per-field '#XXXX: ... must be compared here' comment pattern) is broken for the newest match dimension. Latent traps in cache-coherency predicates are exactly the bug class (#1430 DSCP) this file exists to prevent, and nothing (test or compile-time exhaustiveness) catches the omission.

**Fix direction** — Add the six flex_* comparisons to filter_term_semantics_match. Harden against recurrence by destructuring `FilterTerm { .. }` into named locals inside the function (compiler errors on any future added field) or add a test compiling two single-term filters differing only in flex_value and asserting non-equality (mirroring cache_sensitive_2400_tests).

**Not a duplicate** — grepped 'semantics_match', 'cache-sensitive', 'flex' in prior-findings.md (no hits for the predicate) and issues-all.txt (#3077/#3232/#3203/#3406 all CLOSED — none cover the change-detection comparison; verified at HEAD the fields are absent from the function). The cache_sensitive_2400_tests in the same file cover only the constrained-flag flips.

---

#### F-130 · Mirror 1-in-N sampling semantics diverge: same-worker binding path consumes a sample on queue-full/frame-reserve failure while the live/cross-worker and flow-cache-hit paths reserve admission before sampling

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-forwarding`  ·  **Location:** `userspace-dp/src/afxdp/mirror/fast_path.rs`:70
- **Labels:** `bug`, `test-gap`

```
    if let Some(target_binding_index) = target_binding_index {
        if !mirror_sample_allows(config.rate, &mut ingress_binding.mirror_sample_counter) {
            return None;
        }
        let Some(target_binding) = binding_by_index_mut(
            left,
            ingress_index,
            ingress_binding,
            right,
            target_binding_index,
        ) else {
            return Some(MirrorCloneResult::NoBinding);
        };
        return Some(enqueue_mirror_clone_to_binding(
```

**Runtime trace**

Config: `rate N>1` port-mirror whose output ifindex resolves to a binding on the SAME worker set. Packet path: tx/dispatch/mod.rs:253 (and retry_pending_neigh) -> enqueue_sampled_mirror_clone -> the target_binding_index arm advances mirror_sample_counter (line 71) BEFORE enqueue_mirror_clone_to_binding, which can then fail with QueueFullSameWorker (pending >= MIRROR_PENDING_LIMIT), TxFrameReserve, or NoFrame — the admitted sample is lost and the next mirror candidate is N packets later. The cross-worker arm of the SAME function (lines 92-103) and enqueue_sampled_mirror_clone_to_live (lines 247-261) deliberately call admit_mirror_clone_to_live FIRST and only consume the sample after admission succeeds — pinned by test `sampled_live_mirror_queue_full_does_not_advance_sampler` ('full live target must fail before consuming a mirror sample') and by the flow_cache_hit path (poll_descriptor/flow_cache_hit.rs:290-341, which commits mirror_sample_counter only after the rewrite succeeds). Observable: under transient TX back-pressure a same-worker mirror target under-samples relative to a cross-worker target with identical config; the analyzer sees systematically fewer than 1-in-N of the offered packets on same-worker topologies and the discrepancy is invisible (drop counters increment but the sampler stride still advanced).

**Why it matters** — The 'do not consume a sample on a failed enqueue' invariant was explicitly designed and test-pinned for the live path, so the same-worker divergence is an unintended inconsistency in analyzer fidelity — the kind of sampling skew that corrupts capacity/forensics measurements taken via port-mirroring on a security appliance.

**Fix direction** — Mirror the admission-first ordering on the binding arm: check MIRROR_PENDING_LIMIT / free_tx_frames reserve (the two capacity gates of enqueue_mirror_clone_to_binding) before calling mirror_sample_allows, or restructure enqueue_mirror_clone_to_binding into admit+commit like the live path. Add the missing counterpart test `sampled_same_worker_mirror_queue_full_does_not_advance_sampler`.

**Not a duplicate** — Searched 'mirror', 'sample', 'sampler', 'port-mirror' in issues-all.txt/prior-findings.md. #1986 (mirror.rs de-monolith), #1545 (cross-worker clone alloc), #3617 (reject replies never mirror-cloned), #47 (eBPF-era modulo sampling cost), prior findings 40/57 (reject mirror metadata). None cover the sample-consumption ordering divergence between the same-worker binding arm and the live admission arm of enqueue_sampled_mirror_clone.

---

#### F-131 · Issue #2405 is CLOSED but its fix commit (8b80763aa, ICMPv4 dest-unreach code 14 mapping + fail-on-revert test) was never merged — and the unmerged fix contradicts RFC 7915 §4.2, so tracker, branch, and master disagree

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-nat`  ·  **Location:** `userspace-dp/src/nat64.rs`:1217
- **Labels:** `process`, `test-gap`, `rfc-conformance`

```
                5 => (ICMPV6_DEST_UNREACHABLE, 0), // source route failed -> no route
                6 => (ICMPV6_DEST_UNREACHABLE, 0), // dest network unknown -> no route
                7 => (ICMPV6_DEST_UNREACHABLE, 0), // dest host unknown -> no route
                8 => (ICMPV6_DEST_UNREACHABLE, 0), // src host isolated -> no route
                11 => (ICMPV6_DEST_UNREACHABLE, 0), // net unreachable for TOS -> no route
                12 => (ICMPV6_DEST_UNREACHABLE, 0), // host unreachable for TOS -> no route
                9 | 10 | 13 | 15 => (ICMPV6_DEST_UNREACHABLE, 1), // admin prohibited
                _ => return None,
```

**Runtime trace**

Verified with git at HEAD ddd...ddf9f58: `git merge-base --is-ancestor 8b80763aa HEAD` -> NOT an ancestor; the commit lives only on dangling branch origin/fix/2405-nat64-icmpv4-code14 ('Closes #2405', adds nat64_v4_to_v6_dest_unreachable_host_precedence_violation_maps). issues-all.txt lists #2405 as CLOSED. HEAD's map_icmpv4_error_to_icmpv6 (nat64.rs:1198-1238) has no code-14 arm — a v4 dest-unreachable code 14 (host precedence violation) falls to `_ => return None` and is dropped. Twist: RFC 7915 §4.2 actually specifies 'Code 14: Silently drop', so master's behavior is RFC-conformant and the unmerged fix (mapping 14 -> ICMPv6 Parameter Problem) would have INTRODUCED a non-conformance; the issue was closed on an incorrect RFC reading. Net state: the tracker says fixed-as-mapped, master drops, and a stale fix branch waits to regress conformance if ever merged.

**Why it matters** — Tracker/master divergence on a security dataplane erodes the dedup and audit chain every review campaign relies on: the closed issue claims behavior master does not have, and the dangling branch is a loaded footgun (merging it would violate RFC 7915). The fail-on-revert test the closure references also does not exist on master.

**Fix direction** — Reconcile the tracker: reopen-and-close #2405 as won't-fix/invalid with the RFC 7915 §4.2 'Code 14: silently drop' citation (or annotate the closure), delete or retitle origin/fix/2405-nat64-icmpv4-code14 so it is never merged, and optionally add a comment + test on master pinning code 14 -> drop as deliberate RFC behavior.

**Not a duplicate** — Searched issues-all.txt for '2405' (listed CLOSED) and recent-commits.txt (fix commit absent from the last ~1200 master commits). This is not a re-report of #2405's defect: per the dedup protocol a closed issue whose fix HEAD does not reflect is reportable; additionally the residual shape is new — the closure itself was based on a misreading of RFC 7915 §4.2 (verified against the fetched RFC text), so the correct action is tracker reconciliation, not merging the fix.

---

#### F-132 · Persistent-NAT lease keeps its creation-time inactivity timeout forever: lease reuse updates expires_at_ns with the new configured timeout but never refreshes lease.timeout_ns, so release_flow re-arms with the stale value

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-nat`  ·  **Location:** `userspace-dp/src/nat/allocator.rs`:366
- **Labels:** `bug`, `test-gap`

```
                        if lease.active_flows == 0 {
                            remove_expiry = Some(lease.expires_at_ns);
                            lease.activation_saw_completion = false;
                            lease.activation_previous_expires_at_ns = lease.expires_at_ns;
                            lease.activation_had_previous_lease = true;
                        }
                        lease.active_flows = lease.active_flows.saturating_add(1);
                        let expires_at_ns =
                            now_ns.saturating_add(persistent_nat_timeout_ns.max(NS_PER_SEC));
                        lease.expires_at_ns = expires_at_ns;
```

**Runtime trace**

(1) Rule with `persistent-nat inactivity-timeout 300` creates lease L with timeout_ns=300s (allocator.rs:449-462). (2) Operator commits inactivity-timeout 7200; parse_source_nat_rules_with_previous reuses the SAME PortAllocator because SourceNatPoolAllocatorKey (source.rs:271-291) keys only on pool name/addresses/port range — persistent-NAT parameters are excluded — so L survives with timeout_ns=300s. (3) A new flow reuses L via the allocate_translation reuse path (allocator.rs:355-368): expires_at_ns is set from the NEW 7200s argument, but lease.timeout_ns is never reassigned. (4) The flow ends -> release_flow (allocator.rs:634-637) computes expires_at_ns = now + lease.timeout_ns = now + 300s. The binding is reclaimed 300s after last use despite the configured 2h timeout (breaking the endpoint-independent mapping a peer expects); in the opposite direction (7200 -> 300) leases keep hoarding pool ports for 2h after the operator shrank the timeout.

**Why it matters** — Persistent NAT exists precisely so the translated binding survives an operator-configurable idle window (STUN/keepalive-dependent applications). A config commit that visibly succeeds but does not take effect for existing leases is a silent divergence between committed config and runtime behavior, and in the shrink direction it delays pool-port reclamation under exhaustion pressure.

**Fix direction** — In the reuse/reactivation path (allocator.rs:364-367) also set lease.timeout_ns = persistent_nat_timeout_ns.max(NS_PER_SEC); optionally walk leases on rule refresh when only the timeout changed. Add a test: create lease at 300s, re-parse rules at 7200s reusing the allocator, reuse + release the lease, assert the expiration entry is now+7200s.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'lease', 'timeout_ns', 'inactivity', 'persistent'. Nearest: #1448/#1449 (leases not preserved across restart / not HA-synced — accepted contracts about lease LIFETIME across process boundaries, not stale per-lease timeout after an in-process config refresh); #3227/#3714 concern per-application session inactivity timeouts, a different subsystem. No prior finding covers allocator-reuse timeout staleness.

---

#### F-133 · Every snapshot apply/refresh parses and builds the ENTIRE policy state twice: fail-closed preflight constructs all books/tries/compiled-apps into a scratch store, discards them, then the real build re-parses identical input

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-policy`  ·  **Location:** `userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs`:71
- **Labels:** `performance`, `refactor`

```
        let preflight_counters = crate::policy::PolicyCounterStore::default();
        ...
        let preflight_zones = crate::policy::zone_name_to_id_from_snapshot(&snapshot.zones);
        if let Err(err) = crate::policy::parse_policy_state_with_counters(
            &snapshot.default_policy,
            &snapshot.policies,
            &preflight_zones,
            &snapshot.address_books,
            &preflight_counters,
        ) {
```

**Runtime trace**

Any config commit or runtime refresh: server/handlers/snapshot.rs:42-65 (apply), coordinator/snapshot_refresh.rs:64-84 (refresh), and coordinator/reconcile/mod.rs:111-130 (reconcile) each call parse_policy_state_with_counters on the FULL snapshot as a preflight — building every BookEntry PrefixSet (including >16-prefix tries, policy.rs:2143-2172), every rule's CompiledApplications, all five zone indices and the rule_id map — into a scratch PolicyCounterStore, then drop the entire result on success. build_forwarding_state (forwarding_build/mod.rs:233) immediately re-parses the identical input with the persistent counter store. For the #1606/#1609 1M-policy scale target, or a feed-scale address book (finding 2), apply latency and transient heap double; the apply runs on the control socket the CLAUDE.md contention rule flags (status poll, HA sync, session installs share it), so a slow double-build extends the window where session installs queue.

**Why it matters** — Doubling apply-time CPU/heap on a shared control path directly conflicts with the project's own 1M-policy ambition and control-socket-contention rule; the second parse buys zero additional safety since the input is byte-identical.

**Fix direction** — Make the preflight return the successfully parsed PolicyState (Ok(state)) and thread it into build_forwarding_state (a with_prebuilt_policy variant), keeping the reject-without-mutation semantics; the scratch-vs-persistent counter-store difference can be reconciled by re-handing counters from the persistent store during the install step only.

**Not a duplicate** — Searched prior-findings.md/issues for 'preflight', 'double', 'parse twice', 'apply latency', '1606'. The Codex F2 scratch-store fix (leak on rejected snapshots) and AGY r2 4.1 (preflight-before-mutation) established the preflight but no prior issue/finding flags the duplicated full build cost; prior finding 345 (per-eval book lookups) and 343/344 (eval-time scans) are eval-path, not apply-path.

---

#### F-134 · Policy delete→re-add orphans the counter Arc bound to surviving sessions: their packets are folded into an unreachable counter while hit-count shows the re-added rule frozen at zero

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-policy`  ·  **Location:** `userspace-dp/src/policy.rs`:1198
- **Labels:** `bug`, `test-gap`

```
    fn rule_hit_counter(&self, rule_id: &str) -> Arc<PolicyRuleCounter> {
        let mut counters = self.counters.lock().expect("policy counter store poisoned");
        if let Some(counter) = counters.get(rule_id) {
            return counter.clone();
        }

        // #3395: stamp the stable rule id onto the counter at creation so a
        // session that binds this Arc can later recover its admitting rule's
        // identity from the handle alone (see PolicyRuleCounter::rule_id).
        let counter = Arc::new(PolicyRuleCounter::with_rule_id(rule_id));
```

**Runtime trace**

t0: commit A installs rule R (stable id "trust->untrust/allow-web"); long-lived session S is admitted and binds counter Arc C_old into SessionMetadata::policy_counter (#3322). t1: commit B deletes R → snapshot refresh succeeds → PolicyCounterStore::reconcile_rules (policy.rs:1178-1188) retains only active ids and EVICTS "trust->untrust/allow-web" from the registry; S keeps forwarding on the established path and resolve_session_hit_counter(bound=Some(C_old)) keeps folding every packet into C_old. t2: commit C re-adds R with the same name/zones → rule_hit_counter (line 1198) misses the registry → creates a FRESH zeroed Arc C_new (policy_tests.rs:604 `hit_counters_reset_after_rule_absent_then_readded` pins the reset). From t2 onward: S's per-packet counts continue into orphan C_old, which no surface reads — counter_snapshots (line 1902) walks rules→C_new plus default only — and `clear security policies hit-count` cannot reach it either (PolicyCounterStore::clear iterates the registry). Observable: `show security policies hit-count` shows R stuck near zero while S moves gigabits admitted BY R, yet reresolve_session_policy_id(bound=C_old) still resolves S to R's current positional id (C_old.rule_id IS present in the new rule_id_to_policy_id map), so RT_FLOW SESSION_CLOSE and the live session row confidently attribute the traffic to R whose counter never saw it — an internally inconsistent audit surface.

**Why it matters** — Hit-count is an audit/forensics surface (`show security policies hit-count`, Prometheus); a delete+re-add (rollback, config churn, HA replay) makes long-lived flows invisibly uncounted while other surfaces still attribute them to the rule — misleading during incident response.

**Fix direction** — On rule_hit_counter registry miss, or at bind-resolution time, detect a bound counter whose rule_id re-exists in the current snapshot and rebind (or have reconcile_rules keep evicted counters in a tombstone map that a re-add re-adopts instead of creating a fresh Arc). Alternatively have resolve_session_hit_counter prefer the current-store Arc for a bound counter whose rule_id resolves in rule_id_to_policy_id.

**Not a duplicate** — Searched prior-findings.md/issues for '3322', '3395', '3448', 'hit counter', 'reconcile'. #3322 (closed) = stale positional idx attributing packets to the WRONG rule; #3395 = policy_id display re-resolution; #3448 = clear-epoch replay. None covers the delete→re-add orphan-Arc case where packets are attributed to NOTHING while display attribution still names the re-added rule — a distinct mechanism (registry eviction + fresh-Arc creation vs positional aliasing/epoch replay).

---

#### F-135 · parse_protocol is a second, weaker Rust protocol table shadowing ip_proto::proto_number — the policy-application path stays correct only because a frozen Go compat list compensates (latent #3393-class commit/apply drift)

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-policy`  ·  **Location:** `userspace-dp/src/policy.rs`:3540
- **Labels:** `refactor`, `bug`

```
fn parse_protocol(protocol: &str) -> Option<u8> {
    match protocol {
        "" => None,
        "tcp" => Some(PROTO_TCP),
        "udp" => Some(PROTO_UDP),
        "icmp" => Some(PROTO_ICMP),
        "icmp6" | "icmpv6" => Some(PROTO_ICMPV6),
        "gre" => Some(PROTO_GRE),
        "89" | "ospf" => Some(PROTO_OSPF),
        "4" | "ipip" => Some(PROTO_IPIP),
```

**Runtime trace**

Today: expandUserspacePolicyApplications (pkg/dataplane/userspace/capabilities.go:290-307) resolves every application protocol via appid.ProtocolNumber, then canonicalizes to the IANA NUMBER any token outside rustParsedProtocolBeforeFix's frozen set ({tcp,udp,icmp,icmpv6,gre,ospf,ipip} + bare numeric) — so "ipv6", junos-* aliases and mixed case never reach the Rust policy matcher as names. Drift scenario (the exact mechanism of #3393, which hit the FILTER path): a future Go change blesses a new name without extending the canonicalization (e.g. widening rustParsedProtocolBeforeFix, or a producer that emits appid-resolvable names verbatim like filters.go does) → parse_protocol (line 3540 — no trim, no lowercase, no junos-* aliases, no "ipv6", unlike ip_proto::proto_number which is the DOCUMENTED mirror of appid.ProtocolNumber) returns None → parse_applications sets dropped_any → parse_policy_state_with_counters rejects the WHOLE snapshot (UnrepresentableApplicationProtocol) → a commit-passing config bricks snapshot apply and the helper pins the previous state (fail-closed brick, the #1961 commit/apply-drift class). Three tables must now stay in lock-step: appid.ProtocolNumber ↔ ip_proto::proto_number ↔ policy.rs parse_protocol, with a fourth frozen compat list (rustParsedProtocolBeforeFix) papering over the gap.

**Why it matters** — #2175/#2505/#3393 were all instances of exactly this table-drift class; keeping a strictly-weaker private copy on a security-policy leaf guarantees the next protocol addition repeats the incident, and the failure mode is a whole-snapshot reject (config brick) on a clean commit.

**Fix direction** — Delegate policy.rs parse_protocol to ip_proto::proto_number (a strict superset with trim/lowercase/aliases, already kept in lock-step with appid.ProtocolNumber), keeping the empty-string → None behavior; add a parity test iterating the Go-accepted named set (mirrored via the existing named_protocol_parse_covers_full_iana_set fixture) against proto_number.

**Not a duplicate** — Searched issues/prior findings for 'parse_protocol', 'ProtocolNumber', '2175', '2505', '3393', 'protocol table'. #2175 centralized GO-side tables; #2505 pointed the Rust FILTER compiler at proto_number; #3393 added "ipv6" to proto_number for filters; prior finding 418 covers Go-side PORT parsing duplication. No prior item flags the surviving second Rust-side protocol table in the policy-application path or its dependence on the frozen rustParsedProtocolBeforeFix list.

---

#### F-136 · No test covers the ICMP (non-TCP) reject-reply BUILD on a VLAN sub-interface — only a TCP-RST VLAN test exists, masking the source-IP lookup gap

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-poll-descriptor`  ·  **Location:** `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs`:1442
- **Labels:** `test-gap`, `vlan`

```
    fn reject_reply_classifies_on_logical_vlan_ifindex_3035() {
        ...
        let (frame, mut meta, flow) = tcp_v4_syn();
        // Inbound SYN arrives on physical parent ifindex 11, tagged VID 80.
        meta.ingress_ifindex = 11;
        meta.ingress_vlan_id = 80;
```

**Runtime trace**

The only VLAN-aware reject test drives a TCP SYN → build_reject_rst_frame (self-contained reflection, no egress lookup), so it exercises classify on the logical ifindex but never the ICMP source-IP/egress path. All ICMP-reject tests (filter_reject_non_tcp_enqueues_icmp_unreachable, reject_reply_dropped_by_egress_output_filter, filter_reject_output_filter_drop_uses_filter_counter) use ingress_ifindex=5 with a matching egress[5], i.e. logical==physical, so egress.get succeeds. The VLAN case (build ifindex != egress key) is never asserted.

**Why it matters** — This coverage hole is exactly why the finding above went unnoticed: a RED-on-revert test that drove an ICMP reject for a packet on a VLAN unit (physical bind != logical egress key) would have failed to enqueue the unreachable, surfacing the physical-vs-logical build bug on the primary WAN topology.

**Fix direction** — Add a test that drives enqueue_filter_reject_reply / enqueue_policy_reject_reply with a non-TCP frame on a VLAN sub-interface (physical ingress ifindex, VLAN id set, egress entry only on the logical unit carrying the address) and asserts an ICMP unreachable IS enqueued with the unit's primary as source.

**Not a duplicate** — prior-findings.md lines 46,47,57 note missing reject event-truthfulness / TX-metadata tests, but none flags the missing VLAN ICMP-build coverage. Distinct test gap directly tied to the build-ifindex finding above.

---

#### F-137 · No integration test drives icmp-flood/LAND through the poll-stage flowless routing, so the finding-1 bypass is invisible to CI

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-screen`  ·  **Location:** `userspace-dp/src/screen/tests.rs`:1817
- **Labels:** `test-gap`

```
fn icmp_flood_triggers() {
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = 3;
    let mut state = make_state("trust", profile);
    let pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        84,
    );
    // First 3 pass
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
```

**Runtime trace**

Every icmp-flood and land test in screen/tests.rs calls state.check_packet[_with_zone_id] directly, which unconditionally runs the flood/land screens regardless of ICMP type. The poll-stage routing (parse_session_flow_from_bytes -> flowless branch -> check_fragment_screens_l3) that decides WHETHER a non-query ICMP packet reaches check_packet at all is only covered by flowless_teardrop_fragment_dropped_3064 (fragment case only). So a regression where non-query ICMP / non-fragmented ICMP-error traffic never reaches the flood counter passes CI green.

**Why it matters** — The screen module's most security-relevant contract (flood/anti-spoof screens run on the actual ingress path for all ICMP) has no end-to-end test through stage_screen_check with a non-query ICMP type, which is exactly why the finding-1 bypass was not caught.

**Fix direction** — Add a poll_stages integration test that pushes a non-fragmented ICMP type-3 (Dest-Unreachable) burst and a src==dst ICMP frame through stage_screen_check with icmp-flood + land configured, asserting the flood counter increments / the land frame is dropped.

**Not a duplicate** — prior-findings.md lists a missing sustained-threshold rate.rs test (#3607-adjacent); this is a distinct integration-path gap (flowless routing of non-query ICMP), not a RateCounter unit gap. No overlap.

---

#### F-138 · SYN-flood enforcement (~110 lines: aggregate + alarm + per-dst + per-src + cookie mint) inlined in check_packet_with_zone_id defeats the #1543 decomposition

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-screen`  ·  **Location:** `userspace-dp/src/screen/mod.rs`:641
- **Labels:** `refactor`

```
        if syn_flood_threshold > 0 && pkt.protocol == PROTO_TCP {
            let tf = pkt.tcp_flags;
            if is_initial_syn(tf) {
                let profile_gen = self.syn_cookie_profile_gen(zone);
                let syn_cookie_validated = syn_cookie
                    && self.syn_cookie_validated.take_valid(
```

**Runtime trace**

Static review: #1543 split screen into focused submodules (packet/syncookie/rate/stateless/scan/syn_rate) so the cookie crypto could be audited independently. Yet the multi-mechanism SYN-flood decision (validated-cache bypass, aggregate dual-threshold classify, cookie-mint side effect on syn_cookie_active_until_secs, log-only alarm cadence, per-destination CMS, per-source CMS gated on cookie-active) remains a single ~110-line inline block (mod.rs:641-748) inside the already-large check_packet_with_zone_id, with the ordering/precedence invariants expressed only as comments.

**Why it matters** — This is the highest-risk, most invariant-dense code in the module (order of aggregate-before-per-dst-before-per-src, the cookie-active gate, the alarm-below-attack cadence). Keeping it inline makes each future edit re-verify the whole method's borrow/return story and is where a subtle precedence regression would hide.

**Fix direction** — Extract a syn_flood submodule (or a ScreenState::check_syn_flood method) taking the pulled-up scalars + &mut self disjoint fields, returning an enum {Pass, Bypass, Challenge, Drop(reason)}; unit-test the enforcement ordering directly rather than only through the full packet path.

**Not a duplicate** — #1543 CLOSED decomposed screen and syncookie; prior-findings poll_descriptor 'oversized poll loop' is a different module. No prior finding proposes extracting the SYN-flood block from check_packet_with_zone_id. Novel refactor-debt observation.

---

#### F-139 · refresh_status (the full per-tick status aggregate) is recomputed 2-3x per mutating control request

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-server`  ·  **Location:** `userspace-dp/src/server/handlers/mod.rs`:208
- **Labels:** `performance`, `refactor`

```
        if export_wait.is_none() && !suppress_status {
            refresh_status(&mut guard);
            response.status = Some(guard.status.clone());
        }
```

**Runtime trace**

For a persisting, non-suppressed request the full status aggregate is rebuilt up to three times: (1) inside the per-verb handler — apply()/queue::set()/drain()/inject()/etc. each end with refresh_status(guard); (2) again at the dispatcher post-match (mod.rs:208); (3) again inside write_state (helpers.rs:1172) on the persist path. refresh_status (helpers.rs:16-318) is heavy: dozens of afxdp accessor calls plus many Vec allocations/clones (fabrics.clone, ha_groups, bindings, per_binding, cos_interfaces, policy/nat/filter/policer counters, neighbor latency histograms, worker_runtime). apply_snapshot therefore pays ~3x this cost on every commit; every other mutating request pays ~2x.

**Why it matters** — Wasted CPU and allocator churn on the control path, all under the global lock (compounding findings 1 and 4's lock-hold time). Not per-packet, but it inflates the critical-section duration exactly when responsiveness matters.

**Fix direction** — Compute status once per request: have the dispatcher own the single refresh_status (drop the per-handler calls), and pass the already-refreshed status into write_state instead of re-refreshing inside it.

**Not a duplicate** — No prior finding or issue references redundant refresh_status invocations (grepped refresh_status/write_state/double refresh). The handlers-split refactor (#1345) preserved the per-handler + dispatcher + write_state calls verbatim; the redundancy is un-flagged.

---

#### F-140 · No test asserts flow-cache↔session coherence on idle expiry / 5-tuple reuse — the F1 coherence hole is entirely uncovered

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-session`  ·  **Location:** `userspace-dp/src/afxdp/flow_cache_tests.rs`:402
- **Labels:** `test-gap`, `flow-cache`

```
fn expired_owner_rg_lease_causes_miss_without_epoch_bump() {
...
fn expired_owner_rg_lease_causes_miss_for_out_of_range_rg() {
```

**Runtime trace**

flow_cache_tests.rs (79 tests) exercises staleness via config_generation (186), fib_generation (213), rg_epoch (240), owner_rg_lease (402/427), neighbor MAC epoch (2608), and the u16 last_used_epoch wrap (2175). NONE construct the scenario where a backing session is reaped by SessionTable::expire_stale_entries while a FlowCacheEntry with an otherwise-valid stamp (config/fib/epoch unchanged, lease==0) survives, then a packet on the same key is looked up. There is also no session-side test that a session reap invalidates or is cross-checked against the flow cache. The only invalidate_slot production caller (worker/lifecycle.rs:235) is gated behind should_teardown_tcp_rst, which returns false (session_glue/mod.rs:759), so even that eviction path is dead in practice — and it too is untested for the expiry case.

**Why it matters** — The absence of any test pinning the cache/session lifetime relationship is why F1 can regress silently. A regression test that reaps a session and asserts the next same-key packet is NOT served the dead decision (or is re-resolved) would both prove F1 and lock the fix.

**Fix direction** — Add a coherence test: install a cacheable UDP/established-TCP session, populate the flow cache, advance now_ns past expires_after_ns with no touch so expire_stale_entries reaps it, then assert either that the flow-cache slot was invalidated or that a subsequent lookup on the same key re-resolves against the (now absent) session rather than replaying the stale descriptor.

**Not a duplicate** — No prior finding or issue flags a missing flow-cache/session-expiry coherence test; existing flow_cache_tests cover only stamp/epoch/lease/MAC/wrap staleness, not session-liveness.

---

#### F-141 · Redirect-acquire sample counter is per-BINDING shared, not per-producer as documented — the anti-lockstep seeding rationale in REDIRECT_SAMPLE_MASK/new_seeded does not hold

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-umem-frame`  ·  **Location:** `userspace-dp/src/afxdp/umem/mod.rs`:957
- **Labels:** `refactor`, `docs`

```
    /// #709: construct a binding live state with the redirect-sample
    /// counter pre-seeded from `worker_id`. Seeding is cosmetic — the
    /// sample mask fires exactly 1-in-(MASK+1) regardless of start
    /// value — but it prevents every worker from firing its first
    /// sample on its very first push...
    pub(super) fn new_seeded(worker_id: u32) -> Self {
        let mut state = Self::new();
        state.owner_profile_peer.redirect_sample_counter = AtomicU64::new(worker_id as u64);
```

**Runtime trace**

The REDIRECT_SAMPLE_MASK doc (lines 177-183) states 'Producer-local counter is seeded from worker_id so samples from different workers don't lockstep onto the same slot', and new_seeded's doc repeats the per-worker anti-lockstep claim. But redirect_sample_counter lives on BindingLiveState.owner_profile_peer — one counter per BINDING, fetch_add'ed by EVERY producer worker that redirects into that binding (enqueue_tx_owned, lines 1119-1124). It is seeded once with the OWNING worker's id, so: (a) all producers pushing into one binding share a single interleaved counter — there is no per-producer phase to de-lockstep; (b) all bindings owned by the SAME worker get the SAME seed, so those inboxes DO fire their first sample on the same push ordinal — the exact startup burst the seed claims to prevent; (c) the sampled latency histogram attributes a mixture of all producers' push latencies to one distribution, which is what #709 wanted, but the doc's mental model (per-producer sampling phase) will mislead the next person tuning REDIRECT_SAMPLE_MASK.

**Why it matters** — Telemetry-comment drift on a hot-path sampling mechanism causes wrong conclusions when the #709 owner-hotspot histograms are next used for a performance investigation, and the claimed startup-bias mitigation is partially inert.

**Fix direction** — Either fix the comments to say 'per-binding counter shared by all producers; seeded from the OWNER worker id so different bindings de-phase', or seed with a per-binding unique value (e.g. binding index or hot_path_hash_seed() fold) so same-owner bindings also de-phase. No functional hot-path change needed.

**Not a duplicate** — Searched for redirect_sample/lockstep/709/746 — #709 (owner hotspot histograms) and #746 (cacheline split) are CLOSED and introduced this code; no issue or prior finding covers the per-binding-vs-per-producer seeding drift.

---

#### F-142 · take_pending_tx_into releases the contended pending_tx_admitted counter with one AcqRel fetch_sub PER POPPED ITEM instead of one batched release per drain

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-umem-frame`  ·  **Location:** `userspace-dp/src/afxdp/umem/mod.rs`:1261
- **Labels:** `performance`

```
        while let Some(req) = unsafe { self.pending_tx.pop() } {
            self.release_pending_tx_admission();
            out.push_back(req);
        }
...
    fn release_pending_tx_admission(&self) {
        let previous = self.pending_tx_admitted.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "pending_tx_admitted underflow");
    }
```

**Runtime trace**

Owner worker drain: drain_shaped_tx -> take_pending_tx_into (umem/mod.rs:1252) pops up to PENDING_TX_INBOX_HARD_CAP=4096 redirected TxRequests; for each pop it executes release_pending_tx_admission() -> pending_tx_admitted.fetch_sub(1, AcqRel) (line 1230). pending_tx_admitted is the SAME AtomicUsize every producer worker CAS-loops on in try_acquire_pending_tx_admission (lines 1216-1221) for every redirected push. Under cross-worker redirect load the owner therefore performs N contended read-modify-writes on the producers' hottest cacheline per drain (N = drained items), each one bouncing the line between the owner core and pushing cores, instead of a single fetch_sub(N, AcqRel) after the pop loop. The MpscInbox itself already got CachePadded head/tail (#706/#715) precisely to avoid this class of bouncing; the admission counter (added with the #1408 mirror-reserve work, commit e2e14a299) sits outside that isolation and is RMW'd per item.

**Why it matters** — The redirect inbox is the documented owner-worker hotspot (#709); every avoidable contended RMW on the admission line adds latency to both the owner drain and concurrent producer pushes at multi-Gbps redirect rates.

**Fix direction** — Count pops locally in take_pending_tx_into and issue one `pending_tx_admitted.fetch_sub(count, AcqRel)` after the loop (or every K items to bound capacity-release latency). Note the tradeoff in a comment: batched release delays slot availability by the drain duration (microseconds against a 4096-item worst case), during which the inbox was full and producers were already dropping.

**Not a duplicate** — Searched for pending_tx_admitted/admission/false sharing/cacheline. #706 (mutex->lock-free MPSC), #715 (MPSC invariants), #746 (owner/peer profile cacheline isolation) are the nearest and all CLOSED; none touch the per-item admission release. Prior-findings rows 618/670 flag generic missing repr(align(64)) on session/telemetry structs — different structs, different mechanism (this is RMW frequency, not layout).

---

#### F-143 · xsk_ffi writer/reader cursors reset without advancing base_idx: insert()-after-commit() would overwrite kernel-owned submitted TX/fill slots, and ReadComplete read()-after-release() re-reads released completions — latent API hazard with zero consumer-side test coverage

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-umem-frame`  ·  **Location:** `userspace-dp/src/xsk_ffi.rs`:952
- **Labels:** `bug`, `refactor`, `test-gap`

```
    /// Commit written descriptors to the kernel.
    pub fn commit(&mut self) {
        if self.written > 0 {
            unsafe { bridge_xsk_ring_prod_submit(self.ring, self.written) };
            self.reserved -= self.written;
            self.written = 0;
        }
    }
```

**Runtime trace**

WriteTx::insert (line 934) writes slot `base_idx + written + n`. commit() (line 952) submits `written` slots to the kernel (advances *producer) then resets written=0 WITHOUT advancing base_idx. A caller holding the writer across a commit — e.g. a future partial-flush pattern `insert(a); commit(); insert(b); commit();`, exactly the shape the #2383 append-safety fix legitimized for insert-after-insert — would have the second insert write descriptor b at base_idx+0, a slot the kernel now owns and may be concurrently DMA-reading, silently corrupting an in-flight TX descriptor (wrong addr/len -> tx_invalid_descs or transmit of arbitrary UMEM bytes). The dual hazard exists on the consumer side: ReadComplete::release (line 1051-1058) resets read_count=0 and shrinks peeked without advancing base_idx, so a subsequent read() re-returns already-released completion addresses -> double frame recycle -> same UMEM frame handed to two TX paths (frame aliasing). Today every production caller does exactly one insert+commit (tx/transmit/mod.rs:193-206, tx/rings.rs:120-124, cos/queue_service/service.rs) and one read-loop+release (tx/rings.rs:35-41), so the defect is latent; the file's test module covers ONLY producer append-safety within one reservation (#2383) — no test pins commit-cursor or release-cursor semantics.

**Why it matters** — This FFI file is the single unsafe boundary in front of kernel-shared rings; a cursor-semantics footgun here turns a future innocent refactor of the TX batching loops into descriptor corruption that presents as inexplicable tx_invalid_descs/frame aliasing in production.

**Fix direction** — In commit(): also do `self.base_idx = self.base_idx.wrapping_add(self.written)` before zeroing written (and same for WriteFill); in ReadComplete::release() advance base_idx by read_count before resetting. Add unit tests pinning insert-after-commit and read-after-release behavior (the leaked test-ring backing already supports slot inspection).

**Not a duplicate** — Searched for WriteTx/WriteFill/xsk/append/reserve. #2383 (CLOSED) fixed insert-after-INSERT append safety within one reservation and added those tests; this is the distinct insert-after-COMMIT / read-after-RELEASE cursor-reset hazard, which #2383's fix and tests do not cover. #625 (descriptor bounds after hugepage rounding) is unrelated.

---

#### F-144 · No test pins first-fragment vs non-first-fragment fabric-hash consistency — the #2357 test only asserts non-first==non-first

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `rs-worker`  ·  **Location:** `userspace-dp/src/afxdp/tests.rs`:11884
- **Labels:** `test-gap`, `fabric`, `ha`

```
fn fabric_queue_hash_non_first_fragment_is_port_independent_3tuple() {
    ...
    let h_a = fabric_queue_hash(None, Some((1111, 2222)), meta_a, true);
    let h_b = fabric_queue_hash(None, Some((40000, 50000)), meta_b, true);
    assert_eq!(h_a, h_b, ...);
```

**Runtime trace**

The only fragment-stability test constructs two NON-first fragments (flow=None, non_first_fragment=true) and asserts equal hashes. There is no test that builds the FIRST fragment of a datagram (flow=Some with ports, non_first_fragment=false) and asserts its fabric_queue_hash equals that datagram's non-first fragments. Because the first-fragment path mixes ports and the non-first path omits them (finding #2), such a test would FAIL today — the missing coverage is exactly why the divergence went unnoticed.

**Why it matters** — The absent negative/consistency test lets the stated 'every fragment of one datagram selects the same fabric binding' invariant silently regress. A security appliance's HA fabric forwarding needs the fragment-stability property pinned end-to-end, first fragment included.

**Fix direction** — Add a test that builds the first fragment (offset 0, MF=1, real L4 ports) and N non-first fragments of the same datagram and asserts fabric_queue_hash maps them all to one fabric_target_index; it should drive the finding-#2 fix.

**Not a duplicate** — Verified in tests.rs around line 11884-11922: only non-first-vs-non-first and non-fragment-port-sensitivity are asserted. No first-vs-non-first consistency assertion exists anywhere (grepped fabric_queue_hash call sites in tests.rs). Complements finding #2; not covered by any prior review.

---

#### F-145 · normalizeAnyInCIDRs is a no-op: computes hasAny4/hasAny6 then discards them and returns the input slices unchanged, contradicting its comment

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `x-default-deny`  ·  **Location:** `pkg/dataplane/userspace/policies.go`:1074
- **Labels:** `refactor`, `test-gap`

```
func normalizeAnyInCIDRs(v4, v6 []string) ([]string, []string) {
	hasAny4 := false
	hasAny6 := false
	cleanV4 := v4[:0]
	for _, s := range v4 {
		if s == "0.0.0.0/0" {
			hasAny4 = true
		}
		cleanV4 = append(cleanV4, s)
	}
```

**Runtime trace**

buildAddressBookTableWithFeeds calls `v4, v6 = normalizeAnyInCIDRs(v4, v6)` (policies.go:696) with the comment 'Normalise any -> 0.0.0.0/0 + ::/0'. Inside, cleanV4 := v4[:0] then appends every element back, so cleanV4 is byte-identical to v4; hasAny4/hasAny6 are set then explicitly discarded (`_ = hasAny4; _ = hasAny6`). The function performs no normalization, no dedup, no filtering — it returns its inputs. The actual any->CIDR conversion already happens upstream in expandBookNameToCIDRs (value=='any' -> append 0.0.0.0/0 and ::/0), so by the time this runs there is no 'any' token to normalize.

**Why it matters** — Misleading dead code in the address-book content-ID pipeline: a future maintainer reading the call site trusts that 'any' normalization/dedup happens here, when it is a pure pass-through. Any change relying on this function's documented behavior would silently do nothing.

**Fix direction** — Delete normalizeAnyInCIDRs and its call site (the conversion is done in expandBookNameToCIDRs; dedup is done by dedupSortedStrings), or implement the documented normalization if a distinct behavior is actually intended.

**Not a duplicate** — No prior finding or issue references normalizeAnyInCIDRs. Searched policies.go address-book pipeline in prior-findings; entries there concern #3261/#2514 representability and collision, not this dead helper.

---

#### F-146 · Dead duplicate ICMP rate limiter (IcmpTeRateLimiter) left in forwarding/mod.rs after #2472/#2955 shipped the real GCRA limiter

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `x-hpc`  ·  **Location:** `userspace-dp/src/afxdp/forwarding/mod.rs`:1002
- **Labels:** `refactor`, `dead-code`

```
/// Rate limiter for ICMP Time Exceeded messages.
#[allow(dead_code)]
struct IcmpTeRateLimiter {
    max_per_sec: u32,
    count: u32,
    window_start_ns: u64,
}
```

**Runtime trace**

forwarding/mod.rs:1000-1031 defines a windowed ICMP Time-Exceeded rate limiter that has no callers (both the struct and its impl are #[allow(dead_code)]). The production limiter for the same purpose is icmp_ratelimit.rs (GeneratedErrorReason::TimeExceeded, the #2472 GCRA bucket hardened by #2955). Keeping a second, non-atomic, subtly different implementation (its window compare `now/1e9 != window_start/1e9` resets on wall-second boundaries rather than a sliding window) in the hot-path forwarding module invites accidental resurrection with the pre-#2955 race semantics and pads an already 2249-line mod.rs.

**Why it matters** — Two implementations of one formula is the drift pattern docs/engineering-style.md rule 3 ('One source of truth for every formula') exists to prevent; dead allow(dead_code) blocks in the forwarding hot-path module are pure review noise and a resurrection hazard.

**Fix direction** — Delete IcmpTeRateLimiter and its impl; if a per-reason configurable limiter knob is planned, extend icmp_ratelimit.rs (which already takes rate/burst parameters) instead.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'IcmpTeRateLimiter', 'time exceeded rate', '2472', 'rate limit'. #2472 (CLOSED) added the real limiter and #2955 (CLOSED) fixed its atomicity; neither mentions removing this stale predecessor, and no refactor issue (e.g. #602 large-file splits) lists it. Distinct from the prior reject-path finding (prior-findings:649, allocation-before-token) which concerns the live limiter's call order.

---

#### F-147 · Release builds spend two getsockopt syscalls per binding per second building a debug String that is compiled-out dead work (binding_summary), duplicating the statistics_v2 call made 100 lines later

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `x-hpc`  ·  **Location:** `userspace-dp/src/afxdp/worker/loop_body/mod.rs`:979
- **Labels:** `performance`, `refactor`, `observability`

```
                let mut binding_summary = String::new();
                for (i, b) in bindings.iter().enumerate() {
                    use std::fmt::Write;
                    let fill_pending = b.xsk.device.pending();
                    let rx_avail = b.xsk.rx.available_relaxed();
                    let xsk_stats = b.xsk.device.statistics_v2().ok();
```

**Runtime trace**

1) Every DBG_REPORT_INTERVAL_NS (1 s) tick of worker_loop, lines 976-1102 run UNCONDITIONALLY in release builds: per binding they format ~300 bytes into binding_summary (growing String), call device.statistics_v2() (an XDP_STATISTICS getsockopt syscall, line 984) and getsockopt(SO_ERROR) (lines 1058-1066), and compute the FRAME_LEAK total (lines 1095-1101). 2) The ONLY consumer, debug_report::emit_periodic_report (line 1109-1117), is #[cfg(feature = "debug-log")] — in release builds the String is dropped unread, and the FRAME_LEAK signal computed here is discarded (invisible to operators). 3) Lines 1181-1185 in the SAME tick call statistics_v2() AGAIN for the real rx_fill_ring_empty_descs publish — so the syscall is duplicated. 4) Net effect in production: dead formatting work, a duplicated syscall, and periodic 1 Hz jitter spikes injected into the packet-polling thread for zero observable output. The #1776 comment ('the always-on binding_summary build above is unchanged') shows this was carried through the code-motion refactor rather than decided.

**Why it matters** — Syscalls and allocator churn on the AF_XDP polling thread are the project's stated no-go ('Latency is sacred'); at 1 Hz the CPU cost is small but the jitter is gratuitous, and the always-computed FRAME_LEAK detection silently evaporates in exactly the builds that run in production.

**Fix direction** — Gate the whole binding_summary construction (String + statistics_v2 + SO_ERROR probes) under #[cfg(feature = "debug-log")] alongside its consumer, reuse the single statistics_v2 sample for both the summary and the rx_fill_ring_empty_descs publish, and promote the frame-leak check (total_accounted != expected_total) to an always-on counter/atomic instead of a debug-string suffix.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'binding_summary', 'debug report', '1776', 'statistics_v2', 'FRAME_LEAK'. #1776 (CLOSED) extracted the cfg-gated report into debug_report.rs but explicitly left this always-on build untouched (pure code motion); no issue or prior finding flags the release-build dead work, the duplicated getsockopt, or the discarded frame-leak signal.

---

#### F-148 · Route-table resolution heap-allocates Strings per lookup — per-packet on fabric-ingress flow-cache revalidation, per-flow on every session miss ('Never allocate per packet' violation)

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `x-hpc`  ·  **Location:** `userspace-dp/src/afxdp/forwarding/mod.rs`:1141
- **Labels:** `performance`, `hot-path-allocation`

```
        IpAddr::V4(ip) => {
            let table = table
                .map(|table| canonical_route_table(table, false))
                .unwrap_or_else(|| DEFAULT_V4_TABLE.to_string());
...
pub(super) fn canonical_route_table(table: &str, is_ipv6: bool) -> String {
    ...
    table.to_string()
}
```

**Runtime trace**

1) Every session-miss slow-path packet calls resolve_forwarding -> lookup_forwarding_resolution_with_dynamic -> lookup_forwarding_resolution_inner_ecmp, which allocates 'inet.0'.to_string() (or a canonical_route_table format!/to_string) at forwarding/mod.rs:1139-1141 / 1182-1184 just to key routes_v4/routes_v6 (which accept &str via Borrow). A next-table static route clones another String per recursion level (line 1607). 2) Worse than per-flow: on a chassis cluster, every fabric-ingress flow-cache HIT runs cached_flow_decision_valid -> prefer_local_forward_candidate_for_fabric_ingress (forwarding/mod.rs:719-731, 493-498) and, for cached FabricRedirect entries, the check at lines 700-706 — both call lookup_forwarding_resolution_with_dynamic per packet, so in split-RG steady state (fabric cross-chassis forwarding after failover/failback) the worker performs one or two malloc/free round-trips per forwarded packet on the polling thread. 3) docs/engineering-style.md 'Hot-path coding discipline / Allocations: Never allocate per packet' codifies this as a violation; allocator pressure also adds jitter on the same cores doing AF_XDP polling.

**Why it matters** — Session-establishment rate (CPS) and the HA fabric path are both benchmarked, latency-sensitive paths; a per-packet/per-flow allocator round-trip is avoidable overhead and jitter on a code path the project's own style guide forbids allocating on.

**Fix direction** — Intern route-table names to small integer IDs (u16) at forwarding_build snapshot time and key routes_v4/routes_v6 by ID; short-term, make canonical_route_table return Cow<'static, str> (default tables and pass-through cases borrow; only the rare prefix-rewrite allocates) and take table: &str all the way down, removing the next-table clone by restructuring the recursion to pass the borrowed route field.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'canonical_route_table', 'to_string', 'allocation', 'session miss', 'route lookup'. Closed #921 fixed 'string-heavy zone resolution' allocations on session miss (different site: zones, fixed); prior findings on canonical_route_table (prior-findings:594/604) are correctness/canonicalization issues, not the allocation. No issue covers the route-table String allocation or its per-packet reach via the fabric-ingress cache-hit revalidation.

---

#### F-149 · make deb dirty-detection uses `git diff --quiet`, missing staged and untracked changes — a deb built from staged-but-uncommitted work is versioned as clean while the embedded LDFLAGS version says -dirty

- **Severity:** 🟡 low  ·  **Confidence:** high
- **Module:** `x-tests-build`  ·  **Location:** `Makefile`:365
- **Labels:** `build`, `bug`, `supply-chain`

```
DEB_GIT_COUNT ?= $(shell git rev-list --count HEAD 2>/dev/null || echo 0)
DEB_GIT_SHA   ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
DEB_GIT_DIRTY ?= $(shell git diff --quiet 2>/dev/null || echo .dirty)
DEB_VERSION ?= 0.0.$(DEB_GIT_COUNT)+g$(DEB_GIT_SHA)$(DEB_GIT_DIRTY)
```

**Runtime trace**

Developer does `git add pkg/dataplane/userspace/policies.go` (staged, not committed) and runs `make deb` (directly or via bake.py / XPF_DEPLOY_DEB=1 cluster dogfood). `git diff --quiet` compares WORKTREE vs INDEX only — staged-only changes exit 0, so DEB_GIT_DIRTY is empty and the package is versioned 0.0.N+g<sha> with no .dirty marker, asserting it is exactly commit <sha>. Meanwhile the binaries inside were compiled from the staged tree, and their embedded `main.version` (Makefile line 8: `git describe --tags --always --dirty`, which uses diff-index against HEAD and DOES flag staged changes) reports -dirty. Two provenance channels of the same artifact now disagree; the #1917 versions/<v> staging dir, upgrade skip/compare decisions, and the bake manifest all key on the deb version, so a not-actually-commit-<sha> build masquerades as reproducible. Untracked new files are missed by BOTH channels.

**Why it matters** — Version strings are the only link from a deployed appliance binary back to source during incident forensics and staggered HA upgrades (#641 version-skew gating); a clean-looking version on dirty binaries is precisely the ambiguity those mechanisms exist to remove.

**Fix direction** — Use `git diff-index --quiet HEAD --` (matches describe --dirty semantics) or `test -z "$(git status --porcelain)"` (also catches untracked files) for DEB_GIT_DIRTY.

**Not a duplicate** — Searched issues-all.txt for 'dirty', 'deb', 'version' — #1917/#1983/#641 (all closed) are the upgrade/version-skew machinery, none touch the dirty-detection predicate; prior-findings.md 'dirty' hits are ipmon dirty-bit items only. Novel mechanism (git diff vs diff-index semantics gap).

---

## 6.2 Medium-confidence findings (108)

> Likely bugs or incomplete behavior that a maintainer should validate against intended semantics before fixing.
> Severity mix: 5 high · 42 medium · 61 low.

#### F-150 · commit-confirmed timeout rollback on the active node is never propagated to the HA peer, leaving the standby permanently on the abandoned config

- **Severity:** 🔴 high  ·  **Confidence:** medium
- **Module:** `go-daemon-lifecycle`  ·  **Location:** `pkg/daemon/daemon_apply.go`:371
- **Labels:** `bug`, `vsrx-parity`, `ha`

```
	if err := d.applyConfigLocked(context.Background(), prevCfg); err != nil {
		slog.Error("commit confirmed auto-rollback dataplane apply failed", "err", err)
	}
	slog.Warn("commit confirmed timed out, configuration rolled back")
```

**Runtime trace**

gRPC CommitConfirmedFn -> commitConfirmedAndApply(ctx, minutes, syncPeer=true). store.CommitConfirmed(minutes) promotes the candidate and arms a store-local confirmTimer; applyConfigLocked applies it; then `if syncPeer { d.syncConfigToPeer() }` (line 310) pushes the UNCONFIRMED config text to the standby via pushConfigToPeer->QueueConfig. The peer's handleConfigSync -> syncAndApply -> store.SyncApply promotes it as a PERMANENT active config (SyncApply arms NO confirm timer). The operator does not confirm within `minutes`; the store-local timer fires executeConfirmedRollback on the active, which PromoteRollback+applyConfigLocked(prevCfg) reverts the ACTIVE only, and returns WITHOUT calling syncConfigToPeer. End state: active=prevCfg (old), standby=new (the config the operator explicitly let expire). No reconnect occurs, so the reverse-sync-on-reconnect path never fires; divergence persists until the next commit on the active. On a subsequent failover the standby serves the abandoned config.

**Why it matters** — In a production firewall HA pair, `commit confirmed` is the standard safety net for a config that might cut off management. On vSRX the confirmed commit is synchronized so BOTH nodes roll back on timeout. Here only the active rolls back, so a failover after an unconfirmed-then-timed-out commit brings up the exact config the operator judged unsafe (e.g. a policy or interface change that stranded management) — defeating the purpose of commit-confirmed in the one environment where it matters most.

**Fix direction** — In executeConfirmedRollback, after the successful prevCfg re-apply, push the rolled-back config to the peer (syncConfigToPeer / pushConfigToPeer) so the standby converges. Better: propagate the confirmed-commit semantics across sync so the peer arms its own rollback timer and both nodes revert together (vSRX parity).

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for commit-confirmed|rollback.*peer|confirmed.*sync|confirmed.*cluster: only hit is #339 (graceful demotion readiness), unrelated. SyncApply confirmed to have no confirm timer (configstore/store.go confirmTimer is store-local; handleConfigSync->syncAndApply->SyncApply is a plain permanent promotion). Not a duplicate of any open/closed issue.

---

#### F-151 · Syslog stream write-timeout leaves a partial RFC 6587 frame on the TCP/TLS socket → permanent octet-counting framing desync

- **Severity:** 🔴 high  ·  **Confidence:** medium
- **Module:** `go-obs`  ·  **Location:** `pkg/logging/syslog.go`:470
- **Labels:** `bug`, `correctness`, `security`, `observability`

```
if isTimeout(err) {
    pendingWarn = s.noteDrop(dropWrite, err)
    return err
}
slog.Debug("syslog send failed, reconnecting", "addr", s.remoteAddr, "err", err)
```

**Runtime trace**

Config: security log stream transport tcp (or tls), a busy/slow collector. Runtime: EventReader.logEvent → SyslogClient.Send builds the RFC 6587 octet-counted frame "<len> <msg>" and calls writeMsg → streamWrite (syslog.go:531). streamWrite sets a 4s write deadline then conn.Write(b). Under sustained load the collector's receive window fills, the kernel send buffer fills, Write blocks and the deadline fires — conn.Write returns (n, timeoutErr) with 0 < n < len(b): the first n bytes of the framed record are already on the wire. isTimeout(err) is true (syslog.go:470), so Send bumps droppedWrites and returns WITHOUT closing or reconnecting the conn (deliberate #2287 behavior to avoid doubling the stall). The socket stays open with a half-written frame. The NEXT Send (or SendBinary, syslog.go:557) writes a fresh complete "<len> <msg>" frame that concatenates directly after the partial bytes. The collector's octet-counting parser read the ORIGINAL <len> and is now consuming the wrong byte count: every subsequent record is misframed. The desync persists indefinitely because a write timeout never triggers the reconnect that would rebuild the stream — only a genuine ECONNRESET/EPIPE does. All RT_FLOW security telemetry to that collector is corrupted until an unrelated connection error happens to reset the socket.

**Why it matters** — On a security appliance the TCP/TLS syslog stream is the audit/forensics channel; a single write timeout under collector backpressure silently corrupts the framing of every following record (dropped or misattributed session/deny/screen events at the SIEM) with no operator-visible signal beyond the drop counter — exactly during the incident load when the logs matter most.

**Fix direction** — On a stream write timeout the framing state is unknown: tear down the conn (set s.conn=nil / close) so the next Send lazily reconnects with a clean frame boundary, instead of continuing to write onto a desynced socket. This keeps the #2287 no-immediate-retry property (drop this message, reconnect on the next one) while restoring frame integrity. Add a test that partial-writes a frame then asserts the next frame starts on a fresh conn.

**Not a duplicate** — Searched issues-all.txt/prior-findings for syslog, framing, octet, desync, partial, reconnect. Nearest: #2283 (no write deadline + reconnect thrash), #2287 (re-entrant deadlock + write-timeout must NOT reconnect/retry — this fix is what INTRODUCED the no-reconnect-on-timeout path), #2302 (accept-then-reset dial-storm cooldown). None address the RFC 6587 partial-frame desync that results from returning on a timeout without closing the conn; this is a new mechanism residual to the #2287 fix.

---

#### F-152 · Cross-worker seq-allocate/enqueue race produces out-of-order frames on the event-stream wire; the Go reader has zero reorder tolerance and treats any inversion as a session-sync gap (spurious full resync + disconnect)

- **Severity:** 🔴 high  ·  **Confidence:** medium
- **Module:** `go-usdp-ha-events`  ·  **Location:** `userspace-dp/src/event_stream/mod.rs`:558
- **Labels:** `bug`, `ha`, `performance`

```
    fn encode_delta_frame(
        &self,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
    ) -> EventFrame {
        let seq = self.next_seq();
        match delta.kind {
            SessionDeltaKind::Open => EventFrame::encode_session_open(
                seq,
                &delta.key,
```

**Runtime trace**

1) Every AF_XDP worker thread flushes its own session deltas (afxdp/session_delta.rs:199 push_delta_lossless, called from worker loop_body) and telemetry; each call allocates seq via the shared atomic (mod.rs:558 / :480) and then独立ly enqueues onto the shared mpsc SyncSender — there is no lock making allocation+enqueue atomic. 2) Worker A allocates seq=100, is preempted during frame encoding; worker B allocates seq=101 and completes try_send first. Channel order (= wire order, single IO thread) is 101 then 100. 3) Go readLoop (pkg/dataplane/userspace/eventstream.go:404) with prevSeq=99 processes seq=101: '101 > 99+1' → handleSessionSyncGap → full owner-RG bulk export + connection drop, even though frame 100 was nanoseconds behind. 4) Even when the inversion straddles the check benignly (100 accepted after 101 when prevSeq math allows), prevSeq regresses to 100 (eventstream.go:408 'prevSeq = seq' unconditionally), so the NEXT contiguous frame 102 again looks like a gap (102 > 100+1) → resync. 5) During the recovery export itself all workers push lossless frames concurrently at maximum rate, maximizing the same inversion probability — recovery can re-trigger the gap detector. The replay buffer stores frames in channel order, so reconnect replays the same inversion.

**Why it matters** — Same blast radius as the seq-burn finding — spurious full exports and event-stream reconnects on the HA-critical path — but triggered by pure concurrency at high session-churn rates (multi-worker SYN floods, failover storms, bulk exports), with a feedback loop during recovery. The wire contract implicitly assumes globally ordered delivery that the multi-producer implementation does not provide.

**Fix direction** — Make seq allocation and channel enqueue atomic under one small mutex on the producer side (allocation is off the per-packet hot path — deltas are drained in batches), or move to per-connection re-sequencing in the IO thread (allocate the wire seq when the IO thread dequeues, keeping producer seqs internal). Alternatively add a bounded reorder window in the Go readLoop (buffer up to N frames / T ms before declaring a session-sync gap).

**Not a duplicate** — Searched for out-of-order/reorder/monotonic seq/ordering in issues-all.txt and prior-findings.md — no hit on the event-stream seq space. #90 (frame corruption from unsynchronized writes) and #430 (barrier ordering) are the closest priors but concern the pkg/cluster peer-sync socket, not the helper→daemon event stream; #2874 added the gap detector without reorder tolerance.

---

#### F-153 · Telemetry frame dropped on a full event-stream channel burns its sequence number, and the Go reader misclassifies the resulting hole as a session-sync gap — spurious full owner-RG bulk export + reconnect, self-amplifying under load

- **Severity:** 🔴 high  ·  **Confidence:** medium
- **Module:** `go-usdp-ha-events`  ·  **Location:** `userspace-dp/src/event_stream/producer.rs`:343
- **Labels:** `bug`, `performance`, `ha`, `test-gap`

```
        let seq = self.next_seq();
        let frame = encode(seq);
        match self.try_send_frame(frame) {
            Ok(()) => {
                self.shared.dataplane_event_counters.record_sent(kind);
                DataplaneEventEmitOutcome::Queued { seq }
            }
            Err(EventStreamSendError::Full) => {
                self.shared.dataplane_event_queue.release(kind);
                self.shared
                    .dataplane_event_counters
                    .record_drop(kind, DataplaneEventDropReason::QueueFull);
```

**Runtime trace**

1) Session-sync frames and dataplane telemetry frames share ONE globally monotonic seq space (next_seq AtomicU64, mod.rs:248). 2) try_emit_dataplane_frame allocates seq only after the rate limiter + queue budget pass (producer.rs:336) — but the queue budget caps telemetry at half of CHANNEL_CAPACITY (8192) while the LOSSLESS session producer can fill the whole channel (send_frame_lossless retries up to 5s). During a bulk session export (or a slow daemon reader) the channel is full, so try_send_frame returns Full at producer.rs:343 and the already-allocated seq is burned — a permanent hole in the sequence space (the frame never enters the channel or replay buffer). 3) In the Go daemon, readLoop (pkg/dataplane/userspace/eventstream.go:404/:424) checks 'seq > prevSeq+1 && prevSeq > 0' on EVERY session open/close frame. When the next frame after the hole is a session frame — near-certain under steady session churn — it cannot distinguish a benign telemetry hole from a lost session delta and calls handleSessionSyncGap: SessionSyncResyncs++, onFullResync → handleEventStreamFullResync → exportUserspaceOwnerRGSessionsWithConfig (full owner-RG export with a 15s worker ack-wait, daemon_ha_userspace.go:670), then drops the connection. 4) The export itself saturates the channel with lossless session frames, so concurrent policy-deny/filter-log/screen telemetry burns MORE seqs → more holes → more resyncs: a feedback loop firing exactly when the control socket is busiest (CLAUDE.md: bulk sync starves session installs). This directly violates the stated design intent at afxdp/session_delta.rs:197: 'a dropped flow-export record is not a correctness loss and must not force a resync'. Tests cover same-type gaps only (TestEventStreamSessionGapTriggersResyncWithholdsAck, TestEventStreamTelemetryGapDoesNotTriggerResync) — the cross-type hole-before-session-frame case is untested.

**Why it matters** — HA session-sync availability: every spurious resync costs a full conntrack-table export plus an event-stream reconnect, starving real session installs during churn/failover — the exact moment the standby needs fresh deltas. Under a policy-deny flood (attacker-controllable telemetry rate) plus normal session churn this becomes a sustained resync storm.

**Fix direction** — Stop burning seqs on drops: make seq-allocation + channel-enqueue atomic (tiny mutex around next_seq+try_send; on Full, roll back with fetch_sub since the lock excludes other allocators), or reserve a channel slot before allocating the seq. Alternatively have the producer plug known holes with a lossless no-op 'seq-skip' frame so the Go reader never sees a false session gap. Add a Go test: telemetry hole followed by a session frame must not force a resync once the producer guarantees hole-freedom.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for eventstream/event-stream/session-sync/gap/resync/replay/spurious/seq-hole. #2874 (closed) made session deltas lossless and ADDED this Go gap→resync path; #2442 covers delta-ring overflow resync; #2959 covers helper-side ACK validation; #2381 write-backlog bound; #2875-2883 drain/replay hardening. None cover a telemetry seq burn being misclassified as a session gap — this is a new defect in the #2874 classification contract itself.

---

#### F-154 · Per-worker flow cache outlives its idle-reaped session: reused/resumed 5-tuple is served the dead flow's cached NAT+redirect decision, blackholing the reverse direction

- **Severity:** 🔴 high  ·  **Confidence:** medium
- **Module:** `rs-session`  ·  **Location:** `userspace-dp/src/afxdp/worker/loop_body/mod.rs`:735
- **Labels:** `bug`, `correctness`, `flow-cache`, `nat`, `security`

```
        for expired_entry in expired_entries {
            release_source_nat_allocation(
                &forwarding.source_nat_rules,
                &expired_entry.key,
                expired_entry.decision.nat,
                expired_entry.metadata.is_reverse,
                loop_now_ns,
            );
            delete_session_map_entry_for_removed_session_with_origin(
                session_map_fd,
                &expired_entry.key,
```

**Runtime trace**

1) A UDP flow (5-tuple K, e.g. NTP/DNS/monitoring with a fixed source port) or an established-TCP flow is cached: poll_descriptor/mod.rs:3731 FlowCacheEntry::from_forward_decision inserts entry E{key=K, decision=SNAT->port P, dst_mac M} with a stamp {config_gen,fib_gen,rg_epoch, owner_rg_lease_until=0 on standalone}. 2) Flow goes idle longer than its expires_after_ns (UDP 60s). No packet arrives, so flow_cache_hit.rs:195 touch_if_stale is never called and the session's last_seen goes stale. 3) session/expire.rs expire_stale_entries_ha reaps the session (remove_entry) and returns it in expired_entries; the loop above runs release_source_nat_allocation (frees SNAT port P) and delete_session_map_entry_for_removed_session_with_origin (removes the USERSPACE_SESSIONS redirect entry userspace-xdp uses to steer replies). NOTHING invalidates the per-binding flow cache — the loop has &mut bindings in scope but never calls binding.flow.flow_cache.invalidate_slot. 4) Flow resumes on the same K. For UDP the first packet is packet_eligible (flow_cache.rs:268), so stage_flow_cache_hit (flow_cache_hit.rs:94) lookup_counted(K) HITS E; cached_flow_decision_valid (forwarding/mod.rs:675) validates only HA/fabric/generation state (it takes no &SessionTable and cannot see that the session is gone), neighbor_mac_epoch_stale is false (MAC unchanged), stamp is unchanged, lease==0 -> served. 5) The packet is SNAT'd to the now-FREED port P via the stale descriptor and forwarded; touch_if_stale(K) and account_packet(K) both no-op (session gone). The reply to P has no session-map entry and no reverse session -> session miss -> dropped as unsolicited inbound (blackhole). If P was reallocated to a different flow, the two flows now share one SNAT binding (cross-flow leak). For TCP the resume SYN builds a NEW session (new SNAT port) but the completing pure-ACK hits stale E and is forwarded with the OLD translation, diverging from the live session.

**Why it matters** — In a production firewall this is a silent, intermittent connectivity break for any flow that idles past its inactivity timeout and then reuses the same 5-tuple (NTP poll >64s, DNS/monitoring with pinned source ports, keepalive gaps). With pool/interface SNAT it black-holes the reverse direction and can cross-wire two flows onto one freed SNAT port; even without NAT the deleted session-map redirect entry means reply traffic is no longer steered to the owner worker. It is hard to diagnose because the forward direction keeps flowing from cache while the session table shows no session.

**Fix direction** — Invalidate the per-binding flow-cache slot when a session is reaped. In the expired_entries loop, for the forward (non-reverse) key iterate bindings and call flow_cache.invalidate_slot(&expired_entry.key, ingress_ifindex). The obstacle is that FlowCacheEntry is keyed by (forward_key, ingress_ifindex) but SessionMetadata does not carry the ingress ifindex; either store ingress_ifindex on the session/ExpiredSession so invalidation is O(1), or add a session-liveness cross-check to cached_flow_decision_valid / lookup so a hit whose backing session is absent is treated as a miss.

**Not a duplicate** — Searched issues-all.txt + prior-findings.md for flow_cache/expire/idle/reuse/stale/outlive. Nearest: #3048 (MAC-change eviction) — different trigger, fires only on a genuine neighbor MAC change; here mac/config/fib/epoch/lease are all unchanged so no invalidation path exists. #429 (flow cache outlives HA lease) — lease-driven and only when owner_rg_lease_until!=0; F1 is standalone/active (lease==0), driven by idle-GC reap + SNAT release + session-map delete. #2220 is the inverse (keep active flows alive) and its touch_if_stale fix does not cover idle-then-resume. Not covered by #2363/#327/#417/#2466.

---

#### F-155 · pkg/api applies auth only when Auth!=nil and always exempts /metrics — a non-loopback web-management bind without api-auth serves the full mutating API (reboot/zeroize/commit/session-clear) unauthenticated

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-api-grpc`  ·  **Location:** `pkg/api/server.go`:389
- **Labels:** `security`, `bug`

```
	var handler http.Handler = mux
	if cfg.Auth != nil {
		handler = authMiddleware(*cfg.Auth, mux)
	}

	s.httpServer = &http.Server{
		Addr:    cfg.Addr,
		Handler: handler,
	}
```

**Runtime trace**

daemon_run.go:1341 resolves `set system services web-management http interface <if>` to that interface's real address (resolveInterfaceAddr), so apiCfg.Addr becomes e.g. 10.0.1.1:8080 (NOT loopback). apiCfg.Auth is set ONLY when wm.APIAuth has users or keys (daemon_run.go:1357). If the operator binds to a LAN/DMZ interface but does not configure api-auth, cfg.Auth==nil, so NewServer leaves handler=mux with NO authMiddleware. An attacker on that segment can POST /api/v1/system/action {"action":"reboot"} (system.go:262 systemActionHandler), POST /api/v1/config/commit, POST /api/v1/security/sessions/clear, POST /api/v1/config/set — all unauthenticated. Separately, even when auth IS configured, authMiddleware (auth.go:21) unconditionally bypasses /health and /metrics, so GET <lanip>:8080/metrics exposes the entire Prometheus operational surface (interface/session/NAT/zone/feed/wireguard-tunnel names + counters) to the network with no credential.

**Why it matters** — Junos never serves web-management without authentication; here the API is insecure-by-omission the moment it leaves loopback, and there is no startup guardrail/warning when a non-loopback bind lacks auth. The exposed verbs include destructive control-plane actions (reboot, halt, zeroize/factory-reset, config commit).

**Fix direction** — Refuse to serve mutating endpoints (or refuse to start the listener) on a non-loopback bind when Auth==nil, or require auth whenever Addr/HTTPSAddr is non-loopback; at minimum emit a loud startup WARN. Consider gating /metrics behind auth (or a separate loopback-only listener) when the API binds a non-loopback interface.

**Not a duplicate** — Grepped issues-all.txt/prior-findings.md for auth/web-management/unauth/metrics: only #2681 (SNMPv3 noAuthPriv) is auth-related and unrelated. No prior finding on optional-auth default or the non-loopback exposure of the mutating REST surface / unauthenticated /metrics. The module note assumes 'localhost-only trust' but the code (daemon_run.go bind resolution) allows non-loopback, which is what makes this live.

---

#### F-156 · Config sync applies via unordered goroutines with no sequence number — a rapid pair of commits can leave the standby converged on the OLDER config

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-cluster-sync`  ·  **Location:** `pkg/cluster/sync_conn.go`:1336
- **Labels:** `bug`, `ha`, `vsrx-parity`

```
	case syncMsgConfig:
		s.stats.ConfigsReceived.Add(1)
		s.stats.LastConfigSyncTime.Store(time.Now().UnixNano())
		s.stats.LastConfigSyncSize.Store(uint64(len(payload)))
		if s.OnConfigReceived != nil {
			configText := string(payload)
			slog.Info("cluster sync: config received from peer", "size", len(payload))
			go s.OnConfigReceived(configText)
		}
```

**Runtime trace**

1) Operator (or automation) commits twice in quick succession on the RG0 primary; each commit calls syncConfigToPeer → QueueConfig, writing config A then config B in order on the TCP stream. 2) The standby's receiveLoop decodes them serially but dispatches each as `go s.OnConfigReceived(...)` (sync_conn.go:1336) — goroutine start order is not execution order. 3) Both goroutines run daemon handleConfigSync (daemon_ha_sync.go:347) → syncAndApply under d.applySem; goroutine B reaches Acquire first (nothing orders them), applies B. 4) Goroutine A then acquires the semaphore; the skip-if-matches-active check compares A against active (=B), they differ, so A is applied — the standby's final active config is the STALE config A while the primary runs B. 5) The wire carries no sequence/monotonic commit ID for syncMsgConfig, so the receiver cannot detect the inversion; divergence persists until the next commit or a reconnect push (OnPeerConnected).

**Why it matters** — Silent config divergence between HA nodes defeats commit-synchronize semantics: after the next failover the new master enforces stale policy/NAT/zones — a security-relevant drift with no alarm (both nodes report config sync success).

**Fix direction** — Carry a monotonically increasing config generation in the syncMsgConfig payload (length-gated trailing field, same discipline as #2170) and have the receiver drop any config older than the last applied; or dispatch OnConfigReceived through a single-worker ordered queue instead of one goroutine per message.

**Not a duplicate** — Grepped 'config sync': #78 (CLOSED, authority not enforced — fixed via RG0-primary reject), #606 (CLOSED, identical-config reapply teardown — fixed via skip-if-matches), #1794 (CLOSED, hung external command wedges config sync). None cover same-authority ordering inversion between two successive pushes; no prior finding mentions the per-message `go OnConfigReceived` dispatch.

---

#### F-157 · Dual-fabric: bulk-receive state is reset only when ALL fabrics drop — mid-bulk loss of the carrying fabric latches bulkInProgress with unbounded bulkRecv map growth and no bulk retry

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-cluster-sync`  ·  **Location:** `pkg/cluster/sync_conn.go`:1570
- **Labels:** `bug`, `ha`, `performance`

```
		s.pendingBulkAckEpoch.Store(0)
		s.pendingBulkAckSince.Store(0)
		s.bulkMu.Lock()
		hadBulkInProgress := s.bulkInProgress
		s.bulkInProgress = false
		s.bulkRecvEpoch = 0
		s.bulkRecvV4 = nil
		s.bulkRecvV6 = nil
```

**Runtime trace**

1) Dual-fabric cluster (#107), cold start: fab1 connects first, handleNewConnection(1) sees wasDisconnected=true and runs doBulkSync over conn1; the fallback BulkSync streams sessions directly. 2) Receiver processed syncMsgBulkStart: bulkInProgress=true, fresh bulkRecvV4/V6 maps (sync_conn.go:1271-1277). 3) fab1 flaps mid-bulk. Sender: write error → iteration aborts, handleNewConnection logs 'bulk sync failed' — no retry loop. Receiver: conn1 receiveLoop exits → handleDisconnect(conn1), but conn0 is (or soon becomes) up, so `connected` stays true and the bulk reset block (:1568-1577) — the ONLY reset besides a new BulkStart — never runs. 4) BulkEnd never arrives; every subsequent incremental v4/v6 install (handleMessage :1187-1191) does `if s.bulkInProgress { s.bulkRecvV4[key] = struct{}{} }`, growing the map for every synced session forever (no cap, unlike genGuardMapCap). 5) reconcileStaleSessions never runs; TransferReadiness().BulkReceiveInProgress stays true → ManualFailover permanently rejected ('local bulk receive still in progress'). 6) No new BulkStart ever comes: when fab1 reconnects, wasDisconnected=false (conn0 up) → 'skipping bulk sync on reconnect' — and sender bulkEverCompleted is still false, but the cold-start branch requires wasDisconnected. Both nodes stay wedged until a full dual-fabric outage.

**Why it matters** — A single fabric-link flap during the cold-start bulk on a dual-fabric HA pair permanently disables explicit failover on the receiver, leaks memory proportional to session churn, and leaves the standby never reconciled — with zero retry and only an all-fabrics outage as recovery.

**Fix direction** — Tie bulk-receive state to the connection that carried BulkStart (reset it in handleDisconnect for that conn even when another fabric survives), and/or have the sender retry doBulkSync while bulkEverCompleted is false when any connection is available, not only on wasDisconnected.

**Not a duplicate** — Grepped 'bulk', 'fabric': #466 (CLOSED) removed re-bulk on reconnect/active-fabric change — that fix created this no-retry gap, so this is a new residual of #466 (different mechanism: partial-disconnect state latch, not redundant re-prime); #117 (CLOSED) was concurrent bulk writers/epochs; #123 (CLOSED) was single replaceable conn flap. None cover keep-bulk-state-when-one-fabric-survives.

---

#### F-158 · compileNAT reads only the FIRST `source`/`destination`/`static`/`nat64`/`proxy-arp` block per `nat` node — a duplicate sub-block from hierarchical load override is silently discarded (SNAT rule-sets vanish, traffic egresses untranslated)

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-config-nat`  ·  **Location:** `pkg/config/compiler_nat.go`:695
- **Labels:** `bug`, `vsrx-parity`

```
	srcNode := node.FindChild("source")
	if srcNode != nil {
		if err := compileNATSource(srcNode, sec); err != nil {
			return fmt.Errorf("source: %w", err)
		}
	}

	dstNode := node.FindChild("destination")
	if dstNode != nil {
		if err := compileNATDestination(dstNode, sec); err != nil {
```

**Runtime trace**

The Junos parser APPENDS a repeated block as a sibling instead of merging (parseStatements, per the project's own #3562 analysis in compiler_nat_dnat_to.go:64-82, which names 'a hierarchical LoadOverride input' as the reachable vector). Input: a hierarchical config containing `security { nat { source { pool A {...} } source { rule-set RS { from zone trust; to zone untrust; rule R1 { ... then source-nat pool A; } } } } }`. (1) parseStatements appends two sibling `source` nodes under one `nat`. (2) compileSecurity compiles every `nat` sibling (compiler_security.go:156-173) but compileNAT then does node.FindChild("source") (compiler_nat.go:695) — FIRST match only. (3) The second `source` block, containing the entire rule-set, is never visited. Empirically verified: CompileConfig succeeds with SourcePools=1 and len(Security.NAT.Source)==0 — the authored SNAT rule-set does not exist. (4) No validator backstops this: #3562 fixed six strict-reject AST WALKS (iterate-all-security-roots) and #3566 fixed flow-trace/log-stream sub-levels, but the NAT compiler itself remains first-match at the source/destination/static/nat64/proxy-arp level (the dnat_to.go comment explicitly acknowledges 'compileNAT itself reads only the first destination per nat' and covers only the `to`-scope case). Result: internal RFC1918 sources egress the WAN untranslated (upstream drops or, worse, leaks internal addressing), or a dropped duplicate `static`/`nat64` block silently removes inbound mappings — all with a green commit.

**Why it matters** — Same silent-config-drop class the project has repeatedly treated as high-priority (#3562, #3566), but on the COMPILER side rather than a validator walk, so the fix pattern (forEachChild) was never applied here. A merge/override workflow that produces duplicate blocks yields a firewall whose running NAT differs from the accepted candidate with no diagnostic.

**Fix direction** — In compileNAT, iterate ALL matching children with forEachChild (already defined in compiler_nat_dnat_to.go:121) for source/destination/static/nat64/natv6v4/proxy-arp, appending into the same SecurityConfig (the sub-compilers already append/merge into maps and slices). Alternatively add a strict duplicate-block reject, but merge is the Junos-faithful semantic.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'duplicate', 'FindChild', 'first-match', '3562', '3566', 'merge block': #3562 (CLOSED, six strict-reject VALIDATOR walks at the security-root level) and #3566 (CLOSED, flow-trace/log-stream validator sub-levels) are the nearest — both fixed validators being BYPASSED; this residual is the NAT COMPILER dropping the duplicated config itself (different observable: config vanishes rather than a reject being skipped), explicitly left behind per the comment in compiler_nat_dnat_to.go:78-82. Prior finding 'default-policy-log FindChild-only parsing' (compiler_security.go) is a different leaf/mechanism (multi-leaf list, not duplicate blocks).

---

#### F-159 · apply-groups drops group-contributed leaf-list values whenever the target already has ANY leaf with the same first key (hasMatchingLeaf matches Keys[0] only) — vSRX merges leaf-lists from groups

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-config-parse`  ·  **Location:** `pkg/config/ast_groups.go`:290
- **Labels:** `bug`, `vsrx-parity`

```
// hasMatchingLeaf returns true if nodes contains a leaf whose first key
// matches. This prevents group values from overriding explicit config
// (e.g., if "host-name explicit" already exists, "host-name group" is skipped).
func hasMatchingLeaf(nodes []*Node, keys []string) bool {
	if len(keys) == 0 {
		return false
	}
	for _, n := range nodes {
		if n.IsLeaf && len(n.Keys) > 0 && n.Keys[0] == keys[0] {
			return true
		}
```

**Runtime trace**

Config: `set groups common system name-server 1.1.1.1` + `set apply-groups common` + `set system name-server 8.8.8.8`. Commit path: compile clones tree -> ExpandGroups -> expandGroupsRecursive -> mergeNodes(system.Children, group system children). Group leaf Keys=[name-server,1.1.1.1]; hasMatchingLeaf finds the existing leaf [name-server,8.8.8.8] by FIRST KEY ONLY -> the group's server is skipped entirely. Empirically confirmed (probe 8): post-expansion FormatSet contains only `set system name-server 8.8.8.8`. On vSRX/Junos, name-server (and ntp server, syslog host, import/export policies, zone lists...) are ordered leaf-LISTS and apply-groups MERGES group members after explicit ones (`show | display inheritance` shows both); here the group value silently never takes effect and `| display inheritance` (FormatInheritance uses the same merge) also hides it. The suppress-by-first-key rule is only correct for single-value scalars like host-name.

**Why it matters** — Configuration groups are the standard HA pattern in this codebase (node0/node1 groups); any shared group that contributes members to a leaf-list the local config also touches is silently ignored — the operator believes the inherited DNS/NTP/syslog/export entry is active on both nodes when it is not.

**Fix direction** — Distinguish scalar leaves from leaf-lists during merge: consult setSchema (multi:true or repeatable leaves) and for leaf-lists append group values whose full Keys differ, keeping first-key suppression only for single-value (args==1, !multi) scalars.

**Not a duplicate** — Searched issues/prior findings for apply-groups/groups/merge/leaf-list: #1914 (wildcard apply-groups refs hashed literally in the tunnel gate) and #1810 (setSchema name-server single-value replace, fixed — probe shows two leaves now coexist) are the nearest; neither covers mergeNodes/hasMatchingLeaf group-merge suppression semantics.

---

#### F-160 · Typo'd / unrecognized application-set MEMBER keyword is silently dropped with no commit gate — under-populates a `deny application-set` policy (fail-open)

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-config-policy`  ·  **Location:** `pkg/config/compiler_applications.go`:183
- **Labels:** `bug`, `security`, `config-fail-open`, `test-gap`

```
			switch member.Name() {
			case "application", "application-set":
				v := nodeVal(member)
				if v != "" {
					as.Applications = append(as.Applications, v)
				}
			}
```

**Runtime trace**

Input: `applications { application evil-app {...} application other-evil {...} application-set blocked { application evil-app; aplication other-evil; } }` (member keyword misspelled `aplication`, or any other non-`application`/`application-set` token). (1) The application-set schema node is `children: nil` (schema_security.go:862), i.e. an opaque subtree, so SchemaValidate never walks the members and does not reject the typo keyword. (2) compileApplications iterates inst.node.Children; the switch has ONLY `case "application", "application-set"` and NO default arm, so member `aplication other-evil` (Name()=="aplication") falls through and is silently dropped — as.Applications = [evil-app]. (3) validateApplicationSetMembersStrict (compiler_validate_strict.go:1894) iterates set.Applications — which now contains only the STORED members — so the dropped typo member is invisible to it; the set is non-empty so the empty-set gate also passes. RUNTIME-CONFIRMED: `blocked` compiled to members=[evil-app] with NO commit error. A policy `then deny application-set blocked` then blocks evil-app but silently permits other-evil.

**Why it matters** — For a deny-application-set policy, silently omitting an intended member is a fail-open: traffic the operator meant to block is admitted, with no commit-time signal. This mirrors the whole reject-at-commit-for-silently-dropped-tokens doctrine the campaign applies to term leaves (#3352), timeouts (#3320), and screen leaves (#3318), but application-set membership has no such gate for an unrecognized member keyword.

**Fix direction** — Add a default arm in the application-set member loop that records the unrecognized member token on a new ApplicationSet.UnknownMembers slice (mirroring ScreenProfile.UnknownLeaves / Application.UnknownTermLeaves), and a strict gate (validateApplicationSetMembersStrict or a sibling) that hard-rejects it on commit / warns on the lenient load path. Alternatively tighten the application-set schema node to enumerate `application`/`application-set` children so SchemaValidate rejects the typo directly.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for application-set member, 2217, 2068, 3149. #2068 fixed NESTED application-set member references being dropped (added the `application-set` arm — those are now STORED). #2217/#3149 validate a STORED member that references an UNDEFINED application/address (validateApplicationSetMembersStrict expands stored members). None cover a member whose KEYWORD itself is unrecognized (typo like `aplication`), which never reaches as.Applications and is thus invisible to every existing gate — a distinct, uncovered silent-drop.

---

#### F-161 · IKE and IPsec policy `proposals [ p1 p2 ]` truncate to the first proposal — negotiation preference list silently narrowed to one crypto suite

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-config-routing-services`  ·  **Location:** `pkg/config/compiler_ipsec.go`:76
- **Labels:** `vsrx-parity`, `bug`

```
		for _, p := range inst.node.Children {
			v := nodeVal(p)
			switch p.Name() {
			case "mode":
				pol.Mode = v
			case "proposals":
				pol.Proposals = v
```

**Runtime trace**

Junos allows an ordered proposal list: `set security ike policy ike-pol proposals [ p-aes256-sha2 p-aes128-sha1 ]`. Per the #2419 lexer contract (documented in CLAUDE.md and firewallMatchValues call sites), the bracket list collapses onto one leaf in BOTH AST shapes: Keys=["proposals","p-aes256-sha2","p-aes128-sha1"]. compileIKE line 76-77 stores nodeVal(p) → Keys[1] only → IKEPolicy.Proposals="p-aes256-sha2" (the field is a scalar string). resolveIKESettings looks up that single name (pkg/ipsec/ike.go:57 `cfg.IKEProposals[ikePol.Proposals]`) and renders one swanctl `proposals =` entry — the second proposal is silently dropped, no warning. A peer that only supports the second suite fails IKE negotiation even though the committed config lists it. The identical scalar read exists for phase 2: compileIPsec line 266-267 `case "proposals": pol.Proposals = v` → esp_proposals carries only the first (ike.go:86-90).

**Why it matters** — Multi-proposal policies are how operators run mixed-peer VPN estates (gradual crypto migration); silent truncation makes tunnels to legacy peers fail with an IKE 'no proposal chosen' that the committed config says cannot happen — a debugging trap on a security appliance.

**Fix direction** — Make IKEPolicy.Proposals / IPsecPolicyDef.Proposals []string, read via the firewallMatchValues SSOT (as #2587/#2702 did for routing export lists), and render comma-separated swanctl proposals preserving order; alternatively add a strict commit gate rejecting >1 token until multi-proposal is supported (fail-closed instead of silent).

**Not a duplicate** — Grepped 'proposal' in issues-all.txt/prior-findings.md: #2270 (broken policy→proposal CHAIN falls to defaults), #2073 (missing proposal ref drops PFS), #2125/#2392/#2604 (algorithm-name rendering) — all different mechanisms; no issue covers bracket-list truncation of the proposals leaf. #3703 enumerated remaining #2419-class leaves but only in security host-inbound/log surfaces, not ike/ipsec policy proposals.

---

#### F-162 · RIP export/redistribute left off the #2587 multi-value sweep — bracket-list policies truncate to the first entry (group export and top-level redistribute read only Keys[1])

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-config-routing-services`  ·  **Location:** `pkg/config/compiler_protocols.go`:585
- **Labels:** `bug`, `vsrx-parity`, `test-gap`

```
			case "group":
				for _, gc := range child.Children {
					switch gc.Name() {
					case "neighbor":
						if len(gc.Keys) >= 2 {
							proto.RIP.Interfaces = append(proto.RIP.Interfaces, gc.Keys[1])
						}
					case "export":
						if len(gc.Keys) >= 2 {
							proto.RIP.Redistribute = append(proto.RIP.Redistribute, gc.Keys[1])
						}
```

**Runtime trace**

Hierarchical config `protocols { rip { group wan-rip { export [ static-to-rip direct-to-rip ]; } } }` — the lexer strips brackets so gc.Keys=["export","static-to-rip","direct-to-rip"] (the #2419 collapse, both AST shapes). The compiler appends only gc.Keys[1] (line 588) → RIP.Redistribute=["static-to-rip"]; the same Keys[1]-only read exists for top-level `redistribute` (lines 599-602). FRR render iterates Redistribute per entry (pkg/frr/policy_render.go:926-928 resolveRedistribute) → only the first policy renders → direct routes are silently never advertised into RIP; commit gives no warning. Contrast: OSPF/BGP/OSPFv3/ISIS export in this same file were all converted to the firewallMatchValues SSOT with #2587/#2702 comments; the two RIP sites kept the pre-#2587 pattern. Additionally the flat-set path is under-modeled: the RIP schema (schema_routing.go:326-333) declares `group` with children:nil and no `export` leaf at all, so the truncation is reachable primarily through hierarchical file loads / peer config sync.

**Why it matters** — Same silent-config-narrowing failure the project classified as a bug class (#2419/#2587/#3703): the operator's committed routing policy is partially discarded, and RIP redistribution gaps surface as missing routes on downstream routers with nothing in logs.

**Fix direction** — Route both RIP sites through firewallMatchValues (matching the OSPF/BGP/ISIS pattern three cases above), add `export` (multi:true) to the RIP group schema subtree, and extend the #2587 regression test matrix with a RIP case.

**Not a duplicate** — #2587 (closed) explicitly lists OSPF/BGP/OSPFv3/IS-IS export/import + community members; #3703 (closed) swept remaining #2419 leaves in security host-inbound/log surfaces. Neither names the RIP export/redistribute leaves; grep for 'rip' in issues/prior-findings shows only a Rust service-name-table drift note. Residual of the #2419/#2587 class at a genuinely new site.

---

#### F-163 · routing-instance `interface [ a b ]` bracket list keeps only the first interface — remaining ports silently stay outside the VRF (isolation break)

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-config-routing-services`  ·  **Location:** `pkg/config/compiler_routing.go`:295
- **Labels:** `bug`, `vsrx-parity`, `test-gap`

```
		for _, prop := range child.Children {
			switch prop.Name() {
			case "description":
				ri.Description = nodeVal(prop)
			case "instance-type":
				ri.InstanceType = nodeVal(prop)
			case "interface":
				if v := nodeVal(prop); v != "" {
					ri.Interfaces = append(ri.Interfaces, v)
				}
```

**Runtime trace**

Valid Junos: `routing-instances { CUST-A { instance-type vrf; interface [ ge-0/0/1.0 ge-0/0/2.0 ]; } }`. Per the #2419 contract the bracket list collapses onto one leaf: prop.Keys=["interface","ge-0/0/1.0","ge-0/0/2.0"] in BOTH AST shapes (the routing-instances schema deliberately leaves `interface` an untyped leaf — schema_routing.go:547-548 comment — so nothing re-shapes it). nodeVal returns Keys[1] only → ri.Interfaces=["ge-0/0/1.0"]. Consumers then act on the truncated list: the daemon VRF membership walk (pkg/daemon/daemon_run.go:131 `for _, ifaceName := range ri.Interfaces`) and the VRF enslavement/FRR/table plumbing never move ge-0/0/2.0 into vrf-CUST-A → its connected subnet and traffic remain in the main routing table. Result: the second customer port routes via the global table — inter-VRF isolation the operator committed is silently not enforced, and overlapping customer prefixes collide in the main table. Repeated single-value `interface x;` lines still work (separate children), which hides the defect in most test configs.

**Why it matters** — VRF membership is a security boundary on a multi-tenant firewall; silently leaving a listed interface in the global table both leaks traffic across tenants and breaks per-VRF routing, with commit reporting success.

**Fix direction** — Read the interface leaf via firewallMatchValues (accumulating Keys[1:] and children) exactly as the export leaves do; add a bracket-list regression test for routing-instances interface (the generic bracket-corpus test gap already noted in prior findings).

**Not a duplicate** — Grepped 'routing-instance interface', 'vrf interface', 'multi-value', 'bracket': #2419 (parser class, closed), #3703 (security-surface leaves), #1904 (tunnel unit binding names) — none cover the routing-instances interface list; prior-findings item on bracket-corpus test gap is a test-infrastructure note, not this defect.

---

#### F-164 · appid catalog collapses ProtocolNumber's (0,true) vs (0,false): a committed `protocol 0` (HOPOPT) application fans out to TCP+UDP catalog entries — with no port constraint it stamps EVERY TCP/UDP session with the wrong app name

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-conntrack-appid`  ·  **Location:** `pkg/appid/catalog.go`:121
- **Labels:** `bug`, `appid`

```
		// Omitted protocol means "any L4"; compileApplications installs both
		// TCP and UDP entries (ICMP is excluded from that fan-out).
		protos := []uint8{proto}
		if proto == 0 && app.Protocol != "icmp" {
			protos = []uint8{6, 17}
		}
```

**Runtime trace**

1) Commit `set applications application my-hopopt protocol 0` (+ AppID enabled or a policy/NAT reference): strict validation ACCEPTS it — filterProtocolResolvable mirrors appid.ProtocolNumber, which deliberately resolves "0" to (0,true) for HOPOPT (#2124: 'callers that fail closed on unrepresentable protocols do not also reject a legitimate protocol 0'). 2) Apply -> buildAppCatalogSnapshot (pkg/dataplane/userspace/flow.go:148) -> appid.BuildCatalog -> catalogProtocolNumber (catalog.go:289-292) DISCARDS the ok flag: `n, _ := ProtocolNumber(name); return n` -> proto=0, indistinguishable from an omitted protocol. 3) catalog.go:119-122 fans proto==0 out to protos={6,17}; with no destination-port the two entries constrain NOTHING but protocol, so the Rust helper stamps this app_id on every TCP and UDP session it can claim (lowest-app-id-wins on overlap per the documented AppCatalog precedence), shadowing port-specific apps whenever the name sorts early. 4) `show security flow session` / RT_FLOW then label web/ssh/dns sessions as my-hopopt, while a genuine protocol-0 packet never gets stamped. 5) The policy ENFORCEMENT path is correct (capabilities.go keys the term under protocol 0 using the (0,true) distinction), so labeling and enforcement diverge for the same config. pkg/dataplane/compiler.go compileApplications (lines 566, 597-599) collapses identically, so both catalog producers agree with each other but not with the policy layer.

**Why it matters** — Session app labels feed RT_FLOW logs, session filtering (`show session application X`, clear-by-app) and NetFlow-adjacent reporting on a security appliance; a single exotic-but-valid app definition silently corrupts app attribution for the entire TCP/UDP session table.

**Fix direction** — Thread the ok flag through catalogProtocolNumber (and pkg/dataplane's protocolNumber): only an OMITTED/empty protocol should trigger the TCP+UDP fan-out; a resolved protocol 0 should emit a protocol-0 entry, and an unresolvable token should emit no entry (fail closed).

**Not a duplicate** — Searched issues/prior-findings for HOPOPT, 'protocol 0', fan-out, catalogProtocolNumber, 'tcp+udp'. Fresh #3725 covers the PORT parsers (uint16 wrap, +80, reversed ranges, bad source-port unconstrained) — different fields, different mechanism. Prior findings 408-424 cover ports/AppNames/overlap precedence; none touch the protocol-resolution collapse. #2124 (CLOSED) CREATED the (0,true) distinction this caller ignores.

---

#### F-165 · OnFenceReceived iterates the startClusterComms-captured config snapshot — redundancy groups added day-2 (without a transport change) are never fenced

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-daemon-ha`  ·  **Location:** `pkg/daemon/daemon_ha_sync.go`:721
- **Labels:** `bug`, `ha`

```
				if cfg.Chassis.Cluster != nil {
					slog.Warn("cluster: fence: disabling all RGs",
						"rg_count", len(cfg.Chassis.Cluster.RedundancyGroups))
					for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
						if err := d.dp.HA().SetRGActive(commsCtx, rg.ID, false); err != nil {
```

**Runtime trace**

1) Boot: startClusterComms captures cfg := d.store.ActiveConfig() (line 381) with redundancy-groups {0,1}; the OnFenceReceived closure (line 703) closes over that snapshot. 2) Day-2 the operator commits 'set chassis cluster redundancy-group 2' plus RETH interfaces for it — the comms-restart check (daemon_apply.go:1400-1412) compares only the six transport fields, so comms are NOT restarted and the closure keeps the stale snapshot. 3) This node's control plane wedges (heartbeats stop) while session sync stays up; the peer's heartbeat timeout fires and it sends a fence. 4) OnFenceReceived loops the captured {0,1} and calls SetRGActive(false) for those only — RG2's rg_active stays TRUE on the fenced node while the peer promotes itself for RG2 → both nodes forward RG2 traffic (dual-active ARP fights / duplicated flows), which is precisely the split-brain state fencing (#72) exists to prevent. The same stale snapshot also drives the 500ms HA-watchdog goroutine's RG list (line 423), though the helper's lease refresh in update_ha_state (max(now)+10s on every active update) neutralizes that copy's impact.

**Why it matters** — Fencing is the last-resort split-brain containment on a production HA pair; silently exempting any RG added after boot undermines the guarantee exactly for the newest (least-tested) traffic groups.

**Fix direction** — Re-read d.store.ActiveConfig() (or d.clusterConfig()) inside OnFenceReceived and iterate the current RedundancyGroups; alternatively fence by enumerating d.cluster.GroupStates().

**Not a duplicate** — Searched 'fence', 'OnFenceReceived', 'fencing', 'stale config capture' in the corpus. #72 [CLOSED] added the fencing path, #1792 [CLOSED] fixed its wall-clock trigger; no issue or prior finding covers the stale-closure RG-set defect. Distinct from prior finding [pkg/daemon/ha/watchdog.go] (fence trigger accuracy, not fence completeness).

---

#### F-166 · handleEventStreamFullResync hardcodes RG scan to 0..15 — sessions owned by RG >= 16 are never re-exported (Go-side sibling of #2466); primaries only on RGs >= 16 make FullResync permanently unackable

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-daemon-ha`  ·  **Location:** `pkg/daemon/daemon_ha_userspace.go`:662
- **Labels:** `bug`, `ha`

```
	var rgIDs []int
	for rgID := 0; rgID < 16; rgID++ {
		if d.cluster.IsLocalPrimary(rgID) {
			rgIDs = append(rgIDs, rgID)
		}
	}
	if len(rgIDs) == 0 {
		return false
	}
```

**Runtime trace**

Config: 'set chassis cluster redundancy-group 20 ...' — the schema's redundancy-group <group-id> slot has no upper-bound validator (schema_chassis.go:169, confirmed by #2466's own title: 'schema accepts them'), and interfaces bind RedundancyGroup=20. Runtime: this node is primary for RG20 and carries its sessions. The helper's event-stream replay buffer trims past the daemon's last ack (sync burst / daemon GC pause) → helper sends FullResync → handleEventStreamFullResync builds rgIDs by looping rgID 0..15 → IsLocalPrimary(20) is never consulted → RG20 omitted from ExportOwnerRGSessions → the peer's synced-session set silently misses every RG20 session; on the next failover those flows have no session on the new primary and are dropped instead of surviving. Worse shape: if this node is primary ONLY for RGs >= 16, len(rgIDs)==0 → return false → EventStream withholds the ack forever and the helper keeps re-requesting FullResync — a permanent resync stall.

**Why it matters** — #2466 fixed the RG>=16 class only in the Rust flow-cache epoch table (PR #2698, userspace-dp/src/afxdp/flow_cache.rs); this Go enumeration in the HA full-resync path has the same out-of-range blind spot, defeating session-sync recovery exactly when the replay buffer overflowed.

**Fix direction** — Derive the owned-RG set from d.cluster.GroupStates() (which enumerates configured groups) instead of a hardcoded 0..15 loop; alternatively add a commit-time upper-bound validator for redundancy-group IDs and make both sides share the constant.

**Not a duplicate** — Searched 'FullResync', 'full resync', 'rgID < 16', 'RG ID' in the corpus. #2466 [CLOSED] is the Rust flow-cache epoch-table sibling (fix verified confined to userspace-dp + docs via grep '2466'); no issue or prior finding covers the Go handleEventStreamFullResync enumeration. Reported as a residual of #2466 with a different mechanism (session re-export omission + unackable-resync stall vs delayed cache invalidation).

---

#### F-167 · monitorFabricState dies permanently and leaks the sibling netlink subscription when either update channel closes (e.g. ENOBUFS)

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-daemon-ha`  ·  **Location:** `pkg/daemon/daemon_ha_fabric.go`:825
- **Labels:** `bug`, `ha`, `resource-leak`, `test-gap`

```
		case update, ok := <-linkUpdates:
			if !ok {
				return
			}
		...
		case update, ok := <-neighUpdates:
			if !ok {
				return
			}
```

**Runtime trace**

vishvananda/netlink v1.3.1 linkSubscribeAt/neighSubscribeAt run 'defer close(ch)' and return on any s.Receive() error — with no SetReceiveBufferSize option here, a neighbor/link event burst that overruns the default socket buffer returns ENOBUFS and closes the channel. monitorFabricState then hits the '!ok { return }' branch (line 825 or 839) and returns WITHOUT closing the sibling done channel: (a) the other subscription's receive goroutine keeps running, fills its 64-slot channel that nobody drains, then blocks forever on send — leaked goroutine + leaked netlink socket for the daemon lifetime; (b) the fabric monitor is never restarted, so ALL event-driven fabric_fwd refresh (#124) is silently lost until a cluster-transport config change restarts comms — peer-MAC/link changes on fab0/fab1 are again only corrected by the 30s ticker, recreating up-to-30s fabric-redirect blackholes during failover windows.

**Why it matters** — On a busy L2 (the exact environment where neighbor churn causes ENOBUFS) the HA cross-chassis forwarding path silently loses its fast-correction mechanism with no log above Warn at subscribe time and no self-healing, and the daemon accumulates a wedged netlink socket.

**Fix direction** — On either channel closing, close both done channels and re-subscribe in a loop (bounded backoff), mirroring the resilience pattern used elsewhere; pass netlink.LinkSubscribeOptions/NeighSubscribeOptions with a larger ReceiveBufferSize and an ErrorCallback that logs the death.

**Not a duplicate** — Searched 'LinkSubscribe', 'NeighSubscribe', 'ENOBUFS', 'monitorFabricState', 'netlink subscribe' in the corpus. Only hit is #1658 [CLOSED] — the RUST netlink neighbor monitor's missing SO_RCVBUF — a sibling class in a different process/language; the Go fabric monitor's die-and-leak behavior is unreported.

---

#### F-168 · startClusterComms heartbeat retry goroutine ignores commsCtx — a stale retry can clobber a restarted heartbeat (StartHeartbeat replaces hbSender/hbReceiver without stopping the old pair)

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-daemon-ha`  ·  **Location:** `pkg/daemon/daemon_ha_sync.go`:445
- **Labels:** `bug`, `ha`, `concurrency`

```
	if cc.ControlInterface != "" && cc.PeerAddress != "" {
		go func() {
			for i := 0; i < 30; i++ {
				localIP := resolveClusterInterfaceAddr(cc.ControlInterface, cc.PeerAddress, "")
				if localIP == "" {
					...
					time.Sleep(2 * time.Second)
					continue
				}
				if err := d.cluster.StartHeartbeat(localIP, cc.PeerAddress, vrfDevice); err != nil {
```

**Runtime trace**

1) Boot: control interface em0 has no address yet (networkd race) → the heartbeat goroutine loops with bare time.Sleep(2s), up to 60s, with NO commsCtx check (contrast: the sync-start goroutine in the same function selects on commsCtx.Done at lines 497-500/765-769). 2) At t=10s the operator commits a peer-address change → daemon_apply.go:1411-1412 runs stopClusterComms() (cancels commsCtx — which this goroutine never observes) then startClusterComms() → a NEW retry goroutine starts and succeeds → cluster.StartHeartbeat installs the new-transport hbSender/hbReceiver. 3) At t=12s the OLD goroutine's next attempt also succeeds (em0 address is now up) → heartbeat_manager.go:18-60 blindly overwrites m.hbSender/m.hbReceiver/m.hbLocalAddr/m.hbPeerAddr with sockets bound to the OLD local IP and OLD peer address, without stopping the new pair. Result: the manager's referenced heartbeat now targets the stale peer (heartbeats to a dead address → false peer-timeout → fence/failover of a healthy peer), the new-transport sender/receiver goroutines and sockets leak un-stoppable (the next StopHeartbeat stops only the referenced stale pair), and #1792's SendLivenessKeepalive/restart-notify paths read the overwritten stale hbPeerAddr.

**Why it matters** — Heartbeat is the split-brain arbiter; a transport-change commit during the (common) startup networkd race can silently point the referenced heartbeat at the wrong peer and leak duplicate senders across restarts on a production HA pair.

**Fix direction** — Thread commsCtx into the heartbeat retry loop (select on commsCtx.Done() instead of time.Sleep, and abort before calling StartHeartbeat if ctx is done); additionally make StartHeartbeat stop/refuse-to-replace an already-running sender/receiver pair.

**Not a duplicate** — Searched 'StartHeartbeat', 'heartbeat restart', 'heartbeat retry', 'heartbeat bind', 'hbSender', 'startClusterComms', 'comms restart' in issues-all.txt and prior-findings.md — no hits. #87 added the comms restart; #1792 covered wall-clock suppression during heartbeat restart, not this stale-goroutine clobber. Nearest: prior finding [pkg/daemon/ha/watchdog.go] heartbeat false positive under CPU congestion — different mechanism.

---

#### F-169 · A non-fatal tail apply error (host-inbound / lo0 / networkd / dhcp-server) silently skips the HA peer config push, leaving the standby on stale config with no alarm

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-daemon-lifecycle`  ·  **Location:** `pkg/daemon/daemon_apply.go`:213
- **Labels:** `bug`, `ha`

```
	if err := d.applyConfigLocked(d.applyCancelCtx(), compiled); err != nil {
		return nil, err
	}
	if syncPeer {
		d.syncConfigToPeer()
	}
	return compiled, nil
```

**Runtime trace**

commitAndApply/commitConfirmedAndApply: store.Commit promotes+persists the compiled config LOCALLY, then applyConfigLocked runs every reconcile step and returns errors.Join(networkdErr, dhcpServerErr, hostInboundErr, lo0Err) (daemon_apply.go:1470). If ANY of those tail errors is non-nil (e.g. a transient nft failure when programming host-inbound), applyConfigLocked returns non-nil, so commitAndApply hits `return nil, err` at line 211 and NEVER reaches `if syncPeer { d.syncConfigToPeer() }`. The active node's store is already promoted and the dataplane has run every step, but the standby is never sent the new config text. There is no HA-divergence alarm on this path. Divergence persists until the next fully-clean commit.

**Why it matters** — The tail errors were made fail-closed (#2987/#3333/#3392) so the OPERATOR sees a failed commit — but the config is still committed+applied locally. Skipping the peer push on that same error means an HA pair silently diverges on a transient kernel-nft hiccup: the active runs new policy, the standby runs old policy, and a failover swaps to the stale ruleset. The operator's `commit` error does not tell them the peer is now out of sync.

**Fix direction** — Decouple peer sync from the tail-error return: on a non-abort tail error the store is already promoted and the steps ran, so push to the peer anyway (both nodes converge) OR raise an explicit HA config-divergence alarm/metric. Only the compileErrorMustAbortApply (disarmed dataplane) case should suppress the push.

**Not a duplicate** — #2987/#3333/#3392 (CLOSED) added the fail-closed tail errors.Join at HEAD; those issues are about local commit-result reporting, not HA propagation. No prior finding covers the syncConfigToPeer being skipped as a side effect. Distinct mechanism.

---

#### F-170 · proxyARPReassertLoop runs reconcileProxyARP without applySem — races the commit-path reconcile and can re-install just-removed proxy-ARP responders for up to 30s

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-daemon-net`  ·  **Location:** `pkg/daemon/daemon_proxyarp.go`:205
- **Labels:** `bug`, `race`

```
func (d *Daemon) proxyARPReassertLoop(ctx context.Context) {
	t := time.NewTicker(proxyARPReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if cfg := d.store.ActiveConfig(); cfg != nil {
				proxyARPReconcileFn(d, cfg)
			}
```

**Runtime trace**

(1) The 30s ticker fires and reads cfg_old = d.store.ActiveConfig(); reconcileProxyARP(cfg_old) begins its netlink NTF_PROXY diff + sysctl writes (dataplane.ReconcileProxyARP). (2) Concurrently an operator commit swaps the active config to cfg_new (proxy-arp entry removed or moved) and applyConfigLocked — which DOES hold applySem — runs d.reconcileProxyARP(cfg_new) at daemon_apply.go:1027: it computes stale=diffProxyResponders(prev, {}) and calls proxyARPDisableFn to drive proxy_arp/proxy_ndp back to 0 and delete the NTF_PROXY entries. (3) The still-running loop pass (cfg_old) now re-adds the deleted NTF_PROXY entries, re-enables the per-interface proxy_arp sysctl, and re-fires GARP for the removed address; whichever pass takes proxyARPEnabledMu last overwrites d.proxyARPEnabled (the mutex protects the map, not the kernel-state interleave — the code comment claims the mutex means the two paths 'cannot race the remembered state', which is only true for the map value). (4) The firewall answers ARP for an address the operator just un-proxied — over-answering that steals traffic from the address's legitimate owner — until the next tick (≤30s) re-runs with cfg_new and tears it down again. Contrast: the equivalent periodic entry point reconcileDNSFromDHCP (daemon_dns.go:339-347) correctly acquires applySem before touching shared state.

**Why it matters** — Proxy-ARP over-answering is a traffic-stealing hazard on shared L2 segments: for up to one reassert period after a commit that removes/moves a proxied NAT address, the firewall keeps claiming the address (and just GARPed for it), blackholing the rightful owner. The daemon's own convention (DNS DHCP-callback path) is that periodic reconciles serialize on applySem; this loop skips it.

**Fix direction** — Acquire d.applySem (context-bounded) around the loop's proxyARPReconcileFn call, mirroring reconcileDNSFromDHCP — the reconcile is cheap and 30s-cadence so contention is nil; alternatively re-read ActiveConfig under the sem so the pass can never run with a stale config.

**Not a duplicate** — Searched issues for 'proxy-arp/proxyARP/reassert': #2197 (OPEN) is the issue whose item 2 CREATED this loop (its remaining opens are v6 pneigh install + per-address narrowing); #2475 (teardown leak), #3010 (VLAN ifindex), #2160 (sysctl left 0), #2519 (fsatomic canary) all closed and reflected at HEAD. None covers the loop-vs-apply serialization race; prior-findings.md has no daemon_proxyarp.go entries.

---

#### F-171 · monitorLinkState exits permanently and silently when the netlink subscription closes (ENOBUFS overrun) — no resubscribe, unlike the neighbor listener

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-daemon-svc`  ·  **Location:** `pkg/daemon/daemon_flow.go`:343
- **Labels:** `bug`, `vsrx-parity`

```
	updates := make(chan netlink.LinkUpdate, 64)
	done := make(chan struct{})
	if err := netlink.LinkSubscribe(updates, done); err != nil {
...
		case update, ok := <-updates:
			if !ok {
				return
			}
```

**Runtime trace**

Under a link-event burst (boot-time rename storm, RETH failover flaps, VLAN churn) the kernel netlink socket overruns: vendored netlink v1.3.1 linkSubscribeAt's receive goroutine gets ENOBUFS from s.Receive(), returns, and `defer close(ch)` closes the updates channel (link_linux.go:2529-2539). monitorLinkState (daemon_flow.go:342-345) reads ok==false and returns — no log line, no resubscribe, no error callback registered (plain LinkSubscribe passes cberr=nil and default rcvbuf; the 64-slot consumer channel back-pressures the receive goroutine, making overrun more likely). From that moment the box sends no linkUp/linkDown traps for the rest of the daemon lifetime while `show`/journal give zero signal. The correct in-repo pattern exists 30 lines away in spirit: daemon_neighbor_listener.go:96-165 wraps NeighSubscribeWithOptions in a resubscribe loop with ReceiveBufferSize 1MB, an ErrorCallback, and a 2s retry.

**Why it matters** — Link traps exist to tell the NOC an interface died; the monitor itself dying silently during exactly the kind of event storm that accompanies real failures is the worst possible failure mode for a monitoring path on an HA firewall.

**Fix direction** — Restructure monitorLinkState like neighborListener: outer resubscribe loop, LinkSubscribeWithOptions with ErrorCallback (WARN log) + ReceiveBufferSize, re-seed prevOper after each resubscribe (emitting traps for state deltas across the gap), and log subscription loss.

**Not a duplicate** — Searched issues 'LinkSubscribe', 'link state', 'snmp': #2991 (CLOSED) is the same function but a different mechanism — synchronous trap DELIVERY stalling the loop, fixed via enqueueTrap (verified at HEAD, traps.go:163-175); channel-close/no-resubscribe death is untouched by that fix and unfiled. prior-findings.md has no monitorLinkState entries.

---

#### F-172 · DHCP relay never re-resolves giaddr: an interface address change (renumber commit / DHCP renew, ifindex unchanged) silently breaks the reply path

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-dhcp`  ·  **Location:** `pkg/dhcprelay/relay.go`:1031
- **Labels:** `bug`, `vsrx-parity`

```
			// Set giaddr to our interface IP so the server knows where to reply.
			pkt.GatewayIPAddr = giaddr
...
	giaddr, ok := m.resolveGIAddrWithRetry(sctx, ifaceName)
...
	serverConn, err := m.newConn(sctx, "", true, false,
		&net.UDPAddr{IP: giaddr, Port: relayPort})
```

**Runtime trace**

1) Operator configures dhcp-relay on ge-0-0-1 (IPv4 10.0.1.1). runRelaySession() resolves giaddr=10.0.1.1 (relay.go:781), binds serverConn to 10.0.1.1:67 (relay.go:849-850), and relays every client request with pkt.GatewayIPAddr=10.0.1.1 (relay.go:1031). 2) The interface is renumbered to 10.0.1.2 — either an operator `set interfaces ge-0-0-1 unit 0 family inet address 10.0.1.2/24` commit, or a DHCP lease change on that interface. The kernel removes 10.0.1.1 but the ifindex is unchanged (no device recreate). 3) daemon reconcileDHCPRelay -> Manager.Apply diffs only relaySpec (servers + always-broadcast); the address is not part of the spec, so the running relay is NOT restarted. 4) The #2347 drift watcher only compares ifindex (relay.go:921-957); ifindex is unchanged, so it reports no drift and never rebinds. 5) serverConn stays bound to the now-removed 10.0.1.1:67 and every relayed request still carries giaddr=10.0.1.1. The upstream server unicasts OFFER/ACK to 10.0.1.1:67 (RFC 2131 §4.1) — no local socket owns 10.0.1.1 — so the kernel drops the reply. All relayed clients on that segment fail to obtain leases until an ifindex-drift event or an xpfd restart.

**Why it matters** — A day-2 address change on the relay's client-facing interface produces a silent, indefinite DHCP-relay outage on a production firewall. The failure is invisible (no error, RepliesForwarded simply stops) and persists across commits because Apply's spec diff never re-binds the server socket. vSRX rebinds relay state to the current interface address.

**Fix direction** — Capture the resolved giaddr in the session and add an address-drift watcher alongside the ifindex watcher (re-run resolveGIAddr on the same 5s cadence); on a changed giaddr, tear down and rebuild the session (rebind serverConn to the new giaddr:67). Alternatively include the resolved giaddr in relaySpec so Apply restarts the relay when the interface address changes.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for dhcp/relay/giaddr/ifindex/drift. Nearest: #2347 (listener goes deaf on ifindex drift — fixed, HEAD has the ifindex watcher) covers device delete/recreate only; #2849 (primary-vs-secondary giaddr selection) and #2888 (server conn binds giaddr:67 vs ephemeral) both assume a FIXED giaddr; #2884 (IPsec local_addrs re-bind on DHCP change) is a different subsystem. None handle a giaddr address change with unchanged ifindex, and the README §ifindex-drift explicitly documents only ifindex, not address, re-resolution.

---

#### F-173 · DHCPv4 client treats a RENEWING DHCPNAK identically to a timeout: keeps the revoked address and waits for T2 instead of immediate re-acquire (RFC 2131 §4.4.5)

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-dhcp`  ·  **Location:** `pkg/dhcp/dhcp.go`:764
- **Labels:** `bug`, `vsrx-parity`

```
			slog.Warn("DHCPv4: T1 renewal failed, waiting for T2",
				"interface", ifaceName, "err", rerr)

			// Wait for T2 (87.5% of lease) — remaining time after T1
			select {
			case <-m.after(t2Remaining):
			case <-ctx.Done():
```

**Runtime trace**

1) Interface holds a committed 600s lease; committed address applied to the NIC. 2) At T1 (300s) runDHCPv4 calls v4Exchange(exchangeRenew); the granting server has lost/rejected the binding (server reload, renumber, or lease taken) and returns a DHCPNAK. 3) doDHCPv4 detects the NAK and returns a plain error `DHCPv4 renew: server sent NAK` (dhcp.go:841-842) — indistinguishable from a socket timeout. 4) runDHCPv4's renew branch (dhcp.go:751-765) takes rerr != nil and falls through to `waiting for T2`, sleeping ~t2Remaining (~225s) while the NAK'd address STAYS applied to the interface. 5) Only after T2 also fails does it break to a fresh DORA. Per RFC 2131 §4.4.5 a client in RENEWING that receives a DHCPNAK MUST immediately transition to INIT: stop using the address and restart discovery. Here the firewall keeps a server-revoked WAN/LAN address in service for up to (T2−T1) ≈ 37.5% of the lease.

**Why it matters** — Holding a revoked address after an explicit NAK causes a black-hole/duplicate-IP window on a firewall interface and delays recovery during a server-side renumber or lease-steal by tens of seconds to minutes. vSRX drops the address and re-DISCOVERs on NAK.

**Fix direction** — Make doDHCPv4 return a distinguishable sentinel (e.g. errDHCPNak) for the NAK case; in runDHCPv4 on a NAK during renew/rebind, remove the committed address, delete the lease, and break to a fresh DORA immediately rather than waiting for T2.

**Not a duplicate** — Searched for dhcp renew/NAK/rebind. #2994 (T1/T2 ran full DORA instead of unicast RENEW — CLOSED/fixed) changed the exchange TYPE but not the failure classification; #2606/#2600 (relay drops DHCPNAK) is the RELAY path, not the client run loop. No prior finding covers the client's NAK-vs-timeout conflation in the RENEWING state machine.

---

#### F-174 · next-table kernel mirror scope divergence: per-instance next-table static routes are never programmed as ip rules (kernel path loses the leak), while global next-table rules at pref 100 fire before the l3mdev VRF rule (pref 1000) and hijack VRF-ingress kernel traffic

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-frr-routing`  ·  **Location:** `pkg/routing/rules.go`:53
- **Labels:** `bug`, `vsrx-parity`, `security`, `routing`

```
// nextTableRulePriority is the base priority for next-table ip rules.
// Lower values = higher priority. We use 100-199 range for next-table rules.
const nextTableRulePriority = 100
...
func (n *nextTableManager) Apply(routes []*config.StaticRoute, instances []*config.RoutingInstanceConfig) error {
...
		rule := netlink.NewRule()
		rule.Dst = dst
		rule.Table = tableID
		rule.Priority = prio
```

**Runtime trace**

Leg A (under-scope): `set routing-instances blue routing-options static route 10.9.0.0/16 next-table red.inet.0`. compileStaticRoutes (pkg/config/compiler_routing.go:238) sets route.NextTable for the INSTANCE route; FRR render drops it (config_render.go:100 `if sr.NextTable != "" { return "" }`); daemon_apply.go:1082-1086 builds allRoutes from cfg.RoutingOptions.StaticRoutes + Inet6StaticRoutes ONLY — instance routes never reach ApplyNextTableRules, so no ip rule exists. The userspace snapshot DOES emit it (pkg/dataplane/userspace/routes.go:44 files NextTable under blue.inet.0), so AF_XDP-forwarded flows leak while kernel slow-path/host-originated flows in VRF blue follow blue's table only -> kernel/userspace FIB split-brain for the same destination. Leg B (over-scope): a GLOBAL next-table route creates `ip rule to 10.9.0.0/16 lookup <red> pref 100`. A kernel-path packet arriving on a VRF-blue-enslaved interface walks fib rules in priority order: pref 100 matches Dst BEFORE the l3mdev rule at pref 1000 ever directs it to blue's table -> traffic that Junos would resolve inside routing-instance blue is steered into red's table. The userspace FIB files the same route under inet.0 only (table-scoped), so again the two dataplanes disagree — and the kernel leg is a VRF-isolation bypass for the matched prefix.

**Why it matters** — next-table is the documented inter-VRF leak primitive. Leg A silently halves the feature (kernel-forwarded and host traffic ignore it); Leg B breaks routing-instance isolation on the kernel path — a security-relevant divergence in a firewall whose zones/instances are isolation boundaries.

**Fix direction** — Pass per-instance static routes into ApplyNextTableRules and program instance-scoped leaks (rules need a source constraint — e.g. iif of the instance's interfaces, or fwmark set by the VRF context; alternatively install real per-prefix routes into the instance table via RouteAdd with the target table's resolved next-hops). For global routes, place the rule band AFTER the l3mdev rule (pref >1000) or add an explicit suppress/iif predicate so VRF-ingress traffic is not captured.

**Not a duplicate** — Searched 'next-table' in both corpora: #3731 (OPEN) = RuleAdd error swallow only; prior findings 594/595 = Rust-side recursive next_table family/loop handling; prior finding 587 = IPv6 family canonicalization of the leak loop; prior finding 427 = PBR (firewall-filter) rules not iif-scoped — same class of missing-context predicate but a different feature and mechanism (FBF attachment context vs next-table instance/table context + l3mdev priority ordering). No prior item covers instance next-table routes never reaching the ip-rule applier or the pref-100-before-l3mdev hijack.

---

#### F-175 · Deleting an IPsec VPN never terminates its established SAs — `swanctl --load-all` only unloads config, so the removed tunnel keeps forwarding until hard lifetime/reauth (vSRX clears SAs at commit)

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-ipsec-wg`  ·  **Location:** `pkg/ipsec/manager.go`:110
- **Labels:** `bug`, `vsrx-parity`, `security`

```
func (m *Manager) reload() error {
	output, err := runSwanctl("--load-all")
	if err != nil {
		return fmt.Errorf("swanctl --load-all: %w: %s", err, string(output))
	}
	slog.Info("swanctl config reloaded")
	return nil
}
```

**Runtime trace**

Operator runs `delete security ipsec vpn branch-2` + commit to cut off a decommissioned/compromised peer -> daemon apply -> ipsec.Apply renders xpf.conf without branch-2 -> reload() runs `swanctl --load-all` -> swanctl unloads the missing connection definition (binary confirms 'loaded %u of %u connections, %u failed to load, %u unloaded') -> charon's unload-conn removes only the peer config; the established IKE_SA and CHILD_SAs (which hold their own config references) stay up, kernel XFRM states/policies remain installed -> encrypted traffic to/from branch-2 continues to flow and be accepted for hours until the SA hard lifetime or IKE reauth fails. On vSRX, deleting/deactivating the VPN tears the SAs down at commit. Additionally Clear() (manager.go:106) discards the reload error entirely (`_ = m.reload()`), so deleting the last VPN can report a clean commit while charon still has every connection and secret loaded.

**Why it matters** — Config removal is a security control: an operator deleting a VPN expects the peer cut off at commit, not at SA expiry. A security appliance that keeps forwarding for a deleted tunnel silently violates the committed policy, and the swallowed Clear() error hides even total reload failure.

**Fix direction** — After a successful reload, terminate SAs for connections no longer rendered: diff ActiveConnectionNames() against the rendered VPN set and run `swanctl --terminate --ike <name> --force` for the removed ones (TerminateAllSAs already contains the machinery); propagate the reload error from Clear().

**Not a duplicate** — Searched issues-all.txt for terminate/unload/stale SA/removed vpn: #2385/#3616 (dataplane passthrough), #2546 (XFRM interface rebuild — opposite problem, too-eager teardown of xfrmi devices in pkg/routing), #2884 (stale local bind). No issue or prior finding covers SA lifetime outliving config removal via swanctl unload semantics.

---

#### F-176 · Rendered swanctl secrets carry no `id` selectors — with two or more PSK VPNs charon has no way to pick the right PSK per peer, breaking one tunnel's authentication

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-ipsec-wg`  ·  **Location:** `pkg/ipsec/policy.go`:233
- **Labels:** `bug`, `vsrx-parity`

```
		if secret != "" {
			decoded, err := normalizePSK(secret)
			if err != nil {
				return "", fmt.Errorf("vpn %s: %w", name, err)
			}
			fmt.Fprintf(&b, "  ike-%s {\n", sanitizeSwanctlValue(name))
			fmt.Fprintf(&b, "    secret = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(decoded)))
			fmt.Fprintf(&b, "  }\n")
		}
```

**Runtime trace**

Config: vpn-a (gateway 203.0.113.1, ike-policy PSK "alpha") and vpn-b (gateway 198.51.100.2, PSK "bravo") -> renderConfig secrets loop emits `secrets { ike-vpn-a { secret = "alpha" } ike-vpn-b { secret = "bravo" } }` with no `id =` selectors (the `ike-<name>` section suffix is arbitrary and NOT matched to the connection). In strongSwan, IKE secrets are selected from a global pool by the identities configured as `id-*` selectors; a secret with no ids matches ANY peer. Peer 198.51.100.2 initiates -> charon's psk authenticator asks the credential manager for ONE shared key for (my_id, peer_id) -> both entries tie at match-any and an arbitrary one is returned -> if "alpha" wins, AUTH verification of vpn-b fails -> AUTHENTICATION_FAILED, tunnel down (persistently, since selection is deterministic per pool order). Same ambiguity as initiator. The gateway's remote address / RemoteIDValue are available at render time and are simply not emitted.

**Why it matters** — Junos scopes each pre-shared-key to its ike policy/gateway; xpf flattens them into an ambiguous global pool, so any deployment with two or more distinct PSKs — the normal multi-site case for a firewall — has at least one tunnel that cannot authenticate, with a misleading AUTHENTICATION_FAILED symptom pointing at the peer.

**Fix direction** — Emit id selectors in each secret block from the resolved gateway: `id-1 = <remoteAddr or formatIdentity(RemoteIDType, RemoteIDValue)>` (plus the local identity when set); fall back to no-id only for the single-VPN case.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for PSK/secrets/id selector/wrong key: #2126 (quote escaping), #2074 (orphan secrets for skipped VPNs), #157 ($9$ decode), #2053 (marshal redaction) — all different mechanisms in the same block; none address missing identity selectors / multi-peer PSK ambiguity.

---

#### F-177 · LLDP neighbor table is unbounded and keyed on attacker-controlled Chassis/Port IDs — L2 frame flood causes memory exhaustion

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-networkd-mon`  ·  **Location:** `pkg/lldp/lldp.go`:496
- **Labels:** `security`, `performance`, `bug`

```
		key := fmt.Sprintf("%s/%s/%s", iface.Name, neighbor.ChassisID, neighbor.PortID)
		m.mu.Lock()
		m.neighbors[key] = neighbor
		m.mu.Unlock()
```

**Runtime trace**

rxLoop parses each inbound frame with ParseTLVs. ChassisID (string subtype) is taken as string(value[1:]) up to 511 bytes and PortID up to 511 bytes (lldp.go:681,688) — both fully attacker-controlled. The map key concatenates them, and TTL is read straight from the frame's TTL TLV (lldp.go:697) up to 65535s. An attacker with L2 adjacency on an LLDP-enabled port emits frames with unique Chassis/Port IDs and max TTL at line rate; each creates a new map entry (~1KB of strings) that expiryLoop (10s tick) will not reap for up to 18 hours. There is no per-interface neighbor cap and no total cap, so m.neighbors grows unboundedly — control-plane OOM. Neighbors() also allocates a full copy of the map on every `show lldp neighbors`.

**Why it matters** — The module handles untrusted L2 input (explicitly flagged). lldpd/vSRX cap neighbors per port; xpf does not, so one malicious or misbehaving neighbor on a monitored segment can exhaust daemon memory and kill the whole firewall control plane.

**Fix direction** — Cap neighbors per interface (e.g. lldpd's default of a few hundred) and/or total; on overflow drop new learns and bump a counter. Optionally clamp accepted TTL to a sane maximum (Junos hold-time is interval*multiplier, bounded).

**Not a duplicate** — Unbounded-state DoS issues #2128 (screen session-limit tracker) and #2209 (screen scan/sweep) are a different module; #2551/#2036 cover LLDP TLV truncation/overlength, not neighbor-table cardinality. No prior finding on LLDP neighbor count. Novel.

---

#### F-178 · Untrusted LLDP TLV strings (SystemName/SystemDesc/PortDesc/ChassisID/PortID) rendered to operator terminal and gRPC without control-char sanitization — ANSI/terminal + log injection

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-networkd-mon`  ·  **Location:** `pkg/lldp/lldp.go`:701
- **Labels:** `security`, `bug`

```
		case tlvSystemName:
			n.SystemName = string(value)
		case tlvSystemDesc:
			n.SystemDesc = string(value)
		case tlvPortDesc:
			n.PortDesc = string(value)
```

**Runtime trace**

ParseTLVs stores raw bytes from the frame into n.SystemName/SystemDesc/PortDesc/ChassisID/PortID with no filtering (each up to 511 bytes). showLLDPNeighbors renders them verbatim: cli_show_services.go:745-747 `fmt.Printf("%-12s %-20s %-16s %-20s ...", n.Interface, n.ChassisID, n.PortID, n.SystemName, ...)` and identically in grpcapi/server_show_dhcp_lldp_snmp.go:443. An attacker on an LLDP-enabled segment sends a frame whose SystemName contains ANSI escape sequences (e.g. cursor-move, screen-clear, or \r overwrite) or embedded newlines; when an operator runs `show lldp neighbors` in a terminal (or the output is piped to a log), the escape sequences execute — spoofed table rows, hidden text, or scrollback manipulation. The #1798 sanitizer only covers config values written into networkd units, not RX-side LLDP strings reaching the terminal.

**Why it matters** — Untrusted L2 input reaches a human-facing sink with no escaping. Terminal-escape injection can hide/forge neighbor entries and is a known operator-deception vector; the project already treats this class seriously (#1798 render-side belt) but only on the config->file path.

**Fix direction** — Strip C0 controls/DEL (reuse networkd.sanitizeUnitValue's approach) when storing LLDP TLV strings in ParseTLVs, or sanitize at every render sink. Also bound stored string lengths.

**Not a duplicate** — #1798 (CLOSED) is control-char injection into generated networkd .network units from CONFIG values — different source (config vs untrusted L2 frame) and different sink (systemd unit file vs operator terminal/gRPC). No LLDP-RX-to-terminal sanitization finding exists. Novel.

---

#### F-179 · Feed fetch has no total body-size/prefix-count cap → a large or compromised feed body drives unbounded control-plane memory growth (OOM)

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-obs`  ·  **Location:** `pkg/feeds/feeds.go`:414
- **Labels:** `security`, `dos`, `bug`

```
return parseFeed(resp.Body)
// ...
scanner := bufio.NewScanner(r)
scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
for scanner.Scan() {
```

**Runtime trace**

Config: `security dynamic-address feed-server X url http(s)://host/feed`. refreshLoop → fetchFeed → readFeed does client.Do (m.client has only Timeout: 30s, no body cap) and passes resp.Body straight to parseFeed (feeds.go:419). parseFeed wraps it in bufio.Scanner with a 1 MiB PER-LINE cap but NO cap on the number of lines or total bytes; every valid CIDR/IP line is appended to `prefixes []string`. A malicious/compromised/misconfigured feed endpoint (or a MITM on a plaintext feed) streams gigabytes of well-formed one-per-line prefixes: within the 30s window (~3.75 GB at 1 Gbps) `prefixes`, then the deduped `canon` slice and the sha256, grow until the daemon OOMs. There is no io.LimitReader, no Content-Length ceiling, and no maximum element count.

**Why it matters** — The feeds manager runs in the firewall control plane; an attacker who controls or can tamper with the feed source (plaintext http, or a breached feed host) can OOM-kill xpfd — a control-plane denial of service that also takes down the dataplane supervisor. Bounding feed size is standard hardening (Junos/most feed clients cap entries).

**Fix direction** — Wrap resp.Body in an io.LimitReader with a configured/default max (e.g. 32–64 MiB) and cap the installed prefix count; treat exceeding the cap as a failed fetch (retain last-good) rather than a partial install, mirroring the overlong-line ErrTooLong handling already present.

**Not a duplicate** — Searched issues-all.txt for feed/size/cap/unbounded/OOM. #2993 (mixed valid+invalid lines → degraded status), #2050 (retain-last-good), #631/prior-finding (nftables compileAddressSet netlink-buffer chunking on the CONSUMER side). None bound the feeds.Manager parse-time allocation; MODULE NOTES explicitly flag 'feeds fetcher size caps' as an open hunt. Distinct from #631 (that is nftables inline transaction size, not manager memory).

---

#### F-180 · SNMP GETBULK invokes the live ifData callback (netlink.LinkList) twice per generated varbind → per-request netlink dump storm

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-obs`  ·  **Location:** `pkg/snmp/agent.go`:691
- **Labels:** `performance`, `dos`, `refactor`

```
for j := 0; j < maxRepetitions; j++ {
    nextOID := a.findNextOID(currentOID)
    ...
    val, valTag := a.getOIDValue(nextOID)
    varbinds = append(varbinds, varbind{oid: nextOID, tag: valTag, value: val})
    currentOID = nextOID
}
```

**Runtime trace**

A monitoring poller sends a single GETBULK walk of ifTable/ifXTable with maxRepetitions up to the 100 cap. handleGetBulk repeaters loop (agent.go:689) runs up to 100 iterations; each iteration calls findNextOID (agent.go:881, one a.getIfData()) AND getOIDValue → getIfTableValue/getIfXTableValue (one a.getIfData()). getIfData is the daemon callback that runs netlink.LinkList() — a full RTM_GETLINK dump of every interface with no caching or per-request memoization (daemon_run.go:1013). So one GETBULK request triggers ~2×varbinds ≈ up to 200 full interface-table netlink dumps, each allocating a fresh []IfData. A routine SNMP walk therefore storms rtnetlink and burns control-plane CPU proportional to (repetitions × interface_count).

**Why it matters** — On a box with many interfaces (VRFs, tunnels, XFRM, veths), a single ordinary SNMP poll — or a deliberately large GETBULK from a valid community — imposes hundreds of full netlink dumps per request, contending with the daemon's own netlink work (link/route reconcile, neighbor resolution) and inflating poll latency; it is a cheap amplification vector for a read-only community.

**Fix direction** — Snapshot getIfData() once per handled packet (memoize on the request) and pass the slice into findNextOID/getOIDValue, or cache LinkList with a short TTL as the Prometheus collector fix (#669) proposes. A sorted map[ifIndex]*IfData built once also removes the O(cols×ifaces) per-varbind scan.

**Not a duplicate** — Searched prior-findings for LinkList/netlink/cache. #669 (Prometheus Exporter.Collect calls netlink.LinkList per scrape, no caching) is the same ROOT (uncached LinkList) but a different call site and a worse multiplier (per-varbind WITHIN one request, ×2, ×maxRepetitions). Reporting as a distinct SNMP-agent instance and explicitly naming #669 as the related mechanism.

---

#### F-181 · pool-utilization-alarm hard-rejects a raise-threshold-only config that is legal on vSRX (clear-threshold is optional in Junos)

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-ops`  ·  **Location:** `pkg/config/compiler_nat.go`:33
- **Labels:** `vsrx-parity`, `config`

```
	var msg string
	switch {
	case a.RaiseThreshold <= 0 || a.RaiseThreshold > 100:
		msg = fmt.Sprintf("pool-utilization-alarm: raise-threshold must be in 1..100, got %d", a.RaiseThreshold)
	case a.ClearThreshold <= 0 || a.ClearThreshold >= a.RaiseThreshold:
		msg = fmt.Sprintf("pool-utilization-alarm: clear-threshold must be in 1..raise-threshold-1 (0 < clear < raise), got clear=%d raise=%d", a.ClearThreshold, a.RaiseThreshold)
```

**Runtime trace**

Operator ports a working vSRX config containing only `set security nat source pool-utilization-alarm raise-threshold 90` (clear-threshold is an OPTIONAL leaf in Junos; when unset the alarm clears when utilization drops back below the raise threshold). xpf parse leaves ClearThreshold=0 (compiler_nat.go:1201-1206 only sets it when the leaf is present) -> commit runs validatePoolUtilizationAlarm strict -> case `a.ClearThreshold <= 0` matches -> commit is REJECTED with 'clear-threshold must be in 1..raise-threshold-1'. On the lenient load path (boot / peer config-sync of a pre-gate config) the same stanza degrades to a warning and the runtime monitor treats it as DISABLED (natpoolalarm.go:229-235) — reintroducing exactly the silent no-op alarm #2079 was opened to eliminate, for a config that alarms correctly on real vSRX. Junos also constrains raise to 50..100 and clear to 40..100; xpf accepts 1..100 (leniency, lesser issue).

**Why it matters** — This is a native-Junos-syntax clone; a config stanza that commits and alarms on vSRX must not be refused at commit (or silently disabled at load). NAT pool exhaustion is precisely the failure mode this alarm exists to warn about — an operator who configured raise-only believes they have coverage and has none.

**Fix direction** — When clear-threshold is unset, default it Junos-style instead of rejecting: treat clear==raise ('clears when utilization falls below raise-threshold', strict less-than) or synthesize the documented Junos default at compile time; keep rejecting only an explicitly inverted clear >= raise. Mirror the same defaulting in Monitor.evaluate's disable gate (natpoolalarm.go:229-231) and update pkg/natpoolalarm/README.md + docs/config-schema.md.

**Not a duplicate** — Searched issues-all.txt for raise-threshold/clear-threshold/pool-utilization — only #2079 (CLOSED, 'no consumer', which ADDED this strict gate) and #2114 (CLOSED, d.dp race). prior-findings.md has no pool-alarm threshold-semantics finding. The strict 0<clear<raise gate was a deliberate #2079 review outcome but the raise-only-is-valid-Junos parity angle was never raised; confidence medium because the exact Junos default-clear behavior is cited from documentation memory.

---

#### F-182 · Control-socket RPC deadline is a fixed 3s while #2744 raised the apply_snapshot body cap to 64MB — large feed-backed snapshots time out mid-apply, diverging desired vs applied state

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-usdp-core`  ·  **Location:** `pkg/dataplane/userspace/process.go`:243
- **Labels:** `bug`, `performance`, `vsrx-parity`

```
conn, err := net.DialTimeout("unix", m.cfg.ControlSocket, 2*time.Second)
	if err != nil {
		return ControlResponse{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	// Reuse the pre-flight-serialized body; the Rust receiver frames on a
	// single trailing newline (json.Encoder appends one).
	if _, err := conn.Write(append(body, '\n')); err != nil {
```

**Runtime trace**

Operator commits a config with a large dynamic-address feed (e.g. ~500K-1.4M CIDRs) -> buildSnapshot serializes an apply_snapshot body of tens of MB up to the MaxControlRequestBytes=64MB pre-flight ceiling (process.go:213). Compile() -> requestLocked -> requestDetailedLocked: pre-flight marshal passes (<64MB), conn.SetDeadline(now+3s) covers ALL subsequent I/O. conn.Write pushes the body (wmem tuned to 64MB so it buffers fast). The Rust side handle_stream (server/handlers/mod.rs:51) gives ITSELF a 5s read timeout just to read the body, THEN takes the global ServerState lock and runs serde_json::from_slice over the whole body + rebuilds every forwarding table (address-book LPM, policies, NAT) before writing the response. Deserialize+apply of a 64MB snapshot on a firewall core routinely exceeds 3s. The Go json.Decode hits the 3s absolute deadline first (3s < the Rust 5s read window alone), requestDetailedLocked returns a timeout, Compile returns fmt.Errorf("publish userspace snapshot: %w") -> ApplyConfig error. For an operator commit this reports a FAILED commit even though the helper may have fully applied the snapshot (only the response was late): desired (Go: not published, publishedSnapshot not advanced) diverges from applied (helper: armed on the new config). Retries re-hit the same 3s wall, so the exact large-feed input #2744 was written to ADMIT becomes effectively un-committable / flapping.

**Why it matters** — The whole point of #2744 was to stop rejecting legitimate large threat-intel-feed apply_snapshots by raising the cap 16->64MB; leaving the transport deadline at 3s reintroduces a different failure for the same input, and on a security appliance a commit that reports failure while the dataplane silently went live is a dangerous desired/applied split (operator may re-push, roll back, or fail over believing enforcement never landed).

**Fix direction** — Size the control-socket deadline to the request class: give apply_snapshot (and other snapshot-carrying requests) a deadline proportional to body size or a generous fixed ceiling (>= the Rust 5s read timeout plus expected apply time), while keeping the tight 3s for status/ping. Alternatively split the write-deadline from the read/response-deadline. Add a regression test that round-trips a near-64MB apply_snapshot against the deadline (control_request_cap_2744_test.go only exercises the byte pre-flight).

**Not a duplicate** — Searched issues-all.txt for 'control socket', 'deadline', 'timeout', '2744', '2523' and prior-findings.md for 'deadline/3s/timeout'. #2744 (cap raise) and #2523 (byte cap) are CLOSED and reflected at HEAD; prior finding #675 is the Rust single-thread concurrent-connection starvation — a DIFFERENT mechanism. No open issue or prior finding covers the Go-side fixed 3s deadline vs the raised 64MB body cap; this is the named residual of #2744.

---

#### F-183 · buildDesiredLocalAddressSets swallows netlink AddrList failure while the caller prunes — a transient enumeration error deletes VRRP VIP / kernel-learned entries from userspace_local_v4/v6, steering host-bound VIP traffic into the XSK transit path

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `go-usdp-programs`  ·  **Location:** `pkg/dataplane/userspace/maps_sync.go`:970
- **Labels:** `bug`, `security`

```
	// Also add kernel addresses (VIPs added by VRRP) that aren't in the
	// config snapshot. Without this, the XDP shim doesn't recognize VIP
	// destinations as local and redirects them to XSK instead of the kernel.
	// Use AddrList(nil, ...) to enumerate ALL addresses on the system.
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		addrs, err := netlink.AddrList(nil, family)
		if err != nil {
			continue
		}
```

**Runtime trace**

syncLocalAddressMapsLocked runs on every ~1s status poll (applyHelperStatusLocked, maps_sync.go:756) and on every classifier sync. It computes desiredV4/desiredV6 via buildDesiredLocalAddressSets, then ITERATES the live BPF maps and DELETES every key not in the desired set (maps_sync.go:915-951). The desired set has two sources: snapshot interface addresses (stale, captured at the last full build) and a LIVE netlink.AddrList(nil, family) enumeration that is the ONLY source for VRRP VIPs installed after the last build (per the function's own comment). If AddrList transiently fails (kernel memory pressure, netlink buffer overrun — precisely the moments a firewall is under stress), the error is silently swallowed (`continue` at 971-973): the desired set silently omits ALL kernel-only addresses, the prune loop classifies the currently-installed VIP keys as stale and deletes them from userspace_local_v4/v6, and the sync returns SUCCESS. For at least one poll interval (longer if the failure persists), the XDP shim no longer classifies VIP-destined packets as local: SSH/BGP/IKE traffic to the cluster VIP is redirected into XSK, where the helper treats it as transit (policy/NAT applied, or dropped for lack of a session) instead of delivering it to the kernel. The reconcile is fail-unsafe: a degraded desired-state computation still drives a full prune.

**Why it matters** — This converts a transient, recoverable netlink error into an active management-plane / routing-protocol outage window on the HA master (VIP-destined control traffic blackholed into the transit path), invisible in logs because the error is swallowed. Desired-state reconcilers must never prune against a partial desired set.

**Fix direction** — Propagate the AddrList error out of buildDesiredLocalAddressSets (or return an 'enumeration incomplete' flag) and have syncLocalAddressMapsLocked skip the stale-key prune phase — keeping previous map contents — when the kernel enumeration failed, updating only the additive side; log the failure.

**Not a duplicate** — Searched prior-findings.md and issues-all.txt for 'AddrList', 'local_v4', 'local address', 'VIP local'. The closest prior findings are routes.go 'netlink.RuleList failure silently skipped per family' (route-leak snapshots vanish — different map, no prune interaction) and the Rust-side local_v4 cross-VRF leak (forwarding_build). No issue/finding covers the local-address desired-set prune-on-partial-enumeration mechanism.

---

#### F-184 · flexible-match-range `bit-offset` (and `flexible-range-name`) silently dropped by the range parser — term matches at the wrong bit position with a clean commit

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `rs-filter`  ·  **Location:** `pkg/config/compiler_firewall.go`:345
- **Labels:** `bug`, `security`, `vsrx-parity`

```
			for _, rangeInst := range namedInstances(child.FindChildren("range")) {
				fm := &FlexMatchConfig{MatchStart: "layer-3"}
				for _, rc := range rangeInst.node.Children {
					switch rc.Name() {
					case "match-start":
					...
					case "byte-offset":
					...
					case "bit-length":
					...
					case "match-mask":
```

**Runtime trace**

Junos `flexible-match-range` range stanzas accept bit-length, bit-offset (0-7), byte-offset, flexible-range-name, match-start, range. The inner switch at compiler_firewall.go:345-441 handles match-start/byte-offset/bit-length/range,match-value/match-mask and has NO default arm — the outer #3307 UnknownFrom default at :443 only covers direct `from` children. Input: `set firewall family inet filter F term T from flexible-match-range range r1 byte-offset 6 bit-offset 4 bit-length 4 match-value 0x5` (match the low nibble starting 4 bits into byte 6). `bit-offset 4` matches no case arm, is never recorded into term.UnknownFlexMatch, so validateFilterFlexMatchStrict (compiler_validate_strict.go:4224) passes and commit succeeds cleanly. The wire snapshot carries offset=6/length=1/value=0x5/mask=0xF; the Rust matcher (userspace-dp/src/filter/engine/matching.rs:145-149) assembles the byte big-endian and compares (val & 0xF)==0x5 — i.e. it tests bits 4..7 of the byte instead of the authored bits 0..3 (window shifted by 4 bits). A `then discard` term over/under-drops and a `then accept` term in a protect filter admits the wrong packets; same silent-drop for `flexible-range-name` template refs.

**Why it matters** — This is the exact residual class #3203/#3232 closed for neighboring fields (silent wrong-offset/wrong-base evaluation = security evasion with a clean commit) resurfacing through the one range child the parser never reads. A real Juniper config import using bit-offset loads without any warning and enforces a different match than authored.

**Fix direction** — Add a default arm inside the range-children switch that records the unhandled leaf (`bit-offset <v>`, `flexible-range-name <v>`) into term.UnknownFlexMatch so validateFilterFlexMatchStrict rejects at commit (lenient path downgrades to warn per #1960), or implement bit-offset by folding it into the derived mask/shift when (bit_offset+bit_length) fits the byte window.

**Not a duplicate** — grepped 'bit-offset|flexible-range|flexible-match|flex' in issues-all.txt, prior-findings.md, known-gaps.md and the repo (zero occurrences of bit-offset anywhere in the tree). #3077 (wholesale drop), #3203 (byte-length truncation/value-0/default mask), #3232 (match-start layer-4 base), #3406 (lenient-load width) are all CLOSED and fixed at HEAD; none touch the bit-offset/flexible-range-name range children — new residual in a new field, same defect family.

---

#### F-185 · GRE/IPIP tunnel endpoints with unparseable outer source/destination are silently dropped from the forwarding state (fail-open config narrowing, inconsistent with #2409/#2410 fail-closed posture)

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `rs-forwarding`  ·  **Location:** `userspace-dp/src/afxdp/forwarding_build/tunnels.rs`:37
- **Labels:** `bug`, `vsrx-parity`

```
        } else {
            let Ok(source) = endpoint.source.parse::<IpAddr>() else {
                continue;
            };
            let Ok(destination) = endpoint.destination.parse::<IpAddr>() else {
                continue;
            };
            (source, destination)
        };
```

**Runtime trace**

A TunnelEndpointSnapshot whose source/destination string fails IpAddr parse (version-drifted peer on the HA config-sync lenient path, or a hostile/corrupt snapshot — the same threat model that motivated #2409 interface-address and #2410 TTL/VLAN fail-closed gates in this very builder) is silently `continue`d at populate_tunnel_endpoints. Consequences: state.tunnel_endpoints and tunnel_endpoint_by_ifindex lack the id, so (a) the gr-X connected route built later in populate_interfaces carries tunnel_endpoint_id=0 and the tunnel prefix degrades to a NORMAL connected route on the tunnel netdev -> lookup returns MissingNeighbor -> ARP probes fired on a GRE logical device -> blackhole with 'missing_neighbor' telemetry pointing away from the real cause; (b) owner_rg_for_resolution returns 0 for stored resolutions referencing the id; (c) gre_decap_index misses so inbound GRE for that endpoint is not decapped. apply succeeds with zero error/counter — silent connectivity loss. Same silent-continue applies to `endpoint.id == 0 || endpoint.ifindex <= 0` at line 17.

**Why it matters** — The #2409/#2410/#2212/#2240 campaign established the invariant that a malformed snapshot row in this builder must fail the snapshot CLOSED (preflight keeps the previous good state) rather than silently narrow config; TTL (same struct, 13 lines above) got exactly that treatment while source/destination did not. Silent tunnel loss on a production firewall's HA lenient path is the precise failure class those fixes targeted.

**Fix direction** — Return SnapshotIntegrityError::TunnelEndpointAddressUnparseable { id, field, value } for a non-WG endpoint whose source or destination fails to parse (and consider one for id==0/ifindex<=0 rows), so the reconcile preflight rejects the snapshot and keeps the previous forwarding state; at minimum add a counter/status row for skipped tunnel endpoints.

**Not a duplicate** — Searched 'tunnel endpoint', 'tunnel_endpoint', 'silently dropped', '#2410' in issues-all.txt/prior-findings.md. #2410 (closed) fixed only the TTL/VlanId/QueueId narrowing casts in this builder; prior finding 602 covers fabric links (different object) silently skipped; #2782 covered GRE checksum decap drops. No issue/finding covers the source/destination parse `continue` in populate_tunnel_endpoints — it is the un-fixed residual of the #2410 fail-closed sweep.

---

#### F-186 · Pool-mode SNAT never translates the ICMP query identifier (RFC 5508 REQ-1 / vSRX NAPT parity): colliding echo IDs from different internal hosts behind one pool address produce identical translated tuples

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `rs-nat`  ·  **Location:** `userspace-dp/src/nat/source.rs`:870
- **Labels:** `bug`, `vsrx-parity`, `rfc-conformance`

```
        // `protocol == 0` is the synthetic "L4 tuple unknown" sentinel used
        // by the address-only `match_source_nat` callers (never a real
        // packet). It keeps its historical behavior — a round-robin port
        // via `try_next_port` with no flow-keyed mapping — because the
        // packet rewriters gate every L4 write on `has_l4_ports`, so the
        // port it returns can never be written to a frame.
        let port_less = protocol != 0 && !crate::ip_proto::has_l4_ports(protocol);
        let tuple_unknown = protocol == 0;
```

**Runtime trace**

Config: source NAT rule with a one-address pool P (or address-persistent hashing two hosts to the same pool IP). Hosts A (10.0.1.5) and B (10.0.1.6) both ping X with ICMP echo identifier 0x0001 (musl/busybox ping derives the ID from the PID; container PID namespaces make collisions routine). (1) Each first packet takes the slow path into match_source_nat_result_for_tuple with protocol=1 and src_port=echo-id (the session layer uses the echo ID as pseudo source port, #3067). (2) source.rs:870: has_l4_ports(1) is false, so port_less=true and the IP-only branch (source.rs:874-903) returns rewrite_src=Some(P), rewrite_src_port=None — no allocator entry, no identifier remap. (3) Both flows' translated forward tuples become (icmp, P->X, id 1) and both reverse keys are the identical (icmp, X->P, id 1). (4) X's echo replies match whichever session the reverse index resolves; the two hosts' replies are indistinguishable, so the second host's pings are misdelivered or time out. RFC 5508 REQ-1 requires a NAPT to translate the ICMP Query Identifier exactly like a source port, and vSRX pool/interface NAPT does remap it; xpf never does — neither pre- nor post-#3111 code ever touched ICMP bytes 4..6.

**Why it matters** — ICMP through overloaded SNAT is a bread-and-butter NAPT case (monitoring probes, health checks, user pings). Silent reply misdelivery/blackholing that depends on PID-derived identifier collisions is extremely hard to diagnose in production, and it diverges from both vSRX behavior and RFC 5508.

**Fix direction** — Treat ICMP/ICMPv6 query messages as port-carrying for pool-mode SNAT: allocate a translated identifier from the flow-keyed PortAllocator (the echo ID is already the session pseudo-port), set rewrite_src_port to it, and teach the packet rewriters to write ICMP bytes 4..6 (+incremental ICMP checksum fixup) for query types instead of gating on has_l4_ports. Non-query ICMP and GRE/ESP/AH keep the #3111 IP-only behavior.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'icmp id', 'identifier', 'pseudo-port', 'query', '5508', 'PAT', '3111'. Nearest: #3111 (CLOSED) which made ALL port-less protocols IP-only to stop GRE/ESP corruption — it deliberately lumped ICMP in but never added identifier PAT (new residual shape); #1760 (CLOSED) fixed the session-table secondary index for shared reverse keys but not the NAT-layer identifier collision itself; #3067 established the echo-ID pseudo-port session keying this finding builds on. docs/feature-gaps.md has no ICMP-ID NAT row.

---

#### F-187 · Uncompressed per-bit prefix trie: feed-scale address books cost one heap Box per bit-level (hundreds of MB) and up to 128 dependent pointer derefs per cold-path lookup

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `rs-policy`  ·  **Location:** `userspace-dp/src/prefix_set.rs`:233
- **Labels:** `performance`

```
#[derive(Debug, Clone, Default)]
struct TrieNode {
    /// True iff some inserted prefix has its END at this node
    /// (depth equals the prefix's `prefix_len`). Lookup short-
    /// circuits on the first `covers == true` along the bit walk.
    covers: bool,
    /// Children indexed by next bit (0 or 1).
    children: [Option<Box<TrieNode>>; 2],
}
```

**Runtime trace**

Config: `security dynamic-address address-name threat-feed ...` bound to a large drop list (threat feeds commonly carry 100k-1M entries; pkg/feeds/feeds.go caps only per-LINE bytes — maxLineBytes, feeds.go:29 — there is no entry-count cap) and a `deny` policy citing the name. Path: daemon fetch → buildAddressBookTableWithFeeds (pkg/dataplane/userspace/policies.go, #2049) merges feed CIDRs into an AddressBookSnapshot row → wire → parse_policy_state_with_counters book loop (policy.rs:2143-2172) → PrefixSetV4::from_v3_literals(N prefixes) → N>16 (PREFIX_SET_LINEAR_MAX, prefix_set.rs:32) → PrefixTrieV4::insert walks up to 32 levels per /32 allocating one Box<TrieNode> (24 B + allocator header) per new node — no path compression (module comment line 211: 'NOT Patricia'). 500k random v4 /32s ≈ 7-12M nodes ≈ 200-400 MB resident for ONE book; a v6 /128-heavy feed walks up to 128 levels (~4x worse). The structure is built TWICE per apply (scratch preflight server/handlers/snapshot.rs:42-65 + real build forwarding_build/mod.rs:233) so transient heap holds two copies. Lookup: every session-miss first packet on the feed-guarded zone pair runs PrefixTrieV4/V6::contains (prefix_set.rs:260-278/298-316) — a serial chain of up to 32/128 DEPENDENT Box derefs (each a potential cache miss, no prefetchable layout) per cited book per candidate rule → cold-path session-setup latency collapses exactly where the feed protection is applied. The companion bench only gates build p95 for 256 prefixes (comment lines 25-31); no lookup-latency or memory ceiling exists for feed-scale N.

**Why it matters** — This is a production security appliance whose stated scale target is 1M policies (#1606/#1609) with dynamic-address feeds materialized into books (#2049); an unbounded feed can trigger hundreds of MB of pointer-chasing heap in the packet-forwarding helper and a serial-cache-miss chain on the session-setup path, degrading new-flow rate precisely under the threat-feed configs the feature exists for.

**Fix direction** — Replace the uncompressed binary trie with a path-compressed (Patricia/LC-trie) or sorted-array binary-search-by-masked-key structure for the >16-prefix case; alternatively bucket by /8 or /16 stride. Add a feed/book prefix-count gauge plus a bench gating lookup latency and bytes/prefix at 100k-1M entries, and reuse the preflight-built sets in the real build to avoid the double construction.

**Not a duplicate** — Searched prior-findings.md and issues-all.txt for 'trie', 'patricia', 'radix', 'prefix set', 'feed memory'. #923 (closed) INTRODUCED this trie; #1609/#1607/#966 (closed) cover cold-path rule-scan scaling, not prefix-set node memory/pointer-chase; prior finding 345 covers per-book repeated lookups per rule, 14 covers AppCatalog linear scan. No prior issue/finding covers the uncompressed-trie memory footprint or the 128-dependent-deref lookup chain for feed-scale books.

---

#### F-188 · Non-TCP reject reply builds source IP from the unresolved PHYSICAL parent ifindex, so `then reject` silently drops on VLAN sub-interfaces (residual of #3035)

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `rs-poll-descriptor`  ·  **Location:** `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs`:246
- **Labels:** `bug`, `vsrx-parity`, `vlan`

```
    let bytes = if meta.protocol == PROTO_TCP {
        build_reject_rst_frame(packet_frame)
    } else {
        build_reject_icmp_unreachable(packet_frame, meta, ingress_ifindex, forwarding)
    };
    let Some(bytes) = bytes else {
        // Unreplyable: fail-closed to the silent drop the caller already
        // performs.
        return false;
    };
```

**Runtime trace**

Config (loss cluster ha-cluster-userspace.conf): reth0 has `vlan-tagging`; only unit 50 (172.16.50.8) and unit 80 (172.16.80.8) carry addresses, the bare parent has none. A host on VLAN 80 sends a UDP datagram that a `deny-all` zone pair / firewall-filter `then reject` (or a lo0 host-bound reject) matches. Packet arrives with meta.ingress_ifindex = physical member ifindex (e.g. 11) and meta.ingress_vlan_id = 80 (the #3035 test asserts resolve_ingress_logical_ifindex(fw,11,80)==Some(202)). enqueue_reject_reply() runs: line 246 calls build_reject_icmp_unreachable(frame, meta, ingress_ifindex=11, fw). Inside icmp.rs build_local_icmp_error_v4/v6 do `forwarding.egress.get(&11)` (icmp.rs:334/429) then `egress.primary_v4?`/`primary_v6?` (icmp.rs:336/431). egress is keyed by the LOGICAL unit ifindex (forwarding_build/interfaces.rs:251), so egress[11] is either absent (→ None) or the addressless parent entry (primary_v4=None → None). build returns None → enqueue_reject_reply returns false → caller silently drops. Note line 328 DOES resolve the logical ifindex, but only for classify_generated_reply (the #3035 fix), never for the build. TCP `then reject` is unaffected because build_reject_rst_frame reflects the frame with no egress lookup.

**Why it matters** — On the primary WAN test path (reth0.80) and any VLAN sub-interface, an operator-configured active `reject` for non-TCP traffic (UDP/ICMP) degrades to a silent drop, diverging from vSRX which emits ICMP admin-prohibited. #3035 fixed only the CoS/output-filter CLASSIFY ifindex; the reply-BUILD source/egress lookup was left on the physical parent, so the fix is incomplete for the reply-synthesis half.

**Fix direction** — Resolve the logical ingress ifindex once at the top of enqueue_reject_reply (as classify already does) and pass it to build_reject_icmp_unreachable for the egress/source-IP lookup, keeping the physical ingress_ifindex only for build_reject_rst_frame reflection and the XSK egress_ifindex/TX. Mirror the same resolution into icmp.rs build_local_time_exceeded_request / PTB builders (they read forwarding.egress.get(&ingress_ident.ifindex) with the same physical value).

**Not a duplicate** — Searched issues-all.txt (#3035 CLOSED, #3026 CLOSED, #3204, #2521) and prior-findings.md (lines 40,53,138,197 reject-reply items). #3035 covered CLASSIFY on physical vs logical ifindex (CoS/output-filter keying) and its test uses a TCP RST which needs no egress lookup; #3026 covered CLASSIFY for TE/PTB. NONE addresses the reply-BUILD egress/source-IP lookup passing the unresolved physical ifindex — a distinct mechanism (source synthesis, not classification). Not a duplicate; named residual of #3035.

---

#### F-189 · Standby HOLD re-buckets every held synced session on every 1s GC tick — O(held)/second churn (pop+push+SessionKey clone) reintroduces the O(N) scan the #965 timer wheel was built to avoid

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `rs-session`  ·  **Location:** `userspace-dp/src/session/expire.rs`:388
- **Labels:** `performance`, `ha`, `timer-wheel`

```
    fn rebucket_alive_entry(&mut self, key: &SessionKey, now_ns: u64) {
        let Some(entry) = self.entry_by_key(key) else {
            return;
        };
        let natural_expiration = entry.last_seen_ns.saturating_add(entry.expires_after_ns);
        // Held entries (past expiration) clamp to `now_ns` so
        // `target_tick_for` yields `now_tick` (delta 0). Self-healed
        // entries keep their future natural expiration.
        let expiration_for_schedule = natural_expiration.max(now_ns);
        let new_target_tick = target_tick_for(now_ns, expiration_for_schedule);
```

**Runtime trace**

1) A standby node holds N peer-synced sessions it does not forward. Each session's last_seen_ns is frozen at import time, so after import+timeout it is idle-crossed. 2) On the first GC pass after crossing, standby_gate_decision returns Hold (expire.rs:454); the Hold arm (expire.rs:220-254) stamps first_held_ns and calls rebucket_alive_entry, which schedules the entry at now_tick (delta 0, since natural_expiration<=now_ns clamps to now_ns) and push_back a fresh WheelEntry with a CLONED SessionKey. 3) The drain loop is `while cursor_tick < now_tick`, so the entry parked at now_tick is not re-drained this pass, but the NEXT GC pass (1s later, now_tick advances by 1) pops it, re-evaluates Hold, and re-buckets it again at the new now_tick. 4) Steady state: every held synced session is popped + re-pushed + key-cloned once per SESSION_GC_INTERVAL_NS (1s), for the entire hold lifetime (up to STALE_SYNCED_CEILING = min(3*timeout, 7 days)). For N held sessions that is N VecDeque pops + N pushes + N SessionKey clones (each up to 2x IpAddr = ~40B) every second.

**Why it matters** — The #965 bucketed wheel exists specifically to make GC O(entries-due-this-tick) instead of O(all-sessions). On a standby holding a large synced-session table (the whole point of HA session sync), the #2120 hold path silently restores O(held) work every second — the exact cost the wheel was designed to eliminate — plus per-tick heap churn from the SessionKey clones. It degrades the standby's steady-state CPU/cache footprint proportional to synced-session count and is not surfaced by any counter.

**Fix direction** — Avoid re-touching held entries every tick: schedule a held entry to a coarse future re-check tick (e.g. now_tick + K, or the min(next-ceiling-check, self-heal-poll) interval) instead of now_tick, so a held session is re-examined every K seconds rather than every second; or maintain a separate 'held' set walked at a lower cadence. Track a held-rebucket counter so the cost is observable.

**Not a duplicate** — Searched issues-all.txt/prior-findings for wheel/expire/standby/hold/#2120. #2120 (CLOSED) introduced the retention gate and the now_tick re-bucket; this is the un-flagged O(N)/sec perf residual of that design, not the retention correctness. Prior-finding #621 (wheel skips buckets) is a different (and wrong-at-HEAD) claim. No existing item covers the per-tick re-bucket cost of held entries.

---

#### F-190 · Responder does not enforce per-peer TAI64N handshake anti-replay — a captured msg1 is accepted and replayed indefinitely (WG §5.4.4 gap)

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `rs-wg-coord`  ·  **Location:** `userspace-dp/src/afxdp/wg/handshake_session.rs`:461
- **Labels:** `security`, `vsrx-parity`, `bug`

```
        let mut ts_sink = [0u8; TAI64N_LEN];
        // snow writes the recovered Noise payload (the peer's TAI64N) into
        // ts_sink; the value is used by a compliant responder for handshake
        // anti-replay. S1 derives the session and (per the (b+) boundary)
        // does not yet enforce per-peer TAI64N anti-replay — that rides
        // with the responder-hardening step. We still must READ it so snow
        // advances the transcript.
```

**Runtime trace**

Attacker captures one on-wire msg1 from a legit peer (msg1 outer framing is not encrypted; a single passive capture suffices). Attacker replays the exact bytes to xpf's listen port. dispatch_inbound → consume_initiation_create_response_inner: parse_initiation MAC1 verifies (MAC1 keys on xpf's PUBLIC key), build_responder_handshake + read_message succeed (valid captured transcript), get_remote_static recovers the peer pubkey, peer_config found → the recovered TAI64N in ts_sink is DISCARDED (handshake_session.rs:461-468). xpf reserves an index, builds/sends msg2, installs a new responder session. No comparison against a stored per-peer greatest-TAI64N is performed, so the replay is indistinguishable from a fresh handshake. Every replay installs another session (feeding the companion rotation/egress-blackhole finding).

**Why it matters** — Kernel WG and wireguard-go reject any initiation whose TAI64N is <= the last one accepted from that peer (whitepaper §5.4.4) precisely to stop handshake replay. Without it, xpf accepts unlimited replays of a single captured initiation, and (via the 2-slot rotation bug) that becomes an egress-disruption DoS against an established tunnel. tai64n.rs already provides the ordered-comparison primitive; only the per-peer stored high-water + reject is missing.

**Fix direction** — Store a per-peer greatest-received TAI64N (Peer field, updated under reconcile_lock at responder completion). In consume_initiation_create_response_inner, reject (new drop counter) when the recovered ts_sink <= the peer's stored value before reserving/installing; update it on accept. Lexicographic byte compare of the 12-byte value equals numeric compare (tai64n.rs already relies on this).

**Not a duplicate** — Documented as deferred in the code comment and in docs/pr/1865-wg-telemetry/plan.md ('TAI64N anti-replay ... responder hardening') and counters.rs 'Reserved reason names', but it is NOT in known-gaps.md and has NO dedicated tracker issue (#1709 CLOSED covered only initiator TAI64N monotonicity/encoding; #1703 OPEN is generic interop). Reporting the residual per the campaign rule for incomplete closed work, naming the deferral. The concrete replay→session-churn consequence is not captured anywhere.

---

#### F-191 · Responder handshake-flood CPU DoS: MAC1-only admission (keyed on the public key) forces full X25519 crypto per forged msg1 on the single per-tunnel control thread; no cookie/MAC2 under-load defense

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `rs-wg-coord`  ·  **Location:** `userspace-dp/src/afxdp/wg/handshake_session.rs`:458
- **Labels:** `security`, `performance`, `vsrx-parity`

```
        let mut state = self
            .build_responder_handshake()
            .map_err(|_| HandshakeError::Internal)?;
        let mut ts_sink = [0u8; TAI64N_LEN];
        ...
        if state.read_message(parsed.noise_body, &mut ts_sink).is_err() {
            return Err(HandshakeError::Crypto);
        }
```

**Runtime trace**

An attacker who knows xpf's WG public key (freely handed to peers and shown in status) crafts msg1 datagrams with a valid MAC1 (MAC1 = keyed-BLAKE2s(BLAKE2s('mac1----'||xpf_pub), body) — no secret needed). parse_initiation passes the MAC1 check, then consume_initiation_create_response_inner runs build_responder_handshake + snow read_message (multiple X25519 scalar multiplications) BEFORE the peer_config lookup rejects an unknown initiator (handshake_session.rs:458-483). The control loop drains up to WG_RX_BURST=64 datagrams per poll wakeup and immediately re-loops while did_work (wg_control.rs:402/398) with no per-source rate limit and no cookie challenge, so the single per-tunnel control thread is pinned doing DH for garbage. That thread also owns decap, the timer pass, keepalives, and TUN egress, so legitimate handshakes/keepalives/forwarding stall.

**Why it matters** — This is exactly the flood WireGuard's cookie/MAC2 under-load mechanism (type-3 CookieReply, require valid MAC2) exists to blunt: a responder must not spend unbounded asymmetric crypto on unauthenticated initiations. xpf drops type-3 as unsupported (dispatch_inbound WG_TYPE_COOKIE → hs_rx_cookie_unsupported) and never emits cookie replies, so it has no defense; on a security appliance this is a remote unauthenticated CPU/availability DoS.

**Fix direction** — Implement the WG cookie mechanism (S7): under a configurable load threshold, emit a CookieReply and require a valid MAC2 before running the responder Noise DH; add per-source initiation rate limiting on the control thread. At minimum, cap responder handshake work per interval.

**Not a duplicate** — Cookie/MAC2 (S7) is noted as future work in handshake.rs and mod.rs (WG_LABEL_COOKIE) but there is no tracker issue for the DoS and it is not in known-gaps.md. Distinct from the TAI64N finding (that is replay of a KNOWN peer; this is forged msg1 from ANY source knowing the public key). Not covered by any SYN-cookie issue (#1374/#3315 etc. are TCP SYN cookies, a different subsystem).

---

#### F-192 · RG-activation reverse prewarm dedup is O(N*M) — Vec::contains linear scan inside a per-key loop, quadratic in synced-session count on the failover path

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `rs-worker`  ·  **Location:** `userspace-dp/src/afxdp/shared_ops.rs`:262
- **Labels:** `performance`, `ha`, `scalability`

```
    for key in reverse_candidate_keys {
        if !candidate_keys.contains(&key) {
            candidate_keys.push(key);
        }
    }
```

**Runtime trace**

RG failover → Coordinator::update_ha_state → handle_activated_rgs (ha.rs:150) → prewarm_reverse_synced_sessions_for_owner_rgs. candidate_keys = owner_rg_session_keys_serialized(sessions index) — up to DEFAULT_MAX_SESSIONS (131072) forward keys for the activated RGs. reverse_candidate_keys = the reverse-prewarm index, comparable magnitude. The merge loop calls candidate_keys.contains(&key) (O(len)) for EACH of M reverse keys → O(N*M). With N=M≈10^5 that is ~10^10 comparisons on the coordinator/HA-state thread, a multi-second CPU burn that stalls subsequent HA state transitions and the rest of activation (BPF republish, neighbor warm) at the exact moment of failover.

**Why it matters** — Failover time is the primary HA SLA for a security appliance. A quadratic dedup means prewarm latency grows with session-table occupancy — a busy firewall (the case that most needs fast failover) is exactly where activation stalls longest, delaying session continuity restoration and back-pressuring the HA state machine. The function is already FastSet-aware internally (owner_rg_session_keys builds a FastSet), so the linear-scan merge is an avoidable regression.

**Fix direction** — Collect candidate_keys into a FastSet (or track a seen-set) and dedup in O(1) per key, or have owner_rg_session_keys_serialized return the union directly. Drop the Vec::contains scan.

**Not a duplicate** — Searched issues-all.txt for 'prewarm' (#287/#524/#297 are correctness/filtering of reverse prewarm, not algorithmic complexity) and prior-findings for 'quadratic'/'O(N'/'prewarm' (hits are policy.rs AppCatalog, intrazone rules, NAT destination.rs — none touch shared_ops prewarm). No prior finding or issue covers the candidate_keys dedup complexity. Nearest: #524 (re-prewarm split-RG sessions) is about WHICH sessions, not the dedup cost.

---

#### F-193 · `to-zone junos-host` DENY/REJECT is silently NOT enforced for ordinary direct host-bound traffic (kernel-shunt bypass of the junos-host security policy)

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `x-default-deny`  ·  **Location:** `pkg/dataplane/userspace/zones.go`:14
- **Labels:** `security`, `vsrx-parity`, `bug`

```
// ZoneHostInboundView is the per-zone host-inbound-traffic enforcement view for
// the KERNEL-nftables primary path (#3070). Ordinary host-bound traffic to a
// firewall interface IP / VRRP VIP (SSH, ping, OSPF/BGP to the box) is shunted
// to the Linux kernel by the XDP shim before it ever reaches userspace-dp, so
// the authoritative host-inbound enforcement for those packets must live in the
// kernel `chain input` (mirroring the lo0-filter precedent). The userspace-dp
// LocalDelivery check (forwarding/host_inbound.rs) remains the secondary path
// for the narrow subset that DOES reach the XSK (DNAT-to-self, static-NAT to a
// firewall service, embedded-ICMP, DNS edge cases).
```

**Runtime trace**

Config: `zones trust host-inbound-traffic system-services ssh` + `policies from-zone trust to-zone junos-host policy blk match source-address 10.0.0.5/32; match application junos-ssh; then deny`. Intent (vSRX): admit SSH generally, DENY SSH from 10.0.0.5 to the box. Runtime: an SSH SYN from 10.0.0.5 to a firewall interface IP arrives -> userspace-xdp/src/lib.rs `is_local_destination(&parsed)` is true (the IP is in userspace_local_v4, populated by buildDesiredLocalAddressSets) -> `cpumap_or_pass(ctrl)` shunts the packet to the kernel BEFORE the XSK. The kernel `chain input` (daemon_nft.go buildHostInboundFilterPayload) mirrors ONLY host-inbound service admission (ssh -> tcp/22 accept); it has NO junos-host security-policy rules. So the packet is ACCEPTED and delivered to the box. The junos-host deny lives only in userspace-dp evaluate_junos_host_policy (reached via junos_host_policy_drops on the LocalDelivery XSK path), which this flow never touches. Result: the `then deny` from 10.0.0.5 fails OPEN for the primary direct-host path; it only ever fires for the narrow DNAT-to-self / static-NAT / embedded-ICMP subset that reaches the XSK.

**Why it matters** — A junos-host security policy is the operator's fine-grained control-plane firewall (source/dest address, application, deny/reject/log) layered on top of coarse host-inbound service admission. #3019 and docs/junos-cli-reference.md present `to-zone junos-host` as ENFORCED, but for the overwhelmingly common case (direct SSH/BGP/OSPF/ping to an interface IP) it is not — a security-visible fail-open where an operator believes management access is restricted by source/application when it is not.

**Fix direction** — Either (a) mirror the junos-host security policy (at least deny/reject terms with source-address/application) into the kernel `chain input` alongside host-inbound admission, or (b) explicitly document in docs/junos-cli-reference.md and the zones.go/host_inbound.rs comments that `to-zone junos-host` deny/reject is enforced ONLY on the XSK secondary subset and does NOT restrict direct-to-interface host traffic, and reject/warn at commit for junos-host policies that add constraints host-inbound cannot express.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md/known-gaps.md for junos-host + kernel/primary/shunt. #3019 (CLOSED) added junos-host enforcement on the userspace LocalDelivery path only; #3611 (OPEN) is from-zone junos-host (host-ORIGINATED egress), a different direction; #3706 (OPEN) is to-zone junos-host permit-log discard; known-gaps line 10 is the to-any/both-any/global tier exclusion. NONE captures that the junos-host DENY is bypassed for the PRIMARY kernel-shunted direct-host path because the kernel nft chain has no junos-host security-policy mirror — this is the new cross-layer shape.

---

#### F-194 · SharedCoSExactBacklog residual-surplus token bucket: split-atomic state + read-then-consume across workers over-admits non-exact surplus up to Nworkers× — same defect class #2955 fixed for generated errors

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `x-hpc`  ·  **Location:** `userspace-dp/src/afxdp/types/shared_cos_lease/backlog.rs`:125
- **Labels:** `bug`, `performance`, `concurrency`, `cos`, `test-gap`

```
    pub(in crate::afxdp) fn residual_surplus_budget(
        &self,
        now_ns: u64,
        residual_rate_bytes: u64,
        residual_burst_bytes: u64,
    ) -> u64 {
        ...
        self.refill_residual_surplus_budget(now_ns, residual_rate_bytes, residual_burst_bytes);
        self.residual_budget
            .tokens
            .load(Ordering::Acquire)
            .min(residual_burst_bytes)
```

**Runtime trace**

1) Interface with an exact-guarantee queue under demand plus non-exact queues; the mlx5 VF exposes 6 RX queues so bindings on workers W1..W6 share ONE SharedCoSExactBacklog (interface-global, per its own doc). 2) W1's surplus phase calls nonexact_surplus_budget_under_exact_demand (cos/queue_service/mod.rs:361-365) -> backlog.residual_surplus_budget(now, rate, burst): refill_residual_surplus_budget CAS-claims the elapsed interval on last_refill_ns, then a SEPARATE CAS loop credits `tokens`, and the function returns a plain load of tokens (= T, up to burst). 3) W2..W6 execute the same read concurrently before any consume commits — each observes ~T and each caps its non-exact drain at T bytes. 4) Each worker transmits up to T non-exact bytes; at TX completion each calls consume_residual_surplus_budget(sent) (cos/tx_completion.rs:821 and :929) — the first fetch drains tokens to 0 and the remaining consumes saturating_sub at 0, so (K-1)×T bytes are never charged. 5) Every refill window repeats this, so sustained non-exact surplus can run up to ~Nworkers× the configured residual rate, stealing the link capacity the exact-guarantee reservation (transmit-rate ... exact) exists to protect. Additionally the refill itself is split across two atomics (last_refill_ns CAS at backlog.rs:188-195, tokens CAS at :196-207): a worker that claims the interval and is preempted before crediting leaves a window where peers observe claimed-but-uncredited state — the exact 'two independent atomics' shape the #2955 comment in icmp_ratelimit.rs calls out as the over-admit bug it replaced with a single GCRA word.

**Why it matters** — CoS exact-rate guarantees are a headline feature (transmit-rate exact, #760 fixed a 40-60% cap overshoot); a multi-worker check-then-act budget silently re-introduces a worker-count-scaled overshoot of the residual bound whenever exact demand and non-exact load coexist across queues — visible as exact-queue starvation/latency under mixed load, and unbounded by any counter.

**Fix direction** — Collapse the budget into a single-word GCRA (theoretical-arrival-time in ns) exactly like icmp_ratelimit.rs post-#2955, and make admission a CAS-consume of the bytes actually granted per drain pass (reserve-then-spend, releasing unspent bytes), instead of an advisory read plus a deferred saturating consume. Port the #2955 concurrent_hammer_never_over_admits test pattern to this bucket (currently no concurrency test exists for it).

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'residual', 'surplus', 'backlog', 'token bucket', 'over-admit', '2158', '2955'. #2955 (CLOSED) fixed this exact defect class but only in icmp_ratelimit.rs (generated-error buckets); no issue or prior finding touches the SharedCoSExactBacklog residual budget (#2158/P2 code). Nearest CoS items (#760 exact-cap overshoot, #914 admission hole, #2981 V_min floor) are different mechanisms. Reported explicitly as a #2955-class sibling in a different subsystem.

---

#### F-195 · pending_tx_admitted: unpadded cross-core CAS field on BindingLiveState plus one AcqRel RMW per popped item — reintroduces the producer/consumer cacheline sharing MpscInbox's CachePadded head/tail was built to eliminate

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `x-hpc`  ·  **Location:** `userspace-dp/src/afxdp/umem/mod.rs`:735
- **Labels:** `performance`, `false-sharing`, `refactor`

```
    pub(super) max_pending_tx: AtomicU32,
    /// Atomic admission count for `pending_tx`: queued requests plus
    /// producer-held reservations that have not committed yet. This is the
    /// linearizable capacity gate; `pending_tx.len()` remains observational.
    pub(super) pending_tx_admitted: AtomicUsize,
    pub(super) last_error: Mutex<String>,
    ...
    pub(super) pending_tx: MpscInbox<TxRequest>,
```

**Runtime trace**

1) Cross-worker redirect path (#706 lock-free conversion): every producer worker's enqueue_tx/enqueue_tx_owned -> push_redirect_inbox -> try_acquire_pending_tx_admission runs a CAS loop on pending_tx_admitted (umem/mod.rs:1216-1224, AcqRel) BEFORE the MpscInbox push (which CASes the CachePadded head). 2) The owner worker's drain, take_pending_tx_into (umem/mod.rs:1252-1265), calls release_pending_tx_admission() — fetch_sub(1, AcqRel) on the SAME atomic (line 1230) — once PER POPPED REQUEST inside the pop loop. 3) pending_tx_admitted is a plain unpadded field in the middle of BindingLiveState (declared between max_pending_tx — read by every producer per push via pending_tx_admission_cap — and last_error/pending_tx), with no #[repr(align(64))] wrapper and no const-assert, unlike mpsc_inbox.rs:39-52 (CachePadded head/tail, comment: 'without this padding ... every producer operation would invalidate the consumer's cached view') and unlike the #746 OwnerProfileOwnerWrites/PeerWrites split (profile.rs:11,121 with compile-time align asserts). 4) Result: at redirect rates (Mpps under CoS cross-worker steering) every redirected packet costs two contended cross-core RMWs on two different lines (inbox head + admission counter), and the owner pays one extra AcqRel RMW per drained item where a single fetch_sub(n, AcqRel) after the pop loop is equivalent (admission only needs to be released once the item leaves the ring).

**Why it matters** — The redirect inbox is the known owner-worker hotspot chain (#704/#706/#709/#746); the admission gate silently added back a producer<->consumer shared cacheline plus per-item RMWs, directly against docs/engineering-style.md 'Cache-pad cross-core atomics' — measurable coherence overhead and tail-latency jitter on redirected flows.

**Fix direction** — Wrap pending_tx_admitted in the existing CachePadded pattern (with a const align assert, matching #746 discipline); batch the owner-side release into one fetch_sub(count, AcqRel) after the take_pending_tx_into pop loop; longer term fold the soft cap into the Vyukov ring occupancy (head/tail are already padded) so producers touch one contended line per push instead of two.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'pending_tx', 'admission', 'mpsc', 'inbox', 'cache line', 'false shar'. Prior cacheline findings cover WorkerStats/telemetry counters (prior-findings:670) and session structs (prior-findings:618); closed #746 isolated owner-profile telemetry and #706/#715 built the padded MPSC. None covers the later-added pending_tx_admitted admission counter, which post-dates those fixes and violates the same documented rule at a different field.

---

#### F-196 · Standalone setup.sh deploy stops the daemon and swaps binaries WITHOUT the #1864 verify-dataplane pre-flight that cluster deploy_vm mandates — a rejected shim leaves the VM config-only

- **Severity:** 🟠 medium  ·  **Confidence:** medium
- **Module:** `x-tests-build`  ·  **Location:** `test/incus/setup.sh`:609
- **Labels:** `test-infra`, `test-gap`, `bug`

```
	# Stop service gracefully, then clean BPF state for binary upgrade.
	# Order matters: systemctl stop sends SIGTERM (graceful socket close),
	# then xpfd cleanup removes pinned BPF maps/links.  The final
	# pkill -9 is a safety net for "text file busy" on push.
	incus exec "$INSTANCE_NAME" -- systemctl stop xpfd 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- xpfd cleanup 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- pkill -9 xpfd 2>/dev/null || true
```

**Runtime trace**

`make test-deploy` -> setup.sh cmd_deploy. Compare cluster-setup.sh deploy_vm lines 805-864: it pushes /tmp/xpfd.preflight and runs `verify-dataplane` against the node's LIVE kernel BEFORE any stop/cleanup/push, with an explicit ORDERING INVARIANT comment ('no dataplane stop ... may run before this check — the 2026-06-10 incident was exactly a stop-then-load-fail that left the node in config-only mode'). setup.sh cmd_deploy has no such step: it goes straight to systemctl stop xpfd (line 609) -> binary push + sha-verify (622-635) -> enable --now (653) -> deploy_verify_running_xpfd (658), which asserts only that the running xpfd PROCESS matches the pushed sha — it says nothing about whether the embedded AF_XDP shim loaded. Input state: the standalone VM's kernel differs from the build host's (e.g. the VM took a point-release the tracked .o was never verified against, or a dev built with XPF_SHIM_ALLOW_UNPINNED_INSTALL=1). The kernel verifier REJECTs the shim at startup -> xpfd runs config-only with no dataplane, yet the deploy exits 0 and prints 'Deploy complete' — the exact silent-degradation the cluster path hard-fails on.

**Why it matters** — The two deploy paths share deploy-lib.sh for sha-verify but diverged on the more important gate: the one that catches a binary whose dataplane cannot load. The standalone VM is where new shim/toolchain work is smoke-tested first, so it is the environment MOST likely to see an unverified object, and a false-green deploy there poisons every subsequent connectivity/perf measurement.

**Fix direction** — Factor the deploy_vm pre-flight block (push xpfd.preflight, nice/taskset verify-dataplane, hard-fail message) into deploy-lib.sh and call it from both setup.sh cmd_deploy and cluster-setup.sh deploy_vm; add a case to deploy-lib-selftest.sh. Optionally also assert post-start dataplane liveness (e.g. `cli -c 'show security flow status'` or the readiness endpoint) after deploy_verify_running_xpfd.

**Not a duplicate** — Searched issues-all.txt for 'preflight', 'verify-dataplane', 'standalone': #1864 (closed) added the make-generate gate + the CLUSTER deploy pre-flight; #2162/#1962 (closed) fixed standalone helper push/instance targeting; #2176 (closed) added sha/pin reconcile. None cover the standalone path's missing verifier pre-flight; prior-findings.md has no setup.sh entries. This is a residual of #1864 in a different deploy path (mechanism: stop-then-load-fail on the standalone VM, not the cluster).

---

#### F-197 · API-key/bearer token comparison and Basic-auth username lookup are non-constant-time (Go map lookup + early return) while only the password uses subtle.ConstantTimeCompare

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-api-grpc`  ·  **Location:** `pkg/api/auth.go`:55
- **Labels:** `security`

```
	// Bearer token
	if strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		return cfg.APIKeys[token]
	}
...
		expected, exists := cfg.Users[user]
		if !exists {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(pass), []byte(expected)) == 1
```

**Runtime trace**

With the API bound non-loopback (finding 2 shows this is possible), an attacker submits X-API-Key:/Bearer guesses. The check is `cfg.APIKeys[token]` (auth.go:36 and :55) — a plain Go map membership test, not a constant-time compare, unlike the password path which deliberately uses subtle.ConstantTimeCompare. For Basic auth, `expected, exists := cfg.Users[user]; if !exists { return false }` (auth.go:68) returns immediately for an unknown username, before any constant-time work, so response latency distinguishes valid from invalid usernames (user enumeration). The intent to be timing-safe is present (the password compare) but is applied inconsistently.

**Why it matters** — The presence of subtle.ConstantTimeCompare for the password signals the code wants to resist timing side channels; leaving the token match and username existence timing-variable undermines that on a network-facing bind, enabling username enumeration and (weakly) token oracle behavior.

**Fix direction** — Compare API keys/bearer tokens in constant time (e.g. iterate the key set with subtle.ConstantTimeCompare, or hash-then-compare a fixed-width digest) and always run a constant-time password compare against a dummy expected value when the username is unknown so the valid/invalid paths take the same time.

**Not a duplicate** — No prior finding mentions timing/constant-time/auth token comparison (grepped 'constant.time|timing|APIKeys|bearer' across issues-all.txt and prior-findings.md — no hits). Distinct from finding 2 (that is auth-absent; this is a weakness within the auth-present path).

---

#### F-198 · writeJSON writes the status header before Encode, so a marshal error (e.g. a secret Marshaler failure) ships a 200 with a truncated/empty body and no error signal

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-api-grpc`  ·  **Location:** `pkg/api/api.go`:41
- **Labels:** `bug`, `refactor`

```
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
```

**Runtime trace**

writeOK -> writeJSON(w, 200, Response{...Data: v}). WriteHeader(200) commits the status line and headers to the wire, THEN json.NewEncoder(w).Encode(v) runs. If Encode fails midway (a nested MarshalJSON error, or a write error after some bytes are flushed) the return value is discarded: the client already received HTTP 200 plus a partial/empty JSON body. For GET /api/v1/config the payload is a *config.Config with several custom Marshalers (Secret, SNMP), so a Marshaler bug surfaces to clients as a silent success with corrupt body rather than a 500.

**Why it matters** — Callers/automation cannot distinguish a real empty result from a serialization failure; the response envelope's Success=true is emitted even when the body is truncated. Harder to diagnose than an explicit 500.

**Fix direction** — Marshal into a buffer first, and only on success write Content-Length + WriteHeader(status) + body; on marshal error emit 500. At minimum log the discarded Encode error so failures are observable.

**Not a duplicate** — No prior finding references writeJSON/writeOK/writeError or encode-error handling in pkg/api (grepped 'writeJSON|Encode|WriteHeader'). Prior pkg/api findings are all about counter/policy content, not the response-writer primitive.

---

#### F-199 · Config-mode dispatch requires exact keywords (no Junos prefix abbreviation), diverging from operational-mode dispatch and from config-mode Tab completion which resolves prefixes

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-cli`  ·  **Location:** `pkg/cli/cli_dispatch.go`:276
- **Labels:** `vsrx-parity`, `bug`

```
	switch parts[0] {
	case "edit":
...
	case "commit":
		return c.handleCommit(parts[1:])
	case "rollback":
```

**Runtime trace**

In operational mode dispatchOperational calls resolveCommand(parts[0], operationalCommands) so `sh`->show, `conf`->configure resolve by unique prefix. dispatchConfig instead switches on the literal parts[0] with no prefix resolution. Config-mode completion (completeConfigWithDesc) DOES resolve prefixes via resolveUniqueTreePrefix(configTopLevel, words[0]), so pressing Tab on `com` completes to `commit` and `?` lists it as valid — but typing `com`<Enter> hits the switch default and returns 'unknown command: com (in configuration mode)'. Same for `ro 1` (rollback), `sh` (show), `ed` (edit).

**Why it matters** — Junos config mode supports unambiguous keyword abbreviation for commit/rollback/show/edit/etc.; xpf advertises it via completion but rejects it at execution, a parity gap and a confusing completion-vs-dispatch contradiction for muscle-memory Junos operators.

**Fix direction** — Route dispatchConfig's parts[0] through resolveCommand/resolveUniqueTreePrefix against the ConfigTopLevel keyset before the switch, mirroring dispatchOperational, so completion and execution agree.

**Not a duplicate** — Searched for prefix/abbreviation/config mode/dispatch. #1319/#1444/#552 are schema/refactor items; no prior finding on config-mode dispatch lacking prefix resolution while completion has it. Novel.

---

#### F-200 · Pipe `| match`/`| except`/`| find` use plain substring (strings.Contains), not Junos regular expressions

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-cli`  ·  **Location:** `pkg/cli/cli_dispatch.go`:82
- **Labels:** `vsrx-parity`, `bug`

```
	case "match", "grep":
		for _, line := range lines {
			if strings.Contains(line, pipeArg) {
				fmt.Fprintln(origStdout, line)
			}
		}
```

**Runtime trace**

Operator runs `show route | match "^10\.0\."`. extractPipe splits pipeType="match", pipeArg=`"^10\.0\."`. dispatchWithPipe filters lines with strings.Contains(line, pipeArg): the anchor `^`, escaped `\.`, and quotes are treated literally, so lines are matched only if they contain the literal text `"^10\.0\."` — i.e. nothing matches. Junos `| match` is a regular-expression (egrep-style) filter, so anchors, character classes, alternation, and quantifiers are expected to work.

**Why it matters** — Operators rely on regex pipe filters (`| match "lo0|fxp0"`, `| match "^Interface"`) in scripts and muscle memory; silent substring semantics produce empty or wrong output with no error, and the `?` help text describes it as 'matches a pattern'.

**Fix direction** — Compile pipeArg as a regexp (regexp.Compile) for match/except/find and fall back to literal only on compile error; document case sensitivity. Note the completePipeFilter help already says 'pattern'.

**Not a duplicate** — Closed #18 addressed pipe case-sensitivity (case-insensitive -> case-sensitive); this is a DIFFERENT mechanism (regex engine vs literal substring). No prior finding covers the regex gap. Distinct from #18, named.

---

#### F-201 · `show/clear security flow session sort-by <x>` accepts any value without validation, unlike protocol/port which error

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-cli`  ·  **Location:** `pkg/cli/session_filter.go`:181
- **Labels:** `bug`, `test-gap`

```
		case "sort-by":
			if v, ok := takeValue(&i, "sort-by"); ok {
				f.sortBy = v // "bytes" or "packets"
			}
```

**Runtime trace**

The parser sets f.setParseErr for unknown protocol, invalid port/prefix, and unknown filter tokens (validate() then fails the command). But `sort-by` stores the raw value with no membership check against {bytes, packets}. `show security flow session sort-by btyes` (typo) passes validate() and the downstream top-talkers sorter silently falls through to its default ordering, so the operator believes they sorted by bytes but did not — with no diagnostic. This is inconsistent with the strict-parse discipline the rest of parseSessionFilter was hardened to (parseErr contract at lines 40-46).

**Why it matters** — The whole point of the parseErr contract is that a silently-dropped/ignored token must not certify a different query than requested; sort-by is the one selector that still fails open to a misleading result.

**Fix direction** — Validate sort-by against the allowed set (bytes|packets) and setParseErr on anything else, so validate() rejects typos like every other selector.

**Not a duplicate** — Searched for sort-by/session filter strictness. #3439 (remote GetSessions malformed filters) and #3696 (policy simulator strict parse) are different surfaces/parsers. session_filter.go strict-parse hardening (#1827) did not cover sort-by. Novel residual.

---

#### F-202 · StartHeartbeat is not self-stopping — a second call without StopHeartbeat leaks the prior sender/receiver goroutines and sockets and double-sends heartbeats

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-cluster-core`  ·  **Location:** `pkg/cluster/heartbeat_manager.go`:53
- **Labels:** `bug`, `resource-leak`, `ha`, `refactor`

```
	m.mu.Lock()
	m.hbSender = newHeartbeatSender(m, sendConn, peer, interval)
	m.hbReceiver = newHeartbeatReceiver(m, recvConn, threshold, interval)
	m.hbLocalAddr = localAddr
	m.hbPeerAddr = peerAddr
	m.hbVRFDevice = vrfDevice
	m.mu.Unlock()
```

**Runtime trace**

StartHeartbeat overwrites m.hbSender/m.hbReceiver without first stopping any existing pair (contrast Monitor.Start at monitor.go:158-159 which calls Stop() first, and RestartHeartbeat which explicitly calls StopHeartbeat before restarting). If StartHeartbeat is invoked while a pair is already running — e.g. the daemon's bind-retry goroutine racing a rapid transport config change, or any future caller — the previous heartbeatSender/heartbeatReceiver goroutines (readLoop, timeoutLoop, run) keep executing on their now-unreferenced UDP conns and are never joined, leaking two goroutines and two sockets per extra call. With SO_REUSEADDR+SO_REUSEPORT both receivers stay bound to the same port (kernel load-balances heartbeats between them, so a subset of packets updates a stale receiver's lastSeen) and both senders transmit, doubling heartbeat traffic.

**Why it matters** — A control-plane goroutine/socket leak plus split heartbeat reception can cause intermittent, hard-to-diagnose false peer-timeout/liveness behavior on a long-running HA node; robustness here should not depend on every external caller pairing Start with Stop.

**Fix direction** — At the top of StartHeartbeat, stop and nil any existing m.hbSender/m.hbReceiver (mirror Monitor.Start), so the call is idempotent and self-cleaning regardless of caller discipline.

**Not a duplicate** — Searched issues for heartbeat start/restart/leak. #87 (CLOSED) reconfigures endpoints on config change and #81 (CLOSED) is retry-exhaustion; neither addresses StartHeartbeat overwriting a live sender/receiver without stopping it. No prior finding on this.

---

#### F-203 · readiness holdTimer is never stopped when its RG is removed by UpdateConfig — leaked AfterFunc timer keeps a stale RG pointer

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-cluster-core`  ·  **Location:** `pkg/cluster/readiness.go`:38
- **Labels:** `refactor`, `resource-leak`, `test-gap`

```
			rg.holdTimer = time.AfterFunc(m.takeoverHoldTime, func() {
				m.mu.Lock()
				defer m.mu.Unlock()
				if !rg.Ready {
					return
				}
				slog.Info("cluster: hold timer expired, re-evaluating election", "rg", rgID)
```

**Runtime trace**

SetRGReady arms rg.holdTimer = time.AfterFunc(takeoverHoldTime, ...) when an RG transitions not-ready->ready and takeoverHoldTime>0. UpdateConfig removes RGs no longer in config (group_state.go:43-52: delete(m.groups, id)) but does not stop rg.holdTimer for the removed group. The pending AfterFunc still fires after the group is gone, re-locks m.mu, reads the stale rg pointer's Ready field, and calls runElection/electSingleNode. It is functionally harmless (the deleted rg is no longer in m.groups so election ignores it), but it is a leaked timer plus a stale-pointer capture that also masks the intended lifecycle: the only place holdTimer.Stop() is called is the ready->not-ready branch (readiness.go:56-59).

**Why it matters** — Minor resource/lifecycle debt in the election-readiness path; on clusters that churn RG config it accumulates orphaned timers and makes the readiness state machine harder to reason about.

**Fix direction** — When UpdateConfig deletes a group (and in Manager.Stop), stop rg.holdTimer if non-nil before dropping the RG; consider stopping/nil-ing it inside a small helper so every RG-teardown path releases the timer.

**Not a duplicate** — Searched issues/prior-findings for holdTimer / readiness / takeover-hold. #1845 (CLOSED) reworked the takeover-hold-time schema range only. No issue or prior finding covers the holdTimer leak on RG removal.

---

#### F-204 · peerClockOffset is never reset on disconnect and rebase is not gated on clockSynced — sessions received before the new ClockSync after a peer reboot get rebased with a stale offset

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-cluster-sync`  ·  **Location:** `pkg/cluster/sync_conn.go`:1192
- **Labels:** `bug`, `ha`, `race`

```
				offset := s.peerClockOffset.Load()
				val.Created = rebaseTimestamp(val.Created, offset)
				val.LastSeen = rebaseTimestamp(val.LastSeen, offset)
				s.installClusterSyncedV4(key, val)
```

**Runtime trace**

1) Node B reboots; its CLOCK_MONOTONIC (monotonicSeconds) restarts near 0 while surviving node A has uptime U (potentially weeks). 2) On A, handleDisconnect (:1567) does clockSynced.Store(false) but leaves peerClockOffset at the pre-reboot value (≈ A_mono - B_old_mono). 3) On reconnect, A's sendLoop still holds a message from before the disconnect (sendOne retry loop) plus up to 4096 backlogged sendCh entries; the instant conn0 is published (handleNewConnection :482-495, before sendClockSync at :505) sendOne can win writeMu and flush backlog — symmetric on B's side. 4) Any session B receives from A before processing A's new syncMsgClockSync is rebased with B's offset (0 on fresh boot) or, in the reverse direction, A rebases B's near-zero timestamps with the stale pre-reboot offset — Created/LastSeen land up to U seconds wrong. 5) Conntrack GC on the receiver then either expires those synced sessions immediately (LastSeen ancient) or never (LastSeen far future), and syncSweep's `val.Created >= threshold` misclassifies them after a failover promotion.

**Why it matters** — Wrong monotonic timestamps on synced sessions silently corrupt idle-timeout enforcement on the standby — the same failure class as #1792/#2332 (wall-clock liveness) but in the session-timestamp domain; the window is small yet recurs on every reconnect with a queued backlog.

**Fix direction** — Reset peerClockOffset (or gate rebaseTimestamp on clockSynced) at disconnect, and write the ClockSync message before publishing the conn to getActiveConn (or send it through sendCh ordering) so no session frame can precede it.

**Not a duplicate** — Grepped 'clock': #1792 (CLOSED, wall-clock vs monotonic liveness — fixed via MonotonicNanos) and #2332 (CLOSED, Rust heartbeat wall-clock) are the nearest; both are about liveness clocks, not the session-timestamp rebase offset lifecycle. No issue/prior finding mentions peerClockOffset or sendClockSync ordering.

---

#### F-205 · Refactor debt: dual-AST-shape grammar is hand-duplicated per call site (interface vs unit tunnel switches, leaf vs child then-clause switches, three classifier/rewrite collector clones) — two confirmed bugs in this review live exactly in diverged duplicate arms

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-config-ifaces-cos-fw`  ·  **Location:** `pkg/config/compiler_interfaces.go`:239
- **Labels:** `refactor`, `test-gap`

```
				for _, prop := range tunnelNode.Children {
					switch prop.Name() {
					case "source":
						if v := nodeVal(prop); v != "" {
							tc.Source = v
						}
					case "destination":
						if v := nodeVal(prop); v != "" {
							tc.Destination = v
						}
```

**Runtime trace**

Structural evidence, not a single runtime path: (1) compiler_interfaces.go carries two ~50-line tunnel-property switches (interface-level lines 151-199 using prop.Keys[1], unit-level lines 239-286 using nodeVal) that already read the same grammar differently, and the unit-level inheritance shim around the second copy is where the confirmed address-aliasing bug (this review, `*tc = *ifc.Tunnel`) lives; (2) compileFilterThen duplicates every action across a leaf-form switch (lines 488-561) and a child-form switch (lines 563-624) whose reject-message-type handling has already diverged in shape; (3) compileClassOfService's dscp-classifier / ieee-802.1-classifier / dscp-rewrite loops are three near-identical clones, and the #1809 inline-leaf fix was applied to exactly two of the three collectors — the missed third is the confirmed rewrite-rules drop in this review. Each new AST-shape fix (#1809, #2419, #2545, #3205) must be re-applied N times and history shows one copy gets missed.

**Why it matters** — In this codebase the dual AST shape is the #1 recurring bug generator (at least 6 tracker issues); every duplicated shape-walk is a future silent-drop. Consolidation converts a class of security-relevant compile bugs into a single audited code path.

**Fix direction** — Introduce a small shared walk module (e.g. pkg/config/astprops or extending the firewallMatchValues family): one helper for 'named-prop scalar across both shapes', one for 'multi-value across both shapes' (exists: firewallMatchValues), one for 'inline-keys keyword scan' (exists ad hoc in three collectors); then collapse the tunnel switches into one parseTunnelProps(tc, node) and make compileFilterThen table-driven over a single action map consumed by both forms. Pin with shape-matrix tests (hierarchical leaf / hierarchical block / flat-set) per grammar family.

**Not a duplicate** — Prior refactor items target file-level splits: #2002 (parser/AST into pkg/config/ast/), #1699/#1701 (ast.go/types.go splits), prior finding on compiler_security.go domain split. None proposes deduplicating the dual-AST-shape property walkers; this is anchored by two bugs confirmed in this campaign (tunnel copy, rewrite collector) rather than LOC thresholds.

---

#### F-206 · Refactor debt: NAT compile + validation logic is scattered across compiler_nat.go (1.9k LOC), compiler_nat_dnat_to.go, natpool.go, six validators embedded in the 6.2k-LOC compiler_validate_strict.go, and ~8 wiring points in compiler.go — no single NAT config module

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-config-nat`  ·  **Location:** `pkg/config/compiler_nat.go`:1
- **Labels:** `refactor`

```
package config

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)
```

**Runtime trace**

Structural observation, not a runtime path: NAT config behavior currently lives in (a) pkg/config/compiler_nat.go (1875 LOC: compile + three strict-vs-lenient validators validatePoolUtilizationAlarm/validateNATHostMaskStrict/validateNPTv6Strict + shared IP-classification helpers), (b) compiler_nat_dnat_to.go (the #3444 AST walk + the generic forEachChild primitive that OTHER subsystems now import from a NAT-named file), (c) natpool.go (operational pool resolution), (d) compiler_validate_strict.go (6211 LOC total; NAT validators validateDNATPoolStrict, validateNATMatchApplicationsStrict, validateNATMatchDestinationPortStrict, validateNATSourceAddressNameReferencesStrict interleaved with DHCP/route-filter/policy/screen validators), and (e) compiler.go wiring at lines 2475, 2498, 3156, 3327, 3490, 3552, 3568, 1853. Consequences observed in this review: the DNAT pool gained a #3450 gate while the SNAT pool port stanza has none (finding 3) — the scatter makes coverage asymmetry invisible; the #3562 forEachChild fix reached validators but not compileNAT (finding 5); and new NAT rejects keep landing as more sibling files (compiler_nat_dnat_to.go pattern).

**Why it matters** — Every NAT review cycle (audits 095/098, #3444, #3450, this one) finds gate asymmetries that a single NAT validation registry would make structurally impossible to miss; the >2k-LOC threshold policy from #2158 is already violated by compiler_validate_strict.go (6.2k) and compiler_nat.go is at 1.9k and growing.

**Fix direction** — Extract a real module directory: pkg/config/natcfg/ (or pkg/config/validate/nat.go family) holding compile{Source,Destination,Static,NAT64}, all NAT strict-vs-lenient validators behind a single registration slice the compiler iterates, the natAddrFamily/isHostMaskAddress helper SSOT, and natpool.go. Move forEachChild to an AST utility file so non-NAT validators stop importing it from a NAT-named file.

**Not a duplicate** — Searched issues-all.txt for 'refactor config', 'split compiler', '2158', '2002', '1891', '1701': #2158 (CLOSED) set the ~2k-LOC split policy and named other files; #2002/#1699/#1701 split parser/AST/types; none proposes consolidating the NAT compile+validate domain, and compiler_validate_strict.go's 6.2k LOC post-dates the #2158 sweep. Prior findings mention compiler_validate_strict.go for specific gates, never its structure.

---

#### F-207 · Duplicate `host-inbound-traffic` (and `screen`/`address-book`) blocks under one security-zone are last-write-wins in compileZones — operator's earlier host-inbound services silently lost (non-additive vs Junos; management-service loss risk)

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-config-policy`  ·  **Location:** `pkg/config/compiler_security.go`:492
- **Labels:** `bug`, `vsrx-parity`, `availability`

```
			case "screen":
				zone.ScreenProfile = nodeVal(prop)
			case "host-inbound-traffic":
				zone.HostInboundTraffic = parseHostInboundNode(prop)
			case "tcp-rst":
```

**Runtime trace**

Input: `load override` of a hierarchical config where one `security-zone <z>` carries two `host-inbound-traffic` blocks, e.g. `host-inbound-traffic { system-services ssh; }` then `host-inbound-traffic { system-services https; }`. (1) parser appends both as sibling children of the security-zone node. (2) compileZones iterates inst.node.Children; for each `host-inbound-traffic` child it does `zone.HostInboundTraffic = parseHostInboundNode(prop)` (line 493) — a plain assignment, so the SECOND block OVERWRITES the first: the compiled zone admits only https, ssh is silently lost. The same last-write-wins overwrite applies to `screen` (line 491) and `address-book` (line 498-507). Unlike the `interfaces` case (which appends/accumulates), these are not merged. Junos treats host-inbound-traffic as additive across statements, so the operator's authored ssh admission vanishes with no commit warning.

**Why it matters** — Host-inbound is deny-by-default so dropping tokens fails CLOSED for traffic — not a packet fail-open — but silently discarding an authored management service (e.g. ssh) can lock an operator out of the box after a load override, and it diverges from Junos additive semantics. address-book overwrite can also drop zone-local address definitions that policies then fail to resolve. It is the zone-level sibling of finding 1's duplicate-inner-block mechanism.

**Fix direction** — In compileZones, MERGE duplicate host-inbound-traffic blocks (union SystemServices/Protocols via the existing UnionHostInboundTokens semantics) and address-book blocks, or reject a zone carrying more than one host-inbound-traffic/screen/address-book block at commit. Route host-inbound accumulation through the shared parseHostInboundNode by appending rather than replacing.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for host-inbound duplicate, compileZones, 3362/3405 (per-interface override / default-deny). Prior host-inbound work (#3200 tokens, #3225 family scoping, #3362 per-interface override, #3405 default-deny, #3654/#3682 presentation) concerns token validation/family/display — none addresses a duplicate zone-level host-inbound-traffic/screen/address-book block being last-write-wins in compileZones. Distinct from finding 1 (policies) by file/function (compileZones) though same root sibling-block mechanism.

---

#### F-208 · Duplicate `policy-statement <name>` blocks overwrite instead of merging — #2641 residual: prefix-lists and communities merge, policy statements still last-block-wins

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-config-routing-services`  ·  **Location:** `pkg/config/compiler_routing.go`:424
- **Labels:** `bug`, `refactor`

```
	for _, inst := range namedInstances(node.FindChildren("policy-statement")) {
		ps := &PolicyStatement{Name: inst.name}
		termsByName := make(map[string]*PolicyTerm)
...
		po.PolicyStatements[ps.Name] = ps
	}
```

**Runtime trace**

The parser APPENDS a repeated named block instead of merging (the documented behavior that motivated #2641 for prefix-lists and #3562 for duplicate security blocks). A config file or `load merge` result containing two `policy-options { policy-statement EXPORT-LAN { term a {...} } }` ... `policy-statement EXPORT-LAN { term b {...} } }` blocks yields two namedInstances entries with the same name. The loop creates a FRESH PolicyStatement per instance (line 425) and stores it with `po.PolicyStatements[ps.Name] = ps` (line 471) — the second block's object replaces the first, silently discarding term a. The sibling collections in the same function were given merge semantics for exactly this case: prefix-lists reuse the existing map entry (lines 362-373, #2641 comment) and communities append (lines 376-396). The resulting FRR route-map is missing the first block's terms → routes that should be exported/filtered are handled by the policy default action instead — either leaked or withheld — while commit succeeds.

**Why it matters** — Route-policy terms silently vanishing changes advertisement/filtering behavior (the #2473 class of unintended permit/deny), and the asymmetry with the adjacent merged collections makes this an operator trap during load merge workflows.

**Fix direction** — Mirror the #2641 pattern: look up po.PolicyStatements[inst.name] first and merge terms into the existing statement (termsByName already handles intra-block duplicates; hoist it per-name), keeping DefaultAction last-wins.

**Not a duplicate** — #2641 (closed) fixed 'duplicate named policy-options prefix-list blocks overwrite instead of merge (community blocks already merge)' — its fix explicitly touched prefix-lists only; policy-statement blocks retain the pre-#2641 overwrite. Grep for 'policy-statement' in issues shows #2998/#2689/#2223, none about duplicate-block merge. Reported as a named residual of #2641 in a new object class.

---

#### F-209 · `route-filter <prefix> ?` completion shows the "<prefix>" placeholder for the MATCH-TYPE slot — per-node placeholder cannot describe the second identity arg

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-config-schema`  ·  **Location:** `pkg/config/schema_routing.go`:159
- **Labels:** `vsrx-parity`, `refactor`, `cli`

```
				"prefix-list":  {desc: "Prefix list", args: 1, multi: true, placeholder: "<list-name>", children: nil},
				"route-filter": {desc: "Route filter", args: 2, multi: true, placeholder: "<prefix>", keyValidator: ValidateRouteFilterArg, children: nil},
				"community":    {desc: "Community", args: 1, multi: true, placeholder: "<community>", children: nil},
```

**Runtime trace**

Operator types `set policy-options policy-statement P term T from route-filter 10.0.0.0/8 ?`. CompleteSetPathWithValues consumes keyword+args (nodeKeyCount=3); with only 2 of 3 tokens present it enters the still-consuming-args branch (schema_complete.go:179-232) and returns the NODE-level placeholder "<prefix>" (line 212-217) — but the slot being completed is the MATCH-TYPE (exact | longer | orlonger | upto | prefix-length-range | through), a fixed vocabulary the walker/commit-check accepts via routeFilterMatchTypes (schema_validators.go:424-431). Junos completion lists the match-type keywords here. So completion advertises a prefix where commit-check expects (and #2105's validator specifically accepts) a match-type — the completion/commit divergence class named in this module's charter. The same single-placeholder limitation applies to every args>=2 node (e.g. `as-path <name> <regex>`), but route-filter is the one with a fixed second-slot vocabulary that could be offered.

**Why it matters** — Misleading `?` help on a commonly-typed routing-policy path pushes operators toward the exact malformed inputs #2105 had to add a validator for; per-arg-slot completion metadata is the missing schema feature.

**Fix direction** — Add per-arg-position completion metadata to schemaNode (e.g. argPlaceholders []string / argExamples [][]string) or special-case the args:2 route-filter node to offer routeFilterMatchTypes when exactly one arg has been consumed; keep ValidateRouteFilterArg as the acceptance SSOT.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'route-filter', 'completion', 'match-type', 'placeholder'. #2105 [CLOSED] added the commit-time validator for this slot and documented the position-agnostic limitation of VALIDATION; neither it nor any prior finding covers the COMPLETION side showing the wrong slot vocabulary. #1892 (empty help) and #1419 (cmdtree help autogen) are about the operational tree / help text, not config value-slot completion.

---

#### F-210 · ValidateConfig mutates the config it validates (sched.SurplusSharing = false) and is invoked on the live active config from four read-only show paths

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-config-validate`  ·  **Location:** `pkg/config/compiler_validate_warn.go`:625
- **Labels:** `refactor`, `concurrency`

```
			if sched.SurplusSharing && !sched.TransmitRateExact {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service scheduler %q surplus-sharing is meaningful only with transmit-rate exact; ignored",
					sched.Name))
				sched.SurplusSharing = false
			}
```

**Runtime trace**

ValidateConfig is documented as 'non-fatal validation' but performs a warn-and-strip write. It is called from the compile path (compiler.go:3470 — where the mutation is the intended #915 strip) AND from four read-only display paths on the SHARED active config pointer: grpcapi/server_show_system.go:116 (showAlarms, cfg := s.store.ActiveConfig()), grpcapi/server_show_security_text.go:347, cli/cli_show_security_log.go:171, cli/cli_show_system.go:912. Today the write cannot fire on the show paths only because compileExpanded already stripped the flag on every load path — an invariant enforced nowhere. The moment anyone adds another warn-and-strip to ValidateConfig (the existing one invites the pattern), a concurrent gRPC `show system alarms` becomes an unsynchronized write to the live *Config racing the dataplane/apply readers (a Go data race, torn reads under -race, and a show command that changes behavior).

**Why it matters** — A security appliance's read-only observability RPCs must never be able to mutate the enforced configuration object; the current safety is accidental, undocumented, and one copy-paste away from a race on the active config.

**Fix direction** — Move the #915 strip out of ValidateConfig into compileClassOfService (or a dedicated normalize step on the compile path), leaving ValidateConfig strictly pure; optionally add a doc comment + test asserting ValidateConfig does not modify its argument (reflect.DeepEqual before/after).

**Not a duplicate** — Grepped prior-findings.md and issues-all.txt for SurplusSharing/surplus and 'ValidateConfig': prior findings reference the warn file only for provider-capability and DuckDNS warnings; #915/#1183 introduced the strip deliberately but no issue or finding covers the mutation-from-read-only-show-path hazard.

---

#### F-211 · Commit-confirmed timeout rollback destroys the unconfirmed config — Junos keeps it reachable as rollback 1; here only a sha256 hash survives in the journal

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-configstore`  ·  **Location:** `pkg/configstore/store_commit.go`:336
- **Labels:** `vsrx-parity`, `bug`

```
	s.active = s.confirmPrevTree
	s.compiled = s.confirmPrevCfg
	if s.candidate != nil {
		s.candidate = s.active.Clone()
	}
	s.dirty = false

	s.confirmTimer = nil
	s.confirmPrevTree = nil
```

**Runtime trace**

1) Operator commits a large change with `commit confirmed 10`; the change breaks their session and the window expires. 2) PromoteRollback (store_commit.go:325) sets active=confirmPrevTree, re-clones the candidate from it, persists, and journals auto_rollback — but never pushes the timed-out tree T1 into s.history and never calls saveRollbackFiles, so T1 exists nowhere: not in the in-memory History ring, not in any xpf.conf.N slot (slot 1 still holds T0 from the CommitConfirmed-time save, which now equals active), not on disk. 3) On Junos the timeout executes 'rollback 1 + commit', which makes the failed config retrievable as rollback 1 so the operator can `show | compare rollback 1`, fix the one bad stanza, and re-commit. 4) Here the operator's only artifact is the journal entry's ConfigHash (sha256 of a tree no file retains) — the recovery workflow after the exact failure commit-confirmed exists to handle requires re-typing the entire change from memory. (The optional auto-archive goroutine may retain a copy, but only if `archiveDir` is configured — it is off by default.)

**Why it matters** — Commit-confirmed is used precisely for risky changes; losing the candidate work product on timeout turns a safety net into a data-loss event and diverges from vSRX operator expectations during incident recovery.

**Fix direction** — In PromoteRollback, push the outgoing active (the timed-out tree) into s.history with a comment like 'commit confirmed timeout (rolled back)' and call saveRollbackFiles, so it appears as rollback 1 — matching Junos's rollback-then-commit model. Document the behavior in pkg/configstore/README.md.

**Not a duplicate** — Grepped issues-all.txt for 'rollback', 'confirm' — #3441 (rollback-file durability), #3447 (rollback arg parsing) are different mechanisms; #1922 Items 1a/1b cover rollback atomicity and the first-commit bootstrap marker, not retention of the timed-out tree. prior-findings.md has no configstore retention findings.

---

#### F-212 · Refactor debt: pkg/conntrack GC sweep machinery (expiry, per-IP session-count publisher, watermark hysteresis, adaptive delay, HA delete callbacks) is unreachable on the only runtime dataplane, yet the daemon still spins the loop and pushes config into it

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-conntrack-appid`  ·  **Location:** `pkg/conntrack/gc.go`:100
- **Labels:** `refactor`, `tech-debt`

```
	// SkipSweep, when non-nil and returning true, causes GC to skip
	// the expensive BPF session map scan entirely. Used when the
	// userspace dataplane manages sessions in its own hash table —
	// the BPF map scan wastes ~19% CPU on maps that aren't used for
	// active session tracking.
	SkipSweep func() bool
```

**Runtime trace**

1) daemon_run.go:764-766 installs `gc.SkipSweep = func() bool { return true }` whenever d.dp implements userspaceSessionDeltaDrainer — which the userspace manager (the only runtime forwarding path post-#1373/#1476) always does. 2) Every sweep short-circuits at gc.go:230, so ~330 lines of sweep logic — v4/v6 expiry with early-ageout, DeleteBatchKnown + OnDeleteV4/V6 HA delete sync (daemon_run.go:777-789), per-IP srcCounts/dstCounts publishing (gc.go:281-327, 459-466; ClearSessionCounts is never called by anyone), watermark hysteresis (468-491), nextSweepDelayAt — are dead in production; only tests exercise them. 3) daemon_apply.go:802-818 still forwards `security flow aging` and screen limit-session config into SetAgingConfig/SetSessionLimitEnabled, sinks that are never read (screen session limits are actually enforced in userspace-dp/src/session/install.rs; aging is documented config-only per #3440). 4) The 10s Run loop and the misleading wiring survive purely to feed GCStats — which is also never written (see the SkipSweep stats finding).

**Why it matters** — Dead-but-wired lifecycle machinery in the session path invites exactly the class of bug this campaign's module notes flag ('GC sweep correctness with HA callbacks'): future contributors patch sweep logic and callbacks that cannot run, while the real session lifetime owner is expire.rs. Engineering-style doctrine here prefers deleting retired paths (cf. #1476 mechanical removal).

**Fix direction** — Retire the sweep body into a thin session-stats sampler over dataplane.SessionStore (also fixing the zero-stats bug), delete the per-IP session-count publisher + sessionCountPublisher interface and the SetAgingConfig/SetSessionLimitEnabled daemon wiring (leaving the #3440 commit-time advisory as the contract), or gate the whole GC construction on a non-userspace backend with a canary.

**Not a duplicate** — Searched issues/prior-findings for SkipSweep/vestigial/conntrack gc. #3604 (CLOSED, fixed) was the config data race; #1515 (CLOSED) tightened the legacy-bridge canary; feature-gaps.md documents the AGING semantics gap (#3440) but nothing proposes retiring the dead sweep/count/callback machinery or notes that ClearSessionCounts has zero callers. Distinct from my SkipSweep zero-stats bug finding (that is behavior; this is structure).

---

#### F-213 · Fabric IPVLAN creation retry sleeps up to 5s synchronously while holding applySem, stalling every concurrent commit/status/HA-sync

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-daemon-lifecycle`  ·  **Location:** `pkg/daemon/daemon_apply.go`:656
- **Labels:** `performance`, `refactor`

```
			var retryErr error
			for retry := 0; retry < 5; retry++ {
				time.Sleep(time.Second)
				slog.Info("retrying fabric IPVLAN creation",
					"parent", parentLinux, "name", fabLinux, "attempt", retry+2)
				retryErr = ensureFabricIPVLAN(parentLinux, fabLinux, addrs)
```

**Runtime trace**

applyConfigLocked runs with applySem held (capacity 1, serializing ALL commit/apply entry points). Inside the fabric-IPVLAN reconcile, if ensureFabricIPVLAN fails on the first try (parent not ready after a power cycle), the code loops up to 5 times with a blocking time.Sleep(time.Second) each — up to 5s of wall time inside the critical section. During that window every HTTP/gRPC commit, cluster config-sync recv, DHCP callback, feed re-apply, and status poll that needs applySem is blocked (the commit wrappers surface 503 to clients on a slow holder).

**Why it matters** — On a firewall boot/power-cycle this can freeze the control plane for 5 seconds exactly when the cluster is trying to converge (heartbeat/session-sync depend on the fabric). A retry loop that blocks the global apply lock amplifies a transient netlink delay into a control-plane stall and 503 storms.

**Fix direction** — Move the bounded retry off the applySem critical path (schedule it via the userspace OnXSKBound callback pattern already used a few lines above, or a background goroutine that re-drives applyConfig), or cap it to a single non-blocking attempt with async re-drive.

**Not a duplicate** — prior-finding [daemon_apply.go] 'Config apply lock over-scoping' (#846-adjacent) covers holding applyLock across the whole compile; this is a distinct, concrete blocking-sleep instance INSIDE the apply, not the compile-scoping theme. Reported narrowly.

---

#### F-214 · Interactive CLI defaults an unknown OS user to super-user RBAC class (fail-open)

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-daemon-lifecycle`  ·  **Location:** `pkg/daemon/daemon_run.go`:1633
- **Labels:** `security`

```
			if !found {
				shell.SetUserClass("super-user")
			}
```

**Runtime trace**

When the interactive CLI starts, Run resolves the OS $USER against cfg.System.Login.Users. If no matching login-user is found (e.g. an out-of-band local account, or an account whose class was removed from config), the code calls shell.SetUserClass("super-user") — granting full super-user CLI privileges by default rather than the most-restricted class.

**Why it matters** — RBAC defaults in a security appliance should fail closed. Any local account able to launch the xpfd interactive CLI that is not explicitly listed in the firewall config is silently granted super-user, which combined with the sudoers-retention gap (F2) widens the privilege-retention surface. Console access already implies significant trust, so impact is bounded, but the fail-open default is the wrong posture.

**Fix direction** — Default an unrecognized user to the most-restricted class (e.g. read-only / unauthorized) and require an explicit login-user entry to grant elevated classes; log the fallback.

**Not a duplicate** — No hit for SetUserClass|super-user|RBAC default in issues/prior-findings. #1944 concerned password provisioning, not the CLI class fallback. Not previously reported.

---

#### F-215 · collectNeighborProbeTargets resolves routing-instance next-hops with VRF-blind netlink.RouteGet — VRF static-route next-hops warm the wrong neighbor (main-table default gateway) or are skipped

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-daemon-net`  ·  **Location:** `pkg/daemon/daemon_neighbor.go`:106
- **Labels:** `bug`, `vrf`, `performance`

```
	addByIPOrConfig := func(ipStr string) {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return
		}
		routes, err := netlink.RouteGet(ip)
		if err == nil && len(routes) > 0 {
			neighborIP := ip
			if gw := routes[0].Gw; gw != nil && !gw.IsUnspecified() {
				neighborIP = gw
			}
			addByLink(neighborIP, routes[0].LinkIndex)
			return
		}
```

**Runtime trace**

(1) Config has `routing-instances red routing-options static route 0/0 next-hop 10.9.9.1` where 10.9.9.0/24 exists only in VRF red's table. (2) collectNeighborProbeTargets iterates cfg.RoutingInstances (lines 172-194) and calls addByIPOrConfig("10.9.9.1"). (3) netlink.RouteGet issues RTM_GETROUTE with no VRF/table/oif scoping → the kernel resolves in the MAIN table. Because a main-table default route almost always exists, the lookup SUCCEEDS with the WAN default gateway: neighborIP is rewritten to the main-table gw and addByLink records (wan-gw, wan-ifindex) — the VRF next-hop is never added, and the config-subnet fallback (lines 115-142) that would have found the VRF interface never runs (it is only reached on RouteGet failure). (4) resolveNeighbors / the 15s periodic pass therefore never pre-resolves 10.9.9.1 on the VRF member interface; the first VRF-routed flow eats the full cold ARP/NDP resolution latency this whole subsystem (#1197/#1636) exists to eliminate, on every idle-timeout cycle.

**Why it matters** — VRFs with static routes and next-table/rib-group leaking are first-class advertised features; the neighbor-warmup mechanism silently degrades for exactly those deployments while its logs claim the targets were resolved (against the wrong interface). Same defect family as OPEN #3744 but in an unrelated subsystem and code path.

**Fix direction** — Use netlink.RouteGetWithOptions with the VRF device (resolve the routing-instance's vrf-<name> master ifindex, or set the route lookup oif/table) for next-hops that belong to a routing instance; fall through to the config-subnet scan when the scoped lookup fails.

**Not a duplicate** — Searched 'RouteGet', 'vrf neighbor', 'routing-instance probe' in both corpora: OPEN #3744 is the same VRF-blind-RouteGet class but exclusively in pkg/flowexport (route masks); closed #2493/#2614 are RPM DNS-resolution VRF escapes; closed #2452 is FRR route rendering. No issue or prior finding covers the daemon_neighbor.go probe-target resolver; prior-findings.md has no daemon_neighbor.go entries.

---

#### F-216 · deriveKernelName/pciAddrToEnp synthesizes only the 'enpXsY[fZ]' name shape — ignores PCI domain, phys_port_name (npX) and slot-based (ensN) udev naming, writing OriginalName= values udev will never match

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-daemon-net`  ·  **Location:** `pkg/daemon/daemon_reth.go`:112
- **Labels:** `bug`, `bare-metal`, `vsrx-parity`

```
func pciAddrToEnp(pciAddr string) string {
	parts := strings.SplitN(pciAddr, ":", 3)
	if len(parts) != 3 {
		return ""
	}
	bus, err := strconv.ParseUint(parts[1], 16, 16)
...
	if fn > 0 {
		return fmt.Sprintf("enp%ds%df%d", bus, slot, fn)
	}
	return fmt.Sprintf("enp%ds%d", bus, slot)
```

**Runtime trace**

(1) deviceMapOriginalNameFor (device_map.go:98-109) falls back to deriveKernelNameFn when a mapped NIC already wears its final logical name and its .link was lost (documented 'second+ boot whose .link was lost' case). (2) deriveKernelName → pciAddrToEnp converts e.g. 0000:09:00.0 to 'enp9s0'. But on the project's own standalone test VM that port's real udev name is 'enp9s0f0np0' (multi-port i40e appends phys_port_name); on virtio/hotplug-slot hardware udev prefers ID_NET_NAME_SLOT ('ens3', not derivable from the PCI address at all); on multi-domain bare metal (the #1956 target) domain!=0 yields 'enP2p1s0' while parts[0] is silently discarded. (3) The wrong name is written into 10-xpf-<logical>.link as OriginalName=; on next boot udev matches nothing, the NIC boots under its kernel name, and every .network referencing the xpf name is inert until the daemon's runtime rename runs — extending the early-boot window where the interface (possibly the operator-mapped management NIC on bare metal) is unconfigured. ensureRethLinkOriginalName has the same fallback (daemon_reth.go:63) though its AltNames scan usually saves it.

**Why it matters** — Device-map mode exists specifically for bare-metal fleets where NIC naming is exotic (multi-port, SmartNIC, non-zero domains); a synthesized-name fallback that only reproduces the simplest enpXsY shape quietly undermines the .link boot-persistence contract on exactly that hardware. The codebase already fixed this class once for stranded NICs by switching to `udevadm info` (predictableName, device_map.go:614-639 — 'Codex r3 MEDIUM'), but deriveKernelName remains a naive parallel resolver.

**Fix direction** — Route deriveKernelNameFn through the same udevadm-property ladder as predictableName (ID_NET_NAME_ONBOARD > SLOT > PATH via `udevadm info --path=/sys/class/net/<name>`), keeping the sysfs synthesis only as a last-ditch fallback when udevadm is unavailable.

**Not a duplicate** — Searched 'deriveKernelName', 'pciAddrToEnp', 'OriginalName', 'predictable' in both corpora: closed #1956 (device-map design) and its AGY r3 MAJOR (don't synthesize enpXsY for CURRENT-name recording) fixed the current!=logical arm at HEAD; the synthesized-shape limitation of the current==logical fallback and the RETH .link fallback is uncovered. prior-findings.md has no daemon_reth.go entries.

---

#### F-217 · applyMgmtVRFRoutes: two management DHCP leases of one family clobber each other's table-999 default route in random map order; stale routes never withdrawn

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-daemon-svc`  ·  **Location:** `pkg/daemon/daemon_flow.go`:59
- **Labels:** `bug`

```
	for _, lease := range d.dhcp.Leases() {
		if !lease.Gateway.IsValid() || !d.mgmtVRFInterfaces[lease.Interface] {
			continue
		}
...
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
			Gw:        net.IP(gwSlice),
			Table:     mgmtTableID,
		}
		if err := nlh.RouteReplace(route); err != nil {
```

**Runtime trace**

mgmtVRFInterfaces covers fxp*/fab*/em* (daemon_apply.go:537-544). Configure DHCPv4 on two of them (e.g. fxp0 plus a DHCP-addressed em0/fab0 lab management segment). Every applyMgmtVRFRoutes pass (each commit + each management-only DHCP change via onDHCPAddressChange) iterates d.dhcp.Leases() — a Go map-ordered slice — and for EACH lease issues RouteReplace{Dst:0.0.0.0/0, Table:999}. The kernel keys replace on dst+table, so the second lease's route overwrites the first's; which gateway wins flips with map iteration order across passes → the management VRF default route flaps between two uplinks nondeterministically (breaking long-lived SSH/heartbeat sessions through the loser). Additionally the function is add-only: when a lease disappears (client stopped, interface deconfigured) no RouteDel is issued, so a dead-gateway default persists in table 999 until the link itself is removed.

**Why it matters** — The management VRF is the operator lifeline; a nondeterministically flapping or stale default route there is precisely the failure that locks operators out during incident response.

**Fix direction** — Make it a reconcile: sort leases deterministically, pick one route per (family, table) with a defined preference (or per-interface metrics), and delete table-999 defaults whose lease is gone (RouteListFiltered on table 999 → diff).

**Not a duplicate** — Searched issues-all.txt for 'mgmt', 'management vrf', 'table 999' (only #2915, unrelated queue-planner) and prior-findings.md for 'mgmt' (none). The #1715-era DNS/mgmt work covered resolv.conf, not VRF route reconcile. Unfiled.

---

#### F-218 · DHCP client ignores server-supplied renewal timers (v4 options 58/59, v6 IA_NA/IA_PD T1/T2), always deriving T1/T2 from lease/valid-lifetime

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-dhcp`  ·  **Location:** `pkg/dhcp/dhcp.go`:908
- **Labels:** `vsrx-parity`, `bug`

```
	// Lease time
	lt := ack.IPAddressLeaseTime(3600 * time.Second) // default 1 hour
	lease.LeaseTime = lt
```

**Runtime trace**

1) leaseFromACKv4 reads only IPAddressLeaseTime (option 51) from the ACK (dhcp.go:908); it never reads OptRenewTimeValue (58) or OptRebindingTimeValue (59). 2) renewalTimers (commit.go:47) then hardcodes T1 = leaseTime/2 (min 30s) and T2 = leaseTime*7/8. 3) A server that intentionally sets option 58=120s / option 59=180s on a 3600s lease (e.g. to force fast renewal for HA/renumber) is ignored — the client renews at 1800s, 15x later than directed. 4) parseV6Reply (dhcp.go:1197+) similarly never reads the OptIANA/OptIAPD T1/T2 fields and reuses the same valid-lifetime-derived timers. Junos honors 58/59 and the IA T1/T2.

**Why it matters** — Server operators use option 58/59 (and IA T1/T2) to control renewal cadence; ignoring them defeats server-driven fast-renewal and load-spreading, and diverges from vSRX behavior. Low severity because the default-derived timers still function.

**Fix direction** — In leaseFromACKv4 read options 58/59 when present and thread them into renewalTimers as explicit T1/T2 overrides; in parseV6Reply capture OptIANA.T1/T2 (and OptIAPD.T1/T2) and use them for the renew/rebind waits, falling back to the 50%/87.5% defaults only when absent/zero.

**Not a duplicate** — Searched for T1/T2/renewal-time/option 58/59. #2994 and #1777 addressed the renewal EXCHANGE (DORA-vs-RENEW) and lease-preservation, not the timer SOURCE. No open/closed issue or prior finding covers honoring option 58/59 or IA T1/T2 — this is the residual timing gap left after #2994's exchange fix.

---

#### F-219 · DHCP relay overwrites a non-zero incoming giaddr (breaks cascaded relay chains) and inserts only Option 82 circuit-id (no remote-id)

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-dhcp`  ·  **Location:** `pkg/dhcprelay/relay.go`:1031
- **Labels:** `vsrx-parity`, `bug`

```
			// Set giaddr to our interface IP so the server knows where to reply.
			pkt.GatewayIPAddr = giaddr
```

**Runtime trace**

1) A BOOTREQUEST reaches this relay with a non-zero giaddr already set by a downstream relay agent (a two-hop relay topology). 2) After the hop-count check, relay.go:1031 unconditionally assigns pkt.GatewayIPAddr = giaddr, discarding the downstream relay's address. RFC 1542 §4.1.1 requires a relay to leave a non-zero giaddr unchanged (only setting it when zero). 3) The server now replies to THIS relay's giaddr instead of the originating relay's, so the reply never returns to the downstream client — the chained relay path is broken. Separately, addOption82 (relay.go:1310) inserts only sub-option 1 (circuit-id = interface name); it never inserts sub-option 2 (remote-id), which Junos dhcp-relay emits by default, so servers keyed on remote-id see no identifier.

**Why it matters** — Cascaded DHCP relay (relay-of-relay) is a valid deployment; overwriting giaddr silently blackholes it. The missing remote-id is an Option 82 parity gap vs vSRX. Both are low severity because single-hop relay (the common case) is unaffected.

**Fix direction** — Only set pkt.GatewayIPAddr when the incoming giaddr is zero (`if pkt.GatewayIPAddr == nil || pkt.GatewayIPAddr.Equal(net.IPv4zero)`); leave a non-zero giaddr intact. Optionally add a configurable Option 82 remote-id sub-option for Junos parity.

**Not a duplicate** — Searched for giaddr/option 82/circuit/remote-id/relay hop. #2076 (broadcast-flag reply delivery), #2153 (INFORM), #2789 (DECLINE), #2645 (FORCERENEW), #2456 (HA master gate) all cover message-type relaying, not the RFC 1542 non-zero-giaddr preservation rule or the remote-id sub-option. No prior finding covers either mechanism.

---

#### F-220 · generatePolicyOptions derives per-term FRR prefix-list names as name+"-"+term.Name, which is not injective — policy 'foo' term 'bar-x' and policy 'foo-bar' term 'x' collide on one FRR list, cross-contaminating route-filter matches

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-frr-routing`  ·  **Location:** `pkg/frr/policy_render.go`:1657
- **Labels:** `bug`, `routing`, `frr`

```
			plName := name + "-" + term.Name
			v4rf, v6rf := partitionRouteFiltersByFamily(term.RouteFilters)
			mixedFamily := len(term.RouteFilters) > 0 && len(v4rf) > 0 && len(v6rf) > 0
```

**Runtime trace**

Config: `policy-options policy-statement wan term backup-v4 from route-filter 10.0.0.0/8 orlonger then accept` and `policy-options policy-statement wan-backup term v4 from route-filter 192.168.0.0/16 orlonger then reject`. Both terms derive plName == "wan-backup-v4". renderRouteFilterEntry writes both terms' entries into the SAME FRR list name with seq (idx+1)*5 — both first entries are seq 5, so under vtysh sequential load the later `ip prefix-list wan-backup-v4 seq 5 permit 192.168.0.0/16 le 32` REPLACES the earlier 10.0.0.0/8 entry. Policy `wan`'s route-map sequence still emits `match ip address prefix-list wan-backup-v4`, which now matches 192.168.0.0/16 instead of 10.0.0.0/8: policy `wan` accepts the wrong prefix set and policy `wan-backup` denies routes on a list polluted by the other policy. Hyphens are ubiquitous in Junos identifiers, so the collision needs no exotic naming. The same non-injective join also affects the _v4/_v6 split names (plName+"_v4").

**Why it matters** — Silent cross-policy match corruption in BGP/OSPF routing policy is a route-leak/blackhole primitive; because the rendered lines are individually FRR-valid, frr-reload applies them cleanly and nothing warns.

**Fix direction** — Use an unambiguous encoding (e.g. name + "~" + term.Name with '~' rejected in identifiers, or index-based names rm-<psIdx>-<termIdx>), or detect plName collisions during render and suffix a disambiguator; add a regression test with hyphenated policy/term names.

**Not a duplicate** — Searched 'prefix-list', 'plName', 'route-map', 'collision' in issues-all.txt/prior-findings.md: #2607/#2071/#2103/#2105/#2525/#2641/#2642 (all CLOSED) cover family split, matcher family, ge/le validity, merge/overwrite of duplicate DEFINITIONS — none covers the derived-name collision between distinct (policy, term) pairs. Nearest is #2641 (duplicate named prefix-list blocks overwrite) which concerns operator-named lists, not the renderer's synthetic name derivation.

---

#### F-221 · `pre-shared-key hexadecimal` is silently mishandled end-to-end: hex digits rendered as ASCII text (or dropped entirely in block form) instead of swanctl 0x hex secret

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-ipsec-wg`  ·  **Location:** `pkg/ipsec/policy.go`:238
- **Labels:** `vsrx-parity`, `bug`

```
			fmt.Fprintf(&b, "    secret = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(decoded)))
// crypto.go normalizePSK — the only secret normalization:
func normalizePSK(secret string) (string, error) {
	if strings.HasPrefix(secret, junosSecretMagic) {
		return decodeJunosSecret(secret)
	}
	return secret, nil
}
```

**Runtime trace**

Junos supports `set security ike policy P pre-shared-key hexadecimal deadbeef01` (key material = raw bytes). xpf schema (schema_security.go:705 'pre-shared-key' has nil children => untyped subtree) accepts it at commit. Compact-hierarchical shape: compiler_ipsec.go:80 `if len(p.Keys) >= 3 { pol.PSK = Secret(p.Keys[2]) }` stores the hex STRING without recording the encoding -> renderConfig -> normalizePSK passes it through (only $9$ handled) -> `secret = "deadbeef01"` -> strongSwan treats the quoted value as ASCII text, not bytes -> PSK mismatch vs a peer configured with the actual hex key -> AUTHENTICATION_FAILED with zero diagnostics. Flat-set/block shape (`pre-shared-key { hexadecimal ...; }`): the children loop matches only `ascii-text` (compiler_ipsec.go:84) -> PSK stays empty -> connection rendered with `auth = psk` and no secret at all.

**Why it matters** — Interop parity: a vSRX config using hexadecimal PSKs (common when keys are machine-generated) commits cleanly and then fails IKE auth at runtime with no hint that the key encoding was dropped; swanctl natively supports `secret = 0x<hex>` so the fix is mechanical.

**Fix direction** — Carry the PSK encoding through config (e.g. PSKHex bool or store as '0x'-prefixed), render hex secrets as unquoted `secret = 0x<hex>`, and make the compiler/validator reject unrecognized pre-shared-key sub-keywords instead of silently ignoring them.

**Not a duplicate** — Grepped issues-all.txt for hexadecimal/hex PSK/pre-shared-key: only #157 [CLOSED] ($9$ ascii-text decryption — different encoding path, fixed at HEAD via crypto.go) and #2126 (quoting). No coverage of the hexadecimal keyword.

---

#### F-222 · FindExternallyManaged only detects .network files that match by Name= — MAC/Path/Driver/Type-matched external mgmt configs are not recognized

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-networkd-mon`  ·  **Location:** `pkg/networkd/networkd.go`:372
- **Labels:** `bug`, `refactor`

```
			if strings.HasPrefix(line, "Name=") {
				ifName := strings.TrimSpace(strings.TrimPrefix(line, "Name="))
				if ifName != "" {
					result[ifName] = true
				}
			}
```

**Runtime trace**

findExternallyManaged parses each non-xpf .network and records only interfaces named by a literal `[Match] Name=` directive. systemd .network files very commonly match by `MACAddress=`, `Path=`, `Driver=`, or `Type=` instead (e.g. a cloud-init or vendor mgmt config keyed on MAC). Such a file protects a real management interface, but FindExternallyManaged returns an empty/partial set for it. In Apply, the `if ifc.Unmanaged && external[ifc.Name]` skip (networkd.go:129) then does NOT fire, so xpf writes a 10-xpf-<name>.network with ActivationPolicy=always-down for that interface and the compiler_iface.go unmanaged path brings it DOWN and strips its addresses — potentially disconnecting a mgmt interface that an external MAC-matched config was managing. The #1922 protected-set is the primary lifeline defense, but the external-config detection (a secondary, operator-authored protection) is defeated by any non-Name match rule.

**Why it matters** — Operators expect an existing systemd .network (however it matches) to keep xpf's hands off that NIC. Matching only on Name= silently narrows that contract and can bring down an externally-managed interface.

**Fix direction** — Parse the full [Match] section: resolve MACAddress=/Path=/Driver=/Type= against live links (netlink) and add the resolved interface names to the external set, or at minimum document that only Name= match protects an interface.

**Not a duplicate** — Not in issues-all.txt (networkd issues are #2988/#2987/#2986/#1798, all about generation/sweep/DHCP/description, none about external-config match granularity). Novel.

---

#### F-223 · LLDP shutdown advertisement (TTL=0) is inserted/refreshed into the neighbor cache instead of removing the neighbor (IEEE 802.1AB deviation)

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-networkd-mon`  ·  **Location:** `pkg/lldp/lldp.go`:494
- **Labels:** `bug`, `vsrx-parity`

```
		neighbor.ExpiresAt = time.Now().Add(time.Duration(neighbor.TTL) * time.Second)

		key := fmt.Sprintf("%s/%s/%s", iface.Name, neighbor.ChassisID, neighbor.PortID)
		m.mu.Lock()
		m.neighbors[key] = neighbor
```

**Runtime trace**

Per IEEE 802.1AB, a received LLDPDU with TTL=0 is a 'shutdown' frame: the receiver must delete the matching neighbor immediately. #2551 correctly made ParseTLVs ACCEPT a 2-byte TTL of 0 (hasTTL=true), but rxLoop then stores the neighbor with ExpiresAt = now+0 = now. So a departing neighbor's shutdown frame OVERWRITES its existing (long-TTL) entry with ExpiresAt=now, and the entry lingers until the next expiryLoop tick (up to 10s, lldp.go:505) instead of being removed at once. A show in that window still lists the neighbor as present.

**Why it matters** — Minor correctness/parity deviation: `show lldp neighbors` shows a device as up for up to 10s after it explicitly announced shutdown. vSRX removes it immediately.

**Fix direction** — In rxLoop, if neighbor.TTL == 0, delete(m.neighbors, key) instead of inserting; that both honors the shutdown semantics and avoids caching a dead entry.

**Not a duplicate** — #2551 (CLOSED) made ParseTLVs accept TTL=0 as a valid shutdown parse but did NOT add the delete-on-zero behavior in rxLoop; that residual is a genuinely new shape. Named the prior issue and the exact mechanism difference (accept vs act-on).

---

#### F-224 · LLDP transmit-interval and hold-multiplier have no schema range validation; advertised TTL (interval*holdMult) truncated to uint16 and can wrap

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-networkd-mon`  ·  **Location:** `pkg/config/schema_routing.go`:456
- **Labels:** `vsrx-parity`, `bug`, `test-gap`

```
		"transmit-interval": {desc: "Transmit interval", args: 1, placeholder: "<seconds>", children: nil},
		"hold-multiplier":   {desc: "Hold multiplier", args: 1, placeholder: "<multiplier>", children: nil},
```

**Runtime trace**

Neither leaf has a validator (compare the RA/sampling leaves in the same file which use ValidateInteger/ValidateIntegerMin). compileProtocols just strconv.Atoi's the value (compiler_protocols.go:35,41) and silently keeps 0 on garbage. txLoop computes `ttl := int(interval.Seconds()) * holdMult` (lldp.go:374) and encodeTTL does `binary.BigEndian.PutUint16(val, uint16(seconds))` (lldp.go:637). With interval=20000, holdMult=4, ttl=80000 -> uint16 wrap = 14464: neighbors expire our advertisement after ~14464s instead of 80000s, or worse, a wrap to a tiny value causes premature flap. Junos bounds transmit-interval to 5..32768 and hold-multiplier to 2..10; xpf accepts any int, so `commit` cannot reject an out-of-range value and the wire TTL silently wraps.

**Why it matters** — vSRX rejects out-of-range LLDP timers at commit; xpf accepts them and emits a wrapped/garbage TTL, so neighbors mistime our liveness. Parity + a wire-boundary integer-truncation bug.

**Fix direction** — Add ValidateInteger(5,32768) to transmit-interval and ValidateInteger(2,10) to hold-multiplier in schema_routing.go; clamp ttl to <=65535 in txLoop as defense in depth.

**Not a duplicate** — No issue in issues-all.txt covers lldp timer validation or TTL wrap (lldp issues are #2992/#2608/#2551/#2372/#2036/#2035). Distinct from those. Novel.

---

#### F-225 · RT_FLOW structured `session-id` is a daemon-local monotonic log counter → SESSION_CREATE and SESSION_CLOSE for the same flow carry different ids and it resets on restart

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-obs`  ·  **Location:** `pkg/logging/ringbuf.go`:621
- **Labels:** `vsrx-parity`, `observability`, `bug`

```
// Assign monotonic session ID
rec.SessionID = atomic.AddUint64(&er.sessionSeq, 1)
```

**Runtime trace**

logEvent runs for every event frame (open, close, deny, ...). Line 621 assigns rec.SessionID by incrementing a per-EventReader atomic counter, and formatStructuredMsg emits it as `session-id="%d"` (ringbuf.go:1062/1091) and into the binary record. Because the counter increments per RECORD, the SESSION_CREATE frame for a flow gets sequence N and the later SESSION_CLOSE frame for the SAME flow gets a different sequence M — the two RT_FLOW lines a SIEM must join by session-id do not share one. The counter also starts at 0 every daemon start, so ids are not stable across restarts and can repeat after a restart. The wire frame carries no dataplane session id, so nothing ties create↔close except the 5-tuple.

**Why it matters** — Junos RT_FLOW_SESSION_CREATE/CLOSE share a stable session-id specifically so collectors correlate the open and close of one session; here the exported id is a non-correlatable log-sequence, silently breaking that Junos-parity contract for anyone building session-lifetime analytics on the syslog feed.

**Fix direction** — Carry a stable per-session id from the dataplane on the create/close frames (or derive a deterministic id from the flow key + creation time) and use it for both create and close instead of a per-record atomic; document that the field is a monotonic sequence if a real id cannot be sourced.

**Not a duplicate** — Searched issues/prior-findings for session-id/correlat/RT_FLOW. #3337 (REST/SSE/gRPC dropped session-id among other fields) and #2615 (create/close omit AppID/ifindex) touch RT_FLOW field completeness but not the create-vs-close non-correlatability of the synthesized session-id. #3713 is about duplicate policy_id aliasing, unrelated. Novel angle.

---

#### F-226 · SNMP trap-group `categories` parsed but never stored/honored — every trap-group receives only link traps regardless of configured category filter

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-obs`  ·  **Location:** `pkg/config/types_system.go`:518
- **Labels:** `vsrx-parity`, `config-drop`

```
type SNMPTrapGroup struct {
	Name    string
	Targets []string // IP addresses
}
```

**Runtime trace**

schemaSNMP (schema_system.go:855) accepts `set snmp trap-group X categories <cat>` as a multi leaf, so it commits clean. SNMPTrapGroup has no Categories field, so the value is discarded at compile. sendLinkTraps (traps.go:164) enqueues to EVERY trap group's targets unconditionally — there is no category gate, and only link up/down traps exist. An operator who scopes a trap-group to a category (e.g. `configuration`, `authentication`) still receives link traps, and any future non-link trap would ignore the filter.

**Why it matters** — Junos trap-group categories select which notification classes go to which managers; silently accepting and dropping the filter is a config-drift parity gap that will misroute traps as soon as more trap classes ship, and today misrepresents intent (a link-only manager still gets link traps only by accident).

**Fix direction** — Add Categories to SNMPTrapGroup, compile it, and gate trap dispatch on category membership; until more trap classes exist, at minimum reject/warn on a categories value that excludes 'link' so intent is not silently ignored.

**Not a duplicate** — feature-gaps.md documents 'Missing trap classes: authentication-failure, cold/warm-start, HA role change' as a known partial, but that is about UNIMPLEMENTED trap TYPES; this finding is the distinct config-drop that the `categories` leaf is parsed-then-dropped with no field to hold it (same shape as the version gap above). Not covered by #2990/#2989.

---

#### F-227 · InstallCandidateKernel never resolves the actual uname -r: the /lib/modules stat is dead code and both branches return the input version

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-ops`  ·  **Location:** `pkg/upgrade/kernel_linux.go`:236
- **Labels:** `bug`, `refactor`, `upgrade`

```
	// The candidate's uname -r is the requested version when the standard
	// "<version>" naming holds; prefer the actual /lib/modules dir if present.
	if _, err := os.Stat(filepath.Join("/lib/modules", version)); err == nil {
		return version, nil
	}
	return version, nil
```

**Runtime trace**

KernelSystem.InstallCandidateKernel documents 'returns the installed kernel's uname -r form', and the caller relies on it: installCandidate (kernel_run.go:242-248) records the return into j.CandidateVersion with the comment 'it may differ from the apt version arg'. But both return paths at kernel_linux.go:236-239 return the caller-supplied `version` verbatim — the os.Stat guard selects between two identical returns, so the 'resolve the real uname -r' contract is unimplemented. If an operator arms with a package-version-style string that installs successfully but whose uname -r differs (e.g. a meta/flavor package name resolving to a concrete ABI kernel), the journaled CandidateVersion is wrong; on the candidate boot, Promote Gate 2 (kernel_run.go:381: running != j.CandidateVersion) reverts a perfectly healthy candidate — a spurious full reboot cycle. Today the failure is mostly masked because pkgs are constructed as linux-image-<version> (apt fails outright on a non-uname arg), but the dead branch means the documented safety net does not exist.

**Why it matters** — The kernel channel's whole design hinges on CandidateVersion exactly matching the candidate boot's uname -r; a silent contract gap here converts operator input drift into an unnecessary revert-reboot of a production firewall node, and the dead stat misleads reviewers into believing resolution happens.

**Fix direction** — Actually resolve: after install, glob /lib/modules for the newly-installed kernel (or parse `dpkg -L linux-image-<version>` for /boot/vmlinuz-*) and return that uname -r when it differs from the arg; or delete the dead stat and hard-validate that /lib/modules/<version> exists, erroring out otherwise so the mismatch is caught pre-arm instead of post-reboot.

**Not a duplicate** — Searched issues-all.txt for kernel upgrade/uname/InstallCandidate — #1930 (CLOSED, the feature umbrella) and its review rounds (r1 Codex High items are cited in-file for OTHER aspects: modules-extra, rehold). prior-findings.md has no pkg/upgrade kernel_linux entries. The dead-stat/unfulfilled-contract shape is unreported.

---

#### F-228 · show chassis forwarding Uptime reports xpfd control-daemon uptime, not the forwarding helper's — helper crash/respawn is invisible

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-ops`  ·  **Location:** `pkg/fwdstatus/builder.go`:73
- **Labels:** `vsrx-parity`, `observability`

```
	if hasProcStat {
		pidStart := time.Unix(int64(stat.BootTime)+int64(selfStat.StartTimeTicks)/userHZ, 0)
		fs.Uptime = time.Since(pidStart)
	} else {
		// Fallback: in-memory daemon start time.  Differs from true
		// PID-start by ms at most.
		fs.Uptime = time.Since(startTime)
	}
```

**Runtime trace**

xpf-userspace-dp (the actual forwarding daemon, vSRX flowd analog) crashes at T and is respawned by the manager. Operator runs `show chassis forwarding` at T+1m: Build() computes Uptime from /proc/SELF/stat of xpfd (builder.go:68-80) — days of uptime — while State/heartbeats/Buffer% on the same screen come from the freshly-restarted helper's Status(). The screen shows 'State Online ... Uptime: 12 days' with no hint the dataplane process restarted 60 seconds ago, even though ProcessStatus.StartedAt (protocol.go:1241) carries the helper's true start time and is already fetched in the same Build() call (usStatus, builder.go:160-168). On vSRX the FWDD uptime row resets when flowd restarts — it is the operator's primary tell for dataplane crashes.

**Why it matters** — The 'FWDD status' screen exists to diagnose the forwarding daemon; masking helper restarts behind the control daemon's uptime hides exactly the incident class (helper OOM/panic/respawn loops) the row is consulted for on a production appliance.

**Fix direction** — On the userspace path, when usErr==nil and usStatus.StartedAt is non-zero, set fs.Uptime = time.Since(usStatus.StartedAt) (fold into the existing Status() fetch); keep the xpfd-PID fallback for the not-running/eBPF paths. Update pkg/fwdstatus/README.md and the Format tests.

**Not a duplicate** — Searched issues-all.txt for 'show chassis forwarding'/uptime — #877 (CLOSED) introduced the screen with this semantics and #879/#881 (CLOSED) reworked peer rendering and CPU windows without touching Uptime; no issue tracks helper-vs-daemon uptime. prior-findings.md has no fwdstatus finding at all.

---

#### F-229 · PrepareLinkCycle swallows stop_workers failure (void return, no rollback) and the intended rollback helper reEnableUserspaceCtrlLocked is dead code — a failed worker-stop leaves ctrl disabled and lets the caller proceed with the link DOWN/UP the function exists to guard

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-usdp-core`  ·  **Location:** `pkg/dataplane/userspace/process.go`:1049
- **Labels:** `bug`, `refactor`, `vsrx-parity`

```
	m.disableUserspaceCtrlLocked()
	// Tell the Rust helper to stop all workers. This joins worker
	// threads so they stop touching UMEM before the NIC unmaps pages
	// during link DOWN.
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "stop_workers"}, &status); err != nil {
		slog.Warn("userspace: stop_workers before link cycle failed", "err", err)
		return
	}
```

**Runtime trace**

During RETH MAC programming the daemon calls userspaceLinkController.PrepareLinkCycle -> Manager.PrepareLinkCycle. It disables ctrl (ctrl=0, transit fail-closed) then sends stop_workers to join the Rust worker threads so no thread touches UMEM during the imminent link DOWN. If stop_workers fails (helper hung/slow — exactly the degraded case), the method logs a Warn and returns void: (1) ctrl stays disabled with no rollback — reEnableUserspaceCtrlLocked (process.go:1000), documented as 'rollback a ctrl disable when the subsequent operation fails', is never called anywhere in the tree; (2) PrepareLinkCycle returns void, so the caller cannot know workers were NOT stopped and proceeds with programRethMAC's link DOWN/UP while worker threads may still be polling UMEM — the mlx5 UMEM-unmap-while-active hazard the function was built to prevent.

**Why it matters** — The UMEM-safety invariant (no worker touches UMEM across a link DOWN) is silently unenforced on the one path where it matters — a stalled helper — and the abandoned rollback path (dead reEnableUserspaceCtrlLocked) is a latent maintenance trap that reads as if rollback exists when it does not.

**Fix direction** — Return an error from PrepareLinkCycle (thread it through LinkController) so the caller can abort or defer the link cycle when workers did not stop; either wire reEnableUserspaceCtrlLocked into the failure path or delete it to remove the false rollback signal.

**Not a duplicate** — grep confirms reEnableUserspaceCtrlLocked has zero callers repo-wide. #580 (standby XSK bindings stuck busy after restart) and #1510 (helper-stop/link-cycle regressions) are CLOSED and about different mechanisms. No prior finding covers PrepareLinkCycle's void-return/swallowed-error or the dead rollback helper.

---

#### F-230 · Forward+reverse session-mirror pair is not atomic against a concurrent DeleteSession pair (m.mu dropped for socket I/O between the two upserts) — interleaving leaves a half-installed synced session in the helper

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-usdp-ha-events`  ·  **Location:** `pkg/dataplane/userspace/manager_ha.go`:1148
- **Labels:** `bug`, `ha`

```
	ctrlReq := ControlRequest{
		Type:           "sync_session",
		SuppressStatus: true,
		SessionSync:    &req,
	}
	m.mu.Unlock()
	err := m.requestSessionSync(ctrlReq)
	m.mu.Lock()
	if err != nil {
		slog.Debug("userspace session sync mirror failed", "operation", req.Operation, "err", err)
	}
```

**Runtime trace**

1) Goroutine G1 runs SetSessionV4(key,val) (manager_ha.go:808): under m.mu it sends the forward upsert via syncSessionV4Locked — which UNLOCKS m.mu around the socket I/O (manager_ha.go:1148) — then relocks and sends the reverse-companion upsert for val.ReverseKey (manager_ha.go:833). 2) In the unlock window, goroutine G2 (conntrack GC delete callback / clear-sessions) runs DeleteSession(key) (manager_ha.go:922): it reads ReverseKey from BPF, deletes the BPF entry, and sends delete(key) + delete(reverseKey) to the helper. Ordering on the dedicated session socket is sessionMu acquisition order, so the wire sees: upsert(fwd), delete(fwd), delete(rev), upsert(rev). 3) Helper-side, sync_session delete with Generation=0 is UNCONDITIONAL (afxdp/ha_tests.rs:691 'delete_synced_session_zero_generation_is_unconditional'; deletes are built with val=nil so req.Generation is 0), so both entries are removed — then G1's trailing reverse upsert re-installs ONLY the reverse companion. 4) Final helper state: a reverse-only SyncedSessionEntry with no forward twin and no BPF backing; there is no aging sweep for the synced store, so it persists until an RG flush or matching future delete, and packets hitting that reverse tuple resolve against stale NAT/zone metadata.

**Why it matters** — HA session-state divergence on the local helper: half-pairs break the invariant that forward/reverse synced entries exist together (the basis of fabric-redirect and failover promotion decisions), and the stale reverse entry can steer post-close traffic with stale metadata. The race window is real under churn: GC deletes race re-installs of the same 5-tuple during failover storms.

**Fix direction** — Send the forward+reverse pair as ONE sync_session request (batch/array form) so the helper applies the pair atomically; or hold a per-key ordering token across both sends (e.g. keep sessionMu across the pair by building both requests first and issuing them under one sessionMu critical section) so a concurrent delete pair cannot interleave between them.

**Not a duplicate** — Searched SetSessionV4/DeleteSession/reverse companion/generation in both corpora. #351 (delete leaves preinstalled reverse behind — fixed by deleting reverseKey), #2170 (wire generation guard) and #2221 (same-generation install/delete reorder on the PEER standby via pkg/cluster) are the nearest priors; all closed. This is a different mechanism: the LOCAL helper-mirror pair's non-atomicity created by the m.mu drop inside syncSessionRequestLocked, which none of those cover (and gen-0 unconditional deletes bypass the #2170 guard entirely).

---

#### F-231 · Helper reconcile zeroes ALL per-binding counters, and safeDelta's aggregate reset heuristic silently discards up to one poll interval of every global flow counter on each snapshot apply / auto-rebind

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-usdp-ha-events`  ·  **Location:** `pkg/dataplane/userspace/manager_ha.go`:801
- **Labels:** `bug`, `observability`

```
// safeDelta returns cur - prev. On counter reset (prev > cur), returns cur
// as the delta so counters don't undercount after helper restarts.
func safeDelta(cur, prev uint64) uint64 {
	if cur < prev {
		return cur // counter reset: treat current cumulative as delta
	}
	return cur - prev
}
```

**Runtime trace**

1) Every snapshot-driven reconcile in the helper calls reset::reset_binding_counters(bindings) (userspace-dp/src/afxdp/coordinator/reconcile/mod.rs:200, reset.rs:9), zeroing rx/tx/session/screen/NAT per-binding counters WITHOUT a helper restart — this fires on config commits that rebind XSK and on the Go manager's maybeAutoRebindBusyBindingsLocked path (process.go:474), which can trigger under load. 2) On the next 1/s status poll, sumBindingCounters yields cur_total < prev_total for every counter; safeDelta returns cur (packets counted since the reset), permanently dropping all packets counted between the previous poll and the reset — up to a full poll interval of rx/tx/forward/session-create/screen-drop/per-reason-screen (#3343)/syncookie/NAT64 deltas per reconcile. 3) The inverse edge also exists early in helper life: if post-reset traffic in the same window exceeds the small pre-reset cumulative total, cur >= prev and delta = cur - prev UNDERCOUNTS by prev without any reset being detected. 4) The aggregate-sum-then-compare design cannot distinguish reset from wrap from binding-set change; only per-binding (Slot-keyed) previous-value tracking can.

**Why it matters** — Counter fidelity on a security appliance: screen-drop and per-reason screen statistics (#3343), syncookie validity counts, and flow statistics feed alerting and forensic baselines; losing a window of drops precisely at each config commit or under auto-rebind (which correlates with attack load) skews exactly the numbers an operator investigates after an event.

**Fix direction** — Track prevBindingCounters per binding Slot (map[uint32]userspaceCounterSnapshot) and compute per-binding safeDelta, treating a missing slot as removed (delta 0) and a decreased slot as reset (delta = cur for that slot only). Alternatively have the helper preserve cumulative binding counters across reconcile (accumulate into a persistent per-slot store before reset).

**Not a duplicate** — Searched counter reset/safeDelta/sumBindingCounters/binding counters in both corpora — no hits; #2218 documents NAT rule counters resetting on helper RESTART (accepted), but nothing covers reconcile-time reset interacting with the Go aggregate delta heuristic. The stronger inflation variant (partial decrease with large residual sum) was investigated and discarded because reconcile resets all bindings together; this bounded-loss residual is what remains.

---

#### F-232 · Router default-lifetime is uint16-truncated by ndp with no commit-time cap, so a committed default-lifetime >= 65536 silently wraps (e.g. 65536 -> 0 = 'not a default router')

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-vrrp-ra`  ·  **Location:** `pkg/ra/sender.go`:671
- **Labels:** `bug`, `config`, `rfc-conformance`

```
	lifetime := s.cfg.DefaultLifetime
	if lifetime <= 0 {
		lifetime = defaultRouterLifetime
	}

	ra := &ndp.RouterAdvertisement{
		CurrentHopLimit:      64,
		ManagedConfiguration: s.cfg.ManagedConfig,
		OtherConfiguration:   s.cfg.OtherStateful,
		RouterLifetime:       time.Duration(lifetime) * time.Second,
```

**Runtime trace**

Schema types default-lifetime as ValidateIntegerMin(1) with no upper bound (schema_routing.go:376). The RA Router Lifetime field is 16 bits; ndp marshals it as uint16(ra.RouterLifetime.Seconds()) (message.go:303-304) with no error on overflow. Config `set protocols router-advertisement interface ge-0-0-1 default-lifetime 65536` commits; buildRA sets RouterLifetime=65536s; ndp truncates uint16(65536)=0. RouterLifetime 0 means 'this router is not a default router' (RFC 4861 §4.2), so hosts remove xpf as their default gateway — the opposite of the operator's intent of a very long lifetime. (Values 65529..65535 additionally trip finding #1 when a nat64prefix inherits this lifetime.)

**Why it matters** — An accepted config value produces the inverse of its intent (default gateway withdrawn) with no error — an IPv6 default-route outage from a one-line commit.

**Fix direction** — Cap default-lifetime at 65535 at commit (and per RFC 4861 recommend <=9000); reject or clamp above that with a warning.

**Not a duplicate** — #2008/#2497 tightened RA leaf typing but neither bounded default-lifetime's upper end nor noted the uint16 wrap. No prior finding references RouterLifetime truncation. Novel residual.

---

#### F-233 · randomAdvInterval can return a 0-second interval when max-advertisement-interval is small, producing a tight advTimer busy-loop / RA storm

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `go-vrrp-ra`  ·  **Location:** `pkg/ra/sender.go`:794
- **Labels:** `bug`, `rfc-conformance`, `performance`, `config`

```
func (s *sender) randomAdvInterval() time.Duration {
	maxI := s.cfg.MaxAdvInterval
	if maxI <= 0 {
		maxI = defaultMaxAdvInterval
	}
	minI := s.cfg.MinAdvInterval
	if minI <= 0 {
		minI = maxI / 3
	}
	if minI >= maxI {
		minI = maxI / 3
	}
	interval := minI + rand.IntN(maxI-minI+1)
	return time.Duration(interval) * time.Second
```

**Runtime trace**

The schema floors max-advertisement-interval at ValidateIntegerMin(1) (schema_routing.go:370), but RFC 4861 §6.2.1 requires MaxRtrAdvInterval>=4s. Config `set protocols router-advertisement interface ge-0-0-1 max-advertisement-interval 1` commits. randomAdvInterval: maxI=1, minI=maxI/3=0 (integer division), interval = 0 + rand.IntN(1-0+1) = rand.IntN(2) ∈ {0,1}. When it returns 0, run() does advTimer.Reset(0) (line 468) which fires immediately on the next loop → sendRA in a tight loop at CPU speed → RA multicast storm on the segment plus a spinning goroutine, until the next interval happens to be 1.

**Why it matters** — A single out-of-RFC-range but schema-accepted value converts a control-plane goroutine into a multicast flood + CPU spin — a self-inflicted DoS on the local L2 that is hard to diagnose from the config.

**Fix direction** — Floor max-advertisement-interval at 4 (RFC 4861) and min-advertisement-interval at 3 with the <=0.75*max relation validated at commit; belt-and-suspenders, clamp the computed interval to a >=1s minimum in randomAdvInterval.

**Not a duplicate** — #2008 typed the RA interval leaves as positive integers (ValidateIntegerMin(1)) but did not enforce the RFC 4861 4s/3s floors nor guard the 0-interval timer. The 0-second busy-loop mechanism is not described in any prior finding. Residual of #2008, distinct mechanism.

---

#### F-234 · Defensive None-queue arms in flow-fair local settle/restore drop UMEM TX frame offsets instead of returning them to free_tx_frames (frame leak if ever reached)

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-cos-tx`  ·  **Location:** `userspace-dp/src/afxdp/cos/queue_service/mod.rs`:1414
- **Labels:** `bug`, `refactor`

```
fn restore_exact_local_scratch_to_queue_head_flow_fair(
    queue: Option<&mut CoSQueueRuntime>,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<(u64, TxRequest)>,
) {
    let Some(queue) = queue else {
        scratch_local_tx.clear();
        return;
    };
```

**Runtime trace**

drain_exact_local_items_to_scratch_flow_fair pops a UMEM offset from free_tx_frames for every scratch entry ((offset, req) pairs, drain.rs:311-330). Both settle_exact_local_scratch_submission_flow_fair (mod.rs:1483-1485) and restore_exact_local_scratch_to_queue_head_flow_fair (mod.rs:1414-1417) handle a None queue by `scratch_local_tx.clear()` — dropping the (offset, req) pairs without pushing the offsets back to free_tx_frames. Every offset in the scratch is permanently lost to the binding's TX frame pool (frames are only recycled via free_tx_frames or the completion ring; these were never submitted). Today the arm is unreachable — the same service call resolved the queue immediately before draining and the worker thread owns the map — but the sibling non-flow-fair settle (settle_exact_local_fifo_submission, line 1449-1451) DOES release frames on its None arm (release_exact_local_scratch_frames), so the flow-fair variants are asymmetrically wrong for the case they claim to defend against. A future refactor that re-resolves the queue across a yield point (e.g. after a reconcile that rebuilds cos_interfaces) would silently bleed TX frames until the pool empties and TX stalls with 'no free TX frame available'.

**Why it matters** — UMEM TX frames are a fixed, non-regenerating pool per binding; a defensive path that leaks them converts a transient inconsistency into permanent TX starvation on a firewall dataplane. Defensive code that is wrong is worse than no defensive code — it documents the wrong recovery.

**Fix direction** — In both None arms, drain scratch and push each offset back onto free_tx_frames (mirroring release_exact_local_scratch_frames) before clearing.

**Not a duplicate** — Grepped issues/prior-findings for free_tx_frames leak / scratch leak — no hits; #2208 (CLOSED) covered ingress-descriptor leaks in dispatch, a different pool and site. No prior coverage of the flow-fair settle/restore None arms.

---

#### F-235 · FIFO exact-queue settle/drop paths bypass cos_queue_pop accounting: local_item_count leaks and sojourn/per-bucket TX stats are skipped (currently-dead code kept for future FIFO adoption)

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-cos-tx`  ·  **Location:** `userspace-dp/src/afxdp/cos/queue_service/mod.rs`:1457
- **Labels:** `bug`, `refactor`, `test-gap`, `performance`

```
    let sent = inserted.min(scratch_local_tx.len());
    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    for _ in 0..sent {
        match queue.hot.items.pop_front() {
            Some(CoSPendingTxItem::Local(req)) => {
                sent_packets += 1;
                sent_bytes += req.bytes.len() as u64;
            }
```

**Runtime trace**

settle_exact_local_fifo_submission pops committed Local items directly via queue.hot.items.pop_front() (line 1457), bypassing cos_queue_pop_known_bucket_inner where local_item_count is decremented (queue_ops/pop.rs:273). Same for the FIFO drain drop paths: drain_exact_local_fifo_items_to_scratch removes Local items via queue.hot.items.remove(index) (drain.rs:75 mirror-reserve, drain.rs:126 drop_error) with no decrement. If this path ever runs, each committed/dropped Local item leaks +1 on local_item_count; once nonzero it never returns to 0, so cos_queue_accepts_prepared (tx/cos_classify.rs:903, `local_item_count == 0`) is permanently false for that queue and every subsequent prepared (zero-copy) frame is force-cloned into a heap Local copy (enqueue_prepared_into_cos fallback) — a persistent per-packet memcpy+alloc regression. The FIFO settle also records no sojourn sample and no account_flow_bucket_tx, silently zeroing per-class latency/rate telemetry on that path. TODAY this is unreachable: promote_cos_queue_flow_fair (admission.rs:525) eagerly allocates flow_fair_state for every exact queue and exact queues never demote, so service_exact_*_queue_direct always takes the flow-fair branch. But the code is kept live deliberately ('#940: FIFO queues currently have vtime_floor=None ... kept ... to shield future flow_fair-FIFO adoption', service.rs:182-184), so any future policy change flipping an exact queue back to FIFO silently activates the counter leak.

**Why it matters** — Latent accounting-corruption trap in shipped (compiled, non-test) code on the CoS TX path of a production firewall: the failure mode is a silent, unrecoverable per-queue performance degradation plus dead telemetry, exactly the class of bug that resists triage because the counters lie.

**Fix direction** — Either delete the four FIFO exact drain/settle variants outright (exact => flow-fair is a build-time invariant now) or route their removals through the cos_queue_pop_* accounting (decrement local_item_count, record sojourn) and pin counter parity with a test that drives the FIFO branch directly.

**Not a duplicate** — Grepped issues-all.txt and prior-findings.md for local_item_count / accepts_prepared — zero hits. Nearest related: #774 (introduced the O(1) counter; its invariant comment claims maintenance 'at every push/pop site' which these direct pops violate) and #1763 (pop API changes). No issue covers the FIFO-path counter desync.

---

#### F-236 · Rust boundary accepts flex_mask == 0, turning a flexible-match constraint into match-all — the #3077 fail-open resurrected via snapshot drift; #3406 validates flex length but not mask

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-filter`  ·  **Location:** `userspace-dp/src/filter/compiler.rs`:474
- **Labels:** `security`, `bug`

```
    if let Some(fm) = snap.flex_match.as_ref() {
        if !(1..=4).contains(&fm.length) {
            return Err(SnapshotIntegrityError::UnrepresentableFilterFlexMatch {
                family: filter_family.to_string(),
                filter: filter_name.to_string(),
                term: snap.name.clone(),
                length: fm.length,
            });
        }
    }
```

**Runtime trace**

parse_term validates only fm.length (1..=4) and stores flex_value pre-masked: `flex_value: map_or(0, |f| f.value & f.mask)` (compiler.rs:678-682). A snapshot carrying mask=0 (never emitted by the current Go builder — compiler_firewall.go:425 derives a nonzero default — but reachable via the tolerant peer-sync / mixed-version / hand-crafted producer path that #3367/#3406/#3232 explicitly defend against) yields flex_value=0, flex_mask=0, flex_enabled=true. matching.rs:149 then computes `(val & 0) == 0` — TRUE for every packet long enough to hold the window. The flexible-match constraint is silently dropped: a lo0 protect-RE term `from flexible-match-range ...; then accept` becomes accept-for-all-matching-5-tuples (fail-open), and a scoped discard term over-drops. This is exactly the pre-#3077 'constraint dropped on the wire' behavior, re-reachable through one unvalidated field while its siblings (length here; tcp-flags #3367; icmp/dscp/flex-width #3406) all fail the snapshot closed.

**Why it matters** — The module's established boundary posture is that every wire field which can silently widen a term must be integrity-checked at parse_term (five precedents in this same function). mask==0 is the one flex field that widens instead of narrowing, and it is the only one unchecked.

**Fix direction** — In parse_term, reject (SnapshotIntegrityError::UnrepresentableFilterFlexMatch or a new variant) a present flex_match with mask == 0, mirroring the length check — or lower it to FlexMatchStart::Unsupported-style fail-closed (never-match) rather than match-all.

**Not a duplicate** — grepped 'flex', 'mask' in issues-all.txt/prior-findings.md. #3203 (CLOSED) fixed the GO default-mask derivation; #3406 (CLOSED) added the Rust length backstop; #3232 (CLOSED) added match-start fail-closed. None validate the mask field at the Rust boundary — verified at HEAD parse_term checks only length; new residual in the same defense-in-depth family, different field and direction (widening).

---

#### F-237 · NAT64 embedded-error translation rewrites the quoted inner packet's length field to the TRUNCATED quote length instead of translating the original Total Length/Payload Length (RFC 7915 §4.3/§5.3)

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-nat`  ·  **Location:** `userspace-dp/src/nat64.rs`:1598
- **Labels:** `bug`, `rfc-conformance`

```
    // Quoted L4 bytes after the IPv4 header, capped by the advertised total
    // length and what was actually quoted.
    let end = total_len_field.clamp(ihl, quote_in.len());
    let l4 = quote_in.get(ihl..end)?;
    let l4_len = l4.len();

    let total = 40 + l4_len;
    let out = dst.get_mut(..total)?;
```

**Runtime trace**

A v4 server/router emits an ICMPv4 Time Exceeded quoting only the first 48 bytes (20-byte header + 28 bytes) of a 1400-byte original datagram; the quoted IPv4 header still advertises Total Length 1400, as ICMP quoting preserves the original header verbatim. write_v4_to_v6_into -> translate_icmpv4_message_to_icmpv6 -> translate_embedded_v4_to_v6 (nat64.rs:1562-1615): end = total_len_field.clamp(ihl, quote_in.len()) = 48, l4_len = 28, and line 1598 writes out[4..6] = 28 — the translated embedded IPv6 header now advertises Payload Length 28 instead of the translated original 1400-20 = 1380. The v6->v4 twin (translate_embedded_v6_to_v4, nat64.rs:1533) has the same defect: embedded IPv4 Total Length = 20 + truncated-quote-l4 instead of original payload_len + 20. RFC 7915 §4.3 requires the packet-in-error be 'translated just like a normal IP packet', i.e. the length field derived from the inner header's own advertised length +/-20 (reference translators Jool and Tayga adjust the original field); receivers and diagnostic tools reading the quote see a header describing a different (shorter) datagram than the one that elicited the error.

**Why it matters** — The embedded header is the only forensic record of the offending packet. Stacks or middleboxes that sanity-check quote consistency, and diagnostics like tracebox/PMTUD-blackhole analysis that compare the quoted Total Length against the advertised MTU, get corrupted data after NAT64 — subtle interop deviations vs vSRX and reference translators.

**Fix direction** — Compute the embedded length fields from the inner header's ORIGINAL advertised length: v4->v6 embedded Payload Length = total_len_field - ihl (unclamped by quote size); v6->v4 embedded Total Length = original inner payload_len + 20 - stripped-ext-header bytes. Keep the copied byte count clamped to the quote as today.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for 'embedded', 'quoted', 'truncat', '2371', '2219'. Nearest: #2371 (CLOSED, embedded TRANSPORT CHECKSUM in error translation — resolved as the documented leave-as-is decision in nat64.rs:1473-1475) and #2219 (error translation existence). Neither covers the embedded IP-header LENGTH field being rewritten to the truncated quote length; no issue/finding mentions it.

---

#### F-238 · NAT64 translates FIRST-fragment ICMPv6 messages with a fragment-scoped checksum instead of dropping them — RFC 7915 §1.2 says fragmented ICMP is never translated

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-nat`  ·  **Location:** `userspace-dp/src/nat64.rs`:836
- **Labels:** `bug`, `rfc-conformance`

```
    let l4_len = if l4_protocol == PROTO_ICMPV6 {
        // The embedded (quoted) original packet is the RETURN-direction packet:
        // its addresses are the outer error's addresses swapped, so v6->v4 the
        // embedded src maps to `dst_v4` and the embedded dst maps to `snat_v4`.
        let embedded = EmbeddedV6ToV4 {
            mapped_embedded_src: dst_v4,
            mapped_embedded_dst: snat_v4,
        };
        translate_icmpv6_message_to_icmpv4(&mut out[20..], l4_payload, &embedded)?
```

**Runtime trace**

A v6 client sends `ping -s 3000` through NAT64; the kernel fragments at 1500. The first fragment (Fragment Header, offset 0, MF=1) carries the ICMPv6 echo header, so ipv6_is_non_first_fragment (nat64.rs:763) passes and the ext-header walk yields l4_protocol=58. write_v6_to_v4_into maps it to PROTO_ICMP and calls translate_icmpv6_message_to_icmpv4 (line 836/844): the echo arm copies the fragment's bytes and finalize_icmpv4_checksum (nat64.rs:1640-1647) sums ONLY the first fragment's slice — but a fragmented ICMPv4 message's checksum field must cover the ENTIRE reassembled ICMP message, so the emitted first fragment carries a checksum that can never verify. The remaining fragments are dropped at nat64.rs:763 regardless, so the v4 target accrues reassembly-buffer state per attempt until timeout while the v6 client sees silent loss. RFC 7915 §1.2 (verified in the RFC text): 'Fragmented ICMP/ICMPv6 packets will not be translated by IP/ICMP translators' — the correct behavior is an explicit drop of the first fragment too, not emission of a poisoned fragment. Same applies on the v4->v6 side, where the code comment (nat64.rs:1090-1094) already concedes fragmented ICMP keeps a zeroed checksum ('degenerate edge').

**Why it matters** — The translator emits provably-corrupt packets (wasted upstream bandwidth, remote reassembly-state consumption on the v4 server per large-ping attempt) instead of failing closed, and the behavior diverges from RFC 7915's explicit exclusion; an explicit drop would also make the loss observable via a counter rather than a mystery timeout.

**Fix direction** — In write_v6_to_v4_into and write_v4_to_v6_into, return None (drop, with a dedicated counter) when frag_info/is_fragment is set AND the terminal protocol is ICMPv6/ICMP, replacing the current translate-with-wrong-checksum behavior; remove the 'degenerate edge is moot' comment in favor of the explicit gate.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for '2488', '2562', 'fragmented icmp', 'fragment'. #2488 (CLOSED) added TCP/UDP fragment translation and left the ICMP-fragment arm as an acknowledged-in-comment degenerate edge on the v4->v6 side only; #2562 (OPEN) is the non-first-fragment SNAT cache for TCP/UDP pass-through. Neither proposes the RFC 7915 §1.2 fragmented-ICMP drop, and the v6->v4 wrong-checksum emission is not mentioned anywhere; screen-level `icmp fragment` (#3316) is an optional IDS knob, not the translator default.

---

#### F-239 · NAT64 v4->v6 ICMP error translation has no output-size clamp: a large inbound ICMPv4 error translates to a >1280-byte ICMPv6 error, violating RFC 4443 §2.4(c) and losing the error at any 1280-MTU hop

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-nat`  ·  **Location:** `userspace-dp/src/nat64.rs`:1458
- **Labels:** `bug`, `rfc-conformance`

```
) -> Option<usize> {
    let embedded_in = src.get(8..)?;
    let mut scratch = [0u8; MAX_EMBEDDED_LEN];
    let embedded_len = translate_embedded_v4_to_v6(&mut scratch, embedded_in, embedded)?;

    let total = 8 + embedded_len;
    let out = dst.get_mut(..total)?;
    out[0] = v6_type;
    out[1] = v6_code;
```

**Runtime trace**

A v4 host (hostile or a non-RFC1812 stack quoting the full datagram) sends a 1330-byte ICMPv4 Destination Unreachable (20 IP + 8 ICMP + 1302-byte quote) that matches a NAT64 session. translate_embedded_v4_to_v6 caps the quote at MAX_EMBEDDED_LEN - 20 = 1280 bytes (nat64.rs:1574) and emits an embedded IPv6 packet of 40 + 1260 = 1300 bytes; write_icmpv6_error_with_embedded (nat64.rs:1446-1466) sets total = 8 + 1300 = 1308 with no cap; the outer IPv6 error becomes 40 + 1308 = 1348 bytes. build_nat64_v4_to_v6_frame's over-allocation (input + 40) fits it, so a 1348-byte ICMPv6 error is emitted. RFC 4443 §2.4(c) requires an ICMPv6 error to quote as much as possible 'without making the error message packet exceed the minimum IPv6 MTU' (1280); any 1280-MTU segment on the path to the v6 client drops the oversized error (it carries DF-less v6 semantics — routers won't fragment), so the very PMTUD/unreachable signal the #2219 work exists to deliver is lost, where a 1280-truncated error would have survived.

**Why it matters** — PMTUD blackholes are the classic NAT64 failure mode this module's error translation was built to prevent; emitting errors that conforming 1280-MTU links must drop re-opens the blackhole for exactly the large-quote case, and produces non-conformant packets attributable to the firewall.

**Fix direction** — Clamp the translated ICMPv6 error so outer IPv6 total <= 1280: truncate embedded_len to 1280 - 40 - 8 = 1232 bytes in write_icmpv6_error_with_embedded (truncating a quote is always legal). Symmetrically cap the v6->v4 direction near the RFC 1812 576-byte guidance in write_icmpv4_error_with_embedded.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for '1280', '576', 'MAX_EMBEDDED', 'packet too big', '2219', '2330'. #2219 added error translation but no size cap; #2330 (PMTUD post-transform sizing) covers forwarding-path MTU checks, not the generated/translated error's own RFC 4443 size limit; #862 (old ICMP checksum 128-byte loop) unrelated. No prior coverage of the missing 1280/576 clamp.

---

#### F-240 · NAT64 v6->v4 FIRST-fragment UDP with the illegal zero IPv6 checksum takes the incremental path on a zero baseline, contradicting the module's own '#3025 defended with a recompute' invariant (asymmetric with the v4->v6 fragment drop)

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-nat`  ·  **Location:** `userspace-dp/src/nat64.rs`:877
- **Labels:** `bug`, `rfc-conformance`

```
    let nonfrag_incremental = frag_info.is_none()
        && (ipv4_protocol == PROTO_TCP
            || (ipv4_protocol == PROTO_UDP && out.get(26..28) != Some(&[0, 0][..])));
    let frag_incremental = frag_info.is_some() && matches!(ipv4_protocol, PROTO_TCP | PROTO_UDP);
    if frag_incremental || nonfrag_incremental {
```

**Runtime trace**

Attacker sends an IPv6 UDP FIRST fragment (Fragment Header present, offset 0, MF=1) with UDP checksum 0x0000 (illegal for v6 UDP per RFC 8200; every conformant v6 receiver would drop it) at a NAT64 destination. write_v6_to_v4_into: frag_info is Some, so nonfrag_incremental's zero-baseline UDP exclusion (lines 874-876) never applies; frag_incremental = true (line 877) -> adjust_l4_checksum_v6_to_v4_incremental folds the v6->v4 address delta into old=0x0000, producing a definite but meaningless non-zero IPv4 UDP checksum on the emitted first fragment. This contradicts the module invariant doc (nat64.rs:74-75: 'v6->v4 UDP with a zero (illegal) IPv6 checksum — no trustworthy baseline; defended against with a recompute') — the defense exists only on the non-fragment path — and is asymmetric with the v4->v6 direction, which explicitly DROPS a fragment-with-zero-checksum (nat64.rs:1004-1010). Today the damage is bounded because non-first v6 fragments are dropped (nat64.rs:763), so the datagram can never reassemble; but once #2562 (open: stateful frag-id cache for non-first fragments) lands, this path starts laundering unverifiable v6 UDP into valid-looking v4 fragments.

**Why it matters** — The dataplane forwards a packet no conformant IPv6 receiver would accept, stamped with a checksum that is neither the original nor a recompute — garbage bytes on the wire attributable to the firewall, a doc-vs-code invariant divergence, and a latent fail-open that arms itself when the open #2562 fragment work completes.

**Fix direction** — Mirror the v4->v6 gate: in write_v6_to_v4_into, drop (return None) a fragmented v6 UDP datagram whose checksum field is 0x0000 before translation, and update the #3025 module-doc invariant to state the fragment path fails closed.

**Not a duplicate** — Searched issues-all.txt/prior-findings.md for '2488', '2562', 'zero checksum', '2333', 'fragment'. #2488 (CLOSED) added fragment translation and the v4->v6 zero-checksum-fragment drop but not the v6->v4 twin; #2562 (OPEN) covers non-first-fragment forwarding, not this checksum-baseline gate; #2333 covered the 0x0000->0xFFFF mapping of a COMPUTED checksum, a different mechanism. The v6->v4 fragment zero-baseline case appears in no issue or prior finding.

---

#### F-241 · AppCatalog exact-port tier is wire-order-dependent (or_insert keeps first writer) while the scan tier deliberately takes min(app_id) — same-tier overlaps can resolve differently from the Go fallback on a reordered snapshot

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-policy`  ·  **Location:** `userspace-dp/src/policy.rs`:1634
- **Labels:** `bug`

```
            if single_dst {
                // First writer wins (lowest app_id) — matches the scan-list
                // "first match wins" rule for overlapping configs.
                bucket.exact_dst.entry(e.dst_port_low).or_insert(e.app_id);
            } else {
```

**Runtime trace**

Snapshot carries two exact-dst-port catalog entries for tcp/443: {app_id 7, "zzz-custom-tls"} listed BEFORE {app_id 3, "junos-https"} (a corrupt/HA-drifted producer, or any future Go emit that stops sorting — the scan tier at policy.rs:1740-1743 was deliberately made order-independent for exactly this reason: 'taking the min makes the tiebreak independent of scan order'). AppCatalog::from_snapshot: exact_dst.entry(443).or_insert(7) — the second entry (id 3) is silently never stored. lookup_directional(tcp, ephemeral, 443, false) → exact=Some(7) → port_based tier resolves 7 → sessions/RT_FLOW label "zzz-custom-tls", while the AppID-disabled Go fallback (resolveTupleFallback, #2578) and the documented lowest-id-wins convention resolve app_id 3 ("junos-https"). The same 5-tuple therefore labels differently depending on producer emit order and on whether AppID is enabled — the operator-visible label drift class #3612 closed across tiers, still open WITHIN the exact tier.

**Why it matters** — Application labels feed session display, RT_FLOW create/close/deny records and incident triage; an order-dependent tie-break that silently diverges from the Go fallback pollutes log integrity under snapshot drift, and the inconsistency with the explicitly order-independent scan tier is a latent trap for the next producer change.

**Fix direction** — Replace or_insert with an explicit min: `bucket.exact_dst.entry(port).and_modify(|cur| *cur = (*cur).min(e.app_id)).or_insert(e.app_id);` and add a from_snapshot test feeding descending-id order.

**Not a duplicate** — Searched prior-findings.md/issues for 'AppCatalog', 'app_id', 'overlap precedence', '3612', '3321'. #3612 (closed, fixed at HEAD) covers CROSS-tier precedence (port-constrained vs protocol-only); prior findings 13/24 cover the enabled-vs-fallback tier divergence now fixed. No prior item covers the WITHIN-exact-tier or_insert order dependence vs the min()-based scan tier.

---

#### F-242 · SnapshotIntegrityError in policy.rs is a cross-domain dumping ground: NAT64/NPTv6/filter/CoS/tunnel/interface fail-closed variants (10+ of ~25) force every non-policy hardening change through the policy module

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-policy`  ·  **Location:** `userspace-dp/src/policy.rs`:16
- **Labels:** `refactor`

```
pub(crate) enum SnapshotIntegrityError {
    AddressBookIdZero,
    DuplicateAddressBookId(u32),
    UnknownAddressBookId { rule_id: String, book_id: u32 },
    ...
    Nat64UnparseableRule { rule_name: String, field: String },
    Nptv6UnparseableRule { rule_name: String, field: String },
    UnrepresentableFilterProtocol { family: String, filter: String, term: String, token: String },
    CosDscpCodePointOutOfRange { classifier: String, dscp: u8 },
    TunnelTtlOutOfRange { tunnel_id: u16, ttl: i32 },
```

**Runtime trace**

policy.rs lines 14-618 are one enum + Display impl spanning at least six unrelated domains (policy addresses/applications/zones, NAT64 #2212, NPTv6 #2240/#2241, firewall filters #2505/#3367/#3406, CoS #2410/#2447/#2458, interfaces/tunnels #2391/#2409/#2410/#2706). Every new fail-closed check in filters or CoS (e.g. the recent #3406 flex-match variant) edits policy.rs, grows its 3625 lines, and recompiles every policy dependent; error construction for CoS/tunnel code paths imports crate::policy. The pattern is structural: the fail-closed family keeps growing (nine variants added since #2400), so the coupling worsens monotonically.

**Why it matters** — Modularity debt with a compounding trend — the module notes and engineering style push toward real module directories; the error SSOT living in the policy evaluator couples unrelated dataplane domains and inflates the highest-risk security module's churn surface.

**Fix direction** — Extract userspace-dp/src/snapshot_integrity/ (or split per-domain sub-enums flattened into one top-level error) housing the enum + Display; mechanical move with re-exports from policy.rs, no behavior change. Follow with per-domain files (policy.rs keeps only the policy variants).

**Not a duplicate** — Searched prior-findings.md for 'policy.rs split', '348', 'SnapshotIntegrityError', 'error enum'. Prior finding 348 proposes splitting policy.rs into policy/{snapshot,address,applications,index,evaluate,counters} — a policy-INTERNAL decomposition. This finding targets a different axis: the cross-domain integrity-error SSOT (NAT64/CoS/filter/tunnel variants) living in policy.rs at all, which 348's proposed layout would still leave inside the policy tree; named 348 explicitly as nearest neighbor.

---

#### F-243 · lo0 host-bound filter-log records the ingress zone from the raw PHYSICAL ifindex, not the resolved logical unit

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-poll-descriptor`  ·  **Location:** `userspace-dp/src/afxdp/poll_descriptor/filter.rs`:499
- **Labels:** `bug`, `observability`, `vlan`

```
    let pending = result.log_match.map(|log_match| PendingFilterLog {
        ingress_zone_id: filter_log_ingress_zone_id(
            forwarding,
            meta,
            ingress_zone_override,
            meta.ingress_ifindex as i32,
        ),
```

**Runtime trace**

apply_lo0_filter_action passes meta.ingress_ifindex (physical bind port) as filter_log_ingress_zone_id's ingress_logical_ifindex arg. filter_log_ingress_zone_id (filter.rs:142) first tries ingress_zone_override, else ifindex_to_zone_id.get(logical), else get(physical). On the session-MISS local-delivery site (mod.rs:1857) ingress_zone_override is the caller's Option which can be None for an unzoned/unresolved probe, and on the flowless arm the override may not resolve; the logical arg is then physical → the lo0 filter-log RT_FLOW carries the parent's (first-subinterface) zone id, not the reth0.80 unit's zone. All sibling sites (input-filter, zone-pair, CoS, host-inbound gate) pass the resolve_ingress_logical_ifindex result.

**Why it matters** — Per-VLAN-subinterface lo0 filter-log records mis-attribute the ingress zone in the emitted RT_FLOW, sending operators to the wrong zone during host-plane incident triage — the same logical-vs-physical class #3609 fixed for the host-inbound gate, left unfixed for the lo0 log's zone hint.

**Fix direction** — Thread the caller's already-resolved logical ingress ifindex into apply_lo0_filter_action / host_inbound_gated_lo0_action and pass it (not meta.ingress_ifindex) to filter_log_ingress_zone_id, matching the host-inbound gate keying.

**Not a duplicate** — #3609 CLOSED and prior-findings.md line 7/22 cover the host-inbound GATE probing raw physical ifindex; those fixed the admission decision. This is the lo0 filter-LOG zone-id display argument in apply_lo0_filter_action, a different code path (log attribution, not gating). Not a duplicate.

---

#### F-244 · Flowless-fragment screen DROP events log UNSPECIFIED (0.0.0.0 / ::) source and destination, losing attacker attribution for teardrop/ping-of-death

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-screen`  ·  **Location:** `userspace-dp/src/afxdp/poll_stages.rs`:396
- **Labels:** `observability`, `vsrx-parity`, `bug`

```
        let (placeholder_src, placeholder_dst) = if meta.addr_family == libc::AF_INET6 as u8 {
            (
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            )
        } else {
            (
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            )
        };
```

**Runtime trace**

Config: zone untrust has `teardrop` enabled. (1) Attacker sends a non-first IPv4 fragment (offset>0, <8B payload) sourced from 203.0.113.9. (2) parse_session_flow_from_bytes returns None (non-first fragment gate) -> flowless branch. (3) poll_stages.rs:396-406 sets placeholder_src=placeholder_dst=0.0.0.0 and passes them to extract_screen_info as src_ip/dst_ip; the real 203.0.113.9 at frame[l3_off+12..16] is never copied into screen_pkt. (4) check_fragment_screens_l3 returns Drop('teardrop'). (5) emit_screen_drop_event(&screen_pkt, ...) at line 440-447 emits an RT_FLOW screen-drop event carrying source 0.0.0.0, destination 0.0.0.0. Operator/SIEM sees a teardrop/ping-of-death drop with no attacker IP.

**Why it matters** — The fragment-based screens (teardrop, ping-of-death, icmp-fragment) exist precisely to catch hostile fragment floods, but their drop logs omit the source IP needed to identify and block the attacker. vSRX RT_FLOW screen events carry the real 5-tuple. The addresses are trivially available in the fragment's own IP header (frame[l3+12..16] v4 / frame[l3+8..24] v6).

**Fix direction** — Derive the real src/dst from the IP header on the flowless path and populate screen_pkt.src_ip/dst_ip (and the flowless parse-error info) so the drop/alarm event attributes the source. The parse itself does not reintroduce the #2344 L4-port classification the flowless path avoids.

**Not a duplicate** — Searched for screen event tuple/timestamp/application defects: #2520 (application_id=0), #2470 (timestamp_ns=0), #2238 (locally-generated replies classified by trigger tuple) — none touch flowless-fragment drop-event source-IP=0.0.0.0. The poll_stages:394 comment acknowledges it as 'out of scope for #3064' but no tracked issue/finding exists. Novel.

---

#### F-245 · set_forwarding_state / set_queue_state / set_binding_state hold the global ServerState lock for up to 2s in wait_for_binding_settle

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-server`  ·  **Location:** `userspace-dp/src/server/handlers/forwarding.rs`:36
- **Labels:** `performance`, `ha`, `refactor`

```
    guard.status.forwarding_armed = forwarding_req.armed;
    set_bindings_forwarding_armed(&mut guard.status, forwarding_req.armed);
    reconcile_status_bindings(guard);
    if forwarding_req.armed {
        wait_for_binding_settle(guard, Duration::from_secs(2));
    }
```

**Runtime trace**

set_forwarding_state runs inside the state.lock() critical section (mod.rs:115-211, arm via forwarding::set at mod.rs:124). On arm, set() calls wait_for_binding_settle(guard, 2s) (forwarding.rs:36), which loops refresh_status + thread::sleep(50ms) until bindings settle OR the 2s deadline (helpers.rs:600-609) — all while holding the global mutex. Concurrent control requests (status poll, update_ha_state, apply_snapshot, and any request racing on the control socket) block on state.lock() for up to 2s. Go's control deadline is 3s (process.go:238), leaving thin margin; during an HA activation burst multiple such waits (queue::set at queue.rs:40 and binding::set at binding.rs:33 do the same) serialize and can push a concurrent poll past its deadline -> spurious failure/restart. Same under-lock-blocking class as the export_all finding.

**Why it matters** — Arming forwarding is an HA activation-critical path; blocking every other control request for up to 2s per arm (and per queue/binding registration change) narrows the failover timing budget the cluster depends on and risks false dataplane-failure detection.

**Fix direction** — Perform the settle wait off the global lock (re-acquire briefly per poll to read binding status), or bound the wait far tighter; the response can report the not-yet-settled state and let the poll loop observe readiness.

**Not a duplicate** — Nearest is #2962 (owner_rg export ack-wait under lock) but that is a distinct code path (export ack) fixed separately; wait_for_binding_settle is a poll-loop settle wait, not an export, and is not named in any open issue or prior finding. Distinct mechanism.

---

#### F-246 · write_state failure in handle_stream masks a successful control operation (persist gated before the response is written)

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-server`  ·  **Location:** `userspace-dp/src/server/handlers/mod.rs`:227
- **Labels:** `bug`, `refactor`

```
    if persist_state {
        write_state(state_file, &state)?;
    }

    let mut writer = BufWriter::new(stream);
    serde_json::to_writer(&mut writer, &response).map_err(|e| format!("encode response: {e}"))?;
```

**Runtime trace**

A mutating request (e.g. apply_snapshot) runs its handler, which HAS ALREADY mutated the dataplane (guard.snapshot set, workers reconciled) and sets persist_state=true. After the lock is released, `if persist_state { write_state(state_file, &state)? }` (mod.rs:226-228) runs. On a transient disk error (ENOSPC on /tmp, or an io_uring failure whose sync fallback ALSO fails), StateWriter.persist returns Err -> write_state returns Err -> the `?` propagates out of handle_stream BEFORE the response is written (mod.rs:230-235 never reached) -> the UnixStream is dropped with no response bytes -> Go's json.Decode gets a bare EOF (process.go:250-259) -> requestDetailedLocked returns an error -> the operation is reported FAILED to the control plane even though the dataplane already applied it. Go then does not run markAppliedSnapshotLocked/publishedSnapshot bookkeeping and re-issues apply on the next reconcile (or surfaces a spurious 'apply failed' to the operator while forwarding runs the new config). The state file is non-authoritative — the helper never reads it back at startup (ServerState is created with snapshot:None in lifecycle.rs) — so its durability should not gate the control response.

**Why it matters** — Couples the correctness-signalling of every mutating control request to the durable write of a debug-only cache file; a rare disk hiccup then desyncs the Go control plane's applied-snapshot bookkeeping and HA state from a dataplane that actually succeeded, and can loop apply retries.

**Fix direction** — Write the response first, then persist best-effort (log a persist failure, do not fail the request); or downgrade write_state failure in handle_stream to a logged warning since state.json is never read back.

**Not a duplicate** — Grepped prior-findings.md + issues-all.txt for write_state/persist/response-masking/EOF — no hits. state_writer durability issues (#2147/#2705/#2714/#2957/#2958) are all about the writer's own crash-safety, none about the persist result gating the control-socket RESPONSE ordering in handle_stream. New mechanism.

---

#### F-247 · IfInfo::from_ifindex hardcodes i8 for the if_indextoname buffer — non-portable c_char assumption breaks aarch64 builds

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-umem-frame`  ·  **Location:** `userspace-dp/src/xsk_ffi.rs`:279
- **Labels:** `refactor`, `portability`

```
    pub fn from_ifindex(&mut self, index: u32) -> Result<(), Errno> {
        let mut buf = [0i8; libc::IFNAMSIZ];
        let err = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
        if err.is_null() {
            return Err(Errno::last_os_error());
        }
        self.ifindex = index;
        self.queue_id = 0;
        // Copy name bytes
        for (i, &b) in buf.iter().enumerate() {
            self.ifname[i] = b as u8;
        }
```

**Runtime trace**

libc::if_indextoname takes *mut c_char. On x86_64-linux c_char = i8 so `[0i8; IFNAMSIZ].as_mut_ptr()` type-checks; on aarch64-linux (and riscv64) c_char = u8, so this line fails to compile (`expected *mut u8, found *mut i8`). The subsequent per-byte `b as u8` copy loop is a second spot that bakes in the i8 assumption. Not a runtime defect on the current x86_64 appliance target, but the first thing that breaks if the bare-metal device-map work (#1956) ever lands on an ARM appliance — and it's a one-line fix now vs a cross-compile surprise later.

**Why it matters** — The project explicitly targets bare-metal appliance hardware (chassis device-map, #1956); ARM network appliances are a plausible port target, and this is the kind of latent portability debt that surfaces as a wall of FFI type errors at the worst time.

**Fix direction** — Use `let mut buf = [0 as core::ffi::c_char; libc::IFNAMSIZ];` and copy with `b as u8` (which stays correct for both signednesses), or use `std::ffi::CStr::from_ptr` on the returned pointer.

**Not a duplicate** — Searched for if_indextoname/c_char/aarch64/portab in issues and prior findings — only #318 (portable session record, unrelated) matches 'portable'. No prior coverage of FFI c_char signedness in xsk_ffi.rs.

---

#### F-248 · hot_hash_seed getrandom fallback silently downgrades the hash-DoS defense seed (no log/counter) and discards partially-read kernel entropy

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-umem-frame`  ·  **Location:** `userspace-dp/src/hot_hash_seed.rs`:94
- **Labels:** `security`, `robustness`

```
    let nonzero = |v: u64| if v == 0 { 1 } else { v };
    if filled == buf.len() {
        return nonzero(u64::from_ne_bytes(buf));
    }

    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
```

**Runtime trace**

os_random_seed_u64: getrandom loop fills buf; on a non-EINTR error or rc==0 it breaks with filled < 8. The fallback then computes CLOCK_MONOTONIC ^ pid*const mixed with a stack address — but (a) any bytes ALREADY read into buf (filled in 1..8, possible via partial reads) are thrown away instead of being mixed into `fallback`, and (b) the downgrade is completely silent: no eprintln/counter distinguishes a strong per-boot seed from the weak time+pid+ASLR fallback. This seed keys the flow-cache set index, session-map buckets, and fabric-queue selection specifically to defeat attacker-precomputed collision sets (#2364); CLOCK_MONOTONIC at daemon start is coarsely guessable from uptime, pid from a narrow range, and the stack address contributes only ASLR bits — materially weaker than getrandom, so an operator should be able to see that the DoS margin is degraded. On the >=6.18 kernel floor getrandom essentially never fails, so reachability is near-zero — this is a hardening/observability gap, not an active hole.

**Why it matters** — In a security appliance, a silent downgrade of an algorithmic-complexity-DoS defense is exactly the kind of state an operator needs a one-time journald line or Prometheus counter for; and discarding real kernel entropy when 1-7 bytes were read is strictly worse than mixing it in for free.

**Fix direction** — Mix the partial buf into the fallback accumulator (mix(&mut fallback, u64::from_ne_bytes(buf))) and emit a single `eprintln!("xpf-userspace-dp: getrandom failed; hot-path hash seed degraded to time/pid fallback")` (one-time, seed-draw is OnceLock) so the downgrade is observable.

**Not a duplicate** — Searched for getrandom/entropy/seed/hash seed in issues and prior findings. #2364 (introduced this module) and #693 (SFQ seed randomization) are CLOSED and cover the seeding itself; neither covers the silent-fallback observability nor the partial-entropy discard.

---

#### F-249 · io_uring write_all restarts user_data tag at 1 per call — a ceiling-aborted SQE's late CQE is deterministically misattributed to the NEXT write on the same ring (state-file corruption / TUN UAF window)

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-umem-frame`  ·  **Location:** `userspace-dp/src/io_uring_write.rs`:238
- **Labels:** `bug`, `security`, `test-gap`

```
pub(crate) fn write_all(
    port: &mut dyn RingPort,
    data: &[u8],
    positioned: bool,
    label: &str,
) -> Result<WriteOutcome, WriteError> {
    let mut offset = 0usize;
    // Distinct tag per submission. Start at 1 so a zero `user_data` (the value
    // an uninitialised / pre-existing CQE would carry) is never a valid match.
    let mut tag: u64 = 1;
```

**Runtime trace**

1) Slow-path TUN thread calls write_all_to_fd(ring, fd, pkt_A, positioned=false) on the long-lived per-thread IoUring (slowpath.rs:640; state_writer.rs:462 for the positioned variant). write_all sets tag=1, pushes SQE(user_data=1), reap_matching submits it, then hits the MAX_WAIT_RETRIES=4096 ceiling (EINTR storm, or the EAGAIN transient-retry ceiling pinned by test transient_error_retries_to_ceiling) -> returns Err with SQE(1) still in flight in io-wq and its CQE unreaped. 2) Next packet: write_all(pkt_B) starts a FRESH tag=1 (line 238 — the tag is a per-call local, not per-ring), pushes SQE(user_data=1) for B. 3) reap_matching's drain_stale (line ~338) drains only ALREADY-READY CQEs; A's punted io-wq write has not completed yet, so nothing is drained. 4) submit_and_wait_one submits B and waits; A's write completes first -> CQE{user_data:1, res:len_A} is reaped, matches want==1, and is returned as B's completion. 5a) Packet fd: if len_A >= len_B write_all returns Done while B's write is still in flight -> caller drops/reuses B's buffer -> kernel io-wq reads freed memory (the exact #2297 UAF re-opened), and B's real CQE is left over to poison the NEXT call in a chain. 5b) State writer (positioned): offset is advanced by A's stale byte count -> subsequent chunks written at wrong file offsets -> silently corrupted persisted state. The module doc (lines 36-39) claims 'Each submission carries a distinct, monotonically increasing user_data ... a stale CQE ... can no longer be mis-attributed' — that uniqueness only holds WITHIN one write_all call; across calls every first submission is tag 1, so after any ceiling abort of a single-chunk write the collision is deterministic, not probabilistic.

**Why it matters** — The #2297 fix's whole safety argument (match-by-user_data + drain_stale) collapses across the call boundary the moment the documented ceiling escape hatch fires once. A single EINTR/EAGAIN storm converts every subsequent slow-path TUN write or config-state write on that ring into a potential misattributed completion: corrupted persisted config state on a firewall appliance, or a freed-buffer read whose bytes get injected into the TUN as a frame.

**Fix direction** — Make user_data unique per ring lifetime, not per call: replace the `let mut tag: u64 = 1` local with a process-wide `static NEXT_TAG: AtomicU64` (fetch_add, skip 0) or a counter carried in the RingPort/IoUringPort, so a leftover CQE from an aborted call can never equal a live tag. Add a regression test: FakeRing that completes a prior call's in-flight SQE during the next call's wait.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for io_uring/2297/2312/2477/2478/user_data/stale CQE. #2297 (CLOSED) fixed in-call misattribution; #2312 (CLOSED) strengthened the stale-CQE test and docs; #2477/#2478 fixed retry-safety and permanent-error spin. None address CROSS-CALL tag reuse after a ceiling abort — the per-call tag restart at 1 is a genuinely new residual mechanism of the #2297 fix (named per the residual-report rule).

---

#### F-250 · No regression test that xpf egress survives a peer-initiated rekey (2-slot rotation blackhole is untested)

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-wg-coord`  ·  **Location:** `userspace-dp/src/afxdp/wg/tests.rs`:2355
- **Labels:** `test-gap`, `vsrx-parity`

```
fn wg_first_peer_pubkey_and_confirmed_session_helpers() {
    ...
    init_engine.peer_has_confirmed_session(&resp_pub),
    ...
    assert!(!no_session.peer_has_confirmed_session(&resp_pub));
```

**Runtime trace**

The WG test suite (tests.rs, engine_tests.rs) covers self-handshake round-trips, replay-window arms, timer semantics, and confirmed-session helpers, but grep for next-session/previous-egress/rekey-egress/rotate-unconfirmed/blackhole returns nothing. No test drives: install confirmed session S1 → deliver a second (responder) initiation → assert that a subsequent try_encap still SUCCEEDS (uses the confirmed keypair) rather than returning NoSession. As a result the displacement bug (finding #1) ships green.

**Why it matters** — The exact security-relevant invariant (a re-handshake must not interrupt egress) has no guard, so the regression is invisible and any future fix has nothing to lock it in.

**Fix direction** — Add an engine test: install a confirmed initiator session, then feed a valid responder initiation for the same peer; assert try_encap still returns Ok until the new session is confirmed. Pair with a replay-of-msg1 test asserting egress is not blackholed.

**Not a duplicate** — No test in tests.rs/engine_tests.rs matches the rekey-egress-continuity scenario (verified by grep). Not tracked in any issue; complements finding #1.

---

#### F-251 · SYN-cookie-ACK session-miss stage redundantly re-resolves the ingress zone the screen stage already computed one stage earlier on the same packet

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-worker`  ·  **Location:** `userspace-dp/src/afxdp/poll_stages.rs`:577
- **Labels:** `performance`, `refactor`, `screen`

```
    let logical_ifindex = resolve_ingress_logical_ifindex(
        worker_ctx.forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let zone_id = ingress_zone_override
        .filter(|id| worker_ctx.forwarding.zone_id_to_name.contains_key(id))
```

**Runtime trace**

For a session-miss TCP packet with screen profiles active, stage_screen_check (line 337-375) already resolves logical_ifindex → zone_id → zone_name → l3_off and runs check_packet. On session miss the pipeline then calls stage_screen_syn_cookie_ack_on_session_miss (poll_stages.rs:557), which re-derives the identical logical_ifindex (577), zone_id (583), zone_name (595), and l3_off (606) plus re-extracts a ScreenPacketInfo — all recomputable from the stage-10 result. This is the SYN-flood cookie path, i.e. the volumetric-attack cold path where per-packet cost matters most.

**Why it matters** — Under a SYN flood (the exact scenario SYN cookies defend), every session-miss ACK pays two full zone-resolution + screen-extract passes instead of one, doubling the per-packet cold-path cost precisely when packet rate is adversarially maximized. resolve_ingress_logical_ifindex is a FastMap probe and zone lookups are two more map probes per pass.

**Fix direction** — Thread the stage-10 (zone_id, zone_name, l3_off, ScreenPacketInfo) result into stage_screen_syn_cookie_ack_on_session_miss instead of recomputing, or fold the cookie-ACK validation into stage_screen_check's return so the resolution happens once.

**Not a duplicate** — Searched prior-findings/issues for 'syn-cookie'/'zone resolution'/'stage_screen'. #1374 (syn-cookie userspace runtime), #3022 (logical-ifindex zone resolution fix), #3315/#3527 (syn-flood sub-thresholds) all concern correctness of the resolution, none the double-resolution cost across the two screen stages. No overlap.

---

#### F-252 · fabric_queue_hash: the FIRST fragment of a datagram hashes WITH ports while its non-first fragments hash port-less — same datagram splits across different fabric egress bindings, defeating #2357's stated fragment-stability invariant

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-worker`  ·  **Location:** `userspace-dp/src/afxdp/worker/mod.rs`:297
- **Labels:** `bug`, `ha`, `fabric`, `vsrx-parity`

```
    if non_first_fragment {
        match meta.addr_family as i32 {
            libc::AF_INET => {
                mix(&mut seed, u32::from_be_bytes([...src...]));
                mix(&mut seed, u32::from_be_bytes([...dst...]));
            }
        ...
        return seed;  // NO ports
    }
    if let Some(flow) = flow {
        ... mix(&mut seed, flow.forward_key.src_port ...); mix(dst_port); return seed;  // WITH ports
    }
```

**Runtime trace**

A fragmented datagram to a peer-owned (FabricRedirect) destination. First fragment (offset 0, MF=1): frame_is_non_first_fragment=false → parse_session_flow_from_bytes returns Some(flow) with real ports → forward_request.rs:110 / flow_cache_hit.rs:267 call fabric_queue_hash(Some(flow), ports, meta, non_first_fragment=false) → takes the `if let Some(flow)` branch (worker/mod.rs:330) and mixes src_port/dst_port. Subsequent fragments (offset>0): flow=None, non_first_fragment=true → fabric_queue_hash(None, .., true) → takes the `if non_first_fragment` branch (line 297) and OMITS ports. Two different seeds → BindingLookup::fabric_target_index maps them to DIFFERENT local fabric egress bindings → the datagram's fragments leave over the fabric on different worker/TX queues and can arrive at the peer out of order.

**Why it matters** — The function's own doc (worker/mod.rs:266-273) and #2357 assert 'every fragment of one datagram must select the same fabric binding (no cross-chassis reordering)'. #2357 only made non-first fragments consistent with EACH OTHER; it never reconciled the first fragment (still ported) with the rest (now port-less), so the invariant it claims is not actually held for the first-vs-rest relationship. Functional impact is bounded (final-destination IP reassembly tolerates fragment reorder), but a reorder-sensitive peer fast-path or a middlebox on the far side can be affected, and the code advertises a guarantee it does not deliver.

**Fix direction** — Make the first fragment hash port-less too when the packet is any fragment of a fragmented datagram (gate the port mix on `!frame_is_fragment` rather than only `!non_first_fragment`), so first and subsequent fragments of one datagram share a seed. Alternatively document that only non-first fragments are stabilized and downgrade the invariant comment.

**Not a duplicate** — Searched issues-all.txt/prior-findings for 'fragment'/'fabric_queue'/'#2357'. #2357 (CLOSED) fixed non-first-fragment port derivation; #2344/#2357 tests (tests.rs:11884 fabric_queue_hash_non_first_fragment_is_port_independent_3tuple) only assert non-first==non-first, never first==non-first. This is a NAMED residual of closed #2357 in a genuinely new shape (first-vs-rest divergence), explicitly not the closed defect.

---

#### F-253 · poll_binding backpressure early-return skips retry_pending_neigh — buffered SYNs to unresolved next-hops are never retried while TX stays backlogged with continuous RX

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `rs-worker`  ·  **Location:** `userspace-dp/src/afxdp/worker/lifecycle.rs`:121
- **Labels:** `bug`, `latency`, `test-gap`

```
        if tx_backlog >= binding.tx_pipeline.max_pending_tx {
            binding.telemetry.dbg_backpressure += 1;
            let _ = drain_pending_tx(...);
            apply_shared_recycles(...);
            let _ = drain_pending_fill(binding, now_ns);
            counters.flush(&binding.live);
            update_binding_debug_state(binding);
            return did_work;   // <-- returns BEFORE the bottom retry_pending_neigh (line 315)
```

**Runtime trace**

The RX-empty path (line 140-167) calls retry_pending_neigh before returning; the normal full-batch path calls it at the bottom (line 315). But the backpressure guard at the TOP of the first batch iteration (line 96) returns at line 121 BEFORE checking RX and WITHOUT calling retry_pending_neigh. Under sustained TX backpressure (tx_backlog >= max_pending_tx) with continuous ingress, poll_binding returns at line 121 every tick, so pending_neigh entries (buffered packets awaiting ARP/NDP resolution) are never retried for this binding until backpressure clears. If the ARP for a buffered SYN's next-hop resolves during the backpressure window, the packet still waits — up to PENDING_NEIGH_TIMEOUT, after which it is dropped and recycled.

**Why it matters** — The pending_neigh buffer exists precisely to release packets the instant the netlink monitor resolves the neighbor (avoiding a ~1s TCP retransmit). Starving its retry during backpressure re-introduces the retransmit-latency the buffer was built to avoid, on flows to freshly-learned hosts, exactly when the box is busy. Bounded (the timeout eventually recycles), so severity is low.

**Fix direction** — Call retry_pending_neigh on the backpressure early-return path too (after the drain_pending_tx/fill that frees frames), or fall through to a shared cleanup tail so all three exits retry pending neighbors.

**Not a duplicate** — Searched prior-findings/issues for 'pending_neigh'/'retry'/'backpressure'. #201 (fill-ring backpressure) and #1651/#1769/#1771 (neg-neigh cache, per-nexthop pending) concern buffering policy and dead-host fast-fail, none the retry-skip on the backpressure exit of poll_binding. No overlap.

---

#### F-254 · #3261 unrepresentable-address whole-snapshot reject fires for scheduler-INACTIVE policies, amplifying blast radius to all-zones default-deny on the lenient/HA-sync path

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `x-default-deny`  ·  **Location:** `pkg/dataplane/userspace/policies.go`:332
- **Labels:** `bug`, `security`, `test-gap`

```
	srcUnrepresentable := !allAddressTokensRepresentable(addrRepresentable, pol.Match.SourceAddresses)
	dstUnrepresentable := !allAddressTokensRepresentable(addrRepresentable, pol.Match.DestinationAddresses)
	// #3376: capture the exact offending tokens BEFORE the side collapses to
	// the sentinel so collectPolicyContentRejections can name them per side.
	var rejectedSrc, rejectedDst, rejectedApps []string
	if srcUnrepresentable {
		rejectedSrc = offendingAddressTokens(addrRepresentable, pol.Match.SourceAddresses)
		sourceAddresses = []string{unsupportedAddressSentinel}
	}
```

**Runtime trace**

buildOneRuleSnapshot computes srcUnrepresentable/dstUnrepresentable and emits the __unsupported_address__ sentinel for ANY policy whose address token is undefined or non-literal (dns-name/wildcard/range), regardless of pol scheduler-inactive state (Inactive is computed independently at line 396 and never gates the sentinel). On the lenient / HA-sync / tolerant-load path (older-binary active.json, peer config sync — where the strict commit gate is downgraded to a warning), a currently-DORMANT (out-of-schedule) policy that references a non-literal book emits the sentinel. parse_policy_state_with_counters -> rule_has_unrepresentable_address_sentinel returns true -> the WHOLE snapshot is rejected (SnapshotIntegrityError::UnrepresentableAddress). On fresh boot this leaves the dataplane with no policy state = default-deny for EVERY zone pair; a dormant policy's config error takes down live enforcement it is not even participating in.

**Why it matters** — vSRX treats a scheduler-inactive policy as absent, so its unresolved references cannot affect active enforcement. Here a single dormant policy with a stale address-book reference can collapse the entire dataplane to default-deny on the exact non-strict path #3261 is meant to protect, an availability over-reach worse than the failure it guards.

**Fix direction** — Skip the sentinel emission (treat the side as match-none / drop the rule) when policyRuleInactive(pol) is true, so an inactive policy's unrepresentable address cannot reject the whole snapshot; or narrow the Rust preflight to ignore sentinels on rules whose inactive flag is set.

**Not a duplicate** — Searched dedup corpus for #3261 / unrepresentable-address / sentinel / inactive. #3261, #3376, #3711 cover the fail-closed whole-snapshot reject and offending-token naming; none observes that the check runs BEFORE (and independent of) the scheduler-inactive gate, so a dormant policy amplifies the reject to all-zones default-deny.

---

#### F-255 · No test pins that a `to-zone junos-host then deny` actually denies direct (non-DNAT) host-bound traffic — the documented 'enforced' claim is unverified against the kernel-shunt path

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `x-default-deny`  ·  **Location:** `userspace-dp/src/afxdp/forwarding/host_inbound.rs`:534
- **Labels:** `test-gap`, `vsrx-parity`, `security`

```
    #[test]
    fn empty_configured_zone_default_denies() {
        const TCP: u8 = 6;
        const ZONE: u16 = 7;

        let mut state = ForwardingState::default();
        // A configured zone with NO tokens = the no-stanza / empty-stanza shape.
        state
            .zone_host_inbound
            .insert(ZONE, zone_host_inbound_from_tokens(&[], &[]));
```

**Runtime trace**

host_inbound.rs tests cover host-inbound admission (empty-zone default-deny, ident-reset, protocols-all L2 exclusion, per-interface override) but there is no test — here or in policy tests — that drives a direct host-bound flow (session-miss to a firewall interface IP, no DNAT) through the full path to confirm a configured `to-zone junos-host then deny` blocks it. Because such flows are shunted to the kernel by the XDP shim (Finding above), any test that only exercises the userspace LocalDelivery XSK path would pass while the primary-path behavior (fail-open) goes unobserved. The absence of an end-to-end junos-host-deny-vs-direct-traffic assertion is why the Finding-1 gap is invisible to CI.

**Why it matters** — The documented `to-zone junos-host` enforcement (docs/junos-cli-reference.md:587) has no regression test that distinguishes the kernel primary path from the XSK secondary path, so the fail-open cannot be caught and a future 'we enforce junos-host' assumption stays unverified.

**Fix direction** — Add an integration/smoke assertion (loss userspace cluster or a shim-level test) that a `from-zone <z> to-zone junos-host ... then deny` on a host-inbound-admitted service actually drops direct-to-interface traffic; if the kernel path cannot enforce it, encode that as an explicit xfail documenting the accepted gap.

**Not a duplicate** — known-gaps line 56 and prior-findings note a missing zone-policy MATRIX test for transit/junos-host on the userspace path; none targets the specific kernel-shunt-vs-XSK direct-host junos-host-deny case that makes Finding 1 invisible.

---

#### F-256 · bake.py manifest provenance lies under --skip-build: version/git_commit come from bake-time HEAD while the packaged binaries come from whatever stale .deb mtime-wins in dist/deb/

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `x-tests-build`  ·  **Location:** `scripts/image/bake.py`:599
- **Labels:** `supply-chain`, `build`, `bug`

```
        try:
            commit = out_text(["git", "-C", ROOT, "rev-parse", "HEAD"]).strip()
        except Exception:
            commit = "unknown"
...
        manifest = os.path.join(a.out, f"xpf-{ver}.manifest")
        with open(manifest, "w") as f:
            f.write(f"version: {ver}\ngit_commit: {commit}\n"
```

**Runtime trace**

Operator runs `make deb` on commit A, then commits B and C (or switches branch), then runs `bake.py --skip-build` (documented flag, line 448). Deb selection (lines 486-491) picks the newest-mtime dist/deb/xpf_*.deb — the commit-A build. But a.version defaults to git_version() = `git describe` at HEAD=C (line 446), and the manifest writes git_commit = HEAD=C (line 599). Result: dist/xpf-<describe-of-C>.qcow2 + a signed manifest asserting git_commit C while the staged xpfd/cli/xpf-userspace-dp inside are commit A binaries. The deb filename itself embeds the truth (0.0.<count>+g<sha-of-A> from Makefile DEB_VERSION) but nothing cross-checks it against HEAD; the #1930 image-roll gate and any incident forensics then trust wrong provenance. The mtime-newest comment (lines 483-485) defends against selecting an OLDER deb over a fresh build, not against --skip-build with a moved HEAD.

**Why it matters** — The manifest is the machine-readable provenance for signed, published appliance images (#1924/#1930 gates read ONLY the manifest). Wrong git_commit breaks reproducibility claims, CVE triage ('which images contain the fix?') and the mixed-base image-replace decision.

**Fix direction** — Parse the g<short-sha> token out of the selected deb's version (or dpkg-deb -f Version) and (a) record THAT as the binary provenance in the manifest, and (b) die (or require an explicit override) when it disagrees with HEAD under --skip-build.

**Not a duplicate** — Searched issues-all.txt for 'bake', 'manifest', 'provenance', 'skip-build' — nothing; prior-findings.md has no bake.py entries (grep 'provenance|manifest|dirty|skip-build' hit only unrelated ipmon/proto items). Nearest neighbor is the in-file mtime-newest fix comment (stale-deb selection), which addresses a different mechanism (deb choice, not manifest attribution).

---

#### F-257 · bake.py trusts the Ubuntu base image checksum from an unauthenticated same-origin SHA256SUMS fetch — no GPG verification, and XPF_BASE_URL collapses the trust root to whatever mirror is configured

- **Severity:** 🟡 low  ·  **Confidence:** medium
- **Module:** `x-tests-build`  ·  **Location:** `scripts/image/bake.py`:203
- **Labels:** `security`, `supply-chain`, `build`

```
    # Re-verify the cache against the upstream checksum (cache not trusted).
    sums = os.path.join(work_dir, "SHA256SUMS.upstream")
    run(["curl", "-fsSL", "-o", sums, f"{base_url}/SHA256SUMS"])
    expected = None
    with open(sums) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("*") == img:
                expected = parts[0]
                break
```

**Runtime trace**

fetch_base() downloads ubuntu-<rel>-server-cloudimg-amd64.img and SHA256SUMS from the SAME base_url (default cloud-images.ubuntu.com, but XPF_BASE_URL / XPF_UBUNTU_RELEASES_URL override to any mirror, line 191-194). Both artifacts traverse the same channel, so the checksum verifies transport integrity of the cache, not authenticity of the image: a compromised/malicious mirror (or a TLS-interposing corporate proxy with an injected CA, or a poisoned internal mirror named in XPF_BASE_URL) serves a trojaned cloudimg plus a matching SHA256SUMS and the bake's 'base image checksum verified' (line 217) passes. The trojaned rootfs then becomes the substrate of the SIGNED xpf appliance image — the project's own minisign signature launders the compromised base into the trusted channel. Ubuntu publishes SHA256SUMS.gpg signed by the cloud-image key precisely for this; the bake never fetches or verifies it (grep 'gpg|SHA256SUMS.gpg' in bake.py: none).

**Why it matters** — For a security appliance whose distribution chain is otherwise carefully fail-closed (#1924 signing, per-file manifests, placeholder-key refusal), the base-OS ingestion is the one unauthenticated input; supply-chain attacks on OS image mirrors are an established vector and the downstream signature makes the blast radius 'every customer install'.

**Fix direction** — Fetch SHA256SUMS.gpg and verify with a repo-pinned copy of the Ubuntu cloud-image signing public key (gpgv --keyring <pinned>) before trusting SHA256SUMS; alternatively support a repo-pinned per-release image sha (like PINNED_BASE_RELEASE) with the gpg path as the default.

**Not a duplicate** — Searched issues-all.txt for 'bake', 'gpg', 'sha256', 'image', '1924', 'supply' — #1924 (open umbrella) covers signing xpf's OWN artifacts, not authenticating the upstream base; no issue or prior finding (prior-findings.md has zero bake.py entries) mentions upstream SHA256SUMS authentication.

---

## 6.3 Low-confidence findings (15)

> Design smells, vSRX parity gaps, and improvements worth issue triage.
> Severity mix: 0 high · 2 medium · 13 low.

#### F-258 · #2198 F3 single-threaded-receiver invariant is violated when fallback BulkSync runs on fab1 while fab0 (re)connects mid-bulk — cross-connection same-key installs race the non-atomic gen guard

- **Severity:** 🟠 medium  ·  **Confidence:** low
- **Module:** `go-cluster-sync`  ·  **Location:** `pkg/cluster/sync_conn.go`:303
- **Labels:** `bug`, `ha`, `race`

```
// for a given peer is single-threaded: messages are decoded and dispatched
// serially within one receiveLoop goroutine over the single ACTIVE fabric
// connection (activeConnLocked prefers conn0; conn1 is used only when conn0 is
// down — never both at once for sends, and the peer sends over one stream). So
// no two installs/deletes for the SAME key are ever applied concurrently, and
// the per-key stored generation cannot be interleaved between the guard read
// and the record write.
```

**Runtime trace**

1) Dual-fabric cold start where fab1 connects first: handleNewConnection(1) starts the fallback BulkSync (event-stream export failed or unavailable), which captures `conn := s.getActiveConn()` ONCE (sync_bulk.go:86) = conn1 and streams every session to it under writeMu. 2) fab0 connects mid-bulk: handleNewConnection(0) sets conn0; getActiveConn now prefers conn0. 3) The 1s syncSweep stamps a fresh generation for live key K (gen=N+1) and queues it to sendCh; sendLoop writes it to conn0 — while the bulk goroutine writes the SAME key K (stamped earlier, gen=N) to conn1. 4) The receiver runs one receiveLoop per connection; both concurrently execute installClusterSyncedV4(K,...): the sequence installGenGuardV4 → PutClusterSyncedV4 → recordInstalledGenV4 takes recvGenMu separately per step (documented at :294-310 as safe because 'never both at once for sends'). 5) Interleave: loop-A(gen N) passes guard, loop-B(gen N+1) passes guard, B does Put(N+1)+record(N+1), then A does Put(N) — the dataplane now holds the OLDER value (stale LastSeen/FIB/counters) — and record(N) regresses the stored generation to N, so a journaled stale delete of gen<=N that #2170 exists to refuse can now kill the live entry.

**Why it matters** — The entire #2170/#2221/#2198 generation-guard correctness argument rests on the single-active-stream invariant stated in this comment; the fallback bulk path breaks it on every dual-fabric cold start where fabrics connect staggered, silently re-opening the stale-overwrite/stale-delete class on the standby.

**Fix direction** — Route fallback BulkSync frames through sendCh (like the override path) so exactly one goroutine writes session traffic, or re-resolve getActiveConn per bulk write, or hold recvGenMu across guard+Put+record for same-key serialization on the receiver.

**Not a duplicate** — This is an explicitly-new-shape residual of #2198 F3 (CLOSED): the F3 review accepted the non-atomic guard sequence based on the single-active-fabric sender invariant; the disproof here is the captured-conn fallback BulkSync coexisting with a sendLoop that switched to a newly-returned fab0 — a scenario the F3 analysis did not consider. Distinct from #117 (epoch interleave of two bulk WRITERS) and #89/#69 (stale receive loop teardown).

---

#### F-259 · Flowless (non-first fragment) transit packets resolving to MissingNeighbor bypass zone security policy and fall to kernel FIB reinject

- **Severity:** 🟠 medium  ·  **Confidence:** low
- **Module:** `rs-poll-descriptor`  ·  **Location:** `userspace-dp/src/afxdp/poll_descriptor/mod.rs`:4016
- **Labels:** `security`, `vsrx-parity`, `fragment`

```
                            // No flow tuple (e.g. non-first fragment) skips
                            // the early policy gate and falls through to the
                            // negative-cache / probe / reinject path,
                            // preserving the pre-#1913 behavior —
                            // `MissingNeighbor` for a flowless packet was
                            // always slow-path-eligible.
```

**Runtime trace**

A non-first IPv4/IPv6 fragment for a transit destination whose next-hop neighbor is not yet resolved: the flowless arm computes final_resolution via flowless_base_resolution → route resolves but neighbor unresolved → MissingNeighbor. The flowless transit policy gate (mod.rs:3155) only runs for `== ForwardCandidate`, so it is skipped. The outer disposition match then hits the MissingNeighbor arm (mod.rs:3806) whose policy gate is `if let Some(flow) = flow.as_ref()` (line 3863); the outer `flow` is None for a flowless packet, so policy is skipped and the fragment falls through to the ARP/NDP probe + maybe_reinject_slow_path, letting the kernel FIB forward it — even when the zone pair is deny-all.

**Why it matters** — #3291 closed the flowless-transit fail-open for ForwardCandidate, but the MissingNeighbor disposition (first fragments of a flow to a cold next-hop, or any fragment during neighbor churn) is an uncovered disposition: fragments of a policy-denied flow can be forwarded by the kernel while the neighbor resolves. It is a narrow window but a genuine fragment-path zone-policy bypass.

**Fix direction** — Evaluate the zone policy for the flowless MissingNeighbor case using the synthetic l3_ctx flow (l4_present=false) before enqueuing the neighbor probe / reinject, mirroring the ForwardCandidate flowless gate; drop on a non-Permit verdict.

**Not a duplicate** — #3291 CLOSED (flowless transit ForwardCandidate enforcement) and #3292 (flowless LocalDelivery); known-gaps.md/#3291 plan mention a deferred fragment-association cache. Neither ticket covers the MissingNeighbor disposition flowless bypass; the code comment documents it as pre-#1913 behavior but no open issue tracks it as a residual. Reporting as a low-confidence residual naming #3291/#1913.

---

#### F-260 · SSE event/log streams send no periodic keepalive comment — idle streams behind an L7 proxy/idle-timeout are silently dropped, and there is no test for long-idle liveness

- **Severity:** 🟡 low  ·  **Confidence:** low
- **Module:** `go-api-grpc`  ·  **Location:** `pkg/api/sse.go`:55
- **Labels:** `bug`, `test-gap`

```
	sub := s.eventBuf.Subscribe(128)
	defer sub.Close()

	var seq uint64
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case rec := <-sub.C:
```

**Runtime trace**

eventStreamHandler/logStreamHandler set SSE headers then block in a for-select that only writes when a matching event arrives on sub.C. On a quiet firewall (or with a narrow category filter) minutes can pass with zero writes. Reverse proxies / load balancers commonly close idle upstreams after 30-60s; SSE best practice is a periodic `:\n\n` keepalive comment. Without it the client sees a connection that appears alive server-side (ctx not yet done) but is torn down by an intermediary, and the client must reconnect blindly. No test exercises the idle path.

**Why it matters** — Live security event streaming is an incident-response surface; a silently-dropped feed during a quiet period means an operator watching for the first POLICY_DENY/SCREEN_DROP may never receive it after a proxy timeout.

**Fix direction** — Add a time.Ticker (e.g. 15-30s) case in the select that writes an SSE comment line (`: keepalive\n\n`) and flushes; add a test asserting a keepalive is emitted on an idle stream.

**Not a duplicate** — prior-findings has SSE entries only for #3383 (fail-open severity/category parsing) and event-truthfulness in the Rust reject path; none concern SSE keepalive/idle liveness. issues-all.txt #3383 is the parse fix, already reflected in parseCategories/ParseSeverityStrict at HEAD. This is a different mechanism (transport liveness).

---

#### F-261 · Heartbeat GroupID/monitor-RGID are uint8 while RG instance IDs are unvalidated at commit — RG ID >= 256 truncates on the wire and corrupts the peer's per-RG election view

- **Severity:** 🟡 low  ·  **Confidence:** low
- **Module:** `go-cluster-core`  ·  **Location:** `pkg/cluster/heartbeat.go`:143
- **Labels:** `bug`, `correctness`, `ha`, `config-validation`

```
	for _, g := range pkt.Groups {
		buf[off] = g.GroupID
		binary.LittleEndian.PutUint16(buf[off+1:off+3], g.Priority)
		buf[off+3] = g.Weight
		buf[off+4] = g.State
		off += heartbeatGroupSize
	}
```

**Runtime trace**

compiler_system.go parses `redundancy-group <id>` via strconv.Atoi(rgInst.name) with no range check, and schema_chassis.go documents the RG instance slot as an unvalidated identity token. buildHeartbeat sets HeartbeatGroup.GroupID = uint8(rg.GroupID) (heartbeat_manager.go:221) and MarshalHeartbeat writes it as one byte (heartbeat.go:144); the same uint8 truncation applies to HeartbeatMonitor.RGID. If node A is configured with `redundancy-group 260`, its heartbeat advertises GroupID = uint8(260) = 4. Node B UnmarshalHeartbeat builds peerGroups[4] from A's RG260 priority/weight/state; handlePeerHeartbeat -> runElection then evaluates B's real RG4 against A's RG260 data (electRG reads m.peerGroups[rg.GroupID]). The result is a cross-RG election decision (wrong owner, possible dual-active or dual-secondary) for two unrelated groups.

**Why it matters** — A committed-but-out-of-range RG ID produces silent cross-RG state aliasing on the peer rather than a commit rejection — a fail-open config/wire split in the HA control plane.

**Fix direction** — Add a commit-time validator bounding redundancy-group instance IDs to the supported range (e.g. 0..255, ideally the Junos 1..128), or widen the heartbeat GroupID/RGID fields and bump the heartbeat/HA protocol version; at minimum reject IDs that do not round-trip through uint8.

**Not a duplicate** — Related to #2466 (CLOSED: userspace-dp flow-cache RG epoch table fixed at 16, 'schema accepts them') but that is a Rust flow-cache invalidation gap at a threshold of 16; this is a distinct code path (pkg/cluster heartbeat wire uint8 GroupID/RGID) with a different threshold (256) causing peer election-state aliasing. Same root cause (unvalidated RG instance ID) but different mechanism and consumer; named per protocol.

---

#### F-262 · IP-monitor probeICMP accepts any echo reply by Type only — no ID/Seq or source-address validation, so a stray reply masks an unreachable target and suppresses failover

- **Severity:** 🟡 low  ·  **Confidence:** low
- **Module:** `go-cluster-core`  ·  **Location:** `pkg/cluster/monitor.go`:406
- **Labels:** `bug`, `correctness`, `ha`, `vsrx-parity`

```
	conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return false
	}

	parsed, err := icmp.ParseMessage(proto, reply[:n])
	if err != nil {
		return false
	}
	return parsed.Type == replyType
```

**Runtime trace**

probeICMP sends one echo (ID=0xbf, Seq=1) to target.Address, then reads the first datagram on an unconnected udp4/udp6 ICMP socket bound to 0.0.0.0/::. The source address returned by ReadFrom is discarded (n, _, err) and the parsed reply's Echo.ID/Seq are never compared to what was sent — the function returns true purely on parsed.Type == EchoReply. Consequence: any ICMP/ICMPv6 echo reply that lands on this socket within 800ms (a delayed reply, a reply from a middlebox/host other than the intended target, or any echo reply carrying the kernel-assigned ID) is accepted as 'target reachable'. evaluateTransition then resets consecutiveFail and the IP monitor never marks the target down, so the RG keeps full weight and HA never fails over even though the monitored next-hop is dead. (On Linux the SOCK_DGRAM ICMP socket demuxes by kernel-assigned ID, which limits cross-socket cross-talk, but source-address and reply Echo.ID/Seq are still unvalidated, so a wrong-source reply with the matching ID is accepted.)

**Why it matters** — ip-monitoring drives preferred-route / weight-based WAN failover; a false 'reachable' from an unrelated echo reply defeats the exact liveness signal the cluster relies on to demote a node whose upstream is gone.

**Fix direction** — Compare the parsed reply's Echo.ID and Seq to the values sent (use a per-probe random ID and incrementing Seq), and validate the reply source address returned by ReadFrom against the target; loop reading until the deadline so a mismatched early reply does not short-circuit the probe.

**Not a duplicate** — Searched issues for probeICMP / ICMP probe. #1918 (CLOSED) is tunnel-keepalive probeICMP that never probes; #2647 (CLOSED) is RPM ICMP hostname ctx; #2494 (CLOSED) is RPM IPv6 zone. None covers the cluster IP-monitor accepting an unvalidated echo reply (no ID/Seq/source check).

---

#### F-263 · applyRethServicesForRG/filterDHCPConfigForMasterRGs treat clusterPri||allVRRPMaster (IsActive) as 'MASTER' — RA/Kea can start for an RG whose VIPs the peer still owns; snapshotRethMasterState comment contradicts its code

- **Severity:** 🟡 low  ·  **Confidence:** low
- **Module:** `go-daemon-ha`  ·  **Location:** `pkg/daemon/daemon_ha.go`:156
- **Labels:** `bug`, `ha`, `docs`

```
// snapshotRethMasterState returns per-RG master state derived from all
// per-instance entries. An RG is MASTER only when ALL its instances are MASTER.
func (d *Daemon) snapshotRethMasterState() map[int]bool {
	d.rgStatesMu.RLock()
	defer d.rgStatesMu.RUnlock()
	out := make(map[int]bool, len(d.rgStates))
	for rgID, s := range d.rgStates {
		out[rgID] = s.IsActive()
	}
```

**Runtime trace**

VRRP (non-strict, non-direct) mode, node A primary for RG1 and RG2. During a failover window cluster state and VRRP disagree for RG2 (sync-hold, posture mismatch — the exact windows CheckVRRPPosture tolerates for 2-10s): cluster says primary but RG2's VRRP is still BACKUP and the peer holds RG2's VIPs. rgStateMachine.IsActive() for RG2 is TRUE via the clusterPri leg of reconcileLocked (rg_state.go:257). Now RG1's VRRP flips MASTER → watchVRRPEvents → applyRethServicesForRG(1) → the 'Collect RA configs from ALL master RGs' loop (line 951) and filterDHCPConfigForMasterRGs (line 1093) consult snapshotRethMasterState, see RG2 'master', and include RG2's interfaces → node A starts RA senders and Kea groups on RG2 interfaces while the peer (actual VRRP MASTER) is also running RA/Kea there → dual-router RAs (hosts ECMP-split default routes to both nodes' link-locals) and duplicate DHCP offers on RG2's subnet for the duration of the mismatch — the exact 'dual-router / dual-DHCP issues' the function's own contract comment (line 926-927) says this gate prevents.

**Why it matters** — Per-RG service ownership is the mechanism that prevents dual-RA/dual-DHCP; deriving it from the forwarding-oriented IsActive() (deliberately eager to avoid dual-inactive forwarding) applies a forwarding policy to a VIP-ownership-scoped concern, and the doc comment actively misstates the code (says AllVRRPMaster).

**Fix direction** — For service filtering, snapshot s.AllVRRPMaster() (VRRP mode) / directVIPOwned (direct mode) instead of IsActive(); at minimum fix the snapshotRethMasterState comment to match behavior and document the eager-services tradeoff.

**Not a duplicate** — Searched 'dual-RA', 'dual DHCP', 'applyRethServices', 'RethServices', 'snapshotRethMaster', 'RA sender' in the corpus — no hits. #93 (dropped-event service reconciliation), #132 (partial VRRP ownership for rg_active), #511 (strict-VIP blackhole removal on cluster-primary) are adjacent but none cover services keying off IsActive vs AllVRRPMaster. Low confidence because the eager behavior may be a deliberate anti-dual-inactive tradeoff — but then the contract comments are wrong.

---

#### F-264 · DHCPv6 RENEW/REBIND reply carrying an IA address with valid-lifetime 0 (server revocation) is treated as a fresh 1-hour lease and kept applied

- **Severity:** 🟡 low  ·  **Confidence:** low
- **Module:** `go-dhcp`  ·  **Location:** `pkg/dhcp/dhcp.go`:1265
- **Labels:** `bug`

```
	if addr.IsValid() {
		lease.Address = netip.PrefixFrom(addr, 128)
		lease.LeaseTime = validLT
	} else if len(result.prefixes) > 0 {
...
	if lease.LeaseTime == 0 {
		lease.LeaseTime = 3600 * time.Second
	}
```

**Runtime trace**

1) On a RENEW the server returns an IA_NA containing an OptIAAddress for the held address with ValidLifetime=0 — RFC 8415 §14: a 0 valid-lifetime means the address is no longer valid and the client MUST stop using it (renumber/revocation). 2) The parse loop (dhcp.go:1224-1228) sets addr=<the address> and validLT=0; addr.IsValid() is true so lease.Address is set and lease.LeaseTime=0 (dhcp.go:1265-1267). 3) The zero-guard at dhcp.go:1273 rewrites LeaseTime to 3600s. 4) parseV6Reply returns success; the run loop commits the lease via commitLease, (re)applying the revoked address to the interface and scheduling the next renewal an hour out — instead of dropping the binding and re-soliciting.

**Why it matters** — A DHCPv6 server that revokes a delegated address during renumbering is disregarded; the firewall keeps a revoked global address in service for an extra hour, a correctness/renumber-latency bug. Low confidence because active mid-renew revocation is uncommon and the loop still eventually recovers on lease expiry.

**Fix direction** — In parseV6Reply, skip OptIAAddress entries whose ValidLifetime==0 when selecting addr (and, if that leaves no valid IA_NA/IA_PD, return the no-address error so the loop re-acquires); do not floor a real 0 lifetime up to 3600s.

**Not a duplicate** — Searched for dhcpv6/valid-lifetime/IA_NA/renew/expiry. #2994/#1777 cover exchange type and lease preservation; #2271 (RA preferred>valid) and #2033/#2032 (RA lifetime withdrawal) are the pkg/ra sender, not the DHCPv6 client. No prior finding covers the valid-lifetime-0 IA address being floored to a fresh lease.

---

#### F-265 · Feeds accept a plaintext http:// feed URL with no scheme enforcement → MITM can tamper the denylist/allowlist prefix set

- **Severity:** 🟡 low  ·  **Confidence:** low
- **Module:** `go-obs`  ·  **Location:** `pkg/feeds/feeds.go`:101
- **Labels:** `security`, `hardening`

```
func resolveBaseURL(fsCfg *config.FeedServer) string {
	if fsCfg.URL != "" {
		return strings.TrimRight(fsCfg.URL, "/")
	}
	if fsCfg.Hostname != "" {
		return "https://" + strings.TrimRight(fsCfg.Hostname, "/")
```

**Runtime trace**

resolveBaseURL returns fsCfg.URL verbatim when set; nothing constrains it to https. readFeed then GETs it over plaintext http if configured that way. A network attacker on the path to the feed host can strip lines (removing their own prefix from a denylist so their traffic is permitted) or inject prefixes (adding a victim prefix to a denylist to blackhole it) — parseFeed will happily install the tampered set as a clean success. Only the Hostname-fallback path forces https; an explicit URL does not.

**Why it matters** — Dynamic-address feeds drive live policy match sets on a security appliance; fetching them over an unauthenticated transport lets an on-path attacker rewrite firewall policy inputs. Enforcing/warning on https (as feed-server deployments generally assume) is basic supply-chain hardening.

**Fix direction** — Reject or warn at commit on a non-https feed URL (allow http only behind an explicit opt-in), and consider surfacing the transport in FeedInfo so an operator can see a plaintext feed is in use.

**Not a duplicate** — Searched issues/prior-findings for feed URL/https/MITM/injection. Prior feed findings (#2993 invalid lines, #2050 retain-last-good, compiler_validate_strict feedServerBaseURLEmpty slash-only URL) concern parse quality and empty-URL bypass, not transport authenticity. MODULE NOTES flag feeds 'injection' as an open hunt. Novel; low confidence because some operators may intentionally use internal http feeds.

---

#### F-266 · natpoolalarm Monitor.Stop is not concurrency-safe: two concurrent Stop calls can double-close m.stop and panic

- **Severity:** 🟡 low  ·  **Confidence:** low
- **Module:** `go-ops`  ·  **Location:** `pkg/natpoolalarm/natpoolalarm.go`:178
- **Labels:** `bug`, `concurrency`

```
	m.mu.Lock()
	started := m.started
	m.mu.Unlock()
	select {
	case <-m.stop:
		// already stopped
	default:
		close(m.stop)
	}
```

**Runtime trace**

Two goroutines call Stop() on the same Monitor concurrently: both evaluate the select's non-blocking <-m.stop while the channel is still open, both fall to the default branch, both execute close(m.stop) -> the second close panics ('close of closed channel') and crashes xpfd. The doc comment promises 'safe to call ... and is idempotent', which holds only for SEQUENTIAL calls. Today the daemon wiring shields it: stopAndDiscardNATPoolAlarm (pkg/daemon/daemon_natpoolalarm.go:126) uses atomic Swap(nil) so exactly one caller ever reaches m.Stop() per instance — but that safety lives in the caller, not in the API that documents itself as idempotent, and any future direct second caller (shutdown path + bootstrap rollback racing) trips it.

**Why it matters** — A latent close-of-closed-channel panic in shutdown/rollback paths of a production firewall daemon turns a clean teardown into a crash; check-then-act on channel close is a classic race that sync.Once removes for free.

**Fix direction** — Replace the select/close pair with a sync.Once (stopOnce.Do(func(){ close(m.stop) })), or guard the close under m.mu with a stopped bool; keep the Swap(nil) caller pattern as belt-and-suspenders.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for natpoolalarm/Monitor.Stop/double close — only #2079 (feature) and #2114 (d.dp pointer race, a DIFFERENT race fixed via atomic.Pointer; it never covered Stop's internal channel close). Low confidence because current daemon wiring makes the race unreachable in production.

---

#### F-267 · Crashed helper process is never auto-respawned by the manager — the status loop only logs poll failures and ensureProcessLocked runs solely on Compile(), so a helper crash leaves the dataplane fail-closed until the next config commit or daemon restart

- **Severity:** 🟡 low  ·  **Confidence:** low
- **Module:** `go-usdp-core`  ·  **Location:** `pkg/dataplane/userspace/process.go`:514
- **Labels:** `bug`, `test-gap`

```
			} else {
				slog.Warn("userspace dataplane status poll failed", "err", err)
			}
```

**Runtime trace**

If the userspace-dp process crashes unexpectedly, m.proc (the *exec.Cmd) stays non-nil (nothing calls Wait outside the intentional stopLocked path, so it also becomes a zombie). statusLoop's per-second requestLocked(status) then fails with connection-refused; the loop takes the else branch and only slog.Warn's — it does NOT call ensureProcessLocked to respawn. The XDP shim's heartbeat map goes stale so transit fails closed (drop), but the helper is not restarted. ensureProcessLocked (the only respawn site) runs only from Compile() and syncSnapshotLocked's binding-plan-change branch; Compile is invoked on config commit / DHCP address change / feed update, and BumpFIBGeneration does NOT call Compile. So absent an operator commit or an xpfd restart, a crashed helper leaves the forwarding path down indefinitely.

**Why it matters** — For an always-on firewall dataplane, a single helper crash without automatic recovery is an availability gap; the heartbeat fail-closed protects correctness (no fail-open) but the box stops forwarding until a human/commit intervenes, and zombies accumulate until the next apply reaps them.

**Fix direction** — Have statusLoop detect a dead helper (repeated poll failure or reaped ProcessState) and drive a bounded-backoff respawn via ensureProcessLocked(m.cfg) + re-publish of lastSnapshot, or surface a health signal the daemon acts on. If leaving recovery to systemd/operator is deliberate, document it as an accepted contract and at least reap the child to avoid zombies.

**Not a duplicate** — Searched issues for 'respawn/helper crash/proc exit/supervise'; #925 (CLOSED) is the Rust WORKER-thread supervisor INSIDE the helper (catch_unwind/respawn), not a full helper PROCESS crash observed from Go. #757 (CLOSED) fixed only the log-spam when the helper is down, not respawn. #1666/#473 are BPF READY/crash-blind gating. No issue/finding covers the manager's lack of process-level respawn. Marked low confidence because heartbeat-fail-closed may be the intended safety response and external supervision may be assumed.

---

#### F-268 · estimate_cos_queue_wakeup_tick assumes the FULL class rate refills a shared v8 exact queue's local bucket — parked queues wake early and churn park/probe under multi-worker sharing

- **Severity:** 🟡 low  ·  **Confidence:** low
- **Module:** `rs-cos-tx`  ·  **Location:** `userspace-dp/src/afxdp/cos/queue_service/mod.rs`:1810
- **Labels:** `performance`

```
pub(in crate::afxdp) fn estimate_cos_queue_wakeup_tick(
    root_tokens: u64,
    root_rate_bytes: u64,
    queue_tokens: u64,
    queue_rate_bytes: u64,
    need_bytes: u64,
    now_ns: u64,
    require_queue_tokens: bool,
) -> Option<u64> {
```

**Runtime trace**

Config: shared_exact class rate R shared by N workers via a v8 lease (worker share = R x elapsed x my_flows/total_flows per 200us epoch). A worker's queue.hot.tokens < head_len after top-up -> the selector parks it with wake tick from estimate_cos_queue_wakeup_tick(root.tokens, root.shaping_rate_bytes, queue.hot.tokens, queue.transmit_rate_bytes(), head_len, ...) (call sites mod.rs:722-730, 1013-1024). cos_refill_ns_until computes deficit/R — but this worker's actual refill channel is the v8 lease grant, which accrues at roughly R/N (flow-proportional share), not R. With N=6 workers the wake tick underestimates the real availability time by ~6x: the timer wheel wakes the queue, prime+top-up grants less than head_len (ShareExhausted/ClassCap), the selector parks it again with another too-short tick. Each churn cycle burns a timer-wheel wake, a lease acquire_v8 (seqlock snapshot + CAS loop), and a selector pass, repeated ~N times per genuine service opportunity on every low-rate shared exact class under contention. Observable as drain_park_queue_tokens and cos_wheel_ticks_advanced climbing far faster than actual service events.

**Why it matters** — Wasted scheduler passes and cross-core lease cacheline traffic on the hot drain loop of every worker, growing with worker count — the exact regime (6-queue mlx5 VFs, 6 workers) the loss cluster runs. Also skews the park-reason telemetry used to tune fairness regressions.

**Fix direction** — For queues holding a v8 lease, estimate the queue refill rate as the worker's published fair share per epoch (worker_fair_share/EPOCH_DURATION_NS) rather than the full transmit_rate_bytes; fall back to the class rate when no lease is attached.

**Not a duplicate** — Grepped issues for park/wakeup/estimate — #916 (transparent-rate park limbo, CLOSED, different: rate==0 handling), #941/#2646 (V_min suspension/cadence, different mechanism), #1782 (undergrant cause telemetry — instruments this symptom but does not fix the estimator). No issue or prior finding addresses the wake-tick rate mismatch for v8-shared queues.

---

#### F-269 · Dynamic (FRR-learned) routes never reach the AF_XDP FIB — transit to OSPF/BGP/IS-IS/RIP/DHCP-learned prefixes is dropped as NoRoute

- **Severity:** 🟡 low  ·  **Confidence:** low  **⚠ DISPUTED (1 verifier refuted)**
- **Module:** `rs-forwarding`  ·  **Location:** `pkg/dataplane/userspace/routes.go`:19
- **Labels:** `bug`, `vsrx-parity`

```
// buildRouteSnapshots derives the helper FIB from config statics,
// connected prefixes, and ip-rule leak rules, then applies the
// ip-monitoring route overlay (#1827 PR-1b): each overlay entry
// REPLACES the entire (table, family, prefix) entry set — never merges
// next-hops — so an ECMP half-override is impossible by construction.
func buildRouteSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot, overlay []config.RouteOverlayEntry) []RouteSnapshot {
```

**Runtime trace**

Config: `set protocols ospf area 0 interface ge-0-0-1` (or BGP); FRR learns 192.168.100.0/24 from a peer and installs it in the kernel FIB. Transit packet trust->192.168.100.5 arrives on an XDP-bound dataplane NIC -> shim steers to XSK (only local-destination packets shunt to kernel) -> session miss -> resolve_forwarding() -> lookup_forwarding_resolution_inner (userspace-dp/src/afxdp/forwarding/mod.rs:1130-1217): dst not in local_v4; routes_v4["inet.0"] holds ONLY config statics + connected prefixes + ip-rule leak synthetics + ip-monitoring overlay (buildRouteSnapshots reads cfg.RoutingOptions.StaticRoutes, per-RI statics, connectedPrefixesForInterface, netlink.RuleList leaks — never the kernel/FRR RIB); no prefix contains dst -> no_route_resolution -> ForwardingDisposition::NoRoute -> poll_descriptor/mod.rs:3788 counts telemetry.dbg.no_route, disposition.rs:363 bump_route_miss, frame recycled (dropped). There is no compensating mechanism: no RTM_NEWROUTE monitor exists in userspace-dp (rg RTM_NEWROUTE/RTNLGRP_ROUTE -> no hits), no update_routes control verb (server/handlers/ has only forwarding-arm, neighbors, fabrics, snapshot...), and the Go snapshot builder never reads netlink.RouteList for FIB purposes (only for neighbor warmup probes in process.go). DHCP-learned default routes (collectDHCPRoutes -> FRR only) have the same fate on a DHCP-addressed dataplane WAN.

**Why it matters** — Feature Coverage advertises 'Routing: FRR integration (static, OSPF, BGP, IS-IS, RIP)' and ECMP, but any prefix reachable only via a dynamic protocol is a silent per-packet drop in the only runtime forwarding path. On a production appliance running BGP/OSPF this is total transit loss to learned destinations, discoverable only via the route_miss counter. The #1827 ip-monitoring overlay solved this narrowly for probe-driven preferred routes, showing the FIB-sync channel exists but was never generalized to the FRR RIB. All existing smoke/HA tests use static routes, so nothing exercises dataplane transit over a learned route.

**Fix direction** — Ingest the kernel FIB into the helper: either (a) subscribe to RTM_NEWROUTE/DELROUTE (RTNLGRP_IPV4_ROUTE/IPV6_ROUTE) in the Go daemon and stream incremental route updates to the helper via a new update_routes control verb (mirroring the update_neighbors path), or (b) extend buildRouteSnapshots to merge netlink.RouteListFiltered (per table) protocol routes, with a periodic + event-driven refresh and FIB-generation bump. Until then, document loudly in feature-gaps.md that the AF_XDP dataplane forwards only static/connected/leaked/overlay routes.

**Not a duplicate** — Searched issues-all.txt and prior-findings.md for 'route snapshot', 'buildRouteSnapshots', 'userspace FIB', 'FIB snapshot', 'OSPF/BGP + userspace/dataplane', 'route_miss', 'NoRoute'. Nearest hits: #2389/#2390 (static-route ECMP/preference at the same boundary — statics only), prior finding 'IPv6 ip-rule leaks emit NextTable <ri>.inet.0 → NoRoute' (routes.go, leak-rule bug), prior finding 'FRR reload failure splits kernel/FRR and userspace FIB' (daemon_ipmon overlay-publish ordering). None state that dynamic-protocol routes are absent from the helper FIB entirely; known-gaps.md's 'mixed kernel boundary' entry covers ARP/mgmt/IPsec punts, not transit routing.

---

#### F-270 · Empty-string address token is whitelisted through the #3711/#3367 fail-closed net: an all-placeholder v3 literal list or book row collapses to MatchNone — deny fail-open pinhole

- **Severity:** 🟡 low  ·  **Confidence:** low
- **Module:** `rs-policy`  ·  **Location:** `userspace-dp/src/policy.rs`:2613
- **Labels:** `security`, `bug`, `test-gap`

```
            "any4" | "any-ipv4" => any_v4 = true,
            "any6" | "any-ipv6" => any_v6 = true,
            "" => {}
            s => {
                if !parse_address(s, &mut v4, &mut v6) && malformed.is_none() {
                    malformed = Some(s.to_string());
                }
            }
```

**Runtime trace**

Hand-built / drifted snapshot (the #3711 threat model): rule {action "deny", source_literals: [""]}. parse_policy_state_with_counters: source_is_v3_shaped = true (the vec is non-empty — it contains one empty string). parse_v3_literal_set: "" hits the no-op arm at line 2613; no wildcard flags; v4/v6 vecs stay empty → from_v3_literals(empty) = MatchNone on both families. The #3711 UnrepresentableV3Address reject does NOT fire (it keys on a non-empty token that fails to parse; "" is whitelisted), so the deny rule matches NOTHING and traffic falls through to a later permit / default-permit — byte-identical failure mode to the malformed-literal fail-open #3711 closed. Same collapse for an address-book row prefixes_v4=[""] via parse_book_prefix_into (line 2657 'accept them so a degenerate snapshot does not hard-fail on a semantically empty token') → BookEntry v4=MatchNone → book-backed deny no-ops. The Go producer never emits "" (classifyPolicyAddresses skips empty tokens; book expansion returns false on empty values), so exposure is drift-only — exactly the exposure class the #3367/#3711 family was accepted for.

**Why it matters** — The fail-closed net around unrepresentable address material (#3261/#3367/#3711) exists precisely so a drifted snapshot cannot silently turn a deny into match-none; the deliberate "" carve-out reproduces that exact collapse when the placeholder is the only content of a side or a book family array.

**Fix direction** — Keep "" as a no-op only when other representable tokens exist; treat a v3 side or book family array whose tokens were ALL placeholders (yielding MatchNone with a non-empty input list) as UnrepresentableV3Address/UnrepresentableAddressBookPrefix, or simply reject "" on the v3/book paths (the Go contract never emits it there).

**Not a duplicate** — Searched prior-findings.md/issues for '3711', '3367', 'empty token', 'placeholder', 'MatchNone'. #3711 (closed, fix verified at HEAD) rejects MALFORMED non-empty tokens and wrong-family book tokens; prior findings 334/340/352 are the pre-#3711 shapes, now fixed. This is a residual of #3711 with a distinct mechanism: a WHITELISTED empty token (deliberate carve-out in the fix itself) rather than an unparseable one reaching the same MatchNone deny collapse. Named per protocol for residuals.

---

#### F-271 · `peer_has_confirmed_session` ignores REJECT_AFTER_TIME — correctness depends entirely on expire_sessions running first in the same tick

- **Severity:** 🟡 low  ·  **Confidence:** low
- **Module:** `rs-wg-coord`  ·  **Location:** `userspace-dp/src/afxdp/wg/engine.rs`:579
- **Labels:** `refactor`, `bug`

```
    pub(crate) fn peer_has_confirmed_session(&self, pubkey: &[u8; 32]) -> bool {
        let Some(peer) = self.peer_arc(pubkey) else {
            return false;
        };
        matches!(
            peer.current.read().unwrap().as_ref(),
            Some(session) if session.is_confirmed()
        )
    }
```

**Runtime trace**

drive_attempt_machine gates the NoSessionEdge trigger on `nosession_edge && !engine.peer_has_confirmed_session(peer)` (wg_control.rs:798). peer_has_confirmed_session returns true for a confirmed-but-EXPIRED (>180s) current session because it checks only is_confirmed(), unlike peer_has_usable_session (timers.rs:137) which also checks REJECT_AFTER_TIME. Today this is masked because run_wg_control_loop calls engine.expire_sessions(now) (wg_control.rs:584) before the per-peer loop, clearing expired sessions to None. If that ordering is ever changed, or a NoSession edge is evaluated on a path that has not just run expiry, a confirmed-but-expired session suppresses re-initiation while encap simultaneously rejects with Expired → silent stall.

**Why it matters** — The two 'is this session usable' predicates disagree on the expiry dimension; the safety of the discrepancy is an implicit call-ordering contract, not an invariant enforced by the predicate. Fragile coupling on the tunnel bring-up/recovery path.

**Fix direction** — Make peer_has_confirmed_session take now_ns and also require now-created_ns < REJECT_AFTER_TIME_NS (mirror peer_has_usable_session), so it cannot report an expired session as confirmed regardless of expire_sessions ordering.

**Not a duplicate** — Not in prior-findings.md (which has coordinator snapshot_refresh/control-socket findings, none about peer_has_confirmed_session vs expiry) nor any issue. #1888 introduced peer_has_usable_session with the expiry check but did not align peer_has_confirmed_session.

---

#### F-272 · policy/junos-host deny events are emitted unconditionally, ignoring the policy's `then log` selection (over-logging vs vSRX RT_FLOW_SESSION_DENY gating)

- **Severity:** 🟡 low  ·  **Confidence:** low
- **Module:** `x-default-deny`  ·  **Location:** `userspace-dp/src/afxdp/event_emit.rs`:156
- **Labels:** `vsrx-parity`, `performance`, `observability`

```
) {
    let Some(event_stream) = event_stream else {
        return;
    };
    let event = DataplaneEventPayload {
        kind: DataplaneEventKind::PolicyDeny,
        addr_family: flow.forward_key.addr_family,
        protocol: flow.forward_key.protocol,
        action: policy_action_to_rt_flow(action, reject_reply_enqueued),
```

**Runtime trace**

A matched deny/reject rule (transit at poll_descriptor/mod.rs ~2952 deny_reply_and_emit, or junos-host at emit_junos_host_deny) calls emit_policy_deny_event with NO reference to the rule's log_session_init/log_session_close flags. The function emits a PolicyDeny event whenever event_stream is Some — every denied packet. Because a denied flow installs no session, EVERY packet of a denied flow re-evaluates on the cold path and re-emits, so a denied-traffic flood produces one deny event per packet. vSRX emits RT_FLOW_SESSION_DENY only when the policy carries `then log session-init`; a bare `then deny` is a silent drop.

**Why it matters** — Divergence from vSRX deny-logging semantics (always-on vs then-log-gated) and a log/CPU amplification vector: a spoofed flood of denied packets emits an unbounded stream of deny events unless the downstream event stream rate-limits, and the operator cannot silence deny logging by omitting `then log`.

**Fix direction** — Gate the deny-event emission on the matched rule's log flags (log_session_init) to match vSRX, or document the always-on deny logging as an intentional security posture and confirm the event stream applies per-source rate limiting to the PolicyDeny kind.

**Not a duplicate** — Searched corpus for deny logging / then log / RT_FLOW_SESSION_DENY. #3610 added tuple-rich host-inbound deny events; #2508/#3534 wired then-log for PERMIT session-create/close and default-policy. None addresses that the DENY event path ignores the per-policy then-log selection and emits unconditionally.

---

## 7. Suggested issue split

Grouping the kept findings into fileable issues. P0/P1 are the High-severity
items (fix individually); the rest bundle by module to keep the tracker sane.

### P0 / P1 — file individually (24 High-severity)

| ID | Module | Title | Confidence |
|---|---|---|---|
| F-001 | `go-config-ifaces-cos-fw` | Hierarchical single-name `source-prefix-list <name>;` leaf is silently dropped from filter terms — term compiles unscoped with a clean strict commit | high |
| F-002 | `go-config-nat` | Deterministic NAT (CGNAT) is un-configurable via flat-set commands: sibling `port deterministic ...` leaves overwrite each other and `host address` is never parsed from Keys — the project's own documented quick-start config fails commit | high |
| F-003 | `go-config-nat` | `then destination-nat off` is accepted at commit but silently dropped — DNAT exemption rules fail open and the 'exempted' traffic is still translated by later rules | high |
| F-004 | `go-config-parse` | DeletePath on a bracket-list (multi-value) leaf silently deletes the ENTIRE list when given the first member, and errors on any other member — filter/policy match constraints vanish (fail-wide) | high |
| F-005 | `go-config-parse` | quoteKey never escapes backslashes but the lexer interprets \n and \\ inside quoted strings — values containing backslashes corrupt on every Format->Parse round-trip (HA config sync, rollback files) | high |
| F-006 | `go-config-policy` | Duplicate inner `match`/`then` blocks in one security policy are silently dropped by the compiler AND bypass every policy strict gate (#3113/#3114/#3115/#3141/#3044/#3043) — fail-open reachable via `load override` | high |
| F-007 | `go-config-routing-services` | Routing-instance kernel table IDs are positional — deleting/reordering one instance renumbers the rest and forces delete+recreate of unrelated live VRF devices | high |
| F-008 | `go-config-routing-services` | qualified-next-hop `preference`/`metric` are schema-declared but silently dropped by the compiler — Junos floating static route becomes active ECMP over the backup path | high |
| F-009 | `go-config-routing-services` | routing-options autonomous-system is parsed but never feeds BGP — canonical vSRX BGP config silently renders no `router bgp` at all | high |
| F-010 | `go-config-schema` | ECMP static route `next-hop [ gw1 gw2 ]` bracket list silently collapses to a single next-hop (canonical Junos ECMP spelling loses multipath) | high |
| F-011 | `go-config-validate` | WireGuard tunnel local identity (listen-port / private-key) never validated at commit — missing/malformed identity commits cleanly and the dataplane silently drops the whole tunnel | high |
| F-012 | `go-configstore` | Plain Store.Commit during a pending commit-confirmed window leaves the auto-rollback timer armed — the timer later reverts the newer committed config (eventengine remediation path is fully exposed) | high |
| F-013 | `go-conntrack-appid` | CLI `set schedulers ...` silently compiles to ZERO schedulers: top-level `schedulers` stanza is missing from setSchema, so flat-set tokens collapse onto one garbage leaf (feature un-authorable via set grammar; set-format save/reload destroys all schedulers) | high |
| F-014 | `go-conntrack-appid` | compileSchedulers drops the Junos `daily { start-time/stop-time }` container (and all day-of-week containers): a real-Junos scheduler compiles to ALWAYS-ACTIVE — time-bounded permit policy is permanently open (fail-open) | high |
| F-150 | `go-daemon-lifecycle` | commit-confirmed timeout rollback on the active node is never propagated to the HA peer, leaving the standby permanently on the abandoned config | medium |
| F-015 | `go-daemon-svc` | archiveConfig (transfer-on-commit) scps the stale boot-time xpf.conf — remote archives never contain the committed config | high |
| F-016 | `go-frr-routing` | rib-group kernel ip-rule mirror (pref 33000) is unreachable behind any main-table default route — imported interface routes are never consulted, and the dst-less rule is also skipped by the userspace leak snapshot | high |
| F-017 | `go-ipsec-wg` | normalizeAuthAlg renders canonical Junos truncation-suffixed integrity names (hmac-sha-256-128, hmac-sha1-96, hmac-md5-96) as strongSwan-invalid tokens — whole proposal rejected, tunnel never loads (never-filed follow-up promised in #2073 review) | high |
| F-151 | `go-obs` | Syslog stream write-timeout leaves a partial RFC 6587 frame on the TCP/TLS socket → permanent octet-counting framing desync | medium |
| F-152 | `go-usdp-ha-events` | Cross-worker seq-allocate/enqueue race produces out-of-order frames on the event-stream wire; the Go reader has zero reorder tolerance and treats any inversion as a session-sync gap (spurious full resync + disconnect) | medium |
| F-153 | `go-usdp-ha-events` | Telemetry frame dropped on a full event-stream channel burns its sequence number, and the Go reader misclassifies the resulting hole as a session-sync gap — spurious full owner-RG bulk export + reconnect, self-amplifying under load | medium |
| F-018 | `go-usdp-programs` | DNAT: rule-level `match destination-port` mishandled whenever `match application` is also configured — invalid tokens widen to wildcard-port (bypasses #3446 guard), valid ports are silently ignored or collapsed to the first port | high |
| F-154 | `rs-session` | Per-worker flow cache outlives its idle-reaped session: reused/resumed 5-tuple is served the dead flow's cached NAT+redirect decision, blackholing the reverse direction | medium |
| F-019 | `rs-wg-coord` | Responder rekey promotes an UNCONFIRMED session straight to `current` (no WG `next` keypair slot) → egress blackhole on every peer-initiated rekey, replay-amplifiable to a persistent egress DoS | high |

### P2 / P3 — bundle by module (Medium + Low severity)

| Module | Findings | IDs |
|---|---:|---|
| `go-api-grpc` | 5 | F-020, F-155, F-197, F-198, F-260 |
| `go-cli` | 7 | F-021, F-022, F-023, F-094, F-199, F-200, F-201 |
| `go-cluster-core` | 5 | F-024, F-202, F-203, F-261, F-262 |
| `go-cluster-sync` | 8 | F-025, F-026, F-095, F-096, F-156, F-157, F-204, F-258 |
| `go-config-ifaces-cos-fw` | 7 | F-027, F-028, F-029, F-030, F-031, F-097, F-205 |
| `go-config-nat` | 5 | F-032, F-033, F-098, F-158, F-206 |
| `go-config-parse` | 6 | F-034, F-035, F-036, F-037, F-099, F-159 |
| `go-config-policy` | 2 | F-160, F-207 |
| `go-config-routing-services` | 5 | F-038, F-161, F-162, F-163, F-208 |
| `go-config-schema` | 7 | F-039, F-040, F-041, F-042, F-043, F-100, F-209 |
| `go-config-validate` | 6 | F-044, F-045, F-046, F-101, F-102, F-210 |
| `go-configstore` | 7 | F-047, F-048, F-049, F-050, F-103, F-104, F-211 |
| `go-conntrack-appid` | 6 | F-051, F-052, F-105, F-106, F-164, F-212 |
| `go-daemon-ha` | 8 | F-053, F-054, F-107, F-165, F-166, F-167, F-168, F-263 |
| `go-daemon-lifecycle` | 5 | F-055, F-108, F-169, F-213, F-214 |
| `go-daemon-net` | 8 | F-056, F-057, F-109, F-110, F-111, F-170, F-215, F-216 |
| `go-daemon-svc` | 7 | F-058, F-059, F-060, F-061, F-112, F-171, F-217 |
| `go-dhcp` | 5 | F-172, F-173, F-218, F-219, F-264 |
| `go-frr-routing` | 7 | F-062, F-063, F-064, F-065, F-113, F-174, F-220 |
| `go-ipsec-wg` | 7 | F-066, F-067, F-114, F-115, F-175, F-176, F-221 |
| `go-networkd-mon` | 6 | F-068, F-177, F-178, F-222, F-223, F-224 |
| `go-obs` | 6 | F-069, F-179, F-180, F-225, F-226, F-265 |
| `go-ops` | 8 | F-070, F-071, F-116, F-117, F-181, F-227, F-228, F-266 |
| `go-usdp-core` | 5 | F-118, F-119, F-182, F-229, F-267 |
| `go-usdp-ha-events` | 5 | F-072, F-073, F-120, F-230, F-231 |
| `go-usdp-programs` | 6 | F-074, F-121, F-122, F-123, F-124, F-183 |
| `go-vrrp-ra` | 6 | F-075, F-076, F-077, F-125, F-232, F-233 |
| `rs-cos-tx` | 6 | F-078, F-079, F-126, F-234, F-235, F-268 |
| `rs-filter` | 6 | F-080, F-127, F-128, F-129, F-184, F-236 |
| `rs-forwarding` | 5 | F-081, F-082, F-130, F-185, F-269 |
| `rs-nat` | 8 | F-083, F-131, F-132, F-186, F-237, F-238, F-239, F-240 |
| `rs-policy` | 8 | F-084, F-133, F-134, F-135, F-187, F-241, F-242, F-270 |
| `rs-poll-descriptor` | 4 | F-136, F-188, F-243, F-259 |
| `rs-screen` | 4 | F-085, F-137, F-138, F-244 |
| `rs-server` | 5 | F-086, F-087, F-139, F-245, F-246 |
| `rs-session` | 2 | F-140, F-189 |
| `rs-umem-frame` | 7 | F-088, F-141, F-142, F-143, F-247, F-248, F-249 |
| `rs-wg-coord` | 4 | F-190, F-191, F-250, F-271 |
| `rs-worker` | 5 | F-144, F-192, F-251, F-252, F-253 |
| `x-default-deny` | 5 | F-145, F-193, F-254, F-255, F-272 |
| `x-hpc` | 6 | F-089, F-146, F-147, F-148, F-194, F-195 |
| `x-tests-build` | 8 | F-090, F-091, F-092, F-093, F-149, F-196, F-256, F-257 |

### vSRX parity tracker (113 findings labelled `vsrx-parity`)

Consider a single umbrella epic linking these for feature-completeness
planning:

| ID | Module | Title |
|---|---|---|
| F-020 | `go-api-grpc` | Config secret redaction (#2053) is bypassed by every raw-AST render surface (REST /config/show\|export\|search\|show-rollback\|compare and gRPC ShowConfig) — cleartext PSK/auth-key/community leaks |
| F-022 | `go-cli` | `monitor traffic ... matching <expr>` truncates the tcpdump filter to the first token, silently dropping the rest of the expression |
| F-023 | `go-cli` | read-only / config-viewer login classes can run `monitor traffic` (root tcpdump full packet capture) and write flow-trace files — `monitor` mapped to PermView |
| F-094 | `go-cli` | Local CLI `ping`/`traceroute` do not clamp count/size, diverging from the REST and gRPC surfaces that share the diagcmd builder |
| F-199 | `go-cli` | Config-mode dispatch requires exact keywords (no Junos prefix abbreviation), diverging from operational-mode dispatch and from config-mode Tab completion which resolves prefixes |
| F-200 | `go-cli` | Pipe `\| match`/`\| except`/`\| find` use plain substring (strings.Contains), not Junos regular expressions |
| F-262 | `go-cluster-core` | IP-monitor probeICMP accepts any echo reply by Type only — no ID/Seq or source-address validation, so a stray reply masks an unreachable target and suppresses failover |
| F-156 | `go-cluster-sync` | Config sync applies via unordered goroutines with no sequence number — a rapid pair of commits can leave the standby converged on the OLDER config |
| F-027 | `go-config-ifaces-cos-fw` | CoS rewrite-rules drop the Junos-canonical inline `loss-priority low code-point ef;` leaf — the #1809 fix was applied to both classifier collectors but not to collectCoSDSCPRewriteCodePoint |
| F-028 | `go-config-ifaces-cos-fw` | Interface-level CoS binding (`class-of-service interfaces <if> scheduler-map/shaping-rate` without `unit`) — the canonical Junos attach form — is silently dropped at commit with no warning |
| F-029 | `go-config-ifaces-cos-fw` | Junos `interfaces interface-range` compiles into a phantom interface literally named "interface-range"; member NICs stay unconfigured and are forced admin-down by the claim-all reconcile |
| F-030 | `go-config-ifaces-cos-fw` | Non-inet6 firewall families (any/mpls/ethernet-switching/...) are folded into FiltersInet — a same-name cross-family filter silently overwrites the real IPv4 filter (fail-open) |
| F-097 | `go-config-ifaces-cos-fw` | Scheduler `transmit-rate percent <n>` / `remainder` (the most common Junos scheduler forms) are unsupported — rejected at commit despite feature-gaps claiming 'bandwidth %' Done, and the lenient path compiles percent to ~16 bit/s |
| F-003 | `go-config-nat` | `then destination-nat off` is accepted at commit but silently dropped — DNAT exemption rules fail open and the 'exempted' traffic is still translated by later rules |
| F-032 | `go-config-nat` | No commit gate for the NAT64 `prefix` value: a non-/96 or malformed prefix commits green, then the Rust helper rejects the ENTIRE forwarding rebuild — the whole commit (and every later one until fixed) never reaches the dataplane |
| F-033 | `go-config-nat` | SNAT pool `port` stanza: Junos-native `port range <low> to <high>` and `port no-translation` are silently ignored (defaults 1024-65535 PAT applied), and out-of-range/reversed low/high values commit green then kill the rule at runtime |
| F-158 | `go-config-nat` | compileNAT reads only the FIRST `source`/`destination`/`static`/`nat64`/`proxy-arp` block per `nat` node — a duplicate sub-block from hierarchical load override is silently discarded (SNAT rule-sets vanish, traffic egresses untranslated) |
| F-004 | `go-config-parse` | DeletePath on a bracket-list (multi-value) leaf silently deletes the ENTIRE list when given the first member, and errors on any other member — filter/policy match constraints vanish (fail-wide) |
| F-034 | `go-config-parse` | #2008/#2051 display-set round-trip is broken for deactivated multi-value leaves: FormatSet emits `deactivate <full list>` but DeactivatePath/deletePath lack SetPath's #2419 absorb and fail with 'container does not exist' on replay |
| F-035 | `go-config-parse` | Annotations are emitted verbatim into /* */ block comments — an annotation containing */ silently injects tokens/statements into the re-parsed config on HA sync and rollback reload (and all annotations are dropped on any text round-trip) |
| F-036 | `go-config-parse` | RenamePath cannot rename any non-first sibling: removeNode takes the FIRST first-key match instead of preferring full-key matches, so `rename ... policy second to policy X` fails 'source not found' |
| F-037 | `go-config-parse` | navigatePath's single-key branch returns only the FIRST matching node, so `show configuration <path>` ending at a repeated keyword (name-server, security-zone, ...) silently hides all other instances across text/set/json/xml renderers |
| F-099 | `go-config-parse` | Structured renderers are malformed for real configs: FormatXML emits invalid XML element names for value-leaves (e.g. <ge-0/0/0.0/>) and nodesToJSON collapses repeated leaves last-writer-wins, so `\| display xml` is unparseable and `\| display json` drops list members |
| F-159 | `go-config-parse` | apply-groups drops group-contributed leaf-list values whenever the target already has ANY leaf with the same first key (hasMatchingLeaf matches Keys[0] only) — vSRX merges leaf-lists from groups |
| F-006 | `go-config-policy` | Duplicate inner `match`/`then` blocks in one security policy are silently dropped by the compiler AND bypass every policy strict gate (#3113/#3114/#3115/#3141/#3044/#3043) — fail-open reachable via `load override` |
| F-207 | `go-config-policy` | Duplicate `host-inbound-traffic` (and `screen`/`address-book`) blocks under one security-zone are last-write-wins in compileZones — operator's earlier host-inbound services silently lost (non-additive vs Junos; management-service loss risk) |
| F-008 | `go-config-routing-services` | qualified-next-hop `preference`/`metric` are schema-declared but silently dropped by the compiler — Junos floating static route becomes active ECMP over the backup path |
| F-009 | `go-config-routing-services` | routing-options autonomous-system is parsed but never feeds BGP — canonical vSRX BGP config silently renders no `router bgp` at all |
| F-038 | `go-config-routing-services` | IKE dead-peer-detection: bare statement disables DPD entirely, and an interval/threshold-only block sets the DPD mode to the literal string "interval" — dpd_action silently degrades to strongSwan's clear |
| F-161 | `go-config-routing-services` | IKE and IPsec policy `proposals [ p1 p2 ]` truncate to the first proposal — negotiation preference list silently narrowed to one crypto suite |
| F-162 | `go-config-routing-services` | RIP export/redistribute left off the #2587 multi-value sweep — bracket-list policies truncate to the first entry (group export and top-level redistribute read only Keys[1]) |
| F-163 | `go-config-routing-services` | routing-instance `interface [ a b ]` bracket list keeps only the first interface — remaining ports silently stay outside the VRF (isolation break) |
| F-010 | `go-config-schema` | ECMP static route `next-hop [ gw1 gw2 ]` bracket list silently collapses to a single next-hop (canonical Junos ECMP spelling loses multipath) |
| F-039 | `go-config-schema` | IKE gateway `version` and IKE policy `mode` are untyped free-form leaves — a typo silently weakens crypto posture (v2-only pin lost, aggressive→main fallback) |
| F-040 | `go-config-schema` | IKE/IPsec policy `proposals [ a b ]` leaf-list truncates to the first proposal (silent crypto-negotiation narrowing) |
| F-041 | `go-config-schema` | List-valued system leaves (ntp server, archival archive-sites, ssh-rsa/ed25519/dsa authorized keys) modeled single-value — a second flat-set silently deletes the first |
| F-042 | `go-config-schema` | policy-options prefix-list body values collapse: single-line bracket form compiles an EMPTY prefix-list; flat one-line form keeps only the first prefix |
| F-100 | `go-config-schema` | snmp location/contact/description are compiled but absent from schemaSNMP — compiled-but-not-schema-visible drift (no completion, no trailing-token gate) |
| F-209 | `go-config-schema` | `route-filter <prefix> ?` completion shows the "<prefix>" placeholder for the MATCH-TYPE slot — per-node placeholder cannot describe the second identity arg |
| F-011 | `go-config-validate` | WireGuard tunnel local identity (listen-port / private-key) never validated at commit — missing/malformed identity commits cleanly and the dataplane silently drops the whole tunnel |
| F-046 | `go-config-validate` | WG peer `endpoint` accepted at commit in forms the Rust dataplane cannot parse (bare IP, port-stripped v6, out-of-range port) — peer silently degrades to responder-only |
| F-012 | `go-configstore` | Plain Store.Commit during a pending commit-confirmed window leaves the auto-rollback timer armed — the timer later reverts the newer committed config (eventengine remediation path is fully exposed) |
| F-047 | `go-configstore` | Bare commit while a confirm is pending returns success WITHOUT committing staged candidate edits, on all three service surfaces (gRPC/REST/CLI) |
| F-048 | `go-configstore` | clusterReadOnly is enforced only at EnterConfigure* — a config session open across a primary->secondary RG0 transition can still Set/Delete/Load and Commit on the read-only secondary |
| F-050 | `go-configstore` | master-password at-rest encryption is defeated by plaintext sibling copies: rollback slots, archives and rescue.conf carry the full config (IKE PSKs etc.) in 0644 world-readable plaintext |
| F-103 | `go-configstore` | db.go candidate/rollback DB API (ReadCandidate/WriteCandidate/DeleteCandidate/ReadRollback/WriteRollback/DeleteRollback) is dead code that implies an encrypted rollback store nobody uses |
| F-211 | `go-configstore` | Commit-confirmed timeout rollback destroys the unconfirmed config — Junos keeps it reachable as rollback 1; here only a sha256 hash survives in the journal |
| F-013 | `go-conntrack-appid` | CLI `set schedulers ...` silently compiles to ZERO schedulers: top-level `schedulers` stanza is missing from setSchema, so flat-set tokens collapse onto one garbage leaf (feature un-authorable via set grammar; set-format save/reload destroys all schedulers) |
| F-014 | `go-conntrack-appid` | compileSchedulers drops the Junos `daily { start-time/stop-time }` container (and all day-of-week containers): a real-Junos scheduler compiles to ALWAYS-ACTIVE — time-bounded permit policy is permanently open (fail-open) |
| F-052 | `go-conntrack-appid` | Scheduler date windows evaluated in UTC while `now` and time-of-day run in local time: with `set system time-zone` applied, start/stop-date boundaries shift by the UTC offset (window opens hours early or late) |
| F-106 | `go-conntrack-appid` | Zone-detail policy summary omits wildcard zone-pair sets (`from-zone any` / `to-zone any`, the #3090 tier): summary can print '(no zone-pair or global policies affecting this zone)' while a wildcard rule governs the zone's traffic |
| F-054 | `go-daemon-ha` | directSendGARPs gateway ARP probe still uses pre-#2377 'force last octet to .1' target — broken on /25+ subnets in the DEFAULT private-rg-election mode |
| F-108 | `go-daemon-lifecycle` | applyKernelTuning never restores redirects / ipv6 zero-hop-limit sysctls when the config leaves are removed (non-declarative) |
| F-150 | `go-daemon-lifecycle` | commit-confirmed timeout rollback on the active node is never propagated to the HA peer, leaving the standby permanently on the abandoned config |
| F-057 | `go-daemon-net` | renameRethMember downs the RETH member for rename and never brings it back up — recovery path leaves the data-path link DOWN (sibling of fixed #2083, uncovered function) |
| F-216 | `go-daemon-net` | deriveKernelName/pciAddrToEnp synthesizes only the 'enpXsY[fZ]' name shape — ignores PCI domain, phys_port_name (npX) and slot-based (ensN) udev naming, writing OriginalName= values udev will never match |
| F-015 | `go-daemon-svc` | archiveConfig (transfer-on-commit) scps the stale boot-time xpf.conf — remote archives never contain the committed config |
| F-058 | `go-daemon-svc` | NetFlow v9/IPFIX export protocolIdentifier is 0 for every non-TCP/UDP/ICMP session — callbacks re-parse the rendered protocol name instead of using EventRecord.ProtocolNum |
| F-059 | `go-daemon-svc` | SNMP agent and linkUp/linkDown trap monitor are boot-gated only — day-2 commit adding snmp or trap-groups is inert until daemon restart |
| F-060 | `go-daemon-svc` | system archival configuration transfer-interval is parsed and typed but never implemented — periodic archival silently does nothing |
| F-171 | `go-daemon-svc` | monitorLinkState exits permanently and silently when the netlink subscription closes (ENOBUFS overrun) — no resubscribe, unlike the neighbor listener |
| F-172 | `go-dhcp` | DHCP relay never re-resolves giaddr: an interface address change (renumber commit / DHCP renew, ifindex unchanged) silently breaks the reply path |
| F-173 | `go-dhcp` | DHCPv4 client treats a RENEWING DHCPNAK identically to a timeout: keeps the revoked address and waits for T2 instead of immediate re-acquire (RFC 2131 §4.4.5) |
| F-218 | `go-dhcp` | DHCP client ignores server-supplied renewal timers (v4 options 58/59, v6 IA_NA/IA_PD T1/T2), always deriving T1/T2 from lease/valid-lifetime |
| F-219 | `go-dhcp` | DHCP relay overwrites a non-zero incoming giaddr (breaks cascaded relay chains) and inserts only Option 82 circuit-id (no remote-id) |
| F-016 | `go-frr-routing` | rib-group kernel ip-rule mirror (pref 33000) is unreachable behind any main-table default route — imported interface routes are never consulted, and the dst-less rule is also skipped by the userspace leak snapshot |
| F-062 | `go-frr-routing` | FRR IS-IS render drops the per-interface `level` override (no `isis circuit-type`) and never activates IPv6 (`ipv6 router isis` missing) — IS-IS is IPv4-only and interface level statements are silently ignored |
| F-063 | `go-frr-routing` | GRE tunnel `keepalive` is a silent no-op on the production userspace dataplane: every tunnel is AnchorOnly and applyAnchorLocked never starts (and actively stops) keepalive runners; no Rust-side GRE keepalive exists and commit accepts the knob without warning |
| F-065 | `go-frr-routing` | show route (CLI/gRPC/REST) renders kernel ECMP/multipath routes with no next-hops: routeToEntry ignores netlink Route.MultiPath, so FRR maximum-paths and multi-next-hop static routes display as a bare 'direct' entry |
| F-174 | `go-frr-routing` | next-table kernel mirror scope divergence: per-instance next-table static routes are never programmed as ip rules (kernel path loses the leak), while global next-table rules at pref 100 fire before the l3mdev VRF rule (pref 1000) and hijack VRF-ingress kernel traffic |
| F-017 | `go-ipsec-wg` | normalizeAuthAlg renders canonical Junos truncation-suffixed integrity names (hmac-sha-256-128, hmac-sha1-96, hmac-md5-96) as strongSwan-invalid tokens — whole proposal rejected, tunnel never loads (never-filed follow-up promised in #2073 review) |
| F-066 | `go-ipsec-wg` | df-bit 'set' and 'clear' are mapped to the wrong copy_df values — 'clear' silently copies the inner DF bit and 'set' clears it (mapping inverted, pinned by tests) |
| F-067 | `go-ipsec-wg` | parseSAOutput parses a fictional SA format — real `swanctl --list-sas` output never populates LocalAddr/RemoteAddr/TS/byte counters, so every SA-status surface (CLI/gRPC/REST) is blank |
| F-175 | `go-ipsec-wg` | Deleting an IPsec VPN never terminates its established SAs — `swanctl --load-all` only unloads config, so the removed tunnel keeps forwarding until hard lifetime/reauth (vSRX clears SAs at commit) |
| F-176 | `go-ipsec-wg` | Rendered swanctl secrets carry no `id` selectors — with two or more PSK VPNs charon has no way to pick the right PSK per peer, breaking one tunnel's authentication |
| F-221 | `go-ipsec-wg` | `pre-shared-key hexadecimal` is silently mishandled end-to-end: hex digits rendered as ASCII text (or dropped entirely in block form) instead of swanctl 0x hex secret |
| F-068 | `go-networkd-mon` | LLDP never starts on Junos slash-named interfaces (ge-0/0/1) — interface name passed to net.InterfaceByName without LinuxIfName normalization |
| F-223 | `go-networkd-mon` | LLDP shutdown advertisement (TTL=0) is inserted/refreshed into the neighbor cache instead of removing the neighbor (IEEE 802.1AB deviation) |
| F-224 | `go-networkd-mon` | LLDP transmit-interval and hold-multiplier have no schema range validation; advertised TTL (interval*holdMult) truncated to uint16 and can wrap |
| F-069 | `go-obs` | SNMP trap-group `version` is parsed by the schema but has no typed-config field → v1 trap-groups always emit v2c traps |
| F-225 | `go-obs` | RT_FLOW structured `session-id` is a daemon-local monotonic log counter → SESSION_CREATE and SESSION_CLOSE for the same flow carry different ids and it resets on restart |
| F-226 | `go-obs` | SNMP trap-group `categories` parsed but never stored/honored — every trap-group receives only link traps regardless of configured category filter |
| F-071 | `go-ops` | natshow rule detail prints per-zone-pair SNAT/DNAT session totals as the per-rule 'Number of sessions', misattributing counts to every rule |
| F-181 | `go-ops` | pool-utilization-alarm hard-rejects a raise-threshold-only config that is legal on vSRX (clear-threshold is optional in Junos) |
| F-228 | `go-ops` | show chassis forwarding Uptime reports xpfd control-daemon uptime, not the forwarding helper's — helper crash/respawn is invisible |
| F-182 | `go-usdp-core` | Control-socket RPC deadline is a fixed 3s while #2744 raised the apply_snapshot body cap to 64MB — large feed-backed snapshots time out mid-apply, diverging desired vs applied state |
| F-229 | `go-usdp-core` | PrepareLinkCycle swallows stop_workers failure (void return, no rollback) and the intended rollback helper reEnableUserspaceCtrlLocked is dead code — a failed worker-stop leaves ctrl disabled and lets the caller proceed with the link DOWN/UP the function exists to guard |
| F-072 | `go-usdp-ha-events` | Port-mirroring config with duplicate ingress interface (or negative rate) passes commit, then silently disables ALL mirror instances at snapshot build (fail-closed whole-table drop with only a Warn) |
| F-018 | `go-usdp-programs` | DNAT: rule-level `match destination-port` mishandled whenever `match application` is also configured — invalid tokens widen to wildcard-port (bypasses #3446 guard), valid ports are silently ignored or collapsed to the first port |
| F-075 | `go-vrrp-ra` | A router-advertisement nat64prefix lifetime > 65528s (or an inherited router default-lifetime that large) makes ndp.PREF64 marshal fail, aborting the ENTIRE RA — the interface silently stops advertising prefixes, RDNSS, and the router itself |
| F-076 | `go-vrrp-ra` | RFC 5798 §6.4.2 violation: a BACKUP never adopts the Master's advertised interval — masterDownInterval always uses the LOCAL advert interval, so an interval mismatch flaps instead of converging |
| F-077 | `go-vrrp-ra` | VRRP accept-data is parsed and stored but never enforced — the VIP is always a live kernel address, so xpf always accepts data to the VIP regardless of the configured (or defaulted-off) accept-data setting |
| F-080 | `rs-filter` | Input-filter `then count` terms double-count: verdict evaluator and TX-selection evaluator both record the same term for the same packet (2x per packet on DSCP/L4-sensitive CoS filters) |
| F-127 | `rs-filter` | CachedThreeColorPolicers hard-caps at 2 runtimes — third+ matched policer silently never meters on the flow-cache hit path (under-policing vs live path) |
| F-184 | `rs-filter` | flexible-match-range `bit-offset` (and `flexible-range-name`) silently dropped by the range parser — term matches at the wrong bit position with a clean commit |
| F-081 | `rs-forwarding` | Dual-fabric HA: dataplane fabric redirect always pins to the first fabric link — no liveness check and no failover to fab1 |
| F-185 | `rs-forwarding` | GRE/IPIP tunnel endpoints with unparseable outer source/destination are silently dropped from the forwarding state (fail-open config narrowing, inconsistent with #2409/#2410 fail-closed posture) |
| F-269 | `rs-forwarding` | Dynamic (FRR-learned) routes never reach the AF_XDP FIB — transit to OSPF/BGP/IS-IS/RIP/DHCP-learned prefixes is dropped as NoRoute |
| F-083 | `rs-nat` | NPTv6 silently mistranslates addresses whose adjusted word is 0xFFFF instead of RFC 6296-mandated discard (/48) or next-word selection (/64) — reply collapses onto the 0x0000 host |
| F-186 | `rs-nat` | Pool-mode SNAT never translates the ICMP query identifier (RFC 5508 REQ-1 / vSRX NAPT parity): colliding echo IDs from different internal hosts behind one pool address produce identical translated tuples |
| F-188 | `rs-poll-descriptor` | Non-TCP reject reply builds source IP from the unresolved PHYSICAL parent ifindex, so `then reject` silently drops on VLAN sub-interfaces (residual of #3035) |
| F-259 | `rs-poll-descriptor` | Flowless (non-first fragment) transit packets resolving to MissingNeighbor bypass zone security policy and fall to kernel FIB reinject |
| F-085 | `rs-screen` | Flowless screen branch bypasses src-independent screens (LAND anti-spoof, icmp-flood, udp-flood, ip-source-route) for non-query ICMP and non-first fragments |
| F-244 | `rs-screen` | Flowless-fragment screen DROP events log UNSPECIFIED (0.0.0.0 / ::) source and destination, losing attacker attribution for teardrop/ping-of-death |
| F-086 | `rs-server` | export_all_sessions HA bulk export runs entirely under the global ServerState lock with per-frame lossless backpressure — the #2962 fix was applied only to owner-RG export |
| F-019 | `rs-wg-coord` | Responder rekey promotes an UNCONFIRMED session straight to `current` (no WG `next` keypair slot) → egress blackhole on every peer-initiated rekey, replay-amplifiable to a persistent egress DoS |
| F-190 | `rs-wg-coord` | Responder does not enforce per-peer TAI64N handshake anti-replay — a captured msg1 is accepted and replayed indefinitely (WG §5.4.4 gap) |
| F-191 | `rs-wg-coord` | Responder handshake-flood CPU DoS: MAC1-only admission (keyed on the public key) forces full X25519 crypto per forged msg1 on the single per-tunnel control thread; no cookie/MAC2 under-load defense |
| F-250 | `rs-wg-coord` | No regression test that xpf egress survives a peer-initiated rekey (2-slot rotation blackhole is untested) |
| F-252 | `rs-worker` | fabric_queue_hash: the FIRST fragment of a datagram hashes WITH ports while its non-first fragments hash port-less — same datagram splits across different fabric egress bindings, defeating #2357's stated fragment-stability invariant |
| F-193 | `x-default-deny` | `to-zone junos-host` DENY/REJECT is silently NOT enforced for ordinary direct host-bound traffic (kernel-shunt bypass of the junos-host security policy) |
| F-255 | `x-default-deny` | No test pins that a `to-zone junos-host then deny` actually denies direct (non-DNAT) host-bound traffic — the documented 'enforced' claim is unverified against the kernel-shunt path |
| F-272 | `x-default-deny` | policy/junos-host deny events are emitted unconditionally, ignoring the policy's `then log` selection (over-logging vs vSRX RT_FLOW_SESSION_DENY gating) |

---

_Generated from the completed 42-module adversarial review workflow
(344 agents, 0 errors). Base `ddf9f58701ef`._
