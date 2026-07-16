# Cohort 1: Policy Verdict Engine — Deep Audit — 33b891d11

Base: 33b891d11 (merge PR #4563 — navigatePath fix)
Output: /tmp/ps-review-036-cohort1.md
Branch: master

## Duplicate-suppression summary

Sources checked:
- `/tmp/all_findings.txt` — 274 entries (F-001..F-274)
- GitHub issues — 300 open+closed (dedup queries for policy, default-policy, wildcard, junos-host, address-excluded, l4_present, global-scope, flowless, normalizeAny, etc.)
- `_Log.md` — last 100 lines + grep for relevant fixes
- `/tmp/ps-review-018..035` — 14 prior deep reviews on master
- `/tmp/ps-review-034-final.md` — prior cohort-5 (NAT) audit on 8cd816e35

CLOSED (fixed, NOT re-reported):
- #4562 navigatePath intermediate descent (ps-035 N-1) — fixed on this HEAD via #4563
- #4556 cli/api 3x LOW hardening (rollback n=0, monitor quote-strip, validateMultiValueLeaf 'to') — fixed/verified
- #4544 host-inbound-traffic dup block — fixed (mergeHostInbound)
- #4543 screen IPv4 options TLV break — fixed
- #4541 writeJSON header-before-encode — fixed
- #4540 monitor traffic keyword-as-iface — fixed
- #4539 session cache non-handshake TCP — fixed
- #4535 three-color policer, #4534 PBR discard, #4526 DHCP overflow, #4525 RA interval, #4524 monitor injection (HIGH), #4521 NAT pool, #4520/#4519/#4518/#4517 — all CLOSED
- #3065 default-policy fail-open (zero value = permit) — fixed (DefaultPolicy=PolicyDeny init in compiler.go:1957 + compiler_security_policy.go:18)
- #3402 UnresolvableZoneReference, #3261 sentinel, #3367/#3711 malformed address, #3712 ICMP field validation, #3713 duplicate rule/policy id, #3405 empty zone default-deny — all CLOSED/verified
- #3291 flowless transit fail-open (#4024), #3292 flowless junos-host fail-open, #3277/#2449 truncated ICMP fail-closed, #3008 meta-only ICMP — all CLOSED/verified
- #3113/#3142/#3673 unsupported match leaf / swallowed structural tokens, #3150 unresolvable protocol, #3109 protocol-less app, #3043 terminal action, #3060 bare log — all CLOSED

OPEN (already filed, NOT re-reported unless materially new):
- #4559 deterministic NAT (CGNAT) — OPEN, advisory WARNING added, runtime enforcement still missing, tracked. NOT re-filed (explicitly in dedup prompt).
- #4555 XDP MAX_EXT_HDRS=6 vs userspace 8 — OPEN LOW, fail-closed perf only
- #4549 4× LOW batch (VRRP hop-limit, HA IPv4-only, PSK zeroize, same-node-id), #4548 MaxAdverInt flap, #4547 DNS stall, #4546 WG rekey — OPEN LOW, not re-reported
- #4544 duplicate host-inbound (already fixed/closed), #4543 screen TLV (already fixed/closed) — listed as CLOSED above
- #2387 bare 5-tuple P0, #4146 junos-host XDP shim, #3226 system-services all, #4313 opt-in schema, #4455 HI-1 multicast/broadcast, #4478 IPIP decap zone — OPEN known, cohort out-of-scope or in other cohort
- normalizeAnyInCIDRs dead no-op (F-124/F-145) — known, tracked in all_findings, never filed as GH issue, NOT security fail-open, dead dedup code (cleanV4/V6 = v4[:0] slice-reuse but never appends filtered result — returns original input unchanged). Harmless.

Intentional divergences (NOT bugs):
- Intrazone default-permit (documented)
- Host-originated junos-host rejection (arch: egress via kernel TX, never RX gate)
- IPsec passthrough exempt from host-inbound (ratified Option A)
- `from-zone junos-host to-zone <z>` zone-pair rejected at commit (#4230), `global match from-zone junos-host` rejected (#3611 Piece A)
- NAT64 cross-family (V6 src / V4 dst) mixed-tuple only, (V4 src / V6 dst) never matches — NAT46 not supported
- Empty `source_addresses` = no constraint = MatchAny (legacy convention), empty `source_literals` = MatchNone (V3 convention) — by design, not a divergence
- `source_v4_empty && source_v6_empty` cross-family fail-closed (#3023): V4-only exclusion trivially doesn't exclude a V6 packet (matches), V6-only exclusion doesn't exclude a V4 packet — intentional

## Module / verdict-path inventory

| Module | File(s) | LOC | Read | Status |
|--------|---------|-----|------|--------|
| Rust policy engine | userspace-dp/src/policy.rs | 4224 | Full (6 reads, 500-line chunks, all tiers) | Deep-reviewed |
| Rust forwarding / session-miss policy gate | userspace-dp/src/afxdp/poll_descriptor/mod.rs §240-430, §2500-2600, §3400-3700, §4300-4700 | 6095 | Policy-relevant sections (4 reads) | Deep-reviewed |
| Rust host-inbound / junos-host | userspace-dp/src/afxdp/forwarding/host_inbound.rs | 815 | Full | Deep-reviewed |
| Rust forwarding build / zone / policy state | userspace-dp/src/afxdp/forwarding/mod.rs, forwarding_build/mod.rs | ~3200 | Policy-relevant | Reviewed |
| Rust frame inspect (ICMP/fragment) | userspace-dp/src/afxdp/frame/inspect.rs §455-590 | 445 of 1813 | policy_packet_icmp / term_match_extra | Reviewed |
| Go policy compile | pkg/config/compiler_security_policy.go | 443 | Full | Reviewed |
| Go zone compile | pkg/config/compiler_security_zones.go | 144 | Full | Reviewed |
| Go security top-level | pkg/config/compiler_security.go | 96 | Full | Reviewed |
| Go policy match validation | pkg/config/compiler_policy_match.go | 320 | Full | Reviewed |
| Go strict app validation | pkg/config/compiler_validate_strict_application.go | 691 | Full | Reviewed |
| Go strict policy validation | pkg/config/compiler_validate_strict_policy.go | 1009 | Full | Reviewed |
| Go strict zone validation | pkg/config/compiler_validate_strict_zones.go | 384 | Full | Reviewed |
| Go dataplane policy snapshot | pkg/dataplane/userspace/policies.go, policies_lower.go, policies_addrbook.go, policies_ids.go, policies_representable.go, policies_reject.go, policies_scheduler.go | ~1200 | Full (all 7 files) | Deep-reviewed |
| Go snapshot builder | pkg/dataplane/userspace/builder.go | 196 | Full | Reviewed |

## Module-by-module inspection log (including negatives)

### 1. policy.rs — core verdict engine (4224 LOC)

**Tier ordering (evaluate_policy_result_l3_aware):**
- Exact zone-pair → wildcard (from_any + to_any merged by config-order index) → both-any → global (with GlobalZoneScope::matches) → default. Correct Junos precedence. Unzoned (from_id==0 || to_id==0) falls through to default without consulting zone-pair/wildcard/global (#3110). Verified.

**Wildcard tier merge:**
- from_any_index keyed by to_id, to_any_index keyed by from_id. Two-pointer merge by rule index (config order). Indices unique across buckets (each rule in exactly one wildcard list), no dedup needed. Correct.

**Global-scope matrix:**
- `GlobalZoneScope::Any` matches any zone id, `Zone(id)` matches only that id. `build_global_zone_scope`: empty or "any" → Any, resolvable name → Zone(id), unresolvable → Err(UnresolvableZoneReference) fail-closed (#3402). Explicit "any" short-circuit prevents `resolve_policy_zone_id("any")` returning None → Unresolved → matches-nothing. Correct.

**configured_zone_pairs histogram expansion (for cold-path latency):**
- Tier 1: exact zone_pair_index pairs. Tier 2: from_any (any concrete -> to_id), to_any (from_id -> any concrete), both_any (concrete x concrete), global scoped by match context. Reserved sentinels excluded. Exact pairs win slot priority. Deterministic (BTreeSet). Correct.

**Address matching (try_match_rule):**
- Non-excluded: `match_any || literal.contains || any book.contains` per family. Excluded: `!(v4_empty && v6_empty) && !(literal.contains || book.contains)` — empty-both-families fail-closed (#2008), single-family-exclusion allows cross-family pass-through (#3023, intentional). NAT64 mixed (V6 src / V4 dst) checks source V6 + dest V4. (V4 src / V6 dst) → None (NAT46 unsupported). Correct.

**Legacy vs V3 address factory:**
- `source_is_v3_shaped = has book_ids OR has literals` (V3 = explicit name or literal list). V3 empty → MatchNone (fail-closed), legacy empty → MatchAny (no constraint). Intentional divergence by design. Sentinel and malformed checks run before book resolution. Correct.

**Default policy:**
- Empty wire string → Deny (fail-closed). Non-empty unknown token → Err(UnknownPolicyAction) fail-closed, not silent collapse to Deny. Per-rule empty action → Err (every configured rule must have concrete action). Go side initializes DefaultPolicy=PolicyDeny (not zero-value PolicyPermit, #3065 fixed). Rust PolicyState::default() default_action=Deny. Consistent.

**Duplicate rule/policy id preflight:**
- Duplicate stable rule_id → Err(DuplicateRuleId). Duplicate non-zero non-sentinel policy_id → Err(DuplicatePolicyId). Policy_id 0 excluded (omitempty + valid first-policy id), DEFAULT_POLICY_SENTINEL_ID excluded. Guards against mixed-version HA peer collision. Correct.

**Book integrity:**
- Id=0 rejected, duplicate ids rejected. V3 book prefix: empty/"any" → true (no-op), family-scoped wildcard accepted only for matching array, wrong-family literal rejected (M02). Malformed / wrong-family → Err(UnrepresentableAddressBookPrefix) fail-closed, not silent drop (was fail-open before #3711). Correct.

**Application matching (CompiledApplications::matches):**
- Empty apps → match_any=true → Some(None) (use-global timeout). Non-empty: group by protocol. ICMP type constraint steers to `icmp_constraints`, only matches when `packet_icmp.is_some()` and type/code match. Otherwise falls to port path. Exact dst-port O(1) accelerator, gated on `l4_present` (#3291). Range terms with empty src+dst = protocol-only → always matches (even with l4_present=false, correct — protocol is known). Port-bearing range → requires l4_present. ICMP constraints → fail-closed when packet_icmp=None. Best-match by config-order index (lowest order wins, #3346 Junos first-term-wins). Correct.

**ICMP type/code validation (parse_applications):**
- Non-ICMP protocol with icmp_type/icmp_code → invalid_icmp recorded (code-without-type or non-ICMP-proto-with-icmp). Empty protocol → dropped (dropped_any), whole snapshot rejected. Correct (#3712).

**Port parsing (parse_port_u16):**
- Rejects empty, non-ascii-digit (including '+'), then parses u16. Mirrors Go validatePortSpec (parseCanonicalPort). Correct (#3606).

**NEGATIVE — verified fail-closed:**
- Duplicate rule_id / policy_id: fail-closed (whole snapshot rejected).
- Malformed address literal (legacy + V3): fail-closed.
- Wrong-family address-book prefix: fail-closed.
- Unresolvable zone reference: fail-closed.
- Unknown action: fail-closed.
- Interface unknown zone: fail-closed.
- Tunnel TTL out-of-range, VLAN out-of-range, CoS queue/range, MTU negative, address unparseable, scheduler unknown class, filter protocol/flags/ICMP/DSCP/flex unrepresentable: all fail-closed.
- Flowless non-first fragment with port-bearing deny: fail-closed (deny lands as default-path? Actually: with l4_present=false, port-bearing app terms don't match, so deny rule with only port-bearing apps doesn't match → falls to default → if default=deny, drop; if default=permit, permit — documented limitation, fragment-assoc-cache deferred, NOT a new fail-open).

---

### 2. poll_descriptor/mod.rs — session-miss and flowless policy gates

**Flow-backed session-miss (transit):**
- Evaluates: input filter (pre-routing) → PBR route-table override → forwarding (route lookup) → zone policy (`evaluate_policy_result_with_icmp`) → filter-deny/reject. Policy uses `policy_packet_icmp` (frame-derived, fragment-safe, truncated-ICMP-safe via term_match_extra_from_frame). NAT destination applied before policy (policy_dst_port = post-DNAT port). Correct.

**Flowless transit (non-first fragment / no-L4, #3291/#4024):**
- Synthetic L3 flow (ports 0, `l4_present=false`). Evaluates: input filter (is-fragment aware), PBR override (checked before LocalDelivery, flowless drop path), zone policy (`evaluate_policy_result_l3_aware` with ports=0, l4_present=false, packet_icmp=None). Port-bearing app terms fail-closed, `application any` / address / protocol still match. Flowless MissingNeighbor arm now also enforces zone policy (#4024, was fail-open before). Flowless LocalDelivery arm → junos-host + host-inbound + lo0, all with l4_present=false. Correct.

**Flowless default-policy behavior:**
- Non-first fragment of a TCP/80 flow denied by `deny tcp/80` (port-bearing) falls through to default-policy. If default=deny-all → drop (correct fail-closed). If default=permit-all → permit remaining fragments (no session, but route-based forward). This is documented as fragment-assoc-cache deferred stage, not a new bypass. vSRX with `default-policy permit-all` also forwards unmatched fragments. NOT a fail-open.

**LocalDelivery (flow-backed):**
- Order: host_inbound_admits → lo0 filter → junos-host policy (flow, l4_present=true) → session install. Host-inbound denies before junos-host permit, so permit cannot re-admit. `junos_host_policy_eval` returns Permit result with metadata (#3706). Correct.

**LocalDelivery (flowless, #3292):**
- Order: host_inbound (dst_port=0, icmp_type=0, l4_present=false) → lo0 (extra with l4_present=false) → junos-host (l4_present=false, packet_icmp=None → icmp-constrained terms fail-closed). Deny/reject = silent drop (no L4 to RST). Permit = Deliver (no session install — synthetic tuple is eval-only). Correct. Verified no bypass.

**ICMP type extraction (policy_packet_icmp):**
- `matches!(protocol, ICMP|ICMPv6)` else None. `term_match_extra_from_frame` with l4_present gate. If l4_present=false (non-first fragment, truncated ICMP #2449) → type/code zeroed + l4_present=false → policy icmp-constrained terms fail-closed. Meta-only path (`term_match_extra_from_meta`, #3008): ICMP → l4_present=false (type/code unknown), non-ICMP → l4_present=true (tcp_flags authoritative). Truncated ICMP: frame.len() < l4_offset+2 → icmp_type_code_present=false → l4_truncated=true → l4_present=false. All correct, fail-closed verified (no spurious `icmp-type 0` match on truncated packet).

**NEGATIVE — verified fail-closed:**
- Flowless non-first fragment transit denied by `deny-all` → drop (#3291/#4024 fix).
- Flowless MissingNeighbor denied by `deny-all` → drop, no reinject (#4024 fix).
- Flowless LocalDelivery denied by host-inbound empty-zone default-deny → drop (#3291 fix).
- Truncated ICMP type/code not spuriously matching `icmp-type 0` / `icmp-code 0` (#2449, #3008 fix).
- Non-query ICMP error/control no longer installs fake sessions via metadata (#3290 fix, third-fold #3521).

---

### 3. host_inbound.rs — zone/interface host-inbound (815 LOC)

**Classification:**
- `classify_system_service`: ssh→22/tcp, ping→icmp echo-request only (8 v4 / 128 v6, NOT whole ICMP), dhcp→67+68/udp v4-only, dhcpv6→546+547/udp v6-only, ike/ipsec→500+4500/udp, traceroute→33434..33523/udp, gre→proto 47, ident-reset→nothing (drop, not admit). Unknown token → ignore (fail-closed). Correct. SSOT parity with Go KnownHostInboundSystemServices via TestHostInboundRustClassifierMatchesGoSSOT (#3486).

**Protocol classification:**
- ospf→89/v4-only, ospf3→89/v6-only, rip→520/v4-only, ripng→521/v6-only, igmp→2/v4-only, pim→103/both, vrrp→112/both, bfd→3784+3785+4784/udp, ldp→646/both, msdp→639/tcp, nhrp→54, rsvp→46, pgm→113, sap→9875/udp dual, dvmrp→2/v4-only, isis→none (L2), router-discovery→9+10/icmp v4 only (v6 RS/RA via global ND accept). `protocols all` → routing_protocol_all_expansion = KNOWN minus L2 (isis), NOT system-services. Correct. L2 exclusion tested.

**Global accepts (is_icmp_host_inbound_global_accept):**
- ICMPv4: 3 (dest-unreach, incl PMTUD code 4), 11 (time-exceeded), 12 (param-problem).
- ICMPv6: 1 (dest-unreach), 2 (pkt-too-big/PMTUD), 3 (time-exceeded), 4 (param-problem) + ND: 133-137 (RS/RA/NS/NA/Redirect).
- Echo-request (8/128) NOT global — gated on `ping` token. Router-advert (9/10) NOT global — gated on `router-discovery`. Source-Quench (4) / Redirect (5) NOT global (deprecated/link-scoped). Correct, matches nft chain.

**Admit check:**
- `is_icmp_host_inbound_global_accept` before zone lookup (PMTUD/ND work on ping-less zone). `None` (unknown/global zone id) → admit (only genuinely unknown zone, not configured empty zone). `Some(empty)` (configured zone, no tokens) → deny (default-deny #3405). Per-interface override (ifindex_host_inbound) keyed by ingress ifindex, effective set = zone ∪ interface (pre-unioned in Go). Global ICMP accept applied in BOTH branches. Correct.

**NEGATIVE — verified fail-closed:**
- Empty configured zone (no `host-inbound-traffic` stanza) → deny everything (#3405).
- Genuinely unknown zone (id not in table, e.g. 0) → admit (management lifeline preserved).
- Unknown token → ignore (fail-closed), not admit-all.
- `ident-reset` → does NOT admit tcp/113 (#3310).
- Truncated ICMP on flowless path: icmp_type=0 (absent), NOT triggering global accepts (3/11/12/2/133-137) — correct.

---

### 4. compiler_security_policy.go / compiler_security_zones.go / compiler_security.go

**Default-policy compilation:**
- Hierarchical `default-policy { deny-all; }` and flat `default-policy deny-all` both handled. `permit-all`→PolicyPermit, `deny-all`→PolicyDeny, `reject-all`→PolicyReject (#3065). Missing stanza → no overwrite of initializer (PolicyDeny from compiler.go). Correct.

**Default-policy-log:**
- Multi-value `default-policy-log [ session-init session-close ]` read via `firewallMatchValues` SSOT (both Keys[1:] and Children), not just first child (#3703, #2419 collapse fix). Unknown tokens rejected by SchemaValidate (not here). Correct.

**Policy-rematch:**
- `policy-rematch [extensive]` Accepted + recorded, warning emitted at commit (ValidateConfig, #4233). Not yet enforced (#4234), advisory only. Correct.

**Global vs zone-pair split:**
- `global { policy ... }` → GlobalPolicies. `from-zone trust to-zone untrust { policy ... }` → Policies (zone-pair). Flat-set vs hierarchical both handled. Correct.

**Duplicate match/then blocks:**
- `policyMatchChildren` / `policyThenChildren` flatten across ALL `match {}` / `then {}` siblings (Junos merge semantics, #3842). Conflicting terminal actions detected before de-dup (dedup by distinct action value, `permit,permit` = one, `permit,deny` = conflict). Correct.

**Address normalization:**
- `any-ipv4`→`0.0.0.0/0`, `any-ipv6`→`::/0` before passing to dataplane (#2008 H11). `any` left intact (dataplane already matches). Correct.

**Application match:**
- `application` multi-value read via `firewallMatchValues` SSOT (#4121). Correct.

**Terminal action default:**
- No terminal action (log-only / count-only) → PolicyDeny (not PolicyPermit zero value, #3043). Conflicting actions → last-wins runtime value but strict gate rejects at commit (#3043). Correct.

**Host-inbound-traffic merge (#4544):**
- `mergeHostInbound` unions SystemServices + Protocols across ALL `host-inbound-traffic` blocks under one zone/interface. Single block returns unchanged (no dedup, byte-identical). Multiple blocks dedup first-seen order. Correct. Fixed on HEAD (this PR's dep).

**NEGATIVE — verified fail-closed:**
- Empty policy (no terminal action) → Deny, not Permit (#3043).
- Duplicate identical `then permit; then permit;` → one permit, not conflict (#3850).
- Duplicate conflicting `then permit; then deny;` → strict reject, lenient = last-wins (#3043).

---

### 5. policies_lower.go / policies_addrbook.go / policies_ids.go / policies_representable.go / policies_reject.go / policies_scheduler.go / builder.go

**policies_lower.go — snapshot lowering:**
- `addrRepresentable`: `""`, `any`, `any4/6`, `any-ipv4/6` → true; literal CIDR/IP → true; feed-bound name → true (empty feed = MatchNone by design, NOT unrepresentable); known book name → structural check via `nameRepresentable`; unknown → false. Correct (#3261, #2049, #3294).
- `buildOneRuleSnapshot`: legacy `source_addresses` + V3 `source_book_ids`/`source_literals` both emitted. Unrepresentable side → sentinel `__unsupported_address__` on BOTH shapes. App terms unrepresentable → `__unsupported__` sentinel. Scheduler state → inactive→true (fail-closed until state arrives, nil map = inactive). Per-policy log selection carried. `MatchFromZone`/`MatchToZone` (global match context) carried. Offending-token detail captured for diagnostic. All correct.

**policies_addrbook.go — book dedup:**
- `buildAddressBookTableWithFeeds`: collects all names (static + feed overlay), expands each name via `expandBookNameRecursive` (feed-aware, cycle-detected with path-based visited unwound on exit), normalizes any→0.0.0.0/0+::/0, dedup/sort/cache, canonicalize, hash (FNV-64a), fold to u32 id, linear probe (bounded by N+8), fail AddressBookIDCollisionError not panic (#2514). Correct. `normalizeAnyInCIDRs` is a dead no-op (computes hasAny4/hasAny6, discards, returns input unchanged — F-124/F-145). Harmless (defeats dedup of `0.0.0.0/0` vs literal any, but doesn't change correctness — two books with same content but different any-representation get different bucket keys → two rows instead of one, but both enforce identically). NOT re-filed (known, low, not security).

**policies_ids.go — runtime id assignment:**
- `walkPolicyRuleSlots` is SSOT: policySetID increment per zone-pair set, ruleIndex advance by `userspacePolicyRuleExpansionCount` (app-set expansion). MaxRulesPerPolicy (256) cap — fail-closed on overflow (config rejected, prior state retained). Global policies occupy set len(Policies). `RuntimePolicyIDs` / `PolicyIDsByStableKey` / `PoliciesByStableKey` all derived from same walk. `RuntimePolicyIndex` fallback to raw ordinal when map miss. `userspacePolicyRuleExpansionCount`: empty/any/unresolvable → 1 (no expansion). Correct.

**policies_representable.go — nameRepresentability:**
- Two-bit return (representable, concrete) decoupled. Cycle revisit → (true, false) (representable, no concrete). Feed-bound name with live prefixes → (true, true) = concrete contribution (#3294 A′). Feed-bound empty → (true, false). Empty set → (false, false). Structurally invalid member → poisons parent (false, false). Top-level `nameRepresentable` = `r && c` (must contribute ≥1 concrete). Mutual-cycle-with-concrete config accepted (was over-rejected before). Direct feed name never reaches here (short-circuited by addrRepresentable). Correct. Parity with strict validator `policyMatchAddressBookResolves`.

**policies_reject.go — content rejection:**
- `collectPolicyContentRejections`: scans built rules for sentinels, names exact offending tokens per side (source/destination/application), scope-qualified rule identity. `PolicyContentRejectionReasons` = SSOT for simulator (#4394) — mirrors runtime fail-closed set (per-rule sentinels + app-catalog build). Correct.

**policies_scheduler.go:**
- `policyRuleInactive(schedulerName, activeState)`: empty name → false (always active), nil map → true (fail-closed, inactive until state arrives), name not in map → true (inactive). `PolicyInactiveFn` captures snapshot by value, always bound (#3414). Correct.

**builder.go — snapshot assembly:**
- Nil cfg → minimal snapshot (version/capabilities, no zones/policies). Non-nil: address-book collision → error (fail-closed, #2514). Policy unrepresentable → sentinel → error diagnostic. App catalog build failure → error (fail-closed, #3438). Route enumeration failure → error (#3772). DefaultPolicy via `policyActionString(cfg.Security.DefaultPolicy)` where cfg.Security.DefaultPolicy=PolicyDeny when unset (Go initializers). DefaultLog flags threaded. SourceNAT/StaticNAT/DestinationNAT via feed-aware builders (#3303). Zone collision quarantine (#3719). Content hash for dedup (excludes volatile fields). Correct.

---

### 6. compiler_validate_strict_policy.go / compiler_policy_match.go / compiler_validate_strict_zones.go / compiler_validate_strict_application.go

**validatePolicyMatchAddressesStrict (#2008):**
- Rejects policy address token that is not: `any`, `any-ipv4/ipv6`, literal CIDR/IP, defined address-book name, or dynamic-address feed binding. Delegates to `policyMatchAddressTokenRecognized` (shared with warn pass #3958, no divergence). `any-ipv4/ipv6` normalized to `0.0.0.0/0`/`::/0` by compilePolicy before this? No — this runs on Config after compilePolicy, which already normalized `any-ipv4/6` → `0.0.0.0/0`/`::/0`. So raw `any-ipv4` passing through here is harmless (also parseable as CIDR after normalization). Correct.

**validatePolicyMatchAddressSetMembersStrict (#3149/#3147):**
- For each defined book name in policy addresses, calls `policyMatchAddressBookResolves` (mirrors runtime `resolveUserspaceAddressBookEntry`). Empty address-set → reject (#3147 — empty excluded set inverts to match-all). Dangling member → reject. Pure self-cycle → reject (count==0). Mutual-cycle-with-concrete → accept (path-based visited). Correct. `any`/literals not checked (domain of #2008 gate).

**validatePolicyMatchApplicationsStrict (#3144/#3146):**
- Rejects undefined app (not predefined junos-*, not user app, not app-set). Rejects defined-but-empty app-set (expands to 0 members → `__unsupported__` → dataplane refuse-to-arm). Accepts `any`/empty. Correct.

**validatePolicyZoneReferencesStrict (#2401/#3148/#4230):**
- Zone-pair: `from-zone junos-host` rejected (host-originated never matches, #4230), undefined from/to → error. Global: `match from-zone junos-host` rejected (host-originated never matches, #3611 Piece A), `match to-zone junos-host` ALLOWED (host-inbound supported, #3639), undefined match context → error (fail-closed #3402). `any`/empty/junos-host exempt from undefined check via `policyZoneSpecialTokens`. Correct.

**validateDuplicatePolicyNamesStrict (#3473):**
- Zone-pair: name unique within (from, to) context (cross-stanza / cross-block via map accumulator). Global: name unique within whole global list (irrespective of match context). Sorted zone names for deterministic error. Correct.

**validatePolicyTerminalActionStrict (#3043/#3850):**
- Dedup by distinct action value: `permit,permit` → 1 action (ok), `permit,deny` → 2 distinct (conflict). 0 actions → error (actionless policy → silent permit was fail-open). 1 action → ok. Correct.

**validatePolicyLogActionStrict (#3060):**
- Bare `then log` (Log != nil but both SessionInit and SessionClose false) → error (would report logging enabled but emit nothing). Correct.

**validateAddressBookEntryNamesStrict (#3061/#4340):**
- Operator-typed address-book entry name must not begin with `zone-local/` prefix (would collide with synthetic zone-local names). Zone name must not contain `/` (keeps synthetic `zone-local/<zone>/<name>` split unambiguous). `/` in entry name otherwise allowed (prefix-in-name convention, e.g. `net_10.0.0.0/8`). Only checks NAMES, never values. Correct. Runs on pristine global book before zone-local fold.

**compiler_policy_match.go — unsupported match leaves (#3113/#3142/#3673):**
- Direct child unsupported leaf (`dynamic-application`, `url-category`, `source-identity`) → error (silently dropped would widen policy). Multi-value leaf collapsed tail (`match application any dynamic-application ...`) → re-checked token by token against `unsupportedPolicyMatchLeaves` + `swallowedStructuralMatchTokens`. Duplicate inner `match {}` blocks all inspected (via `policyMatchChildren`, #3842). Top-level `security {}` / `policies {}` duplicates via `forEachChild` at both levels (#3562). Zone-pair `from-zone`/`to-zone` as collapsed tail tokens rejected when app-named "from-zone" defined (#3673). Global-only `from-zone`/`to-zone` allowed in global scope (#3148). Correct.

**compiler_validate_strict_zones.go — zone gates:**
- `validateReservedZoneNamesStrict` (#3055): `junos-global`, `any`, `junos-host` as zone DEFINITION → error (would turn zone-scoped policies into device-wide global fallbacks). `validateZoneCountStrict` (#2391 superseded → #3075): >65533 zones → error (would overflow u16 space). `validateZoneInterfaceMembershipStrict` (#3072): same interface in two zones → error (silent first-writer-wins over sorted zones). `validateHostInboundTokensStrict` (#3200): unknown `system-services`/`protocols` token → error (nft vs Rust classifier split-brain). Per-interface override tokens also validated (#3362). Correct.

**compiler_validate_strict_application.go:**
- `validateApplicationSetMembersStrict` (#2217): dangling app-set member → error. Implicit term-sets skipped. Sorted for deterministic error. Correct.
- `validateApplicationSpecsStrict` (#2142/#3150/#3109/#3373/#3320/#3348): referenced-app-only scope (policy or NAT rule refs + app-id-enabled = all apps). Port range malformed → error. Protocol-less app → error (would unrepresentable → whole dataplane disable, #3261). Unknown protocol (not via filterProtocolResolvable) → error (blanket junos-* would commit but dataplane rejects). Non-port-bearing protocol with port → error (#3373). Invalid timeout / ICMP type/code / mixed ICMP+non-ICMP / code-without-type → errors. Sorted for deterministic error. Correct.
- `validateApplicationSyntaxStrict` (#3352/#4337/#3890): every user app (not just referenced): unknown `term` leaf → error, unknown `application-set` member keyword → error. `alg <unknown>` no longer hard-rejected (#4337 relaxed to accepted-but-inert advisory). Predefined junos-* apps never in this map, so their legitimate ALGs unaffected. Correct.
- `validateApplicationStructureStrict` (#3366): mixed direct+term → error (direct silently dropped), duplicate scalar term leaf with conflicting value → error (last-writer-wins). Idempotent same-value not flagged. `protocol` repeat = multi-proto intentional, not flagged. Correct.

---

### 7. Cross-cutting policy verdict properties (what vSRX does vs xpf)

**Default-policy:**
- When set explicitly: `deny-all`→Deny, `permit-all`→Permit, `reject-all`→Reject (RST/ICMP-unreach). When unset: Go zero value was originally Permit (fail-open, #3065) but NOW PolicyDeny (fixed). Rust default ""→Deny (fail-closed). Both consistent.

**Unzoned / unknown-zone (#3110):**
- from_id==0 || to_id==0 → skip zone-pair/wildcard/global → default-policy (not wildcard any). `from-zone any` / `to-zone any` are configured zone wildcards (id never 0), never match unzoned traffic. Correct. Documented: unzoned ≠ any.

**Address-negation (excluded):**
- Non-excluded: empty (no constraint) → MatchAny (legacy: `from_prefixes(empty)` = MatchAny). No addr match → deny rule narrows to nothing (fail-closed would be to not install, but that's the correct behavior — rule simply never matches).
- Excluded (source-address-excluded): empty-both-families → fail-closed (rule never matches, not match-all). Single-family populated → cross-family packet (V6 when exclusion is V4-only) matches (intentional #3023 — V6 addr is trivially not in V4 exclusion set). Verified no fail-open.

**Application match:**
- Port 0 rejected (0 is not a valid port, not "any-port"). Application "any" / empty → match-any on protocol + port. No-match → fall to next rule or default. Application-set member drop under-populating deny → whole rule rejected via sentinel (fail-closed, #2124). Predefined junos-* table expanded. Malformed set → empty expansion → sentinel → whole snapshot rejected (#3261). App-term ordering via compiled precedence (first-term-wins #3346 = Junos first-match).

**Snapshot integrity:**
- Unrepresentable address (undefined book, non-literal dns-name/wildcard/range, empty/dangling/cycle set) → sentinel → whole snapshot rejected (fail-closed, #3261). Unrepresentable application → sentinel (#2124). Unknown action → fail-closed (#3365). Duplicate rule/policy id → fail-closed (#3713). Unknown zone → fail-closed (#3402). Malformed address literal → fail-closed (#3367/#3711). Invalid ICMP field combo → fail-closed (#3712). NPTv6/NAT64/filter/v6 issues out of scope for this cohort. Policy snapshot integrity = fail-closed, not silently degraded.

---

## Findings

After exhaustive trace of every module listed above against 274 prior findings, 300 GH issues, _Log.md, and 15 prior deep reviews, NO new High-confidence policy fail-open was found on HEAD 33b891d11. Two Low findings survive.

---

### [L-01] normalizeAnyInCIDRs dead no-op — dedup defeats content equality

- Title: normalizeAnyInCIDRs computes hasAny4/hasAny6 but discards them, returning input unchanged
- Severity: Low
- Confidence: High
- Class: implementation-bug / parity-gap
- Evidence:
  ```go
  // pkg/dataplane/userspace/policies_addrbook.go:399-419
  func normalizeAnyInCIDRs(v4, v6 []string) ([]string, []string) {
      hasAny4 := false
      hasAny6 := false
      cleanV4 := v4[:0]          // slice-reuse, not copy — mutates input backing array
      for _, s := range v4 {
          if s == "0.0.0.0/0" {
              hasAny4 = true
          }
          cleanV4 = append(cleanV4, s)  // appends every element, no filtering
      }
      cleanV6 := v6[:0]
      for _, s := range v6 {
          if s == "::/0" {
              hasAny6 = true
          }
          cleanV6 = append(cleanV6, s)
      }
      _ = hasAny4    // dead — discarded
      _ = hasAny6    // dead — discarded
      return cleanV4, cleanV6  // returns original (aliased) slices unchanged
  }
  ```
- Trace:
  - Input: address-book `TRUST-NET-1` has `0.0.0.0/0` (wildcard), `TRUST-NET-2` has `any` expanded as `0.0.0.0/0` + `::/0` (both families). Both should dedup to same bucket.
  - `normalizeAnyInCIDRs` is called at policies_addrbook.go:202 after `expandBookNameToCIDRs`. Intended: if `0.0.0.0/0` present, collapse family to single entry (or strip redundant prefixes covered by /0). Actual: computes hasAny4/hasAny6 but discards them, returns input unchanged (also aliased via `v4[:0]` reuse — mutates original backing array if caller held reference).
  - Result: two books with identical semantic content but different syntactic any-representation (e.g., explicit `0.0.0.0/0` vs `any` expanded) get different canonical bytes (one has extra `::/0` in v6, other doesn't, despite normalization being supposed to unify them). They get different u32 IDs, two rows instead of one.
  - Security impact: NONE — both rows enforce identically (both match all). No fail-open, no extra permits. The only effect is wasted deduplication (two rows vs one) and slightly larger snapshot. The `_ = hasAny4/discard` also defeats the stated intent to strip redundant specific prefixes when `/0` present.
  - Refutation attempted: Searched for any code path where two different canonical bytes from same semantic content causes a deny rule to miss — no, because both rows contain `0.0.0.0/0` and match all, so deny still denies. No bypass.
  - Why it matters: Dead code, dedup intent defeated, snapshot bloat, aliasing via `v4[:0]` could theoretically corrupt caller's slice if it held `v4` longer (but `v4` is a local in buildAddressBookTableWithFeeds, not shared). Low only.
  - Fix direction: Either remove `normalizeAnyInCIDRs` call site (make dead code obvious and delete function), or implement intended normalization: when `hasAny4`, return `["0.0.0.0/0"], v6` (strip specific v4 prefixes covered by /0); when `hasAny6`, return `v4, ["::/0"]`. Copy-on-build, not aliasing via `v4[:0]`.
  - Labels: `implementation-bug`, `dead-code`, `low`, `policy`, `address-book`
  - Dedup note: F-124 and F-145 in /tmp/all_findings.txt both note this exact dead no-op (`normalizeAnyInCIDRs is a dead no-op`). Mentioned in /tmp/ps-review-019.md §5.2.4, /tmp/ps-review-022.md, /tmp/ps-review-024.md, /tmp/ps-review-025.md but never filed as a GH issue. NOT re-filed as High/Med because prior reviews correctly classified as Low/dead-code/harmless. This entry re-states with full code evidence but at Low severity, consistent with prior triage.

---

### [L-02] Snapshot build uses Go map iteration under `policyActionString` — deterministic today, but `SecurityConfig.DefaultPolicy` change would be invisible until test fails

- Title: builder.go DefaultPolicy string conversion could drift from Rust parser if action names change
- Severity: Low
- Confidence: Medium
- Class: robustness-dos / parity-gap
- Evidence:
  ```go
  // pkg/dataplane/userspace/builder.go:93
  DefaultPolicy:   policyActionString(cfg.Security.DefaultPolicy),
  
  // pkg/dataplane/userspace/policies_lower.go:221-230
  func policyActionString(action config.PolicyAction) string {
      switch action {
      case config.PolicyPermit: return "permit"
      case config.PolicyReject: return "reject"
      default:                 return "deny"  // includes PolicyDeny AND any future/forged value
      }
  }
  
  // userspace-dp/src/policy.rs:2526-2537
  let default_action = if default_policy.is_empty() {
      PolicyAction::Deny
  } else {
      parse_action(default_policy).ok_or_else(|| UnknownPolicyAction { ... })?
  };
  // parse_action: "permit"|"reject"|"deny" only, None for anything else.
  ```
- Trace:
  - `policyActionString` default arm returns `"deny"` for ANY non-Permit non-Reject value, including a future `PolicyAction(99)` (e.g., a hypothetical `PolicyDrop` or a corrupt value). This string then reaches Rust `parse_action("deny")` → `Some(Deny)`. So the Go default arm silently maps unknown actions to deny (fail-closed, correct today).
  - But if a future action `PolicyAction(99)` named `"drop"` is added to Go without updating this function, it silently becomes `"deny"` in the snapshot (wrong semantics: `drop` vs `deny` — `deny` is silent drop, `drop` might be... same? In Junos `deny` is silent drop, `reject` is RST/ICMP-unreach). If a new action `PolicyAction(99)` = `PolicyRejectICMP` is added, mapping it to `"deny"` loses the reject behavior (fail-open for a `reject-icmp` intended rule — packet dropped silently instead of RST sent, but traffic still blocked, so fail-closed, not fail-open).
  - The Rust `parse_action` hard-rejects unknown `default_policy` strings (UnknownPolicyAction), but the Go `policyActionString` never produces an unknown string (it always emits one of three known tokens), so the Rust reject arm is unreachable for `default_policy` from a clean Go build. Only a corrupt/hand-built snapshot could trigger it.
  - This is NOT a current fail-open. It's a robustness/dead-code observation that the two sides' action enums are coupled by string convention with no compile-time check.
  - Refutation attempted: Searched for any current code path where `policyActionString` could produce an unknown string that Rust would reject → none (all PolicyAction values map to "permit"/"reject"/"deny"). Searched for map-iteration non-determinism in DefaultPolicy path → none (it's a single field, not a map iteration).
  - Why it matters: Low — future action addition could silently mis-map, but today's behavior is correct and fail-closed.
  - Fix direction: Make `policyActionString` exhaustive (explicit `case PolicyDeny: return "deny"` + `default: return "deny"` stays as catch-all, or `default: panic` during snapshot build so a new action forces an explicit case). On Rust side, ensure `parse_action` stays in lock-step with Go `policyActionString` output set — cross-language contract test (default_policy_3065_test.go already pins empty→"deny" and explicit overrides, but doesn't pin the default arm mapping for invalid input).
  - Labels: `robustness`, `low`, `policy`, `cross-language-contract`
  - Dedup note: Not in all_findings F-001..F-274 (searched for "policyActionString", "default_policy", "UnknownPolicyAction" — F-274 mentions DefaultPolicy only in context of #3065 which is CLOSED). Not in GH issues (searched for policyActionString, default_policy drift — none). Not in ps-review-018..035 (none mention this specific Go-`default`-arm-to-Rust-hard-reject coupling). NEW Low finding.

---

## Negative results (paths verified fail-closed with reason)

| Path | Verdict | Why fail-closed | Evidence |
|------|---------|-----------------|----------|
| Unzoned transit + permit-global (#3110) | Default-policy (Deny) | `evaluate_policy_result_l3_aware` guards `if from_id != 0 && to_id != 0` before zone-pair/wildcard/global; unzoned (0) falls to default (Deny when unset per #3065) | policy.rs:3406-3418 |
| Wildcard `from-zone any` matching unzoned | No match | Same guard — unzoned never enters wildcard path | policy.rs:3406-3418, 3090 indices |
| Empty configured host-inbound-traffic zone (#3405) | Default-deny (no SSH/HTTP) | Every configured zone inserted into `zone_host_inbound` with empty `ZoneHostInbound` → `admits()` returns false for every service/protocol; `None` (unknown zone) only for genuinely unknown id | host_inbound.rs:49-58 + policy.rs:3405-3411 |
| Flowless non-first fragment transit via `deny-all` (#3291/#4024) | Deny (drop, no reinject) | `l3_session_flow_from_meta` → `evaluate_policy_result_l3_aware` with `l4_present=false` → address/protocol/`any` terms match, deny → `PolicyDenied` → recycle + continue. MissingNeighbor flowless also enforces policy (#4024) | poll_descriptor/mod.rs:3433-3646, 4469-4576 |
| Flowless LocalDelivery via `deny-all` / empty host-inbound (#3292) | Deny (silent drop) | `flowless_local_delivery_verdict`: host-inbound (dst_port=0, icmp_type=0, l4_present=false) → empty zone denies; lo0 filter → discard; junos-host deny → silent drop | poll_descriptor/mod.rs:309-424 |
| Non-first fragment ICMP policy (junos-ping type 8) | No spurious match | `policy_packet_icmp` returns None for non-first fragment (l4_present=false) → icmp_constraints fail-closed. flowless transit uses `policy_icmp=None` | poll_descriptor/mod.rs:59-69, policy.rs:1827-1898 |
| Truncated ICMP (frame len < l4_offset+2) matching `icmp-type 0` (#2449) | Fail-closed | `term_match_extra_from_frame`: `icmp_type_code_present=false` → `l4_truncated=true` → `l4_present=false` → icmp-type/code terms don't match | frame/inspect.rs:472-510 |
| Meta-only ICMP type/code matching `icmp-type 0` (#3008) | Fail-closed | `term_match_extra_from_meta`: ICMP/ICMPv6 → `l4_present=false`, non-ICMP → true; icmp-type/code terms gated on l4_present | frame/inspect.rs:616-645 |
| Non-query ICMP error/control installing fake sessions (#3290) | Flowless (no session) | `parse_session_flow_from_bytes` gated by `icmp_identifier_bearing` + `meta_icmp_identifier_bearing`; non-query types → None → flowless | Referenced in review (code not re-read this pass but verified in prior audits) |
| Address-excluded with empty set inverting to match-all (#2008) | Fail-closed | `!(source_v4_empty && source_v6_empty)` — both families empty → false → side never matches (not match-all) | policy.rs:3828-3942 |
| Legacy malformed address literal widening deny to MatchAny (#3367) | Fail-closed | `parse_legacy_address_set` returns `malformed=Some(token)` → caller `UnrepresentableLegacyAddress` → whole snapshot rejected | policy.rs:3043-3135, 2736-2777 |
| V3 malformed address literal dropping to MatchNone (#3711) | Fail-closed | `parse_v3_literal_set` returns `malformed=Some(token)` → caller `UnrepresentableV3Address` → whole snapshot rejected | policy.rs:3137-3193, 2736-2777 |
| Wrong-family address-book prefix (M02) | Fail-closed | `parse_book_prefix_into` returns false for wrong-family token → `UnrepresentableAddressBookPrefix` → whole snapshot rejected | policy.rs:3194-3278 |
| Duplicate policy name within zone-pair (#3473) | Hard-reject at commit | `validateDuplicatePolicyNamesStrict` rejects, lenient = warning only | compiler_validate_strict_policy.go:615-702 |
| Undefined zone in zone-pair (#2401) | Hard-reject at commit | `validatePolicyZoneReferencesStrict` rejects, lenient = warning | compiler_validate_strict_policy.go:490-613 |
| Scoped global `match from-zone` undefined (#3402) | Fail-closed (whole snapshot rejected) | `build_global_zone_scope` → Err(UnresolvableZoneReference) | policy.rs:1158-1173 |
| `from-zone junos-host to-zone <z>` zone-pair (#4230) | Hard-reject at commit | `validatePolicyZoneReferencesStrict`: `zpp.FromZone=="junos-host"` → error | compiler_validate_strict_policy.go:531-553 |
| `global match from-zone junos-host` (#3611 Piece A) | Hard-reject at commit | `pol.Match.FromZone=="junos-host"` → error | compiler_validate_strict_policy.go:596-600 |
| `global match to-zone junos-host` (#3639) | ALLOWED + enforced | Not rejected; consulted in `evaluate_junos_host_policy_l3_aware` global tier | policy.rs:3755-3777 |
| Empty terminal action (log-only) (#3043) | Deny (runtime), hard-reject (commit) | `compilePolicy` defaults Action=PolicyDeny when `len(terminalActions)==0`; `validatePolicyTerminalActionStrict` rejects 0-action | compiler_security_policy.go:328-341, compiler_validate_strict_policy.go:728-821 |
| Bare `then log` (#3060) | Hard-reject | `validatePolicyLogActionStrict`: Log!=nil but both flags false → error | compiler_validate_strict_policy.go:823-886 |
| Unsupported match leaf (`dynamic-application` etc.) (#3113) | Hard-reject | `validatePolicyMatchLeavesStrict` rejects, including collapsed-tail escape | compiler_policy_match.go:162-320 |
| Swallowed structural token (`from-zone`/`to-zone` as app value, #3673) | Hard-reject | `validatePolicyMatchLeavesStrict` checks `swallowedStructuralMatchTokens` in collapsed tail | compiler_policy_match.go:123-260 |
| Duplicate inner `match {}` / `then {}` blocks (#3842) | Merged (Junos semantics) | `policyMatchChildren` / `policyThenChildren` flatten all siblings; conflicting actions rejected | compiler_security_policy.go:152-203, 259-270 |
| Undefined application (#3144) | Hard-reject | `validatePolicyMatchApplicationsStrict` | compiler_validate_strict_policy.go:129-229 |
| Defined-but-empty app-set (#3146) | Hard-reject | `validatePolicyMatchApplicationsStrict`: Expand len==0 → error | compiler_validate_strict_policy.go:182-198 |
| Address-set with empty/dangling/cycle member (#3149/#3147) | Hard-reject | `validatePolicyMatchAddressSetMembersStrict` → `policyMatchAddressBookResolves` | compiler_validate_strict_policy.go:268-489 |
| Unrepresentable address (undefined / non-literal) (#3261) | Whole snapshot rejected | `allAddressTokensRepresentable` false → sentinel → Rust `UnrepresentableAddress` | policies_lower.go:55-145, policy.rs:904-921 |
| Unrepresentable app protocol/port (#2124) | Whole snapshot rejected | `expandUserspacePolicyApplications` false → sentinel → Rust `UnrepresentableApplicationProtocol` | policies_lower.go:141-158, policy.rs:4062-4123 |
| Invalid ICMP field combo (code-without-type, non-ICMP-proto-with-icmp, #3712) | Whole snapshot rejected | `parse_applications` records `invalid_icmp` → `InvalidApplicationIcmpFields` | policy.rs:4079-4096 |
| Protocol 0 `+80` / non-canonical port (#3606) | Rejected | `parse_port_u16`: non-ascii-digit → None → `parse_port_spec` None → dropped → whole snapshot rejected | policy.rs:4208-4213 |
| Duplicate rule_id / policy_id (#3713) | Whole snapshot rejected | Pre-flight before counter allocation | policy.rs:2538-2593 |
| Zone interface double-assign (#3072) | Hard-reject | `validateZoneInterfaceMembershipStrict` | compiler_validate_strict_zones.go:223-295 |
| Unknown host-inbound token (#3200) | Hard-reject | `validateHostInboundTokensStrict` | compiler_validate_strict_zones.go:297-384 |

## Suggested issue split (fail-opens first — none on this pass)

No new High/Med fail-open on this cohort. Two Low findings (L-01 normalizeAny dead no-op, L-02 policyActionString default-arm coupling) suitable for a single Low hardening issue or two separate Low issues.

## Output file

`/tmp/ps-review-036-cohort1.md` — this file.
