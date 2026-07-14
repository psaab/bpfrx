Base commit: d4506d4450e23f9a3fc572206b3c82f6b6c99029
Area: A3_go_config_cli_tree — batch 2/3 (150 files)
Repo: /home/ps/git/avacado-xpf

# Batch File List

```
pkg/config/compiler_prewalk.go
pkg/config/compiler_protocols.go
pkg/config/compiler_qualified_nexthop_3871_test.go
pkg/config/compiler_retired_dataplane_knobs_test.go
pkg/config/compiler_ribgroup_ref_2226_test.go
pkg/config/compiler_rip_multivalue_3904_test.go
pkg/config/compiler_route_filter_range_2525_test.go
pkg/config/compiler_routing.go
pkg/config/compiler_routing_instance_interface_3904_test.go
pkg/config/compiler_routing_rules_test.go
pkg/config/compiler_rpm_http_scheme_2495_test.go
pkg/config/compiler_rpm_linklocal_zone_2494_test.go
pkg/config/compiler_rpm_routing_instance_2496_test.go
pkg/config/compiler_rpm_scoped_hostname_2493_test.go
pkg/config/compiler_rpm_source_2492_test.go
pkg/config/compiler_sampling_source_address_test.go
pkg/config/compiler_schedulers_3849_test.go
pkg/config/compiler_security.go
pkg/config/compiler_security_addressbook.go
pkg/config/compiler_security_alg.go
pkg/config/compiler_security_bracket_list_3703_test.go
pkg/config/compiler_security_flow.go
pkg/config/compiler_security_log.go
pkg/config/compiler_security_policy.go
pkg/config/compiler_security_screen.go
pkg/config/compiler_security_zones.go
pkg/config/compiler_services.go
pkg/config/compiler_signed_port_3606_test.go
pkg/config/compiler_snmp_trapgroup_2990_test.go
pkg/config/compiler_ssh_hardening_4305_test.go
pkg/config/compiler_static_nexthop_list_3872_test.go
pkg/config/compiler_static_route_inline_iface_3881_test.go
pkg/config/compiler_surface_a_ddns_test.go
pkg/config/compiler_syslog_hostmods_4303_test.go
pkg/config/compiler_system.go
pkg/config/compiler_tailgates.go
pkg/config/compiler_tcp_mss_range_test.go
pkg/config/compiler_tcp_session_seqcheck_test.go
pkg/config/compiler_test.go
pkg/config/compiler_three_color_default_4535_test.go
pkg/config/compiler_undefined_ref_2217_test.go
pkg/config/compiler_uniformgates.go
pkg/config/compiler_validate_scheduler_no_window_3860_test.go
pkg/config/compiler_validate_strict.go
pkg/config/compiler_validate_strict_application.go
pkg/config/compiler_validate_strict_chassis.go
pkg/config/compiler_validate_strict_cos.go
pkg/config/compiler_validate_strict_filter.go
pkg/config/compiler_validate_strict_ipsec.go
pkg/config/compiler_validate_strict_nat.go
pkg/config/compiler_validate_strict_observability.go
pkg/config/compiler_validate_strict_policy.go
pkg/config/compiler_validate_strict_routing.go
pkg/config/compiler_validate_strict_screen.go
pkg/config/compiler_validate_strict_zones.go
pkg/config/compiler_validate_vrf_overlap.go
pkg/config/compiler_validate_vrf_overlap_2387_test.go
pkg/config/compiler_validate_warn.go
pkg/config/compiler_validate_warn_nil_3494_test.go
pkg/config/compiler_validate_wireguard.go
pkg/config/completion_prefix_test.go
pkg/config/ddns_provider_string_test.go
pkg/config/deactivate_multi_leaf_3975_test.go
pkg/config/delete_multi_leaf_member_3846_test.go
pkg/config/delete_static_nexthop_3872_test.go
pkg/config/deterministic_nat_advisory_4559_test.go
pkg/config/deterministic_nat_flatset_3864_test.go
pkg/config/dhcp_expired_leases_test.go
pkg/config/dhcp_static_binding_test.go
pkg/config/dual_ast_differential_test.go
pkg/config/dup_host_local_address.go
pkg/config/dup_host_local_address_3718_test.go
pkg/config/event_options_4423_test.go
pkg/config/event_options_match.go
pkg/config/event_options_within.go
pkg/config/event_options_within_3751_test.go
pkg/config/fable167_advisory_test.go
pkg/config/fbf_fixture_test.go
pkg/config/filter_match_resolve.go
pkg/config/filter_protocol_rust_mirror_3393_test.go
pkg/config/firewall_address_except_matchany_4338_test.go
pkg/config/firewall_address_except_mutex_3359_test.go
pkg/config/firewall_address_literal_3433_test.go
pkg/config/firewall_crossfield_3723_test.go
pkg/config/firewall_dscp_drift_3309_test.go
pkg/config/firewall_dscp_range_3309_test.go
pkg/config/firewall_filter_expand.go
pkg/config/firewall_from_unenforced_3307_test.go
pkg/config/firewall_multivalue_2545_test.go
pkg/config/firewall_port_except_2622_test.go
pkg/config/firewall_port_except_mutex_3297_test.go
pkg/config/firewall_ri_conflict_3308_test.go
pkg/config/firewall_ri_output_direction_3432_test.go
pkg/config/firewall_symbolic_match_3205_test.go
pkg/config/firewall_terminal_conflict_4375_test.go
pkg/config/flow_aging_3440_test.go
pkg/config/flow_traceoptions_file_3420_test.go
pkg/config/flow_traceoptions_filter_3422_test.go
pkg/config/flow_traceoptions_size_3424_test.go
pkg/config/flowserver_template_ref_test.go
pkg/config/freetext.go
pkg/config/global_policy_zone_scope_3680_test.go
pkg/config/host_inbound_dup_block_4544_test.go
pkg/config/host_inbound_effective_3720_test.go
pkg/config/host_inbound_match_3627_test.go
pkg/config/host_inbound_per_iface_3362_test.go
pkg/config/host_inbound_rust_parity_test.go
pkg/config/host_inbound_tokens.go
pkg/config/host_inbound_tokens_test.go
pkg/config/host_inbound_view.go
pkg/config/host_inbound_view_3654_test.go
pkg/config/host_inbound_view_lifeline_3682_test.go
pkg/config/ike_policy_chain_ref_test.go
pkg/config/inactive.go
pkg/config/inactive_test.go
pkg/config/inline_inactive_4335_test.go
pkg/config/interface_parity_4308_test.go
pkg/config/ipsec_dhgroup_test.go
pkg/config/ipsec_proposal_ref_test.go
pkg/config/lexer.go
pkg/config/lifeline.go
pkg/config/log_profile_schema_test.go
pkg/config/log_profile_test.go
pkg/config/log_stream_config_3349_test.go
pkg/config/log_stream_tls_profile_3350_test.go
pkg/config/login_custom_class_4304_test.go
pkg/config/login_password_test.go
pkg/config/named_port_caseinsensitive_3372_test.go
pkg/config/natpool.go
pkg/config/parser.go
pkg/config/parser_ast_test.go
pkg/config/parser_bracket_list_2419_test.go
pkg/config/parser_class_of_service_test.go
pkg/config/parser_cluster_test.go
pkg/config/parser_fbf_test.go
pkg/config/parser_ipmonitoring_test.go
pkg/config/parser_recursion_dos_hb164_test.go
pkg/config/parser_routing_test.go
pkg/config/parser_rpm_pin_test.go
pkg/config/parser_security_test.go
pkg/config/parser_services_test.go
pkg/config/parser_system_test.go
pkg/config/policy_community_ref_test.go
pkg/config/policy_from_multileaf_2689_test.go
pkg/config/policy_log_action_3060_test.go
pkg/config/policy_match_excluded_test.go
```

# Module-by-Module Log

## compiler_prewalk.go
**Result: CLEAN (negative)**. Runs 22 AST pre-walk gates in fixed order. Each gate's strict/lenient split preserves #1960 doctrine. Warning concatenation order matches original compileExpanded. No Atoi->uint truncation (all gates use typed config). No Keys OOB. Invariant: `expandInterfaceRanges` mutation happens before unsupported-stanza gate — both see expanded members, correct.

## compiler_protocols.go
**Result: FINDING (F-01 Low)**. BGP ASN and OSPF/BGP timer parsing uses `strconv.Atoi` then casts to `uint32` without negative check. Remainder (OSPF areas, BGP groups, ISIS, RA, RIP, BGP multipath/damping, export multi-value via firewallMatchValues) is correct. Dual-shape handling via `namedInstances` is sound.

## compiler_routing.go
**Result: CLEAN** (with note on BGP AS inheritance). Static route ECMP (`next-hop [ a b ]`) correctly accumulates all gateways. `qualified-next-hop` preference/metric/interface modifiers correctly parsed in both inline and hierarchical shapes. `compileRoutingInstances` stable table-ID via `StableRoutingInstanceTableID` avoids renumbering outage. `resolveBGPAutonomousSystem` correctly inherits global AS when `local-as` unset. No new truncation beyond F-01 (shared with protocols.go).

## compiler_security.go
**Result: CLEAN (negative)**. Thin dispatcher — delegates to compileZones, compilePolicies, compileScreen, compileNAT, compileAddressBook, compileLog, compileFlow, compileIKE, compileIPsec, compileDynamicAddress, compileALG. No logic to audit.

## compiler_security_addressbook.go
**Result: CLEAN (negative)**. `zoneLocalQualify`/`ZoneLocalUnqualify` correctly handle `/` in address names (#4340). `mergeAddressNode` correctly distinguishes description vs prefix via `looksLikeIPOrCIDR`. TrailingTokens recorded for strict gate. `resolveZoneLocalAddressBooks` correctly folds zone-local books with no-clobber and rewrites policy tokens.

## compiler_security_alg.go
**Result: CLEAN (negative)**. Wires dns/ftp/sip/tftp disable flags. Records UnsupportedProtos for advisory. No truncation, no OOB.

## compiler_security_flow.go
**Result: CLEAN (negative)**. `flowTraceFileNameError` correctly rejects `.`, `..`, `/`, `\`, absolute paths. `flowTraceSizeFilesValues` handles all three AST shapes. `validateTCPMSSRanges` validates only compiler-selected token via `selectMSSToken`. `compileFlow` aging/tcp-session/udp-session/icmp-session use Atoi->int, no narrowing. No truncation to u16/u32 in this file (MSS fields are int, checked separately). Checked: mss uses int, not uint16 directly here.

## compiler_security_log.go
**Result: CLEAN (negative)**. Dual-location port validation mirrors compileLog traversal. TLS-profile gate correctly rejects any present profile. Port range 1..65535 via Atoi with bounds — safe (int field, no uint16 cast).

## compiler_security_policy.go
**Result: FINDING (F-03 Low)**. Main logic clean: dual-shape zone-pair/global, duplicate inner match/then accumulation (#3842), normalize any-ipv4/any-ipv6, firewallMatchValues SSOT for multi-value leaves (#4121), collapsed deny modifiers, terminal-action fail-closed default (deny when no action). Minor: global policy match from-zone/to-zone single-value read.

## compiler_security_screen.go
**Result: CLEAN (negative)**. `parseThresh` records BadNumeric for deferred gate, applies Junos defaults when 0. `recordKeyExtras`/`recordChildExtras` correctly flag trailing garbage from both Keys-overflow and child-node shapes (#3332). Default thresholds applied for icmp/udp flood, ip-sweep, port-scan when enabled without explicit value (#3230). math.MaxUint32 bound check prevents wrap — correct.

## compiler_security_zones.go
**Result: CLEAN (negative)**. `parseHostInboundNode` uses firewallMatchValues for multi-value. `mergeHostInbound` unions duplicate blocks with dedup only on merge path. Per-interface override iterates FindChildren (not FindChild). No truncation.

## compiler_services.go
**Result: CLEAN (negative)**. DHCP/DDNS compilation, RPM probe parsing, flow-monitoring, forwarding-options all handle dual shapes. DDNS compileDDNSProvider skips empty blocks. No integer narrowing beyond standard Atoi->int for intervals.

## compiler_system.go
**Result: CLEAN (negative)**. System hostname/domain/search/name-server, login classes, SNMP communities, syslog hosts/files, archival, chassis/DHCP server, SSH ciphers/macs via firewallMatchValues (bracket-list safe). UserspaceDataplane workers/ring-entries via Atoi->int, no narrowing.

## compiler_tailgates.go / compiler_uniformgates.go / compiler_prewalk.go orchestration
**Result: CLEAN (negative)**. Pure dispatch — call validators in fixed order. No logic.

## natpool.go
**Result: CLEAN (negative)**. SourceNATPoolNets resolves pool to nets, handles both pool.Address and pool.Addresses. parsePoolAddr handles CIDR and bare IP -> /32 or /128. No truncation.

## host_inbound_tokens.go
**Result: CLEAN (negative)**. SSOT for host-inbound token sets. KnownHostInboundSystemServices/Protocols canonical. ServiceMatch/ProtocolMatch correctly family-gate. PortRange{Lo,Hi uint16} constructed from uint16 literals 22,23,53 etc — safe (compile-time constants within range). AllExpansionProtocols excludes all and L2 — correct. HostInboundL2Protocols (isis) correctly no-ops on IP path.

## host_inbound_view.go
**Result: CLEAN (negative)**. InterfaceHostInboundEffective unions physical+unit overrides (#3720). HostInboundView/Render shows zone-level posture even with per-interface overrides (#3671). Lifeline exemption surfaced.

## filter_match_resolve.go
**Result: CLEAN (negative)**. resolveSinglePort uses parseCanonicalPort (strict unsigned) not Atoi — rejects non-canonical signed tokens (#3606). resolveFilterPort handles hyphenated service names before range split. ResolveFilterPortRange checks range before uint16 cast — safe. resolveFilterPortTokens records UnknownPorts for deferred gate.

## firewall_filter_expand.go
**Result: FINDING (F-02 Low)**. FilterTermExpansionCount computes cross-product in int then casts to uint32 — truncation possible when product > 4B.

## dup_host_local_address.go
**Result: CLEAN (negative)**. Commit-time gate for duplicate host-local addresses with differing host-inbound sets. Correctly implements Option B, excludes lifelines, handles IPv4+IPv6+VRRP VIPs, deterministic sorted iteration. Builds zone/interface maps locally mirroring dataplane logic — no truncation.

## event_options_match.go / event_options_within.go
**Result: CLEAN (negative)**. RE2 regex compilation, known field validation, within/trigger numeric validation with bounds [1,86400]/[1,1000000]. No truncation.

## freetext.go
**Result: CLEAN (negative)**. Control-char and comment-delimiter sanitization handles strict reject and lenient scrub. sanitizeCommentDelim handles chained delimiters.

## inactive.go / lexer.go / lifeline.go / parser.go
**Result: CLEAN (negative)**. Inactive marker lifting preserves identity, handles inline inactive (#4335). Lexer bracket-list stripping iterative (not recursive) avoids stack overflow. Lifeline matching base-name extraction correct. Parser maxParseDepth 256 prevents DoS, skipToBlockClose iterative — safe.

## compiler_validate_strict.go / compiler_validate_strict_*.go (8 files)
**Result: CLEAN (negative)**. All strict gates validated: they are either int-range checks (no narrowing) or string/enum checks. No Atoi->uint truncation in these files (they read typed config, not raw tokens). Zone count, reserved names, duplicate detection, trail tokens, flow aging, VRF overlap warnings — all correct.

## compiler_validate_warn.go / compiler_validate_wireguard.go / compiler_validate_vrf_overlap.go
**Result: CLEAN (negative)**. Warn-only gates, no narrowing. WireGuard key validation uses hex length check, not integer truncation.

## Test files (108 files)
**Result: CLEAN (negative — coverage)**. All test files exercise dual-AST differential, bracket-list, strict/lenient gates, regression for specific bugs (#2419, #3703, #2419, etc.). No production truncation in test helpers. Coverage gaps tracked in #4422/#4499, not new findings.

---

# Findings

## Finding 1: BGP ASN negative-value truncation via Atoi -> uint32

Title: BGP ASN fields accept negative integers via Atoi, truncating to large uint32 on cast
Severity (Critical/High/Medium/Low): Low
Confidence (High/Medium/Low): High
Evidence (file:line refs + a quoted 5-10 line code snippet you actually read):
  - File: /home/ps/git/avacado-xpf/pkg/config/compiler_protocols.go:211-215
```go
                case "local-as":
                    if len(child.Keys) >= 2 {
                        if v, err := strconv.Atoi(child.Keys[1]); err == nil {
                            proto.BGP.LocalAS = uint32(v)
                        }
                    }
```
  - File: /home/ps/git/avacado-xpf/pkg/config/compiler_protocols.go:305-310
```go
                case "peer-as":
                    if v := nodeVal(child); v != "" {
                        if n, err := strconv.Atoi(v); err == nil {
                            peerAS = uint32(n)
                        }
                    }
```
  - Same pattern at compiler_protocols.go:312-316 (group local-as), 322-325 (hold-time), 376-379 (per-neighbor peer-as), etc.
Trace (step-by-step runtime execution trace; REQUIRED for High/Medium):
  N/A — Low severity, but for completeness:
  1. Operator types `set protocols bgp group external peer-as -1` (typo - intended 1).
  2. Parser accepts `-1` as single identifier token (`-` is in isIdentChar, digits are valid, so `-1` is one token).
  3. `strconv.Atoi("-1")` returns (-1, nil) — no error, negative parses fine.
  4. `uint32(-1)` = 4294967295 stored in peerAS/groupLocalAS/LocalAS.
  5. `validateBGPNeighborPeerASStrict` checks `PeerAS == 0` to reject missing AS, but 4294967295 != 0 — passes.
  6. FRR renders `neighbor <addr> remote-as 4294967295` — valid 4-byte ASN syntax but wrong value. BGP OPEN fails or establishes with wrong identity.
Refutation attempt (REQUIRED for High/Critical: describe how you TRIED to prove this is a false positive — read the validators/guards/callers/type defs that would make it safe — and state why the finding survived. If it does not survive, downgrade or drop it. Do NOT report a High/Critical you did not try to refute.):
  N/A — Low severity
HPC/invariant check (where relevant: atomic wrapping, lock contention, cache-line alignment, endianness):
  N/A
Why it matters:
  Operator typo (`-1` instead of `1`) commits cleanly and produces valid-looking but wrong FRR config. BGP session fails or establishes with wrong ASN. Violates fail-closed-on-typo doctrine. Low severity — requires specific typo, not security bypass, but produces silent misconfiguration.
Fix direction (concrete — the report is a remediation work-list):
  Replace `strconv.Atoi` with `strconv.ParseUint(v, 10, 32)` for all ASN fields (local-as, peer-as, group peer-as, etc.), or add explicit `n > 0` check before `uint32(n)` cast. For fields with range 1..4294967295, use ParseUint with 32-bit size. For priority (0..255) and similar small-range fields, use ParseUint with 8-bit or explicit bounds check `n >= 0 && n <= 255`. Audit all `Atoi -> uint32` / `Atoi -> uint16` sites in compiler_protocols.go and compiler_routing.go.
Labels (include vsrx-parity for parity issues):
  correctness, integer-truncation, vsrx-parity
Dedup note (why this is not a restatement of any entry in the dedup index — cite specific dedup entries you checked against):
  Not in dedup. Checked #4572 (heartbeat workers uint32 overflow — different field), #4533 (icmp_embed), #4526 (dhcp leaseTime int64 overflow — different field), #4525 (ra max-advertisement-interval), #4519 (nptv6 host-bits), #4548 (vrrp hop-limit), #4434 (heartbeat RG count uint8 — similar class but different subsystem), #4323 (IPsec passthrough), #4146 (junos-host). None cover BGP ASN negative truncation.

## Finding 2: FilterTermExpansionCount uint32 truncation on large cross-product

Title: FilterTermExpansionCount truncates when term expansion exceeds 4B rules, causing counter-slot stride drift
Severity (Critical/High/Medium/Low): Low
Confidence (High/Medium/Low): Medium
Evidence (file:line refs + a quoted 5-10 line code snippet you actually read):
  - File: /home/ps/git/avacado-xpf/pkg/config/firewall_filter_expand.go:24-52
```go
func FilterTermExpansionCount(term *FirewallFilterTerm, prefixLists map[string]*PrefixList) uint32 {
	nSrc := len(term.SourceAddresses)
	for _, ref := range term.SourcePrefixLists {
		if pl, ok := prefixLists[ref.Name]; ok {
			nSrc += len(pl.Prefixes)
		}
	}
	if nSrc == 0 {
		nSrc = 1
	}
	nDst := len(term.DestAddresses)
	for _, ref := range term.DestPrefixLists {
		if pl, ok := prefixLists[ref.Name]; ok {
			nDst += len(pl.Prefixes)
		}
	}
	if nDst == 0 {
		nDst = 1
	}
	nDstPorts := len(term.DestinationPorts)
	if nDstPorts == 0 {
		nDstPorts = 1
	}
	nSrcPorts := len(term.SourcePorts)
	if nSrcPorts == 0 {
		nSrcPorts = 1
	}
	return uint32(nSrc * nDst * nDstPorts * nSrcPorts)
}
```
Trace (step-by-step runtime execution trace; REQUIRED for High/Medium):
  N/A — Low severity, but trace:
  1. Operator defines prefix-list big-src with 2000 prefixes, big-dst with 2000 prefixes.
  2. Filter term matches source-prefix-list big-src, dest-prefix-list big-dst, destination-port [80 443 8000-9000 range 100 discrete ports], source-port [1024-65535 range 100 discrete ports].
  3. nSrc=2000, nDst=2000, nDstPorts=100, nSrcPorts=100. Product = 2000*2000*100*100 = 40,000,000,00 = 40B > 2^32 (4.29B).
  4. On amd64, int is 64-bit, so nSrc*nDst*nDstPorts*nSrcPorts = 40B fits in int64, but uint32(40B) truncates to 40B mod 2^32 = 1,346,177,024 — wrong stride.
  5. On 386, int is 32-bit, product overflows int before cast — undefined/wrapped.
  6. CLI `show firewall filter` uses this to advance counter offsets (RuleStart + count). Truncated count causes next term to read neighbour's slots — counter drift (#3459 class).
Refutation attempt (REQUIRED for High/Critical: describe how you TRIED to prove this is a false positive — read the validators/guards/callers/type defs that would make it safe — and state why the finding survived. If it does not survive, downgrade or drop it. Do NOT report a High/Critical you did not try to refute.):
  N/A — Low severity. Attempted refutation: checked if expandFilterTerm itself would OOM before truncation matters. expandFilterTerm creates slice of length product — if product is 40B, it would try to allocate 40B * sizeof(rule) and OOM first. So practical trigger requires product >4B but < memory limit to cause silent truncation without OOM. Example: 5000*5000*10*10 = 2.5B fits uint32, 7000*7000*10*10 = 4.9B truncates. 7000-prefix lists are uncommon but possible via Junos prefix-list scaling. Product 4.9B would allocate 4.9B rules — OOM. So real-world trigger is unlikely, but not impossible with moderate lists (1000*1000*100*100 = 10B truncates, 10B rules OOM). The function is called for counter stride, not for expansion itself — drift test pins it to len(expandFilterTerm) which would also be truncated if expansion succeeded, so they would agree but still be wrong. Downgraded to Low.
HPC/invariant check (where relevant: atomic wrapping, lock contention, cache-line alignment, endianness):
  N/A
Why it matters:
  Counter drift causes `show firewall filter` to display wrong hit counts for terms after a large-expansion term. Could mask policy bypass — operator thinks deny term has 0 hits when it actually has hits from neighbour's slots. Also could cause prometheus xpf_filter_hits_total to be wrong.
Fix direction (concrete — the report is a remediation work-list):
  Change return type to uint64 for internal calculation, then check overflow before truncating to uint32 for wire. Or compute product in uint64 and return uint64, with callers that need uint32 checking for overflow and warning. Or cap expansion count at math.MaxUint32 and warn when exceeded. At minimum, add `if product > math.MaxUint32 { return math.MaxUint32 }` with warning, or compute in uint64 and return uint64.
Labels (include vsrx-parity for parity issues):
  correctness, integer-truncation, observability
Dedup note (why this is not a restatement of any entry in the dedup index — cite specific dedup entries you checked against):
  Not in dedup. Checked #4408 (tx/dispatch god-functions), #4407 (daemon.go god-struct), #4404 (poll_descriptor), #4422 (test-coverage backlog), #4415 (review-watcher backlog), #3459 (counter-slot stride — related but not about uint32 truncation, about stride correctness). None cover uint32 overflow in FilterTermExpansionCount.

## Finding 3: Global policy match from-zone/to-zone single-value read drops bracket-list

Title: Global policy match from-zone/to-zone reads only first value, silently dropping additional zones from bracket-list
Severity (Critical/High/Medium/Low): Low
Confidence (High/Medium/Low): Medium
Evidence (file:line refs + a quoted 5-10 line code snippet you actually read):
  - File: /home/ps/git/avacado-xpf/pkg/config/compiler_security_policy.go:240-257
```go
			case "from-zone":
				// #3148: global-policy from-zone match context. The schema
				// exposes this leaf only under `security policies global
				// policy <p> match`; for zone-pair policies the zones come
				// from the surrounding from-zone/to-zone stanza so this case
				// is never reached. Empty stays "all zones".
				if len(m.Keys) >= 2 {
					pol.Match.FromZone = m.Keys[1]
				} else if len(m.Children) > 0 {
					pol.Match.FromZone = m.Children[0].Name()
				}
			case "to-zone":
				// #3148: global-policy to-zone match context (see from-zone).
				if len(m.Keys) >= 2 {
					pol.Match.ToZone = m.Keys[1]
				} else if len(m.Children) > 0 {
					pol.Match.ToZone = m.Children[0].Name()
				}
```
Trace (step-by-step runtime execution trace; REQUIRED for High/Medium):
  N/A — Low severity, but trace:
  1. Operator configures `set security policies global policy allow-trust-untrust match from-zone [ trust untrust ]` intending global policy to match traffic from both trust and untrust.
  2. Parser bracket-list stripping collapses `[ trust untrust ]` onto Keys = ["from-zone", "trust", "untrust"] with no children — #2419 shape.
  3. Compiler reads only m.Keys[1] = "trust", drops Keys[2] = "untrust" silently.
  4. Policy matches only from-zone trust, not untrust — traffic from untrust that should match falls through to default-policy deny-all (fail-closed) or, if deny global policy, traffic from untrust that should be denied is permitted by later permit.
Refutation attempt (REQUIRED for High/Critical: describe how you TRIED to prove this is a false positive — read the validators/guards/callers/type defs that would make it safe — and state why the finding survived. If it does not survive, downgrade or drop it. Do NOT report a High/Critical you did not try to refute.):
  N/A — Low severity. Attempted refutation: checked Junos docs — global policy match from-zone/to-zone in Junos take single zone name (match context is one zone). Bracket-list is likely not valid Junos for these leaves. Schema likely declares them single-value (multi:false), so bracket-list would be caught by trailing-token gate (#3332) or schema multi:false validation. Checked if validateTrailingTokensStrict covers these — it walks address-book and IKE gateway, not policy from-zone/to-zone. Checked if generic schema walker rejects multi-value on single-value leaf — yes, schema_walk would error on extra Keys beyond expected arity for single-value leaf. If that gate exists, bracket-list would be rejected at commit, making this not a bug, just inconsistent with other multi-value leaves that use firewallMatchValues. Downgraded to Low / Medium confidence.
HPC/invariant check (where relevant: atomic wrapping, lock contention, cache-line alignment, endianness):
  N/A
Why it matters:
  If operator mistakenly uses bracket-list (thinking it works like source-address [ a b ]), second zone silently dropped. For deny global policy, could be fail-open. Violates #2419 bracket-list handling discipline (all multi-value leaves must use firewallMatchValues SSOT).
Fix direction (concrete — the report is a remediation work-list):
  Either: (a) Ensure schema declares from-zone/to-zone as single-value and trailing-token gate rejects bracket-list with clear error like "from-zone takes single zone, not list". Or: (b) If Junos supports bracket-list for these (unlikely), read all values via firewallMatchValues and change Match.FromZone/ToZone to []string, or handle multi-zone match context. At minimum, add comment that these are intentionally single-value and bracket-list is rejected elsewhere, to prevent future regression.
Labels (include vsrx-parity for parity issues):
  correctness, vsrx-parity
Dedup note (why this is not a restatement of any entry in the dedup index — cite specific dedup entries you checked against):
  Not in dedup. Checked #3148 (global-policy from-zone/to-zone scope — added the feature, but not about bracket-list truncation), #4365 (global-policy from-zone/to-zone not regression-tested — about test coverage, not truncation), #4497 (global-scope matrix into Rust), #4313 (schema opt-in). None cover bracket-list truncation for global-policy zone context.

# Integer-Truncation Audit Summary

Searched all `strconv.Atoi -> uint16/uint32` casts and `len() -> uint16/uint32` in batch:

| Site | Cast | Guard | Verdict |
|------|------|-------|---------|
| compiler_interfaces.go:571 WgListenPort = uint16(n) | uint16 | n > 0 && n <= 65535 | SAFE |
| compiler_interfaces.go:629 KeepaliveSecs = uint16(n) | uint16 | n >= 0 && n <= 65535 | SAFE |
| compiler_protocols.go:213 LocalAS = uint32(v) | uint32 | none (Atoi, no negative check) | FINDING F-01 |
| compiler_protocols.go:307 peerAS = uint32(n) | uint32 | none | FINDING F-01 |
| compiler_protocols.go:313 groupLocalAS = uint32(n) | uint32 | none | FINDING F-01 |
| filter_match_resolve.go:232 return uint16(n) | uint16 | n >=1 && n <=65535 via parseCanonicalPort | SAFE |
| filter_match_resolve.go:295 return uint16(l), uint16(h) | uint16 | l>=0 && h<=65535 && l<=h, range-checked | SAFE |
| firewall_filter_expand.go:52 return uint32(product) | uint32 | none — int product may exceed 4B | FINDING F-02 |

No `len() -> uint16` direct truncation found (grep `uint16(len`, `uint32(len` empty). Closest is FilterTermExpansionCount len sum then multiply then cast.

# Keys[1] / Keys[1:] OOB Audit Summary

- All Keys[1] accesses guarded by len(Keys) >=2 or len(child.Keys) >=2.
- All Keys[1:] slices guarded by len >=2 or unconditional (empty slice safe in Go).
- No out-of-bounds found. One minor single-value read where bracket-list could be intended (F-03).

# Zone/Global Policy / Host-Inbound / Application Matching Audit Summary

- Zone policies: dual-shape correct, duplicate inner match/then accumulation correct (#3842), terminal-action conflict detection correct (#3043).
- Global policies: correct via global { policy ... }, from-zone/to-zone single-value read minor issue (F-03).
- Host-inbound: multi-value system-services/protocols via firewallMatchValues correct, duplicate blocks merge via mergeHostInbound correct, per-interface override additive (#3720) correct, lifeline exemption correct.
- Application matching: policy match application via firewallMatchValues correct, app-set expansion with cycle detection correct, undefined app reject hard + empty-set check correct (#3146).
- Default-permit/deny: default-policy map permit-all/deny-all/reject-all correct (#3065), empty stays nil (default-deny fail-closed).

