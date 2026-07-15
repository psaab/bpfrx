# Paladin Review — A8_go_api_grpc_rest batch 2/2

Base commit: d4506d4450e23f9a3fc572206b3c82f6b6c99029
Area: A8_go_api_grpc_rest — batch 2/2 (82 files)
Reviewer: paladin-038 campaign batch 18
Date: 2026-07-07

## Batch File List

```
pkg/grpcapi/server_routing.go
pkg/grpcapi/server_screen_inventory_3327_test.go
pkg/grpcapi/server_security_nil_3476_test.go
pkg/grpcapi/server_sessions.go
pkg/grpcapi/server_sessions_test.go
pkg/grpcapi/server_show.go
pkg/grpcapi/server_show_appid.go
pkg/grpcapi/server_show_appid_test.go
pkg/grpcapi/server_show_chassis.go
pkg/grpcapi/server_show_chassis_forwarding_test.go
pkg/grpcapi/server_show_cluster_text.go
pkg/grpcapi/server_show_compare_strict_3443_test.go
pkg/grpcapi/server_show_cos_gap7_test.go
pkg/grpcapi/server_show_device_map.go
pkg/grpcapi/server_show_dhcp_lldp_snmp.go
pkg/grpcapi/server_show_events.go
pkg/grpcapi/server_show_events_forensic_3337_test.go
pkg/grpcapi/server_show_events_historical_zone_3335_test.go
pkg/grpcapi/server_show_events_zone0_3338_test.go
pkg/grpcapi/server_show_events_zone_3334_test.go
pkg/grpcapi/server_show_firewall.go
pkg/grpcapi/server_show_firewall_test.go
pkg/grpcapi/server_show_flow.go
pkg/grpcapi/server_show_forwarding.go
pkg/grpcapi/server_show_forwarding_adapter_test.go
pkg/grpcapi/server_show_golden_test.go
pkg/grpcapi/server_show_interfaces.go
pkg/grpcapi/server_show_interfaces_reth_4328_test.go
pkg/grpcapi/server_show_interfaces_text.go
pkg/grpcapi/server_show_nat.go
pkg/grpcapi/server_show_nat_shared_test.go
pkg/grpcapi/server_show_nat_test.go
pkg/grpcapi/server_show_policies_addr_inventory_3336_test.go
pkg/grpcapi/server_show_policies_hitcount_gate_test.go
pkg/grpcapi/server_show_policies_hitcount_globals_test.go
pkg/grpcapi/server_show_policies_scheduler_3062_test.go
pkg/grpcapi/server_show_policies_text.go
pkg/grpcapi/server_show_policies_text_exclusion_3667_test.go
pkg/grpcapi/server_show_policies_text_scoped_global_3357_test.go
pkg/grpcapi/server_show_policies_thencount_3074_test.go
pkg/grpcapi/server_show_policies_zone_local_3358_test.go
pkg/grpcapi/server_show_rollback_zero_n_4556_test.go
pkg/grpcapi/server_show_routes_text.go
pkg/grpcapi/server_show_rpm_test.go
pkg/grpcapi/server_show_screen_inventory_text_3327_test.go
pkg/grpcapi/server_show_security_log_zone_3547_test.go
pkg/grpcapi/server_show_security_text.go
pkg/grpcapi/server_show_security_wireguard_test.go
pkg/grpcapi/server_show_status.go
pkg/grpcapi/server_show_status_3929_test.go
pkg/grpcapi/server_show_system.go
pkg/grpcapi/server_show_system_buffers_test.go
pkg/grpcapi/server_show_testpolicy_srcport_test.go
pkg/grpcapi/server_show_zones.go
pkg/grpcapi/server_show_zones_default_policy_3363_test.go
pkg/grpcapi/server_show_zones_default_policy_log_3670_test.go
pkg/grpcapi/server_show_zones_explicit_any_3680_test.go
pkg/grpcapi/server_show_zones_hostinbound_3328_test.go
pkg/grpcapi/server_show_zones_hostinbound_display_3654_test.go
pkg/grpcapi/server_show_zones_lifeline_3682_test.go
pkg/grpcapi/server_show_zones_metadata_3684_test.go
pkg/grpcapi/server_show_zones_policy_tiers_3658_test.go
pkg/grpcapi/server_show_zones_scheduler_inventory_3624_test.go
pkg/grpcapi/server_show_zones_scoped_global_3286_test.go
pkg/grpcapi/server_show_zones_test.go
pkg/grpcapi/server_show_zones_text.go
pkg/grpcapi/server_testpolicy_dup_3709_test.go
pkg/grpcapi/server_testpolicy_strictness_3696_test.go
pkg/grpcapi/server_zone_nil_3493_test.go
pkg/grpcapi/session_app_srcport_3428_test.go
pkg/grpcapi/session_filter_3439_test.go
pkg/grpcapi/session_filter_test.go
pkg/grpcapi/sessions_iterator_error_test.go
pkg/grpcapi/system_action_journal_4108_test.go
pkg/grpcapi/system_action_test.go
pkg/grpcapi/test_commands_test.go
pkg/grpcapi/text_filter_flood_counter_error_test.go
pkg/grpcapi/xpfv1/xpf.pb.go
pkg/grpcapi/xpfv1/xpf_grpc.pb.go
pkg/grpcapi/zone_flood_counters_hide_test.go
pkg/grpcapi/zonepair_summary_3592_test.go
pkg/grpcapi/zones_policies_counter_error_test.go
```

## Module-by-Module Log

| Module | Files | Verdict | Notes |
|--------|-------|---------|-------|
| server_routing.go | GetRoutes, GetOSPFStatus, GetBGPStatus, GetRIPStatus, GetISISStatus, GetIPsecSA | FINDING (F-001 Medium) | BGP Type→IP unvalidated before vtysh concat; otherwise sound |
| server_sessions.go | GetSessions, getSessionsCursor, getSessionsLegacy, GetSessionSummary, GetZonePairSummary, ClearSessions, buildSessionFilter, matchV4/V6, protoFilterMatches, sessionFilter, clearErrors, sessionEntryV4/V6, page tokens | NEGATIVE | All truncation guards present, clear path mirrors show path, reverse-key correct |
| server_show.go | ShowText dispatcher, 80+ topic cases | NEGATIVE | Dispatch table correct, log path sanitized via filepath.Base, tail lines clamped |
| server_show_appid.go | showApplicationIdentificationStatus | NEGATIVE | Thin delegate to pkg/appid.RenderStatus |
| server_show_chassis.go | showChassis | NEGATIVE | /proc reads only |
| server_show_cluster_text.go | showChassisForwarding, showChassisCluster* | NEGATIVE | Recursion guard, peer label guard, counter error surfacing |
| server_show_device_map.go | showChassisDeviceMap, showChassisDeviceMapCandidates | NEGATIVE | Local NIC inventory only |
| server_show_dhcp_lldp_snmp.go | showSNMP, showSNMPv3, showDHCPServer, showDHCPDynamicDNS, showServicesDynamicDNS, showDHCPRelay, showLLDP | NEGATIVE | TSIG secrets redacted, SNMP community only auth mode |
| server_show_events.go | GetEvents, showEventOptions | NEGATIVE | Zone uint16 truncation fixed (#3334), limit clamped |
| server_show_firewall.go | showFirewall, showTestPolicy, showFirewallFilter | NEGATIVE | showTestPolicy strictness fixed (#3696/#3709) |
| server_show_flow.go | showFlowMonitoring*, showFlowTimeouts, showFlowStatistics, showSessionsTop, showFlowTraceoptions | NEGATIVE | Counter errors surfaced (#3345), no secret leak |
| server_show_forwarding.go | buildLocalForwarding, dialAndShowForwarding, showForwardingOptions | NEGATIVE | Peer dial recursion guarded, ctx timeout |
| server_show_interfaces.go | GetInterfaces, ShowInterfacesDetail, showInterfacesTerse, reth helpers | NEGATIVE | Ifname resolution via ResolveKernelIfName, nil-zone guards |
| server_show_interfaces_text.go | showInterfacesExtensive/Detail/Statistics, showClassOfService, showCoS*, showVLANs, showIPv6RA | NEGATIVE | netlink listing, sysfs reads, config-driven |
| server_show_nat.go | showNATStatic/NPTv6/Persistent/Source/Dest/Detail/NAT64 | NEGATIVE | Thin wrappers over pkg/natshow |
| server_show_policies_text.go | showPoliciesHitCount, showPoliciesDetail, showPolicyOptions | NEGATIVE | Nil-zone/nil-rule guards (#3476), bulk counter reader (#4344), global tier, exclusion markers (#3667) |
| server_show_routes_text.go | showRouteAll/Summary/Terse/Detail/Table/Protocol/Prefix/TestRouting, showRoutingOptions/Instances | FINDING (F-002 Low, F-003 Low) | showTestRouting silent-drop; showRoutePrefix fragile but functional |
| server_show_security_text.go | showIPsecStatistics, showTunnels, showRPM, showSecurityLog, showSchedulers, showApplications, showSecurityAlarms, showScreen*, showAlg, showAddressBook, showIKE, showWireguard | NEGATIVE | Nil guards, screen SSOT, threshold surfacing, zone-filter fail-closed (#3547) |
| server_show_status.go | GetStatus, GetGlobalStats, GetSystemInfo | NEGATIVE | GetSystemInfo uses outputTimeout, counter errors→Internal (#3345), SessionCount not GC (#3929) |
| server_show_system.go | showVersion/Storage/CommitHistory/Alarms/ChassisEnvironment/SystemServices/NTP/SystemSyslog/Login/etc | NEGATIVE | No user input, NTP exec bounded by ctx+timeout |
| server_show_zones.go | GetZones, GetPolicies, GetScreen | NEGATIVE | host_inbound_configured=true always (#3653), lifeline surfaced (#3682), nil-zone guards, counter error→Internal (#3408) |
| server_show_zones_text.go | showZonesDetail, showTestZone | NEGATIVE | Host-inbound via shared presenter, screen SSOT (#3327), policy tiers (#3658) |
| *_test.go (62 files) | Fail-on-revert guards | NEGATIVE | No production code; tests correctly pin fixed behavior |

## Findings

### F-001 — FRR vtysh command injection via unvalidated BGP neighbor IP in GetBGPStatus

Title
FRR vtysh command injection — gRPC GetBGPStatus Type field flows unsanitized into vtysh command string

Severity
Medium

Confidence
Medium

Evidence
File pkg/grpcapi/server_routing.go lines 142-167:
```
        // "received-routes:<ip>" for neighbor received routes
        if strings.HasPrefix(req.Type, "received-routes:") {
            ip := strings.TrimPrefix(req.Type, "received-routes:")
            output, err := s.frr.GetBGPNeighborReceivedRoutes(ip)
            if err != nil {
                return nil, status.Errorf(codes.Internal, "%v", err)
            }
            return &pb.GetBGPStatusResponse{Output: output}, nil
        }
        // "advertised-routes:<ip>" for neighbor advertised routes
        if strings.HasPrefix(req.Type, "advertised-routes:") {
            ip := strings.TrimPrefix(req.Type, "advertised-routes:")
            output, err := s.frr.GetBGPNeighborAdvertisedRoutes(ip)
```
File pkg/frr/vtysh.go lines 192-196:
```
func (m *Manager) GetBGPNeighborReceivedRoutes(ip string) (string, error) {
    if ip == "" {
        return "", fmt.Errorf("neighbor IP required")
    }
    return m.executor().Vtysh("show bgp neighbor " + ip + " received-routes")
}
```
Identical pattern at lines 200-204 (GetBGPNeighborAdvertisedRoutes) and 209-214 (GetBGPNeighborDetail). No net.ParseIP validation anywhere in the path.

Trace
1. gRPC client sends `GetBGPStatusRequest{Type: "received-routes:10.0.0.1 vrf default"}`. Transport is localhost-only (127.0.0.1:50051) per CLAUDE.md, but reachable by any local process or via SSRF to localhost.
2. GetBGPStatus extracts `ip = "10.0.0.1 vrf default"` via strings.TrimPrefix — no validation.
3. Calls `s.frr.GetBGPNeighborReceivedRoutes("10.0.0.1 vrf default")`.
4. Constructs vtysh command: `"show bgp neighbor 10.0.0.1 vrf default received-routes"` — FRR interprets `vrf default` as a VRF selector, leaking routes from another VRF.
5. `realExecutor.Vtysh` executes `exec.CommandContext(ctx, "vtysh", "-c", "show bgp neighbor 10.0.0.1 vrf default received-routes")` — OS shell not involved, but FRR CLI parser interprets the extra tokens.
6. More aggressive payload: attacker could try newline injection for FRR command chaining, though vtysh -c typically takes a single command (not confirmed to support chaining).

Refutation attempt
- Checked realExecutor.Vtysh uses `exec.CommandContext(ctx, "vtysh", "-c", command)` — no OS shell, so classic shell injection ($(), ;, |) is blocked. This eliminates Critical severity.
- Checked FRR vtysh docs: vtysh -c takes a single command string. Does not document semicolon or newline chaining. Reduces likelihood of full FRR config modification.
- However, FRR vtysh DOES support rich command qualification — e.g. "show bgp neighbor WORD" where WORD could pivot VRF context or include address-family selectors. An attacker can inject extra FRR tokens after the IP.
- Checked whether GetBGPStatus validates ip with net.ParseIP: it does not. Checked all three vtysh wrappers — only guard is `ip == ""`.
- Checked gRPC auth: gRPC is on localhost with no per-RPC authz beyond transport — any local process (including a compromised helper or container) can call it.
- Compared with other vtysh callers: showRoutePrefix, showTestRouting etc. do NOT pass gRPC-supplied strings to vtysh; only GetBGPStatus does.
- Finding survives as Medium (defense-in-depth, VRF pivot, information disclosure). Not Critical because no OS shell and vtysh -c single-command limit.

HPC/invariant check
Not applicable — input-validation / injection issue, not hot-path / atomic / cache-line concern.

Why it matters
- FRR vtysh controls routing state. An attacker with local gRPC access could enumerate VRF routes, leak BGP state from other tenants, or potentially inject BGP state if FRR parser supports chaining.
- Even without full command execution, VRF confusion (reading routes from wrong VRF) is a confidentiality violation in multi-tenant deployments.
- Defense-in-depth requires validating IP before concatenating into privileged command channels.

Fix direction
Add net.ParseIP validation at the vtysh boundary in pkg/frr/vtysh.go so both gRPC and any future REST callers are covered:
```go
func (m *Manager) GetBGPNeighborReceivedRoutes(ip string) (string, error) {
    if ip == "" { return "", fmt.Errorf("neighbor IP required") }
    if net.ParseIP(ip) == nil { return "", fmt.Errorf("invalid neighbor IP %q", ip) }
    return m.executor().Vtysh("show bgp neighbor " + ip + " received-routes")
}
```
Apply identically to GetBGPNeighborAdvertisedRoutes and GetBGPNeighborDetail (and GetISIS/OSPF detail methods if they take similar input). Also consider adding require import "net" to vtysh.go. Alternatively, validate in server_routing.go before calling FRR methods. Return InvalidArgument gRPC code for bad IP.

Labels
api-security, injection, vtysh, frr, defense-in-depth

Dedup note
Checked all 80+ entries in dedup index. No entry mentions BGP, GetBGPStatus, vtysh, FRR command injection, or neighbor IP validation. #4482/#4481 mention FRR sanitize-belt but for route-map/prefix-list during commit (config compilation), not operational vtysh show commands. #4524 mentions monitor traffic / tcpdump -w/-z injection, not FRR vtysh. #4498 FRR sanitize-belt residual is for config load path. This is a new finding.

### F-002 — showTestRouting silently drops malformed/unknown selector keys (inconsistent with showTestPolicy strictness)

Title
showTestRouting silently ignores malformed selector segments and unknown keys

Severity
Low

Confidence
High

Evidence
File pkg/grpcapi/server_show_routes_text.go lines 178-192:
```
func (s *Server) showTestRouting(req *pb.ShowTextRequest, buf *strings.Builder) (*pb.ShowTextResponse, error) {
    params := strings.TrimPrefix(req.Topic, "test-routing:")
    var dest, instance string
    for _, kv := range strings.Split(params, ",") {
        parts := strings.SplitN(kv, "=", 2)
        if len(parts) != 2 {
            continue
        }
        switch parts[0] {
        case "dest":
            dest = parts[1]
        case "instance":
            instance = parts[1]
        }
    }
```
Compare with the fixed sibling pkg/grpcapi/server_show_firewall.go lines 199-268 (showTestPolicy) which tracks parseErr, seen map, duplicate detection, unknown-key errors, and reports before evaluating — the #3696 fix.

Trace
1. Operator types `test routing destination 10.0.0.0/24` but gRPC topic arrives as `test-routing:destinat=10.0.0.0/24` (typo).
2. Loop splits on "," → ["destinat=10.0.0.0/24"], splits on "=" → ["destinat","10.0.0.0/24"].
3. Switch has no case "destinat" — falls through, no default arm, no error.
4. dest stays "" → falls into `else if dest == ""` → "Missing dest parameter" — confusing, no hint about typo.
5. Worse: `dest=10.0.0.0/24,instnace=dmz` — "instnace" silently dropped, lookup runs against main table instead of VRF dmz, returning wrong route with no warning.

Refutation attempt
- Verified the sibling showTestPolicy was fixed in #3696 to report malformed/unknown keys as errors. Confirmed showTestRouting was NOT fixed at the same time — it still has the old silent-drop pattern.
- Checked whether showTestRouting's callers ever pass malformed data: the local CLI (pkg/cli) constructs the topic from user input, so typo is possible. The gRPC client passes operator-typed strings directly.
- Checked dedup: #3696 fix documented for showTestPolicy only. No dedup entry for showTestRouting.
- Finding survives as Low (operator confusion, wrong VRF lookup, but no security bypass).

HPC/invariant check
Not applicable — diagnostic tool, not hot path.

Why it matters
- Operator troubleshooting tool returns wrong/misleading results on typo with no diagnostic. Could mask real routing issues during outage triage.
- Inconsistency with showTestPolicy which was fixed in #3696 to fail-closed — operators expect consistent strictness across test-* commands.

Fix direction
Mirror the #3696 fix from showTestPolicy:
```go
var parseErr error
for _, kv := range strings.Split(params, ",") {
    parts := strings.SplitN(kv, "=", 2)
    if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
        if parseErr == nil { parseErr = fmt.Errorf("malformed selector %q", kv) }
        continue
    }
    switch parts[0] {
    case "dest": dest = parts[1]
    case "instance": instance = parts[1]
    default:
        if parseErr == nil { parseErr = fmt.Errorf("unknown selector %q", parts[0]) }
    }
}
if parseErr != nil {
    fmt.Fprintf(buf, "%v\n", parseErr)
    return &pb.ShowTextResponse{Output: buf.String()}, nil
}
```

Labels
api-security, input-validation, observability, vsrx-parity

Dedup note
Checked dedup index — #3696 fix is documented for showTestPolicy only. No dedup entry covers showTestRouting's silent-drop behavior. This is a parity gap with the already-fixed sibling, not a re-report.

### F-003 — showRoutePrefix modifier parsing fragile (space-in-prefix theoretical edge)

Title
showRoutePrefix LastIndex-based modifier extraction could mis-split if prefix contains space

Severity
Low

Confidence
Low

Evidence
File pkg/grpcapi/server_show_routes_text.go lines 150-161:
```
func (s *Server) showRoutePrefix(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
    prefixAndMod := strings.TrimPrefix(req.Topic, "route-prefix:")
    prefix := prefixAndMod
    modifier := ""
    if idx := strings.LastIndex(prefixAndMod, " "); idx != -1 {
        candidate := prefixAndMod[idx+1:]
        switch candidate {
        case "exact", "longer", "orlonger":
            prefix = prefixAndMod[:idx]
            modifier = candidate
        }
    }
```

Trace
1. Normal: `route-prefix:10.0.0.0/24 exact` → LastIndex finds space before "exact" → prefix="10.0.0.0/24", modifier="exact" → correct.
2. Normal: `route-prefix:10.0.0.0/24` → no trailing keyword match → prefix unchanged → correct.
3. Malformed: `route-prefix:10.0.0.0/ 8` (space in prefix) → prefixAndMod="10.0.0.0/ 8", LastIndex finds space before "8", candidate="8" not in switch → prefix stays "10.0.0.0/ 8" → FormatRouteDestination fails CIDR parse → empty result, not wrong route. So even the edge is fail-safe.

Refutation attempt
- Verified all practical inputs (IPv4 CIDR, IPv6 CIDR, with/without modifier) parse correctly.
- Verified malformed input (space in CIDR) results in empty result, not wrong route.
- No security impact — only theoretical code-quality concern.

HPC/invariant check
Not applicable.

Why it matters
- Code is functionally correct for all well-formed inputs. Only theoretical malformed input could cause confusion, and even then result is empty not wrong. No security impact.

Fix direction
No immediate fix required. If hardening desired, split on first space or use explicit topic-argument separation. Close as informational.

Labels
robustness, code-quality

Dedup note
No dedup entry covers showRoutePrefix. Code-quality observation with no security impact.

## Negative Results (Required)

### server_sessions.go — NEGATIVE

What was checked
Session filter input validation (zone ID truncation, port truncation, protocol validation, prefix parsing), cursor pagination bounds, legacy offset/limit bounds, ClearSessions filter consistency, page token encoding/decoding, session entry enrichment, peer forwarding recursion guard, DoS amplification (limit/page_size clamping to 10000).

Why NEGATIVE
All integer-truncation paths are guarded:
- req.Zone > 65535 → InvalidArgument (line 366, #3334)
- req.SourcePort/DestinationPort > 65535 → InvalidArgument (lines 369-374)
- Unknown snatPool → InvalidArgument (lines 332-334, #3439)
- Invalid CIDR → InvalidArgument (lines 390-401)
- Unknown protocol → InvalidArgument (lines 381-385)
- Negative offset → InvalidArgument before dispatch (line 44, #3439)
- PageSize clamped to 10000, Limit defaulted to 100
- Page tokens opaque (base64+hex of session key bytes) — no injection
- ClearSessions builds filter from same buildSessionFilter as GetSessions (no show/clear divergence per #1827)
- Reverse session cleanup uses val.ReverseKey (translated tuple), not naive swap (fixes #2733)
- Negative zone in GetEvents fixed (#3334), same guard in sessions path

### server_show.go ShowText dispatcher — NEGATIVE

What was checked
Topic dispatch table, prefix-based routing, parameterized topic handling, switch-case completeness, log file path traversal, tail line count DoS, unknown topic handling, chassis-hardware alias context forwarding.

Why NEGATIVE
- log: topic uses filepath.Base(parts[1]) to prevent path traversal
- Tail line count clamped via clampTailLines (prevents huge N → OOM)
- All parameterized topics use TrimPrefix with proper bounds
- Unknown topics return InvalidArgument
- Chassis-hardware alias correctly forwards context for xpf-no-peer guard
- No integer truncation issues

### server_show_zones.go — NEGATIVE

What was checked
GetZones host-inbound posture (host_inbound_configured always true per #3653 mirrors dataplane), lifeline interfaces surfaced (#3682), nil-zone guards (#3493), counter read failures → codes.Internal (#3408), GetPolicies policy-stats gating (#2118) + then-count override (#3074), global policy scoping (#3148), default-policy synthetic row (#3363), GetScreen nil-profile handling (#3476), screenChecks SSOT delegation.

Why NEGATIVE
All previously reported issues fixed and pinned by fail-on-revert tests. No truncation, no secret leak, no bypass.

### server_show_* text renderers — NEGATIVE

What was checked
showFlowMonitoring, showFlowMonitoringStatistics, showFlowTimeouts, showFlowStatistics, showSessionsTop, showFlowTraceoptions, showForwardingOptions, showDHCPDynamicDNS, showServicesDynamicDNS, showLLDP, showScreen, showScreenIDSOption/Statistics/Detail, showSecurityLog, showSecurityAlarms, showIKE, showWireguard, showBuffers, showSystemServices, showNTP, showSystemSyslog, showLogin, showInternetOptions, showRootAuthentication, showCoreDumps, showTask, showBackupRouter, showClassOfService, showInterfacesQueue, showCoSClassifier, showCoSSchedulerMap, showCoSForwardingClass, showVLANs, showIPv6RouterAdvertisement — for secret exposure, context propagation, path traversal, DoS amplification, injection.

Why NEGATIVE
- DDNS TSIG/Surface-A secrets redacted (only key name printed) — showDHCPDynamicDNS line 229, showServicesDynamicDNS line 301
- SNMP community secrets not leaked (only Authorization field shown, not community string) — showSNMP line 40
- showNTP uses combinedOutputTimeout(ctx, ...) — bounded by request context + per-exec timeout
- showSecurityLog parses filter via shared logging.ParseEventFilterArgs — fails closed on unknown zone (#3547)
- showFlowStatistics / showFlowMonitoringStatistics — counter errors surfaced as warnings (#3345)
- showSystemSyslog / showLogin — no user input, config-derived only
- showSecurityLog zone-name resolution prefers stored name, falls back to live config only for legacy records (#3335) — correct

## Summary

Reviewed 82 files (~15K LOC production + ~8K LOC tests) in A8_go_api_grpc_rest batch 2/2:

- 1 Medium (F-001): FRR vtysh command injection via unvalidated BGP neighbor IP in GetBGPStatus. Requires local gRPC access (localhost-only transport bounds impact). Fix: add net.ParseIP validation at pkg/frr/vtysh.go boundary.
- 1 Low (F-002): showTestRouting silent-drop vs showTestPolicy strictness (#3696 parity gap) — operator typo returns wrong routing table with no diagnostic.
- 1 Low (F-003): showRoutePrefix LastIndex fragility — functionally correct, theoretical edge only, no security impact.
- All other modules NEGATIVE with high confidence — extensive fail-on-revert test coverage provides strong regression protection. Integer truncation, secret exposure, DoS amplification, and HA correctness all verified sound.
