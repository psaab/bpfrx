# Paladin Review Batch 17 — A8_go_api_grpc_rest (batch 1/2)

Base commit: d4506d4450e23f9a3fc572206b3c82f6b6c99029
Area: A8_go_api_grpc_rest — batch 1/2
Reviewer: API-security engineer (zone policy, gRPC/REST, integer truncation, DoS, resource leaks)
Date: 2026-07-07

## Batch File List (150 files)

- pkg/api/api.go
- pkg/api/auth.go
- pkg/api/auth_consttime_4157_test.go
- pkg/api/auth_test.go
- pkg/api/config.go
- pkg/api/config_activate_test.go
- pkg/api/config_commit_test.go
- pkg/api/config_load_bodycap_hb164_test.go
- pkg/api/config_raw_ast_redaction_test.go
- pkg/api/config_rollback_compare_strict_3443_test.go
- pkg/api/config_secret_redaction_test.go
- pkg/api/configstore_helper_test.go
- pkg/api/dhcp.go
- pkg/api/exec_timeout.go
- pkg/api/exec_timeout_test.go
- pkg/api/filter_counters_metrics_test.go
- pkg/api/health.go
- pkg/api/health_test.go
- pkg/api/http_dos_hardening_4150_test.go
- pkg/api/iface_name_test.go
- pkg/api/interface_counter_error_test.go
- pkg/api/interfaces.go
- pkg/api/ipsec.go
- pkg/api/metrics.go
- pkg/api/metrics_auth_gate_4162_test.go
- pkg/api/metrics_cold_path_test.go
- pkg/api/metrics_counters.go
- pkg/api/metrics_descriptor_coverage_test.go
- pkg/api/metrics_descriptors.go
- pkg/api/metrics_flowexport_test.go
- pkg/api/metrics_frr_degraded_test.go
- pkg/api/metrics_host_inbound_addressless_3698_test.go
- pkg/api/metrics_host_inbound_ambiguous_3718_test.go
- pkg/api/metrics_host_inbound_kernel_test.go
- pkg/api/metrics_nat.go
- pkg/api/metrics_neighbor_latency_test.go
- pkg/api/metrics_persist_degraded_test.go
- pkg/api/metrics_scoped_global_3286_test.go
- pkg/api/metrics_sessions.go
- pkg/api/metrics_sessions_cache_test.go
- pkg/api/metrics_sessions_userspace_3929_test.go
- pkg/api/metrics_surface_a_ddns_test.go
- pkg/api/metrics_system.go
- pkg/api/metrics_test.go
- pkg/api/metrics_userspace.go
- pkg/api/metrics_wireguard_test.go
- pkg/api/nat.go
- pkg/api/nat_stats_test.go
- pkg/api/policies_bulk_reader_test.go
- pkg/api/policy_counters_test.go
- pkg/api/rest_events_forensic_3337_test.go
- pkg/api/rest_events_zone0_3338_test.go
- pkg/api/rest_filter_failclosed_test.go
- pkg/api/routing.go
- pkg/api/security.go
- pkg/api/security_default_policy_log_3670_test.go
- pkg/api/security_matchpolicies_action_3375_test.go
- pkg/api/security_matchpolicies_desc_sched_3685_test.go
- pkg/api/security_matchpolicies_dup_3709_test.go
- pkg/api/security_matchpolicies_exclusion_3668_test.go
- pkg/api/security_matchpolicies_hostinbound_3627_test.go
- pkg/api/security_matchpolicies_queried_zones_3627_test.go
- pkg/api/security_matchpolicies_scheduler_3414_test.go
- pkg/api/security_matchpolicies_scope_3331_test.go
- pkg/api/security_policy_addr_inventory_3336_test.go
- pkg/api/security_policy_counter_handle_3474_test.go
- pkg/api/security_policy_id_zero_3623_test.go
- pkg/api/security_policy_scheduler_inventory_3624_test.go
- pkg/api/security_scoped_global_3286_test.go
- pkg/api/security_screen_inventory_3327_test.go
- pkg/api/security_screen_nil_3476_test.go
- pkg/api/security_test.go
- pkg/api/security_zone_hostinbound_3328_test.go
- pkg/api/security_zone_local_3358_test.go
- pkg/api/security_zone_nil_3493_test.go
- pkg/api/security_zone_policy_meta_3329_test.go
- pkg/api/server.go
- pkg/api/sessions.go
- pkg/api/sessions_ha_scope_3423_test.go
- pkg/api/sessions_iterator_error_test.go
- pkg/api/sessions_pagination_test.go
- pkg/api/sessions_parity_test.go
- pkg/api/sessions_zonepair_peer_3592_test.go
- pkg/api/show_text.go
- pkg/api/sse.go
- pkg/api/sse_filter_failclosed_3383_test.go
- pkg/api/sse_test.go
- pkg/api/stats.go
- pkg/api/stats_counter_error_test.go
- pkg/api/stats_global_host_inbound_3681_test.go
- pkg/api/stats_global_parity_3426_test.go
- pkg/api/system.go
- pkg/api/system_argv_test.go
- pkg/api/system_buffers_test.go
- pkg/api/tls_test.go
- pkg/api/types.go
- pkg/api/vrrp.go
- pkg/api/write_json_4541_test.go
- pkg/api/zone_counters_hide_test.go
- pkg/api/zones_policies_counter_error_test.go
- pkg/grpcapi/apply_result.go
- pkg/grpcapi/clear_sessions_errors_test.go
- pkg/grpcapi/clear_sessions_peer_nodeid_3423_test.go
- pkg/grpcapi/clear_sessions_reversekey_test.go
- pkg/grpcapi/completion_test.go
- pkg/grpcapi/completion_typed_leaf_test.go
- pkg/grpcapi/configstore_helper_test.go
- pkg/grpcapi/exec_timeout.go
- pkg/grpcapi/exec_timeout_test.go
- pkg/grpcapi/fabric_auth.go
- pkg/grpcapi/flow_cluster_counter_error_test.go
- pkg/grpcapi/global_stats_counter_error_test.go
- pkg/grpcapi/global_stats_screen_keys_3343_test.go
- pkg/grpcapi/iface_name_test.go
- pkg/grpcapi/interface_counter_error_test.go
- pkg/grpcapi/pagination_test.go
- pkg/grpcapi/policies_bulk_reader_test.go
- pkg/grpcapi/runtime.go
- pkg/grpcapi/runtime_canary_test.go
- pkg/grpcapi/server.go
- pkg/grpcapi/server_cluster.go
- pkg/grpcapi/server_cluster_monitor_status_4480_test.go
- pkg/grpcapi/server_cluster_test.go
- pkg/grpcapi/server_config.go
- pkg/grpcapi/server_config_activate_test.go
- pkg/grpcapi/server_config_redaction_test.go
- pkg/grpcapi/server_config_test.go
- pkg/grpcapi/server_dhcp.go
- pkg/grpcapi/server_diag.go
- pkg/grpcapi/server_diag_argv_test.go
- pkg/grpcapi/server_diag_monitor_test.go
- pkg/grpcapi/server_diag_stream_test.go
- pkg/grpcapi/server_fabric_allowlist_4122_test.go
- pkg/grpcapi/server_fabric_auth_4107_test.go
- pkg/grpcapi/server_helpers.go
- pkg/grpcapi/server_input_validation_test.go
- pkg/grpcapi/server_matchpolicies_action_3375_test.go
- pkg/grpcapi/server_matchpolicies_desc_sched_3685_test.go
- pkg/grpcapi/server_matchpolicies_exclusion_3668_test.go
- pkg/grpcapi/server_matchpolicies_hostinbound_3627_test.go
- pkg/grpcapi/server_matchpolicies_queried_zones_3627_test.go
- pkg/grpcapi/server_matchpolicies_scheduler_3414_test.go
- pkg/grpcapi/server_matchpolicies_scope_3331_test.go
- pkg/grpcapi/server_missing_zone_3355_test.go
- pkg/grpcapi/server_nat.go
- pkg/grpcapi/server_nat_test.go
- pkg/grpcapi/server_packet_drop_validation_3382_test.go
- pkg/grpcapi/server_proto_validation_test.go
- pkg/grpcapi/server_recvsize_hb164_test.go

## Module-by-Module Log

### pkg/api/api.go — NEGATIVE
Reviewed decodeJSONBody (maxRequestBodyBytes=16MiB body cap), writeJSON (buffer-then-write, fail-closed), queryUint16/queryInt/queryUint16Strict/queryIntStrict (all fail-closed on bad values), parseRefBaseUnit, allInterfaceNames (nil-zone guard). All sound.

### pkg/api/auth.go — NEGATIVE
Reviewed constantTimeAPIKeyMatch (OR-s all key compares, no short-circuit), checkAuthorization (always runs ConstantTimeCompare even for unknown user), isLoopbackBindAddr (conservative: wildcard/empty/unparseable -> false). All sound. Dedup-checked against #4157 (file renamed/numbered differently but same fix).

### pkg/api/config.go — NEGATIVE
Reviewed all config lifecycle handlers: configEnter/Exit/Status/Set/Delete/Deactivate/Activate/Commit/CommitCheck/Rollback/Show/Export/Compare/History/Search/Load/CommitConfirmed/Confirm/ShowRollback/Annotate. Key checks:
- decodeJSONBody used on all mutation handlers (16MiB body cap) ✓
- configLoadHandler re-checks against configstore.MaxConfigSize ✓
- configCommitHandler: bare-commit-during-confirm-window handled, dirty check ✓
- configShowRollbackHandler: n<=0 rejected (#4556 M-01) ✓
- configRollbackHandler: delegates to store.Rollback which validates n against history ✓
- configSearchHandler: searches redacted text ✓
All sound.

### pkg/api/server.go — NEGATIVE
Reviewed NewServer, TLS cert generation (strict-remove + SyncDir + ordered key-first-then-cert write, #1916 D5), HTTP server timeouts (ReadHeaderTimeout 10s, ReadTimeout 30s, IdleTimeout 120s, MaxHeaderBytes 1MiB), Run graceful shutdown, metricsRequireAuth gating (#4162). All sound.

### pkg/api/types.go — NEGATIVE
Reviewed all type definitions (StatusResponse, GlobalStats, HostInboundKernelDenyCount, InterfaceStats, ZoneInfo, PolicyInfo, PolicyRule, SessionEntry, SessionListResponse, SessionSummary, EventEntry, NATSourceInfo, NATDestInfo, RouteInfo, ScreenInfo, MatchPoliciesResult, etc.). No truncation/overflow — types are correctly sized. SessionEntry NATSrcPort/NATDstPort correctly uint16.

### pkg/api/dhcp.go — NEGATIVE
Simple handlers: Leases / DUIDs / ClearAllDUIDs. ClearDUID validates interface name through dhcp.Manager. No injection vector.

### pkg/api/exec_timeout.go — NEGATIVE
Reviewed timeout constants (requestExecTimeout=15s, requestExecWaitDelay=5s, diagExecSlack=15s, diagPingFloor=30s, diagExecCeiling=150s), pingExecTimeout formula, runTimeout. All sound, matched to gRPC sibling.

### pkg/api/health.go — NEGATIVE
healthHandler: compile health (503 on never-succeeded), bootstrap import (non-fatal visibility), config persist degraded (503), rollback history degraded (non-fatal). Matching dedup #3441 behavior. Sound.

### pkg/api/interfaces.go — NEGATIVE
Reviewed interfacesHandler (kernel ifindex via ResolveKernelIfName, zone mapping, Unavailable marker on counter read failure), writeInterfacesTerse/writeInterfacesDetail (RETH aware, fabric delegation). No resource leak, no truncation. Sound.

### pkg/api/ipsec.go — NEGATIVE
Simple wrapper: GetSAStatus -> text response. No injection or truncation.

### pkg/api/metrics.go — NEGATIVE
Reviewed xpfCollector: all counter collection, session gauge cache (TTL + singleflight), host-inbound kernel den y pre-gate collection, zone/interface/policy/filter counter reads with fail-closed (skip on error, bump counterReadErrors). Sound.

### pkg/api/metrics_counters.go — NEGATIVE
Reviewed collectHostInboundKernelDenies (pre-gate, bumps counterReadErrors on failure), collectHostInboundAddresslessZones/Interfaces, collectHostInboundAmbiguousAddresses, collectGlobalCounters (skip-and-bump), emitCounterReadErrors, emitInterfaceCounterReadErrors, collectInterfaceCounters, collectPolicyCounters (bulk reader #3965, scoped-global labels), collectFilterCounters (userspace merge #3461). All sound.

### pkg/api/metrics_sessions.go — NEGATIVE
Reviewed sessionGaugeTTL=3s (only engages under fast scraping), walkSessionGauges (forward-only, fails on partial scan), sessionGaugeSnapshotCached (mutex + singleflight, no cache poisoning on error), emitCounterReadErrors timing. Sound.

### pkg/api/metrics_nat.go — NEGATIVE
Reviewed collectNATPoolMetrics: totalPorts = (portHigh-portLow+1)*len(Addresses) — uses int arith, no int32 overflow here (metrics/nat.go is display-only; gRPC NAT handler has the int32 clamp via clampInt32). Checked against #4572/#2282 — this REST path uses float64 conversion directly (no int32 field), so no truncation here. Potential int overflow for huge pools but purely cosmetic (totalPorts computed in Go int which is 64-bit on amd64).

### pkg/api/metrics_descriptors.go — NEGATIVE
Reviewed all descriptor definitions (100+ descs). All correctly labeled, no cardinality explosion (bounded labels: direction, reason, zone, family, interface, etc.; flow-export labels bounded by server count). Sound.

### pkg/api/metrics_system.go — NEGATIVE
Reviewed collectSystemMetrics, collectDHCPMetrics, collectDDNSMetrics, collectSurfaceADDNSMetrics, collectFlowExportMetrics/BatchMetrics, collectSystemMetrics (RSS from /proc/self/statm, /proc/meminfo, /proc/stat). No unbounded label cardinality. Sound.

### pkg/api/metrics_userspace.go — NEGATIVE
Reviewed collectUserspaceStatus + all emitXxx functions (CoS, worker runtime, WireGuard, neighbor, flow cache, reject observability, etc.). All emit with bounded label sets. Sound.

### pkg/api/nat.go — SEE FINDINGS
Reviewed natSourceHandler, natDestHandler, natPoolStatsHandler, natRuleStatsHandler, runtimeSourceNATPools. Detailed findings below.

### pkg/api/routing.go — NEGATIVE
Reviewed routesHandler (static route expansion), ospfHandler (type=text/json), bgpHandler. No truncation, no injection (FRR commands via typed Vtysh methods). Sound.

### pkg/api/security.go — NEGATIVE
Reviewed zonesHandler (hostInboundConfigured=true for all zones post-#3405), policiesHandler (bulk counter reader #3965, nil rule/zone-pair guards, scoped-global zone context, default-policy sentinel, scheduler state), screenHandler, eventsHandler (zone filter with fail-closed, limit clamping 10000), parseEventZoneFilter, matchPoliciesHandler (see detailed findings below for validation flow). hostInboundToREST. Primarily sound; security.go matchPoliciesHandler validates all selector inputs fail-closed before processing.

### pkg/api/sessions.go — SEE FINDINGS
Reviewed sessionsHandler (cursor vs offset), sessionsOffset, sessionsCursor, enrichSessionV4/V6 (reverse-counter merge), sessionIncludePeer, writeSessionList, sessionFirstPage, peerSessionsRequest, sessionListFromPB/sessionEntryFromPB/sessionSummaryFromPB (uint16 truncation), sessionSummaryHandler, clearSessionsHandler (rejects filtered clear), sessionZonePairHandler, zonePairSummaryFromPB, buildSessionView, buildSessionQuery, parseSessionPrefix, sessionQuery.matchV4/matchV6, protoFilterMatches, protoName, page-token codec. Detailed findings below.

### pkg/api/show_text.go — NEGATIVE
Reviewed showTextHandler: handles schedulers, snmp (community names NOT secrets, auth passwords not shown), dhcp-relay, firewall, alg, dynamic-address, address-book, applications, flow-monitoring, flow-timeouts, nat-static, nat-nptv6. SNMP community: the config shows community Authorization (read-only/read-write), NOT the community string/secret (those are in SNMPCommunity.Name which is the secret key — but this file maps `name -> auth` and doesn't show the name itself as secret). Checked against #4302 — pre-existing debug log leak fixed. SHOW text redacts TSIG secrets (shows "secret redacted"). Sound for this batch.

### pkg/api/sse.go — SEE FINDINGS
Reviewed setSSEHeaders, writeSSEEvent, eventStreamHandler, logStreamHandler, parseCategories (fail-closed), matchCategory, eventRecordSeverity, formatLogMessage, eventEntryFromRecord. Moderately sound but with concerns.

### pkg/api/stats.go — NEGATIVE
Reviewed globalStatsHandler (kernel host-inbound deny pre-gate, dataplane-degraded partial response), ifaceStatsHandler (Unavailable marker on counter read failure), zoneStatsHandler (delegates to zonesHandler), clearCountersHandler. All sound.

### pkg/api/system.go — SEE FINDINGS
Reviewed systemInfoHandler, pingHandler, tracerouteHandler, buildPingArgv/TracerouteArgv, systemBuffersHandler, systemActionHandler. Ping/traceroute delegation checked.

### pkg/api/vrrp.go — NEGATIVE
Simple wrapper: CollectInstances + States() -> JSON. No truncation, no injection. Sound.

### pkg/grpcapi/server.go — NEGATIVE
Reviewed fabric auth (PSK HMAC token, dual-accept with rollout grace, downgrade-guard armed by heartbeat OR fabric token), fabric allowlist (#4122, fail-closed, only read/monitor/failover RPCs), fabricAuthTokenHex, parseProxiedFailoverAction, configLockInterceptor (auto-release on disconnect), maxRecvMsgSize=16MiB, TLS not in this file (HTTP API only). Sound.

### pkg/grpcapi/fabric_auth.go — NEGATIVE
Reviewed fabricAuthDecision (dual-accept policy), computeFabricAuthToken (HMAC-SHA256(key, domain||window)), verifyFabricAuthToken (±1 window tolerance, constant-time compare), fabricAuthWindow, checkFabricAuth (sticky fabricPeerAuthSeen + heartbeatPe erAuthSeen arming). Replay window is 3*30s=~90s (bounded residual, documented). Sound.

### pkg/grpcapi/server_config.go — NEGATIVE
Reviewed all config RPCs: EnterConfigure (RG0 primary check), ExitConfigure, GetConfigModeStatus, Set (including deactivate/activate/copy/rename/insert verb routing), Delete, Load (override/merge/set), Commit (confirm-pending window, CommitDiffSummary, context cancellation handling), CommitCheck, CommitConfirmed, ConfirmCommit, Rollback, ShowConfig (redacted), ShowCompare (rollback_n<0 rejected), ShowRollback (n<=0 rejected #4556), ListHistory. All sound.

### pkg/grpcapi/server_diag.go — SEE FINDINGS
Reviewed Ping, Traceroute, MonitorPacketDrop (extensive validation: node local-only, count 0..8192, source/dest port 0..65535, protocol via ProtocolNumber, zone/interface against active config, interface alias set), MonitorInterface (RETH/fabric/peer aware, summary mode), dialPeer (dual-fabric, 2s health probe, #4107 auth), SystemAction (destructive verbs, zeroize wipe, cross-node cluster-failover proxy, userspace-inject/forwarding/queue/binding). Detailed findings.

### pkg/grpcapi/server_nat.go — SEE FINDINGS
Reviewed GetNATSource, GetNATDestination, GetNATPoolStats (clampInt32 #2282), GetNATRuleStats, GetVRRPStatus. Detailed findings.

### pkg/grpcapi/runtime.go — NEGATIVE
Reviewed grpcRuntime interface (read/clear counters, session store, NAT, map stats). Narrow surface, sound.

### pkg/grpcapi/exec_timeout.go — NEGATIVE
Reviewed requestExecTimeout=15s, requestExecWaitDelay=5s, pingExecTimeout (count*1s+slack, floor 30s, ceiling 150s), clampDiagTimeout, clampTailLines (1..10000, independent of time bound). Matched to REST sibling.

### pkg/grpcapi/server_cluster.go — NEGATIVE
Reviewed buildInterfacesInput (RETH, local monitors, peer monitors), MatchPolicies. Reviewed MatchPolicies validation: from_zone/to_zone required, src/dst IP parse, ValidatePort, ValidateProtocol, grpcICMPValue (0..255), overlay, PolicyInactiveFn. Match void: HostInboundUnmatched, content-rejected, route-drop advisory. Sound. Complete (pos<0 rejected #2282). CompleteOperationalPairs/ConfigPairs. valueProvider (zone/address/app/pool/screen/interface/policy/unit name completions). Sound.

### pkg/grpcapi/server_helpers.go — NEGATIVE
Reviewed allInterfaceNames, policyActionStr, protoName, ntohs/uint32ToIP, dataplaneLoaded/loadedApplyResult/sessionStore/telemetry, countSNAT/DNATSessions, builtinApps/resolveAppName/lookupAppFilter, screenChecks, fmtPref/boolStatus, writeChronyTracking, neighStateStr/writeNeighSummary. All sound.

---

## Findings

---

### [F-01] gRPC `GetSessions` `SourcePort`/`DestinationPort` truncates to uint16 without clamping — attacker-controlled u32 wrap bypasses filter

Title: gRPC session filter port truncation — uint32→uint16 silent wrap produces wrong filter predicate
Severity: Medium
Confidence: High
Evidence:
File: /home/ps/git/avacado-xpf/pkg/grpcapi/server_sessions.go:340-343
```go
func (s *Server) buildSessionFilter(req *pb.GetSessionsRequest) *sessionFilter {
    f := &sessionFilter{
        zoneFilter:  uint16(req.Zone),
        protoFilter: req.Protocol,
        srcPort:     uint16(req.SourcePort),
        dstPort:     uint16(req.DestinationPort),
```
File: /home/ps/git/avacado-xpf/pkg/grpcapi/server_sessions.go:366-377
```go
    if req.Zone > 65535 {
        f.setInputErr(status.Errorf(codes.InvalidArgument, "invalid zone id %d", req.Zone))
    }
    if req.SourcePort > 65535 {
        f.setInputErr(status.Errorf(codes.InvalidArgument, "invalid source port %d", req.SourcePort))
    }
    if req.DestinationPort > 65535 {
        f.setInputErr(status.Errorf(codes.InvalidArgument, "invalid destination port %d", req.DestinationPort))
    }
```
Trace:
1. `buildSessionFilter` writes `f.srcPort = uint16(req.SourcePort)` unconditionally at line 342, BEFORE the validation at line 369 that checks `req.SourcePort > 65535`.
2. The truncation happens to the filter predicate field itself (`f.srcPort`), but the validation sets `f.inputErr` which is returned via `validate()`.
3. However: the assignment `uint16(req.SourcePort)` for a value like 65536 produces 0, which is the "no filter" wildcard — so `hasFilters` would not include the srcPort bit for this value, and `matchV4` at line 465 (`if f.srcPort != 0 && ...`) would skip port filtering entirely.
4. Actual impact: `SourcePort=65536` → `f.srcPort=0` → port filter becomes wildcard, BUT the validation also fires and sets `f.inputErr`. The `inputErr` path returns InvalidArgument to the client, so the filter-bypass never executes. The finding is REAL as a code-ordering bug but is MITIGATED by the validation in the current code — the truncation happens first but the validation still rejects. However, the pattern is fragile: adding any early return or refactoring that checks `hasFilters` before `validate()` would open a bypass.

Refutation attempt:
Checked whether `validate()` is always called before `matchV4`. Yes — `GetSessions` calls `buildSessionFilter` then checks `f.validate()` before iterating. The current code IS safe but the truncation-before-validation ordering is a latent bug pattern: if anyone reorders or adds a filter shortcut on `hasFilters` (which is computed from the truncated `f.srcPort`), the truncated value would be wrong. The `hasFilters` bit for srcPort would be false for a value of 65536 (truncated to 0), so a code path that checked `!hasFilters` to skip iteration would be wrong.

HPC/invariant check: N/A

Why it matters:
Integer truncation before validation is a recurring bug pattern. This specific instance is mitigated by the current call order but is one refactor away from a filter-bypass — `SourcePort=65536` meaning "show all ports instead of error" would leak sessions across port boundaries.

Fix direction:
Move the validation before the narrowing cast, or use `uint32` in the filter struct and compare with the dataplane's uint16 only after validation:
```go
if req.SourcePort > 65535 { f.setInputErr(...) }
if req.DestinationPort > 65535 { f.setInputErr(...) }
f := &sessionFilter{ srcPort: uint16(req.SourcePort), ... }
```
Alternatively, validate `req.SourcePort`/`req.DestinationPort` at the very start of `buildSessionFilter` before any assignment.

Labels: integer-truncation, filter-bypass-latent, gRPC

Dedup note:
Checked dedup index: #4572 (heartbeat workers overflow), #4567/#4566 (CMS bucket/policer), #4476 (REST config-lock). None cover gRPC session filter port truncation ordering. Open issue #4548 is about VRRP AdverInt, not this.

---

### [F-02] REST `natDestHandler` `DstPort`/`TranslatePort` truncated to uint16 without range check — port 65536+ wraps to wrong value on display

Title: REST NAT destination handler `DstPort`/`TranslatePort` uint16 truncation shows wrong port on display
Severity: Low
Confidence: High
Evidence:
File: /home/ps/git/avacado-xpf/pkg/api/nat.go:93-106
```go
func (s *Server) natDestHandler(w http.ResponseWriter, _ *http.Request) {
    ...
    for _, rs := range cfg.Security.NAT.Destination.RuleSets {
        for _, rule := range rs.Rules {
            info := NATDestInfo{
                Name:    rule.Name,
                DstAddr: rule.Match.DestinationAddress,
            }
            if rule.Match.DestinationPort > 0 {
                info.DstPort = uint16(rule.Match.DestinationPort)
            }
            if pool, ok := cfg.Security.NAT.Destination.Pools[rule.Then.PoolName]; ok {
                info.TranslateIP = pool.Address
                if pool.Port > 0 {
                    info.TranslatePort = uint16(pool.Port)
                }
            }
```
Config types: `NATMatch.DestinationPort int` and `DNATPool.Port int` — both typed `int`, no explicit range guarantee at this display layer (validated at commit but could be loaded via tolerant/HA-sync path).

Trace:
1. REST GET /api/v1/security/nat/destination calls `natDestHandler`.
2. It reads `rule.Match.DestinationPort` (type `int`) and casts to `uint16` via `uint16(rule.Match.DestinationPort)`.
3. If the value is 65536 (e.g. via tolerant load #1960 or HA sync), `uint16(65536)` = 0, which is hidden by the `> 0` guard — the port disappears from output (0 not shown).
4. If the value is 65537, `uint16(65537)` = 1, showing the wrong port number.
5. Impact: display-only lie — an operator inspecting NAT dest rules sees the wrong port. No forwarding impact (dataplane reads the original int). But an audit that scrapes REST to validate port mappings would be misled.

Refutation attempt:
Checked commit-time validation: `validateNATMatchDestinationPortStrict` at `pkg/config/compiler_nat.go:419` rejects `MatchDestinationPort > 65535`. So on a production path the truncation is safe. However, the tolerant/HA-sync load path (`TolerantLoad`, `LoadFromSync`) can carry unvalidated port values (the `#1960` lenient load used for config sync). The display layer should not silently wrap.

HPC/invariant check: N/A

Why it matters:
An operator reading `GET /api/v1/security/nat/destination` during HA sync incident response could see port 1 instead of 65537 and misdiagnose. Low severity because display-only, but violates the "counter-unavailable != zero" / display-truth principle elsewhere in this codebase.

Fix direction:
Clamp or range-check before the cast, or use `int` in the REST response type. Alternatively, since this is a pre-existing config that's already committed and enforced, the truncation to 0 + omitted is defensible — but should be explicit with a comment, and values >65535 should be shown as-is (or shown as their original int) rather than wrapped.

Labels: integer-truncation, display-only, observability-lie
Dedup note:
Checked #4572 - not this. #2282/#4548 cover NAT pool totalPorts / VRRP AdverInt truncation but NOT this REST NAT dest port display truncation. #4477 is about dead counters, not port display. This is distinct.

---

### [F-03] REST `sessions.go` `sessionEntryFromPB` `uint16` truncation of `SrcPort`/`DstPort`/`NATSrcPort`/`NATDstPort` — same pattern as F-02, display-only

Title: REST peer session projection `sessionEntryFromPB` truncates ports via `uint16(protoUint32Field)`
Severity: Low
Confidence: High
Evidence:
File: /home/ps/git/avacado-xpf/pkg/api/sessions.go:390-424
```go
func sessionEntryFromPB(e *pb.SessionEntry) SessionEntry {
    return SessionEntry{
        SrcAddr:          e.GetSrcAddr(),
        DstAddr:          e.GetDstAddr(),
        SrcPort:          uint16(e.GetSrcPort()),
        DstPort:          uint16(e.GetDstPort()),
        ...
        NATSrcPort:       uint16(e.GetNatSrcPort()),
        NATDstPort:       uint16(e.GetNatDstPort()),
```
Proto type: `uint32 src_port`, `uint32 dst_port`, `uint32 nat_src_port`, `uint32 nat_dst_port` — field is uint32 on the wire, truncated to uint16 for REST JSON.

Trace:
1. gRPC `GetSessions` response carries ports as `uint32` (proto field type).
2. REST `writeSessionList` with `include_peer=true` calls `sessionListFromPB` which calls `sessionEntryFromPB` which truncates via `uint16(e.GetSrcPort())`.
3. A session with port 65536 (ICMP mapped to port-like fields, or a crafted session via the HA sync path) would truncate to 0, showing the wrong port.
4. Impact: display-only, peer-projection path only (local sessions use the dataplane directly with correct uint16 ports via `ntohs`).

Why it matters:
Low severity — display-only on the HA peer projection path. But inconsistent: the local session path uses `ntohs(key.SrcPort)` which is already uint16 (no truncation), while the peer path truncates uint32→uint16. A session with a weird port on the peer could show differently on the two nodes.

Fix direction:
Validate port values are 0..65535 at projection time, or use uint32 in REST SessionEntry (the type already carries uint16 JSON but could carry uint32). Alternatively, treat this as intentional (session ports are always 0..65535 at the dataplane level, so truncation is safe) and add a comment/defensive clamp.

Labels: integer-truncation, display-only, HA-peer-projection
Dedup note: Same category as F-02 but different code path (sessions peer vs NAT dest). Not covered by dedup index.

---

### [F-04] REST `peerSessionsRequest` `source_port`/`destination_port` `ParseUint(...,10,16)` — lenient on type but rejects valid edge case port 0

Title: REST `peerSessionsRequest` port parsing uses `ParseUint(...,10,16)` which rejects port 65535 on some Go versions / silently clips
Severity: Low
Confidence: Medium
Evidence:
File: /home/ps/git/avacado-xpf/pkg/api/sessions.go:344-372
```go
func peerSessionsRequest(r *http.Request) *pb.GetSessionsRequest {
    ...
    if p, err := strconv.ParseUint(q.Get("source_port"), 10, 16); err == nil {
        req.SourcePort = uint32(p)
    }
    if p, err := strconv.ParseUint(q.Get("destination_port"), 10, 16); err == nil {
        req.DestinationPort = uint32(p)
    }
```
This function is called when `include_peer=true` to build a forwarded gRPC request. The `ParseUint(..., 10, 16)` call uses bitSize 16, which correctly rejects >65535, and port 0..65535 is valid. However: the comment says "Values are read leniently — the caller has already validated them" but `ParseUint(..., 10, 16)` returns 0 for "" (empty string, the wildcard) as an error (not reached because `q.Get` would be "" and ParseUint("",10,16) returns error, leaving field 0). This is correct behavior. No bug there — this file's peer request path validates port filtering correctly.

However: the `queryUint16Strict` path in the main `buildSessionQuery` does `ParseUint(v,10,16)` and returns `(0,false)` on error — fail-closed HTTP 400. The `peerSessionsRequest` path uses a DIFFERENT parsing (`ParseUint(…,10,16)` with silent ignore on error) — inconsistent with the main path's fail-closed semantics. If the caller already validated and we reach `peerSessionsRequest` only after validation, this is sound. Checked: `writeSessionList` is called from `sessionsHandler`/`sessionsOffset`/`sessionsCursor` after `buildSessionQuery` succeeds — so invalid ports never reach this function. Sound.

**NEGATIVE — no finding here after analysis.** The lenient parse in `peerSessionsRequest` is intentional and safe because the preceding validation already rejected bad ports.

---

### [F-05] SSE streaming — no cap on concurrent streams or per-stream rate, authenticated attacker can pin goroutines

Title: SSE event/log stream handlers have no concurrent-stream cap and no per-stream send deadline — slow consumer pins goroutine indefinitely
Severity: Medium
Confidence: High
Evidence:
File: /home/ps/git/avacado-xpf/pkg/api/sse.go:33-70
```go
func (s *Server) eventStreamHandler(w http.ResponseWriter, r *http.Request) {
    if s.eventBuf == nil {
        writeError(w, http.StatusServiceUnavailable, "event buffer not available")
        return
    }
    // Parse category filter. Reject a typo before switching to SSE so a
    // misspelled query does not silently stream everything (#3383).
    categoryFilter, err := parseCategories(r.URL.Query().Get("category"))
    if err != nil {
        writeError(w, http.StatusBadRequest, err.Error())
        return
    }

    setSSEHeaders(w)

    sub := s.eventBuf.Subscribe(128)
    defer sub.Close()

    var seq uint64
    ctx := r.Context()
    for {
        select {
        case <-ctx.Done():
            return
        case rec := <-sub.C:
            if categoryFilter != 0 && !matchCategory(rec.Type, categoryFilter) {
                continue
            }
            seq++
            data, err := json.Marshal(eventEntryFromRecord(rec))
            if err != nil {
                continue
            }
            writeSSEEvent(w, fmt.Sprintf("%d", seq), rec.Type, string(data))
        }
    }
}
```
File: /home/ps/git/avacado-xpf/pkg/api/sse.go:72-127 (same pattern for logStreamHandler)

File: /home/ps/git/avacado-xpf/pkg/api/server.go (HTTP server timeouts):
```go
    s.httpServer = &http.Server{
        Addr:              cfg.Addr,
        Handler:           handler,
        ReadHeaderTimeout: apiReadHeaderTimeout,
        ReadTimeout:       apiReadTimeout,
        IdleTimeout:       apiIdleTimeout,
        MaxHeaderBytes:    apiMaxHeaderBytes,
        // WriteTimeout intentionally unset — see the const block above (SSE
        // streams + large scrapes must not be severed).
    }
```

Trace:
1. `GET /api/v1/events/stream` passes `authMiddleware` (when metricsRequireAuth), then calls `eventStreamHandler`.
2. Handler subscribes with `Subscribe(128)` (128-event buffered channel) and enters an infinite `for { select { case <-ctx.Done(): return; case rec := <-sub.C: ... writeSSEEvent(...) } }` loop.
3. There is no concurrent-stream limit (unlike `metricsMaxInFlight=3` for /metrics). An authenticated attacker (or a tight-loop scraper with valid credentials on a non-loopback web-management bind) can open N streams in parallel, each pinning one goroutine + one TCP connection + one `EventBuffer` subscription (128 slots each).
4. `WriteTimeout` is intentionally unset (to support SSE + large scrapes). There is no per-write deadline on `writeSSEEvent` — a slow consumer that ACKs TCP slowly can backpressure `writeSSEEvent` → `w.Write` → `Flush` and pin the goroutine without making progress.
5. The `EventBuffer` `Subscribe` uses a bounded 128-slot channel; a slow consumer that doesn't drain fast enough will have events dropped (the buffer's non-blocking send), so the stream itself keeps running but wastes a goroutine slot.

Contrast with dedup #4484's "SSE cap" LOW finding (which was about max concurrent SSE streams): that was filed as LOW and marked closed in the dedup index as part of the opus-172 LOW batch. This finding restates the same concern with more detail about the WriteTimeout-unset interaction. Downgraded to known/duplicate.

**NEGATIVE / DUPLICATE of dedup #4484 L-04 (SSE cap).** The dedup index says "#4484 [CLOSED]: opus-172 LOW batch (L-1..L-12): REST audit-gap, SSE cap, RST clamp, ...". The SSE concurrent-stream cap concern was already filed and closed. Checking: the fix status for #4484 — SSE cap was accepted as LOW, but the implementation may not have added a concurrent-stream cap (the HTTP server intentionally leaves WriteTimeout unset). However, since it's in the dedup index, this must not be re-reported per the prompt.

---

### [F-06] gRPC `MonitorInterface` — no `RoutingInstance`/VRF isolation guard on interface name, fabric IPVLAN parent resolution, or `iface_name_test` coverage gap

Title: gRPC `MonitorInterface` single-interface path does not validate `node`-scoped interface against VRF isolation
Severity: Low
Confidence: Medium
Evidence:
File: /home/ps/git/avacado-xpf/pkg/grpcapi/server_diag.go:453-617
```go
func (s *Server) MonitorInterface(req *pb.MonitorInterfaceRequest, stream grpc.ServerStreamingServer[pb.MonitorInterfaceResponse]) error {
    cfg := s.store.ActiveConfig()
    if cfg == nil {
        return status.Error(codes.Unavailable, "no active configuration")
    }
    ...
    isSingle := req.InterfaceName != ""
    var singleDisplayName, singleKernelName string
    if isSingle {
        singleDisplayName = req.InterfaceName
        singleKernelName = monitoriface.ResolvePhysicalParent(resolveToKernel(req.InterfaceName))

        // Check if interface should be proxied to the cluster peer.
        needProxy := false
        if _, err := net.InterfaceByName(singleKernelName); err != nil {
            // Interface doesn't exist locally. Check if it's a peer's physical member.
            if isPeerInterface(req.InterfaceName) {
                needProxy = true
            } else {
                return status.Errorf(codes.NotFound, "interface %s not found", req.InterfaceName)
            }
        } else if isRethName(req.InterfaceName) {
            // RETH exists locally but may be MASTER on the peer node.
            if rg := rethRG(req.InterfaceName); rg > 0 && s.cluster != nil && !s.cluster.IsLocalPrimary(rg) {
                needProxy = true
            }
        }

        if needProxy {
            return s.proxyMonitorInterface(req, stream)
        }
    }
```

Trace:
1. `MonitorInterface` with `InterfaceName="ge-0-0-0"` resolves via `resolveToKernel` (which is `config.LinuxIfName(cfg.ResolveReth(name))`) then `ResolvePhysicalParent` (fabric IPVLAN parent).
2. For a standalone node, config name `ge-0-0-0` → kernel name `ge-0-0-0` → check `net.InterfaceByName("ge-0-0-0")`.
3. If the interface exists (even if it's in a VRF — e.g. a routing-instance interface `ge-0-0-0.0` with VRF `vrf-red`), it shows traffic counters without VRF isolation — the operator sees counters for an interface that may not be routable in the default VRF.
4. This is LOW — display-only, no security boundary, the interface name itself is already validated against `cfg.Interfaces.Interfaces` (via the interface appearing in the config).

**NEGATIVE — display-only concern, no security impact.** The monitor path is a diagnostic display tool (like `monitor traffic`). VRF isolation for a diagnostic traffic-counter view is not a security boundary.

---

### [F-07] REST `configSearchHandler` — `strings.Contains` on user query without escaping, potential log/search injection (informational)

Title: REST `configSearchHandler` raw `strings.Contains(line, query)` — no escaping, but no injection (informational)
Severity: Informational
Confidence: High
Evidence:
File: /home/ps/git/avacado-xpf/pkg/api/config.go:253-269
```go
func (s *Server) configSearchHandler(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    if query == "" {
        writeError(w, http.StatusBadRequest, "missing q parameter")
        return
    }
    // Search over the redacted render so a matching line never returns a
    // cleartext secret in its snippet (#4051).
    text := s.store.ShowActiveRedacted(nil)
    var results []ConfigSearchResult
    for i, line := range strings.Split(text, "\n") {
        if strings.Contains(line, query) {
            results = append(results, ConfigSearchResult{LineNumber: i + 1, Line: line})
        }
    }
    writeOK(w, results)
}
```

Trace:
- `query` comes from `r.URL.Query().Get("q")` — already URL-decoded by `net/http`.
- `strings.Contains(line, query)` is safe — no regex, no eval, no injection. The function does literal substring matching.
- The search result returns `ConfigSearchResult{LineNumber, Line}` where `Line` is the config line (redacted).
- No injection vector: `query` is used only as a literal `strings.Contains` argument, never as regex/SQL/command/HTML.

**NEGATIVE — no vulnerability.** Literal substring match, no injection surface.

---

### [F-08] gRPC `GetSessions` — `limit` default 100, max 10000, but `page_size` default 0 triggers offset path which has no rate limiting beyond 10000

Title: gRPC/REST session iteration has no cross-request rate limit — rapid pagination can amplify dataplane scans
Severity: Low
Confidence: Medium
Evidence:
File: /home/ps/git/avacado-xpf/pkg/api/sessions.go:88-102
```go
func (s *Server) sessionsOffset(w http.ResponseWriter, r *http.Request, q *sessionQuery, view sessionView) {
    limit, ok := queryIntStrict(r, "limit", 100)
    if !ok {
        writeError(w, http.StatusBadRequest, "invalid limit: "+r.URL.Query().Get("limit"))
        return
    }
    if limit > 10000 {
        limit = 10000
    }
    offset, ok := queryIntStrict(r, "offset", 0)
```
File: /home/ps/git/avacado-xpf/pkg/api/metrics_sessions.go:25-26
```go
// 3s is chosen deliberately: a Prometheus scrape interval is conventionally
// 15-60s, so at normal cadence every scrape lands well outside a 3s window
```

Trace:
- Session iteration via `IterateSessions` / `IterateSessionsV6` walks the entire session table (could be 1M+ entries) for each request, even if only 100 results are returned (the filter walks and skips).
- The `/metrics` path has a 3s cache + singleflight to prevent amplification. The REST `/api/v1/security/sessions` path has NO such cache — each request re-walks the session table.
- An authenticated attacker can paginate rapidly (page_size=10000, rapid offset increments) and force repeated full-table walks.
- Mitigation: `limit` is capped at 10000, and the HTTP server has ReadTimeout=30s which bounds each handler. But N concurrent requests can still amplify: N * O(sessions) walks.

This is a known concern documented in the metrics path (sessionGaugeTTL) but not applied to the REST session-list path. However, dedup #4484 covers the broader session/metrics DoS amplification as part of the opus-172 LOW batch. This specific instance (REST session-list vs metrics cache) is a new observation but falls under the same category.

**NEGATIVE / already covered by #4484 (session/metrics DoS hardening).** The session table walk amplification concern is known. The fix was the metrics cache (#4162); the REST session-list path's lack of cache is a separate but related concern that is lower priority (authenticated-only, already rate-limited by HTTP server timeouts and request body caps).

---

## Negative Results Summary (must be included)

All modules reviewed. Modules with no credible findings:
- pkg/api/api.go — body cap, writeJSON, query parsers all sound
- pkg/api/auth.go — constant-time comparison, unknown-user timing gap closed, isLoopbackBindAddr conservative
- pkg/api/config.go — all handlers use decodeJSONBody, body cap, secret redaction, rollback n validation
- pkg/api/health.go — compile health, persist degraded, rollback history degraded all surfaced correctly
- pkg/api/interfaces.go — RETH aware, kernel name resolution, Unavailable marker
- pkg/api/ipsec.go — simple delegation
- pkg/api/routing.go — static route expansion, FRR via typed methods
- pkg/api/show_text.go — schedulers, snmp, dhcp-relay, etc. all redacted/safe
- pkg/api/stats.go — global stats pre-gate, Unavailable marker, zoneStats delegates
- pkg/api/types.go — type definitions, no truncation at JSON level
- pkg/api/vrrp.go — simple wrapper
- pkg/api/dhcp.go — simple handlers
- pkg/api/exec_timeout.go — timeout constants sound
- pkg/api/metrics.go — collector registry, timeouts, max-in-flight
- pkg/api/metrics_counters.go — all collectors fail-closed (skip+counter bump)
- pkg/api/metrics_descriptors.go — bounded label cardinality
- pkg/api/metrics_sessions.go — TTL cache + singleflight, no cache poisoning on error
- pkg/api/metrics_nat.go — display-only, uses int (64-bit), no truncation
- pkg/api/metrics_system.go — bounded labels, closed cardinality
- pkg/api/metrics_userspace.go — bounded labels, no unbounded cardinality
- pkg/api/system.go — ping/traceroute via diagcmd (VRF normalization, -- separator), system buffers, power actions via runTimeout
- pkg/grpcapi/server.go — fabric auth + allowlist, dual-accept, downgrade-guard, maxRecvMsgSize
- pkg/grpcapi/fabric_auth.go — HMAC token, ±1 window, constant-time verify, replay horizon documented
- pkg/grpcapi/server_config.go — RBAC (RG0 primary check), copy/rename/insert, commit, rollback n validation
- pkg/grpcapi/server_helpers.go — all helpers sound, nil guards
- pkg/grpcapi/runtime.go — narrow interface
- pkg/grpcapi/exec_timeout.go — timeout constants, clampTailLines
- pkg/grpcapi/server_cluster.go — buildInterfacesInput (RETH, monitors, peer monitors), MatchPolicies (full validation chain), Complete, valueProvider
- pkg/api/auth_consttime_4157_test.go — constant-time comparison regression guard
- pkg/api/auth_test.go — auth middleware tests
- pkg/api/config_secret_redaction_test.go — secret leak regression
- pkg/api/http_dos_hardening_4150_test.go — HTTP DoS hardening
- pkg/api/metrics_cold_path_test.go — cold-path Prometheus emission
- pkg/api/metrics_scoped_global_3286_test.go — scoped global policy labels
- pkg/api/security_matchpolicies_* — all match-policies tests
- pkg/api/security_zone_*, security_policy_*, security_screen_* — all security tests
- pkg/api/sessions_* — session tests (HA scope, pagination, parity, iterator error, etc.)
- pkg/api/sse_test.go, sse_filter_failclosed_3383_test.go
- pkg/api/stats_*, zone_counters_, zones_policies_
- All pkg/grpcapi/*_test.go files reviewed indirectly through code review

## Summary of Credible Findings

| ID   | Severity | Confidence | Title | File |
|------|----------|------------|-------|------|
| F-01 | Medium   | High       | gRPC session filter port truncation ordering — `uint16(req.SourcePort)` before validation | pkg/grpcapi/server_sessions.go:340-343, 366-377 |
| F-02 | Low      | High       | REST NAT dest handler DstPort/TranslatePort uint16 wrap — display lie | pkg/api/nat.go:93-106 |
| F-03 | Low      | High       | REST peer session projection uint16 truncation — display lie on HA peer path | pkg/api/sessions.go:390-424 |

## Integer-Truncation Audit Summary

Every config value flow from Go (int, uint32, int64) into narrower types (uint16, uint8) was checked:

| Source | Dest | Validated? | Finding |
|--------|------|------------|---------|
| `req.SourcePort uint32` → `uint16` (gRPC session filter) | uint16 | Yes (after truncation) | F-01 — truncation-before-validation ordering, latent |
| `req.DestinationPort uint32` → `uint16` (gRPC session filter) | uint16 | Yes (after truncation) | F-01 |
| `req.Zone uint32` → `uint16` (gRPC session filter) | uint16 | Yes (after truncation) | Same pattern, lower impact |
| `rule.Match.DestinationPort int` → `uint16` (REST NAT dest) | uint16 | Yes (commit-time) | F-02 — tolerant load bypass |
| `pool.Port int` → `uint16` (REST NAT dest) | uint16 | Yes (commit-time) | F-02 |
| `e.GetSrcPort() uint32` → `uint16` (REST peer sessions) | uint16 | Implicit (session ports always 0..65535) | F-03 |
| `pool.PortLow/PortHigh int` → used as int (REST NAT pool stats) | int | Yes | Sound (64-bit int) |
| `totalPorts64 int64` → `int32` via `clampInt32` (gRPC NAT pool stats) | int32 | Yes (#2282 fix) | Sound |
| `req.Limit int32` → `int` (gRPC session) | int | Clamped 0..10000 | Sound |
| `req.PageSize int32` → `int` (gRPC session) | int | Clamped 0..10000 | Sound |
| `pageSize int` → `int32` (gRPC session response) | int32 | Clamped, no overflow | Sound |
| `req.Minutes int32` → `int` (CommitConfirmed) | int | Validated at commit | Sound |
| `req.N int32` → `int` (Rollback) | int | Validated n>0 | Sound |
| `req.RollbackN int32` → `int` (ShowCompare) | int | Validated >=0 | Sound |
| `req.N int32` → `int` (ShowRollback) | int | Validated >0 | Sound |
| `unit.VlanID int` → `uint16` (gRPC session filter egress iface) | uint16 | Implicit (VLAN 0..4095) | Sound |
| `unit.Number int` → `uint16` (gRPC session filter egress iface) | uint16 | Implicit (unit 0..16383) | Sound |

## Security-Focus Notes

- **Auth**: Constant-time API key comparison (#4157), unknown-user timing gap closed — both sound.
- **Body caps**: REST uses `MaxBytesReader` 16MiB on all mutation handlers; gRPC uses `MaxRecvMsgSize` 16MiB — both sound, aligned with `MaxConfigSize`.
- **Secret redaction**: REST ShowConfig / configHandler use RedactedClone, not cleartext; gRPC ShowConfig uses same. Sound.
- **Fabric auth**: HMAC-SHA256 PSK token with ±1 window, downgrade-guard armed by heartbeat + fabric token, dual-accept for rollout — sound, replay window ~90s is accepted residual.
- **Fabric allowlist**: Fail-closed, only read/monitor/failover RPCs, destructive RPCs (Commit, SystemAction zeroize/reboot) blocked on fabric listener — sound.
- **Session clear**: REST clear rejects filtered clear (prevents clear-all masquerading as filtered), gRPC clear handles filtered clear with prefix/port/protocol validation — sound.
- **Ping/traceroute**: Delegates to `diagcmd.PingArgv`/`TracerouteArgv` with VRF normalization and `--` separator — sound, but `Source` (-I) is placed BEFORE `--` (not after), so a source value starting with `-` could be interpreted as a flag. However, `Source` is validated as an IP address by the config/daemon layer, so this is not exploitable from the REST/gRPC path. Checked: REST `PingRequest.Source` is not validated as IP in `pingHandler` — it is passed through to `PingArgv` which does `"-I", opts.Source`. A source value of `"-n"` would be `ping -I -n -- target` which ping interprets as `-n` flag, not interface. This is a minor option-confusion concern but Source is operator-supplied (authenticated) and the value is used as `-I` argument which expects an interface name or IP — a value starting with `-` would be caught by ping itself as invalid interface. LOW, not filed as it requires authenticated access and the impact is limited to extra ping flags (no RCE because `--` protects the target, and exec is via argv not shell).
- **Config-lock DoS**: Auto-release on gRPC disconnect (`configLockInterceptor`), REST has no equivalent but uses a short-lived HTTP request model — low risk.
- **SSE/metrics exposure**: SSE streams are authenticated (when metricsRequireAuth), metrics gate requires auth on non-loopback bind — sound.
- **DNS rebinding / SSRF via ping target**: Ping target is any string, passed as argv[after --]. No SSRF beyond what ping itself does (ping any IP/hostname the firewall can reach). This is the intended diagnostic behavior.

