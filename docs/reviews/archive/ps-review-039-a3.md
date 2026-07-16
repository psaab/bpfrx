# 039 — Go config compilers + schema + validation monoliths

**Batch:** A3 — Go config compilers + schema + validation  
**Base:** f70146951583823a5ace87b0b11a2e58f46e8db9  
**Date:** 2026-07-08  
**Auditor:** ps (claude-spark)  
**Scope:** `pkg/config/compiler*.go`, `pkg/config/types_system.go`, `pkg/config/schema_*.go` (all non-test, non-gen, >1000 LOC)

---

## File-size / shape inventory

| File | LOC | funcs | types | Largest func (LOC) | Responsibilities (est.) |
|------|-----|-------|-------|--------------------|------------------------|
| `compiler_validate_warn.go` | 3330 | 35 | 0 | `ValidateConfig` 1559 | ~12 (NAT alarms, deterministic NAT, zone/parity, address-book, screen, policy log, junos-host, filter, DDNS, routing, CoS, DHCP relay, sampling, host-inbound) |
| `compiler_nat.go` | 2529 | 37 | 1 | `compileNATSource` ~500 (pool+alarm+deterministic+rule expansion) | 4+7 helpers (helpers/predicates, 4 strict gates, 4 compile entry points, 10+ parse/expand helpers) |
| `compiler.go` | 2110 | 8 | 1 (`compileOpts` with 70+ bool fields) | `CompileConfigLenient` ~100 (opts literal), `compileConfigWithOpts` ~75, `compileConfigForNodeWithOpts` ~60 | 3 (strict/lenient entry points, `compileOpts` god-struct definition, `compileExpanded` orchestrator now thin after #4406) |
| `compiler_system.go` | 1881 | 27 | 0 | `compileSystem` 536, `compileChassis` 300 | 8+ (system leaf parsing, DDNS catalog, dataplane-typed dispatch, userspace tunables, syslog host/file/user, SNMP community/trap-group/v3, login RBAC, chassis/cluster/RG, schedulers, archival, MUEM artifact, advisory warnings) |
| `compiler_services.go` | 1821 | 27 | 0 | `compileDHCPRelay` 149, `compileDHCPLocalServer` 126, `compileRPM` 122, `compileSamplingFamily` 121 | ~10 (RPM probe/test validation×5, DHCP local-server, DHCP DDNS, DHCP expired-leases, dynamic-address, services dispatch, ip-monitoring/overlay, flow-monitoring, forwarding-options sampling/port-mirroring, DHCP relay, event-options, bridge-domains) |
| `compiler_validate_strict_filter.go` | 1660 | 28 | 0 | `validateFilterAddressExceptStrict` ~140, `validateFilterFromMatchStrict` ~120 | 1 domain (firewall filter) but 15+ independent gates |
| `compiler_uniformgates.go` | 1659 | 1 | 0 | `runUniformGates` 1659 | 1 (orchestrator) but ~75 distinct validation gates inlined sequentially |
| `types_system.go` | 1544 | 15 | 64 | `mapJunosPermissions` ~70 | 7+ (SystemConfig, UserspaceConfig, SNMP/MIB, Login RBAC, DHCP server/lease, Services/RPM/IP-monitoring, Flow/Sampling, Firewall/Policer/Filter — firewall types do not belong in "system") |
| `compiler_interfaces.go` | 1279 | 14 | 0 | `compileInterfaces` 535, `parseVRRPGroups` 237 | 5 (interface/VLAN/MTU/speed/encap/LAG/RETH/fabric, tunnel, WireGuard multi-peer, VRRP groups+AST validation+track shape, MSS selection, per-iface DDNS binding) |
| `compiler_routing.go` | 1226 | (not in top-9) | — | — | — |
| `compiler_firewall.go` | 1206 | — | — | — | — |
| `compiler_class_of_service.go` | 1205 | — | — | — | — |
| `compiler_protocols.go` | 1180 | — | — | — | — |
| `types_security.go` | 1202 | — | — | — | — |
| `schema_security.go` | 1255 | — | — | schema only | — |
| `schema_system.go` | 1021 | — | — | schema only | — |

Post-#4405 / #4406 splits already landed:
`compiler_validate_strict.go` (478 LOC remainder) + 10 per-domain files (`_application.go`, `_chassis.go`, `_cos.go`, `_ipsec.go`, `_nat.go`, `_observability.go`, `_policy.go`, `_routing.go`, `_screen.go`, `_vrrp.go`, `_zones.go`, `_filter.go`) = former 6997 LOC god-file decomposed.  
`compiler.go` `compileExpanded` decomposed into `compiler_prewalk.go`, `compiler_dispatch.go`, `compiler_derivations.go`, `compiler_earlystrict.go`, `compiler_uniformgates.go`, `compiler_tailgates.go` — `compileExpanded` now 7 calls.

---

## Finding 1 — `compiler_validate_warn.go` 3330 LOC — warning monolith (A)

**Severity:** Medium  
**Confidence:** High  
**Refactor class:** (A) MECHANICAL / SAFE — cold path, pure file-move

**Evidence:**

- 3330 LOC, 35 funcs, 0 types. Single largest func `ValidateConfig` 1559 LOC (47% of file), branches across 12+ config domains.
- Function list spans unrelated subsystems: `deterministicIPv4Enforced`, `sortedPoolNames`, `ValidateConfig`, `validateHostInboundMulticastWarnings`, `validateDHCPRelayParityWarnings`, `validateInterfaceParityWarnings`, `validateDefaultPolicyLogWarnings`, `validatePolicyLogInertOnDenyWarnings`, `junosHostPolicySourceScoped`, `validateJunosHostDirectDeliveryWarnings`, `validateFilterLossPriorityWarnings`, `validateFirewallInterfaceSpecificWarnings`, `validateLo0FilterKernelMirrorWarnings`, `validateFilterNoCatchAllWarnings`, `validateDDNSBackendWarnings`, `validateSurfaceADDNSWarnings`, `validateRoutingRuleWindowWarnings`, `validateRibGroupLeakWarnings`, `validateCoSOversubscriptionWarnings`, `classOfServiceClassifierQueueWarnings`, …

Quote — `ValidateConfig` mixes login auth, zone bookkeeping, app port validation, policy zone refs, NAT zone refs, screen refs, host-inbound full-admit, address-book CIDR, all in one function:

```go
func ValidateConfig(cfg *Config) []string {
    var warnings []string
    if cfg.Services.ApplicationIdentification {
        warnings = append(warnings,
            "services application-identification is enabled, but xpf "+
                "AppID is port+protocol catalog matching only — no L7 "+
                "DPI / signature engine. ...")
    }
    if userspaceSynCookieProtectionActive(cfg) &&
        (cfg.System.RootAuthentication == nil ||
            cfg.System.RootAuthentication.EncryptedPassword == "") {
        warnings = append(warnings,
            "active userspace-dp SYN-cookie screen profiles require "+
                "system root-authentication encrypted-password material ...")
    }
    if cfg.System.Login != nil {
        for _, u := range cfg.System.Login.Users {
            ...
        }
    }
    // Collect valid zone names
    zones := make(map[string]bool)
    ...
    // Validate policies ... NAT zone references ...
    // Validate screen references in zones ...
    // #3226: `system-services all` / `any-service` is a packet-wide ...
    fullAdmitAdvice := func(where string, svcs []string) {
```

Seam: `ValidateConfig` does (a) operator-facing advice generation, (b) cross-reference resolution (`zones`, `addrs` map builds), and (c) per-domain semantic checks — three responsibilities in one 1559-line function.

**Proposed decomposition:**

```
compiler_validate_warn.go              (keep ValidateConfig skeleton, ~80 LOC dispatch)
compiler_validate_warn_nat.go          (deterministicIPv4Enforced, sortedPoolNames, NAT alarm helpers)
compiler_validate_warn_security.go     (policy log, default-policy, junos-host, zone/screen, host-inbound full-admit)
compiler_validate_warn_forwarding.go   (firewall filter CoS/warn, lo0 mirror, interface parity, DHCP relay parity)
compiler_validate_warn_ddns.go         (validateDDNSBackendWarnings, ddns* helpers, validateSurfaceADDNSWarnings)
compiler_validate_warn_routing.go      (validateRoutingRuleWindowWarnings, validateRibGroupLeakWarnings)
compiler_validate_warn_cos.go          (validateCoSOversubscriptionWarnings, classOfServiceClassifierQueueWarnings, schedulerHasEffectiveWindow, firewallFilterHasCatchAllTerminator …)
```

Each new file: `package config`, takes `*Config`, returns `[]string`, no new imports. Helpers `hasFamily`, `anySamplingDirectionConfigured`, `firewallFilterHasCatchAllTerminator`, etc. travel with their domain.

**Shared private types / consts:** None — all helpers are pure `func(cfg *Config) []string` or tiny predicates. No package-private type shared across domains.

**Hot-path preservation:** (A) SAFE — `ValidateConfig` is called only from `runTailGates` (P7), which runs on `CompileConfig` / commit path. Not reachable from per-packet path. Mechanical file-move, no logic change.

**Tests + gate:** `go test ./pkg/config -run TestValidate` — byte-identical warnings. Verify sorted top-level decl-NAME set unchanged per #4144: `go list -f '{{.GoFiles}}' | xargs grep -h '^func ' | sort` before/after identical.

**Why it matters:** 3330 LOC file with 35 functions is the single largest remaining warning monolith after #4405. Every NAT / security / CoS / DDNS fix touches this file → merge conflicts. Reviewers must scroll past unrelated domain code.

**Fix direction:**

1. PR1: Extract `compiler_validate_warn_nat.go` + `compiler_validate_warn_security.go` (largest two slices, ~1200 LOC moved, no behavior change).
2. PR2: Extract remaining domains (`_forwarding.go`, `_ddns.go`, `_routing.go`, `_cos.go`), thin `ValidateConfig` to a dispatch table.

**Labels:** `refactor`, `modularity`, `pkg/config`, `A-mechanical`

---

## Finding 2 — `compiler_system.go` 1881 LOC — system god-compiler (A)

**Severity:** Medium  
**Confidence:** High  
**Refactor class:** (A) MECHANICAL / SAFE

**Evidence:**

- 1881 LOC, 27 funcs, 0 types. Largest: `compileSystem` 536 LOC, `compileChassis` 300 LOC, `compileUserspaceDataplane` 127, `compileSNMP` 131.
- Single `compileSystem` switch handles 15+ top-level `system` children, each invoking a distinct subsystem compiler:

```go
func compileSystem(node *Node, sys *SystemConfig, cfg *Config, opts compileOpts) error {
    dpType, err := compileSystemDataplaneType(node)
    ...
    for _, child := range node.Children {
        switch child.Name() {
        case "host-name":
            if len(child.Keys) >= 2 { sys.HostName = child.Keys[1] }
        case "domain-search":
            sys.DomainSearch = append(sys.DomainSearch, firewallMatchValues(child)...)
        case "login":
            sys.Login = &LoginConfig{}
            for _, classInst := range namedInstances(child.FindChildren("class")) {
                lc := &LoginClass{Name: classInst.name}
                ...
                lc.MappedPermissions, _ = mapJunosPermissions(lc.Permissions)
            }
        case "archival":
            sys.Archival = &ArchivalConfig{ ArchiveDir: "/var/lib/xpf/archive", ... }
            ...
        case "syslog":
            sys.Syslog = &SystemSyslogConfig{}
            for _, slInst := range namedInstances(child.FindChildren("host")) {
                host := &SyslogHostConfig{Address: slInst.name}
                ...
            }
        case "dataplane":
            ...
        }
    }
    svcNode := node.FindChild("services")
    snmpNode := node.FindChild("snmp")
    ...
}
```

Seam crossed: leaf parsing (`host-name` / `domain-search` / `name-server`), RBAC class mapping, DDNS provider catalog, archival SCP site parsing, DHCP server binding, SSH hardening, syslog host/file/user FD logic, SNMP community/trap-group/v3, chassis RG/interface-monitor/ip-monitoring, scheduler/day-window, shared-UMEM artifact JSON read + normalize — all in one file.

Responsibility count: at least 8 (system leaf, login, DDNS, SNMP, chassis/cluster, schedulers, syslog, userspace dataplane tunables + shared-UMEM, archival, advisory generators).

**Proposed decomposition:**

```
compiler_system.go                     (keep compileSystem dispatch ~80 LOC + compileSystemDataplaneType)
compiler_system_login.go               (compileSystem login block, LoginClass mapping, loginClassAdvisoryWarnings, loginClassPermName, sshHardeningAdvisoryWarnings)
compiler_system_ddns.go                (ddnsProviderStringProps, compileDDNSServices, ddnsServicesScalar, parseDurationSeconds, compileDDNSProvider)
compiler_system_syslog.go              (syslogFacilitySeverity, syslog host/file/user parse from compileSystem)
compiler_system_snmp.go                (compileSNMP, compileSNMPv3, parseSNMPv3UserKeys, snmpInertKnobWarnings)
compiler_system_chassis.go             (compileChassis, compileSchedulers, schedulerWindowFromNode, validateBackupRouterDst, schedulerWeekdays)
compiler_system_userspace.go           (compileUserspaceDataplane, compileSharedUMEMConfig, readSharedUMEMPhase0Artifact, normalize*Artifact*, userspaceRetiredKnobWarnings, hasDNSProxyChild, systemInertKnobWarnings)
```

**Shared private types / consts to carry:**

- `sharedUMEMPhase0ArtifactMaxBytes` const → moves with `compiler_system_userspace.go`.
- `ddnsProviderStringProps` var → moves with `compiler_system_ddns.go`.
- `schedulerWeekdays` map → moves with `compiler_system_chassis.go`.
- `compileSystem` calls `firewallMatchValues`, `nodeVal`, `namedInstances` (global helpers in `compiler_*.go`) — remain accessible via same package.

**Hot-path preservation:** (A) SAFE — all `compileSystem*` functions run once per commit (cold path). Not reachable from per-packet path.

**Tests + gate:** `go test ./pkg/config -run TestCompileSystem` / `TestSNMP` / `TestChassis`. Decl-NAME set unchanged.

**Why it matters:** 1881 LOC with 536-LOC `compileSystem` + 300-LOC `compileChassis` is the second-largest compiler after `compiler_nat.go`. Every syslog / SNMP / login / chassis / DDNS change collides here. Splitting by subsystem aligns files with `docs/config-schema.md` aspect boundaries (`system`, `system login`, `system services`, `system syslog`, `system snmp`, `chassis`).

**Fix direction:**

1. PR1: Extract `compiler_system_login.go` + `compiler_system_snmp.go` (well-bounded, no shared state).
2. PR2: Extract `compiler_system_chassis.go` + `compiler_system_ddns.go` + `compiler_system_userspace.go`.

**Labels:** `refactor`, `modularity`, `pkg/config`, `A-mechanical`

---

## Finding 3 — `compiler_services.go` 1821 LOC — services god-compiler (A)

**Severity:** Medium  
**Confidence:** High  
**Refactor class:** (A) MECHANICAL / SAFE

**Evidence:**

- 1821 LOC, 27 funcs, 0 types.
- Mixes 5 RPM validators, 3 DHCP compilers, dynamic-address, IP-monitoring, flow-monitoring, forwarding-options/Sampling/Port-mirroring, DHCP-relay, event-options, bridge-domains:

```
func parseRPMPositiveInt(...) ...
func validateRPMTest(...) ...
func validateRPMSourceAddressStrict(...) ...  // 63 LOC
func validateRPMLinkLocalZoneStrict(...) ...  // 53 LOC
func validateRPMHTTPGetSchemeStrict(...) ...
func validateRPMRoutingInstanceStrict(...) ...
func validateRPMProbePinsStrict(...) ...
func compileDHCPLocalServer(...) ...          // 126 LOC
func mergeDHCPDynamicDNS(...) ...
func compileDHCPDynamicDNS(...) ...           // 98 LOC
func compileDHCPExpiredLeases(...) ...
func compileDynamicAddress(...) ...
func compileServices(...) ...                 // 26 LOC dispatch
func compileIPMonitoring(...) ...
func compilePreferredRoutes(...) ...
func validateIPMonitoringStrict(...) ...      // 85 LOC
func compileRPM(...) ...                      // 122 LOC
func compileFlowMonitoring(...) ...
func compileForwardingOptions(...) ...
func compilePortMirroring(...) ...            // 73 LOC
func compileSampling(...) ...
func compileSamplingFamily(...) ...           // 121 LOC — also parses flow-server version/template/src-addr
func compileDHCPRelay(...) ...                // 149 LOC
func compileEventOptions(...) ...             // 93 LOC
func compileBridgeDomains(...) ...
```

Seam crossed in a single file:

```go
// RPM test validation (icmp/tcp/http) lives next to:
func compileDHCPLocalServer(node *Node, dhcp *DHCPServerConfig, isV6 bool) error {
// ... 126 LOC of DHCP pool/range/subnet/router/DNS/lease/domain/static-bindings ...

// 600 lines later:
func compileSamplingFamily(node *Node) *SamplingFamily {
// ... flow-server version9/version-ipfix/template/source-address/inline-jflow parsing ...
    for _, child := range node.Children {
        switch child.Name() {
        case "flow-server":
            // per-collector version + template + source-address
        case "source-address":
        case "inline-jflow":
        }
    }
}
```

Parsing (DHCP lease-time int), validation (RPM source-address family match), and rendering-prep (SamplingFamily flow-server version binding) all fused via file proximity.

**Proposed decomposition:**

```
compiler_services.go               (keep compileServices dispatch ~30 LOC)
compiler_services_rpm.go           (parseRPMPositiveInt, parseRPMRootPositiveInt, validateRPMTest, validateRPMSourceAddressStrict, validateRPMLinkLocalZoneStrict, validateRPMHTTPGetSchemeStrict, validateRPMRoutingInstanceStrict, validateRPMProbePinsStrict, compileRPM)
compiler_services_dhcp.go          (compileDHCPLocalServer, compileDHCPExpiredLeases, compileDHCPRelay, compileDHCPDynamicDNS, mergeDHCPDynamicDNS, compileDynamicAddress)
compiler_services_ip_monitoring.go (compileIPMonitoring, compilePreferredRoutes, validateIPMonitoringStrict, resolveIPMonitoringInterfaceNextHop)
compiler_services_flow.go          (compileFlowMonitoring, compileForwardingOptions, compileSampling, compileSamplingFamily, compilePortMirroring)
compiler_services_event.go         (compileEventOptions, compileBridgeDomains)
```

**Shared private types / consts:** `supportedRPMProbeTypes` map moves with `_rpm.go`. No cross-domain private const otherwise.

**Hot-path preservation:** (A) SAFE — all `compile*` / `validate*` run on commit path only.

**Tests + gate:** `go test ./pkg/config -run 'TestRPM|TestDHCP|TestSampling|TestFlow'`. Decl-NAME set unchanged.

**Why it matters:** 1821 LOC services file forces every RPM / DHCP / flow / sampling change through same file. Recent DHCP and RPM changes already collide frequently (`git log --oneline --grep=dhcp --grep=rpm` shows interleaved edits).

**Fix direction:**

1. PR1: Extract `compiler_services_rpm.go` (self-contained, 5 validators + `compileRPM`).
2. PR2: Extract `compiler_services_dhcp.go` + `compiler_services_flow.go`.
3. PR3: Extract remaining `_ip_monitoring.go`, `_event.go`.

**Labels:** `refactor`, `modularity`, `pkg/config`, `A-mechanical`

---

## Finding 4 — `compiler_nat.go` 2529 LOC — helper predicates + strict gates + compilation fused (A)

**Severity:** Medium  
**Confidence:** High  
**Refactor class:** (A) MECHANICAL / SAFE (with private-helper carry noted)

**Evidence:**

- 2529 LOC, 37 funcs, 1 type (`natMatchScope`). Four distinct concerns in one file:

  1. **Helper predicates** (family/mask classification, used by both compile and validation):
     `natAddrFamily`, `natCIDRIPPart`, `isHostMaskAddress`, `natStaticPrefixInfo`, `isStaticBlockPair`, `isNAT64PoolHostAddress`, `nptv6PrefixHasHostBits` — 160 LOC, no validation, pure parsing.

  2. **Strict validation gates** (commit-time hard-reject, lenient-warn on load):
     `validatePoolUtilizationAlarm`, `validateNATHostMaskStrict` (213 LOC), `validateNPTv6Strict` (234 LOC), `validateNAT64PrefixStrict` (70 LOC), plus `defaultPoolAlarmClearThreshold` / `defaultPoolAlarmHysteresis`.

  3. **Compile dispatch + scope parsing:**
     `compileNAT`, `compileNAT64`, `parseZoneList`, `parseNATMatchScopes`, `collectNATScopes`, `applyNATFromScope`, `applyNATToScope`, `applyStaticNATFromScope`.

  4. **Pool / rule compilation:**
     `appendPoolAddresses`, `expandAddressRange`, `parseSourcePoolPortRange`, `applyDeterministicKeys/Children/Host`, `compileNATSource`, `compileNATDestination`, `compileNATStatic` (each 200-500 LOC).

  Largest func `compileNATSource` ~500 LOC covers pool `address` bracket-list expansion, `port range` Junos-vs-legacy shape, deterministic CGNAT accumulate, persistent-NAT, port-overloading-factor, routing-instance, pool-utilization-alarm defaulting, deterministic capacity check, NAT rule-set from/to scope expansion, match `source-address`/`source-address-name`/`destination-address`/port/application, `then source-nat` interface/pool/off.

Quote — validation gate living in compilation file:

```go
// validateNATHostMaskStrict is the #2173 strict-vs-lenient gate that
// rejects a static-NAT match/prefix or a NAT64 source-pool address whose
// mask is not a host route (/32 for v4, /128 for v6; a bare address is a
// host too). #2132 made the Rust dataplane TOLERATE the canonical host
// mask, and PR #2167 then hardened the Rust parser to REJECT a non-host
// mask — so today a misconfigured /24 static-NAT match or pool address is
// SILENTLY DROPPED at the dataplane (the rule is parsed-out, never
// installed) with no operator feedback. This commit-time check surfaces
// the misconfiguration at `commit`/`commit check` instead.
func validateNATHostMaskStrict(cfg *Config, lenient bool) ([]string, error) {
    if cfg == nil {
        return nil, nil
    }
    var warnings []string
    emitSuffix := func(msg, suffix string) error {
        if lenient {
            warnings = append(warnings, msg+suffix)
            return nil
        }
        return fmt.Errorf("%s", msg)
    }
```

This gate is called from `runUniformGates` (P6b), not from `compileNAT*`. It belongs with the other strict gates, not with pool address expansion.

Quote — helper predicate reused by 3+ call sites across validation + compilation:

```go
func natAddrFamily(ipPart string) string {
    if net.ParseIP(ipPart) == nil {
        return ""
    }
    if strings.IndexByte(ipPart, ':') >= 0 {
        return "v6"
    }
    return "v4"
}
```

Used in `validateNATHostMaskStrict`, `validateBackupRouterDst` (in `compiler_system.go`), `validateNPTv6Strict`, `validateNAT64PrefixStrict`, and `(indirectly) compile-time pool checks`. Same-package reuse across `compiler_nat.go` + `compiler_system.go` + `compiler_validate_strict_nat.go` means splitting must keep this helper visible.

**Proposed decomposition:**

```
compiler_nat.go                    (keep compileNAT, compileNAT64, compileNATSource, compileNATDestination,
                                   compileNATStatic, parseZoneList, parseNATMatchScopes, collectNATScopes,
                                   applyNAT*Scope, appendPoolAddresses, expandAddressRange,
                                   parseSourcePoolPortRange, applyDeterministic*, ~1500 LOC)
compiler_nat_helpers.go             (natAddrFamily, natCIDRIPPart, isHostMaskAddress, natStaticPrefixInfo,
                                   isStaticBlockPair, isNAT64PoolHostAddress, nptv6PrefixHasHostBits,
                                   defaultPoolAlarmClearThreshold, defaultPoolAlarmHysteresis)
compiler_validate_strict_nat.go    (already exists 702 LOC — MOVE validatePoolUtilizationAlarm,
                                   validateNATHostMaskStrict, validateNPTv6Strict, validateNAT64PrefixStrict
                                   FROM compiler_nat.go into this file, so all NAT strict gates live together)
```

Note: `compiler_validate_strict_nat.go` already exists but does NOT contain these 4 gates — they still live in `compiler_nat.go`. The `natAddrFamily` / `isHostMaskAddress` helpers are used by both `compiler_nat.go` (compile-time pool validation) and the strict gates, so they belong in a shared `compiler_nat_helpers.go` (or unexported helpers in `pkg/config/nat_helpers.go`).

**Shared private types / consts — subtlety:**

- `defaultPoolAlarmHysteresis` const, `natScopeKinds` var / `natMatchScope` type must be carried with whichever file keeps the scope helpers.
- `natAddrFamily` is also called from `compiler_system.go:validateBackupRouterDst` — if helpers move to `compiler_nat_helpers.go`, that file must stay in `package config` (same package) so `compiler_system.go` still sees it; no import change needed.
- If `isHostMaskAddress` moves, verify `compiler_nat.go:pool.Address` check (`compileNATSource` static-NAT pool host check) still compiles — it uses the same helper.

**Hot-path preservation:** (A) SAFE — NAT helpers + validation + compilation all run on commit path only (cold). No per-packet function calls this code. Pure file move.

**Tests + gate:** `go test ./pkg/config -run 'TestNAT|TestNPTv6|TestNAT64|TestPool'`. Decl-NAME set must stay identical per #4144 discipline (`go list -f '{{.GoFiles}}'` sorted func/method names before vs after).

**Why it matters:** 2529 LOC file with 37 functions mixing 3 concerns is the single largest compiler file after `compiler_validate_warn.go`. NAT changes (pool, deterministic, NPTv6, NAT64) all collide here, and the inline validation gates duplicate the responsibility already owned by `compiler_validate_strict_nat.go`.

**Fix direction:**

1. PR1: Create `compiler_nat_helpers.go` moving 7 helper predicates + 1 const (no behavior change, `go build` passes).
2. PR2: Move `validatePoolUtilizationAlarm`, `validateNATHostMaskStrict`, `validateNPTv6Strict`, `validateNAT64PrefixStrict` into existing `compiler_validate_strict_nat.go` (now all NAT strict gates co-located).

**Labels:** `refactor`, `modularity`, `pkg/config`, `A-mechanical`

---

## Finding 5 — `compiler_uniformgates.go` 1659 LOC + `compiler_validate_strict_filter.go` 1660 LOC — genuinely cohesive, do NOT split (D)

**Severity:** Low (negative finding)  
**Confidence:** High  
**Refactor class:** (D) DO-NOT-SPLIT

### `compiler_uniformgates.go` — single-func orchestrator preserving order invariants

**Why it is cohesive:**

- After #4406 step 4, this file is **exactly one function** `runUniformGates` (1659 LOC) — a linear sequence of ~75 `validate*Strict` calls, each with identical shape:

```go
if err := validateClassOfServiceSchedulerMapRefsStrict(cfg.ClassOfService); err != nil {
    if opts.lenientSchedulerMapRef {
        cfg.Warnings = append(cfg.Warnings,
            fmt.Sprintf("class-of-service scheduler-map reference (downgraded to warning on tolerant path): %v", err))
    } else {
        return err
    }
}
// ... 70+ more gates, same pattern, order is invariant #6/#7 ...
```

- File header explicitly documents invariants #6 (strict path first-error wins) and #7 (tolerant path warning order). These are **observable** via `compile_golden_4406_test.go`. Splitting this orchestrator across files would break the contiguous-order guarantee and require cross-file ordering discipline.

- Each gate is already per-domain in its own `compiler_validate_strict_*.go` file; this file is the **single ordered call-site**, not the gate implementations.

**Verdict:** Keep as single file. Future work should NOT extract per-domain gate groups into separate orchestrator files.

### `compiler_validate_strict_filter.go` — single-domain strict validation

**Why it is cohesive:**

- 1660 LOC, 28 funcs, all strictly firewall-filter domain: `validateFirewallPolicerReferencesStrict`, `validateFirewallPrefixListReferencesStrict`, `validateFirewallRoutingInstanceReferencesStrict`, `validateFirewallFilterReferencesStrict`, `validateFilterProtocolsStrict`, `validateFilterCrossFieldStrict`, `validateFilterActionsStrict`, `validateFilterMatchValuesStrict`, `validateFilterFlexMatchStrict`, `validateFilterPortExceptStrict`, `validateFilterAddressExceptStrict`, `validateFilterAddressLiteralsStrict`, `validateFilterFromMatchStrict`, `validateFilterRoutingInstanceConflictStrict`, `validateFilterTerminalConflictStrict`, `validateFilterDSCPStrict`, plus helpers `filterDSCPResolvable`, `filterProtocolResolvable`, `protocolIsPortBearing`, etc.

- This file IS the per-domain split result of #4405 for the filter domain. Further splitting by individual gate would produce 15+ files each 80-150 LOC with shared helpers (`filterProtocolResolvable`, `protocolIsPortBearing`, `filterDSCPResolvable`, `classifyFilterAddrFamily`), increasing file count without reducing cognitive load.

- Companion `compiler_validate_strict_test.go` pattern (drift guards like `TestFilterProtocolResolvableMatchesProtocolNumber`) expects these helpers co-located.

**Verdict:** Keep as single file. Do NOT further split by gate.

### `types_system.go` 1544 LOC — borderline, but keep for now (D with reservation)

- 64 type definitions. While it mixes SystemConfig, UserspaceConfig, SNMP, Login, DHCP server, Services/RPM, FlowMonitoring, Sampling, **and** Firewall/Policer/Filter (firewall types logically belong in `types_security.go` or `types_firewall.go`), splitting Go type definitions across files is high-blast-radius (every `pkg/config` consumer + `pkg/dataplane/userspace` snapshot builder imports these types).

- The types are cohesive in the sense of "all types compiled by `compiler_system.go` + `compiler_services.go`" — a historical accident, but moving `FirewallConfig` / `PolicerConfig` / `FirewallFilter` to `types_firewall.go` would touch 20+ files and is not a mechanical rename.

- Recommendation: file a tracking issue for `types_system.go` firewall-type extraction, but do NOT block current modularity work on it. Low priority relative to compiler splits.

**Hot-path preservation:** N/A — negative findings, no change proposed.

**Dedup note:** `compiler_validate_strict_filter.go` was already per-domain split in #4405; `compiler_uniformgates.go` was created in #4406 step 4. Do not re-report these as "large monoliths needing split" — they ARE the split result, intentionally kept coarse at the domain/orchestrator level.

---

## Summary of proposed PR sequence (A findings only)

| Order | File(s) created | Source | LOC moved | Risk |
|-------|----------------|--------|-----------|------|
| 1 | `compiler_nat_helpers.go` | `compiler_nat.go` helpers (7 funcs + 1 const) | ~200 | Very low — pure helper move |
| 2 | (move) into `compiler_validate_strict_nat.go` | `compiler_nat.go` 4 strict gates | ~600 | Low — same package, same call site (`runUniformGates`) |
| 3 | `compiler_validate_warn_nat.go` + `_security.go` | `compiler_validate_warn.go` | ~800 | Low — pure warning func move |
| 4 | `compiler_system_login.go` + `_snmp.go` | `compiler_system.go` | ~450 | Low — well-bounded |
| 5 | `compiler_system_chassis.go` + `_ddns.go` + `_userspace.go` | `compiler_system.go` | ~900 | Medium — carries consts/vars |
| 6 | `compiler_services_rpm.go` | `compiler_services.go` 8 funcs | ~350 | Low |
| 7 | `compiler_services_dhcp.go` + `_flow.go` + `_ip_monitoring.go` | `compiler_services.go` | ~800 | Medium |

Each PR: `go build ./... && go test ./pkg/config -run ...` + decl-NAME set check per #4144. No logic change, no new dependencies.

---

## Dedup checklist

- [x] #4405 `compiler_validate_strict.go` 6997 LOC → CLOSED (now 478 + 11 per-domain files). Do NOT re-report.
- [x] #4421 `compiler_security.go` / `firewall-filter` / `rules.go` — separate issue, not re-reported here (filter strict is reported only as D-negative, not as A-split).
- [x] #4406 `compileExpanded` god-orchestrator → CLOSED (`compiler_prewalk.go`, `compiler_dispatch.go`, `compiler_derivations.go`, `compiler_earlystrict.go`, `compiler_uniformgates.go`, `compiler_tailgates.go`). `compiler_uniformgates.go` single-func orchestrator reported as D-negative.

---

## Hot-path preservation statement for all A findings

Go config compilers are **cold path** — `CompileConfig` / `CompileConfigLenient` / `CompileConfigForNode{,Lenient}` run once per operator commit, once per `Store.Load` (boot), and once per HA peer-sync. They are NOT called from `userspace-dp` per-packet path, VRRP advert loop, or HA heartbeat. All proposed splits are pure file moves with no logic change, same package (`package config`), same function signatures, same initialization order. Byte-identical behavior verified by `go build` + `go test ./pkg/config` passing and sorted top-level decl-NAME set unchanged.

One subtlety: `natAddrFamily` / `isHostMaskAddress` / `natCIDRIPPart` helpers are used across `compiler_nat.go`, `compiler_validate_strict_nat.go`, and `compiler_system.go:validateBackupRouterDst`. If extracted to `compiler_nat_helpers.go`, they must stay in `package config` so all existing call sites compile without import changes. Similarly, `schedulerWeekdays`, `ddnsProviderStringProps`, `sharedUMEMPhase0ArtifactMaxBytes`, `supportedRPMProbeTypes` must travel with their domain file.

---

## Labels for new issues

`refactor`, `modularity`, `pkg/config`, `A-mechanical` (findings 1-4), `D-do-not-split` (finding 5)

---

*Generated by modularity audit 039 (A3) against f70146951. Mechanical-split findings follow #4144 decl-NAME discipline.*
