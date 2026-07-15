# Review: A3_go_config_cli_tree-b3 (116 files)

Base commit: d4506d4450e23f9a3fc572206b3c82f6b6c99029
Area: A3_go_config_cli_tree batch 3/3 — Go config schema / CLI tree / chassis / SNMP / screen / interface / VLAN / remaining compilers
Date: 2026-07-07

## Batch file list (116 files)

```
pkg/config/policy_rematch_advisory_test.go
pkg/config/policy_terminal_action_3043_test.go
pkg/config/policy_zone_ref_test.go
pkg/config/predefined.go
pkg/config/predefined_app_sets_4102_test.go
pkg/config/predefined_icmp_3020_test.go
pkg/config/protocols_multileaf_2587_test.go
pkg/config/quoted_inactive_4348_test.go
pkg/config/quotekey_roundtrip_3854_test.go
pkg/config/reserved_zone_name_3055_test.go
pkg/config/reth_show.go
pkg/config/ribgroup_leak_warn_3876_test.go
pkg/config/router_id_2980_test.go
pkg/config/routing_adjacency_4285_test.go
pkg/config/routing_export_ref_test.go
pkg/config/routinginstanceid.go
pkg/config/routinginstanceid_test.go
pkg/config/sampling_instance_conflict_test.go
pkg/config/schema.go
pkg/config/schema_chassis.go
pkg/config/schema_closedworld_ipsec_4313_test.go
pkg/config/schema_closedworld_nat_then_4313_test.go
pkg/config/schema_complete.go
pkg/config/schema_cos.go
pkg/config/schema_cos_hb166_test.go
pkg/config/schema_desc_test.go
pkg/config/schema_global_zone_list_4415_test.go
pkg/config/schema_ike_enum_3896_test.go
pkg/config/schema_interfaces.go
pkg/config/schema_policy_then_3377_test.go
pkg/config/schema_route_preference_3771_test.go
pkg/config/schema_route_qnh_preference_3827_test.go
pkg/config/schema_routing.go
pkg/config/schema_scheduler_name_3117_test.go
pkg/config/schema_schedulers.go
pkg/config/schema_security.go
pkg/config/schema_system.go
pkg/config/schema_validate_2008_test.go
pkg/config/schema_validate_2497_test.go
pkg/config/schema_validate_2524_test.go
pkg/config/schema_validate_3895_test.go
pkg/config/schema_validate_4119_test.go
pkg/config/schema_validate_chassis_test.go
pkg/config/schema_validate_cos_rate_percent_4228_test.go
pkg/config/schema_validate_ddns_hostname_2779_test.go
pkg/config/schema_validate_ddns_source_address_2780_test.go
pkg/config/schema_validate_firewall_test.go
pkg/config/schema_validate_flow_numwidth_test.go
pkg/config/schema_validate_interfaces_test.go
pkg/config/schema_validate_route_2448_test.go
pkg/config/schema_validate_route_filter_test.go
pkg/config/schema_validate_routing_4285_test.go
pkg/config/schema_validate_system_test.go
pkg/config/schema_validate_test.go
pkg/config/schema_validate_trailing_token_3332_test.go
pkg/config/schema_validators.go
pkg/config/schema_validators_cos.go
pkg/config/schema_validators_ddns.go
pkg/config/schema_validators_devicemap.go
pkg/config/schema_validators_ipsec.go
pkg/config/schema_validators_logging.go
pkg/config/schema_validators_network.go
pkg/config/schema_validators_routing.go
pkg/config/schema_validators_scheduler.go
pkg/config/schema_validators_system.go
pkg/config/schema_walk.go
pkg/config/schema_walk_internal_test.go
pkg/config/screen_alarm_without_drop_test.go
pkg/config/screen_inventory.go
pkg/config/screen_numeric_strict_3317_test.go
pkg/config/screen_profile_ref_test.go
pkg/config/screen_synflood_subthreshold_3315_test.go
pkg/config/screen_trailing_token_3332_test.go
pkg/config/screen_unknown_strict_3318_test.go
pkg/config/secret.go
pkg/config/secret_test.go
pkg/config/set_repeated_leaf_3984_test.go
pkg/config/show_config_dup_context_4562_test.go
pkg/config/show_config_repeated_keyword_3980_test.go
pkg/config/snmp_clients.go
pkg/config/snmp_clients_4289_test.go
pkg/config/sqm_cookbook_fixture_test.go
pkg/config/static_nat_mapped_port_2491_test.go
pkg/config/static_nat_source_address_3435_test.go
pkg/config/static_nat_zone_test.go
pkg/config/system_multileaf_test.go
pkg/config/tcp_flags.go
pkg/config/tcp_flags_test.go
pkg/config/tcp_session_advisory_test.go
pkg/config/tunnel_perunit_deepcopy_test.go
pkg/config/tunnelemit.go
pkg/config/tunnelid.go
pkg/config/tunnelid_test.go
pkg/config/types.go
pkg/config/types_chassis.go
pkg/config/types_cos.go
pkg/config/types_interfaces.go
pkg/config/types_routing.go
pkg/config/types_security.go
pkg/config/types_system.go
pkg/config/types_test.go
pkg/config/value_type.go
pkg/config/vrrp_authentication_4288_test.go
pkg/config/vrrp_preempt_holdtime_test.go
pkg/config/vrrp_track_test.go
pkg/config/vrrp_v6_test.go
pkg/config/vrrp_vaddr_subnet_3013_test.go
pkg/config/web_management_auth_4047_test.go
pkg/config/wireguard_multipeer_test.go
pkg/config/xfrmi.go
pkg/config/xfrmi_test.go
pkg/config/zone_count_cap_test.go
pkg/config/zone_interface_membership_test.go
pkg/config/zone_local_unqualify_3358_test.go
pkg/config/zoneid.go
pkg/config/zoneid_test.go
```

## Module-by-module log

### schema.go — No finding
Reviewed schemaNode type, isScalarValueLeaf structural guards (multi, children, compoundKey, midKeyword, isTypedLeaf, args>0), isTypedLeaf, isScalarValueLeaf, setSchema root composition. No integer handling. No truncation. Correct.

### schema_chassis.go — One finding (A3-b3-01)
Reviewed all typed leaves: cluster-id 0..255 (MAC byte, heartbeat uint16), node 0..1, reth-count 1..128, heartbeat-interval 1..MaxDurationMillis, heartbeat-threshold Min(1), reth-advertise-interval 10..40959, takeover-hold-time 0..MaxDurationMillis, peer-fencing enum, gratuitous-arp-count Min(1), global-weight/threshold 0..255, per-target weight 0..255, device-map pci/mac/key/unmapped-policy. All typed leaves correct. One gap: interface-monitor weight is explicitly deferred (children:nil, no validator) with no runtime range check. Finding A3-b3-01.

### schema_interfaces.go — No finding
vlan-id 1..4094 correct, inner-vlan-id 1..4094 correct (QinQ rejected by seperate gate), native-vlan-id 1..4094 accepted-only #4308 correct, mtu Min(1) correct, tunnel key 0..4294967295 correct, ttl 0..255 correct, listen-port 1..65535 correct, persistent-keepalive 0..65535 correct, vrrp priority 1..255, preempt hold-time 1..3600, advertise-interval 1..40 — all correct. No integer truncation.

### schema_routing.go — No finding
BGP local-as 1..4294967295 correct, OSPF hello/dead/retransmit 1..65535 priority 0..255 correct, RA default-lifetime 0..65535 (0="not default router" #4119), reachable-time/retrans-timer 0..4294967295, valid/preferred-lifetime 0..4294967295, PREF64 lifetime 0..65528 (13-bit scaled), link-mtu Min(1280), max-adv-interval 4..1800, min-adv-interval 3..1350 — all correct.

### schema_cos.go, schema_schedulers.go — No finding
Reviewed transmit-rate/shaping-rate tail validators, scheduler priority enum, buffer-size, CoS rate/percent forms. All correct.

### schema_security.go — No finding
Reviewed security, zones, policies, NAT, screen, applications subtrees. Multi-value leaves (source-address, destination-address, application) all `multi:true` — correct bracket-list handling. Global policy from-zone/to-zone tagged scalar:true — correct fail-closed (reject list with clear error rather than silently keep first). No truncation.

### schema_system.go — No finding
Reviewed system, services, snmp, event-options subtrees. All typed leaves correct. No truncation.

### schema_complete.go — No finding
Completion logic only reads schema keywords, no integer narrowing.

### schema_walk.go — No finding
validateMultiValueLeaf reads both Keys[1:] AND Children — correct bracket-list (#2419). validateScalarValueLeaf rejects trailing tokens — fail-closed. validateTypedLeaf rejects missing/unknown — fail-closed. validateTailLeaf gatherLeafTailTokens flattens both shapes — correct dual-shape. No integer truncation (all string-keyed). Recursion bounded by schema depth (fixed ~6-8 levels), not AST depth — no DoS.

### value_type.go — No finding
Pure enum/string mapping.

### schema_validators.go — No finding
ValidateInteger/ValidateIntegerMin/ValidatePercent/ValidateEnum + MaxDurationMillis/MaxDurationSeconds/maxWireU16/U32/I32 — all correct. All use ParseInt 64-bit then range check — no truncation before validation.

### schema_validators_cos.go — No finding
ValidateRate/ValidateByteSize/ValidateByteSizeOrPercent/tail validators/validateCoSPercentValue/coSRateSiblingSuppliesValue — all correct. Percent range (0,100] excludes 0% (intentional, 0% indistinguishable from absent). Correct.

### schema_validators_ddns.go — No finding
ValidateDDNSHostname LDH + length limits correct. maxDNSLabelLen=63, maxDNSNameLen=253 mirrors publish path.

### schema_validators_devicemap.go — No finding
ValidatePCIAddr exact 12-char canonical DDDD:BB:DD.F correct. ValidateMAC net.ParseMAC + all-zero + multicast reject correct. ValidateDeviceMapLogicalName correct.

### schema_validators_ipsec.go — No finding
ValidateDHGroup Atoi with "group" prefix strip, v>=1, no upper bound (deliberate, compiler truncates to int). No narrowing.

### schema_validators_logging.go — No finding
ValidateSyslogSourceInterface Atoi unit with non-negative check correct.

### schema_validators_network.go — No finding
ValidateIPAddress/IPv4CIDR/IPv6CIDR/PREF64/IPv6Address/parseCIDRStrict — all net.ParseIP/ParseCIDR with family gates correct.

### schema_validators_routing.go — No finding
ValidateBGPHoldTime 0 or 3..65535 correct (FRR 16-bit, 0=unset). ValidateRouteFilterArg routeFilterMatchTypes + parseCIDRStrict correct. ValidateRouteDestination family-agnostic CIDR correct. ValidateStaticNextHop ip@interface/interface-name handling correct.

### schema_validators_scheduler.go — No finding
ValidateTimeOfDay time.Parse "15:04:05" correct. ValidateDate time.Parse "2006-01-02" correct.

### schema_validators_system.go — No finding
ValidateCryptHash modular hash structure correct. ValidateRingEntries [1,16384] + power-of-two correct.

### snmp_clients.go — No finding (deep review)
parseSNMPClients: reads Keys[1:] (bracket-list collapsed) + Children — handles both shapes. `restrict` modifier attaches to out[len-1].Restrict — correct for flat `clients [ 10.0.0.0/24 restrict 10.0.1.0/24 ]` and hierarchical `clients { 10.0.0.0/24 restrict; }`. Empty out + bare "restrict" → no-op (len>0 check) — safe. AllowsSource longest-prefix-match, restrict handling, unparseable prefix skipped (continue, not allow-all) — fail-closed correct. Nil srcIP allowed (test path with no address). No truncation.

### screen_inventory.go — No finding
ScreenChecks/ScreenThresholds/ScreenEnabledCheckList — pure inventory. All checks present (syn-flood, land, winnuke, syn-frag, syn-fin, tcp-no-flag, fin-no-ack, ping-death, icmp-fragment, icmp-flood, udp-flood, source-route-option, tear-drop, port-scan, ip-sweep, limit-session-source/dest = 18 entries). Nil profile → nil (no panic). Thresholds only positive values. No truncation.

### tcp_flags.go — No finding
ParseTCPFlagsExpression: lex into toks (operators &,|,!,(), flag words), pendingNeg tracking, `|` rejection (disjunction), negated group rejection (De Morgan), unknown flag rejection, required&forbidden contradiction check — all fail-closed correct. Bit order matches userspace-dp/src/tcp_flags.rs. `push` alias for `psh` (Junos compat). No truncation.

### secret.go — No finding
Secret type redaction correct. SecretRedacted="<redacted>", MarshalJSON/MarshalYAML redaction, UnmarshalJSON refuses sentinel — correct. RedactURL userinfo + query string redaction correct. No truncation.

### reth_show.go — No finding (one low note A3-b3-02 below)
RethShowMaps dual-keyed PhysToReth (Junos + Linux names), RethToPhys, LookupReth/LookupMember, RethShowUnits sorted by unit, v4/v6 split via net.ParseCIDR + To4() — all correct. No truncation.

### tunnelid.go, zoneid.go, routinginstanceid.go — No finding
StableTunnelEndpointID/ZoneID/RoutingInstanceTableID FNV xor-fold — intentional wire-adjacent, MUST NOT CHANGE, documented — correct. Collision detection 3-view (pre-expansion + node0/node1 post-expansion), quarantine on lenient, strict reject on commit — correct. ZoneIDReservedMin=0xFFFE mirrors Rust. Tunnel/zone/RI collision dedup index entries all checked.

### xfrmi.go — No finding (one low dead-code note A3-b3-02)
XFRMIfNameAndID bounds: stIndex <0x10000 (65536), unit <0xFFFF (65535), ifID=uint32(stIndex)<<16|uint32(unit+1) — overflow prevented, max ifID=0xFFFFFFFF fits uint32. Dead-code `if ifID==0` guard (see A3-b3-02).

### tunnelemit.go — No finding
EmitTunnelEndpointNames pure function of typed config, deterministic sort, non-WG source/destination gate mirrored from builder, interface-level WG single-lowest-unit pick (#1910) — correct.

### predefined.go — No finding
PredefinedApplications map (130+ entries), PredefinedApplicationSets (4 entries), ResolveApplication/ResolveApplicationSet/ExpandApplicationSet depth=3 + seen dedup, ExpandAddressSet depth=5 + visited cycle detection + seen dedup — all correct. u8p helper correct. Parsing: parseICMPTypeCode 0..255 validated, uint8 cast only after range check — safe.

### types.go — No finding
LinuxIfName/DHCPLeaseIfName/InterfaceSlot/SlotToNodeID/RethToPhysical/ResolveReth/ResolveFab/ResolveKernelIfName/DHCPLeaseKey/TunnelNameMap/IRBToBridge — all Atoi→int (matching int fields), no truncation. InterfaceSlot -1 on no dash/slash, no panic.

### types_chassis.go — No finding
All int fields. DeviceMapConfig.Active() len>0 check correct. EffectiveKeyOrder/EffectiveUnmappedPolicy defaults correct.

### types_cos.go — No finding
CoS type definitions. QueueID uint8 validated 0..255 before cast in compiler_class_of_service.go — safe. Other uint8/uint32 fields (DSCPValue, CodePoints, DSCPValue) validated at compile.

### types_interfaces.go — No finding
Interface type fields. VlanID int 1..4094 validated. No truncation.

### types_routing.go — No finding
TunnelConfig.Key uint32 (0..4294967295 validated by schema), WgListenPort uint16 (1..65535 validated by schema+compiler), WgPeerConfig.KeepaliveSecs uint16 (0..65535 validated) — all safe. WgHasEndpoint/WgOuterFamilyV6 correct. cloneForUnit deep-copies Addresses + WgPeers.AllowedIPs — correct (no aliasing, #3898).

### types_security.go — No finding
All int fields. IsWildcardZone/Set logic. GlobalPolicyAppliesToZone. PolicyMatch FromZone/ToZone single-string (not list, correct per #4415 M03 scalar:true rejection). TerminalActions conflict detection (#3043). UnknownChildren advisory. InterfaceHostInbound additive union.

### types_system.go — No finding
All type definitions. SNMPCommunity.MarshalJSON/MarshalYAML redaction (map→slice to hide secret key) correct. SNMPCommunity.AllowsSource via snmp_clients.go. FlexMatchConfig ByteOffset/BitLength/Value/Mask narrow but validated in compiler_firewall.go before cast — safe.

### All *_test.go files — No new findings (negative results, test-only)
All 60+ test files reviewed for coverage and correctness of assertions. No new production bugs found in test files themselves.

### Integer truncation audit — specific cast sites

| Site | Source | Target | Validated? | Verdict |
|------|--------|--------|------------|---------|
| tunnel key Atoi→uint32 | schema 0..4294967295 | uint32 | Yes | Safe |
| wg listen-port Atoi→uint16 | schema 1..65535 + compiler n>0&&<=65535 | uint16 | Yes | Safe |
| wg keepalive Atoi→uint16 | schema 0..65535 + compiler n>=0&&<=65535 | uint16 | Yes | Safe |
| flex byte-offset Atoi→uint8 | compiler 0..255 | uint8 | Yes | Safe |
| flex bit-length Atoi→uint8 | compiler 1..32 | uint8 | Yes | Safe |
| screen thresh Atoi→uint32 | parseThresh 1..MaxUint32 | uint32 (snapshot) | Yes | Safe |
| CoS queue Atoi→uint8 | compiler 0..255 | uint8 | Yes | Safe |
| CoS fairness queue Atoi→uint8 | compiler 0..255 | uint8 | Yes | Safe |
| app icmp-type Atoi→uint8 | compiler 0..255 | uint8 | Yes | Safe |
| vlan-id Atoi→int | schema 1..4094 | int | Yes | Safe |
| native-vlan-id Atoi→int | schema 1..4094 | int | Yes | Safe |
| cluster-id Atoi→int | schema 0..255 | int | Yes | Safe |
| node Atoi→int | schema 0..1 | int | Yes | Safe |
| reth-count Atoi→int | schema 1..128 | int | Yes | Safe |
| zone-id fold →uint16 | FNV xor-fold [1,65533] | uint16 | Intentional (wire) | Safe |
| tunnel-id fold →uint16 | FNV xor-fold [1,65535] | uint16 | Intentional (wire) | Safe |
| RI table-id fold →int | FNV xor-fold [100000,999999] | int | Intentional | Safe |
| xfrmi if_id →uint32 | stIndex<0x10000, unit<0xFFFF | uint32 | Yes | Safe |
| interface-monitor weight Atoi→int | NO validation | int (Weight) | **No** | **Low (A3-b3-01)** |

No len()→uint16 truncation. No silent Atoi→uint16 wrap.

### Bracket-list handling audit

| Site | Pattern | Keys[1:]? | Children? | Verdict |
|------|---------|----------|-----------|---------|
| snmp_clients.go parseSNMPClients | multi leaf clients | Yes | Yes | Safe |
| schema_walk.go validateMultiValueLeaf | multi typed leaf | Yes | Yes | Safe |
| compiler_security_zones.go host-inbound | multi (system-services/protocols) | Yes (firewallMatchValues) | Yes | Safe |
| compiler_interfaces.go vrrp virtual-address | multi | Yes | Yes | Safe |
| compiler_firewall.go compileFilterFrom | multi from ports/addrs | Yes (firewallMatchValues) | Yes | Safe |
| predefined.go expandAppSet/expandAddrSet | multi members | N/A (namedInstances) | N/A | Safe |

No new bracket-list truncation bugs in batch files.

### Zone/VLAN completeness

- Zone compilation: interfaces, screen, host-inbound (zone-level + per-interface override), tcp-rst, description, address-book (zone-local) — all compiled.
- Zone ID: StableZoneID [1,65533], collision detection 3-view, quarantine on lenient — complete.
- Zone-local address-book fold — complete.
- Wildcard zone: IsWildcardZone ("" or "any"), GlobalPolicyAppliesToZone — correct.
- VLAN: vlan-id 1..4094 typed+compiled, inner-vlan-id rejected (honest posture #2354), native-vlan-id accepted-only #4308, flexible-vlan-tagging presence, vlan-id-list 1..4094, DHCPLeaseIfName vlan-id suffix — complete.
- No zone/VLAN gaps.

---

## Findings

---

Title
chassis cluster interface-monitor weight has no range validation — accepts negative (priority-raising on link-down) and very large values

Severity
Low

Confidence
High

Evidence
File: pkg/config/schema_chassis.go:219-225 and pkg/config/compiler_system.go:1726-1746

In schema_chassis.go:
```go
// interface-monitor weight is NOT typed in PR 2: the
// `<ifname> weight <n>` tokens pack inline into one leaf
// (children==nil here); typing the weight would require a
// children/wildcard map, which flips SetPath's
// replace-vs-container grouping — forbidden by the
// fields-only rule. Deferred (docs/config-schema.md).
"interface-monitor": {desc: "Deduct weight from the redundancy group while a monitored interface is down", children: nil},
```

In compiler_system.go:1726-1746:
```go
case "interface-monitor":
    for _, ifChild := range child.Children {
        im := &InterfaceMonitor{
            Interface: ifChild.Name(),
        }
        for i := 1; i < len(ifChild.Keys)-1; i++ {
            if ifChild.Keys[i] == "weight" {
                if n, err := strconv.Atoi(ifChild.Keys[i+1]); err == nil {
                    im.Weight = n
                }
            }
        }
        if wNode := ifChild.FindChild("weight"); wNode != nil {
            if v := nodeVal(wNode); v != "" {
                if n, err := strconv.Atoi(v); err == nil {
                    im.Weight = n
                }
            }
        }
        rg.InterfaceMonitors = append(rg.InterfaceMonitors, im)
    }
```

Bare `strconv.Atoi` with no range check follows the explicitly-deferred schema typing.

Trace
1. Operator configures: `set chassis cluster redundancy-group 0 interface-monitor ge-0-0-1 weight -100`
2. Schema has no validator for interface-monitor weight — explicitly documented as deferred in schema_chassis.go:219-224 comment
3. `compileChassis` at compiler_system.go:1730 parses via `strconv.Atoi("-100")` → -100 with no range check → `InterfaceMonitor{Interface:"ge-0-0-1", Weight:-100}`
4. At runtime, `pkg/cluster/election.go:getPriority` subtracts Weight from RG effective priority when interface is down. With Weight=-100, effective priority = base_priority - (-100) = base_priority + 100 when link is down — priority INCREASES, preventing failover when it should trigger
5. Contrast with ip-monitoring weights which ARE validated 0..255 (schema_chassis.go:230-264 shows Junos vSRX 0..255, heartbeat wire uint8). Interface-monitor is the only chassis weight without validation
6. VRRP `track-interface priority-cost` had the same class of bug (negative cost raises priority on link-down) — fixed in #1814 with range 1..254 AST pre-walk. Interface-monitor has no equivalent fix

Refutation attempt
I checked downstream clamping in `pkg/cluster/election.go:getPriority` and `pkg/cluster/group_state.go`. `getPriority` clamps effective priority to [1,254] for non-owner-255 nodes, so a huge positive weight (e.g. 99999) clamps to 1 — effectively "always fail over when interface down" which might be operator intent but exceeds Junos 0..255 documented range. A negative weight (-100) makes effective priority = 100+100 = 200 when interface is down — still in [1,254] so clamp does NOT catch it, and it prevents failover by raising priority above peer. No downstream correctly handles negative weight — getPriority just applies arithmetic. I also checked heartbeat wire encoding: `pkg/cluster/heartbeat_manager.go:buildHeartbeat` encodes monitor weights as uint8, so a negative or >255 value would truncate/wrap on the wire. This finding survives refutation — the bug is real but impact is Low (operator must explicitly misconfigure a negative weight; no crash, just inverted HA semantics).

HPC/invariant check
N/A — control-plane config parsing, not hot-path.

Why it matters
- Negative weight inverts failover semantics: interface-down raises priority instead of lowering it — HA correctness issue where a failed link prevents failover instead of causing it
- Very large weight (>255) exceeds Junos documented range and truncates when encoded as uint8 on the heartbeat wire — potential priority mismatch between cluster nodes

Fix direction
Add range validation for interface-monitor weight in an AST pre-walk function (like `validateVRRPTrackInterfaceAST` for VRRP track-interface, #1814) since schema cannot type it without flipping SetPath's replace-vs-container grouping (documented fields-only constraint). Walk should reject weight < 0 and weight > 255 on strict commit, warn on lenient load/peer-sync. Document that interface-monitor weight follows same 0..255 range as ip-monitoring weights (Junos vSRX range) and VRRP track-interface priority-cost (1..254).

Labels
ha, chassis-cluster, integer-validation, vsrx-parity

Dedup note
Not in dedup index. Checked all 60 entries: dedup #4549 lists 4 LOW cluster/vrrp/ipsec hardening residuals (VRRP hop-limit, HA heartbeat IPv4-only, PSK zeroize, election split-brain) — does not mention interface-monitor weight. Dedup #4434 (CLOSED) covers RG count/id uint8 overflow, not monitor weight. No match in open or closed issues.

---

Title
XFRM if_id computation: dead-code `ifID == 0` guard is unreachable (cosmetic)

Severity
Low

Confidence
High

Evidence
File: pkg/config/xfrmi.go:22-37

```go
stIndex, err := strconv.Atoi(devName[2:])
if err != nil || stIndex < 0 || stIndex >= 0x10000 {
    return "", 0
}
unit := 0
if len(parts) == 2 {
    unit, err = strconv.Atoi(parts[1])
    if err != nil || unit < 0 || unit >= 0xffff {
        return "", 0
    }
}
ifID := uint32(stIndex)<<16 | uint32(unit+1)
if ifID == 0 {
    return "", 0
}
return LinuxIfName(bindIface), ifID
```

- stIndex validated: 0 <= stIndex < 65536 (0x10000)
- unit validated: 0 <= unit < 65535 (0xFFFF exclusive), default 0 when no suffix
- ifID = stIndex<<16 | (unit+1): unit+1 is in [1, 65535], so low 16 bits always non-zero
- Therefore ifID is always >= 1 for any valid stIndex/unit — the `ifID == 0` check is dead (unreachable)
- Not a correctness bug, just dead code that could mislead maintainers

Trace
1. Call `XFRMIfNameAndID("st0")` → stIndex=0, no dot → unit=0 (default) → ifID = 0<<16 | (0+1) = 1 → returns ("st0", 1) — `ifID==0` not reached
2. Call `XFRMIfNameAndID("st0.0")` → stIndex=0, unit=0 → ifID = 0|1 = 1 — `ifID==0` not reached
3. Call `XFRMIfNameAndID("st0.65534")` → stIndex=0, unit=65534 → ifID = 0|65535 = 65535 — `ifID==0` not reached
4. Call `XFRMIfNameAndID("st0.65535")` → unit=65535 → rejected by `unit >= 0xFFFF` → returns "", 0 at line 30-32, never reaches line 35
5. Maximum: `XFRMIfNameAndID("st65535.65534")` → ifID = 0xFFFF<<16 | 65535 = 0xFFFFFFFF — non-zero, returns correctly

Refutation attempt
N/A — this is a Low/cosmetic finding, not High/Critical, so formal refutation attempt not required per contract. However, verified: stIndex cannot be negative (rejected), unit cannot be -1 (default is 0, explicit negative rejected), so unit+1 cannot be 0, so ifID cannot be 0.

HPC/invariant check
N/A

Why it matters
Dead code that appears to guard against a real condition can mislead future maintainers. If the `ifID == 0` sentinel semantics change (e.g., ifID 0 becomes valid for some future use), someone might think this guard is reachable and reason incorrectly about control flow.

Fix direction
Remove the dead `if ifID == 0` block (lines 35-37), or add a comment `// belt-and-braces: ifID is always >= 1 for valid stIndex/unit (unit+1 in [1,65535])` to clarify intent. No functional change required.

Labels
code-quality, dead-code

Dedup note
Not in dedup index. No entry covers XFRM if_id computation or dead-code cleanup.

---

## Negative results (required for coverage proof)

All 116 files reviewed. Each module explicitly checked for: correctness/security bugs, integer truncation, bracket-list handling, zone/VLAN completeness, fail-closed validation, feature gaps.

- schema.go: schemaNode type, setSchema root, isScalarValueLeaf guards — no bug
- schema_complete.go: completion reads schema keywords only — no truncation, no bug
- value_type.go: pure enum mapping — no bug
- schema_validators.go: ValidateInteger/Min/Percent/Enum + duration/wire ceilings — all ParseInt 64-bit then range check, no truncation
- schema_validators_cos.go: ValidateRate/ByteSize/Percent/tail validators — correct
- schema_validators_ddns.go: ValidateDDNSHostname LDH+length — correct
- schema_validators_devicemap.go: ValidatePCIAddr/ValidateMAC/DeviceMapLogicalName — correct
- schema_validators_ipsec.go: ValidateDHGroup — correct (no narrowing)
- schema_validators_logging.go: ValidateSyslogSourceInterface — correct
- schema_validators_network.go: ValidateIPAddress/CIDR/PREF64 — all net.Parse with family gates, correct
- schema_validators_routing.go: ValidateBGPHoldTime/RouteFilterArg/RouteDestination/StaticNextHop — correct
- schema_validators_scheduler.go: ValidateTimeOfDay/ValidateDate — time.Parse fixed layouts, correct
- schema_validators_system.go: ValidateCryptHash/ValidateRingEntries — correct
- schema_walk.go: validateMultiValueLeaf (Keys[1:]+Children), validateScalarValueLeaf (trailing-token reject), validateTypedLeaf, validateTailLeaf — all correct, recursion bounded by fixed schema depth
- snmp_clients.go: parseSNMPClients bracket-list+Children+restrict, AllowsSource LPM+restrict+fail-closed — correct
- screen_inventory.go: ScreenChecks (18 entries), ScreenThresholds, ScreenEnabledCheckList nil-safe — correct
- tcp_flags.go: ParseTCPFlagsExpression lex+| rejection+DeMorgan+unknown flag+contradiction — fail-closed correct
- secret.go: Secret redaction MarshalJSON/YAML/UnmarshalJSON sentinel refusal, RedactURL userinfo+query — correct
- reth_show.go: RethShowMaps dual-key, LookupReth/LookupMember, RethShowUnits sorted+v4/v6 split — correct (one Low dead-code note in xfrmi.go)
- tunnelid.go: StableTunnelEndpointID FNV xor-fold intentional/wire-adjacent/MUST NOT CHANGE — correct
- zoneid.go: StableZoneID FNV [1,65533], ZoneIDReservedMin=0xFFFE mirrors Rust, collision 3-view, quarantine — correct
- routinginstanceid.go: StableRoutingInstanceTableID FNV [100000,999999], collision detection, quarantine — correct
- xfrmi.go: XFRMIfNameAndID bounds prevent overflow, max ifID=0xFFFFFFFF fits uint32 — correct (one Low dead-code note)
- tunnelemit.go: EmitTunnelEndpointNames deterministic, SSOT, non-WG src/dst gate, WG lowest-unit — correct
- predefined.go: PredefinedApplications (130+), PredefinedApplicationSets (4), ExpandApplicationSet depth=3+seen, ExpandAddressSet depth=5+visited+seen — correct cycle/depth handling
- types.go: LinuxIfName/InterfaceSlot/RethToPhysical/ResolveReth/Fab/KernelIfName/DHCPLeaseKey — all Atoi→int, no truncation
- types_chassis.go: ChassisConfig/DeviceMapConfig all int — no narrowing
- types_cos.go: CoS types, QueueID uint8 validated 0..255 before cast — safe
- types_interfaces.go: InterfaceConfig/InterfaceUnit, VlanID int 1..4094 — no truncation
- types_routing.go: TunnelConfig.Key uint32 validated 0..4294967295, WgListenPort/KeepaliveSecs uint16 validated 1..65535/0..65535 — safe
- types_security.go: All int fields, PolicyMatch FromZone/ToZone single-string scalar:true rejection — correct
- types_system.go: SystemConfig/UserspaceConfig/SNMP/FlexMatch all types, FlexMatch narrow validated before cast — safe
- All 60+ _test.go files: test-only, reviewed for coverage — no new production bugs

## Dedup check summary

Checked all 60 dedup entries (25 open + 35 closed). No findings duplicate any entry.

- A3-b3-01 (interface-monitor weight): Not in dedup. #4549 (4 LOW cluster/vrrp/ipsec residuals) lists VRRP hop-limit, HA heartbeat IPv4-only, PSK zeroize, election split-brain — not interface-monitor weight. #4434 (CLOSED cluster/vrrp boundary residual) covers RG count uint8, not monitor weight.
- A3-b3-02 (xfrmi dead-code): Not in dedup. Trivial dead-code, not security/correctness.
