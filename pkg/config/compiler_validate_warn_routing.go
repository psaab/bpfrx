package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateDHCPRelayParityWarnings emits WARN-only commit-time advisories for
// the #4309 (fable-review-167 I-4) DHCP relay override knobs that are
// accepted-only. maximum-hop-count is ENFORCED (the relay's hop limit) so it
// gets no advisory; forward-only and relay-agent-option are typed + compiled
// so they stop silently vanishing but the relay already behaves as they
// request (it forwards statelessly and always inserts Option 82), so the
// advisory tells the operator the knob is accepted and matches the default.
// Groups are reported in sorted order for a deterministic message.
func validateDHCPRelayParityWarnings(cfg *Config) []string {
	relay := cfg.ForwardingOptions.DHCPRelay
	if relay == nil || len(relay.Groups) == 0 {
		return nil
	}
	names := make([]string, 0, len(relay.Groups))
	for name := range relay.Groups {
		names = append(names, name)
	}
	sort.Strings(names)

	var warnings []string
	for _, name := range names {
		g := relay.Groups[name]
		if g == nil {
			continue
		}
		var knobs []string
		if g.ForwardOnly {
			knobs = append(knobs, "forward-only (the relay already forwards statelessly)")
		}
		if g.RelayAgentOption {
			knobs = append(knobs, "relay-agent-option (Option 82 circuit-id is always inserted)")
		}
		if len(knobs) > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"forwarding-options dhcp-relay group %s: %s configured but accepted-only — accepted and matches the relay's default behavior (#4309)",
				name, strings.Join(knobs, ", ")))
		}
	}
	return warnings
}

// validateInterfaceParityWarnings emits WARN-only commit-time advisories for
// the #4308 (fable-review-167 I-3) interface knobs. Each is typed in the
// schema and compiled into the typed config so it no longer silently vanishes,
// but the runtime does not enforce it yet: native-vlan-id needs the QinQ
// tagging pipeline (#2354); unnumbered-address needs a networkd borrow-address
// implementation; the gratuitous-ARP knobs map to per-interface sysctls the
// apply path does not write; targeted-broadcast needs dataplane directed-
// broadcast forwarding. The advisory mirrors the #2078 accepted-only doctrine
// so an operator who sets one is not misled into believing it has effect.
// Interfaces are reported in sorted order for a deterministic message.
func validateInterfaceParityWarnings(cfg *Config) []string {
	if cfg.Interfaces.Interfaces == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	var warnings []string
	for _, name := range names {
		ifc := cfg.Interfaces.Interfaces[name]
		if ifc == nil {
			continue
		}
		var knobs []string
		if ifc.NativeVlanID != 0 {
			knobs = append(knobs, "native-vlan-id")
		}
		if ifc.GratuitousARPReply {
			knobs = append(knobs, "gratuitous-arp-reply")
		}
		if ifc.NoGratuitousARPRequest {
			knobs = append(knobs, "no-gratuitous-arp-request")
		}
		// family inet knobs live per-unit; report them qualified so the
		// operator can find the offending unit.
		unitNums := make([]int, 0, len(ifc.Units))
		for un := range ifc.Units {
			unitNums = append(unitNums, un)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil {
				continue
			}
			if unit.UnnumberedInet != "" {
				knobs = append(knobs, fmt.Sprintf("unit %d family inet unnumbered-address", un))
			}
			if unit.TargetedBroadcast {
				knobs = append(knobs, fmt.Sprintf("unit %d family inet targeted-broadcast", un))
			}
		}
		if len(knobs) > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"interfaces %s: %s configured but accepted-only — typed and stored but not enforced by the runtime yet (parity, #4308)",
				name, strings.Join(knobs, ", ")))
		}
	}
	return warnings
}

// validateIpipTunnelDeadWarning emits the #4788 commit-time advisory for a
// tunnel configured with `mode ipip`. IPIP (ip-in-ip, proto-4/41) is accepted
// and creates a Tuntap routing anchor, but it is NOT implemented in the
// userspace dataplane (#4785, PLAN-DEFERRED): there is no userspace IPIP encap
// or decap stage (unlike GRE), so under anchor-only an inbound proto-4 packet
// is dropped fail-closed and an egress inner packet routed to the IPIP anchor
// classifies as an unknown tunnel mode and drops — the tunnel is silently dead
// in BOTH directions. This advisory surfaces that so an operator is not misled;
// WARN-only, never a reject (valid Junos), mirroring the accepted-only doctrine
// (#2078/#4308/#4309) and honoring #1960 lenient-load.
func validateIpipTunnelDeadWarning(cfg *Config) []string {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	var warnings []string
	advise := func(where string) {
		warnings = append(warnings, fmt.Sprintf(
			"interfaces %s tunnel mode ipip: IPIP (ip-in-ip) is accepted but NOT yet "+
				"implemented in the userspace dataplane (#4785) — the tunnel is created "+
				"but passes NO traffic in either direction (inbound proto-4 is dropped "+
				"fail-closed; an egress inner packet classifies as an unknown tunnel mode "+
				"and drops). Use `mode gre` or `mode wireguard` for a working tunnel.",
			where))
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		if iface.Tunnel != nil && iface.Tunnel.Mode == "ipip" {
			advise(fmt.Sprintf("%q", name))
		}
		unitNums := make([]int, 0, len(iface.Units))
		for u := range iface.Units {
			unitNums = append(unitNums, u)
		}
		sort.Ints(unitNums)
		for _, u := range unitNums {
			unit := iface.Units[u]
			if unit != nil && unit.Tunnel != nil && unit.Tunnel.Mode == "ipip" {
				advise(fmt.Sprintf("%q unit %d", name, u))
			}
		}
	}
	return warnings
}

// validateRoutingRuleWindowWarnings emits commit-time warnings when a
// config would program more next-table or rib-group ip rules than the
// applier's fixed priority window can hold (see pkg/routing/rules.go:
// nextTableRulePriority window of 100, ribGroupRulePriority window of
// 100 split into 50 v4+v6 pairs). The counts here are CONSERVATIVE
// upper bounds computed from the same inputs the applier consumes —
// they intentionally do NOT replicate the applier's exact skip/dedup
// logic (unknown-instance skips, self-only rib-groups, duplicate source
// tables), so they may warn slightly early but never miss a real
// truncation. The runtime accepts the config; the apply-time cap is the
// hard guard against the rule leak.
func validateRoutingRuleWindowWarnings(cfg *Config) []string {
	var warnings []string

	// next-table: the applier feeds it the global inet + inet6 static
	// routes (daemon_apply.go), counting those with a NextTable set.
	const nextTableWindow = 100
	nextTableRoutes := 0
	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		if sr != nil && sr.NextTable != "" {
			nextTableRoutes++
		}
	}
	for _, sr := range cfg.RoutingOptions.Inet6StaticRoutes {
		if sr != nil && sr.NextTable != "" {
			nextTableRoutes++
		}
	}
	if nextTableRoutes > nextTableWindow {
		warnings = append(warnings, fmt.Sprintf(
			"routing-options: %d static routes use next-table, but only %d can be "+
				"programmed as ip rules; routes beyond the limit will be ignored at "+
				"apply time. Reduce the number of next-table routes.",
			nextTableRoutes, nextTableWindow))
	}

	// rib-group (#3876): the applier now programs one ip rule PER CONNECTED
	// PREFIX of each source instance whose interface-routes rib-group imports
	// the main table, into a fixed window of maxRibGroupLeakRules (1000)
	// priorities that clear() scans. Count the connected prefixes the applier
	// would leak and warn if they exceed the window (an over-count against
	// pkg/routing.maxRibGroupLeakRules — kept in lockstep here).
	const ribGroupLeakLimit = 1000
	leakPrefixes := 0
	for _, prefixes := range RibGroupConnectedPrefixes(cfg) {
		leakPrefixes += len(prefixes)
	}
	if leakPrefixes > ribGroupLeakLimit {
		warnings = append(warnings, fmt.Sprintf(
			"routing-options: interface-routes rib-group would leak %d connected "+
				"prefixes as ip rules, but only %d can be programmed; prefixes beyond "+
				"the limit will be ignored at apply time. Reduce the number of "+
				"rib-group-leaked interface prefixes.",
			leakPrefixes, ribGroupLeakLimit))
	}

	return warnings
}

// validateRibGroupLeakWarnings emits commit-time warnings for
// interface-routes rib-group imports the #3876 Phase-1 per-prefix leak
// cannot fully realize, so the operator sees a fail-loud diagnostic instead
// of a silent no-op:
//
//   - A source instance whose rib-group imports the main table but has NO
//     enumerable static connected prefix (DHCP-only / unaddressed member
//     interfaces): the leak installs no ip rule because there is no static
//     prefix to enumerate at commit. (Runtime route-copy for dynamically
//     learned addresses is the deferred Phase-2 mechanism.)
//   - A rib-group importing a NON-MAIN (VRF→VRF) rib: Phase 1 leaks only into
//     the main table; a VRF→VRF import target is not yet installed (Phase 2).
//
// The strict import-rib reference gate
// (validateRibGroupImportRibReferencesStrict) is unchanged; these are
// additional non-fatal WARN diagnostics.
func validateRibGroupLeakWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	ribGroups := cfg.RoutingOptions.RibGroups
	if len(ribGroups) == 0 {
		return nil
	}
	definedInstances := make(map[string]bool, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name != "" {
			definedInstances[ri.Name] = true
		}
	}
	connected := RibGroupConnectedPrefixes(cfg)

	var warnings []string
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		// Classify the union of this instance's v4 + v6 rib-group imports.
		importsMain := false
		var vrfTargets []string
		seenVRF := make(map[string]bool)
		for _, rgName := range []string{ri.InterfaceRoutesRibGroup, ri.InterfaceRoutesRibGroupV6} {
			if rgName == "" {
				continue
			}
			rgDef, ok := ribGroups[rgName]
			if !ok {
				continue // unknown group — the reference gate/warn covers it
			}
			for _, ribName := range rgDef.ImportRibs {
				switch ribTargetKind(ribName, ri.Name, definedInstances) {
				case "main":
					importsMain = true
				case "vrf":
					if !seenVRF[ribName] {
						seenVRF[ribName] = true
						vrfTargets = append(vrfTargets, ribName)
					}
				}
			}
		}

		if importsMain && len(connected[ri.Name]) == 0 {
			warnings = append(warnings, fmt.Sprintf(
				"routing-instance %q: interface-routes rib-group imports the main "+
					"table but the instance has no enumerable static connected prefix "+
					"(DHCP-only or unaddressed member interfaces); no leak ip rule is "+
					"installed. Configure a static interface address to leak, or note "+
					"that dynamically learned addresses are not leaked (Phase 2).",
				ri.Name))
		}
		if len(vrfTargets) > 0 {
			sort.Strings(vrfTargets)
			warnings = append(warnings, fmt.Sprintf(
				"routing-instance %q: interface-routes rib-group imports non-main "+
					"rib(s) [%s] (VRF→VRF import); this is not yet installed and takes "+
					"no effect — only imports into the main table (inet.0/inet6.0) leak "+
					"interface routes today (Phase 2 deferral).",
				ri.Name, strings.Join(vrfTargets, ", ")))
		}
	}
	return warnings
}
