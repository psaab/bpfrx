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

// validateLinkAggregationWarnings emits the accepted-only advisory for
// 802.3ad link aggregation (#6544).
//
// `interfaces ae0 aggregated-ether-options { lacp ...; minimum-links N; }` and
// the member binding `interfaces ge-0/0/1 gigether-options 802.3ad ae0` are
// schema-advertised (tab completion offers them), parse cleanly, and compile
// into `AggregatedEtherOpts` / `LAGParent` on the typed config — and then stop.
// NOTHING reads either field. Measured on the compiled config: an `ae0` with
// `lacp active`, `periodic fast` and `minimum-links 2` plus two members bound
// via `802.3ad ae0` commits with ZERO warnings and yields ZERO bond models
// from `buildFabricBondModels` (pkg/dataplane/compiler_iface.go), so no
// `.netdev` is written, no member gets `Bond=`, no bond device is created, no
// member is enslaved, no LACP runs, and `minimum-links` is not honoured.
//
// The bond machinery itself is NOT missing — `pkg/networkd` generateNetdev
// already emits `Mode=802.3ad` with `LACPTransmitRate` / `TransmitHashPolicy`
// / `MinLinks`, and `pkg/routing/bond.go` reconciles kernel bonds. Both are
// reached ONLY from `fabric-options member-interfaces`, which hard-codes
// `active-backup`. Wiring `ae` into them is real feature work, tracked in the
// parity matrix (`docs/vsrx-gaps.md`, "Interface Redundancy (LAG)").
//
// This advisory is the #2078/#4231/#5804 accepted-only doctrine applied to the
// config grammar: an operator who configures a LAG for bandwidth or redundancy
// is told the feature exists at three independent layers (schema completion, a
// clean commit, and — before #6544 — the documentation) and receives nothing.
// A hard reject was rejected as the posture: `ae` config is inert rather than
// dangerous, and rejecting it would newly brick an already-persisted config
// that carries it (the #1960 no-brick rule).
//
// The consequence gets its own advisory line rather than folding into
// validateInterfaceParityWarnings' generic "typed and stored but not enforced"
// list, following #5804: what the operator loses here is SPECIFIC — the whole
// aggregate, not one knob on a working interface.
func validateLinkAggregationWarnings(cfg *Config) []string {
	if cfg.Interfaces.Interfaces == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	// aeNames: interfaces carrying an aggregated-ether-options body.
	// membersByAE: members bound to a parent via `gigether-options 802.3ad`.
	// A member naming a parent that was never configured still counts — it is
	// just as inert, and staying silent about it would leave the operator's
	// typo invisible on top of the missing feature.
	var aeNames []string
	membersByAE := make(map[string][]string)
	var aeParents []string
	for _, name := range names {
		ifc := cfg.Interfaces.Interfaces[name]
		if ifc == nil {
			continue
		}
		if ifc.AggregatedEtherOpts != nil {
			aeNames = append(aeNames, name)
		}
		if ifc.LAGParent != "" {
			if _, ok := membersByAE[ifc.LAGParent]; !ok {
				aeParents = append(aeParents, ifc.LAGParent)
			}
			membersByAE[ifc.LAGParent] = append(membersByAE[ifc.LAGParent], name)
		}
	}
	if len(aeNames) == 0 && len(aeParents) == 0 {
		return nil
	}
	sort.Strings(aeParents)

	var warnings []string
	if len(aeNames) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"interfaces %s: aggregated-ether-options configured but accepted-only "+
				"— xpf does not implement 802.3ad link aggregation: no bond device "+
				"is created, no member interface is enslaved, no LACP is run, and "+
				"minimum-links is not honoured, so the aggregate carries no traffic "+
				"and provides no redundancy; use chassis-cluster reth interfaces for "+
				"link redundancy (parity, #6544)",
			strings.Join(aeNames, ", ")))
	}
	for _, parent := range aeParents {
		warnings = append(warnings, fmt.Sprintf(
			"interfaces %s: gigether-options 802.3ad %s configured but "+
				"accepted-only — the member binding is stored and never acted on, "+
				"so %s stays a standalone interface and is NOT enslaved to %s "+
				"(parity, #6544)",
			strings.Join(membersByAE[parent], ", "), parent,
			strings.Join(membersByAE[parent], "/"), parent))
	}
	return warnings
}

// Note: the next-table / rib-group ip-rule WINDOW over-subscription check that
// used to live here (validateRoutingRuleWindowWarnings, warn-only) moved to the
// strict commit gate validateRoutingRuleWindowsStrict
// (compiler_validate_strict_routing_windows.go, wired in runUniformGates) in
// #5854: a config that exceeds the applier's fixed 100 next-table / 1000
// rib-group ip-rule windows is now HARD-REJECTED at commit / commit-check
// (silent apply-time truncation = routes claimed but not programmed) and only
// downgraded to a warning on the tolerant load / peer-sync paths. The
// leak-cannot-be-realized advisory below is a DIFFERENT check and is unchanged.

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
