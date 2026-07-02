package userspace

import (
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"syscall"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// ruleListFn is the netlink ip-rule enumerator, indirected so tests can
// inject a transient failure and assert it is surfaced (#3772 M9).
var ruleListFn = netlink.RuleList

// buildRouteSnapshots derives the helper FIB from config statics,
// connected prefixes, and ip-rule leak rules, then applies the
// ip-monitoring route overlay (#1827 PR-1b): each overlay entry
// REPLACES the entire (table, family, prefix) entry set — never merges
// next-hops — so an ECMP half-override is impossible by construction.
//
// It returns an error when the kernel ip-rule enumeration fails (#3772
// M9): the synthetic rib-group / next-table leak routes are derived from
// the live ip-rule table, so a transient RuleList failure must fail the
// whole snapshot build closed (the apply path then retains the prior
// dataplane state) rather than silently emitting a PARTIAL snapshot that
// drops every route-leak route for that family while the kernel/FRR leak
// path stays up — a divergence with no signal. Mirrors #3731's
// surface-don't-swallow contract on the RuleAdd (write) side.
func buildRouteSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot, overlay []config.RouteOverlayEntry) ([]RouteSnapshot, error) {
	if cfg == nil {
		return nil, nil
	}
	out := make([]RouteSnapshot, 0)
	seen := make(map[string]struct{})
	addSnapshot := func(snap RouteSnapshot) {
		// #3770 (H8): the dedupe key MUST include Discard and Preference.
		// A discard (blackhole) route and a normal route to the same prefix
		// are DISTINCT forwarding decisions — omitting Discard let one
		// silently hide the other. Two routes differing only in preference
		// (e.g. a static next-table route at its configured preference and
		// the kernel ip-rule mirror at preference 0) collided on the old key
		// and the second was dropped before the Rust FIB could apply its
		// preference tie-break (fib.rs sort_routes).
		key := fmt.Sprintf("%s|%s|%s|%s|%s|%t|%d",
			snap.Table, snap.Family, snap.Destination,
			strings.Join(snap.NextHops, ","), snap.NextTable,
			snap.Discard, snap.Preference)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, snap)
	}
	addRoutes := func(table, family string, routes []*config.StaticRoute) {
		for _, route := range routes {
			if route == nil {
				continue
			}
			tableName, familyName := normalizeRouteSnapshotFamily(table, family, route.Destination)
			snap := RouteSnapshot{
				Table:       tableName,
				Family:      familyName,
				Destination: route.Destination,
				Discard:     route.Discard,
				NextTable:   route.NextTable,
				Preference:  route.Preference,
			}
			for _, nh := range route.NextHops {
				switch {
				case nh.Address != "" && nh.Interface != "":
					snap.NextHops = append(snap.NextHops, nh.Address+"@"+nh.Interface)
				case nh.Address != "":
					snap.NextHops = append(snap.NextHops, nh.Address)
				case nh.Interface != "":
					snap.NextHops = append(snap.NextHops, "@"+nh.Interface)
				}
			}
			addSnapshot(snap)
		}
	}
	interfaceTablesV4, interfaceTablesV6 := buildInterfaceRouteTables(cfg)
	addConnectedRoutes := func(family, table string, prefixes []string) {
		for _, prefix := range prefixes {
			snap := RouteSnapshot{
				Table:       table,
				Family:      family,
				Destination: prefix,
			}
			addSnapshot(snap)
		}
	}
	addRoutes("inet.0", "inet", cfg.RoutingOptions.StaticRoutes)
	addRoutes("inet6.0", "inet6", cfg.RoutingOptions.Inet6StaticRoutes)

	if len(cfg.RoutingInstances) > 0 {
		insts := make([]*config.RoutingInstanceConfig, 0, len(cfg.RoutingInstances))
		for _, ri := range cfg.RoutingInstances {
			if ri != nil {
				insts = append(insts, ri)
			}
		}
		sort.Slice(insts, func(i, j int) bool { return insts[i].Name < insts[j].Name })
		for _, ri := range insts {
			addRoutes(ri.Name+".inet.0", "inet", ri.StaticRoutes)
			addRoutes(ri.Name+".inet6.0", "inet6", ri.Inet6StaticRoutes)
		}
	}
	for _, iface := range interfaces {
		if iface.Name == "" {
			continue
		}
		v4Table := interfaceTablesV4[iface.Name]
		if v4Table == "" {
			v4Table = "inet.0"
		}
		v6Table := interfaceTablesV6[iface.Name]
		if v6Table == "" {
			v6Table = "inet6.0"
		}
		v4Prefixes, v6Prefixes := connectedPrefixesForInterface(iface)
		addConnectedRoutes("inet", v4Table, v4Prefixes)
		addConnectedRoutes("inet6", v6Table, v6Prefixes)
	}

	// Add synthetic routes for ip rule entries that implement inter-VRF
	// route leaking (rib-groups, next-table). These rules send traffic
	// matching a destination prefix to a different routing table.
	// Without these, the userspace FIB can't cross-reference VRF tables.
	//
	// #3768 (H6): key the map on the BARE routing-instance name and derive
	// the family-specific next-table name (".inet.0" vs ".inet6.0") per
	// family INSIDE the loop below. The old map baked in "<inst>.inet.0"
	// unconditionally and the AF_INET6 pass reused it verbatim, so an IPv6
	// ip-rule leaking e.g. 2001:db8:1::/48 into instance "blue" emitted
	// RouteSnapshot{Table:"inet6.0", Family:"inet6", NextTable:"blue.inet.0"}.
	// The Rust FIB keys routes_v6 as canonical_route_table(table, true) =
	// "blue.inet6.0", so the v6 next-table recursion into "blue.inet.0"
	// missed -> NoRoute -> leaked IPv6 traffic blackholed. Note that
	// normalizeRouteSnapshotFamily canonicalizes static-route tables but is
	// NOT applied to these synthetic ip-rule leak snapshots.
	tableIDToInst := make(map[int]string)
	for _, inst := range cfg.RoutingInstances {
		if inst != nil && inst.TableID > 0 {
			tableIDToInst[inst.TableID] = inst.Name
		}
	}
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		rules, err := ruleListFn(family)
		if err != nil {
			// #3772 (M9): do NOT swallow. A partial snapshot missing this
			// family's route-leak routes would blackhole or policy-bypass
			// inter-VRF traffic that the kernel/FRR still routes.
			return nil, fmt.Errorf("route snapshot: list ip-rules for family %d: %w", family, err)
		}
		for _, rule := range rules {
			if rule.Dst == nil || rule.Table <= 0 {
				continue
			}
			instName, ok := tableIDToInst[rule.Table]
			if !ok {
				continue
			}
			familyStr := "inet"
			mainTable := "inet.0"
			nextTable := instName + ".inet.0"
			if family == syscall.AF_INET6 {
				familyStr = "inet6"
				mainTable = "inet6.0"
				nextTable = instName + ".inet6.0"
			}
			addSnapshot(RouteSnapshot{
				Table:       mainTable,
				Family:      familyStr,
				Destination: rule.Dst.String(),
				NextTable:   nextTable,
			})
		}
	}

	out = applyRouteOverlay(out, overlay)

	// #3770 (M10): stable sort with a TOTAL order. The old comparator
	// keyed only on Table/Family/Destination, so two same-prefix routes
	// (distinct after the H8 dedupe fix, e.g. a next-table leak and its
	// ip-rule mirror, or a discard and a connected route) compared equal
	// and their relative order followed the non-deterministic build input
	// order (map iteration, kernel ip-rule order) under an UNSTABLE sort —
	// producing spurious snapshot-to-snapshot diffs and ECMP-member churn
	// that re-installed the FIB for no config change. Tie-break on
	// next-hops, next-table, discard, then preference so the wire order is
	// a deterministic function of content alone.
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Table != b.Table {
			return a.Table < b.Table
		}
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Destination != b.Destination {
			return a.Destination < b.Destination
		}
		an, bn := strings.Join(a.NextHops, ","), strings.Join(b.NextHops, ",")
		if an != bn {
			return an < bn
		}
		if a.NextTable != b.NextTable {
			return a.NextTable < b.NextTable
		}
		if a.Discard != b.Discard {
			// Non-discard (false) sorts before discard (true).
			return b.Discard
		}
		return a.Preference < b.Preference
	})
	return out, nil
}

// applyRouteOverlay folds the winner-resolved ip-monitoring overlay
// into the route set: for each entry, every existing snapshot for the
// same (table, family, canonical prefix) is REMOVED (whole-entry
// replacement, including all ECMP next-hops) and the single overlay
// route is appended.
func applyRouteOverlay(routes []RouteSnapshot, overlay []config.RouteOverlayEntry) []RouteSnapshot {
	if len(overlay) == 0 {
		return routes
	}
	type key struct{ table, family, dest string }
	replaced := make(map[key]RouteSnapshot, len(overlay))
	for _, entry := range overlay {
		table, family := overlayTableFamily(entry)
		dest := canonicalRoutePrefix(entry.Destination)
		if dest == "" {
			continue
		}
		replaced[key{table, family, dest}] = RouteSnapshot{
			Table:       table,
			Family:      family,
			Destination: dest,
			NextHops:    []string{entry.NextHop},
			// #3770 (M7): the ip-monitoring overlay injects the documented
			// Static/1 route (route preference 1, PreferredRoute contract in
			// pkg/config/types_system.go). Leaving it at 0 made the Rust FIB
			// sort it as MORE preferred than the documented value and diverged
			// from the FRR managed-section render (distance-1 static).
			Preference: 1,
		}
	}
	out := make([]RouteSnapshot, 0, len(routes)+len(replaced))
	for _, snap := range routes {
		k := key{snap.Table, snap.Family, canonicalRoutePrefix(snap.Destination)}
		if _, gone := replaced[k]; gone {
			continue
		}
		out = append(out, snap)
	}
	for _, snap := range replaced {
		out = append(out, snap)
	}
	return out
}

// overlayTableFamily maps an overlay entry to its snapshot table and
// family names ("<ri>.inet.0" / "inet6.0" etc.).
func overlayTableFamily(entry config.RouteOverlayEntry) (string, string) {
	family := "inet"
	table := "inet.0"
	if strings.Contains(entry.Destination, ":") {
		family = "inet6"
		table = "inet6.0"
	}
	if entry.RoutingInstance != "" {
		table = entry.RoutingInstance + "." + table
	}
	return table, family
}

// canonicalRoutePrefix mask-normalizes a CIDR for overlay matching and
// returns "" when the input does not parse as a CIDR (#3772 M8). The
// caller in applyRouteOverlay treats "" as "skip this entry", so an
// overlay destination that fails to parse is dropped rather than being
// injected into the FIB verbatim as a garbage prefix. Previously the
// function returned the raw string, contradicting this contract and its
// own doc comment, and let a malformed overlay destination through.
func canonicalRoutePrefix(s string) string {
	_, n, err := net.ParseCIDR(s)
	if err != nil || n == nil {
		return ""
	}
	return n.String()
}

func buildInterfaceRouteTables(cfg *config.Config) (map[string]string, map[string]string) {
	v4 := make(map[string]string)
	v6 := make(map[string]string)
	if cfg == nil {
		return v4, v6
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		for _, ifname := range ri.Interfaces {
			if ifname == "" {
				continue
			}
			v4[ifname] = ri.Name + ".inet.0"
			v6[ifname] = ri.Name + ".inet6.0"
		}
	}
	return v4, v6
}

// buildInterfaceRoutingInstances maps each interface (config name, e.g.
// "ge-0-0-1.80") to the routing-instance it belongs to. The default
// instance is the empty string. This mirrors buildInterfaceRouteTables'
// membership lookup, but carries the bare instance NAME so the Rust
// dataplane can scope its rebuilt-from-interface connected routes to the
// owning routing table (#2388): without it, the Rust connected store is
// global and a per-table (VRF / next-table) FIB lookup can match a
// connected prefix owned by a different routing-instance.
func buildInterfaceRoutingInstances(cfg *config.Config) map[string]string {
	out := make(map[string]string)
	if cfg == nil {
		return out
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		for _, ifname := range ri.Interfaces {
			if ifname == "" {
				continue
			}
			out[ifname] = ri.Name
		}
	}
	return out
}

func connectedPrefixesForInterface(iface InterfaceSnapshot) ([]string, []string) {
	var v4 []string
	var v6 []string
	for _, addr := range iface.Addresses {
		if addr.Scope != 0 && addr.Scope != int(netlink.SCOPE_UNIVERSE) {
			continue
		}
		ip, network, err := net.ParseCIDR(addr.Address)
		if err != nil || network == nil {
			continue
		}
		ones, bits := network.Mask.Size()
		if ones <= 0 || ones == bits {
			continue
		}
		network.IP = ip.Mask(network.Mask)
		prefix := network.String()
		switch addr.Family {
		case "inet":
			v4 = append(v4, prefix)
		case "inet6":
			if ip.IsLinkLocalUnicast() {
				continue
			}
			v6 = append(v6, prefix)
		}
	}
	slices.Sort(v4)
	slices.Sort(v6)
	return slices.Compact(v4), slices.Compact(v6)
}

func normalizeRouteSnapshotFamily(table, family, destination string) (string, string) {
	isIPv6 := strings.Contains(destination, ":")
	if isIPv6 {
		family = "inet6"
		switch {
		case table == "inet.0":
			table = "inet6.0"
		case strings.HasSuffix(table, ".inet.0"):
			table = strings.TrimSuffix(table, ".inet.0") + ".inet6.0"
		}
		return table, family
	}
	family = "inet"
	switch {
	case table == "inet6.0":
		table = "inet.0"
	case strings.HasSuffix(table, ".inet6.0"):
		table = strings.TrimSuffix(table, ".inet6.0") + ".inet.0"
	}
	return table, family
}
