package userspace

import (
	"fmt"
	"log/slog"
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
		// #6568 (member 1): the destination must reach the wire as something
		// the Rust FIB can PARSE. `populate_routes` (forwarding_build/fib.rs)
		// tries `Ipv4Net` then `Ipv6Net` and, before this, fell off the end of
		// the loop body when both failed — no Err, no counter, no log — at a
		// boundary whose whole #2409/#2410/#3771 contract is "no silent skips".
		//
		// That is a traffic FAIL-OPEN for a discard/blackhole route, not the
		// low-materiality residual it was filed as. `ipnet`'s parsers REQUIRE a
		// prefix length, and nothing in the config compiler validates the
		// destination, so measured: `route 10.0.0.1 discard`,
		// `route 2001:db8::1 discard` and `route default discard` all commit,
		// all ship, and all vanish in the helper — traffic then longest-prefix
		// matches a LESS-SPECIFIC route (typically the default) and is
		// FORWARDED where the operator asked for it to be dropped.
		//
		// A bare host address is normalised to its /32 or /128 host prefix,
		// which is what the operator meant and what the kernel/FRR path already
		// does with it. Anything still unparseable is dropped HERE, loudly, so
		// it never reaches the helper: the operator gets a diagnostic naming
		// the route instead of a silent forwarding hole. The Rust side now
		// fails the snapshot closed on the same condition as defence in depth.
		if dest, ok := routeDestinationForWire(snap.Destination); ok {
			snap.Destination = dest
		} else {
			slog.Warn("dropping route with an unusable destination from the "+
				"helper FIB: it is neither a CIDR prefix nor a bare IP "+
				"address, so the userspace dataplane cannot install it "+
				"(#6568). Traffic to it will follow a less-specific route",
				"destination", snap.Destination, "table", snap.Table,
				"family", snap.Family, "discard", snap.Discard)
			return
		}
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
	// #6467: the kernel programs GLOBAL next-table leaks as ip rules capped at
	// config.NextTableRuleWindow entries (pkg/routing nextTableManager.Apply
	// iterates v4 then v6 with a single shared priority counter). The two global
	// addRoutes calls below (v4 then v6) share this counter so the userspace FIB
	// mirror truncates the SAME tail the kernel drops — otherwise leak #101+
	// would resolve into the target VRF on the AF_XDP fast path while a slow-path
	// (XDP_PASS / IPsec-reinjected / non-native-XDP fabric) packet resolves in
	// the main table, a kernel/dataplane verdict split for the same flow.
	nextTableLeakCount := 0
	// #6467 fold: the applier (pkg/routing nextTableManager.Apply) only installs
	// an ip rule — and only advances its window counter (prio++) — for a global
	// next-table route whose target names a DEFINED routing instance AND whose
	// destination parses as a CIDR; it `continue`s otherwise. The FIB mirror MUST
	// apply the SAME eligibility. Otherwise a dangling (unknown-instance) or
	// unparseable route consumes a FIB window slot and publishes a ghost leak the
	// kernel never installs — squeezing a valid leak out of the window (FIB
	// missing a leak the kernel HAS) while carrying a ghost the kernel LACKS.
	// Build the defined-instance name set once, mirroring the applier's tableIDs
	// map (keyed by instance name, membership-only — a TableID value is not
	// required, matching `tableIDs[sr.NextTable]` returning ok for any defined
	// instance).
	definedInstances := make(map[string]struct{}, len(cfg.RoutingInstances))
	for _, inst := range cfg.RoutingInstances {
		if inst != nil {
			definedInstances[inst.Name] = struct{}{}
		}
	}
	addRoutes := func(table, family string, routes []*config.StaticRoute, perInstance bool) {
		for _, route := range routes {
			if route == nil {
				continue
			}
			// #5830: a `next-table` authored UNDER a routing-instance is NOT
			// programmed on the kernel/FRR forwarding plane — daemon_apply feeds
			// only the GLOBAL routing-options statics to ApplyNextTableRules, the
			// FRR renderer emits nothing for a NextTable route, and the kernel
			// ip-rule leak carries no source-table scoping. Publishing it here as
			// a live per-instance NextTable route made the userspace FIB leak
			// traffic the kernel/FRR view never routes — a control-plane/data-
			// plane split-brain. Skip it so both planes agree the per-instance
			// next-table is ABSENT. The commit-time gate
			// (validateNextTableTargetReferencesStrict, #5830) hard-rejects such a
			// config; this companion drop keeps a tolerantly-loaded / peer-synced
			// legacy config (its reject downgraded to a warning, #1960 no-brick)
			// from leaking in the userspace dataplane. GLOBAL next-table
			// (perInstance == false) IS programmed via ip rule and stays
			// published so the Rust FIB can cross-reference the target table.
			if perInstance && route.NextTable != "" {
				continue
			}
			// #6467: cap the GLOBAL next-table leaks the FIB publishes at the
			// same window the kernel applier installs (config.NextTableRuleWindow),
			// counting v4 then v6 in the same order as ApplyNextTableRules. A
			// route past the cap is dropped here just as the kernel drops the
			// ip rule past prio nextTableRulePriority+maxNextTableRules, so the
			// userspace FIB never carries a next-table leak the kernel does not.
			// Only GLOBAL next-table routes are programmed as ip rules (the
			// per-instance case is skipped above), so this is the only leak class
			// that must be bounded here.
			if !perInstance && route.NextTable != "" {
				// Eligibility gate mirroring the applier (rules.go ~136-147): an
				// unknown-instance target or an unparseable destination installs no
				// kernel ip rule and consumes no window slot there, so skip it here
				// too — no ghost snapshot, no window-slot consumption. Only an
				// eligible route counts against and publishes into the capped window.
				if _, ok := definedInstances[route.NextTable]; !ok {
					continue
				}
				if _, _, err := net.ParseCIDR(route.Destination); err != nil {
					continue
				}
				if nextTableLeakCount >= config.NextTableRuleWindow {
					continue
				}
				nextTableLeakCount++
			}
			tableName, familyName := normalizeRouteSnapshotFamily(table, family, route.Destination)
			base := RouteSnapshot{
				Table:       tableName,
				Family:      familyName,
				Destination: route.Destination,
				// #5298: a `reject` route drops on the AF_XDP fast path the same
				// way `discard` does. Without an entry in the userspace FIB, a
				// reject prefix would longest-prefix-match a less-specific route
				// (e.g. the default) and forward — the identical fail-wide the
				// FRR/kernel reject route closes. Fold reject into the helper's
				// silent-drop disposition (fail-closed). The ICMP-unreachable
				// distinction (reject vs discard) is emitted by the kernel/FRR
				// reject route today; a userspace-generated ICMP unreachable is a
				// follow-up that would need a dedicated RouteSnapshot field.
				Discard:    route.Discard || route.Reject,
				NextTable:  route.NextTable,
				Preference: route.Preference,
			}
			// #5678: group next-hops by their EFFECTIVE preference. A
			// qualified-next-hop carries its own admin distance (#3871
			// HasPreference — the Junos floating-static idiom: a primary
			// next-hop plus a less-preferred backup); a plain next-hop uses the
			// route-level preference. Emit ONE snapshot per distinct preference
			// so a backup lowers as a SEPARATE, higher-preference standby route,
			// NOT co-installed with the primary as an equal-cost ECMP member.
			// The Rust FIB tie-breaks same-prefix routes by ascending
			// preference (#2390 sort_routes) and selects the lowest via
			// first-match lookup, holding the higher-preference backup as a
			// standby entry — so folding the backup into the primary's next-hop
			// list load-balanced traffic across both instead of preferring the
			// primary (the #5678 silent routing-semantics change). Next-hops
			// that share a preference (a plain `next-hop [ a b ]` list, or
			// qualified next-hops at the SAME distance) stay a single
			// equal-cost ECMP snapshot — no regression for real ECMP. Mirrors
			// the FRR renderer (pkg/frr/config_render.go), which emits one `ip
			// route` line per next-hop at dist = nh.Preference when
			// HasPreference else the route-level distance.
			type prefGroup struct {
				preference int
				nextHops   []string
			}
			order := make([]int, 0, len(route.NextHops))
			groups := make(map[int]*prefGroup)
			for _, nh := range route.NextHops {
				var target string
				switch {
				case nh.Address != "" && nh.Interface != "":
					target = nh.Address + "@" + nh.Interface
				case nh.Address != "":
					target = nh.Address
				case nh.Interface != "":
					target = "@" + nh.Interface
				default:
					continue
				}
				pref := route.Preference
				if nh.HasPreference {
					pref = nh.Preference
				}
				g, ok := groups[pref]
				if !ok {
					g = &prefGroup{preference: pref}
					groups[pref] = g
					order = append(order, pref)
				}
				g.nextHops = append(g.nextHops, target)
			}
			if len(order) == 0 {
				// No forwarding next-hops (discard / reject / next-table, or
				// every next-hop had an empty target): emit the base
				// disposition unchanged so the negative-route / leak entry is
				// preserved.
				addSnapshot(base)
				continue
			}
			for _, pref := range order {
				snap := base
				snap.Preference = groups[pref].preference
				snap.NextHops = groups[pref].nextHops
				addSnapshot(snap)
			}
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
	addRoutes("inet.0", "inet", cfg.RoutingOptions.StaticRoutes, false)
	addRoutes("inet6.0", "inet6", cfg.RoutingOptions.Inet6StaticRoutes, false)

	if len(cfg.RoutingInstances) > 0 {
		insts := make([]*config.RoutingInstanceConfig, 0, len(cfg.RoutingInstances))
		for _, ri := range cfg.RoutingInstances {
			if ri != nil {
				insts = append(insts, ri)
			}
		}
		sort.Slice(insts, func(i, j int) bool { return insts[i].Name < insts[j].Name })
		for _, ri := range insts {
			addRoutes(ri.Name+".inet.0", "inet", ri.StaticRoutes, true)
			addRoutes(ri.Name+".inet6.0", "inet6", ri.Inet6StaticRoutes, true)
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
			// A Dst-less rule (`from all lookup <table>`) cannot be
			// represented as a per-prefix NextTable leak (it would mean
			// "leak the whole table"), so it is skipped here. The rib-group
			// import leak installs per-prefix `to <prefix> lookup
			// <sourceTable>` rules (pkg/routing, #3876) that DO carry a Dst,
			// so they are auto-captured by this loop as NextTable leaks into
			// main — no change to this skip is needed for the fix.
			if rule.Dst == nil || rule.Table <= 0 {
				continue
			}
			// #4479 (opus-172 M-2): SKIP policy-based-routing / filter-based-
			// forwarding rules. xpf installs FBF `then routing-instance`
			// filter actions as ip rules in the PBR priority band
			// (config.PBRRulePriorityBase, 31000-31999; pkg/routing
			// pbrRulePriority) that carry match SELECTORS — source/dest
			// address, DSCP, protocol, source/dest port — IN ADDITION to a
			// Dst that happens to point at a routing-instance table. This
			// synthetic snapshot can only express a bare per-prefix NextTable
			// leak, so ingesting a PBR rule here would DROP every selector and
			// widen a constrained, source-scoped steer into an unconditional
			// dst-only VRF leak — the exact fail-open the kernel FBF path was
			// hardened against in #3730. Fail CLOSED instead: leave the PBR
			// rule out of the userspace FIB entirely. The kernel still applies
			// the real, fully-qualified PBR rule (and the userspace filter
			// path enforces the term), so the leak is not lost — it just is
			// not wrongly widened. Only xpf's own pure per-prefix leak bands
			// (next-table 100-199, rib-group per-prefix import 30000-30999)
			// carry a Dst with no selectors and are safe to mirror below.
			if rule.Priority >= config.PBRRulePriorityBase &&
				rule.Priority < config.PBRRulePriorityBase+config.PBRRuleWindow {
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
// routeDestinationForWire returns the destination in the form the Rust FIB can
// parse, and whether it is usable at all (#6568).
//
//   - a valid CIDR prefix passes through UNCHANGED. It is deliberately not
//     re-canonicalised: masking a host-bearing prefix such as 10.0.0.5/24 down
//     to 10.0.0.0/24 would change both the installed prefix and the
//     addSnapshot dedupe key, which is a behaviour change this fix has no
//     business making.
//   - a BARE IP address gains its host prefix (/32 or /128). `ipnet`'s
//     Ipv4Net/Ipv6Net parsers require a prefix length, so a bare address is
//     exactly the plausible operator input that vanished silently.
//   - anything else (a typo, or the Junos `default` keyword, which the config
//     compiler accepts verbatim) is unusable and reports false.
func routeDestinationForWire(dest string) (string, bool) {
	if _, _, err := net.ParseCIDR(dest); err == nil {
		return dest, true
	}
	if ip := net.ParseIP(dest); ip != nil {
		// The family test is the TEXT, not ip.To4(): net.IP.To4() folds an
		// IPv4-MAPPED IPv6 address (::ffff:10.0.0.1) to its 4-byte form, so
		// keying on it would emit "::ffff:10.0.0.1/32" — a v6 literal carrying
		// a v4 prefix length, which parses as neither. Colon-means-v6 is the
		// same discriminator normalizeRouteSnapshotFamily already uses on this
		// exact field, so the two cannot disagree about a route's family.
		if strings.Contains(dest, ":") {
			return dest + "/128", true
		}
		if ip.To4() != nil {
			return dest + "/32", true
		}
		return "", false
	}
	return "", false
}

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
			// #5878 phase 2: canonicalize the .<unit> suffix so ge-0/0/0.01 binds
			// the same route table as ge-0/0/0.1 (the per-unit snapshot consumer
			// keys these maps by the canonical "%s.%d" unit name).
			key := config.CanonicalInterfaceUnitRef(ifname)
			v4[key] = ri.Name + ".inet.0"
			v6[key] = ri.Name + ".inet6.0"
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
			// #5878 phase 2: canonicalize the .<unit> suffix so ge-0/0/0.01 binds
			// the same routing-instance as ge-0/0/0.1 (the per-unit snapshot
			// consumer keys this map by the canonical "%s.%d" unit name).
			out[config.CanonicalInterfaceUnitRef(ifname)] = ri.Name
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
		// Mask-to-network + skip-host + skip-link-local is factored into
		// config.ConnectedNetworkPrefix so the rib-group per-prefix leak
		// (pkg/routing, #3876) derives the identical connected-prefix set
		// from the config addresses and the ip rules it installs match the
		// connected routes this FIB carries in the source table.
		prefix, family, ok := config.ConnectedNetworkPrefix(addr.Address)
		if !ok {
			continue
		}
		switch family {
		case "inet":
			v4 = append(v4, prefix)
		case "inet6":
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
