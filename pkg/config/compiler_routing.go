package config

import (
	"fmt"
	"strconv"
	"strings"
)

func compileRoutingOptions(node *Node, ro *RoutingOptionsConfig) error {
	// Parse autonomous-system
	if asNode := node.FindChild("autonomous-system"); asNode != nil {
		if v := nodeVal(asNode); v != "" {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				ro.AutonomousSystem = uint32(n)
			}
		}
	}

	// Parse forwarding-table { export <policy>; }
	if ftNode := node.FindChild("forwarding-table"); ftNode != nil {
		if expNode := ftNode.FindChild("export"); expNode != nil {
			ro.ForwardingTableExport = nodeVal(expNode)
		}
	}

	// Parse rib inet6.0 { static { route ... } }
	// In routing-instances, the rib name is "<instance>.inet6.0" (e.g., "ATT.inet6.0").
	for _, ribNode := range node.FindChildren("rib") {
		ribName := nodeVal(ribNode)
		if ribName == "inet6.0" || strings.HasSuffix(ribName, ".inet6.0") {
			if ribStatic := ribNode.FindChild("static"); ribStatic != nil {
				ro.Inet6StaticRoutes = compileStaticRoutes(ribStatic, ro.Inet6StaticRoutes)
			}
		}
	}

	staticNode := node.FindChild("static")
	if staticNode != nil {
		ro.StaticRoutes = compileStaticRoutes(staticNode, ro.StaticRoutes)
	}

	// Parse rib-groups
	if rgNode := node.FindChild("rib-groups"); rgNode != nil {
		if ro.RibGroups == nil {
			ro.RibGroups = make(map[string]*RibGroup)
		}
		for _, inst := range namedInstances(rgNode.FindChildren("")) {
			rg := &RibGroup{Name: inst.name}
			if irNode := inst.node.FindChild("import-rib"); irNode != nil {
				// import-rib [ rib1 rib2 ... ] or import-rib rib1;
				for i := 1; i < len(irNode.Keys); i++ {
					if irNode.Keys[i] == "[" || irNode.Keys[i] == "]" {
						continue
					}
					rg.ImportRibs = append(rg.ImportRibs, irNode.Keys[i])
				}
				for _, child := range irNode.Children {
					rg.ImportRibs = append(rg.ImportRibs, child.Name())
				}
			}
			ro.RibGroups[rg.Name] = rg
		}
		// Also handle direct children (non-named instances)
		for _, child := range rgNode.Children {
			name := child.Name()
			if _, exists := ro.RibGroups[name]; exists {
				continue
			}
			rg := &RibGroup{Name: name}
			if irNode := child.FindChild("import-rib"); irNode != nil {
				for i := 1; i < len(irNode.Keys); i++ {
					if irNode.Keys[i] == "[" || irNode.Keys[i] == "]" {
						continue
					}
					rg.ImportRibs = append(rg.ImportRibs, irNode.Keys[i])
				}
				for _, child := range irNode.Children {
					rg.ImportRibs = append(rg.ImportRibs, child.Name())
				}
			}
			ro.RibGroups[rg.Name] = rg
		}
	}

	// Parse generate routes (aggregate routes)
	if genNode := node.FindChild("generate"); genNode != nil {
		for _, routeNode := range genNode.FindChildren("route") {
			prefix := nodeVal(routeNode)
			if prefix == "" {
				continue
			}
			gr := &GenerateRoute{Prefix: prefix}
			if policyNode := routeNode.FindChild("policy"); policyNode != nil {
				gr.Policy = nodeVal(policyNode)
			}
			if routeNode.FindChild("discard") != nil {
				gr.Discard = true
			}
			// Also handle inline keys: "route X/Y discard" or "route X/Y policy Z"
			for i := 2; i < len(routeNode.Keys); i++ {
				switch routeNode.Keys[i] {
				case "discard":
					gr.Discard = true
				case "policy":
					if i+1 < len(routeNode.Keys) {
						gr.Policy = routeNode.Keys[i+1]
						i++
					}
				}
			}
			ro.GenerateRoutes = append(ro.GenerateRoutes, gr)
		}
	}

	// Parse global interface-routes { rib-group { inet X; inet6 Y; } }
	if irNode := node.FindChild("interface-routes"); irNode != nil {
		if rgNode := irNode.FindChild("rib-group"); rgNode != nil {
			for _, rgChild := range rgNode.Children {
				switch rgChild.Name() {
				case "inet":
					ro.InterfaceRoutesRibGroup = nodeVal(rgChild)
				case "inet6":
					ro.InterfaceRoutesRibGroupV6 = nodeVal(rgChild)
				}
			}
			// Also handle inline: "rib-group inet NAME" or "rib-group inet6 NAME"
			for i := 1; i < len(rgNode.Keys)-1; i++ {
				switch rgNode.Keys[i] {
				case "inet":
					ro.InterfaceRoutesRibGroup = rgNode.Keys[i+1]
				case "inet6":
					ro.InterfaceRoutesRibGroupV6 = rgNode.Keys[i+1]
				}
			}
		}
	}

	return nil
}

// compileStaticRoutes parses static route entries from a "static" node,
// appending to and returning the updated slice.
func compileStaticRoutes(staticNode *Node, existing []*StaticRoute) []*StaticRoute {
	// Track destination→index so flat "set" duplicates merge into one route.
	destIdx := make(map[string]int)
	for i, sr := range existing {
		destIdx[sr.Destination] = i
	}

	for _, routeInst := range namedInstances(staticNode.FindChildren("route")) {
		route := &StaticRoute{
			Destination: routeInst.name,
			Preference:  5, // default
		}

		// Handle inline keys: "route ::/0 next-hop 2001:db8::1" has all in Keys
		if len(routeInst.node.Children) == 0 && len(routeInst.node.Keys) > 2 {
			for i := 2; i < len(routeInst.node.Keys); i++ {
				switch routeInst.node.Keys[i] {
				case "next-hop":
					if i+1 < len(routeInst.node.Keys) {
						i++
						route.NextHops = append(route.NextHops, NextHopEntry{Address: routeInst.node.Keys[i]})
					}
				case "next-table":
					if i+1 < len(routeInst.node.Keys) {
						i++
						route.NextTable = parseNextTableInstance(routeInst.node.Keys[i])
					}
				case "qualified-next-hop":
					if i+1 < len(routeInst.node.Keys) {
						i++
						nh := NextHopEntry{Address: routeInst.node.Keys[i]}
						// Check for "interface <name>" following the address
						if i+2 < len(routeInst.node.Keys) && routeInst.node.Keys[i+1] == "interface" {
							i += 2
							nh.Interface = routeInst.node.Keys[i]
						}
						route.NextHops = append(route.NextHops, nh)
					}
				case "discard":
					route.Discard = true
				case "preference":
					if i+1 < len(routeInst.node.Keys) {
						i++
						if n, err := strconv.Atoi(routeInst.node.Keys[i]); err == nil {
							route.Preference = n
						}
					}
				}
			}
		}

		// Handle children (hierarchical syntax)
		for _, prop := range routeInst.node.Children {
			switch prop.Name() {
			case "next-hop":
				nh := NextHopEntry{}
				nh.Address = nodeVal(prop)
				// Check children for interface (needed for IPv6 link-local next-hops)
				for _, child := range prop.Children {
					if child.Name() == "interface" {
						nh.Interface = nodeVal(child)
					}
				}
				// Also check inline keys: "next-hop fe80::50 interface reth0.50"
				// has all in Keys rather than Children.
				for j := 2; j < len(prop.Keys)-1; j++ {
					if prop.Keys[j] == "interface" {
						nh.Interface = prop.Keys[j+1]
					}
				}
				route.NextHops = append(route.NextHops, nh)
			case "discard":
				route.Discard = true
			case "preference":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						route.Preference = n
					}
				}
			case "qualified-next-hop":
				nh := NextHopEntry{}
				nh.Address = nodeVal(prop)
				// Check for "interface <name>" among remaining keys
				for j := 2; j < len(prop.Keys)-1; j++ {
					if prop.Keys[j] == "interface" {
						nh.Interface = prop.Keys[j+1]
					}
				}
				// Also check children for flat set syntax
				if ifNode := prop.FindChild("interface"); ifNode != nil {
					nh.Interface = nodeVal(ifNode)
				}
				route.NextHops = append(route.NextHops, nh)
			case "next-table":
				if v := nodeVal(prop); v != "" {
					route.NextTable = parseNextTableInstance(v)
				}
			}
		}

		// Merge routes with the same destination (flat "set" syntax creates duplicates).
		if idx, exists := destIdx[route.Destination]; exists {
			existingRoute := existing[idx]
			existingRoute.NextHops = append(existingRoute.NextHops, route.NextHops...)
			if route.Discard {
				existingRoute.Discard = true
			}
			if route.Preference != 5 {
				existingRoute.Preference = route.Preference
			}
			if route.NextTable != "" {
				existingRoute.NextTable = route.NextTable
			}
		} else {
			destIdx[route.Destination] = len(existing)
			existing = append(existing, route)
		}
	}
	return existing
}

// parseNextTableInstance extracts the routing instance name from a Junos
// next-table value like "Comcast-GigabitPro.inet.0" → "Comcast-GigabitPro".
func parseNextTableInstance(table string) string {
	// Strip .inet.0 or .inet6.0 suffix to get the routing instance name
	if idx := strings.Index(table, ".inet"); idx > 0 {
		return table[:idx]
	}
	return table
}

func compileRoutingInstances(node *Node, cfg *Config) error {
	// Auto-assign VRF table IDs starting from 100
	tableID := 100

	for _, child := range node.Children {
		if child.IsLeaf || len(child.Keys) == 0 {
			continue
		}
		instanceName := child.Keys[0]
		ri := &RoutingInstanceConfig{
			Name:    instanceName,
			TableID: tableID,
		}
		tableID++

		for _, prop := range child.Children {
			switch prop.Name() {
			case "description":
				ri.Description = nodeVal(prop)
			case "instance-type":
				ri.InstanceType = nodeVal(prop)
			case "interface":
				if v := nodeVal(prop); v != "" {
					ri.Interfaces = append(ri.Interfaces, v)
				}
			case "routing-options":
				var ro RoutingOptionsConfig
				if err := compileRoutingOptions(prop, &ro); err != nil {
					return fmt.Errorf("instance %s routing-options: %w", instanceName, err)
				}
				ri.StaticRoutes = ro.StaticRoutes
				ri.Inet6StaticRoutes = ro.Inet6StaticRoutes
				// Parse interface-routes rib-group
				if irNode := prop.FindChild("interface-routes"); irNode != nil {
					if rgNode := irNode.FindChild("rib-group"); rgNode != nil {
						for _, rgChild := range rgNode.Children {
							switch rgChild.Name() {
							case "inet":
								ri.InterfaceRoutesRibGroup = nodeVal(rgChild)
							case "inet6":
								ri.InterfaceRoutesRibGroupV6 = nodeVal(rgChild)
							}
						}
						// Also handle inline: "rib-group inet NAME"
						for i := 1; i < len(rgNode.Keys)-1; i++ {
							switch rgNode.Keys[i] {
							case "inet":
								ri.InterfaceRoutesRibGroup = rgNode.Keys[i+1]
							case "inet6":
								ri.InterfaceRoutesRibGroupV6 = rgNode.Keys[i+1]
							}
						}
					}
				}
			case "protocols":
				var proto ProtocolsConfig
				if err := compileProtocols(prop, &proto); err != nil {
					return fmt.Errorf("instance %s protocols: %w", instanceName, err)
				}
				ri.OSPF = proto.OSPF
				ri.OSPFv3 = proto.OSPFv3
				ri.BGP = proto.BGP
				ri.RIP = proto.RIP
				ri.ISIS = proto.ISIS
			}
		}

		cfg.RoutingInstances = append(cfg.RoutingInstances, ri)
	}
	return nil
}

func compilePolicyOptions(node *Node, po *PolicyOptionsConfig) error {
	if po.PrefixLists == nil {
		po.PrefixLists = make(map[string]*PrefixList)
	}
	if po.Communities == nil {
		po.Communities = make(map[string]*CommunityDef)
	}
	if po.PolicyStatements == nil {
		po.PolicyStatements = make(map[string]*PolicyStatement)
	}

	// Parse prefix-lists
	for _, inst := range namedInstances(node.FindChildren("prefix-list")) {
		pl := &PrefixList{Name: inst.name}
		for _, entry := range inst.node.Children {
			if len(entry.Keys) > 0 {
				pl.Prefixes = append(pl.Prefixes, entry.Keys[0])
			}
		}
		po.PrefixLists[pl.Name] = pl
	}

	// Parse community definitions
	for _, inst := range namedInstances(node.FindChildren("community")) {
		cd := po.Communities[inst.name]
		if cd == nil {
			cd = &CommunityDef{Name: inst.name}
			po.Communities[inst.name] = cd
		}
		for _, entry := range inst.node.Children {
			if entry.Name() == "members" {
				// Multi-value leaf (#2587): `members [ c1 c2 ]` (and a
				// hierarchical block) collapses onto entry.Keys[1:] and/or
				// entry.Children. Read ALL via the firewallMatchValues SSOT;
				// the prior nodeVal-only read kept just the first community.
				cd.Members = append(cd.Members, firewallMatchValues(entry)...)
			}
		}
		// Handle flat set syntax where `members` collapses onto the community
		// instance node itself: Keys like ["members", "65000:100", ...].
		if len(inst.node.Keys) > 1 && inst.node.Keys[0] == "members" {
			cd.Members = append(cd.Members, inst.node.Keys[1:]...)
		}
	}

	// Parse AS-path definitions
	if po.ASPaths == nil {
		po.ASPaths = make(map[string]*ASPathDef)
	}
	for _, child := range node.FindChildren("as-path") {
		if len(child.Keys) >= 3 {
			// Hierarchical: Keys=["as-path", "NAME", "REGEX"]
			po.ASPaths[child.Keys[1]] = &ASPathDef{
				Name:  child.Keys[1],
				Regex: child.Keys[2],
			}
		} else if len(child.Keys) >= 2 {
			// Flat set syntax may produce: Keys=["as-path","NAME"] with children
			name := child.Keys[1]
			ap := &ASPathDef{Name: name}
			// Look for path child (regex value)
			for _, entry := range child.Children {
				if len(entry.Keys) > 0 {
					ap.Regex = entry.Keys[0]
				}
			}
			po.ASPaths[name] = ap
		}
	}

	// Parse policy-statements
	for _, inst := range namedInstances(node.FindChildren("policy-statement")) {
		ps := &PolicyStatement{Name: inst.name}
		termsByName := make(map[string]*PolicyTerm)

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "term":
				if len(prop.Keys) < 2 {
					continue
				}
				termName := prop.Keys[1]

				// Find or create term (flat set syntax may create multiple
				// nodes for the same term name)
				term, exists := termsByName[termName]
				if !exists {
					term = &PolicyTerm{Name: termName}
					termsByName[termName] = term
					ps.Terms = append(ps.Terms, term)
				}

				// Handle both hierarchical children and flat inline keys.
				// Flat: Keys=["term","t1","from","protocol","direct"] with no children
				// Hierarchical: Keys=["term","t1"] with from/then children
				if len(prop.Children) > 0 {
					// Hierarchical form
					parsePolicyTermChildren(term, prop.Children)
				} else if len(prop.Keys) > 2 {
					// Flat form: remaining keys after term name are key-value pairs
					parsePolicyTermInlineKeys(term, prop.Keys[2:])
				}
			case "then":
				// Default action at the policy level
				for _, ac := range prop.Children {
					switch ac.Name() {
					case "accept":
						ps.DefaultAction = "accept"
					case "reject":
						ps.DefaultAction = "reject"
					}
				}
				if len(prop.Keys) >= 2 {
					ps.DefaultAction = prop.Keys[1]
				}
			}
		}

		po.PolicyStatements[ps.Name] = ps
	}

	return nil
}

// collectProtocolList flattens a single "from protocol ..." node into the
// protocol names it carries. After the lexer strips the brackets, a protocol
// node reaches the compiler in one of three shapes:
//   - block parse, bracket list: every protocol is a key on the node itself
//     (Keys = ["protocol", "bgp", "ospf", "static"]).
//   - flat-set SetPath, bracket list: the first protocol is Keys[1] and the
//     remaining protocols hang off a nested single-child chain
//     (Keys = ["protocol", "bgp"] -> child Keys = ["ospf", "static"] -> ...).
//   - flat-set SetPath, separate "set ... from protocol <X>" commands: each
//     command lands its own leaf (Keys = ["protocol", "<X>"]) as a sibling
//     under the term's "from" block. The caller iterates those siblings and
//     calls this helper once per node, which then returns the single protocol.
//
// All three shapes (and arbitrarily long lists) are handled by taking
// Keys[1:] of the protocol node, then appending every key of each descendant
// in the single-child chain.
func collectProtocolList(protoNode *Node) []string {
	var protocols []string
	if len(protoNode.Keys) >= 2 {
		protocols = append(protocols, protoNode.Keys[1:]...)
	}
	for n := protoNode; len(n.Children) > 0; {
		child := n.Children[0]
		protocols = append(protocols, child.Keys...)
		n = child
	}
	return protocols
}

// parseRouteFilterLen parses a Junos route-filter length token of the
// form "/24" (the leading slash is how Junos writes "upto /24") or a
// bare "24". It returns (n, true) only for a well-formed length in the
// valid range 1..128; a malformed or out-of-range token yields
// (0, false) so the caller leaves UptoLen at 0 and the renderer
// degrades safely (#2072). Upper bound is 128 (IPv6 max); the renderer
// separately clamps against the per-family max and the prefix length.
//
// Zero is REJECTED on purpose (Codex #2102 MAJOR): "upto /0" is not a
// meaningful length, and UptoLen is a plain int with no presence bit, so
// accepting 0 would make an explicit "upto /0" indistinguishable from an
// unset UptoLen. Keeping 0 strictly as "unset" lets the renderer treat
// UptoLen==0 unambiguously as the degrade case.
func parseRouteFilterLen(tok string) (int, bool) {
	tok = strings.TrimPrefix(tok, "/")
	// Require digits only — strconv.Atoi would also accept signed forms
	// like "+24" or "-0", which are not valid Junos length tokens (Codex
	// #2102 MINOR). An empty token (e.g. a bare "/") has no digits and is
	// rejected here.
	if tok == "" {
		return 0, false
	}
	for _, c := range tok {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(tok)
	if err != nil || n < 1 || n > 128 {
		return 0, false
	}
	return n, true
}

// parseRouteFilterRange parses a Junos "prefix-length-range" length token of
// the form "/16-/24" (or the slashless "16-24") into its low and high
// prefix-length bounds. It returns (low, high, true) only when BOTH bounds are
// well-formed lengths in 1..128; any malformed token (missing dash, empty
// half, non-numeric, out of range) yields (0, 0, false) so the caller leaves
// RangeLow/RangeHigh at 0 and the strict gate / renderer treat 0 as "no
// parseable range" (#2525). Ordering (low<=high), the per-family max, and the
// base-prefix floor are enforced separately by validateRouteFilterMatchTypesStrict
// — this helper only parses syntax.
func parseRouteFilterRange(tok string) (low, high int, ok bool) {
	parts := strings.SplitN(tok, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	lo, okLo := parseRouteFilterLen(parts[0])
	hi, okHi := parseRouteFilterLen(parts[1])
	if !okLo || !okHi {
		return 0, 0, false
	}
	return lo, hi, true
}

// routeFilterTrailingToken extracts the single trailing argument token of a
// hierarchical-parse route-filter node (the "/N" for upto, the "/lo-/hi" for
// prefix-length-range, the CIDR for through). It reaches the compiler in two
// shapes: brace parse puts it at Keys[3]; flat-set SetPath nests it as the
// first key of the first child. Returns "" when neither shape carries it.
func routeFilterTrailingToken(fc *Node) string {
	if len(fc.Keys) >= 4 {
		return fc.Keys[3]
	}
	if len(fc.Children) > 0 && len(fc.Children[0].Keys) > 0 {
		return fc.Children[0].Keys[0]
	}
	return ""
}

// parsePolicyTermChildren handles hierarchical form of policy term
// where "from" and "then" are child nodes.
func parsePolicyTermChildren(term *PolicyTerm, children []*Node) {
	for _, tc := range children {
		switch tc.Name() {
		case "from":
			for _, fc := range tc.Children {
				switch fc.Name() {
				case "protocol":
					// Junos "from protocol [ bgp ospf static ]" matches any
					// listed protocol. The lexer strips the brackets, so the
					// protocol list arrives in one of two AST shapes:
					//  - hierarchical block parse: all protocols land in
					//    fc.Keys (Keys=["protocol","bgp","ospf","static"]);
					//  - flat-set SetPath: the first protocol is fc.Keys[1]
					//    and the rest form a nested child chain
					//    (Keys=["protocol","bgp"] -> child Keys=["ospf","static"]).
					// Collect every protocol from both shapes, not just the
					// first (#2008 H18).
					term.FromProtocols = append(term.FromProtocols, collectProtocolList(fc)...)
				case "prefix-list":
					// Junos allows repeated `prefix-list` siblings in one
					// term (match ANY). Accumulate so multiple statements are
					// all kept, not just the last (#2642). A bracketed list
					// `prefix-list [ p1 p2 ]` ALSO collapses onto one leaf's
					// Keys[1:] / Children in BOTH AST shapes (#2419), so read
					// every value via the firewallMatchValues SSOT — the prior
					// nodeVal-only read kept just the first list entry (#2689).
					term.PrefixList = append(term.PrefixList, firewallMatchValues(fc)...)
				case "route-filter":
					if len(fc.Keys) >= 3 {
						rf := &RouteFilter{
							Prefix:    fc.Keys[1],
							MatchType: fc.Keys[2],
						}
						// "upto", "prefix-length-range", and "through" all carry
						// a trailing argument token (a "/N" length, a "/lo-/hi"
						// range, or a CIDR prefix). It reaches the compiler in
						// two shapes (#2072/#2525):
						//   - brace parse: a single leaf, the arg at Keys[3];
						//   - flat-set SetPath: a container node with the arg as
						//     its first child key (Children[0].Keys[0]). On a
						//     single-line flat set the child also folds trailing
						//     clause tokens, so read only its first key.
						switch rf.MatchType {
						case "upto":
							if argTok := routeFilterTrailingToken(fc); argTok != "" {
								if n, ok := parseRouteFilterLen(argTok); ok {
									rf.UptoLen = n
								}
							}
						case "prefix-length-range":
							if argTok := routeFilterTrailingToken(fc); argTok != "" {
								if lo, hi, ok := parseRouteFilterRange(argTok); ok {
									rf.RangeLow = lo
									rf.RangeHigh = hi
								}
							}
						case "through":
							rf.ThroughPrefix = routeFilterTrailingToken(fc)
						}
						term.RouteFilters = append(term.RouteFilters, rf)
					}
				case "community":
					// Repeated `community` siblings match ANY (#2642) — keep
					// every one, not just the last. A bracketed list
					// `community [ c1 c2 ]` ALSO collapses onto one leaf's
					// Keys[1:] / Children in BOTH AST shapes (#2419), so read
					// every value via the firewallMatchValues SSOT — the prior
					// nodeVal-only read kept just the first list entry (#2689).
					term.FromCommunity = append(term.FromCommunity, firewallMatchValues(fc)...)
				case "as-path":
					// Repeated `as-path` siblings match ANY (#2642).
					if v := nodeVal(fc); v != "" {
						term.FromASPath = append(term.FromASPath, v)
					}
				}
			}
		case "then":
			for _, ac := range tc.Children {
				switch ac.Name() {
				case "accept":
					term.Action = "accept"
				case "reject":
					term.Action = "reject"
				case "next-hop":
					term.NextHop = nodeVal(ac)
				case "load-balance":
					term.LoadBalance = nodeVal(ac)
				case "local-preference":
					if v := nodeVal(ac); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							term.LocalPreference = n
						}
					}
				case "metric":
					if v := nodeVal(ac); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							term.Metric = n
						}
					}
				case "metric-type":
					if v := nodeVal(ac); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							term.MetricType = n
						}
					}
				case "community":
					term.Community = nodeVal(ac)
				case "origin":
					term.Origin = nodeVal(ac)
				}
			}
			if len(tc.Keys) >= 2 {
				term.Action = tc.Keys[1]
			}
		}
	}
}

// policyTermInlineKeywords is the set of clause keywords recognized by
// parsePolicyTermInlineKeys. It is used to find where a variable-length
// value run (e.g. a multi-protocol "from protocol [ ... ]" list) ends.
var policyTermInlineKeywords = map[string]bool{
	"from": true, "then": true, "protocol": true, "prefix-list": true,
	"route-filter": true, "next-hop": true, "load-balance": true,
	"local-preference": true, "metric": true, "metric-type": true,
	"community": true, "as-path": true, "origin": true,
	"accept": true, "reject": true,
}

// parsePolicyTermInlineKeys handles flat set syntax where remaining keys
// after the term name are inline key-value pairs like:
// "from", "protocol", "direct" or "from", "route-filter", "10.0.0.0/8", "exact"
// or "then", "accept"
func parsePolicyTermInlineKeys(term *PolicyTerm, keys []string) {
	inFrom := false
	for i := 0; i < len(keys); i++ {
		switch keys[i] {
		case "from":
			inFrom = true
			continue
		case "then":
			inFrom = false
			if i+1 < len(keys) {
				i++
				term.Action = keys[i]
			}
		case "protocol":
			// "from protocol [ bgp ospf static ]" — the lexer strips the
			// brackets, so every protocol arrives as a separate key. Consume
			// all consecutive values until the next clause keyword, so a
			// multi-protocol list keeps every protocol (not just the first).
			for i+1 < len(keys) && !policyTermInlineKeywords[keys[i+1]] {
				i++
				term.FromProtocols = append(term.FromProtocols, keys[i])
			}
		case "prefix-list":
			if i+1 < len(keys) {
				i++
				term.PrefixList = append(term.PrefixList, keys[i])
			}
		case "route-filter":
			if i+2 < len(keys) {
				rf := &RouteFilter{
					Prefix:    keys[i+1],
					MatchType: keys[i+2],
				}
				// "upto"/"prefix-length-range"/"through" carry a trailing
				// argument token at keys[i+3] (a "/N" length, a "/lo-/hi"
				// range, or a CIDR prefix). Consume it only when present so
				// the next clause keyword is not misread as a value.
				// (#2072/#2525 — belt-and-suspenders: the inline path is not
				// reached for route-filter under the current schema, which
				// always nests "from" as a child node, but keep it correct in
				// case dispatch ever changes.)
				consumed := 2
				if i+3 < len(keys) {
					switch rf.MatchType {
					case "upto":
						if n, ok := parseRouteFilterLen(keys[i+3]); ok {
							rf.UptoLen = n
							consumed = 3
						}
					case "prefix-length-range":
						if lo, hi, ok := parseRouteFilterRange(keys[i+3]); ok {
							rf.RangeLow = lo
							rf.RangeHigh = hi
							consumed = 3
						}
					case "through":
						rf.ThroughPrefix = keys[i+3]
						consumed = 3
					}
				}
				term.RouteFilters = append(term.RouteFilters, rf)
				i += consumed
			}
		case "next-hop":
			if i+1 < len(keys) {
				i++
				term.NextHop = keys[i]
			}
		case "load-balance":
			if i+1 < len(keys) {
				i++
				term.LoadBalance = keys[i]
			}
		case "local-preference":
			if i+1 < len(keys) {
				i++
				if n, err := strconv.Atoi(keys[i]); err == nil {
					term.LocalPreference = n
				}
			}
		case "metric":
			if i+1 < len(keys) {
				i++
				if n, err := strconv.Atoi(keys[i]); err == nil {
					term.Metric = n
				}
			}
		case "metric-type":
			if i+1 < len(keys) {
				i++
				if n, err := strconv.Atoi(keys[i]); err == nil {
					term.MetricType = n
				}
			}
		case "community":
			if i+1 < len(keys) {
				i++
				if inFrom {
					term.FromCommunity = append(term.FromCommunity, keys[i])
				} else {
					term.Community = keys[i]
				}
			}
		case "as-path":
			if i+1 < len(keys) {
				i++
				term.FromASPath = append(term.FromASPath, keys[i])
			}
		case "origin":
			if i+1 < len(keys) {
				i++
				term.Origin = keys[i]
			}
		case "accept":
			term.Action = "accept"
		case "reject":
			term.Action = "reject"
		}
	}
}
