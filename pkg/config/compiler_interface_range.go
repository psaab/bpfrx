package config

import (
	"fmt"
	"strconv"
)

// compiler_interface_range.go implements the #4027 interface-range
// expansion pre-pass.
//
// Junos `interfaces interface-range <name> { member <if>; ... }` groups a
// SET of member interfaces so a common block of configuration is applied to
// each one at once. Before this pass xpf had no interface-range handling:
// the generic `interfaces` wildcard treated `interface-range` itself as an
// interface NAME, so the compiler minted a PHANTOM InterfaceConfig keyed
// "interface-range" (matching no kernel NIC, later reconciled admin-down) and
// the range's shared configuration — plus the member interfaces themselves —
// were silently dropped.
//
// expandInterfaceRanges rewrites every interface-range stanza into its member
// interfaces BEFORE section compilation: each member interface gets the
// range's shared configuration, merged with the member's own per-interface
// configuration (the member's own statements win on a scalar conflict), and
// no interface named after the range survives. It runs in compileExpanded on
// the group-expanded, inactive-pruned clone (so an apply-groups-inherited
// interface-range is expanded and an `inactive:` range is ignored for free),
// and it MUTATES the clone in place — the caller's tree is untouched.
//
// The rewrite is done by flattening the range's shared statements into
// `set`-command token suffixes and replaying them through ConfigTree.SetPath
// under each member's name. SetPath re-nests the tokens with the exact
// schema-driven shape a normal per-interface config would have, so the
// downstream compileInterfaces reads them identically whether they arrived
// via a real interface stanza or an interface-range — and both the flat-set
// (`set interfaces interface-range R member geX`) and the hierarchical
// (`interface-range R { member geX; ... }`) AST shapes normalize to the same
// member interfaces.

// interfaceRangeDef is one parsed `interface-range <name>` definition: its
// member interface names and the shared configuration statements (each a
// `set`-command token suffix, i.e. the tokens that would follow
// `set interfaces <member>`).
type interfaceRangeDef struct {
	name    string
	members []string
	shared  [][]string
}

// expandInterfaceRanges expands every `interfaces interface-range` stanza in
// the tree into its member interfaces (#4027). It mutates tree in place and
// returns operator-visible warnings (malformed range, member-range that
// cannot be expanded, a range with no members). It is a no-op — returning nil
// and leaving the tree byte-identical — when there is no interface-range
// stanza, so a config without the construct is unaffected.
func expandInterfaceRanges(tree *ConfigTree) ([]string, error) {
	// #5675: union across EVERY top-level `interfaces` root, not just the first.
	// A hierarchical config can split its interfaces across two sibling
	// `interfaces { }` stanzas, and compileSections compiles them all — so if
	// an interface-range lives in a second root the old first-root-only scan
	// skipped it, re-minting the #4027 phantom "interface-range" iface and
	// dropping the range's shared config for its members.
	ifaceRoots := tree.FindChildren("interfaces")
	if len(ifaceRoots) == 0 {
		return nil, nil
	}

	// Separate interface-range definitions from real interface children, across
	// every interfaces root. keptByRoot holds each root's non-range children so
	// the strip is deferred until we know a range was actually seen (a config
	// with no interface-range stays byte-identical — the no-op contract).
	var ranges []interfaceRangeDef
	var warnings []string
	sawRange := false
	keptByRoot := make([][]*Node, len(ifaceRoots))
	for ri, ifaces := range ifaceRoots {
		kept := make([]*Node, 0, len(ifaces.Children))
		for _, child := range ifaces.Children {
			if child.Name() != "interface-range" {
				kept = append(kept, child)
				continue
			}
			sawRange = true
			if len(child.Keys) >= 2 {
				// Hierarchical: Keys=["interface-range", <name>], children are
				// the member/config nodes directly.
				rd, w := parseHierInterfaceRange(child)
				warnings = append(warnings, w...)
				if rd != nil {
					ranges = append(ranges, *rd)
				}
			} else {
				// Flat-set: Keys=["interface-range"], each child is a leaf whose
				// Keys[0] is the range name and Keys[1:] the config statement.
				rds, w := parseFlatInterfaceRanges(child)
				warnings = append(warnings, w...)
				ranges = append(ranges, rds...)
			}
		}
		keptByRoot[ri] = kept
	}
	if !sawRange {
		// No interface-range stanza present — leave the tree untouched.
		return nil, nil
	}
	// Strip every interface-range node (in every root) so the range name is
	// never compiled as a phantom interface, even if the stanza was malformed
	// and yielded no expandable range.
	for ri, ifaces := range ifaceRoots {
		ifaces.Children = keptByRoot[ri]
	}

	// #8438 TOTAL EXPANSION BUDGET. Debited by BOTH spellings, across every
	// range, and checked BEFORE any statement is replayed — see the constant's
	// comment for the measurements that set the number and for why a
	// member-COUNT cap does not bound the cost.
	if total, over := interfaceRangeExpansionCost(ranges); over {
		return append(warnings, fmt.Sprintf(
				"interfaces interface-range: total expansion of %d statement applications "+
					"across %d range(s) exceeds the %d limit; no interface-range was expanded "+
					"(each range costs members x shared-statements: a 4096-member range with 6 "+
					"shared statements takes 78s to compile, and the cost grows faster than "+
					"linearly in both)",
				total, len(ranges), interfaceRangeMaxExpansion)),
			fmt.Errorf(
				"interfaces interface-range: total expansion of %d statement applications "+
					"across %d range(s) exceeds the %d limit; reduce the member lists or the "+
					"shared configuration (cost is members x shared-statements per range)",
				total, len(ranges), interfaceRangeMaxExpansion)
	}

	// Build the ordered, de-duplicated member set and, per member, the
	// concatenation of every containing range's shared statements (range
	// definition order preserved).
	memberShared := map[string][][]string{}
	inRange := map[string]bool{}
	var memberOrder []string
	for _, rd := range ranges {
		if len(rd.members) == 0 {
			warnings = append(warnings, fmt.Sprintf(
				"interfaces interface-range %s: no members; shared configuration is not applied to any interface",
				rd.name))
			continue
		}
		for _, m := range rd.members {
			if m == "" {
				continue
			}
			if !inRange[m] {
				inRange[m] = true
				memberOrder = append(memberOrder, m)
			}
			memberShared[m] = append(memberShared[m], rd.shared...)
		}
	}

	// Snapshot and remove each member's existing explicit interface node (in
	// every root) so its own statements can be re-applied LAST — SetPath
	// replaces a single-value leaf (e.g. mtu), so applying shared config first
	// and the member's own config last gives the member precedence on a
	// conflict while additive statements (addresses) accumulate. A member whose
	// own node lives in a different root than its range is still captured
	// because we sweep every root; SetPath below replays into the first root,
	// which compileSections merges with the rest.
	memberOwn := map[string][][]string{}
	for _, ifaces := range ifaceRoots {
		remaining := ifaces.Children[:0]
		for _, child := range ifaces.Children {
			name := child.Name()
			if inRange[name] && !child.IsLeaf {
				memberOwn[name] = append(memberOwn[name], flattenNodesToPaths(child.Children, nil)...)
				continue
			}
			remaining = append(remaining, child)
		}
		ifaces.Children = remaining
	}

	for _, m := range memberOrder {
		for _, p := range memberShared[m] {
			if err := tree.SetPath(append([]string{"interfaces", m}, p...)); err != nil {
				warnings = append(warnings, fmt.Sprintf(
					"interfaces interface-range: applying shared config to %s: %v", m, err))
			}
		}
		for _, p := range memberOwn[m] {
			if err := tree.SetPath(append([]string{"interfaces", m}, p...)); err != nil {
				warnings = append(warnings, fmt.Sprintf(
					"interfaces %s: re-applying member config: %v", m, err))
			}
		}
	}
	return warnings, nil
}

// parseHierInterfaceRange parses a hierarchical `interface-range <name> { ... }`
// node (Keys=["interface-range", <name>]) into an interfaceRangeDef.
func parseHierInterfaceRange(node *Node) (*interfaceRangeDef, []string) {
	if len(node.Keys) < 2 {
		return nil, []string{"interfaces interface-range: definition with no name; ignored"}
	}
	rd := &interfaceRangeDef{name: node.Keys[1]}
	var warnings []string
	for _, c := range node.Children {
		switch c.Name() {
		case "member":
			// `member <if>` or bracketed `member [ a b ]` — every name lands
			// on Keys[1:] (flat-set replay may also split trailing names into
			// leaf children).
			for _, m := range c.Keys[1:] {
				if m != "" {
					rd.members = append(rd.members, m)
				}
			}
			for _, ch := range c.Children {
				if n := ch.Name(); n != "" {
					rd.members = append(rd.members, n)
				}
			}
		case "member-range":
			ms, w := expandMemberRange(rd.name, c.Keys[1:])
			rd.members = append(rd.members, ms...)
			warnings = append(warnings, w...)
		default:
			rd.shared = append(rd.shared, flattenNodesToPaths([]*Node{c}, nil)...)
		}
	}
	return rd, warnings
}

// parseFlatInterfaceRanges parses the flat-set `interface-range` node
// (Keys=["interface-range"], children are per-statement leaves prefixed by
// the range name) into one interfaceRangeDef per distinct range name,
// preserving first-seen order.
func parseFlatInterfaceRanges(node *Node) ([]interfaceRangeDef, []string) {
	byName := map[string]*interfaceRangeDef{}
	var order []string
	var warnings []string
	for _, c := range node.Children {
		if len(c.Keys) < 2 {
			warnings = append(warnings,
				"interfaces interface-range: malformed entry (no range name); ignored")
			continue
		}
		rname := c.Keys[0]
		tokens := c.Keys[1:]
		rd := byName[rname]
		if rd == nil {
			rd = &interfaceRangeDef{name: rname}
			byName[rname] = rd
			order = append(order, rname)
		}
		switch tokens[0] {
		case "member":
			for _, m := range tokens[1:] {
				if m != "" {
					rd.members = append(rd.members, m)
				}
			}
		case "member-range":
			ms, w := expandMemberRange(rname, tokens[1:])
			rd.members = append(rd.members, ms...)
			warnings = append(warnings, w...)
		default:
			rd.shared = append(rd.shared, append([]string(nil), tokens...))
		}
	}
	out := make([]interfaceRangeDef, 0, len(order))
	for _, n := range order {
		out = append(out, *byName[n])
	}
	return out, warnings
}

// interfaceRangeMaxMembers caps a single member-range expansion so a typo
// like `member-range ge-0/0/0 to ge-0/0/999999` cannot mint a runaway
// interface list.
const interfaceRangeMaxMembers = 4096

// expandMemberRange expands a `member-range <start> to <end>` selector into
// the individual member names. start and end must share a common prefix and
// differ only in a trailing decimal number (e.g. ge-0/0/1 to ge-0/0/4). An
// unparseable or inverted range is skipped with a warning.
func expandMemberRange(rangeName string, toks []string) ([]string, []string) {
	if len(toks) != 3 || toks[1] != "to" {
		return nil, []string{fmt.Sprintf(
			"interfaces interface-range %s: malformed member-range (expected `<start> to <end>`); ignored",
			rangeName)}
	}
	start, end := toks[0], toks[2]
	sp, sn, ok1 := splitTrailingInt(start)
	ep, en, ok2 := splitTrailingInt(end)
	if !ok1 || !ok2 || sp != ep || sn > en {
		return nil, []string{fmt.Sprintf(
			"interfaces interface-range %s: cannot expand member-range %s to %s "+
				"(endpoints must share a prefix and differ only in a trailing number); ignored",
			rangeName, start, end)}
	}
	// splitTrailingInt only ever returns non-negative values (it scans a
	// pure decimal digit run), so sn >= 0 and, given the sn > en rejection
	// above, en >= sn >= 0 here. That makes en-sn itself overflow-safe (a
	// non-negative difference bounded by en). Comparing en-sn against the
	// cap BEFORE adding 1 avoids the en-sn+1 overflow that a start/end pair
	// near math.MaxInt64 could otherwise trigger — en-sn+1 would wrap to a
	// large negative number, silently bypassing this guard and reaching the
	// make() below with a negative capacity (a crashing panic, #4807).
	if en-sn >= interfaceRangeMaxMembers {
		return nil, []string{fmt.Sprintf(
			"interfaces interface-range %s: member-range %s to %s exceeds %d interfaces; ignored",
			rangeName, start, end, interfaceRangeMaxMembers)}
	}
	// Iterate on the bounded COUNT, not the raw endpoint. The cap above
	// guarantees n = en-sn is in [0, interfaceRangeMaxMembers), so the loop
	// variable k stays small and can never approach the point where k++
	// overflows int64. Forming names as sn+k still yields exactly sn..en
	// (sn+n == en, and every sn+k <= en <= MaxInt64 is overflow-free).
	// Looping on `i` up to `en` instead overflowed when en == MaxInt64: the
	// body ran at i == MaxInt64, then i++ wrapped to MinInt64, i <= en
	// stayed true, and the loop appended forever (#5373 infinite loop / OOM,
	// reachable at commit AND on the tolerant / HA config-sync load path).
	n := en - sn
	out := make([]string, 0, n+1)
	for k := 0; k <= n; k++ {
		out = append(out, fmt.Sprintf("%s%d", sp, sn+k))
	}
	return out, nil
}

// splitTrailingInt splits s into a leading prefix and a trailing decimal
// number (e.g. "ge-0/0/12" -> "ge-0/0/", 12). ok is false when s has no
// trailing digit run or the digits do not parse as an int.
func splitTrailingInt(s string) (prefix string, num int, ok bool) {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	if i == len(s) {
		return "", 0, false
	}
	n, err := strconv.Atoi(s[i:])
	if err != nil {
		return "", 0, false
	}
	return s[:i], n, true
}

// flattenNodesToPaths flattens a list of AST nodes into `set`-command token
// suffixes: each leaf (or empty container) yields one token slice of its full
// key path from the given prefix. It is the inverse of ConfigTree.SetPath's
// re-nesting and mirrors formatSetNodes, so a member's own config and a
// range's hierarchical shared config can both be replayed through SetPath.
func flattenNodesToPaths(nodes []*Node, prefix []string) [][]string {
	var out [][]string
	for _, c := range nodes {
		path := append(append([]string(nil), prefix...), c.Keys...)
		if c.IsLeaf || len(c.Children) == 0 {
			out = append(out, path)
			continue
		}
		out = append(out, flattenNodesToPaths(c.Children, path)...)
	}
	return out
}

// interfaceRangeMaxExpansion bounds the TOTAL interface-range expansion work in
// one config — every range, both spellings, one budget (#8438).
//
// WHY A MEMBER-COUNT CAP IS NOT ENOUGH. The obvious guard, and the one the
// issue proposed by pointing at the sibling `member-range` cap, is a limit on
// the number of members. Measured on this tree, that does not bound the cost:
//
//	members  shared stmts  compile
//	  2,000       1          0.4 s
//	  4,096       1          1.4 s
//	  4,096       3         23.2 s
//	  4,096       6         77.9 s
//	  2,000      20        268   s
//
// A 4096-MEMBER cap admits every row above: 4096 members with six shared
// statements — an mtu, a description, a unit with an address — is a 78-second
// commit that a member-count guard waves through. The cost is driven by the
// PRODUCT, members x shared-statements, because each statement is replayed
// through ConfigTree.SetPath under each member and SetPath locates the member
// by a linear scan of the `interfaces` root, which by then holds every member.
// A CPU profile of the expansion is 100% SetPathQuotedGrouped, 55% of it in
// keysEqual/memeqbody. So the budget debits that product, not the member count.
//
// WHY 4096. It is the number the sibling per-range `member-range` cap already
// ships (interfaceRangeMaxMembers), so the two guards state one limit rather
// than two; and it bounds the worst admitted case at ~1.4 s (the 4,096 x 1 row).
// It is enormously generous against real configuration: the largest
// interface-range anywhere in this tree — fixtures included — is 23 members,
// and no shipped .conf uses the construct at all. A 23-member range would need
// 178 shared statements to reach the limit.
//
// WHAT AN OPERATOR SEES ON EXCEEDING IT. At commit / commit-check, a hard
// rejection naming the total, the number of ranges and the limit. On the
// tolerant load / peer-sync path, the same text as a warning and NO expansion:
// the members simply do not materialize. Warn-and-expand-anyway was rejected as
// the tolerant disposition because the harm here IS the expansion — a config
// that reached the store this way would otherwise stall the peer and every
// subsequent boot for minutes to hours, which is the availability failure the
// guard exists to stop. Skipping matches what the shipped `member-range` cap
// already does with an over-limit range ("ignored" with a warning).
//
// The count cannot diverge between cluster nodes, so this cannot reject on one
// node and accept on its peer (the sync-wedging shape): expansion cost is a
// property of the statement list, and the per-node mechanisms — apply-groups
// and ${node} substitution — rewrite member NAMES without changing how many
// statements there are. Measured both: identical counts on node 0 and node 1.
const interfaceRangeMaxExpansion = 4096

// interfaceRangeExpansionCost totals the expansion work across every range and
// reports whether it exceeds the budget. The cost of one range is its member
// count times its shared-statement count — the number of SetPath replays it
// will drive. A range with no shared statements still debits its members (it
// still costs the per-member node sweep), hence the floor of 1.
//
// Accumulation is short-circuited so a hostile input cannot overflow the
// counter on the way to being rejected: once the running total is over the
// budget the answer cannot change, since every remaining term is non-negative.
func interfaceRangeExpansionCost(ranges []interfaceRangeDef) (int, bool) {
	total := 0
	for _, rd := range ranges {
		perMember := len(rd.shared)
		if perMember < 1 {
			perMember = 1
		}
		if len(rd.members) > interfaceRangeMaxExpansion/perMember {
			return interfaceRangeMaxExpansion + 1, true
		}
		total += len(rd.members) * perMember
		if total > interfaceRangeMaxExpansion {
			return total, true
		}
	}
	return total, false
}
