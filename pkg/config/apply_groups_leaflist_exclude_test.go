package config

import "testing"

// #4070 follow-up: the apply-groups leaf-list UNION (schema-aware) must EXCLUDE
// token-packed / operation / multi-token multi-leaves and revert them to the
// safe pre-#4070 OVERRIDE. The `multi:true && children==nil` discriminator
// over-includes leaves that pack a SEPARATOR or OPERATION keyword onto the
// value list, or that carry multiple tokens per member:
//
//   - port RANGES (firewall/NAT `destination-port`/`source-port`): a range
//     `3000 to 4000` packs the `to` separator. Union/dedup would collapse two
//     ranges into `3000 to 4000 1000 2000` — a silently miscompiled matcher
//     (fail-OPEN on a discard/reject term). Marked groupReplace + guarded by
//     the leafListCarriesRange net.
//   - policy-options `then community add|set|delete|none` and
//     `then as-path-prepend`: these pack an operation keyword / are
//     order+repetition sensitive ACTIONS, not match-list members. Marked
//     groupReplace.
//   - args>=2 multi leaves (address-book `address <name> <prefix>`,
//     route-filter `<prefix> <match-type>`, as-path `<name> <regex>`, CoS
//     `queue <n> <class>`): multi-token members; token-level union mashes the
//     tokens together. Excluded by the args<=1 gate in isLeafListSchema.
//
// These tests assert those leaves OVERRIDE (inline wins, no corruption) and
// that a GENUINE single-token leaf-list in the SAME subtree (firewall `from
// protocol`) STILL unions — the exclusion is narrow.

// setTreeFromCommands builds a ConfigTree from flat set commands and expands
// apply-groups (no compile — keeps the assertion at the merge layer).
func setTreeFromCommands(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range cmds {
		path, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	return tree
}

// findNodesByKey returns every node in the tree whose Keys[0] == key (recursing
// through containers).
func findNodesByKey(nodes []*Node, key string) []*Node {
	var out []*Node
	for _, n := range nodes {
		if len(n.Keys) > 0 && n.Keys[0] == key {
			out = append(out, n)
		}
		if !n.IsLeaf {
			out = append(out, findNodesByKey(n.Children, key)...)
		}
	}
	return out
}

// TestApplyGroupsLeafListPortRangeOverrides is the headline exclusion: a group
// and an inline firewall-filter term both set a destination-port RANGE. The
// group value must be DROPPED (inline range wins) — NOT token-merged into a
// corrupted `3000 to 4000 1000 2000`. RED on the un-fixed union: the collapsed
// leaf would carry all five tokens (a fail-OPEN matcher on a discard term).
func TestApplyGroupsLeafListPortRangeOverrides(t *testing.T) {
	tree := setTreeFromCommands(t, []string{
		"set groups g firewall family inet filter F term T from destination-port 1000 to 2000",
		"set firewall family inet filter F term T from destination-port 3000 to 4000",
		"set firewall family inet filter F term T then accept",
		"set apply-groups g",
	})
	dports := findNodesByKey(tree.Children, "destination-port")
	if len(dports) != 1 {
		t.Fatalf("port-range override must yield exactly ONE destination-port "+
			"node, got %d: %s", len(dports), describeNodes(dports))
	}
	got := firewallMatchValues(dports[0])
	assertMembers(t, "port-range override (inline wins, not a token-merge)",
		got, []string{"3000", "to", "4000"})
}

// TestApplyGroupsLeafListThenCommunityOverrides: a group and inline
// policy-options `then community add <value>` must OVERRIDE (inline wins), not
// merge the operation keyword + a second community. RED on union: the collapsed
// leaf becomes `add 65000:200 65000:100`.
func TestApplyGroupsLeafListThenCommunityOverrides(t *testing.T) {
	tree := setTreeFromCommands(t, []string{
		"set groups g policy-options policy-statement P term t1 then community add 65000:100",
		"set policy-options policy-statement P term t1 then community add 65000:200",
		"set policy-options policy-statement P term t1 then accept",
		"set apply-groups g",
	})
	comm := findNodesByKey(tree.Children, "community")
	if len(comm) != 1 {
		t.Fatalf("then-community override must yield exactly ONE community node, "+
			"got %d: %s", len(comm), describeNodes(comm))
	}
	assertMembers(t, "then community override (operation not merged)",
		firewallMatchValues(comm[0]), []string{"add", "65000:200"})
}

// TestApplyGroupsLeafListThenAsPathPrependOverrides: a group and inline
// `then as-path-prepend` must OVERRIDE — as-path-prepend is order + repetition
// sensitive, so union/dedup would both add ASNs and drop meaningful repeats.
func TestApplyGroupsLeafListThenAsPathPrependOverrides(t *testing.T) {
	tree := setTreeFromCommands(t, []string{
		"set groups g policy-options policy-statement P term t1 then as-path-prepend [ 65002 65002 ]",
		"set policy-options policy-statement P term t1 then as-path-prepend [ 65001 65001 65001 ]",
		"set policy-options policy-statement P term t1 then accept",
		"set apply-groups g",
	})
	prep := findNodesByKey(tree.Children, "as-path-prepend")
	if len(prep) != 1 {
		t.Fatalf("as-path-prepend override must yield ONE node, got %d: %s",
			len(prep), describeNodes(prep))
	}
	// Inline's three prepends survive EXACTLY (order + repetition preserved,
	// so an exact slice compare — not the dedup-checking assertMembers); the
	// group's 65002 pair is NOT added.
	got := firewallMatchValues(prep[0])
	want := []string{"65001", "65001", "65001"}
	if len(got) != len(want) {
		t.Fatalf("as-path-prepend override: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("as-path-prepend override: got %v, want %v (pos %d)", got, want, i)
		}
	}
}

// TestApplyGroupsLeafListArgs2AddressNotCorrupted: an address-book `address
// <name> <prefix>` is an args>=2 multi leaf (a NAMED entry, two tokens per
// member). The args<=1 gate excludes it from union, so the inline entry keeps
// its clean 3-key shape (`address net-a <prefix>`) rather than being mashed
// with the group's entry into a 5-key leaf. RED on the un-fixed union.
func TestApplyGroupsLeafListArgs2AddressNotCorrupted(t *testing.T) {
	tree := setTreeFromCommands(t, []string{
		"set groups g security zones security-zone Z address-book address net-b 10.0.1.0/24",
		"set security zones security-zone Z address-book address net-a 10.0.0.0/24",
		"set apply-groups g",
	})
	addrs := findNodesByKey(tree.Children, "address")
	if len(addrs) == 0 {
		t.Fatal("no address node after expansion")
	}
	for _, a := range addrs {
		// A clean named entry is [address, name, prefix] — never a mashed
		// multi-entry leaf (the token-union corruption).
		if !a.IsLeaf || len(a.Keys) != 3 {
			t.Fatalf("address entry must stay a clean 3-key leaf, got %s "+
				"(keys=%v) — args>=2 leaf was token-merged", describeNodes([]*Node{a}), a.Keys)
		}
	}
	// The inline entry is present and intact.
	foundNetA := false
	for _, a := range addrs {
		if a.Keys[1] == "net-a" && a.Keys[2] == "10.0.0.0/24" {
			foundNetA = true
		}
	}
	if !foundNetA {
		t.Fatalf("inline address net-a 10.0.0.0/24 must survive, got %s",
			describeNodes(addrs))
	}
}

// TestApplyGroupsLeafListFirewallProtocolStillUnions proves the exclusion is
// NARROW: firewall `from protocol` (args:1, single-token, no groupReplace) is a
// GENUINE leaf-list in the SAME `from` subtree as the excluded destination-port,
// and it STILL unions. Group udp + inline tcp → both present.
func TestApplyGroupsLeafListFirewallProtocolStillUnions(t *testing.T) {
	tree := setTreeFromCommands(t, []string{
		"set groups g firewall family inet filter F term T from protocol udp",
		"set firewall family inet filter F term T from protocol tcp",
		"set firewall family inet filter F term T then accept",
		"set apply-groups g",
	})
	protos := findNodesByKey(tree.Children, "protocol")
	if len(protos) != 1 {
		t.Fatalf("from protocol union must yield ONE node, got %d: %s",
			len(protos), describeNodes(protos))
	}
	assertMembers(t, "from protocol union (genuine leaf-list still unions)",
		firewallMatchValues(protos[0]), []string{"tcp", "udp"})
}
