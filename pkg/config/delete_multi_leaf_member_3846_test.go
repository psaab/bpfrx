package config

import (
	"sort"
	"strings"
	"testing"
)

// TestDeleteMultiLeafMember_3846 pins the delete-side counterpart of the #2419
// multi-value-leaf class. On a `multi: true` value-list leaf that holds a
// bracket list (`from protocol [ tcp udp icmp ]`, policy match values,
// host-inbound-services), `delete ... from protocol tcp` must remove ONLY the
// named member and keep the rest — before #3846 it prefix-matched the leaf by
// its first key and deleted the WHOLE list (a config-integrity fail-wide), and
// a non-first member was undeletable.
//
// fail-on-revert: reverting removeMultiLeafMembers makes every "member
// survives" assertion RED (the whole bracket list disappears on the first
// member delete; a non-first member delete errors "path not found").

// buildTree3846 applies a slice of `set ...` commands via ParseSetCommand+SetPath —
// the ONLY correct way to exercise flat-set / bracket-list shapes (NewParser
// merges newline-separated set lines into one giant node).
func buildTree3846(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// firewallProtocols reads the compiled `from protocol` match values for a
// firewall-filter term via the compiler (the read side, firewallMatchValues).
func firewallProtocols(t *testing.T, tree *ConfigTree, filter, term string) []string {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	f := cfg.Firewall.FiltersInet[filter]
	if f == nil {
		t.Fatalf("filter %q not found", filter)
	}
	for _, tm := range f.Terms {
		if tm.Name == term {
			got := append([]string(nil), tm.Protocols...)
			sort.Strings(got)
			return got
		}
	}
	t.Fatalf("term %q not found in filter %q", term, filter)
	return nil
}

func mustDelete(t *testing.T, tree *ConfigTree, cmd string) {
	t.Helper()
	path, err := ParseSetCommand(cmd)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
	}
	if err := tree.DeletePath(path); err != nil {
		t.Fatalf("DeletePath(%q): %v", cmd, err)
	}
}

func TestDeleteMultiLeafMember_FirewallProtocol(t *testing.T) {
	base := "set firewall family inet filter F term T from protocol [ tcp udp icmp ]"
	accept := "set firewall family inet filter F term T then accept"

	// (1) delete first member -> [udp icmp] survive.
	t.Run("delete-first-member", func(t *testing.T) {
		tree := buildTree3846(t, base, accept)
		mustDelete(t, tree, "delete firewall family inet filter F term T from protocol tcp")
		got := firewallProtocols(t, tree, "F", "T")
		if want := []string{"icmp", "udp"}; !equalStrs3846(got, want) {
			t.Fatalf("after delete tcp: protocols = %v, want %v (whole list was wrongly deleted before #3846)", got, want)
		}
	})

	// (2) delete a NON-FIRST member -> only udp removed (was undeletable before #3846).
	t.Run("delete-non-first-member", func(t *testing.T) {
		tree := buildTree3846(t, base, accept)
		mustDelete(t, tree, "delete firewall family inet filter F term T from protocol udp")
		got := firewallProtocols(t, tree, "F", "T")
		if want := []string{"icmp", "tcp"}; !equalStrs3846(got, want) {
			t.Fatalf("after delete udp: protocols = %v, want %v", got, want)
		}
	})

	// (3) delete the last-remaining member -> whole leaf gone, term has no protocol match.
	t.Run("delete-only-member-clears-leaf", func(t *testing.T) {
		tree := buildTree3846(t, "set firewall family inet filter F term T from protocol tcp", accept)
		mustDelete(t, tree, "delete firewall family inet filter F term T from protocol tcp")
		got := firewallProtocols(t, tree, "F", "T")
		if len(got) != 0 {
			t.Fatalf("after delete only member: protocols = %v, want empty", got)
		}
		if strings.Contains(tree.FormatSet(), "from protocol") {
			t.Fatalf("emptied leaf should be removed; FormatSet still has `from protocol`:\n%s", tree.FormatSet())
		}
	})

	// (4) whole-leaf delete (no trailing member) still clears the list.
	t.Run("delete-whole-leaf-no-member", func(t *testing.T) {
		tree := buildTree3846(t, base, accept)
		mustDelete(t, tree, "delete firewall family inet filter F term T from protocol")
		got := firewallProtocols(t, tree, "F", "T")
		if len(got) != 0 {
			t.Fatalf("after delete whole leaf: protocols = %v, want empty", got)
		}
	})

	// (5) deleting a member that is not present is an error (not-found contract).
	t.Run("delete-absent-member-errors", func(t *testing.T) {
		tree := buildTree3846(t, base, accept)
		path, _ := ParseSetCommand("delete firewall family inet filter F term T from protocol gre")
		if err := tree.DeletePath(path); err == nil {
			t.Fatal("deleting an absent member should return an error")
		}
		// The list is untouched by the failed delete.
		got := firewallProtocols(t, tree, "F", "T")
		if want := []string{"icmp", "tcp", "udp"}; !equalStrs3846(got, want) {
			t.Fatalf("after failed delete: protocols = %v, want %v", got, want)
		}
	})

	// (6) multiple members in one bracketed delete are all removed.
	t.Run("delete-multiple-members", func(t *testing.T) {
		tree := buildTree3846(t, base, accept)
		mustDelete(t, tree, "delete firewall family inet filter F term T from protocol [ tcp icmp ]")
		got := firewallProtocols(t, tree, "F", "T")
		if want := []string{"udp"}; !equalStrs3846(got, want) {
			t.Fatalf("after delete [tcp icmp]: protocols = %v, want %v", got, want)
		}
	})
}

// TestDeleteMultiLeafMember_HostInboundServices exercises the same fix on a
// security-zone host-inbound-traffic system-services value list.
func TestDeleteMultiLeafMember_HostInboundServices(t *testing.T) {
	tree := buildTree3846(t,
		"set security zones security-zone trust host-inbound-traffic system-services [ ssh ping https ]",
	)
	mustDelete(t, tree, "delete security zones security-zone trust host-inbound-traffic system-services ssh")

	out := tree.FormatSet()
	if strings.Contains(out, "system-services ssh") {
		t.Fatalf("ssh should be gone:\n%s", out)
	}
	for _, want := range []string{"https", "ping"} {
		if !strings.Contains(out, want) {
			t.Fatalf("host-inbound-services %q should survive deleting ssh:\n%s", want, out)
		}
	}

	// Non-first member removable too.
	mustDelete(t, tree, "delete security zones security-zone trust host-inbound-traffic system-services https")
	out = tree.FormatSet()
	if strings.Contains(out, "https") {
		t.Fatalf("https should be gone:\n%s", out)
	}
	if !strings.Contains(out, "ping") {
		t.Fatalf("ping should survive:\n%s", out)
	}
}

// TestDeleteMultiLeafMember_PolicyMatch exercises the fix on a security policy
// match value list (source-address).
func TestDeleteMultiLeafMember_PolicyMatch(t *testing.T) {
	tree := buildTree3846(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address a1 10.0.1.0/24",
		"set security address-book global address a2 10.0.2.0/24",
		"set security address-book global address a3 10.0.3.0/24",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address [ a1 a2 a3 ]",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
	)
	mustDelete(t, tree, "delete security policies from-zone trust to-zone untrust policy p1 match source-address a2")

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var pol *Policy
	for _, pr := range cfg.Security.Policies {
		if pr.FromZone == "trust" && pr.ToZone == "untrust" {
			for _, p := range pr.Policies {
				if p.Name == "p1" {
					pol = p
				}
			}
		}
	}
	if pol == nil {
		t.Fatal("policy p1 not found")
	}
	got := append([]string(nil), pol.Match.SourceAddresses...)
	sort.Strings(got)
	if want := []string{"a1", "a3"}; !equalStrs3846(got, want) {
		t.Fatalf("after delete source-address a2: source-addresses = %v, want %v", got, want)
	}
}

// TestDeleteMultiLeafMember_KeyedEntriesUnaffected asserts the args==2 keyed
// multi entry (address <name> <prefix>) keeps whole-node delete semantics: the
// #3846 member branch must NOT touch it (deleting `address a1` removes that
// whole entry, not just the name token).
func TestDeleteMultiLeafMember_KeyedEntriesUnaffected(t *testing.T) {
	tree := buildTree3846(t,
		"set security address-book global address a1 10.0.1.0/24",
		"set security address-book global address a2 10.0.2.0/24",
	)
	mustDelete(t, tree, "delete security address-book global address a1")
	out := tree.FormatSet()
	if strings.Contains(out, "address a1") {
		t.Fatalf("address a1 should be fully deleted:\n%s", out)
	}
	if !strings.Contains(out, "address a2 10.0.2.0/24") {
		t.Fatalf("address a2 should survive intact:\n%s", out)
	}
}

func equalStrs3846(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
