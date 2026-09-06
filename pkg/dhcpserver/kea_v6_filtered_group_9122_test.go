package dhcpserver

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9122: a DHCPv6 group NARROWED by the RG member filter rendered `subnet6`
// with an EMPTY interface selector, contradicting the renderer's own invariant
// three lines above.
//
// Kea v6 subnet selection cannot fall back to address matching the way v4 can —
// clients talk from link-local sources — so `subnet6` REQUIRES the selector.
// The renderer says exactly that and rejects `len(group.Interfaces) > 1`. But
// `subnetInterface` returns "" first on `MembersFiltered`, and the filtered
// list is a SINGLETON, so the rejection no longer trips and the subnet renders
// selector-less. Kea then cannot select it for a link-local SOLICIT: a silent,
// total DHCPv6 outage for that group with no error anywhere.
//
// IT IS THE STEADY STATE, not a failover transient.
// `filterDHCPConfigForMasterRGs` runs on the 2s periodic converger as well as
// on RG edges, so a v6 group spanning two RGs in an active/active cluster
// renders this way continuously on BOTH nodes.
//
// #6520's remedy — suppress the selector and fall back to address-based
// selection — is valid for v4 and INVALID for v6. The v4 half is untouched and
// a cell below pins that.
//
// The originating report's proposed fix is HARMFUL and is pinned against here:
// returning `group.Interfaces[0]` for a narrowed singleton binds the REMOVED
// member's pool to the SURVIVOR's interface — precisely the cross-bind #6520
// exists to stop, re-opened for v6. Kea would lease a foreign prefix on that
// link.

// filteredGroupV6Config mirrors filteredGroupV4Config: two pools, one per
// member, as the group arrives after the cluster filter removed one member.
func filteredGroupV6Config(filtered bool) *config.DHCPServerConfig {
	// generateKea6Config reads DHCPv6LocalServer, not DHCPLocalServer. Using the
	// v4 container here rendered NOTHING and panicked on the nil — a fixture
	// that silently answers a different question than the cell asks.
	return &config.DHCPServerConfig{
		DHCPv6LocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{
				"v6mixed": {
					Name:            "v6mixed",
					Interfaces:      []string{"ge-0-0-1"},
					MembersFiltered: filtered,
					Pools: []*config.DHCPPool{
						{Name: "lan", Subnet: "2001:db8:1::/64", RangeLow: "2001:db8:1::10", RangeHigh: "2001:db8:1::20"},
					},
				},
			},
		},
	}
}

// twoInterfaceV6Config is the LOUD path that already existed: an operator-
// authored multi-interface v6 group.
func twoInterfaceV6Config() *config.DHCPServerConfig {
	c := filteredGroupV6Config(false)
	g := c.DHCPv6LocalServer.Groups["v6mixed"]
	g.Interfaces = []string{"ge-0-0-1", "ge-0-0-2"}
	return c
}

// subnet6Selectors returns subnet CIDR -> per-subnet `interface` selector.
func subnet6Selectors(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var outer struct {
		Dhcp6 struct {
			Subnet6 []struct {
				Subnet    string `json:"subnet"`
				Interface string `json:"interface"`
			} `json:"subnet6"`
		} `json:"Dhcp6"`
	}
	if err := json.Unmarshal(raw, &outer); err != nil {
		t.Fatal(err)
	}
	out := make(map[string]string, len(outer.Dhcp6.Subnet6))
	for _, s := range outer.Dhcp6.Subnet6 {
		out[s.Subnet] = s.Interface
	}
	return out
}

// CONTROL: an operator-authored single-interface v6 group is unaffected and
// keeps its selector. Without this, a fix that refused every v6 group would
// satisfy the subject cell while removing DHCPv6 entirely.
func TestV6AuthoredSingletonGroupKeepsItsSelector9122(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	if err := m.generateKea6Config(filteredGroupV6Config(false)); err != nil {
		t.Fatalf("CONTROL BROKE: an authored singleton v6 group must render: %v", err)
	}
	got := subnet6Selectors(t, m.confPath6)
	if len(got) != 1 {
		t.Fatalf("expected 1 rendered subnet6, got %d (%v)", len(got), got)
	}
	for subnet, sel := range got {
		if sel != "ge-0-0-1" {
			t.Fatalf("CONTROL BROKE: subnet %s selector = %q, want ge-0-0-1", subnet, sel)
		}
	}
}

// THE DEFECT: a narrowed v6 group must be REFUSED, not rendered selector-less.
func TestV6FilteredGroupIsRefusedNotRenderedSelectorless9122(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	err := m.generateKea6Config(filteredGroupV6Config(true))
	if err == nil {
		got := subnet6Selectors(t, m.confPath6)
		for subnet, sel := range got {
			if sel == "" {
				t.Fatalf("#9122: subnet6 %s rendered with an EMPTY interface selector. "+
					"Kea v6 cannot fall back to address matching (clients talk from "+
					"link-local sources), so the subnet is unselectable for a SOLICIT — "+
					"a silent, total DHCPv6 outage for this group, and the STEADY state "+
					"on an active/active pair rather than a failover transient", subnet)
			}
		}
		t.Fatalf("#9122: a narrowed v6 group must be refused; it rendered %v", got)
	}
	// The refusal must NAME the narrowing, not be mistaken for the
	// multi-interface case: the remedy differs (author one group per RG, versus
	// split an over-broad group), and #9073's lesson is that distinct states
	// need distinct signals.
	if !strings.Contains(err.Error(), "narrowed") {
		t.Errorf("#9122: the refusal must identify RG NARROWING as the cause, so the "+
			"operator is told to author one group per redundancy group rather than "+
			"to split a group they did not write that way: %v", err)
	}
	if !strings.Contains(err.Error(), "v6mixed") {
		t.Errorf("#9122: the refusal must name the group: %v", err)
	}
}

// THE HARMFUL FIX, pinned against. If a future change makes the narrowed group
// render `Interfaces[0]`, the removed member's pool is cross-bound to the
// survivor's link — #6520 re-opened for v6.
func TestV6FilteredGroupNeverCrossBindsToTheSurvivor9122(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	if err := m.generateKea6Config(filteredGroupV6Config(true)); err == nil {
		got := subnet6Selectors(t, m.confPath6)
		for subnet, sel := range got {
			if sel != "" {
				t.Fatalf("#9122: subnet6 %s was bound to %q after RG narrowing. The "+
					"group has no pool->member edge, so this binds the REMOVED member's "+
					"network to the SURVIVOR's interface and Kea leases a foreign "+
					"prefix on that link — the #6520 cross-bind, re-opened for v6",
					subnet, sel)
			}
		}
	}
}

// The pre-existing LOUD path must still fire, and with its own message. This is
// the control the issue calls the one that matters: it proves the loud path
// exists, so the subject cell's failure is attributable to filtering routing
// AROUND it rather than to there being no gate at all.
func TestV6MultiInterfaceGroupIsStillRefusedSeparately9122(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	err := m.generateKea6Config(twoInterfaceV6Config())
	if err == nil {
		t.Fatal("#9122: an authored multi-interface v6 group must still be refused")
	}
	if !strings.Contains(err.Error(), "split the group per interface") {
		t.Errorf("#9122: the multi-interface refusal must keep its own remedy text — "+
			"folding the two causes into one message loses the distinction between "+
			"'you authored this too broadly' and 'the runtime narrowed it': %v", err)
	}
	if strings.Contains(err.Error(), "narrowed") {
		t.Errorf("#9122: the multi-interface case must NOT be reported as narrowing: %v", err)
	}
}

// The v4 suppression is UNCHANGED. #6520's address-fallback remedy is valid for
// v4 and only invalid for v6, so the fix must not leak across families.
func TestV4FilteredGroupSuppressionIsUnchanged9122(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	if err := m.generateKea4Config(filteredGroupV4Config(true)); err != nil {
		t.Fatalf("#9122: the v4 path must still RENDER a narrowed group (address-based "+
			"selection is valid there); it returned: %v", err)
	}
	got := subnetSelectors(t, m.confPath4)
	if len(got) != 2 {
		t.Fatalf("expected 2 rendered v4 subnets, got %d (%v)", len(got), got)
	}
	for subnet, sel := range got {
		if sel != "" {
			t.Fatalf("#9122: v4 subnet %s must still suppress its selector (#6520), got %q",
				subnet, sel)
		}
	}
}
