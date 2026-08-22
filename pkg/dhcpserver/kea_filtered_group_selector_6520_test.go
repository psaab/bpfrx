package dhcpserver

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6520 (b): the CONSUMER half of the cluster-filter agreement. A
// DHCPServerGroup whose member list was narrowed at runtime
// (config.DHCPServerGroup.MembersFiltered, set by
// daemon.filterDHCPConfigForMasterRGs) still carries the pools of the members
// that were removed, because Interfaces and Pools have no semantic edge. Kea's
// per-subnet `interface` selector must therefore be suppressed for such a
// group: emitting it binds EVERY pool in the group — including a removed
// member's network — to the one survivor.
//
// The producer half (the filter setting the flag exactly when it shrinks a
// group) is asserted in pkg/daemon; each test names its own side so a failure
// says which one broke.

// filteredGroupV4Config renders a group holding two pools — one belonging to a
// mgmt member, one to a RETH member — as it arrives after the cluster filter
// removed the mgmt member. filtered selects whether the narrowing is recorded.
func filteredGroupV4Config(filtered bool) *config.DHCPServerConfig {
	return &config.DHCPServerConfig{
		DHCPLocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{
				"mixed": {
					Name:            "mixed",
					Interfaces:      []string{"ge-0-0-1"},
					MembersFiltered: filtered,
					Pools: []*config.DHCPPool{
						{Name: "mgmt", Subnet: "10.99.0.0/24", RangeLow: "10.99.0.10", RangeHigh: "10.99.0.20"},
						{Name: "lan", Subnet: "10.0.61.0/24", RangeLow: "10.0.61.10", RangeHigh: "10.0.61.20"},
					},
				},
			},
		},
	}
}

// subnetSelectors returns subnet CIDR -> per-subnet `interface` selector for
// every rendered Dhcp4 subnet (absent selector => "").
func subnetSelectors(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var outer struct {
		Dhcp4 struct {
			Subnet4 []struct {
				Subnet    string `json:"subnet"`
				Interface string `json:"interface"`
			} `json:"subnet4"`
		} `json:"Dhcp4"`
	}
	if err := json.Unmarshal(raw, &outer); err != nil {
		t.Fatal(err)
	}
	out := make(map[string]string, len(outer.Dhcp4.Subnet4))
	for _, s := range outer.Dhcp4.Subnet4 {
		out[s.Subnet] = s.Interface
	}
	return out
}

// TestKeaSubnetSelectorBoundForAuthoredSingletonGroup_6520 is the CONTROL: an
// operator-authored single-interface group is unchanged by #6520 and keeps the
// explicit #1778 binding on every one of its subnets.
func TestKeaSubnetSelectorBoundForAuthoredSingletonGroup_6520(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	if err := m.generateKea4Config(filteredGroupV4Config(false)); err != nil {
		t.Fatalf("generateKea4Config: %v", err)
	}
	got := subnetSelectors(t, m.confPath4)
	if len(got) != 2 {
		t.Fatalf("expected 2 rendered subnets, got %d (%v)", len(got), got)
	}
	for subnet, sel := range got {
		if sel != "ge-0-0-1" {
			t.Fatalf("CONTROL BROKE (producer side is not implicated): authored singleton group must keep its #1778 per-subnet selector; subnet %s got interface %q, want %q", subnet, sel, "ge-0-0-1")
		}
	}
}

// TestKeaSubnetSelectorSuppressedForFilteredGroup_6520 is the #6520 (b)
// regression: once the cluster filter has narrowed the group, no subnet may
// carry a per-subnet selector — the removed member's pool would be cross-bound
// onto the survivor.
func TestKeaSubnetSelectorSuppressedForFilteredGroup_6520(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	if err := m.generateKea4Config(filteredGroupV4Config(true)); err != nil {
		t.Fatalf("generateKea4Config: %v", err)
	}
	got := subnetSelectors(t, m.confPath4)
	if len(got) != 2 {
		t.Fatalf("expected 2 rendered subnets, got %d (%v)", len(got), got)
	}
	for subnet, sel := range got {
		if sel != "" {
			t.Fatalf("CONSUMER SIDE BROKE (dhcpserver.subnetInterface ignored MembersFiltered): a runtime-narrowed group must emit NO per-subnet interface selector, else the removed member's pool is cross-bound; subnet %s got interface %q", subnet, sel)
		}
	}
}
