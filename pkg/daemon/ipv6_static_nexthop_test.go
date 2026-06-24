package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestInferIPv6StaticNextHopInterfaces(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Units: map[int]*config.InterfaceUnit{
						50: {Addresses: []string{"2001:559:8585:50::8/64"}},
						80: {Addresses: []string{"2001:559:8585:80::8/64"}},
					},
				},
				"reth1": {
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"2001:559:8585:ef00::1/64"}},
					},
				},
			},
		},
		RoutingOptions: config.RoutingOptionsConfig{
			StaticRoutes: []*config.StaticRoute{
				{
					Destination: "::/0",
					NextHops: []config.NextHopEntry{
						{Address: "2001:559:8585:50::1"},
					},
				},
				{
					Destination: "2602:ffd3:0:2::/64",
					NextHops: []config.NextHopEntry{
						{Address: "2001:559:8585:80::1"},
					},
				},
			},
			Inet6StaticRoutes: []*config.StaticRoute{
				{
					Destination: "2001:db8:ffff::/48",
					NextHops: []config.NextHopEntry{
						{Address: "2001:559:8585:ef00::2"},
					},
				},
			},
		},
	}

	got := inferIPv6StaticNextHopInterfaces(cfg)
	if got[""]["2001:559:8585:50::1"] != "reth0.50" {
		t.Fatalf("default route next-hop interface = %q, want reth0.50", got[""]["2001:559:8585:50::1"])
	}
	if got[""]["2001:559:8585:80::1"] != "reth0.80" {
		t.Fatalf("gre route next-hop interface = %q, want reth0.80", got[""]["2001:559:8585:80::1"])
	}
	if got[""]["2001:559:8585:ef00::2"] != "reth1" {
		t.Fatalf("inet6 static route next-hop interface = %q, want reth1", got[""]["2001:559:8585:ef00::2"])
	}
}

func TestInferIPv6StaticNextHopInterfaces_ByVRFAndDeterministicTieBreak(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth1": {
					Units: map[int]*config.InterfaceUnit{
						10: {Addresses: []string{"2001:db8:1::1/64"}},
					},
				},
				"reth0": {
					Units: map[int]*config.InterfaceUnit{
						10: {Addresses: []string{"2001:db8:1::2/64"}},
					},
				},
			},
		},
		RoutingOptions: config.RoutingOptionsConfig{
			Inet6StaticRoutes: []*config.StaticRoute{
				{
					Destination: "::/0",
					NextHops:    []config.NextHopEntry{{Address: "2001:db8:1::100"}},
				},
			},
		},
		RoutingInstances: []*config.RoutingInstanceConfig{
			{
				Name:         "BLUE",
				InstanceType: "vrf",
				Interfaces:   []string{"reth1.10"},
				Inet6StaticRoutes: []*config.StaticRoute{
					{
						Destination: "2001:db8:ffff::/48",
						NextHops:    []config.NextHopEntry{{Address: "2001:db8:1::100"}},
					},
				},
			},
		},
	}

	got := inferIPv6StaticNextHopInterfaces(cfg)
	if got[""]["2001:db8:1::100"] != "reth0.10" {
		t.Fatalf("global tie-break interface = %q, want reth0.10", got[""]["2001:db8:1::100"])
	}
	if got["vrf-BLUE"]["2001:db8:1::100"] != "reth1.10" {
		t.Fatalf("vrf-scoped interface = %q, want reth1.10", got["vrf-BLUE"]["2001:db8:1::100"])
	}
}

// TestInferIPv6StaticNextHopInterfaces_LinkLocalSingleInterface proves the
// #2452 fix: an unqualified fe80::/64 next-hop on the box's only IPv6
// interface resolves to that interface scope via the synthetic fe80::/64
// candidate. Fail-on-revert: removing the synthetic candidate (or the
// link-local resolve branch) leaves the next-hop unresolved ("") and FRR
// would emit a scopeless `ipv6 route ::/0 fe80::1`, which it rejects.
func TestInferIPv6StaticNextHopInterfaces_LinkLocalSingleInterface(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/3": {
					Units: map[int]*config.InterfaceUnit{
						50: {Addresses: []string{"2001:559:8585:50::8/64"}},
					},
				},
			},
		},
		RoutingOptions: config.RoutingOptionsConfig{
			Inet6StaticRoutes: []*config.StaticRoute{
				{
					Destination: "::/0",
					NextHops:    []config.NextHopEntry{{Address: "fe80::1"}},
				},
			},
		},
	}

	got := inferIPv6StaticNextHopInterfaces(cfg)
	if got[""]["fe80::1"] != "ge-0-0-3.50" {
		t.Fatalf("link-local next-hop interface = %q, want ge-0-0-3.50", got[""]["fe80::1"])
	}
}

// TestInferIPv6StaticNextHopInterfaces_LinkLocalMultipleAmbiguous proves the
// disambiguation rule: with multiple IPv6-capable interfaces and NO explicit
// interface qualifier, an unqualified link-local next-hop is genuinely
// ambiguous (it matches every interface's fe80::/64). We refuse to guess and
// leave it unresolved rather than silently routing to the wrong link.
func TestInferIPv6StaticNextHopInterfaces_LinkLocalMultipleAmbiguous(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/3": {
					Units: map[int]*config.InterfaceUnit{
						50: {Addresses: []string{"2001:559:8585:50::8/64"}},
					},
				},
				"ge-0/0/4": {
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"2001:559:8585:ef00::1/64"}},
					},
				},
			},
		},
		RoutingOptions: config.RoutingOptionsConfig{
			Inet6StaticRoutes: []*config.StaticRoute{
				{
					Destination: "::/0",
					NextHops:    []config.NextHopEntry{{Address: "fe80::1"}},
				},
			},
		},
	}

	got := inferIPv6StaticNextHopInterfaces(cfg)
	if iface := got[""]["fe80::1"]; iface != "" {
		t.Fatalf("ambiguous link-local next-hop interface = %q, want \"\" (refuse to guess)", iface)
	}
}

// TestInferIPv6StaticNextHopInterfaces_LinkLocalExplicitQualifier confirms an
// operator-qualified link-local next-hop never reaches the inference path
// (addRoutes skips next-hops with an explicit Interface), so even with
// multiple IPv6 interfaces the inference map carries no entry for it — the
// FRR renderer uses nh.Interface directly. This documents the
// "explicit-qualifier wins" arm of the disambiguation rule.
func TestInferIPv6StaticNextHopInterfaces_LinkLocalExplicitQualifier(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/3": {
					Units: map[int]*config.InterfaceUnit{
						50: {Addresses: []string{"2001:559:8585:50::8/64"}},
					},
				},
				"ge-0/0/4": {
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"2001:559:8585:ef00::1/64"}},
					},
				},
			},
		},
		RoutingOptions: config.RoutingOptionsConfig{
			Inet6StaticRoutes: []*config.StaticRoute{
				{
					Destination: "::/0",
					NextHops:    []config.NextHopEntry{{Address: "fe80::1", Interface: "ge-0/0/3.50"}},
				},
			},
		},
	}

	got := inferIPv6StaticNextHopInterfaces(cfg)
	if iface, ok := got[""]["fe80::1"]; ok {
		t.Fatalf("qualified link-local next-hop should not be in inference map, got %q", iface)
	}
}

// TestInferIPv6StaticNextHopInterfaces_VRRPVIPSubnet proves the #2452
// secondary fix (agy-13): a next-hop inside a VRRP virtual-address subnet on
// a member interface that carries ONLY the VIP (no unit.Addresses entry —
// bondless RETH) resolves to that member interface. Fail-on-revert: dropping
// the VRRPGroups scan leaves the next-hop unresolved ("").
func TestInferIPv6StaticNextHopInterfaces_VRRPVIPSubnet(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Units: map[int]*config.InterfaceUnit{
						50: {
							// No real Addresses — only the VRRP VIP subnet.
							VRRPGroups: map[string]*config.VRRPGroup{
								"2001:559:8585:50::8/64": {
									ID:               1,
									VirtualAddresses: []string{"2001:559:8585:50::1"},
								},
							},
						},
					},
				},
			},
		},
		RoutingOptions: config.RoutingOptionsConfig{
			Inet6StaticRoutes: []*config.StaticRoute{
				{
					Destination: "2602:ffd3::/48",
					NextHops:    []config.NextHopEntry{{Address: "2001:559:8585:50::254"}},
				},
			},
		},
	}

	got := inferIPv6StaticNextHopInterfaces(cfg)
	if got[""]["2001:559:8585:50::254"] != "reth0.50" {
		t.Fatalf("VIP-subnet next-hop interface = %q, want reth0.50", got[""]["2001:559:8585:50::254"])
	}
}
