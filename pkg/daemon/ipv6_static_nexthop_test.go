package daemon

import (
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
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
	if got["vrf-BLUE"]["2001:db8:1::100"] != "reth0.10" {
		t.Fatalf("vrf tie-break interface = %q, want reth0.10", got["vrf-BLUE"]["2001:db8:1::100"])
	}
}
