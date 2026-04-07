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
			Inet6StaticRoutes: []*config.StaticRoute{
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
		},
	}

	got := inferIPv6StaticNextHopInterfaces(cfg)
	if got["2001:559:8585:50::1"] != "reth0.50" {
		t.Fatalf("default route next-hop interface = %q, want reth0.50", got["2001:559:8585:50::1"])
	}
	if got["2001:559:8585:80::1"] != "reth0.80" {
		t.Fatalf("gre route next-hop interface = %q, want reth0.80", got["2001:559:8585:80::1"])
	}
}
