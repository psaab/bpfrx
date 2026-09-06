package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// rethCfg9137 builds a bondless-RETH cluster config: reth0 carries the unit
// addresses, and ge-0/0/2 (node 0) / ge-7/0/2 (node 1) are its physical
// members. This is the shipped HA model — no bond device is created, so
// `reth0` is NOT a kernel netdev on either node.
func rethCfg9137(t *testing.T, nodeID int, addrs []string) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: nodeID}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {
			Name:  "reth0",
			Units: map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: addrs}},
		},
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
		"ge-7/0/2": {Name: "ge-7/0/2", RedundantParent: "reth0"},
	}
	// Guard the fixture itself: if RethToPhysical does not bind, every
	// assertion below would be about a config that models nothing.
	if got := cfg.ResolveReth("reth0"); got == "reth0" || got == "" {
		t.Fatalf("FIXTURE: ResolveReth(reth0) = %q — the reth binding did not "+
			"form, so this config does not model bondless RETH", got)
	}
	return cfg
}

// #9137: resolveConfiguredInterfaceAddress zone-qualifies a link-local IPsec
// local-bind source with `config.LinuxIfName(base)` and no ResolveReth, so an
// `external-interface reth0.0` produced `fe80::1%reth0`. Under bondless RETH
// — the shipped model — `reth0` has no kernel device: xpfd programs the VRRP
// VIP and virtual MAC on the PHYSICAL member and creates no reth netdev, and
// pkg/dataplane/compiler_iface.go skips reth for the same reason. charon
// cannot if_nametoindex("reth0"), so the IKE SA never binds and the tunnel
// never establishes — from a config that commits clean.
//
// The asymmetry is inside one function pair: the sibling kernel-lookup
// fallback twenty lines up (resolveInterfaceAddressFamily) already does
// `cfg.ResolveReth(ifaceRef)`.
func TestLinkLocalZoneResolvesReth9137(t *testing.T) {
	for _, tc := range []struct {
		name   string
		nodeID int
		want   string
	}{
		{"node 0 binds its own member", 0, "fe80::1%ge-0-0-2"},
		{"node 1 binds its own member", 1, "fe80::1%ge-7-0-2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := rethCfg9137(t, tc.nodeID, []string{"fe80::1/64"})
			got := resolveConfiguredInterfaceAddress(cfg, "reth0.0", 6)
			if got != tc.want {
				t.Errorf("#9137: the IPsec link-local local_addrs zone must name a "+
					"KERNEL netdev. resolveConfiguredInterfaceAddress(reth0.0, 6) = "+
					"%q, want %q.\n  `reth0` is not a kernel device under bondless "+
					"RETH, so charon's if_nametoindex fails and the IKE SA never "+
					"binds — with a config that commits clean.", got, tc.want)
			}
		})
	}

	// The BARE-REF fallback branch (no unit in the reference) shares the same
	// `zone` variable, so it must resolve identically. A fix applied to only
	// the unit branch leaves this one wrong.
	t.Run("bare ref fallback", func(t *testing.T) {
		cfg := rethCfg9137(t, 0, []string{"fe80::1/64"})
		if got := resolveConfiguredInterfaceAddress(cfg, "reth0", 6); got != "fe80::1%ge-0-0-2" {
			t.Errorf("#9137 bare-ref fallback: got %q, want %q", got, "fe80::1%ge-0-0-2")
		}
	})

	// CONTROL 1: a NON-reth base must be byte-identical to before. A fix that
	// resolved unconditionally, or through a wider resolver, would rewrite
	// ge-0/0/3 into something else and this catches it.
	t.Run("control non-reth unchanged", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"ge-0/0/3": {Name: "ge-0/0/3", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"fe80::1/64"}},
			}},
		}
		if got := resolveConfiguredInterfaceAddress(cfg, "ge-0/0/3.0", 6); got != "fe80::1%ge-0-0-3" {
			t.Errorf("CONTROL: a non-reth base must keep its own kernel name as the "+
				"zone. got %q, want %q", got, "fe80::1%ge-0-0-3")
		}
	})

	// CONTROL 2: a GLOBAL address on the same reth must NOT acquire a zone.
	// zoneQualify only zones IPv6 link-local, and selectFamilyAddress is
	// global-wins — which is also the real bound on this finding: the
	// link-local branch is reached only when the reth unit has no global IPv6.
	t.Run("control global not zoned", func(t *testing.T) {
		cfg := rethCfg9137(t, 0, []string{"fe80::1/64", "2001:db8::5/64"})
		if got := resolveConfiguredInterfaceAddress(cfg, "reth0.0", 6); got != "2001:db8::5" {
			t.Errorf("CONTROL: a global IPv6 must win and must not be zone-qualified. "+
				"got %q, want %q", got, "2001:db8::5")
		}
	})

	// CONTROL 3: a reth whose members carry RedundantParent but no Name makes
	// RethToPhysical map reth0 -> "", and ResolveReth then returns "". An EMPTY
	// zone is strictly WORSE than the wrong one: zoneQualify returns the address
	// unqualified, losing the #2885 disambiguation entirely. The fix must
	// degrade to the pre-#9137 spelling, never to no zone.
	t.Run("control degenerate empty resolution keeps a zone", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"fe80::1/64"}},
			}},
			"ge-0/0/2": {RedundantParent: "reth0"}, // Name deliberately unset
		}
		if got := cfg.ResolveReth("reth0"); got != "" {
			t.Skipf("FIXTURE no longer degenerate: ResolveReth(reth0) = %q; "+
				"RethToPhysical no longer maps a Name-less member to the empty "+
				"string, so this control has nothing to guard", got)
		}
		if got := resolveConfiguredInterfaceAddress(cfg, "reth0.0", 6); got != "fe80::1%reth0" {
			t.Errorf("a degenerate reth binding must degrade to the pre-#9137 zone, "+
				"not to NO zone (an unqualified fe80:: is ambiguous across every "+
				"interface on the box). got %q, want %q", got, "fe80::1%reth0")
		}
	})
}

// WIRING BIND. The cells above call resolveConfiguredInterfaceAddress directly,
// which says nothing about whether its answer becomes swanctl `local_addrs`.
// This drives PrepareConfig — the function the daemon apply path and the CLI
// commit path both call — so severing
// `cp.LocalAddress = resolveInterfaceAddress(...)` reds a named cell.
func TestPrepareConfigRethLinkLocalZone9137(t *testing.T) {
	cfg := rethCfg9137(t, 0, []string{"fe80::1/64"})
	cfg.Security.IPsec = config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			// A literal IPv6 remote gives gatewayRemoteFamilyHint family 6
			// with no DNS, so the link-local branch is reached deterministically.
			"gw1": {Address: "2001:db8:9::1", ExternalIface: "reth0.0"},
		},
	}
	out := PrepareConfig(cfg)
	if out == nil {
		t.Fatal("PrepareConfig returned nil")
	}
	gw := out.Gateways["gw1"]
	if gw == nil {
		t.Fatal("NON-VACUITY: gateway gw1 absent from the prepared config, so the " +
			"assertion below would pass on an empty result")
	}
	if gw.LocalAddress != "fe80::1%ge-0-0-2" {
		t.Errorf("#9137 end-to-end: PrepareConfig -> swanctl local_addrs = %q, "+
			"want %q. `reth0` is not a kernel netdev, so charon cannot bind it.",
			gw.LocalAddress, "fe80::1%ge-0-0-2")
	}
}
