package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// withFakeIfaceResolver replaces the proxyARPIfaceMap interface resolver with a
// fixed name→ifindex map so the RETH-resolution logic can be exercised without
// real interfaces, restoring the production resolver on cleanup.
func withFakeIfaceResolver(t *testing.T, byName map[string]int) {
	t.Helper()
	prev := ifaceIndexByName
	ifaceIndexByName = func(name string) (int, error) {
		if idx, ok := byName[name]; ok {
			return idx, nil
		}
		return 0, errors.New("no such device: " + name)
	}
	t.Cleanup(func() { ifaceIndexByName = prev })
}

// TestProxyARPIfaceMap_ResolvesRethToPhysical is the #2195/#2197 SMR F6
// regression guard: a proxy-arp entry on a RETH (sub-)interface must resolve to
// the PHYSICAL member ifindex (via cfg.RethToPhysical + config.LinuxIfName).
// Losing this resolution in the apply-path extraction would silently break
// proxy-arp on RETH interfaces (the NTF_PROXY entry / sysctl would land on the
// wrong — or no — link). The fake resolver only knows the physical member name,
// so a non-resolving extraction would drop the entry and fail this test.
func TestProxyARPIfaceMap_ResolvesRethToPhysical(t *testing.T) {
	// RethToPhysical is built from Interfaces with RedundantParent set; node 0
	// is local (slot-0 member preferred). reth0 → ge-0/0/2 (local member).
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
				"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
				"ge-7/0/2": {Name: "ge-7/0/2", RedundantParent: "reth0"},
			},
		},
	}
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 0}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "reth0.50", Addresses: []string{"172.16.50.50/32"}},
	}

	// reth0 → ge-0/0/2 (local member) → Linux name ge-0-0-2.
	const wantIdx = 42
	linux := config.LinuxIfName("ge-0/0/2")
	withFakeIfaceResolver(t, map[string]int{linux: wantIdx})

	m := proxyARPIfaceMap(cfg)
	got, ok := m["reth0.50"]
	if !ok {
		t.Fatalf("reth0.50 not resolved; map=%v (RETH→physical resolution dropped?)", m)
	}
	if got != wantIdx {
		t.Fatalf("reth0.50 ifindex = %d, want %d (physical member %s)", got, wantIdx, linux)
	}
}

// TestProxyARPIfaceMap_DedupesAndSkipsUnresolvable verifies the helper dedupes
// repeated interface keys and best-effort skips an interface that does not
// resolve, without aborting the rest.
func TestProxyARPIfaceMap_DedupesAndSkipsUnresolvable(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "ge-0/0/1", Addresses: []string{"10.0.0.1/32"}},
		{Interface: "ge-0/0/1", Addresses: []string{"10.0.0.2/32"}}, // dup key
		{Interface: "ge-0/0/9", Addresses: []string{"10.0.0.3/32"}}, // unresolvable
	}
	withFakeIfaceResolver(t, map[string]int{config.LinuxIfName("ge-0/0/1"): 5})

	m := proxyARPIfaceMap(cfg)
	if len(m) != 1 {
		t.Fatalf("map = %v, want exactly one resolved entry", m)
	}
	if m["ge-0/0/1"] != 5 {
		t.Fatalf("ge-0/0/1 ifindex = %d, want 5", m["ge-0/0/1"])
	}
}

// TestReconcileProxyARP_NoEntriesIsNoOp verifies the extracted daemon method is
// a no-op (no panic, no resolver call) when no proxy-arp entries are
// configured — the property that makes the always-on loop cheap on configs that
// do not use proxy-arp.
func TestReconcileProxyARP_NoEntriesIsNoOp(t *testing.T) {
	called := false
	prev := ifaceIndexByName
	ifaceIndexByName = func(name string) (int, error) { called = true; return 0, nil }
	t.Cleanup(func() { ifaceIndexByName = prev })

	d := &Daemon{}
	d.reconcileProxyARP(&config.Config{}) // empty config
	d.reconcileProxyARP(nil)              // nil config
	if called {
		t.Fatal("reconcileProxyARP resolved interfaces despite no proxy-arp entries")
	}
}
