package daemon

import (
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ddns"
)

// #2691 P2 daemon-level Surface A tests: scope construction from the committed
// per-interface bindings + provider catalog (with RG attribution), and the
// per-RG HA gate. Fail-on-revert: prove a binding resolves to a scoped publish
// record and that an HA-owned (reth) interface scope is keyed on its RG.

func TestBuildSurfaceAScopesFromConfig(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set system services dynamic-dns provider corp-2136 backend rfc2136",
		"set system services dynamic-dns provider corp-2136 update-server 192.0.2.53",
		"set system services dynamic-dns forced-refresh 24h",
		"set interfaces ge-0/0/2 unit 50 family inet dynamic-dns provider corp-2136",
		"set interfaces ge-0/0/2 unit 50 family inet dynamic-dns hostname wan.example.net",
		"set interfaces ge-0/0/2 unit 50 family inet dynamic-dns address-source dhcp",
		"set interfaces ge-0/0/2 unit 50 family inet6 dynamic-dns provider corp-2136",
		"set interfaces ge-0/0/2 unit 50 family inet6 dynamic-dns hostname wan6.example.net",
		// A binding whose provider is undefined must be skipped.
		"set interfaces ge-0/0/3 unit 0 family inet dynamic-dns provider ghost",
		"set interfaces ge-0/0/3 unit 0 family inet dynamic-dns hostname ghost.example.net",
	})
	d := &Daemon{store: store}
	cfg := d.store.ActiveConfig()
	scopes := d.buildSurfaceAScopes(cfg)

	byFQDN := map[string]ddns.SurfaceAScope{}
	for _, s := range scopes {
		byFQDN[s.FQDN] = s
	}
	if _, ok := byFQDN["ghost.example.net"]; ok {
		t.Fatal("a binding referencing an undefined provider must be skipped")
	}
	v4, ok := byFQDN["wan.example.net"]
	if !ok {
		t.Fatalf("inet binding scope missing; got %d scopes", len(scopes))
	}
	if v4.Key.Family != ddns.FamilyV4 || v4.Key.Interface != "ge-0/0/2" || v4.Key.Unit != 50 {
		t.Fatalf("inet scope key mismatch: %+v", v4.Key)
	}
	if v4.Source != ddns.AddressSourceDHCP {
		t.Fatalf("inet scope source = %q, want dhcp", v4.Source)
	}
	if v4.Provider == nil || v4.Provider.UpdateServer != "192.0.2.53" {
		t.Fatalf("inet scope provider not resolved: %+v", v4.Provider)
	}
	if v4.ForcedRefresh.Hours() != 24 {
		t.Fatalf("forced-refresh not threaded into the scope: %v", v4.ForcedRefresh)
	}
	v6, ok := byFQDN["wan6.example.net"]
	if !ok {
		t.Fatal("inet6 binding scope missing")
	}
	if v6.Key.Family != ddns.FamilyV6 {
		t.Fatalf("inet6 scope family mismatch: %+v", v6.Key)
	}
	if v4.Source == ddns.AddressSourceInterface {
		t.Fatal("inet scope should be dhcp, not interface default")
	}
}

func TestBuildSurfaceAScopesAttributesRG(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set system services dynamic-dns provider corp-2136 backend rfc2136",
		"set system services dynamic-dns provider corp-2136 update-server 192.0.2.53",
		"set interfaces reth0 unit 80 family inet dynamic-dns provider corp-2136",
		"set interfaces reth0 unit 80 family inet dynamic-dns hostname vip.example.net",
	})
	d := &Daemon{store: store, cluster: cluster.NewManager(0, 1)}
	cfg := d.store.ActiveConfig()
	scopes := d.buildSurfaceAScopes(cfg)
	if len(scopes) != 1 {
		t.Fatalf("expected one reth scope, got %d", len(scopes))
	}
	if scopes[0].Key.RGOwner != 1 {
		t.Fatalf("a reth0 (RG1) binding must attribute RGOwner=1, got %d", scopes[0].Key.RGOwner)
	}
}

func TestSurfaceAGatePerRG(t *testing.T) {
	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cluster.NewManager(0, 1),
	}
	// No RG is master yet → an RG1 scope is gated CLOSED; an RG0 (non-HA)
	// scope is always admitted.
	gate := d.surfaceAGate()
	if gate == nil {
		t.Fatal("cluster daemon must produce a per-RG gate")
	}
	if gate(ddns.ScopeKey{RGOwner: 1}) {
		t.Fatal("RG1 scope must be gated closed when not master for RG1")
	}
	if !gate(ddns.ScopeKey{RGOwner: 0}) {
		t.Fatal("RG0 (non-HA) scope must be admitted")
	}
}

func TestSurfaceAStandaloneGateNil(t *testing.T) {
	d := &Daemon{} // no cluster
	if d.surfaceAGate() != nil {
		t.Fatal("standalone daemon must return a nil gate (every scope writable)")
	}
}

func TestStaticUnitAddr(t *testing.T) {
	unit := &config.InterfaceUnit{Addresses: []string{"203.0.113.5/24", "2001:db8::8/64"}}
	a4, ok := staticUnitAddr(unit, true)
	if !ok || a4 != netip.MustParseAddr("203.0.113.5") {
		t.Fatalf("v4 static addr = %v ok=%v", a4, ok)
	}
	a6, ok := staticUnitAddr(unit, false)
	if !ok || a6 != netip.MustParseAddr("2001:db8::8") {
		t.Fatalf("v6 static addr = %v ok=%v", a6, ok)
	}
	// Link-local / loopback are skipped.
	llUnit := &config.InterfaceUnit{Addresses: []string{"fe80::1/64"}}
	if _, ok := staticUnitAddr(llUnit, false); ok {
		t.Fatal("link-local must not be selected as a Surface A address")
	}
}
