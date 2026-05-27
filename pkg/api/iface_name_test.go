package api

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcp"
)

// TestInterfacesHandler_ResolvesRethToLoopback pins the #1565 fix: when
// a Junos config name doesn't directly map to a kernel ifname (RETH
// alias, slash-containing name, etc.), the handler must translate via
// (*Config).ResolveKernelIfName before calling net.InterfaceByName.
//
// We synthesize a cfg where reth0's RETH member is literally named
// "lo" — the loopback netdev is the only one guaranteed to exist on
// any Linux test runner. Pre-fix, the raw lookup of "reth0" returns
// no kernel ifindex (RETH names are virtual). Post-fix,
// ResolveKernelIfName("reth0") returns "lo" and the row's ifindex
// matches net.InterfaceByName("lo").Index.
func TestInterfacesHandler_ResolvesRethToLoopback(t *testing.T) {
	loIface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("test runner has no lo netdev: %v", err)
	}

	// Build a Junos config via configstore.LoadSet so we exercise the
	// real compiler path. `lo { gigether-options { redundant-parent reth0; } }`
	// plus `reth0` registers lo as reth0's physical member.
	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	sets := []string{
		"set chassis cluster reth-count 1",
		"set interfaces lo gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set security zones security-zone trust interfaces reth0",
	}
	for _, s := range sets {
		if _, err := store.LoadSet(s); err != nil {
			t.Fatalf("LoadSet(%q): %v", s, err)
		}
	}
	cfg, err := store.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Sanity: cfg.ResolveReth must resolve reth0 to lo. If not, the
	// test setup is wrong and we should fail loudly rather than
	// silently observing ifindex=0.
	if got := cfg.ResolveReth("reth0"); got != "lo" {
		t.Fatalf("ResolveReth(reth0) = %q, want lo (test cfg setup wrong)", got)
	}
	if got := cfg.ResolveKernelIfName("reth0"); got != "lo" {
		t.Fatalf("ResolveKernelIfName(reth0) = %q, want lo", got)
	}

	s := &Server{store: store}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/interfaces", nil)
	s.interfacesHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rows, ok := resp.Data.([]any)
	if !ok {
		t.Fatalf("data = %T, want []any", resp.Data)
	}

	var rethRow map[string]any
	for _, r := range rows {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if name, _ := m["name"].(string); name == "reth0" {
			rethRow = m
			break
		}
	}
	if rethRow == nil {
		t.Fatalf("no row for reth0 in /interfaces response: %s", rr.Body.String())
	}
	idx, _ := rethRow["ifindex"].(float64)
	if int(idx) != loIface.Index {
		t.Errorf("reth0 ifindex = %v, want %d (loopback) — translation broken",
			rethRow["ifindex"], loIface.Index)
	}
}

// TestWriteInterfacesDetail_DHCPLeasePath pins the #1565 fix on the
// detail handler: DHCP lease annotation must key by the daemon's
// actual lease-key shape (LinuxIfName(configRef) + ".VlanID" when
// positive), not by the raw Junos config name.
//
// We bind the cfg's reth0 to lo (the only netdev guaranteed to exist)
// and use unit 0 with no VLAN tagging so the kernel link resolves
// (ResolveKernelIfName("reth0")="lo") and the detail handler reaches
// the lease-print branch.
func TestWriteInterfacesDetail_DHCPLeasePath(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skipf("test runner has no lo netdev: %v", err)
	}

	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	sets := []string{
		"set chassis cluster reth-count 1",
		"set interfaces lo gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet dhcp",
		"set security zones security-zone trust interfaces reth0",
	}
	for _, s := range sets {
		if _, err := store.LoadSet(s); err != nil {
			t.Fatalf("LoadSet(%q): %v", s, err)
		}
	}
	cfg, err := store.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Compute the expected DHCP lease key the daemon would use.
	// For unit 0 with no vlan-id, the key is just LinuxIfName("reth0")
	// = "reth0".
	wantKey, ok := cfg.DHCPLeaseKey("reth0", 0)
	if !ok || wantKey != "reth0" {
		t.Fatalf("DHCPLeaseKey(reth0, 0) = (%q, %v), want (reth0, true)", wantKey, ok)
	}

	// Seed a lease at that key in a real dhcp.Manager.
	dm, err := dhcp.New(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("dhcp.New: %v", err)
	}
	lease := &dhcp.Lease{
		Address: netip.MustParsePrefix("192.0.2.5/24"),
		Gateway: netip.MustParseAddr("192.0.2.1"),
	}
	dm.SeedLeaseForTesting(wantKey, dhcp.AFInet, lease)

	s := &Server{store: store, dhcp: dm}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/interfaces-detail", nil)
	s.interfacesDetailHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tr, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("data = %T, want map", resp.Data)
	}
	out, _ := tr["output"].(string)
	if !strings.Contains(out, "DHCPv4: 192.0.2.5/24 (gw 192.0.2.1)") {
		t.Errorf("output missing DHCPv4 lease annotation; got:\n%s", out)
	}
}
