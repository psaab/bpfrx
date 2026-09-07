package dataplane

import (
	"errors"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TestReconcileProxyARP_SweepsRemovedInterface is the #4955 fail-on-revert
// anchor: an NTF_PROXY neighbor entry on an interface that a PRIOR commit
// installed proxy-arp on, but that has since dropped out of the config, must be
// NeighDel'd. Before the fix ReconcileProxyARP built its managed listing set
// exclusively from the current config, so a removed interface's ifindex was
// never listed and its NTF_PROXY entry was orphaned — the kernel kept answering
// ARP for the retired target. Feeding the prior interface set in through
// priorIfaceMap makes the reconcile list it, find the entry stale (nothing in
// the config wants it), and delete it.
//
// Fail-on-revert: dropping the priorIfaceMap→managedSet fold makes managedSet
// empty (the config has no entries), so nothing is listed and no NeighDel
// fires — failing the "want 1 NeighDel" assertion.
func TestReconcileProxyARP_SweepsRemovedInterface(t *testing.T) {
	const removedIdx = 200
	orphan := net.ParseIP("10.0.2.50").To4()
	existing := []netlink.Neigh{{
		LinkIndex: removedIdx,
		IP:        orphan,
		Flags:     unix.NTF_PROXY,
		Family:    unix.AF_INET,
	}}
	_, dels := captureNeigh(t, existing)
	captureProxySysctl(t, false)

	// Current config has NO proxy-arp entries — the interface (and its address)
	// was fully removed. The daemon still remembers it installed proxy-arp on
	// ge-0-0-1 last commit, and passes that through as priorIfaceMap.
	cfg := &config.Config{}
	priorIfaceMap := map[string]int{"ge-0-0-1": removedIdx}

	_, _, err := ReconcileProxyARP(cfg, map[string]int{}, priorIfaceMap, nil)
	if err != nil {
		t.Fatalf("ReconcileProxyARP: %v", err)
	}

	if len(*dels) != 1 {
		t.Fatalf("got %d NeighDel calls, want 1 (orphaned NTF_PROXY sweep): %+v", len(*dels), *dels)
	}
	d := (*dels)[0]
	if d.LinkIndex != removedIdx || d.Family != unix.AF_INET || !d.IP.Equal(orphan) {
		t.Fatalf("NeighDel = {ifindex %d, family %d, ip %v}, want {%d, AF_INET, %v}",
			d.LinkIndex, d.Family, d.IP, removedIdx, orphan)
	}
	if d.Flags&unix.NTF_PROXY == 0 {
		t.Fatalf("NeighDel flags = %#x, missing NTF_PROXY", d.Flags)
	}
}

// TestReconcileProxyARP_PartialAddKeepsEnabledSet guards the #4955 secondary
// bug: a NeighSet failure mid-add must NOT abort with a nil enabled set. The
// daemon overwrites its remembered proxy-arp state with the returned enabled
// set every reconcile; a nil return wiped it, so the daemon forgot every
// interface it had managed and never tore down the sysctl or swept the neighbor
// entries on a later removal. The add loop is now best-effort — it logs the
// failure, keeps going, and returns the computed (non-nil) enabled set plus the
// first error.
//
// Fail-on-revert: restoring the `return nil, nil, err` fast-path makes the
// enabled return nil, failing the non-nil assertion.
func TestReconcileProxyARP_PartialAddKeepsEnabledSet(t *testing.T) {
	prevList, prevSet, prevDel := neighProxyListSeam, neighSetSeam, neighDelSeam
	neighProxyListSeam = func(_, _ int) ([]netlink.Neigh, error) { return nil, nil }
	neighSetSeam = func(_ *netlink.Neigh) error { return errors.New("simulated netlink failure") }
	neighDelSeam = func(_ *netlink.Neigh) error { return nil }
	t.Cleanup(func() { neighProxyListSeam, neighSetSeam, neighDelSeam = prevList, prevSet, prevDel })
	captureProxySysctl(t, false)

	cfg := &config.Config{}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "ge-0-0-2", Addresses: []string{"10.0.2.50/32"}},
	}
	ifaceMap := map[string]int{"ge-0-0-2": 7}

	_, enabled, err := ReconcileProxyARP(cfg, ifaceMap, nil, nil)
	if err == nil {
		t.Fatalf("want the NeighSet failure surfaced as an error, got nil")
	}
	if enabled == nil {
		t.Fatalf("enabled set is nil after a partial add failure — the daemon's " +
			"remembered proxy-arp state would be wiped (#4955 secondary)")
	}
}
