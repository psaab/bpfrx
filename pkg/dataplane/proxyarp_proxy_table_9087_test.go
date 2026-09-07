// #9087: the reconcile listed the ORDINARY neighbour table while the entries it
// manages live in the kernel's separate PROXY (pneigh) table.
//
// netlink.NeighList and netlink.NeighProxyList differ by one field in the dump
// request:
//
//	NeighList      -> Ndmsg{Family, Index}                 (Flags 0)
//	NeighProxyList -> Ndmsg{Family, Index, Flags: NTF_PROXY}
//
// and the kernel dumps pneigh only when the request carries NTF_PROXY. So
// `existing` came back empty on every pass and both loops it feeds broke in
// opposite directions: the stale-removal loop removed NOTHING EVER (the #8297
// standby answered for the pool address indefinitely, however correctly the
// ownership gate fired), and the add loop re-issued a NeighSet every 30s
// forever because every desired key looked missing.
//
// WHY NO EXISTING UNIT TEST COULD SEE IT. Every one replaces the seam with a
// fake that returns whatever the case wants — so in every test the seam behaved
// like NeighProxyList. The fake was the only NeighProxyList in the tree, and a
// test that supplies the correct behaviour cannot observe that production does
// not. That is why the first cell below asserts the WIRING by function
// identity: it is the only layer at which this defect is visible in Go.

package dataplane

import (
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
)

// THE WIRING. A behavioural test cannot reach this: the seam is what the
// behavioural tests replace.
func TestProxyARPListsTheProxyTable9087(t *testing.T) {
	got := reflect.ValueOf(neighProxyListSeam).Pointer()
	want := reflect.ValueOf(netlink.NeighProxyList).Pointer()
	if got == reflect.ValueOf(netlink.NeighList).Pointer() {
		t.Fatal("#9087: the proxy reconcile is wired to netlink.NeighList, which dumps " +
			"the ORDINARY neighbour table (Ndmsg Flags 0). The kernel keeps proxy " +
			"entries in a separate pneigh table and dumps it only for a request " +
			"carrying NTF_PROXY, so `existing` is always empty: the stale-removal " +
			"loop can never remove anything and the add loop re-installs on every " +
			"pass forever. Wire netlink.NeighProxyList.")
	}
	if got != want {
		t.Fatalf("#9087: the proxy reconcile must list the PROXY table via " +
			"netlink.NeighProxyList; it is wired to some other function")
	}
}

// proxyEntry9087 builds the netlink.Neigh a pneigh dump returns for addr on
// ifindex — pneigh_fill_info sets ndm_flags |= NTF_PROXY, so the flag is
// present on a real dump and the reconcile's own belt still passes.
func proxyEntry9087(ifindex int, addr string) netlink.Neigh {
	return netlink.Neigh{
		LinkIndex: ifindex,
		IP:        net.ParseIP(addr),
		Flags:     unix.NTF_PROXY,
		Family:    unix.AF_INET,
	}
}

func proxyCfg9087(iface, cidr string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: iface, Addresses: []string{cidr}},
	}
	return cfg
}

// CONVERGENCE. An entry that is already installed must be recognised, so a
// steady state reports added=0. This is the observable that was screaming for
// months and that nothing asserted: the loss cluster logged
// `proxy-arp reconciled added=1 removed=0` every 30 seconds, indefinitely,
// with the entry demonstrably present in `ip neigh show proxy`.
func TestProxyARPConvergesToZeroAdds9087(t *testing.T) {
	const idx = 41
	prevList, prevSet, prevDel := neighProxyListSeam, neighSetSeam, neighDelSeam
	prevLink, prevSysctl := linkByIndexSeam, proxyARPSysctlSeam
	t.Cleanup(func() {
		neighProxyListSeam, neighSetSeam, neighDelSeam = prevList, prevSet, prevDel
		linkByIndexSeam, proxyARPSysctlSeam = prevLink, prevSysctl
	})

	neighProxyListSeam = func(linkIndex, family int) ([]netlink.Neigh, error) {
		if linkIndex == idx && family == unix.AF_INET {
			return []netlink.Neigh{proxyEntry9087(idx, "172.16.80.7")}, nil
		}
		return nil, nil
	}
	sets := 0
	neighSetSeam = func(*netlink.Neigh) error { sets++; return nil }
	neighDelSeam = func(*netlink.Neigh) error { return nil }
	linkByIndexSeam = func(int) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-2.80", Index: idx}}, nil
	}
	proxyARPSysctlSeam = func(string, int, bool) error { return nil }

	cfg := proxyCfg9087("reth0.80", "172.16.80.7/32")
	added, _, err := ReconcileProxyARP(cfg, map[string]int{"reth0.80": idx}, nil,
		map[int]string{idx: "ge-0-0-2.80"})
	if err != nil {
		t.Fatalf("ReconcileProxyARP: %v", err)
	}
	if len(added) != 0 || sets != 0 {
		t.Fatalf("#9087: an ALREADY-INSTALLED proxy entry must be recognised as "+
			"converged. added=%d NeighSet calls=%d, want 0 and 0.\n"+
			"Re-installing every pass is the visible half of listing the wrong "+
			"table, and it ran for months as `added=1 removed=0` every 30s.",
			len(added), sets)
	}
}

// THE SWEEP. A proxy entry on an interface with nothing desired — the #8297
// demoted standby, whose ownership gate correctly emptied the desired set —
// must be DELETED. This is the half that was permanently broken: the gate fired
// every 30s while the kernel entry survived indefinitely.
func TestProxyARPSweepsStaleProxyEntry9087(t *testing.T) {
	const idx = 42
	prevList, prevSet, prevDel := neighProxyListSeam, neighSetSeam, neighDelSeam
	prevLink, prevSysctl := linkByIndexSeam, proxyARPSysctlSeam
	t.Cleanup(func() {
		neighProxyListSeam, neighSetSeam, neighDelSeam = prevList, prevSet, prevDel
		linkByIndexSeam, proxyARPSysctlSeam = prevLink, prevSysctl
	})

	neighProxyListSeam = func(linkIndex, family int) ([]netlink.Neigh, error) {
		if linkIndex == idx && family == unix.AF_INET {
			return []netlink.Neigh{proxyEntry9087(idx, "172.16.80.7")}, nil
		}
		return nil, nil
	}
	neighSetSeam = func(*netlink.Neigh) error { return nil }
	var deleted []netip.Addr
	neighDelSeam = func(n *netlink.Neigh) error {
		if a, ok := netip.AddrFromSlice(n.IP.To4()); ok {
			deleted = append(deleted, a)
		}
		return nil
	}
	linkByIndexSeam = func(int) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "ge-7-0-2.80", Index: idx}}, nil
	}
	proxyARPSysctlSeam = func(string, int, bool) error { return nil }

	// The suppressed standby: the entry is configured, but the ownership gate
	// dropped it from ifaceMap, so it reaches the reconcile only as a PRIOR
	// interface — a sweep target.
	cfg := proxyCfg9087("reth0.80", "172.16.80.7/32")
	if _, _, err := ReconcileProxyARP(cfg, map[string]int{}, map[string]int{"ge-7-0-2.80": idx},
		map[int]string{}); err != nil {
		t.Fatalf("ReconcileProxyARP: %v", err)
	}
	if len(deleted) != 1 || deleted[0].String() != "172.16.80.7" {
		t.Fatalf("#9087: a proxy entry on an interface this node must not answer for "+
			"has to be SWEPT. deleted=%v, want [172.16.80.7].\n"+
			"With the wrong table listed, `existing` was empty and this loop removed "+
			"nothing, ever — so the demoted standby kept answering for the pool "+
			"address and the upstream saw one IP at two RETH virtual MACs.", deleted)
	}
}
