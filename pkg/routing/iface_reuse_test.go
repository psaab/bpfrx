package routing

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// fakeLinkOps is an in-memory linkOps for the #1706 tunnel/xfrm reuse
// tests. It records which link object LinkSetUp/AddrAdd were invoked
// against so the tests can prove the apply paths operate on the
// kernel-fetched (indexed) link rather than a freshly-constructed,
// ifindex-less one. LinkAdd can be made to fail (EEXIST) to drive the
// "already exists" branches.
type fakeLinkOps struct {
	links map[string]netlink.Link // name -> seeded existing link

	// addExisting makes LinkAdd report the link already exists.
	addExisting bool

	// byNameErrAfter, when > 0, makes LinkByName return an error once it
	// has been called this many times for the same name (used to drive a
	// transient second-lookup failure under the OLD double-lookup code).
	byNameCount    map[string]int
	byNameErrAfter int

	// hiddenUntil[name] = k makes LinkByName report not-found for the
	// first k calls, then return the seeded link. Models a link that the
	// pre-loop delete lookup misses but that exists by the time LinkAdd's
	// EEXIST fallback lookup runs — the only way the tunnel reuse path
	// (goto anchorReady) is reached.
	hiddenUntil map[string]int

	// Recorded ops.
	setUpLinks []netlink.Link
	addrLinks  []netlink.Link
}

func newFakeLinkOps() *fakeLinkOps {
	return &fakeLinkOps{
		links:       map[string]netlink.Link{},
		byNameCount: map[string]int{},
		hiddenUntil: map[string]int{},
	}
}

func (f *fakeLinkOps) LinkByName(name string) (netlink.Link, error) {
	f.byNameCount[name]++
	if f.byNameErrAfter > 0 && f.byNameCount[name] > f.byNameErrAfter {
		return nil, errors.New("transient netlink error")
	}
	if hide, ok := f.hiddenUntil[name]; ok && f.byNameCount[name] <= hide {
		return nil, errLinkNotFound{errors.New("link not found")}
	}
	if l, ok := f.links[name]; ok {
		return l, nil
	}
	return nil, errLinkNotFound{errors.New("link not found")}
}

func (f *fakeLinkOps) LinkAdd(l netlink.Link) error {
	if f.addExisting {
		return errors.New("file exists")
	}
	f.links[l.Attrs().Name] = l
	return nil
}

func (f *fakeLinkOps) LinkDel(l netlink.Link) error {
	delete(f.links, l.Attrs().Name)
	return nil
}

func (f *fakeLinkOps) LinkSetUp(l netlink.Link) error {
	// Mirror the real netlink handle: dereferencing a nil link panics.
	// A correct caller never passes nil here.
	_ = l.Attrs()
	f.setUpLinks = append(f.setUpLinks, l)
	return nil
}

func (f *fakeLinkOps) LinkSetDown(l netlink.Link) error      { return nil }
func (f *fakeLinkOps) LinkSetMaster(l, m netlink.Link) error { return nil }
func (f *fakeLinkOps) LinkList() ([]netlink.Link, error)     { return nil, nil }

func (f *fakeLinkOps) AddrAdd(l netlink.Link, a *netlink.Addr) error {
	_ = l.Attrs()
	f.addrLinks = append(f.addrLinks, l)
	return nil
}

func (f *fakeLinkOps) AddrDel(l netlink.Link, a *netlink.Addr) error {
	_ = l.Attrs()
	return nil
}

func (f *fakeLinkOps) AddrList(l netlink.Link, family int) ([]netlink.Addr, error) {
	return nil, nil
}

// noopVRFBinder satisfies vrfBinder without touching netlink.
type noopVRFBinder struct{}

func (noopVRFBinder) BindInterfaceToVRF(ifaceName, instanceName string) error { return nil }

// TestTunnelAnchorReuseUsesExistingLink covers #1706 defect 1: when an
// anchor-only TUN already exists, the reuse path (LinkAdd fails, lookup
// finds an existing *netlink.Tuntap) must run LinkSetUp/AddrAdd against
// the kernel-fetched link that carries the real ifindex — NOT the
// freshly-constructed, ifindex-less anchor.
func TestTunnelAnchorReuseUsesExistingLink(t *testing.T) {
	ops := newFakeLinkOps()
	const name = "gr-0/0/0.0"
	const wantIndex = 42
	existing := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: name, Index: wantIndex},
		Mode:      netlink.TUNTAP_MODE_TUN,
	}
	ops.links[name] = existing
	ops.addExisting = true // force the LinkAdd-fails reuse branch
	// The pre-loop delete lookup (call #1) must miss so the link is not
	// deleted; LinkAdd then fails EEXIST and the fallback lookup (call #2)
	// finds the existing TUN — the only path that reaches goto anchorReady.
	ops.hiddenUntil[name] = 1

	tm := &tunnelManager{ops: ops, vrfBinder: noopVRFBinder{}, keepalives: map[string]*keepaliveRunner{}}
	tunnels := []*config.TunnelConfig{{
		Name:       name,
		AnchorOnly: true,
		Addresses:  []string{"10.1.2.3/32"},
	}}
	if err := tm.Apply(tunnels); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if len(ops.setUpLinks) != 1 {
		t.Fatalf("expected exactly one LinkSetUp, got %d", len(ops.setUpLinks))
	}
	if got := ops.setUpLinks[0].Attrs().Index; got != wantIndex {
		t.Errorf("LinkSetUp ran against a link with index %d, want the existing link's index %d "+
			"(reuse path used the fresh ifindex-less anchor)", got, wantIndex)
	}
	if len(ops.addrLinks) != 1 {
		t.Fatalf("expected exactly one AddrAdd, got %d", len(ops.addrLinks))
	}
	if got := ops.addrLinks[0].Attrs().Index; got != wantIndex {
		t.Errorf("AddrAdd ran against a link with index %d, want %d", got, wantIndex)
	}
}

// TestXfrmAlreadyExistsSingleLookup covers #1706 defect 2: the
// "already exists" path must look up the link exactly once and bring up
// the non-nil link from that lookup — never a second lookup whose error
// is ignored (which risked LinkSetUp(nil) panicking).
func TestXfrmAlreadyExistsSingleLookup(t *testing.T) {
	ops := newFakeLinkOps()
	// config.XFRMIfNameAndID maps "st0.1" -> ("xfrm1", id). Seed that.
	ifName, _ := config.XFRMIfNameAndID("st0.1")
	if ifName == "" {
		t.Fatalf("XFRMIfNameAndID returned empty name for st0.1")
	}
	const wantIndex = 7
	ops.links[ifName] = &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{Name: ifName, Index: wantIndex},
	}
	// Make any SECOND LinkByName for this name fail — under the old
	// double-lookup code this would feed nil to LinkSetUp and panic. The
	// fixed single-lookup code never makes the second call.
	ops.byNameErrAfter = 1

	xm := &xfrmManager{ops: ops}
	vpns := map[string]*config.IPsecVPN{
		"v1": {Name: "v1", BindInterface: "st0.1"},
	}
	if err := xm.Apply(vpns); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := ops.byNameCount[ifName]; got != 1 {
		t.Errorf("expected exactly 1 LinkByName for %s on the already-exists path, got %d "+
			"(a second lookup risks LinkSetUp(nil))", ifName, got)
	}
	if len(ops.setUpLinks) != 1 {
		t.Fatalf("expected exactly one LinkSetUp, got %d", len(ops.setUpLinks))
	}
	if ops.setUpLinks[0] == nil {
		t.Fatal("LinkSetUp received nil link")
	}
	if got := ops.setUpLinks[0].Attrs().Index; got != wantIndex {
		t.Errorf("LinkSetUp ran against index %d, want existing %d", got, wantIndex)
	}
}
