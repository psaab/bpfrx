package routing

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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

	// delFail[name] makes LinkDel fail for that link name (#1884
	// removal-retention tests).
	delFail map[string]error

	// addrDelFail["name|ipnet"] makes AddrDel fail for that address on
	// that link (#1884 link-local retention tests).
	addrDelFail map[string]error

	// addrListFail[name] makes AddrList return an error for that link
	// (#1919 prune AddrList-failure retry test).
	addrListFail map[string]error

	// byNameHardErr[name] makes LinkByName return a NON-not-found
	// (transient) error for that name — distinct from errLinkNotFound, so
	// isLinkNotFound(err) is false (#1919 transient-lookup retention test).
	byNameHardErr map[string]error

	// addrAddFail makes AddrAdd fail (models real-netlink EEXIST when an
	// address is already present and AddrList could not report it — #1919
	// AddrList-failure link-local ownership preservation test).
	addrAddFail bool

	// noMasterErr makes LinkSetNoMaster fail (claim retention tests).
	noMasterErr error

	// addrs is the per-link kernel address store backing
	// AddrAdd/AddrDel/AddrList for the #1884 reconcile tests.
	addrs map[string][]netlink.Addr

	// Recorded ops.
	setUpLinks []netlink.Link
	addrLinks  []netlink.Link
	delNames   []string
	noMaster   []string
	mtuSet     map[string][]int
	addrDels   map[string][]string
}

func newFakeLinkOps() *fakeLinkOps {
	return &fakeLinkOps{
		links:         map[string]netlink.Link{},
		byNameCount:   map[string]int{},
		hiddenUntil:   map[string]int{},
		delFail:       map[string]error{},
		addrDelFail:   map[string]error{},
		addrListFail:  map[string]error{},
		byNameHardErr: map[string]error{},
		addrs:         map[string][]netlink.Addr{},
		mtuSet:        map[string][]int{},
		addrDels:      map[string][]string{},
	}
}

func (f *fakeLinkOps) LinkByName(name string) (netlink.Link, error) {
	f.byNameCount[name]++
	if err, ok := f.byNameHardErr[name]; ok {
		// Non-not-found (transient) error: isLinkNotFound(err) is false.
		return nil, err
	}
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
	name := l.Attrs().Name
	if err, ok := f.delFail[name]; ok {
		return err
	}
	f.delNames = append(f.delNames, name)
	delete(f.links, name)
	delete(f.addrs, name)
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

func (f *fakeLinkOps) LinkSetNoMaster(l netlink.Link) error {
	if f.noMasterErr != nil {
		return f.noMasterErr
	}
	f.noMaster = append(f.noMaster, l.Attrs().Name)
	l.Attrs().MasterIndex = 0
	return nil
}

func (f *fakeLinkOps) LinkSetMTU(l netlink.Link, mtu int) error {
	name := l.Attrs().Name
	f.mtuSet[name] = append(f.mtuSet[name], mtu)
	l.Attrs().MTU = mtu
	return nil
}

func (f *fakeLinkOps) LinkList() ([]netlink.Link, error) { return nil, nil }

func (f *fakeLinkOps) AddrAdd(l netlink.Link, a *netlink.Addr) error {
	_ = l.Attrs()
	if f.addrAddFail {
		// Mirror real netlink: adding an already-present address yields
		// EEXIST (matched via errors.Is in reconcileLinkAddrsLocked).
		return unix.EEXIST
	}
	f.addrLinks = append(f.addrLinks, l)
	name := l.Attrs().Name
	f.addrs[name] = append(f.addrs[name], *a)
	return nil
}

func (f *fakeLinkOps) AddrDel(l netlink.Link, a *netlink.Addr) error {
	name := l.Attrs().Name
	key := a.IPNet.String()
	if err, ok := f.addrDelFail[name+"|"+key]; ok {
		return err
	}
	f.addrDels[name] = append(f.addrDels[name], key)
	kept := f.addrs[name][:0]
	for _, existing := range f.addrs[name] {
		if existing.IPNet.String() != key {
			kept = append(kept, existing)
		}
	}
	f.addrs[name] = kept
	return nil
}

func (f *fakeLinkOps) AddrList(l netlink.Link, family int) ([]netlink.Addr, error) {
	name := l.Attrs().Name
	if err, ok := f.addrListFail[name]; ok {
		return nil, err
	}
	return append([]netlink.Addr(nil), f.addrs[name]...), nil
}

// hasAddr reports whether the fake kernel store holds ipnet on name.
func (f *fakeLinkOps) hasAddr(name, ipnet string) bool {
	for _, a := range f.addrs[name] {
		if a.IPNet.String() == ipnet {
			return true
		}
	}
	return false
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
		// #1884: the reuse gate now also requires NO_PI + persistent
		// (anchorReusable), matching what kernel readback reports for a
		// real anchor created by this code.
		Flags: netlink.TUNTAP_NO_PI,
	}
	ops.links[name] = existing
	ops.addExisting = true // force the LinkAdd-fails reuse branch
	// The reuse-first lookup (call #1) must miss so the link is not
	// reused directly; LinkAdd then fails EEXIST and the fallback lookup
	// (call #2) finds the existing TUN — the #1706 transient-race path.
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
