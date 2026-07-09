package routing

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// fakeBondLinkOps is a minimal in-memory linkOps double for the #4823
// bondManager.Apply() error-propagation tests. It implements only the
// linkOps methods bond.go actually calls; failure injection is keyed by
// link name so a single test can target exactly one netlink call.
type fakeBondLinkOps struct {
	links map[string]netlink.Link // name -> existing link (LinkByName hits)

	failLinkAdd       map[string]error // bond name -> LinkAdd error
	failLinkSetUp     map[string]error // link name -> LinkSetUp error
	failLinkSetMaster map[string]error // member name -> LinkSetMaster error

	setUpCalls  []string
	masterCalls []string
}

func newFakeBondLinkOps() *fakeBondLinkOps {
	return &fakeBondLinkOps{
		links:             map[string]netlink.Link{},
		failLinkAdd:       map[string]error{},
		failLinkSetUp:     map[string]error{},
		failLinkSetMaster: map[string]error{},
	}
}

func (f *fakeBondLinkOps) LinkByName(name string) (netlink.Link, error) {
	if l, ok := f.links[name]; ok {
		return l, nil
	}
	return nil, errors.New("link not found")
}

func (f *fakeBondLinkOps) LinkAdd(l netlink.Link) error {
	name := l.Attrs().Name
	if err, ok := f.failLinkAdd[name]; ok {
		return err
	}
	f.links[name] = l
	return nil
}

func (f *fakeBondLinkOps) LinkDel(l netlink.Link) error {
	delete(f.links, l.Attrs().Name)
	return nil
}

func (f *fakeBondLinkOps) LinkSetUp(l netlink.Link) error {
	name := l.Attrs().Name
	f.setUpCalls = append(f.setUpCalls, name)
	if err, ok := f.failLinkSetUp[name]; ok {
		return err
	}
	return nil
}

func (f *fakeBondLinkOps) LinkSetDown(netlink.Link) error { return nil }

func (f *fakeBondLinkOps) LinkSetMaster(member, _ netlink.Link) error {
	name := member.Attrs().Name
	f.masterCalls = append(f.masterCalls, name)
	if err, ok := f.failLinkSetMaster[name]; ok {
		return err
	}
	return nil
}

func (f *fakeBondLinkOps) LinkSetNoMaster(netlink.Link) error        { return nil }
func (f *fakeBondLinkOps) LinkSetMTU(netlink.Link, int) error        { return nil }
func (f *fakeBondLinkOps) LinkList() ([]netlink.Link, error)         { return nil, nil }
func (f *fakeBondLinkOps) AddrAdd(netlink.Link, *netlink.Addr) error { return nil }
func (f *fakeBondLinkOps) AddrDel(netlink.Link, *netlink.Addr) error { return nil }
func (f *fakeBondLinkOps) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
	return nil, nil
}

// seedMember pre-populates a member link so LinkByName(linuxName) in the
// enslave loop succeeds and the test reaches LinkSetMaster.
func (f *fakeBondLinkOps) seedMember(name string) {
	f.links[name] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

func bondFabricConfig(name string, members ...string) *config.InterfaceConfig {
	return &config.InterfaceConfig{
		Name:          name,
		FabricMembers: members,
		BondMode:      "active-backup",
	}
}

// TestBondApplyReportsLinkAddFailure is the #4823 RED-on-revert guard for
// the bond-creation failure path: a LinkAdd error must make Apply() return
// non-nil instead of being logged and swallowed.
func TestBondApplyReportsLinkAddFailure(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.failLinkAdd["bond0"] = errors.New("injected: EPERM")
	b := &bondManager{ops: ops}

	if err := b.Apply([]*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1")}); err == nil {
		t.Fatal("Apply() = nil error, want non-nil after an injected LinkAdd failure")
	}
}

// TestBondApplyReportsLinkSetMasterFailure is the #4823 RED-on-revert guard
// for the member-enslavement failure path.
func TestBondApplyReportsLinkSetMasterFailure(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	ops.failLinkSetMaster["ge-0-0-1"] = errors.New("injected: EBUSY")
	b := &bondManager{ops: ops}

	if err := b.Apply([]*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1")}); err == nil {
		t.Fatal("Apply() = nil error, want non-nil after an injected LinkSetMaster failure")
	}
}

// TestBondApplyReportsLinkSetUpFailure is the #4823 RED-on-revert guard for
// the final bring-up failure path.
func TestBondApplyReportsLinkSetUpFailure(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	ops.failLinkSetUp["bond0"] = errors.New("injected: ENETDOWN")
	b := &bondManager{ops: ops}

	if err := b.Apply([]*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1")}); err == nil {
		t.Fatal("Apply() = nil error, want non-nil after an injected LinkSetUp failure")
	}
}

// TestBondApplyReportsExistingBondLinkSetUpFailure covers the OTHER
// LinkSetUp call site — the "bond already exists" fast path — which uses
// the identical swallowed-error pattern the issue reports for the
// newly-created-bond bring-up.
func TestBondApplyReportsExistingBondLinkSetUpFailure(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.links["bond0"] = &netlink.Bond{LinkAttrs: netlink.LinkAttrs{Name: "bond0"}}
	ops.failLinkSetUp["bond0"] = errors.New("injected: ENETDOWN")
	b := &bondManager{ops: ops}

	if err := b.Apply([]*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1")}); err == nil {
		t.Fatal("Apply() = nil error, want non-nil after an injected LinkSetUp failure on an already-existing bond")
	}
}

// TestBondApplySucceedsCleanly is the positive control: with no injected
// failures, Apply() must still return nil (errors.Join of zero errors is
// nil) and both bonds must be created and tracked.
func TestBondApplySucceedsCleanly(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	ops.seedMember("ge-0-0-2")
	b := &bondManager{ops: ops}

	err := b.Apply([]*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1"),
		bondFabricConfig("bond1", "ge-0-0-2"),
	})
	if err != nil {
		t.Fatalf("Apply() = %v, want nil (no injected failures)", err)
	}
	if len(b.bonds) != 2 {
		t.Fatalf("len(b.bonds) = %d, want 2: %+v", len(b.bonds), b.bonds)
	}
}

// TestBondApplyContinuesPastOneFailedBond asserts the fix does not regress
// the existing "one bad bond must not block the rest" tolerance: with two
// fabric bonds where the first's LinkAdd fails, the second must still be
// created (and tracked in b.bonds) AND Apply() must still report the first
// bond's failure via a non-nil error — an aggregated error must not turn
// back into an early return that skips the remaining interfaces.
func TestBondApplyContinuesPastOneFailedBond(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.failLinkAdd["bond0"] = errors.New("injected: EPERM")
	ops.seedMember("ge-0-0-2")
	b := &bondManager{ops: ops}

	err := b.Apply([]*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1"),
		bondFabricConfig("bond1", "ge-0-0-2"),
	})
	if err == nil {
		t.Fatal("Apply() = nil error, want non-nil (bond0's LinkAdd failed)")
	}
	found := false
	for _, name := range b.bonds {
		if name == "bond1" {
			found = true
		}
		if name == "bond0" {
			t.Fatalf("bond0 tracked despite its LinkAdd failure: %+v", b.bonds)
		}
	}
	if !found {
		t.Fatalf("bond1 (unaffected by bond0's failure) was not created: %+v", b.bonds)
	}
}
