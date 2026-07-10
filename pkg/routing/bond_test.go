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
	failLinkDel       map[string]error // link name -> LinkDel error

	setUpCalls  []string
	masterCalls []string
	addCalls    []string // names passed to LinkAdd
	delCalls    []string // names passed to LinkDel
}

func newFakeBondLinkOps() *fakeBondLinkOps {
	return &fakeBondLinkOps{
		links:             map[string]netlink.Link{},
		failLinkAdd:       map[string]error{},
		failLinkSetUp:     map[string]error{},
		failLinkSetMaster: map[string]error{},
		failLinkDel:       map[string]error{},
	}
}

// reset zeroes the recorded call slices so a test can assert on the link
// operations issued by a SECOND Apply in isolation from the first.
func (f *fakeBondLinkOps) reset() {
	f.setUpCalls = nil
	f.masterCalls = nil
	f.addCalls = nil
	f.delCalls = nil
}

func (f *fakeBondLinkOps) LinkByName(name string) (netlink.Link, error) {
	if l, ok := f.links[name]; ok {
		return l, nil
	}
	return nil, errors.New("link not found")
}

func (f *fakeBondLinkOps) LinkAdd(l netlink.Link) error {
	name := l.Attrs().Name
	f.addCalls = append(f.addCalls, name)
	if err, ok := f.failLinkAdd[name]; ok {
		return err
	}
	f.links[name] = l
	return nil
}

func (f *fakeBondLinkOps) LinkDel(l netlink.Link) error {
	name := l.Attrs().Name
	f.delCalls = append(f.delCalls, name)
	if err, ok := f.failLinkDel[name]; ok {
		return err
	}
	delete(f.links, name)
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
	if _, ok := b.bonds["bond0"]; ok {
		t.Fatalf("bond0 tracked despite its LinkAdd failure: %+v", b.bonds)
	}
	if _, ok := b.bonds["bond1"]; !ok {
		t.Fatalf("bond1 (unaffected by bond0's failure) was not created: %+v", b.bonds)
	}
}

// contains reports whether s appears in xs.
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// TestBondApplyIdempotentNoFlap is the #5119 RED-on-revert guard: applying
// the SAME fabric bond config twice must not tear down and rebuild the
// unchanged bond. The second Apply must issue ZERO LinkDel, LinkAdd, and
// LinkSetMaster calls — otherwise an unrelated policy-only commit flaps the
// LAG (LinkDel->LinkAdd->re-enslave->LACP re-converge). Reverting to the
// unconditional clearLocked()-then-rebuild fails this test.
func TestBondApplyIdempotentNoFlap(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	ops.seedMember("ge-0-0-2")
	b := &bondManager{ops: ops}

	cfg := []*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1", "ge-0-0-2"),
	}
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("first Apply() = %v, want nil", err)
	}
	if !contains(ops.addCalls, "bond0") {
		t.Fatalf("first Apply did not create bond0: addCalls=%v", ops.addCalls)
	}

	// Re-apply the identical config. Nothing changed, so the bond must be
	// left in place.
	ops.reset()
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("second Apply() = %v, want nil", err)
	}
	if len(ops.delCalls) != 0 {
		t.Fatalf("second (identical) Apply issued LinkDel(s) %v — the "+
			"unchanged bond was flapped", ops.delCalls)
	}
	if len(ops.addCalls) != 0 {
		t.Fatalf("second (identical) Apply issued LinkAdd(s) %v — the "+
			"unchanged bond was rebuilt", ops.addCalls)
	}
	if len(ops.masterCalls) != 0 {
		t.Fatalf("second (identical) Apply re-enslaved member(s) %v — the "+
			"unchanged bond was flapped", ops.masterCalls)
	}
	if _, ok := b.bonds["bond0"]; !ok {
		t.Fatalf("bond0 dropped from tracking after idempotent re-apply: %+v", b.bonds)
	}
}

// TestBondApplyReconcilesChangedBond asserts a GENUINE config change (a
// member added) IS reconciled: the changed bond is deleted and rebuilt so
// the new member set is realized. Skipping it would leave the kernel bond
// stale.
func TestBondApplyReconcilesChangedBond(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	ops.seedMember("ge-0-0-2")
	b := &bondManager{ops: ops}

	if err := b.Apply([]*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1"),
	}); err != nil {
		t.Fatalf("first Apply() = %v, want nil", err)
	}

	// Add a second member — the signature changes, so the bond must be
	// reconciled (delete + rebuild).
	ops.reset()
	if err := b.Apply([]*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1", "ge-0-0-2"),
	}); err != nil {
		t.Fatalf("second Apply() = %v, want nil", err)
	}
	if !contains(ops.delCalls, "bond0") {
		t.Fatalf("changed bond0 was NOT deleted: delCalls=%v", ops.delCalls)
	}
	if !contains(ops.addCalls, "bond0") {
		t.Fatalf("changed bond0 was NOT rebuilt: addCalls=%v", ops.addCalls)
	}
	if !contains(ops.masterCalls, "ge-0-0-2") {
		t.Fatalf("new member ge-0-0-2 was NOT enslaved: masterCalls=%v", ops.masterCalls)
	}
	if _, ok := b.bonds["bond0"]; !ok {
		t.Fatalf("bond0 dropped from tracking after reconcile: %+v", b.bonds)
	}
}

// TestBondApplyDeletesRemovedBond asserts a bond dropped from the desired
// set (its fabric interface was removed from config) is deleted, while an
// UNCHANGED sibling bond in the same commit is left untouched (no flap).
func TestBondApplyDeletesRemovedBond(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	ops.seedMember("ge-0-0-2")
	b := &bondManager{ops: ops}

	if err := b.Apply([]*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1"),
		bondFabricConfig("bond1", "ge-0-0-2"),
	}); err != nil {
		t.Fatalf("first Apply() = %v, want nil", err)
	}

	// Drop bond1; bond0 is unchanged.
	ops.reset()
	if err := b.Apply([]*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1"),
	}); err != nil {
		t.Fatalf("second Apply() = %v, want nil", err)
	}
	if !contains(ops.delCalls, "bond1") {
		t.Fatalf("removed bond1 was NOT deleted: delCalls=%v", ops.delCalls)
	}
	if contains(ops.delCalls, "bond0") {
		t.Fatalf("unchanged bond0 was deleted (flapped): delCalls=%v", ops.delCalls)
	}
	if contains(ops.addCalls, "bond0") {
		t.Fatalf("unchanged bond0 was rebuilt (flapped): addCalls=%v", ops.addCalls)
	}
	if _, ok := b.bonds["bond1"]; ok {
		t.Fatalf("bond1 still tracked after removal: %+v", b.bonds)
	}
	if _, ok := b.bonds["bond0"]; !ok {
		t.Fatalf("bond0 dropped from tracking despite being unchanged: %+v", b.bonds)
	}
}
