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
func (f *fakeBondLinkOps) AddrAdd(netlink.Link, *netlink.Addr) error { return nil }
func (f *fakeBondLinkOps) AddrDel(netlink.Link, *netlink.Addr) error { return nil }
func (f *fakeBondLinkOps) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
	return nil, nil
}

// LinkList returns every seeded link so bondManager.observedMembers can
// enumerate a bond's enslaved members by MasterIndex (#5261).
func (f *fakeBondLinkOps) LinkList() ([]netlink.Link, error) {
	links := make([]netlink.Link, 0, len(f.links))
	for _, l := range f.links {
		links = append(links, l)
	}
	return links, nil
}

// seedMember pre-populates a member link so LinkByName(linuxName) in the
// enslave loop succeeds and the test reaches LinkSetMaster.
func (f *fakeBondLinkOps) seedMember(name string) {
	f.links[name] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

// seedBond pre-populates an already-present kernel bond with a non-zero
// index so observedMembers can key member enslavement off it (a real bond
// never has index 0; index 0 makes observedMembers fall back). Models the
// daemon-restart adopt case where the bond outlived in-memory tracking.
func (f *fakeBondLinkOps) seedBond(name string, index int) {
	f.links[name] = &netlink.Bond{
		LinkAttrs: netlink.LinkAttrs{Name: name, Index: index},
	}
}

// seedEnslavedMember pre-populates a member link already enslaved to the
// bond whose kernel index is masterIndex (MasterIndex set), so
// observedMembers reports it as part of the realized member set.
func (f *fakeBondLinkOps) seedEnslavedMember(name string, masterIndex int) {
	f.links[name] = &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: name, MasterIndex: masterIndex},
	}
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

// TestBondAdoptPartialMemberSetNotTrackedAsComplete is the #5261 RED-on-revert
// guard. A daemon restart adopts a kernel bond that was realized with a
// PARTIAL member set (one member was absent at realization time — a #4823 soft
// error). The adopt path must NOT record the full desired signature (which
// would make every future reconcile see "unchanged" and KEEP the partial bond
// forever); it must track the ACTUAL realized member set so a later reconcile
// completes the enslavement once the missing member appears. Reverting the fix
// tracks the full desired sig → the partial bond is KEEP'd forever (RED here on
// both the tracked-sig assertion AND the completion assertion).
func TestBondAdoptPartialMemberSetNotTrackedAsComplete(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedBond("bond0", 10)
	ops.seedEnslavedMember("ge-0-0-1", 10) // realized member
	// ge-0-0-2 is absent from the kernel — the partial realization.
	b := &bondManager{ops: ops}

	cfg := []*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1", "ge-0-0-2")}
	full := bondSigOf(cfg[0])

	if err := b.Apply(cfg); err != nil {
		t.Fatalf("first Apply() (adopt) = %v, want nil", err)
	}
	// Adopt must not flap the good member: no LinkDel/LinkAdd, and the absent
	// member cannot be enslaved yet (soft error), so no LinkSetMaster either.
	if len(ops.delCalls) != 0 || len(ops.addCalls) != 0 {
		t.Fatalf("adopt flapped the bond: delCalls=%v addCalls=%v", ops.delCalls, ops.addCalls)
	}
	got, ok := b.bonds["bond0"]
	if !ok {
		t.Fatalf("bond0 not tracked after adopt: %+v", b.bonds)
	}
	if got == full {
		t.Fatalf("partial adopt tracked the FULL desired sig %+v — a subsequent "+
			"reconcile will KEEP the partial bond forever (#5261)", got)
	}
	if got.members != "ge-0-0-1" {
		t.Fatalf("adopt tracked members=%q, want %q (only the realized member)",
			got.members, "ge-0-0-1")
	}

	// The missing member now appears in the kernel. The next reconcile must
	// detect the tracked/desired mismatch and complete the enslavement.
	ops.reset()
	ops.seedMember("ge-0-0-2")
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("second Apply() (member appeared) = %v, want nil", err)
	}
	if !contains(ops.masterCalls, "ge-0-0-2") {
		t.Fatalf("missing member ge-0-0-2 was NOT enslaved on the follow-up "+
			"reconcile: masterCalls=%v", ops.masterCalls)
	}
	if got := b.bonds["bond0"]; got != full {
		t.Fatalf("after completion b.bonds[bond0]=%+v, want full desired %+v", got, full)
	}
}

// TestBondAdoptPartialCompletesImmediatelyWhenMemberPresent covers the common
// restart case where the previously-absent member has since appeared in the
// kernel (the enumeration race resolved across the restart). The adopt path
// must enslave the now-present member in place — without an intervening
// recreate — and track the full desired sig, and it must NOT re-enslave the
// member that was already attached (#5259 no-flap for the good member). A
// subsequent identical reconcile is then a clean KEEP.
func TestBondAdoptPartialCompletesImmediatelyWhenMemberPresent(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedBond("bond0", 10)
	ops.seedEnslavedMember("ge-0-0-1", 10) // already enslaved
	ops.seedMember("ge-0-0-2")             // present in kernel but NOT yet enslaved
	b := &bondManager{ops: ops}

	cfg := []*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1", "ge-0-0-2")}
	full := bondSigOf(cfg[0])

	if err := b.Apply(cfg); err != nil {
		t.Fatalf("Apply() (adopt+complete) = %v, want nil", err)
	}
	if len(ops.delCalls) != 0 || len(ops.addCalls) != 0 {
		t.Fatalf("adopt+complete recreated the bond: delCalls=%v addCalls=%v",
			ops.delCalls, ops.addCalls)
	}
	if !contains(ops.masterCalls, "ge-0-0-2") {
		t.Fatalf("present member ge-0-0-2 was NOT enslaved at adopt: masterCalls=%v", ops.masterCalls)
	}
	if contains(ops.masterCalls, "ge-0-0-1") {
		t.Fatalf("already-enslaved member ge-0-0-1 was re-enslaved (flap): masterCalls=%v", ops.masterCalls)
	}
	if got := b.bonds["bond0"]; got != full {
		t.Fatalf("after in-place completion b.bonds[bond0]=%+v, want full desired %+v", got, full)
	}

	// Healed: the next identical reconcile is a pure KEEP (no ops at all).
	ops.reset()
	// Reflect the enslavement the fake does not model automatically so the
	// re-adopt sees a complete member set.
	ops.seedEnslavedMember("ge-0-0-2", 10)
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("third Apply() = %v, want nil", err)
	}
	if len(ops.delCalls) != 0 || len(ops.addCalls) != 0 || len(ops.masterCalls) != 0 {
		t.Fatalf("healed bond flapped on KEEP: delCalls=%v addCalls=%v masterCalls=%v",
			ops.delCalls, ops.addCalls, ops.masterCalls)
	}
}

// TestBondAdoptCompleteMemberSetNoFlap is the #5259 no-flap guarantee for the
// adopt path: a daemon restart that adopts a FULLY-realized kernel bond (every
// desired member already enslaved) must track the full desired sig and only
// bring the bond up — zero LinkDel, zero LinkAdd, zero LinkSetMaster. The
// partial-member verification must NOT tear down or re-enslave a good bond.
func TestBondAdoptCompleteMemberSetNoFlap(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedBond("bond0", 10)
	ops.seedEnslavedMember("ge-0-0-1", 10)
	ops.seedEnslavedMember("ge-0-0-2", 10)
	b := &bondManager{ops: ops}

	cfg := []*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1", "ge-0-0-2")}
	full := bondSigOf(cfg[0])

	if err := b.Apply(cfg); err != nil {
		t.Fatalf("Apply() (adopt complete) = %v, want nil", err)
	}
	if len(ops.delCalls) != 0 {
		t.Fatalf("fully-realized adopt issued LinkDel(s) %v — flapped a good bond", ops.delCalls)
	}
	if len(ops.addCalls) != 0 {
		t.Fatalf("fully-realized adopt issued LinkAdd(s) %v — rebuilt a good bond", ops.addCalls)
	}
	if len(ops.masterCalls) != 0 {
		t.Fatalf("fully-realized adopt re-enslaved member(s) %v — flapped a good bond", ops.masterCalls)
	}
	if got := b.bonds["bond0"]; got != full {
		t.Fatalf("adopt tracked %+v, want full desired %+v", got, full)
	}
}
