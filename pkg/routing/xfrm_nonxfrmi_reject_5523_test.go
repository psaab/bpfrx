package routing

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestXfrmApplyRejectsNonXfrmiSameName is the #5523 C179-104 guard: a kernel
// link that wears the xfrmi's NAME but is NOT an xfrm interface (a foreign or
// leftover dummy/veth) must be reclaimed via delete+recreate, never silently
// adopted. The pre-fix type guard gated only the stale-if_id recreate branch
// (`if xi, ok := link.(*netlink.Xfrmi); ok && xi.Ifid != ifID`), so a non-xfrmi
// link fell through to the adopt path: the name was tracked as satisfied while
// NO xfrm interface carried the if_id, and the route-based VPN bound to it
// silently blackholed.
//
// FAIL-ON-REVERT: under the old guard a non-xfrmi link is brought up and tracked
// with zero LinkDel and zero LinkAdd — the delete/create assertions below go RED.
func TestXfrmApplyRejectsNonXfrmiSameName(t *testing.T) {
	ops := newFakeLinkOps()
	ifName, ifID := config.XFRMIfNameAndID("st0.1")
	if ifName == "" || ifID == 0 {
		t.Fatalf("XFRMIfNameAndID returned name=%q id=%d for st0.1", ifName, ifID)
	}
	// Seed a NON-xfrmi link (a dummy) already wearing the xfrmi's name.
	ops.links[ifName] = &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: ifName, Index: 7},
	}

	xm := &xfrmManager{ops: ops}
	if err := xm.Apply(xfrmVPNs("st0.1")); err != nil {
		t.Fatalf("reclaim of a non-xfrmi same-name link must succeed (delete+recreate), got %v", err)
	}

	// The foreign link must have been DELETED (reclaimed), not adopted.
	deleted := false
	for _, n := range ops.delNames {
		if n == ifName {
			deleted = true
		}
	}
	if !deleted {
		t.Errorf("a non-xfrmi link wearing the xfrmi name %q must be deleted+recreated, "+
			"not silently adopted (C179-104); delNames=%v", ifName, ops.delNames)
	}

	// A real xfrmi must have been created in its place.
	if ops.addCount != 1 {
		t.Errorf("exactly one xfrmi must be created after reclaiming the foreign link, "+
			"got %d LinkAdd", ops.addCount)
	}
	created, ok := ops.links[ifName].(*netlink.Xfrmi)
	if !ok {
		t.Fatalf("link %q after reclaim must be an *netlink.Xfrmi, got %T", ifName, ops.links[ifName])
	}
	if created.Ifid != ifID {
		t.Errorf("recreated xfrmi if_id = %d, want %d", created.Ifid, ifID)
	}
	if got := xm.xfrmis[ifName]; got != ifID {
		t.Errorf("reclaimed xfrmi tracked if_id %d, want %d", got, ifID)
	}
}

// TestXfrmApplyRejectsSubstitutedReadbackAfterCreate is the #6396 C179-104
// residual guard: the POST-CREATE readback (LinkByName after LinkAdd) must
// re-assert the link is the xfrm interface just created before bringing it up
// and tracking it. LinkAdd and the readback are two syscalls; a concurrent
// external actor that deletes the fresh device and substitutes a same-name
// foreign link in that window must NOT be adopted — otherwise the NAME is
// tracked as satisfied while no device carries the desired if_id and the
// route-based VPN silently blackholes (the same failure the adopt-path guard
// closes on restart).
//
// FAIL-ON-REVERT: dropping the create-path type/if_id check brings the foreign
// link UP and tracks it (Apply returns nil, xm.xfrmis[ifName]==ifID, LinkSetUp
// ran on the foreign link) — the error/untracked/no-setup assertions go RED.
func TestXfrmApplyRejectsSubstitutedReadbackAfterCreate(t *testing.T) {
	ops := newFakeLinkOps()
	ifName, ifID := config.XFRMIfNameAndID("st0.1")
	if ifName == "" || ifID == 0 {
		t.Fatalf("XFRMIfNameAndID returned name=%q id=%d for st0.1", ifName, ifID)
	}
	// No seeded link → the create path runs. In the add→readback window a
	// foreign (non-xfrmi) link is swapped in under the same name.
	ops.substituteAfterAdd[ifName] = &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: ifName, Index: 9},
	}

	xm := &xfrmManager{ops: ops}
	err := xm.Apply(xfrmVPNs("st0.1"))
	if err == nil {
		t.Fatalf("a substituted (non-xfrmi) readback after create must fail the commit closed, got nil")
	}

	// The intended xfrmi was created (addCount bumped) but the substitute must
	// NOT be adopted: not tracked, and never brought up.
	if _, ok := xm.xfrmis[ifName]; ok {
		t.Errorf("a substituted readback must not be tracked as a satisfied xfrmi; xfrmis=%v", xm.xfrmis)
	}
	for _, l := range ops.setUpLinks {
		if l.Attrs().Name == ifName {
			t.Errorf("the substituted foreign link %q must not be brought up", ifName)
		}
	}
}

// TestXfrmApplyRejectsWrongIfIDReadbackAfterCreate covers the same create-path
// readback guard for the second substitution shape: an xfrm interface that
// wears the name but carries the WRONG if_id (an aborted concurrent recreate).
// It too must be rejected rather than tracked as satisfied.
func TestXfrmApplyRejectsWrongIfIDReadbackAfterCreate(t *testing.T) {
	ops := newFakeLinkOps()
	ifName, ifID := config.XFRMIfNameAndID("st0.1")
	if ifName == "" || ifID == 0 {
		t.Fatalf("XFRMIfNameAndID returned name=%q id=%d for st0.1", ifName, ifID)
	}
	ops.substituteAfterAdd[ifName] = &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{Name: ifName, Index: 9},
		Ifid:      ifID + 1, // wrong if_id
	}

	xm := &xfrmManager{ops: ops}
	if err := xm.Apply(xfrmVPNs("st0.1")); err == nil {
		t.Fatalf("a wrong-if_id readback after create must fail the commit closed, got nil")
	}
	if _, ok := xm.xfrmis[ifName]; ok {
		t.Errorf("a wrong-if_id readback must not be tracked; xfrmis=%v", xm.xfrmis)
	}
}

// TestXfrmAdoptRejectsParentBoundReadback is the #6396 Codex MAJOR 1 guard for
// the ADOPT path. xpf creates every xfrmi PARENTLESS (the SA selects the egress
// device), so a same-name, same-if_id xfrmi bound to a NONZERO parent link
// (IFLA_XFRM_LINK, which pins the physical egress interface) is NOT the device
// we intend: adopting it would egress the VPN's SA traffic out the wrong
// interface. if_id alone does not distinguish it, so the adopt guard asserts
// ParentIndex == 0 and delete+recreates on a mismatch.
//
// FAIL-ON-REVERT: dropping the ParentIndex==0 clause adopts the parent-bound
// link as-is (0 LinkDel / 0 LinkAdd) — the delete/recreate/parentless
// assertions go RED.
func TestXfrmAdoptRejectsParentBoundReadback(t *testing.T) {
	ops := newFakeLinkOps()
	ifName, ifID := config.XFRMIfNameAndID("st0.1")
	if ifName == "" || ifID == 0 {
		t.Fatalf("XFRMIfNameAndID returned name=%q id=%d for st0.1", ifName, ifID)
	}
	// Same name + if_id, but bound to a nonzero parent link.
	ops.links[ifName] = &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{Name: ifName, Index: 7, ParentIndex: 3},
		Ifid:      ifID,
	}

	xm := &xfrmManager{ops: ops}
	if err := xm.Apply(xfrmVPNs("st0.1")); err != nil {
		t.Fatalf("reclaim of a parent-bound xfrmi must succeed (delete+recreate), got %v", err)
	}
	if !sliceHas(ops.delNames, ifName) {
		t.Errorf("a parent-bound xfrmi must be delete+recreated, not adopted; delNames=%v", ops.delNames)
	}
	if ops.addCount != 1 {
		t.Errorf("exactly one xfrmi must be recreated after reclaim, got %d LinkAdd", ops.addCount)
	}
	created, ok := ops.links[ifName].(*netlink.Xfrmi)
	if !ok {
		t.Fatalf("link %q after reclaim must be *netlink.Xfrmi, got %T", ifName, ops.links[ifName])
	}
	if created.Attrs().ParentIndex != 0 {
		t.Errorf("recreated xfrmi must be parentless, got ParentIndex %d", created.Attrs().ParentIndex)
	}
	if got := xm.xfrmis[ifName]; got != ifID {
		t.Errorf("reclaimed xfrmi tracked if_id %d, want %d", got, ifID)
	}
}

// TestXfrmCreateRejectsParentBoundReadback is the #6396 Codex MAJOR 1 guard for
// the POST-CREATE readback: a same-name, same-if_id xfrmi bound to a nonzero
// parent, substituted in the add→readback window, must be rejected (not brought
// up or tracked) — if_id matches, so only the ParentIndex==0 assertion catches
// it.
//
// FAIL-ON-REVERT: dropping the ParentIndex==0 clause brings the parent-bound
// link up and tracks it (Apply returns nil) — RED.
func TestXfrmCreateRejectsParentBoundReadback(t *testing.T) {
	ops := newFakeLinkOps()
	ifName, ifID := config.XFRMIfNameAndID("st0.1")
	ops.substituteAfterAdd[ifName] = &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{Name: ifName, Index: 9, ParentIndex: 5},
		Ifid:      ifID, // matching if_id — only the parent differs
	}

	xm := &xfrmManager{ops: ops}
	if err := xm.Apply(xfrmVPNs("st0.1")); err == nil {
		t.Fatalf("a parent-bound readback after create must fail the commit closed, got nil")
	}
	if _, ok := xm.xfrmis[ifName]; ok {
		t.Errorf("a parent-bound readback must not be tracked; xfrmis=%v", xm.xfrmis)
	}
}

// TestXfrmCreateRejectDropsStaleTracking is the #6396 Codex MINOR 3 guard: when
// the create-path readback is rejected AND the name was already tracked from a
// prior reconcile, the stale x.xfrmis entry must be DROPPED — otherwise a later
// reconcile path could treat the foreign substitute as a satisfied xfrmi.
//
// FAIL-ON-REVERT: without the delete on the mismatch branch the pre-existing
// tracking entry survives — the "not tracked" assertion goes RED. (The other
// create-path tests use fresh managers, so only this pre-tracked case binds the
// delete.)
func TestXfrmCreateRejectDropsStaleTracking(t *testing.T) {
	ops := newFakeLinkOps()
	ifName, ifID := config.XFRMIfNameAndID("st0.1")
	// Foreign substitute swapped into the readback window.
	ops.substituteAfterAdd[ifName] = &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: ifName, Index: 9},
	}
	// PRE-TRACKED: a prior reconcile recorded this name as satisfied, but the
	// kernel link is absent now (deleted out-of-band), so Apply takes the create
	// path and the readback returns the substitute.
	xm := &xfrmManager{ops: ops, xfrmis: map[string]uint32{ifName: ifID}}
	if err := xm.Apply(xfrmVPNs("st0.1")); err == nil {
		t.Fatalf("a foreign readback after create must fail the commit closed, got nil")
	}
	if _, ok := xm.xfrmis[ifName]; ok {
		t.Errorf("the stale tracking entry must be dropped on a rejected readback so a later "+
			"reconcile cannot act on the foreign substitute; xfrmis=%v", xm.xfrmis)
	}
}

// TestXfrmCreateLinkAddFailureDropsStaleTracking is the #6396 Codex MINOR 4
// guard: a GENUINE LinkAdd failure on the create path must also honor the
// "UNTRACKED" contract by dropping any pre-existing x.xfrmis entry for the
// name. Otherwise, a name that a prior reconcile tracked (then its kernel link
// vanished, forcing the create path) whose recreate then fails would stay
// tracked — and the removal pass (deleteLocked) could later delete whatever
// foreign link comes to wear that name.
//
// FAIL-ON-REVERT: without the delete on the LinkAdd-failure exit the pre-tracked
// entry survives — the "not tracked" assertion goes RED.
func TestXfrmCreateLinkAddFailureDropsStaleTracking(t *testing.T) {
	ops := newFakeLinkOps()
	ifName, ifID := config.XFRMIfNameAndID("st0.1")
	// A GENUINE (non-EEXIST) LinkAdd failure — the link is never created.
	ops.addFail[ifName] = errors.New("injected: LinkAdd EPERM")
	// PRE-TRACKED from a prior reconcile; the kernel link is absent now, so Apply
	// takes the create path and LinkAdd fails.
	xm := &xfrmManager{ops: ops, xfrmis: map[string]uint32{ifName: ifID}}
	if err := xm.Apply(xfrmVPNs("st0.1")); err == nil {
		t.Fatalf("a genuine LinkAdd failure must fail the commit closed, got nil")
	}
	if _, ok := xm.xfrmis[ifName]; ok {
		t.Errorf("a failed LinkAdd must drop the stale tracking entry so the removal pass "+
			"cannot act on a foreign link that later wears the name; xfrmis=%v", xm.xfrmis)
	}
}
