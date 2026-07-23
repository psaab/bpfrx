package routing

import (
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
