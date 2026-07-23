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
