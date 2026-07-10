package routing

import (
	"errors"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// #4901: the xfrm / bond / tunnel teardown paths (clearLocked, reached via
// Clear) logged a failed netlink LinkDel, then dropped the object from their
// ownership tracking and returned nil. A transient / EBUSY / EPERM delete
// failure leaves the link in the kernel while the manager forgets it owned it,
// so a later reconcile has no memory of the orphaned xfrmi / bond / tunnel and
// the caller observes a clean teardown. The fix returns the joined delete errors
// AND retains tracking for objects whose LinkDel failed (mirroring the VRF /
// tunnel Apply retention), so the next reconcile retries.

func seedDummy(ops *fakeLinkOps, name string) {
	ops.links[name] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

func sliceHas(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

// TestXfrmClearRetainsAndReturnsOnLinkDelFailure: a failed xfrmi LinkDel during
// Clear must return an error and RETAIN the tracked entry.
//
// fail-on-revert: original clearLocked nils x.xfrmis and returns nil → both the
// error and retention assertions fail RED.
func TestXfrmClearRetainsAndReturnsOnLinkDelFailure(t *testing.T) {
	ops := newFakeLinkOps()
	seedDummy(ops, "xfrm-bad")
	seedDummy(ops, "xfrm-ok")
	ops.delFail["xfrm-bad"] = errors.New("injected EBUSY")

	xm := &xfrmManager{ops: ops, xfrmis: map[string]uint32{"xfrm-bad": 100, "xfrm-ok": 101}}

	err := xm.Clear()
	if err == nil {
		t.Fatal("Clear must return the LinkDel failure, not nil (orphaned xfrmi, lost ownership)")
	}
	if !strings.Contains(err.Error(), "xfrm-bad") {
		t.Errorf("Clear error should name the failed xfrmi: %v", err)
	}
	if _, ok := xm.xfrmis["xfrm-bad"]; !ok {
		t.Fatal("failed-delete xfrmi must be RETAINED in tracking so the next reconcile retries")
	}
	if _, ok := xm.xfrmis["xfrm-ok"]; ok {
		t.Fatal("successfully-deleted xfrmi must be dropped from tracking")
	}
}

// TestBondClearRetainsAndReturnsOnLinkDelFailure: a failed bond LinkDel during
// Clear must return an error and RETAIN the bond name for retry.
func TestBondClearRetainsAndReturnsOnLinkDelFailure(t *testing.T) {
	ops := newFakeLinkOps()
	seedDummy(ops, "bond-bad")
	seedDummy(ops, "bond-ok")
	ops.delFail["bond-bad"] = errors.New("injected EPERM")

	b := &bondManager{ops: ops, bonds: map[string]bondSig{"bond-bad": {}, "bond-ok": {}}}

	err := b.Clear()
	if err == nil {
		t.Fatal("Clear must return the LinkDel failure, not nil (orphaned bond + enslaved members)")
	}
	if !strings.Contains(err.Error(), "bond-bad") {
		t.Errorf("Clear error should name the failed bond: %v", err)
	}
	if _, ok := b.bonds["bond-bad"]; !ok {
		t.Fatal("failed-delete bond must be RETAINED in tracking so the next reconcile retries")
	}
	if _, ok := b.bonds["bond-ok"]; ok {
		t.Fatal("successfully-deleted bond must be dropped from tracking")
	}
}

// TestTunnelClearRetainsAndReturnsOnLinkDelFailure: a failed tunnel LinkDel
// during Clear must return an error and RETAIN ownership for retry (the Apply
// removal diff keys off ownedNames).
func TestTunnelClearRetainsAndReturnsOnLinkDelFailure(t *testing.T) {
	ops := newFakeLinkOps()
	seedDummy(ops, "gr-bad")
	seedDummy(ops, "gr-ok")
	ops.delFail["gr-bad"] = errors.New("injected transient netlink error")

	tm := &tunnelManager{
		ops:        ops,
		tunnels:    []string{"gr-bad", "gr-ok"},
		ownedNames: map[string]bool{"gr-bad": true, "gr-ok": true},
		keepalives: map[string]*keepaliveRunner{},
	}

	err := tm.Clear()
	if err == nil {
		t.Fatal("Clear must return the LinkDel failure, not nil (orphaned tunnel, stale XFRM if_id state)")
	}
	if !strings.Contains(err.Error(), "gr-bad") {
		t.Errorf("Clear error should name the failed tunnel: %v", err)
	}
	if !tm.ownedNames["gr-bad"] {
		t.Fatal("failed-delete tunnel must RETAIN ownership so a post-Clear Apply retries the delete")
	}
	if tm.ownedNames["gr-ok"] {
		t.Fatal("successfully-deleted tunnel must drop ownership")
	}
	// tunnels is the success-tracked (GetStatus) list — always reset by Clear.
	if len(tm.tunnels) != 0 {
		t.Fatalf("tunnels list must be reset by Clear, got %v", tm.tunnels)
	}
}
