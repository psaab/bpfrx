package routing

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #5310: xfrmManager.Apply used to log every create / find-after-create /
// bring-up / delete failure and return nil UNCONDITIONALLY. A route-based
// IPsec VPN whose xfrmi could not be realized in the kernel (LinkAdd failed)
// therefore reported a SUCCESSFUL commit while the interface — and the routes
// bound to it — carried no traffic (fail-open false convergence). Apply now
// aggregates the GENUINE netlink failures with errors.Join and returns them so
// the daemon apply-error join fails the commit closed. The tolerated idempotent
// conditions (adopt an already-exists link, delete an already-gone link) stay
// non-errors.

// TestXfrmApplyFailsClosedOnGenuineCreateFailure is the core #5310 guard: a
// genuine (non-EEXIST) LinkAdd failure on a newly-desired xfrmi makes Apply
// return a non-nil error that names the interface and wraps the netlink error,
// and leaves the interface UNTRACKED so the next reconcile retries.
//
// FAIL-ON-REVERT: the pre-#5310 Apply logged the LinkAdd failure and returned
// nil unconditionally. Under that code this test goes RED at the "want non-nil"
// assertion — the exact silent fail-open the issue describes.
func TestXfrmApplyFailsClosedOnGenuineCreateFailure(t *testing.T) {
	ops := newFakeLinkOps()
	ifName, ifID := config.XFRMIfNameAndID("st0.1")
	if ifName == "" || ifID == 0 {
		t.Fatalf("XFRMIfNameAndID returned name=%q id=%d for st0.1", ifName, ifID)
	}
	injected := errors.New("injected: LinkAdd EPERM")
	ops.addFail[ifName] = injected

	xm := &xfrmManager{ops: ops}
	err := xm.Apply(xfrmVPNs("st0.1"))
	if err == nil {
		t.Fatal("Apply must return the xfrmi create failure (fail-closed); got nil " +
			"(the silent fail-open #5310 describes: a route-based VPN reports a " +
			"successful commit while its xfrmi never made it into the kernel)")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned error must wrap the injected netlink failure, got %v", err)
	}
	if !strings.Contains(err.Error(), ifName) {
		t.Errorf("returned error should name the failed xfrmi %q, got %v", ifName, err)
	}
	if _, ok := xm.xfrmis[ifName]; ok {
		t.Error("a failed-create xfrmi must be left UNTRACKED so the next reconcile retries")
	}
}

// TestXfrmApplyToleratesAlreadyExistsIdempotent proves the idempotency the fix
// must preserve: an xfrmi that already exists in the kernel with the matching
// if_id is ADOPTED (re-tracked + brought up) and Apply returns nil — a benign
// re-apply (unrelated commit; daemon-restart adopt) must NOT be turned into a
// commit failure. GREEN both before and after the fix.
func TestXfrmApplyToleratesAlreadyExistsIdempotent(t *testing.T) {
	ops := newFakeLinkOps()
	ifName, ifID := config.XFRMIfNameAndID("st0.1")
	ops.links[ifName] = &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{Name: ifName, Index: 9},
		Ifid:      ifID,
	}

	xm := &xfrmManager{ops: ops}
	if err := xm.Apply(xfrmVPNs("st0.1")); err != nil {
		t.Fatalf("adopt of an already-exists xfrmi must be a no-error idempotent "+
			"reconcile, got %v", err)
	}
	if got := xm.xfrmis[ifName]; got != ifID {
		t.Errorf("adopted xfrmi tracked if_id %d, want %d", got, ifID)
	}
	if ops.addCount != 0 {
		t.Errorf("adopt path must issue zero LinkAdd, got %d", ops.addCount)
	}
}

// TestXfrmApplyFailsClosedOnBringUpFailure covers the create→bring-up path: the
// LinkAdd succeeds but LinkSetUp on the freshly-created xfrmi fails. Apply must
// surface that genuine bring-up failure (fail-closed) yet still TRACK the
// interface (it exists in the kernel, we own it) so the next reconcile
// re-attempts the LinkSetUp rather than orphaning it.
//
// FAIL-ON-REVERT: pre-#5310 the bring-up failure was logged and Apply returned
// nil — RED at the "want non-nil" assertion.
func TestXfrmApplyFailsClosedOnBringUpFailure(t *testing.T) {
	ops := newFakeLinkOps()
	ifName, ifID := config.XFRMIfNameAndID("st0.1")
	injected := errors.New("injected: LinkSetUp ENETDOWN")
	ops.upFail[ifName] = injected

	xm := &xfrmManager{ops: ops}
	err := xm.Apply(xfrmVPNs("st0.1"))
	if err == nil {
		t.Fatal("Apply must surface the xfrmi bring-up failure (fail-closed); got nil")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned error must wrap the injected bring-up failure, got %v", err)
	}
	if got, ok := xm.xfrmis[ifName]; !ok || got != ifID {
		t.Errorf("a created-but-not-up xfrmi must stay TRACKED (if_id %d) for retry; got %d, tracked=%v",
			ifID, got, ok)
	}
}

// TestManagerApplyXfrmiSurfacesCreateFailure proves the *Manager façade
// (ApplyXfrmi -> xfrm.Apply) propagates the xfrmi create failure — this is the
// exact boundary the daemon apply pipeline calls, so the error must not be
// dropped in the delegation.
func TestManagerApplyXfrmiSurfacesCreateFailure(t *testing.T) {
	ops := newFakeLinkOps()
	ifName, _ := config.XFRMIfNameAndID("st0.1")
	injected := errors.New("injected: LinkAdd ENOBUFS")
	ops.addFail[ifName] = injected

	m := &Manager{xfrm: &xfrmManager{ops: ops}}
	if err := m.ApplyXfrmi(xfrmVPNs("st0.1")); err == nil || !errors.Is(err, injected) {
		t.Fatalf("Manager.ApplyXfrmi must propagate the xfrmi create failure, got %v", err)
	}
}

// TestManagerApplyBondsSurfacesCreateFailure proves the *Manager façade
// (ApplyBonds -> bond.Apply) propagates a genuine bond-creation failure into
// the caller. Bond.Apply already returns the error (#4823); this pins the
// façade + the fact that daemon_apply.go's applyInterfaceReconcile now
// aggregates it (see the daemon-side #5310 test).
func TestManagerApplyBondsSurfacesCreateFailure(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.failLinkAdd["bond0"] = errors.New("injected: bond LinkAdd EPERM")

	m := &Manager{bond: &bondManager{ops: ops}}
	err := m.ApplyBonds([]*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1")})
	if err == nil {
		t.Fatal("Manager.ApplyBonds must propagate the bond create failure (fail-closed); got nil")
	}
}
