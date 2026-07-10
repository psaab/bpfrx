package routing

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5355: tunnelManager.Apply used to log every per-tunnel create /
// bring-up / delete failure and return nil UNCONDITIONALLY. A GRE/tunnel
// LinkAdd / LinkSetUp / LinkDel that genuinely failed therefore reported a
// SUCCESSFUL commit while the interface was absent (or admin-DOWN, or a
// removed tunnel's device lingered) — the same fail-open false-convergence
// that #5310 fixed for the xfrmManager. Apply now aggregates the GENUINE
// netlink failures with errors.Join and returns them so the #5354
// applyInterfaceReconcile tail-join fails the commit closed. The tolerated
// idempotent conditions (adopt an already-present compatible anchor, delete
// an already-gone tunnel) stay non-errors.
//
// Each fail-closed test is RED-on-revert: restoring the pre-#5355
// unconditional `return nil` in Apply (and the void helper signatures)
// makes the "want non-nil" assertions fail — the exact silent fail-open the
// issue describes. The two idempotency tests are GREEN both before and
// after the fix and pin the behavior the fix must not break.

// TestTunnelApplyFailsClosedOnGenuineCreateFailure is the core #5355 guard:
// a genuine (non-EEXIST) LinkAdd failure on a newly-desired anchor makes
// Apply return a non-nil error that names the tunnel and wraps the netlink
// error.
func TestTunnelApplyFailsClosedOnGenuineCreateFailure(t *testing.T) {
	ops := newFakeLinkOps()
	injected := errors.New("injected: anchor LinkAdd EPERM")
	ops.addFail["gr-0-0-0"] = injected
	tm, _ := newReconcileManager(ops)

	err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")})
	if err == nil {
		t.Fatal("Apply must return the anchor create failure (fail-closed); got nil " +
			"(the silent fail-open #5355 describes: a commit reports success while " +
			"the tunnel interface never made it into the kernel)")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned error must wrap the injected netlink failure, got %v", err)
	}
	if !strings.Contains(err.Error(), "gr-0-0-0") {
		t.Errorf("returned error should name the failed tunnel, got %v", err)
	}
}

// TestTunnelApplyFailsClosedOnBringUpFailure covers the create→bring-up
// path: the LinkAdd succeeds but LinkSetUp on the freshly-created anchor
// fails. Apply must surface that genuine bring-up failure (the device is
// present but admin-DOWN — no traffic).
func TestTunnelApplyFailsClosedOnBringUpFailure(t *testing.T) {
	ops := newFakeLinkOps()
	injected := errors.New("injected: LinkSetUp ENETDOWN")
	ops.upFail["gr-0-0-0"] = injected
	tm, _ := newReconcileManager(ops)

	err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")})
	if err == nil {
		t.Fatal("Apply must surface the anchor bring-up failure (fail-closed); got nil")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned error must wrap the injected bring-up failure, got %v", err)
	}
}

// TestTunnelApplyFailsClosedOnRemovalDeleteFailure covers the removal diff:
// a tunnel dropped from config whose device is still present but whose
// LinkDel genuinely fails must fail the commit closed — the removed
// tunnel's interface (and its addresses) linger live in the kernel.
// Ownership is still retained so the next apply retries (existing #1884
// behavior, exercised by TestTunnelRemovalRetriedAfterFailedDelete).
func TestTunnelApplyFailsClosedOnRemovalDeleteFailure(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)

	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("seed apply (create + own): %v", err)
	}

	injected := errors.New("injected: LinkDel EBUSY")
	ops.delFail["gr-0-0-0"] = injected
	err := tm.Apply(nil) // remove from config
	if err == nil {
		t.Fatal("Apply must surface the removed-tunnel LinkDel failure (fail-closed); got nil")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned error must wrap the injected LinkDel failure, got %v", err)
	}
	if !strings.Contains(err.Error(), "gr-0-0-0") {
		t.Errorf("returned error should name the failed tunnel, got %v", err)
	}
}

// TestTunnelApplyToleratesAdoptIdempotent proves the idempotency the fix
// must preserve: an anchor TUN that already exists in the kernel and is
// reusable is ADOPTED in place (reused + brought up, zero LinkAdd/LinkDel)
// and Apply returns nil — a benign re-apply (unrelated commit; daemon
// restart adopt) must NOT be turned into a commit failure. GREEN both
// before and after the fix.
func TestTunnelApplyToleratesAdoptIdempotent(t *testing.T) {
	ops := newFakeLinkOps()
	seedAnchor(ops, "gr-0-0-0", 42, 1500) // reusable NO_PI persistent TUN
	tm, _ := newReconcileManager(ops)

	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("adopt of an already-present reusable anchor must be a no-error "+
			"idempotent reconcile, got %v", err)
	}
	if ops.addCount != 0 {
		t.Errorf("adopt path must issue zero LinkAdd, got %d", ops.addCount)
	}
	if len(ops.delNames) != 0 {
		t.Errorf("adopt path must issue zero LinkDel, got %v", ops.delNames)
	}
}

// TestTunnelApplyToleratesAlreadyGoneDelete proves the removal-side
// idempotency: a tunnel dropped from config whose device is ALREADY GONE
// from the kernel (manual `ip link del`, or a prior successful removal) is
// a tolerated no-op — Apply returns nil, not a delete error. GREEN both
// before and after the fix.
func TestTunnelApplyToleratesAlreadyGoneDelete(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)

	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("seed apply (create + own): %v", err)
	}
	// Device vanishes out-of-band; LinkByName now reports not-found.
	delete(ops.links, "gr-0-0-0")

	if err := tm.Apply(nil); err != nil {
		t.Fatalf("removal of an already-gone tunnel must be a tolerated no-op, got %v", err)
	}
}

// TestTunnelApplyAggregatesMultipleFailures proves errors.Join accumulates
// EVERY genuine per-tunnel failure in one Apply — a partial failure does
// not mask the others, and all are surfaced to the commit.
func TestTunnelApplyAggregatesMultipleFailures(t *testing.T) {
	ops := newFakeLinkOps()
	inj0 := errors.New("injected: LinkAdd gr-0-0-0")
	inj1 := errors.New("injected: LinkAdd gr-0-0-1")
	ops.addFail["gr-0-0-0"] = inj0
	ops.addFail["gr-0-0-1"] = inj1
	tm, _ := newReconcileManager(ops)

	err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0"), anchorTC("gr-0-0-1")})
	if err == nil {
		t.Fatal("Apply must surface both create failures (fail-closed); got nil")
	}
	if !errors.Is(err, inj0) || !errors.Is(err, inj1) {
		t.Fatalf("errors.Join must aggregate BOTH create failures, got %v", err)
	}
}

// TestManagerApplyTunnelsSurfacesCreateFailure proves the *Manager façade
// (ApplyTunnels -> tunnel.Apply) propagates the tunnel create failure —
// this is the exact boundary daemon_apply.go's applyInterfaceReconcile
// calls (#5354), so the error must not be dropped in the delegation.
func TestManagerApplyTunnelsSurfacesCreateFailure(t *testing.T) {
	ops := newFakeLinkOps()
	injected := errors.New("injected: anchor LinkAdd ENOBUFS")
	ops.addFail["gr-0-0-0"] = injected
	binder := &fakeVRFBinder{ops: ops, fail: map[string]error{}}
	m := &Manager{tunnel: &tunnelManager{
		ops:        ops,
		vrfBinder:  binder,
		keepalives: map[string]*keepaliveRunner{},
	}}

	if err := m.ApplyTunnels([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err == nil || !errors.Is(err, injected) {
		t.Fatalf("Manager.ApplyTunnels must propagate the tunnel create failure, got %v", err)
	}
}
