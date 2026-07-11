package routing

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #5461 / #5495: xfrmManager treated ANY LinkByName error as "interface not
// present", conflating a transient/lookup failure (EBUSY, EINVAL, timeout,
// netlink transport) with genuine absence.
//
//   - #5461 (Apply create path): on a transient lookup error for an xfrmi that
//     actually EXISTS, Apply fell through to LinkAdd -> EEXIST -> a spurious
//     fail-closed commit error, leaving the interface desired-but-untracked.
//   - #5495 (deleteLocked / full-tunnel Clear): on ANY LinkByName error it
//     deleted tracking and returned nil-gone. A transient error therefore
//     silently ORPHANED a live kernel xfrmi (+ stale routing/security state)
//     while reporting convergence — a later Apply had no removed-desired entry
//     to drive cleanup.
//
// The fix mirrors reconcileVRFs (vrf.go): only a GENUINE not-found
// (isLinkNotFound) may (a) fall through to create or (b) drop tracking + report
// gone. A transient error retains ownership and surfaces the real error so the
// commit fails closed and the next reconcile retries.
//
// The fake distinguishes the two error classes: ops.byNameHardErr[name] returns
// a NON-not-found (transient) error, while an un-seeded name returns the
// errLinkNotFound sentinel (isLinkNotFound == true).

// TestXfrmApplyTransientLookupDoesNotCreate is the #5461 guard: a TRANSIENT
// LinkByName error on a tracked, still-desired xfrmi that actually exists in the
// kernel must NOT drive a LinkAdd (which would EEXIST). Apply must retain the
// tracking entry and surface the transient error itself.
//
// FAIL-ON-REVERT: revert Apply to the blanket `if link, err := ...; err == nil`
// gate and, on the transient error, `err == nil` is false so Apply falls
// through to LinkAdd. With the device already present (ops.addExisting) that
// LinkAdd returns "file exists" — so ops.addAttempts becomes 1 (RED at the
// zero-attempt assertion) and the returned error wraps "file exists" rather than
// the injected transient error (RED at errors.Is).
func TestXfrmApplyTransientLookupDoesNotCreate(t *testing.T) {
	ops := newFakeLinkOps()
	ifName, ifID := config.XFRMIfNameAndID("st0.1")
	if ifName == "" || ifID == 0 {
		t.Fatalf("XFRMIfNameAndID returned name=%q id=%d for st0.1", ifName, ifID)
	}
	// Model reality: the xfrmi EXISTS in the kernel with the matching if_id,
	// so a fall-through LinkAdd would EEXIST.
	ops.links[ifName] = &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{Name: ifName, Index: 12},
		Ifid:      ifID,
	}
	ops.addExisting = true // a fall-through LinkAdd would report EEXIST
	injected := errors.New("injected: LinkByName EBUSY (transient)")
	ops.byNameHardErr[ifName] = injected

	// Already tracked with the matching if_id (so the delete pass leaves it and
	// the reconcile loop takes the lookup path under test).
	xm := &xfrmManager{ops: ops, xfrmis: map[string]uint32{ifName: ifID}}

	err := xm.Apply(xfrmVPNs("st0.1"))
	if err == nil {
		t.Fatal("Apply must surface the transient lookup error (fail-closed); got nil")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned error must wrap the injected TRANSIENT lookup error "+
			"(not a spurious EEXIST from a fall-through create), got %v", err)
	}
	if !strings.Contains(err.Error(), ifName) {
		t.Errorf("returned error should name the xfrmi %q, got %v", ifName, err)
	}
	if ops.addAttempts != 0 {
		t.Errorf("Apply attempted %d LinkAdd on a transient lookup error, want 0 "+
			"(a transient error must NOT drive a create that EEXISTs)", ops.addAttempts)
	}
	if got, ok := xm.xfrmis[ifName]; !ok || got != ifID {
		t.Errorf("a transiently-unlookupable xfrmi must stay TRACKED (if_id %d) for retry; "+
			"got %d, tracked=%v", ifID, got, ok)
	}
}

// TestXfrmApplyGenuineNotFoundStillCreates is the #5461 preserved-behavior half:
// a GENUINE not-found (isLinkNotFound) still falls through to LinkAdd and tracks
// the new xfrmi, exactly as before. GREEN both before and after the fix.
func TestXfrmApplyGenuineNotFoundStillCreates(t *testing.T) {
	ops := newFakeLinkOps() // un-seeded name -> LinkByName returns errLinkNotFound
	ifName, ifID := config.XFRMIfNameAndID("st0.1")

	xm := &xfrmManager{ops: ops}
	if err := xm.Apply(xfrmVPNs("st0.1")); err != nil {
		t.Fatalf("genuine not-found must create with no error, got %v", err)
	}
	if ops.addCount != 1 {
		t.Errorf("genuine not-found issued %d LinkAdd, want exactly 1", ops.addCount)
	}
	if got, ok := xm.xfrmis[ifName]; !ok || got != ifID {
		t.Errorf("newly-created xfrmi must be tracked with if_id %d; got %d, tracked=%v",
			ifID, got, ok)
	}
}

// TestXfrmDeleteLockedTransientLookupRetains is the #5495 guard: a TRANSIENT
// LinkByName error inside deleteLocked must NOT drop tracking and must NOT
// report success. It retains the entry (so a later Apply still has a
// removed-desired entry to drive cleanup) and surfaces the error.
//
// FAIL-ON-REVERT: revert deleteLocked to the blanket `if err != nil { delete;
// return nil }` and a transient error deletes the tracking entry and returns nil
// — RED at both the retention and the non-nil-error assertions (the exact silent
// orphan #5495 describes).
func TestXfrmDeleteLockedTransientLookupRetains(t *testing.T) {
	ops := newFakeLinkOps()
	const name = "xfrm1"
	seedDummy(ops, name)
	injected := errors.New("injected: LinkByName ETIMEDOUT (transient)")
	ops.byNameHardErr[name] = injected

	xm := &xfrmManager{ops: ops, xfrmis: map[string]uint32{name: 100}}

	err := xm.deleteLocked(name)
	if err == nil {
		t.Fatal("deleteLocked must surface the transient lookup error, not report gone " +
			"(a transient error must not orphan a live kernel xfrmi)")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned error must wrap the injected transient error, got %v", err)
	}
	if !strings.Contains(err.Error(), name) {
		t.Errorf("returned error should name the xfrmi %q, got %v", name, err)
	}
	if _, ok := xm.xfrmis[name]; !ok {
		t.Fatal("a transiently-unlookupable xfrmi must be RETAINED in tracking so a later " +
			"Apply drives cleanup (do NOT delete tracking + report gone)")
	}
	if len(ops.delNames) != 0 {
		t.Errorf("LinkDel must not run when the lookup failed transiently, got %v", ops.delNames)
	}
}

// TestXfrmDeleteLockedGenuineNotFoundDropsTracking is the #5495 preserved-behavior
// half: a GENUINE not-found still drops the tracking entry and returns nil-gone,
// exactly as before. GREEN both before and after the fix.
func TestXfrmDeleteLockedGenuineNotFoundDropsTracking(t *testing.T) {
	ops := newFakeLinkOps() // un-seeded name -> errLinkNotFound
	const name = "xfrm1"

	xm := &xfrmManager{ops: ops, xfrmis: map[string]uint32{name: 100}}
	if err := xm.deleteLocked(name); err != nil {
		t.Fatalf("genuine not-found must be treated as already-gone (nil), got %v", err)
	}
	if _, ok := xm.xfrmis[name]; ok {
		t.Error("a genuinely-absent xfrmi must be dropped from tracking")
	}
}

// TestXfrmClearTransientLookupRetains is the #5495 full-tunnel Clear path: a
// transient LinkByName error during Clear must RETAIN the tracked entry and
// surface the error, while a genuinely-present peer entry is still deleted.
//
// FAIL-ON-REVERT: with the blanket deleteLocked, the transient "xfrm-bad" entry
// is deleted + reported gone (Clear then sees len==0 and nils the map), so the
// retention and non-nil-error assertions go RED.
func TestXfrmClearTransientLookupRetains(t *testing.T) {
	ops := newFakeLinkOps()
	seedDummy(ops, "xfrm-bad")
	seedDummy(ops, "xfrm-ok")
	injected := errors.New("injected: LinkByName EBUSY (transient)")
	ops.byNameHardErr["xfrm-bad"] = injected

	xm := &xfrmManager{ops: ops, xfrmis: map[string]uint32{"xfrm-bad": 100, "xfrm-ok": 101}}

	err := xm.Clear()
	if err == nil {
		t.Fatal("Clear must surface the transient lookup failure, not nil (orphaned xfrmi)")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("Clear error must wrap the injected transient error, got %v", err)
	}
	if !strings.Contains(err.Error(), "xfrm-bad") {
		t.Errorf("Clear error should name the retained xfrmi: %v", err)
	}
	if _, ok := xm.xfrmis["xfrm-bad"]; !ok {
		t.Fatal("transiently-unlookupable xfrmi must be RETAINED so the next reconcile retries")
	}
	if _, ok := xm.xfrmis["xfrm-ok"]; ok {
		t.Fatal("genuinely-present xfrmi must be deleted from tracking on a successful LinkDel")
	}
	if !sliceHas(ops.delNames, "xfrm-ok") {
		t.Errorf("the present xfrmi should have been LinkDel'd, delNames=%v", ops.delNames)
	}
}
