package routing

import (
	"errors"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// #7529: bond delete and tunnel clear treated EVERY LinkByName failure as
// absence and dropped ownership.
//
// A transient netlink lookup error — a busy or truncated socket, ENOBUFS under
// load, EINTR — is not the same answer as "this link does not exist". Both
// sites conflated them:
//
//   - bondManager.deleteLocked dropped the name from tracking AND returned nil,
//     so xpf reported a successful delete for a bond still in the kernel, still
//     enslaving its members, and no longer tracked. Nothing retries, because
//     the reconcile diff keys off b.bonds.
//   - ClearTunnels fell through with `continue`, which leaves the name out of
//     `failed` — and ownedNames is rebuilt from `failed`. A live tunnel with
//     stale addresses and XFRM if_id state became untracked.
//
// Both are the SAME defect #4901 fixed one call later, at the LinkDel leg: a
// failed delete retains the name so the next reconcile retries. The lookup leg
// kept the old behaviour and undid it, because a transient lookup discards the
// entry before LinkDel is ever reached.
//
// The fix shape was already in-tree: isLinkNotFound (vrf.go), used by the VRF
// path and by the XFRM path under #5461/#5495 — the identical conflation, in a
// sibling manager, fixed there and not here.
//
// The fake distinguishes the two error classes, which is what makes these cells
// mean anything: ops.byNameHardErr[name] returns a NON-not-found error, while
// an un-seeded name returns the errLinkNotFound sentinel.

func TestBondDeleteRetainsOwnershipOnTransientLookup7529(t *testing.T) {
	const name = "bond0"
	ops := newFakeLinkOps()
	ops.links[name] = &netlink.Bond{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 7}}
	injected := errors.New("injected: LinkByName ENOBUFS (transient)")
	ops.byNameHardErr[name] = injected

	b := &bondManager{ops: ops, bonds: map[string]bondSig{name: {}}}
	err := b.deleteLocked(name)

	if err == nil {
		t.Error("deleteLocked reported SUCCESS on a transient lookup error. The bond " +
			"is still in the kernel and still enslaving its members, and the caller " +
			"has been told it was deleted (#7529)")
	}
	if !errors.Is(err, injected) {
		t.Errorf("the returned error does not wrap the real cause: %v", err)
	}
	if _, still := b.bonds[name]; !still {
		t.Error("deleteLocked dropped the bond from tracking on a transient lookup " +
			"error. The reconcile diff keys off b.bonds, so nothing ever retries the " +
			"delete and the live bond is orphaned (#7529)")
	}
}

// THE OTHER HALF, and it is what stops the fix from being "never release
// ownership". A genuine not-found MUST still drop tracking and report success —
// otherwise a bond an operator removed out-of-band is retained forever and
// every reconcile reports a failure that can never clear.
func TestBondDeleteStillReleasesOnGenuineAbsence7529(t *testing.T) {
	const name = "bond1"
	ops := newFakeLinkOps() // un-seeded -> errLinkNotFound
	b := &bondManager{ops: ops, bonds: map[string]bondSig{name: {}}}

	if err := b.deleteLocked(name); err != nil {
		t.Errorf("deleteLocked on a genuinely absent bond returned %v, want nil. "+
			"Retaining ownership here would make every reconcile report a failure "+
			"that can never clear", err)
	}
	if _, still := b.bonds[name]; still {
		t.Error("a genuinely absent bond was RETAINED in tracking; only a transient " +
			"error may retain")
	}
}

func TestTunnelClearRetainsOwnershipOnTransientLookup7529(t *testing.T) {
	const name = "gr-0-0-0"
	ops := newFakeLinkOps()
	ops.links[name] = &netlink.Gretun{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 9}}
	injected := errors.New("injected: LinkByName EINTR (transient)")
	ops.byNameHardErr[name] = injected

	tm := &tunnelManager{ops: ops, ownedNames: map[string]bool{name: true}}
	err := tm.Clear()

	if err == nil {
		t.Error("Clear reported SUCCESS on a transient lookup error (#7529)")
	} else if !strings.Contains(err.Error(), name) {
		t.Errorf("the error does not name the tunnel it could not clear: %v", err)
	}
	if !tm.ownedNames[name] {
		t.Error("Clear dropped the tunnel from ownedNames on a transient lookup " +
			"error. A post-Clear Apply's removal diff keys off ownedNames, so a live " +
			"tunnel with stale addresses and XFRM if_id state is orphaned and never " +
			"retried (#7529)")
	}
}

func TestTunnelClearStillReleasesOnGenuineAbsence7529(t *testing.T) {
	const name = "gr-0-0-1"
	ops := newFakeLinkOps() // un-seeded -> errLinkNotFound
	tm := &tunnelManager{ops: ops, ownedNames: map[string]bool{name: true}}

	if err := tm.Clear(); err != nil {
		t.Errorf("Clear on a genuinely absent tunnel returned %v, want nil", err)
	}
	if tm.ownedNames[name] {
		t.Error("a genuinely absent tunnel was RETAINED in ownedNames; only a " +
			"transient error may retain")
	}
}

// THE MIXED CASE. One transient and one genuinely-absent name in the same
// Clear: the absent one must be released and the transient one retained. A
// fix that retains ALL names whenever ANY lookup fails passes both single-name
// cells above and is wrong here — and this is the shape a real reconcile sees,
// since Clear walks every owned name in one pass.
func TestTunnelClearMixedTransientAndAbsent7529(t *testing.T) {
	const transient, absent = "gr-0-0-2", "gr-0-0-3"
	ops := newFakeLinkOps()
	ops.links[transient] = &netlink.Gretun{
		LinkAttrs: netlink.LinkAttrs{Name: transient, Index: 11},
	}
	ops.byNameHardErr[transient] = errors.New("injected: transient")

	tm := &tunnelManager{ops: ops, ownedNames: map[string]bool{transient: true, absent: true}}
	if err := tm.Clear(); err == nil {
		t.Error("Clear reported success despite a transient lookup failure")
	}
	if !tm.ownedNames[transient] {
		t.Error("the transiently-failing tunnel was released")
	}
	if tm.ownedNames[absent] {
		t.Error("the genuinely absent tunnel was RETAINED. A fix that keeps every name " +
			"whenever any lookup fails passes both single-name cells and is still " +
			"wrong: ownership must be released per-name, on that name's own answer")
	}
}
