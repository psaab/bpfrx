package routing

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestBondAdoptRejectsForeignLink is the #6402 fail-on-revert guard for the
// bond ADOPT path (the steady-state reconcile branch of createLocked). It is
// the last member of the post-create/adopt readback identity-assertion family:
// the #6396 create readback re-asserts *netlink.Bond, xfrm/VRF gate both their
// create and adopt paths, and this closes the bond adopt gap.
//
// LinkByName resolves the NAME, not the type. When a same-name FOREIGN
// (non-bond) link wears the tracked bond's name — an external actor's device,
// or a leftover of a different type after a name collision — the ungated adopt
// path brought it up and tracked the NAME as a satisfied bond while NO bond
// device carries the fabric/RETH members: the LAG silently does not exist yet
// the reconcile reports success. The type gate reclaims the name via
// delete+recreate instead.
//
// FAIL-ON-REVERT: dropping the `existing.(*netlink.Bond)` gate makes createLocked
// adopt the foreign *netlink.Dummy in place — it is never deleted (delCalls has
// no entry) and never recreated, so the kernel link under the name stays a
// *netlink.Dummy. Both assertions below then go RED (clean assertion failures,
// not a build break).
func TestBondAdoptRejectsForeignLink(t *testing.T) {
	ops := newFakeBondLinkOps()
	const name = "bond0"
	// A same-name foreign (non-bond) link is already present under the bond's
	// name when the reconcile runs — the steady-state adopt case, distinct from
	// the #6396 create-path add→readback TOCTOU. Give it a non-zero kernel index
	// so observedMembers does not fall back (models a real leftover device).
	ops.links[name] = &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: name, Index: 4242},
	}

	b := &bondManager{ops: ops}
	// The member is configured (so Apply does not skip the bond) but NOT seeded,
	// so enslaveMembers finds none and issues zero LinkSetMaster — the member
	// state in which the ungated adopt silently accepts the foreign link.
	if err := b.Apply([]*config.InterfaceConfig{bondFabricConfig(name, "ge-0-0-1")}); err != nil {
		t.Fatalf("Apply must succeed: the foreign link is reclaimed via delete+recreate "+
			"and the absent member is a soft error; got %v", err)
	}

	// The foreign link must have been deleted to reclaim the name.
	if !contains(ops.delCalls, name) {
		t.Errorf("the foreign link %q must be deleted to reclaim the name; delCalls=%v",
			name, ops.delCalls)
	}
	// After the reconcile a REAL bond must wear the name — the foreign Dummy must
	// not survive as the tracked device.
	link, ok := ops.links[name]
	if !ok {
		t.Fatalf("a bond must exist under %q after the reconcile; kernel links=%v", name, ops.links)
	}
	if _, isBond := link.(*netlink.Bond); !isBond {
		t.Errorf("the kernel link under %q must be a *netlink.Bond after delete+recreate, "+
			"got %T (the foreign link was adopted instead of reclaimed)", name, link)
	}
	if _, tracked := b.bonds[name]; !tracked {
		t.Errorf("the recreated bond must be tracked; bonds=%v", b.bonds)
	}
}

// TestBondAdoptAcceptsRealBond pins the happy path: a real *netlink.Bond that
// outlived in-memory tracking (the common daemon-restart adopt case) is adopted
// in place — brought up, tracked — and is NEVER deleted or recreated. This
// proves the #6402 type gate does not over-reject a legitimate bond and never
// flaps a live fabric/RETH LAG on an unrelated commit.
func TestBondAdoptAcceptsRealBond(t *testing.T) {
	ops := newFakeBondLinkOps()
	const name = "bond0"
	// A real kernel bond with its member already enslaved (daemon-restart adopt).
	ops.seedBond(name, 77)
	ops.seedEnslavedMember(config.LinuxIfName("ge-0-0-1"), 77)

	b := &bondManager{ops: ops}
	if err := b.Apply([]*config.InterfaceConfig{bondFabricConfig(name, "ge-0-0-1")}); err != nil {
		t.Fatalf("adopting a real bond must succeed, got %v", err)
	}

	if contains(ops.delCalls, name) {
		t.Errorf("a real bond must be adopted in place, never deleted; delCalls=%v", ops.delCalls)
	}
	if contains(ops.addCalls, name) {
		t.Errorf("a real bond must be adopted in place, never recreated; addCalls=%v", ops.addCalls)
	}
	if !contains(ops.setUpCalls, name) {
		t.Errorf("the adopted bond must be brought up; setUpCalls=%v", ops.setUpCalls)
	}
	if _, tracked := b.bonds[name]; !tracked {
		t.Errorf("the adopted bond must be tracked; bonds=%v", b.bonds)
	}
}

// TestBondKeepPathRejectsForeignReplacement is the #6402 fold guard for the
// SYMMETRIC readback: the Apply create/reconcile pass KEEP fast-path
// (`if trackedSig == sig` → LinkByName → LinkSetUp → continue). A bond that is
// already TRACKED as satisfied (b.bonds[name] == desired sig) can be replaced
// by a same-name FOREIGN (non-bond) link out from under the daemon. Without a
// type gate on the KEEP path, the next reconcile brings the foreign link up and
// declares convergence — the same silent LAG-absence bug the createLocked adopt
// gate closes, on a different path. The KEEP-path type gate falls a non-bond
// link through to createLocked, which reclaims it via delete+recreate.
//
// FAIL-ON-REVERT: dropping the KEEP-path `isBond` check makes the KEEP path
// bring the foreign *netlink.Dummy up and `continue` — it is never deleted
// (delCalls empty) and never recreated, so the kernel link under the name stays
// a *netlink.Dummy tracked as satisfied. Both assertions below then go RED
// (clean assertion failures, not a build break).
func TestBondKeepPathRejectsForeignReplacement(t *testing.T) {
	ops := newFakeBondLinkOps()
	const name = "bond0"
	cfg := bondFabricConfig(name, "ge-0-0-1")
	// A same-name foreign (non-bond) link now wears the tracked bond's name.
	ops.links[name] = &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: name, Index: 4242},
	}

	// Seed the bond as already TRACKED and SATISFIED (trackedSig == desired), so
	// Apply routes it through the KEEP fast-path rather than the fresh-create /
	// adopt branch the other #6402 tests exercise.
	b := &bondManager{ops: ops, bonds: map[string]bondSig{name: bondSigOf(cfg)}}
	if err := b.Apply([]*config.InterfaceConfig{cfg}); err != nil {
		t.Fatalf("Apply must succeed: the foreign link is reclaimed via delete+recreate "+
			"and the absent member is a soft error; got %v", err)
	}

	// The foreign link must have been deleted to reclaim the name.
	if !contains(ops.delCalls, name) {
		t.Errorf("the KEEP path must fall through to createLocked and delete the foreign "+
			"link; delCalls=%v", ops.delCalls)
	}
	// A REAL bond must wear the name after the reconcile — the foreign Dummy must
	// not survive as the tracked device.
	link, ok := ops.links[name]
	if !ok {
		t.Fatalf("a bond must exist under %q after the reconcile; kernel links=%v", name, ops.links)
	}
	if _, isBond := link.(*netlink.Bond); !isBond {
		t.Errorf("the kernel link under %q must be a *netlink.Bond after delete+recreate, "+
			"got %T (the KEEP path adopted the foreign link instead of reclaiming it)", name, link)
	}
	if _, tracked := b.bonds[name]; !tracked {
		t.Errorf("the recreated bond must be tracked; bonds=%v", b.bonds)
	}
}

// TestBondKeepPathForeignDeleteFailRetries covers the delete-fail transition
// Codex flagged: a tracked bond is replaced by a foreign link whose deletion
// FAILS. createLocked's adopt gate fails the commit closed, but tracking only
// clears after a SUCCESSFUL LinkDel (#4901), so b.bonds[name] is retained ==
// desired sig. The KEEP-path type gate guarantees the NEXT reconcile re-enters
// createLocked (re-attempts the delete) instead of KEEP-adopting the foreign
// link and reporting false convergence — createLocked is re-entered every
// reconcile until the delete succeeds.
//
// FAIL-ON-REVERT: dropping the KEEP-path `isBond` check makes the very first
// reconcile bring the foreign link up and `continue` (returning nil), so the
// fail-closed assertion goes RED; the next-reconcile re-entry assertions go RED
// too (no delete is attempted).
func TestBondKeepPathForeignDeleteFailRetries(t *testing.T) {
	ops := newFakeBondLinkOps()
	const name = "bond0"
	cfg := bondFabricConfig(name, "ge-0-0-1")
	// A foreign (non-bond) link wears the tracked bond's name, and its deletion
	// is stuck (a wedged netlink op).
	ops.links[name] = &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: name, Index: 4242},
	}
	ops.failLinkDel[name] = errors.New("injected: EBUSY")

	b := &bondManager{ops: ops, bonds: map[string]bondSig{name: bondSigOf(cfg)}}

	// First reconcile: the KEEP path must NOT adopt the foreign link. It falls
	// through to createLocked, whose adopt gate ATTEMPTS the delete; the delete
	// fails, so the commit fails closed.
	if err := b.Apply([]*config.InterfaceConfig{cfg}); err == nil {
		t.Fatalf("a failed reclaim of a foreign link on a tracked bond must fail the commit " +
			"closed, got nil (false convergence)")
	}
	if !contains(ops.delCalls, name) {
		t.Errorf("the KEEP path must fall through to createLocked and ATTEMPT the delete; "+
			"delCalls=%v", ops.delCalls)
	}
	if contains(ops.setUpCalls, name) {
		t.Errorf("the foreign link must NOT be brought up as a satisfied bond; setUpCalls=%v",
			ops.setUpCalls)
	}

	// Tracking is retained after the failed delete (#4901), but the type gate
	// guarantees the NEXT reconcile re-enters createLocked (re-attempts the
	// delete) rather than KEEP-adopting the foreign link — no false convergence.
	ops.reset()
	if err := b.Apply([]*config.InterfaceConfig{cfg}); err == nil {
		t.Fatalf("the next reconcile must STILL fail closed (re-enter createLocked), not " +
			"KEEP-adopt the foreign link, got nil")
	}
	if !contains(ops.delCalls, name) {
		t.Errorf("the next reconcile must re-attempt the delete (re-enter createLocked), not "+
			"KEEP-adopt; delCalls=%v", ops.delCalls)
	}
	if contains(ops.setUpCalls, name) {
		t.Errorf("the next reconcile must NOT bring up the foreign link as satisfied; "+
			"setUpCalls=%v", ops.setUpCalls)
	}
}
