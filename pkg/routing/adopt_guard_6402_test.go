package routing

import (
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
