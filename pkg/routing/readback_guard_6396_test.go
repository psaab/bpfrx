package routing

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestCreateLinkedVRFRejectsNonVrfReadback is the #6396 mirror of the xfrm
// post-create readback guard, for VRFs. LinkAdd and the LinkByName readback are
// two syscalls; a concurrent external actor that deleted the fresh VRF and
// substituted a same-name foreign (non-VRF) link in that window must NOT be
// brought up and recorded as satisfied — otherwise the name reads as realized
// while no VRF with the desired table exists and the routes leaked into it
// silently blackhole.
//
// FAIL-ON-REVERT: dropping the type/table re-assertion brings the foreign link
// UP (setUps>0) and returns a nil error — the error/no-bring-up assertions go
// RED.
func TestCreateLinkedVRFRejectsNonVrfReadback(t *testing.T) {
	ops := newFakeVRFOps()
	const name = "vrf-red"
	// A foreign (non-VRF) link is swapped in during the add→readback window.
	ops.substituteAfterAdd[name] = &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: name, Index: 9},
	}

	added, err := createLinkedVRF(ops, name, 100)
	if !added {
		t.Errorf("added must be true after a successful LinkAdd so the caller records " +
			"ownership for cleanup; got added=false")
	}
	if err == nil {
		t.Fatalf("a substituted non-VRF readback after create must fail closed, got nil")
	}
	if ops.setUps != 0 {
		t.Errorf("the substituted foreign link must not be brought up, got %d LinkSetUp", ops.setUps)
	}
}

// TestCreateLinkedVRFRejectsWrongTableReadback covers the second substitution
// shape: a VRF that wears the name but carries the WRONG routing table. It too
// must be rejected rather than adopted (adopting it would leak routes into the
// wrong table's VRF).
func TestCreateLinkedVRFRejectsWrongTableReadback(t *testing.T) {
	ops := newFakeVRFOps()
	const name = "vrf-red"
	ops.substituteAfterAdd[name] = &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: name, Index: 9},
		Table:     999, // desired below is 100
	}

	added, err := createLinkedVRF(ops, name, 100)
	if !added {
		t.Errorf("added must be true after a successful LinkAdd, got false")
	}
	if err == nil {
		t.Fatalf("a wrong-table VRF readback after create must fail closed, got nil")
	}
	if ops.setUps != 0 {
		t.Errorf("the wrong-table link must not be brought up, got %d LinkSetUp", ops.setUps)
	}
}

// TestCreateLinkedVRFCleanReadbackSucceeds pins the happy path: a matching-table
// VRF readback is brought up and reported success — so the guard above does not
// over-reject.
func TestCreateLinkedVRFCleanReadbackSucceeds(t *testing.T) {
	ops := newFakeVRFOps()
	added, err := createLinkedVRF(ops, "vrf-blue", 200)
	if !added || err != nil {
		t.Fatalf("a clean create must return (true, nil), got (%v, %v)", added, err)
	}
	if ops.setUps != 1 {
		t.Errorf("a clean create must bring the VRF up exactly once, got %d", ops.setUps)
	}
}

// TestBondCreateRejectsForeignReadback is the #6396 bond mirror. A bond is only
// created (createLocked) for a config WITH members (Apply skips zero-member
// configs), but enslaveMembers surfaces a foreign-substitute error only when a
// member is actually enslavable. When the configured members are all currently
// absent (the #4823 soft-error enumeration case) nothing is enslaved, so a
// same-name foreign link substituted in the add→readback window would be
// brought up and tracked as a satisfied bond. The explicit type re-assertion
// fails the commit closed instead.
//
// FAIL-ON-REVERT: dropping the type re-assertion tracks the foreign bond
// (b.bonds["bond0"] set) and returns nil — the error/untracked assertions go
// RED.
func TestBondCreateRejectsForeignReadback(t *testing.T) {
	ops := newFakeBondLinkOps()
	const name = "bond0"
	// Foreign (non-bond) link swapped in during the add→readback window.
	ops.substituteAfterAdd[name] = &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: name, Index: 4242},
	}

	b := &bondManager{ops: ops}
	// Members are configured (so Apply does not skip the bond) but NOT seeded,
	// so enslaveMembers finds none and issues zero LinkSetMaster — the path
	// where a foreign readback is otherwise silently adopted.
	err := b.Apply([]*config.InterfaceConfig{bondFabricConfig(name, "ge-0-0-1")})
	if err == nil {
		t.Fatalf("a foreign non-bond readback after create must fail the commit closed, got nil")
	}
	if _, tracked := b.bonds[name]; tracked {
		t.Errorf("a foreign readback must not be tracked as a satisfied bond; bonds=%v", b.bonds)
	}
	for _, n := range ops.setUpCalls {
		if n == name {
			t.Errorf("the foreign link %q must not be brought up", name)
		}
	}
}
