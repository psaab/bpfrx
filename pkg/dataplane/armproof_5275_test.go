package dataplane

import (
	"testing"

	"github.com/vishvananda/netlink"
)

// #5275 PR1 — the observe-only arm-coverage proof.
//
// These tests pin the proof's DEFINITION, which is the part that must not
// drift: which surfaces count as covered, and why. The plan's §5/D1 wording
// ("strict program INSTANCE identity on every mapped attach point (native or
// generic)") is a native/generic binary and misses the delegated case
// entirely; implemented literally it would fail-close every VLAN deployment.

// newProofResult builds a CompileResult carrying only what the proof reads.
func newProofResult(pending []int) *CompileResult {
	return &CompileResult{
		pendingXDP:               pending,
		tunnelIfindexes:          map[int]bool{},
		genericXDPIfindexes:      map[int]bool{},
		fallbackGenericIfindexes: map[int]bool{},
		linkIdxMap:               map[int]netlink.Link{},
		linkCache:                map[string]netlink.Link{},
	}
}

// vlanChild registers ifidx as a VLAN sub-interface of parent, exactly as
// compiler_iface.go marks them: genericXDPIfindexes set, not a tunnel.
func vlanChild(r *CompileResult, ifidx, parent int) {
	r.genericXDPIfindexes[ifidx] = true
	r.linkIdxMap[ifidx] = &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{Index: ifidx, ParentIndex: parent},
	}
}

// lookupFrom builds an instanceLookup from a table of covered ifindexes.
func lookupFrom(covered map[int]uint32, generic map[int]bool) instanceLookup {
	return func(ifidx int) (uint32, bool, bool) {
		id, ok := covered[ifidx]
		if !ok {
			return 0, false, false
		}
		return id, generic[ifidx], true
	}
}

// TestArmProofGenericFallbackCountsAsArmed pins the STATED DECISION that a
// generic (skb-mode) attach is armed.
//
// It is deliberately a test and not only a comment. A generic shim still
// steers packets to userspace-dp and still enforces policy — slower, but
// #5275 exists to prevent a POLICY-FREE kernel, and this box is not policy
// free. iavf SR-IOV VFs have NO native XDP support at all, so the fallback is
// a supported steady state; failing it closed would brick a supported
// deployment to prevent a condition that is not occurring.
//
// Without this test the decision is an implicit consequence of how the
// readback happens to be written, and a later "tighten the proof" change flips
// those boxes to fail-closed with nobody intending it.
func TestArmProofGenericFallbackCountsAsArmed(t *testing.T) {
	r := newProofResult([]int{10})
	r.fallbackGenericIfindexes[10] = true // native attach failed, re-attached generic

	rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 77}, map[int]bool{10: true}))

	if rep.Uncovered != 0 || rep.Direct != 1 {
		t.Fatalf("generic fallback must count as armed; got %+v", rep)
	}
	if rep.WouldGate {
		t.Fatal("a gating build would have REFUSED a box running the shim in skb-mode — " +
			"that is a supported deployment (iavf VFs have no native XDP at all)")
	}
	s := rep.Surfaces[0]
	if s.Kind != CoverageDirect || !s.Generic {
		t.Fatalf("expected direct+generic; got kind=%s generic=%v", s.Kind, s.Generic)
	}
	if s.ProgramID != 77 {
		t.Fatalf("proof did not record the attached program instance; got %d", s.ProgramID)
	}
}

// TestArmProofDelegatedVlanChildResolvesToParent pins the third category the
// plan's native/generic binary misses.
//
// A VLAN sub-interface under the userspace shim is NEVER attached — both
// attach loops skip it and it is recorded in VlanSubInterfaces instead —
// because the PARENT's XDP sees VLAN-tagged frames before kernel VLAN
// demuxing, and attaching the shim to the child breaks IPv6 NDP. Policy is
// enforced, at a different attach point.
//
// A proof demanding an instance on every mapped attach point fails here, and
// the loss cluster (reth0.50 / reth0.80) plus the standalone VM (VLAN 50) both
// have such surfaces — i.e. it would fail-close essentially every real
// deployment.
func TestArmProofDelegatedVlanChildResolvesToParent(t *testing.T) {
	r := newProofResult([]int{10, 20})
	vlanChild(r, 20, 10) // 20 is a VLAN child of 10

	// Only the PARENT carries an instance. That is the correct steady state.
	rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 55}, nil))

	if rep.Uncovered != 0 {
		t.Fatalf("a VLAN child covered by its parent must not read as uncovered; got %+v", rep)
	}
	if rep.Direct != 1 || rep.Delegated != 1 {
		t.Fatalf("expected 1 direct (parent) + 1 delegated (child); got %+v", rep)
	}
	if rep.WouldGate {
		t.Fatal("a gating build would have REFUSED a plain VLAN deployment — " +
			"the loss cluster and the standalone VM both run VLAN sub-interfaces")
	}
	var child SurfaceCoverage
	for _, s := range rep.Surfaces {
		if s.Ifindex == 20 {
			child = s
		}
	}
	if child.Kind != CoverageDelegated || child.Via != 10 {
		t.Fatalf("child must resolve to its covering parent; got kind=%s via=%d", child.Kind, child.Via)
	}
	if child.ProgramID != 55 {
		t.Fatalf("delegated surface must carry the DELEGATE's instance; got %d", child.ProgramID)
	}
}

// TestArmProofDelegationIsResolvedNotAssumed is the other half of the pair
// above, and the reason "skip VLAN children" is not an acceptable shortcut.
//
// If the parent carries no instance, the child is NOT covered — nothing is
// enforcing its traffic. A proof that skipped VLAN children unconditionally
// would pass this box, which is precisely the policy-free-router state #5275
// exists to prevent.
func TestArmProofDelegationIsResolvedNotAssumed(t *testing.T) {
	r := newProofResult([]int{10, 20})
	vlanChild(r, 20, 10)

	// NOTHING is attached — parent included.
	rep := classifyArmCoverage(r, lookupFrom(nil, nil))

	if rep.Delegated != 0 {
		t.Fatalf("a child whose parent carries no instance must NOT read as delegated; got %+v", rep)
	}
	if rep.Uncovered != 2 {
		t.Fatalf("both parent and child are uncovered; got %+v", rep)
	}
	if !rep.WouldGate {
		t.Fatal("a fully unattached dataplane must be reported as WOULD-GATE — " +
			"this is the policy-free kernel #5275 is about")
	}
}

// TestArmProofUncoveredIsTheZeroValue pins the fail-safe default. An entry that
// was never populated must read as uncovered, so a partially-built report can
// only ever be more conservative, never less.
func TestArmProofUncoveredIsTheZeroValue(t *testing.T) {
	var k SurfaceCoverageKind
	if k != CoverageUncovered {
		t.Fatalf("the zero SurfaceCoverageKind must be Uncovered, got %s — "+
			"an unpopulated entry would otherwise read as covered", k)
	}
	var s SurfaceCoverage
	if s.Kind != CoverageUncovered {
		t.Fatal("a zero SurfaceCoverage must read as uncovered")
	}
}

// TestArmProofReadbackFailureIsUncovered pins that a tracked link whose
// identity cannot be read is not treated as proof of coverage. The lookup
// returning ok=false is exactly what Manager.attachedInstance does when
// link.Info() errors.
func TestArmProofReadbackFailureIsUncovered(t *testing.T) {
	r := newProofResult([]int{10})
	// Link tracked (generic flag known) but the instance readback failed.
	rep := classifyArmCoverage(r, func(int) (uint32, bool, bool) { return 0, true, false })

	if rep.Uncovered != 1 || rep.Direct != 0 {
		t.Fatalf("a failed instance readback must degrade to uncovered; got %+v", rep)
	}
	if !rep.WouldGate {
		t.Fatal("unreadable link identity must be reported as WOULD-GATE, not assumed benign")
	}
}

// TestArmProofIsDeterministic pins the stable ordering the log line depends on:
// two reports of the same box must be diffable.
func TestArmProofIsDeterministic(t *testing.T) {
	r := newProofResult([]int{30, 10, 20})
	lookup := lookupFrom(map[int]uint32{10: 1, 20: 2, 30: 3}, nil)

	rep := classifyArmCoverage(r, lookup)
	if len(rep.Surfaces) != 3 {
		t.Fatalf("expected 3 surfaces; got %d", len(rep.Surfaces))
	}
	for i, want := range []int{10, 20, 30} {
		if rep.Surfaces[i].Ifindex != want {
			t.Fatalf("surfaces must be in ascending ifindex order; got %+v", rep.Surfaces)
		}
	}
	// The input slice must not be reordered underneath the caller — the proof
	// runs mid-apply against live compile state.
	if r.pendingXDP[0] != 30 {
		t.Fatalf("proof MUTATED the compile result's pendingXDP order: %v", r.pendingXDP)
	}
}

// TestArmProofEmptySurfaceSetGatesNothing pins that a config requiring no XDP
// surfaces produces no report and no would-gate. A box with nothing to arm is
// not an unarmed box.
func TestArmProofEmptySurfaceSetGatesNothing(t *testing.T) {
	rep := classifyArmCoverage(newProofResult(nil), lookupFrom(nil, nil))
	if len(rep.Surfaces) != 0 || rep.WouldGate {
		t.Fatalf("an empty surface set must not report a gate; got %+v", rep)
	}
	// nil result / nil lookup must be inert too — the proof runs on paths where
	// the dataplane may not exist.
	if rep := classifyArmCoverage(nil, lookupFrom(nil, nil)); rep.WouldGate {
		t.Fatal("nil compile result must not report a gate")
	}
	if rep := classifyArmCoverage(newProofResult([]int{1}), nil); rep.WouldGate {
		t.Fatal("nil lookup must not report a gate")
	}
}
