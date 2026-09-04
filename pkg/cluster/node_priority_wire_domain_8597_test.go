package cluster

import (
	"math"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 (muse-004 K17) — an out-of-range redundancy-group node priority put a
// TRUNCATED value on the heartbeat wire while election.go compared the RAW
// local int, so the two nodes computed opposite winners and both went primary.
//
// 65700 is the fixture because its low 16 bits are 164, which lands on the far
// side of a peer at 200: local sees 65700 > 200, peer sees 200 > 164. A value
// that merely wrapped to something still above the peer would not diverge, so
// the fixture is chosen for the inversion, not for being large.
const (
	divergentPriority8597 = 65700
	peerPriority8597      = 200
)

// TestOutOfRangePriorityFixtureInverts_8597 is the non-vacuity guard. The cells
// below assert that exactly one node is primary, and "exactly one primary" is
// also what a correct system does for almost any input — so the fixture has to
// be one that DOES invert under truncation, or those cells prove nothing.
func TestOutOfRangePriorityFixtureInverts_8597(t *testing.T) {
	// Through a variable: Go rejects the constant conversion at compile time,
	// which is itself part of the story — the value only reaches the cast at
	// RUNTIME, as an int the compiler read with strconv.Atoi.
	raw := divergentPriority8597
	truncated := int(uint16(raw))
	if truncated != 164 {
		t.Fatalf("uint16(%d) = %d, want 164", divergentPriority8597, truncated)
	}
	if !(truncated < peerPriority8597 && peerPriority8597 < divergentPriority8597) {
		t.Fatalf("fixture does not invert: need truncated(%d) < peer(%d) < raw(%d); "+
			"without that ordering both nodes agree on the winner even while "+
			"truncating, and the cells below are vacuous",
			truncated, peerPriority8597, divergentPriority8597)
	}
	if divergentPriority8597 <= config.MaxRedundancyGroupNodePriority {
		t.Fatalf("fixture %d is inside the configured range %d; it would never be clamped",
			divergentPriority8597, config.MaxRedundancyGroupNodePriority)
	}
}

// twoNodeElection drives BOTH managers against each other through the real
// wire path — node A's buildHeartbeat output is what node B's
// handlePeerHeartbeat consumes — and reports each node's primary verdict.
//
// Driving buildHeartbeat rather than hand-building a HeartbeatPacket is the
// point: the defect is in what the SENDER puts on the wire, so a fixture that
// supplies its own packet would test the receiver and leave the truncation
// unobserved.
func twoNodeElection(t *testing.T, priorities map[int]int) (aPrimary, bPrimary bool) {
	t.Helper()
	cfg := makeConfig(makeRG(0, true, priorities))

	a := NewManager(0, 1)
	b := NewManager(1, 1)
	a.UpdateConfig(cfg)
	b.UpdateConfig(cfg)
	drainEvents(a, 1)
	drainEvents(b, 1)

	// Two rounds, so each node has seen the other's advertisement and
	// re-elected against it.
	for i := 0; i < 2; i++ {
		b.handlePeerHeartbeat(a.buildHeartbeat())
		a.handlePeerHeartbeat(b.buildHeartbeat())
	}
	return a.IsLocalPrimary(0), b.IsLocalPrimary(0)
}

// TestOutOfRangeNodePriorityDoesNotSplitTheElection_8597 is the RED-on-revert
// core. Reverting either half of the fix — the clampNodePriority calls in
// UpdateConfig, or clampWirePriority in buildHeartbeat — puts both nodes in
// StatePrimary: duplicate VIPs and a duplicate RETH virtual MAC on the LAN.
func TestOutOfRangeNodePriorityDoesNotSplitTheElection_8597(t *testing.T) {
	aPrimary, bPrimary := twoNodeElection(t, map[int]int{
		0: divergentPriority8597,
		1: peerPriority8597,
	})
	if aPrimary && bPrimary {
		t.Fatal("BOTH nodes elected themselves primary for RG 0 — the out-of-range " +
			"priority truncated on the wire while the local election compared the " +
			"raw int (#8597/K17). Duplicate VIPs and duplicate RETH virtual MAC.")
	}
	if !aPrimary && !bPrimary {
		t.Fatal("NEITHER node is primary for RG 0; the clamp must bound the priority, " +
			"not disqualify the group")
	}
	// The clamped node still outranks the peer (254 > 200), so the node that
	// asked for the absurd priority is the one that wins — the operator's
	// INTENT is preserved, only the magnitude is bounded.
	if !aPrimary {
		t.Error("node 0 (configured priority above range, clamped to 254) lost to a " +
			"peer at 200; clamping must stay MONOTONIC with the configured intent")
	}
}

// TestOrdinaryPrioritiesStillElectTheHigherNode_8597 is the OVER-BROAD control.
// A clamp that flattened every priority to one value, or that disqualified any
// group it touched, would satisfy the cell above and break every real cluster.
func TestOrdinaryPrioritiesStillElectTheHigherNode_8597(t *testing.T) {
	aPrimary, bPrimary := twoNodeElection(t, map[int]int{0: 200, 1: 100})
	if !aPrimary || bPrimary {
		t.Fatalf("in-range priorities 200 vs 100 elected a=%v b=%v; want node 0 only",
			aPrimary, bPrimary)
	}
	// And the reverse, so the cell cannot pass by always favouring node 0.
	aPrimary, bPrimary = twoNodeElection(t, map[int]int{0: 100, 1: 200})
	if aPrimary || !bPrimary {
		t.Fatalf("in-range priorities 100 vs 200 elected a=%v b=%v; want node 1 only",
			aPrimary, bPrimary)
	}
}

// TestUpdateConfigClampsBothAssignmentBranches_8597: UpdateConfig has TWO
// LocalPriority assignments — one for a group it is seeing for the first time,
// one for a group it already holds. On a running box the SECOND is the common
// path (every subsequent commit), so a clamp applied to only the first would
// leave the more frequent path installing the raw value.
func TestUpdateConfigClampsBothAssignmentBranches_8597(t *testing.T) {
	m := NewManager(0, 1)

	// First apply — the new-group branch.
	m.UpdateConfig(makeConfig(makeRG(0, true, map[int]int{0: divergentPriority8597})))
	drainEvents(m, 1)
	if got := m.groups[0].LocalPriority; got != config.MaxRedundancyGroupNodePriority {
		t.Errorf("new-group branch installed LocalPriority %d, want %d",
			got, config.MaxRedundancyGroupNodePriority)
	}

	// Second apply on the SAME group — the existing-group branch.
	m.UpdateConfig(makeConfig(makeRG(0, true, map[int]int{0: divergentPriority8597 + 1})))
	if got := m.groups[0].LocalPriority; got != config.MaxRedundancyGroupNodePriority {
		t.Errorf("existing-group branch installed LocalPriority %d, want %d — the clamp "+
			"must cover BOTH assignments, and this is the one a running box takes on "+
			"every commit", got, config.MaxRedundancyGroupNodePriority)
	}
}

// TestClampWirePrioritySaturates_8597 pins the last belt directly. It is not
// red-on-revert on its own (the domain is closed upstream, so this is an
// identity for every value the runtime can hold today) — it exists so a future
// writer who bypasses clampNodePriority degrades to a bounded, MONOTONIC value
// instead of one that wrapped past the peer's.
func TestClampWirePrioritySaturates_8597(t *testing.T) {
	cases := []struct {
		in   int
		want uint16
	}{
		{0, 0},
		{1, 1},
		{200, 200},
		{254, 254},
		{math.MaxUint16, math.MaxUint16},
		{math.MaxUint16 + 1, math.MaxUint16},
		{divergentPriority8597, math.MaxUint16},
		{-1, 0},
	}
	for _, c := range cases {
		if got := clampWirePriority(c.in); got != c.want {
			t.Errorf("clampWirePriority(%d) = %d, want %d", c.in, got, c.want)
		}
	}
	// The property the election actually depends on: saturation is monotonic,
	// truncation is not. Any two priorities that order one way as ints must
	// order the same way on the wire.
	for _, pair := range [][2]int{
		{divergentPriority8597, peerPriority8597},
		{300, 254},
		{math.MaxUint16 + 5, math.MaxUint16},
	} {
		hi, lo := pair[0], pair[1]
		if clampWirePriority(hi) < clampWirePriority(lo) {
			t.Errorf("clampWirePriority inverted %d > %d into %d < %d — a wire narrowing "+
				"that inverts an ordering is the whole defect",
				hi, lo, clampWirePriority(hi), clampWirePriority(lo))
		}
	}
}

// TestClampRedundancyGroupNodePriorityReportsClamping_8597 pins the config
// helper's second return value, which is what lets the caller warn. A clamp
// that silently substituted a value would leave an operator with a cluster
// behaving on a number they never wrote and no line saying so.
func TestClampRedundancyGroupNodePriorityReportsClamping_8597(t *testing.T) {
	for _, c := range []struct {
		in       int
		want     int
		wantFlag bool
		whatItIs string
	}{
		{divergentPriority8597, config.MaxRedundancyGroupNodePriority, true, "above range"},
		{0, config.MinRedundancyGroupNodePriority, true, "below range (0 = unset)"},
		{-5, config.MinRedundancyGroupNodePriority, true, "negative"},
		{255, config.MaxRedundancyGroupNodePriority, true, "255 is the RFC 5798 owner value, out of range here"},
		{1, 1, false, "min boundary"},
		{254, 254, false, "max boundary"},
		{100, 100, false, "ordinary"},
	} {
		got, clamped := config.ClampRedundancyGroupNodePriority(c.in)
		if got != c.want || clamped != c.wantFlag {
			t.Errorf("ClampRedundancyGroupNodePriority(%d) = (%d, %v), want (%d, %v) — %s",
				c.in, got, clamped, c.want, c.wantFlag, c.whatItIs)
		}
	}
}

// TestBothNodesAboveTheWireCeilingStillElectOne_8597 is the cell that
// distinguishes the two halves of the fix, and the reason the upstream clamp is
// the fix rather than the wire saturation.
//
// For the 65700-vs-200 fixture above, EITHER half is sufficient on its own: a
// saturating wire cast advertises 65535, the peer at 200 stands down, and the
// nodes agree. That makes the headline cell above unable to tell which half is
// load-bearing.
//
// This fixture separates them. With both nodes configured ABOVE the uint16
// ceiling, saturation alone collapses both advertisements to 65535 while each
// node still compares its own raw value — 70000 > 65535 and 80000 > 65535 —
// so both elect themselves. Only closing the domain upstream, so the local
// comparison and the wire carry the SAME number, survives it.
//
// This is the general form of the defect: it is not that the wire value is
// wrong, it is that the local decision is made on a value the peer can never
// see.
func TestBothNodesAboveTheWireCeilingStillElectOne_8597(t *testing.T) {
	aPrimary, bPrimary := twoNodeElection(t, map[int]int{0: 70000, 1: 80000})
	if aPrimary && bPrimary {
		t.Fatal("BOTH nodes elected themselves primary with priorities above the uint16 " +
			"wire ceiling — saturating the wire cast is not enough on its own; the " +
			"local comparison must use the value that was advertised (#8597/K17)")
	}
	if !aPrimary && !bPrimary {
		t.Fatal("NEITHER node is primary; the clamp must bound the priorities, not " +
			"disqualify the group")
	}
}

// TestBuildHeartbeatSaturatesAnUnclampedPriority_8597 binds the wire CALL SITE,
// not the helper.
//
// clampWirePriority's own unit cell passes whether or not buildHeartbeat calls
// it — reverting the call site to a bare `uint16(...)` leaves that cell green,
// which is exactly the "bind the wiring, not the function it calls" trap. This
// cell writes LocalPriority directly, simulating the future writer the belt
// exists for (one who bypasses clampNodePriority), and asserts what the packet
// actually carries.
func TestBuildHeartbeatSaturatesAnUnclampedPriority_8597(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(makeRG(0, true, map[int]int{0: 200})))
	drainEvents(m, 1)

	// Bypass clampNodePriority the way a future writer would.
	m.mu.Lock()
	m.groups[0].LocalPriority = divergentPriority8597
	m.mu.Unlock()

	rawDivergent := divergentPriority8597
	pkt := m.buildHeartbeat()
	var found bool
	for _, g := range pkt.Groups {
		if g.GroupID == 0 {
			found = true
			if g.Priority != math.MaxUint16 {
				t.Errorf("buildHeartbeat advertised priority %d for a local %d; want %d "+
					"(saturated). A bare uint16 cast gives %d, which is BELOW a peer at "+
					"%d and inverts the election.",
					g.Priority, divergentPriority8597, uint16(math.MaxUint16),
					uint16(rawDivergent), peerPriority8597)
			}
		}
	}
	if !found {
		t.Fatal("buildHeartbeat emitted no group 0")
	}
}
