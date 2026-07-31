package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6549: a redundancy group's LOCAL weight and the weight it ADVERTISES in the
// heartbeat must never disagree.
//
// The local election reads rg.Weight as a wide int (EffectivePriority =
// priority * weight / 255) while buildHeartbeat marshals it through a single
// byte (HeartbeatGroup.Weight is uint8). Before the fix, recalcWeight computed
// `rg.Weight = 255 - totalLost` with only a `< 0` floor, so a NEGATIVE monitor
// debt — an out-of-range `interface-monitor <if> weight -100`, which the
// tolerant load / peer-sync compile path only warns about (#1960) — pushed
// rg.Weight to 355 locally while the peer received uint8(355) == 99. The two
// nodes then elected from different views of identical state and both took
// primary: duplicate VIP and duplicate RETH virtual MAC on the LAN.
//
// These tests drive the REAL marshal (MarshalHeartbeat / UnmarshalHeartbeat on
// the packet buildHeartbeat actually produces), not a re-implementation of it.

// localVsAdvertisedWeight returns the manager's local weight for rgID and the
// weight a peer decodes from a real heartbeat marshal/unmarshal round-trip.
func localVsAdvertisedWeight(t *testing.T, m *Manager, rgID int) (local, advertised int) {
	t.Helper()

	states := m.GroupStates()
	found := false
	for _, gs := range states {
		if gs.GroupID == rgID {
			local = gs.Weight
			found = true
		}
	}
	if !found {
		t.Fatalf("redundancy group %d not present in GroupStates()", rgID)
	}

	wire := MarshalHeartbeat(m.buildHeartbeat())
	pkt, err := UnmarshalHeartbeat(wire)
	if err != nil {
		t.Fatalf("UnmarshalHeartbeat: %v", err)
	}
	for _, g := range pkt.Groups {
		if int(g.GroupID) == rgID {
			return local, int(g.Weight)
		}
	}
	t.Fatalf("redundancy group %d missing from the marshalled heartbeat", rgID)
	return 0, 0
}

// TestRGWeight_LocalAndAdvertisedCannotDiverge_6549 pins the core invariant
// across the whole debt domain, including debts no legal config can produce.
//
// Fail-on-revert: restore `rg.Weight = 255 - totalLost; if rg.Weight < 0 {
// rg.Weight = 0 }` in recalcWeight (i.e. drop the ceiling from
// rgWeightFromDebt) and every negative-debt row fails with local 355 vs
// advertised 99.
func TestRGWeight_LocalAndAdvertisedCannotDiverge_6549(t *testing.T) {
	// Debts fed straight into SetMonitorWeight: this is the hostile-input leg,
	// proving the weight DOMAIN is closed regardless of which caller supplies
	// the debt (interface monitor, ip-monitoring target, or a future caller).
	debts := []int{-100000, -1000, -256, -255, -100, -1, 0, 1, 128, 254, 255, 256, 1000, 100000}

	for _, debt := range debts {
		m := NewManager(0, 1)
		m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 100},
			&config.InterfaceMonitor{Interface: "ge-0/0/0", Weight: 255})))
		drainEvents(m, 4)

		m.SetMonitorWeight(0, "ge-0/0/0", true, debt)
		drainEvents(m, 4)

		local, advertised := localVsAdvertisedWeight(t, m, 0)
		if local != advertised {
			t.Errorf("debt %d: local weight %d but advertised %d — the two nodes "+
				"would compute different effective priorities from identical state",
				debt, local, advertised)
		}
		if local < 0 || local > 255 {
			t.Errorf("debt %d: local weight %d escapes the [0,255] heartbeat weight domain",
				debt, local)
		}
	}
}

// TestRGWeight_ConfiguredMonitorWeightCannotDiverge_6549 drives the same
// invariant through the CONFIG path an out-of-range weight actually travels on
// a tolerant load / peer-sync: the weight is installed as debt, then a config
// apply re-derives it via reconcileMonitorDebtsLocked.
//
// Fail-on-revert (either half): drop the ceiling from rgWeightFromDebt, or drop
// the config.ClampInterfaceMonitorWeight call in reconcileMonitorDebtsLocked,
// and the weight -100 row diverges (local 355, advertised 99).
func TestRGWeight_ConfiguredMonitorWeightCannotDiverge_6549(t *testing.T) {
	tests := []struct {
		name       string
		configured int
		wantWeight int // expected effective rg.Weight with the monitor DOWN
	}{
		// Over-reach guard: every legal weight must still behave exactly as
		// before — 255 minus the configured debt, advertised identically.
		{"legal-zero", 0, 255},
		{"legal-one", 1, 254},
		{"legal-half", 128, 127},
		{"legal-max", 255, 0},
		// Out-of-range: clamped into the domain, never diverging.
		{"negative-small", -1, 255},
		{"negative-large", -100, 255},
		{"over-max", 256, 0},
		{"over-max-large", 100000, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const iface = "ge-0/0/0"

			m := NewManager(0, 1)
			// Seed with a legal weight so the monitor can be marked down
			// through the normal path first.
			m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 100},
				&config.InterfaceMonitor{Interface: iface, Weight: 200})))
			drainEvents(m, 4)
			m.SetMonitorWeight(0, iface, true, 200)
			drainEvents(m, 4)

			// Now apply the config carrying the weight under test. The monitor
			// is still down, so reconcileMonitorDebtsLocked re-derives the debt
			// from the new configured weight (the "changed weight for a monitor
			// that is still failed" branch).
			m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 100},
				&config.InterfaceMonitor{Interface: iface, Weight: tt.configured})))
			drainEvents(m, 4)

			local, advertised := localVsAdvertisedWeight(t, m, 0)
			if local != advertised {
				t.Errorf("configured weight %d: local %d but advertised %d",
					tt.configured, local, advertised)
			}
			if local != tt.wantWeight {
				t.Errorf("configured weight %d: rg.Weight = %d, want %d",
					tt.configured, local, tt.wantWeight)
			}
		})
	}
}

// TestReconcileMonitorDebts_OutOfRangeWeightCannotCancelARealFailure_6549 is
// the config-apply twin of the poll-path test below: reconcileMonitorDebtsLocked
// re-derives the debt of a monitor that is STILL failed when its configured
// weight changes, so a config apply is a second way an out-of-range weight
// enters the debt set — and a negative one there likewise credits weight back
// and cancels a sibling monitor's real failure.
//
// Fail-on-revert: drop the config.ClampInterfaceMonitorWeight call in
// reconcileMonitorDebtsLocked and the reconciled debt becomes 255 + (-100) =
// 155, restoring the group to weight 100 while both monitored links are down.
func TestReconcileMonitorDebts_OutOfRangeWeightCannotCancelARealFailure_6549(t *testing.T) {
	const ifA, ifB = "trust0", "trust1"

	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200},
		&config.InterfaceMonitor{Interface: ifA, Weight: 255},
		&config.InterfaceMonitor{Interface: ifB, Weight: 200},
	)))
	drainEvents(m, 4)

	// Both monitors fail with their legal weights.
	m.SetMonitorWeight(0, ifA, true, 255)
	m.SetMonitorWeight(0, ifB, true, 200)
	drainEvents(m, 4)
	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("weight with both monitors failed = %d, want 0", w)
	}

	// A config apply changes the still-failed ifB's weight out of range. The
	// reconcile re-derives ifB's debt from it.
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200},
		&config.InterfaceMonitor{Interface: ifA, Weight: 255},
		&config.InterfaceMonitor{Interface: ifB, Weight: -100},
	)))
	drainEvents(m, 4)

	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("weight after reconciling an out-of-range monitor weight = %d, "+
			"want 0 — the negative weight credited debt back and cancelled %s's "+
			"real failure (fail-open)", w, ifA)
	}
	local, advertised := localVsAdvertisedWeight(t, m, 0)
	if local != advertised {
		t.Fatalf("local weight %d but advertised %d", local, advertised)
	}
}

// TestMonitorPoll_OutOfRangeWeightCannotCancelARealFailure_6549 pins the
// second consequence of an unbounded interface-monitor weight, on the REAL
// poll path (mock netlink -> pollInterfaceMonitors -> SetMonitorWeight): a
// NEGATIVE weight is negative DEBT, so it cancels the demotion a genuinely
// failed sibling monitor just applied. Two dead links then leave the node at
// weight 100 and still PRIMARY, blackholing traffic — a fail-open that the
// rg.Weight domain clamp alone does not catch, because the sum stays inside
// [0,255].
//
// Fail-on-revert: drop the config.ClampInterfaceMonitorWeight call in
// pollInterfaceMonitors and the debt becomes 255 + (-100) = 155, leaving
// weight 100 and the node primary.
func TestMonitorPoll_OutOfRangeWeightCannotCancelARealFailure_6549(t *testing.T) {
	m := NewManager(0, 1) // node 0
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200},
		&config.InterfaceMonitor{Interface: "trust0", Weight: 255},
		&config.InterfaceMonitor{Interface: "trust1", Weight: -100},
	))
	m.UpdateConfig(cfg)
	drainEvents(m, 4)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)
	nlh.setLink("trust1", true)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("weight with both links up = %d, want 255", w)
	}

	// Both monitored links die. The full-weight monitor alone must resign the
	// group; the out-of-range one must not credit any weight back.
	nlh.setLink("trust0", false)
	nlh.setLink("trust1", false)
	mon.poll()

	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("weight with both monitored links down = %d, want 0 — a negative "+
			"interface-monitor weight credited debt back and cancelled a real "+
			"link failure (fail-open)", w)
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("node must not stay primary with both monitored links down")
	}
}

// TestMonitorPoll_LocalAndAdvertisedMonitorWeightAgree_6549 pins the per-MONITOR
// half of the divergence: HeartbeatMonitor.Weight is also a single byte, so what
// this node reports locally about a monitor and what it advertises about that
// same monitor must agree.
//
// Fail-on-revert: drop the config.ClampInterfaceMonitorWeight call in
// pollInterfaceMonitors and the local status carries -100 while the wire carries
// 0 (or, without clampWireWeight too, 156).
func TestMonitorPoll_LocalAndAdvertisedMonitorWeightAgree_6549(t *testing.T) {
	for _, configured := range []int{-100, -1, 0, 1, 128, 255, 256, 100000} {
		m := NewManager(0, 1)
		cfg := makeConfig(makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: configured},
		))
		m.UpdateConfig(cfg)
		drainEvents(m, 4)

		nlh := newMockNlHandle()
		nlh.setLink("trust0", true)
		mon := NewMonitor(m, cfg.RedundancyGroups)
		mon.nlHandle = nlh
		setNoDampening(mon)
		// buildHeartbeat sources its Monitors section from m.monitor's local
		// statuses; Start() is the production setter, which a unit test cannot
		// run (it spawns the poll loop). Same-package assignment under m.mu.
		m.mu.Lock()
		m.monitor = mon
		m.mu.Unlock()
		mon.poll()

		local := mon.LocalInterfaceStatuses()
		if len(local) != 1 {
			t.Fatalf("configured %d: expected 1 local monitor status, got %d",
				configured, len(local))
		}

		pkt, err := UnmarshalHeartbeat(MarshalHeartbeat(m.buildHeartbeat()))
		if err != nil {
			t.Fatalf("configured %d: UnmarshalHeartbeat: %v", configured, err)
		}
		if len(pkt.Monitors) != 1 {
			t.Fatalf("configured %d: expected 1 advertised monitor, got %d",
				configured, len(pkt.Monitors))
		}
		if local[0].Weight != int(pkt.Monitors[0].Weight) {
			t.Errorf("configured weight %d: local monitor status weight %d but "+
				"advertised %d", configured, local[0].Weight, pkt.Monitors[0].Weight)
		}
	}
}

// TestRGWeightFromDebt_ClosesTheDomain_6549 is the unit-level statement of the
// same rule, so a reviewer can see the boundary without running a cluster.
func TestRGWeightFromDebt_ClosesTheDomain_6549(t *testing.T) {
	tests := []struct {
		debt, want int
	}{
		{-100000, 255}, {-256, 255}, {-1, 255}, // negative debt: ceiling holds
		{0, 255}, {1, 254}, {255, 0}, // in-domain: unchanged arithmetic
		{256, 0}, {100000, 0}, // over-large debt: floor holds
	}
	for _, tt := range tests {
		if got := rgWeightFromDebt(tt.debt); got != tt.want {
			t.Errorf("rgWeightFromDebt(%d) = %d, want %d", tt.debt, got, tt.want)
		}
	}
}

// TestClampWireWeight_SaturatesNotTruncates_6549 pins the marshal-boundary
// belt: `uint8(355)` aliases to 99, which is what made the local and advertised
// views disagree. Saturation keeps a stray value bounded and monotonic.
func TestClampWireWeight_SaturatesNotTruncates_6549(t *testing.T) {
	tests := []struct {
		in   int
		want uint8
	}{
		{-1, 0}, {0, 0}, {1, 1}, {128, 128}, {255, 255},
		{256, 255}, {355, 255}, {100000, 255},
	}
	for _, tt := range tests {
		if got := clampWireWeight(tt.in); got != tt.want {
			t.Errorf("clampWireWeight(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
