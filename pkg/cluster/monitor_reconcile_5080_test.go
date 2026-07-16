package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestMonitorReconcile_MissingLocalLinkDemotes_5080 pins the FAIL-OPEN half of
// #5080: a configured LOCAL member link that is absent (cold boot, or a
// delete/recreate between polls) must count as DOWN and demote the RG's
// effective weight — NOT be silently skipped with only a warning. Skipping
// fails open: an already-primary node keeps effective weight 255 and stays
// primary while its data link is missing, blackholing traffic.
//
// Fail-on-revert: restore the `slog.Warn(...) + continue` branch in
// pollInterfaceMonitors (no down-state published) and the missing link leaves
// the weight at 255 / the node primary, failing this test.
func TestMonitorReconcile_MissingLocalLinkDemotes_5080(t *testing.T) {
	m := NewManager(0, 1) // node 0
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 255},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 4)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	// Link present and up: full weight, node primary.
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("weight with link up = %d, want 255", w)
	}
	if !m.IsLocalPrimary(0) {
		t.Fatalf("node should be primary with a healthy local monitor")
	}

	// Local member link vanishes (LinkByName now errors). The absence must be
	// treated as DOWN and demote the RG.
	delete(nlh.links, "trust0")
	mon.poll()

	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("weight after local link missing = %d, want 0 (missing local "+
			"link must count as down and demote — fail-open regression)", w)
	}
	if m.IsLocalPrimary(0) {
		t.Fatalf("node must not stay primary while its local data link is missing")
	}
	// The manager must actually record the failed monitor debt.
	if fails := m.GroupStates()[0].MonitorFails; len(fails) != 1 || fails[0] != "trust0" {
		t.Fatalf("MonitorFails = %v, want [trust0] for the missing local link", fails)
	}
}

// TestMonitorReconcile_StaleDebtClearedOnMonitorRemoval_5080 pins the
// STALE-DEBT half of #5080: after a monitor's weight debt is installed, an
// operator removing that monitor must clear the stale ifaceState / MonitorFails
// / monitorWeights and let the RG's effective weight recover — otherwise a
// healthy node is stranded secondary forever because UpdateConfig only swapped
// the desired monitor slice.
//
// Fail-on-revert: remove the reconcileMonitorDebtsLocked call from
// UpdateConfig (and the UpdateGroups ifaceState clear) and the removed
// monitor's debt persists, leaving weight 0 / MonitorFails=[trust0], failing
// this test.
func TestMonitorReconcile_StaleDebtClearedOnMonitorRemoval_5080(t *testing.T) {
	m := NewManager(0, 1) // node 0
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 255},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 4)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", false) // present but carrier-down

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)
	// Register the monitor so UpdateConfig drives its UpdateGroups reconcile.
	m.monitor = mon

	// The failed monitor installs a full-weight debt: weight 0, secondary.
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("weight with failed monitor = %d, want 0", w)
	}
	if fails := m.GroupStates()[0].MonitorFails; len(fails) != 1 {
		t.Fatalf("precondition MonitorFails = %v, want [trust0]", fails)
	}
	if _, ok := mon.ifaceState[monitorKey{rgID: 0, iface: "trust0"}]; !ok {
		t.Fatalf("precondition: monitor ifaceState should hold trust0 dampening state")
	}

	// Operator removes the monitor entirely (RG kept, no interface monitors).
	cfg2 := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg2)
	drainEvents(m, 4)

	// The stale debt must be gone and the weight recovered so the node can be
	// primary again.
	st := m.GroupStates()[0]
	if st.Weight != 255 {
		t.Fatalf("weight after monitor removal = %d, want 255 (stale debt must be "+
			"cleared so a healthy node recovers)", st.Weight)
	}
	if len(st.MonitorFails) != 0 {
		t.Fatalf("MonitorFails after removal = %v, want empty (stale debt)", st.MonitorFails)
	}
	if _, ok := m.monitorWeights[monitorKey{rgID: 0, iface: "trust0"}]; ok {
		t.Fatalf("monitorWeights still holds removed monitor trust0 (stale manager debt)")
	}
	if _, ok := mon.ifaceState[monitorKey{rgID: 0, iface: "trust0"}]; ok {
		t.Fatalf("monitor ifaceState still holds removed monitor trust0 (stale dampening state)")
	}
	if !m.IsLocalPrimary(0) {
		t.Fatalf("node should recover to primary after the failed monitor is removed")
	}
}

// TestMonitorReconcile_ChangedMonitorReapplied_5080 covers the CHANGE arm of
// the stale-debt half: (a) changing the monitored interface must clear the old
// interface's stale debt, and (b) changing a still-failed monitor's weight must
// re-derive the debt to the new weight (the interface stays down, so no
// dampening transition would re-fire SetMonitorWeight on its own).
//
// Fail-on-revert: remove reconcileMonitorDebtsLocked and the interface-change
// arm strands the old debt (weight stuck at 155) while the weight-change arm
// keeps deducting the old weight (100 instead of 200).
func TestMonitorReconcile_ChangedMonitorReapplied_5080(t *testing.T) {
	// --- (a) interface changed: old debt cleared ---
	t.Run("interface_changed_clears_old_debt", func(t *testing.T) {
		m := NewManager(0, 1)
		cfg := makeConfig(
			makeRG(0, false, map[int]int{0: 200},
				&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
			),
		)
		m.UpdateConfig(cfg)
		drainEvents(m, 4)

		nlh := newMockNlHandle()
		nlh.setLink("trust0", false)
		nlh.setLink("untrust0", true)

		mon := NewMonitor(m, cfg.RedundancyGroups)
		mon.nlHandle = nlh
		setNoDampening(mon)
		m.monitor = mon

		mon.poll()
		if w := m.GroupStates()[0].Weight; w != 155 {
			t.Fatalf("weight with trust0 down = %d, want 155 (255-100)", w)
		}

		// Operator changes the monitored interface trust0 -> untrust0 (which is
		// healthy). The stale trust0 debt must clear; untrust0 is up.
		cfg2 := makeConfig(
			makeRG(0, false, map[int]int{0: 200},
				&config.InterfaceMonitor{Interface: "untrust0", Weight: 100},
			),
		)
		m.UpdateConfig(cfg2)
		drainEvents(m, 4)
		mon.poll() // evaluate the new monitor (untrust0 up)

		st := m.GroupStates()[0]
		if st.Weight != 255 {
			t.Fatalf("weight after interface change = %d, want 255 (old trust0 debt "+
				"must clear, untrust0 is up)", st.Weight)
		}
		for _, f := range st.MonitorFails {
			if f == "trust0" {
				t.Fatalf("MonitorFails still contains removed interface trust0: %v", st.MonitorFails)
			}
		}
	})

	// --- (b) weight changed on a still-failed monitor: debt re-derived ---
	t.Run("weight_changed_reapplied", func(t *testing.T) {
		m := NewManager(0, 1)
		cfg := makeConfig(
			makeRG(0, false, map[int]int{0: 200},
				&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
			),
		)
		m.UpdateConfig(cfg)
		drainEvents(m, 4)

		nlh := newMockNlHandle()
		nlh.setLink("trust0", false)

		mon := NewMonitor(m, cfg.RedundancyGroups)
		mon.nlHandle = nlh
		setNoDampening(mon)
		m.monitor = mon

		mon.poll()
		if w := m.GroupStates()[0].Weight; w != 155 {
			t.Fatalf("weight with trust0 down @100 = %d, want 155", w)
		}

		// Operator raises the monitor weight to 200 while the interface stays
		// down. No dampening transition fires (still down), so the reconcile
		// must re-derive the debt to the new weight.
		cfg2 := makeConfig(
			makeRG(0, false, map[int]int{0: 200},
				&config.InterfaceMonitor{Interface: "trust0", Weight: 200},
			),
		)
		m.UpdateConfig(cfg2)
		drainEvents(m, 4)

		if w := m.GroupStates()[0].Weight; w != 55 {
			t.Fatalf("weight after monitor weight change to 200 = %d, want 55 "+
				"(255-200; changed weight must be re-derived)", w)
		}
		if got := m.monitorWeights[monitorKey{rgID: 0, iface: "trust0"}]; got != 200 {
			t.Fatalf("monitorWeights[trust0] = %d, want 200 (reapplied)", got)
		}
	})
}
