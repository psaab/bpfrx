package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// independentIPRG builds an RG that IP-monitors a single address at the given
// weight in INDEPENDENT mode (no global-threshold), so an unreachable target
// installs a per-target "ip:<addr>" debt via reconcileRGIPDebts.
func independentIPRG(id, weight int, addr string) *config.RedundancyGroup {
	return &config.RedundancyGroup{
		ID:             id,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			Targets: []*config.IPMonitorTarget{{Address: addr, Weight: weight}},
		},
	}
}

// TestMonitorReconcile_IPDebtPreservedOnConfigChange_5080 pins the MAJOR fold
// for #5080: m.monitorWeights + rg.MonitorFails are a SHARED structure that also
// holds IP-MONITORING debts (installed by SetMonitorWeight from the ip-monitor
// path under "ip:<addr>" and the aggregate ipAggregateMonitorName). The
// interface-monitor reconcile (reconcileMonitorDebtsLocked) builds its `desired`
// set from InterfaceMonitors ONLY, so an ip debt always looks "no longer
// desired". Deleting it on any UpdateConfig would wipe a LIVE ip-monitoring debt
// and recompute the RG weight WITHOUT it — and it does NOT self-heal (the
// Monitor's ipDebts still records the debt installed, so the next
// reconcileRGIPDebts poll sees desired==installed and no-ops). A node with a
// dead monitored uplink would then jump back to weight 255 and could win
// election → blackhole. Fail-open — exactly the class this PR set out to fix.
//
// Both naming conventions are exercised: the per-target "ip:<addr>" form
// (independent mode) and the aggregate "ip-monitoring" form (global-threshold
// mode).
//
// Fail-on-revert: remove the isIPMonitorName skip in reconcileMonitorDebtsLocked
// and the unrelated config change wipes the ip debt (weight jumps 155→255, the
// ip key vanishes from monitorWeights and MonitorFails), failing this test.
func TestMonitorReconcile_IPDebtPreservedOnConfigChange_5080(t *testing.T) {
	// --- per-target "ip:<addr>" debt (independent mode) ---
	t.Run("per_target_ip_debt", func(t *testing.T) {
		m := NewManager(0, 1)
		cfg := makeConfig(independentIPRG(1, 100, "10.0.0.1"))
		m.UpdateConfig(cfg)
		drainEvents(m, 4)

		reach := map[string]bool{"10.0.0.1": true}
		mon := NewMonitor(m, cfg.RedundancyGroups)
		injectFakeNl(mon)
		setNoDampening(mon)
		mon.probeFn = reachProbeFn(reach)
		m.monitor = mon

		// Healthy target: full weight.
		mon.poll()
		if w := m.GroupState(1).Weight; w != 255 {
			t.Fatalf("all-reachable weight = %d, want 255", w)
		}

		// Target unreachable → per-target ip debt installed (255-100=155).
		reach["10.0.0.1"] = false
		mon.poll()
		const ipKey = "ip:10.0.0.1"
		if w := m.GroupState(1).Weight; w != 155 {
			t.Fatalf("weight with ip target down = %d, want 155 (255-100)", w)
		}
		if _, ok := m.monitorWeights[monitorKey{rgID: 1, iface: ipKey}]; !ok {
			t.Fatalf("precondition: monitorWeights missing live ip debt %s", ipKey)
		}

		// Operator commits an UNRELATED change: add an interface monitor on a
		// DIFFERENT RG. UpdateConfig → reconcileMonitorDebtsLocked must NOT touch
		// the live ip-monitoring debt on RG 1.
		cfg2 := makeConfig(
			independentIPRG(1, 100, "10.0.0.1"),
			makeRG(0, false, map[int]int{0: 200},
				&config.InterfaceMonitor{Interface: "ctrl0", Weight: 128},
			),
		)
		m.UpdateConfig(cfg2)
		drainEvents(m, 4)

		st := m.GroupState(1)
		if st.Weight != 155 {
			t.Fatalf("weight after unrelated config change = %d, want 155 "+
				"(live ip-monitoring debt must be preserved; reconcileMonitorDebtsLocked "+
				"must not wipe ip debt — fail-open regression #5080)", st.Weight)
		}
		if _, ok := m.monitorWeights[monitorKey{rgID: 1, iface: ipKey}]; !ok {
			t.Fatalf("monitorWeights lost live ip debt %s after unrelated config change", ipKey)
		}
		if !monitorFailsHas(st.MonitorFails, ipKey) {
			t.Fatalf("MonitorFails = %v, want to still contain %s", st.MonitorFails, ipKey)
		}
	})

	// --- aggregate "ip-monitoring" debt (global-threshold mode) ---
	t.Run("aggregate_ip_debt", func(t *testing.T) {
		m := NewManager(0, 1)
		// global-threshold 100, global-weight 100, one target weight 100.
		cfg := makeConfig(thresholdRG(1, 100, 100, 100, "10.0.0.9"))
		m.UpdateConfig(cfg)
		drainEvents(m, 4)

		reach := map[string]bool{"10.0.0.9": true}
		mon := NewMonitor(m, cfg.RedundancyGroups)
		injectFakeNl(mon)
		setNoDampening(mon)
		mon.probeFn = reachProbeFn(reach)
		m.monitor = mon

		mon.poll()
		if w := m.GroupState(1).Weight; w != 255 {
			t.Fatalf("all-reachable weight = %d, want 255", w)
		}

		// Target down: cumulative 100 >= threshold 100 → aggregate debt (255-100=155).
		reach["10.0.0.9"] = false
		mon.poll()
		if w := m.GroupState(1).Weight; w != 155 {
			t.Fatalf("weight with aggregate ip debt = %d, want 155 (255 - global-weight 100)", w)
		}
		if _, ok := m.monitorWeights[monitorKey{rgID: 1, iface: ipAggregateMonitorName}]; !ok {
			t.Fatalf("precondition: monitorWeights missing aggregate ip debt %q", ipAggregateMonitorName)
		}

		// Unrelated config change on a different RG.
		cfg2 := makeConfig(
			thresholdRG(1, 100, 100, 100, "10.0.0.9"),
			makeRG(0, false, map[int]int{0: 200},
				&config.InterfaceMonitor{Interface: "ctrl0", Weight: 128},
			),
		)
		m.UpdateConfig(cfg2)
		drainEvents(m, 4)

		st := m.GroupState(1)
		if st.Weight != 155 {
			t.Fatalf("weight after unrelated config change = %d, want 155 "+
				"(aggregate ip-monitoring debt must be preserved — fail-open regression #5080)", st.Weight)
		}
		if _, ok := m.monitorWeights[monitorKey{rgID: 1, iface: ipAggregateMonitorName}]; !ok {
			t.Fatalf("monitorWeights lost aggregate ip debt after unrelated config change")
		}
		if !monitorFailsHas(st.MonitorFails, ipAggregateMonitorName) {
			t.Fatalf("MonitorFails = %v, want to still contain %q", st.MonitorFails, ipAggregateMonitorName)
		}
	})
}

func monitorFailsHas(fails []string, want string) bool {
	for _, f := range fails {
		if f == want {
			return true
		}
	}
	return false
}
