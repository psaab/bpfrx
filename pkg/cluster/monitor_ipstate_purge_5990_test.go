package cluster

import (
	"testing"
)

// TestMonitorIPStatePurgedOnRGRemoval_5990 pins the map-lifecycle fix for #5990:
// when an RG is REMOVED from config, the Monitor's per-RG ipState and ipDebts
// (and the ipThresholdState mirror) must be purged, so a same-id RG re-add while
// a monitored target is STILL DOWN re-derives the ip-monitor election debt from
// a fresh probe rather than no-oping against stale bookkeeping.
//
// The manager clears the removed RG's monitorWeights on removal, but the Monitor
// keys ipState by (rgID, address) and ipDebts by rgID. Leaving them behind means
// the next reconcileRGIPDebts after a same-id re-add sees desired==installed by
// its OWN stale ipDebts record and fires no SetMonitorWeight — the re-added RG
// carries a MISSING ip-monitor debt (weight stuck at 255) and can stay primary
// with a dead monitored uplink. Fail-open.
//
// Fail-on-revert: delete the ipState/ipDebts/ipThresholdState purge loops in
// Monitor.UpdateGroups. After re-add the stale ipDebts[1] makes the reconcile
// no-op, so RG 1's weight stays 255 (the ip debt is never re-installed) and the
// final assertions fail RED.
func TestMonitorIPStatePurgedOnRGRemoval_5990(t *testing.T) {
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

		const ipKey = "ip:10.0.0.1"
		ipStateKey := ipMonitorKey{rgID: 1, address: "10.0.0.1"}

		// Healthy target → full weight, no debt.
		mon.poll()
		if w := m.GroupState(1).Weight; w != 255 {
			t.Fatalf("all-reachable weight = %d, want 255", w)
		}

		// Target unreachable → per-target ip debt installed (255-100=155).
		reach["10.0.0.1"] = false
		mon.poll()
		if w := m.GroupState(1).Weight; w != 155 {
			t.Fatalf("weight with ip target down = %d, want 155 (255-100)", w)
		}
		if _, ok := m.monitorWeights[monitorKey{rgID: 1, iface: ipKey}]; !ok {
			t.Fatalf("precondition: monitorWeights missing live ip debt %s", ipKey)
		}
		if _, ok := mon.ipDebts[1]; !ok {
			t.Fatalf("precondition: mon.ipDebts[1] missing installed ip debt")
		}
		if st := mon.ipState[ipStateKey]; st == nil || !st.down {
			t.Fatalf("precondition: mon.ipState[%v] should be dampened-down, got %+v", ipStateKey, st)
		}

		// --- REMOVE RG 1 from config while the target is still down. ---
		// m.monitor is set, so UpdateConfig routes through Monitor.UpdateGroups,
		// which must purge the per-RG ipState/ipDebts/ipThresholdState.
		reach["10.0.0.1"] = false
		m.UpdateConfig(makeConfig())
		drainEvents(m, 4)

		if m.GroupState(1) != nil {
			t.Fatalf("RG 1 should be gone after removal, still present")
		}
		if _, ok := mon.ipDebts[1]; ok {
			t.Fatalf("mon.ipDebts[1] not purged on RG removal (#5990)")
		}
		if _, ok := mon.ipThresholdState[1]; ok {
			t.Fatalf("mon.ipThresholdState[1] not purged on RG removal (#5990)")
		}
		if st, ok := mon.ipState[ipStateKey]; ok {
			t.Fatalf("mon.ipState[%v] not purged on RG removal (#5990), got %+v", ipStateKey, st)
		}
		// The manager-side debt is also gone (removal loop clears monitorWeights).
		if _, ok := m.monitorWeights[monitorKey{rgID: 1, iface: ipKey}]; ok {
			t.Fatalf("monitorWeights[rg1,%s] should be cleared on RG removal", ipKey)
		}

		// --- RE-ADD the SAME RG id while the target is STILL DOWN. ---
		// A fresh RedundancyGroupState starts at weight 255 with no debt; the
		// next poll must RE-DERIVE the ip debt from a clean per-RG slate.
		m.UpdateConfig(makeConfig(independentIPRG(1, 100, "10.0.0.1")))
		drainEvents(m, 4)
		if w := m.GroupState(1).Weight; w != 255 {
			t.Fatalf("re-added RG weight before poll = %d, want 255 (fresh state)", w)
		}

		mon.poll()

		// With the purge, the fresh ipState dampens to down and the reconcile
		// installs the debt again. Without the purge, stale ipDebts[1] makes the
		// reconcile no-op and the weight stays 255 (fail-open) — RED.
		if w := m.GroupState(1).Weight; w != 155 {
			t.Fatalf("weight after same-id re-add + poll = %d, want 155 "+
				"(ip debt must be RE-DERIVED from a clean per-RG monitor state; "+
				"stale ipDebts must not no-op the install — #5990)", w)
		}
		if _, ok := m.monitorWeights[monitorKey{rgID: 1, iface: ipKey}]; !ok {
			t.Fatalf("monitorWeights missing re-derived ip debt %s after same-id re-add", ipKey)
		}
		if st := m.GroupState(1); !monitorFailsHas(st.MonitorFails, ipKey) {
			t.Fatalf("MonitorFails = %v, want to contain re-derived %s", st.MonitorFails, ipKey)
		}
	})

	t.Run("aggregate_threshold_ip_debt", func(t *testing.T) {
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

		ipStateKey := ipMonitorKey{rgID: 1, address: "10.0.0.9"}

		mon.poll()
		if w := m.GroupState(1).Weight; w != 255 {
			t.Fatalf("all-reachable weight = %d, want 255", w)
		}

		// Target down: cumulative 100 >= threshold 100 → aggregate debt (255-100=155).
		reach["10.0.0.9"] = false
		mon.poll()
		if w := m.GroupState(1).Weight; w != 155 {
			t.Fatalf("weight with aggregate ip debt = %d, want 155", w)
		}
		if !mon.ipThresholdState[1] {
			t.Fatalf("precondition: mon.ipThresholdState[1] should be true (aggregate installed)")
		}

		// --- REMOVE RG 1 while the target is still down. ---
		m.UpdateConfig(makeConfig())
		drainEvents(m, 4)
		if _, ok := mon.ipDebts[1]; ok {
			t.Fatalf("mon.ipDebts[1] not purged on RG removal (aggregate, #5990)")
		}
		if _, ok := mon.ipThresholdState[1]; ok {
			t.Fatalf("mon.ipThresholdState[1] not purged on RG removal (aggregate, #5990)")
		}
		if _, ok := mon.ipState[ipStateKey]; ok {
			t.Fatalf("mon.ipState[%v] not purged on RG removal (aggregate, #5990)", ipStateKey)
		}

		// --- RE-ADD same id, target still down → aggregate debt re-derived. ---
		m.UpdateConfig(makeConfig(thresholdRG(1, 100, 100, 100, "10.0.0.9")))
		drainEvents(m, 4)
		mon.poll()
		if w := m.GroupState(1).Weight; w != 155 {
			t.Fatalf("weight after same-id re-add + poll = %d, want 155 "+
				"(aggregate ip debt must be RE-DERIVED — #5990)", w)
		}
		if _, ok := m.monitorWeights[monitorKey{rgID: 1, iface: ipAggregateMonitorName}]; !ok {
			t.Fatalf("monitorWeights missing re-derived aggregate ip debt after same-id re-add")
		}
	})
}
