package cluster

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// thresholdRG builds an RG that IP-monitors the given addresses (each at the
// given per-target weight) under a cumulative global-threshold + global-weight.
func thresholdRG(id, globalWeight, globalThreshold, perTargetWeight int, addrs ...string) *config.RedundancyGroup {
	targets := make([]*config.IPMonitorTarget, len(addrs))
	for i, a := range addrs {
		targets[i] = &config.IPMonitorTarget{Address: a, Weight: perTargetWeight}
	}
	return &config.RedundancyGroup{
		ID:             id,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight:    globalWeight,
			GlobalThreshold: globalThreshold,
			Targets:         targets,
		},
	}
}

// reachSet is a per-address reachability probe seam shared by these tests.
func reachProbeFn(reach map[string]bool) func(context.Context, string) (bool, bool) {
	return func(_ context.Context, addr string) (bool, bool) {
		return reach[addr], true
	}
}

// TestMonitor_GlobalThresholdGatesFailover_5271 is the issue's exact scenario:
// with global-threshold=200 and global-weight=100, one failing weight-50 target
// (cumulative 50 < 200) must NOT deduct any RG election weight, and only once
// enough targets fail to reach 200 does the single global-weight deduction
// apply.
//
// Fail-on-revert: remove the applyRGIPMonitorThreshold gate (or restore the old
// per-target SetMonitorWeight for the threshold case) and the first failing
// weight-50 target immediately drops the RG weight from 255, failing the
// "stays 255 below threshold" assertion.
func TestMonitor_GlobalThresholdGatesFailover_5271(t *testing.T) {
	rg := thresholdRG(0, 100, 200, 50, "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4")
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reach := map[string]bool{"10.0.0.1": true, "10.0.0.2": true, "10.0.0.3": true, "10.0.0.4": true}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)

	// All reachable → full health.
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("all-reachable weight = %d, want 255", w)
	}

	// One weight-50 target fails: cumulative 50 < threshold 200 → no debt.
	reach["10.0.0.1"] = false
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("one failing target (cumulative 50 < 200) weight = %d, want 255 "+
			"(sub-threshold failure must NOT deduct RG weight)", w)
	}

	// Second and third targets fail: cumulative 150 < 200 → still no debt.
	reach["10.0.0.2"] = false
	reach["10.0.0.3"] = false
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("three failing targets (cumulative 150 < 200) weight = %d, want 255", w)
	}

	// Fourth target fails: cumulative 200 >= 200 → deduct global-weight 100.
	reach["10.0.0.4"] = false
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 155 {
		t.Fatalf("cumulative 200 >= threshold weight = %d, want 155 (255 - global-weight 100)", w)
	}

	// One target recovers: cumulative 150 < 200 → clear the debt.
	reach["10.0.0.1"] = true
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("recovery below threshold weight = %d, want 255 (global-weight cleared)", w)
	}
}

// TestMonitor_GlobalThresholdUnsetIsIndependent_5271 pins that with NO
// global-threshold configured, behavior is byte-identical to the historical
// per-target-independent debt: each failing target deducts its own weight.
func TestMonitor_GlobalThresholdUnsetIsIndependent_5271(t *testing.T) {
	// global-threshold 0 (unset), two targets of weight 40 and 30.
	rg := &config.RedundancyGroup{
		ID:             0,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight: 100,
			Targets: []*config.IPMonitorTarget{
				{Address: "10.0.0.1", Weight: 40},
				{Address: "10.0.0.2", Weight: 30},
			},
		},
	}
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reach := map[string]bool{"10.0.0.1": true, "10.0.0.2": true}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("all-reachable weight = %d, want 255", w)
	}

	// One target fails → its own weight (40) deducted immediately (independent).
	reach["10.0.0.1"] = false
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 215 {
		t.Fatalf("independent-mode one failure weight = %d, want 215 (255-40)", w)
	}

	// Both fail → 40+30 deducted.
	reach["10.0.0.2"] = false
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 185 {
		t.Fatalf("independent-mode both failing weight = %d, want 185 (255-40-30)", w)
	}
}

// TestMonitor_GlobalThresholdClearedOnDisable_5271 pins Finding 1: disabling
// global-threshold on a KEPT group must release a previously installed
// aggregate global-weight debt. UpdateConfig clears monitorWeights only for
// REMOVED groups and UpdateGroups just swaps the slice, so without the
// clear-on-disable path the deduction is stranded — the RG stays stuck at a
// wrong weight that can wrongly suppress or force a failover.
//
// Fail-on-revert: restore the bare early-return in applyRGIPMonitorThreshold
// and the crossed-then-disabled RG stays at 155 instead of returning to 255.
func TestMonitor_GlobalThresholdClearedOnDisable_5271(t *testing.T) {
	rg := thresholdRG(0, 100, 200, 100, "10.0.0.1", "10.0.0.2")
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reach := map[string]bool{"10.0.0.1": true, "10.0.0.2": true}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)

	// Cross the threshold: both weight-100 targets fail → cumulative 200 >= 200
	// → deduct global-weight 100.
	reach["10.0.0.1"] = false
	reach["10.0.0.2"] = false
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 155 {
		t.Fatalf("crossed weight = %d, want 155 (255 - global-weight 100)", w)
	}
	if !mon.ipThresholdState[0] {
		t.Fatalf("ipThresholdState[0] = false, want true after crossing")
	}

	// Live reconfigure: SAME group kept, global-threshold disabled (0), targets
	// now healthy. UpdateConfig keeps the group and does NOT clear the stuck
	// aggregate debt.
	rgDisabled := thresholdRG(0, 100, 0, 100, "10.0.0.1", "10.0.0.2")
	cfg2 := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rgDisabled}}
	m.UpdateConfig(cfg2)
	mon.UpdateGroups(cfg2.RedundancyGroups)
	reach["10.0.0.1"] = true
	reach["10.0.0.2"] = true

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("after disabling global-threshold (group kept) weight = %d, want 255 "+
			"(stranded aggregate global-weight debt must be cleared)", w)
	}
	if mon.ipThresholdState[0] {
		t.Errorf("ipThresholdState[0] = true after disable, want false")
	}
}

// TestMonitor_GlobalThresholdClearedOnIPMonitoringRemoved_5271 is the harder
// Finding 1 variant: ip-monitoring is removed ENTIRELY (rg.IPMonitoring == nil)
// while the group is kept, so global-weight is no longer available to name the
// debt. The clear path must still release it via the fixed aggregate monitor
// name.
func TestMonitor_GlobalThresholdClearedOnIPMonitoringRemoved_5271(t *testing.T) {
	rg := thresholdRG(0, 100, 200, 100, "10.0.0.1", "10.0.0.2")
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reach := map[string]bool{"10.0.0.1": false, "10.0.0.2": false}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 155 {
		t.Fatalf("crossed weight = %d, want 155", w)
	}

	// Reconfigure: group kept but ip-monitoring dropped entirely.
	rgNoIPM := &config.RedundancyGroup{ID: 0, NodePriorities: map[int]int{0: 200}}
	cfg2 := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rgNoIPM}}
	m.UpdateConfig(cfg2)
	mon.UpdateGroups(cfg2.RedundancyGroups)

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("after removing ip-monitoring (group kept) weight = %d, want 255 "+
			"(stranded aggregate debt must be cleared even when IPMonitoring is nil)", w)
	}
	if mon.ipThresholdState[0] {
		t.Errorf("ipThresholdState[0] = true after ip-monitoring removal, want false")
	}
}

// TestMonitor_GlobalThresholdPerRGIndependence_5271 pins that one RG's
// cumulative threshold state does not leak into another RG's decision.
func TestMonitor_GlobalThresholdPerRGIndependence_5271(t *testing.T) {
	// rg0: threshold 100, two weight-60 targets (one failure = 60 < 100).
	// rg1: threshold 100, two weight-60 targets.
	rg0 := thresholdRG(0, 100, 100, 60, "10.0.0.1", "10.0.0.2")
	rg1 := thresholdRG(1, 100, 100, 60, "10.1.0.1", "10.1.0.2")
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg0, rg1}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)

	reach := map[string]bool{
		"10.0.0.1": true, "10.0.0.2": true,
		"10.1.0.1": true, "10.1.0.2": true,
	}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)

	mon.poll()

	// rg0 crosses its threshold (both targets fail → 120 >= 100); rg1 stays
	// sub-threshold (one target fails → 60 < 100).
	reach["10.0.0.1"] = false
	reach["10.0.0.2"] = false
	reach["10.1.0.1"] = false
	mon.poll()

	states := m.GroupStates()
	var w0, w1 int
	for _, s := range states {
		switch s.GroupID {
		case 0:
			w0 = s.Weight
		case 1:
			w1 = s.Weight
		}
	}
	if w0 != 155 {
		t.Errorf("rg0 weight = %d, want 155 (crossed 120>=100, -100)", w0)
	}
	if w1 != 255 {
		t.Errorf("rg1 weight = %d, want 255 (sub-threshold 60<100, no debt) — rg0 state leaked", w1)
	}
}
