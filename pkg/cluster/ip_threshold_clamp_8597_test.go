package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 (muse-004 K71) — the aggregate ip-monitoring comparison clamped the
// WEIGHT and not the THRESHOLD.
//
// Both are bounded to [0,255] by the same strict gate (schema_chassis.go's
// ValidateInteger(0, 255) and validateChassisClusterStrict, #6588), and both
// reach runtime unbounded on the tolerant load / peer-sync path. #6549 bounded
// the weight; the threshold this comparison uses stayed raw.
//
// `cumulative` is a sum of per-target weights that ARE clamped, so a
// lenient-loaded threshold of 1,000,000 can never be reached however many
// probes fail. The RG never demotes, the status shows no failure, and failover
// is effectively OFF for that RG while the operator believes they configured
// protection.
//
// A monitor that cannot fire is worse than a missing one: it is a missing one
// that reports healthy.

// pollUntilDown drives the monitor with every target unreachable and returns
// the RG's resulting election weight.
func pollWithAllTargetsDown(t *testing.T, rg *config.RedundancyGroup, addrs ...string) int {
	t.Helper()
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reach := map[string]bool{}
	for _, a := range addrs {
		reach[a] = false
	}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)
	mon.poll()
	return m.GroupStates()[0].Weight
}

// TestOutOfRangeGlobalThresholdStillDemotes_8597 is the RED-on-revert core.
//
// Threshold 1,000,000 with four weight-100 targets: the cumulative can reach at
// most 400, so the raw comparison can NEVER fire. With the threshold clamped to
// the same [0,255] domain as the weights, all-down crosses it and the RG
// demotes by the global weight.
func TestOutOfRangeGlobalThresholdStillDemotes_8597(t *testing.T) {
	addrs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
	rg := thresholdRG(0, 100, 1000000, 100, addrs...)
	got := pollWithAllTargetsDown(t, rg, addrs...)
	if got == 255 {
		t.Fatalf("RG weight stayed 255 with EVERY monitored target down and a " +
			"lenient-loaded global-threshold of 1000000: the cumulative weight is a " +
			"sum of CLAMPED per-target weights and can never reach it, so this RG " +
			"never demotes and its failover is effectively off while the status " +
			"reports healthy (#8597/K71)")
	}
	if want := 255 - 100; got != want {
		t.Errorf("RG weight = %d, want %d (255 minus the clamped global-weight)", got, want)
	}
}

// TestInRangeGlobalThresholdIsUnchanged_8597 is the OVER-BROAD control: the
// clamp must not move a threshold that is already in range, in either
// direction. A threshold of 200 with 4x50 targets fires only when all four are
// down — the #5271 semantics — and one of 400 (out of range) must behave like
// 255, not like 0.
func TestInRangeGlobalThresholdIsUnchanged_8597(t *testing.T) {
	addrs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}

	// In range: 200 <= cumulative 200, so it fires, and the deduction is the
	// global weight. This is #5271's own scenario and must be untouched.
	if got := pollWithAllTargetsDown(t, thresholdRG(0, 100, 200, 50, addrs...), addrs...); got != 155 {
		t.Errorf("in-range threshold 200 gave weight %d, want 155; the clamp must not "+
			"move a threshold that is already inside [0,255]", got)
	}

	// Just above the range: clamps to 255, and 4x100 = 400 >= 255 fires. The
	// clamp must not turn an out-of-range threshold into ZERO, which would make
	// the monitor fire with nothing down.
	if got := pollWithAllTargetsDown(t, thresholdRG(0, 100, 256, 100, addrs...), addrs...); got != 155 {
		t.Errorf("threshold 256 gave weight %d, want 155", got)
	}
}

// TestClampedThresholdDoesNotFireWithNothingDown_8597 is the other half of the
// over-broad control, and the one a clamp-to-zero would fail.
//
// Clamping an out-of-range threshold DOWN is only safe if it does not clamp to
// something the cumulative always exceeds. With every target REACHABLE the
// cumulative is 0, and 0 >= 0 would fire — so a clamp that mapped 1,000,000 to
// 0 would demote a perfectly healthy RG.
func TestClampedThresholdDoesNotFireWithNothingDown_8597(t *testing.T) {
	addrs := []string{"10.0.0.1", "10.0.0.2"}
	rg := thresholdRG(0, 100, 1000000, 100, addrs...)
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(map[string]bool{"10.0.0.1": true, "10.0.0.2": true})
	mon.poll()

	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("RG weight = %d with every target REACHABLE; the threshold clamp must "+
			"not map an out-of-range value to something a zero cumulative already "+
			"exceeds", w)
	}
}

// TestStatusReportsTheEffectiveThreshold_8597: the decision and the display
// must use the same number.
//
// IPGlobalThreshold feeds the operator-facing status. Reporting the raw
// configured value while the election compares a clamped one is the #6534
// shape — the screen and the behaviour disagree, and the screen is the only
// thing the operator can see.
func TestStatusReportsTheEffectiveThreshold_8597(t *testing.T) {
	rg := thresholdRG(0, 100, 1000000, 100, "10.0.0.1")
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)

	threshold, weight, ok := mon.IPGlobalThreshold(0)
	if !ok {
		t.Fatal("IPGlobalThreshold reported no aggregate mode for an RG configured with one")
	}
	if threshold == 1000000 {
		t.Error("the status reports the RAW configured threshold while the election " +
			"compares a clamped one; an operator reading it cannot tell why failover " +
			"never fires")
	}
	if threshold != 255 {
		t.Errorf("reported threshold = %d, want the clamped 255", threshold)
	}
	if weight != 100 {
		t.Errorf("reported weight = %d, want 100", weight)
	}
}
