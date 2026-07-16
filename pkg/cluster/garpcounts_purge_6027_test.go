package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// garpRG builds an RG with an explicit gratuitous-arp-count. A count of 0 means
// "no explicit count" — UpdateConfig only writes m.garpCounts when the count is
// positive, so a 0 leaves the RG on the default GARP burst (3, applied by the
// VRRP/daemon consumers when the map entry is absent).
func garpRG(id, garpCount int) *config.RedundancyGroup {
	return &config.RedundancyGroup{
		ID:                 id,
		NodePriorities:     map[int]int{0: 200},
		GratuitousARPCount: garpCount,
	}
}

// TestGARPCountsPurgedOnRGRemoval_6027 pins the map-lifecycle fix for #6027:
// when an RG is REMOVED from config, the manager's per-RG m.garpCounts entry
// must be purged in the same removed-RG cleanup loop that already clears
// monitorWeights and the group. Otherwise a same-id RG remove/re-add where the
// re-added config omits an explicit gratuitous-arp-count inherits the PRIOR
// incarnation's count instead of the default.
//
// This is the third same-id-re-add gap in this loop: #5990 fixed the
// ip-monitor ipState/ipDebts/ipThresholdState; this fixes garpCounts.
//
// Fail-on-revert: remove `delete(m.garpCounts, id)` from UpdateConfig's
// removed-RG loop. After removal the stale garpCounts[1]==7 survives (the
// "PURGED" assertion goes RED), and after a same-id re-add with no explicit
// count the stale 7 is still present instead of an absent entry (the "default"
// assertion goes RED).
func TestGARPCountsPurgedOnRGRemoval_6027(t *testing.T) {
	m := NewManager(0, 1)

	// --- Add RG 1 with an explicit non-default GARP count. ---
	m.UpdateConfig(makeConfig(garpRG(1, 7)))
	drainEvents(m, 4)

	if got, ok := m.garpCounts[1]; !ok || got != 7 {
		t.Fatalf("after add: garpCounts[1] = (%d, present=%v), want (7, true)", got, ok)
	}

	// --- REMOVE RG 1 from config. The removed-RG cleanup loop must purge
	// the per-RG GARP count alongside monitorWeights and the group. ---
	m.UpdateConfig(makeConfig())
	drainEvents(m, 4)

	if m.GroupState(1) != nil {
		t.Fatalf("RG 1 should be gone after removal, still present")
	}
	if got, ok := m.garpCounts[1]; ok {
		t.Fatalf("garpCounts[1] not purged on RG removal (#6027): got %d, want absent", got)
	}

	// --- RE-ADD the SAME RG id with NO explicit gratuitous-arp-count. ---
	// Because UpdateConfig only writes garpCounts for a positive count, the
	// entry must stay ABSENT so the consumer falls back to the default burst.
	// Without the purge, the stale garpCounts[1]==7 survives here and the
	// re-added RG wrongly inherits the prior incarnation's count.
	m.UpdateConfig(makeConfig(garpRG(1, 0)))
	drainEvents(m, 4)

	if m.GroupState(1) == nil {
		t.Fatalf("RG 1 should be present after re-add")
	}
	if got, ok := m.garpCounts[1]; ok {
		t.Fatalf("after same-id re-add with no explicit count: garpCounts[1] = %d "+
			"(stale from prior incarnation), want absent so the default GARP "+
			"count is used (#6027)", got)
	}
}
