package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #7178: the arm-state transitions must actually DRIVE the redundancy-group
// weight, not merely have a helper that could.
//
// WHY THIS IS SEPARATE FROM THE ARITHMETIC TESTS. pkg/cluster pins the cost's
// value — large enough to lose to an armed peer, small enough to leave the node
// eligible. Those pass whether or not anything ever applies it. Deleting the
// applyDataplaneArmTrack call from markDataplaneArmFailed leaves every one of
// them green, because they exercise rgWeightFromDebt directly. The defect being
// fixed lives in the WIRING — a node that failed to arm went on holding RG
// mastership — so the wiring is what this file asserts.

func armTrackManager(t *testing.T) *cluster.Manager {
	t.Helper()
	m := cluster.NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{{ID: 1, NodePriorities: map[int]int{0: 200}}},
	})
	return m
}

func rgWeight(t *testing.T, m *cluster.Manager, id int) int {
	t.Helper()
	for _, rg := range m.GroupStates() {
		if rg.GroupID == id {
			return rg.Weight
		}
	}
	t.Fatalf("redundancy group %d not found", id)
	return -1
}

func TestArmFailureDemotesRedundancyGroupWeight7178(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")

	m := armTrackManager(t)
	d := &Daemon{cluster: m}

	// Precondition: a group with no monitor debt carries the full weight. Without
	// this the assertion below could pass on a group that was never healthy.
	if w := rgWeight(t, m, 1); w == 0 {
		t.Fatalf("precondition: the group must start with a non-zero weight, got %d", w)
	}
	full := rgWeight(t, m, 1)

	d.markDataplaneArmFailed("test", "test", errors.New("boom"))

	got := rgWeight(t, m, 1)
	if got >= full {
		t.Fatalf("after an arm FAILURE the RG weight is %d, unchanged from %d. The node "+
			"still outbids a peer that can forward, so it keeps taking the RETH VIPs and "+
			"attracting traffic it drops (#7178)", got, full)
	}
	if got == 0 {
		t.Errorf("the arm failure drove the weight to 0, which also demotes a STANDALONE "+
			"node — nothing takes its VIPs and the operator may lose the address they reach "+
			"it on. The cost is sub-total on purpose")
	}
}

// The gate must FOLLOW the arm state, not be pinned off: a successful arm has to
// clear the debt, or a node that recovered would stay demoted forever and could
// never take back mastership after the peer fails.
func TestSuccessfulArmClearsTheDemotion7178(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")

	m := armTrackManager(t)
	d := &Daemon{cluster: m}
	full := rgWeight(t, m, 1)

	d.markDataplaneArmFailed("test", "test", errors.New("boom"))
	if rgWeight(t, m, 1) >= full {
		t.Fatalf("precondition: the failure must demote before recovery can be observed")
	}

	d.markDataplaneArmed("test")

	if got := rgWeight(t, m, 1); got != full {
		t.Errorf("after a successful arm the RG weight is %d, want the full %d restored. A "+
			"node that recovered but stays demoted can never take mastership back when the "+
			"peer fails — a permanent single point of failure created by the fix", got, full)
	}
}

// A daemon with no cluster configured must not panic. This is the standalone
// non-cluster box, which is the common case.
func TestArmTrackIsSafeWithoutACluster7178(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")
	d := &Daemon{} // nil cluster
	d.markDataplaneArmFailed("test", "test", errors.New("boom"))
	d.markDataplaneArmed("test")
}
