package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8640: LocalGroupPrimary answers the two facts the proxy-ARP responder needs
// — is this node primary, and is the group known at all — under one RLock with
// no allocation and no callback.
//
// The tri-state matters: `IsLocalPrimary` collapses "unknown group" into
// `false`, and the responder must distinguish them. Unknown falls back to the
// older ownership signal; not-primary suppresses. Collapsing them would make a
// node stop answering for every RG its cluster manager does not track, which is
// the silent non-answer #8621 was filed to fix.
func TestLocalGroupPrimaryIsTriState8640(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(clusterCfg8640())

	m.SetGroupStateForTesting(1, StatePrimary)
	m.SetGroupStateForTesting(2, StateSecondary)

	if p, known := m.LocalGroupPrimary(1); !known || !p {
		t.Errorf("rg1: got (primary=%v known=%v), want (true, true)", p, known)
	}
	if p, known := m.LocalGroupPrimary(2); !known || p {
		t.Errorf("rg2: got (primary=%v known=%v), want (false, true) — a SECONDARY "+
			"group must report known, or its caller falls back instead of "+
			"suppressing", p, known)
	}
	if p, known := m.LocalGroupPrimary(9); known || p {
		t.Errorf("rg9 (untracked): got (primary=%v known=%v), want (false, false) — "+
			"an unknown group must be distinguishable from a secondary one", p, known)
	}
}

// The property that put this accessor here rather than reusing GroupState: it
// runs per inbound ARP frame on a socket any host on the segment can drive, so
// it must not allocate.
//
// GroupState allocates for MonitorFails/ReadinessReasons and invokes
// transferReadinessFn; this asserts the cheap path stays cheap. A regression
// that reintroduces an allocation here puts it on an attacker-drivable path.
func TestLocalGroupPrimaryDoesNotAllocate8640(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(clusterCfg8640())
	m.SetGroupStateForTesting(1, StatePrimary)

	if got := testing.AllocsPerRun(200, func() {
		_, _ = m.LocalGroupPrimary(1)
	}); got != 0 {
		t.Fatalf("LocalGroupPrimary allocated %v times per call, want 0. It runs "+
			"per inbound ARP frame on the #8621 responder's socket; an allocation "+
			"there is reachable by anyone on the segment", got)
	}

	// CONTROL: GroupState — the call this accessor exists to avoid — DOES
	// allocate on the same manager. Without this the assertion above could pass
	// against a manager where nothing allocates for unrelated reasons.
	m.SetGroupStateForTesting(1, StatePrimary)
	if got := testing.AllocsPerRun(200, func() {
		_ = m.GroupState(1)
	}); got == 0 {
		t.Fatal("GroupState allocated 0 times, so this cell cannot show that " +
			"LocalGroupPrimary is the cheaper path — the comparison is vacuous")
	}
}

func clusterCfg8640() *config.ClusterConfig {
	return &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 1, NodePriorities: map[int]int{0: 200}},
			{ID: 2, NodePriorities: map[int]int{0: 200}},
		},
	}
}
