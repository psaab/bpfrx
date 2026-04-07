package daemon

import (
	"testing"

	"github.com/psaab/bpfrx/pkg/cluster"
)

func TestDirectVIPOwnershipDesired(t *testing.T) {
	tests := []struct {
		name       string
		localState cluster.NodeState
		want       bool
	}{
		{
			name:       "local secondary never owns VIPs",
			localState: cluster.StateSecondary,
			want:       false,
		},
		{
			name:       "peer lost lets local primary own VIPs",
			localState: cluster.StatePrimary,
			want:       true,
		},
		{
			name:       "local primary still owns VIPs during dual-active resolution",
			localState: cluster.StatePrimary,
			want:       true,
		},
		{
			name:       "local secondary hold does not own VIPs",
			localState: cluster.StateSecondaryHold,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := directVIPOwnershipDesired(tt.localState); got != tt.want {
				t.Fatalf("directVIPOwnershipDesired(%s) = %v, want %v",
					tt.localState, got, tt.want)
			}
		})
	}
}

func TestApplyDirectVIPOwnershipRemovesStaleVIPsWithoutEdge(t *testing.T) {
	var removeCalls int
	d := &Daemon{
		directVIPOwned: make(map[int]bool),
		directRemoveVIPsFn: func(rgID int) int {
			if rgID != 1 {
				t.Fatalf("unexpected rgID %d", rgID)
			}
			removeCalls++
			return 1
		},
		directRemoveStableLLFn: func(rgID int) {
			if rgID != 1 {
				t.Fatalf("unexpected stable-LL rgID %d", rgID)
			}
		},
	}

	d.applyDirectVIPOwnership(1, false, "test")

	if removeCalls != 1 {
		t.Fatalf("expected one VIP removal attempt, got %d", removeCalls)
	}
	if d.directVIPOwnershipApplied(1) {
		t.Fatal("expected direct VIP ownership to remain false")
	}
}
