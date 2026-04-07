package daemon

import (
	"testing"

	"github.com/psaab/bpfrx/pkg/cluster"
)

func TestDirectVIPOwnershipDesired(t *testing.T) {
	tests := []struct {
		name           string
		localState     cluster.NodeState
		peerAlive      bool
		peerState      cluster.NodeState
		peerStateKnown bool
		want           bool
	}{
		{
			name:       "local secondary never owns VIPs",
			localState: cluster.StateSecondary,
			want:       false,
		},
		{
			name:       "peer lost lets local primary own VIPs",
			localState: cluster.StatePrimary,
			peerAlive:  false,
			want:       true,
		},
		{
			name:           "peer primary blocks ownership",
			localState:     cluster.StatePrimary,
			peerAlive:      true,
			peerState:      cluster.StatePrimary,
			peerStateKnown: true,
			want:           false,
		},
		{
			name:           "peer transfer out allows ownership",
			localState:     cluster.StatePrimary,
			peerAlive:      true,
			peerState:      cluster.StateSecondaryHold,
			peerStateKnown: true,
			want:           true,
		},
		{
			name:           "missing peer RG info does not block ownership",
			localState:     cluster.StatePrimary,
			peerAlive:      true,
			peerStateKnown: false,
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := directVIPOwnershipDesired(tt.localState, tt.peerAlive, tt.peerState, tt.peerStateKnown); got != tt.want {
				t.Fatalf("directVIPOwnershipDesired(%s, peerAlive=%v, peerState=%s, known=%v) = %v, want %v",
					tt.localState, tt.peerAlive, tt.peerState, tt.peerStateKnown, got, tt.want)
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
