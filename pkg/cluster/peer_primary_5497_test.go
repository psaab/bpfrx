package cluster

import "testing"

// TestIsPeerPrimary verifies the peer-ownership predicate MonitorInterface uses
// to decide whether to proxy a locally-present RETH to the peer (#5497). The
// bug it guards against: proxying merely because the LOCAL node is not primary,
// which — when the peer is ALSO not primary — forms an A->B->A loop.
func TestIsPeerPrimary(t *testing.T) {
	tests := []struct {
		name      string
		peerAlive bool
		peerState *NodeState // nil = RG unknown to peer
		want      bool
	}{
		{"peer primary + alive", true, statePtr(StatePrimary), true},
		{"peer secondary (both-secondary)", true, statePtr(StateSecondary), false},
		{"peer secondary-hold (sync-hold)", true, statePtr(StateSecondaryHold), false},
		{"peer disabled", true, statePtr(StateDisabled), false},
		{"peer RG unknown", true, nil, false},
		{"peer primary but dead (lost)", false, statePtr(StatePrimary), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewManager(0, 1)
			m.mu.Lock()
			m.peerAlive = tt.peerAlive
			if tt.peerState != nil {
				m.peerGroups[1] = PeerGroupState{GroupID: 1, State: *tt.peerState}
			}
			m.mu.Unlock()

			if got := m.IsPeerPrimary(1); got != tt.want {
				t.Fatalf("IsPeerPrimary(1) = %v, want %v", got, tt.want)
			}
		})
	}
}

func statePtr(s NodeState) *NodeState { return &s }
