package daemon

import "sync"

// rgStateMachine tracks the combined cluster + VRRP state for a single
// redundancy group. Both watchClusterEvents and watchVRRPEvents funnel
// transitions through this struct, which determines the desired rg_active
// value from the combined inputs.
//
// Activation rule: rg_active = clusterPri || anyVrrpMaster
//   - Cluster Primary alone activates (avoids dual-inactive window while
//     VRRP catches up)
//   - VRRP MASTER alone activates (VRRP is faster than heartbeat; cluster
//     Primary event may lag by ~200ms)
//   - Both false → deactivate
//
// The epoch counter is monotonically incremented on every state change,
// enabling stale-update detection in the reconciliation loop (task #2).
type rgStateMachine struct {
	mu            sync.Mutex
	clusterPri    bool            // cluster says Primary for this RG
	vrrpInstances map[string]bool // per-interface VRRP master state
	active        bool            // current rg_active value in BPF
	epoch         uint64          // monotonic counter
}

// rgTransition is returned by state machine updates to inform the caller
// whether rg_active changed and what the new value is.
type rgTransition struct {
	Changed bool   // rg_active value changed
	Active  bool   // new rg_active value
	Epoch   uint64 // current epoch after this transition
}

func newRGStateMachine() *rgStateMachine {
	return &rgStateMachine{
		vrrpInstances: make(map[string]bool),
	}
}

// SetCluster updates the cluster Primary/Secondary state and returns
// the resulting rg_active transition.
func (s *rgStateMachine) SetCluster(isPrimary bool) rgTransition {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clusterPri = isPrimary
	return s.reconcileLocked()
}

// SetVRRP updates the VRRP state for a specific interface and returns
// the resulting rg_active transition.
func (s *rgStateMachine) SetVRRP(iface string, isMaster bool) rgTransition {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vrrpInstances[iface] = isMaster
	return s.reconcileLocked()
}

// IsActive returns the current rg_active value.
func (s *rgStateMachine) IsActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// Epoch returns the current epoch counter.
func (s *rgStateMachine) Epoch() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch
}

// AnyVRRPMaster returns true if any VRRP instance is MASTER.
func (s *rgStateMachine) AnyVRRPMaster() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.anyMasterLocked()
}

// AllVRRPMaster returns true if ALL VRRP instances are MASTER.
// Returns false if no instances exist.
func (s *rgStateMachine) AllVRRPMaster() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allMasterLocked()
}

// Reconcile overwrites the internal state with the authoritative cluster
// and VRRP state, then recomputes rg_active. Called by the periodic
// reconciliation loop to correct any drift from dropped events.
// vrrpStates maps interface name → isMaster.
func (s *rgStateMachine) Reconcile(clusterPri bool, vrrpStates map[string]bool) rgTransition {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clusterPri = clusterPri
	// Replace all VRRP instance states.
	s.vrrpInstances = make(map[string]bool, len(vrrpStates))
	for iface, isMaster := range vrrpStates {
		s.vrrpInstances[iface] = isMaster
	}
	return s.reconcileLocked()
}

func (s *rgStateMachine) reconcileLocked() rgTransition {
	s.epoch++
	desired := s.clusterPri || s.anyMasterLocked()
	changed := desired != s.active
	s.active = desired
	return rgTransition{Changed: changed, Active: desired, Epoch: s.epoch}
}

func (s *rgStateMachine) anyMasterLocked() bool {
	for _, m := range s.vrrpInstances {
		if m {
			return true
		}
	}
	return false
}

func (s *rgStateMachine) allMasterLocked() bool {
	if len(s.vrrpInstances) == 0 {
		return false
	}
	for _, m := range s.vrrpInstances {
		if !m {
			return false
		}
	}
	return true
}
