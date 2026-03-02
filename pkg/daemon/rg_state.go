package daemon

import (
	"sync"
	"time"
)

// rgStateMachine tracks the combined cluster + VRRP state for a single
// redundancy group. Both watchClusterEvents and watchVRRPEvents funnel
// transitions through this struct, which determines the desired rg_active
// value from the combined inputs.
//
// Activation rule (default): rg_active = clusterPri || anyVrrpMaster
//   - Cluster Primary alone activates (avoids dual-inactive window while
//     VRRP catches up)
//   - VRRP MASTER alone activates (VRRP is faster than heartbeat; cluster
//     Primary event may lag by ~200ms)
//   - Both false → deactivate
//
// Activation rule (strict-vip-ownership): rg_active = anyVrrpMaster
//   - VRRP master state is the sole authority for activation
//   - Prevents brief dual-active window during failover in same-L2 deployments
//
// Desired-vs-applied tracking: the state machine tracks both what the
// desired rg_active value should be and whether it was successfully applied
// to the BPF map. The reconciliation loop retries when they diverge.
//
// The epoch counter is monotonically incremented on every state change,
// enabling stale-update detection in the reconciliation loop.
type rgStateMachine struct {
	mu            sync.Mutex
	clusterPri    bool            // cluster says Primary for this RG
	vrrpInstances map[string]bool // per-interface VRRP master state
	active        bool            // desired rg_active value
	applied       bool            // last successfully applied rg_active value
	applyPending  bool            // true when desired != applied
	epoch         uint64          // monotonic counter

	// VRRP posture mismatch tracking (#86): detect when VRRP state
	// doesn't match cluster expectations and only take corrective action
	// after a sustained mismatch (vrrpPostureDelay). This prevents the
	// reconcile loop from fighting transient states (sync-hold, election,
	// hitless restart).
	vrrpMismatchSince time.Time // when mismatch was first detected (zero = no mismatch)

	startedAt time.Time // when this state machine was created (for posture delay selection)

	// Strict VIP ownership (#104): when enabled, rg_active is derived
	// solely from VRRP master state, NOT clusterPri || anyVrrpMaster.
	// This prevents the brief dual-active window during failover.
	strictVIPOwnership bool
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
		startedAt:     time.Now(),
	}
}

// SetStrictVIPOwnership enables or disables strict VIP ownership mode.
// When enabled, rg_active is derived from VRRP master state only.
func (s *rgStateMachine) SetStrictVIPOwnership(strict bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.strictVIPOwnership = strict
}

// IsStrictVIPOwnership returns whether strict VIP ownership mode is enabled.
func (s *rgStateMachine) IsStrictVIPOwnership() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.strictVIPOwnership
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

// IsActive returns the current desired rg_active value.
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

// MarkApplied records that the desired rg_active value was successfully
// written to the BPF map.
func (s *rgStateMachine) MarkApplied(active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied = active
	if s.applied == s.active {
		s.applyPending = false
	}
}

// NeedsApply returns true if the desired rg_active differs from the last
// successfully applied value.
func (s *rgStateMachine) NeedsApply() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyPending
}

// DesiredActive returns the current desired active state.
func (s *rgStateMachine) DesiredActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// ApplyIfCurrent atomically marks the transition as applied only if
// the state machine's epoch still matches the transition's epoch.
// Returns true if the apply was recorded, false if a newer transition
// superseded it (stale-update detection for concurrent goroutines).
func (s *rgStateMachine) ApplyIfCurrent(tr rgTransition) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch != tr.Epoch {
		return false
	}
	s.applied = tr.Active
	if s.applied == s.active {
		s.applyPending = false
	}
	return true
}

// CurrentDesired returns the current desired active state and epoch
// atomically. Use this to re-read the authoritative state before
// applying side effects in race-prone paths.
func (s *rgStateMachine) CurrentDesired() (active bool, epoch uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active, s.epoch
}

func (s *rgStateMachine) reconcileLocked() rgTransition {
	s.epoch++
	var desired bool
	if s.strictVIPOwnership {
		desired = s.anyMasterLocked() // VRRP-only: prevents dual-active window
	} else {
		desired = s.clusterPri || s.anyMasterLocked()
	}
	changed := desired != s.active
	s.active = desired
	if s.active != s.applied {
		s.applyPending = true
	}
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

// vrrpPostureDelayStartup is the posture mismatch delay used during the
// first 30 seconds after daemon startup. The longer delay avoids fighting
// transient states like sync-hold, VRRP election, and hitless restart.
const vrrpPostureDelayStartup = 10 * time.Second

// vrrpPostureDelaySteadyState is the posture mismatch delay used after
// the startup window. In normal operation, 2 seconds is enough to ride
// out brief VRRP election jitter while still recovering quickly from a
// stuck mismatch (#101).
const vrrpPostureDelaySteadyState = 2 * time.Second

// vrrpPostureStartupWindow is how long after state machine creation the
// startup (conservative) delay is used before switching to steady-state.
const vrrpPostureStartupWindow = 30 * time.Second

// vrrpPostureMismatch describes the type of posture correction needed.
type vrrpPostureMismatch int

const (
	vrrpPostureOK          vrrpPostureMismatch = iota // no correction needed
	vrrpPostureNeedsMaster                            // cluster=primary but VRRP != MASTER
	vrrpPostureNeedsResign                            // cluster=secondary but VRRP == MASTER
)

// CheckVRRPPosture checks whether VRRP state matches cluster expectations
// and returns a correction action if the mismatch has persisted long enough.
// Uses a conservative 10s delay during the startup window (first 30s) and
// a faster 2s delay in steady state. Resets the mismatch timer when state
// matches.
//
// The caller is responsible for skipping this check during sync-hold.
func (s *rgStateMachine) CheckVRRPPosture(now time.Time) vrrpPostureMismatch {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If no VRRP instances exist for this RG (e.g. member interface
	// missing after reboot), posture correction is impossible — skip.
	if len(s.vrrpInstances) == 0 {
		s.vrrpMismatchSince = time.Time{}
		return vrrpPostureOK
	}

	anyMaster := s.anyMasterLocked()

	var mismatch vrrpPostureMismatch
	switch {
	case s.clusterPri && !anyMaster:
		// Cluster says we're primary but VRRP is not MASTER.
		mismatch = vrrpPostureNeedsMaster
	case !s.clusterPri && anyMaster:
		// Cluster says secondary but VRRP is still MASTER.
		mismatch = vrrpPostureNeedsResign
	default:
		// State matches — clear mismatch timer.
		s.vrrpMismatchSince = time.Time{}
		return vrrpPostureOK
	}

	// Start or continue mismatch tracking.
	if s.vrrpMismatchSince.IsZero() {
		s.vrrpMismatchSince = now
		return vrrpPostureOK // first detection, don't act yet
	}

	// Use conservative delay near startup (sync-hold, election), fast
	// correction in steady state (#101).
	delay := vrrpPostureDelaySteadyState
	if now.Sub(s.startedAt) < vrrpPostureStartupWindow {
		delay = vrrpPostureDelayStartup
	}

	if now.Sub(s.vrrpMismatchSince) < delay {
		return vrrpPostureOK // mismatch hasn't persisted long enough
	}

	// Sustained mismatch — reset timer and signal correction.
	s.vrrpMismatchSince = time.Time{}
	return mismatch
}
