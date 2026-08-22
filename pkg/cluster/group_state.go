package cluster

import (
	"log/slog"
	"sort"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// UpdateConfig synchronizes redundancy group definitions from config.
// Called during config apply. Preserves runtime state for existing groups.
func (m *Manager) UpdateConfig(cfg *config.ClusterConfig) {
	if cfg == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	seen := make(map[int]bool)
	for _, rg := range cfg.RedundancyGroups {
		seen[rg.ID] = true
		existing, ok := m.groups[rg.ID]
		if !ok {
			pri := rg.NodePriorities[m.nodeID]
			existing = &RedundancyGroupState{
				GroupID:       rg.ID,
				LocalPriority: pri,
				Weight:        255,
				State:         StateSecondary,
				Preempt:       rg.Preempt,
			}
			m.groups[rg.ID] = existing
			slog.Info("cluster: new redundancy group",
				"rg", rg.ID, "priority", pri, "preempt", rg.Preempt)
		} else {
			existing.LocalPriority = rg.NodePriorities[m.nodeID]
			existing.Preempt = rg.Preempt
		}
	}

	// Remove groups no longer in config and their monitor weights.
	for id, rg := range m.groups {
		if !seen[id] {
			// Stop the armed takeover-hold timer before dropping the group
			// so its AfterFunc closure cannot fire an election against
			// removed state (#5245). Mirrors the readiness.go not-ready
			// clear site and Stop(): stop + nil the field under m.mu (held
			// here). AfterFunc's Stop() does not block on an in-flight
			// callback; if a fired callback is already parked on m.mu it
			// runs after we unlock, but the readiness.go closure's
			// staleness guard makes it a no-op once the group is gone.
			if rg.holdTimer != nil {
				rg.holdTimer.Stop()
				rg.holdTimer = nil
			}
			for k := range m.monitorWeights {
				if k.rgID == id {
					delete(m.monitorWeights, k)
				}
			}
			// Purge the per-RG GARP count so a same-id re-add that omits an
			// explicit gratuitous-arp-count does not inherit this incarnation's
			// stale count (#6027). garpCounts is only WRITTEN when the config
			// sets a positive count, so a re-add with no explicit count relies
			// on the map entry being absent to fall back to the default. The
			// third same-id-re-add map-lifecycle gap in this loop after #5990
			// (ip-monitor ipState/ipDebts/ipThresholdState).
			delete(m.garpCounts, id)
			delete(m.groups, id)
		}
	}

	// Update heartbeat parameters.
	if cfg.HeartbeatInterval > 0 {
		m.hbInterval = time.Duration(cfg.HeartbeatInterval) * time.Millisecond
	}
	if cfg.HeartbeatThreshold > 0 {
		m.hbThreshold = cfg.HeartbeatThreshold
	}
	if cfg.ControlInterface != "" {
		m.controlInterface = cfg.ControlInterface
	}

	// #4107: plumb the control-channel PSK. Reveal() reads the cleartext
	// secret; it is stored as raw bytes and NEVER logged. Empty clears it
	// (reverts to legacy dual-accept). The slice is replaced, not mutated, so
	// the RLock read in controlLinkAuthKey() stays race-free.
	if k := cfg.ControlLinkAuthKey.Reveal(); k != "" {
		m.controlAuthKey = []byte(k)
	} else {
		m.controlAuthKey = nil
	}
	// #6630: the additional ACCEPTED key. Clearing it is the operator's
	// explicit FINALIZE step — the retired key stops being accepted on the
	// next commit, so the overlap is bounded by an operator action rather
	// than being permanent.
	if k := cfg.ControlLinkAuthKeyAlt.Reveal(); k != "" {
		m.controlAuthKeyAlt = []byte(k)
	} else {
		m.controlAuthKeyAlt = nil
	}

	// Update peer fencing config.
	m.peerFencing = cfg.PeerFencing

	// Update takeover hold time. Zero or negative resets to the default
	// immediate-takeover behavior.
	if cfg.TakeoverHoldTime < 0 {
		slog.Warn("cluster: invalid negative takeover hold time, using default immediate takeover",
			"takeover_hold_time_ms", cfg.TakeoverHoldTime)
	}
	if cfg.TakeoverHoldTime > 0 {
		m.takeoverHoldTime = time.Duration(cfg.TakeoverHoldTime) * time.Millisecond
	} else {
		m.takeoverHoldTime = DefaultTakeoverHoldTime
	}

	// Store GARP counts and update monitor groups.
	for _, rg := range cfg.RedundancyGroups {
		if rg.GratuitousARPCount > 0 {
			m.garpCounts[rg.ID] = rg.GratuitousARPCount
		}
	}
	// Reconcile installed interface-monitor debt against the new desired
	// monitor set BEFORE electing, so a monitor the operator just removed or
	// changed cannot strand this node with stale weight debt (#5080).
	m.reconcileMonitorDebtsLocked(cfg)

	if m.monitor != nil {
		m.monitor.UpdateGroups(cfg.RedundancyGroups)
	}

	// Election: use peer-aware if peer is alive, otherwise single-node.
	if m.peerAlive {
		m.runElection()
	} else {
		m.electSingleNode()
	}
}

// GroupStates returns a snapshot of all redundancy group states.
func (m *Manager) GroupStates() []RedundancyGroupState {
	m.mu.RLock()
	states := make([]RedundancyGroupState, 0, len(m.groups))
	for _, rg := range m.groups {
		cp := *rg
		if len(rg.MonitorFails) > 0 {
			cp.MonitorFails = make([]string, len(rg.MonitorFails))
			copy(cp.MonitorFails, rg.MonitorFails)
		}
		if len(rg.ReadinessReasons) > 0 {
			cp.ReadinessReasons = make([]string, len(rg.ReadinessReasons))
			copy(cp.ReadinessReasons, rg.ReadinessReasons)
		}
		states = append(states, cp)
	}
	fn := m.transferReadinessFn
	m.mu.RUnlock()

	if fn != nil {
		for i := range states {
			ready, reasons := fn(states[i].GroupID)
			states[i].TransferReady = ready
			if len(reasons) > 0 {
				states[i].TransferReadinessReasons = append([]string(nil), reasons...)
			}
		}
	} else {
		for i := range states {
			states[i].TransferReady = true
		}
	}

	sort.Slice(states, func(i, j int) bool {
		return states[i].GroupID < states[j].GroupID
	})
	return states
}

// DataGroupIDs returns the configured non-control redundancy groups in
// ascending order. RG0 is reserved for control-plane ownership and is omitted.
func (m *Manager) DataGroupIDs() []int {
	m.mu.RLock()
	ids := make([]int, 0, len(m.groups))
	for rgID := range m.groups {
		if rgID == 0 {
			continue
		}
		ids = append(ids, rgID)
	}
	m.mu.RUnlock()
	sort.Ints(ids)
	return ids
}

// GroupState returns the state for a specific redundancy group, or nil if not found.
func (m *Manager) GroupState(rgID int) *RedundancyGroupState {
	m.mu.RLock()
	rg, ok := m.groups[rgID]
	if !ok {
		m.mu.RUnlock()
		return nil
	}
	cp := *rg
	if len(rg.MonitorFails) > 0 {
		cp.MonitorFails = make([]string, len(rg.MonitorFails))
		copy(cp.MonitorFails, rg.MonitorFails)
	}
	if len(rg.ReadinessReasons) > 0 {
		cp.ReadinessReasons = make([]string, len(rg.ReadinessReasons))
		copy(cp.ReadinessReasons, rg.ReadinessReasons)
	}
	fn := m.transferReadinessFn
	m.mu.RUnlock()
	if fn != nil {
		cp.TransferReady, cp.TransferReadinessReasons = fn(rgID)
		if len(cp.TransferReadinessReasons) > 0 {
			cp.TransferReadinessReasons = append([]string(nil), cp.TransferReadinessReasons...)
		}
	} else {
		cp.TransferReady = true
	}
	return &cp
}

// IsLocalPrimary returns true if this node is primary for the given RG.
func (m *Manager) IsLocalPrimary(rgID int) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if rg, ok := m.groups[rgID]; ok {
		return rg.State == StatePrimary
	}
	return false
}

// IsPeerPrimary reports whether the PEER node is primary for the given RG,
// per the last heartbeat-advertised peer group state. It returns false when the
// peer is not alive, the RG is unknown to the peer, or the peer is in any
// non-primary state (secondary, secondary-hold, election, disabled, lost).
//
// MonitorInterface uses this to proxy a locally-present RETH ONLY when the peer
// actually OWNS the RG. Proxying merely because the LOCAL node is not primary
// lets two non-primary nodes (both-secondary / election / sync-hold) forward
// the request to each other in an A->B->A loop that storms
// connections/streams/goroutines (#5497).
func (m *Manager) IsPeerPrimary(rgID int) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.peerAlive {
		return false
	}
	if pg, ok := m.peerGroups[rgID]; ok {
		return pg.State == StatePrimary
	}
	return false
}

// IsLocalPrimaryAny returns true if this node is primary for any RG.
func (m *Manager) IsLocalPrimaryAny() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, rg := range m.groups {
		if rg.State == StatePrimary {
			return true
		}
	}
	return false
}

// LocalPriorities returns a map of redundancy group ID to VRRP priority.
// Primary RGs get priority 200, all others get 100.
func (m *Manager) LocalPriorities() map[int]int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[int]int, len(m.groups))
	for _, rg := range m.groups {
		if rg.State == StatePrimary {
			result[rg.GroupID] = 200
		} else {
			result[rg.GroupID] = 100
		}
	}
	return result
}
