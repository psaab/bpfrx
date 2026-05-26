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
	for id := range m.groups {
		if !seen[id] {
			for k := range m.monitorWeights {
				if k.rgID == id {
					delete(m.monitorWeights, k)
				}
			}
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
