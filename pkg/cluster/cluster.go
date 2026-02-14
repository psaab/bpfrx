package cluster

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/psaab/bpfrx/pkg/config"
)

// NodeState represents the HA state of a node for a redundancy group.
type NodeState int

const (
	StateSecondary     NodeState = iota // backup/standby
	StatePrimary                        // active/master
	StateSecondaryHold                  // waiting before claiming primary
	StateLost                           // peer unreachable
	StateDisabled                       // administratively disabled
)

func (s NodeState) String() string {
	switch s {
	case StateSecondary:
		return "secondary"
	case StatePrimary:
		return "primary"
	case StateSecondaryHold:
		return "secondary-hold"
	case StateLost:
		return "lost"
	case StateDisabled:
		return "disabled"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// RedundancyGroupState holds the runtime state of a single redundancy group.
type RedundancyGroupState struct {
	GroupID        int
	LocalPriority  int
	PeerPriority   int
	State          NodeState
	Preempt        bool
	ManualFailover bool     // true if manually forced
	Weight         int      // current effective weight (255 - sum of down monitor weights)
	FailoverCount  int
	MonitorFails   []string // names of currently-failed monitors
}

// ClusterEvent signals a state change in the cluster.
type ClusterEvent struct {
	GroupID  int
	OldState NodeState
	NewState NodeState
}

// monitorKey uniquely identifies a monitor within a redundancy group.
type monitorKey struct {
	rgID  int
	iface string
}

// Manager manages cluster redundancy group states.
type Manager struct {
	nodeID         int
	clusterID      int
	groups         map[int]*RedundancyGroupState
	monitorWeights map[monitorKey]int // per-RG per-interface monitor weights
	mu             sync.RWMutex
	eventCh        chan ClusterEvent
}

// NewManager creates a new cluster manager.
func NewManager(nodeID, clusterID int) *Manager {
	return &Manager{
		nodeID:         nodeID,
		clusterID:      clusterID,
		groups:         make(map[int]*RedundancyGroupState),
		monitorWeights: make(map[monitorKey]int),
		eventCh:        make(chan ClusterEvent, 64),
	}
}

// NodeID returns the local node ID.
func (m *Manager) NodeID() int { return m.nodeID }

// ClusterID returns the cluster ID.
func (m *Manager) ClusterID() int { return m.clusterID }

// Events returns the event channel for state change notifications.
func (m *Manager) Events() <-chan ClusterEvent { return m.eventCh }

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

	// Single-node election: if no peer, highest priority node is primary.
	m.electSingleNode()
}

// electSingleNode performs election when no heartbeat peer is present.
// In single-node mode, the local node is always primary if weight > 0.
func (m *Manager) electSingleNode() {
	for _, rg := range m.groups {
		if rg.State == StateDisabled || rg.ManualFailover {
			continue
		}
		oldState := rg.State
		if rg.Weight > 0 {
			rg.State = StatePrimary
		} else {
			rg.State = StateSecondary
		}
		if oldState != rg.State {
			m.sendEvent(rg.GroupID, oldState, rg.State)
		}
	}
}

// SetMonitorWeight updates the weight contribution of an interface monitor.
// down=true subtracts weight; down=false restores it.
func (m *Manager) SetMonitorWeight(rgID int, iface string, down bool, weight int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rg, ok := m.groups[rgID]
	if !ok {
		return
	}

	key := monitorKey{rgID: rgID, iface: iface}

	if down {
		// Record the monitor weight and add to failure list.
		m.monitorWeights[key] = weight
		found := false
		for _, f := range rg.MonitorFails {
			if f == iface {
				found = true
				break
			}
		}
		if !found {
			rg.MonitorFails = append(rg.MonitorFails, iface)
			sort.Strings(rg.MonitorFails)
			slog.Warn("cluster: interface monitor failure",
				"rg", rgID, "interface", iface, "weight", weight)
		}
	} else {
		// Remove from failures and delete stored weight.
		delete(m.monitorWeights, key)
		for i, f := range rg.MonitorFails {
			if f == iface {
				rg.MonitorFails = append(rg.MonitorFails[:i], rg.MonitorFails[i+1:]...)
				slog.Info("cluster: interface monitor recovered",
					"rg", rgID, "interface", iface)
				break
			}
		}
	}

	m.recalcWeight(rg)
}

// recalcWeight recalculates the effective weight for a redundancy group
// and triggers re-election if needed.
func (m *Manager) recalcWeight(rg *RedundancyGroupState) {
	totalLost := 0
	for _, iface := range rg.MonitorFails {
		key := monitorKey{rgID: rg.GroupID, iface: iface}
		totalLost += m.monitorWeights[key]
	}
	oldWeight := rg.Weight
	rg.Weight = 255 - totalLost
	if rg.Weight < 0 {
		rg.Weight = 0
	}
	if oldWeight != rg.Weight {
		slog.Info("cluster: weight changed",
			"rg", rg.GroupID, "old", oldWeight, "new", rg.Weight)
	}
	m.electSingleNode()
}

// GroupStates returns a snapshot of all redundancy group states.
func (m *Manager) GroupStates() []RedundancyGroupState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	states := make([]RedundancyGroupState, 0, len(m.groups))
	for _, rg := range m.groups {
		cp := *rg
		if len(rg.MonitorFails) > 0 {
			cp.MonitorFails = make([]string, len(rg.MonitorFails))
			copy(cp.MonitorFails, rg.MonitorFails)
		}
		states = append(states, cp)
	}
	sort.Slice(states, func(i, j int) bool {
		return states[i].GroupID < states[j].GroupID
	})
	return states
}

// GroupState returns the state for a specific redundancy group, or nil if not found.
func (m *Manager) GroupState(rgID int) *RedundancyGroupState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rg, ok := m.groups[rgID]
	if !ok {
		return nil
	}
	cp := *rg
	if len(rg.MonitorFails) > 0 {
		cp.MonitorFails = make([]string, len(rg.MonitorFails))
		copy(cp.MonitorFails, rg.MonitorFails)
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

// ManualFailover forces a redundancy group to failover.
func (m *Manager) ManualFailover(rgID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rg, ok := m.groups[rgID]
	if !ok {
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	oldState := rg.State
	rg.ManualFailover = true
	rg.State = StateSecondary
	rg.FailoverCount++
	if oldState != rg.State {
		m.sendEvent(rg.GroupID, oldState, rg.State)
	}
	slog.Info("cluster: manual failover", "rg", rgID)
	return nil
}

// ResetFailover clears manual failover and resumes normal election.
func (m *Manager) ResetFailover(rgID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rg, ok := m.groups[rgID]
	if !ok {
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	rg.ManualFailover = false
	m.electSingleNode()
	slog.Info("cluster: failover reset", "rg", rgID)
	return nil
}

func (m *Manager) sendEvent(groupID int, oldState, newState NodeState) {
	select {
	case m.eventCh <- ClusterEvent{GroupID: groupID, OldState: oldState, NewState: newState}:
	default:
		slog.Warn("cluster: event channel full, dropping event",
			"rg", groupID, "old", oldState, "new", newState)
	}
}

// FormatStatus returns a Junos-style status string for all RGs.
func (m *Manager) FormatStatus() string {
	states := m.GroupStates()
	var b strings.Builder
	fmt.Fprintf(&b, "Cluster ID: %d\n", m.clusterID)
	fmt.Fprintf(&b, "Node name: node%d\n\n", m.nodeID)
	fmt.Fprintf(&b, "%-6s %-8s %-14s %-8s %-8s %s\n",
		"Node", "Priority", "Status", "Preempt", "Manual", "Monitor-failures")
	fmt.Fprintln(&b)

	for _, rg := range states {
		fmt.Fprintf(&b, "Redundancy group: %d , Failover count: %d\n",
			rg.GroupID, rg.FailoverCount)
		preempt := "no"
		if rg.Preempt {
			preempt = "yes"
		}
		manual := "no"
		if rg.ManualFailover {
			manual = "yes"
		}
		monFails := "None"
		if len(rg.MonitorFails) > 0 {
			monFails = strings.Join(rg.MonitorFails, ", ")
		}
		fmt.Fprintf(&b, "%-6s %-8d %-14s %-8s %-8s %s\n",
			fmt.Sprintf("node%d", m.nodeID),
			rg.LocalPriority, rg.State, preempt, manual, monFails)
		fmt.Fprintln(&b)
	}
	return b.String()
}
