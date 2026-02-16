package cluster

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
	"golang.org/x/sys/unix"
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

// RethIPMapping maps a RETH interface to its IP addresses (for GARP).
type RethIPMapping struct {
	Interface string
	IPs       []net.IP
	RG        int // redundancy group ID
}

// Manager manages cluster redundancy group states.
type Manager struct {
	nodeID         int
	clusterID      int
	groups         map[int]*RedundancyGroupState
	monitorWeights map[monitorKey]int // per-RG per-interface monitor weights
	mu             sync.RWMutex
	eventCh        chan ClusterEvent
	monitor        *Monitor
	rethIPs        []RethIPMapping
	garpCounts     map[int]int // rgID -> gratuitous ARP count from config

	// Peer state tracking (heartbeat).
	peerAlive    bool
	peerNodeID   int
	peerGroups   map[int]PeerGroupState

	// Heartbeat goroutines (nil when not started).
	hbSender   *heartbeatSender
	hbReceiver *heartbeatReceiver

	// Heartbeat config.
	controlInterface string
	hbInterval       time.Duration
	hbThreshold      int
}

// NewManager creates a new cluster manager.
func NewManager(nodeID, clusterID int) *Manager {
	return &Manager{
		nodeID:         nodeID,
		clusterID:      clusterID,
		groups:         make(map[int]*RedundancyGroupState),
		monitorWeights: make(map[monitorKey]int),
		eventCh:        make(chan ClusterEvent, 64),
		garpCounts:     make(map[int]int),
		peerGroups:     make(map[int]PeerGroupState),
		hbInterval:     DefaultHeartbeatInterval,
		hbThreshold:    DefaultHeartbeatThreshold,
	}
}

// NodeID returns the local node ID.
func (m *Manager) NodeID() int { return m.nodeID }

// ClusterID returns the cluster ID.
func (m *Manager) ClusterID() int { return m.clusterID }

// Events returns the event channel for state change notifications.
func (m *Manager) Events() <-chan ClusterEvent { return m.eventCh }

// PeerAlive returns whether the peer node is reachable.
func (m *Manager) PeerAlive() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.peerAlive
}

// PeerNodeID returns the peer's node ID (valid only when PeerAlive is true).
func (m *Manager) PeerNodeID() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.peerNodeID
}

// PeerGroupStates returns a snapshot of the peer's RG states.
func (m *Manager) PeerGroupStates() map[int]PeerGroupState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := make(map[int]PeerGroupState, len(m.peerGroups))
	for k, v := range m.peerGroups {
		cp[k] = v
	}
	return cp
}

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
	if m.peerAlive {
		m.runElection()
	} else {
		m.electSingleNode()
	}
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

// ForceSecondary sets weight to 0 for all redundancy groups, forcing this node
// to become secondary. Used by ISSU to drain traffic to the peer before upgrade.
// Returns an error if the peer is not alive (no peer to take over).
func (m *Manager) ForceSecondary() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.peerAlive {
		return fmt.Errorf("peer not alive — cannot force secondary without active peer")
	}

	for _, rg := range m.groups {
		if rg.State == StateDisabled {
			continue
		}
		oldState := rg.State
		rg.Weight = 0
		rg.ManualFailover = true
		rg.State = StateSecondary
		if oldState != rg.State {
			rg.FailoverCount++
			m.sendEvent(rg.GroupID, oldState, rg.State)
		}
	}

	slog.Info("cluster: forced secondary for all RGs (ISSU)")
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
	if m.peerAlive {
		m.runElection()
	} else {
		m.electSingleNode()
	}
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

	// Trigger GARP on transition to primary.
	if newState == StatePrimary && oldState != StatePrimary {
		m.triggerGARP(groupID)
	}
}

// Start begins periodic interface/IP monitoring.
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.monitor != nil {
		m.monitor.Stop()
	}
	m.monitor = NewMonitor(m, nil) // groups set via UpdateConfig
	m.monitor.Start(ctx)
}

// Stop halts monitoring and heartbeat goroutines.
func (m *Manager) Stop() {
	m.mu.Lock()
	mon := m.monitor
	sender := m.hbSender
	receiver := m.hbReceiver
	m.hbSender = nil
	m.hbReceiver = nil
	m.mu.Unlock()

	if mon != nil {
		mon.Stop()
	}
	if sender != nil {
		sender.stop()
	}
	if receiver != nil {
		receiver.stop()
	}
}

// StartHeartbeat launches heartbeat sender and receiver goroutines.
// localAddr is the local control link IP, peerAddr is the peer control link IP.
// vrfDevice is optional — if non-empty, sockets bind to that VRF device so
// packets route through the correct table.
func (m *Manager) StartHeartbeat(localAddr, peerAddr, vrfDevice string) error {
	m.mu.Lock()
	interval := m.hbInterval
	threshold := m.hbThreshold
	m.mu.Unlock()

	// Resolve peer address.
	peer, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", peerAddr, HeartbeatPort))
	if err != nil {
		return fmt.Errorf("resolve peer addr: %w", err)
	}

	// Bind receiver to local address.
	local, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", localAddr, HeartbeatPort))
	if err != nil {
		return fmt.Errorf("resolve local addr: %w", err)
	}

	lc := vrfListenConfig(vrfDevice)

	recvPkt, err := lc.ListenPacket(context.Background(), "udp4", local.String())
	if err != nil {
		return fmt.Errorf("listen heartbeat: %w", err)
	}
	recvConn := recvPkt.(*net.UDPConn)

	// Create sender socket (bound to local address).
	sendAddr := fmt.Sprintf("%s:0", localAddr)
	sendPkt, err := lc.ListenPacket(context.Background(), "udp4", sendAddr)
	if err != nil {
		recvConn.Close()
		return fmt.Errorf("sender socket: %w", err)
	}
	sendConn := sendPkt.(*net.UDPConn)

	m.mu.Lock()
	m.hbSender = newHeartbeatSender(m, sendConn, peer, interval)
	m.hbReceiver = newHeartbeatReceiver(m, recvConn, threshold, interval)
	m.mu.Unlock()

	m.hbReceiver.start()
	m.hbSender.start()

	slog.Info("cluster: heartbeat started",
		"local", localAddr, "peer", peerAddr,
		"interval", interval, "threshold", threshold)
	return nil
}

// vrfListenConfig returns a net.ListenConfig that binds sockets to a VRF device
// via SO_BINDTODEVICE. If vrfDevice is empty, returns a default ListenConfig.
func vrfListenConfig(vrfDevice string) net.ListenConfig {
	if vrfDevice == "" {
		return net.ListenConfig{}
	}
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET,
					syscall.SO_BINDTODEVICE, vrfDevice)
			})
			return err
		},
	}
}

// StopHeartbeat halts heartbeat sender and receiver goroutines.
func (m *Manager) StopHeartbeat() {
	m.mu.Lock()
	sender := m.hbSender
	receiver := m.hbReceiver
	m.hbSender = nil
	m.hbReceiver = nil
	m.mu.Unlock()

	if sender != nil {
		sender.stop()
	}
	if receiver != nil {
		receiver.stop()
	}
}

// buildHeartbeat creates a heartbeat packet from current state.
func (m *Manager) buildHeartbeat() *HeartbeatPacket {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pkt := &HeartbeatPacket{
		NodeID:    uint8(m.nodeID),
		ClusterID: uint16(m.clusterID),
	}
	for _, rg := range m.groups {
		pkt.Groups = append(pkt.Groups, HeartbeatGroup{
			GroupID:  uint8(rg.GroupID),
			Priority: uint16(rg.LocalPriority),
			Weight:   uint8(rg.Weight),
			State:    uint8(rg.State),
		})
	}
	return pkt
}

// handlePeerHeartbeat processes an incoming peer heartbeat.
func (m *Manager) handlePeerHeartbeat(pkt *HeartbeatPacket) {
	m.mu.Lock()
	defer m.mu.Unlock()

	wasAlive := m.peerAlive
	m.peerAlive = true
	m.peerNodeID = int(pkt.NodeID)

	// Update peer group states.
	for _, g := range pkt.Groups {
		m.peerGroups[int(g.GroupID)] = PeerGroupState{
			GroupID:  int(g.GroupID),
			Priority: int(g.Priority),
			Weight:   int(g.Weight),
			State:    NodeState(g.State),
		}
	}

	// Update PeerPriority on local RG state for display.
	for _, rg := range m.groups {
		if pg, ok := m.peerGroups[rg.GroupID]; ok {
			rg.PeerPriority = pg.Priority
		}
	}

	if !wasAlive {
		slog.Info("cluster: peer heartbeat received",
			"peer_node", pkt.NodeID, "groups", len(pkt.Groups))
	}

	m.runElection()
}

// handlePeerTimeout is called when the peer heartbeat timeout expires.
func (m *Manager) handlePeerTimeout() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.peerAlive {
		return // already marked lost
	}

	m.peerAlive = false
	m.peerGroups = make(map[int]PeerGroupState)
	slog.Warn("cluster: peer heartbeat timeout, marking peer lost")

	// Peer lost: re-run single-node election.
	m.electSingleNode()
}

// RegisterRethIPs stores RETH interface→IP mappings for GARP on primary transition.
func (m *Manager) RegisterRethIPs(mappings []RethIPMapping) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rethIPs = mappings
}

// triggerGARP sends gratuitous ARPs (IPv4) and unsolicited Neighbor
// Advertisements (IPv6) for all RETH interfaces in the given RG.
// Called internally when a transition to primary is detected (holds m.mu).
func (m *Manager) triggerGARP(rgID int) {
	// Snapshot under lock (called with lock held, so read fields directly).
	rethIPs := m.rethIPs
	count := m.garpCounts[rgID]
	if count <= 0 {
		count = 4
	}

	// Send GARP/NA in a goroutine to avoid holding the lock during I/O.
	go func() {
		for _, mapping := range rethIPs {
			if mapping.RG != rgID {
				continue
			}
			for _, ip := range mapping.IPs {
				if ip.To4() != nil {
					if err := SendGratuitousARP(mapping.Interface, ip, count); err != nil {
						slog.Warn("cluster: failed to send GARP",
							"interface", mapping.Interface, "ip", ip, "err", err)
					}
				} else {
					if err := SendGratuitousIPv6(mapping.Interface, ip, count); err != nil {
						slog.Warn("cluster: failed to send IPv6 NA",
							"interface", mapping.Interface, "ip", ip, "err", err)
					}
				}
			}
		}
	}()
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

// FormatStatus returns a Junos-style status string for all RGs.
func (m *Manager) FormatStatus() string {
	states := m.GroupStates()
	m.mu.RLock()
	peerAlive := m.peerAlive
	peerNodeID := m.peerNodeID
	peerGroups := make(map[int]PeerGroupState, len(m.peerGroups))
	for k, v := range m.peerGroups {
		peerGroups[k] = v
	}
	m.mu.RUnlock()

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
		// Local node line.
		fmt.Fprintf(&b, "%-6s %-8d %-14s %-8s %-8s %s\n",
			fmt.Sprintf("node%d", m.nodeID),
			rg.LocalPriority, rg.State, preempt, manual, monFails)
		// Peer node line (if alive).
		if peerAlive {
			if pg, ok := peerGroups[rg.GroupID]; ok {
				fmt.Fprintf(&b, "%-6s %-8d %-14s %-8s %-8s %s\n",
					fmt.Sprintf("node%d", peerNodeID),
					pg.Priority, pg.State, preempt, "no", "None")
			}
		}
		fmt.Fprintln(&b)
	}
	return b.String()
}

// FormatInformation returns detailed cluster information.
func (m *Manager) FormatInformation() string {
	m.mu.RLock()
	peerAlive := m.peerAlive
	peerNodeID := m.peerNodeID
	interval := m.hbInterval
	threshold := m.hbThreshold
	controlIface := m.controlInterface
	m.mu.RUnlock()

	var b strings.Builder
	fmt.Fprintf(&b, "Cluster ID: %d\n", m.clusterID)
	fmt.Fprintf(&b, "Node ID: %d\n", m.nodeID)
	fmt.Fprintf(&b, "Heartbeat interval: %d ms\n", interval.Milliseconds())
	fmt.Fprintf(&b, "Heartbeat threshold: %d\n", threshold)
	if controlIface != "" {
		fmt.Fprintf(&b, "Control interface: %s\n", controlIface)
	}

	peerStatus := "lost"
	if peerAlive {
		peerStatus = fmt.Sprintf("alive (node%d)", peerNodeID)
	}
	fmt.Fprintf(&b, "Peer status: %s\n", peerStatus)

	states := m.GroupStates()
	fmt.Fprintf(&b, "Redundancy groups: %d\n\n", len(states))

	for _, rg := range states {
		fmt.Fprintf(&b, "Redundancy group %d:\n", rg.GroupID)
		fmt.Fprintf(&b, "  Local priority: %d\n", rg.LocalPriority)
		fmt.Fprintf(&b, "  Peer priority: %d\n", rg.PeerPriority)
		fmt.Fprintf(&b, "  Local state: %s\n", rg.State)
		fmt.Fprintf(&b, "  Weight: %d\n", rg.Weight)
		fmt.Fprintf(&b, "  Effective priority: %d\n", EffectivePriority(rg.LocalPriority, rg.Weight))
		preempt := "no"
		if rg.Preempt {
			preempt = "yes"
		}
		fmt.Fprintf(&b, "  Preempt: %s\n", preempt)
		fmt.Fprintf(&b, "  Failover count: %d\n", rg.FailoverCount)
		if len(rg.MonitorFails) > 0 {
			fmt.Fprintf(&b, "  Monitor failures: %s\n", strings.Join(rg.MonitorFails, ", "))
		}
		fmt.Fprintln(&b)
	}
	return b.String()
}
