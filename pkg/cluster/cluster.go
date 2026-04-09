package cluster

import (
	"context"
	"errors"
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
	GroupID          int
	LocalPriority    int
	PeerPriority     int
	State            NodeState
	Preempt          bool
	ManualFailover   bool      // true if manually forced
	ManualFailoverAt time.Time // when ManualFailover was set (for deadlock detection)
	Weight           int       // current effective weight (255 - sum of down monitor weights)
	FailoverCount    int
	MonitorFails     []string // names of currently-failed monitors

	// Readiness gate: blocks promotion to primary until interfaces + VRRP
	// are confirmed ready. TakeoverHoldTime is an optional extra delay.
	Ready            bool        // true if all local prerequisites are satisfied
	ReadySince       time.Time   // when Ready transitioned to true (zero if not ready)
	ReadinessReasons []string    // reasons why not ready (empty when ready)
	holdTimer        *time.Timer // fires at ReadySince+holdTime to re-trigger election

	// Transfer readiness is the stricter explicit-manual-failover readiness.
	// It intentionally stays separate from takeover readiness so operators can
	// distinguish election readiness from transfer protocol readiness.
	TransferReady            bool
	TransferReadinessReasons []string
}

// IsReadyForTakeover returns true if the RG has been ready for at least
// the specified hold time duration. Used by election to gate promotion.
func (rg *RedundancyGroupState) IsReadyForTakeover(holdTime time.Duration) bool {
	return rg.Ready && !rg.ReadySince.IsZero() && time.Since(rg.ReadySince) >= holdTime
}

// ClusterEvent signals a state change in the cluster.
type ClusterEvent struct {
	GroupID       int
	OldState      NodeState
	NewState      NodeState
	DualActiveWin bool // true when dual-active resolved with local node as winner (no state change)
}

// RetryablePreFailoverError marks a pre-manual-failover hook error as
// transient. ManualFailover retries these for a bounded window instead of
// failing the operator request immediately.
type RetryablePreFailoverError struct {
	Err error
}

func (e *RetryablePreFailoverError) Error() string { return e.Err.Error() }
func (e *RetryablePreFailoverError) Unwrap() error { return e.Err }

func IsRetryablePreFailoverError(err error) bool {
	var target *RetryablePreFailoverError
	return errors.As(err, &target)
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
	monitor        *Monitor
	garpCounts     map[int]int // rgID -> gratuitous ARP count from config
	history        *EventHistory

	// Peer state tracking (heartbeat).
	peerAlive    bool
	peerEverSeen bool // true once first heartbeat received; distinguishes "never heard" from "lost"
	peerNodeID   int
	peerGroups   map[int]PeerGroupState
	// Optional software version metadata advertised via heartbeat.
	localSoftwareVersion string
	peerSoftwareVersion  string
	// peerTransferOutOverride preserves an explicitly acknowledged peer
	// transfer-out across heartbeat refreshes until the transfer is either
	// committed or aborted locally.
	peerTransferOutOverride map[int]uint64
	// peerTransferCommitGraceUntil keeps the peer in secondary-hold for a
	// short window after a transfer commit so a transient stale heartbeat
	// cannot immediately steal the RG back from the new primary.
	peerTransferCommitGraceUntil map[int]time.Time
	// localTransferOutHoldUntil keeps a just-demoted local RG parked in
	// secondary during the same window so a transient heartbeat gap cannot
	// immediately re-promote the old primary.
	localTransferOutHoldUntil map[int]time.Time
	peerTransferOutPrevious map[int]peerGroupSnapshot
	peerMonitors            []InterfaceMonitorInfo

	// Heartbeat goroutines (nil when not started).
	hbSender   *heartbeatSender
	hbReceiver *heartbeatReceiver

	// Heartbeat config.
	controlInterface string
	hbInterval       time.Duration
	hbThreshold      int
	hbLocalAddr      string // last StartHeartbeat localAddr (for restart)
	hbPeerAddr       string // last StartHeartbeat peerAddr (for restart)
	hbVRFDevice      string // last StartHeartbeat vrfDevice (for restart)

	// Sync stats provider (set by daemon after sessionSync creation).
	syncStats SyncStatsProvider

	// peerFailoverFn sends a remote failover request to the peer and returns
	// the acknowledged request ID for the transfer.
	peerFailoverFn func(rgID int) (uint64, error)

	// peerFailoverCommitFn sends the transfer-commit message after the local
	// node has explicitly assumed primary ownership.
	peerFailoverCommitFn func(rgID int, reqID uint64) error

	// peerFailoverBatchFn sends an explicit transfer-out request for multiple
	// redundancy groups that must move together in one handoff unit.
	peerFailoverBatchFn func(rgIDs []int) (uint64, error)

	// peerFailoverCommitBatchFn sends the ownership-commit message for a
	// previously acknowledged multi-RG transfer.
	peerFailoverCommitBatchFn func(rgIDs []int, reqID uint64) error

	// peerFenceFn sends a fence (disable-rg) message to the peer.
	// Set by daemon after sessionSync creation.
	peerFenceFn func() error

	// peerTimeoutGuardFn can suppress heartbeat-driven peer loss when an
	// external signal proves the peer is still alive (for example, recent
	// session-sync traffic on the control link).
	peerTimeoutGuardFn func() (suppress bool, reason string)

	// preManualFailoverFn runs before the local node resigns an RG.
	// The daemon uses this to pre-stage userspace continuity before
	// weight/state changes let the peer take over.
	preManualFailoverFn func(rgID int) error
	// transferReadinessFn reports whether explicit manual failover can be
	// attempted for the local RG right now and, if not, why.
	transferReadinessFn func(rgID int) (bool, []string)
	// localTransferCommitReadyFn runs on the requesting node after local
	// ownership has been committed but before the final peer-demotion
	// commit is sent. The daemon uses this to ensure the target node has
	// actually applied its local failover side effects before the old
	// owner is told to stand down.
	localTransferCommitReadyFn func(rgIDs []int) error
	// Retry policy for transient pre-failover prepare failures.
	preManualFailoverRetryTimeout  time.Duration
	preManualFailoverRetryInterval time.Duration
	// peerFencing holds the configured fencing action (e.g. "disable-rg").
	peerFencing string

	// onEventDrop is called when a cluster event is dropped due to a full
	// channel. The daemon uses this to trigger immediate reconciliation.
	onEventDrop func()

	// takeoverHoldTime is the minimum duration an RG must be ready before
	// election will promote it to primary. Zero means immediate takeover
	// once readiness is established.
	takeoverHoldTime time.Duration

	// syncReady is true once bulk session sync has been received (or timed
	// out). Used in private-rg-election / no-reth-vrrp mode as the
	// equivalent of VRRP sync-hold — gates RG promotion until session state
	// is synchronized from the peer.
	syncReady bool

	// syncTransport records whether session sync uses "fabric" or
	// "control-link" transport. Displayed in CLI status.
	syncTransport string

	// failoverInProgress tracks per-RG failover serialization. When a
	// ManualFailover is in progress for an RG (including the preHook
	// barrier wait), a second request for the same RG is rejected
	// immediately. This prevents back-to-back failover/failback from
	// racing and hitting "session sync disconnected during barrier wait".
	failoverInProgress map[int]bool
}

type peerGroupSnapshot struct {
	state   PeerGroupState
	present bool
}

// DefaultTakeoverHoldTime is the default additional delay after an RG becomes
// ready before election promotes it to primary. Zero means promote as soon as
// readiness is established.
const DefaultTakeoverHoldTime = 0
const DefaultPreManualFailoverRetryTimeout = 5 * time.Second
const DefaultPreManualFailoverRetryInterval = 500 * time.Millisecond
const minTransferCommitGracePeriod = 10 * time.Second
const transferCommitHeartbeatSlack = 5 * time.Second

// NewManager creates a new cluster manager.
func NewManager(nodeID, clusterID int) *Manager {
	return &Manager{
		nodeID:                         nodeID,
		clusterID:                      clusterID,
		groups:                         make(map[int]*RedundancyGroupState),
		monitorWeights:                 make(map[monitorKey]int),
		eventCh:                        make(chan ClusterEvent, 64),
		garpCounts:                     make(map[int]int),
		peerGroups:                     make(map[int]PeerGroupState),
		peerTransferOutOverride:        make(map[int]uint64),
		peerTransferCommitGraceUntil:   make(map[int]time.Time),
		localTransferOutHoldUntil:      make(map[int]time.Time),
		peerTransferOutPrevious:        make(map[int]peerGroupSnapshot),
		hbInterval:                     DefaultHeartbeatInterval,
		hbThreshold:                    DefaultHeartbeatThreshold,
		history:                        NewEventHistory(64),
		takeoverHoldTime:               DefaultTakeoverHoldTime,
		preManualFailoverRetryTimeout:  DefaultPreManualFailoverRetryTimeout,
		preManualFailoverRetryInterval: DefaultPreManualFailoverRetryInterval,
		failoverInProgress:             make(map[int]bool),
	}
}

func (m *Manager) applyPeerTransferOutOverrideLocked(rgID int, reqID uint64) {
	previous, ok := m.peerGroups[rgID]
	m.peerTransferOutOverride[rgID] = reqID
	m.peerTransferOutPrevious[rgID] = peerGroupSnapshot{
		state:   previous,
		present: ok,
	}
	peerGroup := previous
	peerGroup.GroupID = rgID
	peerGroup.State = StateSecondaryHold
	m.peerGroups[rgID] = peerGroup
	if rg := m.groups[rgID]; rg != nil {
		rg.PeerPriority = peerGroup.Priority
	}
}

func (m *Manager) clearPeerTransferOutOverrideLocked(rgID int) {
	delete(m.peerTransferOutOverride, rgID)
	delete(m.peerTransferOutPrevious, rgID)
}

func (m *Manager) restorePeerTransferOutOverrideLocked(rgID int, reqID uint64) bool {
	currentReqID, ok := m.peerTransferOutOverride[rgID]
	if !ok || currentReqID != reqID {
		return false
	}
	delete(m.peerTransferOutOverride, rgID)
	snapshot, hadSnapshot := m.peerTransferOutPrevious[rgID]
	delete(m.peerTransferOutPrevious, rgID)
	if hadSnapshot && snapshot.present {
		// A fresh heartbeat can race this restore and overwrite peerGroups
		// with newer live state. If that happens we may briefly put the older
		// snapshot back here, but the next heartbeat corrects it again.
		m.peerGroups[rgID] = snapshot.state
	} else {
		delete(m.peerGroups, rgID)
	}
	if rg := m.groups[rgID]; rg != nil {
		if snapshot.present {
			rg.PeerPriority = snapshot.state.Priority
		} else {
			rg.PeerPriority = 0
		}
	}
	return true
}

// NodeID returns the local node ID.
func (m *Manager) NodeID() int { return m.nodeID }

// ClusterID returns the cluster ID.
func (m *Manager) ClusterID() int { return m.clusterID }

// Events returns the event channel for state change notifications.
func (m *Manager) Events() <-chan ClusterEvent { return m.eventCh }

// Monitor returns the cluster interface/IP monitor, or nil if not set.
func (m *Manager) Monitor() *Monitor {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.monitor
}

// SetSyncReady marks session sync as ready (bulk sync received or timed out).
// In private-rg-election mode this gates RG promotion via the readiness pipeline.
func (m *Manager) SetSyncReady(ready bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.syncReady == ready {
		return
	}
	m.syncReady = ready
	slog.Info("cluster: sync readiness changed", "ready", ready)
}

// IsSyncReady returns true if session sync is ready.
func (m *Manager) IsSyncReady() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.syncReady
}

// SetSyncTransport records the active sync transport mode ("fabric" or "control-link").
func (m *Manager) SetSyncTransport(transport string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncTransport = transport
}

// SyncTransport returns the active sync transport mode.
func (m *Manager) SyncTransport() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.syncTransport == "" {
		return "fabric"
	}
	return m.syncTransport
}

// SetRGReady updates the readiness state for a redundancy group.
// When transitioning not-ready → ready, sets ReadySince to now.
// When transitioning ready → not-ready, clears ReadySince and stores reasons.
// After any change, triggers re-election to evaluate the readiness gate.
func (m *Manager) SetRGReady(rgID int, ready bool, reasons []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rg, ok := m.groups[rgID]
	if !ok {
		return
	}

	wasReady := rg.Ready
	rg.Ready = ready

	if ready && !wasReady {
		// Transition: not-ready → ready.
		rg.ReadySince = time.Now()
		rg.ReadinessReasons = nil
		slog.Info("cluster: RG readiness: ready", "rg", rgID)

		// Schedule a wakeup at ReadySince + takeoverHoldTime to
		// re-trigger election. Without this, the edge-triggered
		// election at readiness change would check too early (hold
		// time not yet elapsed) and never retry.
		if m.takeoverHoldTime > 0 {
			if rg.holdTimer != nil {
				rg.holdTimer.Stop()
			}
			rg.holdTimer = time.AfterFunc(m.takeoverHoldTime, func() {
				m.mu.Lock()
				defer m.mu.Unlock()
				if !rg.Ready {
					return
				}
				slog.Info("cluster: hold timer expired, re-evaluating election", "rg", rgID)
				if m.peerAlive {
					m.runElection()
				} else {
					m.electSingleNode()
				}
			})
		}
	} else if !ready && wasReady {
		// Transition: ready → not-ready.
		rg.ReadySince = time.Time{}
		rg.ReadinessReasons = reasons
		if rg.holdTimer != nil {
			rg.holdTimer.Stop()
			rg.holdTimer = nil
		}
		slog.Info("cluster: RG readiness: not ready", "rg", rgID, "reasons", reasons)
	} else if !ready {
		// Still not ready — update reasons.
		rg.ReadinessReasons = reasons
	}

	// Re-evaluate election on readiness change.
	if wasReady != ready {
		if m.peerAlive {
			m.runElection()
		} else {
			m.electSingleNode()
		}
	}
}

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

// SetSoftwareVersion records the local software version advertised to the peer.
func (m *Manager) SetSoftwareVersion(version string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(version) > maxHeartbeatSoftwareVersionSize {
		version = version[:maxHeartbeatSoftwareVersionSize]
	}
	m.localSoftwareVersion = version
}

// SoftwareVersions returns the currently known local and peer software versions.
func (m *Manager) SoftwareVersions() (local, peer string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.localSoftwareVersion, m.peerSoftwareVersion
}

// SoftwareVersionMismatch reports whether both sides advertised different versions.
func (m *Manager) SoftwareVersionMismatch() (bool, string, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.localSoftwareVersion == "" || m.peerSoftwareVersion == "" {
		return false, m.localSoftwareVersion, m.peerSoftwareVersion
	}
	return m.localSoftwareVersion != m.peerSoftwareVersion, m.localSoftwareVersion, m.peerSoftwareVersion
}

// PeerMonitorStatuses returns the peer's interface monitor states from heartbeat.
// Returns nil if peer is not alive or no monitor data received.
func (m *Manager) PeerMonitorStatuses() []InterfaceMonitorInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.peerMonitors) == 0 {
		return nil
	}
	cp := make([]InterfaceMonitorInfo, len(m.peerMonitors))
	copy(cp, m.peerMonitors)
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

// electSingleNode performs election when no heartbeat peer is present.
// In single-node mode, the local node is always primary if weight > 0.
// Non-preempt exception: if the peer has never been seen (fresh boot),
// stay secondary and wait for the heartbeat timeout to confirm the peer
// is truly absent before claiming primary.
func (m *Manager) electSingleNode() {
	for _, rg := range m.groups {
		if rg.State == StateDisabled || rg.ManualFailover {
			continue
		}
		// Non-preempt in cluster mode: don't claim primary on fresh boot
		// before hearing from the peer. The peer may be running as
		// primary — wait for heartbeat timeout to confirm it's truly
		// down. controlInterface != "" indicates cluster mode (heartbeat
		// configured); standalone nodes always elect immediately.
		if !rg.Preempt && !m.peerEverSeen && rg.State == StateSecondary && m.controlInterface != "" {
			continue
		}
		// Readiness gate: block new promotions in cluster mode until
		// interfaces + VRRP are confirmed ready for holdTime.
		// Does not gate standalone mode (no controlInterface).
		// Bypass when peer is dead: sync readiness is impossible without
		// a peer, and the surviving node must take over immediately.
		if rg.State != StatePrimary && rg.Weight > 0 && m.controlInterface != "" && m.peerAlive {
			if !rg.IsReadyForTakeover(m.takeoverHoldTime) {
				continue
			}
		}
		oldState := rg.State
		if rg.Weight > 0 {
			rg.State = StatePrimary
		} else {
			rg.State = StateSecondary
		}
		if oldState != rg.State {
			m.sendEvent(rg.GroupID, oldState, rg.State, "Only node present")
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

// ManualFailover forces a redundancy group to transfer out of primary.
// Unlike ForceSecondary, this preserves the group's monitor-derived weight
// and advertises an explicit transfer-out state so the peer can claim
// primary without relying on weight-zero election semantics.
func (m *Manager) ManualFailover(rgID int) error {
	m.mu.Lock()
	rg, ok := m.groups[rgID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	if m.failoverInProgress[rgID] {
		m.mu.Unlock()
		return fmt.Errorf("failover already in progress for redundancy group %d, please wait", rgID)
	}
	m.failoverInProgress[rgID] = true
	preHook := m.preManualFailoverFn
	retryTimeout := m.preManualFailoverRetryTimeout
	retryInterval := m.preManualFailoverRetryInterval
	m.mu.Unlock()

	var preHookErr error
	if preHook != nil {
		deadline := time.Now().Add(retryTimeout)
		for attempts := 1; ; attempts++ {
			if err := preHook(rgID); err != nil {
				if !IsRetryablePreFailoverError(err) {
					preHookErr = fmt.Errorf("pre-failover prepare for redundancy group %d: %w", rgID, err)
					break
				}
				remaining := time.Until(deadline)
				if remaining <= 0 {
					preHookErr = fmt.Errorf("pre-failover prepare for redundancy group %d: %w", rgID, err)
					break
				}
				sleep := retryInterval
				if sleep <= 0 {
					sleep = DefaultPreManualFailoverRetryInterval
				}
				if sleep > remaining {
					sleep = remaining
				}
				slog.Info("cluster: waiting to admit manual failover",
					"rg", rgID,
					"attempt", attempts,
					"remaining", remaining.String(),
					"err", err)
				time.Sleep(sleep)
				continue
			}
			break
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Always clear the in-progress flag under the same lock acquisition
	// that performs the state change, so there is no window where another
	// caller can slip in between flag-clear and state-commit.
	defer delete(m.failoverInProgress, rgID)

	if preHookErr != nil {
		return preHookErr
	}

	rg, ok = m.groups[rgID]
	if !ok {
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	oldState := rg.State
	rg.ManualFailover = true
	rg.ManualFailoverAt = time.Now()
	rg.State = StateSecondaryHold
	rg.FailoverCount++
	if oldState != rg.State {
		m.sendEvent(rg.GroupID, oldState, rg.State, "Manual failover")
	}
	slog.Info("cluster: manual failover", "rg", rgID)
	return nil
}

// SetPreManualFailoverHook registers a callback that runs before ManualFailover
// changes local RG ownership.
func (m *Manager) SetPreManualFailoverHook(fn func(rgID int) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.preManualFailoverFn = fn
}

// SetTransferReadinessFunc sets the callback used to report whether a local
// redundancy group is ready for explicit transfer-based manual failover.
func (m *Manager) SetTransferReadinessFunc(fn func(rgID int) (bool, []string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transferReadinessFn = fn
}

// SetLocalTransferCommitReadyHook registers a callback that runs on the
// requesting node after local ownership is committed and before the final
// peer-demotion commit is sent.
func (m *Manager) SetLocalTransferCommitReadyHook(fn func(rgIDs []int) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.localTransferCommitReadyFn = fn
}

// SetPeerFailoverFunc sets the callback used to send remote failover requests
// to the peer via the fabric sync connection.
func (m *Manager) SetPeerFailoverFunc(fn func(rgID int) (uint64, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFailoverFn = fn
}

// SetPeerFailoverCommitFunc sets the callback used to send remote
// transfer-commit messages via the fabric sync connection.
func (m *Manager) SetPeerFailoverCommitFunc(fn func(rgID int, reqID uint64) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFailoverCommitFn = fn
}

// SetPeerFailoverBatchFunc sets the callback used to send remote multi-RG
// failover requests to the peer via the fabric sync connection.
func (m *Manager) SetPeerFailoverBatchFunc(fn func(rgIDs []int) (uint64, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFailoverBatchFn = fn
}

// SetPeerFailoverCommitBatchFunc sets the callback used to send the final
// multi-RG transfer-commit message via the fabric sync connection.
func (m *Manager) SetPeerFailoverCommitBatchFunc(fn func(rgIDs []int, reqID uint64) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFailoverCommitBatchFn = fn
}

// SetPeerFenceFunc sets the callback used to send a fence message to the
// peer via the fabric sync connection, telling it to disable all RGs.
func (m *Manager) SetPeerFenceFunc(fn func() error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFenceFn = fn
}

// SetPeerTimeoutGuard sets a callback that can suppress heartbeat-driven
// peer-loss if another control-plane signal proves the peer is still alive.
func (m *Manager) SetPeerTimeoutGuard(fn func() (bool, string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerTimeoutGuardFn = fn
}

func (m *Manager) transferCommitGracePeriodLocked() time.Duration {
	grace := 2*time.Duration(m.hbThreshold)*m.hbInterval + transferCommitHeartbeatSlack
	if grace < minTransferCommitGracePeriod {
		grace = minTransferCommitGracePeriod
	}
	return grace
}

func (m *Manager) suppressPeerTimeoutForTransferCommitLocked(now time.Time) (bool, string) {
	activeRGs := make([]int, 0, len(m.localTransferOutHoldUntil))
	for rgID, until := range m.localTransferOutHoldUntil {
		if now.Before(until) {
			activeRGs = append(activeRGs, rgID)
			continue
		}
		delete(m.localTransferOutHoldUntil, rgID)
	}
	if len(activeRGs) == 0 {
		return false, ""
	}
	sort.Ints(activeRGs)
	return true, fmt.Sprintf("recent transfer commit grace active rgs=%v", activeRGs)
}

// FenceStatus returns the configured fencing action and history of fence events.
func (m *Manager) FenceStatus() (action string, events []HistoryEvent) {
	m.mu.RLock()
	action = m.peerFencing
	m.mu.RUnlock()
	events = m.history.Events(EventFence)
	return
}

// RequestPeerFailover asks the peer to transfer the given RG out of primary,
// making the local node eligible to become primary. Used when
// "request chassis cluster failover redundancy-group N node <local>" is run.
func (m *Manager) RequestPeerFailover(rgID int) error {
	m.mu.Lock()
	rg, ok := m.groups[rgID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	if rg.State == StatePrimary {
		m.mu.Unlock()
		return fmt.Errorf("node is already primary for redundancy group %d", rgID)
	}
	if !rg.IsReadyForTakeover(m.takeoverHoldTime) {
		readySince := "<zero>"
		if !rg.ReadySince.IsZero() {
			readySince = rg.ReadySince.Format(time.RFC3339Nano)
		}
		reasons := append([]string(nil), rg.ReadinessReasons...)
		m.mu.Unlock()
		return fmt.Errorf(
			"local redundancy group %d not ready for explicit failover ready=%t ready_since=%s reasons=%v",
			rgID,
			rg.Ready,
			readySince,
			reasons,
		)
	}
	fn := m.peerFailoverFn
	commitFn := m.peerFailoverCommitFn
	transferReadyFn := m.transferReadinessFn
	peerAlive := m.peerAlive
	localCommitReadyFn := m.localTransferCommitReadyFn
	m.mu.Unlock()

	if fn == nil {
		if !peerAlive {
			return fmt.Errorf("peer not alive — cannot request failover")
		}
		return fmt.Errorf("peer failover not available (sync not connected)")
	}
	if commitFn == nil {
		if !peerAlive {
			return fmt.Errorf("peer not alive — cannot request failover")
		}
		return fmt.Errorf("peer failover commit not available (sync not connected)")
	}
	if transferReadyFn != nil {
		ready, reasons := transferReadyFn(rgID)
		if !ready {
			return fmt.Errorf(
				"local redundancy group %d not transfer-ready for explicit failover reasons=%v",
				rgID,
				append([]string(nil), reasons...),
			)
		}
	}
	reqID, err := fn(rgID)
	if err != nil {
		return err
	}
	m.mu.Lock()
	rg, ok = m.groups[rgID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	// Preserve a local manual-failover hold until the peer has explicitly
	// acknowledged the transfer-out request. Preflight rejection or request-send
	// failure must not silently release the existing transfer-out state.
	if rg.ManualFailover {
		rg.ManualFailover = false
		rg.ManualFailoverAt = time.Time{}
		m.recalcWeight(rg)
	}
	m.mu.Unlock()
	if err := m.commitRequestedPeerFailover(rgID, reqID); err != nil {
		return err
	}
	if localCommitReadyFn != nil {
		if err := localCommitReadyFn([]int{rgID}); err != nil {
			m.abortRequestedPeerFailover(rgID, reqID)
			return err
		}
	}
	if err := commitFn(rgID, reqID); err != nil {
		m.abortRequestedPeerFailover(rgID, reqID)
		return err
	}
	m.notePeerTransferCommitted(rgID)
	return nil
}

func (m *Manager) commitRequestedPeerFailover(rgID int, reqID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rg, ok := m.groups[rgID]
	if !ok {
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	if !rg.IsReadyForTakeover(m.takeoverHoldTime) {
		readySince := "<zero>"
		if !rg.ReadySince.IsZero() {
			readySince = rg.ReadySince.Format(time.RFC3339Nano)
		}
		return fmt.Errorf(
			"redundancy group %d lost takeover readiness before transfer commit ready=%t ready_since=%s reasons=%v",
			rgID,
			rg.Ready,
			readySince,
			append([]string(nil), rg.ReadinessReasons...),
		)
	}

	m.applyPeerTransferOutOverrideLocked(rgID, reqID)
	delete(m.peerTransferCommitGraceUntil, rgID)
	delete(m.localTransferOutHoldUntil, rgID)
	peerGroup := m.peerGroups[rgID]

	m.runElection()
	if rg.State != StatePrimary {
		return fmt.Errorf(
			"failed to commit redundancy group %d primary ownership local_state=%s peer_state=%s ready=%t reasons=%v",
			rgID,
			rg.State,
			peerGroup.State,
			rg.Ready,
			append([]string(nil), rg.ReadinessReasons...),
		)
	}
	return nil
}

func (m *Manager) abortRequestedPeerFailover(rgID int, reqID uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.restorePeerTransferOutOverrideLocked(rgID, reqID) {
		return
	}
	delete(m.peerTransferCommitGraceUntil, rgID)
	m.runElection()
}

func (m *Manager) notePeerTransferCommitted(rgID int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.clearPeerTransferOutOverrideLocked(rgID)
	m.peerTransferCommitGraceUntil[rgID] = time.Now().Add(m.transferCommitGracePeriodLocked())
	peerGroup, ok := m.peerGroups[rgID]
	if !ok {
		return
	}
	peerGroup.State = StateSecondaryHold
	m.peerGroups[rgID] = peerGroup
}

// FinalizePeerTransferOut completes a previously acknowledged transfer-out
// after the peer commits ownership on the sync channel.
func (m *Manager) FinalizePeerTransferOut(rgID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rg, ok := m.groups[rgID]
	if !ok {
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	if rg.State == StatePrimary {
		return fmt.Errorf("%w: redundancy group %d still primary locally", ErrRemoteFailoverRejected, rgID)
	}
	if rg.State == StateSecondary && !rg.ManualFailover {
		return nil
	}

	oldState := rg.State
	rg.ManualFailover = false
	rg.ManualFailoverAt = time.Time{}
	rg.State = StateSecondary
	// A completed transfer-out invalidates any stale inbound-transfer view
	// from the previous owner direction. If we keep forcing the peer into
	// secondary-hold here, the next heartbeat can immediately re-elect the
	// old owner during rapid failback/failover sequences.
	delete(m.peerTransferOutOverride, rgID)
	delete(m.peerTransferCommitGraceUntil, rgID)
	m.localTransferOutHoldUntil[rgID] = time.Now().Add(m.transferCommitGracePeriodLocked())
	if oldState != rg.State {
		m.sendEvent(rg.GroupID, oldState, rg.State, "Peer transfer committed")
	}
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
		rg.ManualFailoverAt = time.Now()
		rg.State = StateSecondary
		if oldState != rg.State {
			rg.FailoverCount++
			m.sendEvent(rg.GroupID, oldState, rg.State, "Forced secondary (ISSU)")
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
	rg.ManualFailoverAt = time.Time{}
	m.recalcWeight(rg) // restore weight from monitor state + run election
	slog.Info("cluster: failover reset", "rg", rgID)
	return nil
}

// SetOnEventDrop registers a callback invoked when a cluster event is
// dropped due to a full channel. The daemon uses this to schedule an
// immediate reconciliation pass.
func (m *Manager) SetOnEventDrop(fn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onEventDrop = fn
}

func (m *Manager) sendEvent(groupID int, oldState, newState NodeState, reason string) {
	select {
	case m.eventCh <- ClusterEvent{GroupID: groupID, OldState: oldState, NewState: newState}:
	default:
		slog.Warn("cluster: event channel full, dropping event",
			"rg", groupID, "old", oldState, "new", newState)
		if m.onEventDrop != nil {
			m.onEventDrop()
		}
	}

	m.history.Record(EventRG, groupID, fmt.Sprintf("%s->%s, reason: %s", oldState, newState, reason))

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
	m.hbLocalAddr = localAddr
	m.hbPeerAddr = peerAddr
	m.hbVRFDevice = vrfDevice
	m.mu.Unlock()

	m.hbReceiver.start()
	m.hbSender.start()

	slog.Info("cluster: heartbeat started",
		"local", localAddr, "peer", peerAddr,
		"interval", interval, "threshold", threshold)
	return nil
}

// vrfListenConfig returns a net.ListenConfig that binds sockets to a VRF device
// via SO_BINDTODEVICE with SO_REUSEADDR+SO_REUSEPORT to allow immediate rebind
// after a restart (even if old sockets linger from a killed process).
// If vrfDevice is empty, only SO_REUSEADDR+SO_REUSEPORT are set.
func vrfListenConfig(vrfDevice string) net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				// Allow immediate rebind after restart — the kernel may
				// still hold the old socket briefly after process death.
				_ = unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET,
					unix.SO_REUSEADDR, 1)
				_ = unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET,
					unix.SO_REUSEPORT, 1)
				if vrfDevice != "" {
					err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET,
						syscall.SO_BINDTODEVICE, vrfDevice)
				}
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

// RestartHeartbeat stops and restarts the heartbeat with the same parameters.
// This is needed when the control interface's VRF binding changes (e.g. during
// DHCP-triggered recompile) which invalidates the existing UDP sockets.
// Retries up to 5 times with 1s delay if the bind fails (address may briefly
// disappear during VRF rebind). Returns false if heartbeat was not running.
func (m *Manager) RestartHeartbeat() bool {
	m.mu.RLock()
	running := m.hbSender != nil || m.hbReceiver != nil
	localAddr := m.hbLocalAddr
	peerAddr := m.hbPeerAddr
	vrfDevice := m.hbVRFDevice
	m.mu.RUnlock()

	if !running || localAddr == "" {
		return false
	}

	slog.Info("cluster: restarting heartbeat after VRF rebind",
		"local", localAddr, "peer", peerAddr, "vrf", vrfDevice)

	m.StopHeartbeat()

	for i := 0; i < 5; i++ {
		if err := m.StartHeartbeat(localAddr, peerAddr, vrfDevice); err != nil {
			slog.Warn("cluster: heartbeat restart bind failed, retrying",
				"err", err, "attempt", i+1)
			time.Sleep(1 * time.Second)
			continue
		}
		return true
	}
	slog.Error("cluster: heartbeat restart failed after retries")
	return false
}

// buildHeartbeat creates a heartbeat packet from current state.
func (m *Manager) buildHeartbeat() *HeartbeatPacket {
	m.mu.RLock()
	mon := m.monitor
	m.mu.RUnlock()

	// Collect local interface statuses outside the lock (monitor has its own).
	var localStatuses []InterfaceMonitorInfo
	if mon != nil {
		localStatuses = mon.LocalInterfaceStatuses()
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	pkt := &HeartbeatPacket{
		NodeID:          uint8(m.nodeID),
		ClusterID:       uint16(m.clusterID),
		SoftwareVersion: m.localSoftwareVersion,
	}
	for _, rg := range m.groups {
		pkt.Groups = append(pkt.Groups, HeartbeatGroup{
			GroupID:  uint8(rg.GroupID),
			Priority: uint16(rg.LocalPriority),
			Weight:   uint8(rg.Weight),
			State:    uint8(rg.State),
		})
	}

	// Include local interface monitor statuses.
	for _, ls := range localStatuses {
		pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{
			RGID:      uint8(ls.RedundancyGroup),
			Weight:    uint8(ls.Weight),
			Up:        ls.Up,
			Interface: ls.Interface,
		})
	}
	return pkt
}

// handlePeerHeartbeat processes an incoming peer heartbeat.
func (m *Manager) handlePeerHeartbeat(pkt *HeartbeatPacket) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()

	wasAlive := m.peerAlive
	m.peerAlive = true
	m.peerEverSeen = true
	m.peerNodeID = int(pkt.NodeID)
	m.peerSoftwareVersion = pkt.SoftwareVersion

	// Rebuild peer group states from scratch — prunes stale RGs that
	// the peer no longer reports (fix #92).
	newPeerGroups := make(map[int]PeerGroupState, len(pkt.Groups))
	for _, g := range pkt.Groups {
		newPeerGroups[int(g.GroupID)] = PeerGroupState{
			GroupID:  int(g.GroupID),
			Priority: int(g.Priority),
			Weight:   int(g.Weight),
			State:    NodeState(g.State),
		}
	}
	for rgID := range m.peerTransferOutOverride {
		peerGroup, ok := newPeerGroups[rgID]
		if !ok {
			continue
		}
		peerGroup.GroupID = rgID
		peerGroup.State = StateSecondaryHold
		newPeerGroups[rgID] = peerGroup
	}
	for rgID, until := range m.peerTransferCommitGraceUntil {
		if !now.Before(until) {
			delete(m.peerTransferCommitGraceUntil, rgID)
			continue
		}
		peerGroup, ok := newPeerGroups[rgID]
		if !ok {
			continue
		}
		peerGroup.GroupID = rgID
		peerGroup.State = StateSecondaryHold
		newPeerGroups[rgID] = peerGroup
	}
	for rgID, until := range m.localTransferOutHoldUntil {
		if !now.Before(until) {
			delete(m.localTransferOutHoldUntil, rgID)
		}
	}
	m.peerGroups = newPeerGroups

	// Update peer interface monitor statuses.
	if len(pkt.Monitors) > 0 {
		m.peerMonitors = make([]InterfaceMonitorInfo, len(pkt.Monitors))
		for i, mon := range pkt.Monitors {
			m.peerMonitors[i] = InterfaceMonitorInfo{
				Interface:       mon.Interface,
				Weight:          int(mon.Weight),
				Up:              mon.Up,
				RedundancyGroup: int(mon.RGID),
			}
		}
	} else {
		m.peerMonitors = nil
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
		m.history.Record(EventHeartbeat, -1, fmt.Sprintf("Peer alive (node%d)", pkt.NodeID))
	}

	m.runElection()
}

// handlePeerTimeout is called when the peer heartbeat timeout expires.
func (m *Manager) handlePeerTimeout() {
	m.mu.Lock()
	if !m.peerAlive {
		m.mu.Unlock()
		return // already marked lost
	}
	if suppress, reason := m.suppressPeerTimeoutForTransferCommitLocked(time.Now()); suppress {
		m.mu.Unlock()
		slog.Debug("cluster: suppressing peer heartbeat timeout", "reason", reason)
		return
	}
	guard := m.peerTimeoutGuardFn
	m.mu.Unlock()

	if guard != nil {
		if suppress, reason := guard(); suppress {
			slog.Debug("cluster: suppressing peer heartbeat timeout", "reason", reason)
			return
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.peerAlive {
		return // already marked lost while guard ran
	}
	if suppress, reason := m.suppressPeerTimeoutForTransferCommitLocked(time.Now()); suppress {
		slog.Debug("cluster: suppressing peer heartbeat timeout", "reason", reason)
		return
	}

	m.peerAlive = false
	m.peerGroups = make(map[int]PeerGroupState)
	m.peerMonitors = nil
	m.peerSoftwareVersion = ""
	slog.Warn("cluster: peer heartbeat timeout, marking peer lost")
	m.history.Record(EventHeartbeat, -1, "Peer heartbeat timeout")

	// Clear ManualFailover on all RGs: the peer is dead, so the surviving
	// node MUST be able to take over. Without this, a previous manual
	// transfer-out would keep the local node parked in secondary-hold even
	// though there is no longer a peer to hand ownership to.
	for _, rg := range m.groups {
		if rg.ManualFailover {
			slog.Info("cluster: clearing manual failover (peer lost)", "rg", rg.GroupID)
			rg.ManualFailover = false
			rg.ManualFailoverAt = time.Time{}
			m.recalcWeight(rg)
		}
	}

	// Peer lost: re-run single-node election.
	m.electSingleNode()

	// Attempt peer fencing if configured.
	if m.peerFencing == "disable-rg" {
		fn := m.peerFenceFn
		if fn != nil {
			// Release lock for the network call.
			m.mu.Unlock()
			err := fn()
			m.mu.Lock()
			if err != nil {
				slog.Warn("cluster: fence: peer unreachable, relying on heartbeat-driven failover", "err", err)
				m.history.Record(EventFence, -1, fmt.Sprintf("Fence failed: %v", err))
			} else {
				slog.Info("cluster: fence: disable-rg sent to peer")
				m.history.Record(EventFence, -1, "Fence disable-rg sent to peer")
			}
		} else {
			slog.Warn("cluster: fence: sync not available, peer unreachable")
			m.history.Record(EventFence, -1, "Fence skipped: sync not available")
		}
	}
}

// handlePeerNeverSeen is called when the heartbeat timeout expires and no
// peer heartbeat has ever been received. This confirms the peer is truly
// absent (not just a fresh boot race). Sets peerEverSeen so non-preempt
// nodes can claim primary via electSingleNode.
func (m *Manager) handlePeerNeverSeen() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.peerEverSeen {
		return // already handled
	}
	m.peerEverSeen = true // no longer "never seen" — now "confirmed absent"
	slog.Info("cluster: peer never seen after heartbeat timeout, proceeding with election")
	m.history.Record(EventHeartbeat, -1, "Peer never seen (timeout)")
	m.electSingleNode()
}

// triggerGARP is called on transition to primary. Native VRRP handles
// GARP for VRRP-backed RETH interfaces, so this is a no-op.
func (m *Manager) triggerGARP(rgID int) {
	slog.Info("cluster: primary transition", "rg", rgID)
}

// RecordEvent records a cluster event to the history ring buffer.
func (m *Manager) RecordEvent(cat EventCategory, rgID int, msg string) {
	m.history.Record(cat, rgID, msg)
}

// EventHistoryFor returns the event history for a given category.
func (m *Manager) EventHistoryFor(cat EventCategory) []HistoryEvent {
	return m.history.Events(cat)
}

// HeartbeatStats holds heartbeat send/receive counters.
type HeartbeatStats struct {
	Sent       uint64
	Received   uint64
	SendErrors uint64
	RecvErrors uint64
}

// HeartbeatStats returns current heartbeat counters.
func (m *Manager) HeartbeatStats() HeartbeatStats {
	m.mu.RLock()
	sender := m.hbSender
	receiver := m.hbReceiver
	m.mu.RUnlock()

	var s HeartbeatStats
	if sender != nil {
		s.Sent = sender.sent.Load()
		s.SendErrors = sender.sendErrors.Load()
	}
	if receiver != nil {
		s.Received = receiver.received.Load()
		s.RecvErrors = receiver.recvErrors.Load()
	}
	return s
}

// SyncStatsProvider abstracts access to session sync statistics.
type SyncStatsProvider interface {
	Stats() SyncStatsSnapshot
	IsConnected() bool
}

// SetSyncStats sets the sync stats provider (called by daemon after sessionSync creation).
func (m *Manager) SetSyncStats(p SyncStatsProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncStats = p
}

// GetSyncStats returns sync stats, or nil if no provider is set.
func (m *Manager) GetSyncStats() *SyncStatsSnapshot {
	m.mu.RLock()
	p := m.syncStats
	m.mu.RUnlock()
	if p == nil {
		return nil
	}
	stats := p.Stats()
	return &stats
}

// IsSyncConnected returns true if the sync peer is connected.
func (m *Manager) IsSyncConnected() bool {
	m.mu.RLock()
	p := m.syncStats
	m.mu.RUnlock()
	if p == nil {
		return false
	}
	return p.IsConnected()
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
	localVersion := m.localSoftwareVersion
	peerVersion := m.peerSoftwareVersion
	peerGroups := make(map[int]PeerGroupState, len(m.peerGroups))
	for k, v := range m.peerGroups {
		peerGroups[k] = v
	}
	m.mu.RUnlock()

	var b strings.Builder
	fmt.Fprintln(&b, "Monitor Failure codes:")
	fmt.Fprintln(&b, "    CS  Cold Sync monitoring        FL  Fabric Connection monitoring")
	fmt.Fprintln(&b, "    IF  Interface monitoring        IP  IP monitoring")
	fmt.Fprintln(&b, "    CF  Config Sync monitoring")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Cluster ID: %d\n", m.clusterID)
	fmt.Fprintf(&b, "Node name: node%d\n\n", m.nodeID)
	if localVersion != "" {
		fmt.Fprintf(&b, "Software version: %s\n", localVersion)
	}
	if peerAlive {
		if peerVersion == "" {
			peerVersion = "unknown"
		}
		fmt.Fprintf(&b, "Peer software version: %s\n", peerVersion)
	}
	if localVersion != "" || peerAlive {
		fmt.Fprintln(&b)
	}
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
		readyStr := "yes"
		if !rg.Ready {
			readyStr = "no"
			if len(rg.ReadinessReasons) > 0 {
				readyStr = "no (" + strings.Join(rg.ReadinessReasons, ", ") + ")"
			}
		}
		transferReadyStr := "yes"
		if !rg.TransferReady {
			transferReadyStr = "no"
			if len(rg.TransferReadinessReasons) > 0 {
				transferReadyStr = "no (" + strings.Join(rg.TransferReadinessReasons, ", ") + ")"
			}
		}
		// Local node line.
		fmt.Fprintf(&b, "%-6s %-8d %-14s %-8s %-8s %s\n",
			fmt.Sprintf("node%d", m.nodeID),
			rg.LocalPriority, rg.State, preempt, manual, monFails)
		fmt.Fprintf(&b, "  Takeover ready: %s\n", readyStr)
		fmt.Fprintf(&b, "  Transfer ready: %s\n", transferReadyStr)
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

// FormatInformation returns detailed cluster information matching vSRX output.
func (m *Manager) FormatInformation() string {
	m.mu.RLock()
	peerAlive := m.peerAlive
	peerNodeID := m.peerNodeID
	localVersion := m.localSoftwareVersion
	peerVersion := m.peerSoftwareVersion
	interval := m.hbInterval
	threshold := m.hbThreshold
	controlIface := m.controlInterface
	m.mu.RUnlock()

	states := m.GroupStates()

	var b strings.Builder

	// Redundancy mode.
	mode := "active-passive"
	if len(states) > 1 {
		// If different RGs have different primaries, it's active-active.
		primary0 := false
		secondary0 := false
		for _, rg := range states {
			if rg.State == StatePrimary {
				primary0 = true
			} else {
				secondary0 = true
			}
		}
		if primary0 && secondary0 {
			mode = "active-active"
		}
	}
	fmt.Fprintf(&b, "Redundancy mode: %s\n\n", mode)

	// Cluster configuration.
	fmt.Fprintln(&b, "Cluster configuration:")
	fmt.Fprintf(&b, "  Cluster ID: %d\n", m.clusterID)
	fmt.Fprintf(&b, "  Node ID: %d\n", m.nodeID)
	fmt.Fprintf(&b, "  Heartbeat interval: %d ms\n", interval.Milliseconds())
	fmt.Fprintf(&b, "  Heartbeat threshold: %d\n", threshold)
	if controlIface != "" {
		fmt.Fprintf(&b, "  Control interface: %s\n", controlIface)
	}
	if localVersion != "" {
		fmt.Fprintf(&b, "  Software version: %s\n", localVersion)
	}
	if peerAlive {
		if peerVersion == "" {
			peerVersion = "unknown"
		}
		fmt.Fprintf(&b, "  Peer software version: %s\n", peerVersion)
	}
	fmt.Fprintf(&b, "  Sync transport: %s\n", m.SyncTransport())
	fmt.Fprintln(&b)

	// Node health.
	localHealth := "healthy"
	for _, rg := range states {
		if len(rg.MonitorFails) > 0 || rg.Weight < 255 {
			localHealth = "degraded"
			break
		}
	}
	remoteHealth := "lost"
	if peerAlive {
		remoteHealth = fmt.Sprintf("healthy (node%d)", peerNodeID)
	}
	fmt.Fprintln(&b, "Node health:")
	fmt.Fprintf(&b, "  Local node: %s\n", localHealth)
	fmt.Fprintf(&b, "  Remote node: %s\n", remoteHealth)
	fmt.Fprintln(&b)

	// Per-RG details with event history.
	for _, rg := range states {
		fmt.Fprintf(&b, "Redundancy group %d:\n", rg.GroupID)
		fmt.Fprintf(&b, "  Local priority: %d\n", rg.LocalPriority)
		fmt.Fprintf(&b, "  Peer priority: %d\n", rg.PeerPriority)
		fmt.Fprintf(&b, "  Local state: %s\n", rg.State)
		fmt.Fprintf(&b, "  Weight: %d/255 (threshold: 0)\n", rg.Weight)
		fmt.Fprintf(&b, "  Effective priority: %d\n", EffectivePriority(rg.LocalPriority, rg.Weight))
		preempt := "no"
		if rg.Preempt {
			preempt = "yes"
		}
		fmt.Fprintf(&b, "  Preempt: %s\n", preempt)
		fmt.Fprintf(&b, "  Failover count: %d\n", rg.FailoverCount)
		if rg.Ready {
			fmt.Fprintf(&b, "  Takeover ready: yes (since %s)\n", rg.ReadySince.Format("15:04:05"))
		} else {
			reasons := "none"
			if len(rg.ReadinessReasons) > 0 {
				reasons = strings.Join(rg.ReadinessReasons, ", ")
			}
			fmt.Fprintf(&b, "  Takeover ready: no (%s)\n", reasons)
		}
		if rg.TransferReady {
			fmt.Fprintf(&b, "  Transfer ready: yes\n")
		} else {
			reasons := "none"
			if len(rg.TransferReadinessReasons) > 0 {
				reasons = strings.Join(rg.TransferReadinessReasons, ", ")
			}
			fmt.Fprintf(&b, "  Transfer ready: no (%s)\n", reasons)
		}
		if len(rg.MonitorFails) > 0 {
			fmt.Fprintf(&b, "  Monitor failures: %s\n", strings.Join(rg.MonitorFails, ", "))
		}

		// RG event history.
		rgEvents := m.history.Events(EventRG)
		var rgFiltered []HistoryEvent
		for _, ev := range rgEvents {
			if ev.GroupID == rg.GroupID {
				rgFiltered = append(rgFiltered, ev)
			}
		}
		if len(rgFiltered) > 0 {
			fmt.Fprintln(&b, "  Event history:")
			for _, ev := range rgFiltered {
				fmt.Fprintf(&b, "    %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
			}
		}
		fmt.Fprintln(&b)
	}

	// Control link statistics.
	hbStats := m.HeartbeatStats()
	fmt.Fprintln(&b, "Control link statistics:")
	fmt.Fprintf(&b, "  Heartbeat packets sent:     %d\n", hbStats.Sent)
	fmt.Fprintf(&b, "  Heartbeat packets received: %d\n", hbStats.Received)
	fmt.Fprintf(&b, "  Heartbeat packet errors:    %d\n", hbStats.SendErrors+hbStats.RecvErrors)
	fmt.Fprintln(&b)

	// Sync link statistics.
	syncLabel := "Fabric link statistics:"
	if m.SyncTransport() == "control-link" {
		syncLabel = "Sync link statistics (control-link):"
	}
	fmt.Fprintln(&b, syncLabel)
	syncStats := m.GetSyncStats()
	if syncStats != nil {
		connected := "Down"
		if m.IsSyncConnected() {
			connected = "Up"
		}
		fmt.Fprintf(&b, "  Status: %s\n", connected)
		fmt.Fprintf(&b, "  Errors: %d\n", syncStats.Errors)
	} else {
		fmt.Fprintln(&b, "  Not configured")
	}
	fabEvents := m.history.Events(EventFabric)
	if len(fabEvents) > 0 {
		fmt.Fprintln(&b, "  Events:")
		for _, ev := range fabEvents {
			fmt.Fprintf(&b, "    %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}
	fmt.Fprintln(&b)

	// Cold synchronization.
	fmt.Fprintln(&b, "Cold synchronization:")
	if syncStats != nil {
		startNano := syncStats.BulkSyncStartTime
		endNano := syncStats.BulkSyncEndTime
		bulkCount := syncStats.BulkSyncs
		if startNano > 0 {
			startTime := time.Unix(0, startNano)
			if endNano > 0 {
				endTime := time.Unix(0, endNano)
				dur := endTime.Sub(startTime)
				fmt.Fprintf(&b, "  Last bulk sync: %s (duration: %s, sessions: %d)\n",
					endTime.Format("Jan 02 15:04:05"), dur.Round(time.Millisecond), syncStats.BulkSyncSessions)
			} else {
				fmt.Fprintf(&b, "  Bulk sync in progress since %s (sessions: %d)\n",
					startTime.Format("Jan 02 15:04:05"), syncStats.BulkSyncSessions)
			}
		}
		fmt.Fprintf(&b, "  Bulk syncs completed: %d\n", bulkCount)
	} else {
		fmt.Fprintln(&b, "  Not configured")
	}
	coldEvents := m.history.Events(EventColdSync)
	if len(coldEvents) > 0 {
		fmt.Fprintln(&b, "  Events:")
		for _, ev := range coldEvents {
			fmt.Fprintf(&b, "    %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}
	fmt.Fprintln(&b)

	// Install fence (barrier-based cutover).
	if syncStats != nil && syncStats.LastFenceSeq > 0 {
		fmt.Fprintln(&b, "Install fence:")
		fmt.Fprintf(&b, "  Last fence sequence: %d\n", syncStats.LastFenceSeq)
		if syncStats.LastFenceAckAt > 0 {
			ackTime := time.Unix(0, syncStats.LastFenceAckAt)
			fmt.Fprintf(&b, "  Last fence ack:      %s\n", ackTime.Format("Jan 02 15:04:05.000"))
		} else {
			fmt.Fprintln(&b, "  Last fence ack:      pending")
		}
		fmt.Fprintln(&b)
	}

	// Interface monitoring events.
	monEvents := m.history.Events(EventMonitor)
	if len(monEvents) > 0 {
		fmt.Fprintln(&b, "Interface monitoring events:")
		for _, ev := range monEvents {
			rgStr := ""
			if ev.GroupID >= 0 {
				rgStr = fmt.Sprintf(" (rg%d)", ev.GroupID)
			}
			fmt.Fprintf(&b, "  %s%s  %s\n", ev.Time.Format("Jan 02 15:04:05"), rgStr, ev.Message)
		}
		fmt.Fprintln(&b)
	}

	// Configuration synchronization.
	fmt.Fprintln(&b, "Configuration synchronization:")
	if syncStats != nil {
		configNano := syncStats.LastConfigSyncTime
		if configNano > 0 {
			configTime := time.Unix(0, configNano)
			fmt.Fprintf(&b, "  Last config sync: %s (size: %d bytes)\n",
				configTime.Format("Jan 02 15:04:05"), syncStats.LastConfigSyncSize)
		}
		fmt.Fprintf(&b, "  Configs sent:     %d\n", syncStats.ConfigsSent)
		fmt.Fprintf(&b, "  Configs received: %d\n", syncStats.ConfigsReceived)
	} else {
		fmt.Fprintln(&b, "  Not configured")
	}
	cfgEvents := m.history.Events(EventConfigSync)
	if len(cfgEvents) > 0 {
		fmt.Fprintln(&b, "  Events:")
		for _, ev := range cfgEvents {
			fmt.Fprintf(&b, "    %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}

	// Heartbeat event history.
	hbEvents := m.history.Events(EventHeartbeat)
	if len(hbEvents) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "Heartbeat events:")
		for _, ev := range hbEvents {
			fmt.Fprintf(&b, "  %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}

	return b.String()
}

// FormatStatistics returns cluster statistics matching vSRX output.
func (m *Manager) FormatStatistics() string {
	var b strings.Builder

	// Control link statistics.
	hbStats := m.HeartbeatStats()
	fmt.Fprintln(&b, "Control link statistics:")
	fmt.Fprintf(&b, "    Heartbeat packets sent:     %d\n", hbStats.Sent)
	fmt.Fprintf(&b, "    Heartbeat packets received: %d\n", hbStats.Received)
	fmt.Fprintf(&b, "    Heartbeat packet errors:    %d\n", hbStats.SendErrors+hbStats.RecvErrors)
	fmt.Fprintln(&b)

	// Services synchronized table.
	syncStats := m.GetSyncStats()
	if syncStats != nil {
		fmt.Fprintln(&b, "Services Synchronized:")
		fmt.Fprintf(&b, "    %-32s %-12s %s\n", "Service name", "Sent", "Received")
		fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Session create",
			syncStats.SessionsSent, syncStats.SessionsReceived)
		fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Session close",
			syncStats.DeletesSent, syncStats.DeletesReceived)
		fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Config",
			syncStats.ConfigsSent, syncStats.ConfigsReceived)
		fmt.Fprintf(&b, "    %-32s %-12d %d\n", "IPsec SA",
			syncStats.IPsecSASent, syncStats.IPsecSAReceived)
		fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Bulk syncs",
			syncStats.BulkSyncs, syncStats.BulkSyncs)
		fmt.Fprintf(&b, "    %-32s %-12s %d\n", "Sessions installed",
			"", syncStats.SessionsInstalled)
		fmt.Fprintf(&b, "    %-32s %-12d %s\n", "Errors",
			syncStats.Errors, "")
		if syncStats.LastFenceSeq > 0 {
			fmt.Fprintf(&b, "    %-32s %-12d %s\n", "Install fence seq",
				syncStats.LastFenceSeq, "")
		}
	} else {
		fmt.Fprintln(&b, "Session sync not configured")
	}

	return b.String()
}

// FormatControlPlaneStatistics returns control-plane (heartbeat) statistics.
func (m *Manager) FormatControlPlaneStatistics() string {
	var b strings.Builder
	hbStats := m.HeartbeatStats()
	fmt.Fprintln(&b, "Control link statistics:")
	fmt.Fprintf(&b, "    Heartbeat packets sent:     %d\n", hbStats.Sent)
	fmt.Fprintf(&b, "    Heartbeat packets received: %d\n", hbStats.Received)
	fmt.Fprintf(&b, "    Heartbeat send errors:      %d\n", hbStats.SendErrors)
	fmt.Fprintf(&b, "    Heartbeat receive errors:   %d\n", hbStats.RecvErrors)
	return b.String()
}

// FormatDataPlaneStatistics returns data-plane (session sync) statistics.
func (m *Manager) FormatDataPlaneStatistics() string {
	var b strings.Builder
	syncStats := m.GetSyncStats()
	if syncStats == nil {
		fmt.Fprintln(&b, "Session sync not configured")
		return b.String()
	}

	fmt.Fprintln(&b, "Services Synchronized:")
	fmt.Fprintf(&b, "    %-32s %-12s %s\n", "Service name", "Sent", "Received")
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Session create",
		syncStats.SessionsSent, syncStats.SessionsReceived)
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Session close",
		syncStats.DeletesSent, syncStats.DeletesReceived)
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Config",
		syncStats.ConfigsSent, syncStats.ConfigsReceived)
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "IPsec SA",
		syncStats.IPsecSASent, syncStats.IPsecSAReceived)
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Bulk syncs",
		syncStats.BulkSyncs, syncStats.BulkSyncs)
	fmt.Fprintf(&b, "    %-32s %-12s %d\n", "Sessions installed",
		"", syncStats.SessionsInstalled)
	fmt.Fprintf(&b, "    %-32s %-12d %s\n", "Errors",
		syncStats.Errors, "")
	if syncStats.LastFenceSeq > 0 {
		fmt.Fprintf(&b, "    %-32s %-12d %s\n", "Install fence seq",
			syncStats.LastFenceSeq, "")
	}
	return b.String()
}

// FormatDataPlaneInterfaces returns fabric interface status.
func (m *Manager) FormatDataPlaneInterfaces() string {
	var b strings.Builder
	if m.SyncTransport() == "control-link" {
		fmt.Fprintln(&b, "Sync link (control-link):")
	} else {
		fmt.Fprintln(&b, "Fabric link:")
	}
	if m.IsSyncConnected() {
		fmt.Fprintln(&b, "  Status: Up")
	} else {
		fmt.Fprintln(&b, "  Status: Down")
	}
	syncStats := m.GetSyncStats()
	if syncStats != nil {
		fmt.Fprintf(&b, "  Errors: %d\n", syncStats.Errors)
	}
	fabEvents := m.history.Events(EventFabric)
	if len(fabEvents) > 0 {
		fmt.Fprintln(&b, "  Events:")
		for _, ev := range fabEvents {
			fmt.Fprintf(&b, "    %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}
	return b.String()
}

// FormatIPMonitoringStatus returns per-RG IP monitoring probe status.
func (m *Manager) FormatIPMonitoringStatus() string {
	m.mu.RLock()
	mon := m.monitor
	m.mu.RUnlock()

	states := m.GroupStates()
	var b strings.Builder
	fmt.Fprintln(&b, "IP monitoring status:")
	fmt.Fprintln(&b)

	hasIP := false
	for _, rg := range states {
		// Check for IP monitor failures (prefixed with "ip:").
		var ipFails []string
		for _, f := range rg.MonitorFails {
			if strings.HasPrefix(f, "ip:") {
				ipFails = append(ipFails, f)
			}
		}
		// Show IP monitor section regardless (config-driven).
		_ = mon // monitor has the config but we show from state
		if len(ipFails) > 0 || true {
			// We always show the section for each RG if any monitors are configured.
			fmt.Fprintf(&b, "Redundancy group %d:\n", rg.GroupID)
			if len(ipFails) > 0 {
				for _, f := range ipFails {
					addr := strings.TrimPrefix(f, "ip:")
					fmt.Fprintf(&b, "  %-20s Status: unreachable\n", addr)
				}
			} else {
				fmt.Fprintln(&b, "  No IP monitoring failures")
			}
			fmt.Fprintln(&b)
			hasIP = true
		}
	}

	if !hasIP {
		fmt.Fprintln(&b, "No IP monitoring configured")
	}

	// Events.
	monEvents := m.history.Events(EventMonitor)
	var ipEvents []HistoryEvent
	for _, ev := range monEvents {
		if strings.HasPrefix(ev.Message, "IP ") {
			ipEvents = append(ipEvents, ev)
		}
	}
	if len(ipEvents) > 0 {
		fmt.Fprintln(&b, "IP monitoring events:")
		for _, ev := range ipEvents {
			fmt.Fprintf(&b, "  %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}

	return b.String()
}

// InterfaceMonitorInfo holds per-interface monitor state for display.
type InterfaceMonitorInfo struct {
	Interface       string
	Weight          int
	Up              bool // physical link state
	RedundancyGroup int
}

// RethInfo holds RETH interface status for display.
type RethInfo struct {
	Name            string
	RedundancyGroup int
	Status          string // "Up" or "Down"
	Members         []string
}

// InterfacesInput provides the data needed to format cluster interfaces output.
type InterfacesInput struct {
	ControlInterface string
	FabricInterface  string
	FabricMembers    []string // bond member interfaces (e.g. fab0-m0, fab0-m1)
	Fabric1Interface string   // secondary fabric interface (e.g. "fab1")
	Fabric1Members   []string // secondary fabric bond members (if any)
	Reths            []RethInfo
	Monitors         []InterfaceMonitorInfo
	PeerMonitors     []InterfaceMonitorInfo
}

// FormatInterfaces returns cluster interface information matching vSRX output.
func (m *Manager) FormatInterfaces(input InterfacesInput) string {
	var b strings.Builder

	m.mu.RLock()
	peerAlive := m.peerAlive
	m.mu.RUnlock()

	// Control link status.
	controlStatus := "Up"
	if !peerAlive {
		controlStatus = "Down"
	}
	fmt.Fprintf(&b, "Control link status: %s\n", controlStatus)
	fmt.Fprintln(&b)

	// Control interfaces table.
	if input.ControlInterface != "" {
		fmt.Fprintln(&b, "Control interfaces:")
		fmt.Fprintf(&b, "    %-8s%-12s%-21s%-14s%s\n", "Index", "Interface", "Monitored-Status", "Internal-SA", "Security")
		monStatus := "Up"
		if !peerAlive {
			monStatus = "Down"
		}
		fmt.Fprintf(&b, "    %-8d%-12s%-21s%-14s%s\n", 0, input.ControlInterface, monStatus, "Disabled", "Disabled")
		fmt.Fprintln(&b)
	}

	// Sync link status.
	fabricUp := m.IsSyncConnected()
	fabricStatus := "Up"
	if !fabricUp {
		fabricStatus = "Down"
	}
	if m.SyncTransport() == "control-link" {
		fmt.Fprintf(&b, "Sync link status (control-link): %s\n", fabricStatus)
	} else {
		fmt.Fprintf(&b, "Fabric link status: %s\n", fabricStatus)
	}
	fmt.Fprintln(&b)

	// Fabric interfaces table.
	if input.FabricInterface != "" || input.Fabric1Interface != "" {
		fmt.Fprintln(&b, "Fabric interfaces:")
		fmt.Fprintf(&b, "    %-8s%-19s%-26s%s\n", "Name", "Child-interface", "Status", "Security")
		fmt.Fprintf(&b, "    %-8s%-19s%s\n", "", "", "(Physical/Monitored)")
		physStatus := "Up"
		if !fabricUp {
			physStatus = "Down"
		}
		statusStr := fmt.Sprintf("%s  /  %s", physStatus, physStatus)
		if input.FabricInterface != "" {
			if len(input.FabricMembers) > 0 {
				for i, member := range input.FabricMembers {
					name := ""
					if i == 0 {
						name = input.FabricInterface
					}
					fmt.Fprintf(&b, "    %-8s%-19s%-26s%s\n", name, member, statusStr, "Disabled")
				}
			} else {
				fmt.Fprintf(&b, "    %-8s%-19s%-26s%s\n", input.FabricInterface, input.FabricInterface, statusStr, "Disabled")
			}
		}
		if input.Fabric1Interface != "" {
			if len(input.Fabric1Members) > 0 {
				for i, member := range input.Fabric1Members {
					name := ""
					if i == 0 {
						name = input.Fabric1Interface
					}
					fmt.Fprintf(&b, "    %-8s%-19s%-26s%s\n", name, member, statusStr, "Disabled")
				}
			} else {
				fmt.Fprintf(&b, "    %-8s%-19s%-26s%s\n", input.Fabric1Interface, input.Fabric1Interface, statusStr, "Disabled")
			}
		}
		fmt.Fprintln(&b)
	}

	// Redundant-ethernet Information.
	if len(input.Reths) > 0 {
		fmt.Fprintln(&b, "Redundant-ethernet Information:")
		fmt.Fprintf(&b, "    %-13s%-12s%s\n", "Name", "Status", "Redundancy-group")
		for _, r := range input.Reths {
			fmt.Fprintf(&b, "    %-13s%-12s%d\n", r.Name, r.Status, r.RedundancyGroup)
		}
		fmt.Fprintln(&b)
	}

	// Interface Monitoring — merge local + peer monitors and sort by RG then name.
	allMonitors := make([]InterfaceMonitorInfo, 0, len(input.Monitors)+len(input.PeerMonitors))
	allMonitors = append(allMonitors, input.Monitors...)
	allMonitors = append(allMonitors, input.PeerMonitors...)
	if len(allMonitors) > 0 {
		sort.Slice(allMonitors, func(i, j int) bool {
			if allMonitors[i].RedundancyGroup != allMonitors[j].RedundancyGroup {
				return allMonitors[i].RedundancyGroup < allMonitors[j].RedundancyGroup
			}
			return allMonitors[i].Interface < allMonitors[j].Interface
		})
		fmt.Fprintln(&b, "Interface Monitoring:")
		fmt.Fprintf(&b, "    %-18s%-10s%-26s%s\n", "Interface", "Weight", "Status", "Redundancy-group")
		fmt.Fprintf(&b, "    %-18s%-10s%s\n", "", "", "(Physical/Monitored)")
		for _, mon := range allMonitors {
			physStatus := "Up"
			if !mon.Up {
				physStatus = "Down"
			}
			// Physical and monitored status are the same (link-state based).
			statusStr := fmt.Sprintf("%s  /  %s", physStatus, physStatus)
			fmt.Fprintf(&b, "    %-18s%-10d%-26s%d\n",
				mon.Interface, mon.Weight, statusStr, mon.RedundancyGroup)
		}
	}

	return b.String()
}
