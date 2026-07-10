package cluster

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
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
	// monStartMu serializes Start's stop-previous + swap + start-new monitor
	// sequence. It is a SEPARATE lock from m.mu because Start must NOT hold
	// m.mu across the old monitor's Stop(): Stop() joins the poll goroutine
	// (mon.wg.Wait()), and that goroutine calls back into SetMonitorWeight,
	// which takes m.mu — holding m.mu across Stop() is a classic AB-BA
	// deadlock (#4828). monStartMu serializes concurrent Start calls without
	// participating in that ordering (no goroutine Stop() waits on ever takes
	// monStartMu), mirroring hbStartMu / StartHeartbeat (#4033).
	monStartMu sync.Mutex
	garpCounts map[int]int // rgID -> gratuitous ARP count from config
	history    *EventHistory

	// kernelUpgradeHold, when set, unconditionally holds this node SECONDARY in
	// election (#1930 INC-2): a kernel-upgrade candidate boot must not become
	// primary until the promotion gate verifies the dataplane. Set BEFORE
	// Start() on a candidate boot; cleared by promote/rejoin/revert.
	kernelUpgradeHold bool

	// Peer state tracking (heartbeat).
	peerAlive    bool
	peerEverSeen bool // true once first heartbeat received; distinguishes "never heard" from "lost"
	peerNodeID   int
	peerGroups   map[int]PeerGroupState
	// Optional software version metadata advertised via heartbeat.
	localSoftwareVersion string
	peerSoftwareVersion  string
	// Explicit HA/session-transfer compatibility version carried in heartbeat.
	// Unlike software version strings, this is a deliberate interoperability
	// contract and is what userspace transfer readiness gates on.
	localHAProtocolVersion uint16
	peerHAProtocolVersion  uint16
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
	peerTransferOutPrevious   map[int]peerGroupSnapshot
	peerMonitors              []InterfaceMonitorInfo

	// lastDupNodeIDWarn rate-limits the duplicate-node-id warning (#4549 F11).
	// A peer advertising the local node's own node-id is an invalid cluster
	// (two chassis cannot share a node-id); the warning fires at most once per
	// 30s so a 5/s heartbeat stream cannot flood the log. Read/written under
	// m.mu.
	lastDupNodeIDWarn time.Time

	// Heartbeat goroutines (nil when not started).
	hbSender   *heartbeatSender
	hbReceiver *heartbeatReceiver

	// hbStartMu serializes StartHeartbeat's stop-previous + socket-create +
	// install sequence so two concurrent StartHeartbeat calls (e.g. a
	// comms-restart bind-retry goroutine racing RestartHeartbeat) cannot
	// interleave and leave two live heartbeat goroutine sets running. It is a
	// separate lock from m.mu because StartHeartbeat calls StopHeartbeat
	// (which acquires m.mu and joins goroutines that also take m.mu). See
	// StartHeartbeat (#4033).
	hbStartMu sync.Mutex

	// Heartbeat config.
	controlInterface string
	// controlAuthKey is the #4107 shared PSK authenticating cluster
	// control-channel messages (chassis cluster authentication-key). Empty =
	// no auth (legacy dual-accept). Raw key bytes; NEVER logged. Replaced (not
	// mutated in place) under m.mu on config apply; read via
	// controlLinkAuthKey().
	controlAuthKey []byte
	hbInterval     time.Duration
	hbThreshold    int
	hbLocalAddr    string // last StartHeartbeat localAddr (for restart)
	hbPeerAddr     string // last StartHeartbeat peerAddr (for restart)
	hbVRFDevice    string // last StartHeartbeat vrfDevice (for restart)

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

	// peerHeartbeatFreshFn reports whether a peer heartbeat is currently
	// within the timeout window (i.e. NOT stale). handlePeerTimeout consults
	// it AFTER the (possibly slow) guard window so a heartbeat that arrived
	// during the guard aborts the spurious peer-lost transition. Defaults to
	// the live receiver-backed check via peerHeartbeatFresh; overridable in
	// tests to inject a fresh/stale heartbeat without a real socket.
	peerHeartbeatFreshFn func() bool

	// hbRestartNotifyFn is invoked around RestartHeartbeat's socket
	// teardown/rebind window (once before teardown, once after each failed
	// bind retry). The daemon wires it to SessionSync.SendLivenessKeepalive
	// so the peer's heartbeat-timeout suppression guard keeps seeing fresh
	// sync traffic while our UDP heartbeats are silent (#1792).
	hbRestartNotifyFn func()

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

	// failoverGen is a per-RG monotonic generation bumped by ResetFailover
	// (#5246). ManualFailover / ManualFailoverBatch snapshot it under m.mu
	// before releasing the lock to run the retryable pre-failover hook, and
	// re-check it after re-acquiring m.mu. A ResetFailover that lands in that
	// unlocked window bumps the generation; the re-check then detects the
	// supersede and abandons its trailing SecondaryHold write so the
	// operator's reset is not silently clobbered. Guarded by m.mu.
	failoverGen map[int]uint64

	// stopped is set by Stop() to mark the manager quiesced. It guards the
	// per-RG hold-timer closure (readiness.go) so a takeover-hold timer that
	// had already fired and is blocked on m.mu when Stop() runs cannot run an
	// election on a stopped manager (#4716). Guarded by m.mu.
	stopped bool
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
		localHAProtocolVersion:         CurrentHAProtocolVersion,
		hbInterval:                     DefaultHeartbeatInterval,
		hbThreshold:                    DefaultHeartbeatThreshold,
		history:                        NewEventHistory(64),
		takeoverHoldTime:               DefaultTakeoverHoldTime,
		preManualFailoverRetryTimeout:  DefaultPreManualFailoverRetryTimeout,
		preManualFailoverRetryInterval: DefaultPreManualFailoverRetryInterval,
		failoverInProgress:             make(map[int]bool),
		failoverGen:                    make(map[int]uint64),
	}
}

// NodeID returns the local node ID.
func (m *Manager) NodeID() int { return m.nodeID }

// ClusterID returns the cluster ID.
func (m *Manager) ClusterID() int { return m.clusterID }

// controlLinkAuthKey returns the configured cluster control-channel PSK (raw
// bytes), or nil when no key is configured. The value is a secret and must
// never be logged. The slice is only ever replaced (never mutated in place),
// so returning the header under RLock is race-free for the read-only HMAC use.
func (m *Manager) controlLinkAuthKey() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.controlAuthKey
}

// ControlLinkAuthKey exposes the #4107 cluster control-channel PSK to
// in-process callers that authenticate a DIFFERENT control surface with the
// same shared secret — specifically the gRPC fabric listener (pkg/grpcapi),
// which HMAC-authenticates peer-proxied RPCs so the network-exposed fabric IP
// is not an unauthenticated management channel. Returns nil when no key is
// configured (legacy / dual-accept). The returned slice is a secret, must not
// be mutated, and must never be logged.
func (m *Manager) ControlLinkAuthKey() []byte {
	return m.controlLinkAuthKey()
}

// Events returns the event channel for state change notifications.
func (m *Manager) Events() <-chan ClusterEvent { return m.eventCh }

// Monitor returns the cluster interface/IP monitor, or nil if not set.
func (m *Manager) Monitor() *Monitor {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.monitor
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
//
// The stop-previous + swap + start-new sequence is serialized by monStartMu,
// but m.mu is released before the blocking calls: holding m.mu across the old
// monitor's Stop() deadlocks (#4828). Stop() joins the poll goroutine via
// wg.Wait(), and an in-flight SetMonitorWeight callback on that goroutine takes
// m.mu — so m.mu held here (AB) vs. m.mu wanted by the poll callback while
// Start waits on wg (BA) is a lock-order inversion. Only the m.monitor pointer
// swap needs m.mu; Stop()/Start() on the Monitor objects are self-synchronized
// (mon.mu + mon.wg), so they run outside m.mu. monStartMu keeps two concurrent
// Start calls from stopping/starting each other's monitors.
func (m *Manager) Start(ctx context.Context) {
	m.monStartMu.Lock()
	defer m.monStartMu.Unlock()

	m.mu.Lock()
	old := m.monitor
	mon := NewMonitor(m, nil) // groups set via UpdateConfig
	m.monitor = mon
	m.mu.Unlock()

	if old != nil {
		old.Stop()
	}
	mon.Start(ctx)
}

// Stop halts monitoring and heartbeat goroutines.
func (m *Manager) Stop() {
	m.mu.Lock()
	mon := m.monitor
	sender := m.hbSender
	receiver := m.hbReceiver
	m.hbSender = nil
	m.hbReceiver = nil
	// Mark the manager stopped and cancel every armed per-RG takeover-hold
	// timer (#4716). A timer armed while rg.Ready was true would otherwise
	// fire after Stop(), take m.mu, and run an election on a quiesced manager
	// — pinning the Manager in memory until takeoverHoldTime elapses. The
	// stopped flag additionally covers the race where a timer had already
	// fired and its closure is parked on m.mu: it acquires the lock after this
	// section releases it, observes m.stopped, and returns without electing.
	m.stopped = true
	for _, rg := range m.groups {
		if rg.holdTimer != nil {
			rg.holdTimer.Stop()
			rg.holdTimer = nil
		}
	}
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
