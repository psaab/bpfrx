package cluster

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
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

// TakeoverHoldRemaining returns how much of holdTime is still to run before
// IsReadyForTakeover(holdTime) can return true, or 0 when the hold is not what
// is holding this RG back — either it is not Ready at all (ReadinessReasons
// carries the real cause) or the hold has already elapsed.
//
// This exists because Ready and takeover-ELIGIBLE are different properties and
// the status render must not report the first as if it were the second (#103
// item 5). Between SetRGReady(ready) and ReadySince+holdTime the election gates
// at election.go/failover.go all refuse to promote, so an operator reading a
// bare "Takeover ready: yes" would see a status line that contradicts an
// election that is actively declining to promote, with nothing naming the hold.
func (rg *RedundancyGroupState) TakeoverHoldRemaining(holdTime time.Duration) time.Duration {
	if !rg.Ready || rg.ReadySince.IsZero() || holdTime <= 0 {
		return 0
	}
	remaining := holdTime - time.Since(rg.ReadySince)
	if remaining <= 0 {
		return 0
	}
	return remaining
}

// TakeoverHoldTime returns the configured minimum ready duration an RG must
// sustain before election will promote it (`set chassis cluster
// takeover-hold-time`). Zero — the default — means the hold adds nothing and
// Ready alone decides.
func (m *Manager) TakeoverHoldTime() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.takeoverHoldTime
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
	// remoteTransferOutLeaseUntil bounds how long a peer-REQUESTED transfer-out
	// keeps this node parked in secondary-hold without a commit. It is armed
	// (ArmRemoteTransferOutLease) when a remote failover request demotes an RG
	// via ManualFailover, and cleared on the matching commit
	// (ClearRemoteTransferOutLease, reqID-bound). If the lease expires with no
	// commit — a requester-side post-ACK abort/crash/partition that never sent
	// (or could not send) the commit — electRG auto-restores this node so a
	// failed coordinated failover cannot strand the cluster with both nodes
	// secondary (#5079). Only a REMOTE transfer-out arms a lease; a local
	// operator ManualFailover / ISSU ForceSecondary clears any stale entry so
	// their deliberate holds are never auto-restored. Read/written under m.mu.
	remoteTransferOutLeaseUntil map[int]time.Time
	remoteTransferOutLeaseReqID map[int]uint64
	// remoteTransferOutLease is how long an armed lease survives without a
	// commit before electRG restores the owner. Sized above the requester's
	// worst-case post-ACK commit latency; see DefaultRemoteTransferOutLease and
	// SetRemoteTransferOutLeaseDuration.
	remoteTransferOutLease time.Duration
	peerMonitors           []InterfaceMonitorInfo

	// lastDupNodeIDWarn rate-limits the duplicate-node-id warning (#4549 F11).
	// A peer advertising the local node's own node-id is an invalid cluster
	// (two chassis cannot share a node-id); the warning fires at most once per
	// 30s so a 5/s heartbeat stream cannot flood the log. Read/written under
	// m.mu.
	lastDupNodeIDWarn time.Time

	// Heartbeat goroutines (nil when not started).
	hbSender   *heartbeatSender
	hbReceiver *heartbeatReceiver

	// hbAuth is the #4107 control-channel authentication state for the peer:
	// the anti-replay watermarks plus the sticky peer-authenticated flag. It
	// deliberately hangs off the Manager rather than the heartbeatReceiver so
	// it survives every StartHeartbeat/RestartHeartbeat — a heartbeat restart
	// must not hand an attacker a fresh, empty replay tracker that re-admits
	// captured heartbeats from retired peer incarnations (#5086). Fixed size
	// (~1 KiB), allocated once, never reset for the life of the process. Its
	// own locking makes it safe to touch without m.mu.
	hbAuth heartbeatAuthState

	// hbNonceOnce/hbSession/hbCounter are the SENDER half of the control-channel
	// anti-replay nonce, scoped to the Manager — i.e. to one daemon incarnation.
	//
	// #6169: this used to be per-heartbeatSender, so every StartHeartbeat minted
	// a fresh random session and restarted the counter. That made the receiver's
	// bounded ring (heartbeatReplaySessions) a bound on peer SESSIONS rather
	// than on peer daemon incarnations, and routine events mint sessions —
	// RestartHeartbeat on a DHCP-triggered VRF rebind, the HA comms restart. A
	// single long-lived daemon could therefore emit more than a ringful of
	// distinct sessions under ONE boot epoch, and an attacker could churn the
	// ring among them without the epoch floor ever rejecting anything.
	//
	// One incarnation now emits exactly one session with a counter that is
	// monotonic across heartbeat restarts, so the epoch floor leaves an attacker
	// at most heartbeatEpochSessionsPerEpoch sessions to replay PER EPOCH VALUE
	// (heartbeatAuthState.highEpochSessions) and the ring rejects those on the
	// watermark.
	// Nothing regresses on the receiver: a heartbeat restart keeps the session
	// and advances the counter, which the ring admits; a daemon restart builds a
	// new Manager and so draws a fresh random session, which the ring admits as
	// never-seen exactly as before.
	hbNonceOnce sync.Once
	hbSession   uint64
	hbCounter   atomic.Uint64

	// bootEpochOnce/bootEpoch/bootEpochReady hold this daemon incarnation's
	// #6169 boot epoch: a persisted, increasing-across-restart counter carried
	// in the signed heartbeat so the peer can order incarnations. NOT strictly
	// increasing in every case — the persisted term is bounded, so a backward
	// clock step larger than bootEpochMaxSkew regresses it (#6711). See the
	// header comment in heartbeat_epoch.go.
	//
	// bootEpoch is published SYNCHRONOUSLY from the wall clock on first use,
	// before any file is touched, so it is never 0 for a node that has asked
	// for it — a storage fault cannot make this node emit epoch-less frames and
	// be declared dead by a latched peer. Persistence is a refinement that runs
	// off the send path (an fsync must never stall the 100ms send loop) and only
	// ever RAISES the value, its one job being to survive a backward clock step.
	// See Manager.heartbeatBootEpoch and refineBootEpoch.
	//
	// bootEpochReady is closed once the first refinement attempt finishes.
	// NOTHING in production waits on it — StartHeartbeat used to, which stalled
	// a node whose heartbeat was already stopped, and that wait was removed
	// (initHeartbeatEpochState).
	//
	// IT IS NOT A JOIN, and this comment used to offer it to tests as one. The
	// worker closes it from INSIDE its loop and then still calls
	// releaseBootEpochRefine — which reads a package-var test seam — and may run
	// further coalesced passes before returning, so a test that stops here
	// returns with a live worker that the next test's seam assignment races.
	// Tests join with awaitFirstRefine or waitBootEpochIdle. See
	// Manager.heartbeatBootEpoch, whose comment is the long form.
	//
	// bootEpochWrote is the epoch this incarnation last persisted. Refinement is
	// RE-RUN on every later heartbeat start (Manager.refreshBootEpoch), because
	// the epoch is resolved against a file other incarnations also write: one
	// that takes withEpochFileLock after us can raise the file above what we
	// published and park us below the peer's floor. Behind the boot-time
	// sync.Once alone that lasted for the life of the process. bootEpochWrote is
	// what keeps the re-run idempotent — a file still holding our own value is
	// left alone rather than chained from, which would ratchet the epoch by one
	// per pass.
	//
	// bootEpochRefine is ONE WORD holding TWO bits — bootEpochRefiningBit admits
	// one refine worker at a time, bootEpochPendingBit COALESCES a request that
	// arrives while that worker is in flight — and their being one word is a
	// correctness requirement, not packing. Two separate atomic.Bools could be
	// observed torn: a requester that read "a worker is in flight" and then
	// stored the pending bit after that worker's last check had nobody left to
	// serve it. Every transition is a CAS on the pair, so a requester whose
	// observation went stale fails its CAS and takes the in-flight slot itself.
	// See Manager.startBootEpochRefine.
	//
	// Dropping the request instead of coalescing it lost exactly the request
	// that was needed: the in-flight worker may already have completed its
	// locked READ, so an update that lands after it is invisible to that pass,
	// and the caller who lost the claim is the one asking for the re-read. It is
	// a BIT, not a queue: at most one extra pass is ever outstanding, so a
	// caller that must not block cannot build an unbounded backlog of fsync-ing
	// workers.
	//
	// bootEpochWorker is the CURRENT refine worker's exit handle — nil when none
	// is running — so Manager.Stop can join it with a bound and WITHOUT spawning
	// a waiter of its own. A per-call `go func() { wg.Wait(); close(done) }()`
	// helper is not cancelled by the caller's timeout, so every timed-out join
	// left one goroutine parked for as long as the worker was wedged, which is
	// forever.
	//
	// It is an atomic.Pointer, NOT a field under bootEpochRefineMu: that mutex
	// is held across claimBootEpochRefine (and so across its
	// epochRefineAfterLostClaim seam, where a requester can park indefinitely),
	// while the join and the worker's exit are precisely the two operations that
	// must not block. It is PUBLISHED under the mutex all the same, which is
	// what keeps Stop's refuse-then-join ordering airtight; bootEpochStopped,
	// under that mutex, refuses a spawn once Stop has begun.
	// See Manager.joinBootEpochRefine.
	bootEpochOnce     sync.Once
	bootEpoch         atomic.Uint64
	bootEpochReady    chan struct{}
	bootEpochWrote    atomic.Uint64
	bootEpochRefine   atomic.Uint32
	bootEpochRefineMu sync.Mutex
	bootEpochStopped  bool
	bootEpochWorker   atomic.Pointer[bootEpochRefineWorker]

	// lastEpochDowngradeWarn rate-limits the epoch-downgrade rejection warning.
	// The rejection is operator-actionable — a peer rolled back to a pre-#6169
	// build stays refused until the control-link PSK is rotated on BOTH nodes
	// and xpfd is then restarted on this one; a bare restart is not reliable
	// recovery, because an archived epoch-bearing frame replayed into the empty
	// post-restart state re-arms the latch (see the arming site in
	// admitAuthed) — so it must be visible. But the peer sends at 5-10/s,
	// so an unguarded log would flood journald. Read/written under m.mu.
	lastEpochDowngradeWarn time.Time

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

	// onDualActiveWinDrop is called when the dual-active "winner stays"
	// reaffirm event is dropped due to a full channel. The generic
	// onEventDrop reconcile is NOT sufficient for this event: the direct-VIP
	// ownership reconcile only re-announces on an ownership CHANGE, and a
	// dual-active winner is already the steady owner, so a plain reconcile
	// would not re-drive the post-split-brain GARP/NA refresh. The daemon
	// wires this to re-drive scheduleDirectAnnounce directly (#4867).
	onDualActiveWinDrop func(groupID int)

	// takeoverHoldTime is the minimum duration an RG must be ready before
	// election will promote it to primary. Zero means immediate takeover
	// once readiness is established.
	takeoverHoldTime time.Duration

	// syncReady is true once bulk session sync has been received (or the
	// readiness timeout released the hold). It gates NOTHING: no consumer
	// reads it to decide RG promotion, in private-rg-election / no-reth-vrrp
	// mode or any other (#7102). It was the no-RETH equivalent of the VRRP
	// sync-hold until 0781f7a60 removed that gate; today its only production
	// readers are the readiness timeout in pkg/daemon/daemon_ha_sync.go and
	// two log fields. See SetSyncReady in sync_state.go for the full account
	// and #110 for whether the gate should return.
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

	// configSyncFailing is a node-global DIAGNOSTIC health annotation raised
	// when a received config-sync generation has stayed un-applied past the
	// stale-duration grace (#6387). Config-sync apply hard-fails on the standby
	// (e.g. a missing host-inbound enforcement dependency) leave the config
	// high-water pinned (M-2/#4151), so the node is stuck `Transfer ready: no`
	// with `applied gen=0` while looking "healthy" in the summary. This flag
	// renders `CF` in the Monitor-failures column and flips Node health →
	// degraded so the stranded standby is operator-visible.
	//
	// It is deliberately a DEDICATED manager-level field, NOT a "CF"-in-
	// rg.MonitorFails sentinel: reconcileMonitorDebtsLocked (election.go) DELETES
	// any MonitorFails entry that is neither a configured interface-monitor nor
	// isIPMonitorName-true on EVERY UpdateConfig, so a sentinel would be wiped on
	// the next commit. A dedicated field also can NEVER perturb
	// Weight/monitorWeights/readiness/election — a config-apply failure is
	// node-global and must only annotate health, never demote priority or gate
	// failover (manual failover stays gated solely by ConfigStale(); crash
	// takeover stays ungated). Set via SetConfigSyncHealth; guarded by m.mu.
	configSyncFailing    bool
	configSyncFailReason string // bounded/sanitized, never a raw apply error
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

// DefaultRemoteTransferOutLease bounds how long a peer-requested transfer-out
// keeps a demoted owner in secondary-hold without a commit before electRG
// auto-restores it (#5079). The requester commits within its local
// commit-ready settle window (localFailoverCommitTimeout, default 3s) plus the
// commit round-trip, so 30s leaves ~10x headroom for a legitimate slow commit
// while bounding a stranded-secondary outage to tens of seconds instead of
// forever. The daemon raises this via SetRemoteTransferOutLeaseDuration when a
// larger commit timeout is configured so the lease never fires on an in-flight
// commit.
const DefaultRemoteTransferOutLease = 30 * time.Second

// minRemoteTransferOutLease floors SetRemoteTransferOutLeaseDuration so a
// misconfigured tiny value cannot abort a legitimate in-flight commit.
const minRemoteTransferOutLease = 15 * time.Second

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
		remoteTransferOutLeaseUntil:    make(map[int]time.Time),
		remoteTransferOutLeaseReqID:    make(map[int]uint64),
		remoteTransferOutLease:         DefaultRemoteTransferOutLease,
		localHAProtocolVersion:         CurrentHAProtocolVersion,
		hbInterval:                     DefaultHeartbeatInterval,
		hbThreshold:                    DefaultHeartbeatThreshold,
		history:                        NewEventHistory(64),
		takeoverHoldTime:               DefaultTakeoverHoldTime,
		preManualFailoverRetryTimeout:  DefaultPreManualFailoverRetryTimeout,
		preManualFailoverRetryInterval: DefaultPreManualFailoverRetryInterval,
		failoverInProgress:             make(map[int]bool),
		failoverGen:                    make(map[int]uint64),
		bootEpochReady:                 make(chan struct{}),
	}
}

// NoteEpochDowngradeHeartbeat surfaces a #6169 epoch-downgrade rejection.
//
// The peer previously proved it runs a build that signs a boot epoch, and is
// now sending frames without one. That is either a replay of pre-upgrade
// captures (the attack this closes) or a genuine rollback of the peer to a
// pre-#6169 build — which is operator-actionable. Rate-limited to once per 30s
// so a 5-10/s heartbeat stream cannot flood the log.
//
// THE RECOVERY THIS NAMES IS THE COMPLETE ONE, in order. Restarting xpfd clears
// the process-scoped latch, but an attacker holding one archived epoch-bearing
// frame re-arms it against the empty post-restart state — see the arming site
// in admitAuthed. Rotating the control-link PSK first makes every
// archived frame fail MAC verification, so it can never reach the latch. An
// operator told only "restart" would loop.
func (m *Manager) NoteEpochDowngradeHeartbeat() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if time.Since(m.lastEpochDowngradeWarn) < 30*time.Second {
		return
	}
	m.lastEpochDowngradeWarn = time.Now()
	slog.Warn("cluster: heartbeat refused — peer stopped signing a boot epoch it previously signed. " +
		"This is a replayed pre-upgrade capture, or the peer was rolled back to a build older than #6169. " +
		"If the rollback was intentional: rotate the control-link PSK on BOTH nodes FIRST, then restart " +
		"xpfd on THIS node to clear the latch. Restarting alone is not enough — a replayed archived " +
		"epoch frame re-arms the latch, and only rotating the PSK retires that capture")
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

// SetOnDualActiveWinDrop registers a callback invoked when the dual-active
// "winner stays" reaffirm event is dropped due to a full channel. The daemon
// wires this to re-drive the direct-mode GARP/NA announce so the
// post-split-brain refresh survives a saturated event channel — a plain
// reconcile does not re-announce for a steady VIP owner (#4867). The callback
// runs with m.mu held during runElection and must not re-enter the manager
// lock or perform blocking work inline.
func (m *Manager) SetOnDualActiveWinDrop(fn func(groupID int)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onDualActiveWinDrop = fn
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
//
// It also joins the boot-epoch refine worker, which nothing used to wait for.
// That worker is spawned from StartHeartbeat (initHeartbeatEpochState) or from
// the first signed send (heartbeatBootEpoch, under bootEpochOnce), and it is
// allowed to park indefinitely inside a flock or an fsync — so it OUTLIVING
// Stop needs no race at all: a single sequential shutdown over a wedged store
// reaches it. It would then still be storing to m.bootEpoch / m.bootEpochWrote
// and writing the state file on a manager the daemon has finished tearing down,
// and in tests it outlives the t.Cleanup that restores bootEpochPath / the
// epochFlock and epochNowNanos seams it reads.
//
// The join is BOUNDED for the reason the wait in initHeartbeatEpochState had to
// go: a storage fault must never stall the HA path, and this one runs directly
// after VRRP priority-0. See Manager.joinBootEpochRefine for what a timeout
// leaves behind.
//
// Stop is terminal, exactly like m.stopped: the flag is never cleared, so a
// manager that has been stopped starts no further refinement. A late
// heartbeatBootEpoch on a sender still winding down therefore still publishes
// its wall-clock epoch — that store is synchronous and ahead of any I/O — and
// simply skips the persistence refinement, which is the same degradation a
// wedged store produces and which the design already treats as survivable.
func (m *Manager) Stop() {
	// Refuse new refine workers BEFORE joining the one already running, so a
	// spawn cannot slip in behind the join and outlive it. startBootEpochRefine
	// claims the slot and publishes the worker's exit channel under this same
	// lock, so the two orders cannot interleave.
	m.bootEpochRefineMu.Lock()
	m.bootEpochStopped = true
	m.bootEpochRefineMu.Unlock()

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
	if !m.joinBootEpochRefine(bootEpochStopJoinBudget) {
		slog.Warn("cluster: HA boot-epoch refinement still in flight after teardown; "+
			"proceeding without it (its store is probably wedged — the shutdown path "+
			"must not block on one)", "waited", bootEpochStopJoinBudget)
	}
}
