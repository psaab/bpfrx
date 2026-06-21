package cluster

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// syncMagic identifies cluster session-sync protocol packets.
var syncMagic = [4]byte{'B', 'P', 'S', 'Y'}

// SessionSyncWireVersion is the schema version of the CROSS-CHASSIS session-sync
// wire protocol (the `syncMagic`/`syncMsg*`/`syncHeader` binary format below —
// NOT the daemon↔helper local control socket `userspace.ProtocolVersion`). It is
// the version the #1930 INC-3 mixed-base image-replace gate must compare across
// a mixed-base cluster: two nodes can only sync sessions if they speak the same
// sync wire schema. Bump this whenever the `syncMsg*` set or `syncHeader`
// changes incompatibly. The header has no on-wire version field today
// (compatibility has ridden the HA protocol version); this constant makes the
// sync schema version explicit for the gate. It tracks CurrentHAProtocolVersion
// (NOT LegacyHAProtocolVersion): the sync wire schema and the HA protocol have
// evolved together, so a CurrentHAProtocolVersion bump that changes the
// `syncMsg*`/`syncHeader` format carries the sync version with it. Deriving
// from the fixed Legacy constant would silently pin the gate to the stale
// schema version after an HA bump (Copilot). If the sync wire format ever
// diverges from the HA protocol version, replace this with its own counter.
const SessionSyncWireVersion = uint16(CurrentHAProtocolVersion)

const (
	syncMsgSessionV4              = 1
	syncMsgSessionV6              = 2
	syncMsgDeleteV4               = 3
	syncMsgDeleteV6               = 4
	syncMsgBulkStart              = 5
	syncMsgBulkEnd                = 6
	syncMsgHeartbeat              = 7
	syncMsgConfig                 = 8
	syncMsgIPsecSA                = 9
	syncMsgFailover               = 10
	syncMsgFence                  = 11
	syncMsgClockSync              = 12
	syncMsgBarrier                = 13
	syncMsgBarrierAck             = 14
	syncMsgBulkAck                = 15
	syncMsgFailoverAck            = 16
	syncMsgFailoverCommit         = 17
	syncMsgFailoverCommitAck      = 18
	syncMsgPrepareActivation      = 19
	syncMsgFailoverBatch          = 20
	syncMsgFailoverBatchAck       = 21
	syncMsgFailoverBatchCommit    = 22
	syncMsgFailoverBatchCommitAck = 23
	syncMsgHeartbeatAck           = 24
	// #2239 HA DHCP-server lease sync (PATH C). A full-set push of the
	// active lease records this node serves, per family. These are ADDITIVE
	// and length-gated: a peer that predates the feature hits the default
	// receive case and ignores them, and the records use the #2170
	// trailing-field discipline so the schema can grow. Deliberately NO
	// CurrentHAProtocolVersion / SessionSyncWireVersion bump — the change is
	// additive AND end-to-end gated on the `dhcp-lease-synchronization` config
	// knob, so a mixed-base pair (one side new, one old) is safe and must
	// still be allowed to sync SESSIONS; bumping the wire version would make
	// the #1930 INC-3 mixed-base gate falsely refuse session sync across the
	// pair. If a FUTURE change to these messages becomes incompatible, bump
	// the version then.
	syncMsgDHCPLeaseV4 = 25
	syncMsgDHCPLeaseV6 = 26
)

// syncHeader is the wire header for each sync message.
type syncHeader struct {
	Magic  [4]byte
	Type   uint8
	Pad    [3]byte
	Length uint32
}

const syncHeaderSize = 12
const syncWriteDeadline = 2 * time.Second
const failoverAckTimeout = 20 * time.Second
const syncReadDeadline = 10 * time.Second
const syncPeerSilenceTimeout = 30 * time.Second

// SyncStats tracks session synchronization statistics.
type SyncStats struct {
	SessionsSent      atomic.Uint64
	SessionsReceived  atomic.Uint64
	SessionsInstalled atomic.Uint64
	DeletesSent       atomic.Uint64
	DeletesReceived   atomic.Uint64
	BulkSyncs         atomic.Uint64
	ConfigsSent       atomic.Uint64
	ConfigsReceived   atomic.Uint64
	IPsecSASent       atomic.Uint64
	IPsecSAReceived   atomic.Uint64
	// #2239 HA DHCP-server lease sync counters. Sent/Received count
	// full-set lease push MESSAGES (one per family per push); Seeded counts
	// leases written into a freshly-started Kea on takeover; errors fold
	// into the shared Errors counter (fail-open posture).
	DHCPLeasesSent     atomic.Uint64
	DHCPLeasesReceived atomic.Uint64
	DHCPLeasesSeeded   atomic.Uint64
	FencesSent         atomic.Uint64
	FencesReceived     atomic.Uint64
	Errors             atomic.Uint64
	DeletesDropped     atomic.Uint64
	// DeletesStaleIgnored counts deletes refused by the #2170 install-
	// generation guard: a journaled/deferred delete whose generation was
	// strictly older than the currently-installed same-key entry. A nonzero
	// value means the guard prevented a stale delete from killing a live
	// same-5-tuple replacement session.
	DeletesStaleIgnored atomic.Uint64
	// InstallsStaleIgnored counts session installs refused because their
	// generation was strictly older than the currently-stored entry — the
	// delayed-stale-install variant (#2170 SMR C3). Refusing these keeps
	// the per-key stored generation monotonic so a later stale delete can
	// still be matched and refused.
	InstallsStaleIgnored atomic.Uint64
	// GenMapOverflow counts how many times a #2170 generation map (sender
	// echo or receiver stored) was at genGuardMapCap and a NEW key therefore
	// could not be recorded (#2198 F1). The key degrades to gen-0 (safe,
	// unconditional) behavior. A nonzero value means a churn workload pushed
	// a generation map to its cap; the map is never cleared, so existing live
	// keys retain their stored generation and the guard stays correct for
	// them.
	GenMapOverflow     atomic.Uint64
	Connected          atomic.Bool
	BulkSyncStartTime  atomic.Int64
	BulkSyncEndTime    atomic.Int64
	BulkSyncSessions   atomic.Uint64
	LastConfigSyncTime atomic.Int64
	LastConfigSyncSize atomic.Uint64
	LastFenceSeq       atomic.Uint64
	LastFenceAckAt     atomic.Int64
}

// SyncStatsSnapshot is a point-in-time copy of SyncStats with plain
// non-atomic fields, safe to copy by value and pass across API boundaries.
type SyncStatsSnapshot struct {
	SessionsSent         uint64
	SessionsReceived     uint64
	SessionsInstalled    uint64
	DeletesSent          uint64
	DeletesReceived      uint64
	BulkSyncs            uint64
	ConfigsSent          uint64
	ConfigsReceived      uint64
	IPsecSASent          uint64
	IPsecSAReceived      uint64
	DHCPLeasesSent       uint64
	DHCPLeasesReceived   uint64
	DHCPLeasesSeeded     uint64
	FencesSent           uint64
	FencesReceived       uint64
	Errors               uint64
	DeletesDropped       uint64
	DeletesStaleIgnored  uint64
	InstallsStaleIgnored uint64
	GenMapOverflow       uint64
	Connected            bool
	ActiveFabric         int
	BulkSyncStartTime    int64
	BulkSyncEndTime      int64
	BulkSyncSessions     uint64
	LastConfigSyncTime   int64
	LastConfigSyncSize   uint64
	LastFenceSeq         uint64
	LastFenceAckAt       int64
}

// TransferReadinessSnapshot captures session-sync state that determines whether
// manual failover can proceed without depending on bootstrap timing.
type TransferReadinessSnapshot struct {
	Connected             bool
	PendingBulkAckEpoch   uint64
	PendingBulkAckAge     time.Duration
	BulkReceiveInProgress bool
	BulkReceiveEpoch      uint64
	BulkReceiveSessions   int
}

// ReadyForManualFailover reports whether the sync path is settled enough to
// use as a manual-failover transport without waiting for bootstrap work.
func (s TransferReadinessSnapshot) ReadyForManualFailover() bool {
	return s.PendingBulkAckEpoch == 0 && !s.BulkReceiveInProgress
}

// Reason explains the current transfer-readiness blocker, if any.
func (s TransferReadinessSnapshot) Reason() string {
	switch {
	case s.PendingBulkAckEpoch != 0:
		age := s.PendingBulkAckAge
		if age < 0 {
			age = 0
		}
		return fmt.Sprintf("peer still receiving outbound bulk epoch=%d age=%s", s.PendingBulkAckEpoch, age.Round(100*time.Millisecond))
	case s.BulkReceiveInProgress:
		return fmt.Sprintf("local bulk receive still in progress epoch=%d sessions=%d", s.BulkReceiveEpoch, s.BulkReceiveSessions)
	default:
		return ""
	}
}

// SessionSync manages TCP-based session state replication between cluster
// peers for stateful failover.
type SessionSync struct {
	localAddr  string
	peerAddr   string
	sessions   dataplane.SessionStore
	telemetry  dataplane.Telemetry
	stats      SyncStats
	mu         sync.Mutex
	conn0      net.Conn
	conn1      net.Conn
	writeMu    sync.Mutex
	listener   net.Listener
	localAddr1 string
	peerAddr1  string
	listener1  net.Listener
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	sendCh     chan []byte // buffered channel for outgoing messages

	// incrementalPauseDepth temporarily pauses background incremental producers
	// during ordered handoff operations.
	incrementalPauseDepth atomic.Int32

	// OnConfigReceived is called when a config sync message arrives from the peer.
	OnConfigReceived func(configText string)
	// OnIPsecSAReceived is called when an IPsec SA list arrives from the peer.
	OnIPsecSAReceived func(connectionNames []string)
	// OnDHCPLeasesReceived is called when a DHCP-server lease set arrives from
	// the peer (#2239). family is 4 or 6; the standby holds these so it can
	// seed Kea on takeover. Fires after the peer*DHCPLeases store is updated.
	OnDHCPLeasesReceived func(family int, leases []dhcpserver.SyncLease)
	// OnRemoteFailover is called when the peer requests a transfer-out for one RG.
	OnRemoteFailover func(rgID int) error
	// OnRemoteFailoverCommit finalizes the demoted side of an acknowledged handoff.
	OnRemoteFailoverCommit func(rgID int) error
	// OnRemoteFailoverBatch is called when the peer requests a multi-RG transfer-out.
	OnRemoteFailoverBatch func(rgIDs []int) error
	// OnRemoteFailoverCommitBatch finalizes a previously acknowledged multi-RG handoff.
	OnRemoteFailoverCommitBatch func(rgIDs []int) error
	// OnFenceReceived requests this node to disable all RGs.
	OnFenceReceived func()
	// OnPrepareActivation asks the peer to pre-warm neighbors for the given RG.
	OnPrepareActivation func(rgID int)
	// OnForwardSessionInstalled fires when a forward synced session is installed locally.
	OnForwardSessionInstalled func()
	// OnBulkSyncReceived fires when an inbound bulk sync completes.
	OnBulkSyncReceived func()
	// BulkSyncOverride, if set, replaces the default BulkSync implementation.
	BulkSyncOverride func() error
	// OnBulkSyncAckReceived fires when the peer acknowledges our outbound bulk sync.
	OnBulkSyncAckReceived func()
	// OnPeerConnected fires when a peer sync connection is established.
	OnPeerConnected func()
	// OnPeerDisconnected fires when all fabric connections are lost.
	OnPeerDisconnected func()
	peerIPsecSAs       []string
	peerIPsecSAsMu     sync.Mutex
	// #2239: the standby holds the peer's most-recent full lease set per
	// family (the peerIPsecSAs precedent). On takeover the daemon reads these
	// and seeds the just-started Kea. Replaced wholesale on each full-set push.
	peerDHCPLeases4  []dhcpserver.SyncLease
	peerDHCPLeases6  []dhcpserver.SyncLease
	peerDHCPLeasesMu sync.Mutex
	// IsPrimaryFn reports whether the local node is primary for the default sync scope.
	IsPrimaryFn func() bool
	// IsPrimaryForRGFn reports whether the local node is primary for a given RG.
	IsPrimaryForRGFn           func(rgID int) bool
	lastSweepTime              uint64
	syncBackfillNeeded         atomic.Bool
	lastNewCounter             uint64
	lastClosedCounter          uint64
	lastSweepEmpty             bool
	vrfDevice                  string
	peerClockOffset            atomic.Int64
	clockSynced                atomic.Bool
	zoneRGMu                   sync.RWMutex
	zoneRGMap                  map[uint16]int
	deleteJournalMu            sync.Mutex
	deleteJournal              [][]byte
	deleteJournalCap           int
	lastPeerRxMono             atomic.Int64 // CLOCK_MONOTONIC nanos of last inbound sync msg (#1792)
	peerHeartbeatAckEver       atomic.Bool
	readDeadline               time.Duration
	peerSilenceLimit           time.Duration
	bulkSendMu                 sync.Mutex
	bulkSendNext               atomic.Uint64
	pendingBulkAckEpoch        atomic.Uint64
	pendingBulkAckSince        atomic.Int64
	bulkEverCompleted          atomic.Bool
	bulkMu                     sync.Mutex
	bulkInProgress             bool
	bulkRecvEpoch              uint64
	bulkRecvV4                 map[dataplane.SessionKey]struct{}
	bulkRecvV6                 map[dataplane.SessionKeyV6]struct{}
	bulkZoneSnapshot           map[uint16]bool
	barrierSeq                 atomic.Uint64
	barrierAckSeq              atomic.Uint64
	barrierWaitMu              sync.Mutex
	barrierWaiters             map[uint64]chan struct{}
	failoverWaitMu             sync.Mutex
	failoverWaiters            map[int]failoverWaiter
	failoverCommitWaiters      map[int]failoverWaiter
	failoverBatchWaiters       map[string]failoverWaiter
	failoverBatchCommitWaiters map[string]failoverWaiter
	failoverSeq                atomic.Uint64
	sessionMirrorWarnedV4      atomic.Bool
	sessionMirrorWarnedV6      atomic.Bool

	// #2170 HA deferred-delete generation guard.
	//
	// Sender side: genCounter is a single process-wide strictly-monotonic
	// install generation, seeded at construction from CLOCK_MONOTONIC nanos
	// so it never regresses below a value a peer may already hold across
	// this node's restarts within a boot. Every session install (Queue*,
	// sweep, bulk) draws genCounter.Add(1) and records it in genSentV4/V6
	// keyed by the wire key. A delete echoes the recorded generation (the
	// exact g of the install it cancels) and evicts the map entry, so the
	// delete's generation is always same-domain as the entry the receiver
	// stored. Generations are only ever compared per-(sender,key), never
	// across keys, so a single sender-local counter is sufficient and no
	// cross-node agreement on absolute values is required.
	//
	// Receiver side: recvGenV4/V6 is the authoritative per-key stored
	// generation (the BPF C struct stays generation-free, SMR fix #3). It
	// is set on install-apply and consulted by both the install guard and
	// the delete guard, then evicted on delete-apply.
	genCounter atomic.Uint64
	genSentMu  sync.Mutex
	genSentV4  map[dataplane.SessionKey]uint64
	genSentV6  map[dataplane.SessionKeyV6]uint64
	recvGenMu  sync.Mutex
	recvGenV4  map[dataplane.SessionKey]uint64
	recvGenV6  map[dataplane.SessionKeyV6]uint64
}
type failoverAck struct {
	status uint8
	detail string
}
type failoverWaiter struct {
	reqID uint64
	ch    chan failoverAck
	rgIDs []int
}

const (
	failoverAckApplied uint8 = iota
	failoverAckRejected
	failoverAckFailed
	failoverAckDisconnected
)

var ErrRemoteFailoverRejected = errors.New("remote failover rejected")

const maxFailoverBatchRGCount = 255

func encodeFailoverBatchRequestPayload(rgIDs []int, reqID uint64) []byte {
	payload := make([]byte, 1+len(rgIDs)+8)
	payload[0] = byte(len(rgIDs))
	for i, rgID := range rgIDs {
		payload[1+i] = byte(rgID)
	}
	binary.LittleEndian.PutUint64(payload[1+len(rgIDs):], reqID)
	return payload
}
func decodeFailoverBatchRequestPayload(payload []byte) ([]int, uint64, error) {
	if len(payload) < 1 {
		return nil, 0, fmt.Errorf("message too short")
	}
	count := int(payload[0])
	if count == 0 {
		return nil, 0, fmt.Errorf("batch has no redundancy groups")
	}
	if len(payload) < 1+count+8 {
		return nil, 0, fmt.Errorf("message too short")
	}
	rgIDs := make([]int, 0, count)
	for _, rgID := range payload[1 : 1+count] {
		rgIDs = append(rgIDs, int(rgID))
	}
	ids, err := normalizeFailoverRGIDs(rgIDs)
	if err != nil {
		return nil, 0, err
	}
	return ids, binary.LittleEndian.Uint64(payload[1+count : 1+count+8]), nil
}
func encodeFailoverBatchAckPayload(rgIDs []int, status uint8, reqID uint64, detail string) []byte {
	payload := make([]byte, 1+len(rgIDs)+1+8+len(detail))
	payload[0] = byte(len(rgIDs))
	for i, rgID := range rgIDs {
		payload[1+i] = byte(rgID)
	}
	payload[1+len(rgIDs)] = status
	binary.LittleEndian.PutUint64(payload[1+len(rgIDs)+1:], reqID)
	copy(payload[1+len(rgIDs)+1+8:], detail)
	return payload
}
func decodeFailoverBatchAckPayload(payload []byte) ([]int, uint8, uint64, string, error) {
	if len(payload) < 1 {
		return nil, 0, 0, "", fmt.Errorf("message too short")
	}
	count := int(payload[0])
	if count == 0 {
		return nil, 0, 0, "", fmt.Errorf("batch has no redundancy groups")
	}
	if len(payload) < 1+count+1+8 {
		return nil, 0, 0, "", fmt.Errorf("message too short")
	}
	rgIDs := make([]int, 0, count)
	for _, rgID := range payload[1 : 1+count] {
		rgIDs = append(rgIDs, int(rgID))
	}
	ids, err := normalizeFailoverRGIDs(rgIDs)
	if err != nil {
		return nil, 0, 0, "", err
	}
	status := payload[1+count]
	reqID := binary.LittleEndian.Uint64(payload[1+count+1 : 1+count+1+8])
	detail := string(payload[1+count+1+8:])
	return ids, status, reqID, detail, nil
}

type sessionSyncSweepProfiler interface {
	SessionSyncSweepProfile() (enabled bool, activeInterval, idleInterval time.Duration)
}
type clusterSyncedSessionInstaller interface {
	SetClusterSyncedSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error
	SetClusterSyncedSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error
}

const deleteJournalDefaultCap = 10000

// NewSessionSync creates a new single-fabric session synchronization manager.
//
// The runtime parameter is backend-neutral (see clusterRuntime in runtime.go).
// In-tree callers either pass nil at construction time and wire the runtime
// later via SetRuntime (the daemon's pattern, see daemon_ha_sync.go) or pass a
// runtime that already implements Sessions()/Telemetry() — both
// *dataplane.Manager and *dataplane/userspace.LegacyDataPlaneAdapter satisfy
// that contract. Callers that hold only a value typed as dataplane.DataPlane
// (the legacy bridge does NOT expose Sessions()/Telemetry() directly) can
// either: (a) wrap it in a small local type that adds Sessions() and
// Telemetry() returning dataplane.SessionStoreOf(dp) /
// dataplane.TelemetryOf(dp) and
// pass that wrapper here — Go structural typing accepts any value with the
// right method set even though clusterRuntime is package-private — or (b)
// pass nil and use the deprecated SetDataPlane alias, which performs the
// same adaptation internally.
func NewSessionSync(localAddr, peerAddr string, rt clusterRuntime) *SessionSync {
	s := &SessionSync{
		localAddr:                  localAddr,
		peerAddr:                   peerAddr,
		sendCh:                     make(chan []byte, 4096),
		deleteJournalCap:           deleteJournalDefaultCap,
		failoverWaiters:            make(map[int]failoverWaiter),
		failoverCommitWaiters:      make(map[int]failoverWaiter),
		failoverBatchWaiters:       make(map[string]failoverWaiter),
		failoverBatchCommitWaiters: make(map[string]failoverWaiter),
	}
	s.initGenState()
	s.SetRuntime(rt)
	return s
}

// initGenState seeds the #2170 install-generation counter from CLOCK_MONOTONIC
// nanos and initializes the sender/receiver generation maps. Seeding from the
// boot-relative monotonic clock keeps the counter from regressing below a
// value the peer may already hold after this node restarts (process restart)
// WITHIN a single OS boot.
//
// CROSS-BOOT (OS reboot) the monotonic clock resets, so this node's counter
// can come up LOWER than a generation the peer stored from our previous boot.
// That is handled on the RECEIVER side, not here: when a (reconnecting,
// possibly rebooted) peer begins its bulk re-prime, the receiver resets its
// per-key stored generations (resetRecvGen, called from the syncMsgBulkStart
// handler, #2198 F2). The bulk re-prime — which re-installs every owned
// session — then lands unconditionally and re-records each key's fresh
// generation, so the install guard accepts it instead of refusing it as stale
// (the stale-RETAIN inverse of #2170). A persisted cross-boot high-water mark
// is therefore unnecessary.
func (s *SessionSync) initGenState() {
	seed := uint64(MonotonicNanos())
	if seed == 0 {
		seed = 1
	}
	s.genCounter.Store(seed)
	s.genSentV4 = make(map[dataplane.SessionKey]uint64)
	s.genSentV6 = make(map[dataplane.SessionKeyV6]uint64)
	s.recvGenV4 = make(map[dataplane.SessionKey]uint64)
	s.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
}

// NewDualSessionSync creates a session sync manager with dual-fabric transport.
// If local1 or peer1 is empty, it falls back to single-fabric behavior. See
// NewSessionSync for the runtime parameter contract.
func NewDualSessionSync(local, peer, local1, peer1 string, rt clusterRuntime) *SessionSync {
	s := &SessionSync{
		localAddr:                  local,
		peerAddr:                   peer,
		localAddr1:                 local1,
		peerAddr1:                  peer1,
		sendCh:                     make(chan []byte, 4096),
		deleteJournalCap:           deleteJournalDefaultCap,
		failoverWaiters:            make(map[int]failoverWaiter),
		failoverCommitWaiters:      make(map[int]failoverWaiter),
		failoverBatchWaiters:       make(map[string]failoverWaiter),
		failoverBatchCommitWaiters: make(map[string]failoverWaiter),
	}
	s.initGenState()
	s.SetRuntime(rt)
	return s
}

// SetVRFDevice sets the VRF device used for SO_BINDTODEVICE on sync sockets.
func (s *SessionSync) SetVRFDevice(dev string) {
	s.vrfDevice = dev
}

// SetZoneRGMap sets the zone ID to redundancy-group mapping used for per-RG
// session synchronization.
func (s *SessionSync) SetZoneRGMap(m map[uint16]int) {
	s.zoneRGMu.Lock()
	s.zoneRGMap = m
	s.zoneRGMu.Unlock()
}

// SetRuntime wires the backend-neutral runtime used by SessionSync.
//
// Passing nil clears both runtime domains, matching the existing nil-
// tolerance contract (see SetRuntimeDomains and the sweep / bulk
// reconcile paths in sync_conn.go and sync_bulk.go that check for
// s.sessions == nil / s.telemetry == nil before touching the
// dataplane).
func (s *SessionSync) SetRuntime(rt clusterRuntime) {
	if rt == nil {
		s.SetRuntimeDomains(nil, nil)
		return
	}
	s.SetRuntimeDomains(rt.Sessions(), rt.Telemetry())
}

// SetDataPlane is the deprecated alias for SetRuntime. It is kept for one
// release cycle so any out-of-tree caller still passing the legacy
// dataplane.DataPlane bridge continues to compile. In-tree callers were
// migrated to SetRuntime as part of #1518.
//
// Deprecated: use SetRuntime. Both legacy *dataplane.Manager and the
// userspace LegacyDataPlaneAdapter satisfy clusterRuntime via Sessions()/
// Telemetry(); no adapter is needed.
func (s *SessionSync) SetDataPlane(dp dataplane.DataPlane) {
	if dp == nil {
		s.SetRuntimeDomains(nil, nil)
		return
	}
	s.SetRuntimeDomains(dataplane.SessionStoreOf(dp), dataplane.TelemetryOf(dp))
}

// SetRuntimeDomains sets the backend-neutral domains used by session sync.
// The old BPF-shaped dataplane is intentionally kept outside SessionSync's
// steady-state paths; callers that still own a legacy dataplane adapt it at the
// boundary with dataplane.SessionStoreOf/TelemetryOf.
func (s *SessionSync) SetRuntimeDomains(sessions dataplane.SessionStore, telemetry dataplane.Telemetry) {
	s.sessions = sessions
	s.telemetry = telemetry
}

// Stats returns a point-in-time snapshot of sync statistics.
func (s *SessionSync) Stats() SyncStatsSnapshot {
	s.mu.Lock()
	var activeFabric int
	if s.conn0 != nil {
		activeFabric = 0
	} else if s.conn1 != nil {
		activeFabric = 1
	} else {
		activeFabric = -1
	}
	s.mu.Unlock()
	return SyncStatsSnapshot{SessionsSent: s.stats.SessionsSent.Load(), SessionsReceived: s.stats.SessionsReceived.Load(), SessionsInstalled: s.stats.SessionsInstalled.Load(), DeletesSent: s.stats.DeletesSent.Load(), DeletesReceived: s.stats.DeletesReceived.Load(), BulkSyncs: s.stats.BulkSyncs.Load(), ConfigsSent: s.stats.ConfigsSent.Load(), ConfigsReceived: s.stats.ConfigsReceived.Load(), IPsecSASent: s.stats.IPsecSASent.Load(), IPsecSAReceived: s.stats.IPsecSAReceived.Load(), DHCPLeasesSent: s.stats.DHCPLeasesSent.Load(), DHCPLeasesReceived: s.stats.DHCPLeasesReceived.Load(), DHCPLeasesSeeded: s.stats.DHCPLeasesSeeded.Load(), FencesSent: s.stats.FencesSent.Load(), FencesReceived: s.stats.FencesReceived.Load(), Errors: s.stats.Errors.Load(), DeletesDropped: s.stats.DeletesDropped.Load(), DeletesStaleIgnored: s.stats.DeletesStaleIgnored.Load(), InstallsStaleIgnored: s.stats.InstallsStaleIgnored.Load(), GenMapOverflow: s.stats.GenMapOverflow.Load(), Connected: s.stats.Connected.Load(), ActiveFabric: activeFabric, BulkSyncStartTime: s.stats.BulkSyncStartTime.Load(), BulkSyncEndTime: s.stats.BulkSyncEndTime.Load(), BulkSyncSessions: s.stats.BulkSyncSessions.Load(), LastConfigSyncTime: s.stats.LastConfigSyncTime.Load(), LastConfigSyncSize: s.stats.LastConfigSyncSize.Load(), LastFenceSeq: s.stats.LastFenceSeq.Load(), LastFenceAckAt: s.stats.LastFenceAckAt.Load()}
}

// IsConnected reports whether a peer sync connection is currently established.
func (s *SessionSync) IsConnected() bool {
	return s.stats.Connected.Load()
}

// BulkEverCompleted reports whether at least one full bulk sync exchange has
// completed during this daemon instance's lifetime.
func (s *SessionSync) BulkEverCompleted() bool {
	return s.bulkEverCompleted.Load()
}

// ActiveFabric reports which fabric carries sync traffic: 0, 1, or -1 if disconnected.
func (s *SessionSync) ActiveFabric() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn0 != nil {
		return 0
	}
	if s.conn1 != nil {
		return 1
	}
	return -1
}

// LastPeerReceiveAge reports how long it has been since the last inbound sync
// message was received from the peer. The age is computed in the
// CLOCK_MONOTONIC domain (#1792): the previous time.Unix(0, last) round-trip
// stripped Go's monotonic reading, so a forward wall-clock step aged the
// peer past maxPeerSyncSilence at exactly the moment the heartbeat-timeout
// suppression guard needed it. Negative ages (impossible on a correct
// monotonic clock) clamp to 0.
func (s *SessionSync) LastPeerReceiveAge() (time.Duration, bool) {
	last := s.lastPeerRxMono.Load()
	if last == 0 {
		return 0, false
	}
	age := time.Duration(MonotonicNanos() - last)
	if age < 0 {
		age = 0
	}
	return age, true
}
func (s *SessionSync) readDeadlineDuration() time.Duration {
	if s.readDeadline > 0 {
		return s.readDeadline
	}
	return syncReadDeadline
}
func (s *SessionSync) peerSilenceDuration() time.Duration {
	if s.peerSilenceLimit > 0 {
		return s.peerSilenceLimit
	}
	return syncPeerSilenceTimeout
}

// PeerRecentlyActive reports whether an inbound sync message has been observed
// from the peer within maxAge.
func (s *SessionSync) PeerRecentlyActive(maxAge time.Duration) bool {
	age, ok := s.LastPeerReceiveAge()
	return ok && age <= maxAge
}

// PeerHealthy reports whether the sync path is connected and, once the peer
// has proved heartbeat-ack support, has been observed within the silence window.
func (s *SessionSync) PeerHealthy() bool {
	if !s.stats.Connected.Load() {
		return false
	}
	if !s.peerHeartbeatAckEver.Load() {
		return true
	}
	return s.PeerRecentlyActive(s.peerSilenceDuration())
}
func (s *SessionSync) WaitForIdle(timeout time.Duration, stableSamples int, sampleInterval time.Duration) error {
	if stableSamples <= 0 {
		stableSamples = 3
	}
	if sampleInterval <= 0 {
		sampleInterval = 200 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	var lastSent uint64
	var lastDeletes uint64
	var lastQueue int
	stable := 0
	initialized := false
	for {
		stats := s.Stats()
		queueLen := len(s.sendCh)
		if initialized && stats.SessionsSent == lastSent && stats.DeletesSent == lastDeletes && queueLen == lastQueue {
			stable++
			if stable >= stableSamples {
				return nil
			}
		} else {
			stable = 0
			lastSent = stats.SessionsSent
			lastDeletes = stats.DeletesSent
			lastQueue = queueLen
			initialized = true
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for session sync idle sessions_sent=%d deletes_sent=%d queue_len=%d", lastSent, lastDeletes, lastQueue)
		}
		time.Sleep(sampleInterval)
	}
}

func (s *SessionSync) snapshotZoneOwnership() map[uint16]bool {
	s.zoneRGMu.RLock()
	m := s.zoneRGMap
	s.zoneRGMu.RUnlock()
	snap := make(map[uint16]bool, len(m))
	for zoneID := range m {
		snap[zoneID] = s.ShouldSyncZone(zoneID)
	}
	return snap
}

func (s *SessionSync) reconcileStaleSessions() {
	s.bulkMu.Lock()
	if !s.bulkInProgress {
		s.bulkMu.Unlock()
		return
	}
	recvV4 := s.bulkRecvV4
	recvV6 := s.bulkRecvV6
	zoneSnap := s.bulkZoneSnapshot
	s.bulkInProgress = false
	s.bulkRecvV4 = nil
	s.bulkRecvV6 = nil
	s.bulkZoneSnapshot = nil
	s.bulkMu.Unlock()
	start := time.Now()
	slog.Info("cluster sync: reconcile stale sessions starting", "recv_v4", len(recvV4), "recv_v6", len(recvV6), "zones", len(zoneSnap))
	if len(recvV4) == 0 && len(recvV6) == 0 {
		slog.Info("cluster sync: reconcile stale sessions skipped (empty bulk)")
		return
	}
	if s.sessions == nil {
		slog.Info("cluster sync: reconcile stale sessions skipped (no dataplane)")
		return
	}
	if len(zoneSnap) == 0 {
		slog.Info("cluster sync: reconcile stale sessions skipped (no zone snapshot)")
		return
	}
	shouldSyncAtBulkStart := func(zoneID uint16) bool {
		if v, ok := zoneSnap[zoneID]; ok {
			return v
		}
		return true
	}
	var deleted int
	result, err := s.sessions.ReconcileClusterBulk(dataplane.ClusterBulkReconcileInput{
		ReceivedV4:     recvV4,
		ReceivedV6:     recvV6,
		ShouldSyncZone: shouldSyncAtBulkStart,
		DeleteReason:   dataplane.DeleteReasonClusterStale,
	})
	deleted = result.DeletedV4 + result.DeletedV6
	if err != nil {
		slog.Warn("cluster sync: reconcile stale sessions failed", "err", err)
		s.stats.Errors.Add(1)
	}
	slog.Info(
		"cluster sync: reconcile stale sessions applied",
		"stale_v4", result.StaleV4,
		"stale_v6", result.StaleV6,
		"deleted_v4", result.DeletedV4,
		"deleted_v6", result.DeletedV6,
	)
	if deleted > 0 {
		slog.Info("cluster sync: reconciled stale sessions", "deleted", deleted)
	}
	slog.Info("cluster sync: reconcile stale sessions complete", "deleted", deleted, "elapsed", time.Since(start))
}

func (s *SessionSync) FormatStats() string {
	activeFabric := s.ActiveFabric()
	fabricStr := "none"
	if activeFabric >= 0 {
		fabricStr = fmt.Sprintf("fab%d", activeFabric)
	}
	fenceSeq := s.stats.LastFenceSeq.Load()
	fenceAckAt := s.stats.LastFenceAckAt.Load()
	fenceAckStr := "never"
	if fenceAckAt > 0 {
		fenceAckStr = time.Unix(0, fenceAckAt).Format("Jan 02 15:04:05.000")
	}
	return fmt.Sprintf("Session sync statistics:\n"+"  Connected:          %v\n"+"  Active fabric:      %s\n"+"  Sessions sent:      %d\n"+"  Sessions received:  %d\n"+"  Sessions installed: %d\n"+"  Deletes sent:       %d\n"+"  Deletes received:   %d\n"+"  Bulk syncs:         %d\n"+"  Configs sent:       %d\n"+"  Configs received:   %d\n"+"  IPsec SAs sent:     %d\n"+"  IPsec SAs received: %d\n"+"  Fences sent:        %d\n"+"  Fences received:    %d\n"+"  Install fence seq:  %d\n"+"  Last fence ack:     %s\n"+"  Errors:             %d\n", s.stats.Connected.Load(), fabricStr, s.stats.SessionsSent.Load(), s.stats.SessionsReceived.Load(), s.stats.SessionsInstalled.Load(), s.stats.DeletesSent.Load(), s.stats.DeletesReceived.Load(), s.stats.BulkSyncs.Load(), s.stats.ConfigsSent.Load(), s.stats.ConfigsReceived.Load(), s.stats.IPsecSASent.Load(), s.stats.IPsecSAReceived.Load(), s.stats.FencesSent.Load(), s.stats.FencesReceived.Load(), fenceSeq, fenceAckStr, s.stats.Errors.Load())
}

func (s *SessionSync) PeerIPsecSAs() []string {
	s.peerIPsecSAsMu.Lock()
	defer s.peerIPsecSAsMu.Unlock()
	cp := make([]string, len(s.peerIPsecSAs))
	copy(cp, s.peerIPsecSAs)
	return cp
}

func (s *SessionSync) QueueIPsecSA(connectionNames []string) {
	conn := s.getActiveConn()
	if conn == nil {
		return
	}
	payload := encodeIPsecSAPayload(connectionNames)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgIPsecSA, payload)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: IPsec SA send error", "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return
	}
	s.stats.IPsecSASent.Add(1)
	slog.Debug("cluster sync: IPsec SA list sent", "count", len(connectionNames))
}

// RecordDHCPLeasesSeeded adds n to the seeded-leases counter (#2239). The
// daemon calls this after seeding a freshly-started Kea on takeover.
func (s *SessionSync) RecordDHCPLeasesSeeded(n int) {
	if n > 0 {
		s.stats.DHCPLeasesSeeded.Add(uint64(n))
	}
}

// PeerDHCPLeases4 returns a copy of the v4 lease set held from the peer (#2239).
// The standby seeds these into Kea on takeover.
func (s *SessionSync) PeerDHCPLeases4() []dhcpserver.SyncLease {
	s.peerDHCPLeasesMu.Lock()
	defer s.peerDHCPLeasesMu.Unlock()
	cp := make([]dhcpserver.SyncLease, len(s.peerDHCPLeases4))
	copy(cp, s.peerDHCPLeases4)
	return cp
}

// PeerDHCPLeases6 returns a copy of the v6 lease set held from the peer (#2239).
func (s *SessionSync) PeerDHCPLeases6() []dhcpserver.SyncLease {
	s.peerDHCPLeasesMu.Lock()
	defer s.peerDHCPLeasesMu.Unlock()
	cp := make([]dhcpserver.SyncLease, len(s.peerDHCPLeases6))
	copy(cp, s.peerDHCPLeases6)
	return cp
}

// SetPeerDHCPLeasesForTesting injects a held peer lease set for a family so
// cross-package tests (pkg/daemon) can drive the takeover-seed path without a
// live sync connection. Production fills this via the receive path.
func (s *SessionSync) SetPeerDHCPLeasesForTesting(family int, leases []dhcpserver.SyncLease) {
	s.storePeerDHCPLeases(family, leases)
}

// storePeerDHCPLeases replaces the held lease set for a family (full-set push
// semantics). Called from the receive path.
func (s *SessionSync) storePeerDHCPLeases(family int, leases []dhcpserver.SyncLease) {
	s.peerDHCPLeasesMu.Lock()
	if family == 6 {
		s.peerDHCPLeases6 = leases
	} else {
		s.peerDHCPLeases4 = leases
	}
	s.peerDHCPLeasesMu.Unlock()
}

// QueueDHCPLeases sends a full-set DHCP-server lease push for one family to the
// peer over the sync channel (#2239). family must be 4 or 6. Fail-open: a write
// error is logged + counted and disconnects the conn (the next reconnect
// re-pushes), it NEVER blocks lease granting on this node. Mirrors QueueIPsecSA.
func (s *SessionSync) QueueDHCPLeases(family int, leases []dhcpserver.SyncLease) {
	conn := s.getActiveConn()
	if conn == nil {
		return
	}
	msgType := byte(syncMsgDHCPLeaseV4)
	if family == 6 {
		msgType = syncMsgDHCPLeaseV6
	}
	payload := encodeDHCPLeasePayload(leases)
	s.writeMu.Lock()
	err := writeMsg(conn, msgType, payload)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: DHCP lease send error", "family", family, "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return
	}
	s.stats.DHCPLeasesSent.Add(1)
	slog.Debug("cluster sync: DHCP lease set sent", "family", family, "count", len(leases))
}
