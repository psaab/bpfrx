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

	"github.com/psaab/bpfrx/pkg/dataplane"
)

var syncMagic = [4]byte{'B', 'P', 'S', 'Y'}

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
)

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

type SyncStats struct {
	SessionsSent       atomic.Uint64
	SessionsReceived   atomic.Uint64
	SessionsInstalled  atomic.Uint64
	DeletesSent        atomic.Uint64
	DeletesReceived    atomic.Uint64
	BulkSyncs          atomic.Uint64
	ConfigsSent        atomic.Uint64
	ConfigsReceived    atomic.Uint64
	IPsecSASent        atomic.Uint64
	IPsecSAReceived    atomic.Uint64
	FencesSent         atomic.Uint64
	FencesReceived     atomic.Uint64
	Errors             atomic.Uint64
	DeletesDropped     atomic.Uint64
	Connected          atomic.Bool
	BulkSyncStartTime  atomic.Int64
	BulkSyncEndTime    atomic.Int64
	BulkSyncSessions   atomic.Uint64
	LastConfigSyncTime atomic.Int64
	LastConfigSyncSize atomic.Uint64
	LastFenceSeq       atomic.Uint64
	LastFenceAckAt     atomic.Int64
}

type SyncStatsSnapshot struct {
	SessionsSent       uint64
	SessionsReceived   uint64
	SessionsInstalled  uint64
	DeletesSent        uint64
	DeletesReceived    uint64
	BulkSyncs          uint64
	ConfigsSent        uint64
	ConfigsReceived    uint64
	IPsecSASent        uint64
	IPsecSAReceived    uint64
	FencesSent         uint64
	FencesReceived     uint64
	Errors             uint64
	DeletesDropped     uint64
	Connected          bool
	ActiveFabric       int
	BulkSyncStartTime  int64
	BulkSyncEndTime    int64
	BulkSyncSessions   uint64
	LastConfigSyncTime int64
	LastConfigSyncSize uint64
	LastFenceSeq       uint64
	LastFenceAckAt     int64
}

type TransferReadinessSnapshot struct {
	Connected             bool
	PendingBulkAckEpoch   uint64
	PendingBulkAckAge     time.Duration
	BulkReceiveInProgress bool
	BulkReceiveEpoch      uint64
	BulkReceiveSessions   int
}

func (s TransferReadinessSnapshot) ReadyForManualFailover() bool {
	return s.PendingBulkAckEpoch == 0 && !s.BulkReceiveInProgress
}

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

type SessionSync struct {
	localAddr  string
	peerAddr   string
	dp         dataplane.DataPlane
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
	sendCh     chan []byte // Package cluster session synchronization (RTO - Real-Time Objects).
	// Replicates session state between cluster nodes for stateful failover.
	// syncMagic identifies RTO protocol packets.
	// Sync message types.
	// full config text sync from primary to secondary
	// IPsec SA connection names sync
	// remote failover request (payload: 1 byte rgID)
	// peer fencing: receiver should disable all RGs
	// monotonic clock exchange for timestamp rebasing
	// ordered marker for remote install barriers
	// failover request result (payload: rgID, status, detail)
	// failover ownership commit (payload: rgID, reqID)
	// failover commit result (payload: rgID, status, detail)
	// hint: demoting node tells peer to pre-warm neighbors (payload: 1 byte rgID)
	// remote failover request for multiple RGs
	// multi-RG failover request result
	// multi-RG failover ownership commit
	// multi-RG failover commit result
	// syncHeader is the wire header for each sync message.
	// payload length after header
	// SyncStats tracks session synchronization statistics.
	// deletes lost when journal is full
	// Cold sync timing.
	// UnixNano (0 = never)
	// UnixNano (0 = in progress or never)
	// sessions in current/last bulk
	// Config sync timing.
	// UnixNano
	// bytes
	// Install fence (#311): barrier-based cutover sequence tracking.
	// last barrier sequence sent
	// UnixNano when last barrier ack was received
	// SyncStatsSnapshot is a point-in-time copy of SyncStats with plain
	// (non-atomic) fields, safe to copy by value and pass across API boundaries.
	// 0=fab0, 1=fab1, -1=disconnected
	// Install fence (#311).
	// UnixNano (0 = never)
	// TransferReadinessSnapshot captures session-sync state that determines
	// whether manual failover can proceed without depending on bootstrap timing.
	// ReadyForManualFailover reports whether the sync path is settled enough to
	// use as a manual-failover transport without waiting for bootstrap work.
	// Reason explains the current transfer-readiness blocker, if any.
	// SessionSync manages TCP-based session state replication between cluster peers.
	// local listen address (e.g. ":4785")
	// peer connect address (e.g. "10.0.0.2:4785")
	// fab0 connection (preferred)
	// fab1 connection (fallback)
	// serializes all conn.Write calls (sendLoop + writeMsg)
	// secondary fabric listen address ("" = single-fabric)
	// secondary fabric peer address
	// secondary fabric listener
	// buffered channel for outgoing messages
	// incrementalPauseDepth temporarily pauses background incremental
	// producers (periodic sweeps) during HA demotion handoff so ordered
	// demotion barriers are not queued behind unrelated backlog.
	// OnConfigReceived is called when a config sync message arrives from peer.
	// The callback receives the full config text. Set by the daemon before Start().
	// OnIPsecSAReceived is called when an IPsec SA list arrives from the peer.
	// On failover, the new primary calls swanctl --initiate for each connection name.
	// OnRemoteFailover is called when the peer requests us to transfer an RG
	// out of primary. The callback receives the redundancy group ID and
	// should return whether the transfer-out was applied or rejected so the
	// requester can treat manual failover as an explicit handshake.
	// OnRemoteFailoverCommit is called when the peer has committed local
	// ownership after an acknowledged transfer-out and asks us to finalize
	// the demoted side of the handoff.
	// OnRemoteFailoverBatch is called when the peer requests us to transfer
	// multiple RGs out of primary in one explicit handoff transaction.
	// OnRemoteFailoverCommitBatch finalizes the demoted side of a previously
	// acknowledged multi-RG handoff after the peer commits ownership.
	// OnFenceReceived is called when the peer sends a fence message, requesting
	// this node to disable all RGs (set rg_active=false). The receiver should
	// call dp.UpdateRGActive(rgID, false) for every RG.
	// OnPrepareActivation is called when the demoting peer has completed its
	// preflight and is about to resign VRRP. The activating node should
	// pre-install neighbor entries and warm the ARP/NDP cache so that
	// bpf_fib_lookup succeeds for the first packet after VRRP MASTER (#485).
	// OnForwardSessionInstalled is called when a forward cluster-synced
	// session has been successfully installed into the local dataplane.
	// The daemon uses this as a low-latency signal to refresh standby
	// neighbor state without waiting for the periodic sweep interval.
	// OnBulkSyncReceived is called when a bulk sync transfer completes
	// (syncMsgBulkEnd received). The secondary uses this to release VRRP
	// sync hold after session state has been installed.
	// BulkSyncOverride, if set, is called instead of BulkSync() when the
	// outbound bulk transfer needs to run. The daemon sets this to route
	// through the event stream export path for userspace dataplanes.
	// OnBulkSyncAckReceived is called when the peer acknowledges that it
	// has fully processed one of our bulk sync transfers.
	// OnPeerConnected is called when a peer sync connection is established
	// (either inbound accept or outbound connect). The primary uses this to
	// push config to a returning secondary.
	// OnPeerDisconnected is called when all fabric connections are lost
	// (total disconnect). Used to reset sync readiness so that a fresh
	// bulk sync is required before the node can promote to primary.
	// peerIPsecSAs holds the latest IPsec connection names received from the peer.
	// returns true if local node is primary for RG 0
	// returns true if local is primary for given RG
	// monotonic seconds of last sync sweep
	// replay sweep window on send queue overflow
	// last seen GLOBAL_CTR_SESSIONS_NEW
	// last seen GLOBAL_CTR_SESSIONS_CLOSED
	// previous sweep found 0 sessions to sync
	// VRF device for SO_BINDTODEVICE (empty = default VRF)
	// Peer clock offset: localMono - peerMono.  Added to incoming
	// session timestamps so Created/LastSeen are in our clock domain.
	// zone_id -> RG_id (for per-RG session sync)
	// Delete journal: bounded ring buffer for delete messages during disconnect.
	// Deletes are journaled when queueMessage fails (disconnect), then flushed
	// on reconnect before normal sync resumes.
	// ring buffer of encoded delete messages
	// max entries (default 10000)
	// bulkSendMu serializes entire BulkSync() calls so two concurrent
	// callers (e.g. acceptLoop and connectLoop) cannot interleave.
	// monotonic epoch counter for outgoing bulk syncs
	// pendingBulkAckEpoch tracks the latest outbound bulk epoch that has been
	// fully written but not yet acknowledged by the peer.
	// UnixNano
	// bulkEverCompleted tracks whether at least one full bulk sync exchange
	// has completed during this daemon instance's lifetime. Once true it
	// survives reconnects; only a daemon restart resets it. Used to
	// distinguish a true cold start (needs bulk) from a routine reconnect
	// or fabric flip (incremental sync is sufficient).
	// Bulk receive tracking for stale-entry reconciliation.
	// During bulk receive (BulkStart..BulkEnd), track all received
	// forward session keys. On BulkEnd, delete local sessions in
	// peer-owned zones that were not refreshed.
	// epoch of current in-progress bulk receive
	// snapshot of ShouldSyncZone at BulkStart
	// deleteJournalDefaultCap is the default max entries in the delete journal.
	// NewSessionSync creates a new session synchronization manager.
	// NewDualSessionSync creates a session sync manager with dual fabric transport.
	// If local1/peer1 are empty, falls back to single-fabric behavior.
	// SetVRFDevice sets the VRF device for SO_BINDTODEVICE on sync sockets.
	// SetZoneRGMap sets the zone ID → redundancy group mapping for per-RG
	// session sync. Sessions are synced only when the local node is primary
	// for the RG that owns the session's ingress zone.
	// SetDataPlane sets the dataplane used for installing received sessions.
	// Called by the daemon after the dataplane is loaded (which happens after sync init).
	// Stats returns a point-in-time snapshot of sync statistics.
	// The snapshot uses plain fields (no atomics) so it is safe to copy by value.
	// IsConnected returns true if the peer connection is established.
	// BulkEverCompleted reports whether at least one full bulk sync exchange
	// has completed during this daemon instance's lifetime.
	// ActiveFabric returns which fabric carries sync traffic: 0, 1, or -1 if disconnected.
	// LastPeerReceiveAge returns how long it has been since the last inbound sync
	// message was received from the peer. The second return value is false if no
	// inbound sync traffic has ever been observed on the current process lifetime.
	// PeerRecentlyActive reports whether an inbound sync message has been observed
	// from the peer within maxAge.
	// PeerHealthy reports whether the sync connection is established and, once the
	// peer has ever proved heartbeat-ack support, has been observed on the
	// protocol within the expected silence window. Before that capability is ever
	// observed we fall back to plain connection state so rolling upgrades do not
	// flap readiness.
	// activeConnLocked returns the preferred active connection.
	// fab0 is preferred; fab1 is used only when fab0 is down.
	// Caller must hold s.mu.
	// getActiveConn returns the active connection, taking the lock.
	// TCP_NODELAY disables Nagle's algorithm so small control messages
	// (barriers, heartbeats) are not held waiting for outstanding data
	// to be ACKed before sending. Important for barrier latency.
	// handleNewConnection processes a newly established connection on the given fabric.
	// It sets the connection in the appropriate slot, starts the receive loop, exchanges
	// clocks, and triggers bulk sync if this is the first connection after a total disconnect.
	// Start receive loop for this connection.
	// Exchange monotonic clocks on every new connection.
	// Only trigger bulk sync on a true cold start — when we have never
	// completed a bulk exchange during this daemon instance's lifetime.
	// Routine reconnects (brief network blip) and active-fabric flips
	// already have synced sessions; they resume incremental sync
	// immediately without the overhead of a full bulk transfer (#466).
	// Start begins the sync protocol (listener + connector).
	// Start listener for incoming peer connections.
	// Accept incoming connections on primary fabric.
	// Start secondary fabric listener if configured.
	// Use one deterministic TCP initiator per fabric. Dual dialers create
	// duplicate sync streams, mid-bulk connection replacement, and lost
	// failover-handoff messages during reconnect windows.
	// Connect to peer on secondary fabric if configured.
	// Sender goroutine.
	// Stop gracefully shuts down session sync.  If goroutines do not exit
	// within 5 seconds the method returns anyway so the daemon can proceed
	// with HA teardown (clearing rg_active, removing BPF state).
	// Clean exit.
	// StartSyncSweep starts a goroutine that periodically syncs sessions to the peer.
	// Sessions with Created >= lastSweepTime (new) or LastSeen >= lastSweepTime
	// (recently active) are queued for sync, ensuring established flows get their
	// updated TCP state, timeouts, and last-seen timestamps replicated to standby.
	// Back off when nothing to sync so the authoritative dataplane
	// is not batch-walked unnecessarily. Userspace forwarding can
	// override these intervals because it already streams create/close
	// deltas out of band and only needs periodic refreshes.
	// ShouldSyncZone returns true if the local node should sync sessions for
	// the given zone. When IsPrimaryForRGFn is set and a zone→RG mapping
	// exists, only sessions whose ingress zone belongs to a locally-primary
	// RG are synced. Falls back to the global IsPrimaryFn otherwise.
	// Fallback: use global primary check (backward compat, or zone not
	// mapped to an RG — e.g. non-RETH interfaces always use RG 0).
	// At least one primary check must be wired.
	// Fast path: skip expensive BatchIterate when no sessions have changed.
	// Reading two per-CPU counters is O(1) vs BatchIterate which is O(buckets)
	// even for an empty 10M-entry hash map.
	// Batch iteration reduces kernel lock contention with BPF datapath
	// Only sweep sessions created since last threshold. The ring event
	// path handles near-real-time create delivery; sweep is reconciliation
	// only. Established flows whose LastSeen moved but were created before
	// the threshold do not need re-syncing — the peer already has them.
	// Keep lastSweepTime unchanged so the next sweep retries this
	// same window, preventing permanent sync gaps on queue pressure.
	// Snapshot counters so next sweep can skip if nothing changed.
	// PauseIncrementalSync temporarily disables background sweep-driven session
	// replication. Explicit sync producers (for example demotion-prep republish)
	// are unaffected and may continue queueing messages.
	// ResumeIncrementalSync releases a previous PauseIncrementalSync call.
	// QueueSessionV4 queues a v4 session for sync to peer.
	// QueueSessionV6 queues a v6 session for sync to peer.
	// QueueDeleteV4 queues a v4 session deletion for sync.
	// If the peer is disconnected, the delete is journaled for replay on reconnect.
	// QueueDeleteV6 queues a v6 session deletion for sync.
	// If the peer is disconnected, the delete is journaled for replay on reconnect.
	// journalDelete stores a delete message in the bounded ring buffer
	// for replay on reconnect. If the journal is full, the oldest entry
	// is evicted and DeletesDropped is incremented.
	// Evict oldest entry (ring buffer behavior).
	// flushDeleteJournal replays all journaled delete messages through the
	// send channel. Called on reconnect before normal sync resumes.
	// QueueConfig sends the full config text to the peer for config synchronization.
	// Called by the primary node after a successful commit.
	// SendFailover sends a remote failover request to the peer and waits for
	// an explicit applied/rejected acknowledgement. On success it returns the
	// acknowledged request ID for the later transfer-commit step.
	// SendFailoverBatch sends a remote failover request for multiple RGs and waits
	// for an explicit applied/rejected acknowledgement.
	// SendFailoverCommit sends the final ownership-commit step for a previously
	// acknowledged failover request and waits for the peer to finalize transfer-out.
	// SendFailoverCommitBatch sends the final ownership-commit step for a
	// previously acknowledged multi-RG failover request.
	// SendFence sends a fence message to the peer, requesting it to disable all
	// RGs (set rg_active=false). This is a best-effort operation — if the sync
	// connection is down (likely during a real failure), the call returns an error.
	// SendPrepareActivation tells the peer to pre-install neighbor entries
	// and warm its ARP/NDP cache for the given RG. Sent by the demoting node
	// after its preflight completes, just before VRRP resign. Best-effort:
	// if the send fails, the activation path still works (slightly slower
	// neighbor resolution via warmNeighborCache).
	// BulkSync sends the entire session table to the connected peer.
	// Serialized by bulkSendMu so concurrent callers cannot interleave.
	// fabricConnectLoop retries outbound connection on a single fabric link.
	// Each fabric gets its own loop so fab0 reconnects independently of fab1.
	// Skip if this fabric is already connected.
	// sendOne writes a single message to the active connection, retrying
	// on transient errors until success or context cancellation.
	// Request an explicit heartbeat ack so one-way steady-state
	// traffic still proves the reverse direction is alive.
	// 16MB sanity limit (config can be large)
	// Track forward keys during bulk receive for stale reconciliation.
	// Rebase timestamps to local monotonic clock using
	// the clock offset exchanged at connection setup.
	// Invalidate FIB cache — peer's cached ifindex/MAC/gen
	// are meaningless on this node. Forces a fresh
	// bpf_fib_lookup so hairpin and RG-active checks work.
	// Create reverse session entry from forward entries so return
	// traffic matches conntrack on the takeover node.
	// Swap zones: reverse traffic enters on egress zone
	// and exits on ingress zone.
	// Create dnat_table entry for SNAT reverse pre-routing.
	// xdp_zone uses dnat_table to rewrite dst back to the real
	// client before conntrack lookup on return traffic.
	// Track forward keys during bulk receive for stale reconciliation.
	// Rebase timestamps using clock offset (same as V4).
	// Invalidate FIB cache (same as V4 above).
	// Look up session before deleting to clean up reverse entry
	// and SNAT dnat_table entry.
	// Snapshot zone ownership at BulkStart so reconciliation uses a
	// consistent view even if primary/secondary roles flip mid-bulk.
	// Record fence ack timestamp for status observability (#311).
	// snapshotZoneOwnership returns a map of zoneID→shouldSync for all zones
	// currently in the zone→RG mapping. Used to freeze ownership at BulkStart.
	// reconcileStaleSessions deletes local sessions in peer-owned zones that
	// were not refreshed during the bulk receive. Called on BulkEnd.
	// shouldSyncAtBulkStart uses the frozen snapshot if available. Zones missing
	// from that snapshot are treated as syncable to avoid deleting sessions
	// before the current bulk stream has finished delivering them.
	// Zone missing from the frozen snapshot means ownership was not known at
	// BulkStart. Skip stale reconciliation for that zone rather than falling
	// back to a later live view that can delete sessions we have not finished
	// receiving from the peer yet.
	// Collect stale v4 sessions for deletion (can't delete during iteration).
	// Only reconcile sessions in zones the peer owns (where we're NOT primary).
	// Look up to clean reverse entry and dnat_table.
	// Collect stale v6 sessions.
	// Do NOT reset barrierSeq — the monotonic counter must keep
	// incrementing across reconnects. Resetting to 0 causes sequence
	// collisions: a stale WaitForPeerBarrier goroutine from the old
	// connection holds seq=N, and after reset the next barrier reuses
	// seq=N. When the stale goroutine's timer fires it deletes the
	// new waiter, causing the new barrier to time out (#458).
	// Keep barrierAckSeq monotonic too — resetting to 0 can cause a
	// completed barrier to be misclassified as a disconnect if the
	// waiter goroutine checks after handleDisconnect runs.
	// Close stale waiter channels so any blocked WaitForPeerBarrier
	// goroutine wakes up immediately instead of leaking until timeout.
	// Reset any in-progress bulk receive — the connection that started
	// it is gone, so the BulkEnd will never arrive.
	// FormatStats returns a formatted string of sync statistics.
	// PeerIPsecSAs returns the latest IPsec connection names received from the peer.
	// QueueIPsecSA sends the list of active IPsec connection names to the peer.
	// monotonicSeconds returns monotonic clock in seconds.
	// rebaseTimestamp adjusts a peer timestamp to the local clock domain.
	// offset = localMono − peerMono (computed at connection setup).
	// --- Wire encoding helpers ---
	// writeFull loops until all bytes are written or an error occurs,
	// handling short writes from TCP backpressure.
	// SessionKey: 4+4+2+2+1+3
	// includes userspace FIB cache metadata
	// Key
	// include pad
	// Value (key fields for session reconstruction)
	// include pad0
	// Counters
	// Reverse key
	// include pad
	// include pad1
	// generous buffer for v6
	// Key
	// include pad
	// Value
	// Reverse key
	// --- Session decode helpers ---
	// decodeSessionV4Payload decodes a v4 session from wire format.
	// Returns key, value, and ok flag. Must match encodeSessionV4Payload layout.
	// minimum key size
	// include pad
	// include pad0
	// partial value is OK for key-only
	// include pad
	// include pad1
	// decodeSessionV6Payload decodes a v6 session from wire format.
	// minimum key size
	// include pad
	// include pad0
	// include pad1
	// --- IPsec SA encode/decode ---
	// encodeIPsecSAPayload encodes a list of IPsec connection names as newline-separated bytes.
	// decodeIPsecSAPayload decodes a newline-separated list of IPsec connection names.

	incrementalPauseDepth       atomic.Int32
	OnConfigReceived            func(configText string)
	OnIPsecSAReceived           func(connectionNames []string)
	OnRemoteFailover            func(rgID int) error
	OnRemoteFailoverCommit      func(rgID int) error
	OnRemoteFailoverBatch       func(rgIDs []int) error
	OnRemoteFailoverCommitBatch func(rgIDs []int) error
	OnFenceReceived             func()
	OnPrepareActivation         func(rgID int)
	OnForwardSessionInstalled   func()
	OnBulkSyncReceived          func()
	BulkSyncOverride            func() error
	OnBulkSyncAckReceived       func()
	OnPeerConnected             func()
	OnPeerDisconnected          func()
	peerIPsecSAs                []string
	peerIPsecSAsMu              sync.Mutex
	IsPrimaryFn                 func() bool
	IsPrimaryForRGFn            func(rgID int) bool
	lastSweepTime               uint64
	syncBackfillNeeded          atomic.Bool
	lastNewCounter              uint64
	lastClosedCounter           uint64
	lastSweepEmpty              bool
	vrfDevice                   string
	peerClockOffset             atomic.Int64
	clockSynced                 atomic.Bool
	zoneRGMu                    sync.RWMutex
	zoneRGMap                   map[uint16]int
	deleteJournalMu             sync.Mutex
	deleteJournal               [][]byte
	deleteJournalCap            int
	lastPeerRxUnix              atomic.Int64
	peerHeartbeatAckEver        atomic.Bool
	readDeadline                time.Duration
	peerSilenceLimit            time.Duration
	bulkSendMu                  sync.Mutex
	bulkSendNext                atomic.Uint64
	pendingBulkAckEpoch         atomic.Uint64
	pendingBulkAckSince         atomic.Int64
	bulkEverCompleted           atomic.Bool
	bulkMu                      sync.Mutex
	bulkInProgress              bool
	bulkRecvEpoch               uint64
	bulkRecvV4                  map[dataplane.SessionKey]struct{}
	bulkRecvV6                  map[dataplane.SessionKeyV6]struct{}
	bulkZoneSnapshot            map[uint16]bool
	barrierSeq                  atomic.Uint64
	barrierAckSeq               atomic.Uint64
	barrierWaitMu               sync.Mutex
	barrierWaiters              map[uint64]chan struct{}
	failoverWaitMu              sync.Mutex
	failoverWaiters             map[int]failoverWaiter
	failoverCommitWaiters       map[int]failoverWaiter
	failoverBatchWaiters        map[string]failoverWaiter
	failoverBatchCommitWaiters  map[string]failoverWaiter
	failoverSeq                 atomic.Uint64
	sessionMirrorWarnedV4       atomic.Bool
	sessionMirrorWarnedV6       atomic.Bool
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

func NewSessionSync(localAddr, peerAddr string, dp dataplane.DataPlane) *SessionSync {
	return &SessionSync{localAddr: localAddr, peerAddr: peerAddr, dp: dp, sendCh: make(chan []byte, 4096), deleteJournalCap: deleteJournalDefaultCap, failoverWaiters: make(map[int]failoverWaiter), failoverCommitWaiters: make(map[int]failoverWaiter), failoverBatchWaiters: make(map[string]failoverWaiter), failoverBatchCommitWaiters: make(map[string]failoverWaiter)}
}

func NewDualSessionSync(local, peer, local1, peer1 string, dp dataplane.DataPlane) *SessionSync {
	return &SessionSync{localAddr: local, peerAddr: peer, localAddr1: local1, peerAddr1: peer1, dp: dp, sendCh: make(chan []byte, 4096), deleteJournalCap: deleteJournalDefaultCap, failoverWaiters: make(map[int]failoverWaiter), failoverCommitWaiters: make(map[int]failoverWaiter), failoverBatchWaiters: make(map[string]failoverWaiter), failoverBatchCommitWaiters: make(map[string]failoverWaiter)}
}

func (s *SessionSync) SetVRFDevice(dev string) {
	s.vrfDevice = dev
}

func (s *SessionSync) SetZoneRGMap(m map[uint16]int) {
	s.zoneRGMu.Lock()
	s.zoneRGMap = m
	s.zoneRGMu.Unlock()
}

func (s *SessionSync) SetDataPlane(dp dataplane.DataPlane) {
	s.dp = dp
}

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
	return SyncStatsSnapshot{SessionsSent: s.stats.SessionsSent.Load(), SessionsReceived: s.stats.SessionsReceived.Load(), SessionsInstalled: s.stats.SessionsInstalled.Load(), DeletesSent: s.stats.DeletesSent.Load(), DeletesReceived: s.stats.DeletesReceived.Load(), BulkSyncs: s.stats.BulkSyncs.Load(), ConfigsSent: s.stats.ConfigsSent.Load(), ConfigsReceived: s.stats.ConfigsReceived.Load(), IPsecSASent: s.stats.IPsecSASent.Load(), IPsecSAReceived: s.stats.IPsecSAReceived.Load(), FencesSent: s.stats.FencesSent.Load(), FencesReceived: s.stats.FencesReceived.Load(), Errors: s.stats.Errors.Load(), DeletesDropped: s.stats.DeletesDropped.Load(), Connected: s.stats.Connected.Load(), ActiveFabric: activeFabric, BulkSyncStartTime: s.stats.BulkSyncStartTime.Load(), BulkSyncEndTime: s.stats.BulkSyncEndTime.Load(), BulkSyncSessions: s.stats.BulkSyncSessions.Load(), LastConfigSyncTime: s.stats.LastConfigSyncTime.Load(), LastConfigSyncSize: s.stats.LastConfigSyncSize.Load(), LastFenceSeq: s.stats.LastFenceSeq.Load(), LastFenceAckAt: s.stats.LastFenceAckAt.Load()}
}

func (s *SessionSync) IsConnected() bool {
	return s.stats.Connected.Load()
}

func (s *SessionSync) BulkEverCompleted() bool {
	return s.bulkEverCompleted.Load()
}

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

func (s *SessionSync) LastPeerReceiveAge() (time.Duration, bool) {
	last := s.lastPeerRxUnix.Load()
	if last == 0 {
		return 0, false
	}
	return time.Since(time.Unix(0, last)), true
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

func (s *SessionSync) PeerRecentlyActive(maxAge time.Duration) bool {
	age, ok := s.LastPeerReceiveAge()
	return ok && age <= maxAge
}

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
	if s.dp == nil {
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
	var staleV4 []dataplane.SessionKey
	v4IterStart := time.Now()
	s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if shouldSyncAtBulkStart(val.IngressZone) {
			return true
		}
		if _, ok := recvV4[key]; !ok {
			staleV4 = append(staleV4, key)
		}
		return true
	})
	slog.Info("cluster sync: reconcile stale sessions iterated v4", "stale", len(staleV4), "elapsed", time.Since(v4IterStart))
	v4DeleteStart := time.Now()
	for _, key := range staleV4 {
		if val, err := s.dp.GetSessionV4(key); err == nil {
			if val.ReverseKey.Protocol != 0 {
				s.dp.DeleteSession(val.ReverseKey)
			}
			if val.Flags&dataplane.SessFlagSNAT != 0 && val.Flags&dataplane.SessFlagStaticNAT == 0 {
				s.dp.DeleteDNATEntry(dataplane.DNATKey{Protocol: key.Protocol, DstIP: val.NATSrcIP, DstPort: val.NATSrcPort})
			}
		}
		s.dp.DeleteSession(key)
		deleted++
	}
	slog.Info("cluster sync: reconcile stale sessions deleted v4", "deleted", len(staleV4), "elapsed", time.Since(v4DeleteStart))
	var staleV6 []dataplane.SessionKeyV6
	v6IterStart := time.Now()
	s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if shouldSyncAtBulkStart(val.IngressZone) {
			return true
		}
		if _, ok := recvV6[key]; !ok {
			staleV6 = append(staleV6, key)
		}
		return true
	})
	slog.Info("cluster sync: reconcile stale sessions iterated v6", "stale", len(staleV6), "elapsed", time.Since(v6IterStart))
	v6DeleteStart := time.Now()
	for _, key := range staleV6 {
		if val, err := s.dp.GetSessionV6(key); err == nil {
			if val.ReverseKey.Protocol != 0 {
				s.dp.DeleteSessionV6(val.ReverseKey)
			}
			if val.Flags&dataplane.SessFlagSNAT != 0 && val.Flags&dataplane.SessFlagStaticNAT == 0 {
				s.dp.DeleteDNATEntryV6(dataplane.DNATKeyV6{Protocol: key.Protocol, DstIP: val.NATSrcIP, DstPort: val.NATSrcPort})
			}
		}
		s.dp.DeleteSessionV6(key)
		deleted++
	}
	slog.Info("cluster sync: reconcile stale sessions deleted v6", "deleted", len(staleV6), "elapsed", time.Since(v6DeleteStart))
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
