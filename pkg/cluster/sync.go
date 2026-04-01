// Package cluster session synchronization (RTO - Real-Time Objects).
// Replicates session state between cluster nodes for stateful failover.
package cluster

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/psaab/bpfrx/pkg/dataplane"
)

// syncMagic identifies RTO protocol packets.
var syncMagic = [4]byte{'B', 'P', 'S', 'Y'}

// Sync message types.
const (
	syncMsgSessionV4  = 1
	syncMsgSessionV6  = 2
	syncMsgDeleteV4   = 3
	syncMsgDeleteV6   = 4
	syncMsgBulkStart  = 5
	syncMsgBulkEnd    = 6
	syncMsgHeartbeat  = 7
	syncMsgConfig     = 8  // full config text sync from primary to secondary
	syncMsgIPsecSA    = 9  // IPsec SA connection names sync
	syncMsgFailover   = 10 // remote failover request (payload: 1 byte rgID)
	syncMsgFence      = 11 // peer fencing: receiver should disable all RGs
	syncMsgClockSync  = 12 // monotonic clock exchange for timestamp rebasing
	syncMsgBarrier    = 13 // ordered marker for remote install barriers
	syncMsgBarrierAck = 14
	syncMsgBulkAck    = 15
)

// syncHeader is the wire header for each sync message.
type syncHeader struct {
	Magic  [4]byte
	Type   uint8
	Pad    [3]byte
	Length uint32 // payload length after header
}

const syncHeaderSize = 12
const syncWriteDeadline = 2 * time.Second

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
	FencesSent        atomic.Uint64
	FencesReceived    atomic.Uint64
	Errors            atomic.Uint64
	DeletesDropped    atomic.Uint64 // deletes lost when journal is full
	Connected         atomic.Bool

	// Cold sync timing.
	BulkSyncStartTime atomic.Int64  // UnixNano (0 = never)
	BulkSyncEndTime   atomic.Int64  // UnixNano (0 = in progress or never)
	BulkSyncSessions  atomic.Uint64 // sessions in current/last bulk

	// Config sync timing.
	LastConfigSyncTime atomic.Int64  // UnixNano
	LastConfigSyncSize atomic.Uint64 // bytes

	// Install fence (#311): barrier-based cutover sequence tracking.
	LastFenceSeq   atomic.Uint64 // last barrier sequence sent
	LastFenceAckAt atomic.Int64  // UnixNano when last barrier ack was received
}

// SyncStatsSnapshot is a point-in-time copy of SyncStats with plain
// (non-atomic) fields, safe to copy by value and pass across API boundaries.
type SyncStatsSnapshot struct {
	SessionsSent      uint64
	SessionsReceived  uint64
	SessionsInstalled uint64
	DeletesSent       uint64
	DeletesReceived   uint64
	BulkSyncs         uint64
	ConfigsSent       uint64
	ConfigsReceived   uint64
	IPsecSASent       uint64
	IPsecSAReceived   uint64
	FencesSent        uint64
	FencesReceived    uint64
	Errors            uint64
	DeletesDropped    uint64
	Connected         bool
	ActiveFabric      int // 0=fab0, 1=fab1, -1=disconnected

	BulkSyncStartTime int64
	BulkSyncEndTime   int64
	BulkSyncSessions  uint64

	LastConfigSyncTime int64
	LastConfigSyncSize uint64

	// Install fence (#311).
	LastFenceSeq   uint64
	LastFenceAckAt int64 // UnixNano (0 = never)
}

// SessionSync manages TCP-based session state replication between cluster peers.
type SessionSync struct {
	localAddr  string // local listen address (e.g. ":4785")
	peerAddr   string // peer connect address (e.g. "10.0.0.2:4785")
	dp         dataplane.DataPlane
	stats      SyncStats
	mu         sync.Mutex
	conn0      net.Conn   // fab0 connection (preferred)
	conn1      net.Conn   // fab1 connection (fallback)
	writeMu    sync.Mutex // serializes all conn.Write calls (sendLoop + writeMsg)
	listener   net.Listener
	localAddr1 string       // secondary fabric listen address ("" = single-fabric)
	peerAddr1  string       // secondary fabric peer address
	listener1  net.Listener // secondary fabric listener
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	sendCh     chan []byte // buffered channel for outgoing messages
	// incrementalPauseDepth temporarily pauses background incremental
	// producers (periodic sweeps) during HA demotion handoff so ordered
	// demotion barriers are not queued behind unrelated backlog.
	incrementalPauseDepth atomic.Int32

	// OnConfigReceived is called when a config sync message arrives from peer.
	// The callback receives the full config text. Set by the daemon before Start().
	OnConfigReceived func(configText string)

	// OnIPsecSAReceived is called when an IPsec SA list arrives from the peer.
	// On failover, the new primary calls swanctl --initiate for each connection name.
	OnIPsecSAReceived func(connectionNames []string)

	// OnRemoteFailover is called when the peer requests us to failover an RG.
	// The callback receives the redundancy group ID. The receiver should call
	// ManualFailover(rgID) to give up primary for that RG.
	OnRemoteFailover func(rgID int)

	// OnFenceReceived is called when the peer sends a fence message, requesting
	// this node to disable all RGs (set rg_active=false). The receiver should
	// call dp.UpdateRGActive(rgID, false) for every RG.
	OnFenceReceived func()

	// OnBulkSyncReceived is called when a bulk sync transfer completes
	// (syncMsgBulkEnd received). The secondary uses this to release VRRP
	// sync hold after session state has been installed.
	OnBulkSyncReceived func()

	// OnBulkSyncAckReceived is called when the peer acknowledges that it
	// has fully processed one of our bulk sync transfers.
	OnBulkSyncAckReceived func()

	// OnPeerConnected is called when a peer sync connection is established
	// (either inbound accept or outbound connect). The primary uses this to
	// push config to a returning secondary.
	OnPeerConnected func()

	// OnPeerDisconnected is called when all fabric connections are lost
	// (total disconnect). Used to reset sync readiness so that a fresh
	// bulk sync is required before the node can promote to primary.
	OnPeerDisconnected func()

	// peerIPsecSAs holds the latest IPsec connection names received from the peer.
	peerIPsecSAs   []string
	peerIPsecSAsMu sync.Mutex

	IsPrimaryFn        func() bool         // returns true if local node is primary for RG 0
	IsPrimaryForRGFn   func(rgID int) bool // returns true if local is primary for given RG
	lastSweepTime      uint64              // monotonic seconds of last sync sweep
	syncBackfillNeeded atomic.Bool         // replay sweep window on send queue overflow
	lastNewCounter     uint64              // last seen GLOBAL_CTR_SESSIONS_NEW
	lastClosedCounter  uint64              // last seen GLOBAL_CTR_SESSIONS_CLOSED
	lastSweepEmpty     bool                // previous sweep found 0 sessions to sync
	vrfDevice          string              // VRF device for SO_BINDTODEVICE (empty = default VRF)

	// Peer clock offset: localMono - peerMono.  Added to incoming
	// session timestamps so Created/LastSeen are in our clock domain.
	peerClockOffset atomic.Int64
	clockSynced     atomic.Bool

	zoneRGMu  sync.RWMutex
	zoneRGMap map[uint16]int // zone_id -> RG_id (for per-RG session sync)

	// Delete journal: bounded ring buffer for delete messages during disconnect.
	// Deletes are journaled when queueMessage fails (disconnect), then flushed
	// on reconnect before normal sync resumes.
	deleteJournalMu  sync.Mutex
	deleteJournal    [][]byte // ring buffer of encoded delete messages
	deleteJournalCap int      // max entries (default 10000)
	lastPeerRxUnix   atomic.Int64

	// bulkSendMu serializes entire BulkSync() calls so two concurrent
	// callers (e.g. acceptLoop and connectLoop) cannot interleave.
	bulkSendMu   sync.Mutex
	bulkSendNext atomic.Uint64 // monotonic epoch counter for outgoing bulk syncs
	// pendingBulkAckEpoch tracks the latest outbound bulk epoch that has been
	// fully written but not yet acknowledged by the peer.
	pendingBulkAckEpoch atomic.Uint64
	pendingBulkAckSince atomic.Int64 // UnixNano

	// Bulk receive tracking for stale-entry reconciliation.
	// During bulk receive (BulkStart..BulkEnd), track all received
	// forward session keys. On BulkEnd, delete local sessions in
	// peer-owned zones that were not refreshed.
	bulkMu           sync.Mutex
	bulkInProgress   bool
	bulkRecvEpoch    uint64 // epoch of current in-progress bulk receive
	bulkRecvV4       map[dataplane.SessionKey]struct{}
	bulkRecvV6       map[dataplane.SessionKeyV6]struct{}
	bulkZoneSnapshot map[uint16]bool // snapshot of ShouldSyncZone at BulkStart

	barrierSeq     atomic.Uint64
	barrierAckSeq  atomic.Uint64
	barrierWaitMu  sync.Mutex
	barrierWaiters map[uint64]chan struct{}
}

type sessionSyncSweepProfiler interface {
	SessionSyncSweepProfile() (enabled bool, activeInterval, idleInterval time.Duration)
}

type clusterSyncedSessionInstaller interface {
	SetClusterSyncedSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error
	SetClusterSyncedSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error
}

// deleteJournalDefaultCap is the default max entries in the delete journal.
const deleteJournalDefaultCap = 10000

// NewSessionSync creates a new session synchronization manager.
func NewSessionSync(localAddr, peerAddr string, dp dataplane.DataPlane) *SessionSync {
	return &SessionSync{
		localAddr:        localAddr,
		peerAddr:         peerAddr,
		dp:               dp,
		sendCh:           make(chan []byte, 4096),
		deleteJournalCap: deleteJournalDefaultCap,
	}
}

// NewDualSessionSync creates a session sync manager with dual fabric transport.
// If local1/peer1 are empty, falls back to single-fabric behavior.
func NewDualSessionSync(local, peer, local1, peer1 string, dp dataplane.DataPlane) *SessionSync {
	return &SessionSync{
		localAddr:        local,
		peerAddr:         peer,
		localAddr1:       local1,
		peerAddr1:        peer1,
		dp:               dp,
		sendCh:           make(chan []byte, 4096),
		deleteJournalCap: deleteJournalDefaultCap,
	}
}

func shouldInitiateFabricDial(localAddr, peerAddr string) bool {
	local, err := netip.ParseAddrPort(localAddr)
	if err != nil {
		return true
	}
	peer, err := netip.ParseAddrPort(peerAddr)
	if err != nil {
		return true
	}
	if cmp := local.Addr().Compare(peer.Addr()); cmp != 0 {
		return cmp < 0
	}
	return local.Port() < peer.Port()
}

// SetVRFDevice sets the VRF device for SO_BINDTODEVICE on sync sockets.
func (s *SessionSync) SetVRFDevice(dev string) {
	s.vrfDevice = dev
}

// SetZoneRGMap sets the zone ID → redundancy group mapping for per-RG
// session sync. Sessions are synced only when the local node is primary
// for the RG that owns the session's ingress zone.
func (s *SessionSync) SetZoneRGMap(m map[uint16]int) {
	s.zoneRGMu.Lock()
	s.zoneRGMap = m
	s.zoneRGMu.Unlock()
}

// SetDataPlane sets the dataplane used for installing received sessions.
// Called by the daemon after the dataplane is loaded (which happens after sync init).
func (s *SessionSync) SetDataPlane(dp dataplane.DataPlane) {
	s.dp = dp
}

// Stats returns a point-in-time snapshot of sync statistics.
// The snapshot uses plain fields (no atomics) so it is safe to copy by value.
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

	return SyncStatsSnapshot{
		SessionsSent:       s.stats.SessionsSent.Load(),
		SessionsReceived:   s.stats.SessionsReceived.Load(),
		SessionsInstalled:  s.stats.SessionsInstalled.Load(),
		DeletesSent:        s.stats.DeletesSent.Load(),
		DeletesReceived:    s.stats.DeletesReceived.Load(),
		BulkSyncs:          s.stats.BulkSyncs.Load(),
		ConfigsSent:        s.stats.ConfigsSent.Load(),
		ConfigsReceived:    s.stats.ConfigsReceived.Load(),
		IPsecSASent:        s.stats.IPsecSASent.Load(),
		IPsecSAReceived:    s.stats.IPsecSAReceived.Load(),
		FencesSent:         s.stats.FencesSent.Load(),
		FencesReceived:     s.stats.FencesReceived.Load(),
		Errors:             s.stats.Errors.Load(),
		DeletesDropped:     s.stats.DeletesDropped.Load(),
		Connected:          s.stats.Connected.Load(),
		ActiveFabric:       activeFabric,
		BulkSyncStartTime:  s.stats.BulkSyncStartTime.Load(),
		BulkSyncEndTime:    s.stats.BulkSyncEndTime.Load(),
		BulkSyncSessions:   s.stats.BulkSyncSessions.Load(),
		LastConfigSyncTime: s.stats.LastConfigSyncTime.Load(),
		LastConfigSyncSize: s.stats.LastConfigSyncSize.Load(),
		LastFenceSeq:       s.stats.LastFenceSeq.Load(),
		LastFenceAckAt:     s.stats.LastFenceAckAt.Load(),
	}
}

// IsConnected returns true if the peer connection is established.
func (s *SessionSync) IsConnected() bool {
	return s.stats.Connected.Load()
}

// ActiveFabric returns which fabric carries sync traffic: 0, 1, or -1 if disconnected.
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

// LastPeerReceiveAge returns how long it has been since the last inbound sync
// message was received from the peer. The second return value is false if no
// inbound sync traffic has ever been observed on the current process lifetime.
func (s *SessionSync) LastPeerReceiveAge() (time.Duration, bool) {
	last := s.lastPeerRxUnix.Load()
	if last == 0 {
		return 0, false
	}
	return time.Since(time.Unix(0, last)), true
}

// PeerRecentlyActive reports whether an inbound sync message has been observed
// from the peer within maxAge.
func (s *SessionSync) PeerRecentlyActive(maxAge time.Duration) bool {
	age, ok := s.LastPeerReceiveAge()
	return ok && age <= maxAge
}

// activeConnLocked returns the preferred active connection.
// fab0 is preferred; fab1 is used only when fab0 is down.
// Caller must hold s.mu.
func (s *SessionSync) activeConnLocked() net.Conn {
	if s.conn0 != nil {
		return s.conn0
	}
	return s.conn1
}

// getActiveConn returns the active connection, taking the lock.
func (s *SessionSync) getActiveConn() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeConnLocked()
}

func connRemoteAddrString(conn net.Conn) (remote string) {
	if conn == nil {
		return "<nil>"
	}
	defer func() {
		if recover() != nil {
			remote = "<unavailable>"
		}
	}()
	addr := conn.RemoteAddr()
	if addr == nil {
		return "<nil>"
	}
	return addr.String()
}

func connLocalAddrString(conn net.Conn) (local string) {
	if conn == nil {
		return "<nil>"
	}
	defer func() {
		if recover() != nil {
			local = "<unavailable>"
		}
	}()
	addr := conn.LocalAddr()
	if addr == nil {
		return "<nil>"
	}
	return addr.String()
}

func configureSessionSyncConn(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if err := tcpConn.SetNoDelay(true); err != nil {
		slog.Warn("cluster sync: failed to enable TCP_NODELAY",
			"local", connLocalAddrString(conn),
			"remote", connRemoteAddrString(conn),
			"err", err)
	}
}

// handleNewConnection processes a newly established connection on the given fabric.
// It sets the connection in the appropriate slot, starts the receive loop, exchanges
// clocks, and triggers bulk sync if this is the first connection after a total disconnect.
func (s *SessionSync) handleNewConnection(ctx context.Context, fabricIdx int, conn net.Conn) {
	configureSessionSyncConn(conn)

	s.mu.Lock()
	wasDisconnected := s.conn0 == nil && s.conn1 == nil
	activeBefore := -1
	if s.conn0 != nil {
		activeBefore = 0
	} else if s.conn1 != nil {
		activeBefore = 1
	}
	hadConn0 := s.conn0 != nil
	hadConn1 := s.conn1 != nil
	switch fabricIdx {
	case 0:
		if s.conn0 != nil {
			s.conn0.Close()
		}
		s.conn0 = conn
	case 1:
		if s.conn1 != nil {
			s.conn1.Close()
		}
		s.conn1 = conn
	}
	activeAfter := -1
	if s.conn0 != nil {
		activeAfter = 0
	} else if s.conn1 != nil {
		activeAfter = 1
	}
	s.stats.Connected.Store(true)
	s.mu.Unlock()
	becameActive := activeAfter == fabricIdx

	slog.Info("cluster sync: handling new connection",
		"fabric", fabricIdx,
		"remote", connRemoteAddrString(conn),
		"was_disconnected", wasDisconnected,
		"active_before", activeBefore,
		"active_after", activeAfter,
		"became_active", becameActive,
		"had_conn0", hadConn0,
		"had_conn1", hadConn1)

	// Start receive loop for this connection.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.receiveLoop(ctx, conn)
	}()

	// Exchange monotonic clocks on every new connection.
	s.sendClockSync(conn)

	// A new connection that becomes the active transport also needs a fresh
	// bulk sync. Otherwise one side can reconnect on the preferred fabric
	// while the peer never sends its own current-generation bulk on that path,
	// leaving reverse-direction sync admission permanently incomplete.
	if wasDisconnected {
		slog.Info("cluster sync: first connection after disconnect",
			"fabric", fabricIdx,
			"remote", connRemoteAddrString(conn))
		s.flushDeleteJournal()
		if s.OnPeerConnected != nil {
			slog.Info("cluster sync: scheduling OnPeerConnected callback",
				"fabric", fabricIdx)
			go s.OnPeerConnected()
		}
		slog.Info("cluster sync: starting bulk sync on new connection",
			"fabric", fabricIdx,
			"remote", connRemoteAddrString(conn))
		if err := s.BulkSync(); err != nil {
			slog.Warn("cluster sync: bulk sync failed", "err", err, "fabric", fabricIdx)
		}
	} else if becameActive {
		slog.Info("cluster sync: starting bulk sync on newly active connection",
			"fabric", fabricIdx,
			"remote", connRemoteAddrString(conn),
			"active_before", activeBefore,
			"active_after", activeAfter)
		if err := s.BulkSync(); err != nil {
			slog.Warn("cluster sync: bulk sync on active connection failed", "err", err, "fabric", fabricIdx)
		}
	} else {
		slog.Info("cluster sync: connection added without bulk sync",
			"fabric", fabricIdx,
			"remote", connRemoteAddrString(conn))
	}
}

// Start begins the sync protocol (listener + connector).
func (s *SessionSync) Start(ctx context.Context) error {
	ctx, s.cancel = context.WithCancel(ctx)

	// Start listener for incoming peer connections.
	lc := vrfListenConfig(s.vrfDevice)
	ln, err := lc.Listen(ctx, "tcp", s.localAddr)
	if err != nil {
		return fmt.Errorf("sync listen: %w", err)
	}
	s.listener = ln
	slog.Info("cluster sync: listening", "addr", s.localAddr)

	// Accept incoming connections on primary fabric.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ctx, ln, 0)
	}()

	// Start secondary fabric listener if configured.
	if s.localAddr1 != "" {
		lc1 := vrfListenConfig(s.vrfDevice)
		ln1, err := lc1.Listen(ctx, "tcp", s.localAddr1)
		if err != nil {
			slog.Warn("cluster sync: secondary fabric listen failed, using primary only",
				"addr", s.localAddr1, "err", err)
		} else {
			s.listener1 = ln1
			slog.Info("cluster sync: listening on secondary fabric", "addr", s.localAddr1)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.acceptLoop(ctx, ln1, 1)
			}()
		}
	}

	// Use one deterministic TCP initiator per fabric. Dual dialers create
	// duplicate sync streams, mid-bulk connection replacement, and lost
	// failover-handoff messages during reconnect windows.
	if shouldInitiateFabricDial(s.localAddr, s.peerAddr) {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.fabricConnectLoop(ctx, 0, s.peerAddr)
		}()
	}

	// Connect to peer on secondary fabric if configured.
	if s.peerAddr1 != "" && shouldInitiateFabricDial(s.localAddr1, s.peerAddr1) {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.fabricConnectLoop(ctx, 1, s.peerAddr1)
		}()
	}

	// Sender goroutine.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.sendLoop(ctx)
	}()

	return nil
}

// Stop gracefully shuts down session sync.  If goroutines do not exit
// within 5 seconds the method returns anyway so the daemon can proceed
// with HA teardown (clearing rg_active, removing BPF state).
func (s *SessionSync) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	if s.listener1 != nil {
		s.listener1.Close()
	}
	s.mu.Lock()
	if s.conn0 != nil {
		s.conn0.Close()
	}
	if s.conn1 != nil {
		s.conn1.Close()
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		// Clean exit.
	case <-time.After(5 * time.Second):
		slog.Warn("cluster sync: Stop timed out waiting for goroutines, proceeding with shutdown")
	}
}

// StartSyncSweep starts a goroutine that periodically syncs sessions to the peer.
// Sessions with Created >= lastSweepTime (new) or LastSeen >= lastSweepTime
// (recently active) are queued for sync, ensuring established flows get their
// updated TCP state, timeouts, and last-seen timestamps replicated to standby.
func (s *SessionSync) StartSyncSweep(ctx context.Context) {
	s.lastSweepTime = monotonicSeconds()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		activeInterval, idleInterval := s.sweepIntervals()
		interval := activeInterval
		timer := time.NewTimer(interval)
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				activeInterval, idleInterval = s.sweepIntervals()
				synced := s.syncSweep()
				if synced > 0 || s.syncBackfillNeeded.Load() {
					interval = activeInterval
				} else {
					// Back off when nothing to sync so the authoritative dataplane
					// is not batch-walked unnecessarily. Userspace forwarding can
					// override these intervals because it already streams create/close
					// deltas out of band and only needs periodic refreshes.
					interval = min(interval*2, idleInterval)
				}
				timer.Reset(interval)
			}
		}
	}()
	slog.Info("cluster sync: sweep started")
}

func (s *SessionSync) sweepIntervals() (time.Duration, time.Duration) {
	return sweepIntervalsForDataPlane(s.dp)
}

func sweepIntervalsForDataPlane(dp any) (time.Duration, time.Duration) {
	activeInterval := time.Second
	idleInterval := 10 * time.Second
	if profiler, ok := dp.(sessionSyncSweepProfiler); ok {
		if enabled, active, idle := profiler.SessionSyncSweepProfile(); enabled {
			if active > 0 {
				activeInterval = active
			}
			if idle > 0 {
				idleInterval = idle
			}
		}
	}
	if idleInterval < activeInterval {
		idleInterval = activeInterval
	}
	return activeInterval, idleInterval
}

// ShouldSyncZone returns true if the local node should sync sessions for
// the given zone. When IsPrimaryForRGFn is set and a zone→RG mapping
// exists, only sessions whose ingress zone belongs to a locally-primary
// RG are synced. Falls back to the global IsPrimaryFn otherwise.
func (s *SessionSync) ShouldSyncZone(zoneID uint16) bool {
	if s.IsPrimaryForRGFn != nil {
		s.zoneRGMu.RLock()
		rgID, ok := s.zoneRGMap[zoneID]
		s.zoneRGMu.RUnlock()
		if ok {
			return s.IsPrimaryForRGFn(rgID)
		}
	}
	// Fallback: use global primary check (backward compat, or zone not
	// mapped to an RG — e.g. non-RETH interfaces always use RG 0).
	if s.IsPrimaryFn != nil {
		return s.IsPrimaryFn()
	}
	return false
}

func (s *SessionSync) syncSweep() int {
	// At least one primary check must be wired.
	if s.IsPrimaryFn == nil && s.IsPrimaryForRGFn == nil {
		return 0
	}
	if s.incrementalPauseDepth.Load() > 0 {
		return 0
	}
	if !s.stats.Connected.Load() {
		return 0
	}
	if s.dp == nil {
		return 0
	}

	// Fast path: skip expensive BatchIterate when no sessions have changed.
	// Reading two per-CPU counters is O(1) vs BatchIterate which is O(buckets)
	// even for an empty 10M-entry hash map.
	if s.lastSweepEmpty && !s.syncBackfillNeeded.Load() {
		newCtr, err1 := s.dp.ReadGlobalCounter(dataplane.GlobalCtrSessionsNew)
		closedCtr, err2 := s.dp.ReadGlobalCounter(dataplane.GlobalCtrSessionsClosed)
		if err1 == nil && err2 == nil &&
			newCtr == s.lastNewCounter &&
			closedCtr == s.lastClosedCounter {
			s.lastSweepTime = monotonicSeconds()
			return 0
		}
		s.lastNewCounter = newCtr
		s.lastClosedCounter = closedCtr
	}

	threshold := s.lastSweepTime
	now := monotonicSeconds()
	var count int
	var overflow bool
	replaying := s.syncBackfillNeeded.Load()

	// Batch iteration reduces kernel lock contention with BPF datapath
	s.dp.BatchIterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		// Only sweep sessions created since last threshold. The ring event
		// path handles near-real-time create delivery; sweep is reconciliation
		// only. Established flows whose LastSeen moved but were created before
		// the threshold do not need re-syncing — the peer already has them.
		if val.Created >= threshold && s.ShouldSyncZone(val.IngressZone) {
			msg := encodeSessionV4(key, val)
			if s.queueMessage(msg, &s.stats.SessionsSent, "sweep_v4") {
				count++
			} else {
				overflow = true
			}
		}
		return true
	})

	s.dp.BatchIterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Created >= threshold && s.ShouldSyncZone(val.IngressZone) {
			msg := encodeSessionV6(key, val)
			if s.queueMessage(msg, &s.stats.SessionsSent, "sweep_v6") {
				count++
			} else {
				overflow = true
			}
		}
		return true
	})

	if overflow {
		// Keep lastSweepTime unchanged so the next sweep retries this
		// same window, preventing permanent sync gaps on queue pressure.
		s.syncBackfillNeeded.Store(true)
		slog.Warn("cluster sync: sweep queue overflow, replaying previous window",
			"threshold", threshold,
			"queued", count,
			"queue_len", len(s.sendCh),
			"queue_cap", cap(s.sendCh))
		return count
	}

	if replaying {
		s.syncBackfillNeeded.Store(false)
		slog.Info("cluster sync: sweep replay recovered",
			"queued", count,
			"threshold", threshold)
	}

	s.lastSweepTime = now
	s.lastSweepEmpty = (count == 0)
	if count == 0 {
		// Snapshot counters so next sweep can skip if nothing changed.
		newCtr, err1 := s.dp.ReadGlobalCounter(dataplane.GlobalCtrSessionsNew)
		closedCtr, err2 := s.dp.ReadGlobalCounter(dataplane.GlobalCtrSessionsClosed)
		if err1 == nil && err2 == nil {
			s.lastNewCounter = newCtr
			s.lastClosedCounter = closedCtr
		}
	}
	if count > 0 {
		slog.Info("cluster sync: sweep synced sessions", "count", count)
	}
	return count
}

// PauseIncrementalSync temporarily disables background sweep-driven session
// replication. Explicit sync producers (for example demotion-prep republish)
// are unaffected and may continue queueing messages.
func (s *SessionSync) PauseIncrementalSync(reason string) {
	depth := s.incrementalPauseDepth.Add(1)
	if depth == 1 {
		stats := s.Stats()
		slog.Info("cluster sync: incremental sync paused",
			"reason", reason,
			"depth", depth,
			"sessions_sent", stats.SessionsSent,
			"sessions_received", stats.SessionsReceived,
			"sessions_installed", stats.SessionsInstalled,
			"queue_len", len(s.sendCh),
			"queue_cap", cap(s.sendCh))
	}
}

// ResumeIncrementalSync releases a previous PauseIncrementalSync call.
func (s *SessionSync) ResumeIncrementalSync(reason string) {
	depth := s.incrementalPauseDepth.Add(-1)
	if depth < 0 {
		s.incrementalPauseDepth.Store(0)
		depth = 0
	}
	if depth == 0 {
		stats := s.Stats()
		slog.Info("cluster sync: incremental sync resumed",
			"reason", reason,
			"sessions_sent", stats.SessionsSent,
			"sessions_received", stats.SessionsReceived,
			"sessions_installed", stats.SessionsInstalled,
			"queue_len", len(s.sendCh),
			"queue_cap", cap(s.sendCh))
	}
}

func (s *SessionSync) queueMessage(msg []byte, sentCounter *atomic.Uint64, source string) bool {
	if !s.stats.Connected.Load() {
		return false
	}
	select {
	case s.sendCh <- msg:
		sentCounter.Add(1)
		return true
	default:
		s.stats.Errors.Add(1)
		if s.syncBackfillNeeded.CompareAndSwap(false, true) {
			slog.Warn("cluster sync: send queue full, enabling sweep replay",
				"source", source,
				"queue_len", len(s.sendCh),
				"queue_cap", cap(s.sendCh))
		}
		return false
	}
}

// QueueSessionV4 queues a v4 session for sync to peer.
func (s *SessionSync) QueueSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	msg := encodeSessionV4(key, val)
	s.queueMessage(msg, &s.stats.SessionsSent, "session_v4")
}

// QueueSessionV6 queues a v6 session for sync to peer.
func (s *SessionSync) QueueSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	msg := encodeSessionV6(key, val)
	s.queueMessage(msg, &s.stats.SessionsSent, "session_v6")
}

// QueueDeleteV4 queues a v4 session deletion for sync.
// If the peer is disconnected, the delete is journaled for replay on reconnect.
func (s *SessionSync) QueueDeleteV4(key dataplane.SessionKey) {
	msg := encodeDeleteV4(key)
	if !s.queueMessage(msg, &s.stats.DeletesSent, "delete_v4") {
		s.journalDelete(msg)
	}
}

// QueueDeleteV6 queues a v6 session deletion for sync.
// If the peer is disconnected, the delete is journaled for replay on reconnect.
func (s *SessionSync) QueueDeleteV6(key dataplane.SessionKeyV6) {
	msg := encodeDeleteV6(key)
	if !s.queueMessage(msg, &s.stats.DeletesSent, "delete_v6") {
		s.journalDelete(msg)
	}
}

// journalDelete stores a delete message in the bounded ring buffer
// for replay on reconnect. If the journal is full, the oldest entry
// is evicted and DeletesDropped is incremented.
func (s *SessionSync) journalDelete(msg []byte) {
	s.deleteJournalMu.Lock()
	defer s.deleteJournalMu.Unlock()

	cap := s.deleteJournalCap
	if cap <= 0 {
		cap = deleteJournalDefaultCap
	}
	if len(s.deleteJournal) >= cap {
		// Evict oldest entry (ring buffer behavior).
		s.deleteJournal = s.deleteJournal[1:]
		s.stats.DeletesDropped.Add(1)
	}
	s.deleteJournal = append(s.deleteJournal, msg)
}

// flushDeleteJournal replays all journaled delete messages through the
// send channel. Called on reconnect before normal sync resumes.
func (s *SessionSync) flushDeleteJournal() {
	s.deleteJournalMu.Lock()
	journal := s.deleteJournal
	s.deleteJournal = nil
	s.deleteJournalMu.Unlock()

	if len(journal) == 0 {
		return
	}

	var flushed int
	for _, msg := range journal {
		if s.queueMessage(msg, &s.stats.DeletesSent, "journal_flush") {
			flushed++
		}
	}
	slog.Info("cluster sync: flushed delete journal", "total", len(journal), "sent", flushed)
}

// QueueConfig sends the full config text to the peer for config synchronization.
// Called by the primary node after a successful commit.
func (s *SessionSync) QueueConfig(configText string) {
	conn := s.getActiveConn()
	if conn == nil {
		return
	}

	payload := []byte(configText)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgConfig, payload)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: config send error", "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return
	}
	s.stats.ConfigsSent.Add(1)
	slog.Info("cluster sync: config sent to peer", "size", len(payload))
}

// SendFailover sends a remote failover request to the peer, asking it to
// give up primary for the specified redundancy group.
func (s *SessionSync) SendFailover(rgID int) error {
	conn := s.getActiveConn()
	if conn == nil {
		return fmt.Errorf("peer not connected")
	}

	payload := []byte{byte(rgID)}
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgFailover, payload)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: failover send error", "err", err, "rg", rgID)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return fmt.Errorf("failed to send failover request: %w", err)
	}
	slog.Info("cluster sync: failover request sent to peer", "rg", rgID)
	return nil
}

// SendFence sends a fence message to the peer, requesting it to disable all
// RGs (set rg_active=false). This is a best-effort operation — if the sync
// connection is down (likely during a real failure), the call returns an error.
func (s *SessionSync) SendFence() error {
	conn := s.getActiveConn()
	if conn == nil {
		return fmt.Errorf("peer not connected")
	}

	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgFence, nil)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: fence send error", "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return fmt.Errorf("failed to send fence message: %w", err)
	}
	s.stats.FencesSent.Add(1)
	slog.Info("cluster sync: fence message sent to peer")
	return nil
}

// BulkSync sends the entire session table to the connected peer.
// Serialized by bulkSendMu so concurrent callers cannot interleave.
func (s *SessionSync) BulkSync() error {
	s.bulkSendMu.Lock()
	defer s.bulkSendMu.Unlock()

	if s.dp == nil {
		return fmt.Errorf("dataplane not ready")
	}
	conn := s.getActiveConn()
	if conn == nil {
		return fmt.Errorf("no peer connection")
	}

	// Assign a monotonically increasing epoch to this bulk transfer.
	epoch := s.bulkSendNext.Add(1)
	var epochBuf [8]byte
	binary.LittleEndian.PutUint64(epochBuf[:], epoch)

	stats := s.Stats()
	slog.Info("cluster sync: bulk sync starting",
		"epoch", epoch,
		"local", connLocalAddrString(conn),
		"remote", connRemoteAddrString(conn),
		"sessions_sent", stats.SessionsSent,
		"sessions_received", stats.SessionsReceived,
		"sessions_installed", stats.SessionsInstalled,
		"queue_len", len(s.sendCh),
		"queue_cap", cap(s.sendCh))

	// Send bulk start marker with epoch.
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgBulkStart, epochBuf[:])
	s.writeMu.Unlock()
	if err != nil {
		s.pendingBulkAckEpoch.Store(0)
		s.pendingBulkAckSince.Store(0)
		s.handleDisconnect(conn)
		return err
	}

	var count, skipped int
	slog.Info("cluster sync: bulk sync iterating v4", "epoch", epoch)
	// Send owned v4 forward sessions.
	err = s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !s.ShouldSyncZone(val.IngressZone) {
			skipped++
			return true
		}
		msg := encodeSessionV4Payload(key, val)
		s.writeMu.Lock()
		err := writeMsg(conn, syncMsgSessionV4, msg)
		s.writeMu.Unlock()
		if err != nil {
			s.handleDisconnect(conn)
			slog.Warn("bulk sync v4 write error", "err", err)
			return false
		}
		count++
		return true
	})
	if err != nil {
		s.pendingBulkAckEpoch.Store(0)
		s.pendingBulkAckSince.Store(0)
		return fmt.Errorf("bulk sync v4 iterate: %w", err)
	}
	slog.Info("cluster sync: bulk sync iterated v4",
		"epoch", epoch,
		"sessions", count,
		"skipped", skipped)

	// Send owned v6 forward sessions.
	slog.Info("cluster sync: bulk sync iterating v6", "epoch", epoch, "sessions", count, "skipped", skipped)
	err = s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !s.ShouldSyncZone(val.IngressZone) {
			skipped++
			return true
		}
		msg := encodeSessionV6Payload(key, val)
		s.writeMu.Lock()
		err := writeMsg(conn, syncMsgSessionV6, msg)
		s.writeMu.Unlock()
		if err != nil {
			s.handleDisconnect(conn)
			slog.Warn("bulk sync v6 write error", "err", err)
			return false
		}
		count++
		return true
	})
	if err != nil {
		s.pendingBulkAckEpoch.Store(0)
		s.pendingBulkAckSince.Store(0)
		return fmt.Errorf("bulk sync v6 iterate: %w", err)
	}
	slog.Info("cluster sync: bulk sync iterated v6",
		"epoch", epoch,
		"sessions", count,
		"skipped", skipped)

	// Send bulk end marker with matching epoch.
	slog.Info("cluster sync: bulk sync writing end marker", "epoch", epoch, "sessions", count, "skipped", skipped)
	s.writeMu.Lock()
	err = writeMsg(conn, syncMsgBulkEnd, epochBuf[:])
	s.writeMu.Unlock()
	if err != nil {
		s.pendingBulkAckEpoch.Store(0)
		s.pendingBulkAckSince.Store(0)
		s.handleDisconnect(conn)
		return err
	}
	s.pendingBulkAckEpoch.Store(epoch)
	s.pendingBulkAckSince.Store(time.Now().UnixNano())

	s.stats.BulkSyncs.Add(1)
	slog.Info("cluster sync: bulk sync complete", "sessions", count, "skipped", skipped, "epoch", epoch)
	return nil
}

// PendingBulkAck reports the latest outbound bulk epoch that is still awaiting
// peer acknowledgement, if any.
func (s *SessionSync) PendingBulkAck() (epoch uint64, age time.Duration, ok bool) {
	epoch = s.pendingBulkAckEpoch.Load()
	if epoch == 0 {
		return 0, 0, false
	}
	since := s.pendingBulkAckSince.Load()
	if since == 0 {
		return epoch, 0, true
	}
	age = time.Since(time.Unix(0, since))
	if age < 0 {
		age = 0
	}
	return epoch, age, true
}

// sendClockSync sends our monotonic clock to the peer so it can compute
// the offset between our clocks.  Called on both sides right after TCP
// connect, before BulkSync.
func (s *SessionSync) sendClockSync(conn net.Conn) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], monotonicSeconds())
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgClockSync, buf[:])
	s.writeMu.Unlock()
	if err != nil {
		s.handleDisconnect(conn)
		slog.Warn("cluster sync: failed to send clock sync", "err", err)
	}
}

func (s *SessionSync) acceptLoop(ctx context.Context, ln net.Listener, fabricIdx int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				slog.Warn("cluster sync: accept error", "err", err)
				time.Sleep(time.Second)
				continue
			}
		}
		slog.Info("cluster sync: peer connected", "remote", conn.RemoteAddr(), "fabric", fabricIdx)
		s.handleNewConnection(ctx, fabricIdx, conn)
	}
}

// fabricConnectLoop retries outbound connection on a single fabric link.
// Each fabric gets its own loop so fab0 reconnects independently of fab1.
func (s *SessionSync) fabricConnectLoop(ctx context.Context, fabricIdx int, peerAddr string) {
	for first := true; ; first = false {
		if !first {
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
		}

		// Skip if this fabric is already connected.
		s.mu.Lock()
		var connected bool
		if fabricIdx == 0 {
			connected = s.conn0 != nil
		} else {
			connected = s.conn1 != nil
		}
		s.mu.Unlock()
		if connected {
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
			continue
		}

		dialer := net.Dialer{Timeout: 3 * time.Second}
		if s.vrfDevice != "" {
			dialer.Control = vrfListenConfig(s.vrfDevice).Control
		}
		conn, err := dialer.DialContext(ctx, "tcp", peerAddr)
		if err != nil {
			continue
		}

		slog.Info("cluster sync: connected to peer", "addr", peerAddr, "fabric", fabricIdx)
		s.handleNewConnection(ctx, fabricIdx, conn)
	}
}

func (s *SessionSync) sendLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-s.sendCh:
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				conn := s.getActiveConn()
				if conn == nil {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				s.writeMu.Lock()
				err := writeFull(conn, msg)
				s.writeMu.Unlock()
				if err != nil {
					slog.Debug("cluster sync: send error", "err", err)
					s.stats.Errors.Add(1)
					s.handleDisconnect(conn)
					time.Sleep(10 * time.Millisecond)
					continue
				}
				break
			}
		}
	}
}

func (s *SessionSync) receiveLoop(ctx context.Context, conn net.Conn) {
	defer func() {
		s.handleDisconnect(conn)
	}()

	hdrBuf := make([]byte, syncHeaderSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		if _, err := io.ReadFull(conn, hdrBuf); err != nil {
			if ctx.Err() != nil {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Send keepalive.
				s.writeMu.Lock()
				err := writeMsg(conn, syncMsgHeartbeat, nil)
				s.writeMu.Unlock()
				if err != nil {
					return
				}
				continue
			}
			slog.Debug("cluster sync: read header error", "err", err)
			return
		}

		var hdr syncHeader
		copy(hdr.Magic[:], hdrBuf[:4])
		hdr.Type = hdrBuf[4]
		hdr.Length = binary.LittleEndian.Uint32(hdrBuf[8:12])

		if hdr.Magic != syncMagic {
			slog.Warn("cluster sync: bad magic")
			s.stats.Errors.Add(1)
			return
		}

		var payload []byte
		if hdr.Length > 0 {
			if hdr.Length > 16*1024*1024 { // 16MB sanity limit (config can be large)
				slog.Warn("cluster sync: payload too large", "len", hdr.Length)
				return
			}
			payload = make([]byte, hdr.Length)
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
		}

		s.lastPeerRxUnix.Store(time.Now().UnixNano())
		s.handleMessage(conn, hdr.Type, payload)
	}
}

func (s *SessionSync) handleMessage(conn net.Conn, msgType uint8, payload []byte) {
	switch msgType {
	case syncMsgSessionV4:
		s.stats.SessionsReceived.Add(1)
		if s.stats.BulkSyncStartTime.Load() > 0 && s.stats.BulkSyncEndTime.Load() == 0 {
			count := s.stats.BulkSyncSessions.Add(1)
			if count == 1 || count%64 == 0 {
				s.bulkMu.Lock()
				epoch := s.bulkRecvEpoch
				s.bulkMu.Unlock()
				slog.Info("cluster sync: bulk receive progress",
					"epoch", epoch,
					"sessions", count,
					"type", "v4",
					"local", connLocalAddrString(conn),
					"remote", connRemoteAddrString(conn))
			}
		}
		if s.dp != nil {
			if key, val, ok := decodeSessionV4Payload(payload); ok {
				// Track forward keys during bulk receive for stale reconciliation.
				if val.IsReverse == 0 {
					s.bulkMu.Lock()
					if s.bulkInProgress {
						s.bulkRecvV4[key] = struct{}{}
					}
					s.bulkMu.Unlock()
				}

				// Rebase timestamps to local monotonic clock using
				// the clock offset exchanged at connection setup.
				offset := s.peerClockOffset.Load()
				val.Created = rebaseTimestamp(val.Created, offset)
				val.LastSeen = rebaseTimestamp(val.LastSeen, offset)

				if installer, ok := s.dp.(clusterSyncedSessionInstaller); ok {
					if err := installer.SetClusterSyncedSessionV4(key, val); err == nil {
						s.stats.SessionsInstalled.Add(1)
					}
				} else {
					// Invalidate FIB cache — peer's cached ifindex/MAC/gen
					// are meaningless on this node. Forces a fresh
					// bpf_fib_lookup so hairpin and RG-active checks work.
					val.FibIfindex = 0
					val.FibVlanID = 0
					val.FibDmac = [6]byte{}
					val.FibSmac = [6]byte{}
					val.FibGen = 0
					if err := s.dp.SetSessionV4(key, val); err == nil {
						s.stats.SessionsInstalled.Add(1)
					}
				}
				// Create reverse session entry from forward entries so return
				// traffic matches conntrack on the takeover node.
				if val.IsReverse == 0 && val.ReverseKey.Protocol != 0 {
					revVal := val
					revVal.IsReverse = 1
					revVal.ReverseKey = key
					// Swap zones: reverse traffic enters on egress zone
					// and exits on ingress zone.
					revVal.IngressZone = val.EgressZone
					revVal.EgressZone = val.IngressZone
					if installer, ok := s.dp.(clusterSyncedSessionInstaller); ok {
						if err := installer.SetClusterSyncedSessionV4(val.ReverseKey, revVal); err != nil {
							slog.Warn("cluster sync: failed to create reverse session", "err", err)
						}
					} else {
						revVal.FibIfindex = 0
						revVal.FibVlanID = 0
						revVal.FibDmac = [6]byte{}
						revVal.FibSmac = [6]byte{}
						revVal.FibGen = 0
						if err := s.dp.SetSessionV4(val.ReverseKey, revVal); err != nil {
							slog.Warn("cluster sync: failed to create reverse session", "err", err)
						}
					}
				}
				// Create dnat_table entry for SNAT reverse pre-routing.
				// xdp_zone uses dnat_table to rewrite dst back to the real
				// client before conntrack lookup on return traffic.
				if val.IsReverse == 0 &&
					val.Flags&dataplane.SessFlagSNAT != 0 &&
					val.Flags&dataplane.SessFlagStaticNAT == 0 {
					dnatKey := dataplane.DNATKey{
						Protocol: key.Protocol,
						DstIP:    val.NATSrcIP,
						DstPort:  val.NATSrcPort,
					}
					dnatVal := dataplane.DNATValue{
						NewDstIP:   binary.NativeEndian.Uint32(key.SrcIP[:]),
						NewDstPort: key.SrcPort,
					}
					if err := s.dp.SetDNATEntry(dnatKey, dnatVal); err != nil {
						slog.Warn("cluster sync: failed to create dnat_table entry", "err", err)
					}
				}
			}
		}

	case syncMsgSessionV6:
		s.stats.SessionsReceived.Add(1)
		if s.stats.BulkSyncStartTime.Load() > 0 && s.stats.BulkSyncEndTime.Load() == 0 {
			count := s.stats.BulkSyncSessions.Add(1)
			if count == 1 || count%64 == 0 {
				s.bulkMu.Lock()
				epoch := s.bulkRecvEpoch
				s.bulkMu.Unlock()
				slog.Info("cluster sync: bulk receive progress",
					"epoch", epoch,
					"sessions", count,
					"type", "v6",
					"local", connLocalAddrString(conn),
					"remote", connRemoteAddrString(conn))
			}
		}
		if s.dp != nil {
			if key, val, ok := decodeSessionV6Payload(payload); ok {
				// Track forward keys during bulk receive for stale reconciliation.
				if val.IsReverse == 0 {
					s.bulkMu.Lock()
					if s.bulkInProgress {
						s.bulkRecvV6[key] = struct{}{}
					}
					s.bulkMu.Unlock()
				}

				// Rebase timestamps using clock offset (same as V4).
				offset := s.peerClockOffset.Load()
				val.Created = rebaseTimestamp(val.Created, offset)
				val.LastSeen = rebaseTimestamp(val.LastSeen, offset)

				if installer, ok := s.dp.(clusterSyncedSessionInstaller); ok {
					if err := installer.SetClusterSyncedSessionV6(key, val); err == nil {
						s.stats.SessionsInstalled.Add(1)
					}
				} else {
					// Invalidate FIB cache (same as V4 above).
					val.FibIfindex = 0
					val.FibVlanID = 0
					val.FibDmac = [6]byte{}
					val.FibSmac = [6]byte{}
					val.FibGen = 0
					if err := s.dp.SetSessionV6(key, val); err == nil {
						s.stats.SessionsInstalled.Add(1)
					}
				}
				if val.IsReverse == 0 && val.ReverseKey.Protocol != 0 {
					revVal := val
					revVal.IsReverse = 1
					revVal.ReverseKey = key
					revVal.IngressZone = val.EgressZone
					revVal.EgressZone = val.IngressZone
					if installer, ok := s.dp.(clusterSyncedSessionInstaller); ok {
						if err := installer.SetClusterSyncedSessionV6(val.ReverseKey, revVal); err != nil {
							slog.Warn("cluster sync: failed to create reverse v6 session", "err", err)
						}
					} else {
						revVal.FibIfindex = 0
						revVal.FibVlanID = 0
						revVal.FibDmac = [6]byte{}
						revVal.FibSmac = [6]byte{}
						revVal.FibGen = 0
						if err := s.dp.SetSessionV6(val.ReverseKey, revVal); err != nil {
							slog.Warn("cluster sync: failed to create reverse v6 session", "err", err)
						}
					}
				}
				if val.IsReverse == 0 &&
					val.Flags&dataplane.SessFlagSNAT != 0 &&
					val.Flags&dataplane.SessFlagStaticNAT == 0 {
					dnatKey := dataplane.DNATKeyV6{
						Protocol: key.Protocol,
						DstIP:    val.NATSrcIP,
						DstPort:  val.NATSrcPort,
					}
					dnatVal := dataplane.DNATValueV6{
						NewDstIP:   key.SrcIP,
						NewDstPort: key.SrcPort,
					}
					if err := s.dp.SetDNATEntryV6(dnatKey, dnatVal); err != nil {
						slog.Warn("cluster sync: failed to create dnat_table_v6 entry", "err", err)
					}
				}
			}
		}

	case syncMsgDeleteV4:
		s.stats.DeletesReceived.Add(1)
		if s.dp != nil && len(payload) >= 16 {
			var key dataplane.SessionKey
			copy(key.SrcIP[:], payload[0:4])
			copy(key.DstIP[:], payload[4:8])
			key.SrcPort = binary.LittleEndian.Uint16(payload[8:10])
			key.DstPort = binary.LittleEndian.Uint16(payload[10:12])
			key.Protocol = payload[12]
			// Look up session before deleting to clean up reverse entry
			// and SNAT dnat_table entry.
			if val, err := s.dp.GetSessionV4(key); err == nil {
				if val.ReverseKey.Protocol != 0 {
					s.dp.DeleteSession(val.ReverseKey)
				}
				if val.IsReverse == 0 &&
					val.Flags&dataplane.SessFlagSNAT != 0 &&
					val.Flags&dataplane.SessFlagStaticNAT == 0 {
					s.dp.DeleteDNATEntry(dataplane.DNATKey{
						Protocol: key.Protocol,
						DstIP:    val.NATSrcIP,
						DstPort:  val.NATSrcPort,
					})
				}
			}
			s.dp.DeleteSession(key)
		}

	case syncMsgDeleteV6:
		s.stats.DeletesReceived.Add(1)
		if s.dp != nil && len(payload) >= 40 {
			var key dataplane.SessionKeyV6
			copy(key.SrcIP[:], payload[0:16])
			copy(key.DstIP[:], payload[16:32])
			key.SrcPort = binary.LittleEndian.Uint16(payload[32:34])
			key.DstPort = binary.LittleEndian.Uint16(payload[34:36])
			key.Protocol = payload[36]
			if val, err := s.dp.GetSessionV6(key); err == nil {
				if val.ReverseKey.Protocol != 0 {
					s.dp.DeleteSessionV6(val.ReverseKey)
				}
				if val.IsReverse == 0 &&
					val.Flags&dataplane.SessFlagSNAT != 0 &&
					val.Flags&dataplane.SessFlagStaticNAT == 0 {
					s.dp.DeleteDNATEntryV6(dataplane.DNATKeyV6{
						Protocol: key.Protocol,
						DstIP:    val.NATSrcIP,
						DstPort:  val.NATSrcPort,
					})
				}
			}
			s.dp.DeleteSessionV6(key)
		}

	case syncMsgBulkStart:
		var epoch uint64
		if len(payload) >= 8 {
			epoch = binary.LittleEndian.Uint64(payload[:8])
		}
		s.stats.BulkSyncStartTime.Store(time.Now().UnixNano())
		s.stats.BulkSyncEndTime.Store(0)
		s.stats.BulkSyncSessions.Store(0)
		// Snapshot zone ownership at BulkStart so reconciliation uses a
		// consistent view even if primary/secondary roles flip mid-bulk.
		zoneSnap := s.snapshotZoneOwnership()
		s.bulkMu.Lock()
		s.bulkInProgress = true
		s.bulkRecvEpoch = epoch
		s.bulkRecvV4 = make(map[dataplane.SessionKey]struct{})
		s.bulkRecvV6 = make(map[dataplane.SessionKeyV6]struct{})
		s.bulkZoneSnapshot = zoneSnap
		s.bulkMu.Unlock()
		slog.Info("cluster sync: bulk transfer starting",
			"epoch", epoch,
			"local", connLocalAddrString(conn),
			"remote", connRemoteAddrString(conn))

	case syncMsgBulkEnd:
		var epoch uint64
		if len(payload) >= 8 {
			epoch = binary.LittleEndian.Uint64(payload[:8])
		}
		s.bulkMu.Lock()
		if s.bulkInProgress && s.bulkRecvEpoch != epoch {
			s.bulkMu.Unlock()
			slog.Warn("cluster sync: ignoring BulkEnd with mismatched epoch",
				"expected", s.bulkRecvEpoch, "got", epoch)
			break
		}
		s.bulkMu.Unlock()
		s.stats.BulkSyncEndTime.Store(time.Now().UnixNano())
		s.reconcileStaleSessions()
		slog.Info("cluster sync: bulk transfer complete",
			"epoch", epoch,
			"sessions", s.stats.BulkSyncSessions.Load(),
			"local", connLocalAddrString(conn),
			"remote", connRemoteAddrString(conn))
		s.sendBulkAck(conn, epoch)
		if s.OnBulkSyncReceived != nil {
			go s.OnBulkSyncReceived()
		}

	case syncMsgBulkAck:
		if len(payload) < 8 {
			slog.Warn("cluster sync: bulk ack message too short")
			return
		}
		epoch := binary.LittleEndian.Uint64(payload[:8])
		stats := s.Stats()
		slog.Info("cluster sync: bulk ack received",
			"epoch", epoch,
			"local", connLocalAddrString(conn),
			"remote", connRemoteAddrString(conn),
			"sessions_sent", stats.SessionsSent,
			"sessions_received", stats.SessionsReceived,
			"sessions_installed", stats.SessionsInstalled,
			"queue_len", len(s.sendCh),
			"queue_cap", cap(s.sendCh))
		if pending := s.pendingBulkAckEpoch.Load(); pending != 0 && epoch >= pending {
			s.pendingBulkAckEpoch.Store(0)
			s.pendingBulkAckSince.Store(0)
		}
		if s.OnBulkSyncAckReceived != nil {
			go s.OnBulkSyncAckReceived()
		}

	case syncMsgHeartbeat:
		// keepalive, no action needed

	case syncMsgConfig:
		s.stats.ConfigsReceived.Add(1)
		s.stats.LastConfigSyncTime.Store(time.Now().UnixNano())
		s.stats.LastConfigSyncSize.Store(uint64(len(payload)))
		if s.OnConfigReceived != nil {
			configText := string(payload)
			slog.Info("cluster sync: config received from peer", "size", len(payload))
			go s.OnConfigReceived(configText)
		}

	case syncMsgIPsecSA:
		s.stats.IPsecSAReceived.Add(1)
		names := decodeIPsecSAPayload(payload)
		s.peerIPsecSAsMu.Lock()
		s.peerIPsecSAs = names
		s.peerIPsecSAsMu.Unlock()
		slog.Debug("cluster sync: received IPsec SA list", "count", len(names))
		if s.OnIPsecSAReceived != nil {
			s.OnIPsecSAReceived(names)
		}

	case syncMsgFailover:
		if len(payload) < 1 {
			slog.Warn("cluster sync: failover message too short")
			return
		}
		rgID := int(payload[0])
		slog.Info("cluster sync: remote failover request received", "rg", rgID)
		if s.OnRemoteFailover != nil {
			go s.OnRemoteFailover(rgID)
		}

	case syncMsgFence:
		s.stats.FencesReceived.Add(1)
		slog.Warn("cluster sync: fence received from peer — disabling all RGs")
		if s.OnFenceReceived != nil {
			s.OnFenceReceived()
		}

	case syncMsgClockSync:
		if len(payload) < 8 {
			slog.Warn("cluster sync: clock sync message too short")
			return
		}
		peerMono := binary.LittleEndian.Uint64(payload[:8])
		localMono := monotonicSeconds()
		offset := int64(localMono) - int64(peerMono)
		s.peerClockOffset.Store(offset)
		s.clockSynced.Store(true)
		slog.Info("cluster sync: clock synced with peer",
			"peer_mono", peerMono, "local_mono", localMono, "offset", offset)
	case syncMsgBarrier:
		if len(payload) < 8 {
			slog.Warn("cluster sync: barrier message too short")
			return
		}
		seq := binary.LittleEndian.Uint64(payload[:8])
		stats := s.Stats()
		slog.Info("cluster sync: barrier received",
			"seq", seq,
			"sessions_received", stats.SessionsReceived,
			"sessions_installed", stats.SessionsInstalled,
			"queue_len", len(s.sendCh),
			"queue_cap", cap(s.sendCh))
		s.sendBarrierAck(conn, seq)
	case syncMsgBarrierAck:
		if len(payload) < 8 {
			slog.Warn("cluster sync: barrier ack message too short")
			return
		}
		seq := binary.LittleEndian.Uint64(payload[:8])
		stats := s.Stats()
		peerSessionsReceived := uint64(0)
		peerSessionsInstalled := uint64(0)
		if len(payload) >= 24 {
			peerSessionsReceived = binary.LittleEndian.Uint64(payload[8:16])
			peerSessionsInstalled = binary.LittleEndian.Uint64(payload[16:24])
		}
		slog.Info("cluster sync: barrier ack received",
			"seq", seq,
			"sessions_sent", stats.SessionsSent,
			"sessions_received", stats.SessionsReceived,
			"sessions_installed", stats.SessionsInstalled,
			"peer_sessions_received", peerSessionsReceived,
			"peer_sessions_installed", peerSessionsInstalled,
			"queue_len", len(s.sendCh),
			"queue_cap", cap(s.sendCh))
		for {
			current := s.barrierAckSeq.Load()
			if seq <= current || s.barrierAckSeq.CompareAndSwap(current, seq) {
				break
			}
		}
		// Record fence ack timestamp for status observability (#311).
		s.stats.LastFenceAckAt.Store(time.Now().UnixNano())
		s.completeBarrierWait(seq)
	}
}

func (s *SessionSync) sendBarrierAck(conn net.Conn, seq uint64) {
	// Queue the barrier ack through sendCh so it goes through the
	// sendLoop in order with session messages. Direct writeMu access
	// from a goroutine starves when sendLoop holds the lock continuously
	// during high-throughput traffic.
	var payload [24]byte
	binary.LittleEndian.PutUint64(payload[:], seq)
	stats := s.Stats()
	binary.LittleEndian.PutUint64(payload[8:16], stats.SessionsReceived)
	binary.LittleEndian.PutUint64(payload[16:24], stats.SessionsInstalled)
	msg := encodeRawMessage(syncMsgBarrierAck, payload[:])
	select {
	case s.sendCh <- msg:
		slog.Info("cluster sync: barrier ack queued",
			"seq", seq,
			"sessions_received", stats.SessionsReceived,
			"sessions_installed", stats.SessionsInstalled)
	default:
		slog.Warn("cluster sync: barrier ack dropped (queue full)", "seq", seq)
	}
}

func (s *SessionSync) completeBarrierWait(seq uint64) {
	s.barrierWaitMu.Lock()
	waiter := s.barrierWaiters[seq]
	delete(s.barrierWaiters, seq)
	s.barrierWaitMu.Unlock()
	if waiter != nil {
		close(waiter)
	}
}

func (s *SessionSync) sendBulkAck(conn net.Conn, epoch uint64) {
	if conn == nil {
		slog.Debug("cluster sync: skipping bulk ack on nil connection", "epoch", epoch)
		return
	}
	// Queue the bulk ack through sendCh so it goes through the sendLoop.
	// Direct writeMu access starves when sendLoop holds the lock during
	// high-throughput traffic.
	var payload [8]byte
	binary.LittleEndian.PutUint64(payload[:], epoch)
	msg := encodeRawMessage(syncMsgBulkAck, payload[:])
	select {
	case s.sendCh <- msg:
		slog.Info("cluster sync: bulk ack queued",
			"epoch", epoch,
			"local", connLocalAddrString(conn),
			"remote", connRemoteAddrString(conn))
	default:
		slog.Warn("cluster sync: bulk ack dropped (queue full)",
			"epoch", epoch)
	}
}

func (s *SessionSync) waitForSendQueueDrain(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if len(s.sendCh) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for session sync send queue drain")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (s *SessionSync) enqueueBarrierMessage(msg []byte, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case s.sendCh <- msg:
		return nil
	case <-timer.C:
		return fmt.Errorf("timed out queueing session sync barrier")
	}
}

func (s *SessionSync) writeBarrierMessage(payload []byte, timeout time.Duration) error {
	// Serialize barrier injection with BulkSync() so a background bulk-prime
	// retry cannot start writing a new bulk ahead of the demotion barrier after
	// quiescence has already been observed.
	s.bulkSendMu.Lock()
	defer s.bulkSendMu.Unlock()
	if err := s.waitForSendQueueDrain(timeout); err != nil {
		return err
	}
	conn := s.getActiveConn()
	if conn == nil {
		return fmt.Errorf("session sync not connected")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := writeMsg(conn, syncMsgBarrier, payload); err != nil {
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return err
	}
	seq := binary.LittleEndian.Uint64(payload)
	slog.Info("cluster sync: barrier sent",
		"seq", seq,
		"local", connLocalAddrString(conn),
		"remote", connRemoteAddrString(conn))
	return nil
}

// WaitForPeerBarrier queues an ordered marker on the session-sync stream and
// waits until the peer acknowledges that it processed all earlier messages.
func (s *SessionSync) WaitForPeerBarrier(timeout time.Duration) error {
	if !s.stats.Connected.Load() {
		return fmt.Errorf("session sync not connected")
	}
	seq := s.barrierSeq.Add(1)
	waiter := make(chan struct{})
	s.barrierWaitMu.Lock()
	if s.barrierWaiters == nil {
		s.barrierWaiters = make(map[uint64]chan struct{})
	}
	s.barrierWaiters[seq] = waiter
	s.barrierWaitMu.Unlock()

	var payload [8]byte
	binary.LittleEndian.PutUint64(payload[:], seq)
	stats := s.Stats()
	slog.Info("cluster sync: queueing barrier",
		"seq", seq,
		"sessions_sent", stats.SessionsSent,
		"sessions_received", stats.SessionsReceived,
		"sessions_installed", stats.SessionsInstalled,
		"queue_len", len(s.sendCh),
		"queue_cap", cap(s.sendCh))
	if err := s.writeBarrierMessage(payload[:], timeout/2); err != nil {
		s.barrierWaitMu.Lock()
		delete(s.barrierWaiters, seq)
		s.barrierWaitMu.Unlock()
		return err
	}
	// Record the install fence sequence for status observability (#311).
	s.stats.LastFenceSeq.Store(seq)

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-waiter:
		return nil
	case <-timer.C:
		s.barrierWaitMu.Lock()
		delete(s.barrierWaiters, seq)
		s.barrierWaitMu.Unlock()
		stats := s.Stats()
		return fmt.Errorf(
			"timed out waiting for session sync barrier ack seq=%d sessions_sent=%d sessions_received=%d sessions_installed=%d queue_len=%d",
			seq,
			stats.SessionsSent,
			stats.SessionsReceived,
			stats.SessionsInstalled,
			len(s.sendCh),
		)
	}
}

// WaitForPeerBarriersDrained waits until all still-pending barrier waiters have
// been acknowledged by the peer. Timed-out barriers are not treated as
// permanently blocking: a later barrier ack is cumulative, so retries should
// not get stuck on stale sequence numbers after the original waiter was removed.
func (s *SessionSync) WaitForPeerBarriersDrained(timeout time.Duration) error {
	s.barrierWaitMu.Lock()
	target := uint64(0)
	for seq := range s.barrierWaiters {
		if seq > target {
			target = seq
		}
	}
	s.barrierWaitMu.Unlock()
	if target == 0 || s.barrierAckSeq.Load() >= target {
		return nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if s.barrierAckSeq.Load() >= target {
			return nil
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			return fmt.Errorf(
				"timed out waiting for previous session sync barriers acked through seq=%d last_acked=%d",
				target,
				s.barrierAckSeq.Load(),
			)
		}
	}
}

// WaitForIdle waits for the outbound sync path to stop advancing for a short
// stable window. This is used before graceful HA demotion so a barrier is not
// injected while unrelated background sync traffic is still actively growing.
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
		if initialized &&
			stats.SessionsSent == lastSent &&
			stats.DeletesSent == lastDeletes &&
			queueLen == lastQueue {
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
			return fmt.Errorf(
				"timed out waiting for session sync idle sessions_sent=%d deletes_sent=%d queue_len=%d",
				lastSent,
				lastDeletes,
				lastQueue,
			)
		}
		time.Sleep(sampleInterval)
	}
}

// snapshotZoneOwnership returns a map of zoneID→shouldSync for all zones
// currently in the zone→RG mapping. Used to freeze ownership at BulkStart.
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

// reconcileStaleSessions deletes local sessions in peer-owned zones that
// were not refreshed during the bulk receive. Called on BulkEnd.
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
	slog.Info("cluster sync: reconcile stale sessions starting",
		"recv_v4", len(recvV4),
		"recv_v6", len(recvV6),
		"zones", len(zoneSnap))
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

	// shouldSyncAtBulkStart uses the frozen snapshot if available. Zones missing
	// from that snapshot are treated as syncable to avoid deleting sessions
	// before the current bulk stream has finished delivering them.
	shouldSyncAtBulkStart := func(zoneID uint16) bool {
		if v, ok := zoneSnap[zoneID]; ok {
			return v
		}
		// Zone missing from the frozen snapshot means ownership was not known at
		// BulkStart. Skip stale reconciliation for that zone rather than falling
		// back to a later live view that can delete sessions we have not finished
		// receiving from the peer yet.
		return true
	}

	var deleted int

	// Collect stale v4 sessions for deletion (can't delete during iteration).
	var staleV4 []dataplane.SessionKey
	v4IterStart := time.Now()
	s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		// Only reconcile sessions in zones the peer owns (where we're NOT primary).
		if shouldSyncAtBulkStart(val.IngressZone) {
			return true
		}
		if _, ok := recvV4[key]; !ok {
			staleV4 = append(staleV4, key)
		}
		return true
	})
	slog.Info("cluster sync: reconcile stale sessions iterated v4",
		"stale", len(staleV4),
		"elapsed", time.Since(v4IterStart))

	v4DeleteStart := time.Now()
	for _, key := range staleV4 {
		// Look up to clean reverse entry and dnat_table.
		if val, err := s.dp.GetSessionV4(key); err == nil {
			if val.ReverseKey.Protocol != 0 {
				s.dp.DeleteSession(val.ReverseKey)
			}
			if val.Flags&dataplane.SessFlagSNAT != 0 &&
				val.Flags&dataplane.SessFlagStaticNAT == 0 {
				s.dp.DeleteDNATEntry(dataplane.DNATKey{
					Protocol: key.Protocol,
					DstIP:    val.NATSrcIP,
					DstPort:  val.NATSrcPort,
				})
			}
		}
		s.dp.DeleteSession(key)
		deleted++
	}
	slog.Info("cluster sync: reconcile stale sessions deleted v4",
		"deleted", len(staleV4),
		"elapsed", time.Since(v4DeleteStart))

	// Collect stale v6 sessions.
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
	slog.Info("cluster sync: reconcile stale sessions iterated v6",
		"stale", len(staleV6),
		"elapsed", time.Since(v6IterStart))

	v6DeleteStart := time.Now()
	for _, key := range staleV6 {
		if val, err := s.dp.GetSessionV6(key); err == nil {
			if val.ReverseKey.Protocol != 0 {
				s.dp.DeleteSessionV6(val.ReverseKey)
			}
			if val.Flags&dataplane.SessFlagSNAT != 0 &&
				val.Flags&dataplane.SessFlagStaticNAT == 0 {
				s.dp.DeleteDNATEntryV6(dataplane.DNATKeyV6{
					Protocol: key.Protocol,
					DstIP:    val.NATSrcIP,
					DstPort:  val.NATSrcPort,
				})
			}
		}
		s.dp.DeleteSessionV6(key)
		deleted++
	}
	slog.Info("cluster sync: reconcile stale sessions deleted v6",
		"deleted", len(staleV6),
		"elapsed", time.Since(v6DeleteStart))

	if deleted > 0 {
		slog.Info("cluster sync: reconciled stale sessions", "deleted", deleted)
	}
	slog.Info("cluster sync: reconcile stale sessions complete",
		"deleted", deleted,
		"elapsed", time.Since(start))
}

func (s *SessionSync) handleDisconnect(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case s.conn0 != nil && s.conn0 == conn:
		s.conn0.Close()
		s.conn0 = nil
		slog.Info("cluster sync: fabric 0 disconnected")
	case s.conn1 != nil && s.conn1 == conn:
		s.conn1.Close()
		s.conn1 = nil
		slog.Info("cluster sync: fabric 1 disconnected")
	default:
		slog.Debug("cluster sync: ignoring stale disconnect",
			"stale", fmt.Sprintf("%p", conn))
		return
	}

	connected := s.conn0 != nil || s.conn1 != nil
	s.stats.Connected.Store(connected)
	if !connected {
		pendingBarriers := s.barrierSeq.Load()
		ackedBarriers := s.barrierAckSeq.Load()
		s.barrierSeq.Store(0)
		s.barrierAckSeq.Store(0)
		s.barrierWaitMu.Lock()
		clearedWaiters := len(s.barrierWaiters)
		s.barrierWaiters = nil
		s.barrierWaitMu.Unlock()
		s.clockSynced.Store(false)
		s.pendingBulkAckEpoch.Store(0)
		s.pendingBulkAckSince.Store(0)
		slog.Info("cluster sync: peer disconnected (all fabrics down)")
		if pendingBarriers != 0 || ackedBarriers != 0 || clearedWaiters != 0 {
			slog.Info("cluster sync: reset barrier state after disconnect",
				"pending_seq", pendingBarriers,
				"acked_seq", ackedBarriers,
				"cleared_waiters", clearedWaiters)
		}
		if s.OnPeerDisconnected != nil {
			go s.OnPeerDisconnected()
		}
	}
}

// FormatStats returns a formatted string of sync statistics.
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
	return fmt.Sprintf(
		"Session sync statistics:\n"+
			"  Connected:          %v\n"+
			"  Active fabric:      %s\n"+
			"  Sessions sent:      %d\n"+
			"  Sessions received:  %d\n"+
			"  Sessions installed: %d\n"+
			"  Deletes sent:       %d\n"+
			"  Deletes received:   %d\n"+
			"  Bulk syncs:         %d\n"+
			"  Configs sent:       %d\n"+
			"  Configs received:   %d\n"+
			"  IPsec SAs sent:     %d\n"+
			"  IPsec SAs received: %d\n"+
			"  Fences sent:        %d\n"+
			"  Fences received:    %d\n"+
			"  Install fence seq:  %d\n"+
			"  Last fence ack:     %s\n"+
			"  Errors:             %d\n",
		s.stats.Connected.Load(),
		fabricStr,
		s.stats.SessionsSent.Load(),
		s.stats.SessionsReceived.Load(),
		s.stats.SessionsInstalled.Load(),
		s.stats.DeletesSent.Load(),
		s.stats.DeletesReceived.Load(),
		s.stats.BulkSyncs.Load(),
		s.stats.ConfigsSent.Load(),
		s.stats.ConfigsReceived.Load(),
		s.stats.IPsecSASent.Load(),
		s.stats.IPsecSAReceived.Load(),
		s.stats.FencesSent.Load(),
		s.stats.FencesReceived.Load(),
		fenceSeq,
		fenceAckStr,
		s.stats.Errors.Load(),
	)
}

// PeerIPsecSAs returns the latest IPsec connection names received from the peer.
func (s *SessionSync) PeerIPsecSAs() []string {
	s.peerIPsecSAsMu.Lock()
	defer s.peerIPsecSAsMu.Unlock()
	cp := make([]string, len(s.peerIPsecSAs))
	copy(cp, s.peerIPsecSAs)
	return cp
}

// QueueIPsecSA sends the list of active IPsec connection names to the peer.
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

// monotonicSeconds returns monotonic clock in seconds.
func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}

// rebaseTimestamp adjusts a peer timestamp to the local clock domain.
// offset = localMono − peerMono (computed at connection setup).
func rebaseTimestamp(peerTS uint64, offset int64) uint64 {
	v := int64(peerTS) + offset
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// --- Wire encoding helpers ---

// writeFull loops until all bytes are written or an error occurs,
// handling short writes from TCP backpressure.
func writeFull(conn net.Conn, buf []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(syncWriteDeadline)); err != nil {
		return err
	}
	defer conn.SetWriteDeadline(time.Time{})
	for len(buf) > 0 {
		n, err := conn.Write(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}

func writeMsg(conn net.Conn, msgType uint8, payload []byte) error {
	buf := make([]byte, syncHeaderSize+len(payload))
	copy(buf[:4], syncMagic[:])
	buf[4] = msgType
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(payload)))
	copy(buf[syncHeaderSize:], payload)
	return writeFull(conn, buf)
}

func encodeSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) []byte {
	payload := encodeSessionV4Payload(key, val)
	return encodeRawMessage(syncMsgSessionV4, payload)
}

func encodeRawMessage(msgType uint8, payload []byte) []byte {
	hdr := make([]byte, syncHeaderSize)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = msgType
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	return append(hdr, payload...)
}

func encodeSessionV4Payload(key dataplane.SessionKey, val dataplane.SessionValue) []byte {
	keySize := 16  // SessionKey: 4+4+2+2+1+3
	valSize := 160 // includes userspace FIB cache metadata
	buf := make([]byte, keySize+valSize)
	off := 0

	// Key
	copy(buf[off:], key.SrcIP[:])
	off += 4
	copy(buf[off:], key.DstIP[:])
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], key.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], key.DstPort)
	off += 2
	buf[off] = key.Protocol
	off += 4 // include pad

	// Value (key fields for session reconstruction)
	buf[off] = val.State
	off++
	buf[off] = val.Flags
	off++
	buf[off] = val.TCPState
	off++
	buf[off] = val.IsReverse
	off += 5 // include pad0

	binary.LittleEndian.PutUint64(buf[off:], val.SessionID)
	off += 8

	binary.LittleEndian.PutUint64(buf[off:], val.Created)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.LastSeen)
	off += 8
	binary.LittleEndian.PutUint32(buf[off:], val.Timeout)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], val.PolicyID)
	off += 4

	binary.LittleEndian.PutUint16(buf[off:], val.IngressZone)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.EgressZone)
	off += 2

	binary.LittleEndian.PutUint32(buf[off:], val.NATSrcIP)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], val.NATDstIP)
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.NATSrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.NATDstPort)
	off += 2

	// Counters
	binary.LittleEndian.PutUint64(buf[off:], val.FwdPackets)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.FwdBytes)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.RevPackets)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.RevBytes)
	off += 8

	// Reverse key
	copy(buf[off:], val.ReverseKey.SrcIP[:])
	off += 4
	copy(buf[off:], val.ReverseKey.DstIP[:])
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.ReverseKey.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.ReverseKey.DstPort)
	off += 2
	buf[off] = val.ReverseKey.Protocol
	off += 4 // include pad

	buf[off] = val.ALGType
	off++
	buf[off] = val.LogFlags
	off += 3 // include pad1

	binary.LittleEndian.PutUint32(buf[off:], val.FibIfindex)
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.FibVlanID)
	off += 2
	copy(buf[off:], val.FibDmac[:])
	off += 6
	copy(buf[off:], val.FibSmac[:])
	off += 6
	binary.LittleEndian.PutUint16(buf[off:], val.FibGen)
	off += 2

	return buf[:off]
}

func encodeSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) []byte {
	payload := encodeSessionV6Payload(key, val)
	hdr := make([]byte, syncHeaderSize)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = syncMsgSessionV6
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	return append(hdr, payload...)
}

func encodeSessionV6Payload(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) []byte {
	buf := make([]byte, 512) // generous buffer for v6
	off := 0

	// Key
	copy(buf[off:], key.SrcIP[:])
	off += 16
	copy(buf[off:], key.DstIP[:])
	off += 16
	binary.LittleEndian.PutUint16(buf[off:], key.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], key.DstPort)
	off += 2
	buf[off] = key.Protocol
	off += 4 // include pad

	// Value
	buf[off] = val.State
	off++
	buf[off] = val.Flags
	off++
	buf[off] = val.TCPState
	off++
	buf[off] = val.IsReverse
	off += 5

	binary.LittleEndian.PutUint64(buf[off:], val.SessionID)
	off += 8

	binary.LittleEndian.PutUint64(buf[off:], val.Created)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.LastSeen)
	off += 8
	binary.LittleEndian.PutUint32(buf[off:], val.Timeout)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], val.PolicyID)
	off += 4

	binary.LittleEndian.PutUint16(buf[off:], val.IngressZone)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.EgressZone)
	off += 2

	copy(buf[off:], val.NATSrcIP[:])
	off += 16
	copy(buf[off:], val.NATDstIP[:])
	off += 16
	binary.LittleEndian.PutUint16(buf[off:], val.NATSrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.NATDstPort)
	off += 2

	binary.LittleEndian.PutUint64(buf[off:], val.FwdPackets)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.FwdBytes)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.RevPackets)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.RevBytes)
	off += 8

	// Reverse key
	copy(buf[off:], val.ReverseKey.SrcIP[:])
	off += 16
	copy(buf[off:], val.ReverseKey.DstIP[:])
	off += 16
	binary.LittleEndian.PutUint16(buf[off:], val.ReverseKey.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.ReverseKey.DstPort)
	off += 2
	buf[off] = val.ReverseKey.Protocol
	off += 4

	buf[off] = val.ALGType
	off++
	buf[off] = val.LogFlags
	off += 3

	binary.LittleEndian.PutUint32(buf[off:], val.FibIfindex)
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.FibVlanID)
	off += 2
	copy(buf[off:], val.FibDmac[:])
	off += 6
	copy(buf[off:], val.FibSmac[:])
	off += 6
	binary.LittleEndian.PutUint16(buf[off:], val.FibGen)
	off += 2

	return buf[:off]
}

func encodeDeleteV4(key dataplane.SessionKey) []byte {
	hdr := make([]byte, syncHeaderSize+16)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = syncMsgDeleteV4
	binary.LittleEndian.PutUint32(hdr[8:12], 16)
	off := syncHeaderSize
	copy(hdr[off:], key.SrcIP[:])
	off += 4
	copy(hdr[off:], key.DstIP[:])
	off += 4
	binary.LittleEndian.PutUint16(hdr[off:], key.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(hdr[off:], key.DstPort)
	off += 2
	hdr[off] = key.Protocol
	return hdr
}

func encodeDeleteV6(key dataplane.SessionKeyV6) []byte {
	hdr := make([]byte, syncHeaderSize+40)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = syncMsgDeleteV6
	binary.LittleEndian.PutUint32(hdr[8:12], 40)
	off := syncHeaderSize
	copy(hdr[off:], key.SrcIP[:])
	off += 16
	copy(hdr[off:], key.DstIP[:])
	off += 16
	binary.LittleEndian.PutUint16(hdr[off:], key.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(hdr[off:], key.DstPort)
	off += 2
	hdr[off] = key.Protocol
	return hdr
}

// --- Session decode helpers ---

// decodeSessionV4Payload decodes a v4 session from wire format.
// Returns key, value, and ok flag. Must match encodeSessionV4Payload layout.
func decodeSessionV4Payload(payload []byte) (dataplane.SessionKey, dataplane.SessionValue, bool) {
	var key dataplane.SessionKey
	var val dataplane.SessionValue
	if len(payload) < 16 { // minimum key size
		return key, val, false
	}

	off := 0
	copy(key.SrcIP[:], payload[off:off+4])
	off += 4
	copy(key.DstIP[:], payload[off:off+4])
	off += 4
	key.SrcPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	key.DstPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	key.Protocol = payload[off]
	off += 4 // include pad

	if off+8 > len(payload) {
		return key, val, false
	}

	val.State = payload[off]
	off++
	val.Flags = payload[off]
	off++
	val.TCPState = payload[off]
	off++
	val.IsReverse = payload[off]
	off += 5 // include pad0

	if off+48 > len(payload) {
		return key, val, true // partial value is OK for key-only
	}

	val.SessionID = binary.LittleEndian.Uint64(payload[off:])
	off += 8

	val.Created = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.LastSeen = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.Timeout = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.PolicyID = binary.LittleEndian.Uint32(payload[off:])
	off += 4

	val.IngressZone = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	val.EgressZone = binary.LittleEndian.Uint16(payload[off:])
	off += 2

	val.NATSrcIP = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.NATDstIP = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.NATSrcPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	val.NATDstPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2

	if off+32 > len(payload) {
		return key, val, true
	}

	val.FwdPackets = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.FwdBytes = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.RevPackets = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.RevBytes = binary.LittleEndian.Uint64(payload[off:])
	off += 8

	if off+16 <= len(payload) {
		copy(val.ReverseKey.SrcIP[:], payload[off:off+4])
		off += 4
		copy(val.ReverseKey.DstIP[:], payload[off:off+4])
		off += 4
		val.ReverseKey.SrcPort = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		val.ReverseKey.DstPort = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		val.ReverseKey.Protocol = payload[off]
		off += 4 // include pad
	}

	if off+2 <= len(payload) {
		val.ALGType = payload[off]
		off++
		val.LogFlags = payload[off]
		off += 3 // include pad1
	}
	if off+20 <= len(payload) {
		val.FibIfindex = binary.LittleEndian.Uint32(payload[off:])
		off += 4
		val.FibVlanID = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		copy(val.FibDmac[:], payload[off:off+6])
		off += 6
		copy(val.FibSmac[:], payload[off:off+6])
		off += 6
		val.FibGen = binary.LittleEndian.Uint16(payload[off:])
	}

	return key, val, true
}

// decodeSessionV6Payload decodes a v6 session from wire format.
func decodeSessionV6Payload(payload []byte) (dataplane.SessionKeyV6, dataplane.SessionValueV6, bool) {
	var key dataplane.SessionKeyV6
	var val dataplane.SessionValueV6
	if len(payload) < 40 { // minimum key size
		return key, val, false
	}

	off := 0
	copy(key.SrcIP[:], payload[off:off+16])
	off += 16
	copy(key.DstIP[:], payload[off:off+16])
	off += 16
	key.SrcPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	key.DstPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	key.Protocol = payload[off]
	off += 4 // include pad

	if off+8 > len(payload) {
		return key, val, false
	}

	val.State = payload[off]
	off++
	val.Flags = payload[off]
	off++
	val.TCPState = payload[off]
	off++
	val.IsReverse = payload[off]
	off += 5 // include pad0

	if off+48 > len(payload) {
		return key, val, true
	}

	val.SessionID = binary.LittleEndian.Uint64(payload[off:])
	off += 8

	val.Created = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.LastSeen = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.Timeout = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.PolicyID = binary.LittleEndian.Uint32(payload[off:])
	off += 4

	val.IngressZone = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	val.EgressZone = binary.LittleEndian.Uint16(payload[off:])
	off += 2

	if off+36 > len(payload) {
		return key, val, true
	}

	copy(val.NATSrcIP[:], payload[off:off+16])
	off += 16
	copy(val.NATDstIP[:], payload[off:off+16])
	off += 16
	val.NATSrcPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	val.NATDstPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2

	if off+32 > len(payload) {
		return key, val, true
	}

	val.FwdPackets = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.FwdBytes = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.RevPackets = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.RevBytes = binary.LittleEndian.Uint64(payload[off:])
	off += 8

	if off+40 <= len(payload) {
		copy(val.ReverseKey.SrcIP[:], payload[off:off+16])
		off += 16
		copy(val.ReverseKey.DstIP[:], payload[off:off+16])
		off += 16
		val.ReverseKey.SrcPort = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		val.ReverseKey.DstPort = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		val.ReverseKey.Protocol = payload[off]
		off += 4
	}

	if off+2 <= len(payload) {
		val.ALGType = payload[off]
		off++
		val.LogFlags = payload[off]
		off += 3 // include pad1
	}
	if off+20 <= len(payload) {
		val.FibIfindex = binary.LittleEndian.Uint32(payload[off:])
		off += 4
		val.FibVlanID = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		copy(val.FibDmac[:], payload[off:off+6])
		off += 6
		copy(val.FibSmac[:], payload[off:off+6])
		off += 6
		val.FibGen = binary.LittleEndian.Uint16(payload[off:])
	}

	return key, val, true
}

// --- IPsec SA encode/decode ---

// encodeIPsecSAPayload encodes a list of IPsec connection names as newline-separated bytes.
func encodeIPsecSAPayload(names []string) []byte {
	if len(names) == 0 {
		return nil
	}
	joined := ""
	for i, name := range names {
		if i > 0 {
			joined += "\n"
		}
		joined += name
	}
	return []byte(joined)
}

// decodeIPsecSAPayload decodes a newline-separated list of IPsec connection names.
func decodeIPsecSAPayload(payload []byte) []string {
	if len(payload) == 0 {
		return nil
	}
	parts := strings.Split(string(payload), "\n")
	var names []string
	for _, p := range parts {
		if p != "" {
			names = append(names, p)
		}
	}
	return names
}
