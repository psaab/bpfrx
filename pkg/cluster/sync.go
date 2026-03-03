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
	syncMsgSessionV4 = 1
	syncMsgSessionV6 = 2
	syncMsgDeleteV4  = 3
	syncMsgDeleteV6  = 4
	syncMsgBulkStart = 5
	syncMsgBulkEnd   = 6
	syncMsgHeartbeat = 7
	syncMsgConfig    = 8  // full config text sync from primary to secondary
	syncMsgIPsecSA   = 9  // IPsec SA connection names sync
	syncMsgFailover  = 10 // remote failover request (payload: 1 byte rgID)
	syncMsgFence     = 11 // peer fencing: receiver should disable all RGs
)

// syncHeader is the wire header for each sync message.
type syncHeader struct {
	Magic  [4]byte
	Type   uint8
	Pad    [3]byte
	Length uint32 // payload length after header
}

const syncHeaderSize = 12

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
	Connected         atomic.Bool

	// Cold sync timing.
	BulkSyncStartTime atomic.Int64  // UnixNano (0 = never)
	BulkSyncEndTime   atomic.Int64  // UnixNano (0 = in progress or never)
	BulkSyncSessions  atomic.Uint64 // sessions in current/last bulk

	// Config sync timing.
	LastConfigSyncTime atomic.Int64  // UnixNano
	LastConfigSyncSize atomic.Uint64 // bytes
}

// SessionSync manages TCP-based session state replication between cluster peers.
type SessionSync struct {
	localAddr string // local listen address (e.g. ":4785")
	peerAddr  string // peer connect address (e.g. "10.0.0.2:4785")
	dp        dataplane.DataPlane
	stats     SyncStats
	mu        sync.Mutex
	conn      net.Conn
	writeMu   sync.Mutex // serializes all conn.Write calls (sendLoop + writeMsg)
	listener  net.Listener
	localAddr1 string       // secondary fabric listen address ("" = single-fabric)
	peerAddr1  string       // secondary fabric peer address
	listener1  net.Listener // secondary fabric listener
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	sendCh    chan []byte // buffered channel for outgoing messages

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

	// OnPeerConnected is called when a peer sync connection is established
	// (either inbound accept or outbound connect). The primary uses this to
	// push config to a returning secondary.
	OnPeerConnected func()

	// peerIPsecSAs holds the latest IPsec connection names received from the peer.
	peerIPsecSAs   []string
	peerIPsecSAsMu sync.Mutex

	IsPrimaryFn        func() bool         // returns true if local node is primary for RG 0
	IsPrimaryForRGFn   func(rgID int) bool // returns true if local is primary for given RG
	lastSweepTime      uint64              // monotonic seconds of last sync sweep
	lastSessionCounter uint64              // last seen GLOBAL_CTR_SESSIONS_NEW value
	syncBackfillNeeded atomic.Bool         // replay sweep window on send queue overflow
	vrfDevice          string              // VRF device for SO_BINDTODEVICE (empty = default VRF)

	zoneRGMu  sync.RWMutex
	zoneRGMap map[uint16]int // zone_id -> RG_id (for per-RG session sync)

	// Bulk receive tracking for stale-entry reconciliation.
	// During bulk receive (BulkStart..BulkEnd), track all received
	// forward session keys. On BulkEnd, delete local sessions in
	// peer-owned zones that were not refreshed.
	bulkMu         sync.Mutex
	bulkInProgress bool
	bulkRecvV4     map[dataplane.SessionKey]struct{}
	bulkRecvV6     map[dataplane.SessionKeyV6]struct{}
}

// NewSessionSync creates a new session synchronization manager.
func NewSessionSync(localAddr, peerAddr string, dp dataplane.DataPlane) *SessionSync {
	return &SessionSync{
		localAddr: localAddr,
		peerAddr:  peerAddr,
		dp:        dp,
		sendCh:    make(chan []byte, 4096),
	}
}

// NewDualSessionSync creates a session sync manager with dual fabric transport.
// If local1/peer1 are empty, falls back to single-fabric behavior.
func NewDualSessionSync(local, peer, local1, peer1 string, dp dataplane.DataPlane) *SessionSync {
	return &SessionSync{
		localAddr:  local,
		peerAddr:   peer,
		localAddr1: local1,
		peerAddr1:  peer1,
		dp:         dp,
		sendCh:     make(chan []byte, 4096),
	}
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

// Stats returns current sync statistics.
func (s *SessionSync) Stats() SyncStats {
	return s.stats
}

// IsConnected returns true if the peer connection is established.
func (s *SessionSync) IsConnected() bool {
	return s.stats.Connected.Load()
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

	// Accept incoming connections.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ctx, ln)
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
				s.acceptLoop(ctx, ln1)
			}()
		}
	}

	// Connect to peer (retry loop).
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.connectLoop(ctx)
	}()

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
	if s.conn != nil {
		s.conn.Close()
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

// StartSyncSweep starts a goroutine that periodically syncs new sessions to the peer.
// Sessions with Created >= lastSweepTime are considered new and queued for sync.
func (s *SessionSync) StartSyncSweep(ctx context.Context) {
	s.lastSweepTime = monotonicSeconds()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.syncSweep()
			}
		}
	}()
	slog.Info("cluster sync: sweep started")
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

func (s *SessionSync) syncSweep() {
	// At least one primary check must be wired.
	if s.IsPrimaryFn == nil && s.IsPrimaryForRGFn == nil {
		return
	}
	if !s.stats.Connected.Load() {
		return
	}
	if s.dp == nil {
		return
	}

	// Fast path: skip iteration when no new sessions since last sweep.
	// GLOBAL_CTR_SESSIONS_NEW (index 3) is incremented by BPF on every new session.
	newCount, err := s.dp.ReadGlobalCounter(3) // GLOBAL_CTR_SESSIONS_NEW
	if err == nil && newCount == s.lastSessionCounter {
		return
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
		return
	}

	if replaying {
		s.syncBackfillNeeded.Store(false)
		slog.Info("cluster sync: sweep replay recovered",
			"queued", count,
			"threshold", threshold)
	}

	s.lastSweepTime = now
	if newCount > 0 {
		s.lastSessionCounter = newCount
	}
	if count > 0 {
		slog.Info("cluster sync: sweep synced sessions", "count", count)
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
func (s *SessionSync) QueueDeleteV4(key dataplane.SessionKey) {
	msg := encodeDeleteV4(key)
	s.queueMessage(msg, &s.stats.DeletesSent, "delete_v4")
}

// QueueDeleteV6 queues a v6 session deletion for sync.
func (s *SessionSync) QueueDeleteV6(key dataplane.SessionKeyV6) {
	msg := encodeDeleteV6(key)
	s.queueMessage(msg, &s.stats.DeletesSent, "delete_v6")
}

// QueueConfig sends the full config text to the peer for config synchronization.
// Called by the primary node after a successful commit.
func (s *SessionSync) QueueConfig(configText string) {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
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
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
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
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
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
func (s *SessionSync) BulkSync() error {
	if s.dp == nil {
		return fmt.Errorf("dataplane not ready")
	}
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("no peer connection")
	}

	// Send bulk start marker.
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgBulkStart, nil)
	s.writeMu.Unlock()
	if err != nil {
		return err
	}

	var count, skipped int
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
			slog.Warn("bulk sync v4 write error", "err", err)
			return false
		}
		count++
		return true
	})
	if err != nil {
		return fmt.Errorf("bulk sync v4 iterate: %w", err)
	}

	// Send owned v6 forward sessions.
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
			slog.Warn("bulk sync v6 write error", "err", err)
			return false
		}
		count++
		return true
	})
	if err != nil {
		return fmt.Errorf("bulk sync v6 iterate: %w", err)
	}

	// Send bulk end marker.
	s.writeMu.Lock()
	err = writeMsg(conn, syncMsgBulkEnd, nil)
	s.writeMu.Unlock()
	if err != nil {
		return err
	}

	s.stats.BulkSyncs.Add(1)
	slog.Info("cluster sync: bulk sync complete", "sessions", count, "skipped", skipped)
	return nil
}

func (s *SessionSync) acceptLoop(ctx context.Context, ln net.Listener) {
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
		slog.Info("cluster sync: peer connected", "remote", conn.RemoteAddr())
		s.mu.Lock()
		if s.conn != nil {
			s.conn.Close()
		}
		s.conn = conn
		s.stats.Connected.Store(true)
		s.mu.Unlock()

		// Handle incoming messages from this connection.
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.receiveLoop(ctx, conn)
		}()

		if s.OnPeerConnected != nil {
			go s.OnPeerConnected()
		}

		// Send our sessions to the peer that just connected.
		// This covers the case where the peer's connectLoop connected
		// to us before our connectLoop could connect to them — without
		// this, the peer would never receive our sessions because only
		// connectLoop calls BulkSync.
		if err := s.BulkSync(); err != nil {
			slog.Warn("cluster sync: accept bulk sync failed", "err", err)
		}
	}
}

func (s *SessionSync) connectLoop(ctx context.Context) {
	peerAddrs := []string{s.peerAddr}
	if s.peerAddr1 != "" {
		peerAddrs = append(peerAddrs, s.peerAddr1)
	}
	addrIdx := 0

	for first := true; ; first = false {
		if !first {
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
		}

		if s.stats.Connected.Load() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
			continue
		}

		addr := peerAddrs[addrIdx]
		dialer := net.Dialer{Timeout: 3 * time.Second}
		if s.vrfDevice != "" {
			dialer.Control = vrfListenConfig(s.vrfDevice).Control
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			// Rotate to next address on failure
			addrIdx = (addrIdx + 1) % len(peerAddrs)
			continue
		}

		slog.Info("cluster sync: connected to peer", "addr", addr)
		// Reset to prefer primary fabric on success
		addrIdx = 0
		s.mu.Lock()
		if s.conn != nil {
			s.conn.Close()
		}
		s.conn = conn
		s.stats.Connected.Store(true)
		s.mu.Unlock()

		// Receive from this connection.
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.receiveLoop(ctx, conn)
		}()

		if s.OnPeerConnected != nil {
			go s.OnPeerConnected()
		}

		// Perform initial bulk sync after connecting.
		if err := s.BulkSync(); err != nil {
			slog.Warn("cluster sync: initial bulk sync failed", "err", err)
		}
	}
}

func (s *SessionSync) sendLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-s.sendCh:
			s.mu.Lock()
			conn := s.conn
			s.mu.Unlock()
			if conn == nil {
				continue
			}
			s.writeMu.Lock()
			err := writeFull(conn, msg)
			s.writeMu.Unlock()
			if err != nil {
				slog.Debug("cluster sync: send error", "err", err)
				s.stats.Errors.Add(1)
				s.handleDisconnect(conn)
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

		s.handleMessage(hdr.Type, payload)
	}
}

func (s *SessionSync) handleMessage(msgType uint8, payload []byte) {
	switch msgType {
	case syncMsgSessionV4:
		s.stats.SessionsReceived.Add(1)
		if s.stats.BulkSyncStartTime.Load() > 0 && s.stats.BulkSyncEndTime.Load() == 0 {
			s.stats.BulkSyncSessions.Add(1)
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

				// Rebase timestamps to local monotonic clock so the
				// local GC doesn't expire sessions due to clock skew
				// between cluster nodes (different boot times).
				localNow := monotonicSeconds()
				val.LastSeen = localNow
				if val.Created > localNow {
					val.Created = localNow
				}

				// Invalidate FIB cache — peer's cached ifindex/MAC/gen
				// are meaningless on this node.  Forces a fresh
				// bpf_fib_lookup so hairpin and RG-active checks work.
				val.FibIfindex = 0

				if err := s.dp.SetSessionV4(key, val); err == nil {
					s.stats.SessionsInstalled.Add(1)
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
					if err := s.dp.SetSessionV4(val.ReverseKey, revVal); err != nil {
						slog.Warn("cluster sync: failed to create reverse session", "err", err)
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
			s.stats.BulkSyncSessions.Add(1)
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

				// Rebase timestamps to local monotonic clock (same as V4).
				localNow := monotonicSeconds()
				val.LastSeen = localNow
				if val.Created > localNow {
					val.Created = localNow
				}

				// Invalidate FIB cache (same as V4 above).
				val.FibIfindex = 0

				if err := s.dp.SetSessionV6(key, val); err == nil {
					s.stats.SessionsInstalled.Add(1)
				}
				if val.IsReverse == 0 && val.ReverseKey.Protocol != 0 {
					revVal := val
					revVal.IsReverse = 1
					revVal.ReverseKey = key
					revVal.IngressZone = val.EgressZone
					revVal.EgressZone = val.IngressZone
					if err := s.dp.SetSessionV6(val.ReverseKey, revVal); err != nil {
						slog.Warn("cluster sync: failed to create reverse v6 session", "err", err)
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
		s.stats.BulkSyncStartTime.Store(time.Now().UnixNano())
		s.stats.BulkSyncEndTime.Store(0)
		s.stats.BulkSyncSessions.Store(0)
		s.bulkMu.Lock()
		s.bulkInProgress = true
		s.bulkRecvV4 = make(map[dataplane.SessionKey]struct{})
		s.bulkRecvV6 = make(map[dataplane.SessionKeyV6]struct{})
		s.bulkMu.Unlock()
		slog.Info("cluster sync: bulk transfer starting")

	case syncMsgBulkEnd:
		s.stats.BulkSyncEndTime.Store(time.Now().UnixNano())
		s.reconcileStaleSessions()
		slog.Info("cluster sync: bulk transfer complete")
		if s.OnBulkSyncReceived != nil {
			go s.OnBulkSyncReceived()
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
			s.OnRemoteFailover(rgID)
		}

	case syncMsgFence:
		s.stats.FencesReceived.Add(1)
		slog.Warn("cluster sync: fence received from peer — disabling all RGs")
		if s.OnFenceReceived != nil {
			s.OnFenceReceived()
		}
	}
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
	s.bulkInProgress = false
	s.bulkRecvV4 = nil
	s.bulkRecvV6 = nil
	s.bulkMu.Unlock()

	if s.dp == nil {
		return
	}

	var deleted int

	// Collect stale v4 sessions for deletion (can't delete during iteration).
	var staleV4 []dataplane.SessionKey
	s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		// Only reconcile sessions in zones the peer owns (where we're NOT primary).
		if s.ShouldSyncZone(val.IngressZone) {
			return true
		}
		if _, ok := recvV4[key]; !ok {
			staleV4 = append(staleV4, key)
		}
		return true
	})

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

	// Collect stale v6 sessions.
	var staleV6 []dataplane.SessionKeyV6
	s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if s.ShouldSyncZone(val.IngressZone) {
			return true
		}
		if _, ok := recvV6[key]; !ok {
			staleV6 = append(staleV6, key)
		}
		return true
	})

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

	if deleted > 0 {
		slog.Info("cluster sync: reconciled stale sessions", "deleted", deleted)
	}
}

func (s *SessionSync) handleDisconnect(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil && s.conn == conn {
		s.conn.Close()
		s.conn = nil
		s.stats.Connected.Store(false)
		slog.Info("cluster sync: peer disconnected")
	} else if s.conn != conn {
		slog.Debug("cluster sync: ignoring stale disconnect",
			"stale", fmt.Sprintf("%p", conn),
			"current", fmt.Sprintf("%p", s.conn))
	}
}

// FormatStats returns a formatted string of sync statistics.
func (s *SessionSync) FormatStats() string {
	return fmt.Sprintf(
		"Session sync statistics:\n"+
			"  Connected:          %v\n"+
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
			"  Errors:             %d\n",
		s.stats.Connected.Load(),
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
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
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

// --- Wire encoding helpers ---

// writeFull loops until all bytes are written or an error occurs,
// handling short writes from TCP backpressure.
func writeFull(conn net.Conn, buf []byte) error {
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
	hdr := make([]byte, syncHeaderSize)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = syncMsgSessionV4
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	return append(hdr, payload...)
}

func encodeSessionV4Payload(key dataplane.SessionKey, val dataplane.SessionValue) []byte {
	keySize := 16  // SessionKey: 4+4+2+2+1+3
	valSize := 120 // approximate SessionValue size
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

	if off+40 > len(payload) {
		return key, val, true // partial value is OK for key-only
	}

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

	if off+40 > len(payload) {
		return key, val, true
	}

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
