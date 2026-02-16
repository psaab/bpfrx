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
	syncMsgSessionV4    = 1
	syncMsgSessionV6    = 2
	syncMsgDeleteV4     = 3
	syncMsgDeleteV6     = 4
	syncMsgBulkStart    = 5
	syncMsgBulkEnd      = 6
	syncMsgHeartbeat    = 7
	syncMsgConfig       = 8 // full config text sync from primary to secondary
	syncMsgIPsecSA      = 9 // IPsec SA connection names sync
)

// syncHeader is the wire header for each sync message.
type syncHeader struct {
	Magic   [4]byte
	Type    uint8
	Pad     [3]byte
	Length  uint32 // payload length after header
}

const syncHeaderSize = 12

// SyncStats tracks session synchronization statistics.
type SyncStats struct {
	SessionsSent     atomic.Uint64
	SessionsReceived atomic.Uint64
	SessionsInstalled atomic.Uint64
	DeletesSent      atomic.Uint64
	DeletesReceived  atomic.Uint64
	BulkSyncs        atomic.Uint64
	ConfigsSent      atomic.Uint64
	ConfigsReceived  atomic.Uint64
	IPsecSASent      atomic.Uint64
	IPsecSAReceived  atomic.Uint64
	Errors           atomic.Uint64
	Connected        atomic.Bool
}

// SessionSync manages TCP-based session state replication between cluster peers.
type SessionSync struct {
	localAddr  string // local listen address (e.g. ":4785")
	peerAddr   string // peer connect address (e.g. "10.0.0.2:4785")
	dp         dataplane.DataPlane
	stats      SyncStats
	mu         sync.Mutex
	conn       net.Conn
	listener   net.Listener
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	sendCh     chan []byte // buffered channel for outgoing messages

	// OnConfigReceived is called when a config sync message arrives from peer.
	// The callback receives the full config text. Set by the daemon before Start().
	OnConfigReceived func(configText string)

	// OnIPsecSAReceived is called when an IPsec SA list arrives from the peer.
	// On failover, the new primary calls swanctl --initiate for each connection name.
	OnIPsecSAReceived func(connectionNames []string)

	// peerIPsecSAs holds the latest IPsec connection names received from the peer.
	peerIPsecSAs   []string
	peerIPsecSAsMu sync.Mutex

	IsPrimaryFn   func() bool // returns true if local node is primary for RG 0
	lastSweepTime uint64      // monotonic seconds of last sync sweep
	vrfDevice     string      // VRF device for SO_BINDTODEVICE (empty = default VRF)
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

// SetVRFDevice sets the VRF device for SO_BINDTODEVICE on sync sockets.
func (s *SessionSync) SetVRFDevice(dev string) {
	s.vrfDevice = dev
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

// Stop gracefully shuts down session sync.
func (s *SessionSync) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	s.mu.Lock()
	if s.conn != nil {
		s.conn.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
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

func (s *SessionSync) syncSweep() {
	if s.IsPrimaryFn == nil || !s.IsPrimaryFn() {
		return
	}
	if !s.stats.Connected.Load() {
		return
	}
	if s.dp == nil {
		return
	}

	threshold := s.lastSweepTime
	now := monotonicSeconds()
	var count int

	s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Created >= threshold {
			s.QueueSessionV4(key, val)
			count++
		}
		return true
	})

	s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Created >= threshold {
			s.QueueSessionV6(key, val)
			count++
		}
		return true
	})

	s.lastSweepTime = now
	if count > 0 {
		slog.Info("cluster sync: sweep synced sessions", "count", count)
	}
}

// QueueSessionV4 queues a v4 session for sync to peer.
func (s *SessionSync) QueueSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	if !s.stats.Connected.Load() {
		return
	}
	msg := encodeSessionV4(key, val)
	select {
	case s.sendCh <- msg:
		s.stats.SessionsSent.Add(1)
	default:
		s.stats.Errors.Add(1)
	}
}

// QueueSessionV6 queues a v6 session for sync to peer.
func (s *SessionSync) QueueSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	if !s.stats.Connected.Load() {
		return
	}
	msg := encodeSessionV6(key, val)
	select {
	case s.sendCh <- msg:
		s.stats.SessionsSent.Add(1)
	default:
		s.stats.Errors.Add(1)
	}
}

// QueueDeleteV4 queues a v4 session deletion for sync.
func (s *SessionSync) QueueDeleteV4(key dataplane.SessionKey) {
	if !s.stats.Connected.Load() {
		return
	}
	msg := encodeDeleteV4(key)
	select {
	case s.sendCh <- msg:
		s.stats.DeletesSent.Add(1)
	default:
		s.stats.Errors.Add(1)
	}
}

// QueueDeleteV6 queues a v6 session deletion for sync.
func (s *SessionSync) QueueDeleteV6(key dataplane.SessionKeyV6) {
	if !s.stats.Connected.Load() {
		return
	}
	msg := encodeDeleteV6(key)
	select {
	case s.sendCh <- msg:
		s.stats.DeletesSent.Add(1)
	default:
		s.stats.Errors.Add(1)
	}
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
	if err := writeMsg(conn, syncMsgConfig, payload); err != nil {
		slog.Warn("cluster sync: config send error", "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect()
		return
	}
	s.stats.ConfigsSent.Add(1)
	slog.Info("cluster sync: config sent to peer", "size", len(payload))
}

// BulkSync sends the entire session table to the connected peer.
func (s *SessionSync) BulkSync() error {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("no peer connection")
	}

	// Send bulk start marker.
	if err := writeMsg(conn, syncMsgBulkStart, nil); err != nil {
		return err
	}

	var count int
	// Send all v4 sessions.
	err := s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		msg := encodeSessionV4Payload(key, val)
		if err := writeMsg(conn, syncMsgSessionV4, msg); err != nil {
			slog.Warn("bulk sync v4 write error", "err", err)
			return false
		}
		count++
		return true
	})
	if err != nil {
		return fmt.Errorf("bulk sync v4 iterate: %w", err)
	}

	// Send all v6 sessions.
	err = s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		msg := encodeSessionV6Payload(key, val)
		if err := writeMsg(conn, syncMsgSessionV6, msg); err != nil {
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
	if err := writeMsg(conn, syncMsgBulkEnd, nil); err != nil {
		return err
	}

	s.stats.BulkSyncs.Add(1)
	slog.Info("cluster sync: bulk sync complete", "sessions", count)
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
	}
}

func (s *SessionSync) connectLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}

		if s.stats.Connected.Load() {
			continue
		}

		dialer := net.Dialer{Timeout: 3 * time.Second}
		if s.vrfDevice != "" {
			dialer.Control = vrfListenConfig(s.vrfDevice).Control
		}
		conn, err := dialer.DialContext(ctx, "tcp", s.peerAddr)
		if err != nil {
			continue // peer not available yet
		}

		slog.Info("cluster sync: connected to peer", "addr", s.peerAddr)
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
			if _, err := conn.Write(msg); err != nil {
				slog.Debug("cluster sync: send error", "err", err)
				s.stats.Errors.Add(1)
				s.handleDisconnect()
			}
		}
	}
}

func (s *SessionSync) receiveLoop(ctx context.Context, conn net.Conn) {
	defer func() {
		s.handleDisconnect()
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
				if err := writeMsg(conn, syncMsgHeartbeat, nil); err != nil {
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
		if s.dp != nil {
			if key, val, ok := decodeSessionV4Payload(payload); ok {
				if err := s.dp.SetSessionV4(key, val); err == nil {
					s.stats.SessionsInstalled.Add(1)
				}
			}
		}

	case syncMsgSessionV6:
		s.stats.SessionsReceived.Add(1)
		if s.dp != nil {
			if key, val, ok := decodeSessionV6Payload(payload); ok {
				if err := s.dp.SetSessionV6(key, val); err == nil {
					s.stats.SessionsInstalled.Add(1)
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
			s.dp.DeleteSessionV6(key)
		}

	case syncMsgBulkStart:
		slog.Info("cluster sync: bulk transfer starting")

	case syncMsgBulkEnd:
		slog.Info("cluster sync: bulk transfer complete")

	case syncMsgHeartbeat:
		// keepalive, no action needed

	case syncMsgConfig:
		s.stats.ConfigsReceived.Add(1)
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
	}
}

func (s *SessionSync) handleDisconnect() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.stats.Connected.Store(false)
	slog.Info("cluster sync: peer disconnected")
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
	if err := writeMsg(conn, syncMsgIPsecSA, payload); err != nil {
		slog.Warn("cluster sync: IPsec SA send error", "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect()
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

func writeMsg(conn net.Conn, msgType uint8, payload []byte) error {
	hdr := make([]byte, syncHeaderSize)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = msgType
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
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
