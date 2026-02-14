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
	"sync"
	"sync/atomic"
	"time"

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
	DeletesSent      atomic.Uint64
	DeletesReceived  atomic.Uint64
	BulkSyncs        atomic.Uint64
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

// Stats returns current sync statistics.
func (s *SessionSync) Stats() SyncStats {
	return s.stats
}

// Start begins the sync protocol (listener + connector).
func (s *SessionSync) Start(ctx context.Context) error {
	ctx, s.cancel = context.WithCancel(ctx)

	// Start listener for incoming peer connections.
	ln, err := net.Listen("tcp", s.localAddr)
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

		conn, err := net.DialTimeout("tcp", s.peerAddr, 3*time.Second)
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
			if hdr.Length > 1024*1024 { // 1MB sanity limit
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
	if s.dp == nil {
		return
	}

	switch msgType {
	case syncMsgSessionV4:
		s.stats.SessionsReceived.Add(1)
		// Decode and install session - for now just count.
		// Full implementation would call dp.SetSession() (needs interface extension).
		slog.Debug("cluster sync: received v4 session")

	case syncMsgSessionV6:
		s.stats.SessionsReceived.Add(1)
		slog.Debug("cluster sync: received v6 session")

	case syncMsgDeleteV4:
		s.stats.DeletesReceived.Add(1)
		if len(payload) >= 16 {
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
		if len(payload) >= 40 {
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
			"  Deletes sent:       %d\n"+
			"  Deletes received:   %d\n"+
			"  Bulk syncs:         %d\n"+
			"  Errors:             %d\n",
		s.stats.Connected.Load(),
		s.stats.SessionsSent.Load(),
		s.stats.SessionsReceived.Load(),
		s.stats.DeletesSent.Load(),
		s.stats.DeletesReceived.Load(),
		s.stats.BulkSyncs.Load(),
		s.stats.Errors.Load(),
	)
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
