package cluster

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// HeartbeatPort is the UDP port used for cluster heartbeat.
	HeartbeatPort = 4784

	// heartbeatMagic identifies bpfrx cluster heartbeat packets.
	heartbeatMagic = "BPFX"

	// heartbeatVersion is the current protocol version.
	heartbeatVersion = 1

	// maxHeartbeatSize is the max packet size we'll read.
	maxHeartbeatSize = 512

	// DefaultHeartbeatInterval is the default heartbeat send interval.
	DefaultHeartbeatInterval = 1000 * time.Millisecond

	// DefaultHeartbeatThreshold is the default missed heartbeat count before peer is lost.
	DefaultHeartbeatThreshold = 3
)

// HeartbeatPacket is the wire format for cluster heartbeats.
// Layout:
//
//	[0:4]   Magic "BPFX"
//	[4]     Version (1)
//	[5]     NodeID
//	[6:8]   ClusterID (little-endian uint16)
//	[8]     NumGroups
//	[9..]   Per-group entries (4 bytes each):
//	          [0] GroupID
//	          [1] Priority high byte
//	          [2] Priority low byte
//	          [3] Weight
//	          [4] State
type HeartbeatPacket struct {
	NodeID    uint8
	ClusterID uint16
	Groups    []HeartbeatGroup
}

// HeartbeatGroup is a per-RG entry in the heartbeat.
type HeartbeatGroup struct {
	GroupID  uint8
	Priority uint16
	Weight   uint8
	State    uint8
}

// heartbeatHeaderSize is Magic(4) + Version(1) + NodeID(1) + ClusterID(2) + NumGroups(1).
const heartbeatHeaderSize = 9

// heartbeatGroupSize is GroupID(1) + Priority(2) + Weight(1) + State(1).
const heartbeatGroupSize = 5

// MarshalHeartbeat encodes a heartbeat packet to wire format.
func MarshalHeartbeat(pkt *HeartbeatPacket) []byte {
	size := heartbeatHeaderSize + len(pkt.Groups)*heartbeatGroupSize
	buf := make([]byte, size)
	copy(buf[0:4], heartbeatMagic)
	buf[4] = heartbeatVersion
	buf[5] = pkt.NodeID
	binary.LittleEndian.PutUint16(buf[6:8], pkt.ClusterID)
	buf[8] = uint8(len(pkt.Groups))

	off := heartbeatHeaderSize
	for _, g := range pkt.Groups {
		buf[off] = g.GroupID
		binary.LittleEndian.PutUint16(buf[off+1:off+3], g.Priority)
		buf[off+3] = g.Weight
		buf[off+4] = g.State
		off += heartbeatGroupSize
	}
	return buf
}

// UnmarshalHeartbeat decodes a heartbeat packet from wire format.
func UnmarshalHeartbeat(data []byte) (*HeartbeatPacket, error) {
	if len(data) < heartbeatHeaderSize {
		return nil, fmt.Errorf("heartbeat too short: %d bytes", len(data))
	}
	if string(data[0:4]) != heartbeatMagic {
		return nil, fmt.Errorf("invalid heartbeat magic: %q", string(data[0:4]))
	}
	if data[4] != heartbeatVersion {
		return nil, fmt.Errorf("unsupported heartbeat version: %d", data[4])
	}

	pkt := &HeartbeatPacket{
		NodeID:    data[5],
		ClusterID: binary.LittleEndian.Uint16(data[6:8]),
	}

	numGroups := int(data[8])
	need := heartbeatHeaderSize + numGroups*heartbeatGroupSize
	if len(data) < need {
		return nil, fmt.Errorf("heartbeat truncated: have %d, need %d", len(data), need)
	}

	pkt.Groups = make([]HeartbeatGroup, numGroups)
	off := heartbeatHeaderSize
	for i := 0; i < numGroups; i++ {
		pkt.Groups[i] = HeartbeatGroup{
			GroupID:  data[off],
			Priority: binary.LittleEndian.Uint16(data[off+1 : off+3]),
			Weight:   data[off+3],
			State:    data[off+4],
		}
		off += heartbeatGroupSize
	}
	return pkt, nil
}

// PeerGroupState holds the last-known state of a peer's redundancy group.
type PeerGroupState struct {
	GroupID  int
	Priority int
	Weight   int
	State    NodeState
}

// heartbeatSender sends periodic heartbeat packets.
type heartbeatSender struct {
	mgr      *Manager
	conn     *net.UDPConn
	peerAddr *net.UDPAddr
	interval time.Duration
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// heartbeatReceiver listens for peer heartbeat packets.
type heartbeatReceiver struct {
	mgr       *Manager
	conn      *net.UDPConn
	threshold int
	interval  time.Duration
	stopCh    chan struct{}
	wg        sync.WaitGroup
	lastSeen  atomic.Int64 // unix nano of last heartbeat
}

func newHeartbeatSender(mgr *Manager, conn *net.UDPConn, peerAddr *net.UDPAddr, interval time.Duration) *heartbeatSender {
	return &heartbeatSender{
		mgr:      mgr,
		conn:     conn,
		peerAddr: peerAddr,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (s *heartbeatSender) start() {
	s.wg.Add(1)
	go s.run()
}

func (s *heartbeatSender) run() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.send()
		}
	}
}

func (s *heartbeatSender) send() {
	pkt := s.mgr.buildHeartbeat()
	data := MarshalHeartbeat(pkt)
	if _, err := s.conn.WriteToUDP(data, s.peerAddr); err != nil {
		slog.Debug("cluster: heartbeat send failed", "err", err)
	}
}

func (s *heartbeatSender) stop() {
	close(s.stopCh)
	s.wg.Wait()
}

func newHeartbeatReceiver(mgr *Manager, conn *net.UDPConn, threshold int, interval time.Duration) *heartbeatReceiver {
	r := &heartbeatReceiver{
		mgr:       mgr,
		conn:      conn,
		threshold: threshold,
		interval:  interval,
		stopCh:    make(chan struct{}),
	}
	return r
}

func (r *heartbeatReceiver) start() {
	r.wg.Add(2)
	go r.readLoop()
	go r.timeoutLoop()
}

func (r *heartbeatReceiver) readLoop() {
	defer r.wg.Done()
	buf := make([]byte, maxHeartbeatSize)

	for {
		select {
		case <-r.stopCh:
			return
		default:
		}

		r.conn.SetReadDeadline(time.Now().Add(r.interval))
		n, _, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-r.stopCh:
				return
			default:
				slog.Debug("cluster: heartbeat read error", "err", err)
				continue
			}
		}

		pkt, err := UnmarshalHeartbeat(buf[:n])
		if err != nil {
			slog.Warn("cluster: invalid heartbeat", "err", err)
			continue
		}

		// Validate cluster ID.
		if int(pkt.ClusterID) != r.mgr.ClusterID() {
			slog.Warn("cluster: heartbeat from wrong cluster",
				"got", pkt.ClusterID, "want", r.mgr.ClusterID())
			continue
		}

		// Ignore our own heartbeats (shouldn't happen with unicast, but be safe).
		if int(pkt.NodeID) == r.mgr.NodeID() {
			continue
		}

		r.lastSeen.Store(time.Now().UnixNano())
		r.mgr.handlePeerHeartbeat(pkt)
	}
}

func (r *heartbeatReceiver) timeoutLoop() {
	defer r.wg.Done()
	timeout := time.Duration(r.threshold) * r.interval
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			lastNano := r.lastSeen.Load()
			if lastNano == 0 {
				// No heartbeat ever received — check if we've been running
				// long enough to declare peer lost.
				continue
			}
			last := time.Unix(0, lastNano)
			if time.Since(last) > timeout {
				r.mgr.handlePeerTimeout()
			}
		}
	}
}

func (r *heartbeatReceiver) stop() {
	close(r.stopCh)
	r.conn.Close()
	r.wg.Wait()
}
