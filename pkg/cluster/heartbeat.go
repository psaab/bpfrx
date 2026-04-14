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

	// heartbeatMagic identifies xpf cluster heartbeat packets.
	heartbeatMagic = "BPFX"

	// heartbeatVersion is the current protocol version.
	heartbeatVersion = 1

	// LegacyHAProtocolVersion is the compatibility version implicitly used by
	// older heartbeats that predate explicit HA protocol advertisement.
	LegacyHAProtocolVersion uint16 = 1

	// CurrentHAProtocolVersion is the HA/session-transfer compatibility version
	// used to decide whether mixed software builds can still hand off RGs. Bump
	// this only when heartbeat/session-sync/failover wire semantics change in a
	// way that breaks mixed-version interoperability.
	CurrentHAProtocolVersion = LegacyHAProtocolVersion

	// maxHeartbeatSize is the max packet size we'll read/write.
	// 1472 = 1500 MTU - 20 IP header - 8 UDP header.
	maxHeartbeatSize = 1472

	// DefaultHeartbeatInterval is the default heartbeat send interval.
	DefaultHeartbeatInterval = 100 * time.Millisecond

	// DefaultHeartbeatThreshold is the default missed heartbeat count before peer is lost.
	DefaultHeartbeatThreshold = 5
)

// HeartbeatPacket is the wire format for cluster heartbeats.
// Layout:
//
//	[0:4]   Magic "BPFX"
//	[4]     Version (1)
//	[5]     NodeID
//	[6:8]   ClusterID (little-endian uint16)
//	[8]     NumGroups
//	[9..]   Per-group entries (5 bytes each):
//	          [0] GroupID
//	          [1:3] Priority (little-endian uint16)
//	          [3] Weight
//	          [4] State
//	After groups:
//	  NumMonitors (1 byte)
//	  Per-monitor:
//	    [0] RGID
//	    [1] Flags (bit0=up)
//	    [2] Weight
//	    [3] NameLen
//	    [4..4+NameLen] Interface name
//	After monitors:
//	  Optional VersionTrailer:
//	    [0] VersionLen
//	    [1..1+VersionLen] SoftwareVersion bytes
//	    [..] uint16 little-endian HAProtocolVersion
//
// The trailing version trailer is optional; packets may end after the monitor
// section. When present, the trailer always starts with a length byte, even if
// the software version string is empty, so newer readers can unambiguously find
// the HA protocol version. Older readers ignore any bytes after the optional
// software-version field, and newer readers treat a missing trailer as the
// legacy protocol version.
type HeartbeatPacket struct {
	NodeID            uint8
	ClusterID         uint16
	Groups            []HeartbeatGroup
	Monitors          []HeartbeatMonitor
	SoftwareVersion   string
	HAProtocolVersion uint16
}

// HeartbeatGroup is a per-RG entry in the heartbeat.
type HeartbeatGroup struct {
	GroupID  uint8
	Priority uint16
	Weight   uint8
	State    uint8
}

// HeartbeatMonitor is a per-interface monitor entry in the heartbeat.
type HeartbeatMonitor struct {
	RGID      uint8
	Weight    uint8
	Up        bool
	Interface string
}

// heartbeatHeaderSize is Magic(4) + Version(1) + NodeID(1) + ClusterID(2) + NumGroups(1).
const heartbeatHeaderSize = 9

// heartbeatGroupSize is GroupID(1) + Priority(2) + Weight(1) + State(1).
const heartbeatGroupSize = 5

const maxHeartbeatSoftwareVersionSize = 255

func normalizeHAProtocolVersion(version uint16) uint16 {
	if version == 0 {
		return LegacyHAProtocolVersion
	}
	return version
}

// MarshalHeartbeat encodes a heartbeat packet to wire format.
// The output is capped at maxHeartbeatSize. RG group entries are always
// included (they are critical for election). When SoftwareVersion is present,
// space for it is reserved first so monitor truncation never drops version
// metadata. If monitors would cause the packet to exceed the limit, the monitor
// section is truncated and the version field is preserved.
func MarshalHeartbeat(pkt *HeartbeatPacket) []byte {
	buf := make([]byte, maxHeartbeatSize)
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

	var version []byte
	const heartbeatVersionTrailerSize = 1 + 2 // version length byte + HA protocol version
	versionReserve := heartbeatVersionTrailerSize
	if pkt.SoftwareVersion != "" {
		version = []byte(pkt.SoftwareVersion)
		if len(version) > maxHeartbeatSoftwareVersionSize {
			version = version[:maxHeartbeatSoftwareVersionSize]
		}
		if off+heartbeatVersionTrailerSize+len(version) <= maxHeartbeatSize {
			versionReserve = heartbeatVersionTrailerSize + len(version)
		} else {
			version = nil
		}
	}

	// Append monitor section, fitting as many monitors as possible.
	monCountOff := off // remember offset of NumMonitors byte
	buf[off] = 0       // NumMonitors — updated below
	off++
	numMon := 0
	for _, mon := range pkt.Monitors {
		nameBytes := []byte(mon.Interface)
		entrySize := 4 + len(nameBytes) // RGID + Flags + Weight + NameLen + name
		if off+entrySize > maxHeartbeatSize-versionReserve {
			break
		}
		buf[off] = mon.RGID
		flags := uint8(0)
		if mon.Up {
			flags |= 1
		}
		buf[off+1] = flags
		buf[off+2] = mon.Weight
		buf[off+3] = uint8(len(nameBytes))
		off += 4
		copy(buf[off:off+len(nameBytes)], nameBytes)
		off += len(nameBytes)
		numMon++
	}
	buf[monCountOff] = uint8(numMon)
	if off+versionReserve <= maxHeartbeatSize {
		buf[off] = uint8(len(version))
		off++
		if len(version) > 0 {
			copy(buf[off:off+len(version)], version)
			off += len(version)
		}
		binary.LittleEndian.PutUint16(buf[off:off+2], normalizeHAProtocolVersion(pkt.HAProtocolVersion))
		off += 2
	}
	return buf[:off]
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
		NodeID:            data[5],
		ClusterID:         binary.LittleEndian.Uint16(data[6:8]),
		HAProtocolVersion: LegacyHAProtocolVersion,
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

	// Parse monitor section if present (backwards compatible — old packets
	// without monitors just have no remaining data). If the monitor section
	// is truncated (sender capped at maxHeartbeatSize), return whatever
	// monitors were successfully parsed rather than erroring — RG state
	// (already parsed above) is the critical data.
	monitorSectionComplete := true
	if off < len(data) {
		numMonitors := int(data[off])
		off++
		for i := 0; i < numMonitors; i++ {
			if off+4 > len(data) {
				monitorSectionComplete = false
				break // truncated — return what we have
			}
			rgID := data[off]
			up := data[off+1]&1 != 0
			weight := data[off+2]
			nameLen := int(data[off+3])
			off += 4
			if off+nameLen > len(data) {
				monitorSectionComplete = false
				break // truncated name — return what we have
			}
			name := string(data[off : off+nameLen])
			off += nameLen
			pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{
				RGID:      rgID,
				Weight:    weight,
				Up:        up,
				Interface: name,
			})
		}
	}
	versionSectionComplete := false
	if monitorSectionComplete && off < len(data) {
		versionLen := int(data[off])
		off++
		if off+versionLen <= len(data) {
			pkt.SoftwareVersion = string(data[off : off+versionLen])
			off += versionLen
			versionSectionComplete = true
		} else {
			return pkt, nil
		}
	}
	if monitorSectionComplete && versionSectionComplete && off+2 <= len(data) {
		pkt.HAProtocolVersion = normalizeHAProtocolVersion(binary.LittleEndian.Uint16(data[off : off+2]))
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
	mgr        *Manager
	conn       *net.UDPConn
	peerAddr   *net.UDPAddr
	interval   time.Duration
	stopCh     chan struct{}
	wg         sync.WaitGroup
	sent       atomic.Uint64
	sendErrors atomic.Uint64
}

// heartbeatReceiver listens for peer heartbeat packets.
type heartbeatReceiver struct {
	mgr        *Manager
	conn       *net.UDPConn
	threshold  int
	interval   time.Duration
	stopCh     chan struct{}
	wg         sync.WaitGroup
	lastSeen   atomic.Int64 // unix nano of last heartbeat
	received   atomic.Uint64
	recvErrors atomic.Uint64
	startedAt  time.Time // when receiver started (for initial peer-lost detection)
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
		s.sendErrors.Add(1)
		slog.Debug("cluster: heartbeat send failed", "err", err)
	} else {
		s.sent.Add(1)
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
	r.startedAt = time.Now()
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
			r.recvErrors.Add(1)
			slog.Warn("cluster: invalid heartbeat", "err", err)
			continue
		}

		// Validate cluster ID.
		if int(pkt.ClusterID) != r.mgr.ClusterID() {
			r.recvErrors.Add(1)
			slog.Warn("cluster: heartbeat from wrong cluster",
				"got", pkt.ClusterID, "want", r.mgr.ClusterID())
			continue
		}

		// Ignore our own heartbeats (shouldn't happen with unicast, but be safe).
		if int(pkt.NodeID) == r.mgr.NodeID() {
			continue
		}

		r.received.Add(1)
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
				// No heartbeat ever received. Once we've waited the full
				// timeout, declare peer absent so the election can proceed
				// (non-preempt nodes start as secondary and need this to
				// take primary when the peer is truly down).
				if time.Since(r.startedAt) > timeout {
					r.mgr.handlePeerNeverSeen()
				}
				continue
			}
			last := time.Unix(0, lastNano)
			// During the first 30 seconds after startup, suppress
			// peer-lost entirely. The config apply phase (VRF binding,
			// FRR reload, fabric creation, RETH MAC) can disrupt the
			// UDP receive path on the control link for 10-15+ seconds.
			// Without this grace, the recovering node sees one peer
			// heartbeat then declares peer lost — creating split-brain.
			if time.Since(r.startedAt) < 30*time.Second {
				continue
			}
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
