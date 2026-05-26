package cluster

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// StartHeartbeat launches heartbeat sender and receiver goroutines.
// localAddr is the local control link IP, peerAddr is the peer control link IP.
// vrfDevice is optional — if non-empty, sockets bind to that VRF device so
// packets route through the correct table.
func (m *Manager) StartHeartbeat(localAddr, peerAddr, vrfDevice string) error {
	m.mu.Lock()
	interval := m.hbInterval
	threshold := m.hbThreshold
	m.mu.Unlock()

	// Resolve peer address.
	peer, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", peerAddr, HeartbeatPort))
	if err != nil {
		return fmt.Errorf("resolve peer addr: %w", err)
	}

	// Bind receiver to local address.
	local, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", localAddr, HeartbeatPort))
	if err != nil {
		return fmt.Errorf("resolve local addr: %w", err)
	}

	lc := vrfListenConfig(vrfDevice)

	recvPkt, err := lc.ListenPacket(context.Background(), "udp4", local.String())
	if err != nil {
		return fmt.Errorf("listen heartbeat: %w", err)
	}
	recvConn := recvPkt.(*net.UDPConn)

	// Create sender socket (bound to local address).
	sendAddr := fmt.Sprintf("%s:0", localAddr)
	sendPkt, err := lc.ListenPacket(context.Background(), "udp4", sendAddr)
	if err != nil {
		recvConn.Close()
		return fmt.Errorf("sender socket: %w", err)
	}
	sendConn := sendPkt.(*net.UDPConn)

	m.mu.Lock()
	m.hbSender = newHeartbeatSender(m, sendConn, peer, interval)
	m.hbReceiver = newHeartbeatReceiver(m, recvConn, threshold, interval)
	m.hbLocalAddr = localAddr
	m.hbPeerAddr = peerAddr
	m.hbVRFDevice = vrfDevice
	m.mu.Unlock()

	m.hbReceiver.start()
	m.hbSender.start()

	slog.Info("cluster: heartbeat started",
		"local", localAddr, "peer", peerAddr,
		"interval", interval, "threshold", threshold)
	return nil
}

// vrfListenConfig returns a net.ListenConfig that binds sockets to a VRF device
// via SO_BINDTODEVICE with SO_REUSEADDR+SO_REUSEPORT to allow immediate rebind
// after a restart (even if old sockets linger from a killed process).
// If vrfDevice is empty, only SO_REUSEADDR+SO_REUSEPORT are set.
func vrfListenConfig(vrfDevice string) net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				// Allow immediate rebind after restart — the kernel may
				// still hold the old socket briefly after process death.
				_ = unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET,
					unix.SO_REUSEADDR, 1)
				_ = unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET,
					unix.SO_REUSEPORT, 1)
				if vrfDevice != "" {
					err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET,
						syscall.SO_BINDTODEVICE, vrfDevice)
				}
			})
			return err
		},
	}
}

// StopHeartbeat halts heartbeat sender and receiver goroutines.
func (m *Manager) StopHeartbeat() {
	m.mu.Lock()
	sender := m.hbSender
	receiver := m.hbReceiver
	m.hbSender = nil
	m.hbReceiver = nil
	m.mu.Unlock()

	if sender != nil {
		sender.stop()
	}
	if receiver != nil {
		receiver.stop()
	}
}

// RestartHeartbeat stops and restarts the heartbeat with the same parameters.
// This is needed when the control interface's VRF binding changes (e.g. during
// DHCP-triggered recompile) which invalidates the existing UDP sockets.
// Retries up to 5 times with 1s delay if the bind fails (address may briefly
// disappear during VRF rebind). Returns false if heartbeat was not running.
func (m *Manager) RestartHeartbeat() bool {
	m.mu.RLock()
	running := m.hbSender != nil || m.hbReceiver != nil
	localAddr := m.hbLocalAddr
	peerAddr := m.hbPeerAddr
	vrfDevice := m.hbVRFDevice
	m.mu.RUnlock()

	if !running || localAddr == "" {
		return false
	}

	slog.Info("cluster: restarting heartbeat after VRF rebind",
		"local", localAddr, "peer", peerAddr, "vrf", vrfDevice)

	m.StopHeartbeat()

	for i := 0; i < 5; i++ {
		if err := m.StartHeartbeat(localAddr, peerAddr, vrfDevice); err != nil {
			slog.Warn("cluster: heartbeat restart bind failed, retrying",
				"err", err, "attempt", i+1)
			time.Sleep(1 * time.Second)
			continue
		}
		return true
	}
	slog.Error("cluster: heartbeat restart failed after retries")
	return false
}

// buildHeartbeat creates a heartbeat packet from current state.
func (m *Manager) buildHeartbeat() *HeartbeatPacket {
	m.mu.RLock()
	mon := m.monitor
	m.mu.RUnlock()

	// Collect local interface statuses outside the lock (monitor has its own).
	var localStatuses []InterfaceMonitorInfo
	if mon != nil {
		localStatuses = mon.LocalInterfaceStatuses()
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	pkt := &HeartbeatPacket{
		NodeID:            uint8(m.nodeID),
		ClusterID:         uint16(m.clusterID),
		SoftwareVersion:   m.localSoftwareVersion,
		HAProtocolVersion: m.localHAProtocolVersion,
	}
	for _, rg := range m.groups {
		pkt.Groups = append(pkt.Groups, HeartbeatGroup{
			GroupID:  uint8(rg.GroupID),
			Priority: uint16(rg.LocalPriority),
			Weight:   uint8(rg.Weight),
			State:    uint8(rg.State),
		})
	}

	// Include local interface monitor statuses.
	for _, ls := range localStatuses {
		pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{
			RGID:      uint8(ls.RedundancyGroup),
			Weight:    uint8(ls.Weight),
			Up:        ls.Up,
			Interface: ls.Interface,
		})
	}
	return pkt
}

// handlePeerHeartbeat processes an incoming peer heartbeat.
func (m *Manager) handlePeerHeartbeat(pkt *HeartbeatPacket) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()

	wasAlive := m.peerAlive
	m.peerAlive = true
	m.peerEverSeen = true
	m.peerNodeID = int(pkt.NodeID)
	m.peerSoftwareVersion = pkt.SoftwareVersion
	m.peerHAProtocolVersion = normalizeHAProtocolVersion(pkt.HAProtocolVersion)

	// Rebuild peer group states from scratch — prunes stale RGs that
	// the peer no longer reports (fix #92).
	newPeerGroups := make(map[int]PeerGroupState, len(pkt.Groups))
	for _, g := range pkt.Groups {
		newPeerGroups[int(g.GroupID)] = PeerGroupState{
			GroupID:  int(g.GroupID),
			Priority: int(g.Priority),
			Weight:   int(g.Weight),
			State:    NodeState(g.State),
		}
	}
	// Apply pending transfer-commit overrides + expire transfer-grace
	// windows. The body is owned by failover.go so that the entire
	// transfer-commit state machine (override map + grace windows +
	// expiry) lives in a single file alongside
	// commitRequestedPeerFailover / notePeerTransferCommitted /
	// FinalizePeerTransferOut. handlePeerHeartbeat is just the caller
	// — heartbeat orchestration does not own transfer-commit state.
	m.applyTransferCommitOverridesOnPeerStateLocked(newPeerGroups, now)
	m.peerGroups = newPeerGroups

	// Update peer interface monitor statuses.
	if len(pkt.Monitors) > 0 {
		m.peerMonitors = make([]InterfaceMonitorInfo, len(pkt.Monitors))
		for i, mon := range pkt.Monitors {
			m.peerMonitors[i] = InterfaceMonitorInfo{
				Interface:       mon.Interface,
				Weight:          int(mon.Weight),
				Up:              mon.Up,
				RedundancyGroup: int(mon.RGID),
			}
		}
	} else {
		m.peerMonitors = nil
	}

	// Update PeerPriority on local RG state for display.
	for _, rg := range m.groups {
		if pg, ok := m.peerGroups[rg.GroupID]; ok {
			rg.PeerPriority = pg.Priority
		}
	}

	if !wasAlive {
		slog.Info("cluster: peer heartbeat received",
			"peer_node", pkt.NodeID, "groups", len(pkt.Groups))
		m.history.Record(EventHeartbeat, -1, fmt.Sprintf("Peer alive (node%d)", pkt.NodeID))
	}

	m.runElection()
}

// handlePeerTimeout is called when the peer heartbeat timeout expires.
func (m *Manager) handlePeerTimeout() {
	m.mu.Lock()
	if !m.peerAlive {
		m.mu.Unlock()
		return // already marked lost
	}
	if suppress, reason := m.suppressPeerTimeoutForTransferCommitLocked(time.Now()); suppress {
		m.mu.Unlock()
		slog.Debug("cluster: suppressing peer heartbeat timeout", "reason", reason)
		return
	}
	guard := m.peerTimeoutGuardFn
	m.mu.Unlock()

	if guard != nil {
		if suppress, reason := guard(); suppress {
			slog.Debug("cluster: suppressing peer heartbeat timeout", "reason", reason)
			return
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.peerAlive {
		return // already marked lost while guard ran
	}
	if suppress, reason := m.suppressPeerTimeoutForTransferCommitLocked(time.Now()); suppress {
		slog.Debug("cluster: suppressing peer heartbeat timeout", "reason", reason)
		return
	}

	m.peerAlive = false
	m.peerGroups = make(map[int]PeerGroupState)
	m.peerMonitors = nil
	m.peerSoftwareVersion = ""
	m.peerHAProtocolVersion = 0
	slog.Warn("cluster: peer heartbeat timeout, marking peer lost")
	m.history.Record(EventHeartbeat, -1, "Peer heartbeat timeout")

	// Clear ManualFailover on all RGs: the peer is dead, so the surviving
	// node MUST be able to take over. Without this, a previous manual
	// transfer-out would keep the local node parked in secondary-hold even
	// though there is no longer a peer to hand ownership to.
	for _, rg := range m.groups {
		if rg.ManualFailover {
			slog.Info("cluster: clearing manual failover (peer lost)", "rg", rg.GroupID)
			rg.ManualFailover = false
			rg.ManualFailoverAt = time.Time{}
			m.recalcWeight(rg)
		}
	}

	// Peer lost: re-run single-node election.
	m.electSingleNode()

	// Attempt peer fencing if configured.
	if m.peerFencing == "disable-rg" {
		fn := m.peerFenceFn
		if fn != nil {
			// Release lock for the network call.
			m.mu.Unlock()
			err := fn()
			m.mu.Lock()
			if err != nil {
				slog.Warn("cluster: fence: peer unreachable, relying on heartbeat-driven failover", "err", err)
				m.history.Record(EventFence, -1, fmt.Sprintf("Fence failed: %v", err))
			} else {
				slog.Info("cluster: fence: disable-rg sent to peer")
				m.history.Record(EventFence, -1, "Fence disable-rg sent to peer")
			}
		} else {
			slog.Warn("cluster: fence: sync not available, peer unreachable")
			m.history.Record(EventFence, -1, "Fence skipped: sync not available")
		}
	}
}

// handlePeerNeverSeen is called when the heartbeat timeout expires and no
// peer heartbeat has ever been received. This confirms the peer is truly
// absent (not just a fresh boot race). Sets peerEverSeen so non-preempt
// nodes can claim primary via electSingleNode.
func (m *Manager) handlePeerNeverSeen() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.peerEverSeen {
		return // already handled
	}
	m.peerEverSeen = true // no longer "never seen" — now "confirmed absent"
	slog.Info("cluster: peer never seen after heartbeat timeout, proceeding with election")
	m.history.Record(EventHeartbeat, -1, "Peer never seen (timeout)")
	m.electSingleNode()
}

// HeartbeatStats returns current heartbeat counters.
func (m *Manager) HeartbeatStats() HeartbeatStats {
	m.mu.RLock()
	sender := m.hbSender
	receiver := m.hbReceiver
	m.mu.RUnlock()

	var s HeartbeatStats
	if sender != nil {
		s.Sent = sender.sent.Load()
		s.SendErrors = sender.sendErrors.Load()
	}
	if receiver != nil {
		s.Received = receiver.received.Load()
		s.RecvErrors = receiver.recvErrors.Load()
	}
	return s
}

// HeartbeatStats holds heartbeat send/receive counters.
type HeartbeatStats struct {
	Sent       uint64
	Received   uint64
	SendErrors uint64
	RecvErrors uint64
}
