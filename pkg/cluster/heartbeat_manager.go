package cluster

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ErrHeartbeatStartSuperseded reports that a StartHeartbeat was overtaken by a
// StopHeartbeat while it was creating its sockets, so it declined to publish
// (#7257). It is a lifecycle outcome, not a failure: the caller asked for a
// heartbeat that the cluster has since torn down. A bind-retry loop must treat
// it as terminal — retrying would race the same teardown again, and on success
// would resurrect a heartbeat the teardown exists to remove.
var ErrHeartbeatStartSuperseded = errors.New("cluster: heartbeat start superseded by teardown")

// heartbeatUDPNetwork returns the UDP network string ("udp4" or "udp6") for a
// literal control-link IP so the heartbeat sockets follow the configured
// address family. A v4 (or v4-mapped) literal yields "udp4"; a v6 literal
// yields "udp6". An address that is not a parseable literal falls back to
// "udp4" — the historical default — so a malformed value fails the same way
// it always did. The daemon may hand StartHeartbeat an IPv6 control-link
// address (selectClusterBindAddr honours an IPv6 peer via
// globalIPv6Candidates), so hardcoding "udp4" made an IPv6 control link
// unusable (#4549 F9); deriving the family here keeps v4 bit-identical while
// letting a v6 control link bind.
func heartbeatUDPNetwork(addr string) string {
	if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
		return "udp6"
	}
	return "udp4"
}

// StartHeartbeat launches heartbeat sender and receiver goroutines.
// localAddr is the local control link IP, peerAddr is the peer control link IP.
// vrfDevice is optional — if non-empty, sockets bind to that VRF device so
// packets route through the correct table.
//
// StartHeartbeat is idempotent: a heartbeat that is already running is torn
// down (cancel + join) BEFORE the new sender/receiver are installed, so
// exactly one heartbeat goroutine set exists at a time. Without this a second
// StartHeartbeat (e.g. a comms restart, or the daemon's bind-retry goroutine
// racing RestartHeartbeat) would overwrite m.hbSender/m.hbReceiver and leak
// the previous goroutines — their stopCh is never closed, so N restarts leak
// N heartbeat goroutines and duplicate the on-wire heartbeat rate (#4033).
func (m *Manager) StartHeartbeat(localAddr, peerAddr, vrfDevice string) error {
	// Serialize the whole stop-previous + create + install sequence so
	// concurrent callers cannot interleave and both install a heartbeat.
	// hbStartMu is distinct from m.mu: StopHeartbeat below takes m.mu and
	// joins goroutines that also take m.mu.
	m.hbStartMu.Lock()
	defer m.hbStartMu.Unlock()

	// Stop any heartbeat that is already running before installing a new one.
	// Safe to call unconditionally — it is a no-op when nothing is running.
	m.StopHeartbeat()

	// #7257: the lifecycle tenure this start belongs to.
	//
	// Captured HERE, deliberately — after the #4033 idempotent teardown above,
	// not at function entry. That teardown is a StopHeartbeat, so it bumps
	// hbEpoch too; an entry-time capture would compare against a value this
	// call had itself invalidated and every start would refuse to publish.
	// The window that actually needs guarding is exactly the one that opens
	// now: socket creation is unbounded in time (two binds, possibly against a
	// VRF that is still settling), and an EXTERNAL StopHeartbeat landing in it
	// must supersede us.
	m.mu.RLock()
	startEpoch := m.hbEpoch
	hook := m.hbStartInWindowHook
	m.mu.RUnlock()
	// Test seam: land a concurrent teardown inside the guarded window. nil in
	// production. Called with no lock held — the hook takes m.mu itself.
	if hook != nil {
		hook()
	}

	m.mu.Lock()
	interval := m.hbInterval
	threshold := m.hbThreshold
	m.mu.Unlock()

	// #6169: kick this node's boot-epoch resolution. This MUST NOT BLOCK —
	// StopHeartbeat() above has already torn the heartbeat down, so any wait
	// here is a window with no frames going out at all, which a peer cannot
	// tell apart from a dead node. An earlier revision waited up to 2s for the
	// persisted value and measured 2.005s/2.012s/2.011s against a 500ms
	// dead-peer threshold under a wedged store. It buys nothing now: the
	// wall-clock epoch is published synchronously before any I/O, so the frame
	// already carries one and persistence catches up off-path.
	m.initHeartbeatEpochState()

	// Select the UDP network from the control-link address family so a v6
	// control link binds; v4 stays "udp4". net.JoinHostPort brackets a v6
	// literal (fd00::1 -> [fd00::1]:port) — plain "%s:%d" would produce an
	// unparseable address for IPv6.
	network := heartbeatUDPNetwork(localAddr)
	portStr := strconv.Itoa(HeartbeatPort)

	// Resolve peer address.
	peer, err := net.ResolveUDPAddr(network, net.JoinHostPort(peerAddr, portStr))
	if err != nil {
		return fmt.Errorf("resolve peer addr: %w", err)
	}

	// Bind receiver to local address.
	local, err := net.ResolveUDPAddr(network, net.JoinHostPort(localAddr, portStr))
	if err != nil {
		return fmt.Errorf("resolve local addr: %w", err)
	}

	lc := vrfListenConfig(vrfDevice)

	recvPkt, err := lc.ListenPacket(context.Background(), network, local.String())
	if err != nil {
		return fmt.Errorf("listen heartbeat: %w", err)
	}
	recvConn := recvPkt.(*net.UDPConn)

	// Create sender socket (bound to local address).
	sendAddr := net.JoinHostPort(localAddr, "0")
	sendPkt, err := lc.ListenPacket(context.Background(), network, sendAddr)
	if err != nil {
		recvConn.Close()
		return fmt.Errorf("sender socket: %w", err)
	}
	sendConn := sendPkt.(*net.UDPConn)

	m.mu.Lock()
	// #7257: refuse a start that a teardown superseded. StopHeartbeat bumps
	// hbEpoch under this same lock, so comparing the entry epoch HERE — in the
	// critical section that publishes — makes "was I superseded?" and "publish"
	// atomic with respect to it. Socket creation above is unbounded in time (two
	// binds, possibly against a VRF that is still settling), so a stop landing in
	// that gap is not theoretical.
	if m.hbEpoch != startEpoch {
		m.mu.Unlock()
		recvConn.Close()
		sendConn.Close()
		slog.Info("cluster: heartbeat start superseded by a teardown, not publishing",
			"local", localAddr, "peer", peerAddr)
		return ErrHeartbeatStartSuperseded
	}
	sender := newHeartbeatSender(m, sendConn, peer, interval)
	receiver := newHeartbeatReceiver(m, recvConn, threshold, interval)
	m.hbSender = sender
	m.hbReceiver = receiver
	m.hbLocalAddr = localAddr
	m.hbPeerAddr = peerAddr
	m.hbVRFDevice = vrfDevice
	// Start the LOCALS, and start them INSIDE the critical section (#7257).
	// Locals because the pre-#7257 code re-read m.hbReceiver/m.hbSender after
	// unlocking, which raced StopHeartbeat nilling them — a nil-deref panic if
	// the stop won. Inside because publishing and starting must be one step: a
	// stop that interleaves between them would capture the handles and stop
	// goroutines that had not been spawned yet, and the spawns would then run
	// with nothing able to stop them. start() only spawns (`go run()` /
	// `go readLoop()` + `go timeoutLoop()`), so it cannot block on this lock.
	receiver.start()
	sender.start()
	m.mu.Unlock()

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

// HeartbeatRunning reports whether a heartbeat sender or receiver is currently
// installed. Used by status reporting and to assert the idempotent
// start/stop discipline (#4033).
func (m *Manager) HeartbeatRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.hbSender != nil || m.hbReceiver != nil
}

// StopHeartbeat halts heartbeat sender and receiver goroutines.
func (m *Manager) StopHeartbeat() {
	m.mu.Lock()
	sender := m.hbSender
	receiver := m.hbReceiver
	m.hbSender = nil
	m.hbReceiver = nil
	// #7257: supersede any StartHeartbeat that is mid-flight. It captured the
	// previous epoch on entry and compares it under this lock before publishing,
	// so from here on it cannot install a pair this Stop would never see.
	// RestartHeartbeat is unaffected: it stops first, and the StartHeartbeat it
	// then calls captures the POST-bump epoch on its own entry.
	m.hbEpoch++
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
//
// The restart window (worst case ~5s of bind retries) is longer than the
// peer's default timeout (5 x 100ms), so two protections wrap it (#1792):
//
//   - Peer side: hbRestartNotifyFn fires before teardown and after each
//     failed bind retry. The daemon wires it to
//     SessionSync.SendLivenessKeepalive, which refreshes the peer's
//     LastPeerReceiveAge — the signal its heartbeat-timeout suppression
//     guard (shouldSuppressPeerHeartbeatTimeout, 2s recency window) checks
//     before fencing/electing. Suppression on the peer is bounded by its
//     existing 5s continuous-suppression cap and self-clearing (it derives
//     purely from message recency — no sticky state), so a node that dies
//     mid-restart still fails over.
//
//   - Local side: lastSeen carries over to the replacement receiver (same
//     CLOCK_MONOTONIC domain, same process) so a peer that dies while our
//     sockets are down is still detected once the post-restart 30s startup
//     grace expires. Without the seed the new receiver starts at
//     lastSeen=0, whose timeout path only invokes handlePeerNeverSeen — a
//     no-op once peerEverSeen is set — and a peer death during the restart
//     window would never be detected.
func (m *Manager) RestartHeartbeat() bool {
	m.mu.RLock()
	running := m.hbSender != nil || m.hbReceiver != nil
	localAddr := m.hbLocalAddr
	peerAddr := m.hbPeerAddr
	vrfDevice := m.hbVRFDevice
	notify := m.hbRestartNotifyFn
	receiver := m.hbReceiver
	m.mu.RUnlock()

	if !running || localAddr == "" {
		return false
	}

	// Preserve the old receiver's last-seen heartbeat timestamp
	// (CLOCK_MONOTONIC nanos — comparable across an in-process restart).
	var lastSeenSeed int64
	if receiver != nil {
		lastSeenSeed = receiver.lastSeen.Load()
	}

	slog.Info("cluster: restarting heartbeat after VRF rebind",
		"local", localAddr, "peer", peerAddr, "vrf", vrfDevice)

	// Freshen the peer's sync-recency suppression guard before our UDP
	// heartbeats go silent.
	if notify != nil {
		notify()
	}

	m.StopHeartbeat()

	for i := 0; i < 5; i++ {
		if err := m.StartHeartbeat(localAddr, peerAddr, vrfDevice); err != nil {
			slog.Warn("cluster: heartbeat restart bind failed, retrying",
				"err", err, "attempt", i+1)
			// Keep the peer's suppression guard fed (2s recency window)
			// through each 1s retry interval.
			if notify != nil {
				notify()
			}
			time.Sleep(1 * time.Second)
			continue
		}
		// Seed the replacement receiver with the pre-restart timestamp
		// unless it has already seen a live heartbeat.
		if lastSeenSeed != 0 {
			m.mu.RLock()
			newReceiver := m.hbReceiver
			m.mu.RUnlock()
			if newReceiver != nil {
				newReceiver.lastSeen.CompareAndSwap(0, lastSeenSeed)
			}
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
			Weight:   clampWireWeight(rg.Weight),
			State:    uint8(rg.State),
		})
	}

	// Include local interface monitor statuses.
	for _, ls := range localStatuses {
		pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{
			RGID:      uint8(ls.RedundancyGroup),
			Weight:    clampWireWeight(ls.Weight),
			Up:        ls.Up,
			Interface: ls.Interface,
		})
	}
	return pkt
}

// clampWireWeight narrows a weight onto the single-byte heartbeat weight field
// by SATURATING instead of truncating (#6549).
//
// This is the last belt, not the fix. `uint8(w)` wraps — 355 leaves as 99 —
// which is what let a node's local weight and its advertised weight disagree
// and put two primaries on the LAN. The fix is that the weight domain is closed
// upstream (rgWeightFromDebt for rg.Weight, config.ClampInterfaceMonitorWeight
// for the per-monitor weight), so every value that reaches here is already in
// [0,255] and this is an identity. Saturating rather than wrapping means a
// future writer that bypasses those helpers degrades to a bounded, monotonic
// weight instead of silently aliasing to an unrelated one.
func clampWireWeight(w int) uint8 {
	if w < 0 {
		return 0
	}
	if w > maxRedundancyGroupWeight {
		return maxRedundancyGroupWeight
	}
	return uint8(w)
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
	// Re-check heartbeat STALENESS, not just peerAlive. m.mu is released
	// across the guard call above, so the receiver read path can run
	// handlePeerHeartbeat — setting peerAlive and advancing lastSeen — for
	// ANY guard duration, not only a slow guard fn (a configured slow guard
	// merely widens the window). peerAlive is essentially always true here
	// (it was true on entry and a fresh heartbeat only keeps it true), so
	// checking it cannot detect that a heartbeat landed during the window —
	// re-reading lastSeen against the live clock can. If the heartbeat is
	// fresh again, the peer is not lost: abort to avoid a spurious peer-loss
	// and the unnecessary failover churn that follows (#2080).
	if m.peerHeartbeatFreshLocked() {
		slog.Debug("cluster: aborting peer heartbeat timeout, fresh heartbeat arrived during guard window")
		return
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
	//
	// Ordering note (#72): the election above runs BEFORE the fence, and the
	// fence is never a precondition for ownership. That is deliberate and not
	// currently changeable by reordering alone — SendFence
	// (sync_failover.go) writes syncMsgFence and returns; there is no
	// fence-ack message on the wire, so "fence acknowledged" is not an
	// observable this code could gate on. Gating takeover on the send
	// SUCCEEDING would be worse than useless: the send fails precisely when
	// the peer is unreachable, which is the split-brain case fencing exists
	// to cover, so it would convert a dead peer into a total outage.
	// Every attempt and its result is recorded to the EventFence history and
	// rendered by FormatInformation's "Peer fencing:" block.
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
//
// The SCOPES here differ, and reporting them off the same nil check was a
// defect. Sent/Received/error counts belong to the goroutine currently
// installed, so they are correctly gated on a live sender/receiver. The #6169
// epoch state does NOT: the downgrade latch and its counters live on
// Manager.hbAuth precisely so a heartbeat restart or a VRF rebind cannot reset
// them (#5086/#6642), and the receiver merely holds a pointer to it.
//
// Gating them on `receiver != nil` therefore reported the latch as CLEAR during
// every window in which no receiver is installed — StopHeartbeat, and the whole
// bind-retry span of a failed RestartHeartbeat, which is up to ~5s of retries
// and is exactly when an operator is looking at the status output. The
// underlying state was armed the entire time. Read it from the Manager, which
// owns it, so the report tracks the process state rather than the goroutine's.
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
	// Process-scoped, not receiver-scoped: valid with no receiver installed.
	s.EpochlessAdmitted = m.hbAuth.epochlessAdmitted.Load()
	s.EpochDowngradeRejected = m.hbAuth.epochDowngradeRejected.Load()
	s.EpochOutOfBandRejected = m.hbAuth.epochOutOfBandRejected.Load()
	s.EpochAheadOfClockRejected = m.hbAuth.epochAheadOfClockRejected.Load()
	s.EpochSessionCollision = m.hbAuth.epochSessionCollision.Load()
	s.PeerEpochLatched = m.hbAuth.peerEpochLatched()
	return s
}

// HeartbeatStats holds heartbeat send/receive counters.
type HeartbeatStats struct {
	Sent       uint64
	Received   uint64
	SendErrors uint64
	RecvErrors uint64

	// EpochlessAdmitted counts authenticated heartbeats admitted WITHOUT a
	// #6169 boot epoch, and EpochDowngradeRejected counts those refused because
	// the peer had already proved it emits them.
	//
	// EpochlessAdmitted is the exposure meter. A frame with no epoch is
	// governed by the bounded session ring alone, which is the mechanism that
	// stops working past heartbeatReplaySessions captures — so a non-zero and
	// still-climbing value after BOTH nodes are upgraded means either a node is
	// still on a pre-#6169 build or someone is replaying pre-upgrade captures.
	// Rotating the control-link PSK is what retires an attacker's archive; see
	// "Operating the control-link PSK" in pkg/cluster/README.md. Without this
	// counter that residual is invisible to an operator.
	EpochlessAdmitted      uint64
	EpochDowngradeRejected uint64

	// EpochSessionCollision counts frames refused because they claimed the
	// FLOOR epoch beyond the bound on how many sessions may be admitted at one
	// epoch value (heartbeatAuthState.highEpochSessions,
	// heartbeatEpochSessionsPerEpoch slots).
	//
	// It is the meter for the one case the floor's own value cannot order: two
	// peer incarnations advertising the SAME epoch. Distinct sessions at one
	// epoch are what let a replay churn the bounded ring, so past the bound they
	// are refused — and a non-zero value says which of the two causes is in
	// play.
	//
	// CLIMBING ALONGSIDE A PEER THAT KEEPS BEING DECLARED DEAD is a SENDER
	// emitting one constant epoch across its own incarnations, and the first
	// thing to check is a NON-WRITABLE /var on that node — a full filesystem, a
	// quota, or a read-only remount. refineBootEpoch chains to persisted+1,
	// which is a pure function of the file, so a store that READS but cannot
	// WRITE hands every restart the identical value. `df` and a test write under
	// /var/lib/xpf find it.
	//
	// IT TAKES THE FILE AS WELL AS THE STORE FAULT, and an earlier revision of
	// this note said the clock was "irrelevant to this and usually perfectly
	// correct". The chain only engages when `prev+1 > epoch`, and `epoch` is
	// this incarnation's WALL-CLOCK seed, so an unwritable /var holding a value
	// BEHIND the current clock changes nothing — each restart simply publishes
	// its own, higher, seed. Measured on the fixture in
	// TestEqualEpochSuccessorIsAdmitted_6669 at both polarities: a file 30
	// minutes behind `now` gives two incarnations 1786141172292358650 and
	// 1786141172295059255 (different), the same file 30 minutes AHEAD gives both
	// 1786142972295695676 (equal). So the regime is an unwritable store holding a
	// value at or above the wall-clock seed — an RTC that ran fast and was
	// corrected back, or a clock that stepped backwards. Look at both, not just
	// `df`. The degenerate third cause — a clock at or before the Unix epoch,
	// which makes bootEpochSeed return the literal 1 for every incarnation — is
	// worth checking only after the store is ruled out. Either way the sender
	// recovers once its epoch can move again; see pkg/cluster/README.md.
	//
	// CLIMBING WHILE PEER LIVENESS IS STILL HEALTHY is an attacker replaying a
	// captured set that shares an epoch. Read that as "not yet affected" rather
	// than "harmless": an earlier revision of this note said liveness is
	// UNAFFECTED, and it is not. Each replayed session spends one of the epoch
	// value's slots, so the peer's NEXT restart at that same value finds the slot
	// it needs already taken and is refused — the same lockout the first cause
	// produces, deferred until the peer happens to restart. Investigate a
	// climbing count even while the peer is up.
	//
	// Neither cause is visible in the other two counters: such a frame carries an
	// epoch (so it is not EpochlessAdmitted) and is not a downgrade (so it is not
	// EpochDowngradeRejected).
	EpochSessionCollision uint64

	// EpochOutOfBandRejected and EpochAheadOfClockRejected are the two epoch
	// refusals that are NOT replays, split out so the operator action differs
	// from the one "stale nonce (replay)" implies.
	//
	// A non-zero EpochOutOfBandRejected means the PEER is emitting an epoch of 0
	// or past the year-2200 horizon. A conforming #6169 build cannot do that
	// (refineBootEpoch declines to chain to such a value, clock-independently),
	// so this points at the peer's state file or at the peer running something
	// that is not this build — never at this node's clock.
	//
	// A non-zero EpochAheadOfClockRejected is a CLOCK fault and usually a
	// perfectly healthy peer: its epoch is more than bootEpochMaxSkew (one hour)
	// ahead of THIS node's clock, so either the peer runs fast or this node runs
	// slow. Check NTP on both nodes. It gates only the RAISE path, so a peer
	// already at the floor keeps being admitted — which is why this can climb
	// while peer liveness stays healthy, and why reading it as an attack wastes
	// an incident. It self-clears once the clocks agree; no restart is needed.
	EpochOutOfBandRejected    uint64
	EpochAheadOfClockRejected uint64

	// PeerEpochLatched is the DOWNGRADE LATCH itself (heartbeatAuthState.
	// epochSeen): an epoch-bearing frame has been accepted from this peer.
	//
	// THAT IS A FACT ABOUT THIS NODE'S STATE, NOT ABOUT WHAT IS ENFORCED, and an
	// earlier revision of this comment said "so an epoch-less frame from it is
	// refused from now on". admitAuthed does refuse one while this is
	// true, but it is not the outermost gate: heartbeatAuthDecision
	// short-circuits to dual-accept whenever no local control-link key is
	// configured, and UpdateConfig clears controlAuthKey WITHOUT resetting
	// hbAuth. So a latched node admits epoch-less frames unverified for as long
	// as the key is absent. Renderers must report the fact — see
	// epochlessExposureNote and peerEpochLatched.
	//
	// This is the state, not a proxy for it. EpochDowngradeRejected was used as
	// one and is not equivalent: it only moves when a LATER epoch-less frame
	// arrives and is refused, so between the frame that arms the latch and the
	// next epoch-less frame — which may never come — the counter is still 0
	// while the latch is armed. Reporting live exposure off the counter told
	// the operator "replay protection is ring-only" at a moment when it was
	// not. epochlessExposureNote reads this instead.
	PeerEpochLatched bool
}
