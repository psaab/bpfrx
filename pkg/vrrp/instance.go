package vrrp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/vishvananda/netlink"
)

// VRRPState represents the VRRPv3 state machine state.
type VRRPState int

const (
	StateInitialize VRRPState = iota
	StateBackup
	StateMaster
)

func (s VRRPState) String() string {
	switch s {
	case StateInitialize:
		return "INIT"
	case StateBackup:
		return "BACKUP"
	case StateMaster:
		return "MASTER"
	default:
		return "UNKNOWN"
	}
}

// VRRPEvent is emitted when a VRRP instance changes state.
type VRRPEvent struct {
	Interface string
	GroupID   int
	State     VRRPState
	VIPs      []string
}

// vrrpInstance is a per-VRRP-group state machine goroutine.
type vrrpInstance struct {
	mu               sync.RWMutex
	cfg              Instance
	desiredPreempt   bool // configured preempt value (may differ from cfg.Preempt during sync hold)
	forcePreemptOnce bool // one-shot preempt override from ForceRGMaster (auto-cleared after use)
	trackDown        bool // tracked interface (cfg.TrackInterface) is down (#1814); guarded by mu

	// Last-seen master advertisement (#2082). Recorded by handleBackupRx /
	// handleMasterRx for every non-zero-priority advert from a peer, and read
	// by shouldPreemptObservedMaster to gate the non-force sync-hold preempt
	// shortcut on a strictly-higher effective priority (RFC 5798 §6.4.2). Both
	// writers and the gate reader run in the run-loop goroutine, so they are
	// already serialized with respect to each other; mu makes the writes/reads
	// race-clean for any future cross-goroutine reader. Priority-0
	// (resignation) adverts are NOT recorded — post-resign takeover flows
	// through the ungated masterDownTimer path. Guarded by mu.
	lastMasterPriority int       // last non-zero peer advert priority
	lastMasterSeen     time.Time // when lastMasterPriority was recorded

	state     VRRPState
	iface     *net.Interface
	eventCh   chan<- VRRPEvent
	localIP   net.IP // our IPv4 address on this interface (for filtering self-sent)
	localIPv6 net.IP // our link-local IPv6 address (source for IPv6 VRRP adverts)

	// Per-instance raw socket and receiver.
	conn    net.PacketConn
	rawConn *ipv4.RawConn

	// IPv6 raw socket for sending VRRPv3 advertisements.
	// nil when no IPv6 VIPs are configured.
	ipv6Conn net.PacketConn
	ipv6FD   int // raw fd for setsockopt (hop limit, multicast)

	// AF_PACKET socket for receiving on VLAN sub-interfaces.
	// Raw IP sockets don't reliably receive multicast on VLAN
	// sub-interfaces (kernel limitation). AF_PACKET captures at
	// the link layer and works correctly. -1 means not used.
	afPacketFD int

	preemptNowCh chan struct{} // signals coordinated preemption from ReleaseSyncHold
	resignCh     chan struct{} // signals forced resignation (manual failover)

	rxCh    chan *VRRPPacket
	stopCh  chan struct{}
	stopped chan struct{}

	// RX backpressure counters (atomic).
	rxDrops      atomic.Uint64 // packets dropped due to full rxCh
	rxReceived   atomic.Uint64 // total packets delivered to rxCh
	lastDropWarn time.Time     // last time we logged a drop warning (rate-limited)

	// GARP suppression for strict-vip-ownership mode.
	suppressGARP  atomic.Bool   // when true, becomeMaster() skips GARP/NA
	garpEpoch     atomic.Uint64 // incremented on each becomeMaster()/ReconcileVIPs transition
	lastGARPEpoch atomic.Uint64 // epoch of last completed sendGARP()
	lastGARPTime  atomic.Int64  // Unix nanos of last GARP send (dampens routine GARP only; forced sends bypass — see garpSendAllowed)

	// onEventDrop is called when an event is dropped due to a full eventCh.
	// Set by the manager to trigger immediate reconciliation.
	onEventDrop func()
}

func newInstance(cfg Instance, iface *net.Interface, eventCh chan<- VRRPEvent, onEventDrop func()) *vrrpInstance {
	return &vrrpInstance{
		cfg:            cfg,
		desiredPreempt: cfg.Preempt,
		state:          StateInitialize,
		iface:          iface,
		eventCh:        eventCh,
		afPacketFD:     -1,
		ipv6FD:         -1,
		preemptNowCh:   make(chan struct{}, 1),
		resignCh:       make(chan struct{}, 1),
		rxCh:           make(chan *VRRPPacket, 64),
		stopCh:         make(chan struct{}),
		stopped:        make(chan struct{}),
		onEventDrop:    onEventDrop,
	}
}

// openSocket creates the per-instance raw socket bound to the interface.
func (vi *vrrpInstance) openSocket() error {
	isVLAN := strings.Contains(vi.cfg.Interface, ".")

	rawConn, conn, err := openPerInterfaceSocket(vi.cfg.Interface, vi.iface, isVLAN)
	if err != nil {
		return err
	}
	vi.conn = conn
	vi.rawConn = rawConn

	// Open AF_PACKET socket for receiving VRRP packets.
	// Raw IP sockets (proto 112) don't reliably receive multicast in
	// generic XDP mode — AF_PACKET taps fire before generic XDP in the
	// kernel's receive path, so they always see the packet regardless
	// of XDP processing. The raw IP socket is kept for sending only.
	fd, err := openAfPacketReceiver(vi.iface.Index)
	if err != nil {
		slog.Warn("vrrp: af_packet open failed, raw socket only",
			"key", vi.key(), "err", err)
	} else {
		vi.afPacketFD = fd
	}

	// Resolve our local IPv4 address (primary IP, not a VIP) for:
	// 1. Source address in VRRP advertisements
	// 2. Filtering self-sent packets
	// We must skip VIP addresses because during split-brain both nodes
	// have the VIP — using it as source would cause the peer to filter
	// our adverts as "self-sent" (matching its own VIP).
	vipSet := make(map[string]bool, len(vi.cfg.VirtualAddresses))
	hasIPv6VIPs := false
	for _, vip := range vi.cfg.VirtualAddresses {
		addr := vip
		if idx := strings.Index(addr, "/"); idx >= 0 {
			addr = addr[:idx]
		}
		vipSet[addr] = true
		if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
			hasIPv6VIPs = true
		}
	}
	addrs, _ := vi.iface.Addrs()
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 != nil && !vipSet[ip4.String()] {
			vi.localIP = ip4
		}
	}
	// Deterministic IPv6 link-local selection: sort candidates and
	// pick the lowest address. This ensures the same source address
	// is used even when the interface has multiple link-locals.
	vi.localIPv6 = vi.resolveIPv6LinkLocal(vipSet)

	// Open IPv6 raw socket if any VIPs are IPv6.
	if hasIPv6VIPs {
		v6Conn, v6FD, err := openIPv6Socket(vi.cfg.Interface, vi.iface)
		if err != nil {
			slog.Warn("vrrp: ipv6 socket open failed, IPv6 adverts disabled",
				"key", vi.key(), "err", err)
		} else {
			vi.ipv6Conn = v6Conn
			vi.ipv6FD = v6FD
		}
	}

	return nil
}

func (vi *vrrpInstance) key() string {
	return fmt.Sprintf("VI_%s_%d", vi.cfg.Interface, vi.cfg.GroupID)
}

// updateConfig updates priority, preempt, and interface-tracking config
// in-place without restarting.
func (vi *vrrpInstance) updateConfig(cfg Instance) {
	vi.mu.Lock()
	vi.cfg.Priority = cfg.Priority
	vi.cfg.Preempt = cfg.Preempt
	vi.cfg.TrackInterface = cfg.TrackInterface
	vi.cfg.TrackPriorityCost = cfg.TrackPriorityCost
	vi.desiredPreempt = cfg.Preempt
	vi.mu.Unlock()
}

// suppressPreempt forces effective preempt to false while preserving the
// configured desiredPreempt value for later restore.
func (vi *vrrpInstance) suppressPreempt() {
	vi.mu.Lock()
	vi.cfg.Preempt = false
	vi.mu.Unlock()
}

// setDesiredPreempt updates the configured preempt value that should be
// restored when sync hold is released.
func (vi *vrrpInstance) setDesiredPreempt(preempt bool) {
	vi.mu.Lock()
	vi.desiredPreempt = preempt
	vi.mu.Unlock()
}

// restorePreempt sets cfg.Preempt to the configured (desired) value.
// Called when sync hold is released to re-enable preemption.
func (vi *vrrpInstance) restorePreempt() {
	vi.mu.Lock()
	vi.cfg.Preempt = vi.desiredPreempt
	vi.mu.Unlock()
}

// triggerPreemptNow signals the run loop to attempt immediate preemption.
// Non-blocking: if a signal is already pending it is silently dropped.
func (vi *vrrpInstance) triggerPreemptNow() {
	select {
	case vi.preemptNowCh <- struct{}{}:
	default:
	}
}

// triggerResign signals the run loop to resign from MASTER by sending
// priority-0 adverts and transitioning to BACKUP. Non-blocking.
func (vi *vrrpInstance) triggerResign() {
	select {
	case vi.resignCh <- struct{}{}:
	default:
	}
}

func (vi *vrrpInstance) getPreempt() bool {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.cfg.Preempt
}

// shouldPreemptObservedMaster decides whether the non-force sync-hold preempt
// shortcut (the preemptNowCh case in run) may transition this BACKUP instance
// to MASTER (#2082). It encodes RFC 5798 §6.4.2 preemption: a BACKUP preempts
// only on a STRICTLY higher priority than the currently-observed master. It
// returns true iff:
//
//   - preempt is configured (a non-preempting node never preempts on the
//     shortcut), AND
//   - either no live master has been observed recently (lastMasterSeen is zero
//     or older than masterDownInterval — the cold-start / peer-down /
//     silent-master-death rescue, where becoming MASTER is correct), OR a
//     recent master was observed AND our effective priority is strictly greater
//     than its last advertised priority.
//
// Equal priority returns false (RFC 5798 §6.4.2 — an equal-priority BACKUP does
// not preempt; the address tie-break in handleMasterRx resolves a MASTER-MASTER
// collision, a different state than preemption). The ForceRGMaster path
// (force=true) is gated OUTSIDE this helper (the run-loop short-circuits it),
// so cluster-authoritative promotion is unaffected.
//
// Lock discipline (BINDING — Go's sync.RWMutex is non-reentrant): this helper
// snapshots everything it needs under ONE vi.mu.RLock(), releases, then
// computes the effective priority and the staleness horizon from the locals.
// It MUST NOT call getPriority()/getPreempt()/masterDownInterval() (each of
// which RLocks vi.mu) while holding the lock. RLock (not Lock) is used so it
// never blocks concurrent external readers such as Status().
func (vi *vrrpInstance) shouldPreemptObservedMaster() bool {
	vi.mu.RLock()
	preempt := vi.cfg.Preempt
	priority := vi.cfg.Priority
	trackDown := vi.trackDown
	trackIface := vi.cfg.TrackInterface
	trackCost := vi.cfg.TrackPriorityCost
	advertMS := vi.cfg.AdvertiseInterval
	lastMasterPriority := vi.lastMasterPriority
	lastMasterSeen := vi.lastMasterSeen
	vi.mu.RUnlock()

	if !preempt {
		return false
	}

	// Effective advertised priority — replicates getPriority() (track.go)
	// from the snapshot: priority 0/255 pass through unchanged; otherwise
	// while the tracked link is down, TrackPriorityCost is subtracted and
	// clamped to [1, 254].
	effective := priority
	if priority != 0 && priority != 255 && trackDown && trackIface != "" {
		effective -= trackCost
		if effective < 1 {
			effective = 1
		} else if effective > 254 {
			effective = 254
		}
	}

	// masterDownInterval staleness horizon — replicates masterDownInterval()
	// (3*advert + skew) from the snapshot using the effective priority.
	advert := time.Duration(advertMS) * time.Millisecond
	if advertMS <= 0 {
		advert = 1000 * time.Millisecond
	}
	skew := time.Duration(256-effective) * advert / 256
	masterDown := 3*advert + skew

	// No live master observed (cold-start) or the last advert is older than
	// the master-down horizon (silent death / peer-down) → no master to
	// respect, becoming MASTER is correct.
	if lastMasterSeen.IsZero() || time.Since(lastMasterSeen) > masterDown {
		return true
	}

	// A live master was observed — preempt only on STRICTLY higher priority.
	return effective > lastMasterPriority
}

func (vi *vrrpInstance) getState() VRRPState {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.state
}

func (vi *vrrpInstance) setState(s VRRPState) {
	vi.mu.Lock()
	vi.state = s
	vi.mu.Unlock()
}

// advertInterval returns the advertisement interval as a Duration.
// AdvertiseInterval is in milliseconds.
func (vi *vrrpInstance) advertInterval() time.Duration {
	ms := vi.cfg.AdvertiseInterval
	if ms <= 0 {
		ms = 1000
	}
	return time.Duration(ms) * time.Millisecond
}

// masterDownInterval returns the master-down timer value.
// Per RFC 5798: Master_Down_Interval = (3 * Advertisement_Interval) + Skew_Time
// Skew_Time = ((256 - priority) * Master_Advert_Interval) / 256
func (vi *vrrpInstance) masterDownInterval() time.Duration {
	advert := vi.advertInterval()
	skew := time.Duration(256-vi.getPriority()) * advert / 256
	return 3*advert + skew
}

// stepBackup runs one iteration of the StateBackup select. It is called by the
// run loop AND directly by unit tests (the run() preamble unconditionally
// spawns a receiver goroutine that nil-derefs vi.conn on a test instance, so
// tests must not call run() — they drive this seam instead). It returns true
// when the instance has been told to stop (the caller's run loop should
// return).
func (vi *vrrpInstance) stepBackup(masterDownTimer, advertTimer *time.Timer) (stop bool) {
	select {
	case <-vi.stopCh:
		return true
	case pkt := <-vi.rxCh:
		vi.handleBackupRx(pkt, masterDownTimer)
	case <-masterDownTimer.C:
		// Master timed out — become Master.
		vi.becomeMaster()
		advertTimer.Reset(vi.advertInterval())
	case <-vi.preemptNowCh:
		// Coordinated preemption from ReleaseSyncHold or forced transition
		// from ForceRGMaster. The forcePreemptOnce flag allows a one-shot
		// preemption even when preempt=false, without leaking into the
		// configured preempt value.
		//
		// force=true (ForceRGMaster) is cluster-authoritative and bypasses
		// the peer-priority gate unconditionally. The non-force sync-hold
		// path is gated on shouldPreemptObservedMaster (#2082): a
		// lower-priority preempt-enabled node no longer transiently becomes
		// a second MASTER while a higher-priority peer is legitimately MASTER.
		vi.mu.Lock()
		force := vi.forcePreemptOnce
		vi.forcePreemptOnce = false
		vi.mu.Unlock()
		if force || vi.shouldPreemptObservedMaster() {
			vi.becomeMaster()
			advertTimer.Reset(vi.advertInterval())
			masterDownTimer.Stop()
		}
	}
	return false
}

// run is the main state machine loop. Must be called as a goroutine.
func (vi *vrrpInstance) run() {
	defer close(vi.stopped)

	slog.Info("vrrp: instance starting",
		"key", vi.key(),
		"interface", vi.cfg.Interface,
		"vrid", vi.cfg.GroupID,
		"priority", vi.cfg.Priority,
		"preempt", vi.cfg.Preempt)

	// Start per-instance receiver goroutine.
	// AF_PACKET captures at the link layer before generic XDP, ensuring
	// reliable multicast reception on all interface types.
	if vi.afPacketFD >= 0 {
		go vi.receiverAfPacket()
	} else {
		go vi.receiver()
		// The IPv4-only raw socket fallback cannot receive IPv6 VRRP.
		// Start a separate IPv6 receiver if we have an IPv6 socket.
		if vi.ipv6Conn != nil {
			slog.Warn("vrrp: af_packet unavailable, using separate IPv6 raw socket fallback",
				"key", vi.key())
			go vi.receiverIPv6()
		} else if vi.localIPv6 != nil {
			slog.Warn("vrrp: af_packet unavailable and no IPv6 socket — IPv6 VRRP reception disabled",
				"key", vi.key())
		}
	}

	// Transition to Backup state.
	// Remove any stale VIPs that may be on the interface from a previous
	// daemon run or config apply. This ensures BACKUP nodes don't have VIPs.
	vi.removeVIPs()
	vi.setState(StateBackup)
	vi.emitEvent()

	// Use an extended initial masterDown timer when preempt is disabled
	// (either from config or sync hold). With short RETH intervals (30ms),
	// the normal masterDown timer (~97ms) can fire before the AF_PACKET
	// receiver starts capturing peer adverts — causing the returning node
	// to erroneously become MASTER. A 3s initial timer gives enough time
	// for the receiver to initialize and for the cluster election to
	// determine our role. After the first received advert, handleBackupRx
	// resets the timer to the normal short interval.
	initialMasterDown := vi.masterDownInterval()
	if !vi.getPreempt() {
		initialMasterDown = 3 * time.Second
	}
	masterDownTimer := time.NewTimer(initialMasterDown)
	defer masterDownTimer.Stop()

	// Not used until we become Master.
	advertTimer := time.NewTimer(0)
	advertTimer.Stop()
	defer advertTimer.Stop()

	for {
		state := vi.getState()

		switch state {
		case StateBackup:
			if vi.stepBackup(masterDownTimer, advertTimer) {
				return
			}

		case StateMaster:
			select {
			case <-vi.stopCh:
				// Send burst of priority-0 advertisements to signal resignation.
				// Multiple adverts improve reliability if one is lost on the wire.
				for i := 0; i < 3; i++ {
					vi.sendAdvert(0)
				}
				vi.removeVIPs()
				return
			case pkt := <-vi.rxCh:
				vi.handleMasterRx(pkt, masterDownTimer, advertTimer)
			case <-advertTimer.C:
				vi.sendAdvert(vi.getPriority())
				advertTimer.Reset(vi.advertInterval())
			case <-vi.resignCh:
				// Forced resignation (manual failover / cluster Primary→Secondary).
				slog.Info("vrrp: forced resignation", "key", vi.key())
				for i := 0; i < 3; i++ {
					vi.sendAdvert(0)
				}
				vi.becomeBackup(masterDownTimer, advertTimer)
				// Use an extended safety-net timer instead of stopping entirely.
				// With short RETH intervals (30ms), masterDownInterval() at
				// priority 0 is only ~120ms, which re-elects the resigned node
				// before the peer can take over. We use 3× the normal
				// masterDownInterval to give the peer time to become MASTER
				// and start advertising, while still providing a recovery path
				// if the peer crashes without sending priority-0.
				//
				// Normal recovery paths (faster than the safety timer):
				//   - preemptNowCh (cluster ForceRGMaster after failover reset)
				//   - priority-0 from peer (peer resigning) → 1ms takeover
				//   - peer advert received → resets timer to masterDownInterval
				//
				// The safety timer only fires if the peer is completely gone
				// (crash without priority-0, network partition).
				safetyTimeout := 3 * vi.masterDownInterval()
				if safetyTimeout < 500*time.Millisecond {
					safetyTimeout = 500 * time.Millisecond
				}
				masterDownTimer.Reset(safetyTimeout)
			}
		}
	}
}

// isTimeoutError returns true if the error is a network timeout.
func isTimeoutError(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

// receiver reads VRRP packets from the per-instance raw socket.
func (vi *vrrpInstance) receiver() {
	buf := make([]byte, 1500)
	for {
		select {
		case <-vi.stopCh:
			return
		default:
		}

		// Set a read deadline so ReadFrom doesn't block forever.
		// ipv4.RawConn.ReadFrom uses RawRead which can get stuck in a
		// blocking recvmsg syscall; the deadline ensures we periodically
		// check stopCh even if the socket is unexpectedly in blocking mode.
		vi.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		hdr, payload, _, err := vi.rawConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-vi.stopCh:
				return
			default:
				// Ignore timeout errors — they're expected from our deadline.
				if !isTimeoutError(err) {
					slog.Debug("vrrp: read error", "key", vi.key(), "err", err)
				}
				continue
			}
		}

		// Verify TTL == 255 (RFC 5798 §5.1.1.3).
		if hdr.TTL != 255 {
			continue
		}

		// Filter self-sent packets (RFC 5798 §6.4.2/6.4.3).
		if vi.localIP != nil && hdr.Src.Equal(vi.localIP) {
			continue
		}

		if len(payload) < vrrpHeaderLen {
			continue
		}

		// Only accept packets matching our VRID.
		if payload[1] != uint8(vi.cfg.GroupID) {
			continue
		}

		srcIP := hdr.Src
		dstIP := hdr.Dst

		pkt, err := ParseVRRPPacket(payload, false, srcIP, dstIP)
		if err != nil {
			slog.Debug("vrrp: parse error", "key", vi.key(), "err", err)
			continue
		}

		select {
		case vi.rxCh <- pkt:
			vi.rxReceived.Add(1)
		default:
			vi.warnRXDrop()
		}
	}
}

// receiverIPv6 reads VRRPv3 packets from the IPv6 raw socket (ip6:112).
// Used as fallback when AF_PACKET is unavailable. The kernel strips the
// IPv6 header for raw sockets, so ReadFrom returns the VRRP payload directly.
// Source address comes from the addr parameter of ReadFrom.
func (vi *vrrpInstance) receiverIPv6() {
	buf := make([]byte, 1500)
	for {
		select {
		case <-vi.stopCh:
			return
		default:
		}

		vi.ipv6Conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := vi.ipv6Conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-vi.stopCh:
				return
			default:
				if !isTimeoutError(err) {
					slog.Debug("vrrp: ipv6 read error", "key", vi.key(), "err", err)
				}
				continue
			}
		}

		if n < vrrpHeaderLen {
			continue
		}

		// Only accept packets matching our VRID.
		if buf[1] != uint8(vi.cfg.GroupID) {
			continue
		}

		// Extract source IP from the addr returned by ReadFrom.
		var srcIP net.IP
		if ipAddr, ok := addr.(*net.IPAddr); ok {
			srcIP = ipAddr.IP
		}

		// Filter self-sent packets.
		if vi.localIPv6 != nil && srcIP != nil && srcIP.Equal(vi.localIPv6) {
			continue
		}

		// IPv6 VRRP multicast destination (ff02::12).
		dstIP := net.ParseIP("ff02::12")

		pkt, err := ParseVRRPPacket(buf[:n], true, srcIP, dstIP)
		if err != nil {
			slog.Debug("vrrp: ipv6 parse error", "key", vi.key(), "err", err)
			continue
		}

		select {
		case vi.rxCh <- pkt:
			vi.rxReceived.Add(1)
		default:
			vi.warnRXDrop()
		}
	}
}

// receiverAfPacket reads VRRP packets via AF_PACKET on VLAN sub-interfaces.
// Uses SOCK_RAW + ETH_P_ALL (same as tcpdump) — receives full Ethernet frames.
// Handles IPv4, IPv6, and 802.1Q-tagged variants. Detects VLAN tags and
// adjusts header skip: 14 bytes untagged, 18 bytes single-tagged.
func (vi *vrrpInstance) receiverAfPacket() {
	buf := make([]byte, 1500)
	for {
		select {
		case <-vi.stopCh:
			return
		default:
		}

		n, _, err := unix.Recvfrom(vi.afPacketFD, buf, 0)
		if err != nil {
			select {
			case <-vi.stopCh:
				return
			default:
				// EAGAIN/EWOULDBLOCK from SO_RCVTIMEO — expected.
				if err != unix.EAGAIN && err != unix.EWOULDBLOCK {
					slog.Debug("vrrp: af_packet read error", "key", vi.key(), "err", err)
				}
				continue
			}
		}

		// Need at least 14 bytes to read the ethertype.
		if n < 14 {
			continue
		}

		// Detect 802.1Q VLAN tag and resolve real ethertype.
		ethHeaderLen := 14
		ethertype := binary.BigEndian.Uint16(buf[12:14])
		if ethertype == 0x8100 || ethertype == 0x88a8 {
			ethHeaderLen = 18 // 14 + 4-byte VLAN tag
			if n < 18 {
				continue
			}
			ethertype = binary.BigEndian.Uint16(buf[16:18])
		}

		isIPv6 := ethertype == 0x86DD

		if isIPv6 {
			vi.parseAfPacketIPv6(buf, n, ethHeaderLen)
		} else if ethertype == 0x0800 {
			vi.parseAfPacketIPv4(buf, n, ethHeaderLen)
		}
	}
}

// parseAfPacketIPv4 parses an IPv4 VRRP packet from a raw Ethernet frame.
func (vi *vrrpInstance) parseAfPacketIPv4(buf []byte, n, ethHeaderLen int) {
	// Minimum: eth header + 20-byte IPv4 + 8-byte VRRP.
	if n < ethHeaderLen+20+vrrpHeaderLen {
		return
	}

	ip := buf[ethHeaderLen:]
	ipLen := n - ethHeaderLen

	ihl := int(ip[0]&0x0F) * 4
	if ihl < 20 || ipLen < ihl+vrrpHeaderLen {
		return
	}

	// Verify TTL == 255 (RFC 5798 §5.1.1.3).
	if ip[8] != 255 {
		return
	}

	srcIP := make(net.IP, 4)
	copy(srcIP, ip[12:16])

	// Filter self-sent packets.
	if vi.localIP != nil && srcIP.Equal(vi.localIP) {
		return
	}

	payload := ip[ihl:ipLen]
	if payload[1] != uint8(vi.cfg.GroupID) {
		return
	}

	dstIP := make(net.IP, 4)
	copy(dstIP, ip[16:20])

	pkt, err := ParseVRRPPacket(payload, false, srcIP, dstIP)
	if err != nil {
		slog.Debug("vrrp: parse error", "key", vi.key(), "err", err)
		return
	}

	select {
	case vi.rxCh <- pkt:
		vi.rxReceived.Add(1)
	default:
		vi.warnRXDrop()
	}
}

// parseAfPacketIPv6 parses an IPv6 VRRP packet from a raw Ethernet frame.
// IPv6 base header: 40 bytes fixed, next-header at offset 6, hop limit at
// offset 7, source at 8-24, destination at 24-40. The VRRP payload may be
// preceded by one or more IPv6 extension headers (#2155); walkIPv6ExtHeaders
// finds the real payload offset.
func (vi *vrrpInstance) parseAfPacketIPv6(buf []byte, n, ethHeaderLen int) {
	const ipv6HeaderLen = 40

	// Minimum: eth header + 40-byte IPv6 + 8-byte VRRP.
	if n < ethHeaderLen+ipv6HeaderLen+vrrpHeaderLen {
		return
	}

	ip6 := buf[ethHeaderLen:]
	ip6Len := n - ethHeaderLen

	// Verify hop limit == 255 (RFC 5798 §5.1.2.3).
	if ip6[7] != 255 {
		return
	}

	srcIP := make(net.IP, 16)
	copy(srcIP, ip6[8:24])

	// Filter self-sent packets.
	if vi.localIPv6 != nil && srcIP.Equal(vi.localIPv6) {
		return
	}

	// Walk any IPv6 extension-header chain to the proto-112 VRRP payload.
	// A bare advert (base Next-Header == 112) yields off == ipv6HeaderLen.
	off, ok := walkIPv6ExtHeaders(ip6, ip6Len)
	if !ok {
		return
	}

	payload := ip6[off:ip6Len]
	if len(payload) < vrrpHeaderLen {
		return
	}
	if payload[1] != uint8(vi.cfg.GroupID) {
		return
	}

	dstIP := make(net.IP, 16)
	copy(dstIP, ip6[24:40])

	pkt, err := ParseVRRPPacket(payload, true, srcIP, dstIP)
	if err != nil {
		slog.Debug("vrrp: ipv6 parse error", "key", vi.key(), "err", err)
		return
	}

	select {
	case vi.rxCh <- pkt:
		vi.rxReceived.Add(1)
	default:
		vi.warnRXDrop()
	}
}

// walkIPv6ExtHeaders walks the IPv6 extension-header chain in ip6 (an IPv6
// packet starting at its base header, ip6Len bytes long) and returns the
// offset of the first proto-112 (VRRP) header. The bool is false if the
// chain does not terminate at VRRP, is truncated, contains a Fragment
// header, or exceeds the iteration cap — all of which mean "not a parseable
// VRRP advert; drop". A bare advert (base Next-Header == 112) returns
// (40, true).
//
// Length-unit conventions differ per header and mixing them is the classic
// walk bug:
//   - Hop-by-Hop (0), Routing (43), Destination Options (60): the header is
//     8 + HdrExtLen*8 bytes, i.e. (HdrExtLen+1)*8.
//   - Authentication Header (51): the header is (PayloadLen+2)*4 bytes
//     (PayloadLen is in 4-byte units, not counting the first two words).
//   - Fragment (44): VRRP adverts are never legitimately fragmented and the
//     receiver does no reassembly, so a Fragment header is a hard drop.
//
// The walk is bounded to maxIPv6ExtHeaders iterations and bounds-checks every
// access against ip6Len, so a malicious or truncated chain can neither loop
// nor read out of bounds.
func walkIPv6ExtHeaders(ip6 []byte, ip6Len int) (int, bool) {
	const (
		ipv6HeaderLen     = 40
		maxIPv6ExtHeaders = 8
		nhVRRP            = 112
		nhHopByHop        = 0
		nhRouting         = 43
		nhFragment        = 44
		nhDestOpts        = 60
		nhAH              = 51
	)

	if ip6Len < ipv6HeaderLen {
		return 0, false
	}

	nh := int(ip6[6]) // base Next-Header
	off := ipv6HeaderLen

	for i := 0; i < maxIPv6ExtHeaders; i++ {
		if nh == nhVRRP {
			return off, true
		}

		// Need at least the 2-byte (NextHeader, length) preamble of the
		// next extension header to make progress.
		if off+2 > ip6Len {
			return 0, false
		}

		var hdrLen int
		switch nh {
		case nhHopByHop, nhRouting, nhDestOpts:
			hdrLen = (int(ip6[off+1]) + 1) * 8
		case nhAH:
			hdrLen = (int(ip6[off+1]) + 2) * 4
		case nhFragment:
			// Fragmented VRRP is non-conformant — drop.
			return 0, false
		default:
			// Some other terminal protocol — not VRRP.
			return 0, false
		}

		next := int(ip6[off]) // NextHeader of this ext-header
		off += hdrLen
		if hdrLen <= 0 || off > ip6Len {
			return 0, false
		}
		nh = next
	}

	// Chain exceeded the iteration cap without reaching VRRP — drop.
	return 0, false
}

// recordMasterAdvert records a peer's last advertised priority for the
// sync-hold preempt gate (#2082). Priority-0 (resignation) adverts are NOT
// recorded — leaving a stale lastMasterPriority is safe because post-resign
// takeover flows through the ungated masterDownTimer path, not the gated
// preemptNowCh shortcut. Called from handleBackupRx/handleMasterRx, which run
// in the run-loop goroutine; mu only guards external readers.
func (vi *vrrpInstance) recordMasterAdvert(pkt *VRRPPacket) {
	if pkt.Priority == 0 {
		return
	}
	vi.mu.Lock()
	vi.lastMasterPriority = int(pkt.Priority)
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
}

// handleBackupRx processes a received advertisement while in Backup state.
func (vi *vrrpInstance) handleBackupRx(pkt *VRRPPacket, masterDownTimer *time.Timer) {
	vi.recordMasterAdvert(pkt)
	pri := vi.getPriority()
	if pkt.Priority == 0 {
		// Master is explicitly resigning — become Master immediately.
		// RFC 5798 says use skew timer, but with only 2 HA nodes there's
		// no contention risk, and immediate transition gives zero-delay
		// planned failover (systemctl stop on primary).
		slog.Info("vrrp: peer resigned (priority 0), immediate takeover",
			"key", vi.key())
		masterDownTimer.Reset(time.Millisecond)
		return
	}

	// If we don't preempt, or the incoming priority is >= ours, accept it.
	if !vi.getPreempt() || int(pkt.Priority) >= pri {
		masterDownTimer.Reset(vi.masterDownInterval())
	}
	// If preempt is true and incoming priority < ours, ignore — let timer expire.
}

// handleMasterRx processes a received advertisement while in Master state.
// Per RFC 5798 §6.4.3: if priority is higher, step down. If equal,
// the node with the higher source IP stays Master (tie-breaking).
func (vi *vrrpInstance) handleMasterRx(pkt *VRRPPacket, masterDownTimer, advertTimer *time.Timer) {
	vi.recordMasterAdvert(pkt)
	pri := vi.getPriority()
	if pkt.Priority == 0 {
		// Peer resigning — send immediate advert and stay Master.
		vi.sendAdvert(pri)
		advertTimer.Reset(vi.advertInterval())
		return
	}

	pktPri := int(pkt.Priority)
	if pktPri > pri {
		// Higher priority — step down unconditionally.
		vi.becomeBackup(masterDownTimer, advertTimer)
	} else if pktPri == pri && pkt.SrcIP != nil {
		// Equal priority — RFC 5798 §6.4.3 tie-break: higher IP wins.
		// Handle both IPv4 and IPv6 address families.
		var peerHigher bool
		if pkt.SrcIP.To4() != nil && vi.localIP != nil {
			peerHigher = bytes.Compare(pkt.SrcIP.To4(), vi.localIP.To4()) > 0
		} else if pkt.SrcIP.To4() == nil && vi.localIPv6 != nil {
			peerHigher = bytes.Compare(pkt.SrcIP.To16(), vi.localIPv6.To16()) > 0
		}
		if peerHigher {
			slog.Info("vrrp: equal priority tie-break, peer IP is higher — stepping down",
				"key", vi.key(), "our_ip", vi.localIP, "our_ipv6", vi.localIPv6,
				"peer_ip", pkt.SrcIP, "priority", pri)
			vi.becomeBackup(masterDownTimer, advertTimer)
		}
	}
	// Lower priority, or equal with our IP higher: stay Master.
}

// becomeMaster transitions to Master state: add VIPs, send advert, emit event,
// then send GARP/NA asynchronously. The critical path is addVIPs (kernel needs
// VIP addresses for bpf_fib_lookup) + sendAdvert (tells peer to step down).
// GARP only updates L2 switch/router MAC tables and runs in the background.
func (vi *vrrpInstance) becomeMaster() {
	pri := vi.getPriority()
	slog.Info("vrrp: transitioning to MASTER",
		"key", vi.key(), "priority", pri)
	vi.setState(StateMaster)
	vi.addVIPs()
	vi.sendAdvert(pri)
	vi.emitEvent()
	vi.garpEpoch.Add(1)
	if !vi.suppressGARP.Load() {
		// Non-forced: a routine MASTER transition is rate-limited by the
		// 500ms dampener (the epoch dedup still guarantees one burst per
		// transition). Post-MAC-change reconcile uses the forced path.
		go vi.sendGARP(false)
	} else {
		slog.Info("vrrp: GARP suppressed (strict-vip-ownership)",
			"key", vi.key())
	}
}

// becomeBackup transitions to Backup state: remove VIPs, reset timers.
func (vi *vrrpInstance) becomeBackup(masterDownTimer, advertTimer *time.Timer) {
	slog.Info("vrrp: transitioning to BACKUP",
		"key", vi.key())
	vi.setState(StateBackup)
	vi.removeVIPs()
	advertTimer.Stop()
	masterDownTimer.Reset(vi.masterDownInterval())
	vi.emitEvent()
}

// emitEvent sends a state change event to the manager's event channel.
func (vi *vrrpInstance) emitEvent() {
	evt := VRRPEvent{
		Interface: vi.cfg.Interface,
		GroupID:   vi.cfg.GroupID,
		State:     vi.getState(),
		VIPs:      vi.cfg.VirtualAddresses,
	}
	select {
	case vi.eventCh <- evt:
	default:
		// Drop if channel full — warn unless we're shutting down.
		select {
		case <-vi.stopCh:
		default:
			slog.Warn("vrrp: event channel full, dropping event",
				"key", vi.key(), "state", evt.State)
			if vi.onEventDrop != nil {
				vi.onEventDrop()
			}
		}
	}
}

// sendAdvert sends a VRRPv3 advertisement with the given priority.
func (vi *vrrpInstance) sendAdvert(priority int) {
	hasIPv6 := false
	var v4Addrs, v6Addrs []net.IP
	for _, vip := range vi.cfg.VirtualAddresses {
		addr := vip
		if idx := strings.Index(addr, "/"); idx >= 0 {
			addr = addr[:idx]
		}
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4Addrs = append(v4Addrs, ip.To4())
		} else {
			v6Addrs = append(v6Addrs, ip.To16())
			hasIPv6 = true
		}
	}

	// Send IPv4 advertisement if we have any IPv4 VIPs.
	if len(v4Addrs) > 0 {
		maxAdvert := uint16(vi.cfg.AdvertiseInterval / 10) // milliseconds → centiseconds
		pkt := &VRRPPacket{
			VRID:         uint8(vi.cfg.GroupID),
			Priority:     uint8(priority),
			MaxAdvertInt: maxAdvert,
			IPAddresses:  v4Addrs,
		}
		if err := vi.sendPacket(pkt, false); err != nil {
			slog.Debug("vrrp: failed to send IPv4 advert",
				"key", vi.key(), "err", err)
		}
	}

	// Send IPv6 advertisement if we have any IPv6 VIPs.
	if hasIPv6 && len(v6Addrs) > 0 {
		maxAdvert := uint16(vi.cfg.AdvertiseInterval / 10) // ms → centiseconds
		pkt := &VRRPPacket{
			VRID:         uint8(vi.cfg.GroupID),
			Priority:     uint8(priority),
			MaxAdvertInt: maxAdvert,
			IPAddresses:  v6Addrs,
		}
		if err := vi.sendPacket(pkt, true); err != nil {
			slog.Debug("vrrp: failed to send IPv6 advert",
				"key", vi.key(), "err", err)
		}
	}
}

// sendPacket sends a VRRP advertisement via the per-instance raw socket.
func (vi *vrrpInstance) sendPacket(pkt *VRRPPacket, isIPv6 bool) error {
	if isIPv6 {
		return vi.sendPacketIPv6(pkt)
	}
	if vi.rawConn == nil {
		return nil
	}

	srcIP := vi.localIP
	if srcIP == nil {
		// Lazy resolve: interface may not have had an address at socket open time.
		// Skip VIPs — must send from primary/base address.
		vipSet := make(map[string]bool, len(vi.cfg.VirtualAddresses))
		for _, vip := range vi.cfg.VirtualAddresses {
			addr := vip
			if idx := strings.Index(addr, "/"); idx >= 0 {
				addr = addr[:idx]
			}
			vipSet[addr] = true
		}
		if addrs, err := vi.iface.Addrs(); err == nil {
			for _, a := range addrs {
				if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.To4() != nil {
					if !vipSet[ipNet.IP.To4().String()] {
						vi.localIP = ipNet.IP.To4()
						srcIP = vi.localIP
						break
					}
				}
			}
		}
		if srcIP == nil {
			return fmt.Errorf("no IPv4 address on %s", vi.cfg.Interface)
		}
	}

	dstIP := net.IPv4(224, 0, 0, 18)

	data, err := pkt.Marshal(false, srcIP, dstIP)
	if err != nil {
		return err
	}

	hdr := &ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 20 + len(data),
		TTL:      255,
		Protocol: vrrpProto,
		Src:      srcIP,
		Dst:      dstIP,
	}

	if err := vi.rawConn.SetMulticastInterface(vi.iface); err != nil {
		return fmt.Errorf("set multicast interface: %w", err)
	}

	cm := &ipv4.ControlMessage{
		IfIndex: vi.iface.Index,
	}

	if err := vi.rawConn.WriteTo(hdr, data, cm); err != nil {
		return fmt.Errorf("writeto: %w", err)
	}

	return nil
}

// sendPacketIPv6 sends a VRRPv3 IPv6 advertisement.
// Source: link-local address, Destination: ff02::12, Hop Limit: 255.
func (vi *vrrpInstance) sendPacketIPv6(pkt *VRRPPacket) error {
	if vi.ipv6Conn == nil {
		return nil
	}

	srcIP := vi.localIPv6
	if srcIP == nil {
		// Lazy resolve: deterministically select the lowest link-local
		// address. This happens when the interface didn't have a
		// link-local at openSocket() time (e.g. DAD still running).
		vipSet := make(map[string]bool, len(vi.cfg.VirtualAddresses))
		for _, vip := range vi.cfg.VirtualAddresses {
			addr := vip
			if idx := strings.Index(addr, "/"); idx >= 0 {
				addr = addr[:idx]
			}
			vipSet[addr] = true
		}
		resolved := vi.resolveIPv6LinkLocal(vipSet)
		if resolved != nil {
			vi.localIPv6 = resolved
			srcIP = resolved
			slog.Info("vrrp: late-resolved IPv6 link-local address",
				"key", vi.key(), "addr", srcIP)
		}
		if srcIP == nil {
			slog.Warn("vrrp: no link-local IPv6 address, skipping IPv6 advert",
				"key", vi.key(), "interface", vi.cfg.Interface)
			return fmt.Errorf("no link-local IPv6 address on %s", vi.cfg.Interface)
		}
	}

	dstIP := net.ParseIP("ff02::12")

	data, err := pkt.Marshal(true, srcIP, dstIP)
	if err != nil {
		return err
	}

	// Don't set Zone — the socket already has IPV6_MULTICAST_IF bound
	// to the interface. Setting Zone on the destination can cause EINVAL
	// on some kernels when the socket option is already set.
	dst := &net.IPAddr{
		IP: dstIP,
	}
	if _, err := vi.ipv6Conn.WriteTo(data, dst); err != nil {
		return fmt.Errorf("ipv6 writeto: %w", err)
	}

	return nil
}

// addVIPs adds virtual IP addresses to the interface via netlink.
func (vi *vrrpInstance) addVIPs() {
	link, err := netlink.LinkByName(vi.cfg.Interface)
	if err != nil {
		slog.Warn("vrrp: failed to find interface for VIP add",
			"key", vi.key(), "err", err)
		return
	}
	for _, vip := range vi.cfg.VirtualAddresses {
		addr, err := netlink.ParseAddr(vip)
		if err != nil {
			slog.Warn("vrrp: failed to parse VIP",
				"key", vi.key(), "vip", vip, "err", err)
			continue
		}
		// Skip DAD for IPv6 VIPs — VRRP handles ownership; DAD would
		// fail because the secondary may still have the address briefly.
		if addr.IP.To4() == nil {
			addr.Flags |= unix.IFA_F_NODAD
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			// EEXIST is fine — address already present.
			if !strings.Contains(err.Error(), "exists") {
				slog.Warn("vrrp: failed to add VIP",
					"key", vi.key(), "vip", vip, "err", err)
			}
		} else {
			slog.Info("vrrp: added VIP", "key", vi.key(), "vip", vip)
		}
	}
}

// removeVIPs removes virtual IP addresses from the interface via netlink.
func (vi *vrrpInstance) removeVIPs() {
	link, err := netlink.LinkByName(vi.cfg.Interface)
	if err != nil {
		slog.Debug("vrrp: failed to find interface for VIP remove",
			"key", vi.key(), "err", err)
		return
	}
	for _, vip := range vi.cfg.VirtualAddresses {
		addr, err := netlink.ParseAddr(vip)
		if err != nil {
			continue
		}
		if err := netlink.AddrDel(link, addr); err != nil {
			// Ignore "not found" — may have been removed already.
			if !strings.Contains(err.Error(), "not found") &&
				!strings.Contains(err.Error(), "no such") {
				slog.Debug("vrrp: failed to remove VIP",
					"key", vi.key(), "vip", vip, "err", err)
			}
		}
	}
}

// minGARPInterval is the minimum spacing between GARP bursts (dampening).
const minGARPInterval = 500 * time.Millisecond

// garpDampened reports whether a GARP burst should be suppressed given the
// wall-clock UnixNano of the previous burst and of now. A negative elapsed
// (backward wall-clock step — time.Unix(0, last) carries no monotonic
// reading) is treated as send-allowed: dampening for the step duration would
// suppress failover GARP bursts and blackhole traffic right after becoming
// MASTER (#1792). The storage stays wall-clock; the clamp alone closes the
// hazard, and an extra GARP burst after a forward step is harmless.
func garpDampened(lastNanos, nowNanos int64) bool {
	if lastNanos <= 0 {
		return false
	}
	elapsed := time.Duration(nowNanos - lastNanos)
	return elapsed >= 0 && elapsed < minGARPInterval
}

// garpSendAllowed reports whether sendGARP should proceed to emit a burst,
// given the current epoch state and whether the caller requested a forced
// send. It centralises the two suppression gates so the decision can be
// unit-tested without performing real network I/O:
//
//   - Epoch dedup: skip if a GARP for the current garpEpoch was already
//     completed (lastGARPEpoch == garpEpoch, epoch > 0). This applies to
//     BOTH forced and non-forced sends — a forced caller is expected to bump
//     garpEpoch first (see ReconcileVIPs/becomeMaster), so the dedup only
//     suppresses a genuine duplicate for the same transition, never the
//     intended forced send.
//   - Time dampener: skip if the previous burst was < minGARPInterval ago
//     (garpDampened). This applies to the NORMAL (force == false) path only,
//     to rate-limit routine/periodic GARP during rapid VRRP flaps. A forced
//     send BYPASSES the dampener: ReconcileVIPs runs after programRethMAC
//     changed the RETH virtual MAC, so peers hold a stale ARP entry and the
//     post-MAC-change GARP is critical even if a routine GARP happened to be
//     emitted within the last 500ms — otherwise traffic blackholes until the
//     stale ARP ages out (#2081).
func (vi *vrrpInstance) garpSendAllowed(force bool, nowNanos int64) bool {
	epoch := vi.garpEpoch.Load()
	if vi.lastGARPEpoch.Load() == epoch && epoch > 0 {
		slog.Debug("vrrp: GARP already sent for this epoch",
			"key", vi.key(), "epoch", epoch)
		return false
	}
	if force {
		// Forced sends (post-MAC-change reconcile via ReconcileVIPs) bypass
		// the time dampener — the dampener exists only to rate-limit routine
		// GARP and must never suppress a MAC-change correction (#2081). Note
		// the becomeMaster path (including manual takeover via ForceRGMaster)
		// is intentionally NOT forced: it does not change the MAC, so it stays
		// subject to the dampener.
		return true
	}
	if last := vi.lastGARPTime.Load(); garpDampened(last, nowNanos) {
		slog.Debug("vrrp: GARP dampened (too soon)",
			"key", vi.key(), "elapsed", time.Duration(nowNanos-last))
		return false
	}
	return true
}

// arpProbeFn is the gateway ARP-probe sender used by sendGARP. It is a
// package var so tests can capture the sender/target sendGARP passes,
// proving the probe carries the VIP (not the interface primary) as the ARP
// sender (#2152) without performing real AF_PACKET I/O.
var arpProbeFn = cluster.SendARPProbe

// sendGARP sends gratuitous ARP (IPv4) and unsolicited NA (IPv6) for all VIPs.
// Uses burst mode: one immediate pair then background follow-ups at 50ms intervals.
// After each IPv4 GARP burst, also sends a standard ARP probe to the subnet's
// gateway (.1) address. Some routers ignore gratuitous ARP but always update
// their ARP cache when they receive a standard ARP Request with the VIP as
// the source address.
//
// force bypasses the 500ms time dampener (but not the per-epoch dedup) so a
// post-MAC-change reconcile GARP is always emitted; see garpSendAllowed.
//
// This method may be called in a goroutine from becomeMaster().
func (vi *vrrpInstance) sendGARP(force bool) {
	epoch := vi.garpEpoch.Load()
	if !vi.garpSendAllowed(force, time.Now().UnixNano()) {
		return
	}
	count := vi.cfg.GARPCount
	if count <= 0 {
		count = 3 // default
	}
	for _, vip := range vi.cfg.VirtualAddresses {
		ip, ipNet, err := net.ParseCIDR(vip)
		if err != nil {
			continue
		}
		if ip.To4() != nil {
			if err := cluster.SendGratuitousARPBurst(vi.cfg.Interface, ip, count); err != nil {
				slog.Warn("vrrp: GARP failed", "key", vi.key(), "vip", ip, "err", err)
			}
			// Probe the .1 address of the VIP subnet — this is the most
			// common gateway address. The ARP Request's source IP/MAC
			// forces the gateway to update its ARP cache for our VIP.
			gwIP := make(net.IP, 4)
			copy(gwIP, ipNet.IP.To4())
			gwIP[3] = 1
			if !gwIP.Equal(ip.To4()) {
				// Send the probe with the VIP as the ARP sender so the
				// gateway re-binds VIP -> our (new) MAC, not the primary
				// IP -> MAC (#2152).
				if err := arpProbeFn(vi.cfg.Interface, ip.To4(), gwIP); err != nil {
					slog.Warn("vrrp: gateway ARP probe failed",
						"key", vi.key(), "gw", gwIP, "err", err)
				} else {
					slog.Info("vrrp: probed subnet gateway",
						"key", vi.key(), "gw", gwIP, "interface", vi.cfg.Interface)
				}
			}
		} else {
			if err := cluster.SendGratuitousIPv6Burst(vi.cfg.Interface, ip, count); err != nil {
				slog.Warn("vrrp: NA failed", "key", vi.key(), "vip", ip, "err", err)
			}
		}
	}
	vi.lastGARPEpoch.Store(epoch)
	vi.lastGARPTime.Store(time.Now().UnixNano())
}

// resolveIPv6LinkLocal deterministically selects the lowest non-VIP
// link-local IPv6 address on the interface. Sorting ensures the same
// address is always chosen regardless of kernel enumeration order,
// even when multiple link-locals exist (e.g. after MAC changes).
func (vi *vrrpInstance) resolveIPv6LinkLocal(vipSet map[string]bool) net.IP {
	addrs, err := vi.iface.Addrs()
	if err != nil {
		return nil
	}
	var candidates []net.IP
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.To4() != nil {
			continue
		}
		if !ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		if vipSet[ipNet.IP.String()] {
			continue
		}
		candidates = append(candidates, ipNet.IP)
	}
	if len(candidates) == 0 {
		return nil
	}
	// Sort and pick lowest for determinism.
	sort.Slice(candidates, func(i, j int) bool {
		return bytes.Compare(candidates[i], candidates[j]) < 0
	})
	return candidates[0]
}

// warnRXDrop increments the drop counter and logs a rate-limited warning.
func (vi *vrrpInstance) warnRXDrop() {
	drops := vi.rxDrops.Add(1)
	now := time.Now()
	if now.Sub(vi.lastDropWarn) >= 10*time.Second {
		vi.lastDropWarn = now
		slog.Warn("vrrp: rx channel full, dropping advertisements",
			"key", vi.key(), "total_drops", drops)
	}
}

// stop signals the instance goroutine to stop and waits for it to finish.
func (vi *vrrpInstance) stop() {
	close(vi.stopCh)

	// Close sockets to unblock any blocking recvmsg in receiver().
	if vi.conn != nil {
		vi.conn.Close()
	}
	if vi.ipv6Conn != nil {
		vi.ipv6Conn.Close()
	}
	if vi.afPacketFD >= 0 {
		unix.Close(vi.afPacketFD)
		vi.afPacketFD = -1
	}

	<-vi.stopped
}
