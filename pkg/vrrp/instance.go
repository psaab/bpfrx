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

	"github.com/psaab/bpfrx/pkg/cluster"
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
	state            VRRPState
	iface            *net.Interface
	eventCh          chan<- VRRPEvent
	localIP          net.IP // our IPv4 address on this interface (for filtering self-sent)
	localIPv6        net.IP // our link-local IPv6 address (source for IPv6 VRRP adverts)

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
	rxDrops    atomic.Uint64 // packets dropped due to full rxCh
	rxReceived atomic.Uint64 // total packets delivered to rxCh
	lastDropWarn time.Time    // last time we logged a drop warning (rate-limited)

	// GARP suppression for strict-vip-ownership mode.
	suppressGARP  atomic.Bool   // when true, becomeMaster() skips GARP/NA
	garpEpoch     atomic.Uint64 // incremented on each becomeMaster() transition
	lastGARPEpoch atomic.Uint64 // epoch of last completed sendGARP()
	lastGARPTime  atomic.Int64  // Unix nanos of last GARP send (dampening)

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

// updateConfig updates priority and preempt in-place without restarting.
func (vi *vrrpInstance) updateConfig(cfg Instance) {
	vi.mu.Lock()
	vi.cfg.Priority = cfg.Priority
	vi.cfg.Preempt = cfg.Preempt
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

func (vi *vrrpInstance) getPriority() int {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.cfg.Priority
}

func (vi *vrrpInstance) getPreempt() bool {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.cfg.Preempt
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
			select {
			case <-vi.stopCh:
				return
			case pkt := <-vi.rxCh:
				vi.handleBackupRx(pkt, masterDownTimer)
			case <-masterDownTimer.C:
				// Master timed out — become Master.
				vi.becomeMaster()
				advertTimer.Reset(vi.advertInterval())
			case <-vi.preemptNowCh:
				// Coordinated preemption from ReleaseSyncHold or forced
				// transition from ForceRGMaster. The forcePreemptOnce flag
				// allows a one-shot preemption even when preempt=false,
				// without leaking into the configured preempt value.
				vi.mu.Lock()
				force := vi.forcePreemptOnce
				vi.forcePreemptOnce = false
				vi.mu.Unlock()
				if vi.getPreempt() || force {
					vi.becomeMaster()
					advertTimer.Reset(vi.advertInterval())
					masterDownTimer.Stop()
				}
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
				// Stop the masterDown timer entirely after forced resignation.
				// With short RETH intervals (30ms), masterDownInterval() at
				// priority 0 is only ~120ms, which re-elects the resigned node
				// before the peer can take over. Even with an extended timer,
				// the resigned node would re-elect as MASTER and send
				// high-priority adverts that keep the peer in BACKUP,
				// creating a split-brain. The resigned node should only
				// become MASTER via:
				//   - preemptNowCh (cluster ForceRGMaster after failover reset)
				//   - priority-0 from peer (peer resigning)
				// This matches Junos behavior: manual failover stays until reset.
				masterDownTimer.Stop()
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
// IPv6 header: 40 bytes fixed, next-header at offset 6, hop limit at offset 7,
// source at 8-24, destination at 24-40.
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

	payload := ip6[ipv6HeaderLen:ip6Len]
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

// handleBackupRx processes a received advertisement while in Backup state.
func (vi *vrrpInstance) handleBackupRx(pkt *VRRPPacket, masterDownTimer *time.Timer) {
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
		go vi.sendGARP()
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

// sendGARP sends gratuitous ARP (IPv4) and unsolicited NA (IPv6) for all VIPs.
// Uses burst mode: one immediate pair then background follow-ups at 50ms intervals.
// After each IPv4 GARP burst, also sends a standard ARP probe to the subnet's
// gateway (.1) address. Some routers ignore gratuitous ARP but always update
// their ARP cache when they receive a standard ARP Request with the VIP as
// the source address.
//
// This method may be called in a goroutine from becomeMaster().
func (vi *vrrpInstance) sendGARP() {
	epoch := vi.garpEpoch.Load()
	if vi.lastGARPEpoch.Load() == epoch && epoch > 0 {
		slog.Debug("vrrp: GARP already sent for this epoch",
			"key", vi.key(), "epoch", epoch)
		return
	}
	// Dampening: minimum 500ms between GARP bursts to avoid storms
	// during rapid VRRP flaps.
	const minGARPInterval = 500 * time.Millisecond
	if last := vi.lastGARPTime.Load(); last > 0 {
		if time.Since(time.Unix(0, last)) < minGARPInterval {
			slog.Debug("vrrp: GARP dampened (too soon)",
				"key", vi.key(), "elapsed", time.Since(time.Unix(0, last)))
			return
		}
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
				if err := cluster.SendARPProbe(vi.cfg.Interface, gwIP); err != nil {
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
