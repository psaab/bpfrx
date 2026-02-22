package vrrp

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
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
	mu      sync.RWMutex
	cfg     Instance
	state   VRRPState
	iface   *net.Interface
	eventCh chan<- VRRPEvent
	localIP net.IP // our IPv4 address on this interface (for filtering self-sent)

	// Per-instance raw socket and receiver.
	conn    net.PacketConn
	rawConn *ipv4.RawConn

	// AF_PACKET socket for receiving on VLAN sub-interfaces.
	// Raw IP sockets don't reliably receive multicast on VLAN
	// sub-interfaces (kernel limitation). AF_PACKET captures at
	// the link layer and works correctly. -1 means not used.
	afPacketFD int

	rxCh    chan *VRRPPacket
	stopCh  chan struct{}
	stopped chan struct{}
}

func newInstance(cfg Instance, iface *net.Interface, eventCh chan<- VRRPEvent) *vrrpInstance {
	return &vrrpInstance{
		cfg:        cfg,
		state:      StateInitialize,
		iface:      iface,
		eventCh:    eventCh,
		afPacketFD: -1,
		rxCh:       make(chan *VRRPPacket, 16),
		stopCh:     make(chan struct{}),
		stopped:    make(chan struct{}),
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

	// For VLAN sub-interfaces, open an AF_PACKET socket for receiving.
	// Raw IP sockets don't reliably receive multicast on VLAN sub-
	// interfaces (kernel limitation — IpInDelivers counts the packet
	// but recvmsg on the raw socket never returns it). AF_PACKET
	// captures at the link layer and works correctly (tcpdump proves
	// it). The raw IP socket is kept for sending advertisements.
	if isVLAN {
		fd, err := openAfPacketReceiver(vi.iface.Index)
		if err != nil {
			slog.Warn("vrrp: af_packet open failed, raw socket only",
				"key", vi.key(), "err", err)
		} else {
			vi.afPacketFD = fd
		}
	}

	// Resolve our local IPv4 address (primary IP, not a VIP) for:
	// 1. Source address in VRRP advertisements
	// 2. Filtering self-sent packets
	// We must skip VIP addresses because during split-brain both nodes
	// have the VIP — using it as source would cause the peer to filter
	// our adverts as "self-sent" (matching its own VIP).
	vipSet := make(map[string]bool, len(vi.cfg.VirtualAddresses))
	for _, vip := range vi.cfg.VirtualAddresses {
		addr := vip
		if idx := strings.Index(addr, "/"); idx >= 0 {
			addr = addr[:idx]
		}
		vipSet[addr] = true
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
			break
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
	vi.mu.Unlock()
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
func (vi *vrrpInstance) advertInterval() time.Duration {
	sec := vi.cfg.AdvertiseInterval
	if sec <= 0 {
		sec = 1
	}
	return time.Duration(sec) * time.Second
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
	// VLAN sub-interfaces use AF_PACKET because raw IP sockets
	// don't receive multicast on VLAN sub-interfaces.
	if vi.afPacketFD >= 0 {
		go vi.receiverAfPacket()
	} else {
		go vi.receiver()
	}

	// Transition to Backup state.
	vi.setState(StateBackup)
	vi.emitEvent()

	masterDownTimer := time.NewTimer(vi.masterDownInterval())
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
			}

		case StateMaster:
			select {
			case <-vi.stopCh:
				// Send priority-0 advertisement to signal resignation.
				vi.sendAdvert(0)
				vi.removeVIPs()
				return
			case pkt := <-vi.rxCh:
				vi.handleMasterRx(pkt, masterDownTimer, advertTimer)
			case <-advertTimer.C:
				vi.sendAdvert(vi.getPriority())
				advertTimer.Reset(vi.advertInterval())
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
		default:
			// Drop if channel full.
		}
	}
}

// receiverAfPacket reads VRRP packets via AF_PACKET on VLAN sub-interfaces.
// Uses SOCK_RAW + ETH_P_ALL (same as tcpdump) — receives full Ethernet frames.
// We skip the 14-byte Ethernet header, then parse IP header + VRRP payload.
func (vi *vrrpInstance) receiverAfPacket() {
	const ethHeaderLen = 14
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

		// Minimum: 14-byte Ethernet + 20-byte IP + 8-byte VRRP.
		if n < ethHeaderLen+20+vrrpHeaderLen {
			continue
		}

		// Skip Ethernet header.
		ip := buf[ethHeaderLen:]
		ipLen := n - ethHeaderLen

		// Parse IP header.
		ihl := int(ip[0]&0x0F) * 4
		if ihl < 20 || ipLen < ihl+vrrpHeaderLen {
			continue
		}

		ttl := int(ip[8])

		// Verify TTL == 255 (RFC 5798 §5.1.1.3).
		if ttl != 255 {
			continue
		}

		srcIP := make(net.IP, 4)
		copy(srcIP, ip[12:16])

		// Filter self-sent packets (RFC 5798 §6.4.2/6.4.3).
		if vi.localIP != nil && srcIP.Equal(vi.localIP) {
			continue
		}

		payload := ip[ihl:ipLen]

		// Only accept packets matching our VRID.
		if payload[1] != uint8(vi.cfg.GroupID) {
			continue
		}

		dstIP := make(net.IP, 4)
		copy(dstIP, ip[16:20])

		pkt, err := ParseVRRPPacket(payload, false, srcIP, dstIP)
		if err != nil {
			slog.Debug("vrrp: parse error", "key", vi.key(), "err", err)
			continue
		}

		select {
		case vi.rxCh <- pkt:
		default:
			// Drop if channel full.
		}
	}
}

// handleBackupRx processes a received advertisement while in Backup state.
func (vi *vrrpInstance) handleBackupRx(pkt *VRRPPacket, masterDownTimer *time.Timer) {
	pri := vi.getPriority()
	if pkt.Priority == 0 {
		// Master is resigning — use short timer.
		skew := time.Duration(256-pri) * vi.advertInterval() / 256
		masterDownTimer.Reset(skew)
		return
	}

	// If we don't preempt, or the incoming priority is >= ours, accept it.
	if !vi.getPreempt() || int(pkt.Priority) >= pri {
		masterDownTimer.Reset(vi.masterDownInterval())
	}
	// If preempt is true and incoming priority < ours, ignore — let timer expire.
}

// handleMasterRx processes a received advertisement while in Master state.
func (vi *vrrpInstance) handleMasterRx(pkt *VRRPPacket, masterDownTimer, advertTimer *time.Timer) {
	pri := vi.getPriority()
	if pkt.Priority == 0 {
		// Peer resigning — send immediate advert and stay Master.
		vi.sendAdvert(pri)
		advertTimer.Reset(vi.advertInterval())
		return
	}

	// If incoming priority is higher, step down.
	if int(pkt.Priority) > pri {
		vi.becomeBackup(masterDownTimer, advertTimer)
	}
	// Equal or lower priority: ignore (we stay Master).
}

// becomeMaster transitions to Master state: add VIPs, send GARP/NA, send advert.
func (vi *vrrpInstance) becomeMaster() {
	pri := vi.getPriority()
	slog.Info("vrrp: transitioning to MASTER",
		"key", vi.key(), "priority", pri)
	vi.setState(StateMaster)
	vi.addVIPs()
	vi.sendGARP()
	vi.sendAdvert(pri)
	vi.emitEvent()
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
	select {
	case vi.eventCh <- VRRPEvent{
		Interface: vi.cfg.Interface,
		GroupID:   vi.cfg.GroupID,
		State:     vi.getState(),
		VIPs:      vi.cfg.VirtualAddresses,
	}:
	default:
		// Drop if channel full — non-blocking.
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
		maxAdvert := uint16(vi.cfg.AdvertiseInterval * 100) // seconds → centiseconds
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
		maxAdvert := uint16(vi.cfg.AdvertiseInterval * 100)
		pkt := &VRRPPacket{
			VRID:         uint8(vi.cfg.GroupID),
			Priority:     uint8(priority),
			MaxAdvertInt: maxAdvert,
			IPAddresses:  v6Addrs,
		}
		// IPv6 VRRP not yet implemented (would need ip6:112 socket).
		_ = pkt
	}
}

// sendPacket sends a VRRP advertisement via the per-instance raw socket.
func (vi *vrrpInstance) sendPacket(pkt *VRRPPacket, isIPv6 bool) error {
	if isIPv6 || vi.rawConn == nil {
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
func (vi *vrrpInstance) sendGARP() {
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
			if err := cluster.SendGratuitousARP(vi.cfg.Interface, ip, 3); err != nil {
				slog.Debug("vrrp: GARP failed", "key", vi.key(), "vip", addr, "err", err)
			}
		} else {
			if err := cluster.SendGratuitousIPv6(vi.cfg.Interface, ip, 3); err != nil {
				slog.Debug("vrrp: NA failed", "key", vi.key(), "vip", addr, "err", err)
			}
		}
	}
}

// stop signals the instance goroutine to stop and waits for it to finish.
func (vi *vrrpInstance) stop() {
	close(vi.stopCh)

	// Close sockets to unblock any blocking recvmsg in receiver().
	if vi.conn != nil {
		vi.conn.Close()
	}
	if vi.afPacketFD >= 0 {
		unix.Close(vi.afPacketFD)
		vi.afPacketFD = -1
	}

	<-vi.stopped
}
