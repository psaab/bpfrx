package vrrp

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

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
	mu           sync.RWMutex
	cfg          Instance
	state        VRRPState
	iface        *net.Interface
	eventCh      chan<- VRRPEvent
	sendFn       func(ifName string, pkt *VRRPPacket, isIPv6 bool) error
	rxCh         chan *VRRPPacket
	stopCh       chan struct{}
	stopped      chan struct{}
}

func newInstance(cfg Instance, iface *net.Interface, eventCh chan<- VRRPEvent,
	sendFn func(string, *VRRPPacket, bool) error) *vrrpInstance {
	return &vrrpInstance{
		cfg:     cfg,
		state:   StateInitialize,
		iface:   iface,
		eventCh: eventCh,
		sendFn:  sendFn,
		rxCh:    make(chan *VRRPPacket, 16),
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

func (vi *vrrpInstance) key() string {
	return fmt.Sprintf("VI_%s_%d", vi.cfg.Interface, vi.cfg.GroupID)
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
	skew := time.Duration(256-vi.cfg.Priority) * advert / 256
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
				vi.sendAdvert(vi.cfg.Priority)
				advertTimer.Reset(vi.advertInterval())
			}
		}
	}
}

// handleBackupRx processes a received advertisement while in Backup state.
func (vi *vrrpInstance) handleBackupRx(pkt *VRRPPacket, masterDownTimer *time.Timer) {
	if pkt.Priority == 0 {
		// Master is resigning — use short timer.
		skew := time.Duration(256-vi.cfg.Priority) * vi.advertInterval() / 256
		masterDownTimer.Reset(skew)
		return
	}

	// If we don't preempt, or the incoming priority is >= ours, accept it.
	if !vi.cfg.Preempt || int(pkt.Priority) >= vi.cfg.Priority {
		masterDownTimer.Reset(vi.masterDownInterval())
	}
	// If preempt is true and incoming priority < ours, ignore — let timer expire.
}

// handleMasterRx processes a received advertisement while in Master state.
func (vi *vrrpInstance) handleMasterRx(pkt *VRRPPacket, masterDownTimer, advertTimer *time.Timer) {
	if pkt.Priority == 0 {
		// Peer resigning — send immediate advert and stay Master.
		vi.sendAdvert(vi.cfg.Priority)
		advertTimer.Reset(vi.advertInterval())
		return
	}

	// If incoming priority is higher, step down.
	if int(pkt.Priority) > vi.cfg.Priority {
		vi.becomeBackup(masterDownTimer, advertTimer)
	}
	// Equal or lower priority: ignore (we stay Master).
}

// becomeMaster transitions to Master state: add VIPs, send GARP/NA, send advert.
func (vi *vrrpInstance) becomeMaster() {
	slog.Info("vrrp: transitioning to MASTER",
		"key", vi.key(), "priority", vi.cfg.Priority)
	vi.setState(StateMaster)
	vi.addVIPs()
	vi.sendGARP()
	vi.sendAdvert(vi.cfg.Priority)
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
		if err := vi.sendFn(vi.cfg.Interface, pkt, false); err != nil {
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
		if err := vi.sendFn(vi.cfg.Interface, pkt, true); err != nil {
			slog.Debug("vrrp: failed to send IPv6 advert",
				"key", vi.key(), "err", err)
		}
	}
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
	<-vi.stopped
}
