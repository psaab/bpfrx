package vrrp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// instanceKey identifies a unique VRRP instance.
type instanceKey struct {
	iface   string
	groupID int
}

// Manager manages all VRRP instances.
type Manager struct {
	mu              sync.RWMutex
	instances       map[instanceKey]*vrrpInstance
	eventCh         chan VRRPEvent
	closeEventOnce  sync.Once   // guards closing eventCh
	cancel          context.CancelFunc
	syncHold        bool        // suppress preemption until session sync completes
	syncHoldTimer   *time.Timer // safety timeout to release hold
	syncHoldReason  string      // "bulk-sync-complete" or "timeout-degraded"
	onEventDrop     func()      // called when an event is dropped (full channel)
}

// SetOnEventDrop registers a callback invoked when a VRRP event is dropped
// due to a full channel. The daemon uses this to schedule an immediate
// reconciliation pass.
func (m *Manager) SetOnEventDrop(fn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onEventDrop = fn
}

// NewManager creates a new VRRP manager.
func NewManager() *Manager {
	return &Manager{
		instances: make(map[instanceKey]*vrrpInstance),
		eventCh:   make(chan VRRPEvent, 256),
	}
}

// Start initializes the manager (no shared socket — each instance has its own).
func (m *Manager) Start(ctx context.Context) error {
	_, m.cancel = context.WithCancel(ctx)
	slog.Info("vrrp: manager started")
	return nil
}

// Stop stops all instances, removes VIPs, and cancels the context.
func (m *Manager) Stop() {
	m.mu.Lock()
	if m.syncHoldTimer != nil {
		m.syncHoldTimer.Stop()
	}
	instances := make(map[instanceKey]*vrrpInstance, len(m.instances))
	for k, v := range m.instances {
		instances[k] = v
	}
	m.instances = make(map[instanceKey]*vrrpInstance)
	m.mu.Unlock()

	// Stop all instances (removes VIPs, sends priority-0, closes per-instance socket).
	for _, vi := range instances {
		vi.stop()
	}

	// Close events channel so watchers (e.g. daemon's watchVRRPEvents) unblock.
	m.closeEventOnce.Do(func() { close(m.eventCh) })

	if m.cancel != nil {
		m.cancel()
	}
	slog.Info("vrrp: manager stopped")
}

// SetSyncHold enables sync hold mode — all VRRP instances start with
// preempt=false regardless of config, suppressing preemption until session
// sync completes. A safety timeout releases the hold if sync never arrives.
func (m *Manager) SetSyncHold(timeout time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if m.syncHoldTimer != nil {
		m.syncHoldTimer.Stop()
		m.syncHoldTimer = nil
	}
	wasHeld := m.syncHold
	m.syncHold = true
	m.syncHoldReason = ""
	if !wasHeld {
		for _, vi := range m.instances {
			vi.suppressPreempt()
		}
	}
	m.syncHoldTimer = time.AfterFunc(timeout, func() {
		slog.Warn("vrrp: sync-hold timeout: bulk sync did not complete within timeout, releasing in degraded mode",
			"timeout", timeout)
		m.releaseSyncHoldWithReason("timeout-degraded")
	})
	slog.Info("vrrp: sync hold active, preemption disabled", "timeout", timeout)
}

// ReleaseSyncHold restores configured preempt values on all instances,
// allowing normal VRRP preemption to proceed. Records reason as
// "bulk-sync-complete" (the normal path).
func (m *Manager) ReleaseSyncHold() {
	m.releaseSyncHoldWithReason("bulk-sync-complete")
}

// releaseSyncHoldWithReason is the internal release path that records why
// the sync hold was released.
func (m *Manager) releaseSyncHoldWithReason(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.syncHold {
		return
	}
	m.syncHold = false
	m.syncHoldReason = reason
	if m.syncHoldTimer != nil {
		m.syncHoldTimer.Stop()
		m.syncHoldTimer = nil
	}
	for _, vi := range m.instances {
		vi.restorePreempt()
		vi.triggerPreemptNow()
	}
	slog.Info("vrrp: sync hold released, preemption enabled", "reason", reason)
}

// InSyncHold returns true if the manager is in sync-hold state (startup,
// waiting for session sync before allowing preemption).
func (m *Manager) InSyncHold() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.syncHold
}

// SyncHoldReason returns why the sync hold was released: "bulk-sync-complete"
// for normal operation, "timeout-degraded" if the safety timeout fired before
// bulk sync arrived, or "" if sync hold was never set or is still active.
func (m *Manager) SyncHoldReason() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.syncHoldReason
}

// Events returns the event channel for state change notifications.
func (m *Manager) Events() <-chan VRRPEvent {
	return m.eventCh
}

// UpdateInstances diffs the current instances against the desired set and
// adds/removes/updates as needed.
func (m *Manager) UpdateInstances(desired []*Instance) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Build desired map.
	desiredMap := make(map[instanceKey]*Instance, len(desired))
	for _, inst := range desired {
		key := instanceKey{iface: inst.Interface, groupID: inst.GroupID}
		desiredMap[key] = inst
	}

	// Remove instances no longer desired.
	for key, vi := range m.instances {
		if _, ok := desiredMap[key]; !ok {
			slog.Info("vrrp: removing instance", "key", vi.key())
			vi.stop()
			delete(m.instances, key)
		}
	}

	// Add or update instances.
	for key, inst := range desiredMap {
		existing, ok := m.instances[key]
		if ok {
			// Check if config changed.
			if existing.cfg.Priority == inst.Priority &&
				existing.cfg.Preempt == inst.Preempt &&
				vipsEqual(existing.cfg.VirtualAddresses, inst.VirtualAddresses) {
				continue // No change.
			}
			// If only priority/preempt changed, update in-place without
			// stopping. Restarting would cause a 3s master-down gap where
			// the node falsely becomes MASTER before hearing the peer.
			if vipsEqual(existing.cfg.VirtualAddresses, inst.VirtualAddresses) {
				slog.Info("vrrp: priority update", "key", existing.key(),
					"old_pri", existing.cfg.Priority, "new_pri", inst.Priority)
				instCfg := *inst
				if m.syncHold {
					instCfg.Preempt = false
				}
				existing.updateConfig(instCfg)
				if m.syncHold {
					existing.setDesiredPreempt(inst.Preempt)
				}
				continue
			}
			// VIPs changed — must restart instance.
			slog.Info("vrrp: restarting instance", "key", existing.key(),
				"old_pri", existing.cfg.Priority, "new_pri", inst.Priority)
			existing.stop()
			delete(m.instances, key)
		}

		// Create new instance.
		iface, err := net.InterfaceByName(inst.Interface)
		if err != nil {
			slog.Warn("vrrp: interface not found, skipping",
				"interface", inst.Interface, "err", err)
			continue
		}

		instCfg := *inst
		if m.syncHold {
			instCfg.Preempt = false
		}
		vi := newInstance(instCfg, iface, m.eventCh, m.onEventDrop)
		// Store the real configured preempt value for when sync hold releases.
		vi.desiredPreempt = inst.Preempt
		if err := vi.openSocket(); err != nil {
			slog.Warn("vrrp: failed to open socket",
				"interface", inst.Interface, "err", err)
			continue
		}
		m.instances[key] = vi

		go vi.run()
	}

	return nil
}

// ResignRG forces all VRRP instances for the given redundancy group
// to resign by sending priority-0 adverts and transitioning to BACKUP.
// Also immediately sets the instance priority to 0 to prevent
// re-election before the debounced priority update fires.
// Used when cluster state transitions from Primary to Secondary
// (manual failover, weight drop, etc.) in non-preempt mode.
func (m *Manager) ResignRG(rgID int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	vrid := 100 + rgID
	for _, vi := range m.instances {
		if vi.cfg.GroupID == vrid {
			// Set priority to 0 BEFORE triggering resign. Without this,
			// the masterDown timer (~97ms) can fire before the debounced
			// priority update (500ms), causing the instance to re-elect
			// at the old high priority and knock the peer back to BACKUP.
			vi.mu.Lock()
			vi.cfg.Priority = 0
			vi.mu.Unlock()
			vi.triggerResign()
		}
	}
}

// UpdateRGPriority immediately sets the VRRP priority for all instances
// belonging to the given redundancy group. Used to restore priority
// after ResignRG set it to 0 — e.g. when a cluster event transitions
// the RG back to Primary before the debounced VRRP update fires.
func (m *Manager) UpdateRGPriority(rgID int, priority int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	vrid := 100 + rgID
	for _, vi := range m.instances {
		if vi.cfg.GroupID == vrid {
			vi.mu.Lock()
			old := vi.cfg.Priority
			vi.cfg.Priority = priority
			vi.mu.Unlock()
			if old != priority {
				slog.Info("vrrp: immediate priority update",
					"key", vi.key(), "old_pri", old, "new_pri", priority)
			}
		}
	}
}

// ForceRGMaster forces all VRRP instances for the given redundancy group
// to become MASTER, even with preempt=false. Used when the cluster state
// machine has determined this node is primary for the RG but VRRP hasn't
// transitioned (e.g. after failover reset with preempt=false).
// Uses a one-shot forcePreemptOnce flag instead of modifying cfg.Preempt,
// so the configured preempt value is never leaked.
func (m *Manager) ForceRGMaster(rgID int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	vrid := 100 + rgID
	for _, vi := range m.instances {
		if vi.cfg.GroupID == vrid && vi.getState() != StateMaster {
			slog.Info("vrrp: forcing MASTER (cluster authoritative)",
				"key", vi.key())
			vi.mu.Lock()
			vi.forcePreemptOnce = true
			vi.mu.Unlock()
			vi.triggerPreemptNow()
		}
	}
}

// ReconcileVIPs re-adds VIPs on any MASTER instances. Call this after
// operations that may remove addresses (e.g. programRethMAC link down/up).
func (m *Manager) ReconcileVIPs() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, vi := range m.instances {
		if vi.getState() == StateMaster {
			vi.addVIPs()
			vi.sendGARP()
		}
	}
}

// States returns the current state of all instances.
// Key format: "VI_<iface>_<group>" → "MASTER", "BACKUP", "INIT".
func (m *Manager) States() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	states := make(map[string]string, len(m.instances))
	for _, vi := range m.instances {
		states[vi.key()] = vi.getState().String()
	}
	return states
}

// InstanceStates returns structured per-instance state. Each entry contains
// the interface name, group ID, and current VRRP state. Used by the
// reconciliation loop to verify that rg_active and blackhole routes match
// actual VRRP state.
func (m *Manager) InstanceStates() []VRRPEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]VRRPEvent, 0, len(m.instances))
	for _, vi := range m.instances {
		out = append(out, VRRPEvent{
			Interface: vi.cfg.Interface,
			GroupID:   vi.cfg.GroupID,
			State:     vi.getState(),
		})
	}
	return out
}

// RXDropStats returns per-instance RX drop and received counts.
// Key format: "VI_<iface>_<group>".
func (m *Manager) RXDropStats() map[string]uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]uint64, len(m.instances)*2)
	for _, vi := range m.instances {
		k := vi.key()
		stats[k+"/drops"] = vi.rxDrops.Load()
		stats[k+"/received"] = vi.rxReceived.Load()
	}
	return stats
}

// Status returns a formatted multi-line status string.
func (m *Manager) Status() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.instances) == 0 {
		return "VRRP: no instances configured\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("VRRP: %d instance(s) running\n\n", len(m.instances)))

	// Sort keys for deterministic output.
	keys := make([]instanceKey, 0, len(m.instances))
	for k := range m.instances {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].iface != keys[j].iface {
			return keys[i].iface < keys[j].iface
		}
		return keys[i].groupID < keys[j].groupID
	})

	for _, key := range keys {
		vi := m.instances[key]
		state := vi.getState()
		sb.WriteString(fmt.Sprintf("  %s: state=%s, priority=%d, preempt=%t, interval=%dms\n",
			vi.key(), state, vi.cfg.Priority, vi.cfg.Preempt, vi.cfg.AdvertiseInterval))
		for _, vip := range vi.cfg.VirtualAddresses {
			sb.WriteString(fmt.Sprintf("    VIP: %s\n", vip))
		}
	}

	return sb.String()
}

// openPerInterfaceSocket creates a raw IP socket (proto 112) and joins the
// VRRP multicast group (224.0.0.18) on the given interface.
// For non-VLAN interfaces, SO_BINDTODEVICE is used for isolation.
// For VLAN sub-interfaces, SO_BINDTODEVICE is skipped because generic XDP
// VLAN handling makes the kernel's interface association unpredictable —
// the packet may be delivered on the parent or sub-interface depending on
// when VLAN stripping occurs. The VRID filter in receiver() provides demuxing.
func openPerInterfaceSocket(ifName string, iface *net.Interface, isVLAN bool) (*ipv4.RawConn, net.PacketConn, error) {
	// Open raw socket for VRRP (protocol 112).
	conn, err := net.ListenPacket("ip4:112", "0.0.0.0")
	if err != nil {
		return nil, nil, fmt.Errorf("listen ip4:112: %w", err)
	}

	// For plain (non-VLAN) interfaces, bind to the interface via SyscallConn
	// (avoids File() which sets blocking mode and removes the fd from Go's poller).
	if !isVLAN {
		sc, err := conn.(*net.IPConn).SyscallConn()
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("syscall conn: %w", err)
		}
		var bindErr error
		if err := sc.Control(func(fd uintptr) {
			bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifName)
		}); err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("control: %w", err)
		}
		if bindErr != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("SO_BINDTODEVICE %s: %w", ifName, bindErr)
		}
	}

	rawConn, err := ipv4.NewRawConn(conn)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("raw conn: %w", err)
	}

	// Join VRRP multicast group on this interface.
	group := net.IPv4(224, 0, 0, 18)
	if err := rawConn.JoinGroup(iface, &net.IPAddr{IP: group}); err != nil {
		slog.Debug("vrrp: join multicast failed", "interface", ifName, "err", err)
	}

	return rawConn, conn, nil
}

// openAfPacketReceiver opens an AF_PACKET SOCK_DGRAM socket bound to the
// given interface for receiving VRRP packets. This is used on VLAN sub-
// interfaces where raw IP sockets don't reliably receive multicast.
// SOCK_DGRAM strips the Ethernet header — received data starts at the IP header.
func openAfPacketReceiver(ifIndex int) (int, error) {
	// Use ETH_P_ALL (same as tcpdump) — VLAN sub-interface + multicast
	// delivery is unreliable with ETH_P_IP protocol filtering.
	proto := htons(unix.ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(proto))
	if err != nil {
		return -1, fmt.Errorf("af_packet socket: %w", err)
	}

	// Bind to specific interface.
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: proto,
		Ifindex:  ifIndex,
	}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind af_packet to ifindex %d: %w", ifIndex, err)
	}

	// Receive timeout so the receiver goroutine can check stopCh.
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("set rcvtimeo: %w", err)
	}

	// Promiscuous mode is required to receive multicast frames from
	// remote peers on VLAN sub-interfaces. Without it, only locally-
	// generated multicast (IP-layer loopback) is delivered. This matches
	// tcpdump's behavior, which also sets PACKET_MR_PROMISC.
	mreq := &unix.PacketMreq{
		Ifindex: int32(ifIndex),
		Type:    unix.PACKET_MR_PROMISC,
	}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, mreq); err != nil {
		slog.Debug("vrrp: failed to set promisc", "err", err)
	}

	// BPF filter: accept VRRP (proto/next-header 112) for IPv4, IPv6,
	// and 802.1Q-tagged variants. SOCK_RAW includes the Ethernet header.
	// Protocol/next-header offsets:
	//   IPv4 untagged:  ethertype 0x0800 @12, proto @23 (14+9)
	//   IPv6 untagged:  ethertype 0x86DD @12, next-hdr @20 (14+6)
	//   IPv4 802.1Q:    ethertype 0x8100 @12, real 0x0800 @16, proto @27 (18+9)
	//   IPv6 802.1Q:    ethertype 0x8100 @12, real 0x86DD @16, next-hdr @24 (18+6)
	//
	// Jump offsets (Jt/Jf) are relative to the NEXT instruction.
	filter := []unix.SockFilter{
		{Code: 0x28, K: 12},                     //  0: ldh [12] — ethertype
		{Code: 0x15, Jt: 7, Jf: 0, K: 0x0800},  //  1: jeq 0x0800 → 9 (check_ipv4)
		{Code: 0x15, Jt: 10, Jf: 0, K: 0x86DD}, //  2: jeq 0x86DD → 13 (check_ipv6)
		{Code: 0x15, Jt: 1, Jf: 0, K: 0x8100},  //  3: jeq 0x8100 → 5 (check_vlan); else reject
		{Code: 0x06, K: 0},                      //  4: ret reject
		// check_vlan:
		{Code: 0x28, K: 16},                     //  5: ldh [16] — real ethertype
		{Code: 0x15, Jt: 10, Jf: 0, K: 0x0800}, //  6: jeq 0x0800 → 17 (check_ipv4_vlan)
		{Code: 0x15, Jt: 13, Jf: 0, K: 0x86DD}, //  7: jeq 0x86DD → 21 (check_ipv6_vlan)
		{Code: 0x06, K: 0},                      //  8: ret reject
		// check_ipv4: proto at 14+9=23
		{Code: 0x30, K: 23},                     //  9: ldb [23]
		{Code: 0x15, Jt: 0, Jf: 1, K: 112},     // 10: jeq 112 → accept; else reject
		{Code: 0x06, K: 0xFFFFFFFF},             // 11: ret accept
		{Code: 0x06, K: 0},                      // 12: ret reject
		// check_ipv6: next-header at 14+6=20
		{Code: 0x30, K: 20},                     // 13: ldb [20]
		{Code: 0x15, Jt: 0, Jf: 1, K: 112},     // 14: jeq 112 → accept; else reject
		{Code: 0x06, K: 0xFFFFFFFF},             // 15: ret accept
		{Code: 0x06, K: 0},                      // 16: ret reject
		// check_ipv4_vlan: proto at 18+9=27
		{Code: 0x30, K: 27},                     // 17: ldb [27]
		{Code: 0x15, Jt: 0, Jf: 1, K: 112},     // 18: jeq 112 → accept; else reject
		{Code: 0x06, K: 0xFFFFFFFF},             // 19: ret accept
		{Code: 0x06, K: 0},                      // 20: ret reject
		// check_ipv6_vlan: next-header at 18+6=24
		{Code: 0x30, K: 24},                     // 21: ldb [24]
		{Code: 0x15, Jt: 0, Jf: 1, K: 112},     // 22: jeq 112 → accept; else reject
		{Code: 0x06, K: 0xFFFFFFFF},             // 23: ret accept
		{Code: 0x06, K: 0},                      // 24: ret reject
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("attach bpf filter: %w", err)
	}

	return fd, nil
}

// openIPv6Socket creates a raw IPv6 socket (IPPROTO_VRRP = 112) bound to
// the given interface for sending VRRPv3 IPv6 advertisements.
// Returns the PacketConn and the raw fd for setsockopt operations.
func openIPv6Socket(ifName string, iface *net.Interface) (net.PacketConn, int, error) {
	conn, err := net.ListenPacket("ip6:112", "::")
	if err != nil {
		return nil, -1, fmt.Errorf("listen ip6:112: %w", err)
	}

	sc, err := conn.(*net.IPConn).SyscallConn()
	if err != nil {
		conn.Close()
		return nil, -1, fmt.Errorf("syscall conn: %w", err)
	}

	var fd int
	var bindErr error
	if err := sc.Control(func(rawfd uintptr) {
		fd = int(rawfd)
		// Bind to interface.
		bindErr = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifName)
		if bindErr != nil {
			return
		}
		// Set hop limit to 255 (RFC 5798 requirement).
		bindErr = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255)
		if bindErr != nil {
			return
		}
		bindErr = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, 255)
		if bindErr != nil {
			return
		}
		// Set multicast interface.
		bindErr = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_IF, iface.Index)
	}); err != nil {
		conn.Close()
		return nil, -1, fmt.Errorf("control: %w", err)
	}
	if bindErr != nil {
		conn.Close()
		return nil, -1, fmt.Errorf("ipv6 socket setup on %s: %w", ifName, bindErr)
	}

	// Join VRRP IPv6 multicast group (ff02::12).
	mreq := &unix.IPv6Mreq{
		Interface: uint32(iface.Index),
	}
	copy(mreq.Multiaddr[:], net.ParseIP("ff02::12").To16())
	if err := sc.Control(func(rawfd uintptr) {
		// Ignore error — may fail if group already joined.
		_ = unix.SetsockoptIPv6Mreq(int(rawfd), unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, mreq)
	}); err != nil {
		slog.Debug("vrrp: ipv6 join multicast failed", "interface", ifName, "err", err)
	}

	return conn, fd, nil
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	b := [2]byte{}
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// vipsEqual compares two VIP slices for equality.
func vipsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
