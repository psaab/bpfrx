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
	mu            sync.RWMutex
	instances     map[instanceKey]*vrrpInstance
	eventCh       chan VRRPEvent
	cancel        context.CancelFunc
	syncHold      bool        // suppress preemption until session sync completes
	syncHoldTimer *time.Timer // safety timeout to release hold
}

// NewManager creates a new VRRP manager.
func NewManager() *Manager {
	return &Manager{
		instances: make(map[instanceKey]*vrrpInstance),
		eventCh:   make(chan VRRPEvent, 64),
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
	m.syncHold = true
	m.syncHoldTimer = time.AfterFunc(timeout, func() {
		slog.Warn("vrrp: sync hold timeout expired, releasing")
		m.ReleaseSyncHold()
	})
	slog.Info("vrrp: sync hold active, preemption disabled", "timeout", timeout)
}

// ReleaseSyncHold restores configured preempt values on all instances,
// allowing normal VRRP preemption to proceed.
func (m *Manager) ReleaseSyncHold() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.syncHold {
		return
	}
	m.syncHold = false
	if m.syncHoldTimer != nil {
		m.syncHoldTimer.Stop()
	}
	for _, vi := range m.instances {
		vi.restorePreempt()
		vi.triggerPreemptNow()
	}
	slog.Info("vrrp: sync hold released, preemption enabled")
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
				existing.updateConfig(*inst)
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
		vi := newInstance(instCfg, iface, m.eventCh)
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

	// BPF filter: accept only IPv4 VRRP (ethertype 0x0800, proto 112).
	// SOCK_RAW includes the Ethernet header, so offsets are:
	//   12-13: ethertype
	//   23: IP protocol (14 + 9)
	filter := []unix.SockFilter{
		{Code: 0x28, K: 12},                    // ldh [12] — ethertype
		{Code: 0x15, Jt: 0, Jf: 3, K: 0x0800}, // jeq #0x0800, check proto; else reject
		{Code: 0x30, K: 23},                     // ldb [23] — IP protocol
		{Code: 0x15, Jt: 0, Jf: 1, K: 112},     // jeq #112 → accept; else reject
		{Code: 0x06, K: 0xFFFFFFFF},             // ret accept
		{Code: 0x06, K: 0},                      // ret reject
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
