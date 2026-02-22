package vrrp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"

	"golang.org/x/net/ipv4"
)

// instanceKey identifies a unique VRRP instance.
type instanceKey struct {
	iface   string
	groupID int
}

// Manager manages all VRRP instances and the shared raw socket.
type Manager struct {
	mu        sync.RWMutex
	instances map[instanceKey]*vrrpInstance
	eventCh   chan VRRPEvent
	conn      net.PacketConn
	rawConn   *ipv4.RawConn
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewManager creates a new VRRP manager.
func NewManager() *Manager {
	return &Manager{
		instances: make(map[instanceKey]*vrrpInstance),
		eventCh:   make(chan VRRPEvent, 64),
	}
}

// Start opens the raw VRRP socket and starts the receiver goroutine.
func (m *Manager) Start(ctx context.Context) error {
	conn, err := net.ListenPacket("ip4:112", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("vrrp: listen ip4:112: %w", err)
	}
	m.conn = conn

	rawConn, err := ipv4.NewRawConn(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("vrrp: raw conn: %w", err)
	}
	m.rawConn = rawConn

	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.receiver(ctx)

	slog.Info("vrrp: manager started")
	return nil
}

// Stop stops all instances, removes VIPs, and closes the socket.
func (m *Manager) Stop() {
	m.mu.Lock()
	instances := make(map[instanceKey]*vrrpInstance, len(m.instances))
	for k, v := range m.instances {
		instances[k] = v
	}
	m.instances = make(map[instanceKey]*vrrpInstance)
	m.mu.Unlock()

	// Stop all instances (removes VIPs, sends priority-0).
	for _, vi := range instances {
		vi.stop()
	}

	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()

	if m.conn != nil {
		m.conn.Close()
	}
	slog.Info("vrrp: manager stopped")
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
			m.leaveMulticast(key.iface)
			delete(m.instances, key)
		}
	}

	// Add or update instances.
	for key, inst := range desiredMap {
		existing, ok := m.instances[key]
		if ok {
			// Check if config changed (priority or VIPs).
			if existing.cfg.Priority == inst.Priority &&
				existing.cfg.Preempt == inst.Preempt &&
				vipsEqual(existing.cfg.VirtualAddresses, inst.VirtualAddresses) {
				continue // No change.
			}
			// Config changed — restart instance.
			slog.Info("vrrp: updating instance", "key", existing.key(),
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

		vi := newInstance(*inst, iface, m.eventCh, m.sendPacket)
		m.instances[key] = vi

		// Join multicast group on this interface.
		m.joinMulticast(inst.Interface)

		go vi.run()
	}

	return nil
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
		sb.WriteString(fmt.Sprintf("  %s: state=%s, priority=%d, preempt=%t, interval=%ds\n",
			vi.key(), state, vi.cfg.Priority, vi.cfg.Preempt, vi.cfg.AdvertiseInterval))
		for _, vip := range vi.cfg.VirtualAddresses {
			sb.WriteString(fmt.Sprintf("    VIP: %s\n", vip))
		}
	}

	return sb.String()
}

// receiver reads VRRP packets from the raw socket and dispatches to instances.
func (m *Manager) receiver(ctx context.Context) {
	defer m.wg.Done()

	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		hdr, payload, _, err := m.rawConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				slog.Debug("vrrp: read error", "err", err)
				continue
			}
		}

		// Verify TTL == 255 (RFC 5798 §5.1.1.3).
		if hdr.TTL != 255 {
			continue
		}

		if len(payload) < vrrpHeaderLen {
			continue
		}

		// Parse VRID from header to dispatch.
		vrid := payload[1]

		// Determine source/dest IPs for checksum verification.
		srcIP := hdr.Src
		dstIP := hdr.Dst

		pkt, err := ParseVRRPPacket(payload, false, srcIP, dstIP)
		if err != nil {
			slog.Debug("vrrp: parse error", "err", err)
			continue
		}

		// Dispatch to all instances matching this VRID.
		m.mu.RLock()
		for key, vi := range m.instances {
			if uint8(key.groupID) == vrid {
				select {
				case vi.rxCh <- pkt:
				default:
					// Drop if channel full.
				}
			}
		}
		m.mu.RUnlock()
	}
}

// sendPacket sends a VRRP advertisement on the specified interface.
func (m *Manager) sendPacket(ifName string, pkt *VRRPPacket, isIPv6 bool) error {
	if isIPv6 {
		// IPv6 VRRP not yet implemented (would need ip6:112 socket).
		return nil
	}

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return fmt.Errorf("interface %s: %w", ifName, err)
	}

	// Get interface's first IPv4 address as source.
	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("interface addrs %s: %w", ifName, err)
	}
	var srcIP net.IP
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.To4() != nil {
			srcIP = ipNet.IP.To4()
			break
		}
	}
	if srcIP == nil {
		return fmt.Errorf("no IPv4 address on %s", ifName)
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

	if err := m.rawConn.SetMulticastInterface(iface); err != nil {
		return fmt.Errorf("set multicast interface: %w", err)
	}

	cm := &ipv4.ControlMessage{
		IfIndex: iface.Index,
	}

	if err := m.rawConn.WriteTo(hdr, data, cm); err != nil {
		return fmt.Errorf("writeto: %w", err)
	}

	return nil
}

// joinMulticast joins the VRRP multicast group (224.0.0.18) on the interface.
func (m *Manager) joinMulticast(ifName string) {
	if m.rawConn == nil {
		return
	}
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		slog.Debug("vrrp: join multicast: interface not found", "interface", ifName, "err", err)
		return
	}
	group := net.IPv4(224, 0, 0, 18)
	if err := m.rawConn.JoinGroup(iface, &net.IPAddr{IP: group}); err != nil {
		slog.Debug("vrrp: join multicast failed", "interface", ifName, "err", err)
	}
}

// leaveMulticast leaves the VRRP multicast group on the interface.
func (m *Manager) leaveMulticast(ifName string) {
	if m.rawConn == nil {
		return
	}
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return
	}
	group := net.IPv4(224, 0, 0, 18)
	_ = m.rawConn.LeaveGroup(iface, &net.IPAddr{IP: group})
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
