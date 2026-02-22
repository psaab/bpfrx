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
	"golang.org/x/sys/unix"
)

// instanceKey identifies a unique VRRP instance.
type instanceKey struct {
	iface   string
	groupID int
}

// Manager manages all VRRP instances.
type Manager struct {
	mu        sync.RWMutex
	instances map[instanceKey]*vrrpInstance
	eventCh   chan VRRPEvent
	cancel    context.CancelFunc
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

		vi := newInstance(*inst, iface, m.eventCh)
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

// openPerInterfaceSocket creates a raw IP socket (proto 112) bound to
// the specified interface using SO_BINDTODEVICE, and joins the VRRP
// multicast group (224.0.0.18) on that interface.
// Returns the ipv4.RawConn and the underlying net.PacketConn.
func openPerInterfaceSocket(ifName string, iface *net.Interface) (*ipv4.RawConn, net.PacketConn, error) {
	// Open raw socket for VRRP (protocol 112).
	conn, err := net.ListenPacket("ip4:112", "0.0.0.0")
	if err != nil {
		return nil, nil, fmt.Errorf("listen ip4:112: %w", err)
	}

	// Get the underlying fd and bind to the interface.
	rawFile, err := conn.(*net.IPConn).File()
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("get fd: %w", err)
	}
	fd := rawFile.Fd()
	if err := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifName); err != nil {
		rawFile.Close()
		conn.Close()
		return nil, nil, fmt.Errorf("SO_BINDTODEVICE %s: %w", ifName, err)
	}
	rawFile.Close()

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
