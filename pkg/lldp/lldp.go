// Package lldp implements the Link Layer Discovery Protocol (IEEE 802.1AB).
//
// It provides periodic LLDP frame transmission and reception on configured
// interfaces, maintaining a neighbor table with TTL-based expiry.
package lldp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// LLDP constants.
var (
	// LLDPMulticast is the standard LLDP destination MAC address.
	LLDPMulticast = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
)

const (
	etherTypeLLDP = 0x88cc

	// TLV types per IEEE 802.1AB.
	tlvEnd            = 0
	tlvChassisID      = 1
	tlvPortID         = 2
	tlvTTL            = 3
	tlvPortDesc       = 4
	tlvSystemName     = 5
	tlvSystemDesc     = 6
	tlvSystemCap      = 7
	tlvManagementAddr = 8

	// Chassis ID subtypes.
	chassisSubtypeMACAddr = 4

	// Port ID subtypes.
	portSubtypeIfName = 5

	// Default LLDP transmit interval and hold multiplier.
	defaultInterval       = 30 * time.Second
	defaultHoldMultiplier = 4

	// Ethernet header length.
	ethHdrLen = 14
)

// Neighbor represents a discovered LLDP neighbor on an interface.
type Neighbor struct {
	ChassisID   string // chassis identifier (MAC or string)
	PortID      string // port identifier (interface name)
	TTL         int    // advertised hold time in seconds
	SystemName  string
	SystemDesc  string
	PortDesc    string
	LastSeen    time.Time
	ExpiresAt   time.Time
	Interface   string // local interface where neighbor was seen
}

// LLDPInterface holds per-interface LLDP configuration.
type LLDPInterface struct {
	Name    string
	Disable bool // per-interface disable
}

// LLDPConfig holds LLDP protocol configuration.
type LLDPConfig struct {
	Interfaces     []LLDPInterface // interfaces to enable LLDP on
	Interval       int             // transmit interval in seconds (0 = default 30)
	HoldMultiplier int             // hold multiplier (0 = default 4)
	SystemName     string          // system name TLV (defaults to hostname)
	SystemDesc     string          // system description TLV
	Disable        bool            // globally disable LLDP
}

// Manager runs LLDP transmit/receive goroutines and maintains the neighbor table.
type Manager struct {
	mu        sync.RWMutex
	neighbors map[string]*Neighbor // key: "ifname/chassisID/portID"
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// New creates a new LLDP manager.
func New() *Manager {
	return &Manager{
		neighbors: make(map[string]*Neighbor),
	}
}

// Apply starts LLDP on the configured interfaces.
func (m *Manager) Apply(ctx context.Context, cfg *LLDPConfig) {
	m.Stop()

	if cfg == nil || cfg.Disable || len(cfg.Interfaces) == 0 {
		return
	}

	lldpCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	interval := time.Duration(cfg.Interval) * time.Second
	if interval <= 0 {
		interval = defaultInterval
	}
	holdMult := cfg.HoldMultiplier
	if holdMult <= 0 {
		holdMult = defaultHoldMultiplier
	}

	sysName := cfg.SystemName
	if sysName == "" {
		sysName = "bpfrx"
	}

	for _, lldpIf := range cfg.Interfaces {
		if lldpIf.Disable {
			continue
		}
		iface, err := net.InterfaceByName(lldpIf.Name)
		if err != nil {
			slog.Warn("LLDP: interface not found", "interface", lldpIf.Name, "err", err)
			continue
		}

		// Start TX goroutine.
		m.wg.Add(1)
		go func(iface *net.Interface) {
			defer m.wg.Done()
			m.txLoop(lldpCtx, iface, interval, holdMult, sysName, cfg.SystemDesc)
		}(iface)

		// Start RX goroutine.
		m.wg.Add(1)
		go func(iface *net.Interface) {
			defer m.wg.Done()
			m.rxLoop(lldpCtx, iface)
		}(iface)

		slog.Info("LLDP started", "interface", lldpIf.Name, "interval", interval)
	}

	// Start neighbor expiry goroutine.
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.expiryLoop(lldpCtx)
	}()
}

// Stop halts all LLDP goroutines and clears the neighbor table.
func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
		m.wg.Wait()
		m.cancel = nil
	}
	m.mu.Lock()
	m.neighbors = make(map[string]*Neighbor)
	m.mu.Unlock()
}

// Neighbors returns a sorted snapshot of all discovered neighbors.
func (m *Manager) Neighbors() []*Neighbor {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]string, 0, len(m.neighbors))
	for k := range m.neighbors {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]*Neighbor, 0, len(keys))
	for _, k := range keys {
		n := m.neighbors[k]
		cp := *n
		out = append(out, &cp)
	}
	return out
}

// txLoop periodically sends LLDP frames on the given interface.
func (m *Manager) txLoop(ctx context.Context, iface *net.Interface, interval time.Duration, holdMult int, sysName, sysDesc string) {
	ttl := int(interval.Seconds()) * holdMult

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Send first frame immediately.
	m.sendFrame(iface, ttl, sysName, sysDesc)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.sendFrame(iface, ttl, sysName, sysDesc)
		}
	}
}

// sendFrame builds and sends a single LLDP frame on the interface.
func (m *Manager) sendFrame(iface *net.Interface, ttl int, sysName, sysDesc string) {
	frame := BuildFrame(iface.HardwareAddr, iface.Name, ttl, sysName, sysDesc)

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		slog.Debug("LLDP TX: socket error", "interface", iface.Name, "err", err)
		return
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrLinklayer{
		Protocol: htons(etherTypeLLDP),
		Ifindex:  iface.Index,
		Halen:    6,
	}
	copy(addr.Addr[:6], LLDPMulticast)

	if err := unix.Sendto(fd, frame, 0, addr); err != nil {
		slog.Debug("LLDP TX: send error", "interface", iface.Name, "err", err)
	}
}

// rxLoop receives LLDP frames on the given interface and updates the neighbor table.
func (m *Manager) rxLoop(ctx context.Context, iface *net.Interface) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(etherTypeLLDP)))
	if err != nil {
		slog.Warn("LLDP RX: socket error", "interface", iface.Name, "err", err)
		return
	}
	defer unix.Close(fd)

	// Bind to specific interface.
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(etherTypeLLDP),
		Ifindex:  iface.Index,
	}); err != nil {
		slog.Warn("LLDP RX: bind error", "interface", iface.Name, "err", err)
		return
	}

	// Set a read timeout so we check for ctx cancellation periodically.
	tv := unix.Timeval{Sec: 2}
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	buf := make([]byte, 1600)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			// Timeout — just loop and check ctx.
			continue
		}
		if n < ethHdrLen {
			continue
		}

		// Skip Ethernet header (dst[6] + src[6] + ethertype[2]).
		neighbor := ParseTLVs(buf[ethHdrLen:n])
		if neighbor == nil {
			continue
		}
		neighbor.Interface = iface.Name
		neighbor.LastSeen = time.Now()
		neighbor.ExpiresAt = time.Now().Add(time.Duration(neighbor.TTL) * time.Second)

		key := fmt.Sprintf("%s/%s/%s", iface.Name, neighbor.ChassisID, neighbor.PortID)
		m.mu.Lock()
		m.neighbors[key] = neighbor
		m.mu.Unlock()
	}
}

// expiryLoop periodically removes expired neighbors.
func (m *Manager) expiryLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			m.mu.Lock()
			for key, n := range m.neighbors {
				if now.After(n.ExpiresAt) {
					slog.Info("LLDP neighbor expired",
						"interface", n.Interface,
						"chassis", n.ChassisID,
						"port", n.PortID)
					delete(m.neighbors, key)
				}
			}
			m.mu.Unlock()
		}
	}
}

// BuildFrame constructs a complete LLDP Ethernet frame.
func BuildFrame(srcMAC net.HardwareAddr, portName string, ttl int, sysName, sysDesc string) []byte {
	var tlvs []byte
	tlvs = append(tlvs, EncodeTLV(tlvChassisID, encodeChassisID(srcMAC))...)
	tlvs = append(tlvs, EncodeTLV(tlvPortID, encodePortID(portName))...)
	tlvs = append(tlvs, EncodeTLV(tlvTTL, encodeTTL(ttl))...)
	if sysName != "" {
		tlvs = append(tlvs, EncodeTLV(tlvSystemName, []byte(sysName))...)
	}
	if sysDesc != "" {
		tlvs = append(tlvs, EncodeTLV(tlvSystemDesc, []byte(sysDesc))...)
	}
	if portName != "" {
		tlvs = append(tlvs, EncodeTLV(tlvPortDesc, []byte(portName))...)
	}
	tlvs = append(tlvs, EncodeTLV(tlvEnd, nil)...) // End TLV

	// Build Ethernet frame: dst(6) + src(6) + ethertype(2) + payload.
	frame := make([]byte, 0, ethHdrLen+len(tlvs))
	frame = append(frame, LLDPMulticast...)
	if len(srcMAC) >= 6 {
		frame = append(frame, srcMAC[:6]...)
	} else {
		frame = append(frame, 0, 0, 0, 0, 0, 0)
	}
	frame = append(frame, byte(etherTypeLLDP>>8), byte(etherTypeLLDP&0xff))
	frame = append(frame, tlvs...)
	return frame
}

// EncodeTLV encodes a single LLDP TLV (type-length-value).
// TLV header: 7 bits type + 9 bits length = 2 bytes.
func EncodeTLV(tlvType int, value []byte) []byte {
	length := len(value)
	header := uint16(tlvType&0x7f)<<9 | uint16(length&0x1ff)
	out := make([]byte, 2+length)
	binary.BigEndian.PutUint16(out[:2], header)
	copy(out[2:], value)
	return out
}

func encodeChassisID(mac net.HardwareAddr) []byte {
	// Subtype (1 byte) + MAC address (6 bytes).
	val := make([]byte, 7)
	val[0] = chassisSubtypeMACAddr
	if len(mac) >= 6 {
		copy(val[1:], mac[:6])
	}
	return val
}

func encodePortID(name string) []byte {
	// Subtype (1 byte) + interface name.
	val := make([]byte, 1+len(name))
	val[0] = portSubtypeIfName
	copy(val[1:], name)
	return val
}

func encodeTTL(seconds int) []byte {
	val := make([]byte, 2)
	binary.BigEndian.PutUint16(val, uint16(seconds))
	return val
}

// ParseTLVs parses LLDP TLVs from raw payload (after Ethernet header).
// Returns nil if mandatory TLVs (Chassis ID, Port ID, TTL) are missing.
func ParseTLVs(data []byte) *Neighbor {
	n := &Neighbor{}
	hasChassis, hasPort, hasTTL := false, false, false

	for len(data) >= 2 {
		header := binary.BigEndian.Uint16(data[:2])
		tlvType := int(header >> 9)
		tlvLen := int(header & 0x1ff)
		data = data[2:]

		if tlvLen > len(data) {
			break
		}
		value := data[:tlvLen]
		data = data[tlvLen:]

		switch tlvType {
		case tlvEnd:
			goto done
		case tlvChassisID:
			if len(value) >= 2 && value[0] == chassisSubtypeMACAddr && len(value) >= 7 {
				n.ChassisID = net.HardwareAddr(value[1:7]).String()
			} else if len(value) >= 2 {
				n.ChassisID = string(value[1:])
			}
			hasChassis = true
		case tlvPortID:
			if len(value) >= 2 && value[0] == portSubtypeIfName {
				n.PortID = string(value[1:])
			} else if len(value) >= 2 {
				n.PortID = string(value[1:])
			}
			hasPort = true
		case tlvTTL:
			if len(value) >= 2 {
				n.TTL = int(binary.BigEndian.Uint16(value[:2]))
			}
			hasTTL = true
		case tlvSystemName:
			n.SystemName = string(value)
		case tlvSystemDesc:
			n.SystemDesc = string(value)
		case tlvPortDesc:
			n.PortDesc = string(value)
		}
	}

done:
	if !hasChassis || !hasPort || !hasTTL {
		return nil
	}
	return n
}

func htons(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return binary.NativeEndian.Uint16(b)
}
