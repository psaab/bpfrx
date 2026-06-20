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
	ChassisID  string // chassis identifier (MAC or string)
	PortID     string // port identifier (interface name)
	TTL        int    // advertised hold time in seconds
	SystemName string
	SystemDesc string
	PortDesc   string
	LastSeen   time.Time
	ExpiresAt  time.Time
	Interface  string // local interface where neighbor was seen
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
	// sessions are the per-interface RX/TX sockets for the current Apply
	// generation. Stop() closes each one to unblock the parked RX Recvfrom
	// immediately, so shutdown does not wait out a read timeout. Guarded by mu.
	sessions []*ifSession
}

// ifSession owns the RX and TX AF_PACKET sockets for one interface for the life
// of an Apply() generation. close() shuts down and closes rxFD, which makes a
// parked unix.Recvfrom in the RX goroutine return immediately, so Stop() does
// not block waiting out a read timeout. This mirrors the close-to-unblock
// pattern VRRP uses for its receiver (pkg/vrrp/instance.go stop()).
type ifSession struct {
	iface     *net.Interface
	rxFD      int // AF_PACKET bound to ifindex, ETH_P_LLDP
	txFD      int // AF_PACKET for periodic Sendto, opened once and reused
	closeOnce sync.Once

	// recvFn, when non-nil, replaces the real unix.Recvfrom-based recv. It is
	// the test seam for exercising rxLoop's transient-error handling (EINTR /
	// EAGAIN retry vs fatal exit) deterministically, without a real socket or
	// signal delivery. Production leaves it nil.
	recvFn func(buf []byte) (int, error)
}

// newIfSessionFn is the construction seam for ifSession. Tests override it to
// inject a socketpair(2)-backed session so the Stop-unblocks-recv contract can
// be exercised without CAP_NET_RAW or a real interface.
var newIfSessionFn = newIfSession

// newIfSession opens and binds the RX socket and opens the TX socket for one
// interface. Both fds live for the Apply generation and are released by close().
func newIfSession(iface *net.Interface) (*ifSession, error) {
	rxFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(etherTypeLLDP)))
	if err != nil {
		return nil, fmt.Errorf("lldp: rx socket: %w", err)
	}
	if err := unix.Bind(rxFD, &unix.SockaddrLinklayer{
		Protocol: htons(etherTypeLLDP),
		Ifindex:  iface.Index,
	}); err != nil {
		unix.Close(rxFD)
		return nil, fmt.Errorf("lldp: rx bind: %w", err)
	}
	// No SO_RCVTIMEO: recv blocks indefinitely and is unblocked by closing the
	// fd in close(), not by a polling timeout.

	txFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		unix.Close(rxFD)
		return nil, fmt.Errorf("lldp: tx socket: %w", err)
	}

	return &ifSession{iface: iface, rxFD: rxFD, txFD: txFD}, nil
}

// recv reads one frame from the RX socket. It blocks until a frame arrives or
// the fd is closed by close().
func (s *ifSession) recv(buf []byte) (int, error) {
	if s.recvFn != nil {
		return s.recvFn(buf)
	}
	n, _, err := unix.Recvfrom(s.rxFD, buf, 0)
	return n, err
}

// send transmits an LLDP frame to the multicast destination on the bound
// interface over the reused TX socket.
func (s *ifSession) send(frame []byte) error {
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(etherTypeLLDP),
		Ifindex:  s.iface.Index,
		Halen:    6,
	}
	copy(addr.Addr[:6], LLDPMulticast)
	return unix.Sendto(s.txFD, frame, 0, addr)
}

// close releases both sockets. It is idempotent (closeOnce) so a double-close
// from a racing Stop cannot panic or double-free.
//
// shutdown(SHUT_RDWR) precedes close on rxFD on purpose: closing an fd that
// another goroutine is actively blocked reading on is NOT a reliable wakeup —
// the fd number is freed but the in-flight Recvfrom can stay parked. shutdown
// reliably wakes a blocked reader. On a connectionless AF_PACKET socket shutdown
// returns ENOTCONN (harmless, ignored) and the subsequent close is what tears
// down the RX queue and unblocks recv (the pattern VRRP relies on); on a
// connection-oriented socket (the socketpair used in tests) shutdown is the
// authoritative wakeup. Doing both is correct for either socket family.
func (s *ifSession) close() {
	s.closeOnce.Do(func() {
		_ = unix.Shutdown(s.rxFD, unix.SHUT_RDWR)
		unix.Close(s.rxFD)
		if s.txFD != s.rxFD {
			unix.Close(s.txFD)
		}
	})
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
		sysName = "xpf"
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

		// Open the RX+TX sockets once for this interface. A CAP_NET_RAW or bind
		// failure now surfaces here (logged, interface skipped) instead of
		// silently per-frame.
		sess, err := newIfSessionFn(iface)
		if err != nil {
			slog.Warn("LLDP: socket setup failed, skipping interface",
				"interface", lldpIf.Name, "err", err)
			continue
		}
		m.mu.Lock()
		m.sessions = append(m.sessions, sess)
		m.mu.Unlock()

		// Start TX goroutine.
		m.wg.Add(1)
		go func(sess *ifSession) {
			defer m.wg.Done()
			m.txLoop(lldpCtx, sess, interval, holdMult, sysName, cfg.SystemDesc)
		}(sess)

		// Start RX goroutine.
		m.wg.Add(1)
		go func(sess *ifSession) {
			defer m.wg.Done()
			m.rxLoop(lldpCtx, sess)
		}(sess)

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
//
// Ordering is load-bearing: cancel the context (stops the timer-driven TX and
// expiry loops), then close every session's sockets (unblocks any RX goroutine
// parked in recv immediately), then wg.Wait(). Closing the fds BEFORE the wait
// is what makes Stop bounded — waiting first would re-introduce the read-timeout
// stall. The close-under-read race is benign: a recv on a just-closed fd returns
// an error and the RX loop treats any post-cancel error as "shutdown, return".
func (m *Manager) Stop() {
	m.mu.Lock()
	sessions := m.sessions
	m.sessions = nil
	m.mu.Unlock()

	if m.cancel != nil {
		m.cancel()
		// Close sockets to unblock any blocking Recvfrom in rxLoop.
		for _, s := range sessions {
			s.close()
		}
		m.wg.Wait()
		m.cancel = nil
	} else {
		// Defensive: close any sessions even if cancel was never set (no
		// goroutines should be running, but never leak an fd).
		for _, s := range sessions {
			s.close()
		}
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

// txLoop periodically sends LLDP frames on the session's interface, reusing the
// session's TX socket for every advertisement.
func (m *Manager) txLoop(ctx context.Context, sess *ifSession, interval time.Duration, holdMult int, sysName, sysDesc string) {
	ttl := int(interval.Seconds()) * holdMult

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Send first frame immediately.
	m.sendFrame(sess, ttl, sysName, sysDesc)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.sendFrame(sess, ttl, sysName, sysDesc)
		}
	}
}

// sendFrame builds and sends a single LLDP frame over the session's reused TX
// socket.
func (m *Manager) sendFrame(sess *ifSession, ttl int, sysName, sysDesc string) {
	iface := sess.iface
	frame, err := BuildFrame(iface.HardwareAddr, iface.Name, ttl, sysName, sysDesc)
	if err != nil {
		// Fail closed: skip this advertisement rather than send a malformed
		// frame with a wrapped TLV length (#2036).
		slog.Warn("LLDP TX: skipping frame with overlength TLV", "interface", iface.Name, "err", err)
		return
	}

	if err := sess.send(frame); err != nil {
		slog.Debug("LLDP TX: send error", "interface", iface.Name, "err", err)
	}
}

// rxLoop receives LLDP frames on the session's interface and updates the
// neighbor table. The RX socket has no read timeout: recv blocks until a frame
// arrives or Stop() closes the fd, at which point Recvfrom returns an error and
// the loop exits. This makes Stop() return promptly instead of waiting out a
// read timeout.
func (m *Manager) rxLoop(ctx context.Context, sess *ifSession) {
	iface := sess.iface
	buf := make([]byte, 1600)
	for {
		n, err := sess.recv(buf)
		if err != nil {
			// Transient, non-fatal recv errors must not kill neighbor
			// discovery on a long-running daemon. EINTR can be delivered to a
			// goroutine (e.g. a signal forwarded through the Go runtime before
			// it can be masked); EAGAIN/EWOULDBLOCK is the spurious-wakeup case
			// (the RX socket is blocking with no SO_RCVTIMEO, so this should not
			// occur, but retrying is the only safe response if it ever does).
			// Retry rather than silently terminating the RX loop.
			if err == unix.EINTR || err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			// recv was unblocked. If the context is cancelled, this is the
			// expected close-to-unblock on Stop(); return. Otherwise it is an
			// unexpected socket error (e.g. interface gone) — also return, since
			// the fd is the session's only RX source and there is no timeout to
			// retry against.
			if ctx.Err() != nil {
				return
			}
			slog.Debug("LLDP RX: recv error, stopping", "interface", iface.Name, "err", err)
			return
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

// BuildFrame constructs a complete LLDP Ethernet frame. It fails closed if any
// variable-length identity TLV (system name/description, port description)
// exceeds the 9-bit TLV length limit, rather than emitting a malformed
// advertisement (#2036).
func BuildFrame(srcMAC net.HardwareAddr, portName string, ttl int, sysName, sysDesc string) ([]byte, error) {
	var tlvs []byte
	// Chassis ID (MAC = 7 bytes) and TTL (2 bytes) are compile-time bounded.
	tlvs = append(tlvs, mustEncodeTLV(tlvChassisID, encodeChassisID(srcMAC))...)
	// Port ID carries portName which is caller-supplied: propagate error rather
	// than panic so BuildFrame stays consistently fail-closed (#2036).
	portIDEnc, err := EncodeTLV(tlvPortID, encodePortID(portName))
	if err != nil {
		return nil, err
	}
	tlvs = append(tlvs, portIDEnc...)
	tlvs = append(tlvs, mustEncodeTLV(tlvTTL, encodeTTL(ttl))...)
	// Variable-length identity TLVs: fail closed on overlength rather than
	// shipping a frame whose wrapped 9-bit length desynchronizes the receiver.
	optional := []struct {
		typ int
		val []byte
		on  bool
	}{
		{tlvSystemName, []byte(sysName), sysName != ""},
		{tlvSystemDesc, []byte(sysDesc), sysDesc != ""},
		{tlvPortDesc, []byte(portName), portName != ""},
	}
	for _, o := range optional {
		if !o.on {
			continue
		}
		enc, err := EncodeTLV(o.typ, o.val)
		if err != nil {
			return nil, err
		}
		tlvs = append(tlvs, enc...)
	}
	tlvs = append(tlvs, mustEncodeTLV(tlvEnd, nil)...) // End TLV

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
	return frame, nil
}

// maxTLVValueLen is the largest value an LLDP TLV can carry: the length field
// is 9 bits, so 511 bytes. A larger value would wrap the header length while
// the full payload stayed in the frame, so a receiver would misparse the
// overflow as following TLVs — a malformed advertisement (#2036).
const maxTLVValueLen = 0x1ff

// EncodeTLV encodes a single LLDP TLV (type-length-value). It FAILS CLOSED on
// an overlength value rather than masking the 9-bit length and emitting a
// malformed frame — advertised identity must not be silently lossy.
// TLV header: 7 bits type + 9 bits length = 2 bytes.
func EncodeTLV(tlvType int, value []byte) ([]byte, error) {
	length := len(value)
	if length > maxTLVValueLen {
		return nil, fmt.Errorf("lldp: TLV type %d value is %d bytes, exceeds the %d-byte (9-bit) length limit",
			tlvType, length, maxTLVValueLen)
	}
	header := uint16(tlvType&0x7f)<<9 | uint16(length&0x1ff)
	out := make([]byte, 2+length)
	binary.BigEndian.PutUint16(out[:2], header)
	copy(out[2:], value)
	return out, nil
}

// mustEncodeTLV is EncodeTLV for callers whose value length is bounded at
// compile time (the End TLV) or by a hard OS/protocol limit (chassis ID = MAC
// = 7 bytes, TTL = 2 bytes) and so can never exceed the 9-bit limit. It panics
// if that invariant is ever violated rather than returning a malformed frame.
// Caller-supplied strings such as port ID must use EncodeTLV directly.
func mustEncodeTLV(tlvType int, value []byte) []byte {
	out, err := EncodeTLV(tlvType, value)
	if err != nil {
		panic(err)
	}
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
