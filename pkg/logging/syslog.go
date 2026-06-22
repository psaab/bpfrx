package logging

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Resilience defaults for the stream (TCP/TLS) transports. These bound the
// time the dataplane event hot-path can spend inside a single Send and rate-
// limit reconnect attempts so a down server cannot drive a fresh 5s-timeout
// dial on every event. UDP is connectionless and never blocks on Write, so
// these do not apply to it.
const (
	// defaultWriteTimeout caps how long a single conn.Write may block before
	// it is treated as a write failure (message dropped, reconnect armed).
	// Generous enough that a healthy server is never affected; short enough
	// that a hung server cannot stall the event reader.
	defaultWriteTimeout = 4 * time.Second
	// defaultReconnectCooldown is the minimum interval between dial attempts
	// after a dial failure. Within the window, a stream Send that needs a
	// reconnect fails fast (drops) instead of dialing — preventing a
	// thundering herd of 5s dials against a down server.
	defaultReconnectCooldown = 1 * time.Second
)

// Syslog severity levels (RFC 3164).
const (
	SyslogError   = 3
	SyslogWarning = 4
	SyslogInfo    = 6
)

// Syslog facility codes (RFC 3164).
const (
	FacilityKern     = 0
	FacilityUser     = 1
	FacilityDaemon   = 3
	FacilityAuth     = 4
	FacilitySyslog   = 5
	FacilityLocal0   = 16
	FacilityLocal1   = 17
	FacilityLocal2   = 18
	FacilityLocal3   = 19
	FacilityLocal4   = 20
	FacilityLocal5   = 21
	FacilityLocal6   = 22
	FacilityLocal7   = 23
)

// SyslogClient sends syslog messages over UDP, TCP, or TLS.
// Supports RFC 3164 (BSD) and RFC 5424 (structured-data syslog) formats.
// TCP/TLS use RFC 6587 octet-counting framing.
type SyslogClient struct {
	mu          sync.Mutex
	conn        net.Conn
	hostname    string
	remoteAddr  string
	sourceAddr  string
	protocol    string     // "udp", "tcp", "tls"
	tlsConfig   *tls.Config
	Facility    int    // syslog facility code (default: FacilityLocal0)
	MinSeverity int    // 0 = no filter, else SyslogError(3)/SyslogWarning(4)/SyslogInfo(6)
	Format      string // "sd-syslog" for RFC 5424, "structured" for Junos RT_FLOW, "" for RFC 3164
	Categories  uint8  // bitmask of allowed event categories (0 = all)

	// Stream-transport resilience (TCP/TLS). All guarded by mu except the
	// atomic counters, which are observability only.
	writeTimeout      time.Duration // per-Write deadline; 0 disables (UDP)
	reconnectCooldown time.Duration // min interval between dial attempts
	lastDialFailure   time.Time     // when the last dial failed (mu-guarded)
	lastDropLog       time.Time     // rate-limit for the drop warning (mu-guarded)

	droppedWrites   atomic.Uint64 // messages dropped on a write timeout/error
	droppedCooldown atomic.Uint64 // messages dropped because reconnect was in cooldown

	// Seams for deterministic testing. nil → real implementations.
	nowFn  func() time.Time          // clock source (default time.Now)
	dialFn func() (net.Conn, error)  // dial override (default s.dial)
}

// now returns the client's clock (overridable in tests).
func (s *SyslogClient) now() time.Time {
	if s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now()
}

// dialConn dials a new connection via the test seam if set, else the real
// protocol dialer.
func (s *SyslogClient) dialConn() (net.Conn, error) {
	if s.dialFn != nil {
		return s.dialFn()
	}
	return s.dial()
}

// Category bitmask constants for event filtering.
const (
	CategorySession  uint8 = 1 << 0 // SESSION_OPEN, SESSION_CLOSE
	CategoryPolicy   uint8 = 1 << 1 // POLICY_DENY
	CategoryScreen   uint8 = 1 << 2 // SCREEN_DROP
	CategoryFirewall uint8 = 1 << 3 // FILTER_LOG
	CategoryAll      uint8 = CategorySession | CategoryPolicy | CategoryScreen | CategoryFirewall
)

// NewSyslogClient creates a new UDP syslog client connected to host:port.
func NewSyslogClient(host string, port int) (*SyslogClient, error) {
	return NewSyslogClientWithSource(host, port, "")
}

// NewSyslogClientWithSource creates a new UDP syslog client with an optional
// source address for the local UDP socket binding.
func NewSyslogClientWithSource(host string, port int, sourceAddr string) (*SyslogClient, error) {
	return NewSyslogClientTransport(host, port, sourceAddr, "udp", nil)
}

// NewSyslogClientTransport creates a syslog client with the specified transport
// protocol ("udp", "tcp", or "tls"). For TLS, a *tls.Config is used; if nil,
// system CA roots are used.
func NewSyslogClientTransport(host string, port int, sourceAddr, protocol string, tlsCfg *tls.Config) (*SyslogClient, error) {
	if protocol == "" {
		protocol = "udp"
	}
	remoteAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}

	c := &SyslogClient{
		hostname:          hostname,
		remoteAddr:        remoteAddr,
		sourceAddr:        sourceAddr,
		protocol:          protocol,
		tlsConfig:         tlsCfg,
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
	}

	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	c.conn = conn
	return c, nil
}

// dial establishes a connection based on the configured protocol.
func (s *SyslogClient) dial() (net.Conn, error) {
	switch s.protocol {
	case "tcp":
		return s.dialTCP()
	case "tls":
		return s.dialTLS()
	default:
		return s.dialUDP()
	}
}

func (s *SyslogClient) dialUDP() (net.Conn, error) {
	if s.sourceAddr != "" {
		laddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(s.sourceAddr, "0"))
		if err != nil {
			return nil, fmt.Errorf("resolve source %s: %w", s.sourceAddr, err)
		}
		raddr, err := net.ResolveUDPAddr("udp", s.remoteAddr)
		if err != nil {
			return nil, fmt.Errorf("resolve remote %s: %w", s.remoteAddr, err)
		}
		return net.DialUDP("udp", laddr, raddr)
	}
	return net.Dial("udp", s.remoteAddr)
}

func (s *SyslogClient) dialTCP() (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if s.sourceAddr != "" {
		laddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(s.sourceAddr, "0"))
		if err != nil {
			return nil, fmt.Errorf("resolve source %s: %w", s.sourceAddr, err)
		}
		dialer.LocalAddr = laddr
	}
	return dialer.Dial("tcp", s.remoteAddr)
}

func (s *SyslogClient) dialTLS() (net.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    s.tlsConfig,
	}
	if s.sourceAddr != "" {
		laddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(s.sourceAddr, "0"))
		if err != nil {
			return nil, fmt.Errorf("resolve source %s: %w", s.sourceAddr, err)
		}
		dialer.NetDialer.LocalAddr = laddr
	}
	return dialer.DialContext(context.Background(), "tcp", s.remoteAddr)
}

// reconnect attempts to re-establish the connection, subject to a cooldown so
// a down server cannot drive a fresh dial on every event. Called with mu held.
//
// Returns errReconnectCooldown without dialing if the previous dial failed
// within reconnectCooldown; the caller drops the message and continues. The
// event hot-path therefore never spends more than one dial's worth of time per
// cooldown window on a dead target.
func (s *SyslogClient) reconnect() error {
	if s.reconnectCooldown > 0 && !s.lastDialFailure.IsZero() {
		if s.now().Sub(s.lastDialFailure) < s.reconnectCooldown {
			return errReconnectCooldown
		}
	}
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	conn, err := s.dialConn()
	if err != nil {
		s.lastDialFailure = s.now()
		return err
	}
	s.lastDialFailure = time.Time{}
	s.conn = conn
	return nil
}

// errReconnectCooldown signals that a reconnect was suppressed by the cooldown
// window; the message is dropped (fail-fast) rather than blocking on a dial.
var errReconnectCooldown = fmt.Errorf("syslog reconnect in cooldown")

// noteDrop bumps the appropriate drop counter and emits a rate-limited warning
// so a flapping target cannot spam the log on the event hot-path. Called with
// mu held.
func (s *SyslogClient) noteDrop(cooldown bool, err error) {
	if cooldown {
		s.droppedCooldown.Add(1)
	} else {
		s.droppedWrites.Add(1)
	}
	now := s.now()
	if s.lastDropLog.IsZero() || now.Sub(s.lastDropLog) >= time.Second {
		s.lastDropLog = now
		slog.Warn("syslog message dropped",
			"addr", s.remoteAddr,
			"cooldown", cooldown,
			"dropped_writes", s.droppedWrites.Load(),
			"dropped_cooldown", s.droppedCooldown.Load(),
			"err", err)
	}
}

// DroppedWrites reports the count of messages dropped on a write timeout or
// write error (observability).
func (s *SyslogClient) DroppedWrites() uint64 { return s.droppedWrites.Load() }

// DroppedCooldown reports the count of messages dropped because a reconnect was
// suppressed by the cooldown window (observability).
func (s *SyslogClient) DroppedCooldown() uint64 { return s.droppedCooldown.Load() }

// Send sends a syslog message with the given severity.
// For TCP/TLS, uses RFC 6587 octet-counting framing.
// On write failure for TCP/TLS, attempts one reconnect.
func (s *SyslogClient) Send(severity int, msg string) error {
	priority := s.Facility*8 + severity
	var line string
	if s.Format == "sd-syslog" {
		// RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
		ts := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
		line = fmt.Sprintf("<%d>1 %s %s xpf - - - %s", priority, ts, s.hostname, msg)
	} else {
		// RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MSG
		ts := time.Now().Format(time.Stamp) // "Jan _2 15:04:05"
		line = fmt.Sprintf("<%d>%s %s xpf: %s", priority, ts, s.hostname, msg)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.writeMsg(line); err != nil {
		// For stream protocols, attempt one cooldown-gated reconnect. UDP
		// never blocks or needs reconnect, so it just returns the error.
		if s.protocol != "udp" {
			slog.Debug("syslog send failed, reconnecting", "addr", s.remoteAddr, "err", err)
			if rerr := s.reconnect(); rerr != nil {
				// Cooldown or dial failure: drop and continue. The event
				// reader must make forward progress regardless.
				s.noteDrop(rerr == errReconnectCooldown, err)
				return fmt.Errorf("syslog reconnect %s: %w", s.remoteAddr, rerr)
			}
			if werr := s.writeMsg(line); werr != nil {
				s.noteDrop(false, werr)
				return werr
			}
			return nil
		}
		return err
	}
	return nil
}

// writeMsg writes the framed message to the connection. Called with mu held.
func (s *SyslogClient) writeMsg(line string) error {
	if s.conn == nil {
		return fmt.Errorf("syslog connection closed")
	}
	if s.protocol == "udp" {
		_, err := s.conn.Write([]byte(line))
		return err
	}
	// TCP/TLS: RFC 6587 octet-counting: "<length> <message>"
	framed := fmt.Sprintf("%d %s", len(line), line)
	return s.streamWrite([]byte(framed))
}

// streamWrite writes to a TCP/TLS conn with a bounded write deadline so a
// hung/congested server cannot block the dataplane event reader indefinitely.
// A deadline expiry surfaces as a timeout error (os.ErrDeadlineExceeded);
// callers treat it as a write failure and drop the message. Called with mu
// held; conn is non-nil.
func (s *SyslogClient) streamWrite(b []byte) error {
	if s.writeTimeout > 0 {
		// Best-effort: if SetWriteDeadline is unsupported by the conn it
		// returns an error we ignore (the Write still proceeds, just
		// without the bound). Real TCP/TLS conns always support it.
		_ = s.conn.SetWriteDeadline(s.now().Add(s.writeTimeout))
	}
	_, err := s.conn.Write(b)
	return err
}

// SendBinary sends a raw binary log record. The record is self-framing
// (contains its own length at offset [3:5]), so no additional framing is added.
// On write failure for TCP/TLS, attempts one reconnect.
func (s *SyslogClient) SendBinary(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.writeBinaryMsg(data); err != nil {
		if s.protocol != "udp" {
			slog.Debug("syslog binary send failed, reconnecting", "addr", s.remoteAddr, "err", err)
			if rerr := s.reconnect(); rerr != nil {
				s.noteDrop(rerr == errReconnectCooldown, err)
				return fmt.Errorf("syslog reconnect %s: %w", s.remoteAddr, rerr)
			}
			if werr := s.writeBinaryMsg(data); werr != nil {
				s.noteDrop(false, werr)
				return werr
			}
			return nil
		}
		return err
	}
	return nil
}

// writeBinaryMsg writes the raw binary data to the connection. Called with mu held.
func (s *SyslogClient) writeBinaryMsg(data []byte) error {
	if s.conn == nil {
		return fmt.Errorf("syslog connection closed")
	}
	if s.protocol == "udp" {
		_, err := s.conn.Write(data)
		return err
	}
	return s.streamWrite(data)
}

// ShouldSend returns true if the event severity passes this client's filter.
// Lower severity number = higher priority (error=3 < warning=4 < info=6).
func (s *SyslogClient) ShouldSend(severity int) bool {
	return s.MinSeverity == 0 || severity <= s.MinSeverity
}

// ShouldSendEvent returns true if both severity and category filters pass.
func (s *SyslogClient) ShouldSendEvent(severity int, categoryBit uint8) bool {
	if !s.ShouldSend(severity) {
		return false
	}
	return s.Categories == 0 || s.Categories&categoryBit != 0
}

// ParseCategory converts a Junos category name to a bitmask.
// "all" or "" returns 0 (no filter = send everything).
func ParseCategory(name string) uint8 {
	switch name {
	case "all", "":
		return 0
	case "session":
		return CategorySession
	case "policy":
		return CategoryPolicy
	case "screen":
		return CategoryScreen
	case "firewall":
		return CategoryFirewall
	default:
		return 0
	}
}

// ParseSeverity converts a severity name to its numeric value.
// Returns 0 (no filter) for unrecognized names.
func ParseSeverity(name string) int {
	switch name {
	case "error":
		return SyslogError
	case "warning":
		return SyslogWarning
	case "info":
		return SyslogInfo
	default:
		return 0
	}
}

// ParseFacility converts a facility name to its numeric code.
// Returns FacilityLocal0 for unrecognized names.
func ParseFacility(name string) int {
	switch name {
	case "kern":
		return FacilityKern
	case "user":
		return FacilityUser
	case "daemon":
		return FacilityDaemon
	case "auth":
		return FacilityAuth
	case "syslog":
		return FacilitySyslog
	case "local0":
		return FacilityLocal0
	case "local1":
		return FacilityLocal1
	case "local2":
		return FacilityLocal2
	case "local3":
		return FacilityLocal3
	case "local4":
		return FacilityLocal4
	case "local5":
		return FacilityLocal5
	case "local6":
		return FacilityLocal6
	case "local7":
		return FacilityLocal7
	case "change-log":
		return FacilityLocal6
	default:
		return FacilityLocal0
	}
}

// Close closes the underlying connection.
func (s *SyslogClient) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}
