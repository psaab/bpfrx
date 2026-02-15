package logging

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
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
		hostname = "bpfrx"
	}

	c := &SyslogClient{
		hostname:   hostname,
		remoteAddr: remoteAddr,
		sourceAddr: sourceAddr,
		protocol:   protocol,
		tlsConfig:  tlsCfg,
		Facility:   FacilityLocal0,
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

// reconnect attempts to re-establish the connection. Called with mu held.
func (s *SyslogClient) reconnect() error {
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	conn, err := s.dial()
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

// Send sends a syslog message with the given severity.
// For TCP/TLS, uses RFC 6587 octet-counting framing.
// On write failure for TCP/TLS, attempts one reconnect.
func (s *SyslogClient) Send(severity int, msg string) error {
	priority := s.Facility*8 + severity
	var line string
	if s.Format == "sd-syslog" {
		// RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
		ts := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
		line = fmt.Sprintf("<%d>1 %s %s bpfrx - - - %s", priority, ts, s.hostname, msg)
	} else {
		// RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MSG
		ts := time.Now().Format(time.Stamp) // "Jan _2 15:04:05"
		line = fmt.Sprintf("<%d>%s %s bpfrx: %s", priority, ts, s.hostname, msg)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.writeMsg(line); err != nil {
		// For stream protocols, attempt one reconnect
		if s.protocol != "udp" {
			slog.Debug("syslog send failed, reconnecting", "addr", s.remoteAddr, "err", err)
			if rerr := s.reconnect(); rerr != nil {
				return fmt.Errorf("syslog reconnect %s: %w", s.remoteAddr, rerr)
			}
			return s.writeMsg(line)
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
	_, err := s.conn.Write([]byte(framed))
	return err
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
