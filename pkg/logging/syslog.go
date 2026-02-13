package logging

import (
	"fmt"
	"net"
	"os"
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

// SyslogClient sends UDP syslog messages.
// Supports RFC 3164 (BSD) and RFC 5424 (structured-data syslog) formats.
type SyslogClient struct {
	conn        net.Conn
	hostname    string
	Facility    int    // syslog facility code (default: FacilityLocal0)
	MinSeverity int    // 0 = no filter, else SyslogError(3)/SyslogWarning(4)/SyslogInfo(6)
	Format      string // "sd-syslog" for RFC 5424, "" for RFC 3164
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
	remoteAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	var conn net.Conn
	var err error
	if sourceAddr != "" {
		laddr, lerr := net.ResolveUDPAddr("udp", net.JoinHostPort(sourceAddr, "0"))
		if lerr != nil {
			return nil, fmt.Errorf("resolve source %s: %w", sourceAddr, lerr)
		}
		raddr, rerr := net.ResolveUDPAddr("udp", remoteAddr)
		if rerr != nil {
			return nil, fmt.Errorf("resolve remote %s: %w", remoteAddr, rerr)
		}
		conn, err = net.DialUDP("udp", laddr, raddr)
	} else {
		conn, err = net.Dial("udp", remoteAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial syslog %s: %w", remoteAddr, err)
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "bpfrx"
	}
	return &SyslogClient{conn: conn, hostname: hostname, Facility: FacilityLocal0}, nil
}

// Send sends a syslog message with the given severity.
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
	_, err := s.conn.Write([]byte(line))
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
	return s.conn.Close()
}
