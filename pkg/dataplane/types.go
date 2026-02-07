// Package dataplane manages eBPF program loading, map operations,
// and XDP/TC attachment for the bpfrx firewall dataplane.
package dataplane

// SessionKey mirrors the C struct session_key (5-tuple).
type SessionKey struct {
	SrcIP    [4]byte
	DstIP    [4]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Pad      [3]byte
}

// SessionValue mirrors the C struct session_value.
type SessionValue struct {
	State     uint8
	Flags     uint8
	TCPState  uint8
	IsReverse uint8
	Pad0      [4]byte // alignment padding for Created (8-byte aligned)

	Created  uint64
	LastSeen uint64
	Timeout  uint32
	PolicyID uint32

	IngressZone uint16
	EgressZone  uint16

	NATSrcIP   uint32
	NATDstIP   uint32
	NATSrcPort uint16
	NATDstPort uint16

	FwdPackets uint64
	FwdBytes   uint64
	RevPackets uint64
	RevBytes   uint64

	ReverseKey SessionKey

	ALGType  uint8
	LogFlags uint8
	Pad1     [2]byte
	Pad2     [4]byte // trailing padding
}

// SessionKeyV6 mirrors the C struct session_key_v6 (5-tuple with 128-bit IPs).
type SessionKeyV6 struct {
	SrcIP    [16]byte
	DstIP    [16]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Pad      [3]byte
}

// SessionValueV6 mirrors the C struct session_value_v6.
type SessionValueV6 struct {
	State     uint8
	Flags     uint8
	TCPState  uint8
	IsReverse uint8
	Pad0      [4]byte // alignment padding for Created (8-byte aligned)

	Created  uint64
	LastSeen uint64
	Timeout  uint32
	PolicyID uint32

	IngressZone uint16
	EgressZone  uint16

	NATSrcIP   [16]byte
	NATDstIP   [16]byte
	NATSrcPort uint16
	NATDstPort uint16

	FwdPackets uint64
	FwdBytes   uint64
	RevPackets uint64
	RevBytes   uint64

	ReverseKey SessionKeyV6

	ALGType  uint8
	LogFlags uint8
	Pad1     [2]byte
}

// ZoneConfig mirrors the C struct zone_config.
type ZoneConfig struct {
	ZoneID          uint16
	ScreenProfileID uint16
	HostInbound     uint32
}

// ZonePairKey mirrors the C struct zone_pair_key.
type ZonePairKey struct {
	FromZone uint16
	ToZone   uint16
}

// PolicySet mirrors the C struct policy_set.
type PolicySet struct {
	PolicySetID   uint32
	NumRules      uint16
	DefaultAction uint16
}

// PolicyRule mirrors the C struct policy_rule.
type PolicyRule struct {
	RuleID      uint32
	PolicySetID uint32
	Sequence    uint16
	Action      uint8
	Log         uint8

	SrcAddrID  uint32
	DstAddrID  uint32
	DstPortLow  uint16
	DstPortHigh uint16
	Protocol   uint8
	Pad        [3]byte

	AppID     uint32
	NATRuleID uint32
	CounterID uint32
}

// CounterValue mirrors the C struct counter_value.
type CounterValue struct {
	Packets uint64
	Bytes   uint64
}

// Event mirrors the C struct event (with 16-byte IPs).
type Event struct {
	Timestamp      uint64
	SrcIP          [16]byte
	DstIP          [16]byte
	SrcPort        uint16
	DstPort        uint16
	PolicyID       uint32
	IngressZone    uint16
	EgressZone     uint16
	EventType      uint8
	Protocol       uint8
	Action         uint8
	AddrFamily     uint8
	SessionPackets uint64
	SessionBytes   uint64
}

// Tail call program indices -- must match C constants.
const (
	XDPProgScreen    = 0
	XDPProgZone      = 1
	XDPProgConntrack = 2
	XDPProgPolicy    = 3
	XDPProgNAT       = 4
	XDPProgForward   = 5

	TCProgConntrack   = 0
	TCProgNAT         = 1
	TCProgScreenEgress = 2
	TCProgForward     = 3
)

// Global counter indices -- must match C constants.
const (
	GlobalCtrRxPackets       = 0
	GlobalCtrTxPackets       = 1
	GlobalCtrDrops           = 2
	GlobalCtrSessionsNew     = 3
	GlobalCtrSessionsClosed  = 4
	GlobalCtrScreenDrops     = 5
	GlobalCtrPolicyDeny      = 6
	GlobalCtrNATAllocFail    = 7
	GlobalCtrHostInboundDeny = 8
	GlobalCtrTCEgressPackets = 9
	GlobalCtrMax             = 10
)

// Host-inbound-traffic service flags (bitmap in zone_config.host_inbound_flags).
const (
	HostInboundSSH        = 1 << 0
	HostInboundPing       = 1 << 1
	HostInboundDNS        = 1 << 2
	HostInboundHTTP       = 1 << 3
	HostInboundHTTPS      = 1 << 4
	HostInboundDHCP       = 1 << 5
	HostInboundNTP        = 1 << 6
	HostInboundSNMP       = 1 << 7
	HostInboundBGP        = 1 << 8
	HostInboundOSPF       = 1 << 9
	HostInboundTraceroute = 1 << 10
	HostInboundTelnet     = 1 << 11
	HostInboundFTP        = 1 << 12
	HostInboundNetconf    = 1 << 13
	HostInboundSyslog     = 1 << 14
	HostInboundRadius     = 1 << 15
	HostInboundIKE        = 1 << 16
	HostInboundAll        = 0xFFFFFFFF
)

// HostInboundServiceFlags maps system-service names to flag bits.
var HostInboundServiceFlags = map[string]uint32{
	"ssh":        HostInboundSSH,
	"ping":       HostInboundPing,
	"dns":        HostInboundDNS,
	"http":       HostInboundHTTP,
	"https":      HostInboundHTTPS,
	"dhcp":       HostInboundDHCP,
	"ntp":        HostInboundNTP,
	"snmp":       HostInboundSNMP,
	"traceroute": HostInboundTraceroute,
	"telnet":     HostInboundTelnet,
	"ftp":        HostInboundFTP,
	"netconf":    HostInboundNetconf,
	"syslog":     HostInboundSyslog,
	"radius":     HostInboundRadius,
	"ike":        HostInboundIKE,
	"all":        HostInboundAll,
}

// HostInboundProtocolFlags maps protocol names to flag bits.
var HostInboundProtocolFlags = map[string]uint32{
	"ospf": HostInboundOSPF,
	"bgp":  HostInboundBGP,
	"all":  HostInboundAll,
}

// Session state constants.
const (
	SessStateNone        = 0
	SessStateNew         = 1
	SessStateSynSent     = 2
	SessStateSynRecv     = 3
	SessStateEstablished = 4
	SessStateFINWait     = 5
	SessStateCloseWait   = 6
	SessStateTimeWait    = 7
	SessStateClosed      = 8
)

// Policy action constants.
const (
	ActionDeny   = 0
	ActionPermit = 1
	ActionReject = 2
)

// MaxRulesPerPolicy is the maximum number of rules in a single policy set.
const MaxRulesPerPolicy = 256

// LPMKeyV4 mirrors the C struct lpm_key_v4 for address book LPM trie.
type LPMKeyV4 struct {
	PrefixLen uint32
	Addr      uint32 // network byte order
}

// LPMKeyV6 mirrors the C struct lpm_key_v6 for IPv6 address book LPM trie.
type LPMKeyV6 struct {
	PrefixLen uint32
	Addr      [16]byte
}

// AddrValue mirrors the C struct addr_value.
type AddrValue struct {
	AddressID uint32
}

// AddrMembershipKey mirrors the C struct addr_membership_key.
type AddrMembershipKey struct {
	IP        uint32 // stores resolved address_id (reused field)
	AddressID uint32
}

// AppKey mirrors the C struct app_key.
type AppKey struct {
	Protocol uint8
	Pad      uint8
	DstPort  uint16 // network byte order
}

// AppValue mirrors the C struct app_value.
type AppValue struct {
	AppID   uint32
	ALGType uint8
	Pad     [3]byte
}

// Session flag constants.
const (
	SessFlagSNAT = 1 << 0
	SessFlagDNAT = 1 << 1
)

// DNAT table flags.
const (
	DNATFlagDynamic = 0 // dynamic/SNAT-return entry
	DNATFlagStatic  = 1 // static/DNAT-config entry
)

// DNATKey mirrors the C struct dnat_key.
type DNATKey struct {
	Protocol uint8
	Pad      [3]byte
	DstIP    uint32 // network byte order
	DstPort  uint16 // network byte order
	Pad2     uint16
}

// DNATValue mirrors the C struct dnat_value.
type DNATValue struct {
	NewDstIP   uint32 // network byte order
	NewDstPort uint16 // network byte order
	Flags      uint8
	Pad        uint8
}

// DNATKeyV6 mirrors the C struct dnat_key_v6.
type DNATKeyV6 struct {
	Protocol uint8
	Pad      [3]byte
	DstIP    [16]byte
	DstPort  uint16 // network byte order
	Pad2     uint16
}

// DNATValueV6 mirrors the C struct dnat_value_v6.
type DNATValueV6 struct {
	NewDstIP   [16]byte
	NewDstPort uint16 // network byte order
	Flags      uint8
	Pad        uint8
}

// SNATKey mirrors the C struct snat_key.
type SNATKey struct {
	FromZone uint16
	ToZone   uint16
}

// SNATValue mirrors the C struct snat_value.
type SNATValue struct {
	SNATIP uint32 // network byte order
	Mode   uint8
	Pad    [3]byte
}

// SNATValueV6 mirrors the C struct snat_value_v6.
type SNATValueV6 struct {
	SNATIP [16]byte
	Mode   uint8
	Pad    [3]byte
}

// Event type constants.
const (
	EventTypeSessionOpen  = 1
	EventTypeSessionClose = 2
	EventTypePolicyDeny   = 3
	EventTypeScreenDrop   = 4
)

// Address family constants.
const (
	AFInet  = 2
	AFInet6 = 10
)

// Protocol number constants.
const (
	ProtoICMPv6 = 58
)
