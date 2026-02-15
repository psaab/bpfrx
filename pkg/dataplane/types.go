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

	FibIfindex uint32
	FibVlanID  uint16
	FibDmac    [6]byte
	FibSmac    [6]byte
	FibGen     uint16
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

	FibIfindex uint32
	FibVlanID  uint16
	FibDmac    [6]byte
	FibSmac    [6]byte
	FibGen     uint16
}

// ZoneConfig mirrors the C struct zone_config.
type ZoneConfig struct {
	ZoneID          uint16
	ScreenProfileID uint16
	HostInbound     uint32
	TCPRst          uint8
	Pad             [3]uint8
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
	Active     uint8
	Pad        [2]byte

	AppID     uint32
	NATRuleID uint32
	CounterID uint32
}

// CounterValue mirrors the C struct counter_value.
type CounterValue struct {
	Packets uint64
	Bytes   uint64
}

// InterfaceCounterValue mirrors the C struct iface_counter_value.
type InterfaceCounterValue struct {
	RxPackets uint64
	RxBytes   uint64
	TxPackets uint64
	TxBytes   uint64
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
	XDPProgNAT64     = 6

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
	GlobalCtrNAT64Xlate      = 10
	GlobalCtrHostInbound     = 11
	// Per-screen-type drop counters (12..25)
	GlobalCtrScreenSynFlood     = 12
	GlobalCtrScreenICMPFlood    = 13
	GlobalCtrScreenUDPFlood     = 14
	GlobalCtrScreenPortScan     = 15
	GlobalCtrScreenIPSweep      = 16
	GlobalCtrScreenLandAttack   = 17
	GlobalCtrScreenPingOfDeath  = 18
	GlobalCtrScreenTearDrop     = 19
	GlobalCtrScreenTCPSynFin   = 20
	GlobalCtrScreenTCPNoFlag   = 21
	GlobalCtrScreenTCPFinNoAck = 22
	GlobalCtrScreenWinNuke     = 23
	GlobalCtrScreenIPSrcRoute  = 24
	GlobalCtrScreenSynFrag     = 25
	GlobalCtrMax               = 26
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
	HostInboundDHCPv6     = 1 << 17
	HostInboundVRRP            = 1 << 18
	HostInboundESP             = 1 << 19
	HostInboundRouterDiscovery = 1 << 20
	HostInboundAll             = 0xFFFFFFFF
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
	"dhcpv6":     HostInboundDHCPv6,
	"ipsec":      HostInboundESP,
	"all":        HostInboundAll,
}

// HostInboundProtocolFlags maps protocol names to flag bits.
var HostInboundProtocolFlags = map[string]uint32{
	"ospf":             HostInboundOSPF,
	"bgp":              HostInboundBGP,
	"router-discovery": HostInboundRouterDiscovery,
	"vrrp":             HostInboundVRRP,
	"all":              HostInboundAll,
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
	AppID       uint32
	ALGType     uint8
	Pad         uint8
	Timeout     uint16 // inactivity timeout override (seconds), 0=default
	SrcPortLow  uint16 // source port range low (host byte order), 0=any
	SrcPortHigh uint16 // source port range high (host byte order), 0=any
}

// NAT pool types.
type NATPoolConfig struct {
	NumIPs         uint16
	NumIPsV6       uint16
	PortLow        uint16
	PortHigh       uint16
	AddrPersistent uint8
	Pad            [3]uint8
}

type NATPoolIPV6 struct {
	IP [16]byte
}

type NATPortCounter struct {
	Counter uint64
}

const MaxNATPoolIPsPerPool = 8
const MaxNATRuleCounters = 256
const SNATModeOff = 0xFF // source-nat off: match but don't translate

// Session flag constants.
const (
	SessFlagSNAT      = 1 << 0
	SessFlagDNAT      = 1 << 1
	SessFlagStaticNAT = 1 << 6
)

// StaticNATKeyV4 mirrors the C struct static_nat_key_v4.
type StaticNATKeyV4 struct {
	IP        uint32 // network byte order
	Direction uint8
	Pad       [3]byte
}

// StaticNATKeyV6 mirrors the C struct static_nat_key_v6.
type StaticNATKeyV6 struct {
	IP        [16]byte
	Direction uint8
	Pad       [3]byte
}

// StaticNATValueV6 mirrors the C struct static_nat_value_v6.
type StaticNATValueV6 struct {
	IP [16]byte
}

// Static NAT direction constants.
const (
	StaticNATDNAT = 0
	StaticNATSNAT = 1
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
	RuleIdx  uint16
	Pad      uint16
}

// SNATValue mirrors the C struct snat_value.
type SNATValue struct {
	SNATIP    uint32 // network byte order
	SrcAddrID uint32 // 0 = any
	DstAddrID uint32 // 0 = any
	Mode      uint8
	Pad       uint8
	CounterID uint16 // index into nat_rule_counters
}

// SNATValueV6 mirrors the C struct snat_value_v6.
type SNATValueV6 struct {
	SNATIP    [16]byte
	SrcAddrID uint32 // 0 = any
	DstAddrID uint32 // 0 = any
	Mode      uint8
	Pad       uint8
	CounterID uint16 // index into nat_rule_counters
}

// MirrorConfig mirrors the C struct mirror_config for port mirroring.
// Key is the ingress ifindex; value tells XDP where to clone-redirect.
type MirrorConfig struct {
	MirrorIfindex uint32 // destination interface ifindex
	Rate          uint32 // 1-in-N sampling rate (0 = mirror all)
}

// ScreenConfig mirrors the C struct screen_config.
type ScreenConfig struct {
	Flags             uint32
	SynFloodThresh    uint32
	ICMPFloodThresh   uint32
	UDPFloodThresh    uint32
	SynFloodSrcThresh uint32
	SynFloodDstThresh uint32
	SynFloodTimeout   uint32
	PortScanThresh    uint32
	IPSweepThresh     uint32
}

// FloodState mirrors the C struct flood_state.
type FloodState struct {
	SynCount    uint64
	ICMPCount   uint64
	UDPCount    uint64
	WindowStart uint64
}

// Screen flag constants -- must match C SCREEN_* defines.
const (
	ScreenSynFlood      = 1 << 0
	ScreenICMPFlood     = 1 << 1
	ScreenUDPFlood      = 1 << 2
	ScreenPortScan      = 1 << 3
	ScreenIPSweep       = 1 << 4
	ScreenLandAttack    = 1 << 5
	ScreenPingOfDeath   = 1 << 6
	ScreenTearDrop      = 1 << 7
	ScreenTCPSynFin     = 1 << 8
	ScreenTCPNoFlag     = 1 << 9
	ScreenTCPFinNoAck   = 1 << 10
	ScreenWinNuke       = 1 << 11
	ScreenIPSourceRoute = 1 << 12
	ScreenSynFrag       = 1 << 13
)

// ScreenFlagNames maps screen flag values to human-readable names.
var ScreenFlagNames = map[uint32]string{
	ScreenSynFlood:      "SYN flood",
	ScreenICMPFlood:     "ICMP flood",
	ScreenUDPFlood:      "UDP flood",
	ScreenPortScan:      "port scan",
	ScreenIPSweep:       "IP sweep",
	ScreenLandAttack:    "LAND attack",
	ScreenPingOfDeath:   "ping of death",
	ScreenTearDrop:      "tear drop",
	ScreenTCPSynFin:     "TCP SYN+FIN",
	ScreenTCPNoFlag:     "TCP no-flag",
	ScreenTCPFinNoAck:   "TCP FIN-no-ACK",
	ScreenWinNuke:       "WinNuke",
	ScreenIPSourceRoute: "IP source-route",
	ScreenSynFrag:       "SYN fragment",
}

// Per-rule logging flags (matches C LOG_FLAG_* defines).
const (
	LogFlagSessionInit  = 1 << 0
	LogFlagSessionClose = 1 << 1
)

// Event type constants.
const (
	EventTypeSessionOpen  = 1
	EventTypeSessionClose = 2
	EventTypePolicyDeny   = 3
	EventTypeScreenDrop   = 4
	EventTypeFilterLog    = 6
)

// Flow timeout indices -- must match C FLOW_TIMEOUT_* defines.
const (
	FlowTimeoutTCPEstablished = 0
	FlowTimeoutTCPInitial     = 1
	FlowTimeoutTCPClosing     = 2
	FlowTimeoutTCPTimeWait    = 3
	FlowTimeoutUDP            = 4
	FlowTimeoutICMP           = 5
	FlowTimeoutOther          = 6
	FlowTimeoutMax            = 7
)

// Address family constants.
const (
	AFInet  = 2
	AFInet6 = 10
)

// IfaceZoneKey mirrors the C struct iface_zone_key (composite key for HASH map).
type IfaceZoneKey struct {
	Ifindex uint32
	VlanID  uint16
	Pad     uint16
}

// IfaceZoneValue mirrors the C struct iface_zone_value.
type IfaceZoneValue struct {
	ZoneID       uint16
	Pad          uint16
	RoutingTable uint32 // kernel table ID, 0 = main table
}

// VlanIfaceInfo mirrors the C struct vlan_iface_info.
type VlanIfaceInfo struct {
	ParentIfindex uint32
	VlanID        uint16
	Pad           uint16
}

// Protocol number constants.
const (
	ProtoICMPv6 = 58
)

// NAT64PrefixKey mirrors the C struct nat64_prefix_key (hash map key).
type NAT64PrefixKey struct {
	Prefix [3]uint32
}

// NAT64Config mirrors the C struct nat64_config.
type NAT64Config struct {
	Prefix     [3]uint32 // first 96 bits of NAT64 prefix (3 x 32-bit words, network order)
	SNATPoolID uint8
	Pad        [3]byte
}

// FilterConfig mirrors the C struct filter_config.
type FilterConfig struct {
	NumRules  uint32
	RuleStart uint32
}

// IfaceFilterKey mirrors the C struct iface_filter_key.
type IfaceFilterKey struct {
	Ifindex   uint32
	VlanID    uint16
	Family    uint8
	Direction uint8 // 0=input, 1=output
}

// FilterRule mirrors the C struct filter_rule.
type FilterRule struct {
	MatchFlags   uint16
	DSCP         uint8
	Protocol     uint8
	Action       uint8
	ICMPType     uint8
	ICMPCode     uint8
	Family       uint8
	DstPort      uint16 // network byte order
	SrcPort      uint16 // network byte order
	DstPortHi    uint16 // range upper bound (network byte order), 0=exact match
	SrcPortHi    uint16 // range upper bound (network byte order), 0=exact match
	DSCPRewrite  uint8  // DSCP rewrite value (0xFF = no rewrite)
	LogFlag      uint8  // 1 = emit ring buffer event on match
	TCPFlags     uint8  // TCP flags bitmask to match
	IsFragment   uint8  // 1 = match IP fragments
	SrcAddr      [16]byte
	SrcMask      [16]byte
	DstAddr      [16]byte
	DstMask      [16]byte
	RoutingTable uint32
	PolicerID    uint8  // policer index (0=none, 1-based)
	FlexOffset   uint8  // flexible match: byte offset from L3 header start
	FlexLength   uint8  // flexible match: match length in bytes (1,2,4)
	PadRule      byte
	FlexValue    uint32 // flexible match: expected value (host byte order, masked)
	FlexMask     uint32 // flexible match: mask to apply before comparison
}

// PolicerConfig mirrors the C struct policer_config.
type PolicerConfig struct {
	RateBytesSec uint64  // CIR: token refill rate (bytes per second)
	BurstBytes   uint64  // CBS: max committed bucket capacity (bytes)
	Action       uint8   // POLICER_ACTION_DISCARD=0
	ColorMode    uint8   // 0=single-rate, 1=two-rate, 2=single-rate-3c
	Pad          [6]byte
	PeakRate     uint64  // PIR: peak refill rate (two-rate only)
	PeakBurst    uint64  // PBS/EBS: peak/excess burst size
}

// Filter match flag constants.
const (
	FilterMatchDSCP       = 1 << 0
	FilterMatchProtocol   = 1 << 1
	FilterMatchSrcAddr    = 1 << 2
	FilterMatchDstAddr    = 1 << 3
	FilterMatchDstPort    = 1 << 4
	FilterMatchICMPType   = 1 << 5
	FilterMatchICMPCode   = 1 << 6
	FilterMatchSrcPort    = 1 << 7
	FilterMatchSrcNegate  = 1 << 8 // negate source address match (prefix-list except)
	FilterMatchDstNegate  = 1 << 9 // negate destination address match (prefix-list except)
	FilterMatchTCPFlags   = 1 << 10 // match TCP flags bitmask
	FilterMatchFragment   = 1 << 11 // match IP fragments
	FilterMatchFlex       = 1 << 12 // flexible byte-offset match
)

// Policer color mode constants.
const (
	PolicerModeSingleRate = 0 // single-rate two-color (default)
	PolicerModeTwoRate    = 1 // two-rate three-color (RFC 2698)
	PolicerModeSR3C       = 2 // single-rate three-color (RFC 2697)
)

// Filter action constants.
const (
	FilterActionAccept  = 0
	FilterActionDiscard = 1
	FilterActionReject  = 2
	FilterActionRoute   = 3
)

// DSCPValues maps DSCP codepoint names to numeric values.
var DSCPValues = map[string]uint8{
	"ef":   46,
	"af11": 10, "af12": 12, "af13": 14,
	"af21": 18, "af22": 20, "af23": 22,
	"af31": 26, "af32": 28, "af33": 30,
	"af41": 34, "af42": 36, "af43": 38,
	"cs0": 0, "cs1": 8, "cs2": 16, "cs3": 24,
	"cs4": 32, "cs5": 40, "cs6": 48, "cs7": 56,
	"be": 0,
}

// MaxFilterRules is the maximum number of filter rules.
const MaxFilterRules = 512

// MaxFilterConfigs is the maximum number of filter configs.
const MaxFilterConfigs = 64

// MaxPolicers is the maximum number of policer configurations.
const MaxPolicers = 64
