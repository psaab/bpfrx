package config

// Config is the top-level typed configuration, compiled from the AST.
type Config struct {
	Security       SecurityConfig
	Interfaces     InterfacesConfig
	Applications   ApplicationsConfig
	RoutingOptions RoutingOptionsConfig
	Protocols      ProtocolsConfig
}

// SecurityConfig holds all security-related configuration.
type SecurityConfig struct {
	Zones         map[string]*ZoneConfig       // keyed by zone name
	Policies      []*ZonePairPolicies          // ordered list of zone-pair policy sets
	DefaultPolicy PolicyAction                 // global fallback policy (permit-all or deny-all)
	NAT           NATConfig
	Screen        map[string]*ScreenProfile    // keyed by profile name
	AddressBook   *AddressBook
	Log           LogConfig
	Flow          FlowConfig
	IPsec         IPsecConfig
}

// FlowConfig holds flow/session timeout configuration.
type FlowConfig struct {
	TCPSession         *TCPSessionConfig
	UDPSessionTimeout  int // seconds, 0 = default (60s)
	ICMPSessionTimeout int // seconds, 0 = default (30s)
}

// TCPSessionConfig holds TCP session timeout configuration.
type TCPSessionConfig struct {
	EstablishedTimeout int // default 1800
	InitialTimeout     int // default 30
	ClosingTimeout     int // default 30
	TimeWaitTimeout    int // default 120
}

// LogConfig holds logging/syslog configuration.
type LogConfig struct {
	Streams map[string]*SyslogStream
}

// SyslogStream defines a syslog forwarding destination.
type SyslogStream struct {
	Name string
	Host string
	Port int // default 514
}

// ZoneConfig represents a security zone.
type ZoneConfig struct {
	Name               string
	Interfaces         []string
	ScreenProfile      string // reference to screen profile name
	HostInboundTraffic *HostInboundTraffic
}

// HostInboundTraffic defines what services are permitted to the firewall itself.
type HostInboundTraffic struct {
	SystemServices []string // ssh, ping, dns, etc.
	Protocols      []string // ospf, bgp, etc.
}

// ZonePairPolicies contains ordered policies for a from-zone/to-zone pair.
type ZonePairPolicies struct {
	FromZone string
	ToZone   string
	Policies []*Policy
}

// Policy is a single security policy rule.
type Policy struct {
	Name   string
	Match  PolicyMatch
	Action PolicyAction
	Log    *PolicyLog
	Count  bool
}

// PolicyMatch defines what traffic a policy matches.
type PolicyMatch struct {
	SourceAddresses      []string // address-book names or "any"
	DestinationAddresses []string
	Applications         []string // application names or "any"
}

// PolicyAction is the action to take when a policy matches.
type PolicyAction int

const (
	PolicyPermit PolicyAction = iota
	PolicyDeny
	PolicyReject
)

// PolicyLog configures session logging for a policy.
type PolicyLog struct {
	SessionInit  bool
	SessionClose bool
}

// NATConfig holds NAT configuration.
type NATConfig struct {
	Source      []*NATRuleSet
	SourcePools map[string]*NATPool    // named source NAT pools
	Destination *DestinationNATConfig
	Static      []*StaticNATRuleSet
}

// StaticNATRuleSet is a set of static 1:1 NAT rules bound to a zone.
type StaticNATRuleSet struct {
	Name     string
	FromZone string
	Rules    []*StaticNATRule
}

// DestinationNATConfig holds destination NAT pools and rule sets.
type DestinationNATConfig struct {
	Pools    map[string]*NATPool
	RuleSets []*NATRuleSet
}

// NATRuleSet is a set of NAT rules bound to a zone pair.
type NATRuleSet struct {
	Name     string
	FromZone string
	ToZone   string
	Rules    []*NATRule
}

// NATRule is a single NAT rule.
type NATRule struct {
	Name  string
	Match NATMatch
	Then  NATThen
}

// NATMatch defines what traffic a NAT rule matches.
type NATMatch struct {
	SourceAddress      string // CIDR
	DestinationAddress string
	DestinationPort    int
	Protocol           string // "tcp", "udp", or "" (auto)
}

// NATThen defines the NAT translation action.
type NATThen struct {
	Type        NATType
	Interface   bool   // source-nat interface mode
	PoolName    string // pool reference
}

// NATType is the type of NAT.
type NATType int

const (
	NATSource NATType = iota
	NATDestination
	NATStatic
)

// NATPool is a pool of addresses for NAT.
type NATPool struct {
	Name      string
	Address   string   // single address (DNAT compat)
	Addresses []string // multiple addresses (source NAT pools)
	Port      int      // optional port mapping (DNAT)
	PortLow   int      // source pool port range low (default 1024)
	PortHigh  int      // source pool port range high (default 65535)
}

// StaticNATRule is a 1:1 bidirectional NAT rule.
type StaticNATRule struct {
	Name    string
	Match   string // destination-address (external/public IP)
	Then    string // static-nat prefix (internal/private IP)
}

// ScreenProfile defines IDS screening options.
type ScreenProfile struct {
	Name string
	ICMP ICMPScreen
	IP   IPScreen
	TCP  TCPScreen
	UDP  UDPScreen
}

// ICMPScreen configures ICMP screening.
type ICMPScreen struct {
	PingDeath      bool
	FloodThreshold int
}

// IPScreen configures IP screening.
type IPScreen struct {
	SourceRouteOption bool
	TearDrop          bool
}

// TCPScreen configures TCP screening.
type TCPScreen struct {
	SynFlood *SynFloodConfig
	Land     bool
	WinNuke  bool
	SynFrag  bool
	SynFin   bool
	NoFlag   bool
	FinNoAck bool
}

// UDPScreen configures UDP screening.
type UDPScreen struct {
	FloodThreshold int
}

// SynFloodConfig configures SYN flood protection thresholds.
type SynFloodConfig struct {
	AlarmThreshold  int
	AttackThreshold int
	SourceThreshold int
	Timeout         int
}

// AddressBook holds named addresses and address sets.
type AddressBook struct {
	Addresses   map[string]*Address
	AddressSets map[string]*AddressSet
}

// Address is a named address entry (IP prefix).
type Address struct {
	Name  string
	Value string // CIDR notation
}

// AddressSet is a named group of addresses.
type AddressSet struct {
	Name      string
	Addresses []string // references to Address names
}

// InterfacesConfig holds interface configuration.
type InterfacesConfig struct {
	Interfaces map[string]*InterfaceConfig
}

// InterfaceConfig represents a network interface.
type InterfaceConfig struct {
	Name        string
	VlanTagging bool // 802.1Q trunk mode
	Units       map[int]*InterfaceUnit
	Tunnel      *TunnelConfig // non-nil for tunnel interfaces (gre0, etc.)
}

// InterfaceUnit represents a logical unit on an interface.
type InterfaceUnit struct {
	Number    int
	VlanID    int      // 0 = native/untagged, >0 = 802.1Q tagged
	Addresses []string // CIDR notation
	DHCP      bool     // family inet { dhcp; }
	DHCPv6    bool     // family inet6 { dhcpv6; }
}

// ApplicationsConfig holds application definitions.
type ApplicationsConfig struct {
	Applications    map[string]*Application
	ApplicationSets map[string]*ApplicationSet
}

// ApplicationSet groups multiple applications or nested application-sets.
type ApplicationSet struct {
	Name         string
	Applications []string // references to Application or ApplicationSet names
}

// Application defines a network application by protocol and port.
type Application struct {
	Name            string
	Protocol        string // tcp, udp, icmp
	DestinationPort string // "80", "8080-8090"
}

// RoutingOptionsConfig holds static routing configuration.
type RoutingOptionsConfig struct {
	StaticRoutes []*StaticRoute
}

// StaticRoute defines a single static route.
type StaticRoute struct {
	Destination string // CIDR: "10.0.0.0/8" or "::/0"
	NextHop     string // IP or ""
	Interface   string // outgoing interface or ""
	Discard     bool   // null route (blackhole)
	Preference  int    // route preference (admin distance), default 5
}

// ProtocolsConfig holds dynamic routing protocol configuration.
type ProtocolsConfig struct {
	OSPF *OSPFConfig
	BGP  *BGPConfig
}

// OSPFConfig holds OSPF routing configuration.
type OSPFConfig struct {
	RouterID string // e.g. "10.0.0.1"
	Areas    []*OSPFArea
	Export   []string // export policy names (future)
}

// OSPFArea defines an OSPF area.
type OSPFArea struct {
	ID         string // "0.0.0.0" (backbone) or area number
	Interfaces []*OSPFInterface
}

// OSPFInterface defines an interface participating in OSPF.
type OSPFInterface struct {
	Name    string
	Passive bool // passive interface (no hello)
	Cost    int  // OSPF cost, 0 = default
}

// BGPConfig holds BGP routing configuration.
type BGPConfig struct {
	LocalAS   uint32
	RouterID  string
	Neighbors []*BGPNeighbor
}

// BGPNeighbor defines a BGP peer.
type BGPNeighbor struct {
	Address     string // peer IP
	PeerAS      uint32
	Description string
	MultihopTTL int // 0 = directly connected
}

// TunnelConfig defines a GRE or other tunnel interface.
type TunnelConfig struct {
	Name        string   // e.g. "gre0"
	Mode        string   // "gre" (future: "ip-ip", "vxlan")
	Source      string   // local tunnel endpoint IP
	Destination string   // remote tunnel endpoint IP
	Key         uint32   // GRE key, 0 = none
	TTL         int      // tunnel TTL, 0 = default 64
	Addresses   []string // IPs to assign to tunnel interface (CIDR)
}

// IPsecConfig holds IPsec VPN configuration.
type IPsecConfig struct {
	Proposals map[string]*IPsecProposal
	Gateways  map[string]*IPsecGateway
	VPNs      map[string]*IPsecVPN
}

// IPsecProposal defines encryption and authentication parameters.
type IPsecProposal struct {
	Name            string
	Protocol        string // "esp"
	EncryptionAlg   string // "aes-256-cbc", "aes-128-gcm"
	AuthAlg         string // "hmac-sha-256" (ignored for GCM)
	DHGroup         int    // DH group number
	LifetimeSeconds int
}

// IPsecGateway defines a remote IKE gateway.
type IPsecGateway struct {
	Name          string
	Address       string // remote gateway IP
	LocalAddress  string // local IP
	IKEPolicy     string // ike proposal reference
	ExternalIface string // external-facing interface
}

// IPsecVPN defines an IPsec VPN tunnel.
type IPsecVPN struct {
	Name        string
	Gateway     string // remote gateway IP or gateway reference
	IPsecPolicy string // reference to IPsecProposal
	LocalID     string // local traffic selector (CIDR)
	RemoteID    string // remote traffic selector (CIDR)
	PSK         string // pre-shared key
	LocalAddr   string // local address
}
