package config

// Config is the top-level typed configuration, compiled from the AST.
type Config struct {
	Security          SecurityConfig
	Interfaces        InterfacesConfig
	Applications      ApplicationsConfig
	RoutingOptions    RoutingOptionsConfig
	Protocols         ProtocolsConfig
	RoutingInstances  []*RoutingInstanceConfig
	Firewall          FirewallConfig
	Services          ServicesConfig
	ForwardingOptions ForwardingOptionsConfig
	System            SystemConfig
	Schedulers        map[string]*SchedulerConfig
}

// SchedulerConfig defines a time-based policy scheduler.
type SchedulerConfig struct {
	Name      string
	StartTime string // "HH:MM:SS"
	StopTime  string // "HH:MM:SS"
	StartDate string // "YYYY-MM-DD" (optional)
	StopDate  string // "YYYY-MM-DD" (optional)
	Daily     bool   // recur daily
}

// SystemConfig holds system-level configuration.
type SystemConfig struct {
	DHCPServer DHCPServerConfig
	SNMP       *SNMPConfig
}

// SNMPConfig holds SNMP agent configuration.
type SNMPConfig struct {
	Location    string
	Contact     string
	Description string
	Communities map[string]*SNMPCommunity
	TrapGroups  map[string]*SNMPTrapGroup
}

// SNMPCommunity defines an SNMP community string.
type SNMPCommunity struct {
	Name          string
	Authorization string // "read-only" or "read-write"
}

// SNMPTrapGroup defines an SNMP trap destination group.
type SNMPTrapGroup struct {
	Name    string
	Targets []string // IP addresses
}

// ServicesConfig holds service configuration (flow-monitoring, RPM, etc.).
type ServicesConfig struct {
	FlowMonitoring *FlowMonitoringConfig
	RPM            *RPMConfig
}

// RPMConfig holds RPM (Real-time Performance Monitoring) configuration.
type RPMConfig struct {
	Probes map[string]*RPMProbe
}

// RPMProbe defines a single RPM probe for health monitoring.
type RPMProbe struct {
	Name            string
	Tests           map[string]*RPMTest
}

// RPMTest defines a test within an RPM probe.
type RPMTest struct {
	Name             string
	ProbeType        string // "http-get", "icmp-ping", "tcp-ping"
	Target           string // target IP or hostname
	SourceAddress    string
	RoutingInstance  string
	ProbeInterval    int // seconds (0 = default 5)
	ProbeCount       int // number of probes per test (0 = default 1)
	TestInterval     int // seconds (0 = default 60)
	ThresholdSuccessive int // successive failures before probe-fail (0 = default 3)
	DestPort         int // for tcp-ping
}

// FlowMonitoringConfig holds flow monitoring configuration.
type FlowMonitoringConfig struct {
	Version9 *NetFlowV9Config
}

// NetFlowV9Config holds NetFlow v9 template definitions.
type NetFlowV9Config struct {
	Templates map[string]*NetFlowV9Template
}

// NetFlowV9Template defines a NetFlow v9 export template.
type NetFlowV9Template struct {
	Name                string
	FlowActiveTimeout   int // seconds (0 = default 60)
	FlowInactiveTimeout int // seconds (0 = default 15)
	TemplateRefreshRate  int // seconds (0 = default 60)
}

// ForwardingOptionsConfig holds forwarding/sampling configuration.
type ForwardingOptionsConfig struct {
	Sampling  *SamplingConfig
	DHCPRelay *DHCPRelayConfig
}

// DHCPRelayConfig holds DHCP relay agent configuration.
type DHCPRelayConfig struct {
	ServerGroups map[string]*DHCPRelayServerGroup
	Groups       map[string]*DHCPRelayGroup
}

// DHCPRelayServerGroup defines a group of DHCP servers.
type DHCPRelayServerGroup struct {
	Name    string
	Servers []string // server IPs
}

// DHCPRelayGroup defines a DHCP relay group bound to interfaces.
type DHCPRelayGroup struct {
	Name              string
	Interfaces        []string
	ActiveServerGroup string // reference to server group name
}

// SamplingConfig holds sampling instance definitions.
type SamplingConfig struct {
	Instances map[string]*SamplingInstance
}

// SamplingInstance defines a traffic sampling instance.
type SamplingInstance struct {
	Name       string
	InputRate  int // 1-in-N sampling rate (0 = sample all)
	FamilyInet  *SamplingFamily
	FamilyInet6 *SamplingFamily
}

// SamplingFamily holds per-AF sampling output configuration.
type SamplingFamily struct {
	FlowServers   []*FlowServer
	SourceAddress string
	InlineJflow   bool
}

// FlowServer defines a flow export collector destination.
type FlowServer struct {
	Address          string
	Port             int
	Version9Template string
}

// FirewallConfig holds firewall filter definitions.
type FirewallConfig struct {
	FiltersInet  map[string]*FirewallFilter // family inet filters
	FiltersInet6 map[string]*FirewallFilter // family inet6 filters
}

// FirewallFilter defines a named firewall filter with ordered terms.
type FirewallFilter struct {
	Name  string
	Terms []*FirewallFilterTerm
}

// FirewallFilterTerm is a single match/action term within a filter.
type FirewallFilterTerm struct {
	Name             string
	SourceAddresses  []string // CIDRs
	DestAddresses    []string // CIDRs
	DSCP             string   // DSCP/traffic-class name (ef, af43, etc.) or number
	Protocol         string   // tcp, udp, icmp, icmpv6
	DestinationPorts []string // port numbers or names
	ICMPType         int      // -1 = not set
	ICMPCode         int      // -1 = not set
	Action           string   // "accept", "reject", "discard", ""
	RoutingInstance  string   // routing-instance name (policy-based routing)
	Log              bool
}

// DHCPServerConfig holds DHCP server configuration.
type DHCPServerConfig struct {
	DHCPLocalServer *DHCPLocalServerConfig
}

// DHCPLocalServerConfig holds per-group DHCP server settings.
type DHCPLocalServerConfig struct {
	Groups map[string]*DHCPServerGroup
}

// DHCPServerGroup defines a DHCP server group.
type DHCPServerGroup struct {
	Name       string
	Interfaces []string
	Pools      []*DHCPPool
}

// DHCPPool defines an address pool for DHCP leases.
type DHCPPool struct {
	Name       string
	RangeLow   string
	RangeHigh  string
	Subnet     string // pool network (e.g. "10.0.1.0/24")
	Router     string
	DNSServers []string
	LeaseTime  int // seconds (0 = default 86400)
	Domain     string
}

// DynamicAddressConfig defines a dynamic address feed server.
type DynamicAddressConfig struct {
	FeedServers map[string]*FeedServer
}

// FeedServer defines a remote address feed source.
type FeedServer struct {
	Name           string
	URL            string
	UpdateInterval int // seconds (0 = default 3600)
	HoldInterval   int // seconds (0 = default 7200)
	FeedName       string
}

// SecurityConfig holds all security-related configuration.
type SecurityConfig struct {
	Zones          map[string]*ZoneConfig       // keyed by zone name
	Policies       []*ZonePairPolicies          // ordered list of zone-pair policy sets
	DefaultPolicy  PolicyAction                 // global fallback policy (permit-all or deny-all)
	NAT            NATConfig
	Screen         map[string]*ScreenProfile    // keyed by profile name
	AddressBook    *AddressBook
	Log            LogConfig
	Flow           FlowConfig
	ALG            ALGConfig
	IPsec          IPsecConfig
	DynamicAddress DynamicAddressConfig
}

// FlowConfig holds flow/session timeout configuration.
type FlowConfig struct {
	TCPSession         *TCPSessionConfig
	UDPSessionTimeout  int // seconds, 0 = default (60s)
	ICMPSessionTimeout int // seconds, 0 = default (30s)
	TCPMSSIPsecVPN     int // TCP MSS clamp for IPsec VPN traffic (0 = disabled)
	TCPMSSGre          int // TCP MSS clamp for GRE tunnel traffic (0 = disabled)
	AllowDNSReply      bool
	AllowEmbeddedICMP  bool
}

// ALGConfig holds ALG (Application Layer Gateway) disable flags.
type ALGConfig struct {
	DNSDisable  bool
	FTPDisable  bool
	SIPDisable  bool
	TFTPDisable bool
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
	Name          string
	Match         PolicyMatch
	Action        PolicyAction
	Log           *PolicyLog
	Count         bool
	SchedulerName string // reference to SchedulerConfig name
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
	NAT64       []*NAT64RuleSet
}

// NAT64RuleSet defines NAT64 translation rules.
type NAT64RuleSet struct {
	Name        string
	Prefix      string // well-known prefix, e.g. "64:ff9b::/96"
	SourcePool  string // IPv4 source pool name for translated packets
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
	Name          string
	Address       string   // single address (DNAT compat)
	Addresses     []string // multiple addresses (source NAT pools)
	Port          int      // optional port mapping (DNAT)
	PortLow       int      // source pool port range low (default 1024)
	PortHigh      int      // source pool port range high (default 65535)
	PersistentNAT *PersistentNATConfig
}

// PersistentNATConfig configures persistent NAT bindings for a pool.
type PersistentNATConfig struct {
	PermitAnyRemoteHost bool
	InactivityTimeout   int // seconds (default 300)
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

// AddressSet is a named group of addresses and/or nested address-sets.
type AddressSet struct {
	Name        string
	Addresses   []string // references to Address names
	AddressSets []string // references to other AddressSet names (nested)
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
	Number        int
	VlanID        int      // 0 = native/untagged, >0 = 802.1Q tagged
	Addresses     []string // CIDR notation
	DHCP          bool     // family inet { dhcp; }
	DHCPv6        bool     // family inet6 { dhcpv6; }
	DHCPv6Client  *DHCPv6ClientConfig
	FilterInputV4 string // family inet { filter { input NAME; } }
	FilterInputV6 string // family inet6 { filter { input NAME; } }
	VRRPGroups    map[string]*VRRPGroup // keyed by address (CIDR), each address can have VRRP groups
}

// VRRPGroup defines a VRRP (Virtual Router Redundancy Protocol) group.
type VRRPGroup struct {
	ID                 int
	VirtualAddresses   []string // virtual IP addresses
	Priority           int      // 1-255, default 100
	Preempt            bool
	AcceptData         bool
	AdvertiseInterval  int    // seconds, default 1
	AuthType           string // "md5" or ""
	AuthKey            string
	TrackInterface     string // lower priority if interface is down
	TrackPriorityDelta int    // how much to lower priority
}

// DHCPv6ClientConfig holds DHCPv6 client options (dhcpv6-client stanza).
type DHCPv6ClientConfig struct {
	DUIDType string // "duid-ll" or "duid-llt"
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
	OSPF                *OSPFConfig
	BGP                 *BGPConfig
	RIP                 *RIPConfig
	ISIS                *ISISConfig
	RouterAdvertisement []*RAInterfaceConfig
}

// RIPConfig holds RIP routing configuration.
type RIPConfig struct {
	Interfaces   []string // interfaces participating in RIP
	Passive      []string // passive interfaces (receive only)
	Redistribute []string // "connected", "static", "ospf"
}

// ISISConfig holds IS-IS routing configuration.
type ISISConfig struct {
	NET        string // ISO NET address (e.g. "49.0001.0100.0000.0001.00")
	Level      string // "level-1", "level-2", "level-1-2" (default "level-2")
	Interfaces []*ISISInterface
}

// ISISInterface defines an interface participating in IS-IS.
type ISISInterface struct {
	Name    string
	Level   string // override per-interface
	Passive bool
	Metric  int // 0 = default
}

// RAInterfaceConfig configures Router Advertisement on an interface.
type RAInterfaceConfig struct {
	Interface          string
	ManagedConfig      bool     // managed-configuration (M flag)
	OtherStateful      bool     // other-stateful-configuration (O flag)
	DefaultLifetime    int      // seconds, 0 = default (1800)
	MaxAdvInterval     int      // seconds, 0 = default (600)
	MinAdvInterval     int      // seconds, 0 = default (200)
	Prefixes           []*RAPrefix
	DNSServers         []string // recursive DNS server addresses
	NAT64Prefix        string   // PREF64 prefix (e.g. "64:ff9b::/96")
	LinkMTU            int      // advertised link MTU, 0 = omit
}

// RAPrefix defines a prefix advertised via RA.
type RAPrefix struct {
	Prefix         string // CIDR notation
	OnLink         bool   // on-link flag (default true)
	Autonomous     bool   // SLAAC autonomous flag (default true)
	ValidLifetime  int    // seconds, 0 = default (2592000 = 30 days)
	PreferredLife  int    // seconds, 0 = default (604800 = 7 days)
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
	Name          string
	Gateway       string // remote gateway IP or gateway reference
	IPsecPolicy   string // reference to IPsecProposal
	LocalID       string // local traffic selector (CIDR)
	RemoteID      string // remote traffic selector (CIDR)
	PSK           string // pre-shared key
	LocalAddr     string // local address
	BindInterface string // tunnel interface (e.g. "st0.0") — creates xfrmi with if_id
}

// RoutingInstanceConfig represents a VRF-based routing instance.
type RoutingInstanceConfig struct {
	Name         string
	InstanceType string              // "virtual-router" or "vrf"
	Interfaces   []string            // interfaces belonging to this instance
	StaticRoutes []*StaticRoute      // per-instance static routes
	OSPF         *OSPFConfig         // per-instance OSPF (optional)
	BGP          *BGPConfig          // per-instance BGP (optional)
	RIP          *RIPConfig          // per-instance RIP (optional)
	ISIS         *ISISConfig         // per-instance IS-IS (optional)
	TableID      int                 // Linux kernel routing table number (auto-assigned)
}
