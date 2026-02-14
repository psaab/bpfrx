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
	PolicyOptions     PolicyOptionsConfig
	Schedulers        map[string]*SchedulerConfig
	Chassis           ChassisConfig
	EventOptions      []*EventPolicy
	Warnings          []string // non-fatal validation warnings
}

// ChassisConfig holds chassis-level configuration (clustering, etc).
type ChassisConfig struct {
	Cluster *ClusterConfig
}

// ClusterConfig defines chassis cluster settings for HA.
type ClusterConfig struct {
	RethCount        int
	RedundancyGroups []*RedundancyGroup
}

// RedundancyGroup defines a cluster redundancy group.
type RedundancyGroup struct {
	ID                 int
	NodePriorities     map[int]int        // node-id -> priority
	GratuitousARPCount int
	InterfaceMonitors  []*InterfaceMonitor
}

// InterfaceMonitor defines an interface health monitor within a redundancy group.
type InterfaceMonitor struct {
	Interface string
	Weight    int
}

// EventPolicy defines an event-driven policy (event-options).
type EventPolicy struct {
	Name             string
	Events           []string
	WithinClauses    []*EventWithin
	AttributesMatch  []string // raw "field matches pattern" strings
	ThenCommands     []string // change-configuration commands
}

// EventWithin defines a temporal trigger clause.
type EventWithin struct {
	Seconds    int
	TriggerOn  int // trigger on N
	TriggerUntil int // trigger until N
}

// PolicyOptionsConfig holds prefix-lists and policy-statements for routing control.
type PolicyOptionsConfig struct {
	PrefixLists      map[string]*PrefixList
	PolicyStatements map[string]*PolicyStatement
}

// PrefixList defines a named list of IP prefixes.
type PrefixList struct {
	Name     string
	Prefixes []string // CIDR entries ("10.0.0.0/8", "2001:db8::/32")
}

// PolicyStatement defines a routing policy with terms.
type PolicyStatement struct {
	Name          string
	Terms         []*PolicyTerm
	DefaultAction string // "accept", "reject", or "" (implicit reject)
}

// PolicyTerm is a single match+action clause within a policy-statement.
type PolicyTerm struct {
	Name         string
	FromProtocol string         // "direct", "static", "bgp", "ospf"
	PrefixList   string         // from prefix-list <name>
	RouteFilters []*RouteFilter // prefix matching
	Action       string         // "accept", "reject"
	NextHop      string         // then next-hop (e.g. "peer-address", "self", IP)
	LoadBalance  string         // then load-balance (e.g. "consistent-hash", "per-packet")
}

// RouteFilter matches a prefix with a match type.
type RouteFilter struct {
	Prefix    string // CIDR ("192.168.50.0/24")
	MatchType string // "exact", "longer", "orlonger", "upto"
	UptoLen   int    // for "upto" match type
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
	HostName           string
	DomainName         string   // system domain-name (e.g. "example.com")
	DomainSearch       []string // system domain-search (search domains)
	TimeZone           string
	NameServers        []string // DNS server addresses
	NTPServers         []string // NTP server addresses
	NTPThreshold       int      // NTP threshold in milliseconds (0 = default)
	NTPThresholdAction string   // "accept" or "reject"
	NoRedirects        bool     // disable ICMP redirects
	BackupRouter       string   // backup default gateway IP
	BackupRouterDst    string   // backup router destination prefix
	DataplaneType      string   // "ebpf" (default) or "dpdk"
	DPDKDataplane      *DPDKConfig
	InternetOptions    *InternetOptionsConfig
	Services           *SystemServicesConfig
	Syslog             *SystemSyslogConfig
	DHCPServer         DHCPServerConfig
	SNMP               *SNMPConfig
	Login              *LoginConfig
	RootAuthentication *RootAuthConfig
	Archival           *ArchivalConfig
	MasterPassword     string // pseudorandom-function value
	LicenseAutoUpdate  string // license autoupdate URL
	DisabledProcesses  []string // processes marked "disable"
}

// DPDKConfig holds DPDK dataplane-specific configuration.
type DPDKConfig struct {
	Cores          string // EAL core list (e.g. "2-5")
	Memory         int    // Hugepages in MB
	SocketMem      string // Per-NUMA socket memory (e.g. "1024,1024")
	RXMode         string // "polling", "interrupt", "adaptive"
	AdaptiveConfig *DPDKAdaptiveConfig
	Ports          []DPDKPort
}

// DPDKAdaptiveConfig holds adaptive RX mode tuning parameters.
type DPDKAdaptiveConfig struct {
	IdleThreshold   int // Empty polls before sleep (default 256)
	ResumeThreshold int // Burst size to resume polling (default 32)
	SleepTimeout    int // Max sleep ms (default 100)
}

// DPDKPort maps a PCI address to a logical interface.
type DPDKPort struct {
	PCIAddress string // e.g. "0000:03:00.0"
	Interface  string // logical interface name (e.g. "wan0")
	RXMode     string // per-port RX mode override
	Cores      string // per-port core list override
}

// RootAuthConfig holds root-authentication settings.
type RootAuthConfig struct {
	EncryptedPassword string
	SSHKeys           []string
}

// ArchivalConfig holds configuration archival settings.
type ArchivalConfig struct {
	TransferOnCommit bool
	ArchiveSites     []string
}

// InternetOptionsConfig holds internet-options settings.
type InternetOptionsConfig struct {
	NoIPv6RejectZeroHopLimit bool
}

// SystemServicesConfig holds system services (SSH, web-management).
type SystemServicesConfig struct {
	SSH           *SSHServiceConfig
	WebManagement *WebManagementConfig
	DNSEnabled    bool // system services dns
}

// SSHServiceConfig holds SSH service settings.
type SSHServiceConfig struct {
	RootLogin string // "allow", "deny", "deny-password"
}

// WebManagementConfig holds web management settings.
type WebManagementConfig struct {
	HTTP                     bool
	HTTPS                    bool
	HTTPInterface            string // interface binding for HTTP
	HTTPSInterface           string // interface binding for HTTPS
	SystemGeneratedCert      bool   // auto-generated TLS certificate
}

// SystemSyslogConfig holds traditional Junos system syslog config.
type SystemSyslogConfig struct {
	Hosts []*SyslogHostConfig
	Files []*SyslogFileConfig
	Users []*SyslogUserConfig // user destinations (e.g. "user * { any emergency; }")
}

// SyslogUserConfig defines a syslog user destination.
type SyslogUserConfig struct {
	User     string // "*" = all users
	Facility string
	Severity string
}

// SyslogHostConfig defines a syslog host destination.
type SyslogHostConfig struct {
	Address         string
	Facilities      []SyslogFacility // multiple facility/severity pairs
	AllowDuplicates bool
}

// SyslogFacility represents a facility/severity pair in syslog config.
type SyslogFacility struct {
	Facility string // "daemon", "change-log", "any", etc.
	Severity string // "info", "warning", "error", "emergency", "any"
}

// SyslogFileConfig defines a syslog file destination.
type SyslogFileConfig struct {
	Name     string
	Facility string
	Severity string
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

// LoginConfig holds user account definitions.
type LoginConfig struct {
	Users []*LoginUser
}

// LoginUser defines a system user account.
type LoginUser struct {
	Name     string
	UID      int
	Class    string // "super-user", "read-only", etc.
	SSHKeys  []string // authorized SSH public keys
}

// ServicesConfig holds service configuration (flow-monitoring, RPM, etc.).
type ServicesConfig struct {
	FlowMonitoring           *FlowMonitoringConfig
	RPM                      *RPMConfig
	ApplicationIdentification bool // DPI-based application detection
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
	Version9     *NetFlowV9Config
	VersionIPFIX *NetFlowIPFIXConfig
}

// NetFlowIPFIXConfig holds IPFIX (NetFlow v10) template definitions.
type NetFlowIPFIXConfig struct {
	Templates map[string]*NetFlowIPFIXTemplate
}

// NetFlowIPFIXTemplate defines an IPFIX export template.
type NetFlowIPFIXTemplate struct {
	Name                string
	FlowActiveTimeout   int      // seconds
	FlowInactiveTimeout int      // seconds
	TemplateRefreshRate int      // seconds
	ExportExtensions    []string // e.g. "app-id", "flow-dir"
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
	Sampling       *SamplingConfig
	DHCPRelay      *DHCPRelayConfig
	FamilyInet6Mode string // "flow-based" or "packet-based" (default "flow-based")
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
	FlowServers              []*FlowServer
	SourceAddress            string
	InlineJflow              bool
	InlineJflowSourceAddress string // inline-jflow { source-address; }
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
	Name               string
	SourceAddresses    []string            // CIDRs
	DestAddresses      []string            // CIDRs
	SourcePrefixLists  []PrefixListRef     // source-prefix-list references
	DestPrefixLists    []PrefixListRef     // destination-prefix-list references
	DSCP               string              // DSCP/traffic-class name (ef, af43, etc.) or number
	Protocol           string              // tcp, udp, icmp, icmpv6
	DestinationPorts   []string            // port numbers or names
	SourcePorts        []string            // source port numbers or ranges
	ICMPType           int                 // -1 = not set
	ICMPCode           int                 // -1 = not set
	Action             string              // "accept", "reject", "discard", ""
	RoutingInstance    string              // routing-instance name (policy-based routing)
	Log                bool
	Count              string              // counter name
	ForwardingClass    string              // forwarding-class name
	LossPriority       string              // loss-priority (low, medium-low, medium-high, high)
	DSCPRewrite        string              // then dscp <value> — rewrite DSCP/traffic-class
}

// PrefixListRef references a named prefix-list with optional "except" modifier.
type PrefixListRef struct {
	Name   string
	Except bool
}

// DHCPServerConfig holds DHCP server configuration.
type DHCPServerConfig struct {
	DHCPLocalServer   *DHCPLocalServerConfig
	DHCPv6LocalServer *DHCPLocalServerConfig
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
	Zones              map[string]*ZoneConfig       // keyed by zone name
	Policies           []*ZonePairPolicies          // ordered list of zone-pair policy sets
	GlobalPolicies     []*Policy                    // global policies (apply to all zone pairs)
	DefaultPolicy      PolicyAction                 // global fallback policy (permit-all or deny-all)
	NAT                NATConfig
	Screen             map[string]*ScreenProfile    // keyed by profile name
	AddressBook        *AddressBook
	Log                LogConfig
	Flow               FlowConfig
	ALG                ALGConfig
	IPsec              IPsecConfig
	DynamicAddress     DynamicAddressConfig
	SSHKnownHosts      map[string][]SSHKnownHostKey // host -> keys
	PolicyStatsEnabled bool                         // policy-stats system-wide enable
	PreIDDefaultPolicy *PreIDDefaultPolicy          // pre-id-default-policy
}

// FlowConfig holds flow/session timeout configuration.
type FlowConfig struct {
	TCPSession                 *TCPSessionConfig
	UDPSessionTimeout          int // seconds, 0 = default (60s)
	ICMPSessionTimeout         int // seconds, 0 = default (30s)
	TCPMSSIPsecVPN             int // TCP MSS clamp for IPsec VPN traffic (0 = disabled)
	TCPMSSGreIn                int // TCP MSS clamp for GRE ingress traffic (0 = disabled)
	TCPMSSGreOut               int // TCP MSS clamp for GRE egress traffic (0 = disabled)
	AllowDNSReply              bool
	AllowEmbeddedICMP          bool
	GREPerformanceAcceleration bool
	PowerModeDisable           bool
	Traceoptions               *FlowTraceoptions
}

// FlowTraceoptions holds flow trace debugging configuration.
type FlowTraceoptions struct {
	File          string // log file name
	FileSize      int    // max file size in bytes
	FileCount     int    // number of rotated files
	Flags         []string // trace flags (e.g. "basic-datapath", "session")
	PacketFilters []*TracePacketFilter
}

// TracePacketFilter defines a packet filter for flow tracing.
type TracePacketFilter struct {
	Name              string
	SourcePrefix      string
	DestinationPrefix string
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
	Mode            string // "stream" or "event"
	Format          string // "sd-syslog", "syslog", "binary"
	SourceInterface string // interface for source address
	Streams         map[string]*SyslogStream
}

// SyslogStream defines a syslog forwarding destination.
type SyslogStream struct {
	Name          string
	Host          string
	Port          int    // default 514
	Severity      string // "error", "warning", "info", or "" (no filter)
	Facility      string // "local0".."local7", "user", "daemon", or "" (default: local0)
	Format        string // per-stream format override
	Category      string // "all", or specific category
	SourceAddress string // source IP for this stream
}

// SSHKnownHostKey represents a known SSH host key.
type SSHKnownHostKey struct {
	Type string // "ecdsa-sha2-nistp256-key", "ssh-rsa-key", etc.
	Key  string
}

// PreIDDefaultPolicy defines a pre-identification default policy.
type PreIDDefaultPolicy struct {
	LogSessionInit  bool
	LogSessionClose bool
}

// ZoneConfig represents a security zone.
type ZoneConfig struct {
	Name               string
	Description        string
	Interfaces         []string
	ScreenProfile      string // reference to screen profile name
	HostInboundTraffic *HostInboundTraffic
	TCPRst             bool // send TCP RST for non-SYN packets to closed ports
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
	Description   string
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
	Source            []*NATRuleSet
	SourcePools       map[string]*NATPool    // named source NAT pools
	AddressPersistent bool                   // source { address-persistent; }
	Destination       *DestinationNATConfig
	Static            []*StaticNATRuleSet
	NAT64             []*NAT64RuleSet
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
	DestinationPort    int    // primary port (first port for BPF rule)
	DestinationPorts   []int  // all matched ports (for multi-port DNAT rules)
	Protocol           string // "tcp", "udp", or "" (auto)
	Application        string // application name (e.g. "junos-http")
}

// NATThen defines the NAT translation action.
type NATThen struct {
	Type        NATType
	Interface   bool   // source-nat interface mode
	PoolName    string // pool reference
	Off         bool   // source-nat off (no-NAT exemption)
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
	SourceRouteOption  bool
	TearDrop           bool
	IPSweepThreshold   int // unique destination IPs per source (0 = disabled)
}

// TCPScreen configures TCP screening.
type TCPScreen struct {
	SynFlood           *SynFloodConfig
	Land               bool
	WinNuke            bool
	SynFrag            bool
	SynFin             bool
	NoFlag             bool
	FinNoAck           bool
	PortScanThreshold  int // TCP SYN count per source IP (0 = disabled)
}

// UDPScreen configures UDP screening.
type UDPScreen struct {
	FloodThreshold int
}

// SynFloodConfig configures SYN flood protection thresholds.
type SynFloodConfig struct {
	AlarmThreshold       int
	AttackThreshold      int
	SourceThreshold      int
	DestinationThreshold int
	Timeout              int
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
	Name            string
	Description     string // free-text interface description
	MTU             int    // interface-level MTU (overridden by unit MTU)
	Speed           string // interface speed (e.g. "1g", "10g", "auto")
	Duplex          string // "full", "half", "auto"
	VlanTagging     bool   // 802.1Q trunk mode
	Disable         bool   // administratively disabled
	RedundantParent string // gigether-options redundant-parent (HA)
	RedundancyGroup int    // redundant-ether-options redundancy-group (0 = none)
	FabricMembers   []string // fabric-options member-interfaces
	Units           map[int]*InterfaceUnit
	Tunnel          *TunnelConfig // non-nil for tunnel interfaces (gre0, etc.)
}

// InterfaceUnit represents a logical unit on an interface.
type InterfaceUnit struct {
	Number         int
	Description    string   // free-text unit description
	VlanID         int      // 0 = native/untagged, >0 = 802.1Q tagged
	PointToPoint   bool     // point-to-point link (for tunnels)
	Addresses      []string // CIDR notation
	PrimaryAddress   string // address marked as primary
	PreferredAddress string // address marked as preferred
	MTU            int      // family-level MTU (0 = default)
	DHCP           bool     // family inet { dhcp; }
	DHCPOptions    *DHCPInetOptions // dhcp sub-options (lease-time, etc.)
	DHCPv6         bool     // family inet6 { dhcpv6; }
	DHCPv6Client   *DHCPv6ClientConfig
	DADDisable     bool   // family inet6 { dad-disable; }
	SamplingInput  bool   // family inet/inet6 { sampling { input; } }
	SamplingOutput bool   // family inet/inet6 { sampling { output; } }
	FilterInputV4  string // family inet { filter { input NAME; } }
	FilterOutputV4 string // family inet { filter { output NAME; } }
	FilterInputV6  string // family inet6 { filter { input NAME; } }
	FilterOutputV6 string // family inet6 { filter { output NAME; } }
	VRRPGroups     map[string]*VRRPGroup // keyed by address (CIDR), each address can have VRRP groups
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
	DUIDType                   string   // "duid-ll" or "duid-llt"
	ClientType                 string   // "stateful" or "stateless"
	ClientIATypes              []string // "ia-pd", "ia-na"
	PrefixDelegatingPrefixLen  int      // preferred-prefix-length (0 = not set)
	PrefixDelegatingSubPrefLen int      // sub-prefix-length (0 = not set)
	ReqOptions                 []string // dns-server, domain-name, etc.
	UpdateRAInterface          string   // update-router-advertisement interface
}

// DHCPInetOptions holds DHCPv4 client options for family inet dhcp stanza.
type DHCPInetOptions struct {
	LeaseTime              int  // seconds (0 = default)
	RetransmissionAttempt  int  // number of retransmission attempts
	RetransmissionInterval int  // seconds between retransmissions
	ForceDiscover          bool // always start with DISCOVER
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
	Name              string
	Protocol          string // tcp, udp, icmp, or numeric ("47")
	DestinationPort   string // "80", "8080-8090"
	SourcePort        string // "1024-65535" (optional)
	InactivityTimeout int    // seconds (0 = default)
	ALG               string // "ssh", "ftp", etc. (informational)
	Description       string
}

// RoutingOptionsConfig holds static routing configuration.
type RoutingOptionsConfig struct {
	StaticRoutes          []*StaticRoute
	Inet6StaticRoutes     []*StaticRoute // rib inet6.0 static routes
	ForwardingTableExport string         // forwarding-table { export <policy>; }
	AutonomousSystem      uint32         // autonomous-system <number>
	RibGroups             map[string]*RibGroup
}

// RibGroup defines a RIB group for route sharing between routing instances.
type RibGroup struct {
	Name       string
	ImportRibs []string // import-rib [ rib1 rib2 ... ]
}

// NextHopEntry defines a single next-hop for a static route.
type NextHopEntry struct {
	Address   string // IP address (e.g. "10.0.1.1" or "fe80::1")
	Interface string // outgoing interface (for IPv6 link-local)
}

// StaticRoute defines a single static route.
type StaticRoute struct {
	Destination string         // CIDR: "10.0.0.0/8" or "::/0"
	NextHops    []NextHopEntry // multiple next-hops = ECMP
	Discard     bool           // null route (blackhole)
	Preference  int            // route preference (admin distance), default 5
	NextTable   string         // routing instance name for inter-VRF route leaking (e.g. "Comcast.inet.0" → "Comcast")
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
	AuthKey      string   // authentication key/password
	AuthType     string   // "md5" or "simple"
}

// ISISConfig holds IS-IS routing configuration.
type ISISConfig struct {
	NET             string // ISO NET address (e.g. "49.0001.0100.0000.0001.00")
	Level           string // "level-1", "level-2", "level-1-2" (default "level-2")
	Interfaces      []*ISISInterface
	Export          []string // "connected", "static", etc.
	AuthKey         string   // area-level authentication key
	AuthType        string   // "md5" or "simple" (plaintext)
	WideMetricsOnly bool     // use wide (32-bit) metrics
	Overload        bool     // set overload bit
}

// ISISInterface defines an interface participating in IS-IS.
type ISISInterface struct {
	Name     string
	Level    string // override per-interface
	Passive  bool
	Metric   int    // 0 = default
	AuthKey  string // per-interface authentication key
	AuthType string // "md5" or "simple"
}

// RAInterfaceConfig configures Router Advertisement on an interface.
type RAInterfaceConfig struct {
	Interface          string
	ManagedConfig      bool     // managed-configuration (M flag)
	OtherStateful      bool     // other-stateful-configuration (O flag)
	Preference         string   // "high", "medium", "low" (default: medium)
	DefaultLifetime    int      // seconds, 0 = default (1800)
	MaxAdvInterval     int      // seconds, 0 = default (600)
	MinAdvInterval     int      // seconds, 0 = default (200)
	Prefixes           []*RAPrefix
	DNSServers         []string // recursive DNS server addresses
	NAT64Prefix        string   // PREF64 prefix (e.g. "64:ff9b::/96")
	NAT64PrefixLife    int      // PREF64 lifetime in seconds (0 = default)
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
	RouterID           string // e.g. "10.0.0.1"
	ReferenceBandwidth int    // Mbps for auto-cost calculation (0 = FRR default 100)
	PassiveDefault     bool   // all interfaces passive by default
	Areas              []*OSPFArea
	Export             []string // export policy names (future)
}

// OSPFArea defines an OSPF area.
type OSPFArea struct {
	ID         string // "0.0.0.0" (backbone) or area number
	AreaType   string // "stub", "nssa", "" (normal)
	NoSummary  bool   // stub/nssa no-summary (totally stubby)
	Interfaces []*OSPFInterface
}

// OSPFInterface defines an interface participating in OSPF.
type OSPFInterface struct {
	Name        string
	Passive     bool   // passive interface (no hello)
	NoPassive   bool   // override passive-default (explicitly active)
	Cost        int    // OSPF cost, 0 = default
	NetworkType string // "point-to-point", "broadcast", "" (default)
	AuthType    string // "md5", "simple", "" (none)
	AuthKey     string // authentication key/password
	AuthKeyID   int    // key-id for MD5 (1-255)
	BFD         bool   // enable BFD on this interface
}

// BGPConfig holds BGP routing configuration.
type BGPConfig struct {
	LocalAS             uint32
	RouterID            string
	ClusterID           string // route reflector cluster ID
	GracefulRestart     bool   // enable graceful restart
	Multipath           int    // maximum equal-cost paths (0 = disabled)
	MultipathMultipleAS bool   // allow multipath across different ASes
	LogNeighborChanges  bool   // log neighbor state transitions
	Neighbors           []*BGPNeighbor
	Export              []string // "connected", "static", "ospf", etc.
}

// BGPNeighbor defines a BGP peer.
type BGPNeighbor struct {
	Address      string   // peer IP
	PeerAS       uint32
	Description  string
	MultihopTTL  int      // 0 = directly connected
	Export       []string // per-group export policies (route-map out)
	FamilyInet   bool     // activate under address-family ipv4 unicast
	FamilyInet6  bool     // activate under address-family ipv6 unicast
	GroupName    string   // BGP group name (for display)
	AuthPassword         string // TCP MD5 password for BGP session
	BFD                  bool   // enable BFD for this neighbor
	BFDInterval          int    // BFD minimum interval in ms (0 = default 300)
	RouteReflectorClient bool   // mark as route-reflector client
	DefaultOriginate     bool   // advertise default route to this neighbor
}

// TunnelConfig defines a GRE or other tunnel interface.
type TunnelConfig struct {
	Name            string   // e.g. "gre0"
	Mode            string   // "gre" (future: "ip-ip", "vxlan")
	Source          string   // local tunnel endpoint IP
	Destination     string   // remote tunnel endpoint IP
	Key             uint32   // GRE key, 0 = none
	TTL             int      // tunnel TTL, 0 = default 64
	Addresses       []string // IPs to assign to tunnel interface (CIDR)
	RoutingInstance string   // destination routing-instance (VRF)
}

// IPsecConfig holds IPsec VPN configuration.
type IPsecConfig struct {
	// Phase 1 (IKE)
	IKEProposals map[string]*IKEProposal
	IKEPolicies  map[string]*IKEPolicy
	Gateways     map[string]*IPsecGateway

	// Phase 2 (IPsec)
	Proposals map[string]*IPsecProposal
	Policies  map[string]*IPsecPolicyDef
	VPNs      map[string]*IPsecVPN
}

// IKEProposal defines Phase 1 (IKE) negotiation parameters.
type IKEProposal struct {
	Name            string
	AuthMethod      string // "pre-shared-keys"
	EncryptionAlg   string // "aes-256-cbc"
	AuthAlg         string // "sha-256"
	DHGroup         int    // DH group number
	LifetimeSeconds int
}

// IKEPolicy defines Phase 1 policy (mode, proposal reference, PSK).
type IKEPolicy struct {
	Name      string
	Mode      string // "main" or "aggressive"
	Proposals string // IKE proposal reference
	PSK       string // pre-shared key
}

// IPsecProposal defines Phase 2 (ESP) encryption and authentication parameters.
type IPsecProposal struct {
	Name            string
	Protocol        string // "esp"
	EncryptionAlg   string // "aes-256-cbc", "aes-128-gcm"
	AuthAlg         string // "hmac-sha-256" (ignored for GCM)
	DHGroup         int    // DH group number
	LifetimeSeconds int
}

// IPsecPolicyDef defines Phase 2 policy (PFS + proposal reference).
type IPsecPolicyDef struct {
	Name       string
	PFSGroup   int    // PFS DH group number (0 = disabled)
	Proposals  string // IPsec proposal reference
}

// IPsecGateway defines a remote IKE gateway.
type IPsecGateway struct {
	Name             string
	Address          string // remote gateway IP
	DynamicHostname  string // dynamic peer hostname (DNS-resolved)
	LocalAddress     string // local IP
	IKEPolicy        string // IKE policy reference
	ExternalIface    string // external-facing interface
	Version          string // "v1-only", "v2-only" (empty = both)
	NoNATTraversal   bool   // disable NAT-T
	DeadPeerDetect   string // "always-send", "optimized", "probe-idle"
	LocalIDType      string // "hostname", "inet", "fqdn"
	LocalIDValue     string // identity value
	RemoteIDType     string // "hostname", "inet", "fqdn"
	RemoteIDValue    string // identity value
}

// IPsecVPN defines an IPsec VPN tunnel.
type IPsecVPN struct {
	Name             string
	Gateway          string // gateway reference
	IPsecPolicy      string // IPsec policy reference
	LocalID          string // local traffic selector (CIDR)
	RemoteID         string // remote traffic selector (CIDR)
	PSK              string // pre-shared key (legacy, prefer IKE policy)
	LocalAddr        string // local address
	BindInterface    string // tunnel interface (e.g. "st0.0") — creates xfrmi with if_id
	DFBit            string // "copy", "set", "clear"
	EstablishTunnels string // "immediately", "on-traffic"
}

// RoutingInstanceConfig represents a VRF-based routing instance.
type RoutingInstanceConfig struct {
	Name                    string
	Description             string
	InstanceType            string              // "virtual-router" or "vrf"
	Interfaces              []string            // interfaces belonging to this instance
	StaticRoutes            []*StaticRoute      // per-instance static routes
	OSPF                    *OSPFConfig         // per-instance OSPF (optional)
	BGP                     *BGPConfig          // per-instance BGP (optional)
	RIP                     *RIPConfig          // per-instance RIP (optional)
	ISIS                    *ISISConfig         // per-instance IS-IS (optional)
	TableID                 int                 // Linux kernel routing table number (auto-assigned)
	InterfaceRoutesRibGroup string              // interface-routes { rib-group inet <name>; }
	InterfaceRoutesRibGroupV6 string            // interface-routes { rib-group inet6 <name>; }
}
