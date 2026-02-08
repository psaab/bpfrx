package config

// Config is the top-level typed configuration, compiled from the AST.
type Config struct {
	Security     SecurityConfig
	Interfaces   InterfacesConfig
	Applications ApplicationsConfig
}

// SecurityConfig holds all security-related configuration.
type SecurityConfig struct {
	Zones         map[string]*ZoneConfig       // keyed by zone name
	Policies      []*ZonePairPolicies          // ordered list of zone-pair policy sets
	DefaultPolicy PolicyAction                 // global fallback policy (permit-all or deny-all)
	NAT           NATConfig
	Screen        map[string]*ScreenProfile    // keyed by profile name
	AddressBook   *AddressBook
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
	Static      []*StaticNATRule
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
	Match   string // internal prefix
	Then    string // external prefix
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
	Name  string
	Units map[int]*InterfaceUnit
}

// InterfaceUnit represents a logical unit on an interface.
type InterfaceUnit struct {
	Number    int
	Addresses []string // CIDR notation
}

// ApplicationsConfig holds application definitions.
type ApplicationsConfig struct {
	Applications map[string]*Application
}

// Application defines a network application by protocol and port.
type Application struct {
	Name            string
	Protocol        string // tcp, udp, icmp
	DestinationPort string // "80", "8080-8090"
}
