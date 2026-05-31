package config

// Chassis cluster, redundancy groups, interface/IP monitoring, event
// policies, and bridge domains.
// ChassisConfig holds chassis-level configuration (clustering, etc).
type ChassisConfig struct {
	Cluster *ClusterConfig
}

// ClusterConfig defines chassis cluster settings for HA.
type ClusterConfig struct {
	ClusterID             int
	NodeID                int
	RethCount             int
	HeartbeatInterval     int    // milliseconds, 0=default(1000)
	HeartbeatThreshold    int    // missed heartbeats before lost, 0=default(3)
	ControlInterface      string // interface for heartbeat traffic (e.g. "hb0")
	PeerAddress           string // peer node's control link IP (e.g. "10.99.0.2")
	FabricInterface       string // interface for session/config sync (e.g. "fab0")
	FabricPeerAddress     string // peer's fabric link IP (e.g. "10.99.1.2")
	Fabric1Interface      string // secondary fabric interface (e.g. "fab1")
	Fabric1PeerAddress    string // peer's secondary fabric IP
	ConfigSync            bool   // enable config synchronization to peer on commit
	ControlLinkRecovery   bool   // enable control-link-recovery
	NATStateSync          bool   // enable NAT state synchronization (session sync with NAT fields)
	IPsecSASync           bool   // enable IPsec SA synchronization (connection name sync for failover re-initiation)
	RethAdvertiseInterval int    // RETH VRRP advertisement interval in milliseconds, 0=default(30)
	HitlessRestart        bool   // preserve BPF state on shutdown (default false in HA — fail-closed)
	PeerFencing           string // peer fencing action on heartbeat timeout: "", "disable-rg"
	TakeoverHoldTime      int    // milliseconds, 0=immediate takeover once ready
	NoRethVRRP            bool   // cluster directly manages VIPs (no VRRP for RETH interfaces)
	PrivateRGElection     bool   // election over control link only, suppress RETH VRRP
	RedundancyGroups      []*RedundancyGroup
}

// RedundancyGroup defines a cluster redundancy group.
type RedundancyGroup struct {
	ID                 int
	NodePriorities     map[int]int // node-id -> priority
	GratuitousARPCount int
	Preempt            bool
	StrictVIPOwnership bool
	InterfaceMonitors  []*InterfaceMonitor
	IPMonitoring       *IPMonitoring
}

// InterfaceMonitor defines an interface health monitor within a redundancy group.
type InterfaceMonitor struct {
	Interface string
	Weight    int
}

// IPMonitoring defines IP reachability monitoring for a redundancy group.
type IPMonitoring struct {
	GlobalWeight    int
	GlobalThreshold int
	Targets         []*IPMonitorTarget
}

// IPMonitorTarget defines a single IP address to probe for reachability.
type IPMonitorTarget struct {
	Address string
	Weight  int
}

// EventPolicy defines an event-driven policy (event-options).
type EventPolicy struct {
	Name            string
	Events          []string
	WithinClauses   []*EventWithin
	AttributesMatch []string // raw "field matches pattern" strings
	ThenCommands    []string // change-configuration commands
}

// EventWithin defines a temporal trigger clause.
type EventWithin struct {
	Seconds      int
	TriggerOn    int // trigger on N
	TriggerUntil int // trigger until N
}

// BridgeDomainConfig defines a bridge domain with VLAN membership and optional IRB interface.
type BridgeDomainConfig struct {
	Name             string // bridge domain name (e.g. "bd0")
	VlanIDs          []int  // member VLAN IDs
	RoutingInterface string // IRB routing interface reference (e.g. "irb.0")
	DomainType       string // bridge domain type (optional)
}
