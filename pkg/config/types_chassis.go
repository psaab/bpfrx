package config

// Chassis cluster, redundancy groups, interface/IP monitoring, event
// policies, and bridge domains.

// ChassisConfig holds chassis-level configuration (clustering, etc).
type ChassisConfig struct {
	Cluster *ClusterConfig
	// DeviceMap is the #1956 bare-metal stable-identity managed allowlist.
	// nil OR an empty entry set means positional mode (today's behavior);
	// device-map mode is selected on len(DeviceMap.Entries) > 0, never on
	// DeviceMap != nil (an empty `chassis device-map {}` block must not
	// trip the silent-all-unconfigured trap — R-7/V-7).
	DeviceMap *DeviceMapConfig
}

// DeviceMapConfig is the #1956 bare-metal device-map: an opt-in stanza that
// binds host NICs (by stable identity — PCI bus address with permanent-MAC
// fallback) to xpf logical names, and governs everything NOT named here via
// UnmappedPolicy. See docs/bare-metal-device-map.md and the plan in
// docs/research/1956-bare-metal-device-map/.
type DeviceMapConfig struct {
	// Entries binds each logical name to a stable host identity.
	Entries []DeviceMapEntry
	// UnmappedPolicy governs NICs with no entry:
	//   "leave-alone" (default in device-map mode): never renamed, never
	//                 marked always-down, never address-stripped.
	//   "manage-down": today's claim-all behavior (bring unconfigured NICs
	//                 down). Provided for operators who DO want xpf to own
	//                 the whole box.
	UnmappedPolicy string
}

// DeviceMapPolicyLeaveAlone / DeviceMapPolicyManageDown are the two
// unmapped-interface-policy values. Leave-alone is the bare-metal default.
const (
	DeviceMapPolicyLeaveAlone = "leave-alone"
	DeviceMapPolicyManageDown = "manage-down"
)

// DeviceMapKey* are the per-entry identity key-order values (V-5). The
// default (empty) is treated as pci-then-mac.
const (
	DeviceMapKeyPCIThenMAC = "pci-then-mac"
	DeviceMapKeyMACThenPCI = "mac-then-pci"
	DeviceMapKeyPCI        = "pci"
	DeviceMapKeyMAC        = "mac"
)

// DeviceMapEntry binds one xpf logical name to one host NIC identity.
type DeviceMapEntry struct {
	// LogicalName is the xpf/vSRX name the bound NIC is renamed to
	// (e.g. "ge-0/0/3", "fxp0"). Stored Junos-style with slashes; the
	// daemon converts to the Linux kernel name (ge-0-0-3) via LinuxIfName.
	LogicalName string
	// PCIAddr is the primary identity key (DDDD:BB:DD.F), "" if unset.
	PCIAddr string
	// MAC is the permanent/factory-MAC fallback key, "" if unset. Compared
	// against PermHWAddr, never the running MAC (RETH virtual-MAC alternates
	// — R-3/R-6).
	MAC string
	// KeyOrder selects the resolution priority chain (DeviceMapKey*).
	// "" => pci-then-mac.
	KeyOrder string
}

// EffectiveKeyOrder returns the entry's key-order, defaulting empty to
// pci-then-mac.
func (e DeviceMapEntry) EffectiveKeyOrder() string {
	if e.KeyOrder == "" {
		return DeviceMapKeyPCIThenMAC
	}
	return e.KeyOrder
}

// EffectiveUnmappedPolicy returns the device-map's unmapped-interface-policy,
// defaulting empty to leave-alone (the bare-metal-safe default — an operator
// who wrote a map clearly wants selective management).
func (d *DeviceMapConfig) EffectiveUnmappedPolicy() string {
	if d == nil || d.UnmappedPolicy == "" {
		return DeviceMapPolicyLeaveAlone
	}
	return d.UnmappedPolicy
}

// Active reports whether device-map mode is engaged: a non-nil config with at
// least one entry. An empty `device-map {}` block is positional mode (R-7).
func (d *DeviceMapConfig) Active() bool {
	return d != nil && len(d.Entries) > 0
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
	DHCPLeaseSync         bool   // enable DHCP-server lease synchronization (#2239 PATH C: lease state held on standby, seeded into Kea on takeover)
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
