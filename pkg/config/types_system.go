package config

// System and platform-services configuration: system stanza, userspace
// dataplane, syslog, SNMP, login, REST API auth, RPM, flow-monitoring,
// forwarding-options, firewall filters/policers, and DHCP server/relay.

// SystemConfig holds system-level configuration.
type SystemConfig struct {
	HostName                 string
	DomainName               string   // system domain-name (e.g. "example.com")
	DomainSearch             []string // system domain-search (search domains)
	TimeZone                 string
	NameServers              []string // DNS server addresses
	NTPServers               []string // NTP server addresses
	NTPThreshold             int      // NTP threshold in seconds (0 = default)
	NTPThresholdAction       string   // "accept" or "reject"
	NoRedirects              bool     // disable ICMP redirects
	BackupRouter             string   // backup default gateway IP
	BackupRouterDst          string   // backup router destination prefix
	Lo0FilterInputV4         string   // lo0 unit 0 family inet filter input (host-bound filtering)
	Lo0FilterInputV6         string   // lo0 unit 0 family inet6 filter input (host-bound filtering)
	DataplaneType            string   // empty defaults to "userspace"; explicit "ebpf" is legacy; "dpdk" is retired (#1525) and tolerated via rewriteRetiredDataplaneType (pkg/configstore/dataplane_retire.go) at both Store.Load and Store.SyncApply for stored-config rolling upgrade
	UserspaceDataplane       *UserspaceConfig
	InternetOptions          *InternetOptionsConfig
	Services                 *SystemServicesConfig
	Syslog                   *SystemSyslogConfig
	DHCPServer               DHCPServerConfig
	SNMP                     *SNMPConfig
	Login                    *LoginConfig
	RootAuthentication       *RootAuthConfig
	Archival                 *ArchivalConfig
	MasterPassword           string   // pseudorandom-function value
	LicenseAutoUpdate        string   // license autoupdate URL
	DisabledProcesses        []string // processes marked "disable"
	PersistGroupsInheritance bool     // system commit persist-groups-inheritance (syntax accepted, runtime no-op)
}

// UserspaceConfig holds separate-process userspace dataplane configuration.
type UserspaceConfig struct {
	Binary        string            `json:"binary"`                 // helper process path
	ControlSocket string            `json:"control_socket"`         // unix control socket path
	EventSocket   string            `json:"event_socket,omitempty"` // event stream socket path (auto-derived if empty)
	StateFile     string            `json:"state_file"`             // helper state file path
	Workers       int               `json:"workers"`                // worker thread count
	RingEntries   int               `json:"ring_entries"`           // planned AF_XDP ring entries
	PollMode      string            `json:"poll_mode"`              // "busy-poll" (default) or "interrupt"
	SharedUMEM    *SharedUMEMConfig `json:"shared_umem,omitempty"`

	// RSSIndirectionDisabled, when true, disables D3 RSS indirection
	// reshaping (#785 / #797). Default is enabled — operators opt out
	// explicitly via `set system dataplane rss-indirection disable`.
	// Serialized as an inverted bool so omission implies the safe
	// default (enabled) and only disabled deploys carry the field.
	RSSIndirectionDisabled bool `json:"rss_indirection_disabled,omitempty"`

	// ClaimHostTunables is the #801 opt-in gate for host-scope knobs
	// that are NOT interface-scoped (CPU governor + netdev_budget + the
	// mlx5 adaptive-coalescence flip). D3's rss-indirection stays bound
	// to a specific NIC so it is safe to apply by default; the Step-0
	// knobs reach outside xpfd's interface allowlist and the operator
	// must explicitly opt in via
	// `set system dataplane claim-host-tunables true`. When false (the
	// default), xpfd never writes to cpufreq scaling_governor,
	// /proc/sys/net/core/netdev_budget, or mlx5 adaptive-rx/tx, even if
	// the derived default values are non-zero. Per-iface rx-usecs/tx-usecs
	// are still applied when coalescence is otherwise configured —
	// those are bound to the same mlx5 interface as D3.
	ClaimHostTunables bool `json:"claim_host_tunables,omitempty"`

	// Phase B Step-0 tunables (#801). Each is a first-class knob with
	// a documented default so operators can override without editing
	// systemd units or sysctl.conf. Omission leaves the zero value and
	// daemon resolves the default at apply-time (empty string / 0).

	// CPUGovernor requests a cpufreq governor on every writable
	// /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor node on the
	// host. Accepted values:
	//   "performance"          — explicit (default)
	//   "schedutil"            — explicit override
	//   "default" / ""         — skip (leave whatever the host has set)
	// Running inside a VM without a writable cpufreq sysfs is a no-op
	// (detected at apply-time); the daemon logs a single informational
	// line noting the skip. On bare metal the setting is applied on
	// daemon start and re-applied on every commit.
	CPUGovernor string `json:"cpu_governor,omitempty"`

	// NetdevBudget is the value written to /proc/sys/net/core/netdev_budget.
	// 0 means "leave the kernel default" (no write); the daemon
	// resolves a non-zero default at apply-time (600, per #801).
	NetdevBudget int `json:"netdev_budget,omitempty"`

	// CoalescenceAdaptiveDisabled, when true, disables mlx5 adaptive
	// coalescing on every userspace-dp-bound mlx5 interface
	// (`ethtool -C <iface> adaptive-rx off adaptive-tx off`). Default
	// is true (disable) at apply-time; the config knob is
	// `set system dataplane coalescence adaptive disable|enable`.
	// Serialized as an inverted bool so the most-common "disable"
	// deploy case is the zero value.
	//
	// CoalescenceAdaptiveExplicit distinguishes "operator explicitly
	// set enable" from "omitted, use default". Default is
	// "disabled" so an omitted knob leaves the field at
	// CoalescenceAdaptiveDisabled=false but the daemon still applies
	// "adaptive off". An explicit "enable" sets Explicit=true and
	// Disabled=false so the daemon skips the ethtool write (operator
	// override).
	CoalescenceAdaptiveDisabled bool `json:"coalescence_adaptive_disabled,omitempty"`
	CoalescenceAdaptiveExplicit bool `json:"coalescence_adaptive_explicit,omitempty"`

	// CoalescenceRXUsecs / CoalescenceTXUsecs set the rx-usecs and
	// tx-usecs coalescing ceiling on mlx5 interfaces. 0 means "use
	// daemon default" (8 µs per #801). Only written when adaptive
	// coalescing is disabled — with adaptive on, the kernel controls
	// these values dynamically and writes are a waste.
	CoalescenceRXUsecs int `json:"coalescence_rx_usecs,omitempty"`
	CoalescenceTXUsecs int `json:"coalescence_tx_usecs,omitempty"`
}

// SharedUMEMConfig is an optional AF_XDP shared-UMEM policy override passed
// through to the userspace helper. Omission lets the helper attempt
// opportunistic cross-NIC shared UMEM and fall back per binding when the live
// device/kernel path cannot support it. Phase 0 artifacts are audit evidence:
// the helper logs mismatches but does not gate runtime selection on them.
type SharedUMEMConfig struct {
	Mode           string                 `json:"mode,omitempty"`
	Interfaces     []string               `json:"interfaces,omitempty"`
	Phase0Artifact map[string]interface{} `json:"phase0_artifact,omitempty"`
}

// RootAuthConfig holds root-authentication settings.
type RootAuthConfig struct {
	EncryptedPassword string
	SSHKeys           []string
}

// ArchivalConfig holds configuration archival settings.
type ArchivalConfig struct {
	TransferOnCommit bool
	TransferInterval int // minutes between auto-archives (0 = on commit only)
	ArchiveSites     []string
	ArchiveDir       string // local directory for archives (default /var/lib/xpf/archive)
	MaxArchives      int    // max number of archives to keep (default 10)

	// #651: archive site URLs for which an inline `password "$9$..."`
	// credential was configured. bpfrx's archival shells out to `scp`
	// with `-o BatchMode=yes` and cannot use inline passwords, so a
	// password here is ignored silently unless we warn. We keep the
	// URLs (not the passwords) so the warning can name the site.
	ArchiveSitesWithPassword []string
}

// InternetOptionsConfig holds internet-options settings.
type InternetOptionsConfig struct {
	NoIPv6RejectZeroHopLimit bool
}

// SystemServicesConfig holds system services (SSH, web-management).
type SystemServicesConfig struct {
	SSH                *SSHServiceConfig
	WebManagement      *WebManagementConfig
	DNSEnabled         bool // system services dns
	DNSProxyConfigured bool // system services dns dns-proxy (syntax accepted, runtime no-op)
}

// SSHServiceConfig holds SSH service settings.
type SSHServiceConfig struct {
	RootLogin string // "allow", "deny", "deny-password"
}

// WebManagementConfig holds web management settings.
type WebManagementConfig struct {
	HTTP                bool
	HTTPS               bool
	HTTPInterface       string         // interface binding for HTTP
	HTTPSInterface      string         // interface binding for HTTPS
	SystemGeneratedCert bool           // auto-generated TLS certificate
	APIAuth             *APIAuthConfig // REST API authentication
}

// APIAuthConfig holds REST API authentication settings.
type APIAuthConfig struct {
	Users   []*APIAuthUser // basic auth users
	APIKeys []string       // bearer/X-API-Key tokens
}

// APIAuthUser defines a basic auth user for the REST API.
type APIAuthUser struct {
	Username string
	Password string
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
	V3Users     map[string]*SNMPv3User
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

// SNMPv3User defines an SNMPv3 USM user with authentication and privacy.
type SNMPv3User struct {
	Name         string
	AuthProtocol string // "md5", "sha", "sha256"
	AuthPassword string
	PrivProtocol string // "des", "aes128"
	PrivPassword string
}

// LoginClassPermission defines what a login class can do.
type LoginClassPermission int

const (
	PermView    LoginClassPermission = iota // show commands
	PermClear                               // clear commands
	PermControl                             // restart/request commands
	PermConfig                              // configure mode
	PermAll                                 // super-user: everything
)

// LoginClassPermissions maps class names to their allowed permissions.
var LoginClassPermissions = map[string][]LoginClassPermission{
	"super-user":   {PermAll},
	"operator":     {PermView, PermClear, PermControl},
	"read-only":    {PermView},
	"unauthorized": {},
}

// LoginConfig holds user account definitions.
type LoginConfig struct {
	Users []*LoginUser
}

// LoginUser defines a system user account.
type LoginUser struct {
	Name    string
	UID     int
	Class   string   // "super-user", "read-only", etc.
	SSHKeys []string // authorized SSH public keys
}

// ServicesConfig holds service configuration (flow-monitoring, RPM, etc.).
type ServicesConfig struct {
	FlowMonitoring            *FlowMonitoringConfig
	RPM                       *RPMConfig
	ApplicationIdentification bool // DPI-based application detection
}

// RPMConfig holds RPM (Real-time Performance Monitoring) configuration.
type RPMConfig struct {
	Probes map[string]*RPMProbe
}

// RPMProbe defines a single RPM probe for health monitoring.
type RPMProbe struct {
	Name  string
	Tests map[string]*RPMTest
}

const (
	DefaultRPMProbeType            = "icmp-ping"
	DefaultRPMProbeIntervalSeconds = 5
	DefaultRPMProbeCount           = 1
	DefaultRPMTestIntervalSeconds  = 60
	DefaultRPMSuccessiveLosses     = 3
	DefaultRPMTCPDestinationPort   = 80
)

// RPMTest defines a test within an RPM probe.
type RPMTest struct {
	Name                string
	ProbeType           string // "http-get", "icmp-ping", "tcp-ping"
	Target              string // target IP or hostname
	SourceAddress       string
	RoutingInstance     string
	ProbeInterval       int // seconds (0 = default 5)
	ProbeCount          int // number of probes per test (0 = default 1)
	TestInterval        int // seconds (0 = default 60)
	ThresholdSuccessive int // successive failures before probe-fail (0 = default 3)
	ProbeLimit          int // max consecutive failed probes before stopping the current test cycle (0 = unlimited)
	DestPort            int // for tcp-ping
}

func (t *RPMTest) EffectiveProbeType() string {
	if t == nil || t.ProbeType == "" {
		return DefaultRPMProbeType
	}
	return t.ProbeType
}

func (t *RPMTest) EffectiveProbeInterval() int {
	if t == nil || t.ProbeInterval <= 0 {
		return DefaultRPMProbeIntervalSeconds
	}
	return t.ProbeInterval
}

func (t *RPMTest) EffectiveProbeCount() int {
	if t == nil || t.ProbeCount <= 0 {
		return DefaultRPMProbeCount
	}
	return t.ProbeCount
}

func (t *RPMTest) EffectiveTestInterval() int {
	if t == nil || t.TestInterval <= 0 {
		return DefaultRPMTestIntervalSeconds
	}
	return t.TestInterval
}

func (t *RPMTest) EffectiveSuccessiveLossThreshold() int {
	if t == nil || t.ThresholdSuccessive <= 0 {
		return DefaultRPMSuccessiveLosses
	}
	return t.ThresholdSuccessive
}

func (t *RPMTest) EffectiveDestinationPort() int {
	if t == nil || t.DestPort <= 0 {
		return DefaultRPMTCPDestinationPort
	}
	return t.DestPort
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
	FlowActiveTimeout   int      // seconds (0 = default 60)
	FlowInactiveTimeout int      // seconds (0 = default 15)
	TemplateRefreshRate int      // seconds (0 = default 60)
	ExportExtensions    []string // e.g. "app-id", "flow-dir"
}

// ForwardingOptionsConfig holds forwarding/sampling configuration.
type ForwardingOptionsConfig struct {
	Sampling        *SamplingConfig
	DHCPRelay       *DHCPRelayConfig
	FamilyInet6Mode string // "flow-based" or "packet-based" (default "flow-based")
	PortMirroring   *PortMirroringConfig
}

// PortMirroringConfig holds port mirroring (SPAN) configuration.
type PortMirroringConfig struct {
	Instances map[string]*PortMirrorInstance
}

// PortMirrorInstance defines a named port mirroring instance.
type PortMirrorInstance struct {
	Name      string
	InputRate int      // 1-in-N sampling rate (0 = mirror all)
	Input     []string // ingress interfaces to mirror
	Output    string   // egress mirror destination interface
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
	Name        string
	InputRate   int // 1-in-N sampling rate (0 = sample all)
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
	FiltersInet        map[string]*FirewallFilter          // family inet filters
	FiltersInet6       map[string]*FirewallFilter          // family inet6 filters
	Policers           map[string]*PolicerConfig           // named policer definitions
	ThreeColorPolicers map[string]*ThreeColorPolicerConfig // named three-color policers
}

// PolicerConfig defines a single-rate two-color policer (token bucket).
type PolicerConfig struct {
	Name                    string
	BandwidthLimit          uint64 // bytes per second (converted from Junos bits/sec)
	BurstSizeLimit          uint64 // burst bucket size in bytes
	ThenAction              string // "discard" or "loss-priority high/medium-high/medium-low/low"
	LogicalInterfacePolicer bool   // shared across protocol families on the interface
}

// ThreeColorPolicerConfig defines a three-color policer (RFC 2697/2698).
type ThreeColorPolicerConfig struct {
	Name       string
	TwoRate    bool // true=two-rate (RFC 2698), false=single-rate (RFC 2697)
	ColorBlind bool // color-blind mode (default: color-aware)
	// Explicit mode/color markers are retained for commit-time ambiguity
	// checks. The dataplane snapshot still carries only the canonical mode.
	SingleRateConfigured bool
	TwoRateConfigured    bool
	ColorAwareConfigured bool
	ColorBlindConfigured bool
	CIR                  uint64 // committed information rate (bytes/sec)
	CBS                  uint64 // committed burst size (bytes)
	PIR                  uint64 // peak information rate (bytes/sec, two-rate only)
	PBS                  uint64 // peak/excess burst size (bytes)
	ThenAction           string // action on exceed/violate: "discard" or "loss-priority"
}

// FirewallFilter defines a named firewall filter with ordered terms.
type FirewallFilter struct {
	Name  string
	Terms []*FirewallFilterTerm
}

// FirewallFilterTerm is a single match/action term within a filter.
type FirewallFilterTerm struct {
	Name              string
	SourceAddresses   []string        // CIDRs
	DestAddresses     []string        // CIDRs
	SourcePrefixLists []PrefixListRef // source-prefix-list references
	DestPrefixLists   []PrefixListRef // destination-prefix-list references
	DSCP              string          // DSCP/traffic-class name (ef, af43, etc.) or number
	Protocol          string          // tcp, udp, icmp, icmpv6
	DestinationPorts  []string        // port numbers or names
	SourcePorts       []string        // source port numbers or ranges
	ICMPType          int             // -1 = not set
	ICMPCode          int             // -1 = not set
	TCPFlags          []string        // TCP flags: "syn", "ack", "fin", "rst", "psh", "urg"
	IsFragment        bool            // match IP fragments
	Action            string          // "accept", "reject", "discard", ""
	RoutingInstance   string          // routing-instance name (policy-based routing)
	Log               bool
	Count             string           // counter name
	ForwardingClass   string           // forwarding-class name
	LossPriority      string           // loss-priority (low, medium-low, medium-high, high)
	DSCPRewrite       string           // then dscp <value> — rewrite DSCP/traffic-class
	Policer           string           // then policer <name> — reference to policer definition
	FlexMatch         *FlexMatchConfig // flexible-match-range configuration
}

// FlexMatchConfig defines a flexible byte-offset match condition.
type FlexMatchConfig struct {
	MatchStart string // "layer-3" (only supported start point)
	ByteOffset uint8  // byte offset from match start
	BitLength  uint8  // match length in bits (8, 16, 32)
	Value      uint32 // expected value (after mask)
	Mask       uint32 // mask to apply before comparison
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
