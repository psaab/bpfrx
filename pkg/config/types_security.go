package config

// Security policy domain: zones, policies, NAT, screen/IDS, address book,
// applications, flow/session, ALG, logging, IPsec/IKE, dynamic-address
// feeds, and the [edit schedulers] policy time-range scheduler.

// SchedulerConfig defines a time-based policy scheduler.
type SchedulerConfig struct {
	Name      string
	StartTime string // "HH:MM:SS"
	StopTime  string // "HH:MM:SS"
	StartDate string // "YYYY-MM-DD" (optional)
	StopDate  string // "YYYY-MM-DD" (optional)
	Daily     bool   // recur daily
}

// DynamicAddressConfig defines dynamic address feed servers and address-name bindings.
type DynamicAddressConfig struct {
	FeedServers     map[string]*FeedServer
	AddressBindings map[string]*AddressBinding // keyed by address-name
}

// FeedServer defines a remote address feed source with optional per-feed paths.
type FeedServer struct {
	Name           string
	URL            string      // explicit url (takes precedence)
	Hostname       string      // hostname for building URLs with per-feed paths
	UpdateInterval int         // seconds (0 = default 3600)
	HoldInterval   int         // seconds; 0/unset = retain last-good forever on failure, >0 = drop to empty after N seconds (#2050)
	FeedName       string      // single feed-name (backward compat, no path)
	FeedEntries    []FeedEntry // named feeds with per-feed paths
}

// FeedEntry is a named feed within a feed-server, with an optional path.
type FeedEntry struct {
	Name string
	Path string
}

// AddressBinding binds an address-name to one or more feed-names via a profile.
type AddressBinding struct {
	Name      string
	FeedNames []string // feed-names referenced in the profile
}

// SecurityConfig holds all security-related configuration.
type SecurityConfig struct {
	Zones              map[string]*ZoneConfig // keyed by zone name
	Policies           []*ZonePairPolicies    // ordered list of zone-pair policy sets
	GlobalPolicies     []*Policy              // global policies (apply to all zone pairs)
	DefaultPolicy      PolicyAction           // global fallback policy (permit-all or deny-all)
	NAT                NATConfig
	Screen             map[string]*ScreenProfile // keyed by profile name
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
	ICMPSessionTimeout         int // seconds, 0 = default (60s — DEFAULT_ICMP_SESSION_TIMEOUT_NS, userspace-dp/src/session/mod.rs)
	TCPMSSAllTCP               int // TCP MSS clamp for all forwarded TCP (0 = disabled) (#2486)
	TCPMSSIPsecVPN             int // TCP MSS clamp for IPsec VPN traffic (0 = disabled) — rejected at commit (#2486: no IPsec context in the userspace forward path)
	TCPMSSGreIn                int // TCP MSS clamp for GRE ingress traffic (0 = disabled)
	TCPMSSGreOut               int // TCP MSS clamp for GRE egress traffic (0 = disabled)
	AllowDNSReply              bool
	AllowEmbeddedICMP          bool
	GREPerformanceAcceleration bool
	PowerModeDisable           bool
	SynFloodProtectionMode     string // "syn-cookie" or "" (default = drop)
	Traceoptions               *FlowTraceoptions
	AgingEarlyAgeout           int // seconds (0 = disabled)
	AgingHighWatermark         int // percent of max sessions (0 = disabled)
	AgingLowWatermark          int // percent of max sessions (0 = disabled)
	// AgingUnknownLeaves records `security flow aging` child keywords the
	// compiler does not recognize (#3440 H2). The aging subtree previously
	// silently dropped any unknown leaf; compileFlow now records them so
	// validateFlowAgingStrict can reject them at commit (mirrors
	// ScreenProfile.UnknownLeaves / #3318).
	AgingUnknownLeaves []string
}

// FlowTraceoptions holds flow trace debugging configuration.
type FlowTraceoptions struct {
	File          string   // log file name
	FileSize      int      // max file size in bytes
	FileCount     int      // number of rotated files
	Flags         []string // trace flags (e.g. "basic-datapath", "session")
	PacketFilters []*TracePacketFilter
}

// TracePacketFilter defines a packet filter for flow tracing.
type TracePacketFilter struct {
	Name              string
	SourcePrefix      string
	DestinationPrefix string
	Protocol          string // protocol name (tcp|udp|icmp|...) or number
	// InvalidPrefix marks a filter whose source-prefix or destination-prefix
	// node was PRESENT in the config but carried an empty value (e.g.
	// `source-prefix ""`). An empty prefix string is indistinguishable from an
	// absent one once it reaches the runtime (PacketFilter carries only
	// strings), but the two have opposite intent: an absent prefix is a
	// legitimate protocol-only filter, while a present-but-empty prefix is
	// malformed and — if treated as "no constraint" — collapses the filter to
	// match EVERY event (the #3422 M01 fail-open in a smaller costume). The
	// compiler, which alone sees the AST and can tell present-empty from
	// absent, sets this so the runtime (NewTraceWriter) can fail the filter
	// closed (match-none) without over-rejecting a protocol-only filter. The
	// strict commit gate rejects present-but-empty loudly; this carries the
	// conclusion through the lenient load / peer-sync path.
	InvalidPrefix bool
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
	EstablishedTimeout   int  // default 1800
	InitialTimeout       int  // default 30
	ClosingTimeout       int  // default 30
	TimeWaitTimeout      int  // default 120
	NoSynCheck           bool // allow mid-stream TCP session creation
	NoSynCheckInTunnel   bool // allow mid-stream TCP for tunnel traffic only
	RstInvalidateSession bool // immediately expire session on RST
	// NoSequenceCheck disables TCP sequence-number validation for flow
	// sessions (`set security flow tcp-session no-sequence-check`, #2008 M9).
	// Typed-config only today, exactly like NoSynCheck / RstInvalidateSession:
	// the userspace AF_XDP dataplane does not currently perform TCP
	// sequence-number window validation, so there is nothing to skip yet. The
	// field captures operator intent at commit (with schema validation +
	// completion) and is the single seam a future sequence-checking dataplane
	// would read.
	NoSequenceCheck bool
}

// LogConfig holds logging/syslog configuration.
type LogConfig struct {
	Mode            string // "stream" or "event"
	Format          string // "sd-syslog", "syslog", "binary", "structured"
	SourceInterface string // interface for source address
	Streams         map[string]*SyslogStream
	Report          bool // enable session aggregation reporting (security log report)
	// Profiles holds Junos `security log profile <name>` objects (#2008
	// H7). Before this was added the whole `profile` stanza parsed but was
	// silently discarded (no schema child, no compiler case) — a config
	// such as `vsrx-ha.conf`'s `profile default-syslog { stream-name ...;
	// default-profile; }` committed with no effect and no validation. It
	// is now compiled and cross-referenced against Streams at commit.
	Profiles map[string]*LogProfile
}

// LogProfile is a Junos `security log profile <name>` object: a named log
// routing profile that targets a configured stream and may be marked the
// default profile (#2008 H7). xpf's per-stream routing is a Junos superset
// — every stream whose category/severity filter matches receives the
// event — so a profile's StreamName names the stream that carries its
// events and DefaultProfile records the operator's default designation.
// No dispatch change is required: the runtime already routes by stream.
// The compiler cross-references StreamName against LogConfig.Streams so a
// profile naming a non-existent stream is rejected at commit rather than
// silently dropped (see validateLogProfileStreamReferencesStrict).
type LogProfile struct {
	Name           string
	StreamName     string // references LogConfig.Streams[StreamName] when set
	DefaultProfile bool   // `default-profile;` — operator's default designation
}

// SyslogTransport defines the transport protocol for a syslog stream.
type SyslogTransport struct {
	Protocol   string // "udp" (default), "tcp", "tls"
	TLSProfile string // TLS profile name (for protocol=tls)
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
	Transport     SyslogTransport
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
	// AddressBook is the zone-local address book (#3061). A policy whose
	// from-zone (source-address) or to-zone (destination-address) is this
	// zone resolves a name against this book FIRST, then falls back to the
	// global SecurityConfig.AddressBook. Resolved into the global book under
	// zone-qualified internal names by resolveZoneLocalAddressBooks during
	// compile, so the dataplane resolution path stays global-only.
	AddressBook *AddressBook
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
	// terminalActions records, in config order, the terminal action tokens
	// (permit/deny/reject) parsed under this policy's `then` stanza. It
	// exists only to drive the commit-time validator
	// (validatePolicyTerminalActionStrict, #3043): a policy MUST resolve to
	// exactly one terminal action. Zero tokens (a log-only/count-only or
	// typo'd `then`) historically fell through to Action's zero value
	// (PolicyPermit) — a silent fail-OPEN; more than one token resolved
	// last-wins (the conflicting actions were silently collapsed by child
	// visitation order). The typed Config is never serialized, so this
	// unexported field carries no persistence / back-compat obligation.
	terminalActions []PolicyAction
}

// PolicyMatch defines what traffic a policy matches.
type PolicyMatch struct {
	SourceAddresses      []string // address-book names or "any"
	DestinationAddresses []string
	Applications         []string // application names or "any"
	// SourceAddressExcluded inverts the source-address match sense:
	// when true the policy matches every source EXCEPT those named in
	// SourceAddresses (Junos `match source-address-excluded`).
	SourceAddressExcluded bool
	// DestinationAddressExcluded inverts the destination-address match
	// sense (Junos `match destination-address-excluded`).
	DestinationAddressExcluded bool
	// FromZone and ToZone carry the optional from-zone/to-zone match
	// context of a Junos GLOBAL policy (#3148). A Junos global policy may
	// narrow which zone pairs it applies to with
	// `match { from-zone <z>; to-zone <z>; }`; an empty value means "all
	// zones" (the historical global behaviour). These fields are only
	// meaningful for global policies — zone-pair policies derive their
	// zones from the surrounding from-zone/to-zone stanza, so the compiler
	// never populates these for them. The global policy is still evaluated
	// in the GLOBAL tier ordering (after exact zone-pair and the #3090
	// from-any/to-any/both-any wildcard tiers); the zone context is an
	// extra match predicate, not a tier promotion.
	FromZone string
	ToZone   string
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
	Source               []*NATRuleSet
	SourcePools          map[string]*NATPool // named source NAT pools
	AddressPersistent    bool                // source { address-persistent; }
	Destination          *DestinationNATConfig
	Static               []*StaticNATRuleSet
	NAT64                []*NAT64RuleSet
	NATv6v4              *NATv6v4Config // natv6v4 options
	PoolUtilizationAlarm *PoolUtilizationAlarmConfig
	ProxyARP             []*ProxyARPEntry
}

// ProxyARPEntry configures proxy ARP responses for NAT addresses.
type ProxyARPEntry struct {
	Interface string
	Addresses []string // /32 CIDRs (expanded from ranges)
}

// PoolUtilizationAlarmConfig configures NAT pool utilization alarms.
type PoolUtilizationAlarmConfig struct {
	RaiseThreshold int
	ClearThreshold int
}

// NATv6v4Config holds NAT64 v6-to-v4 translation options.
type NATv6v4Config struct {
	NoV6FragHeader bool // no-v6-frag-header: omit IPv6 fragment header in translated packets
}

// NAT64RuleSet defines NAT64 translation rules.
type NAT64RuleSet struct {
	Name       string
	Prefix     string // well-known prefix, e.g. "64:ff9b::/96"
	SourcePool string // IPv4 source pool name for translated packets
}

// StaticNATRuleSet is a set of static 1:1 NAT rules bound to a from scope.
// Junos static NAT has only a `from` clause (no `to`). The scope is one of
// zone | interface | routing-instance (#3096); exactly one of FromZone /
// FromInterface / FromRoutingInstance is non-empty for a scoped rule-set, and
// all three empty means match-any (global). The compiler Cartesian-expands a
// bracket list of scope values into one StaticNATRuleSet per value.
type StaticNATRuleSet struct {
	Name     string
	FromZone string
	// FromInterface scopes the rule-set to traffic ingressing this logical
	// interface (config name, e.g. "ge-0/0/1.0"). "" = unscoped. #3096.
	FromInterface string
	// FromRoutingInstance scopes the rule-set to traffic in this routing
	// instance / VRF. "" = the default instance / unscoped. #3096.
	FromRoutingInstance string
	Rules               []*StaticNATRule
}

// DestinationNATConfig holds destination NAT pools and rule sets.
type DestinationNATConfig struct {
	Pools    map[string]*NATPool
	RuleSets []*NATRuleSet
}

// NATRuleSet is a set of NAT rules bound to a from/to scope pair. Each scope
// side is one of zone | interface | routing-instance (Junos #3096); within a
// side exactly one of the *Zone / *Interface / *RoutingInstance fields is
// non-empty for a scoped rule-set, and all-empty means match-any (global) on
// that side. The compiler Cartesian-expands a bracket list of scope values
// into one NATRuleSet per (from-scope, to-scope) pair, mirroring the existing
// from-zone × to-zone expansion.
type NATRuleSet struct {
	Name     string
	FromZone string
	ToZone   string
	// FromInterface / ToInterface scope the rule-set to traffic
	// ingressing / egressing this logical interface (config name, e.g.
	// "ge-0/0/1.0"). "" = unscoped on that side. #3096.
	FromInterface string
	ToInterface   string
	// FromRoutingInstance / ToRoutingInstance scope the rule-set to traffic
	// in this routing instance / VRF on ingress / egress. "" = the default
	// instance / unscoped. #3096.
	FromRoutingInstance string
	ToRoutingInstance   string
	Rules               []*NATRule
}

// NATRule is a single NAT rule.
type NATRule struct {
	Name  string
	Match NATMatch
	Then  NATThen
}

// NATMatch defines what traffic a NAT rule matches.
type NATMatch struct {
	SourceAddress          string   // CIDR (first address, for backward compat)
	SourceAddresses        []string // all matched source CIDRs (bracket list support)
	SourceAddressName      string   // address-book name (resolved during compilation)
	DestinationAddress     string   // CIDR (first address, for backward compat)
	DestinationAddresses   []string // all matched destination CIDRs (bracket list support)
	DestinationAddressName string   // address-book name (resolved during compilation, #3229)
	DestinationPort        int      // primary port (first port for BPF rule)
	DestinationPorts       []int    // all matched ports (for multi-port DNAT rules)
	Protocol               string   // "tcp", "udp", "icmp6", "gre", or "" (auto)
	Application            string   // application name (e.g. "junos-http")
}

// NATThen defines the NAT translation action.
type NATThen struct {
	Type      NATType
	Interface bool   // source-nat interface mode
	PoolName  string // pool reference
	Off       bool   // source-nat off (no-NAT exemption)
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
	Deterministic *DeterministicNATConfig
}

// PersistentNATPermit selects the remote-endpoint scope of a persistent
// NAT binding (Junos `persistent-nat permit`, #2823). It replaces the
// pre-#2823 binary PermitAnyRemoteHost bool with the full three-way enum.
type PersistentNATPermit string

const (
	// PersistentNATPermitAnyRemoteHost: any external host reuses the
	// binding. The lease is keyed by the local source tuple only (no
	// remote endpoint in the key). Junos `permit any-remote-host`.
	PersistentNATPermitAnyRemoteHost PersistentNATPermit = "any-remote-host"
	// PersistentNATPermitTargetHost: scoped to the original remote HOST.
	// The lease is keyed by the source tuple + remote destination IP only
	// (the remote PORT is dropped), so a new flow to a NEW remote port on
	// the SAME host reuses the binding. Junos `permit target-host`.
	PersistentNATPermitTargetHost PersistentNATPermit = "target-host"
	// PersistentNATPermitTargetHostPort: scoped to the original remote
	// host:PORT. The lease is keyed by the source tuple + remote
	// destination IP + destination port, so a new remote port keys to a
	// distinct lease. Junos `permit target-host-port`. This is the
	// pre-#2823 false-flag behavior and the default when `persistent-nat`
	// is configured without an explicit `permit` (preserves #2819).
	PersistentNATPermitTargetHostPort PersistentNATPermit = "target-host-port"
)

// PersistentNATConfig configures persistent NAT bindings for a pool.
type PersistentNATConfig struct {
	// Permit is the remote-host reuse scope. The default (when
	// `persistent-nat` is configured with no `permit`) is
	// PersistentNATPermitTargetHostPort, matching the pre-#2823 binary
	// model's false-flag (dst_ip, dst_port) keying so existing configs are
	// byte-identical. #2823.
	Permit            PersistentNATPermit
	InactivityTimeout int // seconds (default 300)
}

// DeterministicNATConfig configures CGNAT deterministic port allocation.
type DeterministicNATConfig struct {
	BlockSize   int    // port block size per subscriber (e.g. 2016)
	HostAddress string // subscriber CIDR (e.g. "100.64.0.0/22")
}

// StaticNATRule is a 1:1 bidirectional NAT rule.
type StaticNATRule struct {
	Name          string
	Match         string // destination-address (external/public IP)
	SourceAddress string // source-address match (optional, e.g. "::/0" for NAT64)
	Then          string // static-nat prefix (internal/private IP), or "inet" for NAT64
	IsNPTv6       bool   // true if this is an nptv6-prefix rule (RFC 6296)
	// MatchDestinationPort is the external (pre-translation) destination
	// port the inbound packet must carry for this rule to apply (Junos
	// `match destination-port`). 0 = match any port (whole-address 1:1,
	// the legacy behaviour). #2491.
	MatchDestinationPort int
	// MappedPort is the internal (post-translation) destination port the
	// 1:1 host receives (Junos `then static-nat prefix <ip> mapped-port
	// <port>`). 0 = no port translation (whole-address 1:1). When set, the
	// inbound DNAT rewrites the destination port to this value and the
	// outbound return SNAT un-translates it back to MatchDestinationPort.
	// #2491.
	MappedPort int
}

// LimitSessionScreen configures per-IP session limiting.
type LimitSessionScreen struct {
	SourceIPBased      int // max sessions per source IP, 0 = disabled
	DestinationIPBased int // max sessions per destination IP, 0 = disabled
}

// ScreenProfile defines IDS screening options.
type ScreenProfile struct {
	Name         string
	ICMP         ICMPScreen
	IP           IPScreen
	TCP          TCPScreen
	UDP          UDPScreen
	LimitSession LimitSessionScreen

	// BadNumeric records screen numeric leaves whose explicitly-provided value
	// failed to parse as a positive integer (#3317). compileScreen previously
	// swallowed the strconv.Atoi error and fell back to a Junos default or to
	// zero/disabled — a typo'd threshold silently disabled or weakened the
	// protection (fail-open). validateScreenNumericStrict reads this to reject
	// the commit fail-closed instead of silently defaulting. Each entry names
	// the screen leaf path and the offending value.
	BadNumeric []ScreenBadNumeric
	// UnknownLeaves records screen leaves the dataplane does NOT support
	// (#3318). The screen schema subtrees are open and compileScreen switched
	// only on known child names with no default case, so a misspelled or
	// unsupported leaf committed cleanly and was silently dropped — the operator
	// believed a control was enabled when it was absent. validateScreenUnknownStrict
	// reads this to reject the commit fail-closed. Each entry is the full
	// `<family> <leaf>` path under the ids-option.
	UnknownLeaves []string
}

// ScreenBadNumeric records a screen numeric leaf whose explicitly-provided value
// did not parse as a positive integer (#3317): the full leaf path (e.g.
// "tcp syn-flood attack-threshold") and the raw offending value.
type ScreenBadNumeric struct {
	Path  string
	Value string
}

// ICMPScreen configures ICMP screening.
type ICMPScreen struct {
	PingDeath      bool
	Fragment       bool
	FloodThreshold int
}

// IPScreen configures IP screening.
type IPScreen struct {
	SourceRouteOption bool
	TearDrop          bool
	IPSweepThreshold  int // unique destination IPs per source (0 = disabled)
}

// TCPScreen configures TCP screening.
type TCPScreen struct {
	SynFlood          *SynFloodConfig
	Land              bool
	WinNuke           bool
	SynFrag           bool
	SynFin            bool
	NoFlag            bool
	FinNoAck          bool
	PortScanThreshold int // TCP SYN count per source IP (0 = disabled)
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
	Name        string
	Value       string // CIDR notation
	Description string // optional Junos `description` sub-stanza
	// TrailingTokens holds tokens that rode past the legitimate arity of a
	// flat-set `address <name> <prefix>` / `address <name> description
	// <text>` line (#3332). The address node is a `multi:true` leaf (so the
	// generic scalar-leaf arity gate cannot reach it) and the compiler reads
	// only the prefix / description-text slot, silently dropping anything
	// after it. validateAddressBookTrailingStrict rejects these at commit
	// (lenient downgrade on the tolerant load / peer-sync path).
	TrailingTokens []string
}

// AddressSet is a named group of addresses and/or nested address-sets.
type AddressSet struct {
	Name        string
	Addresses   []string // references to Address names
	AddressSets []string // references to other AddressSet names (nested)
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
	// ICMPType / ICMPCode constrain an ICMP/ICMPv6 application to a single
	// message type (and optionally code), e.g. junos-ping = ICMP type 8
	// (echo-request) and junos-pingv6 = ICMPv6 type 128. nil means "no
	// constraint" — the application matches every type/code of its protocol
	// (the historical behavior and what the all-ICMP aliases keep). #3020.
	ICMPType *uint8
	ICMPCode *uint8
	// UnknownTimeouts records the raw `inactivity-timeout` / `timeout` tokens
	// (top-level or inline-term) that did NOT parse to a valid integer in the
	// accepted 1..86400-second range. compileApplications cannot return an
	// error from the per-leaf parse without breaking the tolerant load path, so
	// — mirroring UnknownActions / UnknownFlexMatch — it records the offending
	// raw token here and the deferred gate (validateApplicationSpecsStrict)
	// hard-rejects it on the strict commit path / warns on the lenient
	// load / peer-sync path. A malformed value left InactivityTimeout at its
	// zero default, silently falling the application back to the global
	// per-protocol timeout instead of the configured one (#3320).
	UnknownTimeouts []string
	// UnknownICMP records the raw `icmp-type` / `icmp-code` tokens (top-level or
	// inline-term) that did NOT parse to a valid integer in 0..255. The schema
	// range-validates the TOP-LEVEL leaves at commit-check, but the inline
	// `term` is opaque to the schema walk (children:nil), so a malformed inline
	// `icmp-type` would otherwise be silently dropped by parseICMPTypeCode —
	// leaving the term UNCONSTRAINED, i.e. matching every ICMP type (a fail-open
	// widening, the inverse of the #3348 fix). Mirroring UnknownTimeouts, the
	// offending raw token is recorded here and the deferred gate
	// (validateApplicationSpecsStrict) hard-rejects it on the strict commit path
	// / warns on the lenient load / peer-sync path (#3348).
	UnknownICMP []string
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
	PSK       Secret // pre-shared key; redacted on JSON/YAML marshal (#2053)
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
	Name      string
	PFSGroup  int    // PFS DH group number (0 = disabled)
	Proposals string // IPsec proposal reference
}

// IPsecGateway defines a remote IKE gateway.
type IPsecGateway struct {
	Name             string
	Address          string // remote gateway IP
	DynamicHostname  string // dynamic peer hostname (DNS-resolved)
	ResponderOnly    bool   // dynamic peer with no fixed address/hostname: responder-only (remote_addrs = %any)
	LocalAddress     string // local IP
	IKEPolicy        string // IKE policy reference
	ExternalIface    string // external-facing interface
	LocalCertificate string // local certificate name for pubkey auth
	Version          string // "v1-only", "v2-only" (empty = both)
	NoNATTraversal   bool   // disable NAT-T (legacy, use NATTraversal)
	NATTraversal     string // "enable" (default), "disable", "force"
	DeadPeerDetect   string // "always-send", "optimized", "probe-idle"
	DPDInterval      int    // seconds
	DPDThreshold     int    // retry count before peer is considered dead
	LocalIDType      string // "hostname", "inet", "fqdn"
	LocalIDValue     string // identity value
	RemoteIDType     string // "hostname", "inet", "fqdn"
	RemoteIDValue    string // identity value
	// DynamicHostnameExtras holds tokens that rode past the FQDN on a
	// compact-hierarchical `dynamic hostname <fqdn> <extra>` line (#3332).
	// The flat-set form lands `hostname <fqdn>` as a scalar child the generic
	// arity gate covers, but the compact-hierarchical form collapses
	// `hostname <fqdn> <extra>` onto the parent `dynamic` node's Keys and the
	// compiler reads only Keys[2], silently dropping the rest.
	// validateTrailingTokensStrict rejects these at commit (lenient downgrade
	// on the tolerant load / peer-sync path).
	DynamicHostnameExtras []string
}

type IPsecTrafficSelector struct {
	Name     string
	LocalIP  string
	RemoteIP string
}

// IPsecVPN defines an IPsec VPN tunnel.
type IPsecVPN struct {
	Name             string
	Gateway          string // gateway reference
	IPsecPolicy      string // IPsec policy reference
	LocalID          string // local traffic selector (CIDR)
	RemoteID         string // remote traffic selector (CIDR)
	PSK              Secret // pre-shared key (legacy, prefer IKE policy); redacted on marshal (#2053)
	LocalAddr        string // local address
	BindInterface    string // tunnel interface (e.g. "st0.0") — creates xfrmi with if_id
	DFBit            string // "copy", "set", "clear"
	EstablishTunnels string // "immediately", "on-traffic"
	TrafficSelectors map[string]*IPsecTrafficSelector
}
