package config

import (
	"encoding/json"
	"fmt"
	"sort"
)

// System and platform-services configuration: system stanza, userspace
// dataplane, syslog, SNMP, login, REST API auth, RPM, flow-monitoring,
// forwarding-options, firewall filters/policers, and DHCP server/relay.

// SystemConfig holds system-level configuration.
type SystemConfig struct {
	HostName           string
	DomainName         string   // system domain-name (e.g. "example.com")
	DomainSearch       []string // system domain-search (search domains)
	TimeZone           string
	NameServers        []string // DNS server addresses
	NTPServers         []string // NTP server addresses
	NTPThreshold       int      // NTP threshold in seconds (0 = default)
	NTPThresholdAction string   // "accept" or "reject"
	NoRedirects        bool     // disable ICMP redirects
	BackupRouter       string   // backup default gateway IP
	BackupRouterDst    string   // backup router destination prefix
	Lo0FilterInputV4   string   // lo0 unit 0 family inet filter input (host-bound filtering)
	Lo0FilterInputV6   string   // lo0 unit 0 family inet6 filter input (host-bound filtering)
	DataplaneType      string   // empty defaults to "userspace"; explicit "ebpf" is legacy; "dpdk" is retired (#1525) and tolerated via rewriteRetiredDataplaneType (pkg/configstore/dataplane_retire.go) at both Store.Load and Store.SyncApply for stored-config rolling upgrade
	UserspaceDataplane *UserspaceConfig
	InternetOptions    *InternetOptionsConfig
	Services           *SystemServicesConfig
	Syslog             *SystemSyslogConfig
	DHCPServer         DHCPServerConfig
	SNMP               *SNMPConfig
	Login              *LoginConfig
	RootAuthentication *RootAuthConfig
	Archival           *ArchivalConfig
	// MasterPassword is a misnomer kept for the Junos token: it holds the
	// `system master-password pseudorandom-function <fn>` value, i.e. the PRF
	// ALGORITHM-SELECTOR NAME (e.g. hmac-sha256), NOT key material. The actual
	// master key is node-local + HKDF-derived and never stored in config (see
	// compiler_system.go / configstore/crypto.go), so this field is not a
	// secret and is intentionally a plain string, not config.Secret (#2053).
	MasterPassword           string   // PRF algorithm-selector name (not a secret)
	LicenseAutoUpdate        string   // license autoupdate URL
	DisabledProcesses        []string // processes marked "disable"
	PersistGroupsInheritance bool     // system commit persist-groups-inheritance (syntax accepted, runtime no-op)

	// ManagementInterface is the #1922 Item 3B/Item 4 explicit management
	// interface override ("" = unset, defaults to fxp0). When set, it joins
	// the protected set (never brought down by the unmanaged strip); an
	// explicit non-fxp0 value also NARROWS fxp0 out of the auto-protection
	// (OQ-D escape valve, so fxp0 can be repurposed as a revenue port).
	// The typed field is wired through the protected-set resolver; the
	// config-mode `set system management-interface <name>` parser grammar is
	// deferred (the no-config bootstrap default-route signal is the primary
	// lifeline path; this leaf is the operator override once a config
	// exists). See docs/research/1922-safe-bootstrap-daemon/plan.md Item 3B.
	ManagementInterface string
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

	// RetiredKnobsSeen records which retired DPDK-era `system dataplane`
	// knobs (cores, memory, socket-mem, rx-mode, ports — consumer deleted
	// in #1525) were present in the compiled tree. They are accepted for
	// stored-config compatibility but have no effect; the compiler turns
	// each into a commit warning (userspaceRetiredKnobWarnings, #1892).
	// Compile-time bookkeeping only — never serialized.
	RetiredKnobsSeen []string `json:"-"`
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
	EncryptedPassword Secret // crypt(3) hash; redacted on JSON/YAML marshal (#2053)
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
	// DynamicDNS is the `system services dynamic-dns` provider catalog + engine
	// tunables (#2691 P2, plan §5.9). It is the OPERATOR-FACING shared catalog
	// the per-interface Surface A `dynamic-dns` bindings reference by name
	// (credentials configured once, referenced by scope). nil == no Surface A
	// DDNS configured.
	DynamicDNS *DDNSServicesConfig
}

// DDNSServicesConfig is the `system services dynamic-dns` block (#2691 P2,
// plan §5.9): a named provider catalog (referenced by per-interface Surface A
// bindings) plus the global engine tunables (the inadyn period/forced-update
// analogues). nil == no Surface A DDNS configured (Surface B's DHCP-lease DDNS
// is unaffected — it keeps its inline stanza under dhcp-local-server).
type DDNSServicesConfig struct {
	// Providers is the named provider catalog, keyed by provider name. A
	// per-interface `dynamic-dns provider <name>` binding references one of
	// these entries (credentials + transport binding configured once here).
	Providers map[string]*DDNSProvider
	// ForcedRefreshSeconds is the wire-update FLOOR for an unchanged address
	// (inadyn idea #7, plan §5.5): the engine re-asserts desired state every
	// reconcile but sends a wire UPDATE for an unchanged address at most once
	// per this interval. 0 == the engine default (24h).
	ForcedRefreshSeconds int
	// ErrorBackoffMaxSeconds caps the per-scope flat error backoff (inadyn idea
	// #8, plan §5.5): a failing provider is not hammered at the poll cadence
	// (ban-avoidance). 0 == the engine default (1h).
	ErrorBackoffMaxSeconds int
}

// DDNSProvider is one named entry in the `system services dynamic-dns provider`
// catalog (#2691 P2, plan §5.2/§5.9). It carries the backend selection, the
// credentials (config.Secret-redacted), and the per-provider transport binding
// (source/interface/VRF). P2 implements the rfc2136 backend; the HTTP backends
// (dyndns2/cloudflare/route53/generic) are reserved enum values that P3
// implements (an unimplemented backend publishes nothing and warns at commit).
type DDNSProvider struct {
	// Name is the provider identity (the `provider <name>` token), used by
	// per-interface bindings to reference this catalog entry.
	Name string
	// Backend selects the DNS-update mechanism. "rfc2136" (default, live in P2)
	// publishes over RFC 2136 UPDATE. "dyndns2" / "cloudflare" / "route53" /
	// "generic" are reserved for P3 (the HTTP providers).
	Backend string
	// UpdateServer is the RFC 2136 target authoritative DNS, host or host:port.
	UpdateServer string
	// TSIGKeyName / TSIGAlgorithm / TSIGSecret are the TSIG credentials for
	// authenticated RFC 2136 updates. TSIGSecret is the sensitive HMAC key,
	// redacted by the Secret type on every marshal and by String() below.
	TSIGKeyName   string
	TSIGAlgorithm string
	TSIGSecret    Secret
	// SourceAddress / DestinationInterface / RoutingInstance scope the RFC 2136
	// UPDATE TRANSPORT for this provider (the same source-binding model as the
	// Surface B per-family leaves, #2665). All optional.
	SourceAddress        string
	DestinationInterface string
	RoutingInstance      string
}

// String redacts TSIGSecret so a %v/%s/slog format of a DDNSProvider never
// leaks the shared HMAC key (logging hygiene, mirrors DHCPDynamicDNSConfig).
func (p *DDNSProvider) String() string {
	if p == nil {
		return "<nil>"
	}
	secret := ""
	if p.TSIGSecret != "" {
		secret = "<redacted>"
	}
	return fmt.Sprintf("DDNSProvider{name=%q backend=%q update-server=%q "+
		"tsig-key=%q tsig-alg=%q tsig-secret=%q source-address=%q "+
		"destination-interface=%q routing-instance=%q}",
		p.Name, p.Backend, p.UpdateServer, p.TSIGKeyName, p.TSIGAlgorithm,
		secret, p.SourceAddress, p.DestinationInterface, p.RoutingInstance)
}

// SSHServiceConfig holds SSH service settings.
type SSHServiceConfig struct {
	RootLogin   string   // "allow", "deny", "deny-password"
	KeyExchange []string // sshd KexAlgorithms (key-exchange methods)
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
	APIKeys []Secret       // bearer/X-API-Key tokens; redacted on marshal (#2053)
}

// APIAuthUser defines a basic auth user for the REST API.
type APIAuthUser struct {
	Username string
	Password Secret // redacted on JSON/YAML marshal (#2053)
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

// MarshalJSON redacts the SNMPv1/v2c community strings on the JSON surface
// (#2053). The community string is the secret AND the Communities map key,
// so a plain map marshal would leak it as a JSON object key regardless of
// SNMPCommunity.MarshalJSON (which only redacts the value's Name field). To
// avoid emitting secret keys, the Communities map is rendered as a sorted
// slice of (already-redacting) SNMPCommunity values — dropping the
// secret-equals-the-key. V3Users/TrapGroups keys are usernames/group names
// (not secrets) and pass through unchanged. The in-memory map (and its
// lookup-by-community-string in pkg/snmp) is untouched.
func (s SNMPConfig) MarshalJSON() ([]byte, error) {
	// NOTE: the snmpAlias projection below is intentionally duplicated in
	// MarshalYAML; the two MUST stay in sync. If you add/rename a field here,
	// mirror it in MarshalYAML or the JSON and YAML redaction surfaces diverge.
	type snmpAlias struct {
		Location    string
		Contact     string
		Description string
		Communities []*SNMPCommunity
		TrapGroups  map[string]*SNMPTrapGroup
		V3Users     map[string]*SNMPv3User
	}
	a := snmpAlias{
		Location:    s.Location,
		Contact:     s.Contact,
		Description: s.Description,
		TrapGroups:  s.TrapGroups,
		V3Users:     s.V3Users,
	}
	if len(s.Communities) > 0 {
		names := make([]string, 0, len(s.Communities))
		for name := range s.Communities {
			names = append(names, name)
		}
		sort.Strings(names)
		a.Communities = make([]*SNMPCommunity, 0, len(names))
		for _, name := range names {
			a.Communities = append(a.Communities, s.Communities[name])
		}
	}
	return json.Marshal(a)
}

// MarshalYAML mirrors MarshalJSON for the gopkg.in/yaml.v3 marshaller,
// redacting the community-string map keys by rendering Communities as a
// sorted slice (future-proofing; no config YAML marshaller exists today —
// #2053).
func (s SNMPConfig) MarshalYAML() (any, error) {
	// Keep this projection in sync with MarshalJSON above (same snmpAlias +
	// Communities map->sorted-slice redaction).
	type snmpAlias struct {
		Location    string
		Contact     string
		Description string
		Communities []*SNMPCommunity
		TrapGroups  map[string]*SNMPTrapGroup
		V3Users     map[string]*SNMPv3User
	}
	a := snmpAlias{
		Location:    s.Location,
		Contact:     s.Contact,
		Description: s.Description,
		TrapGroups:  s.TrapGroups,
		V3Users:     s.V3Users,
	}
	if len(s.Communities) > 0 {
		names := make([]string, 0, len(s.Communities))
		for name := range s.Communities {
			names = append(names, name)
		}
		sort.Strings(names)
		a.Communities = make([]*SNMPCommunity, 0, len(names))
		for _, name := range names {
			a.Communities = append(a.Communities, s.Communities[name])
		}
	}
	return a, nil
}

// SNMPCommunity defines an SNMP community string.
//
// Name is the SNMPv1/v2c community string, which IS the shared secret (it
// authorizes the request on the wire). It is also the key of the
// SNMPConfig.Communities map, so it stays a plain string (the map lookup in
// pkg/snmp/agent.go is by the on-wire community string). Redaction is
// applied only on the JSON/YAML surface via the targeted MarshalJSON /
// MarshalYAML below — keeping it a string means the map key, the compiler
// assignment, and the text `show snmp` / `show configuration` render paths
// (which print the map key, not this field, and are out of scope for the
// #2053 marshal leak) are all unchanged.
type SNMPCommunity struct {
	Name          string
	Authorization string // "read-only" or "read-write"
}

// MarshalJSON redacts the community string (the secret) on the JSON
// surface, e.g. GET /api/v1/config, while leaving Authorization in the
// clear. See the type doc for why Name stays a plain string (#2053).
func (c SNMPCommunity) MarshalJSON() ([]byte, error) {
	type alias struct {
		Name          Secret
		Authorization string
	}
	return json.Marshal(alias{Name: Secret(c.Name), Authorization: c.Authorization})
}

// MarshalYAML mirrors MarshalJSON for the gopkg.in/yaml.v3 marshaller
// (future-proofing; no config YAML marshaller exists today — #2053).
func (c SNMPCommunity) MarshalYAML() (any, error) {
	return struct {
		Name          Secret
		Authorization string
	}{Name: Secret(c.Name), Authorization: c.Authorization}, nil
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
	AuthPassword Secret // redacted on JSON/YAML marshal (#2053)
	PrivProtocol string // "des", "aes128"
	PrivPassword Secret // redacted on JSON/YAML marshal (#2053)
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
//
// The key set here is the authoritative list of system-defined Junos login
// classes xpf accepts; ValidLoginClasses (and the schema `class` enum, #2008
// H6) is derived from it so the commit-time validator and the runtime RBAC
// table can never drift apart.
var LoginClassPermissions = map[string][]LoginClassPermission{
	"super-user": {PermAll},
	"operator":   {PermView, PermClear, PermControl},
	"read-only":  {PermView},
	// config-viewer can view (including config display, which routes through
	// `show`) but cannot enter configure to modify, clear, or operate (#2008
	// H6). Within the current coarse permission model that is PermView only.
	"config-viewer": {PermView},
	"unauthorized":  {},
}

// ValidLoginClasses is the sorted set of system-defined login class names the
// `system login user <name> class <class>` leaf accepts at commit (#2008 H6).
// Derived from LoginClassPermissions so the commit-time enum validator and the
// runtime RBAC table stay in lockstep.
func ValidLoginClasses() []string {
	classes := make([]string, 0, len(LoginClassPermissions))
	for name := range LoginClassPermissions {
		classes = append(classes, name)
	}
	sort.Strings(classes)
	return classes
}

// LoginConfig holds user account definitions.
type LoginConfig struct {
	Users []*LoginUser
}

// LoginUser defines a system user account.
type LoginUser struct {
	Name              string
	UID               int
	Class             string   // "super-user", "read-only", etc.
	EncryptedPassword Secret   // crypt(3) hash; applied via `chpasswd -e` (#1944); redacted on marshal (#2053)
	SSHKeys           []string // authorized SSH public keys
}

// ServicesConfig holds service configuration (flow-monitoring, RPM, etc.).
type ServicesConfig struct {
	FlowMonitoring            *FlowMonitoringConfig
	RPM                       *RPMConfig
	IPMonitoring              *IPMonitoringConfig // services ip-monitoring (#1827 PR-1b)
	ApplicationIdentification bool                // DPI-based application detection
}

// IPMonitoringConfig holds `services ip-monitoring` policies (#1827
// PR-1b): probe-driven preferred-route injection, Junos parity.
type IPMonitoringConfig struct {
	Policies map[string]*IPMonitoringPolicy
}

// IPMonitoringPolicy matches one RPM probe and injects its preferred
// routes (at route preference 1, Static/1 on SRX) while ANY test of the
// matched probe is FAILED; on recovery they are withdrawn.
type IPMonitoringPolicy struct {
	Name            string
	MatchRPMProbe   string
	PreferredRoutes []*PreferredRoute
	// HoldDownSecs damps recovery flaps (extension beyond Junos;
	// 0 = Junos parity: withdraw immediately on recovery).
	HoldDownSecs int
}

// PreferredRoute is one injected route of an ip-monitoring policy.
type PreferredRoute struct {
	RoutingInstance string // "" = master; may target instance-type forwarding (FBF, #1827 PR-2)
	Destination     string // CIDR
	// NextHop is the literal next-hop IP; "" when the configured
	// next-hop is interface-typed (#1844). Mutually exclusive with
	// NextHopInterface.
	NextHop string
	// NextHopInterface is the resolved Linux DHCP lease key
	// (DHCPLeaseIfName: LinuxIfName + optional ".<vlan-id>") when the
	// configured next-hop names a DHCP-enabled interface unit
	// (`next-hop ge-0/0/3.0`, #1844). The route then tracks that
	// unit's DHCP-learned gateway at actuation time. Compile-time
	// derived; config identity only, never lease state. Mutually
	// exclusive with NextHop.
	NextHopInterface string
	// PreferredMetric is a metric AMONG injected routes for the same
	// prefix (the tie-break when two policies in FAIL both inject the
	// same destination — lowest wins, then lexicographic policy name).
	// It is NOT the route preference: the injected route always has
	// preference 1.
	PreferredMetric int
}

// RouteOverlayEntry is one winner-resolved effective route of the
// ip-monitoring overlay (#1827 PR-1b §4.3): the single decision point
// consumed by BOTH the FRR managed-section render (distance-1 static)
// and the userspace dataplane snapshot builder (whole-entry replacement
// of the (table, family, prefix) route set). Runtime state, never
// config: it does not participate in config sync.
type RouteOverlayEntry struct {
	RoutingInstance string // "" = master table
	Destination     string // CIDR
	NextHop         string
	// NextHopInterface records the DHCP lease key the NextHop was
	// resolved from when the owning PreferredRoute is interface-typed
	// (#1844); "" for literal next-hops. FRR/snapshot consumers read
	// NextHop only — this field exists so FilterOverlayForConfig can
	// match an interface-typed entry against the incoming config (the
	// resolved gateway is runtime state and never equals the config
	// spec).
	NextHopInterface string
	Metric           int    // winning preferred-metric (informational downstream)
	Policy           string // owning policy name (logging/show)
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

// Probe pin plumbing constants (#1827 PR-1a). Each RPM test with a
// `next-hop` pin gets a deterministic per-test fwmark + kernel routing
// table + ip-rule priority, assigned in sorted probe/test order. The
// reserved probe table range 7000-7049 is clear of the Linux reserved
// tables (0/253/254/255), the daemon's management VRF table (999), and
// the routing-instance auto-assignment that grows upward from 100
// (compileRoutingInstances). The ip-rule priority band 50-99 sits below
// the next-table (100-199), PBR (31000+), and rib-group (33000+) clear
// windows in pkg/routing/rules.go. pkg/routing's probe-pin reconciler
// and pkg/rpm's SO_MARK assignment both consume these constants so the
// rule/table/mark assignment cannot drift between the two sides.
const (
	// ProbeTableBase is the first kernel routing table reserved for
	// RPM probe next-hop pins.
	ProbeTableBase = 7000
	// ProbeTableCount caps the number of next-hop-pinned RPM tests
	// (commit error past the cap).
	ProbeTableCount = 50
	// ProbeFwmarkBase is the first fwmark value used for probe pins
	// (mark = ProbeFwmarkBase + index).
	ProbeFwmarkBase = 0x1000
	// ProbeRulePriorityBase is the first ip-rule priority of the
	// probe-pin band (50-99).
	ProbeRulePriorityBase = 50
)

// RPMTest defines a test within an RPM probe.
type RPMTest struct {
	Name                 string
	ProbeType            string // "http-get", "icmp-ping", "tcp-ping"
	Target               string // target IP or hostname
	SourceAddress        string
	RoutingInstance      string
	DestinationInterface string // egress interface pin (SO_BINDTODEVICE), Junos unit name
	NextHop              string // next-hop IP pin via reserved fwmark probe table (#1827)
	ProbeInterval        int    // seconds (0 = default 5)
	ProbeCount           int    // number of probes per test (0 = default 1)
	TestInterval         int    // seconds (0 = default 60)
	ThresholdSuccessive  int    // successive failures before probe-fail (0 = default 3)
	ProbeLimit           int    // max consecutive failed probes before stopping the current test cycle (0 = unlimited)
	DestPort             int    // for tcp-ping
}

// IsScoped reports whether the test's probe DATA socket is bound to a
// specific VRF / egress device / next-hop path — i.e. probeOpts would set
// SO_BINDTODEVICE (from destination-interface, or the routing-instance VRF
// device) or SO_MARK (from a next-hop pin). A scoped test measures a
// SPECIFIC path, so a hostname target must resolve in that path's context.
// Since #2614 the runtime resolver does exactly that — it binds the DNS
// socket to the same SO_BINDTODEVICE / SO_MARK as the probe socket
// (rpm.resolveProbeTarget / probeDialer.Resolver) — so a scoped hostname
// resolves in-context (the #2493 commit gate that previously refused this
// combination was removed). This predicate is retained as the shared
// definition of "scoped".
func (t *RPMTest) IsScoped() bool {
	if t == nil {
		return false
	}
	return t.DestinationInterface != "" || t.RoutingInstance != "" || t.NextHop != ""
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
	// AllowDataplaneSleep mirrors `forwarding-options allow-dataplane-sleep`
	// (#2008 H13 Stage 1). Syntax accepted + typed; the idle-yield runtime
	// (workers currently busy-poll) is Stage 2 / lab-gated, so this is an
	// accepted-but-unenforced flag that emits a commit warning.
	AllowDataplaneSleep bool
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
	// AlwaysBroadcast forces every server reply (OFFER/ACK) to be
	// broadcast to 255.255.255.255:68 even when the client cleared the
	// broadcast flag, mirroring Junos `dhcp-relay ... overrides
	// always-broadcast`. When false (the default) the relay honors the
	// client's broadcast flag and raw-L2-unicasts flag-clear replies to
	// chaddr+yiaddr (#2076).
	AlwaysBroadcast bool
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
//
// Version selects the export protocol for THIS collector (Junos binds
// each flow-server to exactly one export version). It is set by the
// compiler from whichever per-server selector nests under the
// flow-server: "version9" (the `version9 { template }` /
// `version9-template` selector) or "version-ipfix" (the
// `version-ipfix { template }` selector). It is "" when the operator
// configured no per-server selector — in that case the live exporter
// resolves a deterministic version per the documented precedence (see
// pkg/flowexport BuildExportConfig / BuildIPFIXExportConfig and #2136).
//
// Before #2136 the live Go exporter ignored the per-server selector
// entirely and flattened all flow-servers into BOTH the v9 and the
// IPFIX collector set, so a flow-server reachable under both global
// version stanzas received every flow twice (one v9 + one IPFIX
// datagram to the same socket).
type FlowServer struct {
	Address              string
	Port                 int
	Version              string // "version9" | "version-ipfix" | "" (unbound)
	Version9Template     string
	VersionIPFIXTemplate string
}

// Flow-server per-collector export version selectors (FlowServer.Version).
const (
	FlowServerVersion9     = "version9"
	FlowServerVersionIPFIX = "version-ipfix"
)

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
	// DSCPs / Protocols / ICMPTypes / ICMPCodes are SCHEMA-DECLARED multi-value
	// (schema_cos.go marks them `multi: true`) and Junos accepts the match
	// criterion repeated within one `from` block. They are stored as SLICES
	// (#2545) so repeated children accumulate into a match-ANY set instead of
	// the prior scalar last-write-wins (`from protocol tcp; from protocol udp`
	// silently dropped tcp). An EMPTY slice means the criterion is unconstrained
	// (matches any), exactly like the prior empty-string / -1 sentinels. The
	// dataplane (filters.go) emits every value into the corresponding wire
	// vector and the Rust matcher evaluates set membership (match-ANY within a
	// field, AND across fields).
	DSCPs            []string // DSCP/traffic-class names (ef, af43, ...) or numbers
	Protocols        []string // tcp, udp, icmp, icmpv6, esp, ...
	DestinationPorts []string // port numbers or names
	SourcePorts      []string // source port numbers or ranges
	ICMPTypes        []int    // ICMP/ICMPv6 type bytes (0..255); empty = not set
	ICMPCodes        []int    // ICMP/ICMPv6 code bytes (0..255); empty = not set
	TCPFlags         []string // TCP flags: "syn", "ack", "fin", "rst", "psh", "urg"
	IsFragment       bool     // match IP fragments
	Action           string   // "accept", "reject", "discard", ""
	// UnknownActions records `then` tokens that are neither a recognized
	// terminating action nor a recognized modifier (#2399 finding 032-16).
	// An unknown or misspelled action would otherwise be silently dropped
	// during compile and default to ACCEPT in BOTH the dataplane compiler and
	// the Rust filter (a fail-open permit). validateFilterActionsStrict
	// hard-rejects any term carrying an entry here at commit; the tolerant
	// load path downgrades it to a warning (#1960 no-brick). Populated by
	// compileFilterThen.
	UnknownActions []string
	// RejectMessageType is the optional message-type after `then reject`
	// (e.g. tcp-reset, administratively-prohibited, port-unreachable). Junos
	// accepts `then reject <message-type>` and the term acts as a plain reject;
	// this captures the type for config fidelity. The dataplane does not act on
	// it today (FilterAction::Reject only). An unknown token after `reject` is
	// a typo and is NOT stored here — it is flagged via UnknownActions.
	RejectMessageType string
	// NextTerm records `then next term` / `then next-term` — an explicit
	// fall-through to the next term (a no-op terminating-wise; Action stays "").
	// It is a recognized, valid construct, not an unknown action.
	NextTerm        bool
	RoutingInstance string // routing-instance name (policy-based routing)
	Log             bool
	Count           string           // counter name
	ForwardingClass string           // forwarding-class name
	LossPriority    string           // loss-priority (low, medium-low, medium-high, high)
	DSCPRewrite     string           // then dscp <value> — rewrite DSCP/traffic-class
	Policer         string           // then policer <name> — reference to policer definition
	FlexMatch       *FlexMatchConfig // flexible-match-range configuration
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
	// DynamicDNS is the opt-in DHCP DDNS policy (#1387 increment 1). It is the
	// IPv4-family (dhcp-local-server) policy. nil == disabled == today's
	// behaviour byte-for-byte; the dataplane (Kea render, daemon wiring)
	// ignores a nil block entirely.
	//
	// #2691 P1b / #2663: this is now the v4 policy ONLY. The v6 policy lives in
	// DynamicDNSv6 and is INDEPENDENT (separate domain / server / TSIG / TTL /
	// conflict-policy / source-binding). The two families are no longer
	// field-merged into one struct — a v4-family block and a v6-family block
	// keep their own settings. Backward compatibility: a config that sets the
	// stanza under only ONE family compiles to that family's field with the
	// other nil (so the single-family case is byte-for-byte unchanged), and a
	// config that set BOTH under the pre-P1b field-merge model now keeps them
	// distinct (the documented behaviour change in §5.8).
	DynamicDNS *DHCPDynamicDNSConfig
	// DynamicDNSv6 is the opt-in IPv6-family (dhcpv6-local-server) DDNS policy
	// (#2691 P1b / #2663), independent of the v4 DynamicDNS policy above. nil
	// == no v6 DDNS policy. When a config sets the stanza under only
	// dhcpv6-local-server, DynamicDNS is nil and this carries the v6 policy.
	DynamicDNSv6 *DHCPDynamicDNSConfig
}

// DHCPDynamicDNSConfig is the opt-in dynamic-DNS policy for the DHCP
// server (#1387). When DHCP clients take a lease, the firewall can
// publish forward (A/AAAA) and reverse (PTR) records into an external
// authoritative DNS server, and remove them again when the lease ends
// (expire / release / decline / reclaim / reassign).
//
// This is the FIRST increment per docs/research/1387-dhcp-ddns/plan.md
// (recommended Path C — pluggable backend, RFC 2136 first). Increment 1
// ships the config model, the state-aware lease parser, the DNSUpdater
// interface + reconciler core (fake-updater unit-tested), and the
// never-delete-non-owned state store. The LIVE rfc2136 backend, the HA
// ownership coupling, and the Kea D2 backend are deferred to later
// lab-gated / test-failover-gated increments. An absent block (nil) is
// the default and changes nothing.
type DHCPDynamicDNSConfig struct {
	// Enabled turns the reconciler on. A block that parses but never
	// sets enable is still disabled — the operator opts in explicitly.
	Enabled bool
	// Domain is the default DNS suffix appended to a client name that is
	// not already a FQDN (e.g. "corp.example.com").
	Domain string
	// TTLSeconds is the TTL applied to published records (default 300
	// when zero, applied at render time, not here).
	TTLSeconds int
	// HostnameSource selects how the published label is derived from the
	// lease: client-hostname (DHCP host-name option, default), fqdn (the
	// client-supplied FQDN option), or mac-fallback (synthesize
	// dhcp-<sanitized-id> when no name is offered).
	HostnameSource string
	// ConflictPolicy governs an existing record collision: replace-owned
	// (default — only replace records this firewall owns per the state
	// store), skip-existing, or strict-fail.
	ConflictPolicy string
	// Backend selects the DNS-update mechanism. "rfc2136" is the default and
	// is LIVE (#1387 inc-2): records are published to and withdrawn from the
	// authoritative server over real RFC 2136 UPDATE by the always-on
	// reconcile loop. "kea-d2" is a reserved enum value that is NOT
	// implemented (Kea D2 is not in the image — bake.py); selecting it warns
	// at commit and publishes nothing.
	Backend string
	// UpdateServer is the RFC 2136 target authoritative DNS, host or
	// host:port (rfc2136 backend). It IS consumed by the live path: an
	// enabled rfc2136 backend with no update-server publishes nothing and
	// warns at commit (validateDDNSBackendWarnings).
	UpdateServer string
	// TSIGKeyName / TSIGAlgorithm / TSIGSecret are the TSIG credentials
	// for authenticated RFC 2136 updates. TSIGSecret is the sensitive HMAC
	// key. It is redacted by String() (so a %v/%s/slog of this struct never
	// leaks the key — see String below) AND, since #2053, by its Secret
	// type on every JSON/YAML marshal (so the compiled-config dump on
	// GET /api/v1/config never leaks it either). The reconciler/render paths
	// read the cleartext via Reveal().
	TSIGKeyName   string
	TSIGAlgorithm string
	TSIGSecret    Secret
	// SourceAddress / DestinationInterface / RoutingInstance scope the RFC
	// 2136 UPDATE TRANSPORT (#2691 P1b / #2665). In a multi-WAN / VRF
	// deployment a DNS UPDATE must egress from the right source IP, the right
	// interface, and/or the right routing-instance (VRF) or it is dropped by
	// source-IP-keyed ACLs or sent to the wrong upstream. The live rfc2136
	// backend builds its transport with a custom net.Dialer:
	//   - SourceAddress       → Dialer.LocalAddr (bind the UDP/TCP socket's
	//     source IP). Must be a bare IP literal (v4 or v6); the port is chosen
	//     by the kernel.
	//   - DestinationInterface → Dialer.Control → SO_BINDTODEVICE (pin egress
	//     to a specific interface; covers the no-source-route / policy-route
	//     case).
	//   - RoutingInstance     → Dialer.Control → SO_BINDTODEVICE on the VRF
	//     master device (Linux binds a socket into a VRF by binding to the vrf
	//     device). xpf names a routing-instance and the VRF device shares that
	//     name (pkg/routing), so the bind target is the routing-instance name.
	// All three are optional; empty means "default table / kernel source
	// selection" (today's behaviour). They are per-family (v4 vs v6 may bind
	// different sources), which is why they live on this per-family struct.
	SourceAddress        string
	DestinationInterface string
	RoutingInstance      string
}

// String redacts TSIGSecret so a %v/%s/slog format of a
// DHCPDynamicDNSConfig never leaks the shared HMAC key (logging hygiene,
// mirrors WireguardPeer in types_routing.go). The reconciler and render
// paths read the field directly; only formatted/logged copies are
// redacted.
func (d *DHCPDynamicDNSConfig) String() string {
	if d == nil {
		return "<nil>"
	}
	secret := ""
	if d.TSIGSecret != "" {
		secret = "<redacted>"
	}
	return fmt.Sprintf("DHCPDynamicDNS{enabled=%t domain=%q ttl=%d "+
		"hostname-source=%q conflict-policy=%q backend=%q update-server=%q "+
		"tsig-key=%q tsig-alg=%q tsig-secret=%q}",
		d.Enabled, d.Domain, d.TTLSeconds, d.HostnameSource,
		d.ConflictPolicy, d.Backend, d.UpdateServer,
		d.TSIGKeyName, d.TSIGAlgorithm, secret)
}

// DHCPLocalServerConfig holds per-group DHCP server settings.
type DHCPLocalServerConfig struct {
	Groups map[string]*DHCPServerGroup
	// ExpiredLeases is the opt-in Kea expired-lease reclamation policy
	// (#1387 stale-lease-cleanup slice / Path S). nil == today's
	// behaviour byte-for-byte: no `expired-leases-processing` block is
	// rendered and Kea uses its built-in reclamation defaults. The block
	// is GLOBAL to the family — Kea has no per-subnet reclamation — so it
	// sits here on DHCPLocalServerConfig (one per family: dhcp-local-server
	// for v4, dhcpv6-local-server for v6), not on DHCPPool. v4 and v6 are
	// tuned independently because Kea renders the block per Dhcp4 / Dhcp6.
	ExpiredLeases *DHCPExpiredLeasesConfig
}

// DHCPExpiredLeasesConfig maps to Kea's per-family
// `expired-leases-processing` block (#1387 stale-lease-cleanup slice).
// It controls how aggressively Kea REMOVES leases that have ALREADY
// expired/been released/declined from the memfile — it is ORTHOGONAL to
// lease-time (DHCPPool.LeaseTime / the hardcoded valid-lifetime), which
// sets how long a lease stays VALID (invariant H4). Field
// units/semantics are Kea-native (the operator types Kea numbers); see
// https://kea.readthedocs.io for the authoritative meaning.
//
// Rendering is opt-in: a nil block OR Enabled==false renders NOTHING, so
// the generated Kea config is byte-identical to today (invariant H1).
// Each numeric field is emitted only when set, so an operator can flip
// `enable` on and tune one knob without pinning the rest to a value we
// invented.
type DHCPExpiredLeasesConfig struct {
	// Enabled gates rendering of the whole block. A block that parses but
	// never sets `enable` still renders nothing (explicit opt-in, mirrors
	// DHCPDynamicDNSConfig.Enabled).
	Enabled bool
	// ReclaimTimerWait is seconds between reclamation cycles
	// (reclaim-timer-wait-time). 0 == unset -> the key is omitted and Kea
	// uses its default.
	ReclaimTimerWait int
	// FlushReclaimedTimerWait is seconds between flush passes that remove
	// reclaimed leases past hold-time (flush-reclaimed-timer-wait-time).
	// 0 == unset -> omitted.
	FlushReclaimedTimerWait int
	// HoldReclaimedTime is seconds a reclaimed lease is retained before
	// physical removal (hold-reclaimed-time). 0 == unset -> omitted. (Kea
	// keeps a reclaimed lease this long so a renewing client reclaims its
	// own address.)
	HoldReclaimedTime int
	// MaxReclaimLeases caps leases reclaimed per cycle (max-reclaim-leases).
	// In Kea, 0 means UNLIMITED — a DIFFERENT desired state from "omit the
	// key and inherit Kea's default" — so the model MUST distinguish a
	// value of 0 from unset (invariant H2). MaxReclaimLeasesSet is true
	// exactly when the operator configured `max-leases`; a bare `if x > 0`
	// render would make `max-leases 0` (unlimited) un-expressible.
	MaxReclaimLeases    int
	MaxReclaimLeasesSet bool
	// MaxReclaimTime caps milliseconds spent reclaiming per cycle
	// (max-reclaim-time). 0 means UNLIMITED in Kea, so it uses the same
	// set/unset discipline as MaxReclaimLeases (invariant H2).
	MaxReclaimTime    int
	MaxReclaimTimeSet bool
	// UnwarnedReclaimCycles is consecutive cycles hitting the cap before
	// Kea warns (unwarned-reclaim-cycles). 0 == unset -> omitted.
	UnwarnedReclaimCycles int
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
	// StaticBindings are fixed (reserved) address assignments scoped to
	// this pool's subnet (#2243). Each binds a client identity
	// (hardware-address / MAC) to a fixed-address that the matching client
	// always receives. They render to Kea per-subnet `reservations`
	// (hw-address -> ip-address [+ hostname]). Reservations derive entirely
	// from the committed config, so an HA pair serving identical subnets is
	// reservation-consistent by construction via the existing cluster
	// config-sync — no per-lease replication is needed for the static case
	// (the dynamic-lease HA gap is the separate companion #2239).
	StaticBindings []*DHCPStaticBinding
}

// DHCPStaticBinding is a single fixed/reserved DHCP-server host binding
// (#2243). Junos `dhcp-local-server group <g> pool <p> static-binding <mac>
// { fixed-address <ip>; host-name <name>; }`. It maps a client hardware
// address to a fixed address within the enclosing pool's subnet; the
// optional host-name becomes the Kea reservation hostname.
type DHCPStaticBinding struct {
	// MACAddress is the client hardware address (the binding identity key),
	// e.g. "00:11:22:33:44:55". Rendered as Kea `hw-address`.
	MACAddress string
	// FixedAddress is the reserved IP the matching client always receives.
	// Must fall inside the enclosing pool's Subnet. Rendered as Kea
	// `ip-address`.
	FixedAddress string
	// HostName is the optional reservation hostname (Kea `hostname`). Empty
	// when not configured.
	HostName string
}
