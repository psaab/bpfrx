package config

import (
	"fmt"
	"net"
	"strings"
)

// Routing: routing-options, policy-options, dynamic protocols
// (OSPF/OSPFv3/BGP/RIP/IS-IS/LLDP), router advertisement, tunnels, and
// VRF routing instances.

// PolicyOptionsConfig holds prefix-lists, communities, as-paths, and policy-statements for routing control.
type PolicyOptionsConfig struct {
	PrefixLists      map[string]*PrefixList
	Communities      map[string]*CommunityDef
	ASPaths          map[string]*ASPathDef
	PolicyStatements map[string]*PolicyStatement
}

// ASPathDef defines a named AS-path regular expression for route matching.
type ASPathDef struct {
	Name  string
	Regex string // AS-path regex pattern (e.g. "65000", "65[0-9]+")
}

// CommunityDef defines a named BGP community with member values.
type CommunityDef struct {
	Name    string
	Members []string // e.g. "65000:100", "no-export", "no-advertise"
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
	Name          string
	FromProtocols []string // "direct", "static", "bgp", "ospf" — Junos
	// "from protocol [ bgp ospf static ]" matches ANY listed protocol.
	// PrefixList / FromCommunity / FromASPath hold the term's `from
	// prefix-list`, `from community`, and `from as-path` match statements.
	// Junos permits MULTIPLE sibling match statements of the same type in
	// one term (e.g. `from { community c1; community c2; }`), which match
	// with OR ("any") semantics. They are slices so every repeated match is
	// kept; a single-string field silently dropped all but the last (#2642).
	PrefixList      []string       // from prefix-list <name> (OR across entries)
	FromCommunity   []string       // from community <name> (match community-list; OR)
	FromASPath      []string       // from as-path <name> (match as-path access-list; OR)
	RouteFilters    []*RouteFilter // prefix matching
	Action          string         // "accept", "reject"
	NextHop         string         // then next-hop (e.g. "peer-address", "self", IP)
	LoadBalance     string         // then load-balance (e.g. "consistent-hash", "per-packet")
	LocalPreference int            // BGP local-preference value (valid when HasLocalPreference)
	// HasLocalPreference distinguishes an explicitly configured
	// local-preference (including the valid value 0, which maximally
	// deprioritizes a route within the AS) from "local-preference not
	// configured". A bare int could not tell local-preference-0 apart
	// from unset, so a `set local-preference 0` term silently rendered
	// no `set local-preference` clause (#2857). The renderer must gate
	// the FRR clause on HasLocalPreference, never on LocalPreference > 0.
	HasLocalPreference bool
	Metric             int // BGP MED/metric value (valid when HasMetric)
	// HasMetric distinguishes an explicitly configured metric (including the
	// valid traffic-engineering value 0, e.g. MED 0 = advertise a highly
	// preferred route) from "metric not configured". A bare int could not
	// tell metric-0 apart from unset, so a `set metric 0` term silently
	// rendered no `set metric` clause (#2847). The renderer must gate the
	// FRR clause on HasMetric, never on Metric > 0.
	HasMetric  bool
	MetricType int    // OSPF metric type (1 or 2, 0 = not set)
	Community  string // BGP community to REPLACE with (`then community set <v>` or the bare `then community <v>`; e.g. "65000:100")
	// CommunityOp distinguishes the Junos `then community (add|delete|set)`
	// operations from the legacy bare `then community <value>` (= replace).
	// Junos/vSRX supports append (additive), delete (by community-list), and
	// none (strip all) in addition to whole-attribute replace; emitting only
	// the replace clause (`set community <v>`) wiped any upstream-set
	// communities, a vSRX-parity gap (#2848). The compiler sets CommunityOp
	// to one of "", "set", "add", "delete", "none". Both "" and "set" mean
	// replace using term.Community (the empty string preserves back-compat
	// with the bare `then community <v>` form). For "add" the value lives in
	// CommunityAdd (rendered `set community <v> additive`), for "delete" the
	// referenced community-list name lives in CommunityDelete (rendered
	// `set comm-list <name> delete`), and "none" carries no argument
	// (rendered `set community none`).
	CommunityOp     string // "", "set", "add", "delete", "none"
	CommunityAdd    string // community value(s) to append (`then community add <v>`)
	CommunityDelete string // community-list name whose members to strip (`then community delete <name>`)
	Origin          string // BGP origin: "igp", "egp", "incomplete"
}

// RouteFilter matches a prefix with a match type.
type RouteFilter struct {
	Prefix    string // CIDR ("192.168.50.0/24")
	MatchType string // "exact", "longer", "orlonger", "upto", "prefix-length-range", "through"
	UptoLen   int    // for "upto" match type
	// RangeLow / RangeHigh hold the two prefix-length bounds for the
	// "prefix-length-range /low-/high" match type (#2525). Both are 0
	// (unset) for every other match type; parseRouteFilterRange leaves them
	// 0 when the "/low-/high" token is malformed so the renderer/validator
	// can treat 0 unambiguously as "no parseable range".
	RangeLow  int
	RangeHigh int
	// ThroughPrefix holds the second (more-specific) CIDR of a Junos
	// "through <prefix2>" match (#2525). FRR has no lossless equivalent for
	// the two-prefix containment-path semantics of "through", so the strict
	// commit gate rejects it; on the tolerant load/peer-sync path the
	// renderer skips the entry (match-nothing, fail-closed). Empty for every
	// other match type.
	ThroughPrefix string
}

// RoutingOptionsConfig holds static routing configuration.
type RoutingOptionsConfig struct {
	StaticRoutes              []*StaticRoute
	Inet6StaticRoutes         []*StaticRoute // rib inet6.0 static routes
	GenerateRoutes            []*GenerateRoute
	ForwardingTableExport     string // forwarding-table { export <policy>; }
	AutonomousSystem          uint32 // autonomous-system <number>
	RibGroups                 map[string]*RibGroup
	InterfaceRoutesRibGroup   string // global interface-routes { rib-group inet <name>; }
	InterfaceRoutesRibGroupV6 string // global interface-routes { rib-group inet6 <name>; }
}

// GenerateRoute defines a Junos generate (aggregate) route.
// In FRR, these become blackhole/reject static routes or BGP aggregate-address.
type GenerateRoute struct {
	Prefix  string // route prefix (e.g. "192.168.0.0/16")
	Policy  string // contributing route policy (optional)
	Discard bool   // discard traffic to this route (blackhole)
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
	OSPFv3              *OSPFv3Config
	BGP                 *BGPConfig
	RIP                 *RIPConfig
	ISIS                *ISISConfig
	RouterAdvertisement []*RAInterfaceConfig
	LLDP                *LLDPConfig
}

// LLDPConfig holds LLDP (Link Layer Discovery Protocol) configuration.
type LLDPConfig struct {
	Interfaces     []LLDPInterface // interfaces to enable LLDP on
	Interval       int             // transmit interval in seconds (0 = default 30)
	HoldMultiplier int             // hold multiplier (0 = default 4)
	Disable        bool            // globally disable LLDP
}

// LLDPInterface holds per-interface LLDP configuration.
type LLDPInterface struct {
	Name    string
	Disable bool // per-interface disable
}

// OSPFv3Config holds OSPFv3 (IPv6 OSPF) routing configuration.
type OSPFv3Config struct {
	RouterID string
	Areas    []*OSPFv3Area
	Export   []string
}

// OSPFv3Area defines an OSPFv3 area.
type OSPFv3Area struct {
	ID         string // "0.0.0.0" (backbone) or area number
	Interfaces []*OSPFv3Interface
}

// OSPFv3Interface defines an interface participating in OSPFv3.
type OSPFv3Interface struct {
	Name          string
	Passive       bool
	Cost          int
	BFD           bool // enable BFD on this interface
	BFDInterval   int  // BFD minimum-interval in ms (0 = default)
	BFDMultiplier int  // BFD detect-multiplier (0 = default)
}

// RIPConfig holds RIP routing configuration.
type RIPConfig struct {
	Interfaces   []string // interfaces participating in RIP
	Passive      []string // passive interfaces (receive only)
	Redistribute []string // "connected", "static", "ospf"
	AuthKey      Secret   // authentication key/password; redacted on marshal (#2053)
	AuthType     string   // "md5" or "simple"
}

// ISISConfig holds IS-IS routing configuration.
type ISISConfig struct {
	NET             string // ISO NET address (e.g. "49.0001.0100.0000.0001.00")
	Level           string // "level-1", "level-2", "level-1-2" (default "level-2")
	Interfaces      []*ISISInterface
	Export          []string // "connected", "static", etc.
	AuthKey         Secret   // area-level authentication key; redacted on marshal (#2053)
	AuthType        string   // "md5" or "simple" (plaintext)
	WideMetricsOnly bool     // use wide (32-bit) metrics
	Overload        bool     // set overload bit
}

// ISISInterface defines an interface participating in IS-IS.
type ISISInterface struct {
	Name          string
	Level         string // override per-interface
	Passive       bool
	Metric        int    // 0 = default
	AuthKey       Secret // per-interface authentication key; redacted on marshal (#2053)
	AuthType      string // "md5" or "simple"
	BFD           bool   // enable BFD on this interface
	BFDInterval   int    // BFD minimum-interval in ms (0 = default)
	BFDMultiplier int    // BFD detect-multiplier (0 = default)
}

// RAInterfaceConfig configures Router Advertisement on an interface.
type RAInterfaceConfig struct {
	Interface       string
	ManagedConfig   bool   // managed-configuration (M flag)
	OtherStateful   bool   // other-stateful-configuration (O flag)
	Preference      string // "high", "medium", "low" (default: medium)
	DefaultLifetime int    // seconds, 0 = default (1800)
	MaxAdvInterval  int    // seconds, 0 = default (600)
	MinAdvInterval  int    // seconds, 0 = default (200)
	Prefixes        []*RAPrefix
	DNSServers      []string // recursive DNS server addresses
	NAT64Prefix     string   // PREF64 prefix (e.g. "64:ff9b::/96")
	NAT64PrefixLife int      // PREF64 lifetime in seconds (0 = default)
	LinkMTU         int      // advertised link MTU, 0 = omit
	SourceLinkLocal string   // explicit link-local to use as RA source (overrides auto-selected)
}

// RAPrefix defines a prefix advertised via RA.
type RAPrefix struct {
	Prefix        string // CIDR notation
	OnLink        bool   // on-link flag (default true)
	Autonomous    bool   // SLAAC autonomous flag (default true)
	ValidLifetime int    // seconds, 0 = default (2592000 = 30 days)
	PreferredLife int    // seconds, 0 = default (604800 = 7 days)
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
	ID           string // "0.0.0.0" (backbone) or area number
	AreaType     string // "stub", "nssa", "" (normal)
	NoSummary    bool   // stub/nssa no-summary (totally stubby)
	Interfaces   []*OSPFInterface
	VirtualLinks []*OSPFVirtualLink
}

// OSPFVirtualLink defines a virtual link to the backbone through a transit area.
type OSPFVirtualLink struct {
	NeighborID  string // router-id of ABR at the other end
	TransitArea string // the area this virtual-link traverses (the area ID where it's configured)
}

// OSPFInterface defines an interface participating in OSPF.
type OSPFInterface struct {
	Name          string
	Passive       bool   // passive interface (no hello)
	NoPassive     bool   // override passive-default (explicitly active)
	Cost          int    // OSPF cost, 0 = default
	NetworkType   string // "point-to-point", "broadcast", "" (default)
	AuthType      string // "md5", "simple", "" (none)
	AuthKey       Secret // authentication key/password; redacted on marshal (#2053)
	AuthKeyID     int    // key-id for MD5 (1-255)
	BFD           bool   // enable BFD on this interface
	BFDInterval   int    // BFD minimum-interval in ms (0 = default)
	BFDMultiplier int    // BFD detect-multiplier (0 = default)
}

// BGPConfig holds BGP routing configuration.
type BGPConfig struct {
	LocalAS              uint32
	RouterID             string
	ClusterID            string // route reflector cluster ID
	GracefulRestart      bool   // enable graceful restart
	Multipath            int    // maximum equal-cost paths (0 = disabled)
	MultipathMultipleAS  bool   // allow multipath across different ASes
	LogNeighborChanges   bool   // log neighbor state transitions
	Dampening            bool   // enable route flap dampening
	DampeningHalfLife    int    // half-life in minutes (default 15)
	DampeningReuse       int    // reuse threshold (default 750)
	DampeningSuppress    int    // suppress threshold (default 2000)
	DampeningMaxSuppress int    // max suppress time in minutes (default 60)
	Neighbors            []*BGPNeighbor
	Export               []string // "connected", "static", "ospf", etc.
	Import               []string // inbound filter policy-statements (route-map in); #2490
}

// BGPNeighbor defines a BGP peer.
type BGPNeighbor struct {
	Address              string // peer IP
	PeerAS               uint32
	Description          string
	MultihopTTL          int      // 0 = directly connected
	Export               []string // export policies (route-map out): group default + per-neighbor override; last wins (most-specific)
	Import               []string // import policies (route-map in): group default + per-neighbor override; last wins (most-specific); #2490
	FamilyInet           bool     // activate under address-family ipv4 unicast
	FamilyInet6          bool     // activate under address-family ipv6 unicast
	GroupName            string   // BGP group name (for display)
	AuthPassword         Secret   // TCP MD5 password for BGP session; redacted on marshal (#2053)
	BFD                  bool     // enable BFD for this neighbor
	BFDInterval          int      // BFD minimum interval in ms (0 = default 300)
	BFDMultiplier        int      // BFD detect-multiplier (0 = default 3)
	RouteReflectorClient bool     // mark as route-reflector client
	DefaultOriginate     bool     // advertise default route to this neighbor
	AllowASIn            int      // allow own AS in path N times (0 = disabled)
	RemovePrivateAS      bool     // strip private AS numbers from updates
	PrefixLimitInet      int      // max IPv4 prefixes (0 = unlimited)
	PrefixLimitInet6     int      // max IPv6 prefixes (0 = unlimited)
}

// TunnelConfig defines a GRE, IPIP, or other tunnel interface.
type TunnelConfig struct {
	Name            string   // Linux interface name (e.g. "gr-0-0-0", "ip-0-0-0")
	Mode            string   // "gre" or "ipip"
	Source          string   // local tunnel endpoint IP
	Destination     string   // remote tunnel endpoint IP
	Key             uint32   // GRE key, 0 = none
	TTL             int      // tunnel TTL, 0 = default 64
	Addresses       []string // IPs to assign to tunnel interface (CIDR)
	RoutingInstance string   // destination routing-instance (VRF)
	Keepalive       int      // keepalive interval in seconds (0 = disabled)
	KeepaliveRetry  int      // number of missed keepalives before declaring down (0 = default 3)
	AnchorOnly      bool     // create a dummy anchor instead of a kernel tunnel device

	// MTU is the config-desired link MTU for the tunnel device (#1884):
	// the owning interface's `mtu` statement (unit-level overrides
	// interface-level for unit tunnels, mirroring compiler_iface
	// precedence). 0 means unconfigured — the tunnel manager then never
	// writes MTU except the one-time TUN-default normalization when
	// ADOPTING an anchor it did not create (wireguard→gre same-name flip
	// repair). Populated by collectAppliedTunnels; the legacy
	// standalone-CLI apply path leaves it 0.
	MTU int

	// RIListMember is the routing-instance whose `interface` LIST names
	// this tunnel (after the daemon step-0a name normalization), or ""
	// (#1884). It is NOT a bind instruction — daemon_apply step 0a owns
	// list binds. The tunnel manager uses it as (a) an unbind VETO so a
	// stanza→list move never strips the 0a bind, and (b) the
	// observation-fallback claim target for later unbind-on-removal.
	// Populated by collectAppliedTunnels; the legacy CLI path leaves "".
	RIListMember string

	// WireGuard (#1432 S2a, multi-peer #1434). Populated only when
	// Mode == "wireguard". Minimal generic surface (the #1703 "generic
	// stanza") — not the full Junos wireguard grammar (S6).
	//
	// WgListenPort / WgLocalPrivkeyHex are TUNNEL-level (one kernel UDP
	// socket, one local identity per WG interface). WgPeers is the
	// ordered per-peer set (#1434): a WG interface may terminate N
	// peers, each with its own pubkey, AllowedIPs (cryptokey routing),
	// endpoint, keepalive, and optional preshared key. The compiler
	// sorts WgPeers by pubkey at the snapshot-builder boundary so both
	// HA nodes serialize byte-identical snapshots (compile determinism,
	// docs/research/1434-multitunnel-wg/plan.md §5.4).
	WgListenPort      uint16         // local UDP listen port for inbound WG
	WgLocalPrivkeyHex Secret         // local static X25519 private key (hex, 64 chars); redacted on marshal (#2053)
	WgPeers           []WgPeerConfig // ordered per-peer set (#1434)
}

// WgPeerConfig is one WireGuard peer on a WG tunnel (#1434). A tunnel
// holds an ordered slice of these (TunnelConfig.WgPeers). The pubkey is
// the peer identity (the named-instance key in the schema); the compiler
// hard-rejects duplicate pubkeys at commit so the slice never carries
// two peers with one identity (the engine's reconcile_peers contract,
// userspace-dp wg/engine.rs).
type WgPeerConfig struct {
	PublicKeyHex    string   // peer static X25519 public key (hex, 64 chars)
	AllowedIPs      []string // this peer's AllowedIPs (CIDR) — cryptokey routing / decap inner-src gate
	Endpoint        string   // optional peer endpoint IP:port (initiator role)
	KeepaliveSecs   uint16   // optional persistent-keepalive seconds (0 = off)
	PresharedKeyHex Secret   // optional per-peer PSK (hex, 64 chars); "" = zero PSK (#1434 B2); redacted on marshal
}

// String redacts WgLocalPrivkeyHex AND every per-peer PresharedKeyHex so
// a `%v`/`%s`/slog format of a TunnelConfig never leaks WireGuard secret
// key material (#1432 S2a privkey hygiene + #1434 B2 PSK hygiene). The
// Rust side already zeroizes + redacts its copy; this closes the Go-side
// cleartext-log exposure.
func (tc *TunnelConfig) String() string {
	if tc == nil {
		return "<nil>"
	}
	priv := "<unset>"
	if tc.WgLocalPrivkeyHex != "" {
		priv = "<redacted>"
	}
	peers := make([]string, 0, len(tc.WgPeers))
	for _, p := range tc.WgPeers {
		psk := "<unset>"
		if p.PresharedKeyHex != "" {
			psk = "<redacted>"
		}
		peers = append(peers, fmt.Sprintf(
			"{PublicKeyHex:%s AllowedIPs:%v Endpoint:%s KeepaliveSecs:%d PresharedKeyHex:%s}",
			p.PublicKeyHex, p.AllowedIPs, p.Endpoint, p.KeepaliveSecs, psk))
	}
	return fmt.Sprintf("TunnelConfig{Name:%s Mode:%s Source:%s Destination:%s "+
		"WgListenPort:%d WgLocalPrivkeyHex:%s WgPeers:[%s]}",
		tc.Name, tc.Mode, tc.Source, tc.Destination,
		tc.WgListenPort, priv, strings.Join(peers, " "))
}

// WgOuterFamilyV6 reports whether the tunnel's outer transport family is
// IPv6 (#1434). A WG interface binds ONE kernel UDP socket, so it has a
// single outer family. The family is derived from the peer(s) that
// declare an endpoint; the commit-time validator
// (validateWireguardPeers) rejects a config where endpoint-bearing peers
// disagree on family, so reading the FIRST endpoint-bearing peer here is
// safe. Returns false (IPv4 default) when no peer declares an endpoint
// (responder-only / roaming — the Rust control thread may still LEARN a
// v6 endpoint, which the larger v6 MTU overhead and dual-stack socket
// accommodate; the conservative v4 default here is the outer-family
// SNIFF, distinct from the MTU overhead, which defaults to the larger v6
// value — see wgTunMTUForEndpoint).
func (tc *TunnelConfig) WgOuterFamilyV6() bool {
	for _, p := range tc.WgPeers {
		if p.Endpoint == "" {
			continue
		}
		// Accept `IP:port` AND a bare IP literal — the config tokenizer
		// stores a v6 `[addr]:port` endpoint as a bare `addr` (see
		// endpointIsV6 / compiler_validate_wireguard.go).
		if host, _, err := net.SplitHostPort(p.Endpoint); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				return ip.To4() == nil
			}
		}
		if ip := net.ParseIP(p.Endpoint); ip != nil {
			return ip.To4() == nil
		}
	}
	return false
}

// WgHasEndpoint reports whether any peer on the tunnel declares an
// endpoint (#1434). A tunnel with no endpoint-bearing peer is
// responder-only/roaming; callers (e.g. the MTU overhead pick) treat
// that as the conservative v6 case.
func (tc *TunnelConfig) WgHasEndpoint() bool {
	for _, p := range tc.WgPeers {
		if p.Endpoint != "" {
			return true
		}
	}
	return false
}

// RoutingInstanceConfig represents a VRF-based routing instance.
type RoutingInstanceConfig struct {
	Name                      string
	Description               string
	InstanceType              string         // "virtual-router" or "vrf"
	Interfaces                []string       // interfaces belonging to this instance
	StaticRoutes              []*StaticRoute // per-instance static routes
	Inet6StaticRoutes         []*StaticRoute // per-instance rib inet6.0 static routes
	OSPF                      *OSPFConfig    // per-instance OSPF (optional)
	OSPFv3                    *OSPFv3Config  // per-instance OSPFv3 (optional)
	BGP                       *BGPConfig     // per-instance BGP (optional)
	RIP                       *RIPConfig     // per-instance RIP (optional)
	ISIS                      *ISISConfig    // per-instance IS-IS (optional)
	TableID                   int            // Linux kernel routing table number (auto-assigned)
	InterfaceRoutesRibGroup   string         // interface-routes { rib-group inet <name>; }
	InterfaceRoutesRibGroupV6 string         // interface-routes { rib-group inet6 <name>; }
}
