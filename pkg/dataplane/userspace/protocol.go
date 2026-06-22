package userspace

import (
	"encoding/json"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

const (
	ProtocolVersion                  = 3
	InjectPacketTupleProtocolVersion = 1
	TypeUserspace                    = "userspace"
)

type ControlRequest struct {
	Type               string                    `json:"type"`
	SuppressStatus     bool                      `json:"suppress_status,omitempty"`
	Snapshot           *ConfigSnapshot           `json:"snapshot,omitempty"`
	Forwarding         *ForwardingControlRequest `json:"forwarding,omitempty"`
	HAState            *HAStateUpdateRequest     `json:"ha_state,omitempty"`
	Queue              *QueueControlRequest      `json:"queue,omitempty"`
	Binding            *BindingControlRequest    `json:"binding,omitempty"`
	Packet             *InjectPacketRequest      `json:"packet,omitempty"`
	SessionSync        *SessionSyncRequest       `json:"session_sync,omitempty"`
	SessionDeltas      *SessionDeltaDrainRequest `json:"session_deltas,omitempty"`
	SessionExport      *SessionExportRequest     `json:"session_export,omitempty"`
	Neighbors          []NeighborSnapshot        `json:"neighbors,omitempty"`
	NeighborGeneration uint64                    `json:"neighbor_generation,omitempty"`
	NeighborReplace    bool                      `json:"neighbor_replace,omitempty"`
	Fabrics            []FabricSnapshot          `json:"fabrics,omitempty"`
}

type ControlResponse struct {
	OK            bool               `json:"ok"`
	Error         string             `json:"error,omitempty"`
	Status        *ProcessStatus     `json:"status,omitempty"`
	SessionDeltas []SessionDeltaInfo `json:"session_deltas,omitempty"`
}

type ConfigSnapshot struct {
	Version            int                          `json:"version"`
	Generation         uint64                       `json:"generation"`
	FIBGeneration      uint32                       `json:"fib_generation,omitempty"`
	GeneratedAt        time.Time                    `json:"generated_at"`
	Summary            SnapshotSummary              `json:"summary"`
	Capabilities       UserspaceCapabilities        `json:"capabilities"`
	MapPins            UserspaceMapPins             `json:"map_pins"`
	Zones              []ZoneSnapshot               `json:"zones,omitempty"`
	Interfaces         []InterfaceSnapshot          `json:"interfaces,omitempty"`
	Fabrics            []FabricSnapshot             `json:"fabrics,omitempty"`
	TunnelEndpoints    []TunnelEndpointSnapshot     `json:"tunnel_endpoints,omitempty"`
	Neighbors          []NeighborSnapshot           `json:"neighbors,omitempty"`
	Routes             []RouteSnapshot              `json:"routes,omitempty"`
	Flow               FlowSnapshot                 `json:"flow,omitempty"`
	DefaultPolicy      string                       `json:"default_policy,omitempty"`
	Policies           []PolicyRuleSnapshot         `json:"policies,omitempty"`
	SourceNAT          []SourceNATRuleSnapshot      `json:"source_nat_rules,omitempty"`
	StaticNAT          []StaticNATRuleSnapshot      `json:"static_nat_rules,omitempty"`
	DestinationNAT     []DestinationNATRuleSnapshot `json:"destination_nat_rules,omitempty"`
	NAT64              []NAT64RuleSnapshot          `json:"nat64_rules,omitempty"`
	Nptv6              []Nptv6RuleSnapshot          `json:"nptv6_rules,omitempty"`
	Screens            []ScreenProfileSnapshot      `json:"screens,omitempty"`
	SYNCookieMasterKey string                       `json:"syn_cookie_master_key,omitempty"`
	Filters            []FirewallFilterSnapshot     `json:"filters,omitempty"`
	Policers           []PolicerSnapshot            `json:"policers,omitempty"`
	ThreeColorPolicers []ThreeColorPolicerSnapshot  `json:"three_color_policers,omitempty"`
	ClassOfService     *ClassOfServiceSnapshot      `json:"class_of_service,omitempty"`
	FlowExport         *FlowExportSnapshot          `json:"flow_export,omitempty"`
	MirrorConfigs      []MirrorConfigSnapshot       `json:"mirror_configs,omitempty"`
	AddressBooks       []AddressBookSnapshot        `json:"address_books,omitempty"`
	// AppCatalog is the L3/L4 application-identification catalog (#2008 M5):
	// the ordered (protocol, port-range) -> app_id classification table the
	// dataplane uses to stamp app_id on a new session. Additive field — an
	// old Rust helper that does not know it simply ignores it (serde does not
	// require it), and an old Go binary that does not emit it leaves Rust's
	// catalog empty (every session keeps app_id 0, the existing default). The
	// app_id values match CompileResult.AppNames so `show security flow
	// session` resolves them back to names.
	AppCatalog   []AppCatalogEntrySnapshot `json:"app_catalog,omitempty"`
	Config       *config.Config            `json:"config,omitempty"`
	Userspace    config.UserspaceConfig    `json:"userspace"`
	DeferWorkers bool                      `json:"defer_workers,omitempty"`
	// #1620: cold-path latency histogram sample mask. *uint64 with
	// omitempty so a nil pointer omits the field entirely from the
	// wire (matching the Rust Option<u64>::None behavior). Default
	// at the Rust receiver: unwrap_or(0xff) = 1-in-256 sampling.
	// Powers-of-two-minus-one only (validated in cmd/xpfd/main.go).
	// Setting to a non-nil pointer to 0 explicitly enables 1-in-1
	// sampling (256× CPU cost) — operator must pass both
	// --cold-path-sample-mask 0 and --enable-cold-path-1-in-1-sampling.
	ColdPathSampleMask *uint64 `json:"cold_path_sample_mask,omitempty"`
}

// AddressBookSnapshot is #1606: one row of the deduplicated address-book
// table. Multiple Junos-declared names whose canonical CIDR sets are
// identical share one row + one ID. Name is diagnostic-only
// (lexicographically smallest declaring name).
type AddressBookSnapshot struct {
	ID         uint32   `json:"id"`
	Name       string   `json:"name,omitempty"`
	PrefixesV4 []string `json:"prefixes_v4,omitempty"`
	PrefixesV6 []string `json:"prefixes_v6,omitempty"`
}

type FlowSnapshot struct {
	AllowDNSReply      bool `json:"allow_dns_reply,omitempty"`
	AllowEmbeddedICMP  bool `json:"allow_embedded_icmp,omitempty"`
	TCPMSSAllTCP       int  `json:"tcp_mss_all_tcp,omitempty"`
	TCPMSSIPsecVPN     int  `json:"tcp_mss_ipsec_vpn,omitempty"`
	TCPMSSGreIn        int  `json:"tcp_mss_gre_in,omitempty"`
	TCPMSSGreOut       int  `json:"tcp_mss_gre_out,omitempty"`
	TCPSessionTimeout  int  `json:"tcp_session_timeout,omitempty"`  // seconds, 0=default
	UDPSessionTimeout  int  `json:"udp_session_timeout,omitempty"`  // seconds, 0=default
	ICMPSessionTimeout int  `json:"icmp_session_timeout,omitempty"` // seconds, 0=default
	GREAcceleration    bool `json:"gre_acceleration,omitempty"`     // extract GRE key into session ports
	// PowerModeDisable carries `security flow power-mode-disable` (#2008 H14).
	// On vSRX power-mode is an express datapath; disabling it forces the
	// regular flow path. The userspace dataplane has a single forwarding path,
	// so this threads the operator's intent into ForwardingState (mirroring the
	// GREAcceleration plumbing) and is read on the Rust side for parity; it does
	// not currently alter packet handling (there is no express/regular split to
	// switch between).
	PowerModeDisable bool   `json:"power_mode_disable,omitempty"`
	Lo0FilterInputV4 string `json:"lo0_filter_input_v4,omitempty"` // lo0 inet input filter name
	Lo0FilterInputV6 string `json:"lo0_filter_input_v6,omitempty"` // lo0 inet6 input filter name
	// ALGDisableFlags carries the `security alg <proto> disable` bitfield
	// (bit 0: DNS, bit 1: FTP, bit 2: SIP, bit 3: TFTP — same layout as the
	// legacy flow_config_map FlowConfigValue.ALGFlags). The userspace
	// dataplane reads this to suppress ALG-type tagging for disabled ALGs
	// (#2008 H3/H4). Junos `alg disable` turns the ALG off; it does NOT drop
	// traffic, so the only enforced effect is that a session matching a
	// disabled ALG is no longer tagged with that ALG type.
	ALGDisableFlags uint8 `json:"alg_disable_flags,omitempty"`
}

type SnapshotSummary struct {
	HostName       string `json:"host_name"`
	DataplaneType  string `json:"dataplane_type"`
	InterfaceCount int    `json:"interface_count"`
	ZoneCount      int    `json:"zone_count"`
	PolicyCount    int    `json:"policy_count"`
	SchedulerCount int    `json:"scheduler_count"`
	HAEnabled      bool   `json:"ha_enabled"`
}

type ZoneSnapshot struct {
	Name string `json:"name"`
	ID   uint16 `json:"id"`
}

type InterfaceSnapshot struct {
	Name                      string                     `json:"name"`
	Zone                      string                     `json:"zone,omitempty"`
	LinuxName                 string                     `json:"linux_name,omitempty"`
	ParentLinuxName           string                     `json:"parent_linux_name,omitempty"`
	Ifindex                   int                        `json:"ifindex,omitempty"`
	ParentIfindex             int                        `json:"parent_ifindex,omitempty"`
	LogicalOnly               bool                       `json:"logical_only,omitempty"`
	RXQueues                  int                        `json:"rx_queues,omitempty"`
	VLANID                    int                        `json:"vlan_id,omitempty"`
	LocalFabric               string                     `json:"local_fabric_member,omitempty"`
	RedundancyGroup           int                        `json:"redundancy_group,omitempty"`
	UnitCount                 int                        `json:"unit_count"`
	Tunnel                    bool                       `json:"tunnel"`
	MTU                       int                        `json:"mtu,omitempty"`
	HardwareAddr              string                     `json:"hardware_addr,omitempty"`
	Addresses                 []InterfaceAddressSnapshot `json:"addresses,omitempty"`
	FilterInputV4             string                     `json:"filter_input_v4,omitempty"`
	FilterOutputV4            string                     `json:"filter_output_v4,omitempty"`
	FilterInputV6             string                     `json:"filter_input_v6,omitempty"`
	FilterOutputV6            string                     `json:"filter_output_v6,omitempty"`
	CoSShapingRateBytesPerSec uint64                     `json:"cos_shaping_rate_bytes_per_sec,omitempty"`
	CoSBurstSize              uint64                     `json:"cos_shaping_burst_bytes,omitempty"`
	CoSSchedulerMap           string                     `json:"cos_scheduler_map,omitempty"`
	CoSDSCPClassifier         string                     `json:"cos_dscp_classifier,omitempty"`
	CoSIEEE8021Classifier     string                     `json:"cos_ieee8021_classifier,omitempty"`
	CoSDSCPRewriteRule        string                     `json:"cos_dscp_rewrite_rule,omitempty"`
	// #1614 A1: operator-selectable oversubscription policy. "" or
	// "proportional" (default) preserves current scheduler bit-for-
	// bit (when CoSPriorityLowMinShareBytes is also 0). "guarantee-
	// rate" activates the two-phase waterfill allocator using
	// CoSOversubscriptionGuaranteeFraction.
	CoSOversubscriptionPolicy string `json:"cos_oversubscription_policy,omitempty"`
	// #1614 A1: Phase 1 budget fraction (0.0..1.0). Only meaningful
	// when CoSOversubscriptionPolicy == "guarantee-rate". 0.0 makes
	// the allocator a no-op even if the policy string is set.
	CoSOversubscriptionGuaranteeFraction float64 `json:"cos_oversubscription_guarantee_fraction,omitempty"`
	// #1614 A2: priority-low minimum share in bytes per second.
	// WIRE SURFACE ONLY in PR #1618 — the per-pass cap_eff
	// subtraction in the Rust selector is deferred to a focused
	// follow-up. Default 0 (no min-share); no hot-path effect
	// today.
	CoSPriorityLowMinShareBytes uint64 `json:"cos_priority_low_min_share_bytes,omitempty"`
}

type ClassOfServiceSnapshot struct {
	ForwardingClasses   []CoSForwardingClassSnapshot    `json:"forwarding_classes,omitempty"`
	DSCPClassifiers     []CoSDSCPClassifierSnapshot     `json:"dscp_classifiers,omitempty"`
	IEEE8021Classifiers []CoSIEEE8021ClassifierSnapshot `json:"ieee8021_classifiers,omitempty"`
	DSCPRewriteRules    []CoSDSCPRewriteRuleSnapshot    `json:"dscp_rewrite_rules,omitempty"`
	Schedulers          []CoSSchedulerSnapshot          `json:"schedulers,omitempty"`
	SchedulerMaps       []CoSSchedulerMapSnapshot       `json:"scheduler_maps,omitempty"`
}

type CoSForwardingClassSnapshot struct {
	Name  string `json:"name"`
	Queue int    `json:"queue"`
}

type CoSDSCPClassifierSnapshot struct {
	Name    string                           `json:"name"`
	Entries []CoSDSCPClassifierEntrySnapshot `json:"entries,omitempty"`
}

type CoSDSCPClassifierEntrySnapshot struct {
	ForwardingClass string        `json:"forwarding_class,omitempty"`
	LossPriority    string        `json:"loss_priority,omitempty"`
	DSCPValues      WireUint8List `json:"dscp_values,omitempty"`
}

type CoSIEEE8021ClassifierSnapshot struct {
	Name    string                               `json:"name"`
	Entries []CoSIEEE8021ClassifierEntrySnapshot `json:"entries,omitempty"`
}

type CoSIEEE8021ClassifierEntrySnapshot struct {
	ForwardingClass string        `json:"forwarding_class,omitempty"`
	LossPriority    string        `json:"loss_priority,omitempty"`
	CodePoints      WireUint8List `json:"code_points,omitempty"`
}

type CoSDSCPRewriteRuleSnapshot struct {
	Name    string                            `json:"name"`
	Entries []CoSDSCPRewriteRuleEntrySnapshot `json:"entries,omitempty"`
}

type CoSDSCPRewriteRuleEntrySnapshot struct {
	ForwardingClass string `json:"forwarding_class,omitempty"`
	LossPriority    string `json:"loss_priority,omitempty"`
	DSCPValue       uint8  `json:"dscp_value,omitempty"`
}

type CoSSchedulerSnapshot struct {
	Name              string `json:"name"`
	TransmitRateBytes uint64 `json:"transmit_rate_bytes,omitempty"`
	TransmitRateExact bool   `json:"transmit_rate_exact,omitempty"`
	Priority          string `json:"priority,omitempty"`
	BufferSizeBytes   uint64 `json:"buffer_size_bytes,omitempty"`
	// BufferSizePercent is additive to preserve the legacy
	// buffer_size_bytes wire contract. Older dataplanes ignore it;
	// newer dataplanes use it only when buffer_size_bytes is absent.
	BufferSizePercent float64 `json:"buffer_size_percent,omitempty"`
	// SurplusSharing (#915) opts an exact queue into surplus-phase
	// participation; only meaningful when TransmitRateExact == true.
	SurplusSharing bool `json:"surplus_sharing,omitempty"`
	// EqualFlowEnforcement is an explicit opt-in for shared v8
	// queue-lease equal-flow suppression on positive transmit-rate
	// exact queues.
	EqualFlowEnforcement bool `json:"equal_flow_enforcement,omitempty"`
	// EqualFlowTargetPolicy (#1746) selects the equal-flow per-flow
	// target reduction: "slowest" | "mean" | "ideal-share". omitempty
	// keeps the wire byte-identical for unset configs ("" == the
	// byte-unchanged "slowest" default on the Rust side).
	EqualFlowTargetPolicy string `json:"equal_flow_target_policy,omitempty"`
	// #1614 A3: per-queue CoDel target in nanoseconds. WIRE
	// SURFACE ONLY in PR #1618 — the dequeue-time sojourn check
	// is deferred to a focused follow-up. 0 disables CoDel for
	// the queue (current default and the only behaviour-affecting
	// value today). Recommended >= 1.5x post-shaper RTT per AGY
	// r2 finding #3 when the sojourn check ships.
	CodelTargetNS uint64 `json:"codel_target_ns,omitempty"`
}

type CoSSchedulerMapSnapshot struct {
	Name    string                         `json:"name"`
	Entries []CoSSchedulerMapEntrySnapshot `json:"entries,omitempty"`
}

type CoSSchedulerMapEntrySnapshot struct {
	ForwardingClass string `json:"forwarding_class"`
	Scheduler       string `json:"scheduler,omitempty"`
}

type FabricSnapshot struct {
	Name            string `json:"name"`
	ParentInterface string `json:"parent_interface,omitempty"`
	ParentLinuxName string `json:"parent_linux_name,omitempty"`
	ParentIfindex   int    `json:"parent_ifindex,omitempty"`
	OverlayLinux    string `json:"overlay_linux_name,omitempty"`
	OverlayIfindex  int    `json:"overlay_ifindex,omitempty"`
	RXQueues        int    `json:"rx_queues,omitempty"`
	PeerAddress     string `json:"peer_address,omitempty"`
	LocalMAC        string `json:"local_mac,omitempty"`
	PeerMAC         string `json:"peer_mac,omitempty"`
}

type TunnelEndpointSnapshot struct {
	ID              uint16 `json:"id,omitempty"`
	Interface       string `json:"interface,omitempty"`
	LinuxName       string `json:"linux_name,omitempty"`
	Ifindex         int    `json:"ifindex,omitempty"`
	Zone            string `json:"zone,omitempty"`
	RedundancyGroup int    `json:"redundancy_group,omitempty"`
	MTU             int    `json:"mtu,omitempty"`
	Mode            string `json:"mode,omitempty"`
	OuterFamily     string `json:"outer_family,omitempty"`
	Source          string `json:"source,omitempty"`
	Destination     string `json:"destination,omitempty"`
	Key             uint32 `json:"key,omitempty"`
	TTL             int    `json:"ttl,omitempty"`
	TransportTable  string `json:"transport_table,omitempty"`

	// WireGuard clean-room termination (see docs/pr/wireguard-clean/plan.md).
	// All fields are wire-compatible additions: a daemon built before the
	// plan landed will simply omit them, and the Rust side defaults each
	// field via #[serde(default)]. The control plane only populates them
	// when Mode == "wireguard".
	//
	// WgListenPort is the local UDP port we listen on for inbound WG
	// transport. Listen-port selection happens at the integration
	// layer's UDP-socket dispatch (one layer above the engine); the
	// engine itself demuxes by `receiver_index` alone via the
	// `sessions_by_local_index` map (see userspace-dp
	// afxdp/wg/engine.rs:275). The receiver index is chosen by the
	// local side at handshake time, so it identifies the session
	// unambiguously without a (port, index) tuple match.
	WgListenPort uint16 `json:"wg_listen_port,omitempty"`
	// WgLocalPrivkeyHex is the local static X25519 private key as
	// hex (64 chars). Control-plane-internal; never logged.
	WgLocalPrivkeyHex string `json:"wg_local_privkey_hex,omitempty"`
	// WgPeers is the ordered per-peer set (#1434 multi-peer),
	// sorted by pubkey at the snapshot-builder boundary for HA
	// determinism. Replaces the scalar Wg{PeerPubkeyHex,AllowedIPs,
	// Endpoint,KeepaliveSecs} fields. The Rust side feeds the engine
	// peer table from this slice; RX/decap demuxes by receiver_index
	// across all peers, and TX/encap selects the peer by inner-dst
	// AllowedIPs LPM (#1434 B1b).
	WgPeers []TunnelWgPeerWire `json:"wg_peers,omitempty"`
}

// TunnelWgPeerWire is one WireGuard peer on the Go→Rust wire (#1434).
// Mirrors the Rust TunnelWgPeerSnapshot (snapshot.rs). Keep json tags
// identical on BOTH sides (feedback_wire_protocol_both_sides).
type TunnelWgPeerWire struct {
	// WgPeerPubkeyHex is the peer's static X25519 public key as hex.
	WgPeerPubkeyHex string `json:"wg_peer_pubkey_hex,omitempty"`
	// WgAllowedIPs is the peer's AllowedIPs as CIDR strings.
	WgAllowedIPs []string `json:"wg_allowed_ips,omitempty"`
	// WgEndpoint is the optional peer endpoint (IP:port). Empty for
	// responder-only.
	WgEndpoint string `json:"wg_endpoint,omitempty"`
	// WgKeepaliveSecs is the optional persistent-keepalive interval.
	// 0 means disabled.
	WgKeepaliveSecs uint16 `json:"wg_keepalive_secs,omitempty"`
	// WgPresharedKeyHex is the optional per-peer preshared key as hex
	// (#1434 B2). Empty = zero PSK. SECRET: like wg_local_privkey_hex
	// it is delivered on the control socket (the engine needs it) but
	// MUST never reach an on-disk state snapshot or a log — the Rust
	// side marks the matching field skip_serializing.
	WgPresharedKeyHex string `json:"wg_preshared_key_hex,omitempty"`
}

type SourceNATRuleSnapshot struct {
	Name                             string   `json:"name"`
	FromZone                         string   `json:"from_zone,omitempty"`
	ToZone                           string   `json:"to_zone,omitempty"`
	SourceAddresses                  []string `json:"source_addresses,omitempty"`
	DestinationAddresses             []string `json:"destination_addresses,omitempty"`
	InterfaceMode                    bool     `json:"interface_mode,omitempty"`
	Off                              bool     `json:"off,omitempty"`
	PoolName                         string   `json:"pool_name,omitempty"`
	PoolAddresses                    []string `json:"pool_addresses,omitempty"`
	PortLow                          uint16   `json:"port_low,omitempty"`
	PortHigh                         uint16   `json:"port_high,omitempty"`
	AddressPersistent                bool     `json:"address_persistent,omitempty"`
	PersistentNAT                    bool     `json:"persistent_nat,omitempty"`
	PersistentNATPermitAnyRemoteHost bool     `json:"persistent_nat_permit_any_remote_host,omitempty"`
	PersistentNATInactivityTimeout   int      `json:"persistent_nat_inactivity_timeout,omitempty"`
	PoolUnusable                     bool     `json:"pool_unusable,omitempty"`
	PoolUnusableReason               string   `json:"pool_unusable_reason,omitempty"`
	// CounterID is the compiler-assigned per-rule translation hit counter ID
	// (stable key-derived hash, non-zero; 0 means "no counter"). The userspace
	// dataplane attributes each SNAT translation on this rule to this slot, and
	// Manager.ReadNATRuleCounter reads it back for `show security nat source
	// rule` (#2218). The ID is stable across config reorder/removal (#2255), so
	// it is u32-wide; the JSON wire is unchanged (a number is width-agnostic).
	CounterID uint32 `json:"counter_id,omitempty"`
}

type StaticNATRuleSnapshot struct {
	Name       string `json:"name"`
	FromZone   string `json:"from_zone,omitempty"`
	ExternalIP string `json:"external_ip"`
	InternalIP string `json:"internal_ip"`
	// CounterID is the compiler-assigned per-rule translation hit counter ID
	// (stable key-derived hash, non-zero; 0 means "no counter") for this static
	// NAT rule (#2218; stable across reorder/removal, #2255).
	CounterID uint32 `json:"counter_id,omitempty"`
}

// DestinationNATRuleSnapshot captures a pre-expanded DNAT table entry for the
// userspace dataplane. Each snapshot is one (protocol, destination IP, destination port)
// tuple. The Go builder handles multi-port and protocol expansion.
type DestinationNATRuleSnapshot struct {
	Name               string `json:"name"`
	FromZone           string `json:"from_zone,omitempty"`
	DestinationAddress string `json:"destination_address"`
	DestinationPort    uint16 `json:"destination_port,omitempty"`
	Protocol           string `json:"protocol,omitempty"` // "tcp", "udp", or ""
	PoolAddress        string `json:"pool_address"`
	PoolPort           uint16 `json:"pool_port,omitempty"`
	// CounterID is the compiler-assigned per-rule translation hit counter ID
	// (stable key-derived hash, non-zero; 0 means "no counter"). All expanded
	// (protocol, port) tuples of the same DNAT rule share one counter ID so
	// every hit attributes to a single slot read back for `show security nat
	// destination rule` (#2218; stable across reorder/removal, #2255).
	CounterID uint32 `json:"counter_id,omitempty"`
}

// NAT64RuleSnapshot captures a NAT64 prefix and its IPv4 source pool for the
// userspace dataplane.
type NAT64RuleSnapshot struct {
	Name          string   `json:"name"`
	Prefix        string   `json:"prefix"`         // e.g. "64:ff9b::/96"
	PoolAddresses []string `json:"pool_addresses"` // resolved IPv4 pool addresses
	// NoV6FragHeader mirrors the global `security nat natv6v4
	// no-v6-frag-header` knob. This is an option-gated LOCAL DF policy (not the
	// size-driven RFC 7915 5.1 selection): when set, the IPv6->IPv4 translator
	// clears DF so the translated IPv4 packet stays fragmentable (DF=0,
	// non-atomic) and carries a generated non-zero, non-repeating
	// Identification (RFC 6864 4.1) instead of the default DF=1 atomic framing.
	// Replicated onto every NAT64 rule because the option is configured once at
	// the natv6v4 level, not per rule-set.
	NoV6FragHeader bool `json:"no_v6_frag_header,omitempty"`
}

// Nptv6RuleSnapshot captures an NPTv6 (RFC 6296) stateless prefix translation
// rule for the userspace dataplane.
type Nptv6RuleSnapshot struct {
	Name           string `json:"name"`
	FromZone       string `json:"from_zone,omitempty"`
	InternalPrefix string `json:"internal_prefix"` // e.g. "fd35:1940:0027::/48"
	ExternalPrefix string `json:"external_prefix"` // e.g. "2602:fd41:0070::/48"
}

// ScreenProfileSnapshot captures a per-zone screen profile for the userspace
// dataplane. Mirrors the BPF screen_config structure.
type ScreenProfileSnapshot struct {
	Zone               string `json:"zone"`
	Land               bool   `json:"land,omitempty"`
	SynFin             bool   `json:"syn_fin,omitempty"`
	NoFlag             bool   `json:"tcp_no_flag,omitempty"`
	FinNoAck           bool   `json:"fin_no_ack,omitempty"`
	WinNuke            bool   `json:"winnuke,omitempty"`
	PingDeath          bool   `json:"ping_death,omitempty"`
	Teardrop           bool   `json:"teardrop,omitempty"`
	ICMPFragment       bool   `json:"icmp_fragment,omitempty"`
	SynFrag            bool   `json:"syn_frag,omitempty"`
	SourceRoute        bool   `json:"source_route,omitempty"`
	ICMPFloodThreshold uint32 `json:"icmp_flood_threshold,omitempty"`
	UDPFloodThreshold  uint32 `json:"udp_flood_threshold,omitempty"`
	SYNFloodThreshold  uint32 `json:"syn_flood_threshold,omitempty"`
	SYNCookie          bool   `json:"syn_cookie,omitempty"`
	// Advanced screen features for userspace dataplane
	SessionLimitSrc   uint32 `json:"session_limit_src,omitempty"`
	SessionLimitDst   uint32 `json:"session_limit_dst,omitempty"`
	PortScanThreshold uint32 `json:"port_scan_threshold,omitempty"`
	IPSweepThreshold  uint32 `json:"ip_sweep_threshold,omitempty"`
}

type FirewallFilterSnapshot struct {
	Name   string                 `json:"name"`
	Family string                 `json:"family"` // "inet" or "inet6"
	Terms  []FirewallTermSnapshot `json:"terms"`
}

type FirewallTermSnapshot struct {
	Name            string        `json:"name"`
	SourceAddresses []string      `json:"source_addresses,omitempty"`
	DestAddresses   []string      `json:"destination_addresses,omitempty"`
	Protocols       []string      `json:"protocols,omitempty"`
	SourcePorts     []string      `json:"source_ports,omitempty"` // "80" or "1024-65535"
	DestPorts       []string      `json:"destination_ports,omitempty"`
	DSCPValues      WireUint8List `json:"dscp_values,omitempty"`
	Action          string        `json:"action"` // "accept", "discard", "reject"
	Count           string        `json:"count,omitempty"`
	Log             bool          `json:"log,omitempty"`
	PolicerName     string        `json:"policer,omitempty"`
	RoutingInstance string        `json:"routing_instance,omitempty"`
	ForwardingClass string        `json:"forwarding_class,omitempty"`
	DSCPRewrite     *uint8        `json:"dscp_rewrite,omitempty"`
}

type PolicerSnapshot struct {
	Name          string `json:"name"`
	BandwidthBps  uint64 `json:"bandwidth_bps"`
	BurstBytes    uint64 `json:"burst_bytes"`
	DiscardExcess bool   `json:"discard_excess"`
}

type ThreeColorPolicerSnapshot struct {
	Name                   string `json:"name"`
	Mode                   string `json:"mode"` // "single-rate" (srTCM) or "two-rate" (trTCM)
	ColorBlind             bool   `json:"color_blind,omitempty"`
	CommittedRateBytes     uint64 `json:"committed_rate_bytes_per_sec"`
	CommittedBurstBytes    uint64 `json:"committed_burst_bytes"`
	PeakOrExcessRateBytes  uint64 `json:"peak_or_excess_rate_bytes_per_sec,omitempty"`
	PeakOrExcessBurstBytes uint64 `json:"peak_or_excess_burst_bytes"`
	ThenAction             string `json:"then_action,omitempty"`
}

// FlowExportSnapshot captures flow monitoring/export configuration for the
// userspace dataplane.
type FlowExportSnapshot struct {
	CollectorAddress string `json:"collector_address"`
	CollectorPort    int    `json:"collector_port"`
	SamplingRate     int    `json:"sampling_rate"`
	ActiveTimeout    int    `json:"active_timeout,omitempty"`   // seconds, 0=default 60
	InactiveTimeout  int    `json:"inactive_timeout,omitempty"` // seconds, 0=default 15
}

// MirrorConfigSnapshot captures one ingress SPAN mapping for userspace-dp.
// It is snapshot/admission state only until the userspace runtime clone path is
// wired. Runtime delivery must use full-L2 cross-binding inject; the L3 TUN
// slow-path is not a valid mirror sink because it strips Ethernet framing.
type MirrorConfigSnapshot struct {
	IngressIfindex int    `json:"ingress_ifindex"`
	OutputIfindex  int    `json:"output_ifindex"`
	Rate           uint32 `json:"rate"`
}

type PolicyApplicationSnapshot struct {
	Name            string `json:"name"`
	Protocol        string `json:"protocol,omitempty"`
	SourcePort      string `json:"source_port,omitempty"`
	DestinationPort string `json:"destination_port,omitempty"`
}

// AppCatalogEntrySnapshot is one row of the application-identification catalog
// (#2008 M5). The dataplane scans these on session create and stamps the
// matching AppID on the conntrack session so `show security flow session`
// resolves a real application name. Inclusive port boundaries; a zero
// DstPortLow/DstPortHigh pair means "no destination-port constraint" (match on
// protocol alone, e.g. ICMP), and a zero SrcPortLow/SrcPortHigh pair means "no
// source-port constraint". AppID is never 0 (0 is the reserved unknown
// sentinel). Rust mirror: AppCatalogEntry in protocol/snapshot.rs.
type AppCatalogEntrySnapshot struct {
	AppID       uint16 `json:"app_id"`
	Protocol    uint8  `json:"protocol"`
	DstPortLow  uint16 `json:"dst_port_low,omitempty"`
	DstPortHigh uint16 `json:"dst_port_high,omitempty"`
	SrcPortLow  uint16 `json:"src_port_low,omitempty"`
	SrcPortHigh uint16 `json:"src_port_high,omitempty"`
}

type PolicyRuleSnapshot struct {
	RuleID        string `json:"rule_id,omitempty"`
	PolicyID      uint32 `json:"policy_id,omitempty"`
	Name          string `json:"name"`
	FromZone      string `json:"from_zone,omitempty"`
	ToZone        string `json:"to_zone,omitempty"`
	SchedulerName string `json:"scheduler_name,omitempty"`
	Inactive      bool   `json:"inactive,omitempty"`
	// Legacy field (carries full expansion: literals ∪ book CIDRs).
	// Used by old-Rust binaries reading new-Go snapshots. New-Rust
	// IGNORES this field when the rule is v3-shaped.
	SourceAddresses      []string `json:"source_addresses,omitempty"`
	DestinationAddresses []string `json:"destination_addresses,omitempty"`
	// #1606: dense u32 IDs of named address books cited by the
	// rule.
	SourceBookIDs      []uint32 `json:"source_book_ids,omitempty"`
	DestinationBookIDs []uint32 `json:"destination_book_ids,omitempty"`
	// #1606: free-form CIDR / "any" literals written inline in the
	// rule (NOT a named address-book reference).
	SourceLiterals      []string                    `json:"source_literals,omitempty"`
	DestinationLiterals []string                    `json:"destination_literals,omitempty"`
	Applications        []string                    `json:"applications,omitempty"`
	ApplicationTerms    []PolicyApplicationSnapshot `json:"application_terms,omitempty"`
	Action              string                      `json:"action,omitempty"`
	// #2008 H2: invert the source/destination match sense — the
	// rule matches every address EXCEPT those named in the
	// corresponding address set (Junos `source-address-excluded` /
	// `destination-address-excluded`).
	SourceAddressExcluded      bool `json:"source_address_excluded,omitempty"`
	DestinationAddressExcluded bool `json:"destination_address_excluded,omitempty"`
}

type InterfaceAddressSnapshot struct {
	Family  string `json:"family"`
	Address string `json:"address"`
	Scope   int    `json:"scope,omitempty"`
}

type RouteSnapshot struct {
	Table       string   `json:"table"`
	Family      string   `json:"family"`
	Destination string   `json:"destination"`
	NextHops    []string `json:"next_hops,omitempty"`
	Discard     bool     `json:"discard"`
	NextTable   string   `json:"next_table,omitempty"`
}

type NeighborSnapshot struct {
	Interface string `json:"interface,omitempty"`
	Ifindex   int    `json:"ifindex,omitempty"`
	Family    string `json:"family"`
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	State     string `json:"state,omitempty"`
	Router    bool   `json:"router,omitempty"`
	LinkLocal bool   `json:"link_local,omitempty"`
}

type UserspaceMapPins struct {
	Ctrl        string `json:"ctrl,omitempty"`
	Bindings    string `json:"bindings,omitempty"`
	Heartbeat   string `json:"heartbeat,omitempty"`
	XSK         string `json:"xsk,omitempty"`
	LocalV4     string `json:"local_v4,omitempty"`
	LocalV6     string `json:"local_v6,omitempty"`
	Sessions    string `json:"sessions,omitempty"`
	ConntrackV4 string `json:"conntrack_v4,omitempty"`
	ConntrackV6 string `json:"conntrack_v6,omitempty"`
	DnatTable   string `json:"dnat_table,omitempty"`
	DnatTableV6 string `json:"dnat_table_v6,omitempty"`
	Trace       string `json:"trace,omitempty"`
}

type UserspaceCapabilities struct {
	ForwardingSupported bool     `json:"forwarding_supported"`
	UnsupportedReasons  []string `json:"unsupported_reasons,omitempty"`
}

type ProcessStatus struct {
	PID                              int                   `json:"pid"`
	ConfigSnapshotProtocolVersion    int                   `json:"config_snapshot_protocol_version,omitempty"`
	InjectPacketTupleProtocolVersion int                   `json:"inject_packet_tuple_protocol_version,omitempty"`
	StartedAt                        time.Time             `json:"started_at"`
	ControlSocket                    string                `json:"control_socket"`
	StateFile                        string                `json:"state_file"`
	Workers                          int                   `json:"workers"`
	RingEntries                      int                   `json:"ring_entries"`
	HelperMode                       string                `json:"helper_mode"`
	IOUringPlanned                   bool                  `json:"io_uring_planned"`
	IOUringActive                    bool                  `json:"io_uring_active,omitempty"`
	IOUringMode                      string                `json:"io_uring_mode,omitempty"`
	IOUringLastError                 string                `json:"io_uring_last_error,omitempty"`
	Enabled                          bool                  `json:"enabled"`
	ForwardingArmed                  bool                  `json:"forwarding_armed,omitempty"`
	Capabilities                     UserspaceCapabilities `json:"capabilities"`
	LastSnapshotGeneration           uint64                `json:"last_snapshot_generation"`
	LastFIBGeneration                uint32                `json:"last_fib_generation,omitempty"`
	LastSnapshotAt                   time.Time             `json:"last_snapshot_at,omitempty"`
	InterfaceAddresses               int                   `json:"interface_addresses,omitempty"`
	NeighborEntries                  int                   `json:"neighbor_entries,omitempty"`
	SessionTableEntries              uint64                `json:"session_table_entries,omitempty"`
	MaxSessions                      uint64                `json:"max_sessions,omitempty"`
	// #1760: aggregate NAT reverse-key displacement events summed across
	// the per-worker session tables -- the latent 1:N collision (#1758)
	// made observable. Near-precise upper bound on live collisions (counts
	// displacement events, not distinct flow-pairs). Nonzero triggers the
	// structural-fix research; does NOT resolve #1760. omitempty for
	// mixed Rust/Go daemon back-compat.
	NatReverseKeyCollisions uint64 `json:"nat_reverse_key_collisions,omitempty"`
	// #1861: aggregate at-cap install refusals (SessionTable create_drops,
	// write-only/invisible before #1861), pair-admission preflight
	// refusals (one per refused flow at the new-flow transaction
	// boundary), and post-preflight partial-install residuals (expected
	// 0 forever; nonzero = preflight/install pairing bug). omitempty for
	// mixed Rust/Go daemon back-compat (older helpers omit the keys).
	SessionCreateDrops             uint64      `json:"session_create_drops,omitempty"`
	SessionInstallAdmissionRefused uint64      `json:"session_install_admission_refused,omitempty"`
	SessionInstallPartial          uint64      `json:"session_install_partial,omitempty"`
	FlowCacheCapacity              uint64      `json:"flow_cache_capacity,omitempty"`
	NeighborCacheCapacity          uint64      `json:"neighbor_cache_capacity,omitempty"`
	NeighborGeneration             uint64      `json:"neighbor_generation,omitempty"`
	RouteEntries                   int         `json:"route_entries,omitempty"`
	WorkerHeartbeats               []time.Time `json:"worker_heartbeats,omitempty"`
	// #869: per-worker busy/idle runtime telemetry.
	WorkerRuntime []WorkerRuntimeStatus `json:"worker_runtime,omitempty"`
	HAGroups      []HAGroupStatus       `json:"ha_groups,omitempty"`
	Fabrics       []FabricSnapshot      `json:"fabrics,omitempty"`
	Queues        []QueueStatus         `json:"queues,omitempty"`
	Bindings      []BindingStatus       `json:"bindings,omitempty"`
	// #802: focused per-binding ring-pressure view. Projected from
	// Bindings by the Rust helper; parallel rather than replacement.
	PerBinding []BindingCountersSnapshot `json:"per_binding,omitempty"`
	// #1249: bounded low-frequency diagnostic map from active flow-cache
	// entries to the worker/RX queue that currently owns them. This is
	// status/debug data only, not a production metric or scheduler input.
	FlowWorkerMap          []FlowWorkerStatus `json:"flow_worker_map,omitempty"`
	FlowWorkerMapTruncated bool               `json:"flow_worker_map_truncated,omitempty"`
	// #1248: per-CoS-queue active flow distribution by egress ifindex,
	// queue, and worker. This is the class-specific {a_i} source for
	// mixed-workload fairness diagnostics.
	CoSActiveFlowCounts          []CoSActiveFlowCountStatus `json:"cos_active_flow_counts,omitempty"`
	CoSActiveFlowCountsTruncated bool                       `json:"cos_active_flow_counts_truncated,omitempty"`
	RecentSessionDeltas          []SessionDeltaInfo         `json:"recent_session_deltas,omitempty"`
	RecentExceptions             []ExceptionStatus          `json:"recent_exceptions,omitempty"`
	EventStream                  *EventStreamStatus         `json:"event_stream,omitempty"`
	EventStreamSent              uint64                     `json:"event_stream_sent,omitempty"`
	EventStreamDropped           uint64                     `json:"event_stream_dropped,omitempty"`
	// #1642: the Rust helper serializes these three flat event-stream
	// fields on ProcessStatus (protocol/control.rs) alongside _sent /
	// _dropped, but the Go side only declared _sent / _dropped, so
	// connected / seq / acked were silently dropped. The nested
	// *EventStreamStatus above carries different, Go-populated counters
	// (frames_read, decode_errors) the Rust helper never emits. JSON tags
	// MUST match Rust serde rename(...) exactly.
	EventStreamConnected bool                      `json:"event_stream_connected,omitempty"`
	EventStreamSeq       uint64                    `json:"event_stream_seq,omitempty"`
	EventStreamAcked     uint64                    `json:"event_stream_acked,omitempty"`
	CoSInterfaces        []CoSInterfaceStatus      `json:"cos_interfaces,omitempty"`
	PolicyRuleCounters   []PolicyRuleCounterStatus `json:"policy_rule_counters,omitempty"`
	// NATRuleCounters carries the userspace dataplane's per-rule SNAT/DNAT/
	// static-NAT translation hit counters keyed by the compiler-assigned
	// counter ID (#2218). The Go control plane mirrors these into the legacy
	// bpfShim nat_rule_counters offset map so Manager.ReadNATRuleCounter (and
	// thus `show security nat source/destination/static rule`) reports the
	// live translation count instead of a perpetual 0.
	NATRuleCounters           []NATRuleCounterStatus            `json:"nat_rule_counters,omitempty"`
	FilterTermCounters        []FirewallFilterTermCounterStatus `json:"filter_term_counters,omitempty"`
	ThreeColorPolicerCounters []ThreeColorPolicerStatus         `json:"three_color_policer_counters,omitempty"`
	SourceNATPools            []SourceNATPoolStatus             `json:"source_nat_pools,omitempty"`
	LastResolution            *PacketResolution                 `json:"last_resolution,omitempty"`
	SlowPath                  SlowPathStatus                    `json:"slow_path,omitempty"`
	LastCacheFlushAt          uint64                            `json:"last_cache_flush_at,omitempty"`    // monotonic secs (#312)
	DataplaneMode             string                            `json:"dataplane_mode,omitempty"`         // Current active mode: "ebpf_only", "userspace_compat", "userspace_strict"
	ConfiguredMode            string                            `json:"configured_mode,omitempty"`        // Desired mode from config
	EntryPrograms             map[int]string                    `json:"entry_programs,omitempty"`         // ifindex -> attached XDP program name
	DegradedPathCounters      map[string]uint64                 `json:"degraded_path_counters,omitempty"` // reason_name -> count
	// #1636 option C: proactive-neighbor-warm telemetry. WarmDrops counts
	// warm requests dropped because the bounded warmer queue was full
	// (transient); WarmDisconnected counts requests dropped because the
	// warmer worker thread died (fatal — warming disabled until restart).
	NeighborWarmDropsTotal        uint64 `json:"neighbor_warm_drops_total,omitempty"`
	NeighborWarmDisconnectedTotal uint64 `json:"neighbor_warm_disconnected_total,omitempty"`
	// #1782 cold-start capture instrumentation. NegNeighFastFailTotal is
	// the per-binding-summed count of neg-neigh-cache fast-fails (the H1
	// amplifier signal); PendingNeighDuplicateDropsTotal is the count of
	// pending_neigh sibling drops where the (egress_ifindex, next_hop)
	// key was already pending (the H5 sibling-drop signal).
	// DynamicNeighborKeys is a debug dump of every key in the helper's
	// dynamic_neighbors mirror ("ifindex ip"), surfaced as the per-key
	// xpf_userspace_dynamic_neighbor_present gauge so the capture harness
	// can confirm the t0' next-hop miss (the H2 fingerprint). It is gated
	// behind the helper's XPF_DEBUG_NEIGHBOR_KEYS env var and is empty by
	// default — an empty slice (and an absent gauge family) does NOT mean
	// the mirror is empty, only that the debug dump was not enabled. All
	// are omitempty for wire-compat with older helpers.
	NegNeighFastFailTotal           uint64 `json:"neg_neigh_fast_fail_total,omitempty"`
	PendingNeighDuplicateDropsTotal uint64 `json:"pending_neigh_duplicate_drops_total,omitempty"`
	// #1902: GRE-decapped MissingNeighbor packets refused pending_neigh
	// admission — buffering the outer UMEM frame with the post-decap
	// inner meta would retry-TX a mis-rewritten outer packet once the
	// neighbor resolves.
	PendingNeighDecapDropsTotal uint64   `json:"pending_neigh_decap_drops_total,omitempty"`
	DynamicNeighborKeys         []string `json:"dynamic_neighbor_keys,omitempty"`
	// #1789: total failed USERSPACE_SESSIONS BPF-map publishes (per-binding
	// worker-poll sites summed with the shared no-binding sites: HA upsert,
	// session-glue worker publish, post-reconcile replay, activation/reverse
	// prewarm). A failed publish means the XDP shim never learns the session
	// key and takes the NO_SESSION degraded path (drop in STRICT mode), so a
	// rising value is the cause-side signal for rising shim no-session
	// fallbacks (session map at capacity, stale fd after reconcile). Surfaced
	// as xpf_userspace_session_publish_errors_total. Omitempty for wire
	// compat with older helpers.
	SessionPublishErrorsTotal uint64 `json:"session_publish_errors_total,omitempty"`
	// DnatPublishErrorsTotal counts failed dnat_table reverse-SNAT BPF-map
	// publishes across userspace workers (#2244). The dnat_table is the
	// reverse lookup the embedded-ICMP NAT path consults to map an inbound
	// ICMP error (PMTUD Packet Too Big / Time Exceeded / traceroute) back
	// to the original pre-NAT source; a failed publish (map at capacity,
	// EINVAL) silently omits the record so the error is dropped or
	// mis-delivered. A rising value is the cause-side signal for dnat_table
	// map-capacity pressure. Surfaced as
	// xpf_userspace_dnat_publish_errors_total. Omitempty for wire compat
	// with older helpers.
	DnatPublishErrorsTotal uint64 `json:"dnat_publish_errors_total,omitempty"`
	// #1760 W3': shared-map NAT reverse-key displacement events — a
	// publish_shared_session insert into shared_nat_sessions displaced a
	// DIFFERENT forward session's entry at the same reverse key (two live
	// forward NAT sessions mapping onto one reply tuple — the #1758/#1760
	// latent 1:N collision). The shared map is the single choke point all
	// transit forward NAT sessions pass through, including
	// MissingNeighborSeed installs the per-worker
	// nat_reverse_key_collisions counter cannot see. Event count, not a
	// pair census. Surfaced as
	// xpf_userspace_session_nat_reverse_key_shared_displacements_total.
	// Omitempty for wire compat with older helpers.
	NatReverseKeySharedDisplacementsTotal uint64 `json:"nat_reverse_key_shared_displacements_total,omitempty"`
	// #1807: total worker-command-queue poison recoveries (a helper
	// thread panicked while holding a worker command mutex; the
	// committed queue was recovered and the poison cleared — uniform
	// policy in afxdp/worker_queue.rs, extends #1790). Nonzero means a
	// worker panic happened and the command queues kept flowing instead
	// of going permanently deaf. Surfaced as
	// xpf_userspace_worker_command_queue_poison_recoveries_total.
	// Omitempty-free on the Rust side (always serialized); plain decode
	// here defaults to 0 for older helpers.
	WorkerCommandQueuePoisonRecoveries uint64 `json:"worker_command_queue_poison_recoveries,omitempty"`
	// #2315: GRE-decap frames dropped by the RFC 6040 §4.2 decap-side ECN
	// combine because the outer header carried a CE mark over an inner
	// packet that was Not-ECT (the illegal combination — a congested
	// router CE-marked a packet whose endpoints never negotiated ECN).
	// RFC 6040 mandates a drop here rather than silently clearing the
	// bogus CE. Surfaced as
	// xpf_userspace_gre_decap_ecn_illegal_drops_total. Omitempty for wire
	// compat with older helpers (defaults to 0).
	GreDecapEcnIllegalDropsTotal uint64 `json:"gre_decap_ecn_illegal_drops_total,omitempty"`
	// #2317: WireGuard-decap inner packets dropped by the SAME RFC 6040
	// §4.2 decap-side ECN combine, for the WG path. The WG decap site
	// captures the outer ECN out-of-band via recvmsg + IP_RECVTOS /
	// IPV6_RECVTCLASS (the kernel UDP socket strips the outer IP header
	// before userspace) and feeds it into the same combine. Surfaced as
	// xpf_userspace_wg_decap_ecn_illegal_drops_total. Omitempty for wire
	// compat with older helpers (defaults to 0).
	WgDecapEcnIllegalDropsTotal uint64 `json:"wg_decap_ecn_illegal_drops_total,omitempty"`
	// #2331: native-GRE encap frames dropped because the fully built outer
	// datagram (outer IP + GRE[+key] + inner) exceeded the resolved
	// transport/egress MTU while the IPv4 outer carries DF=1 (the only
	// outer the native encap builder emits). A DF-set oversized outer
	// cannot be fragmented downstream and would silently blackhole every
	// inner flow with no PMTUD signal — so the builder refuses to emit it.
	// Surfaced as xpf_userspace_gre_encap_df_oversize_drops_total. PMTUD /
	// PTB signalling is deferred to #2330. Omitempty for wire compat with
	// older helpers (defaults to 0).
	GreEncapDfOversizeDropsTotal uint64 `json:"gre_encap_df_oversize_drops_total,omitempty"`
	// #1769: on-demand neighbor-resolver telemetry. The resolver fires
	// when a MissingNeighbor negative-cache fast-fail nudges a wedged dst
	// (single-key RTM_GETNEIGH + epoch-guarded cache or probe-on-stale).
	// QueueDepth is a live gauge; the rest are monotonic counters. These
	// are the operator-visible signal for the #1769 stuck-state.
	NeighborResolverQueueDepth        uint64 `json:"neighbor_resolver_queue_depth,omitempty"`
	NeighborResolverEnqueueDropsTotal uint64 `json:"neighbor_resolver_enqueue_drops_total,omitempty"`
	NeighborResolverDisconnectedTotal uint64 `json:"neighbor_resolver_disconnected_total,omitempty"`
	NeighborResolverGetAttemptsTotal  uint64 `json:"neighbor_resolver_get_attempts_total,omitempty"`
	NeighborResolverGetResolvedTotal  uint64 `json:"neighbor_resolver_get_resolved_total,omitempty"`
	NeighborResolverProbeOnStaleTotal uint64 `json:"neighbor_resolver_probe_on_stale_total,omitempty"`
	NeighborResolverGetFailuresTotal  uint64 `json:"neighbor_resolver_get_failures_total,omitempty"`
	NeighborResolverEpochRejectsTotal uint64 `json:"neighbor_resolver_epoch_rejects_total,omitempty"`
	// #1772: neighbor/ARP resolution LATENCY telemetry. Complements the
	// #1769 count-only resolver telemetry above with TIMING so the
	// intermittent slow-new-connection symptom is visible. The bucket
	// slices are NON-cumulative per-bucket sample counts on a 16-bucket
	// pow2-ns ladder (bucket i upper bound 2^(16+i) ns; bucket 15 = +Inf;
	// the 3 s blackout class lands in bucket 15).
	NeighborPendingDwellBuckets      []uint64 `json:"neighbor_pending_dwell_buckets,omitempty"`
	NeighborPendingDwellSumNs        uint64   `json:"neighbor_pending_dwell_sum_ns,omitempty"`
	NeighborPendingDwellCount        uint64   `json:"neighbor_pending_dwell_count,omitempty"`
	NeighborResolverGetRttBuckets    []uint64 `json:"neighbor_resolver_get_rtt_buckets,omitempty"`
	NeighborResolverGetRttSumNs      uint64   `json:"neighbor_resolver_get_rtt_sum_ns,omitempty"`
	NeighborResolverGetRttCount      uint64   `json:"neighbor_resolver_get_rtt_count,omitempty"`
	NeighborPendingTimeoutDropsTotal uint64   `json:"neighbor_pending_timeout_drops_total,omitempty"`
	NeighborPendingMaxDepth          uint64   `json:"neighbor_pending_max_depth,omitempty"`
	// #1771 §2.6: per-key resolver + §2.5 ENOBUFS-re-dump telemetry.
	// GetBackoffAttempts is the subset of resolver GET attempts that were
	// backoff RETRIES (key re-admitted after the per-key rate-limit
	// window) — invariant N1 (§2.4): these keep firing while a key is
	// negatively cached. The Netlink* counters instrument the monitor
	// thread's lost-notification self-heal: ENOBUFS receives, throttled
	// upsert-only re-dumps issued, and entries actually (re)added by
	// re-dump replies. PendingKeys / NegNeighKeys are gauges summed over
	// the per-binding ~65ms debug-tick snapshots: distinct unresolved
	// next-hop keys buffered in pending_neigh, and keys held in the
	// negative caches (lazy-TTL upper bound). All decode to 0 for older
	// helpers (keys absent).
	NeighborResolverGetBackoffAttemptsTotal uint64 `json:"neighbor_resolver_get_backoff_attempts_total,omitempty"`
	NeighborNetlinkEnobufsTotal             uint64 `json:"neighbor_netlink_enobufs_total,omitempty"`
	NeighborNetlinkRedumpsTotal             uint64 `json:"neighbor_netlink_redumps_total,omitempty"`
	NeighborNetlinkRedumpUpsertsTotal       uint64 `json:"neighbor_netlink_redump_upserts_total,omitempty"`
	NeighborPendingKeys                     uint64 `json:"neighbor_pending_keys,omitempty"`
	NegNeighKeys                            uint64 `json:"neg_neigh_keys,omitempty"`
	// WgTunnels carries the #1865 per-WG-tunnel telemetry rows. Keyed
	// by tunnel NAME (Tunnel) — TunnelEndpointID is informational only
	// (#1873: positional ids renumber across commits). Absent/empty for
	// non-WG deployments and for older helpers (key omitted on the
	// Rust side when no tunnel is configured).
	WgTunnels []WgTunnelStatus `json:"wg_tunnels,omitempty"`
}

// WgPeerStatus mirrors the Rust WgPeerStatus in
// userspace-dp/src/protocol/control.rs (#1434 multi-peer) — keep json
// tags identical on BOTH sides.
type WgPeerStatus struct {
	// PeerPubkeyHex is the peer static public key, 64-char lowercase hex
	// (same rendering as the config-side wg_peer_pubkey_hex; note
	// `wg show` renders base64 — xpf surfaces are uniformly hex).
	PeerPubkeyHex string `json:"peer_pubkey_hex,omitempty"`
	// PeerEndpoint is the configured-or-learned endpoint (empty for a
	// responder-only peer with no learned endpoint yet).
	PeerEndpoint string `json:"peer_endpoint,omitempty"`
	// SessionConfirmed is whether this peer holds a confirmed
	// (egress-usable) transport session.
	SessionConfirmed bool `json:"session_confirmed,omitempty"`
}

// WgTunnelStatus mirrors the Rust WgTunnelStatus in
// userspace-dp/src/protocol/control.rs — keep json tags identical on
// BOTH sides (feedback_wire_protocol_both_sides). Counter semantics
// and the reset rules live in userspace-dp/src/afxdp/wg/counters.rs;
// the Prometheus emitters are in pkg/api/metrics_userspace.go.
type WgTunnelStatus struct {
	// Tunnel is the interface name (e.g. "wg0") — the PRIMARY key and
	// the only Prometheus label. Helper falls back to
	// "wg-endpoint-<id>" when the ifindex has no resolved name.
	Tunnel           string `json:"tunnel,omitempty"`
	TunnelEndpointID uint16 `json:"tunnel_endpoint_id,omitempty"`
	ListenPort       uint16 `json:"listen_port,omitempty"`
	// LocalPubkeyHex is OUR local static public key, 64-char lowercase
	// hex (#1434 Increment 1) — the key an operator hands to the peer.
	// Derived once by the helper from the local private key at engine
	// construction; the snapshot redacts the private key, so this is the
	// only surface for it. Travels as a hex STRING (not []byte, to dodge
	// the Go↔Rust base64 wire trap, MEMORY #1961); `show security
	// wireguard public-key` re-renders it as WireGuard-canonical base64.
	// omitempty keeps a pre-#1434 helper payload (field absent) decoding
	// to "".
	LocalPubkeyHex string `json:"local_pubkey_hex,omitempty"`
	// Peers carries the per-peer rows (#1434 multi-peer): pubkey,
	// endpoint, and confirmed-session per configured peer. Replaces the
	// scalar PeerPubkeyHex/PeerEndpoint/SessionConfirmed. The counters
	// below remain tunnel-level (per-engine).
	Peers []WgPeerStatus `json:"peers,omitempty"`
	// LastHandshakeUnixSecs is wall-clock epoch seconds of the most
	// recent handshake completion (either role); 0 = never (epoch 0 is
	// unreachable, so the in-band sentinel is unambiguous).
	LastHandshakeUnixSecs uint64 `json:"last_handshake_unix_secs,omitempty"`

	HsInitiationsCreated      uint64 `json:"hs_initiations_created,omitempty"`
	HsInitiationBuildFailures uint64 `json:"hs_initiation_build_failures,omitempty"`
	HsResponsesCreated        uint64 `json:"hs_responses_created,omitempty"`
	HsCompletionsInitiator    uint64 `json:"hs_completions_initiator,omitempty"`
	HsRxDropsMac1Mismatch     uint64 `json:"hs_rx_drops_mac1_mismatch,omitempty"`
	HsRxDropsMalformed        uint64 `json:"hs_rx_drops_malformed,omitempty"`
	HsRxDropsCrypto           uint64 `json:"hs_rx_drops_crypto,omitempty"`
	HsRxDropsUnknownPeer      uint64 `json:"hs_rx_drops_unknown_peer,omitempty"`
	HsRxDropsStaleResponse    uint64 `json:"hs_rx_drops_stale_response,omitempty"`
	HsRxDropsIndexExhausted   uint64 `json:"hs_rx_drops_index_exhausted,omitempty"`
	HsRxCookieUnsupported     uint64 `json:"hs_rx_cookie_unsupported,omitempty"`
	RxUnknownType             uint64 `json:"rx_unknown_type,omitempty"`
	HsSendErrors              uint64 `json:"hs_send_errors,omitempty"`
	HsRequestsArmed           uint64 `json:"hs_requests_armed,omitempty"`

	DecapPackets              uint64 `json:"decap_packets,omitempty"`
	DecapBytes                uint64 `json:"decap_bytes,omitempty"`
	DecapKeepalives           uint64 `json:"decap_keepalives,omitempty"`
	DecapDropsMalformedHeader uint64 `json:"decap_drops_malformed_header,omitempty"`
	DecapDropsUnknownSession  uint64 `json:"decap_drops_unknown_session,omitempty"`
	DecapDropsCounterCeiling  uint64 `json:"decap_drops_counter_ceiling,omitempty"`
	DecapDropsCrypto          uint64 `json:"decap_drops_crypto,omitempty"`
	DecapDropsReplay          uint64 `json:"decap_drops_replay,omitempty"`
	DecapDropsAllowedIPs      uint64 `json:"decap_drops_allowed_ips,omitempty"`
	DecapDropsMalformedInner  uint64 `json:"decap_drops_malformed_inner,omitempty"`
	DecapDropsBuffer          uint64 `json:"decap_drops_buffer,omitempty"`

	EncapPackets            uint64 `json:"encap_packets,omitempty"`
	EncapBytes              uint64 `json:"encap_bytes,omitempty"`
	EncapDropsNoSession     uint64 `json:"encap_drops_no_session,omitempty"`
	EncapDropsUnconfirmed   uint64 `json:"encap_drops_unconfirmed,omitempty"`
	EncapDropsRekeyRequired uint64 `json:"encap_drops_rekey_required,omitempty"`
	EncapDropsOther         uint64 `json:"encap_drops_other,omitempty"`
	EncapMtuDrops           uint64 `json:"encap_mtu_drops,omitempty"`
	TransportSendErrors     uint64 `json:"transport_send_errors,omitempty"`
	TunWriteErrors          uint64 `json:"tun_write_errors,omitempty"`
	TunRxDropsNoEndpoint    uint64 `json:"tun_rx_drops_no_endpoint,omitempty"`

	// #1888 S5 timer telemetry (wire-additive; zero on pre-S5 helpers).
	EncapDropsExpired                 uint64 `json:"encap_drops_expired,omitempty"`
	DecapDropsExpired                 uint64 `json:"decap_drops_expired,omitempty"`
	SessionsExpired                   uint64 `json:"sessions_expired,omitempty"`
	RekeysInitiatedAge                uint64 `json:"rekeys_initiated_age,omitempty"`
	RekeysInitiatedDeadPeer           uint64 `json:"rekeys_initiated_dead_peer,omitempty"`
	RekeysInitiatedKeepaliveNoSession uint64 `json:"rekeys_initiated_keepalive_no_session,omitempty"`
	KeepalivesTxPassive               uint64 `json:"keepalives_tx_passive,omitempty"`
	KeepalivesTxPersistent            uint64 `json:"keepalives_tx_persistent,omitempty"`
	PendingAbortedAttemptWindow       uint64 `json:"pending_aborted_attempt_window,omitempty"`
}

// MarshalJSON intentionally uses a value receiver so both ProcessStatus values
// and *ProcessStatus pointers emit the temporary legacy alias during the
// rolling-upgrade window.
func (s ProcessStatus) MarshalJSON() ([]byte, error) {
	type processStatusAlias ProcessStatus
	aux := struct {
		*processStatusAlias
		LegacyFallbackCounters map[string]uint64 `json:"fallback_counters,omitempty"`
	}{
		processStatusAlias: (*processStatusAlias)(&s),
	}
	if len(s.DegradedPathCounters) > 0 {
		// encoding/json never mutates input maps, so sharing the map keeps the
		// legacy alias byte-for-byte consistent with the primary field.
		aux.LegacyFallbackCounters = s.DegradedPathCounters
	}
	return json.Marshal(aux)
}

func (s *ProcessStatus) UnmarshalJSON(data []byte) error {
	type processStatusAlias ProcessStatus
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var aux processStatusAlias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*s = ProcessStatus(aux)
	if _, ok := raw["degraded_path_counters"]; ok {
		return nil
	}
	if legacyRaw, ok := raw["fallback_counters"]; ok {
		var legacy map[string]uint64
		if err := json.Unmarshal(legacyRaw, &legacy); err != nil {
			return err
		}
		s.DegradedPathCounters = legacy
	}
	return nil
}

type SourceNATPoolStatus struct {
	RuleName                         string `json:"rule_name,omitempty"`
	PoolName                         string `json:"pool_name,omitempty"`
	AddressCount                     int    `json:"address_count,omitempty"`
	PortLow                          uint16 `json:"port_low,omitempty"`
	PortHigh                         uint16 `json:"port_high,omitempty"`
	PersistentNAT                    bool   `json:"persistent_nat,omitempty"`
	PersistentNATPermitAnyRemoteHost bool   `json:"persistent_nat_permit_any_remote_host,omitempty"`
	PersistentNATInactivityTimeout   int    `json:"persistent_nat_inactivity_timeout,omitempty"`
	LiveFlows                        uint64 `json:"live_flows,omitempty"`
	UsedPorts                        uint64 `json:"used_ports,omitempty"`
	PersistentLeases                 uint64 `json:"persistent_leases,omitempty"`
	MaxTrackedFlows                  uint64 `json:"max_tracked_flows,omitempty"`
	AllocationsTotal                 uint64 `json:"allocations_total,omitempty"`
	ReusesTotal                      uint64 `json:"reuses_total,omitempty"`
	ExhaustionTotal                  uint64 `json:"exhaustion_total,omitempty"`
}

type EventStreamStatus struct {
	FramesRead        uint64 `json:"frames_read,omitempty"`
	FramesWritten     uint64 `json:"frames_written,omitempty"`
	DecodeErrors      uint64 `json:"decode_errors,omitempty"`
	SeqGaps           uint64 `json:"seq_gaps,omitempty"`
	PolicyDenyEvents  uint64 `json:"policy_deny_events,omitempty"`
	ScreenDropEvents  uint64 `json:"screen_drop_events,omitempty"`
	ScreenAlarmEvents uint64 `json:"screen_alarm_events,omitempty"`
	FilterLogEvents   uint64 `json:"filter_log_events,omitempty"`
	PolicyDenyDrops   uint64 `json:"policy_deny_drops,omitempty"`
	ScreenDropDrops   uint64 `json:"screen_drop_drops,omitempty"`
	FilterLogDrops    uint64 `json:"filter_log_drops,omitempty"`
	UnknownFrameDrops uint64 `json:"unknown_frame_drops,omitempty"`
}

type CoSInterfaceStatus struct {
	Ifindex             int     `json:"ifindex,omitempty"`
	InterfaceName       string  `json:"interface_name,omitempty"`
	OwnerWorkerID       *uint32 `json:"owner_worker_id,omitempty"`
	ShapingRateBytes    uint64  `json:"shaping_rate_bytes,omitempty"`
	BurstBytes          uint64  `json:"burst_bytes,omitempty"`
	WorkerInstances     int     `json:"worker_instances,omitempty"`
	NonemptyQueues      int     `json:"nonempty_queues,omitempty"`
	RunnableQueues      int     `json:"runnable_queues,omitempty"`
	TimerLevel0Sleepers int     `json:"timer_level0_sleepers,omitempty"`
	TimerLevel1Sleepers int     `json:"timer_level1_sleepers,omitempty"`
	// #1628: per-interface waterfill-selector trace counters. JSON tags
	// MUST match the Rust serde rename(...) byte-for-byte (protocol/cos.rs).
	// WaterfillEpochs / WaterfillPhase1BudgetBreaks are SUMMED across
	// workers. WaterfillMinEpochsPerWorker is the coordinator MIN of each
	// worker's per-binding MIN over bindings with active exact-guarantee
	// backlog; a LOW value vs Epochs flags a single stalled selector, and
	// 0 is a HARD lock-in (backlogged binding, zero epochs completed).
	// math.MaxUint64 is the "no active-backlog candidate" (idle) sentinel,
	// preserved through aggregation so it never collides with a real 0;
	// Prometheus suppresses the MAX gauge and the CLI renders it "none".
	WaterfillEpochs             uint64           `json:"waterfill_epochs,omitempty"`
	WaterfillPhase1BudgetBreaks uint64           `json:"waterfill_phase1_budget_breaks,omitempty"`
	WaterfillMinEpochsPerWorker uint64           `json:"waterfill_min_epochs_per_worker,omitempty"`
	Queues                      []CoSQueueStatus `json:"queues,omitempty"`
}

type ThreeColorPolicerStatus struct {
	ID            uint32 `json:"id,omitempty"`
	Name          string `json:"name,omitempty"`
	Mode          string `json:"mode,omitempty"`
	ColorBlind    bool   `json:"color_blind,omitempty"`
	GreenPackets  uint64 `json:"green_packets,omitempty"`
	GreenBytes    uint64 `json:"green_bytes,omitempty"`
	YellowPackets uint64 `json:"yellow_packets,omitempty"`
	YellowBytes   uint64 `json:"yellow_bytes,omitempty"`
	RedPackets    uint64 `json:"red_packets,omitempty"`
	RedBytes      uint64 `json:"red_bytes,omitempty"`
	DropPackets   uint64 `json:"drop_packets,omitempty"`
	DropBytes     uint64 `json:"drop_bytes,omitempty"`
}

type CoSQueueStatus struct {
	QueueID           int     `json:"queue_id,omitempty"`
	OwnerWorkerID     *uint32 `json:"owner_worker_id,omitempty"`
	ForwardingClass   string  `json:"forwarding_class,omitempty"`
	Priority          int     `json:"priority,omitempty"`
	Exact             bool    `json:"exact,omitempty"`
	GuaranteeEnabled  *bool   `json:"guarantee_enabled,omitempty"`
	TransmitRateBytes uint64  `json:"transmit_rate_bytes,omitempty"`
	// BufferBytes is total queue capacity for this status row. Rust status
	// aggregation sums it with QueuedBytes across worker/binding instances.
	BufferBytes         uint64 `json:"buffer_bytes,omitempty"`
	WorkerInstances     int    `json:"worker_instances,omitempty"`
	QueuedPackets       uint64 `json:"queued_packets,omitempty"`
	QueuedBytes         uint64 `json:"queued_bytes,omitempty"`
	RunnableInstances   int    `json:"runnable_instances,omitempty"`
	ParkedInstances     int    `json:"parked_instances,omitempty"`
	NextWakeupTick      uint64 `json:"next_wakeup_tick,omitempty"`
	SurplusDeficitBytes uint64 `json:"surplus_deficit_bytes,omitempty"`
	// #710/#718: per-queue admission-path counters aggregated across
	// worker instances by the Rust coordinator. JSON tags MUST match the
	// Rust serde rename(...) exactly — the wire format is the contract.
	AdmissionFlowShareDrops uint64 `json:"admission_flow_share_drops,omitempty"`
	AdmissionBufferDrops    uint64 `json:"admission_buffer_drops,omitempty"`
	AdmissionEcnMarked      uint64 `json:"admission_ecn_marked,omitempty"`
	// #1642: shaper starvation / TX-ring-pressure diagnostics the Rust
	// helper serializes on CoSQueueStatus (protocol/cos.rs). These are
	// distinct from the DrainPark* fields below (which count drain-loop
	// parks). JSON tags MUST match Rust serde rename(...) exactly.
	RootTokenStarvationParks  uint64 `json:"root_token_starvation_parks,omitempty"`
	QueueTokenStarvationParks uint64 `json:"queue_token_starvation_parks,omitempty"`
	TxRingFullSubmitStalls    uint64 `json:"tx_ring_full_submit_stalls,omitempty"`
	// #1304: Rust-owned equal-flow enforcement telemetry. The
	// measurement-only xpf_fairness_equal_flow_* gauges remain advisory;
	// these fields describe the opt-in shared v8 queue-lease suppressor.
	EqualFlowEnforcement              bool   `json:"equal_flow_enforcement,omitempty"`
	EqualFlowEnforced                 bool   `json:"equal_flow_enforced,omitempty"`
	EqualFlowTargetPerFlowBPS         uint64 `json:"equal_flow_target_per_flow_bps,omitempty"`
	EqualFlowMaxWorkerCapBytes        uint64 `json:"equal_flow_max_worker_cap_bytes,omitempty"`
	EqualFlowCapHitEvents             uint64 `json:"equal_flow_cap_hit_events,omitempty"`
	EqualFlowSuppressedGrantBytes     uint64 `json:"equal_flow_suppressed_grant_bytes,omitempty"`
	EqualFlowStaleOrTagMismatchEvents uint64 `json:"equal_flow_stale_or_tag_mismatch_events,omitempty"`
	EqualFlowFailOpenReason           string `json:"equal_flow_fail_open_reason,omitempty"`
	// EqualFlowTargetPolicy (#1746): active target-policy label
	// ("slowest" | "mean" | "ideal-share"); populated only for
	// equal-flow leases, empty otherwise.
	EqualFlowTargetPolicy string `json:"equal_flow_target_policy,omitempty"`
	// #1863 Step-0: per-worker cumulative v8 queue-lease claim flow —
	// requested bytes (every acquire_v8 ask, granted or not) and
	// granted bytes, indexed by worker id. Empty for legacy/non-v8
	// leases. JSON tags MUST match the Rust serde rename(...) in
	// protocol/cos.rs byte-for-byte.
	LeaseV8WorkerRequestedBytes []uint64 `json:"lease_v8_worker_requested_bytes,omitempty"`
	LeaseV8WorkerGrantedBytes   []uint64 `json:"lease_v8_worker_granted_bytes,omitempty"`
	// #709 / #751: owner-profile telemetry. Populated only when an
	// exact queue can inherit a binding-scoped owner profile
	// unambiguously; zero for shared_exact, non-exact, and ambiguous
	// multi-owner-local shapes. See docs/709-owner-hotspot-plan.md for
	// the decision tree these counters drive. JSON tags MUST match Rust
	// serde rename(...) byte-for-byte.
	//
	// DrainLatencyHist and RedirectAcquireHist are power-of-two ns
	// bucketed (see Rust `bucket_index_for_ns`): index 0 is < 1 µs,
	// index N >= 1 is [2^(N+9), 2^(N+10)) ns, index 15 saturates at
	// >= 2^24 ns (~16 ms).
	ActiveFlowBucketsPeak uint64 `json:"active_flow_buckets_peak,omitempty"`
	FlowFair              bool   `json:"flow_fair,omitempty"`
	// #1830 (g): bucket-vs-flow occupancy telemetry. JSON tags MUST
	// match the Rust serde rename(...) in protocol/cos.rs exactly.
	// FlowFairBucketsOccupied is the instantaneous occupied
	// (backlogged) SFQ bucket count summed across workers;
	// FlowFairFlowsActive is the flow-cache active-window (~650 ms)
	// distinct-flow count mapped to this queue, summed across workers.
	// The flows/buckets ratio distinguishes hash-collision unfairness
	// (ratio persistently > 1 while continuously backlogged) from
	// demand unfairness — see the INTERPRETATION contract on the Rust
	// CoSQueueStatus.
	FlowFairBucketsOccupied uint64   `json:"flow_fair_buckets_occupied,omitempty"`
	FlowFairFlowsActive     uint64   `json:"flow_fair_flows_active,omitempty"`
	DrainLatencyHist        []uint64 `json:"drain_latency_hist,omitempty"`
	DrainInvocations        uint64   `json:"drain_invocations,omitempty"`
	DrainNoopInvocations    uint64   `json:"drain_noop_invocations,omitempty"`
	RedirectAcquireHist     []uint64 `json:"redirect_acquire_hist,omitempty"`
	OwnerPPS                uint64   `json:"owner_pps,omitempty"`
	PeerPPS                 uint64   `json:"peer_pps,omitempty"`
	// #760 overshoot-hunt instrumentation. DrainSentBytes /
	// DrainParkRootTokens / DrainParkQueueTokens are queue-scoped.
	// PostDrainBackupBytes is binding-scoped (same row as
	// OwnerPPS/PeerPPS). See Rust `CoSQueueStatus` for field
	// semantics and write-site locations.
	DrainSentBytes          uint64 `json:"drain_sent_bytes,omitempty"`
	DrainGuaranteeSentBytes uint64 `json:"drain_guarantee_sent_bytes,omitempty"`
	DrainSurplusSentBytes   uint64 `json:"drain_surplus_sent_bytes,omitempty"`
	// #1369: non-exact bytes sent while exact queue demand existed on
	// the same shaped interface. A rising delta means best-effort or
	// uncapped service was competing with exact queues.
	DrainNonExactSentBytesWhileExactBacklogged uint64 `json:"drain_nonexact_sent_bytes_while_exact_backlogged,omitempty"`
	DrainParkRootTokens                        uint64 `json:"drain_park_root_tokens,omitempty"`
	DrainParkQueueTokens                       uint64 `json:"drain_park_queue_tokens,omitempty"`
	PostDrainBackupBytes                       uint64 `json:"post_drain_backup_bytes,omitempty"`
	DrainSentBytesShapedUnconditional          uint64 `json:"drain_sent_bytes_shaped_unconditional,omitempty"`
	// #1628: per-class waterfill-selector trace counters, aggregated across
	// worker instances. Zero on the Proportional (legacy RR) path. JSON
	// tags MUST match Rust serde rename(...) byte-for-byte. These are
	// EVIDENCE to combine with QueuedBytes + *StarvationParks, not
	// standalone fingerprints (see Rust CoSQueueWaterfillCounters).
	WaterfillPhase1Admissions uint64 `json:"waterfill_phase1_admissions,omitempty"`
	WaterfillPhase2Admissions uint64 `json:"waterfill_phase2_admissions,omitempty"`
	WaterfillEligibleVisits   uint64 `json:"waterfill_eligible_visits,omitempty"`
	// #1829 Phase 1: dequeue-time sojourn telemetry. JSON tags MUST
	// match the Rust serde rename(...) in protocol/cos.rs exactly.
	// All three are MAX-merged across worker instances and across
	// workers (worst instance — see the AGGREGATION contract on the
	// Rust CoSQueueStatus). SojournWindowedMinNS is the #1829 gate
	// metric: the minimum sojourn over the last 1-2 100 ms windows
	// (CoDel's standing-queue estimator); it reads 0 when the queue
	// has not popped for >= 2 windows at snapshot time. SojournPeakNS
	// is the lifetime maximum; SojournEwmaNS is a shift-add EWMA
	// (alpha = 1/8) over pops — both supporting context only (biased
	// high by scheduler service gaps).
	SojournEwmaNS        uint64 `json:"sojourn_ewma_ns,omitempty"`
	SojournPeakNS        uint64 `json:"sojourn_peak_ns,omitempty"`
	SojournWindowedMinNS uint64 `json:"sojourn_windowed_min_ns,omitempty"`
	// #1642: post_drain_backup_cos_drops / _cos_drop_bytes were on this
	// struct, but the Rust helper serializes them on BindingStatus
	// (protocol/binding.rs), a different JSON nesting level. The Rust
	// binding-level values never decoded into CoSQueueStatus, so they were
	// silently dropped. They now live on BindingStatus to match the source.
	// (PostDrainBackupBytes above is correct here — Rust does serialize
	// post_drain_backup_bytes on CoSQueueStatus.)
}

type FirewallFilterTermCounterStatus struct {
	Family     string `json:"family,omitempty"`
	FilterName string `json:"filter_name,omitempty"`
	TermName   string `json:"term_name,omitempty"`
	Packets    uint64 `json:"packets,omitempty"`
	Bytes      uint64 `json:"bytes,omitempty"`
}

type PolicyRuleCounterStatus struct {
	RuleID  string `json:"rule_id,omitempty"`
	Packets uint64 `json:"packets,omitempty"`
	Bytes   uint64 `json:"bytes,omitempty"`
}

// NATRuleCounterStatus is one per-rule NAT translation hit counter reported
// by the userspace dataplane (#2218). CounterID is the compiler-assigned NAT
// rule counter ID (stable key-derived hash; matches CompileResult.NATCounterIDs
// and the CounterID stamped on the SNAT/DNAT/static rule snapshots, #2255).
// Packets/Bytes are cumulative since helper start (or last clear).
type NATRuleCounterStatus struct {
	CounterID uint32 `json:"counter_id,omitempty"`
	Packets   uint64 `json:"packets,omitempty"`
	Bytes     uint64 `json:"bytes,omitempty"`
}

type HAStateUpdateRequest struct {
	Groups []HAGroupStatus `json:"groups,omitempty"`
}

// #869: WorkerRuntimeStatus mirrors the Rust WorkerRuntimeStatus;
// each entry is one AF_XDP worker thread's cumulative runtime counters,
// refreshed on the worker's ~1s publish cadence.  All fields omit when
// zero so older daemons parse correctly.
type WorkerRuntimeStatus struct {
	WorkerID    uint32 `json:"worker_id,omitempty"`
	TID         uint64 `json:"tid,omitempty"`
	WallNS      uint64 `json:"wall_ns,omitempty"`
	ActiveNS    uint64 `json:"active_ns,omitempty"`
	IdleSpinNS  uint64 `json:"idle_spin_ns,omitempty"`
	IdleBlockNS uint64 `json:"idle_block_ns,omitempty"`
	ThreadCPUNS uint64 `json:"thread_cpu_ns,omitempty"`
	WorkLoops   uint64 `json:"work_loops,omitempty"`
	IdleLoops   uint64 `json:"idle_loops,omitempty"`
	// #1240: cumulative v8 per-worker queue-lease acquire calls and
	// granted bytes. Scrape with rate() and compare against per-worker
	// TX throughput to diagnose token-acquisition imbalance.
	CoSQueueLeaseAcquireV8Calls        uint64 `json:"cos_queue_lease_acquire_v8_calls,omitempty"`
	CoSQueueLeaseAcquireV8GrantedBytes uint64 `json:"cos_queue_lease_acquire_v8_granted_bytes,omitempty"`
	// #1782 Step-1 (plan §5.2 mechanism (i)): cumulative CoS timer-wheel
	// ticks advanced by advance_cos_timer_wheel across this worker's
	// bindings, plus the largest single-call advance ever observed (a
	// monotonic high-water mark). One cold drain catching up a
	// multi-minute per-worker idle lag appears as a single
	// multi-million-tick max sample. omitempty for mixed-version
	// back-compat with pre-Step-1 helpers.
	CoSWheelTicksAdvancedTotal uint64 `json:"cos_wheel_ticks_advanced_total,omitempty"`
	CoSWheelTicksAdvancedMax   uint64 `json:"cos_wheel_ticks_advanced_max,omitempty"`
	// #1782 Step-1 (plan §5.2 mechanism (ii)): per-cause v8 queue-lease
	// under-grant attribution, counted at the CoS exact-guarantee
	// selector sites when the post-top-up queue tokens still cannot
	// cover the head frame. A v8-attributed subset of the per-queue
	// drain_park_queue_tokens counter. Surfaced as the single
	// xpf_userspace_worker_cos_queue_lease_undergrant_total family with
	// a cause label.
	CoSQueueLeaseUndergrantSeqlockGiveUp  uint64 `json:"cos_queue_lease_undergrant_seqlock_give_up,omitempty"`
	CoSQueueLeaseUndergrantCapZero        uint64 `json:"cos_queue_lease_undergrant_cap_zero,omitempty"`
	CoSQueueLeaseUndergrantEpochRotated   uint64 `json:"cos_queue_lease_undergrant_epoch_rotated,omitempty"`
	CoSQueueLeaseUndergrantShareExhausted uint64 `json:"cos_queue_lease_undergrant_share_exhausted,omitempty"`
	CoSQueueLeaseUndergrantClassCap       uint64 `json:"cos_queue_lease_undergrant_class_cap,omitempty"`
	CoSQueueLeaseUndergrantOutstandingCap uint64 `json:"cos_queue_lease_undergrant_outstanding_cap,omitempty"`
	SessionTableEntries                   uint64 `json:"session_table_entries,omitempty"`
	MaxSessions                           uint64 `json:"max_sessions,omitempty"`
	// #1760: cumulative NAT reverse-key displacement events on this
	// worker's SessionTable nat_reverse_index (#1758). omitempty for
	// mixed-version back-compat.
	NatReverseKeyCollisions uint64 `json:"nat_reverse_key_collisions,omitempty"`
	// #1861: per-worker install-refusal trio (see the ProcessStatus
	// aggregate fields for semantics). omitempty for back-compat.
	SessionCreateDrops             uint64 `json:"session_create_drops,omitempty"`
	SessionInstallAdmissionRefused uint64 `json:"session_install_admission_refused,omitempty"`
	SessionInstallPartial          uint64 `json:"session_install_partial,omitempty"`
	// #925 Phase 1+2 (catch+report+observe): Dead == true means the
	// worker_loop panicked and the supervisor caught it. Set-only
	// today — cleared only by daemon restart. Phase 2 surfaces this
	// on Prometheus as `xpf_userspace_worker_dead` (this PR). A
	// hypothetical Phase 3 (respawn, deferred indefinitely) would
	// clear this by replacing WorkerRuntimeAtomics on relaunch.
	// PanicMessage holds the rendered payload for operator diagnosis.
	Dead         bool   `json:"dead,omitempty"`
	PanicMessage string `json:"panic_message,omitempty"`
	// Rolling last-window delta for CPU/wall/active counters. Under
	// the normal ~1 Hz worker publish cadence the rotated window is
	// ~60-61s wide (one publish-tick of overshoot past the 60s
	// threshold); a stalled publisher can widen it further. WindowNS
	// carries the exact measured width so consumers should always
	// divide by it rather than assuming a fixed denominator. All
	// zero until ~60s after worker start.
	ThreadCPUNS60s uint64 `json:"thread_cpu_ns_60s,omitempty"`
	WallNS60s      uint64 `json:"wall_ns_60s,omitempty"`
	ActiveNS60s    uint64 `json:"active_ns_60s,omitempty"`
	WindowNS       uint64 `json:"window_ns,omitempty"`

	// === #1635 cold-path histogram surface (sparse v3) ===
	//
	// Mirrors the Rust WorkerRuntimeStatus cold_path_* fields. All
	// slice fields use omitempty so an empty histogram (older Rust
	// daemon, or a worker with no samples this window) omits the field
	// from the wire; the Go emitter skips on empty. Per
	// feedback_wire_protocol_both_sides.
	//
	// #1635 replaces the v1 dense [16-slot] arrays with a SPARSE
	// active-slot encoding: parallel arrays, one entry per active
	// (from_zone, to_zone) pair. ColdPathLayoutVersion selects the
	// emission path (0/absent = no data / pre-#1635; 3 = sparse).
	//
	// Aggregated PER WORKER: when a worker owns multiple bindings, the
	// published values reflect the cross-binding merge performed at the
	// publish tick (sum for histogram data, OR for builder_collision).
	ColdPathLayoutVersion uint32 `json:"cold_path_layout_version,omitempty"`
	// Legacy v1 dense fields, retained READ-ONLY so a new Go collector
	// still emits correct v1 metrics when paired with a pre-#1635 Rust
	// daemon (plan §3.2 row "v1 Rust / v3 Go"). Current daemons leave
	// these empty. Per feedback_wire_protocol_both_sides.
	ColdPathHist      [][]uint64 `json:"cold_path_hist,omitempty"`
	ColdPathSumNS     []uint64   `json:"cold_path_sum_ns,omitempty"`
	ColdPathSamples   []uint64   `json:"cold_path_samples,omitempty"`
	ColdPathFirstKey  []uint64   `json:"cold_path_first_key,omitempty"`
	ColdPathAliasSeen []bool     `json:"cold_path_alias_seen,omitempty"`
	// Parallel sparse arrays (index i describes one active zone-pair).
	ColdPathActiveSlotIDs          []uint32   `json:"cold_path_active_slot_ids,omitempty"`
	ColdPathActiveZoneFrom         []uint32   `json:"cold_path_active_zone_from,omitempty"`
	ColdPathActiveZoneTo           []uint32   `json:"cold_path_active_zone_to,omitempty"`
	ColdPathActiveSamples          []uint64   `json:"cold_path_active_samples,omitempty"`
	ColdPathActiveSumNS            []uint64   `json:"cold_path_active_sum_ns,omitempty"`
	ColdPathActiveBuckets          [][]uint64 `json:"cold_path_active_buckets,omitempty"`
	ColdPathActiveBuilderCollision []bool     `json:"cold_path_active_builder_collision,omitempty"`
	// True if a configured zone-pair could not be assigned a slot —
	// either the 255-slot capacity was exhausted OR the pair references
	// a zone-id outside the 0..=64 direct-table range.
	ColdPathOverflowActive        bool   `json:"cold_path_overflow_active,omitempty"`
	ColdPathSamplePhase           uint64 `json:"cold_path_sample_phase,omitempty"`
	ColdPathWrapperUnderflowCount uint64 `json:"cold_path_wrapper_underflow_count,omitempty"`
	ColdPathNSPerTSCQ32           uint64 `json:"cold_path_ns_per_tsc_q32,omitempty"`
	ColdPathWrapperNSBaseline     uint64 `json:"cold_path_wrapper_ns_baseline,omitempty"`
	// "tsc" / "clock_gettime" / "" (Unset). Harness gates Table
	// publication on == "tsc" for every worker.
	ColdPathClockSource string `json:"cold_path_clock_source,omitempty"`
	// #1621 plan v2: monotonic count of snapshot() calls at the
	// coordinator status path that exhausted their retry budget.
	// Surfaced as xpf_userspace_worker_cold_path_snapshot_failed_total.
	ColdPathSnapshotFailed uint64 `json:"cold_path_snapshot_failed,omitempty"`
}

type HAGroupStatus struct {
	RGID              int    `json:"rg_id"`
	Active            bool   `json:"active"`
	WatchdogTimestamp uint64 `json:"watchdog_timestamp,omitempty"`
	// #1642: lease-telemetry fields the Rust helper serializes on
	// HAGroupStatus (protocol/binding.rs). Observability only — the HA
	// failover *decision* is taken from BPF maps via mergeHAStateFromMaps,
	// not from these. JSON tags MUST match the Rust serde rename(...) exactly.
	ForwardingActive bool   `json:"forwarding_active,omitempty"`
	LeaseState       string `json:"lease_state,omitempty"`
	LeaseUntil       uint64 `json:"lease_until,omitempty"`
}

type SlowPathStatus struct {
	Active             bool   `json:"active"`
	DeviceName         string `json:"device_name,omitempty"`
	Mode               string `json:"mode,omitempty"`
	LastError          string `json:"last_error,omitempty"`
	QueuedPackets      uint64 `json:"queued_packets,omitempty"`
	InjectedPackets    uint64 `json:"injected_packets,omitempty"`
	InjectedBytes      uint64 `json:"injected_bytes,omitempty"`
	DroppedPackets     uint64 `json:"dropped_packets,omitempty"`
	DroppedBytes       uint64 `json:"dropped_bytes,omitempty"`
	RateLimitedPackets uint64 `json:"rate_limited_packets,omitempty"`
	QueueFullPackets   uint64 `json:"queue_full_packets,omitempty"`
	WriteErrors        uint64 `json:"write_errors,omitempty"`
}

type PacketResolution struct {
	Disposition    string `json:"disposition"`
	LocalIfindex   int    `json:"local_ifindex,omitempty"`
	EgressIfindex  int    `json:"egress_ifindex,omitempty"`
	IngressIfindex int    `json:"ingress_ifindex,omitempty"`
	NextHop        string `json:"next_hop,omitempty"`
	NeighborMAC    string `json:"neighbor_mac,omitempty"`
	SrcIP          string `json:"src_ip,omitempty"`
	DstIP          string `json:"dst_ip,omitempty"`
	SrcPort        uint16 `json:"src_port,omitempty"`
	DstPort        uint16 `json:"dst_port,omitempty"`
	FromZone       string `json:"from_zone,omitempty"`
	ToZone         string `json:"to_zone,omitempty"`
}

type FlowTupleStatus struct {
	AddrFamily uint8  `json:"addr_family,omitempty"`
	Protocol   uint8  `json:"protocol,omitempty"`
	SrcIP      string `json:"src_ip,omitempty"`
	DstIP      string `json:"dst_ip,omitempty"`
	SrcPort    uint16 `json:"src_port,omitempty"`
	DstPort    uint16 `json:"dst_port,omitempty"`
}

type FlowWorkerStatus struct {
	Slot                uint32          `json:"slot,omitempty"`
	QueueID             uint32          `json:"queue_id,omitempty"`
	WorkerID            uint32          `json:"worker_id,omitempty"`
	Interface           string          `json:"interface,omitempty"`
	Ifindex             int             `json:"ifindex,omitempty"`
	IngressIfindex      int             `json:"ingress_ifindex,omitempty"`
	EgressIfindex       int             `json:"egress_ifindex,omitempty"`
	TxIfindex           int             `json:"tx_ifindex,omitempty"`
	SessionKey          FlowTupleStatus `json:"session_key,omitempty"`
	ForwardWireKey      FlowTupleStatus `json:"forward_wire_key,omitempty"`
	ReverseCanonicalKey FlowTupleStatus `json:"reverse_canonical_key,omitempty"`
	CoSQueueID          *uint8          `json:"cos_queue_id,omitempty"`
	DSCPRewrite         *uint8          `json:"dscp_rewrite,omitempty"`
	AgeEpochs           uint16          `json:"age_epochs,omitempty"`
	ObservedBytes       uint64          `json:"observed_bytes,omitempty"`
}

type CoSActiveFlowCountStatus struct {
	Ifindex         int    `json:"ifindex,omitempty"`
	QueueID         uint8  `json:"queue_id,omitempty"`
	WorkerID        uint32 `json:"worker_id,omitempty"`
	ActiveFlowCount uint32 `json:"active_flow_count,omitempty"`
}

type ForwardingControlRequest struct {
	Armed bool `json:"armed"`
}

type QueueControlRequest struct {
	QueueID    uint32 `json:"queue_id"`
	Registered bool   `json:"registered"`
	Armed      bool   `json:"armed"`
}

type BindingControlRequest struct {
	Slot       uint32 `json:"slot"`
	Registered bool   `json:"registered"`
	Armed      bool   `json:"armed"`
}

type QueueStatus struct {
	QueueID    uint32    `json:"queue_id"`
	WorkerID   uint32    `json:"worker_id"`
	Interfaces []string  `json:"interfaces,omitempty"`
	Registered bool      `json:"registered"`
	Armed      bool      `json:"armed"`
	Ready      bool      `json:"ready"`
	LastChange time.Time `json:"last_change,omitempty"`
}

type BindingStatus struct {
	Slot                     uint32 `json:"slot"`
	QueueID                  uint32 `json:"queue_id"`
	WorkerID                 uint32 `json:"worker_id"`
	Interface                string `json:"interface,omitempty"`
	Ifindex                  int    `json:"ifindex,omitempty"`
	Registered               bool   `json:"registered"`
	Armed                    bool   `json:"armed"`
	Ready                    bool   `json:"ready"`
	Bound                    bool   `json:"bound"`
	XSKRegistered            bool   `json:"xsk_registered"`
	XSKBindMode              string `json:"xsk_bind_mode,omitempty"`
	ZeroCopy                 bool   `json:"zero_copy,omitempty"`
	SocketFD                 int    `json:"socket_fd,omitempty"`
	SharedUMEMMode           string `json:"shared_umem_mode,omitempty"`
	SharedUMEMGroup          string `json:"shared_umem_group,omitempty"`
	SharedUMEMSocketRole     string `json:"shared_umem_socket_role,omitempty"`
	SharedUMEMDisabledReason string `json:"shared_umem_disabled_reason,omitempty"`
	RXPackets                uint64 `json:"rx_packets,omitempty"`
	RXBytes                  uint64 `json:"rx_bytes,omitempty"`
	RXBatches                uint64 `json:"rx_batches,omitempty"`
	RXWakeups                uint64 `json:"rx_wakeups,omitempty"`
	MetadataPackets          uint64 `json:"metadata_packets,omitempty"`
	MetadataErrors           uint64 `json:"metadata_errors,omitempty"`
	ValidatedPackets         uint64 `json:"validated_packets,omitempty"`
	ValidatedBytes           uint64 `json:"validated_bytes,omitempty"`
	LocalDeliveryPackets     uint64 `json:"local_delivery_packets,omitempty"`
	ForwardCandidatePkts     uint64 `json:"forward_candidate_packets,omitempty"`
	RouteMissPackets         uint64 `json:"route_miss_packets,omitempty"`
	NeighborMissPackets      uint64 `json:"neighbor_miss_packets,omitempty"`
	DiscardRoutePackets      uint64 `json:"discard_route_packets,omitempty"`
	NextTablePackets         uint64 `json:"next_table_packets,omitempty"`
	ExceptionPackets         uint64 `json:"exception_packets,omitempty"`
	ConfigGenMismatches      uint64 `json:"config_gen_mismatches,omitempty"`
	FIBGenMismatches         uint64 `json:"fib_gen_mismatches,omitempty"`
	UnsupportedPackets       uint64 `json:"unsupported_packets,omitempty"`
	FlowCacheHits            uint64 `json:"flow_cache_hits,omitempty"`
	FlowCacheMisses          uint64 `json:"flow_cache_misses,omitempty"`
	FlowCacheEvictions       uint64 `json:"flow_cache_evictions,omitempty"`
	// #918: collision-driven subset of flow_cache_evictions (full-set
	// LRU displacement vs stale-on-lookup eviction). Acceptance gate
	// watches collision_evictions / hits under load.
	FlowCacheCollisionEvictions uint64 `json:"flow_cache_collision_evictions,omitempty"`
	// #1219: snapshot count of distinct active flows on this binding's
	// flow_cache, refreshed at the helper's ~65ms debug-state tick. The
	// fairness harness reads this via the xpf_userspace_binding_active_flow_count
	// Prometheus metric to compute {a_i} for the structural CoV gate
	// per docs/fairness-regimes.md.
	ActiveFlowCount uint32 `json:"active_flow_count,omitempty"`
	// FlowCacheCapacity is Rust-owned and helper-published; Go must not
	// duplicate the helper's private FLOW_CACHE_SIZE constant.
	FlowCacheCapacity uint32 `json:"flow_cache_capacity,omitempty"`
	// #941 Work item D / #943: V_min throttle counters. Hard-cap is
	// the escape-hatch firing when fairness brake (regular throttle)
	// has thrown V_MIN_CONSECUTIVE_SKIP_HARD_CAP back-to-back times.
	// Together: VMinThrottles = "fairness brake fired",
	// VMinThrottleHardCapOverrides = "brake too tight, escape hatch
	// rescued throughput". Ratio is the LAG_THRESHOLD diagnostic.
	VMinThrottleHardCapOverrides uint64 `json:"v_min_throttle_hard_cap_overrides,omitempty"`
	VMinThrottles                uint64 `json:"v_min_throttles,omitempty"`
	SessionHits                  uint64 `json:"session_hits,omitempty"`
	SessionMisses                uint64 `json:"session_misses,omitempty"`
	SessionCreates               uint64 `json:"session_creates,omitempty"`
	SessionExpires               uint64 `json:"session_expires,omitempty"`
	SessionDeltaPending          uint64 `json:"session_delta_pending,omitempty"`
	SessionDeltaGenerated        uint64 `json:"session_delta_generated,omitempty"`
	SessionDeltaDropped          uint64 `json:"session_delta_dropped,omitempty"`
	SessionDeltaDrained          uint64 `json:"session_delta_drained,omitempty"`
	PolicyDeniedPackets          uint64 `json:"policy_denied_packets,omitempty"`
	ScreenDrops                  uint64 `json:"screen_drops,omitempty"`
	SYNCookieChallenges          uint64 `json:"syn_cookie_challenges,omitempty"`
	SYNCookieSecretUnavailable   uint64 `json:"syn_cookie_secret_unavailable,omitempty"`
	SYNCookieSynAckSent          uint64 `json:"syn_cookie_syn_ack_sent,omitempty"`
	SYNCookieAckRstSent          uint64 `json:"syn_cookie_ack_rst_sent,omitempty"`
	SYNCookieReplyBudgetDrops    uint64 `json:"syn_cookie_reply_budget_drops,omitempty"`
	SYNCookieAckValid            uint64 `json:"syn_cookie_ack_valid,omitempty"`
	SYNCookieAckInvalid          uint64 `json:"syn_cookie_ack_invalid,omitempty"`
	SYNCookieBypass              uint64 `json:"syn_cookie_bypass,omitempty"`
	// #2089: policy `reject` action — RST/ICMP-unreachable replies sent,
	// and replies suppressed due to TX-frame budget exhaustion.
	PolicyRejectSent             uint64 `json:"policy_reject_sent,omitempty"`
	PolicyRejectReplyBudgetDrops uint64 `json:"policy_reject_reply_budget_drops,omitempty"`
	// #2238: locally-generated replies (Time Exceeded, policy-reject
	// RST/ICMP-unreachable, SYN-cookie SYN-ACK/ACK-RST) are now classified by
	// their OWN egress 5-tuple + egress interface. An output firewall filter
	// terminal discard/reject (or three-color policer) on the egress
	// interface drops the reply; these per-leg counters make that
	// (operator-installed) drop attributable. GeneratedReplyClassifyParseErrors
	// counts fail-closed drops when the generated bytes could not be re-parsed
	// (§6.2). omitempty + Rust serde `default` keep cross-version wire safety.
	TimeExceededOutputFilterDrops     uint64 `json:"time_exceeded_output_filter_drops,omitempty"`
	PolicyRejectOutputFilterDrops     uint64 `json:"policy_reject_output_filter_drops,omitempty"`
	SYNCookieOutputFilterDrops        uint64 `json:"syn_cookie_output_filter_drops,omitempty"`
	GeneratedReplyClassifyParseErrors uint64 `json:"generated_reply_classify_parse_errors,omitempty"`
	SNATPackets                       uint64 `json:"snat_packets,omitempty"`
	DNATPackets                       uint64 `json:"dnat_packets,omitempty"`
	// #2161: NAT64 (v6<->v4) translations on this binding. omitempty +
	// the Rust serde `default` keep cross-version wire safety (#1961-class:
	// an older helper omits the field, Go reads 0 rather than failing decode).
	Nat64Translations uint64 `json:"nat64_translations,omitempty"`
	// #2291: fail-closed NAT64 drops — a prefix matched but no IPv4 source
	// could be allocated (empty/exhausted pool), so the synthetic IPv6
	// destination was dropped rather than route-looked-up as IPv6. omitempty +
	// Rust serde `default` keep the same cross-version wire safety.
	Nat64NoSourcePool              uint64 `json:"nat64_no_source_pool,omitempty"`
	SlowPathPackets                uint64 `json:"slow_path_packets,omitempty"`
	SlowPathBytes                  uint64 `json:"slow_path_bytes,omitempty"`
	SlowPathLocalDeliveryPackets   uint64 `json:"slow_path_local_delivery_packets,omitempty"`
	SlowPathMissingNeighborPackets uint64 `json:"slow_path_missing_neighbor_packets,omitempty"`
	SlowPathNoRoutePackets         uint64 `json:"slow_path_no_route_packets,omitempty"`
	SlowPathNextTablePackets       uint64 `json:"slow_path_next_table_packets,omitempty"`
	SlowPathForwardBuildPackets    uint64 `json:"slow_path_forward_build_packets,omitempty"`
	SlowPathDrops                  uint64 `json:"slow_path_drops,omitempty"`
	SlowPathRateLimited            uint64 `json:"slow_path_rate_limited,omitempty"`
	// TunnelEncapUnresolvedDrops counts tunnel-marked inner packets
	// dropped at the slow-path chokepoint / pending-neigh exclusion
	// instead of plaintext kernel reinjection (#1873 R-C/R-E).
	// Wire-additive: older helpers omit it.
	TunnelEncapUnresolvedDrops uint64 `json:"tunnel_encap_unresolved_drops,omitempty"`
	// FabricRedirectUnsendableDrops counts FabricRedirect frames dropped
	// fail-closed because they could not be TX'd to the HA peer (no
	// fabric XSK binding, or the forward-frame build/enqueue failed)
	// instead of being reinjected to the local kernel FIB (#1946).
	// Wire-additive: older helpers omit it.
	FabricRedirectUnsendableDrops     uint64 `json:"fabric_redirect_unsendable_drops,omitempty"`
	KernelRXDropped                   uint64 `json:"kernel_rx_dropped,omitempty"`
	KernelRXInvalidDescs              uint64 `json:"kernel_rx_invalid_descs,omitempty"`
	TXPackets                         uint64 `json:"tx_packets,omitempty"`
	TXBytes                           uint64 `json:"tx_bytes,omitempty"`
	TXErrors                          uint64 `json:"tx_errors,omitempty"`
	TXSharedRecycleUnknownSlotDrops   uint64 `json:"tx_shared_recycle_unknown_slot_drops,omitempty"`
	RedirectInboxOverflowDrops        uint64 `json:"redirect_inbox_overflow_drops,omitempty"`
	PendingTXLocalOverflowDrops       uint64 `json:"pending_tx_local_overflow_drops,omitempty"`
	TxSubmitErrorDrops                uint64 `json:"tx_submit_error_drops,omitempty"`
	TXCompletions                     uint64 `json:"tx_completions,omitempty"`
	MirroredPackets                   uint64 `json:"mirrored_packets,omitempty"`
	MirroredBytes                     uint64 `json:"mirrored_bytes,omitempty"`
	MirrorDropsNoFrame                uint64 `json:"mirror_drops_no_frame,omitempty"`
	MirrorDropsTXFrameReserve         uint64 `json:"mirror_drops_tx_frame_reserve,omitempty"`
	MirrorDropsNoBinding              uint64 `json:"mirror_drops_no_binding,omitempty"`
	MirrorDropsQueueFull              uint64 `json:"mirror_drops_queue_full,omitempty"`
	MirrorDropsQueueFullSameWorker    uint64 `json:"mirror_drops_queue_full_same_worker,omitempty"`
	MirrorDropsQueueFullCrossWorker   uint64 `json:"mirror_drops_queue_full_cross_worker,omitempty"`
	DirectTXPackets                   uint64 `json:"direct_tx_packets,omitempty"`
	CopyTXPackets                     uint64 `json:"copy_tx_packets,omitempty"`
	InPlaceTXPackets                  uint64 `json:"in_place_tx_packets,omitempty"`
	InPlaceVLANPushDescPackets        uint64 `json:"in_place_vlan_push_desc_packets,omitempty"`
	InPlaceVLANPopDescPackets         uint64 `json:"in_place_vlan_pop_desc_packets,omitempty"`
	InPlaceVLANPushNoHeadroomPackets  uint64 `json:"in_place_vlan_push_no_headroom_packets,omitempty"`
	InPlaceL2MemmoveFallbackPackets   uint64 `json:"in_place_l2_memmove_fallback_packets,omitempty"`
	DirectTXNoFrameFallbackPackets    uint64 `json:"direct_tx_no_frame_fallback_packets,omitempty"`
	DirectTXBuildFallbackPackets      uint64 `json:"direct_tx_build_fallback_packets,omitempty"`
	DirectTXDisallowedFallbackPackets uint64 `json:"direct_tx_disallowed_fallback_packets,omitempty"`
	DebugPendingFillFrames            uint32 `json:"debug_pending_fill_frames,omitempty"`
	DebugSpareFillFrames              uint32 `json:"debug_spare_fill_frames,omitempty"`
	DebugFreeTXFrames                 uint32 `json:"debug_free_tx_frames,omitempty"`
	DebugPendingTXPrepared            uint32 `json:"debug_pending_tx_prepared,omitempty"`
	DebugPendingTXLocal               uint32 `json:"debug_pending_tx_local,omitempty"`
	DebugOutstandingTX                uint32 `json:"debug_outstanding_tx,omitempty"`
	// #1241: low-frequency AF_XDP TX completion-ring availability
	// samples, published from owner-local worker telemetry. Current is
	// the last sampled CQ depth before a reap; Max is the peak in the
	// last debug window.
	TXCompletionRingAvailable    uint32 `json:"tx_completion_ring_available,omitempty"`
	TXCompletionRingAvailableMax uint32 `json:"tx_completion_ring_available_max,omitempty"`
	DebugInFlightRecycles        uint32 `json:"debug_in_flight_recycles,omitempty"`
	// #802/#804: ring-pressure instrumentation mirror fields. See the
	// Rust `BindingStatus` for semantics and write sites. The #804
	// split replaces the pre-#804 `dbg_pending_overflow` field with
	// two distinct wire keys — `dbg_bound_pending_overflow` for the
	// `bound_pending` FIFO evict sites in `tx.rs`, and
	// `dbg_cos_queue_overflow` for binding-lifetime CoS queue drops:
	// admission rejects in `enqueue_cos_item` plus reset-time CoS queue
	// drains. The wire key is historical. A snapshot from a pre-#804
	// helper deserializes both as 0 (standard Go json zero-value),
	// which is the right backward-compat behavior.
	DbgTxRingFull           uint64 `json:"dbg_tx_ring_full,omitempty"`
	DbgSendtoENOBUFS        uint64 `json:"dbg_sendto_enobufs,omitempty"`
	DbgBoundPendingOverflow uint64 `json:"dbg_bound_pending_overflow,omitempty"`
	DbgCoSQueueOverflow     uint64 `json:"dbg_cos_queue_overflow,omitempty"`
	RxFillRingEmptyDescs    uint64 `json:"rx_fill_ring_empty_descs,omitempty"`
	OutstandingTX           uint32 `json:"outstanding_tx,omitempty"`
	// #878: per-binding UMEM total frames and TX-ring depth (set
	// once at worker construction) plus in-flight gauge (republished
	// each ~1s by the worker as a single atomic store from local
	// state — no torn reads). fwdstatus Buffer% =
	//   max(UmemInflightFrames/UmemTotalFrames,
	//       OutstandingTX/TxRingCapacity)
	// aggregated as max across bindings. Zero on UmemTotalFrames
	// means "not yet published" — fwdstatus falls back to the legacy
	// "unknown" display.
	UmemTotalFrames    uint32 `json:"umem_total_frames,omitempty"`
	TxRingCapacity     uint32 `json:"tx_ring_capacity,omitempty"`
	UmemInflightFrames uint32 `json:"umem_inflight_frames,omitempty"`
	// #812: per-queue TX submit→completion latency telemetry. 16 log2-
	// spaced buckets (see Rust `DRAIN_HIST_BUCKETS` wire contract), plus
	// a total completion count and running sum-ns. Emitted on the rich
	// BindingStatus AND projected onto BindingCountersSnapshot so
	// step1-capture consumers can compute per-queue latency
	// distributions without a second join. omitempty keeps forward-
	// compat — a pre-#812 helper that lacks these fields decodes into
	// empty slice / zero u64.
	TxSubmitLatencyHist  []uint64 `json:"tx_submit_latency_hist,omitempty"`
	TxSubmitLatencyCount uint64   `json:"tx_submit_latency_count,omitempty"`
	TxSubmitLatencySumNs uint64   `json:"tx_submit_latency_sum_ns,omitempty"`
	// #825: per-kick `sendto` latency telemetry. 16 log2 buckets
	// (wire-compatible with `tx_submit_latency_hist` /
	// `drain_latency_hist`), plus count, sum-ns, and the
	// EAGAIN/EWOULDBLOCK retry tally (T1 ring-pushback signal per
	// #819 §4.1). omitempty keeps forward-compat — a pre-#825
	// helper that lacks these fields decodes into empty slice /
	// zero uint64.
	TxKickLatencyHist  []uint64 `json:"tx_kick_latency_hist,omitempty"`
	TxKickLatencyCount uint64   `json:"tx_kick_latency_count,omitempty"`
	TxKickLatencySumNs uint64   `json:"tx_kick_latency_sum_ns,omitempty"`
	TxKickRetryCount   uint64   `json:"tx_kick_retry_count,omitempty"`
	// #760 (#1642): the post-drain backup filter drop counters are
	// binding-scoped in the Rust helper (protocol/binding.rs), not
	// queue-scoped. They were previously declared on CoSQueueStatus, a
	// different JSON nesting level, so the Rust binding-level values were
	// silently dropped on unmarshal. JSON tags MUST match Rust serde
	// rename(...) exactly.
	PostDrainBackupCosDrops     uint64    `json:"post_drain_backup_cos_drops,omitempty"`
	PostDrainBackupCosDropBytes uint64    `json:"post_drain_backup_cos_drop_bytes,omitempty"`
	LastHeartbeat               time.Time `json:"last_heartbeat,omitempty"`
	LastError                   string    `json:"last_error,omitempty"`
	LastChange                  time.Time `json:"last_change,omitempty"`
}

// BindingCountersSnapshot is the focused per-binding ring-pressure view
// surfaced on ProcessStatus.PerBinding. It is a strict subset of
// BindingStatus, emitted by the Rust helper so the daemon's poll path
// can deserialize only the triage counters when that's all it needs.
// See the Rust `BindingCountersSnapshot` definition for semantics.
//
// #802.
type BindingCountersSnapshot struct {
	WorkerID         uint32 `json:"worker_id"`
	Ifindex          int    `json:"ifindex,omitempty"`
	QueueID          uint32 `json:"queue_id"`
	DbgTxRingFull    uint64 `json:"dbg_tx_ring_full,omitempty"`
	DbgSendtoENOBUFS uint64 `json:"dbg_sendto_enobufs,omitempty"`
	// #804: split from the pre-#804 `dbg_pending_overflow` field. Two
	// distinct increment sites (bound-pending FIFO evict in tx.rs vs
	// CoS queue admission in enqueue_cos_item) now publish two
	// distinct wire keys so operators can disambiguate. A snapshot
	// from a pre-#804 helper will leave both fields at the Go
	// zero-value — there is no silent re-attribution of the legacy
	// counter. Consumers that want a total across either path should
	// sum these two explicitly.
	DbgBoundPendingOverflow uint64 `json:"dbg_bound_pending_overflow,omitempty"`
	DbgCoSQueueOverflow     uint64 `json:"dbg_cos_queue_overflow,omitempty"`
	RxFillRingEmptyDescs    uint64 `json:"rx_fill_ring_empty_descs,omitempty"`
	OutstandingTX           uint32 `json:"outstanding_tx,omitempty"`
	// #1241: low-frequency AF_XDP TX completion-ring availability
	// gauges mirrored from BindingStatus for fast-poll consumers.
	TXCompletionRingAvailable    uint32 `json:"tx_completion_ring_available,omitempty"`
	TXCompletionRingAvailableMax uint32 `json:"tx_completion_ring_available_max,omitempty"`
	// #878: per-binding capacities pulled through to the leaner
	// snapshot so the daemon's fast poller can compute Buffer%
	// without joining the full BindingStatus. See BindingStatus
	// for full semantics.
	UmemTotalFrames                 uint32 `json:"umem_total_frames,omitempty"`
	TxRingCapacity                  uint32 `json:"tx_ring_capacity,omitempty"`
	UmemInflightFrames              uint32 `json:"umem_inflight_frames,omitempty"`
	TXErrors                        uint64 `json:"tx_errors,omitempty"`
	TXSharedRecycleUnknownSlotDrops uint64 `json:"tx_shared_recycle_unknown_slot_drops,omitempty"`
	TxSubmitErrorDrops              uint64 `json:"tx_submit_error_drops,omitempty"`
	PendingTxLocalOverflowDrops     uint64 `json:"pending_tx_local_overflow_drops,omitempty"`
	MirroredPackets                 uint64 `json:"mirrored_packets,omitempty"`
	MirroredBytes                   uint64 `json:"mirrored_bytes,omitempty"`
	MirrorDropsNoFrame              uint64 `json:"mirror_drops_no_frame,omitempty"`
	MirrorDropsTXFrameReserve       uint64 `json:"mirror_drops_tx_frame_reserve,omitempty"`
	MirrorDropsNoBinding            uint64 `json:"mirror_drops_no_binding,omitempty"`
	MirrorDropsQueueFull            uint64 `json:"mirror_drops_queue_full,omitempty"`
	MirrorDropsQueueFullSameWorker  uint64 `json:"mirror_drops_queue_full_same_worker,omitempty"`
	MirrorDropsQueueFullCrossWorker uint64 `json:"mirror_drops_queue_full_cross_worker,omitempty"`
	// #812: per-queue TX submit→completion latency histogram, pulled
	// through from BindingStatus so step1-capture consumers can
	// compute per-queue latency distributions without a second
	// query. Layout is 16 log2-spaced buckets (see the Rust
	// `DRAIN_HIST_BUCKETS` wire contract); omitempty on all three
	// preserves forward-compat — a pre-#812 helper that lacks these
	// fields decodes into empty slice / zero u64 without the daemon
	// erroring.
	TxSubmitLatencyHist  []uint64 `json:"tx_submit_latency_hist,omitempty"`
	TxSubmitLatencyCount uint64   `json:"tx_submit_latency_count,omitempty"`
	TxSubmitLatencySumNs uint64   `json:"tx_submit_latency_sum_ns,omitempty"`
	// #825: per-kick `sendto` latency telemetry, pulled through
	// from BindingStatus so step1-capture / P3 consumers can
	// compute per-queue kick-latency distributions without a
	// second query. omitempty on all four preserves forward-compat.
	TxKickLatencyHist  []uint64 `json:"tx_kick_latency_hist,omitempty"`
	TxKickLatencyCount uint64   `json:"tx_kick_latency_count,omitempty"`
	TxKickLatencySumNs uint64   `json:"tx_kick_latency_sum_ns,omitempty"`
	TxKickRetryCount   uint64   `json:"tx_kick_retry_count,omitempty"`
	// #918: per-set LRU collision-eviction counter, brought through
	// to the lean snapshot for fast-poll consumers that need the
	// flow-cache thrash signal. Default keeps pre-#918 helpers parseable.
	FlowCacheCollisionEvictions uint64 `json:"flow_cache_collision_evictions,omitempty"`
	// #1219: distinct active flow count snapshot for fairness harness.
	// See BindingStatus.ActiveFlowCount.
	ActiveFlowCount uint32 `json:"active_flow_count,omitempty"`
	// FlowCacheCapacity mirrors BindingStatus for fast-poll consumers.
	FlowCacheCapacity uint32 `json:"flow_cache_capacity,omitempty"`
	// #941 Work item D / #943: V_min throttle counters. The lean
	// per_binding view is what fast-poll consumers (mouse-latency
	// orchestrator, MQFQ diagnostics) read; without these here, V_min
	// observability stops at the rich BindingStatus and ProcessStatus.per_binding
	// projects zeros even when the atomics flushed real values.
	VMinThrottleHardCapOverrides uint64 `json:"v_min_throttle_hard_cap_overrides,omitempty"`
	VMinThrottles                uint64 `json:"v_min_throttles,omitempty"`
}

type ExceptionStatus struct {
	Timestamp        time.Time `json:"timestamp"`
	Slot             uint32    `json:"slot"`
	QueueID          uint32    `json:"queue_id"`
	WorkerID         uint32    `json:"worker_id"`
	Interface        string    `json:"interface,omitempty"`
	Ifindex          int       `json:"ifindex,omitempty"`
	IngressIfindex   int       `json:"ingress_ifindex,omitempty"`
	Reason           string    `json:"reason"`
	PacketLength     uint32    `json:"packet_length,omitempty"`
	AddrFamily       uint8     `json:"addr_family,omitempty"`
	Protocol         uint8     `json:"protocol,omitempty"`
	ConfigGeneration uint64    `json:"config_generation,omitempty"`
	FIBGeneration    uint32    `json:"fib_generation,omitempty"`
	SrcIP            string    `json:"src_ip,omitempty"`
	DstIP            string    `json:"dst_ip,omitempty"`
	SrcPort          uint16    `json:"src_port,omitempty"`
	DstPort          uint16    `json:"dst_port,omitempty"`
	FromZone         string    `json:"from_zone,omitempty"`
	ToZone           string    `json:"to_zone,omitempty"`
	RuleName         string    `json:"rule_name,omitempty"`
	PoolName         string    `json:"pool_name,omitempty"`
}

type InjectPacketRequest struct {
	Slot                 uint32  `json:"slot"`
	PacketLength         uint32  `json:"packet_length,omitempty"`
	AddrFamily           uint8   `json:"addr_family,omitempty"`
	Protocol             uint8   `json:"protocol,omitempty"`
	ConfigGeneration     uint64  `json:"config_generation,omitempty"`
	FIBGeneration        uint32  `json:"fib_generation,omitempty"`
	MetadataValid        bool    `json:"metadata_valid"`
	DestinationIP        string  `json:"destination_ip,omitempty"`
	EmitOnWire           bool    `json:"emit_on_wire,omitempty"`
	TupleMetadataVersion int     `json:"tuple_metadata_version,omitempty"`
	SourceIP             string  `json:"source_ip,omitempty"`
	SourcePort           *uint16 `json:"source_port,omitempty"`
	DestinationPort      *uint16 `json:"destination_port,omitempty"`
}

type SessionDeltaDrainRequest struct {
	Max uint32 `json:"max,omitempty"`
}

type SessionExportRequest struct {
	OwnerRGs []int  `json:"owner_rgs,omitempty"`
	Max      uint32 `json:"max,omitempty"`
}

type SessionSyncRequest struct {
	Operation   string `json:"operation,omitempty"`
	AddrFamily  uint8  `json:"addr_family,omitempty"`
	Protocol    uint8  `json:"protocol,omitempty"`
	SrcIP       string `json:"src_ip,omitempty"`
	DstIP       string `json:"dst_ip,omitempty"`
	SrcPort     uint16 `json:"src_port,omitempty"`
	DstPort     uint16 `json:"dst_port,omitempty"`
	IngressZone string `json:"ingress_zone,omitempty"`
	EgressZone  string `json:"egress_zone,omitempty"`
	// #919/#922: u16 zone-id mirrors. Additive — the Rust daemon
	// prefers the IDs when nonzero and falls back to the legacy
	// name strings otherwise. Old peers without these fields
	// continue to work (Rust serde sets the IDs to 0).
	IngressZoneID    uint16 `json:"ingress_zone_id,omitempty"`
	EgressZoneID     uint16 `json:"egress_zone_id,omitempty"`
	OwnerRGID        int    `json:"owner_rg_id,omitempty"`
	EgressIfindex    int    `json:"egress_ifindex,omitempty"`
	TXIfindex        int    `json:"tx_ifindex,omitempty"`
	TunnelEndpointID uint16 `json:"tunnel_endpoint_id,omitempty"`
	TXVLANID         uint16 `json:"tx_vlan_id,omitempty"`
	NextHop          string `json:"next_hop,omitempty"`
	NeighborMAC      string `json:"neighbor_mac,omitempty"`
	SrcMAC           string `json:"src_mac,omitempty"`
	NATSrcIP         string `json:"nat_src_ip,omitempty"`
	NATDstIP         string `json:"nat_dst_ip,omitempty"`
	NATSrcPort       uint16 `json:"nat_src_port,omitempty"`
	NATDstPort       uint16 `json:"nat_dst_port,omitempty"`
	FabricIngress    bool   `json:"fabric_ingress,omitempty"`
	IsReverse        bool   `json:"is_reverse,omitempty"`
	// Generation carries the #2170 HA install generation to the helper so
	// its in-memory SyncedSessionEntry can mirror the cluster apply layer's
	// generation guard (belt-and-suspenders for helper-originated deletes
	// and the delayed-stale-install variant). Plain uint64 with NO
	// omitempty: a 0 value MUST serialize as 0 (legacy/unknown) so an old
	// helper without the field still decodes via serde(default), and a new
	// helper sees an explicit 0 rather than a missing key — the #1961
	// wire-type discipline (no omitempty ambiguity on a numeric field). The
	// Rust side declares `#[serde(default)] generation: u64`.
	Generation uint64 `json:"generation"`
}

type SessionDeltaInfo struct {
	Timestamp   time.Time `json:"timestamp"`
	Slot        uint32    `json:"slot"`
	QueueID     uint32    `json:"queue_id"`
	WorkerID    uint32    `json:"worker_id"`
	Interface   string    `json:"interface,omitempty"`
	Ifindex     int       `json:"ifindex,omitempty"`
	Event       string    `json:"event"`
	AddrFamily  uint8     `json:"addr_family,omitempty"`
	Protocol    uint8     `json:"protocol,omitempty"`
	SrcIP       string    `json:"src_ip,omitempty"`
	DstIP       string    `json:"dst_ip,omitempty"`
	SrcPort     uint16    `json:"src_port,omitempty"`
	DstPort     uint16    `json:"dst_port,omitempty"`
	IngressZone string    `json:"ingress_zone,omitempty"`
	EgressZone  string    `json:"egress_zone,omitempty"`
	// #919/#922: u16 zone-id mirrors decoded directly from the binary
	// event-stream payload (bytes [21],[22] u8 → u16 here for symmetry
	// with SessionSyncRequest). The HA delta path prefers these IDs;
	// the legacy strings stay populated when JSON callers fill them.
	IngressZoneID    uint16 `json:"ingress_zone_id,omitempty"`
	EgressZoneID     uint16 `json:"egress_zone_id,omitempty"`
	OwnerRGID        int    `json:"owner_rg_id,omitempty"`
	Disposition      string `json:"disposition,omitempty"`
	Origin           string `json:"origin,omitempty"`
	EgressIfindex    int    `json:"egress_ifindex,omitempty"`
	TXIfindex        int    `json:"tx_ifindex,omitempty"`
	TunnelEndpointID uint16 `json:"tunnel_endpoint_id,omitempty"`
	TXVLANID         uint16 `json:"tx_vlan_id,omitempty"`
	NextHop          string `json:"next_hop,omitempty"`
	NeighborMAC      string `json:"neighbor_mac,omitempty"`
	SrcMAC           string `json:"src_mac,omitempty"`
	NATSrcIP         string `json:"nat_src_ip,omitempty"`
	NATDstIP         string `json:"nat_dst_ip,omitempty"`
	NATSrcPort       uint16 `json:"nat_src_port,omitempty"`
	NATDstPort       uint16 `json:"nat_dst_port,omitempty"`
	FabricRedirect   bool   `json:"fabric_redirect,omitempty"`
	FabricIngress    bool   `json:"fabric_ingress,omitempty"`
}

// ---------------------------------------------------------------------------
// Event stream wire format (binary framed, helper → daemon push stream).
// ---------------------------------------------------------------------------

// EventFrameHeaderSize is the byte length of every event stream frame header.
const EventFrameHeaderSize = 16

// Event stream message types.
const (
	EventTypeSessionOpen     uint8 = 1
	EventTypeSessionClose    uint8 = 2
	EventTypeSessionUpdate   uint8 = 3
	EventTypeAck             uint8 = 4  // daemon → helper
	EventTypePause           uint8 = 5  // daemon → helper
	EventTypeResume          uint8 = 6  // daemon → helper
	EventTypeDrainRequest    uint8 = 7  // daemon → helper (target seq in header)
	EventTypeDrainComplete   uint8 = 8  // helper → daemon
	EventTypeFullResync      uint8 = 9  // helper → daemon
	EventTypeKeepalive       uint8 = 10 // helper → daemon (idle heartbeat)
	EventFrameTypePolicyDeny uint8 = 11 // helper → daemon (RT_FLOW policy deny)
	EventFrameTypeScreenDrop uint8 = 12 // helper → daemon (RT_FLOW screen drop)
	EventFrameTypeFilterLog  uint8 = 13 // helper → daemon (RT_FLOW filter log)
)

// Session event flag bits in the Flags byte of SessionOpen/Update/Close payloads.
const (
	SessionEventFlagFabricRedirect uint8 = 1 << 0
	SessionEventFlagFabricIngress  uint8 = 1 << 1
	SessionEventFlagIsReverse      uint8 = 1 << 2
)
