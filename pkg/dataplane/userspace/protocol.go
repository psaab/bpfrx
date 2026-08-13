package userspace

import (
	"time"

	"github.com/psaab/xpf/pkg/config"
)

const (
	// ProtocolVersion is the config-snapshot wire contract version. It is
	// the Go mirror of CONFIG_SNAPSHOT_PROTOCOL_VERSION
	// (userspace-dp/src/protocol/control.rs) and the two MUST be bumped in
	// lockstep: both apply_snapshot and bump_fib_generation gate on EXACT
	// equality, so a helper at a different version refuses the snapshot
	// outright rather than decoding it under the wrong contract.
	//
	// v4 (#5488): a scoped GLOBAL policy carries its zone SCOPE as a zone
	// SET in the plural match_from_zones/match_to_zones fields, and those
	// fields are AUTHORITATIVE. The singular match_from_zone/match_to_zone
	// fields carry only the FIRST element (config.ScopeSingular).
	//
	// #4626 added the plural fields as purely ADDITIVE JSON without bumping
	// this constant, which made the version handshake lie: a pre-#4626
	// helper advertising the same version 3 ignores fields it does not know
	// and reads ONLY the singular field, so a global `deny` scoped
	// `[dmz trust] -> untrust` silently NARROWS to `dmz -> untrust` and the
	// trust-sourced traffic the operator denied is evaluated by lower
	// precedence rules instead — a rolling-upgrade fail-OPEN. A
	// compatibility extension that changes deny/reject COVERAGE must not be
	// silently ignorable under an unchanged protocol version.
	//
	// The bump alone only makes an old helper REFUSE the snapshot (it keeps
	// forwarding its previous-good image), so it is paired with the
	// ensureScopedGlobalZoneSetProtocolLocked required-protocol gate in
	// manager_compile.go, which DISARMS the helper and aborts the commit
	// when the running helper is too old to represent a multi-zone scope.
	ProtocolVersion                  = 4
	InjectPacketTupleProtocolVersion = 1
	TypeUserspace                    = "userspace"

	// MaxInjectPacketLength bounds the operator/API-supplied packet
	// length for the `request inject-packet` control RPC (#2443). An
	// injected packet is always emitted as a single unfragmented frame
	// that must fit in one AF_XDP UMEM frame on the TX path
	// (UMEM_FRAME_SIZE = 4096 in userspace-dp), and 4096 is also well
	// within the u16 range of the IPv4 total-length / IPv6 payload-length
	// wire fields, so the on-wire length can never wrap. The bound is the
	// smaller of "u16-representable" and "max single egress frame"; the
	// UMEM frame ceiling is the binding constraint. A length above this is
	// REJECTED (not clamped) so an API misuse / DoS attempt surfaces as an
	// error rather than being silently masked.
	MaxInjectPacketLength = 4096
)

type ControlRequest struct {
	Type           string                    `json:"type"`
	SuppressStatus bool                      `json:"suppress_status,omitempty"`
	Snapshot       *ConfigSnapshot           `json:"snapshot,omitempty"`
	Forwarding     *ForwardingControlRequest `json:"forwarding,omitempty"`
	HAState        *HAStateUpdateRequest     `json:"ha_state,omitempty"`
	Queue          *QueueControlRequest      `json:"queue,omitempty"`
	Binding        *BindingControlRequest    `json:"binding,omitempty"`
	Packet         *InjectPacketRequest      `json:"packet,omitempty"`
	SessionSync    *SessionSyncRequest       `json:"session_sync,omitempty"`
	SessionDeltas  *SessionDeltaDrainRequest `json:"session_deltas,omitempty"`
	SessionExport  *SessionExportRequest     `json:"session_export,omitempty"`
	// Neighbors carries the manager-neighbor set for an update_neighbors
	// request. It deliberately does NOT use omitempty (#5864): when the
	// authoritative publishable set transitions to EMPTY, the send path
	// still passes a present-but-empty slice with NeighborReplace=true to
	// CLEAR the helper table. omitempty drops both nil and empty slices,
	// which erased that clear on the wire (the helper decoded neighbors as
	// absent and returned before applying the replacement, leaving stale
	// dynamic neighbors installed → blackhole after kernel neighbor
	// deletion). Without omitempty a present-empty replace encodes as
	// "neighbors":[] — distinct from an absent field — so the helper
	// applies the clear. A nil slice on non-neighbor requests encodes as
	// "neighbors":null, which the Rust Option<Vec<..>> decodes back to
	// None (harmless; those requests ignore the field).
	Neighbors          []NeighborSnapshot `json:"neighbors"`
	NeighborGeneration uint64             `json:"neighbor_generation,omitempty"`
	NeighborReplace    bool               `json:"neighbor_replace,omitempty"`
	Fabrics            []FabricSnapshot   `json:"fabrics,omitempty"`
}

type ControlResponse struct {
	OK            bool               `json:"ok"`
	Error         string             `json:"error,omitempty"`
	Status        *ProcessStatus     `json:"status,omitempty"`
	SessionDeltas []SessionDeltaInfo `json:"session_deltas,omitempty"`
}

type ConfigSnapshot struct {
	Version         int                      `json:"version"`
	Generation      uint64                   `json:"generation"`
	FIBGeneration   uint32                   `json:"fib_generation,omitempty"`
	GeneratedAt     time.Time                `json:"generated_at"`
	Summary         SnapshotSummary          `json:"summary"`
	Capabilities    UserspaceCapabilities    `json:"capabilities"`
	MapPins         UserspaceMapPins         `json:"map_pins"`
	Zones           []ZoneSnapshot           `json:"zones,omitempty"`
	Interfaces      []InterfaceSnapshot      `json:"interfaces,omitempty"`
	Fabrics         []FabricSnapshot         `json:"fabrics,omitempty"`
	TunnelEndpoints []TunnelEndpointSnapshot `json:"tunnel_endpoints,omitempty"`
	Neighbors       []NeighborSnapshot       `json:"neighbors,omitempty"`
	Routes          []RouteSnapshot          `json:"routes,omitempty"`
	Flow            FlowSnapshot             `json:"flow,omitempty"`
	DefaultPolicy   string                   `json:"default_policy,omitempty"`
	// DefaultLogSessionInit / DefaultLogSessionClose carry
	// `security policies default-policy-log session-init|session-close` (#3534).
	// They request RT_FLOW session logging for the IMPLICIT default-policy
	// verdict (the result returned when a flow matches no zone-pair, wildcard,
	// or global policy), mirroring a named policy's `then log` selection. The
	// Rust default-verdict result stamps these onto the metadata of a
	// default-PERMIT session so it emits RT_FLOW_SESSION_CREATE/CLOSE; a
	// default-DENY/REJECT verdict installs no session (already logged via the
	// policy-deny record), so they are inert there. Additive/skew-tolerant:
	// omitempty on the Go side + #[serde(default)] on the Rust side, so an old
	// helper decodes a missing field as false and an old Go binary that does not
	// emit it leaves the Rust flag false.
	DefaultLogSessionInit  bool                         `json:"default_log_session_init,omitempty"`
	DefaultLogSessionClose bool                         `json:"default_log_session_close,omitempty"`
	Policies               []PolicyRuleSnapshot         `json:"policies,omitempty"`
	SourceNAT              []SourceNATRuleSnapshot      `json:"source_nat_rules,omitempty"`
	StaticNAT              []StaticNATRuleSnapshot      `json:"static_nat_rules,omitempty"`
	DestinationNAT         []DestinationNATRuleSnapshot `json:"destination_nat_rules,omitempty"`
	NAT64                  []NAT64RuleSnapshot          `json:"nat64_rules,omitempty"`
	Nptv6                  []Nptv6RuleSnapshot          `json:"nptv6_rules,omitempty"`
	Screens                []ScreenProfileSnapshot      `json:"screens,omitempty"`
	// ScreenMissingProfiles records zones that REFERENCE a screen profile
	// which was NOT defined at snapshot-build time (#3082). On the
	// lenient/HA-sync path (#1960 — older-binary-persisted active.json on
	// upgrade, or an HA sync from an un-upgraded primary) a zone can
	// reference an undefined screen profile and boot with an apply-time
	// warning, yet the dataplane would have no `screens` entry for that zone
	// and so silently PASS all screen checks. Both "zone has no screen
	// configured" and "zone references a MISSING screen" otherwise produce
	// no entry. This additive field carries the missing references so the
	// dataplane can distinguish the two and emit a rate-limited runtime WARN
	// (the verdict stays Pass — the fail-closed-vs-pass posture is deferred).
	// Additive/skew-tolerant: an old helper without the field decodes it as
	// empty (all-Pass, no warn); an old Go binary that does not emit it
	// leaves the Rust set empty.
	ScreenMissingProfiles []ScreenMissingProfileRef   `json:"screen_missing_profile_zones,omitempty"`
	SYNCookieMasterKey    string                      `json:"syn_cookie_master_key,omitempty"`
	Filters               []FirewallFilterSnapshot    `json:"filters,omitempty"`
	Policers              []PolicerSnapshot           `json:"policers,omitempty"`
	ThreeColorPolicers    []ThreeColorPolicerSnapshot `json:"three_color_policers,omitempty"`
	ClassOfService        *ClassOfServiceSnapshot     `json:"class_of_service,omitempty"`
	FlowExport            *FlowExportSnapshot         `json:"flow_export,omitempty"`
	MirrorConfigs         []MirrorConfigSnapshot      `json:"mirror_configs,omitempty"`
	AddressBooks          []AddressBookSnapshot       `json:"address_books,omitempty"`
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
	// zoneIDCollisions is the manager-facing (#3719) record of every security
	// zone the snapshot builder QUARANTINED because its StableZoneID collided
	// with an earlier-sorting zone. It is unexported so it never rides the wire
	// or perturbs the snapshot hash (JSON ignores unexported fields), yet it
	// carries the diagnostic from the pure builder up to ApplyConfig, which
	// stamps it onto ProcessStatus.ZoneIDCollisions and fires the one-shot
	// operator alarm. Empty means no collision (the common case).
	zoneIDCollisions []ZoneIDCollision
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
	// GREAcceleration carries `security flow gre-performance-acceleration`
	// (#3360). On vSRX this extracts the GRE key/call-id into the session tuple
	// so multiple GRE tunnels between the same endpoints map to distinct
	// sessions. The userspace dataplane keys GRE flows on the 5-tuple only, so
	// this threads the operator's intent into the Rust ForwardingState
	// (mirroring the PowerModeDisable plumbing) for config truth/parity; the bit
	// is NOT yet read by any forwarding path. The consumer (GRE key/call-id
	// extraction) is a deferred feature.
	GREAcceleration bool `json:"gre_acceleration,omitempty"`
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

type InterfaceSnapshot struct {
	Name string `json:"name"`
	Zone string `json:"zone,omitempty"`
	// RoutingInstance is the bare routing-instance name this interface
	// belongs to ("" = the default instance). The Rust dataplane derives
	// the connected-route table (<ri>.inet.0 / <ri>.inet6.0, or
	// inet.0/inet6.0 for the default instance) from it so connected routes
	// rebuilt from interface addresses are table-scoped and do not leak
	// across VRF boundaries (#2388). Additive: an old Rust helper that does
	// not know the field treats every interface as the default instance
	// (the pre-#2388 global behavior); an old Go binary omits it.
	RoutingInstance string `json:"routing_instance,omitempty"`
	LinuxName       string `json:"linux_name,omitempty"`
	ParentLinuxName string `json:"parent_linux_name,omitempty"`
	Ifindex         int    `json:"ifindex,omitempty"`
	ParentIfindex   int    `json:"parent_ifindex,omitempty"`
	LogicalOnly     bool   `json:"logical_only,omitempty"`
	RXQueues        int    `json:"rx_queues,omitempty"`
	VLANID          int    `json:"vlan_id,omitempty"`
	LocalFabric     string `json:"local_fabric_member,omitempty"`
	RedundancyGroup int    `json:"redundancy_group,omitempty"`
	UnitCount       int    `json:"unit_count"`
	Tunnel          bool   `json:"tunnel"`
	// SecureTunnel reports that an IPsec configuration BINDS this interface
	// — i.e. some `security ipsec vpn <name> bind-interface` derives this
	// row's if_id (Config.SecureTunnelNetdevForRef). It is OWNERSHIP, not
	// name shape: nothing reserves the `st` prefix, so a wildcard-authored
	// `st5` with no VPN is an ordinary data interface and this stays false
	// (#6691).
	//
	// Additive: an old Rust helper that does not know the field treats every
	// interface as not-a-secure-tunnel, so an xfrmi would get an AF_XDP
	// binding it cannot use — the #5619 GAP, which both planes' comments
	// already rank as less bad than the outage over-matching causes. An old
	// Go binary omits it.
	SecureTunnel              bool                       `json:"secure_tunnel,omitempty"`
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
	// HostInbound* carry the per-interface host-inbound-traffic OVERRIDE
	// (#3362). Junos models host-inbound at both the zone level (ZoneSnapshot
	// above) and the interface level; the EFFECTIVE admission set for an
	// interface is the UNION of the zone-level set and any interface-level
	// override. These fields carry that already-unioned effective set and are
	// populated ONLY for an interface that declared an interface-level stanza
	// (and is not a management/cluster-control lifeline). When present the Rust
	// dataplane keys the host-inbound admission check by ingress interface
	// (ifindex) instead of the from-zone, so a service exposed on one interface
	// of a zone is admitted there while the zone-default set governs the rest.
	// Additive: an old Rust helper without the fields ignores them and falls
	// back to the zone-keyed check (pre-#3362 behaviour); an old Go binary omits
	// them (omitempty). HostInboundConfigured distinguishes a present-but-empty
	// override (enforcing, deny-all) from an absent one (zone-keyed fallback).
	HostInboundConfigured     bool     `json:"host_inbound_configured,omitempty"`
	HostInboundSystemServices []string `json:"host_inbound_system_services,omitempty"`
	HostInboundProtocols      []string `json:"host_inbound_protocols,omitempty"`
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
	// Up is the local fabric parent link's carrier/oper state (#4082). The
	// Rust dataplane prefers an UP fabric when resolving the cross-chassis
	// redirect, so a dual-fabric cluster fails over to the secondary when the
	// primary parent drops. This field MUST NOT be omitempty: a genuinely-down
	// fabric has to serialize "up":false, not drop the field — the Rust decoder
	// defaults an absent field to true (fail-open), so dropping it on down
	// would defeat the failover.
	Up bool `json:"up"`
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

type InterfaceAddressSnapshot struct {
	Family  string `json:"family"`
	Address string `json:"address"`
	Scope   int    `json:"scope,omitempty"`
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
	// PolicyContentRejected lists the reasons the published snapshot carries
	// the reserved __unsupported__ sentinel term and will be REJECTED by the
	// helper's non-mutating integrity preflight (the #2124 fail-closed family).
	// UNLIKE UnsupportedReasons, these entries do NOT disarm the helper
	// (#3261): the snapshot still publishes, the current helper rejects it via
	// SnapshotIntegrityError and KEEPS the previous-good PolicyState (running
	// node) or leaves the default-deny PolicyState (fresh boot) — it never
	// fails open to the kernel. Setting ForwardingSupported=false for this
	// class instead DISARMS the helper, so the XDP shim XDP_PASSes transit to
	// the kernel and bypasses the integrity reject — the system-level
	// fail-OPEN #3261 closes. Go-side diagnostic only; omitempty so
	// representable configs keep their exact wire shape (and snapshot hash).
	// The Rust helper has no field for this and (lacking deny_unknown_fields)
	// silently ignores it on decode.
	PolicyContentRejected []string `json:"policy_content_rejected,omitempty"`
}
