package userspace

import (
	"time"

	"github.com/psaab/xpf/pkg/config"
)

const (
	ProtocolVersion                  = 3
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
	RoutingInstance           string                     `json:"routing_instance,omitempty"`
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

type EventStreamStatus struct {
	FramesRead             uint64 `json:"frames_read,omitempty"`
	FramesWritten          uint64 `json:"frames_written,omitempty"`
	DecodeErrors           uint64 `json:"decode_errors,omitempty"`
	SeqGaps                uint64 `json:"seq_gaps,omitempty"`
	SessionSyncResyncs     uint64 `json:"session_sync_resyncs,omitempty"`     // #2874/#5483
	DecodeResyncSuppressed uint64 `json:"decode_resync_suppressed,omitempty"` // #6130
	PolicyDenyEvents       uint64 `json:"policy_deny_events,omitempty"`
	ScreenDropEvents       uint64 `json:"screen_drop_events,omitempty"`
	ScreenAlarmEvents      uint64 `json:"screen_alarm_events,omitempty"`
	FilterLogEvents        uint64 `json:"filter_log_events,omitempty"`
	SessionCloseEvents     uint64 `json:"session_close_events,omitempty"`  // #2460/#2510
	SessionCreateEvents    uint64 `json:"session_create_events,omitempty"` // #2508/#2510
	PolicyDenyDrops        uint64 `json:"policy_deny_drops,omitempty"`
	ScreenDropDrops        uint64 `json:"screen_drop_drops,omitempty"`
	FilterLogDrops         uint64 `json:"filter_log_drops,omitempty"`
	SessionCloseDrops      uint64 `json:"session_close_drops,omitempty"`  // #2460/#2510
	SessionCreateDrops     uint64 `json:"session_create_drops,omitempty"` // #2508/#2510
	UnknownFrameDrops      uint64 `json:"unknown_frame_drops,omitempty"`
}

type HAStateUpdateRequest struct {
	Groups []HAGroupStatus `json:"groups,omitempty"`
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
	// #2785: the admitting policy's per-policy `then log` selection, carried
	// so a session synced to the peer logs the same RT_FLOW
	// SESSION_CREATE/CLOSE records after failover. omitempty is safe — an old
	// helper without these keys decodes them via serde(default) to false (no
	// per-policy log), bit-identical to pre-#2785 behavior.
	LogSessionInit  bool `json:"log_session_init,omitempty"`
	LogSessionClose bool `json:"log_session_close,omitempty"`
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
	// #3301: the admitting policy's firewall metadata, carried so a
	// peer-PROMOTED session is correctly attributed, counted, and aged after
	// failover instead of degrading to policy 0 / no counter / the global
	// timeout. omitempty is safe — an old helper without these keys decodes
	// them via serde(default) to 0, which is the legitimate "unattributed /
	// no per-rule counter / use-global-timeout" value, bit-identical to the
	// pre-#3301 synced-session behavior (rolling-upgrade safe).
	//
	// PolicyID is the admitting policy ID (#3056 namespace). PolicyCounterIdx
	// is the 1-based per-rule hit-counter handle (#3073); HA requires
	// identical config on both nodes so the same idx resolves the same rule.
	// InactivityTimeout is the per-application idle timeout in SECONDS (#3227,
	// matching SessionValue.AppTimeout); the helper converts it to ns.
	PolicyID          uint32 `json:"policy_id,omitempty"`
	PolicyCounterIdx  uint32 `json:"policy_counter_idx,omitempty"`
	InactivityTimeout uint32 `json:"inactivity_timeout,omitempty"`
	// #4565: the NAT64 translated pool SOURCE (dotted-quad IPv4). A non-empty
	// value is the peer helper's signal that this is a NAT64 cross-family
	// session — it sets nat.nat64, rewrites the forward source to this v4 pool
	// address, and reconstructs the reverse (v4->v6) BIB (orig v6 src/dst from
	// the synced forward v6 key, dst_v4 from the /96-embedded low 32 of the key
	// dst). This is the one part of the reverse mapping not carried by the
	// synced forward key. omitempty is safe — an old helper without the key
	// decodes it via serde(default) to "" (not NAT64), bit-identical to
	// pre-#4565 (rolling-upgrade safe).
	Nat64SnatV4 string `json:"nat64_snat_v4,omitempty"`
	// #5212: the ORIGINATING node's stable RT_FLOW session id (the dataplane's
	// alloc_session_id value). Carried so a peer-PROMOTED session ADOPTS the
	// originating node's id rather than minting a fresh node-local one on import
	// — its RT_FLOW SESSION_CREATE (origin node) and SESSION_CLOSE (possibly the
	// peer, after failover) then share one correlatable id. The helper stamps it
	// onto the imported entry (build_synced_session_entry). omitempty is safe —
	// an old helper without the key decodes it via serde(default) to 0, the "no
	// id carried" sentinel that falls back to a fresh local id (rolling-upgrade
	// safe). The Rust side declares `#[serde(rename = "session_id", default)]`.
	RTFlowSessionID uint64 `json:"session_id,omitempty"`
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
	// #2785: the admitting policy's per-policy `then log` selection. Decoded
	// from the binary open-frame flags byte (bits 1<<3/1<<4) AND mirrored on
	// the JSON RPC-fallback delta; stamped onto the synced session's
	// LogFlags so it logs identically after failover.
	LogSessionInit  bool `json:"log_session_init,omitempty"`
	LogSessionClose bool `json:"log_session_close,omitempty"`
	// #3301: the admitting policy's firewall metadata, decoded from the
	// trailing fields of the binary open frame (after NextHop) AND mirrored on
	// the JSON RPC-fallback delta. Stamped onto the synced SessionValue
	// (PolicyID/PolicyCounterIdx/AppTimeout) by daemon_ha_userspace.go so the
	// cluster sync wire and the peer helper carry them, correcting a
	// peer-promoted session's policy attribution / hit-count / idle timeout
	// after failover. PolicyID = #3056 policy ID; PolicyCounterIdx = #3073
	// 1-based per-rule counter handle; AppTimeout = #3227 per-application idle
	// timeout in SECONDS.
	PolicyID         uint32 `json:"policy_id,omitempty"`
	PolicyCounterIdx uint32 `json:"policy_counter_idx,omitempty"`
	AppTimeout       uint32 `json:"app_timeout,omitempty"`
	// #4565: NAT64 cross-family marker (open-frame flags bit 1<<5) + the
	// translated pool SOURCE (trailing 4 bytes). Stamped onto the synced
	// SessionValueV6 (SessFlagNAT64 + Nat64SnatV4) by daemon_ha_userspace.go so
	// the cluster sync wire and the peer helper carry them, letting a
	// peer-PROMOTED NAT64 session rebuild its reverse (v4->v6) BIB after
	// failover. Nat64SnatV4 is the one datum not reconstructable from the synced
	// forward v6 key (the orig v6 src/dst ARE the key; dst_v4 is the /96 low 32).
	Nat64       bool   `json:"nat64,omitempty"`
	Nat64SnatV4 string `json:"nat64_snat_v4,omitempty"`
	// #5212: the ORIGINATING node's stable RT_FLOW session id, decoded from the
	// trailing u64 of the binary open frame (after the #4565 snat_v4). Stamped
	// onto the synced SessionValue{,V6}.RTFlowSessionID by daemon_ha_userspace.go
	// so the cluster sync wire and the peer helper carry it, letting a
	// peer-synced session adopt the originating node's id (SESSION_CREATE/CLOSE
	// correlate across HA nodes). Absent on an old helper => 0, the standby
	// allocs a fresh local id (pre-#5212 behavior, rolling-upgrade safe).
	RTFlowSessionID uint64 `json:"rt_flow_session_id,omitempty"`
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
	// #2460: RT_FLOW SESSION_CLOSE on the raw dataplane-event channel,
	// carrying the canonical 144-byte dataplane.Event payload (#3056) with the
	// event-type byte = dataplane.EventTypeSessionClose (2). Routed through
	// the same decodeDataplaneEventPayload → eventReader.ProcessRawEvent
	// path as the deny/screen/filter frames so the NetFlow/IPFIX
	// session-close exporters fire. ADDITIVE to the minimal type-2
	// EventTypeSessionClose HA session-sync delta — both are produced per
	// close; the HA sync path is unchanged.
	EventFrameTypeSessionClose uint8 = 14 // helper → daemon (RT_FLOW session close)
	// #2508: RT_FLOW SESSION_CREATE on the raw dataplane-event channel,
	// carrying the canonical 144-byte dataplane.Event payload (#3056) with the
	// event-type byte = dataplane.EventTypeSessionOpen (1). Emitted by the
	// helper ONLY for sessions admitted by a policy configured with
	// `then log session-init` — there is no flowexport consumer of session
	// opens, so this frame is gated entirely at the producer. Routed
	// through the same decodeDataplaneEventPayload → ProcessRawEvent path;
	// logEvent then formats it as an RT_FLOW_SESSION_CREATE syslog record.
	EventFrameTypeSessionCreate uint8 = 15 // helper → daemon (RT_FLOW session create)
)

// Session event flag bits in the Flags byte of SessionOpen/Update/Close payloads.
const (
	SessionEventFlagFabricRedirect uint8 = 1 << 0
	SessionEventFlagFabricIngress  uint8 = 1 << 1
	SessionEventFlagIsReverse      uint8 = 1 << 2
	// #2785: per-policy `then log` selection carried on the open frame so a
	// synced session logs the same RT_FLOW records after failover. Must match
	// FLAG_LOG_SESSION_INIT/CLOSE in userspace-dp/src/event_stream/codec.rs.
	SessionEventFlagLogSessionInit  uint8 = 1 << 3
	SessionEventFlagLogSessionClose uint8 = 1 << 4
	// #4565: NAT64 cross-family marker carried on the open frame so a peer-
	// PROMOTED session rebuilds its reverse (v4->v6) BIB after failover. Must
	// match FLAG_NAT64 in userspace-dp/src/event_stream/codec.rs.
	SessionEventFlagNat64 uint8 = 1 << 5
)
