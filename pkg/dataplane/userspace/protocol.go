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
	// #4743: NoRoute drops whose destination is a MARTIAN address (IPv4
	// multicast/broadcast/unspecified/loopback, IPv6
	// multicast/unspecified/loopback). A strict sub-breakout of RouteMissPackets
	// (a martian dst misses the FIB and drops as NoRoute, so it bumps both),
	// letting an operator tell a martian-dst drop apart from an ordinary route
	// miss and correlate it with the filter-accept log. omitempty + the Rust
	// serde `default` keep cross-version wire safety (an older helper omits it →
	// 0). Summed across bindings and rendered as the "Martian drops" status row.
	MartianDropped uint64 `json:"martian_dropped,omitempty"`
	// #4743: fail-closed drops of an IPv6 packet whose extension-header chain is
	// still on an extension header after MAX_IPV6_EXT_HEADERS (8) iterations (an
	// over-limit, uninspectable chain). Before #4743 such a packet was forwarded
	// flowless; it is now dropped explicitly and counted. Distinct from a
	// truncated chain (which stays flowless). omitempty + the Rust serde
	// `default` keep cross-version wire safety. Rendered as the "IPv6 ext-header
	// drops" status row.
	IPv6ExtHeaderDropped uint64 `json:"ipv6_ext_header_dropped,omitempty"`
	NeighborMissPackets  uint64 `json:"neighbor_miss_packets,omitempty"`
	DiscardRoutePackets  uint64 `json:"discard_route_packets,omitempty"`
	NextTablePackets     uint64 `json:"next_table_packets,omitempty"`
	ExceptionPackets     uint64 `json:"exception_packets,omitempty"`
	ConfigGenMismatches  uint64 `json:"config_gen_mismatches,omitempty"`
	FIBGenMismatches     uint64 `json:"fib_gen_mismatches,omitempty"`
	UnsupportedPackets   uint64 `json:"unsupported_packets,omitempty"`
	FlowCacheHits        uint64 `json:"flow_cache_hits,omitempty"`
	FlowCacheMisses      uint64 `json:"flow_cache_misses,omitempty"`
	FlowCacheEvictions   uint64 `json:"flow_cache_evictions,omitempty"`
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
	// #hb166 T-6(a): count of V_min suspended drain batches — batches
	// where the fairness brake was OFF because a prior hard-cap armed
	// suspension. VMinSuspendedBatches / VMinThrottleHardCapOverrides is
	// the effective suspension-window-length diagnostic.
	VMinSuspendedBatches  uint64 `json:"v_min_suspended_batches,omitempty"`
	SessionHits           uint64 `json:"session_hits,omitempty"`
	SessionMisses         uint64 `json:"session_misses,omitempty"`
	SessionCreates        uint64 `json:"session_creates,omitempty"`
	SessionExpires        uint64 `json:"session_expires,omitempty"`
	SessionDeltaPending   uint64 `json:"session_delta_pending,omitempty"`
	SessionDeltaGenerated uint64 `json:"session_delta_generated,omitempty"`
	SessionDeltaDropped   uint64 `json:"session_delta_dropped,omitempty"`
	SessionDeltaDrained   uint64 `json:"session_delta_drained,omitempty"`
	PolicyDeniedPackets   uint64 `json:"policy_denied_packets,omitempty"`
	// #3326: host-bound packets dropped by the zone host-inbound admission
	// gate. Mirrored into dataplane.GlobalCtrHostInboundDeny by
	// syncBPFCountersLocked so REST (host_inbound_denies), Prometheus
	// (xpf_host_inbound_denies_total), and `show security flow statistics`
	// reflect the drop. Before #3326 these denies were never counted.
	HostInboundDeniedPackets uint64 `json:"host_inbound_denied_packets,omitempty"`
	ScreenDrops              uint64 `json:"screen_drops,omitempty"`
	// ScreenReasonDrops (#3343): per-screen-reason DROP counters, one element per
	// dataplane.ScreenReasonCounters ordinal (the userspace-dp wire array). The
	// manager sums these across bindings and pushes each ordinal's delta into its
	// dataplane.GlobalCtrScreen* index so the per-reason screen-statistics rows
	// (CLI alarms / show security screen / flow statistics, gRPC, REST,
	// Prometheus) stop reading a permanent 0. The Rust side always serializes the
	// fixed-length array, so the key is present even when all-zero.
	ScreenReasonDrops          []uint64 `json:"screen_reason_drops,omitempty"`
	SYNCookieChallenges        uint64   `json:"syn_cookie_challenges,omitempty"`
	SYNCookieSecretUnavailable uint64   `json:"syn_cookie_secret_unavailable,omitempty"`
	SYNCookieSynAckSent        uint64   `json:"syn_cookie_syn_ack_sent,omitempty"`
	SYNCookieAckRstSent        uint64   `json:"syn_cookie_ack_rst_sent,omitempty"`
	SYNCookieReplyBudgetDrops  uint64   `json:"syn_cookie_reply_budget_drops,omitempty"`
	SYNCookieAckValid          uint64   `json:"syn_cookie_ack_valid,omitempty"`
	SYNCookieAckInvalid        uint64   `json:"syn_cookie_ack_invalid,omitempty"`
	SYNCookieBypass            uint64   `json:"syn_cookie_bypass,omitempty"`
	// #2089: policy `reject` action — RST/ICMP-unreachable replies sent,
	// and replies suppressed due to TX-frame budget exhaustion.
	PolicyRejectSent uint64 `json:"policy_reject_sent,omitempty"`
	// #2521: firewall-filter `then reject` — RST/ICMP-unreachable replies
	// sent (mirrors PolicyRejectSent). #3615 (L04/L05): the budget and
	// output-filter suppression legs are now SPLIT by source
	// (FilterRejectReplyBudgetDrops / FilterRejectOutputFilterDrops) so a
	// filter-reject drop is not conflated with a policy-reject drop; the
	// parse-error leg stays source-neutral. omitempty + Rust serde `default`
	// keep cross-version wire safety.
	FilterRejectSent             uint64 `json:"filter_reject_sent,omitempty"`
	PolicyRejectReplyBudgetDrops uint64 `json:"policy_reject_reply_budget_drops,omitempty"`
	// #3615 (L04): FILTER-`reject` reply TX-frame-budget suppression, split
	// from PolicyRejectReplyBudgetDrops (which is now policy-reject-only).
	FilterRejectReplyBudgetDrops uint64 `json:"filter_reject_reply_budget_drops,omitempty"`
	// #3661: reject replies dropped because the shared per-reason rate-limit
	// token bucket (REJECT_BUCKET) was empty, split by source. The aggregate
	// ProcessStatus.RejectRateLimitedTotal stays source-neutral for
	// back-compat; policy+filter here sum to it exactly (the Reject bucket has
	// one consume site). omitempty + the Rust serde `default` keep
	// cross-version wire safety (an older helper omits them → 0).
	PolicyRejectRateLimitDrops uint64 `json:"policy_reject_rate_limit_drops,omitempty"`
	FilterRejectRateLimitDrops uint64 `json:"filter_reject_rate_limit_drops,omitempty"`
	// #2238: locally-generated replies (Time Exceeded, policy-reject
	// RST/ICMP-unreachable, SYN-cookie SYN-ACK/ACK-RST) are now classified by
	// their OWN egress 5-tuple + egress interface. An output firewall filter
	// terminal discard/reject (or three-color policer) on the egress
	// interface drops the reply; these per-leg counters make that
	// (operator-installed) drop attributable. GeneratedReplyClassifyParseErrors
	// counts fail-closed drops when the generated bytes could not be re-parsed
	// (§6.2). omitempty + Rust serde `default` keep cross-version wire safety.
	TimeExceededOutputFilterDrops uint64 `json:"time_exceeded_output_filter_drops,omitempty"`
	PolicyRejectOutputFilterDrops uint64 `json:"policy_reject_output_filter_drops,omitempty"`
	// #3615 (L05): FILTER-`reject` reply egress-output-filter suppression,
	// split from PolicyRejectOutputFilterDrops (now policy-reject-only).
	FilterRejectOutputFilterDrops uint64 `json:"filter_reject_output_filter_drops,omitempty"`
	SYNCookieOutputFilterDrops    uint64 `json:"syn_cookie_output_filter_drops,omitempty"`
	// #2328: egress-MTU PTB / Frag-Needed replies (#2301 PMTUD path) are now
	// classified by the PTB's OWN egress tuple like the three siblings above,
	// so an output firewall filter discard/reject drops the PTB. Per-leg.
	PTBOutputFilterDrops              uint64 `json:"ptb_output_filter_drops,omitempty"`
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
	Nat64NoSourcePool uint64 `json:"nat64_no_source_pool,omitempty"`
	// #4520: transient NAT64 pool-exhaustion drops — a prefix matched and its
	// pool was non-empty, but no free translated port could be allocated
	// (AllocatorExhausted). The transient sibling of Nat64NoSourcePool
	// (config/empty): a full pool under load (add capacity) is now
	// distinguishable from a misconfigured/empty pool (fix config). omitempty +
	// the Rust serde `default` keep cross-version wire safety (an older helper
	// omits it → 0).
	Nat64PoolExhausted uint64 `json:"nat64_pool_exhausted,omitempty"`
	// #2562: fail-closed NAT64 fragment drops — a datagram dropped because it is
	// a fragment NAT64 cannot safely translate: a non-first fragment (no L4
	// header) or a real ICMP/ICMPv6 fragment (the ICMP checksum covers the whole
	// datagram and cannot be recomputed from a single fragment). The
	// observable-drop half of #2562; the stateful frag-association cache (#3291
	// stage 4) that would let real fragments traverse end-to-end is deferred.
	// omitempty + the Rust serde `default` keep cross-version wire safety (an
	// older helper omits it → 0).
	Nat64FragDropped uint64 `json:"nat64_frag_dropped,omitempty"`
	// #5623: fail-closed NAT64 SOURCE-ineligibility drops — an incoming IPv6
	// packet whose SOURCE lies within a configured Pref64 (a looping/synthesized
	// "already-translated" source, the RFC 6146 §5 hairpin construction — plus
	// the lower/upper Pref64 boundary and any embedded non-global v4) dropped
	// BEFORE route lookup, policy, or allocate_source per RFC 6146 §3.5. Distinct
	// from the pool counters above (config/capacity on an ELIGIBLE flow); this is
	// an input-validation reject. omitempty + the Rust serde `default` keep
	// cross-version wire safety (an older helper omits it → 0).
	Nat64IneligibleSource uint64 `json:"nat64_ineligible_source,omitempty"`
	// #5625: fail-closed NAT64 EXTENSION-HEADER ineligibility drops — a v6→v4
	// forward translation rejected because the IPv6 packet carried an
	// Authentication Header (51), an ACTIVE Routing header (43, Segments
	// Left > 0), or a Mobility (135) / HIP (139) / Shim6 (140) header, none of
	// which a stateless NAT64 translation can carry to IPv4 (RFC 7915 §5.1 /
	// §5.1.1) — translating would strip the active extension semantics or break
	// AH authentication. Distinct from the source/pool/fragment counters; this
	// is an ext-header input reject. omitempty + the Rust serde `default` keep
	// cross-version wire safety (an older helper omits it → 0).
	Nat64ExthdrIneligible uint64 `json:"nat64_exthdr_ineligible,omitempty"`
	// #4477: source-NAT allocation failures (a source-NAT rule matched but no
	// translated mapping could be allocated — missing/empty/invalid/exhausted
	// pool, wrong family, or a non-first fragment on a port-translating rule);
	// the packet is dropped. Summed across bindings and pushed into
	// dataplane.GlobalCtrNATAllocFail (and, with the other enforcement drops,
	// GlobalCtrDrops) by syncBPFCountersLocked so `show security flow
	// statistics` ("NAT allocation failures" / "Packets dropped"), REST
	// (nat_alloc_fails / drops), and Prometheus (xpf_nat_alloc_fails_total /
	// xpf_drops_total) stop reading a permanent 0. omitempty + the Rust serde
	// `default` keep cross-version wire safety (an older helper omits it → 0).
	NatAllocFail uint64 `json:"nat_alloc_fail,omitempty"`
	// #6122: fail-closed drops of an ordinary same-family NAT'd (SNAT /
	// static-NAT / DNAT / NPTv6) NON-FIRST fragment that MISSED the
	// fragment-association cache. Forwarding it untranslated would leak the
	// internal source (SNAT / NPTv6) or the pre-NAT destination (DNAT), so the
	// permitted-but-untranslatable fragment is dropped fail-closed. The
	// same-family sibling of Nat64FragDropped; a plain (no-NAT) fragment matches
	// no rule and is NOT counted here, so ordinary fragmented forwarding is
	// preserved. omitempty + the Rust serde `default` keep cross-version wire
	// safety (an older helper omits it → 0).
	NatFragUntranslatedDropped     uint64 `json:"nat_frag_untranslated_dropped,omitempty"`
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
	// #hb166 T-6(a): V_min suspended-batch count (per_binding lean view).
	VMinSuspendedBatches uint64 `json:"v_min_suspended_batches,omitempty"`
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
