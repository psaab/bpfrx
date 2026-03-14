package userspace

import (
	"time"

	"github.com/psaab/bpfrx/pkg/config"
)

const (
	ProtocolVersion = 1
	TypeUserspace   = "userspace"
)

type ControlRequest struct {
	Type          string                    `json:"type"`
	Snapshot      *ConfigSnapshot           `json:"snapshot,omitempty"`
	Forwarding    *ForwardingControlRequest `json:"forwarding,omitempty"`
	HAState       *HAStateUpdateRequest     `json:"ha_state,omitempty"`
	Queue         *QueueControlRequest      `json:"queue,omitempty"`
	Binding       *BindingControlRequest    `json:"binding,omitempty"`
	Packet        *InjectPacketRequest      `json:"packet,omitempty"`
	SessionSync   *SessionSyncRequest       `json:"session_sync,omitempty"`
	SessionDeltas *SessionDeltaDrainRequest `json:"session_deltas,omitempty"`
}

type ControlResponse struct {
	OK            bool               `json:"ok"`
	Error         string             `json:"error,omitempty"`
	Status        *ProcessStatus     `json:"status,omitempty"`
	SessionDeltas []SessionDeltaInfo `json:"session_deltas,omitempty"`
}

type ConfigSnapshot struct {
	Version       int                     `json:"version"`
	Generation    uint64                  `json:"generation"`
	FIBGeneration uint32                  `json:"fib_generation,omitempty"`
	GeneratedAt   time.Time               `json:"generated_at"`
	Summary       SnapshotSummary         `json:"summary"`
	Capabilities  UserspaceCapabilities   `json:"capabilities"`
	MapPins       UserspaceMapPins        `json:"map_pins"`
	Zones         []ZoneSnapshot          `json:"zones,omitempty"`
	Interfaces    []InterfaceSnapshot     `json:"interfaces,omitempty"`
	Fabrics       []FabricSnapshot        `json:"fabrics,omitempty"`
	Neighbors     []NeighborSnapshot      `json:"neighbors,omitempty"`
	Routes        []RouteSnapshot         `json:"routes,omitempty"`
	Flow          FlowSnapshot            `json:"flow,omitempty"`
	DefaultPolicy string                  `json:"default_policy,omitempty"`
	Policies      []PolicyRuleSnapshot    `json:"policies,omitempty"`
	SourceNAT      []SourceNATRuleSnapshot      `json:"source_nat_rules,omitempty"`
	StaticNAT      []StaticNATRuleSnapshot      `json:"static_nat_rules,omitempty"`
	DestinationNAT []DestinationNATRuleSnapshot `json:"destination_nat_rules,omitempty"`
	NAT64          []NAT64RuleSnapshot          `json:"nat64_rules,omitempty"`
	Config        *config.Config          `json:"config,omitempty"`
	Userspace     config.UserspaceConfig  `json:"userspace"`
}

type FlowSnapshot struct {
	AllowDNSReply     bool `json:"allow_dns_reply,omitempty"`
	AllowEmbeddedICMP bool `json:"allow_embedded_icmp,omitempty"`
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
	Name            string                     `json:"name"`
	Zone            string                     `json:"zone,omitempty"`
	LinuxName       string                     `json:"linux_name,omitempty"`
	ParentLinuxName string                     `json:"parent_linux_name,omitempty"`
	Ifindex         int                        `json:"ifindex,omitempty"`
	ParentIfindex   int                        `json:"parent_ifindex,omitempty"`
	RXQueues        int                        `json:"rx_queues,omitempty"`
	VLANID          int                        `json:"vlan_id,omitempty"`
	LocalFabric     string                     `json:"local_fabric_member,omitempty"`
	RedundancyGroup int                        `json:"redundancy_group,omitempty"`
	UnitCount       int                        `json:"unit_count"`
	Tunnel          bool                       `json:"tunnel"`
	MTU             int                        `json:"mtu,omitempty"`
	HardwareAddr    string                     `json:"hardware_addr,omitempty"`
	Addresses       []InterfaceAddressSnapshot `json:"addresses,omitempty"`
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
}

type SourceNATRuleSnapshot struct {
	Name                 string   `json:"name"`
	FromZone             string   `json:"from_zone,omitempty"`
	ToZone               string   `json:"to_zone,omitempty"`
	SourceAddresses      []string `json:"source_addresses,omitempty"`
	DestinationAddresses []string `json:"destination_addresses,omitempty"`
	InterfaceMode        bool     `json:"interface_mode,omitempty"`
	Off                  bool     `json:"off,omitempty"`
	PoolName             string   `json:"pool_name,omitempty"`
}

type StaticNATRuleSnapshot struct {
	Name       string `json:"name"`
	FromZone   string `json:"from_zone,omitempty"`
	ExternalIP string `json:"external_ip"`
	InternalIP string `json:"internal_ip"`
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
}

// NAT64RuleSnapshot captures a NAT64 prefix and its IPv4 source pool for the
// userspace dataplane.
type NAT64RuleSnapshot struct {
	Name          string   `json:"name"`
	Prefix        string   `json:"prefix"`         // e.g. "64:ff9b::/96"
	PoolAddresses []string `json:"pool_addresses"` // resolved IPv4 pool addresses
}

type PolicyApplicationSnapshot struct {
	Name            string `json:"name"`
	Protocol        string `json:"protocol,omitempty"`
	SourcePort      string `json:"source_port,omitempty"`
	DestinationPort string `json:"destination_port,omitempty"`
}

type PolicyRuleSnapshot struct {
	Name                 string                      `json:"name"`
	FromZone             string                      `json:"from_zone,omitempty"`
	ToZone               string                      `json:"to_zone,omitempty"`
	SourceAddresses      []string                    `json:"source_addresses,omitempty"`
	DestinationAddresses []string                    `json:"destination_addresses,omitempty"`
	Applications         []string                    `json:"applications,omitempty"`
	ApplicationTerms     []PolicyApplicationSnapshot `json:"application_terms,omitempty"`
	Action               string                      `json:"action,omitempty"`
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
	Ctrl      string `json:"ctrl,omitempty"`
	Bindings  string `json:"bindings,omitempty"`
	Heartbeat string `json:"heartbeat,omitempty"`
	XSK       string `json:"xsk,omitempty"`
	LocalV4   string `json:"local_v4,omitempty"`
	LocalV6   string `json:"local_v6,omitempty"`
	Sessions  string `json:"sessions,omitempty"`
	Trace     string `json:"trace,omitempty"`
}

type UserspaceCapabilities struct {
	ForwardingSupported bool     `json:"forwarding_supported"`
	UnsupportedReasons  []string `json:"unsupported_reasons,omitempty"`
}

type ProcessStatus struct {
	PID                    int                   `json:"pid"`
	StartedAt              time.Time             `json:"started_at"`
	ControlSocket          string                `json:"control_socket"`
	StateFile              string                `json:"state_file"`
	Workers                int                   `json:"workers"`
	RingEntries            int                   `json:"ring_entries"`
	HelperMode             string                `json:"helper_mode"`
	IOUringPlanned         bool                  `json:"io_uring_planned"`
	IOUringActive          bool                  `json:"io_uring_active,omitempty"`
	IOUringMode            string                `json:"io_uring_mode,omitempty"`
	IOUringLastError       string                `json:"io_uring_last_error,omitempty"`
	Enabled                bool                  `json:"enabled"`
	ForwardingArmed        bool                  `json:"forwarding_armed,omitempty"`
	Capabilities           UserspaceCapabilities `json:"capabilities"`
	LastSnapshotGeneration uint64                `json:"last_snapshot_generation"`
	LastFIBGeneration      uint32                `json:"last_fib_generation,omitempty"`
	LastSnapshotAt         time.Time             `json:"last_snapshot_at,omitempty"`
	InterfaceAddresses     int                   `json:"interface_addresses,omitempty"`
	NeighborEntries        int                   `json:"neighbor_entries,omitempty"`
	RouteEntries           int                   `json:"route_entries,omitempty"`
	WorkerHeartbeats       []time.Time           `json:"worker_heartbeats,omitempty"`
	HAGroups               []HAGroupStatus       `json:"ha_groups,omitempty"`
	Fabrics                []FabricSnapshot      `json:"fabrics,omitempty"`
	Queues                 []QueueStatus         `json:"queues,omitempty"`
	Bindings               []BindingStatus       `json:"bindings,omitempty"`
	RecentSessionDeltas    []SessionDeltaInfo    `json:"recent_session_deltas,omitempty"`
	RecentExceptions       []ExceptionStatus     `json:"recent_exceptions,omitempty"`
	LastResolution         *PacketResolution     `json:"last_resolution,omitempty"`
	SlowPath               SlowPathStatus        `json:"slow_path,omitempty"`
}

type HAStateUpdateRequest struct {
	Groups []HAGroupStatus `json:"groups,omitempty"`
}

type HAGroupStatus struct {
	RGID              int    `json:"rg_id"`
	Active            bool   `json:"active"`
	WatchdogTimestamp uint64 `json:"watchdog_timestamp,omitempty"`
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
	Slot                  uint32    `json:"slot"`
	QueueID               uint32    `json:"queue_id"`
	WorkerID              uint32    `json:"worker_id"`
	Interface             string    `json:"interface,omitempty"`
	Ifindex               int       `json:"ifindex,omitempty"`
	Registered            bool      `json:"registered"`
	Armed                 bool      `json:"armed"`
	Ready                 bool      `json:"ready"`
	Bound                 bool      `json:"bound"`
	XSKRegistered         bool      `json:"xsk_registered"`
	XSKBindMode           string    `json:"xsk_bind_mode,omitempty"`
	ZeroCopy              bool      `json:"zero_copy,omitempty"`
	SocketFD              int       `json:"socket_fd,omitempty"`
	RXPackets             uint64    `json:"rx_packets,omitempty"`
	RXBytes               uint64    `json:"rx_bytes,omitempty"`
	RXBatches             uint64    `json:"rx_batches,omitempty"`
	RXWakeups             uint64    `json:"rx_wakeups,omitempty"`
	MetadataPackets       uint64    `json:"metadata_packets,omitempty"`
	MetadataErrors        uint64    `json:"metadata_errors,omitempty"`
	ValidatedPackets      uint64    `json:"validated_packets,omitempty"`
	ValidatedBytes        uint64    `json:"validated_bytes,omitempty"`
	LocalDeliveryPackets  uint64    `json:"local_delivery_packets,omitempty"`
	ForwardCandidatePkts  uint64    `json:"forward_candidate_packets,omitempty"`
	RouteMissPackets      uint64    `json:"route_miss_packets,omitempty"`
	NeighborMissPackets   uint64    `json:"neighbor_miss_packets,omitempty"`
	DiscardRoutePackets   uint64    `json:"discard_route_packets,omitempty"`
	NextTablePackets      uint64    `json:"next_table_packets,omitempty"`
	ExceptionPackets      uint64    `json:"exception_packets,omitempty"`
	ConfigGenMismatches   uint64    `json:"config_gen_mismatches,omitempty"`
	FIBGenMismatches      uint64    `json:"fib_gen_mismatches,omitempty"`
	UnsupportedPackets    uint64    `json:"unsupported_packets,omitempty"`
	SessionHits           uint64    `json:"session_hits,omitempty"`
	SessionMisses         uint64    `json:"session_misses,omitempty"`
	SessionCreates        uint64    `json:"session_creates,omitempty"`
	SessionExpires        uint64    `json:"session_expires,omitempty"`
	SessionDeltaPending   uint64    `json:"session_delta_pending,omitempty"`
	SessionDeltaGenerated uint64    `json:"session_delta_generated,omitempty"`
	SessionDeltaDropped   uint64    `json:"session_delta_dropped,omitempty"`
	SessionDeltaDrained   uint64    `json:"session_delta_drained,omitempty"`
	PolicyDeniedPackets   uint64    `json:"policy_denied_packets,omitempty"`
	SNATPackets           uint64    `json:"snat_packets,omitempty"`
	DNATPackets           uint64    `json:"dnat_packets,omitempty"`
	SlowPathPackets       uint64    `json:"slow_path_packets,omitempty"`
	SlowPathBytes         uint64    `json:"slow_path_bytes,omitempty"`
	SlowPathDrops         uint64    `json:"slow_path_drops,omitempty"`
	SlowPathRateLimited   uint64    `json:"slow_path_rate_limited,omitempty"`
	KernelRXDropped       uint64    `json:"kernel_rx_dropped,omitempty"`
	KernelRXInvalidDescs  uint64    `json:"kernel_rx_invalid_descs,omitempty"`
	TXPackets             uint64    `json:"tx_packets,omitempty"`
	TXBytes               uint64    `json:"tx_bytes,omitempty"`
	TXErrors              uint64    `json:"tx_errors,omitempty"`
	LastHeartbeat         time.Time `json:"last_heartbeat,omitempty"`
	LastError             string    `json:"last_error,omitempty"`
	LastChange            time.Time `json:"last_change,omitempty"`
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
}

type InjectPacketRequest struct {
	Slot             uint32 `json:"slot"`
	PacketLength     uint32 `json:"packet_length,omitempty"`
	AddrFamily       uint8  `json:"addr_family,omitempty"`
	Protocol         uint8  `json:"protocol,omitempty"`
	ConfigGeneration uint64 `json:"config_generation,omitempty"`
	FIBGeneration    uint32 `json:"fib_generation,omitempty"`
	MetadataValid    bool   `json:"metadata_valid"`
	DestinationIP    string `json:"destination_ip,omitempty"`
	EmitOnWire       bool   `json:"emit_on_wire,omitempty"`
}

type SessionDeltaDrainRequest struct {
	Max uint32 `json:"max,omitempty"`
}

type SessionSyncRequest struct {
	Operation     string `json:"operation,omitempty"`
	AddrFamily    uint8  `json:"addr_family,omitempty"`
	Protocol      uint8  `json:"protocol,omitempty"`
	SrcIP         string `json:"src_ip,omitempty"`
	DstIP         string `json:"dst_ip,omitempty"`
	SrcPort       uint16 `json:"src_port,omitempty"`
	DstPort       uint16 `json:"dst_port,omitempty"`
	IngressZone   string `json:"ingress_zone,omitempty"`
	EgressZone    string `json:"egress_zone,omitempty"`
	OwnerRGID     int    `json:"owner_rg_id,omitempty"`
	EgressIfindex int    `json:"egress_ifindex,omitempty"`
	TXIfindex     int    `json:"tx_ifindex,omitempty"`
	TXVLANID      uint16 `json:"tx_vlan_id,omitempty"`
	NextHop       string `json:"next_hop,omitempty"`
	NeighborMAC   string `json:"neighbor_mac,omitempty"`
	SrcMAC        string `json:"src_mac,omitempty"`
	NATSrcIP      string `json:"nat_src_ip,omitempty"`
	NATDstIP      string `json:"nat_dst_ip,omitempty"`
	NATSrcPort    uint16 `json:"nat_src_port,omitempty"`
	NATDstPort    uint16 `json:"nat_dst_port,omitempty"`
	IsReverse     bool   `json:"is_reverse,omitempty"`
}

type SessionDeltaInfo struct {
	Timestamp     time.Time `json:"timestamp"`
	Slot          uint32    `json:"slot"`
	QueueID       uint32    `json:"queue_id"`
	WorkerID      uint32    `json:"worker_id"`
	Interface     string    `json:"interface,omitempty"`
	Ifindex       int       `json:"ifindex,omitempty"`
	Event         string    `json:"event"`
	AddrFamily    uint8     `json:"addr_family,omitempty"`
	Protocol      uint8     `json:"protocol,omitempty"`
	SrcIP         string    `json:"src_ip,omitempty"`
	DstIP         string    `json:"dst_ip,omitempty"`
	SrcPort       uint16    `json:"src_port,omitempty"`
	DstPort       uint16    `json:"dst_port,omitempty"`
	IngressZone   string    `json:"ingress_zone,omitempty"`
	EgressZone    string    `json:"egress_zone,omitempty"`
	OwnerRGID     int       `json:"owner_rg_id,omitempty"`
	EgressIfindex int       `json:"egress_ifindex,omitempty"`
	NextHop       string    `json:"next_hop,omitempty"`
	NATSrcIP      string    `json:"nat_src_ip,omitempty"`
	NATDstIP      string    `json:"nat_dst_ip,omitempty"`
	NATSrcPort    uint16    `json:"nat_src_port,omitempty"`
	NATDstPort    uint16    `json:"nat_dst_port,omitempty"`
}
