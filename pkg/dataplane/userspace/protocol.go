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
	Type     string                 `json:"type"`
	Snapshot *ConfigSnapshot        `json:"snapshot,omitempty"`
	Queue    *QueueControlRequest   `json:"queue,omitempty"`
	Binding  *BindingControlRequest `json:"binding,omitempty"`
}

type ControlResponse struct {
	OK     bool           `json:"ok"`
	Error  string         `json:"error,omitempty"`
	Status *ProcessStatus `json:"status,omitempty"`
}

type ConfigSnapshot struct {
	Version       int                    `json:"version"`
	Generation    uint64                 `json:"generation"`
	FIBGeneration uint32                 `json:"fib_generation,omitempty"`
	GeneratedAt   time.Time              `json:"generated_at"`
	Summary       SnapshotSummary        `json:"summary"`
	MapPins       UserspaceMapPins       `json:"map_pins"`
	Interfaces    []InterfaceSnapshot    `json:"interfaces,omitempty"`
	Neighbors     []NeighborSnapshot     `json:"neighbors,omitempty"`
	Routes        []RouteSnapshot        `json:"routes,omitempty"`
	Config        *config.Config         `json:"config,omitempty"`
	Userspace     config.UserspaceConfig `json:"userspace"`
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
	Name            string                     `json:"name"`
	LinuxName       string                     `json:"linux_name,omitempty"`
	Ifindex         int                        `json:"ifindex,omitempty"`
	RXQueues        int                        `json:"rx_queues,omitempty"`
	LocalFabric     string                     `json:"local_fabric_member,omitempty"`
	RedundancyGroup int                        `json:"redundancy_group,omitempty"`
	UnitCount       int                        `json:"unit_count"`
	Tunnel          bool                       `json:"tunnel"`
	MTU             int                        `json:"mtu,omitempty"`
	HardwareAddr    string                     `json:"hardware_addr,omitempty"`
	Addresses       []InterfaceAddressSnapshot `json:"addresses,omitempty"`
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
	Ctrl     string `json:"ctrl,omitempty"`
	Bindings string `json:"bindings,omitempty"`
	XSK      string `json:"xsk,omitempty"`
}

type ProcessStatus struct {
	PID                    int             `json:"pid"`
	StartedAt              time.Time       `json:"started_at"`
	ControlSocket          string          `json:"control_socket"`
	StateFile              string          `json:"state_file"`
	Workers                int             `json:"workers"`
	RingEntries            int             `json:"ring_entries"`
	HelperMode             string          `json:"helper_mode"`
	IOUringPlanned         bool            `json:"io_uring_planned"`
	Enabled                bool            `json:"enabled"`
	LastSnapshotGeneration uint64          `json:"last_snapshot_generation"`
	LastFIBGeneration      uint32          `json:"last_fib_generation,omitempty"`
	LastSnapshotAt         time.Time       `json:"last_snapshot_at,omitempty"`
	InterfaceAddresses     int             `json:"interface_addresses,omitempty"`
	NeighborEntries        int             `json:"neighbor_entries,omitempty"`
	RouteEntries           int             `json:"route_entries,omitempty"`
	WorkerHeartbeats       []time.Time     `json:"worker_heartbeats,omitempty"`
	Queues                 []QueueStatus   `json:"queues,omitempty"`
	Bindings               []BindingStatus `json:"bindings,omitempty"`
}

type QueueControlRequest struct {
	QueueID    uint32 `json:"queue_id"`
	Registered bool   `json:"registered"`
	Ready      bool   `json:"ready"`
}

type BindingControlRequest struct {
	Slot       uint32 `json:"slot"`
	Registered bool   `json:"registered"`
	Ready      bool   `json:"ready"`
}

type QueueStatus struct {
	QueueID    uint32    `json:"queue_id"`
	WorkerID   uint32    `json:"worker_id"`
	Interfaces []string  `json:"interfaces,omitempty"`
	Registered bool      `json:"registered"`
	Ready      bool      `json:"ready"`
	LastChange time.Time `json:"last_change,omitempty"`
}

type BindingStatus struct {
	Slot                 uint32    `json:"slot"`
	QueueID              uint32    `json:"queue_id"`
	WorkerID             uint32    `json:"worker_id"`
	Interface            string    `json:"interface,omitempty"`
	Ifindex              int       `json:"ifindex,omitempty"`
	Registered           bool      `json:"registered"`
	Ready                bool      `json:"ready"`
	Bound                bool      `json:"bound"`
	XSKRegistered        bool      `json:"xsk_registered"`
	SocketFD             int       `json:"socket_fd,omitempty"`
	RXPackets            uint64    `json:"rx_packets,omitempty"`
	RXBytes              uint64    `json:"rx_bytes,omitempty"`
	RXBatches            uint64    `json:"rx_batches,omitempty"`
	RXWakeups            uint64    `json:"rx_wakeups,omitempty"`
	MetadataPackets      uint64    `json:"metadata_packets,omitempty"`
	MetadataErrors       uint64    `json:"metadata_errors,omitempty"`
	ValidatedPackets     uint64    `json:"validated_packets,omitempty"`
	ValidatedBytes       uint64    `json:"validated_bytes,omitempty"`
	ExceptionPackets     uint64    `json:"exception_packets,omitempty"`
	ConfigGenMismatches  uint64    `json:"config_gen_mismatches,omitempty"`
	FIBGenMismatches     uint64    `json:"fib_gen_mismatches,omitempty"`
	UnsupportedPackets   uint64    `json:"unsupported_packets,omitempty"`
	KernelRXDropped      uint64    `json:"kernel_rx_dropped,omitempty"`
	KernelRXInvalidDescs uint64    `json:"kernel_rx_invalid_descs,omitempty"`
	LastError            string    `json:"last_error,omitempty"`
	LastChange           time.Time `json:"last_change,omitempty"`
}
