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
	Type     string               `json:"type"`
	Snapshot *ConfigSnapshot      `json:"snapshot,omitempty"`
	Queue    *QueueControlRequest `json:"queue,omitempty"`
}

type ControlResponse struct {
	OK     bool           `json:"ok"`
	Error  string         `json:"error,omitempty"`
	Status *ProcessStatus `json:"status,omitempty"`
}

type ConfigSnapshot struct {
	Version     int                    `json:"version"`
	Generation  uint64                 `json:"generation"`
	GeneratedAt time.Time              `json:"generated_at"`
	Summary     SnapshotSummary        `json:"summary"`
	MapPins     UserspaceMapPins       `json:"map_pins"`
	Interfaces  []InterfaceSnapshot    `json:"interfaces,omitempty"`
	Routes      []RouteSnapshot        `json:"routes,omitempty"`
	Config      *config.Config         `json:"config,omitempty"`
	Userspace   config.UserspaceConfig `json:"userspace"`
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
	Name            string `json:"name"`
	LinuxName       string `json:"linux_name,omitempty"`
	Ifindex         int    `json:"ifindex,omitempty"`
	RXQueues        int    `json:"rx_queues,omitempty"`
	LocalFabric     string `json:"local_fabric_member,omitempty"`
	RedundancyGroup int    `json:"redundancy_group,omitempty"`
	UnitCount       int    `json:"unit_count"`
	Tunnel          bool   `json:"tunnel"`
}

type RouteSnapshot struct {
	Table       string   `json:"table"`
	Family      string   `json:"family"`
	Destination string   `json:"destination"`
	NextHops    []string `json:"next_hops,omitempty"`
	Discard     bool     `json:"discard"`
	NextTable   string   `json:"next_table,omitempty"`
}

type UserspaceMapPins struct {
	Ctrl       string `json:"ctrl,omitempty"`
	QueueReady string `json:"queue_ready,omitempty"`
	XSK        string `json:"xsk,omitempty"`
}

type ProcessStatus struct {
	PID                    int           `json:"pid"`
	StartedAt              time.Time     `json:"started_at"`
	ControlSocket          string        `json:"control_socket"`
	StateFile              string        `json:"state_file"`
	Workers                int           `json:"workers"`
	RingEntries            int           `json:"ring_entries"`
	HelperMode             string        `json:"helper_mode"`
	IOUringPlanned         bool          `json:"io_uring_planned"`
	Enabled                bool          `json:"enabled"`
	LastSnapshotGeneration uint64        `json:"last_snapshot_generation"`
	LastSnapshotAt         time.Time     `json:"last_snapshot_at,omitempty"`
	WorkerHeartbeats       []time.Time   `json:"worker_heartbeats,omitempty"`
	Queues                 []QueueStatus `json:"queues,omitempty"`
}

type QueueControlRequest struct {
	QueueID    uint32 `json:"queue_id"`
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
