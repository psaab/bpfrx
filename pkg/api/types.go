// Package api implements the HTTP REST API and Prometheus metrics endpoint.
package api

// Response is the standard JSON response envelope.
type Response struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

// StatusResponse holds daemon status information.
type StatusResponse struct {
	Uptime          string `json:"uptime"`
	DataplaneLoaded bool   `json:"dataplane_loaded"`
	ConfigLoaded    bool   `json:"config_loaded"`
	ZoneCount       int    `json:"zone_count"`
	SessionCount    int    `json:"session_count"`
}

// GlobalStats holds all global counter values.
type GlobalStats struct {
	RxPackets       uint64 `json:"rx_packets"`
	TxPackets       uint64 `json:"tx_packets"`
	Drops           uint64 `json:"drops"`
	SessionsCreated uint64 `json:"sessions_created"`
	SessionsClosed  uint64 `json:"sessions_closed"`
	ScreenDrops     uint64 `json:"screen_drops"`
	PolicyDenies    uint64 `json:"policy_denies"`
	NATAllocFails   uint64 `json:"nat_alloc_failures"`
	HostInboundDeny uint64 `json:"host_inbound_denies"`
	TCEgressPackets uint64 `json:"tc_egress_packets"`
}

// InterfaceStats holds per-interface counter values.
type InterfaceStats struct {
	Name      string `json:"name"`
	Ifindex   int    `json:"ifindex"`
	Zone      string `json:"zone,omitempty"`
	RxPackets uint64 `json:"rx_packets"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxBytes   uint64 `json:"tx_bytes"`
}

// ZoneInfo holds zone configuration and counter data.
type ZoneInfo struct {
	Name           string   `json:"name"`
	ID             uint16   `json:"id"`
	ScreenProfile  string   `json:"screen_profile,omitempty"`
	Interfaces     []string `json:"interfaces"`
	HostInbound    []string `json:"host_inbound_services"`
	IngressPackets uint64   `json:"ingress_packets"`
	IngressBytes   uint64   `json:"ingress_bytes"`
	EgressPackets  uint64   `json:"egress_packets"`
	EgressBytes    uint64   `json:"egress_bytes"`
}

// PolicyInfo holds policy configuration data.
type PolicyInfo struct {
	FromZone string       `json:"from_zone"`
	ToZone   string       `json:"to_zone"`
	Rules    []PolicyRule `json:"rules"`
}

// PolicyRule holds a single policy rule with counters.
type PolicyRule struct {
	Name         string   `json:"name"`
	Action       string   `json:"action"`
	SrcAddresses []string `json:"src_addresses"`
	DstAddresses []string `json:"dst_addresses"`
	Applications []string `json:"applications"`
	Log          bool     `json:"log"`
	Count        bool     `json:"count"`
	HitPackets   uint64   `json:"hit_packets"`
	HitBytes     uint64   `json:"hit_bytes"`
}

// SessionEntry holds a single session table entry.
type SessionEntry struct {
	SrcAddr    string `json:"src_addr"`
	DstAddr    string `json:"dst_addr"`
	SrcPort    uint16 `json:"src_port"`
	DstPort    uint16 `json:"dst_port"`
	Protocol   string `json:"protocol"`
	State      string `json:"state"`
	PolicyID   uint32 `json:"policy_id"`
	InZone     uint16 `json:"ingress_zone"`
	OutZone    uint16 `json:"egress_zone"`
	FwdPackets uint64 `json:"fwd_packets"`
	FwdBytes   uint64 `json:"fwd_bytes"`
	RevPackets uint64 `json:"rev_packets"`
	RevBytes   uint64 `json:"rev_bytes"`
	NAT        string `json:"nat,omitempty"`
	Age        int64  `json:"age_seconds"`
	Timeout    uint32 `json:"timeout_seconds"`
}

// SessionListResponse holds paginated session results.
type SessionListResponse struct {
	Total    int            `json:"total"`
	Limit    int            `json:"limit"`
	Offset   int            `json:"offset"`
	Sessions []SessionEntry `json:"sessions"`
}

// SessionSummary holds session table summary stats.
type SessionSummary struct {
	TotalEntries  int `json:"total_entries"`
	ForwardOnly   int `json:"forward_only"`
	Established   int `json:"established"`
	IPv4Sessions  int `json:"ipv4_sessions"`
	IPv6Sessions  int `json:"ipv6_sessions"`
	SNATSessions  int `json:"snat_sessions"`
	DNATSessions  int `json:"dnat_sessions"`
}

// EventEntry holds a single event record.
type EventEntry struct {
	Time         string `json:"time"`
	Type         string `json:"type"`
	SrcAddr      string `json:"src_addr"`
	DstAddr      string `json:"dst_addr"`
	Protocol     string `json:"protocol"`
	Action       string `json:"action"`
	PolicyID     uint32 `json:"policy_id"`
	InZone       uint16 `json:"ingress_zone"`
	OutZone      uint16 `json:"egress_zone"`
	ScreenCheck  string `json:"screen_check,omitempty"`
	SessionPkts  uint64 `json:"session_packets,omitempty"`
	SessionBytes uint64 `json:"session_bytes,omitempty"`
}

// NATSourceInfo holds source NAT configuration.
type NATSourceInfo struct {
	FromZone string `json:"from_zone"`
	ToZone   string `json:"to_zone"`
	Type     string `json:"type"`
	Pool     string `json:"pool,omitempty"`
}

// NATDestInfo holds destination NAT configuration.
type NATDestInfo struct {
	Name        string `json:"name"`
	DstAddr     string `json:"dst_addr"`
	DstPort     uint16 `json:"dst_port,omitempty"`
	TranslateIP string `json:"translate_ip"`
	TranslatePort uint16 `json:"translate_port,omitempty"`
}

// DHCPLeaseInfo holds DHCP lease information.
type DHCPLeaseInfo struct {
	Interface string   `json:"interface"`
	Family    string   `json:"family"`
	Address   string   `json:"address"`
	Gateway   string   `json:"gateway,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	LeaseTime string   `json:"lease_time"`
	Obtained  string   `json:"obtained"`
}

// RouteInfo holds route information.
type RouteInfo struct {
	Destination string `json:"destination"`
	NextHop     string `json:"next_hop,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Preference  int    `json:"preference,omitempty"`
	NextTable   string `json:"next_table,omitempty"`
}

// ScreenInfo holds screen profile information.
type ScreenInfo struct {
	Name   string   `json:"name"`
	Checks []string `json:"checks"`
}

// TextResponse wraps text output from commands.
type TextResponse struct {
	Output string `json:"output"`
}

// NATPoolStatsInfo holds NAT pool statistics.
type NATPoolStatsInfo struct {
	Name           string `json:"name"`
	Address        string `json:"address"`
	TotalPorts     int    `json:"total_ports"`
	UsedPorts      int    `json:"used_ports"`
	AvailablePorts int    `json:"available_ports"`
	Utilization    string `json:"utilization"`
	IsInterface    bool   `json:"is_interface,omitempty"`
}

// NATRuleStatsInfo holds NAT rule counters.
type NATRuleStatsInfo struct {
	RuleSet     string `json:"rule_set"`
	RuleName    string `json:"rule_name"`
	FromZone    string `json:"from_zone"`
	ToZone      string `json:"to_zone"`
	Action      string `json:"action"`
	SrcMatch    string `json:"source_match"`
	DstMatch    string `json:"destination_match"`
	HitPackets  uint64 `json:"hit_packets"`
	HitBytes    uint64 `json:"hit_bytes"`
}

// VRRPInstanceInfo holds VRRP instance information.
type VRRPInstanceInfo struct {
	Interface        string   `json:"interface"`
	GroupID          int      `json:"group_id"`
	State            string   `json:"state"`
	Priority         int      `json:"priority"`
	VirtualAddresses []string `json:"virtual_addresses"`
	Preempt          bool     `json:"preempt"`
}

// VRRPStatusResponse holds VRRP status.
type VRRPStatusResponse struct {
	Instances     []VRRPInstanceInfo `json:"instances"`
	ServiceStatus string             `json:"service_status"`
}

// MatchPoliciesResult holds policy match results.
type MatchPoliciesResult struct {
	Matched      bool     `json:"matched"`
	PolicyName   string   `json:"policy_name,omitempty"`
	Action       string   `json:"action"`
	SrcAddresses []string `json:"src_addresses,omitempty"`
	DstAddresses []string `json:"dst_addresses,omitempty"`
	Applications []string `json:"applications,omitempty"`
}

// ClearSessionsResult holds session clear results.
type ClearSessionsResult struct {
	IPv4Cleared int `json:"ipv4_cleared"`
	IPv6Cleared int `json:"ipv6_cleared"`
}

// DHCPClientIdentifierInfo holds DHCP client identifier information.
type DHCPClientIdentifierInfo struct {
	Interface string `json:"interface"`
	Type      string `json:"type"`
	Display   string `json:"display"`
	Hex       string `json:"hex"`
}

// PingRequest holds parameters for a ping request.
type PingRequest struct {
	Target          string `json:"target"`
	Count           int    `json:"count,omitempty"`
	Source          string `json:"source,omitempty"`
	Size            int    `json:"size,omitempty"`
	RoutingInstance string `json:"routing_instance,omitempty"`
}

// TracerouteRequest holds parameters for a traceroute request.
type TracerouteRequest struct {
	Target          string `json:"target"`
	Source          string `json:"source,omitempty"`
	RoutingInstance string `json:"routing_instance,omitempty"`
}

// ConfigModeStatus holds config mode status.
type ConfigModeStatus struct {
	InConfigMode   bool `json:"in_config_mode"`
	Dirty          bool `json:"dirty"`
	ConfirmPending bool `json:"confirm_pending"`
}

// ConfigSetRequest holds a config set/delete input.
type ConfigSetRequest struct {
	Input string `json:"input"`
}

// ConfigRollbackRequest holds a rollback index.
type ConfigRollbackRequest struct {
	N int `json:"n"`
}

// HistoryEntry holds a commit history entry.
type HistoryEntry struct {
	Index     int    `json:"index"`
	Timestamp string `json:"timestamp"`
}

// ConfigLoadRequest holds a config load request.
type ConfigLoadRequest struct {
	Mode    string `json:"mode"`    // "override", "merge"
	Content string `json:"content"` // config text (hierarchical or set format)
}

// CommitConfirmedRequest holds a commit confirmed request.
type CommitConfirmedRequest struct {
	Minutes int `json:"minutes"`
}

// ClearDHCPIdentifierRequest holds a clear DHCP identifier request.
type ClearDHCPIdentifierRequest struct {
	Interface string `json:"interface"` // empty = clear all
}

// SystemActionRequest holds a system action request.
type SystemActionRequest struct {
	Action string `json:"action"` // "reboot", "halt"
}

// ShowTextRequest holds a show text request.
type ShowTextRequest struct {
	Topic string `json:"topic"`
}

// ZonePairSessionSummary holds session counts aggregated by zone pair.
type ZonePairSessionSummary struct {
	FromZone string `json:"from_zone"`
	ToZone   string `json:"to_zone"`
	TCP      int    `json:"tcp"`
	UDP      int    `json:"udp"`
	ICMP     int    `json:"icmp"`
	Other    int    `json:"other"`
	Total    int    `json:"total"`
}

// BufferInfo holds BPF map utilization information.
type BufferInfo struct {
	Name         string  `json:"name"`
	Type         string  `json:"type"`
	MaxEntries   int     `json:"max_entries"`
	UsedCount    int     `json:"used_count"`
	UsagePercent float64 `json:"usage_percent"`
	Status       string  `json:"status"`
}

// ConfigSearchResult holds a single config search match.
type ConfigSearchResult struct {
	LineNumber int    `json:"line_number"`
	Line       string `json:"line"`
}
