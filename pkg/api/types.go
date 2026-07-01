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
	// HostInboundKernelDenies is the aggregate of the kernel nftables
	// host-inbound DROP counters across all zones/families (#3361). This is the
	// PRIMARY host-inbound enforcement path and is DISTINCT from
	// HostInboundDeny (the userspace-dp #3326 path) — they are not double
	// counts. Best-effort: a netlink read failure leaves this 0 (the canonical
	// per-zone/family signal is the xpf_host_inbound_kernel_denies_total
	// Prometheus metric, which omits the series on a read error rather than
	// reporting a misleading 0).
	HostInboundKernelDenies uint64 `json:"host_inbound_kernel_denies"`
	HostInboundAllowed      uint64 `json:"host_inbound_allowed"`
	NAT64Translations       uint64 `json:"nat64_translations"`
	TCEgressPackets         uint64 `json:"tc_egress_packets"`
	FabricRedirects         uint64 `json:"fabric_redirects"`
	FabricFwdDrops          uint64 `json:"fabric_fwd_drops"`
	FlowCacheHits           uint64 `json:"flow_cache_hits"`
	FlowCacheMisses         uint64 `json:"flow_cache_misses"`
	FlowCacheFlushes        uint64 `json:"flow_cache_flushes"`
	FlowCacheInvalidates    uint64 `json:"flow_cache_invalidations"`
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
	// Unavailable is true when the per-interface dataplane counter read
	// FAILED (#3464). The counter fields above are then left at 0 but are NOT
	// authoritative, so a real idle 0 stays distinguishable from a degraded
	// counter bridge. Omitted (false) when counters read successfully. Both
	// REST surfaces (/stats/interfaces and /interfaces) set it uniformly, and
	// it mirrors gRPC InterfaceInfo.unavailable + the Prometheus
	// xpf_interface_counter_read_errors_total counter.
	Unavailable bool `json:"unavailable,omitempty"`
}

// ZoneInfo holds zone configuration and counter data.
type ZoneInfo struct {
	Name string `json:"name"`
	ID   uint16 `json:"id"`
	// Description carries the zone's `description` sub-stanza (#3329). gRPC
	// GetZones already exposes it; REST omits it when unset (no behavior
	// change for zones without a description). Security audits routinely use
	// the description to carry intent/owner/ticket metadata.
	Description string `json:"description,omitempty"`
	// TcpRst mirrors gRPC GetZones (#3329): when `set security zones
	// security-zone <z> tcp-rst` is configured the zone sends a TCP RST for
	// non-SYN packets to closed ports, changing client-visible deny
	// behaviour. Omitted (false) for zones without it.
	TcpRst        bool     `json:"tcp_rst,omitempty"`
	ScreenProfile string   `json:"screen_profile,omitempty"`
	Interfaces    []string `json:"interfaces"`
	// HostInbound is the LEGACY flattened admission set: system-services +
	// protocols concatenated. Kept as a back-compat alias (#3328); new
	// consumers should read the split fields below.
	HostInbound []string `json:"host_inbound_services"`
	// HostInboundConfigured (#3328/#3405) records whether the zone is
	// host-inbound ENFORCING. Post-#3405 EVERY configured security zone is
	// enforcing (Junos default-deny parity), so this mirrors the dataplane
	// posture bit (ZoneSnapshot.HostInboundConfigured) and is TRUE for every
	// zone the inventory returns. A zone with NO `host-inbound-traffic` stanza
	// default-DENIES host-bound traffic exactly like an explicit empty stanza
	// (deny-all) — there is no admit-all posture for a configured zone. The
	// admitted set lives in HostInboundSystemServices / HostInboundProtocols
	// (empty = deny-all) plus any per-interface override in
	// InterfaceHostInbound. Before #3653 this bit was re-derived from config
	// shape and reported false for a no-stanza zone — the pre-#3405
	// "false = admit-all" reading, contradicting the runtime default-deny.
	// (Note: global ICMP/ND/PMTUD accepts and lifeline interfaces fxp0/em0/fab*
	// still bypass the per-zone host-inbound deny; see zones.go.)
	HostInboundConfigured bool `json:"host_inbound_configured"`
	// HostInboundSystemServices / HostInboundProtocols (#3328) carry the
	// ZONE-LEVEL admission set, kept distinct so automation can tell a
	// system-service (ssh, ping, dhcp) apart from a routing protocol (ospf,
	// bgp). Empty when the zone expresses host-inbound only via per-interface
	// overrides.
	HostInboundSystemServices []string `json:"host_inbound_system_services"`
	HostInboundProtocols      []string `json:"host_inbound_protocols"`
	// InterfaceHostInbound (#3328, #3362) carries per-interface host-inbound
	// overrides. An entry exists only for an interface that declares its own
	// `host-inbound-traffic` stanza; the effective admission set for that
	// interface is the UNION of the zone-level set above and the override.
	// Omitted when no interface declares an override.
	InterfaceHostInbound []ZoneInterfaceHostInbound `json:"interface_host_inbound,omitempty"`
	IngressPackets       uint64                     `json:"ingress_packets"`
	IngressBytes         uint64                     `json:"ingress_bytes"`
	EgressPackets        uint64                     `json:"egress_packets"`
	EgressBytes          uint64                     `json:"egress_bytes"`
	// PerZoneCountersAvailable (#3643) is false when the per-zone traffic
	// counters above are NOT sourced by the userspace dataplane. In that case
	// the four counter fields are meaningless zeros rather than real traffic
	// volume -- the eBPF per-zone writers were deleted in #1476 and the
	// userspace POPULATE path is deferred (see docs/research/3643-dead-counters).
	// It exists so an operator/automation can tell "no per-zone accounting" from
	// "genuinely zero traffic"; without it the endpoint reported a misleading 0
	// (or, for a stable-hash zone id >= MaxZones, 500'd the whole response).
	PerZoneCountersAvailable bool `json:"per_zone_counters_available"`
}

// ZoneInterfaceHostInbound is a per-interface host-inbound-traffic override
// (#3328, #3362): a zone may expose a service (e.g. ssh) on one interface
// while denying it on the others. Configured is always true for an emitted
// entry (the stanza is present); empty SystemServices/Protocols with
// Configured=true mean an explicit deny-all override on that interface.
type ZoneInterfaceHostInbound struct {
	Interface      string   `json:"interface"`
	Configured     bool     `json:"configured"`
	SystemServices []string `json:"system_services"`
	Protocols      []string `json:"protocols"`
}

// PolicyInfo holds policy configuration data.
type PolicyInfo struct {
	FromZone string       `json:"from_zone"`
	ToZone   string       `json:"to_zone"`
	Rules    []PolicyRule `json:"rules"`
}

// PolicyRule holds a single policy rule with counters.
type PolicyRule struct {
	Name string `json:"name"`
	// Description carries the policy's `description` sub-stanza (#3329). gRPC
	// GetPolicies already exposes it; REST omits it when unset (no behavior
	// change for rules without a description). Audits use it for
	// intent/owner/ticket/break-glass metadata.
	Description  string   `json:"description,omitempty"`
	Action       string   `json:"action"`
	SrcAddresses []string `json:"src_addresses"`
	DstAddresses []string `json:"dst_addresses"`
	Applications []string `json:"applications"`
	Log          bool     `json:"log"`
	Count        bool     `json:"count"`
	HitPackets   uint64   `json:"hit_packets"`
	HitBytes     uint64   `json:"hit_bytes"`
	// MatchFromZone / MatchToZone carry the optional from-zone/to-zone
	// match context of a scoped GLOBAL policy (#3148, #3286). The global
	// PolicyInfo group still reports from_zone="*"/to_zone="*" (all-zones
	// tier), but a global policy may narrow itself to a zone pair; these
	// per-rule fields surface that scope so automation/audit do not see a
	// scoped global as all-zones. Empty (omitted) for an all-zones global
	// and for ordinary zone-pair rules.
	MatchFromZone string `json:"match_from_zone,omitempty"`
	MatchToZone   string `json:"match_to_zone,omitempty"`
	// SourceAddressExcluded / DestinationAddressExcluded carry the match
	// inversion (#3336): the rule matches every address EXCEPT those in
	// src_addresses / dst_addresses (Junos `source-address-excluded` /
	// `destination-address-excluded`). The flags exist end-to-end (config ->
	// snapshot -> dataplane) but were never surfaced here, so an audit reading
	// the address slices saw the rule's meaning INVERTED. Omitted (false) for a
	// rule without the modifier — no behavior change for existing consumers.
	SourceAddressExcluded      bool `json:"source_address_excluded,omitempty"`
	DestinationAddressExcluded bool `json:"destination_address_excluded,omitempty"`
	// LogSessionInit / LogSessionClose expose the independent `then log
	// session-init` / `session-close` modes (#3336). The Log bool above
	// collapses both into one flag, so init-only, close-only, and both rendered
	// identically. Omitted (false) when unset.
	LogSessionInit  bool `json:"log_session_init,omitempty"`
	LogSessionClose bool `json:"log_session_close,omitempty"`
	// PolicyID / RuleID carry the runtime identity (#3336): PolicyID is the
	// span-accumulated runtime/RT_FLOW policy ID (the value events expose);
	// RuleID is the stable "<from>-><to>/<name>" string the snapshot carries.
	// Together they let automation join a runtime event (policy_id=N) back to
	// this inventory row. RuleID is always populated.
	//
	// #3623: NO omitempty. The first rule of the first zone-pair set has runtime
	// id 0, and since #3057 the implicit default policy uses a distinct sentinel
	// (0xFFFFFFFF), so id 0 is UNAMBIGUOUSLY a real policy. With omitempty the
	// first, highest-priority rule's policy_id was dropped from the JSON, so a
	// consumer joining an RT_FLOW event (policy_id=0) found no matching row. The
	// inventory always sets PolicyID, so it is always emitted (including 0).
	PolicyID uint32 `json:"policy_id"`
	RuleID   string `json:"rule_id,omitempty"`
	// SchedulerName / Inactive expose the policy's scheduler binding and its
	// runtime scheduler state (#3624), the structured sibling of the #3062
	// TEXT policy-detail surface (State: inactive + Scheduler: lines).
	// SchedulerName is the configured `scheduler-name` (empty for an
	// always-on rule). Inactive is true when the policy is bound to a
	// scheduler that is currently runtime-inactive — the dataplane is
	// skipping the rule right now — mirroring the text "State: inactive"
	// token. Without these an audit reads a time-gated, currently-dormant
	// permit/deny as an active allow/deny, disagreeing with effective
	// dataplane behavior. Both omitempty: empty/false for the common
	// always-on rule, and (like the text surface) Inactive stays false when
	// live scheduler state cannot be queried, so existing consumers see no
	// change.
	SchedulerName string `json:"scheduler_name,omitempty"`
	Inactive      bool   `json:"inactive,omitempty"`
}

// SessionEntry holds a single session table entry.
//
// Field parity with the gRPC SessionEntry contract (#3419): the REST view
// previously dropped or conflated several fields the gRPC GetSessions RPC
// already surfaced. The numeric PolicyID/InZone/OutZone fields are retained
// for backward compatibility; the *_name, interface, application,
// session_id, idle_seconds and structured nat_* fields mirror gRPC.
type SessionEntry struct {
	SrcAddr  string `json:"src_addr"`
	DstAddr  string `json:"dst_addr"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	PolicyID uint32 `json:"policy_id"`
	// PolicyName / IngressZoneName / EgressZoneName mirror the gRPC
	// enrichment (#3419 M6). The numeric ids above stay for compatibility;
	// these resolve them to operator-facing names. Omitted when unresolved.
	PolicyName      string `json:"policy_name,omitempty"`
	IngressZoneName string `json:"ingress_zone_name,omitempty"`
	EgressZoneName  string `json:"egress_zone_name,omitempty"`
	InZone          uint16 `json:"ingress_zone"`
	OutZone         uint16 `json:"egress_zone"`
	// IngressInterface / EgressInterface mirror the gRPC FIB-resolved
	// interface display (#3419 M4). Empty when unresolved.
	IngressInterface string `json:"ingress_interface,omitempty"`
	EgressInterface  string `json:"egress_interface,omitempty"`
	// Application is the resolved application name (#3419 M1), mirroring
	// gRPC's appid.ResolveSessionName. Empty when enrichment is unavailable.
	Application string `json:"application,omitempty"`
	FwdPackets  uint64 `json:"fwd_packets"`
	FwdBytes    uint64 `json:"fwd_bytes"`
	RevPackets  uint64 `json:"rev_packets"`
	RevBytes    uint64 `json:"rev_bytes"`
	// NAT keeps the human-readable summary, but a session with BOTH SNAT
	// and DNAT now joins both parts instead of the DNAT branch overwriting
	// the SNAT branch (#3419 H2). The structured NatSrc*/NatDst* fields
	// mirror gRPC so callers do not have to parse the text.
	NAT        string `json:"nat,omitempty"`
	NATSrcAddr string `json:"nat_src_addr,omitempty"`
	NATSrcPort uint16 `json:"nat_src_port,omitempty"`
	NATDstAddr string `json:"nat_dst_addr,omitempty"`
	NATDstPort uint16 `json:"nat_dst_port,omitempty"`
	// Age is wall age since the session was CREATED; Idle is time since the
	// last packet (#3419 H1). REST previously reported idle time in the
	// age_seconds field, so a long-lived active session looked seconds old.
	Age     int64  `json:"age_seconds"`
	Idle    int64  `json:"idle_seconds"`
	Timeout uint32 `json:"timeout_seconds"`
	// SessionID is the dataplane session identity; HAActive reports whether
	// this node is the active member for the session's resource group
	// (#3419 M6). HAActive defaults true on a standalone firewall.
	SessionID uint64 `json:"session_id,omitempty"`
	HAActive  bool   `json:"ha_active"`
}

// SessionListResponse holds paginated session results.
//
// Two pagination modes share this shape (#3421 H4):
//   - Offset mode (default): Total/Limit/Offset describe a best-effort
//     limit/offset window over a live map traversal.
//   - Cursor mode (page_size>0): PageSize and NextPageToken describe a
//     stable cursor page; an empty NextPageToken marks the last page.
//     Total is omitted in cursor mode (it would require a full scan).
type SessionListResponse struct {
	Total         int            `json:"total"`
	Limit         int            `json:"limit"`
	Offset        int            `json:"offset"`
	PageSize      int            `json:"page_size,omitempty"`
	NextPageToken string         `json:"next_page_token,omitempty"`
	Sessions      []SessionEntry `json:"sessions"`
	// NodeID is the cluster node this list was observed on (0 standalone),
	// mirroring the gRPC GetSessionsResponse.node_id. It is always present
	// so a dashboard polling one node knows WHICH node's table it sees —
	// the REST list reports the LOCAL table only (#3423 M5).
	NodeID int `json:"node_id"`
	// Peer carries the cluster peer's sessions when the request set
	// include_peer=true and this node is in an HA cluster with a reachable
	// peer (#3423 M5). Nil for a standalone node, an unreachable peer, or a
	// request that did not opt in. The local list above understates total
	// HA state without it.
	Peer *SessionListResponse `json:"peer,omitempty"`
}

// SessionSummary holds session table summary stats.
type SessionSummary struct {
	TotalEntries int `json:"total_entries"`
	ForwardOnly  int `json:"forward_only"`
	Established  int `json:"established"`
	IPv4Sessions int `json:"ipv4_sessions"`
	IPv6Sessions int `json:"ipv6_sessions"`
	SNATSessions int `json:"snat_sessions"`
	DNATSessions int `json:"dnat_sessions"`
	// NodeID / Peer mirror SessionListResponse (#3423 M5): node identity is
	// always present; Peer carries the cluster peer's summary when
	// include_peer=true and a reachable peer exists.
	NodeID int             `json:"node_id"`
	Peer   *SessionSummary `json:"peer,omitempty"`
}

// EventEntry holds a single event record. The forensic fields below the
// core 5-tuple mirror the gRPC EventEntry (proto/xpf/v1/xpf.proto) and the
// RT_FLOW record the CLI prints (#3337), so REST/SSE consumers can reproduce
// the full close record. They are omitempty: an event that does not carry a
// field (a non-close event, an unNAT'd flow, a screen drop) omits it.
type EventEntry struct {
	Time            string `json:"time"`
	Type            string `json:"type"`
	SrcAddr         string `json:"src_addr"`
	DstAddr         string `json:"dst_addr"`
	Protocol        string `json:"protocol"`
	Action          string `json:"action"`
	PolicyID        uint32 `json:"policy_id"`
	InZone          uint16 `json:"ingress_zone"`
	OutZone         uint16 `json:"egress_zone"`
	InZoneName      string `json:"ingress_zone_name,omitempty"`
	OutZoneName     string `json:"egress_zone_name,omitempty"`
	ScreenCheck     string `json:"screen_check,omitempty"`
	SessionPkts     uint64 `json:"session_packets,omitempty"`
	SessionBytes    uint64 `json:"session_bytes,omitempty"`
	RevSessionPkts  uint64 `json:"rev_session_pkts,omitempty"`
	RevSessionBytes uint64 `json:"rev_session_bytes,omitempty"`
	PolicyName      string `json:"policy_name,omitempty"`
	AppName         string `json:"app_name,omitempty"`
	IngressIface    string `json:"ingress_iface,omitempty"`
	CloseReason     string `json:"close_reason,omitempty"`
	Reason          string `json:"reason,omitempty"`
	NATSrcAddr      string `json:"nat_src_addr,omitempty"`
	NATDstAddr      string `json:"nat_dst_addr,omitempty"`
	SessionID       uint64 `json:"session_id,omitempty"`
	ElapsedTime     uint32 `json:"elapsed_time,omitempty"`
	Created         uint32 `json:"created,omitempty"`
	CreatedNanos    uint32 `json:"created_nanos,omitempty"`
	EgressIfindex   uint32 `json:"egress_ifindex,omitempty"`
	IngressIfindex  uint32 `json:"ingress_ifindex,omitempty"`
	TOS             uint8  `json:"tos,omitempty"`
	TCPControlBits  uint8  `json:"tcp_control_bits,omitempty"`
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
	Name          string `json:"name"`
	DstAddr       string `json:"dst_addr"`
	DstPort       uint16 `json:"dst_port,omitempty"`
	TranslateIP   string `json:"translate_ip"`
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
	// Thresholds carries the configured numeric screen thresholds keyed by
	// check name (or by a syn-flood-specific key for the several syn-flood
	// sub-thresholds). Only explicitly-configured positive values appear, so a
	// consumer can distinguish a default threshold from an intentionally tight
	// or accidentally clamped one (#3327). Omitted when no threshold is set.
	Thresholds map[string]int `json:"thresholds,omitempty"`
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
	RuleSet    string `json:"rule_set"`
	RuleName   string `json:"rule_name"`
	FromZone   string `json:"from_zone"`
	ToZone     string `json:"to_zone"`
	Action     string `json:"action"`
	SrcMatch   string `json:"source_match"`
	DstMatch   string `json:"destination_match"`
	HitPackets uint64 `json:"hit_packets"`
	HitBytes   uint64 `json:"hit_bytes"`
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
	Matched    bool   `json:"matched"`
	PolicyName string `json:"policy_name,omitempty"`
	// Global is true when the matched policy is a `policy global` rule rather
	// than a zone-pair rule (#3331). It distinguishes a global-scope verdict
	// from a same-named zone-pair policy.
	Global bool `json:"global,omitempty"`
	// FromZone/ToZone are the SCOPE of the matched policy (#3331): for a
	// zone-pair policy the surrounding from-zone/to-zone stanza; for a global
	// policy its optional `match from-zone`/`match to-zone` scope (empty when
	// the global policy applies to all zones). They disambiguate a verdict when
	// the same policy name repeats across zone pairs (legal in Junos).
	FromZone string `json:"from_zone,omitempty"`
	ToZone   string `json:"to_zone,omitempty"`
	// PolicyID is the stable runtime/RT_FLOW/session-table policy ID of the
	// matched policy (#3331), so a match-policies answer can be cross-referenced
	// against the session table and the policy-deny/permit audit log even when
	// policy names collide across scopes. Present only when matched.
	//
	// #3623: pointer with explicit presence. The first zone-pair set's first
	// rule has runtime id 0; a plain uint32+omitempty dropped it, making a
	// matched-first-policy answer look unmatched (both encoded as absent/0). A
	// *uint32 is set only on a match, so its presence means "matched with this
	// id" (emitted even at 0) and nil (omitted) means "no matched id".
	PolicyID *uint32 `json:"policy_id,omitempty"`
	// RuleID is the stable "<from>-><to>/<name>" rule identity the inventory
	// (GetPolicies) carries (#3668). PolicyID is the runtime/reorder-fragile
	// numeric id; RuleID lets a match-policies hit be joined to the stable
	// identifier used by inventory, logs, and tests even after a policy reorder.
	// Present only on a positive match (a matched global policy uses the
	// "junos-global->junos-global/<name>" form, matching inventory global rows).
	RuleID       string   `json:"rule_id,omitempty"`
	Action       string   `json:"action"`
	SrcAddresses []string `json:"src_addresses,omitempty"`
	DstAddresses []string `json:"dst_addresses,omitempty"`
	// SourceAddressExcluded / DestinationAddressExcluded report whether the
	// matched policy carries Junos `source-address-excluded` /
	// `destination-address-excluded` (#3668): the rule matches every address
	// EXCEPT those in SrcAddresses/DstAddresses. Without them a positive verdict
	// reads BACKWARDS — a match against a source OUTSIDE an excluded set prints
	// the excluded list as if it were the reason for the match (the shared
	// matcher already inverts correctly; only the response omitted the flag).
	// Present (true) only when the modifier is set on a matched policy; false /
	// omitted otherwise.
	SourceAddressExcluded      bool     `json:"source_address_excluded,omitempty"`
	DestinationAddressExcluded bool     `json:"destination_address_excluded,omitempty"`
	Applications               []string `json:"applications,omitempty"`
	// HostInboundUnmatched is true for a `to-zone junos-host` query that matched
	// no host-bound policy (#3285): the dataplane host gate returns None (local
	// delivery; no transit global/default fallback), so Action is not a
	// default-policy verdict for this case.
	HostInboundUnmatched bool `json:"host_inbound_unmatched,omitempty"`
	// DefaultUsed is true when no policy matched and Action is the configured
	// default-policy verdict (#3375), including the no-active-config fail-closed
	// case (deny). It is the typed form of the " (default)" suffix on Action, so
	// a client can branch on the posture without string-parsing. False for a
	// concrete policy match and for HostInboundUnmatched.
	DefaultUsed bool `json:"default_used,omitempty"`
	// QueriedFromZone/QueriedToZone echo the zone pair the caller ASKED about
	// (#3627 M06). Unlike FromZone/ToZone (the SCOPE of the MATCHED policy, set
	// only on a positive match), these are populated on EVERY response —
	// positive match, no-match/default, and host-inbound — so a stored JSON
	// diagnostic for a default-deny or host-inbound verdict proves which zone
	// pair was tested without also capturing the request URL. They are the query
	// context, not a policy attribute; for a wildcard-zone or global match they
	// can differ from FromZone/ToZone.
	QueriedFromZone string `json:"queried_from_zone,omitempty"`
	QueriedToZone   string `json:"queried_to_zone,omitempty"`
}

// ClearSessionsResult holds session clear results.
//
// In an HA cluster the REST clear fans out to the peer (the same
// service-layer clear gRPC uses), so the counts above are the LOCAL node's
// and the peer-clear outcome is surfaced via Failures/FailureSummary
// (#3423 H5). A non-zero Failures with a "peer clear:" FailureSummary means
// the local clear succeeded but the peer's sessions were NOT cleared and
// can reappear as active state on failover. NodeID identifies the node the
// request hit.
type ClearSessionsResult struct {
	IPv4Cleared int `json:"ipv4_cleared"`
	IPv6Cleared int `json:"ipv6_cleared"`
	// NodeID is the cluster node that served the clear (0 standalone).
	NodeID int `json:"node_id"`
	// Failures counts sub-operations (notably the HA peer clear) that
	// failed; FailureSummary describes them. Zero on a clean standalone or
	// cluster-wide clear.
	Failures       int    `json:"failures"`
	FailureSummary string `json:"failure_summary,omitempty"`
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

// ZonePairSummaryResponse wraps the zone-pair breakdown with the local node
// identity (#3423 M5). This summary class previously returned a bare array, so
// — unlike its /sessions/summary sibling — it carried no node_id and could not
// tell an operator WHICH node the counts came from. node_id is now always
// present.
//
// include_peer cross-node fan-out now matches the /sessions/summary sibling
// (#3592): when an operator sets include_peer=true the handler forwards to the
// new gRPC GetZonePairSummary RPC and attaches the cluster peer's OWN zone-pair
// breakdown under Peer. node_id identity is always present; Peer is omitted on
// a standalone node or an unreachable peer.
type ZonePairSummaryResponse struct {
	NodeID    int                      `json:"node_id"`
	ZonePairs []ZonePairSessionSummary `json:"zone_pairs"`
	// Peer carries the cluster peer's zone-pair breakdown when the request set
	// include_peer=true and an HA-aware session service is wired; nil otherwise
	// (standalone build, unreachable peer, or include_peer absent). Mirrors
	// SessionSummary.Peer (#3592).
	Peer *ZonePairSummaryResponse `json:"peer,omitempty"`
}

// BufferInfo holds dataplane buffer utilization information.
type BufferInfo struct {
	Name         string  `json:"name"`
	Type         string  `json:"type"`
	Scope        string  `json:"scope,omitempty"`
	MaxEntries   uint64  `json:"max_entries"`
	UsedCount    uint64  `json:"used_count"`
	Value        uint64  `json:"value,omitempty"`
	UsagePercent float64 `json:"usage_percent"`
	Status       string  `json:"status"`
}

// ConfigSearchResult holds a single config search match.
type ConfigSearchResult struct {
	LineNumber int    `json:"line_number"`
	Line       string `json:"line"`
}

// AnnotateRequest holds a config annotation request.
type AnnotateRequest struct {
	Path    string `json:"path"`    // space-separated config path
	Comment string `json:"comment"` // annotation text
}
