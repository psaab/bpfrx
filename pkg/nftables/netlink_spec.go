package nftables

// netlink_spec.go defines the self-contained input specs the #6387 PR-2 netlink
// installer consumes. They MIRROR the daemon / dpuserspace types the exec-`nft`
// oracle consumes (dpuserspace.ZoneHostInboundView, dpuserspace.JunosHostProgram,
// config.JunosHostDenyRule/L4, config.FirewallFilterTerm) but are declared here
// so pkg/nftables does not import pkg/dataplane/userspace (which imports
// pkg/nftables — an import cycle). The PR-3 daemon converter copies daemon
// values into these structs field-for-field; PR-2 constructs them directly in
// the parity tests.
//
// The high-level builders (netlink_hostinbound.go / netlink_lo0.go /
// netlink_fence.go) re-derive the low-level matches from these specs using the
// SAME shared SSOT the oracle uses (config.HostInboundServiceMatch,
// appid.ProtocolNumber, config.ParseTCPFlagsExpression, dataplane.DSCPValues),
// so the only thing that differs between oracle and netlink is the
// rendering-to-kernel step — which the T1 ruleset-parity test pins.

// PortRange mirrors config.PortRange: an inclusive [Lo,Hi] transport-port range
// (Lo==Hi is a single port).
type PortRange struct {
	Lo uint16
	Hi uint16
}

// HostInboundZoneView mirrors dpuserspace.ZoneHostInboundView. Addresses are
// bare host IPs (no prefix), as the daemon builder guarantees.
type HostInboundZoneView struct {
	Zone           string
	SystemServices []string
	Protocols      []string
	V4Addrs        []string
	V6Addrs        []string
}

// JunosHostDenyL4 mirrors config.JunosHostDenyL4.
type JunosHostDenyL4 struct {
	Proto       uint8
	Ports       []PortRange
	SourcePorts []PortRange
	ICMPType    *uint8
	ICMPCode    *uint8
}

// JunosHostDenyRule mirrors config.JunosHostDenyRule.
type JunosHostDenyRule struct {
	Family         string // "ip" or "ip6"
	SrcAny         bool
	SrcExcluded    bool
	Src            []string
	PermitSubtract []string
	L4             []JunosHostDenyL4
}

// JunosHostProgram mirrors dpuserspace.JunosHostProgram.
type JunosHostProgram struct {
	Zone                  string
	IngressIfnames        []string
	RulesV4               []JunosHostDenyRule
	RulesV6               []JunosHostDenyRule
	CoarseAdmitsIKE       bool
	CoarseIdentResets     bool
	HasApplicationAnyDeny bool
	IKEExemptNetdevs      []string
	IdentResetNetdevs     []string
}

// Lo0FilterTerm mirrors one lowered config.FirewallFilterTerm for the kernel lo0
// input chain. Source/destination scopes are the RESOLVED (prefix-list-expanded)
// address lists exactly as dpuserspace.ResolveFilterPrefixListAddrs returns them
// — mixed-family and unfiltered; the netlink builder family-filters per chain
// pass (mirroring nftFamilyAddrs) and applies the Junos empty-set / except /
// match-nothing semantics (mirroring nftAddrPredicate). Every other field is a
// verbatim copy of the config term; the builder re-derives protocol numbers,
// DSCP values, and tcp-flags masks via the shared SSOT.
type Lo0FilterTerm struct {
	Name string

	SrcAddrs       []string
	SrcExcept      bool
	SrcConstrained bool
	DstAddrs       []string
	DstExcept      bool
	DstConstrained bool

	Protocols         []string
	SourcePorts       []string
	DestinationPorts  []string
	SourcePortsExcept []string
	DestPortsExcept   []string
	DSCPs             []string
	ICMPTypes         []int
	ICMPCodes         []int
	TCPFlags          []string
	IsFragment        bool

	Log   bool
	Count string

	Action          string
	NextTerm        bool
	RoutingInstance string
}

// Lo0FilterSpec is the full lo0 input-filter render request: the ordered v4 then
// v6 terms (each already family-scoped by the caller as the oracle emits — the
// v4 filter's terms rendered with family "ip", the v6 filter's with "ip6").
type Lo0FilterSpec struct {
	V4Terms []Lo0FilterTerm
	V6Terms []Lo0FilterTerm
}

// HostInboundSpec is the full host-inbound render request (plan §5.1). It is the
// exact input set buildHostInboundFilterPayload consumes.
type HostInboundSpec struct {
	Views         []HostInboundZoneView
	UnzonedV4     []string
	UnzonedV6     []string
	Programs      []JunosHostProgram
	WGListenPorts []uint16
}

// FenceSpec is the cold-boot fail-closed fence render request (#5644): the
// address sets to DROP plus the mandatory-admit WG ports.
type FenceSpec struct {
	Views         []HostInboundZoneView
	UnzonedV4     []string
	UnzonedV6     []string
	WGListenPorts []uint16
}

// GapFenceSpec is the additive coverage-gap fence render request (#5789): the
// uncovered addresses to DROP plus the mandatory-admit WG ports.
type GapFenceSpec struct {
	UncoveredV4   []string
	UncoveredV6   []string
	WGListenPorts []uint16
}
