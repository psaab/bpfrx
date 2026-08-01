package daemon

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #5566: the xpf_hostinbound kernel chain leads with `ct state
// established,related accept`, which precedes the per-zone coarse host-inbound
// drops, and replacing the table does NOT flush Linux conntrack. Removing a host
// service therefore left an EXISTING direct-kernel connection authorized under the
// OLD config (the established-accept short-circuits the new drop) — a host-inbound
// false-allow the Rust userspace path already tears down per hit. The fix flushes
// the now-denied host-directed conntrack entries after a successful host-inbound
// apply so the next packet is re-evaluated against the current rules.
//
// These are the fail-on-revert proofs. Reverting the matcher logic
// (MatchConntrackFlow) turns the match assertions RED; reverting the wiring
// (removing d.flushDeniedHostInboundConntrack from applyHostInboundFilter) turns
// the reconcile-invocation assertion RED.

// hostInboundFlushTestConfig clones hostInboundTestConfig and parameterizes the
// wan zone's system-services, opening the lan zone (reth1.0, 10.0.61.1) to `all`
// so an allows-all address is available. em0/fxp0 stay management/cluster-control
// lifelines (excluded from the host-inbound views, so never in the covered set).
func hostInboundFlushTestConfig(wanServices ...string) *config.Config {
	cfg := hostInboundTestConfig()
	cfg.Security.Zones["wan"].HostInboundTraffic.SystemServices = wanServices
	cfg.Security.Zones["lan"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"any-service"}}
	return cfg
}

// ctFlow builds a synthetic conntrack flow with the given original-direction
// (proto, destination IP, destination port) — the tuple the kernel host-inbound
// chain evaluates for an inbound host connection.
func ctFlow(proto uint8, dstIP string, dport uint16) *netlink.ConntrackFlow {
	return &netlink.ConntrackFlow{
		Forward: netlink.IPTuple{
			SrcIP:    net.ParseIP("203.0.113.7"),
			DstIP:    net.ParseIP(dstIP),
			Protocol: proto,
			SrcPort:  40000,
			DstPort:  dport,
		},
	}
}

// TestHostInboundConntrackFlushFilterMatch_5566 exercises the flush filter's
// per-flow decision directly. The wan zone is tightened to `snmp` only (ssh
// removed): an established ssh (tcp/22) flow to the wan address is now denied and
// MUST be selected for flush, while the still-permitted snmp (udp/161) flow, an
// allows-all zone's flow, a lifeline address, ESP, ICMP, and a WireGuard flow MUST
// all be preserved.
func TestHostInboundConntrackFlushFilterMatch_5566(t *testing.T) {
	cfg := hostInboundFlushTestConfig("snmp") // ssh removed → now denied
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)

	f := buildHostInboundConntrackFlushFilter(views, unzonedV4, unzonedV6, nil)
	if f == nil {
		t.Fatal("expected a non-nil flush filter for an enforcing config")
	}

	cases := []struct {
		name string
		flow *netlink.ConntrackFlow
		want bool
	}{
		// The headline bug: a removed service's established flow is now denied.
		{"ssh-now-denied-v4", ctFlow(config.HostInboundProtoTCP, "172.16.50.8", 22), true},
		{"ssh-now-denied-v6", ctFlow(config.HostInboundProtoTCP, "2001:db8:50::8", 22), true},
		// A never-permitted service on a covered address is likewise flushable.
		{"telnet-denied-v4", ctFlow(config.HostInboundProtoTCP, "172.16.50.8", 23), true},
		// The still-permitted service's established flow MUST survive (no regression).
		{"snmp-permitted-v4", ctFlow(config.HostInboundProtoUDP, "172.16.50.8", 161), false},
		// An allows-all zone address keeps everything.
		{"allows-all-zone", ctFlow(config.HostInboundProtoTCP, "10.0.61.1", 22), false},
		// A management/cluster-control lifeline address is not covered → never flushed.
		{"lifeline-em0", ctFlow(config.HostInboundProtoTCP, "10.99.0.1", 22), false},
		// Global exemptions the chain always accepts are never flushed.
		{"esp-exempt", ctFlow(50, "172.16.50.8", 0), false},
		{"ah-exempt", ctFlow(51, "172.16.50.8", 0), false},
		{"icmp-exempt", ctFlow(config.HostInboundProtoICMP, "172.16.50.8", 0), false},
		{"icmpv6-exempt", ctFlow(config.HostInboundProtoICMPv6, "2001:db8:50::8", 0), false},
		// A non-local (transit / host-originated) destination is never covered.
		{"transit-dst", ctFlow(config.HostInboundProtoTCP, "8.8.8.8", 22), false},
	}
	for _, tc := range cases {
		if got := f.MatchConntrackFlow(tc.flow); got != tc.want {
			t.Errorf("%s: MatchConntrackFlow = %v, want %v", tc.name, got, tc.want)
		}
	}

	// The WireGuard listen port is globally admitted (#5582): a UDP flow to it on a
	// covered address must NOT be flushed even though no zone service names it.
	fWG := buildHostInboundConntrackFlushFilter(views, unzonedV4, unzonedV6, []uint16{51820})
	if fWG.MatchConntrackFlow(ctFlow(config.HostInboundProtoUDP, "172.16.50.8", 51820)) {
		t.Error("WireGuard listen-port flow to a covered address must not be flushed")
	}
}

// TestHostInboundConntrackFlushReconcileOnTightening_5566 is the end-to-end
// fail-on-revert proof for the wiring: a successful host-inbound apply that
// TIGHTENS the config (removes ssh, keeps snmp) must drive the conntrack reconcile
// with a filter that flushes the now-denied ssh flow and preserves the permitted
// snmp flow. Removing d.flushDeniedHostInboundConntrack from applyHostInboundFilter
// leaves conntrackDeleteFilters uncalled → the invocation assertion RED (the stale
// ssh entry would survive on the leading established-accept).
func TestHostInboundConntrackFlushReconcileOnTightening_5566(t *testing.T) {
	origApply := nftApplyPayload
	origDelete := nftDeleteTable
	origCT := conntrackDeleteFilters
	defer func() {
		nftApplyPayload = origApply
		nftDeleteTable = origDelete
		conntrackDeleteFilters = origCT
	}()
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	nftDeleteTable = func(string, string) ([]byte, error) { return nil, nil }

	var ctCalls int
	var lastFilter netlink.CustomConntrackFilter
	conntrackDeleteFilters = func(_ netlink.InetFamily, filters ...netlink.CustomConntrackFilter) (uint, error) {
		ctCalls++
		if len(filters) > 0 {
			lastFilter = filters[0]
		}
		return 0, nil
	}

	d := &Daemon{}

	// Step 1: loose config permits ssh + snmp; a direct-kernel ssh session exists.
	if err := d.applyHostInboundFilter(hostInboundFlushTestConfig("ssh", "snmp")); err != nil {
		t.Fatalf("step 1 (loose apply): %v", err)
	}

	// Step 2: TIGHTEN — remove ssh (keep snmp). The reconcile must run against the
	// new set.
	callsBefore := ctCalls
	if err := d.applyHostInboundFilter(hostInboundFlushTestConfig("snmp")); err != nil {
		t.Fatalf("step 2 (tighten apply): %v", err)
	}
	if ctCalls-callsBefore == 0 {
		t.Fatal("#5566 FAIL-OPEN: a host-inbound tightening applied but the kernel conntrack " +
			"reconcile never ran — an existing direct-kernel ssh connection would keep OLD " +
			"authorization via the chain's leading `ct state established,related accept`")
	}
	if lastFilter == nil {
		t.Fatal("reconcile ran but no conntrack filter was captured")
	}
	// The captured filter flushes the now-denied ssh flow...
	if !lastFilter.MatchConntrackFlow(ctFlow(config.HostInboundProtoTCP, "172.16.50.8", 22)) {
		t.Error("the tightening reconcile filter must flush the now-denied ssh (tcp/22) flow")
	}
	// ...and preserves the still-permitted snmp flow (no regression).
	if lastFilter.MatchConntrackFlow(ctFlow(config.HostInboundProtoUDP, "172.16.50.8", 161)) {
		t.Error("the reconcile filter must NOT flush the still-permitted snmp (udp/161) flow")
	}
}

// TestHostInboundConntrackFlushNoOpWhenNothingCovered_5566 asserts the reconcile
// is a no-op (no netlink delete) when there is no covered firewall-local
// host-inbound address — an all-open config produces no default-deny, so there is
// nothing to reconcile and the filter builder returns nil.
func TestHostInboundConntrackFlushNoOpWhenNothingCovered_5566(t *testing.T) {
	// Only an allows-all zone: no catch-all drop, so no covered address.
	// #3226: `any-service` is the packet-wide admit token (`all` now expands to
	// the named-service union and DOES emit a catch-all drop).
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.61.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"open": {
			Name:               "open",
			Interfaces:         []string{"reth1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"any-service"}},
		},
	}
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	if f := buildHostInboundConntrackFlushFilter(views, unzonedV4, unzonedV6, nil); f != nil {
		t.Errorf("expected nil filter when no address is covered by a default-deny, got %+v", f)
	}
}
