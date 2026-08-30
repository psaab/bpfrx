package daemon

import (
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #7284, the half that actually locks the operator out. The rule emission and
// the #5566 conntrack reconcile are built from the SAME views/unzoned sets
// (daemon_nft.go passes one pair to toNftHostInboundSpec and to
// flushDeniedHostInboundConntrack), so withholding a lifeline-shared address at
// the builders fixes both. That is a structural claim and this asserts it
// directly rather than trusting it: fixing only the rules would stop NEW
// management connections being dropped and still tear down the operator's
// CURRENT session on the next apply.
func TestFlushFilterExcludesLifelineSharedAddr_7284(t *testing.T) {
	const (
		mgmt  = "192.0.2.1"
		plain = "198.51.100.1"
	)
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{mgmt + "/24"}}}},
		// Unzoned, carrying the shared management address and a plain one.
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{mgmt + "/24", plain + "/24"}}}},
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.61.1/24"}}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0/0/2.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}

	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	filter := buildHostInboundConntrackFlushFilter(views, unzonedV4, unzonedV6, nil)
	if filter == nil {
		t.Fatal("no flush filter built; the fixture must produce a non-empty desired set")
	}

	mgmtAddr := netip.MustParseAddr(mgmt)
	if _, covered := filter.admit[mgmtAddr]; covered {
		t.Errorf("%s is a management address on fxp0: it must not be in the #5566 "+
			"covered set, or the reconcile tears down the operator's ESTABLISHED "+
			"session on the next apply", mgmt)
	}

	// NEGATIVE CONTROL. Without it this test passes for an implementation that
	// covers nothing at all, which would disable the reconcile entirely.
	plainAddr := netip.MustParseAddr(plain)
	if _, covered := filter.admit[plainAddr]; !covered {
		t.Errorf("NEGATIVE CONTROL: %s is not on any lifeline and must remain in "+
			"the covered set so its now-denied entries are still flushed", plain)
	}
}
