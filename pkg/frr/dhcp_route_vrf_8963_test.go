package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8963: a DHCP-learned route was emitted once, in the default FRR context,
// even when the interface that learned it belonged to a routing instance.
//
// WHAT MADE THIS A FINDING WAS THE SIBLING, NOT THE ABSENCE. "renderDHCPDefaults
// emits no vrf clause" alone is consistent with correct-by-design. The same
// file, for the same kind of object, threading `vrf <name>` for STATIC routes
// and not for DHCP-learned ones is what converts it.
//
// REACHABILITY, which decides latent vs live and was the open column on the
// issue: measured at `configstore.CheckText`, a DHCP-client interface placed in
// a routing instance COMMITS CLEAN --
//
//	interfaces ge-0/0/1 unit 0 family inet dhcp
//	routing-instances vrf1 instance-type vrf interface ge-0/0/1.0
//
// with both single-sided controls also accepted, so nothing upstream refuses
// the combination. This is live, not latent.

func renderDHCP8963(t *testing.T, fc *FullConfig) string {
	t.Helper()
	var b strings.Builder
	renderDHCPDefaults(&b, fc)
	return b.String()
}

// #9136 UPDATE to the two cells below. Both asserted the literal `vrf vrf1` —
// the BARE routing-instance name. That expectation shared the code's
// misconception: FRR knows the KERNEL namespace, and a `virtual-router`
// instance is backed by the device `vrf-vrf1` (pkg/routing/vrf.go), which is
// what InstanceConfig.VRFName carries and what every SIBLING renderer in this
// package emits. A positive control that shares the defect it guards can never
// fail on it, so the literal was wrong, not the claim.
//
// The CLAIMS both cells were written to pin are unchanged and restated verbatim
// below: (1) a DHCP route learned on an instance interface must carry a clause
// putting it in that instance's table, and (2) a default-context static default
// must not suppress an instance's DHCP default. Only the rendered spelling and
// the fixtures move — the fixtures now carry the VRFName a real instance has
// (daemon_ipmon.go sets it for every non-forwarding instance), which they
// omitted because the namespace was not the question they were asked.

func TestDHCPRouteCarriesItsVRF8963(t *testing.T) {
	fc := &FullConfig{
		Instances: []InstanceConfig{{Name: "vrf1", VRFName: "vrf-vrf1"}},
		DHCPRoutes: []DHCPRoute{
			{Gateway: "10.0.2.1", Interface: "ge-0/0/1", VRF: "vrf1"},
			{Gateway: "10.9.9.1", Interface: "ge-0/0/2"},
		},
	}
	out := renderDHCP8963(t, fc)
	if out == "" {
		t.Fatal("NON-VACUITY: the renderer emitted nothing, so neither assertion " +
			"below can distinguish a missing vrf clause from a missing route")
	}

	if !strings.Contains(out, "ip route 0.0.0.0/0 10.0.2.1 ge-0/0/1 200 vrf vrf-vrf1") {
		t.Errorf("#8963: the DHCP route learned on an interface in `vrf1` was emitted "+
			"without a `vrf` clause, so it lands in the DEFAULT routing table.\n"+
			"  The instance does not get the route it learned, and the default "+
			"context gets one it should not have. Static routes in this same file "+
			"have threaded `vrf <name>` since #5557.\n  got:\n%s", out)
	}
	// CONTROL: a route with no instance must NOT acquire a vrf clause. Without
	// this, a fix that appended `vrf` unconditionally would pass the assertion
	// above and break every default-context DHCP route.
	if !strings.Contains(out, "ip route 0.0.0.0/0 10.9.9.1 ge-0/0/2 200\n") {
		t.Errorf("CONTROL FAILED: a DHCP route with no routing instance must render "+
			"with NO vrf clause. got:\n%s", out)
	}
}

// Suppression is per-VRF. A static default in the DEFAULT context must not
// suppress a DHCP default belonging to an instance, and vice versa.
func TestDHCPDefaultSuppressionIsPerVRF8963(t *testing.T) {
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{
			{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "10.9.9.254"}}},
		},
		Instances: []InstanceConfig{{Name: "vrf1", VRFName: "vrf-vrf1"}},
		DHCPRoutes: []DHCPRoute{
			{Gateway: "10.0.2.1", Interface: "ge-0/0/1", VRF: "vrf1"},
			{Gateway: "10.9.9.1", Interface: "ge-0/0/2"},
		},
	}
	out := renderDHCP8963(t, fc)

	// CONTROL: the top-level static default DOES suppress the default-context
	// DHCP default. That is pre-existing behaviour and must not regress.
	if strings.Contains(out, "10.9.9.1") {
		t.Errorf("CONTROL FAILED: a top-level static default must still suppress the "+
			"DEFAULT-context DHCP default (#5519). got:\n%s", out)
	}
	// SUBJECT: it must NOT suppress the instance's.
	if !strings.Contains(out, "vrf vrf-vrf1") {
		t.Errorf("#8963: a static default in the DEFAULT context suppressed a DHCP "+
			"default belonging to `vrf1`. The suppression check read only the "+
			"top-level static lists, so the instance loses its learned default "+
			"because of a route in a different table.\n  got:\n%s", out)
	}
}

// And the other direction: a static default INSIDE the instance must suppress
// that instance's DHCP default.
func TestInstanceStaticDefaultSuppressesItsOwnDHCPDefault8963(t *testing.T) {
	fc := &FullConfig{
		Instances: []InstanceConfig{{
			Name: "vrf1",
			StaticRoutes: []*config.StaticRoute{
				{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "10.0.2.254"}}},
			},
		}},
		DHCPRoutes: []DHCPRoute{
			{Gateway: "10.0.2.1", Interface: "ge-0/0/1", VRF: "vrf1"},
		},
	}
	out := renderDHCP8963(t, fc)
	if strings.Contains(out, "10.0.2.1") {
		t.Errorf("#8963: a static default inside `vrf1` did not suppress that "+
			"instance's DHCP-learned default, so the instance installs both. "+
			"Before this the check read only top-level statics, so an instance "+
			"static neither suppressed nor was suppressed.\n  got:\n%s", out)
	}
}
