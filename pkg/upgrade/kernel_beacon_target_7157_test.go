package upgrade

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Measured verbatim on loss:xpf-userspace-fw0/fw1 (#7157). Using the real
// shapes rather than invented ones matters here: the FRR nexthop-group form
// (`nhid 115 via ...`) and the HA-secondary blackhole form are both produced by
// this product on its own reference cluster, and neither appeared in the parse
// table this code shipped with.
const (
	routeGetOnLinkV4 = "172.16.50.1 dev ge-0-0-2.50 src 172.16.50.8 uid 0 \n    cache \n"
	routeGetViaGWV4  = "10.136.126.1 via 172.16.50.1 dev ge-0-0-2.50 src 172.16.50.8 uid 0 \n    cache \n"
	routeGetV6       = "2001:559:8585:50::1 from :: dev ge-0-0-2.50 proto kernel src 2001:559:8585:50::8 metric 256 pref medium\n"
	routeGetLocalV4  = "local 172.16.50.8 dev lo table local src 172.16.50.8 uid 0 \n    cache <local> \n"
	routeGetLocalV6  = "local 2001:559:8585:80::8 from :: dev lo table local proto kernel src 2001:559:8585:80::8 metric 0 pref medium\n"
	routeGetMgmt     = "10.136.126.1 dev fxp0 src 10.136.126.113 uid 0 \n    cache \n"
)

// TestParseRouteGetDev_7157 pins the egress-device extraction against the
// measured shapes.
func TestParseRouteGetDev_7157(t *testing.T) {
	for _, tc := range []struct{ name, out, want string }{
		{"on-link v4", routeGetOnLinkV4, "ge-0-0-2.50"},
		{"via gateway v4", routeGetViaGWV4, "ge-0-0-2.50"},
		{"v6", routeGetV6, "ge-0-0-2.50"},
		{"local v4 (the false-PASS shape)", routeGetLocalV4, "lo"},
		{"local v6", routeGetLocalV6, "lo"},
		{"management", routeGetMgmt, "fxp0"},
		// An unreadable answer must yield "", which the caller treats as
		// UNRESOLVED. It must never fall through to a device name that would
		// pass the eligibility check.
		{"empty", "", ""},
		{"whitespace", "   \n  \n", ""},
		{"no dev field", "broadcast 10.0.0.255 table local src 10.0.0.1\n", ""},
		// `dev` as the LAST token has no value after it; the scan must not
		// index past the end, and must not report the literal "dev".
		{"trailing dev with no value", "1.2.3.4 dev", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseRouteGetDev(tc.out); got != tc.want {
				t.Errorf("parseRouteGetDev(%q) = %q, want %q", tc.out, got, tc.want)
			}
		})
	}
}

// TestParseDefaultRoute_7157 pins the default-route parse — the PRODUCTION
// function, which TestDefaultGatewayParseLogic used to re-implement inside
// itself.
func TestParseDefaultRoute_7157(t *testing.T) {
	for _, tc := range []struct{ name, out, wantGW, wantDev string }{
		{"classic", "default via 10.0.0.1 dev eth0 proto dhcp", "10.0.0.1", "eth0"},
		// MEASURED on loss:xpf-userspace-fw0. FRR installs the default through a
		// nexthop GROUP, so the line leads with `nhid <id>` before the via. A
		// positional parse (`$3`) reads the nexthop-group id as the gateway.
		{
			"FRR nexthop-group form (measured)",
			"default nhid 115 via 172.16.50.1 dev ge-0-0-2.50 proto static metric 20 \n",
			"172.16.50.1", "ge-0-0-2.50",
		},
		// MEASURED on loss:xpf-userspace-fw1, the HA SECONDARY. FRR blackholes
		// the static default while the peer holds the RETH VIP, so there is no
		// via at all and the beacon has no target — on the node an HA operator
		// upgrades FIRST.
		{"HA-secondary blackhole (measured)", "blackhole default proto static metric 20 \n", "", ""},
		{"HA-secondary blackhole v6 (measured)", "blackhole default dev lo proto static metric 20 pref medium\n", "", ""},
		{"empty", "", "", ""},
		{"no via (point-to-point)", "default dev wg0 scope link", "", ""},
		// A blackhole line FOLLOWED by a real default: the device must come from
		// the SAME line as the via. The old flattened field scan would have
		// paired this via with the blackhole line's `dev lo` and reported the
		// beacon target as egressing lo — which the eligibility check would then
		// refuse, reverting a promotion that should have been allowed.
		{
			"blackhole line then a real default",
			"blackhole default dev lo proto static metric 20\ndefault via 172.16.50.1 dev ge-0-0-2.50 proto static\n",
			"172.16.50.1", "ge-0-0-2.50",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw, dev := parseDefaultRoute(tc.out)
			if gw != tc.wantGW || dev != tc.wantDev {
				t.Errorf("parseDefaultRoute(%q) = (%q, %q), want (%q, %q)",
					tc.out, gw, dev, tc.wantGW, tc.wantDev)
			}
		})
	}
}

// TestBeaconTargetEligible_7157 is the total verdict table.
//
// Every row fixes the ROUTE-GET result, so the only thing that can decide the
// outcome is the eligibility rule itself. Without that seam each row would be
// decided by the routing table of whatever machine runs the suite, and a row
// that rejects because the test host has no route to 192.0.2.1 cannot be told
// apart from a row that rejects for the reason it was written to assert.
func TestBeaconTargetEligible_7157(t *testing.T) {
	isMgmt := func(dev string) bool {
		return strings.HasPrefix(dev, "fxp") || strings.HasPrefix(dev, "fab") || strings.HasPrefix(dev, "em")
	}
	for _, tc := range []struct {
		name     string
		out      string
		getErr   error
		isMgmt   func(string) bool
		wantErr  bool
		wantWord string // a distinguishing fragment, so a row cannot pass on the WRONG rejection
	}{
		{name: "dataplane v4 is eligible", out: routeGetOnLinkV4, isMgmt: isMgmt},
		{name: "dataplane v6 is eligible", out: routeGetV6, isMgmt: isMgmt},
		{name: "via a gateway is eligible", out: routeGetViaGWV4, isMgmt: isMgmt},
		{
			// THE LIVE FALSE-PASS. `ping <own dataplane address>` is answered by
			// the local stack in 55us with the dataplane in any state, so before
			// this check an operator who set XPF_KERNEL_BEACON_TARGET to the
			// box's own dataplane address — which ForwardBeacon's own guidance
			// invites — made Gate 4 pass unconditionally.
			name: "LOCAL target (dev lo) is refused", out: routeGetLocalV4, isMgmt: isMgmt,
			wantErr: true, wantWord: "LOCAL",
		},
		{name: "local v6 is refused", out: routeGetLocalV6, isMgmt: isMgmt, wantErr: true, wantWord: "LOCAL"},
		{
			name: "management egress is refused", out: routeGetMgmt, isMgmt: isMgmt,
			wantErr: true, wantWord: "MANAGEMENT",
		},
		{
			// MEASURED on the HA secondary: `ip route get` returns EINVAL for
			// every address because main's only default is a blackhole.
			name: "no route at all is refused", getErr: errors.New("RTNETLINK answers: Invalid argument"),
			isMgmt: isMgmt, wantErr: true, wantWord: "no route",
		},
		{
			name: "unresolvable egress device is refused", out: "broadcast 10.0.0.255 table local\n",
			isMgmt: isMgmt, wantErr: true, wantWord: "egress interface",
		},
		{
			// A nil classifier is "no information", not "ineligible" — the same
			// contract the nil-HelperStatus branch documents. Failing closed here
			// would revert every embedder that cannot classify interfaces.
			name: "nil classifier does not refuse a management egress", out: routeGetMgmt, isMgmt: nil,
		},
		{
			// ...but `lo` needs no classifier to be recognised, so the nil case
			// must NOT become a blanket bypass of the whole check. This row is
			// what stops "nil means skip everything" from being an easy and
			// wrong simplification.
			name: "nil classifier still refuses a LOCAL target", out: routeGetLocalV4, isMgmt: nil,
			wantErr: true, wantWord: "LOCAL",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig := beaconRouteGet
			t.Cleanup(func() { beaconRouteGet = orig })
			var probed string
			beaconRouteGet = func(target string) (string, error) {
				probed = target
				return tc.out, tc.getErr
			}
			err := beaconTargetEligible("198.51.100.7", tc.isMgmt)
			if probed != "198.51.100.7" {
				t.Fatalf("beaconTargetEligible resolved %q, want the target it was given", probed)
			}
			switch {
			case tc.wantErr && err == nil:
				t.Fatalf("want a refusal, got nil — an ineligible target would be probed and its "+
					"ping treated as proof of forwarding (case %s)", tc.name)
			case !tc.wantErr && err != nil:
				t.Fatalf("want eligible, got refusal: %v", err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), tc.wantWord) {
				t.Fatalf("refusal %q does not name %q — the row could be passing on a "+
					"DIFFERENT rejection than the one it asserts", err, tc.wantWord)
			}
		})
	}
}

// TestForwardBeaconRefusesLocalTarget_7157 is the security regression: the
// end-to-end gate, not the helper.
//
// Every other precondition is forced HEALTHY and the ping is forced to SUCCEED,
// so the target eligibility check is the only thing left that can reject. That
// is what makes this a proof rather than a coincidence: without the forced ping
// the case passes even with the check deleted, because a real ping to the
// target fails and the beacon returns false for a reason the assertion cannot
// see (the same trap the #6607 tests in this package document).
func TestForwardBeaconRefusesLocalTarget_7157(t *testing.T) {
	origUnit, origPing, origGet := unitActiveProbeCtx, beaconPing, beaconRouteGet
	t.Cleanup(func() {
		unitActiveProbeCtx, beaconPing, beaconRouteGet = origUnit, origPing, origGet
	})
	unitActiveProbeCtx = func(context.Context, string) (bool, error) { return true, nil }
	pinged := false
	beaconPing = func(string, int) error { pinged = true; return nil }
	beaconRouteGet = func(string) (string, error) { return routeGetLocalV4, nil }

	s := &realKernelSystem{
		BeaconTarget: "172.16.50.8", // the box's OWN dataplane address
		HelperStatus: func(string, time.Duration) (bool, bool, int, error) {
			return true, true, 1234, nil
		},
		IsManagementIface: func(string) bool { return false },
	}
	ok, err := s.ForwardBeacon(time.Second)
	if ok {
		t.Fatal("ForwardBeacon PASSED on a target local to the box. The ping is answered by " +
			"the host stack without a packet leaving, so it succeeds with the dataplane in any " +
			"state — Gate 4 would promote every candidate kernel unconditionally")
	}
	if err == nil || !strings.Contains(err.Error(), "LOCAL") {
		t.Fatalf("ForwardBeacon err = %v; want a refusal naming the LOCAL target, because that "+
			"text is what reaches the operator through KernelRollOutcome.Reason", err)
	}
	if pinged {
		t.Fatal("ForwardBeacon pinged a target it had already established could not leave the box")
	}
}

// TestForwardBeaconRefusesManagementEgress_7157 is the issue's original form of
// the same defect: a candidate kernel can keep management reachable while the
// dataplane cannot forward transit traffic.
func TestForwardBeaconRefusesManagementEgress_7157(t *testing.T) {
	origUnit, origPing, origGet := unitActiveProbeCtx, beaconPing, beaconRouteGet
	t.Cleanup(func() {
		unitActiveProbeCtx, beaconPing, beaconRouteGet = origUnit, origPing, origGet
	})
	unitActiveProbeCtx = func(context.Context, string) (bool, error) { return true, nil }
	pinged := false
	beaconPing = func(string, int) error { pinged = true; return nil }
	beaconRouteGet = func(string) (string, error) { return routeGetMgmt, nil }

	s := &realKernelSystem{
		BeaconTarget: "10.136.126.1",
		HelperStatus: func(string, time.Duration) (bool, bool, int, error) {
			return true, true, 1, nil
		},
		IsManagementIface: func(dev string) bool { return strings.HasPrefix(dev, "fxp") },
	}
	ok, err := s.ForwardBeacon(time.Second)
	if ok || err == nil || !strings.Contains(err.Error(), "MANAGEMENT") {
		t.Fatalf("ForwardBeacon = (%v, %v) for a target egressing fxp0; want a refusal naming "+
			"the management interface", ok, err)
	}
	if pinged {
		t.Fatal("ForwardBeacon pinged a target it had established leaves via management")
	}
}

// TestForwardBeaconPassesEligibleDataplaneTarget_7157 is the positive control
// for the two refusals above: without it, an eligibility check that refused
// EVERYTHING would satisfy both.
func TestForwardBeaconPassesEligibleDataplaneTarget_7157(t *testing.T) {
	origUnit, origPing, origGet := unitActiveProbeCtx, beaconPing, beaconRouteGet
	t.Cleanup(func() {
		unitActiveProbeCtx, beaconPing, beaconRouteGet = origUnit, origPing, origGet
	})
	unitActiveProbeCtx = func(context.Context, string) (bool, error) { return true, nil }
	beaconPing = func(string, int) error { return nil }
	beaconRouteGet = func(string) (string, error) { return routeGetOnLinkV4, nil }

	s := &realKernelSystem{
		BeaconTarget: "172.16.50.1",
		HelperStatus: func(string, time.Duration) (bool, bool, int, error) {
			return true, true, 1, nil
		},
		IsManagementIface: func(string) bool { return false },
	}
	if ok, err := s.ForwardBeacon(time.Second); !ok || err != nil {
		t.Fatalf("ForwardBeacon = (%v, %v) for an off-box target egressing a dataplane "+
			"interface with every precondition healthy; want (true, nil)", ok, err)
	}
}

// TestBothProductionConstructorsWireIsManagement_7157 binds the WIRING.
//
// beaconTargetEligible treats a nil classifier as "no information" and does not
// refuse a management egress, which is the right contract for an embedder that
// cannot classify — but it means the management refusal is DEAD unless the
// production callers actually pass the predicate. A test that only drove
// beaconTargetEligible would stay green with both call sites reverted to nil,
// which is the exact defect #7916 had to fix in its own first attempt.
//
// realKernelSystem is unexported but its fields are exported, so reflection
// reaches them without widening the type's API.
func TestBothProductionConstructorsWireIsManagement_7157(t *testing.T) {
	s := NewKernelSystemWithHelperStatus(nil, nil, "", nil)
	f := reflect.ValueOf(s).Elem().FieldByName("IsManagementIface")
	if !f.IsValid() {
		t.Fatal("realKernelSystem has no IsManagementIface field — the beacon's #7157 " +
			"management refusal has no way to be wired")
	}
	if !f.IsNil() {
		t.Fatal("NewKernelSystemWithHelperStatus(.., nil) left IsManagementIface non-nil; " +
			"the constructor must pass through what the caller gave it")
	}
	want := func(string) bool { return true }
	s = NewKernelSystemWithHelperStatus(nil, nil, "", want)
	if reflect.ValueOf(s).Elem().FieldByName("IsManagementIface").IsNil() {
		t.Fatal("NewKernelSystemWithHelperStatus dropped the IsManagementIface argument — " +
			"every production caller's management refusal would be dead")
	}
	// The bare constructor must NOT silently supply one: a caller that has not
	// thought about the classifier should get the documented "no information"
	// behaviour, not a hidden default that could refuse a legitimate target.
	if !reflect.ValueOf(NewKernelSystem()).Elem().FieldByName("IsManagementIface").IsNil() {
		t.Fatal("NewKernelSystem() pre-set IsManagementIface; the seam must stay caller-supplied")
	}
}
