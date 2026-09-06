package rpm

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9026: probeICMP resolved an IPv6 link-local scope and probeTCP did not, so
// the SAME unscopeable target held the test on one probe type and counted as
// PATH LOSS on the other.
//
// The consumer distinction is load-bearing: pkg/rpm treats ErrProbeSetup as
// "this probe never ran" (no counters, no transition) and anything else as a
// path signal that increments SuccFail and can trip a state change. `services
// ip-monitoring` drives preferred-route injection off that state — so a
// tcp-ping to an unscopeable fe80:: address, a probe that never left the box,
// could fail over a WAN.

// TestLinkLocalZoneGuardIsShared9026 exercises the shared guard directly, which
// is what makes "both probe types agree" a property rather than a coincidence.
func TestLinkLocalZoneGuardIsShared9026(t *testing.T) {
	m := &Manager{}
	for _, tc := range []struct {
		name      string
		ip        string
		zone      string
		destIface string
		wantZone  string
		wantSetup bool // expect ErrProbeSetup
	}{
		// THE DEFECT: an unscopeable link-local must HOLD, not report loss.
		{"link-local, no zone and no destination-interface", "fe80::1", "", "", "", true},

		// An explicit %zone is honoured, and a Junos slash name is normalized —
		// `ge-0/0/3` is not a kernel device name.
		{"link-local with an explicit zone", "fe80::1", "eth0", "", "eth0", false},
		{"link-local, Junos slash zone normalized", "fe80::1", "ge-0/0/3", "", "ge-0-0-3", false},

		// The destination-interface supplies the scope when no %zone was typed.
		{"link-local scoped by destination-interface", "fe80::1", "", "ge-0/0/3", "ge-0-0-3", false},

		// CONTROLS. A guard that fired on these would hold every ordinary
		// probe, which is a far worse failure than the one it fixes: an RPM
		// test that never runs cannot detect a real outage either.
		{"a global v6 address is not scoped", "2001:db8::1", "", "", "", false},
		{"a v4 address is not scoped", "192.0.2.1", "", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("fixture: %q is not an IP", tc.ip)
			}
			got, err := m.resolveLinkLocalZone9026("tcp", ip, tc.zone, tc.destIface)
			if tc.wantSetup {
				if !errors.Is(err, ErrProbeSetup) {
					t.Fatalf("err = %v, want ErrProbeSetup — anything else is counted as PATH "+
						"LOSS and can drive a WAN failover from a probe that never left the box", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantZone {
				t.Errorf("zone = %q, want %q", got, tc.wantZone)
			}
		})
	}
}

// TestTargetZoneSplit9026 pins the parse probeTCP does before the guard. A
// hostname must come back with a nil IP so the guard is skipped: a hostname is
// not a link-local scope question, and resolving it here would duplicate the
// resolver the ICMP path already uses.
func TestTargetZoneSplit9026(t *testing.T) {
	for _, tc := range []struct {
		target   string
		wantIP   string
		wantZone string
	}{
		{"fe80::1%eth0", "fe80::1", "eth0"},
		{"fe80::1", "fe80::1", ""},
		{"192.0.2.1", "192.0.2.1", ""},
		{"probe.example.com", "", ""},
	} {
		t.Run(tc.target, func(t *testing.T) {
			ip, zone := splitTargetZone9026(tc.target)
			if tc.wantIP == "" {
				if ip != nil {
					t.Errorf("a hostname parsed as IP %v — the guard would then run on it", ip)
				}
				return
			}
			if ip == nil || ip.String() != net.ParseIP(tc.wantIP).String() {
				t.Errorf("ip = %v, want %s", ip, tc.wantIP)
			}
			if zone != tc.wantZone {
				t.Errorf("zone = %q, want %q", zone, tc.wantZone)
			}
		})
	}
}

// TestProbeTCPHoldsOnAnUnscopeableLinkLocal9026 binds the WIRING, not the
// helper.
//
// The cells above drive resolveLinkLocalZone9026 directly, and a mutation
// removing its CALL from probeTCP left every one of them green — the guard
// correct and unreachable, which is precisely the state this issue reports for
// the TCP path. That is the second time today I wrote a gate whose test could
// not see it being unwired, so it is bound here explicitly.
//
// The assertion is the SENTINEL, not merely "an error": pkg/rpm distinguishes
// ErrProbeSetup (hold, no counters) from any other error (path loss, SuccFail++,
// possible state transition and a WAN failover). "probeTCP returned an error" is
// satisfied by the defect itself.
func TestProbeTCPHoldsOnAnUnscopeableLinkLocal9026(t *testing.T) {
	m := &Manager{}
	test := &config.RPMTest{
		Name:   "t1",
		Target: "fe80::1", // no %zone, and no destination-interface below
	}
	_, err := m.probeTCP(context.Background(), test, probeSockOpts{})
	if !errors.Is(err, ErrProbeSetup) {
		t.Fatalf("probeTCP(fe80::1) err = %v, want ErrProbeSetup.\n"+
			"Anything else is counted as PATH LOSS: SuccFail increments, the test can "+
			"transition, and `services ip-monitoring` can inject a preferred route — from a "+
			"probe that never left the box (#9026).", err)
	}

	// CONTROL: with a destination-interface the scope resolves, so the guard
	// must NOT hold. It will fail to dial (there is nothing at fe80::1%lo),
	// and that is a genuine path signal — which is the point: this cell must
	// not pass merely because everything errors.
	scoped := &config.RPMTest{Name: "t2", Target: "fe80::1", DestinationInterface: "lo"}
	if _, err := m.probeTCP(context.Background(), scoped, probeSockOpts{}); errors.Is(err, ErrProbeSetup) {
		t.Errorf("a link-local target WITH a destination-interface still held as a setup "+
			"failure: %v", err)
	}
}
