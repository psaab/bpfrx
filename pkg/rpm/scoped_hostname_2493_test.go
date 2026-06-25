// scoped_hostname_2493_test.go — #2493 / #2614.
//
// #2493 introduced a runtime guard that HELD a VRF/device-scoped RPM test
// (routing-instance / destination-interface / next-hop) whose target was a
// HOSTNAME, because DNS resolution ran through the process-default resolver
// (the SO_BINDTODEVICE bind was applied per-connection, AFTER name
// resolution) and so escaped the configured scope.
//
// #2614 LIFTS that guard: the resolver now resolves a hostname IN the
// probe's VRF/path scope — the DNS socket is bound to the SAME
// SO_BINDTODEVICE / SO_MARK the probe DATA socket uses (resolveProbeTarget
// for icmp-ping, probeDialer.Resolver for tcp-ping / http-get). So a
// scoped hostname now RESOLVES (in-context) and the probe runs. These
// tests assert the seam is consulted WITH the probe's opts (device/mark)
// so resolution is bound to the scope. Live VRF DNS is lab-bound; the
// seam/construction assertion is the gate.
package rpm

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestScopedHostnameResolvesInScope asserts the #2614 fix: a scoped
// hostname probe is NO LONGER held — it resolves through the seam, and the
// seam is handed the probe's probeSockOpts carrying the SAME BindDevice /
// Mark the probe DATA socket binds, so the lookup egresses the VRF/path.
//
// fail-on-revert: reverting resolveProbeTarget to the unbound
// net.ResolveIPAddr (which takes no opts) breaks the seam signature, and
// dropping the opts arg here makes the recorded BindDevice empty — the
// scope assertion below goes red.
func TestScopedHostnameResolvesInScope(t *testing.T) {
	scoped := []struct {
		name     string
		test     *config.RPMTest
		wantDev  string
		wantMark uint32
	}{
		{
			name:    "routing-instance",
			test:    &config.RPMTest{Name: "t", Target: "wan-a.example.com", RoutingInstance: "ISP-B"},
			wantDev: "vrf-ISP-B",
		},
		{
			name:    "destination-interface",
			test:    &config.RPMTest{Name: "t", Target: "wan-a.example.com", DestinationInterface: "ge-0/0/1"},
			wantDev: "ge-0-0-1",
		},
	}
	for _, tc := range scoped {
		t.Run(tc.name, func(t *testing.T) {
			target := net.ParseIP("203.0.113.1")
			var resolves atomic.Int32
			var gotOpts probeSockOpts
			m, conn := newFakeManager(func(b []byte, _ net.Addr) []fakeReply {
				return []fakeReply{echoReply(t, b, false, false, target)}
			})
			m.resolveTarget = func(_ context.Context, name string, opts probeSockOpts) (*net.IPAddr, error) {
				resolves.Add(1)
				gotOpts = opts
				return &net.IPAddr{IP: target}, nil
			}

			if _, err := m.executeProbe(context.Background(), tc.test, "WAN/t"); err != nil {
				t.Fatalf("scoped hostname probe must now run (#2614): %v", err)
			}
			if n := resolves.Load(); n != 1 {
				t.Fatalf("scoped hostname consulted the resolver %d times, want 1 "+
					"(#2614 resolves in-scope instead of holding)", n)
			}
			if gotOpts.BindDevice != tc.wantDev {
				t.Fatalf("resolver opts.BindDevice = %q, want %q "+
					"(DNS must bind the SAME scope as the probe socket)", gotOpts.BindDevice, tc.wantDev)
			}
			if gotOpts.Mark != tc.wantMark {
				t.Fatalf("resolver opts.Mark = %d, want %d", gotOpts.Mark, tc.wantMark)
			}
			if len(conn.sent) != 1 {
				t.Fatalf("scoped hostname sent %d packets, want 1", len(conn.sent))
			}
		})
	}
}

// TestVRFBoundResolverIsBuiltForScope is the construction-level gate (live
// VRF DNS is lab-bound): resolveProbeTarget with a non-empty scope builds a
// PreferGo resolver carrying a Dial hook (the slot that applies
// SO_BINDTODEVICE / SO_MARK), whereas an unscoped probe uses the default
// resolver (no Dial). fail-on-revert: the unbound net.ResolveIPAddr path
// has no per-scope resolver, so vrfBoundResolver would not exist / not be
// selected and this assertion fails.
func TestVRFBoundResolverIsBuiltForScope(t *testing.T) {
	// A scoped probe MUST get a bound (PreferGo + Dial) resolver, NOT the
	// process-default one. fail-on-revert: restoring the unbound
	// net.ResolveIPAddr / net.DefaultResolver path makes resolverForOpts
	// return net.DefaultResolver for a scoped probe and this goes red.
	for _, opts := range []probeSockOpts{
		{BindDevice: "vrf-ISP-B"},         // routing-instance / dest-iface scope
		{Mark: 0x1234},                    // next-hop pin scope
		{BindDevice: "ge-0-0-1", Mark: 7}, // both
	} {
		r := resolverForOpts(opts)
		if r == net.DefaultResolver {
			t.Fatalf("resolverForOpts(%+v) returned the DEFAULT resolver — DNS would "+
				"escape the probe's VRF/path scope (#2614)", opts)
		}
		if !r.PreferGo {
			t.Fatalf("resolverForOpts(%+v) must set PreferGo so the Dial hook (and its "+
				"SO_BINDTODEVICE / SO_MARK bind) is honored — the cgo resolver ignores Dial", opts)
		}
		if r.Dial == nil {
			t.Fatalf("resolverForOpts(%+v) must set a Dial hook to apply the VRF bind", opts)
		}
	}

	// An UNSCOPED probe uses the process-default resolver unchanged.
	if r := resolverForOpts(probeSockOpts{}); r != net.DefaultResolver {
		t.Fatal("resolverForOpts(unscoped) must be the default resolver (no behavior change)")
	}
}

// TestUnscopedHostnameUsesDefaultResolver is the contrast case: an UNSCOPED
// hostname probe still uses the seam and resolves with EMPTY opts — the
// default resolver, bit-identical to pre-#2614 behavior.
func TestUnscopedHostnameUsesDefaultResolver(t *testing.T) {
	var resolves atomic.Int32
	var gotOpts probeSockOpts
	target := net.ParseIP("203.0.113.5")
	m, conn := newFakeManager(func(b []byte, _ net.Addr) []fakeReply {
		return []fakeReply{echoReply(t, b, false, false, target)}
	})
	m.resolveTarget = func(_ context.Context, name string, opts probeSockOpts) (*net.IPAddr, error) {
		resolves.Add(1)
		gotOpts = opts
		return &net.IPAddr{IP: target}, nil
	}

	test := &config.RPMTest{Name: "t", Target: "host.example.com"} // no scope
	if _, err := m.executeProbe(context.Background(), test, "WAN/t"); err != nil {
		t.Fatalf("unscoped hostname probe must run: %v", err)
	}
	if resolves.Load() != 1 {
		t.Fatalf("unscoped hostname did not consult the resolver seam: calls=%d", resolves.Load())
	}
	if gotOpts.BindDevice != "" || gotOpts.Mark != 0 {
		t.Fatalf("unscoped probe resolver opts = %+v, want zero (default resolver)", gotOpts)
	}
	if len(conn.sent) != 1 {
		t.Fatalf("unscoped hostname did not send: sent=%d", len(conn.sent))
	}
}

// TestScopedIPLiteralSkipsDNS confirms a scoped IP-literal target never
// hits DNS — resolveProbeTarget short-circuits via net.ParseIP regardless
// of scope, so no resolver (bound or default) is consulted.
func TestScopedIPLiteralSkipsDNS(t *testing.T) {
	addr, err := resolveProbeTarget(context.Background(), "192.0.2.10", probeSockOpts{BindDevice: "vrf-ISP-B"})
	if err != nil {
		t.Fatalf("resolveProbeTarget IP literal: %v", err)
	}
	if !addr.IP.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("IP = %v, want 192.0.2.10", addr.IP)
	}

	// And the full probe path with a scoped IP literal still sends.
	target := net.ParseIP("192.0.2.10")
	m, conn := newFakeManager(func(b []byte, _ net.Addr) []fakeReply {
		return []fakeReply{echoReply(t, b, false, false, target)}
	})
	test := &config.RPMTest{Name: "t", Target: "192.0.2.10", DestinationInterface: "ge-0/0/1"}
	if _, err := m.executeProbe(context.Background(), test, "WAN/t"); err != nil {
		t.Fatalf("scoped IP-literal probe must run: %v", err)
	}
	if len(conn.sent) != 1 {
		t.Fatalf("scoped IP-literal did not send: sent=%d", len(conn.sent))
	}
}
