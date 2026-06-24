// scoped_hostname_2493_test.go — #2493: a VRF/device-scoped RPM test
// (routing-instance / destination-interface / next-hop) against a HOSTNAME
// must NOT probe. DNS resolution runs through the process-default resolver,
// which is not bound to the test's scope (the SO_BINDTODEVICE bind is
// applied per-connection, AFTER name resolution), so a scoped hostname
// probe measures resolver context, not path health. The commit gate
// rejects this; a leniently-loaded config still reaches the prober, so it
// holds state via ErrProbeSetup before any resolution runs.
package rpm

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestScopedHostnameHoldsStateAndSkipsResolver asserts the runtime guard:
// a scoped hostname probe returns ErrProbeSetup, opens NO socket, and never
// falls through to the (process-default) resolver seam.
func TestScopedHostnameHoldsStateAndSkipsResolver(t *testing.T) {
	scoped := []struct {
		name string
		test *config.RPMTest
	}{
		{"routing-instance", &config.RPMTest{Name: "t", Target: "wan-a.example.com", RoutingInstance: "ISP-B"}},
		{"destination-interface", &config.RPMTest{Name: "t", Target: "wan-a.example.com", DestinationInterface: "ge-0/0/1"}},
	}
	for _, tc := range scoped {
		t.Run(tc.name, func(t *testing.T) {
			var listens, resolves atomic.Int32
			m, conn := newFakeManager(nil)
			inner := m.icmpListen
			m.icmpListen = func(network, laddr string, opts probeSockOpts) (net.PacketConn, error) {
				listens.Add(1)
				return inner(network, laddr, opts)
			}
			m.resolveTarget = func(target string) (*net.IPAddr, error) {
				resolves.Add(1)
				return &net.IPAddr{IP: net.ParseIP("203.0.113.1")}, nil
			}

			_, err := m.executeProbe(context.Background(), tc.test, "WAN/t")
			if !errors.Is(err, ErrProbeSetup) {
				t.Fatalf("scoped hostname not classified ErrProbeSetup: %v", err)
			}
			if n := resolves.Load(); n != 0 {
				t.Fatalf("scoped hostname consulted the default resolver %d times, want 0 "+
					"(DNS would escape the configured scope)", n)
			}
			if n := listens.Load(); n != 0 {
				t.Fatalf("scoped hostname opened %d sockets, want 0", n)
			}
			if len(conn.sent) != 0 {
				t.Fatalf("scoped hostname sent %d packets, want 0", len(conn.sent))
			}
		})
	}
}

// TestUnscopedHostnameUsesResolver is the contrast case: an UNSCOPED
// hostname probe is NOT held — it resolves through the seam (in the same
// default context it probes) and sends.
func TestUnscopedHostnameUsesResolver(t *testing.T) {
	var resolves atomic.Int32
	target := net.ParseIP("203.0.113.5")
	m, conn := newFakeManager(func(b []byte, _ net.Addr) []fakeReply {
		return []fakeReply{echoReply(t, b, false, false, target)}
	})
	m.resolveTarget = func(name string) (*net.IPAddr, error) {
		resolves.Add(1)
		return &net.IPAddr{IP: target}, nil
	}

	test := &config.RPMTest{Name: "t", Target: "host.example.com"} // no scope
	if _, err := m.executeProbe(context.Background(), test, "WAN/t"); err != nil {
		t.Fatalf("unscoped hostname probe must run: %v", err)
	}
	if resolves.Load() != 1 {
		t.Fatalf("unscoped hostname did not consult the resolver seam: calls=%d", resolves.Load())
	}
	if len(conn.sent) != 1 {
		t.Fatalf("unscoped hostname did not send: sent=%d", len(conn.sent))
	}
}

// TestScopedIPLiteralProbes confirms a scoped IP-literal target is NOT held
// by the scoped-hostname guard — the legitimate multi-WAN scoped-probe
// shape probes normally. (The real resolveProbeTarget short-circuits an IP
// literal via net.ParseIP without any DNS lookup, so no scope is escaped.)
func TestScopedIPLiteralProbes(t *testing.T) {
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
