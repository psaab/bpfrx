package ddns

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
)

// #2691 P1b / #2665 source-binding tests: the resolved bindConfig + the custom
// net.Dialer the rfc2136 backend uses. The socket bind itself is a kernel
// operation exercised on the cluster; here we assert the DIAL CONFIGURATION
// (the unit the issue's fix-direction names) — LocalAddr/Control are wired iff
// a binding is configured, an invalid source-address is rejected, and the
// rfc2136 backend installs the custom dialer.

func TestResolveBindConfigEmptyIsNoBinding(t *testing.T) {
	b, err := resolveBindConfig(&config.DHCPDynamicDNSConfig{})
	if err != nil {
		t.Fatalf("empty config: %v", err)
	}
	if b.isSet() {
		t.Fatal("empty source-binding config must request NO binding")
	}
	if d := b.dialer(time.Second); d != nil {
		t.Fatal("no-binding config must yield a nil dialer (default transport)")
	}
}

func TestResolveBindConfigSourceAddress(t *testing.T) {
	b, err := resolveBindConfig(&config.DHCPDynamicDNSConfig{SourceAddress: "10.0.0.9"})
	if err != nil {
		t.Fatalf("source-address: %v", err)
	}
	if !b.sourceAddr.IsValid() || b.sourceAddr.String() != "10.0.0.9" {
		t.Fatalf("source-address not resolved: %v", b.sourceAddr)
	}
	if !b.isSet() {
		t.Fatal("a source-address must request a binding")
	}
	if d := b.dialer(time.Second); d == nil || d.Control == nil {
		t.Fatal("a source-address must produce a dialer with a Control hook (source bind)")
	}
}

func TestResolveBindConfigInvalidSourceAddressRejected(t *testing.T) {
	if _, err := resolveBindConfig(&config.DHCPDynamicDNSConfig{SourceAddress: "not-an-ip"}); err == nil {
		t.Fatal("an invalid source-address must be rejected (the manager then falls back to no-op + counts it)")
	}
}

func TestResolveBindConfigDestInterfaceWinsOverVRF(t *testing.T) {
	// destination-interface is the more specific SO_BINDTODEVICE pin; when both
	// it and a routing-instance are set, the destination-interface wins.
	b, err := resolveBindConfig(&config.DHCPDynamicDNSConfig{
		DestinationInterface: "ge-0-0-2",
		RoutingInstance:      "VRF-WAN",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if b.bindDevice != "ge-0-0-2" {
		t.Fatalf("destination-interface must win for SO_BINDTODEVICE, got %q", b.bindDevice)
	}
	if b.routingInst != "VRF-WAN" {
		t.Fatalf("routing-instance must be recorded, got %q", b.routingInst)
	}
}

func TestResolveBindConfigVRFOnlyBindsVRFDevice(t *testing.T) {
	b, err := resolveBindConfig(&config.DHCPDynamicDNSConfig{RoutingInstance: "VRF-WAN"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// A VRF binds to its VRF master device, which shares the routing-instance
	// name (Linux's VRF socket-binding model).
	if b.bindDevice != "VRF-WAN" {
		t.Fatalf("a VRF-only config must bind to the VRF device, got %q", b.bindDevice)
	}
}

// TestNewRFC2136UpdaterInstallsCustomDialer proves the rfc2136 backend installs
// the source-binding dialer on its production *dns.Client when a binding is
// configured (and leaves the default dialer when none is). The client seam is
// nil here so newRFC2136Updater builds the real *dns.Client.
func TestNewRFC2136UpdaterInstallsCustomDialer(t *testing.T) {
	pol := policyFromConfig(&config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", UpdateServer: "192.0.2.53:53",
	})
	// With a binding configured → custom dialer installed.
	withBind := &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", UpdateServer: "192.0.2.53:53",
		SourceAddress: "10.0.0.9",
	}
	u, err := newRFC2136Updater(pol, withBind, nil, nil, nil)
	if err != nil {
		t.Fatalf("newRFC2136Updater (with bind): %v", err)
	}
	cl, ok := u.client.(*dns.Client)
	if !ok {
		t.Fatalf("expected production *dns.Client, got %T", u.client)
	}
	if cl.Dialer == nil || cl.Dialer.Control == nil {
		t.Fatal("a configured source-address must install a custom dialer on the *dns.Client")
	}

	// With NO binding → default dialer (today's behaviour).
	noBind := &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", UpdateServer: "192.0.2.53:53",
	}
	u2, err := newRFC2136Updater(pol, noBind, nil, nil, nil)
	if err != nil {
		t.Fatalf("newRFC2136Updater (no bind): %v", err)
	}
	cl2 := u2.client.(*dns.Client)
	if cl2.Dialer != nil {
		t.Fatal("no source-binding must leave the *dns.Client's default dialer (nil)")
	}
}

// TestNewRFC2136UpdaterInvalidSourceAddressErrors proves an invalid
// source-address is surfaced from the constructor so the manager falls back to
// no-op for that family rather than emitting UPDATEs from the wrong source.
func TestNewRFC2136UpdaterInvalidSourceAddressErrors(t *testing.T) {
	pol := policyFromConfig(&config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", UpdateServer: "192.0.2.53:53",
	})
	bad := &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", UpdateServer: "192.0.2.53:53",
		SourceAddress: "garbage",
	}
	if _, err := newRFC2136Updater(pol, bad, nil, nil, nil); err == nil {
		t.Fatal("an invalid source-address must fail newRFC2136Updater")
	}
}

// TestSourceMatchesDialFamily proves the family gate keying off the
// Dialer.Control "network" argument: a v4 source matches a "4"-suffixed network
// and not a "6"-suffixed one (and vice-versa); an unsuffixed network permits the
// bind (no family hint, pre-#2901 behaviour).
func TestSourceMatchesDialFamily(t *testing.T) {
	v4 := netip.MustParseAddr("10.0.0.9")
	v6 := netip.MustParseAddr("2001:db8::9")
	cases := []struct {
		src     netip.Addr
		network string
		want    bool
	}{
		{v4, "tcp4", true}, {v4, "udp4", true},
		{v4, "tcp6", false}, {v4, "udp6", false},
		{v6, "tcp6", true}, {v6, "udp6", true},
		{v6, "tcp4", false}, {v6, "udp4", false},
		{v4, "tcp", true}, {v6, "udp", true}, // no family hint ⇒ permit
	}
	for _, c := range cases {
		if got := sourceMatchesDialFamily(c.src, c.network); got != c.want {
			t.Errorf("sourceMatchesDialFamily(%s, %q)=%v want %v", c.src, c.network, got, c.want)
		}
	}
}

// runDialerControl opens a real socket of the requested family, invokes the
// dialer's Control hook with the matching "network" string, and returns any
// error the hook surfaced. This exercises the exact unix.Bind path the issue
// describes, so the family gate is proven against the kernel (EAFNOSUPPORT is a
// kernel verdict, not a Go-level check).
func runDialerControl(t *testing.T, d *net.Dialer, family int, network string) error {
	t.Helper()
	fd, err := unix.Socket(family, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket(%d): %v", family, err)
	}
	defer unix.Close(fd)
	rc := rawConnFD(fd)
	return d.Control(network, "", rc)
}

// rawConnFD adapts a raw fd to the syscall.RawConn the Control hook expects. We
// only need Control(); Read/Write are unused by backend_bind's hook.
type rawConnFD int

func (r rawConnFD) Control(f func(fd uintptr)) error {
	f(uintptr(r))
	return nil
}
func (r rawConnFD) Read(func(fd uintptr) (done bool)) error  { return nil }
func (r rawConnFD) Write(func(fd uintptr) (done bool)) error { return nil }

var _ syscall.RawConn = rawConnFD(0)

// TestDialerSourceBindFamilyGate is the #2901 FAIL-ON-REVERT test. A
// source-address whose family MATCHES the dial network binds successfully (the
// source IP is applied — proven by reading it back with getsockname). A MISMATCH
// (v4 source on a v6 socket, and v6 source on a v4 socket) must NOT attempt the
// bind: it returns nil and the socket is left unbound. If the family gate is
// removed, the mismatch case attempts unix.Bind with the wrong-family Sockaddr
// and the kernel returns EAFNOSUPPORT (EINVAL on some kernels) — turning this
// test RED.
func TestDialerSourceBindFamilyGate(t *testing.T) {
	// A loopback source binds without needing the address assigned to an iface.
	b4, err := resolveBindConfig(&config.DHCPDynamicDNSConfig{SourceAddress: "127.0.0.1"})
	if err != nil {
		t.Fatalf("resolve v4: %v", err)
	}
	d4 := b4.dialer(time.Second)
	if d4 == nil || d4.Control == nil {
		t.Fatal("v4 source must produce a Control dialer")
	}

	// MATCH: v4 source on an AF_INET / "tcp4" dial → bind applied, no error.
	if err := runDialerControl(t, d4, unix.AF_INET, "tcp4"); err != nil {
		t.Fatalf("v4 source on tcp4 must bind cleanly, got %v", err)
	}
	// MISMATCH: v4 source on an AF_INET6 / "tcp6" dial → bind SKIPPED, no error.
	// Without the family gate this attempts unix.Bind(SockaddrInet4) on an
	// AF_INET6 socket → EAFNOSUPPORT/EINVAL.
	if err := runDialerControl(t, d4, unix.AF_INET6, "tcp6"); err != nil {
		if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EINVAL) {
			t.Fatalf("v4 source on tcp6 must SKIP the bind (family gate), got family error %v", err)
		}
		t.Fatalf("v4 source on tcp6 must not error, got %v", err)
	}

	b6, err := resolveBindConfig(&config.DHCPDynamicDNSConfig{SourceAddress: "::1"})
	if err != nil {
		t.Fatalf("resolve v6: %v", err)
	}
	d6 := b6.dialer(time.Second)
	if d6 == nil || d6.Control == nil {
		t.Fatal("v6 source must produce a Control dialer")
	}
	// MATCH: v6 source on an AF_INET6 / "tcp6" dial → bind applied, no error.
	if err := runDialerControl(t, d6, unix.AF_INET6, "tcp6"); err != nil {
		t.Fatalf("v6 source on tcp6 must bind cleanly, got %v", err)
	}
	// MISMATCH: v6 source on an AF_INET / "tcp4" dial → bind SKIPPED, no error.
	if err := runDialerControl(t, d6, unix.AF_INET, "tcp4"); err != nil {
		if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EINVAL) {
			t.Fatalf("v6 source on tcp4 must SKIP the bind (family gate), got family error %v", err)
		}
		t.Fatalf("v6 source on tcp4 must not error, got %v", err)
	}
}
