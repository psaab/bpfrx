package ddns

import (
	"testing"
	"time"

	"github.com/miekg/dns"

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
