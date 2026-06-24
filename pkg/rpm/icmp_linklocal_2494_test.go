package rpm

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestResolveProbeTargetPreservesZone proves resolveProbeTarget keeps the
// IPv6 link-local zone (#2494). net.ParseIP rejects a zoned literal, so a
// `fe80::1%ge-0-0-3` target must round-trip through net.ResolveIPAddr,
// which populates IPAddr.Zone. Before #2494 the resolver returned a bare
// net.IP and the zone was dropped — this test fails on master.
func TestResolveProbeTargetPreservesZone(t *testing.T) {
	addr, err := resolveProbeTarget("fe80::1%ge-0-0-3")
	if err != nil {
		t.Fatalf("resolveProbeTarget: %v", err)
	}
	if addr.Zone != "ge-0-0-3" {
		t.Fatalf("zone = %q, want ge-0-0-3 (link-local scope dropped)", addr.Zone)
	}
	if !addr.IP.IsLinkLocalUnicast() {
		t.Fatalf("IP = %v, want a link-local address", addr.IP)
	}

	// A plain global literal carries no zone.
	g, err := resolveProbeTarget("2001:db8::10")
	if err != nil {
		t.Fatalf("resolveProbeTarget global: %v", err)
	}
	if g.Zone != "" {
		t.Fatalf("global zone = %q, want empty", g.Zone)
	}
}

// TestProbeICMPLinkLocalSendsWithExplicitZone confirms the send path
// builds an &net.IPAddr carrying the explicit zone from the target
// literal. This is the core correctness fix: the echo leaves the right
// link. Fails on master (send used &net.IPAddr{IP: dst} with no Zone).
func TestProbeICMPLinkLocalSendsWithExplicitZone(t *testing.T) {
	target := net.ParseIP("fe80::1")
	m, conn := newFakeManager(func(b []byte, _ net.Addr) []fakeReply {
		return []fakeReply{echoReply(t, b, true, false, target)}
	})
	test := &config.RPMTest{Name: "t", Target: "fe80::1%ge-0-0-3"}
	if _, err := m.probeICMP(context.Background(), test, probeSockOpts{}); err != nil {
		t.Fatalf("probeICMP link-local: %v", err)
	}
	if len(conn.sentAddr) != 1 {
		t.Fatalf("sent %d packets, want 1", len(conn.sentAddr))
	}
	dst, ok := conn.sentAddr[0].(*net.IPAddr)
	if !ok {
		t.Fatalf("send addr type = %T, want *net.IPAddr", conn.sentAddr[0])
	}
	if dst.Zone != "ge-0-0-3" {
		t.Fatalf("send zone = %q, want ge-0-0-3", dst.Zone)
	}
}

// TestProbeICMPLinkLocalDefaultsZoneToBindDevice confirms a bare
// link-local target with no %zone defaults the send zone to the resolved
// egress device (opts.BindDevice — the same kernel ifname the data socket
// binds via SO_BINDTODEVICE), derived from destination-interface.
func TestProbeICMPLinkLocalDefaultsZoneToBindDevice(t *testing.T) {
	target := net.ParseIP("fe80::1")
	m, conn := newFakeManager(func(b []byte, _ net.Addr) []fakeReply {
		return []fakeReply{echoReply(t, b, true, false, target)}
	})
	test := &config.RPMTest{Name: "t", Target: "fe80::1", DestinationInterface: "ge-0/0/3"}
	// opts.BindDevice mirrors what probeOpts derives from
	// destination-interface (kernel ifname, slashes->dashes).
	opts := probeSockOpts{BindDevice: "ge-0-0-3"}
	if _, err := m.probeICMP(context.Background(), test, opts); err != nil {
		t.Fatalf("probeICMP link-local default zone: %v", err)
	}
	dst, ok := conn.sentAddr[0].(*net.IPAddr)
	if !ok {
		t.Fatalf("send addr type = %T, want *net.IPAddr", conn.sentAddr[0])
	}
	if dst.Zone != "ge-0-0-3" {
		t.Fatalf("send zone = %q, want ge-0-0-3 (defaulted from BindDevice)", dst.Zone)
	}
}

// TestProbeICMPLinkLocalNoZoneHeld confirms a bare link-local with no
// %zone and no resolvable egress device is HELD with ErrProbeSetup rather
// than sent to the wrong link.
func TestProbeICMPLinkLocalNoZoneHeld(t *testing.T) {
	m, conn := newFakeManager(nil)
	test := &config.RPMTest{Name: "t", Target: "fe80::1"}
	_, err := m.probeICMP(context.Background(), test, probeSockOpts{})
	if err == nil {
		t.Fatal("probeICMP link-local with no zone returned nil error, want ErrProbeSetup")
	}
	if !errors.Is(err, ErrProbeSetup) {
		t.Fatalf("err = %v, want ErrProbeSetup", err)
	}
	if len(conn.sent) != 0 {
		t.Fatalf("sent %d packets, want 0 (must not probe an unscoped link-local)", len(conn.sent))
	}
}

// TestProbeICMPGlobalV6NoZone confirms a global IPv6 target still sends
// with an empty zone (the link-local handling does not touch it).
func TestProbeICMPGlobalV6NoZone(t *testing.T) {
	target := net.ParseIP("2001:db8::10")
	m, conn := newFakeManager(func(b []byte, _ net.Addr) []fakeReply {
		return []fakeReply{echoReply(t, b, true, false, target)}
	})
	test := &config.RPMTest{Name: "t", Target: "2001:db8::10"}
	if _, err := m.probeICMP(context.Background(), test, probeSockOpts{BindDevice: "ge-0-0-3"}); err != nil {
		t.Fatalf("probeICMP global v6: %v", err)
	}
	dst := conn.sentAddr[0].(*net.IPAddr)
	if dst.Zone != "" {
		t.Fatalf("global v6 send zone = %q, want empty", dst.Zone)
	}
}
