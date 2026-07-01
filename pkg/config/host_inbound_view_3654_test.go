package config

import (
	"strings"
	"testing"
)

// #3654: the shared host-inbound presentation SSOT. Every text/CLI surface
// (local `show security zones` / `show interfaces` / `test security-zone
// interface`, gRPC text zones + interface diagnostic, remote cmd/cli zones)
// routes through these helpers so none can drift back to hiding per-interface
// overrides (#3362) or the no-stanza default-deny posture (#3405). These unit
// tests pin the view/union/render contract the surface golden tests build on.

func TestUnionHostInboundTokens3654(t *testing.T) {
	got := UnionHostInboundTokens([]string{"ssh", "ping"}, []string{"ping", "https", ""})
	want := []string{"ssh", "ping", "https"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("UnionHostInboundTokens = %v, want %v (zone-first, dedup, empties skipped)", got, want)
	}
	if got := UnionHostInboundTokens(nil, nil); len(got) != 0 {
		t.Fatalf("UnionHostInboundTokens(nil,nil) = %v, want empty", got)
	}
}

func TestHostInboundDenyReason3654(t *testing.T) {
	cases := []struct {
		overridden, zoneConfigured bool
		want                       string
	}{
		{true, false, "interface override: deny-all"},
		{true, true, "interface override: deny-all"},
		{false, true, "empty stanza"},
		{false, false, "no stanza"},
	}
	for _, c := range cases {
		if got := HostInboundDenyReason(c.overridden, c.zoneConfigured); got != c.want {
			t.Errorf("HostInboundDenyReason(%v,%v) = %q, want %q", c.overridden, c.zoneConfigured, got, c.want)
		}
	}
}

func TestInterfaceHostInboundEffective3654(t *testing.T) {
	z := &ZoneConfig{
		HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}, Protocols: []string{"ospf"}},
		InterfaceHostInbound: map[string]*HostInboundTraffic{
			"ge-0/0/9.0": {SystemServices: []string{"https", "ssh"}},
		},
	}
	// Overridden interface: effective = zone UNION override.
	svc, proto, overridden := z.InterfaceHostInboundEffective("ge-0/0/9.0")
	if !overridden {
		t.Fatal("expected overridden=true for ge-0/0/9.0")
	}
	if strings.Join(svc, ",") != "ssh,https" {
		t.Fatalf("effective svc = %v, want [ssh https]", svc)
	}
	if strings.Join(proto, ",") != "ospf" {
		t.Fatalf("effective proto = %v, want [ospf]", proto)
	}
	// Non-overridden interface: effective = zone-level only, overridden=false.
	svc, _, overridden = z.InterfaceHostInboundEffective("ge-0/0/0.0")
	if overridden {
		t.Fatal("expected overridden=false for a non-overriding interface")
	}
	if strings.Join(svc, ",") != "ssh" {
		t.Fatalf("non-override svc = %v, want [ssh]", svc)
	}
}

func TestHostInboundViewRender3654(t *testing.T) {
	labels := HostInboundLabels{Indent: "  ", Sep: ", ", ServicesLabel: "Host-inbound system-services", ProtocolsLabel: "Host-inbound protocols"}

	// Populated zone with a per-interface override.
	z := &ZoneConfig{
		HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
		InterfaceHostInbound: map[string]*HostInboundTraffic{
			"ge-0/0/9.0": {SystemServices: []string{"https"}},
		},
	}
	out := strings.Join(z.HostInboundView().Render(labels), "\n")
	for _, want := range []string{
		"Host-inbound system-services: ssh",
		"Host-inbound interface overrides:",
		"ge-0/0/9.0:",
		"override system-services: https",
		"effective system-services: ssh, https",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("populated+override render missing %q\n%s", want, out)
		}
	}

	// No-stanza zone: explicit default-deny posture line.
	out = strings.Join((&ZoneConfig{}).HostInboundView().Render(labels), "\n")
	if !strings.Contains(out, "Host-inbound: default deny (no stanza)") {
		t.Errorf("no-stanza render missing posture line\n%s", out)
	}

	// Empty-stanza zone: posture line distinguishes it.
	z = &ZoneConfig{HostInboundTraffic: &HostInboundTraffic{}}
	out = strings.Join(z.HostInboundView().Render(labels), "\n")
	if !strings.Contains(out, "Host-inbound: default deny (empty stanza)") {
		t.Errorf("empty-stanza render missing posture line\n%s", out)
	}
}

func TestRenderInterfaceHostInbound3654(t *testing.T) {
	labels := HostInboundLabels{Indent: "  ", Sep: ", ", ServicesLabel: "Host-inbound services", ProtocolsLabel: "Host-inbound protocols"}
	z := &ZoneConfig{
		HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
		InterfaceHostInbound: map[string]*HostInboundTraffic{
			"ge-0/0/9.0": {SystemServices: []string{"https"}},
		},
	}
	// Overridden interface: shows zone-level, the override marker, and effective.
	out := strings.Join(z.RenderInterfaceHostInbound("ge-0/0/9.0", labels), "\n")
	for _, want := range []string{
		"Host-inbound services: ssh",
		"Host-inbound interface override on ge-0/0/9.0:",
		"effective host-inbound services: ssh, https",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("override diagnostic missing %q\n%s", want, out)
		}
	}
	// A no-stanza zone interface: default-deny posture line.
	out = strings.Join((&ZoneConfig{}).RenderInterfaceHostInbound("ge-0/0/0.0", labels), "\n")
	if !strings.Contains(out, "Host-inbound: default deny (no stanza)") {
		t.Errorf("no-stanza diagnostic missing posture line\n%s", out)
	}
}
