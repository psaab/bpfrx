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
	// Overridden interface: effective = the OVERRIDE, which REPLACES the
	// zone-level stanza (#6515). The fixture is deliberately asymmetric — the
	// override declares only system-services — so it also pins the granularity:
	// the whole zone stanza is replaced, so the zone's `protocols ospf` does NOT
	// survive on this interface either. A per-leaf inheritance rule would leave
	// ospf here, and no vendor text describes one.
	svc, proto, overridden := z.InterfaceHostInboundEffective("ge-0/0/9.0")
	if !overridden {
		t.Fatal("expected overridden=true for ge-0/0/9.0")
	}
	if strings.Join(svc, ",") != "https,ssh" {
		t.Fatalf("effective svc = %v, want [https ssh] (the override REPLACES the zone stanza, #6515)", svc)
	}
	if len(proto) != 0 {
		t.Fatalf("effective proto = %v, want none: the whole zone stanza is replaced, so the "+
			"zone's `protocols ospf` does not reach an interface that declares its own "+
			"host-inbound-traffic (#6515 granularity)", proto)
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
		// #6515: the override REPLACES the zone stanza on this interface, so
		// the effective line is the override alone. The zone-level line above
		// still reads `ssh` — it governs every interface that does NOT declare
		// a stanza, which is exactly why both lines are asserted here: an
		// operator reading only one of them would misjudge the posture.
		"effective system-services: https",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("populated+override render missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "effective system-services: ssh") {
		t.Errorf("the effective line must NOT carry the zone's `ssh` on an overridden "+
			"interface — the interface stanza replaces it (#6515)\n%s", out)
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

// TestHostInboundViewRenderZonePostureWithOverride3671 pins the #3671 residual
// fix (H08 / folds the L03 test gap): a zone with EMPTY zone-level host-inbound
// lists but a per-interface override must STILL render the zone-level
// default-deny posture line, because that posture governs every non-overridden
// interface in the zone. The override block is additional context printed below
// it, not a replacement for it.
//
// RED-on-revert: restoring the old `&& len(v.Interfaces) == 0` clause on the
// posture guard suppresses the "Host-inbound: default deny (...)" line whenever
// any interface override exists, failing the posture assertion here.
func TestHostInboundViewRenderZonePostureWithOverride3671(t *testing.T) {
	labels := HostInboundLabels{Indent: "  ", Sep: ", ", ServicesLabel: "Host-inbound system-services", ProtocolsLabel: "Host-inbound protocols"}

	// A zone with no zone-level stanza at all, but an override on ONE interface.
	// The zone default-deny posture (reason "no stanza") governs the other,
	// non-overridden interfaces and must remain visible.
	z := &ZoneConfig{
		InterfaceHostInbound: map[string]*HostInboundTraffic{
			"ge-0/0/9.0": {SystemServices: []string{"https"}},
		},
	}
	lines := z.HostInboundView().Render(labels)
	out := strings.Join(lines, "\n")
	for _, want := range []string{
		// zone-level default-deny posture line — MUST survive the override
		"Host-inbound: default deny (no stanza)",
		// override block still rendered below the posture line
		"Host-inbound interface overrides:",
		"ge-0/0/9.0:",
		"override system-services: https",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no-stanza zone + override render missing %q\n%s", want, out)
		}
	}
	// Ordering: the zone posture line precedes the override block (posture is the
	// baseline, overrides are additional context).
	postureIdx, overrideIdx := -1, -1
	for i, ln := range lines {
		if strings.Contains(ln, "Host-inbound: default deny") {
			postureIdx = i
		}
		if strings.Contains(ln, "Host-inbound interface overrides:") {
			overrideIdx = i
		}
	}
	if postureIdx < 0 || overrideIdx < 0 || postureIdx > overrideIdx {
		t.Errorf("expected zone posture line before override block; posture=%d override=%d\n%s",
			postureIdx, overrideIdx, out)
	}

	// An EXPLICIT-EMPTY zone stanza with an override: posture reason distinguishes
	// it as "empty stanza" and still renders alongside the override block.
	z = &ZoneConfig{
		HostInboundTraffic: &HostInboundTraffic{},
		InterfaceHostInbound: map[string]*HostInboundTraffic{
			"ge-0/0/9.0": {SystemServices: []string{"https"}},
		},
	}
	out = strings.Join(z.HostInboundView().Render(labels), "\n")
	if !strings.Contains(out, "Host-inbound: default deny (empty stanza)") {
		t.Errorf("empty-stanza zone + override render missing posture line\n%s", out)
	}
	if !strings.Contains(out, "Host-inbound interface overrides:") {
		t.Errorf("empty-stanza zone + override render missing override block\n%s", out)
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
	out := strings.Join(z.RenderInterfaceHostInbound("ge-0/0/9.0", false, labels), "\n")
	for _, want := range []string{
		"Host-inbound services: ssh",
		"Host-inbound interface override on ge-0/0/9.0:",
		// #6515: effective = the override, the zone's ssh having been replaced.
		"effective host-inbound services: https",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("override diagnostic missing %q\n%s", want, out)
		}
	}
	// A no-stanza zone interface: default-deny posture line.
	out = strings.Join((&ZoneConfig{}).RenderInterfaceHostInbound("ge-0/0/0.0", false, labels), "\n")
	if !strings.Contains(out, "Host-inbound: default deny (no stanza)") {
		t.Errorf("no-stanza diagnostic missing posture line\n%s", out)
	}
}
