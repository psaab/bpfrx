package config

import (
	"strings"
	"testing"
)

// #3682: the host-inbound LIFELINE exemption (management / cluster-control
// interfaces excluded from host-inbound deny scoping) must be OPERATOR-VISIBLE.
// Before #3682 a zone-assigned em0/fab*/fxp0 (or a configured control/fabric)
// interface silently dropped out of the host-inbound default-deny with nothing
// on any zone view to say so. These tests pin the visibility contract on the
// shared presenter SSOT: the zone-view render emits a lifeline-exempt line, and
// the per-interface diagnostic emits a lifeline-exempt marker in place of the
// (misleading) default-deny line. They go RED if the exemption is made invisible
// again (the render lines removed) — the exemption becomes silent once more.

func TestHostInboundLifelineInterface3682(t *testing.T) {
	def := HostInboundLifelineSet(nil)
	// The always-on defaults plus fxp0 are lifelines regardless of config.
	for _, name := range []string{"fxp0", "fxp0.0", "em0", "em0.0", "fab0", "fab0.0", "fab1.0"} {
		if !HostInboundLifelineInterface(name, def) {
			t.Errorf("HostInboundLifelineInterface(%q) = false, want true (default lifeline)", name)
		}
	}
	// A regular data-plane interface is NOT a lifeline.
	for _, name := range []string{"ge-0/0/0.0", "reth0.50", "xe-1/0/0.0", ""} {
		if HostInboundLifelineInterface(name, def) {
			t.Errorf("HostInboundLifelineInterface(%q) = true, want false", name)
		}
	}
	// A configured chassis-cluster control-interface is added to the set (#3277).
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{ControlInterface: "hb0", FabricInterface: "fabx0"}
	set := HostInboundLifelineSet(cfg)
	for _, name := range []string{"hb0", "hb0.0", "fabx0.0"} {
		if !HostInboundLifelineInterface(name, set) {
			t.Errorf("configured lifeline %q not matched", name)
		}
	}
}

// TestHostInboundViewLifelineExemptRendered3682 is the RED-on-revert proof: a
// zone with an em0/fab* member must render the lifeline-exempt line in the zone
// host-inbound view, and a zone without any lifeline member must NOT.
func TestHostInboundViewLifelineExemptRendered3682(t *testing.T) {
	labels := HostInboundLabels{
		Indent: "  ", Sep: ", ",
		ServicesLabel: "Host-inbound system-services", ProtocolsLabel: "Host-inbound protocols",
	}
	const marker = "Host-inbound lifeline-exempt interfaces (management/fabric, bypass host-inbound deny):"

	// Zone that (mis)assigns em0 and fab0 alongside a regular data interface.
	z := &ZoneConfig{
		Interfaces:         []string{"ge-0/0/0.0", "em0.0", "fab0.0"},
		HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
	}
	out := strings.Join(z.HostInboundViewWithLifelines(nil).Render(labels), "\n")
	if !strings.Contains(out, marker) {
		t.Fatalf("zone view missing lifeline-exempt line (exemption is invisible)\n%s", out)
	}
	// The exempt line must list the lifeline members and NOT the data interface.
	for _, want := range []string{"em0.0", "fab0.0"} {
		if !strings.Contains(out, want) {
			t.Errorf("lifeline-exempt line missing %q\n%s", want, out)
		}
	}
	lifelineLine := ""
	for _, l := range z.HostInboundViewWithLifelines(nil).Render(labels) {
		if strings.Contains(l, marker) {
			lifelineLine = l
		}
	}
	if strings.Contains(lifelineLine, "ge-0/0/0.0") {
		t.Errorf("data interface ge-0/0/0.0 wrongly listed as lifeline-exempt: %q", lifelineLine)
	}

	// A zone with only data interfaces must NOT render the lifeline line.
	zd := &ZoneConfig{
		Interfaces:         []string{"ge-0/0/0.0"},
		HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
	}
	if out := strings.Join(zd.HostInboundViewWithLifelines(nil).Render(labels), "\n"); strings.Contains(out, marker) {
		t.Errorf("no-lifeline zone wrongly rendered the exempt line\n%s", out)
	}
}

// TestHostInboundViewLifelineFromClusterConfig3682 proves a configured
// (non-default-named) control/fabric interface is surfaced too.
func TestHostInboundViewLifelineFromClusterConfig3682(t *testing.T) {
	labels := HostInboundLabels{Indent: "  ", Sep: ", "}
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{ControlInterface: "hb0"}
	z := &ZoneConfig{Interfaces: []string{"hb0.0", "ge-0/0/1.0"}}
	out := strings.Join(z.HostInboundViewWithLifelines(HostInboundLifelineSet(cfg)).Render(labels), "\n")
	if !strings.Contains(out, "hb0.0") ||
		!strings.Contains(out, "lifeline-exempt interfaces") {
		t.Fatalf("configured control-interface hb0.0 not surfaced as lifeline-exempt\n%s", out)
	}
}

// TestRenderInterfaceHostInboundLifeline3682 pins the per-interface diagnostic:
// a lifeline interface renders the exempt marker in place of the default-deny
// line; a non-lifeline no-stanza interface still renders default-deny.
func TestRenderInterfaceHostInboundLifeline3682(t *testing.T) {
	labels := HostInboundLabels{Indent: "  ", Sep: ", ", ServicesLabel: "Host-inbound services", ProtocolsLabel: "Host-inbound protocols"}
	const exempt = "Host-inbound: lifeline-exempt (management/fabric, bypasses host-inbound deny)"

	z := &ZoneConfig{}
	// lifeline=true: exempt marker, NO default-deny line.
	out := strings.Join(z.RenderInterfaceHostInbound("em0.0", true, labels), "\n")
	if !strings.Contains(out, exempt) {
		t.Errorf("lifeline diagnostic missing exempt marker\n%s", out)
	}
	if strings.Contains(out, "default deny") {
		t.Errorf("lifeline diagnostic must not show default-deny\n%s", out)
	}
	// lifeline=false, no stanza: default-deny line, NO exempt marker.
	out = strings.Join(z.RenderInterfaceHostInbound("ge-0/0/0.0", false, labels), "\n")
	if !strings.Contains(out, "Host-inbound: default deny (no stanza)") {
		t.Errorf("non-lifeline diagnostic missing default-deny line\n%s", out)
	}
	if strings.Contains(out, exempt) {
		t.Errorf("non-lifeline diagnostic must not show lifeline-exempt marker\n%s", out)
	}
}
