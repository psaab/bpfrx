package policymatch

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestHostInboundVerdictNotMisleadingProceeds is the #3627 RED-on-revert guard
// for the host-inbound match-policies verdict wording.
//
// Post-#3405 a security zone with interfaces but NO host-inbound-traffic stanza
// DEFAULT-DENIES host-bound traffic (see
// dataplane/userspace.TestNoStanzaZoneDefaultDeniesBothSurfaces). The
// simulator does not model host-inbound-traffic service admission — it only
// reports that no transit/global/default policy governs a `to-zone junos-host`
// flow (#3285) — so the operator-facing verdict must NOT claim local delivery
// unconditionally "proceeds": for a no-stanza zone the packet is dropped by the
// host-inbound default-deny. The pre-#3627 strings said "local delivery
// proceeds", which read as an admit even for a default-deny zone.
//
// Fail-on-revert: restoring the "local delivery proceeds" / "local delivery;
// not governed ..." wording drops the host-inbound-traffic + default-deny
// qualification, turning the assertions below RED.
func TestHostInboundVerdictNotMisleadingProceeds(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    string
	}{
		{"HostInboundActionString", HostInboundActionString},
		{"HostInboundShowLine", HostInboundShowLine},
	} {
		s := tc.s
		// Must not assert unconditional delivery.
		if strings.Contains(s, "proceeds") {
			t.Errorf("%s = %q\nmust not say delivery \"proceeds\": misleading for a "+
				"no-stanza host-inbound default-deny zone (#3405/#3627)", tc.name, s)
		}
		// Must name the surface that actually governs local delivery and note
		// the no-stanza default-deny.
		if !strings.Contains(s, "host-inbound-traffic") {
			t.Errorf("%s = %q\nmust reference host-inbound-traffic service admission (#3627)", tc.name, s)
		}
		if !strings.Contains(s, "default") {
			t.Errorf("%s = %q\nmust convey the no-stanza default-deny (#3405/#3627)", tc.name, s)
		}
		// Must still record the #3285 fact that transit/global/default policy
		// is not consulted on the host path.
		if !strings.Contains(s, "NOT applied") {
			t.Errorf("%s = %q\nmust still note transit/global/default policy NOT applied (#3285)", tc.name, s)
		}
	}
}

// TestNoStanzaZoneHostQueryRendersAccurateVerdict exercises the real match
// path: a `to-zone junos-host` query against a config whose ingress zone has no
// matching host-bound policy returns HostInboundUnmatched, and DisplayAction
// renders the accurate (non-misleading) verdict string — not "proceeds".
func TestNoStanzaZoneHostQueryRendersAccurateVerdict(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		// "edge" has no host-inbound-traffic stanza and no to-zone junos-host
		// policy, so the runtime host gate returns None and the actual admit is
		// decided by host-inbound-traffic (default-deny for this zone, #3405).
		Zones: zones("edge"),
	}, config.ApplicationsConfig{})

	res := Match(cfg, Query{FromZone: "edge", ToZone: "junos-host"})
	if !res.HostInboundUnmatched {
		t.Fatalf("HostInboundUnmatched = false, want true for an unmatched to-zone junos-host query")
	}
	got := res.DisplayAction()
	if got != HostInboundActionString {
		t.Errorf("DisplayAction() = %q, want HostInboundActionString %q", got, HostInboundActionString)
	}
	if strings.Contains(got, "proceeds") {
		t.Errorf("host-inbound verdict %q falsely asserts delivery proceeds "+
			"(a no-stanza zone default-denies host-inbound, #3405/#3627)", got)
	}
}
