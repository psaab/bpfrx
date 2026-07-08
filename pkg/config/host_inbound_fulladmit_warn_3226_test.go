package config

import (
	"strings"
	"testing"
)

// hostInboundFullAdmitWarnings returns the #3226 commit-time advisories emitted
// by ValidateConfig for a `system-services all` / `any-service` packet-wide
// full-admit. The advisory phrase is unique to this check.
func hostInboundFullAdmitWarnings(cfg *Config) []string {
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "broad packet-wide full-admit") {
			out = append(out, w)
		}
	}
	return out
}

// Test_3226_SystemServicesAllEmitsFullAdmitAdvisory is the #3226 RED-on-revert
// guard for the commit-time advisory the issue's Direction asks for ("document
// it as such with an explicit commit warning"). A zone whose
// host-inbound-traffic sets `system-services all` (or the `any-service` alias)
// must:
//
//   - COMPILE with NO error (it is valid Junos — the breadth is deliberate and
//     documented per #3199; the advisory is a WARNING, never a reject), and
//   - carry the packet-wide-full-admit advisory naming the offending zone.
//
// A zone that lists only SPECIFIC services (e.g. ssh) must draw NO such
// advisory, and the per-interface override form (#3362) must warn identically.
//
// RED-on-revert: delete the `HostInboundFullAdmitService` advisory loop in
// compiler_validate_warn.go and the `all` / `any-service` / per-interface cases
// below stop warning, turning this test RED.
func Test_3226_SystemServicesAllEmitsFullAdmitAdvisory(t *testing.T) {
	for _, tok := range []string{"all", "any-service"} {
		t.Run("zone-level-"+tok, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
				"set security zones security-zone trust host-inbound-traffic system-services " + tok,
			})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig must accept system-services %s (valid Junos, warn-not-reject): %v", tok, err)
			}
			got := hostInboundFullAdmitWarnings(cfg)
			if len(got) != 1 {
				t.Fatalf("system-services %s: expected exactly one full-admit advisory, got %d: %v", tok, len(got), got)
			}
			if !strings.Contains(got[0], `zone "trust"`) {
				t.Errorf("advisory must name the zone, got: %q", got[0])
			}
			if !strings.Contains(got[0], tok) {
				t.Errorf("advisory must name the offending token %q, got: %q", tok, got[0])
			}
		})
	}
}

// Test_3226_SpecificServiceNoAdvisory pins the other half of the contract: a
// zone that lists only named/specific system-services (ssh, ping) is NOT a
// packet-wide full-admit and must draw NO #3226 advisory.
func Test_3226_SpecificServiceNoAdvisory(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone trust host-inbound-traffic system-services ping",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got := hostInboundFullAdmitWarnings(cfg); len(got) != 0 {
		t.Fatalf("specific services (ssh/ping) must NOT draw a full-admit advisory, got: %v", got)
	}
}

// Test_3226_PerInterfaceFullAdmitAdvisory covers the #3362 per-interface
// override path: a `system-services all` set only on one interface of a zone
// must warn and name BOTH the zone and the interface.
func Test_3226_PerInterfaceFullAdmitAdvisory(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone wan interfaces ge-0/0/0.0 host-inbound-traffic system-services all",
		// a sibling interface with a specific service — must NOT warn.
		"set security zones security-zone wan interfaces ge-0/0/1.0 host-inbound-traffic system-services ssh",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig must accept a per-interface system-services all: %v", err)
	}
	got := hostInboundFullAdmitWarnings(cfg)
	if len(got) != 1 {
		t.Fatalf("expected exactly one per-interface full-admit advisory, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], `zone "wan"`) || !strings.Contains(got[0], `interface "ge-0/0/0.0"`) {
		t.Errorf("per-interface advisory must name both zone and interface, got: %q", got[0])
	}
}
