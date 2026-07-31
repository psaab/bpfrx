package config

import (
	"strings"
	"testing"
)

// hostInboundFullAdmitWarnings returns the commit-time advisories emitted by
// ValidateConfig for a `system-services any-service` packet-wide full-admit.
// The advisory phrase is unique to this check.
func hostInboundFullAdmitWarnings(cfg *Config) []string {
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "broad packet-wide full-admit") {
			out = append(out, w)
		}
	}
	return out
}

// hostInboundAllScopingWarnings returns the #3226 commit-time UPGRADE advisories
// emitted for a `system-services all` stanza on an enforcing (non-lifeline)
// zone/interface. The advisory phrase is unique to this check.
func hostInboundAllScopingWarnings(cfg *Config) []string {
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "expands to the union of the") {
			out = append(out, w)
		}
	}
	return out
}

// Test_3226_SystemServicesAllEmitsFullAdmitAdvisory is the RED-on-revert guard
// for the commit-time advisories the issue's Direction asks for ("document it
// as such with an explicit commit warning"). Since #3226 the two tokens carry
// DIFFERENT advisories because they now have different semantics:
//
//   - `any-service` is still the packet-wide full admit -> the breadth advisory;
//   - `all` is the named-service union -> the SCOPING advisory, an upgrade
//     notice for a deploy that leaned on the old packet-wide breadth.
//
// Both must COMPILE with NO error (each is valid Junos; the advisory is a
// WARNING, never a reject).
//
// RED-on-revert: delete the advisory loops in compiler_validate_warn.go and
// both cases stop warning. Restoring `all` to HostInboundFullAdmitService makes
// it emit the FULL-ADMIT advisory instead of the scoping one, which this test
// also catches (each subtest asserts the OTHER advisory is absent).
func Test_3226_SystemServicesAllEmitsFullAdmitAdvisory(t *testing.T) {
	compileZone := func(t *testing.T, tok string) *Config {
		t.Helper()
		tree := buildTree(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set security zones security-zone trust interfaces ge-0/0/0.0",
			"set security zones security-zone trust host-inbound-traffic system-services " + tok,
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig must accept system-services %s (valid Junos, warn-not-reject): %v", tok, err)
		}
		return cfg
	}

	t.Run("zone-level-any-service", func(t *testing.T) {
		cfg := compileZone(t, "any-service")
		got := hostInboundFullAdmitWarnings(cfg)
		if len(got) != 1 {
			t.Fatalf("system-services any-service: expected exactly one full-admit advisory, got %d: %v", len(got), got)
		}
		if !strings.Contains(got[0], `zone "trust"`) {
			t.Errorf("advisory must name the zone, got: %q", got[0])
		}
		if !strings.Contains(got[0], "any-service") {
			t.Errorf("advisory must name the offending token, got: %q", got[0])
		}
		if extra := hostInboundAllScopingWarnings(cfg); len(extra) != 0 {
			t.Errorf("any-service must NOT draw the `all` scoping advisory, got: %v", extra)
		}
	})

	t.Run("zone-level-all", func(t *testing.T) {
		cfg := compileZone(t, "all")
		// #3226: `all` is no longer packet-wide, so it must NOT draw the
		// full-admit advisory. Reverting the narrowing turns this RED.
		if got := hostInboundFullAdmitWarnings(cfg); len(got) != 0 {
			t.Errorf("system-services all must NOT draw the packet-wide full-admit advisory (#3226), got: %v", got)
		}
		got := hostInboundAllScopingWarnings(cfg)
		if len(got) != 1 {
			t.Fatalf("system-services all: expected exactly one scoping advisory, got %d: %v", len(got), got)
		}
		if !strings.Contains(got[0], `zone "trust"`) {
			t.Errorf("scoping advisory must name the zone, got: %q", got[0])
		}
		if !strings.Contains(got[0], "any-service") {
			t.Errorf("scoping advisory must point at the `any-service` escape hatch, got: %q", got[0])
		}
	})
}

// Test_3226_AllScopingAdvisorySilentOnLifelineOnlyZone pins the advisory's
// noise gate: a zone whose every interface is a LIFELINE (fxp0 + the configured
// cluster control / fabric interfaces, #3277) is excluded from the host-inbound
// deny address sets by BuildZoneHostInboundViews, so it emits no rules at all
// and the #3226 narrowing cannot change its enforcement. Every shipped HA
// config puts `system-services all` on exactly such a zone (the lifeline-only
// `control` zone — docs/ha-cluster-userspace.conf), so an ungated advisory would
// fire on every cluster commit forever while flagging a guaranteed no-op.
//
// RED-on-revert: drop the `zoneEnforces` gate in compiler_validate_warn.go and
// this test goes RED with a spurious advisory.
func Test_3226_AllScopingAdvisorySilentOnLifelineOnlyZone(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"set security zones security-zone control interfaces em0.0",
		"set security zones security-zone control host-inbound-traffic system-services all",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got := hostInboundAllScopingWarnings(cfg); len(got) != 0 {
		t.Errorf("a lifeline-only zone must draw NO #3226 scoping advisory (the narrowing is a no-op there), got: %v", got)
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
// override path: a full-admit / `all` set on only one interface of a zone must
// warn and name BOTH the zone and the interface. Both advisory flavours are
// exercised so the per-interface path cannot drift from the zone-level one.
func Test_3226_PerInterfaceFullAdmitAdvisory(t *testing.T) {
	compileIface := func(t *testing.T, tok string) *Config {
		t.Helper()
		tree := buildTree(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
			"set security zones security-zone wan interfaces ge-0/0/0.0 host-inbound-traffic system-services " + tok,
			// a sibling interface with a specific service — must NOT warn.
			"set security zones security-zone wan interfaces ge-0/0/1.0 host-inbound-traffic system-services ssh",
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig must accept a per-interface system-services %s: %v", tok, err)
		}
		return cfg
	}

	got := hostInboundFullAdmitWarnings(compileIface(t, "any-service"))
	if len(got) != 1 {
		t.Fatalf("expected exactly one per-interface full-admit advisory, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], `zone "wan"`) || !strings.Contains(got[0], `interface "ge-0/0/0.0"`) {
		t.Errorf("per-interface advisory must name both zone and interface, got: %q", got[0])
	}

	got = hostInboundAllScopingWarnings(compileIface(t, "all"))
	if len(got) != 1 {
		t.Fatalf("expected exactly one per-interface scoping advisory, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], `zone "wan"`) || !strings.Contains(got[0], `interface "ge-0/0/0.0"`) {
		t.Errorf("per-interface scoping advisory must name both zone and interface, got: %q", got[0])
	}
}
