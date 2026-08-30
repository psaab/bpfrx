package config

import (
	"strings"
	"testing"
)

// junos_host_app_gap_7374_test.go — #7374.
//
// A `to-zone junos-host` PERMIT narrowed by `match application` is stricter
// than the coarse kernel host-inbound gate, is not enforced on the direct
// host-bound path, and drew NO warning: the predicate tested only the source
// (#4168) and destination (#6612) dimensions.
//
// THE CENTRAL DESIGN CONSTRAINT is that this must be a COMPARISON, not a token
// test. A syntactic "application != any" check would fire on the very common
// `application [ junos-ssh junos-ping ]` even when the zone admits nothing
// beyond ssh and ping — a false positive on a large fraction of real configs.
// The tests below are built around that: the SECOND cell is the one that a
// naive fix passes and a correct fix must also pass.

func compileGap7374(t *testing.T, lines []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func junosHostWarnings7374(t *testing.T, cfg *Config) []string {
	t.Helper()
	var out []string
	for _, w := range validateJunosHostDirectDeliveryWarnings(cfg) {
		out = append(out, w)
	}
	return out
}

func policyBase7374(apps []string, zoneServices []string) []string {
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.2.1/24",
		"set security zones security-zone untrust",
		"set security zones security-zone untrust interfaces ge-0/0/0.0",
	}
	for _, s := range zoneServices {
		lines = append(lines, "set security zones security-zone untrust host-inbound-traffic system-services "+s)
	}
	lines = append(lines,
		"set security policies from-zone untrust to-zone junos-host policy app-only match source-address any",
		"set security policies from-zone untrust to-zone junos-host policy app-only match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy app-only then permit",
	)
	for _, a := range apps {
		lines = append(lines, "set security policies from-zone untrust to-zone junos-host policy app-only match application "+a)
	}
	return lines
}

// THE DEFECT: the zone admits MORE than the permit covers.
func TestAppScopedPermitWithAGapWarns7374(t *testing.T) {
	cfg := compileGap7374(t, policyBase7374(
		[]string{"junos-ssh"},
		[]string{"ssh", "https", "ping"}))
	ws := junosHostWarnings7374(t, cfg)
	found := false
	for _, w := range ws {
		if strings.Contains(w, "app-only") && strings.Contains(w, "application-restricted permit") {
			found = true
		}
	}
	if !found {
		t.Errorf("an application-scoped permit covering only junos-ssh, against a zone whose "+
			"host-inbound gate also admits https and ping, drew NO warning. Those services "+
			"stay admitted by the kernel while Junos would drop them to the junos-host "+
			"default, and the permit is not enforced on the direct path (#7374). warnings=%v", ws)
	}
}

// THE FALSE-POSITIVE CELL — this is the one that decides the design.
//
// The zone admits EXACTLY what the permit covers, so there is no gap and no
// warning is owed. A syntactic "application != any" test passes every other
// cell in this file and fails this one, which is why the fix compares the
// permitted set against the zone's effective admit set instead.
func TestAppScopedPermitWithNoGapIsSilent7374(t *testing.T) {
	cfg := compileGap7374(t, policyBase7374(
		[]string{"junos-ssh", "junos-ping"},
		[]string{"ssh", "ping"}))
	for _, w := range junosHostWarnings7374(t, cfg) {
		if strings.Contains(w, "application-restricted permit") {
			t.Errorf("a permit covering ssh and ping, against a zone admitting exactly ssh "+
				"and ping, drew a warning. There is no gap: this is the false positive the "+
				"issue forbids, and it would fire on a large fraction of real configs "+
				"(#7374): %s", w)
		}
	}
}

// `application any` is not narrowed at all.
func TestApplicationAnyIsSilent7374(t *testing.T) {
	cfg := compileGap7374(t, policyBase7374(
		[]string{"any"},
		[]string{"ssh", "https", "ping"}))
	for _, w := range junosHostWarnings7374(t, cfg) {
		if strings.Contains(w, "application-restricted permit") {
			t.Errorf("`application any` is not application-scoped and must not warn: %s", w)
		}
	}
}

// FAIL QUIET on what cannot be resolved. An unknown application name must not
// manufacture a gap — a false negative costs an advisory, a false positive
// costs the advisory's credibility.
func TestUnresolvableApplicationIsSilent7374(t *testing.T) {
	cfg := compileGap7374(t, append(policyBase7374(nil, []string{"ssh", "https"}),
		"set applications application zzcustom protocol tcp",
		"set security policies from-zone untrust to-zone junos-host policy app-only match application zzcustom"))
	for _, w := range junosHostWarnings7374(t, cfg) {
		if strings.Contains(w, "application-restricted permit") {
			t.Errorf("an application with no destination-port cannot be reduced to an L4 "+
				"tuple, so no gap can be DEMONSTRATED and none must be claimed: %s", w)
		}
	}
}

// The comparison must see PER-INTERFACE overrides too — the coarse gate admits
// the union across the zone's local addresses, so a gap introduced by an
// interface stanza is a real gap.
func TestPerInterfaceOverrideIsIncludedInTheAdmitSet7374(t *testing.T) {
	cfg := compileGap7374(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.2.1/24",
		"set security zones security-zone untrust",
		"set security zones security-zone untrust interfaces ge-0/0/0.0 host-inbound-traffic system-services https",
		"set security zones security-zone untrust host-inbound-traffic system-services ssh",
		"set security policies from-zone untrust to-zone junos-host policy app-only match source-address any",
		"set security policies from-zone untrust to-zone junos-host policy app-only match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy app-only match application junos-ssh",
		"set security policies from-zone untrust to-zone junos-host policy app-only then permit",
	})
	found := false
	for _, w := range junosHostWarnings7374(t, cfg) {
		if strings.Contains(w, "application-restricted permit") {
			found = true
		}
	}
	if !found {
		t.Error("a per-interface host-inbound override admitting https, against a permit " +
			"covering only junos-ssh, drew no warning. The coarse gate admits the UNION " +
			"across the zone's local addresses, so an interface-level admit is as real a " +
			"gap as a zone-level one (#7374)")
	}
}

// The existing source/destination warnings must be unchanged — this adds a
// dimension, it does not replace the two that already worked.
func TestSourceScopedPermitStillWarns7374(t *testing.T) {
	cfg := compileGap7374(t, []string{
		"set security zones security-zone untrust",
		"set security zones security-zone untrust host-inbound-traffic system-services ssh",
		"set security policies from-zone untrust to-zone junos-host policy src-only match source-address 10.0.0.0/8",
		"set security policies from-zone untrust to-zone junos-host policy src-only match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy src-only match application any",
		"set security policies from-zone untrust to-zone junos-host policy src-only then permit",
	})
	found := false
	for _, w := range junosHostWarnings7374(t, cfg) {
		if strings.Contains(w, "source-restricted permit") {
			found = true
		}
	}
	if !found {
		t.Error("the #4168 source-restricted permit warning regressed")
	}
}

// FAIL QUIET when the permit MIXES resolvable and unresolvable applications.
//
// This cell exists because the mutation matrix found its absence: dropping the
// `!ok` bail passed every other test, because with a single unresolvable
// application the permitted set ends up empty and the function returns quiet
// anyway. The difference only appears when SOME applications resolve.
//
// Then the unresolvable one is silently treated as covering nothing, and the
// comparison reports a gap that the application it could not read might well
// have closed — a fabricated finding, which is worse than the silence this
// advisory replaced.
func TestMixedResolvableAndUnresolvableApplicationsAreSilent7374(t *testing.T) {
	cfg := compileGap7374(t, append(policyBase7374([]string{"junos-ssh"}, []string{"ssh", "https"}),
		"set applications application zzcustom protocol tcp",
		"set security policies from-zone untrust to-zone junos-host policy app-only match application zzcustom"))
	for _, w := range junosHostWarnings7374(t, cfg) {
		if strings.Contains(w, "application-restricted permit") {
			t.Errorf("the permit names junos-ssh AND an application that cannot be reduced "+
				"to an L4 tuple. The unresolvable one may well cover https, so no gap can "+
				"be DEMONSTRATED and none must be claimed — reporting one here fabricates "+
				"a finding (#7374): %s", w)
		}
	}
}
