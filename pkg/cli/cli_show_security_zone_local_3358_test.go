package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3358: a zone-local address book (#3061) is folded into the global book at
// compile time under a synthetic key zone-local/<zone>/<name>. The CLI
// `show security policies detail` printed that internal compiler token verbatim
// and labelled it "(global)", so an operator saw `zone-local/trust/web(global)`
// instead of the address-book name `web` they configured — and worse, an
// internal, zone-scoped object mislabelled as global. The detail view now
// renders `web(zone trust)` while still resolving the CIDR off the qualified
// global-book key. These are the fail-on-revert guards: revert the
// unqualification in printPolicyMatchAddresses and the assertions go RED.

func zoneLocal3358Config(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := []string{
		"set security zones security-zone trust interfaces eth0",
		"set security zones security-zone untrust interfaces eth1",
		// Same name 'web' both globally and zone-locally in trust, with
		// different prefixes: zone-local must win AND display as the zone name.
		"set security address-book global address web 10.9.9.9/32",
		"set security address-book global address external 198.51.100.0/24",
		"set security zones security-zone trust address-book address web 10.0.1.100/32",
		"set security zones security-zone untrust address-book address svc 192.0.2.5/32",
		// Zone-local policy: source resolves trust-local web, destination
		// resolves untrust-local svc.
		"set security policies from-zone trust to-zone untrust policy zl match source-address web",
		"set security policies from-zone trust to-zone untrust policy zl match destination-address svc",
		"set security policies from-zone trust to-zone untrust policy zl match application any",
		"set security policies from-zone trust to-zone untrust policy zl then permit",
		// Control: a normal policy whose source is a GLOBAL book name (not in
		// trust's local book) must render "(global)" exactly as before.
		"set security policies from-zone trust to-zone untrust policy normal match source-address external",
		"set security policies from-zone trust to-zone untrust policy normal match destination-address any",
		"set security policies from-zone trust to-zone untrust policy normal match application any",
		"set security policies from-zone trust to-zone untrust policy normal then permit",
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func Test_3358_PolicyDetailUnqualifiesZoneLocalName(t *testing.T) {
	cfg := zoneLocal3358Config(t)
	c := &CLI{}

	out := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})

	// The synthetic compiler token must NOT appear anywhere in operator output.
	if strings.Contains(out, "zone-local/") {
		t.Fatalf("detail output leaked the synthetic zone-local token:\n%s", out)
	}

	// Zone-local policy: authored name + zone scope, CIDR from the zone-local
	// entry (10.0.1.100/32), NOT the global web (10.9.9.9/32).
	zl := policyDetailBlock(t, out, "zl")
	if !strings.Contains(zl, "web(zone trust): 10.0.1.100/32") {
		t.Fatalf("zl detail = %q, want \"web(zone trust): 10.0.1.100/32\" "+
			"(zone-local source name not unqualified — #3358 regression)", zl)
	}
	if !strings.Contains(zl, "svc(zone untrust): 192.0.2.5/32") {
		t.Fatalf("zl detail = %q, want \"svc(zone untrust): 192.0.2.5/32\" "+
			"(zone-local destination name not unqualified — #3358 regression)", zl)
	}
	if strings.Contains(zl, "(global)") && strings.Contains(zl, "web") {
		// "web" must never be labelled global — it is zone-scoped.
		if strings.Contains(zl, "web(global)") {
			t.Fatalf("zl detail = %q, zone-local web mislabelled (global)", zl)
		}
	}

	// Control: a normal global-book name renders "(global)" unchanged.
	normal := policyDetailBlock(t, out, "normal")
	if !strings.Contains(normal, "external(global): 198.51.100.0/24") {
		t.Fatalf("normal detail = %q, want \"external(global): 198.51.100.0/24\" "+
			"(global address render regressed)", normal)
	}
	if !strings.Contains(normal, "any-ipv4(global): 0.0.0.0/0") {
		t.Fatalf("normal detail = %q, want the any-ipv4(global) line", normal)
	}
}
