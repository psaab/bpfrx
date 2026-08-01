package config

import (
	"strings"
	"testing"
)

func compileWarn5619(t *testing.T, lines ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v (a #5619 plaintext advisory must NEVER reject)", err)
	}
	return cfg
}

func plaintextWarnings5619(cfg *Config) []string {
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5619") {
			out = append(out, w)
		}
	}
	return out
}

// TestPlaintextWarningFiresForRouteBasedVPN is the core #5619 assertion: an
// operator committing a route-based IPsec VPN is told, at commit, that the
// decrypted plaintext is not evaluated against xpf security policies.
func TestPlaintextWarningFiresForRouteBasedVPN(t *testing.T) {
	cfg := compileWarn5619(t,
		"set security ipsec vpn myvpn bind-interface st0.0",
	)
	got := plaintextWarnings5619(cfg)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 #5619 advisory, got %d: %v", len(got), cfg.Warnings)
	}
	for _, want := range []string{"myvpn", "st0.0", "NOT evaluated against xpf security policies"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("advisory missing %q; got: %s", want, got[0])
		}
	}
}

// TestPlaintextWarningNamesTheContradictedZone covers the sharpest case: the
// operator put the tunnel in a security zone and the commit ACCEPTED it, so
// they have been told something specific and untrue. The advisory must say the
// zone does not govern the decrypted traffic.
func TestPlaintextWarningNamesTheContradictedZone(t *testing.T) {
	cfg := compileWarn5619(t,
		"set security ipsec vpn myvpn bind-interface st0.0",
		"set security zones security-zone vpn interfaces st0.0",
	)
	got := plaintextWarnings5619(cfg)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 #5619 advisory, got %d: %v", len(got), cfg.Warnings)
	}
	if !strings.Contains(got[0], `security-zone "vpn"`) {
		t.Errorf("advisory must name the contradicted zone; got: %s", got[0])
	}
	if !strings.Contains(got[0], "does NOT currently govern") {
		t.Errorf("advisory must state the zone does not govern the plaintext; got: %s", got[0])
	}
}

// TestPlaintextWarningNeverRejects is the no-brick property (#1960), and it is
// the one this file exists to defend. An operator with a working VPN must be
// able to commit an UNRELATED change. Compiles must succeed in every shape.
func TestPlaintextWarningNeverRejects(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"bare bind-interface", []string{
			"set security ipsec vpn v bind-interface st0",
		}},
		{"zoned tunnel plus unrelated change", []string{
			"set security ipsec vpn v bind-interface st0.0",
			"set security zones security-zone vpn interfaces st0.0",
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
			"set security zones security-zone trust interfaces ge-0/0/0.0",
			"set system host-name fw-unrelated-change",
		}},
		{"several tunnels", []string{
			"set security ipsec vpn a bind-interface st0.0",
			"set security ipsec vpn b bind-interface st0.1",
			"set security ipsec vpn c bind-interface st1.0",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileWarn5619(t, tc.lines...)
			if len(plaintextWarnings5619(cfg)) == 0 {
				t.Error("expected at least one #5619 advisory")
			}
		})
	}
}

// TestPlaintextWarningIsQuietWithoutIPsec is the negative control: a config
// with no route-based IPsec must produce no advisory at all. It is true in both
// worlds by construction, so it stays green under every #5619 mutation and a red
// here means the walk over-fires rather than that the fix regressed.
func TestPlaintextWarningIsQuietWithoutIPsec(t *testing.T) {
	cfg := compileWarn5619(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set interfaces gr-0/0/0 unit 0 tunnel source 10.0.1.1",
		"set interfaces gr-0/0/0 unit 0 tunnel destination 10.0.2.1",
	)
	if got := plaintextWarnings5619(cfg); len(got) != 0 {
		t.Errorf("advisory fired with no route-based IPsec configured: %v", got)
	}
}

// TestPlaintextWarningSkipsInvalidBindInterface: a bind-interface that
// materializes NO xfrm device is already reported by the #5297 arm (silent
// tunnel down). Adding a plaintext advisory on top would be noise about a
// plaintext path that does not exist.
func TestPlaintextWarningSkipsInvalidBindInterface(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range []string{
		"set security ipsec vpn bad bind-interface ge-0/0/0.0",
	} {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("setpath: %v", err)
		}
	}
	// The strict path REJECTS an invalid bind-interface (#5297), so drive the
	// advisory directly against the AST rather than through CompileConfig.
	if got := warnSecureTunnelPlaintextUnadjudicatedAST(tree.Children); len(got) != 0 {
		t.Errorf("advisory fired for a bind-interface that creates no xfrm device: %v", got)
	}
}

// TestPlaintextWarningCoversDuplicateSecurityBlocks: parseStatements APPENDS a
// repeated top-level block rather than merging it, and the compiler compiles
// every one — so a VPN living in a duplicate `security {}` must not be missed.
func TestPlaintextWarningCoversDuplicateSecurityBlocks(t *testing.T) {
	tree, err := NewParser(`
security {
    ipsec {
        vpn first {
            bind-interface st0.0;
        }
    }
}
security {
    ipsec {
        vpn second {
            bind-interface st1.0;
        }
    }
}
`).Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := warnSecureTunnelPlaintextUnadjudicatedAST(tree.Children)
	if len(got) != 2 {
		t.Fatalf("want an advisory for BOTH VPNs across duplicate security blocks, got %d: %v",
			len(got), got)
	}
	joined := strings.Join(got, "\n")
	for _, want := range []string{"first", "second", "st0.0", "st1.0"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in: %s", want, joined)
		}
	}
}

// TestPlaintextWarningReadsBracketedZoneList: a bracketed membership list
// arrives bracket-stripped and NESTED under the first member (#5248/#2419), so
// reading only the first would drop the rest and silently omit the zone clause
// for every tunnel after the first.
func TestPlaintextWarningReadsBracketedZoneList(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range []string{
		"set security ipsec vpn a bind-interface st0.0",
		"set security ipsec vpn b bind-interface st0.1",
		"set security zones security-zone vpn interfaces [ st0.0 st0.1 ]",
	} {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("setpath %q: %v", line, err)
		}
	}
	got := warnSecureTunnelPlaintextUnadjudicatedAST(tree.Children)
	if len(got) != 2 {
		t.Fatalf("want 2 advisories, got %d: %v", len(got), got)
	}
	for _, w := range got {
		if !strings.Contains(w, `security-zone "vpn"`) {
			t.Errorf("a bracketed zone member lost its zone clause — the tail of "+
				"`interfaces [ st0.0 st0.1 ]` was dropped: %s", w)
		}
	}
}
