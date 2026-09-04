package config

import (
	"strings"
	"testing"
)

// #8597 K66: the DHCP dynamic-DNS commit warnings covered only the v4 policy,
// so the independent v6 policy #2691 P1b added compiled enabled with zero
// diagnostics. These drive the REAL set-command -> SchemaValidate ->
// CompileConfig -> ValidateConfig pipeline, mirroring the v4 pins in
// compiler_dhcp_ddns_test.go, because the row is about what an OPERATOR sees at
// commit and a unit call on the validator would not prove the stanza is
// reachable through the schema.

// v6WarnsOn compiles the given set lines and returns the warnings whose text
// names the dhcpv6 stanza.
func v6WarnsOn(t *testing.T, lines []string) []string {
	t.Helper()
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "dhcpv6 dynamic-dns") {
			out = append(out, w)
		}
	}
	return out
}

func hasSub(ws []string, substr string) bool {
	for _, w := range ws {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// The four diagnostics the v6 family was missing, one cell per class so a
// partial fix cannot pass. Each mirrors an existing v4 pin.
func TestDHCPv6DDNSGetsTheBackendWarnings_8597(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lines  []string
		expect string
	}{
		{
			name: "enabled rfc2136 with no update-server",
			lines: []string{
				"set system services dhcpv6-local-server dynamic-dns enable",
				"set system services dhcpv6-local-server dynamic-dns domain corp.example.com",
			},
			expect: "no update-server",
		},
		{
			name: "update-server without a tsig-key sends unsigned UPDATEs (#4483)",
			lines: []string{
				"set system services dhcpv6-local-server dynamic-dns enable",
				"set system services dhcpv6-local-server dynamic-dns update-server 192.0.2.53",
			},
			expect: "unsigned",
		},
		{
			name: "tsig-key without tsig-secret (#2666)",
			lines: []string{
				"set system services dhcpv6-local-server dynamic-dns enable",
				"set system services dhcpv6-local-server dynamic-dns update-server 192.0.2.53",
				"set system services dhcpv6-local-server dynamic-dns tsig-key k1",
			},
			expect: "tsig-secret is empty",
		},
		{
			name: "reserved kea-d2 backend",
			lines: []string{
				"set system services dhcpv6-local-server dynamic-dns enable",
				"set system services dhcpv6-local-server dynamic-dns backend kea-d2",
			},
			expect: "kea-d2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ws := v6WarnsOn(t, tc.lines)
			if len(ws) == 0 {
				t.Fatalf("the v6 policy produced NO dhcpv6 warning at all; want one "+
					"containing %q (#8597 K66)", tc.expect)
			}
			if !hasSub(ws, tc.expect) {
				t.Errorf("no dhcpv6 warning contains %q: %v", tc.expect, ws)
			}
		})
	}
}

// The label must NAME the stanza the operator edits. A v6 warning carrying the
// v4 wording would send them to the wrong block, and would also be
// indistinguishable from a v4 warning to every existing v4 pin, which matches
// on the substring "dhcp dynamic-dns".
func TestTheV6WarningNamesTheV6Stanza_8597(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set system services dhcpv6-local-server dynamic-dns enable",
		"set system services dhcpv6-local-server dynamic-dns domain corp.example.com",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ws := ValidateConfig(cfg)
	for _, w := range ws {
		if strings.Contains(w, "dhcp dynamic-dns") {
			t.Errorf("a v6-only config produced a warning labelled for the v4 "+
				"stanza: %q. Every existing v4 pin matches on that substring, so "+
				"this would also make them pass on v6 input (#8597 K66)", w)
		}
	}
	if !hasSub(ws, "dhcpv6 dynamic-dns") {
		t.Fatalf("no dhcpv6-labelled warning at all: %v", ws)
	}
}

// The v4 wording is UNCHANGED by the split. The existing pins match on
// "dhcp dynamic-dns" and their messages are part of the operator contract.
func TestTheV4WarningWordingIsUnchanged_8597(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set system services dhcp-local-server dynamic-dns enable",
		"set system services dhcp-local-server dynamic-dns domain corp.example.com",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	const want = "dhcp dynamic-dns is enabled with backend rfc2136 but no " +
		"update-server is configured; no records will be published until an " +
		"update-server is set"
	if !hasSub(ValidateConfig(cfg), want) {
		t.Errorf("the v4 message changed; it is byte-pinned here because the "+
			"family split must be invisible to the v4 family: %v", ValidateConfig(cfg))
	}
}

// THE INHERITANCE NOTE. pkg/ddns ReconcileScoped gives a family with no block
// of its own the OTHER family's, so a broken v6-only block governs v4 too. The
// note fires only alongside a real warning, so a healthy single-family config —
// the historical and common shape — stays quiet.
func TestASingleFamilyBlockSaysItGovernsBoth_8597(t *testing.T) {
	t.Run("v6 only, and broken", func(t *testing.T) {
		ws := v6WarnsOn(t, []string{
			"set system services dhcpv6-local-server dynamic-dns enable",
		})
		if !hasSub(ws, "also governs DHCPv4") {
			t.Errorf("a broken v6-only block did not say it governs v4 as well; the "+
				"operator reads a v6 warning and fixes half the problem: %v", ws)
		}
	})
	t.Run("v4 only, and broken", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if !hasSub(ValidateConfig(cfg), "also governs DHCPv6") {
			t.Errorf("a broken v4-only block did not say it governs v6 as well: %v",
				ValidateConfig(cfg))
		}
	})
	t.Run("both families configured: no inheritance note", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcpv6-local-server dynamic-dns enable",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		ws := ValidateConfig(cfg)
		if hasSub(ws, "also governs") {
			t.Errorf("both families have their own block, so neither inherits — the "+
				"note must not fire: %v", ws)
		}
		// Non-vacuity: both families must still be warned about individually,
		// or the absence above proves nothing.
		if !hasSub(ws, "dhcp dynamic-dns is enabled") || !hasSub(ws, "dhcpv6 dynamic-dns is enabled") {
			t.Errorf("both families should still warn about the missing update-server: %v", ws)
		}
	})
	// The v6 mirror of the cell below. Found by mutation: dropping the
	// `len(v6) > 0` guard on the v6 note escaped every cell, because the only
	// healthy single-family fixture was a v4 one and the v4 note has its own
	// guard. A quiet-when-healthy claim needs a fixture on EACH side.
	t.Run("a HEALTHY v6-only block stays quiet", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcpv6-local-server dynamic-dns enable",
			"set system services dhcpv6-local-server dynamic-dns update-server 192.0.2.53",
			"set system services dhcpv6-local-server dynamic-dns tsig-key k1",
			"set system services dhcpv6-local-server dynamic-dns tsig-secret c2VjcmV0",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		ws := ValidateConfig(cfg)
		if hasSub(ws, "also governs") {
			t.Errorf("the v6 inheritance note fired on a config with nothing wrong "+
				"with it: %v", ws)
		}
		// Non-vacuity: prove this fixture IS a v6-only block that the validator
		// looked at, so "quiet" means "nothing to say" and not "not inspected".
		if hasSub(ws, "dhcpv6 dynamic-dns") {
			t.Errorf("a healthy v6 block should produce no dhcpv6 warning at all: %v", ws)
		}
		if cfg.System.DHCPServer.DynamicDNSv6 == nil || cfg.System.DHCPServer.DynamicDNS != nil {
			t.Fatal("the fixture is not a v6-ONLY block, so it cannot test the v6 note")
		}
	})

	t.Run("a HEALTHY single-family block stays quiet", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
			"set system services dhcp-local-server dynamic-dns tsig-key k1",
			"set system services dhcp-local-server dynamic-dns tsig-secret c2VjcmV0",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		ws := ValidateConfig(cfg)
		if hasSub(ws, "also governs") {
			t.Errorf("the inheritance note fired on a config with nothing wrong with "+
				"it. It is attached to warnings, not emitted on its own, precisely so "+
				"the historical v4-only shape is not made noisy: %v", ws)
		}
		if cfg.System.DHCPServer.DynamicDNS == nil || cfg.System.DHCPServer.DynamicDNSv6 != nil {
			t.Fatal("the fixture is not a v4-ONLY block, so it cannot test the v4 note")
		}
	})
}
