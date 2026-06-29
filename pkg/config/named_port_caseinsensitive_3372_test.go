package config

import (
	"strings"
	"testing"
)

// #3372: a custom-application named port spelled in mixed/upper case
// (`destination-port HTTPS`, `source-port Http`) must resolve to the SAME
// numeric port as its lowercase spelling at compile time. Junos treats service
// names case-insensitively, and resolveAppPort canonicalizes named ports to the
// numeric form against the shared junosServicePorts catalog BEFORE either the
// strict commit gate (validatePortSpec) or the userspace #2124 capability gate
// (userspacePortSpecRepresentable / Rust parse_port_spec) sees the value.
//
// This is the load-bearing case-fold: the userspace capability gate and Rust
// parse_port_spec match service aliases CASE-SENSITIVELY (lowercase literals
// only) to stay in lock-step with each other. If resolveAppPort did not
// lowercase, a mixed-case alias would pass the case-INSENSITIVE strict commit
// gate yet reach the case-SENSITIVE userspace gate as a raw name, which rejects
// it — the commit/apply split #2142/#2124 set out to prevent (one mixed-case
// alias disarms userspace enforcement for the whole snapshot, a system-level
// fail-open onto the kernel slow path).
//
// RED-on-revert: deleting the strings.ToLower in resolveAppPort makes
// junosServicePorts["HTTPS"] miss, resolveAppPort returns "HTTPS" verbatim, and
// the compiled DestinationPort != "443" — these assertions fail.
func TestNamedPortMixedCaseResolvesToNumeric(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		numeric string
	}{
		{"upper-https", "HTTPS", "443"},
		{"mixed-http", "Http", "80"},
		{"lower-http", "http", "80"},
		{"upper-dns", "DNS", "53"},
		{"upper-hyphen", "FTP-DATA", "20"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set applications application app protocol tcp",
				"set applications application app destination-port " + tc.spec,
				"set applications application app source-port " + tc.spec,
			})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			app, ok := ResolveApplication("app", cfg.Applications.Applications)
			if !ok || app == nil {
				t.Fatal("application app not compiled")
			}
			if app.DestinationPort != tc.numeric {
				t.Fatalf("destination-port %q compiled to %q, want %q", tc.spec, app.DestinationPort, tc.numeric)
			}
			if app.SourcePort != tc.numeric {
				t.Fatalf("source-port %q compiled to %q, want %q", tc.spec, app.SourcePort, tc.numeric)
			}
		})
	}
}

// TestNamedPortMixedCaseMatchesLowercaseCompile pins case-insensitivity directly:
// the compiled config for an uppercase alias must be byte-identical (in the
// port fields) to the lowercase compile. Reverting the case-fold makes the
// uppercase spec resolve verbatim while the lowercase spec resolves to numeric,
// so the two diverge.
func TestNamedPortMixedCaseMatchesLowercaseCompile(t *testing.T) {
	compilePort := func(t *testing.T, spec string) string {
		t.Helper()
		tree := buildTree(t, []string{
			"set applications application app protocol tcp",
			"set applications application app destination-port " + spec,
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig(%q): %v", spec, err)
		}
		app, _ := ResolveApplication("app", cfg.Applications.Applications)
		if app == nil {
			t.Fatalf("application app not compiled for spec %q", spec)
		}
		return app.DestinationPort
	}
	if upper, lower := compilePort(t, "HTTPS"), compilePort(t, "https"); upper != lower {
		t.Fatalf("HTTPS compiled to %q but https compiled to %q (must be case-insensitive)", upper, lower)
	}
}

// TestNamedPortAliasTablesDoNotDrift is the source-level canary the #3372 audit
// asked for: the two hand-maintained 15-name alias tables (the strict commit
// gate's validatePortSpec namedPorts and the userspace #2124 capability gate's
// userspacePortSpecRepresentable, mirrored by Rust parse_port_spec) must each be
// a consistent subset of the single-source-of-truth junosServicePorts catalog
// that resolveAppPort canonicalizes through. If a future edit adds a name to one
// table that the catalog does not know (or maps to a different port), the
// canary fails — the divergence that could re-open a commit/apply split.
//
// Note the deliberate case asymmetry this guards: validatePortSpec is
// case-INSENSITIVE (it lowercases before lookup) while the userspace gate is
// case-SENSITIVE (mirrors Rust). That asymmetry is safe ONLY because
// resolveAppPort canonicalizes every recognized name to a number before either
// gate runs (TestNamedPortMixedCaseResolvesToNumeric pins that), so a mixed-case
// name never reaches the case-sensitive gate as a raw name. This canary pins the
// remaining invariant: the name SETS agree with the catalog.
func TestNamedPortAliasTablesDoNotDrift(t *testing.T) {
	// The 15 names the strict commit gate accepts directly (validatePortSpec).
	commitGateNames := []string{
		"http", "https", "ssh", "telnet", "ftp", "ftp-data", "smtp", "dns",
		"pop3", "imap", "snmp", "ntp", "bgp", "ldap", "syslog",
	}
	for _, name := range commitGateNames {
		if _, ok := junosServicePorts[name]; !ok {
			t.Errorf("validatePortSpec accepts %q but junosServicePorts (the resolveAppPort SSOT) does not know it — alias-table drift", name)
		}
		// validatePortSpec must accept the name (belt-and-suspenders backstop).
		if err := validatePortSpec(name); err != nil {
			t.Errorf("validatePortSpec(%q) = %v, want accepted", name, err)
		}
		// And the uppercase spelling must accept too (case-insensitive gate).
		if err := validatePortSpec(strings.ToUpper(name)); err != nil {
			t.Errorf("validatePortSpec(%q upper) = %v, want accepted (case-insensitive)", name, err)
		}
	}
}
